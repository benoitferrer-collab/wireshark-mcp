import time
from types import SimpleNamespace
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.identity.web import create_identity_router, WebIdentityMiddleware
from app.identity.store import IdentityStore
from cryptography.fernet import Fernet

OWNER='65c6def3-d34c-414d-9d6e-a9266fa76264'
GROUP='12345678-1234-1234-1234-123456789abc'
@pytest.fixture
def env(tmp_path):
    store=IdentityStore('sqlite:///'+str(tmp_path/'web.db'),Fernet.generate_key().decode())
    settings=SimpleNamespace(tenant_id='tenant',owner_oid=OWNER,origin='https://app.example',client_id='client',client_secret='secret',api_token='x'*40,callback_url='https://app.example/auth/callback')
    class Provider:
        allowed=True
        def group_member(self,session,group): return self.allowed
        def begin(self): return {'auth_uri':'https://login.microsoftonline.com/test','state':'state'}
        def finish(self,flow,params): return {'oid':OWNER,'name':'Owner','cache':'private'}
    provider=Provider()
    app=FastAPI()
    app.include_router(create_identity_router(settings,store,provider))
    @app.get('/api/private')
    def private(): return {'ok':True}
    @app.post('/api/private')
    def mutate(): return {'ok':True}
    @app.get('/')
    def root(): return {'ok':True}
    from app.api_auth import APIAccessMiddleware
    app.add_middleware(APIAccessMiddleware,token=settings.api_token)
    app.add_middleware(WebIdentityMiddleware,settings=settings,store=store,provider=provider)
    client=TestClient(app,base_url=settings.origin,follow_redirects=False)
    return client,store,provider,settings

def login(env,oid=OWNER,version=None,checked=None):
    client,store,provider,settings=env
    policy=store.get_policy()
    store.save_session('session',{'oid':oid,'name':'Test','csrf':'csrf','policy_version':version or policy['version'],'checked':checked or time.time(),'session_expires':time.time()+3600},time.time()+3600)
    client.cookies.set('nomios_session','session')

def test_anonymous_and_internal_bearer(env):
    client,*_=env
    assert client.get('/').status_code==303
    assert client.get('/api/private').status_code==401
    assert client.get('/api/private',headers={'Authorization':'Bearer '+'x'*40}).status_code==200
    assert client.get('/api/identity/me',headers={'Authorization':'Bearer '+'x'*40}).status_code==401

def test_owner_admin_csrf_and_group_validation(env):
    login(env)
    client,store,*_=env
    assert client.get('/api/identity/me').json()['is_admin']
    assert client.put('/api/identity/group',json={'group_id':GROUP}).status_code==403
    headers={'X-CSRF-Token':'csrf','Origin':'https://app.example'}
    assert client.put('/api/identity/group',json={'group_id':'bad'},headers=headers).status_code==422
    assert client.put('/api/identity/group',json={'group_id':GROUP},headers=headers).status_code==200
    assert store.get_policy()['group_id']==GROUP

def test_group_change_revokes_member_and_nonadmin_cannot_admin(env):
    client,store,provider,_=env
    store.set_group(GROUP,OWNER)
    login(env,'member')
    assert client.get('/api/private').status_code==200
    assert client.get('/api/identity/group').status_code==403
    store.set_group('',OWNER)
    assert client.get('/api/private').status_code==403

def test_group_recheck_failure_fails_closed(env):
    client,store,provider,_=env
    store.set_group(GROUP,OWNER)
    login(env,'member',checked=time.time()-301)
    provider.allowed=False
    assert client.get('/api/private').status_code==403

def test_session_csrf_and_origin_are_required(env):
    login(env)
    client,*_=env
    assert client.post('/api/private').status_code==403
    assert client.post('/api/private',headers={'X-CSRF-Token':'csrf','Origin':'https://evil.example'}).status_code==403
    assert client.post('/api/private',headers={'X-CSRF-Token':'csrf','Origin':'https://app.example'}).status_code==200

def test_callback_requires_flow_cookie_and_consumes_once(env):
    client,store,provider,_=env
    assert client.get('/auth/callback?state=state&code=x').status_code==400
    store.save_session('flow',{'flow':{'state':'state'}},time.time()+600)
    client.cookies.set('nomios_flow','flow')
    response=client.get('/auth/callback?state=state&code=x')
    assert response.status_code==303
    assert 'HttpOnly' in response.headers['set-cookie'] and 'Secure' in response.headers['set-cookie']
    assert client.get('/auth/callback?state=state&code=x').status_code==400

def test_failed_group_recheck_deletes_session(env):
    client,store,provider,_=env
    store.set_group(GROUP,OWNER)
    login(env,'member',checked=time.time()-301)
    provider.allowed=False
    assert client.get('/api/private').status_code==403
    assert store.get_session('session') is None

def test_graph_exception_expires_session(env):
    client,store,provider,_=env
    store.set_group(GROUP,OWNER)
    login(env,'member',checked=time.time()-301)
    def fail(*args): raise RuntimeError('Graph unavailable')
    provider.group_member=fail
    assert client.get('/api/private').status_code==503
    assert store.get_session('session') is None

def test_logout_during_graph_recheck_cannot_resurrect_session(env):
    from app.identity.web import resolve_session
    client,store,provider,settings=env
    store.set_group(GROUP,OWNER)
    login(env,'member',checked=time.time()-301)
    def revoke_during_check(session,group):
        store.delete_session('session')
        return True
    provider.group_member=revoke_during_check
    assert resolve_session(store,provider,settings,'session') is None
    assert store.get_session('session') is None

def test_internal_upload_requires_cookie_csrf_origin_and_server_bearer(env):
    login(env)
    client,*_=env
    body={'session_id':'session','csrf':'csrf','origin':'https://app.example'}
    path='/api/identity/internal/authorize-upload'
    assert client.post(path,json=body,headers={'X-CSRF-Token':'csrf','Origin':'https://app.example'}).status_code==403
    headers={'Authorization':'Bearer '+'x'*40}
    assert client.post(path,json=body,headers=headers).status_code==200
    assert client.post(path,json={**body,'csrf':'wrong'},headers=headers).status_code==403
    assert client.post(path,json={**body,'origin':'https://evil.example'},headers=headers).status_code==403

def test_activity_drops_unknown_sensitive_fields_and_rejects_arbitrary_tool_names(env):
    client,store,*_=env
    headers={'Authorization':'Bearer '+'x'*40}
    path='/api/identity/internal/activity'
    event={'event_id':'12345678-1234-1234-1234-123456789abc','client_id':'claude','tool':'list_analyses','success':True,'duration_ms':12,'arguments':'sensitive'}
    assert client.post(path,json=event,headers=headers).status_code==200
    assert 'sensitive' not in str(store.activity())
    assert client.post(path,json={**event,'tool':'raw captured text !'},headers=headers).status_code==422

def test_login_landing_has_microsoft_button_before_redirect(env):
    client,*_=env
    response=client.get('/auth/login')
    assert response.status_code==200
    assert 'Se connecter avec Microsoft' in response.text
    assert client.get('/auth/start').status_code==303

def test_scheduled_purge_requires_dedicated_credential(env,monkeypatch):
    client,store,*_=env
    monkeypatch.setenv('CRON_SECRET','cron-secret')
    store.save_session('expired',{'cache':'private'},time.time()-10)
    assert client.get('/api/identity/maintenance').status_code==401
    assert client.get('/api/identity/maintenance',headers={'Authorization':'Bearer '+'x'*40}).status_code==401
    assert client.get('/api/identity/maintenance',headers={'Authorization':'Bearer cron-secret'}).status_code==200
    with store.connect() as db:
        assert db.execute('SELECT COUNT(*) AS n FROM web_sessions').fetchone()['n']==0
