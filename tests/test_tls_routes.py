import time
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.identity.web import WebIdentityMiddleware
from app.tls.routes import create_tls_router
from tests.test_tls_jobs import env,KEYLOG
from types import SimpleNamespace

@pytest.fixture
def client_env(env):
    service,objects=env
    app=FastAPI();sent=[]
    async def sender(job):sent.append(job)
    app.include_router(create_tls_router(service,sender))
    settings=SimpleNamespace(api_token='x'*40,owner_oid='owner',origin='https://app.example')
    app.add_middleware(WebIdentityMiddleware,settings=settings,store=service.store,provider=object())
    client=TestClient(app,base_url=settings.origin,follow_redirects=False)
    service.store.save_session('session',{'oid':'owner','name':'Owner','csrf':'csrf'},time.time()+3600)
    return client,service,objects,sent

def test_secret_upload_requires_cookie_csrf_and_not_machine_token(client_env):
    client,service,objects,sent=client_env
    path='/api/identity/tls/capture'
    args={'data':{'kind':'keylog'},'files':{'file':('a.keys',KEYLOG)}}
    assert client.post(path,**args).status_code==401
    assert client.post(path,headers={'Authorization':'Bearer '+'x'*40},**args).status_code==401
    client.cookies.set('nomios_session','session')
    assert client.post(path,**args).status_code==403
    r=client.post(path,headers={'X-CSRF-Token':'csrf','Origin':'https://app.example'},**args)
    assert r.status_code==202
    assert sent
    assert 'secret' not in r.text
    service.complete(sent[0],{'rows':[{'method':'GET','path':'/'}],'state':'decoded','decrypted_packets':1})
    r=client.get(path)
    assert r.status_code==200 and r.json()['report']['data'][0]['method']=='GET'

def test_capture_must_be_single_and_completed(client_env):
    client,service,objects,_=client_env
    client.cookies.set('nomios_session','session')
    objects.write_json('status/capture.json',{'status':'processing'})
    r=client.post('/api/identity/tls/capture',data={'kind':'keylog'},files={'file':('a',KEYLOG)},headers={'Origin':'https://app.example','X-CSRF-Token':'csrf'})
    assert r.status_code==400

def test_mcp_reads_paged_report_without_secret(env):
    from app.mcp_api import create_mcp_router
    service,objects=env
    job=service.create('capture','owner','keylog',KEYLOG)
    service.complete(job['id'],{'rows':[{'method':'GET','packet_index':n} for n in range(80)],'state':'decoded'})
    app=FastAPI();app.include_router(create_mcp_router(object(),tls_service=service))
    client=TestClient(app)
    r=client.get('/api/mcp-data/capture/tls-decryption?offset=50&limit=25')
    assert r.status_code==200 and len(r.json()['report']['data'])==25
    assert r.json()['report']['next_offset']==75
    assert 'CLIENT_RANDOM' not in r.text and 'owner' not in r.text
    assert client.get('/api/mcp-data/capture/tls-decryption?limit=50').status_code==422
