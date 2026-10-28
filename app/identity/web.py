"""Single-tenant Entra browser sessions and owner-only access administration."""
import hmac
import hashlib
import os
import logging
import secrets
import time
from http.cookies import SimpleCookie
from uuid import UUID
from urllib.parse import urlencode
import httpx
import jwt
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

SESSION='nomios_session'
FLOW='nomios_flow'
SESSION_SECONDS=8*3600
logger=logging.getLogger(__name__)

class EntraProvider:
    def __init__(self, settings):
        self.settings=settings
        self.issuer=f'https://login.microsoftonline.com/{settings.tenant_id}/v2.0'
        self.jwks=jwt.PyJWKClient(f'https://login.microsoftonline.com/{settings.tenant_id}/discovery/v2.0/keys',timeout=5)

    def application(self, cache=None):
        import msal
        return msal.ConfidentialClientApplication(self.settings.client_id,client_credential=self.settings.client_secret,authority=f'https://login.microsoftonline.com/{self.settings.tenant_id}',token_cache=cache)

    def begin(self):
        return self.application().initiate_auth_code_flow(['User.Read'],redirect_uri=self.settings.callback_url)

    def finish(self, flow, params):
        import msal
        cache=msal.SerializableTokenCache()
        result=self.application(cache).acquire_token_by_auth_code_flow(flow,params)
        raw=result.get('id_token')
        if not raw or not result.get('access_token'): raise ValueError('Authentication failed')
        claims=jwt.decode(raw,self.jwks.get_signing_key_from_jwt(raw).key,algorithms=['RS256'],audience=self.settings.client_id,issuer=self.issuer,options={'require':['exp','iat','sub','iss','aud','nonce','tid','oid']})
        # MSAL sends the SHA-256 hex digest, while retaining the original nonce in the flow.
        expected_nonce=hashlib.sha256(flow['nonce'].encode('ascii')).hexdigest()
        if claims['tid']!=self.settings.tenant_id or not hmac.compare_digest(claims['nonce'],expected_nonce): raise ValueError('Invalid identity')
        return {'oid':str(UUID(claims['oid'])),'name':str(claims.get('name') or 'Utilisateur'),'cache':cache.serialize()}

    def group_member(self, session, group):
        import msal
        cache=msal.SerializableTokenCache()
        cache.deserialize(session.get('cache',''))
        app=self.application(cache)
        accounts=[a for a in app.get_accounts() if a.get('local_account_id')==session['oid']]
        if not accounts: return False
        token=app.acquire_token_silent(['User.Read'],account=accounts[0])
        if not token or not token.get('access_token'): return False
        session['cache']=cache.serialize()
        with httpx.Client(timeout=8,follow_redirects=False) as client:
            response=client.post('https://graph.microsoft.com/v1.0/me/checkMemberGroups',headers={'Authorization':'Bearer '+token['access_token']},json={'groupIds':[group]})
            response.raise_for_status()
            return group in response.json().get('value',[])


def bearer_ok(scope, settings):
    return hmac.compare_digest(dict(scope.get('headers',[])).get(b'authorization',b''),('Bearer '+settings.api_token).encode())


def cookie(scope, name):
    jar=SimpleCookie()
    try: jar.load(dict(scope.get('headers',[])).get(b'cookie',b'').decode()); return jar[name].value if name in jar else ''
    except Exception: return ''


def resolve_session(store, provider, settings, session_id):
    session=store.get_session(session_id)
    if not session or 'oid' not in session: return None
    if session['oid']==settings.owner_oid: return session
    policy=store.get_policy()
    if not policy['group_id']:
        store.delete_session(session_id)
        return None
    if session.get('policy_version')!=policy['version'] or time.time()-session.get('checked',0)>=300:
        try:
            allowed=provider.group_member(session,policy['group_id'])
        except Exception:
            store.delete_session(session_id)
            raise
        if not allowed:
            store.delete_session(session_id)
            return None
        session.update(policy_version=policy['version'],checked=time.time())
        if not store.refresh_session(session_id,session): return None
    return session


class WebIdentityMiddleware:
    def __init__(self, app, settings, store, provider): self.app,self.settings,self.store,self.provider=app,settings,store,provider

    async def __call__(self, scope, receive, send):
        if scope['type']!='http': return await self.app(scope,receive,send)
        path=scope['path']
        if path=='/api/identity/maintenance':
            cron=os.getenv('CRON_SECRET','')
            valid=bool(cron) and hmac.compare_digest(dict(scope.get('headers',[])).get(b'authorization',b''),('Bearer '+cron).encode())
            if not valid: return await JSONResponse({'detail':'Maintenance authorization required'},401)(scope,receive,send)
            scope['headers']=[(k,v) for k,v in scope.get('headers',[]) if k!=b'authorization']+[(b'authorization',('Bearer '+self.settings.api_token).encode())]
            return await self.app(scope,receive,send)
        public=path in ('/auth/login','/auth/start','/auth/callback','/auth/error','/api/health') or path.startswith(('/static/','/cloud-assets/'))
        if public: return await self.app(scope,receive,send)
        internal=bearer_ok(scope,self.settings)
        # Shared machine credential may call analysis routes and explicit internal identity routes only.
        if internal and (not path.startswith('/api/identity/') or path.startswith('/api/identity/internal/')):
            return await self.app(scope,receive,send)
        session_id=cookie(scope,SESSION)
        try: session=await run_in_threadpool(resolve_session,self.store,self.provider,self.settings,session_id)
        except Exception:
            response=JSONResponse({'detail':'Vérification de connexion indisponible'},503,headers={'Cache-Control':'no-store'})
            return await response(scope,receive,send)
        if not session:
            status=403 if session_id else 401
            response=JSONResponse({'detail':'Connexion ou appartenance au groupe requise'},status,headers={'Cache-Control':'no-store'}) if path.startswith('/api/') else RedirectResponse('/auth/login',303)
            return await response(scope,receive,send)
        if path.startswith('/api/identity/internal/'):
            return await JSONResponse({'detail':'Accès serveur requis'},403)(scope,receive,send)
        headers=dict(scope.get('headers',[]))
        if scope['method'] not in ('GET','HEAD','OPTIONS'):
            valid_origin=headers.get(b'origin',b'').decode()==self.settings.origin
            csrf=headers.get(b'x-csrf-token',b'').decode()
            if not valid_origin or not csrf or not hmac.compare_digest(csrf,session['csrf']):
                return await JSONResponse({'detail':'Protection CSRF'},403)(scope,receive,send)
        scope.setdefault('state',{})['identity']=session
        scope['state']['identity_session_id']=session_id
        # Legacy middleware receives a server credential only after full session authorization.
        if path.startswith('/api/'):
            scope['headers']=[(k,v) for k,v in scope.get('headers',[]) if k!=b'authorization']+[(b'authorization',('Bearer '+self.settings.api_token).encode())]
        async def no_cache(message):
            if message['type']=='http.response.start':
                message.setdefault('headers',[]).extend([(b'cache-control',b'no-store'),(b'vary',b'Cookie')])
            await send(message)
        await self.app(scope,receive,no_cache)


class GroupInput(BaseModel): group_id:str=Field(max_length=36)
class EventInput(BaseModel):
    event_id:UUID
    client_id:str=Field(min_length=1,max_length=128,pattern=r'^[a-zA-Z0-9_.:-]+$')
    tool:str=Field(min_length=1,max_length=80,pattern=r'^[a-zA-Z0-9_-]+$')
    success:bool
    duration_ms:int=Field(ge=0,le=86400000)


def create_identity_router(settings, store, provider, maintenance_hook=None):
    router=APIRouter()
    def identity(request):
        session=getattr(request.state,'identity',None)
        if not session: raise HTTPException(401,'Connexion requise')
        return session
    def admin(request):
        session=identity(request)
        if session['oid']!=settings.owner_oid: raise HTTPException(403,'Administration réservée au propriétaire')
        return session

    @router.get('/auth/login', response_class=HTMLResponse)
    def login_landing():
        from pathlib import Path
        page=Path(__file__).resolve().parents[2]/'templates'/'login.html'
        return HTMLResponse(page.read_text(),headers={'Cache-Control':'no-store','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})

    @router.get('/auth/start')
    def login():
        flow=provider.begin()
        if 'auth_uri' not in flow: raise HTTPException(503,'Connexion Microsoft indisponible')
        key=secrets.token_urlsafe(32)
        store.save_session(key,{'flow':flow},time.time()+600)
        response=RedirectResponse(flow['auth_uri'],303,headers={'Cache-Control':'no-store'})
        response.set_cookie(FLOW,key,max_age=600,secure=True,httponly=True,samesite='lax',path='/auth')
        return response

    @router.get('/auth/callback')
    def callback(request:Request):
        key=request.cookies.get(FLOW,'')
        flow=store.take_session(key) if key else None
        params=dict(request.query_params)
        if not flow or not params.get('state') or not hmac.compare_digest(params['state'],flow['flow']['state']): raise HTTPException(400,'Connexion expirée ou invalide')
        try:
            session=provider.finish(flow['flow'],params)
            policy=store.get_policy()
            if session['oid']!=settings.owner_oid and (not policy['group_id'] or not provider.group_member(session,policy['group_id'])):
                raise HTTPException(403,'Votre compte ne fait pas partie du groupe autorisé')
        except HTTPException: raise
        except Exception: raise HTTPException(400,'Connexion Microsoft refusée ; recommencez') from None
        session.update(csrf=secrets.token_urlsafe(32),checked=time.time(),policy_version=policy['version'],session_expires=time.time()+SESSION_SECONDS)
        session_id=secrets.token_urlsafe(32)
        store.save_session(session_id,session,session['session_expires'])
        previous=request.cookies.get(SESSION)
        if previous: store.delete_session(previous)
        response=RedirectResponse('/',303,headers={'Cache-Control':'no-store'})
        response.set_cookie(SESSION,session_id,max_age=SESSION_SECONDS,secure=True,httponly=True,samesite='lax',path='/')
        response.delete_cookie(FLOW,path='/auth',secure=True,httponly=True,samesite='lax')
        return response

    @router.post('/api/identity/logout')
    def logout(request:Request):
        identity(request)
        store.delete_session(request.state.identity_session_id)
        response=JSONResponse({'login_url':'/auth/login'})
        response.delete_cookie(SESSION,path='/',secure=True,httponly=True,samesite='lax')
        return response

    @router.get('/api/identity/me')
    def me(request:Request):
        session=identity(request)
        return {'name':session['name'],'is_admin':session['oid']==settings.owner_oid,'csrf':session['csrf'],'tenant_id':settings.tenant_id}

    @router.get('/api/identity/group')
    def group(request:Request): admin(request); return store.get_policy()

    @router.put('/api/identity/group')
    def update_group(body:GroupInput,request:Request):
        session=admin(request)
        try: return store.set_group(body.group_id.strip(),session['oid'])
        except ValueError: raise HTTPException(422,'Object ID de groupe invalide') from None

    @router.get('/api/identity/activity')
    def activity(request:Request):
        identity(request)
        store.prune()
        result=store.activity()
        result['endpoint']=settings.origin+'/mcp'
        try:
            with httpx.Client(timeout=4,follow_redirects=False) as client:
                probe=client.get(settings.origin+'/mcp/activity-health',headers={'Authorization':'Bearer '+settings.api_token})
                probe.raise_for_status()
                result['collection_state']=probe.json().get('state','unavailable')
        except Exception: result['collection_state']='unavailable'
        return result

    @router.post('/api/identity/internal/authorize-upload')
    def authorize_upload(request:Request,body:dict):
        if not bearer_ok(request.scope,settings): raise HTTPException(403)
        session=resolve_session(store,provider,settings,str(body.get('session_id','')))
        if not session: raise HTTPException(403,'Connexion requise')
        if body.get('origin')!=settings.origin or not hmac.compare_digest(str(body.get('csrf','')),session['csrf']): raise HTTPException(403,'Protection CSRF')
        return {'authorized':True}

    @router.get('/api/identity/maintenance')
    def maintenance():
        store.prune()
        if maintenance_hook: maintenance_hook()
        return {'ok':True}

    @router.post('/api/identity/internal/activity-probe')
    def activity_probe(request:Request):
        if not bearer_ok(request.scope,settings): raise HTTPException(403)
        store.get_policy()  # Verify actual storage connectivity.
        return {'ok':True}

    @router.post('/api/identity/internal/activity')
    def event(body:EventInput,request:Request):
        if not bearer_ok(request.scope,settings): raise HTTPException(403)
        store.record_event(str(body.event_id),body.client_id,body.tool,body.success,body.duration_ms)
        store.prune()
        return {'ok':True}
    return router
