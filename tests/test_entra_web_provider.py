import time
from types import SimpleNamespace
from urllib.parse import urlparse, parse_qs
import jwt
import pytest
from msal.oauth2cli.oidc import Client as OIDCClient
from cryptography.hazmat.primitives.asymmetric import rsa
from app.identity.web import EntraProvider

KEY=rsa.generate_private_key(public_exponent=65537,key_size=2048)
TENANT='4b0a3328-264b-4f04-a6e9-66b104b58487'
CLIENT='11111111-1111-1111-1111-111111111111'
OWNER='65c6def3-d34c-414d-9d6e-a9266fa76264'

@pytest.mark.parametrize('changes,valid', [({},True),({'tid':'other'},False),({'aud':'other'},False),({'nonce':'other'},False),({'iss':'https://evil.example'},False),({'exp':1},False),({'nonce':'raw'},False)])
def test_provider_checks_signed_tenant_audience_issuer_nonce_and_expiration(changes,valid):
    provider=EntraProvider(SimpleNamespace(tenant_id=TENANT,client_id=CLIENT))
    # Generate the actual MSAL wire nonce rather than assuming it equals the stored nonce.
    oidc=OIDCClient(client_id=CLIENT,server_configuration={'authorization_endpoint':'https://login.example/authorize','token_endpoint':'https://login.example/token'})
    flow=oidc.initiate_auth_code_flow(scope=['openid'])
    wire_nonce=parse_qs(urlparse(flow['auth_uri']).query)['nonce'][0]
    assert wire_nonce != flow['nonce']
    if changes.get('nonce')=='raw': changes={**changes,'nonce':flow['nonce']}
    claims={'tid':TENANT,'aud':CLIENT,'oid':OWNER,'sub':'subject','nonce':wire_nonce,'iss':f'https://login.microsoftonline.com/{TENANT}/v2.0','iat':int(time.time()),'exp':int(time.time())+300,**changes}
    encoded=jwt.encode(claims,KEY,algorithm='RS256')
    provider.jwks=SimpleNamespace(get_signing_key_from_jwt=lambda raw:SimpleNamespace(key=KEY.public_key()))
    provider.application=lambda cache:SimpleNamespace(acquire_token_by_auth_code_flow=lambda flow,params:{'id_token':encoded,'access_token':'graph'})
    if valid: assert provider.finish(flow,{})['oid']==OWNER
    else:
        with pytest.raises((ValueError,jwt.PyJWTError)): provider.finish(flow,{})
