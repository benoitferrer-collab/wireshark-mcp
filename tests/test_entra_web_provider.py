import time
from types import SimpleNamespace
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from app.identity.web import EntraProvider

KEY=rsa.generate_private_key(public_exponent=65537,key_size=2048)
TENANT='4b0a3328-264b-4f04-a6e9-66b104b58487'
CLIENT='11111111-1111-1111-1111-111111111111'
OWNER='65c6def3-d34c-414d-9d6e-a9266fa76264'

@pytest.mark.parametrize('changes,valid', [({},True),({'tid':'other'},False),({'aud':'other'},False),({'nonce':'other'},False),({'iss':'https://evil.example'},False),({'exp':1},False)])
def test_provider_checks_signed_tenant_audience_issuer_nonce_and_expiration(changes,valid):
    provider=EntraProvider(SimpleNamespace(tenant_id=TENANT,client_id=CLIENT))
    claims={'tid':TENANT,'aud':CLIENT,'oid':OWNER,'sub':'subject','nonce':'nonce','iss':f'https://login.microsoftonline.com/{TENANT}/v2.0','iat':int(time.time()),'exp':int(time.time())+300,**changes}
    encoded=jwt.encode(claims,KEY,algorithm='RS256')
    provider.jwks=SimpleNamespace(get_signing_key_from_jwt=lambda raw:SimpleNamespace(key=KEY.public_key()))
    provider.application=lambda cache:SimpleNamespace(acquire_token_by_auth_code_flow=lambda flow,params:{'id_token':encoded,'access_token':'graph'})
    if valid: assert provider.finish({'nonce':'nonce'},{})['oid']==OWNER
    else:
        with pytest.raises((ValueError,jwt.PyJWTError)): provider.finish({'nonce':'nonce'},{})
