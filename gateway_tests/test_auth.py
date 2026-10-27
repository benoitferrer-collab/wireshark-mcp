import time
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp_gateway.auth import OAuthTokenVerifier
from test_gateway import settings

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)

def make_token(**overrides):
    claims = {'iss': 'https://auth.example.com/', 'aud': 'https://pcap.example.com/mcp',
              'sub': 'owner', 'exp': int(time.time()) + 300, 'iat': int(time.time()),
              'scope': 'pcap:read', 'client_id': 'claude'}
    claims.update(overrides)
    return jwt.encode(claims, KEY, algorithm='RS256', headers={'kid': 'local'})

@pytest.mark.asyncio
async def test_owner_token_accepted_and_identity_retained():
    verifier = OAuthTokenVerifier(settings(), signing_key=KEY.public_key())
    result = await verifier.verify_token(make_token())
    assert result is not None
    assert result.scopes == ['pcap:read']

@pytest.mark.asyncio
async def test_generic_oidc_retains_other_granted_scopes():
    verifier = OAuthTokenVerifier(settings(), signing_key=KEY.public_key())
    result = await verifier.verify_token(make_token(scope='openid pcap:read'))
    assert result is not None
    assert result.scopes == ['openid', 'pcap:read']

@pytest.mark.asyncio
@pytest.mark.parametrize('claims', [
    {'exp': 1}, {'aud': 'other'}, {'iss': 'https://evil.example/'},
    {'sub': 'other-user'}, {'scope': 'other'}, {'sub': ''},
])
async def test_invalid_or_unauthorized_tokens_rejected(claims):
    verifier = OAuthTokenVerifier(settings(), signing_key=KEY.public_key())
    assert await verifier.verify_token(make_token(**claims)) is None

@pytest.mark.asyncio
async def test_unsigned_token_rejected():
    verifier = OAuthTokenVerifier(settings(), signing_key=KEY.public_key())
    assert await verifier.verify_token(jwt.encode({'sub': 'owner'}, '', algorithm='none')) is None
