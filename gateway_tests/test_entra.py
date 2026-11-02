"""Delegated Entra v2 tokens must authorize the owner, never an entire tenant."""
import pytest
from starlette.testclient import TestClient
from mcp_gateway.auth import OAuthTokenVerifier
from mcp_gateway.config import GatewaySettings
from mcp_gateway.server import create_server
from test_auth import KEY, make_token


def entra_settings(**overrides):
    values = dict(
        public_url='https://pcap.example.com/mcp', backend_url='http://fastapi:8000',
        backend_token='x' * 40, oauth_provider='entra',
        tenant_id='11111111-1111-4111-8111-111111111111',
        issuer='https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0',
        audience='22222222-2222-4222-8222-222222222222',
        jwks_url='https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/discovery/v2.0/keys',
        allowed_subjects=['33333333-3333-4333-8333-333333333333'],
    )
    values.update(overrides)
    return GatewaySettings(**values)


def entra_token(**overrides):
    claims = dict(
        iss='https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0',
        aud='22222222-2222-4222-8222-222222222222',
        tid='11111111-1111-4111-8111-111111111111', ver='2.0',
        oid='33333333-3333-4333-8333-333333333333', sub='pairwise-subject',
        scp='openid pcap:read', scope=None, client_id=None,
        azp='44444444-4444-4444-8444-444444444444',
    )
    claims.update(overrides)
    return make_token(**claims)


@pytest.mark.asyncio
async def test_entra_delegated_owner_token_uses_oid_and_qualified_scope():
    verifier = OAuthTokenVerifier(entra_settings(), signing_key=KEY.public_key())
    result = await verifier.verify_token(entra_token())
    assert result is not None
    assert result.subject == '33333333-3333-4333-8333-333333333333'
    assert result.client_id == '44444444-4444-4444-8444-444444444444'
    assert result.scopes == ['https://pcap.example.com/mcp/pcap:read']


@pytest.mark.asyncio
@pytest.mark.parametrize('claims', [
    {'tid': '55555555-5555-4555-8555-555555555555'},
    {'iss': 'https://login.microsoftonline.com/common/v2.0'},
    {'aud': 'https://graph.microsoft.com'},
    {'oid': '55555555-5555-4555-8555-555555555555'},
    {'oid': None}, {'ver': '1.0'},
    {'scp': None, 'scope': 'pcap:read', 'roles': ['pcap:read']},
    {'scp': 'other'}, {'exp': 1},
])
async def test_entra_wrong_tenant_identity_or_permission_is_refused(claims):
    verifier = OAuthTokenVerifier(entra_settings(), signing_key=KEY.public_key())
    assert await verifier.verify_token(entra_token(**claims)) is None


@pytest.mark.parametrize('overrides', [
    {'tenant_id': None}, {'tenant_id': 'not-a-tenant'},
    {'issuer': 'https://login.microsoftonline.com/common/v2.0'},
    {'audience': 'https://pcap.example.com/mcp'}, {'allowed_subjects': ['email@example.com']},
])
def test_entra_settings_refuse_incomplete_or_ambiguous_identity(overrides):
    with pytest.raises(ValueError):
        entra_settings(**overrides)


def test_entra_http_discovery_and_tool_access_with_delegated_token():
    config = entra_settings()
    server = create_server(config, verifier=OAuthTokenVerifier(config, signing_key=KEY.public_key()))
    with TestClient(server.streamable_http_app(), base_url='https://pcap.example.com') as client:
        response = client.post('/mcp', json={'jsonrpc': '2.0', 'method': 'tools/list', 'id': 1})
        assert response.status_code == 401
        assert 'resource_metadata=' in response.headers['www-authenticate']
        metadata = client.get('/.well-known/oauth-protected-resource/mcp').json()
        assert metadata['scopes_supported'] == ['https://pcap.example.com/mcp/pcap:read']
        response = client.post('/mcp', headers={
            'Authorization': 'Bearer ' + entra_token(), 'Accept': 'application/json, text/event-stream',
        }, json={'jsonrpc': '2.0', 'method': 'tools/list', 'id': 2})
        assert response.status_code == 200, response.text
        assert 'get_tls_decryption' in {tool['name'] for tool in response.json()['result']['tools']}
