from starlette.testclient import TestClient
from mcp_gateway.auth import OAuthTokenVerifier
from mcp_gateway.server import create_server
from test_auth import KEY, make_token
from test_gateway import settings

def test_http_rejects_anonymous_and_advertises_oauth_discovery():
    server = create_server(settings(), verifier=OAuthTokenVerifier(settings(), signing_key=KEY.public_key()))
    with TestClient(server.streamable_http_app(), base_url='https://pcap.example.com') as client:
        response = client.post('/mcp', json={'jsonrpc': '2.0', 'method': 'tools/list', 'id': 1})
        assert response.status_code == 401
        assert 'resource_metadata=' in response.headers['www-authenticate']
        metadata = client.get('/.well-known/oauth-protected-resource/mcp').json()
        assert metadata['resource'] == 'https://pcap.example.com/mcp'
        assert metadata['authorization_servers'] == ['https://auth.example.com/']
        assert 'pcap:read' in metadata['scopes_supported']

def test_real_mcp_http_initialization_and_tool_listing_with_owner_token():
    server = create_server(settings(), verifier=OAuthTokenVerifier(settings(), signing_key=KEY.public_key()))
    with TestClient(server.streamable_http_app(), base_url='https://pcap.example.com') as client:
        headers = {'Authorization': 'Bearer ' + make_token(), 'Accept': 'application/json, text/event-stream'}
        response = client.post('/mcp', headers=headers, json={
            'jsonrpc': '2.0', 'method': 'initialize', 'id': 1,
            'params': {'protocolVersion': '2025-03-26', 'capabilities': {},
                       'clientInfo': {'name': 'test', 'version': '1'}},
        })
        assert response.status_code == 200, response.text
        assert response.json()['result']['serverInfo']['name'] == 'PCAP Analyzer Pro'
        response = client.post('/mcp', headers=headers, json={'jsonrpc': '2.0', 'method': 'tools/list', 'id': 2})
        names = {tool['name'] for tool in response.json()['result']['tools']}
        assert {'list_analyses', 'query_analysis', 'get_packet_details', 'get_diagnostic'} <= names
