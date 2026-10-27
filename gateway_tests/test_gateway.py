import json
import httpx
import pytest
from mcp_gateway.backend import BackendClient, bounded_result
from mcp_gateway.config import GatewaySettings
from mcp_gateway.server import create_server

def settings():
    return GatewaySettings(
        public_url='https://pcap.example.com/mcp', backend_url='http://fastapi:8000',
        backend_token='x' * 40, issuer='https://auth.example.com/',
        audience='https://pcap.example.com/mcp', jwks_url='https://auth.example.com/jwks',
        allowed_subjects=['owner'],
    )

def test_response_budget_scrubs_payloads_and_reports_truncation():
    result = bounded_result({'pcap_path': '/secret', 'payload': 'password', 'rows': [
        {'value': 'é' * 10000} for _ in range(100)
    ]})
    serialized = json.dumps(result, ensure_ascii=False)
    assert len(serialized) <= 60000
    assert '/secret' not in serialized
    assert 'password' not in serialized
    assert result['limitations']

def test_packet_endpoint_actual_raw_fields_are_omitted():
    data = {'packet_num': 0, 'raw_hex': 'aa bb cc', 'l7_application': {
        'protocol': 'HTTP', 'detail': {'first_line': 'GET / HTTP/1.1',
                                     'body_preview': 'Authorization: secret-password'},
    }}
    serialized = json.dumps(bounded_result(data))
    assert 'secret-password' not in serialized
    assert 'aa bb cc' not in serialized
    assert 'GET / HTTP/1.1' in serialized

def test_final_envelope_respects_budget_with_source_and_task():
    data = {'rows': ['a' * 1490] * 25, 'extra': ['b' * 1450] * 15}
    result = bounded_result(data, source='/api/mcp-data/' + 'a' * 64 + '/summary', task_id='a' * 64)
    assert len(json.dumps(result)) <= 60000

@pytest.mark.asyncio
async def test_tools_use_only_read_endpoints_with_backend_auth():
    def handler(request):
        assert request.headers['authorization'] == 'Bearer ' + 'x' * 40
        assert request.method == 'GET'
        if request.url.path == '/api/mcp-data/abc/summary':
            return httpx.Response(200, json={'task_id': 'abc', 'summary': {'total_packets': 123}})
        return httpx.Response(404)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        server = create_server(settings(), BackendClient(settings(), client), verifier=object())
        tools = await server.list_tools()
        assert all(t.annotations.readOnlyHint for t in tools)
        assert not any('delete' in t.name or 'config' in t.name for t in tools)
        result = await server.call_tool('get_analysis_summary', {'task_id': 'abc'})
        assert '123' in str(result)

@pytest.mark.asyncio
async def test_backend_error_does_not_disclose_paths_or_credentials():
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500, text='/app/secret xxxxx'))) as client:
        with pytest.raises(ValueError, match='500') as exc:
            await BackendClient(settings(), client).get('/api/history')
        assert '/app/secret' not in str(exc.value)

@pytest.mark.asyncio
async def test_tool_rejects_path_traversal_before_network():
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: pytest.fail('network called'))) as client:
        server = create_server(settings(), BackendClient(settings(), client), verifier=object())
        with pytest.raises(Exception):
            await server.call_tool('get_analysis_summary', {'task_id': '../secret'})

def test_settings_reject_incomplete_public_auth():
    with pytest.raises(ValueError):
        GatewaySettings(public_url='http://public.example/mcp', backend_url='http://fastapi:8000',
                        backend_token='short', issuer='', audience='', jwks_url='', allowed_subjects=[])

@pytest.mark.asyncio
async def test_diagnostic_supports_narrow_pointer_and_anomaly_filters_reach_backend():
    def handler(request):
        if request.url.path == '/api/abc/tcp-health':
            return httpx.Response(200, json={'sessions': [{'rtt': 10}, {'rtt': 500}]})
        if request.url.path == '/api/mcp-data/abc/anomalies':
            assert request.url.params['severity'] == 'high'
            assert request.url.params['source'] == 'dns'
            return httpx.Response(200, json={'data': [{'severity': 'high'}], 'total': 1})
        return httpx.Response(404)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        server = create_server(settings(), BackendClient(settings(), client), verifier=object())
        result = await server.call_tool('get_diagnostic', {'task_id': 'abc', 'diagnostic': 'tcp-health',
                                                        'pointer': '/sessions', 'offset': 1, 'limit': 1})
        assert '500' in str(result)
        result = await server.call_tool('get_anomalies', {'task_id': 'abc', 'severity': 'high', 'source': 'dns'})
        assert 'high' in str(result)
