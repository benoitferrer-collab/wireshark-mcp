import pytest
from mcp_gateway.activity import ActivityFastMCP
from mcp.server.auth.provider import AccessToken

@pytest.mark.asyncio
async def test_authenticated_calls_count_success_validation_and_runtime_errors_without_payload():
    events=[]
    async def collect(event): events.append(event)
    token=AccessToken(token='private',client_id='claude',scopes=['pcap:read'])
    server=ActivityFastMCP('test',activity_sink=collect,identity_reader=lambda:token)
    @server.tool()
    def valid(count:int): return {'sensitive':'not in events'}
    @server.tool()
    def broken(): raise ValueError('secret failure')
    await server.call_tool('valid',{'count':1})
    for name,args in [('valid',{'count':'bad'}),('broken',{})]:
        with pytest.raises(Exception): await server.call_tool(name,args)
    assert len(events)==3 and [e['success'] for e in events]==[True,False,False]
    assert all(e['client_id']=='claude' for e in events)
    assert not any(x in str(events) for x in ['private','sensitive','secret failure','arguments'])
    await server.list_tools()
    assert len(events)==3

@pytest.mark.asyncio
async def test_collector_failure_does_not_break_tool():
    async def broken(event): raise RuntimeError('database down')
    server=ActivityFastMCP('test',activity_sink=broken,identity_reader=lambda:AccessToken(token='private',client_id='claude',scopes=[]))
    @server.tool()
    def okay(): return {'okay':True}
    assert await server.call_tool('okay',{})

@pytest.mark.asyncio
async def test_no_attribution_without_authenticated_context():
    events=[]
    async def collect(event): events.append(event)
    server=ActivityFastMCP('test',activity_sink=collect,identity_reader=lambda:None)
    @server.tool()
    def okay(): return True
    await server.call_tool('okay',{})
    assert events==[]

@pytest.mark.asyncio
async def test_invalid_tool_name_is_counted_with_safe_placeholder():
    events=[]
    async def collect(event): events.append(event)
    server=ActivityFastMCP('test',activity_sink=collect,identity_reader=lambda:AccessToken(token='private',client_id='claude',scopes=[]))
    with pytest.raises(Exception): await server.call_tool('unknown.tool',{})
    assert len(events)==1 and events[0]['tool']=='unknown_tool'

def test_collection_health_is_server_only_and_reports_disabled(monkeypatch):
    from starlette.testclient import TestClient
    from test_gateway import settings
    from mcp_gateway.server import create_server
    monkeypatch.delenv('MCP_ACTIVITY_ENABLED',raising=False)
    config=settings()
    server=create_server(config)
    with TestClient(server.streamable_http_app(),base_url='https://pcap.example.com') as client:
        assert client.get('/mcp/activity-health').status_code==401
        response=client.get('/mcp/activity-health',headers={'Authorization':'Bearer '+config.backend_token})
        assert response.status_code==200 and response.json()['state']=='disabled'

def test_real_http_context_counts_only_authenticated_tool_calls(monkeypatch):
    from starlette.testclient import TestClient
    from test_gateway import settings
    from test_auth import KEY, make_token
    from mcp_gateway.auth import OAuthTokenVerifier
    import mcp_gateway.server as module
    events=[]
    async def collect(event): events.append(event)
    monkeypatch.setenv('MCP_ACTIVITY_ENABLED','true')
    monkeypatch.setattr(module,'backend_sink',lambda config:collect)
    config=settings()
    server=module.create_server(config,verifier=OAuthTokenVerifier(config,signing_key=KEY.public_key()))
    with TestClient(server.streamable_http_app(),base_url='https://pcap.example.com') as client:
        body={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'unknown.tool','arguments':{}}}
        headers={'Authorization':'Bearer '+make_token(),'Accept':'application/json, text/event-stream'}
        assert client.post('/mcp',json=body).status_code==401
        assert events==[]
        response=client.post('/mcp',json=body,headers=headers)
        assert response.status_code==200
        assert len(events)==1 and events[0]['client_id']=='claude' and events[0]['success'] is False
        assert events[0]['tool']=='unknown_tool'
        client.post('/mcp',json={'jsonrpc':'2.0','id':2,'method':'tools/list'},headers=headers)
        assert len(events)==1

@pytest.mark.asyncio
async def test_unregistered_tool_never_stores_arbitrary_user_supplied_name():
    events=[]
    async def collect(event): events.append(event)
    server=ActivityFastMCP('test',activity_sink=collect,identity_reader=lambda:AccessToken(token='private',client_id='claude',scopes=[]))
    with pytest.raises(Exception): await server.call_tool('private_capture_name',{})
    assert events[0]['tool']=='unknown_tool'
