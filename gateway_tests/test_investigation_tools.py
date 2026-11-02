import json
import httpx
import pytest
from mcp_gateway.server import create_server
from mcp_gateway.backend import BackendClient
from test_gateway import settings


@pytest.mark.asyncio
async def test_investigation_tools_discovery_and_real_dispatch():
    calls=[]
    def handler(r):
        calls.append(r)
        return httpx.Response(200,json={'data':[{'frame_number':5002,'packet_index':5001}],'coverage':{'complete':True}})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        server=create_server(settings(),BackendClient(settings(),client),verifier=object())
        schemas={t.name:t for t in await server.list_tools()}
        expected={'get_investigation_capabilities','search_packets','get_conversations','hunt_indicators',
                  'triage_capture','correlate_entity','compare_analyses','get_traffic_statistics','get_packet_context'}
        assert expected <= schemas.keys()
        assert all(schemas[n].annotations.readOnlyHint for n in expected)
        await server.call_tool('search_packets',{'task_id':'abc','filters':{'dst_port':443,'ip':'192.0.2.1'},'limit':2})
        assert calls[-1].url.path=='/api/mcp-data/abc/search'
        assert json.loads(calls[-1].url.params['filters'])['dst_port']==443
        await server.call_tool('hunt_indicators',{'task_id':'abc','indicators':['evil.example']})
        assert json.loads(calls[-1].url.params['indicators'])==['evil.example']
        await server.call_tool('compare_analyses',{'baseline_task_id':'abc','comparison_task_id':'def'})
        assert calls[-1].url.params['other_task_id']=='def'
        for name,args,path in [
            ('get_investigation_capabilities',{'task_id':'abc'},'capabilities'),
            ('get_conversations',{'task_id':'abc','sort_by':'resets'},'conversations'),
            ('correlate_entity',{'task_id':'abc','entity':'192.0.2.1'},'correlate'),
            ('triage_capture',{'task_id':'abc','preset':'tcp-failures'},'triage'),
            ('get_traffic_statistics',{'task_id':'abc','group_by':'timeline'},'statistics'),
            ('get_packet_context',{'task_id':'abc','packet_index':5001},'context'),
        ]:
            await server.call_tool(name,args)
            assert calls[-1].url.path.endswith('/'+path)
        prompts={p.name for p in await server.list_prompts()}
        assert {'investigate_capture','investigate_indicator'} <= prompts
        assert all(r.method=='GET' and r.headers['authorization']=='Bearer '+'x'*40 for r in calls)


@pytest.mark.asyncio
async def test_evidence_urls_are_absolute_and_response_keeps_coverage():
    def handler(r):
        return httpx.Response(200,json={'data':[{'packet_index':5001,'evidence_url':'/?task=abc#tab=packets&packet=5001'}],
                                       'coverage':{'complete':False,'reason':'time_limit'}})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        server=create_server(settings(),BackendClient(settings(),client),verifier=object())
        result=await server.call_tool('search_packets',{'task_id':'abc'})
        envelope=json.loads(result[0].text)
        assert envelope['data']['data'][0]['evidence_url']=='https://pcap.example.com/?task=abc#tab=packets&packet=5001'
        assert envelope['data']['coverage']['complete'] is False


@pytest.mark.asyncio
async def test_new_tools_reject_invalid_inputs_before_network():
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r:pytest.fail('network called'))) as client:
        server=create_server(settings(),BackendClient(settings(),client),verifier=object())
        for name,args in [
            ('search_packets',{'task_id':'../secret'}),
            ('search_packets',{'task_id':'abc','filters':{'port':70000}}),
            ('hunt_indicators',{'task_id':'abc','indicators':[]}),
            ('compare_analyses',{'baseline_task_id':'abc','comparison_task_id':'../secret'}),
        ]:
            with pytest.raises(Exception): await server.call_tool(name,args)
