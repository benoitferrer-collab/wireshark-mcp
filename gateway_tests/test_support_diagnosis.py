import json
import httpx
import pytest
from mcp_gateway.server import create_server
from mcp_gateway.backend import BackendClient
from test_gateway import settings


@pytest.mark.asyncio
async def test_support_diagnosis_tool_is_read_only_and_validates_both_ids():
    calls=[]
    def handler(request):
        calls.append(request)
        assert request.method=='GET'
        assert request.url.path=='/api/mcp-data/current/support-diagnosis'
        assert request.url.params['reference_task_id']=='reference'
        return httpx.Response(200,json={'method':{'trained_model':False},'findings':[{'evidence':[{'evidence_url':'/?task=current#tab=packets&packet=0'}]}]})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        server=create_server(settings(),BackendClient(settings(),client),verifier=object())
        result=await server.call_tool('get_support_diagnosis',{'task_id':'current','reference_task_id':'reference'})
        data=json.loads(result[0].text)['data']
        assert data['method']['trained_model'] is False
        assert data['findings'][0]['evidence'][0]['evidence_url'].startswith('https://')
        tool=next(t for t in await server.list_tools() if t.name=='get_support_diagnosis')
        assert tool.annotations.readOnlyHint is True
        with pytest.raises(Exception):
            await server.call_tool('get_support_diagnosis',{'task_id':'current','reference_task_id':'../other'})
        assert len(calls)==1
