import json
import httpx
import pytest
from mcp_gateway.server import create_server
from mcp_gateway.backend import BackendClient
from test_gateway import settings

SUMMARY={'task_id':'abc','summary':{'total_packets':8000,'capture_duration_seconds':60,
    'first_packet_time':1700000000,'last_packet_time':1700000060},
    'packet_index':{'available':5000,'complete':False},'sections':['tcp_analysis','dns_analysis']}


def test_first_question_is_grounded_in_capture_and_not_a_questionnaire():
    from mcp_gateway.guidance import InvestigationContext, build_guidance
    result=build_guidance('abc',SUMMARY,{'data':[],'total':0},InvestigationContext())
    assert result['next_question']['id']=='symptom'
    assert len(result['questions'])==1
    assert result['observations'][0]['value']==8000
    assert result['next_question']['based_on']
    assert result['coverage']['packet_index_complete'] is False
    assert result['root_cause_status']=='not_established'


def test_known_context_is_not_asked_again_and_next_calls_are_executable():
    from mcp_gateway.guidance import InvestigationContext, build_guidance
    ctx=InvestigationContext(issue='performance',symptom='Application lente',expected_behavior='Réponse en moins de 1 seconde',
        capture_point='Côté client',filters={'ip':'192.0.2.10','port':443,'time_start':1700000001,'time_end':1700000005})
    result=build_guidance('abc',SUMMARY,{'data':[]},ctx)
    assert result['next_question']['id']=='reproducibility'
    assert not set(result['missing_context']) & {'symptom','expected_behavior','capture_point','target','time_window'}
    call=result['next_checks'][0]
    assert call['tool']=='get_conversations'
    assert call['arguments']['filters']['ip']=='192.0.2.10/32'
    assert call['arguments']['task_id']=='abc'


def test_report_mode_and_unknown_information_do_not_force_questions():
    from mcp_gateway.guidance import InvestigationContext, build_guidance
    ctx=InvestigationContext(mode='report',unavailable_context=['symptom','target','time_window','capture_point','expected_behavior','reproducibility'])
    result=build_guidance('abc',SUMMARY,None,ctx)
    assert result['next_question'] is None and result['questions']==[]
    assert result['limitations']


def test_outside_capture_window_is_a_clarification_not_a_false_search():
    from mcp_gateway.guidance import InvestigationContext, build_guidance, search_filters_for
    ctx=InvestigationContext(symptom='Lenteur',issue='performance',filters={'ip':'192.0.2.10','time_start':1700001000,'time_end':1700001005})
    result=build_guidance('abc',SUMMARY,{'data':[]},ctx)
    assert result['next_question']['id']=='capture_window_mismatch'
    assert search_filters_for(ctx,SUMMARY) is None
    assert result['coverage']['requested_window_overlaps_capture'] is False


def test_packet_evidence_grounds_followups_without_echoing_raw_secrets():
    from mcp_gateway.guidance import InvestigationContext, build_guidance
    scan={'data':[{'frame_number':50,'packet_index':49,'src_ip':'192.0.2.10','dst_ip':'198.51.100.1',
                  'tcp_stream':3,'tcp_reset':True,'payload':'private-leaked-body-927','evidence_url':'https://pcap.example.com/?task=abc#tab=packets&packet=49'}],
          'coverage':{'complete':False,'reason':'time_limit'}}
    result=build_guidance('abc',SUMMARY,None,InvestigationContext(issue='connectivity',symptom='Connexion fermée',filters={'ip':'192.0.2.10'}),scan)
    assert 'private-leaked-body-927' not in json.dumps(result)
    assert result['coverage']['original_capture']['complete'] is False
    assert any(c['tool']=='search_packets' and c['arguments']['filters']=={'tcp_stream':3} for c in result['next_checks'])
    assert result['root_cause_status']=='not_established'


@pytest.mark.asyncio
async def test_guided_tool_reads_real_evidence_and_proposes_one_question():
    calls=[]
    def handler(r):
        calls.append(r)
        if r.url.path.endswith('/summary'): return httpx.Response(200,json=SUMMARY)
        if r.url.path.endswith('/anomalies'): return httpx.Response(200,json={'data':[],'total':0})
        if r.url.path.endswith('/search'):
            assert json.loads(r.url.params['filters'])['ip']=='192.0.2.10/32'
            return httpx.Response(200,json={'data':[],'coverage':{'complete':True}})
        return httpx.Response(404)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        server=create_server(settings(),BackendClient(settings(),client),verifier=object())
        result=await server.call_tool('guide_investigation',{'task_id':'abc','context':{
            'issue':'performance','symptom':'Application lente','filters':{'ip':'192.0.2.10'}}})
        report=json.loads(result[0].text)['data']
        assert len(report['questions'])==1
        assert report['observations'][0]['value']==8000
        assert any(r.url.path.endswith('/search') for r in calls)
        assert all(r.method=='GET' and r.headers['authorization']=='Bearer '+'x'*40 for r in calls)
        assert 'guide_engineer' in {p.name for p in await server.list_prompts()}


@pytest.mark.asyncio
async def test_optional_failures_are_explicit_but_missing_capture_is_not_ignored():
    def handler(r):
        return httpx.Response(200,json=SUMMARY) if r.url.path.endswith('/summary') else httpx.Response(503)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        server=create_server(settings(),BackendClient(settings(),client),verifier=object())
        result=await server.call_tool('guide_investigation',{'task_id':'abc'})
        assert json.loads(result[0].text)['data']['limitations']
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r:httpx.Response(404))) as client:
        server=create_server(settings(),BackendClient(settings(),client),verifier=object())
        with pytest.raises(Exception): await server.call_tool('guide_investigation',{'task_id':'abc'})


@pytest.mark.asyncio
async def test_invalid_context_is_rejected_before_backend():
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r:pytest.fail('network called'))) as client:
        server=create_server(settings(),BackendClient(settings(),client),verifier=object())
        for args in [
            {'task_id':'../private'}, {'task_id':'abc','context':{'filters':{'port':70000}}},
            {'task_id':'abc','context':{'issue':'run_shell'}},
        ]:
            with pytest.raises(Exception): await server.call_tool('guide_investigation',args)


@pytest.mark.parametrize('issue',['connectivity','performance'])
def test_generic_problem_does_not_silently_exclude_udp(issue):
    from mcp_gateway.guidance import InvestigationContext, build_guidance, search_filters_for
    context=InvestigationContext(issue=issue,symptom='UDP application times out',filters={'ip':'192.0.2.1','port':123})
    assert search_filters_for(context,SUMMARY).protocol is None
    result=build_guidance('abc',SUMMARY,None,context)
    assert not any(c['tool']=='get_diagnostic' and c['arguments'].get('diagnostic')=='tcp-health' for c in result['next_checks'])


def test_unavailable_timestamp_is_not_reasked_on_mismatch():
    from mcp_gateway.guidance import InvestigationContext, build_guidance
    context=InvestigationContext(symptom='Application lente',filters={'time_start':1700010000,'time_end':1700010100},unavailable_context=['time_window'])
    result=build_guidance('abc',SUMMARY,None,context)
    assert result['next_question'] is None
    assert any(o['kind']=='capture_window_mismatch' for o in result['observations'])
    assert result['next_checks'][0]['tool']=='list_analyses'


@pytest.mark.asyncio
async def test_optional_sources_timeout_without_stalling_conversation(monkeypatch):
    import asyncio
    import mcp_gateway.server as module
    monkeypatch.setattr(module,'GUIDANCE_OPTIONAL_TIMEOUT',.01)
    monkeypatch.setattr(module,'GUIDANCE_SCAN_TIMEOUT',.01)
    async def handler(r):
        if r.url.path.endswith('/summary'): return httpx.Response(200,json=SUMMARY)
        await asyncio.sleep(1)
        return httpx.Response(200,json={'data':[]})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        server=create_server(settings(),BackendClient(settings(),client),verifier=object())
        result=await server.call_tool('guide_investigation',{'task_id':'abc','context':{'issue':'performance','symptom':'Application lente','filters':{'ip':'192.0.2.1'}}})
        report=json.loads(result[0].text)['data']
        assert report['next_question']
        assert report['coverage']['original_capture'] is None
        assert sum('indisponible' in note for note in report['limitations'])>=2
