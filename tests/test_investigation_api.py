import json
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.mcp_api import create_mcp_router
from app.services.storage_service import StorageService
from tests.test_investigation import capture


def client_for(tmp_path, capture):
    storage=StorageService()
    storage.results_dir=tmp_path/'results'; storage.upload_dir=tmp_path/'uploads'; storage._ensure_directories()
    path=storage.get_upload_path('demo','capture.pcap'); path.write_bytes(capture.read_bytes())
    base={'metadata':{'filename':'demo.pcap'},'protocol_analysis':{'summary':{'total_packets':7,'total_bytes':500}},
          'packets_index':[{'idx':0,'src_ip':'192.0.2.10','dst_ip':'198.51.100.20','protocol':'TCP'}],
          'dns_analysis':{'queries':[{'packet_idx':2,'query':'evil.example','src_ip':'192.0.2.10','password':'sensitive'}]},
          'http_analysis':{'requests':[{'packet_idx':6,'host':'web.example','src_ip':'192.0.2.10','url':'https://web.example/?token=secret','cookie':'secret'}]},
          'tcp_analysis':{'sessions':[{'src':'192.0.2.10:50000','dst':'198.51.100.20:443','rst_count':1}]},
          'all_anomalies':[{'severity':'high','source':'dns','src_ip':'192.0.2.10','description':'secret body'}]}
    storage.save_results('demo',base)
    storage.save_results('other',{**base,'protocol_analysis':{'summary':{'total_packets':10,'total_bytes':1000}}})
    app=FastAPI(); app.include_router(create_mcp_router(storage))
    return TestClient(app)


def test_investigation_routes_search_hunt_triage_and_validation(tmp_path,capture):
    with client_for(tmp_path,capture) as c:
        caps=c.get('/api/mcp-data/demo/capabilities').json()
        assert caps['original_capture_available'] is True
        assert caps['packet_index']['complete'] is False
        assert caps['engine_available'] is True
        r=c.get('/api/mcp-data/demo/search',params={'filters':json.dumps({'protocol':'dns'}),'limit':1})
        assert r.status_code==200,r.text
        data=r.json(); assert data['data'][0]['frame_number']==3
        assert 'task=demo' in data['data'][0]['evidence_url']
        assert 'packet=2' in data['data'][0]['evidence_url']
        assert c.get('/api/mcp-data/demo/conversations').json()['data']
        h=c.get('/api/mcp-data/demo/hunt',params={'indicators':json.dumps(['evil.example'])}).json()
        assert h['data'][0]['matched_packets']==2
        assert c.get('/api/mcp-data/demo/triage',params={'preset':'dns-failures'}).json()['data'][0]['frame_number']==4
        assert c.get('/api/mcp-data/demo/search',params={'filters':'{"port":99999}'}).status_code==400
        assert c.get('/api/mcp-data/demo/search',params={'filters':'[]'}).status_code==400
        assert c.get('/api/mcp-data/../search').status_code!=200
        assert c.get('/api/mcp-data/missing/search').status_code==404


def test_correlation_exact_references_and_safe_projection(tmp_path,capture):
    with client_for(tmp_path,capture) as c:
        r=c.get('/api/mcp-data/demo/correlate',params={'entity':'192.0.2.10'}).json()
        assert {row['section'] for row in r['data']} >= {'packets_index','dns_analysis','http_analysis','tcp_analysis','all_anomalies'}
        serialized=json.dumps(r)
        assert 'sensitive' not in serialized and 'secret' not in serialized
        assert '/sessions/0' in serialized
        assert r['coverage']['scope']=='stored_results'
        assert r['coverage']['complete'] is False
        domain=c.get('/api/mcp-data/demo/correlate',params={'entity':'evil.example'}).json()
        assert domain['data'][0]['pointer']=='/queries/0'


def test_compare_preserves_direction_and_does_not_claim_causality(tmp_path,capture):
    with client_for(tmp_path,capture) as c:
        r=c.get('/api/mcp-data/demo/compare',params={'other_task_id':'other'}).json()
        assert r['baseline_task_id']=='demo'
        assert r['metrics']['total_packets']['delta']==3
        assert r['metrics']['total_bytes']['delta']==500
        assert r['limitations']
        assert c.get('/api/mcp-data/demo/compare',params={'other_task_id':'../secret'}).status_code==400


def test_packet_details_available_outside_partial_index(tmp_path,capture,monkeypatch):
    from app.api import routes
    with client_for(tmp_path,capture) as c:
        storage=StorageService(); storage.results_dir=tmp_path/'results'; storage.upload_dir=tmp_path/'uploads'
        monkeypatch.setattr(routes,'storage_service',storage)
        c.app.include_router(routes.router)
        response=c.get('/api/analysis/demo/packet/6')
        assert response.status_code==200,response.text
        assert response.json()['packet_num']==6
        assert response.json()['basic_info']['src_ip']=='192.0.2.10'
        assert c.get('/api/analysis/demo/packet/99999999').status_code==404


def test_capture_statistics_and_packet_context(tmp_path,capture):
    with client_for(tmp_path,capture) as c:
        r=c.get('/api/mcp-data/demo/statistics',params={'group_by':'dns'}).json()
        assert r['data'][0]['value']=='evil.example'
        assert r['data'][0]['packet_count']==2
        r=c.get('/api/mcp-data/demo/context',params={'packet_index':3,'radius':1}).json()
        assert [p['frame_number'] for p in r['data']]==[3,4,5]


def test_correlation_real_dns_schema_and_ipv6_endpoints():
    from app.investigation_views import correlate
    results={'dns_analysis':{'responses':[{'packet_idx':42,'src_ip':'192.0.2.53',
        'answers':[{'name':'evil.example','type':'A','ttl':300,'data':'203.0.113.77'},
                   {'name':'evil.example','type':'TXT','data':'private-token-123'}]}]},
        'tcp_analysis':{'sessions':[{'src':'2001:db8::1:443','dst':'2001:db8::2:50000'}]}}
    ip=correlate('abc',results,'203.0.113.77')
    assert ip['data'][0]['packet_index']==42
    assert ip['data'][0]['pointer']=='/responses/0'
    domain=correlate('abc',results,'evil.example')
    assert domain['data'][0]['packet_index']==42
    assert '203.0.113.77' in json.dumps(domain)
    assert 'private-token-123' not in json.dumps(domain)
    assert correlate('abc',results,'2001:db8::1')['data'][0]['section']=='tcp_analysis'
