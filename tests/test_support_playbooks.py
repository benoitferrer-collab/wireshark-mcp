import copy
import pytest
from app.services.ir_playbook_service import IRPlaybookGenerator


def test_no_evidence_proposes_qualification_instead_of_c2():
    result=IRPlaybookGenerator().generate({})
    assert result['incident_types_detected']==[]
    assert [p['incident_type'] for p in result['playbooks']]==['qualification']
    assert result['playbooks'][0]['selection_reason']


def test_catalog_contains_support_performance_and_cyber_paths():
    generator=IRPlaybookGenerator()
    catalog=generator.catalog()
    ids={p['id'] for p in catalog}
    assert {'qualification','network_latency','packet_loss','dns_resolution','tls_failure','firewall_access','vpn_failure','c2_beaconing','exfiltration','lateral_movement','brute_force','ransomware','network_scan','traffic_flood'}<=ids
    result=generator.generate({},['network_latency','packet_loss','c2_beaconing'])
    assert result['incident_types_detected']==[]
    assert result['selection_mode']=='manual'
    assert all(p['selection_basis']=='manual' for p in result['playbooks'])
    for p in result['playbooks']:
        assert p['name'] and p['description'] and p['selection_reason']
        assert p['total_tasks']==sum(len(phase['tasks']) for phase in p['phases'])
        assert p['playbook_id']==f"nomios-v2-{p['incident_type']}"
        assert all(phase['phase'] and phase['tasks'] for phase in p['phases'])


def test_recommendations_use_actual_metrics_without_diagnosing_attack():
    source={'dns_analysis':{'summary':{'nxdomain_count':4}},'tcp_analysis':{'summary':{'total_retransmissions':8},'rtt_analysis':{'avg_rtt_ms':150}}}
    result=IRPlaybookGenerator().generate(source)
    assert {'dns_resolution','packet_loss','network_latency'}<=set(p['incident_type'] for p in result['playbooks'])
    assert result['incident_types_detected']==[]
    assert all(p['selection_basis']=='observed_signal' for p in result['playbooks'])


def test_unknown_empty_or_excessive_selections_are_rejected_without_fake_fallback():
    generator=IRPlaybookGenerator()
    for selection in [[],['does-not-exist'],['qualification']*15]:
        with pytest.raises(ValueError):generator.generate({},selection)


def test_results_do_not_mutate_templates_or_capture_and_stable_ids_are_per_playbook():
    generator=IRPlaybookGenerator();source={'all_anomalies':[{'type':'BRUTE_FORCE','description':'<script>untrusted</script>'}]};before=copy.deepcopy(source)
    first=generator.generate(source,['brute_force','packet_loss'])
    first['playbooks'][0]['phases'][0]['tasks'].append('changed')
    second=generator.generate(source,['brute_force'])
    assert source==before
    assert all('changed' not in phase['tasks'] for phase in second['playbooks'][0]['phases'])
    assert first['playbooks'][0]['playbook_id']!=first['playbooks'][1]['playbook_id']
    assert '<script>' not in str(second)

def test_catalog_and_generation_api_validate_selection(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from types import SimpleNamespace
    from app.api import additional_routes as routes
    monkeypatch.setattr(routes,'storage_service',SimpleNamespace(load_results=lambda task: {} if task=='missing' else {'metadata':{'filename':'capture.pcap'}}))
    app=FastAPI();app.include_router(routes.additional_router)
    with TestClient(app) as client:
        catalog=client.get('/api/playbooks/catalog')
        assert catalog.status_code==200 and len(catalog.json()['playbooks'])==14
        manual=client.post('/api/capture/generate-playbook',json={'incident_types':['network_latency','packet_loss']})
        assert manual.status_code==200
        assert [p['incident_type'] for p in manual.json()['playbooks']]==['network_latency','packet_loss']
        for payload in [{'incident_types':[]},{'incident_types':['bad']},{'incident_types':['qualification']*15}]:
            assert client.post('/api/capture/generate-playbook',json=payload).status_code==422
        assert client.post('/api/missing/generate-playbook',json={}).status_code==404

def test_generation_uses_available_derived_signals_without_modifying_results(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from types import SimpleNamespace
    from app.api import additional_routes as routes
    base={'metadata':{'filename':'one.pcap'}}
    calls=[]
    def derived(task,name):
        calls.append((task,name))
        return {'summary':{'beaconing_alerts':2}} if name=='flow_behavior' else None
    monkeypatch.setattr(routes,'storage_service',SimpleNamespace(load_results=lambda task:base,load_derived=derived))
    app=FastAPI();app.include_router(routes.additional_router)
    with TestClient(app) as client:
        result=client.post('/api/one/generate-playbook',json={}).json()
        assert result['suggested_types']==['c2_beaconing']
        assert result['incident_types_detected']==[]
    assert 'flow_behavior' not in base
    assert calls==[('one','flow_behavior'),('one','lateral_movement')]
