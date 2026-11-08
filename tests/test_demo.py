import json
from pathlib import Path

def test_demo_install_reuses_only_synthetic_capture(tmp_path):
    from app.demo import install_demo, DEMO_NAME
    from app.services.storage_service import StorageService
    store=StorageService();store.upload_dir=tmp_path/'uploads';store.results_dir=tmp_path/'results';store._ensure_directories()
    first=install_demo(store);second=install_demo(store)
    assert first['task_id']==second['task_id']
    assert Path(store.get_pcap_path(first['task_id'])).read_bytes()==Path('app/demo_data',DEMO_NAME).read_bytes()
    result=store.load_results(first['task_id'])
    assert result['metadata']['demo'] is True
    assert result['protocol_analysis']['summary']['total_packets']==192
    assert store.delete_analysis(first['task_id'])
    assert install_demo(store)['task_id']!=first['task_id']

def test_demo_bundle_has_no_private_paths_or_real_addresses():
    payload=Path('app/demo_data/results.json').read_text()
    assert '/Users/' not in payload and 'Bearer ' not in payload
    assert json.loads(payload)['metadata']['demo_version']==1

def test_cloud_demo_original_capture_survives_new_instance(tmp_path):
    from tests.test_cloud import Objects, make_storage
    from app.demo import install_demo
    objects=Objects();store=make_storage(objects,tmp_path/'one')
    first=install_demo(store)
    task=first['task_id']
    assert objects.read_json(f'status/{task}.json')['status']=='completed'
    fresh=make_storage(objects,tmp_path/'two')
    assert Path(fresh.get_pcap_path(task)).read_bytes()==Path(store.get_pcap_path(task)).read_bytes()
    assert install_demo(fresh)['task_id']==task

def test_demo_original_supports_real_wireshark_investigation():
    from app.services.investigation_service import CaptureInvestigator, SearchFilters
    scan=CaptureInvestigator().search(Path('app/demo_data/DEMO_Nomios_Support.pcap'), SearchFilters(display_filter='tcp.flags.reset == 1'))
    assert scan['coverage']['complete'] is True
    assert scan['total_matching']==6
    assert scan['data'][0]['frame_number']==8

def test_presenter_facts_come_from_original_capture_and_reject_real_tasks(tmp_path):
    import pytest
    from app.demo import install_demo, demo_evidence
    from app.services.storage_service import StorageService
    store=StorageService();store.upload_dir=tmp_path/'uploads';store.results_dir=tmp_path/'results';store._ensure_directories()
    demo=install_demo(store);facts=demo_evidence(store,demo['task_id'])
    assert facts['resets']['count']==6
    assert facts['resets']['frames'][0]==8
    assert facts['dns_errors']['count']==4
    assert facts['http_ok']['count']==18
    assert facts['coverage']['complete'] is True
    with pytest.raises(ValueError):demo_evidence(store,'real-capture')
