"""Contracts for managed storage: no cloud account or network is needed."""
import copy
import json
from pathlib import Path
import pytest
from app.services.storage_service import StorageService
from app.cloud.storage import create_cloud_storage
from app.cloud.jobs import JobService

class Objects:
    def __init__(self): self.data = {}
    def read_json(self, key):
        return json.loads(self.data[key]) if key in self.data else None
    def write_json(self, key, value): self.data[key] = json.dumps(value).encode()
    def download(self, key, path, max_size=None):
        body = self.data[key]
        if max_size is not None and len(body) > max_size: raise ValueError('File too large')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    def put_file(self, key, path): self.data[key] = path.read_bytes()
    def head(self, key): return {'size': len(self.data[key])}
    def keys(self, prefix): return sorted(k for k in self.data if k.startswith(prefix))
    def delete(self, keys):
        for key in keys: self.data.pop(key, None)

@pytest.fixture
def objects(): return Objects()

def make_storage(objects, tmp_path):
    return create_cloud_storage(StorageService, objects, root=tmp_path)

def test_results_and_derived_survive_new_instance_and_local_disk_loss(objects, tmp_path):
    first = make_storage(objects, tmp_path / 'first')
    first.save_results('abc', {'metadata': {'filename': 'x.pcap'}, 'protocol_analysis': {'summary': {'total_packets': 3}}})
    first.save_derived('abc', 'tls_audit', {'version': 'TLS1.3'})
    second = make_storage(objects, tmp_path / 'second')
    assert second.load_results('abc')['protocol_analysis']['summary']['total_packets'] == 3
    assert second.load_derived('abc', 'tls_audit') == {'version': 'TLS1.3'}
    assert second.get_analysis_history()[0]['filename'] == 'x.pcap'
    assert second.get_file_path('abc', 'results.json').exists()

def test_capture_download_is_scoped_to_manifest_not_local_path(objects, tmp_path):
    objects.data['captures/abc/source.pcap'] = b'pcap-data'
    objects.write_json('jobs/abc.json', {'kind': 'single', 'captures': [{'pathname': 'captures/abc/source.pcap', 'filename': 'source.pcap'}]})
    storage = make_storage(objects, tmp_path)
    assert Path(storage.get_pcap_path('abc')).read_bytes() == b'pcap-data'
    with pytest.raises(ValueError): storage.get_results_path('../escape')

def test_delete_tombstone_prevents_worker_recreating_results(objects, tmp_path):
    storage = make_storage(objects, tmp_path)
    storage.save_results('abc', {'metadata': {}, 'protocol_analysis': {}})
    assert storage.delete_analysis('abc')
    storage.save_results('abc', {'metadata': {}, 'protocol_analysis': {}})
    assert storage.load_results('abc') is None
    assert objects.read_json('deleted/abc.json') is not None

def test_manifest_replay_preserves_completed_status(objects):
    objects.data['captures/abc/source.pcap'] = b'pcap'
    jobs = JobService(objects)
    capture = {'pathname': 'captures/abc/source.pcap', 'filename': 'source.pcap'}
    jobs.create('abc', [capture])
    jobs.status('abc', 'completed', 100, 'Done')
    jobs.create('abc', [capture])
    assert jobs.read_status('abc')['status'] == 'completed'

@pytest.mark.parametrize('pathname', ['https://evil.example/file.pcap', 'captures/other/source.pcap', 'captures/abc/../source.pcap', 'captures/abc/source.exe'])
def test_forged_capture_paths_are_rejected_before_storage_lookup(objects, pathname):
    with pytest.raises(ValueError):
        JobService(objects).create('abc', [{'pathname': pathname, 'filename': 'file.pcap'}])

def test_oversized_file_rejected_based_on_stored_size(objects):
    class BigObjects(Objects):
        def head(self, key): return {'size': 104857601}
    with pytest.raises(ValueError, match='100'):
        JobService(BigObjects()).create('abc', [{'pathname': 'captures/abc/source.pcap', 'filename': 'source.pcap'}])

def test_deletion_during_result_upload_does_not_leave_sensitive_artifacts(tmp_path):
    class RaceObjects(Objects):
        def put_file(self, key, path):
            self.write_json('deleted/abc.json', {'deleted': True})
            super().put_file(key, path)
    objects = RaceObjects()
    storage = make_storage(objects, tmp_path)
    storage.save_results('abc', {'metadata': {}, 'protocol_analysis': {}})
    assert not objects.keys('results/abc/')
    assert not objects.keys('summaries/')

def test_manifest_replay_repairs_missing_status(objects):
    objects.data['captures/abc/source.pcap'] = b'pcap'
    jobs = JobService(objects)
    capture = {'pathname': 'captures/abc/source.pcap', 'filename': 'source.pcap'}
    jobs.create('abc', [capture])
    objects.delete(['status/abc.json'])
    jobs.create('abc', [capture])
    assert jobs.read_status('abc')['status'] == 'queued'
