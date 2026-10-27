"""Read-only bridge tested with actual on-disk StorageService results."""
import json
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.mcp_api import create_mcp_router
from app.services.storage_service import StorageService


def test_bridge_reads_single_and_multi_evidence_and_rejects_missing_pointer(tmp_path):
    storage = StorageService()
    storage.results_dir = tmp_path / 'results'
    storage.upload_dir = tmp_path / 'uploads'
    storage._ensure_directories()
    storage.save_results('single-id', {
        'metadata': {'filename': 'capture.pcap'},
        'protocol_analysis': {'summary': {'total_packets': 300}},
        'tcp_analysis': {'sessions': [{'session_id': 'a'}, {'session_id': 'b'}]},
        'all_anomalies': [{'severity': 'high', 'source': 'dns'}, {'severity': 'low', 'source': 'tcp'}],
    })
    multi = storage.get_results_path('multi-id') / 'multi_results.json'
    multi.write_text(json.dumps({'task_id': 'multi-id', 'analysis': {'sessions': [{'hop': 2}]}}))
    app = FastAPI()
    app.include_router(create_mcp_router(storage))
    with TestClient(app) as client:
        summary = client.get('/api/mcp-data/single-id/summary').json()
        assert summary['summary']['total_packets'] == 300
        page = client.get('/api/mcp-data/single-id/query', params={
            'section': 'tcp_analysis', 'pointer': '/sessions', 'offset': 1, 'limit': 1,
        }).json()
        assert page['data'] == [{'session_id': 'b'}]
        assert page['total'] == 2
        history = client.get('/api/mcp-data/history', params={'kind': 'multi'}).json()
        assert history['analyses'][0]['task_id'] == 'multi-id'
        assert client.get('/api/mcp-data/multi-id/query', params={
            'kind': 'multi', 'section': 'analysis', 'pointer': '/sessions/0/hop',
        }).json()['data'] == 2
        assert client.get('/api/mcp-data/single-id/query', params={
            'section': 'tcp_analysis', 'pointer': '/sessions/99',
        }).status_code == 400
        assert client.get('/api/mcp-data/missing/summary').status_code == 404
        assert client.get('/api/mcp-data/single-id/query', params={
            'section': 'metadata',
        }).status_code == 400
        filtered = client.get('/api/mcp-data/single-id/anomalies', params={'severity': 'high', 'source': 'dns'}).json()
        assert filtered['total'] == 1
        assert filtered['data'] == [{'severity': 'high', 'source': 'dns'}]
