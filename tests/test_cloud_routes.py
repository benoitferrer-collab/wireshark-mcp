from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.cloud.routes import create_cloud_router
from app.cloud.storage import create_cloud_storage
from app.services.storage_service import StorageService
from tests.test_cloud import Objects

def test_finalize_queues_only_task_id_and_reads_durable_status(tmp_path):
    objects = Objects()
    objects.data['captures/abc/source.pcap'] = b'pcap'
    storage = create_cloud_storage(StorageService, objects, tmp_path)
    sent = []
    async def send(task_id): sent.append(task_id)
    app = FastAPI()
    app.include_router(create_cloud_router(storage, send))
    with TestClient(app) as client:
        response = client.post('/api/cloud/jobs', json={'task_id': 'abc', 'captures': [
            {'pathname': 'captures/abc/source.pcap', 'filename': 'source.pcap'}]})
        assert response.status_code == 200, response.text
        assert sent == ['abc']
        assert client.get('/api/status/abc').json()['status'] == 'queued'
        assert client.get('/api/status/missing').status_code == 404
        assert client.post('/api/upload', content=b'file').status_code == 409

def test_delayed_analysis_reports_durable_queue_warning(tmp_path):
    objects=Objects()
    objects.write_json('status/abc.json',{'task_id':'abc','status':'queued','updated_at':'2026-01-01T00:00:00+00:00','message':'Waiting'})
    app=FastAPI();app.include_router(create_cloud_router(create_cloud_storage(StorageService,objects,tmp_path)))
    result=TestClient(app).get('/api/status/abc').json()
    assert result['waiting_delayed'] is True
    assert 'retardée' in result['message']
    assert result['status']=='queued'
