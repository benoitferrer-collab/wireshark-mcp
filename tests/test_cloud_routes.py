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

def test_push_publish_uses_current_deployment_partition(monkeypatch,tmp_path):
    from vercel.queue import QueueClient
    calls=[]
    async def send(self,*args,**kwargs):
        calls.append(self.deployment)
    monkeypatch.setattr(QueueClient,'send',send)
    monkeypatch.setenv('VERCEL_REGION','iad1')
    objects=Objects();objects.data['captures/abc/source.pcap']=b'pcap'
    app=FastAPI();app.include_router(create_cloud_router(create_cloud_storage(StorageService,objects,tmp_path)))
    response=TestClient(app).post('/api/cloud/jobs',json={'task_id':'abc','captures':[{'pathname':'captures/abc/source.pcap','filename':'source.pcap'}]})
    assert response.status_code==200,response.text
    from vercel.queue import CURRENT_DEPLOYMENT
    assert calls==[CURRENT_DEPLOYMENT]

def test_stalled_retry_needs_browser_identity_and_refuses_active_jobs(tmp_path):
    from starlette.requests import Request
    from app.cloud.jobs import JobService
    objects=Objects();jobs=JobService(objects)
    jobs.status('abc','processing',10,'Active')
    objects.write_json('jobs/abc.json',{'task_id':'abc'})
    sent=[]
    async def sender(task):sent.append(task)
    app=FastAPI();app.include_router(create_cloud_router(create_cloud_storage(StorageService,objects,tmp_path),sender))
    client=TestClient(app)
    assert client.post('/api/identity/analysis/abc/retry').status_code==401
    app=FastAPI();app.include_router(create_cloud_router(create_cloud_storage(StorageService,objects,tmp_path),sender))
    @app.middleware('http')
    async def identify(request,call_next):
        request.state.identity={'oid':'owner'}
        return await call_next(request)
    client=TestClient(app)
    assert client.post('/api/identity/analysis/abc/retry').status_code==409
    objects.write_json('status/abc.json',{'task_id':'abc','status':'queued','updated_at':'2026-01-01T00:00:00+00:00'})
    assert client.post('/api/identity/analysis/abc/retry').status_code==202
    assert sent==['abc']
    assert jobs.read_status('abc')['status']=='queued'
