from fastapi import FastAPI
from fastapi.testclient import TestClient

def test_support_library_includes_older_captures_and_validates_explicit_limit(monkeypatch):
    from app.api import routes
    entries = [{'task_id': f'capture-{i}', 'filename': f'capture-{i}.pcap'} for i in range(61)]
    monkeypatch.setattr(routes.storage_service, 'get_analysis_history', lambda limit=None: entries[:limit])
    app = FastAPI()
    app.include_router(routes.router)
    with TestClient(app) as client:
        response = client.get('/api/history')
        assert response.status_code == 200
        assert len(response.json()['history']) == 61
        assert response.json()['history'][-1]['task_id'] == 'capture-60'
        assert len(client.get('/api/history?limit=20').json()['history']) == 20
        assert client.get('/api/history?limit=-1').status_code == 422
