from types import SimpleNamespace
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.services.diagnosis_feedback import DiagnosisFeedbackStore
from app.services.support_diagnosis_routes import create_support_diagnosis_router


def test_machine_clients_cannot_write_engineer_feedback(monkeypatch,tmp_path):
    from app.services.support_diagnosis import SupportDiagnosis
    monkeypatch.setattr(SupportDiagnosis,'report',lambda *args:{'version':'v1','findings':[{'id':'a'*24,'kind':'tcp_reset','evidence_frames':[1]}],'summary':{}})
    storage=SimpleNamespace(load_results=lambda task: {'exists':True},get_pcap_path=lambda task:tmp_path/'capture.pcap')
    store=DiagnosisFeedbackStore(local_path=tmp_path/'feedback.db')
    app=FastAPI();app.include_router(create_support_diagnosis_router(storage,store))
    client=TestClient(app)
    report=client.get('/api/mcp-data/task/support-diagnosis').json()
    assert report['feedback_available'] is True
    response=client.post('/api/analysis/task/support-diagnosis/feedback',json={'report_id':report['report_id'],'finding_id':'a'*24,'rating':'relevant'})
    assert response.status_code==403
    assert client.get('/api/identity/support-learning-export').status_code==403


def test_local_feedback_rejects_cross_origin_and_requires_real_report(monkeypatch,tmp_path):
    from app.services.support_diagnosis import SupportDiagnosis
    monkeypatch.setattr(SupportDiagnosis,'report',lambda *args:{'version':'v1','findings':[{'id':'a'*24,'kind':'tcp_reset','evidence_frames':[1]}],'summary':{}})
    storage=SimpleNamespace(load_results=lambda task: {'exists':True},get_pcap_path=lambda task:tmp_path/'capture.pcap')
    store=DiagnosisFeedbackStore(local_path=tmp_path/'feedback.db')
    app=FastAPI();app.include_router(create_support_diagnosis_router(storage,store,local_mode=True))
    client=TestClient(app)
    report=client.get('/api/analysis/task/support-diagnosis').json()
    body={'report_id':report['report_id'],'finding_id':'a'*24,'rating':'relevant'}
    assert client.post('/api/analysis/task/support-diagnosis/feedback',json=body,headers={'Origin':'https://attacker.example'}).status_code==403
    assert client.post('/api/analysis/task/support-diagnosis/feedback',json=body,headers={'Origin':'http://testserver'}).json()['saved'] is True
    body['finding_id']='b'*24
    assert client.post('/api/analysis/task/support-diagnosis/feedback',json=body,headers={'Origin':'http://testserver'}).status_code==400
    assert client.get('/api/analysis/task/support-diagnosis?reference_task_id=task').status_code==400
