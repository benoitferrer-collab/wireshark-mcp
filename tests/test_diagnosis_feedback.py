import pytest
from app.services.diagnosis_feedback import DiagnosisFeedbackStore


def test_feedback_is_report_scoped_actor_specific_and_upserted(tmp_path):
    store=DiagnosisFeedbackStore(local_path=tmp_path/'feedback.db')
    store.save_report('task','report',{'version':'v1','findings':[{'id':'finding','kind':'tcp_reset'}],'summary':{}})
    store.rate('task','report','finding','alice','relevant','unknown')
    store.rate('task','report','finding','alice','false_positive','unknown')
    store.rate('task','report','finding','bob','confirmed','application')
    result=store.feedback('task','report','alice')
    assert result['counts']=={'false_positive':1,'confirmed':1}
    assert result['mine']['finding']['rating']=='false_positive'
    assert 'bob' not in str(result)
    with pytest.raises(ValueError):store.rate('other','report','finding','alice','relevant','unknown')
    with pytest.raises(ValueError):store.rate('task','report','invented','alice','relevant','unknown')
    with pytest.raises(ValueError):store.rate('task','report','finding','alice','invented','unknown')


def test_confirmed_requires_explicit_cause_and_export_has_no_user_identity(tmp_path):
    store=DiagnosisFeedbackStore(local_path=tmp_path/'feedback.db')
    store.save_report('task','report',{'version':'v1','findings':[{'id':'finding','kind':'tcp_reset'}],'summary':{'packets':4}})
    with pytest.raises(ValueError):store.rate('task','report','finding','alice','confirmed','unknown')
    store.rate('task','report','finding','alice','confirmed','application')
    exported=store.export_labels()
    assert len(exported)==1
    assert 'alice' not in str(exported)
    assert exported[0]['rating']=='confirmed'
    assert exported[0]['confirmed_cause']=='application'


def test_snapshot_omits_network_names_and_delete_prevents_late_resurrection(tmp_path):
    store=DiagnosisFeedbackStore(local_path=tmp_path/'feedback.db')
    report={'version':'v1','findings':[{'id':'finding','kind':'dns_error','facts':['private.example']}],
            'summary':{'packets':4},'stage_metrics':{'data':[{'service':'private.example:53'}]}}
    store.save_report('task','report',report)
    assert 'private.example' not in str(store.report('task','report'))
    store.rate('task','report','finding','alice','relevant','unknown')
    store.delete_capture('task')
    assert store.report('task','report') is None
    assert store.export_labels()==[]
    with pytest.raises(ValueError):store.save_report('task','late',report)
    with pytest.raises(ValueError):store.rate('task','report','finding','alice','relevant','unknown')


def test_capture_deletion_removes_feedback_through_storage_hook(tmp_path):
    from types import SimpleNamespace
    from app.services.storage_service import StorageService
    feedback=DiagnosisFeedbackStore(local_path=tmp_path/'feedback.db')
    feedback.save_report('task','report',{'version':'v1','findings':[{'id':'finding','kind':'dns_error'}],'summary':{}})
    storage=StorageService.__new__(StorageService)
    storage.diagnosis_feedback_store=feedback
    storage._results_cache=SimpleNamespace(invalidate=lambda task:None)
    storage.results_dir=tmp_path/'results';storage.upload_dir=tmp_path/'uploads'
    (storage.results_dir/'task').mkdir(parents=True)
    (storage.upload_dir/'task').mkdir(parents=True)
    assert storage.delete_analysis('task') is True
    assert feedback.report('task','report') is None
    assert not (storage.results_dir/'task').exists()


def test_synthetic_demo_votes_do_not_enter_learning_export(tmp_path):
    store=DiagnosisFeedbackStore(local_path=tmp_path/'feedback.db')
    store.save_report('demo','report',{'version':'v1','synthetic_demo':True,'findings':[{'id':'finding','kind':'tcp_reset'}],'summary':{}})
    store.rate('demo','report','finding','alice','relevant','unknown')
    assert store.feedback('demo','report','alice')['counts']['relevant']==1
    assert store.export_labels()==[]
