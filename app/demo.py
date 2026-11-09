"""Install a bundled offline PCAP through existing authorized storage paths."""
import json
import shutil
import threading
import uuid
from pathlib import Path
from fastapi import APIRouter, HTTPException

DATA=Path(__file__).with_name('demo_data')
DEMO_NAME='DEMO_Nomios_Support.pcap'
_lock=threading.Lock()

def install_demo(storage):
    with _lock:
        for entry in storage.get_analysis_history(limit=None):
            if entry.get('filename')!=DEMO_NAME or not str(entry.get('task_id','')).startswith('demo-support-'):
                continue
            task_id=entry['task_id']
            result=storage.load_results(task_id)
            if result and result.get('metadata',{}).get('demo_version')==2 and result['metadata'].get('demo') is True and storage.get_pcap_path(task_id):
                return {'task_id':task_id,'synthetic':True,'reused':True,'packets':192}
        task_id='demo-support-'+uuid.uuid4().hex
        capture=storage.get_upload_path(task_id,DEMO_NAME)
        shutil.copyfile(DATA/DEMO_NAME,capture)
        result=json.loads((DATA/'results.json').read_text())
        result['metadata']['pcap_path']=str(capture)
        result.get('streams',{}).update({'pcap_path':str(capture)})
        if hasattr(storage,'objects'):
            from app.cloud.jobs import JobService
            pathname=f'captures/{task_id}/{DEMO_NAME}'
            storage.objects.put_file(pathname,capture)
            jobs=JobService(storage.objects)
            jobs.create(task_id,[{'pathname':pathname,'filename':DEMO_NAME}],kind='single')
        storage.save_results(task_id,result)
        if hasattr(storage,'objects'):
            jobs.status(task_id,'completed',100,'Démonstration synthétique prête')
        return {'task_id':task_id,'synthetic':True,'reused':False,'packets':192}

def demo_evidence(storage, task_id):
    from app.services.storage_service import _validate_task_id
    from app.services.investigation_service import CaptureInvestigator
    _validate_task_id(task_id)
    if not task_id.startswith('demo-support-'):raise ValueError('Not a demo capture')
    result=storage.load_results(task_id)
    if not result or result.get('metadata',{}).get('demo') is not True:raise ValueError('Not a demo capture')
    path=storage.get_pcap_path(task_id)
    if not path:raise ValueError('Demo capture unavailable')
    rows,coverage=CaptureInvestigator().scan(path,'tcp.flags.reset == 1 || dns.flags.rcode == 3 || http.response.code == 200')
    def facts(predicate):
        matching=[r for r in rows if predicate(r)]
        return {'count':len(matching),'frames':[r['frame_number'] for r in matching]}
    return {'task_id':task_id,'coverage':coverage,
            'resets':facts(lambda r:r['tcp_reset']),
            'dns_errors':facts(lambda r:r['dns_response'] and r['dns_rcode']==3),
            'http_ok':facts(lambda r:r['http_status']==200),
            'root_cause':'not_established'}

def create_demo_router(storage):
    router=APIRouter()
    @router.post('/api/demo/start',tags=['Support demo'])
    def start():
        # Existing WebIdentity/API middleware provides authorization and CSRF.
        try:return install_demo(storage)
        except Exception:
            raise HTTPException(503,'La démonstration ne peut pas être préparée. Réessayez dans un instant.') from None
    @router.get('/api/demo/{task_id}/evidence',tags=['Support demo'])
    def evidence(task_id: str):
        try:return demo_evidence(storage,task_id)
        except ValueError:raise HTTPException(404,'Capture de démonstration indisponible') from None
        except Exception:raise HTTPException(503,'Lecture des preuves indisponible ; réessayez.') from None
    return router
