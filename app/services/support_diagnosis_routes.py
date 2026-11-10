"""Shared read-only diagnosis and web-identity-only engineer feedback."""
from typing import Literal
from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from app.services.storage_service import _validate_task_id
from app.services.investigation_service import InvestigationError
from app.services.support_diagnosis import SupportDiagnosis, report_identity


class FeedbackInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    report_id:str=Field(min_length=1,max_length=24,pattern=r'^[a-f0-9]+$')
    finding_id:str=Field(min_length=1,max_length=24,pattern=r'^[a-f0-9]+$')
    rating:Literal['relevant','false_positive','confirmed']
    cause:Literal['unknown','dns','tcp_connectivity','latency','receiver_flow_control','application','tls','capture_artifact','expected_behavior','other']='unknown'


def create_support_diagnosis_router(storage, feedback_store=None, web_settings=None, local_mode=False):
    router=APIRouter(tags=['Diagnostic support'])
    service=SupportDiagnosis()

    def path(task):
        try:_validate_task_id(task)
        except ValueError:raise HTTPException(400,'Identifiant de capture invalide') from None
        if not storage.load_results(task):raise HTTPException(404,'Analyse introuvable')
        result=storage.get_pcap_path(task)
        if not result:raise HTTPException(404,'PCAP original indisponible ; diagnostic corrélé impossible')
        return result

    def actor(request,write=False):
        identity=getattr(request.state,'identity',None)
        if identity and identity.get('oid'):return identity['oid']
        if local_mode:
            if write and request.headers.get('origin')!=str(request.base_url).rstrip('/'):
                raise HTTPException(403,'Origine locale requise')
            return 'local-engineer'
        raise HTTPException(403,'Une session web Microsoft Entra est requise pour les avis ingénieur')

    def generate(task,reference=None):
        current_path=path(task)
        if reference==task:raise HTTPException(400,'Choisissez une autre capture de référence')
        reference_path=path(reference) if reference else None
        try:result=service.report(current_path,reference_path)
        except InvestigationError:
            raise HTTPException(503,'Moteur occupé ou capture illisible ; réessayez.') from None
        result.update(task_id=task,reference_task_id=reference)
        metadata=(storage.load_results(task) or {}).get('metadata',{})
        result['synthetic_demo']=metadata.get('demo') is True or task=='engineering-demo'
        result['report_id']=report_identity(task,result,reference)
        for finding in result['findings']:
            finding['evidence']=[{'frame_number':frame,'evidence_url':f'/?task={task}#tab=packets&packet={frame-1}'} for frame in finding['evidence_frames']]
        if feedback_store:
            try:feedback_store.save_report(task,result['report_id'],result)
            except Exception:
                # Evidence remains available during a database outage, writes stay disabled.
                result['feedback_available']=False
            else:result['feedback_available']=True
        else:result['feedback_available']=False
        return result

    @router.get('/api/analysis/{task_id}/support-diagnosis')
    def diagnosis(task_id:str,response:Response,reference_task_id:str|None=Query(None,max_length=64)):
        response.headers['Cache-Control']='no-store'
        return generate(task_id,reference_task_id)

    @router.get('/api/mcp-data/{task_id}/support-diagnosis')
    def mcp_diagnosis(task_id:str,response:Response,reference_task_id:str|None=Query(None,max_length=64),
                      offset:int=Query(0,ge=0),limit:int=Query(5,ge=1,le=25)):
        response.headers['Cache-Control']='no-store'
        result=generate(task_id,reference_task_id)
        findings=result['findings']
        result['findings']=findings[offset:offset+limit]
        result['listed_findings']=len(findings)
        result['next_offset']=offset+limit if offset+limit<len(findings) else None
        # Detailed session metrics remain available via the dedicated TCP/search tools.
        result.pop('sessions',None)
        result.pop('stage_metrics',None)
        return result

    @router.get('/api/analysis/{task_id}/support-diagnosis/feedback')
    def feedback(task_id:str,report_id:str,request:Request,response:Response):
        response.headers['Cache-Control']='no-store'
        who=actor(request)
        if not feedback_store:raise HTTPException(503,'Stockage des avis indisponible')
        # Access is still checked if a capture has been removed since the snapshot.
        path(task_id)
        return feedback_store.feedback(task_id,report_id,who)

    @router.post('/api/analysis/{task_id}/support-diagnosis/feedback')
    def rate(task_id:str,body:FeedbackInput,request:Request):
        who=actor(request,write=True)
        if not feedback_store:raise HTTPException(503,'Stockage des avis indisponible')
        path(task_id)
        try:feedback_store.rate(task_id,body.report_id,body.finding_id,who,body.rating,body.cause)
        except ValueError:raise HTTPException(400,'Avis invalide ou diagnostic inconnu ; sélectionnez une cause pour une confirmation.') from None
        return {'saved':True,**feedback_store.feedback(task_id,body.report_id,who)}

    @router.get('/api/identity/support-learning-export')
    def export(request:Request,response:Response):
        who=actor(request)
        if web_settings and who!=web_settings.owner_oid:raise HTTPException(403,'Administrateur requis')
        if not web_settings and not local_mode:raise HTTPException(403,'Administrateur requis')
        if not feedback_store:raise HTTPException(503,'Stockage des avis indisponible')
        response.headers['Cache-Control']='no-store'
        return {'data':feedback_store.export_labels(),'limit':500,'adjudication_required':True,
                'note':'Avis non arbitrés. Définir incident_id, split et label après revue humaine ; aucune donnée n’est envoyée à un LLM.'}

    return router
