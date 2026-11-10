"""Session-only secret submission and safe, paged investigation results."""
import asyncio
import os
import time
from typing import Literal
from fastapi import APIRouter,Request,HTTPException,UploadFile,File,Form,Query
from mcp_gateway.policy import page_value
from app.cloud.jobs import valid_id
from .secrets import LIMITS


def public_view(service,capture,offset=0,limit=25):
    valid_id(capture)
    job=service.current(capture)
    if not job:return {'status':'not_requested','report':None}
    result={key:job[key] for key in ('id','kind','status','created','error')}
    elapsed=max(0,int(time.time()-job['created']))
    result['elapsed_seconds']=elapsed
    result['waiting_delayed']=job['status']=='queued' and elapsed>=90
    if result['waiting_delayed']:
        result['notice']='Prise en charge retardée. Le traitement n’a pas démarré ; vérifiez la disponibilité et les quotas Vercel.'
    progress=service.objects.read_json(f"tls-progress/{job['id']}.json") or {}
    result['attempt']=progress.get('attempt',0)
    result['stage']=progress.get('stage','queued' if job['status']=='queued' else job['status'])
    report=service.report(job)
    result['report']={**{k:v for k,v in report.items() if k!='rows'},**page_value(report.get('rows',[]),offset=offset,limit=limit)} if report else None
    return result


def create_tls_router(service,sender=None,storage=None):
    router=APIRouter()
    def identity(request):
        if not getattr(request.state,'identity',None):raise HTTPException(401,'Connexion Microsoft requise.')
        return request.state.identity
    @router.get('/api/identity/tls/{capture}/preflight')
    def preflight(capture:str,request:Request,kind:Literal['rsa','keylog']=Query('rsa')):
        identity(request)
        if storage is None:raise HTTPException(503,'Vérification TLS indisponible.')
        try:
            valid_id(capture)
            path=storage.get_pcap_path(capture)
            if not path:raise HTTPException(404,'Capture indisponible.')
            from .readiness import inspect_capture
            return inspect_capture(path,kind)
        except ValueError as exc:raise HTTPException(400,str(exc)) from None
    @router.post('/api/identity/tls/{capture}',status_code=202)
    async def submit(capture:str,request:Request,kind:Literal['rsa','keylog']=Form(...),file:UploadFile=File(...),password:str=Form('')):
        actor=identity(request)
        body=await file.read(LIMITS[kind]+1)
        try:
            job=await asyncio.to_thread(service.create,capture,actor['oid'],kind,body,password)
        except ValueError as exc:raise HTTPException(400,str(exc)) from None
        finally:await file.close()
        try:
            if sender:await sender(job['id'])
            else:
                from vercel.queue import QueueClient,ALL_DEPLOYMENTS
                queue=QueueClient(region=os.getenv('PCAP_QUEUE_REGION','iad1'),deployment=ALL_DEPLOYMENTS)
                await queue.send('pcap-tls-decryption',{'kind':'tls','task_id':job['id']},idempotency_key='tls-'+job['id'],retention=86400)
        except Exception:
            await asyncio.to_thread(service.fail,job['id'],'Mise en file indisponible ; réimportez le fichier.')
            raise HTTPException(503,'Mise en file indisponible ; réessayez.') from None
        return {'id':job['id'],'status':'queued'}
    @router.get('/api/identity/tls/{capture}')
    def report(capture:str,request:Request,offset:int=Query(0,ge=0),limit:int=Query(25,ge=1,le=25)):
        identity(request)
        try:return public_view(service,capture,offset,limit)
        except ValueError:raise HTTPException(400,'Identifiant ou pagination invalide.') from None
    return router
