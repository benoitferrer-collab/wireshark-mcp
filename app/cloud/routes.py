import asyncio
import os
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from .jobs import JobService


def create_cloud_router(storage, sender=None):
    router = APIRouter()
    jobs = JobService(storage.objects)

    async def send(task_id):
        if sender is not None: return await sender(task_id)
        from vercel.queue import QueueClient
        queue = QueueClient(region=os.getenv('PCAP_QUEUE_REGION', 'iad1'))
        return await queue.send('pcap-analysis', {'task_id': task_id}, idempotency_key=task_id, retention=86400)

    @router.post('/api/cloud/jobs')
    async def finalize(payload: dict):
        try:
            job = await asyncio.to_thread(jobs.create, payload.get('task_id'), payload.get('captures'),
                                          payload.get('kind', 'single'), payload.get('options'))
            status = await asyncio.to_thread(jobs.read_status, job['task_id'])
            if not status or status['status'] not in ('completed', 'failed'):
                await send(job['task_id'])
        except (ValueError, TypeError, KeyError) as exc:
            raise HTTPException(400, str(exc)) from None
        except Exception:
            raise HTTPException(503, 'Stockage ou file Vercel indisponible ; réessayez la finalisation.') from None
        if status is None:
            raise HTTPException(503, 'Statut indisponible ; réessayez la finalisation avec le même identifiant.')
        return {'task_id': job['task_id'], 'status': status['status'], 'filename': job['captures'][0]['filename'], 'message': status['message']}

    @router.get('/api/status/{task_id}')
    def status(task_id: str):
        try: data = jobs.read_status(task_id)
        except ValueError: raise HTTPException(400, 'Identifiant invalide') from None
        if data is None: raise HTTPException(404, 'Analyse inconnue ou supprimée')
        if data.get('status') in ('queued','processing'):
            try:elapsed=max(0,int((datetime.now(timezone.utc)-datetime.fromisoformat(data['updated_at'])).total_seconds()))
            except (KeyError,ValueError,TypeError):elapsed=0
            data['elapsed_seconds']=elapsed
            data['waiting_delayed']=data['status']=='queued' and elapsed>=90
            if data['waiting_delayed']:
                data['message']='Prise en charge retardée : vérifiez la disponibilité et les quotas Vercel. La capture reste en file.'
            elif data['status']=='processing' and elapsed>=360:
                data['message']='Traitement interrompu ou prolongé ; la file prévoit une nouvelle tentative. Consultez les logs si l’attente persiste.'
        return data

    @router.post('/api/upload')
    @router.post('/api/multi-pcap/analyze')
    def require_direct_upload():
        raise HTTPException(409, 'Utilisez le transfert direct Blob de l’interface (100 Mo par capture).')

    return router
