"""One polling daemon; each analysis runs in a fresh process to release Scapy memory."""
import asyncio
import os
import signal
import subprocess
import sys
from .jobs import JobService, valid_id
from .objects import BlobObjects


def handle_delivery(task_id, delivery_count, objects, runner=subprocess.run):
    valid_id(task_id)
    jobs = JobService(objects)
    if objects.read_json(f'deleted/{task_id}.json'): return True
    status = jobs.read_status(task_id)
    if status and status['status'] in ('completed', 'failed'): return True
    jobs.status(task_id, 'processing', 10, 'Analyse en cours sur Vercel')
    try:
        process = runner([sys.executable, '-m', 'app.cloud.run_job', task_id], timeout=1200, check=False)
        if process.returncode == 0:
            completed = jobs.read_status(task_id)
            if completed and completed['status'] == 'completed': return True
            if objects.read_json(f'deleted/{task_id}.json'): return True
    except (subprocess.TimeoutExpired, OSError): pass
    if delivery_count >= 3:
        jobs.status(task_id, 'failed', 100, 'Analyse échouée après trois tentatives (fichier invalide, délai ou mémoire).')
        return True
    jobs.status(task_id, 'processing', 10, 'Le worker relancera cette analyse après un échec.')
    return False


POLL_WAIT_SECONDS=15

async def poll_cycle(queue,objects):
    for topic in ('pcap-analysis','pcap-tls-decryption'):
        iterator=None
        try:
            iterator=queue.poll(topic,'pcap-worker',limit=1,lease_duration=300)
            # Bound only the receive, never the analysis/decoder running afterward.
            async with asyncio.timeout(POLL_WAIT_SECONDS):
                delivery=await anext(iterator,None)
            if delivery is None:continue
            async with delivery as message:
                payload=message.payload
                task_id=payload['task_id']
                print('Worker received '+topic,flush=True)
                if payload.get('kind')=='tls':
                    from app.tls.worker import handle_tls_delivery
                    done=await asyncio.to_thread(handle_tls_delivery,task_id,message.metadata.delivery_count,objects)
                else:
                    done=await asyncio.to_thread(handle_delivery,task_id,message.metadata.delivery_count,objects)
                if not done:
                    from vercel.queue import RetryAfter
                    raise RetryAfter(30)
                print('Worker completed '+topic,flush=True)
        except Exception as exc:
            print('Queue retry '+topic+': '+type(exc).__name__,flush=True)
        finally:
            if iterator is not None:await iterator.aclose()



async def main():
    from vercel.queue import QueueClient,ALL_DEPLOYMENTS
    queue=QueueClient(region=os.getenv('PCAP_QUEUE_REGION','iad1'),deployment=ALL_DEPLOYMENTS)
    objects=BlobObjects();stop=asyncio.Event();loop=asyncio.get_running_loop()
    for sig in (signal.SIGTERM,signal.SIGINT):loop.add_signal_handler(sig,stop.set)
    print('Worker ready: PCAP and TLS',flush=True)
    while not stop.is_set():
        await poll_cycle(queue,objects)
        try:await asyncio.wait_for(stop.wait(),timeout=5)
        except TimeoutError:pass

if __name__=='__main__':asyncio.run(main())
