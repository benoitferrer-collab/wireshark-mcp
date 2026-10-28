"""Separate process for TLS jobs: plaintext secrets live only in disposable scratch."""
import os
from pathlib import Path
import subprocess
import signal
import time
import sys
import tempfile
from app.cloud.jobs import validate_capture,MAX_FILE
from app.identity.store import IdentityStore
from .jobs import TLSJobs
from .decoder import decode


def from_env(objects):
    store=IdentityStore(os.environ['DATABASE_URL'],os.environ['WEB_SESSION_ENCRYPTION_KEY'])
    return TLSJobs(store,objects,os.environ['TLS_SECRETS_ENCRYPTION_KEY'])


def execute(job_id,service,root):
    job=service.get(job_id)
    if not job or service.deleted(job['capture_id']):return
    secret=service.material(job_id)
    manifest=service.objects.read_json(f"jobs/{job['capture_id']}.json")
    if not manifest or manifest['kind']!='single':raise ValueError('Capture indisponible')
    pathname=validate_capture(job['capture_id'],manifest['captures'][0])
    root=Path(root);root.chmod(0o700)
    path=root/'capture.pcap'
    service.objects.download(pathname,path,max_size=MAX_FILE)
    report=decode(path,job['kind'],secret,root)
    service.complete(job_id,report)


def run_isolated(args,timeout,check=False,**kwargs):
    # The parent owns the process group and scratch even if the child is killed.
    with subprocess.Popen(args,start_new_session=True,**kwargs) as process:
        try:
            code=process.wait(timeout=timeout)
            return subprocess.CompletedProcess(args,code)
        finally:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait()


def handle_tls_delivery(job_id,count,objects,runner=run_isolated,service=None):
    service=service or from_env(objects)
    job=service.get(job_id)
    if not job:return True
    if service.deleted(job['capture_id']):service.delete_capture(job['capture_id']);return True
    if job['status'] in ('completed','failed'):objects.delete([f'tls-secrets/{job_id}.json']);return True
    if job['expires']<=time.time():service.fail(job_id,'Secrets expirés ; importez-les à nouveau.');return True
    service.processing(job_id)
    try:
        with tempfile.TemporaryDirectory(prefix='tls-worker-') as root:
            runner([sys.executable,'-m','app.tls.worker',job_id,root],timeout=240,check=False,
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        current=service.get(job_id)
        if not current or current['status']=='completed' or service.deleted(job['capture_id']):return True
    except (OSError,subprocess.TimeoutExpired):pass
    if count>=3:service.fail(job_id);return True
    return False


if __name__=='__main__':
    from app.cloud.objects import BlobObjects
    try:execute(sys.argv[1],from_env(BlobObjects()),sys.argv[2])
    except Exception:sys.exit(1) # Never print a traceback containing secret-bearing locals.
