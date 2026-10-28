import json
import time
from pathlib import Path
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization as S
from app.identity.store import IdentityStore
from app.tls.secrets import validate_secret
from app.tls.jobs import TLSJobs

class Objects:
    def __init__(self): self.data={}
    def read_json(self,key): return self.data.get(key)
    def write_json(self,key,value): self.data[key]=json.loads(json.dumps(value))
    def delete(self,keys):
        for k in keys:self.data.pop(k,None)
    def keys(self,prefix):return [k for k in self.data if k.startswith(prefix)]

KEYLOG=b'CLIENT_RANDOM '+b'a'*64+b' '+b'b'*96+b'\n'
@pytest.fixture
def env(tmp_path):
    objects=Objects()
    objects.write_json('jobs/capture.json',{'kind':'single','captures':[{'pathname':'captures/capture/a.pcap','filename':'a.pcap'}]})
    objects.write_json('status/capture.json',{'status':'completed'})
    store=IdentityStore('sqlite:///'+str(tmp_path/'db'),Fernet.generate_key().decode())
    return TLSJobs(store,objects,Fernet.generate_key().decode()),objects

def test_validates_keylog_and_encrypted_rsa():
    assert validate_secret('keylog',KEYLOG)==KEYLOG
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    encrypted=key.private_bytes(S.Encoding.PEM,S.PrivateFormat.PKCS8,S.BestAvailableEncryption(b'pass'))
    plain=validate_secret('rsa',encrypted,'pass')
    assert b'PRIVATE KEY' in plain and b'ENCRYPTED' not in plain
    with pytest.raises(ValueError):validate_secret('rsa',encrypted,'wrong')
    ec_key=ec.generate_private_key(ec.SECP256R1()).private_bytes(S.Encoding.PEM,S.PrivateFormat.PKCS8,S.NoEncryption())
    with pytest.raises(ValueError):validate_secret('rsa',ec_key)

@pytest.mark.parametrize('kind,body',[('keylog',b'garbage'),('keylog',b'x'*(2097152+1)),('rsa',KEYLOG),('unknown',KEYLOG)])
def test_rejects_bad_secret(kind,body):
    with pytest.raises(ValueError):validate_secret(kind,body)

def test_encrypted_bound_secret_and_latest_generation(env):
    service,objects=env
    first=service.create('capture','owner','keylog',KEYLOG)
    second=service.create('capture','owner','keylog',KEYLOG)
    assert service.material(first['id'])==KEYLOG
    assert KEYLOG.decode().strip() not in json.dumps(objects.data)
    service.complete(first['id'],{'rows':[{'method':'GET'}]})
    assert service.current('capture')['id']==second['id']
    assert service.current('capture')['status']=='queued'
    service.complete(second['id'],{'rows':[]})
    assert service.current('capture')['status']=='completed'
    with pytest.raises(ValueError): service.material(second['id'])

def test_expiry_and_delete_prevent_late_publication(env):
    service,objects=env
    job=service.create('capture','owner','keylog',KEYLOG)
    with service.store.connect() as db:db.execute('UPDATE tls_jobs SET expires=?',(time.time()-1,))
    with pytest.raises(ValueError):service.material(job['id'])
    service.prune()
    assert not objects.keys('tls-secrets/')
    objects.write_json('deleted/capture.json',{'deleted':True})
    service.delete_capture('capture')
    service.complete(job['id'],{'rows':[{'method':'GET'}]})
    assert service.current('capture') is None
    assert not objects.keys('tls-results/')

def test_duplicate_completion_keeps_committed_result(env):
    service,objects=env
    job=service.create('capture','owner','keylog',KEYLOG)
    service.complete(job['id'],{'rows':[{'method':'GET'}]})
    service.complete(job['id'],{'rows':[{'method':'POST'}]})
    assert service.report(service.current('capture'))['rows'][0]['method']=='GET'

def test_deleted_during_secret_or_report_write_is_collected(env):
    service,objects=env
    original=objects.write_json
    def delete_during_write(key,value):
        original(key,value)
        if key.startswith('tls-secrets/') or key.startswith('tls-results/'):
            original('deleted/capture.json',{'deleted':True})
    objects.write_json=delete_during_write
    with pytest.raises(ValueError):service.create('capture','owner','keylog',KEYLOG)
    assert not objects.keys('tls-secrets/')
    objects.data.pop('deleted/capture.json')
    objects.write_json=original
    job=service.create('capture','owner','keylog',KEYLOG)
    objects.write_json=delete_during_write
    service.complete(job['id'],{'rows':[]})
    assert not objects.keys('tls-results/')
    assert not objects.keys('tls-secrets/')

def test_secret_envelope_cannot_be_moved_to_another_job(env):
    service,objects=env
    one=service.create('capture','owner','keylog',KEYLOG)
    two=service.create('capture','owner','keylog',KEYLOG)
    objects.data[f"tls-secrets/{two['id']}.json"]=objects.data[f"tls-secrets/{one['id']}.json"]
    with pytest.raises(ValueError):service.material(two['id'])

def test_worker_preserves_secret_for_retry_and_cleans_terminal_failure(env):
    from app.tls.worker import handle_tls_delivery
    from types import SimpleNamespace
    service,objects=env
    job=service.create('capture','owner','keylog',KEYLOG)
    runner=lambda *a,**kw:SimpleNamespace(returncode=1)
    assert not handle_tls_delivery(job['id'],1,objects,runner,service)
    assert service.material(job['id'])==KEYLOG
    assert handle_tls_delivery(job['id'],3,objects,runner,service)
    assert not objects.keys('tls-secrets/')
    assert service.get(job['id'])['status']=='failed'

def test_timeout_removes_parent_owned_plaintext_scratch(env):
    import subprocess
    from app.tls.worker import handle_tls_delivery
    service,objects=env
    job=service.create('capture','owner','keylog',KEYLOG)
    seen=[]
    def slow(args,**kwargs):
        root=Path(args[-1]);assert root.is_dir()
        (root/'secret-material').write_bytes(KEYLOG);seen.append(root)
        raise subprocess.TimeoutExpired(args,240)
    assert not handle_tls_delivery(job['id'],1,objects,slow,service)
    assert seen and not seen[0].exists()
    assert service.material(job['id'])==KEYLOG

def test_timeout_kills_descendant_processes(tmp_path):
    import subprocess,sys,time
    from app.tls.worker import run_isolated
    heartbeat=tmp_path/'heartbeat'
    grandchild="import time;from pathlib import Path;p=Path("+repr(str(heartbeat))+");\nwhile True:\n with p.open('ab') as f:f.write(b'x')\n time.sleep(.02)"
    child='import subprocess,sys,time;subprocess.Popen([sys.executable,"-c",'+repr(grandchild)+']);time.sleep(10)'
    with pytest.raises(subprocess.TimeoutExpired):run_isolated([sys.executable,'-c',child],timeout=.6,check=False)
    size=heartbeat.stat().st_size
    time.sleep(.15)
    assert heartbeat.stat().st_size==size
