"""Transactional generations and encrypted, expiring private Blob secrets."""
import base64
import json
import time
from uuid import uuid4
from cryptography.fernet import Fernet
from app.cloud.jobs import valid_id
from .secrets import validate_secret

class TLSJobs:
    def __init__(self,store,objects,key):
        self.store,self.objects,self.cipher=store,objects,Fernet(key.encode())
        with store.connect() as db:
            if not store.url.startswith('sqlite:///'):db.execute('SELECT pg_advisory_xact_lock(901922634)')
            db.execute('CREATE TABLE IF NOT EXISTS tls_jobs (id TEXT PRIMARY KEY, capture_id TEXT NOT NULL, actor TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, created DOUBLE PRECISION NOT NULL, expires DOUBLE PRECISION NOT NULL, error TEXT NOT NULL)')
            db.execute('CREATE INDEX IF NOT EXISTS tls_jobs_capture ON tls_jobs(capture_id)')
            db.execute('CREATE TABLE IF NOT EXISTS tls_current (capture_id TEXT PRIMARY KEY, job_id TEXT NOT NULL)')
    def deleted(self,capture):return bool(self.objects.read_json(f'deleted/{valid_id(capture)}.json'))
    def get(self,job_id):
        with self.store.connect() as db:row=db.execute('SELECT * FROM tls_jobs WHERE id=?',(valid_id(job_id),)).fetchone()
        return dict(row) if row else None
    def current(self,capture):
        if self.deleted(capture):return None
        with self.store.connect() as db:
            row=db.execute('SELECT j.* FROM tls_jobs j JOIN tls_current c ON c.job_id=j.id WHERE c.capture_id=?',(capture,)).fetchone()
        return dict(row) if row else None
    def create(self,capture,actor,kind,body,password=''):
        valid_id(capture)
        manifest=self.objects.read_json(f'jobs/{capture}.json')
        status=self.objects.read_json(f'status/{capture}.json')
        if self.deleted(capture) or not manifest or manifest['kind']!='single' or not status or status['status']!='completed':
            raise ValueError('Choisissez une capture individuelle dont l’analyse est terminée.')
        material=validate_secret(kind,body,password)
        job_id=str(uuid4());now=time.time();expires=now+86400
        key=f'tls-secrets/{job_id}.json'
        envelope={'id':job_id,'capture_id':capture,'kind':kind,'expires':expires,'secret':base64.b64encode(material).decode()}
        self.objects.write_json(key,{'encrypted':self.cipher.encrypt(json.dumps(envelope).encode()).decode(),'expires':expires})
        try:
            with self.store.connect() as db:
                db.execute('INSERT INTO tls_jobs VALUES (?,?,?,?,?,?,?,?)',(job_id,capture,actor,kind,'queued',now,expires,''))
                db.execute('INSERT INTO tls_current VALUES (?,?) ON CONFLICT(capture_id) DO UPDATE SET job_id=excluded.job_id',(capture,job_id))
        except Exception:
            self.objects.delete([key]);raise
        if self.deleted(capture):
            self.delete_capture(capture);raise ValueError('Capture supprimée.')
        return self.get(job_id)
    def material(self,job_id):
        job=self.get(job_id)
        if not job or self.deleted(job['capture_id']) or job['expires']<=time.time() or job['status'] not in ('queued','processing'):
            raise ValueError('Secret expiré ou traitement terminé.')
        obj=self.objects.read_json(f'tls-secrets/{job_id}.json')
        if not obj:raise ValueError('Secret indisponible.')
        envelope=json.loads(self.cipher.decrypt(obj['encrypted'].encode()))
        if any(envelope[k]!=job[k] for k in ('id','capture_id','kind','expires')):raise ValueError('Secret incompatible.')
        return base64.b64decode(envelope['secret'],validate=True)
    def processing(self,job_id):
        with self.store.connect() as db:db.execute("UPDATE tls_jobs SET status='processing' WHERE id=? AND status IN ('queued','processing')",(job_id,))
    def report(self,job):
        return self.objects.read_json(f"tls-results/{job['id']}.json") if job and job['status']=='completed' and not self.deleted(job['capture_id']) else None
    def complete(self,job_id,report):
        job=self.get(job_id)
        if not job:return
        key=f'tls-results/{job_id}.json'
        if self.deleted(job['capture_id']):self.delete_capture(job['capture_id']);return
        with self.store.connect() as db:
            # Serialize duplicate deliveries before publishing the immutable report.
            claimed=db.execute("UPDATE tls_jobs SET status=status WHERE id=? AND status IN ('queued','processing')",(job_id,)).rowcount
            if not claimed:return
            self.objects.write_json(key,report)
            db.execute("UPDATE tls_jobs SET status='completed', error='' WHERE id=?",(job_id,))
        if self.deleted(job['capture_id']):self.objects.delete([key])
        self.objects.delete([f'tls-secrets/{job_id}.json'])
    def fail(self,job_id,message='Déchiffrement impossible ; vérifiez le fichier et la compatibilité TLS.'):
        with self.store.connect() as db:db.execute("UPDATE tls_jobs SET status='failed',error=? WHERE id=? AND status IN ('queued','processing')",(message,job_id))
        self.objects.delete([f'tls-secrets/{job_id}.json'])
    def delete_capture(self,capture):
        with self.store.connect() as db:
            rows=db.execute('DELETE FROM tls_jobs WHERE capture_id=? RETURNING id',(capture,)).fetchall()
            db.execute('DELETE FROM tls_current WHERE capture_id=?',(capture,))
        self.objects.delete([key for row in rows for key in (f"tls-secrets/{row['id']}.json",f"tls-results/{row['id']}.json")])
    def prune(self):
        with self.store.connect() as db:rows=db.execute('SELECT id FROM tls_jobs WHERE expires<=?',(time.time(),)).fetchall()
        for row in rows:self.fail(row['id'],'Secrets expirés ; importez-les à nouveau.')
        # Also collect blobs orphaned by a crash before the transaction committed.
        for key in self.objects.keys('tls-secrets/'):
            obj=self.objects.read_json(key)
            if obj and obj.get('expires',0)<=time.time():self.objects.delete([key])
