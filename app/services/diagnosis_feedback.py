"""Versioned engineer ratings. Raw captures, credentials and free-form notes are never stored here."""
import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager

RATINGS={'relevant','false_positive','confirmed'}
CAUSES={'unknown','dns','tcp_connectivity','latency','receiver_flow_control','application','tls','capture_artifact','expected_behavior','other'}


class DiagnosisFeedbackStore:
    def __init__(self, identity_store=None, local_path=None):
        self.identity_store,self.local_path=identity_store,local_path
        if not identity_store and not local_path:
            raise ValueError('Persistent feedback storage required')
        with self.connect() as db:
            if identity_store and not identity_store.url.startswith('sqlite:///'):
                db.execute('SELECT pg_advisory_xact_lock(901922634)')
            db.execute('CREATE TABLE IF NOT EXISTS support_reports (task_id TEXT NOT NULL, report_id TEXT NOT NULL, body TEXT NOT NULL, created DOUBLE PRECISION NOT NULL, PRIMARY KEY(task_id,report_id))')
            db.execute('CREATE TABLE IF NOT EXISTS support_feedback (task_id TEXT NOT NULL, report_id TEXT NOT NULL, finding_id TEXT NOT NULL, actor TEXT NOT NULL, rating TEXT NOT NULL, cause TEXT NOT NULL, changed DOUBLE PRECISION NOT NULL, PRIMARY KEY(task_id,report_id,finding_id,actor))')
            db.execute('CREATE TABLE IF NOT EXISTS support_deleted (task_id TEXT PRIMARY KEY)')

    @contextmanager
    def connect(self):
        if self.identity_store:
            with self.identity_store.connect() as db:
                yield db
        else:
            db=sqlite3.connect(self.local_path,timeout=20)
            try:
                db.row_factory=sqlite3.Row
                with db:yield db
            finally:db.close()

    def save_report(self,task_id,report_id,report):
        # Retain numeric learning features and validation IDs only, not network names/addresses or prose.
        snapshot={k:report[k] for k in ('version','summary','coverage','capture_signature','synthetic_demo') if k in report}
        snapshot['findings']=[{'id':f['id'],'kind':f['kind']} for f in report.get('findings',[])]
        body=json.dumps(snapshot,ensure_ascii=True,allow_nan=False)
        if len(body)>150000:
            raise ValueError('Report snapshot too large')
        with self.connect() as db:
            self.lock_task(db,task_id)
            if db.execute('SELECT task_id FROM support_deleted WHERE task_id=?',(task_id,)).fetchone():
                raise ValueError('Capture deleted')
            db.execute('INSERT INTO support_reports VALUES (?,?,?,?) ON CONFLICT(task_id,report_id) DO NOTHING',
                       (task_id,report_id,body,time.time()))

    def report(self,task_id,report_id):
        with self.connect() as db:
            row=db.execute('SELECT body FROM support_reports WHERE task_id=? AND report_id=?',(task_id,report_id)).fetchone()
        return json.loads(row['body']) if row else None

    def rate(self,task_id,report_id,finding_id,actor,rating,cause):
        if rating not in RATINGS or cause not in CAUSES or (rating=='confirmed' and cause=='unknown'):
            raise ValueError('Invalid rating or confirmed cause')
        if rating!='confirmed':cause='unknown'
        report=self.report(task_id,report_id)
        if not report or not any(f['id']==finding_id for f in report.get('findings',[])):
            raise ValueError('Unknown report or finding; regenerate the diagnosis')
        with self.connect() as db:
            self.lock_task(db,task_id)
            if db.execute('SELECT task_id FROM support_deleted WHERE task_id=?',(task_id,)).fetchone():
                raise ValueError('Capture deleted')
            db.execute('INSERT INTO support_feedback VALUES (?,?,?,?,?,?,?) ON CONFLICT(task_id,report_id,finding_id,actor) DO UPDATE SET rating=excluded.rating,cause=excluded.cause,changed=excluded.changed',
                (task_id,report_id,finding_id,actor,rating,cause,time.time()))

    def feedback(self,task_id,report_id,actor):
        with self.connect() as db:
            counts=db.execute('SELECT rating, COUNT(*) AS total FROM support_feedback WHERE task_id=? AND report_id=? GROUP BY rating',(task_id,report_id)).fetchall()
            mine=db.execute('SELECT finding_id,rating,cause FROM support_feedback WHERE task_id=? AND report_id=? AND actor=?',(task_id,report_id,actor)).fetchall()
        return {'counts':{r['rating']:r['total'] for r in counts},
                'mine':{r['finding_id']:{'rating':r['rating'],'cause':r['cause']} for r in mine},
                'usage':'Avis humains non arbitrés ; ils ne constituent pas une vérité terrain automatique ni un modèle entraîné.'}

    def lock_task(self,db,task_id):
        if self.identity_store and not self.identity_store.url.startswith('sqlite:///'):
            key=int(hashlib.sha256(('support:'+task_id).encode()).hexdigest()[:15],16)
            db.execute('SELECT pg_advisory_xact_lock(?)',(key,))
        else:
            db.execute('BEGIN IMMEDIATE')

    def delete_capture(self,task_id):
        with self.connect() as db:
            self.lock_task(db,task_id)
            db.execute('INSERT INTO support_deleted VALUES (?) ON CONFLICT(task_id) DO NOTHING',(task_id,))
            db.execute('DELETE FROM support_feedback WHERE task_id=?',(task_id,))
            db.execute('DELETE FROM support_reports WHERE task_id=?',(task_id,))

    def export_labels(self,limit=500):
        """Owner-only API uses this bounded export; group splitting is mandatory downstream."""
        with self.connect() as db:
            rows=db.execute('SELECT f.task_id,f.report_id,f.finding_id,f.rating,f.cause,r.body FROM support_feedback f JOIN support_reports r ON r.task_id=f.task_id AND r.report_id=f.report_id ORDER BY f.changed DESC LIMIT ?', (min(500,max(1,limit)),)).fetchall()
        result=[]
        allowed=('packets','bytes','rtt_samples','rtt_avg_ms','resets','retransmissions','zero_windows','duration_seconds','dns_error_responses')
        for row in rows:
            report=json.loads(row['body'])
            if report.get('synthetic_demo') is True:continue
            finding=next((f for f in report.get('findings',[]) if f['id']==row['finding_id']),None)
            if not finding:continue
            result.append({'capture_id':hashlib.sha256(row['task_id'].encode()).hexdigest()[:24],
                'capture_signature':report.get('capture_signature'), 'report_id':row['report_id'],
                'finding_id':row['finding_id'],'kind':finding['kind'],'rating':row['rating'],
                'confirmed_cause':row['cause'],'version':report['version'],
                'coverage_complete':bool(report.get('coverage',{}).get('complete')),
                'synthetic_demo':False,
                'features':{key:report['summary'].get(key) for key in allowed},
                'label_status':'unadjudicated_engineer_feedback'})
        return result
