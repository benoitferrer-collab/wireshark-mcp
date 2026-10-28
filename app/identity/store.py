"""Transactional identity state; secrets encrypted, session identifiers hashed."""
import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from uuid import UUID, uuid4
from cryptography.fernet import Fernet


class IdentityStore:
    def __init__(self, url, encryption_key):
        self.url = url
        self.cipher = Fernet(encryption_key.encode())
        with self.connect() as db:
            if not self.url.startswith('sqlite:///'):
                db.execute('SELECT pg_advisory_xact_lock(901922633)')
            for sql in (
                'CREATE TABLE IF NOT EXISTS web_sessions (id TEXT PRIMARY KEY, payload TEXT NOT NULL, expires DOUBLE PRECISION NOT NULL)',
                'CREATE TABLE IF NOT EXISTS identity_policy (id INTEGER PRIMARY KEY, group_id TEXT NOT NULL, version TEXT NOT NULL, changed_by TEXT NOT NULL, changed_at DOUBLE PRECISION NOT NULL)',
                'CREATE TABLE IF NOT EXISTS mcp_activity (id TEXT PRIMARY KEY, client_id TEXT NOT NULL, tool TEXT NOT NULL, success INTEGER NOT NULL, duration_ms INTEGER NOT NULL, occurred DOUBLE PRECISION NOT NULL)',
                'CREATE INDEX IF NOT EXISTS mcp_activity_time ON mcp_activity(occurred)',
                'CREATE TABLE IF NOT EXISTS identity_audit (id TEXT PRIMARY KEY, actor TEXT NOT NULL, group_id TEXT NOT NULL, occurred DOUBLE PRECISION NOT NULL)',
            ): db.execute(sql)
            db.execute("INSERT INTO identity_policy VALUES (1, '', ?, '', ?) ON CONFLICT(id) DO NOTHING", (str(uuid4()), time.time()))

    @contextmanager
    def connect(self):
        if self.url.startswith('sqlite:///'):
            db = sqlite3.connect(self.url[10:], timeout=20)
            db.row_factory = sqlite3.Row
        else:
            import psycopg
            from psycopg.rows import dict_row
            raw = psycopg.connect(self.url, row_factory=dict_row, connect_timeout=5)
            class Adapter:
                def execute(self, sql, values=()): return raw.execute(sql.replace('?', '%s'), values)
            db = Adapter()
        try:
            yield db
            (db if self.url.startswith('sqlite:///') else raw).commit()
        except Exception:
            (db if self.url.startswith('sqlite:///') else raw).rollback()
            raise
        finally: (db if self.url.startswith('sqlite:///') else raw).close()

    @staticmethod
    def _key(value): return hashlib.sha256(value.encode()).hexdigest()

    def save_session(self, session_id, payload, expires):
        encrypted = self.cipher.encrypt(json.dumps(payload).encode()).decode()
        with self.connect() as db:
            db.execute('INSERT INTO web_sessions VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, expires=excluded.expires', (self._key(session_id), encrypted, expires))

    def refresh_session(self, session_id, payload):
        encrypted=self.cipher.encrypt(json.dumps(payload).encode()).decode()
        with self.connect() as db:
            result=db.execute('UPDATE web_sessions SET payload=? WHERE id=? AND expires>?', (encrypted,self._key(session_id),time.time()))
            return result.rowcount == 1

    def get_session(self, session_id):
        if not session_id or len(session_id)>256: return None
        with self.connect() as db:
            row=db.execute('SELECT payload, expires FROM web_sessions WHERE id=?', (self._key(session_id),)).fetchone()
        if not row or row['expires'] <= time.time(): return None
        return json.loads(self.cipher.decrypt(row['payload'].encode()))

    def take_session(self, session_id):
        """Atomically consume OAuth flow to prevent concurrent callback replay."""
        with self.connect() as db:
            row=db.execute('DELETE FROM web_sessions WHERE id=? RETURNING payload, expires', (self._key(session_id),)).fetchone()
        if not row or row['expires'] <= time.time(): return None
        return json.loads(self.cipher.decrypt(row['payload'].encode()))

    def delete_session(self, session_id):
        with self.connect() as db: db.execute('DELETE FROM web_sessions WHERE id=?',(self._key(session_id),))

    def get_policy(self):
        with self.connect() as db: return dict(db.execute('SELECT group_id, version, changed_at FROM identity_policy WHERE id=1').fetchone())

    def set_group(self, group_id, actor):
        group_id=str(UUID(group_id)) if group_id else ''
        with self.connect() as db:
            db.execute('UPDATE identity_policy SET group_id=?, version=?, changed_by=?, changed_at=? WHERE id=1',(group_id,str(uuid4()),actor,time.time()))
            db.execute('INSERT INTO identity_audit VALUES (?, ?, ?, ?)',(str(uuid4()),actor,group_id,time.time()))
        return self.get_policy()

    def record_event(self, event_id, client_id, tool, success, duration_ms, occurred=None):
        with self.connect() as db:
            db.execute('INSERT INTO mcp_activity VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING', (event_id,client_id,tool,int(success),int(duration_ms),occurred if occurred is not None else time.time()))

    def activity(self, now=None):
        now=now if now is not None else time.time()
        today=int(now//86400)*86400
        with self.connect() as db:
            rows=db.execute('SELECT client_id, COUNT(*) AS calls_30d, SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) AS errors_30d, SUM(CASE WHEN occurred>=? THEN 1 ELSE 0 END) AS calls_today, MAX(occurred) AS last_call, MAX(CASE WHEN success=1 THEN occurred ELSE NULL END) AS last_success FROM mcp_activity WHERE occurred>=? GROUP BY client_id',(today,now-30*86400)).fetchall()
            recent=db.execute('SELECT client_id, tool, success, duration_ms, occurred FROM mcp_activity WHERE occurred>=? ORDER BY occurred DESC LIMIT 50',(now-30*86400,)).fetchall()
            first=db.execute('SELECT MIN(occurred) AS started FROM mcp_activity').fetchone()['started']
        return {'clients':[dict(row) for row in rows], 'recent':[dict(row) for row in recent], 'collection_started':first, 'timezone':'UTC', 'recent_window_seconds':900}

    def prune(self, now=None):
        now=now if now is not None else time.time()
        with self.connect() as db:
            result=db.execute('DELETE FROM mcp_activity WHERE occurred<?',(now-30*86400,))
            count=result.rowcount
            db.execute('DELETE FROM web_sessions WHERE expires<=?',(now,))
            db.execute('DELETE FROM identity_audit WHERE occurred<?',(now-30*86400,))
        return count
