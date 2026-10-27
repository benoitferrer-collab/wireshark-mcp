"""Durable manifests and statuses. Queue messages contain only an opaque task ID."""
import re
from datetime import datetime, timezone

MAX_FILE = 100 * 1024 * 1024
MAX_TOTAL = 200 * 1024 * 1024

def valid_id(task_id):
    if not isinstance(task_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', task_id):
        raise ValueError('Invalid task_id')
    return task_id

def validate_capture(task_id, capture):
    pathname = capture.get('pathname', '')
    if not re.fullmatch(r'captures/' + re.escape(valid_id(task_id)) + r'/[A-Za-z0-9][A-Za-z0-9._-]{0,200}\.(pcap|pcapng|cap)', pathname, re.I) or '..' in pathname:
        raise ValueError('Invalid capture pathname')
    filename = capture.get('filename', '')
    if not isinstance(filename, str) or not filename or len(filename) > 255:
        raise ValueError('Invalid filename')
    return pathname

class JobService:
    def __init__(self, objects): self.objects = objects
    def create(self, task_id, captures, kind='single', options=None):
        valid_id(task_id)
        if kind not in ('single', 'multi') or not isinstance(captures, list) or not 1 <= len(captures) <= 8:
            raise ValueError('One to eight captures required')
        if (kind == 'single' and len(captures) != 1) or (kind == 'multi' and len(captures) < 2):
            raise ValueError('Invalid capture count for this job')
        total, normalized = 0, []
        for index, capture in enumerate(captures):
            pathname = validate_capture(task_id, capture)
            size = self.objects.head(pathname)['size']
            if not 0 < size <= MAX_FILE: raise ValueError('Capture exceeds 100 MiB or is empty')
            total += size
            normalized.append({'pathname': pathname, 'filename': capture['filename'], 'size': size,
                               'equipment_name': str(capture.get('equipment_name', 'Capture'))[:100],
                               'position': index + 1, 'comment': str(capture.get('comment', ''))[:500]})
        if total > MAX_TOTAL: raise ValueError('Multi-PCAP exceeds 200 MiB total')
        if self.objects.read_json(f'deleted/{task_id}.json'): raise ValueError('Analysis deleted')
        existing = self.objects.read_json(f'jobs/{task_id}.json')
        if existing:
            if existing['captures'] != normalized or existing['kind'] != kind: raise ValueError('Task ID already used')
            if self.read_status(task_id) is None:
                self.status(task_id, 'queued', 0, 'Analyse en attente du worker Vercel')
            return existing
        options = options or {}
        job = {'task_id': task_id, 'kind': kind, 'captures': normalized,
               'options': {'time_tolerance': max(.2, min(60, float(options.get('time_tolerance', 5)))),
                           'max_packets_per_capture': max(1000, min(250000, int(options.get('max_packets_per_capture', 250000)))),
                           'root_cause_thresholds': options.get('root_cause_thresholds') if isinstance(options.get('root_cause_thresholds'), dict) else {}},
               'created_at': datetime.now(timezone.utc).isoformat()}
        self.objects.write_json(f'jobs/{task_id}.json', job)
        self.status(task_id, 'queued', 0, 'Analyse en attente du worker Vercel')
        return job
    def read_status(self, task_id):
        valid_id(task_id)
        if self.objects.read_json(f'deleted/{task_id}.json'): return None
        return self.objects.read_json(f'status/{task_id}.json')
    def status(self, task_id, status, progress, message):
        valid_id(task_id)
        if self.objects.read_json(f'deleted/{task_id}.json'): return
        self.objects.write_json(f'status/{task_id}.json', {'task_id': task_id, 'status': status,
            'progress': progress, 'message': message, 'updated_at': datetime.now(timezone.utc).isoformat()})
