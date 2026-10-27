"""Persist original StorageService artifacts in Blob, using only disposable scratch."""
import json
from pathlib import Path
from .context import scratch
from .jobs import MAX_FILE, valid_id, validate_capture
from .objects import BlobObjects


def create_cloud_storage(base_class, objects=None, root=None):
    class CloudStorage(base_class):
        managed = True
        @property
        def upload_dir(self): return (scratch.get() or self._root) / 'uploads'
        @upload_dir.setter
        def upload_dir(self, value): pass
        @property
        def results_dir(self): return (scratch.get() or self._root) / 'results'
        @results_dir.setter
        def results_dir(self, value): pass
        def __init__(self):
            self._root = Path(root or '/tmp/pcap-cloud-worker')
            self.objects = objects or BlobObjects()
            super().__init__()
        def deleted(self, task_id):
            valid_id(task_id)
            return bool(self.objects.read_json(f'deleted/{task_id}.json'))
        def _cleanup_if_deleted(self, task_id, keys):
            if self.deleted(task_id): self.objects.delete(keys)
        def save_results(self, task_id, results):
            if self.deleted(task_id): return None
            keys = [f'results/{task_id}/results.json', f'results/{task_id}/summary.json', f'summaries/{task_id}.json']
            try:
                path = super().save_results(task_id, results)
                for filename in ('results.json', 'summary.json'):
                    self.objects.put_file(f'results/{task_id}/{filename}', path.parent / filename)
                summary = json.loads((path.parent / 'summary.json').read_bytes())
                self.objects.write_json(f'summaries/{task_id}.json', summary)
                return path
            finally: self._cleanup_if_deleted(task_id, keys)
        def load_results(self, task_id):
            if self.deleted(task_id): return None
            results = self.objects.read_json(f'results/{task_id}/results.json')
            if results:
                # Export freshness checks expect a local results.json.
                path = self.get_results_path(task_id) / 'results.json'
                path.write_text(json.dumps(results, default=str))
            return results
        def save_derived(self, task_id, name, data):
            if self.deleted(task_id): return
            key = f'results/{task_id}/derived_{self._sanitize_filename(name)}.json'
            try: self.objects.write_json(key, data)
            finally: self._cleanup_if_deleted(task_id, [key])
        def load_derived(self, task_id, name):
            if self.deleted(task_id): return None
            return self.objects.read_json(f'results/{task_id}/derived_{self._sanitize_filename(name)}.json')
        def get_analysis_history(self, limit=50):
            entries = [self.objects.read_json(k) for k in self.objects.keys('summaries/')]
            entries = [r for r in entries if r and not self.deleted(r['task_id'])]
            return sorted(entries, key=lambda r: r.get('timestamp', ''), reverse=True)[:limit]
        def get_multi_history(self):
            entries = [self.objects.read_json(k) for k in self.objects.keys('multi-summaries/')]
            return sorted([r for r in entries if r and not self.deleted(r['task_id'])], key=lambda r: r.get('timestamp', ''), reverse=True)
        def get_pcap_path(self, task_id):
            if self.deleted(task_id): return None
            job = self.objects.read_json(f'jobs/{task_id}.json')
            if not job or job['kind'] != 'single': return None
            capture = job['captures'][0]
            pathname = validate_capture(task_id, capture)
            path = self.get_upload_path(task_id, Path(pathname).name)
            if not path.exists(): self.objects.download(pathname, path, max_size=MAX_FILE)
            return str(path)
        def get_file_path(self, task_id, filename):
            if self.deleted(task_id): return None
            filename = self._sanitize_filename(filename)
            path = self.get_results_path(task_id) / filename
            value = self.objects.read_json(f'results/{task_id}/{filename}')
            if value is None: return None
            path.write_text(json.dumps(value, default=str))
            return path
        def save_multi(self, task_id, payload):
            if self.deleted(task_id): return
            keys = [f'results/{task_id}/multi_results.json', f'multi-summaries/{task_id}.json']
            try:
                self.objects.write_json(keys[0], payload)
                self.objects.write_json(keys[1], {
                    'task_id': task_id, 'kind': 'multi', 'timestamp': payload['generated_at']})
            finally: self._cleanup_if_deleted(task_id, keys)
        def delete_analysis(self, task_id):
            valid_id(task_id)
            self.objects.write_json(f'deleted/{task_id}.json', {'deleted': True})
            keys = self.objects.keys(f'captures/{task_id}/') + self.objects.keys(f'results/{task_id}/')
            keys += [f'summaries/{task_id}.json', f'multi-summaries/{task_id}.json', f'jobs/{task_id}.json', f'status/{task_id}.json']
            self.objects.delete(keys)
            super().delete_analysis(task_id)
            return True
    return CloudStorage()
