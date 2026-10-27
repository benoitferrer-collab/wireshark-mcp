"""Official private Blob SDK behind a narrow, testable object-store boundary."""
import json
from pathlib import Path

class BlobObjects:
    def _sdk(self):
        from vercel.blob import sync
        return sync
    def read_json(self, key):
        from vercel.blob.errors import BlobNotFoundError
        try: return json.loads(self._sdk().get_blob(key, access='private').body)
        except BlobNotFoundError: return None
    def write_json(self, key, value):
        return self._sdk().put_blob(key, json.dumps(value, default=str, separators=(',', ':')).encode(),
                                    access='private', allow_overwrite=True, content_type='application/json', cache_control_max_age=0)
    def head(self, key):
        result = self._sdk().head_blob(key)
        return {'size': result.size, 'pathname': result.pathname}
    def download(self, key, path, max_size=None):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        partial = path.with_suffix(path.suffix + '.part')
        try:
            with self._sdk().stream_blob(key, access='private') as stream, partial.open('wb') as dest:
                total = 0
                for chunk in stream:
                    total += len(chunk)
                    if max_size is not None and total > max_size: raise ValueError('File too large')
                    dest.write(chunk)
            partial.replace(path)
        finally: partial.unlink(missing_ok=True)
    def put_file(self, key, path):
        with Path(path).open('rb') as body:
            self._sdk().put_blob(key, body, access='private', content_length=Path(path).stat().st_size,
                                 allow_overwrite=True, cache_control_max_age=0)
    def keys(self, prefix):
        return [entry.pathname for entry in self._sdk().query_blobs(prefix=prefix)]
    def delete(self, keys):
        if keys: self._sdk().delete_blob(keys)
