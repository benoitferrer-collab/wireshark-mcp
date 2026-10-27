from contextvars import ContextVar
from pathlib import Path
import shutil
import tempfile

scratch = ContextVar('pcap_scratch', default=None)

class ScratchMiddleware:
    """Keep scratch request-scoped and remove it after FileResponse finishes."""
    def __init__(self, app): self.app = app
    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http': return await self.app(scope, receive, send)
        from vercel.headers import set_headers
        set_headers({k.decode('latin1'): v.decode('latin1') for k, v in scope.get('headers', [])})
        root = Path(tempfile.mkdtemp(prefix='pcap-request-'))
        marker = scratch.set(root)
        try: await self.app(scope, receive, send)
        finally:
            scratch.reset(marker)
            shutil.rmtree(root, ignore_errors=True)
