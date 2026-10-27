"""Optional access protection for the legacy API; required by production Compose."""
import hmac
from starlette.responses import JSONResponse


class APIAccessMiddleware:
    def __init__(self, app, token: str = ''):
        if token and len(token) < 32:
            raise ValueError('API_ACCESS_TOKEN must contain at least 32 characters')
        self.app = app
        self.token = token

    async def __call__(self, scope, receive, send):
        if self.token and scope['type'] == 'http' and scope['path'].startswith('/api/') and scope['path'] != '/api/health':
            headers = dict(scope.get('headers', []))
            supplied = headers.get(b'authorization', b'')
            expected = ('Bearer ' + self.token).encode('utf-8')
            if not hmac.compare_digest(supplied, expected):
                response = JSONResponse({'detail': 'Authentication required'}, status_code=401,
                                        headers={'WWW-Authenticate': 'Bearer', 'Cache-Control': 'no-store'})
                return await response(scope, receive, send)
        await self.app(scope, receive, send)
