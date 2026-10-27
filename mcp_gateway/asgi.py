"""ASGI entrypoint for Vercel; an unconfigured OAuth endpoint stays closed."""
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from pydantic import ValidationError
from .config import GatewaySettings
from .server import create_server


def create_app():
    try:
        return create_server(GatewaySettings.from_env()).streamable_http_app()
    except (KeyError, ValueError, ValidationError):
        async def unavailable(request):
            return JSONResponse({'error': 'MCP OAuth configuration required. See docs/VERCEL_MANAGED.md.'}, status_code=503)
        return Starlette(routes=[Route('/{path:path}', unavailable, methods=['GET', 'POST', 'DELETE'])])

app = create_app()
