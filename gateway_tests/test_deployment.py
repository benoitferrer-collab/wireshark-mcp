import json
import os
from pathlib import Path
import subprocess
import httpx
import pytest
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route
from app.api_auth import APIAccessMiddleware

ROOT = Path(__file__).resolve().parents[1]

@pytest.mark.asyncio
async def test_api_requires_secret_but_allows_health_and_cors_preflight():
    async def endpoint(request):
        return JSONResponse({'ok': True})
    app = Starlette(routes=[Route('/api/history', endpoint), Route('/api/health', endpoint)])
    app.add_middleware(APIAccessMiddleware, token='x' * 40)
    app.add_middleware(CORSMiddleware, allow_origins=['https://ui.example.com'],
                       allow_methods=['GET'], allow_headers=['Authorization'])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        assert (await client.get('/api/history')).status_code == 401
        assert (await client.get('/api/health')).status_code == 200
        assert (await client.get('/api/history', headers={'Authorization': 'Bearer ' + 'x' * 40})).status_code == 200
        assert (await client.get('/api/history', headers={'Authorization': 'Bearer wrong'})).status_code == 401
        preflight = await client.options('/api/history', headers={
            'Origin': 'https://ui.example.com', 'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': 'authorization',
        })
        assert preflight.status_code == 200
        assert preflight.headers['access-control-allow-origin'] == 'https://ui.example.com'

def test_vercel_build_renders_template_without_leaking_environment_secrets(tmp_path):
    output = tmp_path / 'site'
    result = subprocess.run([
        os.sys.executable, str(ROOT / 'scripts/build_frontend.py'), '--output', str(output),
    ], env={**os.environ, 'PCAP_API_BASE_URL': 'https://api.example.com',
            'API_ACCESS_TOKEN': 'secret-must-not-be-in-build'}, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    html = (output / 'index.html').read_text()
    assert '{{' not in html and '{%' not in html
    assert (output / 'static/js/app.js').exists()
    contents = (output / 'static/js/runtime-config.js').read_text()
    assert 'https://api.example.com' in contents
    assert 'secret-must-not-be-in-build' not in contents + html

def test_vercel_build_rejects_non_https_backend(tmp_path):
    result = subprocess.run([
        os.sys.executable, str(ROOT / 'scripts/build_frontend.py'), '--output', str(tmp_path / 'site'),
    ], env={**os.environ, 'PCAP_API_BASE_URL': 'http://public.example.com'}, capture_output=True)
    assert result.returncode != 0
