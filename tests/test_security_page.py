import json
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest


def test_overview_distinguishes_detection_from_validation_and_omits_secrets():
    from app.security_page import security_overview
    env={'MCP_OAUTH_PROVIDER':'entra','MCP_ENTRA_TENANT_ID':'secret-tenant-id',
         'MCP_ALLOWED_SUBJECTS':'secret-owner-id','MCP_BACKEND_URL':'https://internal-private',
         'API_ACCESS_TOKEN':'private-secret','WEB_ENTRA_CLIENT_SECRET':'private-client-secret'}
    result=security_overview(None,env)
    assert result['web']['state']=='disabled'
    assert result['mcp']['state']=='configuration_detected'
    assert result['litellm']['state']=='external'
    assert result['mcp']['authorization']=='subject_allowlist_and_scope'
    assert len(result['tools'])==19
    text=json.dumps(result)
    for value in env.values():
        if value not in {'entra'}: assert value not in text
    assert result['live_security_audit'] is False


def test_security_routes_and_runtime_status_are_not_public_api():
    from app.security_page import create_security_router
    from app.api_auth import APIAccessMiddleware
    app=FastAPI(); app.include_router(create_security_router(None,{}))
    app.add_middleware(APIAccessMiddleware,token='x'*40)
    with TestClient(app) as c:
        assert c.get('/api/security/overview').status_code==401
        r=c.get('/api/security/overview',headers={'Authorization':'Bearer '+'x'*40})
        assert r.status_code==200
        assert r.headers['cache-control']=='no-store'
        page=c.get('/securite')
        assert page.status_code==200
        assert 'Centre de sécurité' in page.text
        assert "script-src 'self'" in page.headers['content-security-policy']


@pytest.mark.asyncio
async def test_security_catalogue_exactly_matches_readonly_mcp_tools():
    from mcp_gateway.catalog import TOOLS
    from mcp_gateway.server import create_server
    from mcp_gateway.config import GatewaySettings
    settings=GatewaySettings(public_url='https://pcap.example/mcp',backend_url='http://127.0.0.1:8000',
        backend_token='x'*40,issuer='https://auth.example/',audience='https://pcap.example/mcp',
        jwks_url='https://auth.example/jwks',allowed_subjects=['owner'])
    advertised=await create_server(settings,verifier=object()).list_tools()
    assert {t['name'] for t in TOOLS}=={t.name for t in advertised}
    assert all(t.annotations.readOnlyHint and not t.annotations.destructiveHint for t in advertised)
