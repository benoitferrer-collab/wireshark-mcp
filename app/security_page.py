"""Authenticated product security explainer. Configuration signals are not audits."""
import os
from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter
from starlette.responses import HTMLResponse, JSONResponse
from mcp_gateway.catalog import TOOLS
from app.services.investigation_service import CaptureInvestigator

ROOT=Path(__file__).resolve().parents[1]


def security_overview(web_settings=None,environ=None):
    env=os.environ if environ is None else environ
    entra=env.get('MCP_OAUTH_PROVIDER')=='entra'
    engine=CaptureInvestigator()
    return {
        'product':'Nomios PcapAnalyzer','generated_at':datetime.now(timezone.utc).isoformat(),
        'live_security_audit':False,
        'web':{'state':'enabled' if web_settings is not None else 'disabled',
               'authorization':'owner_or_configured_group','session_seconds':28800,'group_recheck_seconds':300},
        'mcp':{'state':'configuration_detected' if entra else 'not_detected',
               'authorization':'subject_allowlist_and_scope','scope':'pcap:read',
               'subject_allowlist_configured':bool(env.get('MCP_ALLOWED_SUBJECTS','').strip()),
               'tenant_configured':bool(env.get('MCP_ENTRA_TENANT_ID'))},
        'litellm':{'state':'external','enforcement_verified':False,'mandatory_proxy_enforced':False},
        'activity':{'configured':env.get('MCP_ACTIVITY_ENABLED')=='true','retention_days':30},
        'limits':{'page_size':25,'indicators':25,'input_packets':engine.max_packets,'scan_seconds':engine.timeout,
                  'output_bytes':engine.max_output},
        'tools':TOOLS,
        'notes':['Configuration observée côté application, sans test de connexion ni audit de sécurité.',
                 'Le groupe Web et la liste d’identités MCP sont deux règles distinctes.',
                 'Les captures sont partagées dans l’espace autorisé ; aucune isolation par utilisateur n’est annoncée.',
                 'LiteLLM est externe : son activation et son caractère obligatoire ne sont pas attestés ici.'],
    }


def create_security_router(web_settings=None,environ=None):
    router=APIRouter()

    @router.get('/api/security/overview',tags=['Product security'])
    def overview():
        return JSONResponse(security_overview(web_settings,environ),headers={'Cache-Control':'no-store'})

    @router.get('/securite',response_class=HTMLResponse,include_in_schema=False)
    def page():
        html=(ROOT/'templates/security.html').read_text()
        for token,path in [('SECURITY_CSS','static/css/security.css'),('SECURITY_JS','static/js/security.js')]:
            html=html.replace(token,str((ROOT/path).stat().st_mtime_ns))
        return HTMLResponse(html,headers={'Cache-Control':'no-store',
            'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            'X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin'})

    return router
