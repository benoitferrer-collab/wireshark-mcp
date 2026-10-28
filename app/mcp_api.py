"""Read-only, paged views used by the MCP gateway over the private API."""
import json
from typing import Literal
from fastapi import APIRouter, HTTPException, Query
from app.mcp_views import analysis_summary, query_view
from mcp_gateway.policy import page_value


def create_mcp_router(storage, tls_service=None):
    router = APIRouter(prefix='/api/mcp-data', tags=['MCP evidence'])

    def load(task_id, kind):
        if kind == 'single':
            result = storage.load_results(task_id)
        else:
            path = storage.get_file_path(task_id, 'multi_results.json')
            result = json.loads(path.read_text()) if path else None
        if not result:
            raise HTTPException(404, 'Analysis not found')
        return result

    @router.get('/history')
    def history(kind: Literal['single', 'multi'] = 'single', offset: int = Query(0, ge=0),
                limit: int = Query(20, ge=1, le=100)):
        if kind == 'single':
            entries = storage.get_analysis_history(limit=offset + limit + 1)
        elif getattr(storage, 'managed', False) is True:
            entries = storage.get_multi_history()
        else:
            entries = []
            for directory in storage.results_dir.iterdir():
                if not directory.is_dir():
                    continue
                path = storage.get_file_path(directory.name, 'multi_results.json')
                if path:
                    entries.append({'task_id': directory.name, 'kind': 'multi',
                                    'modified_at': path.stat().st_mtime})
            entries.sort(key=lambda row: row['modified_at'], reverse=True)
        return {'kind': kind, 'analyses': entries[offset:offset + limit],
                'next_offset': offset + limit if len(entries) > offset + limit else None}

    @router.get('/{task_id}/tls-decryption')
    def tls_report(task_id: str, offset: int = Query(0, ge=0), limit: int = Query(25, ge=1, le=25)):
        if tls_service is None: raise HTTPException(503, 'TLS decryption unavailable')
        from app.tls.routes import public_view
        try: return public_view(tls_service, task_id, offset, limit)
        except ValueError: raise HTTPException(400, 'Invalid task or pagination') from None

    @router.get('/{task_id}/summary')
    def summary(task_id: str):
        result = analysis_summary(task_id, load(task_id, 'single'))
        if tls_service:
            job = tls_service.current(task_id)
            result['tls_decryption'] = {'status': job['status'] if job else 'not_requested', 'tool': 'get_tls_decryption'}
        return result

    @router.get('/{task_id}/anomalies')
    def anomalies(task_id: str, severity: str | None = None, source: str | None = None,
                  offset: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
        items = load(task_id, 'single').get('all_anomalies', [])
        if severity:
            items = [item for item in items if str(item.get('severity', '')).lower() == severity.lower()]
        if source:
            items = [item for item in items if str(item.get('source', '')).lower() == source.lower()]
        return {'task_id': task_id, **page_value(items, offset=offset, limit=limit)}

    @router.get('/{task_id}/query')
    def query(task_id: str, section: str, pointer: str = '', kind: Literal['single', 'multi'] = 'single',
              offset: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
        try:
            result = query_view(load(task_id, kind), section, pointer, offset, limit)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        return {'task_id': task_id, 'kind': kind, **result}

    return router
