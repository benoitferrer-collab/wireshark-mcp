"""Read-only, paged views used by the MCP gateway over the private API."""
import json
from typing import Literal
from fastapi import APIRouter, HTTPException, Query
from app.mcp_views import analysis_summary, query_view
from mcp_gateway.policy import page_value
from app.services.storage_service import _validate_task_id
from app.services.investigation_service import CaptureInvestigator, SearchFilters, InvestigationError, PRESETS
from app.investigation_views import attach_references, correlate, compare
import os
import shutil


def create_mcp_router(storage, tls_service=None):
    router = APIRouter(prefix='/api/mcp-data', tags=['MCP evidence'])

    def load(task_id, kind):
        try: _validate_task_id(task_id)
        except ValueError: raise HTTPException(400, 'Invalid task ID') from None
        if kind == 'single':
            result = storage.load_results(task_id)
        else:
            path = storage.get_file_path(task_id, 'multi_results.json')
            result = json.loads(path.read_text()) if path else None
        if not result:
            raise HTTPException(404, 'Analysis not found')
        return result

    engine=CaptureInvestigator()

    def capture_path(task_id):
        load(task_id,'single')
        path=storage.get_pcap_path(task_id)
        if not path: raise HTTPException(404,'Original capture unavailable; stored analysis tools remain available')
        return path

    def filters_from_json(value):
        try: return SearchFilters.model_validate_json(value)
        except ValueError: raise HTTPException(400,'Invalid search filters; use the advertised typed schema') from None

    def run(action,task_id):
        try: return attach_references(action(),task_id)
        except InvestigationError as exc:
            raise HTTPException(503 if 'unavailable' in str(exc) or 'busy' in str(exc) else 400,str(exc)) from None
        except ValueError:
            raise HTTPException(400,'Invalid investigation parameters') from None

    @router.get('/{task_id}/capabilities')
    def capabilities(task_id: str):
        results=load(task_id,'single')
        return {'task_id':task_id,'engine_available':bool(os.getenv('TSHARK_PATH') or shutil.which('tshark')),
                'original_capture_available':bool(storage.get_pcap_path(task_id)),
                'packet_index':analysis_summary(task_id,results)['packet_index'],
                'limits':{'page_size':25,'indicators':25,'input_packets':engine.max_packets,
                          'scan_seconds':engine.timeout,'output_bytes':engine.max_output},
                'triage_presets':list(PRESETS),'packet_index_base':0,'frame_number_base':1,
                'workflow':['summary','triage_capture','search_packets','get_conversations','correlate_entity'],
                'privacy':'Protocol metadata only; secrets, raw payload and HTTP query strings are not returned.'}

    @router.get('/{task_id}/search')
    def search(task_id: str, filters: str = Query('{}',max_length=4096),
               after_frame: int = Query(0,ge=0), limit: int = Query(25,ge=1,le=25)):
        parsed=filters_from_json(filters)
        return run(lambda:engine.search(capture_path(task_id),parsed,after_frame,limit),task_id)

    @router.get('/{task_id}/conversations')
    def conversations(task_id: str, filters: str = Query('{}',max_length=4096),
                      offset: int = Query(0,ge=0),limit: int = Query(25,ge=1,le=25),
                      sort_by: Literal['bytes','packets','resets','retransmissions'] = 'bytes'):
        parsed=filters_from_json(filters)
        return run(lambda:engine.conversations(capture_path(task_id),parsed,offset,limit,sort_by),task_id)

    @router.get('/{task_id}/hunt')
    def hunt(task_id: str, indicators: str = Query(...,max_length=8192)):
        try:
            values=json.loads(indicators)
            if not isinstance(values,list) or not 1<=len(values)<=25 or any(not isinstance(v,str) or len(v)>253 for v in values):
                raise ValueError()
            from mcp_gateway.search_schema import normalize_indicator
            for value in values: normalize_indicator(value)
        except (ValueError,UnicodeError): raise HTTPException(400,'Provide 1..25 valid IP, CIDR or DNS indicators') from None
        return run(lambda:engine.hunt(capture_path(task_id),values),task_id)

    @router.get('/{task_id}/triage')
    def triage(task_id: str,preset: Literal['tcp-failures','dns-failures','cleartext','remote-access','tls-handshakes'],
               after_frame: int = Query(0,ge=0),limit: int = Query(25,ge=1,le=25)):
        return run(lambda:engine.triage(capture_path(task_id),preset,after_frame,limit),task_id)

    @router.get('/{task_id}/correlate')
    def correlation(task_id: str,entity: str = Query(...,min_length=1,max_length=253),
                    offset: int = Query(0,ge=0),limit: int = Query(25,ge=1,le=25)):
        try: return correlate(task_id,load(task_id,'single'),entity,offset,limit)
        except ValueError: raise HTTPException(400,'Invalid IP, CIDR or domain') from None

    @router.get('/{task_id}/compare')
    def comparison(task_id: str,other_task_id: str):
        return compare(task_id,load(task_id,'single'),other_task_id,load(other_task_id,'single'))

    @router.get('/{task_id}/statistics')
    def statistics(task_id: str,group_by: Literal['source','destination','dns','tls','http','transport','timeline'],
                   filters: str = Query('{}',max_length=4096),offset: int = Query(0,ge=0),limit: int = Query(25,ge=1,le=25)):
        parsed=filters_from_json(filters)
        return run(lambda:engine.statistics(capture_path(task_id),parsed,group_by,offset,limit),task_id)

    @router.get('/{task_id}/context')
    def context(task_id: str,packet_index: int = Query(...,ge=0,lt=250000),radius: int = Query(5,ge=0,le=10)):
        filters=SearchFilters(display_filter=f'frame.number >= {max(1,packet_index+1-radius)} && frame.number <= {packet_index+1+radius}')
        return run(lambda:engine.search(capture_path(task_id),filters),task_id)

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
