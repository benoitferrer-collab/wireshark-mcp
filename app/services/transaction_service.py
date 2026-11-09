"""Bounded, metadata-only protocol timings; never invent an end-to-end chain."""
from bisect import bisect_right
from collections import defaultdict
from math import isfinite
from fastapi import APIRouter, HTTPException, Query, Response
from app.services.investigation_service import CaptureInvestigator, InvestigationError
from app.services.storage_service import _validate_task_id

STAGES = ('dns', 'tcp', 'tls', 'http')


def blank(note='Étape non observée ou non mesurable dans le périmètre inspecté.'):
    return {'duration_ms': None, 'state': 'missing', 'evidence_frames': [], 'note': note}


def measured(first, last, note, state='observed'):
    if not first or not last:
        return blank(note)
    start, end = first.get('timestamp'), last.get('timestamp')
    if not isinstance(start, (float, int)) or not isinstance(end, (float, int)) or not isfinite(start) or not isfinite(end) or end < start:
        return blank('Horodatages incohérents : durée non mesurable.')
    return {'duration_ms': round((end-start)*1000, 3), 'state': state,
            'evidence_frames': [first['frame_number'], last['frame_number']], 'note': note}


def endpoint(row, side):
    return {'ip': row[side+'_ip'], 'port': row[side+'_port']}


def reverse(a, b):
    return endpoint(a, 'src') == endpoint(b, 'dst') and endpoint(a, 'dst') == endpoint(b, 'src')


class TransactionService:
    def __init__(self, engine=None):
        self.engine = engine or CaptureInvestigator()

    def report(self, path, after_frame=0, limit=10):
        if not 1 <= limit <= 25 or after_frame < 0:
            raise ValueError('Invalid transaction pagination')
        rows, coverage = self.engine.scan(path, 'dns || tcp')
        frames = {r['frame_number']: r for r in rows}
        queries = {r['frame_number']: r for r in rows if r['dns_names'] and not r['dns_response']}
        dns_responses = {}
        for row in rows:
            query = queries.get(row.get('dns_request_frame'))
            if row['dns_response'] and query and reverse(query, row):
                dns_responses.setdefault(query['frame_number'], row)
        records = []
        by_answer = defaultdict(list)
        for frame, query in queries.items():
            response = dns_responses.get(frame)
            record = {'anchor_frame': frame, 'kind': 'dns', 'host': query['dns_name'],
                      'client': endpoint(query, 'src'), 'server': endpoint(query, 'dst'),
                      'tcp_stream': None, 'http_method': '', 'http_status': None,
                      'dns_rcode': response['dns_rcode'] if response else None,
                      'resets': 0, 'retransmissions': 0, 'stages': {key: blank() for key in STAGES}}
            record['stages']['dns'] = measured(query, response, 'Requête → réponse DNS corrélée par Wireshark.',
                                                       'error' if response and response['dns_rcode'] else 'observed')
            records.append(record)
            if response and response['dns_rcode'] == 0 and isinstance(response['timestamp'], (int, float)):
                for ip in response['dns_answer_ips']:
                    by_answer[(query['src_ip'], ip)].append((response['timestamp'], frame, record))
        for items in by_answer.values():
            items.sort(key=lambda value: (value[0], value[1]))
        answer_times = {key: [item[0] for item in values] for key, values in by_answer.items()}
        streams = defaultdict(list)
        for row in rows:
            if row['tcp_stream'] is not None:
                streams[row['tcp_stream']].append(row)
        for stream_id, packets in streams.items():
            syn = next((r for r in packets if r['tcp_syn'] and not r['tcp_ack']), None)
            requests = [r for r in packets if r['http_method']]
            hello = next((r for r in packets if 1 in r['tls_handshake_types']), None)
            origin = syn or hello or (requests[0] if requests else packets[0])
            # A partial DNS-over-TCP stream may start at a query already listed
            # as a DNS exchange. Coalesce instead of issuing a duplicate cursor.
            if not requests and origin['frame_number'] in queries:
                continue
            syn_ack = next((r for r in packets if syn and r['frame_number'] > syn['frame_number'] and reverse(syn, r)
                            and r['tcp_syn'] and r['tcp_ack'] and r['tcp_ack_number'] == (syn['tcp_sequence']+1) % 2**32), None) if syn and syn['tcp_sequence'] is not None else None
            ack = next((r for r in packets if syn_ack and r['frame_number'] > syn_ack['frame_number']
                        and endpoint(r, 'src') == endpoint(syn, 'src') and not r['tcp_syn'] and r['tcp_ack']
                        and r['tcp_payload_length'] == 0 and r['tcp_ack_number'] == (syn_ack['tcp_sequence']+1) % 2**32
                        and r['tcp_sequence'] == (syn['tcp_sequence']+1) % 2**32), None) if syn_ack and syn_ack['tcp_sequence'] is not None else None
            server_hello = next((r for r in packets if hello and r['frame_number'] > hello['frame_number']
                                 and reverse(hello, r) and 2 in r['tls_handshake_types']), None)
            responses = {}
            for row in packets:
                if row['http_status'] is not None and len(row['http_request_frames']) == 1:
                    responses.setdefault(row['http_request_frames'][0], row)
            for request in requests or [origin]:
                host = request['http_host'] or (hello['tls_server_name'] if hello else '')
                record = {'anchor_frame': request['frame_number'], 'kind': 'http' if requests else 'tcp',
                          'host': host, 'client': endpoint(origin, 'src'), 'server': endpoint(origin, 'dst'),
                          'tcp_stream': stream_id, 'http_method': request['http_method'],
                          'http_status': None, 'dns_rcode': None,
                          'resets': sum(r['tcp_reset'] for r in packets),
                          'retransmissions': sum(r['retransmission'] for r in packets),
                          'endpoint_basis': 'syn' if syn else 'client_hello' if hello else 'request' if requests else 'first_observed_packet',
                          'stages': {key: blank() for key in STAGES}}
                record['stages']['tcp'] = measured(syn, ack, 'SYN → ACK de fin de handshake visible. Mesure au point de capture, commune aux requêtes de cette connexion.')
                record['stages']['tls'] = measured(hello, server_hello, 'ClientHello → ServerHello uniquement ; ce délai ne mesure pas toute la négociation TLS.')
                response = responses.get(request['frame_number']) if requests else None
                if response and not reverse(request, response):
                    response = None
                record['http_status'] = response['http_status'] if response else None
                record['stages']['http'] = measured(request if requests else None, response,
                    'Requête → trame de réponse HTTP corrélée par Wireshark. Pas une mesure du temps serveur seul ; HTTP chiffré non déchiffré et HTTP/2 ne sont pas reconstruits ici.')
                if syn and syn['timestamp'] is not None:
                    key = (syn['src_ip'], syn['dst_ip'])
                    candidates = by_answer.get(key, [])
                    index = bisect_right(answer_times.get(key, []), syn['timestamp'])-1
                    if index >= 0:
                        stamp, _, dns = candidates[index]
                        same_name = not host or host.lower().split(':')[0].rstrip('.') == dns['host'].lower().rstrip('.')
                        if 0 <= syn['timestamp']-stamp <= 60 and same_name:
                            stage = dict(dns['stages']['dns'])
                            stage.update(association='candidate', note='Association DNS candidate : même client, adresse retournée et réponse précédente de moins de 60 s ; lien applicatif non prouvé.')
                            record['stages']['dns'] = stage
                records.append(record)
        records.sort(key=lambda record: record['anchor_frame'])
        page = [item for item in records if item['anchor_frame'] > after_frame]
        selected = page[:limit]
        return {'data': selected, 'coverage': coverage, 'observed_transactions': len(records),
                'next_after_frame': selected[-1]['anchor_frame'] if len(page) > limit else None,
                'limitations': [
                    'Aucune somme DNS+TCP+TLS+HTTP : ces durées ne constituent pas une mesure de bout en bout.',
                    'Absence d’étape ou de réponse : non observée dans le périmètre, pas preuve de panne.',
                    'TCP et TLS concernent la connexion, réutilisée éventuellement par plusieurs requêtes HTTP.',
                    'Comparaison de deux échanges choisis : vérifier même opération, point de capture, charge et qualité des horloges.',
                    'Métadonnées uniquement : aucun contenu applicatif, URL, cookie ou secret retourné.',
                    'Messages regroupés dans une trame : corrélation HTTP pouvant rester non mesurable ; DNS sur TCP peut aussi apparaître comme une connexion TCP.',
                ]}


def create_transaction_router(storage):
    router = APIRouter(prefix='/api/analysis', tags=['Transactions'])
    service = TransactionService()

    @router.get('/{task_id}/transactions')
    def transactions(task_id: str, response: Response, after_frame: int = Query(0, ge=0), limit: int = Query(10, ge=1, le=25)):
        response.headers['Cache-Control'] = 'no-store'
        try:
            _validate_task_id(task_id)
        except ValueError:
            raise HTTPException(400, 'Identifiant de capture invalide') from None
        if not storage.load_results(task_id):
            raise HTTPException(404, 'Analyse introuvable')
        path = storage.get_pcap_path(task_id)
        if not path:
            raise HTTPException(404, 'PCAP original indisponible : chronologie non mesurable')
        try:
            report = service.report(path, after_frame, limit)
        except InvestigationError:
            raise HTTPException(503, 'Moteur occupé ou lecture PCAP indisponible. Réessayez.') from None
        for item in report['data']:
            for stage in item['stages'].values():
                stage['evidence'] = [{'frame_number': frame, 'url': f'/?task={task_id}#tab=packets&packet={frame-1}'} for frame in stage['evidence_frames']]
        return {'task_id': task_id, **report}

    return router
