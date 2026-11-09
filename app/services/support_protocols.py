"""Read-only protocol views and TCP stream health from bounded Wireshark scans."""
from collections import Counter, defaultdict
from math import isfinite
from typing import Literal
from fastapi import APIRouter, HTTPException, Query, Response
from app.services.investigation_service import CaptureInvestigator, InvestigationError
from app.services.storage_service import _validate_task_id

PROTOCOLS = {
    'icmp': ('ICMP / ICMPv6', 'icmp || icmpv6'),
    'dhcp': ('DHCP / DHCPv6', 'dhcp || dhcpv6'),
    'ssh': ('SSH', 'ssh'), 'smb': ('SMB / SMB2', 'smb || smb2'),
    'rdp': ('RDP', 'rdp || rdpudp'), 'ntp': ('NTP', 'ntp'),
    'quic': ('QUIC', 'quic'), 'tcp': ('TCP', 'tcp'), 'udp': ('UDP', 'udp'),
}
ProtocolName = Literal['icmp', 'dhcp', 'ssh', 'smb', 'rdp', 'ntp', 'quic', 'tcp', 'udp']


def metrics(rows):
    windows = [r['tcp_window'] for r in rows if isinstance(r.get('tcp_window'), (int, float)) and isfinite(r['tcp_window']) and r['tcp_window'] >= 0]
    rtts = [r['ack_rtt_seconds'] * 1000 for r in rows
            if isinstance(r.get('ack_rtt_seconds'), (int, float))
            and isfinite(r['ack_rtt_seconds']) and r['ack_rtt_seconds'] >= 0]
    stamps = [r['timestamp'] for r in rows if isinstance(r.get('timestamp'), (int, float)) and isfinite(r['timestamp'])]
    result = {'packets': len(rows), 'bytes': sum(r.get('length') or 0 for r in rows),
              'rtt_samples': len(rtts), 'rtt_avg_ms': round(sum(rtts)/len(rtts), 3) if rtts else None,
              'rtt_min_ms': round(min(rtts), 3) if rtts else None,
              'rtt_max_ms': round(max(rtts), 3) if rtts else None,
              'duration_seconds': round(max(stamps)-min(stamps), 6) if len(stamps) >= 2 else None,
              'window_raw_avg': round(sum(windows)/len(windows), 2) if windows else None,
              'window_raw_min': min(windows) if windows else None,
              'window_raw_max': max(windows) if windows else None}
    for name, field in [('resets', 'tcp_reset'), ('retransmissions', 'retransmission'),
                        ('zero_windows', 'zero_window'), ('duplicate_acks', 'duplicate_ack'),
                        ('out_of_order', 'out_of_order'), ('previous_segment_missing', 'lost_segment'),
                        ('syn_packets', 'tcp_syn'), ('fin_packets', 'tcp_fin')]:
        result[name] = sum(bool(r.get(field)) for r in rows)
    return result


class SupportProtocolService:
    def __init__(self, engine=None):
        self.engine = engine or CaptureInvestigator()

    def report(self, path, protocol, stream=None, after_frame=0, limit=25, session_offset=0):
        if protocol not in PROTOCOLS or not 1 <= limit <= 50 or after_frame < 0 or session_offset < 0:
            raise ValueError('Invalid protocol or pagination')
        if stream is not None and (protocol != 'tcp' or not isinstance(stream, int) or stream < 0):
            raise ValueError('Invalid TCP stream')
        expression = PROTOCOLS[protocol][1]
        if stream is not None:
            expression = f'({expression}) && tcp.stream == {stream}'
        rows, coverage = self.engine.scan(path, expression)
        groups = defaultdict(list)
        hosts = Counter()
        for row in rows:
            if row.get('tcp_stream') is not None:
                groups[row['tcp_stream']].append(row)
            hosts.update(ip for ip in (row.get('src_ip'), row.get('dst_ip')) if ip)
        sessions = []
        for ident, packets in sorted(groups.items()):
            first = packets[0]
            sessions.append({'stream_id': ident, 'endpoint_a': {'ip': first['src_ip'], 'port': first['src_port']},
                             'endpoint_b': {'ip': first['dst_ip'], 'port': first['dst_port']},
                             'first_frame': first['frame_number'], **metrics(packets)})
        page = [r for r in rows if r['frame_number'] > after_frame]
        # Explicit metadata allowlist: do not expose payloads, identities or URLs.
        keys = ('frame_number', 'timestamp', 'length', 'protocols', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                'tcp_stream', 'tcp_reset', 'retransmission', 'ack_rtt_seconds', 'zero_window', 'duplicate_ack',
                'out_of_order', 'lost_segment', 'tcp_syn', 'tcp_ack', 'tcp_fin', 'tcp_window', 'protocol_details')
        return {'protocol': protocol, 'title': PROTOCOLS[protocol][0], 'display_filter': expression,
                'stream_id': stream, 'summary': metrics(rows), 'coverage': coverage,
                'observed_packets': len(rows), 'observed_sessions': len(sessions),
                'sessions': sessions[session_offset:session_offset+50],
                'next_session_offset': session_offset+50 if len(sessions) > session_offset+50 else None,
                'top_hosts': [{'ip': ip, 'packet_appearances': count} for ip, count in hosts.most_common(10)],
                'data': [{k: row[k] for k in keys if k in row} for row in page[:limit]],
                'next_after_frame': page[limit-1]['frame_number'] if len(page) > limit else None,
                'limitations': ['Décodage Wireshark observé, pas une identification par numéro de port seul.',
                    'Les compteurs concernent les paquets inspectés. Absence de réponse ne signifie pas perte confirmée.',
                    'RTT calculé uniquement sur les ACK corrélés par Wireshark ; absence de mesure = inconnue.',
                    'Sens A/B selon le premier paquet observé, pas une attribution garantie du rôle client/serveur.',
                    'Sessions identifiées par tcp.stream Wireshark ; identifiants distincts de ceux du tableau historique Flux réseau.',
                    'Contenu chiffré et secrets non restitués. Les détails applicatifs peuvent être invisibles.']}


def create_support_protocol_router(storage):
    router = APIRouter(prefix='/api/analysis', tags=['Protocoles support'])
    service = SupportProtocolService()

    @router.get('/{task_id}/protocols/{protocol}')
    def report(task_id: str, protocol: ProtocolName, response: Response,
               stream: int | None = Query(None, ge=0, le=2147483647),
               after_frame: int = Query(0, ge=0), limit: int = Query(25, ge=1, le=50),
               session_offset: int = Query(0, ge=0)):
        response.headers['Cache-Control'] = 'no-store'
        try:
            _validate_task_id(task_id)
        except ValueError:
            raise HTTPException(400, 'Identifiant invalide') from None
        if not storage.load_results(task_id):
            raise HTTPException(404, 'Analyse introuvable')
        path = storage.get_pcap_path(task_id)
        if not path:
            raise HTTPException(404, 'PCAP original indisponible')
        try:
            return {'task_id': task_id, **service.report(path, protocol, stream, after_frame, limit, session_offset)}
        except InvestigationError:
            raise HTTPException(503, 'Moteur occupé ou capture illisible ; réessayez.') from None
        except ValueError:
            raise HTTPException(400, 'Sélection de session invalide') from None

    return router
