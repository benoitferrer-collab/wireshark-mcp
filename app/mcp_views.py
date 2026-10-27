"""Read-only projections of stored evidence, independent of analysis infrastructure."""
from mcp_gateway.policy import page_value

SECTIONS = {
    'protocol_analysis', 'tcp_analysis', 'anomaly_analysis', 'anomaly_detection',
    'dns_analysis', 'http_analysis', 'smb_analysis', 'ldap_analysis',
    'kerberos_analysis', 'rdp_analysis', 'ssh_analysis', 'enrichment',
    'timeline', 'network_graph', 'streams', 'packets_index', 'all_anomalies',
    'analysis',  # multi-PCAP results
}


def analysis_summary(task_id: str, results: dict) -> dict:
    summary = results.get('protocol_analysis', {}).get('summary', {})
    count = len(results.get('packets_index', []))
    anomaly = results.get('anomaly_analysis') or results.get('anomaly_detection') or {}
    return {
        'task_id': task_id,
        'filename': results.get('metadata', {}).get('filename', ''),
        'summary': summary,
        'anomalies': anomaly.get('summary', {}),
        'sections': sorted(SECTIONS.intersection(results)),
        'packet_index': {
            'available': count,
            'complete': count == summary.get('total_packets', 0),
            'note': 'The initial packet index may cover only the first 5000 packets. '
                    'Absence from this index does not prove absence from the capture.',
        },
        'limitations': ['Security detections are heuristic indicators, not proof of compromise.'],
    }


def query_view(results: dict, section: str, pointer: str = '', offset: int = 0, limit: int = 25) -> dict:
    """Select an allowlisted section using RFC 6901 JSON Pointer, then page its children."""
    if section not in SECTIONS or offset < 0 or not 1 <= limit <= 100:
        raise ValueError('Invalid section or pagination')
    if section not in results:
        raise ValueError('Section is not available for this analysis')
    return {'section': section, **page_value(results[section], pointer, offset, limit)}
