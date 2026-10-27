import json
import pytest
from app.mcp_views import analysis_summary, query_view

RESULTS = {
    'metadata': {'filename': 'capture.pcap', 'pcap_path': '/app/uploads/private.pcap'},
    'protocol_analysis': {'summary': {'total_packets': 12000}},
    'tcp_analysis': {'sessions': [{'id': 'a', 'rtt': 20}, {'id': 'b', 'rtt': 80}]},
    'packets_index': [{'index': 0}],
    'all_anomalies': [{'severity': 'high', 'src_ip': '10.0.0.1'}],
}

def test_summary_omits_internal_path_and_declares_packet_index_limit():
    result = analysis_summary('abc', RESULTS)
    assert result['summary']['total_packets'] == 12000
    assert result['packet_index']['available'] == 1
    assert result['packet_index']['complete'] is False
    assert '/app/' not in json.dumps(result)

def test_query_traverses_json_pointer_and_paginates_without_losing_evidence():
    result = query_view(RESULTS, 'tcp_analysis', '/sessions', 1, 1)
    assert result['data'] == [{'id': 'b', 'rtt': 80}]
    assert result['total'] == 2
    assert result['next_offset'] is None

@pytest.mark.parametrize('pointer', ['/missing', '/sessions/-1', '/sessions/99'])
def test_missing_pointer_rejected(pointer):
    with pytest.raises(ValueError):
        query_view(RESULTS, 'tcp_analysis', pointer, 0, 10)

def test_unknown_section_and_bad_pagination_rejected():
    for section, offset, limit in [('metadata', 0, 5), ('tcp_analysis', -1, 5), ('tcp_analysis', 0, 101)]:
        with pytest.raises(ValueError):
            query_view(RESULTS, section, '', offset, limit)

@pytest.mark.parametrize('pointer', ['/capture_points/0/file_path', '/password', '/payload', '/raw_hex', '/body_preview'])
def test_sensitive_leaf_cannot_bypass_scrubbing_via_pointer(pointer):
    results = {'analysis': {'capture_points': [{'file_path': '/private/capture.pcap'}],
                            'password': 'secret', 'payload': 'secret', 'raw_hex': '736563726574',
                            'body_preview': 'secret'}}
    with pytest.raises(ValueError, match='Sensitive'):
        query_view(results, 'analysis', pointer, 0, 10)
