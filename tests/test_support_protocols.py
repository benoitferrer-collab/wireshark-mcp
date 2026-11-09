from app.services.support_protocols import SupportProtocolService


class Engine:
    def __init__(self, rows):
        self.rows = rows
        self.expression = None

    def scan(self, path, expression):
        self.expression = expression
        return self.rows, {'complete': False, 'reason': 'packet_limit'}


def packet(frame, stream=0, **extra):
    return dict(frame_number=frame, timestamp=frame / 10, length=60,
                src_ip='192.0.2.1', dst_ip='198.51.100.1', src_port=40000,
                dst_port=443, tcp_stream=stream, protocols='eth:ip:tcp',
                tcp_reset=False, retransmission=False, ack_rtt_seconds=None, **extra)


def test_sessions_keep_unknown_rtt_and_do_not_mix_streams():
    a = packet(1)
    a['tcp_reset'] = True
    b = packet(2, stream=1)
    b['ack_rtt_seconds'] = .125
    result = SupportProtocolService(Engine([a, b])).report('capture', 'tcp')
    assert result['sessions'][0]['rtt_avg_ms'] is None
    assert result['sessions'][0]['resets'] == 1
    assert result['sessions'][1]['rtt_avg_ms'] == 125
    assert result['sessions'][1]['resets'] == 0
    assert result['coverage']['complete'] is False


def test_fixed_protocol_filters_and_stream_zero_and_pagination():
    engine = Engine([packet(1), packet(2), packet(3)])
    report = SupportProtocolService(engine).report('capture', 'tcp', stream=0, after_frame=1, limit=1)
    assert engine.expression == '(tcp) && tcp.stream == 0'
    assert report['data'][0]['frame_number'] == 2
    assert report['next_after_frame'] == 2
    assert report['observed_packets'] == 3
    assert report['summary']['rtt_avg_ms'] is None


def test_protocol_allowlist_and_no_arbitrary_filter():
    import pytest
    service = SupportProtocolService(Engine([]))
    for protocol in ['icmp', 'dhcp', 'ssh', 'smb', 'rdp', 'ntp', 'quic', 'tcp', 'udp']:
        assert service.report('capture', protocol)['protocol'] == protocol
    with pytest.raises(ValueError):
        service.report('capture', 'tcp || ip')
    with pytest.raises(ValueError):
        service.report('capture', 'udp', stream=0)


def test_negative_or_nan_rtt_not_shown_as_real_measurement():
    row = packet(1)
    row['ack_rtt_seconds'] = float('nan')
    result = SupportProtocolService(Engine([row])).report('capture', 'tcp')
    assert result['summary']['rtt_samples'] == 0
    assert result['summary']['rtt_avg_ms'] is None


def test_router_validates_input_and_hides_engine_errors(monkeypatch, tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.services.support_protocols import create_support_protocol_router
    from app.services.investigation_service import InvestigationError

    class Storage:
        def load_results(self, task):
            return {'exists': True} if task == 'capture' else None

        def get_pcap_path(self, task):
            return tmp_path / 'original.pcap'

    app = FastAPI()
    app.include_router(create_support_protocol_router(Storage()))
    client = TestClient(app)
    assert client.get('/api/analysis/capture/protocols/arbitrary').status_code == 422
    assert client.get('/api/analysis/missing/protocols/tcp').status_code == 404
    assert client.get('/api/analysis/capture/protocols/tcp?stream=-1').status_code == 422

    def busy(*args, **kwargs):
        raise InvestigationError('sensitive local file location')
    monkeypatch.setattr(SupportProtocolService, 'report', busy)
    result = client.get('/api/analysis/capture/protocols/tcp')
    assert result.status_code == 503
    assert 'sensitive' not in result.text


def test_real_protocol_decoding_and_metadata_only(tmp_path):
    import os
    import pytest
    if not os.environ.get('TSHARK_PATH'):
        pytest.skip('Requires TShark')
    from scapy.all import Ether, IP, ICMP, UDP, BOOTP, DHCP, Raw, wrpcap
    from scapy.layers.ntp import NTP
    path = tmp_path / 'support.pcap'
    wrpcap(str(path), [
        Ether()/IP(src='192.0.2.1', dst='198.51.100.1')/ICMP(type=8)/Raw(b'PRIVATE-PAYLOAD'),
        Ether()/IP(src='0.0.0.0', dst='255.255.255.255')/UDP(sport=68, dport=67)/BOOTP()/DHCP(options=[('message-type','discover'),'end']),
        Ether()/IP(src='192.0.2.1', dst='198.51.100.1')/UDP(sport=123,dport=123)/NTP(mode=3),
    ])
    service = SupportProtocolService()
    for protocol in ['icmp','dhcp','ntp']:
        report = service.report(path, protocol)
        assert report['observed_packets'] == 1
        assert report['data'][0]['protocol_details']
        assert 'PRIVATE-PAYLOAD' not in str(report)
    for protocol in ['ssh','smb','rdp','quic','tcp','udp']:
        assert service.report(path, protocol)['coverage']['complete'] is True
