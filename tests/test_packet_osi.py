"""Tests for enriched packet details endpoint (OSI layers)."""
import pytest
from unittest.mock import patch, MagicMock



def test_extract_osi_layers_returns_all_keys():
    """extract_osi_layers returns a dict with all 8 layer keys."""
    from app.api.routes import extract_osi_layers

    mock_pkt = MagicMock()
    # IP layer
    mock_pkt.haslayer = lambda cls: cls.__name__ in ('IP', 'TCP', 'Ether')
    mock_ip = MagicMock()
    mock_ip.src = '10.0.0.1'
    mock_ip.dst = '8.8.8.8'
    mock_ip.ttl = 64
    mock_ip.version = 4
    mock_ip.ihl = 5
    mock_ip.tos = 0
    mock_ip.frag = 0
    mock_ip.chksum = 0x1a2b
    mock_ip.proto = 6
    mock_pkt.__getitem__ = lambda self, cls: mock_ip

    result = extract_osi_layers(mock_pkt, packet_info={
        'src_ip': '10.0.0.1', 'dst_ip': '8.8.8.8',
        'src_port': 12345, 'dst_port': 443,
        'protocol': 'TCP', 'length': 74
    })

    for key in ('l1_physical', 'l2_datalink', 'l3_network', 'l4_transport',
                'l5_session', 'l6_presentation', 'l7_application', 'raw_hex'):
        assert key in result, f"Missing key: {key}"


def test_extract_osi_layers_l3_fields():
    """L3 fields map correctly from IP layer."""
    from app.api.routes import extract_osi_layers
    from unittest.mock import patch, MagicMock

    mock_pkt = MagicMock()

    ip_mock = MagicMock()
    ip_mock.src = '192.168.1.1'
    ip_mock.dst = '1.1.1.1'
    ip_mock.ttl = 128
    ip_mock.version = 4
    ip_mock.ihl = 5
    ip_mock.tos = 0
    ip_mock.frag = 0
    ip_mock.chksum = 0xabcd
    ip_mock.proto = 17  # UDP

    def haslayer(cls):
        return cls.__name__ in ('IP',)
    mock_pkt.haslayer = haslayer
    mock_pkt.__getitem__ = lambda self, cls: ip_mock

    result = extract_osi_layers(mock_pkt, packet_info={
        'src_ip': '192.168.1.1', 'dst_ip': '1.1.1.1',
        'src_port': 5353, 'dst_port': 53,
        'protocol': 'UDP', 'length': 50
    })

    assert result['l3_network']['src_ip'] == '192.168.1.1'
    assert result['l3_network']['ttl'] == 128
    assert result['l3_network']['version'] == 4
