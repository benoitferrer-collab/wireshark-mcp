"""
Tests unitaires pour les analyseurs PCAP
"""

import pytest
from pathlib import Path
import sys

# Ajouter le chemin du projet
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.analyzers.protocol_analyzer import ProtocolAnalyzer
from app.analyzers.tcp_analyzer import TCPAnalyzer
from app.analyzers.anomaly_detector import AnomalyDetector, Severity, Anomaly
from app.core.mac_vendor import normalize_mac_address, classify_mac_address, resolve_mac_vendor
import app.core.mac_vendor as mac_vendor
from scapy.all import Ether, IP, TCP


class TestProtocolAnalyzer:
    """Tests pour ProtocolAnalyzer"""
    
    def test_initialization(self):
        """Test de l'initialisation"""
        analyzer = ProtocolAnalyzer()
        assert analyzer.name == 'ProtocolAnalyzer'
        assert analyzer.results == {}
    
    def test_format_bytes(self):
        """Test du formatage des bytes"""
        analyzer = ProtocolAnalyzer()
        
        assert analyzer.format_bytes(0) == '0.00 B'
        assert analyzer.format_bytes(1024) == '1.00 KB'
        assert analyzer.format_bytes(1048576) == '1.00 MB'
        assert analyzer.format_bytes(1073741824) == '1.00 GB'
    
    def test_get_service_name(self):
        """Test de la résolution des noms de services"""
        analyzer = ProtocolAnalyzer()
        
        assert analyzer._get_service_name(80) == 'HTTP'
        assert analyzer._get_service_name(443) == 'HTTPS'
        assert analyzer._get_service_name(22) == 'SSH'
        assert analyzer._get_service_name(99999) == ''
    
    def test_get_icmp_type_name(self):
        """Test de la résolution des types ICMP"""
        analyzer = ProtocolAnalyzer()
        
        assert analyzer._get_icmp_type_name(0) == 'Echo Reply'
        assert analyzer._get_icmp_type_name(8) == 'Echo Request'
        assert analyzer._get_icmp_type_name(255) == 'Type 255'

    def test_mac_statistics_output(self):
        """Vérifie la présence des stats MAC/constructeurs."""
        analyzer = ProtocolAnalyzer()
        packets = [
            Ether(src="02:42:ac:11:00:02", dst="00:50:56:aa:bb:cc") / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=12345, dport=443, flags="S"),
            Ether(src="00:50:56:aa:bb:cc", dst="02:42:ac:11:00:02") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=443, dport=12345, flags="SA"),
        ]

        results = analyzer.analyze(packets)
        mac_stats = results.get("mac_statistics", {})

        assert mac_stats.get("unique_macs", 0) >= 2
        assert isinstance(mac_stats.get("top_macs", []), list)
        assert any(item.get("vendor") for item in mac_stats.get("top_macs", []))


class TestMacVendorHelpers:
    """Tests utilitaires résolution MAC/OUI."""

    def test_normalize_mac_address(self):
        assert normalize_mac_address("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
        assert normalize_mac_address("aabb.ccdd.eeff") == "AA:BB:CC:DD:EE:FF"
        assert normalize_mac_address("invalid") == ""

    def test_classify_mac_address(self):
        assert classify_mac_address("ff:ff:ff:ff:ff:ff") == "broadcast"
        assert classify_mac_address("01:00:5e:00:00:01") == "multicast"
        assert classify_mac_address("02:42:ac:11:00:02") == "local-admin"
        assert classify_mac_address("00:50:56:aa:bb:cc") == "unicast"

    def test_resolve_mac_vendor_hint(self):
        assert resolve_mac_vendor("02:42:ac:11:00:02") == "Docker / Bridge local"

    def test_resolve_mac_vendor_online_fallback(self, monkeypatch):
        resolve_mac_vendor.cache_clear()
        mac_vendor._resolve_vendor_online_from_oui.cache_clear()

        monkeypatch.setattr(mac_vendor.conf.manufdb, "lookup", lambda mac: (mac, mac))
        monkeypatch.setattr(mac_vendor, "_resolve_vendor_online_from_oui", lambda oui: "Fallback Vendor Inc")

        vendor = resolve_mac_vendor("aa:bb:cc:11:22:33")
        assert vendor == "Fallback Vendor Inc"


class TestTCPAnalyzer:
    """Tests pour TCPAnalyzer"""
    
    def test_initialization(self):
        """Test de l'initialisation"""
        analyzer = TCPAnalyzer()
        assert analyzer.name == 'TCPAnalyzer'
        assert analyzer.sessions == {}
    
    def test_session_key_bidirectional(self):
        """Test que les clés de session sont bidirectionnelles"""
        analyzer = TCPAnalyzer()
        
        key1 = analyzer._get_session_key('192.168.1.1', '192.168.1.2', 12345, 80)
        key2 = analyzer._get_session_key('192.168.1.2', '192.168.1.1', 80, 12345)
        
        # Les deux clés doivent être identiques (session bidirectionnelle)
        assert key1 == key2


class TestAnomalyDetector:
    """Tests pour AnomalyDetector"""
    
    def test_initialization(self):
        """Test de l'initialisation"""
        detector = AnomalyDetector()
        assert detector.name == 'AnomalyDetector'
        assert detector.anomalies == []
    
    def test_anomaly_to_dict(self):
        """Test de la conversion d'anomalie en dictionnaire"""
        anomaly = Anomaly(
            type='SYN_FLOOD',
            severity=Severity.CRITICAL,
            score=100,
            description='Test anomaly',
            details={'test': 'value'},
            source_ip='192.168.1.1'
        )
        
        result = anomaly.to_dict()
        
        assert result['type'] == 'SYN_FLOOD'
        assert result['severity'] == 'CRITICAL'
        assert result['score'] == 100
        assert result['source_ip'] == '192.168.1.1'
    
    def test_calculate_risk_level(self):
        """Test du calcul du niveau de risque"""
        detector = AnomalyDetector()
        
        assert detector._calculate_risk_level(0) == 'NONE'
        assert detector._calculate_risk_level(30) == 'LOW'
        assert detector._calculate_risk_level(100) == 'MEDIUM'
        assert detector._calculate_risk_level(200) == 'HIGH'
        assert detector._calculate_risk_level(500) == 'CRITICAL'
    
    def test_severity_enum(self):
        """Test de l'énumération des sévérités"""
        assert Severity.INFO.value == 1
        assert Severity.LOW.value == 2
        assert Severity.MEDIUM.value == 3
        assert Severity.HIGH.value == 4
        assert Severity.CRITICAL.value == 5


class TestStorageService:
    """Tests pour le service de stockage"""
    
    def test_sanitize_filename(self):
        """Test de la sanitization des noms de fichiers"""
        from app.services.storage_service import StorageService
        
        storage = StorageService()
        
        assert storage._sanitize_filename('test.pcap') == 'test.pcap'
        assert storage._sanitize_filename('../../../etc/passwd') == 'passwd'
        assert storage._sanitize_filename('test\x00.pcap') == 'test.pcap'
        assert storage._sanitize_filename('') == 'unnamed.pcap'


# Pytest configuration
if __name__ == '__main__':
    pytest.main([__file__, '-v'])
