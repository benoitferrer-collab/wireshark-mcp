from pathlib import Path
import pytest
from scapy.all import DNS, DNSQR, IP, UDP, rdpcap
from app.analyzers.dns_analyzer import DNSAnalyzer


def responses(total, failures):
    return [IP(src='192.0.2.53', dst='192.0.2.10')/UDP(sport=53,dport=53000+i)/DNS(id=i,qr=1,rcode=3 if i<failures else 0,qd=DNSQR(qname='absent.example')) for i in range(total)]


def test_demo_nxdomain_is_visible_as_resolution_failure_with_real_packet_references():
    packets=rdpcap(str(Path('app/demo_data/DEMO_Nomios_Support.pcap')))
    result=DNSAnalyzer().analyze(packets)
    failure=next(a for a in result['anomalies'] if a['type']=='NXDOMAIN_RESPONSES')
    assert failure['severity']=='LOW'
    assert failure['details']['count']==4
    assert failure['details']['total_responses']==24
    assert failure['details']['rate']==pytest.approx(4/24)
    assert [r['packet_idx'] for r in failure['details']['packets']]==[i for i,p in enumerate(packets) if DNS in p and p[DNS].qr and p[DNS].rcode==3]
    assert 'malveillant' not in failure['description']
    assert not any(a['type']=='HIGH_NXDOMAIN_RATE' for a in result['anomalies'])


@pytest.mark.parametrize('total,failed,kind,severity',[(1,1,'NXDOMAIN_RESPONSES','LOW'),(20,6,'NXDOMAIN_RESPONSES','LOW'),(20,7,'HIGH_NXDOMAIN_RATE','MEDIUM'),(20,11,'HIGH_NXDOMAIN_RATE','HIGH')])
def test_resolution_failures_preserve_high_rate_threshold_without_duplicate_alerts(total,failed,kind,severity):
    result=DNSAnalyzer().analyze(responses(total,failed))
    alerts=[a for a in result['anomalies'] if a['type'] in ('NXDOMAIN_RESPONSES','HIGH_NXDOMAIN_RATE')]
    assert len(alerts)==1
    assert alerts[0]['type']==kind and alerts[0]['severity']==severity


def test_no_nxdomain_does_not_create_resolution_failure():
    assert not DNSAnalyzer().analyze(responses(24,0))['anomalies']


def test_exact_error_count_survives_capped_response_storage(monkeypatch):
    monkeypatch.setattr(DNSAnalyzer,'MAX_STORED_RECORDS',2)
    result=DNSAnalyzer().analyze(responses(24,4))
    alert=next(a for a in result['anomalies'] if a['type']=='NXDOMAIN_RESPONSES')
    assert alert['details']['count']==4
    assert alert['details']['packets']==[]
