import json
import shutil
from pathlib import Path

import pytest
from scapy.all import Ether, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap

TSHARK = shutil.which('tshark') or '/Applications/Wireshark.app/Contents/MacOS/tshark'


@pytest.fixture
def capture(tmp_path, monkeypatch):
    monkeypatch.setenv('TSHARK_PATH', TSHARK)
    packets = [
        Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='192.0.2.10', dst='198.51.100.20')/TCP(sport=50000,dport=443,flags='S'),
        Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='198.51.100.20', dst='192.0.2.10')/TCP(sport=443,dport=50000,flags='RA'),
        Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='192.0.2.10', dst='192.0.2.53')/UDP(sport=53000,dport=53)/DNS(id=1,qd=DNSQR(qname='evil.example')),
        Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='192.0.2.53', dst='192.0.2.10')/UDP(sport=53,dport=53000)/DNS(id=1,qr=1,rcode=3,qd=DNSQR(qname='evil.example')),
        Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='192.0.2.10', dst='192.0.2.53')/UDP(sport=53001,dport=53)/DNS(qd=DNSQR(qname='notevil.example')),
        Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IPv6(src='2001:db8::1', dst='2001:db8::2')/TCP(sport=23456,dport=22,flags='S'),
        Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='192.0.2.10', dst='198.51.100.20')/TCP(sport=50001,dport=80)/Raw(b'GET /?password=secret HTTP/1.1\r\nHost: web.example\r\nAuthorization: Bearer secret\r\nCookie: private\r\n\r\n'),
    ]
    for i,p in enumerate(packets): p.time=1700000000+i
    path=tmp_path/'capture.pcap'
    wrpcap(str(path),packets)
    return path


def test_search_typed_filters_pagination_and_safe_fields(capture):
    from app.services.investigation_service import CaptureInvestigator, SearchFilters
    engine=CaptureInvestigator()
    first=engine.search(capture,SearchFilters(ip='192.0.2.0/24',protocol='tcp'),limit=1)
    assert first['data'][0]['frame_number']==1
    assert first['data'][0]['packet_index']==0
    assert first['next_after_frame']==1
    second=engine.search(capture,SearchFilters(ip='192.0.2.0/24',protocol='tcp'),after_frame=first['next_after_frame'])
    assert [p['frame_number'] for p in second['data']]==[2,7]
    assert second['coverage']['complete'] is True
    assert 'secret' not in json.dumps(second)
    assert 'private' not in json.dumps(second)
    assert engine.search(capture,SearchFilters(ip='2001:db8::/32'))['data'][0]['src_ip']=='2001:db8::1'


def test_hunt_domain_boundaries_and_conversations(capture):
    from app.services.investigation_service import CaptureInvestigator, SearchFilters
    engine=CaptureInvestigator()
    hunt=engine.hunt(capture,['evil.example','198.51.100.20','203.0.113.1'])
    rows={r['indicator']:r for r in hunt['data']}
    assert rows['evil.example']['matched_packets']==2
    assert rows['203.0.113.1']['matched_packets']==0
    assert rows['evil.example']['evidence'][0]['frame_number']==3
    conversations=engine.conversations(capture,SearchFilters(protocol='tcp'))
    tcp=next(r for r in conversations['data'] if r['packet_count']==2)
    assert tcp['rst_count']==1
    assert tcp['tcp_stream'] is not None
    assert tcp['first_frame']==1 and tcp['last_frame']==2


def test_scan_cap_never_claims_complete(capture):
    from app.services.investigation_service import CaptureInvestigator, SearchFilters
    result=CaptureInvestigator(max_packets=2).search(capture,SearchFilters(protocol='dns'))
    assert result['coverage']['complete'] is False
    assert result['coverage']['reason']=='packet_limit'
    assert result['total_matching'] is None
    assert result['data']==[]


def test_search_original_capture_beyond_initial_index(tmp_path,monkeypatch):
    from app.services.investigation_service import CaptureInvestigator, SearchFilters
    monkeypatch.setenv('TSHARK_PATH',TSHARK)
    path=tmp_path/'large.pcap'
    filler=Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='192.0.2.1',dst='192.0.2.2')/UDP(sport=1000,dport=1001)
    wrpcap(str(path),[filler]*5001+[Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='203.0.113.1',dst='192.0.2.2')/TCP(dport=3389)])
    result=CaptureInvestigator().search(path,SearchFilters(ip='203.0.113.1'))
    assert result['data'][0]['packet_index']==5001
    assert result['coverage']['complete'] is True


@pytest.mark.parametrize('filters',[
    {'ip':'$(cat /etc/passwd)'},{'port':70000},{'time_start':float('nan')},
    {'time_start':2,'time_end':1},{'domain':'a" or tcp'},
    {'display_filter':'@/etc/passwd'}, {'display_filter':'tcp\n-w /tmp/out'},
])
def test_invalid_filters_rejected_before_execution(filters):
    from app.services.investigation_service import SearchFilters
    with pytest.raises(ValueError): SearchFilters(**filters)


def test_invalid_display_filter_is_actionable_and_private(capture):
    from app.services.investigation_service import CaptureInvestigator, SearchFilters, InvestigationError
    with pytest.raises(InvestigationError,match='filter') as exc:
        CaptureInvestigator().search(capture,SearchFilters(display_filter='tcp &&&&'))
    assert str(capture) not in str(exc.value)


def test_triage_returns_evidence_without_compromise_claims(capture):
    from app.services.investigation_service import CaptureInvestigator
    result=CaptureInvestigator().triage(capture,'dns-failures')
    assert [r['frame_number'] for r in result['data']]==[4]
    assert 'heuristic' in ' '.join(result['limitations']).lower()


def test_runner_deadline_and_output_limits_kill_children(tmp_path,monkeypatch):
    from app.services.investigation_service import CaptureInvestigator, SearchFilters
    fake=tmp_path/'fake-tshark'
    fake.write_text('#!/usr/bin/env python3\nimport sys,time\nprint("x"*20000,flush=True)\ntime.sleep(3)\n')
    fake.chmod(0o700)
    monkeypatch.setenv('TSHARK_PATH',str(fake))
    result=CaptureInvestigator(max_output=1000).search(tmp_path/'capture',SearchFilters())
    assert result['coverage']['complete'] is False
    assert result['coverage']['reason']=='output_limit'
    fake.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(3)\n')
    result=CaptureInvestigator(timeout=.05).search(tmp_path/'capture',SearchFilters())
    assert result['coverage']['reason']=='time_limit'


def test_hunt_ip_in_dns_answer_and_pcapng(tmp_path,monkeypatch):
    from scapy.utils import PcapNgWriter
    from app.services.investigation_service import CaptureInvestigator, SearchFilters
    monkeypatch.setenv('TSHARK_PATH',TSHARK)
    packet=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src='192.0.2.53',dst='192.0.2.10')/UDP(sport=53,dport=53000)/DNS(qr=1,qd=DNSQR(qname='answer.example'),an=DNSRR(rrname='answer.example',rdata='203.0.113.77'))
    path=tmp_path/'capture.pcapng'
    with PcapNgWriter(str(path)) as writer: writer.write(packet)
    result=CaptureInvestigator().hunt(path,['203.0.113.77'])
    assert result['data'][0]['matched_packets']==1
    assert result['data'][0]['evidence'][0]['packet_index']==0


def test_temporal_directional_filters(capture):
    from app.services.investigation_service import CaptureInvestigator, SearchFilters
    result=CaptureInvestigator().search(capture,SearchFilters(src_ip='192.0.2.10',dst_port=53,time_start=1700000002,time_end=1700000002))
    assert [r['frame_number'] for r in result['data']]==[3]


def test_hunt_preserves_repeated_dns_and_tunneled_ips(tmp_path,monkeypatch):
    from app.services.investigation_service import CaptureInvestigator
    monkeypatch.setenv('TSHARK_PATH',TSHARK)
    ethernet=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')
    dns=ethernet/IP(src='192.0.2.1',dst='192.0.2.53')/UDP(sport=53000,dport=53)/DNS(qd=[DNSQR(qname='evil.example'),DNSQR(qname='benign.example')])
    tunnel=ethernet/IP(src='192.0.2.1',dst='192.0.2.2')/IP(src='203.0.113.77',dst='203.0.113.78')/TCP(dport=443)
    path=tmp_path/'repeated.pcap'; wrpcap(str(path),[dns,tunnel])
    result=CaptureInvestigator().hunt(path,['evil.example','203.0.113.77'])
    assert [r['matched_packets'] for r in result['data']]==[1,1]
    assert all(r['status']=='observed' for r in result['data'])
