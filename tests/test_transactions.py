import json
from pathlib import Path
import pytest
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap


def capture(path, delay=.2, host='web.example'):
    def frame(src,dst): return Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src=src,dst=dst)
    client='192.0.2.10';server='198.51.100.20';resolver='192.0.2.53'
    packets=[
        (0,frame(client,resolver)/UDP(sport=53000,dport=53)/DNS(id=1,qd=DNSQR(qname='web.example'))),
        (.025,frame(resolver,client)/UDP(sport=53,dport=53000)/DNS(id=1,qr=1,qd=DNSQR(qname='web.example'),an=DNSRR(rrname='web.example',rdata=server),ancount=1)),
        (.1,frame(client,server)/TCP(sport=42000,dport=80,flags='S',seq=100)),
        (.12,frame(server,client)/TCP(sport=80,dport=42000,flags='SA',seq=200,ack=101)),
        (.14,frame(client,server)/TCP(sport=42000,dport=80,flags='A',seq=101,ack=201)),
        (.2,frame(client,server)/TCP(sport=42000,dport=80,flags='PA',seq=101,ack=201)/Raw(('GET /?password=secret HTTP/1.1\r\nHost: '+host+'\r\nAuthorization: Bearer private\r\nCookie: token=secret\r\n\r\n').encode())),
        (.2+delay,frame(server,client)/TCP(sport=80,dport=42000,flags='PA',seq=201,ack=101)/Raw(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')),
    ]
    for time,p in packets:p.time=1700000000+time
    wrpcap(str(path),[p for _,p in packets]);return path


def test_measured_stages_have_exact_original_frames_and_no_secret(tmp_path):
    from app.services.transaction_service import TransactionService
    report=TransactionService().report(capture(tmp_path/'one.pcap'))
    item=next(x for x in report['data'] if x['kind']=='http')
    assert item['stages']['dns']['duration_ms']==pytest.approx(25,abs=.001)
    assert item['stages']['tcp']['duration_ms']==pytest.approx(40,abs=.001)
    assert item['stages']['http']['duration_ms']==pytest.approx(200,abs=.001)
    assert item['stages']['tls']['duration_ms'] is None
    assert item['stages']['http']['evidence_frames']==[6,7]
    assert item['stages']['dns']['association']=='candidate'
    assert report['coverage']['complete'] is True
    assert not any(s in json.dumps(report['data']) for s in ['password','secret','Bearer','Cookie','private'])


def test_demo_keeps_dns_failure_separate_and_missing_http_unknown():
    from app.services.transaction_service import TransactionService
    report=TransactionService().report(Path('app/demo_data/DEMO_Nomios_Support.pcap'),limit=25)
    reset=next(x for x in report['data'] if x['kind']=='http' and x['resets'])
    assert reset['stages']['http']['duration_ms'] is None
    assert reset['stages']['http']['state']=='missing'
    dns_error=next(x for x in report['data'] if x['kind']=='dns' and x['dns_rcode']==3)
    assert dns_error['stages']['dns']['state']=='error'
    assert dns_error['stages']['dns']['evidence_frames']==[1,2]
    assert report['next_after_frame']
    other=TransactionService().report(Path('app/demo_data/DEMO_Nomios_Support.pcap'),after_frame=report['next_after_frame'],limit=25)
    assert {x['anchor_frame'] for x in report['data']}.isdisjoint(x['anchor_frame'] for x in other['data'])


def test_incomplete_scan_never_claims_complete_and_validates_pagination(tmp_path):
    from app.services.transaction_service import TransactionService
    from app.services.investigation_service import CaptureInvestigator
    service=TransactionService(CaptureInvestigator(max_packets=4))
    report=service.report(capture(tmp_path/'short.pcap'))
    assert report['coverage']['complete'] is False
    with pytest.raises(ValueError):service.report(tmp_path/'short.pcap',limit=100)


def test_absent_handshake_is_not_zero_or_invented(tmp_path):
    from app.services.transaction_service import TransactionService
    from scapy.all import rdpcap
    path=capture(tmp_path/'partial.pcap');packets=rdpcap(str(path));wrpcap(str(path),packets[5:])
    item=next(x for x in TransactionService().report(path)['data'] if x['kind']=='http')
    assert item['stages']['tcp']['duration_ms'] is None
    assert item['stages']['dns']['duration_ms'] is None
    assert item['stages']['http']['duration_ms']==pytest.approx(200,abs=.001)

def test_transaction_api_returns_protected_capture_links_and_unknown_paths(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from types import SimpleNamespace
    from app.services.transaction_service import create_transaction_router
    path=capture(tmp_path/'one.pcap')
    storage=SimpleNamespace(load_results=lambda task: {'metadata':{}} if task!='missing' else None,get_pcap_path=lambda task:path if task!='gone' else None)
    app=FastAPI();app.include_router(create_transaction_router(storage))
    with TestClient(app) as client:
        response=client.get('/api/analysis/one/transactions')
        assert response.status_code==200
        http=next(item for item in response.json()['data'] if item['kind']=='http')
        assert http['stages']['http']['evidence'][0]=={'frame_number':6,'url':'/?task=one#tab=packets&packet=5'}
        assert client.get('/api/analysis/missing/transactions').status_code==404
        assert client.get('/api/analysis/gone/transactions').status_code==404
        assert client.get('/api/analysis/one/transactions?limit=100').status_code==422


def test_dns_candidate_does_not_attach_a_different_hostname(tmp_path):
    from app.services.transaction_service import TransactionService
    path=capture(tmp_path/'names.pcap',host='other.example')
    http=next(item for item in TransactionService().report(path)['data'] if item['kind']=='http')
    assert http['stages']['dns']['duration_ms'] is None

def test_partial_dns_over_tcp_has_no_duplicate_cursor_records(tmp_path):
    from app.services.transaction_service import TransactionService
    packets=[]
    for i in range(2):
        query=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src='192.0.2.10',dst='192.0.2.53')/TCP(sport=53000+i,dport=53,flags='PA',seq=1,ack=1)/DNS(id=i,qd=DNSQR(qname='web.example'))
        query.time=1700000000+i
        packets.append(query)
    path=tmp_path/'dns-tcp.pcap';wrpcap(str(path),packets)
    service=TransactionService();first=service.report(path,limit=1)
    second=service.report(path,after_frame=first['next_after_frame'],limit=1)
    assert [item['anchor_frame'] for item in first['data']+second['data']]==[1,2]
    assert first['observed_transactions']==2
    assert second['next_after_frame'] is None


def test_tls_stage_is_only_clienthello_to_serverhello(tmp_path):
    from app.services.transaction_service import TransactionService
    from scapy.layers.tls.record import TLS
    from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
    hello=bytes(TLS(msg=[TLSClientHello()]))
    server=bytes(TLS(msg=[TLSServerHello()]))
    packets=[Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src='192.0.2.10',dst='198.51.100.20')/TCP(sport=43000,dport=443,flags='PA',seq=1,ack=1)/Raw(hello),
             Ether(src='02:00:00:00:00:02',dst='02:00:00:00:00:01')/IP(src='198.51.100.20',dst='192.0.2.10')/TCP(sport=443,dport=43000,flags='PA',seq=1,ack=1+len(hello))/Raw(server)]
    for i,p in enumerate(packets):p.time=1700000000+i*.08
    path=tmp_path/'tls.pcap';wrpcap(str(path),packets)
    item=TransactionService().report(path)['data'][0]
    assert item['stages']['tls']['duration_ms']==pytest.approx(80,abs=.001)
    assert 'ne mesure pas toute' in item['stages']['tls']['note']
    assert item['stages']['tcp']['duration_ms'] is None
    assert item['stages']['http']['duration_ms'] is None
