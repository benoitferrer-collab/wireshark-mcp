"""Reproducible offline support scenario. No real traffic, keys or external enrichment."""
import json
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap
from app.services.pcap_service import PCAPAnalysisService

ROOT=Path(__file__).resolve().parents[1]
DEST=ROOT/'app/demo_data'
NAME='DEMO_Nomios_Support.pcap'

def build():
    DEST.mkdir(exist_ok=True)
    packets=[]
    def add(packet, offset):
        packet.time=1794229200+offset
        packets.append(packet)
    client='192.0.2.10';server='198.51.100.20';resolver='192.0.2.53'
    def frame(src,dst):
        return Ether(src='02:00:00:00:00:01' if src==client else '02:00:00:00:00:02',dst='02:00:00:00:00:02' if src==client else '02:00:00:00:00:01')/IP(src=src,dst=dst)
    for i in range(24):
        t=i*2.;port=42000+i;domain=b'portail.support.example';name=domain if i%6 else b'introuvable.support.example'
        add(frame(client,resolver)/UDP(sport=53000+i,dport=53)/DNS(id=i,qd=DNSQR(qname=name)),t)
        if i%6:
            add(frame(resolver,client)/UDP(sport=53,dport=53000+i)/DNS(id=i,qr=1,qd=DNSQR(qname=name),an=DNSRR(rrname=name,rdata=server),ancount=1),t+.025)
        else:
            add(frame(resolver,client)/UDP(sport=53,dport=53000+i)/DNS(id=i,qr=1,rcode=3,qd=DNSQR(qname=name)),t+.4)
        add(frame(client,server)/TCP(sport=port,dport=80,flags='S',seq=1000),t+.5)
        add(frame(server,client)/TCP(sport=80,dport=port,flags='SA',seq=5000,ack=1001),t+.52)
        add(frame(client,server)/TCP(sport=port,dport=80,flags='A',seq=1001,ack=5001),t+.54)
        request=b'GET /support/incident HTTP/1.1\r\nHost: portail.support.example\r\n\r\n'
        add(frame(client,server)/TCP(sport=port,dport=80,flags='PA',seq=1001,ack=5001)/Raw(request),t+.6)
        if i%4==0:
            add(frame(client,server)/TCP(sport=port,dport=80,flags='PA',seq=1001,ack=5001)/Raw(request),t+.9)
            add(frame(server,client)/TCP(sport=80,dport=port,flags='RA',seq=5001,ack=1001+len(request)),t+1.2)
        else:
            reply=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK'
            add(frame(server,client)/TCP(sport=80,dport=port,flags='PA',seq=5001,ack=1001+len(request))/Raw(reply),t+.8)
            add(frame(client,server)/TCP(sport=port,dport=80,flags='FA',seq=1001+len(request),ack=5001+len(reply)),t+1.)
    packets.sort(key=lambda p:p.time)
    path=DEST/NAME;wrpcap(str(path),packets)
    results=PCAPAnalysisService().analyze(path,NAME,enable_enrichment=False)
    results['metadata'].update({'demo':True,'demo_version':1,'analysis_timestamp':'2026-11-09T13:00:00Z','analysis_duration_seconds':0,'pcap_path':NAME})
    results.get('streams',{}).update({'pcap_path':NAME})
    (DEST/'results.json').write_text(json.dumps(results,separators=(',',':'),default=str))
    print('Synthetic demo generated:',len(packets),'packets')
if __name__=='__main__':build()
