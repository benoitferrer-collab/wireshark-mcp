from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap
from app.services.multi_pcap_service import MultiPcapAnalysisService, CaptureInput


def points(tmp_path, downstream_payload=b'alpha', downstream_id=999, offset=2, repeat=False, omit=False):
    client='192.0.2.10';nat='203.0.113.10';server='198.51.100.20'
    def packets(c, port, ipid, payload, shift):
        p=[IP(src=c,dst=server,id=ipid)/TCP(sport=port,dport=443,flags='S',seq=100),
           IP(src=server,dst=c,id=ipid+1)/TCP(sport=443,dport=port,flags='SA',seq=200,ack=101),
           IP(src=c,dst=server,id=ipid+2)/TCP(sport=port,dport=443,flags='A',seq=101,ack=201),
           IP(src=c,dst=server,id=ipid+3)/TCP(sport=port,dport=443,flags='PA',seq=101,ack=201)/Raw(payload),
           IP(src=server,dst=c,id=ipid+4)/TCP(sport=443,dport=port,flags='PA',seq=201,ack=106)/Raw(b'reply')]
        if repeat:p.append(p[3].copy())
        result=[]
        for i,row in enumerate(p):
            row=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/row;row.time=1700000000+i*.02+shift;result.append(row)
        return result
    a=packets(client,43000,10,b'alpha',0)
    b=packets(nat,55000,downstream_id,downstream_payload,offset)
    if omit:b=b[:3]+b[4:]
    output=[]
    for i,packets_ in enumerate([a,b]):
        path=tmp_path/f'point{i}.pcap';wrpcap(str(path),packets_)
        output.append(CaptureInput(path,path.name,['LAN','WAN'][i],i))
    return output


def test_nat_and_ipid_rewrite_keep_directional_packet_evidence(tmp_path):
    result=MultiPcapAnalysisService().analyze(points(tmp_path))
    segment=result['packet_match']['segments'][0]
    assert segment['matched_packets']==2
    assert segment['unmatched_packets']==0
    assert segment['confirmed_loss_packets'] is None
    assert segment['loss_ratio'] is None
    assert {row['direction'] for row in segment['directions']}=={'client_to_server','server_to_client'}
    assert segment['evidence'][0]['from_frame'] in (4,5)
    assert segment['evidence'][0]['to_frame'] in (4,5)
    assert 'payload_digest' not in str(result)


def test_repeated_occurrences_are_preserved_and_ambiguity_is_explicit(tmp_path):
    result=MultiPcapAnalysisService().analyze(points(tmp_path,repeat=True))
    segment=result['packet_match']['segments'][0]
    assert segment['upstream_packets']==3
    assert segment['matched_packets']==3
    assert segment['ambiguous_packets']>=2
    assert all(row['pairing']=='occurrence_candidate' for row in segment['evidence'] if row['from_frame'] in (4,6))


def test_missing_packets_are_visibility_gaps_not_confirmed_network_loss(tmp_path):
    result=MultiPcapAnalysisService().analyze(points(tmp_path,omit=True))
    segment=result['packet_match']['segments'][0]
    assert segment['unmatched_packets']==1
    assert segment['confirmed_loss_packets'] is None
    assert segment['loss_ratio'] is None
    assert any(row['state']=='not_observed_at_other_point' for row in segment['evidence'])
    assert all('jamais' not in text for verdict in result['bottleneck_verdicts'] for text in verdict['reasons'])


def test_packet_caps_are_exact_and_visible_in_quality(tmp_path):
    result=MultiPcapAnalysisService().analyze(points(tmp_path),max_packets_per_capture=4)
    assert all(point['packet_count']==4 for point in result['capture_points'])
    assert all(point['coverage']['packet_limit_reached'] for point in result['capture_points'])
    assert all(segment['confidence']=='LOW' for segment in result['packet_match']['segments'])


def test_no_corresponding_data_has_unknown_relative_delay(tmp_path):
    captures=points(tmp_path,downstream_payload=b'xxxxx')
    # Same client/ports so flow identity remains known, but payloads differ.
    from scapy.all import rdpcap
    packets=rdpcap(str(captures[1].file_path))
    for row in packets:
        if row[IP].src=='203.0.113.10':row[IP].src='192.0.2.10';row[TCP].sport=43000
        else:row[IP].dst='192.0.2.10';row[TCP].dport=43000
        if Raw in row:row[Raw].load=b'xxxxx'
        del row[IP].chksum;del row[TCP].chksum
    wrpcap(str(captures[1].file_path),packets)
    result=MultiPcapAnalysisService().analyze(captures)
    segment=result['packet_match']['segments'][0]
    assert segment['matched_packets']==0
    assert segment['relative_delay_ms']['p95'] is None
    assert segment['clock_offset_seconds'] is None

def test_nat_flow_is_not_rejected_when_signature_samples_do_not_overlap():
    service=MultiPcapAnalysisService()
    def flow(client,start):
        return {'protocol':'TCP','service_port':443,'client_ip':client,'client_port':43000,'server_ip':'198.51.100.20',
                'participant_ips':[client,'198.51.100.20'],'participant_ports':[43000,443],
                'packet_count':200,'duration_seconds':4,'reference_ts':1,
                'fp_by_dir':{(client,43000,'198.51.100.20',443):{i:[] for i in range(start,start+200)}}}
    assert service._score_match(flow('192.0.2.10',0),flow('203.0.113.10',64),5)>=40


def test_ambiguous_occurrence_has_no_individual_raw_or_relative_delay(tmp_path):
    result=MultiPcapAnalysisService().analyze(points(tmp_path,repeat=True))
    rows=[row for row in result['packet_match']['segments'][0]['evidence'] if row['pairing']=='occurrence_candidate']
    assert rows and all(row['raw_delta_ms'] is None and row['relative_delta_ms'] is None for row in rows)


def test_opposite_directions_are_never_flattened_through_nat(tmp_path):
    from scapy.all import rdpcap
    captures=points(tmp_path,omit=True)
    packets=rdpcap(str(captures[1].file_path))
    # Make the WAN server->client packet share the LAN client->server signature.
    packets[-1][TCP].seq=101;packets[-1][Raw].load=b'alpha'
    del packets[-1][TCP].chksum
    wrpcap(str(captures[1].file_path),packets)
    result=MultiPcapAnalysisService().analyze(captures)
    segment=result['packet_match']['segments'][0]
    assert segment['matched_packets']==0
    assert segment['unmatched_packets']==2
    assert segment['right_only_packets']==1


def test_result_is_json_serializable_without_payload_or_internal_digests(tmp_path):
    import json
    result=MultiPcapAnalysisService().analyze(points(tmp_path))
    text=json.dumps(result)
    assert 'alpha' not in text and 'reply' not in text and '_fp_by_dir' not in text

def test_original_tcp_bytes_are_used_without_serializing_tls_objects():
    from types import SimpleNamespace
    class Payload:
        def __bytes__(self):raise AssertionError('Must not serialize Scapy TLS payload')
    tcp=SimpleNamespace(original=b'\0'*20+b'alpha',dataofs=5,payload=Payload())
    assert MultiPcapAnalysisService._captured_tcp_payload(tcp,5)==b'alpha'
    tcp.original=b'\0'*20+b'al'
    assert MultiPcapAnalysisService._captured_tcp_payload(tcp,5) is None


def test_snaplen_truncation_is_visible_and_excluded_from_signatures(tmp_path):
    from scapy.all import rdpcap
    captures=points(tmp_path)
    packets=list(rdpcap(str(captures[0].file_path)))
    original=bytes(packets[3]);truncated=Ether(original[:-2]);truncated.wirelen=len(original);truncated.time=packets[3].time
    packets[3]=truncated;wrpcap(str(captures[0].file_path),packets)
    result=MultiPcapAnalysisService().analyze(captures)
    assert result['capture_points'][0]['coverage']['truncated_packets']==1
    segment=result['packet_match']['segments'][0]
    assert segment['coverage_partial'] is True and segment['confidence']=='LOW'
    assert all(row['from_frame']!=4 for row in segment['evidence'])

def test_per_session_timing_cap_is_explicit_even_below_segment_cap():
    from app.services.multi_pcap_evidence import match_evidence
    def hop(index,shift):
        return {'capture_index':index,'client_ip':'192.0.2.1','client_port':50000,'server_ip':'198.51.100.1','server_port':443,
                'tcp_metrics':{'syn':1},'_fp_by_dir':{('192.0.2.1',50000,'198.51.100.1',443):{i:[{'frame':i+1,'timestamp':10+i+shift}] for i in range(3)}}}
    result=match_evidence([{'equipment_name':'A'},{'equipment_name':'B'}],[{'session_id':'s','hops':[hop(0,0),hop(1,2)]}],1)
    assert result['segments'][0]['sample_count']==1
    assert result['segments'][0]['directions'][0]['timing_sample_capped'] is True
