import json
from app.services.support_diagnosis import build_report, compare_reports, report_identity


def row(frame, stream=0, **changes):
    value = dict(frame_number=frame, timestamp=1700000000+frame/10, length=60,
                 src_ip='192.0.2.10', dst_ip='198.51.100.20', src_port=42000, dst_port=80,
                 tcp_stream=stream, protocols='eth:ip:tcp', tcp_reset=False, retransmission=False,
                 ack_rtt_seconds=None, tcp_syn=False, tcp_ack=True, tcp_sequence=100,
                 tcp_ack_number=101, tcp_payload_length=0, tls_handshake_types=[],
                 http_method='', http_status=None, http_host='', http_request_frames=[],
                 tls_server_name='', dns_names=[], dns_response=False, dns_name='',
                 dns_rcode=None, dns_request_frame=None, dns_answer_ips=[])
    value.update(changes)
    return value


def test_same_stream_reset_is_linked_to_unanswered_request_not_unrelated_dns():
    rows = [row(1,http_method='GET',http_host='web.example'),row(2,tcp_reset=True),
            row(3,stream=None,dns_response=True,dns_rcode=3,dns_names=['unrelated.example'],dns_name='unrelated.example')]
    report = build_report(rows, {'complete':True})
    finding = next(x for x in report['findings'] if x['kind']=='tcp_reset')
    assert finding['tcp_stream']==0
    assert finding['evidence_frames']==[2,1]
    assert finding['confidence']=='limited'
    assert 'root_cause' not in report
    assert report['method']['trained_model'] is False
    assert report['summary']['rtt_avg_ms'] is None
    assert report['summary']['confirmed_packet_loss'] is None


def test_partial_capture_and_no_signals_never_claim_healthy():
    report=build_report([row(1)], {'complete':False,'reason':'packet_limit'})
    assert report['state']=='insufficient_evidence'
    assert report['coverage']['complete'] is False
    assert report['findings']==[]
    assert report['unknowns']


def test_stable_report_and_findings_do_not_contain_payload_or_raw_identifiers():
    rows=[row(1,tcp_reset=True)]
    a=build_report(rows,{'complete':True})
    b=build_report(rows,{'complete':True})
    assert a['findings'][0]['id']==b['findings'][0]['id']
    assert report_identity('task-a',a)==report_identity('task-a',b)
    assert report_identity('task-b',a)!=report_identity('task-a',a)


def test_reference_only_compares_shared_observed_services_and_keeps_zero():
    def report(host, delay):
        rows=[]
        for i in range(5):
            start=i*3+1
            rows.extend([row(start,stream=i,http_method='GET',http_host=host),
                         row(start+1,stream=i,http_status=200,http_request_frames=[start],
                             src_ip='198.51.100.20',dst_ip='192.0.2.10',src_port=80,dst_port=42000,
                             timestamp=1700000000+start/10+delay)])
        return build_report(rows,{'complete':True})
    a,b=report('web.example',.2),report('web.example',0)
    comparison=compare_reports(a,b)
    stage=next(x for x in comparison['stages'] if x['stage']=='http')
    assert stage['current_median_ms']==200
    assert stage['reference_median_ms']==0
    assert stage['ratio'] is None
    assert stage['difference_ms']==200
    assert compare_reports(a,report('another.example',.1))['state']=='not_comparable'


def test_finding_lists_bounded_and_evidence_original():
    report=build_report([row(i+1,stream=i,tcp_reset=True) for i in range(40)], {'complete':True})
    assert report['observed_findings']==40
    assert len(report['findings'])==20
    assert report['findings_truncated'] is True
    assert all(1<=frame<=40 for f in report['findings'] for frame in f['evidence_frames'])


def test_dns_reference_sample_not_duplicated_across_http_requests():
    query=row(1,stream=None,dns_names=['web.example'],dns_name='web.example',src_port=53000,dst_port=53)
    response=row(2,stream=None,dns_names=['web.example'],dns_name='web.example',dns_response=True,
                 dns_rcode=0,dns_request_frame=1,dns_answer_ips=['198.51.100.20'],
                 src_ip='198.51.100.20',dst_ip='192.0.2.10',src_port=53,dst_port=53000)
    packets=[query,response,row(3,tcp_syn=True,tcp_ack=False)]
    for i in range(4,14):packets.append(row(i,http_method='GET',http_host='web.example'))
    report=build_report(packets,{'complete':True})
    dns=[r for r in report['stage_metrics']['data'] if r['stage']=='dns']
    assert len(dns)==1
    assert dns[0]['samples']==1


def test_keepalive_stream_counters_are_not_recomputed_per_http_request():
    from app.services.transaction_service import TransactionService
    reads=[0]
    class Counted(dict):
        def __getitem__(self,key):
            if key in ('tcp_reset','retransmission'):reads[0]+=1
            return super().__getitem__(key)
    packets=[Counted(row(i+1,http_method='GET')) for i in range(100)]
    assert len(TransactionService.from_rows(packets,{'complete':True},limit=25)['data'])==25
    assert reads[0]<=400


def test_internal_aggregation_caps_input_before_transaction_reconstruction():
    from app.services.transaction_service import TransactionService
    report=TransactionService.from_rows([row(i+1,http_method='GET') for i in range(100)],{'complete':True},internal_limit=10)
    assert report['aggregation_input_truncated'] is True
    assert report['observed_transactions']==10
    assert len(report['data'])==10
