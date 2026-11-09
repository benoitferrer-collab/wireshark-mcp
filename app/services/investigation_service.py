"""Bounded offline Wireshark investigations. No payloads or user-selected argv."""
import csv
import io
import ipaddress
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time

from mcp_gateway.search_schema import SearchFilters, normalize_indicator, indicator_filter

SCAN_LOCK = threading.BoundedSemaphore(1)
FIELDS = (
    'frame.number', 'frame.time_epoch', 'frame.len', 'frame.protocols',
    'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst', 'tcp.srcport', 'tcp.dstport',
    'udp.srcport', 'udp.dstport', 'tcp.stream', 'tcp.flags.reset',
    'tcp.analysis.retransmission', 'tcp.analysis.ack_rtt', 'dns.qry.name',
    'dns.flags.response', 'dns.flags.rcode', 'dns.a', 'dns.aaaa',
    'tls.handshake.extensions_server_name', 'http.host', 'http.request.method', 'http.response.code',
    'tcp.flags.syn', 'tcp.flags.ack', 'tcp.seq_raw', 'tcp.ack_raw', 'tcp.len',
    'tls.handshake.type', 'http.request_in', 'dns.response_to',
)
PRESETS = {
    'tcp-failures': ('tcp.flags.reset == 1 || tcp.analysis.retransmission || tcp.analysis.lost_segment',
                     'Transport errors are observations; retransmission analysis depends on capture position and completeness.'),
    'dns-failures': ('dns.flags.response == 1 && dns.flags.rcode != 0',
                     'DNS failures may be normal; correlate names, timing and repetition.'),
    'cleartext': ('http || ftp || telnet || pop || imap || smtp',
                  'Protocol presence is not proof of leaked credentials; STARTTLS and encrypted upgrades require inspection.'),
    'remote-access': ('tcp.port in {22 23 3389 445 5985 5986} || udp.port == 3389',
                      'Port-based candidate only; this does not prove protocol, lateral movement or compromise.'),
    'tls-handshakes': ('tls.handshake || tls.alert_message',
                       'Handshake/alert visibility does not imply successful decryption or malicious behavior.'),
}


class InvestigationError(ValueError):
    pass



def _number(value,cast=int):
    try: return cast(value.split(',')[-1] if isinstance(value,str) else value)
    except (ValueError,TypeError): return None


def _decode(values):
    row=dict(zip(FIELDS,values))
    frame=_number(row.get('frame.number'))
    if frame is None: return None
    tcp=bool(row.get('tcp.srcport'))
    split=lambda field: [v for v in row.get(field,'').split(',') if v]
    src_ips=split('ip.src')+split('ipv6.src'); dst_ips=split('ip.dst')+split('ipv6.dst')
    result = {
        'frame_number':frame,'packet_index':frame-1,
        'timestamp':_number(row.get('frame.time_epoch'),float),'length':_number(row.get('frame.len')),
        'protocols':row.get('frame.protocols','')[:300],
        'src_ip':src_ips[-1] if src_ips else '',
        'dst_ip':dst_ips[-1] if dst_ips else '',
        'src_port':_number(row.get('tcp.srcport') or row.get('udp.srcport')),
        'dst_port':_number(row.get('tcp.dstport') or row.get('udp.dstport')),
        'transport':'TCP' if tcp else ('UDP' if row.get('udp.srcport') else 'other'),
        'tcp_stream':_number(row.get('tcp.stream')),
        'tcp_reset':any(v.lower() in {'1','true'} for v in split('tcp.flags.reset')),
        'retransmission':bool(row.get('tcp.analysis.retransmission')),
        'ack_rtt_seconds':_number(row.get('tcp.analysis.ack_rtt'),float),
        'dns_name':row.get('dns.qry.name','')[:253], 'dns_response':any(v.lower() in {'1','true'} for v in split('dns.flags.response')),
        'dns_rcode':_number(row.get('dns.flags.rcode')),
        'dns_answers':','.join(filter(None,[row.get('dns.a'),row.get('dns.aaaa')]))[:1000],
        'tls_server_name':row.get('tls.handshake.extensions_server_name','')[:253],
        'http_host':row.get('http.host','')[:253], 'http_method':row.get('http.request.method','')[:20],
        'http_status':_number(row.get('http.response.code')),
        'tcp_syn':any(v.lower() in {'1','true'} for v in split('tcp.flags.syn')),
        'tcp_ack':any(v.lower() in {'1','true'} for v in split('tcp.flags.ack')),
        'tcp_sequence':_number(row.get('tcp.seq_raw')), 'tcp_ack_number':_number(row.get('tcp.ack_raw')),
        'tcp_payload_length':_number(row.get('tcp.len')),
        'tls_handshake_types':[_number(v) for v in split('tls.handshake.type')],
        'http_request_frames':[_number(v) for v in split('http.request_in')],
        'dns_request_frame':_number(row.get('dns.response_to')),
    }
    result.update(src_ips=src_ips,dst_ips=dst_ips,dns_names=split('dns.qry.name'),
                  tls_server_names=split('tls.handshake.extensions_server_name'),http_hosts=split('http.host'),
                  dns_answer_ips=split('dns.a')+split('dns.aaaa'))
    return result


class CaptureInvestigator:
    def __init__(self,max_packets=250000,timeout=20,max_output=8*1024*1024):
        self.max_packets,self.timeout,self.max_output=max_packets,timeout,max_output

    def scan(self,path,expression):
        executable=os.getenv('TSHARK_PATH') or shutil.which('tshark')
        if not executable: raise InvestigationError('TShark engine unavailable; deploy the investigation-enabled application image')
        if not SCAN_LOCK.acquire(blocking=False): raise InvestigationError('Investigation busy; retry after the current scan')
        try:
            with tempfile.TemporaryDirectory(prefix='pcap-investigate-') as config, tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                # Extra sentinel frame proves a packet-cap stop even when the user's filter matches nothing.
                argv=[executable,'-n','-l','-r',str(path),'-c',str(self.max_packets+1),
                      '-Y',f'({expression}) || frame.number == {self.max_packets+1}',
                      '-T','fields','-E','separator=\t','-E','quote=d','-E','occurrence=a','-E','escape=y']
                for field in FIELDS: argv.extend(['-e',field])
                env={'PATH':os.defpath,'LC_ALL':'C','HOME':config,'XDG_CONFIG_HOME':config,'WIRESHARK_CONFIG_DIR':config}
                try: process=subprocess.Popen(argv,stdout=out,stderr=err,stdin=subprocess.DEVNULL,env=env,start_new_session=True)
                except OSError: raise InvestigationError('TShark engine unavailable') from None
                started=time.monotonic()
                reason=None
                try:
                    while True:
                        if os.fstat(out.fileno()).st_size > self.max_output or os.fstat(err.fileno()).st_size > self.max_output:
                            reason='output_limit'; break
                        if time.monotonic()-started >= self.timeout:
                            reason='time_limit'; break
                        if process.poll() is not None: break
                        time.sleep(.02)
                finally:
                    if process.poll() is None:
                        try: os.killpg(process.pid,signal.SIGKILL)
                        except ProcessLookupError: pass
                    process.wait()
                if reason is None and process.returncode:
                    raise InvestigationError('Invalid display filter or unreadable capture; verify filter syntax and capture availability')
                out.seek(0)
                raw=out.read(self.max_output)
                if reason or len(raw)==self.max_output:
                    # Only parse complete lines after a terminated/truncated scan.
                    raw=raw[:raw.rfind(b'\n')+1] if b'\n' in raw else b''
                rows=[]
                for values in csv.reader(io.StringIO(raw.decode('utf-8','replace')),delimiter='\t'):
                    row=_decode(values)
                    if not row: continue
                    if row['frame_number'] > self.max_packets:
                        reason=reason or 'packet_limit'
                    else: rows.append(row)
                return rows, {'scope':'original_capture','engine':'tshark','complete':reason is None,
                              'reason':reason,'max_input_packets':self.max_packets,'time_budget_seconds':self.timeout,
                              'output_budget_bytes':self.max_output,'name_resolution':False}
        finally: SCAN_LOCK.release()

    @staticmethod
    def envelope(data,coverage,**extra):
        return {'data':data,'coverage':coverage,**extra,'limitations':[
            'Only allowlisted protocol metadata is returned; no raw payload, cookies, credentials or URL query strings.',
            'No match is evidence of absence only within the inspected scope; incomplete scans cannot establish absence.',
            'Timestamps are Unix epoch seconds; packet_index is zero-based, frame_number is one-based.',
        ]}

    def search(self,path,filters,after_frame=0,limit=25):
        if not 1 <= limit <=25 or after_frame<0: raise InvestigationError('limit must be 1..25 and after_frame >= 0')
        rows,coverage=self.scan(path,filters.expression())
        page=[row for row in rows if row['frame_number']>after_frame]
        has_more=len(page)>limit
        return self.envelope(page[:limit],coverage,display_filter=filters.expression(),
                             total_matching=len(rows) if coverage['complete'] else None,
                             observed_matching=len(rows),next_after_frame=page[limit-1]['frame_number'] if has_more else None)

    def conversations(self,path,filters,offset=0,limit=25,sort_by='bytes'):
        if not 1<=limit<=25 or offset<0 or sort_by not in {'bytes','packets','resets','retransmissions'}:
            raise InvestigationError('Invalid conversation sort or pagination')
        rows,coverage=self.scan(path,filters.expression())
        groups={}
        for row in rows:
            a,b=sorted([(row['src_ip'],row['src_port'] or 0),(row['dst_ip'],row['dst_port'] or 0)])
            key=(row['transport'],a,b,row['tcp_stream'])
            if key not in groups:
                groups[key]={'transport':key[0],'endpoint_a':{'ip':a[0],'port':a[1]},'endpoint_b':{'ip':b[0],'port':b[1]},
                             'tcp_stream':row['tcp_stream'],'packet_count':0,'bytes':0,'rst_count':0,'retransmissions':0,
                             'first_frame':row['frame_number'],'last_frame':row['frame_number'],
                             'first_timestamp':row['timestamp'],'last_timestamp':row['timestamp']}
            group=groups[key]
            group['packet_count']+=1; group['bytes']+=row['length'] or 0
            group['rst_count']+=int(row['tcp_reset']); group['retransmissions']+=int(row['retransmission'])
            group['last_frame']=row['frame_number']; group['last_timestamp']=row['timestamp']
        field={'bytes':'bytes','packets':'packet_count','resets':'rst_count','retransmissions':'retransmissions'}[sort_by]
        ordered=sorted(groups.values(),key=lambda r:(-r[field],r['first_frame']))
        return self.envelope(ordered[offset:offset+limit],coverage,total=len(ordered),
                             next_offset=offset+limit if offset+limit<len(ordered) else None,
                             aggregation_scope='packets_matching_filter',sort_by=sort_by)

    def hunt(self,path,indicators):
        if not 1<=len(indicators)<=25: raise InvestigationError('Provide 1..25 indicators')
        normalized=[normalize_indicator(v) for v in indicators]
        rows,coverage=self.scan(path,' || '.join(f'({indicator_filter(v)})' for v in indicators))
        findings=[]
        for original,(kind,value) in zip(indicators,normalized):
            matches=[]
            for row in rows:
                if kind=='ip':
                    net=ipaddress.ip_network(value)
                    addresses=row['src_ips']+row['dst_ips']+row['dns_answer_ips']
                    matched=any(ipaddress.ip_address(a) in net for a in addresses if a and _valid_ip(a))
                else:
                    matched=any(name.lower().rstrip('.')==value or name.lower().rstrip('.').endswith('.'+value)
                                for name in row['dns_names']+row['tls_server_names']+row['http_hosts'])
                if matched: matches.append(row)
            findings.append({'indicator':original,'normalized':value,'kind':kind,'matched_packets':len(matches),
                             'evidence':[{k:r[k] for k in ('frame_number','packet_index','timestamp','src_ip','dst_ip','dns_name','tls_server_name','http_host')}
                                         for r in matches[:3]],'evidence_truncated':len(matches)>3,
                             'status':'observed' if matches else ('not_observed' if coverage['complete'] else 'unknown')})
        return self.envelope(findings,coverage)

    def triage(self,path,preset,after_frame=0,limit=25):
        if preset not in PRESETS: raise InvestigationError('Unknown triage preset')
        expression,note=PRESETS[preset]
        result=self.search(path,SearchFilters(display_filter=expression),after_frame,limit)
        result['preset']=preset
        result['limitations'].append('Heuristic triage: '+note)
        return result

    def statistics(self,path,filters,group_by,offset=0,limit=25):
        fields={'source':'src_ip','destination':'dst_ip','dns':'dns_name','tls':'tls_server_name','http':'http_host',
                'transport':'transport','timeline':'timestamp'}
        if group_by not in fields: raise InvestigationError('Invalid grouping')
        rows,coverage=self.scan(path,filters.expression())
        groups={}
        for row in rows:
            value=row.get(fields[group_by])
            if value is None or value=='': continue
            # Minute buckets on the absolute UTC Unix timeline, never local-time guesses.
            if group_by=='timeline': value=int(value)//60*60
            if value not in groups:
                groups[value]={'value':value,'packet_count':0,'bytes':0,'rst_count':0,'retransmissions':0,
                               'first_frame':row['frame_number'],'last_frame':row['frame_number']}
            g=groups[value]; g['packet_count']+=1; g['bytes']+=row['length'] or 0
            g['rst_count']+=int(row['tcp_reset']); g['retransmissions']+=int(row['retransmission'])
            g['last_frame']=row['frame_number']
        ordered=sorted(groups.values(),key=(lambda r:r['value']) if group_by=='timeline' else lambda r:(-r['packet_count'],str(r['value'])))
        return self.envelope(ordered[offset:offset+limit],coverage,group_by=group_by,
                             bucket_seconds=60 if group_by=='timeline' else None,total=len(ordered),
                             next_offset=offset+limit if offset+limit<len(ordered) else None,
                             aggregation_scope='packets_matching_filter')


def _valid_ip(value):
    try: ipaddress.ip_address(value); return True
    except ValueError: return False
