"""Bounded chart aggregates from the entire saved, sanitized TLS report."""
from collections import Counter
import re


def http_summary(report):
    rows=(report.get('rows') or [])[:10000]
    methods=Counter();codes=Counter();hosts=Counter();urls=Counter();samples=[]
    requests=responses=0
    for row in rows:
        method=row.get('method')
        if isinstance(method,str) and re.fullmatch(r'[A-Z][A-Z0-9_-]{0,23}',method):
            requests+=1;methods[method]+=1
            if row.get('host'):hosts[str(row['host'])[:255]]+=1
            if row.get('path'):urls[str(row['path'])[:512]]+=1
            if len(samples)<25:
                samples.append({k:row[k] for k in ('method','host','path','source','destination','frame_number','packet_index','stream_id') if k in row})
        status=row.get('status')
        if isinstance(status,int) and 100<=status<=599:
            responses+=1;codes[str(status)]+=1
    readiness=report.get('readiness') or {}
    versions=readiness.get('version_counts') or dict(Counter(s.get('version','Inconnue') for s in readiness.get('sessions',[])))
    versions={str(k).replace('TLS ','TLSv').replace('SSL ','SSLv'):v for k,v in versions.items() if isinstance(v,int) and v>0}
    top=lambda counts:[{'name':key,'count':count} for key,count in counts.most_common(20)]
    return {'total_requests':requests,'total_responses':responses,
            'methods':dict(methods.most_common(20)),'status_codes':dict(codes),
            'hosts':top(hosts),'top_urls':top(urls),'requests_sample':samples,
            'tls_versions':versions,'tls_versions_sampled':bool(readiness.get('coverage',{}).get('truncated') or readiness.get('coverage',{}).get('packet_scan_limit')) or (not bool(readiness.get('version_counts')) and readiness.get('observed_sessions',0)>len(readiness.get('sessions',[]))),
            'user_agents_available':False,'row_limit':10000,
            'truncated':len(report.get('rows') or [])>=10000}
