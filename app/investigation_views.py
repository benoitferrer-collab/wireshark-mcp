"""Evidence projections: bounded cross-section correlation, references and comparisons."""
import ipaddress
from urllib.parse import urlencode
from app.mcp_views import SECTIONS, analysis_summary
from mcp_gateway.search_schema import normalize_indicator
from mcp_gateway.policy import HIDDEN_KEYS

MATCH_FIELDS={'src_ip','dst_ip','client_ip','server_ip','src','dst','query','qname','name','queried_domain',
              'domain','hostname','host','sni','server_name','answer','answers','resolved_ips'}
SAFE_FIELDS=MATCH_FIELDS | {'idx','packet_idx','packet_index','timestamp','start_time','end_time',
    'src_port','dst_port','protocol','length','packets','bytes','duration','state','severity','source',
    'rst_count','retransmissions','method','status_code','response_code','query_type','rcode','session_id'}


def evidence_url(task_id,tab='packets',packet_index=None):
    query=urlencode({'task':task_id})
    fragment=urlencode({'tab':tab,**({'packet':packet_index} if packet_index is not None else {})})
    return '/?'+query+'#'+fragment


def attach_references(result,task_id):
    result['task_id']=task_id
    for row in result.get('data',[]):
        if 'packet_index' in row: row['evidence_url']=evidence_url(task_id,packet_index=row['packet_index'])
        if 'first_frame' in row: row['evidence_url']=evidence_url(task_id,packet_index=row['first_frame']-1)
        for packet in row.get('evidence',[]):
            if 'packet_index' in packet: packet['evidence_url']=evidence_url(task_id,packet_index=packet['packet_index'])
    return result


def _dns_answers(value):
    safe=[]
    if not isinstance(value,list): return safe
    for answer in value[:100]:
        if not isinstance(answer,dict): continue
        data=answer.get('data'); record_type=answer.get('type')
        if record_type not in {'A','AAAA','CNAME','PTR','NS'} or not isinstance(data,str): continue
        try:
            kind,normalized=normalize_indicator(data)
            if (record_type in {'A','AAAA'}) != (kind=='ip'): continue
            safe.append({'name':str(answer.get('name',''))[:253],'type':record_type,
                         'data':str(ipaddress.ip_address(data)) if kind=='ip' else normalized})
        except ValueError: continue
    return safe


def _matches(value,kind,entity,endpoint=False):
    if isinstance(value,list):
        return any(_matches(v,kind,entity) for v in value[:100] if not isinstance(v,dict)) or any(
            _matches(a['name'],kind,entity) or _matches(a['data'],kind,entity) for a in _dns_answers(value))
    if not isinstance(value,str): return False
    value=value.lower().rstrip('.')
    if kind=='domain': return value==entity or value.endswith('.'+entity)
    try:
        # src/dst endpoints in stored TCP sessions use IP:port (including unbracketed IPv6).
        if endpoint: addr=ipaddress.ip_address(value.rsplit(':',1)[0].strip('[]'))
        else: addr=ipaddress.ip_address(value)
        return addr in ipaddress.ip_network(entity)
    except ValueError: return False


def correlate(task_id,results,entity,offset=0,limit=25):
    kind,normalized=normalize_indicator(entity)
    found=[]; total=0; visited=0; exhausted=False
    def walk(value,section,pointer,depth=0):
        nonlocal total,visited,exhausted
        visited+=1
        if visited>100000 or depth>12:
            exhausted=True; return
        if isinstance(value,dict):
            if any(_matches(v,kind,normalized,endpoint=k in {'src','dst'}) for k,v in value.items() if k in MATCH_FIELDS):
                if offset<=total<offset+limit:
                    safe={k:v[:300] if isinstance(v,str) else v for k,v in value.items()
                          if k in SAFE_FIELDS and (v is None or isinstance(v,(str,int,float,bool)))}
                    answers=_dns_answers(value.get('answers'))
                    if answers: safe['answers']=answers
                    idx=next((value[k] for k in ('packet_idx','packet_index','idx')
                              if isinstance(value.get(k),int) and value[k]>=0),None)
                    found.append({'section':section,'pointer':pointer,'evidence':safe,
                                  'packet_index':idx,'evidence_url':evidence_url(task_id,'overview' if idx is None else 'packets',idx)})
                total+=1
            for key,child in value.items():
                if key!='answers' and str(key).lower() not in HIDDEN_KEYS and isinstance(child,(dict,list)):
                    walk(child,section,pointer+'/'+str(key).replace('~','~0').replace('/','~1'),depth+1)
                    if visited>100000: break
        elif isinstance(value,list):
            for i,child in enumerate(value):
                walk(child,section,pointer+'/'+str(i),depth+1)
                if visited>100000: break
    sections=sorted((SECTIONS-{'analysis','enrichment','network_graph'}).intersection(results))
    for section in sections:
        walk(results[section],section,'')
        if visited>100000: break
    return {'task_id':task_id,'entity':entity,'normalized':normalized,'data':found,'total_observed':total,
            'next_offset':offset+limit if offset+limit<total else None,
            'coverage':{'scope':'stored_results','complete':False,'traversal_limited':exhausted,'sections':sections,
                        'packet_index':analysis_summary(task_id,results)['packet_index']},
            'limitations':['Correlation is co-occurrence in stored records, not proof of causation or compromise.',
                           'Stored sections may be top-N or truncated; use search_packets for original-capture evidence.']}


def compare(baseline_id,baseline,other_id,other):
    a=analysis_summary(baseline_id,baseline); b=analysis_summary(other_id,other)
    metrics={}
    for key in sorted(set(a['summary'])|set(b['summary'])):
        x,y=a['summary'].get(key),b['summary'].get(key)
        if isinstance(x,(int,float)) and not isinstance(x,bool) and isinstance(y,(int,float)) and not isinstance(y,bool):
            metrics[key]={'baseline':x,'comparison':y,'delta':y-x,'percent_change':round((y-x)/x*100,2) if x else None}
    def severities(results):
        counts={}
        for row in results.get('all_anomalies',[]):
            severity=str(row.get('severity','unknown'))[:30]; counts[severity]=counts.get(severity,0)+1
        return counts
    return {'baseline_task_id':baseline_id,'comparison_task_id':other_id,'metrics':metrics,
            'anomaly_counts':{'baseline':severities(baseline),'comparison':severities(other)},
            'coverage':{'baseline':a['packet_index'],'comparison':b['packet_index']},
            'evidence_urls':[evidence_url(baseline_id,'overview'),evidence_url(other_id,'overview')],
            'limitations':['Raw totals are not normalized for capture duration, capture point or filters.',
                           'Differences do not establish causality; security detections are heuristic.']}
