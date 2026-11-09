"""Bounded cross-capture evidence. Unmatched observations never establish loss."""
from collections import defaultdict
from statistics import median
from math import isfinite


def percentile(values, percent):
    if not values:return None
    ordered=sorted(values);position=(len(ordered)-1)*percent/100;low=int(position);high=min(low+1,len(ordered)-1)
    return ordered[low]+(ordered[high]-ordered[low])*(position-low)


def timing(values):
    return {key:round(value,3) if value is not None else None for key,value in {
        'min':min(values) if values else None,'p50':percentile(values,50),
        'p95':percentile(values,95),'p99':percentile(values,99),'max':max(values) if values else None}.items()}


def logical_maps(hop):
    output={}
    client=(hop.get('client_ip'),hop.get('client_port'));server=(hop.get('server_ip'),hop.get('server_port'))
    for endpoints, signatures in (hop.get('_fp_by_dir') or {}).items():
        direction='client_to_server' if endpoints[:2]==client else 'server_to_client' if endpoints[:2]==server else None
        if direction:
            target=output.setdefault(direction,{})
            for signature,occurrences in signatures.items():
                target.setdefault(signature,[]).extend(occurrences)
    return output


def match_evidence(capture_points,sessions,max_samples_per_session=2000):
    buckets={};per_session={}
    for session in sessions:
        hops={hop['capture_index']:hop for hop in session.get('hops',[])}
        for index in range(len(capture_points)-1):
            a,b=hops.get(index),hops.get(index+1)
            if not a or not b:continue
            left,right=logical_maps(a),logical_maps(b)
            if not left and not right:continue
            pair=(index,index+1)
            bucket=buckets.setdefault(pair,{'directions':{},'evidence':[],'partial':False,'heuristic_direction':False})
            bucket['partial'] |= any(capture_points[i].get('coverage',{}).get('packet_limit_reached') or capture_points[i].get('coverage',{}).get('fingerprint_limit_reached') or capture_points[i].get('coverage',{}).get('truncated_packets') for i in pair) or a.get('fingerprints_truncated',False) or b.get('fingerprints_truncated',False)
            bucket['heuristic_direction'] |= any(not hop.get('tcp_metrics',{}).get('syn') for hop in (a,b))
            row={'from_capture_index':index,'to_capture_index':index+1,'matched_packets':0,'upstream_packets':0,
                 'unmatched_packets':0,'right_only_packets':0,'ambiguous_packets':0,'_deltas':[],
                 'lost_packets':None,'loss_ratio':None,'confirmed_loss_packets':None,'loss_assessment':'not_established'}
            for direction in sorted(set(left)|set(right)):
                one,two=left.get(direction,{}),right.get(direction,{})
                stat=bucket['directions'].setdefault(direction,{'raw':[],'reference':0,'matched':0,'missing':0,'other_only':0,'ambiguous':0,'sample_capped':False})
                remaining=max_samples_per_session
                for signature in sorted(set(one)|set(two)):
                    aa=one.get(signature,[]);bb=two.get(signature,[])
                    count=min(len(aa),len(bb));repeated=len(aa)>1 or len(bb)>1
                    missing=max(0,len(aa)-count);other_only=max(0,len(bb)-count)
                    stat['reference']+=len(aa);stat['matched']+=count;stat['missing']+=missing;stat['other_only']+=other_only
                    stat['ambiguous']+=count if repeated else 0
                    row['upstream_packets']+=len(aa);row['matched_packets']+=count;row['unmatched_packets']+=missing;row['right_only_packets']+=other_only;row['ambiguous_packets']+=count if repeated else 0
                    if count and not repeated:
                        value=bb[0]['timestamp']-aa[0]['timestamp']
                        if isfinite(value) and remaining>0:
                            row['_deltas'].append((direction,value));remaining-=1
                            if len(stat['raw'])<5000:stat['raw'].append(value)
                            else:stat['sample_capped']=True
                        elif isfinite(value):
                            stat['sample_capped']=True
                    # Keep only a small, payload-free sample for the whole segment.
                    room=12-len(bucket['evidence'])
                    for offset in range(min(count,room)):
                        first,last=aa[offset],bb[offset]
                        bucket['evidence'].append({'session_id':session.get('session_id'),'direction':direction,
                            'from_frame':first['frame'],'to_frame':last['frame'],
                            'raw_delta_ms':None if repeated else round((last['timestamp']-first['timestamp'])*1000,3),
                            'state':'matched_candidate','pairing':'occurrence_candidate' if repeated else 'unique_signature',
                            '_delta':None if repeated else last['timestamp']-first['timestamp']})
                    room=12-len(bucket['evidence'])
                    for first in aa[count:count+room]:
                        bucket['evidence'].append({'session_id':session.get('session_id'),'direction':direction,
                            'from_frame':first['frame'],'to_frame':None,'raw_delta_ms':None,
                            'state':'not_observed_at_other_point','pairing':None,'_delta':None})
                    room=12-len(bucket['evidence'])
                    for last in bb[count:count+room]:
                        bucket['evidence'].append({'session_id':session.get('session_id'),'direction':direction,
                            'from_frame':None,'to_frame':last['frame'],'raw_delta_ms':None,
                            'state':'only_observed_at_other_point','pairing':None,'_delta':None})
            row['unmatched_ratio']=round(row['unmatched_packets']/row['upstream_packets'],6) if row['upstream_packets'] else None
            per_session.setdefault(str(session.get('session_id')),[]).append(row)
    segments=[];baselines={}
    for (a,b),bucket in sorted(buckets.items()):
        directions=[];relative=[];all_raw=[]
        for name,stat in sorted(bucket['directions'].items()):
            baseline=median(stat['raw']) if stat['raw'] else None
            baselines[(a,b,name)]=baseline
            values=[(value-baseline)*1000 for value in stat['raw']] if baseline is not None else []
            relative.extend(values);all_raw.extend(stat['raw'])
            directions.append({'direction':name,'reference_packets':stat['reference'],'matched_packets':stat['matched'],
                'unmatched_packets':stat['missing'],'right_only_packets':stat['other_only'],'ambiguous_packets':stat['ambiguous'],
                'timing_sample_count':len(values),'timing_sample_capped':stat['sample_capped'],
                'median_raw_offset_seconds':round(baseline,6) if baseline is not None else None,'relative_delay_ms':timing(values)})
        reference=sum(d['reference_packets'] for d in directions);matched=sum(d['matched_packets'] for d in directions)
        unmatched=sum(d['unmatched_packets'] for d in directions);ambiguous=sum(d['ambiguous_packets'] for d in directions)
        ratio=matched/reference if reference else None
        confidence='HIGH' if len(relative)>=50 and (ratio or 0)>=.7 else 'MEDIUM' if len(relative)>=10 and (ratio or 0)>=.4 else 'LOW'
        warnings=['Non-appariement ≠ perte réseau : vérifier fenêtres, SPAN/TAP, asymétrie, segmentation/offload et transformations TCP.',
                  'Décalage brut médian = horloge et transit confondus ; seules les variations centrées par sens sont publiées. Dérive des horloges non estimée.']
        if bucket['partial']:confidence='LOW';warnings.append('Lecture, trames ou index d’empreintes incomplets : confiance limitée.')
        if bucket['heuristic_direction']:confidence='LOW';warnings.append('Au moins un sens client/serveur est déduit sans SYN observé.')
        if any(item['timing_sample_capped'] for item in directions):
            warnings.append('Échantillons temporels plafonnés : les variations portent sur les paires retenues, pas sur toutes les occurrences.')
            if confidence=='HIGH':confidence='MEDIUM'
        if ambiguous and confidence=='HIGH':confidence='MEDIUM'
        if ambiguous:warnings.append('Occurrences répétées : appariement candidat par ordre, exclu des mesures temporelles.')
        for evidence in bucket['evidence']:
            value=evidence.pop('_delta');baseline=baselines[(a,b,evidence['direction'])]
            evidence['relative_delta_ms']=round((value-baseline)*1000,3) if value is not None and baseline is not None else None
        offset=median(all_raw) if all_raw else None
        segment={'from_capture_index':a,'to_capture_index':b,'from_equipment':capture_points[a].get('equipment_name'),
                 'to_equipment':capture_points[b].get('equipment_name'),
                 'segment':f"{capture_points[a].get('equipment_name')} -> {capture_points[b].get('equipment_name')}",
                 'method_version':2,'matched_packets':matched,'upstream_packets':reference,'unmatched_packets':unmatched,
                 'right_only_packets':sum(d['right_only_packets'] for d in directions),'ambiguous_packets':ambiguous,
                 'match_ratio':round(ratio,4) if ratio is not None else None,
                 'unmatched_ratio':round(unmatched/reference,6) if reference else None,
                 'confirmed_loss_packets':None,'lost_packets':None,'loss_ratio':None,'loss_assessment':'not_established',
                 'sample_count':len(relative),'clock_offset_seconds':round(offset,6) if offset is not None else None,
                 'clock_offset_warning':abs(offset)>1 if offset is not None else False,
                 'relative_delay_ms':timing(relative),'queuing_jitter_ms':round(percentile(relative,95)-min(relative),3) if relative else None,
                 'confidence':confidence,'coverage_partial':bucket['partial'],'quality_warnings':warnings,
                 'directions':directions,'evidence':bucket['evidence']}
        segments.append(segment)
    for rows in per_session.values():
        for row in rows:
            values=[]
            for direction,value in row.pop('_deltas'):
                base=baselines.get((row['from_capture_index'],row['to_capture_index'],direction))
                if base is not None:values.append((value-base)*1000)
            row['relative_delay_ms']=timing(values);row['sample_count']=len(values)
    worst=max(segments,key=lambda s:s.get('unmatched_ratio') or 0,default=None)
    with_delays=[s for s in segments if s['relative_delay_ms']['p95'] is not None]
    slow=max(with_delays,key=lambda s:s['relative_delay_ms']['p95'],default=None)
    return {'segments':segments,'per_session':per_session,'worst_loss_segment':None,
            'worst_visibility_segment':worst['segment'] if worst and worst['unmatched_packets'] else None,
            'worst_delay_segment':slow['segment'] if slow else None,
            'method':'Occurrences TCP data : séquence, longueur, flags et empreinte de contenu interne, par sens logique. '
                     'NAT/IP-ID exclus. Répétitions explicites, délais relatifs par sens ; pertes et délais absolus non établis.'}
