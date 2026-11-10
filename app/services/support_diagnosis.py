"""Versioned, evidence-first support reasoning. No learned model or causal certainty."""
import hashlib
import json
from collections import defaultdict
from statistics import median
from math import isfinite
from app.services.investigation_service import CaptureInvestigator
from app.services.support_protocols import metrics
from app.services.transaction_service import TransactionService

VERSION = 'support-evidence-1'
LIMIT = 20


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()).hexdigest()[:24]


def report_identity(task_id, report, reference_task_id=None):
    return digest([VERSION, task_id, reference_task_id, report])


def build_report(rows, coverage):
    findings=[]
    groups=defaultdict(list)
    dns_errors=[]
    for row in rows:
        if row.get('tcp_stream') is not None:
            groups[row['tcp_stream']].append(row)
        if row.get('dns_response') and row.get('dns_rcode') not in (None,0):
            dns_errors.append(row)

    def add(kind,title,facts,frames,hypotheses,checks,stream=None,priority='review'):
        frames=list(dict.fromkeys(frames))[:4]
        findings.append({'id':digest([VERSION,kind,stream,frames]), 'kind':kind, 'title':title,
            'priority':priority,'tcp_stream':stream,'facts':facts,'evidence_frames':frames,
            'confidence':'limited','hypotheses':hypotheses,'next_checks':checks,
            'unknowns':['La cause et la responsabilité d’un équipement ne sont pas établies par ces observations.']})

    if dns_errors:
        codes=sorted({r['dns_rcode'] for r in dns_errors})
        names=list(dict.fromkeys(r.get('dns_name') for r in dns_errors if r.get('dns_name')))[:3]
        add('dns_error','Des réponses DNS signalent un échec de résolution.',
            [f"{len(dns_errors)} réponse(s) avec code DNS {', '.join(map(str,codes))}."]+(['Noms observés : '+', '.join(names)] if names else []),
            [r['frame_number'] for r in dns_errors],
            ['Nom absent, politique de résolution ou erreur du résolveur : distinguer les codes et le nom demandé.'],
            ['Vérifier que le nom concerné correspond au service en panne ; comparer la réponse du résolveur attendu.'])
    for stream, packets in groups.items():
        resets=[r['frame_number'] for r in packets if r.get('tcp_reset')]
        retrans=[r['frame_number'] for r in packets if r.get('retransmission')]
        zeros=[r['frame_number'] for r in packets if r.get('zero_window')]
        requests=[r for r in packets if r.get('http_method')]
        answered={frame for r in packets if r.get('http_status') is not None for frame in r.get('http_request_frames',[])}
        unanswered=[r['frame_number'] for r in requests if r['frame_number'] not in answered]
        if resets:
            facts=[f'{len(resets)} reset(s) TCP observé(s) dans la session Wireshark #{stream}.']
            if unanswered:
                facts.append(f'{len(unanswered)} requête(s) HTTP sans réponse corrélée visible dans cette même session.')
            add('tcp_reset','Connexion réinitialisée : vérifier l’émetteur et le contexte.',facts,resets+unanswered,
                ['Fermeture par l’hôte, l’application ou un intermédiaire ; l’adresse source ne suffit pas à attribuer la cause.'],
                ['Examiner la trame RST et l’échange qui la précède.',
                 'Corréler l’horaire avec les journaux applicatifs et pare-feu ; comparer une capture à l’autre extrémité.'],stream,'investigate')
        if zeros:
            add('receiver_window','Fenêtre TCP nulle annoncée.',
                [f'{len(zeros)} annonce(s) Zero Window dans la session #{stream}.'],zeros,
                ['L’extrémité qui annonce la fenêtre peut temporairement ne plus accepter de données.'],
                ['Identifier l’émetteur de la fenêtre nulle, puis vérifier lecture socket, charge et mémoire sur cet hôte.'],stream,'investigate')
        if retrans:
            add('retransmission','Des segments sont retransmis.',
                [f'{len(retrans)} retransmission(s) signalée(s) par Wireshark dans la session #{stream}.'],retrans,
                ['Perte, acquittement retardé, réordonnancement ou artefact de capture restent à départager.'],
                ['Contrôler ACK/SACK et qualité du point de capture ; comparer les mêmes segments à deux endroits.'],stream)
        errors=[r for r in packets if (r.get('http_status') or 0)>=400]
        if errors:
            add('http_error','Des réponses HTTP portent un code d’erreur.',
                [f"Codes observés : {', '.join(map(str,sorted({r['http_status'] for r in errors})))}."],
                [r['frame_number'] for r in errors],
                ['Réponse applicative ou d’un intermédiaire HTTP ; un code seul ne prouve pas une panne du serveur.'],
                ['Identifier le code précis et la requête associée ; rapprocher les journaux de l’application et du proxy.'],stream)
        if unanswered and not resets:
            add('http_unanswered','Une réponse HTTP n’est pas visible.',
                [f'{len(unanswered)} requête(s) sans réponse corrélée visible dans la session #{stream}.'],unanswered,
                ['Capture coupée, asymétrie, réponse non décodable ou absence effective de réponse.'],
                ['Vérifier la durée et le sens de capture avant de conclure à un délai ou à une panne.'],stream)
    # Priority is a transparent ordering rule, not a probability or trained ranking.
    findings.sort(key=lambda f:(f['priority']!='investigate', f['evidence_frames'][0],f['kind']))
    # Preserve diagnostic diversity: a large reset family must not hide DNS/HTTP findings.
    first_kind={}
    for finding in findings:first_kind.setdefault(finding['kind'],finding)
    selected=list(first_kind.values())
    selected_ids={f['id'] for f in selected}
    selected.extend(f for f in findings if f['id'] not in selected_ids)
    session_rows=[]
    for stream,packets in groups.items():
        session_rows.append({'tcp_stream':stream,'first_frame':packets[0]['frame_number'],**metrics(packets)})
    # Avoid repeated transaction reconstruction: only one bounded set enters stage aggregation.
    stage_samples=stage_metrics(rows,coverage)
    return {'version':VERSION,
        'capture_signature':digest([[r.get(k) for k in ('frame_number','timestamp','src_ip','dst_ip','src_port','dst_port','length')] for r in rows]),
        'state':'signals_observed' if findings else 'insufficient_evidence',
        'summary':{**metrics(rows),'observed_sessions':len(groups),'dns_error_responses':len(dns_errors),
                   'confirmed_packet_loss':None},
        'method':{'type':'explainable_rules_and_protocol_correlation','trained_model':False,
                  'ranking':'reset/window first, then frame order; no probability estimate'},
        'findings':selected[:LIMIT],'observed_findings':len(findings),'findings_truncated':len(findings)>LIMIT,
        'sessions':session_rows[:25],'coverage':coverage,'stage_metrics':stage_samples,
        'unknowns':['Le point de capture, l’horaire exact de l’incident et le comportement attendu doivent être confirmés.',
                    'La capture ne mesure pas à elle seule la charge CPU, les journaux serveur ou les décisions du pare-feu.',
                    'Pas de signal relevé ne signifie pas absence de problème ; les protocoles chiffrés peuvent masquer des échanges.'],
        'next_question':'Quel service et quelle plage horaire correspondent au symptôme à expliquer ?'}


def stage_metrics(rows,coverage):
    # Reconstruct at most 5000 decoded DNS/TCP rows for descriptive stage aggregation.
    transactions=TransactionService.from_rows(rows,coverage,limit=25,internal_limit=5000)
    samples=defaultdict(list)
    evidence_frames=defaultdict(list)
    counted=set()
    for item in transactions['data']:
        server=item.get('server') or {}
        host=(item.get('host') or server.get('ip') or '').lower().rstrip('.')
        service=f"{host}:{server.get('port')}"
        for stage,value in item['stages'].items():
            # A DNS stage copied as a candidate association is not another DNS measurement.
            if stage=='dns' and item['kind']!='dns':continue
            delay=value.get('duration_ms')
            if delay is None or not isfinite(delay) or value.get('state')=='error': continue
            if stage in ('tcp','tls'):
                key=(stage,service,item.get('tcp_stream'))
                if key in counted: continue
                counted.add(key)
            samples[(stage,service)].append(delay)
            for frame in value.get('evidence_frames',[]):
                if frame not in evidence_frames[(stage,service)] and len(evidence_frames[(stage,service)])<4:
                    evidence_frames[(stage,service)].append(frame)
    result=[]
    for (stage,service),values in sorted(samples.items()):
        result.append({'stage':stage,'service':service,'samples':len(values),
                       'evidence_frames':evidence_frames[(stage,service)],
                       'median_ms':round(median(values),3),'min_ms':round(min(values),3),'max_ms':round(max(values),3)})
    return {'data':result[:25],'input_packet_limit':5000,
            'truncated':len(result)>25 or transactions['next_after_frame'] is not None or transactions['aggregation_input_truncated']}


def compare_reports(current, reference):
    index={(r['stage'],r['service']):r for r in reference['stage_metrics']['data']}
    stages=[]
    for row in current['stage_metrics']['data']:
        ref=index.get((row['stage'],row['service']))
        if not ref: continue
        stages.append({'stage':row['stage'],'service':row['service'],
                       'current_samples':row['samples'],'reference_samples':ref['samples'],
                       'current_evidence_frames':row['evidence_frames'],'reference_evidence_frames':ref['evidence_frames'],
                       'current_median_ms':row['median_ms'],'reference_median_ms':ref['median_ms'],
                       'difference_ms':round(row['median_ms']-ref['median_ms'],3),
                       'ratio':round(row['median_ms']/ref['median_ms'],3) if ref['median_ms']>0 else None,
                       'sample_support':'limited' if min(row['samples'],ref['samples'])<5 else 'descriptive'})
    return {'state':'descriptive_comparison' if stages else 'not_comparable','stages':stages[:25],
            'coverage_complete':bool(current['coverage'].get('complete') and reference['coverage'].get('complete')),
            'stage_aggregation_truncated':bool(current['stage_metrics']['truncated'] or reference['stage_metrics']['truncated']),
            'limitations':['Même nom/adresse et port : service candidat seulement ; confirmer opération, point de capture et charge comparables.',
                           'La référence n’est pas automatiquement saine. Écarts descriptifs, sans attribution causale ni validation d’un correctif.',
                           'Un échantillon faible ou une capture partielle limite la comparaison. Aucun pourcentage n’est calculé sur une référence nulle.']}


class SupportDiagnosis:
    def __init__(self, engine=None):
        self.engine=engine or CaptureInvestigator()

    def report(self,path,reference_path=None):
        rows,coverage=self.engine.scan(path,'dns || tcp')
        result=build_report(rows,coverage)
        if reference_path is not None:
            rows,coverage=self.engine.scan(reference_path,'dns || tcp')
            result['reference_comparison']=compare_reports(result,build_report(rows,coverage))
        return result
