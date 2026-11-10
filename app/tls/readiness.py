"""Bounded ServerHello metadata; eligibility is never proof that a secret matches."""
import csv
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

# Conservative allowlists: unknown suites remain unknown, never guessed RSA.
RSA_SUITES={0x0004,0x0005,0x000a,0x002f,0x0035,0x003c,0x003d,0x009c,0x009d}
EPHEMERAL_SUITES={0x0033,0x0039,0x0067,0x006b,0x009e,0x009f,
                  0xc009,0xc00a,0xc013,0xc014,0xc023,0xc024,0xc027,0xc028,
                  0xc02b,0xc02c,0xc02f,0xc030,0xcca8,0xcca9,0xccaa}
FIELDS=['frame.number','tcp.stream','tls.handshake.version',
        'tls.handshake.extensions.supported_version','tls.handshake.ciphersuite']


def number(value):
    try:return int(value,16) if value.startswith('0x') else int(value)
    except (ValueError,TypeError,AttributeError):return None


def summarize(rows,kind,truncated=False):
    if kind not in ('rsa','keylog'):raise ValueError('Type TLS invalide')
    sessions={}
    for values in rows:
        if len(values)!=5:continue
        frame,stream,legacy,selected,suite=map(number,values)
        if frame is None or stream is None or stream in sessions:continue
        version=selected or legacy
        # TLS 1.3's selected suite is additional evidence even if the extension
        # field is absent in the installed dissector.
        tls13=version==0x0304 or (suite is not None and 0x1301<=suite<=0x1305)
        mode='keylog_required' if tls13 or suite in EPHEMERAL_SUITES else 'rsa_candidate' if suite in RSA_SUITES and version in (0x0300,0x0301,0x0302,0x0303) else 'unknown'
        sessions[stream]={'frame_number':frame,'stream_id':stream,
            'version':'TLS 1.3' if tls13 else {0x0303:'TLS 1.2',0x0302:'TLS 1.1',0x0301:'TLS 1.0',0x0300:'SSL 3.0'}.get(version,'Inconnue'),
            'cipher_suite':f'0x{suite:04x}' if suite is not None else None,'mode':mode}
        if len(sessions)>=100:truncated=True;break
    counts={mode:sum(s['mode']==mode for s in sessions.values()) for mode in ('rsa_candidate','keylog_required','unknown')}
    state='keylog_candidate' if kind=='keylog' and sessions else 'rsa_candidate' if counts['rsa_candidate'] else 'keylog_recommended' if counts['keylog_required'] else 'unknown'
    messages={
        'keylog_candidate':'Secrets de session utilisables si les sessions correspondantes figurent dans le keylog ; leur correspondance reste à vérifier.',
        'rsa_candidate':'Échange RSA observé : déchiffrement envisageable ; la correspondance de la clé et la complétude de la capture restent à vérifier.',
        'keylog_recommended':'TLS 1.3 ou échange éphémère observé : utilisez un SSLKEYLOGFILE pour ces sessions. La clé privée serveur seule ne suffit pas.',
        'unknown':'Compatibilité indéterminée : ServerHello absent ou suite non classée. Une capture partielle peut masquer la négociation.'}
    return {'state':state,'message':messages[state],'kind':kind,'observed_sessions':len(sessions),
            'rsa_candidates':counts['rsa_candidate'],'keylog_required':counts['keylog_required'],'unknown':counts['unknown'],
            'sessions':list(sessions.values())[:25],
            'coverage':{'scope':'ServerHello observés uniquement ; les autres sessions restent indéterminées.',
                        'truncated':truncated,'display_limit':25},
            'limitations':['Ce contrôle ne lit aucun secret et ne prouve pas que la clé correspond.',
                           'Le déchiffrement nécessite les échanges complets et les secrets de session appropriés.']}


def inspect_capture(path,kind,tshark=None):
    binary=tshark or os.getenv('TSHARK_PATH') or shutil.which('tshark')
    if not binary:raise ValueError('Vérification TLS indisponible : TShark absent.')
    args=[binary,'-n','-r',str(Path(path).resolve()),'-c','100000','-Y','tls.handshake.type == 2',
          '-T','fields','-E','separator=/t','-E','quote=d','-E','occurrence=f']
    for field in FIELDS:args.extend(['-e',field])
    with tempfile.TemporaryFile() as output:
        try:
            result=subprocess.run(args,stdout=output,stderr=subprocess.DEVNULL,timeout=20,check=False)
        except (OSError,subprocess.TimeoutExpired):raise ValueError('Vérification TLS interrompue ; la compatibilité reste indéterminée.') from None
        if result.returncode:raise ValueError('Vérification TLS indisponible pour cette capture.')
        output.seek(0)
        body=output.read(2*1024*1024+1)
    truncated=len(body)>2*1024*1024
    # The input packet cap means coverage is always bounded, not exhaustive.
    report=summarize(csv.reader(body[:2*1024*1024].decode('utf-8','replace').splitlines(),delimiter='\t'),kind,truncated)
    report['coverage']['packet_scan_limit']=100000
    return report
