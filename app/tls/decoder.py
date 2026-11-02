"""Bounded TShark metadata extraction; never export decrypted bodies or credentials."""
import csv
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys
from urllib.parse import urlsplit,unquote

FIELDS=['frame.number','tcp.stream','ip.src','ipv6.src','ip.dst','ipv6.dst',
        'http.request.method','http.host','http.request.uri','http.response.code',
        'http2.headers.method','http2.headers.authority','http2.headers.path','http2.headers.status',
        'tls.app_data_proto','frame.len','http2.streamid','frame.protocols']
LIMITATIONS=['Métadonnées uniquement : corps, cookies et authentification exclus.',
 'Une occurrence par champ et par trame : les trames HTTP/2 multiplexées peuvent contenir d’autres échanges.',
 'Couverture limitée aux échanges présents, complets et reconnus par TShark ; un résultat vide ne prouve pas une absence de trafic.']

def safe_path(value):
    try:path=urlsplit(value).path
    except ValueError:return '[chemin invalide]'
    parts=[];mask_next=False
    for part in path[:2048].split('/'):
        decoded=unquote(part)
        sensitive=mask_next or len(decoded)>32 or bool(re.search(r'(?i)(token|password|secret|bearer|eyJ)',decoded))
        parts.append('[masqué]' if sensitive else re.sub(r'[\x00-\x1f\x7f]','',part))
        mask_next=decoded.lower() in ('reset','token','password','secret','auth','session')
    return '/'.join(parts)[:512]

def _limits():
    resource.setrlimit(resource.RLIMIT_CPU,(180,180))
    resource.setrlimit(resource.RLIMIT_FSIZE,(32*1024*1024,32*1024*1024))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if sys.platform=='linux':resource.setrlimit(resource.RLIMIT_AS,(1024*1024*1024,1024*1024*1024))

def decode(pcap,kind,secret,root,tshark=None):
    binary=tshark or shutil.which('tshark')
    if not binary:raise ValueError('Moteur de déchiffrement indisponible.')
    root=Path(root);root.mkdir(parents=True,exist_ok=True);root.chmod(0o700)
    secret_path=root/'secret-material';output=root/'metadata.tsv'
    fd=os.open(secret_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(secret)
    preference=f'tls.keylog_file:{secret_path}' if kind=='keylog' else f'uat:rsa_keys:"{secret_path}",""'
    args=[str(binary),'-n','-2','-r',str(Path(pcap).resolve()),'-o',preference,
          '-o','tcp.desegment_tcp_streams:TRUE','-o','tls.desegment_ssl_records:TRUE',
          '-o','tls.desegment_ssl_application_data:TRUE','-Y','tls.app_data_proto',
          '-T','fields','-E','separator=/t','-E','quote=d','-E','occurrence=f']
    for field in FIELDS:args.extend(['-e',field])
    try:
        with output.open('wb') as target:
            process=subprocess.run(args,stdout=target,stderr=subprocess.DEVNULL,timeout=200,check=False,
                env={'PATH':os.defpath,'HOME':str(root),'XDG_CONFIG_HOME':str(root),'LC_ALL':'C'},preexec_fn=_limits)
        if process.returncode!=0:raise ValueError('Capture non traitable ou limites du moteur atteintes.')
        rows=[];packets=0;streams=set();protocols={};truncated=False
        with output.open(encoding='utf-8',errors='replace',newline='') as source:
            for values in csv.reader(source,delimiter='\t'):
                if len(values)!=len(FIELDS):continue
                d=dict(zip(FIELDS,values))
                # ALPN alone can set app_data_proto even when the secret is wrong.
                # Count only application protocols actually dissected after TLS.
                chain=d['frame.protocols'].split(':')
                after_tls=chain[len(chain)-chain[::-1].index('tls'):] if 'tls' in chain else []
                if not set(after_tls)&{'http','http2','smtp','imap','pop','ftp','ldap','smb','smb2','dns','mqtt'}:continue
                packets+=1
                stream=d['tcp.stream'];streams.add(stream)
                proto=d['tls.app_data_proto'][:100];protocols[proto]=protocols.get(proto,0)+1
                method=d['http.request.method'] or d['http2.headers.method']
                status=d['http.response.code'] or d['http2.headers.status']
                if not (method or status):continue
                if len(rows)>=10000:truncated=True;continue
                host=d['http.host'] or d['http2.headers.authority']
                host=re.sub(r'[^A-Za-z0-9.\-:\[\]]','',host.split('@')[-1])[:255]
                rows.append({'packet_index':max(0,int(d['frame.number'])-1),'frame_number':int(d['frame.number']),
                    'stream_id':int(stream) if stream.isdecimal() else None,
                    'http2_stream_id':int(d['http2.streamid']) if d['http2.streamid'].isdecimal() else None,
                    'protocol':'HTTP/2' if d['http2.headers.method'] or d['http2.headers.status'] else 'HTTP/1',
                    'source':d['ip.src'] or d['ipv6.src'],'destination':d['ip.dst'] or d['ipv6.dst'],
                    'method':method if re.fullmatch(r'[A-Z][A-Z0-9_-]{0,23}',method) else '',
                    'host':host,'path':safe_path(d['http.request.uri'] or d['http2.headers.path']),
                    'status':int(status) if status.isdecimal() else None,'frame_bytes':int(d['frame.len'] or 0)})
        return {'state':'decoded' if packets else 'no_match','decrypted_packets':packets,'stream_count':len(streams),
                'protocols':protocols,'rows':rows,'limitations':LIMITATIONS+(['Rapport limité à 10 000 échanges.'] if truncated else []),
                'message':'Échanges applicatifs décodés sous TLS.' if packets else 'Aucun échange déchiffré : secrets sans correspondance, capture incomplète ou chiffrement incompatible.'}
    except (subprocess.TimeoutExpired,OSError,csv.Error,ValueError):
        raise ValueError('Déchiffrement impossible : capture invalide, moteur indisponible ou limite atteinte.') from None
    finally:
        secret_path.unlink(missing_ok=True);output.unlink(missing_ok=True)
