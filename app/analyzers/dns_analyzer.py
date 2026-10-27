"""
Analyseur DNS
Analyse les requêtes/réponses DNS, détecte les anomalies (tunneling, DGA, NXDOMAIN)
"""

import re
import math
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict, deque
from scapy.all import Packet, DNS, DNSQR, DNSRR, UDP, IP, IPv6
from .base import BaseAnalyzer
from app.core.logging_config import get_logger

logger = get_logger(__name__)


class DNSAnalyzer(BaseAnalyzer):
    """Analyseur de trafic DNS"""
    
    # Types de records DNS
    DNS_TYPES = {
        1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
        15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR',
        43: 'DS', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 65: 'HTTPS',
        99: 'SPF', 255: 'ANY', 256: 'URI', 257: 'CAA'
    }
    
    # Codes de réponse DNS
    RCODE_NAMES = {
        0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
        4: 'NOTIMP', 5: 'REFUSED', 6: 'YXDOMAIN', 7: 'YXRRSET',
        8: 'NXRRSET', 9: 'NOTAUTH', 10: 'NOTZONE'
    }
    
    # Domaines suspects pour tunneling/exfiltration
    SUSPICIOUS_TLD = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work']

    # Plafonds anti-explosion (mémoire et taille du results.json sur les grosses captures)
    MAX_ANOMALIES_PER_TYPE = 200   # Anomalies listées par type (les compteurs restent exacts)
    MAX_STORED_RECORDS = 10000     # Requêtes/réponses conservées en mémoire (les plus récentes)

    def __init__(self):
        super().__init__()
        # Deques plafonnées (on garde les plus récentes) — les compteurs *_count restent exacts
        self.queries: deque = deque(maxlen=self.MAX_STORED_RECORDS)
        self.responses: deque = deque(maxlen=self.MAX_STORED_RECORDS)
        self.query_count = 0
        self.response_count = 0
        self.domain_stats = defaultdict(lambda: {'count': 0, 'types': defaultdict(int)})
        self.dns_servers = defaultdict(lambda: {'queries': 0, 'responses': 0})
        self.query_types = defaultdict(int)
        self.response_codes = defaultdict(int)
        self.anomalies: List[Dict] = []
        # Compteurs exacts par type d'anomalie (la liste ci-dessus est plafonnée)
        self.anomaly_counts_by_type: Dict[str, int] = defaultdict(int)
        self._anomaly_overflow: Dict[str, str] = {}  # type -> sévérité pour le récapitulatif
        self.pending_queries: Dict[int, Dict] = {}  # Pour calculer les temps de réponse
        # Statistiques incrémentales des temps de réponse (exactes malgré le plafond)
        self._rt_count = 0
        self._rt_sum = 0.0
        self._rt_min: Optional[float] = None
        self._rt_max: Optional[float] = None

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """Analyse les paquets DNS"""
        logger.info("dns_analysis_started", packet_count=len(packets))
        
        for idx, pkt in enumerate(packets):
            if pkt.haslayer(DNS):
                self._analyze_dns_packet(pkt, idx)
        
        # Calculer les statistiques
        stats = self._compile_statistics()
        
        # Détecter les anomalies
        self._detect_anomalies()
        
        self.results = {
            'summary': stats['summary'],
            'queries': list(self.queries)[-100:],  # Limiter pour JSON
            'responses': list(self.responses)[-100:],
            'top_domains': stats['top_domains'],
            'dns_servers': stats['dns_servers'],
            'query_types': dict(self.query_types),
            'response_codes': dict(self.response_codes),
            'anomalies': self.anomalies,
            'response_times': stats['response_times']
        }
        
        logger.info("dns_analysis_completed",
                   queries=self.query_count,
                   responses=self.response_count,
                   anomalies=sum(self.anomaly_counts_by_type.values()))
        
        return self.results
    
    def _analyze_dns_packet(self, pkt: Packet, packet_idx: int):
        """Analyse un paquet DNS individuel"""
        dns = pkt[DNS]
        timestamp = self.get_packet_timestamp(pkt)
        
        # Récupérer les IPs
        src_ip, dst_ip = self.get_ip_pair(pkt)
        
        # Transaction ID
        txid = dns.id
        
        # QR flag: 0 = query, 1 = response
        is_query = dns.qr == 0
        
        if is_query:
            self._process_query(dns, pkt, packet_idx, timestamp, src_ip, dst_ip, txid)
        else:
            self._process_response(dns, pkt, packet_idx, timestamp, src_ip, dst_ip, txid)
    
    def _process_query(self, dns: DNS, pkt: Packet, idx: int, ts: float,
                       src_ip: str, dst_ip: str, txid: int):
        """Traite une requête DNS"""
        if not dns.qdcount or not dns.qd:
            return
            
        qname = dns.qd.qname.decode() if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
        qname = qname.rstrip('.')
        qtype = dns.qd.qtype
        qtype_name = self.DNS_TYPES.get(qtype, f'TYPE{qtype}')
        
        query_info = {
            'packet_idx': idx,
            'timestamp': ts,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'txid': txid,
            'domain': qname,
            'type': qtype_name,
            'type_code': qtype
        }
        
        self.queries.append(query_info)
        self.query_count += 1  # Compteur exact (la deque est plafonnée)

        # Statistiques
        self.domain_stats[qname]['count'] += 1
        self.domain_stats[qname]['types'][qtype_name] += 1
        self.query_types[qtype_name] += 1
        self.dns_servers[dst_ip]['queries'] += 1
        
        # Stocker pour calculer le temps de réponse
        self.pending_queries[txid] = {
            'timestamp': ts,
            'domain': qname,
            'src_ip': src_ip
        }
    
    def _process_response(self, dns: DNS, pkt: Packet, idx: int, ts: float,
                          src_ip: str, dst_ip: str, txid: int):
        """Traite une réponse DNS"""
        rcode = dns.rcode
        rcode_name = self.RCODE_NAMES.get(rcode, f'RCODE{rcode}')
        
        response_info = {
            'packet_idx': idx,
            'timestamp': ts,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'txid': txid,
            'rcode': rcode_name,
            'rcode_num': rcode,
            'answers': [],
            'response_time_ms': None
        }
        
        # Calculer le temps de réponse
        if txid in self.pending_queries:
            query = self.pending_queries[txid]
            response_time = round((ts - query['timestamp']) * 1000, 2)  # en ms
            response_info['response_time_ms'] = response_time
            response_info['queried_domain'] = query['domain']
            del self.pending_queries[txid]
            # Statistiques incrémentales (exactes malgré le plafond de stockage)
            self._rt_count += 1
            self._rt_sum += response_time
            if self._rt_min is None or response_time < self._rt_min:
                self._rt_min = response_time
            if self._rt_max is None or response_time > self._rt_max:
                self._rt_max = response_time
        
        # Extraire les réponses
        if dns.ancount and dns.an:
            for i in range(dns.ancount):
                try:
                    rr = dns.an[i] if hasattr(dns.an, '__getitem__') else dns.an
                    answer = self._extract_answer(rr)
                    if answer:
                        response_info['answers'].append(answer)
                except:
                    break
        
        self.responses.append(response_info)
        self.response_count += 1  # Compteur exact (la deque est plafonnée)

        # Statistiques
        self.response_codes[rcode_name] += 1
        self.dns_servers[src_ip]['responses'] += 1
    
    def _extract_answer(self, rr) -> Optional[Dict]:
        """Extrait les informations d'une réponse DNS"""
        try:
            rrname = rr.rrname.decode() if isinstance(rr.rrname, bytes) else str(rr.rrname)
            rrtype = self.DNS_TYPES.get(rr.type, f'TYPE{rr.type}')
            
            rdata = None
            if hasattr(rr, 'rdata'):
                if isinstance(rr.rdata, bytes):
                    try:
                        rdata = rr.rdata.decode('utf-8', errors='ignore')
                    except:
                        rdata = rr.rdata.hex()
                else:
                    rdata = str(rr.rdata)
            
            return {
                'name': rrname.rstrip('.'),
                'type': rrtype,
                'ttl': rr.ttl if hasattr(rr, 'ttl') else None,
                'data': rdata
            }
        except Exception as e:
            return None
    
    def _compile_statistics(self) -> Dict:
        """Compile les statistiques DNS"""
        # Top domaines
        sorted_domains = sorted(
            self.domain_stats.items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )[:50]
        
        top_domains = [
            {
                'domain': domain,
                'count': stats['count'],
                'types': dict(stats['types'])
            }
            for domain, stats in sorted_domains
        ]
        
        # Serveurs DNS
        sorted_servers = sorted(
            self.dns_servers.items(),
            key=lambda x: x[1]['queries'] + x[1]['responses'],
            reverse=True
        )[:20]
        
        dns_servers = [
            {'ip': ip, **stats}
            for ip, stats in sorted_servers
        ]
        
        # Temps de réponse (statistiques incrémentales, exactes malgré le plafond de stockage)
        avg_response_time = (self._rt_sum / self._rt_count) if self._rt_count else 0
        max_response_time = self._rt_max if self._rt_max is not None else 0
        min_response_time = self._rt_min if self._rt_min is not None else 0

        # NXDOMAIN rate
        total_responses = self.response_count
        nxdomain_count = self.response_codes.get('NXDOMAIN', 0)
        nxdomain_rate = (nxdomain_count / total_responses * 100) if total_responses > 0 else 0

        summary = {
            'total_queries': self.query_count,
            'total_responses': self.response_count,
            'unique_domains': len(self.domain_stats),
            'unique_dns_servers': len(self.dns_servers),
            'avg_response_time_ms': round(avg_response_time, 2),
            'max_response_time_ms': round(max_response_time, 2),
            'min_response_time_ms': round(min_response_time, 2),
            'nxdomain_count': nxdomain_count,
            'nxdomain_rate': round(nxdomain_rate, 2)
        }
        
        return {
            'summary': summary,
            'top_domains': top_domains,
            'dns_servers': dns_servers,
            'response_times': {
                'avg': avg_response_time,
                'max': max_response_time,
                'min': min_response_time,
                'count': self._rt_count
            }
        }
    
    def _add_anomaly(self, anomaly: Dict):
        """Ajoute une anomalie en plafonnant la liste par type.
        Les compteurs restent exacts: seules les premières occurrences sont listées."""
        atype = anomaly.get('type', 'UNKNOWN')
        self.anomaly_counts_by_type[atype] += 1
        if self.anomaly_counts_by_type[atype] <= self.MAX_ANOMALIES_PER_TYPE:
            self.anomalies.append(anomaly)
        elif atype not in self._anomaly_overflow:
            # Mémorise la sévérité du type pour l'anomalie récapitulative
            self._anomaly_overflow[atype] = anomaly.get('severity', 'INFO')

    def _append_overflow_summaries(self):
        """Ajoute UNE anomalie récapitulative par type dont la liste a été plafonnée"""
        for atype, severity in self._anomaly_overflow.items():
            total = self.anomaly_counts_by_type[atype]
            hidden = total - self.MAX_ANOMALIES_PER_TYPE
            self.anomalies.append({
                'type': atype,
                'severity': severity,
                'description': f"{hidden} occurrences supplémentaires du même type non listées",
                'details': {
                    'total_occurrences': total,
                    'occurrences_listees': self.MAX_ANOMALIES_PER_TYPE,
                    'occurrences_non_listees': hidden,
                    'resume': True
                },
                'recommendation': 'Liste plafonnée pour limiter la taille du rapport'
            })

    def _detect_anomalies(self):
        """Détecte les anomalies DNS"""
        # 1. Taux de NXDOMAIN élevé (possible DGA)
        total_responses = self.response_count
        if total_responses > 10:
            nxdomain_count = self.response_codes.get('NXDOMAIN', 0)
            nxdomain_rate = nxdomain_count / total_responses
            if nxdomain_rate > 0.3:  # Plus de 30%
                self._add_anomaly({
                    'type': 'HIGH_NXDOMAIN_RATE',
                    'severity': 'HIGH' if nxdomain_rate > 0.5 else 'MEDIUM',
                    'description': f'Taux NXDOMAIN élevé: {nxdomain_rate*100:.1f}% ({nxdomain_count}/{total_responses})',
                    'details': {'rate': nxdomain_rate, 'count': nxdomain_count},
                    'recommendation': 'Possible Domain Generation Algorithm (DGA) - Vérifier les domaines interrogés'
                })
        
        # 2. Détection de DNS Tunneling
        for domain, stats in self.domain_stats.items():
            # Sous-domaines très longs (tunneling)
            parts = domain.split('.')
            if len(parts) > 2:
                subdomain = '.'.join(parts[:-2])
                if len(subdomain) > 50:
                    self._add_anomaly({
                        'type': 'DNS_TUNNELING_SUSPECT',
                        'severity': 'HIGH',
                        'description': f'Sous-domaine anormalement long détecté',
                        'details': {'domain': domain, 'subdomain_length': len(subdomain)},
                        'recommendation': 'Possible DNS tunneling - Analyser le contenu des requêtes'
                    })
                    break
            
            # Entropie élevée (encodage base64/hex)
            entropy = self._calculate_entropy(domain.split('.')[0])
            if entropy > 4.0 and len(domain.split('.')[0]) > 15:
                self._add_anomaly({
                    'type': 'HIGH_ENTROPY_DOMAIN',
                    'severity': 'MEDIUM',
                    'description': f'Domaine avec entropie élevée: {domain}',
                    'details': {'domain': domain, 'entropy': entropy},
                    'recommendation': 'Possible DNS tunneling ou DGA'
                })
        
        # 3. Requêtes TXT suspectes (souvent utilisées pour tunneling)
        txt_count = self.query_types.get('TXT', 0)
        total_queries = self.query_count
        if total_queries > 20 and txt_count > 10:
            txt_ratio = txt_count / total_queries
            if txt_ratio > 0.2:
                self._add_anomaly({
                    'type': 'HIGH_TXT_QUERIES',
                    'severity': 'MEDIUM',
                    'description': f'Volume élevé de requêtes TXT: {txt_count} ({txt_ratio*100:.1f}%)',
                    'details': {'count': txt_count, 'ratio': txt_ratio},
                    'recommendation': 'Les requêtes TXT peuvent être utilisées pour l\'exfiltration de données'
                })
        
        # 4. Domaines suspects (TLDs gratuits souvent utilisés pour malware)
        for domain, stats in self.domain_stats.items():
            for tld in self.SUSPICIOUS_TLD:
                if domain.endswith(tld) and stats['count'] > 5:
                    self._add_anomaly({
                        'type': 'SUSPICIOUS_TLD',
                        'severity': 'LOW',
                        'description': f'Domaine avec TLD suspect: {domain}',
                        'details': {'domain': domain, 'tld': tld, 'count': stats['count']},
                        'recommendation': 'TLD souvent associé à des activités malveillantes'
                    })
                    break
        
        # 5. Requêtes vers des serveurs DNS non standard
        standard_dns_ports = [53, 853, 5353]
        for query in list(self.queries)[:100]:  # Échantillon
            # Vérifier si c'est un serveur DNS connu (Google, Cloudflare, etc.)
            known_dns = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9']
            dst = query.get('dst_ip')
            if dst and dst not in known_dns and not dst.startswith(('192.168.', '10.', '172.16.')):
                # Compter les serveurs DNS non standard
                pass

        # Anomalies récapitulatives pour les types dont la liste a été plafonnée
        self._append_overflow_summaries()
    
    def _calculate_entropy(self, s: str) -> float:
        """Calcule l'entropie de Shannon d'une chaîne"""
        if not s:
            return 0.0
        
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob if p > 0)
    
    def reset(self):
        """Réinitialise l'analyseur"""
        super().reset()
        self.queries = deque(maxlen=self.MAX_STORED_RECORDS)
        self.responses = deque(maxlen=self.MAX_STORED_RECORDS)
        self.query_count = 0
        self.response_count = 0
        self.domain_stats = defaultdict(lambda: {'count': 0, 'types': defaultdict(int)})
        self.dns_servers = defaultdict(lambda: {'queries': 0, 'responses': 0})
        self.query_types = defaultdict(int)
        self.response_codes = defaultdict(int)
        self.anomalies = []
        self.anomaly_counts_by_type = defaultdict(int)
        self._anomaly_overflow = {}
        self.pending_queries = {}
        self._rt_count = 0
        self._rt_sum = 0.0
        self._rt_min = None
        self._rt_max = None
