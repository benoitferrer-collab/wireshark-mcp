"""
Analyseur HTTP/HTTPS
Analyse les requêtes/réponses HTTP, extrait SNI/TLS pour HTTPS
Détecte les anomalies (scans, injections, user-agents suspects)
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict, deque
from scapy.all import Packet, TCP, IP, IPv6, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse, HTTP

# Try to import TLS layers, fall back gracefully if not available
try:
    from scapy.layers.tls.handshake import TLSClientHello
    from scapy.layers.tls.extensions import TLS_Ext_ServerName, ServerName
    from scapy.layers.tls.record import TLS
    HAS_TLS_SUPPORT = True
except ImportError:
    HAS_TLS_SUPPORT = False
    TLSClientHello = None
    TLS_Ext_ServerName = None
    ServerName = None
    TLS = None

from .base import BaseAnalyzer
from app.core.logging_config import get_logger

logger = get_logger(__name__)


class HTTPAnalyzer(BaseAnalyzer):
    """Analyseur de trafic HTTP et HTTPS"""
    
    # User-Agents suspects (malware, scanners, bots malveillants)
    SUSPICIOUS_USER_AGENTS = [
        'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'gobuster',
        'dirbuster', 'wfuzz', 'burpsuite', 'hydra', 'curl/', 'wget/',
        'python-requests', 'python-urllib', 'go-http-client', 'libwww-perl',
        'scanner', 'bot', 'crawl', 'spider', 'scraper'
    ]
    
    # Patterns d'injection SQL/XSS (compilés une seule fois)
    INJECTION_PATTERNS = [
        r'(?:union\s+select|select\s+.*\s+from)',
        r'(?:or\s+1\s*=\s*1|and\s+1\s*=\s*1)',
        r'(?:<script|javascript:|onerror=|onload=)',
        r'(?:\.\.\/|\.\.\\)',
        r'(?:\/etc\/passwd|\/proc\/self)',
        r'(?:cmd=|exec=|system\()',
        r'(?:%27|%22|%3C|%3E|%00)'
    ]
    INJECTION_PATTERNS_COMPILED = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]

    # Méthodes HTTP reconnues (lookup O(1) dans le hot path)
    HTTP_METHOD_SET = frozenset({'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT'})
    
    # TLS versions
    TLS_VERSIONS = {
        0x0301: 'TLS 1.0',
        0x0302: 'TLS 1.1',
        0x0303: 'TLS 1.2',
        0x0304: 'TLS 1.3'
    }

    # Plafonds anti-explosion (mémoire et taille du results.json sur les grosses captures)
    MAX_ANOMALIES_PER_TYPE = 200   # Anomalies listées par type (les compteurs restent exacts)
    MAX_STORED_RECORDS = 10000     # Requêtes/réponses/sessions TLS conservées (les plus récentes)

    def __init__(self):
        super().__init__()
        # Deques plafonnées (on garde les plus récentes) — les compteurs *_count restent exacts
        self.http_requests: deque = deque(maxlen=self.MAX_STORED_RECORDS)
        self.http_responses: deque = deque(maxlen=self.MAX_STORED_RECORDS)
        self.tls_sessions: deque = deque(maxlen=self.MAX_STORED_RECORDS)
        self.request_count = 0
        self.response_count = 0
        self.tls_session_count = 0

        # Statistiques
        self.methods = defaultdict(int)
        self.status_codes = defaultdict(int)
        self.user_agents = defaultdict(int)
        self.hosts = defaultdict(int)
        self.content_types = defaultdict(int)
        self.urls = defaultdict(int)

        # TLS stats
        self.tls_versions = defaultdict(int)
        self.cipher_suites = defaultdict(int)
        self.sni_hosts = defaultdict(int)

        self.anomalies: List[Dict] = []
        # Compteurs exacts par type d'anomalie (la liste ci-dessus est plafonnée)
        self.anomaly_counts_by_type: Dict[str, int] = defaultdict(int)
        self._anomaly_overflow: Dict[str, str] = {}  # type -> sévérité pour le récapitulatif

    def reset(self):
        """Réinitialise l'analyseur"""
        super().reset()
        self.http_requests = deque(maxlen=self.MAX_STORED_RECORDS)
        self.http_responses = deque(maxlen=self.MAX_STORED_RECORDS)
        self.tls_sessions = deque(maxlen=self.MAX_STORED_RECORDS)
        self.request_count = 0
        self.response_count = 0
        self.tls_session_count = 0
        self.methods = defaultdict(int)
        self.status_codes = defaultdict(int)
        self.user_agents = defaultdict(int)
        self.hosts = defaultdict(int)
        self.content_types = defaultdict(int)
        self.urls = defaultdict(int)
        self.tls_versions = defaultdict(int)
        self.cipher_suites = defaultdict(int)
        self.sni_hosts = defaultdict(int)
        self.anomalies = []
        self.anomaly_counts_by_type = defaultdict(int)
        self._anomaly_overflow = {}

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

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """Analyse les paquets HTTP/HTTPS"""
        logger.info("http_analysis_started", packet_count=len(packets))
        
        for idx, pkt in enumerate(packets):
            # Analyser HTTP
            if pkt.haslayer(HTTP) or pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse):
                self._analyze_http_packet(pkt, idx)
            
            # Analyser le trafic TCP port 80/8080 même sans couche HTTP explicite
            elif pkt.haslayer(TCP) and pkt.haslayer(Raw):
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                if dport in [80, 8080, 8000, 3000] or sport in [80, 8080, 8000, 3000]:
                    self._analyze_raw_http(pkt, idx)
            
            # Analyser TLS/HTTPS (test TCP/port en premier: bien moins coûteux
            # que la résolution de couche TLS sur chaque paquet)
            if HAS_TLS_SUPPORT and TLS is not None:
                if (pkt.haslayer(TCP) and pkt[TCP].dport == 443) or pkt.haslayer(TLS):
                    self._analyze_tls_packet(pkt, idx)
            elif pkt.haslayer(TCP) and pkt[TCP].dport == 443:
                # Basic HTTPS tracking without TLS parsing
                self._track_https_connection(pkt, idx)
        
        # Détecter les anomalies
        self._detect_anomalies()
        
        # Compiler les résultats
        self.results = {
            'summary': self._compile_summary(),
            'requests': list(self.http_requests)[-100:],
            'responses': list(self.http_responses)[-100:],
            'tls_sessions': list(self.tls_sessions)[-50:],
            'methods': dict(self.methods),
            'status_codes': self._format_status_codes(),
            'user_agents': self._get_top_items(self.user_agents, 20),
            'hosts': self._get_top_items(self.hosts, 20),
            'content_types': dict(self.content_types),
            'top_urls': self._get_top_items(self.urls, 30),
            'tls': {
                'versions': dict(self.tls_versions),
                'cipher_suites': self._get_top_items(self.cipher_suites, 10),
                'sni_hosts': self._get_top_items(self.sni_hosts, 20)
            },
            'anomalies': self.anomalies
        }
        
        logger.info("http_analysis_completed",
                   requests=self.request_count,
                   responses=self.response_count,
                   tls_sessions=self.tls_session_count,
                   anomalies=sum(self.anomaly_counts_by_type.values()))
        
        return self.results
    
    def _analyze_http_packet(self, pkt: Packet, packet_idx: int):
        """Analyse un paquet HTTP"""
        timestamp = self.get_packet_timestamp(pkt)
        src_ip, dst_ip = self.get_ip_pair(pkt)
        src_port, dst_port = self.get_port_pair(pkt)
        
        if pkt.haslayer(HTTPRequest):
            self._process_http_request(pkt, packet_idx, timestamp, src_ip, dst_ip, src_port, dst_port)
        
        if pkt.haslayer(HTTPResponse):
            self._process_http_response(pkt, packet_idx, timestamp, src_ip, dst_ip, src_port, dst_port)
    
    def _process_http_request(self, pkt: Packet, idx: int, ts: float,
                              src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        """Traite une requête HTTP"""
        try:
            http = pkt[HTTPRequest]
            
            method = http.Method.decode() if hasattr(http.Method, 'decode') else str(http.Method)
            path = http.Path.decode() if hasattr(http.Path, 'decode') else str(http.Path)
            host = http.Host.decode() if http.Host and hasattr(http.Host, 'decode') else str(http.Host or dst_ip)
            
            # Headers
            user_agent = ''
            referer = ''
            content_type = ''
            
            if hasattr(http, 'User_Agent') and http.User_Agent:
                user_agent = http.User_Agent.decode() if hasattr(http.User_Agent, 'decode') else str(http.User_Agent)
            
            if hasattr(http, 'Referer') and http.Referer:
                referer = http.Referer.decode() if hasattr(http.Referer, 'decode') else str(http.Referer)
            
            if hasattr(http, 'Content_Type') and http.Content_Type:
                content_type = http.Content_Type.decode() if hasattr(http.Content_Type, 'decode') else str(http.Content_Type)
            
            request_info = {
                'packet_idx': idx,
                'timestamp': ts,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'method': method,
                'host': host,
                'path': path,
                'url': f"http://{host}{path}",
                'user_agent': user_agent,
                'referer': referer,
                'content_type': content_type
            }
            
            self.http_requests.append(request_info)
            self.request_count += 1  # Compteur exact (la deque est plafonnée)
            # Détection d'injection au fil de l'eau (couvre toutes les requêtes)
            self._check_injection(request_info)

            # Statistiques
            self.methods[method] += 1
            self.hosts[host] += 1
            if user_agent:
                self.user_agents[user_agent] += 1
            self.urls[path[:100]] += 1  # Limiter la longueur

        except Exception as e:
            logger.debug(f"Error processing HTTP request: {e}")
    
    def _process_http_response(self, pkt: Packet, idx: int, ts: float,
                               src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        """Traite une réponse HTTP"""
        try:
            http = pkt[HTTPResponse]
            
            status_code = int(http.Status_Code) if hasattr(http, 'Status_Code') else 0
            reason = http.Reason_Phrase.decode() if hasattr(http.Reason_Phrase, 'decode') else str(http.Reason_Phrase or '')
            
            content_type = ''
            content_length = 0
            server = ''
            
            if hasattr(http, 'Content_Type') and http.Content_Type:
                content_type = http.Content_Type.decode() if hasattr(http.Content_Type, 'decode') else str(http.Content_Type)
            
            if hasattr(http, 'Content_Length') and http.Content_Length:
                try:
                    content_length = int(http.Content_Length)
                except:
                    pass
            
            if hasattr(http, 'Server') and http.Server:
                server = http.Server.decode() if hasattr(http.Server, 'decode') else str(http.Server)
            
            response_info = {
                'packet_idx': idx,
                'timestamp': ts,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'status_code': status_code,
                'reason': reason,
                'content_type': content_type,
                'content_length': content_length,
                'server': server
            }
            
            self.http_responses.append(response_info)
            self.response_count += 1  # Compteur exact (la deque est plafonnée)

            # Statistiques
            self.status_codes[str(status_code)] += 1
            if content_type:
                self.content_types[content_type.split(';')[0].strip()] += 1
                
        except Exception as e:
            logger.debug(f"Error processing HTTP response: {e}")
    
    def _analyze_raw_http(self, pkt: Packet, packet_idx: int):
        """Analyse le payload brut pour détecter HTTP"""
        try:
            payload = bytes(pkt[Raw].load)
            
            # Essayer de décoder
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
            except:
                return
            
            timestamp = self.get_packet_timestamp(pkt)
            src_ip, dst_ip = self.get_ip_pair(pkt)
            src_port, dst_port = self.get_port_pair(pkt)

            # Détecter une requête HTTP (test du premier mot, sans allocations en boucle)
            method = payload_str.split(' ', 1)[0]
            if method in self.HTTP_METHOD_SET:
                    lines = payload_str.split('\r\n')
                    if lines:
                        first_line = lines[0]
                        parts = first_line.split(' ')
                        if len(parts) >= 2:
                            path = parts[1]
                            
                            # Extraire le Host
                            host = dst_ip
                            user_agent = ''
                            for line in lines[1:]:
                                if line.lower().startswith('host:'):
                                    host = line[5:].strip()
                                elif line.lower().startswith('user-agent:'):
                                    user_agent = line[11:].strip()
                            
                            request_info = {
                                'packet_idx': packet_idx,
                                'timestamp': timestamp,
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'src_port': src_port,
                                'dst_port': dst_port,
                                'method': method,
                                'host': host,
                                'path': path,
                                'url': f"http://{host}{path}",
                                'user_agent': user_agent,
                                'referer': '',
                                'content_type': ''
                            }
                            
                            self.http_requests.append(request_info)
                            self.request_count += 1  # Compteur exact (la deque est plafonnée)
                            # Détection d'injection au fil de l'eau
                            self._check_injection(request_info)
                            self.methods[method] += 1
                            self.hosts[host] += 1
                            if user_agent:
                                self.user_agents[user_agent] += 1
                            self.urls[path[:100]] += 1
                    return
            
            # Détecter une réponse HTTP
            if payload_str.startswith('HTTP/'):
                lines = payload_str.split('\r\n')
                if lines:
                    parts = lines[0].split(' ', 2)
                    if len(parts) >= 2:
                        try:
                            status_code = int(parts[1])
                            reason = parts[2] if len(parts) > 2 else ''
                            
                            response_info = {
                                'packet_idx': packet_idx,
                                'timestamp': timestamp,
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'status_code': status_code,
                                'reason': reason,
                                'content_type': '',
                                'content_length': 0,
                                'server': ''
                            }
                            
                            self.http_responses.append(response_info)
                            self.response_count += 1  # Compteur exact (la deque est plafonnée)
                            self.status_codes[str(status_code)] += 1
                        except:
                            pass
                            
        except Exception as e:
            pass
    
    def _track_https_connection(self, pkt: Packet, packet_idx: int):
        """Basic HTTPS tracking when TLS parsing is not available"""
        try:
            timestamp = self.get_packet_timestamp(pkt)
            src_ip, dst_ip = self.get_ip_pair(pkt)
            src_port, dst_port = self.get_port_pair(pkt)
            
            # Try to extract SNI from raw payload
            if pkt.haslayer(Raw):
                self._extract_sni_from_raw(pkt, packet_idx, timestamp, src_ip, dst_ip, src_port, dst_port)
        except Exception as e:
            logger.debug(f"Error tracking HTTPS connection: {e}")
    
    def _analyze_tls_packet(self, pkt: Packet, packet_idx: int):
        """Analyse un paquet TLS pour extraire SNI et informations"""
        if not HAS_TLS_SUPPORT:
            return
        
        try:
            timestamp = self.get_packet_timestamp(pkt)
            src_ip, dst_ip = self.get_ip_pair(pkt)
            src_port, dst_port = self.get_port_pair(pkt)
            
            if TLS is not None and pkt.haslayer(TLS):
                tls = pkt[TLS]
                
                # TLS Client Hello
                if pkt.haslayer(TLSClientHello):
                    client_hello = pkt[TLSClientHello]
                    
                    session_info = {
                        'packet_idx': packet_idx,
                        'timestamp': timestamp,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'type': 'ClientHello',
                        'sni': None,
                        'tls_version': None,
                        'cipher_suites': []
                    }
                    
                    # Version TLS
                    if hasattr(client_hello, 'version'):
                        version = client_hello.version
                        session_info['tls_version'] = self.TLS_VERSIONS.get(version, f'0x{version:04x}')
                        self.tls_versions[session_info['tls_version']] += 1
                    
                    # Cipher suites
                    if hasattr(client_hello, 'ciphers'):
                        session_info['cipher_suites'] = [f'0x{c:04x}' for c in client_hello.ciphers[:10]]
                        for c in client_hello.ciphers[:5]:
                            self.cipher_suites[f'0x{c:04x}'] += 1
                    
                    # Extraire SNI
                    if hasattr(client_hello, 'ext') and TLS_Ext_ServerName is not None:
                        for ext in client_hello.ext or []:
                            if isinstance(ext, TLS_Ext_ServerName):
                                if hasattr(ext, 'servernames'):
                                    for sn in ext.servernames or []:
                                        if hasattr(sn, 'servername'):
                                            sni = sn.servername.decode() if isinstance(sn.servername, bytes) else str(sn.servername)
                                            session_info['sni'] = sni
                                            self.sni_hosts[sni] += 1
                                            self.hosts[sni] += 1
                                            break
                    
                    self.tls_sessions.append(session_info)
                    self.tls_session_count += 1  # Compteur exact (la deque est plafonnée)

            # Essayer d'extraire SNI du payload brut si pas de couche TLS
            elif pkt.haslayer(Raw) and dst_port == 443:
                self._extract_sni_from_raw(pkt, packet_idx, timestamp, src_ip, dst_ip, src_port, dst_port)
                
        except Exception as e:
            logger.debug(f"Error processing TLS packet: {e}")
    
    def _extract_sni_from_raw(self, pkt: Packet, idx: int, ts: float,
                              src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        """Extrait le SNI du payload brut TLS"""
        try:
            payload = bytes(pkt[Raw].load)
            
            # TLS Client Hello: Content Type 22 (Handshake), Handshake Type 1 (ClientHello)
            # Le SNI n'existe que dans le ClientHello: le test payload[5] == 0x01
            # évite le scan octet par octet sur tous les autres paquets TLS
            if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
                # Rechercher SNI extension (type 0x0000)
                # Simple pattern matching pour SNI
                idx_search = 0
                while idx_search < len(payload) - 10:
                    # Extension type 0x0000 = SNI
                    if payload[idx_search:idx_search+2] == b'\x00\x00':
                        ext_len = int.from_bytes(payload[idx_search+2:idx_search+4], 'big')
                        if ext_len > 0 and ext_len < 256:
                            # SNI list length
                            sni_list_len = int.from_bytes(payload[idx_search+4:idx_search+6], 'big')
                            if sni_list_len > 0:
                                # Type 0 = hostname
                                if payload[idx_search+6] == 0x00:
                                    name_len = int.from_bytes(payload[idx_search+7:idx_search+9], 'big')
                                    if name_len > 0 and name_len < 256:
                                        sni = payload[idx_search+9:idx_search+9+name_len].decode('utf-8', errors='ignore')
                                        if sni and '.' in sni:
                                            self.sni_hosts[sni] += 1
                                            self.hosts[sni] += 1
                                            
                                            session_info = {
                                                'packet_idx': idx,
                                                'timestamp': ts,
                                                'src_ip': src_ip,
                                                'dst_ip': dst_ip,
                                                'src_port': src_port,
                                                'dst_port': dst_port,
                                                'type': 'ClientHello',
                                                'sni': sni,
                                                'tls_version': None,
                                                'cipher_suites': []
                                            }
                                            self.tls_sessions.append(session_info)
                                            self.tls_session_count += 1  # Compteur exact
                                            return
                    idx_search += 1
        except Exception:
            pass
    
    def _check_injection(self, request_info: Dict):
        """Détecte les patterns d'injection sur une requête, au fil de l'eau
        (toutes les requêtes sont couvertes malgré le plafond de stockage)"""
        url = request_info.get('url', '') + request_info.get('path', '')
        for pattern in self.INJECTION_PATTERNS_COMPILED:
            if pattern.search(url):
                self._add_anomaly({
                    'type': 'INJECTION_ATTEMPT',
                    'severity': 'HIGH',
                    'description': f'Tentative d\'injection détectée',
                    'details': {
                        'url': url[:200],
                        'src_ip': request_info.get('src_ip'),
                        'packet_idx': request_info.get('packet_idx')
                    },
                    'recommendation': 'Analyser la requête pour confirmer l\'attaque'
                })
                break

    def _detect_anomalies(self):
        """Détecte les anomalies HTTP"""
        # 1. User-Agents suspects
        for ua, count in self.user_agents.items():
            ua_lower = ua.lower()
            for suspicious in self.SUSPICIOUS_USER_AGENTS:
                if suspicious in ua_lower:
                    self._add_anomaly({
                        'type': 'SUSPICIOUS_USER_AGENT',
                        'severity': 'MEDIUM',
                        'description': f'User-Agent suspect détecté: {ua[:80]}',
                        'details': {'user_agent': ua, 'count': count, 'pattern': suspicious},
                        'recommendation': 'Vérifier si ce trafic est légitime (scan de sécurité autorisé)'
                    })
                    break

        # 2. Patterns d'injection: détectés au fil de l'eau dans _check_injection()

        # 3. Taux d'erreurs 4xx/5xx élevé
        total_responses = self.response_count
        if total_responses > 20:
            error_count = sum(
                count for code, count in self.status_codes.items()
                if code.startswith('4') or code.startswith('5')
            )
            error_rate = error_count / total_responses
            if error_rate > 0.3:
                self._add_anomaly({
                    'type': 'HIGH_ERROR_RATE',
                    'severity': 'MEDIUM',
                    'description': f'Taux d\'erreurs HTTP élevé: {error_rate*100:.1f}%',
                    'details': {'rate': error_rate, 'error_count': error_count},
                    'recommendation': 'Possible scan de répertoires ou attaque brute force'
                })
        
        # 4. Nombreuses 404 (directory scanning)
        not_found_count = self.status_codes.get('404', 0)
        if not_found_count > 50:
            self._add_anomaly({
                'type': 'DIRECTORY_SCAN',
                'severity': 'MEDIUM',
                'description': f'Possible scan de répertoires: {not_found_count} erreurs 404',
                'details': {'404_count': not_found_count},
                'recommendation': 'Vérifier les URLs ciblées pour identifier l\'outil de scan'
            })
        
        # 5. Méthodes HTTP suspectes
        suspicious_methods = ['TRACE', 'TRACK', 'DEBUG', 'CONNECT']
        for method in suspicious_methods:
            if self.methods.get(method, 0) > 0:
                self._add_anomaly({
                    'type': 'SUSPICIOUS_HTTP_METHOD',
                    'severity': 'LOW',
                    'description': f'Méthode HTTP suspecte utilisée: {method}',
                    'details': {'method': method, 'count': self.methods[method]},
                    'recommendation': 'Ces méthodes peuvent être utilisées pour des attaques XST ou tunneling'
                })
        
        # 6. TLS versions obsolètes
        if self.tls_versions.get('TLS 1.0', 0) > 0 or self.tls_versions.get('TLS 1.1', 0) > 0:
            self._add_anomaly({
                'type': 'DEPRECATED_TLS',
                'severity': 'MEDIUM',
                'description': 'Versions TLS obsolètes détectées',
                'details': {
                    'tls_1_0': self.tls_versions.get('TLS 1.0', 0),
                    'tls_1_1': self.tls_versions.get('TLS 1.1', 0)
                },
                'recommendation': 'Mettre à jour vers TLS 1.2 ou 1.3'
            })

        # Anomalies récapitulatives pour les types dont la liste a été plafonnée
        self._append_overflow_summaries()
    
    def _compile_summary(self) -> Dict:
        """Compile les statistiques résumées"""
        # Status codes par catégorie
        status_2xx = sum(c for s, c in self.status_codes.items() if s.startswith('2'))
        status_3xx = sum(c for s, c in self.status_codes.items() if s.startswith('3'))
        status_4xx = sum(c for s, c in self.status_codes.items() if s.startswith('4'))
        status_5xx = sum(c for s, c in self.status_codes.items() if s.startswith('5'))
        
        return {
            'total_requests': self.request_count,
            'total_responses': self.response_count,
            'total_tls_sessions': self.tls_session_count,
            'unique_hosts': len(self.hosts),
            'unique_user_agents': len(self.user_agents),
            'unique_urls': len(self.urls),
            'status_2xx': status_2xx,
            'status_3xx': status_3xx,
            'status_4xx': status_4xx,
            'status_5xx': status_5xx,
            'unique_sni_hosts': len(self.sni_hosts),
            # Compteur exact (les listes d'anomalies sont plafonnées, pas les compteurs)
            'anomalies_count': sum(self.anomaly_counts_by_type.values())
        }
    
    def _format_status_codes(self) -> Dict:
        """Formate les status codes avec descriptions"""
        status_descriptions = {
            '200': 'OK', '201': 'Created', '204': 'No Content',
            '301': 'Moved Permanently', '302': 'Found', '304': 'Not Modified',
            '400': 'Bad Request', '401': 'Unauthorized', '403': 'Forbidden',
            '404': 'Not Found', '405': 'Method Not Allowed', '429': 'Too Many Requests',
            '500': 'Internal Server Error', '502': 'Bad Gateway', '503': 'Service Unavailable'
        }
        
        return {
            code: {
                'count': count,
                'description': status_descriptions.get(code, '')
            }
            for code, count in self.status_codes.items()
        }
    
    def _get_top_items(self, d: Dict, limit: int) -> List[Dict]:
        """Retourne les top items triés par count"""
        sorted_items = sorted(d.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{'name': name, 'count': count} for name, count in sorted_items]
    
    def reset(self):
        """Réinitialise l'analyseur"""
        super().reset()
        self.http_requests = []
        self.http_responses = []
        self.tls_sessions = []
        self.methods = defaultdict(int)
        self.status_codes = defaultdict(int)
        self.user_agents = defaultdict(int)
        self.hosts = defaultdict(int)
        self.content_types = defaultdict(int)
        self.urls = defaultdict(int)
        self.tls_versions = defaultdict(int)
        self.cipher_suites = defaultdict(int)
        self.sni_hosts = defaultdict(int)
        self.anomalies = []
