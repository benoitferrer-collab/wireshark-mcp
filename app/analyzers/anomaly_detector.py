"""
Détecteur d'anomalies réseau
Détection: SYN flood, port scan, connexions orphelines, RST anormaux, bursts
Système de scoring des anomalies avec niveaux de sévérité
"""

from typing import Dict, Any, List, Tuple
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from scapy.all import Packet, TCP, IP, IPv6, UDP
from .base import BaseAnalyzer
from app.core.logging_config import get_logger

logger = get_logger(__name__)


class Severity(Enum):
    """Niveaux de sévérité des anomalies"""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class Anomaly:
    """Représentation d'une anomalie détectée"""
    type: str
    severity: Severity
    score: int
    description: str
    details: Dict[str, Any]
    timestamp: float = 0
    source_ip: str = ""
    destination_ip: str = ""

    def to_dict(self) -> Dict:
        return {
            'type': self.type,
            'severity': self.severity.name,
            'score': self.score,
            'description': self.description,
            'details': self.details,
            'timestamp': self.timestamp,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip
        }


class AnomalyDetector(BaseAnalyzer):
    """Détecteur d'anomalies réseau basé sur l'analyse comportementale"""

    # Seuils de détection (configurables)
    THRESHOLDS = {
        'syn_flood_rate': 100,          # SYN par seconde par IP
        'syn_flood_ratio': 0.9,         # Ratio SYN/(SYN+ACK) suspect
        'port_scan_ports': 20,          # Nombre de ports distincts
        'port_scan_time_window': 10,    # Secondes
        'orphan_timeout': 30,           # Secondes sans réponse
        'retransmission_threshold': 0.1, # 10% de retransmissions
        'rst_ratio_threshold': 0.3,     # 30% de RST suspect
        'burst_threshold': 1000,        # Paquets par seconde
        'burst_window': 1               # Fenêtre en secondes
    }

    # Plafonds anti-explosion (mémoire et taille du results.json sur les grosses captures)
    MAX_ANOMALIES_PER_TYPE = 200        # Anomalies listées par type (les compteurs restent exacts)
    MAX_PORTS_PER_IP = 10000            # Couples (dst_ip, port) suivis par IP source
    MAX_SYN_TARGETS_PER_IP = 10000      # Cibles SYN distinctes suivies par IP source
    MAX_CONNECTION_ATTEMPTS = 100000    # Tentatives de connexion suivies (connexions orphelines)

    def __init__(self):
        super().__init__()
        self.anomalies: List[Anomaly] = []
        # Compteurs exacts par type/sévérité: la liste ci-dessus est plafonnée,
        # les compteurs comptabilisent TOUTES les occurrences détectées
        self.anomaly_counts_by_type: Dict[str, int] = defaultdict(int)
        self.anomaly_counts_by_severity: Dict[str, int] = defaultdict(int)
        self.total_anomaly_score: int = 0
        self._anomaly_overflow: Dict[str, Dict] = {}  # type -> sévérité/score pour le récapitulatif
        self.ip_activity: Dict[str, Dict] = defaultdict(lambda: {
            'syn_count': 0,             # Compteur de SYN émis (remplace la liste syn_sent)
            'syn_first_ts': None,       # Premier/dernier SYN (pour le taux de SYN/s)
            'syn_last_ts': None,
            'syn_targets': set(),       # Cibles (dst_ip, port) des SYN — plafonné
            'syn_received': 0,          # Compteur de SYN-ACK reçus (remplace la liste de timestamps)
            'ports_contacted': set(),   # Plafonné à MAX_PORTS_PER_IP
            'first_ts': None,           # Premier/dernier paquet vus (remplace la liste timestamps)
            'last_ts': None,
            'rst_sent': 0,
            'rst_received': 0,
            'total_packets': 0
        })
        self.connection_attempts: Dict[Tuple, Dict] = {}
        # Agrégation incrémentale paquets/seconde pour la détection de bursts
        # (remplace packet_timeline qui stockait un tuple par paquet — mémoire non bornée)
        self.packets_per_second: Dict[int, int] = defaultdict(int)

    def reset(self):
        """Réinitialise l'état interne de l'analyseur"""
        super().reset()
        self.anomalies = []
        self.anomaly_counts_by_type = defaultdict(int)
        self.anomaly_counts_by_severity = defaultdict(int)
        self.total_anomaly_score = 0
        self._anomaly_overflow = {}
        self.ip_activity.clear()
        self.connection_attempts = {}
        self.packets_per_second = defaultdict(int)

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """Analyse les paquets pour détecter des anomalies"""
        logger.info("anomaly_detection_started", packet_count=len(packets))

        # Phase 1: Collecte des données
        for pkt in packets:
            self._collect_packet_data(pkt)

        # Phase 2: Détection des anomalies
        self._detect_syn_flood()
        self._detect_port_scan()
        self._detect_orphan_connections()
        self._detect_excessive_rst()
        self._detect_traffic_bursts()
        self._detect_unusual_ports()

        # Anomalies récapitulatives pour les types dont la liste a été plafonnée
        self._append_overflow_summaries()

        # Calcul du score global (compteurs exacts, occurrences non listées incluses)
        total_score = self.total_anomaly_score
        total_anomalies = sum(self.anomaly_counts_by_type.values())

        # Compilation des résultats
        self.results = {
            'summary': {
                'total_anomalies': total_anomalies,
                'total_score': total_score,
                'risk_level': self._calculate_risk_level(total_score),
                'by_severity': self._count_by_severity(),
                'by_type': self._count_by_type()
            },
            'anomalies': [a.to_dict() for a in sorted(self.anomalies,
                         key=lambda x: x.score, reverse=True)],
            'top_suspicious_ips': self._get_suspicious_ips(),
            'detection_details': {
                'syn_flood': self._get_syn_flood_details(),
                'port_scan': self._get_port_scan_details(),
                'rst_analysis': self._get_rst_details()
            }
        }

        logger.info("anomaly_detection_completed",
                   anomalies_found=total_anomalies,
                   total_score=total_score)

        return self.results

    def _add_anomaly(self, anomaly: Anomaly):
        """Enregistre une anomalie en plafonnant la liste par type.
        Les compteurs (type, sévérité, score) restent exacts au-delà du plafond:
        seules les premières occurrences de chaque type sont listées."""
        self.anomaly_counts_by_type[anomaly.type] += 1
        self.anomaly_counts_by_severity[anomaly.severity.name] += 1
        self.total_anomaly_score += anomaly.score

        if self.anomaly_counts_by_type[anomaly.type] <= self.MAX_ANOMALIES_PER_TYPE:
            self.anomalies.append(anomaly)
        elif anomaly.type not in self._anomaly_overflow:
            # Mémorise la sévérité/score du type pour l'anomalie récapitulative
            self._anomaly_overflow[anomaly.type] = {
                'severity': anomaly.severity,
                'score': anomaly.score
            }

    def _append_overflow_summaries(self):
        """Ajoute UNE anomalie récapitulative par type dont la liste a été plafonnée"""
        for atype, info in self._anomaly_overflow.items():
            total = self.anomaly_counts_by_type[atype]
            hidden = total - self.MAX_ANOMALIES_PER_TYPE
            self.anomalies.append(Anomaly(
                type=atype,
                severity=info['severity'],
                score=info['score'],
                description=f"{hidden} occurrences supplémentaires du même type non listées",
                details={
                    'total_occurrences': total,
                    'occurrences_listees': self.MAX_ANOMALIES_PER_TYPE,
                    'occurrences_non_listees': hidden,
                    'resume': True
                }
            ))

    def _collect_packet_data(self, pkt: Packet):
        """Collecte les données d'un paquet pour analyse"""
        timestamp = self.get_packet_timestamp(pkt)

        # Extraction des IPs
        src_ip, dst_ip = None, None
        if pkt.haslayer(IP):
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst

        if not src_ip or not dst_ip:
            return

        # Agrégation incrémentale par seconde (détection de bursts)
        self.packets_per_second[int(timestamp)] += 1

        # Activité IP (suivi premier/dernier paquet plutôt que liste de timestamps)
        activity = self.ip_activity[src_ip]
        activity['total_packets'] += 1
        if activity['first_ts'] is None or timestamp < activity['first_ts']:
            activity['first_ts'] = timestamp
        if activity['last_ts'] is None or timestamp > activity['last_ts']:
            activity['last_ts'] = timestamp

        # Analyse TCP
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = tcp.flags
            dst_port = tcp.dport

            # Tracking des SYN
            if flags.S and not flags.A:
                activity['syn_count'] += 1
                if activity['syn_first_ts'] is None or timestamp < activity['syn_first_ts']:
                    activity['syn_first_ts'] = timestamp
                if activity['syn_last_ts'] is None or timestamp > activity['syn_last_ts']:
                    activity['syn_last_ts'] = timestamp
                # Ensembles plafonnés: au-delà du plafond, on cesse d'ajouter
                # (les seuils de détection sont très en dessous des plafonds)
                if len(activity['syn_targets']) < self.MAX_SYN_TARGETS_PER_IP:
                    activity['syn_targets'].add((dst_ip, dst_port))
                if len(activity['ports_contacted']) < self.MAX_PORTS_PER_IP:
                    activity['ports_contacted'].add((dst_ip, dst_port))

                # Tentative de connexion (dict plafonné: au-delà, les nouvelles
                # tentatives ne sont plus suivies individuellement)
                conn_key = (src_ip, tcp.sport, dst_ip, dst_port)
                if conn_key in self.connection_attempts or \
                        len(self.connection_attempts) < self.MAX_CONNECTION_ATTEMPTS:
                    self.connection_attempts[conn_key] = {
                        'syn_time': timestamp,
                        'syn_ack_received': False,
                        'established': False
                    }

            # SYN-ACK reçu
            elif flags.S and flags.A:
                self.ip_activity[dst_ip]['syn_received'] += 1
                conn_key = (dst_ip, tcp.dport, src_ip, tcp.sport)
                if conn_key in self.connection_attempts:
                    self.connection_attempts[conn_key]['syn_ack_received'] = True

            # RST
            if flags.R:
                self.ip_activity[src_ip]['rst_sent'] += 1
                self.ip_activity[dst_ip]['rst_received'] += 1

        # Analyse UDP
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            if len(activity['ports_contacted']) < self.MAX_PORTS_PER_IP:
                activity['ports_contacted'].add((dst_ip, udp.dport))

    def _detect_syn_flood(self):
        """Détection des attaques SYN flood"""
        for ip, activity in self.ip_activity.items():
            syn_count = activity['syn_count']
            if not syn_count:
                continue

            # Calcul du taux de SYN par seconde
            if syn_count >= 2:
                duration = activity['syn_last_ts'] - activity['syn_first_ts']
                if duration > 0:
                    syn_rate = syn_count / duration

                    if syn_rate > self.THRESHOLDS['syn_flood_rate']:
                        # Calcul du ratio SYN/SYN-ACK
                        syn_ack_count = activity['syn_received']
                        ratio = syn_count / (syn_count + syn_ack_count + 1)

                        if ratio > self.THRESHOLDS['syn_flood_ratio']:
                            self._add_anomaly(Anomaly(
                                type='SYN_FLOOD',
                                severity=Severity.CRITICAL,
                                score=100,
                                description=f"Possible SYN flood depuis {ip}",
                                details={
                                    'syn_rate': round(syn_rate, 2),
                                    'total_syn': syn_count,
                                    'syn_ack_received': syn_ack_count,
                                    'ratio': round(ratio, 3)
                                },
                                source_ip=ip
                            ))

            # Détection de nombreux SYN vers différentes destinations
            if len(activity['syn_targets']) > 50:
                self._add_anomaly(Anomaly(
                    type='SYN_SCAN',
                    severity=Severity.HIGH,
                    score=70,
                    description=f"Nombreux SYN vers différentes cibles depuis {ip}",
                    details={
                        'unique_targets': len(activity['syn_targets']),
                        'total_syn': syn_count
                    },
                    source_ip=ip
                ))

    def _detect_port_scan(self):
        """Détection des scans de ports"""
        for ip, activity in self.ip_activity.items():
            ports_by_target = defaultdict(set)

            for target_ip, target_port in activity['ports_contacted']:
                ports_by_target[target_ip].add(target_port)

            for target_ip, ports in ports_by_target.items():
                if len(ports) >= self.THRESHOLDS['port_scan_ports']:
                    # Analyse temporelle (premier/dernier paquet vus pour cette IP)
                    if activity['first_ts'] is not None:
                        duration = activity['last_ts'] - activity['first_ts']

                        severity = Severity.MEDIUM
                        score = 50

                        # Port scan rapide = plus suspect
                        if duration < self.THRESHOLDS['port_scan_time_window']:
                            severity = Severity.HIGH
                            score = 80

                        self._add_anomaly(Anomaly(
                            type='PORT_SCAN',
                            severity=severity,
                            score=score,
                            description=f"Port scan détecté: {ip} -> {target_ip}",
                            details={
                                'ports_scanned': len(ports),
                                'ports_list': sorted(list(ports))[:50],  # Limiter
                                'duration_seconds': round(duration, 2)
                            },
                            source_ip=ip,
                            destination_ip=target_ip
                        ))

    def _detect_orphan_connections(self):
        """Détection des connexions orphelines (SYN sans réponse)"""
        orphan_count = 0
        orphan_ips = defaultdict(int)

        for conn_key, conn_data in self.connection_attempts.items():
            if not conn_data['syn_ack_received']:
                orphan_count += 1
                orphan_ips[conn_key[0]] += 1

        if orphan_count > 10:
            # Identifier les IPs avec le plus de connexions orphelines
            top_orphan_ips = sorted(orphan_ips.items(),
                                   key=lambda x: x[1], reverse=True)[:10]

            self._add_anomaly(Anomaly(
                type='ORPHAN_CONNECTIONS',
                severity=Severity.MEDIUM,
                score=40,
                description=f"{orphan_count} connexions sans réponse SYN-ACK",
                details={
                    'orphan_count': orphan_count,
                    'top_sources': [{'ip': ip, 'count': c} for ip, c in top_orphan_ips]
                }
            ))

    def _detect_excessive_rst(self):
        """Détection des RST anormaux"""
        for ip, activity in self.ip_activity.items():
            rst_sent = activity['rst_sent']
            total = activity['total_packets']

            if total > 10:
                rst_ratio = rst_sent / total

                if rst_ratio > self.THRESHOLDS['rst_ratio_threshold']:
                    self._add_anomaly(Anomaly(
                        type='EXCESSIVE_RST',
                        severity=Severity.MEDIUM,
                        score=45,
                        description=f"Ratio RST élevé depuis {ip}",
                        details={
                            'rst_count': rst_sent,
                            'total_packets': total,
                            'rst_ratio': round(rst_ratio, 3)
                        },
                        source_ip=ip
                    ))

    def _detect_traffic_bursts(self):
        """Détection des bursts de trafic"""
        if not self.packets_per_second:
            return

        # Détecter les pics (compteurs par seconde agrégés incrémentalement à la
        # collecte) — parcours chronologique pour lister les premiers pics
        for second in sorted(self.packets_per_second):
            count = self.packets_per_second[second]
            if count > self.THRESHOLDS['burst_threshold']:
                self._add_anomaly(Anomaly(
                    type='TRAFFIC_BURST',
                    severity=Severity.LOW,
                    score=25,
                    description=f"Pic de trafic détecté: {count} paquets/seconde",
                    details={
                        'packets_per_second': count,
                        'timestamp': second
                    },
                    timestamp=second
                ))

    def _detect_unusual_ports(self):
        """Détection de l'utilisation de ports inhabituels"""
        suspicious_ports = set()

        for ip, activity in self.ip_activity.items():
            for target_ip, port in activity['ports_contacted']:
                # Ports souvent utilisés pour backdoors/malware
                if port in [4444, 5555, 6666, 31337, 12345, 54321]:
                    suspicious_ports.add((ip, target_ip, port))

        if suspicious_ports:
            self._add_anomaly(Anomaly(
                type='SUSPICIOUS_PORTS',
                severity=Severity.HIGH,
                score=60,
                description=f"Utilisation de ports suspects détectée",
                details={
                    'connections': [
                        {'src': src, 'dst': dst, 'port': port}
                        for src, dst, port in suspicious_ports
                    ][:20]  # Limiter
                }
            ))

    def _calculate_risk_level(self, total_score: int) -> str:
        """Calcule le niveau de risque global"""
        if total_score == 0:
            return 'NONE'
        elif total_score < 50:
            return 'LOW'
        elif total_score < 150:
            return 'MEDIUM'
        elif total_score < 300:
            return 'HIGH'
        else:
            return 'CRITICAL'

    def _count_by_severity(self) -> Dict[str, int]:
        """Compte les anomalies par sévérité (compteurs exacts, plafond inclus)"""
        return dict(self.anomaly_counts_by_severity)

    def _count_by_type(self) -> Dict[str, int]:
        """Compte les anomalies par type (compteurs exacts, plafond inclus)"""
        return dict(self.anomaly_counts_by_type)

    def _get_suspicious_ips(self) -> List[Dict]:
        """Identifie les IPs les plus suspectes"""
        ip_scores = defaultdict(int)
        ip_anomalies = defaultdict(list)

        for a in self.anomalies:
            if a.source_ip:
                ip_scores[a.source_ip] += a.score
                ip_anomalies[a.source_ip].append(a.type)

        sorted_ips = sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)

        return [
            {
                'ip': ip,
                'score': score,
                'anomaly_types': list(set(ip_anomalies[ip]))
            }
            for ip, score in sorted_ips[:20]
        ]

    def _get_syn_flood_details(self) -> Dict:
        """Détails sur la détection SYN flood"""
        syn_floods = [a for a in self.anomalies
                      if a.type == 'SYN_FLOOD' and not a.details.get('resume')]
        count = self.anomaly_counts_by_type.get('SYN_FLOOD', 0)
        return {
            'detected': count > 0,
            'count': count,
            'sources': [a.source_ip for a in syn_floods]
        }

    def _get_port_scan_details(self) -> Dict:
        """Détails sur la détection de port scan"""
        scans = [a for a in self.anomalies
                 if a.type == 'PORT_SCAN' and not a.details.get('resume')]
        count = self.anomaly_counts_by_type.get('PORT_SCAN', 0)
        return {
            'detected': count > 0,
            'count': count,
            'scanners': [{'src': a.source_ip, 'dst': a.destination_ip} for a in scans]
        }

    def _get_rst_details(self) -> Dict:
        """Détails sur les anomalies RST"""
        count = sum(c for t, c in self.anomaly_counts_by_type.items() if 'RST' in t)
        return {
            'detected': count > 0,
            'count': count
        }
