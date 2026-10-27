"""
Service principal d'analyse PCAP
Orchestration des analyseurs et gestion des tâches Celery
Inclut les analyseurs de protocoles entreprise et l'enrichissement
"""

import os
import time
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime

from celery import shared_task
from scapy.all import rdpcap, PcapReader

from app.core.celery_app import celery_app
from app.core.config import settings
from app.core.logging_config import get_logger

# Analyseurs de base
from app.analyzers.protocol_analyzer import ProtocolAnalyzer
from app.analyzers.tcp_analyzer import TCPAnalyzer
from app.analyzers.anomaly_detector import AnomalyDetector
from app.analyzers.dns_analyzer import DNSAnalyzer
from app.analyzers.http_analyzer import HTTPAnalyzer

# Analyseurs de protocoles entreprise
from app.analyzers.smb_analyzer import SMBAnalyzer
from app.analyzers.ldap_analyzer import LDAPAnalyzer
from app.analyzers.kerberos_analyzer import KerberosAnalyzer
from app.analyzers.rdp_analyzer import RDPAnalyzer
from app.analyzers.ssh_analyzer import SSHAnalyzer

# Services
from app.services.storage_service import storage_service
from app.services.enrichment_service import get_enrichment_service
from app.services.timeline_service import TimelineService
from app.services.graph_service import GraphService
from app.services.stream_service import StreamService

logger = get_logger(__name__)


class PCAPAnalysisService:
    """Service d'analyse PCAP orchestrant les différents analyseurs"""

    # Plafond de la liste agrégée des anomalies (on garde les plus sévères)
    MAX_AGGREGATED_ANOMALIES = 1000

    def __init__(self):
        # Analyseurs de base
        self.protocol_analyzer = ProtocolAnalyzer()
        self.tcp_analyzer = TCPAnalyzer()
        self.anomaly_detector = AnomalyDetector()
        self.dns_analyzer = DNSAnalyzer()
        self.http_analyzer = HTTPAnalyzer()
        
        # Analyseurs de protocoles entreprise
        self.smb_analyzer = SMBAnalyzer()
        self.ldap_analyzer = LDAPAnalyzer()
        self.kerberos_analyzer = KerberosAnalyzer()
        self.rdp_analyzer = RDPAnalyzer()
        self.ssh_analyzer = SSHAnalyzer()
        
        # Service d'enrichissement
        self.enrichment_service = get_enrichment_service()
        
        # Services supplémentaires
        from app.services.stream_service import get_stream_service
        self.timeline_service = TimelineService()
        self.graph_service = GraphService()
        # Singleton partagé avec les routes (un seul cache de streams)
        self.stream_service = get_stream_service()
        
        # Stockage des paquets pour drill-down
        self.packets_data: List[Dict] = []
    
    def analyze(self, pcap_path: Path, filename: str = "", enable_enrichment: bool = True) -> Dict[str, Any]:
        """Exécute l'analyse complète d'un fichier PCAP"""
        start_time = time.time()
        
        logger.info("analysis_started", file=str(pcap_path))
        
        # Charger les paquets
        try:
            packets = self._load_packets(pcap_path)
        except Exception as e:
            logger.error("packet_loading_failed", error=str(e))
            raise ValueError(f"Impossible de charger le fichier PCAP: {e}")
        
        if not packets:
            raise ValueError("Le fichier PCAP est vide ou invalide")
        
        logger.info("packets_loaded", count=len(packets))
        
        # Exécuter les analyseurs
        results = {
            'metadata': {
                'filename': filename or pcap_path.name,
                'file_size': pcap_path.stat().st_size,
                'analysis_timestamp': datetime.utcnow().isoformat(),
                'analysis_duration_seconds': 0,
                'pcap_path': str(pcap_path),  # Pour reconstruction de streams
            },
            'protocol_analysis': {},
            'tcp_analysis': {},
            'anomaly_analysis': {},
            'anomaly_detection': {},  # Alias de compatibilité (frontend/exports existants)
            'dns_analysis': {},
            'http_analysis': {},
            # Protocoles entreprise
            'smb_analysis': {},
            'ldap_analysis': {},
            'kerberos_analysis': {},
            'rdp_analysis': {},
            'ssh_analysis': {},
            # Enrichissement
            'enrichment': {},
            # Services
            'timeline': {},
            'network_graph': {},
            'streams': {},
            'packets_index': []  # Index des paquets pour drill-down
        }
        
        # Extraire les données des paquets pour drill-down (max 5000)
        results['packets_index'] = self._extract_packets_index(packets, limit=5000)

        # === DISPATCH UNIQUE ===
        # Chaque paquet est classé une seule fois; les analyseurs spécialisés
        # ne parcourent que leurs paquets candidats au lieu de refaire chacun
        # une passe complète sur toute la capture (9 passes -> 1).
        dispatch, dispatch_indices = self._dispatch_packets(packets)

        # === ANALYSEURS DE BASE ===
        
        # Analyse protocolaire
        try:
            self.protocol_analyzer.reset()
            results['protocol_analysis'] = self.protocol_analyzer.analyze(packets)
        except Exception as e:
            logger.error("protocol_analysis_failed", error=str(e))
            results['protocol_analysis'] = {'error': str(e)}
        
        # Analyse TCP approfondie
        try:
            self.tcp_analyzer.reset()
            self.tcp_analyzer.sessions = {}
            self.tcp_analyzer.timeline_events = []
            results['tcp_analysis'] = self.tcp_analyzer.analyze(dispatch['tcp'])
        except Exception as e:
            logger.error("tcp_analysis_failed", error=str(e))
            results['tcp_analysis'] = {'error': str(e)}
        
        # Détection d'anomalies (reset() réinitialise tout l'état interne:
        # anomalies, compteurs, ip_activity, connection_attempts, packets_per_second)
        try:
            self.anomaly_detector.reset()
            anomaly_results = self.anomaly_detector.analyze(packets)
            results['anomaly_analysis'] = anomaly_results
            results['anomaly_detection'] = anomaly_results
        except Exception as e:
            logger.error("anomaly_detection_failed", error=str(e))
            anomaly_error = {'error': str(e)}
            results['anomaly_analysis'] = anomaly_error
            results['anomaly_detection'] = anomaly_error
        
        # Analyse DNS
        try:
            self.dns_analyzer.reset()
            results['dns_analysis'] = self._remap_packet_indices(
                self.dns_analyzer.analyze(dispatch['dns']), dispatch_indices['dns'])
        except Exception as e:
            logger.error("dns_analysis_failed", error=str(e))
            results['dns_analysis'] = {'error': str(e)}
        
        # Analyse HTTP/HTTPS
        try:
            self.http_analyzer.reset()
            results['http_analysis'] = self._remap_packet_indices(
                self.http_analyzer.analyze(dispatch['tcp']), dispatch_indices['tcp'])
        except Exception as e:
            logger.error("http_analysis_failed", error=str(e))
            results['http_analysis'] = {'error': str(e)}
        
        # === ANALYSEURS PROTOCOLES ENTREPRISE ===
        
        # Analyse SMB
        try:
            self.smb_analyzer.reset()
            results['smb_analysis'] = self._remap_packet_indices(
                self.smb_analyzer.analyze(dispatch['smb']), dispatch_indices['smb'])
        except Exception as e:
            logger.error("smb_analysis_failed", error=str(e))
            results['smb_analysis'] = {'error': str(e)}
        
        # Analyse LDAP
        try:
            self.ldap_analyzer.reset()
            results['ldap_analysis'] = self._remap_packet_indices(
                self.ldap_analyzer.analyze(dispatch['ldap']), dispatch_indices['ldap'])
        except Exception as e:
            logger.error("ldap_analysis_failed", error=str(e))
            results['ldap_analysis'] = {'error': str(e)}
        
        # Analyse Kerberos
        try:
            self.kerberos_analyzer.reset()
            results['kerberos_analysis'] = self._remap_packet_indices(
                self.kerberos_analyzer.analyze(dispatch['kerberos']), dispatch_indices['kerberos'])
        except Exception as e:
            logger.error("kerberos_analysis_failed", error=str(e))
            results['kerberos_analysis'] = {'error': str(e)}
        
        # Analyse RDP
        try:
            self.rdp_analyzer.reset()
            results['rdp_analysis'] = self._remap_packet_indices(
                self.rdp_analyzer.analyze(dispatch['rdp']), dispatch_indices['rdp'])
        except Exception as e:
            logger.error("rdp_analysis_failed", error=str(e))
            results['rdp_analysis'] = {'error': str(e)}
        
        # Analyse SSH
        try:
            self.ssh_analyzer.reset()
            results['ssh_analysis'] = self._remap_packet_indices(
                self.ssh_analyzer.analyze(dispatch['ssh']), dispatch_indices['ssh'])
        except Exception as e:
            logger.error("ssh_analysis_failed", error=str(e))
            results['ssh_analysis'] = {'error': str(e)}
        
        # === ENRICHISSEMENT ===
        if enable_enrichment:
            try:
                results['enrichment'] = self._enrich_results(results)
            except Exception as e:
                logger.error("enrichment_failed", error=str(e))
                results['enrichment'] = {'error': str(e)}
        
        # === SERVICES SUPPLEMENTAIRES ===
        
        # Timeline
        try:
            results['timeline'] = self.timeline_service.generate_timeline(results)
        except Exception as e:
            logger.error("timeline_generation_failed", error=str(e))
            results['timeline'] = {'error': str(e), 'events': [], 'groups': []}
        
        # Network Graph
        try:
            results['network_graph'] = self.graph_service.generate_network_graph(results)
        except Exception as e:
            logger.error("graph_generation_failed", error=str(e))
            results['network_graph'] = {'error': str(e), 'nodes': [], 'edges': []}
        
        # Stream List
        try:
            results['streams'] = {
                'stream_list': self.stream_service.get_stream_list(results),
                'pcap_path': str(pcap_path)  # Pour reconstruction à la demande
            }
        except Exception as e:
            logger.error("stream_list_failed", error=str(e))
            results['streams'] = {'error': str(e), 'stream_list': []}
        
        # Agrégation des anomalies de tous les analyseurs
        results['all_anomalies'] = self._aggregate_anomalies(results)
        
        # Durée totale
        analysis_duration = time.time() - start_time
        results['metadata']['analysis_duration_seconds'] = round(analysis_duration, 2)
        
        logger.info("analysis_completed", 
                   duration=analysis_duration,
                   packets=len(packets))
        
        return results
    
    def _enrich_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Enrichit les résultats avec GeoIP, ASN, etc."""
        # Collecter toutes les IPs uniques
        all_ips = set()
        all_domains = set()
        
        # IPs des paquets
        for pkt in results.get('packets_index', [])[:1000]:
            if pkt.get('src_ip'):
                all_ips.add(pkt['src_ip'])
            if pkt.get('dst_ip'):
                all_ips.add(pkt['dst_ip'])
        
        # IPs de l'analyse protocolaire
        proto = results.get('protocol_analysis', {})
        for ip_stat in proto.get('top_source_ips', []) + proto.get('top_dest_ips', []):
            if isinstance(ip_stat, dict) and ip_stat.get('ip'):
                all_ips.add(ip_stat['ip'])
            elif isinstance(ip_stat, tuple) and len(ip_stat) > 0:
                all_ips.add(ip_stat[0])
        
        # Domaines DNS
        dns = results.get('dns_analysis', {})
        for domain_info in dns.get('top_domains', []):
            if isinstance(domain_info, dict) and domain_info.get('domain'):
                all_domains.add(domain_info['domain'])
            elif isinstance(domain_info, tuple) and len(domain_info) > 0:
                all_domains.add(domain_info[0])
        
        # Hosts HTTP
        http = results.get('http_analysis', {})
        for host_info in http.get('top_hosts', []):
            if isinstance(host_info, dict) and host_info.get('host'):
                all_domains.add(host_info['host'])
        
        # Enrichir (limité pour performance)
        enrichment = self.enrichment_service.enrich_batch(
            list(all_ips)[:50],
            list(all_domains)[:20]
        )
        
        return enrichment
    
    def _aggregate_anomalies(self, results: Dict[str, Any]) -> List[Dict]:
        """Agrège toutes les anomalies de tous les analyseurs"""
        all_anomalies = []
        
        # Anomalies générales
        anomaly_analysis = results.get('anomaly_analysis', {})
        for anomaly in anomaly_analysis.get('anomalies', []):
            anomaly['source'] = 'network'
            all_anomalies.append(anomaly)
        
        # Anomalies DNS
        dns_analysis = results.get('dns_analysis', {})
        for anomaly in dns_analysis.get('anomalies', []):
            anomaly['source'] = 'dns'
            all_anomalies.append(anomaly)
        
        # Anomalies HTTP
        http_analysis = results.get('http_analysis', {})
        for anomaly in http_analysis.get('anomalies', []):
            anomaly['source'] = 'http'
            all_anomalies.append(anomaly)
        
        # Anomalies SMB
        smb_analysis = results.get('smb_analysis', {})
        for anomaly in smb_analysis.get('anomalies', []):
            anomaly['source'] = 'smb'
            all_anomalies.append(anomaly)
        
        # Anomalies LDAP
        ldap_analysis = results.get('ldap_analysis', {})
        for anomaly in ldap_analysis.get('anomalies', []):
            anomaly['source'] = 'ldap'
            all_anomalies.append(anomaly)
        
        # Anomalies Kerberos
        kerberos_analysis = results.get('kerberos_analysis', {})
        for anomaly in kerberos_analysis.get('anomalies', []):
            anomaly['source'] = 'kerberos'
            all_anomalies.append(anomaly)
        
        # Anomalies RDP
        rdp_analysis = results.get('rdp_analysis', {})
        for anomaly in rdp_analysis.get('anomalies', []):
            anomaly['source'] = 'rdp'
            all_anomalies.append(anomaly)
        
        # Anomalies SSH
        ssh_analysis = results.get('ssh_analysis', {})
        for anomaly in ssh_analysis.get('anomalies', []):
            anomaly['source'] = 'ssh'
            all_anomalies.append(anomaly)
        
        # Trier par sévérité (insensible à la casse: les analyseurs émettent 'HIGH', etc.)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        all_anomalies.sort(key=lambda x: severity_order.get(str(x.get('severity', 'info')).lower(), 5))

        # Plafonner la liste agrégée pour ne pas faire exploser le results.json
        # (le tri ci-dessus garantit qu'on conserve les plus sévères)
        if len(all_anomalies) > self.MAX_AGGREGATED_ANOMALIES:
            logger.warning("all_anomalies_truncated",
                           total=len(all_anomalies),
                           kept=self.MAX_AGGREGATED_ANOMALIES)
            all_anomalies = all_anomalies[:self.MAX_AGGREGATED_ANOMALIES]

        return all_anomalies
    
    def _dispatch_packets(self, packets: list) -> Dict[str, list]:
        """Classe chaque paquet une seule fois vers les analyseurs candidats.

        Les ensembles de ports proviennent des analyseurs eux-mêmes: le
        filtrage interne de chaque analyseur reste actif (prédicat identique,
        appliqué à un sous-ensemble), donc les résultats sont inchangés.
        """
        from scapy.all import TCP, UDP, DNS
        from app.analyzers.smb_analyzer import SMB_PORTS
        from app.analyzers.ldap_analyzer import LDAP_PORTS
        from app.analyzers.kerberos_analyzer import KERBEROS_PORTS
        from app.analyzers.rdp_analyzer import RDP_PORTS
        from app.analyzers.ssh_analyzer import SSH_PORTS

        dispatch: Dict[str, list] = {
            'tcp': [], 'dns': [], 'smb': [], 'ldap': [],
            'kerberos': [], 'rdp': [], 'ssh': []
        }
        # Position globale (dans la capture) de chaque paquet des sous-listes:
        # sert à remapper les packet_idx émis par les analyseurs (indices
        # relatifs à leur sous-liste) vers l'index global du drill-down
        indices: Dict[str, list] = {k: [] for k in dispatch}

        def _add(key: str, pkt, global_idx: int):
            dispatch[key].append(pkt)
            indices[key].append(global_idx)

        for i, pkt in enumerate(packets):
            if pkt.haslayer(TCP):
                _add('tcp', pkt, i)
                tcp = pkt[TCP]
                sport, dport = tcp.sport, tcp.dport
                if sport in SMB_PORTS or dport in SMB_PORTS:
                    _add('smb', pkt, i)
                if sport in LDAP_PORTS or dport in LDAP_PORTS:
                    _add('ldap', pkt, i)
                if sport in KERBEROS_PORTS or dport in KERBEROS_PORTS:
                    _add('kerberos', pkt, i)
                if sport in RDP_PORTS or dport in RDP_PORTS:
                    _add('rdp', pkt, i)
                if sport in SSH_PORTS or dport in SSH_PORTS:
                    _add('ssh', pkt, i)
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                sport, dport = udp.sport, udp.dport
                # LDAP (CLDAP) et Kerberos existent aussi sur UDP
                if sport in LDAP_PORTS or dport in LDAP_PORTS:
                    _add('ldap', pkt, i)
                if sport in KERBEROS_PORTS or dport in KERBEROS_PORTS:
                    _add('kerberos', pkt, i)

            if pkt.haslayer(DNS):
                _add('dns', pkt, i)

        logger.info("packet_dispatch_done",
                    tcp=len(dispatch['tcp']), dns=len(dispatch['dns']),
                    smb=len(dispatch['smb']), ldap=len(dispatch['ldap']),
                    kerberos=len(dispatch['kerberos']), rdp=len(dispatch['rdp']),
                    ssh=len(dispatch['ssh']))
        return dispatch, indices

    @staticmethod
    def _remap_packet_indices(result, mapping: list):
        """Remappe récursivement les champs packet_idx (relatifs à une
        sous-liste dispatchée) vers les positions globales de la capture."""
        n = len(mapping)
        stack = [result]
        while stack:
            obj = stack.pop()
            if isinstance(obj, dict):
                v = obj.get('packet_idx')
                if isinstance(v, int) and 0 <= v < n:
                    obj['packet_idx'] = mapping[v]
                stack.extend(obj.values())
            elif isinstance(obj, list):
                stack.extend(obj)
        return result

    def _load_packets(self, pcap_path: Path) -> list:
        """Charge les paquets d'un fichier PCAP"""
        # Pour les gros fichiers, utiliser PcapReader en streaming
        file_size = pcap_path.stat().st_size
        
        if file_size > 500 * 1024 * 1024:  # > 500MB
            logger.info("using_streaming_reader", file_size=file_size)
            packets = []
            with PcapReader(str(pcap_path)) as reader:
                for pkt in reader:
                    packets.append(pkt)
                    # Limiter pour éviter les problèmes de mémoire
                    if len(packets) >= 10_000_000:  # 10M paquets max
                        logger.warning("packet_limit_reached")
                        break
            return packets
        else:
            return list(rdpcap(str(pcap_path)))
    
    def _extract_packets_index(self, packets: list, limit: int = 5000) -> List[Dict]:
        """Extrait un index des paquets pour le drill-down (au plus `limit` paquets)"""
        from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS, Ether
        from app.core.mac_vendor import normalize_mac_address

        packets_index = []

        for idx, pkt in enumerate(packets):
            if idx >= limit:
                break
            try:
                packet_info = {
                    'idx': idx,
                    'timestamp': float(pkt.time) if hasattr(pkt, 'time') else 0,
                    'length': len(pkt),
                    'src_mac': None,
                    'dst_mac': None,
                    'src_ip': None,
                    'dst_ip': None,
                    'src_port': None,
                    'dst_port': None,
                    'protocol': 'Unknown',
                    'info': ''
                }

                # Couche Ethernet
                if pkt.haslayer(Ether):
                    eth = pkt[Ether]
                    packet_info['src_mac'] = normalize_mac_address(getattr(eth, 'src', ''))
                    packet_info['dst_mac'] = normalize_mac_address(getattr(eth, 'dst', ''))
                
                # Couche IP
                if pkt.haslayer(IP):
                    ip = pkt[IP]
                    packet_info['src_ip'] = ip.src
                    packet_info['dst_ip'] = ip.dst
                    packet_info['protocol'] = 'IPv4'
                elif pkt.haslayer(IPv6):
                    ip = pkt[IPv6]
                    packet_info['src_ip'] = ip.src
                    packet_info['dst_ip'] = ip.dst
                    packet_info['protocol'] = 'IPv6'
                
                # Couche Transport
                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    packet_info['src_port'] = tcp.sport
                    packet_info['dst_port'] = tcp.dport
                    packet_info['protocol'] = 'TCP'
                    flags = []
                    if tcp.flags.S: flags.append('SYN')
                    if tcp.flags.A: flags.append('ACK')
                    if tcp.flags.F: flags.append('FIN')
                    if tcp.flags.R: flags.append('RST')
                    if tcp.flags.P: flags.append('PSH')
                    packet_info['info'] = f"[{','.join(flags)}] Seq={tcp.seq} Ack={tcp.ack}"
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    packet_info['src_port'] = udp.sport
                    packet_info['dst_port'] = udp.dport
                    packet_info['protocol'] = 'UDP'
                    packet_info['info'] = f"Len={udp.len}"
                elif pkt.haslayer(ICMP):
                    icmp = pkt[ICMP]
                    packet_info['protocol'] = 'ICMP'
                    packet_info['info'] = f"Type={icmp.type} Code={icmp.code}"
                
                # DNS
                if pkt.haslayer(DNS):
                    dns = pkt[DNS]
                    packet_info['protocol'] = 'DNS'
                    if dns.qd:
                        qname = dns.qd.qname.decode() if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
                        packet_info['info'] = f"{'Query' if dns.qr == 0 else 'Response'}: {qname}"
                
                packets_index.append(packet_info)
                
            except Exception as e:
                packets_index.append({
                    'idx': idx,
                    'timestamp': 0,
                    'length': len(pkt) if pkt else 0,
                    'protocol': 'Error',
                    'info': str(e)[:50]
                })
        
        return packets_index


@celery_app.task(bind=True, name='analyze_pcap')
def analyze_pcap_task(self, task_id: str, pcap_path: str, filename: str = ""):
    """
    Tâche Celery pour l'analyse asynchrone d'un fichier PCAP
    
    Args:
        task_id: Identifiant unique de la tâche
        pcap_path: Chemin vers le fichier PCAP
        filename: Nom original du fichier
    """
    logger.info("celery_task_started", task_id=task_id, file=pcap_path)
    
    try:
        # Mise à jour du statut
        self.update_state(state='PROGRESS', meta={'status': 'Chargement du fichier...', 'progress': 10})
        
        # Validation
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            raise FileNotFoundError(f"Fichier non trouvé: {pcap_path}")
        
        if not storage_service.validate_pcap_file(pcap_path):
            raise ValueError("Fichier PCAP invalide")
        
        # Analyse
        self.update_state(state='PROGRESS', meta={'status': 'Analyse en cours...', 'progress': 30})
        
        service = PCAPAnalysisService()
        results = service.analyze(pcap_path, filename)
        results['metadata']['task_id'] = task_id
        results['metadata']['filename'] = filename
        
        # Sauvegarde des résultats
        self.update_state(state='PROGRESS', meta={'status': 'Sauvegarde des résultats...', 'progress': 90})
        storage_service.save_results(task_id, results)
        
        logger.info("celery_task_completed", task_id=task_id)
        
        return {
            'status': 'completed',
            'task_id': task_id,
            'summary': {
                'total_packets': results.get('protocol_analysis', {}).get('summary', {}).get('total_packets', 0),
                'anomalies': (results.get('anomaly_detection') or results.get('anomaly_analysis') or {}).get('summary', {}).get('total_anomalies', 0),
                'risk_level': (results.get('anomaly_detection') or results.get('anomaly_analysis') or {}).get('summary', {}).get('risk_level', 'NONE')
            }
        }
        
    except Exception as e:
        logger.error("celery_task_failed", task_id=task_id, error=str(e))
        self.update_state(state='FAILURE', meta={'status': 'Erreur', 'error': str(e)})
        raise
