"""
Analyseur de protocoles réseau
Analyse: Ethernet, IPv4, IPv6, TCP, UDP, ICMP
Génère des statistiques détaillées par protocole
"""

from typing import Dict, Any, List
from collections import defaultdict
from scapy.all import Packet, Ether, IP, IPv6, TCP, UDP, ICMP, ARP
from .base import BaseAnalyzer
from app.core.logging_config import get_logger
from app.core.mac_vendor import (
    normalize_mac_address,
    resolve_mac_vendor,
    classify_mac_address,
    is_broadcast_mac,
    is_multicast_mac,
    is_locally_administered_mac,
)

logger = get_logger(__name__)


class ProtocolAnalyzer(BaseAnalyzer):
    """Analyseur de protocoles réseau (couches 2-4)"""
    
    def __init__(self):
        super().__init__()
        self.protocol_stats = defaultdict(lambda: {'count': 0, 'bytes': 0})
        self.ip_stats = {
            'sources': defaultdict(lambda: {'count': 0, 'bytes': 0}),
            'destinations': defaultdict(lambda: {'count': 0, 'bytes': 0}),
            'conversations': defaultdict(lambda: {'count': 0, 'bytes': 0})
        }
        self.ethernet_stats = defaultdict(int)
        self.mac_stats = {
            'sources': defaultdict(int),
            'destinations': defaultdict(int),
            'total': defaultdict(int),
        }
        self.mac_conversations = defaultdict(int)
        self.tcp_flags_distribution = defaultdict(int)
        self.port_stats = {
            'src_ports': defaultdict(int),
            'dst_ports': defaultdict(int)
        }
        self.icmp_types = defaultdict(int)
    
    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """Analyse les paquets et extrait les statistiques protocolaires"""
        logger.info("protocol_analysis_started", packet_count=len(packets))
        
        total_bytes = 0
        timestamps = []
        
        for pkt in packets:
            pkt_len = len(pkt)
            total_bytes += pkt_len
            timestamps.append(self.get_packet_timestamp(pkt))
            
            # Analyse Ethernet (couche 2)
            self._analyze_ethernet(pkt)
            
            # Analyse IP (couche 3)
            self._analyze_ip(pkt, pkt_len)
            
            # Analyse Transport (couche 4)
            self._analyze_transport(pkt, pkt_len)
        
        # Calcul de la durée de capture
        duration = 0
        if timestamps:
            duration = max(timestamps) - min(timestamps)
        
        # Compilation des résultats
        self.results = {
            'summary': {
                'total_packets': len(packets),
                'total_bytes': total_bytes,
                'total_bytes_formatted': self.format_bytes(total_bytes),
                'capture_duration_seconds': round(duration, 3),
                'packets_per_second': round(len(packets) / duration, 2) if duration > 0 else 0,
                'bytes_per_second': round(total_bytes / duration, 2) if duration > 0 else 0,
                'first_packet_time': min(timestamps) if timestamps else 0,
                'last_packet_time': max(timestamps) if timestamps else 0
            },
            'protocols': self._compile_protocol_stats(),
            'ip_statistics': self._compile_ip_stats(),
            'ethernet': dict(self.ethernet_stats),
            'mac_statistics': self._compile_mac_stats(),
            'tcp_flags': dict(self.tcp_flags_distribution),
            'ports': self._compile_port_stats(),
            'icmp_types': dict(self.icmp_types)
        }
        
        logger.info("protocol_analysis_completed", 
                   total_packets=len(packets),
                   total_bytes=total_bytes)
        
        return self.results
    
    def _analyze_ethernet(self, pkt: Packet):
        """Analyse la couche Ethernet"""
        if pkt.haslayer(Ether):
            ether = pkt[Ether]
            self.protocol_stats['Ethernet']['count'] += 1
            self.protocol_stats['Ethernet']['bytes'] += len(pkt)
            
            # Type Ethernet
            eth_type = hex(ether.type) if ether.type else 'Unknown'
            self.ethernet_stats[eth_type] += 1

            src_mac = normalize_mac_address(getattr(ether, 'src', ''))
            dst_mac = normalize_mac_address(getattr(ether, 'dst', ''))

            if src_mac:
                self.mac_stats['sources'][src_mac] += 1
                self.mac_stats['total'][src_mac] += 1
            if dst_mac:
                self.mac_stats['destinations'][dst_mac] += 1
                self.mac_stats['total'][dst_mac] += 1
            if src_mac and dst_mac:
                pair = tuple(sorted((src_mac, dst_mac)))
                self.mac_conversations[pair] += 1
            
            # ARP
            if pkt.haslayer(ARP):
                self.protocol_stats['ARP']['count'] += 1
                self.protocol_stats['ARP']['bytes'] += len(pkt)
    
    def _analyze_ip(self, pkt: Packet, pkt_len: int):
        """Analyse la couche IP (IPv4 et IPv6)"""
        src_ip, dst_ip = None, None
        
        if pkt.haslayer(IP):
            ip = pkt[IP]
            src_ip, dst_ip = ip.src, ip.dst
            self.protocol_stats['IPv4']['count'] += 1
            self.protocol_stats['IPv4']['bytes'] += pkt_len
            
        elif pkt.haslayer(IPv6):
            ip = pkt[IPv6]
            src_ip, dst_ip = ip.src, ip.dst
            self.protocol_stats['IPv6']['count'] += 1
            self.protocol_stats['IPv6']['bytes'] += pkt_len
        
        if src_ip and dst_ip:
            # Statistiques par IP
            self.ip_stats['sources'][src_ip]['count'] += 1
            self.ip_stats['sources'][src_ip]['bytes'] += pkt_len
            self.ip_stats['destinations'][dst_ip]['count'] += 1
            self.ip_stats['destinations'][dst_ip]['bytes'] += pkt_len
            
            # Conversations
            conv_key = tuple(sorted([src_ip, dst_ip]))
            self.ip_stats['conversations'][conv_key]['count'] += 1
            self.ip_stats['conversations'][conv_key]['bytes'] += pkt_len
    
    def _analyze_transport(self, pkt: Packet, pkt_len: int):
        """Analyse la couche Transport (TCP, UDP, ICMP)"""
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            self.protocol_stats['TCP']['count'] += 1
            self.protocol_stats['TCP']['bytes'] += pkt_len
            
            # Flags TCP
            flags = tcp.flags
            if flags.S: self.tcp_flags_distribution['SYN'] += 1
            if flags.A: self.tcp_flags_distribution['ACK'] += 1
            if flags.F: self.tcp_flags_distribution['FIN'] += 1
            if flags.R: self.tcp_flags_distribution['RST'] += 1
            if flags.P: self.tcp_flags_distribution['PSH'] += 1
            if flags.U: self.tcp_flags_distribution['URG'] += 1
            
            # Ports
            self.port_stats['src_ports'][tcp.sport] += 1
            self.port_stats['dst_ports'][tcp.dport] += 1
            
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            self.protocol_stats['UDP']['count'] += 1
            self.protocol_stats['UDP']['bytes'] += pkt_len
            
            # Ports
            self.port_stats['src_ports'][udp.sport] += 1
            self.port_stats['dst_ports'][udp.dport] += 1
            
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            self.protocol_stats['ICMP']['count'] += 1
            self.protocol_stats['ICMP']['bytes'] += pkt_len
            
            # Type ICMP
            icmp_type_name = self._get_icmp_type_name(icmp.type)
            self.icmp_types[icmp_type_name] += 1
    
    def _get_icmp_type_name(self, icmp_type: int) -> str:
        """Convertit le type ICMP en nom lisible"""
        icmp_types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            4: 'Source Quench',
            5: 'Redirect',
            8: 'Echo Request',
            11: 'Time Exceeded',
            12: 'Parameter Problem',
            13: 'Timestamp',
            14: 'Timestamp Reply'
        }
        return icmp_types.get(icmp_type, f'Type {icmp_type}')
    
    def _compile_protocol_stats(self) -> Dict:
        """Compile les statistiques de protocoles"""
        return {
            proto: {
                'count': stats['count'],
                'bytes': stats['bytes'],
                'bytes_formatted': self.format_bytes(stats['bytes']),
                'percentage': 0  # Sera calculé plus tard
            }
            for proto, stats in self.protocol_stats.items()
        }
    
    def _compile_ip_stats(self) -> Dict:
        """Compile les statistiques IP (top 20)"""
        return {
            'top_sources': self._get_top_ips(self.ip_stats['sources'], 20),
            'top_destinations': self._get_top_ips(self.ip_stats['destinations'], 20),
            'top_conversations': self._get_top_conversations(20),
            'unique_sources': len(self.ip_stats['sources']),
            'unique_destinations': len(self.ip_stats['destinations'])
        }
    
    def _get_top_ips(self, ip_dict: Dict, limit: int) -> List[Dict]:
        """Retourne les top IPs par nombre de paquets"""
        sorted_ips = sorted(ip_dict.items(), key=lambda x: x[1]['count'], reverse=True)
        return [
            {'ip': ip, 'count': stats['count'], 'bytes': stats['bytes']}
            for ip, stats in sorted_ips[:limit]
        ]
    
    def _get_top_conversations(self, limit: int) -> List[Dict]:
        """Retourne les top conversations"""
        sorted_convs = sorted(
            self.ip_stats['conversations'].items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )
        return [
            {
                'ip_a': conv[0],
                'ip_b': conv[1],
                'count': stats['count'],
                'bytes': stats['bytes']
            }
            for (conv, stats) in sorted_convs[:limit]
        ]
    
    def _compile_port_stats(self) -> Dict:
        """Compile les statistiques de ports (top 20)"""
        def get_top_ports(port_dict, limit):
            sorted_ports = sorted(port_dict.items(), key=lambda x: x[1], reverse=True)
            return [
                {'port': port, 'count': count, 'service': self._get_service_name(port)}
                for port, count in sorted_ports[:limit]
            ]
        
        return {
            'top_src_ports': get_top_ports(self.port_stats['src_ports'], 20),
            'top_dst_ports': get_top_ports(self.port_stats['dst_ports'], 20)
        }

    def _compile_mac_stats(self, limit: int = 20) -> Dict[str, Any]:
        """Compile les statistiques MAC et constructeurs."""
        totals = self.mac_stats['total']
        if not totals:
            return {
                'unique_macs': 0,
                'broadcast_packets': 0,
                'multicast_packets': 0,
                'locally_administered_packets': 0,
                'top_macs': [],
                'top_vendors': [],
                'top_pairs': [],
            }

        sorted_macs = sorted(totals.items(), key=lambda x: x[1], reverse=True)
        vendor_buckets: Dict[str, Dict[str, Any]] = defaultdict(lambda: {'count': 0, 'macs': set()})

        for mac, count in totals.items():
            vendor = resolve_mac_vendor(mac)
            vendor_buckets[vendor]['count'] += count
            vendor_buckets[vendor]['macs'].add(mac)

        type_label = {
            'broadcast': 'Broadcast',
            'multicast': 'Multicast',
            'local-admin': 'Local Admin',
            'unicast': 'Unicast',
            'unknown': 'Inconnu',
        }

        top_macs = []
        for mac, count in sorted_macs[:limit]:
            src_count = int(self.mac_stats['sources'].get(mac, 0))
            dst_count = int(self.mac_stats['destinations'].get(mac, 0))
            role = (
                'Source'
                if src_count > dst_count
                else 'Destination'
                if dst_count > src_count
                else 'Bidirectionnel'
            )
            top_macs.append({
                'mac': mac,
                'vendor': resolve_mac_vendor(mac),
                'count': int(count),
                'src_count': src_count,
                'dst_count': dst_count,
                'role': role,
                'mac_type': type_label.get(classify_mac_address(mac), 'Inconnu'),
            })

        top_vendors = sorted(
            (
                {
                    'vendor': vendor,
                    'count': data['count'],
                    'unique_macs': len(data['macs']),
                }
                for vendor, data in vendor_buckets.items()
            ),
            key=lambda x: x['count'],
            reverse=True,
        )[:limit]

        top_pairs = []
        for (mac_a, mac_b), count in sorted(self.mac_conversations.items(), key=lambda x: x[1], reverse=True)[:limit]:
            top_pairs.append({
                'mac_a': mac_a,
                'vendor_a': resolve_mac_vendor(mac_a),
                'mac_b': mac_b,
                'vendor_b': resolve_mac_vendor(mac_b),
                'count': int(count),
            })

        broadcast_packets = int(totals.get('FF:FF:FF:FF:FF:FF', 0))
        multicast_packets = sum(
            int(count)
            for mac, count in totals.items()
            if is_multicast_mac(mac) and not is_broadcast_mac(mac)
        )
        locally_admin_packets = sum(
            int(count) for mac, count in totals.items() if is_locally_administered_mac(mac)
        )

        return {
            'unique_macs': len(totals),
            'broadcast_packets': broadcast_packets,
            'multicast_packets': multicast_packets,
            'locally_administered_packets': locally_admin_packets,
            'top_macs': top_macs,
            'top_vendors': top_vendors,
            'top_pairs': top_pairs,
        }
    
    def _get_service_name(self, port: int) -> str:
        """Retourne le nom du service commun pour un port"""
        services = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
            25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
            80: 'HTTP', 110: 'POP3', 123: 'NTP', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        return services.get(port, '')
