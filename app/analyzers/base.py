"""
Classe de base pour tous les analyseurs PCAP
Définit l'interface commune et les méthodes utilitaires
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from scapy.all import Packet, rdpcap
from app.core.logging_config import get_logger

logger = get_logger(__name__)


class BaseAnalyzer(ABC):
    """Classe abstraite de base pour les analyseurs de paquets"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.results: Dict[str, Any] = {}
    
    @abstractmethod
    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """Méthode principale d'analyse à implémenter"""
        pass
    
    def reset(self):
        """Réinitialise les résultats de l'analyseur"""
        self.results = {}
    
    def get_packet_timestamp(self, packet: Packet) -> float:
        """Extrait le timestamp d'un paquet"""
        return float(packet.time) if hasattr(packet, 'time') else 0.0
    
    def get_ip_pair(self, packet: Packet) -> tuple:
        """Extrait la paire IP source/destination"""
        if packet.haslayer('IP'):
            return (packet['IP'].src, packet['IP'].dst)
        elif packet.haslayer('IPv6'):
            return (packet['IPv6'].src, packet['IPv6'].dst)
        return (None, None)
    
    def get_port_pair(self, packet: Packet) -> tuple:
        """Extrait la paire port source/destination"""
        if packet.haslayer('TCP'):
            return (packet['TCP'].sport, packet['TCP'].dport)
        elif packet.haslayer('UDP'):
            return (packet['UDP'].sport, packet['UDP'].dport)
        return (None, None)
    
    def format_bytes(self, size: int) -> str:
        """Formate une taille en bytes vers une représentation lisible"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
