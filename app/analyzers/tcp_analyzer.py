"""
Analyseur TCP approfondi
Analyse des sessions TCP, handshake, retransmissions, RST, RTT, window size
Détection des connexions half-open et problèmes TCP
"""

from typing import Dict, Any, List, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass, field
from scapy.all import Packet, TCP, IP, IPv6
from .base import BaseAnalyzer
from app.core.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class TCPSession:
    """Représentation d'une session TCP"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    
    # État de la session
    state: str = 'INIT'  # INIT, SYN_SENT, SYN_RECEIVED, ESTABLISHED, FIN_WAIT, CLOSED
    
    # Timestamps
    start_time: float = 0
    end_time: float = 0
    syn_time: float = 0
    syn_ack_time: float = 0
    ack_time: float = 0
    
    # Compteurs
    packet_count: int = 0
    bytes_transferred: int = 0
    
    # Flags
    syn_count: int = 0
    syn_ack_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    
    # Retransmissions (basé sur seq numbers)
    retransmissions: int = 0
    seen_seq_numbers: set = field(default_factory=set)
    
    # Window sizes
    window_sizes: List[int] = field(default_factory=list)
    effective_window_sizes: List[int] = field(default_factory=list)
    window_scale_src: Optional[int] = None
    window_scale_dst: Optional[int] = None
    
    # RTT
    rtt_samples: List[float] = field(default_factory=list)
    
    # RST analysis
    rst_by_src: int = 0
    rst_by_dst: int = 0
    rst_timestamps: List[float] = field(default_factory=list)


class TCPAnalyzer(BaseAnalyzer):
    """Analyseur TCP approfondi avec analyse de sessions"""
    
    def __init__(self):
        super().__init__()
        self.sessions: Dict[Tuple, TCPSession] = {}
        self.timeline_events: List[Dict] = []
    
    def _get_session_key(self, src_ip: str, dst_ip: str, 
                         src_port: int, dst_port: int) -> Tuple:
        """Génère une clé unique pour une session TCP (bidirectionnelle)"""
        # Normalisation pour rendre la clé bidirectionnelle
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, src_port, dst_ip, dst_port)
        return (dst_ip, dst_port, src_ip, src_port)
    
    def _get_or_create_session(self, src_ip: str, dst_ip: str,
                                src_port: int, dst_port: int) -> TCPSession:
        """Récupère ou crée une session TCP"""
        key = self._get_session_key(src_ip, dst_ip, src_port, dst_port)
        
        if key not in self.sessions:
            self.sessions[key] = TCPSession(
                src_ip=key[0], dst_ip=key[2],
                src_port=key[1], dst_port=key[3]
            )
        
        return self.sessions[key]
    
    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """Analyse TCP approfondie des paquets"""
        logger.info("tcp_analysis_started", packet_count=len(packets))
        
        tcp_packets = [p for p in packets if p.haslayer(TCP)]
        
        for pkt in tcp_packets:
            self._analyze_tcp_packet(pkt)
        
        # Compilation des résultats
        self.results = {
            'summary': self._compile_summary(tcp_packets),
            'sessions': self._compile_sessions(),
            'handshake_analysis': self._analyze_handshakes(),
            'retransmission_analysis': self._analyze_retransmissions(),
            'rst_analysis': self._analyze_rst(),
            'rtt_analysis': self._analyze_rtt(),
            'window_analysis': self._analyze_windows(),
            'connection_states': self._analyze_connection_states(),
            'timeline': sorted(self.timeline_events, key=lambda x: x['timestamp'])[:1000]  # Limiter
        }
        
        logger.info("tcp_analysis_completed",
                   sessions_count=len(self.sessions),
                   tcp_packets=len(tcp_packets))
        
        return self.results
    
    def _analyze_tcp_packet(self, pkt: Packet):
        """Analyse un paquet TCP individuel"""
        tcp = pkt[TCP]
        timestamp = self.get_packet_timestamp(pkt)
        pkt_len = len(pkt)
        
        # Extraction des IPs
        if pkt.haslayer(IP):
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return
        
        src_port, dst_port = tcp.sport, tcp.dport
        session = self._get_or_create_session(src_ip, dst_ip, src_port, dst_port)
        
        # Mise à jour des compteurs de base
        session.packet_count += 1
        session.bytes_transferred += pkt_len
        
        if session.start_time == 0:
            session.start_time = timestamp
        session.end_time = timestamp
        
        # Analyse des flags
        flags = tcp.flags
        self._analyze_flags(session, flags, timestamp, src_ip, dst_ip)
        
        # Détection des retransmissions (simplifiée)
        seq = tcp.seq
        if seq in session.seen_seq_numbers and pkt_len > 0:
            session.retransmissions += 1
        session.seen_seq_numbers.add(seq)
        
        # Window size tracking
        session.window_sizes.append(tcp.window)
        side = "src" if (src_ip == session.src_ip and src_port == session.src_port) else "dst"
        packet_wscale = self._extract_window_scale(tcp)
        if packet_wscale is not None:
            if side == "src":
                session.window_scale_src = packet_wscale
            else:
                session.window_scale_dst = packet_wscale
        scale_for_packet = session.window_scale_src if side == "src" else session.window_scale_dst
        if isinstance(scale_for_packet, int):
            session.effective_window_sizes.append(int(tcp.window) * (2 ** max(0, min(14, int(scale_for_packet)))))
        
        # Timeline event
        self._add_timeline_event(timestamp, src_ip, dst_ip, src_port, dst_port, flags)

    def _extract_window_scale(self, tcp: TCP) -> Optional[int]:
        """Extrait le facteur de scaling de fenêtre TCP (option WScale) si présent."""
        options = getattr(tcp, "options", None)
        if not isinstance(options, list):
            return None

        for option in options:
            if not isinstance(option, tuple) or len(option) < 2:
                continue
            name, value = option[0], option[1]
            name_norm = str(name).strip().lower()
            if name_norm not in {"wscale", "window scale", "window_scale"}:
                continue
            try:
                scale = int(value)
            except (TypeError, ValueError):
                continue
            return max(0, min(14, scale))

        return None
    
    def _analyze_flags(self, session: TCPSession, flags, timestamp: float,
                       src_ip: str, dst_ip: str):
        """Analyse les flags TCP et met à jour l'état de session"""
        
        # SYN (sans ACK) - Début de connexion
        if flags.S and not flags.A:
            session.syn_count += 1
            if session.state == 'INIT':
                session.state = 'SYN_SENT'
                session.syn_time = timestamp
        
        # SYN+ACK - Réponse du serveur
        elif flags.S and flags.A:
            session.syn_ack_count += 1
            if session.state == 'SYN_SENT':
                session.state = 'SYN_RECEIVED'
                session.syn_ack_time = timestamp
                # Calcul du RTT (SYN -> SYN-ACK)
                if session.syn_time > 0:
                    rtt = timestamp - session.syn_time
                    session.rtt_samples.append(rtt)
        
        # ACK simple (handshake complet ou ACK normal)
        elif flags.A and not flags.S and not flags.F and not flags.R:
            session.ack_count += 1
            if session.state == 'SYN_RECEIVED':
                session.state = 'ESTABLISHED'
                session.ack_time = timestamp
        
        # FIN - Fin de connexion
        if flags.F:
            session.fin_count += 1
            if session.state == 'ESTABLISHED':
                session.state = 'FIN_WAIT'
        
        # RST - Reset
        if flags.R:
            session.rst_count += 1
            session.rst_timestamps.append(timestamp)
            session.state = 'CLOSED'
            
            # Identifier qui envoie le RST
            if src_ip == session.src_ip:
                session.rst_by_src += 1
            else:
                session.rst_by_dst += 1
        
        # PSH - Push
        if flags.P:
            session.psh_count += 1
    
    def _add_timeline_event(self, timestamp: float, src_ip: str, dst_ip: str,
                            src_port: int, dst_port: int, flags):
        """Ajoute un événement à la timeline"""
        flag_str = ''
        if flags.S: flag_str += 'S'
        if flags.A: flag_str += 'A'
        if flags.F: flag_str += 'F'
        if flags.R: flag_str += 'R'
        if flags.P: flag_str += 'P'
        
        # Borne mémoire: seuls les 1000 premiers (triés) sont exposés au final,
        # inutile d'accumuler un événement par paquet TCP sur une grosse capture
        if len(self.timeline_events) < 5000:
            self.timeline_events.append({
                'timestamp': timestamp,
                'src': f"{src_ip}:{src_port}",
                'dst': f"{dst_ip}:{dst_port}",
                'flags': flag_str
            })
    
    def _compile_summary(self, tcp_packets: List[Packet]) -> Dict:
        """Compile le résumé de l'analyse TCP"""
        total_sessions = len(self.sessions)
        established = sum(1 for s in self.sessions.values() if s.state == 'ESTABLISHED')
        half_open = sum(1 for s in self.sessions.values() 
                       if s.state in ['SYN_SENT', 'SYN_RECEIVED'])
        reset = sum(1 for s in self.sessions.values() if s.rst_count > 0)
        
        return {
            'total_tcp_packets': len(tcp_packets),
            'total_sessions': total_sessions,
            'established_sessions': established,
            'half_open_connections': half_open,
            'sessions_with_rst': reset,
            'total_retransmissions': sum(s.retransmissions for s in self.sessions.values())
        }
    
    def _compile_sessions(self) -> List[Dict]:
        """Compile les informations de sessions (top 100)"""
        sessions_list = []
        
        for key, session in self.sessions.items():
            sessions_list.append({
                'src': f"{session.src_ip}:{session.src_port}",
                'dst': f"{session.dst_ip}:{session.dst_port}",
                'state': session.state,
                'packets': session.packet_count,
                'bytes': session.bytes_transferred,
                'duration': round(session.end_time - session.start_time, 3) if session.end_time > session.start_time else 0,
                'retransmissions': session.retransmissions,
                'rst_count': session.rst_count,
                'window_scale': {
                    'src': session.window_scale_src,
                    'dst': session.window_scale_dst,
                    'negotiated': session.window_scale_src is not None or session.window_scale_dst is not None,
                },
                'effective_window_avg': round(sum(session.effective_window_sizes) / len(session.effective_window_sizes), 0)
                    if session.effective_window_sizes else None,
                'flags': {
                    'syn': session.syn_count,
                    'syn_ack': session.syn_ack_count,
                    'ack': session.ack_count,
                    'fin': session.fin_count,
                    'rst': session.rst_count,
                    'psh': session.psh_count
                }
            })
        
        # Trier par nombre de paquets et limiter
        sessions_list.sort(key=lambda x: x['packets'], reverse=True)
        return sessions_list[:100]
    
    def _analyze_handshakes(self) -> Dict:
        """Analyse des handshakes TCP (3-way)"""
        complete = 0
        incomplete = 0
        
        for session in self.sessions.values():
            if session.syn_count > 0 and session.syn_ack_count > 0 and session.ack_count > 0:
                complete += 1
            elif session.syn_count > 0:
                incomplete += 1
        
        return {
            'complete_handshakes': complete,
            'incomplete_handshakes': incomplete,
            'handshake_success_rate': round(complete / (complete + incomplete) * 100, 2) if (complete + incomplete) > 0 else 0
        }
    
    def _analyze_retransmissions(self) -> Dict:
        """Analyse des retransmissions TCP"""
        sessions_with_retrans = [s for s in self.sessions.values() if s.retransmissions > 0]
        
        total_retrans = sum(s.retransmissions for s in self.sessions.values())
        total_packets = sum(s.packet_count for s in self.sessions.values())
        
        return {
            'total_retransmissions': total_retrans,
            'sessions_with_retransmissions': len(sessions_with_retrans),
            'retransmission_rate': round(total_retrans / total_packets * 100, 2) if total_packets > 0 else 0,
            'top_retransmitting_sessions': [
                {
                    'session': f"{s.src_ip}:{s.src_port} <-> {s.dst_ip}:{s.dst_port}",
                    'retransmissions': s.retransmissions,
                    'packets': s.packet_count
                }
                for s in sorted(sessions_with_retrans, key=lambda x: x.retransmissions, reverse=True)[:10]
            ]
        }
    
    def _analyze_rst(self) -> Dict:
        """Analyse des RST TCP"""
        sessions_with_rst = [s for s in self.sessions.values() if s.rst_count > 0]
        
        total_rst = sum(s.rst_count for s in sessions_with_rst)
        rst_by_src = sum(s.rst_by_src for s in sessions_with_rst)
        rst_by_dst = sum(s.rst_by_dst for s in sessions_with_rst)
        
        # Analyse temporelle des RST
        rst_timeline = []
        for s in sessions_with_rst:
            for ts in s.rst_timestamps:
                rst_timeline.append({
                    'timestamp': ts,
                    'session': f"{s.src_ip}:{s.src_port} <-> {s.dst_ip}:{s.dst_port}"
                })
        
        rst_timeline.sort(key=lambda x: x['timestamp'])
        
        return {
            'total_rst_packets': total_rst,
            'sessions_with_rst': len(sessions_with_rst),
            'rst_by_initiator': rst_by_src,
            'rst_by_responder': rst_by_dst,
            'rst_timeline': rst_timeline[:50]  # Limiter
        }
    
    def _analyze_rtt(self) -> Dict:
        """Analyse du RTT (Round-Trip Time)"""
        all_rtt = []
        for session in self.sessions.values():
            all_rtt.extend(session.rtt_samples)
        
        if not all_rtt:
            return {
                'samples_count': 0,
                'min_rtt_ms': 0,
                'max_rtt_ms': 0,
                'avg_rtt_ms': 0
            }
        
        return {
            'samples_count': len(all_rtt),
            'min_rtt_ms': round(min(all_rtt) * 1000, 3),
            'max_rtt_ms': round(max(all_rtt) * 1000, 3),
            'avg_rtt_ms': round(sum(all_rtt) / len(all_rtt) * 1000, 3)
        }
    
    def _analyze_windows(self) -> Dict:
        """Analyse des window sizes TCP"""
        all_windows = []
        all_effective_windows = []
        all_scales = []
        scale_observed_sessions = 0
        scale_observed_directions = 0
        for session in self.sessions.values():
            all_windows.extend(session.window_sizes)
            all_effective_windows.extend(session.effective_window_sizes)
            has_scale = False
            if isinstance(session.window_scale_src, int):
                all_scales.append(session.window_scale_src)
                has_scale = True
                scale_observed_directions += 1
            if isinstance(session.window_scale_dst, int):
                all_scales.append(session.window_scale_dst)
                has_scale = True
                scale_observed_directions += 1
            if has_scale:
                scale_observed_sessions += 1

        if not all_windows:
            return {
                'min_window': 0,
                'max_window': 0,
                'avg_window': 0,
                'zero_window_count': 0,
                'zero_window_percentage': 0,
                'effective_min_window': 0,
                'effective_max_window': 0,
                'effective_avg_window': 0,
                'window_scale_min': 0,
                'window_scale_max': 0,
                'window_scale_avg': 0,
                'window_scale_p95': 0,
                'window_scale_observed_sessions': 0,
                'window_scale_observed_directions': 0,
                'window_scale_coverage_pct': 0,
            }

        zero_windows = sum(1 for w in all_windows if w == 0)
        scale_values = sorted(all_scales)
        p95_scale = 0
        if scale_values:
            idx = int((len(scale_values) - 1) * 0.95)
            p95_scale = scale_values[idx]
        total_sessions = len(self.sessions)

        return {
            'min_window': min(all_windows),
            'max_window': max(all_windows),
            'avg_window': round(sum(all_windows) / len(all_windows), 0),
            'zero_window_count': zero_windows,
            'zero_window_percentage': round(zero_windows / len(all_windows) * 100, 2),
            'effective_min_window': min(all_effective_windows) if all_effective_windows else 0,
            'effective_max_window': max(all_effective_windows) if all_effective_windows else 0,
            'effective_avg_window': round(sum(all_effective_windows) / len(all_effective_windows), 0) if all_effective_windows else 0,
            'window_scale_min': min(scale_values) if scale_values else 0,
            'window_scale_max': max(scale_values) if scale_values else 0,
            'window_scale_avg': round(sum(scale_values) / len(scale_values), 3) if scale_values else 0,
            'window_scale_p95': p95_scale,
            'window_scale_observed_sessions': scale_observed_sessions,
            'window_scale_observed_directions': scale_observed_directions,
            'window_scale_coverage_pct': round((scale_observed_sessions / total_sessions) * 100, 2) if total_sessions > 0 else 0,
        }
    
    def _analyze_connection_states(self) -> Dict:
        """Analyse de la distribution des états de connexion"""
        states = defaultdict(int)
        for session in self.sessions.values():
            states[session.state] += 1
        
        return dict(states)
