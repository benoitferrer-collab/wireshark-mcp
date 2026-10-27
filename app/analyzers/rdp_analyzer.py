"""
RDP (Remote Desktop Protocol) Analyzer
Analyzes RDP traffic for connections, authentication, and security threats
Detects: Brute force, BlueKeep indicators, unauthorized access patterns
"""

from typing import Dict, Any, List, Optional
from collections import defaultdict
from datetime import datetime
import struct

from scapy.all import Packet, TCP, Raw
from app.analyzers.base import BaseAnalyzer
from app.core.logging_config import get_logger

logger = get_logger(__name__)


def _iso(ts: float) -> str:
    """Format a raw float timestamp to ISO string (called once at result compilation)"""
    return datetime.fromtimestamp(ts).isoformat()


# RDP Ports
RDP_PORTS = {3389, 3388}  # Standard RDP and alternate

# RDP Protocol Data Unit (PDU) Types
RDP_PDU_TYPES = {
    0x01: "TPKT",
    0x03: "X224_CONN_REQ",
    0x0D: "X224_CONN_CONFIRM",
    0x0F: "X224_DATA",
}

# RDP Negotiation Protocols
RDP_PROTOCOLS = {
    0x00: "PROTOCOL_RDP",
    0x01: "PROTOCOL_SSL",
    0x02: "PROTOCOL_HYBRID",
    0x08: "PROTOCOL_HYBRID_EX",
}

# RDP Security Protocols
RDP_SECURITY = {
    0x00: "ENCRYPTION_LEVEL_NONE",
    0x01: "ENCRYPTION_LEVEL_LOW",
    0x02: "ENCRYPTION_LEVEL_CLIENT_COMPATIBLE",
    0x03: "ENCRYPTION_LEVEL_HIGH",
    0x04: "ENCRYPTION_LEVEL_FIPS",
}


class RDPAnalyzer(BaseAnalyzer):
    """Analyzer for RDP protocol traffic"""

    def __init__(self):
        super().__init__()
        self.connections: Dict[str, Dict] = {}
        self.connection_attempts: List[Dict] = []
        self.handshakes: List[Dict] = []
        self.sessions: Dict[str, Dict] = {}
        self.protocols_used: Dict[str, int] = defaultdict(int)
        self.security_levels: Dict[str, int] = defaultdict(int)
        self.anomalies: List[Dict] = []
        self.failed_attempts: Dict[str, List] = defaultdict(list)

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """Analyze RDP traffic"""
        self.reset()
        logger.info("rdp_analysis_started", packet_count=len(packets))
        
        rdp_packets = []
        for idx, packet in enumerate(packets):
            if self._is_rdp_packet(packet):
                rdp_packets.append((idx, packet))
                self._process_rdp_packet(idx, packet)
        
        # Analyze patterns and detect anomalies
        self._detect_anomalies()
        
        # Calculate session statistics
        successful_sessions = sum(1 for s in self.sessions.values() if s.get("established"))

        # Format float timestamps to ISO once, only for records included in results
        connections = list(self.connections.values())[:100]
        for conn in connections:
            conn["first_seen"] = _iso(conn["first_seen"])
            conn["last_seen"] = _iso(conn["last_seen"])

        connection_attempts = self.connection_attempts[:200]
        for attempt in connection_attempts:
            attempt["timestamp"] = _iso(attempt["timestamp"])

        handshakes = self.handshakes[:100]
        for handshake in handshakes:
            handshake["timestamp"] = _iso(handshake["timestamp"])

        sessions = list(self.sessions.values())[:100]
        for session in sessions:
            session["first_data"] = _iso(session["first_data"])
            session["last_activity"] = _iso(session["last_activity"])

        self.results = {
            "summary": {
                "total_packets": len(rdp_packets),
                "total_connections": len(self.connections),
                "total_connection_attempts": len(self.connection_attempts),
                "total_sessions": len(self.sessions),
                "successful_sessions": successful_sessions,
                "total_anomalies": len(self.anomalies),
            },
            "connections": connections,
            "connection_attempts": connection_attempts,
            "handshakes": handshakes,
            "sessions": sessions,
            "protocols_used": dict(self.protocols_used),
            "security_levels": dict(self.security_levels),
            "anomalies": self.anomalies,
        }
        
        logger.info("rdp_analysis_completed",
                   packets=len(rdp_packets),
                   connections=len(self.connections),
                   sessions=len(self.sessions))
        return self.results

    def reset(self):
        """Reset analyzer state"""
        super().reset()
        self.connections = {}
        self.connection_attempts = []
        self.handshakes = []
        self.sessions = {}
        self.protocols_used = defaultdict(int)
        self.security_levels = defaultdict(int)
        self.anomalies = []
        self.failed_attempts = defaultdict(list)

    def _is_rdp_packet(self, packet: Packet) -> bool:
        """Check if packet is RDP traffic"""
        if not packet.haslayer(TCP):
            return False
        tcp = packet[TCP]
        return tcp.sport in RDP_PORTS or tcp.dport in RDP_PORTS

    def _process_rdp_packet(self, idx: int, packet: Packet) -> None:
        """Process individual RDP packet"""
        try:
            tcp = packet[TCP]
            timestamp = self.get_packet_timestamp(packet)
            src_ip, dst_ip = self.get_ip_pair(packet)
            src_port, dst_port = tcp.sport, tcp.dport
            
            # Determine direction
            is_to_server = dst_port in RDP_PORTS
            server_ip = dst_ip if is_to_server else src_ip
            client_ip = src_ip if is_to_server else dst_ip
            
            conn_key = f"{client_ip}:{server_ip}"
            
            # Track connection
            if conn_key not in self.connections:
                self.connections[conn_key] = {
                    "client_ip": client_ip,
                    "server_ip": server_ip,
                    "server_port": dst_port if is_to_server else src_port,
                    "first_seen": timestamp,  # raw float, formatted to ISO at compile time
                    "last_seen": timestamp,
                    "packet_count": 0,
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "state": "connecting",
                    "protocol": None,
                    "security_level": None,
                }
            
            conn = self.connections[conn_key]
            conn["last_seen"] = timestamp
            conn["packet_count"] += 1
            
            # Track data volume
            pkt_len = len(packet)
            if is_to_server:
                conn["bytes_sent"] += pkt_len
            else:
                conn["bytes_received"] += pkt_len
            
            # Analyze TCP flags
            self._analyze_tcp_state(tcp, conn, idx, timestamp, client_ip, server_ip)
            
            # Parse RDP payload if present
            if packet.haslayer(Raw):
                raw_data = bytes(packet[Raw].load)
                self._parse_rdp_payload(idx, raw_data, timestamp, client_ip, server_ip, 
                                       conn, is_to_server)
                
        except Exception as e:
            logger.debug(f"Error processing RDP packet: {e}")

    def _analyze_tcp_state(self, tcp, conn: Dict, idx: int, timestamp: float,
                          client_ip: str, server_ip: str) -> None:
        """Analyze TCP state for RDP connection"""
        flags = tcp.flags
        
        # SYN - Connection initiation
        if flags & 0x02 and not (flags & 0x10):  # SYN without ACK
            conn["state"] = "syn_sent"
            self.connection_attempts.append({
                "packet_idx": idx,
                "timestamp": timestamp,  # raw float, formatted to ISO at compile time
                "client_ip": client_ip,
                "server_ip": server_ip,
                "type": "connection_attempt",
            })
        
        # SYN-ACK
        elif flags & 0x12:  # SYN+ACK
            conn["state"] = "syn_received"
        
        # ACK after SYN-ACK completes handshake
        elif flags & 0x10 and conn.get("state") == "syn_received":
            conn["state"] = "established"
        
        # RST - Connection rejected/reset
        elif flags & 0x04:
            if conn.get("state") != "established":
                conn["state"] = "rejected"
                self.failed_attempts[client_ip].append({
                    "timestamp": timestamp,  # raw float, formatted to ISO at compile time
                    "server_ip": server_ip,
                    "reason": "connection_reset",
                })
        
        # FIN - Connection closing
        elif flags & 0x01:
            conn["state"] = "closing"

    def _parse_rdp_payload(self, idx: int, data: bytes, timestamp: float,
                          client_ip: str, server_ip: str, conn: Dict,
                          is_to_server: bool) -> None:
        """Parse RDP protocol payload"""
        try:
            if len(data) < 4:
                return
            
            # Check for TPKT header (version 3)
            if data[0] == 0x03:
                self._parse_tpkt(idx, data, timestamp, client_ip, server_ip, 
                               conn, is_to_server)
            
            # Check for Fast-Path Input/Output
            elif data[0] & 0x03 == 0x00:
                self._parse_fastpath(idx, data, timestamp, conn)
                
        except Exception as e:
            logger.debug(f"Error parsing RDP payload: {e}")

    def _parse_tpkt(self, idx: int, data: bytes, timestamp: float,
                   client_ip: str, server_ip: str, conn: Dict,
                   is_to_server: bool) -> None:
        """Parse TPKT/X.224 layer"""
        try:
            if len(data) < 7:
                return
            
            # TPKT header: version (1) + reserved (1) + length (2)
            tpkt_length = struct.unpack('>H', data[2:4])[0]
            
            # X.224 header starts at offset 4
            x224_length = data[4]
            x224_type = data[5]
            
            # Connection Request (CR)
            if x224_type == 0xE0:
                self._parse_connection_request(idx, data, timestamp, client_ip, 
                                              server_ip, conn)
            
            # Connection Confirm (CC)
            elif x224_type == 0xD0:
                self._parse_connection_confirm(idx, data, timestamp, conn)
            
            # Data (DT)
            elif x224_type == 0xF0:
                self._parse_rdp_data(idx, data, timestamp, conn, is_to_server)
                
        except Exception as e:
            logger.debug(f"Error parsing TPKT: {e}")

    def _parse_connection_request(self, idx: int, data: bytes, timestamp: float,
                                  client_ip: str, server_ip: str, conn: Dict) -> None:
        """Parse RDP Connection Request"""
        handshake = {
            "packet_idx": idx,
            "timestamp": timestamp,  # raw float, formatted to ISO at compile time
            "client_ip": client_ip,
            "server_ip": server_ip,
            "type": "connection_request",
            "cookie": None,
            "requested_protocols": [],
        }
        
        try:
            # Look for RDP cookie ("Cookie: mstshash=")
            cookie_start = data.find(b'Cookie: mstshash=')
            if cookie_start != -1:
                cookie_end = data.find(b'\r\n', cookie_start)
                if cookie_end != -1:
                    cookie = data[cookie_start + 17:cookie_end].decode('utf-8', errors='ignore')
                    handshake["cookie"] = cookie
                    # Cookie often contains username
                    if cookie:
                        conn["username_hint"] = cookie
            
            # Look for RDP Negotiation Request
            # Starts with 0x01 (TYPE_RDP_NEG_REQ)
            neg_req_offset = data.find(b'\x01\x00')
            if neg_req_offset != -1 and neg_req_offset + 8 <= len(data):
                flags = data[neg_req_offset + 1]
                req_protocols = struct.unpack('<I', data[neg_req_offset + 4:neg_req_offset + 8])[0]
                
                protocols = []
                if req_protocols & 0x01:
                    protocols.append("TLS")
                    self.protocols_used["TLS"] += 1
                if req_protocols & 0x02:
                    protocols.append("CredSSP")
                    self.protocols_used["CredSSP"] += 1
                if req_protocols & 0x08:
                    protocols.append("CredSSP_Early")
                    self.protocols_used["CredSSP_Early"] += 1
                if not protocols:
                    protocols.append("Standard_RDP")
                    self.protocols_used["Standard_RDP"] += 1
                
                handshake["requested_protocols"] = protocols
                conn["requested_protocols"] = protocols
                
        except Exception as e:
            logger.debug(f"Error parsing connection request: {e}")
        
        self.handshakes.append(handshake)

    def _parse_connection_confirm(self, idx: int, data: bytes, timestamp: float,
                                 conn: Dict) -> None:
        """Parse RDP Connection Confirm"""
        try:
            # Look for RDP Negotiation Response
            neg_resp_offset = data.find(b'\x02\x00')  # TYPE_RDP_NEG_RSP
            if neg_resp_offset != -1 and neg_resp_offset + 8 <= len(data):
                selected_protocol = struct.unpack('<I', data[neg_resp_offset + 4:neg_resp_offset + 8])[0]
                
                if selected_protocol == 0x00:
                    conn["protocol"] = "Standard_RDP"
                elif selected_protocol == 0x01:
                    conn["protocol"] = "TLS"
                elif selected_protocol == 0x02:
                    conn["protocol"] = "CredSSP"
                elif selected_protocol == 0x08:
                    conn["protocol"] = "CredSSP_Early"
                
                conn["state"] = "negotiated"
            
            # Check for Negotiation Failure
            neg_fail_offset = data.find(b'\x03\x00')  # TYPE_RDP_NEG_FAILURE
            if neg_fail_offset != -1:
                conn["state"] = "negotiation_failed"
                
        except Exception as e:
            logger.debug(f"Error parsing connection confirm: {e}")

    def _parse_rdp_data(self, idx: int, data: bytes, timestamp: float,
                       conn: Dict, is_to_server: bool) -> None:
        """Parse RDP data PDU"""
        try:
            # Update session tracking
            session_key = f"{conn.get('client_ip')}:{conn.get('server_ip')}"
            
            if session_key not in self.sessions:
                self.sessions[session_key] = {
                    "client_ip": conn.get("client_ip"),
                    "server_ip": conn.get("server_ip"),
                    "protocol": conn.get("protocol"),
                    "established": True,
                    "first_data": timestamp,  # raw float, formatted to ISO at compile time
                    "last_activity": timestamp,
                    "data_packets": 0,
                }
            
            session = self.sessions[session_key]
            session["last_activity"] = timestamp
            session["data_packets"] += 1
            
            # Look for MCS/GCC data structures
            self._analyze_mcs_data(data, conn)
            
        except Exception as e:
            logger.debug(f"Error parsing RDP data: {e}")

    def _analyze_mcs_data(self, data: bytes, conn: Dict) -> None:
        """Analyze MCS channel data for encryption info"""
        try:
            # Look for Server Security Data (SC_SECURITY)
            # Contains encryption level info
            sec_offset = data.find(b'\x02\x0c')  # SC_SECURITY header
            if sec_offset != -1 and sec_offset + 8 <= len(data):
                enc_method = struct.unpack('<I', data[sec_offset + 4:sec_offset + 8])[0]
                
                if enc_method == 0x00:
                    conn["security_level"] = "NONE"
                    self.security_levels["NONE"] += 1
                elif enc_method == 0x01:
                    conn["security_level"] = "40-bit"
                    self.security_levels["40-bit"] += 1
                elif enc_method == 0x02:
                    conn["security_level"] = "128-bit"
                    self.security_levels["128-bit"] += 1
                elif enc_method == 0x08:
                    conn["security_level"] = "56-bit"
                    self.security_levels["56-bit"] += 1
                elif enc_method == 0x10:
                    conn["security_level"] = "FIPS"
                    self.security_levels["FIPS"] += 1
                    
        except Exception:
            pass

    def _parse_fastpath(self, idx: int, data: bytes, timestamp: float,
                       conn: Dict) -> None:
        """Parse Fast-Path data (keyboard/mouse input or screen updates)"""
        # Fast-Path is used for performance-critical data
        # Just track that session is active
        session_key = f"{conn.get('client_ip')}:{conn.get('server_ip')}"
        if session_key in self.sessions:
            self.sessions[session_key]["last_activity"] = timestamp

    def _detect_anomalies(self) -> None:
        """Detect RDP security anomalies"""
        self._detect_brute_force()
        self._detect_bluekeep_indicators()
        self._detect_weak_security()
        self._detect_scanning()
        self._detect_unusual_patterns()

    def _detect_brute_force(self) -> None:
        """Detect RDP brute force attempts"""
        for client_ip, failures in self.failed_attempts.items():
            if len(failures) > 10:
                targets = set(f.get("server_ip") for f in failures)
                self.anomalies.append({
                    "type": "RDP Brute Force",
                    "severity": "high",
                    "description": f"Multiple failed RDP connections ({len(failures)}) from {client_ip}",
                    "src_ip": client_ip,
                    "targets": list(targets)[:10],
                    "failed_attempts": len(failures),
                    "recommendation": "Block source IP and enable NLA",
                })
        
        # Check connection attempt frequency per target
        attempts_by_target = defaultdict(list)
        for attempt in self.connection_attempts:
            attempts_by_target[attempt.get("server_ip")].append(attempt)
        
        for server_ip, attempts in attempts_by_target.items():
            unique_sources = set(a.get("client_ip") for a in attempts)
            if len(attempts) > 50 or len(unique_sources) > 10:
                self.anomalies.append({
                    "type": "RDP Attack Target",
                    "severity": "high",
                    "description": f"High connection attempts ({len(attempts)}) to {server_ip}",
                    "target": server_ip,
                    "attempt_count": len(attempts),
                    "unique_sources": len(unique_sources),
                    "sources_sample": list(unique_sources)[:10],
                    "recommendation": "Review firewall rules and enable account lockout",
                })

    def _detect_bluekeep_indicators(self) -> None:
        """Detect potential BlueKeep (CVE-2019-0708) exploitation indicators"""
        for conn_key, conn in self.connections.items():
            # BlueKeep targets pre-NLA RDP
            if conn.get("protocol") == "Standard_RDP":
                # Check for suspicious patterns
                if conn.get("packet_count", 0) > 100 and conn.get("state") == "established":
                    # High packet count without proper session could indicate exploit
                    session_key = f"{conn.get('client_ip')}:{conn.get('server_ip')}"
                    if session_key not in self.sessions:
                        self.anomalies.append({
                            "type": "Potential BlueKeep Indicator",
                            "severity": "critical",
                            "description": "Standard RDP with high packet count but no established session",
                            "client_ip": conn.get("client_ip"),
                            "server_ip": conn.get("server_ip"),
                            "packet_count": conn.get("packet_count"),
                            "cve": "CVE-2019-0708",
                            "recommendation": "Ensure systems are patched and NLA is enabled",
                        })

    def _detect_weak_security(self) -> None:
        """Detect weak RDP security configurations"""
        weak_security_count = self.security_levels.get("NONE", 0) + \
                             self.security_levels.get("40-bit", 0) + \
                             self.security_levels.get("56-bit", 0)
        
        if weak_security_count > 0:
            weak_connections = []
            for conn_key, conn in self.connections.items():
                if conn.get("security_level") in ["NONE", "40-bit", "56-bit"]:
                    weak_connections.append({
                        "client_ip": conn.get("client_ip"),
                        "server_ip": conn.get("server_ip"),
                        "level": conn.get("security_level"),
                    })
            
            self.anomalies.append({
                "type": "Weak RDP Encryption",
                "severity": "medium",
                "description": f"Weak RDP encryption detected in {weak_security_count} connections",
                "weak_connections": weak_connections[:10],
                "recommendation": "Configure minimum encryption level to High or FIPS",
            })
        
        # Check for Standard RDP (no TLS/CredSSP)
        standard_rdp = self.protocols_used.get("Standard_RDP", 0)
        if standard_rdp > 0:
            self.anomalies.append({
                "type": "Unencrypted RDP Protocol",
                "severity": "high",
                "description": f"Standard RDP without TLS/NLA detected ({standard_rdp} connections)",
                "count": standard_rdp,
                "recommendation": "Enable Network Level Authentication (NLA) and TLS",
            })

    def _detect_scanning(self) -> None:
        """Detect RDP port scanning"""
        sources_by_targets = defaultdict(set)
        
        for attempt in self.connection_attempts:
            sources_by_targets[attempt.get("client_ip")].add(attempt.get("server_ip"))
        
        for src_ip, targets in sources_by_targets.items():
            if len(targets) > 5:
                self.anomalies.append({
                    "type": "RDP Port Scan",
                    "severity": "medium",
                    "description": f"RDP scanning detected from {src_ip} to {len(targets)} hosts",
                    "src_ip": src_ip,
                    "target_count": len(targets),
                    "targets_sample": list(targets)[:10],
                    "recommendation": "Block source and investigate for reconnaissance",
                })

    def _detect_unusual_patterns(self) -> None:
        """Detect unusual RDP usage patterns"""
        # Check for sessions at unusual hours (if timestamp parsing available)
        # Check for long-duration sessions
        for session_key, session in self.sessions.items():
            if session.get("data_packets", 0) > 10000:
                self.anomalies.append({
                    "type": "High Volume RDP Session",
                    "severity": "low",
                    "description": f"Unusually high data volume in RDP session",
                    "client_ip": session.get("client_ip"),
                    "server_ip": session.get("server_ip"),
                    "packet_count": session.get("data_packets"),
                    "recommendation": "Review session for data exfiltration",
                })
