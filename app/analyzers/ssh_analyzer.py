"""
SSH Protocol Analyzer
Analyzes SSH traffic for connections, authentication, and security threats
Detects: Brute force, tunneling, weak versions, credential attacks
"""

from typing import Dict, Any, List, Optional
from collections import defaultdict
from datetime import datetime
import re

from scapy.all import Packet, TCP, Raw
from app.analyzers.base import BaseAnalyzer
from app.core.logging_config import get_logger

logger = get_logger(__name__)


def _iso(ts: float) -> str:
    """Format a raw float timestamp to ISO string (called once at result compilation)"""
    return datetime.fromtimestamp(ts).isoformat()


# SSH Ports (standard and common alternatives)
SSH_PORTS = {22, 2222, 222, 8022}

# SSH Message Types
SSH_MSG_TYPES = {
    1: "SSH_MSG_DISCONNECT",
    2: "SSH_MSG_IGNORE",
    3: "SSH_MSG_UNIMPLEMENTED",
    4: "SSH_MSG_DEBUG",
    5: "SSH_MSG_SERVICE_REQUEST",
    6: "SSH_MSG_SERVICE_ACCEPT",
    20: "SSH_MSG_KEXINIT",
    21: "SSH_MSG_NEWKEYS",
    30: "SSH_MSG_KEXDH_INIT",
    31: "SSH_MSG_KEXDH_REPLY",
    50: "SSH_MSG_USERAUTH_REQUEST",
    51: "SSH_MSG_USERAUTH_FAILURE",
    52: "SSH_MSG_USERAUTH_SUCCESS",
    53: "SSH_MSG_USERAUTH_BANNER",
    60: "SSH_MSG_USERAUTH_PK_OK",
    80: "SSH_MSG_GLOBAL_REQUEST",
    81: "SSH_MSG_REQUEST_SUCCESS",
    82: "SSH_MSG_REQUEST_FAILURE",
    90: "SSH_MSG_CHANNEL_OPEN",
    91: "SSH_MSG_CHANNEL_OPEN_CONFIRMATION",
    92: "SSH_MSG_CHANNEL_OPEN_FAILURE",
    93: "SSH_MSG_CHANNEL_WINDOW_ADJUST",
    94: "SSH_MSG_CHANNEL_DATA",
    95: "SSH_MSG_CHANNEL_EXTENDED_DATA",
    96: "SSH_MSG_CHANNEL_EOF",
    97: "SSH_MSG_CHANNEL_CLOSE",
    98: "SSH_MSG_CHANNEL_REQUEST",
    99: "SSH_MSG_CHANNEL_SUCCESS",
    100: "SSH_MSG_CHANNEL_FAILURE",
}

# Weak SSH versions and ciphers
WEAK_SSH_VERSIONS = ['SSH-1.', 'SSH-1.5', 'SSH-1.99']
WEAK_CIPHERS = ['arcfour', 'arcfour128', 'arcfour256', 'blowfish', 
                '3des-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc',
                'cast128-cbc']
WEAK_MACS = ['hmac-md5', 'hmac-md5-96', 'hmac-sha1-96']
WEAK_KEX = ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
            'diffie-hellman-group-exchange-sha1']


class SSHAnalyzer(BaseAnalyzer):
    """Analyzer for SSH protocol traffic"""

    def __init__(self):
        super().__init__()
        self.connections: Dict[str, Dict] = {}
        self.sessions: Dict[str, Dict] = {}
        self.auth_attempts: List[Dict] = []
        self.version_exchanges: List[Dict] = []
        self.tunnels: List[Dict] = []
        self.client_versions: Dict[str, int] = defaultdict(int)
        self.server_versions: Dict[str, int] = defaultdict(int)
        self.ciphers_negotiated: Dict[str, int] = defaultdict(int)
        self.key_exchanges: Dict[str, int] = defaultdict(int)
        self.anomalies: List[Dict] = []
        self.failed_auth: Dict[str, List] = defaultdict(list)

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """Analyze SSH traffic"""
        self.reset()
        logger.info("ssh_analysis_started", packet_count=len(packets))
        
        ssh_packets = []
        for idx, packet in enumerate(packets):
            if self._is_ssh_packet(packet):
                ssh_packets.append((idx, packet))
                self._process_ssh_packet(idx, packet)
        
        # Detect security anomalies
        self._detect_anomalies()
        
        # Calculate statistics
        successful_auth = sum(1 for s in self.sessions.values() if s.get("authenticated"))

        # Format float timestamps to ISO once, only for records included in results
        connections = list(self.connections.values())[:100]
        for conn in connections:
            conn["first_seen"] = _iso(conn["first_seen"])
            conn["last_seen"] = _iso(conn["last_seen"])

        sessions = list(self.sessions.values())[:100]
        for session in sessions:
            session["first_seen"] = _iso(session["first_seen"])
            session["last_seen"] = _iso(session["last_seen"])

        auth_attempts = self.auth_attempts[:200]
        for auth in auth_attempts:
            auth["timestamp"] = _iso(auth["timestamp"])

        version_exchanges = self.version_exchanges[:100]
        for version in version_exchanges:
            version["timestamp"] = _iso(version["timestamp"])

        tunnels = self.tunnels[:50]
        for tunnel in tunnels:
            tunnel["timestamp"] = _iso(tunnel["timestamp"])

        self.results = {
            "summary": {
                "total_packets": len(ssh_packets),
                "total_connections": len(self.connections),
                "total_sessions": len(self.sessions),
                "successful_authentications": successful_auth,
                "total_auth_attempts": len(self.auth_attempts),
                "tunnels_detected": len(self.tunnels),
                "total_anomalies": len(self.anomalies),
            },
            "connections": connections,
            "sessions": sessions,
            "auth_attempts": auth_attempts,
            "version_exchanges": version_exchanges,
            "tunnels": tunnels,
            "client_versions": dict(sorted(self.client_versions.items(), 
                                          key=lambda x: x[1], reverse=True)[:20]),
            "server_versions": dict(sorted(self.server_versions.items(),
                                          key=lambda x: x[1], reverse=True)[:20]),
            "ciphers_negotiated": dict(self.ciphers_negotiated),
            "key_exchanges": dict(self.key_exchanges),
            "anomalies": self.anomalies,
        }
        
        logger.info("ssh_analysis_completed",
                   packets=len(ssh_packets),
                   connections=len(self.connections),
                   sessions=len(self.sessions))
        return self.results

    def reset(self):
        """Reset analyzer state"""
        super().reset()
        self.connections = {}
        self.sessions = {}
        self.auth_attempts = []
        self.version_exchanges = []
        self.tunnels = []
        self.client_versions = defaultdict(int)
        self.server_versions = defaultdict(int)
        self.ciphers_negotiated = defaultdict(int)
        self.key_exchanges = defaultdict(int)
        self.anomalies = []
        self.failed_auth = defaultdict(list)

    def _is_ssh_packet(self, packet: Packet) -> bool:
        """Check if packet is SSH traffic"""
        if not packet.haslayer(TCP):
            return False
        tcp = packet[TCP]
        return tcp.sport in SSH_PORTS or tcp.dport in SSH_PORTS

    def _process_ssh_packet(self, idx: int, packet: Packet) -> None:
        """Process individual SSH packet"""
        try:
            tcp = packet[TCP]
            timestamp = self.get_packet_timestamp(packet)
            src_ip, dst_ip = self.get_ip_pair(packet)
            src_port, dst_port = tcp.sport, tcp.dport
            
            # Determine direction
            is_to_server = dst_port in SSH_PORTS
            server_ip = dst_ip if is_to_server else src_ip
            server_port = dst_port if is_to_server else src_port
            client_ip = src_ip if is_to_server else dst_ip
            client_port = src_port if is_to_server else dst_port
            
            conn_key = f"{client_ip}:{client_port}:{server_ip}:{server_port}"
            
            # Track connection
            if conn_key not in self.connections:
                self.connections[conn_key] = {
                    "client_ip": client_ip,
                    "client_port": client_port,
                    "server_ip": server_ip,
                    "server_port": server_port,
                    "first_seen": timestamp,  # raw float, formatted to ISO at compile time
                    "last_seen": timestamp,
                    "packet_count": 0,
                    "bytes_client": 0,
                    "bytes_server": 0,
                    "state": "connecting",
                    "client_version": None,
                    "server_version": None,
                }
            
            conn = self.connections[conn_key]
            conn["last_seen"] = timestamp
            conn["packet_count"] += 1
            
            # Track data volume
            pkt_len = len(packet)
            if is_to_server:
                conn["bytes_client"] += pkt_len
            else:
                conn["bytes_server"] += pkt_len
            
            # Analyze TCP state
            self._analyze_tcp_state(tcp, conn, client_ip, server_ip, timestamp)
            
            # Parse SSH payload
            if packet.haslayer(Raw):
                raw_data = bytes(packet[Raw].load)
                self._parse_ssh_payload(idx, raw_data, timestamp, conn, 
                                       is_to_server, client_ip, server_ip)
                
        except Exception as e:
            logger.debug(f"Error processing SSH packet: {e}")

    def _analyze_tcp_state(self, tcp, conn: Dict, client_ip: str, 
                          server_ip: str, timestamp: float) -> None:
        """Analyze TCP state for SSH connection"""
        flags = tcp.flags
        
        if flags & 0x02 and not (flags & 0x10):  # SYN
            conn["state"] = "syn_sent"
        elif flags & 0x12:  # SYN-ACK
            conn["state"] = "syn_received"
        elif flags & 0x10 and conn.get("state") == "syn_received":  # ACK
            conn["state"] = "established"
        elif flags & 0x04:  # RST
            if conn.get("state") != "authenticated":
                conn["state"] = "rejected"
                self.failed_auth[client_ip].append({
                    "timestamp": timestamp,  # raw float, formatted to ISO at compile time
                    "server_ip": server_ip,
                    "reason": "connection_reset",
                })
        elif flags & 0x01:  # FIN
            conn["state"] = "closing"

    def _parse_ssh_payload(self, idx: int, data: bytes, timestamp: float,
                          conn: Dict, is_to_server: bool, 
                          client_ip: str, server_ip: str) -> None:
        """Parse SSH protocol payload"""
        try:
            # Check for SSH version string
            if data.startswith(b'SSH-'):
                self._parse_version_string(idx, data, timestamp, conn, 
                                          is_to_server, client_ip, server_ip)
                return
            
            # Encrypted SSH packets have a specific structure
            # packet_length (4 bytes) + padding_length (1 byte) + payload
            if len(data) >= 5:
                self._parse_ssh_packet_data(idx, data, timestamp, conn,
                                           is_to_server, client_ip, server_ip)
                
        except Exception as e:
            logger.debug(f"Error parsing SSH payload: {e}")

    def _parse_version_string(self, idx: int, data: bytes, timestamp: float,
                             conn: Dict, is_to_server: bool,
                             client_ip: str, server_ip: str) -> None:
        """Parse SSH version exchange"""
        try:
            # Extract version string (ends with \r\n or \n)
            version_end = data.find(b'\r\n')
            if version_end == -1:
                version_end = data.find(b'\n')
            if version_end == -1:
                version_end = min(len(data), 255)
            
            version_str = data[:version_end].decode('utf-8', errors='ignore').strip()
            
            version_info = {
                "packet_idx": idx,
                "timestamp": timestamp,  # raw float, formatted to ISO at compile time
                "client_ip": client_ip,
                "server_ip": server_ip,
                "is_client": is_to_server,
                "version_string": version_str,
            }
            
            # Parse version components
            # Format: SSH-protoversion-softwareversion comments
            parts = version_str.split('-', 2)
            if len(parts) >= 2:
                version_info["protocol_version"] = parts[1]
                if len(parts) >= 3:
                    sw_parts = parts[2].split(' ', 1)
                    version_info["software_version"] = sw_parts[0]
                    if len(sw_parts) > 1:
                        version_info["comments"] = sw_parts[1]
            
            if is_to_server:
                conn["client_version"] = version_str
                self.client_versions[version_str] += 1
                version_info["direction"] = "client"
            else:
                conn["server_version"] = version_str
                self.server_versions[version_str] += 1
                version_info["direction"] = "server"
                conn["state"] = "version_exchanged"
            
            self.version_exchanges.append(version_info)
            
        except Exception as e:
            logger.debug(f"Error parsing SSH version: {e}")

    def _parse_ssh_packet_data(self, idx: int, data: bytes, timestamp: float,
                              conn: Dict, is_to_server: bool,
                              client_ip: str, server_ip: str) -> None:
        """Parse SSH binary packet protocol"""
        try:
            if len(data) < 6:
                return
            
            # Before key exchange, packets are unencrypted
            # packet_length (4) + padding_length (1) + msg_type (1)
            import struct
            packet_length = struct.unpack('>I', data[:4])[0]
            
            # Sanity check
            if packet_length > 35000 or packet_length < 1:
                return
            
            padding_length = data[4]
            
            if len(data) > 5:
                msg_type = data[5]
                msg_name = SSH_MSG_TYPES.get(msg_type, f"UNKNOWN_{msg_type}")
                
                # Track session
                session_key = f"{conn.get('client_ip')}:{conn.get('server_ip')}"
                if session_key not in self.sessions:
                    self.sessions[session_key] = {
                        "client_ip": conn.get("client_ip"),
                        "server_ip": conn.get("server_ip"),
                        "server_port": conn.get("server_port"),
                        "client_version": conn.get("client_version"),
                        "server_version": conn.get("server_version"),
                        "first_seen": timestamp,  # raw float, formatted to ISO at compile time
                        "last_seen": timestamp,
                        "authenticated": False,
                        "messages": [],
                        "auth_methods_tried": [],
                        "channels_opened": 0,
                    }
                
                session = self.sessions[session_key]
                session["last_seen"] = timestamp
                
                if msg_name not in session["messages"]:
                    session["messages"].append(msg_name)
                
                # Process specific message types
                if msg_type == 20:  # SSH_MSG_KEXINIT
                    self._parse_kexinit(data[5:], conn)
                elif msg_type == 50:  # SSH_MSG_USERAUTH_REQUEST
                    self._parse_userauth_request(idx, data[5:], timestamp, conn,
                                                client_ip, server_ip, session)
                elif msg_type == 51:  # SSH_MSG_USERAUTH_FAILURE
                    self._record_auth_failure(idx, timestamp, conn, client_ip, 
                                             server_ip, session)
                elif msg_type == 52:  # SSH_MSG_USERAUTH_SUCCESS
                    session["authenticated"] = True
                    conn["state"] = "authenticated"
                elif msg_type == 90:  # SSH_MSG_CHANNEL_OPEN
                    self._parse_channel_open(idx, data[5:], timestamp, conn, 
                                            session, client_ip, server_ip)
                    session["channels_opened"] += 1
                    
        except Exception as e:
            logger.debug(f"Error parsing SSH packet data: {e}")

    def _parse_kexinit(self, data: bytes, conn: Dict) -> None:
        """Parse SSH_MSG_KEXINIT to extract algorithms"""
        try:
            if len(data) < 17:
                return
            
            # Skip cookie (16 bytes) + msg_type (1 byte already skipped)
            offset = 16
            
            # Parse name-lists
            name_lists = []
            for i in range(10):  # 10 name-lists in KEXINIT
                if offset + 4 > len(data):
                    break
                import struct
                list_len = struct.unpack('>I', data[offset:offset+4])[0]
                offset += 4
                if offset + list_len > len(data):
                    break
                name_list = data[offset:offset+list_len].decode('utf-8', errors='ignore')
                name_lists.append(name_list.split(','))
                offset += list_len
            
            if len(name_lists) >= 4:
                # name_lists[0] = kex algorithms
                # name_lists[1] = server host key algorithms  
                # name_lists[2] = encryption_algorithms_client_to_server
                # name_lists[3] = encryption_algorithms_server_to_client
                
                for kex in name_lists[0]:
                    self.key_exchanges[kex] += 1
                for cipher in name_lists[2]:
                    self.ciphers_negotiated[cipher] += 1
                    
                conn["kex_algorithms"] = name_lists[0][:5]
                conn["ciphers"] = name_lists[2][:5]
                
        except Exception as e:
            logger.debug(f"Error parsing KEXINIT: {e}")

    def _parse_userauth_request(self, idx: int, data: bytes, timestamp: float,
                               conn: Dict, client_ip: str, server_ip: str,
                               session: Dict) -> None:
        """Parse SSH_MSG_USERAUTH_REQUEST"""
        try:
            import struct
            offset = 1  # Skip msg_type
            
            if offset + 4 > len(data):
                return
            
            # username string
            user_len = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4
            username = ""
            if offset + user_len <= len(data):
                username = data[offset:offset+user_len].decode('utf-8', errors='ignore')
                offset += user_len
            
            # service string
            if offset + 4 > len(data):
                return
            svc_len = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4
            service = ""
            if offset + svc_len <= len(data):
                service = data[offset:offset+svc_len].decode('utf-8', errors='ignore')
                offset += svc_len
            
            # method string
            if offset + 4 > len(data):
                return
            method_len = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4
            method = ""
            if offset + method_len <= len(data):
                method = data[offset:offset+method_len].decode('utf-8', errors='ignore')
            
            auth_info = {
                "packet_idx": idx,
                "timestamp": timestamp,  # raw float, formatted to ISO at compile time
                "client_ip": client_ip,
                "server_ip": server_ip,
                "username": username,
                "service": service,
                "method": method,
                "success": None,  # Will be updated on response
            }
            
            self.auth_attempts.append(auth_info)
            
            if method and method not in session.get("auth_methods_tried", []):
                session["auth_methods_tried"].append(method)
                
        except Exception as e:
            logger.debug(f"Error parsing userauth request: {e}")

    def _record_auth_failure(self, idx: int, timestamp: float, conn: Dict,
                            client_ip: str, server_ip: str, session: Dict) -> None:
        """Record authentication failure"""
        # Update last auth attempt as failed
        if self.auth_attempts:
            for auth in reversed(self.auth_attempts):
                if auth.get("client_ip") == client_ip and auth.get("server_ip") == server_ip:
                    if auth.get("success") is None:
                        auth["success"] = False
                        break
        
        self.failed_auth[client_ip].append({
            "timestamp": timestamp,  # raw float, formatted to ISO at compile time
            "server_ip": server_ip,
            "reason": "auth_failure",
        })

    def _parse_channel_open(self, idx: int, data: bytes, timestamp: float,
                           conn: Dict, session: Dict, client_ip: str, 
                           server_ip: str) -> None:
        """Parse SSH_MSG_CHANNEL_OPEN for tunneling detection"""
        try:
            import struct
            offset = 1  # Skip msg_type
            
            if offset + 4 > len(data):
                return
            
            # channel type string
            type_len = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4
            channel_type = ""
            if offset + type_len <= len(data):
                channel_type = data[offset:offset+type_len].decode('utf-8', errors='ignore')
            
            # Check for tunneling indicators
            if channel_type in ['direct-tcpip', 'forwarded-tcpip', 'x11']:
                tunnel_info = {
                    "packet_idx": idx,
                    "timestamp": timestamp,  # raw float, formatted to ISO at compile time
                    "client_ip": client_ip,
                    "server_ip": server_ip,
                    "channel_type": channel_type,
                    "tunnel_type": None,
                }
                
                if channel_type == 'direct-tcpip':
                    tunnel_info["tunnel_type"] = "Local Port Forward"
                elif channel_type == 'forwarded-tcpip':
                    tunnel_info["tunnel_type"] = "Remote Port Forward"
                elif channel_type == 'x11':
                    tunnel_info["tunnel_type"] = "X11 Forwarding"
                
                self.tunnels.append(tunnel_info)
                
        except Exception as e:
            logger.debug(f"Error parsing channel open: {e}")

    def _detect_anomalies(self) -> None:
        """Detect SSH security anomalies"""
        self._detect_brute_force()
        self._detect_weak_versions()
        self._detect_weak_crypto()
        self._detect_tunneling_abuse()
        self._detect_scanning()

    def _detect_brute_force(self) -> None:
        """Detect SSH brute force attempts"""
        for client_ip, failures in self.failed_auth.items():
            if len(failures) > 5:
                targets = set(f.get("server_ip") for f in failures)
                self.anomalies.append({
                    "type": "SSH Brute Force",
                    "severity": "high",
                    "description": f"Multiple failed SSH auth ({len(failures)}) from {client_ip}",
                    "src_ip": client_ip,
                    "targets": list(targets)[:10],
                    "failed_attempts": len(failures),
                    "recommendation": "Block source IP, implement fail2ban",
                })
        
        # Check auth attempts per target
        attempts_by_target = defaultdict(list)
        for attempt in self.auth_attempts:
            attempts_by_target[attempt.get("server_ip")].append(attempt)
        
        for server_ip, attempts in attempts_by_target.items():
            failed = sum(1 for a in attempts if a.get("success") == False)
            unique_users = set(a.get("username") for a in attempts if a.get("username"))
            
            if failed > 20 or len(unique_users) > 10:
                self.anomalies.append({
                    "type": "SSH Attack Target",
                    "severity": "high",
                    "description": f"High SSH attack activity against {server_ip}",
                    "target": server_ip,
                    "failed_attempts": failed,
                    "unique_usernames": len(unique_users),
                    "usernames_sample": list(unique_users)[:10],
                    "recommendation": "Review access controls and enable MFA",
                })

    def _detect_weak_versions(self) -> None:
        """Detect weak SSH versions"""
        for version, count in self.server_versions.items():
            for weak in WEAK_SSH_VERSIONS:
                if version.startswith(weak):
                    self.anomalies.append({
                        "type": "Weak SSH Version (Server)",
                        "severity": "critical",
                        "description": f"Deprecated SSH version detected: {version}",
                        "version": version,
                        "count": count,
                        "recommendation": "Upgrade SSH server immediately",
                    })
        
        for version, count in self.client_versions.items():
            for weak in WEAK_SSH_VERSIONS:
                if version.startswith(weak):
                    self.anomalies.append({
                        "type": "Weak SSH Version (Client)",
                        "severity": "high",
                        "description": f"Client using deprecated SSH: {version}",
                        "version": version,
                        "count": count,
                        "recommendation": "Update SSH client software",
                    })

    def _detect_weak_crypto(self) -> None:
        """Detect weak cryptographic algorithms"""
        weak_ciphers_found = {}
        for cipher, count in self.ciphers_negotiated.items():
            if any(weak.lower() in cipher.lower() for weak in WEAK_CIPHERS):
                weak_ciphers_found[cipher] = count
        
        if weak_ciphers_found:
            self.anomalies.append({
                "type": "Weak SSH Ciphers",
                "severity": "medium",
                "description": "Weak encryption ciphers in use",
                "ciphers": weak_ciphers_found,
                "recommendation": "Disable weak ciphers in SSH configuration",
            })
        
        weak_kex_found = {}
        for kex, count in self.key_exchanges.items():
            if any(weak.lower() in kex.lower() for weak in WEAK_KEX):
                weak_kex_found[kex] = count
        
        if weak_kex_found:
            self.anomalies.append({
                "type": "Weak Key Exchange",
                "severity": "medium",
                "description": "Weak key exchange algorithms detected",
                "algorithms": weak_kex_found,
                "recommendation": "Configure stronger key exchange algorithms",
            })

    def _detect_tunneling_abuse(self) -> None:
        """Detect potentially abusive SSH tunneling"""
        tunnel_by_source = defaultdict(list)
        for tunnel in self.tunnels:
            tunnel_by_source[tunnel.get("client_ip")].append(tunnel)
        
        for client_ip, tunnels in tunnel_by_source.items():
            if len(tunnels) > 5:
                types = set(t.get("tunnel_type") for t in tunnels)
                self.anomalies.append({
                    "type": "Excessive SSH Tunneling",
                    "severity": "medium",
                    "description": f"Multiple SSH tunnels ({len(tunnels)}) from {client_ip}",
                    "src_ip": client_ip,
                    "tunnel_count": len(tunnels),
                    "tunnel_types": list(types),
                    "recommendation": "Review tunneling policies and usage",
                })

    def _detect_scanning(self) -> None:
        """Detect SSH port scanning"""
        sources_by_targets = defaultdict(set)
        
        for conn_key, conn in self.connections.items():
            sources_by_targets[conn.get("client_ip")].add(conn.get("server_ip"))
        
        for src_ip, targets in sources_by_targets.items():
            if len(targets) > 5:
                self.anomalies.append({
                    "type": "SSH Port Scan",
                    "severity": "medium",
                    "description": f"SSH scanning from {src_ip} to {len(targets)} hosts",
                    "src_ip": src_ip,
                    "target_count": len(targets),
                    "targets_sample": list(targets)[:10],
                    "recommendation": "Block source and investigate reconnaissance",
                })
