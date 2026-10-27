"""
SMB/CIFS Protocol Analyzer
Analyzes SMB traffic for shares, authentication, file access, and security threats
Detects: EternalBlue, SMBGhost, Pass-the-Hash attacks
"""

from typing import Dict, Any, List, Optional
from collections import defaultdict
from datetime import datetime
import struct
import re

from scapy.all import Packet, TCP, Raw
from app.analyzers.base import BaseAnalyzer
from app.core.logging_config import get_logger

logger = get_logger(__name__)


def _iso(ts: float) -> str:
    """Format a raw float timestamp to ISO string (called once at result compilation)"""
    return datetime.fromtimestamp(ts).isoformat()


# SMB Ports
SMB_PORTS = {139, 445}

# SMB Commands
SMB_COMMANDS = {
    0x00: "SMB_COM_CREATE_DIRECTORY",
    0x01: "SMB_COM_DELETE_DIRECTORY",
    0x02: "SMB_COM_OPEN",
    0x03: "SMB_COM_CREATE",
    0x04: "SMB_COM_CLOSE",
    0x05: "SMB_COM_FLUSH",
    0x06: "SMB_COM_DELETE",
    0x07: "SMB_COM_RENAME",
    0x08: "SMB_COM_QUERY_INFORMATION",
    0x09: "SMB_COM_SET_INFORMATION",
    0x0A: "SMB_COM_READ",
    0x0B: "SMB_COM_WRITE",
    0x0C: "SMB_COM_LOCK_BYTE_RANGE",
    0x0D: "SMB_COM_UNLOCK_BYTE_RANGE",
    0x0E: "SMB_COM_CREATE_TEMPORARY",
    0x0F: "SMB_COM_CREATE_NEW",
    0x10: "SMB_COM_CHECK_DIRECTORY",
    0x11: "SMB_COM_PROCESS_EXIT",
    0x12: "SMB_COM_SEEK",
    0x13: "SMB_COM_LOCK_AND_READ",
    0x14: "SMB_COM_WRITE_AND_UNLOCK",
    0x22: "SMB_COM_SET_INFORMATION2",
    0x23: "SMB_COM_QUERY_INFORMATION2",
    0x24: "SMB_COM_LOCKING_ANDX",
    0x25: "SMB_COM_TRANSACTION",
    0x26: "SMB_COM_TRANSACTION_SECONDARY",
    0x27: "SMB_COM_IOCTL",
    0x2A: "SMB_COM_COPY",
    0x2B: "SMB_COM_MOVE",
    0x2C: "SMB_COM_ECHO",
    0x2D: "SMB_COM_WRITE_AND_CLOSE",
    0x2E: "SMB_COM_OPEN_ANDX",
    0x2F: "SMB_COM_READ_ANDX",
    0x32: "SMB_COM_TRANSACTION2",
    0x33: "SMB_COM_TRANSACTION2_SECONDARY",
    0x34: "SMB_COM_FIND_CLOSE2",
    0x35: "SMB_COM_FIND_NOTIFY_CLOSE",
    0x70: "SMB_COM_TREE_CONNECT",
    0x71: "SMB_COM_TREE_DISCONNECT",
    0x72: "SMB_COM_NEGOTIATE",
    0x73: "SMB_COM_SESSION_SETUP_ANDX",
    0x74: "SMB_COM_LOGOFF_ANDX",
    0x75: "SMB_COM_TREE_CONNECT_ANDX",
    0x80: "SMB_COM_QUERY_INFORMATION_DISK",
    0xA2: "SMB_COM_NT_CREATE_ANDX",
    0xC0: "SMB_COM_OPEN_PRINT_FILE",
    0xC1: "SMB_COM_WRITE_PRINT_FILE",
    0xC2: "SMB_COM_CLOSE_PRINT_FILE",
    0xC3: "SMB_COM_GET_PRINT_QUEUE",
}

# SMB2 Commands
SMB2_COMMANDS = {
    0x00: "SMB2_NEGOTIATE",
    0x01: "SMB2_SESSION_SETUP",
    0x02: "SMB2_LOGOFF",
    0x03: "SMB2_TREE_CONNECT",
    0x04: "SMB2_TREE_DISCONNECT",
    0x05: "SMB2_CREATE",
    0x06: "SMB2_CLOSE",
    0x07: "SMB2_FLUSH",
    0x08: "SMB2_READ",
    0x09: "SMB2_WRITE",
    0x0A: "SMB2_LOCK",
    0x0B: "SMB2_IOCTL",
    0x0C: "SMB2_CANCEL",
    0x0D: "SMB2_ECHO",
    0x0E: "SMB2_QUERY_DIRECTORY",
    0x0F: "SMB2_CHANGE_NOTIFY",
    0x10: "SMB2_QUERY_INFO",
    0x11: "SMB2_SET_INFO",
    0x12: "SMB2_OPLOCK_BREAK",
}


class SMBAnalyzer(BaseAnalyzer):
    """Analyzer for SMB/CIFS protocol traffic"""

    def __init__(self):
        super().__init__()
        self.sessions: Dict[str, Dict] = {}
        self.shares: Dict[str, Dict] = {}
        self.file_operations: List[Dict] = []
        self.auth_attempts: List[Dict] = []
        self.commands: Dict[str, int] = defaultdict(int)
        self.anomalies: List[Dict] = []
    
    def reset(self):
        """Reset analyzer state"""
        super().reset()
        self.sessions = {}
        self.shares = {}
        self.file_operations = []
        self.auth_attempts = []
        self.commands = defaultdict(int)
        self.anomalies = []
        
    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """Analyze SMB/CIFS traffic"""
        self.reset()
        logger.info("smb_analysis_started", packet_count=len(packets))
        
        smb_packets = []
        for idx, packet in enumerate(packets):
            if self._is_smb_packet(packet):
                smb_packets.append((idx, packet))
                self._process_smb_packet(idx, packet)
        
        # Detect security anomalies
        self._detect_anomalies()
        
        # Convert sets to lists for JSON serialization
        # Format float timestamps to ISO once, only for records included in results
        sessions_list = []
        for session in list(self.sessions.values())[:100]:
            session_copy = dict(session)
            if "data_types" in session_copy and isinstance(session_copy["data_types"], set):
                session_copy["data_types"] = list(session_copy["data_types"])
            session_copy["first_seen"] = _iso(session_copy["first_seen"])
            session_copy["last_seen"] = _iso(session_copy["last_seen"])
            sessions_list.append(session_copy)

        shares_list = list(self.shares.values())[:50]
        for share in shares_list:
            share["first_access"] = _iso(share["first_access"])
            share["last_access"] = _iso(share["last_access"])

        file_operations = self.file_operations[:200]
        for file_op in file_operations:
            file_op["timestamp"] = _iso(file_op["timestamp"])

        auth_attempts = self.auth_attempts[:100]
        for auth in auth_attempts:
            auth["timestamp"] = _iso(auth["timestamp"])

        self.results = {
            "summary": {
                "total_packets": len(smb_packets),
                "total_sessions": len(self.sessions),
                "total_shares": len(self.shares),
                "total_file_operations": len(self.file_operations),
                "total_auth_attempts": len(self.auth_attempts),
                "total_anomalies": len(self.anomalies),
            },
            "sessions": sessions_list,
            "shares": shares_list,
            "file_operations": file_operations,
            "auth_attempts": auth_attempts,
            "commands": dict(self.commands),
            "anomalies": self.anomalies,
        }
        
        logger.info("smb_analysis_completed", 
                   sessions=len(self.sessions), 
                   packets=len(smb_packets),
                   anomalies=len(self.anomalies))
        return self.results

    def _is_smb_packet(self, packet: Packet) -> bool:
        """Check if packet is SMB traffic"""
        if not packet.haslayer(TCP):
            return False
        tcp = packet[TCP]
        if tcp.sport not in SMB_PORTS and tcp.dport not in SMB_PORTS:
            return False
        return packet.haslayer(Raw)

    def _process_smb_packet(self, idx: int, packet: Packet) -> None:
        """Process individual SMB packet"""
        try:
            tcp = packet[TCP]
            raw_data = bytes(packet[Raw].load)
            timestamp = self.get_packet_timestamp(packet)
            src_ip, dst_ip = self.get_ip_pair(packet)
            
            # Skip if too small for SMB header
            if len(raw_data) < 4:
                return
                
            # Check for NetBIOS Session Service header (4 bytes)
            netbios_offset = 0
            if raw_data[0] == 0x00:  # NetBIOS Session Message
                netbios_offset = 4
                
            if len(raw_data) < netbios_offset + 4:
                return
                
            smb_data = raw_data[netbios_offset:]
            
            # Identify SMB version at start
            if smb_data[:4] == b'\xffSMB':  # SMB1
                self._process_smb1(idx, packet, smb_data, timestamp, src_ip, dst_ip)
            elif smb_data[:4] == b'\xfeSMB':  # SMB2/3
                self._process_smb2(idx, packet, smb_data, timestamp, src_ip, dst_ip)
            else:
                # Search for SMB signature anywhere in payload (fragmented traffic)
                smb1_pos = raw_data.find(b'\xffSMB')
                smb2_pos = raw_data.find(b'\xfeSMB')
                
                if smb1_pos >= 0:
                    self._process_smb1(idx, packet, raw_data[smb1_pos:], timestamp, src_ip, dst_ip)
                elif smb2_pos >= 0:
                    self._process_smb2(idx, packet, raw_data[smb2_pos:], timestamp, src_ip, dst_ip)
                else:
                    # Track as SMB activity on port 445 even without clear protocol signature
                    self._track_smb_activity(idx, timestamp, src_ip, dst_ip, raw_data)
                
        except Exception as e:
            logger.debug(f"Error processing SMB packet: {e}")
    
    def _track_smb_activity(self, idx: int, timestamp: float, src_ip: str, 
                            dst_ip: str, data: bytes) -> None:
        """Track SMB port activity that doesn't have clear protocol signature"""
        session_key = f"{min(src_ip, dst_ip)}:{max(src_ip, dst_ip)}:445"
        
        if session_key not in self.sessions:
            self.sessions[session_key] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "session_id": "unknown",
                "tree_id": 0,
                "smb_version": "SMB/CIFS",
                "first_seen": timestamp,  # raw float, formatted to ISO at compile time
                "last_seen": timestamp,
                "commands": [],
                "packet_count": 0,
                "data_types": set(),
            }
        
        session = self.sessions[session_key]
        session["last_seen"] = timestamp
        session["packet_count"] += 1
        
        # Detect common patterns
        if b'NTLMSSP' in data:
            session["data_types"].add("NTLM_AUTH")
        if data[:2] == b'\x60\x48' or b'\x06\x06\x2b\x06' in data:
            session["data_types"].add("GSSAPI/SPNEGO")
        if data[:4] == b'\x00\x00\x00\x00':
            session["data_types"].add("KEEPALIVE")

    def _process_smb1(self, idx: int, packet: Packet, data: bytes, 
                      timestamp: float, src_ip: str, dst_ip: str) -> None:
        """Process SMB1 packet"""
        try:
            if len(data) < 33:
                return
                
            command = data[4]
            cmd_name = SMB_COMMANDS.get(command, f"UNKNOWN_{hex(command)}")
            self.commands[cmd_name] += 1
            
            # Extract session info
            flags = data[13]
            flags2 = struct.unpack('<H', data[14:16])[0]
            tree_id = struct.unpack('<H', data[24:26])[0]
            process_id = struct.unpack('<H', data[26:28])[0]
            user_id = struct.unpack('<H', data[28:30])[0]
            
            session_key = f"{src_ip}:{dst_ip}:{user_id}"
            
            # Track sessions
            if session_key not in self.sessions:
                self.sessions[session_key] = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "user_id": user_id,
                    "tree_id": tree_id,
                    "smb_version": "SMB1",
                    "first_seen": timestamp,  # raw float, formatted to ISO at compile time
                    "last_seen": timestamp,
                    "commands": [],
                    "packet_count": 0,
                }
            
            session = self.sessions[session_key]
            session["last_seen"] = timestamp
            session["packet_count"] += 1
            if cmd_name not in session["commands"]:
                session["commands"].append(cmd_name)
            
            # Track authentication attempts
            if command == 0x73:  # SESSION_SETUP_ANDX
                self._track_auth_attempt(idx, timestamp, src_ip, dst_ip, data, "SMB1")
                
            # Track tree connections (share access)
            if command in [0x70, 0x75]:  # TREE_CONNECT or TREE_CONNECT_ANDX
                self._track_share_access(idx, timestamp, src_ip, dst_ip, data, "SMB1")
                
            # Track file operations
            if command in [0x02, 0x03, 0x0A, 0x0B, 0x2E, 0x2F, 0xA2]:
                self._track_file_operation(idx, timestamp, src_ip, dst_ip, cmd_name, data)
                
        except Exception as e:
            logger.debug(f"Error processing SMB1: {e}")

    def _process_smb2(self, idx: int, packet: Packet, data: bytes,
                      timestamp: float, src_ip: str, dst_ip: str) -> None:
        """Process SMB2/3 packet"""
        try:
            if len(data) < 64:
                return
                
            # SMB2 header
            header_length = struct.unpack('<H', data[4:6])[0]
            command = struct.unpack('<H', data[12:14])[0]
            cmd_name = SMB2_COMMANDS.get(command, f"SMB2_UNKNOWN_{hex(command)}")
            self.commands[cmd_name] += 1
            
            flags = struct.unpack('<I', data[16:20])[0]
            message_id = struct.unpack('<Q', data[24:32])[0]
            tree_id = struct.unpack('<I', data[36:40])[0]
            session_id = struct.unpack('<Q', data[40:48])[0]
            
            session_key = f"{src_ip}:{dst_ip}:{session_id}"
            
            # Track sessions
            if session_key not in self.sessions:
                self.sessions[session_key] = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "session_id": session_id,
                    "tree_id": tree_id,
                    "smb_version": "SMB2/3",
                    "first_seen": timestamp,  # raw float, formatted to ISO at compile time
                    "last_seen": timestamp,
                    "commands": [],
                    "packet_count": 0,
                }
            
            session = self.sessions[session_key]
            session["last_seen"] = timestamp
            session["packet_count"] += 1
            if cmd_name not in session["commands"]:
                session["commands"].append(cmd_name)
            
            # Track authentication
            if command == 0x01:  # SESSION_SETUP
                self._track_auth_attempt(idx, timestamp, src_ip, dst_ip, data, "SMB2/3")
                
            # Track tree connections
            if command == 0x03:  # TREE_CONNECT
                self._track_share_access(idx, timestamp, src_ip, dst_ip, data, "SMB2/3")
                
            # Track file operations
            if command in [0x05, 0x06, 0x08, 0x09]:  # CREATE, CLOSE, READ, WRITE
                self._track_file_operation(idx, timestamp, src_ip, dst_ip, cmd_name, data)
                
        except Exception as e:
            logger.debug(f"Error processing SMB2: {e}")

    def _track_auth_attempt(self, idx: int, timestamp: float, src_ip: str, 
                            dst_ip: str, data: bytes, version: str) -> None:
        """Track authentication attempts"""
        auth_info = {
            "packet_idx": idx,
            "timestamp": timestamp,  # raw float, formatted to ISO at compile time
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "smb_version": version,
            "auth_type": "Unknown",
            "username": None,
            "domain": None,
            "status": "attempt",
        }
        
        # Try to extract NTLM info
        try:
            ntlmssp_idx = data.find(b'NTLMSSP\x00')
            if ntlmssp_idx != -1:
                msg_type = data[ntlmssp_idx + 8] if len(data) > ntlmssp_idx + 8 else 0
                if msg_type == 1:
                    auth_info["auth_type"] = "NTLM_NEGOTIATE"
                elif msg_type == 2:
                    auth_info["auth_type"] = "NTLM_CHALLENGE"
                elif msg_type == 3:
                    auth_info["auth_type"] = "NTLM_AUTH"
                    # Try to extract username/domain from Type 3 message
                    self._extract_ntlm_credentials(data[ntlmssp_idx:], auth_info)
        except Exception:
            pass
            
        self.auth_attempts.append(auth_info)

    def _extract_ntlm_credentials(self, ntlm_data: bytes, auth_info: Dict) -> None:
        """Extract credentials from NTLM Type 3 message"""
        try:
            if len(ntlm_data) < 60:
                return
            
            # Domain
            domain_len = struct.unpack('<H', ntlm_data[28:30])[0]
            domain_offset = struct.unpack('<I', ntlm_data[32:36])[0]
            if domain_offset + domain_len <= len(ntlm_data):
                domain = ntlm_data[domain_offset:domain_offset+domain_len]
                auth_info["domain"] = domain.decode('utf-16-le', errors='ignore')
            
            # Username
            user_len = struct.unpack('<H', ntlm_data[36:38])[0]
            user_offset = struct.unpack('<I', ntlm_data[40:44])[0]
            if user_offset + user_len <= len(ntlm_data):
                username = ntlm_data[user_offset:user_offset+user_len]
                auth_info["username"] = username.decode('utf-16-le', errors='ignore')
                
        except Exception as e:
            logger.debug(f"Error extracting NTLM credentials: {e}")

    def _track_share_access(self, idx: int, timestamp: float, src_ip: str,
                            dst_ip: str, data: bytes, version: str) -> None:
        """Track share access attempts"""
        share_info = {
            "packet_idx": idx,
            "timestamp": timestamp,  # raw float, formatted to ISO at compile time
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "smb_version": version,
            "share_name": None,
        }
        
        # Try to extract share path
        try:
            # Look for UNC path pattern
            for encoding in ['utf-16-le', 'utf-8', 'ascii']:
                try:
                    decoded = data.decode(encoding, errors='ignore')
                    match = re.search(r'\\\\[^\\]+\\([^\x00]+)', decoded)
                    if match:
                        share_info["share_name"] = match.group(0)
                        break
                except:
                    continue
        except Exception:
            pass
            
        share_key = f"{dst_ip}:{share_info.get('share_name', 'unknown')}"
        if share_key not in self.shares:
            self.shares[share_key] = {
                "server": dst_ip,
                "share_name": share_info.get("share_name"),
                "first_access": share_info["timestamp"],
                "last_access": share_info["timestamp"],
                "access_count": 0,
                "clients": [],
            }
        
        share = self.shares[share_key]
        share["last_access"] = share_info["timestamp"]
        share["access_count"] += 1
        if src_ip not in share["clients"]:
            share["clients"].append(src_ip)

    def _track_file_operation(self, idx: int, timestamp: float, src_ip: str,
                              dst_ip: str, operation: str, data: bytes) -> None:
        """Track file operations"""
        file_op = {
            "packet_idx": idx,
            "timestamp": timestamp,  # raw float, formatted to ISO at compile time
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "operation": operation,
            "filename": None,
        }
        
        # Try to extract filename
        try:
            # Look for common filename patterns
            for pattern in [b'\x00([A-Za-z0-9_\\-\\.]+\\.[a-z]{2,4})\x00',
                          b'([A-Za-z]:\\\\[^\x00]+)']:
                match = re.search(pattern, data)
                if match:
                    file_op["filename"] = match.group(1).decode('utf-8', errors='ignore')
                    break
        except Exception:
            pass
            
        self.file_operations.append(file_op)

    def _detect_anomalies(self) -> None:
        """Detect SMB security anomalies"""
        
        # Check for potential EternalBlue (MS17-010)
        # Looks for specific patterns in SMB traffic
        self._detect_eternalblue()
        
        # Check for potential SMBGhost (CVE-2020-0796)
        self._detect_smbghost()
        
        # Check for pass-the-hash attempts
        self._detect_pass_the_hash()
        
        # Check for brute force authentication
        self._detect_auth_brute_force()
        
        # Check for suspicious share access patterns
        self._detect_suspicious_shares()

    def _detect_eternalblue(self) -> None:
        """Detect potential EternalBlue exploitation"""
        # Look for sessions with high TRANSACTION commands
        trans_by_session = defaultdict(int)
        for session_id, session in self.sessions.items():
            for cmd in session.get("commands", []):
                if "TRANSACTION" in cmd:
                    trans_by_session[session_id] += 1
        
        for session_id, count in trans_by_session.items():
            if count > 10:
                session = self.sessions[session_id]
                self.anomalies.append({
                    "type": "Potential EternalBlue",
                    "severity": "critical",
                    "description": f"High number of SMB TRANSACTION commands ({count}) detected",
                    "src_ip": session.get("src_ip"),
                    "dst_ip": session.get("dst_ip"),
                    "recommendation": "Investigate for MS17-010 exploitation attempt",
                    "cve": "CVE-2017-0144",
                })

    def _detect_smbghost(self) -> None:
        """Detect potential SMBGhost vulnerability exploitation"""
        # SMBGhost targets SMB 3.1.1 with compression
        for session_id, session in self.sessions.items():
            if session.get("smb_version") == "SMB2/3":
                # Look for signs of compression negotiation abuse
                cmds = session.get("commands", [])
                if "SMB2_NEGOTIATE" in cmds and session.get("packet_count", 0) > 50:
                    self.anomalies.append({
                        "type": "Potential SMBGhost Probe",
                        "severity": "high",
                        "description": "Unusual SMB3 session pattern detected",
                        "src_ip": session.get("src_ip"),
                        "dst_ip": session.get("dst_ip"),
                        "recommendation": "Verify SMB 3.1.1 compression is disabled or patched",
                        "cve": "CVE-2020-0796",
                    })

    def _detect_pass_the_hash(self) -> None:
        """Detect potential pass-the-hash attacks"""
        # Group auth attempts by source
        auth_by_source = defaultdict(list)
        for auth in self.auth_attempts:
            if auth.get("auth_type") == "NTLM_AUTH":
                auth_by_source[auth.get("src_ip")].append(auth)
        
        # Check for multiple users from same source
        for src_ip, attempts in auth_by_source.items():
            users = set(a.get("username") for a in attempts if a.get("username"))
            targets = set(a.get("dst_ip") for a in attempts)
            
            if len(users) > 3 or (len(users) > 1 and len(targets) > 2):
                self.anomalies.append({
                    "type": "Potential Pass-the-Hash",
                    "severity": "critical",
                    "description": f"Multiple NTLM auth from {src_ip} with {len(users)} users to {len(targets)} targets",
                    "src_ip": src_ip,
                    "users": list(users)[:10],
                    "targets": list(targets)[:10],
                    "recommendation": "Investigate for credential theft and lateral movement",
                })

    def _detect_auth_brute_force(self) -> None:
        """Detect authentication brute force attempts"""
        auth_by_pair = defaultdict(int)
        for auth in self.auth_attempts:
            key = f"{auth.get('src_ip')}:{auth.get('dst_ip')}"
            auth_by_pair[key] += 1
        
        for pair, count in auth_by_pair.items():
            if count > 20:
                src_ip, dst_ip = pair.split(":")
                self.anomalies.append({
                    "type": "SMB Auth Brute Force",
                    "severity": "high",
                    "description": f"High number of auth attempts ({count}) from {src_ip} to {dst_ip}",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "attempt_count": count,
                    "recommendation": "Block source IP and investigate compromised credentials",
                })

    def _detect_suspicious_shares(self) -> None:
        """Detect access to suspicious shares"""
        suspicious_patterns = ['admin$', 'c$', 'ipc$', 'd$', 'print$']
        
        for share_key, share in self.shares.items():
            share_name = (share.get("share_name") or "").lower()
            for pattern in suspicious_patterns:
                if pattern in share_name:
                    self.anomalies.append({
                        "type": "Suspicious Share Access",
                        "severity": "medium",
                        "description": f"Access to administrative share: {share.get('share_name')}",
                        "server": share.get("server"),
                        "share": share.get("share_name"),
                        "clients": share.get("clients", [])[:10],
                        "access_count": share.get("access_count"),
                        "recommendation": "Verify authorized access to administrative shares",
                    })
                    break
