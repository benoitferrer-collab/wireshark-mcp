"""
LDAP Protocol Analyzer
Analyzes LDAP traffic for Active Directory queries, enumeration, and security threats
Detects: LDAP injection, AD enumeration, credential exposure
"""

from typing import Dict, Any, List, Optional
from collections import defaultdict
from datetime import datetime
import struct
import re

from scapy.all import Packet, TCP, UDP, Raw
from app.analyzers.base import BaseAnalyzer
from app.core.logging_config import get_logger

logger = get_logger(__name__)


def _iso(ts: float) -> str:
    """Format a raw float timestamp to ISO string (called once at result compilation)"""
    return datetime.fromtimestamp(ts).isoformat()


# LDAP Ports
LDAP_PORTS = {389, 636, 3268, 3269}  # LDAP, LDAPS, Global Catalog, GC-SSL

# LDAP Operation Types (BER encoded)
LDAP_OPERATIONS = {
    0x60: "BindRequest",
    0x61: "BindResponse",
    0x42: "UnbindRequest",
    0x63: "SearchRequest",
    0x64: "SearchResultEntry",
    0x65: "SearchResultDone",
    0x66: "ModifyRequest",
    0x67: "ModifyResponse",
    0x68: "AddRequest",
    0x69: "AddResponse",
    0x4a: "DeleteRequest",
    0x6b: "DeleteResponse",
    0x6c: "ModifyDNRequest",
    0x6d: "ModifyDNResponse",
    0x6e: "CompareRequest",
    0x6f: "CompareResponse",
    0x50: "AbandonRequest",
    0x77: "ExtendedRequest",
    0x78: "ExtendedResponse",
}

# Sensitive LDAP attributes for enumeration detection
SENSITIVE_ATTRIBUTES = [
    'userpassword', 'unicodepwd', 'ntpwdhistory', 'lmpwdhistory',
    'samaccountname', 'admincount', 'memberof', 'primarygroupid',
    'serviceprincipalname', 'msds-allowedtodelegateto',
    'msds-allowedtoactonbehalfofotheridentity', 'sidhistory',
    'supplementalcredentials', 'useraccountcontrol',
]

# LDAP injection patterns
INJECTION_PATTERNS = [
    r'\*\)\(\|', r'\)\(\&', r'\)\(\|', r'\*\)\(', r'\)\(cn=\*',
    r'\\00', r'\\29', r'\\28', r'\x00', r'\x29', r'\x28',
    r'\*\)\(password', r'\*\)\(userpassword',
]


class LDAPAnalyzer(BaseAnalyzer):
    """Analyzer for LDAP protocol traffic"""

    def __init__(self):
        super().__init__()
        self.sessions: Dict[str, Dict] = {}
        self.bind_attempts: List[Dict] = []
        self.search_queries: List[Dict] = []
        self.modifications: List[Dict] = []
        self.operations: Dict[str, int] = defaultdict(int)
        self.queried_attributes: Dict[str, int] = defaultdict(int)
        self.base_dns: Dict[str, int] = defaultdict(int)
        self.anomalies: List[Dict] = []

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """Analyze LDAP traffic"""
        self.reset()
        logger.info("ldap_analysis_started", packet_count=len(packets))
        
        ldap_packets = []
        for idx, packet in enumerate(packets):
            if self._is_ldap_packet(packet):
                ldap_packets.append((idx, packet))
                self._process_ldap_packet(idx, packet)
        
        # Detect security anomalies
        self._detect_anomalies()

        # Format float timestamps to ISO once, only for records included in results
        sessions = list(self.sessions.values())[:100]
        for session in sessions:
            session["first_seen"] = _iso(session["first_seen"])
            session["last_seen"] = _iso(session["last_seen"])

        bind_attempts = self.bind_attempts[:100]
        for bind in bind_attempts:
            bind["timestamp"] = _iso(bind["timestamp"])

        search_queries = self.search_queries[:200]
        for query in search_queries:
            query["timestamp"] = _iso(query["timestamp"])

        modifications = self.modifications[:100]
        for mod in modifications:
            mod["timestamp"] = _iso(mod["timestamp"])

        self.results = {
            "summary": {
                "total_packets": len(ldap_packets),
                "total_sessions": len(self.sessions),
                "total_bind_attempts": len(self.bind_attempts),
                "total_search_queries": len(self.search_queries),
                "total_modifications": len(self.modifications),
                "total_anomalies": len(self.anomalies),
            },
            "sessions": sessions,
            "bind_attempts": bind_attempts,
            "search_queries": search_queries,
            "modifications": modifications,
            "operations": dict(self.operations),
            "queried_attributes": dict(sorted(self.queried_attributes.items(), 
                                             key=lambda x: x[1], reverse=True)[:50]),
            "base_dns": dict(sorted(self.base_dns.items(), 
                                   key=lambda x: x[1], reverse=True)[:20]),
            "anomalies": self.anomalies,
        }
        
        logger.info("ldap_analysis_completed", 
                   packets=len(ldap_packets),
                   sessions=len(self.sessions),
                   queries=len(self.search_queries))
        return self.results

    def reset(self):
        """Reset analyzer state"""
        super().reset()
        self.sessions = {}
        self.bind_attempts = []
        self.search_queries = []
        self.modifications = []
        self.operations = defaultdict(int)
        self.queried_attributes = defaultdict(int)
        self.base_dns = defaultdict(int)
        self.anomalies = []

    def _is_ldap_packet(self, packet: Packet) -> bool:
        """Check if packet is LDAP traffic"""
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.sport in LDAP_PORTS or tcp.dport in LDAP_PORTS:
                return packet.haslayer(Raw)
        if packet.haslayer(UDP):
            udp = packet[UDP]
            if udp.sport in LDAP_PORTS or udp.dport in LDAP_PORTS:
                return packet.haslayer(Raw)
        return False

    def _process_ldap_packet(self, idx: int, packet: Packet) -> None:
        """Process individual LDAP packet"""
        try:
            raw_data = bytes(packet[Raw].load)
            timestamp = self.get_packet_timestamp(packet)
            src_ip, dst_ip = self.get_ip_pair(packet)
            src_port, dst_port = self.get_port_pair(packet)
            
            # Determine if LDAPS
            is_ldaps = dst_port in {636, 3269} or src_port in {636, 3269}
            
            session_key = f"{src_ip}:{src_port}:{dst_ip}:{dst_port}"
            
            # Track session
            if session_key not in self.sessions:
                self.sessions[session_key] = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "is_ldaps": is_ldaps,
                    "first_seen": timestamp,  # raw float, formatted to ISO at compile time
                    "last_seen": timestamp,
                    "packet_count": 0,
                    "operations": [],
                    "bind_dn": None,
                }
            
            session = self.sessions[session_key]
            session["last_seen"] = timestamp
            session["packet_count"] += 1
            
            # Parse LDAP BER encoded data
            self._parse_ldap_message(idx, raw_data, timestamp, src_ip, dst_ip, 
                                    session, is_ldaps)
            
        except Exception as e:
            logger.debug(f"Error processing LDAP packet: {e}")

    def _parse_ldap_message(self, idx: int, data: bytes, timestamp: float,
                           src_ip: str, dst_ip: str, session: Dict,
                           is_ldaps: bool) -> None:
        """Parse LDAP BER-encoded message"""
        try:
            if len(data) < 2:
                return
            
            offset = 0
            while offset < len(data) - 2:
                # LDAP messages start with SEQUENCE (0x30)
                if data[offset] != 0x30:
                    offset += 1
                    continue
                
                # Parse length
                length_byte = data[offset + 1]
                if length_byte & 0x80:
                    length_bytes = length_byte & 0x7f
                    if offset + 2 + length_bytes > len(data):
                        break
                    msg_length = int.from_bytes(data[offset + 2:offset + 2 + length_bytes], 'big')
                    header_size = 2 + length_bytes
                else:
                    msg_length = length_byte
                    header_size = 2
                
                msg_start = offset + header_size
                msg_end = msg_start + msg_length
                
                if msg_end > len(data):
                    break
                
                msg_data = data[msg_start:msg_end]
                self._parse_ldap_operation(idx, msg_data, timestamp, src_ip, dst_ip, 
                                          session, is_ldaps)
                
                offset = msg_end
                
        except Exception as e:
            logger.debug(f"Error parsing LDAP message: {e}")

    def _parse_ldap_operation(self, idx: int, data: bytes, timestamp: float,
                             src_ip: str, dst_ip: str, session: Dict,
                             is_ldaps: bool) -> None:
        """Parse LDAP operation from message data"""
        try:
            if len(data) < 4:
                return
            
            # Skip message ID
            if data[0] != 0x02:  # INTEGER (message ID)
                return
            
            id_len = data[1]
            op_offset = 2 + id_len
            
            if op_offset >= len(data):
                return
            
            op_tag = data[op_offset]
            op_name = LDAP_OPERATIONS.get(op_tag, f"Unknown_{hex(op_tag)}")
            self.operations[op_name] += 1
            
            if op_name not in session.get("operations", []):
                session["operations"].append(op_name)
            
            # Parse specific operations
            op_data = data[op_offset:]
            
            if op_tag == 0x60:  # BindRequest
                self._parse_bind_request(idx, op_data, timestamp, src_ip, dst_ip, 
                                        session, is_ldaps)
            elif op_tag == 0x61:  # BindResponse
                self._parse_bind_response(idx, op_data, timestamp, src_ip, dst_ip)
            elif op_tag == 0x63:  # SearchRequest
                self._parse_search_request(idx, op_data, timestamp, src_ip, dst_ip,
                                          session)
            elif op_tag in [0x66, 0x68, 0x6c]:  # Modify/Add/ModifyDN
                self._parse_modification(idx, op_tag, op_data, timestamp, src_ip, dst_ip)
                
        except Exception as e:
            logger.debug(f"Error parsing LDAP operation: {e}")

    def _parse_bind_request(self, idx: int, data: bytes, timestamp: float,
                           src_ip: str, dst_ip: str, session: Dict,
                           is_ldaps: bool) -> None:
        """Parse LDAP Bind Request"""
        bind_info = {
            "packet_idx": idx,
            "timestamp": timestamp,  # raw float, formatted to ISO at compile time
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "is_ldaps": is_ldaps,
            "bind_dn": None,
            "auth_type": "simple",
            "version": 3,
        }
        
        try:
            # Extract bind DN (usually starts after tag and length)
            offset = 2  # Skip tag and length
            if offset < len(data) and data[offset] == 0x02:  # VERSION
                offset += 2 + data[offset + 1]
            
            if offset < len(data) and data[offset] == 0x04:  # OCTET STRING (DN)
                dn_len = data[offset + 1]
                if offset + 2 + dn_len <= len(data):
                    bind_dn = data[offset + 2:offset + 2 + dn_len].decode('utf-8', errors='ignore')
                    bind_info["bind_dn"] = bind_dn
                    session["bind_dn"] = bind_dn
                    
            # Check for SASL authentication
            sasl_offset = data.find(b'\xa3')  # SASL choice tag
            if sasl_offset != -1:
                bind_info["auth_type"] = "SASL"
                # Try to extract mechanism
                if b'GSSAPI' in data:
                    bind_info["auth_type"] = "SASL/GSSAPI"
                elif b'DIGEST-MD5' in data:
                    bind_info["auth_type"] = "SASL/DIGEST-MD5"
                elif b'NTLM' in data:
                    bind_info["auth_type"] = "SASL/NTLM"
                    
        except Exception as e:
            logger.debug(f"Error parsing bind request: {e}")
        
        self.bind_attempts.append(bind_info)

    def _parse_bind_response(self, idx: int, data: bytes, timestamp: float,
                            src_ip: str, dst_ip: str) -> None:
        """Parse LDAP Bind Response for result code"""
        try:
            # Look for result code (ENUMERATED type 0x0a)
            for i in range(len(data) - 2):
                if data[i] == 0x0a and data[i + 1] == 0x01:
                    result_code = data[i + 2]
                    # Update last bind attempt with result
                    if self.bind_attempts:
                        last_bind = self.bind_attempts[-1]
                        if last_bind.get("dst_ip") == src_ip:
                            last_bind["result_code"] = result_code
                            last_bind["success"] = result_code == 0
                    break
        except Exception:
            pass

    def _parse_search_request(self, idx: int, data: bytes, timestamp: float,
                             src_ip: str, dst_ip: str, session: Dict) -> None:
        """Parse LDAP Search Request"""
        search_info = {
            "packet_idx": idx,
            "timestamp": timestamp,  # raw float, formatted to ISO at compile time
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "base_dn": None,
            "scope": None,
            "filter": None,
            "attributes": [],
        }
        
        try:
            offset = 2  # Skip tag and length
            
            # Base DN (OCTET STRING)
            if offset < len(data) and data[offset] == 0x04:
                dn_len = data[offset + 1]
                if offset + 2 + dn_len <= len(data):
                    base_dn = data[offset + 2:offset + 2 + dn_len].decode('utf-8', errors='ignore')
                    search_info["base_dn"] = base_dn
                    self.base_dns[base_dn] += 1
                offset += 2 + dn_len
            
            # Scope (ENUMERATED)
            if offset < len(data) and data[offset] == 0x0a:
                scope = data[offset + 2] if offset + 2 < len(data) else 0
                search_info["scope"] = ["baseObject", "singleLevel", "wholeSubtree"][scope] if scope < 3 else str(scope)
                offset += 3
            
            # Skip derefAliases, sizeLimit, timeLimit, typesOnly
            for _ in range(4):
                if offset < len(data):
                    if data[offset] == 0x02 or data[offset] == 0x0a or data[offset] == 0x01:
                        offset += 2 + (data[offset + 1] if offset + 1 < len(data) else 0)
            
            # Extract filter string (approximate - BER parsing is complex)
            filter_data = data[offset:].decode('utf-8', errors='ignore')
            # Clean up non-printable characters
            filter_clean = ''.join(c if c.isprintable() else ' ' for c in filter_data)
            search_info["filter"] = filter_clean[:200]
            
            # Track queried attributes
            self._extract_attributes(data, search_info)
            
        except Exception as e:
            logger.debug(f"Error parsing search request: {e}")
        
        self.search_queries.append(search_info)

    def _extract_attributes(self, data: bytes, search_info: Dict) -> None:
        """Extract queried attributes from search request"""
        try:
            # Common attribute patterns in LDAP
            attr_patterns = [
                b'objectClass', b'cn', b'sn', b'givenName', b'mail',
                b'userPrincipalName', b'sAMAccountName', b'memberOf',
                b'member', b'description', b'distinguishedName',
                b'userAccountControl', b'servicePrincipalName',
                b'adminCount', b'pwdLastSet', b'lastLogon',
            ]
            
            for pattern in attr_patterns:
                if pattern in data:
                    attr_name = pattern.decode('utf-8')
                    search_info["attributes"].append(attr_name)
                    self.queried_attributes[attr_name.lower()] += 1
                    
            # Check for sensitive attributes
            for attr in SENSITIVE_ATTRIBUTES:
                if attr.encode() in data.lower():
                    self.queried_attributes[attr] += 1
                    if attr not in search_info["attributes"]:
                        search_info["attributes"].append(attr)
                        
        except Exception:
            pass

    def _parse_modification(self, idx: int, op_tag: int, data: bytes,
                           timestamp: float, src_ip: str, dst_ip: str) -> None:
        """Parse LDAP modification operations"""
        mod_type = {0x66: "Modify", 0x68: "Add", 0x6c: "ModifyDN"}.get(op_tag, "Unknown")
        
        mod_info = {
            "packet_idx": idx,
            "timestamp": timestamp,  # raw float, formatted to ISO at compile time
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "type": mod_type,
            "target_dn": None,
        }
        
        try:
            # Extract target DN
            if len(data) > 4 and data[2] == 0x04:
                dn_len = data[3]
                if 4 + dn_len <= len(data):
                    mod_info["target_dn"] = data[4:4 + dn_len].decode('utf-8', errors='ignore')
        except Exception:
            pass
        
        self.modifications.append(mod_info)

    def _detect_anomalies(self) -> None:
        """Detect LDAP security anomalies"""
        self._detect_ldap_injection()
        self._detect_enumeration()
        self._detect_sensitive_queries()
        self._detect_bind_brute_force()
        self._detect_anonymous_access()

    def _detect_ldap_injection(self) -> None:
        """Detect LDAP injection attempts"""
        for query in self.search_queries:
            filter_str = query.get("filter", "")
            for pattern in INJECTION_PATTERNS:
                if re.search(pattern, filter_str, re.IGNORECASE):
                    self.anomalies.append({
                        "type": "LDAP Injection Attempt",
                        "severity": "critical",
                        "description": f"Potential LDAP injection detected in search filter",
                        "src_ip": query.get("src_ip"),
                        "dst_ip": query.get("dst_ip"),
                        "filter_sample": filter_str[:100],
                        "packet_idx": query.get("packet_idx"),
                        "recommendation": "Block source and investigate for attack",
                    })
                    break

    def _detect_enumeration(self) -> None:
        """Detect AD enumeration attempts"""
        # Check for high volume of searches
        searches_by_source = defaultdict(list)
        for query in self.search_queries:
            searches_by_source[query.get("src_ip")].append(query)
        
        for src_ip, queries in searches_by_source.items():
            if len(queries) > 50:
                # Check for enumeration patterns
                base_dns = set(q.get("base_dn") for q in queries if q.get("base_dn"))
                scopes = set(q.get("scope") for q in queries)
                
                if "wholeSubtree" in scopes and len(base_dns) > 3:
                    self.anomalies.append({
                        "type": "AD Enumeration",
                        "severity": "high",
                        "description": f"Extensive LDAP enumeration detected from {src_ip}",
                        "src_ip": src_ip,
                        "query_count": len(queries),
                        "base_dns_targeted": list(base_dns)[:10],
                        "recommendation": "Investigate for reconnaissance activity",
                    })

    def _detect_sensitive_queries(self) -> None:
        """Detect queries for sensitive attributes"""
        sensitive_queries = defaultdict(list)
        
        for query in self.search_queries:
            for attr in query.get("attributes", []):
                if attr.lower() in SENSITIVE_ATTRIBUTES:
                    sensitive_queries[query.get("src_ip")].append({
                        "attribute": attr,
                        "timestamp": query.get("timestamp"),
                    })
        
        for src_ip, queries in sensitive_queries.items():
            if len(queries) > 5:
                attrs = set(q["attribute"] for q in queries)
                self.anomalies.append({
                    "type": "Sensitive Attribute Query",
                    "severity": "high",
                    "description": f"Queries for sensitive AD attributes detected",
                    "src_ip": src_ip,
                    "sensitive_attributes": list(attrs),
                    "query_count": len(queries),
                    "recommendation": "Review access permissions and investigate intent",
                })

    def _detect_bind_brute_force(self) -> None:
        """Detect LDAP bind brute force attempts"""
        bind_by_pair = defaultdict(list)
        
        for bind in self.bind_attempts:
            key = f"{bind.get('src_ip')}:{bind.get('dst_ip')}"
            bind_by_pair[key].append(bind)
        
        for pair, binds in bind_by_pair.items():
            failed = sum(1 for b in binds if b.get("success") == False)
            if failed > 10:
                src_ip, dst_ip = pair.split(":")
                dns_tried = set(b.get("bind_dn") for b in binds if b.get("bind_dn"))
                self.anomalies.append({
                    "type": "LDAP Bind Brute Force",
                    "severity": "high",
                    "description": f"Multiple failed bind attempts ({failed}) detected",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "failed_attempts": failed,
                    "dns_tried": list(dns_tried)[:10],
                    "recommendation": "Block source IP and check for compromised accounts",
                })

    def _detect_anonymous_access(self) -> None:
        """Detect anonymous LDAP access"""
        anonymous_binds = []
        
        for bind in self.bind_attempts:
            bind_dn = bind.get("bind_dn", "")
            if not bind_dn or bind_dn.strip() == "":
                anonymous_binds.append(bind)
        
        if anonymous_binds:
            sources = set(b.get("src_ip") for b in anonymous_binds)
            targets = set(b.get("dst_ip") for b in anonymous_binds)
            
            self.anomalies.append({
                "type": "Anonymous LDAP Bind",
                "severity": "medium",
                "description": f"Anonymous LDAP bind attempts detected ({len(anonymous_binds)} attempts)",
                "sources": list(sources)[:10],
                "targets": list(targets)[:10],
                "recommendation": "Disable anonymous LDAP access if not required",
            })
