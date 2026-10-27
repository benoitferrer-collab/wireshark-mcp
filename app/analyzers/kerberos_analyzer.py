"""
Kerberos Protocol Analyzer
Analyzes Kerberos traffic for authentication and security threats
Detects: Golden Ticket, Silver Ticket, Kerberoasting, AS-REP Roasting
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


# Kerberos Ports
KERBEROS_PORTS = {88, 464}  # Kerberos, Kerberos password change

# Kerberos Message Types
KRB_MSG_TYPES = {
    10: "AS-REQ",      # Authentication Service Request
    11: "AS-REP",      # Authentication Service Response
    12: "TGS-REQ",     # Ticket Granting Service Request
    13: "TGS-REP",     # Ticket Granting Service Response
    14: "AP-REQ",      # Application Request
    15: "AP-REP",      # Application Response
    20: "KRB-SAFE",    # Safe (integrity-protected)
    21: "KRB-PRIV",    # Private (encrypted)
    22: "KRB-CRED",    # Credential forwarding
    30: "KRB-ERROR",   # Error response
}

# Kerberos Error Codes
KRB_ERROR_CODES = {
    0: "KDC_ERR_NONE",
    1: "KDC_ERR_NAME_EXP",
    2: "KDC_ERR_SERVICE_EXP",
    3: "KDC_ERR_BAD_PVNO",
    4: "KDC_ERR_C_OLD_MAST_KVNO",
    5: "KDC_ERR_S_OLD_MAST_KVNO",
    6: "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    7: "KDC_ERR_S_PRINCIPAL_UNKNOWN",
    8: "KDC_ERR_PRINCIPAL_NOT_UNIQUE",
    9: "KDC_ERR_NULL_KEY",
    10: "KDC_ERR_CANNOT_POSTDATE",
    11: "KDC_ERR_NEVER_VALID",
    12: "KDC_ERR_POLICY",
    13: "KDC_ERR_BADOPTION",
    14: "KDC_ERR_ETYPE_NOSUPP",
    15: "KDC_ERR_SUMTYPE_NOSUPP",
    16: "KDC_ERR_PADATA_TYPE_NOSUPP",
    17: "KDC_ERR_TRTYPE_NOSUPP",
    18: "KDC_ERR_CLIENT_REVOKED",
    19: "KDC_ERR_SERVICE_REVOKED",
    20: "KDC_ERR_TGT_REVOKED",
    21: "KDC_ERR_CLIENT_NOTYET",
    22: "KDC_ERR_SERVICE_NOTYET",
    23: "KDC_ERR_KEY_EXPIRED",
    24: "KDC_ERR_PREAUTH_FAILED",
    25: "KDC_ERR_PREAUTH_REQUIRED",
    26: "KDC_ERR_SERVER_NOMATCH",
    27: "KDC_ERR_MUST_USE_USER2USER",
    31: "KRB_AP_ERR_BAD_INTEGRITY",
    32: "KRB_AP_ERR_TKT_EXPIRED",
    33: "KRB_AP_ERR_TKT_NYV",
    34: "KRB_AP_ERR_REPEAT",
    35: "KRB_AP_ERR_NOT_US",
    36: "KRB_AP_ERR_BADMATCH",
    37: "KRB_AP_ERR_SKEW",
    38: "KRB_AP_ERR_BADADDR",
    39: "KRB_AP_ERR_BADVERSION",
    40: "KRB_AP_ERR_MSG_TYPE",
    41: "KRB_AP_ERR_MODIFIED",
    42: "KRB_AP_ERR_BADORDER",
    44: "KRB_AP_ERR_BADKEYVER",
    45: "KRB_AP_ERR_NOKEY",
    46: "KRB_AP_ERR_MUT_FAIL",
    47: "KRB_AP_ERR_BADDIRECTION",
    48: "KRB_AP_ERR_METHOD",
    49: "KRB_AP_ERR_BADSEQ",
    50: "KRB_AP_ERR_INAPP_CKSUM",
    60: "KRB_ERR_GENERIC",
    61: "KRB_ERR_FIELD_TOOLONG",
    62: "KDC_ERR_CLIENT_NOT_TRUSTED",
    63: "KDC_ERR_KDC_NOT_TRUSTED",
    64: "KDC_ERR_INVALID_SIG",
    68: "KDC_ERR_WRONG_REALM",
    69: "KRB_AP_ERR_USER_TO_USER_REQUIRED",
}

# Encryption Types
ENCRYPTION_TYPES = {
    1: "des-cbc-crc",
    3: "des-cbc-md5",
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    23: "rc4-hmac",  # Often targeted in attacks
    24: "rc4-hmac-exp",
}


class KerberosAnalyzer(BaseAnalyzer):
    """Analyzer for Kerberos protocol traffic"""

    def __init__(self):
        super().__init__()
        self.as_requests: List[Dict] = []
        self.as_responses: List[Dict] = []
        self.tgs_requests: List[Dict] = []
        self.tgs_responses: List[Dict] = []
        self.errors: List[Dict] = []
        self.message_types: Dict[str, int] = defaultdict(int)
        self.encryption_types: Dict[str, int] = defaultdict(int)
        self.principals: Dict[str, Dict] = {}
        self.services: Dict[str, int] = defaultdict(int)
        self.realms: Dict[str, int] = defaultdict(int)
        self.anomalies: List[Dict] = []

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """Analyze Kerberos traffic"""
        self.reset()
        logger.info("kerberos_analysis_started", packet_count=len(packets))
        
        krb_packets = []
        for idx, packet in enumerate(packets):
            if self._is_kerberos_packet(packet):
                krb_packets.append((idx, packet))
                self._process_kerberos_packet(idx, packet)
        
        # Detect security anomalies
        self._detect_anomalies()

        # Format float timestamps to ISO once, only for records included in results
        as_requests = self.as_requests[:100]
        as_responses = self.as_responses[:100]
        tgs_requests = self.tgs_requests[:200]
        tgs_responses = self.tgs_responses[:100]
        errors = self.errors[:100]
        for record in as_requests + as_responses + tgs_requests + tgs_responses + errors:
            record["timestamp"] = _iso(record["timestamp"])

        principals = list(self.principals.values())[:100]
        for principal in principals:
            principal["first_seen"] = _iso(principal["first_seen"])
            principal["last_seen"] = _iso(principal["last_seen"])

        self.results = {
            "summary": {
                "total_packets": len(krb_packets),
                "total_as_requests": len(self.as_requests),
                "total_as_responses": len(self.as_responses),
                "total_tgs_requests": len(self.tgs_requests),
                "total_tgs_responses": len(self.tgs_responses),
                "total_errors": len(self.errors),
                "total_anomalies": len(self.anomalies),
            },
            "as_requests": as_requests,
            "as_responses": as_responses,
            "tgs_requests": tgs_requests,
            "tgs_responses": tgs_responses,
            "errors": errors,
            "message_types": dict(self.message_types),
            "encryption_types": dict(self.encryption_types),
            "principals": principals,
            "services": dict(sorted(self.services.items(), key=lambda x: x[1], reverse=True)[:50]),
            "realms": dict(self.realms),
            "anomalies": self.anomalies,
        }
        
        logger.info("kerberos_analysis_completed", 
                   packets=len(krb_packets),
                   as_requests=len(self.as_requests),
                   tgs_requests=len(self.tgs_requests))
        return self.results

    def reset(self):
        """Reset analyzer state"""
        super().reset()
        self.as_requests = []
        self.as_responses = []
        self.tgs_requests = []
        self.tgs_responses = []
        self.errors = []
        self.message_types = defaultdict(int)
        self.encryption_types = defaultdict(int)
        self.principals = {}
        self.services = defaultdict(int)
        self.realms = defaultdict(int)
        self.anomalies = []

    def _is_kerberos_packet(self, packet: Packet) -> bool:
        """Check if packet is Kerberos traffic"""
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.sport in KERBEROS_PORTS or tcp.dport in KERBEROS_PORTS:
                return packet.haslayer(Raw)
        if packet.haslayer(UDP):
            udp = packet[UDP]
            if udp.sport in KERBEROS_PORTS or udp.dport in KERBEROS_PORTS:
                return packet.haslayer(Raw)
        return False

    def _process_kerberos_packet(self, idx: int, packet: Packet) -> None:
        """Process individual Kerberos packet"""
        try:
            raw_data = bytes(packet[Raw].load)
            timestamp = self.get_packet_timestamp(packet)
            src_ip, dst_ip = self.get_ip_pair(packet)
            
            # Parse Kerberos ASN.1 data
            self._parse_kerberos_message(idx, raw_data, timestamp, src_ip, dst_ip)
            
        except Exception as e:
            logger.debug(f"Error processing Kerberos packet: {e}")

    def _parse_kerberos_message(self, idx: int, data: bytes, timestamp: float,
                                src_ip: str, dst_ip: str) -> None:
        """Parse Kerberos ASN.1 message"""
        try:
            if len(data) < 4:
                return
            
            # Kerberos messages are ASN.1 DER encoded
            # Application tags: 0x6a (AS-REQ=10), 0x6b (AS-REP=11), etc.
            offset = 0
            
            # Check for TCP length prefix
            if data[0:2] == b'\x00\x00' or (data[0] == 0 and len(data) > 4):
                offset = 4  # Skip TCP length field
            
            if offset >= len(data):
                return
            
            # Look for Kerberos application tag
            tag = data[offset]
            if tag < 0x60 or tag > 0x7f:
                return
            
            msg_type = tag - 0x60
            msg_name = KRB_MSG_TYPES.get(msg_type, f"Unknown_{msg_type}")
            self.message_types[msg_name] += 1
            
            msg_data = data[offset:]
            
            if msg_type == 10:  # AS-REQ
                self._parse_as_request(idx, msg_data, timestamp, src_ip, dst_ip)
            elif msg_type == 11:  # AS-REP
                self._parse_as_response(idx, msg_data, timestamp, src_ip, dst_ip)
            elif msg_type == 12:  # TGS-REQ
                self._parse_tgs_request(idx, msg_data, timestamp, src_ip, dst_ip)
            elif msg_type == 13:  # TGS-REP
                self._parse_tgs_response(idx, msg_data, timestamp, src_ip, dst_ip)
            elif msg_type == 30:  # KRB-ERROR
                self._parse_error(idx, msg_data, timestamp, src_ip, dst_ip)
                
        except Exception as e:
            logger.debug(f"Error parsing Kerberos message: {e}")

    def _parse_as_request(self, idx: int, data: bytes, timestamp: float,
                          src_ip: str, dst_ip: str) -> None:
        """Parse AS-REQ (TGT request)"""
        as_req = {
            "packet_idx": idx,
            "timestamp": timestamp,  # raw float, formatted to ISO at compile time
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "client_principal": None,
            "realm": None,
            "requested_etypes": [],
            "has_preauth": False,
            "preauth_type": None,
        }
        
        try:
            # Extract principal names and realm
            self._extract_principal_info(data, as_req)
            
            # Extract encryption types
            self._extract_encryption_types(data, as_req)
            
            # Check for pre-authentication
            if b'\xa2' in data or b'\xa3' in data:  # PA-DATA tags
                as_req["has_preauth"] = True
                
            # Track principal
            if as_req.get("client_principal"):
                principal = as_req["client_principal"]
                if principal not in self.principals:
                    self.principals[principal] = {
                        "name": principal,
                        "realm": as_req.get("realm"),
                        "first_seen": as_req["timestamp"],
                        "last_seen": as_req["timestamp"],
                        "as_req_count": 0,
                        "tgs_req_count": 0,
                        "error_count": 0,
                        "sources": [],
                    }
                self.principals[principal]["as_req_count"] += 1
                self.principals[principal]["last_seen"] = as_req["timestamp"]
                if src_ip not in self.principals[principal]["sources"]:
                    self.principals[principal]["sources"].append(src_ip)
                    
        except Exception as e:
            logger.debug(f"Error parsing AS-REQ: {e}")
        
        self.as_requests.append(as_req)

    def _parse_as_response(self, idx: int, data: bytes, timestamp: float,
                           src_ip: str, dst_ip: str) -> None:
        """Parse AS-REP (TGT response)"""
        as_rep = {
            "packet_idx": idx,
            "timestamp": timestamp,  # raw float, formatted to ISO at compile time
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "client_principal": None,
            "realm": None,
            "ticket_etype": None,
        }
        
        try:
            self._extract_principal_info(data, as_rep)
            
            # Try to extract ticket encryption type
            self._extract_ticket_etype(data, as_rep)
            
        except Exception as e:
            logger.debug(f"Error parsing AS-REP: {e}")
        
        self.as_responses.append(as_rep)

    def _parse_tgs_request(self, idx: int, data: bytes, timestamp: float,
                           src_ip: str, dst_ip: str) -> None:
        """Parse TGS-REQ (Service ticket request)"""
        tgs_req = {
            "packet_idx": idx,
            "timestamp": timestamp,  # raw float, formatted to ISO at compile time
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "client_principal": None,
            "service_principal": None,
            "realm": None,
            "requested_etypes": [],
        }
        
        try:
            self._extract_principal_info(data, tgs_req)
            self._extract_service_principal(data, tgs_req)
            self._extract_encryption_types(data, tgs_req)
            
            # Track service requests
            if tgs_req.get("service_principal"):
                service = tgs_req["service_principal"]
                self.services[service] += 1
                
            # Track principal
            if tgs_req.get("client_principal"):
                principal = tgs_req["client_principal"]
                if principal in self.principals:
                    self.principals[principal]["tgs_req_count"] += 1
                    self.principals[principal]["last_seen"] = tgs_req["timestamp"]
                    
        except Exception as e:
            logger.debug(f"Error parsing TGS-REQ: {e}")
        
        self.tgs_requests.append(tgs_req)

    def _parse_tgs_response(self, idx: int, data: bytes, timestamp: float,
                            src_ip: str, dst_ip: str) -> None:
        """Parse TGS-REP (Service ticket response)"""
        tgs_rep = {
            "packet_idx": idx,
            "timestamp": timestamp,  # raw float, formatted to ISO at compile time
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "service_principal": None,
            "realm": None,
            "ticket_etype": None,
        }
        
        try:
            self._extract_principal_info(data, tgs_rep)
            self._extract_service_principal(data, tgs_rep)
            self._extract_ticket_etype(data, tgs_rep)
        except Exception as e:
            logger.debug(f"Error parsing TGS-REP: {e}")
        
        self.tgs_responses.append(tgs_rep)

    def _parse_error(self, idx: int, data: bytes, timestamp: float,
                     src_ip: str, dst_ip: str) -> None:
        """Parse KRB-ERROR"""
        error = {
            "packet_idx": idx,
            "timestamp": timestamp,  # raw float, formatted to ISO at compile time
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "error_code": None,
            "error_name": None,
            "client_principal": None,
            "service_principal": None,
            "realm": None,
        }
        
        try:
            # Look for error code (usually in a specific position)
            for i in range(len(data) - 3):
                if data[i:i+2] == b'\xa6\x03\x02\x01':  # Error code tag
                    error["error_code"] = data[i + 4]
                    error["error_name"] = KRB_ERROR_CODES.get(data[i + 4], "Unknown")
                    break
            
            self._extract_principal_info(data, error)
            self._extract_service_principal(data, error)
            
            # Track errors for principals
            if error.get("client_principal") and error["client_principal"] in self.principals:
                self.principals[error["client_principal"]]["error_count"] += 1
                
        except Exception as e:
            logger.debug(f"Error parsing KRB-ERROR: {e}")
        
        self.errors.append(error)

    def _extract_principal_info(self, data: bytes, info: Dict) -> None:
        """Extract principal name and realm from Kerberos data"""
        try:
            # Look for realm (GeneralString after tag 0xa1 or 0xa9)
            realm_patterns = [b'\xa1.*?\x1b', b'\xa9.*?\x1b', b'\x1b']
            for pattern in realm_patterns:
                match = re.search(pattern, data)
                if match:
                    start = match.end()
                    if start < len(data) - 1:
                        length = data[start]
                        if start + 1 + length <= len(data):
                            realm = data[start + 1:start + 1 + length].decode('utf-8', errors='ignore')
                            if realm and len(realm) > 1:
                                info["realm"] = realm
                                self.realms[realm] += 1
                                break
            
            # Look for principal name components
            # PrincipalName is SEQUENCE of GeneralString
            name_parts = []
            for i in range(len(data) - 2):
                if data[i] == 0x1b:  # GeneralString tag
                    length = data[i + 1]
                    if i + 2 + length <= len(data):
                        part = data[i + 2:i + 2 + length].decode('utf-8', errors='ignore')
                        if part and len(part) > 0 and len(part) < 100:
                            # Filter out likely realm names
                            if '.' not in part or info.get("realm") != part:
                                name_parts.append(part)
            
            if name_parts:
                # First unique name is usually client/service principal
                seen = set()
                unique_parts = []
                for p in name_parts:
                    if p not in seen and p != info.get("realm"):
                        seen.add(p)
                        unique_parts.append(p)
                
                if unique_parts:
                    info["client_principal"] = unique_parts[0]
                    if len(unique_parts) > 1:
                        info["service_principal"] = unique_parts[1]
                        
        except Exception as e:
            logger.debug(f"Error extracting principal info: {e}")

    def _extract_service_principal(self, data: bytes, info: Dict) -> None:
        """Extract service principal name"""
        try:
            # Look for service patterns like HTTP/, CIFS/, MSSQLSvc/, etc.
            service_patterns = [
                b'HTTP/', b'CIFS/', b'MSSQLSvc/', b'LDAP/', b'HOST/',
                b'krbtgt/', b'TERMSRV/', b'WSMAN/', b'DNS/',
            ]
            
            for pattern in service_patterns:
                idx = data.find(pattern)
                if idx != -1:
                    # Extract until null or non-printable
                    end = idx
                    while end < len(data) and data[end] >= 0x20 and data[end] < 0x7f:
                        end += 1
                    service = data[idx:end].decode('utf-8', errors='ignore')
                    if service:
                        info["service_principal"] = service
                        break
                        
        except Exception as e:
            logger.debug(f"Error extracting service principal: {e}")

    def _extract_encryption_types(self, data: bytes, info: Dict) -> None:
        """Extract requested encryption types"""
        try:
            # Look for SEQUENCE of INTEGER (etype list)
            etypes = []
            for i in range(len(data) - 2):
                if data[i] == 0x02 and data[i + 1] == 0x01:  # INTEGER of length 1
                    etype = data[i + 2]
                    if etype in ENCRYPTION_TYPES or etype < 30:
                        etype_name = ENCRYPTION_TYPES.get(etype, f"etype_{etype}")
                        etypes.append(etype_name)
                        self.encryption_types[etype_name] += 1
            
            info["requested_etypes"] = list(set(etypes))[:10]
            
        except Exception as e:
            logger.debug(f"Error extracting encryption types: {e}")

    def _extract_ticket_etype(self, data: bytes, info: Dict) -> None:
        """Extract ticket encryption type"""
        try:
            # Look for etype in encrypted data section
            for i in range(len(data) - 4):
                if data[i:i+2] == b'\xa0\x03\x02\x01':  # etype tag
                    etype = data[i + 4]
                    info["ticket_etype"] = ENCRYPTION_TYPES.get(etype, f"etype_{etype}")
                    break
        except Exception:
            pass

    def _detect_anomalies(self) -> None:
        """Detect Kerberos security anomalies"""
        self._detect_kerberoasting()
        self._detect_asrep_roasting()
        self._detect_golden_ticket()
        self._detect_silver_ticket()
        self._detect_brute_force()
        self._detect_weak_encryption()

    def _detect_kerberoasting(self) -> None:
        """Detect Kerberoasting attacks (mass TGS requests with RC4)"""
        # Group TGS requests by source
        tgs_by_source = defaultdict(list)
        for tgs in self.tgs_requests:
            tgs_by_source[tgs.get("src_ip")].append(tgs)
        
        for src_ip, requests in tgs_by_source.items():
            # Check for high volume of service ticket requests
            unique_services = set(r.get("service_principal") for r in requests if r.get("service_principal"))
            
            # Check if RC4 (etype 23) is requested
            rc4_requests = sum(1 for r in requests if "rc4-hmac" in r.get("requested_etypes", []))
            
            if len(unique_services) > 10 or (len(unique_services) > 5 and rc4_requests > 3):
                self.anomalies.append({
                    "type": "Potential Kerberoasting",
                    "severity": "critical",
                    "description": f"Mass TGS requests for {len(unique_services)} services detected",
                    "src_ip": src_ip,
                    "service_count": len(unique_services),
                    "services_sample": list(unique_services)[:10],
                    "rc4_requests": rc4_requests,
                    "recommendation": "Investigate for credential theft attempt on service accounts",
                    "mitre_attack": "T1558.003",
                })

    def _detect_asrep_roasting(self) -> None:
        """Detect AS-REP Roasting (requests without pre-auth)"""
        # Look for AS-REQ without pre-authentication
        no_preauth = defaultdict(list)
        
        for as_req in self.as_requests:
            if not as_req.get("has_preauth"):
                no_preauth[as_req.get("src_ip")].append(as_req)
        
        for src_ip, requests in no_preauth.items():
            if len(requests) > 5:
                principals = set(r.get("client_principal") for r in requests if r.get("client_principal"))
                self.anomalies.append({
                    "type": "Potential AS-REP Roasting",
                    "severity": "high",
                    "description": f"Multiple AS-REQ without pre-auth from {src_ip}",
                    "src_ip": src_ip,
                    "request_count": len(requests),
                    "principals_targeted": list(principals)[:10],
                    "recommendation": "Enable Kerberos pre-authentication for all accounts",
                    "mitre_attack": "T1558.004",
                })

    def _detect_golden_ticket(self) -> None:
        """Detect potential Golden Ticket usage"""
        # Golden tickets often show unusual patterns:
        # - TGS requests without corresponding AS-REQ
        # - Long ticket lifetimes
        # - Unusual encryption types
        
        as_req_sources = set(r.get("src_ip") for r in self.as_requests)
        
        for tgs in self.tgs_requests:
            src_ip = tgs.get("src_ip")
            # Check if TGS-REQ came from a source with no AS-REQ
            if src_ip not in as_req_sources and tgs.get("service_principal"):
                # Check for krbtgt service (TGT renewal)
                if "krbtgt" in (tgs.get("service_principal") or "").lower():
                    self.anomalies.append({
                        "type": "Potential Golden Ticket",
                        "severity": "critical",
                        "description": f"TGS-REQ for krbtgt without prior AS-REQ",
                        "src_ip": src_ip,
                        "service": tgs.get("service_principal"),
                        "timestamp": _iso(tgs["timestamp"]),  # tgs holds a raw float timestamp
                        "recommendation": "Investigate for Golden Ticket attack - reset krbtgt password twice",
                        "mitre_attack": "T1558.001",
                    })

    def _detect_silver_ticket(self) -> None:
        """Detect potential Silver Ticket usage"""
        # Silver tickets bypass the KDC entirely
        # Look for service access without TGS requests to KDC
        
        tgs_services = set()
        for tgs in self.tgs_requests:
            if tgs.get("service_principal"):
                tgs_services.add(tgs.get("service_principal").lower())
        
        # This requires correlation with service access logs
        # For now, flag suspicious patterns
        for principal, info in self.principals.items():
            if info.get("tgs_req_count", 0) == 0 and info.get("error_count", 0) > 3:
                self.anomalies.append({
                    "type": "Suspicious Kerberos Pattern",
                    "severity": "medium",
                    "description": f"Principal {principal} has errors but no TGS requests",
                    "principal": principal,
                    "error_count": info.get("error_count"),
                    "recommendation": "Verify legitimate authentication flow",
                })

    def _detect_brute_force(self) -> None:
        """Detect Kerberos brute force attempts"""
        # Look for high error rates from single source
        errors_by_source = defaultdict(list)
        
        for error in self.errors:
            errors_by_source[error.get("dst_ip")].append(error)  # dst_ip because errors come from KDC
        
        for dst_ip, errs in errors_by_source.items():
            # Count specific error types
            preauth_failed = sum(1 for e in errs if e.get("error_code") == 24)
            client_unknown = sum(1 for e in errs if e.get("error_code") == 6)
            
            if preauth_failed > 10:
                principals = set(e.get("client_principal") for e in errs if e.get("error_code") == 24)
                self.anomalies.append({
                    "type": "Kerberos Brute Force",
                    "severity": "high",
                    "description": f"Multiple pre-auth failures ({preauth_failed}) detected",
                    "kdc": dst_ip,
                    "failed_attempts": preauth_failed,
                    "principals_targeted": list(principals)[:10],
                    "recommendation": "Block source and investigate credential guessing",
                })
            
            if client_unknown > 20:
                self.anomalies.append({
                    "type": "User Enumeration",
                    "severity": "medium",
                    "description": f"Multiple 'client unknown' errors ({client_unknown}) - possible enumeration",
                    "kdc": dst_ip,
                    "error_count": client_unknown,
                    "recommendation": "Investigate for user enumeration attack",
                })

    def _detect_weak_encryption(self) -> None:
        """Detect use of weak encryption types"""
        weak_etypes = ["rc4-hmac", "des-cbc-crc", "des-cbc-md5"]
        
        weak_usage = defaultdict(int)
        for etype, count in self.encryption_types.items():
            if any(weak in etype.lower() for weak in ["rc4", "des"]):
                weak_usage[etype] = count
        
        if weak_usage:
            total_weak = sum(weak_usage.values())
            total_all = sum(self.encryption_types.values())
            
            if total_weak > 0 and total_weak / max(total_all, 1) > 0.3:
                self.anomalies.append({
                    "type": "Weak Kerberos Encryption",
                    "severity": "medium",
                    "description": f"High usage of weak encryption types ({total_weak}/{total_all} requests)",
                    "weak_types": dict(weak_usage),
                    "recommendation": "Disable RC4 and DES encryption in domain policy",
                })
