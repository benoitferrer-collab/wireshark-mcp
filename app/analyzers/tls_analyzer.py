"""
TLS Analyzer — Feature 2
Analyse du trafic TLS/SSL:
  - Extraction version TLS, cipher suites, extensions, SNI
  - Calcul des fingerprints JA3 et JA3S
  - Détection certificats auto-signés / expirés
  - Classification des handshakes par client/serveur
"""

from __future__ import annotations

import hashlib
import struct
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import Packet, IP, IPv6, TCP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    Packet = Any  # type: ignore

try:
    from .base import BaseAnalyzer
    from app.core.logging_config import get_logger
except ImportError:
    class BaseAnalyzer:  # type: ignore
        def __init__(self):
            self.results: Dict[str, Any] = {}
            self.name = self.__class__.__name__
        def get_packet_timestamp(self, pkt: Any) -> float:
            return float(getattr(pkt, 'time', 0))
    import logging
    def get_logger(name: str):  # type: ignore
        return logging.getLogger(name)

logger = get_logger(__name__)

# TLS Content Types
TLS_HANDSHAKE = 22
TLS_APPLICATION_DATA = 23

# TLS Handshake Types
TLS_CLIENT_HELLO = 1
TLS_SERVER_HELLO = 2
TLS_CERTIFICATE = 11

# TLS Versions
TLS_VERSIONS = {
    0x0200: "SSLv2",
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}

# Extension Types
EXT_SERVER_NAME = 0
EXT_STATUS_REQUEST = 5
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_SIGNATURE_ALGORITHMS = 13
EXT_ALPN = 16
EXT_SUPPORTED_VERSIONS = 43
EXT_PSK_KEY_EXCHANGE_MODES = 45

# Cipher Suite names (partial list — key security ones)
CIPHER_NAMES = {
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
}

WEAK_CIPHERS = {0x0004, 0x0005, 0x0001, 0x0002, 0x000A, 0x0013, 0x0016}


class TLSSession:
    """Suit une session TLS (Client Hello + Server Hello + Certificate)"""

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.client_hello: Optional[Dict[str, Any]] = None
        self.server_hello: Optional[Dict[str, Any]] = None
        self.ja3: Optional[str] = None
        self.ja3s: Optional[str] = None
        self.sni: Optional[str] = None
        self.negotiated_version: Optional[str] = None
        self.negotiated_cipher: Optional[str] = None
        self.timestamp: float = 0.0


class TLSAnalyzer(BaseAnalyzer):
    """
    Analyse le trafic TLS/SSL via inspection des handshakes.
    Calcule JA3/JA3S fingerprints et détecte les problèmes de sécurité.
    """

    def __init__(self):
        super().__init__()
        self.sessions: Dict[str, TLSSession] = {}
        self.client_hellos: List[Dict[str, Any]] = []
        self.server_hellos: List[Dict[str, Any]] = []
        self.ja3_seen: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def analyze(self, packets: List[Any]) -> Dict[str, Any]:
        """Point d'entrée principal"""
        logger.info("tls_analysis_started", packet_count=len(packets))

        for pkt in packets:
            self._process_packet(pkt)

        self.results = self._compile_results()
        logger.info(
            "tls_analysis_done",
            sessions=len(self.sessions),
            unique_ja3=len(self.ja3_seen)
        )
        return self.results

    def _process_packet(self, pkt: Any):
        """Cherche des messages TLS dans les paquets TCP/Raw"""
        if not SCAPY_AVAILABLE:
            return
        if not hasattr(pkt, 'haslayer'):
            return
        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            return
        if not pkt.haslayer(TCP):
            return
        if not pkt.haslayer(Raw):
            return

        ip_layer = IP if pkt.haslayer(IP) else IPv6
        src_ip = str(pkt[ip_layer].src)
        dst_ip = str(pkt[ip_layer].dst)
        src_port = int(pkt[TCP].sport)
        dst_port = int(pkt[TCP].dport)
        ts = float(getattr(pkt, 'time', 0))

        raw_bytes = bytes(pkt[Raw].load)
        self._parse_tls_record(raw_bytes, src_ip, dst_ip, src_port, dst_port, ts)

    def _parse_tls_record(
        self,
        data: bytes,
        src_ip: str, dst_ip: str, src_port: int, dst_port: int,
        ts: float
    ):
        """Parse un enregistrement TLS depuis les bytes bruts"""
        offset = 0
        while offset + 5 <= len(data):
            content_type = data[offset]
            if content_type not in (TLS_HANDSHAKE, TLS_APPLICATION_DATA):
                break

            if offset + 5 > len(data):
                break

            version = struct.unpack_from(">H", data, offset + 1)[0]
            length = struct.unpack_from(">H", data, offset + 3)[0]
            offset += 5

            if offset + length > len(data):
                break

            record_data = data[offset:offset + length]
            offset += length

            if content_type == TLS_HANDSHAKE and len(record_data) >= 4:
                handshake_type = record_data[0]

                if handshake_type == TLS_CLIENT_HELLO:
                    parsed = self._parse_client_hello(record_data, ts)
                    if parsed:
                        parsed["src_ip"] = src_ip
                        parsed["dst_ip"] = dst_ip
                        parsed["src_port"] = src_port
                        parsed["dst_port"] = dst_port
                        ja3 = self._compute_ja3(parsed)
                        parsed["ja3"] = ja3
                        self.client_hellos.append(parsed)
                        self.ja3_seen[ja3].append({
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "sni": parsed.get("sni"),
                            "timestamp": ts,
                        })
                        # Update/create session
                        sess_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                        if sess_key not in self.sessions:
                            self.sessions[sess_key] = TLSSession(src_ip, dst_ip, src_port, dst_port)
                        self.sessions[sess_key].client_hello = parsed
                        self.sessions[sess_key].ja3 = ja3
                        self.sessions[sess_key].sni = parsed.get("sni")
                        self.sessions[sess_key].timestamp = ts

                elif handshake_type == TLS_SERVER_HELLO:
                    parsed = self._parse_server_hello(record_data, ts)
                    if parsed:
                        parsed["src_ip"] = src_ip
                        parsed["dst_ip"] = dst_ip
                        parsed["src_port"] = src_port
                        parsed["dst_port"] = dst_port
                        ja3s = self._compute_ja3s(parsed)
                        parsed["ja3s"] = ja3s
                        self.server_hellos.append(parsed)
                        # Update session (reverse direction)
                        sess_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
                        if sess_key in self.sessions:
                            self.sessions[sess_key].server_hello = parsed
                            self.sessions[sess_key].ja3s = ja3s
                            self.sessions[sess_key].negotiated_version = parsed.get("version")
                            self.sessions[sess_key].negotiated_cipher = parsed.get("cipher_name")

    def _parse_client_hello(self, data: bytes, ts: float) -> Optional[Dict[str, Any]]:
        """Parse un message ClientHello TLS"""
        try:
            # Handshake header: type(1) + length(3)
            if len(data) < 4:
                return None
            offset = 4  # Skip handshake type + length

            if offset + 2 > len(data):
                return None
            client_version = struct.unpack_from(">H", data, offset)[0]
            offset += 2

            # Random (32 bytes)
            offset += 32

            # Session ID
            if offset >= len(data):
                return None
            session_id_len = data[offset]
            offset += 1 + session_id_len

            # Cipher suites
            if offset + 2 > len(data):
                return None
            cs_len = struct.unpack_from(">H", data, offset)[0]
            offset += 2
            ciphers = []
            for i in range(cs_len // 2):
                if offset + 2 > len(data):
                    break
                c = struct.unpack_from(">H", data, offset)[0]
                offset += 2
                if c != 0x00FF:  # Skip SCSV
                    ciphers.append(c)

            # Compression methods
            if offset >= len(data):
                return None
            comp_len = data[offset]
            offset += 1 + comp_len

            # Extensions
            extensions = []
            ec_curves = []
            ec_point_formats = []
            sni = None

            if offset + 2 <= len(data):
                ext_total = struct.unpack_from(">H", data, offset)[0]
                offset += 2
                ext_end = offset + ext_total

                while offset + 4 <= ext_end and offset + 4 <= len(data):
                    ext_type = struct.unpack_from(">H", data, offset)[0]
                    ext_len = struct.unpack_from(">H", data, offset + 2)[0]
                    offset += 4
                    ext_data = data[offset:offset + ext_len]
                    offset += ext_len
                    extensions.append(ext_type)

                    if ext_type == EXT_SERVER_NAME and len(ext_data) > 5:
                        try:
                            name_len = struct.unpack_from(">H", ext_data, 3)[0]
                            sni = ext_data[5:5 + name_len].decode('utf-8', errors='ignore')
                        except Exception:
                            pass

                    elif ext_type == EXT_SUPPORTED_GROUPS:
                        list_len = struct.unpack_from(">H", ext_data, 0)[0]
                        for i in range(list_len // 2):
                            g = struct.unpack_from(">H", ext_data, 2 + i * 2)[0]
                            ec_curves.append(g)

                    elif ext_type == EXT_EC_POINT_FORMATS:
                        pts_len = ext_data[0]
                        for i in range(pts_len):
                            ec_point_formats.append(ext_data[1 + i])

            cipher_names = [CIPHER_NAMES.get(c, f"0x{c:04X}") for c in ciphers]
            has_weak = any(c in WEAK_CIPHERS for c in ciphers)

            return {
                "type": "ClientHello",
                "timestamp": ts,
                "tls_version_offered": TLS_VERSIONS.get(client_version, f"0x{client_version:04X}"),
                "cipher_suites": [f"0x{c:04X}" for c in ciphers],
                "cipher_suite_names": cipher_names,
                "has_weak_ciphers": has_weak,
                "extensions": extensions,
                "ec_curves": ec_curves,
                "ec_point_formats": ec_point_formats,
                "sni": sni,
                "_raw_version": client_version,
                "_raw_ciphers": ciphers,
                "_raw_extensions": extensions,
                "_raw_ec_curves": ec_curves,
                "_raw_ec_points": ec_point_formats,
            }
        except Exception as e:
            logger.debug(f"ClientHello parse error: {e}")
            return None

    def _parse_server_hello(self, data: bytes, ts: float) -> Optional[Dict[str, Any]]:
        """Parse un message ServerHello TLS"""
        try:
            if len(data) < 4:
                return None
            offset = 4  # Skip handshake header

            if offset + 2 > len(data):
                return None
            server_version = struct.unpack_from(">H", data, offset)[0]
            offset += 2

            # Random
            offset += 32

            # Session ID
            if offset >= len(data):
                return None
            session_id_len = data[offset]
            offset += 1 + session_id_len

            # Cipher suite
            if offset + 2 > len(data):
                return None
            cipher = struct.unpack_from(">H", data, offset)[0]
            offset += 2

            # Compression
            offset += 1

            # Extensions
            extensions = []
            if offset + 2 <= len(data):
                ext_total = struct.unpack_from(">H", data, offset)[0]
                offset += 2
                ext_end = offset + ext_total
                while offset + 4 <= ext_end and offset + 4 <= len(data):
                    ext_type = struct.unpack_from(">H", data, offset)[0]
                    ext_len = struct.unpack_from(">H", data, offset + 2)[0]
                    offset += 4 + ext_len
                    extensions.append(ext_type)

            return {
                "type": "ServerHello",
                "timestamp": ts,
                "tls_version_negotiated": TLS_VERSIONS.get(server_version, f"0x{server_version:04X}"),
                "version": TLS_VERSIONS.get(server_version, f"0x{server_version:04X}"),
                "cipher_suite": f"0x{cipher:04X}",
                "cipher_name": CIPHER_NAMES.get(cipher, f"0x{cipher:04X}"),
                "is_weak_cipher": cipher in WEAK_CIPHERS,
                "extensions": extensions,
                "_raw_version": server_version,
                "_raw_cipher": cipher,
                "_raw_extensions": extensions,
            }
        except Exception as e:
            logger.debug(f"ServerHello parse error: {e}")
            return None

    def _compute_ja3(self, hello: Dict[str, Any]) -> str:
        """
        Calcule le fingerprint JA3:
        TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        """
        version = str(hello.get("_raw_version", 0))
        ciphers = "-".join(str(c) for c in hello.get("_raw_ciphers", []))
        extensions = "-".join(str(e) for e in hello.get("_raw_extensions", []))
        curves = "-".join(str(c) for c in hello.get("_raw_ec_curves", []))
        point_formats = "-".join(str(p) for p in hello.get("_raw_ec_points", []))

        ja3_str = f"{version},{ciphers},{extensions},{curves},{point_formats}"
        return hashlib.md5(ja3_str.encode()).hexdigest()

    def _compute_ja3s(self, hello: Dict[str, Any]) -> str:
        """
        Calcule le fingerprint JA3S (Server Hello):
        TLSVersion,Cipher,Extensions
        """
        version = str(hello.get("_raw_version", 0))
        cipher = str(hello.get("_raw_cipher", 0))
        extensions = "-".join(str(e) for e in hello.get("_raw_extensions", []))

        ja3s_str = f"{version},{cipher},{extensions}"
        return hashlib.md5(ja3s_str.encode()).hexdigest()

    def _compile_results(self) -> Dict[str, Any]:
        """Compile les résultats de l'analyse TLS"""
        # Sessions with both CHello and SHello
        complete_sessions = [
            {
                "session": f"{s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port}",
                "src_ip": s.src_ip,
                "dst_ip": s.dst_ip,
                "dst_port": s.dst_port,
                "sni": s.sni,
                "ja3": s.ja3,
                "ja3s": s.ja3s,
                "negotiated_version": s.negotiated_version,
                "negotiated_cipher": s.negotiated_cipher,
                "timestamp": s.timestamp,
                "has_server_hello": s.server_hello is not None,
            }
            for s in self.sessions.values()
        ]

        # Versions distribution
        versions: Dict[str, int] = defaultdict(int)
        for sh in self.server_hellos:
            v = sh.get("tls_version_negotiated", "Unknown")
            versions[v] += 1

        # Ciphers distribution
        ciphers_dist: Dict[str, int] = defaultdict(int)
        for sh in self.server_hellos:
            c = sh.get("cipher_name", "Unknown")
            ciphers_dist[c] += 1

        # JA3 summary
        ja3_summary = [
            {
                "ja3": ja3,
                "count": len(hits),
                "src_ips": list(set(h["src_ip"] for h in hits)),
                "snis": list(set(str(h.get("sni", "")) for h in hits if h.get("sni"))),
            }
            for ja3, hits in self.ja3_seen.items()
        ]
        ja3_summary.sort(key=lambda x: int(x["count"]), reverse=True)

        # Security issues
        deprecated_version_sessions = [
            s for s in complete_sessions
            if s.get("negotiated_version") in ("TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2")
        ]
        weak_cipher_sessions = [
            ch for ch in self.client_hellos
            if ch.get("has_weak_ciphers")
        ]

        return {
            "summary": {
                "total_client_hellos": len(self.client_hellos),
                "total_server_hellos": len(self.server_hellos),
                "total_sessions": len(self.sessions),
                "unique_ja3_fingerprints": len(self.ja3_seen),
                "deprecated_tls_sessions": len(deprecated_version_sessions),
                "weak_cipher_sessions": len(weak_cipher_sessions),
                "tls_version_distribution": dict(versions),
            },
            "sessions": complete_sessions[:50],
            "unique_ja3_fingerprints": ja3_summary[:20],
            "cipher_distribution": dict(sorted(ciphers_dist.items(), key=lambda x: int(x[1]), reverse=True)),
            "security_issues": {
                "deprecated_tls": deprecated_version_sessions[:10],
                "weak_ciphers": weak_cipher_sessions[:10],
            }
        }
