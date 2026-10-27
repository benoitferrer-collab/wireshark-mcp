"""
Flow Behavior Analyzer — Feature 1
Détection comportementale:
  - Beaconing C2 (intervalles réguliers, jitter, tailles fixes)
  - Exfiltration lente (ratio upload/download anormal)
  - Flow fingerprinting (empreinte comportementale par flux)
"""

from __future__ import annotations

import math
import hashlib
from typing import Dict, Any, List, Tuple, Optional, Union
from collections import defaultdict
from dataclasses import dataclass, field

try:
    from scapy.all import Packet, IP, IPv6, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    Packet = Any  # type: ignore

try:
    from .base import BaseAnalyzer
    from app.core.logging_config import get_logger
except ImportError:
    # Fallback minimal pour les tests unitaires hors container
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


# Seuils de détection
BEACONING_MIN_PACKETS = 8
BEACONING_REGULARITY_THRESHOLD = 0.80
JITTER_MAX_RATIO = 0.25
EXFIL_RATIO_THRESHOLD = 5.0
EXFIL_MIN_BYTES = 50_000


class FlowKey:
    """Clé bidirectionnelle pour identifier un flux réseau"""

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto

    def __hash__(self) -> int:
        return hash((
            tuple(sorted([self.src_ip, self.dst_ip])),
            tuple(sorted([self.src_port, self.dst_port])),
            self.proto
        ))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FlowKey):
            return False
        return hash(self) == hash(other)

    def to_str(self) -> str:
        return f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port} [{self.proto}]"


class FlowStats:
    """Statistiques d'un flux réseau"""

    def __init__(self, key: FlowKey, first_seen: float = 0.0):
        self.key = key
        self.packets_out: List[Tuple[float, int]] = []   # (timestamp, size) src→dst
        self.packets_in: List[Tuple[float, int]] = []    # (timestamp, size) dst→src
        self.first_seen: float = first_seen
        self.last_seen: float = first_seen

    @property
    def bytes_out(self) -> int:
        return sum(s for _, s in self.packets_out)

    @property
    def bytes_in(self) -> int:
        return sum(s for _, s in self.packets_in)

    @property
    def total_packets(self) -> int:
        return len(self.packets_out) + len(self.packets_in)


class FlowBehaviorAnalyzer(BaseAnalyzer):
    """
    Analyse comportementale des flux réseau:
    - Détection de beaconing C2 (régularité d'intervalles)
    - Détection d'exfiltration (ratio upload/download)
    - Flow fingerprinting (empreinte comportementale)
    """

    def __init__(self):
        super().__init__()
        self.flows: Dict[int, FlowStats] = {}  # keyed by hash(FlowKey)
        self.flow_keys: Dict[int, FlowKey] = {}
        self.beaconing_alerts: List[Dict[str, Any]] = []
        self.exfiltration_alerts: List[Dict[str, Any]] = []
        self.flow_fingerprints: List[Dict[str, Any]] = []

    def analyze(self, packets: List[Any]) -> Dict[str, Any]:
        """Point d'entrée principal de l'analyseur"""
        logger.info("flow_behavior_analysis_started", packet_count=len(packets))

        # Phase 1: Construction des flux
        for pkt in packets:
            self._process_packet(pkt)

        # Phase 2: Analyse comportementale
        for h, stats in self.flows.items():
            if stats.total_packets < BEACONING_MIN_PACKETS:
                continue
            key = self.flow_keys[h]
            self._detect_beaconing(key, stats)
            self._detect_exfiltration(key, stats)
            self._compute_fingerprint(key, stats)

        # Phase 3: Compilation des résultats
        self.results = self._compile_results()
        logger.info(
            "flow_behavior_analysis_done",
            flows=len(self.flows),
            beaconing_alerts=len(self.beaconing_alerts),
            exfil_alerts=len(self.exfiltration_alerts)
        )
        return self.results

    # ─────────────────────────────────────
    # Internal — Packet processing
    # ─────────────────────────────────────

    def _process_packet(self, pkt: Any):
        """Extrait les métriques d'un paquet et les ajoute au flux correspondant"""
        if not SCAPY_AVAILABLE:
            return

        has_ip = pkt.haslayer(IP) if hasattr(pkt, 'haslayer') else False
        has_ipv6 = pkt.haslayer(IPv6) if hasattr(pkt, 'haslayer') else False

        if not (has_ip or has_ipv6):
            return

        ip_layer = IP if has_ip else IPv6
        src_ip = str(pkt[ip_layer].src)
        dst_ip = str(pkt[ip_layer].dst)
        ts = float(pkt.time) if hasattr(pkt, 'time') else 0.0
        size = int(len(pkt))

        proto = "OTHER"
        src_port = 0
        dst_port = 0

        has_tcp = pkt.haslayer(TCP) if hasattr(pkt, 'haslayer') else False
        has_udp = pkt.haslayer(UDP) if hasattr(pkt, 'haslayer') else False

        if has_tcp:
            proto = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
        elif has_udp:
            proto = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)

        key = FlowKey(src_ip=src_ip, dst_ip=dst_ip,
                      src_port=src_port, dst_port=dst_port, proto=proto)
        h = hash(key)

        if h not in self.flows:
            self.flows[h] = FlowStats(key=key, first_seen=ts)
            self.flow_keys[h] = key

        flow = self.flows[h]
        flow.last_seen = max(flow.last_seen, ts)

        # Direction: canonique = src_ip <= dst_ip
        canonical_src = min(src_ip, dst_ip)
        if src_ip == canonical_src:
            flow.packets_out.append((ts, size))
        else:
            flow.packets_in.append((ts, size))

    # ─────────────────────────────────────
    # Internal — Beaconing detection
    # ─────────────────────────────────────

    def _detect_beaconing(self, key: FlowKey, stats: FlowStats):
        """Détecte un comportement de beaconing C2."""
        all_packets = sorted(stats.packets_out + stats.packets_in, key=lambda x: x[0])
        if len(all_packets) < BEACONING_MIN_PACKETS:
            return

        timestamps = [float(ts) for ts, _ in all_packets]
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

        if not intervals:
            return

        avg_interval = sum(intervals) / len(intervals)
        if avg_interval < 0.5:
            return

        std_dev = self._std_dev(intervals)
        jitter_ratio = std_dev / avg_interval if avg_interval > 0 else 1.0
        regularity_score = max(0.0, 1.0 - jitter_ratio)

        if regularity_score >= BEACONING_REGULARITY_THRESHOLD:
            sizes_float = [float(s) for _, s in all_packets]
            size_std = self._std_dev(sizes_float)
            size_mean = sum(sizes_float) / len(sizes_float) if sizes_float else 0.0
            size_jitter_ratio = (size_std / size_mean) if size_mean > 0 else 1.0

            beacon_score = int(regularity_score * 100)
            if size_jitter_ratio < 0.20:
                beacon_score = min(100, beacon_score + 15)

            self.beaconing_alerts.append({
                "flow": key.to_str(),
                "src_ip": key.src_ip,
                "dst_ip": key.dst_ip,
                "dst_port": key.dst_port,
                "proto": key.proto,
                "beacon_score": beacon_score,
                "avg_interval_sec": round(float(avg_interval), 3),
                "jitter_ratio": round(float(jitter_ratio), 3),
                "regularity_score": round(float(regularity_score), 3),
                "packet_count": len(all_packets),
                "size_jitter_ratio": round(float(size_jitter_ratio), 3),
                "duration_sec": round(float(stats.last_seen - stats.first_seen), 1),
                "verdict": (
                    "🔴 BEACONING C2 PROBABLE" if beacon_score >= 90
                    else "🟠 COMPORTEMENT SUSPECT" if beacon_score >= 75
                    else "🟡 À SURVEILLER"
                ),
                "mitre": "T1071.001 / T1132 - Data Encoding"
            })

    # ─────────────────────────────────────
    # Internal — Exfiltration detection
    # ─────────────────────────────────────

    def _detect_exfiltration(self, key: FlowKey, stats: FlowStats):
        """Détecte une exfiltration de données."""
        bytes_out = float(stats.bytes_out)
        bytes_in = float(stats.bytes_in)

        if bytes_in < 1024:
            return

        ratio = bytes_out / bytes_in if bytes_in > 0 else float('inf')

        if ratio >= EXFIL_RATIO_THRESHOLD and bytes_out >= EXFIL_MIN_BYTES:
            exfil_score = min(100, int(50 + (ratio - EXFIL_RATIO_THRESHOLD) * 5))

            self.exfiltration_alerts.append({
                "flow": key.to_str(),
                "src_ip": key.src_ip,
                "dst_ip": key.dst_ip,
                "dst_port": key.dst_port,
                "proto": key.proto,
                "bytes_out": int(bytes_out),
                "bytes_in": int(bytes_in),
                "upload_download_ratio": round(float(ratio), 2),
                "exfil_score": exfil_score,
                "duration_sec": round(float(stats.last_seen - stats.first_seen), 1),
                "estimated_exfil_mb": round(float(bytes_out) / 1_048_576, 3),
                "verdict": (
                    "🔴 EXFILTRATION PROBABLE" if exfil_score >= 80
                    else "🟠 FUITE DE DONNÉES SUSPECTE" if exfil_score >= 60
                    else "🟡 RATIO ÉLEVÉ — À INVESTIGUER"
                ),
                "mitre": "T1041 - Exfiltration Over C2 / T1048 - Exfiltration Over Alternative Protocol"
            })

    # ─────────────────────────────────────
    # Internal — Flow fingerprinting
    # ─────────────────────────────────────

    def _compute_fingerprint(self, key: FlowKey, stats: FlowStats):
        """Calcule une empreinte comportementale du flux"""
        all_pkts = sorted(stats.packets_out + stats.packets_in, key=lambda x: x[0])
        if len(all_pkts) < 3:
            return

        timestamps = [float(ts) for ts, _ in all_pkts]
        sizes_float = [float(s) for _, s in all_pkts]
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

        median_size = self._median(sizes_float)
        avg_interval = sum(intervals) / len(intervals) if intervals else 0.0
        duration = stats.last_seen - stats.first_seen

        size_bucket = (int(median_size) // 100) * 100
        interval_bucket = (int(avg_interval * 1000) // 500) * 500

        fp_string = f"{key.proto}:{key.dst_port}:{size_bucket}:{interval_bucket}"
        fp_hash = hashlib.md5(fp_string.encode()).hexdigest()[:12]

        self.flow_fingerprints.append({
            "flow": key.to_str(),
            "src_ip": key.src_ip,
            "dst_ip": key.dst_ip,
            "fingerprint": fp_hash,
            "fingerprint_details": {
                "proto": key.proto,
                "dst_port": key.dst_port,
                "median_pkt_size_bytes": int(median_size),
                "avg_interval_ms": round(float(avg_interval) * 1000, 1),
                "duration_sec": round(float(duration), 1),
                "total_packets": stats.total_packets,
                "bytes_out": stats.bytes_out,
                "bytes_in": stats.bytes_in,
            }
        })

    # ─────────────────────────────────────
    # Internal — Results compilation
    # ─────────────────────────────────────

    def _compile_results(self) -> Dict[str, Any]:
        """Compile tous les résultats de l'analyse comportementale"""
        fp_groups: Dict[str, List[str]] = defaultdict(list)
        for fp in self.flow_fingerprints:
            fp_groups[fp["fingerprint"]].append(fp["flow"])

        shared_fingerprints = [
            {"fingerprint": fp, "flows": flows, "count": len(flows)}
            for fp, flows in fp_groups.items()
            if len(flows) > 2
        ]

        top_beaconing = sorted(
            self.beaconing_alerts,
            key=lambda x: int(x["beacon_score"]),
            reverse=True
        )[:20]

        top_exfil = sorted(
            self.exfiltration_alerts,
            key=lambda x: int(x["exfil_score"]),
            reverse=True
        )[:20]

        overall_risk = "NONE"
        if any(int(a["beacon_score"]) >= 90 for a in self.beaconing_alerts):
            overall_risk = "CRITICAL"
        elif any(int(a["exfil_score"]) >= 80 for a in self.exfiltration_alerts):
            overall_risk = "HIGH"
        elif self.beaconing_alerts or self.exfiltration_alerts:
            overall_risk = "MEDIUM"

        return {
            "summary": {
                "total_flows_analyzed": len(self.flows),
                "beaconing_alerts": len(self.beaconing_alerts),
                "exfiltration_alerts": len(self.exfiltration_alerts),
                "shared_fingerprints": len(shared_fingerprints),
                "overall_risk": overall_risk,
            },
            "beaconing_alerts": top_beaconing,
            "exfiltration_alerts": top_exfil,
            "flow_fingerprints": self.flow_fingerprints[:50],
            "shared_fingerprints": shared_fingerprints[:10],
        }

    # ─────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────

    @staticmethod
    def _std_dev(values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean)**2 for x in values) / len(values)
        return math.sqrt(variance)

    @staticmethod
    def _median(values: List[float]) -> float:
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        n = len(sorted_vals)
        if n % 2 == 1:
            return sorted_vals[n // 2]
        return (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2.0
