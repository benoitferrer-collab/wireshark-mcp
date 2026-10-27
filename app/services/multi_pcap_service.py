"""
Service d'analyse multi-PCAP (corrélation multi-hop).

Objectif:
- analyser plusieurs captures prises sur des points réseau différents
- corréler les sessions entre points de capture
- détecter les changements majeurs (NAT/ports, TTL, DSCP, VLAN, options TCP, pertes)
- estimer la latence inter-points avec score de confiance
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict
from statistics import median
import math

from scapy.all import PcapReader, IP, IPv6, TCP, UDP, Dot1Q  # type: ignore

from app.core.logging_config import get_logger

logger = get_logger(__name__)

DEFAULT_ROOT_CAUSE_THRESHOLDS: Dict[str, float] = {
    "ttl_shift_medium": 4.0,
    "ttl_shift_high": 10.0,
    "retrans_increase_medium": 0.03,
    "retrans_increase_high": 0.08,
    "latency_segment_medium_ms": 60.0,
    "latency_segment_high_ms": 120.0,
    "latency_segment_notice_ms": 25.0,
    "segment_trigger_score": 45.0,
    "segment_trigger_changes_min": 2.0,
    "segment_trigger_soft_score": 30.0,
    "mss_spread_signal_min": 80.0,
    "nat_pairs_weight_step": 6.0,
    "bufferbloat_duration_ratio": 2.2,
    "bufferbloat_window_ratio": 1.8,
    "bufferbloat_reorder_min": 3.0,
    "asymmetry_missing_hops_min": 2.0,
}


@dataclass
class CaptureInput:
    """Entrée de capture multi-PCAP."""

    file_path: Path
    filename: str
    equipment_name: str
    position: int
    comment: str = ""


from app.core.utils import as_int as _safe_int, as_float as _safe_float  # noqa: E402


def _percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    arr = sorted(values)
    if len(arr) == 1:
        return float(arr[0])
    rank = (len(arr) - 1) * (pct / 100.0)
    low = int(math.floor(rank))
    high = int(math.ceil(rank))
    if low == high:
        return float(arr[low])
    weight = rank - low
    return float(arr[low] * (1 - weight) + arr[high] * weight)


def _iso_or_none(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    from datetime import datetime, timezone

    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except Exception:
        return None


def _sanitize_root_cause_thresholds(raw: Optional[Dict[str, Any]]) -> Dict[str, float]:
    thresholds = dict(DEFAULT_ROOT_CAUSE_THRESHOLDS)
    if not isinstance(raw, dict):
        return thresholds

    for key, default_value in DEFAULT_ROOT_CAUSE_THRESHOLDS.items():
        if key not in raw:
            continue
        value = _safe_float(raw.get(key), default_value)
        # garde-fous simples pour éviter des valeurs aberrantes
        if key.startswith("retrans_"):
            value = max(0.0, min(1.0, value))
        elif key.endswith("_ratio"):
            value = max(1.0, min(20.0, value))
        elif key.endswith("_ms"):
            value = max(1.0, min(10_000.0, value))
        elif "trigger" in key:
            value = max(1.0, min(100.0, value))
        elif key.endswith("_min") or key.endswith("_step"):
            value = max(1.0, min(200.0, value))
        thresholds[key] = value

    # cohérence interne
    thresholds["ttl_shift_high"] = max(thresholds["ttl_shift_medium"] + 1.0, thresholds["ttl_shift_high"])
    thresholds["retrans_increase_high"] = max(
        thresholds["retrans_increase_medium"] + 0.005,
        thresholds["retrans_increase_high"],
    )
    thresholds["latency_segment_high_ms"] = max(
        thresholds["latency_segment_medium_ms"] + 5.0,
        thresholds["latency_segment_high_ms"],
    )
    thresholds["segment_trigger_score"] = max(
        thresholds["segment_trigger_soft_score"] + 1.0,
        thresholds["segment_trigger_score"],
    )

    return thresholds


def _canonical_flow_key(protocol: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Tuple[str, Tuple[Tuple[str, int], Tuple[str, int]]]:
    a = (src_ip, int(src_port))
    b = (dst_ip, int(dst_port))
    return protocol.upper(), tuple(sorted([a, b]))


def _guess_client_server(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Tuple[Tuple[str, int], Tuple[str, int]]:
    """Heuristique simple client/server quand handshake non disponible."""
    # Port bien connu côté serveur
    src_well_known = src_port <= 1024
    dst_well_known = dst_port <= 1024

    if src_well_known and not dst_well_known:
        return (dst_ip, dst_port), (src_ip, src_port)
    if dst_well_known and not src_well_known:
        return (src_ip, src_port), (dst_ip, dst_port)

    # Sinon: port le plus élevé côté client (éphémère)
    if src_port > dst_port:
        return (src_ip, src_port), (dst_ip, dst_port)
    if dst_port > src_port:
        return (dst_ip, dst_port), (src_ip, src_port)

    # Dernier fallback: ordre du premier paquet
    return (src_ip, src_port), (dst_ip, dst_port)


class MultiPcapAnalysisService:
    """Service principal de corrélation multi-PCAP."""

    def analyze(
        self,
        capture_inputs: List[CaptureInput],
        time_tolerance: float = 5.0,
        max_packets_per_capture: int = 250_000,
        root_cause_thresholds: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if len(capture_inputs) < 2:
            raise ValueError("Au moins 2 captures sont nécessaires pour l'analyse multi-PCAP")

        ordered = sorted(capture_inputs, key=lambda c: (c.position, c.filename.lower()))

        capture_points: List[Dict[str, Any]] = []
        for idx, capture in enumerate(ordered):
            logger.info(
                "multi_pcap_capture_started",
                capture=str(capture.file_path),
                position=capture.position,
                equipment=capture.equipment_name,
            )
            point = self._analyze_capture_point(capture, idx, max_packets_per_capture)
            capture_points.append(point)

        thresholds = _sanitize_root_cause_thresholds(root_cause_thresholds)
        sessions = self._correlate_chain(
            capture_points,
            time_tolerance=max(0.2, float(time_tolerance)),
            thresholds=thresholds,
        )
        latency_summary = self._estimate_latency(capture_points, sessions)
        self._apply_latency_to_sessions(latency_summary, sessions, thresholds=thresholds)

        # Phase 1: bande passante comparée entre points de la chaîne
        bandwidth_chain = self._build_bandwidth_chain(capture_points, sessions)
        # Phase 2: appariement paquet -> délai relatif et pertes localisées
        packet_match = self._match_packets_across_captures(capture_points, sessions)
        # Phase 3: verdicts de goulot par segment + classification des flux
        bottleneck_verdicts = self._build_bottleneck_verdicts(bandwidth_chain, packet_match)
        per_session_match = packet_match.get("per_session", {})
        for session in sessions:
            session["flow_limitation"] = self._classify_flow_limitation(session)
            session["packet_match_by_segment"] = per_session_match.get(str(session.get("session_id")), [])
            self._apply_packet_loss_to_risk(session)

        # Le classement des sessions doit refléter le risque réévalué
        sessions.sort(key=lambda x: (
            0 if x.get("problematic") else 1,
            -_safe_int(x.get("risk_score"), 0),
            -_safe_int(x.get("total_packets"), 0),
        ))

        problematic_sessions = [s for s in sessions if bool(s.get("problematic"))]
        problematic_ips = self._extract_problematic_ips(problematic_sessions)
        total_packets_observed = sum(_safe_int(p.get("packet_count"), 0) for p in capture_points)
        total_bytes_observed = sum(_safe_int(p.get("byte_count"), 0) for p in capture_points)
        sessions_by_protocol = self._count_sessions_by_protocol(sessions)
        confidence_breakdown = self._count_confidence_levels(sessions)
        top_causes = self._count_top_causes(sessions)
        top_cause_codes = self._count_top_cause_codes(sessions)
        capture_volumetry = self._build_capture_volumetry(capture_points)
        segment_health = self._build_segment_health(sessions)
        culprit_ranking = self._build_culprit_ranking(sessions, capture_points)
        equipment_chain = self._build_equipment_chain(capture_points, segment_health)

        summary = {
            "total_capture_points": len(capture_points),
            "total_sessions_detected": sum(int(p.get("sessions_count", 0)) for p in capture_points),
            "correlated_sessions": len(sessions),
            "problematic_sessions": len(problematic_sessions),
            "high_risk_sessions": len([s for s in sessions if _safe_int(s.get("risk_score"), 0) >= 70]),
            "major_changes_detected": sum(len(s.get("changes", [])) for s in sessions),
            "latency_segments": len(latency_summary.get("segments", [])),
            "time_tolerance_seconds": float(time_tolerance),
            "total_packets_observed": total_packets_observed,
            "total_bytes_observed": total_bytes_observed,
            "sessions_by_protocol": sessions_by_protocol,
            "confidence_breakdown": confidence_breakdown,
            "top_causes": top_causes[:8],
            "top_cause_codes": top_cause_codes[:8],
            "capture_volumetry": capture_volumetry[:12],
            "segment_health_top": segment_health[:12],
            "culprit_ranking_top": culprit_ranking[:10],
            "thresholds_applied": thresholds,
            "primary_bottleneck": (bottleneck_verdicts[0].get("segment") if bottleneck_verdicts else None),
            "primary_bottleneck_score": (bottleneck_verdicts[0].get("bottleneck_score") if bottleneck_verdicts else 0.0),
            "worst_loss_segment": packet_match.get("worst_loss_segment"),
            "worst_delay_segment": packet_match.get("worst_delay_segment"),
            "flow_limitation_breakdown": self._count_flow_limitations(sessions),
        }

        # Purge des champs internes volumineux (empreintes, bins bruts):
        # utiles au calcul, jamais au client
        for cp in capture_points:
            cp.pop("_bytes_per_second", None)
            for sess in cp.get("sessions", []) or []:
                sess.pop("fp_by_dir", None)
                sess.pop("timeseries_bytes", None)
        for session in sessions:
            for hop in session.get("hops", []) or []:
                hop.pop("_fp_by_dir", None)

        return {
            "summary": summary,
            "capture_points": capture_points,
            "sessions": sessions,
            "bandwidth_chain": bandwidth_chain,
            "packet_match": {k: v for k, v in packet_match.items() if k != "per_session"},
            "bottleneck_verdicts": bottleneck_verdicts,
            "latency": latency_summary,
            "problematic_ips": problematic_ips,
            "capture_volumetry": capture_volumetry,
            "segment_health": segment_health,
            "culprit_ranking": culprit_ranking,
            "equipment_chain": equipment_chain,
            "thresholds_applied": thresholds,
            "limitations": [
                "Horloges potentiellement non synchronisées entre équipements.",
                "Captures partielles possibles selon SPAN/tap/ACL.",
                "La corrélation NAT/PAT est heuristique si mapping explicite indisponible.",
            ],
        }

    # ------------------------------------------------------------------
    # Capture parsing
    # ------------------------------------------------------------------

    def _analyze_capture_point(self, capture: CaptureInput, capture_index: int, max_packets: int) -> Dict[str, Any]:
        sessions: Dict[Tuple[str, Tuple[Tuple[str, int], Tuple[str, int]]], Dict[str, Any]] = {}

        total_packets = 0
        total_bytes = 0
        start_ts: Optional[float] = None
        end_ts: Optional[float] = None
        # Budget d'empreintes pour l'appariement inter-captures (borne mémoire)
        fp_budget = [150_000]
        # Série temporelle agrégée du point de capture (octets/s)
        capture_bins: Dict[int, int] = {}

        path = Path(capture.file_path)
        with PcapReader(str(path)) as reader:
            for pkt in reader:
                total_packets += 1
                if total_packets > max_packets:
                    break

                pkt_len = len(pkt)
                total_bytes += pkt_len
                ts = _safe_float(getattr(pkt, "time", 0.0), 0.0)

                cbin = int(ts)
                if cbin in capture_bins:
                    capture_bins[cbin] += pkt_len
                elif len(capture_bins) < 7200:
                    capture_bins[cbin] = pkt_len

                if start_ts is None or ts < start_ts:
                    start_ts = ts
                if end_ts is None or ts > end_ts:
                    end_ts = ts

                ip_layer = None
                protocol = None
                src_ip = ""
                dst_ip = ""
                ttl_val: Optional[int] = None
                dscp: Optional[int] = None
                ecn: Optional[int] = None

                if pkt.haslayer(IP):
                    ip_layer = pkt[IP]
                    protocol = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "IP")
                    src_ip = str(getattr(ip_layer, "src", ""))
                    dst_ip = str(getattr(ip_layer, "dst", ""))
                    ttl_val = _safe_int(getattr(ip_layer, "ttl", 0), 0)
                    tos = _safe_int(getattr(ip_layer, "tos", 0), 0)
                    dscp = (tos >> 2) & 0x3F
                    ecn = tos & 0x03
                elif pkt.haslayer(IPv6):
                    ip_layer = pkt[IPv6]
                    protocol = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "IPv6")
                    src_ip = str(getattr(ip_layer, "src", ""))
                    dst_ip = str(getattr(ip_layer, "dst", ""))
                    ttl_val = _safe_int(getattr(ip_layer, "hlim", 0), 0)
                    tc = _safe_int(getattr(ip_layer, "tc", 0), 0)
                    dscp = (tc >> 2) & 0x3F
                    ecn = tc & 0x03

                if not ip_layer or protocol not in {"TCP", "UDP"}:
                    continue

                src_port = 0
                dst_port = 0
                if protocol == "TCP":
                    src_port = _safe_int(getattr(pkt[TCP], "sport", 0), 0)
                    dst_port = _safe_int(getattr(pkt[TCP], "dport", 0), 0)
                elif protocol == "UDP":
                    src_port = _safe_int(getattr(pkt[UDP], "sport", 0), 0)
                    dst_port = _safe_int(getattr(pkt[UDP], "dport", 0), 0)

                if not src_ip or not dst_ip or src_port <= 0 or dst_port <= 0:
                    continue

                flow_key = _canonical_flow_key(protocol, src_ip, src_port, dst_ip, dst_port)
                flow = sessions.get(flow_key)
                if flow is None:
                    flow = {
                        "capture_index": capture_index,
                        "protocol": protocol,
                        "first_ts": ts,
                        "last_ts": ts,
                        "reference_ts": ts,
                        "packet_count": 0,
                        "byte_count": 0,
                        "participant_ips": set(),
                        "participant_ports": set(),
                        "ttl_min": None,
                        "ttl_max": None,
                        "ttl_sum": 0,
                        "ttl_count": 0,
                        "dscp_values": set(),
                        "ecn_values": set(),
                        "vlan_ids": set(),
                        "tcp": {
                            "syn": 0,
                            "synack": 0,
                            "ack": 0,
                            "fin": 0,
                            "rst": 0,
                            "retransmissions": 0,
                            "dup_acks": 0,
                            "out_of_order": 0,
                            "mss_values": set(),
                            "window_min": None,
                            "window_max": None,
                            "window_sum": 0,
                            "window_count": 0,
                            "sack_seen": False,
                            "timestamp_seen": False,
                            "first_syn_ts": None,
                            "synack_ts": None,
                            "hs_ack_ts": None,
                            "client_ep": None,
                            "server_ep": None,
                            "direction_state": {},
                        },
                        # Statistiques par direction (débit, fenêtres, bins temporels)
                        "dir_stats": {},
                        # Empreintes de paquets data pour l'appariement inter-captures
                        # {dir_key: {fingerprint_int: timestamp}}
                        "fp_by_dir": {},
                    }
                    sessions[flow_key] = flow

                flow["packet_count"] += 1
                flow["byte_count"] += pkt_len
                flow["participant_ips"].update([src_ip, dst_ip])
                flow["participant_ports"].update([src_port, dst_port])
                if ts < flow["first_ts"]:
                    flow["first_ts"] = ts
                if ts > flow["last_ts"]:
                    flow["last_ts"] = ts

                if ttl_val is not None and ttl_val > 0:
                    flow["ttl_count"] += 1
                    flow["ttl_sum"] += ttl_val
                    flow["ttl_min"] = ttl_val if flow["ttl_min"] is None else min(flow["ttl_min"], ttl_val)
                    flow["ttl_max"] = ttl_val if flow["ttl_max"] is None else max(flow["ttl_max"], ttl_val)

                if dscp is not None:
                    flow["dscp_values"].add(int(dscp))
                if ecn is not None:
                    flow["ecn_values"].add(int(ecn))

                if pkt.haslayer(Dot1Q):
                    vlan_id = _safe_int(getattr(pkt[Dot1Q], "vlan", -1), -1)
                    if vlan_id >= 0:
                        flow["vlan_ids"].add(vlan_id)

                # Payload utile (goodput) — calculé une seule fois ici
                if protocol == "TCP":
                    payload_len = self._safe_tcp_payload_len(pkt, pkt[TCP])
                else:
                    payload_len = max(0, _safe_int(getattr(pkt[UDP], "len", 8), 8) - 8)

                # Comptabilité par direction: octets fil/utiles + bins 1s
                dir_key = (src_ip, src_port, dst_ip, dst_port)
                dstat = flow["dir_stats"].get(dir_key)
                if dstat is None:
                    dstat = flow["dir_stats"].setdefault(dir_key, {
                        "wire_bytes": 0,
                        "payload_bytes": 0,
                        "retrans_payload_bytes": 0,
                        "packets": 0,
                        "bins": {},              # seconde -> [octets fil, octets payload]
                        "bins_truncated": False,
                        "zero_window_events": 0,
                        "window_scale": None,    # shift WScale annoncé par cet émetteur
                        "eff_window_min": None,
                        "eff_window_max": None,
                        "eff_window_sum": 0,
                        "eff_window_count": 0,
                    })
                dstat["wire_bytes"] += pkt_len
                dstat["payload_bytes"] += payload_len
                dstat["packets"] += 1
                tbin = int(ts)
                bins = dstat["bins"]
                cell = bins.get(tbin)
                if cell is not None:
                    cell[0] += pkt_len
                    cell[1] += payload_len
                elif len(bins) < 7200:
                    bins[tbin] = [pkt_len, payload_len]
                else:
                    dstat["bins_truncated"] = True

                if protocol == "TCP":
                    self._update_tcp_metrics(
                        flow, pkt, src_ip, src_port, dst_ip, dst_port, ts,
                        payload_len=payload_len, dstat=dstat, fp_budget=fp_budget,
                        ip_id=_safe_int(getattr(ip_layer, "id", 0), 0) if pkt.haslayer(IP) else 0,
                    )

        sessions_list = [self._finalize_session_record(k, s) for k, s in sessions.items()]
        sessions_list.sort(key=lambda x: x.get("packet_count", 0), reverse=True)

        duration = 0.0
        if start_ts is not None and end_ts is not None and end_ts >= start_ts:
            duration = float(end_ts - start_ts)

        return {
            "_bytes_per_second": capture_bins,
            "capture_id": f"cp-{capture_index + 1}",
            "capture_index": capture_index,
            "filename": capture.filename,
            "file_path": str(capture.file_path),
            "file_size": _safe_int(capture.file_path.stat().st_size, 0),
            "equipment_name": capture.equipment_name,
            "position": capture.position,
            "comment": capture.comment,
            "packet_count": total_packets,
            "byte_count": total_bytes,
            "capture_start_ts": start_ts,
            "capture_end_ts": end_ts,
            "capture_start": _iso_or_none(start_ts),
            "capture_end": _iso_or_none(end_ts),
            "capture_duration_seconds": round(duration, 6),
            "sessions_count": len(sessions_list),
            "sessions": sessions_list,
        }

    def _update_tcp_metrics(
        self,
        flow: Dict[str, Any],
        pkt: Any,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        ts: float,
        payload_len: int = 0,
        dstat: Optional[Dict[str, Any]] = None,
        fp_budget: Optional[List[int]] = None,
        ip_id: int = 0,
    ) -> None:
        tcp_layer = pkt[TCP]
        tcp = flow["tcp"]

        flags = getattr(tcp_layer, "flags", 0)
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)
        fin = bool(flags & 0x01)
        rst = bool(flags & 0x04)

        if syn:
            tcp["syn"] += 1
            if ack:
                tcp["synack"] += 1
        if ack:
            tcp["ack"] += 1
        if fin:
            tcp["fin"] += 1
        if rst:
            tcp["rst"] += 1

        if syn and not ack and tcp.get("first_syn_ts") is None:
            tcp["first_syn_ts"] = ts
            tcp["client_ep"] = (src_ip, src_port)
            tcp["server_ep"] = (dst_ip, dst_port)
            flow["reference_ts"] = ts

        # Handshake: SYN -> SYN/ACK -> ACK donne le RTT vu depuis ce point
        if syn and ack and tcp.get("synack_ts") is None:
            tcp["synack_ts"] = ts
        elif (ack and not syn and payload_len == 0
              and tcp.get("synack_ts") is not None and tcp.get("hs_ack_ts") is None):
            tcp["hs_ack_ts"] = ts

        options = getattr(tcp_layer, "options", []) or []
        for opt, value in options:
            if opt == "MSS" and value is not None:
                mss = _safe_int(value, 0)
                if mss > 0:
                    tcp["mss_values"].add(mss)
            elif opt in {"SAckOK", "SAck"}:
                tcp["sack_seen"] = True
            elif opt == "Timestamp":
                tcp["timestamp_seen"] = True
            elif opt == "WScale" and value is not None and dstat is not None:
                # Le shift n'est annoncé qu'au SYN et s'applique aux fenêtres
                # ultérieures de CET émetteur
                dstat["window_scale"] = max(0, min(14, _safe_int(value, 0)))

        wnd = _safe_int(getattr(tcp_layer, "window", 0), 0)
        if wnd > 0:
            tcp["window_count"] += 1
            tcp["window_sum"] += wnd
            tcp["window_min"] = wnd if tcp["window_min"] is None else min(tcp["window_min"], wnd)
            tcp["window_max"] = wnd if tcp["window_max"] is None else max(tcp["window_max"], wnd)

        if dstat is not None:
            # Fenêtre effective = window * 2^scale (le scale ne s'applique pas au SYN)
            scale = _safe_int(dstat.get("window_scale"), 0) or 0
            eff = wnd if syn else (wnd << scale)
            if wnd == 0 and not rst and not syn:
                dstat["zero_window_events"] += 1
            if eff > 0:
                dstat["eff_window_count"] += 1
                dstat["eff_window_sum"] += eff
                dstat["eff_window_min"] = eff if dstat["eff_window_min"] is None else min(dstat["eff_window_min"], eff)
                dstat["eff_window_max"] = eff if dstat["eff_window_max"] is None else max(dstat["eff_window_max"], eff)

        seq = _safe_int(getattr(tcp_layer, "seq", 0), 0)
        ack_num = _safe_int(getattr(tcp_layer, "ack", 0), 0)
        seq_span = seq + payload_len + (1 if syn else 0) + (1 if fin else 0)

        # Empreinte d'un paquet data: identifie le MÊME paquet aux différents
        # points de capture (seq + taille + IP ID survivent au routage; l'IP ID
        # peut être réécrit par du NAT, d'où sa faible pondération à l'appariement)
        if payload_len > 0 and fp_budget is not None and fp_budget[0] > 0:
            fp = (seq & 0xFFFFFFFF) ^ ((payload_len & 0xFFFF) << 32) ^ ((ip_id & 0xFFFF) << 48)
            fp_dir = flow["fp_by_dir"].setdefault((src_ip, src_port, dst_ip, dst_port), {})
            if fp not in fp_dir:
                fp_dir[fp] = ts
                fp_budget[0] -= 1

        dir_key = (src_ip, src_port, dst_ip, dst_port)
        dir_state = tcp["direction_state"].setdefault(  # noqa: E501
            dir_key,
            {
                "max_seq": -1,
                "seen_seq": set(),
                "last_ack": None,
                "ack_repeat": 0,
            },
        )

        seen_seq: set = dir_state["seen_seq"]
        if payload_len > 0 or syn or fin:
            if seq in seen_seq:
                tcp["retransmissions"] += 1
                if dstat is not None:
                    dstat["retrans_payload_bytes"] += payload_len
            elif _safe_int(dir_state["max_seq"], -1) >= 0 and seq < _safe_int(dir_state["max_seq"], -1):
                tcp["out_of_order"] += 1
            seen_seq.add(seq)
            if len(seen_seq) > 4096:
                seen_seq.clear()

            if seq_span > _safe_int(dir_state["max_seq"], -1):
                dir_state["max_seq"] = seq_span

        if ack and payload_len == 0:
            last_ack = dir_state.get("last_ack")
            if last_ack is not None and ack_num == _safe_int(last_ack, -1):
                dir_state["ack_repeat"] = _safe_int(dir_state.get("ack_repeat"), 0) + 1
                if _safe_int(dir_state["ack_repeat"], 0) >= 2:
                    tcp["dup_acks"] += 1
            else:
                dir_state["last_ack"] = ack_num
                dir_state["ack_repeat"] = 0

    def _safe_tcp_payload_len(self, pkt: Any, tcp_layer: Any) -> int:
        """
        Évalue la taille payload TCP sans sérialiser tcp_layer.payload.
        Important pour éviter certains crashes Scapy TLS sur __bytes__().
        """
        # 1) Cas Raw classique
        payload = getattr(tcp_layer, "payload", None)
        raw_load = getattr(payload, "load", None)
        if isinstance(raw_load, (bytes, bytearray)):
            return len(raw_load)

        # 2) Calcul à partir des longueurs IP/TCP (évite bytes(payload))
        tcp_hlen = _safe_int(getattr(tcp_layer, "dataofs", 5), 5) * 4
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            ip_total = _safe_int(getattr(ip_layer, "len", 0), 0)
            ip_hlen = _safe_int(getattr(ip_layer, "ihl", 5), 5) * 4
            if ip_total > 0:
                return max(0, ip_total - ip_hlen - tcp_hlen)

        if pkt.haslayer(IPv6):
            ip6_layer = pkt[IPv6]
            # plen = payload length IPv6 (sans en-tête IPv6)
            plen = _safe_int(getattr(ip6_layer, "plen", 0), 0)
            if plen > 0:
                return max(0, plen - tcp_hlen)

        # 3) Fallback conservateur
        return 0

    # ------------------------------------------------------------------
    # Débit / fenêtres / bornes théoriques (Phase 1)
    # ------------------------------------------------------------------

    @staticmethod
    def _direction_throughput(dstat: Dict[str, Any], duration: float) -> Dict[str, Any]:
        """Débit d'une direction: moyenne, pic et p95 sur les bins de 1 seconde.

        - wire = tout ce qui passe sur le fil
        - goodput = payload utile hors retransmissions (ce que l'application reçoit)
        """
        bins = dstat.get("bins", {}) or {}
        wire_bytes = _safe_int(dstat.get("wire_bytes"), 0)
        payload_bytes = _safe_int(dstat.get("payload_bytes"), 0)
        retrans_bytes = _safe_int(dstat.get("retrans_payload_bytes"), 0)
        goodput_bytes = max(0, payload_bytes - retrans_bytes)

        dur = max(duration, 0.001)
        wire_series = sorted(v[0] for v in bins.values())
        avg_mbps = (wire_bytes * 8.0) / dur / 1_000_000.0
        peak_mbps = (wire_series[-1] * 8.0 / 1_000_000.0) if wire_series else 0.0
        p95_mbps = (_percentile([float(v) for v in wire_series], 95.0) * 8.0 / 1_000_000.0) if wire_series else 0.0
        goodput_mbps = (goodput_bytes * 8.0) / dur / 1_000_000.0

        return {
            "wire_bytes": wire_bytes,
            "payload_bytes": payload_bytes,
            "goodput_bytes": goodput_bytes,
            "retrans_payload_bytes": retrans_bytes,
            "packets": _safe_int(dstat.get("packets"), 0),
            "avg_mbps": round(avg_mbps, 4),
            "peak_mbps": round(peak_mbps, 4),
            "p95_mbps": round(p95_mbps, 4),
            "goodput_mbps": round(goodput_mbps, 4),
            "active_seconds": len(bins),
            "bins_truncated": bool(dstat.get("bins_truncated")),
        }

    @staticmethod
    def _direction_window(dstat: Dict[str, Any]) -> Dict[str, Any]:
        """Fenêtre effective (window << scale) et événements de fenêtre nulle."""
        count = _safe_int(dstat.get("eff_window_count"), 0)
        avg = (float(dstat.get("eff_window_sum", 0)) / count) if count > 0 else 0.0
        return {
            "scale_shift": dstat.get("window_scale"),
            "effective_min": _safe_int(dstat.get("eff_window_min"), 0),
            "effective_max": _safe_int(dstat.get("eff_window_max"), 0),
            "effective_avg": round(avg, 1),
            "zero_window_events": _safe_int(dstat.get("zero_window_events"), 0),
        }

    @staticmethod
    def _theoretical_limits(rwnd_bytes: float, rtt_ms: float, mss: int, loss_ratio: float) -> Dict[str, Any]:
        """Bornes hautes du débit atteignable, pour comparer au débit réel.

        - limite fenêtre: rwnd / RTT (on ne peut pas avoir plus de rwnd octets en vol)
        - limite pertes (Mathis): MSS / (RTT * sqrt(p))
        Les deux supposent un RTT mesuré fiable; renvoie None sinon.
        """
        out: Dict[str, Any] = {"window_limited_mbps": None, "loss_limited_mbps": None, "limiting_factor": None}
        if rtt_ms <= 0:
            return out

        rtt_s = rtt_ms / 1000.0
        if rwnd_bytes > 0:
            out["window_limited_mbps"] = round((rwnd_bytes * 8.0) / rtt_s / 1_000_000.0, 4)
        if loss_ratio > 0 and mss > 0:
            mathis_bps = (mss * 8.0) / (rtt_s * math.sqrt(loss_ratio))
            out["loss_limited_mbps"] = round(mathis_bps / 1_000_000.0, 4)

        candidates = [(v, k) for k, v in (
            ("window", out["window_limited_mbps"]),
            ("loss", out["loss_limited_mbps"]),
        ) if v is not None]
        if candidates:
            out["limiting_factor"] = min(candidates)[1]
        return out

    def _finalize_session_record(
        self,
        flow_key: Tuple[str, Tuple[Tuple[str, int], Tuple[str, int]]],
        flow: Dict[str, Any],
    ) -> Dict[str, Any]:
        protocol, endpoints = flow_key
        ep1, ep2 = endpoints

        tcp = flow["tcp"]
        client_ep = tcp.get("client_ep")
        server_ep = tcp.get("server_ep")
        if not client_ep or not server_ep:
            guessed_client, guessed_server = _guess_client_server(ep1[0], ep1[1], ep2[0], ep2[1])
            client_ep = client_ep or guessed_client
            server_ep = server_ep or guessed_server

        ttl_avg = 0.0
        if _safe_int(flow.get("ttl_count"), 0) > 0:
            ttl_avg = float(flow.get("ttl_sum", 0)) / float(flow.get("ttl_count", 1))

        window_avg = 0.0
        if _safe_int(tcp.get("window_count"), 0) > 0:
            window_avg = float(tcp.get("window_sum", 0)) / float(tcp.get("window_count", 1))

        packet_count = _safe_int(flow.get("packet_count"), 0)
        retransmissions = _safe_int(tcp.get("retransmissions"), 0)
        retrans_ratio = (float(retransmissions) / float(packet_count)) if packet_count > 0 else 0.0

        state = "UNKNOWN"
        if protocol == "UDP":
            state = "OBSERVED"
        else:
            rst_cnt = _safe_int(tcp.get("rst"), 0)
            syn_cnt = _safe_int(tcp.get("syn"), 0)
            synack_cnt = _safe_int(tcp.get("synack"), 0)
            fin_cnt = _safe_int(tcp.get("fin"), 0)
            ack_cnt = _safe_int(tcp.get("ack"), 0)
            if rst_cnt > 0:
                state = "RESET"
            elif syn_cnt > 0 and synack_cnt == 0:
                state = "SYN_ONLY"
            elif fin_cnt > 0:
                state = "FINISHED"
            elif ack_cnt > 0:
                state = "ESTABLISHED"

        service_port = _safe_int(server_ep[1], 0)

        # --- Débit / fenêtres par direction (Phase 1) ---
        duration_s = max(0.0, _safe_float(flow.get("last_ts"), 0.0) - _safe_float(flow.get("first_ts"), 0.0))
        dir_stats = flow.get("dir_stats", {}) or {}
        c2s_key = (client_ep[0], _safe_int(client_ep[1], 0), server_ep[0], _safe_int(server_ep[1], 0))
        s2c_key = (server_ep[0], _safe_int(server_ep[1], 0), client_ep[0], _safe_int(client_ep[1], 0))
        empty_dir = {"bins": {}, "wire_bytes": 0, "payload_bytes": 0, "retrans_payload_bytes": 0, "packets": 0}
        c2s_stat = dir_stats.get(c2s_key, empty_dir)
        s2c_stat = dir_stats.get(s2c_key, empty_dir)

        throughput = {
            "client_to_server": self._direction_throughput(c2s_stat, duration_s),
            "server_to_client": self._direction_throughput(s2c_stat, duration_s),
            "duration_seconds": round(duration_s, 3),
        }
        windows = {
            "client_to_server": self._direction_window(c2s_stat),
            "server_to_client": self._direction_window(s2c_stat),
        }

        # RTT du handshake vu depuis CE point de capture (SYN -> SYN/ACK -> ACK)
        rtt_ms = None
        syn_ts = tcp.get("first_syn_ts")
        synack_ts = tcp.get("synack_ts")
        hs_ack_ts = tcp.get("hs_ack_ts")
        if syn_ts is not None and synack_ts is not None and synack_ts >= syn_ts:
            rtt_ms = (float(synack_ts) - float(syn_ts)) * 1000.0
            if hs_ack_ts is not None and hs_ack_ts >= synack_ts:
                # Moyenne des deux moitiés du handshake: plus robuste au bruit
                rtt_ms = ((float(synack_ts) - float(syn_ts)) + (float(hs_ack_ts) - float(synack_ts))) * 1000.0
            rtt_ms = round(rtt_ms, 3)

        # Bornes théoriques du débit descendant (serveur -> client)
        mss_vals = [v for v in tcp.get("mss_values", set()) if _safe_int(v, 0) > 0]
        mss = min(mss_vals) if mss_vals else 1460
        rwnd_for_download = _safe_int(windows["client_to_server"].get("effective_max"), 0)
        limits = self._theoretical_limits(
            rwnd_bytes=float(rwnd_for_download),
            rtt_ms=float(rtt_ms or 0.0),
            mss=int(mss),
            loss_ratio=float(retrans_ratio),
        )

        # Séries temporelles par seconde (octets fil), pour la comparaison inter-points
        timeseries = {
            "client_to_server": {str(k): v[0] for k, v in sorted((c2s_stat.get("bins", {}) or {}).items())},
            "server_to_client": {str(k): v[0] for k, v in sorted((s2c_stat.get("bins", {}) or {}).items())},
        }

        return {
            "throughput": throughput,
            "windows": windows,
            "handshake_rtt_ms": rtt_ms,
            "theoretical_limits": limits,
            "timeseries_bytes": timeseries,
            "fp_by_dir": flow.get("fp_by_dir", {}),
            "client_to_server_key": list(c2s_key),
            "server_to_client_key": list(s2c_key),
            "protocol": protocol,
            "client_ip": str(client_ep[0]),
            "client_port": _safe_int(client_ep[1], 0),
            "server_ip": str(server_ep[0]),
            "server_port": _safe_int(server_ep[1], 0),
            "service_port": service_port,
            "participant_ips": sorted(list(flow.get("participant_ips", set()))),
            "participant_ports": sorted([_safe_int(x, 0) for x in flow.get("participant_ports", set()) if _safe_int(x, 0) > 0]),
            "first_ts": _safe_float(flow.get("first_ts"), 0.0),
            "last_ts": _safe_float(flow.get("last_ts"), 0.0),
            "reference_ts": _safe_float(flow.get("reference_ts"), 0.0),
            "duration_seconds": max(0.0, _safe_float(flow.get("last_ts"), 0.0) - _safe_float(flow.get("first_ts"), 0.0)),
            "packet_count": packet_count,
            "byte_count": _safe_int(flow.get("byte_count"), 0),
            "state": state,
            "ttl": {
                "min": _safe_int(flow.get("ttl_min"), 0),
                "max": _safe_int(flow.get("ttl_max"), 0),
                "avg": round(ttl_avg, 3),
            },
            "dscp_values": sorted([_safe_int(v, 0) for v in flow.get("dscp_values", set())]),
            "ecn_values": sorted([_safe_int(v, 0) for v in flow.get("ecn_values", set())]),
            "vlan_ids": sorted([_safe_int(v, -1) for v in flow.get("vlan_ids", set()) if _safe_int(v, -1) >= 0]),
            "tcp_metrics": {
                "syn": _safe_int(tcp.get("syn"), 0),
                "synack": _safe_int(tcp.get("synack"), 0),
                "ack": _safe_int(tcp.get("ack"), 0),
                "fin": _safe_int(tcp.get("fin"), 0),
                "rst": _safe_int(tcp.get("rst"), 0),
                "retransmissions": retransmissions,
                "retrans_ratio": round(retrans_ratio, 6),
                "dup_acks": _safe_int(tcp.get("dup_acks"), 0),
                "out_of_order": _safe_int(tcp.get("out_of_order"), 0),
                "mss_values": sorted([_safe_int(v, 0) for v in tcp.get("mss_values", set()) if _safe_int(v, 0) > 0]),
                "window": {
                    "min": _safe_int(tcp.get("window_min"), 0),
                    "max": _safe_int(tcp.get("window_max"), 0),
                    "avg": round(window_avg, 3),
                },
                "sack_seen": bool(tcp.get("sack_seen")),
                "timestamp_seen": bool(tcp.get("timestamp_seen")),
            },
            "flow_fingerprint": f"{protocol}:{client_ep[0]}:{client_ep[1]}->{server_ep[0]}:{server_ep[1]}",
        }

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------

    def _correlate_chain(
        self,
        capture_points: List[Dict[str, Any]],
        time_tolerance: float,
        thresholds: Dict[str, float],
    ) -> List[Dict[str, Any]]:
        if not capture_points:
            return []

        # Précalcul des ensembles IP/ports par session: la corrélation compare
        # O(groupes × candidats) paires et reconstruisait 4 sets à chaque score
        match_sets: Dict[int, Tuple[set, set]] = {}
        for cp in capture_points:
            for sess in cp.get("sessions", []):
                ips = set(sess.get("participant_ips", []) or [])
                ports = {int(p) for p in sess.get("participant_ports", []) if _safe_int(p, 0) > 0}
                match_sets[id(sess)] = (ips, ports)

        # Seed groups from first capture
        groups: List[Dict[str, Any]] = []
        first_sessions = capture_points[0].get("sessions", [])
        for idx, sess in enumerate(first_sessions):
            groups.append(
                {
                    "group_id": f"sess-{idx + 1}",
                    "by_capture": {0: sess},
                    "link_scores": [],
                }
            )

        # Progressively match each next capture against existing groups
        for capture_idx in range(1, len(capture_points)):
            sessions = capture_points[capture_idx].get("sessions", [])
            if not sessions:
                continue

            bucket: Dict[Tuple[str, int], List[int]] = defaultdict(list)
            proto_bucket: Dict[str, List[int]] = defaultdict(list)
            for s_idx, sess in enumerate(sessions):
                proto = str(sess.get("protocol", "")).upper()
                bucket[(proto, _safe_int(sess.get("service_port"), 0))].append(s_idx)
                proto_bucket[proto].append(s_idx)

            assigned: set[int] = set()

            for group in groups:
                prev_idx = max((k for k in group["by_capture"].keys() if k < capture_idx), default=-1)
                if prev_idx < 0:
                    continue
                prev = group["by_capture"].get(prev_idx)
                if not prev:
                    continue

                key = (str(prev.get("protocol", "")).upper(), _safe_int(prev.get("service_port"), 0))
                candidates_idx = bucket.get(key) or proto_bucket.get(key[0], [])

                best_score = -1.0
                best_idx: Optional[int] = None

                for cand_idx in candidates_idx:
                    if cand_idx in assigned:
                        continue
                    cand = sessions[cand_idx]
                    score = self._score_match(prev, cand, time_tolerance, match_sets)
                    if score > best_score:
                        best_score = score
                        best_idx = cand_idx

                if best_idx is not None and best_score >= 40.0:
                    group["by_capture"][capture_idx] = sessions[best_idx]
                    group["link_scores"].append(float(best_score))
                    assigned.add(best_idx)

            # Remaining sessions start new groups at this hop
            for s_idx, sess in enumerate(sessions):
                if s_idx in assigned:
                    continue
                groups.append(
                    {
                        "group_id": f"sess-{len(groups) + 1}",
                        "by_capture": {capture_idx: sess},
                        "link_scores": [],
                    }
                )

        # Build serializable session records
        records: List[Dict[str, Any]] = []
        for group in groups:
            record = self._build_group_record(group, capture_points, thresholds=thresholds)
            records.append(record)

        records.sort(key=lambda x: (0 if x.get("problematic") else 1, -_safe_int(x.get("risk_score"), 0), -_safe_int(x.get("total_packets"), 0)))
        return records

    def _score_match(
        self,
        left: Dict[str, Any],
        right: Dict[str, Any],
        time_tolerance: float,
        match_sets: Optional[Dict[int, Tuple[set, set]]] = None,
    ) -> float:
        if str(left.get("protocol", "")).upper() != str(right.get("protocol", "")).upper():
            return -1.0

        score = 0.0

        lp = _safe_int(left.get("service_port"), 0)
        rp = _safe_int(right.get("service_port"), 0)
        if lp > 0 and rp > 0:
            if lp == rp:
                score += 30.0
            elif abs(lp - rp) <= 2:
                score += 8.0
        else:
            score += 5.0

        # Sets précalculés par _correlate_chain (fallback: reconstruction locale)
        l_cached = match_sets.get(id(left)) if match_sets else None
        r_cached = match_sets.get(id(right)) if match_sets else None

        l_ips = l_cached[0] if l_cached else set(left.get("participant_ips", []))
        r_ips = r_cached[0] if r_cached else set(right.get("participant_ips", []))
        shared_ips = len(l_ips & r_ips)
        if shared_ips >= 2:
            score += 26.0
        elif shared_ips == 1:
            score += 16.0

        l_ports = l_cached[1] if l_cached else set(int(p) for p in left.get("participant_ports", []) if _safe_int(p, 0) > 0)
        r_ports = r_cached[1] if r_cached else set(int(p) for p in right.get("participant_ports", []) if _safe_int(p, 0) > 0)
        shared_ports = len(l_ports & r_ports)
        if shared_ports >= 2:
            score += 12.0
        elif shared_ports == 1:
            score += 6.0

        if str(left.get("server_ip", "")) and str(left.get("server_ip", "")) == str(right.get("server_ip", "")):
            score += 12.0
        if str(left.get("client_ip", "")) and str(left.get("client_ip", "")) == str(right.get("client_ip", "")):
            score += 8.0

        l_pkts = max(1, _safe_int(left.get("packet_count"), 1))
        r_pkts = max(1, _safe_int(right.get("packet_count"), 1))
        pkt_ratio = min(l_pkts, r_pkts) / max(l_pkts, r_pkts)
        if pkt_ratio >= 0.8:
            score += 10.0
        elif pkt_ratio >= 0.5:
            score += 6.0
        elif pkt_ratio >= 0.2:
            score += 2.0

        l_dur = max(0.001, _safe_float(left.get("duration_seconds"), 0.0))
        r_dur = max(0.001, _safe_float(right.get("duration_seconds"), 0.0))
        dur_ratio = min(l_dur, r_dur) / max(l_dur, r_dur)
        if dur_ratio >= 0.8:
            score += 7.0
        elif dur_ratio >= 0.4:
            score += 3.0

        l_ts = _safe_float(left.get("reference_ts"), 0.0)
        r_ts = _safe_float(right.get("reference_ts"), 0.0)
        dt = abs(r_ts - l_ts)
        if dt <= time_tolerance:
            score += 14.0
        elif dt <= time_tolerance * 3:
            score += 8.0
        elif dt <= time_tolerance * 10:
            score += 3.0

        l_tcp = left.get("tcp_metrics", {}) if isinstance(left.get("tcp_metrics", {}), dict) else {}
        r_tcp = right.get("tcp_metrics", {}) if isinstance(right.get("tcp_metrics", {}), dict) else {}

        if _safe_int(l_tcp.get("rst"), 0) > 0 and _safe_int(r_tcp.get("rst"), 0) > 0:
            score += 4.0
        if _safe_int(l_tcp.get("syn"), 0) > 0 and _safe_int(r_tcp.get("syn"), 0) > 0:
            score += 4.0

        # Identité de flux: hors NAT, le quadruplet exact est le signal le plus
        # fort. Sans ce bonus, deux connexions d'un même poste vers un même
        # serveur sont indiscernables (et le bonus NAT ci-dessous faisait même
        # gagner le MAUVAIS candidat).
        same_client_ip = str(left.get("client_ip", "")) == str(right.get("client_ip", ""))
        same_client_port = _safe_int(left.get("client_port"), 0) == _safe_int(right.get("client_port"), 0)
        same_server_ip = str(left.get("server_ip", "")) == str(right.get("server_ip", ""))

        if same_client_ip and same_client_port and same_server_ip and lp > 0 and lp == rp:
            score += 25.0
        elif same_client_ip and not same_client_port:
            # Même poste, port source différent = AUTRE connexion, pas une
            # réécriture NAT (un NAT change l'adresse, pas seulement le port)
            score -= 20.0

        # Bonus NAT/PAT probable: même service, mais l'IP client a été réécrite
        if (
            lp > 0
            and lp == rp
            and same_server_ip
            and not same_client_ip
        ):
            score += 10.0

        return score

    def _build_group_record(
        self,
        group: Dict[str, Any],
        capture_points: List[Dict[str, Any]],
        thresholds: Dict[str, float],
    ) -> Dict[str, Any]:
        by_capture = group.get("by_capture", {})
        link_scores = [float(x) for x in group.get("link_scores", [])]

        hops: List[Dict[str, Any]] = []
        presence = []
        total_packets = 0
        total_bytes = 0

        for c_idx, capture in enumerate(capture_points):
            obs = by_capture.get(c_idx)
            capture_id = capture.get("capture_id")
            equip = capture.get("equipment_name")
            present = obs is not None

            if present:
                total_packets += _safe_int(obs.get("packet_count"), 0)
                total_bytes += _safe_int(obs.get("byte_count"), 0)
                hops.append(
                    {
                        "capture_index": c_idx,
                        "capture_id": capture_id,
                        "equipment_name": equip,
                        "protocol": obs.get("protocol"),
                        "client_ip": obs.get("client_ip"),
                        "client_port": _safe_int(obs.get("client_port"), 0),
                        "server_ip": obs.get("server_ip"),
                        "server_port": _safe_int(obs.get("server_port"), 0),
                        "state": obs.get("state"),
                        "packet_count": _safe_int(obs.get("packet_count"), 0),
                        "byte_count": _safe_int(obs.get("byte_count"), 0),
                        "duration_seconds": _safe_float(obs.get("duration_seconds"), 0.0),
                        "first_ts": _safe_float(obs.get("first_ts"), 0.0),
                        "last_ts": _safe_float(obs.get("last_ts"), 0.0),
                        "reference_ts": _safe_float(obs.get("reference_ts"), 0.0),
                        "ttl": obs.get("ttl", {}),
                        "dscp_values": obs.get("dscp_values", []),
                        "vlan_ids": obs.get("vlan_ids", []),
                        "tcp_metrics": obs.get("tcp_metrics", {}),
                        "throughput": obs.get("throughput", {}),
                        "windows": obs.get("windows", {}),
                        "handshake_rtt_ms": obs.get("handshake_rtt_ms"),
                        "theoretical_limits": obs.get("theoretical_limits", {}),
                        # Champ interne (préfixe _): retiré avant sérialisation
                        "_fp_by_dir": obs.get("fp_by_dir", {}),
                    }
                )

            presence.append(
                {
                    "capture_index": c_idx,
                    "capture_id": capture_id,
                    "equipment_name": equip,
                    "present": present,
                    "first_seen": _iso_or_none(_safe_float(obs.get("first_ts"), 0.0)) if present else None,
                    "last_seen": _iso_or_none(_safe_float(obs.get("last_ts"), 0.0)) if present else None,
                }
            )

        changes = self._detect_hop_changes(capture_points, by_capture, thresholds=thresholds)
        confidence_score = self._compute_confidence(len(capture_points), by_capture, link_scores)
        risk = self._derive_risk_and_cause(changes, by_capture, len(capture_points), thresholds=thresholds)
        risk_score = _safe_int(risk.get("risk_score"), 0)
        probable_cause = str(risk.get("probable_cause", "Comportement à surveiller"))
        probable_cause_code = str(risk.get("probable_cause_code", "watch"))
        cause_details = str(risk.get("cause_details", "")).strip()
        root_cause_signals = risk.get("root_cause_signals", [])

        first_obs = None
        for c_idx in range(len(capture_points)):
            if by_capture.get(c_idx):
                first_obs = by_capture[c_idx]
                break

        protocol = str(first_obs.get("protocol", "UNKNOWN")) if first_obs else "UNKNOWN"
        flow_label = "unknown"
        if first_obs:
            flow_label = (
                f"{first_obs.get('client_ip', '?')}:{first_obs.get('client_port', 0)} -> "
                f"{first_obs.get('server_ip', '?')}:{first_obs.get('server_port', 0)}"
            )

        return {
            "session_id": group.get("group_id"),
            "protocol": protocol,
            "flow_label": flow_label,
            "presence": presence,
            "hops": hops,
            "changes": changes,
            "confidence_score": confidence_score,
            "confidence_level": self._confidence_level(confidence_score),
            "risk_score": risk_score,
            "problematic": risk_score >= 45 or len(changes) >= 2,
            "probable_cause": probable_cause,
            "probable_cause_code": probable_cause_code,
            "cause_details": cause_details,
            "root_cause_signals": root_cause_signals,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "latency_by_hop": [],
            "latency_total_ms": None,
            "latency_confidence": "UNKNOWN",
            "degradation_segments": [],
            "degradation_primary": None,
        }

    def _compute_confidence(self, total_captures: int, by_capture: Dict[int, Any], link_scores: List[float]) -> int:
        presence_ratio = len(by_capture) / max(total_captures, 1)
        avg_link = (sum(link_scores) / len(link_scores)) if link_scores else 35.0
        gap_penalty = max(0, (total_captures - len(by_capture)) * 8)
        score = int(round((presence_ratio * 45.0) + (avg_link * 0.6) - gap_penalty))
        return max(0, min(100, score))

    def _confidence_level(self, score: int) -> str:
        if score >= 75:
            return "HIGH"
        if score >= 45:
            return "MEDIUM"
        return "LOW"

    def _detect_hop_changes(
        self,
        capture_points: List[Dict[str, Any]],
        by_capture: Dict[int, Any],
        thresholds: Optional[Dict[str, float]] = None,
    ) -> List[Dict[str, Any]]:
        changes: List[Dict[str, Any]] = []
        cfg = _sanitize_root_cause_thresholds(thresholds)

        for idx in range(len(capture_points) - 1):
            left = by_capture.get(idx)
            right = by_capture.get(idx + 1)
            from_name = capture_points[idx].get("equipment_name")
            to_name = capture_points[idx + 1].get("equipment_name")

            if left and not right:
                changes.append(
                    {
                        "hop": f"{from_name} -> {to_name}",
                        "type": "disappearance",
                        "severity": "HIGH",
                        "description": "Session visible au point amont mais absente au point aval (drop, filtrage, asymétrie ou capture incomplète).",
                    }
                )
                continue

            if not left and right:
                changes.append(
                    {
                        "hop": f"{from_name} -> {to_name}",
                        "type": "appearance",
                        "severity": "MEDIUM",
                        "description": "Session absente au point amont mais visible au point aval (capture partielle, asymétrie, point de capture trop tardif).",
                    }
                )
                continue

            if not left or not right:
                continue

            # NAT / réécriture IP/ports
            if str(left.get("client_ip")) != str(right.get("client_ip")) or str(left.get("server_ip")) != str(right.get("server_ip")):
                changes.append(
                    {
                        "hop": f"{from_name} -> {to_name}",
                        "type": "ip_rewrite",
                        "severity": "MEDIUM",
                        "description": (
                            f"Changement d'IP observé: {left.get('client_ip')}->{left.get('server_ip')} vers "
                            f"{right.get('client_ip')}->{right.get('server_ip')} (NAT/routage/policy)."
                        ),
                    }
                )

            if _safe_int(left.get("client_port"), 0) != _safe_int(right.get("client_port"), 0) or _safe_int(left.get("server_port"), 0) != _safe_int(right.get("server_port"), 0):
                changes.append(
                    {
                        "hop": f"{from_name} -> {to_name}",
                        "type": "port_rewrite",
                        "severity": "MEDIUM",
                        "description": "Réécriture de port détectée (PAT/LB/proxy possible).",
                    }
                )

            # TTL / DSCP / VLAN
            l_ttl = _safe_float((left.get("ttl") or {}).get("avg"), 0.0)
            r_ttl = _safe_float((right.get("ttl") or {}).get("avg"), 0.0)
            ttl_delta = abs(l_ttl - r_ttl)
            if ttl_delta >= cfg["ttl_shift_medium"]:
                severity = "HIGH" if ttl_delta >= cfg["ttl_shift_high"] else "MEDIUM"
                changes.append(
                    {
                        "hop": f"{from_name} -> {to_name}",
                        "type": "ttl_shift",
                        "severity": severity,
                        "description": f"Variation TTL/HopLimit moyenne: {l_ttl:.1f} -> {r_ttl:.1f} (Δ={ttl_delta:.1f}).",
                    }
                )

            if set(left.get("dscp_values", [])) != set(right.get("dscp_values", [])):
                changes.append(
                    {
                        "hop": f"{from_name} -> {to_name}",
                        "type": "dscp_change",
                        "severity": "MEDIUM",
                        "description": f"DSCP/ToS modifié: {left.get('dscp_values', [])} -> {right.get('dscp_values', [])}.",
                    }
                )

            if set(left.get("vlan_ids", [])) != set(right.get("vlan_ids", [])):
                changes.append(
                    {
                        "hop": f"{from_name} -> {to_name}",
                        "type": "vlan_change",
                        "severity": "MEDIUM",
                        "description": f"VLAN modifié: {left.get('vlan_ids', [])} -> {right.get('vlan_ids', [])}.",
                    }
                )

            # TCP options / window
            l_tcp = left.get("tcp_metrics", {}) if isinstance(left.get("tcp_metrics", {}), dict) else {}
            r_tcp = right.get("tcp_metrics", {}) if isinstance(right.get("tcp_metrics", {}), dict) else {}

            if set(l_tcp.get("mss_values", [])) != set(r_tcp.get("mss_values", [])):
                changes.append(
                    {
                        "hop": f"{from_name} -> {to_name}",
                        "type": "mss_change",
                        "severity": "HIGH",
                        "description": f"MSS changé: {l_tcp.get('mss_values', [])} -> {r_tcp.get('mss_values', [])} (MTU/fragmentation suspecte).",
                    }
                )

            l_wnd = _safe_float((l_tcp.get("window") or {}).get("avg"), 0.0)
            r_wnd = _safe_float((r_tcp.get("window") or {}).get("avg"), 0.0)
            if l_wnd > 0 and r_wnd > 0:
                ratio = max(l_wnd, r_wnd) / max(1.0, min(l_wnd, r_wnd))
                if ratio >= 1.8:
                    changes.append(
                        {
                            "hop": f"{from_name} -> {to_name}",
                            "type": "window_shift",
                            "severity": "MEDIUM",
                            "description": f"Window Size moyenne modifiée: {l_wnd:.1f} -> {r_wnd:.1f}.",
                        }
                    )

            if bool(l_tcp.get("sack_seen")) != bool(r_tcp.get("sack_seen")):
                changes.append(
                    {
                        "hop": f"{from_name} -> {to_name}",
                        "type": "sack_toggle",
                        "severity": "MEDIUM",
                        "description": "Différence SACK observée entre points de capture.",
                    }
                )

            if bool(l_tcp.get("timestamp_seen")) != bool(r_tcp.get("timestamp_seen")):
                changes.append(
                    {
                        "hop": f"{from_name} -> {to_name}",
                        "type": "tcp_timestamp_toggle",
                        "severity": "LOW",
                        "description": "Différence option TCP Timestamp observée.",
                    }
                )

            # Symptômes qualité
            l_retrans = _safe_float(l_tcp.get("retrans_ratio"), 0.0)
            r_retrans = _safe_float(r_tcp.get("retrans_ratio"), 0.0)
            retrans_delta = r_retrans - l_retrans
            if retrans_delta >= cfg["retrans_increase_medium"]:
                changes.append(
                    {
                        "hop": f"{from_name} -> {to_name}",
                        "type": "retrans_increase",
                        "severity": "HIGH" if retrans_delta >= cfg["retrans_increase_high"] else "MEDIUM",
                        "description": f"Hausse des retransmissions: {l_retrans*100:.1f}% -> {r_retrans*100:.1f}%.",
                    }
                )

            l_rst = _safe_int(l_tcp.get("rst"), 0)
            r_rst = _safe_int(r_tcp.get("rst"), 0)
            if l_rst != r_rst:
                changes.append(
                    {
                        "hop": f"{from_name} -> {to_name}",
                        "type": "rst_delta",
                        "severity": "HIGH" if r_rst > l_rst else "MEDIUM",
                        "description": f"Variation des paquets RST: {l_rst} -> {r_rst}.",
                    }
                )

            l_pkt = _safe_int(left.get("packet_count"), 0)
            r_pkt = _safe_int(right.get("packet_count"), 0)
            if l_pkt > 0:
                ratio = r_pkt / float(max(1, l_pkt))
                if ratio < 0.7 or ratio > 1.3:
                    changes.append(
                        {
                            "hop": f"{from_name} -> {to_name}",
                            "type": "packet_volume_shift",
                            "severity": "MEDIUM",
                            "description": f"Variation du volume paquets: {l_pkt} -> {r_pkt} (ratio={ratio:.2f}).",
                        }
                    )

        return changes

    def _derive_risk_and_cause(
        self,
        changes: List[Dict[str, Any]],
        by_capture: Dict[int, Any],
        total_capture_points: int,
        thresholds: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        cfg = _sanitize_root_cause_thresholds(thresholds)
        score = 0
        sev_weight = {"LOW": 8, "MEDIUM": 16, "HIGH": 28, "CRITICAL": 40}
        for change in changes:
            score += sev_weight.get(str(change.get("severity", "LOW")).upper(), 8)

        def add_signal(
            rows: List[Dict[str, Any]],
            code: str,
            label: str,
            severity: str,
            weight: int,
            evidence: str,
        ) -> None:
            rows.append(
                {
                    "code": code,
                    "label": label,
                    "severity": str(severity or "LOW").upper(),
                    "weight": int(max(0, weight)),
                    "evidence": evidence,
                }
            )

        all_tcp = []
        for obs in by_capture.values():
            tcp = obs.get("tcp_metrics", {}) if isinstance(obs.get("tcp_metrics", {}), dict) else {}
            all_tcp.append(tcp)

        rst_total = sum(_safe_int(t.get("rst"), 0) for t in all_tcp)
        retrans_ratio_max = max([_safe_float(t.get("retrans_ratio"), 0.0) for t in all_tcp] + [0.0])
        dup_acks_total = sum(_safe_int(t.get("dup_acks"), 0) for t in all_tcp)
        out_of_order_total = sum(_safe_int(t.get("out_of_order"), 0) for t in all_tcp)
        half_open = any(str(obs.get("state", "")).upper() == "SYN_ONLY" for obs in by_capture.values())
        types = {str(c.get("type", "")).lower() for c in changes}
        signals: List[Dict[str, Any]] = []

        if rst_total > 0:
            score += min(30, rst_total * 8)
        if retrans_ratio_max >= cfg["retrans_increase_high"]:
            score += 22
        elif retrans_ratio_max >= cfg["retrans_increase_medium"]:
            score += 12
        if half_open:
            score += 18

        by_idx = {int(k): v for k, v in by_capture.items()}
        present_indexes = sorted(by_idx.keys())
        has_middle_gap = any((b - a) > 1 for a, b in zip(present_indexes, present_indexes[1:]))
        missing_hops = max(0, total_capture_points - len(present_indexes))

        # NAT/PAT suspect: service identique, serveur stable, client IP/port réécrits.
        nat_pairs = 0
        for left_idx, right_idx in zip(present_indexes, present_indexes[1:]):
            left = by_idx.get(left_idx, {})
            right = by_idx.get(right_idx, {})
            if str(left.get("server_ip", "")) and str(left.get("server_ip", "")) == str(right.get("server_ip", "")):
                client_changed = str(left.get("client_ip", "")) != str(right.get("client_ip", ""))
                client_port_changed = _safe_int(left.get("client_port"), 0) != _safe_int(right.get("client_port"), 0)
                if client_changed or client_port_changed:
                    nat_pairs += 1

        if nat_pairs > 0 and ("ip_rewrite" in types or "port_rewrite" in types):
            weight = 20 + min(20, nat_pairs * int(cfg["nat_pairs_weight_step"]))
            add_signal(
                signals,
                "nat-suspect",
                "NAT/PAT suspect (réécriture de session)",
                "MEDIUM" if nat_pairs == 1 else "HIGH",
                weight,
                f"{nat_pairs} transition(s) hop avec IP/port client réécrits et serveur stable.",
            )

        # MTU blackhole: changement MSS + pertes/retransmissions + handshake incomplet/disparition.
        all_mss_values: List[int] = []
        for t in all_tcp:
            mss_values = t.get("mss_values", [])
            if isinstance(mss_values, list):
                all_mss_values.extend([_safe_int(v, 0) for v in mss_values if _safe_int(v, 0) > 0])
        mss_spread = (max(all_mss_values) - min(all_mss_values)) if all_mss_values else 0
        mtu_signal = (
            ("mss_change" in types or mss_spread >= cfg["mss_spread_signal_min"])
            and (retrans_ratio_max >= cfg["retrans_increase_medium"] or "retrans_increase" in types)
            and (half_open or "disappearance" in types or dup_acks_total >= 2)
        )
        if mtu_signal:
            add_signal(
                signals,
                "mtu-blackhole",
                "MTU blackhole probable (MSS/fragmentation)",
                "HIGH",
                34,
                (
                    f"MSS variable (écart {mss_spread}) avec retrans max {retrans_ratio_max*100:.1f}% "
                    "et symptômes de perte/handshake incomplet."
                ),
            )

        # Bufferbloat: durée qui gonfle, fenêtre TCP qui s'écrase, dup ACK sans explosion RST.
        durations = [_safe_float(obs.get("duration_seconds"), 0.0) for obs in by_capture.values() if _safe_float(obs.get("duration_seconds"), 0.0) > 0.0]
        duration_growth = (max(durations) / max(0.001, min(durations))) if len(durations) >= 2 else 1.0
        windows = []
        for t in all_tcp:
            wnd = _safe_float((t.get("window") or {}).get("avg"), 0.0)
            if wnd > 0:
                windows.append(wnd)
        window_spread = (max(windows) / max(1.0, min(windows))) if len(windows) >= 2 else 1.0
        high_volume = any(_safe_int(obs.get("packet_count"), 0) >= 120 for obs in by_capture.values())
        if (
            duration_growth >= cfg["bufferbloat_duration_ratio"]
            and window_spread >= cfg["bufferbloat_window_ratio"]
            and (dup_acks_total + out_of_order_total) >= int(cfg["bufferbloat_reorder_min"])
            and high_volume
            and rst_total <= 1
        ):
            add_signal(
                signals,
                "bufferbloat",
                "Bufferbloat probable (files d'attente saturées)",
                "MEDIUM",
                26,
                (
                    f"Durée x{duration_growth:.2f}, fenêtre TCP ratio x{window_spread:.2f}, "
                    f"dupACK/out-of-order={dup_acks_total + out_of_order_total}."
                ),
            )

        # Asymétrie / trou de visibilité entre hops.
        if (
            has_middle_gap
            or ("appearance" in types and "disappearance" in types)
            or missing_hops >= int(cfg["asymmetry_missing_hops_min"])
        ):
            add_signal(
                signals,
                "asymmetry",
                "Routage asymétrique ou capture partielle",
                "HIGH" if has_middle_gap else "MEDIUM",
                28 if has_middle_gap else 22,
                (
                    "Présence de gaps de session entre points de capture "
                    f"(hops manquants: {missing_hops}, gap interne: {'oui' if has_middle_gap else 'non'})."
                ),
            )

        # Signaux classiques complémentaires
        if "rst_delta" in types or rst_total >= 2:
            add_signal(
                signals,
                "reset-pair",
                "Reset TCP induit par un équipement intermédiaire",
                "HIGH",
                24,
                f"RST cumulés observés: {rst_total}.",
            )
        if "retrans_increase" in types or retrans_ratio_max >= cfg["retrans_increase_medium"]:
            sev = "HIGH" if retrans_ratio_max >= cfg["retrans_increase_high"] else "MEDIUM"
            add_signal(
                signals,
                "congestion-loss",
                "Congestion/perte sur un segment",
                sev,
                22 if sev == "HIGH" else 14,
                f"Retransmissions max: {retrans_ratio_max*100:.1f}%.",
            )
        if half_open:
            add_signal(
                signals,
                "half-open",
                "Handshake TCP incomplet (half-open)",
                "MEDIUM",
                18,
                "SYN observé sans établissement complet sur au moins un point.",
            )
        if "disappearance" in types:
            add_signal(
                signals,
                "loss",
                "Perte/filtrage sur un segment",
                "HIGH",
                24,
                "Session présente en amont et absente en aval.",
            )

        # Consolidation du score: base + combinaison pondérée des signaux les plus forts.
        signals.sort(key=lambda s: int(s.get("weight", 0)), reverse=True)
        weights = [int(s.get("weight", 0)) for s in signals]
        signal_score = 0.0
        for idx, w in enumerate(weights[:4]):
            decay = 1.0 if idx == 0 else (0.65 if idx == 1 else (0.45 if idx == 2 else 0.3))
            signal_score += float(w) * decay

        score += min(55, int(round(signal_score)))
        score = max(0, min(100, score))

        if signals:
            top = signals[0]
            cause = str(top.get("label", "Comportement à surveiller"))
            cause_code = str(top.get("code", "watch"))
            cause_details = str(top.get("evidence", "")).strip()
        elif score < 20:
            cause = "Flux globalement stable"
            cause_code = "stable"
            cause_details = "Aucun signal fort de rupture ou de dégradation multi-hop."
        else:
            cause = "Comportement à surveiller"
            cause_code = "watch"
            cause_details = "Signaux faibles ou contradictoires, surveillance recommandée."

        return {
            "risk_score": score,
            "probable_cause": cause,
            "probable_cause_code": cause_code,
            "cause_details": cause_details,
            "root_cause_signals": signals[:6],
        }

    @staticmethod
    def _apply_packet_loss_to_risk(session: Dict[str, Any]) -> None:
        """Intègre les pertes localisées au paquet dans le risque de la session.

        Sans cela, un flux traversant un segment qui lui mange 10% de ses
        paquets pouvait rester noté « stable »: les détecteurs historiques
        comparent des agrégats de session, pas les paquets un à un.
        """
        rows = session.get("packet_match_by_segment") or []
        if not rows:
            return

        worst = max(rows, key=lambda r: _safe_float(r.get("loss_ratio"), 0.0))
        loss_pct = _safe_float(worst.get("loss_ratio"), 0.0) * 100.0
        if loss_pct < 1.0:
            return

        if loss_pct >= 10:
            bonus, severity = 45, "HIGH"
        elif loss_pct >= 3:
            bonus, severity = 30, "MEDIUM"
        else:
            bonus, severity = 15, "LOW"

        session["risk_score"] = min(100, _safe_int(session.get("risk_score"), 0) + bonus)
        if session["risk_score"] >= 45:
            session["problematic"] = True

        hops = {_safe_int(h.get("capture_index"), -1): h for h in session.get("hops", [])}
        left = hops.get(_safe_int(worst.get("from_capture_index"), -1), {})
        right = hops.get(_safe_int(worst.get("to_capture_index"), -1), {})
        segment_label = f"{left.get('equipment_name', '?')} -> {right.get('equipment_name', '?')}"
        evidence = (
            f"{loss_pct:.2f}% des paquets de ce flux disparaissent sur {segment_label} "
            f"({_safe_int(worst.get('lost_packets'), 0)} paquets sur "
            f"{_safe_int(worst.get('upstream_packets'), 0)})."
        )

        # La perte de paquets prime sur les causes heuristiques existantes
        if loss_pct >= 3 or str(session.get("probable_cause_code", "")) in {"stable", "watch", ""}:
            session["probable_cause"] = f"Pertes de paquets sur {segment_label}"
            session["probable_cause_code"] = "packet_loss_segment"
            session["cause_details"] = evidence

        signals = session.get("root_cause_signals")
        if not isinstance(signals, list):
            signals = []
        signals.insert(0, {
            "code": "packet_loss_segment",
            "label": f"Pertes de paquets sur {segment_label}",
            "severity": severity,
            "evidence": evidence,
        })
        session["root_cause_signals"] = signals[:6]

        changes = session.get("changes")
        if isinstance(changes, list):
            changes.append({
                "hop": segment_label,
                "type": "packet_loss",
                "severity": severity,
                "description": evidence,
            })

        # Aligner le « segment déclencheur » sur la preuve la plus solide:
        # sinon l'ancienne heuristique de latence pouvait désigner un segment
        # sain pendant que le verdict incrimine celui qui perd les paquets.
        from_idx = _safe_int(worst.get("from_capture_index"), -1)
        to_idx = _safe_int(worst.get("to_capture_index"), -1)
        loss_reason = f"Pertes de paquets mesurées: {loss_pct:.2f}% sur ce segment."
        segments = session.get("degradation_segments")
        target = None
        if isinstance(segments, list):
            for row in segments:
                if (isinstance(row, dict)
                        and _safe_int(row.get("from_capture_index"), -2) == from_idx
                        and _safe_int(row.get("to_capture_index"), -2) == to_idx):
                    target = row
                    break

        if target is None:
            target = {
                "segment": segment_label,
                "from_capture_index": from_idx,
                "to_capture_index": to_idx,
                "from_equipment": left.get("equipment_name"),
                "to_equipment": right.get("equipment_name"),
                "score": 0,
                "latency_ms": None,
                "latency_confidence": "UNKNOWN",
                "change_types": [],
                "reasons": [],
            }
            if isinstance(segments, list):
                segments.append(target)
            else:
                session["degradation_segments"] = segments = [target]

        target["score"] = max(_safe_int(target.get("score"), 0), bonus)
        target["severity"] = severity
        target["triggered"] = True
        reasons = target.get("reasons")
        if not isinstance(reasons, list):
            reasons = []
        if loss_reason not in reasons:
            reasons.insert(0, loss_reason)
        target["reasons"] = reasons[:8]
        change_types = target.get("change_types")
        if isinstance(change_types, list) and "packet_loss" not in change_types:
            change_types.append("packet_loss")

        if isinstance(segments, list):
            segments.sort(key=lambda r: (_safe_int(r.get("score"), 0), len(r.get("reasons", []) or [])), reverse=True)
        session["degradation_primary"] = target

    # ------------------------------------------------------------------
    # Bande passante inter-points et verdicts de goulot (Phases 1 & 3)
    # ------------------------------------------------------------------

    def _build_bandwidth_chain(
        self,
        capture_points: List[Dict[str, Any]],
        sessions: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Compare le débit observé aux points successifs.

        Un écart de goodput entre deux points sur les MÊMES flux corrélés est
        l'indicateur le plus direct d'un goulot: ce qui entre au point A et
        n'arrive pas au point B a été perdu, jeté ou mis en file d'attente.
        """
        per_point: List[Dict[str, Any]] = []
        for cp in capture_points:
            dur = max(0.001, _safe_float(cp.get("capture_duration_seconds"), 0.0))
            series = cp.get("_bytes_per_second", {}) or {}
            values = sorted(float(v) for v in series.values())
            peak_mbps = (values[-1] * 8.0 / 1_000_000.0) if values else 0.0
            p95_mbps = (_percentile(values, 95.0) * 8.0 / 1_000_000.0) if values else 0.0
            per_point.append({
                "capture_index": _safe_int(cp.get("capture_index"), 0),
                "equipment_name": cp.get("equipment_name"),
                "avg_mbps": round((_safe_int(cp.get("byte_count"), 0) * 8.0) / dur / 1_000_000.0, 4),
                "peak_mbps": round(peak_mbps, 4),
                "p95_mbps": round(p95_mbps, 4),
                "active_seconds": len(series),
            })

        # Agrégation par segment, sur les sessions présentes des deux côtés
        seg_acc: Dict[Tuple[int, int], Dict[str, float]] = defaultdict(
            lambda: {"up_good": 0.0, "down_good": 0.0, "up_wire": 0.0, "down_wire": 0.0, "sessions": 0}
        )

        def _good(hop: Dict[str, Any]) -> float:
            tp = hop.get("throughput", {}) or {}
            return (
                _safe_float((tp.get("client_to_server") or {}).get("goodput_bytes"), 0.0)
                + _safe_float((tp.get("server_to_client") or {}).get("goodput_bytes"), 0.0)
            )

        def _wire(hop: Dict[str, Any]) -> float:
            tp = hop.get("throughput", {}) or {}
            return (
                _safe_float((tp.get("client_to_server") or {}).get("wire_bytes"), 0.0)
                + _safe_float((tp.get("server_to_client") or {}).get("wire_bytes"), 0.0)
            )

        for session in sessions:
            hops = {_safe_int(h.get("capture_index"), -1): h for h in session.get("hops", [])}
            for idx in range(len(capture_points) - 1):
                left, right = hops.get(idx), hops.get(idx + 1)
                if not left or not right:
                    continue
                acc = seg_acc[(idx, idx + 1)]
                acc["up_good"] += _good(left)
                acc["down_good"] += _good(right)
                acc["up_wire"] += _wire(left)
                acc["down_wire"] += _wire(right)
                acc["sessions"] += 1

        segments: List[Dict[str, Any]] = []
        for (a, b), acc in sorted(seg_acc.items()):
            up_good, down_good = acc["up_good"], acc["down_good"]
            delivery = (down_good / up_good) if up_good > 0 else None
            loss_pct = round((1.0 - delivery) * 100.0, 3) if delivery is not None else None
            segments.append({
                "from_capture_index": a,
                "to_capture_index": b,
                "from_equipment": capture_points[a].get("equipment_name"),
                "to_equipment": capture_points[b].get("equipment_name"),
                "segment": f"{capture_points[a].get('equipment_name')} -> {capture_points[b].get('equipment_name')}",
                "sessions_compared": int(acc["sessions"]),
                "upstream_goodput_bytes": int(up_good),
                "downstream_goodput_bytes": int(down_good),
                "delivery_ratio": round(delivery, 6) if delivery is not None else None,
                "goodput_loss_pct": loss_pct,
                "upstream_wire_bytes": int(acc["up_wire"]),
                "downstream_wire_bytes": int(acc["down_wire"]),
            })

        return {"per_capture_point": per_point, "segments": segments}

    @staticmethod
    def _classify_flow_limitation(session: Dict[str, Any]) -> Dict[str, Any]:
        """Pourquoi ce flux ne va-t-il pas plus vite ?

        - receiver-limited : la fenêtre annoncée plafonne le débit (zero-window,
          ou débit ≈ borne rwnd/RTT)
        - network-limited  : pertes/retransmissions significatives
        - application-limited : fenêtre ouverte, pas de pertes, mais l'émetteur
          n'envoie pas (le débit reste très en deçà des bornes)
        """
        hops = [h for h in session.get("hops", []) if isinstance(h, dict)]
        if not hops:
            return {"class": "UNKNOWN", "reason": "Aucun point d'observation exploitable."}

        ref = hops[0]
        tp = ref.get("throughput", {}) or {}
        windows = ref.get("windows", {}) or {}
        limits = ref.get("theoretical_limits", {}) or {}
        tcp_metrics = ref.get("tcp_metrics", {}) or {}

        observed = max(
            _safe_float((tp.get("client_to_server") or {}).get("goodput_mbps"), 0.0),
            _safe_float((tp.get("server_to_client") or {}).get("goodput_mbps"), 0.0),
        )
        zero_win = (
            _safe_int((windows.get("client_to_server") or {}).get("zero_window_events"), 0)
            + _safe_int((windows.get("server_to_client") or {}).get("zero_window_events"), 0)
        )
        retrans_ratio = _safe_float(tcp_metrics.get("retrans_ratio"), 0.0)
        win_limit = _safe_float(limits.get("window_limited_mbps"), 0.0)
        loss_limit = _safe_float(limits.get("loss_limited_mbps"), 0.0)

        if zero_win > 0:
            return {
                "class": "RECEIVER_LIMITED",
                "reason": f"{zero_win} annonce(s) de fenêtre nulle: le récepteur ne draine pas assez vite.",
                "observed_mbps": round(observed, 4),
                "window_limited_mbps": win_limit or None,
                "loss_limited_mbps": loss_limit or None,
            }
        if retrans_ratio >= 0.01:
            return {
                "class": "NETWORK_LIMITED",
                "reason": f"Retransmissions à {round(retrans_ratio * 100, 2)}%: le réseau limite via les pertes.",
                "observed_mbps": round(observed, 4),
                "window_limited_mbps": win_limit or None,
                "loss_limited_mbps": loss_limit or None,
            }
        if win_limit > 0 and observed >= win_limit * 0.8:
            return {
                "class": "RECEIVER_LIMITED",
                "reason": "Débit au plafond rwnd/RTT: augmenter la fenêtre de réception (ou réduire le RTT).",
                "observed_mbps": round(observed, 4),
                "window_limited_mbps": win_limit,
                "loss_limited_mbps": loss_limit or None,
            }
        if win_limit > 0 and observed < win_limit * 0.3:
            return {
                "class": "APPLICATION_LIMITED",
                "reason": "Fenêtre disponible et peu de pertes: l'émetteur n'alimente pas le lien.",
                "observed_mbps": round(observed, 4),
                "window_limited_mbps": win_limit,
                "loss_limited_mbps": loss_limit or None,
            }
        return {
            "class": "UNDETERMINED",
            "reason": "Aucun facteur limitant dominant (RTT ou fenêtre non mesurables de façon fiable).",
            "observed_mbps": round(observed, 4),
            "window_limited_mbps": win_limit or None,
            "loss_limited_mbps": loss_limit or None,
        }

    def _build_bottleneck_verdicts(
        self,
        bandwidth_chain: Dict[str, Any],
        packet_match: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Verdict par segment: score + cause dominante + recommandation.

        Croise perte de goodput (bande passante), pertes localisées au paquet,
        délai relatif ajouté et gigue de file d'attente.
        """
        by_pair: Dict[Tuple[int, int], Dict[str, Any]] = {}
        for seg in bandwidth_chain.get("segments", []):
            by_pair[(seg["from_capture_index"], seg["to_capture_index"])] = {"bw": seg, "pkt": None}
        for seg in packet_match.get("segments", []):
            key = (seg["from_capture_index"], seg["to_capture_index"])
            by_pair.setdefault(key, {"bw": None, "pkt": None})["pkt"] = seg

        verdicts: List[Dict[str, Any]] = []
        for (a, b), data in sorted(by_pair.items()):
            bw, pkt = data.get("bw"), data.get("pkt")
            reasons: List[str] = []
            recommendations: List[str] = []
            score = 0.0

            goodput_loss = _safe_float((bw or {}).get("goodput_loss_pct"), 0.0) if bw else 0.0
            if goodput_loss >= 20:
                score += 40
                reasons.append(f"Perte de goodput de {goodput_loss:.1f}% entre les deux points.")
            elif goodput_loss >= 5:
                score += 20
                reasons.append(f"Baisse de goodput de {goodput_loss:.1f}% entre les deux points.")

            pkt_loss_pct = _safe_float((pkt or {}).get("loss_ratio"), 0.0) * 100.0 if pkt else 0.0
            if pkt_loss_pct >= 2:
                score += 35
                reasons.append(f"{pkt_loss_pct:.2f}% des paquets amont n'atteignent jamais le point aval.")
                recommendations.append("Vérifier saturation, policing/ACL et erreurs d'interface sur ce segment.")
            elif pkt_loss_pct >= 0.5:
                score += 18
                reasons.append(f"Pertes localisées: {pkt_loss_pct:.2f}% des paquets disparaissent sur ce segment.")

            delay = (pkt or {}).get("relative_delay_ms") or {}
            delay_p95 = _safe_float(delay.get("p95"), 0.0)
            delay_min = _safe_float(delay.get("min"), 0.0)
            added = delay_p95 - delay_min
            if added >= 100:
                score += 30
                reasons.append(f"Délai ajouté p95 de {added:.1f} ms (mise en file d'attente marquée).")
                recommendations.append("Suspicion de bufferbloat: contrôler les buffers/QoS de l'équipement aval.")
            elif added >= 30:
                score += 15
                reasons.append(f"Délai ajouté p95 de {added:.1f} ms sur ce segment.")

            jitter = _safe_float((pkt or {}).get("queuing_jitter_ms"), 0.0)
            if jitter >= 50:
                score += 12
                reasons.append(f"Gigue de file d'attente de {jitter:.1f} ms.")

            # Signature shaper (délai sans perte) vs policer (perte sans délai)
            signature = None
            if added >= 30 and pkt_loss_pct < 0.5:
                signature = "SHAPING"
                recommendations.append("Profil de shaping (file d'attente sans perte): vérifier les limites de débit configurées.")
            elif pkt_loss_pct >= 2 and added < 10:
                signature = "POLICING"
                recommendations.append("Profil de policing (pertes sans file d'attente): vérifier les rate-limiters/CAR.")

            score = max(0.0, min(100.0, score))
            severity = "HIGH" if score >= 60 else ("MEDIUM" if score >= 30 else "LOW")
            confidence = str((pkt or {}).get("confidence", "LOW")).upper()

            verdicts.append({
                "from_capture_index": a,
                "to_capture_index": b,
                "segment": (bw or pkt or {}).get("segment"),
                "from_equipment": (bw or pkt or {}).get("from_equipment"),
                "to_equipment": (bw or pkt or {}).get("to_equipment"),
                "bottleneck_score": round(score, 1),
                "severity": severity,
                "confidence": confidence,
                "goodput_loss_pct": round(goodput_loss, 3),
                "packet_loss_pct": round(pkt_loss_pct, 3),
                "added_delay_p95_ms": round(added, 3),
                "queuing_jitter_ms": round(jitter, 3),
                "traffic_shaping_signature": signature,
                "reasons": reasons or ["Aucun signal de dégradation notable sur ce segment."],
                "recommendations": recommendations,
            })

        verdicts.sort(key=lambda v: v.get("bottleneck_score", 0.0), reverse=True)
        return verdicts

    # ------------------------------------------------------------------
    # Appariement paquet-à-paquet entre points de capture (Phase 2)
    # ------------------------------------------------------------------

    def _match_packets_across_captures(
        self,
        capture_points: List[Dict[str, Any]],
        sessions: List[Dict[str, Any]],
        max_samples_per_session: int = 2000,
    ) -> Dict[str, Any]:
        """Retrouve le MÊME paquet aux points successifs de la chaîne.

        Pour chaque session corrélée et chaque paire de points consécutifs, on
        intersecte les empreintes (seq + taille + IP ID) par direction:
          - paquet vu des deux côtés  -> échantillon de délai one-way (OWD)
          - paquet vu en amont seulement -> perte imputée à ce segment

        Les horloges des équipements n'étant pas synchronisées, le délai brut
        contient un décalage constant. On le retire via la MÉDIANE des délais du
        segment: les valeurs publiées sont donc des délais RELATIFS (variation,
        jitter, gigue de file d'attente), pas des délais absolus.
        """
        seg_samples: Dict[Tuple[int, int], List[float]] = defaultdict(list)
        seg_lost: Dict[Tuple[int, int], int] = defaultdict(int)
        seg_matched: Dict[Tuple[int, int], int] = defaultdict(int)
        seg_upstream: Dict[Tuple[int, int], int] = defaultdict(int)
        per_session: Dict[str, List[Dict[str, Any]]] = {}

        for session in sessions:
            hops = {_safe_int(h.get("capture_index"), -1): h for h in session.get("hops", [])}
            session_rows: List[Dict[str, Any]] = []

            for idx in range(len(capture_points) - 1):
                left, right = hops.get(idx), hops.get(idx + 1)
                if not left or not right:
                    continue

                left_fp = left.get("_fp_by_dir") or {}
                right_fp = right.get("_fp_by_dir") or {}
                if not left_fp or not right_fp:
                    continue

                deltas: List[float] = []
                matched = 0
                lost = 0
                upstream_total = 0

                for dir_key, left_map in left_fp.items():
                    # Direction identique attendue en aval; sinon (NAT) on
                    # tente l'appariement toutes directions confondues
                    right_map = right_fp.get(dir_key)
                    if right_map is None:
                        right_map = {}
                        for cand in right_fp.values():
                            right_map.update(cand)

                    budget = max_samples_per_session
                    for fp, l_ts in left_map.items():
                        upstream_total += 1
                        r_ts = right_map.get(fp)
                        if r_ts is None:
                            lost += 1
                            continue
                        matched += 1
                        if budget > 0:
                            deltas.append(float(r_ts) - float(l_ts))
                            budget -= 1

                if upstream_total == 0:
                    continue

                pair = (idx, idx + 1)
                seg_samples[pair].extend(deltas[:max_samples_per_session])
                seg_lost[pair] += lost
                seg_matched[pair] += matched
                seg_upstream[pair] += upstream_total

                session_rows.append({
                    "from_capture_index": idx,
                    "to_capture_index": idx + 1,
                    "matched_packets": matched,
                    "lost_packets": lost,
                    "upstream_packets": upstream_total,
                    "loss_ratio": round(lost / float(upstream_total), 6),
                    "_deltas": deltas,
                })

            if session_rows:
                per_session[str(session.get("session_id"))] = session_rows

        # Décalage d'horloge par segment = médiane des délais bruts
        segments: List[Dict[str, Any]] = []
        skew_by_pair: Dict[Tuple[int, int], float] = {}

        for pair in sorted(set(list(seg_samples.keys()) + list(seg_upstream.keys()))):
            a, b = pair
            raw = seg_samples.get(pair, [])
            upstream = seg_upstream.get(pair, 0)
            matched = seg_matched.get(pair, 0)
            lost = seg_lost.get(pair, 0)

            skew = float(median(raw)) if raw else 0.0
            skew_by_pair[pair] = skew
            rel_ms = sorted((v - skew) * 1000.0 for v in raw)

            # Gigue de file d'attente: écart entre le délai typique et le minimum
            min_ms = rel_ms[0] if rel_ms else 0.0
            p50 = _percentile(rel_ms, 50.0) if rel_ms else 0.0
            p95 = _percentile(rel_ms, 95.0) if rel_ms else 0.0
            p99 = _percentile(rel_ms, 99.0) if rel_ms else 0.0
            jitter = round(p95 - min_ms, 3) if rel_ms else 0.0

            # Confiance: nombre d'échantillons + dispersion + taux d'appariement
            match_ratio = (matched / float(upstream)) if upstream > 0 else 0.0
            if len(rel_ms) >= 50 and match_ratio >= 0.7 and (p95 - min_ms) < 100:
                conf = "HIGH"
            elif len(rel_ms) >= 10 and match_ratio >= 0.4:
                conf = "MEDIUM"
            else:
                conf = "LOW"

            segments.append({
                "from_capture_index": a,
                "to_capture_index": b,
                "from_equipment": capture_points[a].get("equipment_name"),
                "to_equipment": capture_points[b].get("equipment_name"),
                "segment": f"{capture_points[a].get('equipment_name')} -> {capture_points[b].get('equipment_name')}",
                "sample_count": len(rel_ms),
                "matched_packets": matched,
                "upstream_packets": upstream,
                "match_ratio": round(match_ratio, 4),
                "lost_packets": lost,
                "loss_ratio": round(lost / float(upstream), 6) if upstream > 0 else 0.0,
                "clock_offset_seconds": round(skew, 6),
                "clock_offset_warning": abs(skew) > 1.0,
                "relative_delay_ms": {
                    "min": round(min_ms, 3),
                    "p50": round(p50, 3),
                    "p95": round(p95, 3),
                    "p99": round(p99, 3),
                    "max": round(rel_ms[-1], 3) if rel_ms else 0.0,
                },
                "queuing_jitter_ms": jitter,
                "confidence": conf,
            })

        # Délais relatifs par session (après retrait du décalage du segment)
        for rows in per_session.values():
            for row in rows:
                pair = (row["from_capture_index"], row["to_capture_index"])
                skew = skew_by_pair.get(pair, 0.0)
                deltas = row.pop("_deltas", [])
                rel = sorted((v - skew) * 1000.0 for v in deltas)
                row["relative_delay_ms"] = {
                    "p50": round(_percentile(rel, 50.0), 3) if rel else None,
                    "p95": round(_percentile(rel, 95.0), 3) if rel else None,
                } if rel else {"p50": None, "p95": None}
                row["sample_count"] = len(rel)

        worst_loss = max(segments, key=lambda s: s.get("loss_ratio", 0.0), default=None)
        worst_delay = max(
            segments,
            key=lambda s: _safe_float((s.get("relative_delay_ms") or {}).get("p95"), 0.0),
            default=None,
        )

        return {
            "segments": segments,
            "per_session": per_session,
            "worst_loss_segment": worst_loss.get("segment") if worst_loss else None,
            "worst_delay_segment": worst_delay.get("segment") if worst_delay else None,
            "method": "Appariement par empreinte (seq TCP + taille payload + IP ID). "
                      "Les délais sont RELATIFS: le décalage d'horloge entre équipements "
                      "est retiré via la médiane par segment.",
        }

    # ------------------------------------------------------------------
    # Latency estimation
    # ------------------------------------------------------------------

    def _estimate_latency(self, capture_points: List[Dict[str, Any]], sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
        segment_raw: Dict[Tuple[int, int], List[float]] = defaultdict(list)

        for session in sessions:
            hops = {h.get("capture_index"): h for h in session.get("hops", [])}
            for idx in range(len(capture_points) - 1):
                left = hops.get(idx)
                right = hops.get(idx + 1)
                if not left or not right:
                    continue
                raw = _safe_float(right.get("reference_ts"), 0.0) - _safe_float(left.get("reference_ts"), 0.0)
                if abs(raw) <= 3600:  # écarter outliers extrêmes
                    segment_raw[(idx, idx + 1)].append(raw)

        segments = []
        for (a, b), raw_values in segment_raw.items():
            if not raw_values:
                continue

            skew = float(median(raw_values))
            adjusted = [v - skew for v in raw_values]
            adjusted_ms = [v * 1000.0 for v in adjusted]
            abs_adjusted = [abs(v) for v in adjusted_ms]

            p95 = _percentile(abs_adjusted, 95)
            conf = "LOW"
            if len(raw_values) >= 10 and p95 < 80:
                conf = "HIGH"
            elif len(raw_values) >= 4 and p95 < 250:
                conf = "MEDIUM"

            seg_name = f"{capture_points[a].get('equipment_name')} -> {capture_points[b].get('equipment_name')}"
            segments.append(
                {
                    "from_capture_index": a,
                    "to_capture_index": b,
                    "from_equipment": capture_points[a].get("equipment_name"),
                    "to_equipment": capture_points[b].get("equipment_name"),
                    "segment": seg_name,
                    "sample_count": len(raw_values),
                    "clock_skew_seconds": round(skew, 6),
                    "latency_ms": {
                        "min": round(min(adjusted_ms), 3),
                        "max": round(max(adjusted_ms), 3),
                        "avg": round(sum(adjusted_ms) / len(adjusted_ms), 3),
                        "p50": round(_percentile(adjusted_ms, 50), 3),
                        "p95": round(_percentile(adjusted_ms, 95), 3),
                        "p99": round(_percentile(adjusted_ms, 99), 3),
                    },
                    "confidence": conf,
                }
            )

        segments.sort(key=lambda s: abs(_safe_float((s.get("latency_ms") or {}).get("p95"), 0.0)), reverse=True)

        return {
            "segments": segments,
            "slowest_segment": segments[0]["segment"] if segments else None,
            "global_confidence": self._latency_global_confidence(segments),
        }

    def _latency_global_confidence(self, segments: List[Dict[str, Any]]) -> str:
        if not segments:
            return "LOW"
        levels = [str(s.get("confidence", "LOW")).upper() for s in segments]
        if all(lvl == "HIGH" for lvl in levels):
            return "HIGH"
        if any(lvl == "HIGH" for lvl in levels) or any(lvl == "MEDIUM" for lvl in levels):
            return "MEDIUM"
        return "LOW"

    def _apply_latency_to_sessions(
        self,
        latency_summary: Dict[str, Any],
        sessions: List[Dict[str, Any]],
        thresholds: Optional[Dict[str, float]] = None,
    ) -> None:
        seg_by_pair = {
            (s.get("from_capture_index"), s.get("to_capture_index")): s
            for s in latency_summary.get("segments", [])
        }

        for session in sessions:
            hops = {h.get("capture_index"): h for h in session.get("hops", [])}
            latency_rows = []
            total_ms = 0.0
            total_samples = 0
            conf_levels = []

            for idx in range(max(hops.keys(), default=-1)):
                left = hops.get(idx)
                right = hops.get(idx + 1)
                if not left or not right:
                    continue
                seg = seg_by_pair.get((idx, idx + 1))
                if not seg:
                    continue

                skew = _safe_float(seg.get("clock_skew_seconds"), 0.0)
                raw = _safe_float(right.get("reference_ts"), 0.0) - _safe_float(left.get("reference_ts"), 0.0)
                lat_ms = (raw - skew) * 1000.0

                latency_rows.append(
                    {
                        "segment": seg.get("segment"),
                        "from_capture_index": _safe_int(seg.get("from_capture_index"), -1),
                        "to_capture_index": _safe_int(seg.get("to_capture_index"), -1),
                        "latency_ms": round(lat_ms, 3),
                        "confidence": seg.get("confidence", "LOW"),
                    }
                )

                total_ms += lat_ms
                total_samples += 1
                conf_levels.append(str(seg.get("confidence", "LOW")).upper())

            session["latency_by_hop"] = latency_rows
            session["latency_total_ms"] = round(total_ms, 3) if total_samples > 0 else None
            if not conf_levels:
                session["latency_confidence"] = "UNKNOWN"
            elif all(c == "HIGH" for c in conf_levels):
                session["latency_confidence"] = "HIGH"
            elif any(c in {"HIGH", "MEDIUM"} for c in conf_levels):
                session["latency_confidence"] = "MEDIUM"
            else:
                session["latency_confidence"] = "LOW"

            degradation_segments, degradation_primary = self._derive_segment_degradation(session, thresholds=thresholds)
            session["degradation_segments"] = degradation_segments
            session["degradation_primary"] = degradation_primary

    def _derive_segment_degradation(
        self,
        session: Dict[str, Any],
        thresholds: Optional[Dict[str, float]] = None,
    ) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        cfg = _sanitize_root_cause_thresholds(thresholds)
        hops = sorted(
            [
                h for h in (session.get("hops", []) if isinstance(session.get("hops", []), list) else [])
                if isinstance(h, dict)
            ],
            key=lambda h: _safe_int(h.get("capture_index"), -1),
        )
        if len(hops) < 2:
            return [], None

        latency_rows = session.get("latency_by_hop", []) if isinstance(session.get("latency_by_hop", []), list) else []
        lat_by_pair: Dict[Tuple[int, int], Dict[str, Any]] = {}
        for row in latency_rows:
            a = _safe_int(row.get("from_capture_index"), -1)
            b = _safe_int(row.get("to_capture_index"), -1)
            if a >= 0 and b >= 0:
                lat_by_pair[(a, b)] = row

        change_rows = session.get("changes", []) if isinstance(session.get("changes", []), list) else []
        changes_by_hop: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for c in change_rows:
            hop_name = str(c.get("hop", "")).strip()
            if hop_name:
                changes_by_hop[hop_name].append(c)

        probable_cause_code = str(session.get("probable_cause_code", "watch")).strip().lower()
        root_codes = {
            str(s.get("code", "")).strip().lower()
            for s in (session.get("root_cause_signals", []) if isinstance(session.get("root_cause_signals", []), list) else [])
            if str(s.get("code", "")).strip()
        }
        if probable_cause_code and probable_cause_code != "watch":
            root_codes.add(probable_cause_code)

        rows: List[Dict[str, Any]] = []
        for left, right in zip(hops, hops[1:]):
            from_idx = _safe_int(left.get("capture_index"), -1)
            to_idx = _safe_int(right.get("capture_index"), -1)
            if from_idx < 0 or to_idx < 0:
                continue

            from_name = str(left.get("equipment_name", f"Hop {from_idx + 1}"))
            to_name = str(right.get("equipment_name", f"Hop {to_idx + 1}"))
            hop_name = f"{from_name} -> {to_name}"
            pair_changes = changes_by_hop.get(hop_name, [])
            change_types = [str(c.get("type", "")).lower() for c in pair_changes]
            lat = lat_by_pair.get((from_idx, to_idx), {})

            score = 0
            reasons: List[str] = []

            lat_ms_raw = lat.get("latency_ms")
            lat_ms = _safe_float(lat_ms_raw, 0.0) if lat_ms_raw is not None else None
            lat_abs = abs(lat_ms) if lat_ms is not None else None
            lat_conf = str(lat.get("confidence", "LOW")).upper()

            if lat_abs is not None:
                if lat_abs >= cfg["latency_segment_high_ms"]:
                    score += 32
                    reasons.append(f"Latence segment très élevée ({lat_ms:.1f} ms).")
                elif lat_abs >= cfg["latency_segment_medium_ms"]:
                    score += 22
                    reasons.append(f"Latence segment élevée ({lat_ms:.1f} ms).")
                elif lat_abs >= cfg["latency_segment_notice_ms"]:
                    score += 10
                    reasons.append(f"Latence segment notable ({lat_ms:.1f} ms).")

                if lat_conf == "HIGH" and lat_abs >= cfg["latency_segment_medium_ms"]:
                    score += 8
                elif lat_conf == "MEDIUM" and lat_abs >= cfg["latency_segment_medium_ms"]:
                    score += 4

            sev_weight = {"LOW": 6, "MEDIUM": 12, "HIGH": 20, "CRITICAL": 28}
            type_bonus = {
                "disappearance": 20,
                "appearance": 10,
                "mss_change": 14,
                "retrans_increase": 14,
                "rst_delta": 12,
                "window_shift": 8,
                "packet_volume_shift": 8,
                "ip_rewrite": 8,
                "port_rewrite": 8,
            }
            for c in pair_changes:
                sev = str(c.get("severity", "LOW")).upper()
                ctype = str(c.get("type", "")).lower()
                score += sev_weight.get(sev, 6)
                score += type_bonus.get(ctype, 0)
                desc = str(c.get("description", "")).strip()
                if desc:
                    reasons.append(desc)

            # Renforcement par root-cause
            if "mtu-blackhole" in root_codes and ("mss_change" in change_types or "retrans_increase" in change_types):
                score += 18
                reasons.append("Signal root-cause MTU blackhole corrélé sur ce segment.")
            if "asymmetry" in root_codes and ("disappearance" in change_types or "appearance" in change_types):
                score += 18
                reasons.append("Signal root-cause asymétrie/capture partielle corrélé.")
            if "nat-suspect" in root_codes and ("ip_rewrite" in change_types or "port_rewrite" in change_types):
                score += 14
                reasons.append("Signal root-cause NAT/PAT suspect corrélé.")
            if "congestion-loss" in root_codes and "retrans_increase" in change_types:
                score += 12
            if "bufferbloat" in root_codes and (lat_abs is not None and lat_abs >= cfg["latency_segment_medium_ms"]):
                score += 10
            if "reset-pair" in root_codes and "rst_delta" in change_types:
                score += 12

            score = max(0, min(100, int(round(score))))
            severity = "LOW"
            if score >= 75:
                severity = "HIGH"
            elif score >= 45:
                severity = "MEDIUM"

            triggered = bool(
                score >= cfg["segment_trigger_score"]
                or (score >= cfg["segment_trigger_soft_score"] and len(pair_changes) >= int(cfg["segment_trigger_changes_min"]))
            )
            if triggered and not reasons:
                reasons.append("Dégradation auto détectée par score consolidé.")

            rows.append(
                {
                    "segment": hop_name,
                    "from_capture_index": from_idx,
                    "to_capture_index": to_idx,
                    "from_equipment": from_name,
                    "to_equipment": to_name,
                    "score": score,
                    "severity": severity,
                    "triggered": triggered,
                    "latency_ms": round(lat_ms, 3) if lat_ms is not None else None,
                    "latency_confidence": lat_conf if lat else "UNKNOWN",
                    "change_types": sorted(set([c for c in change_types if c])),
                    "reasons": reasons[:8],
                }
            )

        rows.sort(key=lambda r: (_safe_int(r.get("score"), 0), len(r.get("reasons", []))), reverse=True)
        primary = None
        for row in rows:
            if bool(row.get("triggered")):
                primary = row
                break
        if primary is None and rows:
            primary = rows[0]
        return rows, primary

    # ------------------------------------------------------------------
    # Summaries
    # ------------------------------------------------------------------

    @staticmethod
    def _count_flow_limitations(sessions: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for s in sessions:
            counts[str((s.get("flow_limitation") or {}).get("class", "UNKNOWN"))] += 1
        return dict(sorted(counts.items(), key=lambda it: it[1], reverse=True))

    def _build_capture_volumetry(self, capture_points: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for cp in capture_points:
            packets = _safe_int(cp.get("packet_count"), 0)
            bytes_count = _safe_int(cp.get("byte_count"), 0)
            duration = max(0.001, _safe_float(cp.get("capture_duration_seconds"), 0.0))
            pps = packets / duration if duration > 0 else 0.0
            bps = (bytes_count * 8.0) / duration if duration > 0 else 0.0
            rows.append(
                {
                    "capture_index": _safe_int(cp.get("capture_index"), 0),
                    "equipment_name": str(cp.get("equipment_name", "")),
                    "position": _safe_int(cp.get("position"), 0),
                    "packet_count": packets,
                    "byte_count": bytes_count,
                    "sessions_count": _safe_int(cp.get("sessions_count"), 0),
                    "duration_seconds": round(duration, 3),
                    "pps": round(pps, 3),
                    "throughput_mbps": round(bps / 1_000_000.0, 4),
                }
            )
        rows.sort(key=lambda x: x.get("capture_index", 0))
        return rows

    def _build_segment_health(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        bucket: Dict[str, Dict[str, Any]] = {}
        for sess in sessions:
            seg_rows = sess.get("degradation_segments", []) if isinstance(sess.get("degradation_segments", []), list) else []
            for seg in seg_rows:
                if not isinstance(seg, dict):
                    continue
                seg_name = str(seg.get("segment", "")).strip()
                if not seg_name:
                    continue
                row = bucket.setdefault(
                    seg_name,
                    {
                        "segment": seg_name,
                        "from_capture_index": _safe_int(seg.get("from_capture_index"), -1),
                        "to_capture_index": _safe_int(seg.get("to_capture_index"), -1),
                        "from_equipment": str(seg.get("from_equipment", "")),
                        "to_equipment": str(seg.get("to_equipment", "")),
                        "session_count": 0,
                        "triggered_count": 0,
                        "scores": [],
                        "latencies": [],
                        "high_count": 0,
                        "medium_count": 0,
                        "low_count": 0,
                        "reasons": defaultdict(int),
                    },
                )
                row["session_count"] += 1
                score = _safe_int(seg.get("score"), 0)
                row["scores"].append(score)
                if bool(seg.get("triggered")):
                    row["triggered_count"] += 1
                lat = seg.get("latency_ms")
                if lat is not None:
                    row["latencies"].append(abs(_safe_float(lat, 0.0)))

                sev = str(seg.get("severity", "LOW")).upper()
                if sev == "HIGH":
                    row["high_count"] += 1
                elif sev == "MEDIUM":
                    row["medium_count"] += 1
                else:
                    row["low_count"] += 1

                for reason in (seg.get("reasons", []) if isinstance(seg.get("reasons", []), list) else []):
                    r = str(reason).strip()
                    if r:
                        row["reasons"][r] += 1

        rows: List[Dict[str, Any]] = []
        for row in bucket.values():
            scores = [int(v) for v in row.get("scores", []) if isinstance(v, int)]
            latencies = [float(v) for v in row.get("latencies", []) if isinstance(v, (int, float))]
            reasons_map = row.get("reasons", {})
            top_reasons = [
                {"reason": k, "count": v}
                for k, v in sorted(reasons_map.items(), key=lambda it: it[1], reverse=True)[:4]
            ]
            session_count = max(1, _safe_int(row.get("session_count"), 0))
            rows.append(
                {
                    "segment": row.get("segment"),
                    "from_capture_index": row.get("from_capture_index"),
                    "to_capture_index": row.get("to_capture_index"),
                    "from_equipment": row.get("from_equipment"),
                    "to_equipment": row.get("to_equipment"),
                    "session_count": session_count,
                    "triggered_count": _safe_int(row.get("triggered_count"), 0),
                    "trigger_ratio": round(_safe_int(row.get("triggered_count"), 0) / float(session_count), 4),
                    "avg_score": round((sum(scores) / len(scores)), 2) if scores else 0.0,
                    "max_score": max(scores) if scores else 0,
                    "latency_avg_ms": round((sum(latencies) / len(latencies)), 3) if latencies else 0.0,
                    "latency_p95_ms": round(_percentile(latencies, 95.0), 3) if latencies else 0.0,
                    "severity_mix": {
                        "high": _safe_int(row.get("high_count"), 0),
                        "medium": _safe_int(row.get("medium_count"), 0),
                        "low": _safe_int(row.get("low_count"), 0),
                    },
                    "top_reasons": top_reasons,
                }
            )

        rows.sort(
            key=lambda x: (
                _safe_float(x.get("avg_score"), 0.0),
                _safe_float(x.get("latency_p95_ms"), 0.0),
                _safe_int(x.get("triggered_count"), 0),
            ),
            reverse=True,
        )
        return rows

    def _build_culprit_ranking(self, sessions: List[Dict[str, Any]], capture_points: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        by_idx = {
            _safe_int(cp.get("capture_index"), idx): str(cp.get("equipment_name", f"Point {idx + 1}"))
            for idx, cp in enumerate(capture_points)
        }
        ranking: Dict[str, Dict[str, Any]] = {}

        def touch_equipment(eq_name: str) -> Dict[str, Any]:
            return ranking.setdefault(
                eq_name,
                {
                    "equipment_name": eq_name,
                    "score": 0,
                    "sessions": 0,
                    "high_risk_sessions": 0,
                    "segments_triggered": 0,
                    "evidence": [],
                    "cause_codes": defaultdict(int),
                    "ips": defaultdict(int),
                },
            )

        for sess in sessions:
            risk = _safe_int(sess.get("risk_score"), 0)
            cause_code = str(sess.get("probable_cause_code", "watch")).strip().lower()
            hops = sess.get("hops", []) if isinstance(sess.get("hops", []), list) else []
            primary = sess.get("degradation_primary", {}) if isinstance(sess.get("degradation_primary", {}), dict) else {}
            triggered = [
                d for d in (sess.get("degradation_segments", []) if isinstance(sess.get("degradation_segments", []), list) else [])
                if isinstance(d, dict) and bool(d.get("triggered"))
            ]

            candidate_names: List[str] = []
            to_idx = _safe_int(primary.get("to_capture_index"), -1)
            if to_idx >= 0 and to_idx in by_idx:
                candidate_names.append(by_idx[to_idx])
            for d in triggered[:2]:
                idx = _safe_int(d.get("to_capture_index"), -1)
                if idx >= 0 and idx in by_idx:
                    candidate_names.append(by_idx[idx])

            if not candidate_names and hops:
                worst = max(hops, key=lambda h: _safe_int((h.get("tcp_metrics") or {}).get("retransmissions"), 0))
                candidate_names.append(str(worst.get("equipment_name", "Inconnu")))

            candidate_names = [c for c in dict.fromkeys(candidate_names) if c]
            if not candidate_names:
                continue

            split_weight = max(1, len(candidate_names))
            for eq_name in candidate_names:
                row = touch_equipment(eq_name)
                row["score"] += int(round(risk / split_weight))
                row["sessions"] += 1
                if risk >= 70:
                    row["high_risk_sessions"] += 1
                row["segments_triggered"] += len(triggered)
                row["cause_codes"][cause_code or "watch"] += 1

                if primary and str(primary.get("segment", "")).strip():
                    row["evidence"].append(
                        f"{sess.get('session_id')}: {primary.get('segment')} score={_safe_int(primary.get('score'), 0)}"
                    )

                for hop in hops:
                    if str(hop.get("equipment_name", "")) == eq_name:
                        for ip_key in ("client_ip", "server_ip"):
                            ip = str(hop.get(ip_key, "")).strip()
                            if ip:
                                row["ips"][ip] += 1

        rows: List[Dict[str, Any]] = []
        for row in ranking.values():
            causes = [
                {"code": c, "count": n}
                for c, n in sorted(row["cause_codes"].items(), key=lambda it: it[1], reverse=True)[:4]
            ]
            top_ips = [ip for ip, _ in sorted(row["ips"].items(), key=lambda it: it[1], reverse=True)[:4]]
            confidence = min(
                100,
                max(
                    0,
                    int(
                        20
                        + min(55, _safe_int(row.get("score"), 0) * 0.35)
                        + min(15, _safe_int(row.get("high_risk_sessions"), 0) * 2)
                    ),
                ),
            )
            rows.append(
                {
                    "equipment_name": row.get("equipment_name"),
                    "score": _safe_int(row.get("score"), 0),
                    "sessions": _safe_int(row.get("sessions"), 0),
                    "high_risk_sessions": _safe_int(row.get("high_risk_sessions"), 0),
                    "segments_triggered": _safe_int(row.get("segments_triggered"), 0),
                    "confidence": confidence,
                    "top_causes": causes,
                    "top_ips": top_ips,
                    "evidence": list(dict.fromkeys(row.get("evidence", [])))[:5],
                }
            )

        rows.sort(
            key=lambda x: (
                _safe_int(x.get("score"), 0),
                _safe_int(x.get("high_risk_sessions"), 0),
                _safe_int(x.get("segments_triggered"), 0),
            ),
            reverse=True,
        )
        return rows[:20]

    def _build_equipment_chain(self, capture_points: List[Dict[str, Any]], segment_health: List[Dict[str, Any]]) -> Dict[str, Any]:
        nodes = []
        for cp in sorted(capture_points, key=lambda c: _safe_int(c.get("capture_index"), 0)):
            idx = _safe_int(cp.get("capture_index"), 0)
            nodes.append(
                {
                    "capture_index": idx,
                    "equipment_name": str(cp.get("equipment_name", f"Point {idx + 1}")),
                    "packet_count": _safe_int(cp.get("packet_count"), 0),
                    "byte_count": _safe_int(cp.get("byte_count"), 0),
                    "sessions_count": _safe_int(cp.get("sessions_count"), 0),
                }
            )

        seg_map = {
            (
                _safe_int(seg.get("from_capture_index"), -1),
                _safe_int(seg.get("to_capture_index"), -1),
            ): seg
            for seg in segment_health
        }
        links = []
        for left, right in zip(nodes, nodes[1:]):
            key = (_safe_int(left.get("capture_index"), -1), _safe_int(right.get("capture_index"), -1))
            seg = seg_map.get(key, {})
            links.append(
                {
                    "from_capture_index": left.get("capture_index"),
                    "to_capture_index": right.get("capture_index"),
                    "from_equipment": left.get("equipment_name"),
                    "to_equipment": right.get("equipment_name"),
                    "avg_score": _safe_float(seg.get("avg_score"), 0.0),
                    "latency_p95_ms": _safe_float(seg.get("latency_p95_ms"), 0.0),
                    "trigger_ratio": _safe_float(seg.get("trigger_ratio"), 0.0),
                    "session_count": _safe_int(seg.get("session_count"), 0),
                }
            )
        return {"nodes": nodes, "links": links}

    def _extract_problematic_ips(self, problematic_sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        ip_scores: Dict[str, Dict[str, Any]] = {}
        for sess in problematic_sessions:
            risk = _safe_int(sess.get("risk_score"), 0)
            for hop in sess.get("hops", []):
                for ip_key in ("client_ip", "server_ip"):
                    ip = str(hop.get(ip_key, "")).strip()
                    if not ip:
                        continue
                    row = ip_scores.setdefault(ip, {"ip": ip, "score": 0, "sessions": 0})
                    row["score"] += risk
                    row["sessions"] += 1

        rows = list(ip_scores.values())
        rows.sort(key=lambda x: (x["score"], x["sessions"]), reverse=True)
        return rows[:30]

    def _count_sessions_by_protocol(self, sessions: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for sess in sessions:
            proto = str(sess.get("protocol", "UNKNOWN")).upper()
            counts[proto] += 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))

    def _count_confidence_levels(self, sessions: List[Dict[str, Any]]) -> Dict[str, int]:
        levels: Dict[str, int] = defaultdict(int)
        for sess in sessions:
            lvl = str(sess.get("confidence_level", "UNKNOWN")).upper()
            levels[lvl] += 1
        return dict(levels)

    def _count_top_causes(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        causes: Dict[str, int] = defaultdict(int)
        for sess in sessions:
            cause = str(sess.get("probable_cause", "")).strip() or "Inconnu"
            causes[cause] += 1
        rows = [{"cause": c, "count": n} for c, n in causes.items()]
        rows.sort(key=lambda x: x["count"], reverse=True)
        return rows

    def _count_top_cause_codes(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        causes: Dict[str, int] = defaultdict(int)
        for sess in sessions:
            code = str(sess.get("probable_cause_code", "")).strip() or "watch"
            causes[code] += 1
        rows = [{"code": c, "count": n} for c, n in causes.items()]
        rows.sort(key=lambda x: x["count"], reverse=True)
        return rows


_multi_pcap_service: Optional[MultiPcapAnalysisService] = None


def get_multi_pcap_service() -> MultiPcapAnalysisService:
    global _multi_pcap_service
    if _multi_pcap_service is None:
        _multi_pcap_service = MultiPcapAnalysisService()
    return _multi_pcap_service
