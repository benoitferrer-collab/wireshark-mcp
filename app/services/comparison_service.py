"""
Baseline Comparator — Feature 3
Compare deux captures PCAP (task_ids) pour identifier les déviances:
  - Nouveaux flux / flux disparus
  - Variation de volume par protocole/IP
  - Nouveaux protocoles / ports apparus
  - Score de déviation global
"""

from __future__ import annotations

from typing import Dict, Any, List, Set, Optional
from collections import defaultdict

try:
    from app.core.logging_config import get_logger
except ImportError:
    import logging
    def get_logger(name: str):  # type: ignore
        return logging.getLogger(name)

logger = get_logger(__name__)


class BaselineComparator:
    """
    Compare deux analyses PCAP pour identifier les déviances
    réseau entre une baseline et une capture d'investigation.
    """

    def compare(
        self,
        baseline: Dict[str, Any],
        investigation: Dict[str, Any],
        baseline_label: str = "Baseline",
        investigation_label: str = "Investigation"
    ) -> Dict[str, Any]:
        """
        Compare deux ensembles de résultats d'analyse.

        Args:
            baseline: Résultats d'analyse de la capture de référence
            investigation: Résultats d'analyse de la capture à comparer
        """
        logger.info("baseline_comparison_started")

        # ── Protocol deviation ──
        proto_diff = self._compare_protocols(baseline, investigation)

        # ── IP communication changes ──
        ip_diff = self._compare_ips(baseline, investigation)

        # ── Anomaly comparison ──
        anomaly_diff = self._compare_anomalies(baseline, investigation)

        # ── New/increased connections ──
        traffic_diff = self._compare_traffic_stats(baseline, investigation)

        # ── Overall deviation score ──
        deviation_score = self._compute_deviation_score(
            proto_diff, ip_diff, anomaly_diff, traffic_diff
        )

        return {
            "comparison": {
                "baseline_label": baseline_label,
                "investigation_label": investigation_label,
                "deviation_score": deviation_score,
                "verdict": self._interpret_deviation(deviation_score),
            },
            "protocol_changes": proto_diff,
            "ip_changes": ip_diff,
            "anomaly_changes": anomaly_diff,
            "traffic_changes": traffic_diff,
        }

    # ─────────────────────────────────────
    # Protocol comparison
    # ─────────────────────────────────────

    def _compare_protocols(
        self, baseline: Dict[str, Any], investigation: Dict[str, Any]
    ) -> Dict[str, Any]:
        b_protos = set(baseline.get("protocols", {}).keys())
        i_protos = set(investigation.get("protocols", {}).keys())

        new_protocols = list(i_protos - b_protos)
        disappeared_protocols = list(b_protos - i_protos)

        # Volume changes per protocol
        volume_changes = []
        for proto in b_protos & i_protos:
            b_vol = int(baseline["protocols"].get(proto, {}).get("bytes", 0) or 0)
            i_vol = int(investigation["protocols"].get(proto, {}).get("bytes", 0) or 0)
            if b_vol > 0:
                pct_change = ((i_vol - b_vol) / b_vol) * 100
                if abs(pct_change) >= 50:  # Variation >= 50%
                    volume_changes.append({
                        "protocol": proto,
                        "baseline_bytes": b_vol,
                        "investigation_bytes": i_vol,
                        "pct_change": round(float(pct_change), 1),
                        "direction": "↑ HAUSSE" if pct_change > 0 else "↓ BAISSE",
                    })

        return {
            "new_protocols": new_protocols,
            "disappeared_protocols": disappeared_protocols,
            "volume_changes": sorted(volume_changes, key=lambda x: abs(float(x["pct_change"])), reverse=True)[:10],
        }

    # ─────────────────────────────────────
    # IP comparison
    # ─────────────────────────────────────

    def _compare_ips(
        self, baseline: Dict[str, Any], investigation: Dict[str, Any]
    ) -> Dict[str, Any]:
        def extract_ips(results: Dict[str, Any]) -> Set[str]:
            ips: Set[str] = set()
            for top_ip in results.get("top_talkers", []):
                ips.add(str(top_ip.get("ip", "")))
            return ips

        b_ips = extract_ips(baseline)
        i_ips = extract_ips(investigation)

        new_ips = list(i_ips - b_ips)
        disappeared_ips = list(b_ips - i_ips)

        return {
            "new_ips": new_ips[:30],
            "disappeared_ips": disappeared_ips[:30],
            "new_ips_count": len(new_ips),
            "disappeared_ips_count": len(disappeared_ips),
        }

    # ─────────────────────────────────────
    # Anomaly comparison
    # ─────────────────────────────────────

    def _compare_anomalies(
        self, baseline: Dict[str, Any], investigation: Dict[str, Any]
    ) -> Dict[str, Any]:
        b_types: Dict[str, int] = defaultdict(int)
        i_types: Dict[str, int] = defaultdict(int)

        for a in baseline.get("anomalies", []):
            b_types[str(a.get("type", "unknown"))] += 1
        for a in investigation.get("anomalies", []):
            i_types[str(a.get("type", "unknown"))] += 1

        new_anomaly_types = [t for t in i_types if t not in b_types]
        increased_anomalies = [
            {
                "type": t,
                "baseline_count": b_types.get(t, 0),
                "investigation_count": i_types[t],
                "increase": i_types[t] - b_types.get(t, 0),
            }
            for t in i_types
            if i_types[t] > b_types.get(t, 0)
        ]

        return {
            "baseline_anomaly_count": len(baseline.get("anomalies", [])),
            "investigation_anomaly_count": len(investigation.get("anomalies", [])),
            "new_anomaly_types": new_anomaly_types,
            "increased_anomalies": sorted(increased_anomalies, key=lambda x: int(x["increase"]), reverse=True)[:10],
        }

    # ─────────────────────────────────────
    # Traffic stats comparison
    # ─────────────────────────────────────

    def _compare_traffic_stats(
        self, baseline: Dict[str, Any], investigation: Dict[str, Any]
    ) -> Dict[str, Any]:
        b_sum = baseline.get("summary", {})
        i_sum = investigation.get("summary", {})

        def safe_pct(b_val: Any, i_val: Any) -> Optional[float]:
            b = float(b_val or 0)
            i = float(i_val or 0)
            if b == 0:
                return None
            return round(((i - b) / b) * 100, 1)

        return {
            "packets": {
                "baseline": int(b_sum.get("total_packets", 0) or 0),
                "investigation": int(i_sum.get("total_packets", 0) or 0),
                "pct_change": safe_pct(b_sum.get("total_packets"), i_sum.get("total_packets")),
            },
            "bytes": {
                "baseline": int(b_sum.get("total_bytes", 0) or 0),
                "investigation": int(i_sum.get("total_bytes", 0) or 0),
                "pct_change": safe_pct(b_sum.get("total_bytes"), i_sum.get("total_bytes")),
            },
            "unique_ips": {
                "baseline": int(b_sum.get("unique_ips", 0) or 0),
                "investigation": int(i_sum.get("unique_ips", 0) or 0),
                "pct_change": safe_pct(b_sum.get("unique_ips"), i_sum.get("unique_ips")),
            },
        }

    # ─────────────────────────────────────
    # Deviation scoring
    # ─────────────────────────────────────

    def _compute_deviation_score(
        self,
        proto_diff: Dict[str, Any],
        ip_diff: Dict[str, Any],
        anomaly_diff: Dict[str, Any],
        traffic_diff: Dict[str, Any],
    ) -> int:
        score = 0

        # New protocols are suspicious
        score += min(30, len(proto_diff.get("new_protocols", [])) * 10)

        # New IPs
        score += min(20, ip_diff.get("new_ips_count", 0) * 2)

        # New anomaly types
        score += min(25, len(anomaly_diff.get("new_anomaly_types", [])) * 8)

        # Anomaly count increase
        b_cnt = int(anomaly_diff.get("baseline_anomaly_count", 0) or 0)
        i_cnt = int(anomaly_diff.get("investigation_anomaly_count", 0) or 0)
        if b_cnt > 0:
            anom_increase_pct = ((i_cnt - b_cnt) / b_cnt) * 100
            score += min(25, int(anom_increase_pct / 10))

        return min(100, score)

    def _interpret_deviation(self, score: int) -> str:
        if score >= 70:
            return f"🔴 DÉVIATION CRITIQUE (score: {score}/100) — Comportement très anormal par rapport à la baseline"
        elif score >= 40:
            return f"🟠 DÉVIATION SIGNIFICATIVE (score: {score}/100) — Plusieurs changements suspects détectés"
        elif score >= 20:
            return f"🟡 DÉVIATION MODÉRÉE (score: {score}/100) — Quelques changements à investiguer"
        return f"🟢 DÉVIATION FAIBLE (score: {score}/100) — Comportement similaire à la baseline"
