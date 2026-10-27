"""
TLS Security Auditor — Feature 7
Audit de sécurité TLS style SSL Labs:
  - Scoring A+/A/B/C/F
  - Détection des cipher suites faibles
  - Matching JA3 vs base de signatures malwares
  - Recommandations de hardening
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any, List, Optional

try:
    from app.core.logging_config import get_logger
except ImportError:
    import logging
    def get_logger(name: str):  # type: ignore
        return logging.getLogger(name)

logger = get_logger(__name__)

# Chemin vers la base de signatures JA3
JA3_DB_PATH = Path(__file__).parent.parent / "core" / "ja3_signatures.json"


def _load_ja3_db() -> Dict[str, Any]:
    try:
        with open(JA3_DB_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"JA3 DB load failed: {e}")
        return {"signatures": [], "weak_ciphers": [], "deprecated_versions": []}


JA3_DB = _load_ja3_db()
JA3_SIGNATURES: Dict[str, Dict[str, Any]] = {
    sig["ja3"]: sig for sig in JA3_DB.get("signatures", [])
}
WEAK_CIPHER_NAMES: set = set(JA3_DB.get("weak_ciphers", []))
DEPRECATED_VERSIONS: set = set(JA3_DB.get("deprecated_versions", []))


class TLSSecurityAuditor:
    """
    Audite la sécurité TLS d'une capture réseau.
    Note les connexions TLS avec un score SSL-Labs-like (A+/A/B/C/F).
    """

    def audit(self, tls_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prend les résultats de TLSAnalyzer et produit un rapport d'audit complet.
        """
        sessions = tls_results.get("sessions", [])
        unique_ja3 = tls_results.get("unique_ja3_fingerprints", [])
        cipher_distribution = tls_results.get("cipher_distribution", {})
        security_issues = tls_results.get("security_issues", {})

        # ── Malware JA3 matching ──
        malware_matches: List[Dict[str, Any]] = []
        for ja3_info in unique_ja3:
            ja3 = ja3_info.get("ja3", "")
            if ja3 in JA3_SIGNATURES:
                sig = JA3_SIGNATURES[ja3]
                malware_matches.append({
                    "ja3": ja3,
                    "count": ja3_info["count"],
                    "src_ips": ja3_info["src_ips"],
                    "snis": ja3_info.get("snis", []),
                    "malware_name": sig["name"],
                    "malware_family": sig["family"],
                    "severity": sig["severity"],
                    "description": sig["description"],
                    "verdict": f"🔴 JA3 MALWARE — {sig['name']} ({sig['family']})",
                })

        # ── Deprecated TLS version sessions ──
        deprecated_sessions = security_issues.get("deprecated_tls", [])
        weak_cipher_sessions = security_issues.get("weak_ciphers", [])

        # Compute how many weak ciphers were negotiated (server-side)
        weak_negotiated_count = sum(
            v for k, v in cipher_distribution.items()
            if k in WEAK_CIPHER_NAMES
        )
        total_negotiated = sum(cipher_distribution.values()) if cipher_distribution else 1

        # ── Global score computation ──
        # Start at 100, subtract deductions
        score = 100
        critical_findings: List[str] = []
        warnings: List[str] = []
        recommendations: List[str] = []

        if malware_matches:
            score -= 50
            critical_findings.append(
                f"🔴 {len(malware_matches)} JA3 fingerprint(s) correspondant à des malwares connus"
            )
            recommendations.append(
                "Isoler les machines ayant des JA3 malwares. Analyser les processus actifs, rechercher des indicateurs de C2."
            )

        if deprecated_sessions:
            score -= 25
            warnings.append(
                f"🟠 {len(deprecated_sessions)} session(s) utilisant TLS 1.0/1.1 ou SSLv3 (déprécié)"
            )
            recommendations.append(
                "Désactiver TLS 1.0 et 1.1 sur tous les serveurs. Imposer TLS 1.2 minimum, TLS 1.3 recommandé."
            )

        if weak_cipher_sessions:
            score -= 20
            warnings.append(
                f"🟠 {len(weak_cipher_sessions)} session(s) proposant des cipher suites faibles (RC4, DES, NULL)"
            )
            recommendations.append(
                "Supprimer les cipher suites NULL, RC4, DES, et 3DES. Utiliser uniquement ECDHE+AES-GCM et ChaCha20."
            )

        if weak_negotiated_count > 0:
            pct = int(weak_negotiated_count * 100 / total_negotiated)
            score -= min(15, pct)
            warnings.append(
                f"🟡 {pct}% des ciphers négociés sont faibles"
            )

        # ── SSL Labs grade ──
        score = max(0, min(100, score))
        grade = "A+"
        if not malware_matches and not deprecated_sessions and not weak_cipher_sessions and score >= 95:
            grade = "A+"
        elif score >= 80:
            grade = "A"
        elif score >= 65:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 35:
            grade = "D"
        else:
            grade = "F"

        return {
            "overall_score": score,
            "grade": grade,
            "grade_color": {
                "A+": "#27ae60", "A": "#2ecc71",
                "B": "#f39c12", "C": "#e67e22",
                "D": "#e74c3c", "F": "#c0392b"
            }.get(grade, "#7f8c8d"),
            "summary": {
                "total_sessions_audited": len(sessions),
                "unique_ja3_fingerprints": len(unique_ja3),
                "malware_ja3_matches": len(malware_matches),
                "deprecated_tls_sessions": len(deprecated_sessions),
                "weak_cipher_sessions": len(weak_cipher_sessions),
                "score": score,
                "grade": grade,
            },
            "critical_findings": critical_findings,
            "warnings": warnings,
            "recommendations": recommendations,
            "malware_ja3_matches": malware_matches,
            "deprecated_sessions": deprecated_sessions,
            "weak_cipher_sessions": weak_cipher_sessions,
            "top_cipher_suites": sorted(
                [{"cipher": k, "count": v, "is_weak": k in WEAK_CIPHER_NAMES}
                 for k, v in cipher_distribution.items()],
                key=lambda x: int(x["count"]), reverse=True
            )[:15],
        }
