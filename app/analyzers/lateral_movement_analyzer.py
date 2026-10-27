"""
Lateral Movement Analyzer — Feature 4
Détection de mouvements latéraux dans le réseau:
  - Pivot hosts (hôtes communiquant avec >N pairs internes)
  - Pass-the-Hash pattern (NTLM failures → success)
  - Kerberoasting (TGS-REQ bursts, AS-REQ sans pre-auth)
  - LDAP enumeration (requêtes massives d'annuaire)
  - Cartographie du graphe de propagation avec tags MITRE
"""

from __future__ import annotations

import ipaddress
from typing import Dict, Any, List, Set, Optional
from collections import defaultdict

try:
    from .base import BaseAnalyzer
    from app.core.logging_config import get_logger
except ImportError:
    class BaseAnalyzer:  # type: ignore
        def __init__(self):
            self.results: Dict[str, Any] = {}
            self.name = self.__class__.__name__
    import logging
    def get_logger(name: str):  # type: ignore
        return logging.getLogger(name)

logger = get_logger(__name__)

PIVOT_THRESHOLD = 3   # Nombre de destinations internes pour détecter un pivot
KERBEROAST_TGS_THRESHOLD = 5   # Nombre de TGS-REQ suspects en peu de temps
LDAP_ENUM_THRESHOLD = 50   # Nombre de requêtes LDAP suspects


def _is_internal(ip: str) -> bool:
    """Vérifie si une IP est interne (RFC1918 + autres ranges privés)"""
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private or
            addr.is_loopback or
            addr.is_link_local
        )
    except ValueError:
        return False


class LateralMovementAnalyzer(BaseAnalyzer):
    """
    Analyse les mouvements latéraux en overlay sur les résultats
    des analyseurs SMB, Kerberos, LDAP et RDP déjà calculés.
    """

    def __init__(self):
        super().__init__()
        self.pivot_hosts: List[Dict[str, Any]] = []
        self.pass_the_hash_indicators: List[Dict[str, Any]] = []
        self.kerberoasting_indicators: List[Dict[str, Any]] = []
        self.ldap_enum_indicators: List[Dict[str, Any]] = []
        self.enriched_edges: List[Dict[str, Any]] = []

    @staticmethod
    def _records(value: Any) -> List[Dict[str, Any]]:
        """Normalize unknown payload shape into list[dict]."""
        if isinstance(value, list):
            return [v for v in value if isinstance(v, dict)]
        if isinstance(value, dict):
            # Some analyzers store records as dict keyed by id
            vals = list(value.values())
            if vals and all(isinstance(v, dict) for v in vals):
                return [v for v in vals if isinstance(v, dict)]
        return []

    @staticmethod
    def _extract_ip(record: Dict[str, Any], preferred: str, fallback: str = "") -> str:
        ip = record.get(preferred)
        if ip:
            return str(ip)
        if fallback:
            alt = record.get(fallback)
            if isinstance(alt, str):
                return alt.rsplit(":", 1)[0] if ":" in alt else alt
        return ""

    def analyze_from_results(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse les mouvements latéraux à partir des résultats
        des autres analyseurs (SMB, Kerberos, LDAP, RDP).
        Pas besoin de reparcourir les paquets bruts.
        """
        smb = analysis_results.get("smb_analysis", {})
        kerberos = analysis_results.get("kerberos_analysis", {})
        ldap = analysis_results.get("ldap_analysis", {})
        rdp = analysis_results.get("rdp_analysis", {})
        tcp = analysis_results.get("tcp_analysis", {})

        self._detect_pivot_hosts(smb, rdp, tcp)
        self._detect_pass_the_hash(smb, kerberos)
        self._detect_kerberoasting(kerberos)
        self._detect_ldap_enumeration(ldap)
        self._build_enriched_graph(smb, kerberos, ldap, rdp)

        self.results = self._compile_results()
        return self.results

    # ─────────────────────────────────────
    # Pivot host detection
    # ─────────────────────────────────────

    def _detect_pivot_hosts(
        self,
        smb: Dict[str, Any],
        rdp: Dict[str, Any],
        tcp: Dict[str, Any]
    ):
        """
        Détecte les hôtes pivots : hôtes internes qui se connectent
        vers >PIVOT_THRESHOLD autres hôtes internes via SMB ou RDP.
        """
        # Count internal→internal connections per src via SMB
        smb_internal_conns: Dict[str, Set[str]] = defaultdict(set)
        for session in self._records(smb.get("sessions", [])):
            src = self._extract_ip(session, "src_ip", "src")
            dst = self._extract_ip(session, "dst_ip", "dst")
            if src and dst and _is_internal(src) and _is_internal(dst) and src != dst:
                smb_internal_conns[src].add(dst)

        for src_ip, targets in smb_internal_conns.items():
            if len(targets) >= PIVOT_THRESHOLD:
                self.pivot_hosts.append({
                    "src_ip": src_ip,
                    "protocol": "SMB",
                    "targets": list(targets),
                    "target_count": len(targets),
                    "risk": "HIGH",
                    "verdict": f"🟠 PIVOT SMB — {src_ip} contacte {len(targets)} hôtes internes",
                    "mitre": "T1021.002 - Remote Services: SMB/Windows Admin Shares",
                    "recommended_action": f"Isoler {src_ip}, vérifier les connexions SMB sortantes, auditer les partages accédés"
                })

        # Count internal→internal RDP sessions
        rdp_internal_conns: Dict[str, Set[str]] = defaultdict(set)
        for session in self._records(rdp.get("sessions", [])):
            src = self._extract_ip(session, "src_ip", "src")
            dst = self._extract_ip(session, "dst_ip", "dst")
            if src and dst and _is_internal(src) and _is_internal(dst) and src != dst:
                rdp_internal_conns[src].add(dst)

        for src_ip, targets in rdp_internal_conns.items():
            if len(targets) >= PIVOT_THRESHOLD:
                self.pivot_hosts.append({
                    "src_ip": src_ip,
                    "protocol": "RDP",
                    "targets": list(targets),
                    "target_count": len(targets),
                    "risk": "HIGH",
                    "verdict": f"🟠 PIVOT RDP — {src_ip} se connecte à {len(targets)} hôtes internes",
                    "mitre": "T1021.001 - Remote Services: Remote Desktop Protocol",
                    "recommended_action": f"Restreindre les connexions RDP depuis {src_ip}, activer NLA, vérifier les comptes utilisés"
                })

    # ─────────────────────────────────────
    # Pass-the-Hash detection
    # ─────────────────────────────────────

    def _detect_pass_the_hash(self, smb: Dict[str, Any], kerberos: Dict[str, Any]):
        """
        Détecte Pass-the-Hash:
        - Plusieurs échecs NTLM (auth_failed) suivis d'un succès
        - Depuis la même IP source en court intervalle
        """
        ntlm_by_src: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "failures": 0, "successes": 0, "targets": set()
        })

        for auth in self._records(smb.get("authentications", [])):
            src = self._extract_ip(auth, "src_ip", "src")
            result = str(auth.get("result", "")).lower()
            dst = self._extract_ip(auth, "dst_ip", "dst")
            if src:
                ntlm_by_src[src]["targets"].add(dst)
                if "fail" in result or "error" in result or result in ("0xc000006d", "0xc0000064"):
                    ntlm_by_src[src]["failures"] += 1
                elif "success" in result or result in ("0x0", "success"):
                    ntlm_by_src[src]["successes"] += 1

        for src_ip, stats in ntlm_by_src.items():
            if stats["failures"] >= 2 and stats["successes"] >= 1:
                self.pass_the_hash_indicators.append({
                    "src_ip": src_ip,
                    "ntlm_failures": stats["failures"],
                    "ntlm_successes": stats["successes"],
                    "targets": list(stats["targets"]),
                    "risk": "CRITICAL",
                    "verdict": f"🔴 PASS-THE-HASH PROBABLE — {src_ip}: {stats['failures']} échecs NTLM puis succès",
                    "mitre": "T1550.002 - Use Alternate Authentication Material: Pass the Hash",
                    "recommended_action": "Réinitialiser les mots de passe NTLM, activer Protected Users, désactiver NTLMv1"
                })

    # ─────────────────────────────────────
    # Kerberoasting detection
    # ─────────────────────────────────────

    def _detect_kerberoasting(self, kerberos: Dict[str, Any]):
        """
        Détecte Kerberoasting:
        - AS-REQ sans pre-authentication (AS_REP Roasting)
        - Burst de TGS-REQ pour des service accounts différents
        """
        # Count TGS-REQ per source
        tgs_by_src: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        asreq_no_preauth: List[Dict[str, Any]] = []

        for pkt in self._records(kerberos.get("packets", [])):
            msg_type = str(pkt.get("msg_type", "")).upper()
            src = self._extract_ip(pkt, "src_ip", "src")

            if "TGS-REQ" in msg_type or "TGS_REQ" in msg_type:
                tgs_by_src[src].append(pkt)

            if ("AS-REQ" in msg_type or "AS_REQ" in msg_type) and not pkt.get("pre_auth"):
                asreq_no_preauth.append(pkt)

        # Kerberoasting: burst TGS-REQ
        for src_ip, reqs in tgs_by_src.items():
            if len(reqs) >= KERBEROAST_TGS_THRESHOLD:
                services = [r.get("service", "") for r in reqs if r.get("service")]
                self.kerberoasting_indicators.append({
                    "src_ip": src_ip,
                    "tgs_req_count": len(reqs),
                    "services_requested": list(set(services)),
                    "risk": "HIGH",
                    "verdict": f"🟠 KERBEROASTING PROBABLE — {src_ip} a demandé {len(reqs)} TGS-REQ",
                    "mitre": "T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting",
                    "recommended_action": "Auditer les comptes de service, activer le chiffrement AES-256, vérifier les SPNs"
                })

        # AS-REP Roasting
        if asreq_no_preauth:
            src_ips = list(set(r.get("src_ip", "") for r in asreq_no_preauth))
            self.kerberoasting_indicators.append({
                "type": "AS_REP_ROASTING",
                "total_asreq_no_preauth": len(asreq_no_preauth),
                "source_ips": src_ips,
                "risk": "HIGH",
                "verdict": f"🟠 AS-REP ROASTING — {len(asreq_no_preauth)} AS-REQ sans pré-authentification",
                "mitre": "T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting",
                "recommended_action": "Activer la pré-authentification Kerberos pour tous les comptes"
            })

    # ─────────────────────────────────────
    # LDAP enumeration detection
    # ─────────────────────────────────────

    def _detect_ldap_enumeration(self, ldap: Dict[str, Any]):
        """Détecte une énumération LDAP massive (reconnaissance Active Directory)"""
        query_by_src: Dict[str, int] = defaultdict(int)

        for op in self._records(ldap.get("operations", [])):
            if str(op.get("type", "")).lower() in ("searchrequest", "search", "bind"):
                src = self._extract_ip(op, "src_ip", "src")
                if src:
                    query_by_src[src] += 1

        for src_ip, count in query_by_src.items():
            if count >= LDAP_ENUM_THRESHOLD:
                self.ldap_enum_indicators.append({
                    "src_ip": src_ip,
                    "ldap_query_count": count,
                    "risk": "MEDIUM",
                    "verdict": f"🟡 ÉNUMÉRATION LDAP — {src_ip}: {count} requêtes LDAP",
                    "mitre": "T1087.002 - Account Discovery: Domain Account",
                    "recommended_action": "Implémenter LDAP signing, surveiller les requêtes LDAP anonymes, restreindre l'accès annuaire"
                })

    # ─────────────────────────────────────
    # Enriched graph building
    # ─────────────────────────────────────

    def _build_enriched_graph(
        self,
        smb: Dict[str, Any],
        kerberos: Dict[str, Any],
        ldap: Dict[str, Any],
        rdp: Dict[str, Any]
    ):
        """Construit le graphe de propagation latérale enrichi"""
        pivot_ips = {p["src_ip"] for p in self.pivot_hosts}
        pth_ips = {p["src_ip"] for p in self.pass_the_hash_indicators}
        kerb_ips = {k["src_ip"] for k in self.kerberoasting_indicators if "src_ip" in k}
        ldap_ips = {l["src_ip"] for l in self.ldap_enum_indicators}

        # SMB edges
        for session in self._records(smb.get("sessions", [])):
            src = self._extract_ip(session, "src_ip", "src")
            dst = self._extract_ip(session, "dst_ip", "dst")
            if src and dst:
                tags = []
                if src in pivot_ips:
                    tags.append("PIVOT")
                if src in pth_ips:
                    tags.append("PASS_THE_HASH")
                self.enriched_edges.append({
                    "src": src,
                    "dst": dst,
                    "protocol": "SMB",
                    "lateral_movement": bool(tags),
                    "tags": tags,
                    "color": "#e74c3c" if tags else "#e67e22",
                    "weight": 3 if tags else 1,
                })

        # RDP edges
        for session in self._records(rdp.get("sessions", [])):
            src = self._extract_ip(session, "src_ip", "src")
            dst = self._extract_ip(session, "dst_ip", "dst")
            if src and dst:
                tags = []
                if src in pivot_ips:
                    tags.append("PIVOT")
                self.enriched_edges.append({
                    "src": src,
                    "dst": dst,
                    "protocol": "RDP",
                    "lateral_movement": bool(tags),
                    "tags": tags,
                    "color": "#e74c3c" if tags else "#f39c12",
                    "weight": 3 if tags else 1,
                })

        # Kerberos edges
        for pkt in self._records(kerberos.get("packets", [])):
            src = self._extract_ip(pkt, "src_ip", "src")
            dst = self._extract_ip(pkt, "dst_ip", "dst")
            if src and dst:
                tags = []
                if src in kerb_ips:
                    tags.append("KERBEROASTING")
                self.enriched_edges.append({
                    "src": src,
                    "dst": dst,
                    "protocol": "Kerberos",
                    "lateral_movement": bool(tags),
                    "tags": tags,
                    "color": "#9b59b6" if tags else "#8e44ad",
                    "weight": 2 if tags else 1,
                })

        # LDAP edges
        for op in self._records(ldap.get("operations", [])):
            src = self._extract_ip(op, "src_ip", "src")
            dst = self._extract_ip(op, "dst_ip", "dst")
            if src and dst:
                tags = []
                if src in ldap_ips:
                    tags.append("LDAP_ENUM")
                self.enriched_edges.append({
                    "src": src,
                    "dst": dst,
                    "protocol": "LDAP",
                    "lateral_movement": bool(tags),
                    "tags": tags,
                    "color": "#e74c3c" if tags else "#3498db",
                    "weight": 2 if tags else 1,
                })

    # ─────────────────────────────────────
    # Results compilation
    # ─────────────────────────────────────

    def _compile_results(self) -> Dict[str, Any]:
        """Compile les résultats d'analyse des mouvements latéraux"""
        all_indicators = (
            self.pivot_hosts +
            self.pass_the_hash_indicators +
            self.kerberoasting_indicators +
            self.ldap_enum_indicators
        )

        risk_level = "NONE"
        if self.pass_the_hash_indicators:
            risk_level = "CRITICAL"
        elif self.kerberoasting_indicators or (len(self.pivot_hosts) > 0):
            risk_level = "HIGH"
        elif self.ldap_enum_indicators:
            risk_level = "MEDIUM"

        lateral_edges = [e for e in self.enriched_edges if e.get("lateral_movement")]

        return {
            "summary": {
                "risk_level": risk_level,
                "total_indicators": len(all_indicators),
                "pivot_hosts": len(self.pivot_hosts),
                "pass_the_hash": len(self.pass_the_hash_indicators),
                "kerberoasting": len(self.kerberoasting_indicators),
                "ldap_enumeration": len(self.ldap_enum_indicators),
                "lateral_movement_edges": len(lateral_edges),
            },
            "pivot_hosts": self.pivot_hosts,
            "pass_the_hash": self.pass_the_hash_indicators,
            "kerberoasting": self.kerberoasting_indicators,
            "ldap_enumeration": self.ldap_enum_indicators,
            "graph_edges": self.enriched_edges[:200],  # Limite pour perf frontend
            "lateral_movement_edges": lateral_edges[:100],
        }
