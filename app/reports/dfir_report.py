"""
DFIR Report Generator — Feature 10
Génère des rapports DFIR professionnels:
  - PDF avec ReportLab
  - Section executive summary, timeline IoCs, statistiques
  - Export JSON structuré pour SIEM/SOAR
"""

from __future__ import annotations

import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether
    )
    from reportlab.platypus.flowables import HRFlowable
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    from app.core.logging_config import get_logger
except ImportError:
    import logging
    def get_logger(name: str):  # type: ignore
        return logging.getLogger(name)

logger = get_logger(__name__)


# ─────────────────────────────────────────────────────────
# Color palette
# ─────────────────────────────────────────────────────────
COLOR_RED = colors.HexColor("#e74c3c")
COLOR_ORANGE = colors.HexColor("#e67e22")
COLOR_YELLOW = colors.HexColor("#f1c40f")
COLOR_GREEN = colors.HexColor("#27ae60")
COLOR_BLUE = colors.HexColor("#2980b9")
COLOR_DARK = colors.HexColor("#1a1a2e")
COLOR_HEADER = colors.HexColor("#16213e")
COLOR_LIGHT = colors.HexColor("#f5f5f5")


class DFIRReportGenerator:
    """
    Génère des rapports DFIR complets au format PDF et JSON.
    """

    def generate_pdf(
        self,
        task_id: str,
        analysis_results: Dict[str, Any],
        analyst_name: str = "PCAP Analyzer Pro v2",
        classification: str = "CONFIDENTIEL"
    ) -> bytes:
        """
        Génère un rapport PDF complet et retourne les octets du PDF.
        """
        if not REPORTLAB_AVAILABLE:
            raise RuntimeError("ReportLab not installed. Run: pip install reportlab")

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2.5*cm,
            bottomMargin=2*cm,
            title=f"DFIR Report — {task_id}",
            author=analyst_name,
        )

        styles = getSampleStyleSheet()
        self._define_styles(styles)

        story = []
        story += self._build_cover_page(task_id, analyst_name, classification, styles)
        story += self._build_executive_summary(analysis_results, styles)
        story += self._build_network_stats(analysis_results, styles)
        story += self._build_threat_intel_section(analysis_results, styles)
        story += self._build_anomaly_section(analysis_results, styles)
        story += self._build_top_ips_section(analysis_results, styles)
        story += self._build_timeline_section(analysis_results, styles)
        story += self._build_recommendations_section(analysis_results, styles)
        story += self._build_footer_section(task_id, styles)

        doc.build(story)
        return buffer.getvalue()

    def generate_json(
        self,
        task_id: str,
        analysis_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Génère un rapport JSON structuré (compatible SIEM/SOAR).
        """
        summary = analysis_results.get("summary", {})
        threat_intel = analysis_results.get("threat_intel", {})
        flow_behavior = analysis_results.get("flow_behavior", {})
        lateral = analysis_results.get("lateral_movement", {})
        anomalies = analysis_results.get("anomalies", [])

        # Extract critical IoCs
        iocs: List[Dict[str, Any]] = []

        for beacon in flow_behavior.get("beaconing_alerts", [])[:10]:
            iocs.append({
                "type": "ip",
                "value": beacon.get("dst_ip"),
                "context": f"C2 beaconing (score: {beacon.get('beacon_score')})",
                "severity": "CRITICAL" if beacon.get("beacon_score", 0) >= 90 else "HIGH",
                "mitre": beacon.get("mitre", ""),
            })

        for exfil in flow_behavior.get("exfiltration_alerts", [])[:5]:
            iocs.append({
                "type": "ip",
                "value": exfil.get("dst_ip"),
                "context": f"Data exfiltration target (~{exfil.get('estimated_exfil_mb', 0)}MB)",
                "severity": "CRITICAL",
                "mitre": exfil.get("mitre", ""),
            })

        for pth in lateral.get("pass_the_hash", [])[:5]:
            iocs.append({
                "type": "ip",
                "value": pth.get("src_ip"),
                "context": "Pass-the-Hash source",
                "severity": "CRITICAL",
                "mitre": pth.get("mitre", ""),
            })

        for ip, intel in threat_intel.get("ip_intel", {}).items():
            if intel.get("reputation_score", 0) >= 70:
                iocs.append({
                    "type": "ip",
                    "value": ip,
                    "context": intel.get("verdict", ""),
                    "severity": "HIGH",
                    "reputation_score": intel.get("reputation_score", 0),
                })

        return {
            "report_id": f"DFIR-{task_id[:8].upper()}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "task_id": task_id,
            "risk_summary": {
                "overall_risk": self._compute_overall_risk(analysis_results),
                "total_anomalies": len(anomalies),
                "beaconing_alerts": flow_behavior.get("summary", {}).get("beaconing_alerts", 0),
                "exfiltration_alerts": flow_behavior.get("summary", {}).get("exfiltration_alerts", 0),
                "lateral_movement_indicators": lateral.get("summary", {}).get("total_indicators", 0),
                "malicious_ips": threat_intel.get("summary", {}).get("malicious_ips", 0),
            },
            "indicators_of_compromise": iocs,
            "top_threats": self._extract_top_threats(analysis_results),
            "network_summary": summary,
        }

    # ─────────────────────────────────────────────────────────
    # PDF Builder Methods
    # ─────────────────────────────────────────────────────────

    def _define_styles(self, styles):
        styles.add(ParagraphStyle(
            name='CoverTitle',
            fontSize=28, fontName='Helvetica-Bold',
            textColor=COLOR_DARK, spaceAfter=12, alignment=1
        ))
        styles.add(ParagraphStyle(
            name='CoverSubtitle',
            fontSize=14, fontName='Helvetica',
            textColor=COLOR_BLUE, spaceAfter=8, alignment=1
        ))
        styles.add(ParagraphStyle(
            name='SectionHeader',
            fontSize=14, fontName='Helvetica-Bold',
            textColor=COLOR_HEADER, spaceAfter=6, spaceBefore=16,
            borderPad=4
        ))
        styles.add(ParagraphStyle(
            name='SubHeader',
            fontSize=11, fontName='Helvetica-Bold',
            textColor=COLOR_DARK, spaceAfter=4, spaceBefore=8
        ))
        styles.add(ParagraphStyle(
            name='BodyText2',
            fontSize=9, fontName='Helvetica',
            textColor=colors.black, spaceAfter=4,
            leading=14
        ))
        styles.add(ParagraphStyle(
            name='ClassificationBanner',
            fontSize=10, fontName='Helvetica-Bold',
            textColor=colors.white, backColor=COLOR_RED,
            spaceAfter=4, spaceBefore=4, alignment=1,
            borderPad=6
        ))

    def _build_cover_page(self, task_id, analyst_name, classification, styles):
        elements = []
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        elements.append(Spacer(1, 2*cm))
        elements.append(Paragraph(
            f"🔒 {classification}",
            styles['ClassificationBanner']
        ))
        elements.append(Spacer(1, 1.5*cm))
        elements.append(Paragraph("RAPPORT DFIR", styles['CoverTitle']))
        elements.append(Paragraph("Digital Forensics & Incident Response", styles['CoverSubtitle']))
        elements.append(Spacer(1, 1*cm))

        cover_data = [
            ["Task ID", task_id[:16] + "..."],
            ["Généré le", now],
            ["Analyste", analyst_name],
            ["Classification", classification],
            ["Outil", "PCAP Analyzer Pro v2"],
        ]
        cover_table = Table(cover_data, colWidths=[4*cm, 10*cm])
        cover_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), COLOR_HEADER),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ROWBACKGROUNDS', (1, 0), (1, -1), [COLOR_LIGHT, colors.white]),
            ('BOX', (0, 0), (-1, -1), 1, COLOR_DARK),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(cover_table)
        elements.append(PageBreak())
        return elements

    def _build_executive_summary(self, results, styles):
        elements = []
        elements.append(Paragraph("1. RÉSUMÉ EXÉCUTIF", styles['SectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=2, color=COLOR_BLUE))
        elements.append(Spacer(1, 0.3*cm))

        summary = results.get("summary", {})
        flow_behavior = results.get("flow_behavior", {})
        lateral = results.get("lateral_movement", {})
        threat_intel = results.get("threat_intel", {})

        risk_hex = {
            "CRITICAL": "e74c3c", "HIGH": "e67e22",
            "MEDIUM": "f1c40f", "LOW": "27ae60", "NONE": "27ae60"
        }
        overall_risk = self._compute_overall_risk(results)
        hex_code = risk_hex.get(overall_risk, "2980b9")
        risk_text = f"<b>Niveau de Risque Global:</b> <font color='#{hex_code}'>{overall_risk}</font>"
        elements.append(Paragraph(risk_text, styles['SubHeader']))
        elements.append(Spacer(1, 0.3*cm))

        exec_data = [
            ["Métrique", "Valeur", "Statut"],
            ["Total paquets analysés", str(summary.get("total_packets", "N/A")), "✓"],
            ["Alertes beaconing C2", str(flow_behavior.get("summary", {}).get("beaconing_alerts", 0)),
             "🔴" if flow_behavior.get("summary", {}).get("beaconing_alerts", 0) > 0 else "✓"],
            ["Alertes exfiltration", str(flow_behavior.get("summary", {}).get("exfiltration_alerts", 0)),
             "🔴" if flow_behavior.get("summary", {}).get("exfiltration_alerts", 0) > 0 else "✓"],
            ["Indicateurs mouvement latéral", str(lateral.get("summary", {}).get("total_indicators", 0)),
             "🟠" if lateral.get("summary", {}).get("total_indicators", 0) > 0 else "✓"],
            ["IPs malveillantes (Threat Intel)", str(threat_intel.get("summary", {}).get("malicious_ips", 0)),
             "🔴" if threat_intel.get("summary", {}).get("malicious_ips", 0) > 0 else "✓"],
        ]

        exec_table = Table(exec_data, colWidths=[7*cm, 4*cm, 3*cm])
        exec_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLOR_HEADER),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOR_LIGHT, colors.white]),
            ('BOX', (0, 0), (-1, -1), 1, COLOR_DARK),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
        ]))
        elements.append(exec_table)
        elements.append(Spacer(1, 0.5*cm))
        return elements

    def _build_network_stats(self, results, styles):
        elements = []
        elements.append(Paragraph("2. STATISTIQUES RÉSEAU", styles['SectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=2, color=COLOR_BLUE))
        elements.append(Spacer(1, 0.3*cm))

        summary = results.get("summary", {})
        protocols = results.get("protocols", {})

        if summary:
            stats_data = [["Paramètre", "Valeur"]]
            for k, v in [
                ("Total paquets", summary.get("total_packets", "N/A")),
                ("Total octets", str(summary.get("total_bytes", "N/A"))),
                ("IPs uniques", summary.get("unique_ips", "N/A")),
                ("Durée capture", f"{summary.get('duration_seconds', 0):.1f}s"),
                ("Paquets/seconde", f"{summary.get('packets_per_second', 0):.1f}"),
            ]:
                stats_data.append([k, str(v)])

            stats_table = Table(stats_data, colWidths=[6*cm, 8*cm])
            stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), COLOR_HEADER),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOR_LIGHT, colors.white]),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOX', (0, 0), (-1, -1), 1, COLOR_DARK),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(stats_table)

        elements.append(Spacer(1, 0.5*cm))
        return elements

    def _build_threat_intel_section(self, results, styles):
        elements = []
        threat_intel = results.get("threat_intel", {})
        if not threat_intel:
            return elements

        elements.append(Paragraph("3. THREAT INTELLIGENCE", styles['SectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=2, color=COLOR_BLUE))
        elements.append(Spacer(1, 0.3*cm))

        critical_iocs = threat_intel.get("critical_iocs", [])
        if critical_iocs:
            elements.append(Paragraph("IoCs critiques détectés:", styles['SubHeader']))
            ioc_data = [["Indicateur", "Type", "Score", "Verdict"]]
            for ioc in critical_iocs[:15]:
                ioc_data.append([
                    str(ioc.get("value", "")),
                    ioc.get("type", ""),
                    str(ioc.get("score", 0)),
                    "🔴 MALICIOUS",
                ])
            ioc_table = Table(ioc_data, colWidths=[5*cm, 2.5*cm, 2.5*cm, 4*cm])
            ioc_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), COLOR_RED),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#ffe6e6"), colors.white]),
                ('BOX', (0, 0), (-1, -1), 1, COLOR_RED),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ('PADDING', (0, 0), (-1, -1), 5),
            ]))
            elements.append(ioc_table)

        elements.append(Spacer(1, 0.5*cm))
        return elements

    def _build_anomaly_section(self, results, styles):
        elements = []
        anomalies = results.get("anomalies", [])
        if not anomalies:
            return elements

        elements.append(Paragraph("4. ANOMALIES DÉTECTÉES", styles['SectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=2, color=COLOR_BLUE))
        elements.append(Spacer(1, 0.3*cm))

        anom_data = [["Sévérité", "Type", "Score", "Description"]]
        for a in anomalies[:20]:
            sev = str(a.get("severity", "")).upper()
            anom_data.append([
                sev,
                str(a.get("type", ""))[:30],
                str(a.get("score", "")),
                str(a.get("description", ""))[:60],
            ])

        anom_table = Table(anom_data, colWidths=[2.5*cm, 4*cm, 1.5*cm, 6*cm])
        anom_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLOR_ORANGE),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOR_LIGHT, colors.white]),
            ('BOX', (0, 0), (-1, -1), 1, COLOR_DARK),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('PADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(anom_table)
        elements.append(Spacer(1, 0.5*cm))
        return elements

    def _build_top_ips_section(self, results, styles):
        elements = []
        geo = results.get("geolocation", {})
        top_ips = results.get("top_talkers", [])
        if not top_ips:
            return elements

        elements.append(Paragraph("5. TOP COMMUNICANTS RÉSEAU", styles['SectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=2, color=COLOR_BLUE))
        elements.append(Spacer(1, 0.3*cm))

        ip_data = [["IP", "Paquets", "Octets", "Pays", "ISP"]]
        for ip_info in top_ips[:10]:
            ip = str(ip_info.get("ip", ""))
            geo_info = geo.get(ip, {})
            ip_data.append([
                ip,
                str(ip_info.get("packets", "")),
                str(ip_info.get("bytes", "")),
                str(geo_info.get("country", "N/A")),
                str(geo_info.get("isp", "N/A"))[:25],
            ])

        ip_table = Table(ip_data, colWidths=[4*cm, 2.5*cm, 2.5*cm, 2.5*cm, 3.5*cm])
        ip_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLOR_HEADER),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOR_LIGHT, colors.white]),
            ('BOX', (0, 0), (-1, -1), 1, COLOR_DARK),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('PADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(ip_table)
        elements.append(Spacer(1, 0.5*cm))
        return elements

    def _build_timeline_section(self, results, styles):
        elements = []
        timeline = results.get("timeline_events", [])
        if not timeline:
            return elements

        elements.append(Paragraph("6. TIMELINE DES ÉVÉNEMENTS CRITIQUES", styles['SectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=2, color=COLOR_BLUE))
        elements.append(Spacer(1, 0.3*cm))

        tl_data = [["Timestamp", "Type", "Source", "Détail"]]
        for event in timeline[:20]:
            tl_data.append([
                str(event.get("timestamp", ""))[:19],
                str(event.get("type", ""))[:20],
                str(event.get("source_ip", "N/A")),
                str(event.get("description", ""))[:50],
            ])

        tl_table = Table(tl_data, colWidths=[3.5*cm, 3*cm, 3*cm, 5.5*cm])
        tl_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLOR_HEADER),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOR_LIGHT, colors.white]),
            ('BOX', (0, 0), (-1, -1), 1, COLOR_DARK),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('PADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(tl_table)
        elements.append(Spacer(1, 0.5*cm))
        return elements

    def _build_recommendations_section(self, results, styles):
        elements = []
        elements.append(Paragraph("7. RECOMMANDATIONS", styles['SectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=2, color=COLOR_BLUE))
        elements.append(Spacer(1, 0.3*cm))

        recs = self._generate_recommendations(results)
        for i, rec in enumerate(recs, 1):
            elements.append(Paragraph(f"<b>{i}.</b> {rec}", styles['BodyText2']))
            elements.append(Spacer(1, 0.1*cm))

        elements.append(Spacer(1, 0.5*cm))
        return elements

    def _build_footer_section(self, task_id, styles):
        elements = []
        elements.append(Spacer(1, 1*cm))
        elements.append(HRFlowable(width="100%", thickness=1, color=COLOR_DARK))
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        elements.append(Paragraph(
            f"Rapport généré automatiquement par PCAP Analyzer Pro v2 | Task ID: {task_id[:16]} | {now}",
            styles['BodyText2']
        ))
        return elements

    # ─────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────

    def _compute_overall_risk(self, results: Dict[str, Any]) -> str:
        flow = results.get("flow_behavior", {}).get("summary", {})
        lateral = results.get("lateral_movement", {}).get("summary", {})
        threat_intel = results.get("threat_intel", {}).get("summary", {})

        if (
            flow.get("beaconing_alerts", 0) > 0 and
            any(a.get("beacon_score", 0) >= 90 for a in results.get("flow_behavior", {}).get("beaconing_alerts", []))
        ) or lateral.get("pass_the_hash", 0) > 0 or threat_intel.get("malicious_ips", 0) > 2:
            return "CRITICAL"
        elif flow.get("exfiltration_alerts", 0) > 0 or lateral.get("total_indicators", 0) > 0:
            return "HIGH"
        elif flow.get("beaconing_alerts", 0) > 0 or threat_intel.get("suspicious_ips", 0) > 0:
            return "MEDIUM"
        return "LOW"

    def _extract_top_threats(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        threats = []

        for beacon in results.get("flow_behavior", {}).get("beaconing_alerts", [])[:5]:
            threats.append({
                "type": "C2 Beaconing",
                "severity": "CRITICAL" if beacon.get("beacon_score", 0) >= 90 else "HIGH",
                "indicator": beacon.get("dst_ip"),
                "description": beacon.get("verdict", ""),
                "mitre": beacon.get("mitre", ""),
            })

        for exfil in results.get("flow_behavior", {}).get("exfiltration_alerts", [])[:3]:
            threats.append({
                "type": "Data Exfiltration",
                "severity": "CRITICAL",
                "indicator": f"{exfil.get('src_ip')} → {exfil.get('dst_ip')}",
                "description": exfil.get("verdict", ""),
                "mitre": exfil.get("mitre", ""),
            })

        return threats

    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        recs = []
        flow = results.get("flow_behavior", {})
        lateral = results.get("lateral_movement", {})
        threat_intel = results.get("threat_intel", {})

        if flow.get("summary", {}).get("beaconing_alerts", 0) > 0:
            recs.append("Bloquer IMMÉDIATEMENT les IPs C2 identifiées au niveau firewall périmètre. Isoler les machines béaconisant.")

        if flow.get("summary", {}).get("exfiltration_alerts", 0) > 0:
            recs.append("Investiguer les transferts de données suspects. Notifier le DPO si des données personnelles sont impliquées.")

        if lateral.get("summary", {}).get("pass_the_hash", 0) > 0:
            recs.append("Réinitialiser TOUS les mots de passe NTLM et activer Protected Users AD. Envisager de désactiver NTLMv1.")

        if lateral.get("summary", {}).get("kerberoasting", 0) > 0:
            recs.append("Auditer les comptes de service Active Directory. Changer les mots de passe des comptes à SPN. Activer AES-256.")

        if threat_intel.get("summary", {}).get("malicious_ips", 0) > 0:
            recs.append("Bloquer les IPs répertoriées comme malveillantes sur l'ensemble de l'infrastructure réseau.")

        recs.append("Déployer un EDR/XDR sur l'ensemble du parc pour une visibilité endpoint complète.")
        recs.append("Activer la journalisation DNS (RPZ) et configurer un DNS sinkhole pour les domaines malveillants.")
        recs.append("Programmer un pentest interne pour valider l'efficacité des mesures correctives mises en place.")

        return recs
