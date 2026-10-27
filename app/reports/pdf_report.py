"""
Générateur de rapports PDF
Rapport professionnel avec graphiques intégrés utilisant ReportLab
"""

import io
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, HRFlowable
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart

import matplotlib
matplotlib.use('Agg')  # Backend non-interactif
import matplotlib.pyplot as plt

from app.core.logging_config import get_logger

logger = get_logger(__name__)


class PDFReportGenerator:
    """Générateur de rapports PDF professionnels"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Configure les styles personnalisés"""
        self.styles.add(ParagraphStyle(
            name='Title2',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#1a365d')
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.HexColor('#2c5282')
        ))
        
        self.styles.add(ParagraphStyle(
            name='SubSection',
            parent=self.styles['Heading3'],
            fontSize=12,
            spaceBefore=15,
            spaceAfter=8,
            textColor=colors.HexColor('#4a5568')
        ))
        
        self.styles.add(ParagraphStyle(
            name='BodyTextCustom',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=6
        ))
    
    def generate(self, results: Dict[str, Any], output_path: Path) -> Path:
        """
        Génère un rapport PDF complet
        
        Args:
            results: Résultats de l'analyse
            output_path: Chemin du fichier de sortie
            
        Returns:
            Chemin du fichier généré
        """
        logger.info("generating_pdf_report", output=str(output_path))
        
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )
        
        story = []
        
        # Page de titre
        story.extend(self._create_title_page(results))
        story.append(PageBreak())
        
        # Résumé exécutif
        story.extend(self._create_executive_summary(results))
        story.append(PageBreak())
        
        # Analyse des protocoles
        story.extend(self._create_protocol_section(results))
        story.append(PageBreak())
        
        # Analyse TCP
        story.extend(self._create_tcp_section(results))
        story.append(PageBreak())
        
        # Détection d'anomalies
        story.extend(self._create_anomaly_section(results))
        
        # Build PDF
        doc.build(story)
        
        logger.info("pdf_report_generated", path=str(output_path))
        return output_path
    
    def _create_title_page(self, results: Dict) -> List:
        """Crée la page de titre"""
        story = []
        
        metadata = results.get('metadata', {})
        
        story.append(Spacer(1, 3*cm))
        story.append(Paragraph("RAPPORT D'ANALYSE PCAP", self.styles['Title2']))
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#2c5282')))
        story.append(Spacer(1, 2*cm))
        
        # Informations du fichier
        info_data = [
            ['Fichier analysé:', metadata.get('filename', 'Inconnu')],
            ['Date d\'analyse:', metadata.get('analysis_timestamp', datetime.now().isoformat())[:19]],
            ['Taille du fichier:', self._format_bytes(metadata.get('file_size', 0))],
            ['Durée d\'analyse:', f"{metadata.get('analysis_duration_seconds', 0):.2f} secondes"],
        ]
        
        info_table = Table(info_data, colWidths=[5*cm, 10*cm])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#4a5568')),
        ]))
        story.append(info_table)
        
        story.append(Spacer(1, 2*cm))
        
        # Risk level badge
        anomaly_summary = (results.get('anomaly_detection') or results.get('anomaly_analysis', {})).get('summary', {})
        risk_level = anomaly_summary.get('risk_level', 'NONE')
        risk_colors = {
            'NONE': colors.HexColor('#48bb78'),
            'LOW': colors.HexColor('#ecc94b'),
            'MEDIUM': colors.HexColor('#ed8936'),
            'HIGH': colors.HexColor('#f56565'),
            'CRITICAL': colors.HexColor('#e53e3e')
        }
        
        risk_data = [[
            'NIVEAU DE RISQUE:',
            risk_level
        ]]
        risk_table = Table(risk_data, colWidths=[5*cm, 5*cm])
        risk_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 14),
            ('BACKGROUND', (1, 0), (1, 0), risk_colors.get(risk_level, colors.grey)),
            ('TEXTCOLOR', (1, 0), (1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(risk_table)
        
        return story
    
    def _create_executive_summary(self, results: Dict) -> List:
        """Crée le résumé exécutif"""
        story = []
        
        story.append(Paragraph("Résumé Exécutif", self.styles['SectionHeader']))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
        story.append(Spacer(1, 0.5*cm))
        
        protocol_summary = results.get('protocol_analysis', {}).get('summary', {})
        tcp_summary = results.get('tcp_analysis', {}).get('summary', {})
        anomaly_summary = (results.get('anomaly_detection') or results.get('anomaly_analysis', {})).get('summary', {})
        
        # Tableau de statistiques clés
        stats_data = [
            ['Métrique', 'Valeur'],
            ['Total Paquets', f"{protocol_summary.get('total_packets', 0):,}"],
            ['Total Bytes', self._format_bytes(protocol_summary.get('total_bytes', 0))],
            ['Durée Capture', f"{protocol_summary.get('capture_duration_seconds', 0):.2f}s"],
            ['Débit Moyen', f"{protocol_summary.get('packets_per_second', 0):.2f} pkt/s"],
            ['Sessions TCP', f"{tcp_summary.get('total_sessions', 0):,}"],
            ['Handshakes Complets', f"{tcp_summary.get('established_sessions', 0):,}"],
            ['Retransmissions', f"{tcp_summary.get('total_retransmissions', 0):,}"],
            ['Anomalies Détectées', f"{anomaly_summary.get('total_anomalies', 0)}"],
            ['Score de Risque', f"{anomaly_summary.get('total_score', 0)}"],
        ]
        
        stats_table = Table(stats_data, colWidths=[8*cm, 6*cm])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5282')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(stats_table)
        
        return story
    
    def _create_protocol_section(self, results: Dict) -> List:
        """Crée la section analyse des protocoles"""
        story = []
        
        story.append(Paragraph("Analyse des Protocoles", self.styles['SectionHeader']))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
        story.append(Spacer(1, 0.5*cm))
        
        protocols = results.get('protocol_analysis', {}).get('protocols', {})
        
        if protocols:
            # Tableau des protocoles
            proto_data = [['Protocole', 'Paquets', 'Bytes', '% Trafic']]
            total_bytes = sum(p.get('bytes', 0) for p in protocols.values())
            
            for proto, stats in sorted(protocols.items(), key=lambda x: x[1].get('bytes', 0), reverse=True):
                pct = (stats.get('bytes', 0) / total_bytes * 100) if total_bytes > 0 else 0
                proto_data.append([
                    proto,
                    f"{stats.get('count', 0):,}",
                    self._format_bytes(stats.get('bytes', 0)),
                    f"{pct:.1f}%"
                ])
            
            proto_table = Table(proto_data, colWidths=[4*cm, 4*cm, 4*cm, 3*cm])
            proto_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a5568')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (1, 0), (-1, -1), 'RIGHT'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(proto_table)
        
        # Top IPs
        story.append(Spacer(1, 1*cm))
        story.append(Paragraph("Top Adresses IP", self.styles['SubSection']))
        
        ip_stats = results.get('protocol_analysis', {}).get('ip_statistics', {})
        top_sources = ip_stats.get('top_sources', [])[:10]
        
        if top_sources:
            ip_data = [['IP Source', 'Paquets', 'Bytes']]
            for ip_info in top_sources:
                ip_data.append([
                    ip_info.get('ip', ''),
                    f"{ip_info.get('count', 0):,}",
                    self._format_bytes(ip_info.get('bytes', 0))
                ])
            
            ip_table = Table(ip_data, colWidths=[6*cm, 4*cm, 5*cm])
            ip_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#718096')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (1, 0), (-1, -1), 'RIGHT'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(ip_table)
        
        return story
    
    def _create_tcp_section(self, results: Dict) -> List:
        """Crée la section analyse TCP"""
        story = []
        
        story.append(Paragraph("Analyse TCP Approfondie", self.styles['SectionHeader']))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
        story.append(Spacer(1, 0.5*cm))
        
        tcp = results.get('tcp_analysis', {})
        summary = tcp.get('summary', {})
        handshake = tcp.get('handshake_analysis', {})
        retrans = tcp.get('retransmission_analysis', {})
        rtt = tcp.get('rtt_analysis', {})
        
        # Statistiques TCP
        tcp_stats = [
            ['Métrique', 'Valeur'],
            ['Total Sessions', f"{summary.get('total_sessions', 0):,}"],
            ['Sessions Établies', f"{summary.get('established_sessions', 0):,}"],
            ['Connexions Half-Open', f"{summary.get('half_open_connections', 0):,}"],
            ['Handshakes Complets', f"{handshake.get('complete_handshakes', 0):,}"],
            ['Handshakes Incomplets', f"{handshake.get('incomplete_handshakes', 0):,}"],
            ['Taux de Succès Handshake', f"{handshake.get('handshake_success_rate', 0):.1f}%"],
            ['Total Retransmissions', f"{retrans.get('total_retransmissions', 0):,}"],
            ['Taux Retransmission', f"{retrans.get('retransmission_rate', 0):.2f}%"],
            ['RTT Moyen (ms)', f"{rtt.get('avg_rtt_ms', 0):.2f}"],
            ['RTT Min (ms)', f"{rtt.get('min_rtt_ms', 0):.2f}"],
            ['RTT Max (ms)', f"{rtt.get('max_rtt_ms', 0):.2f}"],
        ]
        
        tcp_table = Table(tcp_stats, colWidths=[8*cm, 6*cm])
        tcp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#38a169')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0fff4')]),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(tcp_table)
        
        # Distribution des états de connexion
        story.append(Spacer(1, 0.8*cm))
        story.append(Paragraph("États des Connexions TCP", self.styles['SubSection']))
        
        conn_states = tcp.get('connection_states', {})
        if conn_states:
            state_data = [['\u00c9tat', 'Nombre']]
            for state, count in conn_states.items():
                state_data.append([state, f"{count:,}"])
            
            state_table = Table(state_data, colWidths=[6*cm, 4*cm])
            state_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#68d391')),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(state_table)
        
        return story
    
    def _create_anomaly_section(self, results: Dict) -> List:
        """Crée la section détection d'anomalies"""
        story = []
        
        story.append(Paragraph("Détection d'Anomalies", self.styles['SectionHeader']))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
        story.append(Spacer(1, 0.5*cm))
        
        anomaly_data = results.get('anomaly_detection') or results.get('anomaly_analysis', {})
        summary = anomaly_data.get('summary', {})
        anomalies = anomaly_data.get('anomalies', [])
        
        # Résumé des anomalies
        summary_text = f"""
        <b>Total d'anomalies détectées:</b> {summary.get('total_anomalies', 0)}<br/>
        <b>Score de risque total:</b> {summary.get('total_score', 0)}<br/>
        <b>Niveau de risque:</b> {summary.get('risk_level', 'NONE')}
        """
        story.append(Paragraph(summary_text, self.styles['BodyTextCustom']))
        story.append(Spacer(1, 0.5*cm))
        
        # Distribution par sévérité
        by_severity = summary.get('by_severity', {})
        if by_severity:
            story.append(Paragraph("Distribution par Sévérité", self.styles['SubSection']))
            sev_data = [['Sévérité', 'Nombre']]
            severity_colors = {
                'CRITICAL': colors.HexColor('#e53e3e'),
                'HIGH': colors.HexColor('#f56565'),
                'MEDIUM': colors.HexColor('#ed8936'),
                'LOW': colors.HexColor('#ecc94b'),
                'INFO': colors.HexColor('#4299e1')
            }
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if sev in by_severity:
                    sev_data.append([sev, str(by_severity[sev])])
            
            if len(sev_data) > 1:
                sev_table = Table(sev_data, colWidths=[5*cm, 3*cm])
                sev_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#742a2a')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                ]))
                story.append(sev_table)
                story.append(Spacer(1, 0.5*cm))
        
        # Liste des anomalies (limitée)
        if anomalies:
            story.append(Paragraph("Détail des Anomalies (Top 20)", self.styles['SubSection']))
            
            anom_data = [['Type', 'Sévérité', 'Score', 'Description']]
            for anom in anomalies[:20]:
                desc = anom.get('description', '')[:60]
                if len(anom.get('description', '')) > 60:
                    desc += '...'
                anom_data.append([
                    anom.get('type', ''),
                    anom.get('severity', ''),
                    str(anom.get('score', 0)),
                    desc
                ])
            
            anom_table = Table(anom_data, colWidths=[3.5*cm, 2*cm, 1.5*cm, 8*cm])
            anom_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c53030')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fff5f5')]),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(anom_table)
        
        return story
    
    def _format_bytes(self, size: int) -> str:
        """Formate une taille en bytes"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
