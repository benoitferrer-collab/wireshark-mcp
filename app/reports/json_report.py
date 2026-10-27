"""
Générateur de rapports JSON
Export structuré complet des résultats d'analyse
"""

import json
from pathlib import Path
from typing import Dict, Any
from app.core.logging_config import get_logger

logger = get_logger(__name__)


class JSONReportGenerator:
    """Générateur de rapports JSON"""
    
    def generate(self, results: Dict[str, Any], output_path: Path) -> Path:
        """
        Génère un rapport JSON complet
        
        Args:
            results: Résultats de l'analyse
            output_path: Chemin du fichier de sortie
            
        Returns:
            Chemin du fichier généré
        """
        logger.info("generating_json_report", output=str(output_path))
        
        # Enrichir avec des métadonnées de rapport
        report = {
            'report_type': 'json',
            'report_version': '1.0',
            **results
        }
        
        # Écrire le fichier JSON formaté
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)
        
        logger.info("json_report_generated", path=str(output_path))
        return output_path
    
    def generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Génère un résumé JSON (version allégée)"""
        protocol = results.get('protocol_analysis', {})
        tcp = results.get('tcp_analysis', {})
        anomaly = results.get('anomaly_detection') or results.get('anomaly_analysis', {})
        dns = results.get('dns_analysis', {})
        http = results.get('http_analysis', {})
        
        return {
            'summary': {
                'total_packets': protocol.get('summary', {}).get('total_packets', 0),
                'total_bytes': protocol.get('summary', {}).get('total_bytes', 0),
                'capture_duration': protocol.get('summary', {}).get('capture_duration_seconds', 0),
                'tcp_sessions': tcp.get('summary', {}).get('total_sessions', 0),
                'anomalies': anomaly.get('summary', {}).get('total_anomalies', 0),
                'risk_level': anomaly.get('summary', {}).get('risk_level', 'NONE'),
                'dns_queries': dns.get('summary', {}).get('total_queries', 0),
                'http_requests': http.get('summary', {}).get('total_requests', 0),
                'tls_sessions': http.get('summary', {}).get('total_tls_sessions', 0)
            },
            'top_ips': protocol.get('ip_statistics', {}).get('top_sources', [])[:5],
            'protocol_distribution': protocol.get('protocols', {}),
            'anomaly_types': anomaly.get('summary', {}).get('by_type', {}),
            'dns': {
                'top_domains': dns.get('top_domains', [])[:10],
                'query_types': dns.get('query_types', {}),
                'nxdomain_rate': dns.get('summary', {}).get('nxdomain_rate', 0),
                'anomalies': len(dns.get('anomalies', []))
            },
            'http': {
                'methods': http.get('methods', {}),
                'status_codes': http.get('status_codes', {}),
                'top_hosts': http.get('hosts', [])[:10],
                'tls_versions': http.get('tls', {}).get('versions', {}),
                'anomalies': len(http.get('anomalies', []))
            }
        }
