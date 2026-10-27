"""
Générateur de rapports CSV
Export tabulaire des données d'analyse
"""

import csv
import io
from pathlib import Path
from typing import Dict, Any, List
from app.core.logging_config import get_logger

logger = get_logger(__name__)


class CSVReportGenerator:
    """Générateur de rapports CSV multi-feuilles"""
    
    def generate(self, results: Dict[str, Any], output_dir: Path) -> Dict[str, Path]:
        """
        Génère plusieurs fichiers CSV
        
        Args:
            results: Résultats de l'analyse
            output_dir: Répertoire de sortie
            
        Returns:
            Dict des chemins des fichiers générés
        """
        logger.info("generating_csv_reports", output_dir=str(output_dir))
        
        output_dir.mkdir(parents=True, exist_ok=True)
        generated_files = {}
        
        # Résumé général
        summary_path = output_dir / 'summary.csv'
        self._generate_summary_csv(results, summary_path)
        generated_files['summary'] = summary_path
        
        # Statistiques IP
        ip_path = output_dir / 'ip_statistics.csv'
        self._generate_ip_csv(results, ip_path)
        generated_files['ip_statistics'] = ip_path
        
        # Sessions TCP
        tcp_path = output_dir / 'tcp_sessions.csv'
        self._generate_tcp_csv(results, tcp_path)
        generated_files['tcp_sessions'] = tcp_path
        
        # Anomalies
        anomalies_path = output_dir / 'anomalies.csv'
        self._generate_anomalies_csv(results, anomalies_path)
        generated_files['anomalies'] = anomalies_path
        
        # Ports
        ports_path = output_dir / 'ports.csv'
        self._generate_ports_csv(results, ports_path)
        generated_files['ports'] = ports_path
        
        logger.info("csv_reports_generated", files=list(generated_files.keys()))
        return generated_files
    
    def generate_combined(self, results: Dict[str, Any], output_path: Path) -> Path:
        """
        Génère un fichier CSV unique combiné (pour téléchargement simple)
        """
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Section Résumé
            writer.writerow(['=== RÉSUMÉ ==='])
            writer.writerow(['Métrique', 'Valeur'])
            summary = results.get('protocol_analysis', {}).get('summary', {})
            dns_summary = results.get('dns_analysis', {}).get('summary', {})
            http_summary = results.get('http_analysis', {}).get('summary', {})
            writer.writerow(['Total Paquets', summary.get('total_packets', 0)])
            writer.writerow(['Total Bytes', summary.get('total_bytes', 0)])
            writer.writerow(['Durée Capture (s)', summary.get('capture_duration_seconds', 0)])
            writer.writerow(['Paquets/Seconde', summary.get('packets_per_second', 0)])
            writer.writerow(['Requêtes DNS', dns_summary.get('total_queries', 0)])
            writer.writerow(['Requêtes HTTP', http_summary.get('total_requests', 0)])
            writer.writerow(['Sessions TLS', http_summary.get('total_tls_sessions', 0)])
            writer.writerow([])
            
            # Section Protocoles
            writer.writerow(['=== PROTOCOLES ==='])
            writer.writerow(['Protocole', 'Paquets', 'Bytes'])
            protocols = results.get('protocol_analysis', {}).get('protocols', {})
            for proto, stats in protocols.items():
                writer.writerow([proto, stats.get('count', 0), stats.get('bytes', 0)])
            writer.writerow([])
            
            # Section DNS
            writer.writerow(['=== ANALYSE DNS ==='])
            writer.writerow(['Top Domaines', 'Requêtes', 'Types'])
            top_domains = results.get('dns_analysis', {}).get('top_domains', [])
            for domain in top_domains[:30]:
                types_str = ', '.join(domain.get('types', {}).keys())
                writer.writerow([domain.get('domain', ''), domain.get('count', 0), types_str])
            writer.writerow([])
            
            writer.writerow(['Types de Requêtes DNS', 'Count'])
            query_types = results.get('dns_analysis', {}).get('query_types', {})
            for qtype, count in query_types.items():
                writer.writerow([qtype, count])
            writer.writerow([])
            
            # Section HTTP
            writer.writerow(['=== ANALYSE HTTP ==='])
            writer.writerow(['Méthode', 'Count'])
            methods = results.get('http_analysis', {}).get('methods', {})
            for method, count in methods.items():
                writer.writerow([method, count])
            writer.writerow([])
            
            writer.writerow(['Status Code', 'Count'])
            status_codes = results.get('http_analysis', {}).get('status_codes', {})
            for code, data in status_codes.items():
                count = data.get('count', data) if isinstance(data, dict) else data
                writer.writerow([code, count])
            writer.writerow([])
            
            writer.writerow(['Top Hosts HTTP', 'Requêtes'])
            hosts = results.get('http_analysis', {}).get('hosts', [])
            for host in hosts[:20]:
                writer.writerow([host.get('name', ''), host.get('count', 0)])
            writer.writerow([])
            
            # Section Anomalies
            writer.writerow(['=== ANOMALIES ==='])
            writer.writerow(['Type', 'Sévérité', 'Score', 'Description', 'IP Source'])
            anomalies = (results.get('anomaly_detection') or results.get('anomaly_analysis', {})).get('anomalies', [])
            for anomaly in anomalies[:50]:
                writer.writerow([
                    anomaly.get('type', ''),
                    anomaly.get('severity', ''),
                    anomaly.get('score', 0),
                    anomaly.get('description', ''),
                    anomaly.get('source_ip', '')
                ])
            writer.writerow([])
            
            # Anomalies DNS
            writer.writerow(['=== ANOMALIES DNS ==='])
            writer.writerow(['Type', 'Sévérité', 'Description', 'Recommandation'])
            dns_anomalies = results.get('dns_analysis', {}).get('anomalies', [])
            for anomaly in dns_anomalies:
                writer.writerow([
                    anomaly.get('type', ''),
                    anomaly.get('severity', ''),
                    anomaly.get('description', ''),
                    anomaly.get('recommendation', '')
                ])
            writer.writerow([])
            
            # Anomalies HTTP
            writer.writerow(['=== ANOMALIES HTTP ==='])
            writer.writerow(['Type', 'Sévérité', 'Description', 'Recommandation'])
            http_anomalies = results.get('http_analysis', {}).get('anomalies', [])
            for anomaly in http_anomalies:
                writer.writerow([
                    anomaly.get('type', ''),
                    anomaly.get('severity', ''),
                    anomaly.get('description', ''),
                    anomaly.get('recommendation', '')
                ])
            writer.writerow([])
            
            # Section Top IPs
            writer.writerow(['=== TOP IPS SOURCES ==='])
            writer.writerow(['IP', 'Paquets', 'Bytes'])
            top_sources = results.get('protocol_analysis', {}).get('ip_statistics', {}).get('top_sources', [])
            for ip_data in top_sources[:20]:
                writer.writerow([ip_data.get('ip', ''), ip_data.get('count', 0), ip_data.get('bytes', 0)])
        
        return output_path
    
    def _generate_summary_csv(self, results: Dict, path: Path):
        """Génère le CSV de résumé"""
        summary = results.get('protocol_analysis', {}).get('summary', {})
        tcp_summary = results.get('tcp_analysis', {}).get('summary', {})
        anomaly_summary = (results.get('anomaly_detection') or results.get('anomaly_analysis', {})).get('summary', {})
        
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Métrique', 'Valeur'])
            writer.writerow(['Total Paquets', summary.get('total_packets', 0)])
            writer.writerow(['Total Bytes', summary.get('total_bytes', 0)])
            writer.writerow(['Durée Capture (secondes)', summary.get('capture_duration_seconds', 0)])
            writer.writerow(['Paquets/Seconde', summary.get('packets_per_second', 0)])
            writer.writerow(['Bytes/Seconde', summary.get('bytes_per_second', 0)])
            writer.writerow(['Sessions TCP', tcp_summary.get('total_sessions', 0)])
            writer.writerow(['Retransmissions', tcp_summary.get('total_retransmissions', 0)])
            writer.writerow(['Anomalies Détectées', anomaly_summary.get('total_anomalies', 0)])
            writer.writerow(['Score de Risque', anomaly_summary.get('total_score', 0)])
            writer.writerow(['Niveau de Risque', anomaly_summary.get('risk_level', 'NONE')])
    
    def _generate_ip_csv(self, results: Dict, path: Path):
        """Génère le CSV des statistiques IP"""
        ip_stats = results.get('protocol_analysis', {}).get('ip_statistics', {})
        
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Type', 'IP', 'Paquets', 'Bytes'])
            
            for ip_data in ip_stats.get('top_sources', []):
                writer.writerow(['Source', ip_data['ip'], ip_data['count'], ip_data['bytes']])
            
            for ip_data in ip_stats.get('top_destinations', []):
                writer.writerow(['Destination', ip_data['ip'], ip_data['count'], ip_data['bytes']])
    
    def _generate_tcp_csv(self, results: Dict, path: Path):
        """Génère le CSV des sessions TCP"""
        sessions = results.get('tcp_analysis', {}).get('sessions', [])
        
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Source', 'Destination', 'État', 'Paquets', 'Bytes', 'Durée (s)', 'Retransmissions', 'RST'])
            
            for session in sessions:
                writer.writerow([
                    session.get('src', ''),
                    session.get('dst', ''),
                    session.get('state', ''),
                    session.get('packets', 0),
                    session.get('bytes', 0),
                    session.get('duration', 0),
                    session.get('retransmissions', 0),
                    session.get('rst_count', 0)
                ])
    
    def _generate_anomalies_csv(self, results: Dict, path: Path):
        """Génère le CSV des anomalies"""
        anomalies = (results.get('anomaly_detection') or results.get('anomaly_analysis', {})).get('anomalies', [])
        
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Type', 'Sévérité', 'Score', 'Description', 'IP Source', 'IP Destination'])
            
            for anomaly in anomalies:
                writer.writerow([
                    anomaly.get('type', ''),
                    anomaly.get('severity', ''),
                    anomaly.get('score', 0),
                    anomaly.get('description', ''),
                    anomaly.get('source_ip', ''),
                    anomaly.get('destination_ip', '')
                ])
    
    def _generate_ports_csv(self, results: Dict, path: Path):
        """Génère le CSV des statistiques de ports"""
        ports = results.get('protocol_analysis', {}).get('ports', {})
        
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Type', 'Port', 'Count', 'Service'])
            
            for port_data in ports.get('top_src_ports', []):
                writer.writerow(['Source', port_data['port'], port_data['count'], port_data.get('service', '')])
            
            for port_data in ports.get('top_dst_ports', []):
                writer.writerow(['Destination', port_data['port'], port_data['count'], port_data.get('service', '')])
