"""
Network Graph Service
Generates network topology graph data for vis-network visualization
Supports clustering, attack path highlighting, and filtering
"""

from typing import Dict, Any, List, Optional, Set, Tuple
from collections import defaultdict
from datetime import datetime
import hashlib

from app.core.logging_config import get_logger

logger = get_logger(__name__)


class GraphService:
    """Service for generating network graph data"""
    
    # Node colors by type
    NODE_COLORS = {
        "internal": "#3498db",
        "external": "#e74c3c",
        "server": "#2ecc71",
        "client": "#9b59b6",
        "dns_server": "#f39c12",
        "gateway": "#1abc9c",
        "attacker": "#c0392b",
        "victim": "#e67e22",
    }
    
    # Edge colors by protocol
    EDGE_COLORS = {
        "TCP": "#3498db",
        "UDP": "#2ecc71",
        "ICMP": "#95a5a6",
        "DNS": "#9b59b6",
        "HTTP": "#e67e22",
        "HTTPS": "#1abc9c",
        "SMB": "#f39c12",
        "LDAP": "#34495e",
        "Kerberos": "#8e44ad",
        "RDP": "#16a085",
        "SSH": "#27ae60",
    }
    
    def generate_network_graph(self, results: Dict[str, Any],
                               filters: Optional[Dict] = None) -> Dict[str, Any]:
        """Generate network graph from analysis results"""
        nodes: Dict[str, Dict] = {}
        edges: Dict[str, Dict] = {}
        
        # Process packets index
        packets_index = results.get("packets_index") or []
        self._process_packets_for_graph(packets_index, nodes, edges)
        
        # Process TCP sessions
        tcp_analysis = results.get("tcp_analysis") or {}
        self._process_tcp_sessions_for_graph(tcp_analysis.get("sessions") or [], nodes, edges)
        
        # Process DNS
        dns_analysis = results.get("dns_analysis") or {}
        self._process_dns_for_graph(dns_analysis, nodes, edges)
        
        # Process HTTP
        http_analysis = results.get("http_analysis") or {}
        self._process_http_for_graph(http_analysis, nodes, edges)
        
        # Process enterprise protocols
        self._process_enterprise_for_graph(results, nodes, edges)
        
        # Process anomalies to mark suspicious nodes
        self._mark_anomalous_nodes(results.get("anomaly_analysis") or {}, nodes)
        
        # Classify nodes
        self._classify_nodes(nodes, edges)
        
        # Apply filters
        if filters:
            nodes, edges = self._apply_filters(nodes, edges, filters)
        
        # Generate clusters
        clusters = self._generate_clusters(nodes, edges)
        
        # Detect attack paths
        attack_paths = self._detect_attack_paths(results, nodes, edges)
        
        # Convert to vis-network format
        vis_nodes = self._format_nodes_for_vis(nodes)
        vis_edges = self._format_edges_for_vis(edges)
        
        return {
            "nodes": vis_nodes,
            "edges": vis_edges,
            "clusters": clusters,
            "attack_paths": attack_paths,
            "statistics": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "internal_nodes": sum(1 for n in nodes.values() if n.get("is_private")),
                "external_nodes": sum(1 for n in nodes.values() if not n.get("is_private")),
            }
        }
    
    def _process_packets_for_graph(self, packets: List[Dict], 
                                   nodes: Dict, edges: Dict) -> None:
        """Process packets to build graph"""
        for pkt in packets:
            src_ip = pkt.get("src_ip")
            dst_ip = pkt.get("dst_ip")
            protocol = pkt.get("protocol", "Unknown")
            
            if not src_ip or not dst_ip:
                continue
            
            # Add nodes
            self._add_node(nodes, src_ip)
            self._add_node(nodes, dst_ip)
            
            # Add edge
            edge_key = f"{src_ip}:{dst_ip}"
            if edge_key not in edges:
                edges[edge_key] = {
                    "from": src_ip,
                    "to": dst_ip,
                    "protocols": set(),
                    "packet_count": 0,
                    "bytes": 0,
                    "ports": set(),
                }
            
            edges[edge_key]["protocols"].add(protocol)
            edges[edge_key]["packet_count"] += 1
            edges[edge_key]["bytes"] += pkt.get("length", 0)
            
            if pkt.get("dst_port"):
                edges[edge_key]["ports"].add(pkt["dst_port"])
    
    def _process_tcp_sessions_for_graph(self, sessions: List[Dict],
                                        nodes: Dict, edges: Dict) -> None:
        """Process TCP sessions for graph"""
        for session in sessions:
            src_ip = session.get("src_ip")
            dst_ip = session.get("dst_ip")
            
            if not src_ip or not dst_ip:
                continue
            
            self._add_node(nodes, src_ip)
            self._add_node(nodes, dst_ip)
            
            edge_key = f"{src_ip}:{dst_ip}"
            if edge_key not in edges:
                edges[edge_key] = {
                    "from": src_ip,
                    "to": dst_ip,
                    "protocols": set(),
                    "packet_count": 0,
                    "bytes": 0,
                    "ports": set(),
                }
            
            edges[edge_key]["protocols"].add("TCP")
            edges[edge_key]["packet_count"] += session.get("packet_count", 0)
            edges[edge_key]["bytes"] += session.get("bytes_sent", 0) + session.get("bytes_received", 0)
            
            if session.get("dst_port"):
                edges[edge_key]["ports"].add(session["dst_port"])
            
            # Update node connection counts
            nodes[src_ip]["outgoing_connections"] = nodes[src_ip].get("outgoing_connections", 0) + 1
            nodes[dst_ip]["incoming_connections"] = nodes[dst_ip].get("incoming_connections", 0) + 1
    
    def _process_dns_for_graph(self, dns_analysis: Dict, 
                               nodes: Dict, edges: Dict) -> None:
        """Process DNS data for graph"""
        for query in (dns_analysis.get("queries") or []):
            src_ip = query.get("src_ip")
            dns_server = query.get("dns_server", query.get("dst_ip"))
            
            if src_ip and dns_server:
                self._add_node(nodes, src_ip)
                self._add_node(nodes, dns_server)
                nodes[dns_server]["is_dns_server"] = True
                
                edge_key = f"{src_ip}:{dns_server}"
                if edge_key not in edges:
                    edges[edge_key] = {
                        "from": src_ip,
                        "to": dns_server,
                        "protocols": set(),
                        "packet_count": 0,
                        "bytes": 0,
                        "ports": {53},
                    }
                edges[edge_key]["protocols"].add("DNS")
                edges[edge_key]["packet_count"] += 1
    
    def _process_http_for_graph(self, http_analysis: Dict,
                                nodes: Dict, edges: Dict) -> None:
        """Process HTTP data for graph"""
        for request in (http_analysis.get("requests") or []):
            src_ip = request.get("src_ip")
            dst_ip = request.get("dst_ip")
            
            if src_ip and dst_ip:
                self._add_node(nodes, src_ip)
                self._add_node(nodes, dst_ip)
                nodes[dst_ip]["is_web_server"] = True
                
                edge_key = f"{src_ip}:{dst_ip}"
                if edge_key not in edges:
                    edges[edge_key] = {
                        "from": src_ip,
                        "to": dst_ip,
                        "protocols": set(),
                        "packet_count": 0,
                        "bytes": 0,
                        "ports": set(),
                    }
                
                is_https = request.get("is_https", False) or request.get("port") == 443
                edges[edge_key]["protocols"].add("HTTPS" if is_https else "HTTP")
                edges[edge_key]["packet_count"] += 1
                edges[edge_key]["ports"].add(request.get("port", 80))
    
    def _process_enterprise_for_graph(self, results: Dict,
                                      nodes: Dict, edges: Dict) -> None:
        """Process enterprise protocol data"""
        # SMB
        smb_analysis = results.get("smb_analysis") or {}
        for session in (smb_analysis.get("sessions") or []):
            src_ip = session.get("src_ip")
            dst_ip = session.get("dst_ip")
            if src_ip and dst_ip:
                self._add_node(nodes, src_ip)
                self._add_node(nodes, dst_ip)
                nodes[dst_ip]["is_file_server"] = True
                self._add_edge(edges, src_ip, dst_ip, "SMB", {445, 139})
        
        # LDAP
        ldap_analysis = results.get("ldap_analysis") or {}
        for session in (ldap_analysis.get("sessions") or []):
            src_ip = session.get("src_ip")
            dst_ip = session.get("dst_ip")
            if src_ip and dst_ip:
                self._add_node(nodes, src_ip)
                self._add_node(nodes, dst_ip)
                nodes[dst_ip]["is_domain_controller"] = True
                self._add_edge(edges, src_ip, dst_ip, "LDAP", {389, 636})
        
        # Kerberos
        kerberos_analysis = results.get("kerberos_analysis") or {}
        as_reqs = kerberos_analysis.get("as_requests") or []
        tgs_reqs = kerberos_analysis.get("tgs_requests") or []
        for req in as_reqs + tgs_reqs:
            src_ip = req.get("src_ip")
            dst_ip = req.get("dst_ip")
            if src_ip and dst_ip:
                self._add_node(nodes, src_ip)
                self._add_node(nodes, dst_ip)
                nodes[dst_ip]["is_kdc"] = True
                self._add_edge(edges, src_ip, dst_ip, "Kerberos", {88})
        
        # RDP
        rdp_analysis = results.get("rdp_analysis") or {}
        for conn in (rdp_analysis.get("connections") or []):
            src_ip = conn.get("client_ip")
            dst_ip = conn.get("server_ip")
            if src_ip and dst_ip:
                self._add_node(nodes, src_ip)
                self._add_node(nodes, dst_ip)
                nodes[dst_ip]["accepts_rdp"] = True
                self._add_edge(edges, src_ip, dst_ip, "RDP", {3389})
        
        # SSH
        ssh_analysis = results.get("ssh_analysis") or {}
        for conn in (ssh_analysis.get("connections") or []):
            src_ip = conn.get("client_ip")
            dst_ip = conn.get("server_ip")
            if src_ip and dst_ip:
                self._add_node(nodes, src_ip)
                self._add_node(nodes, dst_ip)
                nodes[dst_ip]["accepts_ssh"] = True
                self._add_edge(edges, src_ip, dst_ip, "SSH", {22})
    
    def _add_node(self, nodes: Dict, ip: str) -> None:
        """Add node if not exists"""
        if ip not in nodes:
            nodes[ip] = {
                "id": ip,
                "label": ip,
                "is_private": self._is_private_ip(ip),
                "incoming_connections": 0,
                "outgoing_connections": 0,
                "protocols": set(),
                "is_suspicious": False,
            }
    
    def _add_edge(self, edges: Dict, src: str, dst: str, 
                  protocol: str, ports: set) -> None:
        """Add or update edge"""
        edge_key = f"{src}:{dst}"
        if edge_key not in edges:
            edges[edge_key] = {
                "from": src,
                "to": dst,
                "protocols": set(),
                "packet_count": 0,
                "bytes": 0,
                "ports": set(),
            }
        edges[edge_key]["protocols"].add(protocol)
        edges[edge_key]["ports"].update(ports)
        edges[edge_key]["packet_count"] += 1
    
    def _mark_anomalous_nodes(self, anomaly_analysis: Dict, nodes: Dict) -> None:
        """Mark nodes involved in anomalies"""
        for anomaly in (anomaly_analysis.get("anomalies") or []):
            for ip_field in ["src_ip", "dst_ip", "source_ip", "target", "attacker_ip"]:
                ip = anomaly.get(ip_field)
                if ip and ip in nodes:
                    nodes[ip]["is_suspicious"] = True
                    nodes[ip]["anomaly_types"] = nodes[ip].get("anomaly_types", [])
                    nodes[ip]["anomaly_types"].append(anomaly.get("type"))
    
    def _classify_nodes(self, nodes: Dict, edges: Dict) -> None:
        """Classify nodes by role"""
        for ip, node in nodes.items():
            # Calculate degrees
            in_degree = sum(1 for e in edges.values() if e["to"] == ip)
            out_degree = sum(1 for e in edges.values() if e["from"] == ip)
            
            node["in_degree"] = in_degree
            node["out_degree"] = out_degree
            
            # Classify
            if node.get("is_suspicious"):
                if out_degree > in_degree * 2:
                    node["role"] = "attacker"
                else:
                    node["role"] = "victim"
            elif node.get("is_domain_controller") or node.get("is_kdc"):
                node["role"] = "domain_controller"
            elif node.get("is_dns_server"):
                node["role"] = "dns_server"
            elif node.get("is_file_server"):
                node["role"] = "file_server"
            elif node.get("is_web_server"):
                node["role"] = "web_server"
            elif in_degree > out_degree * 3:
                node["role"] = "server"
            elif out_degree > in_degree * 3:
                node["role"] = "client"
            elif node.get("is_private"):
                node["role"] = "internal"
            else:
                node["role"] = "external"
    
    def _apply_filters(self, nodes: Dict, edges: Dict, 
                       filters: Dict) -> Tuple[Dict, Dict]:
        """Apply filters to graph"""
        filtered_nodes = nodes.copy()
        filtered_edges = edges.copy()
        
        # Filter by protocol
        if filters.get("protocols"):
            protocols = set(filters["protocols"])
            filtered_edges = {
                k: v for k, v in filtered_edges.items()
                if v["protocols"] & protocols
            }
        
        # Filter by IP subnet
        if filters.get("subnet"):
            import ipaddress
            subnet = ipaddress.ip_network(filters["subnet"], strict=False)
            filtered_nodes = {
                k: v for k, v in filtered_nodes.items()
                if ipaddress.ip_address(k) in subnet
            }
        
        # Filter by role
        if filters.get("roles"):
            roles = set(filters["roles"])
            filtered_nodes = {
                k: v for k, v in filtered_nodes.items()
                if v.get("role") in roles
            }
        
        # Remove edges without matching nodes
        valid_ips = set(filtered_nodes.keys())
        filtered_edges = {
            k: v for k, v in filtered_edges.items()
            if v["from"] in valid_ips and v["to"] in valid_ips
        }
        
        return filtered_nodes, filtered_edges
    
    def _generate_clusters(self, nodes: Dict, edges: Dict) -> List[Dict]:
        """Generate clusters based on connectivity"""
        clusters = []
        
        # Group by subnet
        subnet_groups = defaultdict(list)
        for ip, node in nodes.items():
            if node.get("is_private"):
                # Extract /24 subnet
                parts = ip.split(".")
                if len(parts) == 4:
                    subnet = ".".join(parts[:3]) + ".0/24"
                    subnet_groups[subnet].append(ip)
        
        for subnet, ips in subnet_groups.items():
            if len(ips) >= 3:
                clusters.append({
                    "id": f"cluster_{subnet.replace('/', '_')}",
                    "label": subnet,
                    "nodes": ips,
                    "type": "subnet",
                })
        
        # Group servers
        server_ips = [ip for ip, n in nodes.items() if n.get("role") in ["server", "web_server", "dns_server", "file_server"]]
        if len(server_ips) >= 2:
            clusters.append({
                "id": "cluster_servers",
                "label": "Servers",
                "nodes": server_ips,
                "type": "role",
            })
        
        return clusters
    
    def _detect_attack_paths(self, results: Dict, nodes: Dict, 
                            edges: Dict) -> List[Dict]:
        """Detect and highlight attack paths"""
        attack_paths = []
        
        # Find suspicious nodes
        suspicious_sources = [ip for ip, n in nodes.items() if n.get("role") == "attacker"]
        suspicious_targets = [ip for ip, n in nodes.items() if n.get("role") == "victim"]
        
        # Simple path detection: source -> intermediate -> target
        for source in suspicious_sources:
            # Get nodes this source connects to
            first_hops = set()
            for edge_key, edge in edges.items():
                if edge["from"] == source:
                    first_hops.add(edge["to"])
            
            # Check if any first hop connects to targets
            for hop in first_hops:
                for target in suspicious_targets:
                    edge_key = f"{hop}:{target}"
                    if edge_key in edges and hop != source:
                        attack_paths.append({
                            "id": f"path_{source}_{target}",
                            "source": source,
                            "target": target,
                            "hops": [source, hop, target],
                            "type": "lateral_movement",
                        })
        
        # Direct attacks
        for source in suspicious_sources:
            for target in suspicious_targets:
                edge_key = f"{source}:{target}"
                if edge_key in edges:
                    attack_paths.append({
                        "id": f"path_direct_{source}_{target}",
                        "source": source,
                        "target": target,
                        "hops": [source, target],
                        "type": "direct",
                    })
        
        return attack_paths[:20]  # Limit
    
    def _format_nodes_for_vis(self, nodes: Dict) -> List[Dict]:
        """Format nodes for vis-network"""
        vis_nodes = []
        
        for ip, node in nodes.items():
            role = node.get("role", "internal")
            color = self.NODE_COLORS.get(role, "#7f8c8d")
            
            # Size based on connectivity
            size = 15 + min(node.get("in_degree", 0) + node.get("out_degree", 0), 50)
            
            # Shape based on role
            shape = "dot"
            if role in ["server", "web_server", "dns_server", "file_server", "domain_controller"]:
                shape = "diamond"
            elif role == "attacker":
                shape = "triangle"
            elif role == "victim":
                shape = "star"
            
            vis_node = {
                "id": ip,
                "label": ip,
                "color": {
                    "background": color,
                    "border": "#2c3e50" if not node.get("is_suspicious") else "#e74c3c",
                    "highlight": {"background": "#f1c40f", "border": "#f39c12"}
                },
                "size": size,
                "shape": shape,
                "borderWidth": 3 if node.get("is_suspicious") else 1,
                "title": self._format_node_tooltip(node),
                "data": {
                    "role": role,
                    "is_private": node.get("is_private"),
                    "is_suspicious": node.get("is_suspicious"),
                    "in_degree": node.get("in_degree", 0),
                    "out_degree": node.get("out_degree", 0),
                }
            }
            
            vis_nodes.append(vis_node)
        
        return vis_nodes
    
    def _format_edges_for_vis(self, edges: Dict) -> List[Dict]:
        """Format edges for vis-network"""
        vis_edges = []
        
        for edge_key, edge in edges.items():
            # Determine primary protocol for color
            protocols = edge.get("protocols", set())
            if "Kerberos" in protocols:
                color = self.EDGE_COLORS["Kerberos"]
            elif "LDAP" in protocols:
                color = self.EDGE_COLORS["LDAP"]
            elif "SMB" in protocols:
                color = self.EDGE_COLORS["SMB"]
            elif "RDP" in protocols:
                color = self.EDGE_COLORS["RDP"]
            elif "SSH" in protocols:
                color = self.EDGE_COLORS["SSH"]
            elif "DNS" in protocols:
                color = self.EDGE_COLORS["DNS"]
            elif "HTTPS" in protocols:
                color = self.EDGE_COLORS["HTTPS"]
            elif "HTTP" in protocols:
                color = self.EDGE_COLORS["HTTP"]
            elif "TCP" in protocols:
                color = self.EDGE_COLORS["TCP"]
            elif "UDP" in protocols:
                color = self.EDGE_COLORS["UDP"]
            else:
                color = "#95a5a6"
            
            # Width based on packet count (log scale)
            import math
            width = 1 + min(math.log10(max(edge.get("packet_count", 1), 1)) * 2, 10)
            
            vis_edge = {
                "id": edge_key,
                "from": edge["from"],
                "to": edge["to"],
                "color": {"color": color, "highlight": "#f1c40f"},
                "width": width,
                "arrows": "to",
                "smooth": {"type": "curvedCW", "roundness": 0.2},
                "title": self._format_edge_tooltip(edge),
                "data": {
                    "protocols": list(protocols),
                    "packet_count": edge.get("packet_count", 0),
                    "bytes": edge.get("bytes", 0),
                    "ports": list(edge.get("ports", set())),
                }
            }
            
            vis_edges.append(vis_edge)
        
        return vis_edges
    
    def _format_node_tooltip(self, node: Dict) -> str:
        """Format node tooltip"""
        lines = [
            f"IP: {node.get('id')}",
            f"Role: {node.get('role', 'unknown')}",
            f"Incoming: {node.get('in_degree', 0)}",
            f"Outgoing: {node.get('out_degree', 0)}",
        ]
        
        if node.get("is_suspicious"):
            lines.append("⚠️ Suspicious activity detected")
            if node.get("anomaly_types"):
                lines.append(f"Anomalies: {', '.join(set(node['anomaly_types'][:3]))}")
        
        return "\n".join(lines)
    
    def _format_edge_tooltip(self, edge: Dict) -> str:
        """Format edge tooltip"""
        protocols = ", ".join(edge.get("protocols", []))
        ports = ", ".join(str(p) for p in sorted(edge.get("ports", set()))[:5])
        
        return (f"From: {edge['from']}\n"
                f"To: {edge['to']}\n"
                f"Protocols: {protocols}\n"
                f"Ports: {ports}\n"
                f"Packets: {edge.get('packet_count', 0)}\n"
                f"Bytes: {edge.get('bytes', 0)}")
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback
        except:
            return False


# Singleton instance
_graph_service = None

def get_graph_service() -> GraphService:
    """Get singleton graph service instance"""
    global _graph_service
    if _graph_service is None:
        _graph_service = GraphService()
    return _graph_service
