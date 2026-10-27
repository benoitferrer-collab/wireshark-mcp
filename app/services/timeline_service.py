"""
Timeline Service
Generates timeline data for vis-timeline visualization
Supports event correlation, filtering, and playback
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import defaultdict

from app.core.logging_config import get_logger

logger = get_logger(__name__)


class TimelineService:
    """Service for generating interactive timeline data"""
    
    # Event types with colors for visualization
    EVENT_TYPES = {
        "tcp_session": {"color": "#3498db", "group": "TCP"},
        "udp_session": {"color": "#2ecc71", "group": "UDP"},
        "dns_query": {"color": "#9b59b6", "group": "DNS"},
        "http_request": {"color": "#e67e22", "group": "HTTP"},
        "tls_handshake": {"color": "#1abc9c", "group": "TLS"},
        "anomaly": {"color": "#e74c3c", "group": "Anomalies"},
        "smb_session": {"color": "#f39c12", "group": "SMB"},
        "ldap_query": {"color": "#34495e", "group": "LDAP"},
        "kerberos": {"color": "#8e44ad", "group": "Kerberos"},
        "rdp_session": {"color": "#16a085", "group": "RDP"},
        "ssh_session": {"color": "#27ae60", "group": "SSH"},
    }
    
    def generate_timeline(self, results: Dict[str, Any], 
                         filters: Optional[Dict] = None) -> Dict[str, Any]:
        """Generate timeline data from analysis results"""
        events = []
        groups = []
        
        # Track groups
        used_groups = set()
        
        # Parse packets index for basic timeline
        packets_index = results.get("packets_index") or []
        if packets_index:
            events.extend(self._process_packets(packets_index, used_groups))
        
        # Process TCP sessions
        tcp_analysis = results.get("tcp_analysis") or {}
        sessions = tcp_analysis.get("sessions") or []
        if sessions:
            events.extend(self._process_tcp_sessions(sessions, used_groups))
        
        # Process DNS queries
        dns_analysis = results.get("dns_analysis") or {}
        queries = dns_analysis.get("queries") or []
        if queries:
            events.extend(self._process_dns_queries(queries, used_groups))
        
        # Process HTTP requests
        http_analysis = results.get("http_analysis") or {}
        requests = http_analysis.get("requests") or []
        if requests:
            events.extend(self._process_http_requests(requests, used_groups))
        
        # Process TLS sessions
        tls_sessions = http_analysis.get("tls_sessions") or []
        if tls_sessions:
            events.extend(self._process_tls_sessions(tls_sessions, used_groups))
        
        # Process anomalies
        anomaly_analysis = results.get("anomaly_analysis") or {}
        anomalies = anomaly_analysis.get("anomalies") or []
        if anomalies:
            events.extend(self._process_anomalies(anomalies, used_groups))
        
        # Process enterprise protocols
        events.extend(self._process_enterprise_protocols(results, used_groups))
        
        # Apply filters if provided
        if filters:
            events = self._apply_filters(events, filters)
        
        # Generate groups for vis-timeline
        for group_id in used_groups:
            groups.append({
                "id": group_id,
                "content": group_id,
                "style": f"color: white; background-color: {self._get_group_color(group_id)}"
            })
        
        # Sort events by start time (handle both numeric and string timestamps)
        def get_sort_key(x):
            start = x.get("start", 0)
            if isinstance(start, (int, float)):
                return start
            if isinstance(start, str) and start:
                try:
                    return float(start)
                except ValueError:
                    return 0
            return 0
        events.sort(key=get_sort_key)
        
        # Calculate time range
        time_range = self._calculate_time_range(events)
        
        return {
            "events": events[:5000],  # Limit for performance
            "groups": groups,
            "time_range": time_range,
            "total_events": len(events),
            "event_counts": self._count_events_by_type(events),
        }
    
    def _process_packets(self, packets: List[Dict], used_groups: set) -> List[Dict]:
        """Process packet index into timeline events"""
        events = []
        # Sample packets for overview (every nth packet)
        sample_rate = max(1, len(packets) // 1000)
        
        for i, pkt in enumerate(packets[::sample_rate]):
            if not pkt.get("timestamp"):
                continue
            
            protocol = pkt.get("protocol", "Unknown")
            group = protocol if protocol in ["TCP", "UDP", "ICMP", "DNS", "HTTP"] else "Other"
            used_groups.add(group)
            
            events.append({
                "id": f"pkt_{pkt.get('idx', i)}",
                "content": f"{protocol}: {pkt.get('src_ip', '?')} → {pkt.get('dst_ip', '?')}",
                "start": pkt["timestamp"],
                "group": group,
                "type": "point",
                "className": f"event-{protocol.lower()}",
                "title": self._format_packet_tooltip(pkt),
                "data": {
                    "type": "packet",
                    "idx": pkt.get("idx"),
                    "protocol": protocol,
                    "src_ip": pkt.get("src_ip"),
                    "dst_ip": pkt.get("dst_ip"),
                }
            })
        
        return events
    
    def _process_tcp_sessions(self, sessions: List[Dict], used_groups: set) -> List[Dict]:
        """Process TCP sessions into timeline events"""
        events = []
        used_groups.add("TCP")
        
        for i, session in enumerate(sessions[:500]):
            start = session.get("start_time") or session.get("first_seen")
            end = session.get("end_time") or session.get("last_seen")
            
            if not start:
                continue
            
            session_id = session.get("session_id", f"tcp_{i}")
            src = session.get("src_ip", "?")
            dst = session.get("dst_ip", "?")
            src_port = session.get("src_port", "?")
            dst_port = session.get("dst_port", "?")
            
            event = {
                "id": f"tcp_{session_id}",
                "content": f"{src}:{src_port} → {dst}:{dst_port}",
                "start": start,
                "group": "TCP",
                "className": "event-tcp-session",
                "title": self._format_session_tooltip(session),
                "data": {
                    "type": "tcp_session",
                    "session_id": session_id,
                }
            }
            
            if end and end != start:
                event["end"] = end
                event["type"] = "range"
            else:
                event["type"] = "point"
            
            events.append(event)
        
        return events
    
    def _process_dns_queries(self, queries: List[Dict], used_groups: set) -> List[Dict]:
        """Process DNS queries into timeline events"""
        events = []
        used_groups.add("DNS")
        
        for i, query in enumerate(queries[:500]):
            timestamp = query.get("timestamp")
            if not timestamp:
                continue
            
            domain = query.get("domain", query.get("query_name", "?"))
            query_type = query.get("type", query.get("query_type", "?"))
            
            events.append({
                "id": f"dns_{i}",
                "content": f"DNS {query_type}: {domain[:30]}",
                "start": timestamp,
                "group": "DNS",
                "type": "point",
                "className": "event-dns",
                "title": f"Query: {domain}\nType: {query_type}\nServer: {query.get('dns_server', '?')}",
                "data": {
                    "type": "dns_query",
                    "domain": domain,
                    "query_type": query_type,
                }
            })
        
        return events
    
    def _process_http_requests(self, requests: List[Dict], used_groups: set) -> List[Dict]:
        """Process HTTP requests into timeline events"""
        events = []
        used_groups.add("HTTP")
        
        for i, req in enumerate(requests[:500]):
            timestamp = req.get("timestamp")
            if not timestamp:
                continue
            
            method = req.get("method", "?")
            host = req.get("host", "?")
            path = req.get("path", "/")[:30]
            
            events.append({
                "id": f"http_{i}",
                "content": f"{method} {host}{path}",
                "start": timestamp,
                "group": "HTTP",
                "type": "point",
                "className": f"event-http event-http-{method.lower()}",
                "title": f"Method: {method}\nHost: {host}\nPath: {req.get('path', '/')}\nStatus: {req.get('status_code', 'N/A')}",
                "data": {
                    "type": "http_request",
                    "method": method,
                    "host": host,
                    "path": req.get("path"),
                }
            })
        
        return events
    
    def _process_tls_sessions(self, sessions: List[Dict], used_groups: set) -> List[Dict]:
        """Process TLS sessions into timeline events"""
        events = []
        used_groups.add("TLS")
        
        for i, session in enumerate(sessions[:200]):
            timestamp = session.get("timestamp")
            if not timestamp:
                continue
            
            sni = session.get("sni", session.get("server_name", "?"))
            version = session.get("version", session.get("tls_version", "?"))
            
            events.append({
                "id": f"tls_{i}",
                "content": f"TLS {version}: {sni[:30]}",
                "start": timestamp,
                "group": "TLS",
                "type": "point",
                "className": "event-tls",
                "title": f"SNI: {sni}\nVersion: {version}",
                "data": {
                    "type": "tls_handshake",
                    "sni": sni,
                    "version": version,
                }
            })
        
        return events
    
    def _process_anomalies(self, anomalies: List[Dict], used_groups: set) -> List[Dict]:
        """Process anomalies into timeline events"""
        events = []
        used_groups.add("Anomalies")
        
        for i, anomaly in enumerate(anomalies[:200]):
            timestamp = anomaly.get("timestamp") or anomaly.get("first_seen")
            if not timestamp:
                continue
            
            anomaly_type = anomaly.get("type", "Unknown")
            severity = anomaly.get("severity", "medium")
            
            events.append({
                "id": f"anomaly_{i}",
                "content": f"⚠️ {anomaly_type}",
                "start": timestamp,
                "group": "Anomalies",
                "type": "point",
                "className": f"event-anomaly event-severity-{severity}",
                "title": f"Type: {anomaly_type}\nSeverity: {severity}\n{anomaly.get('description', '')}",
                "data": {
                    "type": "anomaly",
                    "anomaly_type": anomaly_type,
                    "severity": severity,
                }
            })
        
        return events
    
    def _process_enterprise_protocols(self, results: Dict, used_groups: set) -> List[Dict]:
        """Process enterprise protocol events"""
        events = []
        
        # SMB
        smb_analysis = results.get("smb_analysis") or {}
        for i, session in enumerate((smb_analysis.get("sessions") or [])[:100]):
            timestamp = session.get("first_seen")
            if timestamp:
                used_groups.add("SMB")
                events.append({
                    "id": f"smb_{i}",
                    "content": f"SMB: {session.get('src_ip')} → {session.get('dst_ip')}",
                    "start": timestamp,
                    "end": session.get("last_seen"),
                    "group": "SMB",
                    "type": "range" if session.get("last_seen") != timestamp else "point",
                    "className": "event-smb",
                    "data": {"type": "smb_session"}
                })
        
        # LDAP
        ldap_analysis = results.get("ldap_analysis") or {}
        for i, query in enumerate((ldap_analysis.get("search_queries") or [])[:100]):
            timestamp = query.get("timestamp")
            if timestamp:
                used_groups.add("LDAP")
                events.append({
                    "id": f"ldap_{i}",
                    "content": f"LDAP: {query.get('base_dn', '?')[:30]}",
                    "start": timestamp,
                    "group": "LDAP",
                    "type": "point",
                    "className": "event-ldap",
                    "data": {"type": "ldap_query"}
                })
        
        # Kerberos
        kerberos_analysis = results.get("kerberos_analysis") or {}
        for i, req in enumerate((kerberos_analysis.get("as_requests") or [])[:100]):
            timestamp = req.get("timestamp")
            if timestamp:
                used_groups.add("Kerberos")
                events.append({
                    "id": f"krb_as_{i}",
                    "content": f"AS-REQ: {req.get('client_principal', '?')[:30]}",
                    "start": timestamp,
                    "group": "Kerberos",
                    "type": "point",
                    "className": "event-kerberos",
                    "data": {"type": "kerberos", "subtype": "as_req"}
                })
        
        for i, req in enumerate((kerberos_analysis.get("tgs_requests") or [])[:100]):
            timestamp = req.get("timestamp")
            if timestamp:
                used_groups.add("Kerberos")
                events.append({
                    "id": f"krb_tgs_{i}",
                    "content": f"TGS-REQ: {req.get('service_principal', '?')[:30]}",
                    "start": timestamp,
                    "group": "Kerberos",
                    "type": "point",
                    "className": "event-kerberos",
                    "data": {"type": "kerberos", "subtype": "tgs_req"}
                })
        
        # RDP
        rdp_analysis = results.get("rdp_analysis") or {}
        for i, conn in enumerate((rdp_analysis.get("connections") or [])[:100]):
            timestamp = conn.get("first_seen")
            if timestamp:
                used_groups.add("RDP")
                events.append({
                    "id": f"rdp_{i}",
                    "content": f"RDP: {conn.get('client_ip')} → {conn.get('server_ip')}",
                    "start": timestamp,
                    "end": conn.get("last_seen"),
                    "group": "RDP",
                    "type": "range" if conn.get("last_seen") != timestamp else "point",
                    "className": "event-rdp",
                    "data": {"type": "rdp_session"}
                })
        
        # SSH
        ssh_analysis = results.get("ssh_analysis") or {}
        for i, session in enumerate((ssh_analysis.get("sessions") or [])[:100]):
            timestamp = session.get("first_seen")
            if timestamp:
                used_groups.add("SSH")
                events.append({
                    "id": f"ssh_{i}",
                    "content": f"SSH: {session.get('client_ip')} → {session.get('server_ip')}",
                    "start": timestamp,
                    "end": session.get("last_seen"),
                    "group": "SSH",
                    "type": "range" if session.get("last_seen") != timestamp else "point",
                    "className": "event-ssh",
                    "data": {"type": "ssh_session"}
                })
        
        return events
    
    def _apply_filters(self, events: List[Dict], filters: Dict) -> List[Dict]:
        """Apply filters to events"""
        filtered = events
        
        # Filter by event type
        if filters.get("types"):
            types = set(filters["types"])
            filtered = [e for e in filtered if e.get("data", {}).get("type") in types]
        
        # Filter by group
        if filters.get("groups"):
            groups = set(filters["groups"])
            filtered = [e for e in filtered if e.get("group") in groups]
        
        # Filter by IP
        if filters.get("ip"):
            ip = filters["ip"]
            filtered = [e for e in filtered if 
                       ip in str(e.get("data", {}).get("src_ip", "")) or
                       ip in str(e.get("data", {}).get("dst_ip", "")) or
                       ip in e.get("content", "")]
        
        # Filter by time range
        if filters.get("start_time"):
            filtered = [e for e in filtered if e.get("start", "") >= filters["start_time"]]
        if filters.get("end_time"):
            filtered = [e for e in filtered if e.get("start", "") <= filters["end_time"]]
        
        return filtered
    
    def _calculate_time_range(self, events: List[Dict]) -> Dict[str, Any]:
        """Calculate time range of events"""
        if not events:
            return {"start": None, "end": None}
        
        def to_numeric(val):
            """Convert to numeric timestamp"""
            if isinstance(val, (int, float)):
                return val
            if isinstance(val, str):
                try:
                    return float(val)
                except ValueError:
                    return None
            return None
        
        starts = [to_numeric(e.get("start")) for e in events]
        starts = [s for s in starts if s is not None]
        
        ends = [to_numeric(e.get("end") or e.get("start")) for e in events]
        ends = [e for e in ends if e is not None]
        
        return {
            "start": min(starts) if starts else None,
            "end": max(ends) if ends else None,
        }
    
    def _count_events_by_type(self, events: List[Dict]) -> Dict[str, int]:
        """Count events by type"""
        counts = defaultdict(int)
        for event in events:
            event_type = event.get("data", {}).get("type", "unknown")
            counts[event_type] += 1
        return dict(counts)
    
    def _get_group_color(self, group: str) -> str:
        """Get color for group"""
        colors = {
            "TCP": "#3498db",
            "UDP": "#2ecc71",
            "ICMP": "#95a5a6",
            "DNS": "#9b59b6",
            "HTTP": "#e67e22",
            "TLS": "#1abc9c",
            "Anomalies": "#e74c3c",
            "SMB": "#f39c12",
            "LDAP": "#34495e",
            "Kerberos": "#8e44ad",
            "RDP": "#16a085",
            "SSH": "#27ae60",
            "Other": "#7f8c8d",
        }
        return colors.get(group, "#7f8c8d")
    
    def _format_packet_tooltip(self, pkt: Dict) -> str:
        """Format packet tooltip"""
        return (f"Protocol: {pkt.get('protocol', '?')}\n"
                f"Source: {pkt.get('src_ip', '?')}:{pkt.get('src_port', '?')}\n"
                f"Destination: {pkt.get('dst_ip', '?')}:{pkt.get('dst_port', '?')}\n"
                f"Length: {pkt.get('length', '?')} bytes")
    
    def _format_session_tooltip(self, session: Dict) -> str:
        """Format session tooltip"""
        return (f"Source: {session.get('src_ip', '?')}:{session.get('src_port', '?')}\n"
                f"Destination: {session.get('dst_ip', '?')}:{session.get('dst_port', '?')}\n"
                f"Packets: {session.get('packet_count', '?')}\n"
                f"State: {session.get('state', '?')}")


# Singleton instance
_timeline_service = None

def get_timeline_service() -> TimelineService:
    """Get singleton timeline service instance"""
    global _timeline_service
    if _timeline_service is None:
        _timeline_service = TimelineService()
    return _timeline_service
