"""
Stream Reconstruction Service
Reconstructs TCP streams and HTTP sessions for analysis
Supports export and syntax highlighting
"""

from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
from datetime import datetime
from pathlib import Path
import re
import html
import gzip
import zlib

from scapy.all import rdpcap, TCP, Raw, IP, IPv6

from app.core.logging_config import get_logger
from app.core.config import get_settings

logger = get_logger(__name__)
settings = get_settings()

# Regex compilées une seule fois (hot path du parsing HTTP)
_HTTP_REQUEST_PATTERN = re.compile(
    r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+HTTP/(\d\.\d)'
)
_HTTP_RESPONSE_PATTERN = re.compile(r'HTTP/(\d\.\d)\s+(\d{3})\s+([^\r\n]*)')


class StreamService:
    """Service for reconstructing TCP streams and HTTP sessions"""
    
    # Content types that can be displayed as text
    TEXT_CONTENT_TYPES = [
        'text/', 'application/json', 'application/xml', 'application/javascript',
        'application/x-www-form-urlencoded', 'application/xhtml+xml',
    ]
    
    # Max size for content display (5MB)
    MAX_DISPLAY_SIZE = 5 * 1024 * 1024
    
    # Nombre max de streams reconstruits gardés en cache (jusqu'à ~5MB chacun)
    MAX_CACHE_ENTRIES = 16

    def __init__(self):
        from collections import OrderedDict
        self.streams_cache: "OrderedDict[str, Dict]" = OrderedDict()

    def _cache_get(self, key: str) -> Optional[Dict]:
        cached = self.streams_cache.get(key)
        if cached is not None:
            self.streams_cache.move_to_end(key)
        return cached

    def _cache_put(self, key: str, value: Dict):
        self.streams_cache[key] = value
        self.streams_cache.move_to_end(key)
        while len(self.streams_cache) > self.MAX_CACHE_ENTRIES:
            self.streams_cache.popitem(last=False)
    
    def reconstruct_tcp_stream(self, pcap_path: Path, stream_id: str,
                               results: Dict = None) -> Dict[str, Any]:
        """Reconstruct a complete TCP stream"""
        try:
            # Parse stream_id format: "src_ip:src_port:dst_ip:dst_port"
            parts = stream_id.split(":")
            if len(parts) != 4:
                return {"error": "Invalid stream_id format"}
            
            src_ip, src_port, dst_ip, dst_port = parts
            src_port, dst_port = int(src_port), int(dst_port)
            
            # Check cache
            cache_key = f"{pcap_path}:{stream_id}"
            cached = self._cache_get(cache_key)
            if cached is not None:
                return cached

            # Lecture en streaming: on ne garde que les paquets du stream ciblé
            from scapy.all import PcapReader

            stream_packets = []
            with PcapReader(str(pcap_path)) as reader:
                for idx, pkt in enumerate(reader):
                    if not pkt.haslayer(TCP):
                        continue

                    pkt_src_ip, pkt_dst_ip = self._get_ip_pair(pkt)
                    if not pkt_src_ip:
                        continue

                    tcp = pkt[TCP]
                    pkt_src_port, pkt_dst_port = tcp.sport, tcp.dport

                    # Match in either direction
                    if ((pkt_src_ip == src_ip and pkt_dst_ip == dst_ip and
                         pkt_src_port == src_port and pkt_dst_port == dst_port) or
                        (pkt_src_ip == dst_ip and pkt_dst_ip == src_ip and
                         pkt_src_port == dst_port and pkt_dst_port == src_port)):

                        stream_packets.append({
                            "idx": idx,
                            "timestamp": float(pkt.time),
                            "src_ip": pkt_src_ip,
                            "dst_ip": pkt_dst_ip,
                            "src_port": pkt_src_port,
                            "dst_port": pkt_dst_port,
                            "seq": tcp.seq,
                            "ack": tcp.ack,
                            "flags": str(tcp.flags),
                            "payload": bytes(tcp.payload) if tcp.payload else b'',
                            "direction": "client" if pkt_src_ip == src_ip else "server",
                        })
            
            # Sort by sequence number and timestamp
            stream_packets.sort(key=lambda x: (x["timestamp"], x["seq"]))
            
            # Reconstruct data flows
            client_data = self._reassemble_data(
                [p for p in stream_packets if p["direction"] == "client"]
            )
            server_data = self._reassemble_data(
                [p for p in stream_packets if p["direction"] == "server"]
            )
            
            result = {
                "stream_id": stream_id,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "packet_count": len(stream_packets),
                "duration": self._calculate_duration(stream_packets),
                "first_seen": datetime.fromtimestamp(stream_packets[0]["timestamp"]).isoformat() if stream_packets else None,
                "last_seen": datetime.fromtimestamp(stream_packets[-1]["timestamp"]).isoformat() if stream_packets else None,
                "client_bytes": len(client_data),
                "server_bytes": len(server_data),
                "client_data": self._format_data_display(client_data, "client"),
                "server_data": self._format_data_display(server_data, "server"),
                "conversation": self._format_conversation(stream_packets),
                "packets": [self._format_packet_info(p) for p in stream_packets[:500]],
            }
            
            # Cache result (LRU borné)
            self._cache_put(cache_key, result)
            return result
            
        except Exception as e:
            logger.error(f"Error reconstructing TCP stream: {e}")
            return {"error": str(e)}
    
    def reconstruct_http_session(self, pcap_path: Path, session_id: str,
                                 results: Dict = None) -> Dict[str, Any]:
        """Reconstruct HTTP session with request/response pairs"""
        try:
            # First reconstruct the TCP stream
            tcp_stream = self.reconstruct_tcp_stream(pcap_path, session_id, results)
            
            if tcp_stream.get("error"):
                return tcp_stream
            
            # Parse HTTP from stream data
            client_data = self._get_raw_data(tcp_stream, "client")
            server_data = self._get_raw_data(tcp_stream, "server")
            
            # Parse HTTP requests
            requests = self._parse_http_requests(client_data)
            responses = self._parse_http_responses(server_data)
            
            # Match requests with responses
            pairs = self._match_http_pairs(requests, responses)
            
            result = {
                "session_id": session_id,
                "src_ip": tcp_stream.get("src_ip"),
                "dst_ip": tcp_stream.get("dst_ip"),
                "src_port": tcp_stream.get("src_port"),
                "dst_port": tcp_stream.get("dst_port"),
                "first_seen": tcp_stream.get("first_seen"),
                "last_seen": tcp_stream.get("last_seen"),
                "request_count": len(requests),
                "response_count": len(responses),
                "pairs": pairs,
                "requests": requests[:50],
                "responses": responses[:50],
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error reconstructing HTTP session: {e}")
            return {"error": str(e)}
    
    def get_stream_list(self, results: Dict[str, Any]) -> List[Dict]:
        """Get list of TCP streams from results"""
        streams = []
        
        tcp_analysis = results.get("tcp_analysis", {})
        for session in tcp_analysis.get("sessions", []):
            src = session.get("src", "")
            dst = session.get("dst", "")
            if ":" not in src or ":" not in dst:
                continue

            src_ip, src_port_raw = src.rsplit(":", 1)
            dst_ip, dst_port_raw = dst.rsplit(":", 1)

            try:
                src_port = int(src_port_raw)
                dst_port = int(dst_port_raw)
            except ValueError:
                continue

            stream_id = f"{src_ip}:{src_port}:{dst_ip}:{dst_port}"
            
            streams.append({
                "stream_id": stream_id,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "packet_count": session.get("packet_count", session.get("packets", 0)),
                "state": session.get("state"),
                "first_seen": session.get("start_time") or session.get("first_seen"),
                "is_http": dst_port in [80, 8080, 8000, 8888] or src_port in [80, 8080, 8000, 8888],
                "is_https": dst_port == 443 or src_port == 443,
            })
        
        return streams[:200]
    
    def export_stream(self, pcap_path: Path, stream_id: str, 
                      format: str = "text") -> Tuple[bytes, str]:
        """Export stream data in various formats"""
        stream = self.reconstruct_tcp_stream(pcap_path, stream_id)
        
        if stream.get("error"):
            return b"Error: " + stream["error"].encode(), "text/plain"
        
        if format == "text":
            return self._export_as_text(stream), "text/plain"
        elif format == "html":
            return self._export_as_html(stream), "text/html"
        elif format == "raw":
            return self._export_as_raw(stream), "application/octet-stream"
        else:
            return self._export_as_text(stream), "text/plain"
    
    def _get_ip_pair(self, packet) -> Tuple[Optional[str], Optional[str]]:
        """Extract IP pair from packet"""
        if packet.haslayer(IP):
            return packet[IP].src, packet[IP].dst
        elif packet.haslayer(IPv6):
            return packet[IPv6].src, packet[IPv6].dst
        return None, None
    
    def _reassemble_data(self, packets: List[Dict]) -> bytes:
        """Reassemble data from packets handling sequence numbers"""
        if not packets:
            return b''
        
        # Simple reassembly - sort by seq and concatenate
        # For production, would need proper TCP reassembly with gap handling
        data_parts = []
        seen_seqs = set()
        
        for pkt in sorted(packets, key=lambda x: x["seq"]):
            payload = pkt.get("payload", b'')
            if payload and pkt["seq"] not in seen_seqs:
                data_parts.append(payload)
                seen_seqs.add(pkt["seq"])
        
        return b''.join(data_parts)
    
    def _calculate_duration(self, packets: List[Dict]) -> float:
        """Calculate stream duration in seconds"""
        if not packets or len(packets) < 2:
            return 0.0
        
        timestamps = [p["timestamp"] for p in packets]
        return max(timestamps) - min(timestamps)
    
    def _format_data_display(self, data: bytes, direction: str) -> Dict[str, Any]:
        """Format data for display with syntax highlighting hints"""
        if not data:
            return {"raw": "", "hex": "", "is_binary": False, "size": 0}
        
        # Limit size
        truncated = len(data) > self.MAX_DISPLAY_SIZE
        display_data = data[:self.MAX_DISPLAY_SIZE]
        
        # Check if binary
        is_binary = self._is_binary(display_data)
        
        result = {
            "size": len(data),
            "truncated": truncated,
            "is_binary": is_binary,
        }
        
        if is_binary:
            result["hex"] = self._format_hex_dump(display_data[:4096])
            result["raw"] = f"[Binary data: {len(data)} bytes]"
        else:
            # Try to decode as text
            try:
                text = display_data.decode('utf-8', errors='replace')
                result["raw"] = text
                result["hex"] = self._format_hex_dump(display_data[:1024])
                
                # Detect content type for syntax highlighting
                result["content_type"] = self._detect_content_type(text)
            except:
                result["hex"] = self._format_hex_dump(display_data[:4096])
                result["raw"] = f"[Unable to decode: {len(data)} bytes]"
        
        return result
    
    def _format_conversation(self, packets: List[Dict]) -> List[Dict]:
        """Format stream as conversation with alternating client/server"""
        conversation = []
        current_direction = None
        current_chunks = []
        current_start = None
        
        for pkt in packets:
            direction = pkt["direction"]
            payload = pkt.get("payload", b'')
            
            if direction != current_direction:
                # Save previous segment
                if current_chunks:
                    conversation.append({
                        "direction": current_direction,
                        "timestamp": datetime.fromtimestamp(current_start).isoformat() if current_start else None,
                        "data": self._format_data_display(b''.join(current_chunks), current_direction),
                    })
                
                current_direction = direction
                current_chunks = [payload] if payload else []
                current_start = pkt["timestamp"]
            elif payload:
                current_chunks.append(payload)
        
        # Add final segment
        if current_chunks:
            conversation.append({
                "direction": current_direction,
                "timestamp": datetime.fromtimestamp(current_start).isoformat() if current_start else None,
                "data": self._format_data_display(b''.join(current_chunks), current_direction),
            })
        
        return conversation[:100]
    
    def _format_packet_info(self, pkt: Dict) -> Dict:
        """Format packet info for display"""
        return {
            "idx": pkt.get("idx"),
            "timestamp": datetime.fromtimestamp(pkt["timestamp"]).isoformat(),
            "direction": pkt.get("direction"),
            "src": f"{pkt.get('src_ip')}:{pkt.get('src_port')}",
            "dst": f"{pkt.get('dst_ip')}:{pkt.get('dst_port')}",
            "seq": pkt.get("seq"),
            "ack": pkt.get("ack"),
            "flags": pkt.get("flags"),
            "payload_size": len(pkt.get("payload", b'')),
        }
    
    def _parse_http_requests(self, data: bytes) -> List[Dict]:
        """Parse HTTP requests from raw data"""
        requests = []
        
        if not data:
            return requests
        
        try:
            text = data.decode('utf-8', errors='replace')
            
            parts = _HTTP_REQUEST_PATTERN.split(text)
            
            i = 0
            while i < len(parts) - 3:
                if parts[i + 1] in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE']:
                    method = parts[i + 1]
                    path = parts[i + 2]
                    version = parts[i + 3]
                    
                    # Get headers and body
                    remaining = parts[i + 4] if i + 4 < len(parts) else ""
                    headers, body = self._parse_http_headers_body(remaining)
                    
                    requests.append({
                        "method": method,
                        "path": path,
                        "version": f"HTTP/{version}",
                        "headers": headers,
                        "body": body[:10000] if body else None,
                        "host": headers.get("Host", headers.get("host")),
                    })
                    i += 4
                else:
                    i += 1
                    
        except Exception as e:
            logger.debug(f"Error parsing HTTP requests: {e}")
        
        return requests
    
    def _parse_http_responses(self, data: bytes) -> List[Dict]:
        """Parse HTTP responses from raw data"""
        responses = []
        
        if not data:
            return responses
        
        try:
            # Try to decompress if gzipped
            try:
                data = gzip.decompress(data)
            except:
                pass
            
            text = data.decode('utf-8', errors='replace')
            
            matches = list(_HTTP_RESPONSE_PATTERN.finditer(text))
            
            for i, match in enumerate(matches):
                version = match.group(1)
                status_code = int(match.group(2))
                reason = match.group(3)
                
                # Get content until next response or end
                start = match.end()
                end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
                content = text[start:end]
                
                headers, body = self._parse_http_headers_body(content)
                
                responses.append({
                    "version": f"HTTP/{version}",
                    "status_code": status_code,
                    "reason": reason,
                    "headers": headers,
                    "body": body[:10000] if body else None,
                    "content_type": headers.get("Content-Type", headers.get("content-type")),
                    "content_length": headers.get("Content-Length", headers.get("content-length")),
                })
                
        except Exception as e:
            logger.debug(f"Error parsing HTTP responses: {e}")
        
        return responses
    
    def _parse_http_headers_body(self, content: str) -> Tuple[Dict, str]:
        """Parse HTTP headers and body from content"""
        headers = {}
        body = ""
        
        if not content:
            return headers, body
        
        # Split headers and body
        parts = content.split('\r\n\r\n', 1)
        if len(parts) == 1:
            parts = content.split('\n\n', 1)
        
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""
        
        # Parse headers
        for line in header_section.split('\n'):
            line = line.strip()
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        return headers, body
    
    def _match_http_pairs(self, requests: List[Dict], 
                          responses: List[Dict]) -> List[Dict]:
        """Match HTTP requests with responses"""
        pairs = []
        
        # Simple matching by order
        for i, req in enumerate(requests):
            pair = {
                "request": req,
                "response": responses[i] if i < len(responses) else None,
            }
            pairs.append(pair)
        
        return pairs
    
    def _get_raw_data(self, tcp_stream: Dict, direction: str) -> bytes:
        """Get raw bytes from stream data"""
        data_info = tcp_stream.get(f"{direction}_data", {})
        raw = data_info.get("raw", "")
        
        if isinstance(raw, str):
            return raw.encode('utf-8', errors='replace')
        return raw or b''
    
    def _is_binary(self, data: bytes) -> bool:
        """Check if data is binary"""
        if not data:
            return False
        
        # Check for null bytes or high ratio of non-printable chars
        text_chars = set(bytes(range(32, 127)) + b'\n\r\t')
        non_text = sum(1 for b in data[:1024] if b not in text_chars)
        return non_text / min(len(data), 1024) > 0.3
    
    def _format_hex_dump(self, data: bytes, bytes_per_line: int = 16) -> str:
        """Format data as hex dump"""
        lines = []
        
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i + bytes_per_line]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{i:08x}  {hex_part:<{bytes_per_line * 3}} {ascii_part}')
        
        return '\n'.join(lines)
    
    def _detect_content_type(self, text: str) -> str:
        """Detect content type for syntax highlighting"""
        text_lower = text.lower()[:1000]
        
        if text.startswith('{') or text.startswith('['):
            return "json"
        elif text.startswith('<?xml') or text.startswith('<'):
            return "xml"
        elif 'function' in text_lower and ('{' in text_lower or '=>' in text_lower):
            return "javascript"
        elif 'def ' in text_lower or 'import ' in text_lower:
            return "python"
        elif text.startswith('HTTP/'):
            return "http"
        else:
            return "text"
    
    def _export_as_text(self, stream: Dict) -> bytes:
        """Export stream as text"""
        lines = [
            f"TCP Stream: {stream.get('stream_id')}",
            f"Duration: {stream.get('duration', 0):.2f} seconds",
            f"Packets: {stream.get('packet_count', 0)}",
            "",
            "=" * 60,
            "CONVERSATION",
            "=" * 60,
            "",
        ]
        
        for segment in stream.get("conversation", []):
            direction = segment.get("direction", "?").upper()
            timestamp = segment.get("timestamp", "")
            data = segment.get("data", {}).get("raw", "")
            
            lines.append(f"[{timestamp}] {direction}:")
            lines.append("-" * 40)
            lines.append(data if data else "[No data]")
            lines.append("")
        
        return '\n'.join(lines).encode('utf-8')
    
    def _export_as_html(self, stream: Dict) -> bytes:
        """Export stream as HTML"""
        html_parts = [
            "<!DOCTYPE html>",
            "<html><head>",
            "<meta charset='utf-8'>",
            "<title>TCP Stream Export</title>",
            "<style>",
            "body { font-family: monospace; background: #1a1a2e; color: #eee; padding: 20px; }",
            ".client { background: #0f3460; padding: 10px; margin: 10px 0; border-left: 3px solid #3498db; }",
            ".server { background: #16213e; padding: 10px; margin: 10px 0; border-left: 3px solid #2ecc71; }",
            "pre { white-space: pre-wrap; word-wrap: break-word; }",
            "h1 { color: #f1c40f; }",
            "</style>",
            "</head><body>",
            f"<h1>TCP Stream: {html.escape(stream.get('stream_id', ''))}</h1>",
            f"<p>Duration: {stream.get('duration', 0):.2f}s | Packets: {stream.get('packet_count', 0)}</p>",
        ]
        
        for segment in stream.get("conversation", []):
            direction = segment.get("direction", "unknown")
            data = segment.get("data", {}).get("raw", "")
            
            html_parts.append(f"<div class='{direction}'>")
            html_parts.append(f"<strong>{direction.upper()}</strong> - {segment.get('timestamp', '')}")
            html_parts.append(f"<pre>{html.escape(data) if data else '[No data]'}</pre>")
            html_parts.append("</div>")
        
        html_parts.append("</body></html>")
        return '\n'.join(html_parts).encode('utf-8')
    
    def _export_as_raw(self, stream: Dict) -> bytes:
        """Export raw stream data"""
        client_data = self._get_raw_data(stream, "client")
        server_data = self._get_raw_data(stream, "server")
        
        return client_data + b'\n\n---SEPARATOR---\n\n' + server_data


# Singleton instance
_stream_service = None

def get_stream_service() -> StreamService:
    """Get singleton stream service instance"""
    global _stream_service
    if _stream_service is None:
        _stream_service = StreamService()
    return _stream_service
