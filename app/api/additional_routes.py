"""
Routes API complémentaires pour résoudre les erreurs 404
Version corrigée avec accès direct aux résultats
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
from collections import defaultdict

from app.services.storage_service import storage_service
from app.core.logging_config import get_logger
from app.core.mac_vendor import normalize_mac_address, resolve_mac_vendor

logger = get_logger(__name__)

# Router complémentaire
additional_router = APIRouter(prefix="/api", tags=["Complementary"])


# ============================================================
# CACHE EN MÉMOIRE (pour compatibilité frontend)
# ============================================================
analysis_cache: Dict[str, Any] = {
    "protocols": {},
    "timeline": [],
    "streams": [],
    "packets": [],
    "statistics": {},
    "last_updated": None,
    "current_task_id": None
}


def get_latest_task_id() -> Optional[str]:
    """
    Récupère le task_id de la dernière analyse
    """
    if analysis_cache["current_task_id"]:
        return analysis_cache["current_task_id"]
    
    history = storage_service.get_analysis_history(limit=1)
    if history:
        task_id = history[0].get('task_id')
        analysis_cache["current_task_id"] = task_id
        return task_id
    
    return None


def sync_cache_from_results(task_id: str):
    """
    Synchronise le cache avec les résultats d'une analyse
    """
    global analysis_cache
    
    results = storage_service.load_results(task_id)
    if not results:
        return False
    
    # Extraire les protocoles
    protocols_dict = {}
    protocol_analysis = results.get('protocol_analysis', {})
    for proto, data in protocol_analysis.get('protocols', {}).items():
        protocols_dict[proto] = {
            "packet_count": data.get('packet_count', data.get('count', 0)),
            "total_bytes": data.get('total_bytes', data.get('bytes', 0)),
            "sources": list(data.get('sources', [])),
            "destinations": list(data.get('destinations', []))
        }
    
    # Timeline depuis packets_index
    timeline_events = []
    for pkt in results.get('packets_index', [])[:1000]:
        timeline_events.append({
            "id": pkt.get('packet_num', pkt.get('idx', 0)),
            "timestamp": pkt.get('timestamp', ''),
            "protocol": pkt.get('protocol', 'Unknown'),
            "src": pkt.get('src_ip', 'N/A'),
            "dst": pkt.get('dst_ip', 'N/A'),
            "length": pkt.get('length', 0),
            "info": f"{pkt.get('protocol', '')} packet"
        })
    
    # Streams depuis tcp_analysis
    streams_list = []
    for session in results.get('tcp_analysis', {}).get('sessions', [])[:200]:
        streams_list.append({
            "stream_id": session.get('session_id', ''),
            "protocol": "TCP",
            "src": session.get('src', '').split(':')[0] if ':' in session.get('src', '') else '',
            "dst": session.get('dst', '').split(':')[0] if ':' in session.get('dst', '') else '',
            "packet_count": session.get('packet_count', session.get('packets', 0)),
            "total_bytes": session.get('total_bytes', session.get('bytes', 0)),
            "status": session.get('state', 'unknown')
        })
    
    # Statistiques
    summary = protocol_analysis.get('summary', {})
    statistics = {
        "total_packets": summary.get('total_packets', 0),
        "total_bytes": summary.get('total_bytes', 0),
        "duration_seconds": summary.get('duration', summary.get('capture_duration_seconds', 0)),
        "packets_per_second": summary.get('packets_per_second', 0),
        "average_packet_size": summary.get('average_packet_size', 0)
    }
    
    # Mettre à jour le cache
    analysis_cache["protocols"] = protocols_dict
    analysis_cache["timeline"] = timeline_events
    analysis_cache["streams"] = streams_list
    analysis_cache["packets"] = results.get('packets_index', [])[:500]
    analysis_cache["statistics"] = statistics
    analysis_cache["last_updated"] = datetime.now().isoformat()
    analysis_cache["current_task_id"] = task_id
    
    logger.info(f"Cache synchronisé avec task_id={task_id}")
    return True


# ============================================================
# MODÈLES PYDANTIC
# ============================================================
class TimelineFilter(BaseModel):
    selectedProtocols: Optional[List[str]] = None
    startTime: Optional[str] = None
    endTime: Optional[str] = None


class GraphRequest(BaseModel):
    chartType: str
    protocol: Optional[str] = None


class StreamFilter(BaseModel):
    protocol: Optional[str] = None
    minPackets: Optional[int] = None


# ============================================================
# ROUTES COMPLÉMENTAIRES
# ============================================================

@additional_router.get("/protocol/{protocol}/details")
async def get_protocol_details_compat(protocol: str, task_id: str = Query(..., description="Identifiant de l'analyse")):
    """
    Route de compatibilité pour les détails de protocole
    Format adapté pour le frontend

    task_id est obligatoire: l'ancien fallback « dernière analyse » exposait
    les captures des autres utilisateurs.
    """
    
    # Charger les résultats directement
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(
            status_code=404,
            detail=f"Résultats non trouvés pour task_id={task_id}"
        )
    
    protocol_lower = protocol.lower()
    
    # ============================================================
    # FORMAT ADAPTÉ POUR LE FRONTEND (4 champs principaux)
    # ============================================================
    
    # 1. SSH
    if protocol_lower == 'ssh':
        ssh_data = results.get('ssh_analysis', {})
        summary = ssh_data.get('summary', {})
        
        return {
            "Paquets": summary.get('total_packets', 0),
            "Volume": f"{summary.get('total_packets', 0) * 1000} octets",  # Estimation
            "Connexions": summary.get('total_connections', 0),
            "Anomalies": summary.get('total_anomalies', 0),
            # Données supplémentaires pour drill-down
            "extra": {
                "sessions": summary.get('total_sessions', 0),
                "auth_attempts": summary.get('total_auth_attempts', 0),
                "successful_auths": summary.get('successful_authentications', 0),
                "client_versions": ssh_data.get('client_versions', {}),
                "server_versions": ssh_data.get('server_versions', {}),
                "tunnels": summary.get('tunnels_detected', 0)
            }
        }
    
    # 2. SMB/CIFS
    elif protocol_lower in ['smb', 'cifs', 'smb/cifs']:
        smb_data = results.get('smb_analysis', {})
        summary = smb_data.get('summary', {})
        
        return {
            "Paquets": summary.get('total_packets', 0),
            "Volume": f"{summary.get('total_bytes', 0)} octets",
            "Connexions": summary.get('total_sessions', 0),
            "Anomalies": summary.get('total_anomalies', 0),
            "extra": {
                "shares": summary.get('unique_shares', 0),
                "file_operations": summary.get('total_file_operations', 0),
                "auth_attempts": summary.get('total_auth_attempts', 0),
                "commands": smb_data.get('commands', {})
            }
        }
    
    # 3. RDP
    elif protocol_lower == 'rdp':
        rdp_data = results.get('rdp_analysis', {})
        summary = rdp_data.get('summary', {})
        
        return {
            "Paquets": summary.get('total_packets', 0),
            "Volume": f"{summary.get('total_bytes', 0)} octets",
            "Connexions": summary.get('total_connections', 0),
            "Anomalies": summary.get('total_anomalies', 0),
            "extra": {
                "connection_attempts": summary.get('total_connection_attempts', 0),
                "successful": summary.get('successful_connections', 0),
                "failed": summary.get('failed_connections', 0),
                "protocols_used": rdp_data.get('protocols_used', {})
            }
        }
    
    # 4. LDAP
    elif protocol_lower == 'ldap':
        ldap_data = results.get('ldap_analysis', {})
        summary = ldap_data.get('summary', {})
        
        return {
            "Paquets": summary.get('total_packets', 0),
            "Volume": f"{summary.get('total_bytes', 0)} octets",
            "Connexions": summary.get('total_sessions', 0),
            "Anomalies": summary.get('total_anomalies', 0),
            "extra": {
                "bind_attempts": summary.get('total_bind_attempts', 0),
                "search_queries": summary.get('total_search_queries', 0),
                "modifications": summary.get('total_modifications', 0),
                "operations": ldap_data.get('operations', {})
            }
        }
    
    # 5. Kerberos
    elif protocol_lower == 'kerberos':
        kerberos_data = results.get('kerberos_analysis', {})
        summary = kerberos_data.get('summary', {})
        
        return {
            "Paquets": summary.get('total_packets', 0),
            "Volume": f"{summary.get('total_bytes', 0)} octets",
            "Connexions": summary.get('total_as_requests', 0) + summary.get('total_tgs_requests', 0),
            "Anomalies": summary.get('total_anomalies', 0),
            "extra": {
                "as_requests": summary.get('total_as_requests', 0),
                "tgs_requests": summary.get('total_tgs_requests', 0),
                "errors": summary.get('total_errors', 0),
                "principals": len(kerberos_data.get('principals', [])),
                "services": kerberos_data.get('services', {})
            }
        }
    
    # 6. DNS
    elif protocol_lower == 'dns':
        dns_data = results.get('dns_analysis', {})
        summary = dns_data.get('summary', {})
        
        return {
            "Paquets": summary.get('total_packets', 0),
            "Volume": f"{summary.get('total_bytes', 0)} octets",
            "Connexions": summary.get('total_queries', 0),
            "Anomalies": len(dns_data.get('anomalies', [])),
            "extra": {
                "queries": summary.get('total_queries', 0),
                "responses": summary.get('total_responses', 0),
                "unique_domains": summary.get('unique_domains', 0),
                "query_types": dns_data.get('query_types', {})
            }
        }
    
    # 7. HTTP/HTTPS
    elif protocol_lower in ['http', 'https']:
        http_data = results.get('http_analysis', {})
        summary = http_data.get('summary', {})
        
        return {
            "Paquets": summary.get('total_packets', 0),
            "Volume": f"{summary.get('total_bytes', 0)} octets",
            "Connexions": summary.get('total_requests', 0),
            "Anomalies": len(http_data.get('anomalies', [])),
            "extra": {
                "requests": summary.get('total_requests', 0),
                "responses": summary.get('total_responses', 0),
                "methods": http_data.get('methods', {}),
                "status_codes": http_data.get('status_codes', {})
            }
        }
    
    # 8. TCP/UDP/ICMP (protocoles de base)
    else:
        protocol_analysis = results.get('protocol_analysis', {})
        protocols = protocol_analysis.get('protocols', {})
        
        # Recherche insensible à la casse
        protocol_data = None
        for proto_name, proto_info in protocols.items():
            if proto_name.upper() == protocol.upper():
                protocol_data = proto_info
                break
        
        if not protocol_data:
            return {
                "Paquets": 0,
                "Volume": "0 octets",
                "Connexions": 0,
                "Anomalies": 0,
                "message": f"Aucun paquet {protocol} trouvé dans le PCAP"
            }
        
        return {
            "Paquets": protocol_data.get('packet_count', 0),
            "Volume": f"{protocol_data.get('total_bytes', 0)} octets",
            "Connexions": len(protocol_data.get('sources', [])),
            "Anomalies": 0,
            "extra": {
                "sources": list(protocol_data.get('sources', [])),
                "destinations": list(protocol_data.get('destinations', []))
            }
        }

@additional_router.post("/graph/update")
async def update_graph_compat(request: GraphRequest, task_id: str = Query(..., description="Identifiant de l'analyse")):
    """
    Route de compatibilité pour générer des graphiques.
    task_id obligatoire: l'ancien fallback « dernière analyse » exposait
    les captures des autres utilisateurs.
    """
    # Synchroniser le cache sur la tâche demandée (pas la « dernière »)
    if analysis_cache.get("current_task_id") != task_id or not analysis_cache["protocols"]:
        sync_cache_from_results(task_id)
    
    if not analysis_cache["protocols"]:
        raise HTTPException(
            status_code=404,
            detail="Aucune donnée disponible."
        )
    
    if request.chartType == "protocol_distribution":
        labels = list(analysis_cache["protocols"].keys())
        data = [
            analysis_cache["protocols"][proto]["packet_count"] 
            for proto in labels
        ]
        
        return {
            "type": "pie",
            "labels": labels,
            "data": data
        }
    
    elif request.chartType == "bytes_per_protocol":
        labels = list(analysis_cache["protocols"].keys())
        data = [
            analysis_cache["protocols"][proto]["total_bytes"] 
            for proto in labels
        ]
        
        return {
            "type": "bar",
            "labels": labels,
            "data": data
        }
    
    elif request.chartType == "timeline":
        timeline = analysis_cache["timeline"][:100]
        
        return {
            "type": "line",
            "labels": [event["timestamp"] for event in timeline],
            "data": [event["length"] for event in timeline]
        }
    
    else:
        raise HTTPException(status_code=400, detail="Type de graphique inconnu")


@additional_router.post("/streams/filter")
async def filter_streams_compat(filters: StreamFilter, task_id: str = Query(..., description="Identifiant de l'analyse")):
    """
    Route de compatibilité pour filtrer les streams.
    task_id obligatoire (voir update_graph_compat).
    """
    if analysis_cache.get("current_task_id") != task_id or not analysis_cache["streams"]:
        sync_cache_from_results(task_id)
    
    if not analysis_cache["streams"]:
        raise HTTPException(
            status_code=404,
            detail="Aucun stream disponible."
        )
    
    streams = analysis_cache["streams"]
    
    # Filtrer par protocole
    if filters.protocol:
        streams = [
            stream for stream in streams
            if stream.get("protocol", "").upper() == filters.protocol.upper()
        ]
    
    # Filtrer par nombre minimum de paquets
    if filters.minPackets:
        streams = [
            stream for stream in streams
            if stream.get("packet_count", 0) >= filters.minPackets
        ]
    
    return {
        "streams": streams,
        "total_streams": len(streams)
    }


@additional_router.get("/cache/status")
async def get_cache_status_compat():
    """
    Route de compatibilité pour le statut du cache
    """
    task_id = get_latest_task_id()
    
    if not task_id:
        return {
            "status": "empty",
            "message": "Aucun fichier PCAP analysé"
        }
    
    # Synchroniser le cache si nécessaire
    if not analysis_cache["last_updated"]:
        sync_cache_from_results(task_id)
    
    return {
        "status": "ready",
        "last_updated": analysis_cache["last_updated"],
        "current_task_id": analysis_cache["current_task_id"],
        "statistics": analysis_cache.get("statistics", {}),
        "protocols_count": len(analysis_cache["protocols"]),
        "packets_count": len(analysis_cache["packets"]),
        "streams_count": len(analysis_cache["streams"])
    }


@additional_router.delete("/cache/clear")
async def clear_cache_compat():
    """
    Route de compatibilité pour vider le cache
    """
    global analysis_cache
    
    analysis_cache = {
        "protocols": {},
        "timeline": [],
        "streams": [],
        "packets": [],
        "statistics": {},
        "last_updated": None,
        "current_task_id": None
    }
    
    return {
        "status": "success",
        "message": "Cache vidé"
    }


# ============================================================
# HOOK POUR SYNCHRONISER LE CACHE APRÈS UPLOAD
# ============================================================
def update_cache_after_analysis(task_id: str):
    """
    À appeler après qu'une analyse soit terminée
    """
    return sync_cache_from_results(task_id)


# ============================================================
# NEW FEATURE ROUTES — Features 1-10
# ============================================================

# ── Feature 1: Flow Behavior Analysis ──
@additional_router.get("/{task_id}/flow-behavior")
def get_flow_behavior(task_id: str):
    """Feature 1: Beaconing C2, exfiltration, flow fingerprinting"""
    from app.analyzers.flow_behavior_analyzer import FlowBehaviorAnalyzer
    results = storage_service.load_results(task_id)
    if not results:
        raise HTTPException(status_code=404, detail="Task non trouvé")

    # Résultat déjà calculé ? (évite de re-parser tout le PCAP)
    cached = storage_service.load_derived(task_id, "flow_behavior")
    if cached is not None:
        return cached
    try:
        from scapy.all import rdpcap  # type: ignore
        pcap_path = storage_service.get_pcap_path(task_id)
        if not pcap_path:
            return {
                "summary": {
                    "total_flows_analyzed": 0,
                    "beaconing_alerts": 0,
                    "exfiltration_alerts": 0,
                    "unique_fingerprints": 0,
                },
                "beaconing_alerts": [],
                "exfiltration_alerts": [],
                "flow_fingerprints": [],
            }
        packets = rdpcap(pcap_path)
        analyzer = FlowBehaviorAnalyzer()
        analysis = analyzer.analyze(packets)
        storage_service.save_derived(task_id, "flow_behavior", analysis)
        return analysis
    except Exception as e:
        logger.error(f"flow_behavior error: {e}")
        return {
            "summary": {
                "total_flows_analyzed": 0,
                "beaconing_alerts": 0,
                "exfiltration_alerts": 0,
                "unique_fingerprints": 0,
                "warning": str(e),
            },
            "beaconing_alerts": [],
            "exfiltration_alerts": [],
            "flow_fingerprints": [],
        }


# ── Feature 2: TLS Analysis ──
@additional_router.get("/{task_id}/tls-analysis")
def get_tls_analysis(task_id: str):
    """Feature 2: JA3/JA3S fingerprints, TLS version, cipher suites, SNI"""
    from app.analyzers.tls_analyzer import TLSAnalyzer
    results = storage_service.load_results(task_id)
    if not results:
        raise HTTPException(status_code=404, detail="Task non trouvé")

    cached = storage_service.load_derived(task_id, "tls_analysis")
    if cached is not None:
        return cached
    try:
        from scapy.all import rdpcap  # type: ignore
        pcap_path = storage_service.get_pcap_path(task_id)
        if not pcap_path:
            return {"summary": {"total_client_hellos": 0}, "sessions": []}
        packets = rdpcap(pcap_path)
        analyzer = TLSAnalyzer()
        analysis = analyzer.analyze(packets)
        storage_service.save_derived(task_id, "tls_analysis", analysis)
        return analysis
    except Exception as e:
        logger.error(f"tls_analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ── Feature 3: Baseline Comparison ──
class CompareRequest(BaseModel):
    baseline_task_id: str
    investigation_task_id: str
    baseline_label: Optional[str] = "Baseline"
    investigation_label: Optional[str] = "Investigation"

@additional_router.post("/compare")
async def compare_pcaps(request: CompareRequest):
    """Feature 3: Compare deux captures PCAP pour détecter les déviances"""
    from app.services.comparison_service import BaselineComparator
    baseline = storage_service.load_results(request.baseline_task_id)
    investigation = storage_service.load_results(request.investigation_task_id)
    if not baseline:
        raise HTTPException(status_code=404, detail=f"Baseline task non trouvé: {request.baseline_task_id}")
    if not investigation:
        raise HTTPException(status_code=404, detail=f"Investigation task non trouvé: {request.investigation_task_id}")
    comparator = BaselineComparator()
    return comparator.compare(baseline, investigation, request.baseline_label, request.investigation_label)


# ── Feature 4: Lateral Movement Graph ──
@additional_router.get("/{task_id}/lateral-movement")
async def get_lateral_movement(task_id: str):
    """Feature 4: Pivot hosts, Pass-the-Hash, Kerberoasting, LDAP enumeration"""
    from app.analyzers.lateral_movement_analyzer import LateralMovementAnalyzer
    results = storage_service.load_results(task_id)
    if not results:
        raise HTTPException(status_code=404, detail="Task non trouvé")
    try:
        analyzer = LateralMovementAnalyzer()
        return analyzer.analyze_from_results(results)
    except Exception as e:
        logger.error(f"lateral_movement error: {e}")
        return {
            "summary": {
                "risk_level": "UNKNOWN",
                "total_indicators": 0,
                "pivot_hosts": 0,
                "pass_the_hash": 0,
                "kerberoasting": 0,
                "ldap_enumeration": 0,
                "lateral_movement_edges": 0,
                "warning": str(e),
            },
            "pivot_hosts": [],
            "pass_the_hash": [],
            "kerberoasting": [],
            "ldap_enumeration": [],
            "graph_edges": [],
            "lateral_movement_edges": [],
        }


# ── Feature 6: QoS Metrics ──
@additional_router.get("/{task_id}/qos-metrics")
async def get_qos_metrics(task_id: str):
    """Feature 6: RTT percentiles, jitter, DSCP, TTL anomalies"""
    results = storage_service.load_results(task_id)
    if not results:
        raise HTTPException(status_code=404, detail="Task non trouvé")
    tcp = results.get("tcp_analysis", {})
    sessions = tcp.get("sessions", [])
    packets_index = results.get("packets_index", []) if isinstance(results.get("packets_index", []), list) else []
    rtts = [float(s.get("rtt_ms", 0) or 0) for s in sessions if s.get("rtt_ms")]
    rtts_sorted = sorted(rtts)
    n = len(rtts_sorted)
    def percentile(lst, pct):
        if not lst:
            return 0.0
        idx = max(0, int(len(lst) * pct / 100) - 1)
        return round(float(lst[idx]), 3)
    jitter_ms = 0.0
    if len(rtts) >= 2:
        # Jitter simple = moyenne des variations absolues RTT entre échantillons successifs.
        diffs = [abs(float(rtts[i]) - float(rtts[i - 1])) for i in range(1, len(rtts))]
        jitter_ms = round(sum(diffs) / len(diffs), 3) if diffs else 0.0

    rtt_metrics = {
            "p50_ms": percentile(rtts_sorted, 50),
            "p95_ms": percentile(rtts_sorted, 95),
            "p99_ms": percentile(rtts_sorted, 99),
            "max_ms": round(max(rtts_sorted), 3) if rtts_sorted else 0,
            "min_ms": round(min(rtts_sorted), 3) if rtts_sorted else 0,
            "avg_ms": round(sum(rtts_sorted) / n, 3) if n > 0 else 0,
            "sample_count": n,
            "jitter_ms": jitter_ms,
        }

    # Frontend compatibility aliases
    rtt_ms = {
        "p50": rtt_metrics["p50_ms"],
        "p95": rtt_metrics["p95_ms"],
        "p99": rtt_metrics["p99_ms"],
        "max": rtt_metrics["max_ms"],
        "min": rtt_metrics["min_ms"],
        "avg": rtt_metrics["avg_ms"],
        "sample_count": rtt_metrics["sample_count"],
        "jitter": rtt_metrics["jitter_ms"],
    }

    # Volumétrie temporelle (1 seconde) pour faciliter les graphes de troubleshooting.
    timeline_buckets: Dict[int, Dict[str, Any]] = defaultdict(lambda: {"packets": 0, "bytes": 0, "retrans": 0})
    for pkt in packets_index[:50000]:
        if not isinstance(pkt, dict):
            continue
        ts = pkt.get("timestamp")
        try:
            if ts is None:
                continue
            sec = int(float(ts))
        except (TypeError, ValueError):
            continue
        length = 0
        try:
            length = int(pkt.get("length", 0) or 0)
        except (TypeError, ValueError):
            length = 0
        info = str(pkt.get("info", "") or "").lower()
        timeline_buckets[sec]["packets"] += 1
        timeline_buckets[sec]["bytes"] += max(0, length)
        if "retrans" in info or "dup ack" in info:
            timeline_buckets[sec]["retrans"] += 1

    timeseries = []
    for sec in sorted(timeline_buckets.keys()):
        row = timeline_buckets[sec]
        bits_per_sec = float(row["bytes"]) * 8.0
        mbps = bits_per_sec / 1_000_000.0
        timeseries.append({
            "timestamp": sec,
            "packets_per_sec": int(row["packets"]),
            "bytes_per_sec": int(row["bytes"]),
            "throughput_mbps": round(mbps, 4),
            "retrans_events": int(row["retrans"]),
        })

    throughput_values = [float(x.get("throughput_mbps", 0.0)) for x in timeseries]
    throughput_avg = round(sum(throughput_values) / len(throughput_values), 4) if throughput_values else 0.0
    throughput_peak = round(max(throughput_values), 4) if throughput_values else 0.0
    throughput_p95 = percentile(sorted(throughput_values), 95) if throughput_values else 0.0
    pps_values = [int(x.get("packets_per_sec", 0)) for x in timeseries]
    pps_avg = round(sum(pps_values) / len(pps_values), 2) if pps_values else 0.0
    pps_peak = max(pps_values) if pps_values else 0

    # Normalize session records for QoS table
    normalized_sessions = []
    for s in sessions[:200]:
        if not isinstance(s, dict):
            continue
        src = str(s.get("src", ""))
        dst = str(s.get("dst", ""))
        src_ip, src_port = (src.rsplit(":", 1) + [""])[:2] if ":" in src else (src, s.get("src_port", ""))
        dst_ip, dst_port = (dst.rsplit(":", 1) + [""])[:2] if ":" in dst else (dst, s.get("dst_port", ""))
        normalized_sessions.append({
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "retransmissions": s.get("retransmissions", 0),
            "zero_windows": s.get("zero_windows", 0),
            "avg_rtt_ms": s.get("rtt_ms", 0),
            "state": s.get("state", "UNKNOWN"),
        })

    # Copie: load_results() renvoie un dict partagé par le cache — ne jamais
    # muter les résultats chargés (pollution inter-requêtes sinon)
    tcp_summary = dict(tcp.get("summary", {})) if isinstance(tcp.get("summary", {}), dict) else {}
    tcp_summary.setdefault("total_retransmissions", sum(int(s.get("retransmissions", 0) or 0) for s in normalized_sessions))
    tcp_summary.setdefault("total_zero_windows", sum(int(s.get("zero_windows", 0) or 0) for s in normalized_sessions))
    tcp_summary["jitter_ms"] = jitter_ms
    tcp_summary["throughput_avg_mbps"] = throughput_avg
    tcp_summary["throughput_peak_mbps"] = throughput_peak
    tcp_summary["throughput_p95_mbps"] = throughput_p95
    tcp_summary["pps_avg"] = pps_avg
    tcp_summary["pps_peak"] = pps_peak

    total_retrans = int(tcp_summary.get("total_retransmissions", 0) or 0)
    total_packets = sum(int(x.get("packets_per_sec", 0) or 0) for x in timeseries) or len(normalized_sessions) or 1
    retrans_ratio_pct = (float(total_retrans) / float(max(total_packets, 1))) * 100.0
    health_score = 100.0
    if rtt_metrics["p95_ms"] >= 200:
        health_score -= 25
    elif rtt_metrics["p95_ms"] >= 120:
        health_score -= 14
    elif rtt_metrics["p95_ms"] >= 60:
        health_score -= 8

    if jitter_ms >= 35:
        health_score -= 20
    elif jitter_ms >= 18:
        health_score -= 12
    elif jitter_ms >= 8:
        health_score -= 6

    if retrans_ratio_pct >= 8:
        health_score -= 22
    elif retrans_ratio_pct >= 3:
        health_score -= 14
    elif retrans_ratio_pct >= 1:
        health_score -= 8

    if int(tcp_summary.get("total_zero_windows", 0) or 0) > 0:
        health_score -= min(18, int(tcp_summary.get("total_zero_windows", 0) or 0))

    health_score = max(0.0, min(100.0, health_score))
    tcp_summary["health_score"] = round(health_score, 1)
    tcp_summary["retrans_ratio_pct_estimated"] = round(retrans_ratio_pct, 3)

    slow_sessions = sorted(
        normalized_sessions,
        key=lambda s: (
            float(s.get("avg_rtt_ms", 0) or 0),
            int(s.get("retransmissions", 0) or 0),
            int(s.get("zero_windows", 0) or 0),
        ),
        reverse=True,
    )[:20]

    return {
        "rtt_metrics": rtt_metrics,
        "rtt_ms": rtt_ms,
        "tcp_summary": tcp_summary,
        "tcp_sessions": normalized_sessions,
        "sessions": normalized_sessions,
        "slow_sessions": slow_sessions,
        "timeseries": timeseries,
        "volumetry": {
            "throughput_avg_mbps": throughput_avg,
            "throughput_peak_mbps": throughput_peak,
            "throughput_p95_mbps": throughput_p95,
            "pps_avg": pps_avg,
            "pps_peak": pps_peak,
        },
        "retransmissions": tcp.get("retransmissions", {}),
        "zero_windows": tcp.get("zero_windows", {}),
    }


# ── Feature 6b: TCP Health & Bottleneck Diagnostics ──
from app.core.utils import as_float as _as_float, as_int as _as_int  # noqa: E402


def _percentile(values: List[float], p: float, default: float = 0.0) -> float:
    clean = sorted(float(v) for v in values if isinstance(v, (int, float)))
    if not clean:
        return default
    if len(clean) == 1:
        return clean[0]
    pct = min(100.0, max(0.0, float(p)))
    rank = (len(clean) - 1) * (pct / 100.0)
    low = int(rank)
    high = min(low + 1, len(clean) - 1)
    if low == high:
        return clean[low]
    return clean[low] + (clean[high] - clean[low]) * (rank - low)


def _extract_ip_port(endpoint: str) -> tuple[str, str]:
    if not endpoint:
        return "", ""
    text = str(endpoint).strip()
    if ":" in text:
        ip, port = text.rsplit(":", 1)
        if port.isdigit():
            return ip, port
    return text, ""


def _detect_bursts_from_packets_index(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    packets = results.get("packets_index", [])
    if not isinstance(packets, list):
        return []

    by_second: Dict[int, int] = defaultdict(int)
    for pkt in packets[:5000]:
        if not isinstance(pkt, dict):
            continue
        ts = _as_float(pkt.get("timestamp"), -1)
        if ts < 0:
            continue
        by_second[int(ts)] += 1

    if not by_second:
        return []

    avg_pps = sum(by_second.values()) / max(len(by_second), 1)
    dynamic_threshold = max(200, int(avg_pps * 3))
    bursts = []
    for second, pps in sorted(by_second.items(), key=lambda x: x[1], reverse=True):
        if pps >= dynamic_threshold:
            bursts.append({
                "timestamp": second,
                "packets_per_second": pps,
                "severity": "HIGH" if pps >= dynamic_threshold * 2 else "MEDIUM",
                "description": f"Pic de trafic: {pps} paquets/s",
            })
    return bursts[:30]


@additional_router.get("/{task_id}/tcp-health")
async def get_tcp_health(task_id: str):
    """
    Diagnostic TCP avancé:
    - Window Size / Zero Window
    - Ralentissements (RTT, retransmissions)
    - Bursts et goulots d'étranglement
    - IPs problématiques et causes probables
    """
    results = storage_service.load_results(task_id)
    if not results:
        raise HTTPException(status_code=404, detail="Task non trouvé")

    tcp = results.get("tcp_analysis", {}) if isinstance(results.get("tcp_analysis", {}), dict) else {}
    sessions = tcp.get("sessions", []) if isinstance(tcp.get("sessions", []), list) else []
    summary = tcp.get("summary", {}) if isinstance(tcp.get("summary", {}), dict) else {}
    rtt = tcp.get("rtt_analysis", {}) if isinstance(tcp.get("rtt_analysis", {}), dict) else {}
    window = tcp.get("window_analysis", {}) if isinstance(tcp.get("window_analysis", {}), dict) else {}
    retrans = tcp.get("retransmission_analysis", {}) if isinstance(tcp.get("retransmission_analysis", {}), dict) else {}
    handshake = tcp.get("handshake_analysis", {}) if isinstance(tcp.get("handshake_analysis", {}), dict) else {}
    rst_analysis = tcp.get("rst_analysis", {}) if isinstance(tcp.get("rst_analysis", {}), dict) else {}
    connection_states = tcp.get("connection_states", {}) if isinstance(tcp.get("connection_states", {}), dict) else {}
    protocol = results.get("protocol_analysis", {}) if isinstance(results.get("protocol_analysis", {}), dict) else {}
    protocol_summary = protocol.get("summary", {}) if isinstance(protocol.get("summary", {}), dict) else {}
    mac_stats = protocol.get("mac_statistics", {}) if isinstance(protocol.get("mac_statistics", {}), dict) else {}
    packets_index = results.get("packets_index", []) if isinstance(results.get("packets_index", []), list) else []

    anomaly_block = results.get("anomaly_detection", {}) or results.get("anomaly_analysis", {}) or {}
    anomalies = anomaly_block.get("anomalies", []) if isinstance(anomaly_block.get("anomalies", []), list) else []
    suspicious_ips = anomaly_block.get("top_suspicious_ips", []) if isinstance(anomaly_block.get("top_suspicious_ips", []), list) else []

    total_sessions = _as_int(summary.get("total_sessions"), len(sessions))
    total_retrans = _as_int(retrans.get("total_retransmissions"), _as_int(summary.get("total_retransmissions"), 0))
    retrans_rate = _as_float(retrans.get("retransmission_rate"), 0.0)
    zero_window_count = _as_int(window.get("zero_window_count"), 0)
    zero_window_pct = _as_float(window.get("zero_window_percentage"), 0.0)
    avg_window = _as_int(window.get("avg_window"), 0)
    min_window = _as_int(window.get("min_window"), 0)
    max_window = _as_int(window.get("max_window"), 0)
    effective_avg_window = _as_int(window.get("effective_avg_window"), 0)
    effective_min_window = _as_int(window.get("effective_min_window"), 0)
    effective_max_window = _as_int(window.get("effective_max_window"), 0)
    window_scale_min = _as_int(window.get("window_scale_min"), 0)
    window_scale_max = _as_int(window.get("window_scale_max"), 0)
    window_scale_avg = _as_float(window.get("window_scale_avg"), 0.0)
    window_scale_p95 = _as_float(window.get("window_scale_p95"), 0.0)
    window_scale_observed_sessions = _as_int(window.get("window_scale_observed_sessions"), 0)
    window_scale_observed_directions = _as_int(window.get("window_scale_observed_directions"), 0)
    window_scale_coverage_pct = _as_float(window.get("window_scale_coverage_pct"), 0.0)
    avg_rtt_ms = _as_float(rtt.get("avg_rtt_ms"), 0.0)
    min_rtt_ms = _as_float(rtt.get("min_rtt_ms"), 0.0)
    max_rtt_ms = _as_float(rtt.get("max_rtt_ms"), 0.0)
    session_rtt_values = [
        _as_float(s.get("rtt_ms"), 0.0)
        for s in sessions
        if isinstance(s, dict) and _as_float(s.get("rtt_ms"), 0.0) > 0
    ]
    rtt_p50_ms = round(_percentile(session_rtt_values, 50.0, avg_rtt_ms), 3) if session_rtt_values else round(avg_rtt_ms, 3)
    rtt_p95_ms = round(_percentile(session_rtt_values, 95.0, max_rtt_ms), 3) if session_rtt_values else round(max_rtt_ms, 3)
    rtt_p99_ms = round(_percentile(session_rtt_values, 99.0, max_rtt_ms), 3) if session_rtt_values else round(max_rtt_ms, 3)
    rtt_jitter_ms = 0.0
    if len(session_rtt_values) >= 2:
        diffs = [
            abs(float(session_rtt_values[idx]) - float(session_rtt_values[idx - 1]))
            for idx in range(1, len(session_rtt_values))
        ]
        rtt_jitter_ms = round(sum(diffs) / len(diffs), 3) if diffs else 0.0
    total_packets = _as_int(protocol_summary.get("total_packets"), 0)
    sessions_with_retrans = _as_int(retrans.get("sessions_with_retransmissions"), 0)
    sessions_with_rst = _as_int(summary.get("sessions_with_rst"), _as_int(rst_analysis.get("sessions_with_rst"), 0))
    half_open_connections = _as_int(summary.get("half_open_connections"), _as_int(connection_states.get("SYN_SENT"), 0) + _as_int(connection_states.get("SYN_RECEIVED"), 0))
    handshake_success_rate = _as_float(handshake.get("handshake_success_rate"), 0.0)
    complete_handshakes = _as_int(handshake.get("complete_handshakes"), 0)
    incomplete_handshakes = _as_int(handshake.get("incomplete_handshakes"), 0)
    rst_by_initiator = _as_int(rst_analysis.get("rst_by_initiator"), 0)
    rst_by_responder = _as_int(rst_analysis.get("rst_by_responder"), 0)
    sessions_with_retrans_pct = round((sessions_with_retrans / total_sessions * 100.0), 3) if total_sessions > 0 else 0.0
    sessions_with_rst_pct = round((sessions_with_rst / total_sessions * 100.0), 3) if total_sessions > 0 else 0.0
    half_open_pct = round((half_open_connections / total_sessions * 100.0), 3) if total_sessions > 0 else 0.0
    rtt_range_ms = max(0.0, max_rtt_ms - min_rtt_ms)
    window_range = max(0, max_window - min_window)

    duration_values = [_as_float(s.get("duration"), 0.0) for s in sessions if isinstance(s, dict)]
    duration_values = [d for d in duration_values if d > 0]
    session_duration_avg_s = round(sum(duration_values) / len(duration_values), 3) if duration_values else 0.0
    session_duration_p95_s = round(_percentile(duration_values, 95.0, 0.0), 3) if duration_values else 0.0
    session_duration_max_s = round(max(duration_values), 3) if duration_values else 0.0

    capture_duration_seconds = _as_float(protocol_summary.get("duration"), 0.0) or _as_float(protocol_summary.get("capture_duration_seconds"), 0.0)
    if capture_duration_seconds <= 0 and packets_index:
        ts_values = []
        for pkt in packets_index[:20000]:
            if not isinstance(pkt, dict):
                continue
            ts = _as_float(pkt.get("timestamp"), -1.0)
            if ts >= 0:
                ts_values.append(ts)
        if len(ts_values) >= 2:
            capture_duration_seconds = max(ts_values) - min(ts_values)
    capture_duration_seconds = max(0.0, capture_duration_seconds)

    window_pressure_score = 0
    if zero_window_pct >= 1:
        window_pressure_score += 45
    elif zero_window_count > 0:
        window_pressure_score += 28
    if avg_window > 0 and avg_window < 2048:
        window_pressure_score += 20
    elif avg_window > 0 and avg_window < 8192:
        window_pressure_score += 10
    if window_range > 50000:
        window_pressure_score += 15
    elif window_range > 15000:
        window_pressure_score += 8
    window_pressure_score = min(100, window_pressure_score)
    window_pressure_level = (
        "CRITIQUE" if window_pressure_score >= 70
        else "ÉLEVÉ" if window_pressure_score >= 45
        else "MODÉRÉ" if window_pressure_score >= 20
        else "FAIBLE"
    )

    bursts = []
    for a in anomalies:
        if not isinstance(a, dict) or a.get("type") != "TRAFFIC_BURST":
            continue
        details = a.get("details", {}) if isinstance(a.get("details", {}), dict) else {}
        bursts.append({
            "timestamp": _as_int(details.get("timestamp"), _as_int(a.get("timestamp"), 0)),
            "packets_per_second": _as_int(details.get("packets_per_second"), 0),
            "severity": str(a.get("severity", "LOW")),
            "description": str(a.get("description", "Pic de trafic détecté")),
        })
    if not bursts:
        bursts = _detect_bursts_from_packets_index(results)
    bursts_per_minute = round((len(bursts) / (capture_duration_seconds / 60.0)), 3) if capture_duration_seconds > 0 else 0.0

    volumetry_by_second: Dict[int, Dict[str, Any]] = defaultdict(lambda: {"packets": 0, "bytes": 0, "retrans": 0})
    for pkt in packets_index[:50000]:
        if not isinstance(pkt, dict):
            continue
        ts_val = _as_float(pkt.get("timestamp"), -1.0)
        if ts_val < 0:
            continue
        sec = int(ts_val)
        length = max(0, _as_int(pkt.get("length"), 0))
        info = str(pkt.get("info", "") or "").lower()
        volumetry_by_second[sec]["packets"] += 1
        volumetry_by_second[sec]["bytes"] += length
        if "retrans" in info or "dup ack" in info:
            volumetry_by_second[sec]["retrans"] += 1

    volumetry_timeseries = []
    for sec in sorted(volumetry_by_second.keys()):
        row = volumetry_by_second[sec]
        throughput_mbps = (float(row["bytes"]) * 8.0) / 1_000_000.0
        volumetry_timeseries.append({
            "timestamp": sec,
            "packets_per_sec": int(row["packets"]),
            "bytes_per_sec": int(row["bytes"]),
            "throughput_mbps": round(throughput_mbps, 4),
            "retrans_events": int(row["retrans"]),
        })

    pps_values = [int(v.get("packets_per_sec", 0)) for v in volumetry_timeseries]
    thr_values = [float(v.get("throughput_mbps", 0.0)) for v in volumetry_timeseries]
    avg_pps = round(sum(pps_values) / len(pps_values), 2) if pps_values else 0.0
    peak_pps = max(pps_values) if pps_values else 0
    avg_throughput_mbps = round(sum(thr_values) / len(thr_values), 4) if thr_values else 0.0
    peak_throughput_mbps = round(max(thr_values), 4) if thr_values else 0.0

    ip_to_macs: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for pkt in packets_index[:10000]:
        if not isinstance(pkt, dict):
            continue

        src_ip = str(pkt.get("src_ip") or "").strip()
        dst_ip = str(pkt.get("dst_ip") or "").strip()
        src_mac = normalize_mac_address(str(pkt.get("src_mac") or ""))
        dst_mac = normalize_mac_address(str(pkt.get("dst_mac") or ""))

        if src_ip and src_mac:
            ip_to_macs[src_ip][src_mac] += 1
        if dst_ip and dst_mac:
            ip_to_macs[dst_ip][dst_mac] += 1

    ip_map: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "ip": "",
        "mac": "",
        "vendor": "Constructeur inconnu",
        "session_count": 0,
        "packets": 0,
        "retransmissions": 0,
        "rst_count": 0,
        "half_open": 0,
        "score": 0,
        "possible_causes": set(),
    })

    for s in sessions[:1000]:
        if not isinstance(s, dict):
            continue
        src_raw = s.get("src", "")
        dst_raw = s.get("dst", "")
        src_ip, _ = _extract_ip_port(str(src_raw))
        dst_ip, _ = _extract_ip_port(str(dst_raw))
        pkt_count = _as_int(s.get("packets"), 0)
        retrans_count = _as_int(s.get("retransmissions"), 0)
        rst_count = _as_int(s.get("rst_count"), 0)
        state = str(s.get("state", "UNKNOWN")).upper()
        is_half_open = 1 if state in {"SYN_SENT", "SYN_RECEIVED"} else 0

        for ip in [src_ip, dst_ip]:
            if not ip:
                continue
            row = ip_map[ip]
            row["ip"] = ip
            row["session_count"] += 1
            row["packets"] += pkt_count
            row["retransmissions"] += retrans_count
            row["rst_count"] += rst_count
            row["half_open"] += is_half_open

            if retrans_count > 0:
                row["possible_causes"].add("Pertes réseau / congestion")
            if rst_count > 0:
                row["possible_causes"].add("Resets TCP fréquents")
            if is_half_open:
                row["possible_causes"].add("Connexions incomplètes")

    for item in suspicious_ips:
        if not isinstance(item, dict):
            continue
        ip = str(item.get("ip", "")).strip()
        if not ip:
            continue
        row = ip_map[ip]
        row["ip"] = ip
        row["score"] += _as_int(item.get("score"), 0)
        for anomaly_type in item.get("anomaly_types", []) if isinstance(item.get("anomaly_types", []), list) else []:
            row["possible_causes"].add(f"Anomalie: {anomaly_type}")

    problematic_ips = []
    for ip, row in ip_map.items():
        score = row["score"]
        score += row["retransmissions"] * 5
        score += row["rst_count"] * 2
        score += row["half_open"] * 8
        if row["packets"] > 0:
            score += min(20, int(row["packets"] / 100))
        row["score"] = score
        row["possible_causes"] = sorted(list(row["possible_causes"]))[:4]
        problematic_ips.append(row)

    problematic_ips.sort(key=lambda x: x.get("score", 0), reverse=True)
    problematic_ips = problematic_ips[:20]

    vendor_map: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"vendor": "", "score": 0, "ips": set(), "sessions": 0})
    mac_hotspots: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"mac": "", "vendor": "", "ips": set(), "score": 0})
    problematic_macs_count = 0

    for row in problematic_ips:
        ip = str(row.get("ip", "")).strip()
        mac_candidates = ip_to_macs.get(ip, {})
        if mac_candidates:
            mac, confidence_hits = max(mac_candidates.items(), key=lambda x: x[1])
            vendor = resolve_mac_vendor(mac)
            row["mac"] = mac
            row["vendor"] = vendor
            row["mac_hits"] = int(confidence_hits)
            problematic_macs_count += 1

            vendor_row = vendor_map[vendor]
            vendor_row["vendor"] = vendor
            vendor_row["score"] += _as_int(row.get("score"), 0)
            vendor_row["ips"].add(ip)
            vendor_row["sessions"] += _as_int(row.get("session_count"), 0)

            hotspot = mac_hotspots[mac]
            hotspot["mac"] = mac
            hotspot["vendor"] = vendor
            hotspot["ips"].add(ip)
            hotspot["score"] += _as_int(row.get("score"), 0)
        else:
            row["mac"] = "N/A"
            row["vendor"] = "Inconnu"
            row["mac_hits"] = 0

    problematic_vendors = sorted(
        [
            {
                "vendor": v["vendor"],
                "score": int(v["score"]),
                "ip_count": len(v["ips"]),
                "sessions": int(v["sessions"]),
            }
            for v in vendor_map.values()
            if v.get("vendor")
        ],
        key=lambda x: x["score"],
        reverse=True,
    )[:10]

    mac_hotspots_top = sorted(
        [
            {
                "mac": h["mac"],
                "vendor": h["vendor"] or "Inconnu",
                "ip_count": len(h["ips"]),
                "score": int(h["score"]),
            }
            for h in mac_hotspots.values()
            if h.get("mac")
        ],
        key=lambda x: x["score"],
        reverse=True,
    )[:10]

    root_cause_matrix = []
    for row in problematic_ips[:20]:
        causes = row.get("possible_causes", []) if isinstance(row.get("possible_causes", []), list) else []
        top_cause = causes[0] if causes else "A surveiller"
        evidence_parts = [
            f"sessions={_as_int(row.get('session_count'), 0)}",
            f"retrans={_as_int(row.get('retransmissions'), 0)}",
            f"rst={_as_int(row.get('rst_count'), 0)}",
            f"packets={_as_int(row.get('packets'), 0)}",
        ]
        if _as_int(row.get("half_open"), 0) > 0:
            evidence_parts.append(f"half-open={_as_int(row.get('half_open'), 0)}")
        confidence = min(100, max(0, int(_as_int(row.get("score"), 0) * 1.3)))
        root_cause_matrix.append({
            "culprit": row.get("ip", ""),
            "mac": row.get("mac", "N/A"),
            "vendor": row.get("vendor", "Inconnu"),
            "top_cause": top_cause,
            "evidence": ", ".join(evidence_parts),
            "confidence": confidence,
            "score": _as_int(row.get("score"), 0),
        })

    root_cause_matrix.sort(key=lambda x: (_as_int(x.get("confidence"), 0), _as_int(x.get("score"), 0)), reverse=True)

    broadcast_packets = _as_int(mac_stats.get("broadcast_packets"), 0)
    multicast_packets = _as_int(mac_stats.get("multicast_packets"), 0)
    locally_administered_packets = _as_int(mac_stats.get("locally_administered_packets"), 0)
    broadcast_pct = round((broadcast_packets / total_packets * 100.0), 3) if total_packets > 0 else 0.0
    multicast_pct = round((multicast_packets / total_packets * 100.0), 3) if total_packets > 0 else 0.0

    bottleneck_score = 0
    if retrans_rate >= 5:
        bottleneck_score += 35
    elif retrans_rate >= 2:
        bottleneck_score += 22
    elif retrans_rate > 0:
        bottleneck_score += 8

    if zero_window_pct >= 1:
        bottleneck_score += 35
    elif zero_window_count > 0:
        bottleneck_score += 20

    if avg_rtt_ms >= 150:
        bottleneck_score += 20
    elif avg_rtt_ms >= 80:
        bottleneck_score += 12
    elif avg_rtt_ms >= 40:
        bottleneck_score += 6

    if len(bursts) >= 3:
        bottleneck_score += 15
    elif len(bursts) > 0:
        bottleneck_score += 8

    bottleneck_score = min(100, bottleneck_score)
    bottleneck_level = (
        "CRITIQUE" if bottleneck_score >= 70
        else "ÉLEVÉ" if bottleneck_score >= 45
        else "MODÉRÉ" if bottleneck_score >= 20
        else "FAIBLE"
    )

    health_score = 100.0
    if rtt_p95_ms >= 200:
        health_score -= 22
    elif rtt_p95_ms >= 120:
        health_score -= 14
    elif rtt_p95_ms >= 60:
        health_score -= 8

    if rtt_jitter_ms >= 35:
        health_score -= 18
    elif rtt_jitter_ms >= 18:
        health_score -= 10
    elif rtt_jitter_ms >= 8:
        health_score -= 5

    if retrans_rate >= 5:
        health_score -= 22
    elif retrans_rate >= 2:
        health_score -= 14
    elif retrans_rate > 0:
        health_score -= 8

    if zero_window_pct >= 1:
        health_score -= 16
    elif zero_window_count > 0:
        health_score -= 8

    if half_open_pct >= 5:
        health_score -= 10
    elif half_open_pct >= 2:
        health_score -= 5

    health_score -= min(20, bottleneck_score * 0.14)
    health_score = max(0.0, min(100.0, health_score))

    probable_issues: List[Dict[str, Any]] = []
    recommendations: List[str] = []

    if zero_window_count > 0:
        probable_issues.append({
            "title": "Fenêtres TCP nulles (Zero Window)",
            "severity": "HIGH" if zero_window_pct >= 1 else "MEDIUM",
            "details": f"{zero_window_count} événements ({zero_window_pct:.2f}%) indiquent un récepteur saturé.",
            "impact": "Ralentissements intermittents, blocages applicatifs.",
        })
        recommendations.append("Vérifier saturation CPU/RAM buffer TCP sur les hôtes récepteurs.")

    if retrans_rate > 0:
        probable_issues.append({
            "title": "Retransmissions TCP",
            "severity": "HIGH" if retrans_rate >= 5 else "MEDIUM" if retrans_rate >= 2 else "LOW",
            "details": f"Taux de retransmission: {retrans_rate:.2f}%, total: {total_retrans}.",
            "impact": "Augmentation latence, baisse de débit, timeout.",
        })
        recommendations.append("Contrôler pertes de paquets, interfaces saturées et qualité de lien.")

    if avg_rtt_ms >= 40:
        probable_issues.append({
            "title": "Latence RTT élevée",
            "severity": "HIGH" if avg_rtt_ms >= 150 else "MEDIUM",
            "details": f"RTT moyen {avg_rtt_ms:.2f} ms (max {max_rtt_ms:.2f} ms).",
            "impact": "Temps de réponse applicatif dégradé.",
        })
        recommendations.append("Traceroute + vérification des sauts WAN/Internet et files d'attente QoS.")

    if handshake_success_rate > 0 and handshake_success_rate < 95:
        probable_issues.append({
            "title": "Taux de handshake TCP dégradé",
            "severity": "HIGH" if handshake_success_rate < 85 else "MEDIUM",
            "details": (
                f"Succès handshake: {handshake_success_rate:.2f}% "
                f"(complets: {complete_handshakes}, incomplets: {incomplete_handshakes})."
            ),
            "impact": "Connexions instables, refus applicatifs intermittents, timeouts à l'établissement.",
        })
        recommendations.append("Analyser SYN/SYN-ACK perdus, filtrage stateful intermédiaire et saturation listener côté serveur.")

    if half_open_connections > 0 and half_open_pct >= 2:
        probable_issues.append({
            "title": "Excès de connexions half-open",
            "severity": "HIGH" if half_open_pct >= 5 else "MEDIUM",
            "details": f"{half_open_connections} sessions half-open ({half_open_pct:.2f}% des sessions TCP).",
            "impact": "Risque de backlog saturation, délais de connexion et erreurs SYN timeout.",
        })
        recommendations.append("Vérifier backlog TCP serveur, SYN cookies, ACL/firewall et pertes sur le chemin aller/retour.")

    if sessions_with_rst_pct >= 5:
        probable_issues.append({
            "title": "Taux de sessions avec RST élevé",
            "severity": "HIGH" if sessions_with_rst_pct >= 12 else "MEDIUM",
            "details": (
                f"{sessions_with_rst} sessions avec reset ({sessions_with_rst_pct:.2f}%). "
                f"RST initiateur: {rst_by_initiator}, responder: {rst_by_responder}."
            ),
            "impact": "Coupures de flux, transactions interrompues, instabilité applicative.",
        })
        recommendations.append("Corréler les resets avec politiques firewall/IDS et erreurs applicatives côté client/serveur.")

    if bursts:
        max_burst_pps = max(_as_int(b.get("packets_per_second"), 0) for b in bursts)
        probable_issues.append({
            "title": "Bursts de trafic",
            "severity": "MEDIUM" if len(bursts) < 5 else "HIGH",
            "details": (
                f"{len(bursts)} pics détectés, pic max {max_burst_pps} paquets/s, "
                f"densité {bursts_per_minute:.2f} burst/min."
            ),
            "impact": "Micro-congestions et variations de latence.",
        })
        recommendations.append("Appliquer shaping/policing QoS sur flux bavards et lisser les envois.")

    if broadcast_pct >= 2:
        probable_issues.append({
            "title": "Trafic Broadcast/Multicast élevé",
            "severity": "HIGH" if broadcast_pct >= 8 else "MEDIUM",
            "details": (
                f"Broadcast: {broadcast_packets} paquets ({broadcast_pct:.2f}%), "
                f"Multicast: {multicast_packets} paquets ({multicast_pct:.2f}%)."
            ),
            "impact": "Risque de tempête L2, contention sur segments partagés, latence variable.",
        })
        recommendations.append("Contrôler STP, ARP/mDNS/LLMNR, et limiter le bruit broadcast sur VLANs.")

    if mac_hotspots_top:
        primary_hotspot = mac_hotspots_top[0]
        if _as_int(primary_hotspot.get("ip_count"), 0) >= 2:
            probable_issues.append({
                "title": "Concentration des symptômes sur un même équipement",
                "severity": "HIGH" if _as_int(primary_hotspot.get("ip_count"), 0) >= 3 else "MEDIUM",
                "details": (
                    f"MAC {primary_hotspot.get('mac')} ({primary_hotspot.get('vendor')}) corrélée à "
                    f"{primary_hotspot.get('ip_count')} IP(s) problématiques."
                ),
                "impact": "Goulot potentiel sur passerelle/firewall/switch ou hôte pivot saturé.",
            })
            recommendations.append("Vérifier l'équipement MAC principal: interfaces, erreurs, files et CPU.")

    probable_issues.append({
        "title": "Indice global de santé TCP",
        "severity": "HIGH" if health_score < 45 else ("MEDIUM" if health_score < 70 else "LOW"),
        "details": (
            f"Health score {health_score:.1f}/100, p95 RTT {rtt_p95_ms:.2f} ms, jitter {rtt_jitter_ms:.2f} ms, "
            f"throughput moyen {avg_throughput_mbps:.3f} Mbps."
        ),
        "impact": "Permet de quantifier rapidement la dégradation globale des flux TCP.",
    })

    if not probable_issues:
        probable_issues.append({
            "title": "Aucune dégradation majeure détectée",
            "severity": "LOW",
            "details": "Les métriques TCP analysées restent dans des plages nominales.",
            "impact": "Pas de symptôme critique visible.",
        })
        recommendations.append("Surveiller en continu RTT/retransmissions pour capter les dérives.")

    recommendations.append("Analyser en priorité les IPs du top problématique pour isoler la cause racine.")
    recommendations = list(dict.fromkeys(recommendations))[:8]

    return {
        "summary": {
            "total_sessions": total_sessions,
            "total_retransmissions": total_retrans,
            "retransmission_rate": round(retrans_rate, 3),
            "avg_rtt_ms": round(avg_rtt_ms, 3),
            "rtt_p50_ms": rtt_p50_ms,
            "rtt_p95_ms": rtt_p95_ms,
            "rtt_p99_ms": rtt_p99_ms,
            "rtt_jitter_ms": rtt_jitter_ms,
            "max_rtt_ms": round(max_rtt_ms, 3),
            "avg_window": avg_window,
            "zero_window_count": zero_window_count,
            "zero_window_percentage": round(zero_window_pct, 3),
            "half_open_connections": half_open_connections,
            "half_open_percentage": half_open_pct,
            "sessions_with_retransmissions": sessions_with_retrans,
            "sessions_with_retransmission_pct": sessions_with_retrans_pct,
            "sessions_with_rst": sessions_with_rst,
            "sessions_with_rst_pct": sessions_with_rst_pct,
            "handshake_success_rate": round(handshake_success_rate, 3),
            "complete_handshakes": complete_handshakes,
            "incomplete_handshakes": incomplete_handshakes,
            "bursts_count": len(bursts),
            "bursts_per_minute": bursts_per_minute,
            "bottleneck_score": bottleneck_score,
            "bottleneck_level": bottleneck_level,
            "window_pressure_score": window_pressure_score,
            "window_pressure_level": window_pressure_level,
            "problematic_ips_count": len(problematic_ips),
            "problematic_macs_count": problematic_macs_count,
            "broadcast_packets": broadcast_packets,
            "broadcast_percentage": broadcast_pct,
            "multicast_packets": multicast_packets,
            "multicast_percentage": multicast_pct,
            "locally_administered_packets": locally_administered_packets,
            "capture_duration_seconds": round(capture_duration_seconds, 3),
            "session_duration_avg_s": session_duration_avg_s,
            "session_duration_p95_s": session_duration_p95_s,
            "session_duration_max_s": session_duration_max_s,
            "rtt_range_ms": round(rtt_range_ms, 3),
            "window_range": window_range,
            "effective_avg_window": effective_avg_window,
            "effective_min_window": effective_min_window,
            "effective_max_window": effective_max_window,
            "window_scale_min": window_scale_min,
            "window_scale_max": window_scale_max,
            "window_scale_avg": round(window_scale_avg, 3),
            "window_scale_p95": round(window_scale_p95, 3),
            "window_scale_observed_sessions": window_scale_observed_sessions,
            "window_scale_observed_directions": window_scale_observed_directions,
            "window_scale_coverage_pct": round(window_scale_coverage_pct, 3),
            "avg_pps": avg_pps,
            "peak_pps": peak_pps,
            "avg_throughput_mbps": avg_throughput_mbps,
            "peak_throughput_mbps": peak_throughput_mbps,
            "health_score": round(health_score, 1),
        },
        "window_metrics": {
            "min_window": min_window,
            "max_window": max_window,
            "avg_window": avg_window,
            "zero_window_count": zero_window_count,
            "zero_window_percentage": round(zero_window_pct, 3),
            "window_range": window_range,
            "window_pressure_score": window_pressure_score,
            "window_pressure_level": window_pressure_level,
            "effective_avg_window": effective_avg_window,
            "effective_min_window": effective_min_window,
            "effective_max_window": effective_max_window,
            "window_scale_min": window_scale_min,
            "window_scale_max": window_scale_max,
            "window_scale_avg": round(window_scale_avg, 3),
            "window_scale_p95": round(window_scale_p95, 3),
            "window_scale_observed_sessions": window_scale_observed_sessions,
            "window_scale_observed_directions": window_scale_observed_directions,
            "window_scale_coverage_pct": round(window_scale_coverage_pct, 3),
        },
        "rtt_metrics": {
            "samples_count": _as_int(rtt.get("samples_count"), 0),
            "min_rtt_ms": round(min_rtt_ms, 3),
            "max_rtt_ms": round(max_rtt_ms, 3),
            "avg_rtt_ms": round(avg_rtt_ms, 3),
            "p50_rtt_ms": rtt_p50_ms,
            "p95_rtt_ms": rtt_p95_ms,
            "p99_rtt_ms": rtt_p99_ms,
            "jitter_ms": rtt_jitter_ms,
            "range_ms": round(rtt_range_ms, 3),
        },
        "advanced_metrics": {
            "handshake_success_rate": round(handshake_success_rate, 3),
            "complete_handshakes": complete_handshakes,
            "incomplete_handshakes": incomplete_handshakes,
            "sessions_with_retransmissions": sessions_with_retrans,
            "sessions_with_retransmission_pct": sessions_with_retrans_pct,
            "sessions_with_rst": sessions_with_rst,
            "sessions_with_rst_pct": sessions_with_rst_pct,
            "rst_by_initiator": rst_by_initiator,
            "rst_by_responder": rst_by_responder,
            "half_open_connections": half_open_connections,
            "half_open_percentage": half_open_pct,
            "capture_duration_seconds": round(capture_duration_seconds, 3),
            "bursts_per_minute": bursts_per_minute,
            "avg_pps": avg_pps,
            "peak_pps": peak_pps,
            "avg_throughput_mbps": avg_throughput_mbps,
            "peak_throughput_mbps": peak_throughput_mbps,
            "health_score": round(health_score, 1),
            "session_duration": {
                "avg_seconds": session_duration_avg_s,
                "p95_seconds": session_duration_p95_s,
                "max_seconds": session_duration_max_s,
            },
            "stability": {
                "rtt_range_ms": round(rtt_range_ms, 3),
                "rtt_jitter_ms": rtt_jitter_ms,
                "window_range": window_range,
                "window_pressure_score": window_pressure_score,
                "window_pressure_level": window_pressure_level,
                "window_scale_avg": round(window_scale_avg, 3),
                "window_scale_p95": round(window_scale_p95, 3),
                "window_scale_coverage_pct": round(window_scale_coverage_pct, 3),
                "effective_avg_window": effective_avg_window,
            },
            "connection_states": connection_states,
        },
        "bursts": bursts[:30],
        "volumetry_timeseries": volumetry_timeseries[:1200],
        "problematic_ips": problematic_ips,
        "problematic_vendors": problematic_vendors,
        "mac_hotspots": mac_hotspots_top,
        "root_cause_matrix": root_cause_matrix[:30],
        "top_retransmitting_sessions": (retrans.get("top_retransmitting_sessions", []) if isinstance(retrans.get("top_retransmitting_sessions", []), list) else [])[:15],
        "probable_issues": probable_issues,
        "recommendations": recommendations,
    }


# ── Feature 7: TLS Security Audit ──
@additional_router.get("/{task_id}/tls-audit")
def get_tls_audit(task_id: str):
    """Feature 7: SSL Labs-style audit with JA3 malware matching"""
    from app.analyzers.tls_analyzer import TLSAnalyzer
    from app.analyzers.tls_security_auditor import TLSSecurityAuditor
    results = storage_service.load_results(task_id)
    if not results:
        raise HTTPException(status_code=404, detail="Task non trouvé")

    cached = storage_service.load_derived(task_id, "tls_audit")
    if cached is not None:
        return cached
    try:
        import warnings
        warnings.filterwarnings("ignore", message=".*TLS cipher suite not usable.*")
        warnings.filterwarnings("ignore", message=".*Unknown cipher suite.*")
        has_cryptography = True
        try:
            import cryptography  # type: ignore # noqa: F401
        except Exception:
            has_cryptography = False
        import logging
        from scapy.all import rdpcap, IP, IPv6, TCP, Raw  # type: ignore
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        logging.getLogger("scapy.loading").setLevel(logging.ERROR)
        pcap_path = storage_service.get_pcap_path(task_id)
        if not pcap_path:
            return {
                "grade": "N/A",
                "overall_score": 0,
                "summary": {"total_sessions_audited": 0},
                "critical_findings": [],
                "warnings": [],
                "recommendations": [],
                "malware_ja3_matches": [],
                "top_cipher_suites": [],
                "tls_session_catalog": [],
                "tcp_handshake_summary": {},
            }
        packets = rdpcap(pcap_path)
        tls_analyzer = TLSAnalyzer()
        tls_results = tls_analyzer.analyze(packets)
        auditor = TLSSecurityAuditor()
        audit = auditor.audit(tls_results)

        tcp = results.get("tcp_analysis", {}) if isinstance(results.get("tcp_analysis", {}), dict) else {}
        tcp_sessions = tcp.get("sessions", []) if isinstance(tcp.get("sessions", []), list) else []
        tcp_handshake = tcp.get("handshake_analysis", {}) if isinstance(tcp.get("handshake_analysis", {}), dict) else {}
        tcp_retrans = tcp.get("retransmission_analysis", {}) if isinstance(tcp.get("retransmission_analysis", {}), dict) else {}
        tcp_rst = tcp.get("rst_analysis", {}) if isinstance(tcp.get("rst_analysis", {}), dict) else {}
        malware_ja3_set = {
            str(m.get("ja3", "")).strip()
            for m in (audit.get("malware_ja3_matches", []) if isinstance(audit.get("malware_ja3_matches", []), list) else [])
            if str(m.get("ja3", "")).strip()
        }

        def _risk_rank(level: str) -> int:
            value = str(level or "").upper()
            if value == "HIGH":
                return 3
            if value == "MEDIUM":
                return 2
            return 1

        def _max_risk(a: str, b: str) -> str:
            return a if _risk_rank(a) >= _risk_rank(b) else b

        def _transport_risk(
            syn: int,
            syn_ack: int,
            ack: int,
            retrans: int,
            rst_count: int,
        ) -> Tuple[str, List[str], bool]:
            reasons: List[str] = []
            complete = syn > 0 and syn_ack > 0 and ack > 0
            if rst_count > 0:
                reasons.append(f"RST observés ({rst_count})")
            if retrans >= 3:
                reasons.append(f"Retransmissions élevées ({retrans} ≥ 3)")
            elif retrans > 0:
                reasons.append(f"Retransmissions présentes ({retrans})")
            if not complete:
                if syn == 0 and syn_ack == 0 and ack > 0:
                    reasons.append("Capture démarrée en cours de session (SYN/SYN-ACK non vus)")
                else:
                    reasons.append("3-way handshake incomplet")

            if rst_count > 0 or retrans >= 3:
                level = "HIGH"
            elif not complete:
                level = "MEDIUM" if (syn == 0 and syn_ack == 0 and ack > 0) else "HIGH"
            elif retrans > 0:
                level = "MEDIUM"
            else:
                level = "LOW"
            return level, reasons, complete

        def _security_risk(session: Dict[str, Any], fallback_mode: bool) -> Tuple[str, List[str]]:
            reasons: List[str] = []
            ja3 = str(session.get("ja3", "") or "").strip()
            tls_version_raw = str(session.get("tls_version", "") or "").strip()
            cipher_raw = str(session.get("cipher", "") or "").strip()
            tls_version = tls_version_raw.upper().replace(" ", "")
            cipher_u = cipher_raw.upper()

            deprecated_versions = {"SSLV2", "SSLV3", "TLSV1.0", "TLSV1.1", "TLS1.0", "TLS1.1"}
            weak_tokens = ("NULL", "RC4", "3DES", " DES", "DES_", "EXPORT", "MD5")

            is_malware_ja3 = ja3 in malware_ja3_set if ja3 else False
            is_deprecated = tls_version in deprecated_versions
            is_weak_cipher = bool(cipher_u) and any(token in cipher_u for token in weak_tokens)
            unknown_crypto = tls_version in {"", "UNKNOWN", "N/A"} or cipher_u in {"", "UNKNOWN", "N/A"}

            if is_malware_ja3:
                reasons.append("JA3 match avec signature malware")
            if is_deprecated:
                reasons.append(f"Version TLS dépréciée ({tls_version_raw or 'Unknown'})")
            if is_weak_cipher:
                reasons.append(f"Cipher faible ({cipher_raw or 'Unknown'})")
            if unknown_crypto and fallback_mode:
                reasons.append("Métadonnées TLS incomplètes (mode fallback)")

            if is_malware_ja3 or is_deprecated or is_weak_cipher:
                level = "HIGH"
            elif unknown_crypto:
                level = "MEDIUM"
            else:
                level = "LOW"
            return level, reasons

        def _split_endpoint(endpoint: str) -> Tuple[str, int]:
            txt = str(endpoint or "").strip()
            if not txt:
                return "", 0
            if ":" not in txt:
                return txt, 0
            ip, port = txt.rsplit(":", 1)
            return ip, _as_int(port, 0)

        def _canon_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
            pair = sorted([(str(src_ip), int(src_port)), (str(dst_ip), int(dst_port))])
            return f"{pair[0][0]}:{pair[0][1]}<->{pair[1][0]}:{pair[1][1]}"

        tcp_by_flow: Dict[str, Dict[str, Any]] = {}
        for sess in tcp_sessions[:500]:
            src_ip, src_port = _split_endpoint(sess.get("src", ""))
            dst_ip, dst_port = _split_endpoint(sess.get("dst", ""))
            if not src_ip or not dst_ip:
                continue
            tcp_by_flow[_canon_key(src_ip, src_port, dst_ip, dst_port)] = sess

        tls_catalog: List[Dict[str, Any]] = []
        for idx, sess in enumerate((tls_results.get("sessions", []) if isinstance(tls_results.get("sessions", []), list) else [])[:120]):
            src_ip = str(sess.get("src_ip", "")).strip()
            dst_ip = str(sess.get("dst_ip", "")).strip()
            src_port = _as_int(sess.get("src_port"), 0)
            dst_port = _as_int(sess.get("dst_port"), 0)
            flow_key = _canon_key(src_ip, src_port, dst_ip, dst_port)
            tcp_sess = tcp_by_flow.get(flow_key, {})
            flags = tcp_sess.get("flags", {}) if isinstance(tcp_sess.get("flags", {}), dict) else {}
            syn = _as_int(flags.get("syn"), 0)
            syn_ack = _as_int(flags.get("syn_ack"), 0)
            ack = _as_int(flags.get("ack"), 0)
            complete = syn > 0 and syn_ack > 0 and ack > 0
            state = str(tcp_sess.get("state", "UNKNOWN"))
            duration_s = _as_float(tcp_sess.get("duration"), 0.0)
            retrans = _as_int(tcp_sess.get("retransmissions"), 0)
            rst = _as_int(tcp_sess.get("rst_count"), 0)

            # Estimation handshake RTT: si pas de mesure explicite, approximation légère.
            est_handshake_ms = 0.0
            if complete:
                est_handshake_ms = round(max(0.5, min(2500.0, (duration_s * 1000.0) * 0.12)), 3)
            elif syn > 0:
                est_handshake_ms = round(max(1.0, min(3000.0, (duration_s * 1000.0) * 0.25)), 3)

            tls_catalog.append({
                "session_id": f"tls-{idx + 1}",
                "flow": f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "sni": sess.get("sni"),
                "ja3": sess.get("ja3"),
                "ja3s": sess.get("ja3s"),
                "tls_version": sess.get("negotiated_version"),
                "cipher": sess.get("negotiated_cipher"),
                "timestamp": sess.get("timestamp"),
                "tcp_state": state,
                "tcp_retransmissions": retrans,
                "tcp_rst": rst,
                "duration_s": duration_s,
                "handshake_flags": {
                    "syn": syn,
                    "syn_ack": syn_ack,
                    "ack": ack,
                    "complete": complete,
                },
                "handshake_rtt_ms_est": est_handshake_ms,
                "risk_level": (
                    "HIGH" if rst > 0 or retrans >= 3 or not complete
                    else ("MEDIUM" if retrans > 0 else "LOW")
                ),
            })

        tls_catalog.sort(
            key=lambda x: (
                2 if x.get("risk_level") == "HIGH" else (1 if x.get("risk_level") == "MEDIUM" else 0),
                _as_int(x.get("tcp_retransmissions"), 0),
                _as_int(x.get("tcp_rst"), 0),
            ),
            reverse=True,
        )

        # Fallback si la détection TLS fine est vide (cas capture partielle / limites dissector TLS).
        # 1) Corrélation depuis tcp_analysis
        if not tls_catalog:
            fallback_ports = {443, 8443, 9443, 993, 995, 465}
            for idx, sess in enumerate(tcp_sessions[:600]):
                src_ip, src_port = _split_endpoint(sess.get("src", ""))
                dst_ip, dst_port = _split_endpoint(sess.get("dst", ""))
                if not src_ip or not dst_ip:
                    continue
                if src_port not in fallback_ports and dst_port not in fallback_ports:
                    continue
                flags = sess.get("flags", {}) if isinstance(sess.get("flags", {}), dict) else {}
                syn = _as_int(flags.get("syn"), 0)
                syn_ack = _as_int(flags.get("syn_ack"), 0)
                ack = _as_int(flags.get("ack"), 0)
                complete = syn > 0 and syn_ack > 0 and ack > 0
                retrans = _as_int(sess.get("retransmissions"), 0)
                rst = _as_int(sess.get("rst_count"), 0)
                duration_s = _as_float(sess.get("duration"), 0.0)

                tls_catalog.append({
                    "session_id": f"tls-fb-{idx + 1}",
                    "flow": f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "sni": None,
                    "ja3": None,
                    "ja3s": None,
                    "tls_version": "Unknown",
                    "cipher": "Unknown",
                    "timestamp": None,
                    "tcp_state": str(sess.get("state", "UNKNOWN")),
                    "tcp_retransmissions": retrans,
                    "tcp_rst": rst,
                    "duration_s": duration_s,
                    "handshake_flags": {
                        "syn": syn,
                        "syn_ack": syn_ack,
                        "ack": ack,
                        "complete": complete,
                    },
                    "handshake_rtt_ms_est": round(max(0.8, min(3000.0, duration_s * 120.0)), 3) if complete else 0.0,
                    "risk_level": (
                        "HIGH" if rst > 0 or retrans >= 3 or not complete
                        else ("MEDIUM" if retrans > 0 else "LOW")
                    ),
                })

            if tls_catalog:
                audit.setdefault("warnings", [])
                audit["warnings"].append(
                    "Catalogue TLS construit en mode fallback TCP (ports TLS usuels) — parser TLS limité sur cette capture."
                )

        # 2) Fallback de dernier recours: reconstruction légère depuis les paquets TCP eux-mêmes.
        if not tls_catalog:
            fallback_ports = {443, 8443, 9443, 993, 995, 465}
            flow_map: Dict[str, Dict[str, Any]] = {}
            for pkt in packets[:250000]:
                try:
                    if not hasattr(pkt, "haslayer") or not pkt.haslayer(TCP):
                        continue
                    ip_layer = IP if pkt.haslayer(IP) else (IPv6 if pkt.haslayer(IPv6) else None)
                    if ip_layer is None:
                        continue
                    src_ip = str(pkt[ip_layer].src)
                    dst_ip = str(pkt[ip_layer].dst)
                    src_port = int(getattr(pkt[TCP], "sport", 0))
                    dst_port = int(getattr(pkt[TCP], "dport", 0))
                    if src_port not in fallback_ports and dst_port not in fallback_ports:
                        continue

                    ts = _as_float(getattr(pkt, "time", 0.0), 0.0)
                    flags_int = int(getattr(pkt[TCP], "flags", 0))
                    syn = 1 if (flags_int & 0x02) else 0
                    ack = 1 if (flags_int & 0x10) else 0
                    rst = 1 if (flags_int & 0x04) else 0
                    syn_ack = 1 if (syn and ack) else 0
                    syn_only = 1 if (syn and not ack) else 0
                    ack_only = 1 if (ack and not syn) else 0

                    payload_len = 0
                    if pkt.haslayer(Raw):
                        payload_len = len(bytes(getattr(pkt[Raw], "load", b"")))
                    is_tls_payload = payload_len > 0 and src_port != 0 and dst_port != 0
                    if is_tls_payload:
                        try:
                            blob = bytes(getattr(pkt[Raw], "load", b""))
                            is_tls_payload = len(blob) >= 3 and blob[0] in (20, 21, 22, 23) and blob[1] == 0x03
                        except Exception:
                            is_tls_payload = payload_len > 0

                    key = _canon_key(src_ip, src_port, dst_ip, dst_port)
                    row = flow_map.get(key)
                    if row is None:
                        row = {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "first_ts": ts,
                            "last_ts": ts,
                            "packet_count": 0,
                            "syn": 0,
                            "syn_ack": 0,
                            "ack": 0,
                            "rst": 0,
                            "tls_payload_hits": 0,
                        }
                        flow_map[key] = row

                    row["packet_count"] += 1
                    row["first_ts"] = min(_as_float(row.get("first_ts"), ts), ts) if ts else _as_float(row.get("first_ts"), ts)
                    row["last_ts"] = max(_as_float(row.get("last_ts"), ts), ts)
                    row["syn"] += syn_only
                    row["syn_ack"] += syn_ack
                    row["ack"] += ack_only
                    row["rst"] += rst
                    if is_tls_payload:
                        row["tls_payload_hits"] += 1
                except Exception:
                    continue

            rebuilt = []
            for idx, row in enumerate(flow_map.values()):
                complete = _as_int(row.get("syn"), 0) > 0 and _as_int(row.get("syn_ack"), 0) > 0 and _as_int(row.get("ack"), 0) > 0
                duration_s = max(0.0, _as_float(row.get("last_ts"), 0.0) - _as_float(row.get("first_ts"), 0.0))
                rst_count = _as_int(row.get("rst"), 0)
                tls_hits = _as_int(row.get("tls_payload_hits"), 0)
                rebuilt.append({
                    "session_id": f"tls-rb-{idx + 1}",
                    "flow": f"{row.get('src_ip')}:{row.get('src_port')} -> {row.get('dst_ip')}:{row.get('dst_port')}",
                    "src_ip": row.get("src_ip"),
                    "dst_ip": row.get("dst_ip"),
                    "src_port": _as_int(row.get("src_port"), 0),
                    "dst_port": _as_int(row.get("dst_port"), 0),
                    "sni": None,
                    "ja3": None,
                    "ja3s": None,
                    "tls_version": "Unknown",
                    "cipher": "Unknown",
                    "timestamp": _as_float(row.get("first_ts"), 0.0) or None,
                    "tcp_state": "ESTABLISHED" if complete else "PARTIAL",
                    "tcp_retransmissions": 0,
                    "tcp_rst": rst_count,
                    "duration_s": duration_s,
                    "handshake_flags": {
                        "syn": _as_int(row.get("syn"), 0),
                        "syn_ack": _as_int(row.get("syn_ack"), 0),
                        "ack": _as_int(row.get("ack"), 0),
                        "complete": complete,
                    },
                    "handshake_rtt_ms_est": round(max(0.8, min(3000.0, duration_s * 120.0)), 3) if complete else 0.0,
                    "risk_level": (
                        "HIGH" if rst_count > 0 or not complete
                        else ("MEDIUM" if tls_hits <= 1 else "LOW")
                    ),
                })
            rebuilt.sort(
                key=lambda x: (
                    2 if x.get("risk_level") == "HIGH" else (1 if x.get("risk_level") == "MEDIUM" else 0),
                    _as_int(x.get("tcp_rst"), 0),
                    _as_float(x.get("duration_s"), 0.0),
                ),
                reverse=True,
            )
            tls_catalog = rebuilt[:120]
            if tls_catalog:
                audit.setdefault("warnings", [])
                audit["warnings"].append(
                    "Catalogue TLS reconstruit depuis les paquets TCP (fallback bas niveau) — parsing TLS indisponible/partiel."
                )

        for sess in tls_catalog:
            flags = sess.get("handshake_flags", {}) if isinstance(sess.get("handshake_flags", {}), dict) else {}
            syn = _as_int(flags.get("syn"), 0)
            syn_ack = _as_int(flags.get("syn_ack"), 0)
            ack = _as_int(flags.get("ack"), 0)
            retrans = _as_int(sess.get("tcp_retransmissions"), 0)
            rst_count = _as_int(sess.get("tcp_rst"), 0)
            transport_level, transport_reasons, complete = _transport_risk(syn, syn_ack, ack, retrans, rst_count)
            flags["complete"] = complete
            sess["handshake_flags"] = flags

            fallback_mode = str(sess.get("tls_version", "") or "").strip().lower() == "unknown"
            security_level, security_reasons = _security_risk(sess, fallback_mode=fallback_mode)
            overall_level = _max_risk(transport_level, security_level)

            sess["transport_risk_level"] = transport_level
            sess["transport_risk_reasons"] = transport_reasons
            sess["security_risk_level"] = security_level
            sess["security_risk_reasons"] = security_reasons
            sess["overall_risk_level"] = overall_level
            # Compat frontend existant
            sess["risk_level"] = transport_level

        high_risk = len([s for s in tls_catalog if s.get("overall_risk_level") == "HIGH"])
        med_risk = len([s for s in tls_catalog if s.get("overall_risk_level") == "MEDIUM"])
        low_risk = len([s for s in tls_catalog if s.get("overall_risk_level") == "LOW"])
        transport_high = len([s for s in tls_catalog if s.get("transport_risk_level") == "HIGH"])
        transport_med = len([s for s in tls_catalog if s.get("transport_risk_level") == "MEDIUM"])
        transport_low = len([s for s in tls_catalog if s.get("transport_risk_level") == "LOW"])
        security_high = len([s for s in tls_catalog if s.get("security_risk_level") == "HIGH"])
        security_med = len([s for s in tls_catalog if s.get("security_risk_level") == "MEDIUM"])
        security_low = len([s for s in tls_catalog if s.get("security_risk_level") == "LOW"])
        handshake_ms = [_as_float(s.get("handshake_rtt_ms_est"), 0.0) for s in tls_catalog if _as_float(s.get("handshake_rtt_ms_est"), 0.0) > 0]
        handshake_avg = round(sum(handshake_ms) / len(handshake_ms), 3) if handshake_ms else 0.0
        handshake_p95 = round(_percentile(handshake_ms, 95.0), 3) if handshake_ms else 0.0

        audit["tls_session_catalog"] = tls_catalog[:120]
        audit.setdefault("summary", {})
        audit["summary"]["total_sessions_audited"] = max(
            _as_int(audit["summary"].get("total_sessions_audited"), 0),
            len(audit["tls_session_catalog"]),
        )
        audit["tcp_handshake_summary"] = {
            "complete_handshakes": _as_int(tcp_handshake.get("complete_handshakes"), 0),
            "incomplete_handshakes": _as_int(tcp_handshake.get("incomplete_handshakes"), 0),
            "handshake_success_rate": _as_float(tcp_handshake.get("handshake_success_rate"), 0.0),
            "total_rst_packets": _as_int(tcp_rst.get("total_rst_packets"), 0),
            "sessions_with_retransmissions": _as_int(tcp_retrans.get("sessions_with_retransmissions"), 0),
            "handshake_rtt_ms_avg_est": handshake_avg,
            "handshake_rtt_ms_p95_est": handshake_p95,
            "risk_distribution": {
                "high": high_risk,
                "medium": med_risk,
                "low": low_risk,
            },
            "transport_risk_distribution": {
                "high": transport_high,
                "medium": transport_med,
                "low": transport_low,
            },
            "security_risk_distribution": {
                "high": security_high,
                "medium": security_med,
                "low": security_low,
            },
        }
        if not has_cryptography:
            audit.setdefault("warnings", [])
            audit["warnings"].append(
                "Le module Python 'cryptography' semble absent: décodage TLS partiel (certains ciphers non résolus)."
            )
        storage_service.save_derived(task_id, "tls_audit", audit)
        return audit
    except Exception as e:
        logger.error(f"tls_audit error: {e}")
        return {
            "grade": "N/A",
            "overall_score": 0,
            "summary": {"total_sessions_audited": 0, "warning": str(e)},
            "critical_findings": [],
            "warnings": [str(e)],
            "recommendations": [],
            "malware_ja3_matches": [],
            "top_cipher_suites": [],
            "tls_session_catalog": [],
            "tcp_handshake_summary": {},
        }


# ── Feature 8: IR Playbook ──
class PlaybookRequest(BaseModel):
    incident_types: Optional[List[str]] = None

@additional_router.post("/{task_id}/generate-playbook")
async def generate_playbook(task_id: str, request: Optional[PlaybookRequest] = None):
    """Feature 8: Generate incident response playbook from analysis results"""
    from app.services.ir_playbook_service import IRPlaybookGenerator
    results = storage_service.load_results(task_id)
    if not results:
        raise HTTPException(status_code=404, detail="Task non trouvé")
    generator = IRPlaybookGenerator()
    return generator.generate(results, (request.incident_types if request else None))


# ── Feature 9: Threat Intelligence ──
@additional_router.get("/{task_id}/threat-intel")
def get_threat_intel(task_id: str):
    """Feature 9: AbuseIPDB + FeodoTracker + URLhaus enrichment"""
    from app.services.enrichment_service import get_threat_intel_service
    results = storage_service.load_results(task_id)
    if not results:
        raise HTTPException(status_code=404, detail="Task non trouvé")
    try:
        # Extract unique external IPs and DNS domains from results
        all_ips = []
        all_domains = []
        for section in ["top_talkers", "tcp_analysis", "dns_analysis", "protocol_analysis"]:
            section_data = results.get(section, {})
            if isinstance(section_data, list):
                for item in section_data:
                    if isinstance(item, dict) and item.get("ip"):
                        all_ips.append(str(item["ip"]))
            elif isinstance(section_data, dict):
                for ip_entry in section_data.get("top_talkers", []):
                    if isinstance(ip_entry, dict) and ip_entry.get("ip"):
                        all_ips.append(str(ip_entry["ip"]))
                # protocol_analysis.ip_statistics
                ip_stats = section_data.get("ip_statistics", {})
                for source in ip_stats.get("top_sources", []):
                    if isinstance(source, dict) and source.get("ip"):
                        all_ips.append(str(source["ip"]))
                for dest in ip_stats.get("top_destinations", []):
                    if isinstance(dest, dict) and dest.get("ip"):
                        all_ips.append(str(dest["ip"]))

        # packets_index fallback
        for pkt in results.get("packets_index", [])[:2000]:
            if isinstance(pkt, dict):
                if pkt.get("src_ip"):
                    all_ips.append(str(pkt["src_ip"]))
                if pkt.get("dst_ip"):
                    all_ips.append(str(pkt["dst_ip"]))

        dns = results.get("dns_analysis", {})
        for domain_entry in dns.get("top_domains", []):
            if isinstance(domain_entry, dict):
                domain = domain_entry.get("domain") or domain_entry.get("name")
                if domain:
                    all_domains.append(str(domain))
            elif isinstance(domain_entry, (list, tuple)) and domain_entry:
                all_domains.append(str(domain_entry[0]))

        # HTTPS SNI hosts from HTTP analysis
        sni_hosts = (((results.get("http_analysis") or {}).get("tls") or {}).get("sni_hosts") or [])
        for sni_item in sni_hosts:
            if isinstance(sni_item, dict):
                host = sni_item.get("name") or sni_item.get("host")
                if host:
                    all_domains.append(str(host))
        # Deduplicate
        all_ips = list(set(all_ips))[:50]
        all_domains = list(set(all_domains))[:30]
        service = get_threat_intel_service()
        summary = service.get_threat_intel_summary(all_ips, all_domains)

        ip_intel = summary.get("ip_intel", {}) if isinstance(summary.get("ip_intel", {}), dict) else {}
        domain_intel = summary.get("domain_intel", {}) if isinstance(summary.get("domain_intel", {}), dict) else {}

        source_hit = defaultdict(int)
        score_dist = {"malicious": 0, "suspicious": 0, "clean": 0}
        country_risk = defaultdict(float)
        feodo_c2 = []
        top_entities = []

        for ip, intel in ip_intel.items():
            if not isinstance(intel, dict):
                continue
            score = _as_float(intel.get("reputation_score"), 0.0)
            verdict = str(intel.get("verdict", "")).lower()
            if score >= 70:
                score_dist["malicious"] += 1
            elif score >= 30:
                score_dist["suspicious"] += 1
            else:
                score_dist["clean"] += 1

            sources = intel.get("sources", {}) if isinstance(intel.get("sources", {}), dict) else {}
            for s_name, s_data in sources.items():
                if isinstance(s_data, dict):
                    if s_data.get("error"):
                        continue
                    source_hit[s_name] += 1
                elif s_data:
                    source_hit[s_name] += 1

            abuse = sources.get("abuseipdb", {}) if isinstance(sources.get("abuseipdb", {}), dict) else {}
            cc = str(abuse.get("country_code", "")).strip()
            if cc:
                country_risk[cc] += score

            feodo = sources.get("feodotracker", {}) if isinstance(sources.get("feodotracker", {}), dict) else {}
            if bool(feodo.get("is_c2")):
                feodo_c2.append({"ip": ip, "score": score, "verdict": intel.get("verdict")})

            top_entities.append({
                "type": "ip",
                "value": ip,
                "score": score,
                "verdict": intel.get("verdict", ""),
            })

        for domain, intel in domain_intel.items():
            if not isinstance(intel, dict):
                continue
            score = _as_float(intel.get("reputation_score"), 0.0)
            top_entities.append({
                "type": "domain",
                "value": domain,
                "score": score,
                "verdict": intel.get("verdict", ""),
            })

        top_entities.sort(key=lambda x: _as_float(x.get("score"), 0.0), reverse=True)
        top_country_risk = [
            {"country": c, "score": round(v, 2)}
            for c, v in sorted(country_risk.items(), key=lambda it: it[1], reverse=True)[:12]
        ]
        summary["analytics"] = {
            "score_distribution": score_dist,
            "source_hit": dict(sorted(source_hit.items(), key=lambda it: it[1], reverse=True)),
            "top_country_risk": top_country_risk,
            "feodo_c2_hits": feodo_c2[:20],
            "top_entities": top_entities[:30],
        }
        return summary
    except Exception as e:
        logger.error(f"threat_intel error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ── Feature 10: DFIR Report ──
from fastapi.responses import StreamingResponse
import io

@additional_router.get("/{task_id}/export/dfir-report")
async def export_dfir_report_pdf(task_id: str, analyst: str = Query("PCAP Analyzer Pro v2")):
    """Feature 10: Export rapport DFIR PDF professionnel"""
    from app.reports.dfir_report import DFIRReportGenerator
    results = storage_service.load_results(task_id)
    if not results:
        raise HTTPException(status_code=404, detail="Task non trouvé")
    try:
        generator = DFIRReportGenerator()
        pdf_bytes = generator.generate_pdf(task_id, results, analyst_name=analyst)
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=dfir-report-{str(task_id)[:8]}.pdf"}
        )
    except RuntimeError as e:
        raise HTTPException(status_code=501, detail=str(e))
    except Exception as e:
        logger.error(f"dfir_report error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@additional_router.get("/{task_id}/export/dfir-report-json")
async def export_dfir_report_json(task_id: str):
    """Feature 10: Export rapport DFIR JSON structuré (SIEM/SOAR)"""
    from app.reports.dfir_report import DFIRReportGenerator
    results = storage_service.load_results(task_id)
    if not results:
        raise HTTPException(status_code=404, detail="Task non trouvé")
    generator = DFIRReportGenerator()
    return generator.generate_json(task_id, results)
