"""
Routes API FastAPI pour PCAP Analyzer
Endpoints: upload, status, analysis, export, history, delete
Endpoints avancés: timeline, network-graph, streams, protocols entreprise
"""

import os
import csv
import io
import json
import shutil
import uuid as uuid_module
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any
from datetime import datetime
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response
try:
    # Sérialisation JSON ~10x plus rapide pour les grosses réponses d'analyse
    import orjson as _orjson  # noqa: F401
    from fastapi.responses import ORJSONResponse as JSONResponse
except ImportError:  # pragma: no cover
    from fastapi.responses import JSONResponse
from pydantic import BaseModel
from celery.result import AsyncResult

from app.core.config import settings
from app.core.celery_app import celery_app
from app.core.logging_config import get_logger
from app.services.storage_service import storage_service
from app.services.pcap_service import analyze_pcap_task
from app.services.timeline_service import get_timeline_service
from app.services.graph_service import get_graph_service
from app.services.stream_service import get_stream_service
from app.services.enrichment_service import get_enrichment_service
from app.services.multi_pcap_service import get_multi_pcap_service, CaptureInput
from app.reports.json_report import JSONReportGenerator
from app.reports.csv_report import CSVReportGenerator
from app.reports.pdf_report import PDFReportGenerator
from app.services.ai_analysis_service import ai_service
from app.core.mac_vendor import (
    get_maclookup_status,
    update_maclookup_runtime_config,
    test_maclookup_connection,
    normalize_mac_address,
    resolve_mac_vendor,
    classify_mac_address,
)
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, DNS, Raw

logger = get_logger(__name__)

router = APIRouter(prefix="/api", tags=["PCAP Analysis"])


# ============================================================
# Fallback local: analyse en thread quand Celery/Redis est indisponible
# ============================================================
_local_tasks: Dict[str, Dict[str, Any]] = {}


def _write_local_status(task_id: str, status: dict):
    """Persiste le statut du fallback local (partagé entre workers via le disque)"""
    try:
        status_path = storage_service.get_results_path(task_id) / 'status.json'
        status_path.write_text(json.dumps(status), encoding='utf-8')
    except Exception as e:
        logger.warning("local_status_write_error", task_id=task_id, error=str(e))


def _read_local_status(task_id: str) -> Optional[dict]:
    try:
        from app.services.storage_service import _validate_task_id
        _validate_task_id(task_id)
        status_path = storage_service.results_dir / task_id / 'status.json'
        if status_path.exists():
            return json.loads(status_path.read_text(encoding='utf-8'))
    except Exception:
        pass
    return None


def _run_analysis_inline(task_id: str, pcap_path: str, filename: str):
    """Exécute l'analyse dans un thread local (sans Celery)"""
    from app.services.pcap_service import PCAPAnalysisService

    def set_status(status: dict):
        _local_tasks[task_id] = status
        _write_local_status(task_id, status)

    set_status({'status': 'processing', 'progress': 30,
                'message': 'Analyse en cours (mode local)...'})
    try:
        service = PCAPAnalysisService()
        results = service.analyze(Path(pcap_path), filename)
        results['metadata']['task_id'] = task_id
        results['metadata']['filename'] = filename
        set_status({'status': 'processing', 'progress': 90,
                    'message': 'Sauvegarde des résultats...'})
        storage_service.save_results(task_id, results)
        set_status({'status': 'completed', 'progress': 100,
                    'message': 'Analyse terminée'})
        # Le résultat existe sur disque: l'entrée mémoire n'est plus nécessaire
        _local_tasks.pop(task_id, None)
        logger.info("local_analysis_completed", task_id=task_id)
    except Exception as e:
        logger.error("local_analysis_failed", task_id=task_id, error=str(e))
        set_status({'status': 'failed', 'progress': 100, 'message': str(e)})
        _local_tasks.pop(task_id, None)


_celery_worker_check = {'ts': 0.0, 'available': False}


def _celery_workers_available() -> bool:
    """Vérifie qu'au moins un worker Celery est vivant (résultat mis en cache 30s).

    Sans ce contrôle, un broker Redis joignable mais sans worker accepte la
    tâche qui reste alors indéfiniment en 'pending'.
    """
    import time as _time
    now = _time.monotonic()
    if now - _celery_worker_check['ts'] < 30:
        return _celery_worker_check['available']
    try:
        replies = celery_app.control.inspect(timeout=0.5).ping()
        available = bool(replies)
    except Exception:
        available = False
    _celery_worker_check['ts'] = now
    _celery_worker_check['available'] = available
    return available


def _start_local_analysis(task_id: str, pcap_path: str, filename: str):
    import threading
    threading.Thread(
        target=_run_analysis_inline,
        args=(task_id, pcap_path, filename),
        daemon=True
    ).start()


def _queue_analysis(task_id: str, pcap_path: str, filename: str):
    """Tente Celery si des workers sont disponibles, sinon thread local"""
    if _celery_workers_available():
        try:
            analyze_pcap_task.delay(task_id, pcap_path, filename)
            logger.info("analysis_task_queued", task_id=task_id)
            return
        except Exception as e:
            logger.warning("celery_publish_failed_local_fallback", task_id=task_id, error=str(e))
    else:
        logger.warning("no_celery_worker_local_fallback", task_id=task_id)
    _start_local_analysis(task_id, pcap_path, filename)


# Pydantic Models
class UploadResponse(BaseModel):
    task_id: str
    filename: str
    status: str
    message: str


class TaskStatus(BaseModel):
    task_id: str
    status: str
    progress: Optional[int] = None
    message: Optional[str] = None
    result: Optional[dict] = None


class AnalysisHistory(BaseModel):
    task_id: str
    filename: str
    timestamp: str
    total_packets: int
    total_bytes: int
    anomalies_count: int
    risk_level: str


class OllamaConfigRequest(BaseModel):
    endpoint: Optional[str] = None
    model: Optional[str] = None
    timeout: Optional[int] = None


class MacLookupConfigRequest(BaseModel):
    enabled: Optional[bool] = None
    endpoint: Optional[str] = None
    api_key: Optional[str] = None
    timeout: Optional[float] = None
    test_mac: Optional[str] = None


class MacLookupTestRequest(BaseModel):
    mac: Optional[str] = None
    enabled: Optional[bool] = None
    endpoint: Optional[str] = None
    api_key: Optional[str] = None
    timeout: Optional[float] = None


class MultiPcapCaptureMeta(BaseModel):
    filename: Optional[str] = None
    equipment_name: Optional[str] = None
    position: Optional[int] = None
    comment: Optional[str] = None


class MultiPcapThresholds(BaseModel):
    ttl_shift_medium: Optional[float] = None
    ttl_shift_high: Optional[float] = None
    retrans_increase_medium: Optional[float] = None
    retrans_increase_high: Optional[float] = None
    latency_segment_medium_ms: Optional[float] = None
    latency_segment_high_ms: Optional[float] = None
    latency_segment_notice_ms: Optional[float] = None
    segment_trigger_score: Optional[float] = None
    segment_trigger_soft_score: Optional[float] = None
    segment_trigger_changes_min: Optional[float] = None
    mss_spread_signal_min: Optional[float] = None
    nat_pairs_weight_step: Optional[float] = None
    bufferbloat_duration_ratio: Optional[float] = None
    bufferbloat_window_ratio: Optional[float] = None
    bufferbloat_reorder_min: Optional[float] = None
    asymmetry_missing_hops_min: Optional[float] = None


def _get_anomaly_block(results: dict) -> dict:
    """Compatibilité ascendante entre anomaly_detection et anomaly_analysis."""
    return results.get('anomaly_detection') or results.get('anomaly_analysis', {})


def _extract_tcp_window_scale(tcp_layer: TCP) -> Optional[int]:
    """Extrait le facteur TCP Window Scale depuis les options (si présent)."""
    options = getattr(tcp_layer, "options", None)
    if not isinstance(options, list):
        return None

    for option in options:
        if not isinstance(option, tuple) or len(option) < 2:
            continue
        name, value = option[0], option[1]
        name_norm = str(name).strip().lower()
        if name_norm not in {"wscale", "window scale", "window_scale"}:
            continue
        try:
            return max(0, min(14, int(value)))
        except (TypeError, ValueError):
            return None

    return None


def _parse_multi_capture_metadata(
    metadata_json: Optional[str],
    files: List[UploadFile]
) -> List[MultiPcapCaptureMeta]:
    if not metadata_json:
        return [MultiPcapCaptureMeta() for _ in files]

    try:
        raw = json.loads(metadata_json)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"metadata_json invalide: {exc}") from exc

    if not isinstance(raw, list):
        raise HTTPException(status_code=400, detail="metadata_json doit être une liste JSON")

    parsed: List[MultiPcapCaptureMeta] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            raise HTTPException(status_code=400, detail=f"metadata_json[{idx}] doit être un objet JSON")
        try:
            parsed.append(MultiPcapCaptureMeta(**item))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"metadata_json[{idx}] invalide: {exc}") from exc

    if len(parsed) < len(files):
        parsed.extend([MultiPcapCaptureMeta() for _ in range(len(files) - len(parsed))])
    return parsed[:len(files)]


def _parse_multi_thresholds(thresholds_json: Optional[str]) -> Optional[Dict[str, Any]]:
    if not thresholds_json:
        return None
    try:
        raw = json.loads(thresholds_json)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"thresholds_json invalide: {exc}") from exc

    if not isinstance(raw, dict):
        raise HTTPException(status_code=400, detail="thresholds_json doit être un objet JSON")

    try:
        parsed = MultiPcapThresholds(**raw)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"thresholds_json invalide: {exc}") from exc
    return parsed.model_dump(exclude_none=True)


def _load_multi_results(task_id: str) -> Dict[str, Any]:
    json_path = storage_service.get_results_path(task_id) / "multi_results.json"
    if not json_path.exists():
        raise HTTPException(status_code=404, detail="Résultats multi-PCAP non trouvés")
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Impossible de lire multi_results.json: {exc}") from exc

@router.get("/analysis/{task_id}/timeline")
async def get_timeline_data(
    task_id: str,
    start_time: Optional[float] = Query(None, description="Timestamp de début"),
    end_time: Optional[float] = Query(None, description="Timestamp de fin"),
    protocols: Optional[str] = Query(None, description="Filtrer par protocoles (comma-separated)"),
    min_packet_size: Optional[int] = Query(None, description="Taille minimale des paquets"),
    max_packet_size: Optional[int] = Query(None, description="Taille maximale des paquets")
):
    """
    Récupère les données de timeline pour visualisation temporelle
    """
    logger.info(f"📊 Requête timeline pour task_id: {task_id}")
    
    try:
        # Charger les résultats
        results = storage_service.load_results(task_id)
        if not results:
            raise HTTPException(status_code=404, detail="Analyse non trouvée")
        
        # Charger le fichier PCAP
        pcap_path = storage_service.get_pcap_path(task_id)
        if not pcap_path:
            logger.warning(f"⚠️ Fichier PCAP non trouvé pour {task_id}, utilisation des résultats existants")
            # Utiliser les données des résultats existants
            return generate_timeline_from_results(task_id, results, start_time, end_time, protocols, min_packet_size, max_packet_size)

        logger.info(f"📂 Fichier PCAP trouvé: {pcap_path}")
        
        # Générer la timeline depuis le PCAP
        timeline_data = generate_timeline_from_pcap(
            pcap_path, 
            start_time, 
            end_time, 
            protocols.split(',') if protocols else None,
            min_packet_size,
            max_packet_size
        )
        
        logger.info(f"✅ Timeline générée: {len(timeline_data.get('events', []))} événements")
        
        return JSONResponse(content={
            "task_id": task_id,
            "timeline": timeline_data,
            "filters_applied": {
                "start_time": start_time,
                "end_time": end_time,
                "protocols": protocols,
                "min_packet_size": min_packet_size,
                "max_packet_size": max_packet_size
            }
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur timeline: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Erreur serveur: {str(e)}")


def generate_timeline_from_results(task_id: str, results: dict, start_time: Optional[float], end_time: Optional[float], protocols: Optional[str], min_size: Optional[int], max_size: Optional[int]):
    """
    Génère une timeline à partir des résultats existants (fallback)
    """
    logger.info("🔄 Génération timeline depuis les résultats existants")
    
    events = []
    protocol_analysis = results.get('protocol_analysis', {})
    
    # Créer des événements fictifs basés sur les statistiques
    # (Ceci est un fallback, idéalement on devrait avoir les paquets)
    
    # Utiliser les sessions TCP
    tcp_sessions = results.get('tcp_analysis', {}).get('sessions', [])
    for i, session in enumerate(tcp_sessions[:100]):  # Limiter à 100
        events.append({
            "packet_num": i,
            "timestamp": 0,  # Timestamp fictif
            "src": session.get('src', 'Unknown'),
            "dst": session.get('dst', 'Unknown'),
            "protocol": "TCP",
            "length": session.get('packets', 0) * 100,
            "info": f"Session {session.get('state', 'UNKNOWN')}"
        })
    
    # Ajouter des requêtes DNS
    dns_queries = results.get('dns_analysis', {}).get('queries', [])
    for i, query in enumerate(dns_queries[:50]):
        events.append({
            "packet_num": len(events) + i,
            "timestamp": 0,
            "src": query.get('src_ip', 'Unknown'),
            "dst": query.get('dst_ip', 'Unknown'),
            "protocol": "DNS",
            "length": 64,
            "info": f"Query: {query.get('domain', 'unknown')}"
        })
    
    # Ajouter des requêtes HTTP
    http_requests = results.get('http_analysis', {}).get('requests', [])
    for i, req in enumerate(http_requests[:50]):
        events.append({
            "packet_num": len(events) + i,
            "timestamp": 0,
            "src": req.get('src_ip', 'Unknown'),
            "dst": req.get('dst_ip', 'Unknown'),
            "protocol": "HTTP",
            "length": 500,
            "info": f"{req.get('method', 'GET')} {req.get('path', '/')}"
        })
    
    # Calculer les statistiques
    total_packets = len(events)
    
    return {
        "events": events,
        "summary": {
            "total_events": total_packets,
            "duration_seconds": 60.0,  # Fictif
            "packets_per_second": total_packets / 60.0 if total_packets > 0 else 0,
            "peak_time": 0,
            "protocols": {
                "TCP": len([e for e in events if e['protocol'] == 'TCP']),
                "UDP": 0,
                "DNS": len([e for e in events if e['protocol'] == 'DNS']),
                "HTTP": len([e for e in events if e['protocol'] == 'HTTP'])
            }
        },
        "time_range": {
            "start": 0,
            "end": 60
        }
    }


def generate_timeline_from_pcap(pcap_path: str, start_time: Optional[float], end_time: Optional[float], protocols: Optional[List[str]], min_size: Optional[int], max_size: Optional[int]):
    """
    Génère une timeline depuis le fichier PCAP
    """
    from scapy.all import PcapReader, IP, TCP, UDP, DNS, Raw
    import itertools

    logger.info(f"📖 Lecture du fichier PCAP: {pcap_path}")

    # Lecture en streaming: seuls les 1000 premiers paquets sont nécessaires,
    # inutile de charger tout le fichier en mémoire
    try:
        with PcapReader(pcap_path) as reader:
            packets = list(itertools.islice(reader, 1000))
        logger.info(f"✅ {len(packets)} paquets chargés (streaming, max 1000)")
    except Exception as e:
        logger.error(f"❌ Erreur lecture PCAP: {e}")
        raise

    events = []
    first_timestamp = None
    last_timestamp = None
    protocol_counts = {}

    for i, pkt in enumerate(packets):
        
        if not pkt.haslayer(IP):
            continue
        
        ip_layer = pkt[IP]
        timestamp = float(pkt.time)
        
        if first_timestamp is None:
            first_timestamp = timestamp
        last_timestamp = timestamp
        
        # Filtres
        if start_time and timestamp < start_time:
            continue
        if end_time and timestamp > end_time:
            continue
        
        # Déterminer le protocole
        protocol = "OTHER"
        info = ""
        
        if pkt.haslayer(TCP):
            protocol = "TCP"
            tcp_layer = pkt[TCP]
            info = f"Port {tcp_layer.sport} → {tcp_layer.dport}"
            
            # Détecter HTTP
            if tcp_layer.dport in [80, 8080] or tcp_layer.sport in [80, 8080]:
                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw]).decode('utf-8', errors='ignore')
                    if payload.startswith(('GET', 'POST', 'HTTP')):
                        protocol = "HTTP"
                        info = payload.split('\n')[0][:50]
            
            # Détecter HTTPS
            if tcp_layer.dport == 443 or tcp_layer.sport == 443:
                protocol = "HTTPS"
                info = f"TLS Port {tcp_layer.sport} → {tcp_layer.dport}"
        
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            udp_layer = pkt[UDP]
            info = f"Port {udp_layer.sport} → {udp_layer.dport}"
            
            # Détecter DNS
            if pkt.haslayer(DNS):
                protocol = "DNS"
                dns_layer = pkt[DNS]
                if dns_layer.qd:
                    info = f"Query: {dns_layer.qd.qname.decode('utf-8', errors='ignore')}"
                elif dns_layer.an:
                    info = f"Response: {dns_layer.an.rdata if hasattr(dns_layer.an, 'rdata') else 'N/A'}"
        
        # Filtre par protocole
        if protocols and protocol not in protocols:
            continue
        
        # Filtre par taille
        packet_len = len(pkt)
        if min_size and packet_len < min_size:
            continue
        if max_size and packet_len > max_size:
            continue
        
        # Compter les protocoles
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
        # Ajouter l'événement
        events.append({
            "packet_num": i + 1,
            "timestamp": timestamp,
            "src": ip_layer.src,
            "dst": ip_layer.dst,
            "protocol": protocol,
            "length": packet_len,
            "info": info
        })
    
    # Calculer les statistiques
    duration = (last_timestamp - first_timestamp) if first_timestamp and last_timestamp else 0
    packets_per_second = len(events) / duration if duration > 0 else 0
    
    logger.info(f"✅ Timeline générée: {len(events)} événements, durée: {duration:.2f}s")
    
    return {
        "events": events,
        "summary": {
            "total_events": len(events),
            "duration_seconds": duration,
            "packets_per_second": packets_per_second,
            "peak_time": first_timestamp if first_timestamp else 0,
            "protocols": protocol_counts
        },
        "time_range": {
            "start": first_timestamp if first_timestamp else 0,
            "end": last_timestamp if last_timestamp else 0
        }
    }


@router.get("/analysis/{task_id}/ai-insights")
def get_ai_insights(task_id: str):
    """
    Obtenir l'analyse IA complète avec Ollama
    """
    logger.info(f"🔍 Requête AI insights pour task_id: {task_id}")
    
    try:
        # 1. Vérifier disponibilité Ollama
        if not ai_service.is_available():
            logger.warning("⚠️ Service Ollama non disponible")
            unavailable_msg = "Service IA non disponible"
            return JSONResponse(
                status_code=200,
                content={
                    "task_id": task_id,
                    "ai_available": False,
                    "error": "Service Ollama non disponible",
                    "message": "Démarrez Ollama avec: OLLAMA_HOST=0.0.0.0:11434 ollama serve",
                    "insights": {
                        "summary": unavailable_msg,
                        "attack_patterns": [],
                        "dns_analysis": {},
                        "http_analysis": {},
                        "troubleshooting": []
                    },
                    "insights_structured": {
                        "summary": ai_service.extract_structured_response(unavailable_msg),
                        "attack_patterns": ai_service.extract_structured_response("Aucun pattern"),
                        "dns_analysis": ai_service.extract_structured_response("Pas de données DNS disponibles"),
                        "http_analysis": ai_service.extract_structured_response("Pas de données HTTP disponibles"),
                        "troubleshooting": ai_service.extract_structured_response(unavailable_msg),
                    }
                }
            )
        
        # 2. Charger les résultats
        logger.info(f"📂 Chargement des résultats pour task_id: {task_id}")
        results = storage_service.load_results(task_id)
        
        if not results:
            logger.error(f"❌ Résultats non trouvés pour task_id: {task_id}")
            raise HTTPException(
                status_code=404, 
                detail=f"Résultats non trouvés pour task_id: {task_id}"
            )
        
        logger.info("✅ Résultats chargés avec succès")
        
        # 3. Générer les insights IA
        insights = {
            "summary": "Analyse en cours...",
            "attack_patterns": [],
            "dns_analysis": {},
            "http_analysis": {},
            "troubleshooting": []
        }
        insights_structured = {
            "summary": {},
            "attack_patterns": {},
            "dns_analysis": {},
            "http_analysis": {},
            "troubleshooting": {}
        }
        
        # Résumé global
        logger.info("🧠 Génération du résumé IA...")
        try:
            summary_result = ai_service.analyze_pcap_summary(results)
            if summary_result.get("success"):
                insights["summary"] = summary_result.get("analysis", "Analyse non disponible")
                insights_structured["summary"] = summary_result.get("structured") or ai_service.extract_structured_response(insights["summary"])
            else:
                insights["summary"] = f"Erreur: {summary_result.get('error', 'Inconnu')}"
                insights_structured["summary"] = summary_result.get("structured") or ai_service.extract_structured_response(insights["summary"])
            logger.info("✅ Résumé généré")
        except Exception as e:
            logger.error(f"❌ Erreur résumé: {e}")
            insights["summary"] = f"Erreur génération résumé: {str(e)}"
            insights_structured["summary"] = ai_service.extract_structured_response(insights["summary"])
        
        # Détection de patterns d'attaque
        logger.info("🎯 Détection des patterns d'attaque...")
        try:
            anomalies = _get_anomaly_block(results).get('anomalies', [])
            protocol_analysis = results.get('protocol_analysis', {})
            
            patterns_result = ai_service.detect_attack_patterns(anomalies, protocol_analysis)
            if patterns_result.get("success"):
                insights["attack_patterns"] = patterns_result.get("patterns", [])
                # Ajouter aussi l'analyse brute si disponible
                insights["attack_patterns_raw"] = patterns_result.get("raw_analysis", "")
                insights_structured["attack_patterns"] = (
                    patterns_result.get("structured")
                    or ai_service.extract_structured_response(insights.get("attack_patterns_raw", ""))
                )
            else:
                insights["attack_patterns"] = []
                insights["attack_patterns_error"] = patterns_result.get("error", "Inconnu")
                insights_structured["attack_patterns"] = patterns_result.get("structured") or ai_service.extract_structured_response(insights["attack_patterns_error"])
            logger.info("✅ Patterns détectés")
        except Exception as e:
            logger.error(f"❌ Erreur patterns: {e}")
            insights["attack_patterns"] = []
            insights["attack_patterns_error"] = str(e)
            insights_structured["attack_patterns"] = ai_service.extract_structured_response(str(e))
        
        # Analyse DNS
        logger.info("🌐 Analyse DNS...")
        try:
            dns_data = results.get('dns_analysis', {})
            if dns_data and dns_data.get('top_domains'):
                dns_result = ai_service.analyze_dns_suspicious(dns_data)
                if dns_result.get("success"):
                    insights["dns_analysis"] = dns_result.get("dns_analysis", {})
                    insights_structured["dns_analysis"] = dns_result.get("structured") or ai_service.extract_structured_response(insights["dns_analysis"])
                else:
                    insights["dns_analysis"] = {"error": dns_result.get("error", "Inconnu")}
                    insights_structured["dns_analysis"] = dns_result.get("structured") or ai_service.extract_structured_response(insights["dns_analysis"].get("error", "Erreur DNS"))
                logger.info("✅ DNS analysé")
            else:
                insights["dns_analysis"] = {"message": "Pas de données DNS disponibles"}
                insights_structured["dns_analysis"] = ai_service.extract_structured_response("Pas de données DNS disponibles")
        except Exception as e:
            logger.error(f"❌ Erreur DNS: {e}")
            insights["dns_analysis"] = {"error": str(e)}
            insights_structured["dns_analysis"] = ai_service.extract_structured_response(str(e))
        
        # Analyse HTTP
        logger.info("🌍 Analyse HTTP...")
        try:
            http_data = results.get('http_analysis', {})
            if http_data and http_data.get('top_hosts'):
                http_result = ai_service.analyze_http_traffic(http_data)
                if http_result.get("success"):
                    insights["http_analysis"] = http_result.get("http_analysis", {})
                    insights_structured["http_analysis"] = http_result.get("structured") or ai_service.extract_structured_response(insights["http_analysis"])
                else:
                    insights["http_analysis"] = {"error": http_result.get("error", "Inconnu")}
                    insights_structured["http_analysis"] = http_result.get("structured") or ai_service.extract_structured_response(insights["http_analysis"].get("error", "Erreur HTTP"))
                logger.info("✅ HTTP analysé")
            else:
                insights["http_analysis"] = {"message": "Pas de données HTTP disponibles"}
                insights_structured["http_analysis"] = ai_service.extract_structured_response("Pas de données HTTP disponibles")
        except Exception as e:
            logger.error(f"❌ Erreur HTTP: {e}")
            insights["http_analysis"] = {"error": str(e)}
            insights_structured["http_analysis"] = ai_service.extract_structured_response(str(e))
        
        # Troubleshooting
        logger.info("🔧 Génération des recommandations...")
        try:
            troubleshooting_result = ai_service.suggest_troubleshooting(results)
            if troubleshooting_result.get("success"):
                insights["troubleshooting"] = troubleshooting_result.get("troubleshooting", "Aucune recommandation")
                insights_structured["troubleshooting"] = troubleshooting_result.get("structured") or ai_service.extract_structured_response(insights["troubleshooting"])
            else:
                insights["troubleshooting"] = f"Erreur: {troubleshooting_result.get('error', 'Inconnu')}"
                insights_structured["troubleshooting"] = troubleshooting_result.get("structured") or ai_service.extract_structured_response(insights["troubleshooting"])
            logger.info("✅ Recommandations générées")
        except Exception as e:
            logger.error(f"❌ Erreur troubleshooting: {e}")
            insights["troubleshooting"] = f"Erreur: {str(e)}"
            insights_structured["troubleshooting"] = ai_service.extract_structured_response(insights["troubleshooting"])
        
        logger.info("🎉 Insights IA générés avec succès")
        
        return JSONResponse(content={
            "task_id": task_id,
            "ai_available": True,
            "model": ai_service.model,
            "insights": insights,
            "insights_structured": insights_structured,
            "generated_at": datetime.now().isoformat()
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"💥 Erreur inattendue: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, 
            detail=f"Erreur serveur: {str(e)}"
        )


@router.get("/ai/status")
def check_ai_status():
    """
    Vérifier le statut du service IA
    """
    return ai_service.refresh_connection()


@router.get("/ai/models")
async def list_ollama_models(endpoint: Optional[str] = Query(None, description="URL du serveur Ollama")):
    """Lister les modèles disponibles sur un endpoint Ollama."""
    return ai_service.list_models(endpoint=endpoint)


@router.get("/ai/config")
async def get_ollama_config():
    """Lire la configuration Ollama active (endpoint, modèle, timeout, statut)."""
    return ai_service.get_status()




def _require_config_access(http_request: Request):
    """Protège les endpoints de configuration runtime (état partagé entre tous
    les utilisateurs). Si CONFIG_API_TOKEN est défini, le header X-Admin-Token
    doit correspondre; sinon comportement historique (accès libre, usage local).
    """
    import hmac
    token = os.getenv("CONFIG_API_TOKEN", "").strip()
    if not token:
        return
    provided = str(http_request.headers.get("X-Admin-Token", ""))
    if not hmac.compare_digest(provided, token):
        raise HTTPException(status_code=403, detail="Token d'administration requis (X-Admin-Token)")

@router.post("/ai/config")
async def update_ollama_config(request: OllamaConfigRequest, http_request: Request = None):
    if http_request is not None:
        _require_config_access(http_request)
    """Mettre à jour la configuration Ollama à chaud."""
    return ai_service.update_runtime_config(
        endpoint=request.endpoint,
        model=request.model,
        timeout=request.timeout
    )


@router.get("/maclookup/status")
async def maclookup_status(
    probe: bool = Query(True, description="Tester la connexion MacLookup"),
    mac: Optional[str] = Query(None, description="MAC utilisée pour le test de santé")
):
    """Statut MacLookup (avec probe optionnel)."""
    return get_maclookup_status(probe=probe, test_mac=mac or "00:50:56:AA:BB:CC")


@router.get("/maclookup/config")
async def get_maclookup_config():
    """Lire la configuration MacLookup active."""
    return get_maclookup_status(probe=True)


@router.post("/maclookup/config")
async def update_maclookup_config(request: MacLookupConfigRequest, http_request: Request = None):
    if http_request is not None:
        _require_config_access(http_request)
    """Mettre à jour la configuration MacLookup à chaud."""
    return update_maclookup_runtime_config(
        enabled=request.enabled,
        base_url=request.endpoint,
        api_key=request.api_key,
        timeout=request.timeout,
        test_mac=request.test_mac or "00:50:56:AA:BB:CC",
    )


@router.post("/maclookup/test")
async def test_maclookup(request: MacLookupTestRequest, http_request: Request = None):
    if http_request is not None:
        _require_config_access(http_request)
    """Tester la connectivité MacLookup avec des paramètres temporaires (non persistés)."""
    return test_maclookup_connection(
        mac=request.mac or "00:50:56:AA:BB:CC",
        enabled=request.enabled,
        base_url=request.endpoint,
        api_key=request.api_key,
        timeout=request.timeout,
    )


@router.get("/maclookup/resolve")
async def resolve_mac(mac: str = Query(..., description="Adresse MAC à résoudre")):
    """Résoudre un vendor MAC (local + fallback MacLookup selon la config)."""
    normalized = normalize_mac_address(mac)
    if not normalized:
        raise HTTPException(status_code=400, detail=f"MAC invalide: {mac}")

    return {
        "mac": normalized,
        "vendor": resolve_mac_vendor(normalized),
        "mac_type": classify_mac_address(normalized),
    }


# ==================== CHATBOT ENDPOINT ====================

class ChatRequest(BaseModel):
    message: str

@router.post("/analysis/{task_id}/chat")
def chat_with_ai(task_id: str, request: ChatRequest):
    """
    Endpoint pour le chatbot IA conversationnel
    
    - **task_id**: Identifiant de la tâche d'analyse
    - **message**: Question de l'utilisateur
    """
    logger.info(f"💬 Chat request for task_id: {task_id}, message: {request.message[:50]}...")
    
    try:
        # Vérifier disponibilité Ollama
        if not ai_service.is_available():
            unavailable_response = "Je ne peux pas répondre actuellement car le service IA n'est pas disponible."
            return JSONResponse(content={
                "success": False,
                "error": "Service IA non disponible. Démarrez Ollama avec: ollama serve",
                "response": unavailable_response,
                "structured": ai_service.extract_structured_response(unavailable_response)
            })
        
        # Charger les résultats d'analyse
        results = storage_service.load_results(task_id)
        
        if not results:
            not_found_response = "Je n'ai pas trouvé d'analyse PCAP à consulter. Veuillez d'abord analyser un fichier."
            return JSONResponse(content={
                "success": False,
                "error": "Analyse non trouvée",
                "response": not_found_response,
                "structured": ai_service.extract_structured_response(not_found_response)
            })
        
        # Préparer le contexte pour l'IA
        protocol = results.get('protocol_analysis', {})
        tcp = results.get('tcp_analysis', {})
        anomaly = _get_anomaly_block(results)
        dns = results.get('dns_analysis', {})
        http = results.get('http_analysis', {})
        
        # Helper: safely extract first meaningful string from various data shapes
        def safe_str(item):
            if item is None:
                return ''
            if isinstance(item, str):
                return item
            if isinstance(item, dict):
                return item.get('domain') or item.get('host') or item.get('name') or str(next(iter(item.values()), ''))
            if isinstance(item, (list, tuple)) and len(item) > 0:
                return str(item[0])
            return str(item)
        
        def safe_list(items, limit=5):
            try:
                return [safe_str(i) for i in (items or [])[:limit] if i is not None]
            except Exception:
                return []
        
        try:
            top_domains = safe_list(dns.get('top_domains', []))
            top_hosts   = safe_list(http.get('top_hosts', http.get('hosts', [])))
            protocols   = list(protocol.get('protocols', {}).keys())[:10]
            top_anomalies = [
                a.get('description', str(a)) if isinstance(a, dict) else str(a)
                for a in anomaly.get('anomalies', [])[:5]
            ]
        except Exception as ctx_err:
            logger.warning(f"⚠️ Erreur contexte chat: {ctx_err}")
            top_domains = []
            top_hosts = []
            protocols = []
            top_anomalies = []
        
        context = {
            "total_packets": protocol.get('summary', {}).get('total_packets', 0),
            "total_bytes": protocol.get('summary', {}).get('total_bytes_formatted', '0 B'),
            "protocols": protocols,
            "tcp_sessions": tcp.get('summary', {}).get('total_sessions', 0),
            "retransmissions": tcp.get('summary', {}).get('total_retransmissions', 0),
            "anomalies_count": anomaly.get('summary', {}).get('total_anomalies', 0),
            "risk_level": anomaly.get('summary', {}).get('risk_level', 'NONE'),
            "top_anomalies": top_anomalies,
            "dns_queries": dns.get('summary', {}).get('total_queries', 0),
            "unique_domains": dns.get('summary', {}).get('unique_domains', 0),
            "top_domains": top_domains,
            "http_requests": http.get('summary', {}).get('total_requests', 0),
            "top_hosts": top_hosts,
        }
        
        # Créer le prompt système
        system_prompt = f"""Tu es un expert en analyse réseau et cybersécurité. Tu aides l'utilisateur à comprendre son analyse PCAP.

CONTEXTE DE L'ANALYSE EN COURS:
- Total paquets: {context['total_packets']}
- Volume: {context['total_bytes']}
- Protocoles détectés: {', '.join(context['protocols']) or 'N/A'}
- Sessions TCP: {context['tcp_sessions']}
- Retransmissions TCP: {context['retransmissions']}
- Anomalies détectées: {context['anomalies_count']}
- Niveau de risque: {context['risk_level']}
- Top anomalies: {'; '.join(context['top_anomalies']) or 'Aucune'}
- Requêtes DNS: {context['dns_queries']} ({context['unique_domains']} domaines uniques)
- Top domaines: {', '.join(context['top_domains']) or 'N/A'}
- Requêtes HTTP: {context['http_requests']}
- Top hosts: {', '.join(context['top_hosts']) or 'N/A'}

INSTRUCTIONS:
- Réponds de manière claire, concise et professionnelle en français
- Base tes réponses sur les données du contexte ci-dessus
- Si l'utilisateur pose une question hors contexte, ramène-le à l'analyse PCAP
- Donne des recommandations de sécurité si pertinent
- Utilise des emojis pour rendre la réponse plus lisible

QUESTION DE L'UTILISATEUR:
{request.message}

RÉPONSE:"""
        
        # Appeler Ollama
        response_text = ai_service._call_ollama(system_prompt)
        structured = ai_service.extract_structured_response(response_text)
        
        logger.info(f"✅ Chat response generated: {len(response_text)} chars")
        
        return JSONResponse(content={
            "success": True,
            "response": response_text,
            "structured": structured,
            "model": ai_service.model,
            "task_id": task_id
        })

        
    except Exception as e:
        logger.error(f"❌ Chat error: {e}", exc_info=True)
        err_message = f"Désolé, une erreur s'est produite: {str(e)}"
        return JSONResponse(content={
            "success": False,
            "error": str(e),
            "response": err_message,
            "structured": ai_service.extract_structured_response(err_message)
        })


@router.post("/upload", response_model=UploadResponse)
async def upload_pcap(file: UploadFile = File(...)):
    """
    Upload un fichier PCAP pour analyse
    
    - **file**: Fichier PCAP/PCAPNG (à 3GB max)
    
    Retourne un task_id pour suivre l'analyse
    """
    logger.info("upload_started", filename=file.filename)
    
    # Validation de l'extension
    if file.filename:
        ext = Path(file.filename).suffix.lower()
        if ext not in settings.allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"Extension non supportée. Extensions acceptées: {settings.allowed_extensions}"
            )
    
    # Générer un ID de tâche
    task_id = storage_service.generate_task_id()
    
    # Chemin de sauvegarde
    pcap_path = storage_service.get_upload_path(task_id, file.filename or "upload.pcap")
    
    try:
        # Sauvegarder le fichier avec vérification de taille
        total_size = 0
        with open(pcap_path, 'wb') as f:
            while chunk := await file.read(1024 * 1024):  # 1MB chunks
                total_size += len(chunk)
                if total_size > settings.max_file_size:
                    f.close()
                    os.unlink(pcap_path)
                    raise HTTPException(
                        status_code=413,
                        detail=f"Fichier trop volumineux. Max: {settings.max_file_size / (1024**3):.1f}GB"
                    )
                f.write(chunk)
        
        logger.info("file_saved", task_id=task_id, size=total_size)
        
        # Valider le fichier PCAP
        if not storage_service.validate_pcap_file(pcap_path):
            os.unlink(pcap_path)
            raise HTTPException(
                status_code=400,
                detail="Fichier PCAP invalide ou corrompu"
            )
        
        # Lancer l'analyse (Celery, ou thread local si le broker est indisponible)
        _queue_analysis(task_id, str(pcap_path), file.filename or "upload.pcap")
        
        return UploadResponse(
            task_id=task_id,
            filename=file.filename or "upload.pcap",
            status="queued",
            message="Analyse en cours de traitement"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("upload_error", error=str(e))
        raise HTTPException(status_code=500, detail=f"Erreur lors de l'upload: {str(e)}")


@router.post("/multi-pcap/analyze")
async def analyze_multi_pcap(
    files: List[UploadFile] = File(...),
    metadata_json: Optional[str] = Form(None),
    thresholds_json: Optional[str] = Form(None),
    time_tolerance: float = Form(5.0),
    max_packets_per_capture: int = Form(250000),
):
    """
    Analyse corrélée multi-PCAP (multi-hop).

    Multipart attendu:
    - files: plusieurs fichiers .pcap/.pcapng/.cap
    - metadata_json: JSON optionnel [{equipment_name, position, comment, filename}, ...]
    - thresholds_json: JSON optionnel des seuils root-cause avancés
    - time_tolerance: tolérance temporelle de corrélation (secondes)
    - max_packets_per_capture: limite de paquets lus par capture (performance)
    """
    if len(files) < 2:
        raise HTTPException(status_code=400, detail="Veuillez fournir au moins 2 fichiers PCAP")

    if max_packets_per_capture < 1000:
        raise HTTPException(status_code=400, detail="max_packets_per_capture doit être >= 1000")

    parsed_meta = _parse_multi_capture_metadata(metadata_json, files)
    parsed_thresholds = _parse_multi_thresholds(thresholds_json)
    task_id = storage_service.generate_task_id()
    capture_inputs: List[CaptureInput] = []

    try:
        for idx, file in enumerate(files):
            original_name = file.filename or f"capture_{idx + 1}.pcap"
            ext = Path(original_name).suffix.lower()
            if ext not in settings.allowed_extensions:
                raise HTTPException(
                    status_code=400,
                    detail=f"Extension non supportée pour {original_name}. "
                           f"Extensions acceptées: {settings.allowed_extensions}"
                )

            # Préfixe pour éviter collisions de noms dans le même task_id
            save_name = f"multi_{idx + 1:02d}_{original_name}"
            pcap_path = storage_service.get_upload_path(task_id, save_name)

            total_size = 0
            with open(pcap_path, "wb") as f:
                while chunk := await file.read(1024 * 1024):
                    total_size += len(chunk)
                    if total_size > settings.max_file_size:
                        f.close()
                        if os.path.exists(pcap_path):
                            os.unlink(pcap_path)
                        raise HTTPException(
                            status_code=413,
                            detail=(
                                f"Fichier {original_name} trop volumineux. "
                                f"Max: {settings.max_file_size / (1024**3):.1f}GB"
                            ),
                        )
                    f.write(chunk)

            if not storage_service.validate_pcap_file(pcap_path):
                if os.path.exists(pcap_path):
                    os.unlink(pcap_path)
                raise HTTPException(
                    status_code=400,
                    detail=f"Fichier PCAP invalide ou corrompu: {original_name}"
                )

            meta = parsed_meta[idx] if idx < len(parsed_meta) else MultiPcapCaptureMeta()
            equipment_name = (meta.equipment_name or "").strip() or f"Point {idx + 1}"
            position = int(meta.position) if meta.position is not None else (idx + 1)
            comment = (meta.comment or "").strip()

            capture_inputs.append(
                CaptureInput(
                    file_path=Path(pcap_path),
                    filename=original_name,
                    equipment_name=equipment_name,
                    position=position,
                    comment=comment,
                )
            )

        logger.info(
            "multi_pcap_analysis_started",
            task_id=task_id,
            captures=len(capture_inputs),
            time_tolerance=time_tolerance,
            max_packets=max_packets_per_capture,
            thresholds=parsed_thresholds or {},
        )

        service = get_multi_pcap_service()
        analysis = service.analyze(
            capture_inputs=capture_inputs,
            time_tolerance=float(time_tolerance),
            max_packets_per_capture=int(max_packets_per_capture),
            root_cause_thresholds=parsed_thresholds,
        )

        payload = {
            "task_id": task_id,
            "status": "completed",
            "generated_at": datetime.utcnow().isoformat(),
            "analysis": analysis,
        }

        # JSON compact via orjson (cohérent avec save_results): ~2x plus petit
        from app.services.storage_service import _dump_json
        results_path = storage_service.get_results_path(task_id) / "multi_results.json"
        _dump_json(payload, results_path)

        logger.info("multi_pcap_analysis_completed", task_id=task_id, output=str(results_path))
        return payload

    except HTTPException:
        raise
    except Exception as e:
        logger.error("multi_pcap_analysis_error", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Erreur analyse multi-PCAP: {e}")


@router.get("/multi-pcap/{task_id}")
async def get_multi_pcap_results(task_id: str):
    """Récupère un résultat multi-PCAP précédemment calculé."""
    return JSONResponse(content=_load_multi_results(task_id))


@router.get("/multi-pcap/{task_id}/export/csv")
async def export_multi_pcap_csv(
    task_id: str,
    problematic_only: bool = Query(False, description="Exporter uniquement les sessions problématiques"),
):
    """Exporte les sessions corrélées multi-PCAP en CSV."""
    payload = _load_multi_results(task_id)
    analysis = payload.get("analysis", payload)
    sessions = analysis.get("sessions", []) if isinstance(analysis, dict) else []

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "session_id",
        "protocol",
        "flow_label",
        "risk_score",
        "confidence_level",
        "probable_cause",
        "probable_cause_code",
        "cause_details",
        "problematic",
        "total_packets",
        "total_bytes",
        "presence_path",
        "changes_count",
        "latency_total_ms",
        "latency_confidence",
        "degradation_primary_segment",
        "degradation_primary_score",
    ])

    for sess in sessions:
        if problematic_only and not bool(sess.get("problematic")):
            continue

        presence_rows = sess.get("presence", []) if isinstance(sess.get("presence", []), list) else []
        present_equips = [str(p.get("equipment_name", "")) for p in presence_rows if p.get("present")]
        presence_path = " -> ".join([e for e in present_equips if e])

        writer.writerow([
            sess.get("session_id", ""),
            sess.get("protocol", ""),
            sess.get("flow_label", ""),
            _to_int(sess.get("risk_score"), 0),
            sess.get("confidence_level", ""),
            sess.get("probable_cause", ""),
            sess.get("probable_cause_code", ""),
            sess.get("cause_details", ""),
            bool(sess.get("problematic")),
            _to_int(sess.get("total_packets"), 0),
            _to_int(sess.get("total_bytes"), 0),
            presence_path,
            len(sess.get("changes", []) if isinstance(sess.get("changes", []), list) else []),
            sess.get("latency_total_ms", ""),
            sess.get("latency_confidence", ""),
            (sess.get("degradation_primary") or {}).get("segment", "") if isinstance(sess.get("degradation_primary"), dict) else "",
            (sess.get("degradation_primary") or {}).get("score", "") if isinstance(sess.get("degradation_primary"), dict) else "",
        ])

    content = output.getvalue()
    output.close()
    filename = f"multi_pcap_{task_id[:8]}_{'problematic' if problematic_only else 'all'}.csv"
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/multi-pcap/{task_id}/export/dfir-report-json")
async def export_multi_pcap_dfir_json(task_id: str):
    """Export DFIR JSON enrichi pour analyse multi-PCAP."""
    payload = _load_multi_results(task_id)
    analysis = payload.get("analysis", payload)
    if not isinstance(analysis, dict):
        raise HTTPException(status_code=404, detail="Résultats multi-PCAP invalides")

    summary = analysis.get("summary", {}) if isinstance(analysis.get("summary", {}), dict) else {}
    sessions = analysis.get("sessions", []) if isinstance(analysis.get("sessions", []), list) else []
    segment_health = analysis.get("segment_health", []) if isinstance(analysis.get("segment_health", []), list) else []
    culprit_ranking = analysis.get("culprit_ranking", []) if isinstance(analysis.get("culprit_ranking", []), list) else []
    thresholds = analysis.get("thresholds_applied") or summary.get("thresholds_applied") or {}

    problematic_sessions = [s for s in sessions if bool(s.get("problematic"))]
    problematic_sessions.sort(key=lambda s: (_to_int(s.get("risk_score"), 0), len(s.get("changes", []))), reverse=True)

    def _presence_path(sess: Dict[str, Any]) -> str:
        presence = sess.get("presence", []) if isinstance(sess.get("presence", []), list) else []
        names = [str(p.get("equipment_name", "")) for p in presence if p.get("present")]
        return " -> ".join([n for n in names if n])

    dfir_json = {
        "report_id": f"DFIR-MULTI-{task_id[:8].upper()}",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "task_id": task_id,
        "report_type": "multi_pcap_dfir",
        "risk_summary": {
            "correlated_sessions": _to_int(summary.get("correlated_sessions"), len(sessions)),
            "problematic_sessions": _to_int(summary.get("problematic_sessions"), len(problematic_sessions)),
            "high_risk_sessions": _to_int(summary.get("high_risk_sessions"), 0),
            "major_changes_detected": _to_int(summary.get("major_changes_detected"), 0),
            "latency_segments": _to_int(summary.get("latency_segments"), 0),
            "slowest_segment": (analysis.get("latency", {}) if isinstance(analysis.get("latency", {}), dict) else {}).get("slowest_segment"),
        },
        "thresholds_applied": thresholds,
        "multi_hop_root_cause_matrix": [
            {
                "equipment_name": row.get("equipment_name"),
                "score": _to_int(row.get("score"), 0),
                "confidence": _to_int(row.get("confidence"), 0),
                "high_risk_sessions": _to_int(row.get("high_risk_sessions"), 0),
                "segments_triggered": _to_int(row.get("segments_triggered"), 0),
                "top_causes": row.get("top_causes", []),
                "top_ips": row.get("top_ips", []),
                "evidence": row.get("evidence", []),
            }
            for row in culprit_ranking[:25]
        ],
        "segment_health": [
            {
                "segment": seg.get("segment"),
                "avg_score": seg.get("avg_score"),
                "max_score": seg.get("max_score"),
                "trigger_ratio": seg.get("trigger_ratio"),
                "latency_p95_ms": seg.get("latency_p95_ms"),
                "session_count": seg.get("session_count"),
                "top_reasons": seg.get("top_reasons", []),
            }
            for seg in segment_health[:40]
        ],
        "problematic_sessions": [
            {
                "session_id": sess.get("session_id"),
                "protocol": sess.get("protocol"),
                "flow_label": sess.get("flow_label"),
                "risk_score": _to_int(sess.get("risk_score"), 0),
                "confidence_level": sess.get("confidence_level"),
                "probable_cause": sess.get("probable_cause"),
                "probable_cause_code": sess.get("probable_cause_code"),
                "cause_details": sess.get("cause_details"),
                "latency_total_ms": sess.get("latency_total_ms"),
                "latency_confidence": sess.get("latency_confidence"),
                "degradation_primary": sess.get("degradation_primary", {}),
                "root_cause_signals": sess.get("root_cause_signals", []),
                "changes_count": len(sess.get("changes", []) if isinstance(sess.get("changes", []), list) else []),
                "presence_path": _presence_path(sess),
            }
            for sess in problematic_sessions[:250]
        ],
        "limitations": analysis.get("limitations", []),
    }
    return JSONResponse(content=dfir_json)


@router.get("/status/{task_id}", response_model=TaskStatus)
async def get_task_status(task_id: str):
    """
    Récupère le statut d'une tâche d'analyse
    
    - **task_id**: Identifiant de la tâche
    """
    # Vérifier si les résultats existent déjà
    results = storage_service.load_results(task_id)
    if results:
        return TaskStatus(
            task_id=task_id,
            status="completed",
            progress=100,
            message="Analyse terminée",
            result={
                'total_packets': results.get('protocol_analysis', {}).get('summary', {}).get('total_packets', 0),
                'anomalies': _get_anomaly_block(results).get('summary', {}).get('total_anomalies', 0),
                'risk_level': _get_anomaly_block(results).get('summary', {}).get('risk_level', 'NONE')
            }
        )
    
    # Analyse exécutée en local (fallback sans Celery) ?
    # Mémoire d'abord (même worker), puis status.json (autre worker / après restart)
    local = _local_tasks.get(task_id) or _read_local_status(task_id)
    if local:
        return TaskStatus(
            task_id=task_id,
            status=local.get('status', 'processing'),
            progress=local.get('progress'),
            message=local.get('message')
        )

    # Vérifier le statut Celery (peut échouer si Redis est indisponible)
    try:
        task = AsyncResult(task_id, app=celery_app)
        task_state = task.state
        task_info = task.info
    except Exception as e:
        logger.warning("celery_status_unavailable", task_id=task_id, error=str(e))
        return TaskStatus(
            task_id=task_id,
            status="processing",
            progress=None,
            message="Analyse en cours..."
        )

    status_mapping = {
        'PENDING': ('pending', 'En attente...'),
        'STARTED': ('processing', 'Démarrage...'),
        'PROGRESS': ('processing', None),
        'SUCCESS': ('completed', 'Analyse terminée'),
        'FAILURE': ('failed', 'Erreur lors de l\'analyse'),
        'REVOKED': ('cancelled', 'Analyse annulée')
    }

    status, default_message = status_mapping.get(task_state, ('unknown', 'Statut inconnu'))

    progress = None
    message = default_message

    if task_state == 'PROGRESS' and task_info:
        progress = task_info.get('progress', 0)
        message = task_info.get('status', 'En cours...')
    elif task_state == 'FAILURE' and task_info:
        message = str(task_info.get('error', 'Erreur inconnue')) if isinstance(task_info, dict) else str(task_info)

    return TaskStatus(
        task_id=task_id,
        status=status,
        progress=progress,
        message=message
    )


@router.get("/analysis/{task_id}")
async def get_analysis_results(task_id: str):
    """
    Récupère les résultats complets d'une analyse
    
    - **task_id**: Identifiant de la tâche
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(
            status_code=404,
            detail="Résultats non trouvés. L'analyse est peut-être encore en cours."
        )
    
    return results


@router.get("/export/{task_id}/{format}")
def export_analysis(task_id: str, format: str):
    """
    Exporte les résultats d'analyse dans le format spécifié
    (handler sync: la génération de rapport est CPU-bound, exécutée en threadpool)

    - **task_id**: Identifiant de la tâche
    - **format**: Format d'export (json, csv, pdf)
    """
    results = storage_service.load_results(task_id)

    if not results:
        raise HTTPException(
            status_code=404,
            detail="Résultats non trouvés"
        )

    results_dir = storage_service.get_results_path(task_id)

    formats = {
        'json': ('report.json', 'application/json', lambda r, p: JSONReportGenerator().generate(r, p)),
        'csv': ('report.csv', 'text/csv', lambda r, p: CSVReportGenerator().generate_combined(r, p)),
        'pdf': ('report.pdf', 'application/pdf', lambda r, p: PDFReportGenerator().generate(r, p)),
    }
    fmt = format.lower()
    if fmt not in formats:
        raise HTTPException(
            status_code=400,
            detail="Format non supporté. Formats disponibles: json, csv, pdf"
        )

    filename, media_type, generate = formats[fmt]
    report_path = results_dir / filename
    results_json = results_dir / 'results.json'

    # Réutiliser le rapport s'il est plus récent que les résultats
    try:
        if not (report_path.exists() and results_json.exists()
                and report_path.stat().st_mtime >= results_json.stat().st_mtime):
            # Génération dans un fichier temporaire puis rename atomique:
            # deux exports concurrents ne peuvent pas se corrompre mutuellement
            tmp_path = results_dir / f'.{filename}.{uuid_module.uuid4().hex}.tmp'
            try:
                generate(results, tmp_path)
                os.replace(tmp_path, report_path)
            finally:
                if tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("export_generation_failed", task_id=task_id, format=fmt, error=str(e))
        raise HTTPException(status_code=500, detail=f"Erreur de génération du rapport: {e}")

    return FileResponse(
        report_path,
        media_type=media_type,
        filename=f'pcap_analysis_{task_id}.{fmt}'
    )


@router.get("/history")
async def get_analysis_history(limit: int = 50):
    """
    Récupère l'historique des analyses
    
    - **limit**: Nombre maximum de résultats (défaut: 50)
    """
    history = storage_service.get_analysis_history(limit=limit)
    return {"history": history, "total": len(history)}


@router.delete("/delete/{task_id}")
async def delete_analysis(task_id: str):
    """
    Supprime une analyse et ses fichiers associés
    
    - **task_id**: Identifiant de la tâche
    """
    success = storage_service.delete_analysis(task_id)
    
    if success:
        return {"status": "deleted", "task_id": task_id}
    else:
        raise HTTPException(
            status_code=404,
            detail="Analyse non trouvée ou erreur lors de la suppression"
        )


@router.get("/health")
async def health_check():
    """Vérification de l'état de santé de l'API"""
    return {
        "status": "healthy",
        "version": settings.app_version,
        "timestamp": datetime.utcnow().isoformat()
    }


# ==================== DRILL-DOWN ENDPOINTS ====================

@router.get("/analysis/{task_id}/ip/{ip}")
async def get_ip_details(task_id: str, ip: str):
    """
    Récupère tous les paquets associés à une IP spécifique
    
    - **task_id**: Identifiant de la tâche
    - **ip**: Adresse IP à filtrer
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    packets_index = results.get('packets_index', [])
    
    # Filtrer les paquets pour cette IP
    ip_packets = [
        pkt for pkt in packets_index
        if pkt.get('src_ip') == ip or pkt.get('dst_ip') == ip
    ]
    
    # Statistiques pour cette IP
    protocols = {}
    ports = {'src': {}, 'dst': {}}
    conversations = {}
    
    for pkt in ip_packets:
        proto = pkt.get('protocol', 'Unknown')
        protocols[proto] = protocols.get(proto, 0) + 1
        
        if pkt.get('src_ip') == ip:
            other_ip = pkt.get('dst_ip')
            if pkt.get('src_port'):
                ports['src'][pkt['src_port']] = ports['src'].get(pkt['src_port'], 0) + 1
        else:
            other_ip = pkt.get('src_ip')
            if pkt.get('dst_port'):
                ports['dst'][pkt['dst_port']] = ports['dst'].get(pkt['dst_port'], 0) + 1
        
        if other_ip:
            conversations[other_ip] = conversations.get(other_ip, 0) + 1
    
    # Sessions TCP impliquant cette IP
    tcp_sessions = []
    for session in results.get('tcp_analysis', {}).get('sessions', []):
        src = session.get('src', '')
        dst = session.get('dst', '')
        if ip in src or ip in dst:
            tcp_sessions.append(session)
    
    # Requêtes DNS depuis cette IP
    dns_queries = [
        q for q in results.get('dns_analysis', {}).get('queries', [])
        if q.get('src_ip') == ip
    ]
    
    # Requêtes HTTP depuis cette IP
    http_requests = [
        r for r in results.get('http_analysis', {}).get('requests', [])
        if r.get('src_ip') == ip
    ]
    
    return {
        'ip': ip,
        'summary': {
            'total_packets': len(ip_packets),
            'total_bytes': sum(p.get('length', 0) for p in ip_packets),
            'protocols': protocols,
            'unique_conversations': len(conversations)
        },
        'packets': ip_packets[:500],  # Limiter
        'tcp_sessions': tcp_sessions,
        'dns_queries': dns_queries[:100],
        'http_requests': http_requests[:100],
        'top_conversations': sorted(conversations.items(), key=lambda x: x[1], reverse=True)[:20],
        'ports': {
            'src': sorted(ports['src'].items(), key=lambda x: x[1], reverse=True)[:20],
            'dst': sorted(ports['dst'].items(), key=lambda x: x[1], reverse=True)[:20]
        }
    }


@router.get("/analysis/{task_id}/session/{session_id}")
async def get_session_details(task_id: str, session_id: str):
    """
    Récupère les détails d'une session TCP spécifique
    
    - **task_id**: Identifiant de la tâche
    - **session_id**: Identifiant de la session (format: src_ip:port-dst_ip:port)
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    # Parser le session_id
    try:
        parts = session_id.replace('-', ':').split(':')
        if len(parts) >= 4:
            src_ip = parts[0]
            src_port = int(parts[1])
            dst_ip = parts[2]
            dst_port = int(parts[3])
        else:
            raise ValueError("Format invalide")
    except:
        raise HTTPException(status_code=400, detail="Format de session_id invalide. Utilisez: src_ip:port-dst_ip:port")
    
    # Trouver la session
    sessions = results.get('tcp_analysis', {}).get('sessions', [])
    session = None
    for s in sessions:
        s_src = s.get('src', '')
        s_dst = s.get('dst', '')
        if f"{src_ip}:{src_port}" in s_src and f"{dst_ip}:{dst_port}" in s_dst:
            session = s
            break
        if f"{dst_ip}:{dst_port}" in s_src and f"{src_ip}:{src_port}" in s_dst:
            session = s
            break
    
    # Filtrer les paquets de cette session
    packets_index = results.get('packets_index', [])
    session_packets = [
        pkt for pkt in packets_index
        if (pkt.get('src_ip') == src_ip and pkt.get('dst_ip') == dst_ip and 
            pkt.get('src_port') == src_port and pkt.get('dst_port') == dst_port) or
           (pkt.get('src_ip') == dst_ip and pkt.get('dst_ip') == src_ip and 
            pkt.get('src_port') == dst_port and pkt.get('dst_port') == src_port)
    ]
    
    return {
        'session_id': session_id,
        'session_info': session,
        'packets': session_packets[:500],
        'packet_count': len(session_packets),
        'timeline': {
            'first_packet': session_packets[0]['timestamp'] if session_packets else None,
            'last_packet': session_packets[-1]['timestamp'] if session_packets else None,
            'duration_seconds': (session_packets[-1]['timestamp'] - session_packets[0]['timestamp']) if len(session_packets) > 1 else 0
        }
    }


def extract_osi_layers(pkt, packet_info: dict) -> dict:
    """Extract OSI L1-L7 fields from a Scapy packet."""
    result = {
        'l1_physical': {
            'medium': 'Ethernet',
            'capture_len': packet_info.get('length', len(pkt)),
            'original_len': len(pkt),
        },
        'l2_datalink': {'src_mac': None, 'dst_mac': None, 'src_vendor': None, 'dst_vendor': None, 'ethertype': None},
        'l3_network': {
            'src_ip': packet_info.get('src_ip'),
            'dst_ip': packet_info.get('dst_ip'),
            'ttl': None, 'version': None, 'ihl': None,
            'tos': None, 'fragment_offset': None, 'checksum': None, 'protocol_num': None,
        },
        'l4_transport': {
            'protocol': packet_info.get('protocol'),
            'src_port': packet_info.get('src_port'),
            'dst_port': packet_info.get('dst_port'),
            'seq': None, 'ack': None, 'window': None,
            'window_scale': None, 'window_effective': None,
            'flags': [], 'checksum': None, 'urgent': None,
            'udp_len': None,
        },
        'l5_session': {'stream_id': None, 'direction': None, 'state': None},
        'l6_presentation': {'tls_version': None, 'cipher_suite': None, 'sni': None},
        'l7_application': {'protocol': None, 'detail': {}},
        'raw_hex': '',
    }

    # L2 — Ethernet
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        src_mac = normalize_mac_address(getattr(eth, "src", ""))
        dst_mac = normalize_mac_address(getattr(eth, "dst", ""))
        result['l2_datalink']['src_mac'] = src_mac or eth.src
        result['l2_datalink']['dst_mac'] = dst_mac or eth.dst
        if src_mac:
            result['l2_datalink']['src_vendor'] = resolve_mac_vendor(src_mac)
        if dst_mac:
            result['l2_datalink']['dst_vendor'] = resolve_mac_vendor(dst_mac)
        try:
            result['l2_datalink']['ethertype'] = f'0x{int(eth.type):04x}'
        except (TypeError, ValueError):
            result['l2_datalink']['ethertype'] = str(eth.type)

    # L3 — IP
    if pkt.haslayer(IP):
        ip = pkt[IP]
        result['l3_network'].update({
            'src_ip': ip.src, 'dst_ip': ip.dst,
            'ttl': ip.ttl, 'version': ip.version, 'ihl': ip.ihl * 4,
            'tos': ip.tos, 'fragment_offset': ip.frag,
            'checksum': hex(ip.chksum) if ip.chksum is not None else None,
            'protocol_num': ip.proto,
        })
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        result['l3_network'].update({
            'src_ip': ip6.src, 'dst_ip': ip6.dst,
            'ttl': ip6.hlim, 'version': 6,
        })

    # L4 — TCP/UDP/ICMP
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        wscale = _extract_tcp_window_scale(tcp)
        effective_window = int(tcp.window) * (2 ** int(wscale)) if isinstance(wscale, int) else None
        flags = []
        flag_map = [('S','SYN'),('A','ACK'),('F','FIN'),('R','RST'),('P','PSH'),('U','URG'),('E','ECE'),('C','CWR')]
        for attr, name in flag_map:
            try:
                if getattr(tcp.flags, attr, False):
                    flags.append(name)
            except Exception:
                pass
        result['l4_transport'].update({
            'protocol': 'TCP',
            'src_port': tcp.sport, 'dst_port': tcp.dport,
            'seq': tcp.seq, 'ack': tcp.ack,
            'window': tcp.window, 'flags': flags,
            'window_scale': wscale,
            'window_effective': effective_window,
            'checksum': hex(tcp.chksum) if tcp.chksum is not None else None,
            'urgent': tcp.urgptr,
        })
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        result['l4_transport'].update({
            'protocol': 'UDP',
            'src_port': udp.sport, 'dst_port': udp.dport,
            'checksum': hex(udp.chksum) if udp.chksum is not None else None,
            'udp_len': udp.len,
        })
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        result['l4_transport']['protocol'] = 'ICMP'
        result['l7_application'] = {
            'protocol': 'ICMP',
            'detail': {'type': icmp.type, 'code': icmp.code},
        }

    # L7 — DNS
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        if dns.qd:
            qname = dns.qd.qname.decode('utf-8', errors='ignore') if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
            result['l7_application'] = {
                'protocol': 'DNS',
                'detail': {
                    'type': 'query' if dns.qr == 0 else 'response',
                    'domain': qname,
                    'qtype': dns.qd.qtype if dns.qd else None,
                    'rcode': dns.rcode if dns.qr == 1 else None,
                }
            }

    # L7 — Raw HTTP (basic detection) — only if not already set by DNS
    if pkt.haslayer(Raw) and result['l7_application']['protocol'] is None:
        try:
            payload = bytes(pkt[Raw]).decode('utf-8', errors='ignore')
            if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'HTTP/')):
                first_line = payload.split('\n')[0].strip()
                result['l7_application'] = {
                    'protocol': 'HTTP',
                    'detail': {'first_line': first_line, 'body_preview': payload[:200]},
                }
        except Exception:
            pass

    # Raw hex (first 256 bytes)
    try:
        raw_bytes = bytes(pkt)[:256]
        result['raw_hex'] = ' '.join(f'{b:02x}' for b in raw_bytes)
    except Exception:
        result['raw_hex'] = ''

    return result


@router.get("/analysis/{task_id}/packet/{packet_num}")
async def get_packet_details(task_id: str, packet_num: int):
    """
    Récupère les détails complets d'un paquet spécifique
    
    - **task_id**: Identifiant de la tâche
    - **packet_num**: Numéro du paquet (index)
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    packets_index = results.get('packets_index', [])
    
    if packet_num < 0 or packet_num >= len(packets_index):
        raise HTTPException(status_code=404, detail="Paquet non trouvé")
    
    packet = packets_index[packet_num]
    
    # Enrichir avec les informations DNS si disponibles
    dns_info = None
    for q in results.get('dns_analysis', {}).get('queries', []):
        if q.get('packet_idx') == packet_num:
            dns_info = {'type': 'query', 'data': q}
            break
    for r in results.get('dns_analysis', {}).get('responses', []):
        if r.get('packet_idx') == packet_num:
            dns_info = {'type': 'response', 'data': r}
            break
    
    # Enrichir avec les informations HTTP si disponibles
    http_info = None
    for r in results.get('http_analysis', {}).get('requests', []):
        if r.get('packet_idx') == packet_num:
            http_info = {'type': 'request', 'data': r}
            break
    for r in results.get('http_analysis', {}).get('responses', []):
        if r.get('packet_idx') == packet_num:
            http_info = {'type': 'response', 'data': r}
            break
    
    # Re-read PCAP for full layer data
    layers = {}
    pcap_path = storage_service.get_pcap_path(task_id)
    if pcap_path:
        try:
            import asyncio
            from scapy.all import PcapReader
            from app.services.packet_index_service import get_packet_by_index

            def _read_packet(path, idx, pkt_info):
                # Accès direct via l'index d'offsets (O(1) au lieu d'un scan O(N))
                raw_pkt = get_packet_by_index(path, idx, storage_service.get_results_path(task_id))
                if raw_pkt is not None:
                    return extract_osi_layers(raw_pkt, pkt_info)
                # Fallback scan linéaire (PCAPNG ou index indisponible)
                with PcapReader(path) as reader:
                    for i, raw_pkt in enumerate(reader):
                        if i == idx:
                            return extract_osi_layers(raw_pkt, pkt_info)
                return {}

            layers = await asyncio.to_thread(_read_packet, pcap_path, packet_num, packet)
        except Exception as e:
            logger.warning(f"Could not re-read PCAP for packet {packet_num}: {e}")

    # Enrich L5 from tcp sessions
    if layers and packet.get('src_port') is not None and packet.get('dst_port') is not None:
        src = f"{packet.get('src_ip')}:{packet.get('src_port')}"
        dst = f"{packet.get('dst_ip')}:{packet.get('dst_port')}"
        for idx, s in enumerate(results.get('tcp_analysis', {}).get('sessions', [])):
            if (s.get('src') == src and s.get('dst') == dst) or \
               (s.get('src') == dst and s.get('dst') == src):
                layers['l5_session'] = {
                    'stream_id': idx,
                    'state': s.get('state'),
                    'direction': 'client_to_server' if s.get('src') == src else 'server_to_client',
                }
                l4_transport = layers.get('l4_transport', {}) if isinstance(layers.get('l4_transport', {}), dict) else {}
                session_wscale = s.get('window_scale', {}) if isinstance(s.get('window_scale', {}), dict) else {}
                packet_scale = None
                if s.get('src') == src:
                    packet_scale = session_wscale.get('src')
                else:
                    packet_scale = session_wscale.get('dst')
                if packet_scale is None:
                    packet_scale = session_wscale.get('src') if session_wscale.get('src') is not None else session_wscale.get('dst')

                if packet_scale is not None and l4_transport.get('window_scale') is None:
                    try:
                        scale_value = max(0, min(14, int(packet_scale)))
                        l4_transport['window_scale'] = scale_value
                        if l4_transport.get('window_effective') is None and l4_transport.get('window') is not None:
                            l4_transport['window_effective'] = int(l4_transport.get('window')) * (2 ** scale_value)
                        layers['l4_transport'] = l4_transport
                    except (TypeError, ValueError):
                        pass
                break

    # Enrich L6 from tls sessions
    if layers and packet.get('src_port') is not None and packet.get('dst_port') is not None:
        src = f"{packet.get('src_ip')}:{packet.get('src_port')}"
        dst = f"{packet.get('dst_ip')}:{packet.get('dst_port')}"
        for tls_s in results.get('tls_analysis', {}).get('sessions', []):
            tls_src = f"{tls_s.get('src_ip') or tls_s.get('client_ip')}:{tls_s.get('src_port') or tls_s.get('client_port') or 0}"
            tls_dst = f"{tls_s.get('dst_ip') or tls_s.get('server_ip')}:{tls_s.get('dst_port') or tls_s.get('server_port') or 443}"
            if (tls_src == src and tls_dst == dst) or (tls_src == dst and tls_dst == src):
                sni = tls_s.get('sni') or tls_s.get('server_name')
                layers['l6_presentation'] = {
                    'tls_version': tls_s.get('version') or tls_s.get('tls_version'),
                    'cipher_suite': tls_s.get('cipher_suite'),
                    'sni': sni,
                }
                break

    return {
        'packet_num': packet_num,
        'basic_info': packet,
        'dns_info': dns_info,
        'http_info': http_info,
        **layers,
    }


@router.get("/analysis/{task_id}/dns")
async def get_dns_analysis(task_id: str, limit: int = 100):
    """
    Récupère l'analyse DNS détaillée
    
    - **task_id**: Identifiant de la tâche
    - **limit**: Nombre maximum de résultats
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    dns = results.get('dns_analysis', {})
    
    return {
        'summary': dns.get('summary', {}),
        'queries': dns.get('queries', [])[:limit],
        'responses': dns.get('responses', [])[:limit],
        'top_domains': dns.get('top_domains', []),
        'dns_servers': dns.get('dns_servers', []),
        'query_types': dns.get('query_types', {}),
        'response_codes': dns.get('response_codes', {}),
        'anomalies': dns.get('anomalies', [])
    }


@router.get("/analysis/{task_id}/http")
async def get_http_analysis(task_id: str, limit: int = 100):
    """
    Récupère l'analyse HTTP/HTTPS détaillée
    
    - **task_id**: Identifiant de la tâche
    - **limit**: Nombre maximum de résultats
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    http = results.get('http_analysis', {})
    
    return {
        'summary': http.get('summary', {}),
        'requests': http.get('requests', [])[:limit],
        'responses': http.get('responses', [])[:limit],
        'methods': http.get('methods', {}),
        'status_codes': http.get('status_codes', {}),
        'user_agents': http.get('user_agents', []),
        'hosts': http.get('hosts', []),
        'top_urls': http.get('top_urls', []),
        'tls': http.get('tls', {}),
        'anomalies': http.get('anomalies', [])
    }


@router.get("/analysis/{task_id}/packets")
async def get_packets_list(task_id: str, page: int = 1, per_page: int = 100,
                           limit: Optional[int] = None,
                           protocol: Optional[str] = None, ip: Optional[str] = None):
    """
    Récupère la liste paginée des paquets avec filtres optionnels
    
    - **task_id**: Identifiant de la tâche
    - **page**: Numéro de page (défaut: 1)
    - **per_page**: Nombre de paquets par page (défaut: 100, max: 500)
    - **protocol**: Filtrer par protocole (TCP, UDP, DNS, etc.)
    - **ip**: Filtrer par adresse IP
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    packets = results.get('packets_index', [])
    
    # Appliquer les filtres
    if protocol:
        packets = [p for p in packets if p.get('protocol', '').upper() == protocol.upper()]
    
    if ip:
        packets = [p for p in packets if p.get('src_ip') == ip or p.get('dst_ip') == ip]
    
    # Compatibilité: "limit" est accepté comme alias de per_page
    if limit is not None:
        per_page = limit

    # Pagination
    per_page = min(max(per_page, 1), 10000)
    total = len(packets)
    start = (page - 1) * per_page
    end = start + per_page
    
    return {
        'page': page,
        'per_page': per_page,
        'total': total,
        'total_pages': (total + per_page - 1) // per_page,
        'packets': packets[start:end]
    }


# ==================== TIMELINE ENDPOINTS ====================

@router.get("/analysis/{task_id}/timeline/structured")
async def get_timeline(
    task_id: str,
    types: Optional[str] = None,
    groups: Optional[str] = None,
    ip: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None
):
    """
    Récupère les données de timeline pour la visualisation interactive
    
    - **task_id**: Identifiant de la tâche
    - **types**: Filtrer par types d'événements (comma-separated)
    - **groups**: Filtrer par groupes (comma-separated)
    - **ip**: Filtrer par adresse IP
    - **start_time**: Filtrer depuis cette date/heure (ISO format)
    - **end_time**: Filtrer jusqu'à cette date/heure (ISO format)
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    # Construire les filtres
    filters = {}
    if types:
        filters["types"] = [t.strip() for t in types.split(",")]
    if groups:
        filters["groups"] = [g.strip() for g in groups.split(",")]
    if ip:
        filters["ip"] = ip
    if start_time:
        filters["start_time"] = start_time
    if end_time:
        filters["end_time"] = end_time
    
    timeline_service = get_timeline_service()
    timeline_data = timeline_service.generate_timeline(results, filters if filters else None)
    
    return timeline_data


# ==================== NETWORK GRAPH ENDPOINTS ====================

@router.get("/analysis/{task_id}/network-graph")
async def get_network_graph(
    task_id: str,
    protocols: Optional[str] = None,
    roles: Optional[str] = None,
    subnet: Optional[str] = None
):
    """
    Récupère les données du graphe de réseau pour la visualisation
    
    - **task_id**: Identifiant de la tâche
    - **protocols**: Filtrer par protocoles (comma-separated)
    - **roles**: Filtrer par rôles (comma-separated: server, client, attacker, etc.)
    - **subnet**: Filtrer par sous-réseau (ex: 192.168.1.0/24)
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    # Construire les filtres
    filters = {}
    if protocols:
        filters["protocols"] = [p.strip() for p in protocols.split(",")]
    if roles:
        filters["roles"] = [r.strip() for r in roles.split(",")]
    if subnet:
        filters["subnet"] = subnet
    
    graph_service = get_graph_service()
    graph_data = graph_service.generate_network_graph(results, filters if filters else None)
    
    return graph_data


# ==================== STREAM RECONSTRUCTION ENDPOINTS ====================

@router.get("/analysis/{task_id}/stream/{stream_id}")
async def get_stream_details(task_id: str, stream_id: int):
    """
    Récupère les détails d'un stream TCP spécifique
    """
    logger.info(f"🔍 Détails stream {stream_id} pour task_id: {task_id}")
    
    try:
        results = storage_service.load_results(task_id)
        if not results:
            raise HTTPException(status_code=404, detail="Résultats non trouvés")
        
        # Récupérer la session correspondante
        tcp_analysis = results.get('tcp_analysis', {})
        sessions = tcp_analysis.get('sessions', [])
        
        logger.info(f"📊 Total sessions disponibles: {len(sessions)}")
        
        if stream_id >= len(sessions):
            logger.error(f"❌ Stream {stream_id} non trouvé (max: {len(sessions)-1})")
            raise HTTPException(status_code=404, detail="Stream non trouvé")
        
        session = sessions[stream_id]
        logger.info(f"📦 Session {stream_id}: {session}")
        
        # Extraire les informations du stream
        src = session.get('src', '')
        dst = session.get('dst', '')
        
        src_parts = src.split(':')
        dst_parts = dst.split(':')
        
        src_ip = src_parts[0] if len(src_parts) > 0 else 'unknown'
        src_port = int(src_parts[1]) if len(src_parts) > 1 else 0
        dst_ip = dst_parts[0] if len(dst_parts) > 0 else 'unknown'
        dst_port = int(dst_parts[1]) if len(dst_parts) > 1 else 0
        
        logger.info(f"🔗 Stream: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        
        stream_info = {
            'stream_id': stream_id,
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'packet_count': session.get('packets', 0),
            'total_bytes': session.get('bytes', 0),
            'state': session.get('state', 'UNKNOWN'),
            'retransmissions': session.get('retransmissions', 0),
            'rst_count': session.get('rst_count', 0)
        }
        
        # Récupérer le chemin du fichier PCAP
        pcap_path = storage_service.get_pcap_path(task_id)
        
        if not pcap_path:
            logger.warning(f"⚠️ Fichier PCAP non trouvé pour task_id: {task_id}")
            return JSONResponse(content={
                "task_id": task_id,
                "stream_info": stream_info,
                "packets": [],
                "error": "Fichier PCAP non disponible"
            })
        
        if not os.path.exists(pcap_path):
            logger.error(f"❌ Fichier PCAP n'existe pas: {pcap_path}")
            return JSONResponse(content={
                "task_id": task_id,
                "stream_info": stream_info,
                "packets": [],
                "error": "Fichier PCAP non accessible"
            })
        
        # Lire les paquets du stream depuis le PCAP
        logger.info(f"📂 Lecture du PCAP: {pcap_path}")
        packets = extract_stream_packets(pcap_path, src_ip, src_port, dst_ip, dst_port)
        
        logger.info(f"✅ Stream {stream_id}: {len(packets)} paquets extraits")
        
        return JSONResponse(content={
            "task_id": task_id,
            "stream_info": stream_info,
            "packets": packets
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur détails stream: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ⬇️⬇️⬇️ METTEZ LA FONCTION ICI ⬇️⬇️⬇️
def extract_stream_packets(pcap_path: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int, max_packets: int = 100):
    """
    Extrait les paquets d'un stream TCP depuis un fichier PCAP
    """
    try:
        from scapy.all import rdpcap, TCP, IP
        import base64
    except ImportError as e:
        logger.error(f"❌ Erreur import Scapy: {e}")
        return []
    
    packets = []
    
    try:
        # Lire le PCAP (limiter à 10000 paquets pour la performance)
        logger.info(f"🔍 Recherche des paquets: {src_ip}:{src_port} <-> {dst_ip}:{dst_port}")
        
        # Vérifier que le fichier existe
        if not os.path.exists(pcap_path):
            logger.error(f"❌ Fichier PCAP introuvable: {pcap_path}")
            return []
        
        # Vérifier la taille du fichier
        file_size = os.path.getsize(pcap_path)
        logger.info(f"📦 Taille du fichier PCAP: {file_size / 1024 / 1024:.2f} MB")
        
        pcap_packets = rdpcap(pcap_path, count=10000)
        logger.info(f"📊 {len(pcap_packets)} paquets lus depuis le PCAP")
        
        packet_count = 0
        
        for idx, pkt in enumerate(pcap_packets):
            if packet_count >= max_packets:
                logger.info(f"⚠️ Limite de {max_packets} paquets atteinte")
                break
            
            # Vérifier si c'est un paquet TCP/IP
            if not (IP in pkt and TCP in pkt):
                continue
            
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]
            
            # Vérifier si le paquet appartient au stream
            is_forward = (
                ip_layer.src == src_ip and tcp_layer.sport == src_port and
                ip_layer.dst == dst_ip and tcp_layer.dport == dst_port
            )
            
            is_backward = (
                ip_layer.src == dst_ip and tcp_layer.sport == dst_port and
                ip_layer.dst == src_ip and tcp_layer.dport == src_port
            )
            
            if not (is_forward or is_backward):
                continue
            
            # Paquet trouvé !
            packet_count += 1
            
            if packet_count == 1:
                logger.info(f"✅ Premier paquet du stream trouvé à l'index {idx}")
            
            # Déterminer la direction
            direction = 'client_to_server' if is_forward else 'server_to_client'
            
            # Extraire les flags TCP
            flags = []
            if tcp_layer.flags.S: flags.append('SYN')
            if tcp_layer.flags.A: flags.append('ACK')
            if tcp_layer.flags.F: flags.append('FIN')
            if tcp_layer.flags.R: flags.append('RST')
            if tcp_layer.flags.P: flags.append('PSH')
            
            # Extraire le payload
            payload = ''
            payload_len = 0
            
            if hasattr(tcp_layer, 'payload') and tcp_layer.payload:
                raw_payload = bytes(tcp_layer.payload)
                payload_len = len(raw_payload)
                
                if payload_len > 0:
                    # Essayer de décoder en UTF-8
                    try:
                        payload = raw_payload.decode('utf-8', errors='ignore')
                        # Limiter la taille
                        if len(payload) > 1000:
                            payload = payload[:1000] + '\n... (tronqué)'
                    except:
                        # Si échec, convertir en base64
                        payload = base64.b64encode(raw_payload[:500]).decode('ascii')
            
            pkt_wscale = _extract_tcp_window_scale(tcp_layer)
            packet_info = {
                'timestamp': float(pkt.time),
                'direction': direction,
                'length': len(pkt),
                'flags': ' '.join(flags) if flags else 'None',
                'seq': tcp_layer.seq,
                'ack': tcp_layer.ack,
                'window': tcp_layer.window,
                'window_scale': pkt_wscale,
                'window_effective': (
                    int(tcp_layer.window) * (2 ** int(pkt_wscale))
                    if pkt_wscale is not None else None
                ),
                'payload': payload,
                'payload_len': payload_len
            }
            
            packets.append(packet_info)
        
        logger.info(f"✅ {len(packets)} paquets extraits du stream sur {len(pcap_packets)} paquets totaux")
        
    except Exception as e:
        logger.error(f"❌ Erreur extraction paquets: {e}", exc_info=True)
    
    return packets
# ⬆️⬆️⬆️ FIN DE LA FONCTION ⬆️⬆️⬆️



@router.get("/analysis/{task_id}/stream/tcp/{stream_id:path}")
async def get_tcp_stream(task_id: str, stream_id: str):
    """
    Reconstruit un stream TCP complet
    
    - **task_id**: Identifiant de la tâche
    - **stream_id**: Identifiant du stream (format: src_ip:src_port:dst_ip:dst_port)
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    pcap_path = results.get("metadata", {}).get("pcap_path")
    if not pcap_path or not Path(pcap_path).exists():
        raise HTTPException(status_code=404, detail="Fichier PCAP non trouvé")
    
    stream_service = get_stream_service()
    stream_data = stream_service.reconstruct_tcp_stream(Path(pcap_path), stream_id, results)
    
    if stream_data.get("error"):
        raise HTTPException(status_code=400, detail=stream_data["error"])
    
    return stream_data


@router.get("/analysis/{task_id}/stream/http/{session_id:path}")
async def get_http_session(task_id: str, session_id: str):
    """
    Reconstruit une session HTTP complète
    
    - **task_id**: Identifiant de la tâche
    - **session_id**: Identifiant de la session (format: src_ip:src_port:dst_ip:dst_port)
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    pcap_path = results.get("metadata", {}).get("pcap_path")
    if not pcap_path or not Path(pcap_path).exists():
        raise HTTPException(status_code=404, detail="Fichier PCAP non trouvé")
    
    stream_service = get_stream_service()
    session_data = stream_service.reconstruct_http_session(Path(pcap_path), session_id, results)
    
    if session_data.get("error"):
        raise HTTPException(status_code=400, detail=session_data["error"])
    
    return session_data


@router.get("/analysis/{task_id}/stream/{stream_id}/export/{format}")
async def export_stream(task_id: str, stream_id: int, format: str):
    """
    Exporte un stream TCP
    
    - **task_id**: Identifiant de la tâche
    - **stream_id**: Identifiant du stream
    - **format**: Format d'export (text, html, raw)
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    pcap_path = results.get("metadata", {}).get("pcap_path")
    if not pcap_path or not Path(pcap_path).exists():
        raise HTTPException(status_code=404, detail="Fichier PCAP non trouvé")

    sessions = results.get("tcp_analysis", {}).get("sessions", [])
    if stream_id < 0 or stream_id >= len(sessions):
        raise HTTPException(status_code=404, detail="Stream non trouvé")

    session = sessions[stream_id]
    src = session.get("src", "")
    dst = session.get("dst", "")
    if ":" not in src or ":" not in dst:
        raise HTTPException(status_code=400, detail="Format de session invalide")

    src_ip, src_port = src.rsplit(":", 1)
    dst_ip, dst_port = dst.rsplit(":", 1)
    stream_identifier = f"{src_ip}:{src_port}:{dst_ip}:{dst_port}"
    
    stream_service = get_stream_service()
    content, media_type = stream_service.export_stream(Path(pcap_path), stream_identifier, format)
    
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename=stream_{stream_id}.{format}"}
    )


# ==================== ENTERPRISE PROTOCOLS ENDPOINTS ====================

@router.get("/analysis/{task_id}/smb")
async def get_smb_analysis(task_id: str):
    """
    Récupère l'analyse SMB/CIFS détaillée
    
    - **task_id**: Identifiant de la tâche
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    smb = results.get('smb_analysis', {})
    
    return {
        'summary': smb.get('summary', {}),
        'sessions': smb.get('sessions', [])[:100],
        'shares': smb.get('shares', [])[:50],
        'file_operations': smb.get('file_operations', [])[:200],
        'auth_attempts': smb.get('auth_attempts', [])[:100],
        'commands': smb.get('commands', {}),
        'anomalies': smb.get('anomalies', [])
    }


@router.get("/analysis/{task_id}/ldap")
async def get_ldap_analysis(task_id: str):
    """
    Récupère l'analyse LDAP détaillée
    
    - **task_id**: Identifiant de la tâche
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    ldap = results.get('ldap_analysis', {})
    
    return {
        'summary': ldap.get('summary', {}),
        'sessions': ldap.get('sessions', [])[:100],
        'bind_attempts': ldap.get('bind_attempts', [])[:100],
        'search_queries': ldap.get('search_queries', [])[:200],
        'modifications': ldap.get('modifications', [])[:100],
        'operations': ldap.get('operations', {}),
        'queried_attributes': ldap.get('queried_attributes', {}),
        'base_dns': ldap.get('base_dns', {}),
        'anomalies': ldap.get('anomalies', [])
    }


@router.get("/analysis/{task_id}/kerberos")
async def get_kerberos_analysis(task_id: str):
    """
    Récupère l'analyse Kerberos détaillée
    
    - **task_id**: Identifiant de la tâche
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    kerberos = results.get('kerberos_analysis', {})
    
    return {
        'summary': kerberos.get('summary', {}),
        'as_requests': kerberos.get('as_requests', [])[:100],
        'as_responses': kerberos.get('as_responses', [])[:100],
        'tgs_requests': kerberos.get('tgs_requests', [])[:200],
        'tgs_responses': kerberos.get('tgs_responses', [])[:100],
        'errors': kerberos.get('errors', [])[:100],
        'message_types': kerberos.get('message_types', {}),
        'encryption_types': kerberos.get('encryption_types', {}),
        'principals': kerberos.get('principals', [])[:100],
        'services': kerberos.get('services', {}),
        'realms': kerberos.get('realms', {}),
        'anomalies': kerberos.get('anomalies', [])
    }


@router.get("/analysis/{task_id}/rdp")
async def get_rdp_analysis(task_id: str):
    """
    Récupère l'analyse RDP détaillée
    
    - **task_id**: Identifiant de la tâche
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    rdp = results.get('rdp_analysis', {})
    
    return {
        'summary': rdp.get('summary', {}),
        'connections': rdp.get('connections', [])[:100],
        'connection_attempts': rdp.get('connection_attempts', [])[:200],
        'handshakes': rdp.get('handshakes', [])[:100],
        'sessions': rdp.get('sessions', [])[:100],
        'protocols_used': rdp.get('protocols_used', {}),
        'security_levels': rdp.get('security_levels', {}),
        'anomalies': rdp.get('anomalies', [])
    }


@router.get("/analysis/{task_id}/ssh")
async def get_ssh_analysis(task_id: str):
    """
    Récupère l'analyse SSH détaillée
    
    - **task_id**: Identifiant de la tâche
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    ssh = results.get('ssh_analysis', {})
    
    return {
        'summary': ssh.get('summary', {}),
        'connections': ssh.get('connections', [])[:100],
        'sessions': ssh.get('sessions', [])[:100],
        'auth_attempts': ssh.get('auth_attempts', [])[:200],
        'version_exchanges': ssh.get('version_exchanges', [])[:100],
        'tunnels': ssh.get('tunnels', [])[:50],
        'client_versions': ssh.get('client_versions', {}),
        'server_versions': ssh.get('server_versions', {}),
        'ciphers_negotiated': ssh.get('ciphers_negotiated', {}),
        'key_exchanges': ssh.get('key_exchanges', {}),
        'anomalies': ssh.get('anomalies', [])
    }


# ==================== ENRICHMENT ENDPOINTS ====================

@router.get("/analysis/{task_id}/enrichment")
async def get_enrichment_data(task_id: str):
    """
    Récupère les données d'enrichissement (GeoIP, ASN, WHOIS)
    
    - **task_id**: Identifiant de la tâche
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    return results.get('enrichment', {})


@router.get("/analysis/{task_id}/enrichment/ip/{ip}")
async def get_ip_enrichment(task_id: str, ip: str):
    """
    Récupère les données d'enrichissement pour une IP spécifique
    
    - **task_id**: Identifiant de la tâche
    - **ip**: Adresse IP à enrichir
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    enrichment = results.get('enrichment', {})
    ip_data = enrichment.get('ips', {}).get(ip)
    
    if ip_data:
        return ip_data
    
    # Si pas en cache, enrichir à la demande
    enrichment_service = get_enrichment_service()
    return enrichment_service.enrich_ip(ip)


# ==================== ALL ANOMALIES ENDPOINT ====================

@router.get("/analysis/{task_id}/anomalies")
async def get_all_anomalies(task_id: str, severity: Optional[str] = None, source: Optional[str] = None):
    """
    Récupère toutes les anomalies agrégées de tous les analyseurs
    
    - **task_id**: Identifiant de la tâche
    - **severity**: Filtrer par sévérité (critical, high, medium, low)
    - **source**: Filtrer par source (network, dns, http, smb, ldap, kerberos, rdp, ssh)
    """
    results = storage_service.load_results(task_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Résultats non trouvés")
    
    anomalies = results.get('all_anomalies', [])
    
    # Appliquer les filtres
    if severity:
        anomalies = [a for a in anomalies if a.get('severity') == severity.lower()]
    if source:
        anomalies = [a for a in anomalies if a.get('source') == source.lower()]
    
    # Statistiques
    severity_counts = {}
    source_counts = {}
    for a in results.get('all_anomalies', []):
        sev = a.get('severity', 'unknown')
        src = a.get('source', 'unknown')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        source_counts[src] = source_counts.get(src, 0) + 1
    
    return {
        'anomalies': anomalies,
        'total': len(anomalies),
        'total_unfiltered': len(results.get('all_anomalies', [])),
        'by_severity': severity_counts,
        'by_source': source_counts
    }
@router.post("/analysis/{task_id}/ai-summary")
async def get_ai_summary(task_id: str):
    """
    Génère un résumé exécutif avec l'IA
    """
    logger.info(f"📊 Génération résumé IA pour task_id: {task_id}")
    
    try:
        # Vérifier Ollama
        if not ai_service.is_available():
            return JSONResponse(
                status_code=503,
                content={
                    "success": False,
                    "error": "Service Ollama non disponible"
                }
            )
        
        # Charger les résultats
        results = storage_service.load_results(task_id)
        if not results:
            raise HTTPException(status_code=404, detail="Résultats non trouvés")
        
        # Générer le résumé
        summary_result = ai_service.analyze_pcap_summary(results)
        
        if summary_result.get("success"):
            return JSONResponse(content={
                "success": True,
                "analysis": summary_result.get("analysis", ""),
                "generated_at": datetime.now().isoformat()
            })
        else:
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "error": summary_result.get("error", "Erreur inconnue")
                }
            )
            
    except Exception as e:
        logger.error(f"❌ Erreur résumé IA: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": str(e)
            }
        )


@router.post("/analysis/{task_id}/ai-dns")
async def get_ai_dns_analysis(task_id: str):
    """
    Analyse DNS avec l'IA
    """
    logger.info(f"🌐 Analyse DNS IA pour task_id: {task_id}")
    
    try:
        # Vérifier Ollama
        if not ai_service.is_available():
            return JSONResponse(
                status_code=503,
                content={
                    "success": False,
                    "error": "Service Ollama non disponible"
                }
            )
        
        # Charger les résultats
        results = storage_service.load_results(task_id)
        if not results:
            raise HTTPException(status_code=404, detail="Résultats non trouvés")
        
        # Extraire les données DNS
        dns_data = results.get('dns_analysis', {})
        
        if not dns_data or not dns_data.get('top_domains'):
            return JSONResponse(content={
                "success": True,
                "dns_analysis": "Aucune donnée DNS disponible dans cette capture"
            })
        
        # Analyser avec l'IA
        dns_result = ai_service.analyze_dns_suspicious(dns_data)
        
        if dns_result.get("success"):
            return JSONResponse(content={
                "success": True,
                "dns_analysis": dns_result.get("dns_analysis", ""),
                "generated_at": datetime.now().isoformat()
            })
        else:
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "error": dns_result.get("error", "Erreur inconnue")
                }
            )
            
    except Exception as e:
        logger.error(f"❌ Erreur analyse DNS IA: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": str(e)
            }
        )

@router.post("/analysis/{task_id}/ai-http")
async def get_ai_http_analysis(task_id: str):
    """
    Analyse HTTP/HTTPS avec l'IA
    """
    logger.info(f"🔗 Analyse HTTP IA pour task_id: {task_id}")
    
    try:
        # Vérifier Ollama
        if not ai_service.is_available():
            return JSONResponse(
                status_code=503,
                content={
                    "success": False,
                    "error": "Service Ollama non disponible"
                }
            )
        
        # Charger les résultats
        results = storage_service.load_results(task_id)
        if not results:
            raise HTTPException(status_code=404, detail="Résultats non trouvés")
        
        # Extraire les données HTTP
        http_data = results.get('http_analysis', {})
        
        logger.info(f"📊 Données HTTP trouvées: {list(http_data.keys())}")
        
        # ✅ CORRECTION: Vérifier PLUSIEURS indicateurs de données HTTP
        has_http_data = any([
            http_data.get('summary', {}).get('total_requests', 0) > 0,
            http_data.get('methods'),
            http_data.get('status_codes'),
            http_data.get('hosts'),
            http_data.get('top_hosts'),
            http_data.get('user_agents'),
            http_data.get('top_urls'),
            http_data.get('tls')
        ])
        
        if not has_http_data:
            logger.warning("⚠️ Aucune donnée HTTP détectée")
            return JSONResponse(content={
                "success": True,
                "http_analysis": "Aucune donnée HTTP/HTTPS n'a été détectée dans cette capture réseau. Cela peut signifier :\n\n• Le trafic capturé ne contient pas de requêtes HTTP/HTTPS\n• Le trafic HTTPS est chiffré et n'a pas pu être décodé\n• La capture est trop courte pour contenir du trafic web\n\nRecommandation : Vérifiez que la capture contient bien du trafic web (ports 80, 443, 8080, etc.)"
            })
        
        # Préparer un résumé structuré pour l'IA
        http_summary = {
            "total_requests": http_data.get('summary', {}).get('total_requests', 0),
            "methods": http_data.get('methods', {}),
            "status_codes": http_data.get('status_codes', {}),
            "top_hosts": http_data.get('hosts', [])[:10] or http_data.get('top_hosts', [])[:10],
            "top_user_agents": http_data.get('user_agents', [])[:5],
            "top_urls": http_data.get('top_urls', [])[:10],
            "tls_sessions": http_data.get('summary', {}).get('total_tls_sessions', 0),
            "tls_versions": http_data.get('tls', {}).get('versions', {}),
            "anomalies": http_data.get('anomalies', [])
        }
        
        logger.info(f"📤 Envoi à l'IA: {http_summary}")
        
        # Analyser avec l'IA
        http_result = ai_service.analyze_http_traffic(http_summary)
        
        if http_result.get("success"):
            return JSONResponse(content={
                "success": True,
                "http_analysis": http_result.get("http_analysis", ""),
                "generated_at": datetime.now().isoformat()
            })
        else:
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "error": http_result.get("error", "Erreur inconnue")
                }
            )
            
    except Exception as e:
        logger.error(f"❌ Erreur analyse HTTP IA: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": str(e)
            }
        )

@router.post("/analysis/{task_id}/ai-troubleshoot")
async def get_ai_troubleshooting(task_id: str):
    """
    Suggestions de dépannage avec l'IA
    """
    logger.info(f"🔧 Dépannage IA pour task_id: {task_id}")
    
    try:
        # Vérifier Ollama
        if not ai_service.is_available():
            return JSONResponse(
                status_code=503,
                content={
                    "success": False,
                    "error": "Service Ollama non disponible"
                }
            )
        
        # Charger les résultats
        results = storage_service.load_results(task_id)
        if not results:
            raise HTTPException(status_code=404, detail="Résultats non trouvés")
        
        # Générer les recommandations
        troubleshoot_result = ai_service.suggest_troubleshooting(results)
        
        if troubleshoot_result.get("success"):
            return JSONResponse(content={
                "success": True,
                "troubleshooting": troubleshoot_result.get("troubleshooting", ""),
                "generated_at": datetime.now().isoformat()
            })
        else:
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "error": troubleshoot_result.get("error", "Erreur inconnue")
                }
            )
            
    except Exception as e:
        logger.error(f"❌ Erreur dépannage IA: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": str(e)
            }
        )

@router.get("/analysis/{task_id}/streams")
async def get_tcp_streams(
    task_id: str,
    type: Optional[str] = Query(None, description="Filter by type: http, https"),
    ip: Optional[str] = Query(None, description="Filter by IP address"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=1000, description="Pagination limit"),
    sort_by: str = Query("risk", description="Sort: risk, packets, retrans, bytes, rst"),
    sort_order: str = Query("desc", description="Sort order: asc, desc"),
    problematic_only: bool = Query(False, description="Only problematic streams"),
):
    """
    Récupère la liste des streams TCP avec filtres, tri et pagination.
    """
    logger.info(
        "📊 Récupération streams task=%s type=%s ip=%s offset=%s limit=%s sort=%s/%s problematic_only=%s",
        task_id, type, ip, offset, limit, sort_by, sort_order, problematic_only
    )

    try:
        results = storage_service.load_results(task_id)
        if not results:
            raise HTTPException(status_code=404, detail="Résultats non trouvés")
        streams, source_counts = collect_streams_from_results(results)

        streams = filter_streams(streams, type, ip, problematic_only)
        streams = sort_streams(streams, sort_by, sort_order)
        total = len(streams)
        paged_streams = streams[offset: offset + limit]
        has_more = offset + limit < total

        logger.info("✅ Streams retournés: %s/%s (offset=%s, limit=%s)", len(paged_streams), total, offset, limit)

        return JSONResponse(content={
            "task_id": task_id,
            "streams": paged_streams,
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": has_more,
            "sort_by": sort_by,
            "sort_order": sort_order,
            "source_counts": source_counts,
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur streams: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analysis/{task_id}/streams/export/csv")
async def export_problematic_streams_csv(
    task_id: str,
    type: Optional[str] = Query(None, description="Filter by type: http, https"),
    ip: Optional[str] = Query(None, description="Filter by IP address"),
    sort_by: str = Query("risk", description="Sort: risk, packets, retrans, bytes, rst"),
    sort_order: str = Query("desc", description="Sort order: asc, desc"),
    problematic_only: bool = Query(True, description="Export only problematic streams"),
):
    """
    Exporte les streams filtrés au format CSV (par défaut uniquement les flux problématiques).
    """
    try:
        results = storage_service.load_results(task_id)
        if not results:
            raise HTTPException(status_code=404, detail="Résultats non trouvés")

        streams, _ = collect_streams_from_results(results)
        streams = filter_streams(streams, type, ip, problematic_only)
        streams = sort_streams(streams, sort_by, sort_order)

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "stream_id", "src_ip", "src_port", "dst_ip", "dst_port",
            "packet_count", "total_bytes", "state", "retransmissions",
            "rst_count", "risk_score", "risk_level", "probable_cause_code", "probable_cause",
            "cause_details", "stream_identifier"
        ])

        for s in streams:
            writer.writerow([
                s.get("stream_id", ""),
                s.get("src_ip", ""),
                s.get("src_port", ""),
                s.get("dst_ip", ""),
                s.get("dst_port", ""),
                _to_int(s.get("packet_count"), 0),
                _to_int(s.get("total_bytes"), 0),
                s.get("state", ""),
                _to_int(s.get("retransmissions"), 0),
                _to_int(s.get("rst_count"), 0),
                _to_int(s.get("risk_score"), 0),
                s.get("risk_level", "NONE"),
                s.get("probable_cause_code", ""),
                s.get("probable_cause", ""),
                s.get("cause_details", ""),
                s.get("stream_identifier", ""),
            ])

        content = output.getvalue()
        output.close()
        filename = f"streams_{task_id[:8]}_{'problematic' if problematic_only else 'all'}.csv"
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur export streams CSV: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


def collect_streams_from_results(results: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Construit la liste complète des streams depuis les sources disponibles."""
    streams: List[Dict[str, Any]] = []
    source_counts: Dict[str, int] = {"tcp_analysis": 0, "packets_index": 0, "protocol_fallback": 0}

    tcp_sessions = results.get("tcp_analysis", {}).get("sessions", [])
    if isinstance(tcp_sessions, list) and tcp_sessions:
        streams = parse_tcp_sessions(tcp_sessions)
        source_counts["tcp_analysis"] = len(streams)

    packets_index = results.get("packets_index", [])
    if isinstance(packets_index, list) and packets_index:
        pi_streams = build_streams_from_packets_index(packets_index)
        source_counts["packets_index"] = len(pi_streams)

        existing_by_key = {_stream_conn_key(s): s for s in streams}
        for s in pi_streams:
            k = _stream_conn_key(s)
            if k in existing_by_key:
                base = existing_by_key[k]
                base["packet_count"] = max(_to_int(base.get("packet_count")), _to_int(s.get("packet_count")))
                base["total_bytes"] = max(_to_int(base.get("total_bytes")), _to_int(s.get("total_bytes")))
                base["rst_count"] = max(_to_int(base.get("rst_count")), _to_int(s.get("rst_count")))
                base["syn_count"] = max(_to_int(base.get("syn_count")), _to_int(s.get("syn_count")))
                base["ack_count"] = max(_to_int(base.get("ack_count")), _to_int(s.get("ack_count")))
                base["fin_count"] = max(_to_int(base.get("fin_count")), _to_int(s.get("fin_count")))
                base["retransmissions"] = max(_to_int(base.get("retransmissions")), _to_int(s.get("retransmissions")))
            else:
                streams.append(s)
                existing_by_key[k] = s

    if not streams:
        protocol_analysis = results.get("protocol_analysis", {})
        tcp_packets: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for pkt in protocol_analysis.get("packets_sample", [])[:5000]:
            if pkt.get("protocol") != "TCP":
                continue
            src = f"{pkt.get('src_ip', 'unknown')}:{pkt.get('src_port', '0')}"
            dst = f"{pkt.get('dst_ip', 'unknown')}:{pkt.get('dst_port', '0')}"
            conn_key = tuple(sorted([src, dst]))
            if conn_key not in tcp_packets:
                tcp_packets[conn_key] = {"src": src, "dst": dst, "packets": 0, "bytes": 0}
            tcp_packets[conn_key]["packets"] += 1
            tcp_packets[conn_key]["bytes"] += pkt.get("length", 0)

        streams = parse_tcp_sessions(list(tcp_packets.values()))
        source_counts["protocol_fallback"] = len(streams)

    for idx, stream in enumerate(streams):
        stream["stream_id"] = idx
        if not stream.get("stream_identifier"):
            stream["stream_identifier"] = (
                f"{stream.get('src_ip', '')}:{stream.get('src_port', '')}:"
                f"{stream.get('dst_ip', '')}:{stream.get('dst_port', '')}"
            )
        enrich_stream_diagnostics(stream)

    return streams, source_counts


from app.core.utils import as_int as _to_int  # noqa: E402


def _stream_conn_key(stream: Dict[str, Any]) -> Tuple[Tuple[str, str], Tuple[str, str]]:
    src = (str(stream.get("src_ip", "")), str(stream.get("src_port", "")))
    dst = (str(stream.get("dst_ip", "")), str(stream.get("dst_port", "")))
    return tuple(sorted([src, dst]))  # type: ignore[return-value]


def _parse_endpoint(endpoint: str) -> Tuple[str, str]:
    raw = str(endpoint or "")
    if ":" not in raw:
        return raw, "0"
    parts = raw.rsplit(":", 1)
    return parts[0], parts[1]


def _detect_stream_type(dst_port: int) -> Tuple[bool, bool, bool]:
    is_http = dst_port in {80, 8080, 8000}
    is_https = dst_port in {443, 8443}
    return is_http, is_https, is_https


def parse_tcp_sessions(sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Parse les sessions TCP en format stream enrichi."""
    streams: List[Dict[str, Any]] = []
    for session in sessions:
        src_ip, src_port = _parse_endpoint(session.get("src", ""))
        dst_ip, dst_port = _parse_endpoint(session.get("dst", ""))
        if not src_ip or src_ip == "unknown" or not dst_ip or dst_ip == "unknown":
            continue

        dst_port_int = _to_int(dst_port, 0)
        is_http, is_https, is_tls = _detect_stream_type(dst_port_int)
        flags = session.get("flags") if isinstance(session.get("flags"), dict) else {}

        streams.append({
            "src": f"{src_ip}:{src_port}",
            "dst": f"{dst_ip}:{dst_port}",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "packet_count": _to_int(session.get("packets"), 0),
            "total_bytes": _to_int(session.get("bytes"), 0),
            "state": session.get("state", "ESTABLISHED"),
            "retransmissions": _to_int(session.get("retransmissions"), 0),
            "rst_count": _to_int(session.get("rst_count"), 0),
            "syn_count": _to_int(flags.get("syn"), 0),
            "ack_count": _to_int(flags.get("ack"), 0),
            "fin_count": _to_int(flags.get("fin"), 0),
            "is_http": is_http,
            "is_https": is_https,
            "is_tls": is_tls,
            "stream_identifier": f"{src_ip}:{src_port}:{dst_ip}:{dst_port}",
        })
    return streams


def _extract_tcp_flags_from_packet_info(pkt: Dict[str, Any]) -> List[str]:
    info = str(pkt.get("info", ""))
    if "[" not in info or "]" not in info:
        return []
    raw = info.split("[", 1)[1].split("]", 1)[0]
    return [f.strip().upper() for f in raw.split(",") if f.strip()]


def _infer_state_from_packet_counters(syn_count: int, ack_count: int, fin_count: int, rst_count: int) -> str:
    if rst_count > 0:
        return "CLOSED"
    if syn_count > 0 and ack_count == 0:
        return "SYN_SENT"
    if fin_count > 0:
        return "FIN_WAIT"
    if ack_count > 0:
        return "ESTABLISHED"
    return "UNKNOWN"


def build_streams_from_packets_index(packets_index: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Construit des streams TCP depuis packets_index (jusqu'à 5000 paquets)."""
    grouped: Dict[Tuple[Tuple[str, str], Tuple[str, str]], Dict[str, Any]] = {}

    for pkt in packets_index:
        if str(pkt.get("protocol", "")).upper() != "TCP":
            continue
        src_ip = str(pkt.get("src_ip") or "")
        dst_ip = str(pkt.get("dst_ip") or "")
        src_port = str(pkt.get("src_port") or "")
        dst_port = str(pkt.get("dst_port") or "")
        if not src_ip or not dst_ip or not src_port or not dst_port:
            continue

        key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
        if key not in grouped:
            grouped[key] = {
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "packet_count": 0,
                "total_bytes": 0,
                "retransmissions": 0,
                "rst_count": 0,
                "syn_count": 0,
                "ack_count": 0,
                "fin_count": 0,
            }

        stream = grouped[key]
        stream["packet_count"] += 1
        stream["total_bytes"] += _to_int(pkt.get("length"), 0)
        flags = _extract_tcp_flags_from_packet_info(pkt)
        if "RST" in flags:
            stream["rst_count"] += 1
        if "SYN" in flags:
            stream["syn_count"] += 1
        if "ACK" in flags:
            stream["ack_count"] += 1
        if "FIN" in flags:
            stream["fin_count"] += 1

    streams: List[Dict[str, Any]] = []
    for stream in grouped.values():
        dst_port_int = _to_int(stream.get("dst_port"), 0)
        is_http, is_https, is_tls = _detect_stream_type(dst_port_int)
        stream["state"] = _infer_state_from_packet_counters(
            _to_int(stream.get("syn_count")),
            _to_int(stream.get("ack_count")),
            _to_int(stream.get("fin_count")),
            _to_int(stream.get("rst_count")),
        )
        stream["is_http"] = is_http
        stream["is_https"] = is_https
        stream["is_tls"] = is_tls
        stream["src"] = f"{stream.get('src_ip')}:{stream.get('src_port')}"
        stream["dst"] = f"{stream.get('dst_ip')}:{stream.get('dst_port')}"
        stream["stream_identifier"] = (
            f"{stream.get('src_ip')}:{stream.get('src_port')}:"
            f"{stream.get('dst_ip')}:{stream.get('dst_port')}"
        )
        streams.append(stream)
    return streams


def enrich_stream_diagnostics(stream: Dict[str, Any]) -> None:
    """Ajoute score de risque + cause probable avec règles explicites."""
    packets = max(1, _to_int(stream.get("packet_count"), 0))
    retransmissions = _to_int(stream.get("retransmissions"), 0)
    rst_count = _to_int(stream.get("rst_count"), 0)
    syn_count = _to_int(stream.get("syn_count"), 0)
    ack_count = _to_int(stream.get("ack_count"), 0)
    state = str(stream.get("state", "UNKNOWN")).upper()

    retrans_ratio = retransmissions / packets
    score = 0
    if rst_count > 0:
        score += min(65, rst_count * 14)
    if retransmissions > 0:
        score += min(45, round(retrans_ratio * 350))
    if state in {"SYN_SENT", "SYN_RECV", "LAST_ACK", "CLOSE_WAIT"}:
        score += 15
    if state and state not in {"ESTABLISHED", "CLOSED", "FIN_WAIT", "TIME_WAIT"}:
        score += 10
    score = min(100, score)

    if score >= 70:
        risk_level = "HIGH"
    elif score >= 35:
        risk_level = "MEDIUM"
    elif score > 0:
        risk_level = "LOW"
    else:
        risk_level = "NONE"

    if rst_count >= 2:
        probable_cause_code = "reset-pair"
        probable_cause = "Reset pair (fermeture distante)"
        cause_details = f"RST={rst_count} détectés, indicative d'un rejet applicatif/ACL ou fermeture brutale."
    elif state in {"SYN_SENT", "SYN_RECV"} or (syn_count > 0 and ack_count == 0):
        probable_cause_code = "half-open"
        probable_cause = "Half-open (handshake incomplet)"
        cause_details = (
            f"Etat={state}, SYN={syn_count}, ACK={ack_count}. "
            "Possible filtrage, service non joignable ou timeout de handshake."
        )
    elif retrans_ratio >= 0.08 and packets >= 30:
        probable_cause_code = "congestion"
        probable_cause = "Congestion probable (retrans élevée)"
        cause_details = (
            f"Retransmissions={retransmissions}/{packets} ({retrans_ratio * 100:.1f}%). "
            "Possible saturation lien, queue pleine ou buffer drops."
        )
    elif retrans_ratio >= 0.02 and retransmissions > 0:
        probable_cause_code = "loss"
        probable_cause = "Perte paquets probable"
        cause_details = (
            f"Retransmissions={retransmissions}/{packets} ({retrans_ratio * 100:.1f}%). "
            "Possible erreurs physiques, Wi-Fi bruité ou micro-coupures."
        )
    elif state == "ESTABLISHED" and retransmissions == 0 and rst_count == 0:
        probable_cause_code = "stable"
        probable_cause = "Flux stable"
        cause_details = "Aucun symptôme de perte, reset ou handshake dégradé."
    else:
        probable_cause_code = "watch"
        probable_cause = "A surveiller"
        cause_details = f"Etat={state}, retrans={retransmissions}, rst={rst_count}."

    stream["risk_score"] = score
    stream["risk_level"] = risk_level
    stream["retrans_ratio"] = round(retrans_ratio, 4)
    stream["probable_cause_code"] = probable_cause_code
    stream["probable_cause"] = probable_cause
    stream["cause_details"] = cause_details


def sort_streams(streams: List[Dict[str, Any]], sort_by: str, sort_order: str) -> List[Dict[str, Any]]:
    sort_key = str(sort_by or "risk").lower()
    reverse = str(sort_order or "desc").lower() != "asc"

    def key_fn(s: Dict[str, Any]) -> Tuple[int, int, int]:
        if sort_key == "packets":
            return (_to_int(s.get("packet_count")), _to_int(s.get("risk_score")), _to_int(s.get("total_bytes")))
        if sort_key == "retrans":
            return (_to_int(s.get("retransmissions")), _to_int(s.get("risk_score")), _to_int(s.get("packet_count")))
        if sort_key == "bytes":
            return (_to_int(s.get("total_bytes")), _to_int(s.get("risk_score")), _to_int(s.get("packet_count")))
        if sort_key == "rst":
            return (_to_int(s.get("rst_count")), _to_int(s.get("risk_score")), _to_int(s.get("packet_count")))
        return (_to_int(s.get("risk_score")), _to_int(s.get("retransmissions")), _to_int(s.get("packet_count")))

    return sorted(streams, key=key_fn, reverse=reverse)


def filter_streams(
    streams: List[Dict[str, Any]],
    type_filter: Optional[str],
    ip_filter: Optional[str],
    problematic_only: bool = False
) -> List[Dict[str, Any]]:
    """Filtre les streams selon type, ip et criticité."""
    filtered: List[Dict[str, Any]] = []
    norm_type = str(type_filter or "").lower().strip()
    norm_ip = str(ip_filter or "").strip()

    for stream in streams:
        if norm_type == "http" and not stream.get("is_http"):
            continue
        if norm_type == "https" and not stream.get("is_https"):
            continue
        if norm_ip and norm_ip not in str(stream.get("src_ip", "")) and norm_ip not in str(stream.get("dst_ip", "")):
            continue
        if problematic_only and str(stream.get("risk_level", "NONE")).upper() == "NONE":
            continue
        filtered.append(stream)
    return filtered






@router.post("/analysis/{task_id}/ai-attack-patterns")
async def get_ai_attack_patterns(task_id: str):
    """
    Détection de patterns d'attaque avec l'IA
    """
    logger.info(f"🎯 Détection patterns pour task_id: {task_id}")
    
    try:
        # Vérifier Ollama
        if not ai_service.is_available():
            return JSONResponse(
                status_code=503,
                content={
                    "success": False,
                    "error": "Service Ollama non disponible"
                }
            )
        
        # Charger les résultats
        results = storage_service.load_results(task_id)
        if not results:
            raise HTTPException(status_code=404, detail="Résultats non trouvés")
        
        # Extraire les anomalies
        anomalies = _get_anomaly_block(results).get('anomalies', [])
        protocol_analysis = results.get('protocol_analysis', {})
        
        if not anomalies:
            return JSONResponse(content={
                "success": True,
                "patterns": [],
                "message": "Aucune anomalie détectée"
            })
        
        # Détecter les patterns
        patterns_result = ai_service.detect_attack_patterns(anomalies, protocol_analysis)
        
        if patterns_result.get("success"):
            return JSONResponse(content={
                "success": True,
                "patterns": patterns_result.get("patterns", []),
                "raw_analysis": patterns_result.get("raw_analysis", ""),
                "generated_at": datetime.now().isoformat()
            })
        else:
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "error": patterns_result.get("error", "Erreur inconnue")
                }
            )
            
    except Exception as e:
        logger.error(f"❌ Erreur détection patterns: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": str(e)
            }
        )
