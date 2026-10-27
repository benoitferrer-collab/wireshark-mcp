"""
Service de stockage pour les fichiers PCAP et résultats
Gestion du filesystem, validation, nettoyage
"""

import os
import re
import json
import uuid
import shutil
import threading
from collections import OrderedDict
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

try:
    import orjson
except ImportError:  # pragma: no cover - fallback si orjson absent
    orjson = None

from app.core.config import settings
from app.core.logging_config import get_logger

logger = get_logger(__name__)

# task_id valide: caractères sûrs uniquement (UUID + variantes), jamais de
# séparateur de chemin ni de '..' — bloque les traversées type /api/delete/..
_SAFE_TASK_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')


def _validate_task_id(task_id: str) -> str:
    if not isinstance(task_id, str) or not _SAFE_TASK_ID.match(task_id):
        raise ValueError(f"task_id invalide: {task_id!r}")
    return task_id


def _dump_json(data: Dict[str, Any], path: Path):
    """Sérialise en JSON compact (orjson si disponible, ~10x plus rapide)"""
    if orjson is not None:
        path.write_bytes(orjson.dumps(data, default=str))
    else:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, separators=(',', ':'), default=str)


def _load_json(path: Path) -> Dict[str, Any]:
    """Désérialise un JSON (orjson si disponible)"""
    if orjson is not None:
        return orjson.loads(path.read_bytes())
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


class _ResultsCache:
    """Cache LRU en mémoire des résultats, invalidé par mtime du fichier"""

    def __init__(self, capacity: int = 4):
        self.capacity = capacity
        self._lock = threading.Lock()
        self._cache: "OrderedDict[str, tuple]" = OrderedDict()

    def get(self, key: str, mtime: float) -> Optional[Dict[str, Any]]:
        with self._lock:
            entry = self._cache.get(key)
            if entry is None or entry[0] != mtime:
                return None
            self._cache.move_to_end(key)
            return entry[1]

    def put(self, key: str, mtime: float, value: Dict[str, Any]):
        with self._lock:
            self._cache[key] = (mtime, value)
            self._cache.move_to_end(key)
            while len(self._cache) > self.capacity:
                self._cache.popitem(last=False)

    def invalidate(self, key_prefix: str):
        with self._lock:
            for key in [k for k in self._cache if k.startswith(key_prefix)]:
                del self._cache[key]


class StorageService:
    """Service de gestion du stockage des fichiers"""
    
    def __init__(self):
        self.upload_dir = settings.upload_dir
        self.results_dir = settings.results_dir
        self._results_cache = _ResultsCache(capacity=4)
        self._history_cache: Optional[tuple] = None  # (signature, history)
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Crée les répertoires si nécessaire"""
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_task_id(self) -> str:
        """Génère un ID unique pour une tâche"""
        return str(uuid.uuid4())
    
    def get_upload_path(self, task_id: str, filename: str) -> Path:
        """Retourne le chemin pour un fichier uploadé"""
        _validate_task_id(task_id)
        # Sanitize filename
        safe_filename = self._sanitize_filename(filename)
        task_dir = self.upload_dir / task_id
        task_dir.mkdir(parents=True, exist_ok=True)
        return task_dir / safe_filename
    
    def get_results_path(self, task_id: str) -> Path:
        """Retourne le répertoire des résultats pour une tâche"""
        _validate_task_id(task_id)
        results_path = self.results_dir / task_id
        results_path.mkdir(parents=True, exist_ok=True)
        return results_path
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize le nom de fichier pour éviter les attaques"""
        # Garder uniquement le nom de base
        filename = os.path.basename(filename)
        # Supprimer les caractères dangereux
        dangerous_chars = ['..', '/', '\\', '\x00', '\n', '\r']
        for char in dangerous_chars:
            filename = filename.replace(char, '')
        return filename or 'unnamed.pcap'
    
    def validate_pcap_file(self, file_path: Path) -> bool:
        """Valide qu'un fichier est un PCAP valide"""
        try:
            # Vérifier la taille
            file_size = file_path.stat().st_size
            if file_size > settings.max_file_size:
                logger.warning("file_too_large", 
                             size=file_size, 
                             max_size=settings.max_file_size)
                return False
            
            if file_size == 0:
                logger.warning("empty_file")
                return False
            
            # Vérifier le magic number PCAP
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                
                # PCAP magic numbers
                pcap_magics = [
                    b'\xd4\xc3\xb2\xa1',  # PCAP little-endian
                    b'\xa1\xb2\xc3\xd4',  # PCAP big-endian
                    b'\x0a\x0d\x0d\x0a',  # PCAPNG
                    b'\x4d\x3c\xb2\xa1',  # PCAP nanosecond
                    b'\xa1\xb2\x3c\x4d',  # PCAP nanosecond big-endian
                ]
                
                if magic not in pcap_magics:
                    logger.warning("invalid_pcap_magic", magic=magic.hex())
                    return False
            
            logger.info("pcap_validation_success", file_path=str(file_path))
            return True
            
        except Exception as e:
            logger.error("pcap_validation_error", error=str(e))
            return False
    
    def save_results(self, task_id: str, results: Dict[str, Any]):
        """Sauvegarde les résultats d'analyse"""
        results_path = self.get_results_path(task_id)
        
        # Ajouter les métadonnées sans écraser les champs existants (ex: pcap_path)
        metadata = results.get('metadata', {})
        metadata.update({
            'task_id': task_id,
            'analysis_timestamp': metadata.get('analysis_timestamp') or datetime.utcnow().isoformat(),
            'analyzer_version': '1.0.0'
        })
        results['metadata'] = metadata
        
        # Sauvegarder en JSON compact (orjson si disponible)
        json_path = results_path / 'results.json'
        _dump_json(results, json_path)

        # Résumé léger pour l'historique (évite de parser les gros results.json)
        try:
            protocol_summary = results.get('protocol_analysis', {}).get('summary', {})
            anomaly_block = results.get('anomaly_detection') or results.get('anomaly_analysis', {})
            anomaly_summary = anomaly_block.get('summary', {}) if isinstance(anomaly_block, dict) else {}
            _dump_json({
                'task_id': task_id,
                'filename': metadata.get('filename', 'Unknown'),
                'timestamp': metadata.get('analysis_timestamp', ''),
                'total_packets': protocol_summary.get('total_packets', 0),
                'total_bytes': protocol_summary.get('total_bytes', 0),
                'anomalies_count': anomaly_summary.get('total_anomalies', 0),
                'risk_level': anomaly_summary.get('risk_level', 'NONE')
            }, results_path / 'summary.json')
        except Exception as e:
            logger.warning("summary_save_error", task_id=task_id, error=str(e))

        # Mettre le cache à jour immédiatement et invalider l'historique
        try:
            self._results_cache.put(task_id, json_path.stat().st_mtime, results)
        except OSError:
            pass
        self._history_cache = None

        logger.info("results_saved", task_id=task_id, path=str(json_path))
        return json_path

    def load_results(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Charge les résultats d'une analyse (cache mémoire LRU + mtime)"""
        try:
            _validate_task_id(task_id)
        except ValueError:
            return None
        json_path = self.results_dir / task_id / 'results.json'

        try:
            mtime = json_path.stat().st_mtime
        except OSError:
            logger.warning("results_not_found", task_id=task_id)
            return None

        cached = self._results_cache.get(task_id, mtime)
        if cached is not None:
            return cached

        results = _load_json(json_path)
        self._results_cache.put(task_id, mtime, results)
        return results

    def load_derived(self, task_id: str, name: str) -> Optional[Dict[str, Any]]:
        """Charge un résultat d'analyse dérivée mis en cache (sidecar JSON)"""
        try:
            _validate_task_id(task_id)
        except ValueError:
            return None
        path = self.results_dir / task_id / f'derived_{name}.json'
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return None
        cache_key = f"{task_id}:{name}"
        cached = self._results_cache.get(cache_key, mtime)
        if cached is not None:
            return cached
        try:
            data = _load_json(path)
        except Exception as e:
            logger.warning("derived_load_error", task_id=task_id, name=name, error=str(e))
            return None
        self._results_cache.put(cache_key, mtime, data)
        return data

    def save_derived(self, task_id: str, name: str, data: Dict[str, Any]):
        """Persiste un résultat d'analyse dérivée (évite de re-parser le PCAP)"""
        results_path = self.get_results_path(task_id)
        path = results_path / f'derived_{name}.json'
        try:
            _dump_json(data, path)
            self._results_cache.put(f"{task_id}:{name}", path.stat().st_mtime, data)
        except Exception as e:
            logger.warning("derived_save_error", task_id=task_id, name=name, error=str(e))
    
    def get_results(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Alias pour load_results() - compatibilité avec les routes
        Récupère les résultats d'analyse pour un task_id donné
        
        ⚠️ MÉTHODE AJOUTÉE POUR CORRIGER L'ERREUR
        """
        return self.load_results(task_id)
    
    def get_pcap_path(self, task_id: str) -> Optional[str]:
        """
        Récupère le chemin du fichier PCAP pour un task_id
        """
        try:
            _validate_task_id(task_id)
        except ValueError:
            return None
        task_dir = self.upload_dir / task_id

        if not task_dir.exists():
            logger.warning(f"⚠️ Répertoire non trouvé: {task_dir}")
            return None
        
        # Chercher le fichier PCAP
        for ext in ['.pcap', '.pcapng', '.cap']:
            pcap_files = list(task_dir.glob(f'*{ext}'))
            if pcap_files:
                logger.info(f"✅ Fichier PCAP trouvé: {pcap_files[0]}")
                return str(pcap_files[0])
        
        logger.warning(f"⚠️ Aucun fichier PCAP trouvé dans {task_dir}")
        return None
    
    def get_analysis_history(self, limit: int = 50) -> List[Dict]:
        """Récupère l'historique des analyses (cache invalidé par mtime des résultats)"""
        history = []

        if not self.results_dir.exists():
            return history

        # Signature du répertoire: liste (task_id, mtime) des results.json
        entries = []
        for task_dir in self.results_dir.iterdir():
            if task_dir.is_dir():
                json_path = task_dir / 'results.json'
                try:
                    entries.append((task_dir, json_path.stat().st_mtime))
                except OSError:
                    continue

        signature = tuple(sorted((d.name, m) for d, m in entries))
        if self._history_cache and self._history_cache[0] == signature:
            return self._history_cache[1][:limit]

        for task_dir, _mtime in entries:
            # Résumé léger si disponible (écrit à la sauvegarde)
            summary_path = task_dir / 'summary.json'
            if summary_path.exists():
                try:
                    entry = _load_json(summary_path)
                    entry['task_id'] = task_dir.name
                    history.append(entry)
                    continue
                except Exception:
                    pass

            json_path = task_dir / 'results.json'
            try:
                # Lecture directe sans passer par le cache LRU (évite d'évincer
                # les résultats actifs en itérant tout l'historique)
                results = _load_json(json_path)
                metadata = results.get('metadata', {})
                protocol_summary = results.get('protocol_analysis', {}).get('summary', {})
                anomaly_block = results.get('anomaly_detection') or results.get('anomaly_analysis', {})
                anomaly_summary = anomaly_block.get('summary', {})

                history.append({
                    'task_id': task_dir.name,
                    'filename': metadata.get('filename', 'Unknown'),
                    'timestamp': metadata.get('analysis_timestamp', ''),
                    'total_packets': protocol_summary.get('total_packets', 0),
                    'total_bytes': protocol_summary.get('total_bytes', 0),
                    'anomalies_count': anomaly_summary.get('total_anomalies', 0),
                    'risk_level': anomaly_summary.get('risk_level', 'NONE')
                })
            except Exception as e:
                logger.error("history_load_error", task_id=task_dir.name, error=str(e))

        # Trier par date décroissante
        history.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        self._history_cache = (signature, history)
        return history[:limit]

    def delete_analysis(self, task_id: str) -> bool:
        """Supprime une analyse et ses fichiers associés"""
        try:
            _validate_task_id(task_id)
            # Invalider les caches (résultats + analyses dérivées + historique)
            self._results_cache.invalidate(task_id)
            self._history_cache = None

            # Supprimer le répertoire des résultats
            results_path = self.results_dir / task_id
            if results_path.exists():
                shutil.rmtree(results_path)
            
            # Supprimer le fichier uploadé
            upload_path = self.upload_dir / task_id
            if upload_path.exists():
                shutil.rmtree(upload_path)
            
            logger.info("analysis_deleted", task_id=task_id)
            return True
            
        except Exception as e:
            logger.error("delete_error", task_id=task_id, error=str(e))
            return False
    
    def get_file_path(self, task_id: str, filename: str) -> Optional[Path]:
        """Récupère le chemin d'un fichier dans les résultats"""
        try:
            _validate_task_id(task_id)
        except ValueError:
            return None
        file_path = self.results_dir / task_id / self._sanitize_filename(filename)
        return file_path if file_path.exists() else None


# Instance singleton
storage_service = StorageService()
