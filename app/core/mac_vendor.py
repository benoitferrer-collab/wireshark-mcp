"""
Utilitaires de résolution constructeur MAC (OUI) et classification L2.
"""

from __future__ import annotations

import re
import os
import json
from functools import lru_cache
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from scapy.config import conf


_MAC_RE = re.compile(r"^[0-9A-F]{12}$")

# Surcouches utiles pour l'analyse réseau (virtualisation / conteneurs)
_OUI_HINTS = {
    "000569": "VMware",
    "000C29": "VMware",
    "001C14": "VMware",
    "005056": "VMware",
    "00155D": "Microsoft Hyper-V",
    "00163E": "Xen",
    "0242AC": "Docker / Bridge local",
    "080027": "Oracle VirtualBox",
    "525400": "QEMU / KVM",
}

_DEFAULT_MACLOOKUP_BASE_URL = "https://api.maclookup.app/v2/macs"
_DEFAULT_MACLOOKUP_TEST_MAC = "00:50:56:AA:BB:CC"
_MACLOOKUP_RUNTIME_CONFIG_ENV = "MACLOOKUP_RUNTIME_CONFIG_PATH"
_MACLOOKUP_RUNTIME_CONFIG_DEFAULT = "/tmp/pcap_analyzer_maclookup_runtime.json"

_RUNTIME_CONFIG: Dict[str, Any] = {}
_RUNTIME_CONFIG_MTIME: float = 0.0


def normalize_mac_address(mac: Optional[str]) -> str:
    """Normalise une MAC en format canonique AA:BB:CC:DD:EE:FF."""
    if not mac:
        return ""

    raw = re.sub(r"[^0-9A-Fa-f]", "", str(mac)).upper()
    if len(raw) != 12 or not _MAC_RE.match(raw):
        return ""
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2))


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() not in {"0", "false", "no", "off"}


def _parse_timeout(value: Any, default: float = 2.0) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        timeout = default
    return max(0.5, min(timeout, 10.0))


def _normalize_base_url(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        raw = _DEFAULT_MACLOOKUP_BASE_URL
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = f"https://{raw}"
    return raw.rstrip("/")


def _runtime_config_path() -> Path:
    return Path(os.getenv(_MACLOOKUP_RUNTIME_CONFIG_ENV, _MACLOOKUP_RUNTIME_CONFIG_DEFAULT))


def _default_runtime_config() -> Dict[str, Any]:
    return {
        # Désactivé par défaut: un appel HTTP (2s max) par OUI inconnu dans le
        # chemin chaud de l'analyse peut ajouter des minutes sur une grosse capture.
        # Activable via MACLOOKUP_FALLBACK_ENABLED=1 ou le panneau de configuration.
        "enabled": _env_flag("MACLOOKUP_FALLBACK_ENABLED", False),
        "base_url": _normalize_base_url(os.getenv("MACLOOKUP_API_BASE_URL", _DEFAULT_MACLOOKUP_BASE_URL)),
        "api_key": str(os.getenv("MACLOOKUP_API_KEY", "")).strip(),
        "timeout": _parse_timeout(os.getenv("MACLOOKUP_TIMEOUT_SECONDS", "2.0"), default=2.0),
        "last_available": False,
        "last_error": "",
        "last_vendor": "",
        "last_checked_mac": "",
    }


def _coerce_runtime_config(payload: Dict[str, Any], base: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg = dict(base or _default_runtime_config())
    if not isinstance(payload, dict):
        return cfg

    if "enabled" in payload:
        cfg["enabled"] = bool(payload.get("enabled"))
    if "base_url" in payload:
        cfg["base_url"] = _normalize_base_url(str(payload.get("base_url") or cfg["base_url"]))
    if "api_key" in payload:
        cfg["api_key"] = str(payload.get("api_key") or "").strip()
    if "timeout" in payload:
        cfg["timeout"] = _parse_timeout(payload.get("timeout"), default=cfg["timeout"])

    # Champs de statut persistés
    cfg["last_available"] = bool(payload.get("last_available", cfg.get("last_available", False)))
    cfg["last_error"] = str(payload.get("last_error", cfg.get("last_error", "")) or "")
    cfg["last_vendor"] = str(payload.get("last_vendor", cfg.get("last_vendor", "")) or "")
    cfg["last_checked_mac"] = str(payload.get("last_checked_mac", cfg.get("last_checked_mac", "")) or "")
    return cfg


def _load_runtime_config(force: bool = False) -> Dict[str, Any]:
    global _RUNTIME_CONFIG
    global _RUNTIME_CONFIG_MTIME

    path = _runtime_config_path()
    defaults = _default_runtime_config()

    if not path.exists():
        _RUNTIME_CONFIG = defaults
        _RUNTIME_CONFIG_MTIME = 0.0
        return dict(_RUNTIME_CONFIG)

    try:
        mtime = path.stat().st_mtime
    except OSError:
        _RUNTIME_CONFIG = defaults
        _RUNTIME_CONFIG_MTIME = 0.0
        return dict(_RUNTIME_CONFIG)

    if _RUNTIME_CONFIG and not force and mtime <= _RUNTIME_CONFIG_MTIME:
        return dict(_RUNTIME_CONFIG)

    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        _RUNTIME_CONFIG = _coerce_runtime_config(payload, defaults)
        _RUNTIME_CONFIG_MTIME = mtime
    except Exception:
        _RUNTIME_CONFIG = defaults
        _RUNTIME_CONFIG_MTIME = 0.0

    return dict(_RUNTIME_CONFIG)


def _persist_runtime_config(config: Dict[str, Any]) -> Dict[str, Any]:
    global _RUNTIME_CONFIG
    global _RUNTIME_CONFIG_MTIME

    cfg = _coerce_runtime_config(config, _default_runtime_config())
    path = _runtime_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    tmp_path.replace(path)

    _RUNTIME_CONFIG = cfg
    try:
        _RUNTIME_CONFIG_MTIME = path.stat().st_mtime
    except OSError:
        _RUNTIME_CONFIG_MTIME = 0.0
    return dict(cfg)


def _mask_api_key(value: str) -> str:
    token = str(value or "")
    if not token:
        return ""
    if len(token) <= 8:
        return "*" * len(token)
    return f"{token[:4]}...{token[-4:]}"


def clear_maclookup_caches():
    _resolve_vendor_online_from_oui.cache_clear()
    resolve_mac_vendor.cache_clear()


def get_maclookup_runtime_config() -> Dict[str, Any]:
    """Lit la configuration runtime MacLookup (persistée et partagée)."""
    return _load_runtime_config()


def _first_octet(mac: str) -> Optional[int]:
    normalized = normalize_mac_address(mac)
    if not normalized:
        return None
    try:
        return int(normalized[0:2], 16)
    except ValueError:
        return None


def is_broadcast_mac(mac: str) -> bool:
    return normalize_mac_address(mac) == "FF:FF:FF:FF:FF:FF"


def is_multicast_mac(mac: str) -> bool:
    if is_broadcast_mac(mac):
        return True
    first_octet = _first_octet(mac)
    return bool(first_octet is not None and (first_octet & 0x01))


def is_locally_administered_mac(mac: str) -> bool:
    first_octet = _first_octet(mac)
    return bool(first_octet is not None and (first_octet & 0x02))


def classify_mac_address(mac: str) -> str:
    """Retourne: broadcast, multicast, local-admin ou unicast."""
    normalized = normalize_mac_address(mac)
    if not normalized:
        return "unknown"
    if is_broadcast_mac(normalized):
        return "broadcast"
    if is_multicast_mac(normalized):
        return "multicast"
    if is_locally_administered_mac(normalized):
        return "local-admin"
    return "unicast"


def test_maclookup_connection(
    mac: str = _DEFAULT_MACLOOKUP_TEST_MAC,
    *,
    enabled: Optional[bool] = None,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Teste la connexion API MacLookup pour une MAC donnée.
    N'altère pas la configuration persistée.
    """
    cfg = _load_runtime_config()

    enabled_val = cfg["enabled"] if enabled is None else bool(enabled)
    base_url_val = cfg["base_url"] if base_url is None else _normalize_base_url(base_url)
    api_key_val = cfg["api_key"] if api_key is None else str(api_key).strip()
    timeout_val = cfg["timeout"] if timeout is None else _parse_timeout(timeout, default=cfg["timeout"])

    normalized = normalize_mac_address(mac)
    if not normalized:
        return {
            "available": False,
            "success": False,
            "error": f"MAC invalide: {mac}",
            "mac": mac,
            "vendor": "",
            "endpoint": base_url_val,
        }

    if not enabled_val:
        return {
            "available": False,
            "success": False,
            "error": "Fallback MacLookup désactivé",
            "mac": normalized,
            "vendor": "",
            "endpoint": base_url_val,
        }

    endpoint = f"{base_url_val}/{normalized}"
    params = {"format": "json"}
    if api_key_val:
        params["apiKey"] = api_key_val
    url = f"{endpoint}?{urlencode(params)}"

    try:
        req = Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "PCAP-Analyzer/1.0"},
        )
        with urlopen(req, timeout=timeout_val) as response:
            status_code = getattr(response, "status", None) or response.getcode()
            if status_code != 200:
                return {
                    "available": False,
                    "success": False,
                    "error": f"HTTP {status_code}",
                    "mac": normalized,
                    "vendor": "",
                    "endpoint": base_url_val,
                }
            payload = response.read()

        if not payload:
            return {
                "available": False,
                "success": False,
                "error": "Réponse vide",
                "mac": normalized,
                "vendor": "",
                "endpoint": base_url_val,
            }

        data = json.loads(payload.decode("utf-8", errors="ignore"))
        if not isinstance(data, dict):
            return {
                "available": False,
                "success": False,
                "error": "Réponse JSON invalide",
                "mac": normalized,
                "vendor": "",
                "endpoint": base_url_val,
            }

        vendor = str(
            data.get("company")
            or data.get("vendor")
            or data.get("organization")
            or ""
        ).strip()
        found = bool(data.get("found")) or bool(vendor)
        success = bool(data.get("success")) if "success" in data else found

        if success and found and vendor:
            return {
                "available": True,
                "success": True,
                "error": "",
                "mac": normalized,
                "vendor": vendor,
                "endpoint": base_url_val,
            }

        return {
            "available": False,
            "success": False,
            "error": "MAC non trouvée dans MacLookup",
            "mac": normalized,
            "vendor": "",
            "endpoint": base_url_val,
        }
    except Exception as e:
        return {
            "available": False,
            "success": False,
            "error": str(e),
            "mac": normalized,
            "vendor": "",
            "endpoint": base_url_val,
        }


def get_maclookup_status(probe: bool = False, test_mac: str = _DEFAULT_MACLOOKUP_TEST_MAC) -> Dict[str, Any]:
    cfg = _load_runtime_config()
    status = {
        "enabled": bool(cfg["enabled"]),
        "endpoint": str(cfg["base_url"]),
        "timeout": float(cfg["timeout"]),
        "has_api_key": bool(cfg["api_key"]),
        "api_key_masked": _mask_api_key(cfg["api_key"]),
        "available": bool(cfg.get("last_available", False)),
        "error": str(cfg.get("last_error", "")),
        "test_mac": str(cfg.get("last_checked_mac") or normalize_mac_address(test_mac) or test_mac),
        "sample_vendor": str(cfg.get("last_vendor", "")),
    }

    if probe:
        probe_result = test_maclookup_connection(test_mac)
        cfg["last_available"] = bool(probe_result.get("available", False))
        cfg["last_error"] = str(probe_result.get("error") or "")
        cfg["last_checked_mac"] = str(probe_result.get("mac") or "")
        cfg["last_vendor"] = str(probe_result.get("vendor") or "")
        _persist_runtime_config(cfg)

        status["available"] = cfg["last_available"]
        status["error"] = cfg["last_error"]
        status["test_mac"] = cfg["last_checked_mac"] or status["test_mac"]
        status["sample_vendor"] = cfg["last_vendor"]

    return status


def update_maclookup_runtime_config(
    *,
    enabled: Optional[bool] = None,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout: Optional[float] = None,
    test_mac: str = _DEFAULT_MACLOOKUP_TEST_MAC,
) -> Dict[str, Any]:
    cfg = _load_runtime_config()

    if enabled is not None:
        cfg["enabled"] = bool(enabled)
    if base_url is not None and str(base_url).strip():
        cfg["base_url"] = _normalize_base_url(str(base_url))
    if api_key is not None:
        cfg["api_key"] = str(api_key).strip()
    if timeout is not None:
        cfg["timeout"] = _parse_timeout(timeout, default=cfg.get("timeout", 2.0))

    _persist_runtime_config(cfg)
    clear_maclookup_caches()

    return get_maclookup_status(probe=True, test_mac=test_mac)


@lru_cache(maxsize=4096)
def _resolve_vendor_online_from_oui(oui: str) -> str:
    """
    Fallback online vers maclookup.app pour un OUI (6 hex chars).
    Retourne une chaîne vide si non trouvé / indisponible.
    """
    cfg = _load_runtime_config()
    if not bool(cfg.get("enabled", True)):
        return ""
    if not oui or len(oui) != 6:
        return ""

    query = ":".join(oui[i:i + 2] for i in range(0, 6, 2))
    endpoint = f"{str(cfg.get('base_url') or _DEFAULT_MACLOOKUP_BASE_URL).rstrip('/')}/{query}"
    params = {"format": "json"}
    api_key = str(cfg.get("api_key") or "").strip()
    if api_key:
        params["apiKey"] = api_key

    query_string = urlencode(params)
    url = f"{endpoint}?{query_string}" if query_string else endpoint

    try:
        req = Request(url, headers={"Accept": "application/json", "User-Agent": "PCAP-Analyzer/1.0"})
        with urlopen(req, timeout=_parse_timeout(cfg.get("timeout"), default=2.0)) as response:
            status_code = getattr(response, "status", None) or response.getcode()
            if status_code != 200:
                return ""
            payload = response.read()
        if not payload:
            return ""
        data = json.loads(payload.decode("utf-8", errors="ignore"))
    except Exception:
        return ""

    if not isinstance(data, dict):
        return ""
    success = bool(data.get("success")) if "success" in data else True
    found = bool(data.get("found")) if "found" in data else True
    if not success or not found:
        return ""

    company = str(
        data.get("company")
        or data.get("vendor")
        or data.get("organization")
        or ""
    ).strip()
    if not company or company in {"*NO COMPANY*", "*PRIVATE*"}:
        return ""
    return company


@lru_cache(maxsize=8192)
def resolve_mac_vendor(mac: str) -> str:
    """
    Résout le constructeur depuis l'OUI.
    Utilise d'abord des hints utiles SOC/NOC, puis la base Scapy/Wireshark.
    """
    normalized = normalize_mac_address(mac)
    if not normalized:
        return "Constructeur inconnu"
    if is_broadcast_mac(normalized):
        return "Broadcast"

    oui = normalized.replace(":", "")[:6]
    if oui in _OUI_HINTS:
        return _OUI_HINTS[oui]

    try:
        short_name, long_name = conf.manufdb.lookup(normalized)
        candidate = str(long_name or short_name or "").strip()
        if candidate and candidate != normalized:
            return candidate
    except Exception:
        pass

    online_vendor = _resolve_vendor_online_from_oui(oui)
    if online_vendor:
        return online_vendor

    if is_locally_administered_mac(normalized):
        return "Adresse locale (LAA) / virtuelle"
    return "Constructeur inconnu"
