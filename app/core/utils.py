"""
Helpers numériques partagés.

Implémentation unique des coercitions int/float tolérantes, auparavant
dupliquées dans routes.py (_to_int), additional_routes.py (_as_int/_as_float)
et multi_pcap_service.py (_safe_int/_safe_float).

NB: les fonctions _percentile restent locales à leurs modules — leurs
sémantiques diffèrent volontairement (filtrage/clamp différents).
"""

from typing import Any


def as_int(value: Any, default: int = 0) -> int:
    """Convertit en int, retourne `default` si impossible"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_float(value: Any, default: float = 0.0) -> float:
    """Convertit en float, retourne `default` si impossible"""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
