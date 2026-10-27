"""
Configuration des logs structurés avec structlog
Format JSON pour intégration avec ELK/Splunk/etc.
"""

import logging
import sys
import structlog
from .config import settings


def setup_logging():
    """Configure le système de logging structuré"""
    
    # Configuration du niveau de log
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)
    
    # Processeurs structlog
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]
    
    # Configuration pour le mode debug vs production
    if settings.debug:
        # Mode développement : logs lisibles
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(colors=True)
        ]
    else:
        # Mode production : logs JSON
        processors = shared_processors + [
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer()
        ]
    
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Configuration du logging standard Python
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )
    
    # Supprimer les logs verbose des bibliothèques tierces
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("celery").setLevel(logging.INFO)


def get_logger(name: str = None):
    """Retourne un logger structuré"""
    return structlog.get_logger(name)
