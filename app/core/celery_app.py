"""
Configuration Celery pour le traitement asynchrone des PCAP
Utilise Redis comme broker et backend de résultats
"""

from celery import Celery
from .config import settings

# Création de l'application Celery
celery_app = Celery(
    'pcap_analyzer',
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=['app.services.pcap_service']  # Module contenant les tâches
)

# Configuration Celery
celery_app.conf.update(
    # Sérialisation
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    
    # Timezone
    timezone='UTC',
    enable_utc=True,
    
    # Performance
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    
    # Résultats
    result_expires=86400,  # 24 heures
    task_track_started=True,
    
    # Timeouts
    task_soft_time_limit=settings.analysis_timeout,
    task_time_limit=settings.analysis_timeout + 60,
    
    # Retry
    task_default_retry_delay=60,
    task_max_retries=3,
    
    # Queue
    task_default_queue='pcap_analysis',
    task_queues={
        'pcap_analysis': {
            'exchange': 'pcap_analysis',
            'routing_key': 'pcap_analysis',
        }
    },
)
