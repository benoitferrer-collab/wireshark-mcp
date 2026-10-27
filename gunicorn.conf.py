# Gunicorn Configuration for PCAP Analyzer Pro
# Production-ready settings with Uvicorn workers

import os
import multiprocessing

# Server socket
bind = f"{os.getenv('HOST', '0.0.0.0')}:{os.getenv('PORT', '8000')}"
backlog = 2048

# Worker processes
workers = int(os.getenv('WORKERS', 2))
worker_class = 'uvicorn.workers.UvicornWorker'
worker_connections = 1000
timeout = 400
keepalive = 5

# Recyclage périodique des workers: borne la croissance mémoire
# (caches in-process, fragmentation scapy) sans interrompre les requêtes en cours
max_requests = 500
max_requests_jitter = 100

# Charge l'app une fois dans le master avant le fork (scapy + tags.json ~283KB
# chargés 1x au lieu de N fois, pages partagées entre workers via copy-on-write)
preload_app = True

# Process naming
proc_name = 'pcap_analyzer'

# Logging
accesslog = '-'
errorlog = '-'
loglevel = os.getenv('LOG_LEVEL', 'info').lower()
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Server mechanics
daemon = False
pidfile = None
user = None
group = None
tmp_upload_dir = None

# SSL (optional)
# keyfile = '/path/to/key.pem'
# certfile = '/path/to/cert.pem'

# Hooks
def on_starting(server):
    """Called just before the master process is initialized."""
    pass

def on_reload(server):
    """Called to recycle workers during a reload via SIGHUP."""
    pass

def worker_int(worker):
    """Called when a worker receives SIGINT or SIGQUIT."""
    pass

def worker_abort(worker):
    """Called when a worker receives SIGABRT."""
    pass
