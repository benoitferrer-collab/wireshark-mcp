# PCAP Analyzer Pro - Dockerfile Multi-Stage Optimisé
# Build optimisé pour production avec sécurité et performance

#########################################
# Stage 1: Builder - Compilation des dépendances
#########################################
FROM python:3.11-slim AS builder

WORKDIR /build

# Installation des dépendances système pour la compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copier et installer les dépendances Python
COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /build/wheels -r requirements.txt

#########################################
# Stage 2: Runtime - Image finale légère
#########################################
FROM python:3.11-slim AS runtime

# Labels pour documentation
LABEL maintainer="PCAP Analyzer Team"
LABEL version="1.0.0"
LABEL description="Application professionnelle d'analyse PCAP pour SOC"

# Variables d'environnement
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    APP_HOME=/app

WORKDIR $APP_HOME

# Installation des dépendances système runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    libmagic1 \
    tini \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Création d'un utilisateur non-root pour la sécurité
RUN groupadd --gid 1000 appgroup \
    && useradd --uid 1000 --gid appgroup --shell /bin/bash --create-home appuser

# Copier les wheels depuis le builder et installer
COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache /wheels/* && rm -rf /wheels

# Copier le code de l'application
COPY --chown=appuser:appgroup . .

# Créer les répertoires nécessaires
RUN mkdir -p uploads results logs \
    && chown -R appuser:appgroup uploads results logs

# Changer vers l'utilisateur non-root
USER appuser

# Port exposé
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

# Point d'entrée avec tini pour gestion propre des signaux
ENTRYPOINT ["/usr/bin/tini", "--"]

# Commande par défaut: Gunicorn avec workers Uvicorn
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app.main:app"]
