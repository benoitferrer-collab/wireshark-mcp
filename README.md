# PCAP Analyzer Pro

## Déploiement Vercel et connexion Claude / ChatGPT

L'interface peut être publiée sur Vercel et les analyses interrogées depuis
Claude ou ChatGPT via le service MCP authentifié. Le moteur d'analyse reste
hébergé dans Docker avec stockage persistant. Voir le [guide de déploiement](docs/MCP_DEPLOYMENT.md).

> Application web professionnelle d'analyse PCAP pour SOC et ingénierie réseau

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 📋 Table des matières

- [Fonctionnalités](#-fonctionnalités)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [API Reference](#-api-reference)
- [Configuration](#-configuration)
- [Développement](#-développement)

## 🎯 Fonctionnalités

### Analyse Protocolaire
- **Ethernet** : Analyse des trames de couche 2
- **IPv4/IPv6** : Statistiques réseau, fragmentation
- **TCP** : Sessions complètes, handshake, flags, retransmissions
- **UDP** : Flux et statistiques
- **ICMP** : Types de messages et anomalies
- **DNS** : Requêtes, réponses, domaines suspects
- **HTTP/HTTPS** : Requêtes, méthodes, User-Agents, TLS

### 🏢 Protocoles Entreprise (NOUVEAU)
- **SMB/CIFS** : Partages, opérations fichiers, authentification, détection Pass-the-Hash
- **LDAP** : Requêtes Active Directory, énumération, injection LDAP
- **Kerberos** : Authentication, TGT/TGS, détection Kerberoasting, Golden/Silver Ticket
- **RDP** : Sessions Remote Desktop, tentatives brute force, BlueKeep
- **SSH** : Connexions SSH, versions, tunneling, authentification

### Analyse TCP Approfondie
- ✅ Sessions TCP complètes (3-way handshake)
- ✅ Détection des retransmissions
- ✅ Analyse RST (qui reset, quand, pourquoi)
- ✅ Estimation RTT (Round-Trip Time)
- ✅ Tracking Window Size
- ✅ Détection connexions half-open

### 🕐 Timeline Interactive (NOUVEAU)
- Visualisation chronologique des événements réseau
- Filtrage par type d'événement, protocole, IP
- Mode playback pour rejouer le trafic
- Export des événements sélectionnés

### 🗺️ Network Graph (NOUVEAU)
- Graphe interactif des communications
- Détection automatique des rôles (serveur, client, attaquant, victime)
- Clustering par subnet
- Visualisation des chemins d'attaque

### 📡 Stream Reconstruction (NOUVEAU)
- Reconstruction complète des streams TCP
- Parsing HTTP avec paires requête/réponse
- Affichage hexdump et ASCII
- Export en TXT, HTML, RAW

### 🌍 IP Enrichment (NOUVEAU)
- GeoIP : Pays, ville, coordonnées
- ASN : Numéro, nom, organisation, ISP
- WHOIS : Informations de domaine
- Cache intelligent avec rate limiting

### Détection d'Anomalies
- 🔴 **SYN Flood** : Détection attaques DoS
- 🟠 **Port Scanning** : Identification reconnaissance
- 🟡 **Connexions orphelines** : Sessions incomplètes
- 🟡 **Retransmissions excessives** : Problèmes réseau
- 🟠 **RST anormaux** : Comportements suspects
- 🟡 **Burst de paquets** : Pics de trafic
- 🔴 **Pass-the-Hash** : Attaques SMB
- 🔴 **Kerberoasting** : Extraction de tickets
- 🔴 **Brute Force RDP/SSH** : Tentatives d'authentification

### Exports & Rapports
- 📄 **JSON** : Données structurées complètes
- 📊 **CSV** : Export tabulaire
- 📑 **PDF** : Rapport professionnel avec graphiques

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      PCAP ANALYZER PRO                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐     ┌─────────────────────────────────────┐   │
│  │   Browser   │────▶│        Frontend (HTML/CSS/JS)       │   │
│  │   Client    │◀────│        - Upload Drag & Drop         │   │
│  └─────────────┘     │        - Visualisations Chart.js    │   │
│                      │        - Historique & Downloads     │   │
│                      └─────────────────────────────────────┘   │
│                                     │                           │
│                                     ▼                           │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │               FastAPI Backend (Gunicorn)                │   │
│  │  ┌─────────────┬─────────────┬─────────────────────┐   │   │
│  │  │  /upload    │  /analysis  │  /export/{format}   │   │   │
│  │  │  /history   │  /status    │  /download          │   │   │
│  │  └─────────────┴─────────────┴─────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                        │                                        │
│          ┌─────────────┼─────────────┐                         │
│          ▼             ▼             ▼                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐               │
│  │   Redis     │ │   Celery    │ │  Filesystem │               │
│  │  (Broker)   │ │  (Workers)  │ │  (Storage)  │               │
│  └─────────────┘ └─────────────┘ └─────────────┘               │
│                        │                                        │
│                        ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Analyzers (Scapy-based)                     │   │
│  │  ┌──────────┬──────────┬──────────┬──────────────────┐  │   │
│  │  │ Protocol │   TCP    │ Anomaly  │     Report       │  │   │
│  │  │ Analyzer │ Analyzer │ Detector │    Generator     │  │   │
│  │  └──────────┴──────────┴──────────┴──────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 📁 Structure du Projet

```
pcap_analyzer/
├── app/                          # Code applicatif principal
│   ├── __init__.py
│   ├── main.py                   # Point d'entrée FastAPI
│   ├── api/                      # Routes API REST
│   │   ├── __init__.py
│   │   └── routes.py             # Endpoints upload, analysis, export
│   ├── core/                     # Configuration & utilitaires
│   │   ├── __init__.py
│   │   ├── config.py             # Variables d'environnement
│   │   ├── logging_config.py     # Configuration logs structurés
│   │   └── celery_app.py         # Configuration Celery
│   ├── analyzers/                # Modules d'analyse PCAP
│   │   ├── __init__.py
│   │   ├── base.py               # Classe de base analyseur
│   │   ├── protocol_analyzer.py  # Analyse Ethernet/IP/TCP/UDP/ICMP
│   │   ├── tcp_analyzer.py       # Analyse TCP approfondie
│   │   └── anomaly_detector.py   # Détection d'anomalies & scoring
│   ├── services/                 # Services métier
│   │   ├── __init__.py
│   │   ├── pcap_service.py       # Orchestration analyse PCAP
│   │   └── storage_service.py    # Gestion fichiers & résultats
│   └── reports/                  # Génération de rapports
│       ├── __init__.py
│       ├── json_report.py        # Export JSON
│       ├── csv_report.py         # Export CSV
│       └── pdf_report.py         # Export PDF avec graphiques
├── static/                       # Assets frontend
│   ├── css/
│   │   └── style.css             # Styles modernes
│   └── js/
│       └── app.js                # Logique frontend & Chart.js
├── templates/
│   └── index.html                # Interface utilisateur
├── uploads/                      # Fichiers PCAP uploadés
├── results/                      # Résultats d'analyse (JSON/CSV/PDF)
├── tests/                        # Tests unitaires & intégration
│   ├── __init__.py
│   ├── test_sample.pcap          # PCAP de test
│   └── test_analyzers.py         # Tests des analyseurs
├── docs/                         # Documentation additionnelle
├── Dockerfile                    # Image Docker multi-stage
├── docker-compose.yml            # Orchestration services
├── gunicorn.conf.py              # Configuration Gunicorn
├── requirements.txt              # Dépendances Python
├── .env.example                  # Template variables d'environnement
└── README.md                     # Documentation principale
```

## 🚀 Installation

### Avec Docker (Recommandé)

```bash
# Cloner le repository
git clone <repository-url>
cd pcap_analyzer

# Copier et configurer les variables d'environnement
cp .env.example .env

# Lancer avec Docker Compose
docker-compose up -d --build

# Accéder à l'application
open http://localhost:8000
```

### Installation Manuelle

```bash
# Prérequis: Python 3.11+, Redis

# Créer l'environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/Mac
# .\venv\Scripts\activate  # Windows

# Installer les dépendances
pip install -r requirements.txt

# Démarrer Redis (dans un terminal séparé)
redis-server

# Démarrer Celery worker (dans un terminal séparé)
celery -A app.core.celery_app worker --loglevel=info

# Démarrer l'application
gunicorn -c gunicorn.conf.py app.main:app
```

## 💻 Utilisation

### Interface Web

1. Ouvrir http://localhost:8000
2. Glisser-déposer un fichier PCAP ou cliquer pour sélectionner
3. L'analyse démarre automatiquement (barre de progression)
4. Consulter les résultats et visualisations
5. Télécharger les rapports (JSON/CSV/PDF)

### API REST

```bash
# Upload d'un fichier PCAP
curl -X POST "http://localhost:8000/api/upload" \
  -F "file=@capture.pcap"

# Vérifier le statut de l'analyse
curl "http://localhost:8000/api/status/{task_id}"

# Récupérer les résultats
curl "http://localhost:8000/api/analysis/{task_id}"

# Exporter en PDF
curl -O "http://localhost:8000/api/export/{task_id}/pdf"

# Historique des analyses
curl "http://localhost:8000/api/history"
```

## 📚 API Reference

### Endpoints de Base
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/upload` | POST | Upload fichier PCAP |
| `/api/status/{task_id}` | GET | Statut de l'analyse |
| `/api/analysis/{task_id}` | GET | Résultats complets |
| `/api/export/{task_id}/{format}` | GET | Export (json/csv/pdf) |
| `/api/history` | GET | Historique des analyses |
| `/api/delete/{task_id}` | DELETE | Supprimer une analyse |

### Endpoints de Drill-Down
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/analysis/{task_id}/ip/{ip}` | GET | Détails d'une IP |
| `/api/analysis/{task_id}/session/{session_id}` | GET | Détails session TCP |
| `/api/analysis/{task_id}/packet/{packet_num}` | GET | Détails d'un paquet |
| `/api/analysis/{task_id}/packets` | GET | Liste paginée des paquets |
| `/api/analysis/{task_id}/dns` | GET | Analyse DNS détaillée |
| `/api/analysis/{task_id}/http` | GET | Analyse HTTP détaillée |

### Endpoints Protocoles Entreprise
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/analysis/{task_id}/smb` | GET | Analyse SMB/CIFS |
| `/api/analysis/{task_id}/ldap` | GET | Analyse LDAP |
| `/api/analysis/{task_id}/kerberos` | GET | Analyse Kerberos |
| `/api/analysis/{task_id}/rdp` | GET | Analyse RDP |
| `/api/analysis/{task_id}/ssh` | GET | Analyse SSH |

### Endpoints Visualisation
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/analysis/{task_id}/timeline` | GET | Timeline interactive |
| `/api/analysis/{task_id}/network-graph` | GET | Graphe de réseau |
| `/api/analysis/{task_id}/streams` | GET | Liste des streams TCP |
| `/api/analysis/{task_id}/stream/tcp/{stream_id}` | GET | Reconstruction stream TCP |
| `/api/analysis/{task_id}/stream/http/{session_id}` | GET | Reconstruction session HTTP |
| `/api/analysis/{task_id}/stream/export/{stream_id}` | GET | Export stream |

### Endpoints Enrichissement
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/analysis/{task_id}/enrichment` | GET | Données d'enrichissement |
| `/api/analysis/{task_id}/enrichment/ip/{ip}` | GET | Enrichissement IP spécifique |
| `/api/analysis/{task_id}/anomalies` | GET | Toutes les anomalies agrégées |

## ⚙️ Configuration

### Variables d'Environnement

| Variable | Description | Défaut |
|----------|-------------|--------|
| `MAX_FILE_SIZE` | Taille max PCAP | 3221225472 (3GB) |
| `ANALYSIS_TIMEOUT` | Timeout analyse (sec) | 3600 |
| `REDIS_URL` | URL Redis | redis://localhost:6379/0 |
| `CELERY_BROKER_URL` | Broker Celery | redis://localhost:6379/0 |
| `LOG_LEVEL` | Niveau de log | INFO |
| `WORKERS` | Nombre workers Gunicorn | 5 |

## 🔒 Sécurité

- ✅ Validation stricte des fichiers PCAP (magic bytes)
- ✅ Limitation taille fichier (3GB max)
- ✅ Timeout configurable sur les analyses
- ✅ Isolation des fichiers uploadés
- ✅ Logs structurés pour audit
- ✅ Sanitization des noms de fichiers

## 🧪 Tests

```bash
# Lancer les tests
pytest tests/ -v

# Avec couverture
pytest tests/ --cov=app --cov-report=html
```

## 🔧 Choix Techniques

### Pourquoi FastAPI ?
- Performances excellentes (asynchrone natif)
- Documentation OpenAPI automatique
- Validation Pydantic intégrée
- Typage Python moderne

### Pourquoi Scapy ?
- Bibliothèque de référence pour l'analyse réseau
- Support complet des protocoles
- Flexibilité pour analyses personnalisées
- Communauté active et documentation riche

### Pourquoi Celery + Redis ?
- Traitement asynchrone robuste
- Scalabilité horizontale
- Suivi des tâches en temps réel
- Retry automatique en cas d'erreur

### Pourquoi ReportLab pour PDF ?
- Génération programmatique de PDF
- Intégration de graphiques
- Contrôle précis du layout
- Pas de dépendances système (wkhtmltopdf)

## 📄 License

MIT License - Voir [LICENSE](LICENSE) pour plus de détails.

## 👥 Contribution

Les contributions sont bienvenues ! Voir [CONTRIBUTING.md](docs/CONTRIBUTING.md).

---

**PCAP Analyzer Pro** - Développé pour les équipes SOC et ingénierie réseau 🔒
# Wireshar-AI
# wireshark-mcp
