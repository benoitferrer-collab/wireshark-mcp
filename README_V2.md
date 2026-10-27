# 🚀 PCAP Analyzer Pro V2

## Nouveautés Phase 1 - Interface Moderne & IA Conversationnelle

Cette version majeure apporte une refonte complète de l'interface utilisateur avec un design moderne flat, un système de thème dark/light switchable, et un chatbot IA conversationnel intégré.

---

## 📋 Nouvelles Fonctionnalités

### 1. 🎨 Interface Moderne Flat Design

- **Palette de couleurs tech** : Bleu cyan (#06b6d4) + Violet (#8b5cf6) avec accents
- **Typographie Inter** : Police moderne Google Fonts pour une meilleure lisibilité
- **Glassmorphism** : Cartes avec effet verre dépoli et transparence
- **Ombres douces** : Shadows modernes avec effets de glow
- **Transitions fluides** : Animations CSS pour toutes les interactions
- **Espacement harmonieux** : Système de spacing cohérent via variables CSS

### 2. 🌓 Mode Dark/Light Switchable

- **Toggle dans le header** : Bouton soleil/lune pour changer de thème
- **Persistance** : Préférence sauvegardée dans localStorage
- **Transition douce** : Animation fluide entre les modes (250ms)
- **Variables CSS** : Système complet de custom properties pour les couleurs
- **Graphiques adaptatifs** : Chart.js s'adapte automatiquement au thème
- **Composants cohérents** : Tous les éléments (cartes, boutons, tables) s'adaptent

### 3. 🤖 Chatbot IA Conversationnel

- **Bouton flottant** : Icône en bas à droite pour ouvrir le chat
- **Panel moderne** : Interface de chat élégante avec header coloré
- **Bulles de messages** : Utilisateur à droite (cyan), IA à gauche (violet)
- **Suggestions prédéfinies** : Questions rapides cliquables :
  - "Quelles sont les principales anomalies ?"
  - "Y a-t-il des IPs suspectes ?"
  - "Résumé du trafic DNS"
  - "Problèmes de performance ?"
- **Historique de session** : Conversation conservée pendant la session
- **Indicateur de frappe** : Animation de chargement pendant la réponse IA
- **Contexte PCAP** : L'IA connaît le contexte de l'analyse en cours

### 4. 🔬 Boutons "Analyser avec IA"

Boutons 🤖 présents sur les éléments clés :
- **Cartes de résumé** : Risque, DNS, HTTP
- **Graphiques** : Distribution protocoles, Top IPs, Anomalies
- **Tables** : Domaines DNS, User-Agents, Anomalies
- **Action** : Clic ouvre le chatbot avec une question contextuelle

### 5. 📊 Améliorations Chart.js

- **Couleurs thématiques** : Adaptation automatique dark/light
- **Tooltips améliorés** : Informations plus détaillées
- **Animations fluides** : Transitions lors du rendu
- **Responsive** : Adaptation mobile optimisée

### 6. ✨ Améliorations UX

- **Toast notifications** : Messages en haut à droite avec animations
  - Types : success (vert), error (rouge), warning (orange), info (bleu)
  - Auto-dismiss après 4 secondes
  - Bouton fermer manuel
- **Loaders modernes** : Spinners avec gradient
- **Micro-interactions** : Hover effects, scale, glow
- **Empty states** : États vides stylisés
- **Animations** : fade-in, slide-in, bounce

---

## 🛠️ Stack Technique

### Backend
- **FastAPI** : Framework Python moderne et performant
- **Scapy** : Analyse de paquets réseau
- **Ollama** : LLM local pour l'IA (llama3.1:8b)
- **Celery + Redis** : Traitement asynchrone

### Frontend
- **HTML5/CSS3** : Design system moderne
- **JavaScript ES6+** : Application SPA
- **Chart.js** : Visualisations graphiques
- **Vis.js** : Timeline et graphe réseau

### Infrastructure
- **Docker** : Conteneurisation complète
- **Docker Compose** : Orchestration multi-services
- **Gunicorn** : Serveur WSGI production

---

## 🚀 Instructions de Lancement

### Prérequis
- Docker & Docker Compose
- Ollama installé avec le modèle llama3.1:8b

### Démarrage avec Docker

```bash
# Cloner le projet
cd /home/ubuntu/pcap_analyzer_pro_v2

# Démarrer Ollama (sur la machine hôte)
OLLAMA_HOST=0.0.0.0:11434 ollama serve &

# Lancer l'application
docker-compose up -d

# Voir les logs
docker-compose logs -f web
```

### Accès à l'application

- **Interface Web** : http://localhost:8000
- **API Documentation** : http://localhost:8000/docs

### Configuration Ollama

```bash
# Vérifier que Ollama fonctionne
curl http://localhost:11434/api/tags

# Télécharger le modèle si nécessaire
ollama pull llama3.1:8b
```

---

## 📸 Captures d'écran (Description)

### Mode Sombre (Dark Mode)
- **Header** : Logo gradient cyan-violet, toggle thème avec lune active
- **Cartes** : Fond semi-transparent (#1e293b), bordures subtiles
- **Graphiques** : Couleurs vives sur fond sombre
- **Chatbot** : Panel flottant avec header gradient

### Mode Clair (Light Mode)
- **Header** : Fond blanc avec ombre légère
- **Cartes** : Fond blanc avec bordures grises claires
- **Graphiques** : Mêmes couleurs, fond clair
- **Chatbot** : Panel blanc avec contraste accentué

### Chatbot IA
- **Fermé** : Bouton rond gradient en bas à droite
- **Ouvert** : Panel 400x550px avec conversation
- **Messages** : Bulles arrondies, avatar emoji
- **Suggestions** : Chips cliquables en bas

---

## 🔧 API Endpoints Nouveaux

### Chatbot
```
POST /api/analysis/{task_id}/chat
Body: { "message": "Question de l'utilisateur" }
Response: { "success": true, "response": "Réponse IA", "model": "llama3.1:8b" }
```

### Status IA
```
GET /api/ai/status
Response: { "available": true, "model": "llama3.1:8b", "endpoint": "http://..." }
```

---

## 📁 Fichiers Modifiés/Créés

### Modifiés
- `static/css/style.css` - Refonte complète du design system
- `templates/index.html` - Ajout toggle thème, chatbot, AI buttons
- `static/js/app.js` - Logique dark mode, chatbot, toasts
- `app/api/routes.py` - Endpoint chatbot

### Créés
- `README_V2.md` - Documentation des nouvelles fonctionnalités

---

## 🎯 Roadmap Phase 2

- [ ] Filtres avancés avec drag & drop
- [ ] Export PDF avec graphiques
- [ ] Comparaison de captures PCAP
- [ ] Dashboard temps réel
- [ ] Intégration Threat Intelligence
- [ ] Mode collaboration multi-utilisateurs

---

## 📝 Notes Techniques

### Variables CSS Principales

```css
/* Couleurs primaires */
--primary: #06b6d4;      /* Cyan */
--accent: #8b5cf6;       /* Violet */
--success: #10b981;      /* Vert */
--warning: #f59e0b;      /* Orange */
--danger: #ef4444;       /* Rouge */

/* Dark mode */
--bg-primary: #0f172a;
--text-primary: #f8fafc;

/* Light mode */
--bg-primary: #f8fafc;
--text-primary: #0f172a;
```

### localStorage Keys

- `pcap-theme` : "dark" ou "light"

---

## 👨‍💻 Auteur

PCAP Analyzer Pro V2 - Développé pour les équipes SOC et ingénierie réseau.

---

## 📄 Licence

Propriétaire - Tous droits réservés © 2024
