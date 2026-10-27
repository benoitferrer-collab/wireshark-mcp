# MCP et Vercel — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connecter les conversations Claude/ChatGPT aux preuves PCAP et préparer l'interface Vercel.

**Architecture:** Service MCP autonome appelant le backend privé ; OAuth externe ; UI statique sur Vercel avec API directe. Compose/Caddy pour le moteur persistant.

**Tech Stack:** Python, SDK MCP officiel 1.x, HTTPX, PyJWT, JavaScript existant, Docker/Caddy.

**Spec:** `docs/superpowers/specs/2026-10-27-mcp-vercel-design.md`

## Global Constraints

- Résultats MCP limités à 60 000 caractères JSON, scope `pcap:read`, jetons RS256.
- Aucun secret dans le build statique ; pas de publication durant l'implémentation.
- Conserver les dépendances du backend et isoler celles du MCP.

## Review Focus

- Jeton valide d'un autre compte : rejet par liste de sujets.
- Données avec chemins internes/payloads : omission et budget de réponse garanti.
- Identifiants/session contenant des séparateurs : validation et encodage.
- Cross-origin : préflight sans authentification et Authorization autorisé.
- Index de paquets limité : limites explicites pour éviter une fausse exhaustivité.

### Task 1: Outils et authentification MCP

**Files:** `mcp_gateway/{config,auth,backend,server}.py`, `mcp_gateway/requirements.txt`, `gateway_tests/`.

**Interfaces:** `create_server(settings, backend, verifier)` retourne le serveur MCP ; `BackendClient.get(path, params)` appelle uniquement l'origine configurée.

- [x] Écrire puis exécuter les tests de contrats, budget, filtres et JWT (RED).
- [x] Implémenter les outils, la validation OAuth et le serveur HTTP.
- [x] Exécuter les tests ciblés et le protocole MCP réel (GREEN).

### Task 2: Interface Vercel et protection de l'API

**Files:** `app/api_auth.py`, `app/mcp_api.py`, `app/mcp_views.py`, `app/main.py`, `static/js/connection.js`, `templates/index.html`, `scripts/build_frontend.py`, `vercel.json`, `gateway_tests/`.

**Interfaces:** `APIAccessMiddleware(app, token)` ; `window.PCAP_CONFIG.apiBaseUrl` ; fetch et téléchargements existants conservés.

- [x] Tests RED pour refus API, preflight, build sans secrets et configuration HTTPS.
- [x] Implémenter protection, connexion UI et build statique sans dépendance.
- [x] Vérifier tests, syntaxe JS et génération complète de l'interface.

### Task 3: Déploiement et documentation

**Files:** `deploy/{compose.yml,Caddyfile,.env.example}`, `mcp_gateway/Dockerfile`, `docs/MCP_DEPLOYMENT.md`, `README.md`.

**Interfaces:** origine publique unique pour API/MCP, origine frontend distincte CORS.

- [x] Ajouter Compose privé, proxy TLS et configurations obligatoires.
- [x] Documenter OAuth externe, accès personnel, import, connexion aux deux clients et limites.
- [x] Exécuter suite existante, suite gateway, validation Compose et revue indépendante.

## Décisions d'exécution

Travail isolé dans le worktree attaché ; exécution par l'agent principal autorisée
par « ok go ». Aucun commit/push/déploiement requis pour rendre les changements
reviewables. Le service hébergé et OAuth ne peuvent être raccordés sans paramètres
réels ; préparer l'ensemble des fichiers puis indiquer les valeurs manquantes.

## Résultats de validation — 27 octobre 2026

- Backend : `python3 -B -m pytest tests -q -p no:cacheprovider` → 36 tests passent.
- Même suite dans l'image Docker Python 3.11 et dépendances exactes → 36 passent.
- MCP : environnement isolé, `python -B -m pytest gateway_tests -q -p no:cacheprovider` → 32 passent.
- Adaptateur fetch : `node --test gateway_tests/test_connection.cjs` → 2 passent.
- Build statique vers `/tmp/pcap-vercel-preview` → génération complète sans expression Jinja restante.
- Images `fastapi` et `mcp` construites avec Compose ; `config --quiet` passe.
- Caddy : validation dans un conteneur sans réseau → configuration valide.
- Smoke backend réel : 171 paquets synthétiques → Scapy → stockage → API protégée → succès.
- Smoke MCP dans son image Python 3.12 : JWT signé → appel HTTP MCP → requête backend simulée → preuve bornée ; anonyme refusé.
- Revue indépendante : trois problèmes détectés (champs bruts, contournement via pointeur, budget final).
  Tous reproduits par tests puis corrigés. Les filtres d'anomalies et la pagination
  des diagnostics ont également été ajoutés.
- Avertissements observés : dépréciations des bibliothèques de test, datetime
  historique et compatibilité de dépendances Requests dans l'image existante.
  Aucun échec sur les commandes ci-dessus.

Décisions techniques : modules API indépendants des `__init__` d'infrastructure ;
politique de filtrage pure partagée avec le backend ; dépendances MCP séparées.
Les en-têtes, IP et chaînes réseau restants ne sont pas anonymisés.
Travail laissé dans le worktree attaché, sans merge ni push.
Publication et OAuth avec les comptes réels restent à effectuer après configuration.
