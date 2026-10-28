# Entra web, activité MCP et interface Nomios Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Livrer une interface Nomios réelle, une connexion Entra par groupe administrable et les métriques MCP.
**Architecture:** Conserver les identifiants DOM et moteurs historiques. Ajouter une couche de session serveur, un stockage transactionnel partagé et un écran Assistants IA alimenté par des événements authentifiés.
**Tech Stack:** FastAPI, MSAL, PyJWT, PostgreSQL/psycopg, SQLite de test, JavaScript existant.
**Spec:** ../specs/2026-10-27-entra-web-mcp-activity-design.md ; ajout utilisateur : intégrer aussi la nouvelle interface web.

## Global Constraints
- Tenant 4b0a3328-264b-4f04-a6e9-66b104b58487 ; administrateur initial 65c6def3-d34c-414d-9d6e-a9266fa76264.
- Groupe vide : administrateur uniquement ; partage des captures approuvé.
- Sessions opaques HttpOnly/Secure/SameSite=Lax, contrôle CSRF, vérification groupe toutes les cinq minutes.
- MCP existant reste limité au propriétaire ; compteurs tools/call, conservation 30 jours, aucune donnée PCAP/prompt/token dans les événements.
- Pas de déploiement incomplet ni d'abonnement payant sans accord.

## Review Focus
- Upload Node : mêmes sessions que FastAPI, aucune clé exposée au navigateur.
- Changement de groupe : invalidation des autorisations en cache.
- Requêtes MCP concurrentes : événements transactionnels, pas de compteur mémoire.
- Erreurs Graph ou base : refus d'accès et indication indisponible.
- Interface : conserver tous les modules et leurs événements existants.

### Task 1: Stockage partagé et politique
**Files:** app/identity/store.py, app/identity/settings.py, tests/test_identity_store.py.
**Interfaces:** IdentityStore.get_session/save_session/delete_session, get_policy/set_group, record_event/activity ; WebSettings.from_env.
- [ ] Écrire les tests de sessions expirées, groupe versionné, compteurs concurrents et suppression à 30 jours ; les exécuter avant le code.
- [ ] Implémenter SQL paramétré, SQLite local et PostgreSQL configuré par DATABASE_URL, chiffrement des secrets de session.
- [ ] Exécuter `python -m pytest tests/test_identity_store.py -q` ; attendu PASS.

### Task 2: Authentification web et uploads
**Files:** app/identity/web.py, app/api_auth.py, app/main.py, cloud_upload/app.js, static/js/connection.js, cloud_upload/browser.js, tests/test_identity_web.py.
**Interfaces:** create_identity_router, WebIdentityMiddleware, session resolution and CSRF; upload service validates session through a fixed internal backend endpoint.
- [ ] Écrire et exécuter les tests callback, mauvais tenant/nonce, hors groupe, erreurs Graph, droits admin, CSRF, origines, sessions expirées et bearer interne.
- [ ] Implémenter MSAL auth code, validation ID token, cache MSAL chiffré, login/logout/me, groupe admin et introspection interne ; aucune clé API JS en mode Entra.
- [ ] Exécuter tests identité et tests Node ; attendu PASS.

### Task 3: Événements MCP
**Files:** mcp_gateway/activity.py, mcp_gateway/server.py, app/identity/web.py, gateway_tests/test_activity.py.
**Interfaces:** instrument accepted tools/call at low-level handler; authenticated internal event ingestion using BackendClient; verified client identity from MCP auth context.
- [ ] Écrire et exécuter les tests succès/erreur/paramètres invalides/non-outil/collecteur indisponible.
- [ ] Ajouter collecte bornée sans contenu, horodatage UTC et agrégation client.
- [ ] Exécuter gateway_tests ; attendu PASS.

### Task 4: Interface et intégration
**Files:** templates/index.html, static/css/nomios.css, static/js/identity-ui.js, static/img/nomios.png, templates/login.html, docs/ENTRA_WEB.md, deploy/requirements-cloud.txt.
**Interfaces:** écrans admin et assistants via /api/identity/* ; conserver toutes les sections historiques.
- [ ] Écrire et exécuter tests de présence des modules et routes protégées.
- [ ] Intégrer la présentation Nomios, navigation et vrais compteurs ; états vides/erreurs explicites, actualisation uniquement panneau visible.
- [ ] Exécuter suites Python/Node, vérification navigateur ordinateur/mobile, revue indépendante de branche.
- [ ] Préparer la configuration Entra/base et documenter les valeurs manquantes ; activer seulement après vérification complète.
