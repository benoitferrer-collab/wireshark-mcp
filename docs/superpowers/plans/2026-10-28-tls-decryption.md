# TLS Decryption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Déchiffrer une capture individuelle avec une clé RSA ou SSLKEYLOGFILE et publier un rapport de dépannage sans secrets.

**Architecture:** Une tâche durable séparée utilise le worker Vercel et TShark. PostgreSQL arbitre la génération courante ; Blob privé conserve les secrets chiffrés temporaires et les résultats dérivés. Les routes d’écriture imposent la session Entra et CSRF ; le MCP lit seulement le rapport filtré.

**Tech Stack:** Python/FastAPI, psycopg, Fernet, TShark, HTML/JS, Vercel Queue/Blob.

**Spec:** docs/superpowers/specs/2026-10-28-tls-decryption-design.md (approved by user: go).

## Global Constraints

- Captures individuelles seulement ; originaux inchangés.
- RSA : 64 Kio ; keylog : 2 Mio ; expiration : 24 h.
- Ni corps, cookies, authentification, secrets ni mots de passe dans les rapports ou journaux.
- Entra et CSRF obligatoires pour déposer des secrets ; pas de dépôt via MCP ou bearer machine.
- Supprimer les secrets après succès/échec définitif et les temporaires après chaque tentative.

## Review Focus

- Suppression pendant une tâche : aucun résultat tardif ni secret restant.
- Relance et générations concurrentes : seul le résultat courant est visible.
- Secret invalide/incompatible : message honnête, pas de faux succès.
- Plusieurs champs HTTP/2 dans une trame : rapport explicite sur les limites de couverture.
- Secrets dans une URL : supprimer query/fragment, limiter et masquer les segments à risque.

### Task 1: Secret validation and durable TLS jobs

**Files:** Create app/tls/{__init__,secrets,jobs}.py; tests/test_tls_jobs.py.
**Interfaces:** validate_secret(kind, body, password)->bytes; TLSJobs(identity_store, objects, key); create(capture_id, actor, kind, body, password)->job; current(capture_id); material(job_id); complete(job_id, report); fail(job_id); delete_capture(capture_id); prune().

- [ ] Write tests for PEM/keylog validation, encrypted persistence, replay/expiry, latest generation and deletion races; observe failure.
- [ ] Implement transactional TLS job rows/current pointer with dedicated encryption key; private Blob contains bound encrypted envelopes only.
- [ ] Run tests and commit.

### Task 2: TShark decoder and queue execution

**Files:** Create app/tls/{decoder,worker}.py; modify app/cloud/worker.py and Dockerfile.worker; tests/test_tls_decoder.py.
**Interfaces:** decode(pcap:Path, kind:str, secret:bytes, root:Path)->dict; handle_tls_delivery(job_id, count, objects)->bool. Queue messages use kind=tls and an opaque ID.

- [ ] Write tests for safe subprocess arguments/resource bounds and metadata normalization, real public TLS 1.2 RSA / TLS 1.3 keylog fixtures, wrong secrets and unsupported inputs; observe failure.
- [ ] Install TShark in worker only, implement bounded isolated extraction and no payload storage. Extract HTTP/1+HTTP/2 metadata with original frame references, document first occurrence per frame where multiplexed.
- [ ] Integrate retries (3 attempts), expiry and terminal cleanup; test deletion mid-publication and older-generation completion.
- [ ] Run tests and commit.

### Task 3: Authenticated routes and MCP evidence

**Files:** Create app/tls/routes.py; modify app/main.py, app/identity/web.py, app/cloud/storage.py, app/mcp_api.py, mcp_gateway/server.py; tests/test_tls_routes.py.
**Interfaces:** POST /api/identity/tls/{capture_id} multipart(kind,file,password); GET same path with offset/limit <=25; GET /api/mcp-data/{capture_id}/tls-decryption with same pagination; get_tls_decryption MCP tool.

- [ ] Write tests for anonymous/bearer/CSRF denials, valid group session, unavailable config and no secrets in report; observe failure.
- [ ] Register routes when Entra+managed storage configured; verify capture completed before enqueue (UI waits after initial upload). GET reports only safe fields and active generation.
- [ ] Hook capture deletion and identity maintenance to TLS cleanup. Existing analysis routes unchanged.
- [ ] Run full Python suite and commit.

### Task 4: UI and deployment

**Files:** Create static/js/tls-decryption.js and static/css/tls-decryption.css; modify templates/index.html and app/main.py asset versions; docs/TLS_DECRYPTION.md.

- [ ] Add collapsible upload options and an HTTP/HTTPS panel reusing one form implementation; keep File/password only in memory until submitted, clear after use.
- [ ] On pcap:analysis-loaded, attach chosen secret to completed capture; existing capture form submits directly. Poll status and page 25 safe rows; cancel polling on capture change.
- [ ] Test DOM behavior with browser, verify no nested navigation, escape untrusted fields via textContent, verify desktop/mobile layout.
- [ ] Generate dedicated TLS key without displaying it, add sensitive Vercel production env, run all relevant tests, request final independent code review, fix material findings.
- [ ] Push branch, deploy production, verify public gates and authenticated synthetic decoding through worker; do not claim real-user end-to-end without evidence.
