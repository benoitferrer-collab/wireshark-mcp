# Vercel managed implementation plan

> **For agentic workers:** Use superpowers:executing-plans. Implement in this session with TDD and a final independent review.

**Goal:** Run the personal PCAP application, worker and MCP on managed Vercel services.
**Architecture:** Private Blob object storage, direct browser uploads, Queues polling Daemon, HTTP API and MCP Services.
**Tech Stack:** Existing Python/Scapy, official vercel-blob/vercel-queue SDKs, Node Blob client, Docker.
**Spec:** docs/superpowers/specs/2026-10-27-vercel-managed-design.md

## Global Constraints
- 100 MiB per file; 200 MiB per multi job; at most 8 files.
- One 2 GiB Hobby daemon; no paid upgrade; personal shared workspace.
- Keep local Docker mode; enable managed storage only with PCAP_STORAGE=vercel.

## Review Focus
- Lost local filesystem between requests: results must persist in Blob.
- Forged path or excessive file size: deny before queuing or analysis.
- Queue redelivery: completed/deleted jobs must not run again.
- Failed/OOM process: job must reach a useful failed state, not poll forever.
- Metadata path from another instance: reconstruct streams from current scratch.

### 1. Persistent evidence and job lifecycle
Files: app/cloud/{objects,context,storage,jobs,worker,run_job}.py, storage_service.py, tests/test_cloud.py.
- [x] RED tests with two storage instances, traversal/size rejection, replay, delete and failure.
- [x] Implement Blob adapter, per-request scratch and job lifecycle.
- [x] GREEN tests and real Scapy smoke in the cloud image.

### 2. HTTP and browser integration
Files: app/cloud/routes.py, app/main.py, cloud_upload/, static/js/connection.js, app.js.
- [x] RED tests for direct upload path/token, limits and async single/multi response.
- [x] Implement token service, browser bundle, managed job routes and status polling.
- [x] GREEN suites and production bundle build.

### 3. Services, Daemon and deployment
Files: vercel.json, Dockerfile.vercel, Dockerfile.worker, Dockerfile.mcp, mcp_gateway/asgi.py, deploy/requirements-cloud.txt, docs/VERCEL_MANAGED.md.
- [x] Prepare correct service routing, private binding, region and fail-closed environment.
- [x] Independent review and fixes with regression tests.
- [x] Run local builds; configure project/private Blob in closer15; try deployment without paid upgrades.

## Verification evidence

Production deployment READY on 2026-10-27 at https://wireshark-mcp.vercel.app. Private Blob roundtrip and real browser-client Blob upload / queue / daemon / summary / packet APIs passed. OAuth credentials are still required before connecting Claude and ChatGPT. See docs/VERCEL_MANAGED.md for current setup and limits.
