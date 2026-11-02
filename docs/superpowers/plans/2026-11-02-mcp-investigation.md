# MCP Investigation Implementation Plan

> **For agentic workers:** Execute inline using superpowers:executing-plans, with a final independent review.

**Goal:** Turn the existing MCP into a bounded, evidence-driven offline investigation workbench.
**Architecture:** A dedicated TShark service reads storage-resolved captures; pure projection helpers correlate stored evidence. Private FastAPI routes serve read-only MCP tools. Existing authentication and response sanitization apply.
**Tech Stack:** Python, FastAPI, Pydantic, MCP FastMCP, TShark, existing browser JavaScript.
**Spec:** docs/superpowers/specs/2026-11-02-mcp-investigation-design.md

## Global Constraints

Read-only, fixed output fields; 25 rows/page; 25 indicators/hunt; 250000 input packets, 20 seconds, 8 MiB output; one scan/process. Preserve current identity and TLS behavior.

## Review Focus

Incomplete scans must not claim complete coverage. User filters must not become CLI options or shell code. Secret fields must not enter correlation output. Evidence numbering must distinguish frame from index. Missing captures/engine and invalid filters must produce actionable errors without paths.

### Task 1: Capture engine

Files: app/services/investigation_service.py; tests/test_investigation.py; Dockerfile.vercel.
- [x] Write/run failing synthetic-capture tests for filters, pagination, IOC matching, conversations, scan bounds, privacy and errors.
- [x] Implement fixed-field offline TShark runner, typed filters, coverage envelopes, aggregation and triage presets.
- [x] Run targeted tests and commit.

### Task 2: Evidence projections and API/MCP

Files: app/investigation_views.py; app/mcp_api.py; mcp_gateway/server.py; gateway_tests/test_investigation_tools.py; tests/test_investigation_api.py.
- [x] Write/run failing route and MCP tests for search, conversations, IOC hunts, triage, correlation, comparisons and capability discovery.
- [x] Implement server-side validation, sanitization, references, tool descriptions and investigation instructions.
- [x] Run targeted and complete suites; commit.

### Task 3: Evidence navigation and delivery

Files: static/js/evidence-links.js; templates/index.html; scripts/build_frontend.py; app/main.py; docs/MCP_INVESTIGATION.md; gateway_tests/test_evidence_links.cjs.
- [x] Write/run failing tests for safe analysis/packet navigation parsing.
- [x] Implement deep links using existing application load/details methods and asset versioning.
- [x] Run browser/runtime verification, full tests, independent review, address findings and deploy.

Execution ledger: start 7cec4af; source checkout clean. Native execution chosen to preserve existing app context. User's request authorizes implementation of the proposed investigation improvements without further design questions.


Final verification before publication: 184 Python tests and 15 JavaScript tests passed; static frontend build succeeded. Independent reviewer found five issues (initial fragment rewrite, repeated TShark occurrences, stored DNS answers, IPv6 endpoints, Compose engine packaging); all addressed, behavioral fixes verified RED→GREEN. Browser opened synthetic capture evidence directly in the correct packet OSI modal. Modal stacking corrected after visual verification. No deferred review findings. Production publication and smoke checks recorded in the delivery result.
