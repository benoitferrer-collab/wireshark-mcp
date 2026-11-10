# Support Workspace Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement task-by-task.

**Goal:** Make the existing application a clear, reliable daily support investigation workspace.
**Architecture:** Vanilla support-workspace module with pure selectors and safe DOM rendering, integrated with existing analyzer events and module buttons. Fix request lifecycle in the analyzer without changing backend/auth contracts.
**Tech Stack:** FastAPI/Jinja, vanilla JavaScript/CSS, Node test runner, pytest.
**Spec:** docs/superpowers/specs/2026-11-08-support-workspace-design.md

## Global Constraints
- Keep every existing analysis module and Azure/MCP policy.
- No fake metrics, automatic LLM calls, payload handoff, or persisted incident text.
- Preserve capture identity in every asynchronous operation.
- Dark/light, keyboard, mobile and reduced motion remain usable.

## Review Focus
- Rapid A→B capture selection cannot show A under B's ID.
- Failed refresh/delete cannot claim success or empty library.
- Missing metrics cannot imply a clean capture.
- File names/IDs/free text cannot create executable DOM.
- Copy failure offers a selectable prompt and announces the error.

### Task 1: Support workflow and library
Files: static/js/support-workspace.js, static/css/support-workspace.css, templates/index.html, app/main.py, scripts/build_frontend.py, gateway_tests/test_support_workspace.cjs.
- [x] Write failing tests for filters, aggregation, unknown evidence and safe bounded handoff.
- [x] Implement exported selectHistory, summarizeHistory, supportSignals and buildHandoff, then safe DOM rendering and event wiring.
- [x] Add responsive support landing, library toolbar, brief dialog and context-sensitive workbench. Register versioned assets in both renderers.
- [x] Run tests, inspect desktop/mobile and real capture navigation.

### Task 2: Reliable requests
Files: static/js/app.js, gateway_tests/test_request_lifecycle.cjs.
- [x] Write failing tests for stale loads, failed refresh/delete, and overlapping polls.
- [x] Guard capture commits and polls by request generation; validate HTTP success before UI changes.
- [x] Run targeted and complete checks.

### Task 3: Release
- [x] Independent code review, resolve material findings, rerun affected checks.
- [x] Document support demo walkthrough with honest limitations; commit, push existing branch, deploy and verify auth gates and assets.

## Verification

200 Python tests, 31 JavaScript tests passed; static build and diff whitespace checks passed. Independent reviewer confirmed no remaining P1/P2 in revised concurrency. Browser: real synthetic capture, diagnostic links, incident context/copy, search empty state, light/dark, 390px mobile without page overflow, no console errors. Screenshot saved outside repository.

Production release: https://wireshark-mcp.vercel.app (deployment dpl_Dog2nAjAJKhNWYMxFTvfiLv9rrF9). CLI completed successfully and production alias applied. New JS/CSS returned HTTP200 and matched local source SHA256. Anonymous /api/identity/me, /api/history, /api/security/overview and /mcp returned401. No authenticated production session was exercised by this release check.
