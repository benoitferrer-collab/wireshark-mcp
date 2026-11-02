# Security Centre

**Goal:** Deliver an authenticated, responsive product security page at `/securite`, with runtime configuration visibility and educational interactions, within the existing Vercel application.

**Design:** Preserve Nomios branding; use a dedicated dark editorial layout, blue/mint accents, one horizontal navigation, an interactive architecture map, policy simulator and searchable read-only tool catalogue. Page interactions are local demonstrations, not real attacks or enforcement changes. A private overview endpoint reports only non-sensitive configuration signals, never secrets/IDs/capture data. External LiteLLM enforcement is declared by the user, not independently monitored or guaranteed. Do not equate closed MCP tool catalogue with blocking general LLM conversation. Web group checks and MCP subject allowlist are distinct. Show local/demo/unknown status honestly. No claims of certification, data residency, infallible injection detection or mandatory proxy routing.

**Implementation:** `mcp_gateway/catalog.py` shared factual tool catalogue; `app/security_page.py` overview projection + page/API router; `templates/security.html`, `static/css/security.css`, `static/js/security.js`; existing app includes router and navigation link. Preserve existing auth. Use CSP, no external scripts/styles and `Cache-Control: no-store` on status.

- [x] RED/GREEN: overview signals, no secret disclosure, catalogue matches actual registered MCP tools; authenticated overview boundary.
- [x] Implement page, dynamic status, architecture selector, refusal simulation, catalogue filter, print styles and explicit limitations.
- [x] RED/GREEN: simulation rejects unknown tools/invalid identity, distinguishes LLM general conversation and external guardrail decisions; JavaScript syntax and full suites.
- [x] Browser verify desktop/mobile, keyboard interactions, screenshot; independent review and fixes.
- [ ] Commit, push, deploy Vercel, verify public/anonymous behavior and deliver URL.

Authorized user request: create a dynamic page describing product security; prior design discretion applies. Native implementation in existing Vercel project; no separate hosted Site or changes to enforcement/permissions.

Verification: 187 Python tests passed with the configured project interpreter (including async catalogue consistency, no skips); 17 JavaScript tests passed; syntax, diff and static build checks passed. Desktop 1440px and mobile 320px browser checks found no horizontal overflow; simulator, architecture selector, catalogue search and no browser errors verified. Screenshot security-centre.png. Independent review: no auth/secret/CSP or claim issues; unknown-scenario fallback corrected with a RED→GREEN regression test so it never implies an unsupported grant. Publication pending final deployment check. No existing permission or guardrail configuration changed.
