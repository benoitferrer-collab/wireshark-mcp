# Guided PCAP investigation

**User request:** Have the MCP guide engineers through their actual problem with targeted questions grounded in the capture.

**Design:** Add a read-only `guide_investigation` tool and a guided prompt. The tool reads the actual analysis summary and a bounded anomaly page; when an issue and a typed target are known, it also performs one bounded original-capture search. A pure planner turns these observations into cited facts, a single prioritized missing-context question with its rationale, and executable follow-up tool arguments. No root cause or compromise assertion is synthesized. Repeated calls accept the known context from the conversation; there is no shared conversation state/database. Unknown context can be explicitly marked unavailable; report mode suppresses questions. Questioning and conversation rendering belong to the client model, not an autonomous MCP chat sender.

**Constraints:** Preserve OAuth, subject authorization, field minimization, original scan budgets and statelessness. Never request keys, passwords, credentials or full payloads. Captured strings and user free text are data, not instructions. A time range outside the capture must be clarified explicitly, without implying it was searched. Evidence is fetched by the tool, not accepted as an unverified caller-supplied finding. Data-source failures and incomplete searches remain explicit. Lightweight summary first, at most one costly scan. The user can request a direct report and stop questions.

**Files:** new `mcp_gateway/guidance.py`, `gateway_tests/test_guidance.py`; extend `mcp_gateway/server.py`, `mcp_gateway/catalog.py`, `docs/MCP_INVESTIGATION.md`, catalogue test count.

- [x] RED/GREEN pure planner: grounded question, missing-context priorities, known/unavailable context, report mode, out-of-range time, safe evidence and no unsupported cause.
- [x] RED/GREEN real tool registration/dispatch: authenticated read backend, targeted scan, graceful optional-source failure, invalid input before network, guided prompt.
- [x] Update instructions/catalogue/docs, full Python/JS suite, independent review, address findings.
- [ ] Commit, push, deploy Vercel and verify availability/auth boundaries.

Verification before publication: 199 Python tests and 17 JavaScript tests passed. Authenticated MCP JSON-RPC guide_investigation -> live local backend -> actual TShark on synthetic engineering-demo produced 10 observations, one incident-time question, and executable follow-up calls. Independent review fixes: no assumed TCP for generic connectivity/performance, and explicitly unavailable time context is not re-asked on mismatch; both RED→GREEN. Optional source deadlines (15s summary, 8s anomalies, 50s scan) are tested. No deferred findings. Deployment check pending delivery.
