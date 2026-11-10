# Evidence-first support diagnosis implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Deliver actionable, testable support conclusions rather than opaque heuristic severity totals.

**Architecture:** One bounded metadata scan generates facts, session-level hypotheses and verification steps. An optional reference capture provides descriptive deltas with comparability warnings. Engineer feedback is stored in the existing shared database; a separate offline evaluation script measures candidate ML against labelled, held-out incidents before any learned diagnosis can be enabled.

**Tech Stack:** Existing FastAPI, TShark scanner, SQLite/PostgreSQL identity store, browser JavaScript, read-only FastMCP. Optional scikit-learn for offline experiments only.

**Spec:** User-approved five-part roadmap in this conversation: reliable measures, symptom correlation, comparable references, engineer feedback, then evaluated targeted ML.

## Global constraints
- Entra authentication and CSRF remain unchanged; MCP stays read-only.
- At most two sequential scans (current and explicit reference), each 250k packets/20 seconds/8MB; metadata only.
- Each finding has facts, original frame references, hypotheses, missing context and next checks.
- No invented causal attribution, packet loss, model accuracy, confidence probabilities or trained model.
- Feedback is scoped to task/report/finding/actor, versioned and bounded; no raw PCAP or secret included.
- Experimental model evaluation uses separate captures/incidents for train/test and no raw IP identifiers as features.

## Review focus
- Partial, asymmetric or missing captures must not produce clean-health claims.
- Shared database writes require an actual authorized web identity and CSRF; MCP cannot submit feedback.
- Reference endpoint/service differences must prevent a confident before/after interpretation.
- Findings must remain stable across pagination and bounded MCP responses.
- Stale browser requests must not display another capture's diagnosis or record feedback on it.

### Task 1: Correlated evidence report
Files: new `app/services/support_diagnosis.py`, `tests/test_support_diagnosis.py`; modify `app/services/transaction_service.py` to expose `from_rows` and reuse the same scan.
- [x] Write tests for DNS failures, resets, unanswered exchanges, missing RTT, independent streams, reference comparability and partial coverage.
- [x] Run failing tests, then implement `SupportDiagnosis.report(path, reference_path=None)` and pure `build_report(rows, coverage)`.
- [x] Keep observations separate from hypotheses; reference findings by version + type + stream/anchor frame.
- [x] Expose protected web and MCP read routes and one read-only MCP tool; test route validation and metadata privacy.

### Task 2: Engineer feedback and evaluation
Files: new `app/services/diagnosis_feedback.py`, tests; extend store schema via its normal initialization and router with authenticated web-only writes.
- [x] Store one current bounded rating per actor/report/finding and corrected cause; hash actor identifiers in public responses.
- [x] Validate report IDs against fresh deterministic diagnosis snapshots and reject stale/arbitrary finding IDs.
- [x] Add offline evaluation script with capture-disjoint train/test, explicit label requirements and metrics; no deployed model enablement without evaluation data.

### Task 3: Web experience and publication
Files: `static/js/support-diagnosis.js`, stylesheet, template and asset registration; MCP catalog/instructions.
- [x] Add on-demand diagnosis panel in Santé TCP, explicit reference selector and engineer feedback controls.
- [x] Display evidence, unknowns, next checks, reference deltas and feedback state using text nodes and request guards.
- [x] Run complete Python/JS checks, local browser diagnosis/reference/feedback tests and fresh independent review.
- [ ] Commit, push, deploy and verify asset integrity + anonymous API rejection. Preserve production/rollback registry images.

## Execution record
- Native implementation in the existing isolated codex branch; no edits to the obsolete Downloads checkout.
- 268 Python + 62 JavaScript checks passed after review fixes; real TShark synthetic capture, browser reference and feedback persistence verified.
- Review fixes: DNS measurements are counted once; stream counters are linear and internal reconstruction input is capped before allocation.
- Privacy follow-up: persist only numeric features/validation IDs; deletion removes feedback and blocks late snapshot resurrection.
- Ruling: ML remains an offline experiment until real adjudicated cases exist; cost is no immediate learned ranking, avoiding an unevaluated product claim.
- Ruling: stage aggregation inspects at most 5000 decoded DNS/TCP rows; cost is explicitly partial stage comparisons on large captures.
- Synthetic Isolation Forest smoke test executed in a separate temporary environment (scikit-learn1.9.1); no real performance claim or deployed model.
