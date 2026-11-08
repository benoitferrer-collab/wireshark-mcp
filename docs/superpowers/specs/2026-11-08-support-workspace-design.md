# Support workspace

Prepare Nomios PcapAnalyzer for the support manager demonstration and daily incident work. The user wants all three outcomes: faster diagnosis, accessible team workflows, and evidence-based guided investigation with Claude.

Keep FastAPI, vanilla JavaScript, existing modules, existing Azure/MCP policies and deployment. My implementation choices: a composed dark/light support landing page, a searchable capture library with real aggregate counters, a compact incident workbench attached to the current capture, and an explicit copyable MCP handoff. No automatic paid LLM calls, no invented diagnosis, no persistent incident free text. The browser keeps the incident brief in memory only, isolated by capture; no keys or raw payload in handoff.

Library: filter filename/task ID, severity, and sort recent/packets/risk. Empty, loading and failed requests are distinguished; failed refresh preserves previous data. DOM-based actions avoid inline user-controlled script. Counters describe library metadata, not unique packets across duplicate captures.

Investigation: select symptom family, enter brief and capture location, jump to relevant existing module, copy prompt containing exact capture ID and known context. Present stored indicators as observations requiring verification. Unknown/missing diagnostics are shown as unknown, never zero. A support checklist explains context → diagnosis → evidence → handoff.

Reliability: prevent overlapping status polls and stale capture responses; validate HTTP outcomes; report failed loads/deletes accurately; retain current capture on load failure. Keep legacy upload and analysis module interfaces.

Verify pure workspace logic, request races, failure states, complete Python/JS suites, static build, desktop/mobile rendering, real synthetic capture navigation. Existing unresolved TLS worker completion is outside this change and must not be claimed fixed.
