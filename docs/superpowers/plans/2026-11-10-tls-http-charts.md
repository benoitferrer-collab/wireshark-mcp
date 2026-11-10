# TLS report to HTTP charts

User reports successful decrypted rows but empty legacy HTTP charts, plus a rejected PEM error displayed green alongside prior success. Fix the two data paths without decrypting again or changing stored captures.

- Web TLS GET computes bounded chart totals from all saved sanitized rows (at most10k), independent of pagination. Fixed top20 lists and25 request samples; no bodies, cookies, authentication, or User-Agents introduced. MCP retains its existing paginated-only report.
- HTTP source selector defaults to decoded TLS on a new successful job and preserves the engineer's choice of initial analysis. Decoded chart scope is explicitly the saved TLS report, outside legacy global filters. Do not mutate original analysis; capture changes cannot reuse another capture's TLS view.
- TLS versions are observed ServerHello counts, labeled as bounded/sampled where relevant. Old stored reports remain readable.
- Rejected replacement material sets error styling and clears prior decoded presentation, while explaining that the prior stored report can be read again via refresh. No secret is retained in browser storage.
- Regression tests: totals beyond25 rows, safe-field allowlist, existing renderer integration, capture change, rejected replacement state, version counters, MCP pagination.
- Verify full tests, frontend build, production charts with existing RSA demo report (GET3,200x2,503x1,TLS1.2); no reimport needed.
