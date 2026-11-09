# Transaction timeline and before/after implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task by task.

**Goal:** Show measured protocol stages and compare two engineer-selected exchanges across captures.
**Architecture:** Reuse bounded offline TShark scanning with allowlisted metadata. Build stream/request timing records in a dedicated service and expose an authenticated paginated API. A single Transactions view shows evidence and compares chosen records, without inventing a full end-to-end duration.
**Tech stack:** Python/FastAPI, TShark, existing vanilla JavaScript and CSS.
**Spec:** User approved transaction chronology and before/after comparison in chat. DNS matching to TCP is a candidate association using client, returned address and preceding timestamp, explicitly labelled. TCP timing requires SYN and matching SYN/ACK/ACK. TLS is ClientHello→ServerHello, never labelled complete TLS negotiation. HTTP uses Wireshark request/response frame correlation. Missing and partial capture data remains unknown. No URL paths, cookies, payload or secrets exposed.

## Tasks
- [x] Write failing tests against real synthetic PCAPs for known timings, resets, absent handshake, DNS errors, request correlation and partial scan coverage.
- [x] Extend investigation decoder with fixed timing fields. Implement transaction reconstruction, bounded paging and packet evidence; add protected router.
- [x] Add Transactions to existing navigation and share allowlists. Build two-pane transaction selection, stage cards, evidence links and signed differences with unknown values preserved. Guard stale asynchronous capture/selection results.
- [x] Run Python/JS tests, build frontend, inspect browser chronology and comparison. Obtain independent review and fix material findings.
- [ ] Document limitations, commit, deploy and verify published assets/auth gate.

## Execution ledger

- Fixed fields validated against installed TShark field catalogue; real synthetic captures verify DNS25/TCP40/HTTP200 ms and ClientHello→ServerHello80 ms.
- Ruling: comparison is between engineer-selected exchanges, not capture-wide averages; HTTP operation equivalence cannot be verified without exposing paths.
- Review found duplicate cursors for a DNS-over-TCP capture starting at a DNS query. Such duplicate generic TCP rows are coalesced; real-PCAP limit1 regression verifies no omitted page records.
- Browser verified reference/current capture separation, packet evidence, numeric equality on identical captures, absent TLS unknown, and paging.
