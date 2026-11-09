# Multi-PCAP evidence improvement plan

> Execute inline using superpowers:executing-plans, with final independent review.

**Goal:** Improve cross-point packet matching and make uncertainty and evidence usable for support.
**Architecture:** Keep existing flow correlation and charts, replace packet matcher with a bounded metadata-only evidence service. Match TCP data by logical direction and an ephemeral sequence/length/payload digest signature, preserving repeated occurrences. Do not depend on IPv4 IDs or flatten opposite directions through NAT. Classify absent observations without asserting network loss. Center timings per direction; median offsets include transit and are not pure clock offsets. Expose capture/index coverage, ambiguous repeats and frame samples, no payload or digest.

- [x] Add failing real-PCAP tests for NAT/IP-ID rewriting, different payloads, reverse directions, repeated packets, partial capture and absent samples.
- [x] Extend bounded extraction with frame occurrences and explicit scan/signature caps. Use matching evidence to disambiguate NAT flow candidates conservatively.
- [x] Add direction-aware evidence matching, matched/unmatched/ambiguous counters and unknown absolute delays/losses. Preserve legacy response keys where required without fabricating measurements.
- [x] Update support verdict wording and add an evidence/coverage panel to existing Multi-PCAP interface. Show frames, association confidence and timing assumptions.
- [ ] Run tests, browser verification, independent review, documentation and deployment verification.

## Execution ledger

- Real synthetic PCAP regressions cover NAT + changed IPv4 IDs, repeated candidates, opposite-direction collisions, exact scan caps and unknown metrics when no match exists.
- Review rejected treating disjoint first64 signature samples as proof of different NAT flows. Fixed: nonoverlap rejects only with complete signature samples.
- Review required no raw timing on ambiguous repeats. Fixed and regression tested.
- Captured TCP bytes are used directly to preserve Scapy TLS robustness; snaplen-truncated frames are flagged and excluded.
- Browser LAN/WAN test: 2 candidate matches, 1 unmatched occurrence, 1 ambiguity; no confirmed network-loss claim.
