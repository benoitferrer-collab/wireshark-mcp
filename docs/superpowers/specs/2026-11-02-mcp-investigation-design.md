# MCP investigation workbench

The user requests the fullest practical cyber investigation upgrade, following the proposed search, correlation, coverage and evidence improvements. Implement within the existing authenticated, read-only MCP and shared storage; no new identity provider or raw payload export.

## Deliverables

- Offline TShark display-filter searches over the original capture, independent of the 5000-packet UI index. Typed IP/CIDR, port, protocol, time and domain filters and optional advanced display filter.
- Conversation aggregation with TCP stream IDs, packet references, bytes, timestamps, reset and retransmission evidence.
- Batch IOC hunting for up to 25 IPs/CIDRs/domains, with exact domain or subdomain matching and no external lookups.
- Deterministic triage presets (TCP failures, DNS failures, cleartext protocols, remote access, TLS handshakes), explicitly heuristic.
- Cross-section entity correlation from stored results with exact JSON pointers, honest scope and restricted metadata.
- Stored-analysis comparison and a capabilities tool explaining coverage, limits and workflow.
- Consistent evidence links loading the correct analysis and packet in the web app; MCP instructions request facts, evidence, hypotheses, unknowns and next steps.

## Constraints and decisions

TShark reads only the storage-resolved capture via fixed argv, never a shell; disable name resolution and isolate configuration. Fields are allowlisted: no payload, cookies, credentials, URLs/query strings or secrets. Limit each scan to 250000 input packets, 20 seconds and 8 MiB output, one concurrent scan per process; report incomplete coverage and require narrower searches on exhaustion. Result pages contain at most 25 rows. Numeric packet_index is zero-based; frame_number is one-based. Packet-index coverage and source-file coverage are distinct. No assertion of absence when coverage is incomplete. No active network capture, arbitrary command, executable, path or output field accepted.

Server-side filtering/aggregation is the authority; the LLM explains evidence and cannot supply numeric observations. Full TCP payload reassembly, secret export, arbitrary file extraction, long-running job orchestration and automated threat attribution are outside this increment. Existing TLS decryption remains a separate worker capability.

## Validation

Use synthetic PCAP/PCAPNG traffic and actual TShark when available; test beyond packet 5000, pagination, IPv6, domain boundaries, empty searches, malformed filters, process time/output bounds, correlation redaction, authenticated MCP schemas/dispatch, existing suites, and web evidence URL behavior. Review independently before production publication.
