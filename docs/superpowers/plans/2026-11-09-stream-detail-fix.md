# Stream detail rendering fix

Root cause: reconstruction endpoint already returns client_data/server_data but UI renders metadata-only packets, making every segment appear unavailable. Use escaped bounded directional content and a separate control-packet chronology. Read actual session metadata by endpoints, never a sorted index; unknown retransmission count remains unknown. Format duration to3decimals. Mark binary hex truncation at4096bytes rather than only5MiB. No new MCP payload capability or authentication changes.

Validation: original synthetic PCAP demonstrates GET request and HTTP200 reply in UI; reset-only server direction correctly empty. Renderer escaping/binary tests and actual Scapy/session matching regression pass. Full208Python43JS passed. Independent review binary-truncation finding fixed with8192byte regression. Screenshot saved outside repo.
