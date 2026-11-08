# Guided product demo

Authorized scope: one-click button and /?demo=1 URI showing real product workflows for tomorrow's support presentation. Keep authentication and CSRF. My design: bundled deterministic synthetic PCAP and precomputed results produced by existing analyzer (no external enrichment), installed on authenticated POST /api/demo/start into normal local/cloud storage. Reuse existing demo results; never touch real captures. Original PCAP remains available to MCP/TShark. A floating accessible tour offers next/previous, optional 12-second autoplay, stop/restart and useful observations, navigating existing modules. Clipboard handoff remains explicit, no external LLM calls. Security/MCP/TLS limitations are stated honestly; demo does not pretend to decrypt unencrypted traffic or simulate live assistant activity.

- [x] Generate reproducible synthetic fixture plus results, verify no personal paths/real hosts.
- [x] Test local/cloud install and reuse, then implement endpoint under existing middleware.
- [x] Test tour sequence and URL trigger; implement button, versioned assets, responsive controls.
- [x] Run full checks, browser tour verification and independent review.
- [x] Commit, deploy, verify anonymous access denied and public assets, push branch.

Verification: 204 Python tests and 34 JS tests pass. Actual TShark finds six RST frames, first at frame8. Cloud test verifies original PCAP survives a new instance. Browser traversed all15steps with no console errors and verified autoplay/pause/stop/relaunch. Review cancellation and real-capture-switch races corrected with regression tests.

Production deployment dpl_7jwJb9YnLFzxJVeAtAk3gR1wrQS6 is READY and aliased to wireshark-mcp.vercel.app. Public tour JS/CSS matched the tested source. Anonymous POST /api/demo/start and /mcp remain401. Production authenticated installation not exercised; cloud/local storage behavior covered by tests. Mobile390px tour controls fit without page overflow; screenshot saved outside repo.
