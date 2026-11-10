# On-demand processing and TLS readiness

Approved scope: user's « go » on the first three reliability priorities. Existing FastAPI, Vercel Blob, Queue SDK and Entra sessions remain in use.

- Replace permanent daemon with two private container services, one per durable queue topic. No public rewrite or new browser credentials. Queue callbacks are handled by the official SDK; max concurrency one per topic, three attempts. Keep old poll entrypoint for operational rollback.
- Enforce subprocess deadlines below Hobby's 300-second request limit; parent owns disposable scratch and child process group. Persist attempt timestamps and distinguish a slow queue from actual known outages. Never invent platform quota readings.
- Add session-protected metadata-only TLS preflight before secret submission: observed ServerHello versions, selected suites, frame references, RSA candidates vs ephemeral/TLS1.3 exchanges, explicit partial/unknown coverage. No secrets required, no plaintext exported, no promise a compatible key matches.
- Improve TLS status/polling, retry transient network failures, show real attempts and delays. No key retention extensions.
- Test callback rejection, dispatch, retry/terminal states, deadlines/cleanup, delayed status, TLS1.3/RSA fixtures, missing handshakes, privacy and existing access controls. Validate Vercel schema/build and production readiness before claiming live operation.

Deployment acceptance: service queue triggers actually present in deployment output, no daemon reserved; synthetic analysis completes through new consumer. Existing jobs are idempotent; no deletion of queued captures or secrets and no paid upgrade.

Implementation ruling: manual container callbacks use v2 CloudEvents and bind the actual platform consumer group. The SDK0.10 rejects v1; an SDK-backed callback test verifies dispatch and acknowledgement. Function-level concurrency beta was rejected during preview deployment; only queue trigger concurrency is used, with separate services for memory isolation.
