# COM-17900 Astra architecture review

- Model: `gpt-6-astra`
- Mode: read-only architecture review
- Verdict: `REVISE`
- Reviewed repository: `/home/hermes/worktrees/com-17900-transport-design`
- Reviewed commit: `65862aa880827eb650c2c91eb116c42d51849173`
- Reviewed design SHA-256: `1a514d940b5c14982fc32c7a54d54f1b561e42c842c6b44708e1c93397145d99`
- Pinned libraries: Slack SDK 3.40.1, Slack Bolt 1.27.0, aiohttp 3.14.1

## Verdict

Hermes must own a thin Socket Mode transport adapter. Replacing the Slack SDK
client session after construction is unsupported and incomplete.

## Material findings

1. The Slack Socket Mode constructor starts `message_processor` and exposes no
   session-injection seam.
2. aiohttp `on_request_start` runs before the SDK's internal persistent retry,
   so traces cannot authorize every wire attempt.
3. Slack recreates its session when it is missing or closed.
4. Slack `connect` catches every `Exception` and retries forever, which can turn
   policy or audit denial into reconnect traffic.
5. `send_frame` bypasses `send_str` and `send_bytes` wrappers.
6. PING carries a timestamp and PONG echoes payload; they are not universally
   payload-free controls.
7. The proposed generation lock covered frame writes only, leaving handshake,
   reconnect, queues, and revocation incompletely linearized.

## Required implementation contract

1. No post-construction session replacement or private writer. Hermes owns
   tasks, sockets, and clean shutdown.
2. Every SDK/aiohttp retry, reconnect, upload, and application frame receives a
   distinct permit; tests include wire-observed dropped-connection negatives.
3. Redirects are denied and released before a second send for same-origin,
   relative, cross-origin, downgrade, and malformed locations.
4. Scheme, host, port, method, and operation are strictly validated, including
   presigned uploads and Socket Mode URLs; no broad fallback exists.
5. Policy, generation, and audit denial are non-fallback and non-reconnecting.
6. Revoke/admit share one linearization protocol. Late handshakes and queued
   sends cannot publish an old generation. Tests use deterministic barriers and
   distinguish an admitted in-flight completion from a new admission.
7. ACK is protected. PING, PONG, and CLOSE have narrow bounded methods.
8. Streams terminate exactly once on exhaustion, close, error, cancellation, or
   abandonment; a watchdog closes resources and bounds lifetime/renewal.
9. Admission is durable before egress. Sink failure means no egress; terminal
   reconciliation reports honestly.
10. Real pinned-library local HTTP/WebSocket tests cover raw/text/binary frames,
    retries, reconnects, closed-session fallback, redirects, sink failures,
    cancellation, abandonment, and duplicate terminal events.

Use public aiohttp client middleware as the innermost layer inside retry loops.
Use traces for observation only.
