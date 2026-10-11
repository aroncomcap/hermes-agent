# COM-17900: Transport-boundary authorization

Status: redesign after PR #8 was closed at exact head
`52e2eac1a92b017223c2a87ce4fb9835bcb36648`.

## Decision

Authorize protected application egress at the last stable boundary before its
HTTP request or WebSocket application frame, not at a convenience SDK method.
Preserve each SDK's retry behavior. Every retry is a new authorization event and
receives a paired completion event. A denial aborts that attempt before request
headers/body or an application frame leaves the process.

The policy unit is an application request carrying credentials or workload data,
not a TCP packet or a payload-free protocol-control frame. TCP retransmission,
TLS negotiation, WebSocket heartbeat PING/PONG, and CLOSE frames do not carry
Hermes workload data and are outside this policy. Connection creation/reconnect
and every text/binary application frame remain protected.

The generic policy API is split into two primitives:

- `begin_external_request(request_type, operation, **safe_context) -> Permit`
- `finish_external_request(permit, outcome) -> None`

`begin_external_request` always creates an opaque request ID, invokes all strict
pre-hooks, and emits its own `denied` completion if policy blocks or fails. It
never includes request bodies, headers, URLs, tokens, filenames, response data,
or exception text. `finish_external_request` is best-effort and idempotent. A
small synchronous context manager remains for transports that expose one attempt
as one call.

## Required boundaries

### Slack HTTP, including presigned uploads

Create one adapter-owned `aiohttp.ClientSession` with public `TraceConfig`
callbacks and pass it to every `AsyncWebClient`, including workspace-specific
clients. `on_request_start` calls `begin_external_request`; `on_request_end` and
`on_request_exception` call `finish_external_request`. The trace context stores
only the opaque permit.

This covers ordinary Web API calls and `files_upload_v2`'s presigned binary POST
because the pinned Slack SDK routes both through the client's supplied session.
SDK retry handlers remain installed. Each retry calls `session.request` again,
so each attempt receives a fresh permit. The operation label is a fixed
classification (`slack_web_api`, `slack_file_upload`, or `slack_socket_handshake`)
derived from a host/path allowlist; raw URLs and query strings never enter hooks.

Redirect following is forbidden for protected Slack requests. A public
`on_request_redirect` trace callback raises before aiohttp transmits the redirected
request. Slack endpoints are expected to return their documented terminal
responses; an unexpected redirect fails closed and is diagnosable by a
names-only operation label. This makes one `session.request` attempt one protected
HTTP transmission even when the remote endpoint is hostile or misconfigured. The
redirect callback finishes the current permit as failed before raising; later
end/exception callbacks are harmless because completion is idempotent.

### Slack Socket Mode

The Slack SDK does not accept a session in `SocketModeClient.__init__`. Build the
handler through one adapter factory which, before `start_async`, closes the
SDK-created unused session and installs an adapter-owned guarded session. Fail
startup closed if the pinned SDK no longer exposes the verified
`handler.client.aiohttp_client_session` seam.

The guarded session uses the same HTTP trace for the WebSocket handshake. It also
uses an adapter-owned `ClientWebSocketResponse` subclass supplied through
aiohttp's `ws_response_class` constructor parameter. That subclass gates each
outbound `send_str` and `send_bytes` application-frame attempt independently.
Inbound receives and payload-free heartbeat/close protocol frames are not
protected application side effects. Existing Socket Mode reconnect and send
retry loops remain unchanged; their repeated handshake or application-frame
calls each request a new permit. Revoking an authorization generation also closes
the established socket, so no later application frame can reuse an admitted
connection after revocation.

The adapter owns and closes both guarded sessions during shutdown. Tests assert
that the SDK-created replaced session is closed exactly once and that no
unguarded session remains reachable before Socket Mode starts.

### Model inference

Supply each provider client with a guarded HTTP transport. For httpx-based
providers, wrap `HTTPTransport`/`AsyncHTTPTransport` and authorize in
`handle_request`/`handle_async_request`, which receives each application HTTP
request after client middleware. Disable transport retries and redirect following;
application-level failover/retry re-enters the guarded transport and obtains a
new permit. Assert those client and transport invariants in constructors and
tests. A provider without a verified transport hook is not activated; a
high-level wrapper is not an accepted fallback.

The guarded transport wraps the returned response stream. For streaming, the
permit remains open until the response iterator is exhausted, closed, or raises.
Completion must not be emitted merely when the response or iterator object is
returned.

### OAuth refresh

Guard the concrete refresh HTTP transport call. Disable redirects and transport
retries; any application retry occurs outside the guarded function and receives a
new permit. A denied refresh is never converted into a provider fallback or a
generic retry. Hook payloads contain provider and operation labels only.

## Policy and failure semantics

- No pre-hook installed still produces a permit so post-only audit plugins work.
- A policy exception fails closed with a generic message and no policy detail.
- Completion outcomes are `completed`, `failed`, or `denied`; HTTP error status is
  still a completed wire attempt, while a transport exception is failed.
- Cleanup hooks cannot mask the transport result.
- The active authorization generation is checked in the pre-hook immediately
  before each attempt. Queue and ingress checks remain defense in depth, not a
  substitute for this boundary.

## Verification contract

Use local fake HTTP/WebSocket servers only.

1. Denial leaves the fake server with zero observed requests or frames.
2. A Slack 503-then-200 retry produces two distinct paired permits while the
   existing retry succeeds.
3. A presigned upload POST is observed through the same trace boundary; an HTTP
   redirect is denied before the redirect target observes a request.
4. Socket handshake, reconnect, and text/binary application frames each pass
   through the guard; a retried send obtains a second permit. Heartbeat and close
   controls contain no workload payload, and revocation closes the socket.
5. Post-only hooks receive completions; failing cleanup hooks do not alter calls.
6. Model and OAuth clients prove redirects and transport retries are disabled;
   their guarded transports observe attempts and application retries produce
   distinct permits.
7. Streaming inference retains the permit through exhaustion, close, and error.
8. Captured hook payloads contain allowlisted names only and no secret values.
9. Existing Slack reconnect/upload, provider failover, and OAuth tests remain
   green without altering their retry counts.

## Release and rollback

Implement on a fresh branch and PR. Require exact-head CI plus two distinct
high-reasoning implementation approvals. Deploy through the supported installer
only. Production readback must prove the gateway is healthy, the expected Slack
and provider integrations work, paired event counts match attempted egress, and
no secret-bearing metadata is emitted.

Rollback is the prior signed package/config through the same installer. If the
guard or audit sink becomes unavailable, protected egress fails closed; health
and local administrative diagnostics remain available. Credential rotation and
the dedicated Doppler/DB boundary remain separate mandatory gates and are not
weakened by this transport change.
