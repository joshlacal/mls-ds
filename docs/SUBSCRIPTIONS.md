Subscriptions and Cursor Invariants (Realtime Workstream C)

Transport
- Support SSE first, optional WebSocket. Server emits event lines with JSON payloads and a cursor. Heartbeats every 15s as comment lines to keep connections alive.

Cursor Format and Semantics
- Use ULID (time‑ordered, 128‑bit) encoded base32 crockford; server ensures monotonicity per conversation even within same ms by incrementing randomness if timestamp equal.
- Cursor invariants:
  - Strictly increasing per (room, eventType) total order; clients treat cursor as opaque.
  - Resume rule: server returns events with cursor > lastSeen; if lastSeen unknown/expired, server starts at current head and emits infoEvent {reason:"compacted"}.
  - Idempotent delivery: duplicate suppression on client by cursor; server may resend the lastSeen event with same cursor if requested window overlaps.

Monotonic ULID (server) — algorithm
- Maintain `last_ulid_ts[room]` and `last_ulid_rand[room]` in process memory.
- On new event with `now_ms`:
  - If `now_ms` > `last_ulid_ts[room]`, set `rand = random128()` and record `(now_ms, rand)`.
  - Else (same ms or clock skew), increment `rand` (as big‑int) by 1 to preserve strict order.
  - Compose ULID with `ts = max(now_ms, last_ulid_ts[room])` and `rand`.
- Persist only the resulting ULID; in multi‑instance deployments, total order is per stream (room) not global.

Event Types
- messageEvent, reactionEvent, typingEvent, infoEvent; all include {cursor, convoId, emittedAt, payload}.
- messageEvent payload includes messageView metadata only (no content fetch).

Backpressure and Windows
- Server maintains a bounded per‑stream buffer (e.g., 1–5k events). On overflow, emit infoEvent {reason:"slow-consumer"} then close with 409 Too Many Events.
- Clients backoff and reconnect with lastSeen cursor; jitter 250–1000ms. Encourage incremental ack via storing lastSeen after each event.

Compaction and Retention
- Retention window T (configurable). Compaction removes old ephemeral events (typing) and collapses redundant reactions; messageEvent retained until T.
- If resume cursor older than retention head, server starts at head and emits infoEvent {reason:"compacted"}.

Persistence
- Persist last‑seen cursor per user and room in cursors table on server side to allow backfill on reconnect and analytics.

Client State Machine (simplified)
- states: `disconnected` → `connecting` → `streaming` → `backoff`.
- `connecting`: perform auth; send `cursor=lastSeen?` as query param; on 410 emit UI hint to skip to head and set lastSeen=head.
- `streaming`: on event, process payload, update lastSeen, fsync periodically; on heartbeat, no‑op.
- overflow/409: transition to `backoff` (jitter 250–1000ms), then `connecting` with same lastSeen.
- network errors: exponential backoff capped (e.g., 30s), jittered; never spin.

Security
- Authenticate requests (DS token). Authorize membership per room on connect and for each event fan‑out.

Errors
- 401 unauthenticated, 403 not a member, 409 slow consumer, 410 gone (compacted), 5xx transient. Include retryAfter where possible.

Resume Pseudocode (client)
```
cursor = store.getLastSeen(room)
while true:
  try:
    for ev in subscribe(room, cursor):
      handle(ev)
      cursor = ev.cursor
      store.setLastSeen(room, cursor)
  except SlowConsumer409:
    sleep(jitter(250..1000ms))
    continue
  except Gone410:
    cursor = None  # start from head
    continue
  except Transient:
    sleep(backoff())
    continue
```

Test Matrix
- Blackhole test (disconnect mid‑burst, resume without gaps). Millisecond collision (ULID monotonic). Slow consumer backpressure. Retention compaction. Multi‑device concurrent resumes.

Cursor Invariant Tests (server)
- [ ] For N events generated within same ms, cursors are strictly increasing.
- [ ] After compaction, resume with stale cursor returns 410 and emits infoEvent(compacted) on next connect.
- [ ] Slow consumer over window receives 409 and stream closes; client can resume with lastSeen.
- [ ] Duplicate suppression holds: if server replays boundary event, client does not duplicate render.

API Endpoints
- SSE: GET /x/blue.catbird.mls.subscribeConvoEvents?convoId={id}&cursor={ulid?} with headers: Authorization: Bearer <token>, Accept: text/event-stream; charset=utf-8. Heartbeats as comment lines (": keep-alive") every 15s; server may send retry: <ms>.
- WebSocket (optional): GET /x/blue.catbird.mls.subscribeConvoEvents.ws?convoId={id}&cursor={ulid?}; first message from client may include {type:"resume", cursor}.
- Reconnect: clients should backoff with jitter (250-1000ms) and always pass lastSeen.

Event Shapes (SSE examples)
- event: messageEvent\n data: {"cursor":"01J9ZK0S5V6ZB9WQ0ZP3S9WJ7H","convoId":"...","emittedAt":"2025-10-22T22:00:00Z","payload":{"messageView":{...}}}
- event: reactionEvent\n data: {...}
- event: typingEvent\n data: {...}
- event: infoEvent\n data: {"reason":"compacted"|"slow-consumer"|"server-restart","detail":{...}}

Headers and Status
- 200 with Content-Type: text/event-stream for SSE; 101 Switching Protocols for WS. 401 unauthenticated; 403 not a member; 409 slow consumer (server will emit infoEvent then close); 410 gone (cursor compacted); 5xx transient.

Cursor Encoding Details
- ULID: 48-bit millisecond timestamp + 80-bit randomness, base32 crockford uppercase. Compare lexicographically to sort by time. Monotonic generator per (convoId, node) must increment randomness if ts == last.ts and ulid <= last.ulid.
- Cross-node: partition by convoId to a single generator or persist last_ulid per convo in memory with fencing token.

Client Resume Pseudocode
- onEvent(e): storeLastSeen(convoId, e.cursor)
- connect(): cursor = loadLastSeen(convoId); GET ...?cursor=cursor; on 410, clear cursor and reconnect.
- onError(status): if 409 or 5xx, backoff with jitter and reconnect with lastSeen; if 403, stop; if 401, refresh token then retry.

Backpressure and Buffering
- Client should process events serially and persist cursor after each event. Target end-to-end processing < heartbeat interval. Server buffer size configurable (1-5k); on overflow emits infoEvent {reason:"slow-consumer"} then 409.

Security and Auth
- Bearer token issued by PDS/DS; membership authorization checked per room on connect and for each fan-out. Do not echo sensitive payloads; only message metadata.

Validation Checklist
- SSE contract validated with curl; reconnection blackhole test passes; ULID monotonic across collisions; retention compaction produces 410 and infoEvent; multi-device resume consistent (last-writer-wins on lastSeen).
