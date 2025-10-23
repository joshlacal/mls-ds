Server Workstream TODOs (B, C, D, G)

B — Delivery Service (API & Persistence)
- [ ] Schema (align with migrations/; add missing pieces):
  - [ ] messages: id (uuid), convo_id, sender_did, message_type, epoch, ciphertext BLOB, sent_at
  - [ ] members: (exists) ensure unread_count, left_at
  - [ ] envelopes: id, convo_id, recipient_did, message_id, created_at (for mailbox fan‑out)
  - [ ] cursors: user_did, convo_id, last_seen_cursor, updated_at (server‑tracked)
  - [ ] reactions: id, convo_id, message_id, actor_did, kind, created_at (with unique(actor,message,kind))
  - AC: Forward/rollback migrations clean; unique indexes created; foreign keys enforced; seed tests pass.
- [ ] Store layer (db.rs/storage.rs):
  - [ ] add get_messages(convo_id, before_cursor?, limit) with pagination and policy filters
  - [ ] add insert_envelope(recipient, message_id) idempotent upsert
  - [ ] add update_last_seen(user, convo, cursor)
  - AC: Unit tests cover empty, single‑page, multi‑page; envelope upsert is idempotent; last_seen updates are monotonic.
- [ ] Handlers (src/handlers):
  - [ ] send_message: validate ExternalAsset pointers in JSON body (no fetch), persist metadata only, return MessageView; enforce size and attachment count limits
  - [ ] get_messages: page via cursor/time; include ExternalAsset pointers
  - [ ] add_members/publish_key_package: finalize responses per lexicon
  - AC: OpenAPI (xrpc) routes respond with 2xx for valid requests; 4xx errors include structured codes; limits tested.
- [ ] Input validation utility: src/util/asset_validate.rs (new)
  - [ ] providers allowlist, max_size, sha256 length (64 hex/32 bytes) and algo check
  - [ ] reuse in send_message and upload_blob
  - AC: Table‑driven tests for valid/invalid providers, sizes, and hashes.

C — Realtime (Event Feed & Cursors)
- [ ] Module: src/realtime/cursor.rs (ULID generator, encode/decode) and src/realtime/mod.rs (SSE/WS mux)
- [ ] Emit events: messageEvent, reactionEvent, typingEvent, infoEvent with cursor
- [ ] Persist last‑seen cursor per user on ack/flush; expose API for backfill
- [ ] Heartbeats and backpressure per SUBSCRIPTIONS.md; close on overflow with infoEvent
 - AC: Blackhole resume test passes; per‑stream buffer metrics exported; 409/410 paths covered.

D — Mailbox Fan‑Out (Scale)
- [ ] Feature flags: src/flags.rs use_mailbox_for_room(room_id)->bool
- [ ] Fan‑out engine: src/fanout/mod.rs
  - [ ] On send: write envelopes per recipient (no content), notify realtime
  - [ ] Idempotent upsert keyed by (recipient,message_id)
- [ ] Per‑user acks table using cursors; O(n) write path and metrics
 - AC: 1000‑member room send stays within target write budget; retries are idempotent; ack advancement updates last_seen per recipient.

G — Infra/Observability/Security
- [ ] Limits config (env or config file): max_size, max_attachments, providers_allowlist
- [ ] Observability middleware: request ids, cursor tracing; export metrics (latency, fanout, buffer)
- [ ] Rate limiting on sendMessage (per room, per DID)
 - AC: Dashboards show p50/p95 route latency, buffer occupancy, fan‑out queue depth; rate limiter emits 429 with retryAfter.

Checkpoints
- CP1: Lexicon freeze; codegen guard green
- CP2: send/get paths green with pagination and limits
- CP3: Realtime resume test passes
- CP4: Mailbox fan‑out behind flag validated on staging

Suggested File/Function Seeds
- `src/realtime/cursor.rs` — `fn next_ulid(room: &RoomId) -> Ulid`
- `src/realtime/mod.rs` — `async fn sse_stream(req) -> impl Stream<Item=Event>`
- `src/fanout/mod.rs` — `async fn fanout(convo: ConvoId, msg_id: MsgId)`
- `src/util/asset_validate.rs` — `fn validate_pointer(ptr: &ExternalAsset) -> Result<(), Error>`

Detailed Breakdown and Acceptance Criteria

B — Delivery Service (API & Persistence)
- Schema DDL (schema.sql):
  - messages(id UUID PK, convo_id TEXT, sender_did TEXT, message_type TEXT, epoch INTEGER, ciphertext BLOB, sent_at TIMESTAMPTZ DEFAULT now());
  - members(id UUID PK, convo_id TEXT, member_did TEXT, unread_count INTEGER DEFAULT 0, left_at TIMESTAMPTZ NULL);
  - envelopes(id UUID PK, convo_id TEXT, recipient_did TEXT, message_id UUID, created_at TIMESTAMPTZ DEFAULT now(), UNIQUE(recipient_did, message_id));
  - cursors(user_did TEXT, convo_id TEXT, last_seen_cursor TEXT, updated_at TIMESTAMPTZ DEFAULT now(), PRIMARY KEY(user_did, convo_id));
  - reactions(id UUID PK, convo_id TEXT, message_id UUID, actor_did TEXT, kind TEXT, created_at TIMESTAMPTZ DEFAULT now(), UNIQUE(message_id, actor_did, kind));
- Store functions (db.rs):
  - get_messages(convo_id: &str, before: Option<&str>, limit: i64) -> Vec<MessageRow>
  - insert_envelope(recipient: &str, convo_id: &str, message_id: Uuid) -> bool // returns true if inserted
  - update_last_seen(user: &str, convo: &str, cursor: &str) -> ()
- Handlers (send_message.rs, get_messages.rs):
  - send_message validates ExternalAsset pointers (size<=max, sha256 hex len==64, provider in allowlist), persists metadata only; returns MessageView {id, convoId, sender, epoch, attachments:[ExternalAsset], sentAt, cursor?}
  - get_messages paginates by ULID cursor and limit; returns messages newest-first with nextCursor
- Acceptance: Unit tests cover validation failures; pagination stable across inserts; policy limits enforced; 95p send latency < 50ms at p50 load.

C — Realtime (Event Feed & Cursors)
- Modules: realtime/cursor.rs (ULID monotonic generator), realtime/sse.rs and realtime/ws.rs (mux in mod.rs).
- Emit events for message/reaction/typing/info with cursor; include convoId and emittedAt.
- Persist last-seen on server via update_last_seen on periodic flush or ack message (for WS); SSE persists on server tick.
- Backpressure: bounded queue per stream; on overflow emit infoEvent then 409 and close.
- Acceptance: Blackhole test passes; resume without gaps verified; heartbeats sent every 15s and observed by client.

D — Mailbox Fan‑out (Scale)
- Feature flags: flags.rs -> fn use_mailbox_for_room(room_id: &str) -> bool sourced from config or DB.
- Fan-out engine (fanout/mod.rs): on send, enumerate active members, write envelopes per recipient, then notify realtime for each.
- Idempotency: upsert keyed by (recipient_did, message_id); return whether new.
- Per-user acks via cursors table; metrics on write amplification and queue depth.
- Acceptance: 100-member room end-to-end delivery rate > 99.99% over 10k messages; O(n) writes per send within budget; p99 fan-out < 250ms.

G — Infra/Observability/Security
- Config keys (config.toml): max_attachment_size_bytes, max_attachments, providers_allowlist=[...], mailbox_enabled=true.
- Metrics: ds_send_latency_ms, ds_get_messages_latency_ms, rt_queue_depth, rt_dropped_streams, fanout_envelopes_written, rate_limit_dropped.
- Rate limiting: token-bucket per (room, did), defaults 20 req/s burst 40; 429 with retryAfter.
- Logging/Tracing: request_id on all handlers; cursor in event logs; trace ids propagated.
- Acceptance: One-click deploy with secrets template; dashboards for metrics; load soak shows no leak.

Two-week Sprint Seed
- Week 1: finalize schema + validation util; implement send_message happy path + SSE skeleton; codegen guard script.
- Week 2: get_messages with pagination; ULID generator + resume; basic fan-out behind flag; metrics and minimal rate limit.
