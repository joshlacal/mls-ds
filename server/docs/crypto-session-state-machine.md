# CryptoSession state machine — Phase 2 contract

Authoritative reference for the `crypto_sessions` lifecycle introduced in Phase 2 of the MLS-DS architectural redesign. This document is the contract; if code disagrees, the code has a bug.

> **Architectural principle**: the server is a Delivery Service per RFC 9750 — it sequences observed envelopes and tracks public crypto session metadata. Clients own MLS cryptographic state. Every transition below moves *server-side observable* state; clients keep their own MLS group state and reconcile via SSE / commit submission.

## ADR-011 transition foundation

New call sites resolve an immutable `ResolvedMlsContext` from the unique active
`crypto_sessions` row and its exact legacy projection, then submit a
`ValidatedMlsTransition` to the repository. The repository performs one SQL
transaction containing the active-session CAS, compatibility mirror, optional
verified-receipt append, and delivery event. Any stale or inconsistent binding
rolls the transaction back.

`ValidatedMlsTransition` validates server-observable identity and monotonicity
only. Deserializing or hashing GroupInfo is not cryptographic verification;
operation-specific code must establish the authenticated signer/device binding
before constructing the transition. Handler conversion and successor/reset
activation remain follow-up work.

## States

| State | Meaning | Set by |
|---|---|---|
| `active` | The current crypto session for a conversation. **At most one active per conversation** (enforced by partial unique index `idx_crypto_sessions_one_active_per_convo`). | `createConvo`, successful `ActivateCryptoSession` |
| `reset_requested` | Repair has been requested for the active session; awaiting candidate MLS material from a client. | `RequestCryptoSessionReset` |
| `superseded` | Replaced by a newer session of higher generation. Retained for historical decryption. | Atomic with successful `ActivateCryptoSession` (the prior session transitions superseded as the new active is inserted) |
| `failed` | (Reserved.) Currently unused: tie-break losers do NOT get a row. Their loss is recorded as a `crypto_session_candidate_rejected` delivery event with `crypto_session_id = NULL`. Reserved for Phase 2.5 if first-class loser audit becomes needed. |
| `pending`, `superseding`, `archived` | Reserved in the CHECK constraint for future use. **No code path currently writes these states.** Treating them as intentional dead states; future plans may use them. |

## Transition diagram

```
              createConvo                     RequestCryptoSessionReset
   (none) ─────────────────► active ────────────────────────────────► reset_requested
                              ▲ │                                          │
                              │ │   ActivateCryptoSession (winner)         │
                              │ └──────────────────────────────────────────┤
                              │                                            │
                              │   prior session: superseded ◄──────────────┤
                              │   new session:   active (atomic)           │
                              │                                            │
                              │   ActivateCryptoSession (loser, race)      │
                              │   no row written; loser audit event ───────┘
                              │   with crypto_session_id = NULL
                              │
                              └── (post-#12 only: also reachable from reset_requested
                                   via legacy do_reset_group migration; not in scope today)
```

## Allowed callers per transition

| From | To | Caller / Trigger | Bound `expected_new_mls_group_id`? |
|---|---|---|---|
| (none) | `active` | `createConvo` HTTP handler | (n/a — no prior session) |
| `active` | `reset_requested` | `reset_group` HTTP, no material | `Some(new_group_id)` always |
| `active` | atomic (`superseded` + new `active`) | `reset_group` HTTP, with material → `RequestCryptoSessionReset` + `ActivateCryptoSession` back-to-back, same tx not enforced | `Some(new_group_id)` always |
| `reset_requested` | atomic (`superseded` + new `active`) | `bootstrap_reset_group` HTTP — validates `new_mls_group_id` against bound expected | reads bound from prior request event |
| `reset_requested` | `reset_requested` (idempotent re-Request) | re-`reset_group` from same admin (deterministic idempotency key) OR new admin with same expected | matrix below |
| (any) | `failed` | (reserved; not currently written) | — |
| (any indirect) | (legacy do_reset_group path) | `RecordResetVote` quorum, `TriggerSystemReset` sweep | **not via chokepoint** — bypasses crypto_sessions until post-#12 funneling |

## Idempotency rules

Every `RequestCryptoSessionReset` and `ActivateCryptoSession` carries an `idempotency_key`. The `delivery_events` table has a partial UNIQUE index `idx_delivery_events_idempotency` on `(conversation_id, COALESCE(sender_did, ''), COALESCE(sender_device_id, ''), COALESCE(idempotency_key, ''))` filtered `WHERE idempotency_key IS NOT NULL`. NULL-distinct loophole closed in Phase 2.

### Key derivation per caller

| Caller | Idempotency key derivation |
|---|---|
| `reset_group.rs` admin path (Request) | `format!("req-reset:{}-{}", convo_id, new_group_id)` — deterministic; retries from same admin/group converge |
| `reset_group.rs` admin path (Activate, when material present) | `format!("activate:{}-{}", convo_id, new_group_id)` — deterministic |
| `bootstrap_reset_group.rs` (Activate) | `format!("{}-{}", convo_id, new_group_id)` (mirrored convention) |
| `RecordResetVote` quorum, `TriggerSystemReset` sweep | **NOT applicable** — these go via legacy `do_reset_group`, not the chokepoint |

### Replay semantics

- **Identical key, exact replay**: chokepoint returns the cached `delivery_event` from the original tx. State is unchanged. For `ActivateCryptoSession`, the result discriminant is `CachedReplay` (not `Won`), and the actor handler returns the cached session **without re-emitting SSE or resetting in-memory actor state** (bug_016 fix).
- **Distinct key, same logical operation**: produces a new event. May or may not have effect depending on session state — see the expected_new_mls_group_id matrix.

## Expected group ID binding (bug_010)

When a session is in `reset_requested`, the binding `expected_new_mls_group_id` recorded in the request event's `payload_json` constrains which group_id can activate. The transition matrix at the request step:

| Existing payload | New Request payload | Result |
|---|---|---|
| `NULL` | `NULL` | no-op (both placeholders) |
| `NULL` | `Some(X)` | upgrade — new binding becomes `X` |
| `Some(X)` | `Some(X)` | idempotent no-op |
| `Some(X)` | `Some(Y)`, X≠Y | **REJECT** at request-time with typed error |
| `Some(X)` | `NULL` | no-op (NULL doesn't weaken existing binding) |

At activation:

- Load the request event that transitioned the prior session into `reset_requested`.
- If `expected_new_mls_group_id` is `Some(X)` and the activator's `new_mls_group_id` ≠ X → **reject** with the same typed error. Maps to 409 `AlreadyBootstrapped` on the wire (Phase 2.5 cleanup target: dedicated error variant).
- If `Some(X)` and equal → proceed.
- If `NULL` → no constraint; any `new_mls_group_id` allowed. **No current caller produces NULL Requests via the chokepoint.** This branch is reserved for post-#12 elected-client-flow, where quorum/sweep emit Requests without pre-claiming a target.

## Epoch semantics

> **Architectural fork**: server holds *observable* epoch only. The actual MLS group epoch is a client-owned counter.

| Field | Authoritative writer | Read by |
|---|---|---|
| `conversations.current_epoch` | `try_advance_conversation_epoch_tx` (in `db.rs`) on every accepted commit | live request paths: `send_message`, `get_messages`, `request_failover`, `commit_group_change` |
| `crypto_sessions.last_observed_epoch` | `RequestCryptoSessionReset`/`ActivateCryptoSession` only | chokepoint internal logic + repository abstractions |

The two are **deliberately not yet synchronized**. `try_advance_conversation_epoch_tx` writes only to the legacy column. The crypto_session value reflects "what the server saw at session boundary" and is rarely read by live request paths.

This is a known transitional state, marked `TODO(phase 4)` at the affected sites. Phase 4's actor split is the natural place to add the dual-write or migrate live reads. **Until then, the live request path's epoch is correct via the legacy column; only the crypto_session projection is stale.**

### Bootstrap shim (`BOOTSTRAP_WIRE_COMPAT_EPOCH`)

`bootstrap_reset_group` returns `BootstrapResetGroupOutput.convo.epoch = 1` to callers, while internal `crypto_sessions.last_observed_epoch = 0`. Marked `TODO(phase-2.5-cleanup)` with explicit deletion criterion: remove when activation processes the bootstrap commit in-tx and advances `last_observed_epoch` from 0 to 1 atomically with crypto_session creation.

## Welcome behavior

| Surface | Storage |
|---|---|
| New writes (chokepoint Activate) | `pending_welcomes` keyed by `(crypto_session_id, generation, recipient_did, recipient_device_id, key_package_hash)`. Bulk-inserted in the activation tx. |
| Legacy reads (`getGroupState(includes=welcome)`) | `welcome_messages` (legacy table). Activation handler **dual-writes** for backwards compatibility. |
| Loser welcomes | Never written. Loser path returns `ActivationResult::Lost` before reaching the welcome-insert step. |
| Drop criterion (`TODO(phase-2.5-cleanup)`) | Stop the legacy welcome_messages dual-write once all clients consume from `pending_welcomes`. |

## Rollback behavior

- **Activation tx fails (any reason)**: prior session state is preserved. The caller can retry — the prior `reset_requested` state remains and no orphan `crypto_sessions` row is created.
- **Bootstrap structural fix**: bootstrap is a *pure activator*; it does NOT issue its own `RequestCryptoSessionReset`. Therefore a failed bootstrap doesn't add new state. The upstream Request's `reset_requested` state stays intact for the next caller's retry.
- **Tie-break loss (SAVEPOINT pattern)**: the candidate INSERT runs inside a `SAVEPOINT`. On any unique-violation (`SQLSTATE 23505` for any of `(conversation_id, generation)`, `mls_group_id`, or the partial active-session index), the SAVEPOINT is rolled back, the outer tx continues, the loser audit event is appended with `crypto_session_id = NULL`, and the handler returns `ActivationResult::Lost`. Other 23505-class errors propagate after savepoint cleanup.
- **Replay during stale state**: handled by `CachedReplay` (bug_016). If a retry's idempotency key hits while the session has moved on (now superseded by a newer activation), the cached result is returned without re-emitting SSE or actor state changes.

## Invariants the chokepoint MUST maintain

These are the load-bearing properties; if any of them is violated by a code change, the change is broken:

1. **At most one `state='active'` row per conversation**. Enforced by the partial unique index `idx_crypto_sessions_one_active_per_convo`.
2. **Generation is strictly increasing per conversation**. Enforced by `UNIQUE (conversation_id, generation)` and chokepoint's `generation = prev + 1`.
3. **Every `mls_group_id` is unique globally** (across all conversations and all generations). Enforced by table-level UNIQUE.
4. **Every active session has an entry on `conversations.active_crypto_session_id`**, and that pointer matches the active row's id. Read paths fall back to legacy columns only if the pointer is NULL (compat window).
5. **`reset_requested` → `active` transition is atomic** (single tx): old session marked superseded + new session inserted active + delivery_events appended + `conversations.active_crypto_session_id` updated + legacy MLS columns mirrored. Either all happen or none.
6. **`expected_new_mls_group_id` is binding once recorded** (non-NULL): subsequent activations must match, subsequent Requests with a different non-NULL expected are rejected at request-time.
7. **Idempotent retries return cached results without state mutation** (`CachedReplay` for activation, plain dedupe for Request).
8. **Tie-break losers leave no `crypto_sessions` row** but DO leave a `crypto_session_candidate_rejected` delivery event with `crypto_session_id = NULL`.
9. **Legacy column sync inside `ActivateCryptoSession` is the ONLY allowed write to `conversations.{group_id, current_epoch, group_info, group_info_epoch, group_info_updated_at, confirmation_tag, reset_count}`** in chokepoint-funneled paths. Indirect callers (`do_reset_group` quorum/sweep) still write directly per `TODO(post-#12)`.
10. **`pending_welcomes` rows are never inserted for losing candidates** (bound to a `failed`-state crypto_session). The implicit-control-flow guarantee: losers bail out before the welcome-insert step.

## Known gaps / attack surface

Reviewed for: ways an active member, retry, race, stale request, or bootstrap call could create wrong active session, orphan state, stale epoch, or unauthorized group_id. Findings:

### Open (intentional, deferred)

- **Sessions stuck in `reset_requested` with no activator**: no TTL on Request → if no client ever submits material via bootstrap, the session sits in `reset_requested` indefinitely. Workaround: admin can issue a new `reset_group` with material to override (transitions through the activate path). **Risk profile**: minor — admin reset is the only caller producing non-paired Requests today, and admins typically pair them with a follow-up. Phase 2.5 should consider an automatic timeout-and-rollback or a "cancel pending reset" admin operation.
- **NULL `expected_new_mls_group_id` is permissive**: at activation, NULL means "any group_id is allowed." No caller currently produces NULL Requests via the chokepoint, so this is unreachable. Reserved for post-#12 elected-client flow. **If any future caller emits NULL by accident, an attacker could race-bootstrap with their own group_id.** Mitigation when post-#12 lands: add an explicit "allowed callers for NULL Request" assertion at request creation.
- **Stale `last_observed_epoch`**: not synchronized with `try_advance_conversation_epoch_tx`. Live request paths read from legacy `conversations.current_epoch` so they're correct; only the crypto_session projection is stale. **Phase 4** dual-write is the natural fix.
- **Legacy `do_reset_group` (quorum/sweep)** doesn't go through the chokepoint, so its rotations don't update `crypto_sessions`. The active session row stays at its pre-rotation generation while `conversations.group_id` rotates. **Reads via the chokepoint return stale data after a quorum reset until that conversation is rebootstrapped via the chokepoint.** This is the post-#12 funneling work.

### Closed (verified)

- **Active member creates wrong active session**: bug_010 closes this. Bootstrap requires `reset_requested` precondition AND `new_mls_group_id` matches `expected`. Member cannot bootstrap to an arbitrary group_id.
- **Multiple admins racing reset_group with different group_ids**: at the request step, the transition matrix rejects `existing Some(X) + new Some(Y), X≠Y`. First-claim-wins.
- **Multiple bootstrappers racing**: the SAVEPOINT pattern catches all three unique-violation cases (conversation_id+generation, mls_group_id, partial active-session index). Exactly one winner.
- **Retry storms inflating generations** (bug_015): admin reset_group now uses deterministic idempotency keys. Retries converge.
- **Stale activation replay clobbering current state** (bug_016): `CachedReplay` returns cached without side effects. Retry after supersession is a no-op for actor / SSE.
- **Tie-break loser FK violation** (merged_bug_004): loser path doesn't write a `crypto_sessions` row, so no FK to violate. Audit event has `crypto_session_id = NULL`.
- **Bootstrap auth bypass** (Codex P1, bug_010): now closes both halves — state precondition AND group_id binding.
- **Orphan rows on every successful reset** (bug_002): supersede WHERE filter now includes `reset_requested`. Each Request → Activate transitions the prior session out of `reset_requested` correctly.

### Unverified empirically (DB-gated; deferred to #11 acceptance tests)

- 5 distinct concurrent reset requests producing exactly one active session at the highest generation
- 5 duplicate reset requests with the same idempotency_key producing exactly one new session
- Welcomes for losing candidates being rejected/uninserted
- `expected_new_mls_group_id` mismatch at activation returning the typed error
- Idempotency key NULL-handling under the partial unique index

These are the cases #11 is designed to verify against a real Postgres. The chokepoint logic is correct against the type-surface tests but a full e2e against the actual DB constraint behavior is the proof.

## Out of scope (separate plans)

- **Post-#12 elected-client flow**: how clients learn to respond to `state='reset_requested'` events. SSE broadcast + tie-break by UNIQUE constraint is the chosen design (resolved task #12); per-platform client implementation pending.
- **Phase 4 actor split**: ConversationCoordinatorActor + DeliverySequencerActor. Includes the `last_observed_epoch` dual-write that closes the stale-projection gap.
- **Phase 2.5 cleanup**: bootstrap-commit-in-tx (drops `BOOTSTRAP_WIRE_COMPAT_EPOCH` shim), legacy `welcome_messages` dual-write removal, `do_reset_group` funneling once clients can respond.

## Document maintenance

This doc is the contract; if behavior changes, this doc changes first. PRs that modify chokepoint state machine logic without updating this doc are incomplete. Reviewers: pin the doc and check each invariant against the diff.
