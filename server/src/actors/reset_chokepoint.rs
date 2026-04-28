//! Phase 2 §2.2 — two-phase crypto session reset transactional core.
//!
//! Free functions operating on `&mut Transaction<'_, Postgres>` so callers
//! can compose the reset steps atomically. Pattern mirrors `db.rs:196,235`.
//!
//! # Why free functions vs trait methods
//!
//! The repository traits (`CryptoSessionRepository`, `DeliveryLogRepository`)
//! expose single-shot operations against a connection pool. The reset
//! handlers need to compose 5+ DB operations atomically — idempotency check,
//! tie-break INSERT, supersede UPDATE, multiple delivery_event APPENDs,
//! UPDATE conversations.{legacy MLS columns}, INSERT pending_welcomes — all
//! under the same `BEGIN/COMMIT`. Putting this in free functions taking a
//! borrowed transaction keeps the trait surface minimal (still useful for
//! the read paths and future fake-based actor tests) while letting handlers
//! compose without async-trait lifetime gymnastics.
//!
//! # Idempotency
//!
//! Both `request_crypto_session_reset_tx` and `activate_crypto_session_tx`
//! dedupe on `(conversation_id, sender_did, idempotency_key)` against
//! `delivery_events` — duplicate retries return the same outcome.
//!
//! # Tie-break (activation)
//!
//! `crypto_sessions UNIQUE (conversation_id, generation)` is the
//! serialization point. `INSERT ... ON CONFLICT DO NOTHING` with a
//! post-INSERT row count check distinguishes winners from losers.
//! Losers get a `crypto_session_candidate_rejected` delivery_event
//! (with `crypto_session_id=NULL`; correlation to the winner is via
//! `(conversation_id, generation, state='active')`) and an error
//! returned to the caller; their welcomes are NOT stored. We
//! deliberately do NOT INSERT a parallel `failed` crypto_sessions row
//! because the loser proposed an `mls_group_id` the winner already
//! owns — colliding on that UNIQUE would either need a synthetic id
//! (polluting the address space) or accept a stale `failed_id` that
//! breaks the delivery_events FK.
//!
//! # Compatibility-window legacy column sync
//!
//! `activate_crypto_session_tx` is the ONLY site outside the chokepoint
//! that writes to `conversations.{group_id, current_epoch, group_info,
//! group_info_epoch, group_info_updated_at, confirmation_tag, reset_count}`
//! during the compat window. Once all clients adopt
//! `active_crypto_session_id` and the cleanup migration drops these
//! columns, this UPDATE goes away.

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::models::CryptoSession;

/// Row shape for `crypto_sessions` SELECT queries in this module.
///
/// Switched from a 16-tuple `query_as::<_, (T0, T1, ..., T15)>` form to a
/// derived FromRow struct: the tuple form is at sqlx's hard limit of 16
/// columns, so adding any new column to `crypto_sessions` would require
/// either truncating the SELECT (data loss) or hitting a compile error
/// against an unimplemented FromRow trait. The struct form scales
/// indefinitely.
#[derive(FromRow)]
struct CryptoSessionRow {
    id: String,
    conversation_id: String,
    generation: i32,
    mls_group_id: String,
    state: String,
    supersedes_id: Option<String>,
    cipher_suite: Option<String>,
    last_observed_epoch: i32,
    last_confirmation_tag: Option<Vec<u8>>,
    group_info: Option<Vec<u8>>,
    group_info_epoch: Option<i32>,
    group_info_updated_at: Option<DateTime<Utc>>,
    created_by_did: Option<String>,
    created_at: DateTime<Utc>,
    activated_at: Option<DateTime<Utc>>,
    superseded_at: Option<DateTime<Utc>>,
}

impl From<CryptoSessionRow> for CryptoSession {
    fn from(r: CryptoSessionRow) -> Self {
        CryptoSession {
            id: r.id,
            conversation_id: r.conversation_id,
            generation: r.generation,
            mls_group_id: r.mls_group_id,
            state: r.state,
            supersedes_id: r.supersedes_id,
            cipher_suite: r.cipher_suite,
            last_observed_epoch: r.last_observed_epoch,
            last_confirmation_tag: r.last_confirmation_tag,
            group_info: r.group_info,
            group_info_epoch: r.group_info_epoch,
            group_info_updated_at: r.group_info_updated_at,
            created_by_did: r.created_by_did,
            created_at: r.created_at,
            activated_at: r.activated_at,
            superseded_at: r.superseded_at,
        }
    }
}

/// Canonical SELECT column list for `CryptoSessionRow`. Order MUST match
/// the FromRow struct field order.
const SELECT_CRYPTO_SESSION_COLS_FOR_TX: &str =
    "id, conversation_id, generation, mls_group_id, state, supersedes_id, \
     cipher_suite, last_observed_epoch, last_confirmation_tag, group_info, \
     group_info_epoch, group_info_updated_at, created_by_did, created_at, \
     activated_at, superseded_at";

use super::messages::{ResetRequest, ResetTrigger, WelcomeEnvelope};

/// Outcome of [`request_crypto_session_reset_tx`].
///
/// Carries both the [`ResetRequest`] handed back to direct callers AND
/// the chokepoint-internal metadata that the indirect-trigger
/// `dual_emit_reset_requested` path needs to populate the SSE event
/// payload without re-querying the database.
///
/// Phase 2.5 review-fix G3 — eliminates the two post-commit DB
/// round-trips (`session_info` + `request_event_id`) the helper was
/// previously doing in `conversation.rs::dual_emit_reset_requested`.
/// All four fields are populated from values the chokepoint already
/// holds in-tx, regardless of which exit path runs (idempotent replay,
/// no-op `(Some, None)` short-circuit, or the new-Request happy path).
#[derive(Debug)]
pub(crate) struct ResetRequestOutcome {
    /// Caller-facing reset request descriptor.
    pub request: ResetRequest,
    /// Id of the prior `crypto_sessions` row (state was `active` or
    /// `reset_requested`). For SSE: this is the session that just
    /// transitioned (or remained) in `reset_requested`; clients use it
    /// to pin the event to a specific generation.
    pub crypto_session_id: String,
    /// Generation of `crypto_session_id`. Same value the SSE listener
    /// surfaces.
    pub generation: i32,
    /// Id of the `delivery_events` row that records this Request. For
    /// SSE: the `request_event_id` field of the broadcast event so
    /// clients can correlate to the persisted audit row.
    pub request_event_id: String,
}

/// Outcome of [`activate_crypto_session_tx`].
///
/// On success, holds the activated session and the SSE-relevant fields the
/// caller will use to emit `GroupResetEvent` after committing the tx.
#[derive(Debug)]
pub(crate) struct ActivationOutcome {
    pub session: CryptoSession,
    pub generation: i32,
    pub cipher_suite: Option<String>,
}

/// Result of [`activate_crypto_session_tx`]. All variants are committed
/// — the loser variant intentionally persists the
/// `crypto_session_candidate_rejected` delivery_event for audit trail.
/// Caller decides how to surface `Lost` to its caller (typically as an
/// error at the actor message boundary).
#[derive(Debug)]
pub(crate) enum ActivationResult {
    /// Candidate won the tie-break THIS tx and was activated. Caller MUST
    /// run post-commit side effects (in-memory state reset, SSE emission).
    Won(ActivationOutcome),
    /// Idempotent replay: this idempotency_key already won in a prior tx.
    /// The session is fully persisted; caller MUST NOT re-emit SSE or
    /// re-clobber actor in-memory state. The session may even be
    /// `superseded` by a later activation — the replay path doesn't
    /// distinguish "current winner" from "former winner."
    ///
    /// bug_016 (ultrareview): the prior code returned `Won` for both
    /// fresh activations and replays, which let stale retries re-emit
    /// SSE GroupResetEvent and reset the actor's `current_epoch` after a
    /// later commit had already advanced it.
    CachedReplay(ActivationOutcome),
    /// Candidate lost the tie-break. Audit row persisted in tx; caller
    /// MUST still commit so the audit trail survives.
    Lost {
        attempted_generation: i32,
        proposed_mls_group_id: String,
    },
}

/// Read the latest non-superseded crypto_session for a conversation, with
/// a row lock. Accepts `'active'`, `'reset_requested'`, or `'superseding'`
/// — the request-reset and activate paths both need to find the
/// "current generation" row even when reset has already been requested
/// (idempotent re-request) or activation is mid-flight (concurrent
/// candidate observation).
async fn read_current_session_for_update(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: &str,
) -> Result<Option<CryptoSession>> {
    let row: Option<CryptoSessionRow> = sqlx::query_as(&format!(
        "SELECT {SELECT_CRYPTO_SESSION_COLS_FOR_TX} \
         FROM crypto_sessions \
         WHERE conversation_id = $1 \
           AND state IN ('active', 'reset_requested', 'superseding') \
         ORDER BY generation DESC \
         LIMIT 1 \
         FOR UPDATE"
    ))
    .bind(conversation_id)
    .fetch_optional(&mut **tx)
    .await
    .context("read_current_session_for_update")?;

    Ok(row.map(CryptoSession::from))
}

/// Look up an existing delivery_event by idempotency tuple. Used by both
/// handler entry paths to short-circuit retries.
///
/// **UNIQUE-mirroring**: the chokepoint inserts events via [`insert_event`]
/// which leaves `sender_device_id` NULL. The `delivery_events` UNIQUE
/// constraint covers `(conversation_id, sender_did, sender_device_id,
/// idempotency_key)`, so this filter must explicitly match NULL device_id
/// — otherwise a row inserted by another path with the same idempotency
/// key but a non-NULL device_id would false-positive here.
async fn find_existing_event(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: &str,
    sender_did: &str,
    idempotency_key: &str,
    expected_event_type: &str,
) -> Result<Option<(String, Option<serde_json::Value>, Option<String>)>> {
    let row: Option<(String, Option<serde_json::Value>, Option<String>)> = sqlx::query_as(
        "SELECT id, payload_json, crypto_session_id FROM delivery_events \
         WHERE conversation_id = $1 \
           AND sender_did IS NOT DISTINCT FROM $2 \
           AND sender_device_id IS NULL \
           AND idempotency_key = $3 \
           AND event_type = $4",
    )
    .bind(conversation_id)
    .bind(sender_did)
    .bind(idempotency_key)
    .bind(expected_event_type)
    .fetch_optional(&mut **tx)
    .await
    .context("find_existing_event")?;

    Ok(row)
}

/// Allocate the next per-conversation `seq` under a transaction-scoped
/// advisory lock so concurrent appends to the same conversation cannot race.
///
/// Lock-key derivation: `hashtextextended(conversation_id, 0)` returns a
/// signed 64-bit hash, used directly with the single-arg
/// `pg_advisory_xact_lock(int8)`. The earlier 32-bit `hashtext()` form
/// raised collision risk because the per-conversation key space was only
/// ~4B; the 64-bit form has effectively no collision concern at our scale.
async fn allocate_seq(tx: &mut Transaction<'_, Postgres>, conversation_id: &str) -> Result<i64> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(conversation_id)
        .execute(&mut **tx)
        .await
        .context("advisory lock")?;

    let seq: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq), -1) + 1 FROM delivery_events WHERE conversation_id = $1",
    )
    .bind(conversation_id)
    .fetch_one(&mut **tx)
    .await
    .context("max(seq)")?;

    Ok(seq)
}

/// Insert one delivery_event under an already-allocated seq.
#[allow(clippy::too_many_arguments)]
async fn insert_event(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: &str,
    seq: i64,
    crypto_session_id: Option<&str>,
    event_type: &str,
    sender_did: Option<&str>,
    mls_group_id: Option<&str>,
    idempotency_key: Option<&str>,
    payload_json: serde_json::Value,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO delivery_events ( \
            id, conversation_id, seq, crypto_session_id, event_type, \
            sender_did, mls_group_id, idempotency_key, payload_json \
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(&id)
    .bind(conversation_id)
    .bind(seq)
    .bind(crypto_session_id)
    .bind(event_type)
    .bind(sender_did)
    .bind(mls_group_id)
    .bind(idempotency_key)
    .bind(&payload_json)
    .execute(&mut **tx)
    .await
    .context("insert delivery_event")?;
    Ok(id)
}

/// Phase 3 — write durable outbox rows for fanout in the SAME tx as the
/// originating `delivery_events` INSERT.
///
/// One `notification_outbox` row is inserted per active member (the
/// in-memory `side_effect_tx` channel was lost on SIGKILL between
/// commit and broadcast; durable rows survive). One `federation_outbox`
/// row is inserted per distinct peer service DID (members.ds_did) for
/// federated conversations; non-federated conversations produce zero.
///
/// Returns `(notification_count, federation_count)` for logging.
///
/// `event_payload_json` is the JSON serialized representation of the
/// event payload — embedded in `notification_outbox.payload` so the
/// worker can replay without a delivery_events join. Federation rows
/// store the same payload by default.
async fn enqueue_outbox_for_event(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: &str,
    delivery_event_id: &str,
    event_payload_json: &serde_json::Value,
) -> Result<(usize, usize)> {
    // 1. Look up active members. Same query shape as the chokepoint's
    //    `allowed_responders` snapshot, but we keep both `member_did`
    //    (per-device) for SSE/push targeting AND `ds_did` (federation
    //    routing peer; NULL for local).
    //
    // member_did is the SSE subscription key (per-device). ds_did is
    // the federation peer DID; NULL means the recipient lives on this
    // local DS (no federation row needed).
    let members: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT member_did, COALESCE(user_did, member_did) AS user_or_member_did, ds_did \
         FROM members \
         WHERE convo_id = $1 AND left_at IS NULL",
    )
    .bind(conversation_id)
    .fetch_all(&mut **tx)
    .await
    .context("snapshot active members for outbox enqueue")?;

    // Serialize once; the JSON column accepts a binary blob via BYTEA.
    let payload_bytes =
        serde_json::to_vec(event_payload_json).context("serialize event payload for outbox")?;

    // 2. Notification rows — one per active member device. `kind='sse'`
    //    is the only currently-wired channel (push/websocket are
    //    follow-ups).
    if !members.is_empty() {
        let mut qb = sqlx::QueryBuilder::<Postgres>::new(
            "INSERT INTO notification_outbox (\
                id, conversation_id, delivery_event_id, recipient_did, \
                recipient_device_id, kind, payload, status \
             ) ",
        );
        qb.push_values(members.iter(), |mut b, (member_did, _user_did, _ds_did)| {
            b.push_bind(Uuid::new_v4().to_string())
                .push_bind(conversation_id)
                .push_bind(delivery_event_id)
                .push_bind(member_did)
                .push_bind(Option::<String>::None)
                .push_bind("sse")
                .push_bind(&payload_bytes)
                .push_bind("pending");
        });
        qb.build()
            .execute(&mut **tx)
            .await
            .context("bulk INSERT notification_outbox")?;
    }

    // 3. Federation rows — one per DISTINCT non-local peer DS DID. A
    //    non-federated conversation has all members with
    //    `ds_did IS NULL`; in that case we insert zero rows.
    let federation_targets: std::collections::BTreeSet<String> = members
        .iter()
        .filter_map(|(_member_did, _user_did, ds_did)| ds_did.clone())
        .collect();

    if !federation_targets.is_empty() {
        let mut qb = sqlx::QueryBuilder::<Postgres>::new(
            "INSERT INTO federation_outbox (\
                id, conversation_id, delivery_event_id, target_service_did, \
                payload, status \
             ) ",
        );
        qb.push_values(federation_targets.iter(), |mut b, target_did| {
            b.push_bind(Uuid::new_v4().to_string())
                .push_bind(conversation_id)
                .push_bind(delivery_event_id)
                .push_bind(target_did)
                .push_bind(&payload_bytes)
                .push_bind("pending");
        });
        qb.build()
            .execute(&mut **tx)
            .await
            .context("bulk INSERT federation_outbox")?;
    }

    Ok((members.len(), federation_targets.len()))
}

/// Phase 2 §2.2 — handle `RequestCryptoSessionReset` inside an open tx.
///
/// Idempotent on `idempotency_key`. Steps:
///
/// 0. **Phase 2.5 §7 R1 Mitigation #1**: enforce the caller allowlist
///    for NULL-binding Requests. When `expected_new_mls_group_id IS
///    None`, the trigger MUST be one of `QuorumVote | SystemSweep |
///    InlineCommit409 | InlineGroupInfo404`. `Admin` and `Bootstrap`
///    are rejected with an error. This is the load-bearing gate that
///    prevents a future caller (or a bug) from emitting an unbound
///    Request that any member could race-bootstrap into.
/// 1. If a `crypto_session_reset_requested` event with this idempotency_key
///    already exists, reconstruct and return the existing
///    `ResetRequestOutcome` (idempotent replay).
/// 2. If the session is already in `reset_requested`, apply the
///    `expected_new_mls_group_id` transition matrix (bug_010). Reject
///    with an error if a prior request bound a different group id, or
///    SHORT-CIRCUIT and reuse the prior event when the new Request
///    weakens the binding (review-fix A1; see matrix below).
/// 3. UPDATE the active crypto_session to `state = 'reset_requested'`
///    (no-op if already in `reset_requested` or `superseding`).
/// 4. **Phase 2.5 §7 R1 Mitigation #3**: snapshot the active member
///    DID list into `payload_json.allowed_responders`. This is keyed
///    off membership at Request time; activations later check the
///    activator's DID is in this snapshot. Membership changes between
///    Request and Activate do NOT alter the allowlist.
/// 5. APPEND a `crypto_session_reset_requested` event referencing the
///    active session, with `payload_json` containing the request body,
///    the freshly-allocated `request_id`, the (optional)
///    `expected_new_mls_group_id` binding for activation-time
///    enforcement, and the `allowed_responders` snapshot.
///
/// # Returns
///
/// A [`ResetRequestOutcome`] populated from in-tx values. Carries the
/// caller-facing `ResetRequest` plus chokepoint metadata
/// (`crypto_session_id`, `generation`, `request_event_id`) the
/// `dual_emit_reset_requested` indirect-trigger path needs for its SSE
/// payload (review-fix G3 — eliminates two post-commit DB
/// round-trips).
pub(crate) async fn request_crypto_session_reset_tx(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: &str,
    trigger: ResetTrigger,
    initiator_did: &str,
    reason: &str,
    idempotency_key: &str,
    expected_new_mls_group_id: Option<&str>,
) -> Result<ResetRequestOutcome> {
    // Phase 2.5 §7 R1 Mitigation #1: caller allowlist for NULL-binding
    // Requests. This is the FIRST check — even before idempotency
    // lookup — so a forbidden trigger never reaches the persistence
    // layer. The check returns a typed Err; we deliberately do NOT
    // debug_assert! here because (a) the error path is itself the test
    // surface, and (b) a panic would crash the actor and drop the
    // reply oneshot channel, surfacing as RecvError to the caller
    // instead of the typed rejection clients should observe.
    if expected_new_mls_group_id.is_none() && !trigger.permits_null_binding() {
        return Err(anyhow!(
            "Phase 2.5 R1 mitigation #1: trigger `{}` may not emit a \
             RequestCryptoSessionReset with expected_new_mls_group_id = None. \
             Direct callers (Admin, Bootstrap) must always supply Some(_); \
             only indirect triggers (QuorumVote, SystemSweep, \
             InlineCommit409, InlineGroupInfo404) may pass None.",
            trigger.as_str()
        ));
    }
    // Idempotent replay: a prior call from this caller with the same
    // idempotency_key resolves to the same ResetRequestOutcome. The
    // transition matrix below only applies to NEW Requests (different
    // idempotency_key) on a session already in `reset_requested`.
    if let Some((event_id, payload_json, cs_id)) = find_existing_event(
        tx,
        conversation_id,
        initiator_did,
        idempotency_key,
        "crypto_session_reset_requested",
    )
    .await?
    {
        let request_id = payload_json
            .as_ref()
            .and_then(|p| p.get("request_id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("existing reset_requested event missing request_id"))?
            .to_string();
        let cs_id = cs_id.ok_or_else(|| {
            anyhow!("existing crypto_session_reset_requested event missing crypto_session_id")
        })?;
        let generation: i32 =
            sqlx::query_scalar("SELECT generation FROM crypto_sessions WHERE id = $1")
                .bind(&cs_id)
                .fetch_one(&mut **tx)
                .await
                .context("read crypto_sessions.generation for idempotent replay outcome")?;
        return Ok(ResetRequestOutcome {
            request: ResetRequest {
                request_id,
                conversation_id: conversation_id.to_string(),
                initiator_did: initiator_did.to_string(),
                reason: reason.to_string(),
            },
            crypto_session_id: cs_id,
            generation,
            request_event_id: event_id,
        });
    }

    let current = read_current_session_for_update(tx, conversation_id)
        .await?
        .ok_or_else(|| anyhow!("no non-superseded crypto_session for {conversation_id}"))?;

    // bug_010 (ultrareview): expected_new_mls_group_id transition matrix
    // when the session is already in `reset_requested`. Look at the most
    // recent crypto_session_reset_requested event for this session and
    // apply:
    //   existing NULL + new NULL          → no-op (idempotent re-request)
    //   existing NULL + new Some(X)       → upgrade the binding
    //   existing Some(X) + new Some(X)    → no-op (same target re-claim)
    //   existing Some(X) + new Some(Y), X≠Y → REJECT (conflicting claim)
    //   existing Some(X) + new NULL       → no-op (NULL doesn't weaken)
    //
    // Phase 2.5 review-fix A1 (advisor-flagged exploit path): the
    // `(Some(X), None)` case previously fell through to the catch-all
    // and a NEW `crypto_session_reset_requested` event was written with
    // `payload_json.expected_new_mls_group_id = null`. The
    // activation-time auth then read `ORDER BY seq DESC LIMIT 1` —
    // most-recent-wins — and the prior `Some(X)` binding was silently
    // downgraded to NULL, letting any current member race-bootstrap
    // with attacker-controlled `Y` instead of admin's `X`.
    //
    // The doc above already says "no-op (NULL doesn't weaken)"; we now
    // ENFORCE that by short-circuiting and returning the existing
    // event's outcome (mirrors the idempotent-replay branch at
    // :339-360 above). No new event is written; the prior `Some(X)`
    // binding remains authoritative.
    if current.state == "reset_requested" {
        let existing_row: Option<(String, Option<String>, Option<serde_json::Value>)> =
            sqlx::query_as(
                "SELECT id, payload_json->>'expected_new_mls_group_id', payload_json \
                 FROM delivery_events \
                 WHERE conversation_id = $1 \
                   AND crypto_session_id = $2 \
                   AND event_type = 'crypto_session_reset_requested' \
                 ORDER BY seq DESC \
                 LIMIT 1",
            )
            .bind(conversation_id)
            .bind(&current.id)
            .fetch_optional(&mut **tx)
            .await
            .context("read prior reset_requested event for transition matrix")?;

        if let Some((prior_event_id, prior_expected, prior_payload)) = existing_row {
            match (prior_expected.as_deref(), expected_new_mls_group_id) {
                // existing Some(X) + new Some(Y), X≠Y → REJECT
                (Some(prior), Some(new)) if prior != new => {
                    return Err(anyhow!(
                        "expected_new_mls_group_id binding conflict: \
                         prior request claimed `{prior}`, new request claims `{new}`. \
                         The earlier admin's claim is binding until activation \
                         resolves; either submit material matching the prior \
                         claim or wait for the prior request to time out."
                    ));
                }
                // existing Some(X) + new None → no-op (NULL doesn't weaken).
                // Phase 2.5 review-fix A1: short-circuit so the existing
                // bound event remains the most-recent row in the audit
                // log. Reconstruct the outcome from event 1 — same shape
                // as idempotent-replay, just keyed off seq instead of
                // idempotency_key.
                (Some(_prior), None) => {
                    let prior_request_id = prior_payload
                        .as_ref()
                        .and_then(|p| p.get("request_id"))
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            anyhow!(
                                "prior crypto_session_reset_requested event \
                                 missing request_id; cannot reconstruct outcome \
                                 for A1 (Some, None) short-circuit"
                            )
                        })?
                        .to_string();
                    return Ok(ResetRequestOutcome {
                        request: ResetRequest {
                            request_id: prior_request_id,
                            conversation_id: conversation_id.to_string(),
                            initiator_did: initiator_did.to_string(),
                            reason: reason.to_string(),
                        },
                        crypto_session_id: current.id.clone(),
                        generation: current.generation,
                        request_event_id: prior_event_id,
                    });
                }
                // All other cases pass through; the existing event remains
                // authoritative on the binding (or NULL stays NULL via
                // the new event's matching NULL).
                _ => {}
            }
        }
    }

    // Idempotent state transition: only flip 'active' → 'reset_requested'.
    // If the row is already in 'reset_requested' or 'superseding', the
    // UPDATE matches zero rows; we still emit the event below so the
    // delivery_events log preserves both request idempotency_keys.
    sqlx::query(
        "UPDATE crypto_sessions \
         SET state = 'reset_requested' \
         WHERE id = $1 AND state = 'active'",
    )
    .bind(&current.id)
    .execute(&mut **tx)
    .await
    .context("mark current session reset_requested")?;

    // Phase 2.5 §7 R1 Mitigation #3: snapshot the active member DID
    // list. This is the load-bearing auth check for NULL-binding
    // Requests. The activation handler at `activate_crypto_session_tx`
    // reads this list and rejects activators not in it. Snapshotting
    // at Request time (rather than at activation) means a member who
    // leaves between Request and Activate cannot fraudulently bootstrap.
    //
    // We use `COALESCE(user_did, member_did)` to yield the IDENTITY
    // DID for multi-device clients (member_did may carry a per-device
    // DID like `did:plc:user#device-uuid`). The activator-side check
    // parses incoming `initiator_did` via `parse_device_did` to extract
    // the identity DID and matches against this list. This mirrors the
    // existing membership check pattern at
    // `bootstrap_reset_group.rs:142` and
    // `report_recovery_failure.rs:149-156`.
    let allowed_responders: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT COALESCE(user_did, member_did) \
         FROM members \
         WHERE convo_id = $1 AND left_at IS NULL",
    )
    .bind(conversation_id)
    .fetch_all(&mut **tx)
    .await
    .context("snapshot allowed_responders for crypto_session_reset_requested")?;

    let request_id = Uuid::new_v4().to_string();
    let payload = json!({
        "request_id": request_id,
        "trigger": trigger.as_str(),
        "reason": reason,
        "expected_new_mls_group_id": expected_new_mls_group_id,
        // Phase 2.5 §7 R1 Mitigation #3: snapshot of permitted
        // activators at Request time. Empty array would mean "no one
        // can activate" — caller paths that emit Requests on
        // memberless conversations should not exist in practice, but
        // the activation handler treats empty/missing as "reject all
        // NULL-binding activators" for defense-in-depth.
        "allowed_responders": allowed_responders,
    });

    let seq = allocate_seq(tx, conversation_id).await?;
    let request_event_id = insert_event(
        tx,
        conversation_id,
        seq,
        Some(&current.id),
        "crypto_session_reset_requested",
        Some(initiator_did),
        Some(&current.mls_group_id),
        Some(idempotency_key),
        payload.clone(),
    )
    .await?;

    // Phase 3 — durable outbox enqueue. Same Postgres tx as the
    // delivery_event INSERT above; rolled back as a unit if the outer tx
    // aborts. Workers drain these on the next tick (or after restart if
    // the server is SIGKILLed before the per-convo SSE broadcast fires).
    let (n_count, f_count) =
        enqueue_outbox_for_event(tx, conversation_id, &request_event_id, &payload)
            .await
            .context("enqueue outbox rows for crypto_session_reset_requested")?;
    tracing::debug!(
        conversation_id,
        event_id = %request_event_id,
        notification_rows = n_count,
        federation_rows = f_count,
        "outbox: enqueued for crypto_session_reset_requested"
    );

    Ok(ResetRequestOutcome {
        request: ResetRequest {
            request_id,
            conversation_id: conversation_id.to_string(),
            initiator_did: initiator_did.to_string(),
            reason: reason.to_string(),
        },
        crypto_session_id: current.id.clone(),
        generation: current.generation,
        request_event_id,
    })
}

/// Phase 2 §2.2 — handle `ActivateCryptoSession` inside an open tx.
///
/// # Steps
///
/// 1. **Idempotency**: if a `crypto_session_activated` event with this
///    `idempotency_key` already exists, fetch and return the corresponding
///    crypto_session (replay-safe).
/// 2. **Read prior active** under `FOR UPDATE` row lock; compute
///    `next_generation = prev.generation + 1`.
/// 3. **Tie-break INSERT** of the new candidate row with `state='active'`
///    using `ON CONFLICT (conversation_id, generation) DO NOTHING`. Zero
///    rows means another candidate won this generation; we INSERT a
///    `failed` row, append a `crypto_session_candidate_rejected` event,
///    and return error. Welcomes are NOT stored for losers.
/// 4. **UPDATE prior** to `state='superseded'`, set
///    `superseded_at`, `superseded_by_id`.
/// 5. **UPDATE conversations** with the new `active_crypto_session_id`
///    pointer AND the legacy MLS columns (compat-window sync — this is
///    the ONLY allowed write site to those columns).
/// 6. **APPEND `crypto_session_superseded` and `crypto_session_activated`**
///    events. Order matters: pending_welcomes FK on `commit_event_id`
///    references the activated event id.
/// 7. **INSERT pending_welcomes** keyed by the new crypto_session_id and
///    generation. Maps `WelcomeEnvelope.recipient_did` → DB column
///    `target_did`.
/// 8. **Clear stale reset/quorum state** (delete reset_votes,
///    pending_device_additions, welcome_messages tied to the prior session
///    — same housekeeping as legacy `do_reset_group`).
///
/// In-memory state updates and SSE emission happen in the *caller* after
/// `tx.commit()` succeeds.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn activate_crypto_session_tx(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: &str,
    reset_request_id: Option<&str>,
    trigger: ResetTrigger,
    new_mls_group_id: &str,
    new_group_info: Option<&[u8]>,
    welcomes: &[WelcomeEnvelope],
    initiator_did: &str,
    idempotency_key: &str,
) -> Result<ActivationResult> {
    // 1. Idempotency check on the activation event.
    if let Some((_event_id, _payload_json, cs_id)) = find_existing_event(
        tx,
        conversation_id,
        initiator_did,
        idempotency_key,
        "crypto_session_activated",
    )
    .await?
    {
        let cs_id = cs_id.ok_or_else(|| {
            anyhow!("existing crypto_session_activated event missing crypto_session_id")
        })?;
        let session = fetch_session_by_id(tx, &cs_id).await?.ok_or_else(|| {
            anyhow!("idempotent replay: crypto_session {cs_id} from prior tx not found")
        })?;
        let cipher_suite = session.cipher_suite.clone();
        let generation = session.generation;
        // bug_016 (ultrareview): mark this as a replay so the caller
        // skips post-commit side effects. The session may already have
        // been superseded by a later activation (a replay arriving after
        // the normal "won and superseded" sequence is legitimate but
        // its post-commit work would clobber the actor's current state).
        return Ok(ActivationResult::CachedReplay(ActivationOutcome {
            session,
            generation,
            cipher_suite,
        }));
    }

    // Idempotent replay of the loser path: a prior call with the same
    // idempotency_key was rejected. Return the same `Lost` outcome so the
    // caller's tx commits cleanly without re-INSERTing audit rows.
    if let Some((_event_id, payload_json, _cs_id)) = find_existing_event(
        tx,
        conversation_id,
        initiator_did,
        idempotency_key,
        "crypto_session_candidate_rejected",
    )
    .await?
    {
        let attempted_generation = payload_json
            .as_ref()
            .and_then(|p| p.get("winning_generation"))
            .and_then(|v| v.as_i64())
            .unwrap_or_default() as i32;
        let proposed_mls_group_id = payload_json
            .as_ref()
            .and_then(|p| p.get("proposed_mls_group_id"))
            .and_then(|v| v.as_str())
            .unwrap_or(new_mls_group_id)
            .to_string();
        return Ok(ActivationResult::Lost {
            attempted_generation,
            proposed_mls_group_id,
        });
    }

    // 2. Read latest non-superseded session under row lock. Accepts
    //    'active', 'reset_requested', or 'superseding' — the activate
    //    path always supersedes whatever is current.
    let prior = read_current_session_for_update(tx, conversation_id)
        .await?
        .ok_or_else(|| anyhow!("no current crypto_session for {conversation_id}"))?;

    // bug_010 (ultrareview): if the prior session is in `reset_requested`
    // and the upstream Request bound an `expected_new_mls_group_id`, the
    // activator's `new_mls_group_id` MUST match. This is the auth-bypass
    // gate Codex P1 had two parts of (state was the first; this is the
    // second).
    //
    // Phase 2.5 §7 R1 Mitigation #2 (activation-time auth): when
    // `expected_new_mls_group_id IS NULL` on the prior Request (i.e.
    // an indirect-trigger Request via QuorumVote / SystemSweep /
    // Inline*), the activator's DID MUST be in the
    // `payload_json.allowed_responders` snapshot taken at Request
    // time. This is the load-bearing R1 gate — without it, any
    // attacker who can submit `bootstrap_reset_group` could win the
    // tie-break for a NULL-binding Request and seize control of the
    // conversation.
    //
    // Both fields are read in a single SELECT so the snapshot is
    // atomic — there is no window where one half of the auth answer
    // is stale relative to the other.
    //
    // # Upstream active-membership audit (review-fix A2)
    //
    // The R1 #2 allowlist check below is downstream defense; the FIRST
    // line of defense is each `ConvoMessage::ActivateCryptoSession`
    // sender enforcing active-membership of the caller against
    // `members WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2)
    // AND left_at IS NULL`. Audit (Apr 2026):
    //
    //   - `handlers/mls_chat/bootstrap_reset_group.rs` (lines 142-172):
    //       enforces `is_member` via the canonical query above; returns
    //       403 NotMember if absent. ✓ GATED.
    //   - `handlers/mls_chat/reset_group.rs` (lines 112-128): enforces
    //       `is_admin` (a STRICTER variant of the membership check —
    //       admin implies an active row). ✓ GATED.
    //   - `actors/conversation.rs::dual_emit_reset_requested`: this
    //       sends `RequestCryptoSessionReset`, NOT `ActivateCryptoSession`,
    //       so the activation gate doesn't apply. The Request side has
    //       its own R1 #1 caller-allowlist (only the four indirect
    //       triggers; see `permits_null_binding`).
    //
    // No other call sites send `ActivateCryptoSession`. New senders
    // MUST add the active-membership gate before dispatching the
    // message — the chokepoint's R1 #2 allowlist alone is NOT
    // sufficient because it operates on the snapshot, not on the
    // current member roster. A grep for `ConvoMessage::ActivateCryptoSession`
    // outside this module is the correct verification surface.
    if prior.state == "reset_requested" {
        let request_payload: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT payload_json \
             FROM delivery_events \
             WHERE conversation_id = $1 \
               AND crypto_session_id = $2 \
               AND event_type = 'crypto_session_reset_requested' \
             ORDER BY seq DESC \
             LIMIT 1",
        )
        .bind(conversation_id)
        .bind(&prior.id)
        .fetch_optional(&mut **tx)
        .await
        .context("read prior reset_requested payload_json")?;

        let payload = request_payload.ok_or_else(|| {
            anyhow!(
                "prior session is `reset_requested` but no \
                 crypto_session_reset_requested event found for it; \
                 inconsistent state — cannot authorize activation."
            )
        })?;

        let bound: Option<&str> = payload
            .get("expected_new_mls_group_id")
            .and_then(|v| v.as_str());

        match bound {
            Some(bound) => {
                if bound != new_mls_group_id {
                    return Err(anyhow!(
                        "expected_new_mls_group_id mismatch: \
                         upstream Request bound `{bound}`, but activation \
                         submitted `{new_mls_group_id}`. The pre-bound claim \
                         from the original requester is authoritative; \
                         bootstrap with the matching mls_group_id or wait \
                         for the prior request to time out."
                    ));
                }
            }
            None => {
                // Phase 2.5 §7 R1 Mitigation #2: NULL binding requires
                // responder allowlist enforcement. Reject if the
                // allowlist is missing/empty (defense-in-depth: no
                // legitimate code path emits a NULL-binding Request
                // without the allowlist post-Phase-2.5 Stage 1).
                let allowed_responders: Vec<String> = payload
                    .get("allowed_responders")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();

                if allowed_responders.is_empty() {
                    return Err(anyhow!(
                        "Phase 2.5 R1 mitigation #2: NULL-binding \
                         Request has empty/missing allowed_responders — \
                         refusing activation. This indicates either a \
                         pre-Phase-2.5 Request (legacy NULL-binding \
                         emit, no allowlist) or a snapshot-time \
                         membership query that returned zero rows. In \
                         either case the activation cannot be \
                         authorized."
                    ));
                }

                // Resolve activator's identity DID. `initiator_did`
                // arrives as whatever the handler passed — for multi-
                // device clients this may be `did:plc:user#device-id`.
                // Extract the user-part to match against the
                // `COALESCE(user_did, member_did)` snapshot stored at
                // Request time.
                let activator_identity_did: String = match initiator_did.split_once('#') {
                    Some((user_part, _device_part)) if !user_part.is_empty() => {
                        user_part.to_string()
                    }
                    _ => initiator_did.to_string(),
                };

                // Accept either the parsed identity DID or the raw
                // initiator_did. The snapshot uses
                // `COALESCE(user_did, member_did)` which yields
                // identity DID for multi-device rows but for legacy
                // single-device rows where user_did IS NULL it yields
                // member_did (which IS the device DID).
                let allowed = allowed_responders
                    .iter()
                    .any(|d| d == &activator_identity_did || d == initiator_did);

                if !allowed {
                    return Err(anyhow!(
                        "Phase 2.5 R1 mitigation #2: activator DID \
                         `{}` (identity `{}`) is not in the \
                         allowed_responders snapshot for this NULL-\
                         binding Request. Refusing activation. The \
                         responder allowlist was snapshotted at \
                         Request time and does not include this DID; \
                         either you were not a member when the reset \
                         was requested, or you have left and rejoined \
                         since.",
                        initiator_did,
                        activator_identity_did
                    ));
                }
            }
        }
    }

    let next_generation = prior.generation + 1;
    let cipher_suite = prior.cipher_suite.clone();
    let new_session_id = Uuid::new_v4().to_string();

    // 3. Tie-break INSERT.
    //
    // merged_bug_004 (ultrareview): the crypto_sessions table has THREE
    // unique constraints that an activation INSERT can violate:
    //   (a) UNIQUE (conversation_id, generation) — the tie-break primary
    //   (b) UNIQUE (mls_group_id) — collides if another row owns the id
    //   (c) idx_crypto_sessions_one_active_per_convo partial index —
    //       collides if a state='active' row already exists for the convo
    //
    // The prior code used `ON CONFLICT (conversation_id, generation) DO
    // NOTHING` which only catches (a). (b) and (c) would raise SQLSTATE
    // 23505 and abort the whole tx.
    //
    // Solution: open a SAVEPOINT around the INSERT, attempt it without
    // any ON CONFLICT clause, and on 23505 ROLLBACK to the savepoint
    // before continuing the loser-path inserts. RELEASE the savepoint on
    // success. This treats all three unique-violations as Lost uniformly.
    sqlx::query("SAVEPOINT activate_insert")
        .execute(&mut **tx)
        .await
        .context("SAVEPOINT activate_insert")?;

    let insert_result: Result<(String,), sqlx::Error> = sqlx::query_as(
        "INSERT INTO crypto_sessions ( \
            id, conversation_id, generation, mls_group_id, state, supersedes_id, \
            cipher_suite, last_observed_epoch, group_info, group_info_epoch, \
            group_info_updated_at, created_by_did, created_at, activated_at \
         ) VALUES ($1, $2, $3, $4, 'active', $5, $6, 0, $7, \
                   CASE WHEN $7 IS NULL THEN NULL ELSE 0 END, \
                   CASE WHEN $7 IS NULL THEN NULL ELSE NOW() END, \
                   $8, NOW(), NOW()) \
         RETURNING id",
    )
    .bind(&new_session_id)
    .bind(conversation_id)
    .bind(next_generation)
    .bind(new_mls_group_id)
    .bind(&prior.id)
    .bind(&cipher_suite)
    .bind(new_group_info)
    .bind(initiator_did)
    .fetch_one(&mut **tx)
    .await;

    let inserted: Option<(String,)> = match insert_result {
        Ok(row) => {
            // Winner: release the savepoint to fold its writes into the
            // outer tx.
            sqlx::query("RELEASE SAVEPOINT activate_insert")
                .execute(&mut **tx)
                .await
                .context("RELEASE SAVEPOINT activate_insert")?;
            Some(row)
        }
        Err(sqlx::Error::Database(ref db_err)) if db_err.code().as_deref() == Some("23505") => {
            // Loser: roll back the failed INSERT so the outer tx can
            // continue with the candidate-rejected event APPEND below.
            sqlx::query("ROLLBACK TO SAVEPOINT activate_insert")
                .execute(&mut **tx)
                .await
                .context("ROLLBACK TO SAVEPOINT activate_insert")?;
            None
        }
        Err(e) => {
            // Non-unique-violation error: still need to rollback the
            // savepoint before the outer tx unwinds, but propagate the
            // error to the caller.
            let _ = sqlx::query("ROLLBACK TO SAVEPOINT activate_insert")
                .execute(&mut **tx)
                .await;
            return Err(anyhow!("INSERT new crypto_session: {e}"));
        }
    };

    if inserted.is_none() {
        // Tie-break loss: another candidate has already won this
        // generation (and owns `new_mls_group_id` at state='active' OR
        // owns the `(conversation_id, generation)` slot at any state).
        //
        // Audit-trail design: we do NOT INSERT a parallel `failed` row,
        // because doing so would either (a) collide on the
        // `mls_group_id UNIQUE` constraint (the winner already owns
        // that id; ON CONFLICT DO NOTHING leaves us with a non-existent
        // `failed_id` that the subsequent FK on delivery_events would
        // reject), or (b) require us to invent a different mls_group_id
        // for the loser, polluting the address space. Instead, we
        // append the `crypto_session_candidate_rejected` event with
        // `crypto_session_id = NULL` (the column is nullable). The
        // payload_json carries the proposed mls_group_id, the
        // attempted generation, and the trigger so audit-log readers
        // can correlate to the winner via `(conversation_id,
        // generation, state='active')`. Welcomes for losing candidates
        // are NOT stored.
        let payload = json!({
            "trigger": trigger.as_str(),
            "reason": "tie_break_loss",
            "proposed_mls_group_id": new_mls_group_id,
            "winning_generation": next_generation,
        });
        let seq = allocate_seq(tx, conversation_id).await?;
        insert_event(
            tx,
            conversation_id,
            seq,
            None, // no failed-row to FK to; correlate via payload_json
            "crypto_session_candidate_rejected",
            Some(initiator_did),
            Some(new_mls_group_id),
            Some(idempotency_key),
            payload,
        )
        .await?;

        // Audit event is persisted; caller commits the tx so the
        // tie-break loss survives. Caller decides how to surface to client
        // (typically as an error at the actor message boundary).
        return Ok(ActivationResult::Lost {
            attempted_generation: next_generation,
            proposed_mls_group_id: new_mls_group_id.to_string(),
        });
    }

    // 4. Mark prior session superseded.
    //
    // Bug 002 (ultrareview): include `reset_requested` in the valid prior
    // states. The Request → Activate happy path leaves the prior session
    // in `reset_requested` (set by `request_crypto_session_reset_tx`), so
    // the supersede UPDATE here MUST cover that state or the prior row
    // never transitions out and a row leaks per reset. The
    // `read_current_session_for_update` filter above already returns
    // rows in any of (active, reset_requested, superseding); the WHERE
    // here must mirror that set.
    sqlx::query(
        "UPDATE crypto_sessions \
         SET state = 'superseded', \
             superseded_at = NOW(), \
             superseded_by_id = $2 \
         WHERE id = $1 AND state IN ('active', 'reset_requested', 'superseding')",
    )
    .bind(&prior.id)
    .bind(&new_session_id)
    .execute(&mut **tx)
    .await
    .context("mark prior session superseded")?;

    // 5. UPDATE conversations: forward pointer + legacy MLS column sync.
    //    This is the only chokepoint allowed to write the legacy columns
    //    during the compatibility window per plan §2.3.
    sqlx::query(
        "UPDATE conversations SET \
            active_crypto_session_id = $1, \
            group_id = $2, \
            current_epoch = 0, \
            group_info = $3, \
            group_info_epoch = CASE WHEN $3 IS NULL THEN NULL ELSE 0 END, \
            group_info_updated_at = CASE WHEN $3 IS NULL THEN NULL ELSE NOW() END, \
            confirmation_tag = NULL, \
            reset_count = $4, \
            last_reset_at = NOW(), \
            last_reset_by = $5, \
            recent_commit_409_count = 0, \
            recent_groupinfo_404_count = 0, \
            updated_at = NOW() \
         WHERE id = $6",
    )
    .bind(&new_session_id)
    .bind(new_mls_group_id)
    .bind(new_group_info)
    .bind(next_generation)
    .bind(initiator_did)
    .bind(conversation_id)
    .execute(&mut **tx)
    .await
    .context("UPDATE conversations legacy column sync")?;

    // 6. APPEND superseded + activated events.
    //    Order: superseded first (just for clarity in the log), activated
    //    second — pending_welcomes.commit_event_id FK references the
    //    activated event so it MUST be inserted before pending_welcomes.
    let supersede_payload = json!({
        "trigger": trigger.as_str(),
        "old_session_id": prior.id,
        "old_generation": prior.generation,
        "new_session_id": new_session_id,
        "new_generation": next_generation,
    });
    let supersede_seq = allocate_seq(tx, conversation_id).await?;
    let supersede_event_id = insert_event(
        tx,
        conversation_id,
        supersede_seq,
        Some(&prior.id),
        "crypto_session_superseded",
        Some(initiator_did),
        Some(&prior.mls_group_id),
        None,
        supersede_payload.clone(),
    )
    .await?;

    let activated_payload = json!({
        "reset_request_id": reset_request_id,
        "trigger": trigger.as_str(),
        "new_mls_group_id": new_mls_group_id,
        "generation": next_generation,
        "supersedes_id": prior.id,
    });
    let activated_seq = allocate_seq(tx, conversation_id).await?;
    let activated_event_id = insert_event(
        tx,
        conversation_id,
        activated_seq,
        Some(&new_session_id),
        "crypto_session_activated",
        Some(initiator_did),
        Some(new_mls_group_id),
        Some(idempotency_key),
        activated_payload.clone(),
    )
    .await?;

    // Phase 3 — durable outbox enqueue for both the supersede AND
    // activated events. Same Postgres tx as the delivery_event INSERTs
    // above; rolled back as a unit if the outer tx aborts. Workers
    // drain these on the next tick (or after restart if the server is
    // SIGKILLed before the per-convo SSE broadcast fires).
    let (n_super, f_super) =
        enqueue_outbox_for_event(tx, conversation_id, &supersede_event_id, &supersede_payload)
            .await
            .context("enqueue outbox rows for crypto_session_superseded")?;
    let (n_act, f_act) =
        enqueue_outbox_for_event(tx, conversation_id, &activated_event_id, &activated_payload)
            .await
            .context("enqueue outbox rows for crypto_session_activated")?;
    tracing::debug!(
        conversation_id,
        supersede_event_id = %supersede_event_id,
        activated_event_id = %activated_event_id,
        notification_rows = n_super + n_act,
        federation_rows = f_super + f_act,
        "outbox: enqueued for crypto_session_superseded + crypto_session_activated"
    );

    // 7. INSERT pending_welcomes for the WINNING candidate. Map
    //    WelcomeEnvelope.recipient_did -> DB column target_did.
    //
    // Loser-path safety: the "this candidate is the active winner"
    // property is implicit in the control flow — losers return
    // `ActivationResult::Lost` at step 3 above and never reach this
    // block. No runtime `state = 'active'` guard is needed here, and
    // the absence of one saves a per-welcome SELECT.
    //
    // Bulk insert via QueryBuilder::push_values to send a single
    // multi-VALUES round-trip rather than N separate INSERTs. For typical
    // group sizes (10–50 members) this turns 50 round-trips into 1.
    if !welcomes.is_empty() {
        // bug_009 (ultrareview): bind WelcomeEnvelope.key_package_hash to
        // the new pending_welcomes.key_package_hash column. Previously
        // collected and silently discarded because no column existed —
        // currently masked by the legacy welcome_messages dual-write,
        // becomes data loss when that's dropped (TODO(phase-2.5-cleanup)
        // referenced by handler).
        let mut qb = sqlx::QueryBuilder::<Postgres>::new(
            "INSERT INTO pending_welcomes ( \
                id, convo_id, target_did, welcome_message, created_by_did, \
                crypto_session_id, generation, commit_event_id, \
                recipient_device_id, key_package_hash \
             ) ",
        );
        qb.push_values(welcomes.iter(), |mut b, w| {
            b.push_bind(Uuid::new_v4().to_string())
                .push_bind(conversation_id)
                .push_bind(&w.recipient_did)
                .push_bind(&w.welcome_data)
                .push_bind(initiator_did)
                .push_bind(&new_session_id)
                .push_bind(next_generation)
                .push_bind(&activated_event_id)
                .push_bind(&w.recipient_device_id)
                .push_bind(&w.key_package_hash);
        });
        qb.build()
            .execute(&mut **tx)
            .await
            .context("bulk INSERT pending_welcomes")?;
    }

    // 8. Housekeeping: clear stale reset/quorum/welcome state for the
    //    prior session. Mirrors `do_reset_group:1707-1721`.
    sqlx::query("DELETE FROM welcome_messages WHERE convo_id = $1")
        .bind(conversation_id)
        .execute(&mut **tx)
        .await
        .context("DELETE welcome_messages")?;
    sqlx::query("DELETE FROM pending_device_additions WHERE convo_id = $1")
        .bind(conversation_id)
        .execute(&mut **tx)
        .await
        .context("DELETE pending_device_additions")?;
    sqlx::query("DELETE FROM reset_votes WHERE convo_id = $1")
        .bind(conversation_id)
        .execute(&mut **tx)
        .await
        .context("DELETE reset_votes")?;

    // Build the CryptoSession result for the caller.
    let session = fetch_session_by_id(tx, &new_session_id)
        .await?
        .ok_or_else(|| anyhow!("inserted crypto_session {new_session_id} not found post-INSERT"))?;

    Ok(ActivationResult::Won(ActivationOutcome {
        session,
        generation: next_generation,
        cipher_suite,
    }))
}

/// Helper used by the idempotent-replay path to reconstruct the
/// `CryptoSession` from a prior activation.
async fn fetch_session_by_id(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<Option<CryptoSession>> {
    let row: Option<CryptoSessionRow> = sqlx::query_as(&format!(
        "SELECT {SELECT_CRYPTO_SESSION_COLS_FOR_TX} \
         FROM crypto_sessions WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .context("fetch_session_by_id")?;

    Ok(row.map(CryptoSession::from))
}
