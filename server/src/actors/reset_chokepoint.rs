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

/// Result of [`activate_crypto_session_tx`]. Both variants are committed
/// — the loser variant intentionally persists the `failed` crypto_sessions
/// row and the `crypto_session_candidate_rejected` delivery_event for
/// audit trail. Caller decides how to surface `Lost` to its caller
/// (typically as an error at the actor message boundary).
#[derive(Debug)]
pub(crate) enum ActivationResult {
    /// Candidate won the tie-break, was activated.
    Won(ActivationOutcome),
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
async fn allocate_seq(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: &str,
) -> Result<i64> {
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

/// Phase 2 §2.2 — handle `RequestCryptoSessionReset` inside an open tx.
///
/// Idempotent on `idempotency_key`. Steps:
///
/// 1. If a `crypto_session_reset_requested` event with this idempotency_key
///    already exists, reconstruct and return its `ResetRequest`.
/// 2. UPDATE the active crypto_session to `state = 'reset_requested'`
///    (no-op if already in `reset_requested` or `superseding`).
/// 3. APPEND a `crypto_session_reset_requested` event referencing the
///    active session, with `payload_json` containing the request body and
///    the freshly-allocated `request_id`.
pub(crate) async fn request_crypto_session_reset_tx(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: &str,
    trigger: ResetTrigger,
    initiator_did: &str,
    reason: &str,
    idempotency_key: &str,
) -> Result<ResetRequest> {
    if let Some((_event_id, payload_json, _cs_id)) = find_existing_event(
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
        return Ok(ResetRequest {
            request_id,
            conversation_id: conversation_id.to_string(),
            initiator_did: initiator_did.to_string(),
            reason: reason.to_string(),
        });
    }

    let current = read_current_session_for_update(tx, conversation_id)
        .await?
        .ok_or_else(|| anyhow!("no non-superseded crypto_session for {conversation_id}"))?;

    // Idempotent transition: only flip 'active' → 'reset_requested'.
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

    let request_id = Uuid::new_v4().to_string();
    let payload = json!({
        "request_id": request_id,
        "trigger": trigger.as_str(),
        "reason": reason,
    });

    let seq = allocate_seq(tx, conversation_id).await?;
    insert_event(
        tx,
        conversation_id,
        seq,
        Some(&current.id),
        "crypto_session_reset_requested",
        Some(initiator_did),
        Some(&current.mls_group_id),
        Some(idempotency_key),
        payload,
    )
    .await?;

    Ok(ResetRequest {
        request_id,
        conversation_id: conversation_id.to_string(),
        initiator_did: initiator_did.to_string(),
        reason: reason.to_string(),
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
        return Ok(ActivationResult::Won(ActivationOutcome {
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
    let next_generation = prior.generation + 1;
    let cipher_suite = prior.cipher_suite.clone();
    let new_session_id = Uuid::new_v4().to_string();

    // 3. Tie-break INSERT.
    let inserted: Option<(String,)> = sqlx::query_as(
        "INSERT INTO crypto_sessions ( \
            id, conversation_id, generation, mls_group_id, state, supersedes_id, \
            cipher_suite, last_observed_epoch, group_info, group_info_epoch, \
            group_info_updated_at, created_by_did, created_at, activated_at \
         ) VALUES ($1, $2, $3, $4, 'active', $5, $6, 0, $7, \
                   CASE WHEN $7 IS NULL THEN NULL ELSE 0 END, \
                   CASE WHEN $7 IS NULL THEN NULL ELSE NOW() END, \
                   $8, NOW(), NOW()) \
         ON CONFLICT (conversation_id, generation) DO NOTHING \
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
    .fetch_optional(&mut **tx)
    .await
    .context("INSERT new crypto_session")?;

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
    sqlx::query(
        "UPDATE crypto_sessions \
         SET state = 'superseded', \
             superseded_at = NOW(), \
             superseded_by_id = $2 \
         WHERE id = $1 AND state IN ('active', 'superseding')",
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
    insert_event(
        tx,
        conversation_id,
        supersede_seq,
        Some(&prior.id),
        "crypto_session_superseded",
        Some(initiator_did),
        Some(&prior.mls_group_id),
        None,
        supersede_payload,
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
        activated_payload,
    )
    .await?;

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
        let mut qb = sqlx::QueryBuilder::<Postgres>::new(
            "INSERT INTO pending_welcomes ( \
                id, convo_id, target_did, welcome_message, created_by_did, \
                crypto_session_id, generation, commit_event_id, recipient_device_id \
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
                .push_bind(&w.recipient_device_id);
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
