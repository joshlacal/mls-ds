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
//! Losers get a `failed` row + `crypto_session_candidate_rejected` event
//! and an error returned to the caller; their welcomes are NOT stored.
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
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::models::CryptoSession;

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

/// Read the most-recent active crypto_session for a conversation, with a
/// row lock so the activate path serializes against concurrent supersedes.
async fn read_active_session_for_update(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: &str,
) -> Result<Option<CryptoSession>> {
    let row: Option<(
        String,
        String,
        i32,
        String,
        String,
        Option<String>,
        Option<String>,
        i32,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i32>,
        Option<DateTime<Utc>>,
        Option<String>,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
    )> = sqlx::query_as(
        "SELECT id, conversation_id, generation, mls_group_id, state, supersedes_id, \
         cipher_suite, last_observed_epoch, last_confirmation_tag, group_info, \
         group_info_epoch, group_info_updated_at, created_by_did, created_at, \
         activated_at, superseded_at \
         FROM crypto_sessions \
         WHERE conversation_id = $1 AND state = 'active' \
         FOR UPDATE",
    )
    .bind(conversation_id)
    .fetch_optional(&mut **tx)
    .await
    .context("read_active_session_for_update")?;

    Ok(row.map(|r| CryptoSession {
        id: r.0,
        conversation_id: r.1,
        generation: r.2,
        mls_group_id: r.3,
        state: r.4,
        supersedes_id: r.5,
        cipher_suite: r.6,
        last_observed_epoch: r.7,
        last_confirmation_tag: r.8,
        group_info: r.9,
        group_info_epoch: r.10,
        group_info_updated_at: r.11,
        created_by_did: r.12,
        created_at: r.13,
        activated_at: r.14,
        superseded_at: r.15,
    }))
}

/// Look up an existing delivery_event by idempotency tuple. Used by both
/// handler entry paths to short-circuit retries.
///
/// Note: we key on (conversation_id, sender_did, idempotency_key) and use
/// `IS NOT DISTINCT FROM` so NULL sender_device_id matches NULL.
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
async fn allocate_seq(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: &str,
) -> Result<i64> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
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

    let active = read_active_session_for_update(tx, conversation_id)
        .await?
        .ok_or_else(|| anyhow!("no active crypto_session for {conversation_id}"))?;

    sqlx::query(
        "UPDATE crypto_sessions \
         SET state = 'reset_requested' \
         WHERE id = $1 AND state = 'active'",
    )
    .bind(&active.id)
    .execute(&mut **tx)
    .await
    .context("mark active session reset_requested")?;

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
        Some(&active.id),
        "crypto_session_reset_requested",
        Some(initiator_did),
        Some(&active.mls_group_id),
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
) -> Result<ActivationOutcome> {
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
        return Ok(ActivationOutcome {
            session,
            generation,
            cipher_suite,
        });
    }

    // 2. Read prior active session under row lock.
    let prior = read_active_session_for_update(tx, conversation_id)
        .await?
        .ok_or_else(|| anyhow!("no active crypto_session for {conversation_id}"))?;
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
        // Tie-break loss: another candidate won this generation. Persist
        // a `failed` row keyed by a different mls_group_id (the one we
        // proposed) so audit trail is preserved, then append a
        // candidate_rejected event and return error. Welcomes for losing
        // candidates are NOT stored.
        let failed_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO crypto_sessions ( \
                id, conversation_id, generation, mls_group_id, state, supersedes_id, \
                cipher_suite, last_observed_epoch, created_by_did, created_at \
             ) VALUES ($1, $2, $3, $4, 'failed', $5, $6, 0, $7, NOW()) \
             ON CONFLICT (mls_group_id) DO NOTHING",
        )
        .bind(&failed_id)
        .bind(conversation_id)
        .bind(next_generation)
        .bind(new_mls_group_id)
        .bind(&prior.id)
        .bind(&cipher_suite)
        .bind(initiator_did)
        .execute(&mut **tx)
        .await
        .context("INSERT failed candidate row")?;

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
            Some(&failed_id),
            "crypto_session_candidate_rejected",
            Some(initiator_did),
            Some(new_mls_group_id),
            Some(idempotency_key),
            payload,
        )
        .await?;

        return Err(anyhow!(
            "ActivateCryptoSession tie-break lost: another candidate already won generation {next_generation}"
        ));
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
    for w in welcomes {
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO pending_welcomes ( \
                id, convo_id, target_did, welcome_message, created_by_did, \
                crypto_session_id, generation, commit_event_id, recipient_device_id \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&id)
        .bind(conversation_id)
        .bind(&w.recipient_did)
        .bind(&w.welcome_data)
        .bind(initiator_did)
        .bind(&new_session_id)
        .bind(next_generation)
        .bind(&activated_event_id)
        .bind(&w.recipient_device_id)
        .execute(&mut **tx)
        .await
        .context("INSERT pending_welcome")?;
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

    Ok(ActivationOutcome {
        session,
        generation: next_generation,
        cipher_suite,
    })
}

/// Helper used by the idempotent-replay path to reconstruct the
/// `CryptoSession` from a prior activation.
async fn fetch_session_by_id(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<Option<CryptoSession>> {
    let row: Option<(
        String,
        String,
        i32,
        String,
        String,
        Option<String>,
        Option<String>,
        i32,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i32>,
        Option<DateTime<Utc>>,
        Option<String>,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
    )> = sqlx::query_as(
        "SELECT id, conversation_id, generation, mls_group_id, state, supersedes_id, \
         cipher_suite, last_observed_epoch, last_confirmation_tag, group_info, \
         group_info_epoch, group_info_updated_at, created_by_did, created_at, \
         activated_at, superseded_at \
         FROM crypto_sessions WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .context("fetch_session_by_id")?;

    Ok(row.map(|r| CryptoSession {
        id: r.0,
        conversation_id: r.1,
        generation: r.2,
        mls_group_id: r.3,
        state: r.4,
        supersedes_id: r.5,
        cipher_suite: r.6,
        last_observed_epoch: r.7,
        last_confirmation_tag: r.8,
        group_info: r.9,
        group_info_epoch: r.10,
        group_info_updated_at: r.11,
        created_by_did: r.12,
        created_at: r.13,
        activated_at: r.14,
        superseded_at: r.15,
    }))
}
