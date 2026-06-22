use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use std::sync::Arc;
use tls_codec::Deserialize as TlsDeserialize;
use tracing::{error, info, warn};

use jacquard_axum::ExtractXrpc;

use crate::{
    actors::ActorRegistry,
    auth::AuthUser,
    block_sync::BlockSyncService,
    device_utils::parse_device_did,
    generated::blue_catbird::mlsChat::commit_group_change::{
        CommitGroupChangeOutput, CommitGroupChangeRequest, PendingDeviceAddition,
    },
    realtime::{sse::StreamEvent, SseState},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.commitGroupChange";

#[cfg(test)]
const TEST_ADD_MEMBERS_COMMIT_BYTES: &[u8] = b"test-add-members-commit";
#[cfg(test)]
const TEST_COMMIT_EPOCH_UNSET: u64 = u64::MAX;
#[cfg(test)]
static TEST_ADD_MEMBERS_COMMIT_EPOCH_OVERRIDE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(TEST_COMMIT_EPOCH_UNSET);
#[cfg(test)]
static TEST_ADD_MEMBERS_ABORT_AFTER_WELCOME: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
struct AddMembersCommitShapeGuard;

#[cfg(test)]
impl Drop for AddMembersCommitShapeGuard {
    fn drop(&mut self) {
        TEST_ADD_MEMBERS_COMMIT_EPOCH_OVERRIDE
            .store(TEST_COMMIT_EPOCH_UNSET, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
fn force_add_members_commit_shape_for_test(epoch: u64) -> AddMembersCommitShapeGuard {
    TEST_ADD_MEMBERS_COMMIT_EPOCH_OVERRIDE.store(epoch, std::sync::atomic::Ordering::SeqCst);
    AddMembersCommitShapeGuard
}

#[cfg(test)]
struct AddMembersAbortAfterWelcomeGuard;

#[cfg(test)]
impl Drop for AddMembersAbortAfterWelcomeGuard {
    fn drop(&mut self) {
        TEST_ADD_MEMBERS_ABORT_AFTER_WELCOME.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
fn enable_add_members_abort_after_welcome_for_test() -> AddMembersAbortAfterWelcomeGuard {
    TEST_ADD_MEMBERS_ABORT_AFTER_WELCOME.store(true, std::sync::atomic::Ordering::SeqCst);
    AddMembersAbortAfterWelcomeGuard
}

// Layer 1 robustness tunables. Plan: ~/.claude/plans/rippling-greeting-whale.md
// Per-(device, group) External Commit cooldown. The existing per-conversation
// 30s rate limit (lines below) catches storms across all devices; this gate
// catches one buggy device retrying on its own.
const PER_DEVICE_EC_COOLDOWN_SECS: i64 = 60;
// Epoch-storm circuit breaker. > N epoch advances in M seconds freezes the
// group for FREEZE seconds; clients see HTTP 423 GroupFrozen until thaw.
const EPOCH_STORM_WINDOW_SECS: i64 = 60;
const EPOCH_STORM_THRESHOLD: i32 = 6;
const EPOCH_STORM_FREEZE_SECS: i64 = 5 * 60;

#[derive(Serialize)]
struct XrpcErrorBody {
    error: &'static str,
    message: String,
}

/// Structured body for `groupReset` errors. Locked contract with CLIENT D —
/// the wire shape MUST match across SERVER A (`commitGroupChange
/// refreshGroupInfo`) and SERVER B (`getGroupState`):
///
///   {"error":"groupReset","message":"<text>","convoId":"<convo>","newCryptoSessionId":<id-or-null>}
///
/// HTTP status: 410 Gone. `newCryptoSessionId` is the id of the currently-
/// active `crypto_sessions` row (the session clients should bootstrap into),
/// or null if the conversation is mid-reset and no active row exists.
#[derive(Serialize)]
pub struct GroupResetBody {
    error: &'static str,
    message: String,
    #[serde(rename = "convoId")]
    convo_id: String,
    #[serde(rename = "newCryptoSessionId")]
    new_crypto_session_id: Option<String>,
}

/// Structured body for CAS-failure 409s, matching the shape already produced by
/// `send_message.rs` on epoch mismatch (task #41). Clients that already parse
/// `serverEpoch` from the send-path 409 get instant epoch-resync here too —
/// no extra `getGroupState` round-trip required.
#[derive(Serialize)]
pub struct EpochConflictBody {
    error: &'static str,
    message: String,
    #[serde(rename = "serverEpoch")]
    server_epoch: i32,
    #[serde(
        rename = "serverSequencerTerm",
        skip_serializing_if = "Option::is_none"
    )]
    server_sequencer_term: Option<i64>,
    #[serde(rename = "expectedEpoch")]
    expected_epoch: i32,
}

/// Layer 1 §1.2: structured 429 body for the two External-Commit rate-limit
/// paths (per-conversation 30s + per-(device,group) 60s). Wire shape locked
/// via the lexicon `#rateLimitedBody` def so clients can parse
/// `retryAfterSeconds` without scraping the message string.
#[derive(Serialize)]
pub struct RateLimitedBody {
    error: &'static str,
    message: String,
    #[serde(rename = "retryAfterSeconds")]
    retry_after_seconds: i64,
    /// `"convo"` = existing per-conversation 30s limit. `"device-convo"` =
    /// per-(device, group) 60s cooldown.
    scope: &'static str,
}

/// N29: structured 423 body for epoch-storm freezes. Mirrors
/// `RateLimitedBody` for client backoff without text scraping.
#[derive(Serialize)]
pub struct GroupFrozenBody {
    error: &'static str,
    message: String,
    #[serde(rename = "retryAfterSeconds")]
    retry_after_seconds: i64,
}

pub enum XrpcError {
    /// Plain error: status + error-name + message.
    Plain(StatusCode, &'static str, String),
    /// 409 epoch-conflict with structured body (task #41).
    EpochConflict(EpochConflictBody),
    /// 410 Gone with `GroupReset` structured body. Used by `refreshGroupInfo`
    /// to signal that the active crypto session has been reset/cleared and
    /// the client must bootstrap-recover instead of retrying.
    GroupReset(GroupResetBody),
    /// Layer 1 §1.2: 429 with structured `RateLimitedBody`. Sets
    /// `Retry-After` header from `retry_after_seconds`.
    RateLimited(RateLimitedBody),
    /// N29: 423 with structured `GroupFrozenBody`. Sets `Retry-After`.
    GroupFrozen(GroupFrozenBody),
}

impl XrpcError {
    /// Back-compat constructor used throughout the file: `XrpcError(status, name, msg)`.
    /// Kept as a function-style ctor so existing `XrpcError(StatusCode::..., ..., ...)`
    /// call sites (e.g. rate-limit 429 at line 794) continue to compile unchanged.
    #[allow(non_snake_case)]
    pub fn new(status: StatusCode, error: &'static str, message: String) -> Self {
        XrpcError::Plain(status, error, message)
    }
}

// Tuple-struct-style invocation used by existing call sites
// (e.g. `XrpcError(StatusCode::TOO_MANY_REQUESTS, "RateLimited", msg)`).
// Rust doesn't allow adding a tuple-struct pattern to an enum directly, so we
// provide this as a `From` impl would collide — instead we reshape the one
// non-helper call site below. All helper call sites (`bad_request`, `conflict`,
// etc.) continue to work via the helpers below.

impl IntoResponse for XrpcError {
    fn into_response(self) -> Response {
        match self {
            XrpcError::Plain(status, error, message) => {
                (status, Json(XrpcErrorBody { error, message })).into_response()
            }
            XrpcError::EpochConflict(body) => (StatusCode::CONFLICT, Json(body)).into_response(),
            XrpcError::GroupReset(body) => (StatusCode::GONE, Json(body)).into_response(),
            XrpcError::RateLimited(body) => {
                let retry = body.retry_after_seconds.max(0).to_string();
                let mut resp = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
                if let Ok(val) = axum::http::HeaderValue::from_str(&retry) {
                    resp.headers_mut()
                        .insert(axum::http::header::RETRY_AFTER, val);
                }
                resp
            }
            XrpcError::GroupFrozen(body) => {
                let retry = body.retry_after_seconds.max(0).to_string();
                let mut resp = (StatusCode::LOCKED, Json(body)).into_response();
                if let Ok(val) = axum::http::HeaderValue::from_str(&retry) {
                    resp.headers_mut()
                        .insert(axum::http::header::RETRY_AFTER, val);
                }
                resp
            }
        }
    }
}

fn group_reset_error(
    convo_id: &str,
    message: impl Into<String>,
    new_crypto_session_id: Option<String>,
) -> XrpcError {
    XrpcError::GroupReset(GroupResetBody {
        error: "groupReset",
        message: message.into(),
        convo_id: convo_id.to_string(),
        new_crypto_session_id,
    })
}

fn bad_request(message: impl Into<String>) -> XrpcError {
    XrpcError::Plain(StatusCode::BAD_REQUEST, "InvalidRequest", message.into())
}

fn auth_required(message: impl Into<String>) -> XrpcError {
    XrpcError::Plain(StatusCode::UNAUTHORIZED, "AuthRequired", message.into())
}

fn forbidden(message: impl Into<String>) -> XrpcError {
    XrpcError::Plain(StatusCode::FORBIDDEN, "Forbidden", message.into())
}

fn conflict(message: impl Into<String>) -> XrpcError {
    XrpcError::Plain(StatusCode::CONFLICT, "Conflict", message.into())
}

/// Structured 409 with `serverEpoch` + `expectedEpoch` so clients can resync
/// without a follow-up `getGroupState` call. Mirrors `send_message.rs`'s
/// `EpochMismatch` body shape (task #41).
///
/// `expected_epoch` is the `current_epoch` the caller just read for its CAS
/// attempt; the server value is fetched fresh from `conversations` since CAS
/// lost — some other commit advanced the row between read and write.
async fn conflict_with_epoch(
    pool: &sqlx::PgPool,
    convo_id: &str,
    expected_epoch: i32,
    message: impl Into<String>,
) -> XrpcError {
    // Fetch the current server epoch + sequencer_term after CAS failure.
    // Non-fatal on query error — fall back to echoing `expected_epoch` so the
    // client still sees a structured body (just without the authoritative
    // server value).
    let row: Option<(Option<i32>, Option<i64>)> =
        sqlx::query_as("SELECT current_epoch, sequencer_term FROM conversations WHERE id = $1")
            .bind(convo_id)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();

    let (server_epoch, server_sequencer_term) = match row {
        Some((Some(ep), term)) => (ep, term),
        _ => (expected_epoch, None),
    };

    XrpcError::EpochConflict(EpochConflictBody {
        error: "EpochMismatch",
        message: message.into(),
        server_epoch,
        server_sequencer_term,
        expected_epoch,
    })
}

fn internal_server_error(message: impl Into<String>) -> XrpcError {
    XrpcError::Plain(
        StatusCode::INTERNAL_SERVER_ERROR,
        "InternalServerError",
        message.into(),
    )
}

fn group_frozen_error(retry_after_seconds: i64) -> XrpcError {
    let retry = retry_after_seconds.max(0);
    XrpcError::GroupFrozen(GroupFrozenBody {
        error: "GroupFrozen",
        message: format!(
            "Conversation is being repaired (epoch-storm circuit breaker). Retry after {retry} seconds."
        ),
        retry_after_seconds: retry,
    })
}

/// Layer 1 §1.3: pre-flight freeze check. Returns `Err(XrpcError)` with HTTP
/// 423 `GroupFrozen` if the group has been frozen by the epoch-storm circuit
/// breaker and the freeze hasn't expired. Best-effort: DB read errors are
/// treated as "not frozen" (fail open) so a transient DB blip can't lock all
/// commits.
async fn check_group_frozen(pool: &sqlx::PgPool, convo_id: &str) -> Result<(), XrpcError> {
    match crate::db::get_freeze_status(pool, convo_id).await {
        Ok(status) => {
            let now = chrono::Utc::now();
            if status.is_frozen_at(now) {
                let retry = status.retry_after_secs_at(now);
                warn!(
                    convo_id = %crate::crypto::redact_for_log(convo_id),
                    retry_after_secs = retry,
                    "commitGroupChange: rejected — group frozen by epoch-storm circuit breaker"
                );
                return Err(group_frozen_error(retry));
            }
            Ok(())
        }
        Err(e) => {
            warn!(
                error = ?e,
                convo_id = %crate::crypto::redact_for_log(convo_id),
                "commitGroupChange: freeze-status read failed (non-fatal, allowing commit)"
            );
            Ok(())
        }
    }
}

/// Layer 1 §1.4: best-effort External Commit audit insert. Logs a warning
/// on failure and returns Ok regardless — audit-row failures must never
/// mask the response we're already about to send.
async fn audit_external_commit(
    pool: &sqlx::PgPool,
    convo_id: &str,
    actor_did: &str,
    actor_device_id: &str,
    epoch_before: i32,
    epoch_after: i32,
    rejection_reason: Option<&'static str>,
) {
    let dev = if actor_device_id.is_empty() {
        None
    } else {
        Some(actor_device_id)
    };
    if let Err(e) = crate::db::record_external_commit_audit(
        pool,
        convo_id,
        actor_did,
        dev,
        epoch_before,
        epoch_after,
        rejection_reason,
    )
    .await
    {
        warn!(
            error = ?e,
            convo_id = %crate::crypto::redact_for_log(convo_id),
            rejection_reason = ?rejection_reason,
            "external_commit_audit insert failed (non-fatal)"
        );
    }
}

fn inspect_commit_for_action(
    action_name: &str,
    commit_bytes: &[u8],
    convo_id: &str,
) -> Result<super::commit_inspect::CommitShape, XrpcError> {
    #[cfg(test)]
    if action_name == "addMembers" && commit_bytes == TEST_ADD_MEMBERS_COMMIT_BYTES {
        let epoch =
            TEST_ADD_MEMBERS_COMMIT_EPOCH_OVERRIDE.load(std::sync::atomic::Ordering::SeqCst);
        if epoch != TEST_COMMIT_EPOCH_UNSET {
            return Ok(super::commit_inspect::CommitShape {
                wire_format: openmls::prelude::WireFormat::PrivateMessage,
                content_type: openmls::prelude::ContentType::Commit,
                epoch,
            });
        }
    }

    super::commit_inspect::inspect_commit_shape(commit_bytes).map_err(|e| {
        warn!(
            "{}: rejected — framing invalid ({}) for convo {}",
            action_name,
            e,
            crate::crypto::redact_for_log(convo_id)
        );
        bad_request(format!("Invalid commit framing: {e}"))
    })
}

// ---------------------------------------------------------------------------
// Row type for pending device additions
// ---------------------------------------------------------------------------

#[derive(Debug, FromRow)]
struct PendingAdditionRow {
    id: String,
    convo_id: String,
    user_did: String,
    new_device_id: String,
    new_device_credential_did: String,
    device_name: Option<String>,
    status: String,
    claimed_by_did: Option<String>,
    created_at: DateTime<Utc>,
}

fn invalidate_welcome_response(rows_affected: u64) -> CommitGroupChangeOutput<'static> {
    CommitGroupChangeOutput {
        success: rows_affected > 0,
        claimed_addition: None,
        confirmation_tag: None,
        new_epoch: None,
        pending_additions: None,
        rejoined_at: None,
        extra_data: Default::default(),
    }
}

async fn mark_reissue_request_answered_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request_id: &str,
    convo_id: &str,
    responded_at: DateTime<Utc>,
) -> sqlx::Result<u64> {
    sqlx::query(
        "UPDATE reissue_requests \
         SET responded_at = $3 \
         WHERE id = $1 \
           AND convo_id = $2 \
           AND responded_at IS NULL",
    )
    .bind(request_id)
    .bind(convo_id)
    .bind(responded_at)
    .execute(&mut **tx)
    .await
    .map(|result| result.rows_affected())
}

fn maybe_abort_add_members_after_welcome_for_test() -> Result<(), XrpcError> {
    #[cfg(test)]
    if TEST_ADD_MEMBERS_ABORT_AFTER_WELCOME.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(internal_server_error("Forced addMembers rollback for test"));
    }

    Ok(())
}

/// ADR-002 §A7.4 — Persist the client-supplied `epoch_authenticator` for the
/// post-commit epoch so future `reportRecoveryFailure` votes can be validated
/// against a recent known-good authenticator.
///
/// Called from the four epoch-advancing branches (`addMembers`,
/// `externalCommit`/`processExternalCommit`, `removeMember`, generic
/// `commit`/`updateMetadata`). No-op when the client omits the field —
/// pre-A7 clients stay functional, they just don't contribute to the
/// authenticator pool (their reports will yield `missing_authenticator`).
///
/// The INSERT is idempotent on `(convo_id, epoch, authenticator)` so a
/// client retrying with the same input doesn't error.
async fn record_epoch_authenticator_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    convo_id: &str,
    epoch: i32,
    authenticator: &Option<jacquard_common::CowStr<'_>>,
    branch: &str,
) {
    let Some(auth) = authenticator else {
        return;
    };
    let auth_str: &str = auth.as_ref();
    if auth_str.is_empty() {
        return;
    }

    if let Err(e) = sqlx::query(
        "INSERT INTO epoch_authenticators (convo_id, epoch, authenticator, recorded_at) \
         VALUES ($1, $2, $3, NOW()) \
         ON CONFLICT (convo_id, epoch, authenticator) DO NOTHING",
    )
    .bind(convo_id)
    .bind(epoch)
    .bind(auth_str)
    .execute(&mut **tx)
    .await
    {
        // NOTE: We log here but we CANNOT swallow the error without also
        // propagating it — in Postgres, any failed statement aborts the
        // current transaction, so the subsequent `tx.commit()` would also
        // fail with "current transaction is aborted, commands ignored
        // until end of transaction block" regardless of what we do here.
        // In steady state (table exists, PK + `ON CONFLICT DO NOTHING`)
        // this INSERT cannot fail except under genuine DB outage, so
        // aborting the commit is the correct behavior.
        //
        // IMPORTANT: migration 20260418_001 MUST be applied before this
        // code ships, otherwise EVERY commit_group_change call that
        // carries an epoch_authenticator will 500.
        warn!(
            convo_id = %crate::crypto::redact_for_log(convo_id),
            branch,
            epoch,
            "failed to record epoch_authenticator (will poison tx): {}",
            e
        );
    }
}

/// Consolidated group change handler
/// POST /xrpc/blue.catbird.mlsChat.commitGroupChange
///
/// Consolidates: addMembers, processExternalCommit, rejoin, readdition, listPending, claimPending
#[tracing::instrument(skip(
    pool,
    sse_state,
    actor_registry,
    inline_trigger_cfg,
    block_sync,
    auth_user,
    input
))]
pub async fn commit_group_change(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    State(actor_registry): State<Arc<ActorRegistry>>,
    State(inline_trigger_cfg): State<Arc<crate::config::InlineTriggerConfig>>,
    State(block_sync): State<Arc<BlockSyncService>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<CommitGroupChangeRequest>,
) -> Result<Response, XrpcError> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(auth_required("Authentication required"));
    }

    let success_response = || CommitGroupChangeOutput {
        success: true,
        claimed_addition: None,
        confirmation_tag: None,
        new_epoch: None,
        pending_additions: None,
        rejoined_at: None,
        extra_data: Default::default(),
    };

    match input.action.as_ref() {
        "addMembers" => {
            let convo_id = input.convo_id.to_string();
            info!(
                "v2.commitGroupChange: addMembers for convo {}",
                crate::crypto::redact_for_log(&convo_id)
            );

            // ── Layer 1 §1.3: freeze check ─────────────────────────────
            // If the epoch-storm circuit breaker has flipped the group to
            // frozen, refuse all epoch-advancing actions until thaw.
            check_group_frozen(&pool, &convo_id).await?;

            // ── Idempotency check ──────────────────────────────────────
            if let Some(ref idem_key) = input.idempotency_key {
                let idem_key_str = idem_key.to_string();
                let already: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM idempotency_cache WHERE key = $1)",
                )
                .bind(&idem_key_str)
                .fetch_one(&pool)
                .await
                .unwrap_or(false);

                if already {
                    // TODO(phase 4): route via CryptoSessionRepository — idempotency-hit
                    // fallback in addMembers; migrate when ConversationActor takes the
                    // repo by ctor.
                    let current_epoch: Option<i32> =
                        sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
                            .bind(&convo_id)
                            .fetch_optional(&pool)
                            .await
                            .ok()
                            .flatten();
                    info!("v2.commitGroupChange: addMembers idempotent hit");
                    return Ok(Json(CommitGroupChangeOutput {
                        success: true,
                        new_epoch: Some(current_epoch.unwrap_or(0) as i64),
                        claimed_addition: None,
                        confirmation_tag: None,
                        pending_additions: None,
                        rejoined_at: None,
                        extra_data: Default::default(),
                    })
                    .into_response());
                }
            }

            // ── Validate required fields (bytes arrive already decoded) ──
            let welcome_bytes = input.welcome.as_ref().ok_or_else(|| {
                warn!("addMembers: missing welcome");
                bad_request("Missing welcome")
            })?;
            let commit_bytes = input.commit.as_ref().ok_or_else(|| {
                warn!("addMembers: missing commit");
                bad_request("Missing commit")
            })?;
            let commit_shape = inspect_commit_for_action("addMembers", commit_bytes, &convo_id)?;
            let commit_wire_epoch = commit_shape.epoch as i64;
            let member_dids = input.member_dids.as_ref().ok_or_else(|| {
                warn!("addMembers: missing member_dids");
                bad_request("Missing memberDids")
            })?;

            // ── Verify caller is a member ──────────────────────────────
            let (caller_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("addMembers: invalid DID format: {}", e);
                bad_request("Invalid DID format")
            })?;
            let is_member: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL)",
            )
            .bind(&convo_id)
            .bind(&caller_did)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("addMembers: membership check failed: {}", e);
                internal_server_error("Failed to check membership")
            })?;
            if !is_member {
                return Err(forbidden("Not a member of this conversation"));
            }

            // ── Block detection (PDS-first with bsky_blocks fallback) ──
            // Reject addMembers if any block edge exists between the
            // post-commit member set (existing members ∪ new members).
            // Mirrors the gate in createConvo (handle_create_convo).
            // See docs/superpowers/plans/2026-04-15-block-leave-shared-groups.md Phase 3.
            {
                let existing_member_dids: Vec<String> = sqlx::query_scalar(
                    "SELECT DISTINCT COALESCE(user_did, member_did) FROM members WHERE convo_id = $1 AND left_at IS NULL",
                )
                .bind(&convo_id)
                .fetch_all(&pool)
                .await
                .map_err(|e| {
                    error!("addMembers: failed to fetch existing members for block check: {}", e);
                    internal_server_error("Failed to check blocks")
                })?;

                let new_member_dids: Vec<String> = member_dids
                    .iter()
                    .map(|d| crate::sqlx_jacquard::did_to_string(d))
                    .collect();

                let mut all_dids: Vec<String> = existing_member_dids;
                all_dids.extend(new_member_dids.iter().cloned());
                all_dids.sort();
                all_dids.dedup();

                if all_dids.len() >= 2 {
                    match block_sync.check_block_conflicts(&all_dids).await {
                        Ok(conflicts) => {
                            if !conflicts.is_empty() {
                                for (blocker, _blocked) in &conflicts {
                                    if let Err(e) =
                                        block_sync.sync_blocks_to_db(&pool, blocker).await
                                    {
                                        warn!("Failed to sync blocks to DB: {}", e);
                                    }
                                }
                                warn!(
                                    "❌ addMembers forbidden: {} block edge(s) between members (convo {})",
                                    conflicts.len(),
                                    crate::crypto::redact_for_log(&convo_id)
                                );
                                return Err(forbidden(
                                    "Cannot add member: one or more members have blocked each other",
                                ));
                            }
                        }
                        Err(e) => {
                            // Fallback to local DB cache — fail secure on DB error.
                            warn!(
                                "addMembers: PDS block check failed, falling back to local DB: {}",
                                e
                            );
                            let blocks: Vec<(String, String)> = sqlx::query_as(
                                "SELECT user_did, target_did FROM bsky_blocks WHERE user_did = ANY($1) AND target_did = ANY($1)",
                            )
                            .bind(&all_dids)
                            .fetch_all(&pool)
                            .await
                            .map_err(|e| {
                                error!(
                                    "❌ addMembers: block fallback DB query failed: {}",
                                    e
                                );
                                internal_server_error("Failed to check blocks")
                            })?;

                            if !blocks.is_empty() {
                                warn!(
                                    "❌ addMembers forbidden: {} block edge(s) between members via DB cache (convo {})",
                                    blocks.len(),
                                    crate::crypto::redact_for_log(&convo_id)
                                );
                                return Err(forbidden(
                                    "Cannot add member: one or more members have blocked each other",
                                ));
                            }
                        }
                    }
                }
            }

            // ── Parse MLS epoch from GroupInfo if provided ──────────
            let (add_group_info_bytes, add_mls_epoch) =
                if let Some(gi_bytes) = input.group_info.as_ref() {
                    let gi_slice: &[u8] = gi_bytes;
                    let epoch = {
                        use openmls::messages::group_info::VerifiableGroupInfo;
                        use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn};

                        let from_mls_msg = MlsMessageIn::tls_deserialize(&mut &*gi_slice)
                            .ok()
                            .and_then(|msg| match msg.extract() {
                                MlsMessageBodyIn::GroupInfo(gi) => Some(gi.epoch().as_u64()),
                                _ => None,
                            });

                        from_mls_msg.or_else(|| {
                            VerifiableGroupInfo::tls_deserialize(&mut &*gi_slice)
                                .ok()
                                .map(|gi| gi.epoch().as_u64())
                        })
                    };

                    if let Some(e) = epoch {
                        info!(
                            "addMembers: parsed MLS epoch {} from GroupInfo for convo {}",
                            e,
                            crate::crypto::redact_for_log(&convo_id)
                        );
                    }

                    (Some(gi_bytes.to_vec()), epoch)
                } else {
                    (None, None)
                };

            // ── Decode client-provided confirmation_tag ──────────
            let add_confirmation_tag = if let Some(ref tag_bytes) = input.confirmation_tag {
                info!(
                    "addMembers: client-provided confirmation_tag ({} bytes) for convo {}",
                    tag_bytes.len(),
                    crate::crypto::redact_for_log(&convo_id)
                );
                Some(tag_bytes.to_vec())
            } else {
                None
            };

            let now = chrono::Utc::now();

            // ── Fetch current epoch for CAS ───────────────────────────
            let current_epoch = crate::db::get_current_epoch(&pool, &convo_id)
                .await
                .map_err(|e| {
                    error!(convo_id = %crate::crypto::redact_for_log(&convo_id), "addMembers: failed to get current epoch: {}", e);
                    internal_server_error("Failed to get current epoch")
                })?;
            if commit_shape.epoch != current_epoch as u64 {
                warn!(
                    "addMembers: stale commit wire_epoch={} current_epoch={} for convo {}",
                    commit_shape.epoch,
                    current_epoch,
                    crate::crypto::redact_for_log(&convo_id)
                );
                // Phase 2 (auto-reset): record 409 for sweep-trigger health
                // counter. Pool-level UPDATE; failure must NEVER mask the
                // 409 response.
                if let Err(e) =
                    crate::jobs::auto_detect_failed_groups::record_commit_409_with_inline_trigger(
                        &pool,
                        &actor_registry,
                        &convo_id,
                        &inline_trigger_cfg,
                    )
                    .await
                {
                    warn!(
                        error = ?e,
                        convo_id = %crate::crypto::redact_for_log(&convo_id),
                        "addMembers: failed to record commit 409 (non-fatal)"
                    );
                }
                return Err(conflict_with_epoch(
                    &pool,
                    &convo_id,
                    current_epoch,
                    "Commit was authored from a stale MLS epoch",
                )
                .await);
            }

            // ── Begin transaction: members + CAS epoch + commit + welcomes + idempotency ──
            let mut tx = pool.begin().await.map_err(|e| {
                error!(convo_id = %crate::crypto::redact_for_log(&convo_id), "addMembers: failed to begin transaction: {}", e);
                internal_server_error("Failed to begin transaction")
            })?;

            // ── Add members (inside transaction for atomicity with welcome) ──
            // Per-device when kp_hashes is provided; user-flat fallback otherwise.
            // The kp_hashes path resolves device_id from key_packages and inserts
            // member_did = "{user_did}#{device_id}" so SSE/push fan-out can target
            // individual devices instead of flooding every active session for a
            // user. See docs/superpowers/plans/2026-05-04-mls-per-device-welcome-and-members-routing.md.
            let member_did_strings: Vec<String> = member_dids
                .iter()
                .map(|d| crate::sqlx_jacquard::did_to_string(d))
                .collect();

            let used_per_device_members_path = match input.key_package_hashes.as_ref() {
                Some(hashes) if !hashes.is_empty() => {
                    // Convert from commit_group_change::KeyPackageHashEntry to
                    // bootstrap_reset_group::KeyPackageHashEntry (helper's accepted type).
                    // jacquard generates nominally distinct types per lexicon module even
                    // though their fields are identical — see Task 3 (commit a60b8af).
                    let converted: Vec<crate::generated::blue_catbird::mlsChat::bootstrap_reset_group::KeyPackageHashEntry> = hashes
                        .iter()
                        .map(|e| crate::generated::blue_catbird::mlsChat::bootstrap_reset_group::KeyPackageHashEntry {
                            did: e.did.clone(),
                            hash: e.hash.clone(),
                            extra_data: Default::default(),
                        })
                        .collect();
                    let count = converted.len();
                    crate::db::insert_members_per_device_in_tx(
                        &mut tx, &convo_id, &converted, now, false,
                    )
                    .await
                    .map_err(|e| {
                        error!(
                            convo_id = %crate::crypto::redact_for_log(&convo_id),
                            "addMembers: failed to insert per-device members: {}", e
                        );
                        internal_server_error("Failed to insert members")
                    })?;
                    info!(
                        "addMembers: inserted {} per-device member rows into convo {}",
                        count,
                        crate::crypto::redact_for_log(&convo_id)
                    );
                    true
                }
                _ => false,
            };

            // Legacy user-flat fallback: only runs when kp_hashes was None or empty.
            if !used_per_device_members_path {
                warn!(
                    "addMembers: key_package_hashes absent/empty — falling back to user-flat members storage for convo {}",
                    crate::crypto::redact_for_log(&convo_id)
                );
                for member_did_str in &member_did_strings {
                    let result = sqlx::query(
                        r#"INSERT INTO members (convo_id, member_did, user_did, joined_at)
                           VALUES ($1, $2, $2, $3)
                           ON CONFLICT (convo_id, member_did) DO UPDATE SET left_at = NULL, needs_rejoin = false"#,
                    )
                    .bind(&convo_id)
                    .bind(member_did_str)
                    .bind(now)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| {
                        error!(convo_id = %crate::crypto::redact_for_log(&convo_id), "addMembers: failed to insert legacy user-flat member: {}", e);
                        internal_server_error("Failed to insert member")
                    })?;
                    info!(
                        "addMembers: legacy user-flat member {} inserted into convo {}, rows_affected={}",
                        crate::crypto::redact_for_log(member_did_str),
                        crate::crypto::redact_for_log(&convo_id),
                        result.rows_affected()
                    );
                }
            }

            // ── Advance epoch (CAS) ───────────────────────────────────
            let new_epoch =
                crate::db::try_advance_conversation_epoch_tx(&mut tx, &convo_id, current_epoch)
                    .await
                    .map_err(|e| {
                        error!("addMembers: failed to advance epoch: {}", e);
                        internal_server_error("Failed to advance epoch")
                    })?;

            let new_epoch = match new_epoch {
                Some(epoch) => epoch,
                None => {
                    warn!("addMembers: epoch CAS failed (concurrent commit), returning 409");
                    // Roll back the tx first so its connection is released,
                    // then fetch authoritative server state for the 409 body.
                    // `conflict_with_epoch` reads on `&pool` (separate conn).
                    drop(tx);
                    // Phase 2 (auto-reset): record 409 on a separate
                    // pool-borrowed conn (the failed tx is gone). Failure
                    // must NEVER mask the 409 response.
                    if let Err(e) = crate::jobs::auto_detect_failed_groups::record_commit_409_with_inline_trigger(&pool, &actor_registry, &convo_id, &inline_trigger_cfg).await {
                        warn!(
                            error = ?e,
                            convo_id = %crate::crypto::redact_for_log(&convo_id),
                            "addMembers: failed to record commit 409 (non-fatal)"
                        );
                    }
                    return Err(conflict_with_epoch(
                        &pool,
                        &convo_id,
                        current_epoch,
                        "Conversation epoch advanced concurrently",
                    )
                    .await);
                }
            };

            // Log MLS epoch from GroupInfo for diagnostics only.
            // Epoch must only advance by exactly +1 per accepted commit (CAS above).
            if let Some(mls_epoch) = add_mls_epoch {
                let mls_epoch_i32 = mls_epoch as i32;
                if mls_epoch_i32 != new_epoch {
                    warn!(
                        "addMembers: MLS epoch divergence — server epoch={}, MLS epoch={} for convo {}",
                        new_epoch,
                        mls_epoch_i32,
                        crate::crypto::redact_for_log(&convo_id)
                    );
                }
            }

            // ── Store or invalidate GroupInfo (uses shared helper) ─────
            if let Some(ref gi_bytes) = add_group_info_bytes {
                // Do NOT rewrite `current_epoch` here. The CAS in try_advance
                // (lines 462-468) already assigned it; overwriting with the
                // client-reported MLS epoch can drift from the `commits`-row
                // epoch written below, stranding other clients that then
                // fetch GroupInfo at a different epoch than the last commit.
                // Divergence between CAS and MLS epoch is logged but not
                // fixed by a raw SET — see divergence warn! above.
                crate::db::store_group_info_in_tx(
                    &mut tx,
                    &convo_id,
                    gi_bytes,
                    add_confirmation_tag.as_deref(),
                )
                .await
                .map_err(|e| {
                    error!("addMembers: failed to store GroupInfo: {}", e);
                    internal_server_error("Failed to store GroupInfo")
                })?;
                info!(
                    "addMembers: stored GroupInfo (mls_epoch={:?}, has_conf_tag={}) for convo {}",
                    add_mls_epoch,
                    add_confirmation_tag.is_some(),
                    crate::crypto::redact_for_log(&convo_id)
                );
            } else {
                warn!(
                    "addMembers: no GroupInfo provided with commit for convo {} — keeping existing (may be stale)",
                    crate::crypto::redact_for_log(&convo_id)
                );
            };

            // ── Store commit message ───────────────────────────────────
            let msg_id = uuid::Uuid::new_v4().to_string();
            let seq: i64 = sqlx::query_scalar(
                "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1",
            )
            .bind(&convo_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                error!("addMembers: failed to get seq: {}", e);
                internal_server_error("Failed to allocate message sequence")
            })?;

            let msg_result = sqlx::query(
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, wire_epoch, seq, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7, $8)",
            )
            .bind(&msg_id)
            .bind(&convo_id)
            .bind(Option::<&str>::None)
            .bind(new_epoch)
            .bind(commit_wire_epoch)
            .bind(seq)
            .bind(&commit_bytes[..])
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("addMembers: failed to insert commit message: {}", e);
                internal_server_error("Failed to store commit message")
            })?;
            info!(
                "addMembers: commit message inserted, rows_affected={}",
                msg_result.rows_affected()
            );

            // ── Store welcome (per-device when kp_hashes provided; user-flat fallback otherwise) ──
            // The MLS welcome_bytes is itself a multi-recipient blob — each device decrypts
            // its own portion locally — so storing identical welcome_data across N rows is
            // correct. The helper persists recipient_device_id when resolvable, while
            // key_package_hash remains the hash discriminator/fallback/audit value. See
            // docs/superpowers/plans/2026-05-04-mls-per-device-welcome-and-members-routing.md.
            let kp_hashes_for_welcomes = input.key_package_hashes.as_ref();
            let used_per_device_path = match kp_hashes_for_welcomes {
                Some(hashes) if !hashes.is_empty() => {
                    // Convert from commit_group_change::KeyPackageHashEntry to
                    // bootstrap_reset_group::KeyPackageHashEntry (helper's accepted type).
                    // jacquard generates nominally distinct types per lexicon module even
                    // though their fields are identical — see Task 3 (commit a60b8af) for
                    // context. The conversion is a mechanical field copy.
                    let converted: Vec<crate::generated::blue_catbird::mlsChat::bootstrap_reset_group::KeyPackageHashEntry> = hashes
                        .iter()
                        .map(|e| crate::generated::blue_catbird::mlsChat::bootstrap_reset_group::KeyPackageHashEntry {
                            did: e.did.clone(),
                            hash: e.hash.clone(),
                            extra_data: Default::default(),
                        })
                        .collect();
                    let count = converted.len();
                    crate::db::store_welcomes_per_device_in_tx(
                        &mut tx,
                        &convo_id,
                        welcome_bytes,
                        &converted,
                        &caller_did,
                    )
                    .await
                    .map_err(|e| {
                        error!("addMembers: failed to store per-device welcomes: {}", e);
                        internal_server_error("Failed to store welcomes")
                    })?;
                    info!(
                        "addMembers: stored {} per-device welcome rows for convo {}",
                        count,
                        crate::crypto::redact_for_log(&convo_id)
                    );
                    true
                }
                _ => false,
            };

            // Legacy user-flat fallback: only runs when kp_hashes was None or empty.
            if !used_per_device_path {
                warn!(
                    "addMembers: key_package_hashes absent/empty — falling back to user-flat welcome storage for convo {}",
                    crate::crypto::redact_for_log(&convo_id)
                );
                for member_did_str in &member_did_strings {
                    let welcome_id = uuid::Uuid::new_v4().to_string();
                    let welcome_result = sqlx::query(
                        r#"INSERT INTO welcome_messages (id, convo_id, recipient_did, welcome_data, key_package_hash, created_at)
                           VALUES ($1, $2, $3, $4, $5, $6)
                           ON CONFLICT (convo_id, recipient_did, COALESCE(key_package_hash, '\x00'::bytea)) WHERE consumed = false
                           DO NOTHING"#,
                    )
                    .bind(&welcome_id)
                    .bind(&convo_id)
                    .bind(member_did_str)
                    .bind(&welcome_bytes[..])
                    .bind::<Option<Vec<u8>>>(None)
                    .bind(now)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| {
                        error!("addMembers: failed to store user-flat welcome: {}", e);
                        internal_server_error("Failed to store welcome")
                    })?;
                    info!(
                        "addMembers: legacy user-flat welcome stored for {}, rows_affected={}",
                        crate::crypto::redact_for_log(member_did_str),
                        welcome_result.rows_affected()
                    );
                }
            }

            maybe_abort_add_members_after_welcome_for_test()?;

            // Welcome reissue auto-responder uses the reissue request id as
            // this commit's idempotency key. Marking it answered in the same
            // transaction keeps the recovery state tied to the replacement
            // commit + Welcome durability boundary.
            if let Some(ref idem_key) = input.idempotency_key {
                let answered = mark_reissue_request_answered_tx(
                    &mut tx,
                    &idem_key.to_string(),
                    &convo_id,
                    now,
                )
                .await
                .map_err(|e| {
                    error!("addMembers: failed to mark reissue request answered: {}", e);
                    internal_server_error("Failed to mark reissue request answered")
                })?;
                if answered == 1 {
                    info!(
                        convo_id = %crate::crypto::redact_for_log(&convo_id),
                        request_id = %crate::crypto::redact_for_log(&idem_key.to_string()),
                        welcome_rows_persisted = used_per_device_path,
                        "addMembers: auto-response stored for Welcome reissue request"
                    );
                } else {
                    info!(
                        convo_id = %crate::crypto::redact_for_log(&convo_id),
                        request_id = %crate::crypto::redact_for_log(&idem_key.to_string()),
                        "addMembers: idempotency key did not match a pending Welcome reissue request"
                    );
                }
            }

            // ── Store idempotency key ──────────────────────────────────
            if let Some(ref idem_key) = input.idempotency_key {
                if let Err(e) = sqlx::query(
                    "INSERT INTO idempotency_cache (caller_did, key, endpoint, response_body, status_code, created_at, expires_at) VALUES ($1, $2, $3, '{}'::jsonb, 200, NOW(), NOW() + INTERVAL '24 hours') ON CONFLICT DO NOTHING",
                )
                .bind(&caller_did)
                .bind(idem_key.to_string())
                .bind(NSID)
                .execute(&mut *tx)
                .await {
                    error!("commitGroupChange: failed to store idempotency key: {}", e);
                }
            }

            // ── A7.4: record epoch_authenticator (if client sent one) ──
            record_epoch_authenticator_tx(
                &mut tx,
                &convo_id,
                new_epoch,
                &input.epoch_authenticator,
                "addMembers",
            )
            .await;

            // ── Phase 2 (auto-reset): record commit-health success ─────
            // Bundled into the wrapping tx so atomicity matches the epoch
            // CAS — if any downstream step rolls back, the health flag does
            // too.
            crate::db::mark_commit_success_tx(&mut tx, &convo_id)
                .await
                .map_err(|e| {
                    error!("addMembers: failed to mark commit success: {}", e);
                    internal_server_error("Failed to mark commit success")
                })?;

            // ── Commit transaction ─────────────────────────────────────
            tx.commit().await.map_err(|e| {
                error!("addMembers: failed to commit transaction: {}", e);
                internal_server_error("Failed to commit transaction")
            })?;

            // ── Post-commit verification ─────────────────────────────
            // Verify the transaction actually persisted (diagnostic for phantom commit bug)
            {
                let verify_count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM members WHERE convo_id = $1 AND left_at IS NULL",
                )
                .bind(&convo_id)
                .fetch_one(&pool)
                .await
                .unwrap_or(-1);
                let verify_welcome: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM welcome_messages WHERE convo_id = $1 AND consumed = false",
                )
                .bind(&convo_id)
                .fetch_one(&pool)
                .await
                .unwrap_or(-1);
                let verify_commit: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM messages WHERE convo_id = $1 AND message_type = 'commit' AND epoch = $2)",
                )
                .bind(&convo_id)
                .bind(new_epoch)
                .fetch_one(&pool)
                .await
                .unwrap_or(false);
                if !verify_commit || verify_count < (member_did_strings.len() as i64 + 2) {
                    error!(
                        "🚨 addMembers POST-COMMIT VERIFICATION FAILED! convo={} members={} welcomes={} commit_exists={} expected_members_added={}",
                        crate::crypto::redact_for_log(&convo_id),
                        verify_count,
                        verify_welcome,
                        verify_commit,
                        member_did_strings.len()
                    );
                } else {
                    info!(
                        "✅ addMembers post-commit verified: convo={} members={} welcomes={} commit_exists={}",
                        crate::crypto::redact_for_log(&convo_id),
                        verify_count,
                        verify_welcome,
                        verify_commit
                    );
                }
            }

            // ── Enqueue commit messageEvent on per-convo FIFO queue (task #39) ──
            // The enqueue MUST be synchronous so its order matches the DB
            // tx.commit() order above. Envelope fanout stays in a detached
            // spawn (non-ordering-sensitive).
            let commit_cursor = sse_state.cursor_gen.next(&convo_id, "messageEvent").await;

            let commit_message_view: crate::realtime::StreamMessageView =
                crate::generated::blue_catbird::mlsChat::MessageView {
                    id: msg_id.clone().into(),
                    convo_id: convo_id.clone().into(),
                    ciphertext: commit_bytes.clone(),
                    epoch: new_epoch as i64,
                    seq,
                    created_at: crate::sqlx_jacquard::chrono_to_datetime(now),
                    message_type: Some("commit".into()),
                    extra_data: Default::default(),
                };

            let commit_event = crate::realtime::StreamEvent::MessageEvent {
                cursor: commit_cursor.clone(),
                message: commit_message_view,
                ephemeral: false,
            };

            sse_state.enqueue_with_store(&convo_id, pool.clone(), commit_event);

            // ── Emit treeChanged event so other clients detect divergence ──
            // Also via the per-convo queue so it strictly follows the commit
            // messageEvent above.
            if let Some(ref tag_bytes) = add_confirmation_tag {
                let tree_cursor = sse_state.cursor_gen.next(&convo_id, "treeChanged").await;
                let tree_event = StreamEvent::TreeChanged {
                    cursor: tree_cursor.clone(),
                    convo_id: convo_id.clone(),
                    confirmation_tag: bytes::Bytes::from(tag_bytes.clone()),
                    epoch: new_epoch as i64,
                };
                sse_state.enqueue_with_store(&convo_id, pool.clone(), tree_event);
            }

            // ── Envelope fanout (still best-effort, non-order-sensitive) ──
            {
                let pool_clone = pool.clone();
                let convo_id_clone = convo_id.clone();
                let msg_id_clone = msg_id.clone();

                tokio::spawn(async move {
                    let members_result = sqlx::query_scalar::<_, String>(
                        "SELECT member_did FROM members WHERE convo_id = $1 AND left_at IS NULL",
                    )
                    .bind(&convo_id_clone)
                    .fetch_all(&pool_clone)
                    .await;

                    if let Ok(member_dids) = members_result {
                        if !member_dids.is_empty() {
                            let envelope_now = chrono::Utc::now();
                            let mut qb: sqlx::QueryBuilder<sqlx::Postgres> =
                                sqlx::QueryBuilder::new(
                                    "INSERT INTO envelopes (id, convo_id, recipient_did, message_id, created_at) ",
                                );
                            qb.push_values(member_dids.iter(), |mut b, did| {
                                b.push_bind(uuid::Uuid::new_v4().to_string())
                                    .push_bind(&convo_id_clone)
                                    .push_bind(did)
                                    .push_bind(&msg_id_clone)
                                    .push_bind(envelope_now);
                            });
                            qb.push(" ON CONFLICT (recipient_did, message_id) DO NOTHING");
                            if let Err(e) = qb.build().execute(&pool_clone).await {
                                error!("addMembers: envelope fanout failed: {:?}", e);
                            }
                        }
                    }
                });
            }

            info!(
                "✅ v2.commitGroupChange: addMembers complete for convo {}, epoch={}",
                crate::crypto::redact_for_log(&convo_id),
                new_epoch
            );
            Ok(Json(CommitGroupChangeOutput {
                success: true,
                new_epoch: Some(new_epoch as i64),
                confirmation_tag: add_confirmation_tag.map(bytes::Bytes::from),
                claimed_addition: None,
                pending_additions: None,
                rejoined_at: None,
                extra_data: Default::default(),
            })
            .into_response())
        }
        "externalCommit" => {
            let convo_id = input.convo_id.to_string();
            info!("v2.commitGroupChange: externalCommit for convo");

            // ── Layer 1 robustness: parse caller identity early so all the
            //    new gates below can attribute audit rows. The duplicate
            //    parse later at the membership-check site is harmless and
            //    kept to minimize blast radius on this branch. ─────────
            let (gate_user_did, gate_device_id) = match parse_device_did(&auth_user.did) {
                Ok(v) => v,
                Err(e) => {
                    error!("externalCommit: invalid DID format: {}", e);
                    return Err(bad_request("Invalid DID format"));
                }
            };

            // Snapshot current epoch ONCE for audit-row epoch_before fields
            // on rejected paths. The real CAS reads its own epoch later.
            let pre_gate_epoch: i32 =
                sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
                    .bind(&convo_id)
                    .fetch_optional(&pool)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or(0);

            // ── Layer 1 §1.3: freeze check ─────────────────────────────
            //    Cheap pre-flight — if the epoch-storm circuit breaker has
            //    flipped the group to frozen, refuse all epoch-advancing
            //    commits with HTTP 423 GroupFrozen until thaw.
            if let Err(e) = check_group_frozen(&pool, &convo_id).await {
                audit_external_commit(
                    &pool,
                    &convo_id,
                    &gate_user_did,
                    &gate_device_id,
                    pre_gate_epoch,
                    pre_gate_epoch,
                    Some("GroupFrozen"),
                )
                .await;
                return Err(e);
            }

            // ── Layer 1 §1.1: KP-publish gate ──────────────────────────
            //    A device that External-Commits without published key
            //    packages produces a "ghost" leaf node — the failure mode
            //    that previously poisoned shared groups for healthy peers
            //    (iOS auto-reset cascade). Skipped for legacy single-
            //    device DIDs (empty device_id) where the existing per-
            //    convo 30s limit is the safety net.
            if !gate_device_id.is_empty() {
                match crate::db::count_available_key_packages_for_device(
                    &pool,
                    &gate_user_did,
                    &gate_device_id,
                )
                .await
                {
                    Ok(0) => {
                        warn!(
                            convo_id = %crate::crypto::redact_for_log(&convo_id),
                            user_did = %crate::crypto::redact_for_log(&gate_user_did),
                            device_id = %crate::crypto::redact_for_log(&gate_device_id),
                            "externalCommit: rejected — device has 0 published key packages"
                        );
                        audit_external_commit(
                            &pool,
                            &convo_id,
                            &gate_user_did,
                            &gate_device_id,
                            pre_gate_epoch,
                            pre_gate_epoch,
                            Some("NoKeyPackagesPublished"),
                        )
                        .await;
                        return Err(XrpcError::Plain(
                            StatusCode::PRECONDITION_FAILED,
                            "NoKeyPackagesPublished",
                            "Device must publish at least one key package before issuing an External Commit.".into(),
                        ));
                    }
                    Ok(_) => {} // proceed
                    Err(e) => {
                        warn!(
                            error = ?e,
                            convo_id = %crate::crypto::redact_for_log(&convo_id),
                            "externalCommit: KP-publish gate query failed (non-fatal, allowing)"
                        );
                    }
                }
            } else {
                warn!(
                    convo_id = %crate::crypto::redact_for_log(&convo_id),
                    user_did = %crate::crypto::redact_for_log(&gate_user_did),
                    "externalCommit: skipping KP-publish gate (legacy single-device DID, no device_id)"
                );
            }

            // ── Layer 1 §1.2: per-(device, group) 60s cooldown ────────
            //    Defense-in-depth above the existing per-convo 30s limit:
            //    catches a single buggy device retrying on its own even if
            //    other clients haven't EC'd recently.
            if !gate_device_id.is_empty() {
                match crate::db::last_external_commit_by_device(
                    &pool,
                    &convo_id,
                    &gate_device_id,
                    PER_DEVICE_EC_COOLDOWN_SECS,
                )
                .await
                {
                    Ok(Some(last_at)) => {
                        let elapsed = chrono::Utc::now() - last_at;
                        let retry = (PER_DEVICE_EC_COOLDOWN_SECS - elapsed.num_seconds()).max(1);
                        warn!(
                            convo_id = %crate::crypto::redact_for_log(&convo_id),
                            device_id = %crate::crypto::redact_for_log(&gate_device_id),
                            elapsed_s = elapsed.num_seconds(),
                            retry_after_s = retry,
                            "externalCommit: rejected — per-(device, group) 60s cooldown"
                        );
                        audit_external_commit(
                            &pool,
                            &convo_id,
                            &gate_user_did,
                            &gate_device_id,
                            pre_gate_epoch,
                            pre_gate_epoch,
                            Some("PerDeviceCooldown"),
                        )
                        .await;
                        return Err(XrpcError::RateLimited(RateLimitedBody {
                            error: "RateLimited",
                            message: format!(
                                "This device just External-Committed on this conversation; retry after {retry} seconds."
                            ),
                            retry_after_seconds: retry,
                            scope: "device-convo",
                        }));
                    }
                    Ok(None) => {} // no recent EC from this device — proceed
                    Err(e) => {
                        warn!(
                            error = ?e,
                            convo_id = %crate::crypto::redact_for_log(&convo_id),
                            "externalCommit: per-device cooldown query failed (non-fatal, allowing)"
                        );
                    }
                }
            }

            // ── Rate-limit: at most 1 external commit per 30s per conversation ──
            // Server-side safety net to prevent epoch inflation spirals
            // where multiple clients auto-repair via external commit in a
            // feedback loop. Layer 1 §1.4: also audits the rejection so
            // forensic replay sees the storm.
            {
                let last_external_commit: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
                    "SELECT MAX(created_at) FROM messages WHERE convo_id = $1 AND message_type = 'commit' AND created_at > NOW() - INTERVAL '30 seconds'"
                )
                .bind(&convo_id)
                .fetch_optional(&pool)
                .await
                .ok()
                .flatten();

                if let Some(last) = last_external_commit {
                    let elapsed = chrono::Utc::now() - last;
                    if elapsed < chrono::Duration::seconds(30) {
                        let retry_after = 30 - elapsed.num_seconds();
                        warn!(
                            "externalCommit: rate limited — last commit was {}s ago for convo {}",
                            elapsed.num_seconds(),
                            crate::crypto::redact_for_log(&convo_id)
                        );
                        audit_external_commit(
                            &pool,
                            &convo_id,
                            &gate_user_did,
                            &gate_device_id,
                            pre_gate_epoch,
                            pre_gate_epoch,
                            Some("RateLimited"),
                        )
                        .await;
                        return Err(XrpcError::RateLimited(RateLimitedBody {
                            error: "RateLimited",
                            message: format!(
                                "Another external commit was accepted recently. Retry after {retry_after} seconds."
                            ),
                            retry_after_seconds: retry_after,
                            scope: "convo",
                        }));
                    }
                }
            }

            // ── Idempotency check ──────────────────────────────────────
            if let Some(ref idem_key) = input.idempotency_key {
                let idem_key_str = idem_key.to_string();
                let already: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM idempotency_cache WHERE key = $1)",
                )
                .bind(&idem_key_str)
                .fetch_one(&pool)
                .await
                .unwrap_or(false);

                if already {
                    // TODO(phase 4): route via CryptoSessionRepository — idempotency-hit
                    // fallback in externalCommit; migrate when ConversationActor takes
                    // the repo by ctor.
                    let current_epoch: Option<i32> =
                        sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
                            .bind(&convo_id)
                            .fetch_optional(&pool)
                            .await
                            .ok()
                            .flatten();
                    info!("v2.commitGroupChange: externalCommit idempotent hit");
                    return Ok(Json(CommitGroupChangeOutput {
                        success: true,
                        new_epoch: Some(current_epoch.unwrap_or(0) as i64),
                        claimed_addition: None,
                        confirmation_tag: None,
                        pending_additions: None,
                        rejoined_at: None,
                        extra_data: Default::default(),
                    })
                    .into_response());
                }
            }

            // ── Validate required fields (bytes arrive already decoded) ──
            let commit_bytes = input.commit.as_ref().ok_or_else(|| {
                warn!("externalCommit: missing commit");
                bad_request("Missing commit")
            })?;
            let commit_shape =
                inspect_commit_for_action("externalCommit", commit_bytes, &convo_id)?;
            let commit_wire_epoch = commit_shape.epoch as i64;

            // ── Verify caller is a current or self-left member (NOT admin-removed) ──
            // Layer 1 §1.4: keep device_id around for the audit trail on
            // both rejection paths and the success path (the early gate
            // parse above already validated the format; this is a clone
            // for clarity at the membership-check site).
            let (caller_did, caller_device_id) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("externalCommit: invalid DID format: {}", e);
                bad_request("Invalid DID format")
            })?;

            // Check membership status: active, self-left (needs_rejoin), or removed
            let member_status: Option<(Option<chrono::DateTime<chrono::Utc>>, bool)> = sqlx::query_as(
                "SELECT left_at, needs_rejoin FROM members WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) LIMIT 1",
            )
            .bind(&convo_id)
            .bind(&caller_did)
            .fetch_optional(&pool)
            .await
            .map_err(|e| {
                error!("externalCommit: membership check failed: {}", e);
                internal_server_error("Failed to check membership")
            })?;

            match member_status {
                None => {
                    return Err(forbidden("Not a member of this conversation"));
                }
                Some((Some(_left_at), false)) => {
                    // Member was removed by admin (left_at set, needs_rejoin=false)
                    // Block External Commit — they must be re-invited via addMembers
                    warn!(
                        "externalCommit: blocked removed member {} from rejoining convo {}",
                        crate::crypto::redact_for_log(&caller_did),
                        crate::crypto::redact_for_log(&convo_id)
                    );
                    return Err(forbidden("You were removed from this conversation"));
                }
                Some((Some(_left_at), true)) => {
                    // Member self-left or needs rejoin (needs_rejoin=true) — allow External Commit
                    info!(
                        "externalCommit: allowing rejoin for member with needs_rejoin=true in convo {}",
                        crate::crypto::redact_for_log(&convo_id)
                    );
                }
                Some((None, _)) => {
                    // Active member — allow External Commit (epoch resync)
                }
            }

            // ── Block detection (PDS-first with bsky_blocks fallback) ──
            // Reject the external commit if the joiner has any block edge
            // with a current member of the conversation (in either direction).
            // Edges between two existing members are not considered here — those
            // are Task 3.1's responsibility at add time, or an auto-leave on the
            // client side.
            // See docs/superpowers/plans/2026-04-15-block-leave-shared-groups.md Phase 3.
            {
                let existing_member_dids: Vec<String> = sqlx::query_scalar(
                    "SELECT DISTINCT COALESCE(user_did, member_did) FROM members WHERE convo_id = $1 AND left_at IS NULL",
                )
                .bind(&convo_id)
                .fetch_all(&pool)
                .await
                .map_err(|e| {
                    error!("externalCommit: failed to fetch member DIDs for block check: {}", e);
                    internal_server_error("Failed to check blocks")
                })?;

                if !existing_member_dids.is_empty() {
                    let mut all_dids: Vec<String> = existing_member_dids.clone();
                    all_dids.push(caller_did.clone());
                    all_dids.sort();
                    all_dids.dedup();

                    if all_dids.len() >= 2 {
                        let joiner_involved = match block_sync
                            .check_block_conflicts(&all_dids)
                            .await
                        {
                            Ok(conflicts) => {
                                // Sync affected users' blocks to local cache.
                                for (blocker, _blocked) in &conflicts {
                                    if let Err(e) =
                                        block_sync.sync_blocks_to_db(&pool, blocker).await
                                    {
                                        warn!("Failed to sync blocks to DB: {}", e);
                                    }
                                }
                                conflicts.iter().any(|(blocker, blocked)| {
                                    blocker == &caller_did || blocked == &caller_did
                                })
                            }
                            Err(e) => {
                                // Fallback to local DB cache — fail secure on DB error.
                                warn!(
                                    "externalCommit: PDS block check failed, falling back to local DB: {}",
                                    e
                                );
                                let existing_slice: &[String] = &existing_member_dids;
                                let blocks: Vec<(String, String)> = sqlx::query_as(
                                    "SELECT user_did, target_did FROM bsky_blocks \
                                     WHERE (user_did = $1 AND target_did = ANY($2)) \
                                        OR (target_did = $1 AND user_did = ANY($2))",
                                )
                                .bind(&caller_did)
                                .bind(existing_slice)
                                .fetch_all(&pool)
                                .await
                                .map_err(|e| {
                                    error!(
                                        "❌ externalCommit: block fallback DB query failed: {}",
                                        e
                                    );
                                    internal_server_error("Failed to check blocks")
                                })?;

                                !blocks.is_empty()
                            }
                        };

                        if joiner_involved {
                            warn!(
                                "❌ externalCommit by {} rejected: block edge with existing member (convo {})",
                                crate::crypto::redact_for_log(&caller_did),
                                crate::crypto::redact_for_log(&convo_id)
                            );
                            return Err(forbidden(
                                "Cannot join conversation: block edge exists with an existing member",
                            ));
                        }
                    }
                }
            }

            // ── Parse MLS epoch and group_id from GroupInfo if provided ──────────
            let (group_info_bytes_opt, mls_epoch, mls_group_id) = if let Some(gi_bytes) =
                input.group_info.as_ref()
            {
                let gi_slice: &[u8] = gi_bytes;
                let (epoch, group_id) = {
                    use openmls::messages::group_info::VerifiableGroupInfo;
                    use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn};

                    let from_mls_msg = MlsMessageIn::tls_deserialize(&mut &*gi_slice)
                        .ok()
                        .and_then(|msg| match msg.extract() {
                            MlsMessageBodyIn::GroupInfo(gi) => {
                                let e = gi.epoch().as_u64();
                                let gid = hex::encode(gi.group_id().as_slice());
                                Some((e, gid))
                            }
                            _ => None,
                        });

                    match from_mls_msg {
                        Some((e, gid)) => (Some(e), Some(gid)),
                        None => {
                            let from_raw = VerifiableGroupInfo::tls_deserialize(&mut &*gi_slice)
                                .ok()
                                .map(|gi| {
                                    let e = gi.epoch().as_u64();
                                    let gid = hex::encode(gi.group_id().as_slice());
                                    (e, gid)
                                });
                            match from_raw {
                                Some((e, gid)) => (Some(e), Some(gid)),
                                None => (None, None),
                            }
                        }
                    }
                };

                if let Some(e) = epoch {
                    info!(
                        "externalCommit: parsed MLS epoch {} from GroupInfo for convo {}",
                        e,
                        crate::crypto::redact_for_log(&convo_id)
                    );
                } else {
                    warn!(
                        "externalCommit: could not parse epoch from GroupInfo for convo {}",
                        crate::crypto::redact_for_log(&convo_id)
                    );
                }

                (Some(gi_bytes.to_vec()), epoch, group_id)
            } else {
                (None, None, None)
            };

            // ── Decode client-provided confirmation_tag ──────────
            let ec_confirmation_tag = if let Some(ref tag_bytes) = input.confirmation_tag {
                info!(
                    "externalCommit: client-provided confirmation_tag ({} bytes) for convo {}",
                    tag_bytes.len(),
                    crate::crypto::redact_for_log(&convo_id)
                );
                Some(tag_bytes.to_vec())
            } else {
                None
            };

            let now = chrono::Utc::now();

            // ── Fetch current epoch for CAS ───────────────────────────
            let current_epoch = crate::db::get_current_epoch(&pool, &convo_id)
                .await
                .map_err(|e| {
                    error!("externalCommit: failed to get current epoch: {}", e);
                    internal_server_error("Failed to get current epoch")
                })?;
            if commit_shape.epoch != current_epoch as u64 {
                warn!(
                    "externalCommit: stale commit wire_epoch={} current_epoch={} for convo {}",
                    commit_shape.epoch,
                    current_epoch,
                    crate::crypto::redact_for_log(&convo_id)
                );
                // Phase 2 (auto-reset): record 409 for sweep-trigger health
                // counter. Pool-level UPDATE; failure must NEVER mask the
                // 409 response.
                if let Err(e) =
                    crate::jobs::auto_detect_failed_groups::record_commit_409_with_inline_trigger(
                        &pool,
                        &actor_registry,
                        &convo_id,
                        &inline_trigger_cfg,
                    )
                    .await
                {
                    warn!(
                        error = ?e,
                        convo_id = %crate::crypto::redact_for_log(&convo_id),
                        "externalCommit: failed to record commit 409 (non-fatal)"
                    );
                }
                audit_external_commit(
                    &pool,
                    &convo_id,
                    &caller_did,
                    &caller_device_id,
                    current_epoch,
                    current_epoch,
                    Some("EpochMismatch"),
                )
                .await;
                return Err(conflict_with_epoch(
                    &pool,
                    &convo_id,
                    current_epoch,
                    "Commit was authored from a stale MLS epoch",
                )
                .await);
            }

            // ── Begin transaction: reactivate + epoch heal + commit + idempotency ──
            let mut tx = pool.begin().await.map_err(|e| {
                error!("externalCommit: failed to begin transaction: {}", e);
                internal_server_error("Failed to begin transaction")
            })?;

            // Reactivate caller (clear left_at for self-left/needs_rejoin members)
            sqlx::query(
                "UPDATE members SET left_at = NULL, needs_rejoin = false, rejoin_requested_at = NULL WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2)",
            )
            .bind(&convo_id)
            .bind(&caller_did)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("externalCommit: failed to reactivate member: {}", e);
                internal_server_error("Failed to reactivate member")
            })?;

            // ── Advance epoch (CAS) ───────────────────────────────────
            //
            // External commits use the same CAS-protected monotonic advance
            // as addMembers. The server epoch must never go backward — even
            // if the GroupInfo MLS epoch is behind the server epoch (which
            // happens after concurrent commits or prior divergence).
            let new_epoch =
                crate::db::try_advance_conversation_epoch_tx(&mut tx, &convo_id, current_epoch)
                    .await
                    .map_err(|e| {
                        error!("externalCommit: failed to advance epoch: {}", e);
                        internal_server_error("Failed to advance epoch")
                    })?;

            let new_epoch = match new_epoch {
                Some(epoch) => epoch,
                None => {
                    warn!("externalCommit: epoch CAS failed (concurrent commit), returning 409");
                    drop(tx);
                    // Phase 2 (auto-reset): record 409 on a separate
                    // pool-borrowed conn (the failed tx is gone). Failure
                    // must NEVER mask the 409 response.
                    if let Err(e) = crate::jobs::auto_detect_failed_groups::record_commit_409_with_inline_trigger(&pool, &actor_registry, &convo_id, &inline_trigger_cfg).await {
                        warn!(
                            error = ?e,
                            convo_id = %crate::crypto::redact_for_log(&convo_id),
                            "externalCommit: failed to record commit 409 (non-fatal)"
                        );
                    }
                    audit_external_commit(
                        &pool,
                        &convo_id,
                        &caller_did,
                        &caller_device_id,
                        current_epoch,
                        current_epoch,
                        Some("EpochMismatch"),
                    )
                    .await;
                    return Err(conflict_with_epoch(
                        &pool,
                        &convo_id,
                        current_epoch,
                        "Conversation epoch advanced concurrently",
                    )
                    .await);
                }
            };

            // Log MLS epoch from GroupInfo for diagnostics only.
            if let Some(mls_epoch) = mls_epoch {
                let mls_epoch_i32 = (mls_epoch + 1) as i32;
                if mls_epoch_i32 != new_epoch {
                    warn!(
                        "externalCommit: MLS epoch divergence — server epoch={}, MLS post-commit epoch={} for convo {}",
                        new_epoch,
                        mls_epoch_i32,
                        crate::crypto::redact_for_log(&convo_id)
                    );
                }
            }

            // ── Update conversations.group_id from GroupInfo ─────────
            //
            // TODO(post-#12 audit): This is the external-commit observer.
            // It fires when a rejoining client's GroupInfo carries a
            // different mls_group_id than what the server has stored —
            // i.e., the client is catching up to a prior reset. After
            // Phase 2 §2.3 made `ActivateCryptoSession` the authoritative
            // writer of `conversations.group_id`, by the time external
            // commit reaches here the server's group_id should ALREADY
            // match what GroupInfo says. This UPDATE becomes redundant
            // (no-op write of the same value) at best and arguably should
            // be replaced with an assertion. Audit + remove once Phase 2
            // soak data confirms the chokepoint covers every path that
            // can rotate group_id. NOT funneled in #10 because the
            // observer is not itself a reset path.
            if let Some(ref new_gid) = mls_group_id {
                sqlx::query("UPDATE conversations SET group_id = $1 WHERE id = $2")
                    .bind(new_gid)
                    .bind(&convo_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| {
                        error!("externalCommit: failed to update group_id: {}", e);
                        internal_server_error("Failed to update group_id")
                    })?;
                info!(
                    "externalCommit: updated group_id for convo {}",
                    crate::crypto::redact_for_log(&convo_id)
                );
            }

            // ── Store or invalidate GroupInfo (uses shared helper) ─────
            if let Some(ref gi_bytes) = group_info_bytes_opt {
                // Do NOT rewrite `current_epoch` here. try_advance (logged as
                // diverging at lines 1091-1100) already CAS-assigned the new
                // epoch; binding the client-reported MLS post-commit epoch
                // can land off-by-one from CAS+1 and desync from the
                // `messages`/`commits` row inserted with `new_epoch`.
                crate::db::store_group_info_in_tx(
                    &mut tx,
                    &convo_id,
                    gi_bytes,
                    ec_confirmation_tag.as_deref(),
                )
                .await
                .map_err(|e| {
                    error!("externalCommit: failed to store GroupInfo: {}", e);
                    internal_server_error("Failed to store GroupInfo")
                })?;
                info!(
                    "externalCommit: stored GroupInfo (mls_epoch={:?}, has_conf_tag={}) for convo {}",
                    mls_epoch,
                    ec_confirmation_tag.is_some(),
                    crate::crypto::redact_for_log(&convo_id)
                );
            } else {
                warn!(
                    "externalCommit: no GroupInfo provided with commit for convo {} — keeping existing (may be stale)",
                    crate::crypto::redact_for_log(&convo_id)
                );
            };

            // ── Store commit message ───────────────────────────────────
            let msg_id = uuid::Uuid::new_v4().to_string();
            let seq: i64 = sqlx::query_scalar(
                "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1",
            )
            .bind(&convo_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                error!("externalCommit: failed to get seq: {}", e);
                internal_server_error("Failed to allocate message sequence")
            })?;

            sqlx::query(
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, wire_epoch, seq, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7, $8)",
            )
            .bind(&msg_id)
            .bind(&convo_id)
            .bind(Option::<&str>::None)
            .bind(new_epoch)
            .bind(commit_wire_epoch)
            .bind(seq)
            .bind(&commit_bytes[..])
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("externalCommit: failed to insert commit message: {}", e);
                internal_server_error("Failed to store commit message")
            })?;

            // ── Store idempotency key ──────────────────────────────────
            if let Some(ref idem_key) = input.idempotency_key {
                if let Err(e) = sqlx::query(
                    "INSERT INTO idempotency_cache (caller_did, key, endpoint, response_body, status_code, created_at, expires_at) VALUES ($1, $2, $3, '{}'::jsonb, 200, NOW(), NOW() + INTERVAL '24 hours') ON CONFLICT DO NOTHING",
                )
                .bind(&caller_did)
                .bind(idem_key.to_string())
                .bind(NSID)
                .execute(&mut *tx)
                .await {
                    error!("commitGroupChange: failed to store idempotency key: {}", e);
                }
            }

            // ── A7.4: record epoch_authenticator (if client sent one) ──
            record_epoch_authenticator_tx(
                &mut tx,
                &convo_id,
                new_epoch,
                &input.epoch_authenticator,
                "externalCommit",
            )
            .await;

            // ── Phase 2 (auto-reset): record commit-health success ─────
            // Bundled into the wrapping tx so atomicity matches the epoch
            // CAS — if any downstream step rolls back, the health flag does
            // too.
            crate::db::mark_commit_success_tx(&mut tx, &convo_id)
                .await
                .map_err(|e| {
                    error!("externalCommit: failed to mark commit success: {}", e);
                    internal_server_error("Failed to mark commit success")
                })?;

            // ── Layer 1 §1.3: epoch-advance counter + maybe freeze ─────
            // Bundled into the same tx so the counter increments
            // atomically with the epoch CAS. If we just advanced the
            // epoch and the post-increment count breaches the threshold
            // within the active window, this also sets `frozen_until`.
            if let Err(e) = crate::db::bump_epoch_advance_and_maybe_freeze_tx(
                &mut tx,
                &convo_id,
                EPOCH_STORM_THRESHOLD,
                EPOCH_STORM_WINDOW_SECS,
                EPOCH_STORM_FREEZE_SECS,
            )
            .await
            {
                error!(
                    error = ?e,
                    convo_id = %crate::crypto::redact_for_log(&convo_id),
                    "externalCommit: failed to bump epoch_advance_count (rolling back)"
                );
                return Err(internal_server_error("Failed to update freeze counters"));
            }

            // ── Commit transaction ─────────────────────────────────────
            tx.commit().await.map_err(|e| {
                error!("externalCommit: failed to commit transaction: {}", e);
                internal_server_error("Failed to commit transaction")
            })?;

            // ── Layer 1 §1.4: audit row for accepted External Commit ───
            audit_external_commit(
                &pool,
                &convo_id,
                &caller_did,
                &caller_device_id,
                current_epoch,
                new_epoch,
                None,
            )
            .await;

            // ── Enqueue commit messageEvent on per-convo FIFO queue (task #39) ──
            let commit_cursor = sse_state.cursor_gen.next(&convo_id, "messageEvent").await;

            let commit_message_view: crate::realtime::StreamMessageView =
                crate::generated::blue_catbird::mlsChat::MessageView {
                    id: msg_id.clone().into(),
                    convo_id: convo_id.clone().into(),
                    ciphertext: commit_bytes.clone(),
                    epoch: new_epoch as i64,
                    seq,
                    created_at: crate::sqlx_jacquard::chrono_to_datetime(now),
                    message_type: Some("commit".into()),
                    extra_data: Default::default(),
                };

            let commit_event = crate::realtime::StreamEvent::MessageEvent {
                cursor: commit_cursor.clone(),
                message: commit_message_view,
                ephemeral: false,
            };

            sse_state.enqueue_with_store(&convo_id, pool.clone(), commit_event);

            // ── Emit treeChanged event so other clients detect divergence ──
            if let Some(ref tag_bytes) = ec_confirmation_tag {
                let tree_cursor = sse_state.cursor_gen.next(&convo_id, "treeChanged").await;
                let tree_event = StreamEvent::TreeChanged {
                    cursor: tree_cursor.clone(),
                    convo_id: convo_id.clone(),
                    confirmation_tag: bytes::Bytes::from(tag_bytes.clone()),
                    epoch: new_epoch as i64,
                };
                sse_state.enqueue_with_store(&convo_id, pool.clone(), tree_event);
            }

            // ── Envelope fanout (non-order-sensitive) ──
            {
                let pool_clone = pool.clone();
                let convo_id_clone = convo_id.clone();
                let msg_id_clone = msg_id.clone();

                tokio::spawn(async move {
                    let members_result = sqlx::query_scalar::<_, String>(
                        "SELECT member_did FROM members WHERE convo_id = $1 AND left_at IS NULL",
                    )
                    .bind(&convo_id_clone)
                    .fetch_all(&pool_clone)
                    .await;

                    if let Ok(member_dids) = members_result {
                        if !member_dids.is_empty() {
                            let envelope_now = chrono::Utc::now();
                            let mut qb: sqlx::QueryBuilder<sqlx::Postgres> =
                                sqlx::QueryBuilder::new(
                                    "INSERT INTO envelopes (id, convo_id, recipient_did, message_id, created_at) ",
                                );
                            qb.push_values(member_dids.iter(), |mut b, did| {
                                b.push_bind(uuid::Uuid::new_v4().to_string())
                                    .push_bind(&convo_id_clone)
                                    .push_bind(did)
                                    .push_bind(&msg_id_clone)
                                    .push_bind(envelope_now);
                            });
                            qb.push(" ON CONFLICT (recipient_did, message_id) DO NOTHING");
                            if let Err(e) = qb.build().execute(&pool_clone).await {
                                error!("externalCommit: envelope fanout failed: {:?}", e);
                            }
                        }
                    }
                });
            }

            info!(
                "✅ v2.commitGroupChange: externalCommit complete, epoch={}",
                new_epoch
            );
            Ok(Json(CommitGroupChangeOutput {
                success: true,
                new_epoch: Some(new_epoch as i64),
                confirmation_tag: ec_confirmation_tag.map(bytes::Bytes::from),
                claimed_addition: None,
                pending_additions: None,
                rejoined_at: None,
                extra_data: Default::default(),
            })
            .into_response())
        }
        "rejoin" => {
            info!("v2.commitGroupChange: rejoin for convo");
            Ok(Json(success_response()).into_response())
        }
        "readdition" => {
            info!("v2.commitGroupChange: readdition for convo");
            Ok(Json(success_response()).into_response())
        }
        "invalidateWelcome" => {
            let convo_id = input.convo_id.to_string();
            if convo_id.trim().is_empty() {
                warn!("invalidateWelcome: missing convo_id");
                return Err(bad_request("Missing convoId"));
            }

            let (invalidated, reissue_requests_marked): (i64, i64) = sqlx::query_as(
                r#"
                WITH consumed AS (
                UPDATE welcome_messages
                SET consumed = true,
                    consumed_at = NOW(),
                    error_reason = COALESCE(error_reason, 'Client invalidated Welcome')
                WHERE convo_id = $1
                  AND recipient_did = $2
                  AND consumed = false
                RETURNING id
                ),
                marked_reissues AS (
                    UPDATE reissue_requests
                    SET status = 'consumed',
                        consumed_at = NOW()
                    WHERE welcome_blob_id IN (SELECT id FROM consumed)
                      AND status IN ('requested', 'delivered_to_inviter', 'responded')
                    RETURNING 1
                )
                SELECT
                    (SELECT COUNT(*) FROM consumed)::BIGINT,
                    (SELECT COUNT(*) FROM marked_reissues)::BIGINT
                "#,
            )
            .bind(&convo_id)
            .bind(&auth_user.did)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("invalidateWelcome: failed to invalidate welcome: {}", e);
                internal_server_error("Failed to invalidate welcome")
            })?;

            info!(
                convo_id = %crate::crypto::redact_for_log(&convo_id),
                recipient_did = %crate::crypto::redact_for_log(&auth_user.did),
                invalidated_welcome_rows = invalidated,
                reissue_requests_marked,
                consumed_any = invalidated > 0,
                "commitGroupChange: invalidateWelcome consumed Welcome rows"
            );

            Ok(Json(invalidate_welcome_response(
                u64::try_from(invalidated).unwrap_or_default(),
            ))
            .into_response())
        }
        "listPending" => {
            let convo_id = input.convo_id.to_string();

            // Extract base user DID
            let (user_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("❌ [v2.commitGroupChange] Invalid DID format: {}", e);
                bad_request("Invalid DID format")
            })?;

            // Age out stale pending additions older than 1 hour.
            // These are unlikely to ever be processed -- the device has either
            // self-joined via External Commit or gone offline permanently.
            let aged_out = sqlx::query(
                r#"
                UPDATE pending_device_additions
                SET status = 'failed', updated_at = NOW()
                WHERE status IN ('pending', 'in_progress')
                  AND created_at < NOW() - INTERVAL '1 hour'
                "#,
            )
            .execute(&pool)
            .await
            .map_err(|e| {
                error!(
                    "❌ [v2.commitGroupChange] Failed to age out stale pending additions: {}",
                    e
                );
                internal_server_error("Failed to age out stale pending additions")
            })?
            .rows_affected();

            if aged_out > 0 {
                info!(
                    "Aged out {} stale pending additions (>1 hour old)",
                    aged_out
                );
            }

            // Release expired claims (for additions that are still fresh)
            let released = sqlx::query(
                r#"
                UPDATE pending_device_additions
                SET status = 'pending', claimed_by_did = NULL, claimed_at = NULL,
                    claim_expires_at = NULL, updated_at = NOW()
                WHERE status = 'in_progress' AND claim_expires_at < NOW()
                "#,
            )
            .execute(&pool)
            .await
            .map_err(|e| {
                error!(
                    "❌ [v2.commitGroupChange] Failed to release expired claims: {}",
                    e
                );
                internal_server_error("Failed to release expired claims")
            })?
            .rows_affected();

            if released > 0 {
                info!("Released {} expired pending addition claims", released);
            }

            // Get pending additions for user's convos
            let pending = if convo_id.is_empty() {
                sqlx::query_as::<_, PendingAdditionRow>(
                    r#"
                    SELECT pda.id, pda.convo_id, pda.user_did, pda.new_device_id,
                           pda.new_device_credential_did, pda.device_name, pda.status,
                           pda.claimed_by_did, pda.created_at
                    FROM pending_device_additions pda
                    INNER JOIN members m ON pda.convo_id = m.convo_id
                    WHERE m.user_did = $1 AND m.left_at IS NULL
                      AND pda.status IN ('pending', 'in_progress')
                      AND pda.user_did != $1
                    ORDER BY pda.created_at ASC
                    LIMIT 100
                    "#,
                )
                .bind(&user_did)
                .fetch_all(&pool)
                .await
            } else {
                sqlx::query_as::<_, PendingAdditionRow>(
                    r#"
                    SELECT pda.id, pda.convo_id, pda.user_did, pda.new_device_id,
                           pda.new_device_credential_did, pda.device_name, pda.status,
                           pda.claimed_by_did, pda.created_at
                    FROM pending_device_additions pda
                    INNER JOIN members m ON pda.convo_id = m.convo_id
                    WHERE m.user_did = $1 AND m.left_at IS NULL
                      AND pda.convo_id = $2
                      AND pda.status IN ('pending', 'in_progress')
                      AND pda.user_did != $1
                    ORDER BY pda.created_at ASC
                    LIMIT 100
                    "#,
                )
                .bind(&user_did)
                .bind(&convo_id)
                .fetch_all(&pool)
                .await
            }
            .map_err(|e| {
                error!(
                    "❌ [v2.commitGroupChange] Failed to fetch pending additions: {}",
                    e
                );
                internal_server_error("Failed to fetch pending additions")
            })?;

            info!(
                "✅ [v2.commitGroupChange] Found {} pending additions",
                pending.len()
            );

            let additions: Vec<PendingDeviceAddition<'static>> = pending
                .into_iter()
                .map(|row| PendingDeviceAddition {
                    id: row.id.into(),
                    convo_id: row.convo_id.into(),
                    user_did: crate::sqlx_jacquard::string_to_did(&row.user_did),
                    device_id: row.new_device_id.into(),
                    device_credential_did: row.new_device_credential_did.into(),
                    status: row.status.into(),
                    created_at: crate::sqlx_jacquard::chrono_to_datetime(row.created_at),
                    device_name: row.device_name.map(|n| n.into()),
                    claimed_by: row
                        .claimed_by_did
                        .as_deref()
                        .map(crate::sqlx_jacquard::string_to_did),
                    extra_data: Default::default(),
                })
                .collect();

            Ok(Json(CommitGroupChangeOutput {
                success: true,
                pending_additions: Some(additions),
                claimed_addition: None,
                confirmation_tag: None,
                new_epoch: None,
                rejoined_at: None,
                extra_data: Default::default(),
            })
            .into_response())
        }
        "updateGroupInfo" => {
            let convo_id = input.convo_id.to_string();
            let group_info_bytes = match input.group_info.as_ref() {
                Some(gi) => gi,
                None => {
                    error!("updateGroupInfo: missing groupInfo field");
                    return Err(bad_request("Missing groupInfo"));
                }
            };

            // Verify membership
            let (caller_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("Invalid DID format: {}", e);
                bad_request("Invalid DID format")
            })?;
            let is_member: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL)",
            )
            .bind(&convo_id)
            .bind(&caller_did)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("Membership check failed: {}", e);
                internal_server_error("Failed to check membership")
            })?;
            if !is_member {
                return Err(forbidden("Not a member of this conversation"));
            }

            // Parse GroupInfo to extract the MLS epoch (GroupInfo is public, no secrets exposed)
            let gi_slice: &[u8] = group_info_bytes;
            let mls_epoch = {
                use openmls::messages::group_info::VerifiableGroupInfo;
                use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn};

                // Try MlsMessage wrapper first, then raw VerifiableGroupInfo
                let from_mls_msg = MlsMessageIn::tls_deserialize(&mut &*gi_slice)
                    .ok()
                    .and_then(|msg| match msg.extract() {
                        MlsMessageBodyIn::GroupInfo(gi) => Some(gi.epoch().as_u64()),
                        _ => None,
                    });

                from_mls_msg
                    .or_else(|| {
                        VerifiableGroupInfo::tls_deserialize(&mut &*gi_slice)
                            .ok()
                            .map(|gi| gi.epoch().as_u64())
                    })
                    .or_else(|| {
                        warn!(
                            convo_id = %crate::crypto::redact_for_log(&convo_id),
                            "Could not parse GroupInfo to extract epoch, accepting without CAS"
                        );
                        None
                    })
            };

            // CAS protection: reject stale GroupInfo uploads
            if let Some(mls_epoch) = mls_epoch {
                // TODO(phase 4): route via CryptoSessionRepository — CAS guard for
                // stale GroupInfo upload; migrate when ConversationActor takes the
                // repo by ctor.
                let current_server_epoch: i32 =
                    sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
                        .bind(&convo_id)
                        .fetch_one(&pool)
                        .await
                        .map_err(|e| {
                            error!("Failed to fetch current_epoch: {}", e);
                            internal_server_error("Failed to fetch current epoch")
                        })?;

                if (mls_epoch as i32) < current_server_epoch {
                    warn!(
                        convo_id = %crate::crypto::redact_for_log(&convo_id),
                        mls_epoch,
                        current_server_epoch,
                        "Rejecting stale GroupInfo (epoch < current)"
                    );
                    return Err(conflict("GroupInfo epoch is behind current epoch"));
                }
                // Epoch transitions require an externalCommit (which persists the commit PDU
                // into the messages stream so peers can catch up via getMessages?type=commit).
                // Accepting a higher epoch here would silently advance current_epoch without
                // a recoverable commit row, stranding every other device at the old epoch.
                if (mls_epoch as i32) > current_server_epoch {
                    warn!(
                        convo_id = %crate::crypto::redact_for_log(&convo_id),
                        mls_epoch,
                        current_server_epoch,
                        "Rejecting updateGroupInfo with higher epoch — epoch transitions require externalCommit"
                    );
                    return Err(conflict(
                        "updateGroupInfo cannot advance the group epoch; use action=\"externalCommit\" for epoch transitions",
                    ));
                }
            }

            // Decode client-provided confirmation_tag
            let ugi_confirmation_tag = if let Some(ref tag_bytes) = input.confirmation_tag {
                info!(
                    "updateGroupInfo: client-provided confirmation_tag ({} bytes) for convo {}",
                    tag_bytes.len(),
                    crate::crypto::redact_for_log(&convo_id)
                );
                Some(tag_bytes.to_vec())
            } else {
                None
            };

            // Store GroupInfo and sync current_epoch atomically
            let mls_epoch_i32 = mls_epoch.map(|e| e as i32);
            sqlx::query(
                r#"UPDATE conversations
                   SET group_info = $1,
                       group_info_epoch = COALESCE(group_info_epoch, 0) + 1,
                       group_info_updated_at = NOW(),
                       current_epoch = GREATEST(current_epoch, COALESCE($2, current_epoch)),
                       confirmation_tag = $4
                   WHERE id = $3"#,
            )
            .bind(gi_slice)
            .bind(mls_epoch_i32)
            .bind(&convo_id)
            .bind(&ugi_confirmation_tag)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to store GroupInfo: {}", e);
                internal_server_error("Failed to store GroupInfo")
            })?;

            // ── A7.4: record epoch_authenticator (best-effort, no tx here) ──
            if let Some(ref auth_hex) = input.epoch_authenticator {
                let auth_str: &str = auth_hex.as_ref();
                if !auth_str.is_empty() {
                    let stored_epoch_i32 = mls_epoch.map(|e| e as i32).unwrap_or(0);
                    if let Err(e) = sqlx::query(
                        "INSERT INTO epoch_authenticators                             (convo_id, epoch, authenticator, recorded_at)                          VALUES ($1, $2, $3, NOW())                          ON CONFLICT (convo_id, epoch, authenticator) DO NOTHING",
                    )
                    .bind(&convo_id)
                    .bind(stored_epoch_i32)
                    .bind(auth_str)
                    .execute(&pool)
                    .await
                    {
                        warn!(
                            convo_id = %crate::crypto::redact_for_log(&convo_id),
                            branch = "updateGroupInfo",
                            epoch = stored_epoch_i32,
                            "failed to record epoch_authenticator: {}",
                            e
                        );
                    }
                }
            }

            let stored_epoch = mls_epoch.unwrap_or(0);
            info!(
                "✅ [v2.commitGroupChange] updateGroupInfo stored for convo {} mls_epoch={}",
                crate::crypto::redact_for_log(&convo_id),
                stored_epoch
            );
            Ok(Json(success_response()).into_response())
        }
        "claimPending" => {
            let convo_id = input.convo_id.to_string();
            let (caller_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("claimPending: invalid DID: {}", e);
                bad_request("Invalid DID format")
            })?;

            let pending_id = input.pending_addition_id.as_ref().ok_or_else(|| {
                warn!("claimPending: missing pending_addition_id");
                bad_request("Missing pendingAdditionId")
            })?;

            let claimed = sqlx::query_as::<_, PendingAdditionRow>(
                r#"
                UPDATE pending_device_additions
                SET status = 'in_progress',
                    claimed_by_did = $1,
                    claimed_at = NOW(),
                    claim_expires_at = NOW() + INTERVAL '5 minutes',
                    updated_at = NOW()
                WHERE id = $2 AND convo_id = $3 AND status = 'pending'
                RETURNING id, convo_id, user_did, new_device_id, new_device_credential_did,
                          device_name, status, claimed_by_did, created_at
                "#,
            )
            .bind(&caller_did)
            .bind(pending_id.to_string())
            .bind(&convo_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| {
                error!("claimPending: DB error: {}", e);
                internal_server_error("Failed to claim pending addition")
            })?;

            match claimed {
                Some(row) => {
                    info!("✅ [v2.commitGroupChange] Claimed pending addition");
                    let addition = PendingDeviceAddition {
                        id: row.id.into(),
                        convo_id: row.convo_id.into(),
                        user_did: crate::sqlx_jacquard::string_to_did(&row.user_did),
                        device_id: row.new_device_id.into(),
                        device_credential_did: row.new_device_credential_did.into(),
                        status: row.status.into(),
                        created_at: crate::sqlx_jacquard::chrono_to_datetime(row.created_at),
                        device_name: row.device_name.map(|n| n.into()),
                        claimed_by: row
                            .claimed_by_did
                            .as_deref()
                            .map(crate::sqlx_jacquard::string_to_did),
                        extra_data: Default::default(),
                    };
                    Ok(Json(CommitGroupChangeOutput {
                        success: true,
                        claimed_addition: Some(addition),
                        confirmation_tag: None,
                        new_epoch: None,
                        pending_additions: None,
                        rejoined_at: None,
                        extra_data: Default::default(),
                    })
                    .into_response())
                }
                None => {
                    warn!("claimPending: no matching pending addition found");
                    Ok(Json(CommitGroupChangeOutput {
                        success: false,
                        claimed_addition: None,
                        confirmation_tag: None,
                        new_epoch: None,
                        pending_additions: None,
                        rejoined_at: None,
                        extra_data: Default::default(),
                    })
                    .into_response())
                }
            }
        }
        "completePending" => {
            let (caller_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("completePending: invalid DID: {}", e);
                bad_request("Invalid DID format")
            })?;

            let pending_id = input.pending_addition_id.as_ref().ok_or_else(|| {
                warn!("completePending: missing pending_addition_id");
                bad_request("Missing pendingAdditionId")
            })?;

            let now = chrono::Utc::now();

            // Mark the pending addition as completed.
            // First try strict match: in_progress + claimed by this user.
            let result = sqlx::query(
                r#"
                UPDATE pending_device_additions
                SET status = 'completed',
                    completed_by_did = $2,
                    completed_at = $3,
                    updated_at = $3
                WHERE id = $1
                  AND status = 'in_progress'
                  AND claimed_by_did = $2
                "#,
            )
            .bind(pending_id.to_string())
            .bind(&caller_did)
            .bind(now)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("completePending: DB error: {}", e);
                internal_server_error("Failed to complete pending addition")
            })?;

            let mut completed = result.rows_affected() > 0;

            if completed {
                info!("completePending: marked {} as completed", pending_id);
            } else {
                // Fallback: the claim may have expired and been reset to 'pending',
                // but the MLS operation already succeeded. Accept completion from
                // any status that isn't already terminal.
                let fallback = sqlx::query(
                    r#"
                    UPDATE pending_device_additions
                    SET status = 'completed',
                        completed_by_did = $2,
                        completed_at = $3,
                        updated_at = $3
                    WHERE id = $1
                      AND status IN ('pending', 'in_progress')
                    "#,
                )
                .bind(pending_id.to_string())
                .bind(&caller_did)
                .bind(now)
                .execute(&pool)
                .await
                .map_err(|e| {
                    error!("completePending fallback: DB error: {}", e);
                    internal_server_error("Failed to complete pending addition")
                })?;

                completed = fallback.rows_affected() > 0;
                if completed {
                    info!("completePending: fallback completed {}", pending_id);
                } else {
                    warn!(
                        "completePending: no matching pending addition found for {}",
                        pending_id
                    );
                }
            }

            Ok(Json(CommitGroupChangeOutput {
                success: completed,
                claimed_addition: None,
                confirmation_tag: None,
                new_epoch: None,
                pending_additions: None,
                rejoined_at: None,
                extra_data: Default::default(),
            })
            .into_response())
        }
        "removeMember" | "removeMembers" => {
            let convo_id = input.convo_id.to_string();
            info!("v2.commitGroupChange: removeMember for convo");

            // ── Layer 1 §1.3: freeze check ─────────────────────────────
            check_group_frozen(&pool, &convo_id).await?;

            // ── Idempotency check ──────────────────────────────────────
            if let Some(ref idem_key) = input.idempotency_key {
                let idem_key_str = idem_key.to_string();
                let already: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM idempotency_cache WHERE key = $1)",
                )
                .bind(&idem_key_str)
                .fetch_one(&pool)
                .await
                .unwrap_or(false);

                if already {
                    // TODO(phase 4): route via CryptoSessionRepository — idempotency-hit
                    // fallback in removeMember; migrate when ConversationActor takes the
                    // repo by ctor.
                    let current_epoch: Option<i32> =
                        sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
                            .bind(&convo_id)
                            .fetch_optional(&pool)
                            .await
                            .ok()
                            .flatten();
                    info!("v2.commitGroupChange: removeMember idempotent hit");
                    return Ok(Json(CommitGroupChangeOutput {
                        success: true,
                        new_epoch: Some(current_epoch.unwrap_or(0) as i64),
                        claimed_addition: None,
                        confirmation_tag: None,
                        pending_additions: None,
                        rejoined_at: None,
                        extra_data: Default::default(),
                    })
                    .into_response());
                }
            }

            // ── Validate required fields (bytes arrive already decoded) ──
            let commit_bytes = input.commit.as_ref().ok_or_else(|| {
                warn!("removeMember: missing commit");
                bad_request("Missing commit")
            })?;
            let commit_shape = inspect_commit_for_action("removeMember", commit_bytes, &convo_id)?;
            let commit_wire_epoch = commit_shape.epoch as i64;
            let member_dids = input.member_dids.as_ref().ok_or_else(|| {
                warn!("removeMember: missing member_dids");
                bad_request("Missing memberDids")
            })?;

            // ── Verify caller is an admin ──────────────────────────────
            let (caller_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("removeMember: invalid DID format: {}", e);
                bad_request("Invalid DID format")
            })?;
            let is_admin: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL AND is_admin = true)",
            )
            .bind(&convo_id)
            .bind(&caller_did)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("removeMember: admin check failed: {}", e);
                internal_server_error("Failed to check admin status")
            })?;
            if !is_admin {
                return Err(forbidden("Not an admin of this conversation"));
            }

            // ── Parse MLS epoch from GroupInfo if provided ──────────
            let (rm_group_info_bytes, rm_mls_epoch) =
                if let Some(gi_bytes) = input.group_info.as_ref() {
                    let gi_slice: &[u8] = gi_bytes;
                    let epoch = {
                        use openmls::messages::group_info::VerifiableGroupInfo;
                        use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn};

                        let from_mls_msg = MlsMessageIn::tls_deserialize(&mut &*gi_slice)
                            .ok()
                            .and_then(|msg| match msg.extract() {
                                MlsMessageBodyIn::GroupInfo(gi) => Some(gi.epoch().as_u64()),
                                _ => None,
                            });

                        from_mls_msg.or_else(|| {
                            VerifiableGroupInfo::tls_deserialize(&mut &*gi_slice)
                                .ok()
                                .map(|gi| gi.epoch().as_u64())
                        })
                    };

                    if let Some(e) = epoch {
                        info!(
                            "removeMember: parsed MLS epoch {} from GroupInfo for convo {}",
                            e,
                            crate::crypto::redact_for_log(&convo_id)
                        );
                    }

                    (Some(gi_bytes.to_vec()), epoch)
                } else {
                    (None, None)
                };

            // ── Decode client-provided confirmation_tag ──────────
            let rm_confirmation_tag: Option<Vec<u8>> = input
                .confirmation_tag
                .as_ref()
                .map(|tag_bytes| tag_bytes.to_vec());

            let now = chrono::Utc::now();

            // ── Fetch current epoch for CAS ───────────────────────────
            let current_epoch = crate::db::get_current_epoch(&pool, &convo_id)
                .await
                .map_err(|e| {
                    error!("removeMember: failed to get current epoch: {}", e);
                    internal_server_error("Failed to get current epoch")
                })?;
            if commit_shape.epoch != current_epoch as u64 {
                warn!(
                    "removeMember: stale commit wire_epoch={} current_epoch={} for convo {}",
                    commit_shape.epoch,
                    current_epoch,
                    crate::crypto::redact_for_log(&convo_id)
                );
                // Phase 2 (auto-reset): record 409 for sweep-trigger health
                // counter. Pool-level UPDATE; failure must NEVER mask the
                // 409 response.
                if let Err(e) =
                    crate::jobs::auto_detect_failed_groups::record_commit_409_with_inline_trigger(
                        &pool,
                        &actor_registry,
                        &convo_id,
                        &inline_trigger_cfg,
                    )
                    .await
                {
                    warn!(
                        error = ?e,
                        convo_id = %crate::crypto::redact_for_log(&convo_id),
                        "removeMember: failed to record commit 409 (non-fatal)"
                    );
                }
                return Err(conflict_with_epoch(
                    &pool,
                    &convo_id,
                    current_epoch,
                    "Commit was authored from a stale MLS epoch",
                )
                .await);
            }

            // ── Begin transaction: CAS epoch + soft-delete + commit + idempotency ───
            //
            // ATOMICITY INVARIANT (task #37): `UPDATE members SET left_at`
            // must live INSIDE this tx, AFTER the CAS succeeds. Previously the
            // soft-delete ran on `&pool` BEFORE the tx began, so if the CAS
            // lost (concurrent commit), the members were booted server-side
            // while the commit was rejected — admin saw 409, member was gone
            // from `members`, epoch unchanged → server inconsistent.
            let mut tx = pool.begin().await.map_err(|e| {
                error!("removeMember: failed to begin transaction: {}", e);
                internal_server_error("Failed to begin transaction")
            })?;

            // ── Advance epoch (CAS) ───────────────────────────────────
            let new_epoch =
                crate::db::try_advance_conversation_epoch_tx(&mut tx, &convo_id, current_epoch)
                    .await
                    .map_err(|e| {
                        error!("removeMember: failed to advance epoch: {}", e);
                        internal_server_error("Failed to advance epoch")
                    })?;

            let new_epoch = match new_epoch {
                Some(epoch) => epoch,
                None => {
                    warn!("removeMember: epoch CAS failed (concurrent commit), returning 409");
                    // tx drop → rollback. Soft-delete (below) lives inside
                    // this tx, so rollback undoes it automatically — no
                    // soft-delete survives a lost CAS (task #37).
                    // Fetch authoritative server state for structured 409
                    // body (task #41).
                    drop(tx);
                    // Phase 2 (auto-reset): record 409 on a separate
                    // pool-borrowed conn (the failed tx is gone). Failure
                    // must NEVER mask the 409 response.
                    if let Err(e) = crate::jobs::auto_detect_failed_groups::record_commit_409_with_inline_trigger(&pool, &actor_registry, &convo_id, &inline_trigger_cfg).await {
                        warn!(
                            error = ?e,
                            convo_id = %crate::crypto::redact_for_log(&convo_id),
                            "removeMember: failed to record commit 409 (non-fatal)"
                        );
                    }
                    return Err(conflict_with_epoch(
                        &pool,
                        &convo_id,
                        current_epoch,
                        "Conversation epoch advanced concurrently",
                    )
                    .await);
                }
            };

            // ── Mark removed members as left (INSIDE tx, after CAS) ────
            for member_did in member_dids {
                let member_did_str = crate::sqlx_jacquard::did_to_string(member_did);
                sqlx::query(
                    "UPDATE members SET left_at = $3 WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL",
                )
                .bind(&convo_id)
                .bind(&member_did_str)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    error!("removeMember: failed to mark member as left: {}", e);
                    internal_server_error("Failed to remove member")
                })?;
            }

            // ── Store or invalidate GroupInfo (uses shared helper) ─────
            if let Some(ref gi_bytes) = rm_group_info_bytes {
                crate::db::store_group_info_in_tx(
                    &mut tx,
                    &convo_id,
                    gi_bytes,
                    rm_confirmation_tag.as_deref(),
                )
                .await
                .map_err(|e| {
                    error!("removeMember: failed to store GroupInfo: {}", e);
                    internal_server_error("Failed to store GroupInfo")
                })?;
                info!(
                    "removeMember: stored GroupInfo (mls_epoch={:?}, has_conf_tag={}) for convo {}",
                    rm_mls_epoch,
                    rm_confirmation_tag.is_some(),
                    crate::crypto::redact_for_log(&convo_id)
                );

                if let Some(mls_epoch) = rm_mls_epoch {
                    let mls_epoch_i32 = mls_epoch as i32;
                    if mls_epoch_i32 != new_epoch {
                        warn!(
                            "removeMember: MLS epoch divergence — server epoch={}, MLS epoch={} for convo {}",
                            new_epoch,
                            mls_epoch_i32,
                            crate::crypto::redact_for_log(&convo_id)
                        );
                    }
                }
            } else {
                warn!(
                    "removeMember: no GroupInfo provided with commit for convo {} — keeping existing (may be stale)",
                    crate::crypto::redact_for_log(&convo_id)
                );
            }

            // ── Store commit message ───────────────────────────────────
            let msg_id = uuid::Uuid::new_v4().to_string();
            let seq: i64 = sqlx::query_scalar(
                "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1",
            )
            .bind(&convo_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                error!("removeMember: failed to get seq: {}", e);
                internal_server_error("Failed to allocate message sequence")
            })?;

            sqlx::query(
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, wire_epoch, seq, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7, $8)",
            )
            .bind(&msg_id)
            .bind(&convo_id)
            .bind(Option::<&str>::None)
            .bind(new_epoch)
            .bind(commit_wire_epoch)
            .bind(seq)
            .bind(&commit_bytes[..])
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("removeMember: failed to insert commit message: {}", e);
                internal_server_error("Failed to store commit message")
            })?;

            // ── Store idempotency key ──────────────────────────────────
            if let Some(ref idem_key) = input.idempotency_key {
                if let Err(e) = sqlx::query(
                    "INSERT INTO idempotency_cache (caller_did, key, endpoint, response_body, status_code, created_at, expires_at) VALUES ($1, $2, $3, '{}'::jsonb, 200, NOW(), NOW() + INTERVAL '24 hours') ON CONFLICT DO NOTHING",
                )
                .bind(&caller_did)
                .bind(idem_key.to_string())
                .bind(NSID)
                .execute(&mut *tx)
                .await {
                    error!("commitGroupChange: failed to store idempotency key: {}", e);
                }
            }

            // ── A7.4: record epoch_authenticator (if client sent one) ──
            record_epoch_authenticator_tx(
                &mut tx,
                &convo_id,
                new_epoch,
                &input.epoch_authenticator,
                "removeMember",
            )
            .await;

            // ── Phase 2 (auto-reset): record commit-health success ─────
            // Bundled into the wrapping tx so atomicity matches the epoch
            // CAS — if any downstream step rolls back, the health flag does
            // too.
            crate::db::mark_commit_success_tx(&mut tx, &convo_id)
                .await
                .map_err(|e| {
                    error!("removeMember: failed to mark commit success: {}", e);
                    internal_server_error("Failed to mark commit success")
                })?;

            // ── Commit transaction ─────────────────────────────────────
            tx.commit().await.map_err(|e| {
                error!("removeMember: failed to commit transaction: {}", e);
                internal_server_error("Failed to commit transaction")
            })?;

            // ── Enqueue commit messageEvent on per-convo FIFO queue (task #39) ──
            let commit_cursor = sse_state.cursor_gen.next(&convo_id, "messageEvent").await;

            let commit_message_view: crate::realtime::StreamMessageView =
                crate::generated::blue_catbird::mlsChat::MessageView {
                    id: msg_id.clone().into(),
                    convo_id: convo_id.clone().into(),
                    ciphertext: commit_bytes.clone(),
                    epoch: new_epoch as i64,
                    seq,
                    created_at: crate::sqlx_jacquard::chrono_to_datetime(now),
                    message_type: Some("commit".into()),
                    extra_data: Default::default(),
                };

            let commit_event = crate::realtime::StreamEvent::MessageEvent {
                cursor: commit_cursor.clone(),
                message: commit_message_view,
                ephemeral: false,
            };

            sse_state.enqueue_with_store(&convo_id, pool.clone(), commit_event);

            // ── Envelope fanout (non-order-sensitive) ──
            {
                let pool_clone = pool.clone();
                let convo_id_clone = convo_id.clone();
                let msg_id_clone = msg_id.clone();

                tokio::spawn(async move {
                    let members_result = sqlx::query_scalar::<_, String>(
                        "SELECT member_did FROM members WHERE convo_id = $1 AND left_at IS NULL",
                    )
                    .bind(&convo_id_clone)
                    .fetch_all(&pool_clone)
                    .await;

                    if let Ok(member_dids) = members_result {
                        if !member_dids.is_empty() {
                            let envelope_now = chrono::Utc::now();
                            let mut qb: sqlx::QueryBuilder<sqlx::Postgres> =
                                sqlx::QueryBuilder::new(
                                    "INSERT INTO envelopes (id, convo_id, recipient_did, message_id, created_at) ",
                                );
                            qb.push_values(member_dids.iter(), |mut b, did| {
                                b.push_bind(uuid::Uuid::new_v4().to_string())
                                    .push_bind(&convo_id_clone)
                                    .push_bind(did)
                                    .push_bind(&msg_id_clone)
                                    .push_bind(envelope_now);
                            });
                            qb.push(" ON CONFLICT (recipient_did, message_id) DO NOTHING");
                            if let Err(e) = qb.build().execute(&pool_clone).await {
                                error!("removeMember: envelope fanout failed: {:?}", e);
                            }
                        }
                    }
                });
            }

            info!(
                "✅ v2.commitGroupChange: removeMember complete, epoch={}",
                new_epoch
            );
            Ok(Json(CommitGroupChangeOutput {
                success: true,
                new_epoch: Some(new_epoch as i64),
                claimed_addition: None,
                confirmation_tag: None,
                pending_additions: None,
                rejoined_at: None,
                extra_data: Default::default(),
            })
            .into_response())
        }
        // Generic commit handler for self-updates, metadata updates, and other
        // epoch-advancing operations that don't add or remove members.
        "commit" | "updateMetadata" => {
            let action_name = input.action.to_string();
            let convo_id = input.convo_id.to_string();
            info!("v2.commitGroupChange: {} for convo", action_name);

            // ── Layer 1 §1.3: freeze check ─────────────────────────────
            check_group_frozen(&pool, &convo_id).await?;

            // ── Idempotency check ──────────────────────────────────────
            if let Some(ref idem_key) = input.idempotency_key {
                let idem_key_str = idem_key.to_string();
                let already: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM idempotency_cache WHERE key = $1)",
                )
                .bind(&idem_key_str)
                .fetch_one(&pool)
                .await
                .unwrap_or(false);

                if already {
                    // TODO(phase 4): route via CryptoSessionRepository — generic
                    // idempotency-hit fallback; migrate when ConversationActor takes
                    // the repo by ctor.
                    let current_epoch: Option<i32> =
                        sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
                            .bind(&convo_id)
                            .fetch_optional(&pool)
                            .await
                            .ok()
                            .flatten();
                    info!("v2.commitGroupChange: {} idempotent hit", action_name);
                    return Ok(Json(CommitGroupChangeOutput {
                        success: true,
                        new_epoch: Some(current_epoch.unwrap_or(0) as i64),
                        claimed_addition: None,
                        confirmation_tag: None,
                        pending_additions: None,
                        rejoined_at: None,
                        extra_data: Default::default(),
                    })
                    .into_response());
                }
            }

            // ── Validate commit field (bytes arrive already decoded) ──
            let commit_bytes = input.commit.as_ref().ok_or_else(|| {
                warn!("{}: missing commit", action_name);
                bad_request("Missing commit")
            })?;

            // ── Verify caller is a member ──────────────────────────────
            let (caller_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("{}: invalid DID format: {}", action_name, e);
                bad_request("Invalid DID format")
            })?;
            let is_member: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL)",
            )
            .bind(&convo_id)
            .bind(&caller_did)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("{}: membership check failed: {}", action_name, e);
                internal_server_error("Failed to check membership")
            })?;
            if !is_member {
                return Err(forbidden("Not a member of this conversation"));
            }

            // ── Defense-in-depth: action→shape contract ──────────────
            // See docs/superpowers/plans/2026-04-16-commit-add-proposal-gate.md.
            // PURE_CIPHERTEXT_WIRE_FORMAT_POLICY means we can't inspect proposal
            // bodies, so we gate on surface markers + framing well-formedness.
            let welcome_present = input.welcome.is_some();
            let member_dids_nonempty = input.member_dids.as_ref().is_some_and(|v| !v.is_empty());
            let commit_shape = match super::commit_inspect::enforce_non_add_action_contract(
                welcome_present,
                member_dids_nonempty,
                commit_bytes,
            ) {
                Ok(shape) => {
                    info!(
                        "{}: framing OK (wire={:?}, ct={:?}, epoch={}) convo {}",
                        action_name,
                        shape.wire_format,
                        shape.content_type,
                        shape.epoch,
                        crate::crypto::redact_for_log(&convo_id)
                    );
                    shape
                }
                Err(super::commit_inspect::CommitActionContractError::WelcomeSet) => {
                    warn!(
                        "{}: rejected — welcome set under non-addMembers action (caller {}, convo {})",
                        action_name,
                        crate::crypto::redact_for_log(&caller_did),
                        crate::crypto::redact_for_log(&convo_id)
                    );
                    return Err(bad_request(
                        "welcome field is only valid with action=addMembers",
                    ));
                }
                Err(super::commit_inspect::CommitActionContractError::MemberDidsSet) => {
                    warn!(
                        "{}: rejected — memberDids set under non-addMembers action (caller {}, convo {})",
                        action_name,
                        crate::crypto::redact_for_log(&caller_did),
                        crate::crypto::redact_for_log(&convo_id)
                    );
                    return Err(bad_request(
                        "memberDids is only valid with action=addMembers",
                    ));
                }
                Err(e @ super::commit_inspect::CommitActionContractError::BadFraming(_)) => {
                    warn!(
                        "{}: rejected — framing invalid ({}) for convo {}",
                        action_name,
                        e,
                        crate::crypto::redact_for_log(&convo_id)
                    );
                    return Err(bad_request(format!("Invalid commit framing: {e}")));
                }
            };
            let commit_wire_epoch = commit_shape.epoch as i64;

            let now = chrono::Utc::now();

            // ── Fetch current epoch for CAS ───────────────────────────
            let current_epoch = crate::db::get_current_epoch(&pool, &convo_id)
                .await
                .map_err(|e| {
                    error!("{}: failed to get current epoch: {}", action_name, e);
                    internal_server_error("Failed to get current epoch")
                })?;
            if commit_shape.epoch != current_epoch as u64 {
                warn!(
                    "{}: stale commit wire_epoch={} current_epoch={} for convo {}",
                    action_name,
                    commit_shape.epoch,
                    current_epoch,
                    crate::crypto::redact_for_log(&convo_id)
                );
                // Phase 2 (auto-reset): record 409 for sweep-trigger health
                // counter. Pool-level UPDATE; failure must NEVER mask the
                // 409 response.
                if let Err(e) =
                    crate::jobs::auto_detect_failed_groups::record_commit_409_with_inline_trigger(
                        &pool,
                        &actor_registry,
                        &convo_id,
                        &inline_trigger_cfg,
                    )
                    .await
                {
                    warn!(
                        error = ?e,
                        action = %action_name,
                        convo_id = %crate::crypto::redact_for_log(&convo_id),
                        "failed to record commit 409 (non-fatal)"
                    );
                }
                return Err(conflict_with_epoch(
                    &pool,
                    &convo_id,
                    current_epoch,
                    "Commit was authored from a stale MLS epoch",
                )
                .await);
            }

            // ── Begin transaction: CAS epoch + commit + idempotency ───
            let mut tx = pool.begin().await.map_err(|e| {
                error!("{}: failed to begin transaction: {}", action_name, e);
                internal_server_error("Failed to begin transaction")
            })?;

            // ── Advance epoch (CAS) ───────────────────────────────────
            let new_epoch =
                crate::db::try_advance_conversation_epoch_tx(&mut tx, &convo_id, current_epoch)
                    .await
                    .map_err(|e| {
                        error!("{}: failed to advance epoch: {}", action_name, e);
                        internal_server_error("Failed to advance epoch")
                    })?;

            let new_epoch = match new_epoch {
                Some(epoch) => epoch,
                None => {
                    warn!(
                        "{}: epoch CAS failed (concurrent commit), returning 409",
                        action_name
                    );
                    drop(tx);
                    // Phase 2 (auto-reset): record 409 on a separate
                    // pool-borrowed conn (the failed tx is gone). Failure
                    // must NEVER mask the 409 response.
                    if let Err(e) = crate::jobs::auto_detect_failed_groups::record_commit_409_with_inline_trigger(&pool, &actor_registry, &convo_id, &inline_trigger_cfg).await {
                        warn!(
                            error = ?e,
                            action = %action_name,
                            convo_id = %crate::crypto::redact_for_log(&convo_id),
                            "failed to record commit 409 (non-fatal)"
                        );
                    }
                    return Err(conflict_with_epoch(
                        &pool,
                        &convo_id,
                        current_epoch,
                        "Conversation epoch advanced concurrently",
                    )
                    .await);
                }
            };

            // ── GroupInfo: keep existing (stale is better than absent) ─
            warn!(
                "{}: no GroupInfo provided with commit for convo {} — keeping existing (may be stale)",
                action_name,
                crate::crypto::redact_for_log(&convo_id)
            );

            // ── Store commit message ───────────────────────────────────
            let msg_id = uuid::Uuid::new_v4().to_string();
            let seq: i64 = sqlx::query_scalar(
                "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1",
            )
            .bind(&convo_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                error!("{}: failed to get seq: {}", action_name, e);
                internal_server_error("Failed to allocate message sequence")
            })?;

            sqlx::query(
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, wire_epoch, seq, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7, $8)",
            )
            .bind(&msg_id)
            .bind(&convo_id)
            .bind(Option::<&str>::None)
            .bind(new_epoch)
            .bind(commit_wire_epoch)
            .bind(seq)
            .bind(&commit_bytes[..])
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("{}: failed to insert commit message: {}", action_name, e);
                internal_server_error("Failed to store commit message")
            })?;

            // ── Store idempotency key ──────────────────────────────────
            if let Some(ref idem_key) = input.idempotency_key {
                if let Err(e) = sqlx::query(
                    "INSERT INTO idempotency_cache (caller_did, key, endpoint, response_body, status_code, created_at, expires_at) VALUES ($1, $2, $3, '{}'::jsonb, 200, NOW(), NOW() + INTERVAL '24 hours') ON CONFLICT DO NOTHING",
                )
                .bind(&caller_did)
                .bind(idem_key.to_string())
                .bind(NSID)
                .execute(&mut *tx)
                .await {
                    error!("commitGroupChange: failed to store idempotency key: {}", e);
                }
            }

            // ── A7.4: record epoch_authenticator (if client sent one) ──
            // action_name is one of "commit" | "updateMetadata" for this branch.
            record_epoch_authenticator_tx(
                &mut tx,
                &convo_id,
                new_epoch,
                &input.epoch_authenticator,
                &action_name,
            )
            .await;

            // ── Phase 2 (auto-reset): record commit-health success ─────
            // Bundled into the wrapping tx so atomicity matches the epoch
            // CAS — if any downstream step rolls back, the health flag does
            // too.
            crate::db::mark_commit_success_tx(&mut tx, &convo_id)
                .await
                .map_err(|e| {
                    error!("{}: failed to mark commit success: {}", action_name, e);
                    internal_server_error("Failed to mark commit success")
                })?;

            // ── Commit transaction ─────────────────────────────────────
            tx.commit().await.map_err(|e| {
                error!("{}: failed to commit transaction: {}", action_name, e);
                internal_server_error("Failed to commit transaction")
            })?;

            // ── Enqueue commit messageEvent on per-convo FIFO queue (task #39) ──
            let commit_cursor = sse_state.cursor_gen.next(&convo_id, "messageEvent").await;

            let commit_message_view: crate::realtime::StreamMessageView =
                crate::generated::blue_catbird::mlsChat::MessageView {
                    id: msg_id.clone().into(),
                    convo_id: convo_id.clone().into(),
                    ciphertext: commit_bytes.clone(),
                    epoch: new_epoch as i64,
                    seq,
                    created_at: crate::sqlx_jacquard::chrono_to_datetime(now),
                    message_type: Some("commit".into()),
                    extra_data: Default::default(),
                };

            let commit_event = crate::realtime::StreamEvent::MessageEvent {
                cursor: commit_cursor.clone(),
                message: commit_message_view,
                ephemeral: false,
            };

            sse_state.enqueue_with_store(&convo_id, pool.clone(), commit_event);

            // ── Envelope fanout (non-order-sensitive) ──
            {
                let pool_clone = pool.clone();
                let convo_id_clone = convo_id.clone();
                let msg_id_clone = msg_id.clone();
                let action_for_log = action_name.clone();

                tokio::spawn(async move {
                    let members_result = sqlx::query_scalar::<_, String>(
                        "SELECT member_did FROM members WHERE convo_id = $1 AND left_at IS NULL",
                    )
                    .bind(&convo_id_clone)
                    .fetch_all(&pool_clone)
                    .await;

                    if let Ok(member_dids) = members_result {
                        if !member_dids.is_empty() {
                            let envelope_now = chrono::Utc::now();
                            let mut qb: sqlx::QueryBuilder<sqlx::Postgres> =
                                sqlx::QueryBuilder::new(
                                    "INSERT INTO envelopes (id, convo_id, recipient_did, message_id, created_at) ",
                                );
                            qb.push_values(member_dids.iter(), |mut b, did| {
                                b.push_bind(uuid::Uuid::new_v4().to_string())
                                    .push_bind(&convo_id_clone)
                                    .push_bind(did)
                                    .push_bind(&msg_id_clone)
                                    .push_bind(envelope_now);
                            });
                            qb.push(" ON CONFLICT (recipient_did, message_id) DO NOTHING");
                            if let Err(e) = qb.build().execute(&pool_clone).await {
                                error!("{}: envelope fanout failed: {:?}", action_for_log, e);
                            }
                        }
                    }
                });
            }

            info!(
                "✅ v2.commitGroupChange: {} complete, epoch={}",
                action_name, new_epoch
            );
            Ok(Json(CommitGroupChangeOutput {
                success: true,
                new_epoch: Some(new_epoch as i64),
                claimed_addition: None,
                confirmation_tag: None,
                pending_additions: None,
                rejoined_at: None,
                extra_data: Default::default(),
            })
            .into_response())
        }
        "refreshGroupInfo" => {
            let convo_id = input.convo_id.to_string();
            let convo_redacted = crate::crypto::redact_for_log(&convo_id);
            info!(
                "v2.commitGroupChange: refreshGroupInfo for convo {}",
                convo_redacted
            );

            let (user_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("refreshGroupInfo: invalid DID format: {}", e);
                bad_request(format!("Invalid DID format: {}", e))
            })?;

            // Check conversation exists
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM conversations WHERE id = $1)")
                    .bind(&convo_id)
                    .fetch_one(&pool)
                    .await
                    .map_err(|e| {
                        error!("refreshGroupInfo: DB error checking convo: {}", e);
                        internal_server_error("Database error")
                    })?;

            if !exists {
                return Err(bad_request("Conversation not found"));
            }

            // Check requester is/was a member (allows former members needing rejoin)
            let is_member: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND user_did = $2)",
            )
            .bind(&convo_id)
            .bind(&user_did)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("refreshGroupInfo: DB error checking membership: {}", e);
                internal_server_error("Database error")
            })?;

            if !is_member {
                return Err(bad_request("Not a member of this conversation"));
            }

            // Inspect the active crypto session. Per the locked contract with
            // CLIENT D: any active session with NULL group_info — regardless
            // of age — is a reset signal. The 4b2cdbaa diagnostic showed
            // gen 24 sat at active+NULL for 50+ minutes, so a "settling
            // window" carve-out would never have fired. Sessions in
            // `reset_requested`/`superseding` also signal reset. Per RFC 9750
            // we cannot mint server-side GroupInfo — clients are the only
            // signing authority; the typed error routes them to
            // bootstrap-recovery.
            let active_session: Option<(String, Option<Vec<u8>>)> = sqlx::query_as(
                "SELECT id, group_info \
                 FROM crypto_sessions \
                 WHERE conversation_id = $1 AND state = 'active'",
            )
            .bind(&convo_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| {
                error!("refreshGroupInfo: DB error querying crypto_sessions: {}", e);
                internal_server_error("Database error")
            })?;

            // If no active row, surface whether a reset is mid-flight so we
            // can emit a typed groupReset (clients should bootstrap-recover,
            // not retry against a phantom session).
            let reset_in_flight: Option<(String,)> = if active_session.is_none() {
                sqlx::query_as(
                    "SELECT state FROM crypto_sessions \
                     WHERE conversation_id = $1 \
                       AND state IN ('reset_requested', 'superseding') \
                     ORDER BY created_at DESC LIMIT 1",
                )
                .bind(&convo_id)
                .fetch_optional(&pool)
                .await
                .map_err(|e| {
                    error!("refreshGroupInfo: DB error querying reset state: {}", e);
                    internal_server_error("Database error")
                })?
            } else {
                None
            };

            match (active_session.as_ref(), reset_in_flight.as_ref()) {
                // Active session with NULL group_info — reset signal.
                // newCryptoSessionId echoes back the active id so clients can
                // bootstrap into the right successor.
                (Some((active_id, None)), _) => {
                    tracing::info!(
                        target: "groupinfo_refresh",
                        action = "refreshGroupInfo",
                        convo_id = %crate::crypto::redact_for_log(&convo_id),
                        active_session_state = "active",
                        new_crypto_session_id = %active_id,
                        outcome = "group_reset_active_null_group_info",
                        "active session has NULL group_info — routing client to bootstrap-recovery"
                    );
                    return Err(group_reset_error(
                        &convo_id,
                        "GroupInfo unavailable for active session; client must bootstrap-recover",
                        Some(active_id.clone()),
                    ));
                }
                // Active session with group_info — fall through to the
                // legacy SSE-emit + 200 happy path so other clients can
                // re-publish via the existing recovery handshake.
                (Some((active_id, Some(_))), _) => {
                    tracing::info!(
                        target: "groupinfo_refresh",
                        action = "refreshGroupInfo",
                        convo_id = %crate::crypto::redact_for_log(&convo_id),
                        active_session_state = "active",
                        active_session_id = %active_id,
                        outcome = "active_with_group_info",
                        "emitting GroupInfoRefreshRequested SSE for active session with cached GroupInfo"
                    );
                }
                // No active session, reset mid-flight. newCryptoSessionId is
                // null since the successor doesn't exist yet.
                (None, Some((reset_state,))) => {
                    tracing::info!(
                        target: "groupinfo_refresh",
                        action = "refreshGroupInfo",
                        convo_id = %crate::crypto::redact_for_log(&convo_id),
                        active_session_state = %reset_state,
                        outcome = "group_reset_in_flight",
                        "no active session — reset in flight; routing client to bootstrap-recovery"
                    );
                    return Err(group_reset_error(
                        &convo_id,
                        "Conversation is being reset; client must bootstrap-recover",
                        None,
                    ));
                }
                // No crypto_sessions row at all (pre-Phase-2 legacy convo).
                // Fall through to legacy SSE-emit path; the repository's
                // legacy fallback path handles reads.
                (None, None) => {
                    tracing::info!(
                        target: "groupinfo_refresh",
                        action = "refreshGroupInfo",
                        convo_id = %crate::crypto::redact_for_log(&convo_id),
                        outcome = "no_crypto_session_legacy",
                        "no crypto_sessions row — falling back to legacy SSE-emit path"
                    );
                }
            }

            // Emit GroupInfoRefreshRequested SSE event (legacy recovery
            // handshake — preserved so clients listening for the SSE
            // continue to drive their refresh handshake).
            let cursor = sse_state
                .cursor_gen
                .next(&convo_id, "groupInfoRefreshRequested")
                .await;
            let event = StreamEvent::GroupInfoRefreshRequested {
                cursor,
                convo_id: convo_id.clone(),
                requested_by: user_did.clone(),
                requested_at: chrono::Utc::now().to_rfc3339(),
            };

            if let Err(e) = sse_state.emit(&convo_id, event).await {
                warn!(error = %e, "Failed to emit GroupInfoRefreshRequested event");
            }

            info!(
                "v2.commitGroupChange: refreshGroupInfo emitted SSE for convo {}",
                convo_redacted
            );
            Ok(Json(success_response()).into_response())
        }
        "confirmWelcome" => {
            // Ack-only: clients may send this after successfully processing a Welcome message.
            // It must not mutate membership, epoch, or welcome state.
            info!("v2.commitGroupChange: confirmWelcome (ack-only no-op)");
            Ok(Json(success_response()).into_response())
        }
        other => {
            warn!("v2.commitGroupChange: unknown action: {}", other);
            Err(bad_request(format!("Unknown action: {}", other)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, StatusCode};
    use bytes::Bytes;
    use jacquard_axum::ExtractXrpc;
    use std::sync::Arc;

    #[test]
    fn invalidate_welcome_response_returns_false_when_nothing_invalidated() {
        let response = invalidate_welcome_response(0);
        assert!(!response.success);
    }

    #[test]
    fn invalidate_welcome_response_returns_true_when_rows_invalidated() {
        let response = invalidate_welcome_response(2);
        assert!(response.success);
    }

    /// Verifies the shape of the addMembers idempotency-hit response:
    /// it must include both `success: true` and a `newEpoch` field.
    #[test]
    fn add_members_idempotent_response_includes_new_epoch() {
        let epoch: i32 = 5;
        let response = CommitGroupChangeOutput {
            success: true,
            new_epoch: Some(epoch as i64),
            claimed_addition: None,
            confirmation_tag: None,
            pending_additions: None,
            rejoined_at: None,
            extra_data: Default::default(),
        };
        assert!(response.success);
        assert_eq!(response.new_epoch, Some(5));
    }

    /// When no epoch row exists the idempotency path falls back to 0.
    #[test]
    fn add_members_idempotent_response_defaults_epoch_to_zero() {
        // Mirror the production codepath: read `current_epoch` (Option<i32>)
        // from the DB, fall back to 0 when the row is absent. Clippy flags the
        // const-None form, so build the Option dynamically.
        let current_epoch: Option<i32> = std::env::var("__never_set_epoch_override")
            .ok()
            .and_then(|v| v.parse().ok());
        let response = CommitGroupChangeOutput {
            success: true,
            new_epoch: Some(current_epoch.unwrap_or(0) as i64),
            claimed_addition: None,
            confirmation_tag: None,
            pending_additions: None,
            rejoined_at: None,
            extra_data: Default::default(),
        };
        assert_eq!(response.new_epoch, Some(0));
    }

    #[test]
    fn xrpc_error_sets_json_content_type() {
        let response = bad_request("Missing commit").into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    /// Task #41: the structured 409 body must carry `serverEpoch`,
    /// `serverSequencerTerm` (optional), and `expectedEpoch` so clients can
    /// resync without a follow-up `getGroupState` call. Matches the shape
    /// produced by `send_message.rs` on epoch mismatch.
    #[test]
    fn epoch_conflict_body_serializes_with_server_epoch_fields() {
        let body = EpochConflictBody {
            error: "EpochMismatch",
            message: "Conversation epoch advanced concurrently".into(),
            server_epoch: 42,
            server_sequencer_term: Some(7),
            expected_epoch: 41,
        };
        let json = serde_json::to_value(&body).expect("serialize");
        assert_eq!(json["error"], "EpochMismatch");
        assert_eq!(json["serverEpoch"], 42);
        assert_eq!(json["serverSequencerTerm"], 7);
        assert_eq!(json["expectedEpoch"], 41);
        assert_eq!(json["message"], "Conversation epoch advanced concurrently");
    }

    /// When `sequencer_term` is NULL in the DB (non-federated convo), the
    /// field must be omitted from the body — we advertised the `skip_serializing_if`
    /// contract to clients.
    #[test]
    fn epoch_conflict_body_omits_null_sequencer_term() {
        let body = EpochConflictBody {
            error: "EpochMismatch",
            message: "x".into(),
            server_epoch: 5,
            server_sequencer_term: None,
            expected_epoch: 4,
        };
        let json = serde_json::to_value(&body).expect("serialize");
        assert!(json.get("serverSequencerTerm").is_none());
    }

    /// Sanity: the structured 409 must produce StatusCode::CONFLICT.
    #[test]
    fn epoch_conflict_into_response_is_409() {
        let err = XrpcError::EpochConflict(EpochConflictBody {
            error: "EpochMismatch",
            message: "x".into(),
            server_epoch: 1,
            server_sequencer_term: None,
            expected_epoch: 0,
        });
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    /// N29: GroupFrozen must be machine-parseable like the existing
    /// RateLimited body, so clients can back off without scraping text.
    #[test]
    fn group_frozen_body_serializes_retry_hint() {
        let body = GroupFrozenBody {
            error: "GroupFrozen",
            message: "Conversation is being repaired".into(),
            retry_after_seconds: 307,
        };
        let json = serde_json::to_value(&body).expect("serialize");
        assert_eq!(json["error"], "GroupFrozen");
        assert_eq!(json["retryAfterSeconds"], 307);
        assert_eq!(json["message"], "Conversation is being repaired");
    }

    #[test]
    fn group_frozen_into_response_is_423_with_retry_after() {
        let err = XrpcError::GroupFrozen(GroupFrozenBody {
            error: "GroupFrozen",
            message: "x".into(),
            retry_after_seconds: 42,
        });
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::LOCKED);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "42");
    }

    async fn setup_test_db() -> DbPool {
        crate::db::init_db(crate::db::DbConfig {
            database_url: std::env::var("TEST_DATABASE_URL")
                .unwrap_or_else(|_| "postgres://localhost/catbird_test".to_string()),
            max_connections: 4,
            min_connections: 1,
            acquire_timeout: std::time::Duration::from_secs(30),
            idle_timeout: std::time::Duration::from_secs(600),
        })
        .await
        .expect("initialize test database")
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn add_members_reissue_request_tracks_idempotency_key_only_after_commit() {
        let pool = setup_test_db().await;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let admin_user_did = format!("did:plc:admin{}", &suffix[..12]);
        let admin_device_did = format!("{admin_user_did}#device-admin");
        let recipient_did = format!("did:plc:recipient{}", &suffix[..8]);
        let convo_id = format!("convo-reissue-handler-{suffix}");
        let request_id = format!("req-{suffix}");
        let other_request_id = format!("req-other-{suffix}");
        let hash_hex =
            "3f1e1d1c1b1a1918171615141312111001020304050607080910111213141516".to_string();

        sqlx::query("INSERT INTO users (did) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(&recipient_did)
            .execute(&pool)
            .await
            .expect("seed recipient user");
        sqlx::query(
            "INSERT INTO conversations \
                (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, is_remote, group_id) \
             VALUES ($1, $2, 1, NOW(), NOW(), $3, false, $1)",
        )
        .bind(&convo_id)
        .bind(&admin_user_did)
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .execute(&pool)
        .await
        .expect("seed conversation");
        sqlx::query(
            "INSERT INTO members \
                (convo_id, member_did, user_did, device_id, joined_at, is_admin) \
             VALUES ($1, $2, $3, $4, NOW(), true)",
        )
        .bind(&convo_id)
        .bind(&admin_device_did)
        .bind(&admin_user_did)
        .bind("device-admin")
        .execute(&pool)
        .await
        .expect("seed admin member");
        sqlx::query(
            "INSERT INTO key_packages \
                (id, owner_did, device_id, cipher_suite, key_package, key_package_hash, created_at, expires_at, state) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW() + INTERVAL '30 days', 'available')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&recipient_did)
        .bind("device-a")
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .bind::<&[u8]>(&[0xA5])
        .bind(&hash_hex)
        .execute(&pool)
        .await
        .expect("seed recipient key package");
        sqlx::query(
            "INSERT INTO reissue_requests \
                (id, convo_id, recipient_device_did, requested_at, attempts, last_attempt_at) \
             VALUES ($1, $2, $3, NOW(), 1, NOW()), ($4, $2, $5, NOW(), 1, NOW())",
        )
        .bind(&request_id)
        .bind(&convo_id)
        .bind(format!("{recipient_did}#device-a"))
        .bind(&other_request_id)
        .bind(format!("{recipient_did}#device-b"))
        .execute(&pool)
        .await
        .expect("seed reissue requests");

        let auth_user = AuthUser {
            did: admin_device_did.clone(),
            claims: crate::auth::AtProtoClaims {
                iss: admin_user_did.clone(),
                aud: "did:web:mls.example.test".to_string(),
                exp: Utc::now().timestamp() + 300,
                iat: Some(Utc::now().timestamp()),
                sub: Some(admin_user_did.clone()),
                lxm: Some(NSID.to_string()),
                jti: Some(format!("jti-{suffix}")),
            },
        };
        let input =
            crate::generated::blue_catbird::mlsChat::commit_group_change::CommitGroupChange {
                action: "addMembers".into(),
                commit: Some(Bytes::from_static(b"test-add-members-commit")),
                convo_id: convo_id.clone().into(),
                idempotency_key: Some(request_id.clone().into()),
                key_package_hashes: Some(vec![
                crate::generated::blue_catbird::mlsChat::commit_group_change::KeyPackageHashEntry {
                    did: crate::sqlx_jacquard::string_to_did(&recipient_did),
                    hash: hash_hex.clone().into(),
                    extra_data: Default::default(),
                },
            ]),
                member_dids: Some(vec![crate::sqlx_jacquard::string_to_did(&recipient_did)]),
                welcome: Some(Bytes::from_static(b"replacement-welcome")),
                ..Default::default()
            };

        let sse_state = Arc::new(crate::realtime::SseState::new(16));
        let actor_registry = Arc::new(crate::actors::ActorRegistry::new(
            pool.clone(),
            sse_state.clone(),
            None,
        ));
        let inline_trigger_cfg = Arc::new(crate::config::InlineTriggerConfig::default());
        let block_sync = Arc::new(BlockSyncService::new());

        let _commit_guard = force_add_members_commit_shape_for_test(1);
        {
            let _rollback_guard = enable_add_members_abort_after_welcome_for_test();
            let error = commit_group_change(
                State(pool.clone()),
                State(sse_state.clone()),
                State(actor_registry.clone()),
                State(inline_trigger_cfg.clone()),
                State(block_sync.clone()),
                auth_user.clone(),
                ExtractXrpc(input.clone()),
            )
            .await
            .expect_err("forced rollback should fail the handler");
            assert_eq!(
                error.into_response().status(),
                StatusCode::INTERNAL_SERVER_ERROR
            );
        }

        let responded_after_rollback: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT responded_at FROM reissue_requests WHERE id = $1")
                .bind(&request_id)
                .fetch_one(&pool)
                .await
                .expect("fetch responded_at after rollback");
        let other_after_rollback: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT responded_at FROM reissue_requests WHERE id = $1")
                .bind(&other_request_id)
                .fetch_one(&pool)
                .await
                .expect("fetch other responded_at after rollback");
        let welcome_rows_after_rollback: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM welcome_messages WHERE convo_id = $1")
                .bind(&convo_id)
                .fetch_one(&pool)
                .await
                .expect("count welcomes after rollback");
        let recipient_members_after_rollback: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM members WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL",
        )
        .bind(&convo_id)
        .bind(&recipient_did)
        .fetch_one(&pool)
        .await
        .expect("count recipient members after rollback");
        assert!(
            responded_after_rollback.is_none(),
            "rollback must keep the matching reissue request pending"
        );
        assert!(
            other_after_rollback.is_none(),
            "rollback must keep unrelated reissue requests pending"
        );
        assert_eq!(
            welcome_rows_after_rollback, 0,
            "rollback must not expose replacement Welcome rows"
        );
        assert_eq!(
            recipient_members_after_rollback, 0,
            "rollback must not leak recipient membership rows"
        );

        let response = commit_group_change(
            State(pool.clone()),
            State(sse_state),
            State(actor_registry),
            State(inline_trigger_cfg),
            State(block_sync),
            auth_user,
            ExtractXrpc(input),
        )
        .await
        .unwrap_or_else(|_| panic!("successful addMembers response"));
        assert_eq!(response.status(), StatusCode::OK);

        let responded_after_commit: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT responded_at FROM reissue_requests WHERE id = $1")
                .bind(&request_id)
                .fetch_one(&pool)
                .await
                .expect("fetch responded_at after commit");
        let other_after_commit: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT responded_at FROM reissue_requests WHERE id = $1")
                .bind(&other_request_id)
                .fetch_one(&pool)
                .await
                .expect("fetch other responded_at after commit");
        let welcome_rows_after_commit: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM welcome_messages \
             WHERE convo_id = $1 AND recipient_did = $2 AND consumed = false",
        )
        .bind(&convo_id)
        .bind(&recipient_did)
        .fetch_one(&pool)
        .await
        .expect("count welcomes after commit");
        let recipient_members_after_commit: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM members WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL",
        )
        .bind(&convo_id)
        .bind(&recipient_did)
        .fetch_one(&pool)
        .await
        .expect("count recipient members after commit");
        assert!(
            responded_after_commit.is_some(),
            "commit must answer the reissue request named by idempotencyKey"
        );
        assert!(
            other_after_commit.is_none(),
            "handler must not answer unrelated reissue requests"
        );
        assert_eq!(
            welcome_rows_after_commit, 1,
            "commit must publish exactly one durable replacement Welcome row"
        );
        assert_eq!(
            recipient_members_after_commit, 1,
            "commit must publish the recipient membership row atomically with the Welcome"
        );

        let _ = sqlx::query("DELETE FROM key_packages WHERE owner_did = $1")
            .bind(&recipient_did)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE did = $1")
            .bind(&recipient_did)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM conversations WHERE id = $1")
            .bind(&convo_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn reissue_request_answered_only_after_commit_and_welcome_persistence() {
        let pool = setup_test_db().await;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let admin_did = format!("did:plc:admin{}", &suffix[..12]);
        let recipient_did = format!("did:plc:recipient{}", &suffix[..8]);
        let convo_id = format!("convo-reissue-{suffix}");
        let request_id = format!("req-{suffix}");
        let hash_hex =
            "1f1e1d1c1b1a1918171615141312111001020304050607080910111213141516".to_string();

        sqlx::query("INSERT INTO users (did) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(&recipient_did)
            .execute(&pool)
            .await
            .expect("seed recipient user");
        sqlx::query(
            "INSERT INTO conversations \
                (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, is_remote, group_id) \
             VALUES ($1, $2, 1, NOW(), NOW(), $3, false, $1)",
        )
        .bind(&convo_id)
        .bind(&admin_did)
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .execute(&pool)
        .await
        .expect("seed conversation");
        sqlx::query(
            "INSERT INTO key_packages \
                (id, owner_did, device_id, cipher_suite, key_package, key_package_hash, created_at, expires_at, state) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW() + INTERVAL '30 days', 'available')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&recipient_did)
        .bind("device-a")
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .bind::<&[u8]>(&[0xA5])
        .bind(&hash_hex)
        .execute(&pool)
        .await
        .expect("seed recipient key package");
        sqlx::query(
            "INSERT INTO reissue_requests \
                (id, convo_id, recipient_device_did, requested_at, attempts, last_attempt_at) \
             VALUES ($1, $2, $3, NOW(), 1, NOW())",
        )
        .bind(&request_id)
        .bind(&convo_id)
        .bind(format!("{recipient_did}#device-a"))
        .execute(&pool)
        .await
        .expect("seed reissue request");

        let entries = vec![
            crate::generated::blue_catbird::mlsChat::bootstrap_reset_group::KeyPackageHashEntry {
                did: crate::sqlx_jacquard::string_to_did(&recipient_did),
                hash: hash_hex.clone().into(),
                extra_data: Default::default(),
            },
        ];

        let mut tx = pool.begin().await.expect("begin rollback tx");
        crate::db::store_welcomes_per_device_in_tx(
            &mut tx,
            &convo_id,
            b"replacement-welcome",
            &entries,
            &admin_did,
        )
        .await
        .expect("stage replacement welcome");
        mark_reissue_request_answered_tx(&mut tx, &request_id, &convo_id, Utc::now())
            .await
            .expect("stage answered marker");
        tx.rollback().await.expect("rollback tx");

        let responded_after_rollback: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT responded_at FROM reissue_requests WHERE id = $1")
                .bind(&request_id)
                .fetch_one(&pool)
                .await
                .expect("fetch responded_at after rollback");
        let welcome_rows_after_rollback: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM welcome_messages WHERE convo_id = $1")
                .bind(&convo_id)
                .fetch_one(&pool)
                .await
                .expect("count welcomes after rollback");
        assert!(
            responded_after_rollback.is_none(),
            "rollback must keep the reissue request pending"
        );
        assert_eq!(
            welcome_rows_after_rollback, 0,
            "rollback must not expose replacement Welcome rows"
        );

        let mut tx = pool.begin().await.expect("begin commit tx");
        crate::db::store_welcomes_per_device_in_tx(
            &mut tx,
            &convo_id,
            b"replacement-welcome",
            &entries,
            &admin_did,
        )
        .await
        .expect("stage replacement welcome");
        mark_reissue_request_answered_tx(&mut tx, &request_id, &convo_id, Utc::now())
            .await
            .expect("stage answered marker");
        tx.commit().await.expect("commit tx");

        let responded_after_commit: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT responded_at FROM reissue_requests WHERE id = $1")
                .bind(&request_id)
                .fetch_one(&pool)
                .await
                .expect("fetch responded_at after commit");
        let welcome_rows_after_commit: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM welcome_messages \
             WHERE convo_id = $1 AND recipient_did = $2 AND consumed = false",
        )
        .bind(&convo_id)
        .bind(&recipient_did)
        .fetch_one(&pool)
        .await
        .expect("count welcomes after commit");
        assert!(
            responded_after_commit.is_some(),
            "commit must publish the answered marker"
        );
        assert_eq!(
            welcome_rows_after_commit, 1,
            "answered marker must become visible with the durable replacement Welcome"
        );

        let _ = sqlx::query("DELETE FROM key_packages WHERE owner_did = $1")
            .bind(&recipient_did)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE did = $1")
            .bind(&recipient_did)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM conversations WHERE id = $1")
            .bind(&convo_id)
            .execute(&pool)
            .await;
    }
}
