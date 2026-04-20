use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
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

#[derive(Serialize)]
struct XrpcErrorBody {
    error: &'static str,
    message: String,
}

/// Structured body for CAS-failure 409s, matching the shape already produced by
/// `send_message.rs` on epoch mismatch (task #41). Clients that already parse
/// `serverEpoch` from the send-path 409 get instant epoch-resync here too —
/// no extra `getGroupState` round-trip required.
#[derive(Serialize)]
struct EpochConflictBody {
    error: &'static str,
    message: String,
    #[serde(rename = "serverEpoch")]
    server_epoch: i32,
    #[serde(rename = "serverSequencerTerm", skip_serializing_if = "Option::is_none")]
    server_sequencer_term: Option<i64>,
    #[serde(rename = "expectedEpoch")]
    expected_epoch: i32,
}

pub enum XrpcError {
    /// Plain error: status + error-name + message.
    Plain(StatusCode, &'static str, String),
    /// 409 epoch-conflict with structured body (task #41).
    EpochConflict(EpochConflictBody),
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
            XrpcError::Plain(status, error, message) => (
                status,
                Json(XrpcErrorBody { error, message }),
            )
                .into_response(),
            XrpcError::EpochConflict(body) => {
                (StatusCode::CONFLICT, Json(body)).into_response()
            }
        }
    }
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
    let row: Option<(Option<i32>, Option<i64>)> = sqlx::query_as(
        "SELECT current_epoch, sequencer_term FROM conversations WHERE id = $1",
    )
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
#[tracing::instrument(skip(pool, sse_state, _actor_registry, block_sync, auth_user, input))]
pub async fn commit_group_change(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    State(_actor_registry): State<Arc<ActorRegistry>>,
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

            // ── Begin transaction: members + CAS epoch + commit + welcomes + idempotency ──
            let mut tx = pool.begin().await.map_err(|e| {
                error!(convo_id = %crate::crypto::redact_for_log(&convo_id), "addMembers: failed to begin transaction: {}", e);
                internal_server_error("Failed to begin transaction")
            })?;

            // ── Add members (inside transaction for atomicity with welcome) ──
            let member_did_strings: Vec<String> = member_dids
                .iter()
                .map(|d| crate::sqlx_jacquard::did_to_string(d))
                .collect();
            for member_did_str in &member_did_strings {
                let result = sqlx::query(
                    r#"INSERT INTO members (convo_id, member_did, user_did, joined_at)
                       VALUES ($1, $2, $2, $3)
                       ON CONFLICT (convo_id, member_did) DO UPDATE SET left_at = NULL, needs_rejoin = false"#,
                )
                .bind(&convo_id)
                .bind(member_did_str)
                .bind(&now)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    error!(convo_id = %crate::crypto::redact_for_log(&convo_id), "addMembers: failed to insert member: {}", e);
                    internal_server_error("Failed to insert member")
                })?;
                info!(
                    "addMembers: inserted member {} into convo {}, rows_affected={}",
                    crate::crypto::redact_for_log(member_did_str),
                    crate::crypto::redact_for_log(&convo_id),
                    result.rows_affected()
                );
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
                        new_epoch, mls_epoch_i32, crate::crypto::redact_for_log(&convo_id)
                    );
                }
            }

            // ── Store or invalidate GroupInfo ─────────────────────────
            if let Some(ref gi_bytes) = add_group_info_bytes {
                // Do NOT rewrite `current_epoch` here. The CAS in try_advance
                // (lines 462-468) already assigned it; overwriting with the
                // client-reported MLS epoch can drift from the `commits`-row
                // epoch written below, stranding other clients that then
                // fetch GroupInfo at a different epoch than the last commit.
                // Divergence between CAS and MLS epoch is logged but not
                // fixed by a raw SET — see divergence warn! above.
                sqlx::query(
                    r#"UPDATE conversations
                       SET group_info = $1,
                           group_info_epoch = COALESCE(group_info_epoch, 0) + 1,
                           group_info_updated_at = NOW(),
                           confirmation_tag = $3
                       WHERE id = $2"#,
                )
                .bind(gi_bytes)
                .bind(&convo_id)
                .bind(&add_confirmation_tag)
                .execute(&mut *tx)
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
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, seq, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7)",
            )
            .bind(&msg_id)
            .bind(&convo_id)
            .bind(Option::<&str>::None)
            .bind(new_epoch)
            .bind(seq)
            .bind(&commit_bytes[..])
            .bind(&now)
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

            // ── Store welcome for each new member ──────────────────────
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
                .bind(&now)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    error!("addMembers: failed to store welcome: {}", e);
                    internal_server_error("Failed to store welcome")
                })?;
                info!(
                    "addMembers: welcome stored for {}, rows_affected={}",
                    crate::crypto::redact_for_log(member_did_str),
                    welcome_result.rows_affected()
                );
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

            // ── Broadcast commit via SSE/WebSocket ───────────────────
            // Without this, connected clients miss epoch-advancing commits
            // and fail to decrypt subsequent messages at the new epoch.
            {
                let pool_clone = pool.clone();
                let sse_state_clone = sse_state.clone();
                let convo_id_clone = convo_id.clone();
                let msg_id_clone = msg_id.clone();
                let commit_bytes_clone = commit_bytes.clone();

                tokio::spawn(async move {
                    // Fan-out envelopes so clients pick up the commit via getMessages
                    let members_result = sqlx::query_scalar::<_, String>(
                        "SELECT member_did FROM members WHERE convo_id = $1 AND left_at IS NULL",
                    )
                    .bind(&convo_id_clone)
                    .fetch_all(&pool_clone)
                    .await;

                    if let Ok(member_dids) = members_result {
                        if !member_dids.is_empty() {
                            let envelope_now = chrono::Utc::now();
                            let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
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

                    // Emit SSE event so WebSocket subscribers see the commit immediately
                    let cursor = sse_state_clone
                        .cursor_gen
                        .next(&convo_id_clone, "messageEvent")
                        .await;

                    let message_view: crate::realtime::StreamMessageView =
                        crate::generated::blue_catbird::mlsChat::MessageView {
                            id: msg_id_clone.clone().into(),
                            convo_id: convo_id_clone.clone().into(),
                            ciphertext: bytes::Bytes::from(commit_bytes_clone),
                            epoch: new_epoch as i64,
                            seq,
                            created_at: crate::sqlx_jacquard::chrono_to_datetime(now),
                            message_type: Some("commit".into()),
                            extra_data: Default::default(),
                        }
                        .into();

                    let event = crate::realtime::StreamEvent::MessageEvent {
                        cursor: cursor.clone(),
                        message: message_view,
                        ephemeral: false,
                    };

                    if let Err(e) =
                        crate::db::store_event(&pool_clone, &convo_id_clone, &event).await
                    {
                        error!("addMembers: store event failed: {:?}", e);
                    }

                    if let Err(e) = sse_state_clone.emit(&convo_id_clone, event).await {
                        error!("addMembers: SSE emit failed: {}", e);
                    }
                });
            }

            // ── Emit treeChanged event so other clients detect divergence ──
            if let Some(ref tag_bytes) = add_confirmation_tag {
                let tree_cursor = sse_state.cursor_gen.next(&convo_id, "treeChanged").await;
                let tree_event = StreamEvent::TreeChanged {
                    cursor: tree_cursor.clone(),
                    convo_id: convo_id.clone(),
                    confirmation_tag: bytes::Bytes::from(tag_bytes.clone()),
                    epoch: new_epoch as i64,
                };
                if let Err(e) = crate::db::store_event(&pool, &convo_id, &tree_event).await {
                    warn!("addMembers: store treeChanged event failed: {:?}", e);
                }
                if let Err(e) = sse_state.emit(&convo_id, tree_event).await {
                    warn!("addMembers: SSE treeChanged emit failed: {}", e);
                }
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

            // ── Rate-limit: at most 1 external commit per 30s per conversation ──
            // This is the server-side safety net to prevent epoch inflation spirals
            // where multiple clients auto-repair via external commit in a feedback loop.
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
                        return Err(XrpcError::Plain(
                            StatusCode::TOO_MANY_REQUESTS,
                            "RateLimited",
                            format!("Another external commit was accepted recently. Retry after {} seconds.", retry_after),
                        ));
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

            // ── Verify caller is a current or self-left member (NOT admin-removed) ──
            let (caller_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
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
                        new_epoch, mls_epoch_i32, crate::crypto::redact_for_log(&convo_id)
                    );
                }
            }

            // ── Update conversations.group_id from GroupInfo ─────────
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

            // ── Store or invalidate GroupInfo ─────────────────────────
            if let Some(ref gi_bytes) = group_info_bytes_opt {
                // Do NOT rewrite `current_epoch` here. try_advance (logged as
                // diverging at lines 1091-1100) already CAS-assigned the new
                // epoch; binding the client-reported MLS post-commit epoch
                // can land off-by-one from CAS+1 and desync from the
                // `messages`/`commits` row inserted with `new_epoch`.
                sqlx::query(
                    r#"UPDATE conversations
                       SET group_info = $1,
                           group_info_epoch = COALESCE(group_info_epoch, 0) + 1,
                           group_info_updated_at = NOW(),
                           confirmation_tag = $3
                       WHERE id = $2"#,
                )
                .bind(gi_bytes)
                .bind(&convo_id)
                .bind(&ec_confirmation_tag)
                .execute(&mut *tx)
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
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, seq, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7)",
            )
            .bind(&msg_id)
            .bind(&convo_id)
            .bind(Option::<&str>::None)
            .bind(new_epoch)
            .bind(seq)
            .bind(&commit_bytes[..])
            .bind(&now)
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

            // ── Commit transaction ─────────────────────────────────────
            tx.commit().await.map_err(|e| {
                error!("externalCommit: failed to commit transaction: {}", e);
                internal_server_error("Failed to commit transaction")
            })?;

            // ── Broadcast commit via SSE/WebSocket ───────────────────
            {
                let pool_clone = pool.clone();
                let sse_state_clone = sse_state.clone();
                let convo_id_clone = convo_id.clone();
                let msg_id_clone = msg_id.clone();
                let commit_bytes_clone = commit_bytes.clone();

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
                            let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
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

                    let cursor = sse_state_clone
                        .cursor_gen
                        .next(&convo_id_clone, "messageEvent")
                        .await;

                    let message_view: crate::realtime::StreamMessageView =
                        crate::generated::blue_catbird::mlsChat::MessageView {
                            id: msg_id_clone.clone().into(),
                            convo_id: convo_id_clone.clone().into(),
                            ciphertext: bytes::Bytes::from(commit_bytes_clone),
                            epoch: new_epoch as i64,
                            seq,
                            created_at: crate::sqlx_jacquard::chrono_to_datetime(now),
                            message_type: Some("commit".into()),
                            extra_data: Default::default(),
                        }
                        .into();

                    let event = crate::realtime::StreamEvent::MessageEvent {
                        cursor: cursor.clone(),
                        message: message_view,
                        ephemeral: false,
                    };

                    if let Err(e) =
                        crate::db::store_event(&pool_clone, &convo_id_clone, &event).await
                    {
                        error!("externalCommit: store event failed: {:?}", e);
                    }

                    if let Err(e) = sse_state_clone.emit(&convo_id_clone, event).await {
                        error!("externalCommit: SSE emit failed: {}", e);
                    }
                });
            }

            // ── Emit treeChanged event so other clients detect divergence ──
            if let Some(ref tag_bytes) = ec_confirmation_tag {
                let tree_cursor = sse_state.cursor_gen.next(&convo_id, "treeChanged").await;
                let tree_event = StreamEvent::TreeChanged {
                    cursor: tree_cursor.clone(),
                    convo_id: convo_id.clone(),
                    confirmation_tag: bytes::Bytes::from(tag_bytes.clone()),
                    epoch: new_epoch as i64,
                };
                if let Err(e) = crate::db::store_event(&pool, &convo_id, &tree_event).await {
                    warn!("externalCommit: store treeChanged event failed: {:?}", e);
                }
                if let Err(e) = sse_state.emit(&convo_id, tree_event).await {
                    warn!("externalCommit: SSE treeChanged emit failed: {}", e);
                }
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

            let invalidated = sqlx::query(
                r#"
                UPDATE welcome_messages
                SET consumed = true,
                    consumed_at = NOW(),
                    error_reason = COALESCE(error_reason, 'Client invalidated Welcome')
                WHERE convo_id = $1
                  AND recipient_did = $2
                  AND consumed = false
                "#,
            )
            .bind(&convo_id)
            .bind(&auth_user.did)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("invalidateWelcome: failed to invalidate welcome: {}", e);
                internal_server_error("Failed to invalidate welcome")
            })?
            .rows_affected();

            info!(
                "✅ [v2.commitGroupChange] invalidateWelcome complete for convo {} (rows={})",
                crate::crypto::redact_for_log(&convo_id),
                invalidated
            );

            Ok(Json(invalidate_welcome_response(invalidated)).into_response())
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

            let now = chrono::Utc::now();

            // ── Fetch current epoch for CAS ───────────────────────────
            let current_epoch = crate::db::get_current_epoch(&pool, &convo_id)
                .await
                .map_err(|e| {
                    error!("removeMember: failed to get current epoch: {}", e);
                    internal_server_error("Failed to get current epoch")
                })?;

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
                .bind(&now)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    error!("removeMember: failed to mark member as left: {}", e);
                    internal_server_error("Failed to remove member")
                })?;
            }

            // ── GroupInfo: keep existing (stale is better than absent) ─
            warn!(
                "removeMember: no GroupInfo provided with commit for convo {} — keeping existing (may be stale)",
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
                error!("removeMember: failed to get seq: {}", e);
                internal_server_error("Failed to allocate message sequence")
            })?;

            sqlx::query(
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, seq, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7)",
            )
            .bind(&msg_id)
            .bind(&convo_id)
            .bind(Option::<&str>::None)
            .bind(new_epoch)
            .bind(seq)
            .bind(&commit_bytes[..])
            .bind(&now)
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

            // ── Commit transaction ─────────────────────────────────────
            tx.commit().await.map_err(|e| {
                error!("removeMember: failed to commit transaction: {}", e);
                internal_server_error("Failed to commit transaction")
            })?;

            // ── Broadcast commit via SSE/WebSocket ───────────────────
            {
                let pool_clone = pool.clone();
                let sse_state_clone = sse_state.clone();
                let convo_id_clone = convo_id.clone();
                let msg_id_clone = msg_id.clone();
                let commit_bytes_clone = commit_bytes.clone();

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
                            let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
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

                    let cursor = sse_state_clone
                        .cursor_gen
                        .next(&convo_id_clone, "messageEvent")
                        .await;

                    let message_view: crate::realtime::StreamMessageView =
                        crate::generated::blue_catbird::mlsChat::MessageView {
                            id: msg_id_clone.clone().into(),
                            convo_id: convo_id_clone.clone().into(),
                            ciphertext: bytes::Bytes::from(commit_bytes_clone),
                            epoch: new_epoch as i64,
                            seq,
                            created_at: crate::sqlx_jacquard::chrono_to_datetime(now),
                            message_type: Some("commit".into()),
                            extra_data: Default::default(),
                        }
                        .into();

                    let event = crate::realtime::StreamEvent::MessageEvent {
                        cursor: cursor.clone(),
                        message: message_view,
                        ephemeral: false,
                    };

                    if let Err(e) =
                        crate::db::store_event(&pool_clone, &convo_id_clone, &event).await
                    {
                        error!("removeMember: store event failed: {:?}", e);
                    }

                    if let Err(e) = sse_state_clone.emit(&convo_id_clone, event).await {
                        error!("removeMember: SSE emit failed: {}", e);
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
            let member_dids_nonempty =
                input.member_dids.as_ref().is_some_and(|v| !v.is_empty());
            match super::commit_inspect::enforce_non_add_action_contract(
                welcome_present,
                member_dids_nonempty,
                commit_bytes,
            ) {
                Ok(shape) => info!(
                    "{}: framing OK (wire={:?}, ct={:?}) convo {}",
                    action_name,
                    shape.wire_format,
                    shape.content_type,
                    crate::crypto::redact_for_log(&convo_id)
                ),
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
            }

            let now = chrono::Utc::now();

            // ── Fetch current epoch for CAS ───────────────────────────
            let current_epoch = crate::db::get_current_epoch(&pool, &convo_id)
                .await
                .map_err(|e| {
                    error!("{}: failed to get current epoch: {}", action_name, e);
                    internal_server_error("Failed to get current epoch")
                })?;

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
                action_name, crate::crypto::redact_for_log(&convo_id)
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
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, seq, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7)",
            )
            .bind(&msg_id)
            .bind(&convo_id)
            .bind(Option::<&str>::None)
            .bind(new_epoch)
            .bind(seq)
            .bind(&commit_bytes[..])
            .bind(&now)
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

            // ── Commit transaction ─────────────────────────────────────
            tx.commit().await.map_err(|e| {
                error!("{}: failed to commit transaction: {}", action_name, e);
                internal_server_error("Failed to commit transaction")
            })?;

            // ── Broadcast commit via SSE/WebSocket ───────────────────
            {
                let pool_clone = pool.clone();
                let sse_state_clone = sse_state.clone();
                let convo_id_clone = convo_id.clone();
                let msg_id_clone = msg_id.clone();
                let commit_bytes_clone = commit_bytes.clone();
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
                            let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
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

                    let cursor = sse_state_clone
                        .cursor_gen
                        .next(&convo_id_clone, "messageEvent")
                        .await;

                    let message_view: crate::realtime::StreamMessageView =
                        crate::generated::blue_catbird::mlsChat::MessageView {
                            id: msg_id_clone.clone().into(),
                            convo_id: convo_id_clone.clone().into(),
                            ciphertext: bytes::Bytes::from(commit_bytes_clone),
                            epoch: new_epoch as i64,
                            seq,
                            created_at: crate::sqlx_jacquard::chrono_to_datetime(now),
                            message_type: Some("commit".into()),
                            extra_data: Default::default(),
                        }
                        .into();

                    let event = crate::realtime::StreamEvent::MessageEvent {
                        cursor: cursor.clone(),
                        message: message_view,
                        ephemeral: false,
                    };

                    if let Err(e) =
                        crate::db::store_event(&pool_clone, &convo_id_clone, &event).await
                    {
                        error!("{}: store event failed: {:?}", action_for_log, e);
                    }

                    if let Err(e) = sse_state_clone.emit(&convo_id_clone, event).await {
                        error!("{}: SSE emit failed: {}", action_for_log, e);
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
            info!(
                "v2.commitGroupChange: refreshGroupInfo for convo {}",
                crate::crypto::redact_for_log(&convo_id)
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

            // Emit GroupInfoRefreshRequested SSE event
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
                crate::crypto::redact_for_log(&convo_id)
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
        let current_epoch: Option<i32> = None;
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
}
