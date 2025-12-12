use axum::{extract::State, Json};
use axum::http::StatusCode;
use openmls::prelude::*;
use openmls::prelude::tls_codec::Deserialize;
use serde::{Deserialize as SerdeDeserialize, Serialize};
use tracing::{error, info, warn};
use base64::Engine;

use crate::{
    auth::AuthUser,
    storage::{get_current_epoch, DbPool},
    realtime::{SseState, StreamEvent},
};
use std::sync::Arc;
use axum::response::{IntoResponse, Response};

// Query result types
#[derive(sqlx::FromRow)]
struct PolicyRow {
    allow_external_commits: bool,
    require_invite_for_join: bool,
    allow_rejoin: bool,
    rejoin_window_days: i32,
}

#[derive(sqlx::FromRow)]
struct MemberCheckRow {
    left_at: Option<chrono::DateTime<chrono::Utc>>,
    needs_rejoin: bool,
    member_did: String,
    user_did: String,
    rejoin_psk_hash: Option<String>,
    joined_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputData {
    pub convo_id: String,
    pub external_commit: String,
    pub idempotency_key: Option<String>,
    pub group_info: Option<String>,

    /// PSK for authentication (client-provided plaintext PSK)
    /// Server will hash this and compare against:
    /// - invite.psk_hash (for new joins)
    /// - member.rejoin_psk_hash (for rejoins)
    ///
    /// Note: In production, this should ideally be extracted from the MLS
    /// external commit PreSharedKey proposal. For now, we accept it as a
    /// separate parameter to simplify implementation.
    pub psk: Option<String>,
}

#[derive(Debug, SerdeDeserialize)]
pub struct Input {
    pub data: InputData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputData {
    pub epoch: i64,
    pub rejoined_at: String,
}

#[derive(Debug, Serialize)]
pub struct Output {
    pub data: OutputData,
}

impl From<OutputData> for Output {
    fn from(data: OutputData) -> Self {
        Self { data }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "error", content = "message")]
pub enum Error {
    Unauthorized(Option<String>),
    InvalidCommit(Option<String>),
    InvalidGroupInfo(Option<String>),
    InvalidPsk(Option<String>),
    PolicyViolation(Option<String>),
}

pub enum ProcessExternalCommitError {
    Structured(Error),
    Generic(StatusCode),
}

impl IntoResponse for ProcessExternalCommitError {
    fn into_response(self) -> Response {
        match self {
            Self::Structured(err) => {
                let status = match &err {
                    Error::Unauthorized(_) => StatusCode::FORBIDDEN,
                    Error::InvalidCommit(_) => StatusCode::BAD_REQUEST,
                    Error::InvalidGroupInfo(_) => StatusCode::BAD_REQUEST,
                    Error::InvalidPsk(_) => StatusCode::FORBIDDEN,
                    Error::PolicyViolation(_) => StatusCode::FORBIDDEN,
                };
                (status, Json(err)).into_response()
            }
            Self::Generic(status) => status.into_response(),
        }
    }
}

impl From<StatusCode> for ProcessExternalCommitError {
    fn from(status: StatusCode) -> Self {
        Self::Generic(status)
    }
}

impl From<Error> for ProcessExternalCommitError {
    fn from(err: Error) -> Self {
        Self::Structured(err)
    }
}

/// Hash PSK using SHA256 and return hex string
fn hash_psk(psk: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(psk.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

pub async fn handle(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth: AuthUser,
    Json(input): Json<InputData>,
) -> Result<Json<Output>, ProcessExternalCommitError> {
    let did = &auth.did;
    let convo_id = &input.convo_id;

    info!("Processing external commit for {} in {}", did, convo_id);

    // Enforce idempotency key
    let require_idem = std::env::var("REQUIRE_IDEMPOTENCY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(true);
    if require_idem && input.idempotency_key.is_none() {
        warn!("❌ [process_external_commit] Missing idempotencyKey");
        return Err(StatusCode::BAD_REQUEST.into());
    }

    // =========================================================================
    // STEP 1: Fetch conversation policy (master switch)
    // =========================================================================

    let policy = sqlx::query_as::<_, PolicyRow>(
        r#"
        SELECT
            allow_external_commits,
            require_invite_for_join,
            allow_rejoin,
            rejoin_window_days
        FROM conversation_policy
        WHERE convo_id = $1
        "#
    )
    .bind(convo_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Database error fetching policy: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or_else(|| {
        error!("No policy found for conversation {}", convo_id);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Master switch: if external commits disabled entirely, reject immediately
    if !policy.allow_external_commits {
        return Err(Error::PolicyViolation(
            Some("External commits are disabled for this conversation".into())
        ).into());
    }

    // =========================================================================
    // STEP 2: Check if user is already a member (rejoin vs new join)
    // =========================================================================

    let member_check = sqlx::query_as::<_, MemberCheckRow>(
        r#"
        SELECT
            left_at,
            needs_rejoin,
            member_did,
            user_did,
            rejoin_psk_hash,
            joined_at
        FROM members
        WHERE convo_id = $1 AND user_did = $2
        ORDER BY joined_at DESC
        LIMIT 1
        "#
    )
    .bind(convo_id)
    .bind(did)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Database error checking membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // =========================================================================
    // STEP 3: Determine flow type and verify authorization
    // =========================================================================

    let is_rejoin = match &member_check {
        Some(member) if member.left_at.is_none() => {
            // Member exists and hasn't left
            true
        }
        Some(member) if member.left_at.is_some() => {
            // Member left the group - treat as unauthorized
            // (Rejoining after leaving is different from resyncing after desync)
            return Err(Error::Unauthorized(
                Some("Member was removed or left. Request re-add from admin.".into())
            ).into());
        }
        None => {
            // Not a member - this is a new join
            false
        }
        _ => false,
    };

    if is_rejoin {
        // =====================================================================
        // REJOIN FLOW: Member exists, needs cryptographic resync
        // =====================================================================

        let member = member_check.as_ref().unwrap();

        info!(
            "Processing rejoin for member {} in {} (needs_rejoin: {})",
            did, convo_id, member.needs_rejoin
        );

        // Check rejoin policy
        if !policy.allow_rejoin {
            return Err(Error::PolicyViolation(
                Some("Rejoin is disabled for this conversation".into())
            ).into());
        }

        // Check rejoin window (0 = unlimited)
        if policy.rejoin_window_days > 0 {
            let window_duration = chrono::Duration::days(policy.rejoin_window_days.into());
            let rejoin_deadline = member.joined_at + window_duration;
            let now = chrono::Utc::now();

            if now > rejoin_deadline {
                return Err(Error::PolicyViolation(
                    Some(format!(
                        "Rejoin window expired. Members can only rejoin within {} days of joining.",
                        policy.rejoin_window_days
                    ))
                ).into());
            }
        }

        // CRYPTO AUTHORIZATION: Verify rejoin PSK
        if let Some(psk) = &input.psk {
            let provided_psk_hash = hash_psk(psk);

            match &member.rejoin_psk_hash {
                Some(stored_hash) => {
                    if provided_psk_hash != *stored_hash {
                        warn!(
                            "❌ Rejoin PSK verification failed for {} in {}",
                            did, convo_id
                        );
                        return Err(Error::InvalidPsk(
                            Some("Invalid rejoin PSK".into())
                        ).into());
                    }
                    info!("✅ Rejoin PSK verified for {} in {}", did, convo_id);
                }
                None => {
                    // No PSK stored - this member joined before PSK system was implemented
                    // For backwards compatibility, allow rejoin without PSK verification
                    // (Production systems may want to require PSK update first)
                    warn!(
                        "⚠️  No rejoin PSK stored for {} in {} - allowing rejoin for backwards compatibility",
                        did, convo_id
                    );
                }
            }
        } else {
            // PSK not provided
            if member.rejoin_psk_hash.is_some() {
                // Member has PSK but didn't provide it
                return Err(Error::InvalidPsk(
                    Some("Rejoin PSK required but not provided".into())
                ).into());
            }
            // No PSK required (legacy member)
        }

    } else {
        // =====================================================================
        // NEW JOIN FLOW: Non-member attempting to join
        // =====================================================================

        info!("Processing new join for {} in {}", did, convo_id);

        // Check if invites are required
        if policy.require_invite_for_join {
            // Invite PSK verification required
            let psk = input.psk.as_ref().ok_or_else(|| {
                Error::InvalidPsk(
                    Some("Invite PSK required but not provided".into())
                )
            })?;

            let psk_hash = hash_psk(psk);

            // Use helper function from create_invite.rs to check invite validity
            use crate::handlers::create_invite::is_invite_valid;

            let invite_id = is_invite_valid(&pool, &psk_hash, Some(did))
                .await
                .map_err(|e| {
                    error!("Error checking invite validity: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?
                .ok_or_else(|| {
                    warn!("❌ Invalid or expired invite for {} in {}", did, convo_id);
                    Error::InvalidPsk(
                        Some("Invalid, expired, or already-used invite".into())
                    )
                })?;

            info!("✅ Invite PSK verified for {} in {} (invite_id: {})", did, convo_id, invite_id);

            // Increment invite uses count (will be committed with the transaction)
            // We do this after all validations to ensure atomicity
            // Note: This happens in the transaction below
        } else {
            // Invites not required - open join allowed
            info!("Open join allowed for {} in {} (no invite required)", did, convo_id);
        }
    }

    // =========================================================================
    // STEP 4: Validate commit structure
    // =========================================================================

    // Decode commit message
    let commit_bytes = base64::engine::general_purpose::STANDARD
        .decode(&input.external_commit)
        .map_err(|e| Error::InvalidCommit(Some(format!("Invalid base64: {}", e))))?;

    // Validate commit structure (server validates format, clients validate cryptography)
    let _mls_message = MlsMessageIn::tls_deserialize(&mut commit_bytes.as_slice())
        .map_err(|e| Error::InvalidCommit(Some(format!("Invalid MLS message: {}", e))))?;

    // =========================================================================
    // STEP 5: Store commit and update state
    // =========================================================================

    let current_epoch = get_current_epoch(&pool, convo_id)
        .await
        .map_err(|e| {
            error!("Failed to get current epoch: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let new_epoch = current_epoch + 1;
    let now = chrono::Utc::now();

    // Decode GroupInfo if present
    let group_info_bytes = if let Some(gi_str) = &input.group_info {
        Some(base64::engine::general_purpose::STANDARD
            .decode(gi_str)
            .map_err(|e| Error::InvalidGroupInfo(Some(format!("Invalid base64: {}", e))))?)
    } else {
        None
    };

    // Start transaction
    let mut tx = pool.begin().await.map_err(|e| {
        error!("Failed to start transaction: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Insert commit message
    let msg_id = uuid::Uuid::new_v4().to_string();
    let seq: i64 = sqlx::query_scalar(
        "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1"
    )
    .bind(convo_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        error!("Failed to calculate sequence number: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query(
        "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, seq, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7)"
    )
    .bind(&msg_id)
    .bind(convo_id)
    .bind(did)
    .bind(new_epoch)
    .bind(seq)
    .bind(&commit_bytes)
    .bind(&now)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("Failed to insert commit message: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Update conversation epoch
    sqlx::query("UPDATE conversations SET current_epoch = $1 WHERE id = $2")
        .bind(new_epoch)
        .bind(convo_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("Failed to update conversation epoch: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Update GroupInfo if provided
    if let Some(gi_bytes) = group_info_bytes {
        sqlx::query(
            "UPDATE conversations
             SET group_info = $1,
                 group_info_updated_at = $2,
                 group_info_epoch = $3
             WHERE id = $4"
        )
        .bind(&gi_bytes)
        .bind(now)
        .bind(new_epoch)
        .bind(convo_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("Failed to update GroupInfo: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    // =========================================================================
    // STEP 6: Update member state or create new member
    // =========================================================================

    if is_rejoin {
        // Clear needs_rejoin flag - device is now cryptographically resynced
        sqlx::query(
            "UPDATE members
             SET needs_rejoin = false,
                 rejoin_requested_at = NULL,
                 rejoin_key_package_hash = NULL
             WHERE convo_id = $1 AND user_did = $2"
        )
        .bind(convo_id)
        .bind(did)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("Failed to update member status: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    } else {
        // New join: Increment invite uses if invite was used
        if policy.require_invite_for_join && input.psk.is_some() {
            let psk_hash = hash_psk(input.psk.as_ref().unwrap());

            // Get invite ID
            let invite_id = sqlx::query_scalar::<_, String>(
                r#"
                SELECT id
                FROM invites
                WHERE psk_hash = $1
                  AND revoked = false
                  AND (expires_at IS NULL OR expires_at > NOW())
                  AND (max_uses IS NULL OR uses_count < max_uses)
                  AND ($2::TEXT IS NULL OR target_did IS NULL OR target_did = $2)
                LIMIT 1
                "#
            )
            .bind(&psk_hash)
            .bind(did)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                error!("Failed to fetch invite ID: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            if let Some(invite_id) = invite_id {
                // Increment uses count
                sqlx::query(
                    "UPDATE invites SET uses_count = uses_count + 1 WHERE id = $1"
                )
                .bind(&invite_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    error!("Failed to increment invite uses: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
            }
        }

        // Note: The actual member row insertion happens via the MLS add_members
        // flow, not here. External commits for new members typically require
        // the group to have already added them, and this commit is just their
        // acceptance of the welcome message.
        //
        // If your implementation expects member creation here, add:
        // INSERT INTO members (convo_id, member_did, user_did, joined_at, ...)
        // VALUES (...)
    }

    tx.commit().await.map_err(|e| {
        error!("Failed to commit transaction: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Mark any pending device additions for this device as self_joined
    // This prevents other members from trying to add a device that just joined itself
    let self_joined_result = sqlx::query!(
        r#"
        UPDATE pending_device_additions
        SET status = 'self_joined',
            completed_at = $2,
            completed_by_did = $1,
            new_epoch = $3,
            updated_at = $2
        WHERE convo_id = $4
          AND new_device_credential_did = $1
          AND status IN ('pending', 'in_progress')
        "#,
        did,
        now,
        new_epoch as i32,
        convo_id
    )
    .execute(&pool)
    .await;

    match self_joined_result {
        Ok(result) if result.rows_affected() > 0 => {
            info!(
                "Marked {} pending addition(s) as self_joined for device {} in {}",
                result.rows_affected(), did, convo_id
            );
        }
        Ok(_) => {
            // No pending additions to mark - that's fine
        }
        Err(e) => {
            // Non-fatal error - log and continue
            warn!("Failed to mark pending additions as self_joined: {}", e);
        }
    }

    info!("External commit processed: {} -> epoch {}", convo_id, new_epoch);

    // =========================================================================
    // STEP 7: Fanout (Async)
    // =========================================================================

    let pool_clone = pool.clone();
    let convo_id_clone = convo_id.clone();
    let msg_id_clone = msg_id.clone();
    let sse_state_clone = sse_state.clone();

    tokio::spawn(async move {
        tracing::debug!("📍 [process_external_commit:fanout] starting commit fan-out");

        // Get all active members
        let members_result = sqlx::query_as::<_, (String,)>(
            r#"
            SELECT member_did
            FROM members
            WHERE convo_id = $1 AND left_at IS NULL
            "#,
        )
        .bind(&convo_id_clone)
        .fetch_all(&pool_clone)
        .await;

        match members_result {
            Ok(members) => {
                tracing::debug!("📍 [process_external_commit:fanout] fan-out commit to {} members", members.len());

                // Create envelopes for each member
                for (member_did,) in &members {
                    let envelope_id = uuid::Uuid::new_v4().to_string();

                    let envelope_result = sqlx::query(
                        r#"
                        INSERT INTO envelopes (id, convo_id, recipient_did, message_id, created_at)
                        VALUES ($1, $2, $3, $4, NOW())
                        ON CONFLICT (recipient_did, message_id) DO NOTHING
                        "#,
                    )
                    .bind(&envelope_id)
                    .bind(&convo_id_clone)
                    .bind(member_did)
                    .bind(&msg_id_clone)
                    .execute(&pool_clone)
                    .await;

                    if let Err(e) = envelope_result {
                        error!(
                            "❌ [process_external_commit:fanout] Failed to insert envelope for {}: {:?}",
                            member_did, e
                        );
                    }
                }
            }
            Err(e) => {
                error!("❌ [process_external_commit:fanout] Failed to get members: {:?}", e);
            }
        }

        // Emit SSE
        let cursor = sse_state_clone.cursor_gen.next(&convo_id_clone, "messageEvent").await;

        // Fetch the commit message from database
        let message_result = sqlx::query_as::<_, (String, Option<String>, Option<Vec<u8>>, i64, i64, chrono::DateTime<chrono::Utc>)>(
            r#"
            SELECT id, sender_did, ciphertext, epoch, seq, created_at
            FROM messages
            WHERE id = $1
            "#,
        )
        .bind(&msg_id_clone)
        .fetch_one(&pool_clone)
        .await;

        match message_result {
            Ok((id, _sender_did, ciphertext, epoch, seq, created_at)) => {
                let message_view = crate::models::MessageView::from(crate::models::MessageViewData {
                    id,
                    convo_id: convo_id_clone.clone(),
                    ciphertext: ciphertext.unwrap_or_default(),
                    epoch: epoch as usize,
                    seq: seq as usize,
                    created_at: crate::sqlx_atrium::chrono_to_datetime(created_at),
                    message_type: None,
                });

                let event = StreamEvent::MessageEvent {
                    cursor: cursor.clone(),
                    message: message_view,
                };

                // Store event
                if let Err(e) = crate::db::store_event(
                    &pool_clone,
                    &cursor,
                    &convo_id_clone,
                    "messageEvent",
                    Some(&msg_id_clone),
                )
                .await
                {
                    error!("❌ [process_external_commit:fanout] Failed to store event: {:?}", e);
                }

                // Emit to SSE subscribers
                if let Err(e) = sse_state_clone.emit(&convo_id_clone, event).await {
                    error!("❌ [process_external_commit:fanout] Failed to emit SSE event: {}", e);
                }
            }
            Err(e) => {
                error!("❌ [process_external_commit:fanout] Failed to fetch commit message for SSE event: {:?}", e);
            }
        }
    });

    Ok(Json(Output::from(OutputData {
        epoch: new_epoch as i64,
        rejoined_at: now.to_rfc3339(),
    })))
}
