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

#[derive(Debug, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputData {
    pub convo_id: String,
    pub external_commit: String,
    pub idempotency_key: Option<String>,
    pub group_info: Option<String>,
}

#[derive(Debug, SerdeDeserialize)]
pub struct Input {
    pub data: InputData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputData {
    pub success: bool,
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

pub async fn handle(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth: AuthUser,
    Json(input): Json<InputData>, // Accept InputData directly if using standard Json extractor, or Input if wrapped
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
    
    // 1. Verify authorization
    // External commits are for members who are still in the group socially,
    // but whose devices are cryptographically out of sync (lost state, app reinstall, etc.)
    // This is different from members who left/were removed (social decision).
    let member_check = sqlx::query!(
        "SELECT left_at, needs_rejoin, member_did
         FROM members
         WHERE convo_id = $1 AND user_did = $2
         ORDER BY joined_at DESC
         LIMIT 1",
        convo_id,
        did
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Database error checking membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let member = member_check.ok_or(Error::Unauthorized(
        Some("Not a member of this conversation".into())
    ))?;

    // Distinguish between social removal and cryptographic desync:
    // - left_at NOT NULL: Removed/left voluntarily (social decision) → REJECT
    // - left_at IS NULL, needs_rejoin = true: Out of sync (crypto issue) → ALLOW
    // - left_at IS NULL, needs_rejoin = false: In sync → ALLOW (idempotent rejoin)

    if member.left_at.is_some() {
        return Err(Error::Unauthorized(
            Some("Member was removed or left. External commits are only for cryptographic resync. Request re-add from admin.".into())
        ).into());
    }

    // Log rejoin attempt for monitoring
    if member.needs_rejoin {
        info!(
            "Processing external commit for out-of-sync member {} in {}",
            did, convo_id
        );
    } else {
        info!(
            "Processing external commit for member {} in {} (idempotent rejoin or proactive resync)",
            did, convo_id
        );
    }
    
    // 2. Decode commit message
    let commit_bytes = base64::engine::general_purpose::STANDARD
        .decode(&input.external_commit)
        .map_err(|e| Error::InvalidCommit(Some(format!("Invalid base64: {}", e))))?;
    
    // 3. Validate commit structure (server validates format, clients validate cryptography)
    let _mls_message = MlsMessageIn::tls_deserialize(&mut commit_bytes.as_slice())
        .map_err(|e| Error::InvalidCommit(Some(format!("Invalid MLS message: {}", e))))?;

    // 4. Store commit and update state
    // Server role: authorization + delivery; Client role: cryptographic validation
    
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
        
    // Clear needs_rejoin flag - device is now cryptographically resynced
    // Cryptographic validation happens client-side when members process this commit
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
    
    tx.commit().await.map_err(|e| {
        error!("Failed to commit transaction: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    info!("External commit processed: {} -> epoch {}", convo_id, new_epoch);
    
    // 5. Fanout (Async)
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
        success: true,
        epoch: new_epoch as i64,
        rejoined_at: now.to_rfc3339(),
    })))
}
