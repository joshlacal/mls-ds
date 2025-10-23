use crate::auth::Claims;
use crate::blob_storage::BlobStorage;
use crate::db::DbPool;
use anyhow::Context;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info};
use uuid::Uuid;

/// Request to store an encrypted message blob
#[derive(Debug, Deserialize)]
pub struct StoreMessageRequest {
    /// Base64-encoded encrypted message data
    pub encrypted_data: String,
    /// Conversation ID this message belongs to
    pub convo_id: String,
    /// List of recipient DIDs
    pub recipients: Vec<String>,
    /// Optional metadata (not encrypted)
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Response after storing a message
#[derive(Debug, Serialize)]
pub struct StoreMessageResponse {
    /// Unique message ID
    pub message_id: String,
    /// R2 blob key
    pub blob_key: String,
    /// When the message was stored
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Request to retrieve an encrypted message
#[derive(Debug, Deserialize)]
pub struct GetMessageRequest {
    pub message_id: String,
}

/// Response containing encrypted message data
#[derive(Debug, Serialize)]
pub struct GetMessageResponse {
    pub message_id: String,
    /// Base64-encoded encrypted message data
    pub encrypted_data: String,
    pub convo_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub metadata: Option<serde_json::Value>,
}

/// Store an encrypted message blob
/// POST /api/v1/messages
pub async fn store_message(
    claims: Claims,
    State(blob_storage): State<Arc<BlobStorage>>,
    State(db_pool): State<DbPool>,
    Json(req): Json<StoreMessageRequest>,
) -> Result<Json<StoreMessageResponse>, AppError> {
    let sender_did = &claims.sub;
    
    // Decode base64 encrypted data
    let encrypted_bytes = BASE64.decode(&req.encrypted_data)
        .context("Invalid base64 encrypted data")?;

    // Generate unique message ID
    let message_id = Uuid::new_v4().to_string();

    // Store blob in R2
    let blob_key = blob_storage
        .store_blob(&message_id, encrypted_bytes)
        .await
        .context("Failed to store message blob")?;

    let created_at = chrono::Utc::now();

    // Store metadata in PostgreSQL
    sqlx::query!(
        r#"
        INSERT INTO messages (id, convo_id, sender_did, blob_key, created_at, metadata)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        message_id,
        req.convo_id,
        sender_did,
        blob_key,
        created_at,
        req.metadata,
    )
    .execute(&db_pool)
    .await
    .context("Failed to store message metadata")?;

    // Store recipient list for fanout
    for recipient_did in &req.recipients {
        sqlx::query!(
            r#"
            INSERT INTO message_recipients (message_id, recipient_did, delivered)
            VALUES ($1, $2, false)
            "#,
            message_id,
            recipient_did,
        )
        .execute(&db_pool)
        .await
        .context("Failed to store recipient")?;
    }

    info!(
        message_id = %message_id,
        sender = %sender_did,
        convo_id = %req.convo_id,
        recipients = req.recipients.len(),
        "Stored encrypted message"
    );

    Ok(Json(StoreMessageResponse {
        message_id,
        blob_key,
        created_at,
    }))
}

/// Retrieve an encrypted message blob
/// GET /api/v1/messages/:message_id
pub async fn get_message(
    claims: Claims,
    State(blob_storage): State<Arc<BlobStorage>>,
    State(db_pool): State<DbPool>,
    Path(message_id): Path<String>,
) -> Result<Json<GetMessageResponse>, AppError> {
    let requester_did = &claims.sub;

    // Fetch message metadata from PostgreSQL
    let message = sqlx::query!(
        r#"
        SELECT m.id, m.convo_id, m.blob_key, m.created_at, m.metadata
        FROM messages m
        INNER JOIN message_recipients mr ON m.id = mr.message_id
        WHERE m.id = $1 AND mr.recipient_did = $2
        "#,
        message_id,
        requester_did,
    )
    .fetch_optional(&db_pool)
    .await
    .context("Failed to fetch message metadata")?
    .ok_or_else(|| anyhow::anyhow!("Message not found or not authorized"))?;

    // Fetch blob from R2
    let encrypted_bytes = blob_storage
        .get_blob(&message_id)
        .await
        .context("Failed to fetch message blob")?;

    // Encode to base64
    let encrypted_data = BASE64.encode(&encrypted_bytes);

    // Mark as delivered
    sqlx::query!(
        r#"
        UPDATE message_recipients
        SET delivered = true, delivered_at = now()
        WHERE message_id = $1 AND recipient_did = $2
        "#,
        message_id,
        requester_did,
    )
    .execute(&db_pool)
    .await
    .context("Failed to mark message as delivered")?;

    info!(
        message_id = %message_id,
        recipient = %requester_did,
        "Retrieved encrypted message"
    );

    Ok(Json(GetMessageResponse {
        message_id,
        encrypted_data,
        convo_id: message.convo_id,
        created_at: message.created_at,
        metadata: message.metadata,
    }))
}

/// List pending messages for the current user
/// GET /api/v1/messages/pending
pub async fn list_pending_messages(
    claims: Claims,
    State(db_pool): State<DbPool>,
) -> Result<Json<Vec<PendingMessage>>, AppError> {
    let recipient_did = &claims.sub;

    let messages = sqlx::query_as!(
        PendingMessage,
        r#"
        SELECT m.id as message_id, m.convo_id, m.created_at
        FROM messages m
        INNER JOIN message_recipients mr ON m.id = mr.message_id
        WHERE mr.recipient_did = $1 AND mr.delivered = false
        ORDER BY m.created_at DESC
        LIMIT 100
        "#,
        recipient_did,
    )
    .fetch_all(&db_pool)
    .await
    .context("Failed to fetch pending messages")?;

    Ok(Json(messages))
}

#[derive(Debug, Serialize)]
pub struct PendingMessage {
    pub message_id: String,
    pub convo_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Error type for message handlers
pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        error!("Handler error: {:?}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("{}", self.0)
            })),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
