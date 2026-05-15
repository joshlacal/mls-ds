use axum::{extract::State, http::StatusCode, Json};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{error, warn};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    realtime::{SseState, StreamEvent},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.reissueWelcomeRespond";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReissueWelcomeRespondRequest {
    pub request_id: String,
    pub welcome_blob: String,
    pub key_package_hash: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReissueWelcomeRespondOutput {
    pub stored: bool,
    pub request_id: String,
    pub welcome_blob_id: String,
    pub responded_at: DateTime<Utc>,
}

#[tracing::instrument(skip(pool, sse_state, auth_user, input))]
pub async fn reissue_welcome_respond(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    Json(input): Json<ReissueWelcomeRespondRequest>,
) -> Result<Json<ReissueWelcomeRespondOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let welcome_bytes = STANDARD.decode(&input.welcome_blob).map_err(|e| {
        warn!("reissueWelcomeRespond: invalid base64 Welcome blob: {}", e);
        StatusCode::BAD_REQUEST
    })?;
    if welcome_bytes.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let welcome_blob_id = Uuid::new_v4().to_string();
    let responded_at = Utc::now();
    let key_package_hash_bytes = match input.key_package_hash.as_deref() {
        Some(hash) => {
            let decoded = hex::decode(hash).map_err(|e| {
                warn!("reissueWelcomeRespond: invalid keyPackageHash hex: {}", e);
                StatusCode::BAD_REQUEST
            })?;
            Some(decoded)
        }
        None => None,
    };

    let mut tx = pool.begin().await.map_err(|e| {
        error!("reissueWelcomeRespond: tx begin failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let row: Option<(String, String)> = sqlx::query_as(
        r#"
        SELECT rr.convo_id, rr.recipient_device_did
        FROM reissue_requests rr
        WHERE rr.id = $1
          AND rr.responded_at IS NULL
        FOR UPDATE
        "#,
    )
    .bind(&input.request_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        error!("reissueWelcomeRespond: request lookup failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let Some((convo_id, recipient_device_did)) = row else {
        return Err(StatusCode::NOT_FOUND);
    };

    let responder_is_admin: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM members
            WHERE convo_id = $1
              AND (member_did = $2 OR user_did = $2)
              AND COALESCE(is_admin, false) = true
              AND left_at IS NULL
        )
        "#,
    )
    .bind(&convo_id)
    .bind(&auth_user.did)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        error!("reissueWelcomeRespond: admin check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if !responder_is_admin {
        return Err(StatusCode::FORBIDDEN);
    }

    sqlx::query(
        r#"
        INSERT INTO welcome_messages
            (id, convo_id, recipient_did, welcome_data, key_package_hash, created_by_did, created_at, consumed)
        VALUES ($1, $2, $3, $4, $5, $6, $7, false)
        "#,
    )
    .bind(&welcome_blob_id)
    .bind(&convo_id)
    .bind(&recipient_device_did)
    .bind(&welcome_bytes)
    .bind(key_package_hash_bytes)
    .bind(&auth_user.did)
    .bind(responded_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("reissueWelcomeRespond: welcome insert failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let updated = sqlx::query(
        r#"
        UPDATE reissue_requests
        SET responded_at = $2,
            welcome_blob_id = $3
        WHERE id = $1
          AND responded_at IS NULL
        "#,
    )
    .bind(&input.request_id)
    .bind(responded_at)
    .bind(&welcome_blob_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("reissueWelcomeRespond: request update failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if updated.rows_affected() != 1 {
        warn!(
            "reissueWelcomeRespond: request {} was answered concurrently",
            input.request_id
        );
        return Err(StatusCode::CONFLICT);
    }

    tx.commit().await.map_err(|e| {
        error!("reissueWelcomeRespond: tx commit failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let info = json!({
        "kind": "welcomeReissued",
        "convoId": convo_id,
        "recipientDeviceDid": recipient_device_did,
        "requestId": input.request_id,
        "welcomeBlobId": welcome_blob_id,
        "respondedAt": responded_at.to_rfc3339(),
    });
    let event = StreamEvent::InfoEvent {
        cursor: sse_state.cursor_gen.next(&convo_id, "infoEvent").await,
        info: info.to_string(),
    };
    if let Err(e) = sse_state.emit(&convo_id, event).await {
        warn!("reissueWelcomeRespond: best-effort SSE emit failed: {}", e);
    }

    Ok(Json(ReissueWelcomeRespondOutput {
        stored: true,
        request_id: input.request_id,
        welcome_blob_id,
        responded_at,
    }))
}
