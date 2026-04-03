use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use tracing::{error, info};

use jacquard_axum::ExtractXrpc;

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::update_cursor::{UpdateCursorOutput, UpdateCursorRequest},
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

#[derive(Serialize)]
struct XrpcErrorBody {
    error: &'static str,
    message: String,
}

pub struct XrpcError(StatusCode, &'static str, String);

impl IntoResponse for XrpcError {
    fn into_response(self) -> Response {
        (
            self.0,
            Json(XrpcErrorBody {
                error: self.1,
                message: self.2,
            }),
        )
            .into_response()
    }
}

const NSID: &str = "blue.catbird.mlsChat.updateCursor";

/// Cursor update endpoint.
///
/// POST /xrpc/blue.catbird.mlsChat.updateCursor
///
/// Updates the opaque read cursor for a conversation and resets unread count.
#[tracing::instrument(skip(pool, auth_user, input))]
pub async fn update_cursor(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<UpdateCursorRequest>,
) -> Result<Json<UpdateCursorOutput<'static>>, XrpcError> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [v2.updateCursor] Unauthorized");
        return Err(XrpcError(StatusCode::UNAUTHORIZED, "AuthRequired", "Authentication required".into()));
    }

    let convo_id = input.convo_id.to_string();
    let caller_did = &auth_user.did;

    // Cursor is required
    let cursor = match input.cursor {
        Some(ref c) => c.to_string(),
        None => {
            return Err(XrpcError(StatusCode::BAD_REQUEST, "InvalidRequest", "cursor is required".into()));
        }
    };

    // Check membership
    let is_member: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM members
            WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL
        )
        "#,
    )
    .bind(&convo_id)
    .bind(caller_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Failed to check membership: {}", e);
        XrpcError(StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", "Failed to check membership".into())
    })?;

    if !is_member {
        return Err(XrpcError(StatusCode::FORBIDDEN, "Forbidden", "Not a member of this conversation".into()));
    }

    // Validate cursor format
    crate::realtime::cursor::CursorGenerator::validate(&cursor)
        .map_err(|_| XrpcError(StatusCode::BAD_REQUEST, "InvalidRequest", "Invalid cursor format".into()))?;

    info!(
        user = %crate::crypto::redact_for_log(caller_did),
        convo = %crate::crypto::redact_for_log(&convo_id),
        "Updating cursor"
    );

    // Upsert cursor
    sqlx::query(
        r#"
        INSERT INTO cursors (user_did, convo_id, last_seen_cursor, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (user_did, convo_id)
        DO UPDATE SET last_seen_cursor = $3, updated_at = NOW()
        "#,
    )
    .bind(caller_did)
    .bind(&convo_id)
    .bind(&cursor)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Failed to update cursor: {}", e);
        XrpcError(StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", "Failed to update cursor".into())
    })?;

    // Reset unread count
    sqlx::query(
        "UPDATE members SET unread_count = 0, last_read_at = NOW() WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL",
    )
    .bind(&convo_id)
    .bind(caller_did)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Failed to reset unread count: {}", e);
        XrpcError(StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", "Failed to reset unread count".into())
    })?;

    Ok(Json(UpdateCursorOutput {
        updated_at: chrono_to_datetime(chrono::Utc::now()),
        read_at: None,
        extra_data: Default::default(),
    }))
}
