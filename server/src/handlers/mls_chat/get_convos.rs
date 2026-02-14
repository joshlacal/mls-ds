use axum::{
    extract::{Query, RawQuery, State},
    http::StatusCode,
    Json,
};
use jacquard_axum::ExtractXrpc;
use tracing::error;

use crate::{
    auth::AuthUser, generated::blue_catbird::mlsChat::get_convos::GetConvosRequest,
    handlers::list_chat_requests::ListChatRequestsParams, storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getConvos";

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Consolidated conversation listing endpoint.
///
/// GET /xrpc/blue.catbird.mlsChat.getConvos
///
/// Query parameter `filter` selects behavior:
/// - `"all"` (default) → delegates to existing `get_convos`
/// - `"pending"`        → delegates to existing `list_chat_requests` + `get_request_count`
/// - `"expected"`       → delegates to existing `get_expected_conversations`
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_convos(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    RawQuery(extra_query): RawQuery,
    ExtractXrpc(params): ExtractXrpc<GetConvosRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let extra_query_str = extra_query.as_deref().unwrap_or("");

    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [v2.getConvos] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let filter = params.filter.as_deref().unwrap_or("all");

    // Parse extra query params not in the generated type
    let mut device_id: Option<String> = None;
    let mut status: Option<String> = None;
    for pair in extra_query_str.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let decoded = match urlencoding::decode(value) {
                Ok(v) => v.to_string(),
                Err(e) => {
                    error!("❌ [v2.getConvos] Failed to decode query parameter '{}': {}", key, e);
                    return Err(StatusCode::BAD_REQUEST);
                }
            };
            match key {
                "deviceId" => device_id = Some(decoded),
                "status" => status = Some(decoded),
                _ => {}
            }
        }
    }

    match filter {
        "all" => {
            // Delegate to v1 get_convos
            let result = crate::handlers::get_convos(State(pool), auth_user).await?;
            Ok(Json(serde_json::to_value(result.0).unwrap()))
        }

        "pending" => {
            let list_params = ListChatRequestsParams {
                cursor: params.cursor.map(|c| c.to_string()),
                limit: params.limit,
                status: status.or_else(|| Some("pending".to_string())),
            };

            let list_result = crate::handlers::list_chat_requests(
                State(pool.clone()),
                auth_user.clone(),
                Query(list_params),
            )
            .await?;

            let count_result =
                crate::handlers::get_request_count::get_request_count(State(pool), auth_user)
                    .await?;

            let mut response = serde_json::to_value(list_result.0).unwrap_or(serde_json::json!({}));
            if let Some(obj) = response.as_object_mut() {
                obj.insert(
                    "pendingCount".to_string(),
                    serde_json::json!(count_result.0.count),
                );
            }

            Ok(Json(response))
        }

        "expected" => {
            let expected_params =
                crate::handlers::get_expected_conversations::GetExpectedConversationsParams {
                    device_id,
                };

            let result = crate::handlers::get_expected_conversations(
                State(pool),
                auth_user,
                Query(expected_params),
            )
            .await?;

            Ok(Json(
                serde_json::to_value(result.0).unwrap_or(serde_json::json!({})),
            ))
        }

        other => {
            error!("❌ [v2.getConvos] Unknown filter: {}", other);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}
