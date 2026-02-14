use axum::{
    extract::{Query, RawQuery, State},
    http::StatusCode,
    Json,
};
use jacquard_axum::ExtractXrpc;
use std::sync::Arc;
use tracing::{error, warn};

use crate::{
    actors::ActorRegistry, auth::AuthUser,
    generated::blue_catbird::mlsChat::get_messages::GetMessagesRequest,
    handlers::get_commits::GetCommitsParams, handlers::get_messages::GetMessagesParams,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getMessages";

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Consolidated message retrieval endpoint.
///
/// GET /xrpc/blue.catbird.mlsChat.getMessages
///
/// Query parameter `type` selects behavior:
/// - `"all"` (default) → returns both app messages and commits
/// - `"app"`           → delegates to existing `get_messages`
/// - `"commit"`        → delegates to existing `get_commits`
#[tracing::instrument(skip(pool, actor_registry, auth_user))]
pub async fn get_messages(
    State(pool): State<DbPool>,
    State(actor_registry): State<Arc<ActorRegistry>>,
    auth_user: AuthUser,
    RawQuery(extra_query): RawQuery,
    ExtractXrpc(params): ExtractXrpc<GetMessagesRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let extra_query_str = extra_query.as_deref().unwrap_or("");

    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [v2.getMessages] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let message_type = params.r#type.as_deref().unwrap_or("all");
    let convo_id = params.convo_id.to_string();
    let limit = params.limit.map(|l| l as i32);
    let since_seq = params.since_seq;

    match message_type {
        "app" => {
            let v1_params = GetMessagesParams {
                convo_id,
                since_seq,
                limit,
            };

            let result = crate::handlers::get_messages(
                State(pool),
                State(actor_registry),
                auth_user,
                Query(v1_params),
            )
            .await?;
            Ok(Json(serde_json::to_value(result.0).unwrap()))
        }

        "commit" => {
            // Parse additional query params for commits from the raw query string
            let mut from_epoch: i64 = 0;
            let mut to_epoch: Option<i64> = None;
            for pair in extra_query_str.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    match key {
                        "fromEpoch" => {
                            from_epoch = value.parse().unwrap_or(0);
                        }
                        "toEpoch" => {
                            to_epoch = value.parse().ok();
                        }
                        _ => {}
                    }
                }
            }

            let v1_params = GetCommitsParams {
                convo_id,
                from_epoch,
                to_epoch,
            };

            let result =
                crate::handlers::get_commits(State(pool), auth_user, Query(v1_params)).await?;

            Ok(Json(
                serde_json::to_value(result.0).unwrap_or(serde_json::json!({})),
            ))
        }

        "all" => {
            let v1_msg_params = GetMessagesParams {
                convo_id: convo_id.clone(),
                since_seq,
                limit,
            };

            let messages_result = crate::handlers::get_messages(
                State(pool.clone()),
                State(actor_registry),
                auth_user.clone(),
                Query(v1_msg_params),
            )
            .await?;

            // Parse additional commit params
            let mut from_epoch: i64 = 0;
            let mut to_epoch: Option<i64> = None;
            for pair in extra_query_str.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    match key {
                        "fromEpoch" => {
                            from_epoch = value.parse().unwrap_or(0);
                        }
                        "toEpoch" => {
                            to_epoch = value.parse().ok();
                        }
                        _ => {}
                    }
                }
            }

            let v1_commit_params = GetCommitsParams {
                convo_id,
                from_epoch,
                to_epoch,
            };

            let commits_result =
                crate::handlers::get_commits(State(pool), auth_user, Query(v1_commit_params))
                    .await?;

            // Merge: take the messages response and add commits
            let mut response = serde_json::to_value(messages_result.0).unwrap();
            if let Some(obj) = response.as_object_mut() {
                obj.insert(
                    "commits".to_string(),
                    serde_json::to_value(&commits_result.0.commits).unwrap_or_default(),
                );
            }

            Ok(Json(response))
        }

        other => {
            warn!("❌ [v2.getMessages] Unknown type filter: {}", other);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}
