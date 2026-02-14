use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use jacquard_axum::ExtractXrpc;
use tracing::warn;

use crate::{
    auth::AuthUser, generated::blue_catbird::mlsChat::get_convo_settings::GetConvoSettingsRequest,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getConvoSettings";

/// Get conversation settings/policy.
/// GET /xrpc/blue.catbird.mlsChat.getConvoSettings
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_convo_settings(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<GetConvoSettingsRequest>,
) -> Response {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let v1_query = crate::handlers::update_policy::GetPolicyInput {
        convo_id: input.convo_id.to_string(),
    };
    match crate::handlers::get_policy(State(pool), auth_user, Query(v1_query)).await {
        Ok(json_output) => Json(serde_json::json!({
            "convoId": input.convo_id.as_ref(),
            "policy": json_output.0.policy,
        }))
        .into_response(),
        Err((status, msg)) => (status, msg).into_response(),
    }
}
