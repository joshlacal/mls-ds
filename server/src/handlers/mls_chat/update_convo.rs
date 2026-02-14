use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use jacquard_axum::ExtractXrpc;
use std::sync::Arc;
use tracing::{info, warn};

use crate::{
    auth::AuthUser, generated::blue_catbird::mlsChat::update_convo::UpdateConvoRequest,
    realtime::SseState, storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.updateConvo";

/// Consolidated conversation update handler (POST)
/// POST /xrpc/blue.catbird.mlsChat.updateConvo
///
/// Consolidates: updatePolicy, promoteAdmin, demoteAdmin, promoteModerator,
/// demoteModerator, updateGroupInfo, groupInfoRefresh
#[tracing::instrument(skip(pool, sse_state, auth_user, input))]
pub async fn update_convo(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<UpdateConvoRequest>,
) -> Response {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let convo_id = input.convo_id.to_string();

    match input.action.as_ref() {
        "promoteAdmin" => {
            let target_did = match input.target_did {
                Some(did) => did.to_string(),
                None => {
                    warn!("v2.updateConvo: missing targetDid for promoteAdmin");
                    return StatusCode::BAD_REQUEST.into_response();
                }
            };
            info!(
                "v2.updateConvo: promoteAdmin {} in {}",
                crate::crypto::redact_for_log(&target_did),
                crate::crypto::redact_for_log(&convo_id)
            );
            let parsed_did = match target_did.parse() {
                Ok(did) => did,
                Err(_) => {
                    warn!("v2.updateConvo: invalid DID format for promoteAdmin");
                    return StatusCode::BAD_REQUEST.into_response();
                }
            };
            let v1_input = crate::generated::blue_catbird::mls::promote_admin::PromoteAdmin {
                convo_id: convo_id.into(),
                target_did: parsed_did,
                extra_data: Default::default(),
            };
            match super::super::promote_admin(
                State(pool),
                auth_user,
                serde_json::to_string(&v1_input).unwrap(),
            )
            .await
            {
                Ok(json_output) => Json(serde_json::json!({
                    "action": "promoteAdmin",
                    "ok": json_output.0.ok,
                    "promotedAt": json_output.0.promoted_at.as_ref(),
                }))
                .into_response(),
                Err(status) => status.into_response(),
            }
        }
        "demoteAdmin" => {
            let target_did = match input.target_did {
                Some(did) => did.to_string(),
                None => {
                    warn!("v2.updateConvo: missing targetDid for demoteAdmin");
                    return StatusCode::BAD_REQUEST.into_response();
                }
            };
            info!(
                "v2.updateConvo: demoteAdmin {} in {}",
                crate::crypto::redact_for_log(&target_did),
                crate::crypto::redact_for_log(&convo_id)
            );
            let parsed_did = match target_did.parse() {
                Ok(did) => did,
                Err(_) => {
                    warn!("v2.updateConvo: invalid DID format for demoteAdmin");
                    return StatusCode::BAD_REQUEST.into_response();
                }
            };
            let v1_input = crate::generated::blue_catbird::mls::demote_admin::DemoteAdmin {
                convo_id: convo_id.into(),
                target_did: parsed_did,
                extra_data: Default::default(),
            };
            match super::super::demote_admin(
                State(pool),
                auth_user,
                serde_json::to_string(&v1_input).unwrap(),
            )
            .await
            {
                Ok(json_output) => Json(serde_json::json!({
                    "action": "demoteAdmin",
                    "ok": json_output.0.ok,
                }))
                .into_response(),
                Err(status) => status.into_response(),
            }
        }
        "promoteModerator" => {
            let target_did = match input.target_did {
                Some(did) => did.to_string(),
                None => {
                    warn!("v2.updateConvo: missing targetDid for promoteModerator");
                    return StatusCode::BAD_REQUEST.into_response();
                }
            };
            info!(
                "v2.updateConvo: promoteModerator {} in {}",
                crate::crypto::redact_for_log(&target_did),
                crate::crypto::redact_for_log(&convo_id)
            );
            let v1_input = crate::handlers::promote_moderator::Input {
                data: crate::handlers::promote_moderator::InputData {
                    convo_id,
                    target_did,
                },
            };
            match super::super::promote_moderator(State(pool), auth_user, Json(v1_input)).await {
                Ok(json_output) => Json(serde_json::json!({
                    "action": "promoteModerator",
                    "ok": json_output.0.data.ok,
                    "promotedAt": json_output.0.data.promoted_at,
                }))
                .into_response(),
                Err(status) => status.into_response(),
            }
        }
        "demoteModerator" => {
            let target_did = match input.target_did {
                Some(did) => did.to_string(),
                None => {
                    warn!("v2.updateConvo: missing targetDid for demoteModerator");
                    return StatusCode::BAD_REQUEST.into_response();
                }
            };
            info!(
                "v2.updateConvo: demoteModerator {} in {}",
                crate::crypto::redact_for_log(&target_did),
                crate::crypto::redact_for_log(&convo_id)
            );
            let v1_input = crate::handlers::demote_moderator::Input {
                data: crate::handlers::demote_moderator::InputData {
                    convo_id,
                    target_did,
                },
            };
            match super::super::demote_moderator(State(pool), auth_user, Json(v1_input)).await {
                Ok(json_output) => Json(serde_json::json!({
                    "action": "demoteModerator",
                    "ok": json_output.0.data.ok,
                }))
                .into_response(),
                Err(status) => status.into_response(),
            }
        }
        "updatePolicy" => {
            info!(
                "v2.updateConvo: updatePolicy for {}",
                crate::crypto::redact_for_log(&convo_id)
            );
            // Serialize PolicyInput to JSON Value for v1 field extraction
            let policy_json = input
                .policy
                .as_ref()
                .map(|p| serde_json::to_value(p).unwrap_or_default())
                .unwrap_or_default();
            let v1_input = crate::handlers::update_policy::UpdatePolicyInput {
                convo_id,
                allow_external_commits: policy_json
                    .get("allowExternalCommits")
                    .and_then(|v| v.as_bool()),
                require_invite_for_join: policy_json
                    .get("requireInviteForJoin")
                    .and_then(|v| v.as_bool()),
                allow_rejoin: policy_json.get("allowRejoin").and_then(|v| v.as_bool()),
                rejoin_window_days: policy_json
                    .get("rejoinWindowDays")
                    .and_then(|v| v.as_i64())
                    .map(|v| v as i32),
                prevent_removing_last_admin: policy_json
                    .get("preventRemovingLastAdmin")
                    .and_then(|v| v.as_bool()),
                max_members: policy_json
                    .get("maxMembers")
                    .and_then(|v| v.as_i64())
                    .map(|v| v as i32),
            };
            match super::super::update_policy(State(pool), auth_user, Json(v1_input)).await {
                Ok(json_output) => Json(serde_json::json!({
                    "action": "updatePolicy",
                    "success": json_output.0.success,
                    "policy": json_output.0.policy,
                }))
                .into_response(),
                Err((status, msg)) => (status, msg).into_response(),
            }
        }
        "updateGroupInfo" => {
            info!(
                "v2.updateConvo: updateGroupInfo for {}",
                crate::crypto::redact_for_log(&convo_id)
            );
            let group_info = match input.group_info {
                Some(gi) => gi.to_string(),
                None => {
                    warn!("v2.updateConvo: missing groupInfo for updateGroupInfo");
                    return StatusCode::BAD_REQUEST.into_response();
                }
            };
            let epoch = match input.epoch {
                Some(e) => e,
                None => {
                    warn!("v2.updateConvo: missing epoch for updateGroupInfo");
                    return StatusCode::BAD_REQUEST.into_response();
                }
            };
            let v1_input =
                crate::generated::blue_catbird::mls::update_group_info::UpdateGroupInfo {
                    convo_id: convo_id.into(),
                    group_info: group_info.into(),
                    epoch,
                    extra_data: Default::default(),
                };
            match crate::handlers::update_group_info(
                State(pool),
                auth_user,
                serde_json::to_string(&v1_input).unwrap(),
            )
            .await
            {
                Ok(json_output) => Json(serde_json::json!({
                    "action": "updateGroupInfo",
                    "updated": json_output.0.updated,
                }))
                .into_response(),
                Err(err) => err.into_response(),
            }
        }
        "refreshGroupInfo" => {
            info!(
                "v2.updateConvo: refreshGroupInfo for {}",
                crate::crypto::redact_for_log(&convo_id)
            );
            let v1_input =
                crate::generated::blue_catbird::mls::group_info_refresh::GroupInfoRefresh {
                    convo_id: convo_id.into(),
                    extra_data: Default::default(),
                };
            match super::super::group_info_refresh(
                State(pool),
                State(sse_state),
                auth_user,
                serde_json::to_string(&v1_input).unwrap(),
            )
            .await
            {
                Ok(json_output) => Json(serde_json::json!({
                    "action": "refreshGroupInfo",
                    "requested": json_output.0.requested,
                    "activeMembers": json_output.0.active_members,
                }))
                .into_response(),
                Err(status) => status.into_response(),
            }
        }
        other => {
            warn!("v2.updateConvo: unknown action '{}'", other);
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}
