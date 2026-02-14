use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use jacquard_axum::ExtractXrpc;
use std::sync::Arc;
use tracing::{error, warn};

use crate::{
    auth::AuthUser, block_sync::BlockSyncService,
    generated::blue_catbird::mlsChat::create_convo::CreateConvoRequest,
    handlers::create_invite::RevokeInviteInput, storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.createConvo";

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Consolidated conversation creation and invite management endpoint.
///
/// POST /xrpc/blue.catbird.mlsChat.createConvo
///
/// The generated CreateConvo type is used for direct creation. Invite management
/// actions are dispatched via the optional `invite.action` field.
#[tracing::instrument(skip(pool, block_sync, auth_user, input))]
pub async fn create_convo(
    State(pool): State<DbPool>,
    State(block_sync): State<Arc<BlockSyncService>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<CreateConvoRequest>,
) -> Response {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("Unauthorized");
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // Check if this is an invite management action
    if let Some(ref invite) = input.invite {
        match invite.action.as_ref() {
            "revoke" => {
                let code = invite.code.as_deref().unwrap_or_default().to_string();
                let revoke_input = RevokeInviteInput { invite_id: code };
                let result = crate::handlers::revoke_invite(
                    State(pool.clone()),
                    auth_user,
                    Json(revoke_input),
                )
                .await;

                return match result {
                    Ok(json) => json.into_response(),
                    Err((status, msg)) => (status, msg).into_response(),
                };
            }
            _ => {
                // "create" invite or unknown - fall through to create convo flow
            }
        }
    }

    // Standard conversation creation - delegate to v1 handler
    // Re-serialize the generated type as the v1 handler expects its own generated type
    let v1_body_str = serde_json::to_string(&input).unwrap_or_default();
    let v1_input = {
        use jacquard_common::IntoStatic;
        let parsed: crate::generated::blue_catbird::mls::create_convo::CreateConvo =
            match serde_json::from_str(&v1_body_str) {
                Ok(input) => input,
                Err(e) => {
                    warn!("[v2.createConvo] Invalid create body: {}", e);
                    return StatusCode::BAD_REQUEST.into_response();
                }
            };
        parsed.into_static()
    };

    let result = crate::handlers::create_convo(
        State(pool),
        State(block_sync),
        auth_user,
        serde_json::to_string(&v1_input).unwrap(),
    )
    .await;

    match result {
        Ok(json) => json.into_response(),
        Err(e) => e.into_response(),
    }
}
