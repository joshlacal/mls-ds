use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tracing;

use jacquard_axum::ExtractXrpc;

use crate::{
    actors::ActorRegistry,
    auth::AuthUser,
    federation::SequencerTransfer,
    generated::blue_catbird::mlsChat::leave_convo::{LeaveConvoOutput, LeaveConvoRequest},
    realtime::SseState,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.leaveConvo";

/// Consolidated leave/remove handler
/// POST /xrpc/blue.catbird.mlsChat.leaveConvo
///
/// Consolidates: leaveConvo, removeMember
/// - No targetDid → self-leave
/// - With targetDid → admin removing member (requires admin/creator privileges)
#[tracing::instrument(skip(pool, sse_state, actor_registry, sequencer_transfer, auth_user, input))]
pub async fn leave_convo(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    State(actor_registry): State<Arc<ActorRegistry>>,
    State(sequencer_transfer): State<Arc<SequencerTransfer>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<LeaveConvoRequest>,
) -> Result<Json<LeaveConvoOutput<'static>>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Delegate to existing leave_convo which already handles target_did
    let v1_input = crate::generated_types::LeaveConvoInput {
        convo_id: input.convo_id.to_string(),
        target_did: input.target_did.as_ref().map(|d| d.to_string()),
        commit: input.commit.as_ref().map(|c| c.to_string()),
    };

    match super::super::leave_convo(
        State(pool),
        State(actor_registry),
        State(sse_state),
        State(sequencer_transfer),
        auth_user,
        Json(v1_input),
    )
    .await
    {
        Ok(Json(output)) => Ok(Json(LeaveConvoOutput {
            success: output.success,
            new_epoch: output.new_epoch as i64,
            extra_data: Default::default(),
        })),
        Err(status) => Err(status),
    }
}
