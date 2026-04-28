use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::{error, info, warn};

use crate::{
    actors::{ActorRegistry, ConvoMessage, ResetTrigger, WelcomeEnvelope},
    auth::AuthUser,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.resetGroup";

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetGroupRequest {
    pub convo_id: String,
    pub new_group_id: String,
    pub cipher_suite: String,
    pub group_info: Option<String>,
    pub reason: Option<String>,
    /// When true, clears the circuit breaker and resets the counter to 0,
    /// re-enabling automatic recovery for this conversation.
    #[serde(default)]
    pub clear_circuit_breaker: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetGroupOutput {
    pub success: bool,
    /// Set on the with-material (activation) path; absent on request-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_group_id: Option<String>,
    /// Set on the with-material (activation) path; absent on request-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_generation: Option<i32>,
    /// Set on the with-material (activation) path; absent on request-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_epoch: Option<i64>,
    /// Set on the request-only path. Identifier of the
    /// `crypto_session_reset_requested` audit event, returned to the
    /// admin caller so they can correlate the request with the future
    /// activation that an elected client will perform.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_request_id: Option<String>,
    /// Set on the request-only path. Indicates whether activation has
    /// been deferred to a client via the `crypto_session_reset_requested`
    /// SSE event flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub awaiting_client_activation: Option<bool>,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Reset an MLS group by replacing its group_id and clearing ephemeral state.
///
/// POST /xrpc/blue.catbird.mlsChat.resetGroup
///
/// Phase 2 §2.3: routes through `ConversationActor` two-phase reset rather
/// than writing the conversations row directly. Admin call, so trigger is
/// `ResetTrigger::Admin`.
///
/// Required path: caller MUST supply `groupInfo` inline. The legacy
/// "two-step" flow (call resetGroup with no groupInfo, then call
/// bootstrapResetGroup later) is deprecated as of Phase 2 — that flow
/// pre-rotated `conversations.group_id` outside the chokepoint, which
/// the new architecture forbids. Callers without inline material should
/// instead invoke `bootstrapResetGroup` directly with material in hand
/// (it now serves as the activation entry point).
///
/// Only admins may reset a group. Activation through the chokepoint
/// increments `reset_count` (the new generation), rotates `group_id`,
/// resets `current_epoch` to 0, supersedes the prior `crypto_session`,
/// emits `crypto_session_reset_requested` + `crypto_session_activated`
/// events, and stores any pending welcomes keyed to the new session.
#[tracing::instrument(skip(pool, actor_registry, auth_user, input))]
pub async fn reset_group(
    State(pool): State<DbPool>,
    State(actor_registry): State<Arc<ActorRegistry>>,
    auth_user: AuthUser,
    Json(input): Json<ResetGroupRequest>,
) -> Result<Response, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("[resetGroup] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let caller_did = auth_user.did.clone();
    let convo_id = input.convo_id.clone();
    let new_group_id = input.new_group_id.clone();

    info!(
        convo = %crate::crypto::redact_for_log(&convo_id),
        caller = %crate::crypto::redact_for_log(&caller_did),
        "[resetGroup] start"
    );

    // --- Verify caller is admin ---
    let is_admin: bool = sqlx::query_scalar(
        "SELECT COALESCE(is_admin, false) FROM members WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL LIMIT 1",
    )
    .bind(&convo_id)
    .bind(&caller_did)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("[resetGroup] admin check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .unwrap_or(false);

    if !is_admin {
        warn!("[resetGroup] caller is not admin");
        return Err(StatusCode::FORBIDDEN);
    }

    // --- Decode optional inline group_info ---
    //
    // Two valid shapes per plan §2.3:
    //   - Material present (groupInfo decoded): full chokepoint flow
    //     (Request + Activate back-to-back). Validate newGroupId is not
    //     already in use before claiming it.
    //   - Material absent: request-only flow. Emit
    //     `RequestCryptoSessionReset` and return `request_id` to the
    //     caller; an elected client subsequently activates via
    //     `bootstrapResetGroup`. NewGroupId uniqueness check is skipped
    //     here — the eventual activator will attempt to claim it.
    let group_info_bytes: Option<Vec<u8>> = if let Some(gi_b64) = input.group_info.as_ref() {
        use base64::Engine;
        Some(
            base64::engine::general_purpose::STANDARD
                .decode(gi_b64)
                .map_err(|e| {
                    warn!("[resetGroup] invalid base64 groupInfo: {}", e);
                    StatusCode::BAD_REQUEST
                })?,
        )
    } else {
        None
    };

    if group_info_bytes.is_some() {
        // --- Validate newGroupId not already in use (with-material path) ---
        let conflicting_convo_id: Option<String> =
            sqlx::query_scalar("SELECT id FROM conversations WHERE group_id = $1 LIMIT 1")
                .bind(&new_group_id)
                .fetch_optional(&pool)
                .await
                .map_err(|e| {
                    error!("[resetGroup] group_id uniqueness check failed: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

        if let Some(existing_convo_id) = conflicting_convo_id {
            warn!("[resetGroup] newGroupId already in use");
            return Ok((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "GroupIdAlreadyExists",
                    "message": "The new group ID is already in use by another conversation",
                    "conflictingGroupId": new_group_id,
                    "conflictingConvoId": existing_convo_id
                })),
            )
                .into_response());
        }
    }

    // --- Optional clear-circuit-breaker side-effect ---
    //
    // Pre-Phase 2 the same UPDATE that rotated group_id also flipped
    // auto_reset_disabled_at to NULL when this flag was set. The new
    // chokepoint doesn't know about the breaker (app-layer concern), so
    // we issue a separate UPDATE before invoking the chokepoint. Best-
    // effort: if this fails we still proceed with the reset.
    if input.clear_circuit_breaker {
        if let Err(e) = sqlx::query(
            "UPDATE conversations SET \
                auto_reset_disabled_at = NULL, \
                updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(&convo_id)
        .execute(&pool)
        .await
        {
            warn!(
                error = ?e,
                "[resetGroup] failed to clear circuit breaker (non-fatal)"
            );
        } else {
            info!(
                convo = %crate::crypto::redact_for_log(&convo_id),
                "[resetGroup] circuit breaker cleared"
            );
        }
    }

    // --- Get or spawn the conversation actor ---
    let actor_ref = actor_registry.get_or_spawn(&convo_id).await.map_err(|e| {
        error!("[resetGroup] failed to spawn actor: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // --- Phase 2 §2.2 admin direct flow: Request + Activate back-to-back.
    //     Idempotency keys are namespaced per the contract documented in
    //     ConvoMessage::RequestCryptoSessionReset (req-reset / activate).
    //
    //     bug_015 (ultrareview): the prior code generated a fresh UUID
    //     per HTTP request, so two retries from the same caller (e.g.
    //     because the response was lost in transit) would each get
    //     unique idempotency_keys → each emits its own Request and
    //     Activate → generation explodes (one per retry). The right
    //     idempotency anchor is the (convo_id, new_group_id) tuple,
    //     mirroring the bootstrap_reset_group convention so retries
    //     converge on the same chokepoint events.
    //
    //     Mismatch: pre-Phase 2 reset_group did accept an idempotency_key
    //     in the request payload but the lexicon doesn't currently
    //     surface it (see ResetGroupRequest above). Use the deterministic
    //     (convo, group) key for now; if/when the lexicon adds an
    //     explicit field, prefer that over the derived form.
    let request_id_uuid = format!("{}-{}", convo_id, new_group_id);

    let (req_tx, req_rx) = oneshot::channel();
    actor_ref
        .send_message(ConvoMessage::RequestCryptoSessionReset {
            trigger: ResetTrigger::Admin,
            initiator_did: caller_did.clone(),
            reason: input
                .reason
                .clone()
                .unwrap_or_else(|| "admin_reset".to_string()),
            idempotency_key: format!("req-reset:{}", request_id_uuid),
            // bug_010 (ultrareview): admin reset binds the new_group_id
            // up-front so the activation half (whether back-to-back here
            // for with-material flow, or later via bootstrap for
            // request-only flow) can validate the activator's
            // mls_group_id matches what the admin claimed. Prevents the
            // auth bypass where any active member could race with their
            // own newGroupId.
            expected_new_mls_group_id: Some(new_group_id.clone()),
            reply: req_tx,
        })
        .map_err(|_| {
            error!("[resetGroup] failed to send Request to actor");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let reset_request = req_rx
        .await
        .map_err(|_| {
            error!("[resetGroup] Request channel closed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .map_err(|e| {
            error!("[resetGroup] Request handler failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // --- Activation step is conditional on material presence ---
    if let Some(gi_bytes) = group_info_bytes {
        // With-material flow: send ActivateCryptoSession back-to-back.
        let (act_tx, act_rx) = oneshot::channel();
        actor_ref
            .send_message(ConvoMessage::ActivateCryptoSession {
                reset_request_id: Some(reset_request.request_id.clone()),
                trigger: ResetTrigger::Admin,
                new_mls_group_id: new_group_id.clone(),
                new_group_info: Some(gi_bytes),
                // Admin reset doesn't carry pending welcomes inline — the
                // admin is rotating the group_id, not adding members.
                welcomes: Vec::<WelcomeEnvelope>::new(),
                initiator_did: caller_did.clone(),
                idempotency_key: format!("activate:{}", request_id_uuid),
                reply: act_tx,
            })
            .map_err(|_| {
                error!("[resetGroup] failed to send Activate to actor");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let session = act_rx
            .await
            .map_err(|_| {
                error!("[resetGroup] Activate channel closed");
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .map_err(|e| {
                error!("[resetGroup] Activate handler failed: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        info!(
            convo = %crate::crypto::redact_for_log(&convo_id),
            new_group_id = %crate::crypto::redact_for_log(&new_group_id),
            new_session_id = %session.id,
            reset_generation = session.generation,
            "[resetGroup] complete (with-material flow)"
        );

        Ok(Json(ResetGroupOutput {
            success: true,
            new_group_id: Some(new_group_id),
            reset_generation: Some(session.generation),
            new_epoch: Some(session.last_observed_epoch as i64),
            reset_request_id: None,
            awaiting_client_activation: None,
        })
        .into_response())
    } else {
        // Request-only flow: an elected client will activate later via
        // bootstrapResetGroup. Per plan §2.3 admin-no-material variant.
        info!(
            convo = %crate::crypto::redact_for_log(&convo_id),
            request_id = %reset_request.request_id,
            "[resetGroup] complete (request-only flow; awaiting client activation)"
        );

        Ok(Json(ResetGroupOutput {
            success: true,
            new_group_id: None,
            reset_generation: None,
            new_epoch: None,
            reset_request_id: Some(reset_request.request_id),
            awaiting_client_activation: Some(true),
        })
        .into_response())
    }
}
