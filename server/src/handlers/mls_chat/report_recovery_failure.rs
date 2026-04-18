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
    actors::{ActorRegistry, ConvoMessage},
    auth::AuthUser,
    device_utils::parse_device_did,
    realtime::SseState,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.reportRecoveryFailure";

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportRecoveryFailureRequest {
    pub convo_id: String,
    pub failure_type: Option<String>,
    /// Hex-encoded RFC 9420 §8.7 `epoch_authenticator` for the reporter's
    /// current epoch. Optional at the schema layer (old clients may omit)
    /// but required for the vote to count toward quorum (see ADR-002 §A7.3).
    pub epoch_authenticator: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportRecoveryFailureOutput {
    pub recorded: bool,
    pub auto_reset_triggered: bool,
    pub failure_count: i64,
    pub member_count: i64,
    /// Discriminator for why the vote was rejected (if any), e.g.
    /// `"stale_authenticator"`, `"missing_authenticator"`, `"rate_limited"`,
    /// `"circuit_breaker"`, `"not_member"`, `"convo_not_found"`.
    /// `None` on a successfully counted vote.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Handler (thin dispatcher per ADR-002 §A7.1 — invariant E6)
// ---------------------------------------------------------------------------

/// Report that recovery has been exhausted for a conversation.
///
/// POST /xrpc/blue.catbird.mlsChat.reportRecoveryFailure
///
/// Every DB write goes through `ActorRegistry::get_or_spawn(convo_id)` and the
/// `ConvoMessage::RecordResetVote` variant. This handler only authenticates,
/// resolves identity, dispatches, and translates the outcome into the wire
/// response shape. No direct PgPool writes (E6).
///
/// Auto-reset policy (ADR-002 §D1-D5):
/// - 67% (ceil of 2/3) of distinct identity DIDs must vote
/// - Each vote must carry a recent valid `epoch_authenticator`
/// - Per-DID 24h rate limit; 30-min cooldown; 3-in-24h circuit breaker
#[tracing::instrument(skip(pool, registry, _sse_state, auth_user, input))]
pub async fn report_recovery_failure(
    State(pool): State<DbPool>,
    State(registry): State<Arc<ActorRegistry>>,
    State(_sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    Json(input): Json<ReportRecoveryFailureRequest>,
) -> Result<Response, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("[reportRecoveryFailure] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let device_did = auth_user.did.clone();
    let convo_id = input.convo_id.clone();
    let failure_type = input
        .failure_type
        .clone()
        .unwrap_or_else(|| "external_commit_exhausted".to_string());

    info!(
        convo = %crate::crypto::redact_for_log(&convo_id),
        caller = %crate::crypto::redact_for_log(&device_did),
        failure_type = %failure_type,
        has_authenticator = input.epoch_authenticator.is_some(),
        "[reportRecoveryFailure] start"
    );

    // --- Resolve device_did → identity_did via the user#device convention.
    // Multi-device DIDs look like `did:plc:user#device-uuid`; we split on '#'
    // and use the user part as the identity DID. For single-device clients
    // (no '#' suffix) parse_device_did returns the full DID as the user part.
    let (identity_did, _device_id) = match parse_device_did(&device_did) {
        Ok(pair) => pair,
        Err(e) => {
            warn!("[reportRecoveryFailure] invalid device DID: {}", e);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // --- Verify caller is a member (handler-side gate; actor double-checks).
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM members \
         WHERE convo_id = $1 AND (user_did = $2 OR member_did = $3) AND left_at IS NULL)",
    )
    .bind(&convo_id)
    .bind(&identity_did)
    .bind(&device_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("[reportRecoveryFailure] membership check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if !is_member {
        warn!("[reportRecoveryFailure] caller is not a member");
        return Err(StatusCode::FORBIDDEN);
    }

    // --- Missing-authenticator short-circuit (ADR §A7.3).
    // A report without an authenticator is accepted with a reason telemetry
    // marker but does NOT count toward quorum and does NOT consume the per-DID
    // 24h rate-limit slot. This lets old clients roll over gracefully.
    let epoch_authenticator = match input.epoch_authenticator.clone() {
        Some(auth) if !auth.is_empty() => auth,
        _ => {
            info!(
                convo = %crate::crypto::redact_for_log(&convo_id),
                "[reportRecoveryFailure] missing_authenticator (old client)"
            );
            let (per_did_count, member_count) = count_votes_and_members(&pool, &convo_id).await;
            return Ok(Json(ReportRecoveryFailureOutput {
                recorded: false,
                auto_reset_triggered: false,
                failure_count: per_did_count,
                member_count,
                reason: Some("missing_authenticator".to_string()),
            })
            .into_response());
        }
    };

    // --- Dispatch to the ConversationActor. All DB writes from here live
    //     inside the actor; invariant E6 satisfied.
    let actor_ref = registry.get_or_spawn(&convo_id).await.map_err(|e| {
        error!("[reportRecoveryFailure] actor spawn failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (reply_tx, reply_rx) = oneshot::channel();
    actor_ref
        .send_message(ConvoMessage::RecordResetVote {
            device_did: device_did.clone(),
            identity_did: identity_did.clone(),
            epoch_authenticator,
            failure_type,
            reply: reply_tx,
        })
        .map_err(|e| {
            error!("[reportRecoveryFailure] actor send failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let outcome = reply_rx
        .await
        .map_err(|e| {
            error!("[reportRecoveryFailure] actor reply dropped: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .map_err(|e| {
            error!("[reportRecoveryFailure] actor handler error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Convo-not-found is a 404 rather than a 200-with-reason — same shape as
    // the old handler so rollout is transparent on the wire.
    if outcome.reason.as_deref() == Some("convo_not_found") {
        return Err(StatusCode::NOT_FOUND);
    }

    info!(
        convo = %crate::crypto::redact_for_log(&convo_id),
        recorded = outcome.recorded,
        auto_reset_triggered = outcome.auto_reset_triggered,
        per_did_vote_count = outcome.per_did_vote_count,
        member_did_count = outcome.member_did_count,
        reason = ?outcome.reason,
        "[reportRecoveryFailure] done"
    );

    Ok(Json(ReportRecoveryFailureOutput {
        recorded: outcome.recorded,
        auto_reset_triggered: outcome.auto_reset_triggered,
        failure_count: outcome.per_did_vote_count,
        member_count: outcome.member_did_count,
        reason: outcome.reason,
    })
    .into_response())
}

/// Read-only helper for the missing_authenticator short-circuit. Matches the
/// actor's counting logic but without writes. Best-effort — if either query
/// fails we return zeros and let the response still be informative about the
/// `missing_authenticator` status.
async fn count_votes_and_members(pool: &DbPool, convo_id: &str) -> (i64, i64) {
    let member_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT COALESCE(user_did, member_did)) \
         FROM members WHERE convo_id = $1 AND left_at IS NULL",
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let per_did_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ( \
            SELECT COALESCE(m.user_did, m.member_did) AS ident \
            FROM members m \
            WHERE m.convo_id = $1 AND m.left_at IS NULL \
            GROUP BY COALESCE(m.user_did, m.member_did) \
            HAVING COUNT(*) = COUNT(CASE WHEN EXISTS ( \
                SELECT 1 FROM reset_votes rv \
                WHERE rv.convo_id = m.convo_id \
                AND rv.device_did = m.member_did \
                AND rv.expires_at > NOW() \
                AND rv.voted_at > NOW() - INTERVAL '1 hour' \
            ) THEN 1 END) \
         ) t",
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    (per_did_count, member_count)
}
