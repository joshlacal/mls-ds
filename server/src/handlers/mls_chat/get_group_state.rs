use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use jacquard_axum::ExtractXrpc;
use serde::Serialize;
use tracing::{error, info, warn};

use crate::{
    actors::ActorRegistry,
    auth::AuthUser,
    config::InlineTriggerConfig,
    generated::blue_catbird::mlsChat::get_group_state::{
        GetGroupStateError, GetGroupStateOutput, GetGroupStateRequest,
    },
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getGroupState";

/// Body shape coordinated with SERVER A (`commitGroupChange::GroupResetBody`)
/// so CLIENT D's parser handles both call sites with one branch. Kept
/// status=404 for backwards-compat with clients that only inspect the
/// status code; new clients detect the reset via the structured body.
#[derive(Debug, Serialize)]
pub struct GroupResetBody {
    error: &'static str,
    message: String,
    #[serde(rename = "convoId")]
    convo_id: String,
}

#[derive(Debug)]
pub enum GetGroupStateContractError {
    Structured {
        status: StatusCode,
        error: GetGroupStateError<'static>,
    },
    GroupReset {
        status: StatusCode,
        body: GroupResetBody,
    },
    Generic(StatusCode),
}

impl GetGroupStateContractError {
    #[cfg(test)]
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Structured { status, .. } => *status,
            Self::GroupReset { status, .. } => *status,
            Self::Generic(status) => *status,
        }
    }

    fn not_found(message: &'static str) -> Self {
        Self::Structured {
            status: StatusCode::NOT_FOUND,
            error: GetGroupStateError::NotFound(Some(message.into())),
        }
    }

    fn unauthorized(message: &'static str) -> Self {
        Self::Structured {
            status: StatusCode::FORBIDDEN,
            error: GetGroupStateError::Unauthorized(Some(message.into())),
        }
    }

    fn group_info_unavailable(status: StatusCode, message: &'static str) -> Self {
        Self::Structured {
            status,
            error: GetGroupStateError::GroupInfoUnavailable(Some(message.into())),
        }
    }

    /// 404 with structured body. Status stays 404 for backwards-compat with
    /// existing clients that branch on status code only — new clients
    /// inspect the body's `error` field to detect a reset.
    fn group_reset(convo_id: &str, message: impl Into<String>) -> Self {
        Self::GroupReset {
            status: StatusCode::NOT_FOUND,
            body: GroupResetBody {
                error: "GroupReset",
                message: message.into(),
                convo_id: convo_id.to_string(),
            },
        }
    }
}

impl IntoResponse for GetGroupStateContractError {
    fn into_response(self) -> Response {
        match self {
            Self::Structured { status, error } => (status, Json(error)).into_response(),
            Self::GroupReset { status, body } => (status, Json(body)).into_response(),
            Self::Generic(status) => status.into_response(),
        }
    }
}

fn is_row_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<sqlx::Error>()
            .is_some_and(|sqlx_error| matches!(sqlx_error, sqlx::Error::RowNotFound))
    })
}

/// Consolidated group state query
/// GET /xrpc/blue.catbird.mlsChat.getGroupState?convoId=xxx&include=groupInfo,welcome,epoch
///
/// Consolidates: getGroupInfo, getEpoch, getWelcome, invalidateWelcome
#[tracing::instrument(skip(pool, actor_registry, inline_trigger_cfg, auth_user))]
pub async fn get_group_state(
    State(pool): State<DbPool>,
    State(actor_registry): State<Arc<ActorRegistry>>,
    State(inline_trigger_cfg): State<Arc<InlineTriggerConfig>>,
    auth_user: AuthUser,
    ExtractXrpc(params): ExtractXrpc<GetGroupStateRequest>,
) -> Result<Json<GetGroupStateOutput<'static>>, GetGroupStateContractError> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(GetGroupStateContractError::Generic(
            StatusCode::UNAUTHORIZED,
        ));
    }

    let convo_id = params.convo_id.as_ref();
    let include_str = params.include.as_deref().unwrap_or("groupInfo,epoch");
    let includes: Vec<&str> = include_str.split(',').map(|s| s.trim()).collect();

    let convo_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM conversations WHERE id = $1)")
            .bind(convo_id)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!(
                    convo_id = %crate::crypto::redact_for_log(convo_id),
                    error = %e,
                    "Failed to check conversation existence"
                );
                GetGroupStateContractError::Generic(StatusCode::INTERNAL_SERVER_ERROR)
            })?;
    if !convo_exists {
        return Err(GetGroupStateContractError::not_found(
            "Conversation not found",
        ));
    }

    let is_current_or_past_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1
            FROM members
            WHERE convo_id = $1 AND (member_did = $2 OR user_did = $2)
        )",
    )
    .bind(convo_id)
    .bind(&auth_user.did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(
            convo_id = %crate::crypto::redact_for_log(convo_id),
            did = %crate::crypto::redact_for_log(&auth_user.did),
            error = %e,
            "Failed to check conversation membership"
        );
        GetGroupStateContractError::Generic(StatusCode::INTERNAL_SERVER_ERROR)
    })?;
    if !is_current_or_past_member {
        return Err(GetGroupStateContractError::unauthorized(
            "Not a current or past member",
        ));
    }

    let mut epoch: Option<i64> = None;
    // group_info / welcome store RAW MLS bytes. The Jacquard
    // `serde_bytes_helper` serializer converts `bytes::Bytes` to
    // `{"$bytes": "base64..."}` on the JSON wire. A previous version of this
    // handler manually base64-encoded the bytes into a String here and then
    // converted to `bytes::Bytes` — which caused Jacquard to base64-encode
    // the UTF-8 of that string AGAIN, yielding a double-encoded payload that
    // clients would unwrap once and then feed (as ASCII of base64) to MLS
    // parsers, which rejected it with "appears to be base64-encoded text".
    let mut group_info: Option<bytes::Bytes> = None;
    let mut welcome: Option<bytes::Bytes> = None;
    let mut expires_at = None;

    // Fetch epoch (lightweight, always useful)
    if includes.contains(&"epoch") {
        match crate::storage::get_current_epoch(&pool, convo_id).await {
            Ok(e) => {
                epoch = Some(e as i64);
            }
            Err(e) => {
                error!(
                    convo_id = %crate::crypto::redact_for_log(convo_id),
                    error = %e,
                    "Failed to get epoch"
                );
                if is_row_not_found(&e) {
                    return Err(GetGroupStateContractError::not_found(
                        "Conversation not found",
                    ));
                }
                return Err(GetGroupStateContractError::Generic(
                    StatusCode::INTERNAL_SERVER_ERROR,
                ));
            }
        }
    }

    // Fetch group info
    if includes.contains(&"groupInfo") {
        match crate::group_info::get_group_info(&pool, convo_id).await {
            Ok(Some((group_info_bytes, gi_epoch, _updated_at))) => {
                info!(
                    convo_id = %crate::crypto::redact_for_log(convo_id),
                    raw_bytes = group_info_bytes.len(),
                    epoch = gi_epoch,
                    "GroupInfo loaded for response"
                );
                group_info = Some(bytes::Bytes::from(group_info_bytes));
                // Set epoch from group info if not already fetched
                if epoch.is_none() {
                    epoch = Some(gi_epoch as i64);
                }
                // Set expiry to 5 minutes from now
                expires_at = Some(chrono_to_datetime(
                    chrono::Utc::now() + chrono::Duration::minutes(5),
                ));
            }
            Ok(None) => {
                // Phase 2 B10: bump the GroupInfo-404 counter and let the
                // inline-trigger evaluator decide whether to fast-path a
                // TriggerSystemReset. Failures are non-fatal — the 404
                // response to the client is the contract; instrumentation
                // must NEVER mask it. The periodic sweep
                // (`sweep_groupinfo_404_once`) remains as a safety net.
                if let Err(e) = crate::jobs::auto_detect_failed_groups::record_groupinfo_404_with_inline_trigger(
                    &pool,
                    &actor_registry,
                    convo_id,
                    &inline_trigger_cfg,
                )
                .await
                {
                    warn!(
                        convo_id = %crate::crypto::redact_for_log(convo_id),
                        error = %e,
                        "Failed to record GroupInfo 404 (non-fatal — 404 response still returned)"
                    );
                }

                // Differentiate genuine "no GroupInfo yet" from "session was
                // reset and GroupInfo cleared" so clients can route to
                // bootstrap-recovery instead of retrying. The conversation
                // row already exists (we checked above) — the question is
                // whether the active crypto session is mid-reset or has had
                // its GroupInfo cleared post-reset.
                let session_state: Option<(
                    String,
                    Option<i32>,
                    chrono::DateTime<chrono::Utc>,
                )> = sqlx::query_as(
                    "SELECT state, group_info_epoch, created_at \
                     FROM crypto_sessions \
                     WHERE conversation_id = $1 \
                     ORDER BY \
                       CASE state \
                         WHEN 'active' THEN 0 \
                         WHEN 'reset_requested' THEN 1 \
                         WHEN 'superseding' THEN 2 \
                         ELSE 3 \
                       END, \
                       created_at DESC \
                     LIMIT 1",
                )
                .bind(convo_id)
                .fetch_optional(&pool)
                .await
                .ok()
                .flatten();

                if let Some((state, group_info_epoch, created_at)) = session_state {
                    let is_reset_state = state == "reset_requested" || state == "superseding";
                    let was_set = group_info_epoch.is_some();
                    let is_recent = (chrono::Utc::now() - created_at).num_seconds() < 30;
                    let cleared_active = state == "active" && (was_set || is_recent);

                    if is_reset_state || cleared_active {
                        tracing::warn!(
                            target: "getgroupstate_reset",
                            convo_id = %crate::crypto::redact_for_log(convo_id),
                            session_state = %state,
                            had_group_info_epoch = was_set,
                            session_age_secs = (chrono::Utc::now() - created_at).num_seconds(),
                            outcome = "reset",
                            "GroupInfo unavailable due to reset — returning typed groupReset"
                        );
                        return Err(GetGroupStateContractError::group_reset(
                            convo_id,
                            "Conversation was reset; client must bootstrap-recover",
                        ));
                    }
                }

                return Err(GetGroupStateContractError::group_info_unavailable(
                    StatusCode::NOT_FOUND,
                    "GroupInfo not yet generated for this conversation",
                ));
            }
            Err(e) => {
                error!(
                    convo_id = %crate::crypto::redact_for_log(convo_id),
                    error = %e,
                    "Failed to get group info"
                );
                return Err(GetGroupStateContractError::group_info_unavailable(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "GroupInfo temporarily unavailable; retry shortly",
                ));
            }
        }
    }

    // Fetch welcome message
    if includes.contains(&"welcome") {
        let welcome_row: Option<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT id, welcome_data FROM welcome_messages \
             WHERE convo_id = $1 AND recipient_did = $2 AND consumed = false \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(convo_id)
        .bind(&auth_user.did)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch welcome: {}", e);
            GetGroupStateContractError::Generic(StatusCode::INTERNAL_SERVER_ERROR)
        })?;

        if let Some((_welcome_id, data)) = welcome_row {
            welcome = Some(bytes::Bytes::from(data));
        }
    }

    info!(
        "Fetched group state for convo {} (includes: {})",
        crate::crypto::redact_for_log(convo_id),
        include_str
    );

    Ok(Json(GetGroupStateOutput {
        epoch,
        group_info,
        welcome,
        expires_at,
        extra_data: Default::default(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[test]
    fn contract_error_maps_to_expected_status_codes() {
        assert_eq!(
            GetGroupStateContractError::not_found("missing").status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            GetGroupStateContractError::unauthorized("unauthorized").status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            GetGroupStateContractError::group_info_unavailable(
                StatusCode::SERVICE_UNAVAILABLE,
                "transient",
            )
            .status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn row_not_found_detection_handles_anyhow_context() {
        let base = anyhow::Error::new(sqlx::Error::RowNotFound);
        assert!(is_row_not_found(&base));

        let contextual = anyhow::Error::new(sqlx::Error::RowNotFound).context("query failed");
        assert!(is_row_not_found(&contextual));
    }

    #[test]
    fn contract_error_preserves_explicit_structured_variants() {
        match GetGroupStateContractError::not_found("Conversation not found") {
            GetGroupStateContractError::Structured { status, error } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert!(matches!(error, GetGroupStateError::NotFound(_)));
            }
            _ => panic!("expected structured not-found error"),
        }

        match GetGroupStateContractError::group_info_unavailable(
            StatusCode::SERVICE_UNAVAILABLE,
            "GroupInfo temporarily unavailable; retry shortly",
        ) {
            GetGroupStateContractError::Structured { status, error } => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert!(matches!(error, GetGroupStateError::GroupInfoUnavailable(_)));
            }
            _ => panic!("expected structured GroupInfoUnavailable error"),
        }
    }

    #[tokio::test]
    async fn structured_error_into_response_keeps_status_and_error_payload() {
        let response = GetGroupStateContractError::group_info_unavailable(
            StatusCode::NOT_FOUND,
            "GroupInfo not yet generated for this conversation",
        )
        .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body_bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        let body_json: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("valid JSON body");
        let error_name = body_json.get("error").and_then(|v| v.as_str());
        assert_eq!(error_name, Some("GroupInfoUnavailable"));
    }
}
