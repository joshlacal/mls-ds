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
/// — locked contract with CLIENT D. Wire shape:
///
///   {"error":"groupReset","message":"<text>","convoId":"<convo>","newCryptoSessionId":<id-or-null>}
///
/// HTTP status: **410 Gone**. `newCryptoSessionId` carries the id of the
/// currently-active `crypto_sessions` row so clients can bootstrap into
/// the right successor; null when the conversation is mid-reset and no
/// active row exists yet.
#[derive(Debug, Serialize)]
pub struct GroupResetBody {
    error: &'static str,
    message: String,
    #[serde(rename = "convoId")]
    convo_id: String,
    #[serde(rename = "newCryptoSessionId")]
    new_crypto_session_id: Option<String>,
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

    /// 410 Gone with structured `groupReset` body — locked contract with
    /// CLIENT D. The "infinite-retry on 404" was the bug being fixed, so
    /// there's no backwards-compat to preserve here; clients that don't
    /// understand 410 will surface it as an error and stop hammering the
    /// server, which is also acceptable.
    fn group_reset(
        convo_id: &str,
        message: impl Into<String>,
        new_crypto_session_id: Option<String>,
    ) -> Self {
        Self::GroupReset {
            status: StatusCode::GONE,
            body: GroupResetBody {
                error: "groupReset",
                message: message.into(),
                convo_id: convo_id.to_string(),
                new_crypto_session_id,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestedWelcomeHashes {
    was_provided: bool,
    hashes: Vec<Vec<u8>>,
}

fn parse_requested_welcome_hashes(
    hashes: Option<&Vec<jacquard_common::CowStr<'_>>>,
) -> RequestedWelcomeHashes {
    let Some(hashes) = hashes else {
        return RequestedWelcomeHashes {
            was_provided: false,
            hashes: Vec::new(),
        };
    };

    let hashes = hashes
        .iter()
        .filter_map(|hash| hex::decode(hash.as_ref()).ok())
        .collect();

    RequestedWelcomeHashes {
        was_provided: true,
        hashes,
    }
}

async fn resolve_welcome_device_candidates(
    pool: &DbPool,
    user_did: &str,
    raw_device_hint: Option<&str>,
) -> Result<Vec<String>, GetGroupStateContractError> {
    let Some(raw_device_hint) = raw_device_hint
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(Vec::new());
    };

    let credential_did = format!("{}#{}", user_did, raw_device_hint);
    let canonical: Option<String> = sqlx::query_scalar(
        "SELECT device_id FROM devices \
         WHERE user_did = $1 \
           AND (device_id = $2 OR device_uuid = $2 OR credential_did = $3) \
         ORDER BY registered_at DESC \
         LIMIT 1",
    )
    .bind(user_did)
    .bind(raw_device_hint)
    .bind(&credential_did)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!(
            did = %crate::crypto::redact_for_log(user_did),
            error = %e,
            "Failed to resolve getGroupState device hint"
        );
        GetGroupStateContractError::Generic(StatusCode::INTERNAL_SERVER_ERROR)
    })?;

    let legacy_bucket = crate::device_utils::bucket_device_id(user_did, raw_device_hint);
    let mut candidates = Vec::new();
    if let Some(canonical) = canonical {
        candidates.push(canonical);
    }
    candidates.push(raw_device_hint.to_string());
    if !legacy_bucket.is_empty() {
        candidates.push(legacy_bucket);
    }
    candidates.sort();
    candidates.dedup();
    Ok(candidates)
}

pub async fn fetch_welcome_row_for_recipient(
    pool: &DbPool,
    convo_id: &str,
    did_str: &str,
    user_form_did: &str,
    requested_hashes: Option<&[Vec<u8>]>,
    device_candidates: &[String],
) -> Result<Option<(String, Vec<u8>)>, GetGroupStateContractError> {
    if let Some(hashes) = requested_hashes {
        if hashes.is_empty() {
            return Ok(None);
        }

        if !device_candidates.is_empty() {
            let device_filtered: Option<(String, Vec<u8>)> = sqlx::query_as(
                "SELECT id, welcome_data FROM welcome_messages \
                 WHERE convo_id = $1 \
                   AND (recipient_did = $2 OR recipient_did = $3) \
                   AND consumed = false \
                   AND key_package_hash = ANY($4::bytea[]) \
                   AND (recipient_device_id IS NULL OR recipient_device_id = ANY($5::text[])) \
                 ORDER BY created_at DESC, id DESC LIMIT 1",
            )
            .bind(convo_id)
            .bind(did_str)
            .bind(user_form_did)
            .bind(hashes)
            .bind(device_candidates)
            .fetch_optional(pool)
            .await
            .map_err(|e| {
                error!(
                    "Failed to fetch device-filtered hash-matched welcome: {}",
                    e
                );
                GetGroupStateContractError::Generic(StatusCode::INTERNAL_SERVER_ERROR)
            })?;

            if device_filtered.is_some() {
                return Ok(device_filtered);
            }

            let hash_matched: Option<(String, Vec<u8>)> = sqlx::query_as(
                "SELECT id, welcome_data FROM welcome_messages \
                 WHERE convo_id = $1 \
                   AND (recipient_did = $2 OR recipient_did = $3) \
                   AND consumed = false \
                   AND key_package_hash = ANY($4::bytea[]) \
                 ORDER BY created_at DESC, id DESC LIMIT 1",
            )
            .bind(convo_id)
            .bind(did_str)
            .bind(user_form_did)
            .bind(hashes)
            .fetch_optional(pool)
            .await
            .map_err(|e| {
                error!(
                    "Failed to fetch hash-matched welcome after device miss: {}",
                    e
                );
                GetGroupStateContractError::Generic(StatusCode::INTERNAL_SERVER_ERROR)
            })?;

            if hash_matched.is_some() {
                warn!(
                    convo_id = %crate::crypto::redact_for_log(convo_id),
                    did = %crate::crypto::redact_for_log(user_form_did),
                    "getGroupState: hash-matched welcome lookup bypassed stale device hint"
                );
            }

            return Ok(hash_matched);
        }

        return sqlx::query_as(
            "SELECT id, welcome_data FROM welcome_messages \
             WHERE convo_id = $1 \
               AND (recipient_did = $2 OR recipient_did = $3) \
               AND consumed = false \
               AND key_package_hash = ANY($4::bytea[]) \
             ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .bind(convo_id)
        .bind(did_str)
        .bind(user_form_did)
        .bind(hashes)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch hash-matched welcome: {}", e);
            GetGroupStateContractError::Generic(StatusCode::INTERNAL_SERVER_ERROR)
        });
    }

    if !device_candidates.is_empty() {
        let directly_device_matched: Option<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT id, welcome_data FROM welcome_messages \
             WHERE convo_id = $1 \
               AND (recipient_did = $2 OR recipient_did = $3) \
               AND consumed = false \
               AND recipient_device_id = ANY($4::text[]) \
             ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .bind(convo_id)
        .bind(did_str)
        .bind(user_form_did)
        .bind(device_candidates)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch device-bound welcome: {}", e);
            GetGroupStateContractError::Generic(StatusCode::INTERNAL_SERVER_ERROR)
        })?;

        if directly_device_matched.is_some() {
            return Ok(directly_device_matched);
        }

        let device_matched: Option<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT id, welcome_data FROM welcome_messages wm \
             WHERE wm.convo_id = $1 \
               AND (wm.recipient_did = $2 OR wm.recipient_did = $3) \
               AND wm.consumed = false \
               AND wm.recipient_device_id IS NULL \
               AND (wm.key_package_hash IS NULL OR EXISTS ( \
                    SELECT 1 FROM key_packages kp \
                    WHERE kp.owner_did = $3 \
                      AND kp.key_package_hash = encode(wm.key_package_hash, 'hex') \
                      AND kp.device_id = ANY($4::text[]) \
               )) \
             ORDER BY wm.created_at DESC, wm.id DESC LIMIT 1",
        )
        .bind(convo_id)
        .bind(did_str)
        .bind(user_form_did)
        .bind(device_candidates)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch device-matched welcome: {}", e);
            GetGroupStateContractError::Generic(StatusCode::INTERNAL_SERVER_ERROR)
        })?;

        if device_matched.is_some() {
            return Ok(device_matched);
        }

        let fallback_rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT id, welcome_data FROM welcome_messages \
             WHERE convo_id = $1 \
               AND (recipient_did = $2 OR recipient_did = $3) \
               AND consumed = false \
               AND recipient_device_id IS NULL \
             ORDER BY created_at DESC, id DESC LIMIT 2",
        )
        .bind(convo_id)
        .bind(did_str)
        .bind(user_form_did)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch fallback welcome: {}", e);
            GetGroupStateContractError::Generic(StatusCode::INTERNAL_SERVER_ERROR)
        })?;

        if fallback_rows.len() == 1 {
            warn!(
                convo_id = %crate::crypto::redact_for_log(convo_id),
                did = %crate::crypto::redact_for_log(user_form_did),
                "getGroupState: device-hinted welcome lookup missed; returning sole user-scoped welcome"
            );
            return Ok(fallback_rows.into_iter().next());
        }

        return Ok(None);
    }

    sqlx::query_as(
        "SELECT id, welcome_data FROM welcome_messages \
         WHERE convo_id = $1 \
           AND (recipient_did = $2 OR recipient_did = $3) \
           AND consumed = false \
         ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(convo_id)
    .bind(did_str)
    .bind(user_form_did)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!("Failed to fetch welcome: {}", e);
        GetGroupStateContractError::Generic(StatusCode::INTERNAL_SERVER_ERROR)
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
                // bootstrap-recovery instead of retrying. Per the locked
                // contract with CLIENT D and the 4b2cdbaa diagnostic
                // (gen 24 sat at active+NULL for 50+ minutes): any active
                // session with NULL group_info is a reset signal regardless
                // of age. A `reset_requested`/`superseding` row without an
                // active sibling is also reset.
                //
                // newCryptoSessionId carries the active session's id so
                // clients can bootstrap into the right successor; null
                // when no active row exists during mid-reset.
                let active_session: Option<(String, Option<Vec<u8>>)> = sqlx::query_as(
                    "SELECT id, group_info \
                     FROM crypto_sessions \
                     WHERE conversation_id = $1 AND state = 'active'",
                )
                .bind(convo_id)
                .fetch_optional(&pool)
                .await
                .ok()
                .flatten();

                let mid_reset: Option<(String,)> = if active_session.is_none() {
                    sqlx::query_as(
                        "SELECT state FROM crypto_sessions \
                         WHERE conversation_id = $1 \
                           AND state IN ('reset_requested', 'superseding') \
                         ORDER BY created_at DESC LIMIT 1",
                    )
                    .bind(convo_id)
                    .fetch_optional(&pool)
                    .await
                    .ok()
                    .flatten()
                } else {
                    None
                };

                match (active_session.as_ref(), mid_reset.as_ref()) {
                    // Active + NULL group_info → reset; emit successor id.
                    (Some((active_id, None)), _) => {
                        tracing::warn!(
                            target: "getgroupstate_reset",
                            convo_id = %crate::crypto::redact_for_log(convo_id),
                            session_state = "active",
                            new_crypto_session_id = %active_id,
                            outcome = "reset_active_null_group_info",
                            "active session has NULL group_info — returning groupReset"
                        );
                        return Err(GetGroupStateContractError::group_reset(
                            convo_id,
                            "GroupInfo unavailable for active session; client must bootstrap-recover",
                            Some(active_id.clone()),
                        ));
                    }
                    // Mid-reset with no active row → emit null successor.
                    (None, Some((reset_state,))) => {
                        tracing::warn!(
                            target: "getgroupstate_reset",
                            convo_id = %crate::crypto::redact_for_log(convo_id),
                            session_state = %reset_state,
                            outcome = "reset_in_flight",
                            "no active session — reset in flight; returning groupReset"
                        );
                        return Err(GetGroupStateContractError::group_reset(
                            convo_id,
                            "Conversation is being reset; client must bootstrap-recover",
                            None,
                        ));
                    }
                    // Active + group_info present, OR no crypto_sessions row
                    // at all (legacy convo): fall through to legacy
                    // GroupInfoUnavailable. The Some-with-group_info case
                    // shouldn't reach here (get_group_info would have
                    // returned Some), but it's harmless if it does.
                    _ => {}
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
        // Defensive against device-form vs user-form ambiguity in
        // `auth_user.did`. Phase B (per-device welcome storage) writes
        // `recipient_did` in user-form (e.g. "did:plc:alice") because
        // jacquard's `Did<'a>` regex rejects '#'. New rows prefer the
        // persisted `recipient_device_id`; legacy rows can still fall back
        // through `key_package_hash`. Task 1's verification of
        // `auth_user.did` for getGroupState callers came back INDIRECT —
        // server-side construction is strong evidence for user-form, but
        // the iOS issuance path was not directly traced. If a device-form
        // string ("did:plc:alice#deviceA") arrives here, a raw bind would
        // miss the user-form-stored welcomes.
        //
        // Mitigation: derive the user-form half by splitting at '#' and
        // bind BOTH forms. `split_once('#')` returns `None` for user-form
        // input, so both binds collapse to the same string and the OR
        // clause is a no-op for user-form callers. For device-form
        // callers, the OR rescues the lookup.
        let did_str = &auth_user.did;
        let user_form_did: String = match did_str.split_once('#') {
            Some((user, _device)) => user.to_string(),
            None => did_str.clone(),
        };

        let requested_hashes = parse_requested_welcome_hashes(params.key_package_hashes.as_ref());
        let device_hint = params
            .device_id
            .as_deref()
            .or_else(|| did_str.split_once('#').map(|(_, device)| device));
        let device_candidates =
            resolve_welcome_device_candidates(&pool, &user_form_did, device_hint).await?;
        let requested_hashes = if requested_hashes.was_provided {
            Some(requested_hashes.hashes.as_slice())
        } else {
            None
        };

        let welcome_row = fetch_welcome_row_for_recipient(
            &pool,
            convo_id,
            did_str,
            &user_form_did,
            requested_hashes,
            &device_candidates,
        )
        .await?;

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
        // SERVER B: groupReset returns 410 Gone with the locked contract body.
        assert_eq!(
            GetGroupStateContractError::group_reset("convo-1", "reset", None).status_code(),
            StatusCode::GONE
        );
    }

    #[test]
    fn welcome_hash_filter_preserves_caller_intent() {
        let absent = parse_requested_welcome_hashes(None);
        assert!(!absent.was_provided);
        assert!(absent.hashes.is_empty());

        let empty: Vec<jacquard_common::CowStr<'static>> = Vec::new();
        let provided_empty = parse_requested_welcome_hashes(Some(&empty));
        assert!(provided_empty.was_provided);
        assert!(provided_empty.hashes.is_empty());

        let requested = vec![
            jacquard_common::CowStr::from("aa11"),
            jacquard_common::CowStr::from("not-hex"),
            jacquard_common::CowStr::from("BB22"),
        ];
        let parsed = parse_requested_welcome_hashes(Some(&requested));
        assert!(parsed.was_provided);
        assert_eq!(parsed.hashes, vec![vec![0xaa, 0x11], vec![0xbb, 0x22]]);
    }

    #[tokio::test]
    async fn group_reset_response_carries_locked_contract_body() {
        let response = GetGroupStateContractError::group_reset(
            "convo-xyz",
            "Conversation was reset",
            Some("session-abc".to_string()),
        )
        .into_response();

        assert_eq!(response.status(), StatusCode::GONE);

        let body_bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        let body_json: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("valid JSON body");
        // Lowercase `groupReset` per locked contract — must NOT regress to
        // PascalCase `GroupReset`, CLIENT D matches the literal string.
        assert_eq!(
            body_json.get("error").and_then(|v| v.as_str()),
            Some("groupReset")
        );
        assert_eq!(
            body_json.get("convoId").and_then(|v| v.as_str()),
            Some("convo-xyz")
        );
        assert_eq!(
            body_json.get("newCryptoSessionId").and_then(|v| v.as_str()),
            Some("session-abc")
        );
    }

    #[tokio::test]
    async fn group_reset_response_emits_null_successor_when_mid_reset() {
        let response = GetGroupStateContractError::group_reset(
            "convo-mid-reset",
            "Conversation is being reset",
            None,
        )
        .into_response();

        let body_bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        let body_json: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("valid JSON body");
        // `newCryptoSessionId` MUST be present and explicitly null when no
        // successor exists yet — the field is part of the locked contract,
        // never absent.
        assert!(body_json.get("newCryptoSessionId").is_some());
        assert!(body_json["newCryptoSessionId"].is_null());
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
