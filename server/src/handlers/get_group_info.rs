use axum::http::StatusCode;
use axum::{
    extract::{Query, State},
    Json,
};
use base64::Engine;
use sqlx::FromRow;
use tracing::{info, warn};

use crate::{
    auth::AuthUser,
    error_responses::GetGroupInfoError,
    generated::blue::catbird::mls::get_group_info::{Error, Output, OutputData, Parameters},
    group_info::{generate_and_cache_group_info, get_group_info},
    sqlx_atrium::chrono_to_datetime,
    storage::DbPool,
};

#[derive(FromRow)]
struct MemberCheckRow {
    #[allow(dead_code)]
    member_did: String,
    left_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn handle(
    State(pool): State<DbPool>,
    auth: AuthUser,
    Query(params): Query<Parameters>,
) -> Result<Json<Output>, GetGroupInfoError> {
    let did = &auth.did;
    let convo_id = &params.data.convo_id;

    // =========================================================================
    // AUTHORIZATION LOG: Track GroupInfo requests for audit
    // =========================================================================
    info!(
        target: "mls_auth",
        event = "group_info_request",
        did = %did,
        convo_id = %convo_id,
        "🔐 [GROUP-INFO] Request by {} for conversation {}",
        did, convo_id
    );

    // 1. Check authorization: must be current member (not removed/left)
    // GroupInfo is for cryptographic resync, not for re-adding removed members
    let member_check: Option<MemberCheckRow> = sqlx::query_as(
        "SELECT member_did, left_at
         FROM members
         WHERE convo_id = $1 AND user_did = $2
         LIMIT 1",
    )
    .bind(convo_id)
    .bind(did)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let member = match member_check {
        Some(m) => m,
        None => {
            warn!(
                target: "mls_auth",
                event = "group_info_rejected",
                did = %did,
                convo_id = %convo_id,
                reason = "not_a_member",
                "❌ [GROUP-INFO] Rejected: Not a member"
            );
            return Err(Error::Unauthorized(Some(
                "Not a member of this conversation".into(),
            ))
            .into());
        }
    };

    // 2. Only current members can fetch GroupInfo (for external commits/resync)
    if member.left_at.is_some() {
        warn!(
            target: "mls_auth",
            event = "group_info_rejected",
            did = %did,
            convo_id = %convo_id,
            reason = "member_left",
            "❌ [GROUP-INFO] Rejected: Member was removed/left"
        );
        return Err(Error::Unauthorized(Some(
            "Member was removed or left. Request re-add from admin.".into(),
        ))
        .into());
    }

    info!(
        target: "mls_auth",
        event = "group_info_authorized",
        did = %did,
        convo_id = %convo_id,
        "✅ [GROUP-INFO] Authorized: Current member"
    );

    // 3. Fetch cached GroupInfo
    let cached = get_group_info(&pool, convo_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some((group_info_bytes, epoch, updated_at)) = cached {
        // 4. Check freshness (regenerate if > 6 hours old)
        // Extended TTL to 6 hours to reduce refresh overhead while still providing recovery
        let age = chrono::Utc::now() - updated_at;
        if age.num_hours() > 6 {
            // Regenerate fresh GroupInfo
            // Note: generate_and_cache_group_info is currently a placeholder that might fail
            // Clients should proactively refresh via publishGroupInfo before expiration
            match generate_and_cache_group_info(&pool, convo_id).await {
                Ok(fresh_info) => {
                    return Ok(Json(Output::from(OutputData {
                        group_info: base64::engine::general_purpose::STANDARD.encode(fresh_info),
                        epoch: epoch as i64,
                        expires_at: Some(chrono_to_datetime(
                            chrono::Utc::now() + chrono::Duration::hours(6),
                        )),
                    })));
                }
                Err(_) => {
                    // If regeneration fails (e.g. not implemented), return cached one if available
                    // Clients can request refresh from active members via groupInfoRefresh
                }
            }
        }

        return Ok(Json(Output::from(OutputData {
            group_info: base64::engine::general_purpose::STANDARD.encode(group_info_bytes),
            epoch: epoch as i64,
            expires_at: Some(chrono_to_datetime(updated_at + chrono::Duration::hours(6))),
        })));
    }

    // If not found, try to generate it
    let _fresh_info = generate_and_cache_group_info(&pool, convo_id)
        .await
        .map_err(|_| {
            Error::GroupInfoUnavailable(Some(
                "GroupInfo not available and cannot be generated".into(),
            ))
        })?;

    // Fetch again to get epoch
    let cached_again = get_group_info(&pool, convo_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some((group_info_bytes, epoch, updated_at)) = cached_again {
        return Ok(Json(Output::from(OutputData {
            group_info: base64::engine::general_purpose::STANDARD.encode(group_info_bytes),
            epoch: epoch as i64,
            expires_at: Some(chrono_to_datetime(updated_at + chrono::Duration::hours(6))),
        })));
    }

    Err(Error::GroupInfoUnavailable(Some("Failed to retrieve generated GroupInfo".into())).into())
}
