use axum::{extract::{Query, State}, Json};
use axum::http::StatusCode;
use base64::Engine;
use sqlx::FromRow;

use crate::{
    auth::AuthUser,
    error_responses::GetGroupInfoError,
    generated::blue::catbird::mls::get_group_info::{Parameters, Output, OutputData, Error},
    storage::DbPool,
    group_info::{get_group_info, generate_and_cache_group_info},
    sqlx_atrium::chrono_to_datetime,
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
    
    // 1. Check authorization: must be current member (not removed/left)
    // GroupInfo is for cryptographic resync, not for re-adding removed members
    let member_check: Option<MemberCheckRow> = sqlx::query_as(
        "SELECT member_did, left_at
         FROM members
         WHERE convo_id = $1 AND user_did = $2
         LIMIT 1"
    )
    .bind(&params.data.convo_id)
    .bind(did)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let member = member_check.ok_or(Error::Unauthorized(
        Some("Not a member of this conversation".into())
    ))?;

    // 2. Only current members can fetch GroupInfo (for external commits/resync)
    if member.left_at.is_some() {
        return Err(Error::Unauthorized(
            Some("Member was removed or left. Request re-add from admin.".into())
        ).into());
    }
    
    // 3. Fetch cached GroupInfo
    let cached = get_group_info(&pool, &params.data.convo_id).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        
    if let Some((group_info_bytes, epoch, updated_at)) = cached {
        // 4. Check freshness (regenerate if > 6 hours old)
        // Extended TTL to 6 hours to reduce refresh overhead while still providing recovery
        let age = chrono::Utc::now() - updated_at;
        if age.num_hours() > 6 {
            // Regenerate fresh GroupInfo
            // Note: generate_and_cache_group_info is currently a placeholder that might fail
            // Clients should proactively refresh via publishGroupInfo before expiration
            match generate_and_cache_group_info(&pool, &params.data.convo_id).await {
                Ok(fresh_info) => {
                    return Ok(Json(Output::from(OutputData {
                        group_info: base64::engine::general_purpose::STANDARD.encode(fresh_info),
                        epoch: epoch as i64,
                        expires_at: Some(chrono_to_datetime(chrono::Utc::now() + chrono::Duration::hours(6))),
                    })));
                },
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
    let _fresh_info = generate_and_cache_group_info(&pool, &params.data.convo_id).await
        .map_err(|_| Error::GroupInfoUnavailable(Some("GroupInfo not available and cannot be generated".into())))?;
        
    // Fetch again to get epoch
    let cached_again = get_group_info(&pool, &params.data.convo_id).await
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
