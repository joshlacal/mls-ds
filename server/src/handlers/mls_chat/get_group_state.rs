use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use tracing::{error, info};

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::get_group_state::{
        GetGroupStateOutput, GetGroupStateRequest,
    },
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getGroupState";

/// Consolidated group state query
/// GET /xrpc/blue.catbird.mlsChat.getGroupState?convoId=xxx&include=groupInfo,welcome,epoch
///
/// Consolidates: getGroupInfo, getEpoch, getWelcome, invalidateWelcome
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_group_state(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(params): ExtractXrpc<GetGroupStateRequest>,
) -> Result<Json<GetGroupStateOutput<'static>>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let convo_id = params.convo_id.as_ref();
    let include_str = params.include.as_deref().unwrap_or("groupInfo,epoch");
    let includes: Vec<&str> = include_str.split(',').map(|s| s.trim()).collect();

    let mut epoch: Option<i64> = None;
    let mut group_info: Option<String> = None;
    let mut welcome: Option<String> = None;
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
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    // Fetch group info
    if includes.contains(&"groupInfo") {
        match crate::group_info::get_group_info(&pool, convo_id).await {
            Ok(Some((group_info_bytes, gi_epoch, _updated_at))) => {
                use base64::Engine;
                group_info =
                    Some(base64::engine::general_purpose::STANDARD.encode(&group_info_bytes));
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
                // No group info available
            }
            Err(e) => {
                error!(
                    convo_id = %crate::crypto::redact_for_log(convo_id),
                    error = %e,
                    "Failed to get group info"
                );
                // Don't fail the whole request, just omit groupInfo
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
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if let Some((_welcome_id, data)) = welcome_row {
            use base64::Engine;
            welcome = Some(base64::engine::general_purpose::STANDARD.encode(&data));
        }
    }

    info!(
        "Fetched group state for convo {} (includes: {})",
        crate::crypto::redact_for_log(convo_id),
        include_str
    );

    Ok(Json(GetGroupStateOutput {
        epoch,
        group_info: group_info.map(Into::into),
        welcome: welcome.map(Into::into),
        expires_at,
        extra_data: Default::default(),
    }))
}
