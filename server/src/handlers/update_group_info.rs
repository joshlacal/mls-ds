use axum::{extract::State, Json};
use axum::http::StatusCode;
use base64::Engine;
use sqlx::FromRow;
use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::MlsMessageIn;
use tls_codec::Deserialize as TlsDeserialize;

use crate::{
    auth::AuthUser,
    error_responses::UpdateGroupInfoError,
    generated::blue::catbird::mls::update_group_info::{Input, Output, OutputData, Error},
    storage::DbPool,
    group_info::{store_group_info, get_group_info, MIN_GROUP_INFO_SIZE, MAX_GROUP_INFO_SIZE},
};

#[derive(FromRow)]
struct MemberCheckRow {
    #[allow(dead_code)]
    member_did: String,
}

pub async fn handle(
    State(pool): State<DbPool>,
    auth: AuthUser,
    Json(input): Json<Input>,
) -> Result<Json<Output>, UpdateGroupInfoError> {
    let did = &auth.did;
    
    // 1. Check authorization: must be current member
    let member_check: Option<MemberCheckRow> = sqlx::query_as(
        "SELECT member_did 
         FROM members 
         WHERE convo_id = $1 AND user_did = $2
         LIMIT 1"
    )
    .bind(&input.data.convo_id)
    .bind(did)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if member_check.is_none() {
        return Err(Error::Unauthorized(
            Some("Not a member of this conversation".into())
        ).into());
    }
    
    // 2. Decode GroupInfo from base64
    let group_info_bytes = base64::engine::general_purpose::STANDARD
        .decode(&input.data.group_info)
        .map_err(|e| {
            tracing::error!(
                convo_id = %input.data.convo_id,
                error = %e,
                "Invalid base64 in GroupInfo"
            );
            Error::InvalidGroupInfo(Some("Invalid base64 encoding".into()))
        })?;

    // 3. Validate size bounds
    if group_info_bytes.len() < MIN_GROUP_INFO_SIZE {
        tracing::error!(
            convo_id = %input.data.convo_id,
            size = group_info_bytes.len(),
            min_size = MIN_GROUP_INFO_SIZE,
            "GroupInfo too small - likely truncated"
        );
        return Err(Error::InvalidGroupInfo(Some(format!(
            "GroupInfo too small: {} bytes (minimum {} required)",
            group_info_bytes.len(), MIN_GROUP_INFO_SIZE
        ))).into());
    }

    if group_info_bytes.len() > MAX_GROUP_INFO_SIZE {
        tracing::error!(
            convo_id = %input.data.convo_id,
            size = group_info_bytes.len(),
            max_size = MAX_GROUP_INFO_SIZE,
            "GroupInfo too large"
        );
        return Err(Error::InvalidGroupInfo(Some(format!(
            "GroupInfo too large: {} bytes (maximum {} allowed)",
            group_info_bytes.len(), MAX_GROUP_INFO_SIZE
        ))).into());
    }

    // 4. Validate MLS structure - CRITICAL: prevents storing corrupted data
    // The client may send GroupInfo wrapped in an MlsMessage or as raw VerifiableGroupInfo
    // Try MlsMessage first (newer client format), then fall back to raw GroupInfo
    let group_info_valid = MlsMessageIn::tls_deserialize(&mut group_info_bytes.as_slice()).is_ok()
        || VerifiableGroupInfo::tls_deserialize(&mut group_info_bytes.as_slice()).is_ok();
    
    if !group_info_valid {
        tracing::error!(
            convo_id = %input.data.convo_id,
            size = group_info_bytes.len(),
            "Invalid MLS GroupInfo structure - deserialization failed for both wrapped and raw formats"
        );
        return Err(Error::InvalidGroupInfo(Some(
            "Invalid MLS GroupInfo structure: could not deserialize as MlsMessage or raw GroupInfo".into()
        )).into());
    }

    // 5. Validate epoch consistency - epoch must increase (no regression)
    if let Ok(Some((_, existing_epoch, _))) = get_group_info(&pool, &input.data.convo_id).await {
        if input.data.epoch as i32 <= existing_epoch {
            tracing::warn!(
                convo_id = %input.data.convo_id,
                new_epoch = input.data.epoch,
                existing_epoch = existing_epoch,
                "Rejecting GroupInfo with non-increasing epoch"
            );
            return Err(Error::InvalidGroupInfo(Some(format!(
                "Epoch {} must be greater than current epoch {}",
                input.data.epoch, existing_epoch
            ))).into());
        }
    }

    // 6. Store validated GroupInfo
    tracing::info!(
        convo_id = %input.data.convo_id,
        epoch = input.data.epoch,
        size = group_info_bytes.len(),
        "GroupInfo validated successfully, storing"
    );

    store_group_info(
        &pool,
        &input.data.convo_id,
        &group_info_bytes,
        input.data.epoch as i32
    ).await.map_err(|e| {
        tracing::error!(
            convo_id = %input.data.convo_id,
            error = %e,
            "Failed to store GroupInfo"
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    Ok(Json(Output {
        data: OutputData {
            updated: true,
        }
    }))
}