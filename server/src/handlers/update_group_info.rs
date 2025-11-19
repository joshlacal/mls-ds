use axum::{extract::State, Json};
use axum::http::StatusCode;
use base64::Engine;
use sqlx::FromRow;

use crate::{
    auth::AuthUser,
    error_responses::UpdateGroupInfoError,
    generated::blue::catbird::mls::update_group_info::{Input, Output, OutputData, Error},
    storage::DbPool,
    group_info::store_group_info,
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
    
    // 2. Decode GroupInfo
    let group_info_bytes = base64::engine::general_purpose::STANDARD
        .decode(&input.data.group_info)
        .map_err(|_| Error::InvalidGroupInfo(Some("Invalid base64".into())))?;
        
    // 3. Store GroupInfo
    store_group_info(
        &pool,
        &input.data.convo_id,
        &group_info_bytes,
        input.data.epoch as i32
    ).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(Output {
        data: OutputData {
            updated: true,
        }
    }))
}