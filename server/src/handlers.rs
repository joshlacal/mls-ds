use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;

use crate::{
    auth::AuthUser,
    models::*,
    storage::{is_member, DbPool},
};

pub async fn create_convo(
    State(pool): State<DbPool>,
    AuthUser(did): AuthUser,
    Json(input): Json<CreateConvoInput>,
) -> Result<Json<ConvoView>, StatusCode> {
    let convo_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    sqlx::query(
        "INSERT INTO conversations (id, creator_did, current_epoch, created_at, title) VALUES (?, ?, 0, ?, ?)"
    )
    .bind(&convo_id)
    .bind(&did)
    .bind(&now)
    .bind(&input.title)
    .execute(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    sqlx::query(
        "INSERT INTO memberships (convo_id, member_did, joined_at) VALUES (?, ?, ?)"
    )
    .bind(&convo_id)
    .bind(&did)
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ConvoView {
        id: convo_id,
        members: vec![MemberInfo { did: did.clone() }],
        created_at: now,
        created_by: did,
        unread_count: 0,
        epoch: 0,
    }))
}

pub async fn add_members(
    State(pool): State<DbPool>,
    AuthUser(did): AuthUser,
    Json(input): Json<AddMembersInput>,
) -> Result<Json<AddMembersOutput>, StatusCode> {
    if !is_member(&pool, &did, &input.convo_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return Err(StatusCode::FORBIDDEN);
    }

    // For MVP: simplified logic, full implementation would handle commit validation
    let current_epoch = crate::storage::get_current_epoch(&pool, &input.convo_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let new_epoch = current_epoch + 1;

    if let Some(commit) = input.commit {
        let commit_bytes = base64::decode(commit).map_err(|_| StatusCode::BAD_REQUEST)?;
        let msg_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        sqlx::query(
            "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, ciphertext, sent_at) VALUES (?, ?, ?, 'commit', ?, ?, ?)"
        )
        .bind(&msg_id)
        .bind(&input.convo_id)
        .bind(&did)
        .bind(new_epoch)
        .bind(&commit_bytes)
        .bind(&now)
        .execute(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        sqlx::query("UPDATE conversations SET current_epoch = ? WHERE id = ?")
            .bind(new_epoch)
            .bind(&input.convo_id)
            .execute(&pool)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        for target_did in &input.did_list {
            sqlx::query(
                "INSERT INTO memberships (convo_id, member_did, joined_at) VALUES (?, ?, ?)"
            )
            .bind(&input.convo_id)
            .bind(target_did)
            .bind(&now)
            .execute(&pool)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }
    }

    Ok(Json(AddMembersOutput {
        success: true,
        new_epoch,
    }))
}

pub async fn send_message(
    State(pool): State<DbPool>,
    AuthUser(did): AuthUser,
    Json(input): Json<SendMessageInput>,
) -> Result<Json<SendMessageOutput>, StatusCode> {
    if !is_member(&pool, &did, &input.convo_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return Err(StatusCode::FORBIDDEN);
    }

    let ciphertext = base64::decode(&input.ciphertext).map_err(|_| StatusCode::BAD_REQUEST)?;
    let msg_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    sqlx::query(
        "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, ciphertext, sent_at) VALUES (?, ?, ?, 'app', ?, ?, ?)"
    )
    .bind(&msg_id)
    .bind(&input.convo_id)
    .bind(&did)
    .bind(input.epoch)
    .bind(&ciphertext)
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(SendMessageOutput {
        message_id: msg_id,
        received_at: now,
    }))
}

pub async fn leave_convo(
    State(pool): State<DbPool>,
    AuthUser(did): AuthUser,
    Json(input): Json<LeaveConvoInput>,
) -> Result<Json<LeaveConvoOutput>, StatusCode> {
    let target_did = input.target_did.unwrap_or_else(|| did.clone());

    if !is_member(&pool, &did, &input.convo_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return Err(StatusCode::FORBIDDEN);
    }

    let current_epoch = crate::storage::get_current_epoch(&pool, &input.convo_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let new_epoch = current_epoch + 1;

    if let Some(commit) = input.commit {
        let commit_bytes = base64::decode(commit).map_err(|_| StatusCode::BAD_REQUEST)?;
        let msg_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        sqlx::query(
            "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, ciphertext, sent_at) VALUES (?, ?, ?, 'commit', ?, ?, ?)"
        )
        .bind(&msg_id)
        .bind(&input.convo_id)
        .bind(&did)
        .bind(new_epoch)
        .bind(&commit_bytes)
        .bind(&now)
        .execute(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        sqlx::query("UPDATE conversations SET current_epoch = ? WHERE id = ?")
            .bind(new_epoch)
            .bind(&input.convo_id)
            .execute(&pool)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    sqlx::query("UPDATE memberships SET left_at = ? WHERE convo_id = ? AND member_did = ?")
        .bind(chrono::Utc::now())
        .bind(&input.convo_id)
        .bind(&target_did)
        .execute(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(LeaveConvoOutput {
        success: true,
        new_epoch,
    }))
}

#[derive(Deserialize)]
pub struct GetMessagesParams {
    #[serde(rename = "convoId")]
    convo_id: String,
    #[serde(rename = "sinceMessage")]
    since_message: Option<String>,
}

pub async fn get_messages(
    State(pool): State<DbPool>,
    AuthUser(did): AuthUser,
    Query(params): Query<GetMessagesParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !is_member(&pool, &did, &params.convo_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return Err(StatusCode::FORBIDDEN);
    }

    let messages = sqlx::query_as::<_, Message>(
        "SELECT * FROM messages WHERE convo_id = ? ORDER BY sent_at ASC"
    )
    .bind(&params.convo_id)
    .fetch_all(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let message_views: Vec<MessageView> = messages
        .into_iter()
        .map(|m| MessageView {
            id: m.id,
            ciphertext: base64::encode(&m.ciphertext),
            epoch: m.epoch,
            sender: MemberInfo {
                did: m.sender_did,
            },
            sent_at: m.sent_at,
        })
        .collect();

    Ok(Json(serde_json::json!({ "messages": message_views })))
}

pub async fn publish_keypackage(
    State(pool): State<DbPool>,
    AuthUser(did): AuthUser,
    Json(input): Json<PublishKeyPackageInput>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let key_data = base64::decode(&input.key_package).map_err(|_| StatusCode::BAD_REQUEST)?;
    let now = chrono::Utc::now();

    sqlx::query(
        "INSERT OR REPLACE INTO keypackages (did, cipher_suite, key_data, created_at, expires_at, consumed) VALUES (?, ?, ?, ?, ?, 0)"
    )
    .bind(&did)
    .bind(&input.cipher_suite)
    .bind(&key_data)
    .bind(&now)
    .bind(&input.expires)
    .execute(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({ "success": true })))
}

#[derive(Deserialize)]
pub struct GetKeyPackagesParams {
    dids: String, // comma-separated
}

pub async fn get_keypackages(
    State(pool): State<DbPool>,
    AuthUser(_did): AuthUser,
    Query(params): Query<GetKeyPackagesParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let dids: Vec<&str> = params.dids.split(',').collect();
    let mut results = Vec::new();

    for did in dids {
        if let Ok(kp) = sqlx::query_as::<_, KeyPackage>(
            "SELECT * FROM keypackages WHERE did = ? AND consumed = 0 AND datetime(expires_at) > datetime('now') LIMIT 1"
        )
        .bind(did)
        .fetch_one(&pool)
        .await
        {
            results.push(KeyPackageInfo {
                did: kp.did,
                key_package: base64::encode(&kp.key_data),
                cipher_suite: kp.cipher_suite,
            });
        }
    }

    Ok(Json(serde_json::json!({ "keyPackages": results })))
}

pub async fn upload_blob(
    State(pool): State<DbPool>,
    AuthUser(did): AuthUser,
    body: axum::body::Bytes,
) -> Result<Json<BlobRef>, StatusCode> {
    use sha2::{Digest, Sha256};

    let data = body.to_vec();
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let cid = format!("{:x}", hasher.finalize());
    let size = data.len() as i64;
    let now = chrono::Utc::now();

    sqlx::query(
        "INSERT OR IGNORE INTO blobs (cid, data, size, uploaded_by_did, uploaded_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&cid)
    .bind(&data)
    .bind(size)
    .bind(&did)
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(BlobRef { cid, size }))
}
