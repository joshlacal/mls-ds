use base64::Engine;

use axum::{extract::State, http::StatusCode, Json};
use tracing::{info, warn, error};

use crate::{
    auth::AuthUser,
    models::{SendMessageInput, SendMessageOutput},
    storage::{is_member, DbPool},
};

/// Send a message to a conversation
/// POST /xrpc/chat.bsky.convo.sendMessage
#[tracing::instrument(skip(pool, input), fields(did = %auth_user.did, convo_id = %input.convo_id))]
pub async fn send_message(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<SendMessageInput>,
) -> Result<Json<SendMessageOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.sendMessage") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let did = &auth_user.did;
    // Validate input
    if input.ciphertext.is_empty() {
        warn!("Empty ciphertext provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    if &input.sender_did != did {
        warn!("Sender DID mismatch: expected {}, got {}", did, input.sender_did);
        return Err(StatusCode::FORBIDDEN);
    }

    if input.epoch < 0 {
        warn!("Invalid epoch: {}", input.epoch);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check if sender is a member
    if !is_member(&pool, did, &input.convo_id)
        .await
        .map_err(|e| {
            error!("Failed to check membership: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    {
        warn!("User {} is not a member of conversation {}", did, input.convo_id);
        return Err(StatusCode::FORBIDDEN);
    }

    // Decode ciphertext
    let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input.ciphertext)
        .map_err(|e| {
            warn!("Invalid base64 ciphertext: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    let msg_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    info!("Sending message {} to conversation {}", msg_id, input.convo_id);

    // Insert message
    sqlx::query(
        "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, ciphertext, sent_at) VALUES ($1, $2, $3, 'app', $4, $5, $6)"
    )
    .bind(&msg_id)
    .bind(&input.convo_id)
    .bind(did)
    .bind(input.epoch)
    .bind(&ciphertext)
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Failed to insert message: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Update unread counts for other members
    sqlx::query(
        "UPDATE members SET unread_count = unread_count + 1 WHERE convo_id = $1 AND member_did != $2 AND left_at IS NULL"
    )
    .bind(&input.convo_id)
    .bind(did)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Failed to update unread counts: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("Message {} sent successfully", msg_id);

    Ok(Json(SendMessageOutput {
        message_id: msg_id,
        received_at: now,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::init_db;

    async fn setup_test_convo(pool: &DbPool, creator: &str, convo_id: &str) {
        let now = chrono::Utc::now();
        sqlx::query("INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at) VALUES ($1, $2, 0, $3, $3)")
            .bind(convo_id)
            .bind(creator)
            .bind(&now)
            .execute(pool)
            .await
            .unwrap();
        
        sqlx::query("INSERT INTO members (convo_id, member_did, joined_at) VALUES ($1, $2, $3)")
            .bind(convo_id)
            .bind(creator)
            .bind(&now)
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_send_message_success() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let convo_id = "test-convo-1";
        let sender = "did:plc:sender";
        
        setup_test_convo(&pool, sender, convo_id).await;

        let did = AuthUser { did: sender.to_string(), claims: crate::auth::AtProtoClaims { iss: sender.to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None } };
        let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"encrypted message");
        let input = SendMessageInput {
            convo_id: convo_id.to_string(),
            ciphertext,
            epoch: 0,
            sender_did: sender.to_string(),
        };

        let result = send_message(State(pool), did, Json(input)).await;
        assert!(result.is_ok());
        
        let output = result.unwrap().0;
        assert!(!output.message_id.is_empty());
    }

    #[tokio::test]
    async fn test_send_message_not_member() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let convo_id = "test-convo-2";
        let creator = "did:plc:creator";
        
        setup_test_convo(&pool, creator, convo_id).await;

        let did = AuthUser { did: "did:plc:outsider".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:outsider".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None } };
        let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"encrypted message");
        let input = SendMessageInput {
            convo_id: convo_id.to_string(),
            ciphertext,
            epoch: 0,
            sender_did: "did:plc:outsider".to_string(),
        };

        let result = send_message(State(pool), did, Json(input)).await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_send_message_empty_ciphertext() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let convo_id = "test-convo-3";
        let sender = "did:plc:sender";
        
        setup_test_convo(&pool, sender, convo_id).await;

        let did = AuthUser { did: sender.to_string(), claims: crate::auth::AtProtoClaims { iss: sender.to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None } };
        let input = SendMessageInput {
            convo_id: convo_id.to_string(),
            ciphertext: String::new(),
            epoch: 0,
            sender_did: sender.to_string(),
        };

        let result = send_message(State(pool), did, Json(input)).await;
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_send_message_sender_mismatch() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let convo_id = "test-convo-4";
        let sender = "did:plc:sender";
        
        setup_test_convo(&pool, sender, convo_id).await;

        let did = AuthUser { did: sender.to_string(), claims: crate::auth::AtProtoClaims { iss: sender.to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None } };
        let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"encrypted message");
        let input = SendMessageInput {
            convo_id: convo_id.to_string(),
            ciphertext,
            epoch: 0,
            sender_did: "did:plc:impostor".to_string(),
        };

        let result = send_message(State(pool), did, Json(input)).await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }
}
