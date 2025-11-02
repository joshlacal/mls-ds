use base64::Engine;

use axum::{extract::State, http::StatusCode, Json};
use tracing::{info, warn, error};

use crate::{
    auth::AuthUser,
    models::{AddMembersInput, AddMembersOutput},
    storage::{get_current_epoch, is_member, DbPool},
};

/// Add members to an existing conversation
/// POST /xrpc/chat.bsky.convo.addMembers
#[tracing::instrument(skip(pool), fields(did = %auth_user.did, convo_id = %input.convo_id))]
pub async fn add_members(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<AddMembersInput>,
) -> Result<Json<AddMembersOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.addMembers") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let did = &auth_user.did;
    // Validate input
    if input.did_list.is_empty() {
        warn!("Empty did_list provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    for d in &input.did_list {
        if !d.starts_with("did:") {
            warn!("Invalid DID format: {}", d);
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Check if requester is a member
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

    let current_epoch = get_current_epoch(&pool, &input.convo_id)
        .await
        .map_err(|e| {
            error!("Failed to get current epoch: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    let new_epoch = current_epoch + 1;
    let now = chrono::Utc::now();

    info!("Adding {} members to conversation {}", input.did_list.len(), input.convo_id);

    // Process commit if provided
    if let Some(commit) = input.commit {
        let commit_bytes = base64::engine::general_purpose::STANDARD.decode(commit)
            .map_err(|e| {
                warn!("Invalid base64 commit: {}", e);
                StatusCode::BAD_REQUEST
            })?;
        
        let msg_id = uuid::Uuid::new_v4().to_string();

        sqlx::query(
            "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6)"
        )
        .bind(&msg_id)
        .bind(&input.convo_id)
        .bind(did)
        .bind(new_epoch)
        .bind(&commit_bytes)
        .bind(&now)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to insert commit message: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        sqlx::query("UPDATE conversations SET current_epoch = $1 WHERE id = $2")
            .bind(new_epoch)
            .bind(&input.convo_id)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to update conversation epoch: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    // Add new members
    for target_did in &input.did_list {
        // Check if already a member
        let is_existing = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM members WHERE convo_id = $1 AND member_did = $2"
        )
        .bind(&input.convo_id)
        .bind(target_did)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!("Failed to check existing membership: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if is_existing > 0 {
            info!("Member {} already exists, skipping", target_did);
            continue;
        }

        sqlx::query(
            "INSERT INTO members (convo_id, member_did, joined_at) VALUES ($1, $2, $3)"
        )
        .bind(&input.convo_id)
        .bind(target_did)
        .bind(&now)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to add member {}: {}", target_did, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    // Store Welcome message for new members
    // MLS generates ONE Welcome message containing encrypted secrets for ALL members
    if let Some(ref welcome_b64) = input.welcome_message {
        info!("📍 [add_members] Processing Welcome message...");

        // Decode base64 Welcome message
        let welcome_data = base64::engine::general_purpose::STANDARD
            .decode(welcome_b64)
            .map_err(|e| {
                warn!("❌ [add_members] Invalid base64 welcome message: {}", e);
                StatusCode::BAD_REQUEST
            })?;
        
        info!("📍 [add_members] Single Welcome message ({} bytes) for {} new members", 
              welcome_data.len(), input.did_list.len());
        
        // Store the SAME Welcome for each new member
        for target_did in &input.did_list {
            let welcome_id = uuid::Uuid::new_v4().to_string();

            // Get the key_package_hash for this member from the input
            let key_package_hash = input.key_package_hashes.as_ref()
                .and_then(|hashes| {
                    hashes.iter()
                        .find(|entry| entry.did == *target_did)
                        .map(|entry| hex::decode(&entry.hash).ok())
                        .flatten()
                });

            sqlx::query(
                "INSERT INTO welcome_messages (id, convo_id, recipient_did, welcome_data, key_package_hash, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (convo_id, recipient_did, COALESCE(key_package_hash, '\\x00'::bytea)) WHERE consumed = false
                 DO NOTHING"
            )
            .bind(&welcome_id)
            .bind(&input.convo_id)
            .bind(target_did)
            .bind(&welcome_data)
            .bind::<Option<Vec<u8>>>(key_package_hash) // key_package_hash from client
            .bind(&now)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("❌ [add_members] Failed to store welcome message for {}: {}", target_did, e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            info!("✅ [add_members] Welcome stored for member {}", target_did);
        }
        info!("📍 [add_members] Stored Welcome for {} members", input.did_list.len());
    } else {
        info!("📍 [add_members] No welcome message provided");
    }

    info!("Successfully added members to conversation {}, new epoch: {}", input.convo_id, new_epoch);

    Ok(Json(AddMembersOutput {
        success: true,
        new_epoch,
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
    async fn test_add_members_success() {
        // Use TEST_DATABASE_URL for Postgres-backed tests; skip if unset
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let convo_id = "test-convo-1";
        let creator = "did:plc:creator";
        
        setup_test_convo(&pool, creator, convo_id).await;

        let did = AuthUser { did: creator.to_string(), claims: crate::auth::AtProtoClaims { iss: creator.to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let input = AddMembersInput {
            convo_id: convo_id.to_string(),
            did_list: vec!["did:plc:member1".to_string()],
            commit: None,
            welcome: None,
        };

        let result = add_members(State(pool), did, Json(input)).await;
        assert!(result.is_ok());
        
        let output = result.unwrap().0;
        assert!(output.success);
        assert_eq!(output.new_epoch, 1);
    }

    #[tokio::test]
    async fn test_add_members_not_member() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let convo_id = "test-convo-2";
        let creator = "did:plc:creator";
        
        setup_test_convo(&pool, creator, convo_id).await;

        let did = AuthUser { did: "did:plc:outsider".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:outsider".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let input = AddMembersInput {
            convo_id: convo_id.to_string(),
            did_list: vec!["did:plc:member1".to_string()],
            commit: None,
            welcome: None,
        };

        let result = add_members(State(pool), did, Json(input)).await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_add_members_empty_list() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let convo_id = "test-convo-3";
        let creator = "did:plc:creator";
        
        setup_test_convo(&pool, creator, convo_id).await;

        let did = AuthUser { did: creator.to_string(), claims: crate::auth::AtProtoClaims { iss: creator.to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let input = AddMembersInput {
            convo_id: convo_id.to_string(),
            did_list: vec![],
            commit: None,
            welcome: None,
        };

        let result = add_members(State(pool), did, Json(input)).await;
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }
}
