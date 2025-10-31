use axum::{extract::State, http::StatusCode, Json};
use base64::Engine;
use tracing::{info, warn, error};

use crate::{
    auth::AuthUser,
    models::{ConvoView, CreateConvoInput},
    storage::DbPool,
};

/// Create a new conversation
/// POST /xrpc/chat.bsky.convo.createConvo
#[tracing::instrument(skip(pool, auth_user), fields(creator_did = %auth_user.did))]
pub async fn create_convo(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<CreateConvoInput>,
) -> Result<Json<ConvoView>, StatusCode> {
    info!("🔷 [create_convo] START - creator: {}, groupId: {}, initialMembers: {}, has_welcome: {}", 
          auth_user.did, 
          input.group_id,
          input.initial_members.as_ref().map(|m| m.len()).unwrap_or(0),
          input.welcome_message.is_some());
    
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.createConvo") {
        error!("❌ [create_convo] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }
    let did = &auth_user.did;
    
    info!("📍 [create_convo] Validating cipher suite: {}", input.cipher_suite);
    // Validate cipher suite
    let valid_suites = ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519", 
                        "MLS_128_DHKEMP256_AES128GCM_SHA256_P256"];
    if !valid_suites.contains(&input.cipher_suite.as_str()) {
        warn!("❌ [create_convo] Invalid cipher suite: {}", input.cipher_suite);
        return Err(StatusCode::BAD_REQUEST);
    }
    
    // Validate initial members
    if let Some(ref members) = input.initial_members {
        info!("📍 [create_convo] Validating {} initial members", members.len());
        if members.len() > 100 {
            warn!("❌ [create_convo] Too many initial members: {}", members.len());
            return Err(StatusCode::BAD_REQUEST);
        }
        
        // Validate DIDs format
        for d in members {
            if !d.starts_with("did:") {
                warn!("❌ [create_convo] Invalid DID format: {}", d);
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    }

    let convo_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    
    let (name, description) = if let Some(ref meta) = input.metadata {
        (meta.name.clone(), meta.description.clone())
    } else {
        (None, None)
    };

    info!("📍 [create_convo] Creating conversation {} in database...", convo_id);

    // Create conversation with group_id from client
    sqlx::query(
        "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at, name, group_id, cipher_suite) VALUES ($1, $2, 0, $3, $3, $4, $5, $6)"
    )
    .bind(&convo_id)
    .bind(did)
    .bind(&now)
    .bind(&name)
    .bind(&input.group_id)
    .bind(&input.cipher_suite)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [create_convo] Failed to create conversation: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("📍 [create_convo] Adding creator as member...");
    // Add creator as first member
    sqlx::query(
        "INSERT INTO members (convo_id, member_did, joined_at) VALUES ($1, $2, $3)"
    )
    .bind(&convo_id)
    .bind(did)
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [create_convo] Failed to add creator membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut members = vec![crate::models::MemberView { 
        did: did.clone(), 
        joined_at: now,
        leaf_index: Some(0),
    }];

    // Add initial members if specified
    if let Some(ref initial_members) = input.initial_members {
        info!("📍 [create_convo] Adding {} initial members...", initial_members.len());
        for (idx, member_did) in initial_members.iter().enumerate() {
            // Skip if member is the creator (already added above)
            if member_did == did {
                continue;
            }
            
            info!("📍 [create_convo] Adding member {}: {}", idx + 1, member_did);
            sqlx::query(
                "INSERT INTO members (convo_id, member_did, joined_at) VALUES ($1, $2, $3)"
            )
            .bind(&convo_id)
            .bind(&member_did)
            .bind(&now)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("❌ [create_convo] Failed to add member {}: {}", member_did, e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            members.push(crate::models::MemberView {
                did: member_did.clone(),
                joined_at: now,
                leaf_index: Some((idx + 1) as i32),
            });
        }
    }

    // Store Welcome message for initial members
    // MLS generates ONE Welcome message containing encrypted secrets for ALL members
    // Each member can decrypt only their portion from the same Welcome
    if let Some(ref welcome_b64) = input.welcome_message {
        info!("📍 [create_convo] Processing Welcome message...");
        
        // Decode base64url Welcome message
        let welcome_data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(welcome_b64)
            .map_err(|e| {
                warn!("❌ [create_convo] Invalid base64 welcome message: {}", e);
                StatusCode::BAD_REQUEST
            })?;
        
        info!("📍 [create_convo] Single Welcome message ({} bytes) for all members/devices", welcome_data.len());
        
        // Store the SAME Welcome for each initial member (excluding creator)
        if let Some(ref member_list) = input.initial_members {
            let non_creator_members: Vec<_> = member_list.iter().filter(|d| *d != did).collect();
            
            for member_did in &non_creator_members {
                let welcome_id = uuid::Uuid::new_v4().to_string();
                
                sqlx::query(
                    "INSERT INTO welcome_messages (id, convo_id, recipient_did, welcome_data, key_package_hash, created_at) 
                     VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (convo_id, recipient_did, COALESCE(key_package_hash, '\\x00'::bytea)) WHERE consumed = false
                     DO NOTHING"
                )
                .bind(&welcome_id)
                .bind(&convo_id)
                .bind(member_did)
                .bind(&welcome_data)
                .bind::<Option<Vec<u8>>>(None) // key_package_hash
                .bind(&now)
                .execute(&pool)
                .await
                .map_err(|e| {
                    error!("❌ [create_convo] Failed to store welcome message for {}: {}", member_did, e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
                
                info!("✅ [create_convo] Welcome stored for member {}", member_did);
            }
            info!("📍 [create_convo] Stored Welcome for {} members (excluding creator)", non_creator_members.len());
        } else {
            info!("📍 [create_convo] No initial_members list - skipping Welcome storage");
        }
    } else {
        info!("📍 [create_convo] No welcome message provided");
    }

    info!("✅ [create_convo] COMPLETE - convoId: {}, members: {}, epoch: 0", 
          convo_id, members.len());

    // Use the actual MLS group ID from client input
    let group_id = input.group_id.clone();
    
    // Build metadata view if metadata exists
    let metadata_view = if name.is_some() || description.is_some() {
        Some(crate::models::ConvoMetadataView {
            name: name.clone(),
            description: description.clone(),
        })
    } else {
        None
    };

    Ok(Json(ConvoView {
        id: convo_id,
        group_id,
        creator: did.clone(),
        members,
        epoch: 0,
        cipher_suite: input.cipher_suite.clone(),
        created_at: now,
        last_message_at: None,
        metadata: metadata_view,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::init_db;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn test_create_convo_success() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let did = AuthUser { did: "did:plc:test123".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:test123".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let input = CreateConvoInput {
            group_id: "abcdef0123456789".to_string(),
            cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string(),
            initial_members: Some(vec!["did:plc:member1".to_string()]),
            metadata: Some(crate::models::ConvoMetadata {
                name: Some("Test Convo".to_string()),
                description: None,
            }),
        };

        let result = create_convo(State(pool), did.clone(), Json(input)).await;
        assert!(result.is_ok());
        
        let convo = result.unwrap().0;
        assert_eq!(convo.members.len(), 2);
        assert_eq!(convo.epoch, 0);
        assert_eq!(convo.creator, did.did);
    }

    #[tokio::test]
    async fn test_create_convo_invalid_did() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let did = AuthUser { did: "did:plc:test123".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:test123".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let input = CreateConvoInput {
            group_id: "abcdef0123456789".to_string(),
            cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string(),
            initial_members: Some(vec!["invalid_did".to_string()]),
            metadata: None,
        };

        let result = create_convo(State(pool), did, Json(input)).await;
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_convo_empty_did_list() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let did = AuthUser { did: "did:plc:test123".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:test123".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let input = CreateConvoInput {
            group_id: "abcdef0123456789".to_string(),
            cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string(),
            initial_members: Some(vec![]),
            metadata: None,
        };

        let result = create_convo(State(pool), did, Json(input)).await;
        // Empty initial_members is actually valid - creator will be the only member
        assert!(result.is_ok());
    }
}
