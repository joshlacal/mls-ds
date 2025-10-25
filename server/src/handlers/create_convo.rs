use axum::{extract::State, http::StatusCode, Json};
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
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.createConvo") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let did = &auth_user.did;
    
    // Validate cipher suite
    let valid_suites = ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519", 
                        "MLS_128_DHKEMP256_AES128GCM_SHA256_P256"];
    if !valid_suites.contains(&input.cipher_suite.as_str()) {
        warn!("Invalid cipher suite: {}", input.cipher_suite);
        return Err(StatusCode::BAD_REQUEST);
    }
    
    // Validate initial members
    if let Some(ref members) = input.initial_members {
        if members.len() > 100 {
            warn!("Too many initial members: {}", members.len());
            return Err(StatusCode::BAD_REQUEST);
        }
        
        // Validate DIDs format
        for d in members {
            if !d.starts_with("did:") {
                warn!("Invalid DID format: {}", d);
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

    info!("Creating conversation {} with cipher suite {}", convo_id, input.cipher_suite);

    // Create conversation
    sqlx::query(
        "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at, title) VALUES ($1, $2, 0, $3, $3, $4)"
    )
    .bind(&convo_id)
    .bind(did)
    .bind(&now)
    .bind(&name)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Failed to create conversation: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

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
        error!("Failed to add creator membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut members = vec![crate::models::MemberView { 
        did: did.clone(), 
        joined_at: now,
        leaf_index: Some(0),
    }];

    // Add initial members if specified
    if let Some(initial_members) = input.initial_members {
        for (idx, member_did) in initial_members.iter().enumerate() {
            sqlx::query(
                "INSERT INTO members (convo_id, member_did, joined_at) VALUES ($1, $2, $3)"
            )
            .bind(&convo_id)
            .bind(&member_did)
            .bind(&now)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to add member {}: {}", member_did, e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            
            members.push(crate::models::MemberView { 
                did: member_did.clone(),
                joined_at: now,
                leaf_index: Some((idx + 1) as i32),
            });
        }
    }

    info!("Conversation {} created successfully with {} members", convo_id, members.len());

    // Generate MLS group ID (for now, derive from conversation ID)
    let group_id = format!("group_{}", convo_id);
    
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
            cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string(),
            initial_members: Some(vec![]),
            metadata: None,
        };

        let result = create_convo(State(pool), did, Json(input)).await;
        // Empty initial_members is actually valid - creator will be the only member
        assert!(result.is_ok());
    }
}
