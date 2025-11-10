use axum::{extract::State, http::StatusCode, Json};
use tracing::{info, error};

use crate::{
    auth::AuthUser,
    models::{ConvoView, Membership},
    storage::DbPool,
};

/// Get all conversations for the authenticated user
/// GET /xrpc/chat.bsky.convo.getConvos
#[tracing::instrument(skip(pool))]
pub async fn get_convos(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let did = &auth_user.did;
    info!("Fetching conversations for user");

    // Get all active memberships for the user
    let memberships = sqlx::query_as::<_, Membership>(
        "SELECT convo_id, member_did, user_did, device_id, device_name, joined_at, left_at, unread_count, last_read_at,
                is_admin, promoted_at, promoted_by_did, leaf_index,
                needs_rejoin, rejoin_requested_at, rejoin_key_package_hash
         FROM members WHERE member_did = $1 AND left_at IS NULL ORDER BY joined_at DESC"
    )
    .bind(did)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("Failed to fetch memberships: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut convos = Vec::new();

    for membership in memberships {
        // Get conversation details
        let convo: Option<crate::models::Conversation> = sqlx::query_as(
            "SELECT id, creator_did, current_epoch, created_at, updated_at, name as title, cipher_suite, group_id FROM conversations WHERE id = $1"
        )
        .bind(&membership.convo_id)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch conversation: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if let Some(c) = convo {
            // Get all active members
            let member_rows: Vec<Membership> = sqlx::query_as(
                "SELECT convo_id, member_did, user_did, device_id, device_name, joined_at, left_at, unread_count, last_read_at,
                        is_admin, promoted_at, promoted_by_did, leaf_index,
                        needs_rejoin, rejoin_requested_at, rejoin_key_package_hash
                 FROM members WHERE convo_id = $1 AND left_at IS NULL ORDER BY user_did, joined_at"
            )
            .bind(&membership.convo_id)
            .fetch_all(&pool)
            .await
            .map_err(|e| {
                error!("Failed to fetch members for conversation: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            let members: Vec<crate::models::MemberView> = member_rows
                .into_iter()
                .map(|m| {
                    m.to_member_view().map_err(|e| {
                        error!("Failed to convert membership to member view: {}", e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })
                })
                .collect::<Result<Vec<_>, StatusCode>>()?;

            // Skip conversations without a valid MLS groupId
            if c.group_id.is_none() || c.group_id.as_ref().map_or(true, |gid| gid.is_empty()) {
                error!("Conversation {} has no MLS group_id, skipping", c.id);
                continue;
            }

            // Convert conversation to ConvoView using the existing method
            let convo_view = c.to_convo_view(members).map_err(|e| {
                error!("Failed to convert conversation to view: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            convos.push(convo_view);
        }
    }

    info!("Found {} conversations for user", convos.len());

    Ok(Json(serde_json::json!({ "conversations": convos })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::init_db;

    async fn setup_test_convo(pool: &DbPool, convo_id: &str, creator: &str, members: Vec<&str>) {
        let now = chrono::Utc::now();
        
        sqlx::query("INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at) VALUES ($1, $2, 0, $3, $3)")
            .bind(convo_id)
            .bind(creator)
            .bind(&now)
            .execute(pool)
            .await
            .unwrap();
        
        for member in members {
            sqlx::query("INSERT INTO members (convo_id, member_did, joined_at) VALUES ($1, $2, $3)")
                .bind(convo_id)
                .bind(member)
                .bind(&now)
                .execute(pool)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn test_get_convos_success() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let user = "did:plc:user";
        
        setup_test_convo(&pool, "convo-1", user, vec![user, "did:plc:member1"]).await;
        setup_test_convo(&pool, "convo-2", "did:plc:other", vec!["did:plc:other", user]).await;

        let did = AuthUser { did: user.to_string(), claims: crate::auth::AtProtoClaims { iss: user.to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let result = get_convos(State(pool), did).await;
        assert!(result.is_ok());
        
        let json = result.unwrap().0;
        let convos = json.get("conversations").unwrap().as_array().unwrap();
        assert_eq!(convos.len(), 2);
    }

    #[tokio::test]
    async fn test_get_convos_no_conversations() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        
        let did = AuthUser { did: "did:plc:lonely".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:lonely".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let result = get_convos(State(pool), did).await;
        assert!(result.is_ok());
        
        let json = result.unwrap().0;
        let convos = json.get("conversations").unwrap().as_array().unwrap();
        assert_eq!(convos.len(), 0);
    }

    #[tokio::test]
    async fn test_get_convos_excludes_left() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let user = "did:plc:user";
        
        // Create conversation
        setup_test_convo(&pool, "convo-1", user, vec![user]).await;
        
        // Mark user as left
        let now = chrono::Utc::now();
        sqlx::query("UPDATE members SET left_at = $1 WHERE convo_id = $2 AND member_did = $3")
            .bind(&now)
            .bind("convo-1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();

        let did = AuthUser { did: user.to_string(), claims: crate::auth::AtProtoClaims { iss: user.to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let result = get_convos(State(pool), did).await;
        assert!(result.is_ok());
        
        let json = result.unwrap().0;
        let convos = json.get("conversations").unwrap().as_array().unwrap();
        assert_eq!(convos.len(), 0);
    }

    #[tokio::test]
    async fn test_get_convos_with_unread_count() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let user = "did:plc:user";
        
        setup_test_convo(&pool, "convo-1", user, vec![user]).await;
        
        // Set unread count
        sqlx::query("UPDATE members SET unread_count = 5 WHERE convo_id = $1 AND member_did = $2")
            .bind("convo-1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();

        let did = AuthUser { did: user.to_string(), claims: crate::auth::AtProtoClaims { iss: user.to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let result = get_convos(State(pool), did).await;
        assert!(result.is_ok());
        
        let json = result.unwrap().0;
        let convos = json.get("conversations").unwrap().as_array().unwrap();
        assert_eq!(convos.len(), 1);
        
        let convo = &convos[0];
        assert_eq!(convo.get("unreadCount").unwrap().as_i64().unwrap(), 5);
    }

    #[tokio::test]
    async fn test_get_convos_member_list() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let user = "did:plc:user";
        let member1 = "did:plc:member1";
        let member2 = "did:plc:member2";
        
        setup_test_convo(&pool, "convo-1", user, vec![user, member1, member2]).await;

        let did = AuthUser { did: user.to_string(), claims: crate::auth::AtProtoClaims { iss: user.to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let result = get_convos(State(pool), did).await;
        assert!(result.is_ok());
        
        let json = result.unwrap().0;
        let convos = json.get("conversations").unwrap().as_array().unwrap();
        assert_eq!(convos.len(), 1);
        
        let convo = &convos[0];
        let members = convo.get("members").unwrap().as_array().unwrap();
        assert_eq!(members.len(), 3);
    }
}
