use base64::Engine;

use axum::{extract::State, http::StatusCode, Json};
use tracing::{info, warn, error};

use crate::{
    auth::AuthUser,
    models::{LeaveConvoInput, LeaveConvoOutput},
    storage::{get_current_epoch, is_member, DbPool},
};

/// Leave a conversation
/// POST /xrpc/chat.bsky.convo.leaveConvo
#[tracing::instrument(skip(pool), fields(did = %auth_user.did, convo_id = %input.convo_id))]
pub async fn leave_convo(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<LeaveConvoInput>,
) -> Result<Json<LeaveConvoOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.leaveConvo") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let did = &auth_user.did;
    // Validate input
    if input.convo_id.is_empty() {
        warn!("Empty convo_id provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    let target_did = input.target_did.unwrap_or_else(|| did.clone());

    // Validate target DID format
    if !target_did.starts_with("did:") {
        warn!("Invalid target DID format: {}", target_did);
        return Err(StatusCode::BAD_REQUEST);
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

    // Users can only remove themselves unless they're the creator
    if &target_did != did {
        let creator_did: String = sqlx::query_scalar(
            "SELECT creator_did FROM conversations WHERE id = $1"
        )
        .bind(&input.convo_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch conversation creator: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if creator_did != *did {
            warn!("User {} is not the creator, cannot remove other members", did);
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let current_epoch = get_current_epoch(&pool, &input.convo_id)
        .await
        .map_err(|e| {
            error!("Failed to get current epoch: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    let new_epoch = current_epoch + 1;
    let now = chrono::Utc::now();

    info!("User {} leaving conversation {}", target_did, input.convo_id);

    // Process commit if provided
    if let Some(commit) = input.commit {
        let commit_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(commit)
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

    // Mark member as left
    sqlx::query("UPDATE members SET left_at = $1 WHERE convo_id = $2 AND member_did = $3")
        .bind(&now)
        .bind(&input.convo_id)
        .bind(&target_did)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to mark member as left: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!("User {} successfully left conversation {}, new epoch: {}", target_did, input.convo_id, new_epoch);

    Ok(Json(LeaveConvoOutput {
        success: true,
        new_epoch,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::init_db;

    async fn setup_test_convo(pool: &DbPool, creator: &str, convo_id: &str, members: Vec<&str>) {
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
    async fn test_leave_convo_success() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let convo_id = "test-convo-1";
        let creator = "did:plc:creator";
        let member = "did:plc:member";
        
        setup_test_convo(&pool, creator, convo_id, vec![creator, member]).await;

        let did = AuthUser { did: member.to_string(), claims: crate::auth::AtProtoClaims { iss: member.to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let input = LeaveConvoInput {
            convo_id: convo_id.to_string(),
            target_did: None,
            commit: None,
        };

        let result = leave_convo(State(pool.clone()), did, Json(input)).await;
        assert!(result.is_ok());
        
        let output = result.unwrap().0;
        assert!(output.success);
        assert_eq!(output.new_epoch, 1);

        // Verify member is marked as left
        let is_active = is_member(&pool, member, convo_id).await.unwrap();
        assert!(!is_active);
    }

    #[tokio::test]
    async fn test_leave_convo_not_member() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let convo_id = "test-convo-2";
        let creator = "did:plc:creator";
        
        setup_test_convo(&pool, creator, convo_id, vec![creator]).await;

        let did = AuthUser { did: "did:plc:outsider".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:outsider".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let input = LeaveConvoInput {
            convo_id: convo_id.to_string(),
            target_did: None,
            commit: None,
        };

        let result = leave_convo(State(pool), did, Json(input)).await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_leave_convo_creator_removes_member() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let convo_id = "test-convo-3";
        let creator = "did:plc:creator";
        let member = "did:plc:member";
        
        setup_test_convo(&pool, creator, convo_id, vec![creator, member]).await;

        let did = AuthUser { did: creator.to_string(), claims: crate::auth::AtProtoClaims { iss: creator.to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let input = LeaveConvoInput {
            convo_id: convo_id.to_string(),
            target_did: Some(member.to_string()),
            commit: None,
        };

        let result = leave_convo(State(pool.clone()), did, Json(input)).await;
        assert!(result.is_ok());
        
        let is_active = is_member(&pool, member, convo_id).await.unwrap();
        assert!(!is_active);
    }

    #[tokio::test]
    async fn test_leave_convo_non_creator_cannot_remove_others() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let convo_id = "test-convo-4";
        let creator = "did:plc:creator";
        let member1 = "did:plc:member1";
        let member2 = "did:plc:member2";
        
        setup_test_convo(&pool, creator, convo_id, vec![creator, member1, member2]).await;

        let did = AuthUser { did: member1.to_string(), claims: crate::auth::AtProtoClaims { iss: member1.to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let input = LeaveConvoInput {
            convo_id: convo_id.to_string(),
            target_did: Some(member2.to_string()),
            commit: None,
        };

        let result = leave_convo(State(pool), did, Json(input)).await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }
}
