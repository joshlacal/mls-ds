use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    storage::{is_member, DbPool},
};

#[derive(Debug, Deserialize)]
pub struct ConfirmWelcomeRequest {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    pub success: bool,
    #[serde(rename = "errorDetails")]
    pub error_details: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ConfirmWelcomeOutput {
    pub confirmed: bool,
}

/// Confirm successful or failed processing of Welcome message
/// POST /xrpc/blue.catbird.mls.confirmWelcome
#[tracing::instrument(skip(pool, input))]
pub async fn confirm_welcome(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<ConfirmWelcomeRequest>,
) -> Result<Json<ConfirmWelcomeOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.confirmWelcome") {
        error!("Unauthorized - failed auth check");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let did = &auth_user.did;

    // Extract user DID from device DID (handles both single and multi-device mode)
    let (user_did, _device_id) = parse_device_did(did)
        .map_err(|e| {
            error!("Invalid device DID format: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    // Validate input
    if input.convo_id.is_empty() {
        warn!("Empty convo_id provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check if user is a member of the conversation (use device DID for membership check)
    if !is_member(&pool, did, &input.convo_id)
        .await
        .map_err(|e| {
            error!("Failed to check membership: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    {
        warn!("User is not a member of conversation");
        return Err(StatusCode::FORBIDDEN);
    }

    if input.success {
        // Mark Welcome as consumed on successful processing
        info!("Confirming successful Welcome processing");

        // NOTE: We use user_did (not device_did) because welcome messages are stored per user
        let rows_updated = sqlx::query(
            "UPDATE welcome_messages
             SET state = 'consumed', confirmed_at = NOW()
             WHERE convo_id = $1 AND recipient_did = $2 AND state = 'in_flight'"
        )
        .bind(&input.convo_id)
        .bind(&user_did)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to update welcome message state: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .rows_affected();

        if rows_updated == 0 {
            warn!("No in-flight Welcome message found");
            // This could be:
            // 1. Already consumed (duplicate confirmation)
            // 2. Never fetched (invalid flow)
            // 3. Expired/cleaned up
            // We return success anyway as the operation is idempotent
        } else {
            info!("Successfully marked Welcome as consumed ({} rows updated)", rows_updated);
        }
    } else {
        // Log failure for debugging
        let error_msg = input.error_details.as_deref().unwrap_or("No error details provided");
        warn!(
            "Welcome processing failed for {} in conversation {}: {}",
            did, input.convo_id, error_msg
        );

        // Optionally update state to 'failed' or leave as 'in_flight' for retry
        // For now, we'll leave it as 'in_flight' to allow retries within the grace period
        // The server's grace period logic in getWelcome will handle re-fetching

        info!("Logging failure but keeping Welcome in 'in_flight' state for potential retry");

        // Log to a failures table if it exists, or just to application logs
        // This helps debug client-side issues with Welcome processing
    }

    Ok(Json(ConfirmWelcomeOutput {
        confirmed: true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::init_db;

    async fn setup_test_convo_with_welcome(
        pool: &DbPool,
        creator: &str,
        member: &str,
        convo_id: &str,
        state: &str,
    ) {
        let now = chrono::Utc::now();

        // Create conversation
        sqlx::query(
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at)
             VALUES ($1, $2, 0, $3, $3)"
        )
        .bind(convo_id)
        .bind(creator)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();

        // Add members
        sqlx::query(
            "INSERT INTO members (convo_id, member_did, joined_at) VALUES ($1, $2, $3)"
        )
        .bind(convo_id)
        .bind(creator)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO members (convo_id, member_did, joined_at) VALUES ($1, $2, $3)"
        )
        .bind(convo_id)
        .bind(member)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();

        // Add welcome message with state column (requires migration)
        let welcome_data = vec![1, 2, 3, 4, 5]; // Mock welcome data
        sqlx::query(
            "INSERT INTO welcome_messages (id, convo_id, recipient_did, welcome_data, state, fetched_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(convo_id)
        .bind(member)
        .bind(&welcome_data)
        .bind(state)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_confirm_welcome_success() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig {
            database_url: db_url,
            max_connections: 5,
            min_connections: 1,
            acquire_timeout: std::time::Duration::from_secs(5),
            idle_timeout: std::time::Duration::from_secs(30),
        })
        .await
        .unwrap();

        let convo_id = "test-confirm-welcome-1";
        let creator = "did:plc:creator";
        let member = "did:plc:member";

        setup_test_convo_with_welcome(&pool, creator, member, convo_id, "in_flight").await;

        let auth_user = AuthUser {
            did: member.to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: member.to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        let input = ConfirmWelcomeRequest {
            convo_id: convo_id.to_string(),
            success: true,
            error_details: None,
        };

        let result = confirm_welcome(State(pool.clone()), auth_user, Json(input)).await;
        assert!(result.is_ok());

        let response = result.unwrap().0;
        assert!(response.confirmed);

        // Verify welcome was marked as consumed
        let state: String = sqlx::query_scalar(
            "SELECT state FROM welcome_messages WHERE convo_id = $1 AND recipient_did = $2"
        )
        .bind(convo_id)
        .bind(member)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(state, "consumed");
    }

    #[tokio::test]
    async fn test_confirm_welcome_failure() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig {
            database_url: db_url,
            max_connections: 5,
            min_connections: 1,
            acquire_timeout: std::time::Duration::from_secs(5),
            idle_timeout: std::time::Duration::from_secs(30),
        })
        .await
        .unwrap();

        let convo_id = "test-confirm-welcome-2";
        let creator = "did:plc:creator";
        let member = "did:plc:member";

        setup_test_convo_with_welcome(&pool, creator, member, convo_id, "in_flight").await;

        let auth_user = AuthUser {
            did: member.to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: member.to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        let input = ConfirmWelcomeRequest {
            convo_id: convo_id.to_string(),
            success: false,
            error_details: Some("Failed to process Welcome".to_string()),
        };

        let result = confirm_welcome(State(pool.clone()), auth_user, Json(input)).await;
        assert!(result.is_ok());

        let response = result.unwrap().0;
        assert!(response.confirmed);

        // Verify welcome is still in_flight (for retry)
        let state: String = sqlx::query_scalar(
            "SELECT state FROM welcome_messages WHERE convo_id = $1 AND recipient_did = $2"
        )
        .bind(convo_id)
        .bind(member)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(state, "in_flight");
    }

    #[tokio::test]
    async fn test_confirm_welcome_not_member() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig {
            database_url: db_url,
            max_connections: 5,
            min_connections: 1,
            acquire_timeout: std::time::Duration::from_secs(5),
            idle_timeout: std::time::Duration::from_secs(30),
        })
        .await
        .unwrap();

        let convo_id = "test-confirm-welcome-3";
        let creator = "did:plc:creator";
        let member = "did:plc:member";

        setup_test_convo_with_welcome(&pool, creator, member, convo_id, "in_flight").await;

        let auth_user = AuthUser {
            did: "did:plc:outsider".to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: "did:plc:outsider".to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        let input = ConfirmWelcomeRequest {
            convo_id: convo_id.to_string(),
            success: true,
            error_details: None,
        };

        let result = confirm_welcome(State(pool), auth_user, Json(input)).await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }
}
