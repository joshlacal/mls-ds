use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use tracing::{error, warn};

use crate::{auth::AuthUser, device_utils::parse_device_did, storage::DbPool};

#[derive(Debug, Deserialize)]
pub struct GetWelcomeParams {
    #[serde(rename = "convoId")]
    pub convo_id: String,
}

// Use generated types for proper ATProto compatibility
use crate::generated::blue::catbird::mls::get_welcome::{Output, OutputData};

/// Get Welcome message for joining an MLS conversation
/// GET /xrpc/blue.catbird.mls.getWelcome
#[tracing::instrument(skip(pool))]
pub async fn get_welcome(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(params): Query<GetWelcomeParams>,
) -> Result<Json<Output>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.getWelcome")
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let device_did = &auth_user.did;

    // Validate input
    if params.convo_id.is_empty() {
        warn!("Empty convo_id provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Extract user DID from device DID (handles both single and multi-device mode)
    let (user_did, _device_id) = parse_device_did(device_did).map_err(|e| {
        error!("Invalid device DID format: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    // Check if the conversation exists
    let convo_exists =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM conversations WHERE id = $1)")
            .bind(&params.convo_id)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("Failed to check conversation existence: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    if !convo_exists {
        warn!(
            "Conversation not found: {}",
            crate::crypto::redact_for_log(&params.convo_id)
        );
        return Err(StatusCode::NOT_FOUND);
    }

    // Check if user is a member or has a pending welcome message
    // We need to allow users who aren't members yet to get their welcome message
    // so they can join. The welcome message itself is the invitation.
    let is_member = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND member_did = $2 AND left_at IS NULL)"
    )
    .bind(&params.convo_id)
    .bind(device_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Failed to check membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Query for unconsumed welcome message WITH KeyPackage validation
    // We use user_did (not device_did) because welcome messages are stored per user
    // Join with key_packages to validate the KeyPackage is still valid (not consumed, not expired)
    // Note: key_packages.key_package_hash is TEXT (hex), welcome_messages.key_package_hash is BYTEA
    let welcome_row = sqlx::query!(
        r#"
        SELECT
            wm.welcome_data,
            wm.key_package_hash,
            kp.consumed_at as "kp_consumed_at?",
            kp.expires_at as "kp_expires_at?"
        FROM welcome_messages wm
        LEFT JOIN key_packages kp
            ON encode(wm.key_package_hash, 'hex') = kp.key_package_hash
        WHERE wm.recipient_did = $1
          AND wm.convo_id = $2
          AND wm.consumed = false
          AND (
              wm.key_package_hash IS NULL
              OR (kp.consumed_at IS NULL AND kp.expires_at > NOW())
          )
        ORDER BY wm.created_at DESC
        LIMIT 1
        "#,
        user_did,
        params.convo_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Failed to query welcome message: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match welcome_row {
        Some(row) => {
            // Warn if KeyPackage hash is missing (shouldn't happen with new code)
            if row.key_package_hash.is_none() {
                warn!(
                    "Welcome message for user {} has no KeyPackage hash - may be from old code",
                    crate::crypto::redact_for_log(&user_did)
                );
            }

            // Encode welcome data as standard base64
            let welcome_base64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &row.welcome_data,
            );

            tracing::info!(
                "Retrieved valid welcome message for user {} in conversation {}",
                crate::crypto::redact_for_log(&user_did),
                crate::crypto::redact_for_log(&params.convo_id)
            );

            Ok(Json(Output::from(OutputData {
                convo_id: params.convo_id,
                welcome: welcome_base64,
            })))
        }
        None => {
            // Check if there's a Welcome with consumed KeyPackage
            let stale_welcome_exists = sqlx::query_scalar::<_, bool>(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM welcome_messages wm
                    LEFT JOIN key_packages kp
                        ON encode(wm.key_package_hash, 'hex') = kp.key_package_hash
                    WHERE wm.recipient_did = $1
                      AND wm.convo_id = $2
                      AND wm.consumed = false
                      AND wm.key_package_hash IS NOT NULL
                      AND (kp.consumed_at IS NOT NULL OR kp.expires_at <= NOW())
                )
                "#,
            )
            .bind(&user_did)
            .bind(&params.convo_id)
            .fetch_one(&pool)
            .await
            .unwrap_or(false);

            if stale_welcome_exists {
                // Welcome exists but KeyPackage is consumed or expired
                warn!(
                    "User {} has stale welcome message (consumed/expired KeyPackage) for conversation {}",
                    crate::crypto::redact_for_log(&user_did),
                    crate::crypto::redact_for_log(&params.convo_id)
                );
                // Return 410 GONE to indicate the resource existed but is no longer valid
                return Err(StatusCode::GONE);
            }

            // No welcome message found at all
            if is_member {
                warn!(
                    "User {} is already a member of conversation {} but has no welcome message",
                    crate::crypto::redact_for_log(&user_did),
                    crate::crypto::redact_for_log(&params.convo_id)
                );
            } else {
                warn!(
                    "No welcome message found for user {} in conversation {}",
                    crate::crypto::redact_for_log(&user_did),
                    crate::crypto::redact_for_log(&params.convo_id)
                );
            }
            Err(StatusCode::NOT_FOUND)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_convo_with_welcome(
        pool: &DbPool,
        creator: &str,
        convo_id: &str,
        recipient: &str,
        welcome_data: &[u8],
    ) {
        let now = chrono::Utc::now();

        // Create conversation
        sqlx::query(
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at)
             VALUES ($1, $2, 0, $3, $3)",
        )
        .bind(convo_id)
        .bind(creator)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();

        // Add creator as member
        sqlx::query(
            "INSERT INTO members (convo_id, member_did, joined_at)
             VALUES ($1, $2, $3)",
        )
        .bind(convo_id)
        .bind(creator)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();

        // Create welcome message for recipient
        sqlx::query(
            "INSERT INTO welcome_messages (id, convo_id, recipient_did, welcome_data, created_at, consumed)
             VALUES ($1, $2, $3, $4, $5, false)"
        )
        .bind(format!("{}-{}", convo_id, recipient))
        .bind(convo_id)
        .bind(recipient)
        .bind(welcome_data)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_get_welcome_success() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let pool = crate::db::init_db(crate::db::DbConfig {
            database_url: db_url,
            max_connections: 5,
            min_connections: 1,
            acquire_timeout: std::time::Duration::from_secs(5),
            idle_timeout: std::time::Duration::from_secs(30),
        })
        .await
        .unwrap();

        let convo_id = "test-welcome-convo-1";
        let creator = "did:plc:creator";
        let recipient = "did:plc:recipient";
        let welcome_data = b"test-welcome-data";

        setup_test_convo_with_welcome(&pool, creator, convo_id, recipient, welcome_data).await;

        let auth_user = AuthUser {
            did: recipient.to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: recipient.to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        let params = GetWelcomeParams {
            convo_id: convo_id.to_string(),
        };

        let result = get_welcome(State(pool), auth_user, Query(params)).await;
        assert!(result.is_ok());

        let response = result.unwrap().0;
        assert_eq!(response.convo_id, convo_id);

        // Decode and verify the welcome data
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &response.welcome,
        )
        .unwrap();
        assert_eq!(decoded, welcome_data);
    }

    #[tokio::test]
    async fn test_get_welcome_not_found() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let pool = crate::db::init_db(crate::db::DbConfig {
            database_url: db_url,
            max_connections: 5,
            min_connections: 1,
            acquire_timeout: std::time::Duration::from_secs(5),
            idle_timeout: std::time::Duration::from_secs(30),
        })
        .await
        .unwrap();

        let convo_id = "test-welcome-convo-2";
        let creator = "did:plc:creator";
        let now = chrono::Utc::now();

        // Create conversation without welcome message
        sqlx::query(
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at)
             VALUES ($1, $2, 0, $3, $3)",
        )
        .bind(convo_id)
        .bind(creator)
        .bind(&now)
        .execute(&pool)
        .await
        .unwrap();

        let auth_user = AuthUser {
            did: "did:plc:recipient".to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: "did:plc:recipient".to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        let params = GetWelcomeParams {
            convo_id: convo_id.to_string(),
        };

        let result = get_welcome(State(pool), auth_user, Query(params)).await;
        assert_eq!(result.unwrap_err(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_welcome_convo_not_found() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let pool = crate::db::init_db(crate::db::DbConfig {
            database_url: db_url,
            max_connections: 5,
            min_connections: 1,
            acquire_timeout: std::time::Duration::from_secs(5),
            idle_timeout: std::time::Duration::from_secs(30),
        })
        .await
        .unwrap();

        let auth_user = AuthUser {
            did: "did:plc:user".to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: "did:plc:user".to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        let params = GetWelcomeParams {
            convo_id: "nonexistent-convo".to_string(),
        };

        let result = get_welcome(State(pool), auth_user, Query(params)).await;
        assert_eq!(result.unwrap_err(), StatusCode::NOT_FOUND);
    }
}
