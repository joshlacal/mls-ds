use axum::{extract::State, http::StatusCode, Json};
use base64::Engine;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    generated::blue::catbird::mls::request_rejoin::{Input, Output, OutputData},
    storage::DbPool,
};

/// Request to rejoin an MLS conversation after local state loss
/// POST /xrpc/blue.catbird.mls.requestRejoin
///
/// When a device registers and gets `auto_joined_convos`, it needs to request
/// rejoin to get Welcome messages for those conversations. This handler:
/// 1. Verifies the user was previously a member (has a member record)
/// 2. Validates and stores the provided KeyPackage
/// 3. Creates a pending rejoin request (may be auto-approved based on criteria)
/// 4. Returns the request status
#[tracing::instrument(skip(pool))]
pub async fn request_rejoin(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<Input>,
) -> Result<Json<Output>, StatusCode> {
    // Enforce authentication
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.requestRejoin") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let device_did = &auth_user.did;
    let convo_id = &input.convo_id;
    let key_package_b64 = &input.key_package;
    let reason = input.reason.as_deref().unwrap_or("device_state_loss");

    // Validate input
    if convo_id.is_empty() {
        warn!("Empty convo_id provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    if key_package_b64.is_empty() {
        warn!("Empty key_package provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Decode and validate KeyPackage
    let key_package_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key_package_b64)
        .map_err(|e| {
            warn!("Invalid base64url KeyPackage: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    if key_package_bytes.is_empty() {
        warn!("Empty KeyPackage after decode");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Extract user DID from device DID
    let (user_did, device_id) = parse_device_did(device_did)
        .map_err(|e| {
            error!("Invalid device DID format: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    info!(
        "Processing rejoin request: user={}, device={}, convo={}, reason={}",
        crate::crypto::redact_for_log(&user_did),
        if device_id.is_empty() { "none" } else { &device_id },
        crate::crypto::redact_for_log(convo_id),
        reason
    );

    // Check if conversation exists
    let convo_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM conversations WHERE id = $1)"
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Failed to check conversation existence: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !convo_exists {
        warn!("Conversation not found: {}", crate::crypto::redact_for_log(convo_id));
        return Err(StatusCode::NOT_FOUND);
    }

    // Check if user was previously a member (either currently active or left)
    // This is the key verification: only users who were once members can rejoin
    #[derive(sqlx::FromRow)]
    struct MemberRecord {
        member_did: String,
        user_did: Option<String>,
        joined_at: chrono::DateTime<chrono::Utc>,
        left_at: Option<chrono::DateTime<chrono::Utc>>,
        needs_rejoin: bool,
        rejoin_auto_approved: Option<bool>,
        last_read_at: Option<chrono::DateTime<chrono::Utc>>,
    }

    let member_record = sqlx::query_as::<_, MemberRecord>(
        r#"
        SELECT
            member_did,
            user_did,
            joined_at,
            left_at,
            needs_rejoin,
            rejoin_auto_approved,
            last_read_at
        FROM members
        WHERE convo_id = $1 AND (user_did = $2 OR member_did = $3)
        ORDER BY joined_at DESC
        LIMIT 1
        "#
    )
    .bind(convo_id)
    .bind(&user_did)
    .bind(device_did)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Failed to query member record: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let member_record = match member_record {
        Some(record) => record,
        None => {
            warn!(
                "User {} was never a member of conversation {}",
                crate::crypto::redact_for_log(&user_did),
                crate::crypto::redact_for_log(convo_id)
            );
            return Err(StatusCode::FORBIDDEN);
        }
    };

    // Check if user is already an active member with valid state
    if member_record.left_at.is_none() && !member_record.needs_rejoin {
        warn!(
            "User {} is already an active member of conversation {} with valid state",
            crate::crypto::redact_for_log(&user_did),
            crate::crypto::redact_for_log(convo_id)
        );
        return Err(StatusCode::CONFLICT);
    }

    // Calculate KeyPackage hash for tracking
    let key_package_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&key_package_bytes);
        let hash = hasher.finalize();
        hex::encode(hash)
    };

    info!(
        "KeyPackage hash: {} (first 8 chars)",
        &key_package_hash[..8.min(key_package_hash.len())]
    );

    // Check rate limiting: max 10 rejoin requests per conversation per hour
    let recent_requests = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM members
        WHERE convo_id = $1
          AND (user_did = $2 OR member_did = $3)
          AND rejoin_requested_at > NOW() - INTERVAL '1 hour'
        "#
    )
    .bind(convo_id)
    .bind(&user_did)
    .bind(device_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Failed to check rate limit: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if recent_requests >= 10 {
        warn!(
            "Rate limit exceeded for user {} in conversation {}: {} requests in last hour",
            crate::crypto::redact_for_log(&user_did),
            crate::crypto::redact_for_log(convo_id),
            recent_requests
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Determine if auto-approval applies
    // Auto-approve if:
    // 1. User was active within the last 30 days (based on last_read_at)
    // 2. User didn't explicitly leave (left_at is NULL OR needs_rejoin is true)
    let auto_approved = if let Some(last_read_at) = member_record.last_read_at {
        let days_since_activity = (chrono::Utc::now() - last_read_at).num_days();
        days_since_activity <= 30
    } else {
        // No activity record, check if joined recently (within 30 days)
        let days_since_join = (chrono::Utc::now() - member_record.joined_at).num_days();
        days_since_join <= 30
    };

    let request_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    info!(
        "Rejoin request {}: auto_approved={}",
        &request_id[..8.min(request_id.len())],
        auto_approved
    );

    // Begin transaction to update member record and store KeyPackage
    let mut tx = pool.begin().await.map_err(|e| {
        error!("Failed to start transaction: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Update or insert member record with rejoin request
    // If the device already has a member record, update it
    // Otherwise, insert a new one for multi-device support
    let updated = sqlx::query_scalar::<_, String>(
        r#"
        UPDATE members
        SET needs_rejoin = true,
            rejoin_requested_at = $1,
            rejoin_key_package_hash = $2,
            rejoin_auto_approved = $3,
            left_at = NULL
        WHERE convo_id = $4 AND member_did = $5
        RETURNING member_did
        "#
    )
    .bind(now)
    .bind(&key_package_hash)
    .bind(auto_approved)
    .bind(convo_id)
    .bind(device_did)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        error!("Failed to update member record: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if updated.is_none() {
        // No existing member record for this device - insert new one
        sqlx::query(
            r#"
            INSERT INTO members (
                convo_id,
                member_did,
                user_did,
                device_id,
                joined_at,
                needs_rejoin,
                rejoin_requested_at,
                rejoin_key_package_hash,
                rejoin_auto_approved,
                is_admin
            )
            VALUES ($1, $2, $3, $4, $5, true, $6, $7, $8, false)
            "#
        )
        .bind(convo_id)
        .bind(device_did)
        .bind(&user_did)
        .bind(&device_id)
        .bind(member_record.joined_at) // Preserve original join time
        .bind(now)
        .bind(&key_package_hash)
        .bind(auto_approved)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("Failed to insert member record: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        info!("Created new member record for device with rejoin request");
    }

    // Store the KeyPackage in key_packages table
    // This makes it available for the next addMembers call
    let kp_id = uuid::Uuid::new_v4().to_string();
    let expires_at = now + chrono::Duration::days(30);
    sqlx::query(
        r#"
        INSERT INTO key_packages (
            id,
            owner_did,
            device_id,
            credential_did,
            cipher_suite,
            key_package,
            key_package_hash,
            created_at,
            expires_at
        )
        VALUES ($1, $2, $3, $4, 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519', $5, $6, $7, $8)
        ON CONFLICT (key_package_hash) DO NOTHING
        "#
    )
    .bind(&kp_id)
    .bind(&user_did)
    .bind(&device_id)
    .bind(device_did)
    .bind(&key_package_bytes)
    .bind(&key_package_hash)
    .bind(now)
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("Failed to store KeyPackage: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("Stored KeyPackage for rejoin request");

    // Commit transaction
    tx.commit().await.map_err(|e| {
        error!("Failed to commit transaction: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let approved_at = if auto_approved {
        Some(crate::sqlx_atrium::chrono_to_datetime(now))
    } else {
        None
    };

    info!(
        "Rejoin request completed: request_id={}, auto_approved={}, pending={}",
        &request_id[..8.min(request_id.len())],
        auto_approved,
        !auto_approved
    );

    Ok(Json(Output::from(OutputData {
        request_id,
        pending: !auto_approved,
        approved_at,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_convo_with_member(
        pool: &DbPool,
        creator: &str,
        convo_id: &str,
        member_did: &str,
        user_did: &str,
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

        // Add member with recent activity (should auto-approve)
        sqlx::query(
            "INSERT INTO members (convo_id, member_did, user_did, joined_at, last_read_at, needs_rejoin)
             VALUES ($1, $2, $3, $4, $5, false)"
        )
        .bind(convo_id)
        .bind(member_did)
        .bind(user_did)
        .bind(now - chrono::Duration::days(10))
        .bind(now - chrono::Duration::days(5)) // Active 5 days ago
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_request_rejoin_auto_approved() {
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

        let convo_id = "test-rejoin-convo-1";
        let creator = "did:plc:creator";
        let user_did = "did:plc:user";
        let device_did = format!("{}#device-1", user_did);

        setup_test_convo_with_member(&pool, creator, convo_id, &device_did, user_did).await;

        let auth_user = AuthUser {
            did: device_did.clone(),
            claims: crate::auth::AtProtoClaims {
                iss: device_did.clone(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        // Create a mock KeyPackage (in reality this would be an MLS KeyPackage)
        let key_package = b"mock-key-package-data";
        let key_package_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(key_package);

        let input = Input::from(crate::generated::blue::catbird::mls::request_rejoin::InputData {
            convo_id: convo_id.to_string(),
            key_package: key_package_b64,
            reason: Some("test_device_state_loss".to_string()),
        });

        let result = request_rejoin(State(pool.clone()), auth_user, Json(input)).await;
        assert!(result.is_ok());

        let output = result.unwrap().0;
        assert!(!output.pending); // Should be auto-approved
        assert!(output.approved_at.is_some());
    }

    #[tokio::test]
    async fn test_request_rejoin_not_member() {
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

        let convo_id = "test-rejoin-convo-2";
        let creator = "did:plc:creator";
        let now = chrono::Utc::now();

        // Create conversation without adding the user as member
        sqlx::query(
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at)
             VALUES ($1, $2, 0, $3, $3)"
        )
        .bind(convo_id)
        .bind(creator)
        .bind(&now)
        .execute(&pool)
        .await
        .unwrap();

        let user_did = "did:plc:nonmember";
        let device_did = format!("{}#device-1", user_did);

        let auth_user = AuthUser {
            did: device_did.clone(),
            claims: crate::auth::AtProtoClaims {
                iss: device_did.clone(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        let key_package = b"mock-key-package-data";
        let key_package_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(key_package);

        let input = Input::from(crate::generated::blue::catbird::mls::request_rejoin::InputData {
            convo_id: convo_id.to_string(),
            key_package: key_package_b64,
            reason: Some("test".to_string()),
        });

        let result = request_rejoin(State(pool), auth_user, Json(input)).await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }
}
