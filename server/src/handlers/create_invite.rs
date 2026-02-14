///! Invite creation and management handlers
///!
///! This module handles:
///! - Creating invite links with PSK authentication
///! - Revoking invites
///! - Listing invites for a conversation
///!
///! Security model:
///! - Server stores SHA256(PSK) only, never sees plaintext PSK
///! - PSK is generated client-side and included in invite link
///! - Only admins can create/revoke invites
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{error, info, warn};

use crate::admin_system::verify_is_admin;
use crate::auth::AuthUser;
use crate::error::Error;

// =============================================================================
// REQUEST/RESPONSE TYPES
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInviteInput {
    /// Conversation ID
    pub convo_id: String,

    /// PSK hash (client generates PSK, hashes it with SHA256, sends hash)
    /// Must be 64 hex characters (SHA256 in hex)
    /// Server NEVER sees plaintext PSK
    pub psk_hash: String,

    /// Optional: Target specific DID (null = open invite, anyone with link can use)
    pub target_did: Option<String>,

    /// Optional: Expiry timestamp (null = never expires)
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Optional: Max uses (null = unlimited, 1 = single-use, N = N uses)
    pub max_uses: Option<i32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInviteOutput {
    /// Invite ID (UUID)
    pub invite_id: String,

    /// Success confirmation
    pub success: bool,

    /// Full invite view (for immediate display)
    pub invite: InviteView,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct InviteView {
    pub id: String,
    pub convo_id: String,
    pub created_by_did: String,

    #[sqlx(default)]
    pub target_did: Option<String>,

    pub created_at: chrono::DateTime<chrono::Utc>,

    #[sqlx(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,

    #[sqlx(default)]
    pub max_uses: Option<i32>,

    pub uses_count: i32,
    pub revoked: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeInviteInput {
    pub invite_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeInviteOutput {
    pub success: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListInvitesInput {
    pub convo_id: String,

    /// Optional: Include revoked invites (default false)
    #[serde(default)]
    pub include_revoked: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListInvitesOutput {
    pub invites: Vec<InviteView>,
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Create an invite link (admin only)
///
/// Authorization: Caller must be an admin of the conversation
/// Security: PSK is hashed client-side, server stores hash only
///
/// Request body:
/// ```json
/// {
///   "convoId": "...",
///   "pskHash": "64-char-hex-string",
///   "targetDid": null,  // optional
///   "expiresAt": null,  // optional
///   "maxUses": 1        // optional
/// }
/// ```
pub async fn create_invite(
    State(pool): State<PgPool>,
    auth_user: AuthUser,
    Json(input): Json<CreateInviteInput>,
) -> Result<Json<CreateInviteOutput>, (StatusCode, String)> {
    let caller_did = &auth_user.did;

    info!(
        convo_id = %input.convo_id,
        caller = %caller_did,
        target = ?input.target_did,
        max_uses = ?input.max_uses,
        "Admin creating invite"
    );

    // Step 1: Verify caller is an admin
    verify_is_admin(&pool, &input.convo_id, caller_did)
        .await
        .map_err(|e| {
            error!("Admin verification failed: {}", e);
            (StatusCode::FORBIDDEN, "Not an admin".to_string())
        })?;

    // Step 2: Validate PSK hash format
    // Must be exactly 64 hex characters (SHA256 in hex = 32 bytes * 2 = 64 chars)
    if input.psk_hash.len() != 64 {
        error!(
            "Invalid PSK hash length: {} (expected 64)",
            input.psk_hash.len()
        );
        return Err((
            StatusCode::BAD_REQUEST,
            "PSK hash must be 64 hex characters (SHA256)".to_string(),
        ));
    }

    if !input.psk_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        error!("Invalid PSK hash format: contains non-hex characters");
        return Err((
            StatusCode::BAD_REQUEST,
            "PSK hash must contain only hex characters (0-9, a-f)".to_string(),
        ));
    }

    // Step 3: If target_did provided, validate it's a valid DID
    if let Some(ref target) = input.target_did {
        if !target.starts_with("did:") {
            error!(
                "Invalid target DID format: {}",
                crate::crypto::redact_for_log(target)
            );
            return Err((
                StatusCode::BAD_REQUEST,
                "Target DID must start with 'did:'".to_string(),
            ));
        }
    }

    // Step 4: Validate max_uses if provided
    if let Some(max_uses) = input.max_uses {
        if max_uses < 1 {
            error!("Invalid max_uses: {} (must be >= 1)", max_uses);
            return Err((
                StatusCode::BAD_REQUEST,
                "max_uses must be >= 1 or null for unlimited".to_string(),
            ));
        }
    }

    // Step 5: Validate expiry is in the future
    if let Some(ref expires_at) = input.expires_at {
        if expires_at < &chrono::Utc::now() {
            warn!("Invite expires_at is in the past");
            return Err((
                StatusCode::BAD_REQUEST,
                "expires_at must be in the future".to_string(),
            ));
        }
    }

    // Step 6: Create invite in database
    let invite_id = uuid::Uuid::new_v4().to_string();

    let invite = sqlx::query_as::<_, InviteView>(
        r#"
        INSERT INTO invites (
            id, convo_id, created_by_did, target_did,
            psk_hash, expires_at, max_uses, uses_count, revoked
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, 0, false)
        RETURNING
            id, convo_id, created_by_did, target_did,
            created_at, expires_at, max_uses, uses_count, revoked
        "#,
    )
    .bind(&invite_id)
    .bind(&input.convo_id)
    .bind(caller_did)
    .bind(&input.target_did)
    .bind(&input.psk_hash)
    .bind(&input.expires_at)
    .bind(&input.max_uses)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Database error creating invite: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create invite".to_string(),
        )
    })?;

    info!(
        invite_id = %invite_id,
        convo_id = %input.convo_id,
        "Invite created successfully"
    );

    Ok(Json(CreateInviteOutput {
        invite_id,
        success: true,
        invite,
    }))
}

/// Revoke an invite (admin only)
///
/// Authorization: Caller must be an admin of the conversation
///
/// Request body:
/// ```json
/// {
///   "inviteId": "uuid"
/// }
/// ```
pub async fn revoke_invite(
    State(pool): State<PgPool>,
    auth_user: AuthUser,
    Json(input): Json<RevokeInviteInput>,
) -> Result<Json<RevokeInviteOutput>, (StatusCode, String)> {
    let caller_did = &auth_user.did;

    info!(
        invite_id = %input.invite_id,
        caller = %caller_did,
        "Admin revoking invite"
    );

    // Step 1: Get conversation ID from invite (and verify it exists)
    let convo_id = sqlx::query_scalar::<_, String>("SELECT convo_id FROM invites WHERE id = $1")
        .bind(&input.invite_id)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            error!("Database error fetching invite: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?
        .ok_or_else(|| {
            warn!("Invite not found: {}", input.invite_id);
            (StatusCode::NOT_FOUND, "Invite not found".to_string())
        })?;

    // Step 2: Verify caller is an admin of this conversation
    verify_is_admin(&pool, &convo_id, caller_did)
        .await
        .map_err(|e| {
            error!("Admin verification failed: {}", e);
            (StatusCode::FORBIDDEN, "Not an admin".to_string())
        })?;

    // Step 3: Revoke the invite
    let rows_affected = sqlx::query(
        r#"
        UPDATE invites
        SET revoked = true,
            revoked_at = NOW(),
            revoked_by_did = $1
        WHERE id = $2
          AND revoked = false  -- Only revoke if not already revoked
        "#,
    )
    .bind(caller_did)
    .bind(&input.invite_id)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Database error revoking invite: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to revoke invite".to_string(),
        )
    })?
    .rows_affected();

    if rows_affected == 0 {
        warn!("Invite already revoked or not found: {}", input.invite_id);
        return Err((
            StatusCode::NOT_FOUND,
            "Invite already revoked or not found".to_string(),
        ));
    }

    info!(
        invite_id = %input.invite_id,
        convo_id = %convo_id,
        "Invite revoked successfully"
    );

    Ok(Json(RevokeInviteOutput { success: true }))
}

/// List invites for a conversation (admin only)
///
/// Authorization: Caller must be an admin of the conversation
///
/// Query params:
/// - `convoId`: Conversation ID
/// - `includeRevoked`: Include revoked invites (default false)
pub async fn list_invites(
    State(pool): State<PgPool>,
    auth_user: AuthUser,
    Query(input): Query<ListInvitesInput>,
) -> Result<Json<ListInvitesOutput>, (StatusCode, String)> {
    let caller_did = &auth_user.did;

    // Verify caller is an admin
    verify_is_admin(&pool, &input.convo_id, caller_did)
        .await
        .map_err(|e| {
            error!("Admin verification failed: {}", e);
            (StatusCode::FORBIDDEN, "Not an admin".to_string())
        })?;

    // Fetch invites
    let query = if input.include_revoked {
        r#"
        SELECT
            id, convo_id, created_by_did, target_did,
            created_at, expires_at, max_uses, uses_count, revoked
        FROM invites
        WHERE convo_id = $1
        ORDER BY created_at DESC
        "#
    } else {
        r#"
        SELECT
            id, convo_id, created_by_did, target_did,
            created_at, expires_at, max_uses, uses_count, revoked
        FROM invites
        WHERE convo_id = $1
          AND revoked = false
        ORDER BY created_at DESC
        "#
    };

    let invites = sqlx::query_as::<_, InviteView>(query)
        .bind(&input.convo_id)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("Database error fetching invites: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to fetch invites".to_string(),
            )
        })?;

    Ok(Json(ListInvitesOutput { invites }))
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Check if an invite is currently valid (not expired, not revoked, has remaining uses)
pub async fn is_invite_valid(
    pool: &PgPool,
    psk_hash: &str,
    target_did: Option<&str>,
) -> Result<Option<String>, Error> {
    let invite_id = sqlx::query_scalar::<_, String>(
        r#"
        SELECT id
        FROM invites
        WHERE psk_hash = $1
          AND revoked = false
          AND (expires_at IS NULL OR expires_at > NOW())
          AND (max_uses IS NULL OR uses_count < max_uses)
          AND ($2::TEXT IS NULL OR target_did IS NULL OR target_did = $2)
        LIMIT 1
        "#,
    )
    .bind(psk_hash)
    .bind(target_did)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!("Database error checking invite validity: {}", e);
        Error::DatabaseError(e.to_string())
    })?;

    Ok(invite_id)
}

/// Increment invite uses count
pub async fn increment_invite_uses(pool: &PgPool, invite_id: &str) -> Result<(), Error> {
    sqlx::query(
        r#"
        UPDATE invites
        SET uses_count = uses_count + 1
        WHERE id = $1
        "#,
    )
    .bind(invite_id)
    .execute(pool)
    .await
    .map_err(|e| {
        error!("Database error incrementing invite uses: {}", e);
        Error::DatabaseError(e.to_string())
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psk_hash_validation() {
        // Valid SHA256 hex
        let valid_hash = "a".repeat(64);
        assert_eq!(valid_hash.len(), 64);
        assert!(valid_hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Invalid: too short
        let short_hash = "a".repeat(63);
        assert_eq!(short_hash.len(), 63);

        // Invalid: contains non-hex
        let mut invalid_hash = String::from("z");
        invalid_hash.push_str(&"a".repeat(63));
        assert!(!invalid_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_did_validation() {
        assert!("did:plc:abc123".starts_with("did:"));
        assert!("did:web:example.com".starts_with("did:"));
        assert!(!"invalid-did".starts_with("did:"));
    }
}
