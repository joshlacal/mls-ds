// =============================================================================
// Automatic Rejoin System
// =============================================================================
// Orchestrates MLS group rejoin when users delete app and reinstall
//
// Flow:
// 1. Client detects: identity in iCloud Keychain but no local MLS state
// 2. Client calls markNeedsRejoin()
// 3. Server sets needs_rejoin = true in members table
// 4. Server asks ANY online member to generate Welcome
// 5. Online member posts Welcome via deliverWelcome()
// 6. Client polls getWelcome() and receives Welcome in 2-5 seconds
// 7. Client processes Welcome and rejoins group
//
// No admin approval needed - server DB is source of truth for membership
// =============================================================================

use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{error, info};
use crate::{
    auth::AuthUser,
    error::{Error, Result},
    models::WelcomeMessage,
};

// =============================================================================
// Request/Response Models
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarkNeedsRejoinInput {
    /// Conversation ID where member needs rejoin
    pub convo_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MarkNeedsRejoinOutput {
    /// Success confirmation
    pub success: bool,
    /// Message for client
    pub message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverWelcomeInput {
    /// Conversation ID
    pub convo_id: String,
    /// Target DID (member who needs rejoin)
    pub target_did: String,
    /// MLS Welcome message bytes
    pub welcome: Vec<u8>,
    /// MLS Commit message bytes
    pub commit: Vec<u8>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverWelcomeOutput {
    /// Created Welcome message ID
    pub welcome_id: String,
    /// Success confirmation
    pub success: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetWelcomeInput {
    /// Conversation ID
    pub convo_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetWelcomeOutput {
    /// Welcome message if available
    pub welcome: Option<WelcomeMessage>,
}

// =============================================================================
// Handler: Mark Member as Needing Rejoin
// =============================================================================

/// Mark authenticated user as needing rejoin in a conversation
/// Client calls this after detecting identity in iCloud but no local MLS state
///
/// Authorization: User must be a member (based on server DB, not MLS state)
/// Auto-approval: Automatically approves if user was active member within 30 days
pub async fn mark_needs_rejoin(
    State(pool): State<PgPool>,
    auth_user: AuthUser,
    Json(input): Json<MarkNeedsRejoinInput>,
) -> Result<Json<MarkNeedsRejoinOutput>> {
    let did = &auth_user.did;

    info!(
        convo_id = %input.convo_id,
        did = %did,
        "Member requesting rejoin"
    );

    // 1. Verify user is a member and check eligibility for auto-rejoin
    let member_info = sqlx::query_as::<_, (bool, Option<chrono::DateTime<chrono::Utc>>, Option<chrono::DateTime<chrono::Utc>>)>(
        r#"
        SELECT
            (left_at IS NULL) as is_active_member,
            last_seen_at,
            left_at
        FROM members
        WHERE convo_id = $1 AND member_did = $2
        "#,
    )
    .bind(&input.convo_id)
    .bind(did)
    .fetch_optional(&pool)
    .await?;

    let (is_active_member, last_seen_at, left_at) = match member_info {
        Some(info) => info,
        None => return Err(Error::NotMember),
    };

    // Check if member left voluntarily
    if !is_active_member && left_at.is_some() {
        error!(
            convo_id = %input.convo_id,
            did = %did,
            "User voluntarily left conversation - rejoin not allowed"
        );
        return Err(Error::BadRequest("Cannot rejoin a conversation you left".to_string()));
    }

    // Check if device was last seen within 30 days (for auto-approval)
    let auto_approve = if let Some(last_seen) = last_seen_at {
        let days_since_seen = (chrono::Utc::now() - last_seen).num_days();
        days_since_seen <= 30
    } else {
        // No last_seen_at means this is a new rejoin request - approve it
        true
    };

    // TODO: Check security flags on account
    // let security_flags = check_security_flags(&pool, did).await?;
    // auto_approve = auto_approve && !security_flags.has_violations;

    // 2. Mark member as needing rejoin with auto-approval status
    sqlx::query(
        r#"
        UPDATE members
        SET needs_rejoin = true,
            rejoin_requested_at = NOW(),
            rejoin_auto_approved = $3
        WHERE convo_id = $1 AND member_did = $2
        "#,
    )
    .bind(&input.convo_id)
    .bind(did)
    .bind(auto_approve)
    .execute(&pool)
    .await?;

    // 3. Log audit entry for rejoin request
    log_rejoin_audit(
        &pool,
        &input.convo_id,
        did,
        auto_approve,
        if auto_approve {
            "Auto-approved: Active member within 30 days"
        } else {
            "Pending manual approval: Device inactive > 30 days"
        }
    ).await?;

    // 4. Notify online members via SSE to generate Welcome
    // (In production, this would broadcast to SSE connections)
    broadcast_rejoin_request(&pool, &input.convo_id, did).await?;

    let message = if auto_approve {
        "Rejoin approved automatically. An online member will deliver your Welcome message shortly."
    } else {
        "Rejoin request pending approval (device inactive > 30 days). Please contact an admin."
    };

    Ok(Json(MarkNeedsRejoinOutput {
        success: true,
        message: message.to_string(),
    }))
}

// =============================================================================
// Handler: Deliver Welcome for Rejoining Member
// =============================================================================

/// Online member delivers Welcome message for rejoining peer
/// Called by any current member who receives rejoin notification
///
/// Authorization: Sender must be an active member
pub async fn deliver_welcome(
    State(pool): State<PgPool>,
    auth_user: AuthUser,
    Json(input): Json<DeliverWelcomeInput>,
) -> Result<Json<DeliverWelcomeOutput>> {
    let helper_did = &auth_user.did;

    info!(
        convo_id = %input.convo_id,
        target_did = %input.target_did,
        helper_did = %helper_did,
        "Member delivering Welcome for rejoin"
    );

    // 1. Verify helper is an active member
    let is_member = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM members
            WHERE convo_id = $1 AND member_did = $2 AND left_at IS NULL
        )
        "#,
    )
    .bind(&input.convo_id)
    .bind(helper_did)
    .fetch_one(&pool)
    .await?;

    if !is_member {
        return Err(Error::NotMember);
    }

    // 2. Verify target actually needs rejoin and is auto-approved
    let rejoin_status = sqlx::query_as::<_, (bool, Option<bool>)>(
        r#"
        SELECT needs_rejoin, rejoin_auto_approved
        FROM members
        WHERE convo_id = $1 AND member_did = $2
        "#,
    )
    .bind(&input.convo_id)
    .bind(&input.target_did)
    .fetch_optional(&pool)
    .await?;

    let (needs_rejoin, auto_approved) = match rejoin_status {
        Some((needs, approved)) => (needs, approved),
        None => return Err(Error::BadRequest(
            "Target member not found in conversation".to_string(),
        )),
    };

    if !needs_rejoin {
        return Err(Error::BadRequest(
            "Target member does not need rejoin".to_string(),
        ));
    }

    // Only allow Welcome delivery for auto-approved rejoins
    if auto_approved != Some(true) {
        return Err(Error::BadRequest(
            "Target member rejoin is not auto-approved - requires manual admin approval".to_string(),
        ));
    }

    // 3. Store Welcome message for target
    let welcome_id = generate_id();

    sqlx::query(
        r#"
        INSERT INTO welcome_messages (
            id, convo_id, recipient_did, welcome_data,
            created_by_did, created_at, consumed
        )
        VALUES ($1, $2, $3, $4, $5, NOW(), false)
        ON CONFLICT (convo_id, recipient_did, COALESCE(key_package_hash, '\x00'::bytea))
        WHERE consumed = false
        DO UPDATE SET
            welcome_data = EXCLUDED.welcome_data,
            created_by_did = EXCLUDED.created_by_did,
            created_at = NOW()
        "#,
    )
    .bind(&welcome_id)
    .bind(&input.convo_id)
    .bind(&input.target_did)
    .bind(&input.welcome)
    .bind(helper_did)
    .execute(&pool)
    .await?;

    // 4. Store Commit message
    let commit_id = generate_id();
    sqlx::query(
        r#"
        INSERT INTO messages (
            id, convo_id, sender_did, message_type,
            epoch, seq, ciphertext, created_at
        )
        VALUES ($1, $2, $3, 'commit', 0, 0, $4, NOW())
        "#,
    )
    .bind(&commit_id)
    .bind(&input.convo_id)
    .bind(helper_did)
    .bind(&input.commit)
    .execute(&pool)
    .await?;

    // 5. Clear needs_rejoin flag (Welcome is ready)
    sqlx::query(
        r#"
        UPDATE members
        SET needs_rejoin = false
        WHERE convo_id = $1 AND member_did = $2
        "#,
    )
    .bind(&input.convo_id)
    .bind(&input.target_did)
    .execute(&pool)
    .await?;

    Ok(Json(DeliverWelcomeOutput {
        welcome_id,
        success: true,
    }))
}

// =============================================================================
// Handler: Get Welcome Message
// =============================================================================

/// Client polls for Welcome message after marking needs_rejoin
/// Typically receives Welcome within 2-5 seconds (from any online member)
///
/// Authorization: Authenticated user
pub async fn get_welcome(
    State(pool): State<PgPool>,
    auth_user: AuthUser,
    Json(input): Json<GetWelcomeInput>,
) -> Result<Json<GetWelcomeOutput>> {
    let did = &auth_user.did;

    // Fetch unconsumed Welcome for this member
    let welcome = sqlx::query_as::<_, WelcomeMessage>(
        r#"
        SELECT id, convo_id, recipient_did, welcome_data,
               key_package_hash, created_at, consumed, consumed_at
        FROM welcome_messages
        WHERE convo_id = $1
          AND recipient_did = $2
          AND consumed = false
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&input.convo_id)
    .bind(did)
    .fetch_optional(&pool)
    .await?;

    Ok(Json(GetWelcomeOutput { welcome }))
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Broadcast rejoin request to online members via SSE
async fn broadcast_rejoin_request(
    pool: &PgPool,
    convo_id: &str,
    target_did: &str,
) -> Result<()> {
    // Get all active members except the one needing rejoin
    let active_members = sqlx::query_scalar::<_, String>(
        r#"
        SELECT member_did
        FROM members
        WHERE convo_id = $1
          AND member_did != $2
          AND left_at IS NULL
        "#,
    )
    .bind(convo_id)
    .bind(target_did)
    .fetch_all(pool)
    .await?;

    info!(
        convo_id = %convo_id,
        target_did = %target_did,
        active_count = active_members.len(),
        "Broadcasting rejoin request to active members"
    );

    // TODO: Send SSE event to online members
    // In production, this would use the event_stream table or a pub/sub system
    // Event type: "member.needs_rejoin"
    // Payload: { "convo_id": "...", "target_did": "..." }

    Ok(())
}

/// Generate a unique ID (placeholder - use proper ID generation)
fn generate_id() -> String {
    use uuid::Uuid;
    Uuid::new_v4().to_string()
}

/// Log rejoin request to audit table for tracking and debugging
async fn log_rejoin_audit(
    pool: &PgPool,
    convo_id: &str,
    member_did: &str,
    auto_approved: bool,
    reason: &str,
) -> Result<()> {
    // Create rejoin_requests table if it doesn't exist (idempotent)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS rejoin_requests (
            id TEXT PRIMARY KEY,
            convo_id TEXT NOT NULL,
            member_did TEXT NOT NULL,
            auto_approved BOOLEAN NOT NULL,
            reason TEXT NOT NULL,
            requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index for audit queries
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_rejoin_requests_convo ON rejoin_requests(convo_id, requested_at DESC)"
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_rejoin_requests_member ON rejoin_requests(member_did, requested_at DESC)"
    )
    .execute(pool)
    .await?;

    // Insert audit log entry
    let request_id = generate_id();
    sqlx::query(
        r#"
        INSERT INTO rejoin_requests (id, convo_id, member_did, auto_approved, reason)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(&request_id)
    .bind(convo_id)
    .bind(member_did)
    .bind(auto_approved)
    .bind(reason)
    .execute(pool)
    .await?;

    info!(
        request_id = %request_id,
        convo_id = %convo_id,
        member_did = %member_did,
        auto_approved = auto_approved,
        reason = %reason,
        "Logged rejoin request to audit table"
    );

    Ok(())
}

// =============================================================================
// Background Task: Rejoin Timeout Cleanup
// =============================================================================

/// Cleanup stale rejoin requests (> 5 minutes)
/// Run this as a background task every minute
pub async fn cleanup_stale_rejoins(pool: &PgPool) -> Result<()> {
    let result = sqlx::query(
        r#"
        UPDATE members
        SET needs_rejoin = false
        WHERE needs_rejoin = true
          AND rejoin_requested_at < NOW() - INTERVAL '5 minutes'
        "#,
    )
    .execute(pool)
    .await?;

    if result.rows_affected() > 0 {
        info!(
            count = result.rows_affected(),
            "Cleaned up stale rejoin requests"
        );
    }

    Ok(())
}
