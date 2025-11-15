use axum::{extract::{Query, State}, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    storage::DbPool,
};

#[derive(Debug, Deserialize)]
pub struct GetExpectedConversationsParams {
    #[serde(rename = "deviceId")]
    pub device_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GetExpectedConversationsOutput {
    pub conversations: Vec<ExpectedConversation>,
}

#[derive(Debug, Serialize)]
pub struct ExpectedConversation {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    pub name: String,
    #[serde(rename = "memberCount")]
    pub member_count: i64,
    #[serde(rename = "shouldBeInGroup")]
    pub should_be_in_group: bool,
    #[serde(rename = "lastActivity", skip_serializing_if = "Option::is_none")]
    pub last_activity: Option<String>,
    #[serde(rename = "needsRejoin")]
    pub needs_rejoin: bool,
    #[serde(rename = "deviceInGroup")]
    pub device_in_group: bool,
}

/// Get list of conversations user should be in but may be missing locally
/// GET /xrpc/blue.catbird.mls.getExpectedConversations
#[tracing::instrument(skip(pool))]
pub async fn get_expected_conversations(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(params): Query<GetExpectedConversationsParams>,
) -> Result<Json<GetExpectedConversationsOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.getExpectedConversations") {
        error!("Unauthorized - failed auth check");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user_did = &auth_user.did;

    // Extract device_id from auth token or use provided parameter
    let device_id = params.device_id.as_ref().or_else(|| {
        // Try to extract device_id from user_did if it has format did:plc:user#device-uuid
        if user_did.contains('#') {
            user_did.split('#').nth(1)
        } else {
            None
        }
    });

    info!(
        user_did = %user_did,
        device_id = ?device_id,
        "Fetching expected conversations"
    );

    // Get base user DID (strip device suffix if present)
    let base_user_did = if user_did.contains('#') {
        user_did.split('#').next().unwrap_or(user_did)
    } else {
        user_did.as_str()
    };

    // Query all conversations where user is a member (not left)
    // For each conversation, check if the specific device is in the members table
    let conversations = sqlx::query_as::<_, (
        String,                                      // convo_id
        String,                                      // name
        i64,                                         // member_count
        Option<chrono::DateTime<chrono::Utc>>,      // last_activity
        bool,                                        // needs_rejoin
        Option<String>,                              // device_id from members
    )>(
        r#"
        SELECT
            c.id as convo_id,
            COALESCE(c.name, 'Unnamed Conversation') as name,
            (SELECT COUNT(*) FROM members m2 WHERE m2.convo_id = c.id AND m2.left_at IS NULL) as member_count,
            (SELECT MAX(created_at) FROM messages WHERE convo_id = c.id) as last_activity,
            m.needs_rejoin,
            m.device_id
        FROM conversations c
        INNER JOIN members m ON c.id = m.convo_id
        WHERE m.member_did = $1
          AND m.left_at IS NULL
        ORDER BY c.updated_at DESC
        "#,
    )
    .bind(base_user_did)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("Failed to fetch expected conversations: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Build response
    let mut result = Vec::new();
    for (convo_id, name, member_count, last_activity, needs_rejoin, member_device_id) in conversations {
        // Determine if this device should be in the group
        let device_in_group = if let Some(ref target_device) = device_id {
            // Check if the specific device is in the members table
            member_device_id.as_ref() == Some(target_device)
        } else {
            // No device_id specified - assume user is asking about their current device
            // If member has device_id set, then device is in group
            member_device_id.is_some()
        };

        // User should be in group if they're an active member but device isn't in group
        let should_be_in_group = !device_in_group && !needs_rejoin;

        result.push(ExpectedConversation {
            convo_id,
            name,
            member_count,
            should_be_in_group,
            last_activity: last_activity.map(|dt| dt.to_rfc3339()),
            needs_rejoin,
            device_in_group,
        });
    }

    info!(
        user_did = %user_did,
        conversation_count = result.len(),
        missing_count = result.iter().filter(|c| c.should_be_in_group).count(),
        "Fetched expected conversations"
    );

    Ok(Json(GetExpectedConversationsOutput {
        conversations: result,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_expected_conversations() {
        // Test would require database setup
        // Integration tests should cover this endpoint
    }
}
