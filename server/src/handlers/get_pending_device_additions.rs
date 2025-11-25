use axum::{extract::{Query, State}, http::StatusCode, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::{auth::AuthUser, device_utils::parse_device_did, storage::DbPool};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPendingDeviceAdditionsInput {
    #[serde(default)]
    convo_ids: Option<Vec<String>>,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingDeviceAddition {
    id: String,
    convo_id: String,
    user_did: String,
    device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_name: Option<String>,
    device_credential_did: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    claimed_by: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPendingDeviceAdditionsOutput {
    pending_additions: Vec<PendingDeviceAddition>,
}

/// Get pending device additions for conversations
/// GET /xrpc/blue.catbird.mls.getPendingDeviceAdditions
#[tracing::instrument(skip(pool))]
pub async fn get_pending_device_additions(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(input): Query<GetPendingDeviceAdditionsInput>,
) -> Result<Json<GetPendingDeviceAdditionsOutput>, StatusCode> {
    if let Err(_e) =
        crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.getPendingDeviceAdditions")
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Extract user DID from potentially device-qualified DID
    let (user_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
        error!("Invalid DID format: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let limit = input.limit.clamp(1, 100);
    let now = Utc::now();

    info!(
        user = %crate::crypto::redact_for_log(&user_did),
        limit = limit,
        "Getting pending device additions"
    );

    // First, release any expired claims (60 second timeout)
    let released = sqlx::query!(
        r#"
        UPDATE pending_device_additions
        SET status = 'pending',
            claimed_by_did = NULL,
            claimed_at = NULL,
            claim_expires_at = NULL,
            updated_at = NOW()
        WHERE status = 'in_progress'
          AND claim_expires_at < $1
        "#,
        now
    )
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Failed to release expired claims: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .rows_affected();

    if released > 0 {
        info!("Released {} expired pending addition claims", released);
    }

    // Query pending additions for conversations where caller is a member
    // Exclude the caller's own devices (they shouldn't add themselves)
    let pending_additions = if let Some(ref convo_ids) = input.convo_ids {
        // Filter by specific conversations
        sqlx::query_as!(
            PendingDeviceAdditionRow,
            r#"
            SELECT
                pda.id,
                pda.convo_id,
                pda.user_did,
                pda.new_device_id as device_id,
                pda.device_name,
                pda.new_device_credential_did as device_credential_did,
                pda.status,
                pda.claimed_by_did as claimed_by,
                pda.created_at
            FROM pending_device_additions pda
            INNER JOIN members m ON pda.convo_id = m.convo_id
            WHERE m.user_did = $1
              AND m.left_at IS NULL
              AND pda.convo_id = ANY($2)
              AND pda.status IN ('pending', 'in_progress')
              AND pda.user_did != $1
            ORDER BY pda.created_at ASC
            LIMIT $3
            "#,
            &user_did,
            convo_ids,
            limit
        )
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch pending additions: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    } else {
        // All conversations
        sqlx::query_as!(
            PendingDeviceAdditionRow,
            r#"
            SELECT
                pda.id,
                pda.convo_id,
                pda.user_did,
                pda.new_device_id as device_id,
                pda.device_name,
                pda.new_device_credential_did as device_credential_did,
                pda.status,
                pda.claimed_by_did as claimed_by,
                pda.created_at
            FROM pending_device_additions pda
            INNER JOIN members m ON pda.convo_id = m.convo_id
            WHERE m.user_did = $1
              AND m.left_at IS NULL
              AND pda.status IN ('pending', 'in_progress')
              AND pda.user_did != $1
            ORDER BY pda.created_at ASC
            LIMIT $2
            "#,
            &user_did,
            limit
        )
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch pending additions: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    };

    info!(
        "Found {} pending device additions for user",
        pending_additions.len()
    );

    let output = GetPendingDeviceAdditionsOutput {
        pending_additions: pending_additions
            .into_iter()
            .map(|row| PendingDeviceAddition {
                id: row.id,
                convo_id: row.convo_id,
                user_did: row.user_did,
                device_id: row.device_id,
                device_name: row.device_name,
                device_credential_did: row.device_credential_did,
                status: row.status,
                claimed_by: row.claimed_by,
                created_at: row.created_at,
            })
            .collect(),
    };

    Ok(Json(output))
}

// Internal row type for sqlx query
#[derive(Debug)]
struct PendingDeviceAdditionRow {
    id: String,
    convo_id: String,
    user_did: String,
    device_id: String,
    device_name: Option<String>,
    device_credential_did: String,
    status: String,
    claimed_by: Option<String>,
    created_at: DateTime<Utc>,
}
