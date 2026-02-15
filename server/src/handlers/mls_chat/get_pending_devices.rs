use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use jacquard_axum::ExtractXrpc;
use sqlx::Row;
use tracing::{error, info};

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    generated::blue_catbird::mlsChat::get_pending_devices::GetPendingDevicesRequest,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getPendingDevices";

/// Get pending device additions for conversations.
/// GET /xrpc/blue.catbird.mlsChat.getPendingDevices
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_pending_devices(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<GetPendingDevicesRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let (user_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
        error!("Invalid DID format: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let limit = input.limit.unwrap_or(50).clamp(1, 100);
    let now = Utc::now();

    info!(
        user = %crate::crypto::redact_for_log(&user_did),
        limit = limit,
        "Getting pending device additions"
    );

    // Release expired claims
    let released = sqlx::query(
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
    )
    .bind(now)
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

    // Fetch pending additions
    let rows = if let Some(ref convo_ids) = input.convo_ids {
        let ids: Vec<String> = convo_ids.iter().map(|s| s.to_string()).collect();
        sqlx::query(
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
        )
        .bind(&user_did)
        .bind(&ids)
        .bind(limit)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch pending additions: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    } else {
        sqlx::query(
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
        )
        .bind(&user_did)
        .bind(limit)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch pending additions: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    };

    info!("Found {} pending device additions for user", rows.len());

    let pending_additions: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            let mut obj = serde_json::json!({
                "id": r.get::<String, _>("id"),
                "convoId": r.get::<String, _>("convo_id"),
                "userDid": r.get::<String, _>("user_did"),
                "newDeviceId": r.get::<String, _>("device_id"),
                "newDeviceCredentialDid": r.get::<String, _>("device_credential_did"),
                "status": r.get::<String, _>("status"),
                "createdAt": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
            });
            if let Some(name) = r.get::<Option<String>, _>("device_name") {
                obj["deviceName"] = serde_json::json!(name);
            }
            if let Some(claimed) = r.get::<Option<String>, _>("claimed_by") {
                obj["claimedBy"] = serde_json::json!(claimed);
            }
            obj
        })
        .collect();

    Ok(Json(serde_json::json!({ "pendingAdditions": pending_additions })))
}
