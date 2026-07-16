use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use jacquard_axum::ExtractXrpc;
use sqlx::Row;
use tracing::{error, info};

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    generated::blue_catbird::mlsChat::get_pending_devices::{
        GetPendingDevicesOutput, GetPendingDevicesRequest, PendingDeviceAddition,
    },
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
) -> Result<Json<GetPendingDevicesOutput>, StatusCode> {
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

    // Age out stale pending additions older than 1 hour.
    // These are unlikely to ever be processed -- the device has either
    // self-joined via External Commit or gone offline permanently.
    let aged_out = sqlx::query(
        r#"
        UPDATE pending_device_additions
        SET status = 'failed', updated_at = NOW()
        WHERE status IN ('pending', 'in_progress')
          AND created_at < $1 - INTERVAL '1 hour'
        "#,
    )
    .bind(now)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Failed to age out stale pending additions: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .rows_affected();

    if aged_out > 0 {
        info!(
            "Aged out {} stale pending additions (>1 hour old)",
            aged_out
        );
    }

    // Release expired claims (for additions that are still fresh)
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

    let pending_additions: Vec<PendingDeviceAddition> = rows
        .into_iter()
        .map(|r| PendingDeviceAddition {
            convo_id: r.get::<String, _>("convo_id").into(),
            device_id: r.get::<String, _>("device_id").into(),
            created_at: crate::sqlx_jacquard::chrono_to_datetime(
                r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            ),
            welcome: None,
            extra_data: Default::default(),
        })
        .collect();

    Ok(Json(GetPendingDevicesOutput {
        pending_additions,
        extra_data: Default::default(),
    }))
}
