use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::{error, warn};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    device_utils::{bucket_device_id, parse_device_did},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.reconcileKeyPackages";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconcileKeyPackagesRequest {
    pub device_id: Option<String>,
    pub device_did: Option<String>,
    #[serde(default)]
    pub local_hashes: Vec<String>,
    pub schema_version: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconcileKeyPackagesOutput {
    pub server_only: Vec<String>,
    pub local_only: Vec<String>,
    pub total: i64,
    pub device_verified: bool,
}

pub fn reconcile_hashes(
    server_hashes: &[String],
    local_hashes: &[String],
) -> (Vec<String>, Vec<String>, bool) {
    let server: HashSet<&str> = server_hashes.iter().map(String::as_str).collect();
    let local: HashSet<&str> = local_hashes.iter().map(String::as_str).collect();

    let mut server_only: Vec<String> = server
        .difference(&local)
        .map(|hash| (*hash).to_string())
        .collect();
    let mut local_only: Vec<String> = local
        .difference(&server)
        .map(|hash| (*hash).to_string())
        .collect();
    server_only.sort();
    local_only.sort();

    let device_verified = server_only.is_empty() && local_only.is_empty();
    (server_only, local_only, device_verified)
}

pub fn merge_reconcile_server_hashes(
    available_hashes: &[String],
    pending_welcome_hashes: &[String],
) -> Vec<String> {
    let mut merged: Vec<String> = available_hashes
        .iter()
        .chain(pending_welcome_hashes.iter())
        .cloned()
        .collect();
    merged.sort();
    merged.dedup();
    merged
}

fn authorize_device(auth_did: &str, device_did: &str) -> Result<(String, String), StatusCode> {
    let (auth_owner_did, _) = parse_device_did(auth_did).map_err(|e| {
        warn!("reconcileKeyPackages: invalid auth DID: {}", e);
        StatusCode::BAD_REQUEST
    })?;
    let (owner_did, device_id) = parse_device_did(device_did).map_err(|e| {
        warn!("reconcileKeyPackages: invalid device DID: {}", e);
        StatusCode::BAD_REQUEST
    })?;
    if owner_did != auth_owner_did {
        warn!("reconcileKeyPackages: caller tried to reconcile another user's device");
        return Err(StatusCode::FORBIDDEN);
    }
    Ok((owner_did, device_id))
}

#[tracing::instrument(skip(pool, auth_user, input))]
pub async fn reconcile_key_packages(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<ReconcileKeyPackagesRequest>,
) -> Result<Json<ReconcileKeyPackagesOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if input.schema_version.unwrap_or(2) != 2 {
        warn!("reconcileKeyPackages: unsupported schemaVersion");
        return Err(StatusCode::BAD_REQUEST);
    }

    let device_did = input
        .device_did
        .clone()
        .unwrap_or_else(|| auth_user.did.clone());
    let (owner_did, parsed_device_id) = authorize_device(&auth_user.did, &device_did)?;
    let raw_device_id = match (input.device_id, parsed_device_id.as_str()) {
        (Some(device_id), parsed) if !parsed.is_empty() && device_id != parsed => {
            warn!("reconcileKeyPackages: deviceId does not match deviceDid fragment");
            return Err(StatusCode::BAD_REQUEST);
        }
        (Some(device_id), _) => device_id,
        (None, parsed) => parsed.to_string(),
    };
    if raw_device_id.trim().is_empty() {
        warn!("reconcileKeyPackages: missing deviceId");
        return Err(StatusCode::BAD_REQUEST);
    }
    let bucketed_device_id = bucket_device_id(&owner_did, &raw_device_id);

    let available_hashes: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT key_package_hash
        FROM key_packages
        WHERE owner_did = $1
          AND (device_id = $2 OR device_id = $3 OR device_id IS NULL)
          AND consumed_at IS NULL
          AND expires_at > NOW()
          AND (state IS NULL OR state = 'available')
          AND dead_at IS NULL
        ORDER BY key_package_hash
        "#,
    )
    .bind(&owner_did)
    .bind(&bucketed_device_id)
    .bind(&raw_device_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("reconcileKeyPackages: failed to fetch server hashes: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let pending_welcome_hashes: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT DISTINCT encode(wm.key_package_hash, 'hex')
        FROM welcome_messages wm
        JOIN key_packages kp
          ON kp.owner_did = $1
         AND kp.key_package_hash = encode(wm.key_package_hash, 'hex')
        WHERE (wm.recipient_did = $1 OR wm.recipient_did = $4)
          AND wm.consumed = false
          AND wm.key_package_hash IS NOT NULL
          AND (kp.device_id = $2 OR kp.device_id = $3 OR kp.device_id IS NULL)
          AND kp.dead_at IS NULL
        ORDER BY encode(wm.key_package_hash, 'hex')
        "#,
    )
    .bind(&owner_did)
    .bind(&bucketed_device_id)
    .bind(&raw_device_id)
    .bind(&device_did)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(
            "reconcileKeyPackages: failed to fetch pending welcome hashes: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let server_hashes = merge_reconcile_server_hashes(&available_hashes, &pending_welcome_hashes);

    let (server_only, local_only, device_verified) =
        reconcile_hashes(&server_hashes, &input.local_hashes);
    let total = server_hashes.len() as i64;

    sqlx::query(
        r#"
        INSERT INTO key_package_audit
            (id, action, owner_did, device_did, device_id, server_only_count,
             local_only_count, total, device_verified, actor_did, created_at)
        VALUES ($1, 'reconcile', $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&owner_did)
    .bind(&device_did)
    .bind(&bucketed_device_id)
    .bind(server_only.len() as i32)
    .bind(local_only.len() as i32)
    .bind(total as i32)
    .bind(device_verified)
    .bind(&auth_user.did)
    .bind(Utc::now())
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("reconcileKeyPackages: failed to write audit row: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(ReconcileKeyPackagesOutput {
        server_only,
        local_only,
        total,
        device_verified,
    }))
}

#[cfg(test)]
mod tests {
    use super::{merge_reconcile_server_hashes, reconcile_hashes};

    #[test]
    fn reconcile_hashes_returns_bidirectional_diff() {
        let server = vec!["b".to_string(), "a".to_string(), "c".to_string()];
        let local = vec!["b".to_string(), "d".to_string()];

        let (server_only, local_only, verified) = reconcile_hashes(&server, &local);

        assert_eq!(server_only, vec!["a", "c"]);
        assert_eq!(local_only, vec!["d"]);
        assert!(!verified);
    }

    #[test]
    fn reconcile_hashes_verifies_exact_match() {
        let server = vec!["a".to_string(), "b".to_string()];
        let local = vec!["b".to_string(), "a".to_string()];

        let (server_only, local_only, verified) = reconcile_hashes(&server, &local);

        assert!(server_only.is_empty());
        assert!(local_only.is_empty());
        assert!(verified);
    }

    #[test]
    fn pending_welcome_hashes_are_reconcile_known_hashes() {
        let available = vec!["available-hash".to_string()];
        let pending_welcome = vec!["consumed-welcome-hash".to_string()];
        let server = merge_reconcile_server_hashes(&available, &pending_welcome);
        let local = vec![
            "available-hash".to_string(),
            "consumed-welcome-hash".to_string(),
        ];

        let (_server_only, local_only, verified) = reconcile_hashes(&server, &local);

        assert!(
            local_only.is_empty(),
            "a key package with an unconsumed Welcome must not be reported local-only"
        );
        assert!(verified);
    }
}
