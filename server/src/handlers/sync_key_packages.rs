use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::{error, info, warn};

use crate::{auth::AuthUser, storage::DbPool};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncKeyPackagesInput {
    /// SHA256 hex hashes of key packages in local storage (have private keys)
    local_hashes: Vec<String>,
    /// Device ID to scope the sync (REQUIRED for multi-device support)
    /// Each device must sync only its own key packages to prevent cross-device interference
    device_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncKeyPackagesOutput {
    /// Hashes of available key packages on server AFTER cleanup
    server_hashes: Vec<String>,
    /// Number of orphaned packages detected
    orphaned_count: i64,
    /// Number of orphaned packages deleted
    deleted_count: i64,
    /// Hashes of deleted orphaned packages (for debugging)
    orphaned_hashes: Vec<String>,
    /// Remaining valid packages after cleanup
    remaining_available: i64,
    /// Device ID that was synced (echoed back for confirmation)
    device_id: String,
}

/// Synchronize key packages between client and server
///
/// This endpoint prevents NoMatchingKeyPackage errors by:
/// 1. Getting all available (unconsumed) key package hashes from server for this device
/// 2. Comparing against local hashes provided by client
/// 3. Deleting any server-side packages that don't have local private keys
///
/// MULTI-DEVICE SUPPORT:
/// device_id is REQUIRED. Only syncs key packages belonging to that specific device.
/// This prevents Device A from accidentally deleting Device B's packages.
///
/// POST /xrpc/blue.catbird.mls.syncKeyPackages
#[tracing::instrument(skip(pool))]
pub async fn sync_key_packages(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<SyncKeyPackagesInput>,
) -> Result<Json<SyncKeyPackagesOutput>, StatusCode> {
    if let Err(_e) =
        crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.syncKeyPackages")
    {
        warn!("Unauthorized access attempt for syncKeyPackages");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user_did = &auth_user.did;
    let device_id = &input.device_id;

    // Validate device_id is not empty
    if device_id.trim().is_empty() {
        warn!("Empty device_id provided for syncKeyPackages");
        return Err(StatusCode::BAD_REQUEST);
    }

    info!(
        "🔄 [syncKeyPackages] START - user has {} local hashes, device_id: {}",
        input.local_hashes.len(),
        device_id
    );

    // Get available key package hashes from server for this specific device
    let server_hashes =
        match crate::db::get_available_key_package_hashes_for_device(&pool, user_did, device_id)
            .await
        {
            Ok(hashes) => hashes,
            Err(e) => {
                error!(
                    "Failed to get server key package hashes for device {}: {}",
                    device_id, e
                );
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

    info!(
        "📊 [syncKeyPackages] Server has {} available key packages for device {}",
        server_hashes.len(),
        device_id
    );

    // Convert local hashes to a set for efficient lookup
    let local_hash_set: HashSet<&String> = input.local_hashes.iter().collect();

    // Find orphaned packages: on server but NOT in local storage
    let orphaned_hashes: Vec<String> = server_hashes
        .iter()
        .filter(|hash| !local_hash_set.contains(hash))
        .cloned()
        .collect();

    let orphaned_count = orphaned_hashes.len() as i64;

    if orphaned_count == 0 {
        info!(
            "✅ [syncKeyPackages] No orphaned key packages found - all synced for device {}",
            device_id
        );
        let remaining_available = server_hashes.len() as i64;
        return Ok(Json(SyncKeyPackagesOutput {
            server_hashes,
            orphaned_count: 0,
            deleted_count: 0,
            orphaned_hashes: vec![],
            remaining_available,
            device_id: input.device_id,
        }));
    }

    // Log orphaned hashes for debugging
    warn!(
        "⚠️ [syncKeyPackages] Found {} ORPHANED key packages for device {} (on server but not in local storage)",
        orphaned_count, device_id
    );
    for (i, hash) in orphaned_hashes.iter().enumerate().take(5) {
        warn!("   [{}] {}", i, &hash[..16.min(hash.len())]);
    }
    if orphaned_count > 5 {
        warn!("   ... and {} more", orphaned_count - 5);
    }

    // Delete orphaned packages from server (scoped to this device)
    let deleted_count = match crate::db::delete_key_packages_by_hashes_for_device(
        &pool,
        user_did,
        device_id,
        &orphaned_hashes,
    )
    .await
    {
        Ok(count) => count as i64,
        Err(e) => {
            error!(
                "Failed to delete orphaned key packages for device {}: {}",
                device_id, e
            );
            let remaining_available = server_hashes.len() as i64;
            return Ok(Json(SyncKeyPackagesOutput {
                server_hashes,
                orphaned_count,
                deleted_count: 0,
                orphaned_hashes,
                remaining_available,
                device_id: input.device_id,
            }));
        }
    };

    info!(
        "🗑️ [syncKeyPackages] Deleted {} orphaned key packages from server for device {}",
        deleted_count, device_id
    );

    // Get updated server hashes after cleanup
    let remaining_hashes =
        match crate::db::get_available_key_package_hashes_for_device(&pool, user_did, device_id)
            .await
        {
            Ok(hashes) => hashes,
            Err(e) => {
                warn!("Failed to get updated hashes after cleanup: {}", e);
                // Return with previous data minus deleted
                let remaining: Vec<String> = server_hashes
                    .iter()
                    .filter(|h| !orphaned_hashes.contains(h))
                    .cloned()
                    .collect();
                return Ok(Json(SyncKeyPackagesOutput {
                    server_hashes: remaining.clone(),
                    orphaned_count,
                    deleted_count,
                    orphaned_hashes,
                    remaining_available: remaining.len() as i64,
                    device_id: input.device_id,
                }));
            }
        };

    let remaining_available = remaining_hashes.len() as i64;

    info!(
        "✅ [syncKeyPackages] COMPLETE for device {} - deleted {} orphaned, {} remaining",
        device_id, deleted_count, remaining_available
    );

    Ok(Json(SyncKeyPackagesOutput {
        server_hashes: remaining_hashes,
        orphaned_count,
        deleted_count,
        orphaned_hashes,
        remaining_available,
        device_id: input.device_id,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orphan_detection() {
        let server_hashes = vec![
            "a054f1dbb72523ed".to_string(),
            "756c1234567890ab".to_string(),
            "e37e9876543210cd".to_string(),
        ];

        let local_hashes = vec![
            "756c1234567890ab".to_string(),
            "e37e9876543210cd".to_string(),
        ];

        let local_hash_set: HashSet<&String> = local_hashes.iter().collect();

        let orphaned: Vec<String> = server_hashes
            .iter()
            .filter(|hash| !local_hash_set.contains(hash))
            .cloned()
            .collect();

        assert_eq!(orphaned.len(), 1);
        assert_eq!(orphaned[0], "a054f1dbb72523ed");
    }
}
