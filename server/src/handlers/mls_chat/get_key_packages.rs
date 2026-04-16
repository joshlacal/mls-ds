use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    block_sync::BlockSyncService,
    device_utils::parse_device_did,
    generated::blue_catbird::mlsChat::{
        get_key_packages::{GetKeyPackagesOutput, GetKeyPackagesRequest},
        KeyPackageRef,
    },
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getKeyPackages";

/// Fetch and consume key packages for the given DIDs.
/// Returns one key package per device (identified by hashed device_id bucket)
/// for each requested DID, so that all of a user's devices can be added to a group.
/// GET /xrpc/blue.catbird.mlsChat.getKeyPackages
///
/// Block filtering: any target DID that has a block edge with the caller
/// (in either direction) is silently removed from the request. This closes
/// the final enforcement gap identified in Phase 3 of
/// docs/superpowers/plans/2026-04-15-block-leave-shared-groups.md
/// (Tasks 3.1 + 3.2 guard commits; this guards the key-package query).
#[tracing::instrument(skip(pool, block_sync, auth_user))]
pub async fn get_key_packages(
    State(pool): State<DbPool>,
    State(block_sync): State<Arc<BlockSyncService>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<GetKeyPackagesRequest>,
) -> Result<Json<GetKeyPackagesOutput<'static>>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if input.dids.len() > 100 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // ── Block edge filter (PDS-first with bsky_blocks fallback) ───────
    // Silently drop any requested DID that has a block edge with the
    // caller in either direction. Mirrors the gate in addMembers /
    // external-commit but returns an empty result instead of a 4xx —
    // this is a query endpoint, not a commit.
    let caller_did_str = match parse_device_did(&auth_user.did) {
        Ok((user_did, _)) => user_did,
        Err(e) => {
            error!("getKeyPackages: invalid caller DID: {}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let requested_dids: Vec<String> = input.dids.iter().map(|d| d.to_string()).collect();

    let mut participants: Vec<String> = requested_dids.clone();
    participants.push(caller_did_str.clone());
    participants.sort();
    participants.dedup();

    let edges: Vec<(String, String)> = if participants.len() >= 2 {
        match block_sync.check_block_conflicts(&participants).await {
            Ok(e) => e,
            Err(e) => {
                warn!(
                    "getKeyPackages: PDS block check failed, falling back to local DB: {}",
                    e
                );
                match sqlx::query_as::<_, (String, String)>(
                    "SELECT user_did, target_did FROM bsky_blocks
                     WHERE (user_did = $1 AND target_did = ANY($2))
                        OR (target_did = $1 AND user_did = ANY($2))",
                )
                .bind(&caller_did_str)
                .bind(&requested_dids)
                .fetch_all(&pool)
                .await
                {
                    Ok(rows) => rows,
                    Err(db_err) => {
                        error!(
                            "getKeyPackages: block fallback DB query failed: {}",
                            db_err
                        );
                        return Err(StatusCode::INTERNAL_SERVER_ERROR);
                    }
                }
            }
        }
    } else {
        Vec::new()
    };

    // Any DID on either side of a block edge involving the caller is
    // filtered out of the target list.
    let blocked_from_caller: HashSet<String> = edges
        .iter()
        .filter_map(|(blocker, blocked)| {
            if blocker == &caller_did_str {
                Some(blocked.clone())
            } else if blocked == &caller_did_str {
                Some(blocker.clone())
            } else {
                None
            }
        })
        .collect();

    let filtered_dids: Vec<jacquard_common::types::string::Did<'static>> = input
        .dids
        .iter()
        .filter(|d| !blocked_from_caller.contains(&d.to_string()))
        .map(|d| crate::sqlx_jacquard::string_to_did(d.as_ref()))
        .collect();

    if !blocked_from_caller.is_empty() {
        info!(
            requested = input.dids.len(),
            filtered = blocked_from_caller.len(),
            "getKeyPackages: filtered blocked target DIDs"
        );
    }

    if filtered_dids.is_empty() {
        // Query, not a denial — return OK with empty results.
        return Ok(Json(GetKeyPackagesOutput {
            key_packages: Vec::new(),
            missing: None,
            extra_data: Default::default(),
        }));
    }

    let mut key_packages: Vec<KeyPackageRef<'static>> = Vec::new();
    let mut missing: Vec<String> = Vec::new();

    for did in &filtered_dids {
        // Claim one key package per distinct device_id bucket for this DID.
        // DISTINCT ON(device_id) picks the oldest available key package per device.
        // Devices without a device_id bucket get one package under NULL.
        let results = if let Some(ref cs) = input.cipher_suite {
            sqlx::query_as::<_, (String, String, String, Option<String>)>(
                "UPDATE key_packages SET consumed_at = NOW()
                 WHERE id IN (
                   SELECT DISTINCT ON (COALESCE(device_id, '')) id
                   FROM key_packages
                   WHERE owner_did = $1 AND consumed_at IS NULL AND expires_at > NOW()
                     AND (reserved_at IS NULL OR reserved_at < NOW() - INTERVAL '5 minutes')
                     AND cipher_suite = $2
                   ORDER BY COALESCE(device_id, ''), created_at ASC
                 )
                 RETURNING owner_did, cipher_suite, replace(encode(key_package, 'base64'), chr(10), ''), key_package_hash",
            )
            .bind(did.as_ref())
            .bind(cs.as_ref())
            .fetch_all(&pool)
            .await
        } else {
            sqlx::query_as::<_, (String, String, String, Option<String>)>(
                "UPDATE key_packages SET consumed_at = NOW()
                 WHERE id IN (
                   SELECT DISTINCT ON (COALESCE(device_id, '')) id
                   FROM key_packages
                   WHERE owner_did = $1 AND consumed_at IS NULL AND expires_at > NOW()
                     AND (reserved_at IS NULL OR reserved_at < NOW() - INTERVAL '5 minutes')
                   ORDER BY COALESCE(device_id, ''), created_at ASC
                 )
                 RETURNING owner_did, cipher_suite, replace(encode(key_package, 'base64'), chr(10), ''), key_package_hash",
            )
            .bind(did.as_ref())
            .fetch_all(&pool)
            .await
        };

        match results {
            Ok(rows) if !rows.is_empty() => {
                for (owner_did, cipher_suite, kp_b64, kp_hash) in rows {
                    key_packages.push(KeyPackageRef {
                        did: crate::sqlx_jacquard::string_to_did(&owner_did),
                        cipher_suite: cipher_suite.into(),
                        key_package: kp_b64.into(),
                        key_package_hash: kp_hash.map(Into::into),
                        extra_data: Default::default(),
                    });
                }
            }
            Ok(_) => {
                missing.push(did.as_ref().to_string());
            }
            Err(e) => {
                error!(
                    "Failed to fetch key packages for h:{}: {}",
                    &crate::crypto::hash_for_log(did.as_ref()),
                    e
                );
                missing.push(did.as_ref().to_string());
            }
        }
    }

    info!(
        requested = input.dids.len(),
        found = key_packages.len(),
        missing = missing.len(),
        "Key packages fetched and consumed (one per device)"
    );

    let missing_dids = if missing.is_empty() {
        None
    } else {
        Some(
            missing
                .into_iter()
                .map(|d| crate::sqlx_jacquard::string_to_did(&d))
                .collect(),
        )
    };

    Ok(Json(GetKeyPackagesOutput {
        key_packages,
        missing: missing_dids,
        extra_data: Default::default(),
    }))
}
