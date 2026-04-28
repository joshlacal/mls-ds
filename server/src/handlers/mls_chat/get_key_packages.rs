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
                        error!("getKeyPackages: block fallback DB query failed: {}", db_err);
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
        // Atomic per-device claim. The inner SELECT picks one available
        // (non-last-resort) row per device_id bucket using
        // FOR UPDATE SKIP LOCKED — concurrent claimants get disjoint rows.
        // The outer UPDATE re-checks `state = 'available'` so the transition
        // available -> claimed is the atomic gate.
        //
        // Returns raw bytea — Jacquard's `Bytes` JSON serializer base64-encodes at the
        // wire boundary. Returning `encode(... , 'base64')` here produced a second
        // base64 layer, so iOS FFI received ASCII base64 text as raw KP bytes and
        // failed `tls_deserialize_bytes`.
        let mut rows = match claim_available_key_packages(
            &pool,
            did.as_ref(),
            input.cipher_suite.as_deref(),
            /* last_resort = */ false,
        )
        .await
        {
            Ok(rows) => rows,
            Err(e) => {
                error!(
                    "Failed to fetch key packages for h:{}: {}",
                    &crate::crypto::hash_for_log(did.as_ref()),
                    e
                );
                missing.push(did.as_ref().to_string());
                continue;
            }
        };

        // Last-resort fallback: if no regular available row was claimable for
        // this DID, try the last-resort pool. Last-resort packages are still
        // single-use here (state -> claimed) — true "reusable last-resort"
        // semantics are deferred to the dedicated key-package plan.
        if rows.is_empty() {
            match claim_available_key_packages(
                &pool,
                did.as_ref(),
                input.cipher_suite.as_deref(),
                /* last_resort = */ true,
            )
            .await
            {
                Ok(lr_rows) => {
                    if !lr_rows.is_empty() {
                        crate::metrics::record_key_package_last_resort_use();
                        rows = lr_rows;
                    }
                }
                Err(e) => {
                    warn!(
                        "Last-resort key-package fallback failed for h:{}: {}",
                        &crate::crypto::hash_for_log(did.as_ref()),
                        e
                    );
                }
            }
        }

        if rows.is_empty() {
            crate::metrics::record_key_package_claim("no_match");
            crate::metrics::record_key_package_exhaustion();
            missing.push(did.as_ref().to_string());
            continue;
        }

        for (owner_did, cipher_suite, kp_bytes, kp_hash) in rows {
            crate::metrics::record_key_package_claim("claimed");
            key_packages.push(KeyPackageRef {
                did: crate::sqlx_jacquard::string_to_did(&owner_did),
                cipher_suite: cipher_suite.into(),
                key_package: kp_bytes.into(),
                key_package_hash: kp_hash.map(Into::into),
                extra_data: Default::default(),
            });
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

/// Atomically claim one available key package per `device_id` bucket for a DID.
///
/// Returns rows of `(owner_did, cipher_suite, key_package, key_package_hash)`
/// for each successfully claimed package. The transition `state='available' ->
/// state='claimed'` is the atomic gate; concurrent callers see disjoint rows
/// because the inner SELECT uses `FOR UPDATE SKIP LOCKED`.
///
/// `last_resort = false` filters to regular packages; `last_resort = true`
/// claims from the last-resort pool only. Last-resort packages are still
/// transitioned to `claimed` here — single-use semantics — pending the
/// dedicated key-package plan.
pub(crate) async fn claim_available_key_packages(
    pool: &DbPool,
    owner_did: &str,
    cipher_suite: Option<&str>,
    last_resort: bool,
) -> Result<Vec<(String, String, Vec<u8>, Option<String>)>, sqlx::Error> {
    let lr_predicate = if last_resort {
        "AND is_last_resort = true"
    } else {
        "AND is_last_resort = false"
    };
    let cs_predicate = if cipher_suite.is_some() {
        "AND cipher_suite = $2"
    } else {
        ""
    };

    let sql = format!(
        "UPDATE key_packages
         SET state = 'claimed', consumed_at = NOW()
         WHERE id IN (
           SELECT DISTINCT ON (COALESCE(device_id, '')) id
           FROM key_packages
           WHERE owner_did = $1
             AND state = 'available'
             AND expires_at > NOW()
             {lr}
             {cs}
           ORDER BY COALESCE(device_id, ''), created_at ASC
           FOR UPDATE SKIP LOCKED
         )
         AND state = 'available'
         RETURNING owner_did, cipher_suite, key_package, key_package_hash",
        lr = lr_predicate,
        cs = cs_predicate,
    );

    let mut q =
        sqlx::query_as::<_, (String, String, Vec<u8>, Option<String>)>(&sql).bind(owner_did);
    if let Some(cs) = cipher_suite {
        q = q.bind(cs);
    }
    q.fetch_all(pool).await
}
