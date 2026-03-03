use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use tracing::{error, info};

use crate::{
    auth::AuthUser,
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
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_key_packages(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<GetKeyPackagesRequest>,
) -> Result<Json<GetKeyPackagesOutput<'static>>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if input.dids.len() > 100 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut key_packages: Vec<KeyPackageRef<'static>> = Vec::new();
    let mut missing: Vec<String> = Vec::new();

    for did in &input.dids {
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
