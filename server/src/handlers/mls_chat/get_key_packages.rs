use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use tracing::{error, info};

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::get_key_packages::GetKeyPackagesRequest,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getKeyPackages";

/// Fetch and consume key packages for the given DIDs.
/// Used when adding members to a group — the creator fetches one key package per invited member.
/// GET /xrpc/blue.catbird.mlsChat.getKeyPackages
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_key_packages(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<GetKeyPackagesRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if input.dids.len() > 100 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut key_packages = Vec::new();
    let mut missing = Vec::new();

    for did in &input.dids {
        let result = if let Some(ref cs) = input.cipher_suite {
            sqlx::query_as::<_, (String, String, String, Option<String>)>(
                "UPDATE key_packages SET consumed_at = NOW()
                 WHERE id = (
                   SELECT id FROM key_packages
                   WHERE owner_did = $1 AND consumed_at IS NULL AND expires_at > NOW()
                     AND (reserved_at IS NULL OR reserved_at < NOW() - INTERVAL '5 minutes')
                     AND cipher_suite = $2
                   ORDER BY created_at ASC LIMIT 1
                 )
                 RETURNING owner_did, cipher_suite, replace(encode(key_package, 'base64'), chr(10), ''), key_package_hash",
            )
            .bind(did.as_ref())
            .bind(cs.as_ref())
            .fetch_optional(&pool)
            .await
        } else {
            sqlx::query_as::<_, (String, String, String, Option<String>)>(
                "UPDATE key_packages SET consumed_at = NOW()
                 WHERE id = (
                   SELECT id FROM key_packages
                   WHERE owner_did = $1 AND consumed_at IS NULL AND expires_at > NOW()
                     AND (reserved_at IS NULL OR reserved_at < NOW() - INTERVAL '5 minutes')
                   ORDER BY created_at ASC LIMIT 1
                 )
                 RETURNING owner_did, cipher_suite, replace(encode(key_package, 'base64'), chr(10), ''), key_package_hash",
            )
            .bind(did.as_ref())
            .fetch_optional(&pool)
            .await
        };

        match result {
            Ok(Some((owner_did, cipher_suite, kp_b64, kp_hash))) => {
                key_packages.push(serde_json::json!({
                    "did": owner_did,
                    "cipherSuite": cipher_suite,
                    "keyPackage": kp_b64,
                    "keyPackageHash": kp_hash,
                }));
            }
            Ok(None) => {
                missing.push(did.as_ref().to_string());
            }
            Err(e) => {
                error!("Failed to fetch key package for h:{}: {}", &crate::crypto::hash_for_log(did.as_ref()), e);
                missing.push(did.as_ref().to_string());
            }
        }
    }

    info!(
        requested = input.dids.len(),
        found = key_packages.len(),
        missing = missing.len(),
        "Key packages fetched and consumed"
    );

    let mut response = serde_json::json!({ "keyPackages": key_packages });
    if !missing.is_empty() {
        response["missing"] = serde_json::json!(missing);
    }

    Ok(Json(response))
}
