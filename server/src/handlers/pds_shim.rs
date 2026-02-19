use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, warn};

use crate::federation::{FederationConfig, FederationError};
use crate::storage::DbPool;

// ---------------------------------------------------------------------------
// GET /.well-known/did.json
// ---------------------------------------------------------------------------

/// Serve a minimal DID document so that federated DSes can resolve this DS as
/// a PDS for its registered users (the `#atproto_pds` service entry points
/// back to `SELF_ENDPOINT`).
pub async fn well_known_did_json(
    State(config): State<FederationConfig>,
) -> Result<Json<serde_json::Value>, FederationError> {
    let service_did = &config.self_did;
    let self_endpoint = &config.self_endpoint;

    debug!(service_did, self_endpoint, "Serving /.well-known/did.json");

    // Build the base DID document.
    let mut doc = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1"
        ],
        "id": service_did,
        "service": [
            {
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": self_endpoint
            }
        ]
    });

    // If we have a signing key, derive the public key and add a
    // verificationMethod entry.
    if let Some(ref pem) = config.signing_key_pem {
        match derive_multibase_public_key(pem) {
            Ok(multibase_pub) => {
                let vm = json!({
                    "id": format!("{}#atproto", service_did),
                    "type": "Multikey",
                    "controller": service_did,
                    "publicKeyMultibase": multibase_pub
                });
                doc.as_object_mut().unwrap().insert(
                    "verificationMethod".to_string(),
                    json!([vm]),
                );
            }
            Err(e) => {
                warn!(error = %e, "Failed to derive public key for DID document; omitting verificationMethod");
            }
        }
    }

    Ok(Json(doc))
}

/// Derive the compressed-public-key multibase (base58btc, `z`-prefix)
/// representation from a PEM-encoded ES256 (P-256) private key.
///
/// The encoding follows the did:key / Multikey convention:
///   multicodec prefix 0x1200 (p256-pub) + compressed SEC1 point
///   then base58btc with a `z` prefix.
fn derive_multibase_public_key(pem: &str) -> Result<String, String> {
    use p256::pkcs8::DecodePrivateKey;

    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(pem)
        .map_err(|e| format!("Failed to parse ES256 PEM key: {e}"))?;

    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(true); // compressed
    let compressed_bytes = encoded_point.as_bytes(); // 33 bytes

    // Multicodec varint for p256-pub is 0x1200
    // Encoded as two-byte varint: [0x80, 0x24]
    let mut multicodec_bytes = vec![0x80u8, 0x24u8];
    multicodec_bytes.extend_from_slice(compressed_bytes);

    // base58btc encoding with 'z' prefix
    let encoded = multibase::encode(multibase::Base::Base58Btc, &multicodec_bytes);
    Ok(encoded)
}

// ---------------------------------------------------------------------------
// GET /xrpc/com.atproto.repo.getRecord
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct GetRecordParams {
    pub repo: String,
    pub collection: String,
    pub rkey: String,
}

/// Minimal `com.atproto.repo.getRecord` shim.
///
/// Only handles `collection=blue.catbird.mls.profile` with `rkey=self`.
/// Returns the DS profile record so that federated resolvers can discover
/// this DS as the delivery service for any user registered here.
pub async fn get_record(
    State(pool): State<DbPool>,
    State(config): State<FederationConfig>,
    Query(params): Query<GetRecordParams>,
) -> Result<Json<serde_json::Value>, FederationError> {
    // Only serve the MLS profile collection.
    if params.collection != "blue.catbird.mls.profile" || params.rkey != "self" {
        return Err(FederationError::ResolutionFailed {
            did: params.repo.clone(),
            reason: format!(
                "Unsupported collection/rkey: {}/{}",
                params.collection, params.rkey
            ),
        });
    }

    let user_did = &params.repo;

    // Check if the user is registered on this DS.
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE did = $1)",
    )
    .bind(user_did)
    .fetch_one(&pool)
    .await
    .map_err(FederationError::Database)?;

    if !exists {
        return Err(FederationError::RecipientNotFound {
            did: user_did.clone(),
        });
    }

    let self_endpoint = &config.self_endpoint;

    debug!(
        user_did,
        self_endpoint,
        "Serving MLS profile record for registered user"
    );

    Ok(Json(json!({
        "uri": format!("at://{}/blue.catbird.mls.profile/self", user_did),
        "value": {
            "$type": "blue.catbird.mls.profile",
            "deliveryService": self_endpoint,
            "supportedCipherSuites": [
                "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
            ]
        }
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_multibase_public_key_from_valid_pem() {
        // Generate a test P-256 key and check it produces a valid multibase string.
        use p256::ecdsa::SigningKey;
        let sk = SigningKey::random(&mut rand::thread_rng());
        let pem = p256::pkcs8::EncodePrivateKey::to_pkcs8_pem(&sk, Default::default())
            .expect("PEM encoding");
        let result = derive_multibase_public_key(pem.as_ref());
        assert!(result.is_ok(), "Should derive public key from valid PEM");
        let mb = result.unwrap();
        assert!(mb.starts_with('z'), "Multibase base58btc starts with 'z'");
        assert!(mb.len() > 10, "Encoded key should have meaningful length");
    }

    #[test]
    fn test_derive_multibase_public_key_from_invalid_pem() {
        let result = derive_multibase_public_key("not-a-pem");
        assert!(result.is_err());
    }
}
