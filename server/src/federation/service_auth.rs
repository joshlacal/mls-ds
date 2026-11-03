use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::errors::FederationError;

/// Claims for DS-to-DS service auth JWT.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceAuthClaims {
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    /// Lexicon method being called.
    pub lxm: String,
    /// Unique token ID for replay protection.
    pub jti: String,
}

/// Signs outbound DS-to-DS requests with service JWTs.
pub struct ServiceAuthClient {
    self_did: String,
    signing_key: ServiceSigningKey,
    key_id: Option<String>,
}

enum ServiceSigningKey {
    Es256(SigningKey),
    SharedSecret(EncodingKey),
}

impl ServiceAuthClient {
    /// Create from PEM-encoded ES256 private key.
    pub fn from_es256_pem(
        self_did: String,
        pem: &[u8],
        key_id: Option<String>,
    ) -> Result<Self, FederationError> {
        let signing_key = parse_es256_pem(pem)?;
        Ok(Self {
            self_did,
            signing_key: ServiceSigningKey::Es256(signing_key),
            key_id,
        })
    }

    /// Create from an ES256 PKCS#8 private key (DER).
    pub fn from_es256_der(
        self_did: String,
        der: &[u8],
        key_id: Option<String>,
    ) -> Result<Self, FederationError> {
        let signing_key =
            SigningKey::from_pkcs8_der(der).map_err(|e| FederationError::ConfigError {
                reason: format!("Invalid ES256 DER key: {e}"),
            })?;
        Ok(Self {
            self_did,
            signing_key: ServiceSigningKey::Es256(signing_key),
            key_id,
        })
    }

    /// Create a shared-secret HMAC client (for development/testing).
    pub fn from_shared_secret(self_did: String, secret: &[u8]) -> Self {
        Self {
            self_did,
            signing_key: ServiceSigningKey::SharedSecret(EncodingKey::from_secret(secret)),
            key_id: None,
        }
    }

    /// Sign a request to a target DS for a specific XRPC method.
    pub fn sign_request(&self, target_did: &str, method: &str) -> Result<String, FederationError> {
        let now = crate::sim_hooks::current_utc().timestamp();
        let jti = crate::sim_hooks::mint_outbound_jti_uuid_v4(
            b"federation.service_auth",
            &[
                self.self_did.as_bytes(),
                target_did.as_bytes(),
                method.as_bytes(),
            ],
        );
        let claims = ServiceAuthClaims {
            iss: self.self_did.clone(),
            aud: target_did.to_string(),
            exp: now + 120,
            iat: now,
            lxm: method.to_string(),
            jti: jti.to_string(),
        };

        let mut header = Header::new(match &self.signing_key {
            ServiceSigningKey::Es256(_) => Algorithm::ES256,
            ServiceSigningKey::SharedSecret(_) => Algorithm::HS256,
        });
        if let Some(ref kid) = self.key_id {
            header.kid = Some(kid.clone());
        }

        let token = match &self.signing_key {
            ServiceSigningKey::Es256(signing_key) => {
                let header =
                    serde_json::to_vec(&header).map_err(|e| FederationError::AuthFailed {
                        reason: format!("JWT encoding failed: {e}"),
                    })?;
                let payload =
                    serde_json::to_vec(&claims).map_err(|e| FederationError::AuthFailed {
                        reason: format!("JWT encoding failed: {e}"),
                    })?;
                let signing_input = format!(
                    "{}.{}",
                    URL_SAFE_NO_PAD.encode(header),
                    URL_SAFE_NO_PAD.encode(payload)
                );
                // RFC 6979 derives a secure nonce from the secret key and message.
                // Unlike seeded RNG signing, this is safe in production too.
                let signature: Signature = signing_key.sign(signing_input.as_bytes());
                let signature = signature.normalize_s().unwrap_or(signature);
                format!(
                    "{signing_input}.{}",
                    URL_SAFE_NO_PAD.encode(signature.to_bytes())
                )
            }
            ServiceSigningKey::SharedSecret(key) => {
                encode(&header, &claims, key).map_err(|e| FederationError::AuthFailed {
                    reason: format!("JWT encoding failed: {e}"),
                })?
            }
        };

        debug!(target_did, method, jti = %claims.jti, "Signed service auth request");
        Ok(token)
    }

    /// Mint an authenticated S2S service token with explicit target audience and method NSID.
    pub fn mint_token(&self, target_did: &str, method: &str) -> Result<String, FederationError> {
        self.sign_request(target_did, method)
    }

    pub fn self_did(&self) -> &str {
        &self.self_did
    }
}

fn parse_es256_pem(pem: &[u8]) -> Result<SigningKey, FederationError> {
    const MAX_PEM_BYTES: usize = 16 * 1024;

    if pem.is_empty() {
        return Err(FederationError::ConfigError {
            reason: "Invalid ES256 PEM key: empty input".to_string(),
        });
    }

    if pem.len() > MAX_PEM_BYTES {
        return Err(FederationError::ConfigError {
            reason: format!(
                "Invalid ES256 PEM key: input exceeds {} bytes",
                MAX_PEM_BYTES
            ),
        });
    }

    let pem_str = std::str::from_utf8(pem).map_err(|_| FederationError::ConfigError {
        reason: "Invalid ES256 PEM key: non-UTF-8 input".to_string(),
    })?;

    if pem_str.trim().is_empty() {
        return Err(FederationError::ConfigError {
            reason: "Invalid ES256 PEM key: empty input".to_string(),
        });
    }

    SigningKey::from_pkcs8_pem(pem_str).map_err(|e| FederationError::ConfigError {
        reason: format!("Invalid ES256 PEM key: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use std::sync::Arc;

    #[test]
    fn es256_tokens_replay_with_rfc6979_and_verify_with_standard_jwt_decoder() {
        use crate::sim_hooks::{with_ds_clock, ManualDsClock};

        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap();
        let der = key.to_pkcs8_der().unwrap();
        let public_pem = key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let client = ServiceAuthClient::from_es256_pem(
            "did:web:sender.example".to_string(),
            pem.as_bytes(),
            Some("#atproto".to_string()),
        )
        .unwrap();
        let der_client = ServiceAuthClient::from_es256_der(
            "did:web:sender.example".to_string(),
            der.as_bytes(),
            Some("#atproto".to_string()),
        )
        .unwrap();
        let now = chrono::DateTime::from_timestamp(1_600_000_000, 0).unwrap();
        let clock = Arc::new(ManualDsClock::new(now));
        let sign = || {
            client
                .sign_request(
                    "did:web:target.example",
                    "blue.catbird.mlsDS.deliverMessage",
                )
                .unwrap()
        };
        let first = with_ds_clock(clock.clone(), sign);
        let second = with_ds_clock(clock.clone(), sign);
        assert_ne!(first, second, "replay IDs must remain unique within a run");
        clock.reset_counters();
        assert_eq!(with_ds_clock(clock, sign), first);
        assert_eq!(
            with_ds_clock(Arc::new(ManualDsClock::new(now)), || {
                der_client
                    .sign_request(
                        "did:web:target.example",
                        "blue.catbird.mlsDS.deliverMessage",
                    )
                    .unwrap()
            }),
            first
        );
        let mut validation = jsonwebtoken::Validation::new(Algorithm::ES256);
        validation.validate_exp = false;
        validation.set_audience(&["did:web:target.example"]);
        let decoded = jsonwebtoken::decode::<ServiceAuthClaims>(
            &first,
            &jsonwebtoken::DecodingKey::from_ec_pem(public_pem.as_bytes()).unwrap(),
            &validation,
        )
        .unwrap();
        assert_eq!(decoded.header.kid.as_deref(), Some("#atproto"));
        assert_eq!(decoded.claims.iat, now.timestamp());
        assert_eq!(decoded.claims.exp, now.timestamp() + 120);
        assert_eq!(decoded.claims.lxm, "blue.catbird.mlsDS.deliverMessage");
    }

    #[test]
    fn test_shared_secret_sign_request() {
        let client = ServiceAuthClient::from_shared_secret(
            "did:web:ds-a.example.com".to_string(),
            b"test-secret-key-minimum-32-bytes!",
        );
        let token = client.sign_request(
            "did:web:ds-b.example.com",
            "blue.catbird.mlsDS.deliverMessage",
        );
        assert!(token.is_ok());
        let token = token.unwrap();
        assert!(!token.is_empty());

        // Decode without verification to check claims structure
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.insecure_disable_signature_validation();
        validation.set_audience(&["did:web:ds-b.example.com"]);
        let key = jsonwebtoken::DecodingKey::from_secret(b"test-secret-key-minimum-32-bytes!");
        let decoded = jsonwebtoken::decode::<ServiceAuthClaims>(&token, &key, &validation);
        assert!(decoded.is_ok());
        let claims = decoded.unwrap().claims;
        assert_eq!(claims.iss, "did:web:ds-a.example.com");
        assert_eq!(claims.aud, "did:web:ds-b.example.com");
        assert_eq!(claims.lxm, "blue.catbird.mlsDS.deliverMessage");
        assert!(claims.exp > claims.iat);
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn test_sign_request_sets_expiry_window() {
        let client = ServiceAuthClient::from_shared_secret(
            "did:web:ds.example.com".to_string(),
            b"secret-key-for-testing-32-bytes!",
        );
        let token = client.sign_request(
            "did:web:other.example.com",
            "blue.catbird.mlsDS.submitCommit",
        );
        assert!(token.is_ok());
        let token = token.unwrap();

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.insecure_disable_signature_validation();
        validation.set_audience(&["did:web:other.example.com"]);
        let key = jsonwebtoken::DecodingKey::from_secret(b"unused");
        let decoded = jsonwebtoken::decode::<ServiceAuthClaims>(&token, &key, &validation);
        assert!(decoded.is_ok());
        let claims = decoded.unwrap().claims;
        // Token should expire 120 seconds after issuance
        assert_eq!(claims.exp - claims.iat, 120);
    }

    #[test]
    fn test_self_did() {
        let client = ServiceAuthClient::from_shared_secret(
            "did:web:my-ds.example.com".to_string(),
            b"test-secret",
        );
        assert_eq!(client.self_did(), "did:web:my-ds.example.com");
    }

    #[test]
    fn test_unique_jti_per_call() {
        let client = ServiceAuthClient::from_shared_secret(
            "did:web:ds.example.com".to_string(),
            b"test-secret-key-minimum-32-bytes!",
        );
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.insecure_disable_signature_validation();
        validation.set_audience(&["did:web:target.example.com"]);
        let key = jsonwebtoken::DecodingKey::from_secret(b"unused");

        let token1 = client
            .sign_request("did:web:target.example.com", "m")
            .unwrap();
        let token2 = client
            .sign_request("did:web:target.example.com", "m")
            .unwrap();

        let jti1 = jsonwebtoken::decode::<ServiceAuthClaims>(&token1, &key, &validation)
            .unwrap()
            .claims
            .jti;
        let jti2 = jsonwebtoken::decode::<ServiceAuthClaims>(&token2, &key, &validation)
            .unwrap()
            .claims
            .jti;
        assert_ne!(
            jti1, jti2,
            "Each token must have a unique jti for replay protection"
        );
    }
}
