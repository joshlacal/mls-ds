use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    encoding_key: EncodingKey,
    algorithm: Algorithm,
    key_id: Option<String>,
}

impl ServiceAuthClient {
    /// Create from PEM-encoded ES256 private key.
    ///
    /// If `key_id` is `None`, a `kid` is automatically derived from the SHA-256
    /// thumbprint of the public key (first 16 hex characters). This allows
    /// verifiers to select the correct key during key rotation.
    pub fn from_es256_pem(
        self_did: String,
        pem: &[u8],
        key_id: Option<String>,
    ) -> Result<Self, FederationError> {
        validate_es256_pem(pem)?;

        let kid = match key_id {
            Some(k) => Some(k),
            None => {
                // Derive kid from public key thumbprint for key rotation support.
                let pem_str = std::str::from_utf8(pem).map_err(|_| {
                    FederationError::ConfigError {
                        reason: "Invalid ES256 PEM key: non-UTF-8 input".to_string(),
                    }
                })?;
                let signing_key = SigningKey::from_pkcs8_pem(pem_str).map_err(|e| {
                    FederationError::ConfigError {
                        reason: format!("Invalid ES256 PEM key: {e}"),
                    }
                })?;
                Some(derive_es256_kid(&signing_key))
            }
        };

        let encoding_key =
            EncodingKey::from_ec_pem(pem).map_err(|e| FederationError::ConfigError {
                reason: format!("Invalid ES256 PEM key: {e}"),
            })?;
        Ok(Self {
            self_did,
            encoding_key,
            algorithm: Algorithm::ES256,
            key_id: kid,
        })
    }

    /// Create from raw ES256 private key bytes (DER).
    ///
    /// If `key_id` is `None`, a `kid` is automatically derived from the SHA-256
    /// thumbprint of the public key (first 16 hex characters).
    pub fn from_es256_der(
        self_did: String,
        der: &[u8],
        key_id: Option<String>,
    ) -> Result<Self, FederationError> {
        let kid = match key_id {
            Some(k) => Some(k),
            None => {
                // Derive kid from public key thumbprint for key rotation support.
                use p256::pkcs8::DecodePrivateKey as _;
                if let Ok(signing_key) = SigningKey::from_pkcs8_der(der) {
                    Some(derive_es256_kid(&signing_key))
                } else {
                    // DER may be SEC1 format instead of PKCS#8; fall back to no kid.
                    None
                }
            }
        };

        let encoding_key = EncodingKey::from_ec_der(der);
        Ok(Self {
            self_did,
            encoding_key,
            algorithm: Algorithm::ES256,
            key_id: kid,
        })
    }

    /// Create a shared-secret HMAC client (for development/testing).
    pub fn from_shared_secret(self_did: String, secret: &[u8]) -> Self {
        Self {
            self_did,
            encoding_key: EncodingKey::from_secret(secret),
            algorithm: Algorithm::HS256,
            key_id: None,
        }
    }

    /// Sign a request to a target DS for a specific XRPC method.
    pub fn sign_request(&self, target_did: &str, method: &str) -> Result<String, FederationError> {
        let now = Utc::now().timestamp();
        let claims = ServiceAuthClaims {
            iss: self.self_did.clone(),
            aud: target_did.to_string(),
            exp: now + 120,
            iat: now,
            lxm: method.to_string(),
            jti: uuid::Uuid::new_v4().to_string(),
        };

        let mut header = Header::new(self.algorithm);
        if let Some(ref kid) = self.key_id {
            header.kid = Some(kid.clone());
        }

        let token = encode(&header, &claims, &self.encoding_key).map_err(|e| {
            FederationError::AuthFailed {
                reason: format!("JWT encoding failed: {e}"),
            }
        })?;

        debug!(target_did, method, jti = %claims.jti, "Signed service auth request");
        Ok(token)
    }

    pub fn self_did(&self) -> &str {
        &self.self_did
    }
}

/// Derive a `kid` (Key ID) from an ES256 signing key by computing the SHA-256
/// thumbprint of the uncompressed public key point and returning the first 16
/// hex characters. This provides a stable, deterministic identifier for key
/// rotation: verifiers can look up which verification key to use based on `kid`.
fn derive_es256_kid(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false); // uncompressed
    let thumbprint = Sha256::digest(encoded_point.as_bytes());
    // Use first 8 bytes (16 hex chars) for a compact but collision-resistant kid.
    hex::encode(&thumbprint[..8])
}

fn validate_es256_pem(pem: &[u8]) -> Result<(), FederationError> {
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
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::EncodePrivateKey;

    #[test]
    fn test_shared_secret_sign_request() {
        let client = ServiceAuthClient::from_shared_secret(
            "did:web:ds-a.example.com".to_string(),
            b"test-secret-key-minimum-32-bytes!",
        );
        let token = client.sign_request(
            "did:web:ds-b.example.com",
            "blue.catbird.mls.ds.deliverMessage",
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
        assert_eq!(claims.lxm, "blue.catbird.mls.ds.deliverMessage");
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
            "blue.catbird.mls.ds.submitCommit",
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
    fn test_es256_pem_auto_derives_kid() {
        // Generate a test P-256 key pair
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let pem = signing_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("PEM encoding should succeed");

        let client = ServiceAuthClient::from_es256_pem(
            "did:web:ds.example.com".to_string(),
            pem.as_bytes(),
            None, // no explicit key_id → auto-derive
        )
        .expect("should create client");

        // kid should be auto-derived (16 hex chars)
        assert!(client.key_id.is_some(), "kid should be auto-derived");
        let kid = client.key_id.as_ref().unwrap();
        assert_eq!(kid.len(), 16, "kid should be 16 hex chars");
        assert!(
            kid.chars().all(|c| c.is_ascii_hexdigit()),
            "kid should be hex"
        );

        // Sign a token and verify the kid header is present
        let token = client
            .sign_request("did:web:target.example.com", "blue.catbird.mls.ds.deliverMessage")
            .unwrap();
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(
            header.kid.as_deref(),
            Some(kid.as_str()),
            "JWT header kid should match derived kid"
        );
    }

    #[test]
    fn test_es256_pem_explicit_kid_used() {
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let pem = signing_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("PEM encoding should succeed");

        let client = ServiceAuthClient::from_es256_pem(
            "did:web:ds.example.com".to_string(),
            pem.as_bytes(),
            Some("my-explicit-kid".to_string()),
        )
        .expect("should create client");

        assert_eq!(client.key_id.as_deref(), Some("my-explicit-kid"));

        let token = client
            .sign_request("did:web:target.example.com", "test.method")
            .unwrap();
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.kid.as_deref(), Some("my-explicit-kid"));
    }

    #[test]
    fn test_kid_deterministic_for_same_key() {
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let pem = signing_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("PEM encoding should succeed");

        let client1 = ServiceAuthClient::from_es256_pem(
            "did:web:ds1.example.com".to_string(),
            pem.as_bytes(),
            None,
        )
        .unwrap();
        let client2 = ServiceAuthClient::from_es256_pem(
            "did:web:ds2.example.com".to_string(),
            pem.as_bytes(),
            None,
        )
        .unwrap();

        assert_eq!(
            client1.key_id, client2.key_id,
            "Same key should produce same kid regardless of DID"
        );
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
