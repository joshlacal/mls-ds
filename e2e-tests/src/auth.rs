use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct AtProtoClaims {
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lxm: Option<String>,
    pub jti: String,
}

/// Generate an HS256 JWT for testing against the mls-ds server.
///
/// The server verifies HS256 tokens when `JWT_SECRET` env var is set.
pub fn generate_jwt(secret: &str, did: &str, audience: &str) -> String {
    let now = Utc::now().timestamp();
    let claims = AtProtoClaims {
        iss: did.to_string(),
        aud: audience.to_string(),
        exp: now + 3600,
        iat: now,
        sub: Some(did.to_string()),
        lxm: None,
        jti: Uuid::new_v4().to_string(),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(secret.as_bytes());
    encode(&header, &claims, &key).expect("JWT encoding should not fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, DecodingKey, Validation};

    #[test]
    fn test_roundtrip_jwt() {
        let secret = "test-secret";
        let did = "did:plc:abc123";
        let token = generate_jwt(secret, did, "did:web:mls-ds.test");

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["did:web:mls-ds.test"]);
        let decoded = decode::<AtProtoClaims>(
            &token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .expect("should decode");

        assert_eq!(decoded.claims.iss, did);
        assert_eq!(decoded.claims.aud, "did:web:mls-ds.test");
    }
}
