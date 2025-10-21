use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};

/// Simplified auth extractor for MVP
/// In production, verify JWT or DID signature
pub struct AuthUser(pub String);

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract bearer token or auth header
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;

        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            // For MVP: simplified auth - decode JWT or validate
            // In production: verify JWT signature, check expiry, extract DID
            // For now, accept any bearer token as DID
            Ok(AuthUser(token.to_string()))
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

// TODO: Implement full DID verification
// - Fetch DID document from PLC/web
// - Verify JWT signature against DID public key
// - Check token expiry
// - Cache DID documents
