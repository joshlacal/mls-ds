use axum::{
    body::Body,
    extract::State,
    http::Request,
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use sqlx::PgPool;
use tracing::debug;

use crate::auth::AuthUser;

/// Middleware to track device activity on every authenticated API call
/// Updates devices.last_seen_at asynchronously without blocking the request
pub async fn track_device_activity(
    State(pool): State<PgPool>,
    auth_user: Option<AuthUser>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // If we have an authenticated user, try to extract device_id and update last_seen_at
    if let Some(user) = auth_user {
        // Try to extract device_id from JWT claims
        // The device_id might be in a custom claim or we can extract it from the credential DID
        if let Some(device_id) = extract_device_id(&user) {
            let pool_clone = pool.clone();
            let device_id_clone = device_id.clone();

            // Spawn async task to update last_seen_at without blocking the request
            tokio::spawn(async move {
                let now = Utc::now();
                let result = sqlx::query!(
                    r#"
                    UPDATE devices
                    SET last_seen_at = $1
                    WHERE id = $2
                    "#,
                    now,
                    device_id_clone
                )
                .execute(&pool_clone)
                .await;

                match result {
                    Ok(r) if r.rows_affected() > 0 => {
                        debug!("Updated last_seen_at for device: {}", device_id_clone);
                    }
                    Ok(_) => {
                        debug!("Device not found in database: {}", device_id_clone);
                    }
                    Err(e) => {
                        debug!("Failed to update device activity: {}", e);
                    }
                }
            });
        }
    }

    // Continue processing the request
    next.run(request).await
}

/// Extract device_id from AuthUser claims
/// Device ID could be in custom claims or derived from credential_did
fn extract_device_id(auth_user: &AuthUser) -> Option<String> {
    // Check for device_id in custom claims
    if let Some(device_id) = auth_user.claims.extra.get("device_id") {
        if let Some(id_str) = device_id.as_str() {
            return Some(id_str.to_string());
        }
    }

    // Check for device_id in other possible claim locations
    if let Some(device_id) = auth_user.claims.extra.get("deviceId") {
        if let Some(id_str) = device_id.as_str() {
            return Some(id_str.to_string());
        }
    }

    // Could also derive from credential DID if available
    // For now, return None if not found
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Claims;
    use serde_json::json;

    #[test]
    fn test_extract_device_id_from_custom_claim() {
        let mut extra = serde_json::Map::new();
        extra.insert("device_id".to_string(), json!("device-123"));

        let claims = Claims {
            iss: "did:plc:test".to_string(),
            aud: "test".to_string(),
            exp: 0,
            iat: None,
            nbf: None,
            jti: None,
            lxm: None,
            extra,
        };

        let auth_user = AuthUser { claims };
        let device_id = extract_device_id(&auth_user);

        assert_eq!(device_id, Some("device-123".to_string()));
    }

    #[test]
    fn test_extract_device_id_camel_case() {
        let mut extra = serde_json::Map::new();
        extra.insert("deviceId".to_string(), json!("device-456"));

        let claims = Claims {
            iss: "did:plc:test".to_string(),
            aud: "test".to_string(),
            exp: 0,
            iat: None,
            nbf: None,
            jti: None,
            lxm: None,
            extra,
        };

        let auth_user = AuthUser { claims };
        let device_id = extract_device_id(&auth_user);

        assert_eq!(device_id, Some("device-456".to_string()));
    }

    #[test]
    fn test_extract_device_id_none() {
        let claims = Claims {
            iss: "did:plc:test".to_string(),
            aud: "test".to_string(),
            exp: 0,
            iat: None,
            nbf: None,
            jti: None,
            lxm: None,
            extra: serde_json::Map::new(),
        };

        let auth_user = AuthUser { claims };
        let device_id = extract_device_id(&auth_user);

        assert_eq!(device_id, None);
    }
}
