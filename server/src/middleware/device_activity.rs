use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};
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

/// Extract device_id from AuthUser DID
/// Device ID is extracted from DID if it's in format did:plc:user#device-uuid
fn extract_device_id(auth_user: &AuthUser) -> Option<String> {
    // Try to extract device_id from DID if it has format did:plc:user#device-uuid
    if auth_user.did.contains('#') {
        auth_user.did.split('#').nth(1).map(|s| s.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AtProtoClaims;

    #[test]
    fn test_extract_device_id_from_did() {
        let claims = AtProtoClaims {
            iss: "did:plc:test".to_string(),
            aud: "test".to_string(),
            exp: 0,
            iat: None,
            sub: None,
            lxm: None,
            jti: None,
        };

        let auth_user = AuthUser {
            did: "did:plc:user123#device-456".to_string(),
            claims,
        };
        let device_id = extract_device_id(&auth_user);

        assert_eq!(device_id, Some("device-456".to_string()));
    }

    #[test]
    fn test_extract_device_id_no_fragment() {
        let claims = AtProtoClaims {
            iss: "did:plc:test".to_string(),
            aud: "test".to_string(),
            exp: 0,
            iat: None,
            sub: None,
            lxm: None,
            jti: None,
        };

        let auth_user = AuthUser {
            did: "did:plc:user123".to_string(),
            claims,
        };
        let device_id = extract_device_id(&auth_user);

        assert_eq!(device_id, None);
    }
}
