//! Handler for getSubscriptionTicket - generates short-lived JWT tickets for WebSocket auth

use axum::{extract::State, http::StatusCode, Json};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{auth::AuthUser, storage::DbPool};

/// Request body for getSubscriptionTicket
#[derive(Debug, Deserialize)]
pub struct GetSubscriptionTicketInput {
    #[serde(rename = "convoId")]
    pub convo_id: Option<String>,
}

/// Response for getSubscriptionTicket
#[derive(Debug, Serialize)]
pub struct GetSubscriptionTicketOutput {
    /// Short-lived JWT ticket for WebSocket authentication
    pub ticket: String,
    /// WebSocket endpoint URL to connect to
    pub endpoint: String,
    /// Ticket expiration time
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
}

/// Ticket JWT Claims (self-signed by MLS DS)
#[derive(Debug, Serialize, Deserialize)]
pub struct TicketClaims {
    /// Issuer: MLS DS service DID
    pub iss: String,
    /// Subject: User's DID
    pub sub: String,
    /// Audience: Same as issuer (self-issued)
    pub aud: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Conversation ID (if subscribing to specific convo)
    #[serde(rename = "convoId", skip_serializing_if = "Option::is_none")]
    pub convo_id: Option<String>,
    /// Unique nonce for replay prevention
    pub jti: String,
}

/// Get a short-lived ticket for WebSocket subscription authentication
/// POST /xrpc/blue.catbird.mls.getSubscriptionTicket
#[tracing::instrument(skip(pool))]
pub async fn get_subscription_ticket(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<GetSubscriptionTicketInput>,
) -> Result<Json<GetSubscriptionTicketOutput>, StatusCode> {
    if let Err(_e) =
        crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.getSubscriptionTicket")
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user_did = &auth_user.did;

    // If convoId provided, verify membership
    if let Some(ref convo_id) = input.convo_id {
        if convo_id.is_empty() {
            warn!("Empty convo_id provided");
            return Err(StatusCode::BAD_REQUEST);
        }

        let is_member = crate::storage::is_member(&pool, user_did, convo_id)
            .await
            .map_err(|e| {
                error!("Failed to check membership: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        if !is_member {
            warn!(
                user = %crate::crypto::redact_for_log(user_did),
                "User is not a member of conversation"
            );
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // Get service DID from environment
    let service_did =
        std::env::var("SERVICE_DID").unwrap_or_else(|_| "did:web:mls.catbird.blue".to_string());

    // Get WebSocket endpoint from environment
    let ws_endpoint = std::env::var("WEBSOCKET_ENDPOINT").unwrap_or_else(|_| {
        "wss://mls.catbird.blue/xrpc/blue.catbird.mls.subscribeConvoEvents".to_string()
    });

    // Generate ticket with 30-second expiry
    let now = Utc::now();
    let expires_at = now + Duration::seconds(30);

    // Generate unique JTI
    let jti = generate_jti();

    let claims = TicketClaims {
        iss: service_did.clone(),
        sub: user_did.clone(),
        aud: service_did,
        exp: expires_at.timestamp(),
        iat: now.timestamp(),
        convo_id: input.convo_id,
        jti,
    };

    // Sign the ticket
    let ticket = sign_ticket(&claims).map_err(|e| {
        error!("Failed to sign ticket: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        user = %crate::crypto::redact_for_log(user_did),
        expires_at = %expires_at.to_rfc3339(),
        "Generated subscription ticket"
    );

    Ok(Json(GetSubscriptionTicketOutput {
        ticket,
        endpoint: ws_endpoint,
        expires_at: expires_at.to_rfc3339(),
    }))
}

/// Generate a unique JTI (JWT ID) for replay prevention
fn generate_jti() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let random_bytes: [u8; 16] = rng.gen();
    hex::encode(random_bytes)
}

/// Sign a ticket using HS256 with dedicated ticket secret.
fn sign_ticket(claims: &TicketClaims) -> Result<String, String> {
    let secret =
        std::env::var("TICKET_SECRET").map_err(|_| "TICKET_SECRET not configured".to_string())?;

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let key = jsonwebtoken::EncodingKey::from_secret(secret.as_bytes());

    jsonwebtoken::encode(&header, claims, &key)
        .map_err(|e| format!("Failed to encode ticket: {}", e))
}

/// Verify a subscription ticket
/// Returns the claims if valid
pub fn verify_ticket(ticket: &str) -> Result<TicketClaims, String> {
    let secret =
        std::env::var("TICKET_SECRET").map_err(|_| "TICKET_SECRET not configured".to_string())?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);

    // Set audience if SERVICE_DID is configured
    if let Ok(service_did) = std::env::var("SERVICE_DID") {
        validation.set_audience(&[&service_did]);
    }

    let key = jsonwebtoken::DecodingKey::from_secret(secret.as_bytes());

    let token_data = jsonwebtoken::decode::<TicketClaims>(ticket, &key, &validation)
        .map_err(|e| format!("Invalid ticket: {}", e))?;

    // Check expiration
    let now = Utc::now().timestamp();
    if token_data.claims.exp < now {
        return Err("Ticket expired".to_string());
    }

    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_ticket() {
        std::env::set_var("TICKET_SECRET", "test-secret-for-unit-tests");

        let claims = TicketClaims {
            iss: "did:web:mls.test".to_string(),
            sub: "did:plc:user123".to_string(),
            aud: "did:web:mls.test".to_string(),
            exp: Utc::now().timestamp() + 30,
            iat: Utc::now().timestamp(),
            convo_id: Some("convo123".to_string()),
            jti: generate_jti(),
        };

        let ticket = sign_ticket(&claims).expect("Failed to sign");
        let verified = verify_ticket(&ticket).expect("Failed to verify");

        assert_eq!(verified.sub, claims.sub);
        assert_eq!(verified.convo_id, claims.convo_id);
    }

    #[test]
    fn test_expired_ticket() {
        std::env::set_var("TICKET_SECRET", "test-secret-for-unit-tests");

        let claims = TicketClaims {
            iss: "did:web:mls.test".to_string(),
            sub: "did:plc:user123".to_string(),
            aud: "did:web:mls.test".to_string(),
            exp: Utc::now().timestamp() - 10, // Already expired
            iat: Utc::now().timestamp() - 40,
            convo_id: None,
            jti: generate_jti(),
        };

        let ticket = sign_ticket(&claims).expect("Failed to sign");
        let result = verify_ticket(&ticket);

        assert!(result.is_err());
    }
}
