use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use catbird_atproto::generated::blue_catbird::mlsDS::deliver_message::DeliverMessage;
use jacquard_common::DefaultStr;
use tracing::{debug, warn};

use crate::auth::AuthUser;
use crate::chat_protocol::repository::federation::deliver_message_replication;
use crate::federation::envelope::{
    validate_entry_locator, validate_envelope_header, DELIVER_MESSAGE_NSID,
};
use crate::federation::{peer_policy, AckSigner, FederationError};
use crate::identity::{canonical_did, dids_equivalent, service_did_base};
use crate::storage::DbPool;

/// POST /xrpc/blue.catbird.mlsDS.deliverMessage
///
/// Deliver a federated MLS application message to a destination DS for a local recipient.
#[tracing::instrument(skip(pool, ack_signer, auth_user, body))]
pub async fn deliver_message(
    State(pool): State<DbPool>,
    State(ack_signer): State<Option<Arc<AckSigner>>>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<serde_json::Value>, FederationError> {
    let Some(ref signer) = ack_signer else {
        return Err(FederationError::SignerUnavailable);
    };

    let msg: DeliverMessage<DefaultStr> = serde_json::from_str(&body).map_err(|e| {
        FederationError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid DeliverMessage body: {e}"),
        )))
    })?;

    if msg.extra_data.as_ref().map_or(false, |m| !m.is_empty()) {
        return Err(FederationError::InvalidEnvelope {
            reason: "unknown fields in DeliverMessage request".to_string(),
        });
    }

    let header = validate_envelope_header(&msg.header)?;
    let locator = validate_entry_locator(&msg.entry_locator)?;

    let self_base_did = service_did_base();
    if !dids_equivalent(&header.receiver_ds_did, &self_base_did) {
        return Err(FederationError::InvalidEnvelope {
            reason: format!(
                "receiverDsDid '{}' does not match local service DID '{}'",
                header.receiver_ds_did, self_base_did
            ),
        });
    }

    let security = enforce_ds_request_security(
        &pool,
        &auth_user,
        DELIVER_MESSAGE_NSID,
        Some(&header.sender_ds_did),
    )
    .await?;
    let requester_ds = security.requester_ds.clone();

    let result: Result<Json<serde_json::Value>, FederationError> = async {
        let mut tx = pool.begin().await.map_err(FederationError::Database)?;

        let output = deliver_message_replication(
            &mut tx,
            signer,
            header,
            msg.recipient_did.as_str().to_string(),
            locator,
            msg.entry_bytes.to_vec(),
            msg.signed_request_bytes.to_vec(),
        )
        .await?;

        tx.commit().await.map_err(FederationError::Database)?;

        debug!(
            delivery_id = %output.receipt.delivery_id,
            convo = %output.receipt.conversation_id,
            "Accepted federated message"
        );

        let value = serde_json::to_value(output).map_err(FederationError::Json)?;
        Ok(Json(value))
    }
    .await;

    record_ds_outcome(&pool, &requester_ds, result.is_ok()).await;
    result
}

#[derive(Debug, Clone)]
pub struct DsSecurityContext {
    pub requester_ds: String,
}

pub async fn enforce_ds_request_security(
    pool: &DbPool,
    auth_user: &AuthUser,
    endpoint_nsid: &str,
    sender_ds_did: Option<&str>,
) -> Result<DsSecurityContext, FederationError> {
    if peer_policy::inbound_emergency_kill_switch_enabled() {
        return Err(FederationError::AuthFailed {
            reason: "Federation emergency kill switch is enabled".to_string(),
        });
    }

    if !crate::federation::FederationMode::effective().allows_remote_traffic() {
        return Err(FederationError::AuthFailed {
            reason: "Federation mode is off".to_string(),
        });
    }

    validate_lxm(auth_user, endpoint_nsid)?;
    validate_ds_issuer(auth_user)?;

    let requester_ds = canonical_did(&auth_user.claims.iss).to_string();
    let policy = match peer_policy::enforce_inbound_peer_policy(pool, &requester_ds).await {
        Ok(policy) => policy,
        Err(err) => {
            peer_policy::record_rejected(pool, &requester_ds).await;
            return Err(err);
        }
    };

    if let Some(sender_ds) = sender_ds_did {
        if !dids_equivalent(sender_ds, &requester_ds) {
            peer_policy::record_rejected(pool, &requester_ds).await;
            return Err(FederationError::AuthFailed {
                reason: format!(
                    "senderDsDid '{}' does not match JWT issuer '{}'",
                    sender_ds, auth_user.claims.iss
                ),
            });
        }
    }

    if let Err(retry_after) = crate::middleware::rate_limit::FEDERATION_DS_RATE_LIMITER
        .check_peer_limit(&requester_ds, endpoint_nsid, policy.max_requests_per_minute)
    {
        peer_policy::record_rejected(pool, &requester_ds).await;
        return Err(FederationError::RemoteError {
            status: 429,
            body: format!(
                "Federation DS rate limit exceeded for {} (retry after {}s)",
                endpoint_nsid, retry_after
            ),
        });
    }

    Ok(DsSecurityContext { requester_ds })
}

pub async fn record_ds_outcome(pool: &DbPool, requester_ds: &str, success: bool) {
    if success {
        peer_policy::record_success(pool, requester_ds).await;
    } else {
        peer_policy::record_rejected(pool, requester_ds).await;
    }
}

pub fn validate_lxm(auth_user: &AuthUser, expected_lxm: &str) -> Result<(), FederationError> {
    if let Some(ref lxm) = auth_user.claims.lxm {
        if lxm == expected_lxm {
            return Ok(());
        }
        return Err(FederationError::AuthFailed {
            reason: format!("lxm mismatch: expected {expected_lxm}, got {lxm}"),
        });
    }
    Err(FederationError::AuthFailed {
        reason: format!("Missing lxm claim for {expected_lxm}"),
    })
}

pub fn validate_ds_issuer(auth_user: &AuthUser) -> Result<(), FederationError> {
    let iss = canonical_did(auth_user.claims.iss.as_str());
    if !iss.starts_with("did:") || iss.contains(char::is_whitespace) {
        return Err(FederationError::AuthFailed {
            reason: format!("Issuer '{}' is not a valid DID", iss),
        });
    }
    Ok(())
}
