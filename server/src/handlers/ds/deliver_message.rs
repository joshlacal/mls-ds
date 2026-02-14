use axum::{extract::State, Json};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::{
    auth::AuthUser,
    federation::{peer_policy, AckSigner, FederationError},
    identity::{canonical_did, dids_equivalent},
    realtime::SseState,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mls.ds.deliverMessage";

/// POST /xrpc/blue.catbird.mls.ds.deliverMessage
///
/// Accept an inbound MLS message from a remote DS and store it for local subscribers.
#[tracing::instrument(skip(pool, sse_state, ack_signer, auth_user, body))]
pub async fn deliver_message(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    State(ack_signer): State<Option<Arc<AckSigner>>>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<serde_json::Value>, FederationError> {
    let msg = crate::jacquard_json::from_json_body::<
        crate::blue_catbird::mls::ds::deliver_message::DeliverMessage<'_>,
    >(&body)
    .map_err(|_| {
        FederationError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid DeliverMessage body",
        )))
    })?;

    let convo_id = msg.convo_id.as_ref();
    let msg_id = msg.msg_id.as_ref();
    let epoch = msg.epoch;
    let sender_ds = msg.sender_ds_did.as_ref();

    let security = enforce_ds_request_security(&pool, &auth_user, NSID, Some(sender_ds)).await?;
    let requester_ds = security.requester_ds.clone();

    let result: Result<Json<serde_json::Value>, FederationError> = async {
        // Verify conversation exists locally and read sequencer binding.
        let sequencer_ds = sqlx::query_scalar::<_, Option<String>>(
            "SELECT sequencer_ds FROM conversations WHERE id = $1",
        )
        .bind(convo_id)
        .fetch_optional(&pool)
        .await
        .map_err(FederationError::Database)?;

        let Some(sequencer_ds) = sequencer_ds else {
            return Err(FederationError::ConversationNotFound {
                convo_id: convo_id.to_string(),
            });
        };

        let self_did = std::env::var("SERVICE_DID")
            .unwrap_or_else(|_| "did:web:mls.catbird.blue".to_string());
        let expected_sequencer = canonical_did(&sequencer_ds.unwrap_or(self_did)).to_string();
        if requester_ds != expected_sequencer {
            return Err(FederationError::AuthFailed {
                reason: format!(
                    "DS {} is not the sequencer for {} (expected {})",
                    requester_ds, convo_id, expected_sequencer
                ),
            });
        }

        // Store the message (idempotent on msg_id)
        let seq = sqlx::query_scalar::<_, i64>(
            "INSERT INTO messages (id, convo_id, sender_did, message_type, ciphertext, epoch, padded_size, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) \
             ON CONFLICT (id) DO UPDATE SET id = messages.id \
             RETURNING seq",
        )
        .bind(msg_id)
        .bind(convo_id)
        .bind(Option::<&str>::None) // sender_did intentionally NULL — PRIV-001 (docs/PRIVACY.md)
        .bind(msg.message_type.as_deref().unwrap_or("app"))
        .bind(msg.ciphertext.as_ref())
        .bind(epoch)
        .bind(msg.padded_size)
        .fetch_one(&pool)
        .await
        .map_err(FederationError::Database)?;

        // Emit to SSE for local subscribers (best-effort)
        let message_view = crate::generated_types::MessageView {
            id: msg_id.to_string(),
            convo_id: convo_id.to_string(),
            ciphertext: msg.ciphertext.to_vec(),
            epoch,
            seq,
            created_at: chrono::Utc::now(),
            message_type: msg.message_type.as_deref().unwrap_or("app").to_string(),
            reactions: None,
        };

        if let Err(e) = sse_state
            .emit(
                convo_id,
                crate::realtime::StreamEvent::MessageEvent {
                    cursor: seq.to_string(),
                    message: message_view,
                    ephemeral: false,
                },
            )
            .await
        {
            warn!(convo_id, error = %e, "Failed to emit SSE event for delivered message");
        }

        debug!(convo_id, msg_id, seq, sender_ds, "Accepted federated message");

        let mut response = json!({
            "accepted": true,
            "seq": seq
        });
        if let Some(ref signer) = ack_signer {
            let ack = signer.sign_ack(msg_id, convo_id, epoch as i32);
            response["ack"] = serde_json::to_value(&ack).unwrap_or_default();
        }

        Ok(Json(response))
    }
    .await;

    record_ds_outcome(&pool, &requester_ds, result.is_ok()).await;
    result
}

#[derive(Debug, Clone)]
pub(super) struct DsSecurityContext {
    pub requester_ds: String,
}

pub(super) async fn enforce_ds_request_security(
    pool: &DbPool,
    auth_user: &AuthUser,
    endpoint_nsid: &str,
    sender_ds_did: Option<&str>,
) -> Result<DsSecurityContext, FederationError> {
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

pub(super) async fn record_ds_outcome(pool: &DbPool, requester_ds: &str, success: bool) {
    if success {
        peer_policy::record_success(pool, requester_ds).await;
    } else {
        peer_policy::record_rejected(pool, requester_ds).await;
    }
}

pub(super) fn validate_lxm(
    auth_user: &AuthUser,
    expected_lxm: &str,
) -> Result<(), FederationError> {
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

pub(super) fn validate_ds_issuer(auth_user: &AuthUser) -> Result<(), FederationError> {
    let iss = canonical_did(auth_user.claims.iss.as_str());
    if !iss.starts_with("did:") || iss.contains(char::is_whitespace) {
        return Err(FederationError::AuthFailed {
            reason: format!("Issuer '{}' is not a valid DID", iss),
        });
    }
    Ok(())
}
