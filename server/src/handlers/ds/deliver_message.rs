use axum::{extract::State, Json};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn};
use ulid::Ulid;

use crate::{
    auth::AuthUser,
    crypto::redact_for_log,
    federation::{peer_policy, AckSigner, FederationError},
    identity::{canonical_did, dids_equivalent},
    realtime::SseState,
    storage::DbPool,
};

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeliverMessage<'a> {
    #[serde(borrow)]
    convo_id: jacquard_common::CowStr<'a>,
    #[serde(borrow)]
    msg_id: jacquard_common::CowStr<'a>,
    epoch: i64,
    #[serde(borrow)]
    sender_ds_did: jacquard_common::CowStr<'a>,
    #[serde(with = "jacquard_common::serde_bytes_helper")]
    ciphertext: bytes::Bytes,
    padded_size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(borrow)]
    message_type: Option<jacquard_common::CowStr<'a>>,
}

const NSID: &str = "blue.catbird.mlsDS.deliverMessage";

/// POST /xrpc/blue.catbird.mlsDS.deliverMessage
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
    let msg: DeliverMessage<'_> = serde_json::from_str(&body).map_err(|_| {
        FederationError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid DeliverMessage body",
        )))
    })?;

    let convo_id = msg.convo_id.as_ref();
    let msg_id = msg.msg_id.as_ref();
    let epoch = msg.epoch;
    let sender_ds = msg.sender_ds_did.as_ref();
    let raw_body: serde_json::Value = serde_json::from_str(&body).map_err(|_| {
        FederationError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid DeliverMessage body",
        )))
    })?;
    let delivery_id = parse_required_ulid(&raw_body, "deliveryId")?;
    let sequencer_term = parse_required_u64(&raw_body, "sequencerTerm")?;

    let security = enforce_ds_request_security(&pool, &auth_user, NSID, Some(sender_ds)).await?;
    let requester_ds = security.requester_ds.clone();

    let result: Result<Json<serde_json::Value>, FederationError> = async {
        let Some(sequencer_state) = load_convo_sequencer_state_optional(&pool, convo_id).await?
        else {
            return Err(FederationError::ConversationNotFound {
                convo_id: convo_id.to_string(),
            });
        };
        if requester_ds != sequencer_state.expected_sequencer {
            return Err(FederationError::NotSequencer {
                convo_id: convo_id.to_string(),
            });
        }
        if sequencer_term != sequencer_state.current_term {
            return Err(FederationError::TermStale {
                convo_id: convo_id.to_string(),
                provided_term: sequencer_term as i64,
                current_term: sequencer_state.current_term as i64,
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
        let message_view = crate::realtime::StreamMessageView {
            id: msg_id.to_string().into(),
            convo_id: convo_id.to_string().into(),
            ciphertext: msg.ciphertext.clone(),
            epoch,
            seq,
            created_at: crate::sqlx_jacquard::chrono_to_datetime(chrono::Utc::now()),
            message_type: Some(msg.message_type.as_deref().unwrap_or("app").to_string().into()),
            extra_data: Default::default(),
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
            warn!(
                convo = %redact_for_log(convo_id),
                error = %e,
                "Failed to emit SSE event for delivered message"
            );
        }

        debug!(
            convo = %redact_for_log(convo_id),
            msg = %redact_for_log(msg_id),
            seq,
            sender_ds = %redact_for_log(sender_ds),
            "Accepted federated message"
        );

        let mut response = json!({
            "accepted": true,
            "seq": seq,
            "deliveryId": delivery_id
        });
        if let Some(ref signer) = ack_signer {
            let ack = signer.sign_ack(msg_id, convo_id, epoch as i32, sequencer_term);
            response["ack"] = serde_json::to_value(&ack).unwrap_or_default();
        }

        Ok(Json(response))
    }
    .await;

    record_ds_outcome(&pool, &requester_ds, result.is_ok()).await;
    result
}

fn parse_required_u64(
    body: &serde_json::Value,
    field: &'static str,
) -> Result<u64, FederationError> {
    body.get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            FederationError::Json(serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Missing or invalid {field}"),
            )))
        })
}

fn parse_required_ulid(
    body: &serde_json::Value,
    field: &'static str,
) -> Result<String, FederationError> {
    let value = body
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            FederationError::Json(serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Missing or invalid {field}"),
            )))
        })?;
    Ulid::from_string(value).map_err(|_| {
        FederationError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid ULID {field}"),
        )))
    })?;
    Ok(value.to_string())
}

#[derive(Debug, Clone)]
pub(super) struct ConvoSequencerState {
    pub expected_sequencer: String,
    pub current_term: u64,
}

pub(super) async fn load_convo_sequencer_state_optional(
    pool: &DbPool,
    convo_id: &str,
) -> Result<Option<ConvoSequencerState>, FederationError> {
    let convo_row = sqlx::query_as::<_, (Option<String>, Option<i64>)>(
        "SELECT sequencer_ds, sequencer_term FROM conversations WHERE id = $1",
    )
    .bind(convo_id)
    .fetch_optional(pool)
    .await
    .map_err(FederationError::Database)?;

    // N31: fail-loudly service identity — no hardcoded fallback DID.
    let self_did = crate::identity::service_did();
    Ok(
        convo_row.map(|(sequencer_ds, current_term_raw)| ConvoSequencerState {
            expected_sequencer: canonical_did(&sequencer_ds.unwrap_or(self_did)).to_string(),
            current_term: current_term_raw.unwrap_or(0).max(0) as u64,
        }),
    )
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
