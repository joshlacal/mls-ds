use std::str::FromStr;
use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use catbird_atproto::generated::blue_catbird::mlsDS::deliver_welcome::DeliverWelcome;
use jacquard_common::DefaultStr;
use tracing::debug;
use uuid::Uuid;

use super::deliver_message::{enforce_ds_request_security, record_ds_outcome};
use crate::auth::AuthUser;
use crate::chat_protocol::repository::federation::{
    deliver_welcome_mailbox, welcome_mailbox_or_receipt_exists,
};
use crate::chat_protocol::repository::remote_prefix::apply_remote_clean_prefix;
use crate::chat_protocol::validation::CanonicalUuidV4;
use crate::federation::bootstrap::{
    bind_direct_welcome_admission, fetch_remote_prefix_admission, DirectWelcomeBootstrapBinding,
    RemotePrefixBootstrapError, RemotePrefixBootstrapSelector,
};
use crate::federation::envelope::{
    compute_welcome_envelope_digest, validate_entry_locator, validate_envelope_header,
    DELIVER_WELCOME_NSID,
};
use crate::federation::outbound::OutboundClient;
use crate::federation::{
    AckSigner, DsResolver, FederationError, RemotePrefixApplyOutcome, ServiceAuthClient,
};
use crate::identity::{dids_equivalent, service_did_base};
use crate::storage::DbPool;

fn direct_welcome_bootstrap_failure(error: RemotePrefixBootstrapError) -> FederationError {
    use RemotePrefixBootstrapError as E;
    let reason = format!("direct Welcome mailbox bootstrap failed: {error}");
    match error {
        E::Unavailable | E::MovingSnapshot => {
            FederationError::RelationshipPolicyUnavailable { reason }
        }
        E::Database => FederationError::Storage(reason),
        E::ServiceAuth => FederationError::SignerUnavailable,
        E::Conflict => FederationError::DeliveryConflict { reason },
        E::DirectWelcomeNotEligible | E::MissingCapability => {
            FederationError::MailboxNotProvisioned { reason }
        }
        E::NoLocalParticipant => FederationError::UnauthorizedRecipient { reason },
        E::PeerDenied => FederationError::Forbidden(reason),
        E::Resolution | E::Query => FederationError::MailboxNotProvisioned { reason },
        E::InvalidSelector
        | E::InvalidDigest
        | E::InvalidEvent
        | E::PrefixTooLarge
        | E::Authority => FederationError::InvalidEnvelope { reason },
    }
}

/// POST /xrpc/blue.catbird.mlsDS.deliverWelcome
///
/// Delivers a federated MLS Welcome. An authenticated first Direct delivery
/// may atomically materialize its exact signed canonical prefix and receipt;
/// all other conversations still require a preprovisioned mailbox.
#[tracing::instrument(skip(pool, ack_signer, resolver, service_auth, outbound, auth_user, body))]
pub async fn deliver_welcome(
    State(pool): State<DbPool>,
    State(ack_signer): State<Option<Arc<AckSigner>>>,
    State(resolver): State<Arc<DsResolver>>,
    State(service_auth): State<Option<Arc<ServiceAuthClient>>>,
    State(outbound): State<Arc<OutboundClient>>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<serde_json::Value>, FederationError> {
    let Some(signer) = ack_signer.as_deref() else {
        return Err(FederationError::SignerUnavailable);
    };

    let msg: DeliverWelcome<DefaultStr> = serde_json::from_str(&body).map_err(|e| {
        FederationError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid DeliverWelcome body: {e}"),
        )))
    })?;

    if msg.extra_data.as_ref().is_some_and(|m| !m.is_empty()) {
        return Err(FederationError::InvalidEnvelope {
            reason: "unknown fields in DeliverWelcome request".to_string(),
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

    let recipient_device_id_canonical = CanonicalUuidV4::parse(msg.recipient_device_id.as_str())
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("invalid recipientDeviceId: {e}"),
        })?;
    let recipient_device_id =
        Uuid::from_str(recipient_device_id_canonical.as_str()).map_err(|_| {
            FederationError::InvalidEnvelope {
                reason: "invalid recipientDeviceId UUID".to_string(),
            }
        })?;

    let welcome_id_canonical = CanonicalUuidV4::parse(msg.welcome_id.as_str()).map_err(|e| {
        FederationError::InvalidEnvelope {
            reason: format!("invalid welcomeId: {e}"),
        }
    })?;
    let welcome_id = Uuid::from_str(welcome_id_canonical.as_str()).map_err(|_| {
        FederationError::InvalidEnvelope {
            reason: "invalid welcomeId UUID".to_string(),
        }
    })?;

    let recovery_request_id_canonical = CanonicalUuidV4::parse(msg.recovery_request_id.as_str())
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("invalid recoveryRequestId: {e}"),
        })?;
    let recovery_request_id =
        Uuid::from_str(recovery_request_id_canonical.as_str()).map_err(|_| {
            FederationError::InvalidEnvelope {
                reason: "invalid recoveryRequestId UUID".to_string(),
            }
        })?;

    if msg.key_package_ref.len() != 32 {
        return Err(FederationError::InvalidEnvelope {
            reason: "keyPackageRef must be exactly 32 bytes".to_string(),
        });
    }
    let mut key_package_ref = [0u8; 32];
    key_package_ref.copy_from_slice(&msg.key_package_ref);

    if msg.welcome_sha256.len() != 32 {
        return Err(FederationError::InvalidEnvelope {
            reason: "welcomeSha256 must be exactly 32 bytes".to_string(),
        });
    }
    let mut welcome_sha256 = [0u8; 32];
    welcome_sha256.copy_from_slice(&msg.welcome_sha256);

    if msg.public_snapshot_sha256.len() != 32 {
        return Err(FederationError::InvalidEnvelope {
            reason: "publicSnapshotSha256 must be exactly 32 bytes".to_string(),
        });
    }
    let mut public_snapshot_sha256 = [0u8; 32];
    public_snapshot_sha256.copy_from_slice(&msg.public_snapshot_sha256);

    if msg.tree_summary_sha256.len() != 32 {
        return Err(FederationError::InvalidEnvelope {
            reason: "treeSummarySha256 must be exactly 32 bytes".to_string(),
        });
    }
    let mut tree_summary_sha256 = [0u8; 32];
    tree_summary_sha256.copy_from_slice(&msg.tree_summary_sha256);

    if !dids_equivalent(&header.sender_ds_did, &header.sequencer_did) {
        return Err(FederationError::InvalidEnvelope {
            reason: "senderDsDid does not equal sequencerDid on inbound delivery".to_string(),
        });
    }
    let envelope_digest = compute_welcome_envelope_digest(
        &header,
        msg.recipient_did.as_str(),
        recipient_device_id,
        welcome_id,
        recovery_request_id,
        &key_package_ref,
        &msg.welcome_bytes,
        &welcome_sha256,
        &msg.entry_bytes,
        &msg.signed_request_bytes,
        &locator,
        &msg.coordinates,
        &public_snapshot_sha256,
        &tree_summary_sha256,
    )?;
    if envelope_digest != header.payload_sha256 {
        return Err(FederationError::InvalidEnvelope {
            reason: "payloadSha256 does not match computed envelope digest".to_string(),
        });
    }

    let security = enforce_ds_request_security(
        &pool,
        &auth_user,
        DELIVER_WELCOME_NSID,
        Some(&header.sender_ds_did),
    )
    .await?;
    let requester_ds = security.requester_ds.clone();

    let mailbox_exists = welcome_mailbox_or_receipt_exists(
        &pool,
        header.delivery_id,
        header.conversation_id,
        welcome_id,
        recipient_device_id,
        recovery_request_id,
    )
    .await?;
    let bootstrap_admission = if mailbox_exists {
        None
    } else {
        let selector = RemotePrefixBootstrapSelector::new(
            header.conversation_id,
            header.sequencer_did.clone(),
            i64::try_from(header.sequencer_term).map_err(|_| FederationError::InvalidEnvelope {
                reason: "sequencerTerm exceeds the supported range".to_string(),
            })?,
        )
        .map_err(direct_welcome_bootstrap_failure)?;
        let service_auth = service_auth
            .as_deref()
            .ok_or(FederationError::SignerUnavailable)?;
        let sign = |target: &str, method: &str| {
            service_auth
                .mint_token(target, method)
                .map_err(|error| error.to_string())
        };
        let mut admission =
            fetch_remote_prefix_admission(&pool, &resolver, &outbound, &sign, selector)
                .await
                .map_err(direct_welcome_bootstrap_failure)?;
        bind_direct_welcome_admission(
            &pool,
            &mut admission,
            &DirectWelcomeBootstrapBinding {
                conversation_id: header.conversation_id,
                sequencer_did: &header.sequencer_did,
                sequencer_term: i64::try_from(header.sequencer_term).map_err(|_| {
                    FederationError::InvalidEnvelope {
                        reason: "sequencerTerm exceeds the supported range".to_string(),
                    }
                })?,
                recipient_did: msg.recipient_did.as_str(),
                recipient_device_id,
                welcome_id,
                recovery_request_id,
                key_package_ref: &key_package_ref,
                welcome_bytes: &msg.welcome_bytes,
                welcome_sha256: &welcome_sha256,
                entry_bytes: &msg.entry_bytes,
                signed_request_bytes: &msg.signed_request_bytes,
                entry_id: locator.entry_id,
                entry_seq: locator.seq,
                accepted_payload_sha256: &locator.accepted_payload_sha256,
                outer_entry_fingerprint: &locator.outer_entry_fingerprint,
                coordinates: &msg.coordinates,
            },
        )
        .await
        .map_err(direct_welcome_bootstrap_failure)?;
        Some(admission)
    };

    let result: Result<Json<serde_json::Value>, FederationError> = async {
        let mut tx = pool.begin().await.map_err(FederationError::Database)?;

        if let Some(admission) = bootstrap_admission {
            match apply_remote_clean_prefix(&mut tx, admission)
                .await
                .map_err(direct_welcome_bootstrap_failure)?
            {
                RemotePrefixApplyOutcome::Applied { .. }
                | RemotePrefixApplyOutcome::ExactReplay { .. } => {}
                RemotePrefixApplyOutcome::Quarantined { reason, .. } => {
                    return Err(FederationError::DeliveryConflict {
                        reason: format!(
                            "direct Welcome prefix is quarantined: {}",
                            reason.as_str()
                        ),
                    });
                }
            }
        }

        let output = deliver_welcome_mailbox(
            &mut tx,
            signer,
            header,
            msg.recipient_did.as_str().to_string(),
            recipient_device_id,
            welcome_id,
            recovery_request_id,
            key_package_ref,
            msg.welcome_bytes.to_vec(),
            welcome_sha256,
            msg.entry_bytes.to_vec(),
            msg.signed_request_bytes.to_vec(),
            locator,
            msg.coordinates,
            public_snapshot_sha256,
            tree_summary_sha256,
        )
        .await?;

        tx.commit().await.map_err(FederationError::Database)?;

        debug!(
            delivery_id = %output.receipt.delivery_id,
            convo = %output.receipt.conversation_id,
            "Accepted federated welcome"
        );

        let value = serde_json::to_value(output).map_err(FederationError::Json)?;
        Ok(Json(value))
    }
    .await;

    record_ds_outcome(&pool, &requester_ds, &result).await;
    result
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;

    use super::*;

    #[test]
    fn unavailable_opening_evidence_is_retryable() {
        for error in [
            RemotePrefixBootstrapError::Unavailable,
            RemotePrefixBootstrapError::MovingSnapshot,
        ] {
            let error = direct_welcome_bootstrap_failure(error);
            assert!(error.is_retryable());
            assert_eq!(
                error.into_response().status(),
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            );
        }
        assert!(!direct_welcome_bootstrap_failure(
            RemotePrefixBootstrapError::DirectWelcomeNotEligible
        )
        .is_retryable());
    }
}
