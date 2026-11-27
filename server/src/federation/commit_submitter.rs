use std::sync::Arc;

use crate::blue_catbird::mls_ds::submit_commit::{
    Input as SubmitCommit, Output as SubmitCommitOutput,
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use super::envelope::{verify_receipt, SUBMIT_COMMIT_NSID};
use super::errors::FederationError;
use super::outbound::{OutboundClient, OutboundError};
use super::peer_policy;
use super::receipt::result_bytes_for_receipt;
use super::resolver::DsResolver;
use super::service_auth::ServiceAuthClient;
use crate::auth::AuthMiddleware;
use crate::identity::dids_equivalent;

pub struct RemoteCommitSubmitter {
    resolver: Arc<DsResolver>,
    outbound: Arc<OutboundClient>,
    service_auth: Arc<ServiceAuthClient>,
    auth_middleware: AuthMiddleware,
}

#[derive(Debug, Clone)]
pub struct VerifiedSubmitCommit {
    pub output: SubmitCommitOutput,
    pub submit_transition_response_bytes: Vec<u8>,
    pub federation_response_bytes: Vec<u8>,
}

impl RemoteCommitSubmitter {
    pub fn new(
        resolver: Arc<DsResolver>,
        outbound: Arc<OutboundClient>,
        service_auth: Arc<ServiceAuthClient>,
        auth_middleware: AuthMiddleware,
    ) -> Self {
        Self {
            resolver,
            outbound,
            service_auth,
            auth_middleware,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn submit(
        &self,
        pool: &PgPool,
        sequencer_ds_did: &str,
        sequencer_term: u64,
        envelope: &SubmitCommit,
        expected_entry_id: uuid::Uuid,
        expected_seq: u64,
        expected_accepted_payload_sha256: [u8; 32],
        expected_outer_entry_fingerprint: [u8; 32],
    ) -> Result<VerifiedSubmitCommit, FederationError> {
        // A closed federation gate refuses before any resolution or DNS lookup.
        peer_policy::ensure_federation_open()?;
        let destination = self
            .resolver
            .resolve_ds_destination_uncached(sequencer_ds_did)
            .await?;

        peer_policy::enforce_outbound_peer_policy(pool, sequencer_ds_did).await?;

        let auth_token = self
            .service_auth
            .sign_request(sequencer_ds_did, SUBMIT_COMMIT_NSID)?;

        let envelope_json = catbird_server::atproto_conv::wire_json_value(envelope)
            .map_err(FederationError::Json)?;
        let resp = match self
            .outbound
            .call_procedure_pinned(
                &destination,
                SUBMIT_COMMIT_NSID,
                &auth_token,
                &envelope_json,
            )
            .await
        {
            Ok(r) => r,
            Err(OutboundError::RemoteError { status, body, .. }) => {
                return Err(FederationError::RemoteError { status, body });
            }
            Err(OutboundError::Timeout { .. }) => {
                return Err(FederationError::DsUnreachable {
                    endpoint: destination.host,
                    reason: "submitCommit request timed out".to_string(),
                });
            }
            Err(OutboundError::ConnectionFailed { reason, .. })
            | Err(OutboundError::RequestFailed { reason, .. }) => {
                return Err(FederationError::DsUnreachable {
                    endpoint: destination.host,
                    reason,
                });
            }
            Err(OutboundError::ResolutionFailed { did, kind }) => {
                return Err(FederationError::ResolutionFailed { did, kind });
            }
            Err(OutboundError::FederationDisabled { reason }) => {
                return Err(FederationError::FederationDisabled { reason });
            }
            Err(e) => {
                return Err(FederationError::InvalidEnvelope {
                    reason: e.to_string(),
                });
            }
        };
        let output: SubmitCommitOutput =
            catbird_server::chat_protocol::retained_json::decode_submit_commit_output(
                &resp.response_bytes,
            )
            .map_err(|e| FederationError::InvalidEnvelope {
                reason: format!("failed to parse submitCommit response: {e}"),
            })?;
        let receipt = &output.receipt;

        let did_doc = self
            .auth_middleware
            .resolve_did(receipt.receiver_ds_did.as_str())
            .await
            .map_err(|error| receipt_key_lookup_failure(receipt.receiver_ds_did.as_str(), error))?;

        let verifying_key = crate::auth::select_verification_method(&did_doc, Some("#atproto"))
            .and_then(crate::auth::extract_p256_key_from_vm)
            .map_err(|error| FederationError::AuthFailed {
                reason: format!(
                    "invalid service-auth verification method for {}: {error}",
                    receipt.receiver_ds_did.as_str()
                ),
            })?;

        match verify_receipt(receipt, &verifying_key) {
            Ok(true) => {}
            Ok(false) => {
                return Err(FederationError::InvalidEnvelope {
                    reason: "receipt signature verification failed".to_string(),
                });
            }
            Err(e) => {
                return Err(FederationError::InvalidEnvelope {
                    reason: format!("receipt verification error: {e}"),
                });
            }
        }
        if receipt.endpoint.as_str() != SUBMIT_COMMIT_NSID {
            return Err(FederationError::InvalidEnvelope {
                reason: format!(
                    "receipt endpoint mismatch: expected {SUBMIT_COMMIT_NSID}, got {}",
                    receipt.endpoint.as_str()
                ),
            });
        }
        if receipt.delivery_id.as_str() != envelope.header.delivery_id.as_str() {
            return Err(FederationError::InvalidEnvelope {
                reason: format!(
                    "receipt deliveryId mismatch: expected {}, got {}",
                    envelope.header.delivery_id.as_str(),
                    receipt.delivery_id.as_str()
                ),
            });
        }
        if receipt.conversation_id.as_str() != envelope.header.conversation_id.as_str() {
            return Err(FederationError::InvalidEnvelope {
                reason: format!(
                    "receipt conversationId mismatch: expected {}, got {}",
                    envelope.header.conversation_id.as_str(),
                    receipt.conversation_id.as_str()
                ),
            });
        }
        if !dids_equivalent(
            receipt.sender_ds_did.as_str(),
            envelope.header.sender_ds_did.as_str(),
        ) {
            return Err(FederationError::InvalidEnvelope {
                reason: format!(
                    "receipt senderDsDid mismatch: expected {}, got {}",
                    envelope.header.sender_ds_did.as_str(),
                    receipt.sender_ds_did.as_str()
                ),
            });
        }
        if !dids_equivalent(receipt.receiver_ds_did.as_str(), sequencer_ds_did) {
            return Err(FederationError::InvalidEnvelope {
                reason: format!(
                    "receipt receiverDsDid mismatch: expected {sequencer_ds_did}, got {}",
                    receipt.receiver_ds_did.as_str()
                ),
            });
        }
        if !dids_equivalent(receipt.sequencer_did.as_str(), sequencer_ds_did) {
            return Err(FederationError::InvalidEnvelope {
                reason: format!(
                    "receipt sequencerDid mismatch: expected {sequencer_ds_did}, got {}",
                    receipt.sequencer_did.as_str()
                ),
            });
        }
        if receipt.sequencer_term as u64 != sequencer_term {
            return Err(FederationError::InvalidEnvelope {
                reason: format!(
                    "receipt sequencerTerm mismatch: expected {sequencer_term}, got {}",
                    receipt.sequencer_term
                ),
            });
        }
        if receipt.envelope_sha256.0.as_slice() != envelope.header.payload_sha256.0.as_slice() {
            return Err(FederationError::InvalidEnvelope {
                reason: "receipt envelope_sha256 mismatch".to_string(),
            });
        }
        let submit_transition_response_bytes =
            result_bytes_for_receipt(SUBMIT_COMMIT_NSID, &resp.response_bytes)?;
        let result_sha256: [u8; 32] = Sha256::digest(&submit_transition_response_bytes).into();
        if receipt.result_sha256.0.as_slice() != &result_sha256[..] {
            return Err(FederationError::InvalidEnvelope {
                reason: "receipt result_sha256 mismatch".to_string(),
            });
        }
        let expected_entry_id_text = expected_entry_id.hyphenated().to_string();
        if receipt.source_locator.entry_id.as_str() != expected_entry_id_text
            || output.commit_entry.entry_id.as_str() != expected_entry_id_text
        {
            return Err(FederationError::InvalidEnvelope {
                reason: "receipt/output entry_id mismatch with local expected entry_id".to_string(),
            });
        }
        if receipt.source_locator.seq as u64 != expected_seq
            || output.commit_entry.seq as u64 != expected_seq
        {
            return Err(FederationError::InvalidEnvelope {
                reason: "receipt/output seq mismatch with local expected seq".to_string(),
            });
        }
        if receipt.source_locator.accepted_payload_sha256.0.as_slice()
            != &expected_accepted_payload_sha256[..]
        {
            return Err(FederationError::InvalidEnvelope {
                reason: "receipt source_locator accepted_payload_sha256 mismatch".to_string(),
            });
        }
        if receipt.source_locator.outer_entry_fingerprint.0.as_slice()
            != &expected_outer_entry_fingerprint[..]
        {
            return Err(FederationError::InvalidEnvelope {
                reason: "receipt source_locator outer_entry_fingerprint mismatch".to_string(),
            });
        }
        Ok(VerifiedSubmitCommit {
            output,
            submit_transition_response_bytes,
            federation_response_bytes: resp.response_bytes,
        })
    }
}

/// The sequencer's receipt key could not be looked up. A DID document that
/// could not be fetched now decided nothing about the commit, so the identical
/// submit may retry (retryable `ResolutionFailed`); any other lookup failure
/// leaves the receipt unauthenticated (`AuthFailed`).
fn receipt_key_lookup_failure(
    receiver_did: &str,
    error: crate::auth::AuthError,
) -> FederationError {
    let reason = format!("failed to resolve receiver DID {receiver_did}: {error}");
    if error.is_retryable() {
        FederationError::ResolutionFailed {
            did: receiver_did.to_owned(),
            kind: super::ResolutionFailureKind::Transient(reason),
        }
    } else {
        FederationError::AuthFailed { reason }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DQ.G22: a receipt key the sequencer's DID document could not supply now
    /// is retryable (the client's `submitTransition` answers 503 + Retry-After
    /// through `ChatFailure::unavailable`), never `AuthFailed` (401); a
    /// permanent lookup failure stays `AuthFailed`.
    #[test]
    fn a_receipt_key_lookup_that_could_not_answer_is_retryable() {
        let did = "did:web:sequencer.example.com";
        let transient = receipt_key_lookup_failure(
            did,
            crate::auth::AuthError::DidResolutionUnavailable("connect timed out".into()),
        );
        assert!(
            matches!(transient, FederationError::ResolutionFailed { .. })
                && transient.is_retryable(),
            "{transient:?}"
        );
        let permanent = receipt_key_lookup_failure(
            did,
            crate::auth::AuthError::DidResolutionFailed("HTTP 404".into()),
        );
        assert!(
            matches!(permanent, FederationError::AuthFailed { .. }),
            "{permanent:?}"
        );
    }
}
