use std::sync::Arc;

use catbird_atproto::generated::blue_catbird::mlsDS::submit_commit::{
    SubmitCommit, SubmitCommitOutput,
};
use jacquard_common::DefaultStr;
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
    pool: PgPool,
    resolver: Arc<DsResolver>,
    outbound: Arc<OutboundClient>,
    service_auth: Arc<ServiceAuthClient>,
    auth_middleware: AuthMiddleware,
}

#[derive(Debug, Clone)]
pub struct VerifiedSubmitCommit {
    pub output: SubmitCommitOutput,
    pub submit_transition_response_bytes: Vec<u8>,
}

impl RemoteCommitSubmitter {
    pub fn new(
        pool: PgPool,
        resolver: Arc<DsResolver>,
        outbound: Arc<OutboundClient>,
        service_auth: Arc<ServiceAuthClient>,
        auth_middleware: AuthMiddleware,
    ) -> Self {
        Self {
            pool,
            resolver,
            outbound,
            service_auth,
            auth_middleware,
        }
    }

    pub async fn submit(
        &self,
        sequencer_ds_did: &str,
        sequencer_term: u64,
        envelope: &SubmitCommit<DefaultStr>,
        expected_entry_id: uuid::Uuid,
        expected_seq: u64,
    ) -> Result<VerifiedSubmitCommit, FederationError> {
        let destination = self
            .resolver
            .resolve_ds_destination(sequencer_ds_did)
            .await?;

        peer_policy::enforce_outbound_peer_policy(&self.pool, sequencer_ds_did).await?;

        let auth_token = self
            .service_auth
            .sign_request(sequencer_ds_did, SUBMIT_COMMIT_NSID)?;

        let resp = match self
            .outbound
            .call_procedure_pinned(&destination, SUBMIT_COMMIT_NSID, &auth_token, envelope)
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
            Err(e) => {
                return Err(FederationError::InvalidEnvelope {
                    reason: e.to_string(),
                });
            }
        };
        let output: SubmitCommitOutput =
            serde_json::from_slice(&resp.response_bytes).map_err(|e| {
                FederationError::InvalidEnvelope {
                    reason: format!("failed to parse submitCommit response: {e}"),
                }
            })?;
        let receipt = output.receipt.clone();

        let did_doc = self
            .auth_middleware
            .resolve_did(receipt.receiver_ds_did.as_str())
            .await
            .map_err(|e| FederationError::AuthFailed {
                reason: format!(
                    "failed to resolve receiver DID {}: {e}",
                    receipt.receiver_ds_did.as_str()
                ),
            })?;

        let matching_vm = did_doc
            .verification_method
            .iter()
            .find(|vm| vm.id == super::RECEIPT_VERIFICATION_METHOD)
            .ok_or_else(|| FederationError::AuthFailed {
                reason: format!(
                    "no verification method matching {} in DID document for {}",
                    super::RECEIPT_VERIFICATION_METHOD,
                    receipt.receiver_ds_did.as_str()
                ),
            })?;

        let method_owner = super::RECEIPT_VERIFICATION_METHOD
            .split_once('#')
            .map(|(did, _)| did)
            .unwrap_or(super::RECEIPT_VERIFICATION_METHOD);
        if !dids_equivalent(&matching_vm.controller, method_owner)
            || !dids_equivalent(&matching_vm.controller, receipt.receiver_ds_did.as_str())
        {
            return Err(FederationError::AuthFailed {
                reason: format!(
                    "receipt verification method controller mismatch: expected {}, got {}",
                    receipt.receiver_ds_did.as_str(),
                    matching_vm.controller
                ),
            });
        }

        let verifying_key = crate::auth::extract_p256_key_from_vm(matching_vm).map_err(|e| {
            FederationError::AuthFailed {
                reason: format!(
                    "failed to extract P-256 key from receipt verification method: {e}"
                ),
            }
        })?;

        match verify_receipt(&receipt, &verifying_key) {
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
        if receipt.envelope_sha256.as_ref() != envelope.header.payload_sha256.as_ref() {
            return Err(FederationError::InvalidEnvelope {
                reason: "receipt envelope_sha256 mismatch".to_string(),
            });
        }
        let submit_transition_response_bytes =
            result_bytes_for_receipt(SUBMIT_COMMIT_NSID, &resp.response_bytes)?;
        let result_sha256: [u8; 32] = Sha256::digest(&submit_transition_response_bytes).into();
        if receipt.result_sha256.as_ref() != &result_sha256[..] {
            return Err(FederationError::InvalidEnvelope {
                reason: "receipt result_sha256 mismatch".to_string(),
            });
        }
        if receipt.source_locator.entry_id.as_str() != expected_entry_id.hyphenated().to_string()
            || output.commit_entry.entry_id.as_str() != expected_entry_id.hyphenated().to_string()
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
        Ok(VerifiedSubmitCommit {
            output,
            submit_transition_response_bytes,
        })
    }
}
