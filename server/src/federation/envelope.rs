//! Clean-chat federation envelope decoding, domain-separated digests, and receipt signing.
//!
//! Every federated operation uses strict, closed version-1 envelopes with
//! domain-separated SHA-256 digests and ES256 P1363 receipt signatures.

use std::str::FromStr;

use catbird_atproto::generated::blue_catbird::chat::ConversationCoordinates;
use catbird_atproto::generated::blue_catbird::mlsDS::{
    EntryLocatorV1, EnvelopeHeaderV1, FederationReceiptV1,
};
use chrono::{DateTime, SecondsFormat, Utc};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::chat_protocol::validation::{BareDid, CanonicalUuidV4, MAX_SAFE_INTEGER};
use crate::federation::ack::AckSigner;
use crate::federation::errors::FederationError;

pub const ENVELOPE_DIGEST_DOMAIN: &[u8] = b"CATBIRD-CLEAN-FEDERATION-ENVELOPE-V1\0";
pub const RECEIPT_SIGNING_DOMAIN: &[u8] = b"CATBIRD-CLEAN-FEDERATION-RECEIPT-V1\0";

pub const DELIVER_MESSAGE_NSID: &str = "blue.catbird.mlsDS.deliverMessage";
pub const DELIVER_WELCOME_NSID: &str = "blue.catbird.mlsDS.deliverWelcome";
pub const SUBMIT_COMMIT_NSID: &str = "blue.catbird.mlsDS.submitCommit";

/// Append length-prefixed bytes `u32_be(len) || bytes` to the buffer.
pub fn lp_bytes(bytes: &[u8], buf: &mut Vec<u8>) {
    let len = bytes.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Validated header fields with parsed strong types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedEnvelopeHeader {
    pub protocol_version: String,
    pub delivery_id: Uuid,
    pub conversation_id: Uuid,
    pub sender_ds_did: String,
    pub receiver_ds_did: String,
    pub sequencer_did: String,
    pub sequencer_term: u64,
    pub payload_sha256: [u8; 32],
}

/// Validated entry locator with parsed strong types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedEntryLocator {
    pub entry_id: Uuid,
    pub seq: u64,
    pub accepted_payload_sha256: [u8; 32],
    pub outer_entry_fingerprint: [u8; 32],
}

/// Validate the closed envelope header according to v1 invariants.
pub fn validate_envelope_header(
    header: &EnvelopeHeaderV1,
) -> Result<ValidatedEnvelopeHeader, FederationError> {
    if header.extra_data.as_ref().map_or(false, |m| !m.is_empty()) {
        return Err(FederationError::InvalidEnvelope {
            reason: "unknown fields in envelope header".to_string(),
        });
    }
    if header.protocol_version.as_str() != "1" {
        return Err(FederationError::InvalidEnvelope {
            reason: format!(
                "unsupported protocolVersion: {}",
                header.protocol_version.as_str()
            ),
        });
    }

    let delivery_canonical = CanonicalUuidV4::parse(header.delivery_id.as_str()).map_err(|e| {
        FederationError::InvalidEnvelope {
            reason: format!("invalid deliveryId UUID: {e}"),
        }
    })?;
    let delivery_id = Uuid::from_str(delivery_canonical.as_str()).map_err(|_| {
        FederationError::InvalidEnvelope {
            reason: "invalid deliveryId UUID".to_string(),
        }
    })?;

    let convo_canonical = CanonicalUuidV4::parse(header.conversation_id.as_str()).map_err(|e| {
        FederationError::InvalidEnvelope {
            reason: format!("invalid conversationId UUID: {e}"),
        }
    })?;
    let conversation_id =
        Uuid::from_str(convo_canonical.as_str()).map_err(|_| FederationError::InvalidEnvelope {
            reason: "invalid conversationId UUID".to_string(),
        })?;

    let sender_did = BareDid::parse(header.sender_ds_did.as_str()).map_err(|e| {
        FederationError::InvalidEnvelope {
            reason: format!("invalid senderDsDid: {e}"),
        }
    })?;
    let receiver_did = BareDid::parse(header.receiver_ds_did.as_str()).map_err(|e| {
        FederationError::InvalidEnvelope {
            reason: format!("invalid receiverDsDid: {e}"),
        }
    })?;
    let sequencer_did = BareDid::parse(header.sequencer_did.as_str()).map_err(|e| {
        FederationError::InvalidEnvelope {
            reason: format!("invalid sequencerDid: {e}"),
        }
    })?;

    if header.sequencer_term < 0 || header.sequencer_term > MAX_SAFE_INTEGER {
        return Err(FederationError::InvalidEnvelope {
            reason: format!("invalid sequencerTerm: {}", header.sequencer_term),
        });
    }
    let sequencer_term = header.sequencer_term as u64;

    if header.payload_sha256.len() != 32 {
        return Err(FederationError::InvalidEnvelope {
            reason: "payloadSha256 must be exactly 32 bytes".to_string(),
        });
    }
    let mut payload_sha256 = [0u8; 32];
    payload_sha256.copy_from_slice(&header.payload_sha256);

    Ok(ValidatedEnvelopeHeader {
        protocol_version: "1".to_string(),
        delivery_id,
        conversation_id,
        sender_ds_did: sender_did.as_str().to_string(),
        receiver_ds_did: receiver_did.as_str().to_string(),
        sequencer_did: sequencer_did.as_str().to_string(),
        sequencer_term,
        payload_sha256,
    })
}

/// Validate the closed entry locator according to v1 invariants.
pub fn validate_entry_locator(
    locator: &EntryLocatorV1,
) -> Result<ValidatedEntryLocator, FederationError> {
    if locator.extra_data.as_ref().map_or(false, |m| !m.is_empty()) {
        return Err(FederationError::InvalidEnvelope {
            reason: "unknown fields in entry locator".to_string(),
        });
    }

    let entry_canonical = CanonicalUuidV4::parse(locator.entry_id.as_str()).map_err(|e| {
        FederationError::InvalidEnvelope {
            reason: format!("invalid entryId UUID: {e}"),
        }
    })?;
    let entry_id =
        Uuid::from_str(entry_canonical.as_str()).map_err(|_| FederationError::InvalidEnvelope {
            reason: "invalid entryId UUID".to_string(),
        })?;

    if locator.seq < 1 || locator.seq > MAX_SAFE_INTEGER {
        return Err(FederationError::InvalidEnvelope {
            reason: format!("invalid entryLocator seq: {}", locator.seq),
        });
    }
    let seq = locator.seq as u64;

    if locator.accepted_payload_sha256.len() != 32 {
        return Err(FederationError::InvalidEnvelope {
            reason: "acceptedPayloadSha256 must be exactly 32 bytes".to_string(),
        });
    }
    let mut accepted_payload_sha256 = [0u8; 32];
    accepted_payload_sha256.copy_from_slice(&locator.accepted_payload_sha256);

    if locator.outer_entry_fingerprint.len() != 32 {
        return Err(FederationError::InvalidEnvelope {
            reason: "outerEntryFingerprint must be exactly 32 bytes".to_string(),
        });
    }
    let mut outer_entry_fingerprint = [0u8; 32];
    outer_entry_fingerprint.copy_from_slice(&locator.outer_entry_fingerprint);

    Ok(ValidatedEntryLocator {
        entry_id,
        seq,
        accepted_payload_sha256,
        outer_entry_fingerprint,
    })
}

/// Compute envelope digest for `blue.catbird.mlsDS.deliverMessage`.
pub fn compute_message_envelope_digest(
    header: &ValidatedEnvelopeHeader,
    recipient_did: &str,
    locator: &ValidatedEntryLocator,
    entry_bytes: &[u8],
    signed_request_bytes: &[u8],
) -> Result<[u8; 32], FederationError> {
    let recipient_did_parsed =
        BareDid::parse(recipient_did).map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("invalid recipientDid: {e}"),
        })?;

    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(ENVELOPE_DIGEST_DOMAIN);
    lp_bytes(DELIVER_MESSAGE_NSID.as_bytes(), &mut buf);
    buf.extend_from_slice(header.delivery_id.as_bytes());
    buf.extend_from_slice(header.conversation_id.as_bytes());
    lp_bytes(header.sender_ds_did.as_bytes(), &mut buf);
    lp_bytes(header.receiver_ds_did.as_bytes(), &mut buf);
    lp_bytes(header.sequencer_did.as_bytes(), &mut buf);
    buf.extend_from_slice(&header.sequencer_term.to_be_bytes());

    // Endpoint-specific fields:
    lp_bytes(recipient_did_parsed.as_str().as_bytes(), &mut buf);
    buf.extend_from_slice(locator.entry_id.as_bytes());
    buf.extend_from_slice(&locator.seq.to_be_bytes());
    buf.extend_from_slice(&locator.accepted_payload_sha256);
    buf.extend_from_slice(&locator.outer_entry_fingerprint);

    let entry_sha256: [u8; 32] = Sha256::digest(entry_bytes).into();
    buf.extend_from_slice(&entry_sha256);
    let signed_req_sha256: [u8; 32] = Sha256::digest(signed_request_bytes).into();
    buf.extend_from_slice(&signed_req_sha256);

    let digest: [u8; 32] = Sha256::digest(&buf).into();
    Ok(digest)
}

/// Compute envelope digest for `blue.catbird.mlsDS.deliverWelcome`.
#[allow(clippy::too_many_arguments)]
pub fn compute_welcome_envelope_digest(
    header: &ValidatedEnvelopeHeader,
    recipient_did: &str,
    recipient_device_id: Uuid,
    welcome_id: Uuid,
    recovery_request_id: Uuid,
    key_package_ref: &[u8; 32],
    welcome_bytes: &[u8],
    welcome_sha256: &[u8; 32],
    entry_bytes: &[u8],
    signed_request_bytes: &[u8],
    locator: &ValidatedEntryLocator,
    coordinates: &ConversationCoordinates,
    public_snapshot_sha256: &[u8; 32],
    tree_summary_sha256: &[u8; 32],
) -> Result<[u8; 32], FederationError> {
    let recipient_did_parsed =
        BareDid::parse(recipient_did).map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("invalid recipientDid: {e}"),
        })?;

    if coordinates.group_id.len() != 32
        || coordinates.group_context_hash.len() != 32
        || coordinates.confirmation_tag.len() != 32
    {
        return Err(FederationError::InvalidEnvelope {
            reason: "invalid coordinates crypto lengths".to_string(),
        });
    }

    let actual_welcome_sha256: [u8; 32] = Sha256::digest(welcome_bytes).into();
    if &actual_welcome_sha256 != welcome_sha256 {
        return Err(FederationError::InvalidEnvelope {
            reason: "welcomeSha256 mismatch".to_string(),
        });
    }

    let mut buf = Vec::with_capacity(1024);
    buf.extend_from_slice(ENVELOPE_DIGEST_DOMAIN);
    lp_bytes(DELIVER_WELCOME_NSID.as_bytes(), &mut buf);
    buf.extend_from_slice(header.delivery_id.as_bytes());
    buf.extend_from_slice(header.conversation_id.as_bytes());
    lp_bytes(header.sender_ds_did.as_bytes(), &mut buf);
    lp_bytes(header.receiver_ds_did.as_bytes(), &mut buf);
    lp_bytes(header.sequencer_did.as_bytes(), &mut buf);
    buf.extend_from_slice(&header.sequencer_term.to_be_bytes());

    // Endpoint-specific fields:
    lp_bytes(recipient_did_parsed.as_str().as_bytes(), &mut buf);
    buf.extend_from_slice(recipient_device_id.as_bytes());
    buf.extend_from_slice(welcome_id.as_bytes());
    buf.extend_from_slice(recovery_request_id.as_bytes());
    buf.extend_from_slice(key_package_ref);
    buf.extend_from_slice(welcome_sha256);
    let entry_sha256: [u8; 32] = Sha256::digest(entry_bytes).into();
    buf.extend_from_slice(&entry_sha256);
    let signed_req_sha256: [u8; 32] = Sha256::digest(signed_request_bytes).into();
    buf.extend_from_slice(&signed_req_sha256);
    buf.extend_from_slice(locator.entry_id.as_bytes());
    buf.extend_from_slice(&locator.seq.to_be_bytes());
    buf.extend_from_slice(&locator.accepted_payload_sha256);
    buf.extend_from_slice(&locator.outer_entry_fingerprint);

    buf.extend_from_slice(&(coordinates.generation as u64).to_be_bytes());
    buf.extend_from_slice(&(coordinates.state_version as u64).to_be_bytes());
    buf.extend_from_slice(&coordinates.group_id);
    buf.extend_from_slice(&(coordinates.epoch as u64).to_be_bytes());
    buf.extend_from_slice(&coordinates.group_context_hash);
    buf.extend_from_slice(&coordinates.confirmation_tag);
    buf.extend_from_slice(public_snapshot_sha256);
    buf.extend_from_slice(tree_summary_sha256);

    let digest: [u8; 32] = Sha256::digest(&buf).into();
    Ok(digest)
}

/// Compute envelope digest for `blue.catbird.mlsDS.submitCommit`.
pub fn compute_commit_envelope_digest(
    header: &ValidatedEnvelopeHeader,
    signed_request_bytes: &[u8],
) -> Result<[u8; 32], FederationError> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(ENVELOPE_DIGEST_DOMAIN);
    lp_bytes(SUBMIT_COMMIT_NSID.as_bytes(), &mut buf);
    buf.extend_from_slice(header.delivery_id.as_bytes());
    buf.extend_from_slice(header.conversation_id.as_bytes());
    lp_bytes(header.sender_ds_did.as_bytes(), &mut buf);
    lp_bytes(header.receiver_ds_did.as_bytes(), &mut buf);
    lp_bytes(header.sequencer_did.as_bytes(), &mut buf);
    buf.extend_from_slice(&header.sequencer_term.to_be_bytes());

    // Endpoint-specific fields:
    let signed_req_sha256: [u8; 32] = Sha256::digest(signed_request_bytes).into();
    buf.extend_from_slice(&signed_req_sha256);

    // Extract and bind canonical signed_at from the signedRequest mutation (fail closed)
    let canonical =
        crate::chat_protocol::transcript::decode_canonical_signed_mutation(signed_request_bytes)
            .map_err(|e| FederationError::InvalidEnvelope {
                reason: format!("cannot decode canonical signed mutation: {e}"),
            })?;
    lp_bytes(canonical.signed_at().as_str().as_bytes(), &mut buf);

    let digest: [u8; 32] = Sha256::digest(&buf).into();
    Ok(digest)
}

/// Construct canonical bytes for signing a receipt.
pub fn canonical_receipt_bytes(
    endpoint: &str,
    delivery_id: Uuid,
    conversation_id: Uuid,
    sender_ds_did: &str,
    receiver_ds_did: &str,
    sequencer_did: &str,
    sequencer_term: u64,
    envelope_sha256: &[u8; 32],
    result_sha256: &[u8; 32],
    source_locator: Option<&ValidatedEntryLocator>,
    completed_at_rfc3339: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(RECEIPT_SIGNING_DOMAIN);
    lp_bytes(b"1", &mut buf);
    lp_bytes(endpoint.as_bytes(), &mut buf);
    buf.extend_from_slice(delivery_id.as_bytes());
    buf.extend_from_slice(conversation_id.as_bytes());
    lp_bytes(sender_ds_did.as_bytes(), &mut buf);
    lp_bytes(receiver_ds_did.as_bytes(), &mut buf);
    lp_bytes(sequencer_did.as_bytes(), &mut buf);
    buf.extend_from_slice(&sequencer_term.to_be_bytes());
    buf.extend_from_slice(envelope_sha256);
    buf.extend_from_slice(result_sha256);

    if let Some(loc) = source_locator {
        buf.push(1u8);
        buf.extend_from_slice(loc.entry_id.as_bytes());
        buf.extend_from_slice(&loc.seq.to_be_bytes());
        buf.extend_from_slice(&loc.accepted_payload_sha256);
        buf.extend_from_slice(&loc.outer_entry_fingerprint);
    } else {
        buf.push(0u8);
    }

    lp_bytes(completed_at_rfc3339.as_bytes(), &mut buf);
    buf
}

/// Produce a signed [`FederationReceiptV1`].
#[allow(clippy::too_many_arguments)]
pub fn sign_receipt(
    signer: &AckSigner,
    endpoint: &str,
    delivery_id: Uuid,
    conversation_id: Uuid,
    sender_ds_did: &str,
    receiver_ds_did: &str,
    sequencer_did: &str,
    sequencer_term: u64,
    envelope_sha256: [u8; 32],
    result_sha256: [u8; 32],
    source_locator: ValidatedEntryLocator,
    completed_at: DateTime<Utc>,
) -> Result<FederationReceiptV1, FederationError> {
    let completed_at_dt = crate::sqlx_jacquard::chrono_to_datetime(completed_at);
    let canonical = canonical_receipt_bytes(
        endpoint,
        delivery_id,
        conversation_id,
        sender_ds_did,
        receiver_ds_did,
        sequencer_did,
        sequencer_term,
        &envelope_sha256,
        &result_sha256,
        Some(&source_locator),
        completed_at_dt.as_str(),
    );

    let sig_bytes = signer.sign_canonical_bytes(&canonical);

    let generated_locator = EntryLocatorV1 {
        accepted_payload_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(
            &source_locator.accepted_payload_sha256,
        ),
        entry_id: jacquard_common::deps::smol_str::SmolStr::from(
            source_locator.entry_id.hyphenated().to_string(),
        ),
        outer_entry_fingerprint: jacquard_common::deps::bytes::Bytes::copy_from_slice(
            &source_locator.outer_entry_fingerprint,
        ),
        seq: source_locator.seq as i64,
        extra_data: None,
    };

    Ok(FederationReceiptV1 {
        completed_at: completed_at_dt,
        conversation_id: jacquard_common::deps::smol_str::SmolStr::from(
            conversation_id.hyphenated().to_string(),
        ),
        delivery_id: jacquard_common::deps::smol_str::SmolStr::from(
            delivery_id.hyphenated().to_string(),
        ),
        endpoint: jacquard_common::deps::smol_str::SmolStr::from(endpoint),
        envelope_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(&envelope_sha256),
        protocol_version: jacquard_common::deps::smol_str::SmolStr::from("1"),
        receiver_ds_did: jacquard_common::types::string::Did::new_owned(
            receiver_ds_did.to_string(),
        )
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("invalid receiverDsDid: {e}"),
        })?,
        result_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(&result_sha256),
        sender_ds_did: jacquard_common::types::string::Did::new_owned(sender_ds_did.to_string())
            .map_err(|e| FederationError::InvalidEnvelope {
                reason: format!("invalid senderDsDid: {e}"),
            })?,
        sequencer_did: jacquard_common::types::string::Did::new_owned(sequencer_did.to_string())
            .map_err(|e| FederationError::InvalidEnvelope {
                reason: format!("invalid sequencerDid: {e}"),
            })?,
        sequencer_term: sequencer_term as i64,
        signature: jacquard_common::deps::bytes::Bytes::copy_from_slice(&sig_bytes),
        source_locator: generated_locator,
        extra_data: None,
    })
}

/// Verify a [`FederationReceiptV1`] signature against a known public verifying key.
pub fn verify_receipt(
    receipt: &FederationReceiptV1,
    verifying_key: &VerifyingKey,
) -> Result<bool, FederationError> {
    if receipt.protocol_version.as_str() != "1" {
        return Ok(false);
    }
    if receipt.signature.len() != 64 {
        return Ok(false);
    }
    if receipt.envelope_sha256.len() != 32 || receipt.result_sha256.len() != 32 {
        return Ok(false);
    }

    let delivery_id = Uuid::from_str(receipt.delivery_id.as_str()).map_err(|_| {
        FederationError::InvalidEnvelope {
            reason: "invalid deliveryId in receipt".to_string(),
        }
    })?;
    let conversation_id = Uuid::from_str(receipt.conversation_id.as_str()).map_err(|_| {
        FederationError::InvalidEnvelope {
            reason: "invalid conversationId in receipt".to_string(),
        }
    })?;

    let validated_locator = validate_entry_locator(&receipt.source_locator)?;

    let mut envelope_sha256 = [0u8; 32];
    envelope_sha256.copy_from_slice(&receipt.envelope_sha256);
    let mut result_sha256 = [0u8; 32];
    result_sha256.copy_from_slice(&receipt.result_sha256);

    let completed_at_str = receipt.completed_at.as_str();

    let canonical = canonical_receipt_bytes(
        receipt.endpoint.as_str(),
        delivery_id,
        conversation_id,
        receipt.sender_ds_did.as_str(),
        receipt.receiver_ds_did.as_str(),
        receipt.sequencer_did.as_str(),
        receipt.sequencer_term as u64,
        &envelope_sha256,
        &result_sha256,
        Some(&validated_locator),
        completed_at_str,
    );

    let signature = match Signature::from_slice(&receipt.signature) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    Ok(verifying_key.verify(&canonical, &signature).is_ok())
}
