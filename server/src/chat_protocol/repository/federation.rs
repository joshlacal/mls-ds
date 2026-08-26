//! PostgreSQL repository primitives for clean-chat federation operations.
//!
//! Implements delivery ID deduplication, preprovisioned Welcome verification (Choice C),
//! exact message replication, and sequencer commit execution.

use std::str::FromStr;

use catbird_atproto::generated::blue_catbird::chat::{
    CommitEntry, ConversationCoordinates, DeviceId, OperationId,
};
use catbird_atproto::generated::blue_catbird::mlsDS::{
    deliver_message::DeliverMessageOutput, deliver_welcome::DeliverWelcomeOutput,
    submit_commit::SubmitCommitOutput, EntryLocatorV1, EnvelopeHeaderV1, FederationReceiptV1,
};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::blobs::{self, BindingKind, BlobPurpose, NewBlobBinding};
use super::delivery::{
    append_exact_application_entry, compare_exact_application_entry, AppendEntry, ApplicationSend,
};
use super::execution_context::{
    apply_prepared_submit_transition_execution, prepare_submit_transition_execution,
};
use super::prelude::PreludeError;
use super::submit_transition::{
    canonical_response_from_plan, canonical_uuid_v4, hydrate_terminal_recovery_packages,
    parse_submit_transition, validate_applied_transition, SubmitTransitionFacadeError,
};
use super::{
    auth::{self, CompletedIdempotentResponse},
    prelude,
};
use crate::chat_protocol::dpop::VerifiedChatDeviceRequest;
use crate::chat_protocol::relationship_policy::{PublicTransport, RelationshipAuthority};
use crate::chat_protocol::snapshot::PublicGroupSnapshotLifecycle;
use crate::chat_protocol::state_machine::{FederatedOperationAdmission, HydrationAuthority};
use crate::chat_protocol::transcript::{
    build_verified_control_entry, decode_and_verify_application_entry,
    decode_and_verify_control_entry, decode_and_verify_signed_mutation,
    decode_canonical_signed_mutation, rebind_persisted_application_entry,
    rebind_persisted_control_entry, CanonicalControlEntryProducts, CanonicalControlServerFields,
    CanonicalSignedMutation, CanonicalValueRef, ControlEntryKind, SignedMutationKind,
    VerifiedApplicationEntry, VerifiedMutationProjection, VerifiedSignedMutation,
};
use crate::chat_protocol::validation::{
    BareDid, CanonicalTimestamp, CanonicalUuidV4, KeyThumbprint, TrustedRequestInstant,
    ValidatedChatNsid, MAX_SAFE_INTEGER,
};
use crate::federation::ack::AckSigner;
use crate::federation::envelope::{
    canonical_receipt_bytes, compute_commit_envelope_digest, compute_message_envelope_digest,
    compute_welcome_envelope_digest, sign_receipt, validate_entry_locator,
    validate_envelope_header, ValidatedEntryLocator, ValidatedEnvelopeHeader, DELIVER_MESSAGE_NSID,
    DELIVER_WELCOME_NSID, SUBMIT_COMMIT_NSID,
};
use crate::federation::errors::FederationError;
use crate::identity::{canonical_did, dids_equivalent, service_did_base};

/// Acquire a transaction-scoped advisory lock on a delivery ID.
pub async fn lock_delivery_id(
    tx: &mut Transaction<'_, Postgres>,
    delivery_id: Uuid,
) -> Result<(), FederationError> {
    let lock_key = format!("federation-delivery-id:{delivery_id}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(lock_key)
        .execute(&mut **tx)
        .await
        .map_err(FederationError::Database)?;
    Ok(())
}

/// Check if an exact delivery receipt already exists, returning the stored response bytes on replay.
/// Revalidates the stored receipt digest, envelope metadata, and (when supplied) the source locator.
/// For submitCommit the source locator is only known after the transition is planned and applied,
/// so it is matched with `None`; for message/welcome deliveries the locator must match exactly.
pub async fn check_delivery_receipt(
    tx: &mut Transaction<'_, Postgres>,
    endpoint: &str,
    header: &ValidatedEnvelopeHeader,
    envelope_digest: &[u8; 32],
    source_locator: Option<&ValidatedEntryLocator>,
) -> Result<Option<Vec<u8>>, FederationError> {
    let row: Option<(
        String,
        Uuid,
        String,
        String,
        String,
        i64,
        Vec<u8>,
        Vec<u8>,
        Uuid,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        DateTime<Utc>,
    )> = sqlx::query_as(
        r#"
        SELECT endpoint_nsid, conversation_id, sender_ds_did, receiver_ds_did,
               sequencer_did, sequencer_term, envelope_sha256, result_sha256,
               source_entry_id, source_entry_seq, source_entry_fingerprint,
               response_bytes, response_sha256, receipt_signature, completed_at
          FROM chat.federation_delivery_receipts
         WHERE delivery_id = $1
        "#,
    )
    .bind(header.delivery_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    let Some((
        stored_endpoint,
        stored_convo,
        stored_sender,
        stored_receiver,
        stored_sequencer,
        stored_term,
        stored_envelope_sha256,
        _stored_result_sha256,
        stored_source_entry_id,
        stored_source_entry_seq,
        stored_source_entry_fingerprint,
        stored_response_bytes,
        stored_response_sha256,
        stored_signature,
        _stored_completed_at,
    )) = row
    else {
        return Ok(None);
    };

    if stored_endpoint != endpoint
        || stored_convo != header.conversation_id
        || stored_sender != header.sender_ds_did
        || stored_receiver != header.receiver_ds_did
        || stored_sequencer != header.sequencer_did
        || stored_term as u64 != header.sequencer_term
        || stored_envelope_sha256 != envelope_digest
    {
        return Err(FederationError::DeliveryConflict {
            reason: "envelope metadata differs from prior delivery with same deliveryId"
                .to_string(),
        });
    }

    // On submitCommit replay the conversation has advanced, so the freshly
    // re-derived source locator legitimately differs from the locator stored at
    // first execution. For message/welcome deliveries the locator is an input
    // of the envelope digest and must match the stored receipt exactly.
    if let Some(source_locator) = source_locator {
        if stored_source_entry_id != source_locator.entry_id
            || stored_source_entry_seq != source_locator.seq as i64
            || stored_source_entry_fingerprint != source_locator.outer_entry_fingerprint.to_vec()
        {
            return Err(FederationError::DeliveryConflict {
                reason: "entry locator differs from prior delivery with same deliveryId"
                    .to_string(),
            });
        }
    }

    // Revalidate stored response digest and signature length
    let computed_response_sha256: [u8; 32] = Sha256::digest(&stored_response_bytes).into();
    if stored_response_sha256 != computed_response_sha256 || stored_signature.len() != 64 {
        return Err(FederationError::DeliveryConflict {
            reason: "stored receipt digest or signature validation failed".to_string(),
        });
    }

    Ok(Some(stored_response_bytes))
}

/// Insert an immutable federation delivery receipt with mandatory non-null source locator.
pub async fn insert_delivery_receipt(
    tx: &mut Transaction<'_, Postgres>,
    receipt: &FederationReceiptV1,
    source_locator: &ValidatedEntryLocator,
    response_bytes: &[u8],
) -> Result<(), FederationError> {
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

    let response_sha256: [u8; 32] = Sha256::digest(response_bytes).into();

    let completed_at_dt = DateTime::parse_from_rfc3339(receipt.completed_at.as_str())
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("invalid completedAt: {e}"),
        })?
        .with_timezone(&Utc);

    sqlx::query(
        r#"
        INSERT INTO chat.federation_delivery_receipts (
            delivery_id, endpoint_nsid, conversation_id, sender_ds_did, receiver_ds_did,
            sequencer_did, sequencer_term, envelope_sha256, result_sha256,
            source_entry_id, source_entry_seq, source_entry_fingerprint,
            response_bytes, response_sha256, receipt_signature, completed_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
        )
        "#,
    )
    .bind(delivery_id)
    .bind(receipt.endpoint.as_str())
    .bind(conversation_id)
    .bind(receipt.sender_ds_did.as_str())
    .bind(receipt.receiver_ds_did.as_str())
    .bind(receipt.sequencer_did.as_str())
    .bind(receipt.sequencer_term)
    .bind(&*receipt.envelope_sha256)
    .bind(&*receipt.result_sha256)
    .bind(source_locator.entry_id)
    .bind(source_locator.seq as i64)
    .bind(&source_locator.outer_entry_fingerprint[..])
    .bind(response_bytes)
    .bind(&response_sha256)
    .bind(&*receipt.signature)
    .bind(completed_at_dt)
    .execute(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    Ok(())
}

/// Deliver and verify an inbound MLS Welcome message for a preprovisioned local recipient (Choice C).
#[allow(clippy::too_many_arguments)]
pub async fn deliver_welcome_mailbox(
    tx: &mut Transaction<'_, Postgres>,
    ack_signer: &AckSigner,
    header: ValidatedEnvelopeHeader,
    recipient_did: String,
    recipient_device_id: Uuid,
    welcome_id: Uuid,
    recovery_request_id: Uuid,
    key_package_ref: [u8; 32],
    welcome_bytes: Vec<u8>,
    welcome_sha256: [u8; 32],
    entry_bytes: Vec<u8>,
    signed_request_bytes: Vec<u8>,
    entry_locator: ValidatedEntryLocator,
    coordinates: ConversationCoordinates,
    public_snapshot_sha256: [u8; 32],
    tree_summary_sha256: [u8; 32],
) -> Result<DeliverWelcomeOutput, FederationError> {
    lock_delivery_id(tx, header.delivery_id).await?;

    // On deliveries, authenticated senderDsDid MUST equal header sequencerDid
    if !dids_equivalent(&header.sender_ds_did, &header.sequencer_did) {
        return Err(FederationError::InvalidEnvelope {
            reason: format!(
                "senderDsDid '{}' does not equal sequencerDid '{}' on inbound delivery",
                header.sender_ds_did, header.sequencer_did
            ),
        });
    }

    let envelope_digest = compute_welcome_envelope_digest(
        &header,
        &recipient_did,
        recipient_device_id,
        welcome_id,
        recovery_request_id,
        &key_package_ref,
        &welcome_bytes,
        &welcome_sha256,
        &entry_bytes,
        &signed_request_bytes,
        &entry_locator,
        &coordinates,
        &public_snapshot_sha256,
        &tree_summary_sha256,
    )?;

    if header.payload_sha256 != envelope_digest {
        return Err(FederationError::InvalidEnvelope {
            reason: "payloadSha256 does not match computed envelope digest".to_string(),
        });
    }

    if let Some(cached_bytes) = check_delivery_receipt(
        tx,
        DELIVER_WELCOME_NSID,
        &header,
        &envelope_digest,
        Some(&entry_locator),
    )
    .await?
    {
        let cached_output: DeliverWelcomeOutput =
            serde_json::from_slice(&cached_bytes).map_err(FederationError::Json)?;
        return Ok(cached_output);
    }

    // 1. One locked exact provenance join locking all relevant tables:
    // welcome_deliveries, welcome_bundles, key_packages, key_package_reservations,
    // devices, participants, conversations, transitions, entries, generation_states.
    #[derive(sqlx::FromRow)]
    struct LockedWelcomeProvenanceRow {
        d_status: String,
        d_terminal_at: Option<DateTime<Utc>>,
        d_expires_at: DateTime<Utc>,
        d_key_package_ref: Vec<u8>,
        stored_welcome_data: Vec<u8>,
        stored_welcome_sha256: Vec<u8>,
        stored_gen: i64,
        stored_sv: i64,
        stored_epoch: i64,
        stored_gid: Vec<u8>,
        stored_gch: Vec<u8>,
        stored_ctag: Vec<u8>,
        stored_transition_id: Uuid,
        stored_entry_seq: i64,
        dev_status: String,
        dev_revoked_at: Option<DateTime<Utc>>,
        p_status: String,
        p_ds_did: Option<String>,
        has_active_leaf: bool,
        kp_status: String,
        kp_terminal_at: Option<DateTime<Utc>>,
        kp_not_after: DateTime<Utc>,
        kp_terminal_transition_id: Option<Uuid>,
        kpr_status: String,
        kpr_terminal_at: Option<DateTime<Utc>>,
        kpr_expires_at: DateTime<Utc>,
        kpr_consumed_transition_id: Option<Uuid>,
        lrr_status: String,
        lrr_terminal_at: Option<DateTime<Utc>>,
        lrr_expires_at: DateTime<Utc>,
        lrr_fulfilling_transition_id: Option<Uuid>,
        is_remote: bool,
        sequencer_ds: Option<String>,
        sequencer_term: i64,
        convo_sv: i64,
        transition_kind: String,
        stored_entry_id: Uuid,
        stored_seq: i64,
        stored_accepted_payload: Vec<u8>,
        stored_accepted_payload_sha256: Vec<u8>,
        stored_signed_request: Vec<u8>,
        stored_outer_fp: Vec<u8>,
        state_gid: Vec<u8>,
        state_epoch: i64,
        stored_snap_sha256: Vec<u8>,
        stored_tree_sha256: Vec<u8>,
    }

    let row: Option<LockedWelcomeProvenanceRow> = sqlx::query_as(
        r#"
        SELECT d.status AS d_status, d.terminal_at AS d_terminal_at, d.expires_at AS d_expires_at, d.key_package_ref AS d_key_package_ref,
               b.wrapper_bytes AS stored_welcome_data, b.wrapper_sha256 AS stored_welcome_sha256, b.generation AS stored_gen, b.state_version AS stored_sv, b.epoch AS stored_epoch, b.group_id AS stored_gid,
               b.group_context_hash AS stored_gch, b.confirmation_tag AS stored_ctag, b.transition_id AS stored_transition_id, b.entry_seq AS stored_entry_seq,
               dev.status AS dev_status, dev.revoked_at AS dev_revoked_at,
               p.status AS p_status, p.ds_did AS p_ds_did,
               (md.leaf_period_id IS NOT NULL) AS has_active_leaf,
               kp.status AS kp_status, kp.terminal_at AS kp_terminal_at, kp.not_after AS kp_not_after, kp.terminal_transition_id AS kp_terminal_transition_id,
               kpr.status AS kpr_status, kpr.terminal_at AS kpr_terminal_at, kpr.expires_at AS kpr_expires_at, kpr.consumed_transition_id AS kpr_consumed_transition_id,
               lrr.status AS lrr_status, lrr.terminal_at AS lrr_terminal_at, lrr.expires_at AS lrr_expires_at, lrr.fulfilling_transition_id AS lrr_fulfilling_transition_id,
               c.is_remote AS is_remote, c.sequencer_ds AS sequencer_ds, c.sequencer_term AS sequencer_term, c.current_generation AS convo_gen, c.current_state_version AS convo_sv,
               t.kind AS transition_kind,
               e.entry_id AS stored_entry_id, e.seq AS stored_seq, e.accepted_payload_bytes AS stored_accepted_payload, e.accepted_payload_sha256 AS stored_accepted_payload_sha256, e.signed_request_bytes AS stored_signed_request, e.outer_entry_fingerprint AS stored_outer_fp,
               s.group_id AS state_gid, s.epoch AS state_epoch, s.snapshot_sha256 AS stored_snap_sha256, s.tree_summary_sha256 AS stored_tree_sha256
          FROM chat.welcome_deliveries d
          JOIN chat.welcome_bundles b ON b.welcome_id = d.welcome_id
          JOIN chat.key_packages kp ON kp.key_package_ref = d.key_package_ref AND kp.owner_did = d.recipient_did AND kp.owner_device_id = d.recipient_device_id
          JOIN chat.key_package_reservations kpr ON kpr.key_package_ref = d.key_package_ref AND kpr.recipient_did = d.recipient_did AND kpr.recipient_device_id = d.recipient_device_id AND kpr.conversation_id = b.conversation_id AND kpr.recovery_request_id = d.recovery_request_id
          JOIN chat.leaf_recovery_requests lrr ON lrr.recovery_request_id = d.recovery_request_id AND lrr.conversation_id = b.conversation_id AND lrr.requester_did = d.recipient_did AND lrr.requester_device_id = d.recipient_device_id
          JOIN chat.devices dev ON dev.user_did = d.recipient_did AND dev.device_id = d.recipient_device_id
          JOIN chat.participants p ON p.conversation_id = b.conversation_id AND p.user_did = d.recipient_did AND p.current_membership = TRUE
          JOIN chat.member_devices md ON md.conversation_id = b.conversation_id AND md.user_did = d.recipient_did AND md.device_id = d.recipient_device_id AND md.active = TRUE AND md.removed_at IS NULL
          JOIN chat.conversations c ON c.conversation_id = b.conversation_id
          JOIN chat.transitions t ON t.conversation_id = b.conversation_id AND t.transition_id = b.transition_id
          JOIN chat.entries e ON e.conversation_id = b.conversation_id AND e.seq = b.entry_seq AND e.entry_id = b.transition_id
          JOIN chat.generation_states s ON s.conversation_id = b.conversation_id AND s.generation = b.generation AND s.state_version = b.state_version AND s.producing_transition_id = b.transition_id
         WHERE d.welcome_id = $1 AND d.recipient_device_id = $2 AND d.recovery_request_id = $3
           AND b.conversation_id = $4
         FOR UPDATE OF c, p, dev, d, b, t, e, s, kp, kpr, md, lrr
        "#,
    )
    .bind(welcome_id)
    .bind(recipient_device_id)
    .bind(recovery_request_id)
    .bind(header.conversation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    let Some(r) = row else {
        return Err(FederationError::MailboxNotProvisioned {
            reason: "preprovisioned welcome provenance graph not found on destination DS"
                .to_string(),
        });
    };
    let is_quarantined = super::core::is_conversation_quarantined(tx, header.conversation_id)
        .await
        .map_err(FederationError::Database)?;
    if is_quarantined {
        return Err(FederationError::DeliveryConflict {
            reason: format!("conversation {} is quarantined", header.conversation_id),
        });
    }

    let d_status = r.d_status;
    let d_terminal_at = r.d_terminal_at;
    let d_expires_at = r.d_expires_at;
    let d_kp_ref = r.d_key_package_ref;
    let stored_welcome_data = r.stored_welcome_data;
    let stored_welcome_sha256 = r.stored_welcome_sha256;
    let stored_gen = r.stored_gen;
    let stored_sv = r.stored_sv;
    let stored_epoch = r.stored_epoch;
    let stored_gid = r.stored_gid;
    let stored_transition_id = r.stored_transition_id;
    let stored_entry_id = r.stored_entry_id;
    let stored_entry_seq = r.stored_entry_seq;
    let stored_accepted_payload_sha256 = r.stored_accepted_payload_sha256;
    let stored_outer_fp = r.stored_outer_fp;
    let dev_status = r.dev_status;
    let dev_revoked_at = r.dev_revoked_at;
    let p_status = r.p_status;
    let p_ds_did = r.p_ds_did;
    let has_active_leaf = r.has_active_leaf;
    let kp_status = r.kp_status;
    let kp_terminal_at = r.kp_terminal_at;
    let kp_not_after = r.kp_not_after;
    let kp_terminal_transition_id = r.kp_terminal_transition_id;
    let kpr_status = r.kpr_status;
    let kpr_terminal_at = r.kpr_terminal_at;
    let kpr_consumed_transition_id = r.kpr_consumed_transition_id;
    let lrr_status = r.lrr_status;
    let lrr_terminal_at = r.lrr_terminal_at;
    let lrr_fulfilling_transition_id = r.lrr_fulfilling_transition_id;
    let is_remote = r.is_remote;
    let sequencer_ds = r.sequencer_ds;
    let sequencer_term = r.sequencer_term;
    let state_gid = r.state_gid;
    let state_epoch = r.state_epoch;
    let stored_snap_sha256 = r.stored_snap_sha256;
    let stored_tree_sha256 = r.stored_tree_sha256;

    // Verify conversation routing and sequencer match
    if !is_remote
        || sequencer_ds.as_deref() != Some(&header.sequencer_did)
        || !dids_equivalent(&header.sender_ds_did, sequencer_ds.as_deref().unwrap_or(""))
    {
        return Err(FederationError::MailboxNotProvisioned {
            reason: "conversation is not provisioned as a remote mailbox for this sequencer"
                .to_string(),
        });
    }

    if sequencer_term as u64 != header.sequencer_term {
        return Err(FederationError::TermStale {
            convo_id: header.conversation_id.to_string(),
            provided_term: header.sequencer_term as i64,
            current_term: sequencer_term,
        });
    }

    // Verify delivery is pending and unexpired
    if d_status != "pending" || d_terminal_at.is_some() {
        return Err(FederationError::DeliveryConflict {
            reason: format!("welcome delivery status is {d_status}, expected pending"),
        });
    }
    let now = Utc::now();
    if d_expires_at <= now {
        return Err(FederationError::DeliveryConflict {
            reason: "welcome delivery has expired".to_string(),
        });
    }

    // Verify recipient device is active and unrevoked
    if dev_status != "active" || dev_revoked_at.is_some() {
        return Err(FederationError::MailboxNotProvisioned {
            reason: format!(
                "recipient device status is {dev_status}, expected active and unrevoked"
            ),
        });
    }

    // Verify recipient is a LOCAL participant (ds_did NULL or the local service DID)
    // with an ACTIVE member leaf in the MLS group.
    let self_base_did = service_did_base();
    let recipient_is_local =
        p_ds_did.is_none() || dids_equivalent(p_ds_did.as_deref().unwrap_or(""), &self_base_did);
    if !recipient_is_local {
        return Err(FederationError::UnauthorizedRecipient {
            reason: format!(
                "recipient participant ds_did {:?} is not local on this destination DS",
                p_ds_did
            ),
        });
    }
    if !has_active_leaf {
        return Err(FederationError::MailboxNotProvisioned {
            reason: "recipient has no active member leaf in this conversation".to_string(),
        });
    }

    // Verify recipient participant is active or pending
    if p_status != "pending" && p_status != "active" {
        return Err(FederationError::MailboxNotProvisioned {
            reason: format!("recipient status is {p_status}, expected pending or active"),
        });
    }

    // Enforce key package / reservation / leaf recovery status and terminality exact recovery lifecycle
    if kp_not_after <= now {
        return Err(FederationError::MailboxNotProvisioned {
            reason: "recipient key package is expired".to_string(),
        });
    }

    if lrr_status == "cancelled" || lrr_status == "expired" {
        return Err(FederationError::MailboxNotProvisioned {
            reason: format!("leaf recovery request is {lrr_status}"),
        });
    }
    if lrr_status == "fulfilled" && lrr_fulfilling_transition_id != Some(stored_transition_id) {
        return Err(FederationError::DeliveryConflict {
            reason: format!(
                "leaf recovery request fulfilled by transition {:?}, expected {stored_transition_id}",
                lrr_fulfilling_transition_id
            ),
        });
    }
    if lrr_status != "fulfilled" && lrr_status != "open" {
        return Err(FederationError::MailboxNotProvisioned {
            reason: format!(
                "leaf recovery request status is {lrr_status}, expected fulfilled or open"
            ),
        });
    }

    if kpr_status == "cancelled" || kpr_status == "expired" {
        return Err(FederationError::MailboxNotProvisioned {
            reason: format!("key package reservation is {kpr_status}"),
        });
    }
    if kpr_status == "consumed" && kpr_consumed_transition_id != Some(stored_transition_id) {
        return Err(FederationError::DeliveryConflict {
            reason: format!(
                "key package reservation consumed by transition {:?}, expected {stored_transition_id}",
                kpr_consumed_transition_id
            ),
        });
    }
    if kpr_status != "consumed" && kpr_status != "active" {
        return Err(FederationError::MailboxNotProvisioned {
            reason: format!(
                "key package reservation status is {kpr_status}, expected consumed or active"
            ),
        });
    }

    if kp_status == "revoked" || kp_status == "available" || kp_status == "expired" {
        return Err(FederationError::MailboxNotProvisioned {
            reason: format!("key package status is {kp_status}"),
        });
    }
    if kp_status == "consumed" && kp_terminal_transition_id != Some(stored_transition_id) {
        return Err(FederationError::DeliveryConflict {
            reason: format!(
                "key package consumed by transition {:?}, expected {stored_transition_id}",
                kp_terminal_transition_id
            ),
        });
    }
    if kp_status != "consumed" && kp_status != "reserved" {
        return Err(FederationError::MailboxNotProvisioned {
            reason: format!("key package status is {kp_status}, expected consumed or reserved"),
        });
    }

    // Verify welcome bytes and entry locator
    let computed_welcome_sha256: [u8; 32] = Sha256::digest(&welcome_bytes).into();
    let computed_entry_sha256: [u8; 32] = Sha256::digest(&entry_bytes).into();

    // The Welcome must be a REAL MLS Welcome bound to exactly the reserved
    // key package ref, not merely byte-for-byte equal to the stored bundle.
    crate::chat_protocol::public_state::verify_recovery_welcome(
        &welcome_bytes,
        key_package_ref,
        crate::chat_protocol::wire::MAX_WELCOME_WIRE_BYTES,
    )
    .map_err(|e| FederationError::InvalidEnvelope {
        reason: format!("welcome is not a valid MLS Welcome for the reserved key package: {e:?}"),
    })?;

    if computed_welcome_sha256 != welcome_sha256
        || computed_entry_sha256 != entry_locator.accepted_payload_sha256
        || stored_welcome_data != welcome_bytes
        || stored_welcome_sha256 != welcome_sha256
        || d_kp_ref != key_package_ref
        || stored_entry_seq != entry_locator.seq as i64
        || stored_entry_id != entry_locator.entry_id
        || stored_accepted_payload_sha256 != entry_locator.accepted_payload_sha256
        || stored_outer_fp != entry_locator.outer_entry_fingerprint
        || stored_gen != coordinates.generation
        || stored_sv != coordinates.state_version
        || stored_epoch != coordinates.epoch
        || stored_gid != coordinates.group_id.as_ref()
        || state_gid != coordinates.group_id.as_ref()
        || state_epoch != coordinates.epoch
        || stored_snap_sha256 != public_snapshot_sha256
        || stored_tree_sha256 != tree_summary_sha256
    {
        return Err(FederationError::DeliveryConflict {
            reason: "welcome delivery material does not match preprovisioned bundle or coordinates"
                .to_string(),
        });
    }

    // 2. Decode and verify signed mutation + control entry, and rebind
    let mutation = decode_canonical_signed_mutation(&signed_request_bytes).map_err(|e| {
        FederationError::InvalidEnvelope {
            reason: format!("cannot decode signed request in welcome: {e}"),
        }
    })?;

    let actor_did = mutation.actor_did().as_str();
    let actor_device_id = Uuid::from_bytes(*mutation.actor_device_id().as_bytes());
    let actor_key_id = mutation.key_id().as_str();

    let key_row: Option<(Vec<u8>, i64)> = sqlx::query_as(
        r#"
        SELECT dk.signing_public_key, dk.enrollment_auth_generation
          FROM chat.device_keys dk
          JOIN chat.devices d ON d.user_did = dk.user_did AND d.device_id = dk.device_id
         WHERE dk.user_did = $1 AND dk.device_id = $2 AND dk.key_id = $3
           AND dk.revoked_at IS NULL AND d.status = 'active' AND d.revoked_at IS NULL
         FOR UPDATE
        "#,
    )
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(actor_key_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    let Some((actor_public_key, enrollment_auth_generation)) = key_row else {
        return Err(FederationError::MailboxNotProvisioned {
            reason: "actor device key not provisioned or revoked on destination DS".to_string(),
        });
    };

    if mutation.auth_generation() as i64 != enrollment_auth_generation {
        return Err(FederationError::InvalidEnvelope {
            reason: "auth_generation does not match stored enrollment generation".to_string(),
        });
    }

    let _verified_mutation =
        decode_and_verify_signed_mutation(&signed_request_bytes, &actor_public_key).map_err(
            |e| FederationError::InvalidEnvelope {
                reason: format!("signed mutation verification failed in welcome: {e}"),
            },
        )?;

    let verified_control = decode_and_verify_control_entry(&entry_bytes, &actor_public_key)
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("control entry verification failed in welcome: {e}"),
        })?;

    let rebound =
        rebind_persisted_control_entry(verified_control, &signed_request_bytes, &actor_public_key)
            .map_err(|e| FederationError::InvalidEnvelope {
                reason: format!("control entry rebind failed in welcome: {e}"),
            })?;

    let rebound_convo_id =
        CanonicalUuidV4::parse(rebound.conversation_id().as_str()).map_err(|_| {
            FederationError::InvalidEnvelope {
                reason: "invalid conversation_id in rebound entry".to_string(),
            }
        })?;
    let rebound_entry_id = CanonicalUuidV4::parse(rebound.entry_id().as_str()).map_err(|_| {
        FederationError::InvalidEnvelope {
            reason: "invalid entry_id in rebound entry".to_string(),
        }
    })?;

    if Uuid::from_str(rebound_convo_id.as_str()).unwrap() != header.conversation_id
        || Uuid::from_str(rebound_entry_id.as_str()).unwrap() != entry_locator.entry_id
        || rebound.seq() != entry_locator.seq
        || rebound.outer_control_fingerprint() != &entry_locator.outer_entry_fingerprint
    {
        return Err(FederationError::DeliveryConflict {
            reason: "rebound entry does not match entry locator or header".to_string(),
        });
    }

    // 3. Build and sign federation receipt with required non-null source locator.
    let now = Utc::now();
    let result_sha256: [u8; 32] = Sha256::digest(b"{\"accepted\":true}").into();
    let receipt = sign_receipt(
        ack_signer,
        DELIVER_WELCOME_NSID,
        header.delivery_id,
        header.conversation_id,
        &header.sender_ds_did,
        &header.receiver_ds_did,
        &header.sequencer_did,
        header.sequencer_term,
        envelope_digest,
        result_sha256,
        entry_locator.clone(),
        now,
    )?;

    let output = DeliverWelcomeOutput {
        accepted: true,
        receipt,
        extra_data: None,
    };

    let response_bytes = serde_json::to_vec(&output).map_err(FederationError::Json)?;

    insert_delivery_receipt(tx, &output.receipt, &entry_locator, &response_bytes).await?;

    Ok(output)
}

/// Arbitration for one inbound federated operation sharing the exact
/// `chat.operation_claims`/`chat.idempotency_records` lifecycle with the local
/// signed-operation prelude.
pub(crate) enum FederatedOperationArbitration {
    First(FederatedOperationReservationGuard),
    Replay(CompletedIdempotentResponse),
}

/// Non-forgeable claim on one operation id in one transaction for the federated
/// (DS-to-DS) submitCommit path. Mirrors `OperationReservationGuard` but is
/// derived from the sealed `FederatedOperationAdmission` rather than a local
/// `VerifiedChatDeviceRequest`.
pub(crate) struct FederatedOperationReservationGuard {
    operation_lock: auth::CanonicalOperationReservationGuard,
    binding: FederatedOperationClaimBinding,
}

impl std::fmt::Debug for FederatedOperationReservationGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FederatedOperationReservationGuard(<sealed>)")
    }
}

impl FederatedOperationReservationGuard {
    pub(crate) fn binding(&self) -> &FederatedOperationClaimBinding {
        &self.binding
    }
}

/// Exact immutable claim binding for a federated commit. The fields are the
/// same authoritative values `OperationClaimBinding` records.
#[derive(Clone, Debug)]
pub(crate) struct FederatedOperationClaimBinding {
    operation_id: Uuid,
    principal_did: String,
    endpoint_nsid: String,
    mutation_kind: String,
    request_digest: [u8; 32],
    accepted_request_sha256: [u8; 32],
    signature: [u8; 64],
    claimed_at: DateTime<Utc>,
}

impl FederatedOperationClaimBinding {
    pub(crate) fn operation_id(&self) -> Uuid {
        self.operation_id
    }
    pub(crate) fn principal_did(&self) -> &str {
        &self.principal_did
    }
    pub(crate) fn endpoint_nsid(&self) -> &str {
        &self.endpoint_nsid
    }
    pub(crate) fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
    pub(crate) fn accepted_request_sha256(&self) -> &[u8; 32] {
        &self.accepted_request_sha256
    }
    pub(crate) fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
    pub(crate) fn claimed_at(&self) -> DateTime<Utc> {
        self.claimed_at
    }
}

/// Reserve the global operation lock and reconcile an exact existing claim for a
/// federated commit before any transition planning. A `Replay` arm means a prior
/// delivery already completed this operation: the caller must reproduce the
/// stored canonical response and only mint a new delivery receipt.
pub(crate) async fn prepare_federated_operation(
    transaction: &mut Transaction<'_, Postgres>,
    admission: &crate::chat_protocol::state_machine::FederatedOperationAdmission,
    mutation: &VerifiedSignedMutation,
    signed_request_bytes: &[u8],
) -> Result<FederatedOperationArbitration, PreludeError> {
    let binding = federated_operation_binding(admission, mutation, signed_request_bytes)?;
    let operation_lock = auth::reserve_canonical_operation_id(
        transaction,
        binding.operation_id,
        Some(binding.operation_id),
    )
    .await?;
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if operation_lock.transaction_id() != transaction_id
        || operation_lock.operation_id() != binding.operation_id
    {
        return Err(PreludeError::ForeignTransaction);
    }

    let existing: Option<(Vec<u8>, Vec<u8>, Vec<u8>, String, String, String)> = sqlx::query_as(
        r#"
        SELECT request_digest, accepted_request_sha256, signature,
               principal_did, endpoint_nsid, mutation_kind
          FROM chat.operation_claims
         WHERE operation_id=$1
        "#,
    )
    .bind(binding.operation_id)
    .fetch_optional(&mut **transaction)
    .await?;

    if let Some((request_digest, accepted_sha, signature, principal, endpoint, mutation_kind)) =
        existing
    {
        if request_digest.as_slice() != binding.request_digest
            || accepted_sha.as_slice() != binding.accepted_request_sha256
            || signature.as_slice() != binding.signature
            || principal != binding.principal_did
            || endpoint != binding.endpoint_nsid
            || mutation_kind != binding.mutation_kind
        {
            return Err(PreludeError::OperationIdConflict);
        }
        let completed: Option<(i32, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            r#"
            SELECT completed_status, response_bytes, response_sha256
              FROM chat.idempotency_records
             WHERE principal_did = $1 AND endpoint_nsid = $2 AND operation_id = $3
            "#,
        )
        .bind(&binding.principal_did)
        .bind(&binding.endpoint_nsid)
        .bind(binding.operation_id)
        .fetch_optional(&mut **transaction)
        .await?;
        let Some((completed_status, response_bytes, stored_response_sha256)) = completed else {
            return Err(PreludeError::ClaimIntegrity);
        };
        if completed_status == 0
            || response_bytes.is_empty()
            || stored_response_sha256.as_slice() != Sha256::digest(&response_bytes).as_slice()
        {
            return Err(PreludeError::ClaimIntegrity);
        }
        return Ok(FederatedOperationArbitration::Replay(
            CompletedIdempotentResponse::for_federated_replay(completed_status, response_bytes),
        ));
    }

    Ok(FederatedOperationArbitration::First(
        FederatedOperationReservationGuard {
            operation_lock,
            binding,
        },
    ))
}

fn federated_operation_binding(
    admission: &crate::chat_protocol::state_machine::FederatedOperationAdmission,
    mutation: &VerifiedSignedMutation,
    signed_request_bytes: &[u8],
) -> Result<FederatedOperationClaimBinding, PreludeError> {
    let endpoint = admission.endpoint_nsid();
    if !prelude::endpoint_has_operation_claim(endpoint)
        || admission.operation_id().get_version_num() != 4
    {
        return Err(PreludeError::NonCanonicalOperation);
    }
    if mutation.actor_did().as_str() != admission.actor_did()
        || mutation.request_digest() != admission.mutation_request_digest()
        || mutation.signature() != admission.mutation_signature()
        || mutation.kind().type_id() != "blue.catbird.chat.defs#commitTransitionBody"
    {
        return Err(PreludeError::ClaimIntegrity);
    }
    Ok(FederatedOperationClaimBinding {
        operation_id: admission.operation_id(),
        principal_did: admission.actor_did().to_owned(),
        endpoint_nsid: admission.endpoint_nsid().to_owned(),
        mutation_kind: mutation.type_id().to_owned(),
        request_digest: *mutation.request_digest(),
        accepted_request_sha256: Sha256::digest(signed_request_bytes).into(),
        signature: *mutation.signature(),
        claimed_at: admission.trusted_read_at(),
    })
}

/// Persist the operation claim for a federated first execution. The caller must
/// hold the reservation guard; this runs under the same transaction as the
/// transition execution.
pub(crate) async fn claim_federated_operation(
    transaction: &mut Transaction<'_, Postgres>,
    reservation: FederatedOperationReservationGuard,
) -> Result<(), PreludeError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if reservation.operation_lock.transaction_id() != transaction_id {
        return Err(PreludeError::ForeignTransaction);
    }
    let binding = reservation.binding;
    let inserted = sqlx::query(
        r#"
        INSERT INTO chat.operation_claims (
            operation_id,principal_did,endpoint_nsid,mutation_kind,
            request_digest,accepted_request_sha256,signature,claimed_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
    )
    .bind(binding.operation_id)
    .bind(&binding.principal_did)
    .bind(&binding.endpoint_nsid)
    .bind(&binding.mutation_kind)
    .bind(binding.request_digest.as_slice())
    .bind(binding.accepted_request_sha256.as_slice())
    .bind(binding.signature.as_slice())
    .bind(binding.claimed_at)
    .execute(&mut **transaction)
    .await;
    match inserted {
        Ok(_) => Ok(()),
        Err(error)
            if error
                .as_database_error()
                .and_then(|db| db.code())
                .as_deref()
                == Some("23505") =>
        {
            Err(PreludeError::OperationIdConflict)
        }
        Err(error) => Err(PreludeError::Database(error)),
    }
}

/// Complete a federated first operation by writing the immutable idempotency
/// record, exactly as the local prelude does. The claim must be recorded first.
pub(crate) async fn complete_federated_operation(
    transaction: &mut Transaction<'_, Postgres>,
    binding: &FederatedOperationClaimBinding,
    accepted_request_bytes: &[u8],
    signing_transcript_bytes: &[u8],
    completed_status: i32,
    response_bytes: &[u8],
    event_position: Option<i64>,
) -> Result<(), PreludeError> {
    if !(200..=599).contains(&completed_status) || response_bytes.is_empty() {
        return Err(PreludeError::ClaimIntegrity);
    }
    let response_sha256: [u8; 32] = Sha256::digest(response_bytes).into();
    let inserted = sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records(
            principal_did,endpoint_nsid,operation_id,request_digest,
            accepted_request_bytes,signing_transcript_bytes,signature,
            completed_status,response_bytes,response_sha256,event_position,
            historical_jkt,current_jkt,completed_at
        ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,NULL,$12)
        "#,
    )
    .bind(&binding.principal_did)
    .bind(&binding.endpoint_nsid)
    .bind(binding.operation_id)
    .bind(binding.request_digest.as_slice())
    .bind(accepted_request_bytes)
    .bind(signing_transcript_bytes)
    .bind(binding.signature.as_slice())
    .bind(completed_status)
    .bind(response_bytes)
    .bind(response_sha256.as_slice())
    .bind(event_position)
    .bind(binding.claimed_at)
    .execute(&mut **transaction)
    .await;
    match inserted {
        Ok(_) => Ok(()),
        Err(error)
            if error
                .as_database_error()
                .and_then(|database| database.code())
                .as_deref()
                == Some("23505") =>
        {
            Err(PreludeError::OperationIdConflict)
        }
        Err(error) => Err(PreludeError::Database(error)),
    }
}

/// Replicate an inbound MLS application message to a destination DS.
pub async fn deliver_message_replication(
    tx: &mut Transaction<'_, Postgres>,
    ack_signer: &AckSigner,
    header: ValidatedEnvelopeHeader,
    recipient_did: String,
    locator: ValidatedEntryLocator,
    entry_bytes: Vec<u8>,
    signed_request_bytes: Vec<u8>,
) -> Result<DeliverMessageOutput, FederationError> {
    lock_delivery_id(tx, header.delivery_id).await?;

    // On deliveries, authenticated senderDsDid MUST equal header sequencerDid
    if !dids_equivalent(&header.sender_ds_did, &header.sequencer_did) {
        return Err(FederationError::InvalidEnvelope {
            reason: format!(
                "senderDsDid '{}' does not equal sequencerDid '{}' on inbound delivery",
                header.sender_ds_did, header.sequencer_did
            ),
        });
    }

    let envelope_digest = compute_message_envelope_digest(
        &header,
        &recipient_did,
        &locator,
        &entry_bytes,
        &signed_request_bytes,
    )?;

    if header.payload_sha256 != envelope_digest {
        return Err(FederationError::InvalidEnvelope {
            reason: "payloadSha256 does not match computed envelope digest".to_string(),
        });
    }

    if let Some(cached_bytes) = check_delivery_receipt(
        tx,
        DELIVER_MESSAGE_NSID,
        &header,
        &envelope_digest,
        Some(&locator),
    )
    .await?
    {
        let cached_output: DeliverMessageOutput =
            serde_json::from_slice(&cached_bytes).map_err(FederationError::Json)?;
        return Ok(cached_output);
    }

    // 1. Lock conversation and verify remote mailbox routing and exact term.
    let convo_row: Option<(bool, Option<String>, i64, i64, i64, i64, Vec<u8>, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT c.is_remote, c.sequencer_ds, c.sequencer_term, c.current_generation,
               c.current_state_version, s.epoch, s.group_id, s.group_context_hash, s.confirmation_tag
          FROM chat.conversations c
          LEFT JOIN chat.generation_states s
            ON s.conversation_id = c.conversation_id
           AND s.generation = c.current_generation
           AND s.state_version = c.current_state_version
         WHERE c.conversation_id = $1
         FOR UPDATE OF c
        "#,
    )
    .bind(header.conversation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    let Some((
        is_remote,
        sequencer_ds,
        sequencer_term,
        current_generation,
        convo_state_version,
        convo_epoch,
        convo_group_id,
        convo_group_context_hash,
        convo_confirmation_tag,
    )) = convo_row
    else {
        return Err(FederationError::MailboxNotProvisioned {
            reason: format!(
                "conversation {} not found on destination DS",
                header.conversation_id
            ),
        });
    };
    let is_quarantined = super::core::is_conversation_quarantined(tx, header.conversation_id)
        .await
        .map_err(FederationError::Database)?;
    if is_quarantined {
        return Err(FederationError::DeliveryConflict {
            reason: format!("conversation {} is quarantined", header.conversation_id),
        });
    }

    if !is_remote
        || sequencer_ds.as_deref() != Some(&header.sequencer_did)
        || !dids_equivalent(&header.sender_ds_did, sequencer_ds.as_deref().unwrap_or(""))
    {
        return Err(FederationError::MailboxNotProvisioned {
            reason: "conversation is not provisioned as a remote mailbox for this sequencer"
                .to_string(),
        });
    }

    if sequencer_term as u64 != header.sequencer_term {
        return Err(FederationError::TermStale {
            convo_id: header.conversation_id.to_string(),
            provided_term: header.sequencer_term as i64,
            current_term: sequencer_term,
        });
    }

    // 2. Verify recipient is a LOCAL participant (ds_did NULL/local) with an
    //    active member leaf, and the application interval covers the entry.
    let recipient_row: Option<(String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT p.status, p.ds_did
          FROM chat.participants p
         WHERE p.conversation_id = $1 AND p.user_did = $2 AND p.current_membership = TRUE
         FOR UPDATE OF p
        "#,
    )
    .bind(header.conversation_id)
    .bind(&recipient_did)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    let Some((p_status, p_ds_did)) = recipient_row else {
        return Err(FederationError::UnauthorizedRecipient {
            reason: format!("user {} is not a participant", recipient_did),
        });
    };

    let self_base_did = service_did_base();
    let recipient_is_local =
        p_ds_did.is_none() || dids_equivalent(p_ds_did.as_deref().unwrap_or(""), &self_base_did);
    if !recipient_is_local {
        return Err(FederationError::UnauthorizedRecipient {
            reason: format!(
                "recipient participant ds_did {:?} is not local on this destination DS",
                p_ds_did
            ),
        });
    }

    if p_status != "active" {
        return Err(FederationError::UnauthorizedRecipient {
            reason: format!("recipient status is {p_status}, expected active"),
        });
    }
    // Lock exact recipient member_devices active leaf and device FOR UPDATE
    let active_leaves: Vec<Uuid> = sqlx::query_scalar(
        r#"
        SELECT md.leaf_period_id
          FROM chat.member_devices md
          JOIN chat.devices dev ON dev.user_did = md.user_did AND dev.device_id = md.device_id
         WHERE md.conversation_id = $1
           AND md.user_did = $2
           AND md.active = TRUE
           AND md.removed_at IS NULL
           AND dev.status = 'active'
           AND dev.revoked_at IS NULL
         FOR UPDATE OF md, dev
        "#,
    )
    .bind(header.conversation_id)
    .bind(&recipient_did)
    .fetch_all(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    if active_leaves.is_empty() {
        return Err(FederationError::UnauthorizedRecipient {
            reason: format!(
                "recipient {} has no active unrevoked member leaf",
                recipient_did
            ),
        });
    }

    if p_status != "active" {
        return Err(FederationError::UnauthorizedRecipient {
            reason: format!("recipient status is {p_status}, expected active"),
        });
    }

    let interval_valid: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM chat.application_intervals
             WHERE conversation_id = $1 AND generation = $2 AND recipient_did = $3
               AND start_seq <= $4 AND (terminal_seq IS NULL OR terminal_seq >= $4)
        )
        "#,
    )
    .bind(header.conversation_id)
    .bind(current_generation)
    .bind(&recipient_did)
    .bind(locator.seq as i64)
    .fetch_one(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    if !interval_valid {
        return Err(FederationError::UnauthorizedRecipient {
            reason: format!(
                "recipient does not have an active application interval covering seq {}",
                locator.seq
            ),
        });
    }

    // 3. Decode signed request to discover actor device key.
    let mutation = decode_canonical_signed_mutation(&signed_request_bytes).map_err(|e| {
        FederationError::InvalidEnvelope {
            reason: format!("cannot decode signed request: {e}"),
        }
    })?;

    let actor_did = mutation.actor_did().as_str();
    let actor_device_id = Uuid::from_bytes(*mutation.actor_device_id().as_bytes());
    let actor_key_id = mutation.key_id().as_str();

    let key_row: Option<(Vec<u8>, i64)> = sqlx::query_as(
        r#"
        SELECT dk.signing_public_key, dk.enrollment_auth_generation
          FROM chat.device_keys dk
          JOIN chat.devices d ON d.user_did = dk.user_did AND d.device_id = dk.device_id
         WHERE dk.user_did = $1 AND dk.device_id = $2 AND dk.key_id = $3
           AND dk.revoked_at IS NULL AND d.status = 'active' AND d.revoked_at IS NULL
         FOR UPDATE
        "#,
    )
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(actor_key_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    let Some((actor_public_key, enrollment_auth_generation)) = key_row else {
        return Err(FederationError::MailboxNotProvisioned {
            reason: format!(
                "actor device key {actor_key_id} not provisioned or revoked on destination DS"
            ),
        });
    };

    let verified_entry = decode_and_verify_application_entry(&entry_bytes, &actor_public_key)
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("application entry verification failed: {e}"),
        })?;

    if verified_entry.mutation().auth_generation() as i64 != enrollment_auth_generation {
        return Err(FederationError::InvalidEnvelope {
            reason: "auth_generation does not match stored enrollment generation".to_string(),
        });
    }

    // Exact rebind of signedRequestBytes to verified entry
    let rebound_entry = rebind_persisted_application_entry(
        verified_entry,
        &entry_bytes,
        &locator.accepted_payload_sha256,
        &signed_request_bytes,
        mutation.request_digest(),
        mutation.signature(),
        &locator.outer_entry_fingerprint,
        &actor_public_key,
    )
    .map_err(|e| FederationError::InvalidEnvelope {
        reason: format!("application entry rebind failed: {e:?}"),
    })?;

    let projection = match rebound_entry.mutation().projection() {
        VerifiedMutationProjection::ApplicationSend(p) => p,
        _ => {
            return Err(FederationError::InvalidEnvelope {
                reason: "not an application send mutation".to_string(),
            })
        }
    };
    let message_id = Uuid::from_bytes(*projection.message_id().as_bytes());

    let entry_id_canonical =
        CanonicalUuidV4::parse(rebound_entry.entry_id().as_str()).map_err(|_| {
            FederationError::InvalidEnvelope {
                reason: "invalid entry_id in entry".to_string(),
            }
        })?;
    let conversation_id_canonical =
        CanonicalUuidV4::parse(rebound_entry.conversation_id().as_str()).map_err(|_| {
            FederationError::InvalidEnvelope {
                reason: "invalid conversation_id in entry".to_string(),
            }
        })?;

    let verified_entry_id = Uuid::from_str(entry_id_canonical.as_str()).map_err(|_| {
        FederationError::InvalidEnvelope {
            reason: "invalid entry_id uuid".to_string(),
        }
    })?;
    let verified_convo_id = Uuid::from_str(conversation_id_canonical.as_str()).map_err(|_| {
        FederationError::InvalidEnvelope {
            reason: "invalid conversation_id uuid".to_string(),
        }
    })?;

    let recomputed_entry_sha256: [u8; 32] = Sha256::digest(&entry_bytes).into();

    if verified_entry_id != locator.entry_id
        || verified_convo_id != header.conversation_id
        || rebound_entry.seq() != locator.seq
        || recomputed_entry_sha256 != locator.accepted_payload_sha256
        || rebound_entry.outer_application_fingerprint() != &locator.outer_entry_fingerprint
    {
        return Err(FederationError::DeliveryConflict {
            reason: "verified entry does not match entry locator or header".to_string(),
        });
    }

    // Verify AAD coordinate and prior state
    let aad = projection.aad();
    let aad_protocol_version = aad.get("protocolVersion");
    let aad_convo = match aad.get("conversationId") {
        Some(CanonicalValueRef::Bytes(v)) if v.len() == 16 => Uuid::from_slice(v).ok(),
        _ => None,
    };
    let aad_msg = match aad.get("messageId") {
        Some(CanonicalValueRef::Bytes(v)) if v.len() == 16 => Uuid::from_slice(v).ok(),
        _ => None,
    };
    let aad_gen = match aad.get("generation") {
        Some(CanonicalValueRef::Integer(g)) => g as i64,
        _ => -1,
    };

    if !matches!(aad_protocol_version, Some(CanonicalValueRef::Text("1")))
        || aad_convo != Some(header.conversation_id)
        || aad_msg != Some(message_id)
        || aad_gen != current_generation
    {
        return Err(FederationError::InvalidEnvelope {
            reason: "invalid AAD coordinate".to_string(),
        });
    }

    if let Some(CanonicalValueRef::Object(aad_prior)) = aad.get("prior") {
        let prior_convo = match aad_prior.get("conversationId") {
            Some(CanonicalValueRef::Bytes(v)) if v.len() == 16 => Uuid::from_slice(v).ok(),
            _ => None,
        };
        let prior_gen = match aad_prior.get("generation") {
            Some(CanonicalValueRef::Integer(g)) => g as i64,
            _ => -1,
        };
        let prior_sv = match aad_prior.get("stateVersion") {
            Some(CanonicalValueRef::Integer(sv)) => sv as i64,
            _ => -1,
        };
        let prior_epoch = match aad_prior.get("epoch") {
            Some(CanonicalValueRef::Integer(ep)) => ep as i64,
            _ => -1,
        };
        let prior_gid = match aad_prior.get("groupId") {
            Some(CanonicalValueRef::Bytes(v)) if v.len() == 32 => &v[..],
            _ => &[],
        };
        let prior_gch = match aad_prior.get("groupContextHash") {
            Some(CanonicalValueRef::Bytes(v)) if v.len() == 32 => &v[..],
            _ => &[],
        };
        let prior_ctag = match aad_prior.get("confirmationTag") {
            Some(CanonicalValueRef::Bytes(v)) if v.len() == 32 => &v[..],
            _ => &[],
        };

        if prior_convo != Some(header.conversation_id)
            || prior_gen != current_generation
            || prior_sv != convo_state_version
            || prior_epoch != convo_epoch
            || prior_gid != convo_group_id.as_slice()
            || prior_gch != convo_group_context_hash.as_slice()
            || prior_ctag != convo_confirmation_tag.as_slice()
            || !matches!(
                aad_prior.get("lifecycle"),
                Some(CanonicalValueRef::Text("active"))
            )
        {
            return Err(FederationError::DeliveryConflict {
                reason: "prior coordinate in AAD does not match current conversation state"
                    .to_string(),
            });
        }
    }

    let received_at_dt = DateTime::parse_from_rfc3339(rebound_entry.received_at().as_str())
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("invalid receivedAt: {e}"),
        })?
        .with_timezone(&Utc);

    let bindings = projection.blob_bindings();
    if bindings.len() > 1 {
        return Err(FederationError::InvalidEnvelope {
            reason: "at most one blob binding is allowed".to_string(),
        });
    }

    let mut pending_blob: Option<NewBlobBinding> = None;
    if let Some(CanonicalValueRef::Object(binding)) = bindings.get(0) {
        let blob_id_val = match binding.get("blobId") {
            Some(CanonicalValueRef::Uuid(u)) => Uuid::from_bytes(*u.as_bytes()),
            _ => {
                return Err(FederationError::InvalidEnvelope {
                    reason: "invalid blobId in binding".to_string(),
                })
            }
        };
        let hash_val = match binding.get("ciphertextSha256") {
            Some(CanonicalValueRef::Bytes(v)) if v.len() == 32 => v.to_vec(),
            _ => {
                return Err(FederationError::InvalidEnvelope {
                    reason: "invalid ciphertextSha256 in binding".to_string(),
                })
            }
        };
        let size_val = match binding.get("ciphertextSize") {
            Some(CanonicalValueRef::Integer(s)) => s as i64,
            _ => {
                return Err(FederationError::InvalidEnvelope {
                    reason: "invalid ciphertextSize in binding".to_string(),
                })
            }
        };
        if !(17..=blobs::MAX_CIPHERTEXT_BYTES).contains(&size_val)
            || !matches!(
                binding.get("purpose"),
                Some(CanonicalValueRef::Text("attachment"))
            )
        {
            return Err(FederationError::InvalidEnvelope {
                reason: "invalid blob binding purpose or size".to_string(),
            });
        }

        let blob_row: Option<(Vec<u8>, i64, i64, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
            r#"
            SELECT ciphertext_sha256, ciphertext_size, plaintext_size, uploaded_at, unbound_expires_at
              FROM chat.blobs
             WHERE blob_id = $1 AND owner_did = $2 AND owner_device_id = $3
               AND purpose = 'attachment' AND status = 'completedUnbound'
             FOR UPDATE
            "#,
        )
        .bind(blob_id_val)
        .bind(actor_did)
        .bind(actor_device_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(FederationError::Database)?;

        let Some((stored_hash, stored_size, plaintext_size, uploaded_at, expires_at)) = blob_row
        else {
            return Err(FederationError::MailboxNotProvisioned {
                reason: "attachment blob not found or not completedUnbound on destination DS"
                    .to_string(),
            });
        };

        if stored_hash != hash_val || stored_size != size_val || expires_at <= received_at_dt {
            return Err(FederationError::DeliveryConflict {
                reason: "attachment blob digest/size mismatch or expired".to_string(),
            });
        }

        let descriptor_bytes = projection.application_message().canonical_dag_cbor();
        let aad_bytes = projection.aad().canonical_dag_cbor();
        let descriptor_sha256: [u8; 32] = Sha256::digest(&descriptor_bytes).into();
        let aad_sha256: [u8; 32] = Sha256::digest(&aad_bytes).into();

        pending_blob = Some(NewBlobBinding {
            blob_id: blob_id_val,
            binding_kind: BindingKind::Application,
            conversation_id: header.conversation_id,
            entry_seq: Some(locator.seq as i64),
            message_id: Some(message_id),
            metadata_origin_transition_id: None,
            metadata_version: None,
            owner_did: actor_did.to_string(),
            owner_device_id: actor_device_id,
            descriptor_bytes,
            descriptor_sha256: descriptor_sha256.to_vec(),
            aad_bytes,
            aad_sha256: aad_sha256.to_vec(),
            ciphertext_sha256: hash_val,
            plaintext_size,
            ciphertext_size: size_val,
            purpose: BlobPurpose::Attachment,
            bound_at: received_at_dt,
            uploaded_at,
            unbound_expires_at: expires_at,
        });
    }

    // Stored fields derived ONLY from rebound entry
    let response = serde_json::json!({
        "entry": {
            "entryId": entry_id_canonical.as_str(),
            "conversationId": conversation_id_canonical.as_str(),
            "seq": locator.seq,
            "signedRequest": serde_json::from_slice::<serde_json::Value>(&signed_request_bytes).map_err(FederationError::Json)?,
            "receivedAt": rebound_entry.received_at().as_str()
        }
    });
    let outcome_bytes = serde_json::to_vec(&response).map_err(FederationError::Json)?;
    let signed_req_sha256: [u8; 32] = Sha256::digest(&signed_request_bytes).into();

    let send = ApplicationSend {
        entry: AppendEntry {
            conversation_id: header.conversation_id,
            entry_id: verified_entry_id,
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_string(),
            accepted_payload_bytes: entry_bytes,
            accepted_payload_sha256: recomputed_entry_sha256.to_vec(),
            signed_request_bytes: signed_request_bytes.clone(),
            request_digest: rebound_entry.mutation().request_digest().to_vec(),
            signature: rebound_entry.mutation().signature().to_vec(),
            server_fields_bytes: serde_ipld_dagcbor::to_vec(&std::collections::BTreeMap::<
                String,
                String,
            >::new())
            .map_err(|_| FederationError::InvalidEnvelope {
                reason: "server fields serialization failed".to_string(),
            })?,
            outer_entry_fingerprint: rebound_entry.outer_application_fingerprint().to_vec(),
            actor_did: actor_did.to_string(),
            actor_device_id,
            actor_key_id: actor_key_id.to_string(),
            actor_auth_generation: enrollment_auth_generation,
            generation: Some(current_generation),
            state_version: None,
            transition_id: None,
            message_id: Some(message_id),
            received_at: received_at_dt,
        },
        signing_transcript_bytes: rebound_entry.mutation().transcript_bytes().to_vec(),
        outcome_bytes,
    };

    // 4. Sequence and append rule.
    let seq_exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM chat.entries
             WHERE conversation_id = $1 AND seq = $2
        )
        "#,
    )
    .bind(header.conversation_id)
    .bind(locator.seq as i64)
    .fetch_one(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    if seq_exists {
        let is_exact =
            compare_exact_application_entry(tx, &send, locator.seq, pending_blob.as_ref())
                .await
                .map_err(|e| FederationError::SequenceConflict {
                    reason: format!("exact compare failed: {e:?}"),
                })?;
        if !is_exact {
            return Err(FederationError::SequenceConflict {
                reason: format!(
                    "entry at seq {} already exists with different content",
                    locator.seq
                ),
            });
        }
    } else {
        // Shared operation claim in chat.operation_claims using blue.catbird.chat.sendMessage
        let claim_res = sqlx::query(
            r#"
            INSERT INTO chat.operation_claims (
                operation_id, principal_did, endpoint_nsid, mutation_kind,
                request_digest, accepted_request_sha256, signature, claimed_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(message_id)
        .bind(actor_did)
        .bind("blue.catbird.chat.sendMessage")
        .bind("blue.catbird.chat.defs#applicationSendBody")
        .bind(&send.entry.request_digest)
        .bind(&signed_req_sha256[..])
        .bind(&send.entry.signature)
        .bind(send.entry.received_at)
        .execute(&mut **tx)
        .await;

        if let Err(e) = claim_res {
            if e.as_database_error().and_then(|db| db.code()).as_deref() == Some("23505") {
                // New delivery ID for same operation returns canonical outcome + new receipt
                let existing_idem: Option<(Vec<u8>, Vec<u8>, String)> = sqlx::query_as(
                    r#"
                    SELECT request_digest, signature, principal_did
                      FROM chat.idempotency_records
                     WHERE endpoint_nsid = 'blue.catbird.chat.sendMessage' AND operation_id = $1
                    "#,
                )
                .bind(message_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(FederationError::Database)?;

                if let Some((stored_req_digest, stored_sig, stored_principal)) = existing_idem {
                    if stored_req_digest != send.entry.request_digest
                        || stored_sig != send.entry.signature
                        || stored_principal != actor_did
                    {
                        return Err(FederationError::DeliveryConflict {
                            reason: "operation claim exists with conflicting payload".to_string(),
                        });
                    }

                    // Mint new receipt for new delivery ID
                    let now = Utc::now();
                    let result_sha256: [u8; 32] = Sha256::digest(b"{\"accepted\":true}").into();
                    let receipt = sign_receipt(
                        ack_signer,
                        DELIVER_MESSAGE_NSID,
                        header.delivery_id,
                        header.conversation_id,
                        &header.sender_ds_did,
                        &header.receiver_ds_did,
                        &header.sequencer_did,
                        header.sequencer_term,
                        envelope_digest,
                        result_sha256,
                        locator.clone(),
                        now,
                    )?;
                    let output = DeliverMessageOutput {
                        accepted: true,
                        receipt,
                        extra_data: None,
                    };
                    let response_bytes =
                        serde_json::to_vec(&output).map_err(FederationError::Json)?;
                    insert_delivery_receipt(tx, &output.receipt, &locator, &response_bytes).await?;
                    return Ok(output);
                }

                return Err(FederationError::DeliveryConflict {
                    reason: "operation claim already exists".to_string(),
                });
            }
            return Err(FederationError::Database(e));
        }

        append_exact_application_entry(tx, &send, locator.seq)
            .await
            .map_err(|e| FederationError::SequenceConflict {
                reason: format!("append_exact_application_entry failed: {e:?}"),
            })?;

        if let Some(ref blob_binding) = pending_blob {
            blobs::bind_application_blob(tx, blob_binding)
                .await
                .map_err(|e| FederationError::DeliveryConflict {
                    reason: format!("blob binding failed: {e:?}"),
                })?;
        }
    }

    // 5. Sign and insert receipt and shared idempotency record.
    let now = Utc::now();
    let result_sha256: [u8; 32] = Sha256::digest(b"{\"accepted\":true}").into();
    let receipt = sign_receipt(
        ack_signer,
        DELIVER_MESSAGE_NSID,
        header.delivery_id,
        header.conversation_id,
        &header.sender_ds_did,
        &header.receiver_ds_did,
        &header.sequencer_did,
        header.sequencer_term,
        envelope_digest,
        result_sha256,
        locator.clone(),
        now,
    )?;

    let output = DeliverMessageOutput {
        accepted: true,
        receipt,
        extra_data: None,
    };

    let response_bytes = serde_json::to_vec(&output).map_err(FederationError::Json)?;
    let response_sha256: [u8; 32] = Sha256::digest(&response_bytes).into();

    if !seq_exists {
        let idem_res = sqlx::query(
            r#"
            INSERT INTO chat.idempotency_records (
                principal_did, endpoint_nsid, operation_id, request_digest,
                accepted_request_bytes, signing_transcript_bytes, signature,
                completed_status, response_bytes, response_sha256, event_position,
                historical_jkt, current_jkt, completed_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULL, NULL, $12)
            "#,
        )
        .bind(actor_did)
        .bind("blue.catbird.chat.sendMessage")
        .bind(message_id)
        .bind(&send.entry.request_digest)
        .bind(&signed_request_bytes)
        .bind(rebound_entry.mutation().transcript_bytes())
        .bind(&send.entry.signature)
        .bind(200i32)
        .bind(&response_bytes)
        .bind(&response_sha256[..])
        .bind(Option::<i64>::None)
        .bind(send.entry.received_at)
        .execute(&mut **tx)
        .await;

        if let Err(e) = idem_res {
            if e.as_database_error().and_then(|db| db.code()).as_deref() == Some("23505") {
                return Err(FederationError::DeliveryConflict {
                    reason: "idempotency record already exists".to_string(),
                });
            }
            return Err(FederationError::Database(e));
        }
    }

    insert_delivery_receipt(tx, &output.receipt, &locator, &response_bytes).await?;

    Ok(output)
}

/// Execute an actor-signed commit on the sequencer DS via the canonical transition planner and executor.
pub async fn submit_commit_sequencing<T: PublicTransport>(
    tx: &mut Transaction<'_, Postgres>,
    ack_signer: &AckSigner,
    header: ValidatedEnvelopeHeader,
    signed_request_bytes: Vec<u8>,
    relationship_authority: &RelationshipAuthority<T>,
) -> Result<SubmitCommitOutput, FederationError> {
    lock_delivery_id(tx, header.delivery_id).await?;

    let envelope_digest = compute_commit_envelope_digest(&header, &signed_request_bytes)?;

    if header.payload_sha256 != envelope_digest {
        return Err(FederationError::InvalidEnvelope {
            reason: "payloadSha256 does not match computed envelope digest".to_string(),
        });
    }

    // On submitCommit the source locator is only known after the transition is
    // planned and applied; on replay the state has already advanced so the commit
    // cannot be re-planned. Dedup on the delivery_id + envelope first.
    if let Some(cached_bytes) =
        check_delivery_receipt(tx, SUBMIT_COMMIT_NSID, &header, &envelope_digest, None).await?
    {
        let cached_output: SubmitCommitOutput =
            serde_json::from_slice(&cached_bytes).map_err(FederationError::Json)?;
        return Ok(cached_output);
    }

    // 1. Lock conversation on sequencer DS.
    let convo_row: Option<(bool, Option<String>, i64)> = sqlx::query_as(
        r#"
        SELECT is_remote, sequencer_ds, sequencer_term
          FROM chat.conversations
         WHERE conversation_id = $1
         FOR UPDATE
        "#,
    )
    .bind(header.conversation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    let Some((is_remote, sequencer_ds, sequencer_term)) = convo_row else {
        return Err(FederationError::ConversationNotFound {
            convo_id: header.conversation_id.to_string(),
        });
    };

    let self_base_did = service_did_base();
    if is_remote {
        return Err(FederationError::NotSequencer {
            convo_id: header.conversation_id.to_string(),
        });
    }

    if let Some(s_did) = &sequencer_ds {
        if !dids_equivalent(s_did, &self_base_did) {
            return Err(FederationError::NotSequencer {
                convo_id: header.conversation_id.to_string(),
            });
        }
    }

    if !dids_equivalent(&header.sequencer_did, &self_base_did) {
        return Err(FederationError::NotSequencer {
            convo_id: header.conversation_id.to_string(),
        });
    }

    if sequencer_term as u64 != header.sequencer_term {
        return Err(FederationError::TermStale {
            convo_id: header.conversation_id.to_string(),
            provided_term: header.sequencer_term as i64,
            current_term: sequencer_term,
        });
    }

    // 2. Decode signed mutation to verify actor and participant DS route.
    let canonical = decode_canonical_signed_mutation(&signed_request_bytes).map_err(|e| {
        FederationError::InvalidEnvelope {
            reason: format!("invalid signed mutation: {e}"),
        }
    })?;

    if canonical.kind() != SignedMutationKind::CommitTransition {
        return Err(FederationError::InvalidEnvelope {
            reason: format!(
                "expected SignedMutationKind::CommitTransition, got {:?}",
                canonical.kind()
            ),
        });
    }

    let actor_did = canonical.actor_did().as_str();
    let actor_device_id = Uuid::from_bytes(*canonical.actor_device_id().as_bytes());
    let actor_key_id = canonical.key_id().as_str();

    // Check participant's ds_did matches sender_ds_did and has active member leaf
    let participant_row: Option<(String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT status, ds_did
          FROM chat.participants
         WHERE conversation_id = $1 AND user_did = $2 AND current_membership = TRUE
         FOR UPDATE
        "#,
    )
    .bind(header.conversation_id)
    .bind(actor_did)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    let Some((p_status, p_ds_did)) = participant_row else {
        return Err(FederationError::UnauthorizedParticipantDs {
            reason: format!("user {actor_did} is not a current participant"),
        });
    };

    if p_status != "active" {
        return Err(FederationError::UnauthorizedParticipantDs {
            reason: format!("participant status is {p_status}, expected active"),
        });
    }

    // Verify the actor has an active member leaf in the MLS group.
    let has_active_leaf: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM chat.member_devices
             WHERE conversation_id = $1 AND user_did = $2 AND device_id = $3
               AND active = TRUE AND removed_at IS NULL
        )
        "#,
    )
    .bind(header.conversation_id)
    .bind(actor_did)
    .bind(actor_device_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    if !has_active_leaf {
        return Err(FederationError::UnauthorizedParticipantDs {
            reason: format!("user {actor_did} has no active member leaf in this conversation"),
        });
    }

    if p_ds_did.as_deref() != Some(&header.sender_ds_did) {
        return Err(FederationError::UnauthorizedParticipantDs {
            reason: format!(
                "participant ds_did {:?} does not match senderDsDid {}",
                p_ds_did, header.sender_ds_did
            ),
        });
    }

    // Fetch actor signing public key and enrollment generation, checking device is active and unrevoked
    let key_row: Option<(Vec<u8>, i64)> = sqlx::query_as(
        r#"
        SELECT dk.signing_public_key, dk.enrollment_auth_generation
          FROM chat.device_keys dk
          JOIN chat.devices d ON d.user_did = dk.user_did AND d.device_id = dk.device_id
         WHERE dk.user_did = $1 AND dk.device_id = $2 AND dk.key_id = $3
           AND dk.revoked_at IS NULL AND d.status = 'active' AND d.revoked_at IS NULL
         FOR UPDATE
        "#,
    )
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(actor_key_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    let Some((public_key, enrollment_auth_generation)) = key_row else {
        return Err(FederationError::UnauthorizedParticipantDs {
            reason: "actor device key not found or revoked on sequencer DS".to_string(),
        });
    };

    if canonical.auth_generation() as i64 != enrollment_auth_generation {
        return Err(FederationError::UnauthorizedParticipantDs {
            reason: "auth_generation does not match stored enrollment generation".to_string(),
        });
    }

    let mutation =
        decode_and_verify_signed_mutation(&signed_request_bytes, &public_key).map_err(|e| {
            FederationError::InvalidEnvelope {
                reason: format!("mutation signature verification failed: {e}"),
            }
        })?;

    let parsed =
        parse_submit_transition(&mutation).map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("cannot parse submit transition: {e:?}"),
        })?;

    // The canonical entry instant is the mailbox's admission instant carried
    // in the envelope header and bound into the envelope digest. The mailbox
    // validated it against its captured trusted instant window, and the
    // sequencer re-verifies the envelope digest above, so this value is
    // bounded and authenticated. Using it here makes the sequencer
    // canonicalize byte-identical entry material to the mailbox.
    let trusted_instant = TrustedRequestInstant::from_canonical(header.received_at.clone());
    let now = trusted_instant.datetime();
    let tx_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **tx)
        .await
        .map_err(FederationError::Database)?;
    let aggregate = super::core::hydrate_locked_conversation_state(tx, header.conversation_id, now)
        .await
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("hydrate_locked_conversation_state error: {e:?}"),
        })?;
    let hydration = HydrationAuthority::from_locked_conversation(&aggregate).map_err(|e| {
        FederationError::InvalidEnvelope {
            reason: format!("HydrationAuthority::from_locked_conversation error: {e:?}"),
        }
    })?;

    let bare_did = BareDid::parse(actor_did).map_err(|e| FederationError::InvalidEnvelope {
        reason: format!("invalid actor DID: {e}"),
    })?;
    let canon_device_id = CanonicalUuidV4::parse(&actor_device_id.hyphenated().to_string())
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("invalid actor device ID: {e}"),
        })?;
    let key_thumbprint =
        KeyThumbprint::parse(actor_key_id).map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("invalid actor key ID: {e}"),
        })?;
    let sig_key: [u8; 32] =
        public_key
            .as_slice()
            .try_into()
            .map_err(|_| FederationError::InvalidEnvelope {
                reason: "invalid public key length".to_string(),
            })?;

    // Create sealed FederatedOperationAdmission and hydrate registration
    let admission = FederatedOperationAdmission::seal(
        bare_did,
        canon_device_id,
        key_thumbprint,
        sig_key,
        enrollment_auth_generation as u64,
        now,
        tx_id,
        header.sender_ds_did.clone(),
        header.conversation_id,
        header.delivery_id,
        envelope_digest,
        parsed.transition_id,
        "blue.catbird.chat.submitTransition".to_string(),
        *mutation.request_digest(),
        *mutation.signature(),
    )
    .map_err(|e| FederationError::UnauthorizedParticipantDs {
        reason: format!("cannot seal federated operation admission: {e:?}"),
    })?;

    let registration = hydration
        .locked_registration_from_federated_admission(&admission)
        .map_err(|e| FederationError::UnauthorizedParticipantDs {
            reason: format!("cannot create locked registration from federated admission: {e:?}"),
        })?;

    let terminal_packages = hydrate_terminal_recovery_packages(tx, &aggregate)
        .await
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("hydrate_terminal_recovery_packages error: {e:?}"),
        })?;

    let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.submitTransition").map_err(|e| {
        FederationError::InvalidEnvelope {
            reason: format!("invalid endpoint nsid: {e}"),
        }
    })?;

    let control_fields =
        CanonicalControlServerFields::empty(ControlEntryKind::Commit).map_err(|e| {
            FederationError::InvalidEnvelope {
                reason: format!("invalid control server fields: {e}"),
            }
        })?;
    let transcript_bytes = mutation.transcript_bytes().to_vec();

    // Shared operation claim via the federated prelude (replaces handwritten SQL).
    let operation_binding = match prepare_federated_operation(
        tx,
        &admission,
        &mutation,
        &signed_request_bytes,
    )
    .await
    .map_err(|e| FederationError::InvalidEnvelope {
        reason: format!("federated operation arbitration failed: {e:?}"),
    })? {
        FederatedOperationArbitration::First(reservation) => {
            let binding = reservation.binding().clone();
            claim_federated_operation(tx, reservation)
                .await
                .map_err(|e| FederationError::InvalidEnvelope {
                    reason: format!("federated operation claim failed: {e:?}"),
                })?;
            Some(binding)
        }
        FederatedOperationArbitration::Replay(response) => {
            if response.status() != 200 || response.response_bytes().is_empty() {
                return Err(FederationError::CommitConflict {
                    convo_id: header.conversation_id.to_string(),
                    current_epoch: 0,
                });
            }
            // New delivery ID for same operation returns canonical outcome + new receipt.
            // Read the stored source locator from the transition's entry.
            let replay_locator: Option<(Uuid, i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
                r#"
                SELECT entry_id, seq, accepted_payload_sha256, outer_entry_fingerprint
                  FROM chat.entries
                 WHERE transition_id = $1
                "#,
            )
            .bind(parsed.transition_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(FederationError::Database)?;

            let Some((entry_id, seq, accepted_payload_sha256, outer_entry_fingerprint)) =
                replay_locator
            else {
                return Err(FederationError::CommitConflict {
                    convo_id: header.conversation_id.to_string(),
                    current_epoch: 0,
                });
            };
            let replay_source_locator = ValidatedEntryLocator {
                entry_id,
                seq: seq as u64,
                accepted_payload_sha256: accepted_payload_sha256.as_slice().try_into().map_err(
                    |_| FederationError::InvalidEnvelope {
                        reason: "stored source locator payload hash not 32 bytes".to_string(),
                    },
                )?,
                outer_entry_fingerprint: outer_entry_fingerprint.as_slice().try_into().map_err(
                    |_| FederationError::InvalidEnvelope {
                        reason: "stored source locator fingerprint not 32 bytes".to_string(),
                    },
                )?,
            };

            let now = Utc::now();
            let result_sha256: [u8; 32] = Sha256::digest(response.response_bytes()).into();
            let receipt = sign_receipt(
                ack_signer,
                SUBMIT_COMMIT_NSID,
                header.delivery_id,
                header.conversation_id,
                &header.sender_ds_did,
                &header.receiver_ds_did,
                &header.sequencer_did,
                header.sequencer_term,
                envelope_digest,
                result_sha256,
                replay_source_locator.clone(),
                now,
            )?;

            let st_output: catbird_atproto::generated::blue_catbird::chat::submit_transition::SubmitTransitionOutput<
                jacquard_common::DefaultStr,
            > = serde_json::from_slice(response.response_bytes()).map_err(FederationError::Json)?;

            let commit_entry_dto = match st_output.entry {
                catbird_atproto::generated::blue_catbird::chat::ConversationEntry::CommitEntry(
                    entry,
                ) => *entry,
                _ => {
                    return Err(FederationError::InvalidEnvelope {
                        reason: "expected commitEntry in submitTransition output".to_string(),
                    })
                }
            };

            let output = SubmitCommitOutput {
                commit_entry: commit_entry_dto,
                coordinates: st_output.coordinates,
                receipt,
                welcomes: vec![],
                extra_data: None,
            };

            let response_bytes = serde_json::to_vec(&output).map_err(FederationError::Json)?;
            insert_delivery_receipt(tx, &output.receipt, &replay_source_locator, &response_bytes)
                .await?;
            return Ok(output);
        }
    };
    let entry = build_verified_control_entry(
        mutation,
        &endpoint,
        canonical_uuid_v4(parsed.transition_id).map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("invalid transition id: {e:?}"),
        })?,
        canonical_uuid_v4(header.conversation_id).map_err(|e| {
            FederationError::InvalidEnvelope {
                reason: format!("invalid conversation id: {e:?}"),
            }
        })?,
        aggregate.head().next_entry_seq(),
        &trusted_instant,
        control_fields,
    )
    .map_err(|e| FederationError::InvalidEnvelope {
        reason: format!("cannot build verified control entry: {e:?}"),
    })?;
    let request_digest = *entry.mutation().request_digest();
    let signature = *entry.mutation().signature();
    let outer_control_fingerprint = *entry.outer_control_fingerprint();
    let products = CanonicalControlEntryProducts::mint(&entry).map_err(|e| {
        FederationError::InvalidEnvelope {
            reason: format!("cannot mint control entry products: {e:?}"),
        }
    })?;
    let planned = hydration
        .plan_commit_entry(&aggregate, entry, &registration, terminal_packages)
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("plan_commit_entry error: {e:?}"),
        })?;

    let plan = planned
        .into_persistence_plan()
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("into_persistence_plan error: {e:?}"),
        })?;

    let response = canonical_response_from_plan(&plan, products.canonical_response_json())
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("cannot build canonical response: {e:?}"),
        })?;

    let expected_entry_id = parsed.transition_id;
    let expected_seq = aggregate.head().next_entry_seq();
    let expected_coordinate = plan.successor_coordinate().copied();
    let accepted_control_entry_bytes = products.durable_json().to_vec();

    // Source locator for the commit entry. For submitCommit the source entry is
    // planned and applied inside this transaction; on replay the receipt's stored
    // locator is authoritative and the freshly re-derived one is not compared.
    let source_locator = ValidatedEntryLocator {
        entry_id: expected_entry_id,
        seq: expected_seq,
        accepted_payload_sha256: Sha256::digest(&accepted_control_entry_bytes).into(),
        outer_entry_fingerprint: outer_control_fingerprint,
    };

    let prepared_execution =
        prepare_submit_transition_execution(tx, &plan, accepted_control_entry_bytes, None)
            .await
            .map_err(|e| FederationError::InvalidEnvelope {
                reason: format!("prepare_submit_transition_execution error: {e:?}"),
            })?;

    let applied = apply_prepared_submit_transition_execution(prepared_execution)
        .await
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("apply_prepared_submit_transition_execution error: {e:?}"),
        })?;

    validate_applied_transition(
        &applied,
        expected_entry_id,
        expected_seq,
        expected_coordinate.as_ref(),
    )
    .map_err(|e| FederationError::InvalidEnvelope {
        reason: format!("validate_applied_transition error: {e:?}"),
    })?;

    let result_sha256: [u8; 32] = *response.sha256();
    let receipt = sign_receipt(
        ack_signer,
        SUBMIT_COMMIT_NSID,
        header.delivery_id,
        header.conversation_id,
        &header.sender_ds_did,
        &header.receiver_ds_did,
        &header.sequencer_did,
        header.sequencer_term,
        envelope_digest,
        result_sha256,
        source_locator.clone(),
        now,
    )?;

    let st_output: catbird_atproto::generated::blue_catbird::chat::submit_transition::SubmitTransitionOutput<
        jacquard_common::DefaultStr,
    > = serde_json::from_slice(response.as_bytes()).map_err(FederationError::Json)?;

    let commit_entry_dto = match st_output.entry {
        catbird_atproto::generated::blue_catbird::chat::ConversationEntry::CommitEntry(entry) => {
            *entry
        }
        _ => {
            return Err(FederationError::InvalidEnvelope {
                reason: "expected commitEntry in submitTransition output".to_string(),
            })
        }
    };

    let output = SubmitCommitOutput {
        commit_entry: commit_entry_dto,
        coordinates: st_output.coordinates,
        receipt,
        welcomes: vec![],
        extra_data: None,
    };

    let response_bytes = serde_json::to_vec(&output).map_err(FederationError::Json)?;

    // Complete the shared operation claim exactly as the local prelude does.
    let Some(binding) = operation_binding else {
        return Err(FederationError::InvalidEnvelope {
            reason: "missing federated operation claim".to_string(),
        });
    };
    complete_federated_operation(
        tx,
        &binding,
        &signed_request_bytes,
        &transcript_bytes,
        200,
        &response_bytes,
        applied.event_positions.first().copied(),
    )
    .await
    .map_err(|e| match e {
        crate::chat_protocol::repository::prelude::PreludeError::OperationIdConflict => {
            FederationError::CommitConflict {
                convo_id: header.conversation_id.to_string(),
                current_epoch: 0,
            }
        }
        other => FederationError::InvalidEnvelope {
            reason: format!("federated operation completion failed: {other:?}"),
        },
    })?;

    insert_delivery_receipt(tx, &output.receipt, &source_locator, &response_bytes).await?;

    Ok(output)
}

/// Insert a typed source job into `federation_outbox` in the same transaction as state.
pub async fn insert_federation_outbox_job(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    conversation_id: Uuid,
    target_service_did: &str,
    method: &str,
    payload: &[u8],
    payload_sha256: &[u8; 32],
) -> Result<(), FederationError> {
    let target = canonical_did(target_service_did).to_string();
    sqlx::query(
        "INSERT INTO federation_outbox (
            id, conversation_id, target_service_did, method, payload, payload_sha256,
            envelope_version, status, next_attempt_at, created_at, updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6, 1, 'pending', NOW(), NOW(), NOW())",
    )
    .bind(id.to_string())
    .bind(conversation_id.to_string())
    .bind(&target)
    .bind(method)
    .bind(payload)
    .bind(payload_sha256.as_slice())
    .execute(&mut **tx)
    .await
    .map_err(FederationError::Database)?;
    Ok(())
}

/// Find all distinct remote participant DSes for a conversation.
pub async fn find_remote_participant_dses(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    self_ds_did: &str,
) -> Result<Vec<(String, String)>, FederationError> {
    let self_base = canonical_did(self_ds_did).to_string();
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT DISTINCT user_did, ds_did \
         FROM chat.participants \
         WHERE conversation_id = $1 \
           AND current_membership = TRUE \
           AND status = 'active' \
           AND ds_did IS NOT NULL \
           AND ds_did != $2",
    )
    .bind(conversation_id)
    .bind(&self_base)
    .fetch_all(&mut **tx)
    .await
    .map_err(FederationError::Database)?;
    Ok(rows)
}

/// Enqueue a `blue.catbird.mlsDS.deliverMessage` job for a remote participant.
pub async fn enqueue_federated_message_job(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    target_ds_did: &str,
    recipient_did: &str,
    entry: &AppendEntry,
    seq: u64,
    sequencer_term: u64,
) -> Result<Uuid, FederationError> {
    use catbird_atproto::generated::blue_catbird::mlsDS::deliver_message::DeliverMessage;
    use jacquard_common::deps::bytes::Bytes;
    use jacquard_common::deps::smol_str::SmolStr;
    use jacquard_common::types::string::Did;

    let delivery_id = Uuid::new_v4();
    let self_base_did = service_did_base();

    let locator = ValidatedEntryLocator {
        entry_id: entry.entry_id,
        seq,
        accepted_payload_sha256: entry
            .accepted_payload_sha256
            .as_slice()
            .try_into()
            .map_err(|_| FederationError::InvalidEnvelope {
                reason: "invalid accepted_payload_sha256 length".to_string(),
            })?,
        outer_entry_fingerprint: entry
            .outer_entry_fingerprint
            .as_slice()
            .try_into()
            .map_err(|_| FederationError::InvalidEnvelope {
                reason: "invalid outer_entry_fingerprint length".to_string(),
            })?,
    };
    let received_at = CanonicalTimestamp::parse(
        &entry
            .received_at
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    )
    .map_err(|e| FederationError::InvalidEnvelope {
        reason: format!("invalid entry receivedAt: {e}"),
    })?;

    let envelope_header_for_digest = ValidatedEnvelopeHeader {
        protocol_version: "1".to_string(),
        delivery_id,
        conversation_id,
        sender_ds_did: self_base_did.clone(),
        receiver_ds_did: canonical_did(target_ds_did).to_string(),
        sequencer_did: self_base_did.clone(),
        sequencer_term,
        received_at: received_at.clone(),
        payload_sha256: [0u8; 32],
    };

    let envelope_sha256 = compute_message_envelope_digest(
        &envelope_header_for_digest,
        recipient_did,
        &locator,
        &entry.accepted_payload_bytes,
        &entry.signed_request_bytes,
    )?;

    let msg = DeliverMessage::<jacquard_common::DefaultStr> {
        header: EnvelopeHeaderV1 {
            protocol_version: SmolStr::from("1"),
            delivery_id: SmolStr::from(delivery_id.hyphenated().to_string()),
            conversation_id: SmolStr::from(conversation_id.hyphenated().to_string()),
            sender_ds_did: Did::new_owned(self_base_did).map_err(|_| {
                FederationError::InvalidEnvelope {
                    reason: "invalid sender DID".to_string(),
                }
            })?,
            receiver_ds_did: Did::new_owned(canonical_did(target_ds_did).to_string()).map_err(
                |_| FederationError::InvalidEnvelope {
                    reason: "invalid receiver DID".to_string(),
                },
            )?,
            sequencer_did: Did::new_owned(service_did_base()).map_err(|_| {
                FederationError::InvalidEnvelope {
                    reason: "invalid sequencer DID".to_string(),
                }
            })?,
            sequencer_term: sequencer_term as i64,
            received_at: crate::sqlx_jacquard::chrono_to_canonical_datetime(entry.received_at),
            payload_sha256: Bytes::copy_from_slice(&envelope_sha256),
            extra_data: None,
        },
        recipient_did: Did::new_owned(recipient_did.to_string()).map_err(|_| {
            FederationError::InvalidEnvelope {
                reason: "invalid recipient DID".to_string(),
            }
        })?,
        entry_locator: EntryLocatorV1 {
            entry_id: SmolStr::from(locator.entry_id.hyphenated().to_string()),
            seq: locator.seq as i64,
            accepted_payload_sha256: Bytes::copy_from_slice(&locator.accepted_payload_sha256),
            outer_entry_fingerprint: Bytes::copy_from_slice(&locator.outer_entry_fingerprint),
            extra_data: None,
        },
        entry_bytes: Bytes::copy_from_slice(&entry.accepted_payload_bytes),
        signed_request_bytes: Bytes::copy_from_slice(&entry.signed_request_bytes),
        extra_data: None,
    };

    let payload = serde_json::to_vec(&msg).map_err(FederationError::Json)?;
    let payload_sha256: [u8; 32] = Sha256::digest(&payload).into();

    insert_federation_outbox_job(
        tx,
        delivery_id,
        conversation_id,
        target_ds_did,
        DELIVER_MESSAGE_NSID,
        &payload,
        &payload_sha256,
    )
    .await?;

    Ok(delivery_id)
}

/// Enqueue message delivery jobs for all remote participants on a conversation.
pub async fn enqueue_clean_federation_message_jobs(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    entry: &AppendEntry,
    seq: u64,
    sequencer_term: u64,
) -> Result<usize, FederationError> {
    let self_base = service_did_base();
    let remote_participants = find_remote_participant_dses(tx, conversation_id, &self_base).await?;
    let count = remote_participants.len();
    for (user_did, ds_did) in remote_participants {
        enqueue_federated_message_job(
            tx,
            conversation_id,
            &ds_did,
            &user_did,
            entry,
            seq,
            sequencer_term,
        )
        .await?;
    }
    Ok(count)
}

/// Enqueue a `blue.catbird.mlsDS.deliverWelcome` job for a remote participant.
#[allow(clippy::too_many_arguments)]
pub async fn enqueue_federated_welcome_job(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    target_ds_did: &str,
    recipient_did: &str,
    recipient_device_id: Uuid,
    welcome_id: Uuid,
    recovery_request_id: Uuid,
    key_package_ref: &[u8; 32],
    welcome_bytes: &[u8],
    welcome_sha256: &[u8; 32],
    entry: &AppendEntry,
    seq: u64,
    coordinates: ConversationCoordinates,
    public_snapshot_sha256: &[u8; 32],
    tree_summary_sha256: &[u8; 32],
    sequencer_term: u64,
) -> Result<Uuid, FederationError> {
    use catbird_atproto::generated::blue_catbird::mlsDS::deliver_welcome::DeliverWelcome;
    use jacquard_common::deps::bytes::Bytes;
    use jacquard_common::deps::smol_str::SmolStr;
    use jacquard_common::types::string::Did;

    let delivery_id = Uuid::new_v4();
    let self_base_did = service_did_base();

    let participant_exists: Option<Option<String>> = sqlx::query_scalar(
        "SELECT ds_did FROM chat.participants \
         WHERE conversation_id = $1 AND user_did = $2 \
           AND current_membership = TRUE AND status IN ('pending', 'active')",
    )
    .bind(conversation_id)
    .bind(recipient_did)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    if participant_exists.is_none() {
        return Err(FederationError::MailboxNotProvisioned {
            reason: format!(
                "recipient participant {recipient_did} not found in conversation {conversation_id}"
            ),
        });
    }

    let locator = ValidatedEntryLocator {
        entry_id: entry.entry_id,
        seq,
        accepted_payload_sha256: entry
            .accepted_payload_sha256
            .as_slice()
            .try_into()
            .map_err(|_| FederationError::InvalidEnvelope {
                reason: "invalid accepted_payload_sha256 length".to_string(),
            })?,
        outer_entry_fingerprint: entry
            .outer_entry_fingerprint
            .as_slice()
            .try_into()
            .map_err(|_| FederationError::InvalidEnvelope {
                reason: "invalid outer_entry_fingerprint length".to_string(),
            })?,
    };

    let received_at = CanonicalTimestamp::parse(
        &entry
            .received_at
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    )
    .map_err(|e| FederationError::InvalidEnvelope {
        reason: format!("invalid entry receivedAt: {e}"),
    })?;

    let envelope_header_for_digest = ValidatedEnvelopeHeader {
        protocol_version: "1".to_string(),
        delivery_id,
        conversation_id,
        sender_ds_did: self_base_did.clone(),
        receiver_ds_did: canonical_did(target_ds_did).to_string(),
        sequencer_did: self_base_did.clone(),
        sequencer_term,
        received_at: received_at.clone(),
        payload_sha256: [0u8; 32],
    };

    let envelope_sha256 = compute_welcome_envelope_digest(
        &envelope_header_for_digest,
        recipient_did,
        recipient_device_id,
        welcome_id,
        recovery_request_id,
        key_package_ref,
        welcome_bytes,
        welcome_sha256,
        &entry.accepted_payload_bytes,
        &entry.signed_request_bytes,
        &locator,
        &coordinates,
        public_snapshot_sha256,
        tree_summary_sha256,
    )?;

    let msg = DeliverWelcome::<jacquard_common::DefaultStr> {
        header: EnvelopeHeaderV1 {
            protocol_version: SmolStr::from("1"),
            delivery_id: SmolStr::from(delivery_id.hyphenated().to_string()),
            conversation_id: SmolStr::from(conversation_id.hyphenated().to_string()),
            sender_ds_did: Did::new_owned(self_base_did).map_err(|_| {
                FederationError::InvalidEnvelope {
                    reason: "invalid sender DID".to_string(),
                }
            })?,
            receiver_ds_did: Did::new_owned(canonical_did(target_ds_did).to_string()).map_err(
                |_| FederationError::InvalidEnvelope {
                    reason: "invalid receiver DID".to_string(),
                },
            )?,
            sequencer_did: Did::new_owned(service_did_base()).map_err(|_| {
                FederationError::InvalidEnvelope {
                    reason: "invalid sequencer DID".to_string(),
                }
            })?,
            sequencer_term: sequencer_term as i64,
            received_at: crate::sqlx_jacquard::chrono_to_canonical_datetime(entry.received_at),
            payload_sha256: Bytes::copy_from_slice(&envelope_sha256),
            extra_data: None,
        },
        recipient_did: Did::new_owned(recipient_did.to_string()).map_err(|_| {
            FederationError::InvalidEnvelope {
                reason: "invalid recipient DID".to_string(),
            }
        })?,
        recipient_device_id: SmolStr::from(recipient_device_id.hyphenated().to_string()),
        welcome_id: SmolStr::from(welcome_id.hyphenated().to_string()),
        recovery_request_id: SmolStr::from(recovery_request_id.hyphenated().to_string()),
        key_package_ref: Bytes::copy_from_slice(key_package_ref),
        welcome_bytes: Bytes::copy_from_slice(welcome_bytes),
        welcome_sha256: Bytes::copy_from_slice(welcome_sha256),
        entry_bytes: Bytes::copy_from_slice(&entry.accepted_payload_bytes),
        signed_request_bytes: Bytes::copy_from_slice(&entry.signed_request_bytes),
        entry_locator: EntryLocatorV1 {
            entry_id: SmolStr::from(locator.entry_id.hyphenated().to_string()),
            seq: locator.seq as i64,
            accepted_payload_sha256: Bytes::copy_from_slice(&locator.accepted_payload_sha256),
            outer_entry_fingerprint: Bytes::copy_from_slice(&locator.outer_entry_fingerprint),
            extra_data: None,
        },
        coordinates,
        public_snapshot_sha256: Bytes::copy_from_slice(public_snapshot_sha256),
        tree_summary_sha256: Bytes::copy_from_slice(tree_summary_sha256),
        extra_data: None,
    };

    let payload = serde_json::to_vec(&msg).map_err(FederationError::Json)?;
    let payload_sha256: [u8; 32] = Sha256::digest(&payload).into();

    insert_federation_outbox_job(
        tx,
        delivery_id,
        conversation_id,
        target_ds_did,
        DELIVER_WELCOME_NSID,
        &payload,
        &payload_sha256,
    )
    .await?;

    Ok(delivery_id)
}

/// Derive a deterministic canonical UUIDv4 delivery ID for submitCommit.
pub fn derive_submit_commit_delivery_id(
    conversation_id: Uuid,
    transition_id: Uuid,
    sequencer_ds_did: &str,
) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"blue.catbird.mlsDS.submitCommit\0");
    hasher.update(conversation_id.as_bytes());
    hasher.update(transition_id.as_bytes());
    hasher.update(canonical_did(sequencer_ds_did).as_bytes());
    let digest = hasher.finalize();
    let mut uuid_bytes: [u8; 16] = digest[..16].try_into().expect("slice has length 16");
    uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x40;
    uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(uuid_bytes)
}

/// Build a deterministic `blue.catbird.mlsDS.submitCommit` envelope from a mailbox to a sequencer.
pub fn build_federated_commit_envelope(
    conversation_id: Uuid,
    transition_id: Uuid,
    sequencer_ds_did: &str,
    signed_request_bytes: &[u8],
    sequencer_term: u64,
    received_at: &CanonicalTimestamp,
) -> Result<
    catbird_atproto::generated::blue_catbird::mlsDS::submit_commit::SubmitCommit<
        jacquard_common::DefaultStr,
    >,
    FederationError,
> {
    use catbird_atproto::generated::blue_catbird::mlsDS::submit_commit::SubmitCommit;
    use jacquard_common::deps::bytes::Bytes;
    use jacquard_common::deps::smol_str::SmolStr;
    use jacquard_common::types::string::Did;

    let delivery_id =
        derive_submit_commit_delivery_id(conversation_id, transition_id, sequencer_ds_did);
    let self_base_did = service_did_base();
    let target = canonical_did(sequencer_ds_did).to_string();

    let envelope_header_for_digest = ValidatedEnvelopeHeader {
        protocol_version: "1".to_string(),
        delivery_id,
        conversation_id,
        sender_ds_did: self_base_did.clone(),
        receiver_ds_did: target.clone(),
        sequencer_did: target.clone(),
        sequencer_term,
        received_at: received_at.clone(),
        payload_sha256: [0u8; 32],
    };

    let envelope_sha256 =
        compute_commit_envelope_digest(&envelope_header_for_digest, signed_request_bytes)?;

    let msg = SubmitCommit::<jacquard_common::DefaultStr> {
        header: EnvelopeHeaderV1 {
            protocol_version: SmolStr::from("1"),
            delivery_id: SmolStr::from(delivery_id.hyphenated().to_string()),
            conversation_id: SmolStr::from(conversation_id.hyphenated().to_string()),
            sender_ds_did: Did::new_owned(self_base_did).map_err(|_| {
                FederationError::InvalidEnvelope {
                    reason: "invalid sender DID".to_string(),
                }
            })?,
            receiver_ds_did: Did::new_owned(target.clone()).map_err(|_| {
                FederationError::InvalidEnvelope {
                    reason: "invalid receiver DID".to_string(),
                }
            })?,
            sequencer_did: Did::new_owned(target).map_err(|_| {
                FederationError::InvalidEnvelope {
                    reason: "invalid sequencer DID".to_string(),
                }
            })?,
            sequencer_term: sequencer_term as i64,
            received_at: crate::sqlx_jacquard::canonical_to_datetime(received_at),
            payload_sha256: Bytes::copy_from_slice(&envelope_sha256),
            extra_data: None,
        },
        signed_request_bytes: Bytes::copy_from_slice(signed_request_bytes),
        extra_data: None,
    };

    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_derive_submit_commit_delivery_id_fixed_vector() {
        let convo_id = Uuid::from_str("11111111-2222-4333-8444-555555555555").unwrap();
        let trans_id = Uuid::from_str("66666666-7777-4888-8999-aaaaaaaaaaaa").unwrap();
        let sequencer_did = "did:web:chat.example.com";

        let delivery_id = derive_submit_commit_delivery_id(convo_id, trans_id, sequencer_did);
        assert_eq!(
            delivery_id.to_string(),
            "de0a360e-1972-4780-bee0-ffe46ea0e7da",
            "delivery_id must match fixed test vector exactly"
        );
        assert_eq!(delivery_id.get_version_num(), 4, "must be UUIDv4");
    }
}
