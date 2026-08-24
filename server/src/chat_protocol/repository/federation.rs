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

use super::delivery::{
    append_exact_application_entry, compare_exact_application_entry, AppendEntry, ApplicationSend,
};
use super::execution_context::{
    apply_prepared_submit_transition_execution, prepare_submit_transition_execution,
};
use super::submit_transition::{
    canonical_response_from_plan, canonical_uuid_v4, hydrate_terminal_recovery_packages,
    parse_submit_transition, validate_applied_transition, SubmitTransitionFacadeError,
};
use crate::chat_protocol::dpop::VerifiedChatDeviceRequest;
use crate::chat_protocol::relationship_policy::{PublicTransport, RelationshipAuthority};
use crate::chat_protocol::snapshot::PublicGroupSnapshotLifecycle;
use crate::chat_protocol::state_machine::HydrationAuthority;
use crate::chat_protocol::transcript::{
    build_verified_control_entry, decode_and_verify_application_entry,
    decode_and_verify_control_entry, decode_and_verify_signed_mutation,
    decode_canonical_signed_mutation, rebind_persisted_control_entry,
    CanonicalControlEntryProducts, CanonicalControlServerFields, CanonicalSignedMutation,
    ControlEntryKind, SignedMutationKind, VerifiedApplicationEntry, VerifiedMutationProjection,
    VerifiedSignedMutation,
};
use crate::chat_protocol::validation::{
    BareDid, CanonicalUuidV4, KeyThumbprint, TrustedRequestInstant, ValidatedChatNsid,
    MAX_SAFE_INTEGER,
};
use crate::federation::ack::AckSigner;
use crate::federation::envelope::{
    canonical_receipt_bytes, compute_commit_envelope_digest, compute_message_envelope_digest,
    compute_welcome_envelope_digest, sign_receipt, validate_entry_locator,
    validate_envelope_header, ValidatedEntryLocator, ValidatedEnvelopeHeader, DELIVER_MESSAGE_NSID,
    DELIVER_WELCOME_NSID, SUBMIT_COMMIT_NSID,
};
use crate::federation::errors::FederationError;

const ADVISORY_LOCK_NAMESPACE: i32 = 0x43415442; // 'CATB'

/// Acquire a transaction-scoped advisory lock on a delivery ID.
pub async fn lock_delivery_id(
    tx: &mut Transaction<'_, Postgres>,
    delivery_id: Uuid,
) -> Result<(), FederationError> {
    let (high, low) = uuid_to_i64_pair(delivery_id);
    sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
        .bind(ADVISORY_LOCK_NAMESPACE)
        .bind(low ^ high)
        .execute(&mut **tx)
        .await
        .map_err(FederationError::Database)?;
    Ok(())
}

fn uuid_to_i64_pair(id: Uuid) -> (i64, i64) {
    let bytes = id.as_bytes();
    let high = i64::from_be_bytes(bytes[0..8].try_into().unwrap());
    let low = i64::from_be_bytes(bytes[8..16].try_into().unwrap());
    (high, low)
}

/// Check if an exact delivery receipt already exists, returning the stored response bytes on replay.
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
        Option<Uuid>,
        Option<i64>,
        Option<Vec<u8>>,
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
        _stored_response_sha256,
        _stored_signature,
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

    if let Some(loc) = source_locator {
        if stored_source_entry_id != Some(loc.entry_id)
            || stored_source_entry_seq != Some(loc.seq as i64)
            || stored_source_entry_fingerprint != Some(loc.outer_entry_fingerprint.to_vec())
        {
            return Err(FederationError::DeliveryConflict {
                reason: "entry locator differs from prior delivery with same deliveryId"
                    .to_string(),
            });
        }
    } else if stored_source_entry_id.is_some() {
        return Err(FederationError::DeliveryConflict {
            reason: "entry locator unexpectedly present in prior delivery with same deliveryId"
                .to_string(),
        });
    }

    Ok(Some(stored_response_bytes))
}

/// Insert an immutable federation delivery receipt.
#[allow(clippy::too_many_arguments)]
pub async fn insert_delivery_receipt(
    tx: &mut Transaction<'_, Postgres>,
    receipt: &FederationReceiptV1,
    source_locator: Option<&ValidatedEntryLocator>,
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

    let (source_id, source_seq, source_fp) = match source_locator {
        Some(loc) => (
            Some(loc.entry_id),
            Some(loc.seq as i64),
            Some(loc.outer_entry_fingerprint.to_vec()),
        ),
        None => (None, None, None),
    };

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
    .bind(source_id)
    .bind(source_seq)
    .bind(source_fp)
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

    // 1. Lock conversation and verify remote mailbox routing.
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
        return Err(FederationError::MailboxNotProvisioned {
            reason: format!(
                "conversation {} not found on destination DS",
                header.conversation_id
            ),
        });
    };

    if !is_remote || sequencer_ds.as_deref() != Some(&header.sequencer_did) {
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

    // 2. Lock recipient participant and device.
    let participant_row: Option<(String, String)> = sqlx::query_as(
        r#"
        SELECT status, role
          FROM chat.participants
         WHERE conversation_id = $1 AND user_did = $2 AND current_membership = TRUE
         FOR UPDATE
        "#,
    )
    .bind(header.conversation_id)
    .bind(&recipient_did)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    let Some((p_status, _role)) = participant_row else {
        return Err(FederationError::MailboxNotProvisioned {
            reason: format!(
                "recipient {} is not a participant in conversation {}",
                recipient_did, header.conversation_id
            ),
        });
    };

    if p_status != "pending" && p_status != "active" {
        return Err(FederationError::MailboxNotProvisioned {
            reason: format!("recipient status is {p_status}, expected pending or active"),
        });
    }

    // 3. Verify welcome bundle and delivery row.
    let welcome_row: Option<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
        r#"
        SELECT b.welcome_data, b.welcome_sha256, b.entry_seq
          FROM chat.welcome_deliveries d
          JOIN chat.welcome_bundles b ON b.welcome_id = d.welcome_id
         WHERE d.welcome_id = $1 AND d.recipient_device_id = $2
           AND d.recovery_request_id = $3
         FOR UPDATE
        "#,
    )
    .bind(welcome_id)
    .bind(recipient_device_id)
    .bind(recovery_request_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    let Some((stored_welcome_data, stored_welcome_sha256, stored_entry_seq)) = welcome_row else {
        return Err(FederationError::MailboxNotProvisioned {
            reason: "preprovisioned welcome delivery row not found".to_string(),
        });
    };

    if stored_welcome_data != welcome_bytes
        || stored_welcome_sha256 != welcome_sha256
        || stored_entry_seq != entry_locator.seq as i64
    {
        return Err(FederationError::DeliveryConflict {
            reason: "welcome delivery material does not match preprovisioned bundle".to_string(),
        });
    }

    // 4. Build and sign federation receipt.
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
        Some(entry_locator.clone()),
        now,
    )?;

    let output = DeliverWelcomeOutput {
        accepted: true,
        receipt,
        extra_data: None,
    };

    let response_bytes = serde_json::to_vec(&output).map_err(FederationError::Json)?;

    insert_delivery_receipt(
        tx,
        &output.receipt,
        Some(&entry_locator),
        &response_bytes,
    )
    .await?;

    Ok(output)
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

    // 1. Lock conversation and verify remote mailbox routing.
    let convo_row: Option<(bool, Option<String>, i64, i64)> = sqlx::query_as(
        r#"
        SELECT is_remote, sequencer_ds, sequencer_term, current_generation
          FROM chat.conversations
         WHERE conversation_id = $1
         FOR UPDATE
        "#,
    )
    .bind(header.conversation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    let Some((is_remote, sequencer_ds, sequencer_term, current_generation)) = convo_row else {
        return Err(FederationError::MailboxNotProvisioned {
            reason: format!(
                "conversation {} not found on destination DS",
                header.conversation_id
            ),
        });
    };

    if !is_remote || sequencer_ds.as_deref() != Some(&header.sequencer_did) {
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

    // 2. Verify recipient participant and application interval.
    let recipient_row: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT status
          FROM chat.participants
         WHERE conversation_id = $1 AND user_did = $2 AND current_membership = TRUE
         FOR UPDATE
        "#,
    )
    .bind(header.conversation_id)
    .bind(&recipient_did)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    let Some((p_status,)) = recipient_row else {
        return Err(FederationError::UnauthorizedRecipient {
            reason: format!("user {} is not a participant", recipient_did),
        });
    };

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
    let mutation = decode_canonical_signed_mutation(&signed_request_bytes)
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("cannot decode signed request: {e}"),
        })?;

    let actor_did = mutation.actor_did().as_str();
    let actor_device_id = Uuid::from_bytes(*mutation.actor_device_id().as_bytes());
    let actor_key_id = mutation.key_id().as_str();

    let key_row: Option<(Vec<u8>,)> = sqlx::query_as(
        r#"
        SELECT public_key
          FROM chat.device_keys
         WHERE user_did = $1 AND device_id = $2 AND key_id = $3 AND status = 'active'
         FOR UPDATE
        "#,
    )
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(actor_key_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    let Some((actor_public_key,)) = key_row else {
        return Err(FederationError::MailboxNotProvisioned {
            reason: format!("actor device key {actor_key_id} not provisioned on destination DS"),
        });
    };

    let verified_entry = decode_and_verify_application_entry(&entry_bytes, &actor_public_key)
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("application entry verification failed: {e}"),
        })?;

    let projection = match verified_entry.mutation().projection() {
        VerifiedMutationProjection::ApplicationSend(p) => p,
        _ => {
            return Err(FederationError::InvalidEnvelope {
                reason: "not an application send mutation".to_string(),
            })
        }
    };
    let message_id = Uuid::from_bytes(*projection.message_id().as_bytes());

    let entry_id_canonical = CanonicalUuidV4::parse(verified_entry.entry_id().as_str())
        .map_err(|_| FederationError::InvalidEnvelope {
            reason: "invalid entry_id in entry".to_string(),
        })?;
    let conversation_id_canonical =
        CanonicalUuidV4::parse(verified_entry.conversation_id().as_str()).map_err(|_| {
            FederationError::InvalidEnvelope {
                reason: "invalid conversation_id in entry".to_string(),
            }
        })?;

    let response = serde_json::json!({
        "entry": {
            "entryId": entry_id_canonical.as_str(),
            "conversationId": conversation_id_canonical.as_str(),
            "seq": locator.seq,
            "signedRequest": serde_json::from_slice::<serde_json::Value>(&signed_request_bytes).map_err(FederationError::Json)?,
            "receivedAt": verified_entry.received_at().as_str()
        }
    });
    let outcome_bytes = serde_json::to_vec(&response).map_err(FederationError::Json)?;

    let send = ApplicationSend {
        entry: AppendEntry {
            conversation_id: header.conversation_id,
            entry_id: locator.entry_id,
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_string(),
            accepted_payload_bytes: entry_bytes,
            accepted_payload_sha256: locator.accepted_payload_sha256.to_vec(),
            signed_request_bytes,
            request_digest: verified_entry.mutation().request_digest().to_vec(),
            signature: verified_entry.mutation().signature().to_vec(),
            server_fields_bytes: serde_ipld_dagcbor::to_vec(&std::collections::BTreeMap::<
                String,
                String,
            >::new())
            .map_err(|_| FederationError::InvalidEnvelope {
                reason: "server fields serialization failed".to_string(),
            })?,
            outer_entry_fingerprint: locator.outer_entry_fingerprint.to_vec(),
            actor_did: actor_did.to_string(),
            actor_device_id,
            actor_key_id: actor_key_id.to_string(),
            actor_auth_generation: verified_entry.mutation().auth_generation() as i64,
            generation: Some(current_generation),
            state_version: None,
            transition_id: None,
            message_id: Some(message_id),
            received_at: DateTime::parse_from_rfc3339(verified_entry.received_at().as_str())
                .map_err(|e| FederationError::InvalidEnvelope {
                    reason: format!("invalid receivedAt: {e}"),
                })?
                .with_timezone(&Utc),
        },
        signing_transcript_bytes: verified_entry.mutation().transcript_bytes().to_vec(),
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
        let is_exact = compare_exact_application_entry(tx, &send, locator.seq)
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
        // Reserve operation claim in chat.operation_claims
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
        .bind(DELIVER_MESSAGE_NSID)
        .bind("sendMessage")
        .bind(&send.entry.request_digest)
        .bind(&send.entry.accepted_payload_sha256)
        .bind(&send.entry.signature)
        .bind(send.entry.received_at)
        .execute(&mut **tx)
        .await;

        if let Err(e) = claim_res {
            if e.as_database_error().and_then(|db| db.code()).as_deref() == Some("23505") {
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
    }

    // 5. Sign and insert receipt.
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
        Some(locator.clone()),
        now,
    )?;

    let output = DeliverMessageOutput {
        accepted: true,
        receipt,
        extra_data: None,
    };

    let response_bytes = serde_json::to_vec(&output).map_err(FederationError::Json)?;

    insert_delivery_receipt(tx, &output.receipt, Some(&locator), &response_bytes).await?;

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

    if let Some(cached_bytes) = check_delivery_receipt(
        tx,
        SUBMIT_COMMIT_NSID,
        &header,
        &envelope_digest,
        None,
    )
    .await?
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

    let Some((is_remote, _sequencer_ds, sequencer_term)) = convo_row else {
        return Err(FederationError::ConversationNotFound {
            convo_id: header.conversation_id.to_string(),
        });
    };

    if is_remote {
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
    let canonical = decode_canonical_signed_mutation(&signed_request_bytes)
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("invalid signed mutation: {e}"),
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

    // Check participant's ds_did matches sender_ds_did
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

    if p_ds_did.as_deref() != Some(&header.sender_ds_did) {
        return Err(FederationError::UnauthorizedParticipantDs {
            reason: format!(
                "participant ds_did {:?} does not match senderDsDid {}",
                p_ds_did, header.sender_ds_did
            ),
        });
    }

    // Fetch actor signing public key
    let key_row: Option<(Vec<u8>,)> = sqlx::query_as(
        r#"
        SELECT public_key
          FROM chat.device_keys
         WHERE user_did = $1 AND device_id = $2 AND key_id = $3 AND status = 'active'
         FOR UPDATE
        "#,
    )
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(actor_key_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    let Some((public_key,)) = key_row else {
        return Err(FederationError::UnauthorizedParticipantDs {
            reason: "actor device key not found or revoked".to_string(),
        });
    };

    let mutation = decode_and_verify_signed_mutation(&signed_request_bytes, &public_key)
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("mutation signature verification failed: {e}"),
        })?;

    let parsed = parse_submit_transition(&mutation).map_err(|e| {
        FederationError::InvalidEnvelope {
            reason: format!("cannot parse submit transition: {e:?}"),
        }
    })?;

    // 3. Hydrate locked conversation state and plan commit transition.
    let now = Utc::now();
    let trusted_instant = TrustedRequestInstant::from_datetime(now).map_err(|e| {
        FederationError::InvalidEnvelope {
            reason: format!("invalid instant: {e}"),
        }
    })?;

    let aggregate = super::core::hydrate_locked_conversation_state(
        tx,
        header.conversation_id,
        now,
    )
    .await
    .map_err(|_| FederationError::CommitConflict {
        convo_id: header.conversation_id.to_string(),
        current_epoch: 0,
    })?;
    let hydration = HydrationAuthority::from_locked_conversation(&aggregate).map_err(|_| {
        FederationError::CommitConflict {
            convo_id: header.conversation_id.to_string(),
            current_epoch: 0,
        }
    })?;

    // Create locked registration directly from stored device row
    let registration = hydration
        .locked_registration_from_raw_parts(
            BareDid::parse(actor_did).unwrap(),
            CanonicalUuidV4::parse(&actor_device_id.hyphenated().to_string()).unwrap(),
            KeyThumbprint::parse(actor_key_id).unwrap(),
            public_key.as_slice().try_into().unwrap(),
            mutation.auth_generation(),
            now,
        )
        .map_err(|e| FederationError::UnauthorizedParticipantDs {
            reason: format!("cannot create locked registration: {e:?}"),
        })?;

    let terminal_packages = hydrate_terminal_recovery_packages(tx, &aggregate).await.map_err(
        |_| FederationError::CommitConflict {
            convo_id: header.conversation_id.to_string(),
            current_epoch: 0,
        },
    )?;

    let endpoint = ValidatedChatNsid::parse(SUBMIT_COMMIT_NSID).map_err(|e| {
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
    let products = CanonicalControlEntryProducts::mint(&entry).map_err(|e| {
        FederationError::InvalidEnvelope {
            reason: format!("cannot mint control entry products: {e:?}"),
        }
    })?;

    let planned = hydration
        .plan_commit_entry(&aggregate, entry, &registration, terminal_packages)
        .map_err(|e| FederationError::CommitConflict {
            convo_id: header.conversation_id.to_string(),
            current_epoch: aggregate.state().coordinate().epoch() as i32,
        })?;

    let plan = planned
        .into_persistence_plan()
        .map_err(|e| FederationError::CommitConflict {
            convo_id: header.conversation_id.to_string(),
            current_epoch: 0,
        })?;

    let response = canonical_response_from_plan(&plan, products.canonical_response_json())
        .map_err(|e| FederationError::InvalidEnvelope {
            reason: format!("cannot build canonical response: {e:?}"),
        })?;

    let expected_entry_id = parsed.transition_id;
    let expected_seq = aggregate.head().next_entry_seq();
    let expected_coordinate = plan.successor_coordinate().copied();
    let accepted_control_entry_bytes = products.durable_json().to_vec();
    // Reserve operation claim
    let signed_req_sha256: [u8; 32] = Sha256::digest(&signed_request_bytes).into();
    let claim_res = sqlx::query(
        r#"
        INSERT INTO chat.operation_claims (
            operation_id, principal_did, endpoint_nsid, mutation_kind,
            request_digest, accepted_request_sha256, signature, claimed_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(parsed.transition_id)
    .bind(actor_did)
    .bind(SUBMIT_COMMIT_NSID)
    .bind("submitTransition")
    .bind(request_digest.as_slice())
    .bind(signed_req_sha256.as_slice())
    .bind(signature.as_slice())
    .bind(now)
    .execute(&mut **tx)
    .await;

    if let Err(e) = claim_res {
        if e.as_database_error().and_then(|db| db.code()).as_deref() == Some("23505") {
            return Err(FederationError::CommitConflict {
                convo_id: header.conversation_id.to_string(),
                current_epoch: 0,
            });
        }
        return Err(FederationError::Database(e));
    }

    let prepared_execution = prepare_submit_transition_execution(
        tx,
        &plan,
        accepted_control_entry_bytes,
        None,
    )
    .await
    .map_err(|e| FederationError::CommitConflict {
        convo_id: header.conversation_id.to_string(),
        current_epoch: 0,
    })?;

    let applied = apply_prepared_submit_transition_execution(prepared_execution)
        .await
        .map_err(|e| FederationError::CommitConflict {
            convo_id: header.conversation_id.to_string(),
            current_epoch: 0,
        })?;

    validate_applied_transition(
        &applied,
        expected_entry_id,
        expected_seq,
        expected_coordinate.as_ref(),
    )
    .map_err(|e| FederationError::CommitConflict {
        convo_id: header.conversation_id.to_string(),
        current_epoch: 0,
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
        None,
        now,
    )?;

    let commit_entry_raw: serde_json::Value =
        serde_json::from_slice(response.as_bytes()).map_err(FederationError::Json)?;
    let commit_entry = commit_entry_raw
        .get("entry")
        .cloned()
        .ok_or_else(|| FederationError::InvalidEnvelope {
            reason: "missing entry in response".to_string(),
        })?;

    let commit_entry_dto: CommitEntry =
        serde_json::from_value(commit_entry).map_err(FederationError::Json)?;

    let coordinates_raw = commit_entry_raw
        .get("coordinates")
        .cloned()
        .ok_or_else(|| FederationError::InvalidEnvelope {
            reason: "missing coordinates in response".to_string(),
        })?;
    let coordinates_dto: ConversationCoordinates =
        serde_json::from_value(coordinates_raw).map_err(FederationError::Json)?;

    let output = SubmitCommitOutput {
        commit_entry: commit_entry_dto,
        coordinates: coordinates_dto,
        receipt,
        welcomes: Vec::new(),
        extra_data: None,
    };

    let response_bytes = serde_json::to_vec(&output).map_err(FederationError::Json)?;

    insert_delivery_receipt(tx, &output.receipt, None, &response_bytes).await?;

    Ok(output)
}
