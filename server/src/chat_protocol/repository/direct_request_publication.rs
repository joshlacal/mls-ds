//! Transaction-bound publication planning. No caller-supplied boolean can mint
//! artifact, preparation, pair or legacy authority. The eventual executor must
//! consume this capsule inside the same transaction and commit all effects.
use super::direct_request_preparation::{
    self as preparation, DirectRequestPublicationAdmission, DirectRequestStoreError,
    LockedDirectRequestPublication, PublicationDisposition,
};
use super::direct_request_receipts::DirectRequestReceiptSigner;
use super::direct_request_retention;
use crate::chat_protocol::{
    relationship_policy::{PublicTransport, RelationshipAuthority},
    request_push::request_push_event_payload_digest,
    snapshot::{PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle},
    state_machine::direct_request::{self, GrantedRequestDevice, VerifiedBootstrap},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[path = "direct_request_publication_charge.rs"]
pub(crate) mod retained_charge;

#[derive(Debug, thiserror::Error)]
pub(crate) enum PublicationError {
    #[error("request publication producers disabled")]
    Disabled,
    #[error(transparent)]
    Store(#[from] DirectRequestStoreError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error("inconsistent publication storage authority")]
    Invariant,
}
pub(crate) enum PublicationPreparation {
    Terminal(Vec<u8>),
    Ready(Box<PreparedPublication>),
}
/// Private, single-use authority. It is intentionally not Clone. A HTTP
/// handler cannot synthesize this from a DTO or reuse it in another transaction.
pub(crate) struct PreparedPublication {
    transaction_id: String,
    candidate: LockedDirectRequestPublication,
    bootstrap: VerifiedBootstrap,
    actor_key: Vec<u8>,
    selected: Vec<GrantedRequestDevice>,
    prior: Option<PublicGroupSnapshotCoordinate>,
    next_seq: i64,
}
impl PreparedPublication {
    pub(super) async fn require_transaction(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), PublicationError> {
        let actual: String = sqlx::query_scalar("SELECT txid_current()::text")
            .fetch_one(&mut **tx)
            .await?;
        if actual != self.transaction_id {
            return Err(PublicationError::Invariant);
        }
        Ok(())
    }
}
#[derive(sqlx::FromRow)]
struct SelectedRow {
    owner_did: String,
    owner_device_id: Uuid,
    signing_public_key: Vec<u8>,
    key_package_ref: Vec<u8>,
    grant_id: Uuid,
    revision: i64,
    expires_at: DateTime<Utc>,
}
#[derive(sqlx::FromRow)]
struct PriorRow {
    conversation_id: Uuid,
    current_generation: i64,
    current_state_version: i64,
    group_id: Vec<u8>,
    epoch: i64,
    group_context_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
    next_entry_seq: i64,
}
fn h(bytes: Vec<u8>) -> Result<[u8; 32], PublicationError> {
    bytes.try_into().map_err(|_| PublicationError::Invariant)
}
fn string<'a>(body: &'a Value, key: &str) -> Result<&'a str, PublicationError> {
    body[key].as_str().ok_or(PublicationError::Invariant)
}
fn time(now: DateTime<Utc>) -> String {
    now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
async fn terminal(
    tx: &mut Transaction<'_, Postgres>,
    candidate: LockedDirectRequestPublication,
    signer: &DirectRequestReceiptSigner,
    disposition: PublicationDisposition,
    kind: &str,
    extra: Value,
) -> Result<PublicationPreparation, PublicationError> {
    let b = candidate.signed().body();
    let mut receipt = json!({"$type":format!("blue.catbird.chat.defs#{kind}"),"requestId":b["requestId"],"requestDigest":STANDARD.encode(candidate.signed().request_digest()),"preparationRequestDigest":b["preparationRequestDigest"],"actorDid":b["actorDid"],"actorDeviceId":b["actorDeviceId"],"actorKeyId":b["keyId"],"authGeneration":b["authGeneration"],"requestKind":"publish","recordedAt":time(candidate.trusted_instant())});
    for (k, v) in extra.as_object().ok_or(PublicationError::Invariant)? {
        receipt[k] = v.clone();
    }
    let receipt=signer.seal_outcome(json!({"$type":"blue.catbird.chat.defs#directRequestReceiptBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-OUTCOME\u{0}","protocolVersion":"2","authorityDid":"did:web:chat.catbird.blue","keyId":signer.key_id(),"receipt":receipt})).map_err(|_|PublicationError::Invariant)?;
    Ok(PublicationPreparation::Terminal(
        preparation::complete_publication(tx, candidate, disposition, &receipt).await?,
    ))
}

/// Does not write a candidate conversation. Terminal decisions are durably
/// recorded under the same operation lock as cancel; caller commits that result.
pub(crate) async fn prepare_publication<T: PublicTransport>(
    tx: &mut Transaction<'_, Postgres>,
    principal: &crate::auth::VerifiedServicePrincipal,
    raw: &[u8],
    signer: &DirectRequestReceiptSigner,
    policy: &RelationshipAuthority<T>,
    now: DateTime<Utc>,
    producers_enabled: bool,
) -> Result<PublicationPreparation, PublicationError> {
    let candidate = match preparation::admit_publication(tx, principal, raw, now).await? {
        DirectRequestPublicationAdmission::Terminal(bytes) => {
            return Ok(PublicationPreparation::Terminal(bytes))
        }
        DirectRequestPublicationAdmission::Candidate(candidate) => candidate,
    };
    if !producers_enabled {
        return Err(PublicationError::Disabled);
    }
    if let Err(error) = candidate.validate_preparation(tx).await {
        let code = match error {
            DirectRequestStoreError::Expired => "PreparationExpired",
            DirectRequestStoreError::IncludedAuthorityChanged => "PreparationRevoked",
            DirectRequestStoreError::Database(error) => return Err(error.into()),
            _ => "PreparationConflict",
        };
        return terminal(
            tx,
            candidate,
            signer,
            PublicationDisposition::Rejected,
            "directRequestRejectedReceipt",
            json!({"code":code}),
        )
        .await;
    }
    if let Err(error) = candidate.validate_policy(tx, policy).await {
        match error {
            DirectRequestStoreError::Database(error) => return Err(error.into()),
            _ => {
                return terminal(
                    tx,
                    candidate,
                    signer,
                    PublicationDisposition::Rejected,
                    "directRequestRejectedReceipt",
                    json!({"code":"RequestPolicyDenied"}),
                )
                .await
            }
        }
    }
    let b = candidate.signed().body();
    let actor = string(b, "actorDid")?;
    let recipient = string(b, "recipientDid")?;
    let actor_device =
        Uuid::parse_str(string(b, "actorDeviceId")?).map_err(|_| PublicationError::Invariant)?;
    let conversation_id =
        Uuid::parse_str(string(b, "conversationId")?).map_err(|_| PublicationError::Invariant)?;
    let (low, high) = if actor < recipient {
        (actor, recipient)
    } else {
        (recipient, actor)
    };
    // Both principals are already locked in T03's canonical prefix. This pair
    // lock also shares ordering with ordinary direct creation through principals.
    let existing:Option<Uuid>=sqlx::query_scalar("SELECT conversation_id FROM chat.conversations WHERE kind='direct' AND lifecycle='active' AND direct_did_low=$1 AND direct_did_high=$2 FOR UPDATE")
        .bind(low).bind(high).fetch_optional(&mut **tx).await?;
    let legacy =
        string(&b["origin"], "$type")? == "blue.catbird.chat.defs#legacyPendingDirectOrigin";
    if let Some(existing) = existing {
        if !legacy || existing != conversation_id {
            let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership AND status='pending')").bind(existing).bind(actor).fetch_one(&mut **tx).await?;
            return terminal(
                tx,
                candidate,
                signer,
                PublicationDisposition::ExistingDirect,
                "directRequestExistingDirectReceipt",
                json!({"conversationId":existing.to_string(),"requiresAcceptance":pending}),
            )
            .await;
        }
    }
    let (prior, next_seq) = if legacy {
        let row:Option<PriorRow>=sqlx::query_as("SELECT c.conversation_id,c.current_generation,c.current_state_version,s.group_id,s.epoch,s.group_context_hash,s.confirmation_tag,c.next_entry_seq FROM chat.conversations c JOIN chat.generation_states s ON s.conversation_id=c.conversation_id AND s.generation=c.current_generation AND s.state_version=c.current_state_version WHERE c.conversation_id=$1 AND c.kind='direct' AND c.lifecycle='active' AND c.protocol_version='1' FOR UPDATE OF c")
            .bind(conversation_id).fetch_optional(&mut **tx).await?;
        let eligible:bool=sqlx::query_scalar(r#"SELECT count(*)=2 AND count(*) FILTER(WHERE user_did=$2 AND status='active' AND created_by_did=$2)=1 AND count(*) FILTER(WHERE user_did=$3 AND status='pending' AND created_by_did=$2)=1 FROM chat.participants WHERE conversation_id=$1 AND current_membership"#)
            .bind(conversation_id).bind(actor).bind(recipient).fetch_one(&mut **tx).await?;
        let recipient_leaf:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active)").bind(conversation_id).bind(recipient).fetch_one(&mut **tx).await?;
        let provenance:Option<(Uuid,String,Uuid)>=sqlx::query_as("SELECT invitation_transition_id,created_by_did,created_by_device_id FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership AND status='pending'").bind(conversation_id).bind(recipient).fetch_optional(&mut **tx).await?;
        let exact_provenance =
            provenance.is_some_and(|(transition, invited_by, invited_device)| {
                let p = &b["origin"]["originalInvitationProvenance"];
                p["invitationTransitionId"] == transition.to_string()
                    && p["invitedByDid"] == invited_by
                    && p["invitedByDeviceId"] == invited_device.to_string()
            });
        // Pending predecessor control/recovery work carries its own immutable
        // authority. A legacy upgrade cannot silently supersede that work.
        let conflicting_work:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM chat.reset_requests WHERE conversation_id=$1 AND status='pending') OR EXISTS(SELECT 1 FROM chat.leaf_recovery_requests WHERE conversation_id=$1 AND status='open') OR EXISTS(SELECT 1 FROM chat.key_package_reservations WHERE conversation_id=$1 AND status='active') OR EXISTS(SELECT 1 FROM chat.leave_requests WHERE conversation_id=$1 AND status='pending') OR EXISTS(SELECT 1 FROM chat.recovery_work_items WHERE conversation_id=$1 AND status='pending') OR EXISTS(SELECT 1 FROM chat.welcome_deliveries d JOIN chat.welcome_bundles b USING(welcome_id) WHERE b.conversation_id=$1 AND d.status='pending')")
            .bind(conversation_id).fetch_one(&mut **tx).await?;
        if !eligible || recipient_leaf || !exact_provenance || row.is_none() || conflicting_work {
            return terminal(
                tx,
                candidate,
                signer,
                PublicationDisposition::Rejected,
                "directRequestRejectedReceipt",
                json!({"code":"StaleLegacyPrior"}),
            )
            .await;
        }
        let row = row.ok_or(PublicationError::Invariant)?;
        let prior = PublicGroupSnapshotCoordinate::new(
            *row.conversation_id.as_bytes(),
            row.current_generation as u64,
            row.current_state_version as u64,
            h(row.group_id)?,
            row.epoch as u64,
            h(row.group_context_hash)?,
            h(row.confirmation_tag)?,
            PublicGroupSnapshotLifecycle::Active,
        );
        (Some(prior), row.next_entry_seq)
    } else {
        (None, 1)
    };
    let actor_key:Vec<u8>=sqlx::query_scalar("SELECT signing_public_key FROM chat.device_keys WHERE user_did=$1 AND device_id=$2 AND key_id=$3")
        .bind(actor).bind(actor_device).bind(candidate.signed().key_id()).fetch_one(&mut **tx).await?;
    let rows:Vec<SelectedRow>=sqlx::query_as("SELECT s.owner_did,s.owner_device_id,k.signing_public_key,s.key_package_ref,s.grant_id,g.revision,g.expires_at FROM chat.direct_request_selected_devices s JOIN chat.direct_request_grants g USING(grant_id) JOIN chat.device_keys k ON k.user_did=s.owner_did AND k.device_id=s.owner_device_id AND k.key_id=s.owner_key_id WHERE s.request_id=$1 ORDER BY s.owner_did,s.owner_device_id")
        .bind(candidate.request_id()).fetch_all(&mut **tx).await?;
    let selected = rows
        .into_iter()
        .map(|row| {
            Ok(GrantedRequestDevice {
                did: row.owner_did,
                device_id: row.owner_device_id,
                signature_key: row.signing_public_key,
                package_ref: h(row.key_package_ref)?,
                grant_id: row.grant_id,
                grant_revision: u64::try_from(row.revision)
                    .map_err(|_| PublicationError::Invariant)?,
                grant_expires_at: u64::try_from(row.expires_at.timestamp())
                    .map_err(|_| PublicationError::Invariant)?,
            })
        })
        .collect::<Result<Vec<_>, PublicationError>>()?;
    let bootstrap = match direct_request::verify_bootstrap(
        candidate.signed(),
        &actor_key,
        &selected,
        prior.as_ref(),
        u64::try_from(
            candidate.trusted_instant().timestamp()
                + i64::from(candidate.trusted_instant().timestamp_subsec_nanos() != 0),
        )
        .map_err(|_| PublicationError::Invariant)?,
    ) {
        Ok(bootstrap) => bootstrap,
        Err(error) => {
            let code = match error {
                direct_request::BootstrapError::ImportDeadline => "ImportHorizonTooShort",
                direct_request::BootstrapError::LegacyIneligible => "StaleLegacyPrior",
                _ => "InvalidBootstrap",
            };
            return terminal(
                tx,
                candidate,
                signer,
                PublicationDisposition::Rejected,
                "directRequestRejectedReceipt",
                json!({"code":code}),
            )
            .await;
        }
    };
    if b["artifacts"]["metadataSnapshot"]["authorProof"]["originSeq"].as_i64() != Some(next_seq) {
        return terminal(
            tx,
            candidate,
            signer,
            PublicationDisposition::Rejected,
            "directRequestRejectedReceipt",
            json!({"code":"InvalidBootstrap"}),
        )
        .await;
    }
    let transaction_id = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **tx)
        .await?;
    Ok(PublicationPreparation::Ready(Box::new(
        PreparedPublication {
            transaction_id,
            candidate,
            bootstrap,
            actor_key,
            selected,
            prior,
            next_seq,
        },
    )))
}

fn binary(value: &Value) -> Result<Vec<u8>, PublicationError> {
    STANDARD
        .decode(value.as_str().ok_or(PublicationError::Invariant)?)
        .map_err(|_| PublicationError::Invariant)
}
fn id(value: &Value) -> Result<Uuid, PublicationError> {
    Uuid::parse_str(value.as_str().ok_or(PublicationError::Invariant)?)
        .map_err(|_| PublicationError::Invariant)
}
fn encode(value: &Value) -> Result<Vec<u8>, PublicationError> {
    serde_json::to_vec(value).map_err(|_| PublicationError::Invariant)
}

async fn reject_prepared(
    tx: &mut Transaction<'_, Postgres>,
    candidate: LockedDirectRequestPublication,
    signer: &DirectRequestReceiptSigner,
    code: &str,
) -> Result<Vec<u8>, PublicationError> {
    match terminal(
        tx,
        candidate,
        signer,
        PublicationDisposition::Rejected,
        "directRequestRejectedReceipt",
        json!({"code":code}),
    )
    .await?
    {
        PublicationPreparation::Terminal(bytes) => Ok(bytes),
        PublicationPreparation::Ready(_) => Err(PublicationError::Invariant),
    }
}

/// Apply the complete prepared publication in the caller-owned transaction.
/// Every error requires rollback; no sub-operation commits, creates a separate
/// group or sends the initial message independently.
pub(crate) async fn execute_publication<T: PublicTransport>(
    tx: &mut Transaction<'_, Postgres>,
    mut prepared: PreparedPublication,
    signer: &DirectRequestReceiptSigner,
    policy: &RelationshipAuthority<T>,
) -> Result<Vec<u8>, PublicationError> {
    prepared.require_transaction(tx).await?;
    if let Err(error) = prepared.candidate.validate_policy(tx, policy).await {
        if let DirectRequestStoreError::Database(error) = error {
            return Err(error.into());
        }
        prepared.candidate.refresh_instant(tx).await?;
        return reject_prepared(tx, prepared.candidate, signer, "RequestPolicyDenied").await;
    }
    prepared.candidate.refresh_instant(tx).await?;
    if let Err(error) = prepared.candidate.validate_preparation(tx).await {
        let code = match error {
            DirectRequestStoreError::Expired => "PreparationExpired",
            DirectRequestStoreError::IncludedAuthorityChanged => "PreparationRevoked",
            DirectRequestStoreError::Database(error) => return Err(error.into()),
            _ => "PreparationConflict",
        };
        return reject_prepared(tx, prepared.candidate, signer, code).await;
    }
    let now = prepared.candidate.trusted_instant();
    // Round upward: the SQL deadline includes fractional acceptance seconds.
    // Revalidate after every lock/policy wait, before constructing persisted time.
    prepared.bootstrap = match direct_request::verify_bootstrap(
        prepared.candidate.signed(),
        &prepared.actor_key,
        &prepared.selected,
        prepared.prior.as_ref(),
        u64::try_from(now.timestamp() + i64::from(now.timestamp_subsec_nanos() != 0))
            .map_err(|_| PublicationError::Invariant)?,
    ) {
        Ok(bootstrap) => bootstrap,
        Err(error) => {
            let code = match error {
                direct_request::BootstrapError::ImportDeadline => "ImportHorizonTooShort",
                direct_request::BootstrapError::LegacyIneligible => "StaleLegacyPrior",
                _ => "InvalidBootstrap",
            };
            return reject_prepared(tx, prepared.candidate, signer, code).await;
        }
    };
    let b = prepared.candidate.signed().body().clone();
    let signed_bytes = prepared
        .candidate
        .signed()
        .accepted_wrapper_bytes()
        .to_vec();
    let transcript = prepared.candidate.signed().transcript_bytes().to_vec();
    let signature = prepared.candidate.signed().signature().to_vec();
    let request = id(&b["requestId"])?;
    let convo = id(&b["conversationId"])?;
    let actor = string(&b, "actorDid")?;
    let actor_device = id(&b["actorDeviceId"])?;
    let actor_key = string(&b, "keyId")?;
    let recipient = string(&b, "recipientDid")?;
    let auth = b["authGeneration"]
        .as_i64()
        .ok_or(PublicationError::Invariant)?;
    let now = prepared.candidate.trusted_instant();
    let seq = prepared.next_seq;
    let next = prepared.bootstrap.final_state().coordinate();
    let generation = next.generation() as i64;
    let final_state = prepared.bootstrap.final_state();
    let entry_id = Uuid::new_v4();
    let signed: Value =
        serde_json::from_slice(&signed_bytes).map_err(|_| PublicationError::Invariant)?;
    let entry = json!({"$type":"blue.catbird.chat.defs#directRequestEntry","entryId":entry_id.to_string(),"conversationId":convo.to_string(),"seq":seq,"signedRequest":signed,"receivedAt":time(now)});
    let entry_bytes = encode(&entry)?;
    let mut untagged_entry = entry.clone();
    untagged_entry
        .as_object_mut()
        .ok_or(PublicationError::Invariant)?
        .remove("$type");
    let fingerprint = crate::chat_protocol::direct_request_transcript::direct_request_entry_hash(
        &encode(&untagged_entry)?,
    )
    .map_err(|_| PublicationError::Invariant)?;
    let server_fields = encode(
        &json!({"entryId":entry_id.to_string(),"conversationId":convo.to_string(),"seq":seq,"receivedAt":time(now)}),
    )?;
    let a = &b["artifacts"];
    let metadata = &a["metadataSnapshot"];
    let metadata_bytes = encode(metadata)?;
    let metadata_ciphertext = binary(&metadata["ciphertext"])?;
    let final_info = binary(&a["finalGroupInfo"]["bytes"])?;
    let welcome = binary(&a["welcome"]["opaqueWelcome"])?;
    let initial = binary(&a["initialCiphertext"])?;
    let genesis_info = binary(&a["genesisGroupInfo"]["bytes"])?;
    let unsigned_body = encode(&b)?;
    let tree = crate::chat_protocol::public_state::encode_public_tree_summary(
        final_state.binding().tree_summary(),
    )
    .map_err(|_| PublicationError::Invariant)?;
    let event = encode(
        &json!({"$type":"blue.catbird.chat.defs#conversationChangedEvent","conversationId":convo.to_string()}),
    )?;
    let import_until = DateTime::from_timestamp(prepared.bootstrap.import_until() as i64, 0)
        .ok_or(PublicationError::Invariant)?;
    // Seal the receipt while package reservations are still present. Every
    // subsequent write is in this same transaction, so a failed effect also
    // rolls this receipt back.
    let receipt=signer.seal_outcome(json!({"$type":"blue.catbird.chat.defs#directRequestReceiptBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-OUTCOME\u{0}","protocolVersion":"2","authorityDid":"did:web:chat.catbird.blue","keyId":signer.key_id(),"receipt":{"$type":"blue.catbird.chat.defs#directRequestPublishedReceipt","requestId":b["requestId"],"requestDigest":STANDARD.encode(prepared.bootstrap.publication_digest()),"preparationRequestDigest":b["preparationRequestDigest"],"actorDid":actor,"actorDeviceId":actor_device.to_string(),"actorKeyId":actor_key,"authGeneration":auth,"requestKind":"publish","recordedAt":time(now),"conversationId":convo.to_string(),"firstMessageId":b["firstMessageId"],"coordinates":b["next"]}})).map_err(|_|PublicationError::Invariant)?;
    let existing_charge = prepared.candidate.existing_artifact_bytes(tx).await?;
    let mut remaining_blobs = 0u64;
    let mut add_blob = |length: usize| -> Result<(), PublicationError> {
        remaining_blobs = remaining_blobs
            .checked_add(u64::try_from(length).map_err(|_| PublicationError::Invariant)?)
            .ok_or(PublicationError::Invariant)?;
        Ok(())
    };
    for blob in [
        server_fields.as_slice(),
        genesis_info.as_slice(),
        final_state.snapshot(),
        tree.bytes(),
        metadata_ciphertext.as_slice(),
        final_info.as_slice(),
        welcome.as_slice(),
        initial.as_slice(),
        metadata_bytes.as_slice(),
        event.as_slice(),
    ] {
        add_blob(blob.len())?;
    }
    let deliveries = a["welcome"]["deliveries"]
        .as_array()
        .ok_or(PublicationError::Invariant)?;
    for delivery in deliveries {
        add_blob(encode(&delivery["provenance"])?.len())?;
    }
    for leaf in final_state.binding().tree_summary().leaves() {
        add_blob(leaf.basic_credential().len())?;
        add_blob(leaf.signature_key().len())?;
    }
    let predecessor_intervals = if let Some(prior) = prepared.prior {
        let (snapshot_bytes, tree_bytes, intervals): (i64, i64, i64) = sqlx::query_as(
            "SELECT octet_length(s.public_snapshot_bytes)::bigint, octet_length(s.tree_summary_bytes)::bigint, (SELECT count(*) FROM chat.application_intervals i WHERE i.conversation_id=s.conversation_id AND i.generation=s.generation AND i.terminal_seq IS NULL) FROM chat.generation_states s WHERE s.conversation_id=$1 AND s.generation=$2 AND s.state_version=$3",
        ).bind(convo).bind(prior.generation() as i64).bind(prior.state_version() as i64)
            .fetch_one(&mut **tx).await?;
        add_blob(usize::try_from(snapshot_bytes).map_err(|_| PublicationError::Invariant)?)?;
        add_blob(usize::try_from(tree_bytes).map_err(|_| PublicationError::Invariant)?)?;
        u64::try_from(intervals).map_err(|_| PublicationError::Invariant)?
    } else {
        0
    };
    // A legacy successor may have devices in older, already-closed schedules.
    // A later close notifies that entire history, so only counting the current
    // predecessor's open intervals would under-reserve retained audience rows.
    let mut final_dids = Vec::new();
    let mut final_devices = Vec::new();
    for leaf in final_state.binding().tree_summary().leaves() {
        let identity = std::str::from_utf8(leaf.basic_credential())
            .map_err(|_| PublicationError::Invariant)?;
        let (did, device) = identity
            .rsplit_once('#')
            .ok_or(PublicationError::Invariant)?;
        final_dids.push(did.to_owned());
        final_devices.push(Uuid::parse_str(device).map_err(|_| PublicationError::Invariant)?);
    }
    let historical_audience: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (SELECT recipient_did,recipient_device_id FROM chat.application_intervals WHERE conversation_id=$1 UNION SELECT * FROM unnest($2::text[],$3::uuid[])) audience",
    ).bind(convo).bind(&final_dids).bind(&final_devices).fetch_one(&mut **tx).await?;
    let historical_audience =
        u64::try_from(historical_audience).map_err(|_| PublicationError::Invariant)?;
    let snapshot_tree_bytes = (final_state.snapshot().len() as u64)
        .checked_add(tree.bytes().len() as u64)
        .ok_or(PublicationError::Invariant)?;
    let decision_reserve = direct_request_retention::decision_reservation_bytes(
        snapshot_tree_bytes,
        historical_audience,
    )
    .ok_or(PublicationError::Invariant)?;
    let lifecycle_reserve = direct_request_retention::lifecycle_reservation_bytes(
        snapshot_tree_bytes,
        historical_audience,
        deliveries.len() as u64,
    )
    .ok_or(PublicationError::Invariant)?;
    let retained_artifact_bytes = retained_charge::charge(
        existing_charge,
        receipt.bytes().len(),
        &retained_charge::PublicationArtifactLengths {
            signed_wrapper: signed_bytes.len(),
            accepted_entry: entry_bytes.len(),
            unsigned_body: unsigned_body.len(),
            transcript: transcript.len(),
            signature: signature.len(),
            remaining_blobs,
            final_leaves: final_state.binding().tree_summary().leaves().len() as u64,
            deliveries: deliveries.len() as u64,
            predecessor_intervals,
            legacy_successor: prepared.prior.is_some(),
        },
    )
    .and_then(|bytes| bytes.checked_add(lifecycle_reserve))
    .ok_or(PublicationError::Invariant)?;
    let response = match preparation::complete_published_publication(
        tx,
        prepared.candidate,
        &receipt,
        signer,
        retained_artifact_bytes,
    )
    .await?
    {
        preparation::PublicationCompletion::Published(bytes) => bytes,
        preparation::PublicationCompletion::Rejected(bytes) => return Ok(bytes),
    };
    let digest = prepared.bootstrap.publication_digest().as_slice();
    if let Some(prior) = prepared.prior {
        let retirement = prior
            .state_version()
            .checked_add(1)
            .ok_or(PublicationError::Invariant)? as i64;
        // Historical snapshot bytes are copied unchanged. The new row records
        // retirement coordinates; the immutable predecessor remains intact.
        sqlx::query("INSERT INTO chat.generation_states(conversation_id,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,lifecycle,state_kind,producing_transition_id,public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,leaf_count,created_at) SELECT conversation_id,generation,$4,group_id,epoch,group_context_hash,confirmation_tag,'superseded','directRequestRetirement',$5,public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,leaf_count,$6 FROM chat.generation_states WHERE conversation_id=$1 AND generation=$2 AND state_version=$3")
            .bind(convo).bind(prior.generation() as i64).bind(prior.state_version() as i64).bind(retirement).bind(request).bind(now).execute(&mut **tx).await?;
        sqlx::query("UPDATE chat.generations SET lifecycle='superseded',current_state_version=$3,superseded_seq=$4,superseded_at=$5 WHERE conversation_id=$1 AND generation=$2 AND lifecycle='active'")
            .bind(convo).bind(prior.generation() as i64).bind(retirement).bind(seq).bind(now).execute(&mut **tx).await?;
        sqlx::query("UPDATE chat.member_devices SET active=false,removed_state_version=$3,removed_transition_id=$4,removed_seq=$5,removed_at=$6 WHERE conversation_id=$1 AND generation=$2 AND active")
            .bind(convo).bind(prior.generation() as i64).bind(retirement).bind(request).bind(seq).bind(now).execute(&mut **tx).await?;
        sqlx::query("UPDATE chat.application_intervals SET terminal_seq=$3,closing_state_version=$4,closing_transition_id=$5,closing_outer_entry_fingerprint=$6,closing_kind='directRequest',closing_leaf_period_id=opening_leaf_period_id,removed_at=$7 WHERE conversation_id=$1 AND generation=$2 AND terminal_seq IS NULL")
            .bind(convo).bind(prior.generation() as i64).bind(seq).bind(retirement).bind(request).bind(fingerprint.as_slice()).bind(now).execute(&mut **tx).await?;
        // Exact successor wins only if acceptance, close and recovery have not
        // advanced the coordinate we validated under the conversation lock.
        let changed=sqlx::query("UPDATE chat.conversations SET current_generation=$4,current_state_version=1,next_entry_seq=$5,protocol_version='2' WHERE conversation_id=$1 AND current_generation=$2 AND current_state_version=$3 AND lifecycle='active' AND protocol_version='1'")
            .bind(convo).bind(prior.generation() as i64).bind(prior.state_version() as i64).bind(generation).bind(seq+1).execute(&mut **tx).await?;
        if changed.rows_affected() != 1 {
            return Err(PublicationError::Invariant);
        }
    } else {
        let (low, high) = if actor < recipient {
            (actor, recipient)
        } else {
            (recipient, actor)
        };
        sqlx::query("INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,direct_did_low,direct_did_high,created_at,protocol_version) VALUES($1,'direct','active',0,1,2,$2,$3,$4,'2')")
            .bind(convo).bind(low).bind(high).bind(now).execute(&mut **tx).await?;
    }
    sqlx::query("INSERT INTO chat.generations(conversation_id,generation,group_id,lifecycle,genesis_group_info_bytes,genesis_group_info_sha256,current_state_version,activated_seq,activated_at) VALUES($1,$2,$3,'active',$4,$5,1,$6,$7)")
        .bind(convo).bind(generation).bind(next.group_id().as_slice()).bind(&genesis_info).bind(binary(&a["genesisGroupInfo"]["sha256"])?).bind(seq).bind(now).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO chat.generation_states(conversation_id,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,lifecycle,state_kind,producing_transition_id,public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,leaf_count,created_at) VALUES($1,$2,1,$3,1,$4,$5,'active','directRequestPublication',$6,$7,$8,$9,$10,$11,$12)")
        .bind(convo).bind(generation).bind(next.group_id().as_slice()).bind(next.group_context_hash().as_slice()).bind(next.confirmation_tag().as_slice()).bind(request).bind(final_state.snapshot()).bind(final_state.snapshot_sha256().as_slice()).bind(tree.bytes()).bind(tree.sha256().as_slice()).bind(final_state.binding().tree_summary().leaves().len() as i64).bind(now).execute(&mut **tx).await?;
    let metadata_id = Uuid::new_v4();
    sqlx::query("INSERT INTO chat.transitions(transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,prior_generation,prior_state_version,next_generation,next_state_version,retired_generation,retired_state_version,successor_generation,successor_state_version,metadata_snapshot_id,entry_seq,accepted_at) VALUES($1,$2,'directRequestPublication',$3,$4,$5,$6,'admin','active',$7,$8,$9,$10,$11,$12,$13,$14,1,$15,$16,$17,$18,$19,$20,$21)")
        .bind(request).bind(convo).bind(actor).bind(actor_device).bind(actor_key).bind(auth).bind(&signed_bytes).bind(&unsigned_body).bind(&transcript).bind(digest).bind(&signature).bind(prepared.prior.map(|p|p.generation() as i64)).bind(prepared.prior.map(|p|p.state_version() as i64)).bind(generation).bind(prepared.prior.map(|p|p.generation() as i64)).bind(prepared.prior.map(|p|p.state_version() as i64+1)).bind(prepared.prior.map(|_|generation)).bind(prepared.prior.map(|_|1i64)).bind(metadata_id).bind(seq).bind(now).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO chat.entries(conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,accepted_payload_sha256,signed_request_bytes,request_digest,signature,server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,actor_key_id,actor_auth_generation,generation,state_version,transition_id,received_at) VALUES($1,$2,$3,'blue.catbird.chat.defs#directRequestEntry',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,1,$16,$17)")
        .bind(convo).bind(seq).bind(entry_id).bind(&entry_bytes).bind(Sha256::digest(&entry_bytes).as_slice()).bind(&signed_bytes).bind(digest).bind(&signature).bind(&server_fields).bind(fingerprint.as_slice()).bind(actor).bind(actor_device).bind(actor_key).bind(auth).bind(generation).bind(request).bind(now).execute(&mut **tx).await?;
    // A successor entry also closes every predecessor device's schedule.
    // Keep intervalClose if a device is included again in the successor.
    sqlx::query("INSERT INTO chat.entry_recipients(conversation_id,seq,user_did,device_id,entitlement_kind) SELECT conversation_id,$2,recipient_did,recipient_device_id,'intervalClose' FROM chat.application_intervals WHERE conversation_id=$1 AND closing_transition_id=$3")
        .bind(convo).bind(seq).bind(request).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO chat.metadata_snapshots(metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,producing_transition_id,origin_transition_id,metadata_version,nonce,ciphertext,ciphertext_sha256,ciphertext_size,author_did,author_device_id,author_key_id,author_public_key,author_auth_generation,author_origin_seq,author_role,author_device_status,created_at) VALUES($1,$2,$3,1,$4,1,$5,$6,$7,$7,1,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'admin','active',$18)")
        .bind(metadata_id).bind(convo).bind(generation).bind(next.group_id().as_slice()).bind(next.group_context_hash().as_slice()).bind(next.confirmation_tag().as_slice()).bind(request).bind(binary(&metadata["nonce"])?).bind(&metadata_ciphertext).bind(Sha256::digest(&metadata_ciphertext).as_slice()).bind(metadata_ciphertext.len() as i64).bind(actor).bind(actor_device).bind(actor_key).bind(&prepared.actor_key).bind(auth).bind(seq).bind(now).execute(&mut **tx).await?;
    if prepared.prior.is_none() {
        for (did, status) in [(actor, "active"), (recipient, "pending")] {
            let pending = status == "pending";
            sqlx::query("INSERT INTO chat.participants(participant_period_id,conversation_id,user_did,status,role,role_transition_id,role_changed_at,created_by_did,created_by_device_id,invitation_transition_id,invitation_entry_id,invited_at,current_membership,created_at) VALUES($1,$2,$3,$4,'admin',$5,$6,$7,$8,$9,$10,$11,true,$6)")
                .bind(Uuid::new_v4()).bind(convo).bind(did).bind(status).bind(request).bind(now).bind(actor).bind(actor_device).bind(pending.then_some(request)).bind(pending.then_some(entry_id)).bind(pending.then_some(now)).execute(&mut **tx).await?;
        }
    }
    sqlx::query("INSERT INTO chat.direct_request_publications(request_id,conversation_id,generation,state_version,first_message_id,actor_did,actor_device_id,actor_key_id,recipient_did,context_hash,preparation_digest,publication_digest,signed_publication,request_entry,request_entry_sha256,final_group_info,final_group_info_sha256,full_welcome,full_welcome_sha256,initial_ciphertext,initial_ciphertext_sha256,metadata_snapshot,metadata_snapshot_sha256,import_until,created_at,actor_auth_generation) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)")
        .bind(request).bind(convo).bind(generation).bind(id(&b["firstMessageId"])?).bind(actor).bind(actor_device).bind(actor_key).bind(recipient).bind(binary(&b["contextHash"])?).bind(binary(&b["preparationDigest"])?).bind(digest).bind(&signed_bytes).bind(&entry_bytes).bind(Sha256::digest(&entry_bytes).as_slice()).bind(&final_info).bind(Sha256::digest(&final_info).as_slice()).bind(&welcome).bind(Sha256::digest(&welcome).as_slice()).bind(&initial).bind(Sha256::digest(&initial).as_slice()).bind(&metadata_bytes).bind(Sha256::digest(&metadata_bytes).as_slice()).bind(import_until).bind(now).bind(auth).execute(&mut **tx).await?;
    direct_request_retention::install_lifecycle_reserve(
        tx,
        request,
        decision_reserve,
        deliveries.len() as u64,
    )
    .await
    .map_err(|error| match error {
        direct_request_retention::RetentionError::Database(error) => {
            PublicationError::Database(error)
        }
        _ => PublicationError::Invariant,
    })?;
    for leaf in final_state.binding().tree_summary().leaves() {
        let identity = std::str::from_utf8(leaf.basic_credential())
            .map_err(|_| PublicationError::Invariant)?;
        let (did, device) = identity
            .rsplit_once('#')
            .ok_or(PublicationError::Invariant)?;
        let device = Uuid::parse_str(device).map_err(|_| PublicationError::Invariant)?;
        let participant:Uuid=sqlx::query_scalar("SELECT participant_period_id FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership").bind(convo).bind(did).fetch_one(&mut **tx).await?;
        let key_id = crate::chat_protocol::validation::ed25519_key_id(leaf.signature_key())
            .map_err(|_| PublicationError::Invariant)?;
        let generation_auth: i64 = sqlx::query_scalar(
            "SELECT auth_generation FROM chat.devices WHERE user_did=$1 AND device_id=$2",
        )
        .bind(did)
        .bind(device)
        .fetch_one(&mut **tx)
        .await?;
        let selected = prepared
            .selected
            .iter()
            .find(|s| s.did == did && s.device_id == device);
        sqlx::query("INSERT INTO chat.entry_recipients(conversation_id,seq,user_did,device_id,entitlement_kind) VALUES($1,$2,$3,$4,'control') ON CONFLICT DO NOTHING")
            .bind(convo).bind(seq).bind(did).bind(device).execute(&mut **tx).await?;
        let leaf_id = Uuid::new_v4();
        sqlx::query("INSERT INTO chat.member_devices(leaf_period_id,participant_period_id,conversation_id,generation,user_did,device_id,leaf_index,basic_credential,leaf_signature_key,leaf_key_id,leaf_auth_generation,origin,join_key_package_ref,joined_state_version,joined_transition_id,joined_seq,active,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,1,$14,$15,true,$16)")
            .bind(leaf_id).bind(participant).bind(convo).bind(generation).bind(did).bind(device).bind(leaf.leaf_index() as i64).bind(leaf.basic_credential()).bind(leaf.signature_key()).bind(key_id.as_str()).bind(generation_auth).bind(if selected.is_some(){"keyPackage"}else{"genesis"}).bind(selected.map(|s|s.package_ref.to_vec())).bind(request).bind(seq).bind(now).execute(&mut **tx).await?;
        sqlx::query("INSERT INTO chat.application_intervals(membership_interval_id,conversation_id,generation,recipient_did,recipient_device_id,start_seq,opening_kind,opening_transition_id,opening_outer_entry_fingerprint,opening_state_version,opening_group_id,opening_epoch,opening_group_context_hash,opening_confirmation_tag,opening_leaf_period_id,created_at) VALUES($1,$2,$3,$4,$5,$6,'directRequest',$7,$8,1,$9,1,$10,$11,$12,$13)")
            .bind(Uuid::new_v4()).bind(convo).bind(generation).bind(did).bind(device).bind(seq).bind(request).bind(fingerprint.as_slice()).bind(next.group_id().as_slice()).bind(next.group_context_hash().as_slice()).bind(next.confirmation_tag().as_slice()).bind(leaf_id).bind(now).execute(&mut **tx).await?;
        if let Some(selected) = selected {
            let delivery = a["welcome"]["deliveries"]
                .as_array()
                .ok_or(PublicationError::Invariant)?
                .iter()
                .find(|d| d["recipientDid"] == did && d["recipientDeviceId"] == device.to_string())
                .ok_or(PublicationError::Invariant)?;
            let provenance = encode(&delivery["provenance"])?;
            sqlx::query("INSERT INTO chat.direct_request_device_deliveries(request_id,owner_did,owner_device_id,owner_key_id,auth_generation,key_package_ref,grant_id,grant_revision,grant_digest,leaf_index,import_until,provenance,provenance_sha256) SELECT $1,$2,$3,$4,$5,$6,$7,$8,g.grant_digest,$9,$10,$11,$12 FROM chat.direct_request_grants g WHERE g.grant_id=$7")
                .bind(request).bind(did).bind(device).bind(key_id.as_str()).bind(generation_auth).bind(selected.package_ref.as_slice()).bind(selected.grant_id).bind(selected.grant_revision as i64).bind(leaf.leaf_index() as i64).bind(import_until).bind(&provenance).bind(Sha256::digest(&provenance).as_slice()).execute(&mut **tx).await?;
            let consumed=sqlx::query("UPDATE chat.key_packages SET status='consumed',terminal_transition_id=$2,terminal_at=$3 WHERE key_package_ref=$1 AND status='reserved' AND usage_scope='direct-request'").bind(selected.package_ref.as_slice()).bind(request).bind(now).execute(&mut **tx).await?;
            if consumed.rows_affected() != 1 {
                return Err(PublicationError::Invariant);
            }
        }
    }
    let event_id = Uuid::new_v4();
    let position:i64=sqlx::query_scalar("INSERT INTO chat.events(event_id,event_kind,payload_bytes,payload_sha256,created_at,protocol_instance_id) SELECT $1,'conversationChanged',$2,$3,$4,protocol_instance_id FROM chat.protocol_instances RETURNING event_position")
        .bind(event_id).bind(&event).bind(Sha256::digest(&event).as_slice()).bind(now).fetch_one(&mut **tx).await?;
    sqlx::query("INSERT INTO chat.event_recipients(event_position,user_did,device_id,entitlement_kind,audience_predecessor_position) SELECT $1,r.user_did,r.device_id,CASE WHEN EXISTS(SELECT 1 FROM chat.member_devices m WHERE m.conversation_id=r.conversation_id AND m.user_did=r.user_did AND m.device_id=r.device_id AND m.joined_transition_id=$4) THEN 'leaf' ELSE 'historicalSchedule' END,(SELECT max(previous.event_position) FROM chat.event_recipients previous WHERE previous.user_did=r.user_did AND previous.device_id=r.device_id) FROM chat.entry_recipients r WHERE r.conversation_id=$2 AND r.seq=$3 ORDER BY r.user_did,r.device_id")
        .bind(position).bind(convo).bind(seq).bind(request).execute(&mut **tx).await?;
    let stream_outbox = Uuid::new_v4();
    let notification_outbox = Uuid::new_v4();
    for (outbox, kind) in [
        (stream_outbox, "stream"),
        (notification_outbox, "notification"),
    ] {
        sqlx::query("INSERT INTO chat.outbox(outbox_id,event_position,work_kind,status,next_attempt_at,created_at) VALUES($1,$2,$3,'pending',$4,$4)").bind(outbox).bind(position).bind(kind).bind(now).execute(&mut **tx).await?;
    }
    let recipient_devices: Vec<Uuid> = sqlx::query_scalar(
        "SELECT owner_device_id FROM chat.direct_request_device_deliveries \
          WHERE request_id=$1 AND owner_did=$2 ORDER BY owner_device_id::text",
    )
    .bind(request)
    .bind(recipient)
    .fetch_all(&mut **tx)
    .await?;
    let first_message_id = id(&b["firstMessageId"])?;
    let payload_digest = request_push_event_payload_digest(
        event_id,
        request,
        convo,
        first_message_id,
        actor,
        recipient,
        &recipient_devices,
    )
    .map_err(|_| PublicationError::Invariant)?;
    sqlx::query("INSERT INTO chat.direct_request_push_events(event_id,request_id,event_position,outbox_id,conversation_id,first_message_id,sender_did,recipient_did,payload_digest,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(event_id).bind(request).bind(position).bind(notification_outbox).bind(convo)
        .bind(first_message_id).bind(actor).bind(recipient).bind(payload_digest.as_slice())
        .bind(now).execute(&mut **tx).await?;
    let mapped = sqlx::query("INSERT INTO chat.direct_request_push_event_recipients(event_id,request_id,recipient_did,recipient_device_id) SELECT $1,$2,$3,owner_device_id FROM chat.direct_request_device_deliveries WHERE request_id=$2 AND owner_did=$3 ORDER BY owner_device_id::text")
        .bind(event_id).bind(request).bind(recipient).execute(&mut **tx).await?;
    if mapped.rows_affected() != recipient_devices.len() as u64 {
        return Err(PublicationError::Invariant);
    }
    Ok(response)
}
