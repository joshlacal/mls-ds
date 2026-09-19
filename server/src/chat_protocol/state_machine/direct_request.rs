//! Closed, side-effect-free validation for encrypted direct-request bootstrap.
//! Construction proves public artifacts only. Repository authority and consent
//! remain separate and must be checked in the publication transaction.
use crate::chat_protocol::{
    direct_request_transcript::{self as transcript, DirectRequestKind, VerifiedDirectRequest},
    public_state::{
        self, ActivePublicState, GenesisGroupInfoExpectations, ResetSuccessorGroupInfoExpectations,
    },
    snapshot::{PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle},
    wire::{self, GroupInfoValidationPolicy},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub(crate) enum BootstrapError {
    #[error("invalid signed request artifact binding")]
    Binding,
    #[error("invalid public MLS bootstrap: {0}")]
    Public(String),
    #[error("request import deadline is not supported by the final tree and grants")]
    ImportDeadline,
    #[error("legacy pending direct is no longer eligible")]
    LegacyIneligible,
}

pub(crate) struct GrantedRequestDevice {
    pub(crate) did: String,
    pub(crate) device_id: Uuid,
    pub(crate) signature_key: Vec<u8>,
    pub(crate) package_ref: [u8; 32],
    pub(crate) grant_id: Uuid,
    pub(crate) grant_revision: u64,
    pub(crate) grant_expires_at: u64,
}

pub(crate) struct VerifiedBootstrap {
    final_state: ActivePublicState,
    publication_digest: [u8; 32],
    import_until: u64,
    total_bytes: usize,
}
impl VerifiedBootstrap {
    pub(crate) fn final_state(&self) -> &ActivePublicState {
        &self.final_state
    }
    pub(crate) fn publication_digest(&self) -> &[u8; 32] {
        &self.publication_digest
    }
    pub(crate) fn import_until(&self) -> u64 {
        self.import_until
    }
    pub(crate) fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}
fn bytes(value: &Value) -> Result<Vec<u8>, BootstrapError> {
    STANDARD
        .decode(value.as_str().ok_or(BootstrapError::Binding)?)
        .map_err(|_| BootstrapError::Binding)
}
fn hash(value: &Value) -> Result<[u8; 32], BootstrapError> {
    bytes(value)?
        .try_into()
        .map_err(|_| BootstrapError::Binding)
}
fn artifact(value: &Value, field: &str) -> Result<Vec<u8>, BootstrapError> {
    let raw = bytes(&value[field])?;
    if hash(&value["sha256"])? != <[u8; 32]>::from(Sha256::digest(&raw)) {
        return Err(BootstrapError::Binding);
    }
    Ok(raw)
}
fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, BootstrapError> {
    value[field].as_str().ok_or(BootstrapError::Binding)
}
fn timestamp(value: &Value) -> Result<u64, BootstrapError> {
    let instant =
        chrono::DateTime::parse_from_rfc3339(value.as_str().ok_or(BootstrapError::Binding)?)
            .map_err(|_| BootstrapError::Binding)?;
    u64::try_from(instant.timestamp()).map_err(|_| BootstrapError::Binding)
}
fn coordinate(value: &Value) -> Result<PublicGroupSnapshotCoordinate, BootstrapError> {
    if text(value, "lifecycle")? != "active" {
        return Err(BootstrapError::Binding);
    }
    Ok(PublicGroupSnapshotCoordinate::new(
        *Uuid::parse_str(text(value, "conversationId")?)
            .map_err(|_| BootstrapError::Binding)?
            .as_bytes(),
        value["generation"]
            .as_u64()
            .ok_or(BootstrapError::Binding)?,
        value["stateVersion"]
            .as_u64()
            .ok_or(BootstrapError::Binding)?,
        hash(&value["groupId"])?,
        value["epoch"].as_u64().ok_or(BootstrapError::Binding)?,
        hash(&value["groupContextHash"])?,
        hash(&value["confirmationTag"])?,
        PublicGroupSnapshotLifecycle::Active,
    ))
}

/// The caller supplies the exact included device snapshot from locked storage.
/// An absent recipient, a subset Welcome, a substituted package or a changed
/// context fails before any mutation. Secret MACs are verified by recipients.
pub(crate) fn verify_bootstrap(
    signed: &VerifiedDirectRequest,
    actor_key: &[u8],
    selected: &[GrantedRequestDevice],
    legacy_prior: Option<&PublicGroupSnapshotCoordinate>,
    now: u64,
) -> Result<VerifiedBootstrap, BootstrapError> {
    let public = |e: wire::WireValidationError| BootstrapError::Public(e.to_string());
    let state_error = |e: public_state::PublicStateError| BootstrapError::Public(e.to_string());
    if signed.kind() != DirectRequestKind::Publish || selected.is_empty() || selected.len() > 39 {
        return Err(BootstrapError::Binding);
    }
    let b = signed.body();
    let a = &b["artifacts"];
    let actor = text(b, "actorDid")?;
    let actor_device = text(b, "actorDeviceId")?;
    let recipient = text(b, "recipientDid")?;
    if actor == recipient || !selected.iter().any(|s| s.did == recipient) {
        return Err(BootstrapError::Binding);
    }
    let actor_credential = format!("{actor}#{actor_device}");
    let mut identities = std::collections::BTreeSet::new();
    let mut refs = std::collections::BTreeSet::new();
    for s in selected {
        if (s.did != actor && s.did != recipient)
            || (s.did == actor && s.device_id.to_string() == actor_device)
            || !identities.insert((&s.did, s.device_id))
            || !refs.insert(s.package_ref)
        {
            return Err(BootstrapError::Binding);
        }
    }
    let context = json!({"protocolVersion":"2","requestId":b["requestId"],"firstMessageId":b["firstMessageId"],"conversationId":b["conversationId"],"origin":b["origin"],"actorDid":actor,"actorDeviceId":actor_device,"actorKeyId":b["keyId"],"recipientDid":recipient,"preparationDigest":b["preparationDigest"]});
    let context_hash = transcript::direct_request_context_hash(
        &serde_json::to_vec(&context).map_err(|_| BootstrapError::Binding)?,
    )
    .map_err(|_| BootstrapError::Binding)?;
    if context_hash != hash(&b["contextHash"])? {
        return Err(BootstrapError::Binding);
    }
    let genesis = artifact(&a["genesisGroupInfo"], "bytes")?;
    let add = artifact(&a["addCommit"], "bytes")?;
    let final_info = artifact(&a["finalGroupInfo"], "bytes")?;
    let welcome = artifact(&a["welcome"], "opaqueWelcome")?;
    let metadata = bytes(&a["metadataSnapshot"]["ciphertext"])?;
    let application = bytes(&a["initialCiphertext"])?;
    let total_bytes = transcript::validate_bootstrap_artifact_lengths(&[
        genesis.len(),
        add.len(),
        final_info.len(),
        welcome.len(),
        metadata.len(),
        application.len(),
    ])
    .map_err(|_| BootstrapError::Binding)?;
    let next = coordinate(&b["next"])?;
    if next.conversation_id()
        != Uuid::parse_str(text(b, "conversationId")?)
            .map_err(|_| BootstrapError::Binding)?
            .as_bytes()
        || next.state_version() != 1
        || next.epoch() != 1
    {
        return Err(BootstrapError::Binding);
    }
    let policy = GroupInfoValidationPolicy {
        expected_basic_credential: actor_credential.as_bytes(),
        expected_signature_key: actor_key,
        now_unix_seconds: now,
        max_bytes: 1_048_576,
        max_ratchet_tree_bytes: 1_048_576,
        max_members: 40,
    };
    let verified_genesis = wire::validate_group_info(&genesis, policy).map_err(public)?;
    let initial_coordinate = PublicGroupSnapshotCoordinate::new(
        *next.conversation_id(),
        next.generation(),
        0,
        *next.group_id(),
        0,
        *verified_genesis.group_context_hash(),
        *verified_genesis.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    let initial = match (text(&b["origin"], "$type")?, legacy_prior) {
        ("blue.catbird.chat.defs#freshDirectOrigin", None) => {
            public_state::verify_genesis_group_info(
                &genesis,
                GenesisGroupInfoExpectations {
                    coordinate: initial_coordinate,
                    expected_basic_credential: actor_credential.as_bytes(),
                    expected_signature_key: actor_key,
                    now_unix_seconds: now,
                    max_wire_bytes: 1_048_576,
                    max_ratchet_tree_bytes: 1_048_576,
                    max_members: 40,
                },
            )
            .map_err(state_error)?
        }
        ("blue.catbird.chat.defs#legacyPendingDirectOrigin", Some(prior)) => {
            if coordinate(&b["origin"]["exactPrior"])? != *prior {
                return Err(BootstrapError::LegacyIneligible);
            }
            public_state::verify_reset_successor_group_info(
                &genesis,
                prior,
                ResetSuccessorGroupInfoExpectations {
                    coordinate: initial_coordinate,
                    expected_basic_credential: actor_credential.as_bytes(),
                    expected_signature_key: actor_key,
                    now_unix_seconds: now,
                    max_wire_bytes: 1_048_576,
                    max_ratchet_tree_bytes: 1_048_576,
                    max_members: 40,
                },
            )
            .map_err(state_error)?
        }
        _ => return Err(BootstrapError::LegacyIneligible),
    };
    let aad = transcript::direct_request_commit_aad(&context_hash)
        .map_err(|_| BootstrapError::Binding)?;
    let commit =
        public_state::process_commit(&initial, &add, &aad, next, now, 40).map_err(state_error)?;
    if !commit.removes().is_empty() || commit.adds().len() != selected.len() {
        return Err(BootstrapError::Binding);
    }
    for added in commit.adds() {
        let s = selected
            .iter()
            .find(|s| &s.package_ref == added.key_package_ref())
            .ok_or(BootstrapError::Binding)?;
        if added.basic_credential() != format!("{}#{}", s.did, s.device_id).as_bytes()
            || added.signature_key() != s.signature_key
        {
            return Err(BootstrapError::Binding);
        }
    }
    let final_verified =
        wire::direct_request::verify_final_group_info(&final_info, policy, commit.next().binding())
            .map_err(public)?;
    let until = timestamp(&b["importUntil"])?;
    let deadline = selected
        .iter()
        .map(|s| s.grant_expires_at)
        .fold(final_verified.earliest_key_package_expiry(), u64::min);
    if until > deadline
        || until
            < now
                .checked_add(604800 + 300)
                .ok_or(BootstrapError::ImportDeadline)?
    {
        return Err(BootstrapError::ImportDeadline);
    }
    let actual_welcome = wire::validate_welcome(&welcome, 1_048_576).map_err(public)?;
    if actual_welcome.key_package_refs().len() != refs.len()
        || actual_welcome
            .key_package_refs()
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            != refs
    {
        return Err(BootstrapError::Binding);
    }
    let deliveries = a["welcome"]["deliveries"]
        .as_array()
        .ok_or(BootstrapError::Binding)?;
    if deliveries.len() != selected.len() {
        return Err(BootstrapError::Binding);
    }
    let mut delivered = std::collections::BTreeSet::new();
    for delivery in deliveries {
        let p = &delivery["provenance"];
        let package = hash(&p["keyPackageRef"])?;
        let s = selected
            .iter()
            .find(|s| s.package_ref == package)
            .ok_or(BootstrapError::Binding)?;
        if !delivered.insert(package)
            || delivery["recipientDid"] != s.did
            || delivery["recipientDeviceId"] != s.device_id.to_string()
            || p["requestId"] != b["requestId"]
            || p["preparationDigest"] != b["preparationDigest"]
            || hash(&p["contextHash"])? != context_hash
            || p["grantId"] != s.grant_id.to_string()
            || p["grantRevision"] != s.grant_revision
            || timestamp(&p["importUntil"])? != until
        {
            return Err(BootstrapError::Binding);
        }
    }
    let app = wire::validate_private_application(&application, 98304).map_err(public)?;
    let app_aad = transcript::direct_request_application_aad(
        &context_hash,
        &serde_json::to_vec(&b["next"]).map_err(|_| BootstrapError::Binding)?,
        text(b, "firstMessageId")?,
    )
    .map_err(|_| BootstrapError::Binding)?;
    if app.group_id() != next.group_id() || app.epoch() != next.epoch() || app.aad() != app_aad {
        return Err(BootstrapError::Binding);
    }
    // Metadata remains opaque but its wrapper must bind the same final state.
    let m = &a["metadataSnapshot"];
    if bytes(&m["coordinate"]["conversationId"])? != next.conversation_id().as_slice() {
        return Err(BootstrapError::Binding);
    }
    for field in [
        "generation",
        "groupId",
        "epoch",
        "groupContextHash",
        "confirmationTag",
    ] {
        if m["coordinate"][field] != b["next"][field] {
            return Err(BootstrapError::Binding);
        }
    }
    let proof = &m["authorProof"];
    if m["originTransitionId"] != b["requestId"]
        || m["metadataVersion"] != 1
        || !m["avatarBinding"].is_null()
        || bytes(&m["nonce"])?.len() != 12
        || metadata.len() < 16
        || metadata.len() > 16384
        || m["ciphertextSize"].as_u64() != Some(metadata.len() as u64)
        || hash(&m["ciphertextSha256"])? != <[u8; 32]>::from(Sha256::digest(&metadata))
        || proof["authorDid"] != actor
        || proof["authorDeviceId"] != actor_device
        || proof["authorKeyId"] != b["keyId"]
        || proof["authGenerationAtOrigin"] != b["authGeneration"]
        || proof["originTransitionId"] != b["requestId"]
        || proof["roleAtOrigin"] != "admin"
        || proof["deviceStatusAtOrigin"] != "active"
        || bytes(&proof["signaturePublicKey"])? != actor_key
    {
        return Err(BootstrapError::Binding);
    }
    Ok(VerifiedBootstrap {
        final_state: commit.into_next(),
        publication_digest: *signed.request_digest(),
        import_until: until,
        total_bytes,
    })
}
