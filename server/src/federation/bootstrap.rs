//! Sealed remote-prefix admission and live bootstrap fetch.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use catbird_atproto::generated::blue_catbird::chat::ConversationCoordinates;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use super::{
    errors::FederationError,
    outbound::{OutboundClient, OutboundError},
    peer_policy,
    reconciliation::{
        fetch_discovery_payload, query_remote_digest, query_remote_events,
        verify_remote_event_receipt_from_peer, RemoteReceiptKeyCache, StrictCleanRemoteEvent,
        DIGEST_NSID, EVENTS_NSID, EVENTS_PAGE_LIMIT,
    },
    resolver::{DsResolver, ValidatedRemoteDestination},
    target_supports_capability, CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1,
    CAPABILITY_RECONCILIATION_V1,
};
use crate::chat_protocol::transcript::{
    decode_canonical_signed_mutation, CanonicalValueRef, CleanEntryKind, SignedMutationKind,
};
use crate::chat_protocol::validation::{BareDid, MAX_SAFE_INTEGER};
use crate::handlers::ds::get_convo_digest::CleanConvoDigestHasher;
use crate::identity::{canonical_did, dids_equivalent};

const MAX_BOOTSTRAP_EVENTS: usize = 500;
const MAX_BOOTSTRAP_MATERIAL_BYTES: usize = 1_048_576; // 1 MiB

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RemotePrefixBootstrapError {
    #[error("invalid bootstrap selector")]
    InvalidSelector,
    #[error("peer policy denied bootstrap")]
    PeerDenied,
    #[error("sequencer resolution failed")]
    Resolution,
    #[error("sequencer lacks bootstrap capability")]
    MissingCapability,
    #[error("service authentication failed")]
    ServiceAuth,
    #[error("sequencer query failed")]
    Query,
    #[error("invalid digest response")]
    InvalidDigest,
    #[error("invalid event prefix")]
    InvalidEvent,
    #[error("sequencer snapshot changed")]
    MovingSnapshot,
    #[error("prefix exceeds bootstrap limits")]
    PrefixTooLarge,
    #[error("no active local recipient")]
    NoLocalParticipant,
    #[error("prefix is not an eligible direct Welcome opening")]
    DirectWelcomeNotEligible,
    #[error("historical authority rejected")]
    Authority,
    #[error("existing conversation conflicts")]
    Conflict,
    #[error("database operation failed")]
    Database,
    /// The sequencer, a resolver or a participant's home could not answer
    /// now; nothing was decided.
    #[error("bootstrap source could not answer now")]
    Unavailable,
}

impl RemotePrefixBootstrapError {
    /// Decided nothing: a source that could not answer now, or a sequencer
    /// snapshot that moved while it was fetched. This DS's own `Database`
    /// failure is matched separately.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Unavailable | Self::MovingSnapshot)
    }
}

/// A resolution or peer-policy failure: this store failing, a resolver that
/// could not answer now, or a refusal.
fn resolution_failure(error: &FederationError) -> RemotePrefixBootstrapError {
    match error {
        FederationError::Database(_) => RemotePrefixBootstrapError::Database,
        error if error.is_retryable() => RemotePrefixBootstrapError::Unavailable,
        _ => RemotePrefixBootstrapError::Resolution,
    }
}

/// A sequencer query that could not answer now, or one it refused.
fn query_failure(error: OutboundError) -> RemotePrefixBootstrapError {
    if error.is_retryable() {
        RemotePrefixBootstrapError::Unavailable
    } else {
        RemotePrefixBootstrapError::Query
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineReason {
    PrefixMismatch,
    LocalAhead,
}

impl QuarantineReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrefixMismatch => "prefix_mismatch",
            Self::LocalAhead => "local_ahead",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemotePrefixApplyOutcome {
    Applied {
        conversation_id: Uuid,
        sequencer_term: i64,
        last_seq: i64,
        digest_sha256: [u8; 32],
    },
    ExactReplay {
        conversation_id: Uuid,
        sequencer_term: i64,
        last_seq: i64,
        digest_sha256: [u8; 32],
    },
    Quarantined {
        conversation_id: Uuid,
        first_mismatch_seq: i64,
        reason: QuarantineReason,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RemotePrefixAdmissionPurpose {
    General,
    DirectWelcome,
}

pub fn compute_bootstrap_advisory_lock_key(conversation_id: Uuid) -> i64 {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"CATBIRD-CLEAN-REMOTE-BOOTSTRAP-LOCK-V1\0");
    hasher.update(conversation_id.as_bytes());
    let hash = hasher.finalize();
    i64::from_be_bytes(hash[..8].try_into().expect("8 bytes"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemotePrefixBootstrapSelector {
    conversation_id: Uuid,
    configured_sequencer_did: String,
    configured_sequencer_term: i64,
}

impl RemotePrefixBootstrapSelector {
    pub fn new(
        conversation_id: Uuid,
        configured_sequencer_did: String,
        configured_sequencer_term: i64,
    ) -> Result<Self, RemotePrefixBootstrapError> {
        if !(0..=MAX_SAFE_INTEGER).contains(&configured_sequencer_term) {
            return Err(RemotePrefixBootstrapError::InvalidSelector);
        }
        if BareDid::parse(&configured_sequencer_did).is_err() {
            return Err(RemotePrefixBootstrapError::InvalidSelector);
        }
        let canonical_seq_did = canonical_did(&configured_sequencer_did).to_string();
        Ok(Self {
            conversation_id,
            configured_sequencer_did: canonical_seq_did,
            configured_sequencer_term,
        })
    }

    pub fn conversation_id(&self) -> Uuid {
        self.conversation_id
    }

    pub fn configured_sequencer_did(&self) -> &str {
        &self.configured_sequencer_did
    }

    pub fn configured_sequencer_term(&self) -> i64 {
        self.configured_sequencer_term
    }
}

pub struct RemoteDigestAnchor {
    conversation_id: Uuid,
    sequencer_did: String,
    sequencer_term: i64,
    last_seq: i64,
    event_count: i64,
    last_generation: i64,
    digest_sha256: [u8; 32],
}

impl RemoteDigestAnchor {
    pub fn conversation_id(&self) -> Uuid {
        self.conversation_id
    }

    pub fn sequencer_did(&self) -> &str {
        &self.sequencer_did
    }

    pub fn sequencer_term(&self) -> i64 {
        self.sequencer_term
    }

    pub fn last_seq(&self) -> i64 {
        self.last_seq
    }

    pub fn event_count(&self) -> i64 {
        self.event_count
    }

    pub fn last_generation(&self) -> i64 {
        self.last_generation
    }

    pub fn digest_sha256(&self) -> &[u8; 32] {
        &self.digest_sha256
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn new_for_test(
        conversation_id: Uuid,
        sequencer_did: String,
        sequencer_term: i64,
        last_seq: i64,
        event_count: i64,
        last_generation: i64,
        digest_sha256: [u8; 32],
    ) -> Self {
        Self {
            conversation_id,
            sequencer_did,
            sequencer_term,
            last_seq,
            event_count,
            last_generation,
            digest_sha256,
        }
    }
}

/// Pinned, verified remote prefix admission.
///
/// This type is move-only and intentionally does not implement `Clone`, `Copy`,
/// `Default`, `Debug`, `Serialize`, or `Deserialize`. It can only be minted by
/// a live authenticated fetch from the configured sequencer.
pub struct VerifiedRemotePrefixAdmission {
    selector: RemotePrefixBootstrapSelector,
    destination: ValidatedRemoteDestination,
    digest: RemoteDigestAnchor,
    events: Vec<StrictCleanRemoteEvent>,
    participant_routes: BTreeMap<String, Option<String>>,
    canonical_material_bytes: usize,
    page_count: usize,
    purpose: RemotePrefixAdmissionPurpose,
}

impl VerifiedRemotePrefixAdmission {
    pub fn conversation_id(&self) -> Uuid {
        self.selector.conversation_id()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn new_for_test(
        selector: RemotePrefixBootstrapSelector,
        destination: ValidatedRemoteDestination,
        digest: RemoteDigestAnchor,
        events: Vec<StrictCleanRemoteEvent>,
        participant_routes: BTreeMap<String, Option<String>>,
        canonical_material_bytes: usize,
    ) -> Self {
        Self {
            selector,
            destination,
            digest,
            events,
            participant_routes,
            canonical_material_bytes,
            page_count: 1,
            purpose: RemotePrefixAdmissionPurpose::General,
        }
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
    pub fn canonical_material_bytes(&self) -> usize {
        self.canonical_material_bytes
    }
    pub fn page_count(&self) -> usize {
        self.page_count
    }

    pub(crate) fn events(&self) -> &[StrictCleanRemoteEvent] {
        &self.events
    }

    pub(crate) fn participant_routes(&self) -> &BTreeMap<String, Option<String>> {
        &self.participant_routes
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        RemotePrefixBootstrapSelector,
        ValidatedRemoteDestination,
        RemoteDigestAnchor,
        Vec<StrictCleanRemoteEvent>,
        BTreeMap<String, Option<String>>,
        usize,
        RemotePrefixAdmissionPurpose,
    ) {
        (
            self.selector,
            self.destination,
            self.digest,
            self.events,
            self.participant_routes,
            self.canonical_material_bytes,
            self.purpose,
        )
    }
}

/// Exact inbound Welcome evidence that can authorize one otherwise-forbidden
/// historical Direct creation. The final mailbox write revalidates every field
/// against the graph produced in the same transaction.
pub struct DirectWelcomeBootstrapBinding<'a> {
    pub conversation_id: Uuid,
    pub sequencer_did: &'a str,
    pub sequencer_term: i64,
    pub recipient_did: &'a str,
    pub recipient_device_id: Uuid,
    pub welcome_id: Uuid,
    pub recovery_request_id: Uuid,
    pub key_package_ref: &'a [u8; 32],
    pub welcome_bytes: &'a [u8],
    pub welcome_sha256: &'a [u8; 32],
    pub entry_bytes: &'a [u8],
    pub signed_request_bytes: &'a [u8],
    pub entry_id: Uuid,
    pub entry_seq: u64,
    pub accepted_payload_sha256: &'a [u8; 32],
    pub outer_entry_fingerprint: &'a [u8; 32],
    pub coordinates: &'a ConversationCoordinates,
}

fn direct_welcome_coordinates_match(
    next: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
    binding: &DirectWelcomeBootstrapBinding<'_>,
) -> bool {
    matches!(
        next.get("conversationId"),
        Some(CanonicalValueRef::Uuid(value))
            if value.as_bytes() == binding.conversation_id.as_bytes()
    ) && matches!(
        next.get("generation"),
        Some(CanonicalValueRef::Integer(value))
            if i64::try_from(value).ok() == Some(binding.coordinates.generation)
    ) && matches!(
        next.get("stateVersion"),
        Some(CanonicalValueRef::Integer(value))
            if i64::try_from(value).ok() == Some(binding.coordinates.state_version)
    ) && matches!(
        next.get("epoch"),
        Some(CanonicalValueRef::Integer(value))
            if i64::try_from(value).ok() == Some(binding.coordinates.epoch)
    ) && matches!(
        next.get("groupId"),
        Some(CanonicalValueRef::Bytes(value))
            if value == binding.coordinates.group_id.as_ref()
    ) && matches!(
        next.get("groupContextHash"),
        Some(CanonicalValueRef::Bytes(value))
            if value == binding.coordinates.group_context_hash.as_ref()
    ) && matches!(
        next.get("confirmationTag"),
        Some(CanonicalValueRef::Bytes(value))
            if value == binding.coordinates.confirmation_tag.as_ref()
    ) && matches!(
        next.get("lifecycle"),
        Some(CanonicalValueRef::Text(value))
            if value == binding.coordinates.lifecycle.as_str()
    )
}

fn direct_welcome_manifest_matches(
    manifest: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
    binding: &DirectWelcomeBootstrapBinding<'_>,
) -> bool {
    let request_matches = matches!(
        manifest.get("leafRecoveryRequestId"),
        Some(CanonicalValueRef::Uuid(value))
            if value.as_bytes() == binding.recovery_request_id.as_bytes()
    );
    let leaf_matches = match manifest.get("leafChanges") {
        Some(CanonicalValueRef::Array(values)) if values.len() == 1 => match values.get(0) {
            Some(CanonicalValueRef::Object(value)) => {
                matches!(
                    value.get("$type"),
                    Some(CanonicalValueRef::Text(
                        "blue.catbird.chat.defs#addLeafByRecovery"
                    ))
                ) && matches!(
                    value.get("userDid"),
                    Some(CanonicalValueRef::Did(did))
                        if dids_equivalent(did.as_str(), binding.recipient_did)
                ) && matches!(
                    value.get("deviceId"),
                    Some(CanonicalValueRef::Uuid(id))
                        if id.as_bytes() == binding.recipient_device_id.as_bytes()
                ) && matches!(
                    value.get("recoveryRequestId"),
                    Some(CanonicalValueRef::Uuid(id))
                        if id.as_bytes() == binding.recovery_request_id.as_bytes()
                ) && matches!(
                    value.get("keyPackageRef"),
                    Some(CanonicalValueRef::Bytes(value))
                        if value == binding.key_package_ref
                )
            }
            _ => false,
        },
        _ => false,
    };
    let welcome_matches = match manifest.get("welcomeBundle") {
        Some(CanonicalValueRef::Object(bundle)) => {
            let delivery_matches = match bundle.get("deliveries") {
                Some(CanonicalValueRef::Array(values)) if values.len() == 1 => {
                    match values.get(0) {
                        Some(CanonicalValueRef::Object(delivery)) => {
                            let provenance_matches = match delivery.get("provenance") {
                                Some(CanonicalValueRef::Object(provenance)) => {
                                    matches!(
                                        provenance.get("recoveryRequestId"),
                                        Some(CanonicalValueRef::Uuid(id))
                                            if id.as_bytes()
                                                == binding.recovery_request_id.as_bytes()
                                    ) && matches!(
                                        provenance.get("keyPackageRef"),
                                        Some(CanonicalValueRef::Bytes(value))
                                            if value == binding.key_package_ref
                                    )
                                }
                                _ => false,
                            };
                            matches!(
                                delivery.get("recipientDid"),
                                Some(CanonicalValueRef::Did(did))
                                    if dids_equivalent(did.as_str(), binding.recipient_did)
                            ) && matches!(
                                delivery.get("recipientDeviceId"),
                                Some(CanonicalValueRef::Uuid(id))
                                    if id.as_bytes() == binding.recipient_device_id.as_bytes()
                            ) && provenance_matches
                        }
                        _ => false,
                    }
                }
                _ => false,
            };
            matches!(
                bundle.get("welcomeId"),
                Some(CanonicalValueRef::Uuid(id))
                    if id.as_bytes() == binding.welcome_id.as_bytes()
            ) && matches!(
                bundle.get("opaqueWelcome"),
                Some(CanonicalValueRef::Bytes(value))
                    if value == binding.welcome_bytes
            ) && matches!(
                bundle.get("sha256"),
                Some(CanonicalValueRef::Bytes(value))
                    if value == binding.welcome_sha256
            ) && delivery_matches
        }
        _ => false,
    };
    request_matches && leaf_matches && welcome_matches
}

/// Narrow the live canonical prefix to the exact first Direct Welcome being
/// delivered. Only this sealed admission can authorize historical Direct
/// creation; the general selector path remains Group-only.
pub async fn bind_direct_welcome_admission(
    pool: &PgPool,
    admission: &mut VerifiedRemotePrefixAdmission,
    binding: &DirectWelcomeBootstrapBinding<'_>,
) -> Result<(), RemotePrefixBootstrapError> {
    if admission.purpose != RemotePrefixAdmissionPurpose::General
        || admission.selector.conversation_id() != binding.conversation_id
        || !dids_equivalent(
            admission.selector.configured_sequencer_did(),
            binding.sequencer_did,
        )
        || admission.selector.configured_sequencer_term() != binding.sequencer_term
        || admission.digest.conversation_id() != binding.conversation_id
        || !dids_equivalent(admission.digest.sequencer_did(), binding.sequencer_did)
        || admission.digest.sequencer_term() != binding.sequencer_term
        || Uuid::parse_str(binding.coordinates.conversation_id.as_str()).ok()
            != Some(binding.conversation_id)
    {
        return Err(RemotePrefixBootstrapError::Authority);
    }

    if admission.events.len() != 3
        || admission.events[0].entry_kind() != CleanEntryKind::Creation
        || admission.events[1].entry_kind() != CleanEntryKind::ParticipantAcceptance
        || admission.events[2].entry_kind() != CleanEntryKind::LeafRecoveryFulfillment
    {
        return Err(RemotePrefixBootstrapError::DirectWelcomeNotEligible);
    }

    let creation = decode_canonical_signed_mutation(admission.events[0].signed_request())
        .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?;
    if creation.kind() != SignedMutationKind::Creation
        || creation
            .creation_conversation_kind()
            .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?
            != "direct"
    {
        return Err(RemotePrefixBootstrapError::DirectWelcomeNotEligible);
    }
    let participant_dids = creation
        .creation_participant_dids()
        .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?;
    let participants: BTreeSet<String> = participant_dids
        .iter()
        .map(|did| canonical_did(did).to_string())
        .collect();
    if participant_dids.len() != 2
        || participants.len() != 2
        || !participants.contains(&canonical_did(binding.recipient_did).to_string())
        || canonical_did(creation.actor_did().as_str()) == canonical_did(binding.recipient_did)
    {
        return Err(RemotePrefixBootstrapError::Authority);
    }
    let routed_participants: BTreeSet<String> = admission
        .participant_routes
        .keys()
        .map(|did| canonical_did(did).to_string())
        .collect();
    let recipient_is_local = admission
        .participant_routes
        .iter()
        .any(|(did, route)| dids_equivalent(did, binding.recipient_did) && route.is_none());
    let creator_is_sequencer_home = admission.participant_routes.iter().any(|(did, route)| {
        dids_equivalent(did, creation.actor_did().as_str())
            && route
                .as_deref()
                .is_some_and(|home| dids_equivalent(home, binding.sequencer_did))
    });
    if routed_participants != participants || !recipient_is_local || !creator_is_sequencer_home {
        return Err(RemotePrefixBootstrapError::NoLocalParticipant);
    }

    let acceptance = decode_canonical_signed_mutation(admission.events[1].signed_request())
        .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?;
    if acceptance.kind() != SignedMutationKind::ParticipantAcceptance
        || !dids_equivalent(acceptance.actor_did().as_str(), binding.recipient_did)
        || acceptance.actor_device_id().as_bytes() != binding.recipient_device_id.as_bytes()
        || acceptance
            .recovery_request_id()
            .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?
            .as_bytes()
            != binding.recovery_request_id.as_bytes()
    {
        return Err(RemotePrefixBootstrapError::Authority);
    }

    let final_event = &admission.events[2];
    let final_seq =
        i64::try_from(binding.entry_seq).map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?;
    let expected_entry_sha256: [u8; 32] = Sha256::digest(binding.entry_bytes).into();
    let expected_welcome_sha256: [u8; 32] = Sha256::digest(binding.welcome_bytes).into();
    if final_event.seq() != final_seq
        || admission.digest.last_seq() != final_seq
        || admission.digest.event_count() != 3
        || final_event.entry_id() != binding.entry_id
        || final_event.accepted_payload_bytes() != binding.entry_bytes
        || final_event.accepted_payload_sha256() != binding.accepted_payload_sha256
        || expected_entry_sha256 != *binding.accepted_payload_sha256
        || final_event.signed_request() != binding.signed_request_bytes
        || final_event.outer_fingerprint() != binding.outer_entry_fingerprint
        || expected_welcome_sha256 != *binding.welcome_sha256
    {
        return Err(RemotePrefixBootstrapError::Conflict);
    }

    let fulfillment = decode_canonical_signed_mutation(final_event.signed_request())
        .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?;
    if fulfillment.kind() != SignedMutationKind::LeafRecoveryFulfillment
        || fulfillment
            .recovery_request_id()
            .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?
            .as_bytes()
            != binding.recovery_request_id.as_bytes()
        || !direct_welcome_coordinates_match(
            &fulfillment
                .recovery_fulfillment_next()
                .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?,
            binding,
        )
        || !direct_welcome_manifest_matches(
            &fulfillment
                .recovery_fulfillment_manifest()
                .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?,
            binding,
        )
    {
        return Err(RemotePrefixBootstrapError::Conflict);
    }

    let active_local_device: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM chat.devices \
         WHERE user_did = $1 AND device_id = $2 \
           AND status = 'active' AND revoked_at IS NULL",
    )
    .bind(binding.recipient_did)
    .bind(binding.recipient_device_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| RemotePrefixBootstrapError::Database)?;
    if active_local_device.is_none() {
        return Err(RemotePrefixBootstrapError::NoLocalParticipant);
    }

    admission.purpose = RemotePrefixAdmissionPurpose::DirectWelcome;
    Ok(())
}

pub(crate) fn validate_prefix_grammar(
    events: &[StrictCleanRemoteEvent],
) -> Result<(), RemotePrefixBootstrapError> {
    if events.is_empty() {
        return Err(RemotePrefixBootstrapError::InvalidEvent);
    }
    if events[0].entry_kind() != CleanEntryKind::Creation {
        return Err(RemotePrefixBootstrapError::InvalidEvent);
    }

    #[derive(Clone, Copy)]
    enum State {
        Ready,
        AwaitingFulfillment,
    }

    let mut state = State::Ready;
    for event in &events[1..] {
        state = match (state, event.entry_kind()) {
            (State::Ready, CleanEntryKind::Policy | CleanEntryKind::Application) => State::Ready,
            (State::Ready, CleanEntryKind::ParticipantAcceptance) => State::AwaitingFulfillment,
            (State::AwaitingFulfillment, CleanEntryKind::LeafRecoveryFulfillment) => State::Ready,
            _ => return Err(RemotePrefixBootstrapError::InvalidEvent),
        };
    }
    // Pending invitations and accepted-but-not-yet-fulfilled invitations are
    // real home mailboxes. The historical planner still validates every edge.
    Ok(())
}

/// Fetch, verify, and seal an authoritative remote prefix admission from a live sequencer.
pub async fn fetch_remote_prefix_admission(
    pool: &PgPool,
    resolver: &DsResolver,
    outbound: &OutboundClient,
    auth_sign: &(dyn Fn(&str, &str) -> Result<String, String> + Send + Sync),
    selector: RemotePrefixBootstrapSelector,
) -> Result<VerifiedRemotePrefixAdmission, RemotePrefixBootstrapError> {
    if canonical_did(selector.configured_sequencer_did()) == canonical_did(resolver.self_did()) {
        return Err(RemotePrefixBootstrapError::PeerDenied);
    }

    peer_policy::enforce_outbound_peer_policy(pool, selector.configured_sequencer_did())
        .await
        .map_err(|error| match error {
            FederationError::Database(_) => RemotePrefixBootstrapError::Database,
            _ => RemotePrefixBootstrapError::PeerDenied,
        })?;

    let destination = resolver
        .resolve_ds_destination_uncached(selector.configured_sequencer_did())
        .await
        .map_err(|error| resolution_failure(&error))?;

    // A discovery fetch that could not complete now decided nothing; any
    // other failure, or a payload without both capabilities, is definitive.
    let discovery_payload = fetch_discovery_payload(&destination)
        .await
        .map_err(|error| {
            if error.is_retryable() {
                RemotePrefixBootstrapError::Unavailable
            } else {
                RemotePrefixBootstrapError::MissingCapability
            }
        })?;
    if !target_supports_capability(CAPABILITY_RECONCILIATION_V1, None, Some(&discovery_payload))
        || !target_supports_capability(
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1,
            None,
            Some(&discovery_payload),
        )
    {
        return Err(RemotePrefixBootstrapError::MissingCapability);
    }

    let convo_id_str = selector.conversation_id().to_string();

    let digest_token = auth_sign(selector.configured_sequencer_did(), DIGEST_NSID)
        .map_err(|_| RemotePrefixBootstrapError::ServiceAuth)?;
    let opening_digest = query_remote_digest(outbound, &destination, &digest_token, &convo_id_str)
        .await
        .map_err(query_failure)?;

    if opening_digest.convo_id != convo_id_str {
        return Err(RemotePrefixBootstrapError::InvalidDigest);
    }
    if canonical_did(&opening_digest.sequencer_ds_did) != selector.configured_sequencer_did() {
        return Err(RemotePrefixBootstrapError::InvalidDigest);
    }
    if opening_digest.sequencer_term != selector.configured_sequencer_term() {
        return Err(RemotePrefixBootstrapError::InvalidDigest);
    }
    if opening_digest.last_seq < 1 || opening_digest.event_count < 1 {
        return Err(RemotePrefixBootstrapError::InvalidDigest);
    }
    if opening_digest.event_count > MAX_BOOTSTRAP_EVENTS as i64 {
        return Err(RemotePrefixBootstrapError::PrefixTooLarge);
    }

    let digest_bytes = hex::decode(&opening_digest.digest_sha256)
        .map_err(|_| RemotePrefixBootstrapError::InvalidDigest)?;
    let digest_sha256: [u8; 32] = digest_bytes
        .try_into()
        .map_err(|_| RemotePrefixBootstrapError::InvalidDigest)?;

    let mut from_seq = 0_i64;
    let mut events: Vec<StrictCleanRemoteEvent> = Vec::new();
    let mut receipt_keys = RemoteReceiptKeyCache::new();
    let mut receipt_coordinate: Option<serde_json::Value> = None;
    let mut total_canonical_material_bytes: usize = 0;
    let mut seen_entry_ids: HashSet<Uuid> = HashSet::new();
    let mut hasher = CleanConvoDigestHasher::new();
    let mut rolling_last_seq = 0_i64;
    let mut rolling_last_generation = 0_i64;

    let mut page_count = 0_usize;
    while from_seq < opening_digest.last_seq {
        let limit = (opening_digest.last_seq - from_seq).min(EVENTS_PAGE_LIMIT);
        let events_token = auth_sign(selector.configured_sequencer_did(), EVENTS_NSID)
            .map_err(|_| RemotePrefixBootstrapError::ServiceAuth)?;
        let page = query_remote_events(
            outbound,
            &destination,
            &events_token,
            &convo_id_str,
            from_seq,
            limit,
        )
        .await
        .map_err(query_failure)?;
        page_count = page_count
            .checked_add(1)
            .ok_or(RemotePrefixBootstrapError::PrefixTooLarge)?;

        if page.convo_id != convo_id_str || page.from_seq_exclusive != from_seq {
            return Err(RemotePrefixBootstrapError::InvalidEvent);
        }
        if page.events.is_empty() || page.events.len() > limit as usize {
            return Err(RemotePrefixBootstrapError::InvalidEvent);
        }

        for raw_event in page.events {
            let strict_event = StrictCleanRemoteEvent::try_from(raw_event)
                .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?;

            if strict_event.seq() != rolling_last_seq + 1 {
                return Err(RemotePrefixBootstrapError::InvalidEvent);
            }
            let verified_coordinate = verify_remote_event_receipt_from_peer(
                pool,
                resolver,
                selector.configured_sequencer_did(),
                selector.conversation_id(),
                &strict_event,
                &mut receipt_keys,
                receipt_coordinate.as_ref(),
            )
            .await
            .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?;
            receipt_coordinate = Some(verified_coordinate);
            rolling_last_seq = strict_event.seq();
            rolling_last_generation = strict_event.generation();

            if !seen_entry_ids.insert(strict_event.entry_id()) {
                return Err(RemotePrefixBootstrapError::InvalidEvent);
            }

            if events.len() >= MAX_BOOTSTRAP_EVENTS {
                return Err(RemotePrefixBootstrapError::PrefixTooLarge);
            }

            let material_bytes = strict_event.accepted_payload_bytes().len()
                + strict_event.signed_request().len()
                + strict_event.sequencer_receipt().len();
            total_canonical_material_bytes = total_canonical_material_bytes
                .checked_add(material_bytes)
                .ok_or(RemotePrefixBootstrapError::PrefixTooLarge)?;
            if total_canonical_material_bytes > MAX_BOOTSTRAP_MATERIAL_BYTES {
                return Err(RemotePrefixBootstrapError::PrefixTooLarge);
            }

            hasher.update_event(
                strict_event.seq(),
                strict_event.generation(),
                strict_event.entry_id(),
                strict_event.entry_kind().type_id(),
                strict_event.accepted_payload_bytes(),
                strict_event.signed_request(),
                strict_event.outer_fingerprint(),
                strict_event.received_at(),
            );

            events.push(strict_event);
        }

        if page.to_seq_inclusive != rolling_last_seq {
            return Err(RemotePrefixBootstrapError::InvalidEvent);
        }
        from_seq = rolling_last_seq;
    }

    if rolling_last_seq != opening_digest.last_seq
        || events.len() as i64 != opening_digest.event_count
        || rolling_last_generation != opening_digest.epoch
    {
        return Err(RemotePrefixBootstrapError::InvalidEvent);
    }

    let computed_digest_hex = hasher.finalize();
    if computed_digest_hex != opening_digest.digest_sha256 {
        return Err(RemotePrefixBootstrapError::InvalidEvent);
    }

    validate_prefix_grammar(&events)?;

    let closing_token = auth_sign(selector.configured_sequencer_did(), DIGEST_NSID)
        .map_err(|_| RemotePrefixBootstrapError::ServiceAuth)?;
    let closing_digest = query_remote_digest(outbound, &destination, &closing_token, &convo_id_str)
        .await
        .map_err(query_failure)?;

    if closing_digest.convo_id != opening_digest.convo_id
        || canonical_did(&closing_digest.sequencer_ds_did)
            != canonical_did(&opening_digest.sequencer_ds_did)
        || closing_digest.sequencer_term != opening_digest.sequencer_term
        || closing_digest.epoch != opening_digest.epoch
        || closing_digest.last_seq != opening_digest.last_seq
        || closing_digest.event_count != opening_digest.event_count
        || closing_digest.digest_sha256 != opening_digest.digest_sha256
    {
        return Err(RemotePrefixBootstrapError::MovingSnapshot);
    }

    let creation_mutation = decode_canonical_signed_mutation(events[0].signed_request())
        .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?;
    let mut participant_dids = creation_mutation
        .creation_participant_dids()
        .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?;

    for event in &events[1..] {
        if event.entry_kind() == CleanEntryKind::Policy {
            let policy_mutation = decode_canonical_signed_mutation(event.signed_request())
                .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?;
            let change_kinds = policy_mutation
                .policy_change_kinds()
                .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?;
            if change_kinds.is_empty()
                || change_kinds
                    .iter()
                    .any(|k| k != "blue.catbird.chat.defs#addParticipant")
            {
                return Err(RemotePrefixBootstrapError::InvalidEvent);
            }
            let mut additions = policy_mutation
                .policy_addition_dids()
                .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?;
            if additions.is_empty() {
                return Err(RemotePrefixBootstrapError::InvalidEvent);
            }
            participant_dids.append(&mut additions);
        }
    }

    let unique_dids: BTreeSet<String> = participant_dids.into_iter().collect();
    if unique_dids.is_empty() {
        return Err(RemotePrefixBootstrapError::InvalidEvent);
    }

    let participant_routes =
        crate::chat_protocol::federation_routing::resolve_participant_routing_authoritative(
            pool,
            Some(resolver),
            &unique_dids,
        )
        .await
        .map_err(|error| {
            use crate::chat_protocol::federation_routing::FederationRoutingError;
            match error {
                FederationRoutingError::ResolutionFailed { source, .. }
                | FederationRoutingError::UntrustedPeer { source, .. } => {
                    resolution_failure(&source)
                }
                FederationRoutingError::DriftDetected { .. } => {
                    RemotePrefixBootstrapError::Resolution
                }
            }
        })?;

    let local_dids: Vec<&str> = participant_routes
        .iter()
        .filter(|(_, route)| route.is_none())
        .map(|(did, _)| did.as_str())
        .collect();

    if local_dids.is_empty() {
        return Err(RemotePrefixBootstrapError::NoLocalParticipant);
    }

    let has_active_local: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM chat.devices WHERE user_did = ANY($1) AND status = 'active' AND revoked_at IS NULL LIMIT 1",
    )
    .bind(&local_dids)
    .fetch_optional(pool)
    .await
    .map_err(|_| RemotePrefixBootstrapError::Database)?;

    if has_active_local.is_none() {
        return Err(RemotePrefixBootstrapError::NoLocalParticipant);
    }

    let digest = RemoteDigestAnchor {
        conversation_id: selector.conversation_id(),
        sequencer_did: selector.configured_sequencer_did().to_string(),
        sequencer_term: selector.configured_sequencer_term(),
        last_seq: opening_digest.last_seq,
        event_count: opening_digest.event_count,
        last_generation: opening_digest.epoch,
        digest_sha256,
    };

    Ok(VerifiedRemotePrefixAdmission {
        selector,
        destination,
        digest,
        events,
        participant_routes,
        canonical_material_bytes: total_canonical_material_bytes,
        page_count,
        purpose: RemotePrefixAdmissionPurpose::General,
    })
}

/// Execute live fetch and atomic bootstrap for one remote clean mailbox from a selector.
pub async fn bootstrap_remote_mailbox_from_selector(
    pool: &PgPool,
    resolver: &DsResolver,
    outbound: &OutboundClient,
    auth_sign: &(dyn Fn(&str, &str) -> Result<String, String> + Send + Sync),
    selector: RemotePrefixBootstrapSelector,
) -> Result<RemotePrefixApplyOutcome, RemotePrefixBootstrapError> {
    let started_at = std::time::Instant::now();
    let conversation_id = selector.conversation_id();
    let sequencer_term = selector.configured_sequencer_term();
    let redacted_sequencer = crate::crypto::redact_for_log(selector.configured_sequencer_did());
    let admission =
        fetch_remote_prefix_admission(pool, resolver, outbound, auth_sign, selector).await?;
    let page_count = admission.page_count();
    let event_count = admission.event_count();
    let canonical_material_bytes = admission.canonical_material_bytes();

    let mut tx = pool
        .begin()
        .await
        .map_err(|_| RemotePrefixBootstrapError::Database)?;
    let outcome = crate::chat_protocol::repository::remote_prefix::apply_remote_clean_prefix(
        &mut tx, admission,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| RemotePrefixBootstrapError::Database)?;

    if let RemotePrefixApplyOutcome::Applied {
        last_seq,
        digest_sha256,
        ..
    } = &outcome
    {
        tracing::info!(
            target: "catbird_federation::bootstrap",
            outcome = "applied",
            sequencer_did = %redacted_sequencer,
            conversation_id = %conversation_id,
            sequencer_term,
            page_count,
            event_count,
            last_seq = *last_seq,
            digest = %hex::encode(digest_sha256),
            canonical_material_bytes,
            elapsed_ms = started_at.elapsed().as_millis(),
            "remote prefix bootstrap applied"
        );
        metrics::counter!("federation_remote_bootstrap_applied_total", 1);
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::super::reconciliation::RemoteEvent;
    use super::*;
    use crate::federation::receipt::I13ReceiptSigner;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_selector_term_boundaries() {
        let convo_id = Uuid::new_v4();
        let valid_did = "did:web:sequencer.catbird.blue".to_string();

        assert!(RemotePrefixBootstrapSelector::new(convo_id, valid_did.clone(), 0).is_ok());
        assert!(RemotePrefixBootstrapSelector::new(convo_id, valid_did.clone(), 1).is_ok());
        assert!(
            RemotePrefixBootstrapSelector::new(convo_id, valid_did.clone(), MAX_SAFE_INTEGER)
                .is_ok()
        );

        assert_eq!(
            RemotePrefixBootstrapSelector::new(convo_id, valid_did.clone(), -1).unwrap_err(),
            RemotePrefixBootstrapError::InvalidSelector
        );
        assert_eq!(
            RemotePrefixBootstrapSelector::new(convo_id, valid_did.clone(), MAX_SAFE_INTEGER + 1)
                .unwrap_err(),
            RemotePrefixBootstrapError::InvalidSelector
        );
        assert_eq!(
            RemotePrefixBootstrapSelector::new(convo_id, "invalid-did".to_string(), 0).unwrap_err(),
            RemotePrefixBootstrapError::InvalidSelector
        );
    }

    fn test_strict_event(seq: i64, kind: CleanEntryKind) -> StrictCleanRemoteEvent {
        let ciphertext = vec![1, 2, 3];
        let hash = Sha256::digest(&ciphertext).to_vec();
        let created_at = chrono::Utc::now();
        let entry_id = format!("00000000-0000-0000-0000-{seq:012x}");
        let actor_device_id = Uuid::from_bytes([7; 16]);
        let signer = I13ReceiptSigner::from_signing_key_for_test(
            "did:web:strict-event.example".to_owned(),
            p256::ecdsa::SigningKey::from_slice(&[0x63; 32]).unwrap(),
        );
        let signed_receipt = signer
            .sign_application_receipt(
                "00000000-0000-0000-0000-000000000000",
                &[3; 32],
                0,
                "did:plc:strict-event",
                &actor_device_id.to_string(),
                &entry_id,
                &[4; 32],
                seq as u64,
                created_at.timestamp_millis(),
            )
            .unwrap();
        let receipt = I13ReceiptSigner::receipt_wire_json(
            &signed_receipt,
            0,
            "did:plc:strict-event",
            &actor_device_id.to_string(),
        );
        StrictCleanRemoteEvent::try_from(RemoteEvent {
            seq,
            epoch: 0,
            msg_id: entry_id.clone(),
            message_type: kind.type_id().to_string(),
            accepted_payload_sha256: Some(hash),
            ciphertext,
            padded_size: 3,
            created_at,
            entry_id: Some(entry_id),
            entry_kind: Some(kind.type_id().to_string()),
            signed_request: Some(vec![1; 64]),
            outer_fingerprint: Some(vec![2; 32]),
            sequencer_receipt: Some(serde_json::to_vec(&receipt).unwrap()),
            account_deleted_entry: None,
        })
        .expect("valid strict event")
    }

    #[test]
    fn test_grammar_validation_comprehensive() {
        assert_eq!(
            validate_prefix_grammar(&[]).unwrap_err(),
            RemotePrefixBootstrapError::InvalidEvent
        );

        let app = test_strict_event(1, CleanEntryKind::Application);
        assert_eq!(
            validate_prefix_grammar(&[app]).unwrap_err(),
            RemotePrefixBootstrapError::InvalidEvent
        );

        let creation = test_strict_event(1, CleanEntryKind::Creation);
        assert!(validate_prefix_grammar(&[creation]).is_ok());

        let c = test_strict_event(1, CleanEntryKind::Creation);
        let acc = test_strict_event(2, CleanEntryKind::ParticipantAcceptance);
        assert!(validate_prefix_grammar(&[c, acc]).is_ok());

        // Creation -> Acceptance -> Fulfillment is valid
        let c = test_strict_event(1, CleanEntryKind::Creation);
        let acc = test_strict_event(2, CleanEntryKind::ParticipantAcceptance);
        let ful = test_strict_event(3, CleanEntryKind::LeafRecoveryFulfillment);
        assert!(validate_prefix_grammar(&[c, acc, ful]).is_ok());

        // Creation -> Policy -> Acceptance -> Fulfillment -> Application is valid
        let c = test_strict_event(1, CleanEntryKind::Creation);
        let pol = test_strict_event(2, CleanEntryKind::Policy);
        let acc = test_strict_event(3, CleanEntryKind::ParticipantAcceptance);
        let ful = test_strict_event(4, CleanEntryKind::LeafRecoveryFulfillment);
        let app = test_strict_event(5, CleanEntryKind::Application);
        assert!(validate_prefix_grammar(&[c, pol, acc, ful, app]).is_ok());

        // Another invitation can be added after application traffic.
        let c = test_strict_event(1, CleanEntryKind::Creation);
        let acc = test_strict_event(2, CleanEntryKind::ParticipantAcceptance);
        let ful = test_strict_event(3, CleanEntryKind::LeafRecoveryFulfillment);
        let app = test_strict_event(4, CleanEntryKind::Application);
        let pol = test_strict_event(5, CleanEntryKind::Policy);
        assert!(validate_prefix_grammar(&[c, acc, ful, app, pol]).is_ok());

        // Skip Acceptance (Creation -> Fulfillment) is rejected
        let c = test_strict_event(1, CleanEntryKind::Creation);
        let ful = test_strict_event(2, CleanEntryKind::LeafRecoveryFulfillment);
        assert_eq!(
            validate_prefix_grammar(&[c, ful]).unwrap_err(),
            RemotePrefixBootstrapError::InvalidEvent
        );

        // Skip Fulfillment (Creation -> Acceptance -> Application) is rejected
        let c = test_strict_event(1, CleanEntryKind::Creation);
        let acc = test_strict_event(2, CleanEntryKind::ParticipantAcceptance);
        let app = test_strict_event(3, CleanEntryKind::Application);
        assert_eq!(
            validate_prefix_grammar(&[c, acc, app]).unwrap_err(),
            RemotePrefixBootstrapError::InvalidEvent
        );

        let repeated = [
            test_strict_event(1, CleanEntryKind::Creation),
            test_strict_event(2, CleanEntryKind::ParticipantAcceptance),
            test_strict_event(3, CleanEntryKind::LeafRecoveryFulfillment),
            test_strict_event(4, CleanEntryKind::Application),
            test_strict_event(5, CleanEntryKind::ParticipantAcceptance),
            test_strict_event(6, CleanEntryKind::LeafRecoveryFulfillment),
        ];
        assert!(validate_prefix_grammar(&repeated).is_ok());
    }
}
