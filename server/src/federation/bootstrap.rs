//! Sealed remote-prefix admission and live bootstrap fetch.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use sqlx::PgPool;
use uuid::Uuid;

use super::{
    outbound::OutboundClient,
    peer_policy,
    reconciliation::{
        fetch_discovery_payload, query_remote_digest, query_remote_events, StrictCleanRemoteEvent,
        DIGEST_NSID, EVENTS_NSID, EVENTS_PAGE_LIMIT,
    },
    resolver::{DsResolver, ValidatedRemoteDestination},
    target_supports_capability, CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1,
    CAPABILITY_RECONCILIATION_V1,
};
use crate::chat_protocol::transcript::{decode_canonical_signed_mutation, CleanEntryKind};
use crate::chat_protocol::validation::{BareDid, MAX_SAFE_INTEGER};
use crate::handlers::ds::get_convo_digest::CleanConvoDigestHasher;
use crate::identity::canonical_did;

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
    #[error("historical authority rejected")]
    Authority,
    #[error("existing conversation conflicts")]
    Conflict,
    #[error("database operation failed")]
    Database,
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

    pub(crate) fn into_parts(
        self,
    ) -> (
        RemotePrefixBootstrapSelector,
        ValidatedRemoteDestination,
        RemoteDigestAnchor,
        Vec<StrictCleanRemoteEvent>,
        BTreeMap<String, Option<String>>,
        usize,
    ) {
        (
            self.selector,
            self.destination,
            self.digest,
            self.events,
            self.participant_routes,
            self.canonical_material_bytes,
        )
    }
}

fn validate_prefix_grammar(
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
        CreationSeen,
        AcceptanceSeen,
        FulfillmentSeen,
        ApplicationSeen,
    }

    let mut state = State::CreationSeen;
    for event in &events[1..] {
        state = match (state, event.entry_kind()) {
            (State::CreationSeen, CleanEntryKind::Policy) => State::CreationSeen,
            (State::CreationSeen, CleanEntryKind::ParticipantAcceptance) => State::AcceptanceSeen,
            (State::AcceptanceSeen, CleanEntryKind::LeafRecoveryFulfillment) => {
                State::FulfillmentSeen
            }
            (State::FulfillmentSeen | State::ApplicationSeen, CleanEntryKind::Application) => {
                State::ApplicationSeen
            }
            _ => return Err(RemotePrefixBootstrapError::InvalidEvent),
        };
    }

    match state {
        State::FulfillmentSeen | State::ApplicationSeen => Ok(()),
        State::CreationSeen | State::AcceptanceSeen => {
            Err(RemotePrefixBootstrapError::InvalidEvent)
        }
    }
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
        .map_err(|_| RemotePrefixBootstrapError::PeerDenied)?;

    let destination = resolver
        .resolve_ds_destination_uncached(selector.configured_sequencer_did())
        .await
        .map_err(|_| RemotePrefixBootstrapError::Resolution)?;

    let discovery_payload = fetch_discovery_payload(&destination).await;
    if !target_supports_capability(
        CAPABILITY_RECONCILIATION_V1,
        None,
        discovery_payload.as_ref(),
    ) || !target_supports_capability(
        CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1,
        None,
        discovery_payload.as_ref(),
    ) {
        return Err(RemotePrefixBootstrapError::MissingCapability);
    }

    let convo_id_str = selector.conversation_id().to_string();

    let digest_token = auth_sign(selector.configured_sequencer_did(), DIGEST_NSID)
        .map_err(|_| RemotePrefixBootstrapError::ServiceAuth)?;
    let opening_digest = query_remote_digest(outbound, &destination, &digest_token, &convo_id_str)
        .await
        .map_err(|_| RemotePrefixBootstrapError::Query)?;

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
        .map_err(|_| RemotePrefixBootstrapError::Query)?;
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
            rolling_last_seq = strict_event.seq();
            rolling_last_generation = strict_event.generation();

            if !seen_entry_ids.insert(strict_event.entry_id()) {
                return Err(RemotePrefixBootstrapError::InvalidEvent);
            }

            if events.len() >= MAX_BOOTSTRAP_EVENTS {
                return Err(RemotePrefixBootstrapError::PrefixTooLarge);
            }

            let material_bytes =
                strict_event.accepted_payload_bytes().len() + strict_event.signed_request().len();
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
        .map_err(|_| RemotePrefixBootstrapError::Query)?;

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
        crate::chat_protocol::federation_routing::resolve_participant_routing_uncached(
            pool,
            Some(resolver),
            &unique_dids,
        )
        .await
        .map_err(|_| RemotePrefixBootstrapError::Resolution)?;

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
        StrictCleanRemoteEvent::try_from(RemoteEvent {
            seq,
            epoch: 0,
            msg_id: format!("00000000-0000-0000-0000-{:012x}", seq),
            message_type: kind.type_id().to_string(),
            accepted_payload_sha256: Some(hash),
            ciphertext,
            padded_size: 3,
            created_at: chrono::Utc::now(),
            entry_id: Some(format!("00000000-0000-0000-0000-{:012x}", seq)),
            entry_kind: Some(kind.type_id().to_string()),
            signed_request: Some(vec![1; 64]),
            outer_fingerprint: Some(vec![2; 32]),
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
        assert_eq!(
            validate_prefix_grammar(&[creation]).unwrap_err(),
            RemotePrefixBootstrapError::InvalidEvent
        );

        let c = test_strict_event(1, CleanEntryKind::Creation);
        let acc = test_strict_event(2, CleanEntryKind::ParticipantAcceptance);
        assert_eq!(
            validate_prefix_grammar(&[c, acc]).unwrap_err(),
            RemotePrefixBootstrapError::InvalidEvent
        );

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

        // Policy after Application is rejected
        let c = test_strict_event(1, CleanEntryKind::Creation);
        let acc = test_strict_event(2, CleanEntryKind::ParticipantAcceptance);
        let ful = test_strict_event(3, CleanEntryKind::LeafRecoveryFulfillment);
        let app = test_strict_event(4, CleanEntryKind::Application);
        let pol = test_strict_event(5, CleanEntryKind::Policy);
        assert_eq!(
            validate_prefix_grammar(&[c, acc, ful, app, pol]).unwrap_err(),
            RemotePrefixBootstrapError::InvalidEvent
        );

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
    }
}
