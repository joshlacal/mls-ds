// One-shot startup seam for the hardened public relationship authority.
//
// The SQL implementation that lands here must expose only these consuming
// repository operations:
// - allocate a projection revision with `nextval(...)` and return an
//   `AllocatedProjectionRevisionGuard`;
// - atomically insert one snapshot and every declaration/relationship child;
// - while holding the durable operation row lock, load fallback evidence by
//   exact operation scope, scope digest, evidence kind, configuration
//   fingerprint, and freshness, then mint the corresponding load guard;
// - provide separate relationship and traffic fallback loaders so live rows
//   can never be promoted to restart authority.
//
// Persisted rows intentionally do not reconstruct caller scope. The loader
// must derive the exact scope from locked durable state and pass it through
// these guards to the evidence-kind-specific hydrator.

use std::collections::BTreeSet;

#[cfg(test)]
use std::ops::Deref;

use chrono::{DateTime, TimeDelta, Utc};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Postgres, QueryBuilder, Transaction};
use uuid::{Uuid, Variant, Version};

use super::super::relationship_policy::{
    consume_admission_projection, consume_block_projection, consume_traffic_projection,
    fixed_production_relationship_policy_config,
    hydrate_persisted_fallback_relationship_projection,
    hydrate_persisted_fallback_traffic_projection, AdmissionOperation, AdmissionRequest,
    DeclarationRecordEvidenceKind, EvidenceKind, IncomingPolicy, PersistedDeclarationEvidence,
    PersistedGraphRelationshipEvidence, PersistedRelationshipProjection,
    PersistedTrafficProjection, ProjectionOperationScope, ProjectionScope, PublicTransport,
    RelationshipAuthority, RelationshipPolicyConfig, RelationshipPolicyConfigError,
    RelationshipProjection, ReqwestPinnedTransport, SealedRelationshipProjection,
    SealedTrafficProjection, SystemDnsResolver, TrafficGraphScope, TrafficProjection,
    TransportError, TransportSecurityProfile,
};
use super::core::AllocatedProjectionRevisionGuard;

use super::super::relationship_policy::{plan_block_only_graph, plan_traffic_graph};
use super::super::state_machine::{
    ConversationKind, LockedRegistrationProjection, ParticipantStatus, PersistedRegistrationStatus,
};
use super::core::{
    LockedConversationHeadGuard, LockedConversationStateGuard, LockedDirectConversationLookupGuard,
    LockedDirectLookupOutcome, LockedInvitationQuotaGuard,
};

// Path-included repository tests compile this file under `cfg(test)` beside
// the policy module's test-only witnesses. Reuse those exact consuming types
// so the hydrator cannot observe a parallel, forgeable guard type. Production
// builds define the repository-owned witnesses below.
#[cfg(test)]
use super::super::relationship_policy::{
    RelationshipProjectionLoadGuard, TrafficProjectionLoadGuard,
    TrustedRelationshipDecisionInstant, TrustedRelationshipPersistenceInstant,
};

const MAX_PROTOCOL_INTEGER: u64 = 9_007_199_254_740_991;
const INSERT_CHUNK_ROWS: usize = 256;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum RelationshipAuthorityStartupError {
    InvalidConfiguration(RelationshipPolicyConfigError),
    InvalidTransport(TransportError),
    InsecureTransportProfile,
}

#[derive(Debug)]
pub(crate) enum RelationshipRepositoryError {
    Database(sqlx::Error),
    InvalidProjection,
    InvalidAuthorityConfiguration(RelationshipPolicyConfigError),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum RelationshipConsumptionError {
    InvalidWitness,
    PolicyDenied,
}

impl From<sqlx::Error> for RelationshipRepositoryError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// Non-Clone witness that startup loaded the one fixed relationship authority
/// configuration and constructed the audited transport internally. Its fields
/// are private so no handler/state caller can substitute an origin, digest, or
/// generic HTTP client.
pub(crate) struct RelationshipAuthorityStartupGuard {
    config: RelationshipPolicyConfig,
    transport: ReqwestPinnedTransport<SystemDnsResolver>,
}

/// Exact durable operation/scope witness for a relationship snapshot load.
/// The future SQL loader must mint this only while holding the operation's
/// locked state and must query by both operation scope and scope digest. There
/// is deliberately no public constructor or caller-supplied DTO shortcut.
#[cfg(not(test))]
pub(crate) struct RelationshipProjectionLoadGuard {
    operation_scope: ProjectionOperationScope,
    scope: ProjectionScope,
}

/// Exact durable traffic scope witness for a traffic snapshot load.
#[cfg(not(test))]
pub(crate) struct TrafficProjectionLoadGuard {
    scope: TrafficGraphScope,
}

/// One exact relationship fallback scope derived from a durable business
/// read-set already locked by the current PostgreSQL transaction. The fields
/// and constructors are private to this repository boundary, and the witness
/// is consumed by the loader.
pub(crate) struct LockedRelationshipFallbackScope {
    transaction_id: String,
    operation_scope: ProjectionOperationScope,
    scope: ProjectionScope,
    authenticated_actor_digest: [u8; 32],
    durable_read_set_digest: [u8; 32],
}

/// Traffic equivalent of `LockedRelationshipFallbackScope`.
pub(crate) struct LockedTrafficFallbackScope {
    transaction_id: String,
    scope: TrafficGraphScope,
    authenticated_actor_digest: [u8; 32],
    durable_read_set_digest: [u8; 32],
}

/// The projection and its decision clock may leave the repository together,
/// but their transaction/read-set binding remains repository-owned. Consumers
/// must present the current durable guards again; the repository re-seals the
/// scope and rejects any cross-transaction or stale-read-set pairing before
/// invoking the pure relationship policy.
pub(crate) struct LockedRelationshipDecisionGuard {
    transaction_id: String,
    operation_scope: ProjectionOperationScope,
    scope: ProjectionScope,
    authenticated_actor_digest: [u8; 32],
    durable_read_set_digest: [u8; 32],
    decision: TrustedRelationshipDecisionInstant,
}

/// Traffic analogue of `LockedRelationshipDecisionGuard`.
pub(crate) struct LockedTrafficDecisionGuard {
    transaction_id: String,
    scope: TrafficGraphScope,
    authenticated_actor_digest: [u8; 32],
    durable_read_set_digest: [u8; 32],
    decision: TrustedRelationshipDecisionInstant,
}

// Existing repository-policy tests intentionally exercise the pure consumer.
// Deref keeps that test seam available without exposing a raw decision from
// production state-machine APIs.
#[cfg(test)]
impl Deref for LockedRelationshipDecisionGuard {
    type Target = TrustedRelationshipDecisionInstant;

    fn deref(&self) -> &Self::Target {
        &self.decision
    }
}

#[cfg(test)]
impl Deref for LockedTrafficDecisionGuard {
    type Target = TrustedRelationshipDecisionInstant;

    fn deref(&self) -> &Self::Target {
        &self.decision
    }
}

/// Closed authority for the exact branch where a signed Creation or Policy
/// mutation introduces no pending participant and therefore requires no
/// external declaration/relationship reads.
pub(crate) struct LockedNoPendingAdmissionGuard {
    transaction_id: String,
    operation_scope: ProjectionOperationScope,
    conversation_id: [u8; 16],
    inviter_did: String,
    head_digest: [u8; 32],
    graph_digest: Option<[u8; 32]>,
    quota_digest: [u8; 32],
    registration_digest: [u8; 32],
    durable_read_set_digest: [u8; 32],
}

impl LockedNoPendingAdmissionGuard {
    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub(crate) fn operation_scope(&self) -> ProjectionOperationScope {
        self.operation_scope
    }

    pub(crate) fn conversation_id(&self) -> &[u8; 16] {
        &self.conversation_id
    }

    pub(crate) fn inviter_did(&self) -> &str {
        &self.inviter_did
    }

    pub(crate) fn evidence_digest(&self) -> [u8; 32] {
        self.durable_read_set_digest
    }

    pub(crate) fn authorizes_creation(
        &self,
        head: &LockedConversationHeadGuard,
        quota: &LockedInvitationQuotaGuard,
        registration: &LockedRegistrationProjection,
    ) -> bool {
        self.binding_is_valid()
            && self.operation_scope == ProjectionOperationScope::Creation
            && self.graph_digest.is_none()
            && self.matches_common(head, quota, registration)
    }

    pub(crate) fn authorizes_non_add_policy(
        &self,
        locked: &LockedConversationStateGuard,
        quota: &LockedInvitationQuotaGuard,
        registration: &LockedRegistrationProjection,
    ) -> bool {
        self.binding_is_valid()
            && self.operation_scope == ProjectionOperationScope::PendingAdd
            && self.graph_digest == Some(*locked.locked_graph_digest())
            && self.matches_common(locked.head(), quota, registration)
    }

    fn matches_common(
        &self,
        head: &LockedConversationHeadGuard,
        quota: &LockedInvitationQuotaGuard,
        registration: &LockedRegistrationProjection,
    ) -> bool {
        self.transaction_id == head.transaction_id()
            && self.transaction_id == quota.transaction_id()
            && self.transaction_id == registration.transaction_id()
            && self.conversation_id == *head.conversation_id().as_bytes()
            && self.conversation_id == *registration.conversation_id()
            && self.inviter_did == quota.inviter_did()
            && registration.actor().principal().as_bytes() == self.inviter_did.as_bytes()
            && quota.new_recipient_dids().is_empty()
            && self.head_digest == *head.durable_row_digest()
            && self.quota_digest == *quota.durable_row_digest()
            && self.registration_digest == *registration.durable_row_digest()
            && self.durable_read_set_digest
                == no_pending_admission_digest(
                    &self.transaction_id,
                    self.operation_scope,
                    &self.conversation_id,
                    &self.inviter_did,
                    &self.head_digest,
                    self.graph_digest.as_ref(),
                    &self.quota_digest,
                    &self.registration_digest,
                )
    }

    fn binding_is_valid(&self) -> bool {
        canonical_transaction_id(&self.transaction_id)
            && self.head_digest != [0; 32]
            && self.quota_digest != [0; 32]
            && self.registration_digest != [0; 32]
            && self.durable_read_set_digest != [0; 32]
    }
}

#[cfg(not(test))]
enum TrustedRelationshipDecisionScope {
    Relationship {
        operation_scope: ProjectionOperationScope,
        scope: ProjectionScope,
    },
    Traffic(TrafficGraphScope),
}

/// Opaque post-lock clock authority for one exact transaction-bound business
/// read-set. It is deliberately non-Clone: callers cannot mint it from request
/// entry time or pair it with a caller-selected relationship/traffic scope.
#[cfg(not(test))]
pub(crate) struct TrustedRelationshipDecisionInstant {
    transaction_id: String,
    scope: TrustedRelationshipDecisionScope,
    authenticated_actor_digest: [u8; 32],
    durable_read_set_digest: [u8; 32],
    observed_at: DateTime<Utc>,
}

/// Opaque wall-clock observation captured only after network collection. This
/// clock is used solely to fence persistence and cannot substitute for request
/// entry time or the post-lock decision instant above.
#[cfg(not(test))]
pub(crate) struct TrustedRelationshipPersistenceInstant(DateTime<Utc>);

#[cfg(not(test))]
impl TrustedRelationshipPersistenceInstant {
    pub(crate) fn datetime(&self) -> DateTime<Utc> {
        self.0
    }
}

#[cfg(not(test))]
impl TrustedRelationshipDecisionInstant {
    fn from_locked_relationship_scope(
        transaction_id: String,
        operation_scope: ProjectionOperationScope,
        scope: ProjectionScope,
        authenticated_actor_digest: [u8; 32],
        durable_read_set_digest: [u8; 32],
        observed_at: DateTime<Utc>,
    ) -> Option<Self> {
        if !canonical_transaction_id(&transaction_id)
            || authenticated_actor_digest == [0; 32]
            || durable_read_set_digest == [0; 32]
            || !relationship_operation_matches_scope(operation_scope, &scope)
        {
            return None;
        }
        Some(Self {
            transaction_id,
            scope: TrustedRelationshipDecisionScope::Relationship {
                operation_scope,
                scope,
            },
            authenticated_actor_digest,
            durable_read_set_digest,
            observed_at,
        })
    }

    fn from_locked_traffic_scope(
        transaction_id: String,
        scope: TrafficGraphScope,
        authenticated_actor_digest: [u8; 32],
        durable_read_set_digest: [u8; 32],
        observed_at: DateTime<Utc>,
    ) -> Option<Self> {
        if !canonical_transaction_id(&transaction_id)
            || authenticated_actor_digest == [0; 32]
            || durable_read_set_digest == [0; 32]
            || plan_traffic_graph(&scope.actor, &scope.members).is_err()
        {
            return None;
        }
        Some(Self {
            transaction_id,
            scope: TrustedRelationshipDecisionScope::Traffic(scope),
            authenticated_actor_digest,
            durable_read_set_digest,
            observed_at,
        })
    }

    pub(crate) fn relationship_scope_matches(
        &self,
        operation_scope: ProjectionOperationScope,
        scope: &ProjectionScope,
    ) -> bool {
        self.binding_is_valid()
            && matches!(
                &self.scope,
                TrustedRelationshipDecisionScope::Relationship {
                    operation_scope: actual_operation_scope,
                    scope: actual_scope,
                } if *actual_operation_scope == operation_scope && actual_scope == scope
            )
    }

    pub(crate) fn traffic_scope(&self) -> Option<&TrafficGraphScope> {
        if !self.binding_is_valid() {
            return None;
        }
        match &self.scope {
            TrustedRelationshipDecisionScope::Traffic(scope) => Some(scope),
            TrustedRelationshipDecisionScope::Relationship { .. } => None,
        }
    }

    pub(crate) fn traffic_scope_matches(&self, scope: &TrafficGraphScope) -> bool {
        self.traffic_scope() == Some(scope)
    }

    pub(crate) fn datetime(&self) -> DateTime<Utc> {
        self.observed_at
    }

    fn binding_is_valid(&self) -> bool {
        canonical_transaction_id(&self.transaction_id)
            && self.authenticated_actor_digest != [0; 32]
            && self.durable_read_set_digest != [0; 32]
    }
}

/// Capture persistence time after collection. Export rejects observations
/// before `completed_at`, so capturing this before collection cannot authorize
/// a projection that finishes later.
#[cfg(not(test))]
pub(crate) fn observe_relationship_persistence() -> TrustedRelationshipPersistenceInstant {
    TrustedRelationshipPersistenceInstant(Utc::now())
}

/// Load the production relationship authority. This intentionally accepts no
/// arguments: changing the AppView, PLC directory, or transport profile is a
/// startup/configuration code change that must pass the authority validation
/// suite, not a request- or repository-call choice.
pub(crate) fn load_fixed_relationship_authority_startup_guard(
) -> Result<RelationshipAuthorityStartupGuard, RelationshipAuthorityStartupError> {
    let config = fixed_production_relationship_policy_config()
        .map_err(RelationshipAuthorityStartupError::InvalidConfiguration)?;
    let transport = ReqwestPinnedTransport::new(SystemDnsResolver, config.max_dns_answers())
        .map_err(RelationshipAuthorityStartupError::InvalidTransport)?;
    if ReqwestPinnedTransport::<SystemDnsResolver>::security_profile()
        != (TransportSecurityProfile {
            no_proxy: true,
            reject_redirects: true,
            dns_pinned: true,
            public_only: true,
            credential_free: true,
        })
    {
        return Err(RelationshipAuthorityStartupError::InsecureTransportProfile);
    }
    Ok(RelationshipAuthorityStartupGuard { config, transport })
}

impl RelationshipAuthorityStartupGuard {
    pub(crate) fn into_parts(
        self,
    ) -> (
        RelationshipPolicyConfig,
        ReqwestPinnedTransport<SystemDnsResolver>,
    ) {
        (self.config, self.transport)
    }
}

#[cfg(not(test))]
impl RelationshipProjectionLoadGuard {
    pub(crate) fn into_parts(self) -> (ProjectionOperationScope, ProjectionScope) {
        (self.operation_scope, self.scope)
    }
}

#[cfg(not(test))]
impl TrafficProjectionLoadGuard {
    pub(crate) fn into_scope(self) -> TrafficGraphScope {
        self.scope
    }
}

impl LockedRelationshipFallbackScope {
    fn from_locked_read_set(
        transaction_id: String,
        operation_scope: ProjectionOperationScope,
        scope: ProjectionScope,
        authenticated_actor_digest: [u8; 32],
        durable_read_set_digest: [u8; 32],
    ) -> Result<Self, RelationshipRepositoryError> {
        if !canonical_transaction_id(&transaction_id)
            || authenticated_actor_digest == [0; 32]
            || durable_read_set_digest == [0; 32]
            || !relationship_operation_matches_scope(operation_scope, &scope)
        {
            return Err(RelationshipRepositoryError::InvalidProjection);
        }
        Ok(Self {
            transaction_id,
            operation_scope,
            scope,
            authenticated_actor_digest,
            durable_read_set_digest,
        })
    }

    fn into_parts(
        self,
    ) -> (
        String,
        ProjectionOperationScope,
        ProjectionScope,
        [u8; 32],
        [u8; 32],
    ) {
        (
            self.transaction_id,
            self.operation_scope,
            self.scope,
            self.authenticated_actor_digest,
            self.durable_read_set_digest,
        )
    }

    #[cfg(test)]
    pub(crate) fn from_locked_read_set_for_test(
        transaction_id: String,
        operation_scope: ProjectionOperationScope,
        scope: ProjectionScope,
        durable_read_set_digest: [u8; 32],
    ) -> Self {
        Self::from_locked_read_set(
            transaction_id,
            operation_scope,
            scope,
            [0xA1; 32],
            durable_read_set_digest,
        )
        .expect("valid test relationship read-set witness")
    }

    #[cfg(test)]
    pub(crate) fn parts_for_test(
        &self,
    ) -> (
        &str,
        ProjectionOperationScope,
        &ProjectionScope,
        &[u8; 32],
        &[u8; 32],
    ) {
        (
            &self.transaction_id,
            self.operation_scope,
            &self.scope,
            &self.authenticated_actor_digest,
            &self.durable_read_set_digest,
        )
    }
}

impl LockedTrafficFallbackScope {
    fn from_locked_read_set(
        transaction_id: String,
        scope: TrafficGraphScope,
        authenticated_actor_digest: [u8; 32],
        durable_read_set_digest: [u8; 32],
    ) -> Result<Self, RelationshipRepositoryError> {
        if !canonical_transaction_id(&transaction_id)
            || authenticated_actor_digest == [0; 32]
            || durable_read_set_digest == [0; 32]
            || traffic_scope_digest(&scope) == [0; 32]
        {
            return Err(RelationshipRepositoryError::InvalidProjection);
        }
        Ok(Self {
            transaction_id,
            scope,
            authenticated_actor_digest,
            durable_read_set_digest,
        })
    }

    fn into_parts(self) -> (String, TrafficGraphScope, [u8; 32], [u8; 32]) {
        (
            self.transaction_id,
            self.scope,
            self.authenticated_actor_digest,
            self.durable_read_set_digest,
        )
    }

    #[cfg(test)]
    pub(crate) fn from_locked_read_set_for_test(
        transaction_id: String,
        scope: TrafficGraphScope,
        durable_read_set_digest: [u8; 32],
    ) -> Self {
        Self::from_locked_read_set(transaction_id, scope, [0xA2; 32], durable_read_set_digest)
            .expect("valid test traffic read-set witness")
    }

    #[cfg(test)]
    pub(crate) fn parts_for_test(&self) -> (&str, &TrafficGraphScope, &[u8; 32], &[u8; 32]) {
        (
            &self.transaction_id,
            &self.scope,
            &self.authenticated_actor_digest,
            &self.durable_read_set_digest,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn no_pending_admission_digest(
    transaction_id: &str,
    operation_scope: ProjectionOperationScope,
    conversation_id: &[u8; 16],
    inviter_did: &str,
    head_digest: &[u8; 32],
    graph_digest: Option<&[u8; 32]>,
    quota_digest: &[u8; 32],
    registration_digest: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-NO-PENDING-ADMISSION\0");
    digest.update((transaction_id.len() as u64).to_be_bytes());
    digest.update(transaction_id.as_bytes());
    digest.update([match operation_scope {
        ProjectionOperationScope::Creation => 0,
        ProjectionOperationScope::PendingAdd => 1,
        _ => u8::MAX,
    }]);
    digest.update(conversation_id);
    digest.update((inviter_did.len() as u64).to_be_bytes());
    digest.update(inviter_did.as_bytes());
    digest.update(head_digest);
    match graph_digest {
        Some(value) => {
            digest.update([1]);
            digest.update(value);
        }
        None => digest.update([0]),
    }
    digest.update(quota_digest);
    digest.update(registration_digest);
    digest.finalize().into()
}

pub(crate) fn seal_group_creation_no_pending_admission(
    head: &LockedConversationHeadGuard,
    quota: &LockedInvitationQuotaGuard,
    registration: &LockedRegistrationProjection,
) -> Result<LockedNoPendingAdmissionGuard, RelationshipRepositoryError> {
    if head.prior_coordinate().is_some()
        || head.next_entry_seq() != 1
        || head.transaction_id() != quota.transaction_id()
        || !quota.new_recipient_dids().is_empty()
        || head.durable_row_digest() == &[0; 32]
        || quota.durable_row_digest() == &[0; 32]
    {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let inviter_did = authenticated_registration_actor(
        registration,
        head.transaction_id(),
        head.conversation_id().as_bytes(),
    )?;
    if inviter_did != quota.inviter_did() {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let operation_scope = ProjectionOperationScope::Creation;
    let conversation_id = *head.conversation_id().as_bytes();
    let head_digest = *head.durable_row_digest();
    let quota_digest = *quota.durable_row_digest();
    let registration_digest = *registration.durable_row_digest();
    let durable_read_set_digest = no_pending_admission_digest(
        head.transaction_id(),
        operation_scope,
        &conversation_id,
        &inviter_did,
        &head_digest,
        None,
        &quota_digest,
        &registration_digest,
    );
    let guard = LockedNoPendingAdmissionGuard {
        transaction_id: head.transaction_id().to_owned(),
        operation_scope,
        conversation_id,
        inviter_did,
        head_digest,
        graph_digest: None,
        quota_digest,
        registration_digest,
        durable_read_set_digest,
    };
    if !guard.authorizes_creation(head, quota, registration) {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    Ok(guard)
}

pub(crate) fn seal_non_add_policy_no_pending_admission(
    locked: &LockedConversationStateGuard,
    quota: &LockedInvitationQuotaGuard,
    registration: &LockedRegistrationProjection,
) -> Result<LockedNoPendingAdmissionGuard, RelationshipRepositoryError> {
    let head = locked.head();
    if head.transaction_id() != quota.transaction_id()
        || !quota.new_recipient_dids().is_empty()
        || head.durable_row_digest() == &[0; 32]
        || locked.locked_graph_digest() == &[0; 32]
        || quota.durable_row_digest() == &[0; 32]
    {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let inviter_did = authenticated_registration_actor(
        registration,
        head.transaction_id(),
        locked.state().coordinate().conversation_id(),
    )?;
    if inviter_did != quota.inviter_did() || !locked_state_has_active_member(locked, &inviter_did)?
    {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let operation_scope = ProjectionOperationScope::PendingAdd;
    let conversation_id = *head.conversation_id().as_bytes();
    let head_digest = *head.durable_row_digest();
    let graph_digest = Some(*locked.locked_graph_digest());
    let quota_digest = *quota.durable_row_digest();
    let registration_digest = *registration.durable_row_digest();
    let durable_read_set_digest = no_pending_admission_digest(
        head.transaction_id(),
        operation_scope,
        &conversation_id,
        &inviter_did,
        &head_digest,
        graph_digest.as_ref(),
        &quota_digest,
        &registration_digest,
    );
    let guard = LockedNoPendingAdmissionGuard {
        transaction_id: head.transaction_id().to_owned(),
        operation_scope,
        conversation_id,
        inviter_did,
        head_digest,
        graph_digest,
        quota_digest,
        registration_digest,
        durable_read_set_digest,
    };
    if !guard.authorizes_non_add_policy(locked, quota, registration) {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    Ok(guard)
}

pub(crate) fn seal_group_creation_fallback_scope(
    head: &LockedConversationHeadGuard,
    quota: &LockedInvitationQuotaGuard,
    registration: &LockedRegistrationProjection,
) -> Result<LockedRelationshipFallbackScope, RelationshipRepositoryError> {
    seal_creation_fallback_scope(head, quota, registration, AdmissionOperation::Group, None)
}

pub(crate) fn seal_direct_creation_fallback_scope(
    head: &LockedConversationHeadGuard,
    quota: &LockedInvitationQuotaGuard,
    direct_lookup: &LockedDirectConversationLookupGuard,
    registration: &LockedRegistrationProjection,
) -> Result<LockedRelationshipFallbackScope, RelationshipRepositoryError> {
    seal_creation_fallback_scope(
        head,
        quota,
        registration,
        AdmissionOperation::Direct,
        Some(direct_lookup),
    )
}

fn seal_creation_fallback_scope(
    head: &LockedConversationHeadGuard,
    quota: &LockedInvitationQuotaGuard,
    registration: &LockedRegistrationProjection,
    operation: AdmissionOperation,
    direct_lookup: Option<&LockedDirectConversationLookupGuard>,
) -> Result<LockedRelationshipFallbackScope, RelationshipRepositoryError> {
    if head.prior_coordinate().is_some()
        || head.next_entry_seq() != 1
        || head.transaction_id() != quota.transaction_id()
        || head.durable_row_digest() == &[0; 32]
        || quota.durable_row_digest() == &[0; 32]
    {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let authenticated_actor = authenticated_registration_actor(
        registration,
        head.transaction_id(),
        head.conversation_id().as_bytes(),
    )?;
    if authenticated_actor != quota.inviter_did() {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let mut roster = quota.new_recipient_dids().to_vec();
    if roster.iter().any(|did| did == quota.inviter_did()) {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    roster.push(quota.inviter_did().to_owned());
    roster.sort();
    if roster.windows(2).any(|pair| pair[0] == pair[1])
        || (operation == AdmissionOperation::Direct && roster.len() != 2)
        || (operation == AdmissionOperation::Group && roster.len() < 2)
    {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    if operation == AdmissionOperation::Direct {
        let lookup = direct_lookup.ok_or(RelationshipRepositoryError::InvalidProjection)?;
        if lookup.transaction_id() != head.transaction_id()
            || lookup.did_low() != roster[0]
            || lookup.did_high() != roster[1]
            || !matches!(lookup.outcome(), LockedDirectLookupOutcome::Absent)
            || lookup.durable_row_digest() == &[0; 32]
        {
            return Err(RelationshipRepositoryError::InvalidProjection);
        }
    } else if direct_lookup.is_some() {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let scope = ProjectionScope::Admission(super::super::relationship_policy::AdmissionRequest {
        inviter: quota.inviter_did().to_owned(),
        roster,
        pending_recipients: quota.new_recipient_dids().to_vec(),
        operation,
    });
    let mut durable_row_digests = vec![
        head.durable_row_digest(),
        quota.durable_row_digest(),
        registration.durable_row_digest(),
    ];
    if let Some(direct_lookup) = direct_lookup {
        durable_row_digests.push(direct_lookup.durable_row_digest());
    }
    let durable_read_set_digest = locked_scope_witness_digest(
        b"creation",
        head.transaction_id(),
        &relationship_scope_digest(&scope),
        &durable_row_digests,
    );
    LockedRelationshipFallbackScope::from_locked_read_set(
        head.transaction_id().to_owned(),
        ProjectionOperationScope::Creation,
        scope,
        *registration.durable_row_digest(),
        durable_read_set_digest,
    )
}

pub(crate) fn seal_pending_add_fallback_scope(
    locked: &LockedConversationStateGuard,
    quota: &LockedInvitationQuotaGuard,
    registration: &LockedRegistrationProjection,
) -> Result<LockedRelationshipFallbackScope, RelationshipRepositoryError> {
    let head = locked.head();
    if head.transaction_id() != quota.transaction_id()
        || head.durable_row_digest() == &[0; 32]
        || locked.locked_graph_digest() == &[0; 32]
        || quota.durable_row_digest() == &[0; 32]
    {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let authenticated_actor = authenticated_registration_actor(
        registration,
        head.transaction_id(),
        locked.state().coordinate().conversation_id(),
    )?;
    if authenticated_actor != quota.inviter_did() {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let mut roster = locked_state_roster(locked, false)?;
    if quota
        .new_recipient_dids()
        .iter()
        .any(|did| roster.binary_search(did).is_ok())
        || !locked_state_has_active_member(locked, quota.inviter_did())?
    {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    roster.extend_from_slice(quota.new_recipient_dids());
    roster.sort();
    let scope = ProjectionScope::Admission(super::super::relationship_policy::AdmissionRequest {
        inviter: quota.inviter_did().to_owned(),
        roster,
        pending_recipients: quota.new_recipient_dids().to_vec(),
        operation: AdmissionOperation::Group,
    });
    let durable_read_set_digest = locked_scope_witness_digest(
        b"pending-add",
        head.transaction_id(),
        &relationship_scope_digest(&scope),
        &[
            head.durable_row_digest(),
            locked.locked_graph_digest(),
            quota.durable_row_digest(),
            registration.durable_row_digest(),
        ],
    );
    LockedRelationshipFallbackScope::from_locked_read_set(
        head.transaction_id().to_owned(),
        ProjectionOperationScope::PendingAdd,
        scope,
        *registration.durable_row_digest(),
        durable_read_set_digest,
    )
}

pub(crate) fn seal_acceptance_fallback_scope(
    locked: &LockedConversationStateGuard,
    registration: &LockedRegistrationProjection,
) -> Result<LockedRelationshipFallbackScope, RelationshipRepositoryError> {
    let head = locked.head();
    let accepting_principal = authenticated_registration_actor(
        registration,
        head.transaction_id(),
        locked.state().coordinate().conversation_id(),
    )?;
    let accepting_participant = locked
        .state()
        .participant(registration.actor().principal())
        .filter(|participant| participant.status() == ParticipantStatus::Pending)
        .ok_or(RelationshipRepositoryError::InvalidProjection)?;
    let inviter = accepting_participant
        .invitation_inviter()
        .ok_or(RelationshipRepositoryError::InvalidProjection)?;
    let inviter = String::from_utf8(inviter.principal().as_bytes().to_vec())
        .map_err(|_| RelationshipRepositoryError::InvalidProjection)?;
    if !locked_state_has_active_member(locked, &inviter)? {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let operation = match locked.state().kind() {
        ConversationKind::Direct => AdmissionOperation::Direct,
        ConversationKind::Group => AdmissionOperation::Group,
    };
    let scope = ProjectionScope::Admission(super::super::relationship_policy::AdmissionRequest {
        inviter,
        roster: locked_state_roster(locked, false)?,
        pending_recipients: vec![accepting_principal],
        operation,
    });
    seal_locked_conversation_relationship_scope(
        locked,
        ProjectionOperationScope::Acceptance,
        scope,
        b"acceptance",
        *registration.durable_row_digest(),
        &[registration.durable_row_digest()],
    )
}

pub(crate) fn seal_recovery_fallback_scope(
    locked: &LockedConversationStateGuard,
    registration: &LockedRegistrationProjection,
    operation_scope: ProjectionOperationScope,
) -> Result<LockedRelationshipFallbackScope, RelationshipRepositoryError> {
    if !matches!(
        operation_scope,
        ProjectionOperationScope::RecoveryReservation
            | ProjectionOperationScope::RecoveryFulfillment
    ) {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let authenticated_actor = authenticated_registration_actor(
        registration,
        locked.head().transaction_id(),
        locked.state().coordinate().conversation_id(),
    )?;
    if !locked_state_has_active_member(locked, &authenticated_actor)? {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let roster = locked_state_roster(locked, false)?;
    let scope = ProjectionScope::BlockOnly(
        plan_block_only_graph(&roster)
            .map_err(|_| RelationshipRepositoryError::InvalidProjection)?
            .scope,
    );
    seal_locked_conversation_relationship_scope(
        locked,
        operation_scope,
        scope,
        b"recovery",
        *registration.durable_row_digest(),
        &[registration.durable_row_digest()],
    )
}

fn seal_locked_conversation_relationship_scope(
    locked: &LockedConversationStateGuard,
    operation_scope: ProjectionOperationScope,
    scope: ProjectionScope,
    domain: &[u8],
    authenticated_actor_digest: [u8; 32],
    additional_row_digests: &[&[u8; 32]],
) -> Result<LockedRelationshipFallbackScope, RelationshipRepositoryError> {
    let head = locked.head();
    if head.durable_row_digest() == &[0; 32] || locked.locked_graph_digest() == &[0; 32] {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let mut durable_row_digests = vec![head.durable_row_digest(), locked.locked_graph_digest()];
    durable_row_digests.extend_from_slice(additional_row_digests);
    let durable_read_set_digest = locked_scope_witness_digest(
        domain,
        head.transaction_id(),
        &relationship_scope_digest(&scope),
        &durable_row_digests,
    );
    LockedRelationshipFallbackScope::from_locked_read_set(
        head.transaction_id().to_owned(),
        operation_scope,
        scope,
        authenticated_actor_digest,
        durable_read_set_digest,
    )
}

pub(crate) fn seal_traffic_fallback_scope(
    locked: &LockedConversationStateGuard,
    registration: &LockedRegistrationProjection,
) -> Result<LockedTrafficFallbackScope, RelationshipRepositoryError> {
    let head = locked.head();
    if head.durable_row_digest() == &[0; 32] || locked.locked_graph_digest() == &[0; 32] {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let actor = authenticated_registration_actor(
        registration,
        head.transaction_id(),
        locked.state().coordinate().conversation_id(),
    )?;
    if !locked_state_has_active_member(locked, &actor)? {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let scope = TrafficGraphScope {
        actor,
        members: locked_state_roster(locked, true)?,
    };
    let durable_read_set_digest = locked_scope_witness_digest(
        b"traffic",
        head.transaction_id(),
        &traffic_scope_digest(&scope),
        &[
            head.durable_row_digest(),
            locked.locked_graph_digest(),
            registration.durable_row_digest(),
        ],
    );
    LockedTrafficFallbackScope::from_locked_read_set(
        head.transaction_id().to_owned(),
        scope,
        *registration.durable_row_digest(),
        durable_read_set_digest,
    )
}

fn authenticated_registration_actor(
    registration: &LockedRegistrationProjection,
    expected_transaction_id: &str,
    expected_conversation_id: &[u8; 16],
) -> Result<String, RelationshipRepositoryError> {
    if registration.transaction_id() != expected_transaction_id
        || registration.conversation_id() != expected_conversation_id
        || registration.status() != PersistedRegistrationStatus::Active
        || registration.durable_row_digest() == &[0; 32]
    {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    String::from_utf8(registration.actor().principal().as_bytes().to_vec())
        .map_err(|_| RelationshipRepositoryError::InvalidProjection)
}

fn locked_state_roster(
    locked: &LockedConversationStateGuard,
    active_only: bool,
) -> Result<Vec<String>, RelationshipRepositoryError> {
    let mut roster = locked
        .state()
        .participants()
        .iter()
        .filter(|participant| !active_only || participant.status() == ParticipantStatus::Active)
        .map(|participant| {
            String::from_utf8(participant.principal().as_bytes().to_vec())
                .map_err(|_| RelationshipRepositoryError::InvalidProjection)
        })
        .collect::<Result<Vec<_>, _>>()?;
    roster.sort();
    if roster.is_empty() || roster.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    Ok(roster)
}

fn locked_state_has_active_member(
    locked: &LockedConversationStateGuard,
    did: &str,
) -> Result<bool, RelationshipRepositoryError> {
    locked_state_has_member_with_status(locked, did, ParticipantStatus::Active)
}

fn locked_state_has_member_with_status(
    locked: &LockedConversationStateGuard,
    did: &str,
    status: ParticipantStatus,
) -> Result<bool, RelationshipRepositoryError> {
    for participant in locked.state().participants() {
        let participant_did = String::from_utf8(participant.principal().as_bytes().to_vec())
            .map_err(|_| RelationshipRepositoryError::InvalidProjection)?;
        if participant_did == did {
            return Ok(participant.status() == status);
        }
    }
    Ok(false)
}

fn locked_scope_witness_digest(
    domain: &[u8],
    transaction_id: &str,
    scope_digest: &[u8; 32],
    durable_row_digests: &[&[u8; 32]],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-LOCKED-RELATIONSHIP-SCOPE\0");
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest.update((transaction_id.len() as u64).to_be_bytes());
    digest.update(transaction_id.as_bytes());
    digest.update(scope_digest);
    for row_digest in durable_row_digests {
        digest.update(*row_digest);
    }
    digest.finalize().into()
}

#[derive(Debug, FromRow)]
struct SnapshotRow {
    projection_id: Uuid,
    projection_revision: i64,
    operation_scope: String,
    canonical_did_set_bytes: Vec<u8>,
    canonical_did_set_sha256: Vec<u8>,
    scope_digest: Vec<u8>,
    appview_base: String,
    configuration_fingerprint: Vec<u8>,
    aggregate_evidence_bytes: Vec<u8>,
    aggregate_evidence_sha256: Vec<u8>,
    source_call_count: i64,
    evidence_kind: String,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct DeclarationRow {
    projection_id: Uuid,
    recipient_did: String,
    resolved_pds_origin: String,
    service_id: String,
    fetch_revision: i64,
    did_request_digest: Vec<u8>,
    did_document_digest: Vec<u8>,
    record_request_digest: Vec<u8>,
    record_response_digest: Vec<u8>,
    record_cid: Option<String>,
    record_evidence_kind: String,
    incoming_policy: String,
    allow_group_invites: Option<String>,
    resolved_group_policy: String,
    evidence_kind: String,
    fetched_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct RelationshipRow {
    projection_id: Uuid,
    actor_did: String,
    other_did: String,
    blocking: bool,
    blocked_by: bool,
    blocking_by_list: bool,
    blocked_by_list: bool,
    following: bool,
    followed_by: bool,
    batch_ordinal: i64,
    fetch_revision: i64,
    request_digest: Vec<u8>,
    response_digest: Vec<u8>,
    evidence_kind: String,
    fetched_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct ProjectionAllocationRow {
    allocation_id: Uuid,
    projection_revision: i64,
}

/// Allocate exactly one non-reusable projection revision from PostgreSQL.
/// Sequence values intentionally survive transaction rollback.
pub(crate) async fn allocate_projection_revision(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<AllocatedProjectionRevisionGuard, RelationshipRepositoryError> {
    let allocation = sqlx::query_as::<_, ProjectionAllocationRow>(
        "SELECT allocation_id, projection_revision FROM chat.allocate_relationship_projection_revision()",
    )
    .fetch_one(&mut **transaction)
    .await?;
    AllocatedProjectionRevisionGuard::from_database_allocation(
        allocation.allocation_id,
        allocation.projection_revision,
    )
    .ok_or(RelationshipRepositoryError::InvalidProjection)
}

/// Insert a sealed relationship projection and all of its evidence into the
/// caller-owned transaction. Deferred cross-row constraints are forced before
/// returning, so callers never receive a false success for an incomplete set.
pub(crate) async fn persist_relationship_projection(
    transaction: &mut Transaction<'_, Postgres>,
    projection: SealedRelationshipProjection,
) -> Result<(), RelationshipRepositoryError> {
    let (allocation_id, projection) = projection.into_parts();
    validate_relationship_projection_for_insert(&projection)?;
    let projection_id = parse_projection_id(&projection.projection_id)?;
    insert_snapshot(
        transaction,
        projection_id,
        allocation_id,
        projection.projection_revision,
        projection.operation_scope,
        &projection.canonical_did_set_bytes,
        &projection.canonical_did_set_sha256,
        &projection.scope_digest,
        &projection.appview_base,
        &projection.configuration_fingerprint,
        &projection.aggregate_evidence_bytes,
        &projection.aggregate_evidence_sha256,
        projection.source_call_count,
        projection.evidence_kind,
        projection.started_at,
        projection.completed_at,
    )
    .await?;
    insert_declarations(transaction, projection_id, &projection.declarations).await?;
    insert_relationships(transaction, projection_id, &projection.relationships).await?;
    force_projection_constraints(transaction).await
}

/// Insert a sealed traffic projection and every graph evidence row into the
/// caller-owned transaction.
pub(crate) async fn persist_traffic_projection(
    transaction: &mut Transaction<'_, Postgres>,
    projection: SealedTrafficProjection,
) -> Result<(), RelationshipRepositoryError> {
    let (allocation_id, projection) = projection.into_parts();
    validate_traffic_projection_for_insert(&projection)?;
    let projection_id = parse_projection_id(&projection.projection_id)?;
    insert_snapshot(
        transaction,
        projection_id,
        allocation_id,
        projection.projection_revision,
        projection.operation_scope,
        &projection.canonical_did_set_bytes,
        &projection.canonical_did_set_sha256,
        &projection.scope_digest,
        &projection.appview_base,
        &projection.configuration_fingerprint,
        &projection.aggregate_evidence_bytes,
        &projection.aggregate_evidence_sha256,
        projection.source_call_count,
        projection.evidence_kind,
        projection.started_at,
        projection.completed_at,
    )
    .await?;
    insert_relationships(transaction, projection_id, &projection.relationships).await?;
    force_projection_constraints(transaction).await
}

/// Mint the post-lock decision clock from one exact relationship scope. The
/// scope witness is consumed, the PostgreSQL transaction identity is checked,
/// and `clock_timestamp()` is sampled only after the caller's business locks.
pub(crate) async fn observe_locked_relationship_decision(
    transaction: &mut Transaction<'_, Postgres>,
    locked_scope: LockedRelationshipFallbackScope,
) -> Result<LockedRelationshipDecisionGuard, RelationshipRepositoryError> {
    let (
        transaction_id,
        operation_scope,
        scope,
        authenticated_actor_digest,
        durable_read_set_digest,
    ) = locked_scope.into_parts();
    require_witness_transaction(transaction, &transaction_id).await?;
    let observed_at = observe_post_lock_time(transaction).await?;
    let decision = TrustedRelationshipDecisionInstant::from_locked_relationship_scope(
        transaction_id.clone(),
        operation_scope,
        scope.clone(),
        authenticated_actor_digest,
        durable_read_set_digest,
        observed_at,
    )
    .ok_or(RelationshipRepositoryError::InvalidProjection)?;
    Ok(LockedRelationshipDecisionGuard {
        transaction_id,
        operation_scope,
        scope,
        authenticated_actor_digest,
        durable_read_set_digest,
        decision,
    })
}

/// Traffic equivalent of `observe_locked_relationship_decision`.
pub(crate) async fn observe_locked_traffic_decision(
    transaction: &mut Transaction<'_, Postgres>,
    locked_scope: LockedTrafficFallbackScope,
) -> Result<LockedTrafficDecisionGuard, RelationshipRepositoryError> {
    let (transaction_id, scope, authenticated_actor_digest, durable_read_set_digest) =
        locked_scope.into_parts();
    require_witness_transaction(transaction, &transaction_id).await?;
    let observed_at = observe_post_lock_time(transaction).await?;
    let decision = TrustedRelationshipDecisionInstant::from_locked_traffic_scope(
        transaction_id.clone(),
        scope.clone(),
        authenticated_actor_digest,
        durable_read_set_digest,
        observed_at,
    )
    .ok_or(RelationshipRepositoryError::InvalidProjection)?;
    Ok(LockedTrafficDecisionGuard {
        transaction_id,
        scope,
        authenticated_actor_digest,
        durable_read_set_digest,
        decision,
    })
}

/// Load only fallback evidence for one exact operation and structural scope.
/// The snapshot and all child rows are locked in the caller-owned business
/// transaction. The repository mints and immediately consumes the load guard;
/// loose SQL rows or a caller-selected digest never cross the seam.
pub(crate) async fn load_fallback_relationship_projection<T: PublicTransport>(
    transaction: &mut Transaction<'_, Postgres>,
    locked_scope: LockedRelationshipFallbackScope,
    authority: &RelationshipAuthority<T>,
) -> Result<
    Option<(RelationshipProjection, LockedRelationshipDecisionGuard)>,
    RelationshipRepositoryError,
> {
    let (
        transaction_id,
        operation_scope,
        scope,
        authenticated_actor_digest,
        durable_read_set_digest,
    ) = locked_scope.into_parts();
    require_witness_transaction(transaction, &transaction_id).await?;
    if durable_read_set_digest == [0; 32] {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let scope_digest = relationship_scope_digest(&scope);
    let fingerprint = fixed_configuration_fingerprint()?;
    let (snapshot, declarations, relationships) = match lock_fallback_snapshot(
        transaction,
        operation_scope.as_persisted_str(),
        &scope_digest,
        &fingerprint,
    )
    .await? {
        Some(s) if observe_post_lock_time(transaction).await? - s.completed_at <= TimeDelta::seconds(60) => {
            let (decl, rel) = lock_projection_children(transaction, s.projection_id).await?;
            (s, decl, rel)
        }
        _ => {
            let live_allocation = allocate_projection_revision(transaction).await?;
            let fallback_allocation = allocate_projection_revision(transaction).await?;
            let live = match &scope {
                ProjectionScope::Admission(req) => {
                    authority
                        .collect_admission_projection(live_allocation, operation_scope, req.clone())
                        .await
                        .map_err(|_| RelationshipRepositoryError::InvalidProjection)?
                }
                ProjectionScope::BlockOnly(s) => {
                    authority
                        .collect_block_projection(live_allocation, operation_scope, s.members.clone())
                        .await
                        .map_err(|_| RelationshipRepositoryError::InvalidProjection)?
                }
            };
            let observation = observe_relationship_persistence();
            let sealed = live
                .export_persisted_fallback(fallback_allocation, authority, &observation)
                .map_err(|_| RelationshipRepositoryError::InvalidProjection)?;
            persist_relationship_projection(transaction, sealed).await?;
            let newly_locked = lock_fallback_snapshot(
                transaction,
                operation_scope.as_persisted_str(),
                &scope_digest,
                &fingerprint,
            )
            .await?
            .ok_or(RelationshipRepositoryError::InvalidProjection)?;
            let (decl, rel) = lock_projection_children(transaction, newly_locked.projection_id).await?;
            (newly_locked, decl, rel)
        }
    };
    let observed_at = observe_post_lock_time(transaction).await?;
    if observed_at < snapshot.completed_at {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let decision = TrustedRelationshipDecisionInstant::from_locked_relationship_scope(
        transaction_id.clone(),
        operation_scope,
        scope.clone(),
        authenticated_actor_digest,
        durable_read_set_digest,
        observed_at,
    )
    .ok_or(RelationshipRepositoryError::InvalidProjection)?;
    let values = relationship_values(snapshot, scope.clone(), declarations, relationships)?;
    let load_guard = relationship_load_guard(operation_scope, scope.clone());
    hydrate_persisted_fallback_relationship_projection(values, load_guard, authority, &decision)
        .map(|projection| {
            Some((
                projection,
                LockedRelationshipDecisionGuard {
                    transaction_id,
                    operation_scope,
                    scope,
                    authenticated_actor_digest,
                    durable_read_set_digest,
                    decision,
                },
            ))
        })
        .map_err(|_| RelationshipRepositoryError::InvalidProjection)
}

/// Traffic equivalent of `load_fallback_relationship_projection`.
pub(crate) async fn load_fallback_traffic_projection<T: PublicTransport>(
    transaction: &mut Transaction<'_, Postgres>,
    locked_scope: LockedTrafficFallbackScope,
    authority: &RelationshipAuthority<T>,
) -> Result<Option<(TrafficProjection, LockedTrafficDecisionGuard)>, RelationshipRepositoryError> {
    let (transaction_id, scope, authenticated_actor_digest, durable_read_set_digest) =
        locked_scope.into_parts();
    require_witness_transaction(transaction, &transaction_id).await?;
    if durable_read_set_digest == [0; 32] {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let scope_digest = traffic_scope_digest(&scope);
    let fingerprint = fixed_configuration_fingerprint()?;
    let Some(snapshot) = lock_fallback_snapshot(
        transaction,
        ProjectionOperationScope::Traffic.as_persisted_str(),
        &scope_digest,
        &fingerprint,
    )
    .await?
    else {
        return Ok(None);
    };
    let (declarations, relationships) =
        lock_projection_children(transaction, snapshot.projection_id).await?;
    if !declarations.is_empty() {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    let observed_at = observe_post_lock_time(transaction).await?;
    if observed_at < snapshot.completed_at {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    if observed_at - snapshot.completed_at > TimeDelta::seconds(60) {
        return Ok(None);
    }
    let decision = TrustedRelationshipDecisionInstant::from_locked_traffic_scope(
        transaction_id.clone(),
        scope.clone(),
        authenticated_actor_digest,
        durable_read_set_digest,
        observed_at,
    )
    .ok_or(RelationshipRepositoryError::InvalidProjection)?;
    let values = traffic_values(snapshot, scope.clone(), relationships)?;
    let load_guard = traffic_load_guard(scope.clone());
    hydrate_persisted_fallback_traffic_projection(values, load_guard, authority, &decision)
        .map(|projection| {
            Some((
                projection,
                LockedTrafficDecisionGuard {
                    transaction_id,
                    scope,
                    authenticated_actor_digest,
                    durable_read_set_digest,
                    decision,
                },
            ))
        })
        .map_err(|_| RelationshipRepositoryError::InvalidProjection)
}

fn consume_resealed_relationship_projection<T: PublicTransport>(
    projection: &RelationshipProjection,
    decision_guard: &LockedRelationshipDecisionGuard,
    current_scope: LockedRelationshipFallbackScope,
    expected_scope: &ProjectionScope,
    authority: &RelationshipAuthority<T>,
    quota_would_exceed: bool,
) -> Result<(), RelationshipConsumptionError> {
    if decision_guard.transaction_id != current_scope.transaction_id
        || decision_guard.operation_scope != current_scope.operation_scope
        || decision_guard.scope != current_scope.scope
        || decision_guard.authenticated_actor_digest != current_scope.authenticated_actor_digest
        || decision_guard.durable_read_set_digest != current_scope.durable_read_set_digest
        || &current_scope.scope != expected_scope
        || !decision_guard
            .decision
            .relationship_scope_matches(current_scope.operation_scope, &current_scope.scope)
    {
        return Err(RelationshipConsumptionError::InvalidWitness);
    }
    match &current_scope.scope {
        ProjectionScope::Admission(request) => consume_admission_projection(
            projection,
            current_scope.operation_scope,
            request,
            authority,
            &decision_guard.decision,
            quota_would_exceed,
        ),
        ProjectionScope::BlockOnly(scope) => consume_block_projection(
            projection,
            current_scope.operation_scope,
            &scope.members,
            authority,
            &decision_guard.decision,
        ),
    }
    .map_err(|_| RelationshipConsumptionError::PolicyDenied)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn consume_locked_creation_projection<T: PublicTransport>(
    projection: &RelationshipProjection,
    decision_guard: &LockedRelationshipDecisionGuard,
    head: &LockedConversationHeadGuard,
    quota: &LockedInvitationQuotaGuard,
    direct_lookup: Option<&LockedDirectConversationLookupGuard>,
    registration: &LockedRegistrationProjection,
    expected_request: &AdmissionRequest,
    quota_would_exceed: bool,
    authority: &RelationshipAuthority<T>,
) -> Result<(), RelationshipConsumptionError> {
    let current_scope = seal_creation_fallback_scope(
        head,
        quota,
        registration,
        expected_request.operation,
        direct_lookup,
    )
    .map_err(|_| RelationshipConsumptionError::InvalidWitness)?;
    consume_resealed_relationship_projection(
        projection,
        decision_guard,
        current_scope,
        &ProjectionScope::Admission(expected_request.clone()),
        authority,
        quota_would_exceed,
    )
}

pub(crate) fn consume_locked_pending_add_projection<T: PublicTransport>(
    projection: &RelationshipProjection,
    decision_guard: &LockedRelationshipDecisionGuard,
    locked: &LockedConversationStateGuard,
    quota: &LockedInvitationQuotaGuard,
    registration: &LockedRegistrationProjection,
    expected_request: &AdmissionRequest,
    quota_would_exceed: bool,
    authority: &RelationshipAuthority<T>,
) -> Result<(), RelationshipConsumptionError> {
    let current_scope = seal_pending_add_fallback_scope(locked, quota, registration)
        .map_err(|_| RelationshipConsumptionError::InvalidWitness)?;
    consume_resealed_relationship_projection(
        projection,
        decision_guard,
        current_scope,
        &ProjectionScope::Admission(expected_request.clone()),
        authority,
        quota_would_exceed,
    )
}

pub(crate) fn consume_locked_acceptance_projection<T: PublicTransport>(
    projection: &RelationshipProjection,
    decision_guard: &LockedRelationshipDecisionGuard,
    locked: &LockedConversationStateGuard,
    registration: &LockedRegistrationProjection,
    expected_request: &AdmissionRequest,
    authority: &RelationshipAuthority<T>,
) -> Result<(), RelationshipConsumptionError> {
    let current_scope = seal_acceptance_fallback_scope(locked, registration)
        .map_err(|_| RelationshipConsumptionError::InvalidWitness)?;
    consume_resealed_relationship_projection(
        projection,
        decision_guard,
        current_scope,
        &ProjectionScope::Admission(expected_request.clone()),
        authority,
        false,
    )
}

pub(crate) fn consume_locked_recovery_projection<T: PublicTransport>(
    projection: &RelationshipProjection,
    decision_guard: &LockedRelationshipDecisionGuard,
    locked: &LockedConversationStateGuard,
    registration: &LockedRegistrationProjection,
    operation_scope: ProjectionOperationScope,
    expected_roster: &[String],
    authority: &RelationshipAuthority<T>,
) -> Result<(), RelationshipConsumptionError> {
    let current_scope = seal_recovery_fallback_scope(locked, registration, operation_scope)
        .map_err(|_| RelationshipConsumptionError::InvalidWitness)?;
    consume_resealed_relationship_projection(
        projection,
        decision_guard,
        current_scope,
        &ProjectionScope::BlockOnly(
            plan_block_only_graph(expected_roster)
                .map_err(|_| RelationshipConsumptionError::InvalidWitness)?
                .scope,
        ),
        authority,
        false,
    )
}

pub(crate) fn consume_locked_traffic_projection<T: PublicTransport>(
    projection: &TrafficProjection,
    decision_guard: &LockedTrafficDecisionGuard,
    locked: &LockedConversationStateGuard,
    registration: &LockedRegistrationProjection,
    authority: &RelationshipAuthority<T>,
) -> Result<(), RelationshipConsumptionError> {
    let current_scope = seal_traffic_fallback_scope(locked, registration)
        .map_err(|_| RelationshipConsumptionError::InvalidWitness)?;
    if decision_guard.transaction_id != current_scope.transaction_id
        || decision_guard.scope != current_scope.scope
        || decision_guard.authenticated_actor_digest != current_scope.authenticated_actor_digest
        || decision_guard.durable_read_set_digest != current_scope.durable_read_set_digest
        || !decision_guard
            .decision
            .traffic_scope_matches(&current_scope.scope)
    {
        return Err(RelationshipConsumptionError::InvalidWitness);
    }
    consume_traffic_projection(projection, authority, &decision_guard.decision)
        .map_err(|_| RelationshipConsumptionError::PolicyDenied)
}

async fn require_witness_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    expected_transaction_id: &str,
) -> Result<(), RelationshipRepositoryError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if transaction_id != expected_transaction_id {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    Ok(())
}

async fn observe_post_lock_time(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<DateTime<Utc>, RelationshipRepositoryError> {
    Ok(sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **transaction)
        .await?)
}

#[allow(clippy::too_many_arguments)]
async fn insert_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    projection_id: Uuid,
    projection_allocation_id: Uuid,
    projection_revision: u64,
    operation_scope: ProjectionOperationScope,
    canonical_did_set_bytes: &[u8],
    canonical_did_set_sha256: &[u8; 32],
    scope_digest: &[u8; 32],
    appview_base: &str,
    configuration_fingerprint: &[u8; 32],
    aggregate_evidence_bytes: &[u8],
    aggregate_evidence_sha256: &[u8; 32],
    source_call_count: u64,
    evidence_kind: EvidenceKind,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
) -> Result<(), RelationshipRepositoryError> {
    sqlx::query(
        r#"
        INSERT INTO chat.relationship_projection_snapshots (
            projection_id, projection_allocation_id, projection_revision, operation_scope,
            canonical_did_set_bytes, canonical_did_set_sha256, scope_digest,
            appview_base, configuration_fingerprint, aggregate_evidence_bytes,
            aggregate_evidence_sha256, source_call_count, evidence_kind,
            started_at, completed_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
        "#,
    )
    .bind(projection_id)
    .bind(projection_allocation_id)
    .bind(to_i64(projection_revision)?)
    .bind(operation_scope.as_persisted_str())
    .bind(canonical_did_set_bytes)
    .bind(canonical_did_set_sha256.as_slice())
    .bind(scope_digest.as_slice())
    .bind(appview_base)
    .bind(configuration_fingerprint.as_slice())
    .bind(aggregate_evidence_bytes)
    .bind(aggregate_evidence_sha256.as_slice())
    .bind(to_i64(source_call_count)?)
    .bind(evidence_kind.as_persisted_str())
    .bind(started_at)
    .bind(completed_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_declarations(
    transaction: &mut Transaction<'_, Postgres>,
    projection_id: Uuid,
    declarations: &[PersistedDeclarationEvidence],
) -> Result<(), RelationshipRepositoryError> {
    for chunk in declarations.chunks(INSERT_CHUNK_ROWS) {
        let mut query = QueryBuilder::<Postgres>::new(
            r#"
            INSERT INTO chat.relationship_projection_declarations (
                projection_id, recipient_did, resolved_pds_origin, service_id,
                fetch_revision, did_request_digest, did_document_digest,
                record_request_digest, record_response_digest, record_cid,
                record_evidence_kind, incoming_policy, allow_group_invites,
                resolved_group_policy, evidence_kind, fetched_at
            )
            "#,
        );
        query.push_values(chunk, |mut values, row| {
            values
                .push_bind(projection_id)
                .push_bind(&row.recipient)
                .push_bind(&row.resolved_pds_origin)
                .push_bind(&row.service_id)
                .push_bind(i64::try_from(row.fetch_revision).expect("prevalidated revision"))
                .push_bind(row.did_request_digest.as_slice())
                .push_bind(row.did_document_digest.as_slice())
                .push_bind(row.record_request_digest.as_slice())
                .push_bind(row.record_response_digest.as_slice())
                .push_bind(row.cid.as_deref())
                .push_bind(row.record_evidence_kind.as_persisted_str())
                .push_bind(row.incoming.as_str())
                .push_bind(row.allow_group_invites.map(IncomingPolicy::as_str))
                .push_bind(row.resolved_group_policy.as_str())
                .push_bind(row.evidence_kind.as_persisted_str())
                .push_bind(row.fetched_at);
        });
        query.build().execute(&mut **transaction).await?;
    }
    Ok(())
}

async fn insert_relationships(
    transaction: &mut Transaction<'_, Postgres>,
    projection_id: Uuid,
    relationships: &[PersistedGraphRelationshipEvidence],
) -> Result<(), RelationshipRepositoryError> {
    for chunk in relationships.chunks(INSERT_CHUNK_ROWS) {
        let mut query = QueryBuilder::<Postgres>::new(
            r#"
            INSERT INTO chat.relationship_projection_relationships (
                projection_id, actor_did, other_did, blocking, blocked_by,
                blocking_by_list, blocked_by_list, following, followed_by,
                batch_ordinal, fetch_revision, request_digest, response_digest,
                evidence_kind, fetched_at
            )
            "#,
        );
        query.push_values(chunk, |mut values, row| {
            values
                .push_bind(projection_id)
                .push_bind(&row.actor)
                .push_bind(&row.target)
                .push_bind(row.blocking)
                .push_bind(row.blocked_by)
                .push_bind(row.blocking_by_list)
                .push_bind(row.blocked_by_list)
                .push_bind(row.following)
                .push_bind(row.followed_by)
                .push_bind(i64::from(row.batch_ordinal))
                .push_bind(i64::try_from(row.fetch_revision).expect("prevalidated revision"))
                .push_bind(row.request_digest.as_slice())
                .push_bind(row.response_digest.as_slice())
                .push_bind(row.evidence_kind.as_persisted_str())
                .push_bind(row.fetched_at);
        });
        query.build().execute(&mut **transaction).await?;
    }
    Ok(())
}

async fn force_projection_constraints(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), RelationshipRepositoryError> {
    sqlx::query(
        r#"
        SET CONSTRAINTS
            chat.relationship_projection_snapshots_complete_deferred,
            chat.relationship_projection_relationships_complete_deferred,
            chat.relationship_projection_declarations_complete_deferred
        IMMEDIATE
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        SET CONSTRAINTS
            chat.relationship_projection_snapshots_complete_deferred,
            chat.relationship_projection_relationships_complete_deferred,
            chat.relationship_projection_declarations_complete_deferred
        DEFERRED
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn lock_fallback_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    operation_scope: &str,
    scope_digest: &[u8; 32],
    configuration_fingerprint: &[u8; 32],
) -> Result<Option<SnapshotRow>, RelationshipRepositoryError> {
    Ok(sqlx::query_as::<_, SnapshotRow>(
        r#"
        SELECT projection_id, projection_revision, operation_scope,
               canonical_did_set_bytes, canonical_did_set_sha256, scope_digest,
               appview_base, configuration_fingerprint, aggregate_evidence_bytes,
               aggregate_evidence_sha256, source_call_count, evidence_kind,
               started_at, completed_at
          FROM chat.relationship_projection_snapshots
         WHERE operation_scope = $1
           AND scope_digest = $2
           AND evidence_kind = 'fallback'
           AND configuration_fingerprint = $3
         ORDER BY completed_at DESC, projection_revision DESC
         LIMIT 1
         FOR UPDATE
        "#,
    )
    .bind(operation_scope)
    .bind(scope_digest.as_slice())
    .bind(configuration_fingerprint.as_slice())
    .fetch_optional(&mut **transaction)
    .await?)
}

async fn lock_projection_children(
    transaction: &mut Transaction<'_, Postgres>,
    projection_id: Uuid,
) -> Result<(Vec<DeclarationRow>, Vec<RelationshipRow>), RelationshipRepositoryError> {
    let declarations = sqlx::query_as::<_, DeclarationRow>(
        r#"
        SELECT projection_id, recipient_did, resolved_pds_origin, service_id,
               fetch_revision, did_request_digest, did_document_digest,
               record_request_digest, record_response_digest, record_cid,
               record_evidence_kind, incoming_policy, allow_group_invites,
               resolved_group_policy, evidence_kind, fetched_at
          FROM chat.relationship_projection_declarations
         WHERE projection_id = $1
         FOR UPDATE
        "#,
    )
    .bind(projection_id)
    .fetch_all(&mut **transaction)
    .await?;
    let relationships = sqlx::query_as::<_, RelationshipRow>(
        r#"
        SELECT projection_id, actor_did, other_did, blocking, blocked_by,
               blocking_by_list, blocked_by_list, following, followed_by,
               batch_ordinal, fetch_revision, request_digest, response_digest,
               evidence_kind, fetched_at
          FROM chat.relationship_projection_relationships
         WHERE projection_id = $1
         FOR UPDATE
        "#,
    )
    .bind(projection_id)
    .fetch_all(&mut **transaction)
    .await?;
    Ok((declarations, relationships))
}

fn relationship_values(
    snapshot: SnapshotRow,
    scope: ProjectionScope,
    declarations: Vec<DeclarationRow>,
    relationships: Vec<RelationshipRow>,
) -> Result<PersistedRelationshipProjection, RelationshipRepositoryError> {
    let mut declarations = declarations
        .into_iter()
        .map(declaration_value)
        .collect::<Result<Vec<_>, _>>()?;
    declarations.sort_by(|left, right| left.recipient.cmp(&right.recipient));
    let mut relationships = relationships
        .into_iter()
        .map(relationship_value)
        .collect::<Result<Vec<_>, _>>()?;
    sort_relationship_values(&mut relationships);
    Ok(PersistedRelationshipProjection {
        projection_id: snapshot.projection_id.to_string(),
        operation_scope: ProjectionOperationScope::from_persisted_str(&snapshot.operation_scope)
            .map_err(|_| RelationshipRepositoryError::InvalidProjection)?,
        scope,
        scope_digest: bytes_32(snapshot.scope_digest)?,
        canonical_did_set_bytes: snapshot.canonical_did_set_bytes,
        canonical_did_set_sha256: bytes_32(snapshot.canonical_did_set_sha256)?,
        appview_base: snapshot.appview_base,
        configuration_fingerprint: bytes_32(snapshot.configuration_fingerprint)?,
        projection_revision: from_i64(snapshot.projection_revision)?,
        source_call_count: from_nonnegative_i64(snapshot.source_call_count)?,
        started_at: snapshot.started_at,
        completed_at: snapshot.completed_at,
        evidence_kind: EvidenceKind::from_persisted_str(&snapshot.evidence_kind)
            .map_err(|_| RelationshipRepositoryError::InvalidProjection)?,
        declarations,
        relationships,
        aggregate_evidence_bytes: snapshot.aggregate_evidence_bytes,
        aggregate_evidence_sha256: bytes_32(snapshot.aggregate_evidence_sha256)?,
    })
}

fn traffic_values(
    snapshot: SnapshotRow,
    scope: TrafficGraphScope,
    relationships: Vec<RelationshipRow>,
) -> Result<PersistedTrafficProjection, RelationshipRepositoryError> {
    let mut relationships = relationships
        .into_iter()
        .map(relationship_value)
        .collect::<Result<Vec<_>, _>>()?;
    sort_relationship_values(&mut relationships);
    Ok(PersistedTrafficProjection {
        projection_id: snapshot.projection_id.to_string(),
        operation_scope: ProjectionOperationScope::from_persisted_str(&snapshot.operation_scope)
            .map_err(|_| RelationshipRepositoryError::InvalidProjection)?,
        scope,
        scope_digest: bytes_32(snapshot.scope_digest)?,
        canonical_did_set_bytes: snapshot.canonical_did_set_bytes,
        canonical_did_set_sha256: bytes_32(snapshot.canonical_did_set_sha256)?,
        appview_base: snapshot.appview_base,
        configuration_fingerprint: bytes_32(snapshot.configuration_fingerprint)?,
        projection_revision: from_i64(snapshot.projection_revision)?,
        source_call_count: from_nonnegative_i64(snapshot.source_call_count)?,
        started_at: snapshot.started_at,
        completed_at: snapshot.completed_at,
        evidence_kind: EvidenceKind::from_persisted_str(&snapshot.evidence_kind)
            .map_err(|_| RelationshipRepositoryError::InvalidProjection)?,
        relationships,
        aggregate_evidence_bytes: snapshot.aggregate_evidence_bytes,
        aggregate_evidence_sha256: bytes_32(snapshot.aggregate_evidence_sha256)?,
    })
}

fn declaration_value(
    row: DeclarationRow,
) -> Result<PersistedDeclarationEvidence, RelationshipRepositoryError> {
    Ok(PersistedDeclarationEvidence {
        projection_id: row.projection_id.to_string(),
        recipient: row.recipient_did,
        incoming: incoming_policy(&row.incoming_policy)?,
        allow_group_invites: row
            .allow_group_invites
            .as_deref()
            .map(incoming_policy)
            .transpose()?,
        resolved_group_policy: incoming_policy(&row.resolved_group_policy)?,
        record_evidence_kind: DeclarationRecordEvidenceKind::from_persisted_str(
            &row.record_evidence_kind,
        )
        .map_err(|_| RelationshipRepositoryError::InvalidProjection)?,
        cid: row.record_cid,
        service_id: row.service_id,
        resolved_pds_origin: row.resolved_pds_origin,
        did_request_digest: bytes_32(row.did_request_digest)?,
        did_document_digest: bytes_32(row.did_document_digest)?,
        record_request_digest: bytes_32(row.record_request_digest)?,
        record_response_digest: bytes_32(row.record_response_digest)?,
        fetch_revision: from_i64(row.fetch_revision)?,
        fetched_at: row.fetched_at,
        evidence_kind: EvidenceKind::from_persisted_str(&row.evidence_kind)
            .map_err(|_| RelationshipRepositoryError::InvalidProjection)?,
    })
}

fn relationship_value(
    row: RelationshipRow,
) -> Result<PersistedGraphRelationshipEvidence, RelationshipRepositoryError> {
    Ok(PersistedGraphRelationshipEvidence {
        projection_id: row.projection_id.to_string(),
        actor: row.actor_did,
        target: row.other_did,
        batch_ordinal: u16::try_from(row.batch_ordinal)
            .map_err(|_| RelationshipRepositoryError::InvalidProjection)?,
        following: row.following,
        followed_by: row.followed_by,
        blocking: row.blocking,
        blocked_by: row.blocked_by,
        blocking_by_list: row.blocking_by_list,
        blocked_by_list: row.blocked_by_list,
        request_digest: bytes_32(row.request_digest)?,
        response_digest: bytes_32(row.response_digest)?,
        fetch_revision: from_i64(row.fetch_revision)?,
        fetched_at: row.fetched_at,
        evidence_kind: EvidenceKind::from_persisted_str(&row.evidence_kind)
            .map_err(|_| RelationshipRepositoryError::InvalidProjection)?,
    })
}

fn sort_relationship_values(values: &mut [PersistedGraphRelationshipEvidence]) {
    values.sort_by(|left, right| {
        (
            left.fetch_revision,
            left.batch_ordinal,
            &left.actor,
            &left.target,
        )
            .cmp(&(
                right.fetch_revision,
                right.batch_ordinal,
                &right.actor,
                &right.target,
            ))
    });
}

fn validate_relationship_projection_for_insert(
    projection: &PersistedRelationshipProjection,
) -> Result<(), RelationshipRepositoryError> {
    validate_snapshot_for_insert(
        &projection.projection_id,
        projection.projection_revision,
        projection.operation_scope,
        &projection.scope_digest,
        &relationship_scope_digest(&projection.scope),
        relationship_scope_dids(&projection.scope),
        &projection.canonical_did_set_bytes,
        &projection.canonical_did_set_sha256,
        &projection.appview_base,
        &projection.configuration_fingerprint,
        &projection.aggregate_evidence_bytes,
        &projection.aggregate_evidence_sha256,
        projection.source_call_count,
        projection.evidence_kind,
        projection.started_at,
        projection.completed_at,
    )?;
    if !relationship_operation_matches_scope(projection.operation_scope, &projection.scope) {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    validate_children(
        &projection.projection_id,
        projection.projection_revision,
        projection.evidence_kind,
        projection.source_call_count,
        &projection.declarations,
        &projection.relationships,
    )
}

fn validate_traffic_projection_for_insert(
    projection: &PersistedTrafficProjection,
) -> Result<(), RelationshipRepositoryError> {
    validate_snapshot_for_insert(
        &projection.projection_id,
        projection.projection_revision,
        projection.operation_scope,
        &projection.scope_digest,
        &traffic_scope_digest(&projection.scope),
        &projection.scope.members,
        &projection.canonical_did_set_bytes,
        &projection.canonical_did_set_sha256,
        &projection.appview_base,
        &projection.configuration_fingerprint,
        &projection.aggregate_evidence_bytes,
        &projection.aggregate_evidence_sha256,
        projection.source_call_count,
        projection.evidence_kind,
        projection.started_at,
        projection.completed_at,
    )?;
    if projection.operation_scope != ProjectionOperationScope::Traffic {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    validate_children(
        &projection.projection_id,
        projection.projection_revision,
        projection.evidence_kind,
        projection.source_call_count,
        &[],
        &projection.relationships,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_snapshot_for_insert(
    projection_id: &str,
    projection_revision: u64,
    _operation_scope: ProjectionOperationScope,
    stored_scope_digest: &[u8; 32],
    expected_scope_digest: &[u8; 32],
    scope_dids: &[String],
    canonical_did_set_bytes: &[u8],
    canonical_did_set_sha256: &[u8; 32],
    appview_base: &str,
    configuration_fingerprint: &[u8; 32],
    aggregate_evidence_bytes: &[u8],
    aggregate_evidence_sha256: &[u8; 32],
    source_call_count: u64,
    _evidence_kind: EvidenceKind,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
) -> Result<(), RelationshipRepositoryError> {
    parse_projection_id(projection_id)?;
    let fixed = fixed_production_relationship_policy_config()
        .map_err(RelationshipRepositoryError::InvalidAuthorityConfiguration)?;
    if !(1..=MAX_PROTOCOL_INTEGER).contains(&projection_revision)
        || source_call_count > MAX_PROTOCOL_INTEGER
        || stored_scope_digest != expected_scope_digest
        || canonical_did_set_bytes
            != encode_canonical_did_set(scope_dids)
                .as_deref()
                .unwrap_or(&[])
        || sha256(canonical_did_set_bytes) != *canonical_did_set_sha256
        || aggregate_evidence_bytes.is_empty()
        || sha256(aggregate_evidence_bytes) != *aggregate_evidence_sha256
        || appview_base != fixed.appview_origin().as_str()
        || configuration_fingerprint != &fixed.fingerprint()
        || completed_at < started_at
        || completed_at - started_at > chrono::TimeDelta::seconds(30)
        || started_at.timestamp_subsec_nanos() % 1_000 != 0
        || completed_at.timestamp_subsec_nanos() % 1_000 != 0
    {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    Ok(())
}

fn validate_children(
    projection_id: &str,
    projection_revision: u64,
    evidence_kind: EvidenceKind,
    source_call_count: u64,
    declarations: &[PersistedDeclarationEvidence],
    relationships: &[PersistedGraphRelationshipEvidence],
) -> Result<(), RelationshipRepositoryError> {
    let mut declaration_revisions = BTreeSet::new();
    for row in declarations {
        if row.projection_id != projection_id
            || row.evidence_kind != evidence_kind
            || row.fetch_revision == projection_revision
            || !(1..=MAX_PROTOCOL_INTEGER).contains(&row.fetch_revision)
            || !declaration_revisions.insert(row.fetch_revision)
        {
            return Err(RelationshipRepositoryError::InvalidProjection);
        }
    }
    let mut graph_revisions = BTreeSet::new();
    for row in relationships {
        if row.projection_id != projection_id
            || row.evidence_kind != evidence_kind
            || row.fetch_revision == projection_revision
            || !(1..=MAX_PROTOCOL_INTEGER).contains(&row.fetch_revision)
            || declaration_revisions.contains(&row.fetch_revision)
        {
            return Err(RelationshipRepositoryError::InvalidProjection);
        }
        graph_revisions.insert(row.fetch_revision);
    }
    let expected_calls = declarations
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(graph_revisions.len()))
        .and_then(|count| u64::try_from(count).ok())
        .ok_or(RelationshipRepositoryError::InvalidProjection)?;
    if source_call_count != expected_calls {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    Ok(())
}

fn fixed_configuration_fingerprint() -> Result<[u8; 32], RelationshipRepositoryError> {
    fixed_production_relationship_policy_config()
        .map(|config| config.fingerprint())
        .map_err(RelationshipRepositoryError::InvalidAuthorityConfiguration)
}

fn parse_projection_id(value: &str) -> Result<Uuid, RelationshipRepositoryError> {
    let parsed =
        Uuid::parse_str(value).map_err(|_| RelationshipRepositoryError::InvalidProjection)?;
    if parsed.to_string() != value
        || parsed.get_variant() != Variant::RFC4122
        || parsed.get_version() != Some(Version::Random)
    {
        return Err(RelationshipRepositoryError::InvalidProjection);
    }
    Ok(parsed)
}

fn to_i64(value: u64) -> Result<i64, RelationshipRepositoryError> {
    i64::try_from(value).map_err(|_| RelationshipRepositoryError::InvalidProjection)
}

fn from_i64(value: i64) -> Result<u64, RelationshipRepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| (1..=MAX_PROTOCOL_INTEGER).contains(value))
        .ok_or(RelationshipRepositoryError::InvalidProjection)
}

fn from_nonnegative_i64(value: i64) -> Result<u64, RelationshipRepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(RelationshipRepositoryError::InvalidProjection)
}

fn relationship_load_guard(
    operation_scope: ProjectionOperationScope,
    scope: ProjectionScope,
) -> RelationshipProjectionLoadGuard {
    #[cfg(test)]
    {
        RelationshipProjectionLoadGuard::for_test(operation_scope, scope)
    }
    #[cfg(not(test))]
    {
        RelationshipProjectionLoadGuard {
            operation_scope,
            scope,
        }
    }
}

fn traffic_load_guard(scope: TrafficGraphScope) -> TrafficProjectionLoadGuard {
    #[cfg(test)]
    {
        TrafficProjectionLoadGuard::for_test(scope)
    }
    #[cfg(not(test))]
    {
        TrafficProjectionLoadGuard { scope }
    }
}

fn bytes_32(value: Vec<u8>) -> Result<[u8; 32], RelationshipRepositoryError> {
    value
        .try_into()
        .map_err(|_| RelationshipRepositoryError::InvalidProjection)
}

fn incoming_policy(value: &str) -> Result<IncomingPolicy, RelationshipRepositoryError> {
    match value {
        "all" => Ok(IncomingPolicy::All),
        "none" => Ok(IncomingPolicy::None),
        "following" => Ok(IncomingPolicy::Following),
        _ => Err(RelationshipRepositoryError::InvalidProjection),
    }
}

fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn hash_len_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn hash_string_list(hash: &mut Sha256, values: &[String]) {
    hash.update((values.len() as u64).to_be_bytes());
    for value in values {
        hash_len_bytes(hash, value.as_bytes());
    }
}

fn relationship_scope_digest(scope: &ProjectionScope) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"CATBIRD-CHAT-RELATIONSHIP-SCOPE\0");
    match scope {
        ProjectionScope::Admission(request) => {
            hash.update([0]);
            hash.update([match request.operation {
                AdmissionOperation::Direct => 0,
                AdmissionOperation::Group => 1,
            }]);
            hash_len_bytes(&mut hash, request.inviter.as_bytes());
            hash_string_list(&mut hash, &request.roster);
            hash_string_list(&mut hash, &request.pending_recipients);
        }
        ProjectionScope::BlockOnly(scope) => {
            hash.update([1]);
            hash_len_bytes(&mut hash, scope.sink.as_bytes());
            hash_string_list(&mut hash, &scope.members);
        }
    }
    hash.finalize().into()
}

fn traffic_scope_digest(scope: &TrafficGraphScope) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"CATBIRD-CHAT-RELATIONSHIP-TRAFFIC-SCOPE\0");
    hash_len_bytes(&mut hash, scope.actor.as_bytes());
    hash_string_list(&mut hash, &scope.members);
    hash.finalize().into()
}

fn relationship_scope_dids(scope: &ProjectionScope) -> &[String] {
    match scope {
        ProjectionScope::Admission(request) => &request.roster,
        ProjectionScope::BlockOnly(scope) => &scope.members,
    }
}

fn encode_canonical_did_set(dids: &[String]) -> Option<Vec<u8>> {
    if dids.is_empty() || dids.windows(2).any(|pair| pair[0] >= pair[1]) || dids.len() > 100 {
        return None;
    }
    let mut output = Vec::new();
    output.extend_from_slice(b"CBDID001");
    output.extend_from_slice(&u16::try_from(dids.len()).ok()?.to_be_bytes());
    for did in dids {
        output.extend_from_slice(&u16::try_from(did.len()).ok()?.to_be_bytes());
        output.extend_from_slice(did.as_bytes());
    }
    Some(output)
}

fn relationship_operation_matches_scope(
    operation: ProjectionOperationScope,
    scope: &ProjectionScope,
) -> bool {
    matches!(
        (operation, scope),
        (
            ProjectionOperationScope::Creation
                | ProjectionOperationScope::PendingAdd
                | ProjectionOperationScope::Acceptance,
            ProjectionScope::Admission(_)
        ) | (
            ProjectionOperationScope::RecoveryReservation
                | ProjectionOperationScope::RecoveryFulfillment,
            ProjectionScope::BlockOnly(_)
        )
    )
}

fn canonical_transaction_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value.as_bytes()[0] != b'0'
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|value| value > 0)
}
