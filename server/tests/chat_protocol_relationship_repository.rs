//! Repository-boundary tests for clean-chat relationship projections.
//!
//! Database cases stay ignored until the root task authorizes a freshly
//! migrated, dedicated `catbird_chat_protocol_test_20260722` database. They
//! stay `#[ignore]`d (not de-ignored into the standard whole-suite gate)
//! because they hydrate durable relationship-projection state that must be read
//! back "after restart" against a pristine schema; a shared, never-truncated
//! database would carry residue between runs. Run them explicitly against a
//! freshly-migrated dedicated database:
//!   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_relationship_repository -- --ignored --test-threads=1

#![allow(dead_code)]

mod common;

#[path = "../src/identity.rs"]
mod identity;
#[path = "../src/util/mod.rs"]
mod util;

#[path = "../src/chat_protocol/model.rs"]
mod model;
#[path = "../src/chat_protocol/relationship_policy.rs"]
mod relationship_policy;
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

// Minimal locked-state types for compiling and exercising the real production
// relationship scope sealers in this path-included repository harness.
mod state_machine {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum ConversationKind {
        Direct,
        Group,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum ParticipantStatus {
        Pending,
        Active,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum PersistedRegistrationStatus {
        Active,
        Revoked,
    }

    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub(crate) struct PrincipalId(Vec<u8>);

    impl PrincipalId {
        pub(crate) fn from_did(value: &str) -> Self {
            Self(value.as_bytes().to_vec())
        }

        pub(crate) fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct DeviceIdentity {
        principal: PrincipalId,
    }

    impl DeviceIdentity {
        pub(crate) fn from_did(value: &str) -> Self {
            Self {
                principal: PrincipalId::from_did(value),
            }
        }

        pub(crate) fn principal(&self) -> &PrincipalId {
            &self.principal
        }
    }

    #[derive(Clone, Debug)]
    pub(crate) struct ParticipantRecord {
        principal: PrincipalId,
        status: ParticipantStatus,
        invitation_inviter: Option<DeviceIdentity>,
    }

    impl ParticipantRecord {
        pub(crate) fn new(
            did: &str,
            status: ParticipantStatus,
            invitation_inviter: Option<DeviceIdentity>,
        ) -> Self {
            Self {
                principal: PrincipalId::from_did(did),
                status,
                invitation_inviter,
            }
        }

        pub(crate) fn principal(&self) -> &PrincipalId {
            &self.principal
        }

        pub(crate) fn status(&self) -> ParticipantStatus {
            self.status
        }

        pub(crate) fn invitation_inviter(&self) -> Option<&DeviceIdentity> {
            self.invitation_inviter.as_ref()
        }
    }

    #[derive(Clone, Debug)]
    pub(crate) struct ConversationCoordinate([u8; 16]);

    impl ConversationCoordinate {
        pub(crate) fn conversation_id(&self) -> &[u8; 16] {
            &self.0
        }
    }

    #[derive(Clone, Debug)]
    pub(crate) struct ConversationState {
        kind: ConversationKind,
        coordinate: ConversationCoordinate,
        participants: Vec<ParticipantRecord>,
    }

    impl ConversationState {
        pub(crate) fn new(
            kind: ConversationKind,
            conversation_id: [u8; 16],
            mut participants: Vec<ParticipantRecord>,
        ) -> Self {
            participants.sort_by(|left, right| left.principal.cmp(&right.principal));
            Self {
                kind,
                coordinate: ConversationCoordinate(conversation_id),
                participants,
            }
        }

        pub(crate) fn kind(&self) -> ConversationKind {
            self.kind
        }

        pub(crate) fn coordinate(&self) -> &ConversationCoordinate {
            &self.coordinate
        }

        pub(crate) fn participants(&self) -> &[ParticipantRecord] {
            &self.participants
        }

        pub(crate) fn participant(&self, principal: &PrincipalId) -> Option<&ParticipantRecord> {
            self.participants
                .iter()
                .find(|participant| participant.principal() == principal)
        }
    }

    #[derive(Debug)]
    pub(crate) struct LockedRegistrationProjection {
        transaction_id: String,
        conversation_id: [u8; 16],
        actor: DeviceIdentity,
        status: PersistedRegistrationStatus,
        durable_row_digest: [u8; 32],
    }

    impl LockedRegistrationProjection {
        pub(crate) fn for_scope_test(
            transaction_id: &str,
            conversation_id: [u8; 16],
            actor_did: &str,
            status: PersistedRegistrationStatus,
            durable_row_digest: [u8; 32],
        ) -> Self {
            Self {
                transaction_id: transaction_id.to_owned(),
                conversation_id,
                actor: DeviceIdentity::from_did(actor_did),
                status,
                durable_row_digest,
            }
        }

        pub(crate) fn transaction_id(&self) -> &str {
            &self.transaction_id
        }

        pub(crate) fn conversation_id(&self) -> &[u8; 16] {
            &self.conversation_id
        }

        pub(crate) fn actor(&self) -> &DeviceIdentity {
            &self.actor
        }

        pub(crate) fn status(&self) -> PersistedRegistrationStatus {
            self.status
        }

        pub(crate) fn durable_row_digest(&self) -> &[u8; 32] {
            &self.durable_row_digest
        }
    }
}

// Compile the real repository implementation under the same module shape it
// has in production. The policy's path-included tests own their lightweight
// revision witness, so this adapter supplies only the production core factory
// surface; the production library still compiles against repository/core.rs.
mod repository {
    pub(crate) mod core {
        pub(crate) use crate::relationship_policy::AllocatedProjectionRevisionGuard;

        impl AllocatedProjectionRevisionGuard {
            pub(super) fn from_database_allocation(
                allocation_id: uuid::Uuid,
                value: i64,
            ) -> Option<Self> {
                u64::try_from(value)
                    .ok()
                    .filter(|value| (1..=9_007_199_254_740_991).contains(value))
                    .filter(|_| {
                        allocation_id.get_variant() == uuid::Variant::RFC4122
                            && allocation_id.get_version_num() == 4
                    })
                    .map(|value| Self::for_test_allocation(allocation_id, value))
            }
        }

        #[derive(Debug)]
        pub(crate) struct LockedConversationHeadGuard {
            transaction_id: String,
            conversation_id: uuid::Uuid,
            prior_coordinate: Option<()>,
            next_entry_seq: u64,
            durable_row_digest: [u8; 32],
        }

        impl LockedConversationHeadGuard {
            pub(crate) fn for_scope_test(
                transaction_id: &str,
                conversation_id: [u8; 16],
                prior_exists: bool,
                next_entry_seq: u64,
                durable_row_digest: [u8; 32],
            ) -> Self {
                Self {
                    transaction_id: transaction_id.to_owned(),
                    conversation_id: uuid::Uuid::from_bytes(conversation_id),
                    prior_coordinate: prior_exists.then_some(()),
                    next_entry_seq,
                    durable_row_digest,
                }
            }

            pub(crate) fn transaction_id(&self) -> &str {
                &self.transaction_id
            }

            pub(crate) fn conversation_id(&self) -> uuid::Uuid {
                self.conversation_id
            }

            pub(crate) fn prior_coordinate(&self) -> Option<&()> {
                self.prior_coordinate.as_ref()
            }

            pub(crate) fn next_entry_seq(&self) -> u64 {
                self.next_entry_seq
            }

            pub(crate) fn durable_row_digest(&self) -> &[u8; 32] {
                &self.durable_row_digest
            }
        }

        #[derive(Debug)]
        pub(crate) struct LockedInvitationQuotaGuard {
            transaction_id: String,
            inviter_did: String,
            new_recipient_dids: Vec<String>,
            durable_row_digest: [u8; 32],
        }

        impl LockedInvitationQuotaGuard {
            pub(crate) fn for_scope_test(
                transaction_id: &str,
                inviter_did: String,
                mut new_recipient_dids: Vec<String>,
                durable_row_digest: [u8; 32],
            ) -> Self {
                new_recipient_dids.sort();
                Self {
                    transaction_id: transaction_id.to_owned(),
                    inviter_did,
                    new_recipient_dids,
                    durable_row_digest,
                }
            }

            pub(crate) fn transaction_id(&self) -> &str {
                &self.transaction_id
            }

            pub(crate) fn inviter_did(&self) -> &str {
                &self.inviter_did
            }

            pub(crate) fn new_recipient_dids(&self) -> &[String] {
                &self.new_recipient_dids
            }

            pub(crate) fn durable_row_digest(&self) -> &[u8; 32] {
                &self.durable_row_digest
            }
        }

        #[derive(Clone, Debug, Eq, PartialEq)]
        pub(crate) enum LockedDirectLookupOutcome {
            Absent,
            Existing,
        }

        #[derive(Debug)]
        pub(crate) struct LockedDirectConversationLookupGuard {
            transaction_id: String,
            did_low: String,
            did_high: String,
            outcome: LockedDirectLookupOutcome,
            durable_row_digest: [u8; 32],
        }

        impl LockedDirectConversationLookupGuard {
            pub(crate) fn for_scope_test(
                transaction_id: &str,
                did_low: String,
                did_high: String,
                outcome: LockedDirectLookupOutcome,
                durable_row_digest: [u8; 32],
            ) -> Self {
                Self {
                    transaction_id: transaction_id.to_owned(),
                    did_low,
                    did_high,
                    outcome,
                    durable_row_digest,
                }
            }

            pub(crate) fn transaction_id(&self) -> &str {
                &self.transaction_id
            }

            pub(crate) fn did_low(&self) -> &str {
                &self.did_low
            }

            pub(crate) fn did_high(&self) -> &str {
                &self.did_high
            }

            pub(crate) fn outcome(&self) -> &LockedDirectLookupOutcome {
                &self.outcome
            }

            pub(crate) fn durable_row_digest(&self) -> &[u8; 32] {
                &self.durable_row_digest
            }
        }

        #[derive(Debug)]
        pub(crate) struct LockedConversationStateGuard {
            state: crate::state_machine::ConversationState,
            head: LockedConversationHeadGuard,
            locked_graph_digest: [u8; 32],
        }

        impl LockedConversationStateGuard {
            pub(crate) fn for_scope_test(
                state: crate::state_machine::ConversationState,
                head: LockedConversationHeadGuard,
                locked_graph_digest: [u8; 32],
            ) -> Self {
                Self {
                    state,
                    head,
                    locked_graph_digest,
                }
            }

            pub(crate) fn state(&self) -> &crate::state_machine::ConversationState {
                &self.state
            }

            pub(crate) fn head(&self) -> &LockedConversationHeadGuard {
                &self.head
            }

            pub(crate) fn locked_graph_digest(&self) -> &[u8; 32] {
                &self.locked_graph_digest
            }
        }
    }

    pub(crate) mod relationship {
        pub(crate) fn observe_relationship_persistence(
        ) -> crate::relationship_policy::TrustedRelationshipPersistenceInstant {
            crate::relationship_policy::TrustedRelationshipPersistenceInstant::for_test(
                chrono::Utc::now(),
            )
        }

        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/relationship.rs"
        ));
    }
}

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use relationship_policy::{
    AdmissionOperation, AdmissionRequest, AllocatedProjectionRevisionGuard, HttpRelationshipSource,
    PolicyDenial, ProjectionClock, ProjectionOperationScope, ProjectionScope, PublicGet,
    PublicResponse, PublicTransport, RelationshipPolicyConfig, RelationshipPolicyConfigInput,
    TrafficGraphScope, TransportError, TrustedRelationshipPersistenceInstant,
    HARD_MAX_REQUEST_BURST, HARD_MAX_REQUEST_RATE, MAX_ADMISSION_GRAPH_CALLS,
    MAX_ADMISSION_SOURCE_CALLS, MAX_DECLARATION_HTTP_CALLS, MAX_TRAFFIC_GRAPH_CALLS,
};
use repository::relationship::{
    allocate_projection_revision, load_fallback_relationship_projection,
    load_fallback_traffic_projection, persist_relationship_projection, persist_traffic_projection,
    seal_acceptance_fallback_scope, seal_direct_creation_fallback_scope,
    seal_group_creation_fallback_scope, seal_pending_add_fallback_scope,
    seal_recovery_fallback_scope, seal_traffic_fallback_scope, LockedRelationshipFallbackScope,
    LockedTrafficFallbackScope,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use validation::{CanonicalTimestamp, TrustedRequestInstant};

use repository::core::{
    LockedConversationHeadGuard, LockedConversationStateGuard, LockedDirectConversationLookupGuard,
    LockedDirectLookupOutcome, LockedInvitationQuotaGuard,
};
use state_machine::{
    ConversationKind, ConversationState, DeviceIdentity, LockedRegistrationProjection,
    ParticipantRecord, ParticipantStatus, PersistedRegistrationStatus,
};

#[test]
fn repository_source_seals_projection_and_scope_authority() {
    let source = include_str!("../src/chat_protocol/repository/relationship.rs");
    let policy_source = include_str!("../src/chat_protocol/relationship_policy.rs");

    for constraint in [
        "chat.relationship_projection_snapshots_complete_deferred",
        "chat.relationship_projection_relationships_complete_deferred",
        "chat.relationship_projection_declarations_complete_deferred",
    ] {
        assert_eq!(
            source.matches(constraint).count(),
            2,
            "both SET CONSTRAINTS statements must schema-qualify {constraint}"
        );
    }

    assert!(source.contains("projection: SealedRelationshipProjection"));
    assert!(source.contains("projection: SealedTrafficProjection"));
    assert!(!source.contains("projection: PersistedRelationshipProjection"));
    assert!(!source.contains("projection: PersistedTrafficProjection"));
    assert!(policy_source.contains("pub(crate) struct PersistedRelationshipProjection"));
    assert!(policy_source.contains("pub(crate) struct PersistedTrafficProjection"));
    let raw_projection_region = policy_source
        .split_once("pub(crate) struct PersistedRelationshipProjection")
        .expect("raw relationship DTO exists")
        .1
        .split_once("pub(crate) struct SealedRelationshipProjection")
        .expect("sealed projection follows raw DTOs")
        .0;
    assert!(raw_projection_region.contains("pub(super) projection_id"));
    assert!(!raw_projection_region.contains("pub(crate) projection_id"));

    let relationship_loader = source
        .split_once("pub(crate) async fn load_fallback_relationship_projection")
        .expect("relationship fallback loader exists")
        .1
        .split_once("pub(crate) async fn load_fallback_traffic_projection")
        .expect("traffic fallback loader follows relationship loader")
        .0;
    assert!(relationship_loader.contains("LockedRelationshipFallbackScope"));
    assert!(!relationship_loader.contains("scope: ProjectionScope"));
    assert!(!relationship_loader.contains("operation_scope: ProjectionOperationScope"));

    let traffic_loader = source
        .split_once("pub(crate) async fn load_fallback_traffic_projection")
        .expect("traffic fallback loader exists")
        .1
        .split_once("async fn insert_snapshot")
        .expect("snapshot insert follows traffic loader")
        .0;
    assert!(traffic_loader.contains("LockedTrafficFallbackScope"));
    assert!(!traffic_loader.contains("scope: TrafficGraphScope"));

    let direct_creation = source
        .split_once("pub(crate) fn seal_direct_creation_fallback_scope")
        .expect("direct creation scope sealer exists")
        .1
        .split_once("pub(crate) fn seal_pending_add_fallback_scope")
        .expect("pending-add sealer follows creation sealers")
        .0;
    assert!(
        direct_creation.contains("direct_lookup.durable_row_digest()"),
        "direct lookup row must participate in the durable read-set digest"
    );

    let acceptance = source
        .split_once("pub(crate) fn seal_acceptance_fallback_scope")
        .expect("acceptance scope sealer exists")
        .1
        .split_once("pub(crate) fn seal_recovery_fallback_scope")
        .expect("recovery sealer follows acceptance")
        .0;
    assert!(acceptance.contains("registration: &LockedRegistrationProjection"));
    assert!(!acceptance.contains("inviter: String"));
    assert!(!acceptance.contains("accepting_principal: String"));

    let traffic = source
        .split_once("pub(crate) fn seal_traffic_fallback_scope")
        .expect("traffic scope sealer exists")
        .1
        .split_once("fn locked_state_roster")
        .expect("locked roster helper follows traffic sealer")
        .0;
    assert!(traffic.contains("registration: &LockedRegistrationProjection"));
    assert!(!traffic.contains("actor: String"));
    assert!(
        traffic.contains("registration.durable_row_digest()"),
        "traffic witness must bind the authenticated actor row"
    );
}

fn did(index: usize) -> String {
    const DIGITS: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut suffix = [b'a'; 24];
    let mut value = index;
    for slot in suffix.iter_mut().rev().take(4) {
        *slot = DIGITS[value % DIGITS.len()];
        value /= DIGITS.len();
    }
    format!("did:plc:{}", String::from_utf8(suffix.to_vec()).unwrap())
}

fn roster(size: usize) -> Vec<String> {
    let mut values = (0..size).map(did).collect::<Vec<_>>();
    values.sort();
    values
}

fn locked_scope_state(
    transaction_id: &str,
    conversation_id: [u8; 16],
    kind: ConversationKind,
    participants: Vec<ParticipantRecord>,
    head_digest: [u8; 32],
    graph_digest: [u8; 32],
) -> LockedConversationStateGuard {
    LockedConversationStateGuard::for_scope_test(
        ConversationState::new(kind, conversation_id, participants),
        LockedConversationHeadGuard::for_scope_test(
            transaction_id,
            conversation_id,
            true,
            2,
            head_digest,
        ),
        graph_digest,
    )
}

#[test]
fn production_scope_sealers_bind_transaction_actor_roster_and_every_locked_digest() {
    let transaction_id = "41";
    let other_transaction_id = "42";
    let conversation_id = [0x41; 16];
    let alice = did(0);
    let bob = did(1);
    let carol = did(2);

    let creation_head = LockedConversationHeadGuard::for_scope_test(
        transaction_id,
        conversation_id,
        false,
        1,
        [0x11; 32],
    );
    // The creation sealers now authenticate the inviter against a locked
    // registration bound to the same transaction + conversation coordinate.
    let creation_registration = LockedRegistrationProjection::for_scope_test(
        transaction_id,
        conversation_id,
        &alice,
        PersistedRegistrationStatus::Active,
        [0x2a; 32],
    );
    let group_quota = LockedInvitationQuotaGuard::for_scope_test(
        transaction_id,
        alice.clone(),
        vec![bob.clone(), carol.clone()],
        [0x12; 32],
    );
    let group_scope =
        seal_group_creation_fallback_scope(&creation_head, &group_quota, &creation_registration)
            .expect("group scope");
    let (transaction, operation, scope, _authenticated_actor_digest, digest) =
        group_scope.parts_for_test();
    assert_eq!(transaction, transaction_id);
    assert_eq!(operation, ProjectionOperationScope::Creation);
    assert_ne!(digest, &[0; 32]);
    let ProjectionScope::Admission(request) = scope else {
        panic!("group creation must produce admission scope");
    };
    assert_eq!(request.inviter, alice);
    assert_eq!(request.roster, vec![alice.clone(), bob.clone(), carol]);
    assert_eq!(request.pending_recipients, vec![bob.clone(), did(2)]);
    assert_eq!(request.operation, AdmissionOperation::Group);

    let wrong_transaction_quota = LockedInvitationQuotaGuard::for_scope_test(
        other_transaction_id,
        alice.clone(),
        vec![bob.clone()],
        [0x12; 32],
    );
    assert!(seal_group_creation_fallback_scope(
        &creation_head,
        &wrong_transaction_quota,
        &creation_registration,
    )
    .is_err());
    let zero_digest_quota = LockedInvitationQuotaGuard::for_scope_test(
        transaction_id,
        alice.clone(),
        vec![bob.clone()],
        [0; 32],
    );
    assert!(seal_group_creation_fallback_scope(
        &creation_head,
        &zero_digest_quota,
        &creation_registration,
    )
    .is_err());

    let direct_quota = LockedInvitationQuotaGuard::for_scope_test(
        transaction_id,
        alice.clone(),
        vec![bob.clone()],
        [0x13; 32],
    );
    let direct_lookup = LockedDirectConversationLookupGuard::for_scope_test(
        transaction_id,
        alice.clone(),
        bob.clone(),
        LockedDirectLookupOutcome::Absent,
        [0x14; 32],
    );
    let direct_scope = seal_direct_creation_fallback_scope(
        &creation_head,
        &direct_quota,
        &direct_lookup,
        &creation_registration,
    )
    .expect("direct scope");
    let direct_digest = *direct_scope.parts_for_test().4;
    let changed_direct_lookup = LockedDirectConversationLookupGuard::for_scope_test(
        transaction_id,
        alice.clone(),
        bob.clone(),
        LockedDirectLookupOutcome::Absent,
        [0x15; 32],
    );
    let changed_direct_scope = seal_direct_creation_fallback_scope(
        &creation_head,
        &direct_quota,
        &changed_direct_lookup,
        &creation_registration,
    )
    .expect("changed direct scope");
    assert_ne!(direct_digest, *changed_direct_scope.parts_for_test().4);
    let wrong_transaction_lookup = LockedDirectConversationLookupGuard::for_scope_test(
        other_transaction_id,
        alice.clone(),
        bob.clone(),
        LockedDirectLookupOutcome::Absent,
        [0x14; 32],
    );
    assert!(seal_direct_creation_fallback_scope(
        &creation_head,
        &direct_quota,
        &wrong_transaction_lookup,
        &creation_registration,
    )
    .is_err());
    let existing_lookup = LockedDirectConversationLookupGuard::for_scope_test(
        transaction_id,
        alice.clone(),
        bob.clone(),
        LockedDirectLookupOutcome::Existing,
        [0x14; 32],
    );
    assert!(seal_direct_creation_fallback_scope(
        &creation_head,
        &direct_quota,
        &existing_lookup,
        &creation_registration,
    )
    .is_err());

    let inviter = DeviceIdentity::from_did(&alice);
    let pending_locked = locked_scope_state(
        transaction_id,
        conversation_id,
        ConversationKind::Group,
        vec![
            ParticipantRecord::new(&alice, ParticipantStatus::Active, None),
            ParticipantRecord::new(&bob, ParticipantStatus::Pending, Some(inviter.clone())),
        ],
        [0x21; 32],
        [0x22; 32],
    );
    let add_quota = LockedInvitationQuotaGuard::for_scope_test(
        transaction_id,
        alice.clone(),
        vec![did(2)],
        [0x23; 32],
    );
    let pending_add =
        seal_pending_add_fallback_scope(&pending_locked, &add_quota, &creation_registration)
            .expect("pending-add scope");
    assert_eq!(
        pending_add.parts_for_test().1,
        ProjectionOperationScope::PendingAdd
    );

    let accepting_registration = LockedRegistrationProjection::for_scope_test(
        transaction_id,
        conversation_id,
        &bob,
        PersistedRegistrationStatus::Active,
        [0x24; 32],
    );
    let acceptance = seal_acceptance_fallback_scope(&pending_locked, &accepting_registration)
        .expect("retained inviter and pending actor derive acceptance");
    let (_, acceptance_operation, acceptance_scope, _acceptance_actor_digest, acceptance_digest) =
        acceptance.parts_for_test();
    assert_eq!(acceptance_operation, ProjectionOperationScope::Acceptance);
    let ProjectionScope::Admission(acceptance_request) = acceptance_scope else {
        panic!("acceptance must produce admission scope");
    };
    assert_eq!(acceptance_request.inviter, alice);
    assert_eq!(acceptance_request.pending_recipients, vec![bob.clone()]);
    assert_eq!(acceptance_request.roster, vec![alice.clone(), bob.clone()]);

    let changed_registration = LockedRegistrationProjection::for_scope_test(
        transaction_id,
        conversation_id,
        &bob,
        PersistedRegistrationStatus::Active,
        [0x25; 32],
    );
    let changed_acceptance = seal_acceptance_fallback_scope(&pending_locked, &changed_registration)
        .expect("changed actor row remains structurally valid");
    assert_ne!(*acceptance_digest, *changed_acceptance.parts_for_test().4);
    let wrong_actor_registration = LockedRegistrationProjection::for_scope_test(
        transaction_id,
        conversation_id,
        &alice,
        PersistedRegistrationStatus::Active,
        [0x24; 32],
    );
    assert!(seal_acceptance_fallback_scope(&pending_locked, &wrong_actor_registration).is_err());
    let wrong_transaction_registration = LockedRegistrationProjection::for_scope_test(
        other_transaction_id,
        conversation_id,
        &bob,
        PersistedRegistrationStatus::Active,
        [0x24; 32],
    );
    assert!(
        seal_acceptance_fallback_scope(&pending_locked, &wrong_transaction_registration).is_err()
    );
    let revoked_registration = LockedRegistrationProjection::for_scope_test(
        transaction_id,
        conversation_id,
        &bob,
        PersistedRegistrationStatus::Revoked,
        [0x24; 32],
    );
    assert!(seal_acceptance_fallback_scope(&pending_locked, &revoked_registration).is_err());
    let zero_digest_registration = LockedRegistrationProjection::for_scope_test(
        transaction_id,
        conversation_id,
        &bob,
        PersistedRegistrationStatus::Active,
        [0; 32],
    );
    assert!(seal_acceptance_fallback_scope(&pending_locked, &zero_digest_registration).is_err());

    for operation in [
        ProjectionOperationScope::RecoveryReservation,
        ProjectionOperationScope::RecoveryFulfillment,
    ] {
        let recovery =
            seal_recovery_fallback_scope(&pending_locked, &creation_registration, operation)
                .expect("recovery scope");
        assert_eq!(recovery.parts_for_test().1, operation);
    }
    assert!(seal_recovery_fallback_scope(
        &pending_locked,
        &creation_registration,
        ProjectionOperationScope::Traffic,
    )
    .is_err());

    assert!(
        seal_traffic_fallback_scope(&pending_locked, &accepting_registration).is_err(),
        "pending participant cannot choose the traffic actor"
    );
    let active_locked = locked_scope_state(
        transaction_id,
        conversation_id,
        ConversationKind::Group,
        vec![
            ParticipantRecord::new(&alice, ParticipantStatus::Active, None),
            ParticipantRecord::new(&bob, ParticipantStatus::Active, None),
        ],
        [0x31; 32],
        [0x32; 32],
    );
    let traffic = seal_traffic_fallback_scope(&active_locked, &accepting_registration)
        .expect("authenticated active actor derives traffic scope");
    let (_, traffic_scope, _traffic_actor_digest, traffic_digest) = traffic.parts_for_test();
    assert_eq!(traffic_scope.actor, bob);
    assert_eq!(traffic_scope.members, vec![alice, bob]);
    let changed_traffic =
        seal_traffic_fallback_scope(&active_locked, &changed_registration).expect("traffic scope");
    assert_ne!(*traffic_digest, *changed_traffic.parts_for_test().3);
    assert!(seal_traffic_fallback_scope(&active_locked, &wrong_transaction_registration).is_err());
    assert!(seal_traffic_fallback_scope(&active_locked, &zero_digest_registration).is_err());
}

fn admission_request() -> AdmissionRequest {
    let members = roster(3);
    AdmissionRequest {
        inviter: members[0].clone(),
        roster: members.clone(),
        pending_recipients: members[1..].to_vec(),
        operation: AdmissionOperation::Group,
    }
}

fn fixed_test_config() -> RelationshipPolicyConfig {
    RelationshipPolicyConfig::new(RelationshipPolicyConfigInput {
        appview_origin: "https://public.api.bsky.app".into(),
        plc_directory_origin: "https://plc.directory".into(),
        max_concurrency: 16,
        request_rate_per_second: HARD_MAX_REQUEST_RATE,
        request_burst: HARD_MAX_REQUEST_BURST,
        total_deadline: Duration::from_secs(20),
        max_response_bytes: 256 * 1024,
        max_dns_answers: 8,
        admission_graph_capacity: MAX_ADMISSION_GRAPH_CALLS,
        declaration_http_capacity: MAX_DECLARATION_HTTP_CALLS,
        admission_source_capacity: MAX_ADMISSION_SOURCE_CALLS,
        traffic_graph_capacity: MAX_TRAFFIC_GRAPH_CALLS,
    })
    .unwrap()
}

fn trusted_at(value: DateTime<Utc>) -> TrustedRequestInstant {
    let submillisecond_nanos = value.timestamp_subsec_nanos() % 1_000_000;
    let canonical_value = if submillisecond_nanos == 0 {
        value
    } else {
        value + TimeDelta::nanoseconds(i64::from(1_000_000 - submillisecond_nanos))
    };
    let canonical = canonical_value.to_rfc3339_opts(SecondsFormat::Millis, true);
    TrustedRequestInstant::from_canonical_for_test(CanonicalTimestamp::parse(&canonical).unwrap())
}

fn persistence_at(value: DateTime<Utc>) -> TrustedRelationshipPersistenceInstant {
    TrustedRelationshipPersistenceInstant::for_test(value)
}

struct StepClock {
    base: DateTime<Utc>,
    calls: AtomicUsize,
}

impl StepClock {
    /// Anchor to a near-`now` instant rather than a fixed calendar date: the
    /// fallback loader's freshness guard rejects snapshots whose `completed_at`
    /// is more than 60s older than its own wall-clock observation, so a
    /// hardcoded past base would make the after-restart hydration tests fail
    /// whenever the suite runs.
    fn new() -> Self {
        Self::anchored(Utc::now())
    }

    /// Anchor `seconds` before now, used to seed a snapshot the loader's
    /// freshness guard must reject as stale (see the backdated-scope witness in
    /// `traffic_fallback_hydrates_exact_scope_and_freshness_after_restart`).
    fn backdated(seconds: i64) -> Self {
        Self::anchored(Utc::now() - TimeDelta::seconds(seconds))
    }

    /// Truncate the base to whole milliseconds for determinism within a run;
    /// per-call millisecond stepping preserves canonical ordering.
    fn anchored(instant: DateTime<Utc>) -> Self {
        let submillisecond_nanos = instant.timestamp_subsec_nanos() % 1_000_000;
        Self {
            base: instant - TimeDelta::nanoseconds(i64::from(submillisecond_nanos)),
            calls: AtomicUsize::new(0),
        }
    }
}

impl ProjectionClock for StepClock {
    fn now(&self) -> DateTime<Utc> {
        self.base + TimeDelta::milliseconds(self.calls.fetch_add(1, Ordering::SeqCst) as i64)
    }
}

#[derive(Clone, Copy)]
struct DeterministicPublicTransport;

fn query_values(url: &url::Url, key: &str) -> Vec<String> {
    url.query_pairs()
        .filter(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
        .collect()
}

#[async_trait]
impl PublicTransport for DeterministicPublicTransport {
    async fn get(&self, request: PublicGet) -> Result<PublicResponse, TransportError> {
        match request.url.path() {
            path if path.starts_with("/did:plc:") => {
                let actor = path.trim_start_matches('/');
                Ok(PublicResponse::json(
                    200,
                    json!({
                        "id": actor,
                        "service": [{
                            "id": format!("{actor}#atproto_pds"),
                            "type": "AtprotoPersonalDataServer",
                            "serviceEndpoint": "https://pds.example.net"
                        }]
                    }),
                ))
            }
            "/xrpc/com.atproto.repo.getRecord" => {
                let actor = query_values(&request.url, "repo").remove(0);
                Ok(PublicResponse::json(
                    200,
                    json!({
                        "uri": format!("at://{actor}/chat.bsky.actor.declaration/self"),
                        "cid": "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
                        "value": {
                            "$type": "chat.bsky.actor.declaration",
                            "allowIncoming": "all",
                            "allowGroupInvites": "all"
                        }
                    }),
                ))
            }
            "/xrpc/app.bsky.graph.getRelationships" => {
                let actor = query_values(&request.url, "actor").remove(0);
                let relationships = query_values(&request.url, "others")
                    .into_iter()
                    .map(|target| {
                        json!({
                            "$type": "app.bsky.graph.defs#relationship",
                            "did": target,
                            "following": format!("at://{actor}/app.bsky.graph.follow/repositorytest")
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(PublicResponse::json(
                    200,
                    json!({"actor": actor, "relationships": relationships}),
                ))
            }
            _ => panic!(
                "unexpected relationship repository request: {}",
                request.url
            ),
        }
    }
}

fn authority() -> HttpRelationshipSource<DeterministicPublicTransport> {
    HttpRelationshipSource::new(fixed_test_config(), DeterministicPublicTransport)
}

#[derive(Clone, Copy)]
struct BlockedTrafficTransport;

#[async_trait]
impl PublicTransport for BlockedTrafficTransport {
    async fn get(&self, request: PublicGet) -> Result<PublicResponse, TransportError> {
        if request.url.path() == "/xrpc/app.bsky.graph.getRelationships" {
            let actor = query_values(&request.url, "actor").remove(0);
            let relationships = query_values(&request.url, "others")
                .into_iter()
                .map(|target| {
                    json!({
                        "$type": "app.bsky.graph.defs#relationship",
                        "did": target,
                        "blocking": format!("at://{actor}/app.bsky.graph.block/repositorytest")
                    })
                })
                .collect::<Vec<_>>();
            return Ok(PublicResponse::json(
                200,
                json!({"actor": actor, "relationships": relationships}),
            ));
        }
        DeterministicPublicTransport.get(request).await
    }
}

fn blocked_authority() -> HttpRelationshipSource<BlockedTrafficTransport> {
    HttpRelationshipSource::new(fixed_test_config(), BlockedTrafficTransport)
}

async fn allocated_revision(pool: &sqlx::PgPool) -> AllocatedProjectionRevisionGuard {
    let mut transaction = pool.begin().await.unwrap();
    let guard = allocate_projection_revision(&mut transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    guard
}

async fn persist_principal_read_set(pool: &sqlx::PgPool, dids: &[String]) {
    let mut canonical = dids.to_vec();
    canonical.sort();
    canonical.dedup();
    assert_eq!(canonical.len(), dids.len(), "scope DIDs must be unique");
    sqlx::query(
        r#"
        INSERT INTO chat.principals(user_did, created_at)
        SELECT user_did, clock_timestamp()
          FROM unnest($1::text[]) AS input(user_did)
        ON CONFLICT (user_did) DO NOTHING
        "#,
    )
    .bind(&canonical)
    .execute(pool)
    .await
    .unwrap();
}

async fn lock_principal_read_set(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    dids: &[String],
    domain: &[u8],
) -> (String, Vec<String>, [u8; 32]) {
    let mut expected = dids.to_vec();
    expected.sort();
    expected.dedup();
    assert_eq!(expected.len(), dids.len(), "scope DIDs must be unique");

    let locked: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT user_did
          FROM chat.principals
         WHERE user_did = ANY($1::text[])
         ORDER BY user_did COLLATE "C"
         FOR UPDATE
        "#,
    )
    .bind(&expected)
    .fetch_all(&mut **transaction)
    .await
    .unwrap();
    assert_eq!(
        locked, expected,
        "the exact durable scope read set must exist"
    );

    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await
        .unwrap();
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-TEST-LOCKED-SCOPE\0");
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest.update((transaction_id.len() as u64).to_be_bytes());
    digest.update(transaction_id.as_bytes());
    digest.update((locked.len() as u64).to_be_bytes());
    for did in &locked {
        digest.update((did.len() as u64).to_be_bytes());
        digest.update(did.as_bytes());
    }
    (transaction_id, locked, digest.finalize().into())
}

async fn lock_creation_scope(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    dids: &[String],
) -> (LockedRelationshipFallbackScope, AdmissionRequest) {
    let (transaction_id, roster, read_set_digest) =
        lock_principal_read_set(transaction, dids, b"creation").await;
    let request = AdmissionRequest {
        inviter: roster[0].clone(),
        pending_recipients: roster[1..].to_vec(),
        roster,
        operation: AdmissionOperation::Group,
    };
    let witness = LockedRelationshipFallbackScope::from_locked_read_set_for_test(
        transaction_id,
        ProjectionOperationScope::Creation,
        ProjectionScope::Admission(request.clone()),
        read_set_digest,
    );
    (witness, request)
}

async fn lock_traffic_scope(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    dids: &[String],
) -> (LockedTrafficFallbackScope, TrafficGraphScope) {
    let (transaction_id, members, read_set_digest) =
        lock_principal_read_set(transaction, dids, b"traffic").await;
    let scope = TrafficGraphScope {
        actor: members[0].clone(),
        members,
    };
    let witness = LockedTrafficFallbackScope::from_locked_read_set_for_test(
        transaction_id,
        scope.clone(),
        read_set_digest,
    );
    (witness, scope)
}

async fn relationship_fallback(
    pool: &sqlx::PgPool,
) -> (
    HttpRelationshipSource<DeterministicPublicTransport>,
    AdmissionRequest,
    TrustedRequestInstant,
    relationship_policy::SealedRelationshipProjection,
) {
    let authority = authority();
    let request = admission_request();
    let live = relationship_policy::collect_admission_projection(
        &authority,
        &StepClock::new(),
        allocated_revision(pool).await,
        ProjectionOperationScope::Creation,
        request.clone(),
    )
    .await
    .unwrap();
    let trusted_now = trusted_at(live.completed_at());
    let persisted = live
        .export_persisted_fallback(
            allocated_revision(pool).await,
            &authority,
            &persistence_at(live.completed_at()),
        )
        .unwrap();
    (authority, request, trusted_now, persisted)
}

async fn traffic_fallback(
    pool: &sqlx::PgPool,
) -> (
    HttpRelationshipSource<DeterministicPublicTransport>,
    TrafficGraphScope,
    TrustedRequestInstant,
    relationship_policy::SealedTrafficProjection,
) {
    let authority = authority();
    let members = roster(32);
    let live = relationship_policy::collect_traffic_projection(
        &authority,
        &StepClock::new(),
        allocated_revision(pool).await,
        members[0].clone(),
        members,
    )
    .await
    .unwrap();
    let scope = live.scope().clone();
    let trusted_now = trusted_at(live.completed_at());
    let persisted = live
        .export_persisted_fallback(
            allocated_revision(pool).await,
            &authority,
            &persistence_at(live.completed_at()),
        )
        .unwrap();
    (authority, scope, trusted_now, persisted)
}

#[tokio::test]
#[ignore = "root fresh-database authorization required"]
async fn relationship_snapshot_is_atomic_and_hydrates_after_pool_restart() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let (authority, request, _trusted_now, mut persisted) = relationship_fallback(&pool).await;
    let projection_id = uuid::Uuid::parse_str(&persisted.projection_id).unwrap();
    let expected_revision = persisted.projection_revision;

    // Persist in deliberately noncanonical vector order. SQL does not promise
    // row order, so the loader must rebuild canonical batches itself.
    persisted.declarations.reverse();
    persisted.relationships.reverse();
    let mut transaction = pool.begin().await.unwrap();
    persist_relationship_projection(&mut transaction, persisted)
        .await
        .unwrap();
    transaction.commit().await.unwrap();

    let counts: (i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
          (SELECT count(*) FROM chat.relationship_projection_snapshots WHERE projection_id=$1),
          (SELECT count(*) FROM chat.relationship_projection_declarations WHERE projection_id=$1),
          (SELECT count(*) FROM chat.relationship_projection_relationships WHERE projection_id=$1)
        "#,
    )
    .bind(projection_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(counts, (1, 2, 3));

    let forbidden_columns: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
          FROM information_schema.columns
         WHERE table_schema='chat'
           AND table_name LIKE 'relationship_projection_%'
           AND column_name IN ('raw_body','response_body','did_document','graph_response')
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        forbidden_columns, 0,
        "raw public response bodies reached SQL"
    );

    persist_principal_read_set(&pool, &request.roster).await;
    let wrong_roster = (100..103).map(did).collect::<Vec<_>>();
    persist_principal_read_set(&pool, &wrong_roster).await;
    pool.close().await;
    let restarted = common::chat_protocol::setup_chat_protocol_db(2).await;

    let mut stale_transaction = restarted.begin().await.unwrap();
    let (stale_witness, stale_request) =
        lock_creation_scope(&mut stale_transaction, &request.roster).await;
    assert_eq!(stale_request, request);
    stale_transaction.rollback().await.unwrap();

    let mut load_transaction = restarted.begin().await.unwrap();
    assert!(load_fallback_relationship_projection(
        &mut load_transaction,
        stale_witness,
        &authority,
    )
    .await
    .is_err());

    let (wrong_witness, wrong_request) =
        lock_creation_scope(&mut load_transaction, &wrong_roster).await;
    assert!(load_fallback_relationship_projection(
        &mut load_transaction,
        wrong_witness,
        &authority,
    )
    .await
    .unwrap()
    .is_none());
    assert_ne!(wrong_request, request);

    let (exact_witness, exact_request) =
        lock_creation_scope(&mut load_transaction, &request.roster).await;
    assert_eq!(exact_request, request);
    let (loaded, decision) =
        load_fallback_relationship_projection(&mut load_transaction, exact_witness, &authority)
            .await
            .unwrap()
            .expect("exact fresh fallback survives pool restart");
    assert_eq!(loaded.projection_id(), projection_id);
    assert_eq!(loaded.projection_revision(), expected_revision);
    assert_eq!(loaded.scope(), &ProjectionScope::Admission(request.clone()));
    assert_eq!(
        relationship_policy::consume_admission_projection(
            &loaded,
            ProjectionOperationScope::Creation,
            &request,
            &authority,
            &decision,
            false,
        ),
        Ok(())
    );
    load_transaction.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "root fresh-database authorization required"]
async fn failed_child_insert_leaves_no_partial_projection() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let (_authority, _request, _trusted_now, mut persisted) = relationship_fallback(&pool).await;
    let projection_id = uuid::Uuid::parse_str(&persisted.projection_id).unwrap();
    persisted.declarations[0].recipient = "not-a-did".into();

    let mut transaction = pool.begin().await.unwrap();
    assert!(persist_relationship_projection(&mut transaction, persisted)
        .await
        .is_err());
    transaction.rollback().await.unwrap();

    let residue: i64 = sqlx::query_scalar(
        r#"
        SELECT
          (SELECT count(*) FROM chat.relationship_projection_snapshots WHERE projection_id=$1)
        + (SELECT count(*) FROM chat.relationship_projection_declarations WHERE projection_id=$1)
        + (SELECT count(*) FROM chat.relationship_projection_relationships WHERE projection_id=$1)
        "#,
    )
    .bind(projection_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(residue, 0);
}

#[tokio::test]
#[ignore = "root fresh-database authorization required"]
async fn traffic_fallback_hydrates_exact_scope_and_freshness_after_restart() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let (authority, scope, _trusted_now, mut persisted) = traffic_fallback(&pool).await;
    let projection_id = uuid::Uuid::parse_str(&persisted.projection_id).unwrap();
    let expected_revision = persisted.projection_revision;
    persisted.relationships.reverse();

    let mut transaction = pool.begin().await.unwrap();
    persist_traffic_projection(&mut transaction, persisted)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    persist_principal_read_set(&pool, &scope.members).await;
    let wrong_members = (200..232).map(did).collect::<Vec<_>>();
    persist_principal_read_set(&pool, &wrong_members).await;

    // Seed a second traffic snapshot under a DISTINCT scope whose `completed_at`
    // is backdated 61s so the loader's post-lock freshness guard
    // (`observed_at - completed_at > 60s`) must reject it as stale. This gives
    // the freshness-rejection assertion below a genuinely stale row to drop,
    // replacing the unsatisfiable `stale_time_witness` block left over from the
    // removed injectable-now loader signature.
    let mut backdated_members = (300..332).map(did).collect::<Vec<_>>();
    backdated_members.sort();
    let backdated_live = relationship_policy::collect_traffic_projection(
        &authority,
        &StepClock::backdated(61),
        allocated_revision(&pool).await,
        backdated_members[0].clone(),
        backdated_members,
    )
    .await
    .unwrap();
    let backdated_scope = backdated_live.scope().clone();
    let backdated_persisted = backdated_live
        .export_persisted_fallback(
            allocated_revision(&pool).await,
            &authority,
            &persistence_at(backdated_live.completed_at()),
        )
        .unwrap();
    let mut backdated_transaction = pool.begin().await.unwrap();
    persist_traffic_projection(&mut backdated_transaction, backdated_persisted)
        .await
        .unwrap();
    backdated_transaction.commit().await.unwrap();
    persist_principal_read_set(&pool, &backdated_scope.members).await;

    let mut future_members = (400..432).map(did).collect::<Vec<_>>();
    future_members.sort();
    let future_live = relationship_policy::collect_traffic_projection(
        &authority,
        &StepClock::anchored(Utc::now() + TimeDelta::seconds(120)),
        allocated_revision(&pool).await,
        future_members[0].clone(),
        future_members,
    )
    .await
    .unwrap();
    let future_scope = future_live.scope().clone();
    let future_persisted = future_live
        .export_persisted_fallback(
            allocated_revision(&pool).await,
            &authority,
            &persistence_at(future_live.completed_at()),
        )
        .unwrap();
    let mut future_transaction = pool.begin().await.unwrap();
    persist_traffic_projection(&mut future_transaction, future_persisted)
        .await
        .unwrap();
    future_transaction.commit().await.unwrap();
    persist_principal_read_set(&pool, &future_scope.members).await;

    pool.close().await;

    let restarted = common::chat_protocol::setup_chat_protocol_db(2).await;
    let mut stale_transaction = restarted.begin().await.unwrap();
    let (stale_witness, stale_scope) =
        lock_traffic_scope(&mut stale_transaction, &scope.members).await;
    assert_eq!(stale_scope, scope);
    stale_transaction.rollback().await.unwrap();

    let mut load_transaction = restarted.begin().await.unwrap();
    assert!(
        load_fallback_traffic_projection(&mut load_transaction, stale_witness, &authority,)
            .await
            .is_err()
    );

    let (wrong_witness, wrong_scope) =
        lock_traffic_scope(&mut load_transaction, &wrong_members).await;
    let (wrong_recollected, wrong_decision) =
        load_fallback_traffic_projection(&mut load_transaction, wrong_witness, &authority)
            .await
            .unwrap()
            .expect("missing traffic snapshot is recollected");
    assert_ne!(wrong_scope, scope);
    assert_eq!(wrong_recollected.scope(), &wrong_scope);
    assert_eq!(
        relationship_policy::consume_traffic_projection(
            &wrong_recollected,
            &authority,
            &wrong_decision,
        ),
        Ok(())
    );

    // Freshness is enforced from the loader's own post-lock observation clock
    // (`observed_at - completed_at > 60s`); the loader no longer accepts an
    // injected instant. Exercise the rejection path by locking the distinct
    // scope seeded above whose `completed_at` is backdated 61s: the guard must
    // drop it even though its scope, read-set, and witness transaction are all
    // exact.
    let (backdated_witness, backdated_lock_scope) =
        lock_traffic_scope(&mut load_transaction, &backdated_scope.members).await;
    assert_eq!(backdated_lock_scope, backdated_scope);
    let (refreshed, refreshed_decision) =
        load_fallback_traffic_projection(&mut load_transaction, backdated_witness, &authority)
            .await
            .unwrap()
            .expect("stale traffic snapshot is recollected");
    assert_eq!(refreshed.scope(), &backdated_scope);
    assert_ne!(refreshed.projection_id(), backdated_live.projection_id());
    assert_eq!(
        relationship_policy::consume_traffic_projection(
            &refreshed,
            &authority,
            &refreshed_decision,
        ),
        Ok(())
    );

    let (future_witness, future_lock_scope) =
        lock_traffic_scope(&mut load_transaction, &future_scope.members).await;
    assert_eq!(future_lock_scope, future_scope);
    assert!(
        load_fallback_traffic_projection(&mut load_transaction, future_witness, &authority)
            .await
            .is_err(),
        "future-dated traffic evidence must never be classified as fresh"
    );

    let (exact_witness, exact_scope) =
        lock_traffic_scope(&mut load_transaction, &scope.members).await;
    assert_eq!(exact_scope, scope);
    let (loaded, decision) =
        load_fallback_traffic_projection(&mut load_transaction, exact_witness, &authority)
            .await
            .unwrap()
            .expect("exact fresh traffic fallback survives pool restart");
    assert_eq!(loaded.projection_id(), projection_id);
    assert_eq!(loaded.projection_revision(), expected_revision);
    assert_eq!(loaded.scope(), &scope);
    assert_eq!(
        relationship_policy::consume_traffic_projection(&loaded, &authority, &decision,),
        Ok(())
    );
    load_transaction.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "root fresh-database authorization required"]
async fn missing_traffic_fallback_recollection_preserves_block_denial() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let members = roster(2);
    persist_principal_read_set(&pool, &members).await;
    let authority = blocked_authority();
    let mut transaction = pool.begin().await.unwrap();
    let (witness, expected_scope) = lock_traffic_scope(&mut transaction, &members).await;
    let (projection, decision) =
        load_fallback_traffic_projection(&mut transaction, witness, &authority)
            .await
            .unwrap()
            .expect("missing blocked traffic scope is recollected");
    assert_eq!(projection.scope(), &expected_scope);
    assert_eq!(
        relationship_policy::consume_traffic_projection(
            &projection,
            &authority,
            &decision,
        ),
        Err(PolicyDenial::BlockedRelationship)
    );
    transaction.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "root fresh-database authorization required"]
async fn zero_call_traffic_fallback_hydrates_after_restart() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let authority = authority();
    let actor = did(0);
    let live = relationship_policy::collect_traffic_projection(
        &authority,
        &StepClock::new(),
        allocated_revision(&pool).await,
        actor.clone(),
        vec![actor.clone()],
    )
    .await
    .unwrap();
    let persisted = live
        .export_persisted_fallback(
            allocated_revision(&pool).await,
            &authority,
            &persistence_at(live.completed_at()),
        )
        .unwrap();
    assert_eq!(persisted.source_call_count, 0);
    assert!(persisted.relationships.is_empty());

    let mut transaction = pool.begin().await.unwrap();
    persist_traffic_projection(&mut transaction, persisted)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    persist_principal_read_set(&pool, std::slice::from_ref(&actor)).await;
    pool.close().await;

    let restarted = common::chat_protocol::setup_chat_protocol_db(2).await;
    let mut load_transaction = restarted.begin().await.unwrap();
    let (witness, scope) =
        lock_traffic_scope(&mut load_transaction, std::slice::from_ref(&actor)).await;
    let (loaded, decision) =
        load_fallback_traffic_projection(&mut load_transaction, witness, &authority)
            .await
            .unwrap()
            .expect("zero-call traffic fallback survives pool restart");
    assert_eq!(loaded.scope(), &scope);
    relationship_policy::consume_traffic_projection(&loaded, &authority, &decision).unwrap();
    load_transaction.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "root fresh-database authorization required"]
async fn sequence_is_unique_across_concurrency_restarts_and_rollback_gaps() {
    let pool = common::chat_protocol::setup_chat_protocol_db(8).await;
    let authority = Arc::new(authority());
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let pool = pool.clone();
        let authority = Arc::clone(&authority);
        tasks.push(tokio::spawn(async move {
            let guard = allocated_revision(&pool).await;
            let actor = did(0);
            let live = relationship_policy::collect_traffic_projection(
                authority.as_ref(),
                &StepClock::new(),
                guard,
                actor.clone(),
                vec![actor],
            )
            .await
            .unwrap();
            let revision = live.projection_revision();
            let persisted = live
                .export_persisted(authority.as_ref(), &persistence_at(live.completed_at()))
                .unwrap();
            let mut transaction = pool.begin().await.unwrap();
            persist_traffic_projection(&mut transaction, persisted)
                .await
                .unwrap();
            transaction.commit().await.unwrap();
            revision
        }));
    }
    let mut revisions = BTreeSet::new();
    for task in tasks {
        assert!(
            revisions.insert(task.await.unwrap()),
            "sequence revision reused"
        );
    }
    assert_eq!(revisions.len(), 16);

    let before_gap: i64 = sqlx::query_scalar(
        "SELECT last_value::bigint FROM chat.relationship_projection_revision_seq",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let mut rolled_back = pool.begin().await.unwrap();
    let burned = allocate_projection_revision(&mut rolled_back)
        .await
        .unwrap();
    drop(burned);
    rolled_back.rollback().await.unwrap();
    pool.close().await;

    let mut previous = u64::try_from(before_gap).unwrap();
    for _ in 0..3 {
        let restarted = common::chat_protocol::setup_chat_protocol_db(2).await;
        let guard = allocated_revision(&restarted).await;
        let actor = did(0);
        let live = relationship_policy::collect_traffic_projection(
            authority.as_ref(),
            &StepClock::new(),
            guard,
            actor.clone(),
            vec![actor],
        )
        .await
        .unwrap();
        assert!(live.projection_revision() > previous);
        previous = live.projection_revision();
        restarted.close().await;
    }
    assert!(
        previous >= u64::try_from(before_gap).unwrap() + 4,
        "rolled-back nextval did not leave the required sequence gap"
    );
}

#[tokio::test]
#[ignore = "root fresh-database authorization required"]
async fn burned_unused_revision_below_high_water_cannot_be_persisted() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;

    let mut burned_tx = pool.begin().await.unwrap();
    let (burned_allocation_id, burned_revision): (uuid::Uuid, i64) = sqlx::query_as(
        "SELECT allocation_id, projection_revision FROM chat.allocate_relationship_projection_revision()",
    )
    .fetch_one(&mut *burned_tx)
    .await
    .unwrap();
    burned_tx.rollback().await.unwrap();

    let (_later_allocation_id, later_revision): (uuid::Uuid, i64) = sqlx::query_as(
        "SELECT allocation_id, projection_revision FROM chat.allocate_relationship_projection_revision()",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        burned_revision < later_revision,
        "negative case must exercise a burned revision below sequence high-water"
    );

    let projection_id = uuid::Uuid::new_v4();
    let error = sqlx::query(
        r#"
        INSERT INTO chat.relationship_projection_snapshots(
            projection_id, projection_allocation_id, projection_revision,
            operation_scope, canonical_did_set_bytes, canonical_did_set_sha256,
            scope_digest, appview_base, configuration_fingerprint,
            aggregate_evidence_bytes, aggregate_evidence_sha256,
            source_call_count, evidence_kind, started_at, completed_at
        ) VALUES(
            $1, $2, $3, 'traffic', $4, digest($4, 'sha256'),
            digest('burned-scope', 'sha256'), 'https://public.api.bsky.app',
            digest('fixed-config', 'sha256'), $5, digest($5, 'sha256'),
            0, 'fallback', clock_timestamp(), clock_timestamp()
        )
        "#,
    )
    .bind(projection_id)
    .bind(burned_allocation_id)
    .bind(burned_revision)
    .bind(b"CBDID001\0\0".as_slice())
    .bind(b"burned-allocation-evidence".as_slice())
    .execute(&pool)
    .await
    .expect_err("a rolled-back allocation identity must not be revived below high-water");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("23514")
    );
    assert!(
        error
            .as_database_error()
            .map(|error| error.message().contains("allocation"))
            .unwrap_or(false),
        "unexpected burned-allocation error: {error}"
    );

    let residue: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.relationship_projection_snapshots WHERE projection_id=$1)",
    )
    .bind(projection_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!residue);
}
