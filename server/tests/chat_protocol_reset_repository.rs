//! Focused authority-boundary tests for the clean-chat Reset repository.
//!
//! Run live cases against the dedicated clean-chat database:
//!   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_reset_repository -- --test-threads=1

#![allow(dead_code)]

#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../src/chat_protocol/relationship_policy.rs"]
mod relationship_policy_source;
#[allow(dead_code)]
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[allow(dead_code)]
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

mod repository {
    pub(crate) use crate::chat_protocol::repository::*;
}

mod chat_protocol {
    pub mod model {
        pub use crate::model::*;
    }
    pub mod validation {
        pub use crate::validation::*;
    }
    pub mod transcript {
        pub use crate::transcript::*;
    }
    pub mod snapshot {
        pub use catbird_server::chat_protocol::snapshot::*;
    }
    pub mod wire {
        pub use catbird_server::chat_protocol::wire::*;
    }
    pub mod public_state {
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/public_state.rs"
        ));
    }
    pub mod dpop {
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/dpop.rs"
        ));
    }
    // `mint_signed_repository_authority` is `pub(super)` in `dpop.rs`, so after the
    // relocation it is visible here but not at this test crate's root, and a `use`
    // re-export cannot widen it (E0364). Forward it from the level where it is
    // already in scope rather than relocating its caller.
    pub(crate) fn mint_signed_repository_authority(
        pre_replay: dpop::PreReplayCryptographicVerification,
        canonical: transcript::CanonicalSignedMutation,
        stored_public_key: &[u8],
        repository_receipt: repository::auth::RepositoryAuthorityReceipt,
    ) -> Result<dpop::VerifiedChatDeviceRequest, model::AuthPrimitiveError> {
        dpop::mint_signed_repository_authority(
            pre_replay,
            canonical,
            stored_public_key,
            repository_receipt,
        )
    }
    pub mod relationship_policy {
        pub use crate::relationship_policy_source::*;
    }
    pub mod repository {
        pub mod auth {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/auth.rs"
            ));
        }
        pub mod prelude {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/prelude.rs"
            ));
        }
        pub mod relationship {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/relationship.rs"
            ));
        }
        pub mod core {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/core.rs"
            ));
        }
        #[allow(dead_code)]
        pub mod reset {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/reset.rs"
            ));

            #[derive(Clone, Copy, Debug)]
            pub(crate) enum PendingResetCasExpectationMutation {
                ResetRequestId,
                ConversationId,
                RequesterDid,
                RequesterDeviceId,
                RequesterKeyId,
                RequesterAuthGeneration,
                PriorGeneration,
                PriorStateVersion,
                PriorGroupId,
                PriorEpoch,
                PriorGroupContextHash,
                PriorConfirmationTag,
                Reason,
                SignedRequestBytes,
                SigningTranscriptBytes,
                RequestDigest,
                Signature,
                ReceivedAt,
                ExpiresAt,
            }

            pub(crate) const ALL_PENDING_RESET_CAS_EXPECTATION_MUTATIONS:
                [PendingResetCasExpectationMutation; 19] = [
                PendingResetCasExpectationMutation::ResetRequestId,
                PendingResetCasExpectationMutation::ConversationId,
                PendingResetCasExpectationMutation::RequesterDid,
                PendingResetCasExpectationMutation::RequesterDeviceId,
                PendingResetCasExpectationMutation::RequesterKeyId,
                PendingResetCasExpectationMutation::RequesterAuthGeneration,
                PendingResetCasExpectationMutation::PriorGeneration,
                PendingResetCasExpectationMutation::PriorStateVersion,
                PendingResetCasExpectationMutation::PriorGroupId,
                PendingResetCasExpectationMutation::PriorEpoch,
                PendingResetCasExpectationMutation::PriorGroupContextHash,
                PendingResetCasExpectationMutation::PriorConfirmationTag,
                PendingResetCasExpectationMutation::Reason,
                PendingResetCasExpectationMutation::SignedRequestBytes,
                PendingResetCasExpectationMutation::SigningTranscriptBytes,
                PendingResetCasExpectationMutation::RequestDigest,
                PendingResetCasExpectationMutation::Signature,
                PendingResetCasExpectationMutation::ReceivedAt,
                PendingResetCasExpectationMutation::ExpiresAt,
            ];

            pub(crate) fn scope_rows_for_test(
                prelude: &PreparedBusinessPrelude,
            ) -> Vec<(String, Uuid, Option<String>)> {
                let scope = prelude.scope_authority();
                let mut rows = scope
                    .keys()
                    .iter()
                    .map(|key| {
                        (
                            key.user_did().to_owned(),
                            key.device_id(),
                            Some(key.key_id().to_owned()),
                        )
                    })
                    .collect::<Vec<_>>();
                for device in scope.devices() {
                    if !rows
                        .iter()
                        .any(|row| row.0 == device.user_did() && row.1 == device.device_id())
                    {
                        rows.push((device.user_did().to_owned(), device.device_id(), None));
                    }
                }
                rows.sort();
                rows
            }

            pub(crate) fn activation_request_for_test(
                authority: LockedResetActivationAuthority,
            ) -> LockedPendingResetRequestGuard {
                authority.request
            }

            pub(crate) fn authority_prior_for_test(
                authority: &LockedResetRequestAuthority,
            ) -> Option<PublicGroupSnapshotCoordinate> {
                authority.aggregate.head().prior_coordinate().cloned()
            }

            pub(crate) fn corrupt_guard_trusted_instant_for_test(
                mut guard: LockedPendingResetRequestGuard,
            ) -> LockedPendingResetRequestGuard {
                guard.trusted_instant += Duration::milliseconds(1);
                guard
            }

            pub(crate) fn mutate_pending_reset_cas_expectation_for_test(
                mut guard: LockedPendingResetRequestGuard,
                mutation: PendingResetCasExpectationMutation,
            ) -> LockedPendingResetRequestGuard {
                match mutation {
                    PendingResetCasExpectationMutation::ResetRequestId => {
                        guard.reset_request_id = Uuid::new_v4()
                    }
                    PendingResetCasExpectationMutation::ConversationId => {
                        guard.conversation_id = Uuid::new_v4()
                    }
                    PendingResetCasExpectationMutation::RequesterDid => {
                        guard.requester_did = "did:plc:casdriftfixtureaaaaaaaa"
                            .to_owned()
                            .into_boxed_str()
                    }
                    PendingResetCasExpectationMutation::RequesterDeviceId => {
                        guard.requester_device_id = Uuid::new_v4()
                    }
                    PendingResetCasExpectationMutation::RequesterKeyId => {
                        guard.requester_key_id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                            .to_owned()
                            .into_boxed_str()
                    }
                    PendingResetCasExpectationMutation::RequesterAuthGeneration => {
                        guard.requester_auth_generation += 1
                    }
                    PendingResetCasExpectationMutation::PriorGeneration => {
                        guard.prior = PublicGroupSnapshotCoordinate::new(
                            *guard.prior.conversation_id(),
                            guard.prior.generation() + 1,
                            guard.prior.state_version(),
                            *guard.prior.group_id(),
                            guard.prior.epoch(),
                            *guard.prior.group_context_hash(),
                            *guard.prior.confirmation_tag(),
                            guard.prior.lifecycle(),
                        )
                    }
                    PendingResetCasExpectationMutation::PriorStateVersion => {
                        guard.prior = PublicGroupSnapshotCoordinate::new(
                            *guard.prior.conversation_id(),
                            guard.prior.generation(),
                            guard.prior.state_version() + 1,
                            *guard.prior.group_id(),
                            guard.prior.epoch(),
                            *guard.prior.group_context_hash(),
                            *guard.prior.confirmation_tag(),
                            guard.prior.lifecycle(),
                        )
                    }
                    PendingResetCasExpectationMutation::PriorGroupId => {
                        let mut value = *guard.prior.group_id();
                        value[0] ^= 1;
                        guard.prior = PublicGroupSnapshotCoordinate::new(
                            *guard.prior.conversation_id(),
                            guard.prior.generation(),
                            guard.prior.state_version(),
                            value,
                            guard.prior.epoch(),
                            *guard.prior.group_context_hash(),
                            *guard.prior.confirmation_tag(),
                            guard.prior.lifecycle(),
                        )
                    }
                    PendingResetCasExpectationMutation::PriorEpoch => {
                        guard.prior = PublicGroupSnapshotCoordinate::new(
                            *guard.prior.conversation_id(),
                            guard.prior.generation(),
                            guard.prior.state_version(),
                            *guard.prior.group_id(),
                            guard.prior.epoch() + 1,
                            *guard.prior.group_context_hash(),
                            *guard.prior.confirmation_tag(),
                            guard.prior.lifecycle(),
                        )
                    }
                    PendingResetCasExpectationMutation::PriorGroupContextHash => {
                        let mut value = *guard.prior.group_context_hash();
                        value[0] ^= 1;
                        guard.prior = PublicGroupSnapshotCoordinate::new(
                            *guard.prior.conversation_id(),
                            guard.prior.generation(),
                            guard.prior.state_version(),
                            *guard.prior.group_id(),
                            guard.prior.epoch(),
                            value,
                            *guard.prior.confirmation_tag(),
                            guard.prior.lifecycle(),
                        )
                    }
                    PendingResetCasExpectationMutation::PriorConfirmationTag => {
                        let mut value = *guard.prior.confirmation_tag();
                        value[0] ^= 1;
                        guard.prior = PublicGroupSnapshotCoordinate::new(
                            *guard.prior.conversation_id(),
                            guard.prior.generation(),
                            guard.prior.state_version(),
                            *guard.prior.group_id(),
                            guard.prior.epoch(),
                            *guard.prior.group_context_hash(),
                            value,
                            guard.prior.lifecycle(),
                        )
                    }
                    PendingResetCasExpectationMutation::Reason => {
                        guard.reason = "poisonedState".to_owned().into_boxed_str()
                    }
                    PendingResetCasExpectationMutation::SignedRequestBytes => {
                        guard.signed_request_bytes[0] ^= 1
                    }
                    PendingResetCasExpectationMutation::SigningTranscriptBytes => {
                        guard.signing_transcript_bytes[0] ^= 1
                    }
                    PendingResetCasExpectationMutation::RequestDigest => {
                        guard.request_digest[0] ^= 1
                    }
                    PendingResetCasExpectationMutation::Signature => guard.signature[0] ^= 1,
                    PendingResetCasExpectationMutation::ReceivedAt => {
                        guard.received_at += Duration::milliseconds(1)
                    }
                    PendingResetCasExpectationMutation::ExpiresAt => {
                        guard.expires_at += Duration::milliseconds(1)
                    }
                }

                let row = PendingResetRow {
                    reset_request_id: guard.reset_request_id,
                    conversation_id: guard.conversation_id,
                    requester_did: guard.requester_did.to_string(),
                    requester_device_id: guard.requester_device_id,
                    requester_key_id: guard.requester_key_id.to_string(),
                    requester_auth_generation: guard.requester_auth_generation,
                    prior_generation: i64::try_from(guard.prior.generation()).unwrap(),
                    prior_state_version: i64::try_from(guard.prior.state_version()).unwrap(),
                    prior_group_id: guard.prior.group_id().to_vec(),
                    prior_epoch: i64::try_from(guard.prior.epoch()).unwrap(),
                    prior_group_context_hash: guard.prior.group_context_hash().to_vec(),
                    prior_confirmation_tag: guard.prior.confirmation_tag().to_vec(),
                    reason: guard.reason.to_string(),
                    status: "pending".to_owned(),
                    signed_request_bytes: guard.signed_request_bytes.to_vec(),
                    signing_transcript_bytes: guard.signing_transcript_bytes.to_vec(),
                    request_digest: guard.request_digest.to_vec(),
                    signature: guard.signature.to_vec(),
                    received_at: guard.received_at,
                    expires_at: guard.expires_at,
                    terminal_transition_id: None,
                    terminal_at: None,
                };
                guard.immutable_row_digest = reset_immutable_row_digest(&row, &guard.prior);
                guard.guard_digest = locked_pending_reset_digest(
                    &guard.transaction_id,
                    guard.trusted_instant,
                    &guard.scope_digest,
                    &guard.head_digest,
                    &guard.immutable_row_digest,
                    &guard.requester_device_digest,
                    &guard.requester_key_digest,
                    guard.authorized_terminal,
                );
                guard
            }
        }
        pub mod transition {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/transition.rs"
            ));
        }
        pub mod recovery {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/recovery.rs"
            ));
        }
        pub mod delivery {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/delivery.rs"
            ));
        }
        pub mod execution_context {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/execution_context.rs"
            ));
        }
        pub mod blobs {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/blobs.rs"
            ));
        }
        pub mod key_packages {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/key_packages.rs"
            ));
        }
    }
    pub mod state_machine {
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/state_machine.rs"
        ));
    }
}

mod common;

use std::sync::{Arc, OnceLock};

use base64::{engine::general_purpose::STANDARD, Engine};
use chat_protocol::{
    repository::{
        auth::{
            recheck_existing_business_authority_for_test, AuthRepositoryError,
            RepositoryAuthorityClass,
        },
        core::hydrate_locked_conversation_state,
        prelude::{
            arbitrate_operation, prepare_identity_scope_prelude, OperationArbitration,
            PreparedBusinessPrelude, ResetOperationClaimMutationForTest,
        },
        reset::{
            self, LockedPendingResetRequestGuard, LockedResetRequestDisposition,
            PendingResetCryptographicBindingMutationForTest, ResetCompositionError,
            ResetRepositoryError, ALL_PENDING_RESET_CAS_EXPECTATION_MUTATIONS,
        },
    },
    snapshot::{PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle},
    transcript::{
        build_verified_control_entry, decode_and_verify_signed_mutation,
        decode_canonical_signed_mutation, CanonicalControlEntryProducts,
        CanonicalControlServerFields, ControlEntryKind, SignedMutationKind, VerifiedControlEntry,
        VerifiedMutationProjection, VerifiedSignedMutation,
    },
    validation::{
        ed25519_key_id, CanonicalTimestamp, CanonicalUuidV4, TrustedRequestInstant,
        ValidatedChatNsid,
    },
};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, Acquire, PgPool, Postgres, Transaction};
use tokio::sync::{Mutex, Notify};
use uuid::Uuid;

const ALICE_DID: &str = "did:plc:alicefixtureaaaaaaaaaaaa";
const ALICE_DEVICE: &str = "2f93a82d-b061-4c75-8f61-57f23146b910";
const ALICE_SIGNING_SEED: [u8; 32] = [
    0x38, 0x8f, 0x37, 0x73, 0x57, 0x9e, 0x8a, 0x2b, 0x5d, 0x57, 0x2d, 0x3b, 0x19, 0x85, 0x55, 0xa6,
    0x93, 0x6f, 0xb7, 0xf0, 0x13, 0xb8, 0x58, 0xe2, 0x69, 0xf6, 0x4f, 0x6e, 0x8c, 0x6b, 0x12, 0x8d,
];
static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, sqlx::FromRow)]
struct ResetFixture {
    conversation_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
    actor_dpop_jkt: String,
    actor_key_id: String,
    signing_public_key: Vec<u8>,
    auth_generation: i64,
    conversation_kind: String,
    generation: i64,
    state_version: i64,
    group_id: Vec<u8>,
    epoch: i64,
    group_context_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
}

impl ResetFixture {
    fn prior(&self) -> PublicGroupSnapshotCoordinate {
        PublicGroupSnapshotCoordinate::new(
            *self.conversation_id.as_bytes(),
            self.generation.try_into().unwrap(),
            self.state_version.try_into().unwrap(),
            self.group_id.as_slice().try_into().unwrap(),
            self.epoch.try_into().unwrap(),
            self.group_context_hash.as_slice().try_into().unwrap(),
            self.confirmation_tag.as_slice().try_into().unwrap(),
            PublicGroupSnapshotLifecycle::Active,
        )
    }
}

fn pure_reset_fixture() -> ResetFixture {
    let signing_public_key = SigningKey::from_bytes(&ALICE_SIGNING_SEED)
        .verifying_key()
        .to_bytes()
        .to_vec();
    ResetFixture {
        conversation_id: Uuid::parse_str("d0cb7273-b90d-44aa-985d-8a68c13a18bd").unwrap(),
        actor_did: ALICE_DID.to_owned(),
        actor_device_id: Uuid::parse_str(ALICE_DEVICE).unwrap(),
        actor_dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        actor_key_id: ed25519_key_id(&signing_public_key)
            .unwrap()
            .as_str()
            .to_owned(),
        signing_public_key,
        auth_generation: 1,
        conversation_kind: "group".to_owned(),
        generation: 1,
        state_version: 1,
        group_id: vec![1; 32],
        epoch: 1,
        group_context_hash: vec![2; 32],
        confirmation_tag: vec![3; 32],
    }
}

async fn pool() -> PgPool {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must explicitly name the dedicated clean-chat database");
    common::chat_protocol::validate_chat_protocol_database_url(Some(&url))
        .expect("unsafe clean-chat Reset repository test database");
    PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("connect without creating, migrating, or cleaning")
}

async fn trusted_now(tx: &mut Transaction<'_, Postgres>) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT date_trunc('milliseconds',clock_timestamp())")
        .fetch_one(&mut **tx)
        .await
        .unwrap()
}

async fn fixture(tx: &mut Transaction<'_, Postgres>, has_pending_welcome: bool) -> ResetFixture {
    let rows: Vec<ResetFixture> = sqlx::query_as(
        r#"
        SELECT c.conversation_id,p.user_did actor_did,d.device_id actor_device_id,
               d.dpop_jkt actor_dpop_jkt,
               k.key_id actor_key_id,k.signing_public_key,d.auth_generation,
               c.kind conversation_kind,
               s.generation,s.state_version,
               s.group_id,s.epoch,s.group_context_hash,s.confirmation_tag
          FROM chat.conversations c
          JOIN chat.participants p ON p.conversation_id=c.conversation_id
               AND p.current_membership AND p.role='admin'
          JOIN chat.devices d ON d.user_did=p.user_did AND d.device_id=$1 AND d.status='active'
          JOIN chat.device_keys k ON k.user_did=d.user_did AND k.device_id=d.device_id
               AND k.revoked_at IS NULL
          JOIN chat.generation_states s ON s.conversation_id=c.conversation_id
               AND s.generation=c.current_generation AND s.state_version=c.current_state_version
         WHERE c.lifecycle='active' AND p.user_did=$2
           AND NOT EXISTS (SELECT 1 FROM chat.reset_requests r
                            WHERE r.conversation_id=c.conversation_id AND r.status='pending')
           AND $3 = EXISTS (
               SELECT 1 FROM chat.welcome_bundles wb
               JOIN chat.welcome_deliveries wd USING(welcome_id)
               WHERE wb.conversation_id=c.conversation_id AND wd.status='pending')
         ORDER BY c.created_at DESC LIMIT 128
        "#,
    )
    .bind(Uuid::parse_str(ALICE_DEVICE).unwrap())
    .bind(ALICE_DID)
    .bind(has_pending_welcome)
    .fetch_all(&mut **tx)
    .await
    .expect("coherent active Reset fixture");
    let row = if has_pending_welcome {
        rows.into_iter().next()
    } else {
        let probe_at = trusted_now(tx).await;
        let mut selected = None;
        for candidate in rows {
            let mut probe = (&mut **tx).begin().await.unwrap();
            let hydrated =
                hydrate_locked_conversation_state(&mut probe, candidate.conversation_id, probe_at)
                    .await
                    .is_ok();
            probe.rollback().await.unwrap();
            if hydrated {
                selected = Some(candidate);
                break;
            }
        }
        selected
    }
    .expect("full aggregate-hydratable active Reset fixture");
    assert_eq!(
        row.signing_public_key,
        SigningKey::from_bytes(&ALICE_SIGNING_SEED)
            .verifying_key()
            .to_bytes()
    );
    row
}

fn verified_request(
    fixture: &ResetFixture,
    at: DateTime<Utc>,
    mutation: &VerifiedSignedMutation,
) -> chat_protocol::dpop::VerifiedChatDeviceRequest {
    let endpoint = match mutation.projection() {
        VerifiedMutationProjection::ResetRequest(_) => "blue.catbird.chat.requestReset",
        VerifiedMutationProjection::ResetActivation(_) => "blue.catbird.chat.activateReset",
        _ => panic!("reset test helper requires a Reset mutation"),
    };
    let pre_replay = chat_protocol::dpop::repository_test_evidence::ordinary_device_with_binding(
        Uuid::new_v4(),
        *Uuid::new_v4().as_bytes().first_chunk::<12>().unwrap(),
        endpoint,
        &at.to_rfc3339_opts(SecondsFormat::Millis, true),
        &fixture.actor_did,
        fixture.actor_device_id,
        &fixture.actor_dpop_jkt,
    );
    let canonical =
        decode_canonical_signed_mutation(mutation.accepted_wrapper_bytes().unwrap()).unwrap();
    let receipt = chat_protocol::repository::auth::reset_existing_device_receipt_for_test(
        mutation,
        &fixture.actor_dpop_jkt,
        &fixture.signing_public_key,
    )
    .unwrap();
    assert_eq!(receipt.class(), RepositoryAuthorityClass::ExistingDevice);
    chat_protocol::mint_signed_repository_authority(
        pre_replay,
        canonical,
        &fixture.signing_public_key,
        receipt,
    )
    .unwrap()
}

async fn prelude(
    tx: &mut Transaction<'_, Postgres>,
    fixture: &ResetFixture,
    at: DateTime<Utc>,
    mutation: &VerifiedSignedMutation,
) -> PreparedBusinessPrelude {
    let request = verified_request(fixture, at, mutation);
    let scope =
        reset::discover_reset_identity_scope(tx, &request, mutation, fixture.conversation_id)
            .await
            .unwrap();
    let reservation = match arbitrate_operation(tx, &request).await.unwrap() {
        OperationArbitration::First(reservation) => reservation,
        OperationArbitration::Replay(_) => {
            panic!("fresh Reset test operation unexpectedly replayed")
        }
    };
    prepare_identity_scope_prelude(tx, &request, reservation, scope)
        .await
        .unwrap()
}

fn coordinate_json(prior: &PublicGroupSnapshotCoordinate) -> Value {
    let lifecycle = match prior.lifecycle() {
        PublicGroupSnapshotLifecycle::Active => "active",
        PublicGroupSnapshotLifecycle::Superseded => "superseded",
    };
    json!({
        "conversationId": Uuid::from_bytes(*prior.conversation_id()).to_string(),
        "generation": prior.generation(), "stateVersion": prior.state_version(),
        "groupId": STANDARD.encode(prior.group_id()), "epoch": prior.epoch(),
        "groupContextHash": STANDARD.encode(prior.group_context_hash()),
        "confirmationTag": STANDARD.encode(prior.confirmation_tag()), "lifecycle": lifecycle
    })
}

fn signed_reset(
    fixture: &ResetFixture,
    kind: SignedMutationKind,
    request_id: Uuid,
    operation_id: Uuid,
    prior: &PublicGroupSnapshotCoordinate,
    at: DateTime<Utc>,
) -> VerifiedSignedMutation {
    let mut body = serde_json::Map::new();
    body.insert("$type".into(), json!(kind.type_id()));
    body.insert(
        "signatureDomain".into(),
        json!(String::from_utf8(kind.domain().to_vec()).unwrap()),
    );
    body.insert("resetRequestId".into(), json!(request_id.to_string()));
    if kind == SignedMutationKind::ResetActivation {
        body.insert("transitionId".into(), json!(operation_id.to_string()));
        let prior_retired = PublicGroupSnapshotCoordinate::new(
            *prior.conversation_id(),
            prior.generation(),
            prior.state_version() + 1,
            *prior.group_id(),
            prior.epoch(),
            *prior.group_context_hash(),
            *prior.confirmation_tag(),
            PublicGroupSnapshotLifecycle::Superseded,
        );
        let successor = PublicGroupSnapshotCoordinate::new(
            *prior.conversation_id(),
            prior.generation() + 1,
            0,
            [0x71; 32],
            0,
            [0x72; 32],
            [0x73; 32],
            PublicGroupSnapshotLifecycle::Active,
        );
        let group_info = [0x74_u8; 8];
        let ciphertext = [0x75_u8; 16];
        body.insert("conversationKind".into(), json!(fixture.conversation_kind));
        body.insert("retired".into(), coordinate_json(&prior_retired));
        body.insert("successor".into(), coordinate_json(&successor));
        body.insert(
            "manifest".into(),
            json!({
                "participants": [{
                    "userDid": fixture.actor_did,
                    "role": "admin",
                    "status": "active"
                }],
                "actorLeaf": {
                    "userDid": fixture.actor_did,
                    "deviceId": fixture.actor_device_id.to_string(),
                    "leafOrigin": "genesis"
                }
            }),
        );
        body.insert(
            "genesisGroupInfo".into(),
            json!({
                "framing": "mlsMessage",
                "contentType": "groupInfo",
                "bytes": STANDARD.encode(group_info),
                "sha256": STANDARD.encode(Sha256::digest(group_info))
            }),
        );
        body.insert(
            "metadataSnapshot".into(),
            json!({
                "coordinate": {
                    "conversationId": STANDARD.encode(prior.conversation_id()),
                    "generation": successor.generation(),
                    "groupId": STANDARD.encode(successor.group_id()),
                    "epoch": successor.epoch(),
                    "groupContextHash": STANDARD.encode(successor.group_context_hash()),
                    "confirmationTag": STANDARD.encode(successor.confirmation_tag())
                },
                "originTransitionId": operation_id.to_string(),
                "metadataVersion": 1,
                "nonce": STANDARD.encode([0x76_u8; 12]),
                "ciphertext": STANDARD.encode(ciphertext),
                "ciphertextSha256": STANDARD.encode(Sha256::digest(ciphertext)),
                "ciphertextSize": ciphertext.len(),
                "authorProof": {
                    "authorDid": fixture.actor_did,
                    "authorDeviceId": fixture.actor_device_id.to_string(),
                    "authorKeyId": fixture.actor_key_id,
                    "signaturePublicKey": STANDARD.encode(&fixture.signing_public_key),
                    "authGenerationAtOrigin": fixture.auth_generation,
                    "originTransitionId": operation_id.to_string(),
                    "originSeq": 1,
                    "roleAtOrigin": "admin",
                    "deviceStatusAtOrigin": "active"
                }
            }),
        );
    }
    body.insert("actorDid".into(), json!(fixture.actor_did));
    body.insert(
        "actorDeviceId".into(),
        json!(fixture.actor_device_id.to_string()),
    );
    body.insert("keyId".into(), json!(fixture.actor_key_id));
    body.insert("authGeneration".into(), json!(fixture.auth_generation));
    body.insert("prior".into(), coordinate_json(prior));
    if kind == SignedMutationKind::ResetRequest {
        body.insert("reason".into(), json!("manualRecovery"));
    }
    body.insert("idempotencyKey".into(), json!(operation_id.to_string()));
    body.insert(
        "signedAt".into(),
        json!(at.to_rfc3339_opts(SecondsFormat::Millis, true)),
    );
    let mut wrapper =
        json!({"body": Value::Object(body), "signature": STANDARD.encode([0_u8; 64])});
    let canonical =
        decode_canonical_signed_mutation(&serde_json::to_vec(&wrapper).unwrap()).unwrap();
    let signature = SigningKey::from_bytes(&ALICE_SIGNING_SEED)
        .sign(canonical.transcript_bytes())
        .to_bytes();
    wrapper["signature"] = Value::String(STANDARD.encode(signature));
    decode_and_verify_signed_mutation(
        &serde_json::to_vec(&wrapper).unwrap(),
        &fixture.signing_public_key,
    )
    .unwrap()
}

async fn insert_pending(
    tx: &mut Transaction<'_, Postgres>,
    f: &ResetFixture,
    id: Uuid,
    received: DateTime<Utc>,
    request: VerifiedSignedMutation,
) {
    insert_pending_with_signed_columns(tx, f, id, received, request, None).await;
}

struct PendingDurableSignedColumns {
    signed_request_bytes: Vec<u8>,
    signing_transcript_bytes: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
}

impl PendingDurableSignedColumns {
    fn exact(request: &VerifiedSignedMutation) -> Self {
        Self {
            signed_request_bytes: request.accepted_wrapper_bytes().unwrap().to_vec(),
            signing_transcript_bytes: request.transcript_bytes().to_vec(),
            request_digest: request.request_digest().to_vec(),
            signature: request.signature().to_vec(),
        }
    }
}

async fn insert_pending_with_signed_columns(
    tx: &mut Transaction<'_, Postgres>,
    f: &ResetFixture,
    id: Uuid,
    received: DateTime<Utc>,
    request: VerifiedSignedMutation,
    signed_columns: Option<PendingDurableSignedColumns>,
) {
    let seq: i64 = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(f.conversation_id)
    .fetch_one(&mut **tx)
    .await
    .unwrap();
    let kind = ControlEntryKind::ResetRequest;
    let trusted = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&received.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
    );
    let entry = build_verified_control_entry(
        request,
        &ValidatedChatNsid::parse("blue.catbird.chat.requestReset").unwrap(),
        CanonicalUuidV4::parse(&Uuid::new_v4().to_string()).unwrap(),
        CanonicalUuidV4::parse(&f.conversation_id.to_string()).unwrap(),
        seq.try_into().unwrap(),
        &trusted,
        CanonicalControlServerFields::empty(kind).unwrap(),
    )
    .unwrap();
    let products = CanonicalControlEntryProducts::mint(&entry).unwrap();
    let accepted_payload = products.durable_json();
    let accepted_payload_sha256 = Sha256::digest(accepted_payload);
    let mutation = entry.mutation();
    let signed_columns =
        signed_columns.unwrap_or_else(|| PendingDurableSignedColumns::exact(mutation));
    sqlx::query(
        r#"INSERT INTO chat.entries(
          conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
          accepted_payload_sha256,signed_request_bytes,request_digest,signature,
          server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
          actor_key_id,actor_auth_generation,generation,state_version,transition_id,received_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NULL,NULL,NULL,$16)"#,
    )
    .bind(f.conversation_id)
    .bind(seq)
    .bind(Uuid::from_bytes(*entry.entry_id().as_bytes()))
    .bind(kind.type_id())
    .bind(accepted_payload)
    .bind(accepted_payload_sha256.as_slice())
    .bind(&signed_columns.signed_request_bytes)
    .bind(&signed_columns.request_digest)
    .bind(&signed_columns.signature)
    .bind(entry.server_fields_dag_cbor().unwrap())
    .bind(entry.outer_control_fingerprint().as_slice())
    .bind(&f.actor_did)
    .bind(f.actor_device_id)
    .bind(&f.actor_key_id)
    .bind(f.auth_generation)
    .bind(received)
    .execute(&mut **tx)
    .await
    .unwrap();

    sqlx::query(
        r#"INSERT INTO chat.reset_requests(
          reset_request_id,conversation_id,requester_did,requester_device_id,requester_key_id,
          requester_auth_generation,prior_generation,prior_state_version,prior_group_id,prior_epoch,
          prior_group_context_hash,prior_confirmation_tag,reason,status,signed_request_bytes,
          signing_transcript_bytes,request_digest,signature,received_at,expires_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'manualRecovery','pending',
                 $13,$14,$15,$16,$17,$17 + interval '24 hours')"#,
    )
    .bind(id)
    .bind(f.conversation_id)
    .bind(&f.actor_did)
    .bind(f.actor_device_id)
    .bind(&f.actor_key_id)
    .bind(f.auth_generation)
    .bind(f.generation)
    .bind(f.state_version)
    .bind(&f.group_id)
    .bind(f.epoch)
    .bind(&f.group_context_hash)
    .bind(&f.confirmation_tag)
    .bind(&signed_columns.signed_request_bytes)
    .bind(&signed_columns.signing_transcript_bytes)
    .bind(&signed_columns.request_digest)
    .bind(&signed_columns.signature)
    .bind(received)
    .execute(&mut **tx)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE chat.conversations SET next_entry_seq=$2 \
         WHERE conversation_id=$1 AND next_entry_seq=$3",
    )
    .bind(f.conversation_id)
    .bind(seq + 1)
    .bind(seq)
    .execute(&mut **tx)
    .await
    .unwrap();
}

async fn guard(
    tx: &mut Transaction<'_, Postgres>,
    f: &ResetFixture,
    at: DateTime<Utc>,
    request_id: Uuid,
) -> LockedPendingResetRequestGuard {
    let authority = signed_reset(
        f,
        SignedMutationKind::ResetActivation,
        request_id,
        Uuid::new_v4(),
        &f.prior(),
        at,
    );
    let prelude = prelude(tx, f, at, &authority).await;
    reset::activation_request_for_test(
        reset::prepare_reset_activation_authority(tx, prelude, &authority)
            .await
            .unwrap(),
    )
}

fn assert_error<T>(
    result: Result<T, ResetRepositoryError>,
    expected: fn(&ResetRepositoryError) -> bool,
) {
    assert!(
        result.as_ref().err().is_some_and(expected),
        "unexpected error: {:?}",
        result.err()
    );
}

async fn durable_snapshot(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
) -> (i64, i64, i64) {
    sqlx::query_as(
        "SELECT c.next_entry_seq, \
         (SELECT count(*) FROM chat.reset_requests r WHERE r.conversation_id=c.conversation_id), \
         (SELECT count(*) FROM chat.events) \
         FROM chat.conversations c WHERE c.conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&mut **tx)
    .await
    .unwrap()
}

fn rust_raw_literal_end(source: &[u8], start: usize, prefix_len: usize) -> Option<usize> {
    let mut quote = start + prefix_len;
    while source.get(quote) == Some(&b'#') {
        quote += 1;
    }
    if source.get(quote) != Some(&b'"') {
        return None;
    }
    let hashes = quote - (start + prefix_len);
    let mut cursor = quote + 1;
    while cursor < source.len() {
        if source[cursor] == b'"'
            && source.get(cursor + 1..cursor + 1 + hashes) == Some(&source[quote - hashes..quote])
        {
            return Some(cursor + 1 + hashes);
        }
        cursor += 1;
    }
    Some(source.len())
}

fn rust_quoted_literal_end(source: &[u8], quote: usize, delimiter: u8) -> Option<usize> {
    let mut cursor = quote + 1;
    while cursor < source.len() {
        match source[cursor] {
            b'\\' => cursor = (cursor + 2).min(source.len()),
            byte if byte == delimiter => return Some(cursor + 1),
            b'\n' | b'\r' if delimiter == b'\'' => return None,
            _ => cursor += 1,
        }
    }
    (delimiter == b'"').then_some(source.len())
}

fn rust_char_literal_end(source: &str, quote: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let content = quote + 1;
    if bytes.get(content) == Some(&b'\\') {
        return rust_quoted_literal_end(bytes, quote, b'\'');
    }
    let character = source.get(content..)?.chars().next()?;
    let closing_quote = content + character.len_utf8();
    (bytes.get(closing_quote) == Some(&b'\'')).then_some(closing_quote + 1)
}

fn rust_code_without_comments_and_literals(source: &str) -> String {
    fn blank(output: &mut [u8], source: &[u8], start: usize, end: usize) {
        for index in start..end.min(output.len()) {
            if source[index] != b'\n' && source[index] != b'\r' {
                output[index] = b' ';
            }
        }
    }

    fn identifier_boundary(source: &[u8], index: usize) -> bool {
        index == 0 || !(source[index - 1].is_ascii_alphanumeric() || source[index - 1] == b'_')
    }

    let bytes = source.as_bytes();
    let mut output = bytes.to_vec();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes.get(cursor..cursor + 2) == Some(b"//") {
            let end = bytes[cursor + 2..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |relative| cursor + 2 + relative);
            blank(&mut output, bytes, cursor, end);
            cursor = end;
            continue;
        }
        if bytes.get(cursor..cursor + 2) == Some(b"/*") {
            let start = cursor;
            cursor += 2;
            let mut depth = 1_u32;
            while cursor < bytes.len() && depth != 0 {
                if bytes.get(cursor..cursor + 2) == Some(b"/*") {
                    depth += 1;
                    cursor += 2;
                } else if bytes.get(cursor..cursor + 2) == Some(b"*/") {
                    depth -= 1;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            blank(&mut output, bytes, start, cursor);
            continue;
        }

        let boundary = identifier_boundary(bytes, cursor);
        let raw_end = if boundary && bytes.get(cursor..cursor + 2) == Some(b"br") {
            rust_raw_literal_end(bytes, cursor, 2)
        } else if boundary && bytes[cursor] == b'r' {
            rust_raw_literal_end(bytes, cursor, 1)
        } else {
            None
        };
        if let Some(end) = raw_end {
            blank(&mut output, bytes, cursor, end);
            cursor = end;
            continue;
        }

        let quoted = if boundary && bytes.get(cursor..cursor + 2) == Some(b"b\"") {
            rust_quoted_literal_end(bytes, cursor + 1, b'"').map(|end| (cursor, end))
        } else if bytes[cursor] == b'"' {
            rust_quoted_literal_end(bytes, cursor, b'"').map(|end| (cursor, end))
        } else if boundary && bytes.get(cursor..cursor + 2) == Some(b"b'") {
            rust_char_literal_end(source, cursor + 1).map(|end| (cursor, end))
        } else if bytes[cursor] == b'\'' {
            rust_char_literal_end(source, cursor).map(|end| (cursor, end))
        } else {
            None
        };
        if let Some((start, end)) = quoted {
            blank(&mut output, bytes, start, end);
            cursor = end;
        } else {
            cursor += 1;
        }
    }
    String::from_utf8(output).expect("blanking Rust comments and literals preserves UTF-8")
}

fn rust_lock_helper_identifiers(source: &str) -> std::collections::BTreeSet<String> {
    let code = rust_code_without_comments_and_literals(source);
    let bytes = code.as_bytes();
    let mut helpers = std::collections::BTreeSet::new();
    let mut cursor = 0;
    while let Some(relative) = code[cursor..].find("lock_") {
        let start = cursor + relative;
        let boundary =
            start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        let mut end = start + "lock_".len();
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        if boundary && code[end..].trim_start().starts_with('(') {
            helpers.insert(code[start..end].to_owned());
        }
        cursor = end;
    }
    helpers
}

#[test]
fn reset_source_has_no_raw_business_guard_or_duplicate_identity_lock_path() {
    let source = include_str!("../src/chat_protocol/repository/reset.rs");
    for forbidden in [
        "BusinessAuthorityGuard",
        "LockedResetScope",
        "ResetCandidateRow",
        "load_candidate_scope",
        "lock_principals",
        "lock_candidate_devices_and_keys",
    ] {
        assert!(
            !source.contains(forbidden),
            "Reset production source regained forbidden authority seam `{forbidden}`"
        );
    }
    assert!(source.contains("prelude: PreparedBusinessPrelude"));
    assert!(source.contains("scope: &ScopeBoundBusinessAuthority"));
}

#[test]
fn reset_identity_discovery_is_read_only_and_locked_preparation_does_not_relock_identity_rows() {
    let source = include_str!("../src/chat_protocol/repository/reset.rs");
    let discovery = source
        .split_once("pub(crate) async fn discover_reset_identity_scope(")
        .unwrap()
        .1
        .split_once("fn request_contains_exact_mutation(")
        .unwrap()
        .0;
    assert!(!discovery.contains("FOR UPDATE"));

    let preparation = source
        .split_once("async fn prepare_reset_read_set_inner(")
        .unwrap()
        .1
        .split_once("fn validate_sealed_admission(")
        .unwrap()
        .0;
    for forbidden in ["lock_principals", "lock_candidate_devices_and_keys"] {
        assert!(
            !preparation.contains(forbidden),
            "sealed Reset preparation regained identity lock path `{forbidden}`"
        );
    }
    let normalized = preparation
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    for (offset, _) in normalized.match_indices("for update") {
        let context = &normalized[offset.saturating_sub(512)..(offset + 512).min(normalized.len())];
        for identity_table in ["chat.principals", "chat.devices", "chat.device_keys"] {
            assert!(
                !context.contains(identity_table),
                "sealed Reset preparation relocks `{identity_table}` near `{context}`"
            );
        }
    }

    // The first two were the entire allowlist through `1bafb796` ("bind Reset repository to
    // scoped operation authority"). The six below entered together in `32529254` ("compose
    // clean protocol handlers and transition facades") — the same commit that promoted
    // `revokeDevice` from cutover stub to real handler. This guard could not report that
    // expansion at the time because its own test target did not compile, and stayed
    // uncompiled until 2026-08-03; the six are therefore accepted drift from sealed
    // clean-protocol work that this guard never got to review. They are enumerated
    // individually, not collapsed to a count, so the guard still fires on a ninth.
    let allowed = std::collections::BTreeSet::from([
        "lock_head_nowait".to_owned(),
        "lock_operation_and_pending_rows".to_owned(),
        "lock_reset_activation_replay_rows".to_owned(),
        "lock_reset_generation_state".to_owned(),
        "lock_reset_replay_entry".to_owned(),
        "lock_reset_replay_post_state".to_owned(),
        "lock_reset_request_replay_rows".to_owned(),
        "lock_signed_operation_replay_authority".to_owned(),
    ]);
    assert_eq!(
        rust_lock_helper_identifiers(source),
        allowed,
        "Reset gained a non-allowlisted lock-helper path"
    );
}

#[test]
fn reset_lock_helper_scanner_ignores_comments_and_rust_string_literals() {
    let decoys = r####"
        // lock_head_nowait()
        /* lock_operation_and_pending_rows()
           /* lock_nested_decoy() */
        */
        const ORDINARY: &str = "lock_head_nowait()";
        const BYTES: &[u8] = b"lock_operation_and_pending_rows()";
        const RAW: &str = r#"lock_head_nowait()"#;
        const RAW_BYTES: &[u8] = br##"lock_operation_and_pending_rows()"##;
        const CHARACTER: char = 'x';
        const BYTE_CHARACTER: u8 = b'x';
    "####;
    assert!(
        rust_lock_helper_identifiers(decoys).is_empty(),
        "comments or Rust literals masqueraded as real lock-helper code"
    );

    let real_calls = r#"
        fn proof<'a>(_value: &'a str) {
            lock_head_nowait();
            lock_operation_and_pending_rows ();
        }
    "#;
    assert_eq!(
        rust_lock_helper_identifiers(real_calls),
        std::collections::BTreeSet::from([
            "lock_head_nowait".to_owned(),
            "lock_operation_and_pending_rows".to_owned(),
        ])
    );
}

#[test]
fn reset_scope_drift_is_not_an_inner_savepoint_retry() {
    let source = include_str!("../src/chat_protocol/repository/reset.rs");
    let preparation = source
        .split_once("async fn prepare_reset_read_set_inner(")
        .unwrap()
        .1
        .split_once("async fn prepare_reset_attempt(")
        .unwrap()
        .0;
    assert!(preparation.contains("matches!(error, ResetRepositoryError::HeadBusy)"));
    assert!(!preparation.contains("matches!(error, ResetRepositoryError::CandidateScopeDrift)"));
}

#[test]
fn reset_request_fixture_authority_remains_test_only() {
    let source = include_str!("../src/chat_protocol/dpop.rs");
    assert!(source.contains("#[cfg(test)]\npub(crate) mod repository_test_evidence"));
    let fixture_module = source
        .split_once("pub(crate) mod repository_test_evidence")
        .unwrap()
        .1;
    assert!(fixture_module.contains("pub(crate) fn ordinary_device_with_binding("));
}

#[test]
fn reset_receipt_fixture_is_test_only_reset_specific_and_not_forged_by_harness() {
    let auth_source = include_str!("../src/chat_protocol/repository/auth.rs");
    let fixture = auth_source
        .split_once("pub(crate) fn reset_existing_device_receipt_for_test(")
        .unwrap();
    assert!(fixture.0.ends_with("#[cfg(test)]\n"));
    let fixture_body = fixture
        .1
        .split_once("pub(crate) enum AuthorizationOutcome")
        .unwrap()
        .0;
    assert!(fixture_body.contains("VerifiedMutationProjection::ResetRequest"));
    assert!(fixture_body.contains("VerifiedMutationProjection::ResetActivation"));
    assert!(fixture_body.contains("UnsupportedAuthorizationShape"));
    assert!(fixture_body.contains("ed25519_key_id(signing_public_key)"));

    let harness = include_str!("chat_protocol_reset_repository.rs");
    let receipt_struct_literal = ["RepositoryAuthority", "Receipt {"].concat();
    let replay_struct_literal = ["ReplayAudit", "Ids {"].concat();
    assert!(!harness.contains(&receipt_struct_literal));
    assert!(!harness.contains(&replay_struct_literal));
}

#[test]
fn reset_operation_claim_verification_binds_every_exact_authority_dimension() {
    let prelude_source = include_str!("../src/chat_protocol/repository/prelude.rs");
    let reset_verifier = prelude_source
        .split_once("pub(crate) fn verify_reset_operation(")
        .unwrap()
        .1
        .split_once("pub(crate) fn verify_device_revocation_operation(")
        .unwrap()
        .0;
    assert!(reset_verifier.contains("self.verify_exact_operation_claim("));
    assert!(reset_verifier.contains("endpoint.endpoint_nsid()"));
    assert!(reset_verifier.contains("endpoint.mutation_kind()"));

    let exact_claim = prelude_source
        .split_once("fn verify_exact_operation_claim(")
        .unwrap()
        .1
        .split_once("pub(crate) fn into_execution_parts(")
        .unwrap()
        .0;
    for (dimension, fragment) in [
        ("UUIDv4 operation", "operation_id.get_version_num() != 4"),
        (
            "transaction",
            "self.operation.transaction_id != self.authority.transaction_id()",
        ),
        ("operation id", "binding.operation_id != operation_id"),
        (
            "principal",
            "binding.principal_did != mutation.actor_did().as_str()",
        ),
        ("endpoint", "binding.endpoint_nsid != endpoint_nsid"),
        (
            "claimed mutation kind",
            "binding.mutation_kind != mutation_kind.type_id()",
        ),
        ("actual mutation kind", "mutation.kind() != mutation_kind"),
        (
            "request digest",
            "binding.request_digest != *mutation.request_digest()",
        ),
        (
            "accepted wrapper hash",
            "Sha256::digest(accepted_request_bytes)",
        ),
        ("signature", "binding.signature != *mutation.signature()"),
    ] {
        assert!(
            exact_claim.contains(fragment),
            "exact Reset claim omitted {dimension}: `{fragment}`"
        );
    }

    let reset_source = include_str!("../src/chat_protocol/repository/reset.rs");
    assert!(reset_source.contains("ResetOperationEndpoint::RequestReset"));
    assert!(reset_source.contains("ResetOperationEndpoint::ActivateReset"));
    assert_eq!(reset_source.matches(".verify_reset_operation(").count(), 3);
    assert!(reset_source.contains("!uuid_v4(operation_id)"));
    let uuid_v4 = reset_source
        .split_once("fn uuid_v4(")
        .unwrap()
        .1
        .split_once("fn whole_millis(")
        .unwrap()
        .0;
    assert!(uuid_v4.contains("value.get_version_num() == 4"));
    assert!(uuid_v4.contains("value.get_variant() == uuid::Variant::RFC4122"));
}

#[test]
fn reset_operation_claim_runtime_rejects_every_mismatched_dimension() {
    let fixture = pure_reset_fixture();
    let at = DateTime::parse_from_rfc3339("2026-07-28T12:00:00.000Z")
        .unwrap()
        .with_timezone(&Utc);
    let original_id = Uuid::parse_str("992fc634-beb1-49cd-b5c1-f68cc7645424").unwrap();
    let alternate_id = Uuid::parse_str("86db988a-c878-4df0-874b-70e27284ad97").unwrap();
    let original = signed_reset(
        &fixture,
        SignedMutationKind::ResetRequest,
        original_id,
        original_id,
        &fixture.prior(),
        at,
    );
    let alternate = signed_reset(
        &fixture,
        SignedMutationKind::ResetRequest,
        alternate_id,
        alternate_id,
        &fixture.prior(),
        at,
    );
    for mutation in [
        ResetOperationClaimMutationForTest::OperationId,
        ResetOperationClaimMutationForTest::Principal,
        ResetOperationClaimMutationForTest::Transaction,
        ResetOperationClaimMutationForTest::RequestDigest,
        ResetOperationClaimMutationForTest::AcceptedWrapperHash,
        ResetOperationClaimMutationForTest::Signature,
        ResetOperationClaimMutationForTest::PresentedMutation,
        ResetOperationClaimMutationForTest::Endpoint,
        ResetOperationClaimMutationForTest::MutationKind,
    ] {
        assert!(
            chat_protocol::repository::prelude::reset_operation_claim_mutation_rejected_for_test(
                &original,
                &alternate,
                &fixture.actor_dpop_jkt,
                &fixture.signing_public_key,
                mutation,
            ),
            "real Reset claim verifier accepted mutation {mutation:?}"
        );
    }
}

#[test]
fn reset_operation_claim_runtime_fixture_seams_are_test_only_and_reset_specific() {
    let auth_source = include_str!("../src/chat_protocol/repository/auth.rs");
    let auth_fixture = auth_source
        .split_once("pub(super) fn reset_locked_scope_for_claim_test(")
        .unwrap();
    assert!(auth_fixture.0.ends_with("#[cfg(test)]\n"));
    let auth_body = auth_fixture
        .1
        .split_once("pub(crate) async fn recheck_existing_business_authority_for_test(")
        .unwrap()
        .0;
    assert!(auth_body.contains("SignedMutationKind::ResetRequest"));
    assert!(auth_body.contains("SignedMutationKind::ResetActivation"));

    let prelude_source = include_str!("../src/chat_protocol/repository/prelude.rs");
    let prelude_fixture = prelude_source
        .split_once("pub(crate) fn reset_operation_claim_mutation_rejected_for_test(")
        .unwrap();
    assert!(prelude_fixture.0.ends_with("#[cfg(test)]\n"));
    let prelude_body = prelude_fixture
        .1
        .split_once("pub(crate) enum RecoveryOperationEndpoint")
        .unwrap()
        .0;
    assert!(prelude_body.contains(".verify_reset_operation("));
    assert!(!prelude_body.contains("verify_recovery_operation"));
    assert!(!prelude_body.contains("verify_welcome_operation"));
}

#[test]
fn pending_reset_rejects_each_cryptographic_binding_mutation() {
    for mutation in [
        PendingResetCryptographicBindingMutationForTest::ScopeDigest,
        PendingResetCryptographicBindingMutationForTest::RequesterDeviceDigest,
        PendingResetCryptographicBindingMutationForTest::RequesterKeyDigest,
        PendingResetCryptographicBindingMutationForTest::RawPublicKey,
        PendingResetCryptographicBindingMutationForTest::StoredRawPublicKeyHash,
    ] {
        assert!(
            reset::pending_reset_cryptographic_binding_mutation_rejected_for_test(mutation),
            "pending Reset accepted cryptographic binding mutation {mutation:?}"
        );
    }
}

#[test]
fn reset_request_event_payload_is_repository_owned_and_canonical() {
    let reset_request_id = Uuid::from_bytes([
        0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x4a, 0xbc, 0x8d, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a,
        0xbc,
    ]);
    let conversation_id = Uuid::from_bytes([
        0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x47, 0x89, 0x8a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56,
        0x78,
    ]);

    assert_eq!(
        reset::canonical_reset_requested_event_payload(reset_request_id, conversation_id),
        br#"{"$type":"blue.catbird.chat.defs#resetRequestedEvent","resetRequestId":"12345678-1234-4abc-8def-123456789abc","conversationId":"abcdef01-2345-4789-8abc-def012345678"}"#
    );
}

#[test]
fn reset_activation_event_payload_is_repository_owned_and_canonical() {
    let conversation_id = Uuid::from_bytes([
        0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x47, 0x89, 0x8a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56,
        0x78,
    ]);

    assert_eq!(
        reset::canonical_reset_activation_event_payload(conversation_id),
        br#"{"$type":"blue.catbird.chat.defs#conversationChangedEvent","conversationId":"abcdef01-2345-4789-8abc-def012345678"}"#
    );
}

#[test]
fn reset_activation_authority_owns_terminal_recovery_packages() {
    fn typecheck(
        authority: reset::LockedResetActivationAuthority,
        mutation: &VerifiedSignedMutation,
        entry: VerifiedControlEntry,
    ) {
        let _ = authority.plan_reset_activation_entry(mutation, entry);
    }

    let _ = typecheck;
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the ALICE reset fixture corpus"]
async fn reset_scope_locks_full_canonical_device_key_union_before_head() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut contender = pool.begin().await.unwrap();
    let f = fixture(&mut contender, true).await;
    let conversation_id = f.conversation_id;
    let at = trusted_now(&mut contender).await;
    let id = Uuid::new_v4();
    let request = signed_reset(&f, SignedMutationKind::ResetRequest, id, id, &f.prior(), at);
    let prepared_prelude = prelude(&mut contender, &f, at, &request).await;
    let blocked_identity: (String, Uuid) = sqlx::query_as(
        "SELECT wd.recipient_did,wd.recipient_device_id FROM chat.welcome_bundles wb \
         JOIN chat.welcome_deliveries wd USING(welcome_id) \
         WHERE wb.conversation_id=$1 AND wd.status='pending'",
    )
    .bind(conversation_id)
    .fetch_one(&mut *contender)
    .await
    .unwrap();
    assert_ne!(
        blocked_identity,
        (f.actor_did.clone(), f.actor_device_id),
        "lock-order witness requires a non-actor retained Welcome recipient"
    );
    let scope = reset::scope_rows_for_test(&prepared_prelude);
    assert!(
        scope.windows(2).all(|pair| pair[0] < pair[1]),
        "device/key union is strictly canonical"
    );
    assert!(
        scope
            .iter()
            .any(|row| row.0 == blocked_identity.0 && row.1 == blocked_identity.1),
        "canonical scope retains the exact pending-Welcome recipient"
    );
    let expected_count: i64 = sqlx::query_scalar(
        r#"WITH candidates(user_did,device_id) AS (
             SELECT DISTINCT p.user_did,d.device_id FROM chat.participants p
             JOIN chat.devices d ON d.user_did=p.user_did
             WHERE p.conversation_id=$1 AND p.current_membership
             UNION SELECT $2::text,$3::uuid
             UNION SELECT wd.recipient_did,wd.recipient_device_id
               FROM chat.welcome_bundles wb
               JOIN chat.welcome_deliveries wd USING(welcome_id)
              WHERE wb.conversation_id=$1 AND wd.status='pending')
           SELECT count(*) FROM candidates c LEFT JOIN chat.device_keys k
             ON k.user_did=c.user_did AND k.device_id=c.device_id"#,
    )
    .bind(conversation_id)
    .bind(&f.actor_did)
    .bind(f.actor_device_id)
    .fetch_one(&mut *contender)
    .await
    .unwrap();
    assert_eq!(scope.len() as i64, expected_count);
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.reset_requests WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&mut *contender)
            .await
            .unwrap();

    let reached = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let mut probe =
        reset::ResetPrepareProbeForTest::pause_before_head(reached.clone(), release.clone());
    let prepare = tokio::spawn(async move {
        let result = reset::prepare_reset_request_authority_with_probe_for_test(
            &mut contender,
            prepared_prelude,
            &request,
            &mut probe,
        )
        .await;
        let after: i64 =
            sqlx::query_scalar("SELECT count(*) FROM chat.reset_requests WHERE conversation_id=$1")
                .bind(conversation_id)
                .fetch_one(&mut *contender)
                .await
                .unwrap();
        contender.rollback().await.unwrap();
        (result, after, probe.attempts())
    });
    reached.notified().await;

    let mut device_observer = pool.begin().await.unwrap();
    let device_error = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM chat.devices WHERE user_did=$1 AND device_id=$2 FOR UPDATE NOWAIT",
    )
    .bind(&blocked_identity.0)
    .bind(blocked_identity.1)
    .fetch_one(&mut *device_observer)
    .await
    .unwrap_err();
    assert!(
        device_error
            .as_database_error()
            .and_then(|error| error.code())
            .is_some_and(|code| code == "55P03"),
        "canonical candidate device was not locked before the head"
    );
    device_observer.rollback().await.unwrap();

    let mut head_observer = pool.begin().await.unwrap();
    let locked_head: Option<Uuid> = sqlx::query_scalar(
        "SELECT conversation_id FROM chat.conversations \
         WHERE conversation_id=$1 FOR UPDATE NOWAIT",
    )
    .bind(conversation_id)
    .fetch_optional(&mut *head_observer)
    .await
    .unwrap();
    assert_eq!(locked_head, Some(conversation_id));
    head_observer.rollback().await.unwrap();
    release.notify_one();

    let (result, after, attempts) = prepare.await.unwrap();
    let prepared = result.unwrap();
    assert!(matches!(
        prepared.disposition(),
        LockedResetRequestDisposition::Vacant
    ));
    assert_eq!(attempts, 1);
    assert_eq!(before, after);
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the ALICE reset fixture corpus"]
async fn reset_scope_includes_exact_pending_welcome_recipient() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut tx = pool.begin().await.unwrap();
    let f = fixture(&mut tx, true).await;
    let at = trusted_now(&mut tx).await;
    let id = Uuid::new_v4();
    let request = signed_reset(&f, SignedMutationKind::ResetRequest, id, id, &f.prior(), at);
    let prepared_prelude = prelude(&mut tx, &f, at, &request).await;
    let (did, device): (String, Uuid) = sqlx::query_as(
        "SELECT wd.recipient_did,wd.recipient_device_id FROM chat.welcome_bundles wb \
         JOIN chat.welcome_deliveries wd USING(welcome_id) \
         WHERE wb.conversation_id=$1 AND wd.status='pending'",
    )
    .bind(f.conversation_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let expected: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT key_id FROM chat.device_keys WHERE user_did=$1 AND device_id=$2 \
         ORDER BY convert_to(key_id,'UTF8')",
    )
    .bind(&did)
    .bind(device)
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    let actual: Vec<Option<String>> = reset::scope_rows_for_test(&prepared_prelude)
        .into_iter()
        .filter(|row| row.0 == did && row.1 == device)
        .map(|row| row.2)
        .collect();
    assert_eq!(actual, expected);
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the ALICE reset fixture corpus"]
async fn reset_head_nowait_contention_retries_without_writes() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut blocker = pool.begin().await.unwrap();
    let f = fixture(&mut blocker, false).await;
    sqlx::query("SELECT 1 FROM chat.conversations WHERE conversation_id=$1 FOR UPDATE")
        .bind(f.conversation_id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let mut contender = pool.begin().await.unwrap();
    let at = trusted_now(&mut contender).await;
    let id = Uuid::new_v4();
    let request = signed_reset(&f, SignedMutationKind::ResetRequest, id, id, &f.prior(), at);
    let prepared_prelude = prelude(&mut contender, &f, at, &request).await;
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.reset_requests WHERE conversation_id=$1")
            .bind(f.conversation_id)
            .fetch_one(&mut *contender)
            .await
            .unwrap();
    assert_error(
        reset::prepare_reset_request_authority(&mut contender, prepared_prelude, &request).await,
        |error| matches!(error, ResetRepositoryError::RetryExhausted),
    );
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.reset_requests WHERE conversation_id=$1")
            .bind(f.conversation_id)
            .fetch_one(&mut *contender)
            .await
            .unwrap();
    assert_eq!(before, after);
    contender.rollback().await.unwrap();
    blocker.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the ALICE reset fixture corpus"]
async fn reset_scope_drift_is_explicit_outer_transaction_retry_outcome() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut tx = pool.begin().await.unwrap();
    let f = fixture(&mut tx, false).await;
    let at = trusted_now(&mut tx).await;
    let before = durable_snapshot(&mut tx, f.conversation_id).await;
    let id = Uuid::new_v4();
    let request = signed_reset(&f, SignedMutationKind::ResetRequest, id, id, &f.prior(), at);
    let prepared_prelude = prelude(&mut tx, &f, at, &request).await;
    let scope_before = reset::scope_rows_for_test(&prepared_prelude);
    let mut probe = reset::ResetPrepareProbeForTest::candidate_scope_drift_once();
    assert_error(
        reset::prepare_reset_request_authority_with_probe_for_test(
            &mut tx,
            prepared_prelude,
            &request,
            &mut probe,
        )
        .await,
        |error| matches!(error, ResetRepositoryError::CandidateScopeDrift),
    );
    assert_eq!(probe.attempts(), 1);
    assert!(!scope_before.is_empty());
    assert_eq!(before, durable_snapshot(&mut tx, f.conversation_id).await);
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the ALICE reset fixture corpus"]
async fn pending_reset_guard_binds_every_immutable_column() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    for mutation in ALL_PENDING_RESET_CAS_EXPECTATION_MUTATIONS {
        let mut tx = pool.begin().await.unwrap();
        let f = fixture(&mut tx, false).await;
        let at = trusted_now(&mut tx).await;
        let id = Uuid::new_v4();
        let request = signed_reset(&f, SignedMutationKind::ResetRequest, id, id, &f.prior(), at);
        insert_pending(&mut tx, &f, id, at, request).await;
        let guard = guard(&mut tx, &f, at, id).await;
        let original = *guard.guard_digest();
        let mutated = reset::mutate_pending_reset_cas_expectation_for_test(guard, mutation);
        assert_ne!(original, *mutated.guard_digest(), "{mutation:?}");
        tx.rollback().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the ALICE reset fixture corpus"]
async fn reset_activation_rejects_retained_pending_row_with_foreign_signed_semantics() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut tx = pool.begin().await.unwrap();
    let f = fixture(&mut tx, false).await;
    let at = trusted_now(&mut tx).await;
    let retained_id = Uuid::new_v4();
    let request = signed_reset(
        &f,
        SignedMutationKind::ResetRequest,
        retained_id,
        retained_id,
        &f.prior(),
        at,
    );
    let mut foreign_wrapper: Value =
        serde_json::from_slice(request.accepted_wrapper_bytes().unwrap()).unwrap();
    foreign_wrapper["body"]["reason"] = json!("poisonedState");
    foreign_wrapper["signature"] = Value::String(STANDARD.encode([0_u8; 64]));
    let canonical =
        decode_canonical_signed_mutation(&serde_json::to_vec(&foreign_wrapper).unwrap()).unwrap();
    let signature = SigningKey::from_bytes(&ALICE_SIGNING_SEED)
        .sign(canonical.transcript_bytes())
        .to_bytes();
    foreign_wrapper["signature"] = Value::String(STANDARD.encode(signature));
    let foreign_semantics = decode_and_verify_signed_mutation(
        &serde_json::to_vec(&foreign_wrapper).unwrap(),
        &f.signing_public_key,
    )
    .unwrap();
    let expected_foreign_wrapper = foreign_semantics.accepted_wrapper_bytes().unwrap().to_vec();
    insert_pending(&mut tx, &f, retained_id, at, foreign_semantics).await;
    let entry_wrapper: Vec<u8> = sqlx::query_scalar(
        "SELECT signed_request_bytes FROM chat.entries \
         WHERE conversation_id=$1 AND entry_kind=$2",
    )
    .bind(f.conversation_id)
    .bind(ControlEntryKind::ResetRequest.type_id())
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let (row_wrapper, row_reason): (Vec<u8>, String) = sqlx::query_as(
        "SELECT signed_request_bytes,reason FROM chat.reset_requests \
         WHERE reset_request_id=$1",
    )
    .bind(retained_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(entry_wrapper, expected_foreign_wrapper);
    assert_eq!(row_wrapper, expected_foreign_wrapper);
    assert_eq!(row_reason, "manualRecovery");
    let before = durable_snapshot(&mut tx, f.conversation_id).await;
    let activation = signed_reset(
        &f,
        SignedMutationKind::ResetActivation,
        retained_id,
        Uuid::new_v4(),
        &f.prior(),
        at,
    );
    let prepared_prelude = prelude(&mut tx, &f, at, &activation).await;

    assert_error(
        reset::prepare_reset_activation_authority(&mut tx, prepared_prelude, &activation).await,
        |error| matches!(error, ResetRepositoryError::InvalidResetRow),
    );
    assert_eq!(before, durable_snapshot(&mut tx, f.conversation_id).await);
    let status: String =
        sqlx::query_scalar("SELECT status FROM chat.reset_requests WHERE reset_request_id=$1")
            .bind(retained_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(status, "pending");
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the ALICE reset fixture corpus"]
async fn reset_activation_rejects_retained_pending_row_with_corrupt_signature() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut tx = pool.begin().await.unwrap();
    let f = fixture(&mut tx, false).await;
    let at = trusted_now(&mut tx).await;
    let retained_id = Uuid::new_v4();
    let request = signed_reset(
        &f,
        SignedMutationKind::ResetRequest,
        retained_id,
        retained_id,
        &f.prior(),
        at,
    );
    let mut signed_columns = PendingDurableSignedColumns::exact(&request);
    let expected_transcript = signed_columns.signing_transcript_bytes.clone();
    let expected_digest = signed_columns.request_digest.clone();
    signed_columns.signature[0] ^= 1;
    let mut corrupt_wrapper: Value =
        serde_json::from_slice(&signed_columns.signed_request_bytes).unwrap();
    corrupt_wrapper["signature"] = Value::String(STANDARD.encode(&signed_columns.signature));
    signed_columns.signed_request_bytes = serde_json::to_vec(&corrupt_wrapper).unwrap();
    let expected_corrupt_wrapper = signed_columns.signed_request_bytes.clone();
    let expected_corrupt_signature = signed_columns.signature.clone();
    insert_pending_with_signed_columns(&mut tx, &f, retained_id, at, request, Some(signed_columns))
        .await;
    let (entry_wrapper, entry_digest, entry_signature): (Vec<u8>, Vec<u8>, Vec<u8>) =
        sqlx::query_as(
            "SELECT signed_request_bytes,request_digest,signature FROM chat.entries \
         WHERE conversation_id=$1 AND entry_kind=$2",
        )
        .bind(f.conversation_id)
        .bind(ControlEntryKind::ResetRequest.type_id())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let (row_wrapper, row_transcript, row_digest, row_signature): (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) = sqlx::query_as(
        "SELECT signed_request_bytes,signing_transcript_bytes,request_digest,signature \
         FROM chat.reset_requests \
         WHERE reset_request_id=$1",
    )
    .bind(retained_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(entry_wrapper, expected_corrupt_wrapper);
    assert_eq!(row_wrapper, expected_corrupt_wrapper);
    assert_eq!(entry_digest, expected_digest);
    assert_eq!(row_digest, expected_digest);
    assert_eq!(row_transcript, expected_transcript);
    assert_eq!(entry_signature, expected_corrupt_signature);
    assert_eq!(row_signature, expected_corrupt_signature);
    let before = durable_snapshot(&mut tx, f.conversation_id).await;
    let activation = signed_reset(
        &f,
        SignedMutationKind::ResetActivation,
        retained_id,
        Uuid::new_v4(),
        &f.prior(),
        at,
    );
    let prepared_prelude = prelude(&mut tx, &f, at, &activation).await;

    assert_error(
        reset::prepare_reset_activation_authority(&mut tx, prepared_prelude, &activation).await,
        |error| matches!(error, ResetRepositoryError::InvalidResetRow),
    );
    assert_eq!(before, durable_snapshot(&mut tx, f.conversation_id).await);
    let status: String =
        sqlx::query_scalar("SELECT status FROM chat.reset_requests WHERE reset_request_id=$1")
            .bind(retained_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(status, "pending");
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the ALICE reset fixture corpus"]
async fn sealed_reset_admission_rejects_alternate_wrapper_with_same_transcript() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut tx = pool.begin().await.unwrap();
    let f = fixture(&mut tx, false).await;
    let at = trusted_now(&mut tx).await;
    let id = Uuid::new_v4();
    let original = signed_reset(&f, SignedMutationKind::ResetRequest, id, id, &f.prior(), at);
    let original_wrapper = original.accepted_wrapper_bytes().unwrap().to_vec();
    let wrapper_value: Value = serde_json::from_slice(&original_wrapper).unwrap();
    let alternate_wrapper = serde_json::to_vec_pretty(&wrapper_value).unwrap();
    assert_ne!(alternate_wrapper, original_wrapper);
    let alternate_for_admission =
        decode_and_verify_signed_mutation(&alternate_wrapper, &f.signing_public_key).unwrap();
    let alternate_for_entry =
        decode_and_verify_signed_mutation(&alternate_wrapper, &f.signing_public_key).unwrap();
    assert_eq!(
        alternate_for_admission.transcript_bytes(),
        original.transcript_bytes()
    );
    assert_eq!(
        alternate_for_admission.request_digest(),
        original.request_digest()
    );
    assert_eq!(alternate_for_admission.signature(), original.signature());
    assert_ne!(
        alternate_for_admission.accepted_wrapper_bytes(),
        original.accepted_wrapper_bytes()
    );
    let seq: i64 = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(f.conversation_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let trusted = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&at.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
    );
    let entry = build_verified_control_entry(
        alternate_for_entry,
        &ValidatedChatNsid::parse("blue.catbird.chat.requestReset").unwrap(),
        CanonicalUuidV4::parse(&Uuid::new_v4().to_string()).unwrap(),
        CanonicalUuidV4::parse(&f.conversation_id.to_string()).unwrap(),
        seq.try_into().unwrap(),
        &trusted,
        CanonicalControlServerFields::empty(ControlEntryKind::ResetRequest).unwrap(),
    )
    .unwrap();
    let before = durable_snapshot(&mut tx, f.conversation_id).await;
    let prepared_prelude = prelude(&mut tx, &f, at, &original).await;
    let authority = reset::prepare_reset_request_authority(&mut tx, prepared_prelude, &original)
        .await
        .unwrap();
    assert!(matches!(
        authority.disposition(),
        LockedResetRequestDisposition::Vacant
    ));

    let result = authority.plan_vacant_reset_request_entry(&alternate_for_admission, entry);
    assert!(matches!(
        result,
        Err(ResetCompositionError::Repository(
            ResetRepositoryError::AuthorityBindingMismatch
        ))
    ));
    assert_eq!(before, durable_snapshot(&mut tx, f.conversation_id).await);
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the ALICE reset fixture corpus"]
async fn pending_reset_guard_rejects_foreign_transaction_and_time() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut tx = pool.begin().await.unwrap();
    let f = fixture(&mut tx, false).await;
    let at = trusted_now(&mut tx).await;
    let id = Uuid::new_v4();
    let request = signed_reset(&f, SignedMutationKind::ResetRequest, id, id, &f.prior(), at);
    insert_pending(&mut tx, &f, id, at, request).await;
    let foreign_guard = guard(&mut tx, &f, at, id).await;
    let mut foreign = pool.begin().await.unwrap();
    assert_error(
        reset::terminalize_locked_reset_request(&mut foreign, foreign_guard).await,
        |error| matches!(error, ResetRepositoryError::ForeignTransaction),
    );
    foreign.rollback().await.unwrap();
    let corrupted = reset::corrupt_guard_trusted_instant_for_test(guard(&mut tx, &f, at, id).await);
    assert_error(
        reset::terminalize_locked_reset_request(&mut tx, corrupted).await,
        |error| matches!(error, ResetRepositoryError::GuardInvariant),
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the ALICE reset fixture corpus"]
async fn reset_terminal_cas_rejects_each_expected_column_drift() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    for mutation in ALL_PENDING_RESET_CAS_EXPECTATION_MUTATIONS {
        let mut tx = pool.begin().await.unwrap();
        let f = fixture(&mut tx, false).await;
        let at = trusted_now(&mut tx).await;
        let id = Uuid::new_v4();
        let request = signed_reset(&f, SignedMutationKind::ResetRequest, id, id, &f.prior(), at);
        insert_pending(&mut tx, &f, id, at, request).await;
        let sealed = guard(&mut tx, &f, at, id).await;
        let mutated = reset::mutate_pending_reset_cas_expectation_for_test(sealed, mutation);
        assert_error(
            reset::terminalize_locked_reset_request(&mut tx, mutated).await,
            |error| matches!(error, ResetRepositoryError::CompareAndSetConflict),
        );
        let status: String =
            sqlx::query_scalar("SELECT status FROM chat.reset_requests WHERE reset_request_id=$1")
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(status, "pending", "{mutation:?}");
        tx.rollback().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the ALICE reset fixture corpus"]
async fn reset_activation_requires_exact_pending_id_and_prior() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut tx = pool.begin().await.unwrap();
    let f = fixture(&mut tx, false).await;
    let at = trusted_now(&mut tx).await;
    let id = Uuid::new_v4();
    let request = signed_reset(&f, SignedMutationKind::ResetRequest, id, id, &f.prior(), at);
    insert_pending(&mut tx, &f, id, at, request).await;
    let wrong_id = signed_reset(
        &f,
        SignedMutationKind::ResetActivation,
        Uuid::new_v4(),
        Uuid::new_v4(),
        &f.prior(),
        at,
    );
    let wrong_id_prelude = prelude(&mut tx, &f, at, &wrong_id).await;
    assert_error(
        reset::prepare_reset_activation_authority(&mut tx, wrong_id_prelude, &wrong_id).await,
        |error| matches!(error, ResetRepositoryError::PendingResetNotFound),
    );
    let prior = f.prior();
    let wrong_prior = PublicGroupSnapshotCoordinate::new(
        *prior.conversation_id(),
        prior.generation(),
        prior.state_version() + 1,
        *prior.group_id(),
        prior.epoch(),
        *prior.group_context_hash(),
        *prior.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    let wrong_coordinate = signed_reset(
        &f,
        SignedMutationKind::ResetActivation,
        id,
        Uuid::new_v4(),
        &wrong_prior,
        at,
    );
    let wrong_coordinate_prelude = prelude(&mut tx, &f, at, &wrong_coordinate).await;
    assert_error(
        reset::prepare_reset_activation_authority(
            &mut tx,
            wrong_coordinate_prelude,
            &wrong_coordinate,
        )
        .await,
        |error| matches!(error, ResetRepositoryError::PendingResetCoordinateMismatch),
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the ALICE reset fixture corpus"]
async fn reset_activation_rejects_at_exact_expiry_boundary() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut tx = pool.begin().await.unwrap();
    let f = fixture(&mut tx, false).await;
    let at = trusted_now(&mut tx).await;
    let id = Uuid::new_v4();
    let request = signed_reset(
        &f,
        SignedMutationKind::ResetRequest,
        id,
        id,
        &f.prior(),
        at - Duration::hours(24),
    );
    insert_pending(&mut tx, &f, id, at - Duration::hours(24), request).await;
    let activation = signed_reset(
        &f,
        SignedMutationKind::ResetActivation,
        id,
        Uuid::new_v4(),
        &f.prior(),
        at,
    );
    let prepared_prelude = prelude(&mut tx, &f, at, &activation).await;
    assert_error(
        reset::prepare_reset_activation_authority(&mut tx, prepared_prelude, &activation).await,
        |error| matches!(error, ResetRepositoryError::PendingResetExpired),
    );
    assert_eq!(
        reset::classify_pending_reset_at(at, at),
        reset::PendingResetTimeState::Expired
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the ALICE reset fixture corpus"]
async fn expired_pending_reset_can_be_replaced_at_exact_boundary() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut tx = pool.begin().await.unwrap();
    let f = fixture(&mut tx, false).await;
    let at = trusted_now(&mut tx).await;
    let old_id = Uuid::new_v4();
    let old = signed_reset(
        &f,
        SignedMutationKind::ResetRequest,
        old_id,
        old_id,
        &f.prior(),
        at - Duration::hours(24),
    );
    insert_pending(&mut tx, &f, old_id, at - Duration::hours(24), old).await;
    let new_id = Uuid::new_v4();
    let incoming = signed_reset(
        &f,
        SignedMutationKind::ResetRequest,
        new_id,
        new_id,
        &f.prior(),
        at,
    );
    let prepared_prelude = prelude(&mut tx, &f, at, &incoming).await;
    let authority = reset::prepare_reset_request_authority(&mut tx, prepared_prelude, &incoming)
        .await
        .unwrap();
    assert!(matches!(
        authority.disposition(),
        LockedResetRequestDisposition::ExpiredReplacement(_)
    ));
    let proof = reset::expire_pending_reset_for_replacement(&mut tx, authority)
        .await
        .unwrap();
    assert_eq!(proof.expired_request_id(), old_id);
    assert!(proof.authorizes_replacement(&incoming));
    let status: String =
        sqlx::query_scalar("SELECT status FROM chat.reset_requests WHERE reset_request_id=$1")
            .bind(old_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(status, "expired");
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the ALICE reset fixture corpus"]
async fn unexpired_pending_reset_blocks_replacement() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut tx = pool.begin().await.unwrap();
    let f = fixture(&mut tx, false).await;
    let at = trusted_now(&mut tx).await;
    let old_id = Uuid::new_v4();
    let old = signed_reset(
        &f,
        SignedMutationKind::ResetRequest,
        old_id,
        old_id,
        &f.prior(),
        at,
    );
    insert_pending(&mut tx, &f, old_id, at, old).await;
    let incoming_id = Uuid::new_v4();
    let incoming = signed_reset(
        &f,
        SignedMutationKind::ResetRequest,
        incoming_id,
        incoming_id,
        &f.prior(),
        at,
    );
    let prepared_prelude = prelude(&mut tx, &f, at, &incoming).await;
    assert_error(
        reset::prepare_reset_request_authority(&mut tx, prepared_prelude, &incoming).await,
        |error| matches!(error, ResetRepositoryError::PendingResetAlreadyExists),
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the ALICE reset fixture corpus"]
async fn replacement_and_activation_have_exactly_one_locked_winner() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut winner = pool.begin().await.unwrap();
    let f = fixture(&mut winner, false).await;
    let at = trusted_now(&mut winner).await;
    let id = Uuid::new_v4();
    let request = signed_reset(&f, SignedMutationKind::ResetRequest, id, id, &f.prior(), at);
    insert_pending(&mut winner, &f, id, at, request).await;
    assert_eq!(guard(&mut winner, &f, at, id).await.reset_request_id(), id);
    let mut contender = pool.begin().await.unwrap();
    let contender_at = trusted_now(&mut contender).await;
    sqlx::query("SET LOCAL lock_timeout='100ms'")
        .execute(&mut *contender)
        .await
        .unwrap();
    let lock_error = recheck_existing_business_authority_for_test(
        &mut contender,
        &f.actor_did,
        f.actor_device_id,
        contender_at,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            lock_error,
            AuthRepositoryError::Database(ref error)
                if error
                    .as_database_error()
                    .and_then(|error| error.code())
                    .is_some_and(|code| code == "55P03")
        ),
        "only the first path owns the canonical device/key and request read-set"
    );
    contender.rollback().await.unwrap();
    winner.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the ALICE reset fixture corpus"]
async fn terminal_operation_id_reuse_is_rejected_before_insert() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut tx = pool.begin().await.unwrap();
    let f = fixture(&mut tx, false).await;
    let at = trusted_now(&mut tx).await;
    let reused = Uuid::new_v4();
    let old = signed_reset(
        &f,
        SignedMutationKind::ResetRequest,
        reused,
        reused,
        &f.prior(),
        at - Duration::hours(24),
    );
    insert_pending(&mut tx, &f, reused, at - Duration::hours(24), old).await;
    sqlx::query(
        "UPDATE chat.reset_requests SET status='expired',terminal_at=expires_at \
         WHERE reset_request_id=$1",
    )
    .bind(reused)
    .execute(&mut *tx)
    .await
    .unwrap();
    let incoming = signed_reset(
        &f,
        SignedMutationKind::ResetRequest,
        reused,
        reused,
        &f.prior(),
        at,
    );
    let prepared_prelude = prelude(&mut tx, &f, at, &incoming).await;
    assert_error(
        reset::prepare_reset_request_authority(&mut tx, prepared_prelude, &incoming).await,
        |error| matches!(error, ResetRepositoryError::OperationIdAlreadyUsed),
    );
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.reset_requests WHERE reset_request_id=$1")
            .bind(reused)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(rows, 1);
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the ALICE reset fixture corpus"]
async fn reset_repository_failure_leaves_head_request_and_events_unchanged() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut tx = pool.begin().await.unwrap();
    let f = fixture(&mut tx, false).await;
    let at = trusted_now(&mut tx).await;
    let before = durable_snapshot(&mut tx, f.conversation_id).await;
    let prior = f.prior();
    let wrong = PublicGroupSnapshotCoordinate::new(
        *prior.conversation_id(),
        prior.generation(),
        prior.state_version() + 1,
        *prior.group_id(),
        prior.epoch(),
        *prior.group_context_hash(),
        *prior.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    let id = Uuid::new_v4();
    let request = signed_reset(&f, SignedMutationKind::ResetRequest, id, id, &wrong, at);
    let prepared_prelude = prelude(&mut tx, &f, at, &request).await;
    assert_error(
        reset::prepare_reset_request_authority(&mut tx, prepared_prelude, &request).await,
        |error| matches!(error, ResetRepositoryError::PendingResetCoordinateMismatch),
    );
    assert_eq!(before, durable_snapshot(&mut tx, f.conversation_id).await);
    tx.rollback().await.unwrap();
}
