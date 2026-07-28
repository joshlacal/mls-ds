//! Focused authority-boundary tests for the clean-chat Reset repository.

#![allow(dead_code)]

#[allow(dead_code)]
#[path = "../src/chat_protocol/dpop.rs"]
mod dpop;
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
        pub use crate::dpop::*;
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

            pub(crate) async fn candidate_scope_rows_for_test(
                transaction: &mut Transaction<'_, Postgres>,
                conversation_id: Uuid,
                business: &BusinessAuthorityGuard,
            ) -> Result<Vec<(String, Uuid, Option<String>)>, ResetRepositoryError> {
                let rows = load_candidate_scope(transaction, conversation_id, business).await?;
                Ok(rows
                    .rows
                    .into_iter()
                    .map(|row| (row.user_did, row.device_id, row.key_id))
                    .collect())
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
        pub mod delivery {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/delivery.rs"
            ));
        }
        pub mod execution_context {
            #[derive(Debug)]
            pub(crate) struct ExecutionContextHydrationProof {
                pub(crate) _minted_here: (),
            }

            #[derive(Debug)]
            pub(crate) struct RevocationBatchHydrationProof {
                pub(crate) _minted_here: (),
            }
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
            BusinessAuthorityGuard,
        },
        core::hydrate_locked_conversation_state,
        reset::{
            self, LockedPendingResetRequestGuard, LockedResetRequestDisposition,
            ResetRepositoryError, ALL_PENDING_RESET_CAS_EXPECTATION_MUTATIONS,
        },
    },
    snapshot::{PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle},
    transcript::{
        build_verified_control_entry, decode_and_verify_signed_mutation,
        decode_canonical_signed_mutation, CanonicalControlEntryProducts,
        CanonicalControlServerFields, ControlEntryKind, SignedMutationKind, VerifiedSignedMutation,
    },
    validation::{CanonicalTimestamp, CanonicalUuidV4, TrustedRequestInstant, ValidatedChatNsid},
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

async fn business(
    tx: &mut Transaction<'_, Postgres>,
    fixture: &ResetFixture,
    at: DateTime<Utc>,
) -> BusinessAuthorityGuard {
    recheck_existing_business_authority_for_test(
        tx,
        &fixture.actor_did,
        fixture.actor_device_id,
        at,
    )
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
    .bind(mutation.accepted_wrapper_bytes().unwrap())
    .bind(mutation.request_digest().as_slice())
    .bind(mutation.signature().as_slice())
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
    .bind(mutation.accepted_wrapper_bytes().unwrap())
    .bind(mutation.transcript_bytes())
    .bind(mutation.request_digest().as_slice())
    .bind(mutation.signature().as_slice())
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
    let business = business(tx, f, at).await;
    reset::activation_request_for_test(
        reset::prepare_reset_activation_authority(tx, &business, &authority)
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

#[tokio::test]
async fn reset_scope_locks_full_canonical_device_key_union_before_head() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut contender = pool.begin().await.unwrap();
    let f = fixture(&mut contender, true).await;
    let conversation_id = f.conversation_id;
    let at = trusted_now(&mut contender).await;
    let business = business(&mut contender, &f, at).await;
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
    let scope = reset::candidate_scope_rows_for_test(&mut contender, conversation_id, &business)
        .await
        .unwrap();
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

    let id = Uuid::new_v4();
    let request = signed_reset(&f, SignedMutationKind::ResetRequest, id, id, &f.prior(), at);
    let reached = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let mut probe =
        reset::ResetPrepareProbeForTest::pause_before_head(reached.clone(), release.clone());
    let prepare = tokio::spawn(async move {
        let result = reset::prepare_reset_request_authority_with_probe_for_test(
            &mut contender,
            &business,
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
async fn reset_scope_includes_exact_pending_welcome_recipient() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut tx = pool.begin().await.unwrap();
    let f = fixture(&mut tx, true).await;
    let at = trusted_now(&mut tx).await;
    let business = business(&mut tx, &f, at).await;
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
    let actual: Vec<Option<String>> =
        reset::candidate_scope_rows_for_test(&mut tx, f.conversation_id, &business)
            .await
            .unwrap()
            .into_iter()
            .filter(|row| row.0 == did && row.1 == device)
            .map(|row| row.2)
            .collect();
    assert_eq!(actual, expected);
    tx.rollback().await.unwrap();
}

#[tokio::test]
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
    let business = business(&mut contender, &f, at).await;
    let id = Uuid::new_v4();
    let request = signed_reset(&f, SignedMutationKind::ResetRequest, id, id, &f.prior(), at);
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.reset_requests WHERE conversation_id=$1")
            .bind(f.conversation_id)
            .fetch_one(&mut *contender)
            .await
            .unwrap();
    assert_error(
        reset::prepare_reset_request_authority(&mut contender, &business, &request).await,
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
async fn reset_scope_drift_retries_and_rehydrates_current_head() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut tx = pool.begin().await.unwrap();
    let f = fixture(&mut tx, false).await;
    let at = trusted_now(&mut tx).await;
    let business = business(&mut tx, &f, at).await;
    let before = durable_snapshot(&mut tx, f.conversation_id).await;
    let scope_before = reset::candidate_scope_rows_for_test(&mut tx, f.conversation_id, &business)
        .await
        .unwrap();
    let id = Uuid::new_v4();
    let request = signed_reset(&f, SignedMutationKind::ResetRequest, id, id, &f.prior(), at);
    let mut probe = reset::ResetPrepareProbeForTest::candidate_scope_drift_once();
    // Deterministic retry-control-flow evidence: the probe injects only the
    // retry outcome after the genuine canonical scope locks.
    let prepared = reset::prepare_reset_request_authority_with_probe_for_test(
        &mut tx, &business, &request, &mut probe,
    )
    .await
    .unwrap();
    let scope_after = reset::candidate_scope_rows_for_test(&mut tx, f.conversation_id, &business)
        .await
        .unwrap();
    assert_eq!(probe.attempts(), 2);
    assert_eq!(reset::authority_prior_for_test(&prepared), Some(f.prior()));
    assert_eq!(scope_before, scope_after);
    assert_eq!(before, durable_snapshot(&mut tx, f.conversation_id).await);
    tx.rollback().await.unwrap();
}

#[tokio::test]
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
async fn reset_activation_requires_exact_pending_id_and_prior() {
    let _serial = SERIAL.get_or_init(|| Mutex::new(())).lock().await;
    let pool = pool().await;
    let mut tx = pool.begin().await.unwrap();
    let f = fixture(&mut tx, false).await;
    let at = trusted_now(&mut tx).await;
    let id = Uuid::new_v4();
    let request = signed_reset(&f, SignedMutationKind::ResetRequest, id, id, &f.prior(), at);
    insert_pending(&mut tx, &f, id, at, request).await;
    let business = business(&mut tx, &f, at).await;
    let wrong_id = signed_reset(
        &f,
        SignedMutationKind::ResetActivation,
        Uuid::new_v4(),
        Uuid::new_v4(),
        &f.prior(),
        at,
    );
    assert_error(
        reset::prepare_reset_activation_authority(&mut tx, &business, &wrong_id).await,
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
    assert_error(
        reset::prepare_reset_activation_authority(&mut tx, &business, &wrong_coordinate).await,
        |error| matches!(error, ResetRepositoryError::PendingResetCoordinateMismatch),
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
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
    let business = business(&mut tx, &f, at).await;
    let activation = signed_reset(
        &f,
        SignedMutationKind::ResetActivation,
        id,
        Uuid::new_v4(),
        &f.prior(),
        at,
    );
    assert_error(
        reset::prepare_reset_activation_authority(&mut tx, &business, &activation).await,
        |error| matches!(error, ResetRepositoryError::PendingResetExpired),
    );
    assert_eq!(
        reset::classify_pending_reset_at(at, at),
        reset::PendingResetTimeState::Expired
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
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
    let business = business(&mut tx, &f, at).await;
    let authority = reset::prepare_reset_request_authority(&mut tx, &business, &incoming)
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
    assert!(proof.authorizes_replacement(&business, &incoming));
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
    let business = business(&mut tx, &f, at).await;
    assert_error(
        reset::prepare_reset_request_authority(&mut tx, &business, &incoming).await,
        |error| matches!(error, ResetRepositoryError::PendingResetAlreadyExists),
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
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
    let business = business(&mut tx, &f, at).await;
    assert_error(
        reset::prepare_reset_request_authority(&mut tx, &business, &incoming).await,
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
    let business = business(&mut tx, &f, at).await;
    assert_error(
        reset::prepare_reset_request_authority(&mut tx, &business, &request).await,
        |error| matches!(error, ResetRepositoryError::PendingResetCoordinateMismatch),
    );
    assert_eq!(before, durable_snapshot(&mut tx, f.conversation_id).await);
    tx.rollback().await.unwrap();
}
