//! Finding-3 wedge: a pending Reset row whose original requester loses live
//! device authority permanently disables Reset for the WHOLE conversation.
//!
//! `prepare_reset_read_set_inner` seals any pending row it finds before either
//! endpoint can classify it, and `seal_pending_reset` re-verifies the ORIGINAL
//! requester's live device. `load_locked_pending_row` selects by
//! `conversation_id` alone, so after the requester is revoked or rebound the
//! seal fails for every caller — including the `requestReset` arm that is
//! supposed to expire the stale row.
//!
//! This target exists because neither existing harness can host the proof:
//! `chat_protocol_reset_repository.rs` includes `reset.rs` but draws its
//! fixtures from the shared database, which holds zero `chat.reset_requests`
//! rows, while the harnesses carrying `common/executor_seed.rs` (and its
//! per-run databases) do not include `reset.rs`.
//!
//! Run:
//!   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_reset_wedge -- --test-threads=1

#![allow(dead_code)]

mod common;

#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../src/chat_protocol/relationship_policy.rs"]
mod relationship_policy_source;
#[allow(dead_code)]
mod snapshot {
    pub use catbird_server::chat_protocol::snapshot::*;
}
#[allow(dead_code)]
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[allow(dead_code)]
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

mod chat_protocol {
    pub mod validation {
        pub use crate::validation::*;
    }
    pub mod model {
        pub(crate) use crate::model::*;
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
    #[allow(dead_code)]
    pub mod dpop {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/dpop.rs"
        ));
    }
    pub mod relationship_policy {
        pub use crate::relationship_policy_source::*;
    }
    // `mint_signed_repository_authority` is `pub(super)` in `dpop.rs`, so it is
    // visible here but not at this test crate's root, and a `use` re-export
    // cannot widen it (E0364). Forward it from the level where it is already in
    // scope, as `tests/chat_protocol_reset_repository.rs` does.
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
    pub mod repository {
        // Every module the executor's dependency closure names — `auth`,
        // `blobs`, `core`, `delivery`, `execution_context`, `prelude`,
        // `recovery`, `relationship`, `transition` — is the REAL production
        // source, path-included the way the sibling harnesses do it (see
        // `tests/chat_protocol_conversation_substrate.rs`). Several are
        // `#[cfg(not(test))]` in the lib (`core`, `execution_context`,
        // `relationship`), so a `#[path]`-including harness must include the
        // real module itself rather than link it.
        #[allow(dead_code)]
        pub mod execution_context {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/execution_context.rs"
            ));
        }
        // Unconditionally compiled in the lib for exactly this reason (see the
        // comments on `repository::blobs` / `key_packages` in repository/mod.rs).
        #[allow(dead_code)]
        pub mod blobs {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/blobs.rs"
            ));
        }
        #[allow(dead_code)]
        pub mod key_packages {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/key_packages.rs"
            ));
        }
        #[allow(dead_code)]
        pub mod auth {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/auth.rs"
            ));
        }
        #[allow(dead_code)]
        pub mod prelude {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/prelude.rs"
            ));
        }
        // `recovery` is `#[allow(dead_code)] pub(crate)` (unconditional) in the
        // lib, and supplies the REAL `RecoveryPersistenceWitness`,
        // `RecoveryExecutorWriteAuthority`, `PreparedRecoveryExecutionGraph`, and
        // `RecoverySqlAuthoritySeal` that `execution_context` and the executor
        // name in their signatures. Path-included here — exactly as
        // `tests/chat_protocol_conversation_substrate.rs` does — so this harness
        // exercises the production Recovery persistence boundary rather than
        // opaque stand-ins.
        pub mod recovery {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/recovery.rs"
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
        // The module under test. `reset.rs` carries no `#[cfg(test)]`
        // prohibition (unlike `read_authority.rs`), so including it here makes
        // the harness a DESCENDANT of it: a child module below can reach
        // `load_locked_pending_row` and `seal_pending_reset` without widening
        // any production visibility.
        pub mod reset {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/reset.rs"
            ));

            /// Reproduce `prepare_reset_attempt`'s pending-row sequence with the
            /// actor-authorization arm removed, so the result isolates the SEAL.
            ///
            /// Everything here is the production path: the same
            /// `lock_head_nowait`, the same `hydrate_locked_conversation_state`,
            /// the same `load_locked_pending_row` (which selects by
            /// `conversation_id` ALONE — it never restricts to the caller), and
            /// the same unconditional `seal_pending_reset` that both endpoints
            /// run before either can classify the row. Dropping only the
            /// role/membership check means a `DeviceOrKeyDrift` here cannot be
            /// explained away as the caller lacking authority: the caller's own
            /// authority is never consulted.
            pub(crate) async fn seal_pending_for_test(
                transaction: &mut Transaction<'_, Postgres>,
                scope: &ScopeBoundBusinessAuthority,
                conversation_id: Uuid,
                preparation_kind: PendingSealKindForTest,
                operation_id: Uuid,
                dispose_lapsed: bool,
            ) -> Result<Option<LockedPendingResetRequestGuard>, ResetRepositoryError> {
                let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
                    .fetch_one(&mut **transaction)
                    .await?;
                if transaction_id != scope.transaction_id() {
                    return Err(ResetRepositoryError::ForeignTransaction);
                }
                let trusted_instant = scope.trusted_instant();
                lock_head_nowait(transaction, conversation_id).await?;
                let aggregate = hydrate_locked_conversation_state(
                    transaction,
                    conversation_id,
                    trusted_instant,
                )
                .await
                .map_err(map_aggregate_error)?;
                let head = aggregate.head();
                let head_coordinate = head
                    .prior_coordinate()
                    .ok_or(ResetRepositoryError::ConversationMissing)?;
                let head_digest = *head.durable_row_digest();
                let Some(row) = load_locked_pending_row(transaction, conversation_id).await? else {
                    return Ok(None);
                };
                let kind = match preparation_kind {
                    PendingSealKindForTest::Request => ResetPreparationKind::Request,
                    PendingSealKindForTest::Activation => ResetPreparationKind::Activation,
                };
                // The production selector: a Request against a LAPSED row
                // disposes of it against the row's recorded authority;
                // everything else keeps the strict live seal.
                let binding = if dispose_lapsed
                    && matches!(kind, ResetPreparationKind::Request)
                    && trusted_instant >= row.expires_at
                {
                    ResetAuthorityBinding::RecordedForDisposal
                } else {
                    ResetAuthorityBinding::Live
                };
                seal_pending_reset(
                    row,
                    &transaction_id,
                    trusted_instant,
                    scope,
                    head_coordinate,
                    head_digest,
                    kind,
                    operation_id,
                    binding,
                )
                .map(Some)
            }

            /// `ResetPreparationKind` is private to the production module and
            /// stays that way; this mirrors it for callers outside it.
            #[derive(Clone, Copy, Debug)]
            pub(crate) enum PendingSealKindForTest {
                Request,
                Activation,
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

#[path = "common/executor_seed.rs"]
mod executor_seed;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use chat_protocol::repository::auth::RepositoryAuthorityClass;
use chat_protocol::repository::core::hydrate_locked_conversation_state;
use chat_protocol::repository::prelude::{
    arbitrate_operation, prepare_identity_scope_prelude, OperationArbitration,
    PreparedBusinessPrelude,
};
use chat_protocol::repository::reset::{self, PendingSealKindForTest, ResetRepositoryError};
use chat_protocol::snapshot::{PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle};
use chat_protocol::transcript::{
    decode_and_verify_signed_mutation, decode_canonical_signed_mutation, SignedMutationKind,
    VerifiedMutationProjection, VerifiedSignedMutation,
};
use executor_seed::{private_genuine_pending_reset_graph, PrivateGenuinePendingResetGraph};

/// One principal's exact signing + registration identity. Field names match the
/// `ResetFixture` the sibling reset harness uses, so the signing helpers below
/// are its code unchanged except for one substitution: the shared
/// `ALICE_SIGNING_SEED` constant becomes a per-principal `signing_seed`, which
/// is what lets a SECOND principal drive the same endpoints.
struct ResetActor {
    conversation_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
    actor_dpop_jkt: String,
    actor_key_id: String,
    signing_public_key: Vec<u8>,
    signing_seed: [u8; 32],
    auth_generation: i64,
    conversation_kind: String,
}

async fn dpop_jkt_of(pool: &PgPool, did: &str, device_id: Uuid) -> String {
    sqlx::query_scalar("SELECT dpop_jkt FROM chat.devices WHERE user_did=$1 AND device_id=$2")
        .bind(did)
        .bind(device_id)
        .fetch_one(pool)
        .await
        .expect("registered device carries a dpop_jkt")
}

impl ResetActor {
    /// The principal that signed the pending row.
    async fn requester(fixture: &PrivateGenuinePendingResetGraph) -> Self {
        Self {
            conversation_id: fixture.conversation_id,
            actor_did: fixture.requester_did.clone(),
            actor_device_id: fixture.requester_device_id,
            actor_dpop_jkt: dpop_jkt_of(
                &fixture.pool,
                &fixture.requester_did,
                fixture.requester_device_id,
            )
            .await,
            actor_key_id: fixture.requester_key_id.clone(),
            signing_public_key: fixture.requester_public_key.clone(),
            signing_seed: fixture.requester_signing_seed,
            auth_generation: fixture.requester_auth_generation,
            conversation_kind: "group".to_owned(),
        }
    }

    /// A DIFFERENT current principal in the same conversation. The wedge claim
    /// is that this principal is blocked too, so every wedge assertion that
    /// matters is made through this actor.
    async fn other(fixture: &PrivateGenuinePendingResetGraph) -> Self {
        Self {
            conversation_id: fixture.conversation_id,
            actor_did: fixture.other_did.clone(),
            actor_device_id: fixture.other_device_id,
            actor_dpop_jkt: dpop_jkt_of(&fixture.pool, &fixture.other_did, fixture.other_device_id)
                .await,
            actor_key_id: fixture.other_key_id.clone(),
            signing_public_key: fixture.other_public_key.clone(),
            signing_seed: fixture.other_signing_seed,
            auth_generation: 1,
            conversation_kind: "group".to_owned(),
        }
    }
}

fn verified_request(
    fixture: &ResetActor,
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
    fixture: &ResetActor,
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
    fixture: &ResetActor,
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
    let signature = SigningKey::from_bytes(&fixture.signing_seed)
        .sign(canonical.transcript_bytes())
        .to_bytes();
    wrapper["signature"] = Value::String(STANDARD.encode(signature));
    decode_and_verify_signed_mutation(
        &serde_json::to_vec(&wrapper).unwrap(),
        &fixture.signing_public_key,
    )
    .unwrap()
}

async fn trusted_now(tx: &mut Transaction<'_, Postgres>) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT date_trunc('milliseconds',clock_timestamp())")
        .fetch_one(&mut **tx)
        .await
        .expect("trusted database clock")
}

/// Proves the fixture itself: a genuine, live, PENDING `chat.reset_requests`
/// row exists in a private per-run database, with both principals current.
/// Everything downstream reads `DeviceOrKeyDrift` off this exact state, so a
/// silently empty or already-consumed fixture would make the wedge tests
/// vacuous.
#[tokio::test]
async fn pending_reset_fixture_leaves_one_live_unconsumed_request() {
    let fixture = private_genuine_pending_reset_graph().await;

    let (status, terminal_transition_id, terminal_at, requester_did, requester_device_id): (
        String,
        Option<uuid::Uuid>,
        Option<chrono::DateTime<chrono::Utc>>,
        String,
        uuid::Uuid,
    ) = sqlx::query_as(
        r#"SELECT status,terminal_transition_id,terminal_at,requester_did,requester_device_id
             FROM chat.reset_requests
            WHERE conversation_id=$1"#,
    )
    .bind(fixture.conversation_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("exactly one seeded reset request");

    assert_eq!(status, "pending");
    assert!(terminal_transition_id.is_none());
    assert!(terminal_at.is_none());
    assert_eq!(requester_did, fixture.requester_did);
    assert_eq!(requester_device_id, fixture.requester_device_id);
    assert_eq!(fixture.reset_request_id.get_version_num(), 4);

    // Live, not expired: the wedge is about authority drift, not expiry.
    assert!(fixture.expires_at > fixture.received_at);
    assert_ne!(fixture.other_did, fixture.requester_did);
}

// ---------------------------------------------------------------------------
// The two trigger variants named in the ruling.
//
// Both apply the DURABLE effect that the live endpoint leaves on
// `chat.devices` / `chat.device_keys`, which is the only state
// `seal_pending_reset` reads about the requester. Fidelity boundary, stated
// plainly: the revocation trigger drives the production writers
// (`insert_device_revocation` + `cas_registration_revoke`) that
// `apply_device_revocation_batch_prefix` composes, not the XRPC facade above
// them; the rebind trigger reproduces the exact CAS in
// `repository/auth.rs` (`SET dpop_jkt, auth_generation = old + 1`
// guarded on `status='active'` at the old generation). Neither invents a
// column or a value the endpoint would not write.
// ---------------------------------------------------------------------------

/// `revokeDevice`: the device goes `active -> revoked`, and both it and its key
/// bind `(revocation_id, revoked_at)`. `auth_generation` is deliberately left
/// unchanged — the deferred FKs require it to equal the revocation row's
/// `target_auth_generation`.
/// A revocation instant that genuinely FOLLOWS the request it invalidates.
///
/// The graph fixture forward-dates its timeline — `received_at` lands a few
/// seconds ahead of the moment the rows are written — so the wall clock at seed
/// time is BEHIND the pending row. Revoking at "now" would place the revocation
/// before the request its requester signed, which the new terminal shape
/// rightly refuses (`terminal_at >= received_at`).
fn revocation_instant(fixture: &PrivateGenuinePendingResetGraph) -> DateTime<Utc> {
    fixture.received_at + Duration::seconds(1)
}

async fn revoke_requester_device(fixture: &PrivateGenuinePendingResetGraph, at: DateTime<Utc>) {
    use chat_protocol::repository::transition::{
        cas_registration_revoke, insert_device_revocation, NewDeviceRevocation, RegistrationRevoke,
    };

    let revocation_id = Uuid::new_v4();

    // `chat.assert_operation_claim_mapping` re-derives the claim's declared
    // mutation kind from the accepted bytes, so a placeholder byte string is
    // rejected: the revocation must be a genuinely signed, canonically
    // classifiable self-revocation wrapper. Signed with the requester's own
    // key, which is what makes this a routine `revokeDevice` rather than a
    // fabricated row.
    let body = json!({
        "$type": SignedMutationKind::DeviceRevocation.type_id(),
        "signatureDomain":
            String::from_utf8(SignedMutationKind::DeviceRevocation.domain().to_vec()).unwrap(),
        "actorDid": &fixture.requester_did,
        "actorDeviceId": fixture.requester_device_id.hyphenated().to_string(),
        "keyId": &fixture.requester_key_id,
        "authGeneration": fixture.requester_auth_generation,
        "targetDeviceId": fixture.requester_device_id.hyphenated().to_string(),
        "targetAuthGeneration": fixture.requester_auth_generation,
        "idempotencyKey": revocation_id.hyphenated().to_string(),
        "signedAt": at.to_rfc3339_opts(SecondsFormat::Millis, true),
    });
    let mut wrapper = json!({ "body": body, "signature": STANDARD.encode([0_u8; 64]) });
    let unsigned =
        decode_canonical_signed_mutation(&serde_json::to_vec(&wrapper).unwrap()).unwrap();
    let signing_transcript_bytes = unsigned.transcript_bytes().to_vec();
    let signature = SigningKey::from_bytes(&fixture.requester_signing_seed)
        .sign(&signing_transcript_bytes)
        .to_bytes();
    wrapper["signature"] = Value::String(STANDARD.encode(signature));
    let accepted_request_bytes = serde_json::to_vec(&wrapper).unwrap();
    let canonical = decode_canonical_signed_mutation(&accepted_request_bytes)
        .expect("signed revocation canonicalizes");
    decode_and_verify_signed_mutation(&accepted_request_bytes, &fixture.requester_public_key)
        .expect("genuine self-revocation verifies");
    let signing_transcript_bytes = canonical.transcript_bytes().to_vec();
    let request_digest = canonical.request_digest().to_vec();
    let signature = canonical.signature().to_vec();
    let response_bytes = b"wedge-revocation-ok".to_vec();

    // The deferred `chat.assert_device_revocation_mapping` trigger requires the
    // caller-owned operation claim and completion receipt that the revokeDevice
    // handler writes, matching the revocation row byte for byte. Without them
    // the COMMIT fails with 23514 rather than leaving a revoked device, so the
    // wedge could not be observed at all. Seeded exactly as
    // `tests/chat_protocol_conversation_substrate.rs` does.
    let mut tx = fixture.pool.begin().await.expect("begin revocation");
    sqlx::query(
        r#"
        INSERT INTO chat.operation_claims(
            operation_id,principal_did,endpoint_nsid,mutation_kind,
            request_digest,accepted_request_sha256,signature,claimed_at
        ) VALUES(
            $1,$2,'blue.catbird.chat.revokeDevice',
            'blue.catbird.chat.defs#deviceRevocationBody',$3,$4,$5,$6
        )
        "#,
    )
    .bind(revocation_id)
    .bind(&fixture.requester_did)
    .bind(&request_digest)
    .bind(Sha256::digest(&accepted_request_bytes).to_vec())
    .bind(&signature)
    .bind(at)
    .execute(&mut *tx)
    .await
    .expect("seed the exact revokeDevice operation claim");
    sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records(
            principal_did,endpoint_nsid,operation_id,request_digest,
            accepted_request_bytes,signing_transcript_bytes,signature,
            completed_status,response_bytes,response_sha256,event_position,
            historical_jkt,current_jkt,completed_at
        ) VALUES($1,'blue.catbird.chat.revokeDevice',$2,$3,$4,$5,$6,200,
            $7,$8,NULL,$9,NULL,$10)
        "#,
    )
    .bind(&fixture.requester_did)
    .bind(revocation_id)
    .bind(&request_digest)
    .bind(&accepted_request_bytes)
    .bind(&signing_transcript_bytes)
    .bind(&signature)
    .bind(&response_bytes)
    .bind(Sha256::digest(&response_bytes).to_vec())
    .bind(&fixture.requester_key_id)
    .bind(at)
    .execute(&mut *tx)
    .await
    .expect("seed the caller-owned revokeDevice receipt");
    insert_device_revocation(
        &mut tx,
        &NewDeviceRevocation {
            revocation_id,
            actor_did: fixture.requester_did.clone(),
            actor_device_id: fixture.requester_device_id,
            actor_key_id: fixture.requester_key_id.clone(),
            actor_auth_generation: fixture.requester_auth_generation,
            target_did: fixture.requester_did.clone(),
            target_device_id: fixture.requester_device_id,
            target_auth_generation: fixture.requester_auth_generation,
            accepted_request_bytes,
            signing_transcript_bytes,
            request_digest,
            signature,
            signed_at: at,
            accepted_at: at,
        },
    )
    .await
    .expect("insert the production revocation row");
    cas_registration_revoke(
        &mut tx,
        &RegistrationRevoke {
            target_did: fixture.requester_did.clone(),
            target_device_id: fixture.requester_device_id,
            expected_auth_generation: fixture.requester_auth_generation,
            revocation_id,
            revoked_at: at,
        },
    )
    .await
    .expect("production registration revoke");
    tx.commit().await.expect("commit the revocation");

    let (status, revoked): (String, bool) = sqlx::query_as(
        "SELECT status,revoked_at IS NOT NULL FROM chat.devices WHERE user_did=$1 AND device_id=$2",
    )
    .bind(&fixture.requester_did)
    .bind(fixture.requester_device_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("read back the revoked requester device");
    assert_eq!(status, "revoked");
    assert!(revoked);
}

/// `rebindDeviceAuthentication`: the device keeps its key rows but moves to a
/// NEW `auth_generation`. `chat.device_keys.enrollment_auth_generation` is left
/// at the old value, which is why the seal still FINDS the key and then fails
/// on the generation comparison rather than on `MissingDeviceKey`.
async fn rebind_requester_auth_generation(
    fixture: &PrivateGenuinePendingResetGraph,
    at: DateTime<Utc>,
) -> i64 {
    let old_jkt = dpop_jkt_of(
        &fixture.pool,
        &fixture.requester_did,
        fixture.requester_device_id,
    )
    .await;
    let new_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(format!("rebound:{old_jkt}")));
    assert_ne!(new_jkt, old_jkt);
    let new_generation = fixture.requester_auth_generation + 1;

    let updated = sqlx::query(
        r#"
        UPDATE chat.devices
           SET dpop_jkt = $4, auth_generation = $5, updated_at = $6
         WHERE user_did = $1
           AND device_id = $2
           AND status = 'active'
           AND dpop_jkt = $3
           AND auth_generation = $7
        "#,
    )
    .bind(&fixture.requester_did)
    .bind(fixture.requester_device_id)
    .bind(&old_jkt)
    .bind(&new_jkt)
    .bind(new_generation)
    .bind(at)
    .bind(fixture.requester_auth_generation)
    .execute(&fixture.pool)
    .await
    .expect("rebind the requester device");
    assert_eq!(updated.rows_affected(), 1, "exact rebind CAS");

    let enrollment: i64 = sqlx::query_scalar(
        "SELECT enrollment_auth_generation FROM chat.device_keys \
         WHERE user_did=$1 AND device_id=$2 AND key_id=$3",
    )
    .bind(&fixture.requester_did)
    .bind(fixture.requester_device_id)
    .bind(&fixture.requester_key_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("read back the requester key enrollment generation");
    assert_eq!(
        enrollment, fixture.requester_auth_generation,
        "rebind leaves the key's enrollment generation behind"
    );
    new_generation
}

/// Drive `load_locked_pending_row` + `seal_pending_reset` as `actor`, for one
/// preparation kind, and return whatever the seal produced.
async fn seal_as(
    fixture: &PrivateGenuinePendingResetGraph,
    actor: &ResetActor,
    kind: PendingSealKindForTest,
) -> Result<bool, ResetRepositoryError> {
    seal_as_at(fixture, actor, kind, Duration::zero(), true).await
}

/// `after` moves the probe's trusted instant forward. The row's `received_at` /
/// `expires_at` cannot be backdated instead: `reset_requests_identity_immutable`
/// makes every column except `status`, `terminal_transition_id` and
/// `terminal_at` immutable, so the only honest way to observe a LAPSED row is to
/// ask later.
async fn seal_as_at(
    fixture: &PrivateGenuinePendingResetGraph,
    actor: &ResetActor,
    kind: PendingSealKindForTest,
    after: Duration,
    dispose_lapsed: bool,
) -> Result<bool, ResetRepositoryError> {
    // `parse_reset_authority` derives a Request's operation id FROM its
    // `resetRequestId` and requires `idempotencyKey` to equal it, so a Request
    // carries one fresh id in both slots -- it is a NEW request, which is
    // precisely the documented rescue for a stale row. An Activation names the
    // EXISTING pending row and carries a separate `transitionId`.
    let (mutation_kind, request_id, operation_id) = match kind {
        PendingSealKindForTest::Request => {
            let fresh = Uuid::new_v4();
            (SignedMutationKind::ResetRequest, fresh, fresh)
        }
        PendingSealKindForTest::Activation => (
            SignedMutationKind::ResetActivation,
            fixture.reset_request_id,
            Uuid::new_v4(),
        ),
    };
    let mut tx = fixture.pool.begin().await.expect("begin seal probe");
    let at = trusted_now(&mut tx).await + after;
    let mutation = signed_reset(
        actor,
        mutation_kind,
        request_id,
        operation_id,
        &fixture.prior,
        at,
    );
    let prelude = prelude(&mut tx, actor, at, &mutation).await;
    let outcome = reset::seal_pending_for_test(
        &mut tx,
        prelude.scope_authority(),
        fixture.conversation_id,
        kind,
        operation_id,
        dispose_lapsed,
    )
    .await;
    tx.rollback().await.expect("probe leaves no residue");
    outcome.map(|guard| guard.is_some())
}

// ---------------------------------------------------------------------------
// WEDGE DOCUMENTATION — these assert the CURRENT BROKEN BEHAVIOUR.
//
// They are not desired-state assertions. Each one flips once the ruled fixes
// land: after (b), revocation while a reset is pending leaves no wedged row at
// all; after (a), a pre-existing wedged row becomes disposable by another
// principal's requestReset.
// ---------------------------------------------------------------------------

/// Control. Before any drift the seal SUCCEEDS for both kinds and for a
/// principal that never touched the row — so every failure below is caused by
/// the trigger, not by the probe, the fixture, or the second principal.
#[tokio::test]
async fn wedge_control_undrifted_requester_seals_for_both_kinds_and_either_principal() {
    let fixture = private_genuine_pending_reset_graph().await;
    let requester = ResetActor::requester(&fixture).await;
    let other = ResetActor::other(&fixture).await;

    for actor in [&requester, &other] {
        for kind in [
            PendingSealKindForTest::Request,
            PendingSealKindForTest::Activation,
        ] {
            let sealed = seal_as(&fixture, actor, kind)
                .await
                .unwrap_or_else(|error| panic!("undrifted seal failed as {:?}: {error:?}", kind));
            assert!(sealed, "the pending row is found and sealed");
        }
    }
}

/// TRIGGER 1, revocation. Both preparation kinds fail, for the principal that
/// did NOT request the reset. The `Request` failure is the load-bearing one:
/// that arm is the documented rescue that would classify the row
/// `ExpiredReplacement` and clear it, and it never reaches that classification.
#[tokio::test]
async fn wedge_revoked_requester_drifts_the_seal_for_both_kinds() {
    let fixture = private_genuine_pending_reset_graph().await;
    let other = ResetActor::other(&fixture).await;
    let at = revocation_instant(&fixture);
    revoke_requester_device(&fixture, at).await;

    for kind in [
        PendingSealKindForTest::Request,
        PendingSealKindForTest::Activation,
    ] {
        let error = seal_as(&fixture, &other, kind)
            .await
            .expect_err("a revoked requester wedges the seal");
        assert!(
            matches!(error, ResetRepositoryError::DeviceOrKeyDrift),
            "expected DeviceOrKeyDrift as {kind:?}, observed {error:?}"
        );
    }
}

/// TRIGGER 2, rebind. Same wedge from a bumped `auth_generation`, with the
/// requester still active — so the wedge is not about revocation specifically,
/// it is about the seal binding to LIVE authority instead of the authority the
/// row recorded.
#[tokio::test]
async fn wedge_rebound_requester_drifts_the_seal_for_both_kinds() {
    let fixture = private_genuine_pending_reset_graph().await;
    let other = ResetActor::other(&fixture).await;
    let at = executor_seed::clock_now(&fixture.pool).await;
    let bumped = rebind_requester_auth_generation(&fixture, at).await;
    assert_ne!(bumped, fixture.requester_auth_generation);

    for kind in [
        PendingSealKindForTest::Request,
        PendingSealKindForTest::Activation,
    ] {
        let error = seal_as(&fixture, &other, kind)
            .await
            .expect_err("a rebound requester wedges the seal");
        assert!(
            matches!(error, ResetRepositoryError::DeviceOrKeyDrift),
            "expected DeviceOrKeyDrift as {kind:?}, observed {error:?}"
        );
    }
}

/// The requester is not privileged here either: once drifted, the principal who
/// SIGNED the row cannot seal it any more than anyone else can. Together with
/// the two tests above this is the "blocks EVERY principal" claim —
/// `load_locked_pending_row` selects by `conversation_id` alone.
#[tokio::test]
async fn wedge_blocks_the_original_requester_too() {
    let fixture = private_genuine_pending_reset_graph().await;
    let at = executor_seed::clock_now(&fixture.pool).await;
    let bumped = rebind_requester_auth_generation(&fixture, at).await;
    // Built AFTER the rebind, so this actor carries the requester's CURRENT
    // jkt and generation and is admitted normally. The drift is in the row's
    // recorded authority, not in the caller.
    let mut requester = ResetActor::requester(&fixture).await;
    requester.actor_dpop_jkt = dpop_jkt_of(
        &fixture.pool,
        &fixture.requester_did,
        fixture.requester_device_id,
    )
    .await;
    requester.auth_generation = bumped;

    let error = seal_as(&fixture, &requester, PendingSealKindForTest::Request)
        .await
        .expect_err("the original requester is wedged out of its own row");
    assert!(matches!(error, ResetRepositoryError::DeviceOrKeyDrift));
}

/// "Nothing in the schedule clears the row."
///
/// The wedge is permanent only if no background path disposes of a pending
/// Reset. This enumerates every production writer of `chat.reset_requests`
/// instead of asserting an absence, and carries positive controls so a rename,
/// a moved file, or a truncated read fails LOUDLY rather than reading as "no
/// clearer exists".
#[test]
fn no_scheduled_path_can_clear_a_pending_reset_row() {
    let reset = include_str!("../src/chat_protocol/repository/reset.rs");
    let transition = include_str!("../src/chat_protocol/repository/transition.rs");
    let sweep = include_str!("../src/chat_protocol/repository/expiry_sweep.rs");
    let executor = include_str!("../src/chat_protocol/state_machine/executor.rs");

    // Positive controls: each source really is the file it claims to be, so a
    // path that stops resolving cannot masquerade as a clean absence.
    assert!(reset.contains("fn seal_pending_reset("));
    assert!(transition.contains("pub(crate) async fn terminalize_reset_request("));
    assert!(sweep.contains("pub(crate) async fn trusted_sweep_instant("));
    assert!(executor.contains("transition::terminalize_reset_request("));

    // Exactly two production statements move a pending row to a terminal
    // status, and both sit BEHIND the seal.
    assert_eq!(
        reset.matches("UPDATE chat.reset_requests").count(),
        1,
        "reset.rs holds exactly one terminal writer (cas_terminalize)"
    );
    assert_eq!(
        transition.matches("UPDATE chat.reset_requests").count(),
        1,
        "transition.rs holds exactly one terminal writer (terminalize_reset_request)"
    );
    assert_eq!(
        reset
            .matches("terminalize_locked_reset_request(transaction, guard)")
            .count(),
        1,
        "the locked terminal writer keeps its single caller, downstream of the seal"
    );

    // The scheduled sweep never names the table at all: it sweeps welcome
    // deliveries, leaf recovery requests and key package reservations.
    assert!(
        !sweep.contains("reset_request"),
        "the expiry sweep has no Reset arm"
    );
    for swept in [
        "chat.welcome_deliveries",
        "chat.leaf_recovery_requests",
        "chat.key_package_reservations",
    ] {
        assert!(
            sweep.contains(swept),
            "positive control: sweep touches {swept}"
        );
    }
}

/// Behavioural counterpart: after the trigger, the row is still exactly as it
/// was. Nothing reaped it, and it is still LIVE rather than expired, so the
/// wedge cannot be dismissed as ordinary expiry.
#[tokio::test]
async fn a_wedged_row_survives_untouched_and_unexpired() {
    let fixture = private_genuine_pending_reset_graph().await;
    let at = executor_seed::clock_now(&fixture.pool).await;
    rebind_requester_auth_generation(&fixture, at).await;

    let (status, terminal_transition_id, terminal_at, expires_at): (
        String,
        Option<Uuid>,
        Option<DateTime<Utc>>,
        DateTime<Utc>,
    ) = sqlx::query_as(
        r#"SELECT status,terminal_transition_id,terminal_at,expires_at
             FROM chat.reset_requests WHERE reset_request_id=$1"#,
    )
    .bind(fixture.reset_request_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("the wedged row is still present");

    assert_eq!(status, "pending");
    assert!(terminal_transition_id.is_none());
    assert!(terminal_at.is_none());
    assert!(
        expires_at > at,
        "the wedged row is live, not expired: {expires_at} <= {at}"
    );
}

// ---------------------------------------------------------------------------
// FIX (a) — lapsed-row disposal bound to RECORDED authority.
//
// These are desired-state assertions, unlike the wedge documentation above.
// Note what they do NOT claim: the six cases above still pass unchanged,
// because they use a LIVE row. Fix (a) time-bounds the wedge to the row's 24h
// expiry; only fix (b) prevents the outage.
// ---------------------------------------------------------------------------

/// The lapsed row a revoked requester left behind is disposable by a DIFFERENT
/// principal. This is the rescue that finding 3 made unreachable.
#[tokio::test]
async fn lapsed_row_from_a_revoked_requester_is_disposable_by_another_principal() {
    let fixture = private_genuine_pending_reset_graph().await;
    let other = ResetActor::other(&fixture).await;
    let at = revocation_instant(&fixture);
    revoke_requester_device(&fixture, at).await;

    let lapsed = Duration::hours(24) + Duration::minutes(1);

    // RED, kept in the same test so the fix cannot be mistaken for the row
    // having been disposable all along: with the live seal it is still wedged
    // even once lapsed.
    let wedged = seal_as_at(
        &fixture,
        &other,
        PendingSealKindForTest::Request,
        lapsed,
        false,
    )
    .await
    .expect_err("the live seal wedges a lapsed row too");
    assert!(matches!(wedged, ResetRepositoryError::DeviceOrKeyDrift));

    let sealed = seal_as_at(
        &fixture,
        &other,
        PendingSealKindForTest::Request,
        lapsed,
        true,
    )
    .await
    .expect("recorded-authority disposal seals the lapsed row");
    assert!(sealed);
}

/// Same for the rebind trigger.
#[tokio::test]
async fn lapsed_row_from_a_rebound_requester_is_disposable_by_another_principal() {
    let fixture = private_genuine_pending_reset_graph().await;
    let at = executor_seed::clock_now(&fixture.pool).await;
    rebind_requester_auth_generation(&fixture, at).await;
    let other = ResetActor::other(&fixture).await;

    let sealed = seal_as_at(
        &fixture,
        &other,
        PendingSealKindForTest::Request,
        Duration::hours(24) + Duration::minutes(1),
        true,
    )
    .await
    .expect("recorded-authority disposal seals the lapsed row");
    assert!(sealed);
}

/// THE HARD CONSTRAINT. `activateReset` keeps FULL strict live-authority
/// verification: a drifted requester still fails, lapsed or not, and the
/// relaxation is unreachable from the activation path.
#[tokio::test]
async fn activation_keeps_full_strict_live_authority_even_on_a_lapsed_row() {
    let fixture = private_genuine_pending_reset_graph().await;
    let other = ResetActor::other(&fixture).await;
    let at = executor_seed::clock_now(&fixture.pool).await;
    rebind_requester_auth_generation(&fixture, at).await;

    for after in [Duration::zero(), Duration::hours(24) + Duration::minutes(1)] {
        let error = seal_as_at(
            &fixture,
            &other,
            PendingSealKindForTest::Activation,
            after,
            true,
        )
        .await
        .expect_err("activation never relaxes the live seal");
        assert!(
            matches!(error, ResetRepositoryError::DeviceOrKeyDrift),
            "activation must still drift after {after}, observed {error:?}"
        );
    }
}

/// Disposal does not weaken what the row must prove about ITSELF.
///
/// This is asserted structurally rather than by corrupting a stored value:
/// `chat.device_keys.signing_public_key` is immutable at the schema level
/// (`enforce_immutable_identity`), as are every column of `chat.reset_requests`
/// except the three terminal ones — so the byte binding cannot be broken from a
/// test at all, which is itself part of why it is safe to relax the live check.
/// What remains falsifiable is the SHAPE of the relaxation, and that is what is
/// pinned here: exactly one comparison is skipped, and everything that binds the
/// row to its own signed bytes runs unconditionally.
#[test]
fn recorded_authority_disposal_still_binds_the_immutable_signed_bytes() {
    let source = include_str!("../src/chat_protocol/repository/reset.rs");

    // Positive controls.
    assert!(source.contains("fn seal_pending_reset("));
    assert!(source.contains("enum ResetAuthorityBinding"));

    // The relaxation is applied in EXACTLY one place, and it guards exactly the
    // live-device comparison.
    assert_eq!(
        source
            .matches("binding == ResetAuthorityBinding::Live")
            .count(),
        1,
        "the live-authority relaxation must have exactly one site"
    );

    let seal = &source[source
        .find("fn seal_pending_reset(")
        .expect("seal_pending_reset is present")..];
    let seal = &seal[..seal
        .find("\nasync fn cas_terminalize(")
        .expect("seal_pending_reset is bounded by cas_terminalize")];

    // Everything that binds the row to its own immutable bytes is unconditional:
    // it appears in the sealed body with no binding mentioned between the
    // relaxation site and it.
    let relaxation = seal
        .find("binding == ResetAuthorityBinding::Live")
        .expect("relaxation is inside the seal");
    for unconditional in [
        "validate_requester_public_key_hash(requester_public_key",
        "decode_and_verify_signed_mutation(&row.signed_request_bytes",
        "parse_reset_authority(&verified, ResetPreparationKind::Request)",
    ] {
        let at = seal
            .find(unconditional)
            .unwrap_or_else(|| panic!("{unconditional} must still run under disposal"));
        assert!(
            at > relaxation,
            "{unconditional} must run after the relaxation site"
        );
        assert!(
            !seal[relaxation..at].contains("ResetAuthorityBinding::RecordedForDisposal"),
            "{unconditional} must not be gated on the disposal binding"
        );
    }

    // A disposal binding can mint EXACTLY the expiry terminal.
    assert!(
        source.contains("(ResetAuthorityBinding::RecordedForDisposal, _) => {"),
        "every non-Request disposal shape must be rejected"
    );
    assert_eq!(
        source
            .matches("ResetAuthorityBinding::RecordedForDisposal")
            .count(),
        3,
        "disposal is named at exactly the two guarded match arms and the one selector"
    );

    // The selector never admits an Activation.
    assert!(
        source.contains("matches!(parsed.kind, ResetPreparationKind::Request)\n                && trusted_instant >= row.expires_at"),
        "disposal is selected only for a Request against a lapsed row"
    );
}

// ---------------------------------------------------------------------------
// ENDPOINT LEVEL — through the production `requestReset` facade.
//
// The child-module probe above selects the authority binding itself, so on its
// own it proves only that `seal_pending_reset` ACCEPTS a disposal binding. These
// two go through `prepare_reset_request_authority`, which means production picks
// the binding. They are a matched pair: same conversation shape, same drifted
// requester, same caller — only the row's age differs.
// ---------------------------------------------------------------------------

async fn request_reset_through_the_facade(
    fixture: &PrivateGenuinePendingResetGraph,
    actor: &ResetActor,
    after: Duration,
) -> Result<String, ResetRepositoryError> {
    let mut tx = fixture.pool.begin().await.expect("begin facade request");
    let at = trusted_now(&mut tx).await + after;
    let fresh = Uuid::new_v4();
    let mutation = signed_reset(
        actor,
        SignedMutationKind::ResetRequest,
        fresh,
        fresh,
        &fixture.prior,
        at,
    );
    let prelude = prelude(&mut tx, actor, at, &mutation).await;
    let outcome = async {
        let authority = reset::prepare_reset_request_authority(&mut tx, prelude, &mutation).await?;
        reset::expire_pending_reset_for_replacement(&mut tx, authority).await?;
        let status: String =
            sqlx::query_scalar("SELECT status FROM chat.reset_requests WHERE reset_request_id=$1")
                .bind(fixture.reset_request_id)
                .fetch_one(&mut *tx)
                .await?;
        Ok(status)
    }
    .await;
    tx.rollback().await.expect("facade probe leaves no residue");
    outcome
}

/// WEDGE, at the endpoint. While the row is LIVE, the drifted requester still
/// blocks `requestReset` for a different principal. Fix (a) deliberately does
/// not change this — only fix (b) will.
#[tokio::test]
async fn endpoint_request_reset_is_still_wedged_while_the_row_is_live() {
    let fixture = private_genuine_pending_reset_graph().await;
    let other = ResetActor::other(&fixture).await;
    let at = revocation_instant(&fixture);
    revoke_requester_device(&fixture, at).await;

    let error = request_reset_through_the_facade(&fixture, &other, Duration::zero())
        .await
        .expect_err("a live wedged row still blocks the endpoint");
    assert!(
        matches!(error, ResetRepositoryError::DeviceOrKeyDrift),
        "observed {error:?}"
    );
}

/// FIXED, at the endpoint. Once the row lapses, the documented rescue is
/// reachable again and actually CLEARS the row: production selects the
/// recorded-authority binding, the disposition classifies `ExpiredReplacement`,
/// and the durable status becomes `expired`.
#[tokio::test]
async fn endpoint_request_reset_disposes_of_a_wedged_lapsed_row() {
    let fixture = private_genuine_pending_reset_graph().await;
    let other = ResetActor::other(&fixture).await;
    let at = revocation_instant(&fixture);
    revoke_requester_device(&fixture, at).await;

    let status = request_reset_through_the_facade(
        &fixture,
        &other,
        Duration::hours(24) + Duration::minutes(1),
    )
    .await
    .expect("the documented rescue is reachable once the row lapses");
    assert_eq!(status, "expired");
}

// ---------------------------------------------------------------------------
// MIGRATION — the revocation-bound terminal shape on chat.reset_requests.
//
// Proves the new (status, terminal column) combination is admitted AND that
// every previously valid combination still binds exactly as before, so the
// widened check cannot have loosened an existing arm by accident.
// ---------------------------------------------------------------------------

/// Attempt one UPDATE inside a savepoint. Returns the SQLSTATE on rejection.
async fn try_terminal_shape(
    pool: &PgPool,
    reset_request_id: Uuid,
    set_clause: &str,
    binds: &[&(dyn std::fmt::Debug)],
) -> Result<(), String> {
    let _ = binds;
    let mut tx = pool.begin().await.expect("begin shape probe");
    let sql = format!(
        "UPDATE chat.reset_requests SET {set_clause} WHERE reset_request_id='{reset_request_id}'"
    );
    let outcome = sqlx::query(&sql)
        .execute(&mut *tx)
        .await
        .map(|_| ())
        // The SQLSTATE, not the Display text: `to_string()` renders the message
        // without the code, so asserting on "23514" against it silently never
        // matches.
        .map_err(|error| {
            error
                .as_database_error()
                .and_then(|db| db.code())
                .map(|code| code.into_owned())
                .unwrap_or_else(|| error.to_string())
        });
    tx.rollback().await.expect("shape probe leaves no residue");
    outcome
}

#[tokio::test]
async fn revocation_terminal_shape_is_admitted_and_old_shapes_still_bind() {
    let fixture = private_genuine_pending_reset_graph().await;
    let at = revocation_instant(&fixture);
    revoke_requester_device(&fixture, at).await;

    let (revocation_id, accepted_at): (Uuid, DateTime<Utc>) = sqlx::query_as(
        "SELECT revocation_id,accepted_at FROM chat.device_revocations \
         WHERE target_did=$1 AND target_device_id=$2",
    )
    .bind(&fixture.requester_did)
    .bind(fixture.requester_device_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("the revocation this reset row's requester is the target of");

    let id = fixture.reset_request_id;
    let ts = |t: DateTime<Utc>| t.to_rfc3339_opts(SecondsFormat::Micros, true);

    // ADMITTED: the new arm.
    try_terminal_shape(
        &fixture.pool,
        id,
        &format!(
            "status='revoked',terminal_revocation_id='{revocation_id}',terminal_at='{}'",
            ts(accepted_at)
        ),
        &[],
    )
    .await
    .expect("a revoked requester's pending row terminalizes against its revocation");

    // REJECTED: 'revoked' without the revocation id, or with a transition id as
    // well — the new status must carry exactly its own evidence.
    for bad in [
        format!("status='revoked',terminal_at='{}'", ts(accepted_at)),
        format!(
            "status='revoked',terminal_revocation_id='{revocation_id}',\
             terminal_transition_id='{}',terminal_at='{}'",
            Uuid::new_v4(),
            ts(accepted_at)
        ),
        format!("status='revoked',terminal_revocation_id='{revocation_id}'"),
    ] {
        let error = try_terminal_shape(&fixture.pool, id, &bad, &[])
            .await
            .expect_err("malformed revoked shape must be rejected");
        assert!(error == "23514", "{error}");
    }

    // REJECTED: every OLD arm still binds exactly as before. A revocation id may
    // not be smuggled into 'stale'/'consumed'/'expired'/'pending'.
    for bad in [
        format!(
            "status='stale',terminal_revocation_id='{revocation_id}',terminal_at='{}'",
            ts(accepted_at)
        ),
        format!(
            "status='consumed',terminal_revocation_id='{revocation_id}',terminal_at='{}'",
            ts(accepted_at)
        ),
        format!(
            "status='expired',terminal_revocation_id='{revocation_id}',terminal_at='{}'",
            ts(fixture.expires_at)
        ),
        format!("status='consumed',terminal_at='{}'", ts(accepted_at)),
        format!("status='expired',terminal_at='{}'", ts(accepted_at)),
        format!("terminal_revocation_id='{revocation_id}'"),
    ] {
        let error = try_terminal_shape(&fixture.pool, id, &bad, &[])
            .await
            .expect_err("an old terminal arm must bind exactly as before");
        assert_eq!(
            error, "23514",
            "an old terminal arm must raise a check violation"
        );
    }

    // ADMITTED still: the pre-existing arms, unchanged.
    try_terminal_shape(
        &fixture.pool,
        id,
        &format!(
            "status='stale',terminal_transition_id='{}',terminal_at='{}'",
            Uuid::new_v4(),
            ts(accepted_at)
        ),
        &[],
    )
    .await
    .expect("the stale arm is unchanged");
    try_terminal_shape(
        &fixture.pool,
        id,
        &format!("status='expired',terminal_at='{}'", ts(fixture.expires_at)),
        &[],
    )
    .await
    .expect("the expiry arm is unchanged");
}

/// The composite FK is the structural guarantee that a reset row can only be
/// terminalized by ITS OWN requester's revocation — never attributed to someone
/// else's. It is DEFERRABLE, so it surfaces at COMMIT.
#[tokio::test]
async fn a_reset_row_cannot_be_terminalized_by_a_foreign_revocation() {
    let fixture = private_genuine_pending_reset_graph().await;
    let at = revocation_instant(&fixture);
    revoke_requester_device(&fixture, at).await;

    let mut tx = fixture
        .pool
        .begin()
        .await
        .expect("begin foreign-revocation probe");
    sqlx::query(
        "UPDATE chat.reset_requests SET status='revoked',terminal_revocation_id=$2,terminal_at=$3 \
         WHERE reset_request_id=$1",
    )
    .bind(fixture.reset_request_id)
    .bind(Uuid::new_v4())
    .bind(at)
    .execute(&mut *tx)
    .await
    .expect("the CHECK shape alone accepts this row");
    let error = tx
        .commit()
        .await
        .expect_err("the deferred FK must reject a revocation this requester is not the target of");
    assert!(error
        .to_string()
        .contains("reset_requests_terminal_revocation_fk"));
}

/// Lifecycle: `pending -> revoked` is admitted, and a revoked row is terminal.
#[tokio::test]
async fn revoked_is_a_terminal_successor_of_pending_and_cannot_be_rewritten() {
    let fixture = private_genuine_pending_reset_graph().await;
    let at = revocation_instant(&fixture);
    revoke_requester_device(&fixture, at).await;

    let (revocation_id, accepted_at): (Uuid, DateTime<Utc>) = sqlx::query_as(
        "SELECT revocation_id,accepted_at FROM chat.device_revocations \
         WHERE target_did=$1 AND target_device_id=$2",
    )
    .bind(&fixture.requester_did)
    .bind(fixture.requester_device_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("the requester's revocation");

    let mut tx = fixture.pool.begin().await.expect("begin lifecycle probe");
    sqlx::query(
        "UPDATE chat.reset_requests SET status='revoked',terminal_revocation_id=$2,terminal_at=$3 \
         WHERE reset_request_id=$1",
    )
    .bind(fixture.reset_request_id)
    .bind(revocation_id)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("pending -> revoked is an admitted lifecycle transition");

    let error =
        sqlx::query("UPDATE chat.reset_requests SET status='expired' WHERE reset_request_id=$1")
            .bind(fixture.reset_request_id)
            .execute(&mut *tx)
            .await
            .expect_err("a terminal reset request cannot be rewritten");
    assert!(error
        .to_string()
        .contains("terminal reset request cannot be rewritten"));
    tx.rollback()
        .await
        .expect("lifecycle probe leaves no residue");
}
