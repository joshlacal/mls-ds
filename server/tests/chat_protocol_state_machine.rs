#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
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

    // The E2b-2/E2b-3 transition executor lives in `state_machine.rs` (included
    // below) and is now compiled unconditionally, so its `super::repository::*`
    // references must resolve inside this test crate too. The repository writer
    // modules are self-contained (only `chrono`/`sha2`/`sqlx`/`uuid`), so they
    // `include!` directly — mirroring `chat_protocol_transition_repository.rs`.
    // The existing 27 state-machine tests do not use these; they are inert here.
    pub mod repository {
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
    }

    pub mod state_machine {
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/state_machine.rs"
        ));
    }
}

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};

use chat_protocol::{
    public_state::{
        decode_public_tree_summary, encode_public_tree_summary, rebind_active_snapshot,
        verify_genesis_group_info, verify_recovery_welcome, verify_reset_successor_group_info,
        GenesisGroupInfoExpectations, PublicStateError, ResetSuccessorGroupInfoExpectations,
    },
    snapshot::{
        PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle, PublicGroupSnapshotTreeSummary,
    },
    state_machine::{
        acceptance_recovery_package_artifact_matches, hydrate_conversation_state as hydrate_graph,
        plan_accept_conversation, plan_close, plan_commit, plan_creation,
        plan_leaf_recovery_cancellation, plan_leaf_recovery_fulfillment,
        plan_leaf_recovery_request, plan_leave_cancellation, plan_leave_fulfillment,
        plan_leave_request, plan_reset_activation, plan_reset_request, plan_zero_leaf_leave,
        AcceptConversation, CloseConversation, CommitCommand, ConversationKind,
        ConversationStateHydration, CreationCommand, CreationDecision, DeviceIdentity,
        DurableSignedRequestEnvelope, HydrationAuthority, IntervalHydrationRow,
        InvitationHydrationRow, LeafHydrationRow, LeafRecoveryCancellation,
        LeafRecoveryFulfillment, LeafRecoveryKind, LeafRecoveryRequestCommand, LeaveCancellation,
        LeaveFulfillment, LeaveFulfillmentTestMutation, LeaveRequestCommand, LeaveRequestStatus,
        LockedRegistrationProjection, OpeningKind, PackageStatus, ParticipantHydrationRow,
        ParticipantRole, ParticipantStatus, PersistedRegistrationRow, PersistedRegistrationStatus,
        PersistedSignedRequestRow, PrincipalId, RecoveryRequestStatus, RecoverySource,
        RequestEntryKind, RequestEvidence, ReservationStatus, ResetActivation, ResetRequestCommand,
        ResetRequestStatus, ServerTimestamp, StateMachineError, TransitionEvidence, ZeroLeafLeave,
    },
    transcript::{
        decode_and_verify_signed_mutation, decode_canonical_signed_mutation, SignedMutationKind,
    },
    validation::{
        ed25519_key_id, BareDid, CanonicalTimestamp, CanonicalUuidV4, KeyThumbprint,
        TrustedRequestInstant,
    },
    wire::{
        validate_group_info, GroupInfoValidationPolicy, MAX_GROUP_INFO_WIRE_BYTES,
        XWING_CIPHERSUITE,
    },
};
use ed25519_dalek::{Signer, SigningKey};
use openmls::prelude::{tls_codec::Serialize as TlsSerialize, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[path = "common/frozen_public_state.rs"]
mod frozen_public_state;

const GENESIS_SEQ: u64 = 1;
const ACCEPT_SEQ: u64 = 2;
const ADD_SEQ: u64 = 3;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusManifest {
    evaluation_unix_seconds: u64,
    identifiers: CorpusIdentifiers,
    identity: CorpusIdentity,
    chain: CorpusChain,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusIdentifiers {
    conversation_id_hex: String,
}

#[derive(Deserialize)]
struct CorpusIdentity {
    alice: CorpusActor,
    bob: CorpusActor,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusActor {
    actor_did: String,
    device_id: String,
    credential_identity: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusChain {
    generation: u64,
    genesis_state_version: u64,
    genesis_epoch: u64,
    genesis_group_context_hash_hex: String,
    genesis_confirmation_tag_hex: String,
    group_id_hex: String,
    inner_key_package_ref_hex: String,
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/generated-artifacts/mls-chat-v1/crypto-wire")
}

fn corpus_file(name: &str) -> Vec<u8> {
    fs::read(corpus_dir().join(name)).expect("read frozen crypto-wire corpus")
}

fn corpus_manifest() -> CorpusManifest {
    serde_json::from_slice(&corpus_file("manifest.json")).expect("parse frozen manifest")
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value)
        .expect("valid fixture hex")
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N}-byte fixture"))
}

fn uuid_bytes(value: &str) -> [u8; 16] {
    *Uuid::parse_str(value).expect("fixture UUID").as_bytes()
}

fn coordinate(
    manifest: &CorpusManifest,
    state_version: u64,
    epoch: u64,
    context_hash: [u8; 32],
    confirmation_tag: [u8; 32],
) -> PublicGroupSnapshotCoordinate {
    PublicGroupSnapshotCoordinate::new(
        hex_array(&manifest.identifiers.conversation_id_hex),
        manifest.chain.generation,
        state_version,
        hex_array(&manifest.chain.group_id_hex),
        epoch,
        context_hash,
        confirmation_tag,
        PublicGroupSnapshotLifecycle::Active,
    )
}

fn genesis_coordinate(manifest: &CorpusManifest) -> PublicGroupSnapshotCoordinate {
    coordinate(
        manifest,
        manifest.chain.genesis_state_version,
        manifest.chain.genesis_epoch,
        hex_array(&manifest.chain.genesis_group_context_hash_hex),
        hex_array(&manifest.chain.genesis_confirmation_tag_hex),
    )
}

fn coordinate_with_conversation(
    source: &PublicGroupSnapshotCoordinate,
    conversation_id: [u8; 16],
) -> PublicGroupSnapshotCoordinate {
    PublicGroupSnapshotCoordinate::new(
        conversation_id,
        source.generation(),
        source.state_version(),
        *source.group_id(),
        source.epoch(),
        *source.group_context_hash(),
        *source.confirmation_tag(),
        source.lifecycle(),
    )
}

fn alice(manifest: &CorpusManifest) -> DeviceIdentity {
    DeviceIdentity::new(
        PrincipalId::new(manifest.identity.alice.actor_did.as_bytes().to_vec()).unwrap(),
        uuid_bytes(&manifest.identity.alice.device_id),
    )
    .unwrap()
}

fn bob(manifest: &CorpusManifest) -> DeviceIdentity {
    DeviceIdentity::new(
        PrincipalId::new(manifest.identity.bob.actor_did.as_bytes().to_vec()).unwrap(),
        uuid_bytes(&manifest.identity.bob.device_id),
    )
    .unwrap()
}

fn evidence(seq: u64, byte: u8) -> TransitionEvidence {
    TransitionEvidence::for_test_at(
        seq,
        uuid_v4_bytes(byte),
        [byte; 32],
        fixture_received_at(seq),
    )
    .unwrap()
}

fn evidence_at(
    seq: u64,
    byte: u8,
    received_at: ServerTimestamp,
    _conversation_id: [u8; 16],
) -> TransitionEvidence {
    TransitionEvidence::for_test_at(seq, uuid_v4_bytes(byte), [byte; 32], received_at).unwrap()
}

fn fixture_received_at(seq: u64) -> ServerTimestamp {
    ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + seq as i64 * 1_000,
    )
    .unwrap()
}

fn fixture_package_not_after() -> ServerTimestamp {
    ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_600_000,
    )
    .unwrap()
}

fn hydrate_conversation_state(
    candidate: chat_protocol::state_machine::ConversationState,
) -> Result<chat_protocol::state_machine::ConversationState, StateMachineError> {
    let expected = *candidate.coordinate().conversation_id();
    hydrate_rows(
        expected,
        ConversationStateHydration::for_test_from_state(candidate),
    )
}

fn hydrate_rows(
    expected_conversation_id: [u8; 16],
    rows: ConversationStateHydration,
) -> Result<chat_protocol::state_machine::ConversationState, StateMachineError> {
    let authority = HydrationAuthority::new(expected_conversation_id).unwrap();
    hydrate_graph(&authority, rows)
}

fn request_evidence(
    kind: RequestEntryKind,
    seq: u64,
    request_id: [u8; 16],
    actor: DeviceIdentity,
    conversation_id: [u8; 16],
    received_at: ServerTimestamp,
    byte: u8,
) -> RequestEvidence {
    RequestEvidence::for_test(
        kind,
        seq,
        request_id,
        actor,
        conversation_id,
        received_at,
        byte,
    )
    .unwrap()
}

fn registered_leave_request(
    actor: DeviceIdentity,
    leave_request_id: [u8; 16],
    received_at: ServerTimestamp,
    conversation_id: [u8; 16],
    seq: u64,
    byte: u8,
) -> LeaveRequestCommand {
    let evidence = request_evidence(
        RequestEntryKind::LeaveRequest,
        seq,
        leave_request_id,
        actor.clone(),
        conversation_id,
        received_at,
        byte,
    );
    let registration = LockedRegistrationProjection::for_test(&evidence);
    LeaveRequestCommand {
        actor,
        leave_request_id,
        received_at,
        evidence,
        registration,
    }
}

fn registered_leave_cancellation(
    actor: DeviceIdentity,
    leave_request_id: [u8; 16],
    received_at: ServerTimestamp,
    conversation_id: [u8; 16],
    seq: u64,
    byte: u8,
) -> LeaveCancellation {
    let evidence = request_evidence(
        RequestEntryKind::LeaveCancellation,
        seq,
        leave_request_id,
        actor.clone(),
        conversation_id,
        received_at,
        byte,
    );
    let registration = LockedRegistrationProjection::for_test(&evidence);
    LeaveCancellation {
        actor,
        leave_request_id,
        received_at,
        evidence,
        registration,
    }
}

fn uuid_v4_bytes(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x40 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}

fn coordinate_json(coordinate: &PublicGroupSnapshotCoordinate) -> Value {
    json!({
        "conversationId": Uuid::from_bytes(*coordinate.conversation_id()).hyphenated().to_string(),
        "generation": coordinate.generation(),
        "stateVersion": coordinate.state_version(),
        "groupId": STANDARD.encode(coordinate.group_id()),
        "epoch": coordinate.epoch(),
        "groupContextHash": STANDARD.encode(coordinate.group_context_hash()),
        "confirmationTag": STANDARD.encode(coordinate.confirmation_tag()),
        "lifecycle": match coordinate.lifecycle() {
            PublicGroupSnapshotLifecycle::Active => "active",
            PublicGroupSnapshotLifecycle::Superseded => "superseded",
        },
    })
}

fn resign_signed_wrapper(mut wrapper: Value, signing_key: &SigningKey) -> Vec<u8> {
    wrapper["signature"] = Value::String(STANDARD.encode([0u8; 64]));
    let unsigned = serde_json::to_vec(&wrapper).unwrap();
    let canonical = decode_canonical_signed_mutation(&unsigned).unwrap();
    wrapper["signature"] =
        Value::String(STANDARD.encode(signing_key.sign(canonical.transcript_bytes()).to_bytes()));
    serde_json::to_vec(&wrapper).unwrap()
}

fn signed_leaf_recovery_request_raw(
    coordinate: &PublicGroupSnapshotCoordinate,
    actor: &DeviceIdentity,
    request_id: [u8; 16],
    signing_key: &SigningKey,
) -> Vec<u8> {
    let kind = SignedMutationKind::LeafRecoveryRequest;
    let body = json!({
        "$type": kind.type_id(),
        "signatureDomain": String::from_utf8(kind.domain().to_vec()).unwrap(),
        "recoveryRequestId": Uuid::from_bytes(request_id).hyphenated().to_string(),
        "actorDid": std::str::from_utf8(actor.principal().as_bytes()).unwrap(),
        "actorDeviceId": Uuid::from_bytes(*actor.device_id()).hyphenated().to_string(),
        "keyId": ed25519_key_id(&signing_key.verifying_key().to_bytes()).unwrap().as_str(),
        "authGeneration": 1,
        "prior": coordinate_json(coordinate),
        "recoveryKind": "replace",
        "idempotencyKey": Uuid::from_bytes(uuid_v4_bytes(0x6d)).hyphenated().to_string(),
        "signedAt": "2029-12-31T23:59:59.000Z",
    });
    resign_signed_wrapper(json!({ "body": body, "signature": "" }), signing_key)
}

#[test]
fn persisted_signed_request_restart_reverifies_raw_authority_and_frozen_row() {
    let state = accepted_direct();
    let actor = bob(&corpus_manifest());
    let request_id = uuid_v4_bytes(0x69);
    let conversation_id = *state.coordinate().conversation_id();
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let raw =
        signed_leaf_recovery_request_raw(state.coordinate(), &actor, request_id, &signing_key);
    let authority = HydrationAuthority::new(conversation_id).unwrap();
    let received_at_text = "2030-01-01T00:00:00.000Z";
    let trusted_received_at = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(received_at_text).unwrap(),
    );
    let admitted = authority
        .signed_request(
            DurableSignedRequestEnvelope::new(conversation_id, &trusted_received_at).unwrap(),
            decode_and_verify_signed_mutation(&raw, &signing_key.verifying_key().to_bytes())
                .unwrap(),
        )
        .unwrap();
    let durable_row_digest = *admitted.durable_row_digest();

    let persisted_row = |received_at: &str, digest: [u8; 32]| {
        PersistedSignedRequestRow::new(conversation_id, received_at, digest).unwrap()
    };
    let restarted = authority
        .hydrate_persisted_signed_request(
            persisted_row(received_at_text, durable_row_digest),
            &raw,
            &signing_key.verifying_key().to_bytes(),
        )
        .unwrap();
    assert_eq!(restarted, admitted);

    let wrong_historical_key = SigningKey::from_bytes(&[0x43; 32]);
    assert_eq!(
        authority.hydrate_persisted_signed_request(
            persisted_row(received_at_text, durable_row_digest),
            &raw,
            &wrong_historical_key.verifying_key().to_bytes(),
        ),
        Err(StateMachineError::InvalidHydrationAuthority)
    );
    assert_eq!(
        authority.hydrate_persisted_signed_request(
            persisted_row("2030-01-01T00:00:00.001Z", durable_row_digest),
            &raw,
            &signing_key.verifying_key().to_bytes(),
        ),
        Err(StateMachineError::InvalidHydrationAuthority)
    );

    let mut validly_resigned_body_tamper: Value = serde_json::from_slice(&raw).unwrap();
    validly_resigned_body_tamper["body"]["recoveryKind"] = Value::String("add".to_owned());
    let validly_resigned_body_tamper =
        resign_signed_wrapper(validly_resigned_body_tamper, &signing_key);
    assert_eq!(
        authority.hydrate_persisted_signed_request(
            persisted_row(received_at_text, durable_row_digest),
            &validly_resigned_body_tamper,
            &signing_key.verifying_key().to_bytes(),
        ),
        Err(StateMachineError::InvalidHydrationAuthority)
    );

    let mut signature_tamper: Value = serde_json::from_slice(&raw).unwrap();
    signature_tamper["signature"] = Value::String(STANDARD.encode([0x99; 64]));
    let signature_tamper = serde_json::to_vec(&signature_tamper).unwrap();
    assert_eq!(
        authority.hydrate_persisted_signed_request(
            persisted_row(received_at_text, durable_row_digest),
            &signature_tamper,
            &signing_key.verifying_key().to_bytes(),
        ),
        Err(StateMachineError::InvalidHydrationAuthority)
    );

    let mut digest_tamper = durable_row_digest;
    digest_tamper[0] ^= 0x01;
    assert_eq!(
        authority.hydrate_persisted_signed_request(
            persisted_row(received_at_text, digest_tamper),
            &raw,
            &signing_key.verifying_key().to_bytes(),
        ),
        Err(StateMachineError::InvalidHydrationAuthority)
    );
}

#[test]
fn leave_requires_sealed_active_registration_for_exact_request_key_generation() {
    let manifest = corpus_manifest();
    let group = added_group();
    let actor = bob(&manifest);
    let leave_request_id = uuid_v4_bytes(0x71);
    let received_at_text = "2030-01-01T00:00:00.000Z";
    let trusted_read_at = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(received_at_text).unwrap(),
    );
    let received_at = ServerTimestamp::from_trusted_request_instant(&trusted_read_at).unwrap();
    let evidence = request_evidence(
        RequestEntryKind::LeaveRequest,
        7,
        leave_request_id,
        actor.clone(),
        *group.coordinate().conversation_id(),
        received_at,
        0x72,
    );
    let authority = HydrationAuthority::new(*group.coordinate().conversation_id()).unwrap();
    let expected_digest = PersistedRegistrationRow::expected_digest(
        *group.coordinate().conversation_id(),
        &actor,
        [0x72; 32],
        [0x74; 32],
        1,
        PersistedRegistrationStatus::Active,
    );
    let registration_row = |digest: [u8; 32], status: PersistedRegistrationStatus| {
        PersistedRegistrationRow::new(
            *group.coordinate().conversation_id(),
            BareDid::parse(std::str::from_utf8(actor.principal().as_bytes()).unwrap()).unwrap(),
            CanonicalUuidV4::parse(
                &Uuid::from_bytes(*actor.device_id())
                    .hyphenated()
                    .to_string(),
            )
            .unwrap(),
            KeyThumbprint::parse(&URL_SAFE_NO_PAD.encode([0x72; 32])).unwrap(),
            [0x74; 32],
            1,
            status,
            digest,
        )
        .unwrap()
    };
    let registration = authority
        .locked_registration(
            registration_row(expected_digest, PersistedRegistrationStatus::Active),
            &trusted_read_at,
        )
        .unwrap();
    plan_leave_request(
        &group,
        LeaveRequestCommand {
            actor: actor.clone(),
            leave_request_id,
            received_at,
            evidence: evidence.clone(),
            registration,
        },
    )
    .expect("canonical active device/key row authorizes its exact signed request");

    let mut digest_tamper = expected_digest;
    digest_tamper[0] ^= 0x01;
    assert!(matches!(
        authority.locked_registration(
            registration_row(digest_tamper, PersistedRegistrationStatus::Active),
            &trusted_read_at,
        ),
        Err(StateMachineError::InvalidHydrationAuthority)
    ));
    assert_eq!(
        plan_leave_request(
            &group,
            LeaveRequestCommand {
                actor: actor.clone(),
                leave_request_id,
                received_at,
                evidence: evidence.clone(),
                registration: LockedRegistrationProjection::for_test_with_status(
                    &evidence,
                    PersistedRegistrationStatus::Revoked,
                ),
            },
        ),
        Err(StateMachineError::InvalidHydrationAuthority)
    );
    assert_eq!(
        plan_leave_request(
            &group,
            LeaveRequestCommand {
                actor: actor.clone(),
                leave_request_id,
                received_at,
                evidence: evidence.clone(),
                registration: LockedRegistrationProjection::for_test_with_key(
                    &evidence, [0x73; 32],
                ),
            },
        ),
        Err(StateMachineError::InvalidHydrationAuthority)
    );
    assert_eq!(
        plan_leave_request(
            &group,
            LeaveRequestCommand {
                actor,
                leave_request_id,
                received_at,
                evidence: evidence.clone(),
                registration: LockedRegistrationProjection::for_test_with_auth_generation(
                    &evidence, 2,
                ),
            },
        ),
        Err(StateMachineError::InvalidHydrationAuthority)
    );
}

fn verified_genesis() -> chat_protocol::public_state::ActivePublicState {
    frozen_public_state::restore_genesis()
}

struct FreshActorGroupInfo {
    bytes: Vec<u8>,
    signature_key: Vec<u8>,
    now_unix_seconds: u64,
    coordinate: PublicGroupSnapshotCoordinate,
}

fn fresh_actor_group_info() -> FreshActorGroupInfo {
    let manifest = corpus_manifest();
    let credential = manifest.identity.alice.credential_identity.as_bytes();
    let provider = openmls_libcrux_crypto::Provider::new().expect("fresh GroupInfo provider");
    let signer =
        SignatureKeyPair::new(XWING_CIPHERSUITE.signature_algorithm()).expect("fresh signer");
    signer
        .store(provider.storage())
        .expect("store fresh signer");
    let signature_key = signer.to_public_vec();
    let now_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let capabilities = Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[XWING_CIPHERSUITE]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    );
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(XWING_CIPHERSUITE)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .capabilities(capabilities)
        .lifetime(Lifetime::init(
            now_unix_seconds - 60,
            now_unix_seconds + 3_600,
        ))
        .build();
    let group = MlsGroup::new_with_group_id(
        &provider,
        &signer,
        &config,
        GroupId::from_slice(&[0xd0; 32]),
        CredentialWithKey {
            credential: BasicCredential::new(credential.to_vec()).into(),
            signature_key: signature_key.clone().into(),
        },
    )
    .expect("create fresh actor-only group");
    let bytes = group
        .export_group_info(provider.crypto(), &signer, true)
        .expect("export fresh actor-only GroupInfo")
        .tls_serialize_detached()
        .expect("serialize fresh actor-only GroupInfo");
    let validated = validate_group_info(
        &bytes,
        GroupInfoValidationPolicy {
            expected_basic_credential: credential,
            expected_signature_key: &signature_key,
            now_unix_seconds,
            max_bytes: MAX_GROUP_INFO_WIRE_BYTES,
            max_ratchet_tree_bytes: 1_048_576,
            max_members: 1,
        },
    )
    .expect("derive fresh GroupInfo coordinate");
    let coordinate = PublicGroupSnapshotCoordinate::new(
        hex_array(&manifest.identifiers.conversation_id_hex),
        0,
        0,
        validated.group_id().try_into().expect("32-byte group id"),
        validated.epoch(),
        *validated.group_context_hash(),
        *validated.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    FreshActorGroupInfo {
        bytes,
        signature_key,
        now_unix_seconds,
        coordinate,
    }
}

#[test]
fn already_expired_frozen_genesis_restores_through_persisted_binding() {
    let manifest = corpus_manifest();
    let state = frozen_public_state::restore_genesis();
    assert_eq!(state.coordinate(), &genesis_coordinate(&manifest));
    assert_eq!(state.binding().snapshot_sha256(), state.snapshot_sha256());
    assert_eq!(state.binding().tree_summary().leaves().len(), 1);
    assert_eq!(state.verified_group_info_sha256(), None);
}

#[test]
fn canonical_tree_summary_codec_is_digest_first_closed_and_round_trips() {
    let state = verified_genesis();
    let summary = state.binding().tree_summary();
    let encoded = encode_public_tree_summary(summary).unwrap();
    let decoded = decode_public_tree_summary(encoded.bytes(), encoded.sha256()).unwrap();
    assert_eq!(&decoded, summary);

    let mut one_field_splice = encoded.bytes().to_vec();
    *one_field_splice.last_mut().unwrap() ^= 0x01;
    assert_eq!(
        decode_public_tree_summary(&one_field_splice, encoded.sha256()),
        Err(PublicStateError::TreeSummaryDigestMismatch)
    );

    let mut unknown_schema = encoded.bytes().to_vec();
    unknown_schema[8..10].copy_from_slice(&2u16.to_be_bytes());
    let unknown_digest: [u8; 32] = Sha256::digest(&unknown_schema).into();
    assert_eq!(
        decode_public_tree_summary(&unknown_schema, &unknown_digest),
        Err(PublicStateError::InvalidTreeSummary)
    );

    let mut trailing = encoded.bytes().to_vec();
    trailing.push(0);
    let trailing_digest: [u8; 32] = Sha256::digest(&trailing).into();
    assert_eq!(
        decode_public_tree_summary(&trailing, &trailing_digest),
        Err(PublicStateError::InvalidTreeSummary)
    );

    let leaf = summary.leaves()[0].clone();
    let duplicate =
        PublicGroupSnapshotTreeSummary::new(*summary.tree_hash(), vec![leaf.clone(), leaf]);
    assert_eq!(
        encode_public_tree_summary(&duplicate),
        Err(PublicStateError::InvalidTreeSummary)
    );

    let oversized = vec![0u8; 256 * 1024 + 1];
    let oversized_digest: [u8; 32] = Sha256::digest(&oversized).into();
    assert_eq!(
        decode_public_tree_summary(&oversized, &oversized_digest),
        Err(PublicStateError::InvalidTreeSummary)
    );
    assert_eq!(
        decode_public_tree_summary(&oversized, &[0xAA; 32]),
        Err(PublicStateError::InvalidTreeSummary)
    );
}

fn direct_creation() -> chat_protocol::state_machine::ConversationState {
    let manifest = corpus_manifest();
    let command = CreationCommand {
        kind: ConversationKind::Direct,
        creator: alice(&manifest),
        invitees: vec![bob(&manifest).principal().clone()],
        transition: evidence(GENESIS_SEQ, 0x11),
        public_state: verified_genesis(),
    };
    match plan_creation(None, command).expect("valid direct creation") {
        CreationDecision::Create(plan) => plan.into_state(),
        CreationDecision::ExistingDirect { .. } => panic!("fresh direct must be created"),
    }
}

fn group_creation() -> chat_protocol::state_machine::ConversationState {
    let manifest = corpus_manifest();
    let command = CreationCommand {
        kind: ConversationKind::Group,
        creator: alice(&manifest),
        invitees: vec![bob(&manifest).principal().clone()],
        transition: evidence(GENESIS_SEQ, 0x11),
        public_state: verified_genesis(),
    };
    match plan_creation(None, command).expect("valid group creation") {
        CreationDecision::Create(plan) => plan.into_state(),
        CreationDecision::ExistingDirect { .. } => panic!("group has no direct identity"),
    }
}

fn accepted_direct() -> chat_protocol::state_machine::ConversationState {
    let manifest = corpus_manifest();
    let state = direct_creation();
    plan_accept_conversation(
        &state,
        AcceptConversation {
            actor: bob(&manifest),
            transition: evidence(ACCEPT_SEQ, 0x22),
            recovery_request_id: uuid_v4_bytes(0x23),
            key_package_ref: hex_array(&manifest.chain.inner_key_package_ref_hex),
            package_not_after: fixture_package_not_after(),
        },
    )
    .expect("pending direct invitee accepts")
    .into_state()
}

fn accepted_group() -> chat_protocol::state_machine::ConversationState {
    let manifest = corpus_manifest();
    plan_accept_conversation(
        &group_creation(),
        AcceptConversation {
            actor: bob(&manifest),
            transition: evidence(ACCEPT_SEQ, 0x22),
            recovery_request_id: uuid_v4_bytes(0x23),
            key_package_ref: hex_array(&manifest.chain.inner_key_package_ref_hex),
            package_not_after: fixture_package_not_after(),
        },
    )
    .expect("pending group invitee accepts")
    .into_state()
}

fn verified_add_commit(
    state: &chat_protocol::state_machine::ConversationState,
) -> chat_protocol::public_state::VerifiedCommitPublicState {
    let manifest = corpus_manifest();
    let sender_leaf_index = state
        .leaf(&alice(&manifest))
        .expect("Alice sender leaf")
        .leaf_index();
    frozen_public_state::restore_add_commit(state.public_state(), sender_leaf_index)
}

fn added_direct() -> chat_protocol::state_machine::ConversationState {
    let manifest = corpus_manifest();
    let state = accepted_direct();
    let commit = verified_add_commit(&state);
    let package_ref = hex_array(&manifest.chain.inner_key_package_ref_hex);
    let welcome = verify_recovery_welcome(&corpus_file("welcome.mls"), package_ref, 1_048_576)
        .expect("one-recipient Welcome is request-bound");
    plan_leaf_recovery_fulfillment(
        &state,
        LeafRecoveryFulfillment {
            actor: alice(&manifest),
            target: bob(&manifest),
            recovery_request_id: uuid_v4_bytes(0x23),
            welcome_id: uuid_v4_bytes(0x34),
            transition: evidence(ADD_SEQ, 0x33),
            commit,
            welcome,
        },
    )
    .expect("accepted target is added exactly once")
    .into_state()
}

fn added_group() -> chat_protocol::state_machine::ConversationState {
    let manifest = corpus_manifest();
    let state = accepted_group();
    let commit = verified_add_commit(&state);
    let package_ref = hex_array(&manifest.chain.inner_key_package_ref_hex);
    let welcome = verify_recovery_welcome(&corpus_file("welcome.mls"), package_ref, 1_048_576)
        .expect("one-recipient Welcome is request-bound");
    plan_leaf_recovery_fulfillment(
        &state,
        LeafRecoveryFulfillment {
            actor: alice(&manifest),
            target: bob(&manifest),
            recovery_request_id: uuid_v4_bytes(0x23),
            welcome_id: uuid_v4_bytes(0x34),
            transition: evidence(ADD_SEQ, 0x33),
            commit,
            welcome,
        },
    )
    .expect("accepted group target is added exactly once")
    .into_state()
}

fn reset_direct() -> chat_protocol::state_machine::ConversationState {
    let manifest = corpus_manifest();
    let state = accepted_direct();
    let request_id = uuid_v4_bytes(0x61);
    let requested = plan_reset_request(
        &state,
        ResetRequestCommand {
            actor: bob(&manifest),
            reset_request_id: request_id,
            received_at: fixture_received_at(3),
            evidence: request_evidence(
                RequestEntryKind::ResetRequest,
                3,
                request_id,
                bob(&manifest),
                *state.coordinate().conversation_id(),
                fixture_received_at(3),
                0x61,
            ),
        },
    )
    .unwrap()
    .into_state();
    let successor_coordinate = PublicGroupSnapshotCoordinate::new(
        *state.coordinate().conversation_id(),
        state.coordinate().generation() + 1,
        0,
        [0x62; 32],
        0,
        [0x63; 32],
        [0x64; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    plan_reset_activation(
        &requested,
        ResetActivation {
            actor: alice(&manifest),
            reset_request_id: request_id,
            transition: evidence(4, 0x66),
            successor_public_state: chat_protocol::public_state::ActivePublicState::for_test(
                &verified_genesis(),
                successor_coordinate,
            ),
        },
    )
    .unwrap()
    .into_state()
}

fn group_with_two_open_recoveries() -> chat_protocol::state_machine::ConversationState {
    let manifest = corpus_manifest();
    let group = added_group();
    let alice_sibling =
        DeviceIdentity::new(alice(&manifest).principal().clone(), uuid_v4_bytes(0xd1)).unwrap();
    let bob_sibling =
        DeviceIdentity::new(bob(&manifest).principal().clone(), uuid_v4_bytes(0xd2)).unwrap();
    let first_id = uuid_v4_bytes(0xd3);
    let first = plan_leaf_recovery_request(
        &group,
        LeafRecoveryRequestCommand {
            actor: alice_sibling.clone(),
            recovery_request_id: first_id,
            kind: LeafRecoveryKind::Add,
            key_package_ref: [0xd4; 32],
            received_at: fixture_received_at(4),
            package_not_after: fixture_package_not_after(),
            evidence: request_evidence(
                RequestEntryKind::LeafRecoveryRequest,
                4,
                first_id,
                alice_sibling,
                *group.coordinate().conversation_id(),
                fixture_received_at(4),
                0xd3,
            ),
        },
    )
    .unwrap()
    .into_state();
    let second_id = uuid_v4_bytes(0xd5);
    plan_leaf_recovery_request(
        &first,
        LeafRecoveryRequestCommand {
            actor: bob_sibling.clone(),
            recovery_request_id: second_id,
            kind: LeafRecoveryKind::Add,
            key_package_ref: [0xd6; 32],
            received_at: fixture_received_at(5),
            package_not_after: fixture_package_not_after(),
            evidence: request_evidence(
                RequestEntryKind::LeafRecoveryRequest,
                5,
                second_id,
                bob_sibling,
                *group.coordinate().conversation_id(),
                fixture_received_at(5),
                0xd5,
            ),
        },
    )
    .unwrap()
    .into_state()
}

fn verified_remove_bob_commit(
    state: &chat_protocol::state_machine::ConversationState,
) -> chat_protocol::public_state::VerifiedCommitPublicState {
    let manifest = corpus_manifest();
    let alice_leaf = state.leaf(&alice(&manifest)).expect("Alice leaf");
    let bob_leaf = state.leaf(&bob(&manifest)).expect("Bob leaf");
    let current = state.coordinate();
    let next = PublicGroupSnapshotCoordinate::new(
        *current.conversation_id(),
        current.generation(),
        current.state_version() + 1,
        *current.group_id(),
        current.epoch() + 1,
        [0xd1; 32],
        [0xd2; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    chat_protocol::public_state::VerifiedCommitPublicState::for_test_remove(
        state.public_state(),
        next,
        alice_leaf.leaf_index(),
        &[bob_leaf.leaf_index()],
    )
    .expect("synthetic sealed remove evidence")
}

#[test]
fn group_info_binding_is_digest_first_and_exact_coordinate_bound() {
    let manifest = corpus_manifest();
    let state = verified_genesis();
    assert_eq!(state.coordinate(), &genesis_coordinate(&manifest));
    assert_eq!(state.binding().snapshot_sha256(), state.snapshot_sha256());
    assert_eq!(state.binding().tree_summary().leaves().len(), 1);

    let mut corrupt = state.snapshot().to_vec();
    corrupt[0] ^= 0x01;
    assert_eq!(
        chat_protocol::public_state::load_active_snapshot(&corrupt, state.binding()),
        Err(PublicStateError::SnapshotDigestMismatch)
    );

    let fresh = fresh_actor_group_info();
    let wrong_coordinate = PublicGroupSnapshotCoordinate::new(
        *fresh.coordinate.conversation_id(),
        0,
        0,
        [0x55; 32],
        0,
        *fresh.coordinate.group_context_hash(),
        *fresh.coordinate.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    assert!(matches!(
        verify_genesis_group_info(
            &fresh.bytes,
            GenesisGroupInfoExpectations {
                coordinate: wrong_coordinate,
                expected_basic_credential: manifest.identity.alice.credential_identity.as_bytes(),
                expected_signature_key: &fresh.signature_key,
                now_unix_seconds: fresh.now_unix_seconds,
                max_wire_bytes: 1_048_576,
                max_ratchet_tree_bytes: 1_048_576,
                max_members: 100,
            },
        ),
        Err(PublicStateError::CoordinateMismatch)
    ));
}

#[test]
fn reset_successor_requires_a_real_actor_only_fresh_generation_group_info() {
    let manifest = corpus_manifest();
    let fresh = fresh_actor_group_info();
    let prior = PublicGroupSnapshotCoordinate::new(
        *fresh.coordinate.conversation_id(),
        0,
        7,
        [0xa1; 32],
        9,
        [0xa2; 32],
        [0xa3; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    let successor = PublicGroupSnapshotCoordinate::new(
        *prior.conversation_id(),
        1,
        0,
        *fresh.coordinate.group_id(),
        0,
        *fresh.coordinate.group_context_hash(),
        *fresh.coordinate.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    let verified = verify_reset_successor_group_info(
        &fresh.bytes,
        &prior,
        ResetSuccessorGroupInfoExpectations {
            coordinate: successor,
            expected_basic_credential: manifest.identity.alice.credential_identity.as_bytes(),
            expected_signature_key: &fresh.signature_key,
            now_unix_seconds: fresh.now_unix_seconds,
            max_wire_bytes: 1_048_576,
            max_ratchet_tree_bytes: 1_048_576,
            max_members: 100,
        },
    )
    .expect("a real actor-only GroupInfo may activate the exact fresh generation");
    assert_eq!(verified.coordinate(), &successor);

    let same_group_prior = PublicGroupSnapshotCoordinate::new(
        *prior.conversation_id(),
        prior.generation(),
        prior.state_version(),
        *successor.group_id(),
        prior.epoch(),
        *prior.group_context_hash(),
        *prior.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    assert_eq!(
        verify_reset_successor_group_info(
            &fresh.bytes,
            &same_group_prior,
            ResetSuccessorGroupInfoExpectations {
                coordinate: successor,
                expected_basic_credential: manifest.identity.alice.credential_identity.as_bytes(),
                expected_signature_key: &fresh.signature_key,
                now_unix_seconds: fresh.now_unix_seconds,
                max_wire_bytes: 1_048_576,
                max_ratchet_tree_bytes: 1_048_576,
                max_members: 100,
            },
        ),
        Err(PublicStateError::InvalidResetSuccessorCoordinate)
    );
}

#[test]
fn creation_freezes_direct_shape_and_duplicate_returns_existing_without_residue() {
    let manifest = corpus_manifest();
    let state = direct_creation();
    assert_eq!(state.kind(), ConversationKind::Direct);
    assert_eq!(state.participants().len(), 2);
    assert_eq!(state.leaves().len(), 1);
    assert_eq!(state.intervals().len(), 1);
    assert_eq!(state.intervals()[0].opening_kind(), OpeningKind::Creation);
    assert!(state
        .participant(bob(&manifest).principal())
        .unwrap()
        .is_pending());

    let attempted_id = uuid_v4_bytes(0x77);
    let attempted_coordinate = PublicGroupSnapshotCoordinate::new(
        attempted_id,
        0,
        0,
        [0x77; 32],
        0,
        [0x78; 32],
        [0x79; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    let attempted_public_state = chat_protocol::public_state::ActivePublicState::for_test(
        &verified_genesis(),
        attempted_coordinate,
    );
    let command = CreationCommand {
        kind: ConversationKind::Direct,
        creator: alice(&manifest),
        invitees: vec![bob(&manifest).principal().clone()],
        transition: evidence(1, 0x78),
        public_state: attempted_public_state,
    };
    let before = state.clone();
    let decision = plan_creation(Some(&state), command).expect("same live pair converges");
    assert!(matches!(
        decision,
        CreationDecision::ExistingDirect { coordinate, .. }
            if coordinate == *state.coordinate()
    ));
    assert_eq!(
        state, before,
        "duplicate decision cannot mutate existing state"
    );
}

#[test]
fn acceptance_rebinds_same_snapshot_and_opens_no_application_interval() {
    let manifest = corpus_manifest();
    let before = direct_creation();
    let after = accepted_direct();
    assert_eq!(after.coordinate().state_version(), 1);
    assert_eq!(after.coordinate().epoch(), 0);
    assert_eq!(
        after.public_state().snapshot(),
        before.public_state().snapshot()
    );
    assert_ne!(
        after.public_state().binding(),
        before.public_state().binding()
    );
    assert_eq!(after.intervals(), before.intervals());
    assert!(after
        .participant(bob(&manifest).principal())
        .unwrap()
        .is_active());
    let request = after
        .recovery_request(&uuid_v4_bytes(0x23))
        .expect("acceptance creates recovery request");
    assert_eq!(request.source(), RecoverySource::Acceptance);
    assert_eq!(request.bound_coordinate(), after.coordinate());
}

#[test]
fn acceptance_recovery_package_comparison_rejects_wrapper_and_hash_drift() {
    let manifest = corpus_manifest();
    let prior = direct_creation().coordinate().clone();
    let wrapper = vec![0xAA_u8; 32];
    let wrapper_sha256: [u8; 32] = Sha256::digest(&wrapper).into();
    let acceptance = TransitionEvidence::for_test_acceptance(
        ACCEPT_SEQ,
        uuid_v4_bytes(0x22),
        [0x22; 32],
        fixture_received_at(ACCEPT_SEQ),
        prior,
        uuid_v4_bytes(0x23),
        bob(&manifest),
        uuid_v4_bytes(0x11),
        alice(&manifest),
        hex_array(&manifest.chain.inner_key_package_ref_hex),
        [0x44; 32],
        1,
        fixture_package_not_after(),
    )
    .expect("acceptance evidence");

    assert!(acceptance_recovery_package_artifact_matches(
        &acceptance,
        &wrapper,
        &wrapper_sha256,
    ));

    let mut wrong_wrapper = wrapper.clone();
    wrong_wrapper[0] ^= 1;
    assert!(!acceptance_recovery_package_artifact_matches(
        &acceptance,
        &wrong_wrapper,
        &wrapper_sha256,
    ));

    let mut wrong_hash = wrapper_sha256;
    wrong_hash[0] ^= 1;
    assert!(!acceptance_recovery_package_artifact_matches(
        &acceptance,
        &wrapper,
        &wrong_hash,
    ));
}

#[test]
fn stale_commit_is_rejected_without_partial_state_mutation() {
    let manifest = corpus_manifest();
    let accepted = accepted_direct();
    let commit = verified_add_commit(&accepted);
    let welcome = verify_recovery_welcome(
        &corpus_file("welcome.mls"),
        hex_array(&manifest.chain.inner_key_package_ref_hex),
        1_048_576,
    )
    .unwrap();
    let advanced = accepted
        .for_test_with_state_version(accepted.coordinate().state_version() + 1)
        .expect("test-only concurrent policy edge");
    let before = advanced.clone();
    assert_eq!(
        plan_leaf_recovery_fulfillment(
            &advanced,
            LeafRecoveryFulfillment {
                actor: alice(&manifest),
                target: bob(&manifest),
                recovery_request_id: uuid_v4_bytes(0x23),
                welcome_id: uuid_v4_bytes(0x34),
                transition: evidence(ADD_SEQ, 0x33),
                commit,
                welcome,
            },
        ),
        Err(StateMachineError::StaleCoordinates)
    );
    assert_eq!(advanced, before);
}

#[test]
fn recovery_is_bound_to_exact_target_device_request_package_and_welcome() {
    let manifest = corpus_manifest();
    let state = accepted_direct();
    let sibling =
        DeviceIdentity::new(bob(&manifest).principal().clone(), uuid_v4_bytes(0x52)).unwrap();
    let before = state.clone();

    let duplicate_request = plan_leaf_recovery_request(
        &state,
        LeafRecoveryRequestCommand {
            actor: bob(&manifest),
            recovery_request_id: uuid_v4_bytes(0x53),
            kind: LeafRecoveryKind::Add,
            key_package_ref: [0x53; 32],
            received_at: fixture_received_at(3),
            package_not_after: fixture_package_not_after(),
            evidence: request_evidence(
                RequestEntryKind::LeafRecoveryRequest,
                3,
                uuid_v4_bytes(0x53),
                bob(&manifest),
                *state.coordinate().conversation_id(),
                fixture_received_at(3),
                0x53,
            ),
        },
    );
    assert_eq!(
        duplicate_request,
        Err(StateMachineError::LeafRecoveryAlreadyOpen),
        "one open request is keyed by exact conversation/generation/DID/device"
    );
    assert_eq!(state, before);

    let wrong_ref = [0xa5; 32];
    assert_eq!(
        verify_recovery_welcome(&corpus_file("welcome.mls"), wrong_ref, 1_048_576),
        Err(PublicStateError::WelcomePackageMismatch)
    );

    let commit = verified_add_commit(&state);
    let welcome = verify_recovery_welcome(
        &corpus_file("welcome.mls"),
        hex_array(&manifest.chain.inner_key_package_ref_hex),
        1_048_576,
    )
    .unwrap();
    assert_eq!(
        plan_leaf_recovery_fulfillment(
            &state,
            LeafRecoveryFulfillment {
                actor: alice(&manifest),
                target: sibling,
                recovery_request_id: uuid_v4_bytes(0x23),
                welcome_id: uuid_v4_bytes(0x34),
                transition: evidence(ADD_SEQ, 0x33),
                commit,
                welcome,
            },
        ),
        Err(StateMachineError::RecoveryDeviceMismatch)
    );
    assert_eq!(state, before);

    let added = added_direct();
    assert!(added.leaf(&bob(&manifest)).is_some());
    assert_eq!(added.intervals().len(), 2);
    assert_eq!(added.intervals()[1].opening_kind(), OpeningKind::Add);
}

#[test]
fn reset_requires_current_request_predecessor_and_fresh_successor_binding() {
    let manifest = corpus_manifest();
    let state = accepted_direct();
    let requested = plan_reset_request(
        &state,
        ResetRequestCommand {
            actor: bob(&manifest),
            reset_request_id: uuid_v4_bytes(0x61),
            received_at: fixture_received_at(3),
            evidence: request_evidence(
                RequestEntryKind::ResetRequest,
                3,
                uuid_v4_bytes(0x61),
                bob(&manifest),
                *state.coordinate().conversation_id(),
                fixture_received_at(3),
                0x61,
            ),
        },
    )
    .expect("active zero-leaf participant may request reset")
    .into_state();
    assert_eq!(requested.coordinate(), state.coordinate());

    let successor_coordinate = PublicGroupSnapshotCoordinate::new(
        *state.coordinate().conversation_id(),
        state.coordinate().generation() + 1,
        0,
        [0x62; 32],
        0,
        [0x63; 32],
        [0x64; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    let successor = chat_protocol::public_state::ActivePublicState::for_test(
        &verified_genesis(),
        successor_coordinate,
    );

    let advanced = requested
        .for_test_with_state_version(requested.coordinate().state_version() + 1)
        .unwrap();
    let before = advanced.clone();
    assert_eq!(
        plan_reset_activation(
            &advanced,
            ResetActivation {
                actor: alice(&manifest),
                reset_request_id: uuid_v4_bytes(0x61),
                transition: evidence(4, 0x66),
                successor_public_state: successor.clone(),
            },
        ),
        Err(StateMachineError::ResetRequestStale)
    );
    assert_eq!(advanced, before);

    let wrong_conversation = PublicGroupSnapshotCoordinate::new(
        uuid_v4_bytes(0x67),
        state.coordinate().generation() + 1,
        0,
        [0x62; 32],
        0,
        [0x63; 32],
        [0x64; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    assert_eq!(
        plan_reset_activation(
            &requested,
            ResetActivation {
                actor: alice(&manifest),
                reset_request_id: uuid_v4_bytes(0x61),
                transition: evidence(4, 0x66),
                successor_public_state: chat_protocol::public_state::ActivePublicState::for_test(
                    &verified_genesis(),
                    wrong_conversation,
                ),
            },
        ),
        Err(StateMachineError::ResetSuccessorMismatch)
    );

    let plan = plan_reset_activation(
        &requested,
        ResetActivation {
            actor: alice(&manifest),
            reset_request_id: uuid_v4_bytes(0x61),
            transition: evidence(4, 0x66),
            successor_public_state: successor,
        },
    )
    .expect("current request and fresh successor form one reset plan");
    assert_eq!(
        plan.retired_coordinate().unwrap().lifecycle(),
        PublicGroupSnapshotLifecycle::Superseded
    );
    let reset = plan.into_state();
    assert_eq!(
        reset.coordinate().generation(),
        state.coordinate().generation() + 1
    );
    assert_eq!(reset.coordinate().state_version(), 0);
    assert_eq!(reset.leaves().len(), 1);
    assert!(reset.leaf(&alice(&manifest)).is_some());
    assert!(reset.leaf(&bob(&manifest)).is_none());
}

#[test]
fn terminal_close_preserves_prior_remove_gap_and_only_closes_open_intervals() {
    let manifest = corpus_manifest();
    let state = added_direct();
    let bob_device = bob(&manifest);
    let with_gap = state
        .for_test_close_leaf_interval(
            &bob_device,
            evidence(5, 0x71),
            chat_protocol::state_machine::CloseKind::Remove,
        )
        .expect("test fixture closes Bob by Remove");
    let bob_intervals = with_gap.intervals_for(&bob_device);
    let bob_before = (*bob_intervals.last().expect("Bob historical interval")).clone();
    let plan = plan_close(
        &with_gap,
        CloseConversation {
            actor: alice(&manifest),
            transition: evidence(10, 0x72),
        },
    )
    .expect("direct participant may terminally close");
    assert!(plan.successor_coordinate().is_none());
    let closed = plan.into_state();
    assert_eq!(
        closed.coordinate().lifecycle(),
        PublicGroupSnapshotLifecycle::Superseded
    );
    assert_eq!(
        *closed.intervals_for(&bob_device).last().unwrap(),
        &bob_before
    );
    assert_eq!(closed.terminal_proofs().len(), 2);
    assert!(closed.terminal_proof(&bob_device).is_some());
    assert_eq!(
        closed
            .intervals_for(&alice(&manifest))
            .last()
            .unwrap()
            .end()
            .unwrap()
            .kind(),
        chat_protocol::state_machine::CloseKind::Terminal
    );
    assert!(closed.leaves().is_empty());

    let same_seq_state = direct_creation();
    assert_eq!(
        plan_close(
            &same_seq_state,
            CloseConversation {
                actor: alice(&manifest),
                transition: evidence(GENESIS_SEQ, 0x73),
            },
        ),
        Err(StateMachineError::InvalidIntervalBoundary)
    );
}

#[test]
fn zero_leaf_leave_is_group_only_and_failure_never_mutates_input() {
    let manifest = corpus_manifest();
    let direct = accepted_direct();
    let before = direct.clone();
    assert_eq!(
        plan_zero_leaf_leave(
            &direct,
            ZeroLeafLeave {
                actor: bob(&manifest),
                transition: evidence(4, 0x81),
            },
        ),
        Err(StateMachineError::DirectParticipantMutationForbidden)
    );
    assert_eq!(direct, before);

    let group = group_creation();
    let left = plan_zero_leaf_leave(
        &group,
        ZeroLeafLeave {
            actor: bob(&manifest),
            transition: evidence(2, 0x82),
        },
    )
    .expect("pending zero-leaf participant exits group immediately")
    .into_state();
    assert!(left.participant(bob(&manifest).principal()).is_none());
    assert_eq!(left.coordinate().state_version(), 1);
    assert_eq!(left.intervals(), group.intervals());
}

#[test]
fn generic_commit_form_rejects_a_request_bound_add_without_mutating_state() {
    let manifest = corpus_manifest();
    let state = accepted_group();
    let before = state.clone();
    assert_eq!(
        plan_commit(
            &state,
            CommitCommand {
                actor: alice(&manifest),
                transition: evidence(ADD_SEQ, 0x33),
                commit: verified_add_commit(&state),
            },
        ),
        Err(StateMachineError::InvalidCommitEffects)
    );
    assert_eq!(state, before);

    let state = added_group();
    let removed = plan_commit(
        &state,
        CommitCommand {
            actor: alice(&manifest),
            transition: evidence(4, 0x34),
            commit: verified_remove_bob_commit(&state),
        },
    )
    .expect("generic Commit may remove a device leaf without changing logical membership")
    .into_state();
    assert!(removed
        .participant(bob(&manifest).principal())
        .unwrap()
        .is_active());
    assert!(removed.leaf(&bob(&manifest)).is_none());
    assert_eq!(
        removed
            .intervals_for(&bob(&manifest))
            .last()
            .unwrap()
            .end()
            .unwrap()
            .kind(),
        chat_protocol::state_machine::CloseKind::Remove
    );
}

#[test]
fn leafed_group_leave_request_and_cancellation_preserve_coordinate_and_public_state() {
    let manifest = corpus_manifest();
    let group = added_group();
    let requested = plan_leave_request(
        &group,
        registered_leave_request(
            bob(&manifest),
            uuid_v4_bytes(0x83),
            fixture_received_at(4),
            *group.coordinate().conversation_id(),
            4,
            0x83,
        ),
    )
    .expect("leafed non-admin group participant may request leave")
    .into_state();
    assert_eq!(requested.coordinate(), group.coordinate());
    assert_eq!(requested.public_state(), group.public_state());
    assert_eq!(requested.intervals(), group.intervals());

    let cancelled = plan_leave_cancellation(
        &requested,
        registered_leave_cancellation(
            bob(&manifest),
            uuid_v4_bytes(0x83),
            fixture_received_at(5),
            *group.coordinate().conversation_id(),
            5,
            0x84,
        ),
    )
    .expect("same-DID active device cancels retained leave request")
    .into_state();
    assert_eq!(cancelled.coordinate(), group.coordinate());
    assert_eq!(cancelled.public_state(), group.public_state());
    assert_eq!(cancelled.intervals(), group.intervals());
    assert_eq!(
        cancelled
            .leave_request(&uuid_v4_bytes(0x83))
            .unwrap()
            .status(),
        LeaveRequestStatus::Cancelled
    );

    let requested = plan_leave_request(
        &group,
        registered_leave_request(
            bob(&manifest),
            uuid_v4_bytes(0x87),
            fixture_received_at(4),
            *group.coordinate().conversation_id(),
            4,
            0x87,
        ),
    )
    .unwrap()
    .into_state();
    let fulfilled = plan_leave_fulfillment(
        &requested,
        LeaveFulfillment {
            actor: alice(&manifest),
            requester: bob(&manifest).principal().clone(),
            leave_request_id: uuid_v4_bytes(0x87),
            transition: evidence(5, 0x88),
            commit: verified_remove_bob_commit(&requested),
        },
    )
    .expect("different-DID current leaf fulfills exact retained consent")
    .into_state();
    assert!(fulfilled.participant(bob(&manifest).principal()).is_none());
    assert!(fulfilled.leaf(&bob(&manifest)).is_none());
    assert!(fulfilled.leaf(&alice(&manifest)).is_some());
    assert_eq!(
        hydrate_conversation_state(fulfilled.clone()),
        Ok(fulfilled),
        "planner fulfillment retains the exact removed participant and closed-leaf proof"
    );
}

#[test]
fn fulfilled_leave_proof_matrix_is_complete_and_allows_later_rejoin() {
    let manifest = corpus_manifest();
    let group = added_group();
    let request_id = uuid_v4_bytes(0x89);
    let requested = plan_leave_request(
        &group,
        registered_leave_request(
            bob(&manifest),
            request_id,
            fixture_received_at(4),
            *group.coordinate().conversation_id(),
            4,
            0x89,
        ),
    )
    .unwrap()
    .into_state();
    let fulfilled = plan_leave_fulfillment(
        &requested,
        LeaveFulfillment {
            actor: alice(&manifest),
            requester: bob(&manifest).principal().clone(),
            leave_request_id: request_id,
            transition: evidence(5, 0x8a),
            commit: verified_remove_bob_commit(&requested),
        },
    )
    .unwrap()
    .into_state();
    let requester = bob(&manifest);
    let exact = fulfilled.for_test_mutate_leave_fulfillment(
        &request_id,
        LeaveFulfillmentTestMutation::ManifestDevices(vec![requester.clone()]),
    );
    assert!(
        exact.for_test_leave_fulfillment_matches(&request_id),
        "exact old participant period plus every pre-terminal requester leaf matches"
    );

    let nonexistent =
        DeviceIdentity::new(requester.principal().clone(), uuid_v4_bytes(0x8b)).unwrap();
    let foreign =
        DeviceIdentity::new(alice(&manifest).principal().clone(), uuid_v4_bytes(0x8c)).unwrap();
    for devices in [
        vec![],
        vec![requester.clone(), nonexistent],
        vec![requester.clone(), foreign],
        vec![requester.clone(), requester.clone()],
    ] {
        assert!(!fulfilled
            .for_test_mutate_leave_fulfillment(
                &request_id,
                LeaveFulfillmentTestMutation::ManifestDevices(devices),
            )
            .for_test_leave_fulfillment_matches(&request_id));
    }

    let wrong_principal = PrincipalId::new(b"did:plc:wrongproofprincipal".to_vec()).unwrap();
    for mutation in [
        LeaveFulfillmentTestMutation::DropParticipantProof,
        LeaveFulfillmentTestMutation::ProofPrincipal(wrong_principal),
        LeaveFulfillmentTestMutation::ProofInactive,
        LeaveFulfillmentTestMutation::ProofInvalidProvenance,
        LeaveFulfillmentTestMutation::ProofWrongTransition,
        LeaveFulfillmentTestMutation::ProofWrongSequence,
        LeaveFulfillmentTestMutation::ProofWrongTime,
        LeaveFulfillmentTestMutation::IntervalLeftOpen(requester.clone()),
        LeaveFulfillmentTestMutation::IntervalClosedLater(requester.clone()),
        LeaveFulfillmentTestMutation::IntervalWrongEvidence(requester.clone()),
        LeaveFulfillmentTestMutation::IntervalWrongKind(requester.clone()),
        LeaveFulfillmentTestMutation::IntervalOpenedAfterOrigin(requester.clone()),
        LeaveFulfillmentTestMutation::DuplicatePreTerminalInterval(requester.clone()),
    ] {
        let label = format!("{mutation:?}");
        assert!(
            !exact
                .for_test_mutate_leave_fulfillment(&request_id, mutation)
                .for_test_leave_fulfillment_matches(&request_id),
            "{label}"
        );
    }

    assert!(exact
        .for_test_mutate_leave_fulfillment(
            &request_id,
            LeaveFulfillmentTestMutation::LaterRejoin(requester),
        )
        .for_test_leave_fulfillment_matches(&request_id));
}

#[test]
fn group_close_and_terminal_proof_order_fail_closed_without_residue() {
    let manifest = corpus_manifest();
    let group = added_group();
    let before = group.clone();
    assert_eq!(
        plan_close(
            &group,
            CloseConversation {
                actor: alice(&manifest),
                transition: evidence(4, 0x84),
            },
        ),
        Err(StateMachineError::ConversationCloseNotAllowed)
    );
    assert_eq!(group, before);

    let direct = added_direct();
    let with_gap = direct
        .for_test_close_leaf_interval(
            &bob(&manifest),
            evidence(8, 0x85),
            chat_protocol::state_machine::CloseKind::Remove,
        )
        .unwrap();
    let gap_before = with_gap.clone();
    assert_eq!(
        plan_close(
            &with_gap,
            CloseConversation {
                actor: alice(&manifest),
                transition: evidence(7, 0x86),
            },
        ),
        Err(StateMachineError::InvalidIntervalBoundary)
    );
    assert_eq!(with_gap, gap_before);
}

#[test]
fn coordinate_only_rebind_rejects_stale_or_changed_crypto_fields() {
    let state = verified_genesis();
    let current = state.coordinate();
    let next = PublicGroupSnapshotCoordinate::new(
        *current.conversation_id(),
        current.generation(),
        current.state_version() + 1,
        *current.group_id(),
        current.epoch(),
        *current.group_context_hash(),
        *current.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    let rebound = rebind_active_snapshot(&state, next).expect("policy coordinate rebind");
    assert_eq!(rebound.snapshot(), state.snapshot());

    let changed_hash = PublicGroupSnapshotCoordinate::new(
        *current.conversation_id(),
        current.generation(),
        current.state_version() + 1,
        *current.group_id(),
        current.epoch(),
        [0x99; 32],
        *current.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    assert_eq!(
        rebind_active_snapshot(&state, changed_hash),
        Err(PublicStateError::CoordinateOnlyEdgeMismatch)
    );
}

#[test]
fn request_and_reservation_lifetimes_use_server_received_at_and_expire_closed() {
    let manifest = corpus_manifest();
    let accepted = accepted_direct();
    let request = accepted
        .recovery_request(&uuid_v4_bytes(0x23))
        .expect("acceptance creates one retained recovery request");
    assert_eq!(request.status(), RecoveryRequestStatus::Open);
    assert_eq!(
        request.expires_at().unix_millis(),
        request.received_at().unix_millis() + 300_000
    );
    let reservation = accepted
        .recovery_reservation(&uuid_v4_bytes(0x23))
        .expect("the request id is also the reservation id");
    assert_eq!(reservation.status(), ReservationStatus::Active);
    assert_eq!(reservation.expires_at(), request.expires_at());

    let commit = verified_add_commit(&accepted);
    let package_ref = hex_array(&manifest.chain.inner_key_package_ref_hex);
    let welcome =
        verify_recovery_welcome(&corpus_file("welcome.mls"), package_ref, 1_048_576).unwrap();
    let before = accepted.clone();
    assert_eq!(
        plan_leaf_recovery_fulfillment(
            &accepted,
            LeafRecoveryFulfillment {
                actor: alice(&manifest),
                target: bob(&manifest),
                recovery_request_id: uuid_v4_bytes(0x23),
                welcome_id: uuid_v4_bytes(0x34),
                transition: evidence_at(
                    ADD_SEQ,
                    0x33,
                    *request.expires_at(),
                    *accepted.coordinate().conversation_id(),
                ),
                commit,
                welcome,
            },
        ),
        Err(StateMachineError::WorkExpired)
    );
    assert_eq!(accepted, before);

    let reset_received = ServerTimestamp::from_unix_millis_for_test(1_800_000_000_123).unwrap();
    let reset = plan_reset_request(
        &accepted,
        ResetRequestCommand {
            actor: alice(&manifest),
            reset_request_id: uuid_v4_bytes(0x91),
            received_at: reset_received,
            evidence: request_evidence(
                RequestEntryKind::ResetRequest,
                4,
                uuid_v4_bytes(0x91),
                alice(&manifest),
                *accepted.coordinate().conversation_id(),
                reset_received,
                0x91,
            ),
        },
    )
    .unwrap()
    .into_state();
    let pending = reset.reset_request(&uuid_v4_bytes(0x91)).unwrap();
    assert_eq!(pending.status(), ResetRequestStatus::Pending);
    assert_eq!(
        pending.expires_at().unix_millis(),
        reset_received.unix_millis() + 86_400_000
    );

    let group = added_group();
    let leave_received = ServerTimestamp::from_unix_millis_for_test(1_800_100_000_456).unwrap();
    let leave = plan_leave_request(
        &group,
        registered_leave_request(
            bob(&manifest),
            uuid_v4_bytes(0x92),
            leave_received,
            *group.coordinate().conversation_id(),
            5,
            0x92,
        ),
    )
    .unwrap()
    .into_state();
    let pending = leave.leave_request(&uuid_v4_bytes(0x92)).unwrap();
    assert_eq!(pending.status(), LeaveRequestStatus::Pending);
    assert_eq!(
        pending.expires_at().unix_millis(),
        leave_received.unix_millis() + 86_400_000
    );
}

#[test]
fn leafed_leave_consent_accepts_an_active_registered_same_did_sibling_without_a_leaf() {
    let manifest = corpus_manifest();
    let group = added_group();
    let sibling =
        DeviceIdentity::new(bob(&manifest).principal().clone(), uuid_v4_bytes(0x95)).unwrap();
    assert!(group.leaf(&sibling).is_none());
    assert!(group.leaf(&bob(&manifest)).is_some());

    let requested = plan_leave_request(
        &group,
        registered_leave_request(
            sibling.clone(),
            uuid_v4_bytes(0x96),
            fixture_received_at(5),
            *group.coordinate().conversation_id(),
            5,
            0x96,
        ),
    )
    .expect("same-DID sibling signs consent while the participant owns another leaf")
    .into_state();
    let request = requested.leave_request(&uuid_v4_bytes(0x96)).unwrap();
    assert_eq!(request.status(), LeaveRequestStatus::Pending);
    assert_eq!(request.requester(), &sibling);
}

#[test]
fn leaf_recovery_cancellation_is_exact_device_bound_and_releases_the_same_reservation() {
    let manifest = corpus_manifest();
    let state = accepted_direct();
    let request_id = uuid_v4_bytes(0x23);
    let cancellation_time = fixture_received_at(3);
    let evidence = request_evidence(
        RequestEntryKind::LeafRecoveryCancellation,
        3,
        request_id,
        bob(&manifest),
        *state.coordinate().conversation_id(),
        cancellation_time,
        0x9a,
    );
    let cancelled = plan_leaf_recovery_cancellation(
        &state,
        LeafRecoveryCancellation {
            actor: bob(&manifest),
            recovery_request_id: request_id,
            received_at: cancellation_time,
            evidence,
        },
    )
    .expect("the exact target device may cancel its still-open request")
    .into_state();
    assert_eq!(
        cancelled.recovery_request(&request_id).unwrap().status(),
        RecoveryRequestStatus::Cancelled
    );
    assert_eq!(
        cancelled
            .recovery_reservation(&request_id)
            .unwrap()
            .status(),
        ReservationStatus::Released
    );
    assert_eq!(cancelled.coordinate(), state.coordinate());

    let sibling =
        DeviceIdentity::new(bob(&manifest).principal().clone(), uuid_v4_bytes(0x9b)).unwrap();
    let before = state.clone();
    assert_eq!(
        plan_leaf_recovery_cancellation(
            &state,
            LeafRecoveryCancellation {
                actor: sibling.clone(),
                recovery_request_id: request_id,
                received_at: cancellation_time,
                evidence: request_evidence(
                    RequestEntryKind::LeafRecoveryCancellation,
                    3,
                    request_id,
                    sibling,
                    *state.coordinate().conversation_id(),
                    cancellation_time,
                    0x9c,
                ),
            },
        ),
        Err(StateMachineError::RecoveryDeviceMismatch)
    );
    assert_eq!(state, before);

    assert_eq!(
        plan_leaf_recovery_cancellation(
            &state,
            LeafRecoveryCancellation {
                actor: bob(&manifest),
                recovery_request_id: request_id,
                received_at: fixture_received_at(ACCEPT_SEQ),
                evidence: request_evidence(
                    RequestEntryKind::LeafRecoveryCancellation,
                    ACCEPT_SEQ,
                    request_id,
                    bob(&manifest),
                    *state.coordinate().conversation_id(),
                    fixture_received_at(ACCEPT_SEQ),
                    0x9d,
                ),
            },
        ),
        Err(StateMachineError::InvalidTransition),
        "cancellation must be later than the retained origin"
    );
    assert_eq!(
        plan_leaf_recovery_cancellation(
            &state,
            LeafRecoveryCancellation {
                actor: bob(&manifest),
                recovery_request_id: request_id,
                received_at: cancellation_time,
                evidence: request_evidence(
                    RequestEntryKind::LeafRecoveryCancellation,
                    3,
                    request_id,
                    bob(&manifest),
                    *state.coordinate().conversation_id(),
                    cancellation_time,
                    0x20,
                ),
            },
        ),
        Err(StateMachineError::InvalidTransition),
        "cancellation cannot reuse the origin entry identity"
    );
}

#[test]
fn coordinate_change_retires_every_prior_bound_work_item_and_emits_a_complete_delta() {
    let manifest = corpus_manifest();
    let group = added_group();
    let sibling =
        DeviceIdentity::new(alice(&manifest).principal().clone(), uuid_v4_bytes(0xa0)).unwrap();
    let recovery_id = uuid_v4_bytes(0xa1);
    let recovery_time = fixture_received_at(4);
    let with_recovery = plan_leaf_recovery_request(
        &group,
        LeafRecoveryRequestCommand {
            actor: sibling.clone(),
            recovery_request_id: recovery_id,
            kind: LeafRecoveryKind::Add,
            key_package_ref: [0xa2; 32],
            received_at: recovery_time,
            package_not_after: fixture_package_not_after(),
            evidence: request_evidence(
                RequestEntryKind::LeafRecoveryRequest,
                4,
                recovery_id,
                sibling,
                *group.coordinate().conversation_id(),
                recovery_time,
                0xa1,
            ),
        },
    )
    .unwrap()
    .into_state();
    let reset_id = uuid_v4_bytes(0xa3);
    let reset_time = fixture_received_at(5);
    let with_reset = plan_reset_request(
        &with_recovery,
        ResetRequestCommand {
            actor: alice(&manifest),
            reset_request_id: reset_id,
            received_at: reset_time,
            evidence: request_evidence(
                RequestEntryKind::ResetRequest,
                5,
                reset_id,
                alice(&manifest),
                *group.coordinate().conversation_id(),
                reset_time,
                0xa3,
            ),
        },
    )
    .unwrap()
    .into_state();
    let leave_id = uuid_v4_bytes(0xa4);
    let leave_time = fixture_received_at(6);
    let prior = plan_leave_request(
        &with_reset,
        registered_leave_request(
            bob(&manifest),
            leave_id,
            leave_time,
            *group.coordinate().conversation_id(),
            6,
            0xa4,
        ),
    )
    .unwrap()
    .into_state();

    let plan = plan_commit(
        &prior,
        CommitCommand {
            actor: alice(&manifest),
            transition: evidence(7, 0xa5),
            commit: verified_remove_bob_commit(&prior),
        },
    )
    .expect("one coordinate CAS terminalizes every work item bound to the predecessor");
    let effects = plan.effects();
    assert!(effects.is_complete());
    assert_eq!(effects.before_counts().participants(), 2);
    assert_eq!(effects.after_counts().participants(), 2);
    assert_eq!(effects.interval_changes().len(), 1);
    assert!(effects.recovery_request_changes().len() >= 1);
    assert!(effects.reservation_changes().len() >= 1);
    assert_eq!(effects.reset_request_changes().len(), 1);
    assert_eq!(effects.leave_request_changes().len(), 1);
    assert_eq!(effects.welcome_changes().len(), 1);
    assert!(effects
        .package_transitions()
        .iter()
        .any(|change| change.key_package_ref() == &[0xa2; 32]
            && change.to() == PackageStatus::Available));

    let next = plan.into_state();
    assert_eq!(
        next.recovery_request(&recovery_id).unwrap().status(),
        RecoveryRequestStatus::Superseded
    );
    assert_eq!(
        next.recovery_reservation(&recovery_id).unwrap().status(),
        ReservationStatus::Released
    );
    assert_eq!(
        next.reset_request(&reset_id).unwrap().status(),
        ResetRequestStatus::Stale
    );
    assert_eq!(
        next.leave_request(&leave_id).unwrap().status(),
        LeaveRequestStatus::Stale
    );
    assert_eq!(
        next.welcome(&uuid_v4_bytes(0x34)).unwrap().status(),
        chat_protocol::state_machine::WelcomeStatus::Superseded
    );
}

#[test]
fn hydration_rejects_noncanonical_unbound_or_incomplete_persisted_state() {
    let manifest = corpus_manifest();
    let active = added_direct();
    assert_eq!(
        hydrate_conversation_state(active.clone()),
        Ok(active.clone()),
        "a planner-produced state round-trips through the production hydration gate"
    );

    assert_eq!(
        hydrate_conversation_state(active.for_test_reverse_intervals()),
        Err(StateMachineError::InvalidIntervalBoundary),
        "persisted intervals must already be in canonical recipient/opening order"
    );
    assert_eq!(
        hydrate_conversation_state(
            active.for_test_corrupt_first_interval_conversation(uuid_v4_bytes(0xc0))
        ),
        Err(StateMachineError::InvalidIntervalBoundary),
        "every historical opening context stays bound to this conversation"
    );

    let touching = active
        .for_test_touch_interval(
            &bob(&manifest),
            evidence(4, 0xc1),
            evidence(4, 0xc1),
            chat_protocol::state_machine::CloseKind::Replace,
            OpeningKind::Add,
        )
        .expect("construct one valid touching Replace/Add boundary");
    assert_eq!(
        hydrate_conversation_state(touching.clone()),
        Ok(touching.clone())
    );
    assert_eq!(
        hydrate_conversation_state(
            touching.for_test_corrupt_touching_opening_transition_id(&bob(&manifest))
        ),
        Err(StateMachineError::InvalidIntervalBoundary),
        "touching boundaries require the exact same transition id"
    );
    assert_eq!(
        hydrate_conversation_state(
            touching.for_test_corrupt_touching_opening_fingerprint(&bob(&manifest))
        ),
        Err(StateMachineError::InvalidIntervalBoundary),
        "touching boundaries require the exact same outer-entry fingerprint"
    );
    assert_eq!(
        hydrate_conversation_state(touching.for_test_corrupt_touching_close_kind(&bob(&manifest))),
        Err(StateMachineError::InvalidIntervalBoundary),
        "only Replace/Add and Reset/Reset may touch"
    );

    let terminal = plan_close(
        &active,
        CloseConversation {
            actor: alice(&manifest),
            transition: evidence(5, 0xc2),
        },
    )
    .expect("direct conversation closes")
    .into_state();
    assert_eq!(
        hydrate_conversation_state(terminal.clone()),
        Ok(terminal.clone())
    );
    assert_eq!(
        hydrate_conversation_state(terminal.for_test_duplicate_terminal_proof()),
        Err(StateMachineError::InvalidIntervalBoundary),
        "every historical recipient has exactly one terminal proof"
    );
    assert_eq!(
        hydrate_conversation_state(
            terminal.for_test_corrupt_first_terminal_proof_conversation(uuid_v4_bytes(0xc3))
        ),
        Err(StateMachineError::InvalidIntervalBoundary),
        "terminal proofs cannot cross conversation boundaries"
    );
    assert_eq!(
        hydrate_conversation_state(terminal.for_test_corrupt_first_terminal_proof_fingerprint()),
        Err(StateMachineError::InvalidIntervalBoundary),
        "all terminal proofs retain the exact terminal transition"
    );

    assert_eq!(
        hydrate_conversation_state(accepted_direct().for_test_drop_first_recovery_reservation()),
        Err(StateMachineError::InvariantViolation),
        "an open recovery request is inseparable from its exact reservation"
    );
}

#[test]
fn adapter_can_build_and_hydrate_a_durable_graph_without_a_runtime_state() {
    let manifest = corpus_manifest();
    let public_state = verified_genesis();
    let coordinate = *public_state.coordinate();
    let creator = alice(&manifest);
    let invitee = bob(&manifest);
    let transition = evidence(GENESIS_SEQ, 0xe1);
    let public_leaf = &public_state.binding().tree_summary().leaves()[0];
    let leaf = LeafHydrationRow {
        device: creator.clone(),
        leaf_index: public_leaf.leaf_index(),
        basic_credential: public_leaf.basic_credential().to_vec(),
        signature_key: public_leaf.signature_key().to_vec(),
        encryption_key: public_leaf.encryption_key().to_vec(),
        key_package_ref: None,
    };
    let rows = ConversationStateHydration {
        kind: ConversationKind::Direct,
        coordinate,
        producer: transition.clone(),
        public_state: Some(public_state),
        metadata: None,
        metadata_producer: None,
        participants: vec![
            ParticipantHydrationRow {
                principal: creator.principal().clone(),
                status: ParticipantStatus::Active,
                role: ParticipantRole::Admin,
                role_producer: None,
                invitation: None,
                acceptance: None,
            },
            ParticipantHydrationRow {
                principal: invitee.principal().clone(),
                status: ParticipantStatus::Pending,
                role: ParticipantRole::Admin,
                role_producer: None,
                invitation: Some(InvitationHydrationRow {
                    transition: transition.clone(),
                    inviter: creator.clone(),
                }),
                acceptance: None,
            },
        ],
        leaves: vec![leaf],
        intervals: vec![IntervalHydrationRow {
            recipient: creator,
            generation: coordinate.generation(),
            opening: transition,
            opening_kind: OpeningKind::Creation,
            opening_context: coordinate,
            end: None,
        }],
        terminal_proofs: Vec::new(),
        recovery_requests: Vec::new(),
        recovery_reservations: Vec::new(),
        reset_requests: Vec::new(),
        leave_requests: Vec::new(),
        welcomes: Vec::new(),
    };
    let hydrated = hydrate_rows(*coordinate.conversation_id(), rows)
        .expect("adapter DTO graph enters only through the validated hydration gate");
    assert_eq!(hydrated.coordinate(), &coordinate);
    assert_eq!(hydrated.participants().len(), 2);
}

#[test]
fn hydration_rejects_same_cardinality_terminal_substitution_and_time_mismatch() {
    let manifest = corpus_manifest();
    let active = added_direct();
    let terminal = plan_close(
        &active,
        CloseConversation {
            actor: alice(&manifest),
            transition: evidence(5, 0xe2),
        },
    )
    .unwrap()
    .into_state();
    let expected = *terminal.coordinate().conversation_id();
    let mut substituted = ConversationStateHydration::for_test_from_state(terminal);
    substituted.terminal_proofs[1].recipient = substituted.terminal_proofs[0].recipient.clone();
    assert_eq!(
        hydrate_rows(expected, substituted),
        Err(StateMachineError::InvalidIntervalBoundary)
    );

    let touching = active
        .for_test_touch_interval(
            &bob(&manifest),
            evidence(4, 0xe3),
            evidence(4, 0xe3),
            chat_protocol::state_machine::CloseKind::Replace,
            OpeningKind::Add,
        )
        .unwrap()
        .for_test_corrupt_touching_opening_received_at(&bob(&manifest));
    assert_eq!(
        hydrate_conversation_state(touching),
        Err(StateMachineError::InvalidIntervalBoundary)
    );
}

#[test]
fn hydration_rejects_invalid_reset_context_tree_rows_and_open_interval_set() {
    let reset = reset_direct();
    let expected = *reset.coordinate().conversation_id();
    let mut reset_rows = ConversationStateHydration::for_test_from_state(reset);
    let reset_opening = reset_rows.intervals.last_mut().unwrap();
    let context = reset_opening.opening_context;
    reset_opening.opening_context = PublicGroupSnapshotCoordinate::new(
        *context.conversation_id(),
        context.generation(),
        1,
        *context.group_id(),
        context.epoch(),
        *context.group_context_hash(),
        *context.confirmation_tag(),
        context.lifecycle(),
    );
    assert_eq!(
        hydrate_rows(expected, reset_rows),
        Err(StateMachineError::InvalidIntervalBoundary)
    );

    let added = added_direct();
    let expected = *added.coordinate().conversation_id();
    let mut wrong_tree = ConversationStateHydration::for_test_from_state(added.clone());
    wrong_tree.leaves[0].signature_key[0] ^= 0x01;
    assert_eq!(
        hydrate_rows(expected, wrong_tree),
        Err(StateMachineError::InvariantViolation)
    );
    let mut missing_open = ConversationStateHydration::for_test_from_state(added);
    missing_open.intervals.pop();
    assert_eq!(
        hydrate_rows(expected, missing_open),
        Err(StateMachineError::InvariantViolation)
    );
}

#[test]
fn hydration_binds_route_and_every_durable_work_coordinate() {
    let wrong_conversation = uuid_v4_bytes(0xe4);
    let accepted = accepted_direct();
    let expected = *accepted.coordinate().conversation_id();
    let mut recovery = ConversationStateHydration::for_test_from_state(accepted.clone());
    recovery.recovery_requests[0].bound_coordinate = coordinate_with_conversation(
        &recovery.recovery_requests[0].bound_coordinate,
        wrong_conversation,
    );
    recovery.recovery_reservations[0].bound_coordinate = coordinate_with_conversation(
        &recovery.recovery_reservations[0].bound_coordinate,
        wrong_conversation,
    );
    assert_eq!(
        hydrate_rows(expected, recovery),
        Err(StateMachineError::InvariantViolation)
    );
    assert_eq!(
        hydrate_rows(
            wrong_conversation,
            ConversationStateHydration::for_test_from_state(accepted)
        ),
        Err(StateMachineError::InvalidHydrationAuthority)
    );

    let manifest = corpus_manifest();
    let reset_base = accepted_direct();
    let reset_id = uuid_v4_bytes(0xe5);
    let reset = plan_reset_request(
        &reset_base,
        ResetRequestCommand {
            actor: alice(&manifest),
            reset_request_id: reset_id,
            received_at: fixture_received_at(4),
            evidence: request_evidence(
                RequestEntryKind::ResetRequest,
                4,
                reset_id,
                alice(&manifest),
                *reset_base.coordinate().conversation_id(),
                fixture_received_at(4),
                0xe5,
            ),
        },
    )
    .unwrap()
    .into_state();
    let mut reset_rows = ConversationStateHydration::for_test_from_state(reset);
    reset_rows.reset_requests[0].bound_coordinate = coordinate_with_conversation(
        &reset_rows.reset_requests[0].bound_coordinate,
        wrong_conversation,
    );
    assert_eq!(
        hydrate_rows(expected, reset_rows),
        Err(StateMachineError::InvariantViolation)
    );

    let group = added_group();
    let leave_id = uuid_v4_bytes(0xe6);
    let leave = plan_leave_request(
        &group,
        registered_leave_request(
            bob(&manifest),
            leave_id,
            fixture_received_at(4),
            *group.coordinate().conversation_id(),
            4,
            0xe6,
        ),
    )
    .unwrap()
    .into_state();
    let mut leave_rows = ConversationStateHydration::for_test_from_state(leave);
    leave_rows.leave_requests[0].bound_coordinate = coordinate_with_conversation(
        &leave_rows.leave_requests[0].bound_coordinate,
        wrong_conversation,
    );
    assert_eq!(
        hydrate_rows(*group.coordinate().conversation_id(), leave_rows),
        Err(StateMachineError::InvariantViolation)
    );

    let welcome_state = added_direct();
    let mut welcome_rows = ConversationStateHydration::for_test_from_state(welcome_state.clone());
    welcome_rows.welcomes[0].coordinate =
        coordinate_with_conversation(&welcome_rows.welcomes[0].coordinate, wrong_conversation);
    assert_eq!(
        hydrate_rows(*welcome_state.coordinate().conversation_id(), welcome_rows),
        Err(StateMachineError::InvariantViolation)
    );
}

#[test]
fn hydration_rejects_recovery_pair_status_package_and_welcome_corruption() {
    let accepted = accepted_direct();
    let expected = *accepted.coordinate().conversation_id();
    let mut mismatched = ConversationStateHydration::for_test_from_state(accepted.clone());
    mismatched.recovery_reservations[0].expires_at = ServerTimestamp::from_unix_millis_for_test(
        mismatched.recovery_reservations[0].expires_at.unix_millis() + 1,
    )
    .unwrap();
    assert_eq!(
        hydrate_rows(expected, mismatched),
        Err(StateMachineError::InvariantViolation)
    );

    for request_status in [
        RecoveryRequestStatus::Open,
        RecoveryRequestStatus::Fulfilled,
        RecoveryRequestStatus::Cancelled,
        RecoveryRequestStatus::Expired,
        RecoveryRequestStatus::Superseded,
    ] {
        for reservation_status in [
            ReservationStatus::Active,
            ReservationStatus::Consumed,
            ReservationStatus::Expired,
            ReservationStatus::Released,
        ] {
            let valid_pair = matches!(
                (request_status, reservation_status),
                (RecoveryRequestStatus::Open, ReservationStatus::Active)
                    | (
                        RecoveryRequestStatus::Fulfilled,
                        ReservationStatus::Consumed
                    )
                    | (
                        RecoveryRequestStatus::Cancelled,
                        ReservationStatus::Released
                    )
                    | (RecoveryRequestStatus::Expired, ReservationStatus::Expired)
                    | (
                        RecoveryRequestStatus::Superseded,
                        ReservationStatus::Released
                    )
            );
            if valid_pair {
                continue;
            }
            let mut rows = ConversationStateHydration::for_test_from_state(accepted.clone());
            rows.recovery_requests[0].status = request_status;
            rows.recovery_reservations[0].status = reservation_status;
            assert_eq!(
                hydrate_rows(expected, rows),
                Err(StateMachineError::InvariantViolation)
            );
        }
    }

    let two = group_with_two_open_recoveries();
    let expected = *two.coordinate().conversation_id();
    let mut duplicate_id = ConversationStateHydration::for_test_from_state(two.clone());
    let first_id = duplicate_id.recovery_requests[0].request_id;
    duplicate_id.recovery_requests[1].request_id = first_id;
    duplicate_id.recovery_reservations[1].request_id = first_id;
    assert_eq!(
        hydrate_rows(expected, duplicate_id),
        Err(StateMachineError::InvariantViolation)
    );

    let mut reused_package = ConversationStateHydration::for_test_from_state(two);
    let first_ref = reused_package.recovery_requests[0].key_package_ref;
    reused_package.recovery_requests[1].key_package_ref = first_ref;
    reused_package.recovery_reservations[1].key_package_ref = first_ref;
    assert_eq!(
        hydrate_rows(expected, reused_package),
        Err(StateMachineError::InvariantViolation)
    );

    let added = added_direct();
    let expected = *added.coordinate().conversation_id();
    let mut digest = ConversationStateHydration::for_test_from_state(added.clone());
    digest.welcomes[0].sha256[0] ^= 0x01;
    assert_eq!(
        hydrate_rows(expected, digest),
        Err(StateMachineError::InvariantViolation)
    );
    let mut duplicate = ConversationStateHydration::for_test_from_state(added);
    let mut second = duplicate.welcomes[0].clone();
    second.welcome_id = uuid_v4_bytes(0xe7);
    duplicate.welcomes.push(second);
    duplicate.welcomes.sort_by_key(|welcome| welcome.welcome_id);
    assert_eq!(
        hydrate_rows(expected, duplicate),
        Err(StateMachineError::InvariantViolation)
    );
}

#[test]
fn hydration_rejects_noncanonical_collection_order_and_historical_pending_work() {
    let direct = added_direct();
    let expected = *direct.coordinate().conversation_id();
    let mut participants = ConversationStateHydration::for_test_from_state(direct.clone());
    participants.participants.reverse();
    assert_eq!(
        hydrate_rows(expected, participants),
        Err(StateMachineError::InvariantViolation)
    );
    let mut leaves = ConversationStateHydration::for_test_from_state(direct.clone());
    leaves.leaves.reverse();
    assert_eq!(
        hydrate_rows(expected, leaves),
        Err(StateMachineError::InvariantViolation)
    );
    let terminal = plan_close(
        &direct,
        CloseConversation {
            actor: alice(&corpus_manifest()),
            transition: evidence(5, 0xe8),
        },
    )
    .unwrap()
    .into_state();
    let terminal_expected = *terminal.coordinate().conversation_id();
    let mut proofs = ConversationStateHydration::for_test_from_state(terminal);
    proofs.terminal_proofs.reverse();
    assert_eq!(
        hydrate_rows(terminal_expected, proofs),
        Err(StateMachineError::InvalidIntervalBoundary)
    );

    let two = group_with_two_open_recoveries();
    let expected = *two.coordinate().conversation_id();
    let mut recovery = ConversationStateHydration::for_test_from_state(two.clone());
    recovery.recovery_requests.reverse();
    assert_eq!(
        hydrate_rows(expected, recovery),
        Err(StateMachineError::InvariantViolation)
    );
    let mut reservations = ConversationStateHydration::for_test_from_state(two);
    reservations.recovery_reservations.reverse();
    assert_eq!(
        hydrate_rows(expected, reservations),
        Err(StateMachineError::InvariantViolation)
    );

    let manifest = corpus_manifest();
    let reset_base = accepted_direct();
    let reset_id = uuid_v4_bytes(0xe9);
    let reset_state = plan_reset_request(
        &reset_base,
        ResetRequestCommand {
            actor: alice(&manifest),
            reset_request_id: reset_id,
            received_at: fixture_received_at(4),
            evidence: request_evidence(
                RequestEntryKind::ResetRequest,
                4,
                reset_id,
                alice(&manifest),
                *reset_base.coordinate().conversation_id(),
                fixture_received_at(4),
                0xe9,
            ),
        },
    )
    .unwrap()
    .into_state();
    let expected_reset = *reset_state.coordinate().conversation_id();
    let mut reset_rows = ConversationStateHydration::for_test_from_state(reset_state);
    let mut second_reset = reset_rows.reset_requests[0].clone();
    second_reset.request_id = uuid_v4_bytes(0xea);
    reset_rows.reset_requests.push(second_reset);
    reset_rows.reset_requests.reverse();
    assert_eq!(
        hydrate_rows(expected_reset, reset_rows),
        Err(StateMachineError::InvariantViolation)
    );

    let group = added_group();
    let leave_id = uuid_v4_bytes(0xeb);
    let leave_state = plan_leave_request(
        &group,
        registered_leave_request(
            bob(&manifest),
            leave_id,
            fixture_received_at(4),
            *group.coordinate().conversation_id(),
            4,
            0xeb,
        ),
    )
    .unwrap()
    .into_state();
    let expected_leave = *leave_state.coordinate().conversation_id();
    let mut leave_rows = ConversationStateHydration::for_test_from_state(leave_state);
    let mut second_leave = leave_rows.leave_requests[0].clone();
    second_leave.request_id = uuid_v4_bytes(0xec);
    leave_rows.leave_requests.push(second_leave);
    leave_rows.leave_requests.reverse();
    assert_eq!(
        hydrate_rows(expected_leave, leave_rows),
        Err(StateMachineError::InvariantViolation)
    );

    let welcome_state = added_direct();
    let expected_welcome = *welcome_state.coordinate().conversation_id();
    let mut welcome_rows = ConversationStateHydration::for_test_from_state(welcome_state);
    let mut second_welcome = welcome_rows.welcomes[0].clone();
    second_welcome.welcome_id = uuid_v4_bytes(0xed);
    welcome_rows.welcomes.push(second_welcome);
    welcome_rows.welcomes.reverse();
    assert_eq!(
        hydrate_rows(expected_welcome, welcome_rows),
        Err(StateMachineError::InvariantViolation)
    );

    let accepted = accepted_direct();
    let expected = *accepted.coordinate().conversation_id();
    let mut historical = ConversationStateHydration::for_test_from_state(accepted);
    let current = historical.coordinate;
    let predecessor = PublicGroupSnapshotCoordinate::new(
        *current.conversation_id(),
        current.generation(),
        current.state_version() - 1,
        *current.group_id(),
        current.epoch(),
        *current.group_context_hash(),
        *current.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    historical.recovery_requests[0].bound_coordinate = predecessor;
    historical.recovery_reservations[0].bound_coordinate = predecessor;
    assert_eq!(
        hydrate_rows(expected, historical),
        Err(StateMachineError::InvariantViolation)
    );
}
