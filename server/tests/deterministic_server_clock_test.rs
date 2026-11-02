//! Deterministic signed mutation/read/ACK replay, per-clock counter isolation,
//! queued task spawning, SQL timestamp auditing, and paused PostgreSQL reset conformance.

use std::{
    future::Future,
    path::PathBuf,
    sync::{Arc, Once},
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::FromRef,
    http::{Request, StatusCode},
    Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use openmls::prelude::{
    tls_codec::Serialize as TlsSerialize, BasicCredential, Capabilities, CredentialType,
    CredentialWithKey, GroupId, KeyPackage, Lifetime, MlsGroup, MlsGroupCreateConfig,
    MlsMessageOut, ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use sqlx::postgres::PgPoolOptions;
use tower_util::ServiceExt;
use uuid::Uuid;

use catbird_server::{
    auth::{DidDocument, VerificationMethod, MLS_APPVIEW_SERVICE_REF},
    chat_protocol::{
        read_auth::{
            canonical_query, ReadClaim, CHAT_READ_DOMAIN, CHAT_READ_HEADER, CHAT_READ_SIG_HEADER,
        },
        snapshot::{PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle},
        wire::{
            validate_group_info, GroupInfoValidationPolicy, MAX_GROUP_INFO_WIRE_BYTES,
            XWING_CIPHERSUITE,
        },
    },
    federation::{receipt::I13ReceiptSigner, service_auth::ServiceAuthClient},
    handlers::chat::{chat_router, ChatRuntime},
    realtime::{SseState, StreamEvent},
    sim_hooks::{
        audit_live_catalog_timestamp_defaults, audit_sql_timestamp_defaults,
        compact_sim_postgres_schema, derive_sim_ed25519_key_id, open_disposable_sim_pool,
        reset_sim_postgres_schema, scope_ds_clock, seed_sim_did_document, sign_sim_chat_body,
        DsClock, ManualDsClock, QueuedTaskSpawner, PROTECTED_DATABASE_NAMES,
    },
    space_host::SpaceHostConfig,
    storage::DbPool,
};

const SERVICE_DID: &str = "did:web:chat.catbird.blue";

#[derive(Clone)]
struct SimAppState {
    pool: DbPool,
    runtime: Arc<ChatRuntime>,
}

impl FromRef<SimAppState> for DbPool {
    fn from_ref(state: &SimAppState) -> DbPool {
        state.pool.clone()
    }
}

impl FromRef<SimAppState> for Arc<ChatRuntime> {
    fn from_ref(state: &SimAppState) -> Arc<ChatRuntime> {
        Arc::clone(&state.runtime)
    }
}

fn ensure_chat_runtime_env() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_test_writer()
            .try_init();
        std::env::set_var("SERVICE_DID", SERVICE_DID);
        std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
        std::env::set_var("CHAT_CURSOR_KEY_ID", URL_SAFE_NO_PAD.encode([0x11_u8; 32]));
        std::env::set_var(
            "CHAT_CURSOR_SEALING_SECRET",
            URL_SAFE_NO_PAD.encode([0xA5_u8; 32]),
        );
        std::env::set_var(
            "CHAT_SUBSCRIPTION_ENDPOINT",
            "wss://chat.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents",
        );
    });
}

fn deterministic_uuid_v4(label: &[u8]) -> Uuid {
    let mut bytes: [u8; 16] = Sha256::digest([b"SIM-TEST-UUID\0".as_ref(), label].concat())[..16]
        .try_into()
        .expect("16-byte slice");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn deterministic_p256(label: &[u8]) -> P256SigningKey {
    for counter in 0_u8..=u8::MAX {
        let seed = Sha256::digest([b"SIM-TEST-P256\0".as_ref(), label, &[counter]].concat());
        if let Ok(key) = P256SigningKey::from_slice(&seed) {
            return key;
        }
    }
    panic!("failed to derive deterministic P-256 key");
}

struct SimActorDevice {
    did: String,
    device_id: Uuid,
    key_id: String,
    device_signing: Ed25519SigningKey,
    service_signing: P256SigningKey,
}

impl SimActorDevice {
    fn new(did: &str, service_signing: P256SigningKey, label: &[u8]) -> Self {
        let ed_seed: [u8; 32] =
            Sha256::digest([b"SIM-TEST-ED25519\0".as_ref(), label].concat()).into();
        let device_signing = Ed25519SigningKey::from_bytes(&ed_seed);
        let key_id = derive_sim_ed25519_key_id(device_signing.verifying_key().as_bytes())
            .expect("derive ed25519 key id");
        let device_id = deterministic_uuid_v4(label);
        Self {
            did: did.to_owned(),
            device_id,
            key_id,
            device_signing,
            service_signing,
        }
    }

    fn credential_bytes(&self) -> Vec<u8> {
        format!("{}#{}", self.did, self.device_id).into_bytes()
    }

    fn did_document(&self) -> DidDocument {
        let point = self.service_signing.verifying_key().to_encoded_point(false);
        let jwk = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().expect("P-256 x")),
            "y": URL_SAFE_NO_PAD.encode(point.y().expect("P-256 y")),
        }))
        .expect("valid P-256 JWK");
        DidDocument {
            id: self.did.clone(),
            verification_method: vec![VerificationMethod {
                id: format!("{}#atproto", self.did),
                key_type: "JsonWebKey2020".to_owned(),
                controller: self.did.clone(),
                public_key_jwk: Some(jwk),
                public_key_multibase: None,
            }],
            service: None,
        }
    }

    fn service_jwt(&self, nsid: &str, now_secs: i64, jti: Uuid) -> String {
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "alg": "ES256",
                "typ": "JWT",
                "kid": format!("{}#atproto", self.did),
            }))
            .expect("encode JWT header"),
        );
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "iss": self.did,
                "sub": self.did,
                "aud": MLS_APPVIEW_SERVICE_REF,
                "lxm": nsid,
                "iat": now_secs,
                "exp": now_secs + 60,
                "jti": jti.hyphenated().to_string(),
            }))
            .expect("encode JWT claims"),
        );
        let signing_input = format!("{header}.{claims}");
        let sig: P256Signature = self.service_signing.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn signed_get_request(
        &self,
        nsid: &str,
        query: &str,
        now: DateTime<Utc>,
        jti_label: &[u8],
    ) -> Request<Body> {
        let claim = ReadClaim {
            v: 1,
            nsid: nsid.to_owned(),
            query: canonical_query(Some(query)),
            did: self.did.clone(),
            device_id: self.device_id.to_string(),
            issued_at: now.timestamp_millis(),
        };
        let claim_bytes = serde_json::to_vec(&claim).expect("encode signed read claim");
        let mut transcript = CHAT_READ_DOMAIN.to_vec();
        transcript.extend_from_slice(&claim_bytes);
        let signature = self.device_signing.sign(&transcript);
        Request::builder()
            .method("GET")
            .uri(format!("/xrpc/{nsid}?{query}"))
            .header(
                "authorization",
                format!(
                    "Bearer {}",
                    self.service_jwt(nsid, now.timestamp(), deterministic_uuid_v4(jti_label))
                ),
            )
            .header(CHAT_READ_HEADER, URL_SAFE_NO_PAD.encode(claim_bytes))
            .header(
                CHAT_READ_SIG_HEADER,
                URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            )
            .body(Body::empty())
            .expect("build signed GET request")
    }

    fn acknowledge_entries_request(
        &self,
        conversation_id: Uuid,
        up_to_seq: i64,
        now: DateTime<Utc>,
        jti_label: &[u8],
    ) -> Request<Body> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct AckTranscriptPayload<'a> {
            key_id: &'a str,
            up_to_seq: i64,
            signed_at: &'a str,
            generation: i64,
            actor_device_id: String,
            auth_generation: i64,
            conversation_id: String,
        }
        let signed_at = now.to_rfc3339_opts(SecondsFormat::Millis, true);
        let payload = AckTranscriptPayload {
            key_id: &self.key_id,
            up_to_seq,
            signed_at: &signed_at,
            generation: 0,
            actor_device_id: self.device_id.to_string(),
            auth_generation: 1,
            conversation_id: conversation_id.to_string(),
        };
        let mut transcript = b"CATBIRD-CHAT-ACK-ENTRIES\0".to_vec();
        transcript.extend_from_slice(
            &serde_ipld_dagcbor::to_vec(&payload).expect("encode ACK transcript"),
        );
        let signature = self.device_signing.sign(&transcript);
        let mut body = serde_json::to_value(&payload).expect("encode ACK body");
        body["signature"] = json!({ "$bytes": STANDARD.encode(signature.to_bytes()) });
        let nsid = "blue.catbird.chat.acknowledgeEntries";
        Request::builder()
            .method("POST")
            .uri(format!("/xrpc/{nsid}"))
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!(
                    "Bearer {}",
                    self.service_jwt(nsid, now.timestamp(), deterministic_uuid_v4(jti_label))
                ),
            )
            .body(Body::from(
                serde_json::to_vec(&body).expect("encode ACK request"),
            ))
            .expect("build acknowledgeEntries request")
    }
}

fn capability_profile() -> Value {
    json!({
        "protocolVersion": "1",
        "mlsVersion": "1.0",
        "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "credentialType": "basic",
        "addByValue": "supported",
        "updatePath": "supported",
        "removeByValue": "supported",
        "ratchetTreeGroupInfo": "supported",
        "externalPubGroupInfo": "presentButExternalCommitsForbidden",
        "applicationFrameProfile": "dagCborApplication1",
        "controlProfile": "publicGroup1",
        "attachmentProfile": "aes256GcmBlob1",
        "metadataProfile": "exporterAes256Gcm1",
        "typingProfile": "signedClearEphemeral1"
    })
}

fn exact_mls_capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[XWING_CIPHERSUITE]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    )
}

struct BuiltKeyPackage {
    package: KeyPackage,
    wrapped: Vec<u8>,
    key_package_ref: [u8; 32],
}

fn build_key_package(
    actor: &SimActorDevice,
    provider: &openmls_libcrux_crypto::Provider,
    signer: &SignatureKeyPair,
    not_before: u64,
    not_after: u64,
) -> BuiltKeyPackage {
    let bundle = KeyPackage::builder()
        .key_package_lifetime(Lifetime::init(not_before, not_after))
        .leaf_node_capabilities(exact_mls_capabilities())
        .build(
            XWING_CIPHERSUITE,
            provider,
            signer,
            CredentialWithKey {
                credential: BasicCredential::new(actor.credential_bytes()).into(),
                signature_key: actor
                    .device_signing
                    .verifying_key()
                    .to_bytes()
                    .to_vec()
                    .into(),
            },
        )
        .expect("build XWing KeyPackage");
    let package = bundle.key_package().clone();
    let wrapped = MlsMessageOut::from(package.clone())
        .tls_serialize_detached()
        .expect("serialize KeyPackage");
    let key_package_ref: [u8; 32] = package
        .hash_ref(provider.crypto())
        .expect("hash_ref")
        .as_slice()
        .try_into()
        .expect("32-byte KeyPackageRef");
    BuiltKeyPackage {
        package,
        wrapped,
        key_package_ref,
    }
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
        "lifecycle": "active",
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommitPriorAad<'a> {
    #[serde(with = "serde_bytes")]
    confirmation_tag: &'a [u8],
    #[serde(with = "serde_bytes")]
    conversation_id: &'a [u8],
    epoch: u64,
    generation: u64,
    #[serde(with = "serde_bytes")]
    group_context_hash: &'a [u8],
    #[serde(with = "serde_bytes")]
    group_id: &'a [u8],
    lifecycle: &'static str,
    state_version: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryCommitAad<'a> {
    #[serde(with = "serde_bytes")]
    conversation_id: &'a [u8],
    generation: u64,
    prior: CommitPriorAad<'a>,
    protocol_version: &'static str,
    #[serde(with = "serde_bytes")]
    transition_id: &'a [u8],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationRoutingAad<'a> {
    #[serde(with = "serde_bytes")]
    archive_commitment: &'a [u8],
    #[serde(with = "serde_bytes")]
    conversation_id: &'a [u8],
    generation: u64,
    #[serde(with = "serde_bytes")]
    message_id: &'a [u8],
    prior: CommitPriorAad<'a>,
    protocol_version: &'static str,
}

fn encode_recovery_commit_aad(
    conversation_id: Uuid,
    transition_id: Uuid,
    prior: &PublicGroupSnapshotCoordinate,
) -> Vec<u8> {
    let cbor = serde_ipld_dagcbor::to_vec(&RecoveryCommitAad {
        protocol_version: "1",
        conversation_id: conversation_id.as_bytes(),
        generation: prior.generation(),
        transition_id: transition_id.as_bytes(),
        prior: CommitPriorAad {
            conversation_id: conversation_id.as_bytes(),
            generation: prior.generation(),
            state_version: prior.state_version(),
            group_id: prior.group_id(),
            epoch: prior.epoch(),
            group_context_hash: prior.group_context_hash(),
            confirmation_tag: prior.confirmation_tag(),
            lifecycle: "active",
        },
    })
    .expect("encode recovery commit AAD");
    let mut aad = b"CATBIRD-CHAT-MLS-AAD-COMMIT\0".to_vec();
    aad.extend_from_slice(&cbor);
    aad
}

fn encode_application_aad(
    prior: &PublicGroupSnapshotCoordinate,
    message_id: Uuid,
    archive_commitment: &[u8; 32],
) -> Vec<u8> {
    let cbor = serde_ipld_dagcbor::to_vec(&ApplicationRoutingAad {
        protocol_version: "1",
        conversation_id: prior.conversation_id(),
        generation: prior.generation(),
        message_id: message_id.as_bytes(),
        archive_commitment,
        prior: CommitPriorAad {
            conversation_id: prior.conversation_id(),
            generation: prior.generation(),
            state_version: prior.state_version(),
            group_id: prior.group_id(),
            epoch: prior.epoch(),
            group_context_hash: prior.group_context_hash(),
            confirmation_tag: prior.confirmation_tag(),
            lifecycle: "active",
        },
    })
    .expect("encode application AAD");
    let mut aad = b"CATBIRD-CHAT-MLS-AAD-MESSAGE\0".to_vec();
    aad.extend_from_slice(&cbor);
    aad
}

struct PreparedStep {
    label: &'static str,
    nsid: &'static str,
    clock_offset_ms: i64,
    bearer_jwt: String,
    body_bytes: Vec<u8>,
}

struct PreparedScenario {
    alice: SimActorDevice,
    bob_primary: SimActorDevice,
    bob_secondary: SimActorDevice,
    conversation_id: Uuid,
    archive_commitment: [u8; 32],
    steps: Vec<PreparedStep>,
}

fn build_deterministic_scenario(t0: DateTime<Utc>) -> PreparedScenario {
    let alice_service_key = deterministic_p256(b"alice-atproto");
    let bob_service_key = deterministic_p256(b"bob-atproto");
    let alice = SimActorDevice::new(
        "did:plc:aaaaaaaabbbbbbbbcccccccc",
        alice_service_key,
        b"alice-dev-1",
    );
    let bob_primary = SimActorDevice::new(
        "did:plc:ddddddddeeeeeeeeffffffff",
        bob_service_key.clone(),
        b"bob-dev-1",
    );
    let bob_secondary = SimActorDevice::new(
        "did:plc:ddddddddeeeeeeeeffffffff",
        bob_service_key,
        b"bob-dev-2",
    );

    let alice_provider = openmls_libcrux_crypto::Provider::new().expect("alice OpenMLS provider");
    let bob1_provider = openmls_libcrux_crypto::Provider::new().expect("bob1 OpenMLS provider");
    let bob2_provider = openmls_libcrux_crypto::Provider::new().expect("bob2 OpenMLS provider");

    let alice_signer = SignatureKeyPair::from_raw(
        XWING_CIPHERSUITE.signature_algorithm(),
        alice.device_signing.to_bytes().to_vec(),
        alice.device_signing.verifying_key().to_bytes().to_vec(),
    );
    alice_signer
        .store(alice_provider.storage())
        .expect("store alice signer");
    let bob1_signer = SignatureKeyPair::from_raw(
        XWING_CIPHERSUITE.signature_algorithm(),
        bob_primary.device_signing.to_bytes().to_vec(),
        bob_primary
            .device_signing
            .verifying_key()
            .to_bytes()
            .to_vec(),
    );
    bob1_signer
        .store(bob1_provider.storage())
        .expect("store bob1 signer");
    let bob2_signer = SignatureKeyPair::from_raw(
        XWING_CIPHERSUITE.signature_algorithm(),
        bob_secondary.device_signing.to_bytes().to_vec(),
        bob_secondary
            .device_signing
            .verifying_key()
            .to_bytes()
            .to_vec(),
    );
    bob2_signer
        .store(bob2_provider.storage())
        .expect("store bob2 signer");

    let t0_unix = u64::try_from(t0.timestamp()).expect("positive timestamp");

    let build_enroll_step = |label: &'static str,
                             actor: &SimActorDevice,
                             provider: &openmls_libcrux_crypto::Provider,
                             signer: &SignatureKeyPair,
                             kp_count: usize,
                             offset_ms: i64,
                             idempotency_seed: &[u8],
                             jti_seed: &[u8]|
     -> (PreparedStep, Vec<BuiltKeyPackage>) {
        let step_time = t0 + TimeDelta::milliseconds(offset_ms);
        let mut built: Vec<BuiltKeyPackage> = (0..kp_count)
            .map(|idx| {
                build_key_package(
                    actor,
                    provider,
                    signer,
                    t0_unix - 8 * 86_400,
                    t0_unix + 21 * 86_400 + idx as u64,
                )
            })
            .collect();
        built.sort_by(|a, b| a.key_package_ref.cmp(&b.key_package_ref));
        let packages: Vec<Value> = built
            .iter()
            .map(|kp| {
                json!({
                    "framing": "mlsMessage",
                    "contentType": "keyPackage",
                    "bytes": STANDARD.encode(&kp.wrapped),
                    "sha256": STANDARD.encode(Sha256::digest(&kp.wrapped)),
                    "keyPackageRef": STANDARD.encode(kp.key_package_ref),
                })
            })
            .collect();
        let body = json!({
            "$type": "blue.catbird.chat.defs#deviceEnrollmentBody",
            "signatureDomain": "CATBIRD-CHAT-DEVICE-ENROLL\u{0}",
            "actorDid": actor.did,
            "deviceId": actor.device_id.hyphenated().to_string(),
            "deviceName": label,
            "keyId": actor.key_id,
            "signaturePublicKey": STANDARD.encode(actor.device_signing.verifying_key().as_bytes()),
            "expectedAuthGeneration": 0,
            "capability": capability_profile(),
            "keyPackages": packages,
            "idempotencyKey": deterministic_uuid_v4(idempotency_seed).hyphenated().to_string(),
            "signedAt": step_time.to_rfc3339_opts(SecondsFormat::Millis, true),
        });
        let signed = sign_sim_chat_body(body, &actor.device_signing).expect("sign enroll body");
        let wrapper: Value = serde_json::from_slice(&signed).expect("decode signed enroll");
        let nsid = "blue.catbird.chat.enrollDevice";
        let step = PreparedStep {
            label,
            nsid,
            clock_offset_ms: offset_ms,
            bearer_jwt: actor.service_jwt(
                nsid,
                step_time.timestamp(),
                deterministic_uuid_v4(jti_seed),
            ),
            body_bytes: serde_json::to_vec(&json!({ "signedRequest": wrapper }))
                .expect("encode enroll envelope"),
        };
        (step, built)
    };

    let (enroll_alice, _alice_kps) = build_enroll_step(
        "enroll_alice",
        &alice,
        &alice_provider,
        &alice_signer,
        2,
        0,
        b"enroll-alice-idem",
        b"enroll-alice-jti",
    );
    let (enroll_bob1, bob1_kps) = build_enroll_step(
        "enroll_bob_primary",
        &bob_primary,
        &bob1_provider,
        &bob1_signer,
        2,
        5,
        b"enroll-bob1-idem",
        b"enroll-bob1-jti",
    );
    let (enroll_bob2, _bob2_kps) = build_enroll_step(
        "enroll_bob_secondary",
        &bob_secondary,
        &bob2_provider,
        &bob2_signer,
        1,
        10,
        b"enroll-bob2-idem",
        b"enroll-bob2-jti",
    );

    // Step 4: Alice creates a group conversation inviting Bob (`status = "pending", role = "member"`).
    let conversation_id = deterministic_uuid_v4(b"sim-conversation-1");
    let create_transition_id = deterministic_uuid_v4(b"sim-create-transition-1");
    let create_offset_ms = 20_i64;
    let create_time = t0 + TimeDelta::milliseconds(create_offset_ms);
    let group_id: [u8; 32] =
        Sha256::digest([b"SIM-MLS-GROUP\0".as_ref(), conversation_id.as_bytes()].concat()).into();
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(XWING_CIPHERSUITE)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .capabilities(exact_mls_capabilities())
        .lifetime(Lifetime::init(t0_unix - 8 * 86_400, t0_unix + 21 * 86_400))
        .build();
    let mut alice_group = MlsGroup::new_with_group_id(
        &alice_provider,
        &alice_signer,
        &group_config,
        GroupId::from_slice(&group_id),
        CredentialWithKey {
            credential: BasicCredential::new(alice.credential_bytes()).into(),
            signature_key: alice
                .device_signing
                .verifying_key()
                .to_bytes()
                .to_vec()
                .into(),
        },
    )
    .expect("create genesis MLS group");
    let genesis_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, true)
        .expect("export genesis GroupInfo")
        .tls_serialize_detached()
        .expect("serialize genesis GroupInfo");
    let validated_gi = validate_group_info(
        &genesis_group_info,
        GroupInfoValidationPolicy {
            expected_basic_credential: &alice.credential_bytes(),
            expected_signature_key: alice.device_signing.verifying_key().as_bytes(),
            now_unix_seconds: u64::try_from(create_time.timestamp()).expect("unix secs"),
            max_bytes: MAX_GROUP_INFO_WIRE_BYTES,
            max_ratchet_tree_bytes: MAX_GROUP_INFO_WIRE_BYTES,
            max_members: 2,
        },
    )
    .expect("validate genesis GroupInfo");
    let genesis_coord = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        0,
        0,
        validated_gi
            .group_id()
            .try_into()
            .expect("32-byte group id"),
        validated_gi.epoch(),
        *validated_gi.group_context_hash(),
        *validated_gi.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    let metadata_nonce = [0x51_u8; 12];
    let metadata_ciphertext = [0x52_u8; 16];
    let create_body = json!({
        "$type": "blue.catbird.chat.defs#creationBody",
        "signatureDomain": "CATBIRD-CHAT-CREATE\u{0}",
        "conversationId": conversation_id.hyphenated().to_string(),
        "conversationKind": "group",
        "transitionId": create_transition_id.hyphenated().to_string(),
        "actorDid": alice.did,
        "actorDeviceId": alice.device_id.hyphenated().to_string(),
        "keyId": alice.key_id,
        "authGeneration": 1,
        "absence": true,
        "next": coordinate_json(&genesis_coord),
        "manifest": {
            "participants": [
                {
                    "userDid": alice.did,
                    "status": "active",
                    "role": "admin",
                },
                {
                    "userDid": bob_primary.did,
                    "status": "pending",
                    "role": "member",
                    "invitationProvenance": {
                        "invitationTransitionId": create_transition_id.hyphenated().to_string(),
                        "invitedByDid": alice.did,
                        "invitedByDeviceId": alice.device_id.hyphenated().to_string(),
                    },
                }
            ],
            "actorLeaf": {
                "userDid": alice.did,
                "deviceId": alice.device_id.hyphenated().to_string(),
                "leafOrigin": "genesis",
            },
        },
        "genesisGroupInfo": {
            "framing": "mlsMessage",
            "contentType": "groupInfo",
            "bytes": STANDARD.encode(&genesis_group_info),
            "sha256": STANDARD.encode(Sha256::digest(&genesis_group_info)),
        },
        "metadataSnapshot": {
            "coordinate": {
                "conversationId": STANDARD.encode(conversation_id.as_bytes()),
                "generation": 0,
                "groupId": STANDARD.encode(genesis_coord.group_id()),
                "epoch": 0,
                "groupContextHash": STANDARD.encode(genesis_coord.group_context_hash()),
                "confirmationTag": STANDARD.encode(genesis_coord.confirmation_tag()),
            },
            "originTransitionId": create_transition_id.hyphenated().to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode(metadata_nonce),
            "ciphertext": STANDARD.encode(metadata_ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(metadata_ciphertext)),
            "ciphertextSize": metadata_ciphertext.len(),
            "authorProof": {
                "authorDid": alice.did,
                "authorDeviceId": alice.device_id.hyphenated().to_string(),
                "authorKeyId": alice.key_id,
                "signaturePublicKey": STANDARD.encode(alice.device_signing.verifying_key().as_bytes()),
                "authGenerationAtOrigin": 1,
                "originTransitionId": create_transition_id.hyphenated().to_string(),
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active",
            },
        },
        "idempotencyKey": create_transition_id.hyphenated().to_string(),
        "signedAt": create_time.to_rfc3339_opts(SecondsFormat::Millis, true),
    });
    let signed_create =
        sign_sim_chat_body(create_body, &alice.device_signing).expect("sign createConversation");
    let create_wrapper: Value = serde_json::from_slice(&signed_create).expect("create wrapper");
    let create_nsid = "blue.catbird.chat.createConversation";
    let create_step = PreparedStep {
        label: "create_conversation",
        nsid: create_nsid,
        clock_offset_ms: create_offset_ms,
        bearer_jwt: alice.service_jwt(
            create_nsid,
            create_time.timestamp(),
            deterministic_uuid_v4(b"create-convo-jti"),
        ),
        body_bytes: serde_json::to_vec(&json!({ "signedRequest": create_wrapper }))
            .expect("encode create envelope"),
    };

    // Step 5: Bob accepts the invitation (`acceptConversation`), reserving `bob1_kps[0]`.
    // Note: `acceptConversation` selects the actor device's available KeyPackage in deterministic
    // `key_package_ref` order (`bob1_kps` was sorted ascending by `key_package_ref` above).
    let accept_offset_ms = 30_i64;
    let accept_time = t0 + TimeDelta::milliseconds(accept_offset_ms);
    let accept_transition_id = deterministic_uuid_v4(b"sim-accept-transition-1");
    let recovery_request_id = deterministic_uuid_v4(b"sim-recovery-request-1");
    let accept_coord = PublicGroupSnapshotCoordinate::new(
        *genesis_coord.conversation_id(),
        0,
        1,
        *genesis_coord.group_id(),
        genesis_coord.epoch(),
        *genesis_coord.group_context_hash(),
        *genesis_coord.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    let accept_body = json!({
        "$type": "blue.catbird.chat.defs#participantAcceptanceBody",
        "signatureDomain": "CATBIRD-CHAT-ACCEPT\u{0}",
        "transitionId": accept_transition_id.hyphenated().to_string(),
        "recoveryRequestId": recovery_request_id.hyphenated().to_string(),
        "actorDid": bob_primary.did,
        "actorDeviceId": bob_primary.device_id.hyphenated().to_string(),
        "keyId": bob_primary.key_id,
        "authGeneration": 1,
        "prior": coordinate_json(&genesis_coord),
        "next": coordinate_json(&accept_coord),
        "invitationProvenance": {
            "invitationTransitionId": create_transition_id.hyphenated().to_string(),
            "invitedByDid": alice.did,
            "invitedByDeviceId": alice.device_id.hyphenated().to_string(),
        },
        "idempotencyKey": accept_transition_id.hyphenated().to_string(),
        "signedAt": accept_time.to_rfc3339_opts(SecondsFormat::Millis, true),
    });
    let signed_accept = sign_sim_chat_body(accept_body, &bob_primary.device_signing)
        .expect("sign acceptConversation");
    let accept_wrapper: Value = serde_json::from_slice(&signed_accept).expect("accept wrapper");
    let accept_nsid = "blue.catbird.chat.acceptConversation";
    let accept_step = PreparedStep {
        label: "accept_conversation",
        nsid: accept_nsid,
        clock_offset_ms: accept_offset_ms,
        bearer_jwt: bob_primary.service_jwt(
            accept_nsid,
            accept_time.timestamp(),
            deterministic_uuid_v4(b"accept-convo-jti"),
        ),
        body_bytes: serde_json::to_vec(&json!({ "signedRequest": accept_wrapper }))
            .expect("encode accept envelope"),
    };

    // Step 6: Alice fulfills Bob's Add recovery via `submitTransition` (`leafRecoveryFulfillmentBody`).
    let add_offset_ms = 40_i64;
    let add_time = t0 + TimeDelta::milliseconds(add_offset_ms);
    let add_transition_id = deterministic_uuid_v4(b"sim-add-transition-1");
    let welcome_id = deterministic_uuid_v4(b"sim-welcome-1");
    let reserved_kp = &bob1_kps[0];
    let add_aad = encode_recovery_commit_aad(conversation_id, add_transition_id, &accept_coord);
    alice_group.set_aad(add_aad);
    let (add_commit_msg, add_welcome_msg, add_group_info) = alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            std::slice::from_ref(&reserved_kp.package),
        )
        .expect("OpenMLS add_members");
    let add_commit = add_commit_msg
        .tls_serialize_detached()
        .expect("serialize Add commit");
    let add_welcome = add_welcome_msg
        .tls_serialize_detached()
        .expect("serialize Add welcome");
    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("merge Add commit");
    let add_group_context = add_group_info
        .expect("Add GroupInfo")
        .group_context()
        .tls_serialize_detached()
        .expect("serialize Add group context");
    let add_group_context_hash: [u8; 32] = Sha256::digest(&add_group_context).into();
    let encoded_conf_tag = alice_group
        .confirmation_tag()
        .tls_serialize_detached()
        .expect("serialize Add confirmation tag");
    assert_eq!(encoded_conf_tag.first(), Some(&32));
    let add_conf_tag: [u8; 32] = encoded_conf_tag[1..33].try_into().expect("32-byte tag");
    let add_coord = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        0,
        2,
        *genesis_coord.group_id(),
        alice_group.epoch().as_u64(),
        add_group_context_hash,
        add_conf_tag,
        PublicGroupSnapshotLifecycle::Active,
    );
    let add_body = json!({
        "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
        "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\u{0}",
        "recoveryRequestId": recovery_request_id.hyphenated().to_string(),
        "transitionId": add_transition_id.hyphenated().to_string(),
        "actorDid": alice.did,
        "actorDeviceId": alice.device_id.hyphenated().to_string(),
        "keyId": alice.key_id,
        "authGeneration": 1,
        "prior": coordinate_json(&accept_coord),
        "next": coordinate_json(&add_coord),
        "aad": {
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(conversation_id.as_bytes()),
            "generation": 0,
            "transitionId": STANDARD.encode(add_transition_id.as_bytes()),
            "prior": {
                "conversationId": STANDARD.encode(conversation_id.as_bytes()),
                "generation": 0,
                "stateVersion": accept_coord.state_version(),
                "groupId": STANDARD.encode(accept_coord.group_id()),
                "epoch": accept_coord.epoch(),
                "groupContextHash": STANDARD.encode(accept_coord.group_context_hash()),
                "confirmationTag": STANDARD.encode(accept_coord.confirmation_tag()),
                "lifecycle": "active",
            },
        },
        "manifest": {
            "participantChanges": [],
            "leafChanges": [{
                "$type": "blue.catbird.chat.defs#addLeafByRecovery",
                "userDid": bob_primary.did,
                "deviceId": bob_primary.device_id.hyphenated().to_string(),
                "recoveryRequestId": recovery_request_id.hyphenated().to_string(),
                "keyPackageRef": STANDARD.encode(reserved_kp.key_package_ref),
            }],
            "leafRecoveryRequestId": recovery_request_id.hyphenated().to_string(),
            "welcomeBundle": {
                "welcomeId": welcome_id.hyphenated().to_string(),
                "framing": "mlsMessage",
                "contentType": "welcome",
                "opaqueWelcome": STANDARD.encode(&add_welcome),
                "sha256": STANDARD.encode(Sha256::digest(&add_welcome)),
                "deliveries": [{
                    "recipientDid": bob_primary.did,
                    "recipientDeviceId": bob_primary.device_id.hyphenated().to_string(),
                    "provenance": {
                        "recoveryRequestId": recovery_request_id.hyphenated().to_string(),
                        "keyPackageRef": STANDARD.encode(reserved_kp.key_package_ref),
                    },
                }],
            },
        },
        "commit": {
            "framing": "mlsMessage",
            "contentType": "publicMessageCommit",
            "bytes": STANDARD.encode(&add_commit),
            "sha256": STANDARD.encode(Sha256::digest(&add_commit)),
        },
        "metadataSnapshot": {
            "coordinate": {
                "conversationId": STANDARD.encode(conversation_id.as_bytes()),
                "generation": 0,
                "groupId": STANDARD.encode(add_coord.group_id()),
                "epoch": add_coord.epoch(),
                "groupContextHash": STANDARD.encode(add_coord.group_context_hash()),
                "confirmationTag": STANDARD.encode(add_coord.confirmation_tag()),
            },
            "originTransitionId": create_transition_id.hyphenated().to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode([0x43_u8; 12]),
            "ciphertext": STANDARD.encode(metadata_ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(metadata_ciphertext)),
            "ciphertextSize": metadata_ciphertext.len(),
            "authorProof": {
                "authorDid": alice.did,
                "authorDeviceId": alice.device_id.hyphenated().to_string(),
                "authorKeyId": alice.key_id,
                "signaturePublicKey": STANDARD.encode(alice.device_signing.verifying_key().as_bytes()),
                "authGenerationAtOrigin": 1,
                "originTransitionId": create_transition_id.hyphenated().to_string(),
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active",
            },
        },
        "idempotencyKey": add_transition_id.hyphenated().to_string(),
        "signedAt": add_time.to_rfc3339_opts(SecondsFormat::Millis, true),
    });
    let signed_add =
        sign_sim_chat_body(add_body, &alice.device_signing).expect("sign submitTransition Add");
    let add_wrapper: Value = serde_json::from_slice(&signed_add).expect("add wrapper");
    let submit_nsid = "blue.catbird.chat.submitTransition";
    let add_step = PreparedStep {
        label: "submit_transition_add",
        nsid: submit_nsid,
        clock_offset_ms: add_offset_ms,
        bearer_jwt: alice.service_jwt(
            submit_nsid,
            add_time.timestamp(),
            deterministic_uuid_v4(b"submit-add-jti"),
        ),
        body_bytes: serde_json::to_vec(&json!({ "signedRequest": add_wrapper }))
            .expect("encode submitTransition envelope"),
    };

    // Step 7: Alice sends an MLS PrivateMessage with `archiveCommitment` via `sendMessage`.
    let send_offset_ms = 50_i64;
    let send_time = t0 + TimeDelta::milliseconds(send_offset_ms);
    let message_id = deterministic_uuid_v4(b"sim-message-1");
    let archive_commitment: [u8; 32] = Sha256::digest(b"sim-archive-commitment-payload-v1").into();
    let app_aad_bytes = encode_application_aad(&add_coord, message_id, &archive_commitment);
    alice_group.set_aad(app_aad_bytes);
    let app_ciphertext = alice_group
        .create_message(
            &alice_provider,
            &alice_signer,
            b"hydrostatic pressure tank message 1",
        )
        .expect("encrypt OpenMLS application message")
        .tls_serialize_detached()
        .expect("serialize OpenMLS application message");
    let mut aad_prior_json = coordinate_json(&add_coord);
    aad_prior_json["conversationId"] = json!(STANDARD.encode(add_coord.conversation_id()));
    let send_body = json!({
        "$type": "blue.catbird.chat.defs#applicationSendBody",
        "signatureDomain": "CATBIRD-CHAT-MESSAGE\u{0}",
        "messageId": message_id.hyphenated().to_string(),
        "actorDid": alice.did,
        "actorDeviceId": alice.device_id.hyphenated().to_string(),
        "keyId": alice.key_id,
        "authGeneration": 1,
        "prior": coordinate_json(&add_coord),
        "aad": {
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(add_coord.conversation_id()),
            "generation": 0,
            "messageId": STANDARD.encode(message_id.as_bytes()),
            "archiveCommitment": STANDARD.encode(archive_commitment),
            "prior": aad_prior_json,
        },
        "applicationMessage": {
            "framing": "mlsMessage",
            "contentType": "privateMessageApplication",
            "bytes": STANDARD.encode(&app_ciphertext),
            "sha256": STANDARD.encode(Sha256::digest(&app_ciphertext)),
        },
        "blobBindings": [],
        "signedAt": send_time.to_rfc3339_opts(SecondsFormat::Millis, true),
    });
    let signed_send =
        sign_sim_chat_body(send_body, &alice.device_signing).expect("sign sendMessage");
    let send_wrapper: Value = serde_json::from_slice(&signed_send).expect("send wrapper");
    let send_nsid = "blue.catbird.chat.sendMessage";
    let send_step = PreparedStep {
        label: "send_message",
        nsid: send_nsid,
        clock_offset_ms: send_offset_ms,
        bearer_jwt: alice.service_jwt(
            send_nsid,
            send_time.timestamp(),
            deterministic_uuid_v4(b"send-msg-jti"),
        ),
        body_bytes: serde_json::to_vec(&json!({ "signedRequest": send_wrapper }))
            .expect("encode sendMessage envelope"),
    };

    // Step 8: Bob primary revokes Bob secondary (`revokeDevice`), triggering post-commit fanout
    // onto `QueuedTaskSpawner` rather than `tokio::spawn`.
    let revoke_offset_ms = 60_i64;
    let revoke_time = t0 + TimeDelta::milliseconds(revoke_offset_ms);
    let revoke_idem = deterministic_uuid_v4(b"sim-revoke-idem-1");
    let revoke_body = json!({
        "$type": "blue.catbird.chat.defs#deviceRevocationBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REVOKE\u{0}",
        "actorDid": bob_primary.did,
        "actorDeviceId": bob_primary.device_id.hyphenated().to_string(),
        "keyId": bob_primary.key_id,
        "authGeneration": 1,
        "targetDeviceId": bob_secondary.device_id.hyphenated().to_string(),
        "targetAuthGeneration": 1,
        "idempotencyKey": revoke_idem.hyphenated().to_string(),
        "signedAt": revoke_time.to_rfc3339_opts(SecondsFormat::Millis, true),
    });
    let signed_revoke =
        sign_sim_chat_body(revoke_body, &bob_primary.device_signing).expect("sign revokeDevice");
    let revoke_wrapper: Value = serde_json::from_slice(&signed_revoke).expect("revoke wrapper");
    let revoke_nsid = "blue.catbird.chat.revokeDevice";
    let revoke_step = PreparedStep {
        label: "revoke_device",
        nsid: revoke_nsid,
        clock_offset_ms: revoke_offset_ms,
        bearer_jwt: bob_primary.service_jwt(
            revoke_nsid,
            revoke_time.timestamp(),
            deterministic_uuid_v4(b"revoke-dev-jti"),
        ),
        body_bytes: serde_json::to_vec(&json!({ "signedRequest": revoke_wrapper }))
            .expect("encode revokeDevice envelope"),
    };

    PreparedScenario {
        alice,
        bob_primary,
        bob_secondary,
        conversation_id,
        archive_commitment,
        steps: vec![
            enroll_alice,
            enroll_bob1,
            enroll_bob2,
            create_step,
            accept_step,
            add_step,
            send_step,
            revoke_step,
        ],
    }
}

async fn drive_paused_io<F: Future>(label: &str, future: F) -> F::Output {
    let started = Instant::now();
    tokio::pin!(future);
    loop {
        tokio::select! {
            result = &mut future => return result,
            _ = tokio::task::yield_now() => assert!(
                started.elapsed() < Duration::from_secs(10),
                "{label} did not complete within 10 real seconds"
            ),
        }
    }
}

async fn execute_request(router: &Router, label: &str, request: Request<Body>) -> Vec<u8> {
    let uri = request.uri().to_string();
    let response = drive_paused_io(label, router.clone().oneshot(request))
        .await
        .expect("dispatch XRPC request");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response bytes")
        .to_vec();
    assert_eq!(
        status,
        StatusCode::OK,
        "step '{label}' ({uri}) failed with {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    bytes
}

async fn execute_scenario_run(
    router: &Router,
    pool: &DbPool,
    clock: &ManualDsClock,
    t0: DateTime<Utc>,
    scenario: &PreparedScenario,
) -> Vec<(String, Vec<u8>)> {
    clock.reset_counters();
    let mut outputs = Vec::with_capacity(scenario.steps.len() + 6);
    for step in &scenario.steps {
        clock.set_utc(t0 + TimeDelta::milliseconds(step.clock_offset_ms));
        let request = Request::builder()
            .method("POST")
            .uri(format!("/xrpc/{}", step.nsid))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", step.bearer_jwt))
            .body(Body::from(step.body_bytes.clone()))
            .expect("build XRPC request");
        let bytes = execute_request(router, step.label, request).await;
        outputs.push((step.label.to_owned(), bytes));
    }

    let entries_query = format!(
        "actorDeviceId={}&conversationId={}&afterSeq=0&limit=100",
        scenario.alice.device_id, scenario.conversation_id
    );
    let entries_time = t0 + TimeDelta::milliseconds(70);
    clock.set_utc(entries_time);
    let entries_bytes = execute_request(
        router,
        "get_entries",
        scenario.alice.signed_get_request(
            "blue.catbird.chat.getEntries",
            &entries_query,
            entries_time,
            b"get-entries-jti",
        ),
    )
    .await;
    let entries_json: Value = serde_json::from_slice(&entries_bytes).expect("parse getEntries");
    let entries = entries_json["entries"].as_array().expect("entries array");
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry["seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4],
        "signed getEntries must retain the whole contiguous transcript"
    );
    assert_eq!(entries_json["nextAfterSeq"], 4);
    assert_eq!(entries_json["hasMore"], false);
    let application_entry = entries.last().expect("application entry");
    assert_eq!(
        application_entry["$type"],
        "blue.catbird.chat.defs#applicationEntry"
    );
    assert!(application_entry["signedRequest"].is_object());
    assert_ne!(application_entry["payloadPruned"], true);
    let send_json: Value = serde_json::from_slice(
        &outputs
            .iter()
            .find(|(label, _)| label == "send_message")
            .unwrap()
            .1,
    )
    .expect("parse sendMessage");
    assert_eq!(
        application_entry["sequencerReceipt"],
        send_json["sequencerReceipt"]
    );
    assert_eq!(
        application_entry["receivedAt"],
        (t0 + TimeDelta::milliseconds(50)).to_rfc3339_opts(SecondsFormat::Millis, true)
    );
    outputs.push(("get_entries".to_owned(), entries_bytes));

    let inventory_time = t0 + TimeDelta::seconds(1);
    clock.set_utc(inventory_time);
    let inventory_query = format!("actorDeviceId={}&limit=100", scenario.bob_primary.device_id);
    let conversations = execute_request(
        router,
        "get_conversations",
        scenario.bob_primary.signed_get_request(
            "blue.catbird.chat.getConversations",
            &inventory_query,
            inventory_time,
            b"get-conversations-jti",
        ),
    );
    tokio::pin!(conversations);
    // Inventory creation rounds up to the next second. Step only after its
    // committed session is visible, never according to how often HTTP was polled.
    let committed_session = async {
        loop {
            if let Some(created_at) = sqlx::query_scalar::<_, DateTime<Utc>>(
                "SELECT created_at FROM chat.inventory_sessions \
                 WHERE user_did = $1 AND device_id = $2 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(&scenario.bob_primary.did)
            .bind(scenario.bob_primary.device_id)
            .fetch_optional(pool)
            .await
            .expect("observe committed inventory session")
            {
                break created_at;
            }
        }
    };
    tokio::pin!(committed_session);
    let publication_started = Instant::now();
    let not_before = loop {
        tokio::select! {
            bytes = &mut conversations => panic!(
                "inventory response preceded its publication horizon: {}",
                String::from_utf8_lossy(&bytes)
            ),
            created_at = &mut committed_session => break created_at,
            _ = tokio::task::yield_now() => {
                assert!(
                    publication_started.elapsed() < Duration::from_secs(10),
                    "inventory session did not commit within 10 seconds"
                );
            }
        }
    };
    assert_eq!(not_before, t0 + TimeDelta::seconds(2));
    clock.set_utc(not_before);
    tokio::time::advance(Duration::from_secs(1)).await;
    let conversations_bytes = conversations.await;
    let conversations_json: Value =
        serde_json::from_slice(&conversations_bytes).expect("parse getConversations");
    let conversations_items = conversations_json["items"]
        .as_array()
        .expect("conversation items");
    assert_eq!(conversations_items.len(), 1);
    assert_eq!(
        conversations_items[0]["state"]["coordinates"]["conversationId"],
        scenario.conversation_id.to_string()
    );
    assert_eq!(conversations_items[0]["state"]["snapshotSeq"], 3);
    assert_eq!(conversations_json["hasMore"], false);
    let inventory_session_id = conversations_json["inventorySessionId"]
        .as_str()
        .expect("inventory capability");
    assert_eq!(
        URL_SAFE_NO_PAD.decode(inventory_session_id).unwrap().len(),
        32
    );
    assert_eq!(
        conversations_json["snapshotEventCursor"],
        inventory_session_id
    );
    let expected_expiry =
        (not_before + TimeDelta::minutes(15)).to_rfc3339_opts(SecondsFormat::Millis, true);
    assert_eq!(conversations_json["snapshotExpiresAt"], expected_expiry);

    let welcomes_time = t0 + TimeDelta::milliseconds(2010);
    clock.set_utc(welcomes_time);
    let welcomes_bytes = execute_request(
        router,
        "get_pending_welcomes",
        scenario.bob_primary.signed_get_request(
            "blue.catbird.chat.getPendingWelcomes",
            &format!(
                "actorDeviceId={}&inventorySessionId={inventory_session_id}&limit=100",
                scenario.bob_primary.device_id
            ),
            welcomes_time,
            b"get-pending-welcomes-jti",
        ),
    )
    .await;
    let welcomes_json: Value =
        serde_json::from_slice(&welcomes_bytes).expect("parse getPendingWelcomes");
    let welcomes = welcomes_json["items"].as_array().expect("welcome items");
    assert_eq!(
        welcomes.len(),
        1,
        "Bob's unacknowledged Welcome must be visible"
    );
    assert_eq!(
        welcomes[0]["welcomeId"],
        deterministic_uuid_v4(b"sim-welcome-1").to_string()
    );
    assert_eq!(
        welcomes[0]["conversationId"],
        scenario.conversation_id.to_string()
    );
    assert_eq!(welcomes[0]["recipientDid"], scenario.bob_primary.did);
    assert_eq!(
        welcomes[0]["recipientDeviceId"],
        scenario.bob_primary.device_id.to_string()
    );
    assert_eq!(welcomes[0]["transitionSeq"], 3);
    assert_eq!(welcomes_json["inventorySessionId"], inventory_session_id);
    assert_eq!(welcomes_json["snapshotExpiresAt"], expected_expiry);
    assert_eq!(welcomes_json["hasMore"], false);
    outputs.push(("get_conversations".to_owned(), conversations_bytes));
    outputs.push(("get_pending_welcomes".to_owned(), welcomes_bytes));

    for (label, actor, offset_ms, expected_pruned) in [
        ("acknowledge_entries_alice", &scenario.alice, 2020, 0),
        ("acknowledge_entries_bob", &scenario.bob_primary, 2030, 1),
    ] {
        let ack_time = t0 + TimeDelta::milliseconds(offset_ms);
        clock.set_utc(ack_time);
        let bytes = execute_request(
            router,
            label,
            actor.acknowledge_entries_request(
                scenario.conversation_id,
                4,
                ack_time,
                label.as_bytes(),
            ),
        )
        .await;
        let ack: Value = serde_json::from_slice(&bytes).expect("parse acknowledgeEntries");
        assert_eq!(ack["acknowledgedSeq"], 4);
        assert_eq!(ack["prunedCount"], expected_pruned);
        outputs.push((label.to_owned(), bytes));
    }

    let pruned_time = t0 + TimeDelta::milliseconds(2040);
    clock.set_utc(pruned_time);
    let pruned_bytes = execute_request(
        router,
        "get_entries_pruned",
        scenario.alice.signed_get_request(
            "blue.catbird.chat.getEntries",
            &entries_query,
            pruned_time,
            b"get-entries-pruned-jti",
        ),
    )
    .await;
    let pruned_json: Value =
        serde_json::from_slice(&pruned_bytes).expect("parse pruned getEntries");
    let pruned_entries = pruned_json["entries"].as_array().expect("pruned entries");
    assert_eq!(pruned_entries.len(), entries.len());
    for (before, after) in entries.iter().zip(pruned_entries) {
        assert_eq!(before["seq"], after["seq"]);
        assert_eq!(before["entryId"], after["entryId"]);
        assert_eq!(before["receivedAt"], after["receivedAt"]);
    }
    let pruned_application = pruned_entries.last().expect("pruned application entry");
    assert_eq!(pruned_application["payloadPruned"], true);
    assert!(pruned_application.get("signedRequest").is_none());
    assert_eq!(
        pruned_application["sequencerReceipt"],
        application_entry["sequencerReceipt"]
    );
    assert_eq!(pruned_json["hasMore"], false);
    assert_eq!(pruned_json["nextAfterSeq"], 4);
    outputs.push(("get_entries_pruned".to_owned(), pruned_bytes));
    outputs
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn identical_clock_and_queued_spawner_produce_identical_sequencer_receipts() {
    ensure_chat_runtime_env();

    let sim_db = open_disposable_sim_pool(None)
        .await
        .expect("open disposable max_connections(1) sim pool");
    assert_eq!(sim_db.max_connections(), 1);
    assert!(
        !PROTECTED_DATABASE_NAMES.contains(&sim_db.database_name()),
        "disposable sim DB must never target a protected database"
    );

    // Intentionally offset +7 days from host wall clock so any un-routed `Utc::now()`
    // or PostgreSQL `clock_timestamp()` trips JWT (60s) / signedAt (5m) / projection-age
    // bounds immediately, while keeping OpenMLS's internal 29-day KeyPackage `Lifetime`
    // window overlapping host `SystemTime::now()` during `MlsGroup::add_members`.
    let host_day_secs = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("host epoch")
        .as_secs()
        / 86_400)
        * 86_400;
    let t0 = DateTime::from_timestamp((host_day_secs + 7 * 86_400) as i64, 0)
        .expect("construct deterministic t0");
    let clock = Arc::new(ManualDsClock::new(t0));
    let spawner = Arc::new(QueuedTaskSpawner::new());

    let receipt_key = deterministic_p256(b"sequencer-receipt-es256");
    let receipt_signer = I13ReceiptSigner::new(receipt_key, SERVICE_DID.to_owned());
    let receipt_verifying_key = receipt_signer.verifying_key();

    let space_key = deterministic_p256(b"space-host-es256");
    let sse_state = Arc::new(SseState::new(16));
    let runtime = Arc::new(
        ChatRuntime::from_env(Arc::clone(&sse_state))
            .expect("build ChatRuntime")
            .with_clock(Arc::clone(&clock) as Arc<dyn DsClock>)
            .with_spawner(Arc::clone(&spawner) as _)
            .with_i13_receipt_signer(receipt_signer)
            .with_space_host_config(SpaceHostConfig::new(SERVICE_DID.to_owned(), space_key))
            .with_sim_allow_all_relationships()
            .expect("configure deterministic sim relationship authority"),
    );

    let router = chat_router::<SimAppState>().with_state(SimAppState {
        pool: sim_db.pool().clone(),
        runtime: Arc::clone(&runtime),
    });

    let scenario = build_deterministic_scenario(t0);
    seed_sim_did_document(scenario.alice.did_document()).await;
    seed_sim_did_document(scenario.bob_primary.did_document()).await;

    // Warm schema reset plan before Run 1 so Run 1 -> Run 2 measures steady-state truncation.
    reset_sim_postgres_schema(sim_db.pool())
        .await
        .expect("initial reset_sim_postgres_schema");

    // --- Run 1 ---
    let run1 = execute_scenario_run(&router, sim_db.pool(), &clock, t0, &scenario).await;

    // Post-commit device revocation work must be queued in `QueuedTaskSpawner`, NOT spawned onto Tokio.
    assert_eq!(spawner.pending_len(), 1);
    assert_eq!(spawner.labels(), vec!["chat.post_commit.device_revoked"]);
    assert_eq!(
        drive_paused_io("run 1 post-commit drain", spawner.drain_all()).await,
        1
    );
    assert_eq!(spawner.pending_len(), 0);

    // Enqueueing an SSE event must also capture onto `QueuedTaskSpawner` until explicitly drained.
    let convo_id_str = scenario.conversation_id.hyphenated().to_string();
    let mut sse_rx = sse_state.get_channel(&convo_id_str).await.subscribe();
    let typing_event: StreamEvent = serde_json::from_value(json!({
        "$type": "blue.catbird.chat.defs#typingEvent",
        "actorDeviceId": scenario.alice.device_id,
        "actorDid": scenario.alice.did,
        "conversationId": convo_id_str,
        "expiresAt": (t0 + TimeDelta::seconds(8)).to_rfc3339_opts(SecondsFormat::Millis, true),
        "isTyping": true,
        "typingId": convo_id_str,
    }))
    .expect("construct StreamEvent::CleanTypingEvent");
    sse_state.enqueue(&convo_id_str, typing_event);
    assert!(
        sse_rx.try_recv().is_err(),
        "SSE typing event must remain queued before drain_next"
    );
    assert_eq!(spawner.labels(), vec!["sse.consume_emit_queue"]);
    assert!(drive_paused_io("SSE event drain", spawner.drain_next()).await);
    assert_eq!(spawner.pending_len(), 0);
    assert!(
        sse_rx.try_recv().is_ok(),
        "SSE typing event must broadcast once drain_next runs"
    );

    // --- Fast Schema + In-Memory Cache Reset (`< 25 ms` on `max_connections(1)`) ---
    let reset_started = Instant::now();
    reset_sim_postgres_schema(sim_db.pool())
        .await
        .expect("reset_sim_postgres_schema between Run 1 and Run 2");
    let reset_elapsed = reset_started.elapsed();
    println!(
        "[deterministic_server_clock_test] steady-state reset_sim_postgres_schema elapsed: {:?}",
        reset_elapsed
    );
    // --- Run 2 (exact same clock schedule, JTIs, idempotency keys, and signed bytes) ---
    let run2 = execute_scenario_run(&router, sim_db.pool(), &clock, t0, &scenario).await;
    assert_eq!(spawner.labels(), vec!["chat.post_commit.device_revoked"]);
    assert_eq!(
        drive_paused_io("run 2 post-commit drain", spawner.drain_all()).await,
        1
    );

    assert_eq!(run1.len(), run2.len());
    assert_eq!(
        run1.len(),
        14,
        "all mutation, signed read, and ACK steps must replay"
    );
    for ((label1, bytes1), (label2, bytes2)) in run1.iter().zip(run2.iter()) {
        assert_eq!(label1, label2);
        assert_eq!(
            bytes1,
            bytes2,
            "HTTP response bytes diverged across deterministic replay at step '{label1}':\nrun1={}\nrun2={}",
            String::from_utf8_lossy(bytes1),
            String::from_utf8_lossy(bytes2),
        );
    }

    // Inspect `sendMessage` output and cryptographically verify `sequencerReceipt`.
    let send_bytes_1 = &run1
        .iter()
        .find(|(label, _)| label == "send_message")
        .expect("send_message output")
        .1;
    let send_bytes_2 = &run2
        .iter()
        .find(|(label, _)| label == "send_message")
        .expect("send_message output")
        .1;
    assert_eq!(send_bytes_1, send_bytes_2);

    let send_json_1: Value = serde_json::from_slice(send_bytes_1).expect("parse send_message JSON");
    let send_json_2: Value = serde_json::from_slice(send_bytes_2).expect("parse send_message JSON");
    let receipt_1 = &send_json_1["sequencerReceipt"];
    let receipt_2 = &send_json_2["sequencerReceipt"];
    assert!(
        receipt_1.is_object(),
        "expected sequencerReceipt object in sendMessage output: {send_json_1}"
    );
    assert_eq!(receipt_1, receipt_2);

    let expected_issued_at_ms = (t0 + TimeDelta::milliseconds(50)).timestamp_millis();
    assert_eq!(
        receipt_1["issuedAtMs"].as_i64(),
        Some(expected_issued_at_ms)
    );
    assert_eq!(receipt_1["seq"].as_u64(), Some(4));
    let expected_received_at =
        (t0 + TimeDelta::milliseconds(50)).to_rfc3339_opts(SecondsFormat::Millis, true);
    assert_eq!(
        send_json_1["entry"]["receivedAt"].as_str(),
        Some(expected_received_at.as_str())
    );
    assert_eq!(
        receipt_1["entryId"].as_str(),
        send_json_1["entry"]["entryId"].as_str()
    );

    let extract_b64 = |v: &Value| -> Vec<u8> {
        let s = v
            .as_str()
            .or_else(|| v.pointer("/$bytes").and_then(Value::as_str))
            .expect("bytes string or $bytes");
        STANDARD.decode(s).expect("base64 decode")
    };
    let sig_1: [u8; 64] = extract_b64(&receipt_1["signature"])
        .try_into()
        .expect("64-byte ES256 signature");
    let sig_2: [u8; 64] = extract_b64(&receipt_2["signature"])
        .try_into()
        .expect("64-byte ES256 signature");
    assert_eq!(
        sig_1, sig_2,
        "ES256 sequencerReceipt signature bytes must match bit-for-bit"
    );

    let group_id_bytes = extract_b64(&receipt_1["groupId"]);
    let commitment_bytes: [u8; 32] = extract_b64(&receipt_1["archiveCommitment"])
        .try_into()
        .expect("32-byte archiveCommitment");
    assert_eq!(commitment_bytes, scenario.archive_commitment);

    let signed_receipt = labyrinth_protocol::receipt::SignedSequencerReceipt {
        payload: labyrinth_protocol::receipt::SequencerReceiptPayload {
            sequencer_did: receipt_1["sequencerDid"].as_str().unwrap().to_owned(),
            conversation_id: receipt_1["conversationId"].as_str().unwrap().to_owned(),
            group_id: group_id_bytes,
            epoch: receipt_1["epoch"].as_u64().unwrap(),
            sender_device_did_url: format!("{}#{}", scenario.alice.did, scenario.alice.device_id),
            entry_id: receipt_1["entryId"].as_str().unwrap().to_owned(),
            archive_commitment: commitment_bytes,
            seq: receipt_1["seq"].as_u64().unwrap(),
            issued_at_ms: receipt_1["issuedAtMs"].as_i64().unwrap(),
        },
        key_id: receipt_1["kid"].as_str().unwrap().to_owned(),
        signature: sig_1,
    };
    labyrinth_protocol::receipt::verify_sequencer_receipt(
        &receipt_verifying_key,
        SERVICE_DID,
        &signed_receipt,
    )
    .expect("ES256 sequencerReceipt must verify cryptographically");

    assert!(
        reset_elapsed < Duration::from_millis(25),
        "steady-state reset_sim_postgres_schema took {reset_elapsed:?}, expected < 25ms"
    );

    drive_paused_io("replay DB cleanup", sim_db.cleanup())
        .await
        .expect("drop disposable sim DB");
}

async fn assert_reset_without_virtual_time_advance(pool: &DbPool, label: &str) {
    let before = tokio::time::Instant::now();
    let (cancel_tx, cancel_rx) = std::sync::mpsc::channel::<()>();
    let (deadline_tx, deadline_rx) = tokio::sync::oneshot::channel();
    // A Tokio timeout can auto-advance paused time or never fire during a yield
    // loop. A sleeping OS thread bounds hangs without keeping Tokio runnable.
    let watchdog = std::thread::spawn(move || {
        if matches!(
            cancel_rx.recv_timeout(Duration::from_secs(10)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            let _ = deadline_tx.send(());
        }
    });
    let reset = tokio::select! {
        result = reset_sim_postgres_schema(pool) => Some(result),
        _ = deadline_rx => None,
    };
    drop(cancel_tx);
    watchdog.join().expect("join reset watchdog");
    reset
        .unwrap_or_else(|| panic!("{label} schema reset hung for 10 real seconds"))
        .unwrap_or_else(|error| panic!("{label} schema reset failed: {error}"));
    assert_eq!(
        tokio::time::Instant::now(),
        before,
        "{label} schema reset must not advance paused Tokio time"
    );
    assert_eq!(
        pool.num_idle(),
        1,
        "{label} must return its single connection"
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn schema_reset_does_not_advance_paused_time_for_worker_or_plain_single_connection_pool() {
    // Establish both pools in real time; only schema reset is under test.
    tokio::time::resume();
    let sim_db = open_disposable_sim_pool(None)
        .await
        .expect("open worker pool for paused reset regression");
    let plain_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(sim_db.pool().connect_options().as_ref().clone())
        .await
        .expect("open plain single-connection pool without worker release hooks");
    tokio::time::pause();
    for (label, pool) in [
        ("worker cold", sim_db.pool()),
        ("worker warm", sim_db.pool()),
        ("plain cold", &plain_pool),
        ("plain warm", &plain_pool),
    ] {
        assert_reset_without_virtual_time_advance(pool, label).await;
    }
    tokio::time::resume();
    plain_pool.close().await;
    sim_db
        .cleanup()
        .await
        .expect("cleanup paused reset regression DB");
}

#[tokio::test(flavor = "current_thread")]
async fn hybrid_schema_reset_compacts_every_64_passes_and_explicitly_reclaims_empty_heaps() {
    async fn probe_state(pool: &DbPool) -> (i64, i64, i64, i64) {
        sqlx::query_as(
            "SELECT count(*), \
                    pg_relation_filenode('public.sim_reset_probe'::regclass)::bigint, \
                    pg_relation_size('public.sim_reset_probe'::regclass), \
                    COALESCE(NULLIF(current_setting( \
                        'catbird_sim.resets_since_compaction', true), ''), '0')::bigint \
             FROM public.sim_reset_probe",
        )
        .fetch_one(pool)
        .await
        .expect("read reset probe rows, heap, and session reset count")
    }

    async fn insert_probe(pool: &DbPool) -> i64 {
        sqlx::query_scalar(
            "INSERT INTO public.sim_reset_probe (payload) VALUES ('live compaction probe') \
             RETURNING id",
        )
        .fetch_one(pool)
        .await
        .expect("insert reset probe with generated identity")
    }

    let sim_db = open_disposable_sim_pool(None)
        .await
        .expect("open disposable pool for hybrid reset regression");
    let pool = sim_db.pool();
    // Create before the reset plan is cached. Disable autovacuum so physical
    // heap measurements distinguish fast DELETE from actual compaction.
    sqlx::query(
        "CREATE TABLE public.sim_reset_probe ( \
             id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, \
             payload TEXT NOT NULL \
         ) WITH (autovacuum_enabled = false)",
    )
    .execute(pool)
    .await
    .expect("create operational identity probe");
    reset_sim_postgres_schema(pool)
        .await
        .expect("cold startup compaction");
    let cold = probe_state(pool).await;
    assert_eq!(cold.0, 0);
    assert_eq!(cold.2, 0);
    assert_eq!(
        cold.3, 0,
        "cold compaction establishes the cadence baseline"
    );
    sqlx::query(
        "INSERT INTO public.sim_reset_probe (payload) \
         SELECT repeat('x', 512) FROM generate_series(1, 32)",
    )
    .execute(pool)
    .await
    .expect("populate reset probe heap");
    let populated = probe_state(pool).await;
    assert_eq!(populated.0, 32);
    assert!(populated.2 > 0);

    reset_sim_postgres_schema(pool)
        .await
        .expect("first fast reset");
    let deleted = probe_state(pool).await;
    assert_eq!(deleted.0, 0);
    assert_eq!(
        deleted.1, populated.1,
        "fast reset must not rewrite the heap"
    );
    assert!(deleted.2 > 0, "DELETE must leave measurable heap storage");
    assert_eq!(deleted.3, 1);
    assert_eq!(insert_probe(pool).await, 1, "fast reset restarts identity");

    compact_sim_postgres_schema(pool)
        .await
        .expect("explicit occupied compaction");
    let compacted = probe_state(pool).await;
    assert_eq!(
        compacted.0, 0,
        "explicit compaction clears operational rows"
    );
    assert_ne!(compacted.1, deleted.1);
    assert_eq!(compacted.2, 0, "new heap cannot retain dead tuples");
    assert_eq!(compacted.3, 0, "explicit compaction restarts the cadence");

    for pass in 1..=64 {
        assert_eq!(
            insert_probe(pool).await,
            1,
            "identity restart before pass {pass}"
        );
        reset_sim_postgres_schema(pool)
            .await
            .unwrap_or_else(|error| panic!("hybrid reset pass {pass} failed: {error}"));
        let state = probe_state(pool).await;
        assert_eq!(state.0, 0, "pass {pass} must clear operational rows");
        if pass < 64 {
            assert_eq!(state.1, compacted.1, "pass {pass} must stay on fast DELETE");
            assert!(state.2 > 0);
            assert_eq!(state.3, pass);
        } else {
            assert_ne!(state.1, compacted.1, "64th reset must compact");
            assert_eq!(state.2, 0, "periodic compaction removes heap tombstones");
            assert_eq!(state.3, 0, "periodic compaction restarts the cadence");
        }
    }

    assert_eq!(
        insert_probe(pool).await,
        1,
        "periodic compaction restarts identity"
    );
    reset_sim_postgres_schema(pool)
        .await
        .expect("delete before empty compaction");
    let empty_bloated = probe_state(pool).await;
    assert_eq!(empty_bloated.0, 0);
    assert!(empty_bloated.2 > 0);
    assert_eq!(empty_bloated.3, 1);
    // Occupancy alone cannot find this heap: the fast path already deleted
    // every live row, but its physical storage still needs reclamation.
    compact_sim_postgres_schema(pool)
        .await
        .expect("explicit empty-heap compaction");
    let empty_compacted = probe_state(pool).await;
    assert_eq!(empty_compacted.0, 0);
    assert_ne!(empty_compacted.1, empty_bloated.1);
    assert_eq!(
        empty_compacted.2, 0,
        "empty compaction must reclaim DELETE storage"
    );
    assert_eq!(empty_compacted.3, 0);
    assert_eq!(
        insert_probe(pool).await,
        1,
        "empty compaction restarts identity"
    );

    sim_db
        .cleanup()
        .await
        .expect("cleanup hybrid reset regression DB");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parallel_manual_clocks_keep_jti_and_tid_sequences_and_resets_isolated() {
    async fn samples(client: &ServiceAuthClient, count: usize) -> Vec<(String, String)> {
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push((
                catbird_server::labyrinth::tid::next_tid(),
                client
                    .sign_request(
                        "did:web:peer.catbird.blue",
                        "blue.catbird.mlsDS.deliverMessage",
                    )
                    .expect("mint deterministic outbound JWT"),
            ));
            tokio::task::yield_now().await;
        }
        values
    }

    let t0 = DateTime::from_timestamp(1_800_000_000, 0).expect("fixed clock origin");
    let client = Arc::new(ServiceAuthClient::from_shared_secret(
        SERVICE_DID.to_owned(),
        b"deterministic-counter-isolation-test",
    ));
    let expected = scope_ds_clock(Arc::new(ManualDsClock::new(t0)), samples(&client, 5)).await;
    assert!(
        expected
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0 && pair[0].1 != pair[1].1),
        "stalled-clock TIDs must increase and each outbound JTI must remain unique"
    );

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let spawn_worker = |clock: Arc<ManualDsClock>, reset: bool| {
        let client = Arc::clone(&client);
        let barrier = Arc::clone(&barrier);
        tokio::spawn(scope_ds_clock(
            Arc::clone(&clock) as Arc<dyn DsClock>,
            async move {
                let before = samples(&client, 4).await;
                barrier.wait().await;
                if reset {
                    clock.reset_counters();
                }
                barrier.wait().await;
                let after = samples(&client, 1).await;
                (before, after)
            },
        ))
    };
    let first = spawn_worker(Arc::new(ManualDsClock::new(t0)), true);
    let second = spawn_worker(Arc::new(ManualDsClock::new(t0)), false);
    let (first, second) = tokio::join!(first, second);
    let (first_before, first_after) = first.expect("first parallel clock");
    let (second_before, second_after) = second.expect("second parallel clock");
    assert_eq!(first_before.as_slice(), &expected[..4]);
    assert_eq!(second_before.as_slice(), &expected[..4]);
    assert_eq!(
        first_after.as_slice(),
        &expected[..1],
        "reset must replay only its clock"
    );
    assert_eq!(
        second_after.as_slice(),
        &expected[4..],
        "resetting the first clock must not rewind the live second clock"
    );
}

#[tokio::test]
async fn sql_migrations_and_live_catalog_enforce_explicit_app_timestamps_for_chat_tables() {
    let migrations_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let report = audit_sql_timestamp_defaults(&migrations_dir)
        .expect("SQL migration wall-clock default audit must pass");
    assert!(
        report.unreviewed_protocol_defaults.is_empty(),
        "found unreviewed SQL wall-clock defaults in chat/labyrinth migrations: {:?}",
        report.unreviewed_protocol_defaults
    );
    assert!(
        report.scanned_migration_files > 0,
        "expected migrations/*.sql to be scanned"
    );

    let sim_db = open_disposable_sim_pool(None)
        .await
        .expect("open disposable sim pool for catalog audit");
    let live_violations = audit_live_catalog_timestamp_defaults(sim_db.pool())
        .await
        .expect("query information_schema.columns");
    assert!(
        live_violations.is_empty(),
        "found live protocol-visible wall-clock column defaults: {live_violations:?}"
    );
    sim_db.cleanup().await.expect("cleanup disposable sim pool");
}
