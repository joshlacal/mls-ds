//! Disposable-DB integration tests for clean-chat federation routing.
//!
//! Covers:
//! 1. Schema constraints and indexes (conversations_is_remote_shape_check, participants_ds_did_check)
//! 2. Allowlisted remote ds_did persisted end-to-end through createConversation handler
//! 3. Resolver failure / untrusted peer returns declared error and causes zero writes
//! 4. Routing drift detection under real database locks aborts cleanly
//! 5. Generation advance across real reset preserves remote sequencer identity and term
//! 6. Replay preflight proves zero resolver calls on idempotent replay
//! 7. A closed federation gate (mode `off`, kill switch) answers a remote member's
//!    creation or add, and a transition forwarded to a remote sequencer, with the
//!    declared retryable 503 (`Retry-After: 5`), unsent and unpersisted; the same
//!    request goes through once it reopens. A participant home resolution that
//!    could not answer is retryable too; refusals stay `NotAuthorized`.
//! 8. Three homes: a relayed policy add whose new member's home cannot answer
//!    now (closed gate, 429, 5xx, unreachable, unresolved host) is retryable at
//!    the actor's home and persists nothing at either home; that home's refusal
//!    stays `NotAuthorized`; once it answers, the sequencer sequences the same
//!    request under a claim bound to its kind, body and signature, refuses
//!    another body under it or a relayed fifth kind, and replays its answer.

#![allow(dead_code)]

mod common;
pub use catbird_server::{auth, crypto, sim_hooks};

#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../src/chat_protocol/read_projection.rs"]
mod read_projection;
#[allow(dead_code)]
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[allow(dead_code)]
#[path = "../src/chat_protocol/validation.rs"]
mod validation;
use std::collections::BTreeMap;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::FromRef,
    http::{Request, StatusCode},
    Router,
};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use openmls::prelude::{
    tls_codec::Serialize as TlsSerialize, BasicCredential, Capabilities, Ciphersuite,
    CredentialType, CredentialWithKey, GroupId, Lifetime, MlsGroup, MlsGroupCreateConfig,
    ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as _, VLBytes};
use tower_util::ServiceExt;
use uuid::Uuid;

use catbird_server::chat_protocol::federation_routing::{
    ConversationRoutingIntent, FederationRoutingError,
};
use catbird_server::handlers::chat::{chat_router, ChatRuntime};
use catbird_server::storage::DbPool;
use transcript::decode_canonical_signed_mutation;
use validation::ed25519_key_id;

// =============================================================================
// TLS Codec Test GroupInfo Envelope
// =============================================================================

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestGroupInfoEnvelope {
    version: u16,
    wire_format: u16,
    group_info: TestGroupInfo,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestGroupInfo {
    group_context: TestGroupContext,
    extensions: Vec<TestExtension>,
    confirmation_tag: VLBytes,
    signer: u32,
    signature: VLBytes,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestGroupContext {
    protocol_version: u16,
    ciphersuite: u16,
    group_id: VLBytes,
    epoch: u64,
    tree_hash: VLBytes,
    confirmed_transcript_hash: VLBytes,
    extensions: Vec<TestExtension>,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestExtension {
    extension_type: u16,
    extension_data: VLBytes,
}

const ISSUER: &str = "did:web:api.catbird.blue";
const AUDIENCE: &str = "did:web:chat.catbird.blue#atproto_mls";
const NEST_KEY_ID: &str = "nest-key-1";
const CHAT_INSTANCE: &str = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
const EXTERNAL_BASE: &str = "https://chat.example.net";
const ENDPOINT: &str = "blue.catbird.chat.createConversation";

#[derive(Clone)]
struct TestState {
    pool: DbPool,
    runtime: Arc<ChatRuntime>,
}

impl FromRef<TestState> for DbPool {
    fn from_ref(state: &TestState) -> DbPool {
        state.pool.clone()
    }
}

impl FromRef<TestState> for Arc<ChatRuntime> {
    fn from_ref(state: &TestState) -> Arc<ChatRuntime> {
        state.runtime.clone()
    }
}

fn nest_signing_key() -> P256SigningKey {
    P256SigningKey::from_bytes((&[0x5a_u8; 32]).into()).expect("nest signing key")
}

async fn ensure_verifier_env(pool: &DbPool) {
    let point = nest_signing_key().verifying_key().to_encoded_point(false);
    std::env::set_var("SERVICE_DID", "did:web:chat.catbird.blue");
    std::env::set_var("CHAT_NEST_ISSUER", ISSUER);
    std::env::set_var("CHAT_NEST_AUDIENCE", AUDIENCE);
    std::env::set_var("CHAT_NEST_KEY_ID", NEST_KEY_ID);
    std::env::set_var("CHAT_NEST_VERIFYING_KEY", STANDARD.encode(point.as_bytes()));
    std::env::set_var("CHAT_INSTANCE_ID", CHAT_INSTANCE);
    std::env::set_var("CHAT_EXTERNAL_BASE", EXTERNAL_BASE);
    let key_id: Option<String> = sqlx::query_scalar(
        "SELECT cursor_key_id FROM chat.protocol_instances WHERE singleton=TRUE",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    let key_id = if let Some(key_id) = key_id {
        key_id
    } else if let Ok(key) = sqlx::query_scalar::<_, String>("SELECT chat.ed25519_key_id($1)")
        .bind(vec![0x51_u8; 32])
        .fetch_one(pool)
        .await
    {
        let inst_id = Uuid::new_v4();
        let _ = sqlx::query("INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING")
            .bind(inst_id)
            .bind(&key)
            .execute(pool)
            .await;
        let _ = sqlx::query("INSERT INTO chat.event_retention(protocol_instance_id,retained_floor,updated_at) VALUES($1,0,clock_timestamp()) ON CONFLICT DO NOTHING")
            .bind(inst_id)
            .execute(pool)
            .await;
        key
    } else {
        URL_SAFE_NO_PAD.encode([0x11_u8; 32])
    };
    std::env::set_var("CHAT_CURSOR_KEY_ID", key_id);
    std::env::set_var(
        "CHAT_CURSOR_SEALING_SECRET",
        URL_SAFE_NO_PAD.encode([0xA5_u8; 32]),
    );
    std::env::set_var(
        "CHAT_SUBSCRIPTION_ENDPOINT",
        "wss://chat.example.net/xrpc/blue.catbird.chat.subscribeEvents",
    );
    let jwk_val = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    });
    let jwk: catbird_server::auth::PublicKeyJwk = serde_json::from_value(jwk_val).unwrap();
    let doc = catbird_server::auth::DidDocument {
        id: ISSUER.to_string(),
        verification_method: vec![catbird_server::auth::VerificationMethod {
            id: format!("{ISSUER}#atproto"),
            key_type: "JsonWebKey2020".to_string(),
            controller: ISSUER.to_string(),
            public_key_jwk: Some(jwk),
            public_key_multibase: None,
        }],
        service: None,
    };
    catbird_server::auth::cache_test_did_document(doc).await;
}

async fn runtime(pool: &DbPool, cutover_enabled: bool) -> Arc<ChatRuntime> {
    ensure_verifier_env(pool).await;
    if cutover_enabled {
        std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    } else {
        std::env::remove_var("CHAT_CUTOVER_ENABLED");
    }
    let self_did = "did:web:chat.catbird.blue".to_string();
    let resolver = Arc::new(catbird_server::federation::resolver::DsResolver::new(
        pool.clone(),
        reqwest::Client::new(),
        self_did,
        "https://chat.example.net".to_string(),
        None,
        300,
    ));
    Arc::new(
        ChatRuntime::from_env(Arc::new(catbird_server::realtime::SseState::new(8)))
            .expect("build clean-chat runtime")
            .with_resolver(resolver),
    )
}
async fn router_with(pool: DbPool, cutover_enabled: bool) -> Router {
    let rt = runtime(&pool, cutover_enabled).await;
    chat_router::<TestState>().with_state(TestState { pool, runtime: rt })
}

fn xrpc(nsid: &str) -> String {
    format!("/xrpc/{nsid}")
}

async fn send_raw(router: Router, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = router.oneshot(request).await.expect("router response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("collect response body");
    (status, bytes.to_vec())
}

async fn send(router: Router, request: Request<Body>) -> (StatusCode, Value) {
    let (status, bytes) = send_raw(router, request).await;
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

fn random_p256() -> P256SigningKey {
    loop {
        let mut seed = [0_u8; 32];
        seed[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        seed[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        if let Ok(key) = P256SigningKey::from_slice(&seed) {
            return key;
        }
    }
}

fn public_jwk(key: &P256SigningKey) -> Value {
    let point = key.verifying_key().to_encoded_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    })
}

fn jwk_thumbprint(jwk: &Value) -> String {
    let canonical = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap()
    );
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn sign_jwt(header: Value, claims: Value, key: &P256SigningKey) -> String {
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature: P256Signature = key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn dpop_proof(
    key: &P256SigningKey,
    jwk: &Value,
    htm: &str,
    htu: &str,
    access_token: &str,
    iat: i64,
    jti_bytes: &[u8],
) -> String {
    sign_jwt(
        json!({"typ":"dpop+jwt","alg":"ES256","jwk":jwk}),
        json!({
            "htm": htm,
            "htu": htu,
            "ath": URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes())),
            "iat": iat,
            "jti": URL_SAFE_NO_PAD.encode(jti_bytes),
        }),
        key,
    )
}

#[derive(Clone)]
struct CreationTestFixture {
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_ed25519_public_key: Vec<u8>,
    actor_ed25519_signing_key: Ed25519SigningKey,
    signed_request_json: Value,
    cid: Uuid,
    transition_id: Uuid,
    group_id: [u8; 32],
    group_context_hash: [u8; 32],
    confirmation_tag: [u8; 32],
}

fn random_did() -> String {
    let bytes: [u8; 15] = Uuid::new_v4().as_bytes()[..15].try_into().unwrap();
    let suffix: String = (0..24)
        .map(|i| {
            let value = (bytes[i % 15] as usize + i * 7) % 32;
            char::from(b"abcdefghijklmnopqrstuvwxyz234567"[value])
        })
        .collect();
    format!("did:plc:{suffix}")
}

fn build_test_creation_fixture_with_invitee(
    trusted_at: DateTime<Utc>,
    invitee_did: Option<&str>,
) -> CreationTestFixture {
    let kind = if invitee_did.is_some() {
        "direct"
    } else {
        "group"
    };
    build_test_creation_fixture(trusted_at, invitee_did, kind)
}

fn build_test_creation_fixture(
    trusted_at: DateTime<Utc>,
    invitee_did: Option<&str>,
    kind: &str,
) -> CreationTestFixture {
    let cid = Uuid::new_v4();
    let transition_id = Uuid::new_v4();
    let actor_did = random_did();
    let actor_device_id = Uuid::new_v4();
    let mut seed = [0_u8; 32];
    seed[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    seed[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    let ed_signing = Ed25519SigningKey::from_bytes(&seed);
    let public_key_bytes = ed_signing.verifying_key().to_bytes();
    let actor_key_id = ed25519_key_id(&public_key_bytes)
        .unwrap()
        .as_str()
        .to_owned();

    let signed_at = (trusted_at - chrono::Duration::milliseconds(500))
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let now_sec = u64::try_from(trusted_at.timestamp()).unwrap();
    let lifetime = Lifetime::init(now_sec - 60, now_sec + 3600);

    let provider = openmls_libcrux_crypto::Provider::new().expect("libcrux provider");
    let ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
    let signer = SignatureKeyPair::from_raw(
        ciphersuite.signature_algorithm(),
        ed_signing.to_bytes().to_vec(),
        public_key_bytes.to_vec(),
    );
    signer.store(provider.storage()).expect("store signer");

    let actor_credential = format!("{actor_did}#{actor_device_id}").into_bytes();
    let capabilities = Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[ciphersuite]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    );

    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .capabilities(capabilities)
        .lifetime(lifetime)
        .build();

    let group_id: [u8; 32] =
        Sha256::digest([b"CATBIRD-TEST-GROUP\0".as_ref(), cid.as_bytes()].concat()).into();

    let group = MlsGroup::new_with_group_id(
        &provider,
        &signer,
        &config,
        GroupId::from_slice(&group_id),
        CredentialWithKey {
            credential: BasicCredential::new(actor_credential.clone()).into(),
            signature_key: signer.to_public_vec().into(),
        },
    )
    .expect("create MLS group");

    let genesis_group_info = group
        .export_group_info(provider.crypto(), &signer, true)
        .expect("export GroupInfo")
        .tls_serialize_detached()
        .expect("serialize GroupInfo");

    let envelope = TestGroupInfoEnvelope::tls_deserialize_exact(&genesis_group_info)
        .expect("parse coordinate GroupInfo");
    let group_context_hash: [u8; 32] = Sha256::digest(
        envelope
            .group_info
            .group_context
            .tls_serialize_detached()
            .expect("serialize coordinate GroupContext"),
    )
    .into();
    let confirmation_tag_32: [u8; 32] = envelope
        .group_info
        .confirmation_tag
        .as_slice()
        .try_into()
        .expect("32-byte confirmation tag");

    let metadata_ciphertext = [0x99_u8; 32];
    let body = json!({
        "$type": "blue.catbird.chat.defs#creationBody",
        "signatureDomain": "CATBIRD-CHAT-CREATE\u{0000}",
        "conversationId": cid.hyphenated().to_string(),
        "transitionId": transition_id.hyphenated().to_string(),
        "conversationKind": kind,
        "absence": true,
        "actorDid": &actor_did,
        "actorDeviceId": actor_device_id.hyphenated().to_string(),
        "authGeneration": 1,
        "idempotencyKey": transition_id.hyphenated().to_string(),
        "keyId": &actor_key_id,
        "signedAt": &signed_at,
        "next": {
            "conversationId": cid.hyphenated().to_string(),
            "generation": 0,
            "stateVersion": 0,
            "groupId": STANDARD.encode(group_id),
            "epoch": 0,
            "groupContextHash": STANDARD.encode(group_context_hash),
            "confirmationTag": STANDARD.encode(confirmation_tag_32),
            "lifecycle": "active"
        },
        "manifest": {
            "actorLeaf": {
                "userDid": &actor_did,
                "deviceId": actor_device_id.hyphenated().to_string(),
                "leafOrigin": "genesis",
            },
            "participants": match invitee_did {
                Some(invitee) => {
                    let mut list = vec![
                        json!({
                            "userDid": &actor_did,
                            "status": "active",
                            "role": "admin"
                        }),
                        json!({
                            "userDid": invitee,
                            "status": "pending",
                            "role": "member",
                            "invitationProvenance": {
                                "invitedByDid": &actor_did,
                                "invitedByDeviceId": actor_device_id.hyphenated().to_string(),
                                "invitationTransitionId": transition_id.hyphenated().to_string(),
                            },
                        }),
                    ];
                    list.sort_by(|a, b| a["userDid"].as_str().cmp(&b["userDid"].as_str()));
                    json!(list)
                }
                None => json!([
                    {
                        "userDid": &actor_did,
                        "status": "active",
                        "role": "admin"
                    }
                ]),
            },
        },
        "genesisGroupInfo": {
            "framing": "mlsMessage",
            "contentType": "groupInfo",
            "bytes": STANDARD.encode(&genesis_group_info),
            "sha256": STANDARD.encode(Sha256::digest(&genesis_group_info))
        },
        "metadataSnapshot": {
            "coordinate": {
                "conversationId": STANDARD.encode(cid.as_bytes()),
                "generation": 0,
                "groupId": STANDARD.encode(group_id),
                "epoch": 0,
                "groupContextHash": STANDARD.encode(group_context_hash),
                "confirmationTag": STANDARD.encode(confirmation_tag_32),
            },
            "originTransitionId": transition_id.hyphenated().to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode([0x73_u8; 12]),
            "ciphertext": STANDARD.encode(metadata_ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(metadata_ciphertext)),
            "ciphertextSize": metadata_ciphertext.len(),
            "authorProof": {
                "authorDid": &actor_did,
                "authorDeviceId": actor_device_id.hyphenated().to_string(),
                "authorKeyId": &actor_key_id,
                "signaturePublicKey": STANDARD.encode(public_key_bytes),
                "authGenerationAtOrigin": 1,
                "originTransitionId": transition_id.hyphenated().to_string(),
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active",
            },
        }
    });

    let mut wrapper = json!({
        "body": body,
        "signature": STANDARD.encode([0_u8; 64]),
    });
    let unsigned = serde_json::to_vec(&wrapper).unwrap();
    let canonical =
        decode_canonical_signed_mutation(&unsigned).expect("canonicalize creation body");
    let signature = ed_signing.sign(canonical.transcript_bytes());
    wrapper["signature"] = json!(STANDARD.encode(signature.to_bytes()));

    CreationTestFixture {
        actor_did,
        actor_device_id,
        actor_key_id,
        actor_ed25519_public_key: public_key_bytes.to_vec(),
        actor_ed25519_signing_key: ed_signing,
        signed_request_json: wrapper,
        cid,
        transition_id,
        group_id,
        group_context_hash,
        confirmation_tag: confirmation_tag_32,
    }
}

async fn ensure_federation_peers_table(pool: &DbPool) {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS federation_peers (
            ds_did TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'pending',
            trust_score INTEGER NOT NULL DEFAULT 0,
            max_requests_per_minute INTEGER DEFAULT 100,
            rejected_request_count BIGINT NOT NULL DEFAULT 0,
            invalid_token_count BIGINT NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT federation_peers_status_check CHECK (status IN ('pending', 'allow', 'suspend', 'block'))
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("create federation_peers table in disposable db");
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ds_endpoints (
            did TEXT PRIMARY KEY,
            endpoint TEXT NOT NULL,
            supported_cipher_suites TEXT,
            federation_capabilities TEXT,
            resolved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour'
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("create ds_endpoints table in disposable db");

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS did_ds_mappings (
            actor_did TEXT PRIMARY KEY,
            ds_did TEXT NOT NULL,
            resolved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour'
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("create did_ds_mappings table in disposable db");
}
async fn seed_device_for_creation(
    pool: &DbPool,
    user_did: &str,
    device_id: Uuid,
    key_id: &str,
    signing_public_key: &[u8],
    dpop_signing_key: &P256SigningKey,
    dpop_jkt: &str,
) {
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO chat.principals (user_did, created_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(user_did)
    .bind(now)
    .execute(pool)
    .await
    .expect("seed principal");

    sqlx::query(
        r#"
        INSERT INTO chat.devices (
            user_did, device_id, device_name, status, dpop_jkt,
            auth_generation, capabilities, created_at, updated_at
        ) VALUES ($1, $2, 'test-device', 'active', $3, 1, chat.protocol_capabilities(), $4, $4)
        ON CONFLICT (user_did, device_id) DO UPDATE SET status = 'active', auth_generation = 1, dpop_jkt = $3
        "#,
    )
    .bind(user_did)
    .bind(device_id)
    .bind(dpop_jkt)
    .bind(now)
    .execute(pool)
    .await
    .expect("seed device");

    sqlx::query(
        r#"
        INSERT INTO chat.device_keys (
            user_did, device_id, key_id, signing_public_key,
            enrollment_auth_generation, created_at
        ) VALUES ($1, $2, $3, $4, 1, $5)
        ON CONFLICT (user_did, device_id, key_id) DO NOTHING
        "#,
    )
    .bind(user_did)
    .bind(device_id)
    .bind(key_id)
    .bind(signing_public_key)
    .bind(now)
    .execute(pool)
    .await
    .expect("seed device key");

    let point = dpop_signing_key.verifying_key().to_encoded_point(false);
    let jwk_val = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    });
    let jwk: catbird_server::auth::PublicKeyJwk = serde_json::from_value(jwk_val).unwrap();
    let doc = catbird_server::auth::DidDocument {
        id: user_did.to_string(),
        verification_method: vec![catbird_server::auth::VerificationMethod {
            id: format!("{user_did}#atproto"),
            key_type: "JsonWebKey2020".to_string(),
            controller: user_did.to_string(),
            public_key_jwk: Some(jwk),
            public_key_multibase: None,
        }],
        service: Some(vec![catbird_server::auth::Service {
            id: "#atproto_pds".to_string(),
            service_type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: "https://pds.local.example.net".to_string(),
        }]),
    };
    catbird_server::auth::cache_test_did_document(doc).await;
}

fn build_authenticated_request(
    user_did: &str,
    device_id: Uuid,
    dpop_signing_key: &P256SigningKey,
    dpop_jwk: &Value,
    dpop_jkt: &str,
    payload: Value,
) -> Request<Body> {
    build_authenticated_request_to(
        ENDPOINT,
        user_did,
        device_id,
        dpop_signing_key,
        dpop_jwk,
        dpop_jkt,
        payload,
    )
}

/// A POST to `nsid` under a fresh device-bound access token and DPoP proof.
fn build_authenticated_request_to(
    nsid: &str,
    user_did: &str,
    device_id: Uuid,
    dpop_signing_key: &P256SigningKey,
    dpop_jwk: &Value,
    dpop_jkt: &str,
    payload: Value,
) -> Request<Body> {
    let now = chrono::Utc::now().timestamp();
    let access_token = sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":format!("{user_did}#atproto")}),
        json!({
            "iss": user_did,
            "sub": user_did,
            "aud": AUDIENCE,
            "lxm": nsid,
            "iat": now,
            "exp": now + 60,
            "jti": Uuid::new_v4().to_string(),
            "cnf": {"jkt": dpop_jkt},
            "device_id": device_id.to_string(),
            "chat_instance": CHAT_INSTANCE,
        }),
        dpop_signing_key,
    );
    let htu = format!("{EXTERNAL_BASE}/xrpc/{nsid}");
    let proof = dpop_proof(
        dpop_signing_key,
        dpop_jwk,
        "POST",
        &htu,
        &access_token,
        now,
        Uuid::new_v4().as_bytes(),
    );

    let body_bytes = serde_json::to_vec(&payload).unwrap();
    Request::builder()
        .method("POST")
        .uri(xrpc(nsid))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {access_token}"))
        .header("dpop", proof)
        .body(Body::from(body_bytes))
        .expect("build request")
}

fn build_authenticated_get_request(
    user_did: &str,
    _device_id: Uuid,
    dpop_signing_key: &P256SigningKey,
    dpop_jwk: &Value,
    dpop_jkt: &str,
    endpoint: &str,
    query: &str,
) -> Request<Body> {
    let now = chrono::Utc::now().timestamp();
    let access_token = sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":format!("{user_did}#atproto")}),
        json!({
            "iss": user_did,
            "sub": user_did,
            "aud": AUDIENCE,
            "lxm": endpoint,
            "iat": now,
            "exp": now + 60,
            "jti": Uuid::new_v4().to_string(),
            "cnf": {"jkt": dpop_jkt},
            "chat_instance": CHAT_INSTANCE,
        }),
        dpop_signing_key,
    );

    let htu = format!("{EXTERNAL_BASE}/xrpc/{endpoint}");
    let proof = dpop_proof(
        dpop_signing_key,
        dpop_jwk,
        "GET",
        &htu,
        &access_token,
        now,
        Uuid::new_v4().as_bytes(),
    );

    Request::builder()
        .method("GET")
        .uri(format!("/xrpc/{endpoint}?{query}"))
        .header("authorization", format!("Bearer {access_token}"))
        .header("dpop", proof)
        .body(Body::empty())
        .expect("build request")
}

// =============================================================================
// Tests
// =============================================================================

#[tokio::test]
async fn test_schema_constraints_and_indexes() {
    let (pool, _disposable) =
        common::fresh_db::fresh_clean_protocol_db("chat_fedrouting_", 4).await;
    let mut tx = pool.begin().await.unwrap();

    let convo_id = Uuid::new_v4();
    let now = Utc::now();

    // 1. Valid local conversation (is_remote = false, sequencer_ds = NULL, sequencer_term = 0)
    sqlx::query(
        r#"
        INSERT INTO chat.conversations(
            conversation_id, kind, lifecycle, current_generation,
            current_state_version, next_entry_seq, created_at,
            is_remote, sequencer_ds, sequencer_term
        ) VALUES ($1, 'group', 'active', 0, 0, 2, $2, FALSE, NULL, 0)
        "#,
    )
    .bind(convo_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .expect("local conversation head insert must succeed");

    // 2. Invalid shape: is_remote = false but sequencer_ds is Some
    let invalid_local_id = Uuid::new_v4();
    sqlx::query("SAVEPOINT invalid_local")
        .execute(&mut *tx)
        .await
        .unwrap();
    let invalid_local = sqlx::query(
        r#"
        INSERT INTO chat.conversations(
            conversation_id, kind, lifecycle, current_generation,
            current_state_version, next_entry_seq, created_at,
            is_remote, sequencer_ds, sequencer_term
        ) VALUES ($1, 'group', 'active', 0, 0, 2, $2, FALSE, 'did:web:remote.ds', 0)
        "#,
    )
    .bind(invalid_local_id)
    .bind(now)
    .execute(&mut *tx)
    .await;
    assert!(
        invalid_local.is_err(),
        "is_remote=false with non-NULL sequencer_ds must violate conversations_is_remote_shape_check"
    );
    sqlx::query("ROLLBACK TO SAVEPOINT invalid_local")
        .execute(&mut *tx)
        .await
        .unwrap();

    // 3. Invalid shape: is_remote = true but sequencer_ds is NULL
    let invalid_remote_id = Uuid::new_v4();
    sqlx::query("SAVEPOINT invalid_remote")
        .execute(&mut *tx)
        .await
        .unwrap();
    let invalid_remote = sqlx::query(
        r#"
        INSERT INTO chat.conversations(
            conversation_id, kind, lifecycle, current_generation,
            current_state_version, next_entry_seq, created_at,
            is_remote, sequencer_ds, sequencer_term
        ) VALUES ($1, 'group', 'active', 0, 0, 2, $2, TRUE, NULL, 1)
        "#,
    )
    .bind(invalid_remote_id)
    .bind(now)
    .execute(&mut *tx)
    .await;
    assert!(
        invalid_remote.is_err(),
        "is_remote=true with NULL sequencer_ds must violate conversations_is_remote_shape_check"
    );
    sqlx::query("ROLLBACK TO SAVEPOINT invalid_remote")
        .execute(&mut *tx)
        .await
        .unwrap();

    // 4. Valid remote conversation
    let valid_remote_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO chat.conversations(
            conversation_id, kind, lifecycle, current_generation,
            current_state_version, next_entry_seq, created_at,
            is_remote, sequencer_ds, sequencer_term
        ) VALUES ($1, 'group', 'active', 0, 0, 2, $2, TRUE, 'did:web:remote.catbird.blue', 1)
        "#,
    )
    .bind(valid_remote_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .expect("remote conversation head insert must succeed");

    // 5. Participants ds_did validation: valid NULL (local) and valid bare DID (remote)
    let creator_did = format!(
        "did:web:creator{}.example.com",
        &Uuid::new_v4().simple().to_string()[..12]
    );
    let remote_did = format!(
        "did:web:remote{}.example.com",
        &Uuid::new_v4().simple().to_string()[..12]
    );
    let device_id = Uuid::new_v4();
    let transition_id = Uuid::new_v4();
    // Seed principals and device
    sqlx::query("INSERT INTO chat.principals (user_did, created_at) VALUES ($1, $2), ($3, $2)")
        .bind(&creator_did)
        .bind(now)
        .bind(&remote_did)
        .execute(&mut *tx)
        .await
        .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.devices (
            user_did, device_id, device_name, status, dpop_jkt,
            auth_generation, capabilities, created_at, updated_at
        ) VALUES (
            $1, $2, 'test-device', 'active',
            'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE',
            1, chat.protocol_capabilities(), $3, $3
        )
        "#,
    )
    .bind(&creator_did)
    .bind(device_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Local participant (ds_did = None)
    sqlx::query(
        r#"
        INSERT INTO chat.participants (
            participant_period_id, conversation_id, user_did, status, role,
            role_transition_id, role_changed_at, created_by_did, created_by_device_id,
            current_membership, created_at, ds_did
        ) VALUES ($1, $2, $3, 'active', 'admin', $4, $5, $3, $6, TRUE, $5, NULL)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(convo_id)
    .bind(&creator_did)
    .bind(transition_id)
    .bind(now)
    .bind(device_id)
    .execute(&mut *tx)
    .await
    .expect("local participant period insert must succeed");

    // Remote participant (ds_did = Some("did:web:remote.catbird.blue"))
    sqlx::query(
        r#"
        INSERT INTO chat.participants (
            participant_period_id, conversation_id, user_did, status, role,
            role_transition_id, role_changed_at, created_by_did, created_by_device_id,
            invitation_transition_id, invitation_entry_id, invited_at,
            current_membership, created_at, ds_did
        ) VALUES ($1, $2, $3, 'pending', 'member', $4, $5, $6, $7, $4, $8, $5, TRUE, $5, 'did:web:remote.catbird.blue')
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(convo_id)
    .bind(&remote_did)
    .bind(transition_id)
    .bind(now)
    .bind(&creator_did)
    .bind(device_id)
    .bind(Uuid::new_v4())
    .execute(&mut *tx)
    .await
    .expect("remote participant period insert must succeed");

    // Invalid participant ds_did (e.g. not a bare DID with fragment)
    sqlx::query("SAVEPOINT invalid_pdid")
        .execute(&mut *tx)
        .await
        .unwrap();
    let invalid_p_res = sqlx::query(
        r#"
        INSERT INTO chat.participants (
            participant_period_id, conversation_id, user_did, status, role,
            role_transition_id, role_changed_at, created_by_did, created_by_device_id,
            current_membership, created_at, ds_did
        ) VALUES ($1, $2, $3, 'pending', 'member', $4, $5, $3, $6, TRUE, $5, 'did:web:remote#fragment')
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(convo_id)
    .bind(&remote_did)
    .bind(transition_id)
    .bind(now)
    .bind(device_id)
    .execute(&mut *tx)
    .await;
    assert!(
        invalid_p_res.is_err(),
        "invalid ds_did with fragment must violate participants_ds_did_check"
    );
    sqlx::query("ROLLBACK TO SAVEPOINT invalid_pdid")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
}

/// How one source in the remote invitee's world answers: its home's device
/// directory, its PLC document, or its PDS (declaration and device records).
#[cfg(feature = "sim")]
#[derive(Clone, Copy, Debug, Default)]
enum Directory {
    /// Answers as it should: the home vouches for the invitee's device, the
    /// PLC serves its document, the PDS its declaration and device key.
    #[default]
    Vouches,
    /// This status and error, as a closed federation gate (503), a rate limit
    /// (429), a failing source (5xx) or a refusal (403) answers.
    Answers(u16, &'static str),
    /// Nothing answers, as when offline.
    Unreachable,
    /// The source's host does not resolve (a temporary DNS failure).
    Unresolved,
    /// A 200 that is not what was asked: a PLC document naming no PDS, or a
    /// device record whose key is malformed.
    Malformed,
    /// The PDS publishes only a key the home did not vouch for.
    Disowns,
}

/// What the server did in the remote invitee's world: `network` counts every
/// HTTP request and DNS lookup it made there; each source answers as its
/// `Directory` says.
#[cfg(feature = "sim")]
#[derive(Clone, Default)]
struct RemoteHome {
    network: Arc<std::sync::atomic::AtomicUsize>,
    directory: Arc<std::sync::Mutex<Directory>>,
    plc: Arc<std::sync::Mutex<Directory>>,
    pds: Arc<std::sync::Mutex<Directory>>,
}

#[cfg(feature = "sim")]
impl RemoteHome {
    fn network(&self) -> usize {
        self.network.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn answer(&self, directory: Directory) {
        *self.directory.lock().unwrap() = directory;
    }

    fn plc_answers(&self, plc: Directory) {
        *self.plc.lock().unwrap() = plc;
    }

    fn pds_answers(&self, pds: Directory) {
        *self.pds.lock().unwrap() = pds;
    }
}

#[cfg(feature = "sim")]
fn local_actor_world(actor_did: &str) -> Arc<catbird_server::sim_hooks::SimDsHooks> {
    use catbird_server::sim_hooks::{SimDsHooks, SimHttpRequest};
    use p256::pkcs8::{EncodePrivateKey as _, LineEnding};
    use std::{future::Future, pin::Pin};
    type Reply = Pin<Box<dyn Future<Output = Result<::http::Response<Vec<u8>>, String>> + Send>>;

    let did = actor_did.to_owned();
    let transport = move |request: SimHttpRequest| -> Reply {
        let repo = request
            .url
            .query_pairs()
            .find(|(name, _)| name == "repo")
            .map(|(_, value)| value.into_owned());
        let answer = (request.url.host_str() == Some("pds.local.example.net")
            && request.url.path() == "/xrpc/com.atproto.repo.getRecord"
            && repo.as_deref() == Some(did.as_str()))
        .then(|| {
            json!({
                "uri": format!("at://{did}/blue.catbird.chat.declaration/self"),
                "value": {
                    "$type": "blue.catbird.chat.declaration",
                    "protocolVersion": "1",
                    "createdAt": "2026-07-15T12:00:00Z",
                    "allowIncoming": "all",
                    "deliveryService": SELF_DS_DID,
                },
            })
        });
        Box::pin(async move {
            let body = answer.ok_or_else(|| "unreachable".to_owned())?;
            ::http::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(body.to_string().into_bytes())
                .map_err(|error| error.to_string())
        })
    };
    Arc::new(SimDsHooks {
        service_did: SELF_DS_DID.to_owned(),
        self_endpoint: EXTERNAL_BASE.to_owned(),
        signing_key_pem: Some(
            random_p256()
                .to_pkcs8_pem(LineEnding::LF)
                .unwrap()
                .to_string(),
        ),
        group_relay_hmac_secret: None,
        http_transport: Arc::new(transport),
        dns_resolver: Arc::new(|_| Ok(vec!["93.184.216.34".parse().unwrap()])),
        retain_application_ciphertext: false,
    })
}

/// The remote invitee's world through the sim transport: its home DS
/// (`remote.example.net`, the endpoint the allowlisted peer's `did:web`
/// document names) vouches for one device; the invitee's PLC document names a
/// PDS publishing its declaration (delivery service: the peer) and that
/// device's key. Every other request is unreachable, as when offline.
#[cfg(feature = "sim")]
fn remote_invitee_world(
    invitee_did: &str,
    device_id: Uuid,
    signing_public_key: [u8; 32],
    home: &RemoteHome,
) -> Arc<catbird_server::sim_hooks::SimDsHooks> {
    use catbird_server::sim_hooks::{SimDsHooks, SimHttpRequest};
    use p256::pkcs8::{EncodePrivateKey as _, LineEnding};
    use std::sync::atomic::Ordering;
    use std::{future::Future, pin::Pin};
    type Reply = Pin<Box<dyn Future<Output = Result<::http::Response<Vec<u8>>, String>> + Send>>;

    let did = invitee_did.to_owned();
    let devices = json!({"devices": [{
        "userDid": invitee_did,
        "deviceId": device_id,
        "keyId": ed25519_key_id(&signing_public_key).unwrap().as_str(),
        "authGeneration": 1,
        "signingPublicKey": signing_public_key.to_vec(),
    }]});
    let document = json!({
        "id": invitee_did,
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": "https://pds.remote.example.net",
        }],
    });
    let peer_document = json!({
        "id": PEER_DS_DID,
        "service": [{
            "id": "#atproto_mls",
            "type": "AtprotoMLSDeliveryService",
            "serviceEndpoint": "https://remote.example.net",
        }],
    });
    let declaration = json!({
        "uri": format!("at://{invitee_did}/blue.catbird.chat.declaration/self"),
        "value": {
            "$type": "blue.catbird.chat.declaration",
            "protocolVersion": "1",
            "createdAt": "2026-07-15T12:00:00Z",
            "allowIncoming": "all",
            "deliveryService": PEER_DS_DID,
        },
    });
    let key_record = |key: &[u8]| {
        json!({"records": [{"value": {
            "mlsSignaturePublicKey": {"$bytes": STANDARD.encode(key)},
            "algorithm": "ed25519",
            "createdAt": "2026-07-15T12:00:00Z",
        }}]})
    };
    let (records, malformed, foreign) = (
        key_record(&signing_public_key),
        key_record(&signing_public_key[..31]),
        key_record(&[0x5c; 32]),
    );
    let failure =
        |status: u16, error: &str| Some((status, json!({"error": error, "message": error})));
    let (network, directory, plc, pds) = (
        home.network.clone(),
        home.directory.clone(),
        home.plc.clone(),
        home.pds.clone(),
    );
    let transport = move |request: SimHttpRequest| -> Reply {
        network.fetch_add(1, Ordering::SeqCst);
        let query = |key: &str| {
            request
                .url
                .query_pairs()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.into_owned())
        };
        let (repo, collection) = (query("repo"), query("collection"));
        let user = serde_json::from_slice::<Value>(&request.body)
            .ok()
            .and_then(|body| body["userDid"].as_str().map(str::to_owned));
        let answer = match (
            request.url.host_str().unwrap_or_default(),
            request.url.path(),
        ) {
            ("plc.directory", path) if path.strip_prefix('/') == Some(did.as_str()) => {
                match *plc.lock().unwrap() {
                    Directory::Vouches => Some((200, document.clone())),
                    Directory::Answers(status, error) => failure(status, error),
                    Directory::Malformed | Directory::Disowns => Some((200, json!({ "id": did }))),
                    Directory::Unreachable | Directory::Unresolved => None,
                }
            }
            ("remote.catbird.blue", /* did-web-test */ "/.well-known/did.json") => {
                Some((200, peer_document.clone()))
            }
            ("remote.example.net", "/xrpc/blue.catbird.mlsDS.resolveGroupDevices")
                if user.as_deref() == Some(did.as_str()) =>
            {
                match *directory.lock().unwrap() {
                    Directory::Vouches | Directory::Malformed | Directory::Disowns => {
                        Some((200, devices.clone()))
                    }
                    Directory::Answers(status, error) => failure(status, error),
                    Directory::Unreachable | Directory::Unresolved => None,
                }
            }
            ("pds.remote.example.net", path) if repo.as_deref() == Some(did.as_str()) => {
                match (*pds.lock().unwrap(), path, collection.as_deref()) {
                    (Directory::Answers(status, error), ..) => failure(status, error),
                    (Directory::Unreachable | Directory::Unresolved, ..) => None,
                    (
                        _,
                        "/xrpc/com.atproto.repo.getRecord",
                        Some("blue.catbird.chat.declaration"),
                    ) => Some((200, declaration.clone())),
                    (Directory::Vouches, "/xrpc/com.atproto.repo.listRecords", _) => {
                        Some((200, records.clone()))
                    }
                    (Directory::Malformed, "/xrpc/com.atproto.repo.listRecords", _) => {
                        Some((200, malformed.clone()))
                    }
                    (Directory::Disowns, "/xrpc/com.atproto.repo.listRecords", _) => {
                        Some((200, foreign.clone()))
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        Box::pin(async move {
            let (status, body) = answer.ok_or_else(|| "unreachable".to_owned())?;
            ::http::Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(body.to_string().into_bytes())
                .map_err(|error| error.to_string())
        })
    };
    let lookups = home.network.clone();
    let hosts = [
        ("remote.example.net", home.directory.clone()),
        ("plc.directory", home.plc.clone()),
        ("pds.remote.example.net", home.pds.clone()),
    ];
    Arc::new(SimDsHooks {
        service_did: "did:web:chat.catbird.blue".to_owned(),
        self_endpoint: EXTERNAL_BASE.to_owned(),
        signing_key_pem: Some(
            random_p256()
                .to_pkcs8_pem(LineEnding::LF)
                .unwrap()
                .to_string(),
        ),
        group_relay_hmac_secret: None,
        http_transport: Arc::new(transport),
        dns_resolver: Arc::new(move |host: &str| -> Result<Vec<std::net::IpAddr>, String> {
            lookups.fetch_add(1, Ordering::SeqCst);
            match hosts.iter().find(|(name, _)| *name == host) {
                Some((_, source)) if matches!(*source.lock().unwrap(), Directory::Unresolved) => {
                    Err("SERVFAIL".to_owned())
                }
                _ => Ok(vec!["93.184.216.34".parse().unwrap()]),
            }
        }),
        retain_application_ciphertext: false,
    })
}

// =============================================================================
// Remote members and the federation gate
// =============================================================================

/// The federation gate (kill switch, runtime mode) is process-global: every
/// test here that closes it or reaches a peer holds this lock.
static FEDERATION_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const KILL_SWITCH: &str = "FEDERATION_EMERGENCY_KILL_SWITCH";
const SELF_DS_DID: &str = "did:web:chat.catbird.blue";
const PEER_DS_DID: &str = "did:web:remote.catbird.blue";

/// Close the gate one of its two ways: the runtime mode `off`, or the
/// emergency kill switch over an open mode.
fn close_federation(kill_switch: bool) {
    use catbird_server::federation::FederationMode;
    if kill_switch {
        std::env::set_var(KILL_SWITCH, "1");
        FederationMode::set_runtime_override(Some(FederationMode::Allowlist));
    } else {
        std::env::remove_var(KILL_SWITCH);
        FederationMode::set_runtime_override(Some(FederationMode::Off));
    }
}

fn open_federation() {
    std::env::remove_var(KILL_SWITCH);
    catbird_server::federation::open_federation_for_test();
}

/// Status, `Retry-After` and JSON body.
async fn send_answer(
    router: Router,
    request: Request<Body>,
) -> (StatusCode, Option<String>, Value) {
    let response = router.oneshot(request).await.expect("router response");
    let status = response.status();
    let retry_after = response
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("collect response body");
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, retry_after, body)
}

/// The endpoint's declared retryable answer: nothing was decided, retry in 5 s.
fn assert_retryable(answer: &(StatusCode, Option<String>, Value), attempt: &str) {
    assert_eq!(
        (answer.0, answer.1.as_deref(), answer.2["error"].as_str()),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Some("5"),
            Some("RelationshipPolicyUnavailable")
        ),
        "{attempt}: {}",
        answer.2
    );
}

/// A refusal: `NotAuthorized`, nothing to retry.
#[cfg(feature = "sim")]
fn assert_refused(answer: &(StatusCode, Option<String>, Value), attempt: &str) {
    assert_eq!(
        (answer.0, answer.1.as_deref(), answer.2["error"].as_str()),
        (StatusCode::UNAUTHORIZED, None, Some("NotAuthorized")),
        "{attempt}: {}",
        answer.2
    );
}

/// A source that could not answer now.
#[cfg(feature = "sim")]
const OUTAGES: [(Directory, &str); 4] = [
    (
        Directory::Answers(503, "ServiceUnavailable"),
        "answering 503",
    ),
    (
        Directory::Answers(429, "RateLimitExceeded"),
        "answering 429",
    ),
    (Directory::Unreachable, "unreachable"),
    (Directory::Unresolved, "its host not resolving"),
];

/// One digest per durable table except the replay caches that consume each
/// request's access-token jti and DPoP proof (every attempt presents fresh ones).
async fn durable_rows(pool: &DbPool) -> BTreeMap<String, String> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT format('%I.%I', table_schema, table_name) FROM information_schema.tables \
          WHERE table_type = 'BASE TABLE' AND table_schema IN ('chat', 'public') \
            AND (table_schema, table_name) NOT IN \
                (('chat', 'service_auth_admissions'), ('chat', 'dpop_replays'), \
                 ('public', 'auth_jti_nonce')) \
          ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .expect("list durable tables");
    let mut rows = BTreeMap::new();
    for table in tables {
        let digest: String = sqlx::query_scalar(&format!(
            "SELECT md5(coalesce(string_agg(to_jsonb(t)::text, ',' ORDER BY to_jsonb(t)::text), '')) \
               FROM {table} t"
        ))
        .fetch_one(pool)
        .await
        .expect("digest durable table");
        rows.insert(table, digest);
    }
    rows
}

/// The durable tables whose rows differ from `before`.
async fn changed_tables(pool: &DbPool, before: &BTreeMap<String, String>) -> Vec<String> {
    durable_rows(pool)
        .await
        .into_iter()
        .filter(|(table, digest)| before.get(table) != Some(digest))
        .map(|(table, _)| table)
        .collect()
}

async fn assert_nothing_persisted(pool: &DbPool, before: &BTreeMap<String, String>, attempt: &str) {
    let changed = changed_tables(pool, before).await;
    assert!(
        changed.is_empty(),
        "{attempt} persisted rows in {changed:?}"
    );
}

/// Every insert into `table` fails, as this store failing mid-transaction
/// would; `heal_inserts` undoes it.
#[cfg(feature = "sim")]
async fn break_inserts(pool: &DbPool, table: &str) {
    sqlx::query(
        "CREATE OR REPLACE FUNCTION public.injected_store_failure() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected store failure'; END $$",
    )
    .execute(pool)
    .await
    .expect("create the store-failure trigger function");
    sqlx::query(&format!(
        "CREATE TRIGGER injected_store_failure BEFORE INSERT ON {table} \
         FOR EACH ROW EXECUTE FUNCTION public.injected_store_failure()"
    ))
    .execute(pool)
    .await
    .expect("fail inserts");
}

#[cfg(feature = "sim")]
async fn heal_inserts(pool: &DbPool, table: &str) {
    sqlx::query(&format!("DROP TRIGGER injected_store_failure ON {table}"))
        .execute(pool)
        .await
        .expect("heal inserts");
}

async fn allowlist(pool: &DbPool, ds_did: &str) {
    ensure_federation_peers_table(pool).await;
    sqlx::query(
        r#"
        INSERT INTO federation_peers (
            ds_did, status, max_requests_per_minute, trust_score,
            rejected_request_count, invalid_token_count, created_at, updated_at
        ) VALUES ($1, 'allow', 100, 100, 0, 0, now(), now())
        ON CONFLICT (ds_did) DO UPDATE SET status = 'allow'
        "#,
    )
    .bind(ds_did)
    .execute(pool)
    .await
    .expect("allowlist peer in federation_peers");
}

/// Cache `did`'s home: this DS, or the allowlisted peer at `remote.example.net`.
async fn cache_home(rt: &ChatRuntime, did: &str, remote: bool) {
    let (ds_did, endpoint) = if remote {
        (PEER_DS_DID, "https://remote.example.net")
    } else {
        (SELF_DS_DID, EXTERNAL_BASE)
    };
    rt.resolver()
        .unwrap()
        .cache_mapping(
            did,
            &catbird_server::federation::resolver::DsEndpoint {
                did: ds_did.to_owned(),
                endpoint: endpoint.to_owned(),
                supported_cipher_suites: None,
                federation_capabilities: None,
            },
        )
        .await
        .unwrap();
}

async fn participant_home(pool: &DbPool, conversation_id: Uuid, did: &str) -> Option<String> {
    sqlx::query_scalar(
        "SELECT ds_did FROM chat.participants WHERE conversation_id = $1 AND user_did = $2",
    )
    .bind(conversation_id)
    .bind(did)
    .fetch_one(pool)
    .await
    .expect("read participant ds_did")
}

/// A home allowlisting `PEER_DS_DID` whose actor created a group, alone,
/// through the real `createConversation`.
struct GroupHome {
    rt: Arc<ChatRuntime>,
    router: Router,
    fixture: CreationTestFixture,
    trusted_at: DateTime<Utc>,
    dpop_key: P256SigningKey,
    dpop_jwk: Value,
    dpop_jkt: String,
}

async fn group_home(pool: &DbPool, rt: Arc<ChatRuntime>) -> GroupHome {
    let trusted_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(pool)
            .await
            .expect("sample timestamp");
    let fixture = build_test_creation_fixture_with_invitee(trusted_at, None);
    create_group(pool, rt, fixture, trusted_at, random_p256()).await
}

async fn create_group(
    pool: &DbPool,
    rt: Arc<ChatRuntime>,
    fixture: CreationTestFixture,
    trusted_at: DateTime<Utc>,
    dpop_key: P256SigningKey,
) -> GroupHome {
    allowlist(pool, PEER_DS_DID).await;
    let dpop_jwk = public_jwk(&dpop_key);
    let dpop_jkt = jwk_thumbprint(&dpop_jwk);
    seed_device_for_creation(
        pool,
        &fixture.actor_did,
        fixture.actor_device_id,
        &fixture.actor_key_id,
        &fixture.actor_ed25519_public_key,
        &dpop_key,
        &dpop_jkt,
    )
    .await;
    cache_home(&rt, &fixture.actor_did, false).await;
    let router = chat_router::<TestState>().with_state(TestState {
        pool: pool.clone(),
        runtime: rt.clone(),
    });
    let home = GroupHome {
        rt,
        router,
        fixture,
        trusted_at,
        dpop_key,
        dpop_jwk,
        dpop_jkt,
    };
    let creation = json!({ "signedRequest": home.fixture.signed_request_json });
    #[cfg(feature = "sim")]
    let (status, bytes) = catbird_server::sim_hooks::scope_sim_ds(
        local_actor_world(&home.fixture.actor_did),
        send_raw(home.router.clone(), home.request(ENDPOINT, creation)),
    )
    .await;
    #[cfg(not(feature = "sim"))]
    let (status, bytes) = send_raw(home.router.clone(), home.request(ENDPOINT, creation)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "createConversation must return 200 OK: {}",
        String::from_utf8_lossy(&bytes)
    );
    home
}

impl GroupHome {
    /// The same actor creating the same group at another home.
    async fn same_group_at(&self, pool: &DbPool, rt: Arc<ChatRuntime>) -> GroupHome {
        create_group(
            pool,
            rt,
            self.fixture.clone(),
            self.trusted_at,
            self.dpop_key.clone(),
        )
        .await
    }

    /// A POST to `nsid` by the actor's device, freshly authenticated.
    fn request(&self, nsid: &str, payload: Value) -> Request<Body> {
        build_authenticated_request_to(
            nsid,
            &self.fixture.actor_did,
            self.fixture.actor_device_id,
            &self.dpop_key,
            &self.dpop_jwk,
            &self.dpop_jkt,
            payload,
        )
    }

    fn submit(&self, signed: &Value) -> Request<Body> {
        self.request(
            "blue.catbird.chat.submitTransition",
            json!({ "signedRequest": signed }),
        )
    }

    /// The actor's signed policy transition adding `invitee` as a pending member.
    fn policy_add(&self, invitee: &str) -> Value {
        let fixture = &self.fixture;
        let transition_id = Uuid::new_v4().hyphenated().to_string();
        let coordinate = |state_version: u64| {
            json!({
                "conversationId": fixture.cid.hyphenated().to_string(),
                "generation": 0,
                "stateVersion": state_version,
                "groupId": STANDARD.encode(fixture.group_id),
                "epoch": 0,
                "groupContextHash": STANDARD.encode(fixture.group_context_hash),
                "confirmationTag": STANDARD.encode(fixture.confirmation_tag),
                "lifecycle": "active",
            })
        };
        let body = json!({
            "$type": "blue.catbird.chat.defs#policyTransitionBody",
            "signatureDomain": "CATBIRD-CHAT-POLICY\u{0000}",
            "transitionId": &transition_id,
            "actorDid": &fixture.actor_did,
            "actorDeviceId": fixture.actor_device_id.hyphenated().to_string(),
            "keyId": &fixture.actor_key_id,
            "authGeneration": 1,
            "prior": coordinate(0),
            "next": coordinate(1),
            "participantChanges": [{
                "$type": "blue.catbird.chat.defs#addParticipant",
                "userDid": invitee,
                "status": "pending",
                "role": "member",
                "invitationProvenance": {
                    "invitedByDid": &fixture.actor_did,
                    "invitedByDeviceId": fixture.actor_device_id.hyphenated().to_string(),
                    "invitationTransitionId": &transition_id,
                },
            }],
            "idempotencyKey": &transition_id,
            "signedAt": (self.trusted_at - chrono::Duration::milliseconds(500))
                .to_rfc3339_opts(SecondsFormat::Millis, true),
        });
        self.sign(body)
    }

    /// `body` signed by the actor's device key.
    fn sign(&self, body: Value) -> Value {
        let mut wrapper = json!({ "body": body, "signature": STANDARD.encode([0_u8; 64]) });
        let canonical = decode_canonical_signed_mutation(&serde_json::to_vec(&wrapper).unwrap())
            .expect("canonicalize signed body");
        let signature = self
            .fixture
            .actor_ed25519_signing_key
            .sign(canonical.transcript_bytes());
        wrapper["signature"] = json!(STANDARD.encode(signature.to_bytes()));
        wrapper
    }
}

/// `invitee` of the peer home: a principal here, its cached home, and the
/// relationship evidence admitting the actor's pending add.
async fn seed_remote_invitee(pool: &DbPool, home: &GroupHome, invitee: &str) {
    seed_remote_principal(pool, home, invitee).await;
    catbird_server::chat_protocol::test_support::seed_deterministic_pending_add_fallback(
        pool,
        &home.fixture.actor_did,
        vec![home.fixture.actor_did.clone(), invitee.to_owned()],
        vec![invitee.to_owned()],
    )
    .await
    .expect("seed deterministic fallback relationship projection");
}

/// `invitee` of the peer home: a principal here and its cached home.
async fn seed_remote_principal(pool: &DbPool, home: &GroupHome, invitee: &str) {
    sqlx::query(
        "INSERT INTO chat.principals (user_did, created_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(invitee)
    .bind(home.trusted_at)
    .execute(pool)
    .await
    .expect("seed remote invitee principal");
    cache_home(&home.rt, invitee, true).await;
}

#[cfg(feature = "sim")]
#[tokio::test]
async fn test_allowlisted_remote_ds_did_persisted_end_to_end() {
    let _gate = FEDERATION_GATE.lock().await;
    // A home federates with an allowlisted peer only through an open gate, as
    // `FEDERATION_MODE=allowlist` opens it; closed (mode `off`, the default),
    // the invitee home's `resolveGroupDevices` call is refused unsent.
    open_federation();
    // Production runs these handlers on the full catalog (`db::init_db`).
    let database = common::fresh_db::fresh_fully_migrated_db("chat_fedrouting_").await;
    let pool = database.connect(4).await;
    let home = group_home(&pool, runtime(&pool, true).await).await;
    let fixture = &home.fixture;

    // Now add a remote participant via submitTransition (policy transition)
    let remote_invitee_did = random_did();
    seed_remote_invitee(&pool, &home, &remote_invitee_did).await;
    let policy_req = home.submit(&home.policy_add(&remote_invitee_did));

    // Adding a remote member first stages the devices its home vouches for.
    let invitee_device_id = Uuid::new_v4();
    let invitee_key = Ed25519SigningKey::from_bytes(&[0x37; 32])
        .verifying_key()
        .to_bytes();
    let (policy_status, policy_bytes) = catbird_server::sim_hooks::scope_sim_ds(
        remote_invitee_world(
            &remote_invitee_did,
            invitee_device_id,
            invitee_key,
            &RemoteHome::default(),
        ),
        send_raw(home.router.clone(), policy_req),
    )
    .await;
    let policy_text = String::from_utf8_lossy(&policy_bytes);
    assert_eq!(
        policy_status,
        StatusCode::OK,
        "submitTransition policy-add must return 200 OK: {policy_text}"
    );
    let staged: (String, Option<String>, i64, Vec<u8>) = sqlx::query_as(
        "SELECT d.status, d.dpop_jkt, d.auth_generation, k.signing_public_key \
           FROM chat.devices d JOIN chat.device_keys k USING (user_did, device_id) \
          WHERE d.user_did = $1 AND d.device_id = $2",
    )
    .bind(&remote_invitee_did)
    .bind(invitee_device_id)
    .fetch_one(&pool)
    .await
    .expect("read the staged home-vouched invitee device");
    assert_eq!(staged, ("active".to_owned(), None, 1, invitee_key.to_vec()));

    let (is_remote, sequencer_ds, sequencer_term): (bool, Option<String>, i64) = sqlx::query_as(
        "SELECT is_remote, sequencer_ds, sequencer_term FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(fixture.cid)
    .fetch_one(&pool)
    .await
    .expect("read conversation routing");

    assert!(!is_remote, "local creation must have is_remote = false");
    assert!(
        sequencer_ds.is_none(),
        "local creation must have sequencer_ds = NULL"
    );
    assert_eq!(sequencer_term, 0);

    // Verify participant ds_did values
    assert!(
        participant_home(&pool, fixture.cid, &fixture.actor_did)
            .await
            .is_none(),
        "local creator must persist ds_did = NULL"
    );
    assert_eq!(
        participant_home(&pool, fixture.cid, &remote_invitee_did).await,
        Some(PEER_DS_DID.to_owned()),
        "remote invitee must persist allowlisted peer ds_did"
    );
    // Verify getConversations retrieval
    let get_convos_req = build_authenticated_get_request(
        &fixture.actor_did,
        fixture.actor_device_id,
        &home.dpop_key,
        &home.dpop_jwk,
        &home.dpop_jkt,
        "blue.catbird.chat.getConversations",
        &format!(
            "actorDeviceId={}&limit=50",
            fixture.actor_device_id.hyphenated()
        ),
    );
    let (get_status, get_response_bytes) = send_raw(home.router.clone(), get_convos_req).await;
    assert_eq!(get_status, StatusCode::OK);
    let get_body: Value = serde_json::from_slice(&get_response_bytes).unwrap();
    assert_eq!(
        get_body["items"][0]["state"]["coordinates"]["conversationId"],
        fixture.cid.hyphenated().to_string()
    );
}

/// Adding a remote member while the gate is closed (mode `off`, or the kill
/// switch) answers the declared retryable `RelationshipPolicyUnavailable`
/// (503, `Retry-After: 5`) before any DNS lookup or request leaves this home,
/// and persists nothing. A member home whose own gate is closed decided
/// nothing either. Once both are open, the same signed transition adds the
/// member.
#[cfg(feature = "sim")]
#[tokio::test]
async fn closed_federation_gate_answers_a_remote_member_add_retryably_and_unsent() {
    let _gate = FEDERATION_GATE.lock().await;
    let database = common::fresh_db::fresh_fully_migrated_db("chat_fedrouting_").await;
    let pool = database.connect(4).await;
    let home = group_home(&pool, runtime(&pool, true).await).await;
    let invitee = random_did();
    seed_remote_invitee(&pool, &home, &invitee).await;
    let signed = home.policy_add(&invitee);
    let remote = RemoteHome::default();
    let invitee_key = Ed25519SigningKey::from_bytes(&[0x37; 32])
        .verifying_key()
        .to_bytes();
    let world = remote_invitee_world(&invitee, Uuid::new_v4(), invitee_key, &remote);
    let submit = || {
        catbird_server::sim_hooks::scope_sim_ds(
            world.clone(),
            send_answer(home.router.clone(), home.submit(&signed)),
        )
    };

    let before = durable_rows(&pool).await;
    for (kill_switch, attempt) in [(false, "mode off"), (true, "kill switch")] {
        close_federation(kill_switch);
        assert_retryable(&submit().await, attempt);
        assert_eq!(
            remote.network(),
            0,
            "{attempt}: nothing may leave this home"
        );
        assert_nothing_persisted(&pool, &before, attempt).await;
    }
    open_federation();
    remote.answer(Directory::Answers(503, "FederationDisabled"));
    assert_retryable(&submit().await, "member home closed");
    assert!(remote.network() > 0, "an open gate asks the member's home");
    assert_nothing_persisted(&pool, &before, "member home closed").await;

    remote.answer(Directory::Vouches);
    let (status, _, body) = submit().await;
    assert_eq!(status, StatusCode::OK, "reopened: {body}");
    assert_eq!(
        participant_home(&pool, home.fixture.cid, &invitee).await,
        Some(PEER_DS_DID.to_owned())
    );
}

/// A remote member's PLC directory or PDS that cannot answer now decided
/// nothing. With the member's home cached, its PDS cannot list the member's
/// device keys; uncached, its PLC document cannot be fetched. Either way
/// adding the member answers the declared retryable
/// `RelationshipPolicyUnavailable` (503, `Retry-After: 5`) and persists
/// nothing. A malformed device record or PLC document, or a PDS that does not
/// authorize the device the home vouches for, is a refusal (`NotAuthorized`).
/// This store failing while staging the member is a storage failure (500).
/// Once every source answers, the same signed transition adds the member,
/// resolved live to the home its declaration names.
#[cfg(feature = "sim")]
#[tokio::test]
async fn a_remote_member_add_is_retryable_while_its_plc_or_pds_cannot_answer() {
    let _gate = FEDERATION_GATE.lock().await;
    open_federation();
    let database = common::fresh_db::fresh_fully_migrated_db("chat_fedrouting_").await;
    let pool = database.connect(4).await;
    let home = group_home(&pool, runtime(&pool, true).await).await;
    let invitee = random_did();
    seed_remote_invitee(&pool, &home, &invitee).await;
    let signed = home.policy_add(&invitee);
    let remote = RemoteHome::default();
    let invitee_key = Ed25519SigningKey::from_bytes(&[0x3b; 32])
        .verifying_key()
        .to_bytes();
    let world = remote_invitee_world(&invitee, Uuid::new_v4(), invitee_key, &remote);
    let submit = || {
        catbird_server::sim_hooks::scope_sim_ds(
            world.clone(),
            send_answer(home.router.clone(), home.submit(&signed)),
        )
    };

    let before = durable_rows(&pool).await;
    for (outage, how) in OUTAGES {
        remote.pds_answers(outage);
        let (attempt, asked) = (format!("member's PDS {how}"), remote.network());
        assert_retryable(&submit().await, &attempt);
        assert!(remote.network() > asked, "{attempt}: its PDS was asked");
        assert_nothing_persisted(&pool, &before, &attempt).await;
    }
    for (pds, attempt) in [
        (Directory::Malformed, "malformed device record"),
        (Directory::Disowns, "PDS not authorizing the vouched device"),
    ] {
        remote.pds_answers(pds);
        assert_refused(&submit().await, attempt);
        assert_nothing_persisted(&pool, &before, attempt).await;
    }
    remote.pds_answers(Directory::Vouches);
    break_inserts(&pool, "chat.device_keys").await;
    let (status, retry_after, body) = submit().await;
    assert_eq!(
        (status, retry_after, body["error"].as_str()),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            Some("InternalServerError")
        ),
        "this store failing while staging: {body}"
    );
    assert_nothing_persisted(&pool, &before, "this store failing while staging").await;
    heal_inserts(&pool, "chat.device_keys").await;

    home.rt
        .resolver()
        .unwrap()
        .invalidate(&invitee)
        .await
        .expect("forget the member's cached home");
    let before = durable_rows(&pool).await;
    for (outage, how) in OUTAGES {
        remote.plc_answers(outage);
        let (attempt, asked) = (format!("member's PLC {how}"), remote.network());
        assert_retryable(&submit().await, &attempt);
        assert!(remote.network() > asked, "{attempt}: the PLC was asked");
        assert_nothing_persisted(&pool, &before, &attempt).await;
    }
    remote.plc_answers(Directory::Malformed);
    assert_refused(&submit().await, "PLC document naming no PDS");
    assert_nothing_persisted(&pool, &before, "PLC document naming no PDS").await;

    remote.plc_answers(Directory::Vouches);
    let (status, _, body) = submit().await;
    assert_eq!(status, StatusCode::OK, "every source answering: {body}");
    assert_eq!(
        participant_home(&pool, home.fixture.cid, &invitee).await,
        Some(PEER_DS_DID.to_owned()),
        "resolved live to the home its declaration names"
    );
}

/// Three homes: this DS relays its actor's policy add to the group's sequencer
/// (`relayGroupMutation`), which stages the new member's devices from the
/// member's own home, a third one, and looks the member's device keys up at
/// its PDS. While that home cannot answer (its gate closed, 429, 5xx,
/// unreachable, its host not resolving), the member's PDS cannot list its
/// keys, the member's PLC document cannot be fetched (its home not cached at
/// the sequencer), the sequencer's own store fails while staging or
/// sequencing, or the member's relationship sources cannot answer
/// (unreachable, 503, 429), the sequencer decided nothing: it answers 5xx, and
/// this DS answers the declared retryable `RelationshipPolicyUnavailable`
/// (`Retry-After: 5`); neither home persists anything but the device
/// directory the sequencer staged before its store failed. The member home's
/// refusal, a malformed device record or PLC document, or a PDS not
/// authorizing the vouched device stays `NotAuthorized`; an unusable
/// relationship answer stays `InvalidRequest`. Once every source
/// answers, the sequencer resolves the member's home live and sequences the
/// same signed transition under an operation claim bound to its kind, body
/// and signature: another body under that operation, or a fifth kind relayed
/// as a transition, is refused unpersisted, and the identical retry replays
/// the sequenced answer.
#[cfg(feature = "sim")]
#[tokio::test]
async fn a_relayed_add_is_retryable_while_the_new_members_home_cannot_answer() {
    use catbird_server::chat_protocol::error::ChatProtocolErrorCode;
    use catbird_server::chat_protocol::relationship_policy::{
        PublicResponse, SimSourceFault, TransportError,
    };
    use catbird_server::federation::group_relay::{
        group_relay_router, relay_group_mutation_to_sequencer, GroupRelayError, GroupRelayState,
        RelayGroupMutationRequest,
    };
    use catbird_server::federation::resolver::{DsResolver, ValidatedRemoteDestination};
    use catbird_server::sim_hooks::{scope_sim_ds, SimDsHooks, SimHttpRequest};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::{future::Future, pin::Pin};
    type Reply = Pin<Box<dyn Future<Output = Result<::http::Response<Vec<u8>>, String>> + Send>>;
    const SEQ_DS_DID: &str = "did:web:seq.catbird.blue";
    const SEQ_ENDPOINT: &str = "https://seq.example.net";
    const SECRET: &str = "three-home-group-relay-secret";
    let _gate = FEDERATION_GATE.lock().await;
    open_federation();

    // The sequencer holds the group, created there by the actor (participant
    // routing is immutable, so its row keeps the actor local), and admits
    // relays from this allowlisted DS. It collects the new member's
    // relationship evidence live (no fallback is seeded there) from sources
    // that allow everything unless `relationships` says otherwise.
    let seq_database = common::fresh_db::fresh_fully_migrated_db("chat_fedrouting_").await;
    let seq_pool = seq_database.connect(4).await;
    let relationships = SimSourceFault::default();
    ensure_verifier_env(&seq_pool).await;
    std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    let seq_rt = ChatRuntime::from_env(Arc::new(catbird_server::realtime::SseState::new(8)))
        .expect("build clean-chat runtime")
        .with_resolver(Arc::new(DsResolver::new(
            seq_pool.clone(),
            reqwest::Client::new(),
            SELF_DS_DID.to_owned(),
            EXTERNAL_BASE.to_owned(),
            None,
            300,
        )))
        .with_sim_faulty_relationships(relationships.clone())
        .expect("the sequencer's relationship authority");
    let seq = group_home(&seq_pool, Arc::new(seq_rt)).await;
    allowlist(&seq_pool, SELF_DS_DID).await;
    let invitee = random_did();
    seed_remote_principal(&seq_pool, &seq, &invitee).await;
    let member_home = RemoteHome::default();
    let invitee_key = Ed25519SigningKey::from_bytes(&[0x39; 32])
        .verifying_key()
        .to_bytes();
    let world = remote_invitee_world(&invitee, Uuid::new_v4(), invitee_key, &member_home);
    let sequencer = group_relay_router(
        GroupRelayState::for_test(
            seq_pool.clone(),
            SEQ_DS_DID.to_owned(),
            SECRET.as_bytes(),
            None,
        )
        .with_sim_hooks(Arc::new(SimDsHooks {
            service_did: SEQ_DS_DID.to_owned(),
            self_endpoint: SEQ_ENDPOINT.to_owned(),
            signing_key_pem: world.signing_key_pem.clone(),
            group_relay_hmac_secret: Some(SECRET.to_owned()),
            http_transport: world.http_transport.clone(),
            dns_resolver: world.dns_resolver.clone(),
            retain_application_ciphertext: false,
        }))
        .with_relationship_authority_of(&seq.rt),
    );

    // This DS mirrors the group and reaches only the sequencer.
    let database = common::fresh_db::fresh_fully_migrated_db("chat_fedrouting_").await;
    let pool = database.connect(4).await;
    ensure_verifier_env(&pool).await;
    std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    let resolver = DsResolver::new(
        pool.clone(),
        reqwest::Client::new(),
        SELF_DS_DID.to_owned(),
        EXTERNAL_BASE.to_owned(),
        None,
        300,
    )
    .with_destination_resolver_hook(Arc::new(|_| {
        Some(Box::pin(async {
            Ok(ValidatedRemoteDestination {
                url: SEQ_ENDPOINT.parse().unwrap(),
                host: "seq.example.net".to_owned(),
                addrs: vec!["93.184.216.35:443".parse().unwrap()],
            })
        }))
    }));
    let rt = ChatRuntime::from_env(Arc::new(catbird_server::realtime::SseState::new(8)))
        .expect("build clean-chat runtime")
        .with_resolver(Arc::new(resolver));
    let home = seq.same_group_at(&pool, Arc::new(rt)).await;
    sqlx::query(
        "UPDATE chat.conversations SET is_remote = TRUE, sequencer_ds = $2, sequencer_term = 1 \
          WHERE conversation_id = $1",
    )
    .bind(home.fixture.cid)
    .bind(SEQ_DS_DID)
    .execute(&pool)
    .await
    .expect("mirror the sequencer's group");
    let relays = Arc::new(AtomicUsize::new(0));
    let counted = relays.clone();
    let hooks = Arc::new(SimDsHooks {
        service_did: SELF_DS_DID.to_owned(),
        self_endpoint: EXTERNAL_BASE.to_owned(),
        signing_key_pem: None,
        group_relay_hmac_secret: Some(SECRET.to_owned()),
        http_transport: Arc::new(move |request: SimHttpRequest| -> Reply {
            counted.fetch_add(1, SeqCst);
            let sequencer = sequencer.clone();
            Box::pin(async move {
                if request.url.host_str() != Some("seq.example.net") {
                    return Err("unreachable".to_owned());
                }
                let mut relayed = Request::new(Body::from(request.body));
                *relayed.method_mut() = request.method;
                *relayed.uri_mut() = request.url.path().parse().unwrap();
                *relayed.headers_mut() = request.headers;
                let (parts, body) = sequencer.oneshot(relayed).await.unwrap().into_parts();
                let body = axum::body::to_bytes(body, usize::MAX)
                    .await
                    .map_err(|error| error.to_string())?;
                Ok(::http::Response::from_parts(parts, body.to_vec()))
            })
        }),
        dns_resolver: Arc::new(|host: &str| Err(format!("{host} is not resolved here"))),
        retain_application_ciphertext: false,
    });
    let signed = home.policy_add(&invitee);
    let submit = || {
        scope_sim_ds(
            hooks.clone(),
            send_answer(home.router.clone(), home.submit(&signed)),
        )
    };

    let (before, seq_before) = (durable_rows(&pool).await, durable_rows(&seq_pool).await);
    for (directory, attempt) in [
        (
            Directory::Answers(503, "FederationDisabled"),
            "member home's gate closed",
        ),
        (
            Directory::Answers(429, "RateLimited"),
            "member home rate limited",
        ),
        (Directory::Answers(502, "BadGateway"), "member home failing"),
        (Directory::Unreachable, "member home unreachable"),
        (Directory::Unresolved, "member home's host not resolving"),
    ] {
        member_home.answer(directory);
        let (relayed, asked) = (relays.load(SeqCst), member_home.network());
        assert_retryable(&submit().await, attempt);
        assert_eq!(relays.load(SeqCst), relayed + 1, "{attempt}: relayed once");
        assert!(
            member_home.network() > asked,
            "{attempt}: the sequencer asked the member's home"
        );
        assert_nothing_persisted(&pool, &before, attempt).await;
        assert_nothing_persisted(&seq_pool, &seq_before, attempt).await;
    }
    member_home.answer(Directory::Answers(403, "NotAuthorized"));
    let (status, retry_after, body) = submit().await;
    assert_eq!(
        (status, retry_after, body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, None, Some("NotAuthorized")),
        "member home refusal: {body}"
    );
    assert_nothing_persisted(&pool, &before, "member home refusal").await;
    assert_nothing_persisted(&seq_pool, &seq_before, "member home refusal").await;

    // The sequencer's own lookups of the new member: its PDS's device keys
    // while the member's home is cached there, then its PLC document.
    member_home.answer(Directory::Vouches);
    for (outage, how) in OUTAGES {
        member_home.pds_answers(outage);
        let attempt = format!("new member's PDS {how}");
        let (relayed, asked) = (relays.load(SeqCst), member_home.network());
        assert_retryable(&submit().await, &attempt);
        assert_eq!(relays.load(SeqCst), relayed + 1, "{attempt}: relayed once");
        assert!(
            member_home.network() > asked,
            "{attempt}: the sequencer asked the member's PDS"
        );
        assert_nothing_persisted(&pool, &before, &attempt).await;
        assert_nothing_persisted(&seq_pool, &seq_before, &attempt).await;
    }
    for (pds, attempt) in [
        (Directory::Malformed, "new member's malformed device record"),
        (
            Directory::Disowns,
            "new member's PDS not authorizing the vouched device",
        ),
    ] {
        member_home.pds_answers(pds);
        assert_refused(&submit().await, attempt);
        assert_nothing_persisted(&pool, &before, attempt).await;
        assert_nothing_persisted(&seq_pool, &seq_before, attempt).await;
    }
    member_home.pds_answers(Directory::Vouches);

    // The sequencer's own store failing, while it stages the new member or
    // while it sequences the transition, decided nothing either.
    let attempt = "sequencer store failing while staging";
    break_inserts(&seq_pool, "chat.device_keys").await;
    assert_retryable(&submit().await, attempt);
    assert_nothing_persisted(&pool, &before, attempt).await;
    assert_nothing_persisted(&seq_pool, &seq_before, attempt).await;
    heal_inserts(&seq_pool, "chat.device_keys").await;
    let attempt = "sequencer store failing while sequencing";
    break_inserts(&seq_pool, "chat.operation_claims").await;
    assert_retryable(&submit().await, attempt);
    assert_nothing_persisted(&pool, &before, attempt).await;
    assert_eq!(
        changed_tables(&seq_pool, &seq_before).await,
        ["chat.device_keys", "chat.devices"],
        "{attempt}: only the vouched device, staged before sequencing, persists"
    );
    heal_inserts(&seq_pool, "chat.operation_claims").await;
    // A store failure deep in executing the transition (its entry append, a
    // delivery write) is the same: never the envelope's refusal.
    let attempt = "sequencer store failing while appending the transition's entry";
    let seq_staged = durable_rows(&seq_pool).await;
    break_inserts(&seq_pool, "chat.entries").await;
    assert_retryable(&submit().await, attempt);
    assert_nothing_persisted(&pool, &before, attempt).await;
    assert_nothing_persisted(&seq_pool, &seq_staged, attempt).await;
    heal_inserts(&seq_pool, "chat.entries").await;

    // The new member's relationship evidence, collected live at the
    // sequencer: a source that could not answer now decided nothing; one that
    // answers with an unusable document is the local transition's refusal,
    // `BlockedRelationship`, never `InvalidRequest`.
    let seq_before = durable_rows(&seq_pool).await;
    for (answer, how) in [
        (Err(TransportError::Network), "unreachable"),
        (Ok(PublicResponse::new(503, Vec::new())), "answering 503"),
        (Ok(PublicResponse::new(429, Vec::new())), "answering 429"),
    ] {
        *relationships.lock().unwrap() = Some(answer);
        let attempt = format!("new member's relationship source {how}");
        let relayed = relays.load(SeqCst);
        assert_retryable(&submit().await, &attempt);
        assert_eq!(relays.load(SeqCst), relayed + 1, "{attempt}: relayed once");
        assert_nothing_persisted(&pool, &before, &attempt).await;
        assert_nothing_persisted(&seq_pool, &seq_before, &attempt).await;
    }
    *relationships.lock().unwrap() = Some(Ok(PublicResponse::new(404, Vec::new())));
    let attempt = "new member's DID document unknown to its relationship source";
    let (status, retry_after, body) = submit().await;
    assert_eq!(
        (status, retry_after, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, None, Some("BlockedRelationship")),
        "{attempt}: {body}"
    );
    assert_nothing_persisted(&pool, &before, attempt).await;
    assert_nothing_persisted(&seq_pool, &seq_before, attempt).await;
    *relationships.lock().unwrap() = None;

    seq.rt
        .resolver()
        .unwrap()
        .invalidate(&invitee)
        .await
        .expect("forget the new member's home at the sequencer");
    let seq_before = durable_rows(&seq_pool).await;
    for (outage, how) in OUTAGES {
        member_home.plc_answers(outage);
        let attempt = format!("new member's PLC {how}");
        let (relayed, asked) = (relays.load(SeqCst), member_home.network());
        assert_retryable(&submit().await, &attempt);
        assert_eq!(relays.load(SeqCst), relayed + 1, "{attempt}: relayed once");
        assert!(
            member_home.network() > asked,
            "{attempt}: the sequencer asked the PLC"
        );
        assert_nothing_persisted(&pool, &before, &attempt).await;
        assert_nothing_persisted(&seq_pool, &seq_before, &attempt).await;
    }
    let attempt = "new member's PLC document naming no PDS";
    member_home.plc_answers(Directory::Malformed);
    assert_refused(&submit().await, attempt);
    assert_nothing_persisted(&pool, &before, attempt).await;
    assert_nothing_persisted(&seq_pool, &seq_before, attempt).await;
    member_home.plc_answers(Directory::Vouches);

    member_home.answer(Directory::Vouches);
    let (status, _, sequenced) = submit().await;
    assert_eq!(status, StatusCode::OK, "member home answering: {sequenced}");
    assert_eq!(
        participant_home(&seq_pool, seq.fixture.cid, &invitee).await,
        Some(PEER_DS_DID.to_owned()),
        "the sequencer routes the new member to its home"
    );

    // The sequencer's claim binds the operation to this request's kind, body
    // and signature.
    let operation_id = Uuid::parse_str(signed["body"]["transitionId"].as_str().unwrap()).unwrap();
    let request = serde_json::to_vec(&signed).unwrap();
    let claim: (String, String, String, Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT mutation_kind, endpoint_nsid, principal_did, request_digest, \
                accepted_request_sha256, signature \
           FROM chat.operation_claims WHERE operation_id = $1",
    )
    .bind(operation_id)
    .fetch_one(&seq_pool)
    .await
    .expect("the sequencer's operation claim");
    assert_eq!(
        claim,
        (
            "blue.catbird.chat.defs#policyTransitionBody".to_owned(),
            "blue.catbird.chat.submitTransition".to_owned(),
            home.fixture.actor_did.clone(),
            decode_canonical_signed_mutation(&request)
                .unwrap()
                .request_digest()
                .to_vec(),
            Sha256::digest(&request).to_vec(),
            STANDARD
                .decode(signed["signature"].as_str().unwrap())
                .unwrap(),
        )
    );

    // Another body under that operation, or a fifth kind relayed as a
    // transition, is refused and changes nothing.
    let (before, seq_before) = (durable_rows(&pool).await, durable_rows(&seq_pool).await);
    let mut body = signed["body"].clone();
    body["signedAt"] = json!((home.trusted_at - chrono::Duration::milliseconds(400))
        .to_rfc3339_opts(SecondsFormat::Millis, true));
    let conflicting = home.sign(body);
    let (status, retry_after, answer) = scope_sim_ds(
        hooks.clone(),
        send_answer(home.router.clone(), home.submit(&conflicting)),
    )
    .await;
    assert_eq!(
        (status, retry_after, answer["error"].as_str()),
        (StatusCode::BAD_REQUEST, None, Some("InvalidRequest")),
        "another body under the operation: {answer}"
    );
    let creation = scope_sim_ds(
        hooks.clone(),
        relay_group_mutation_to_sequencer(
            SEQ_ENDPOINT,
            SELF_DS_DID,
            SEQ_DS_DID,
            SECRET.as_bytes(),
            &RelayGroupMutationRequest {
                conversation_id: home.fixture.cid,
                endpoint: "blue.catbird.chat.submitTransition".to_owned(),
                actor_did: home.fixture.actor_did.clone(),
                actor_device_id: home.fixture.actor_device_id,
                signed_request: home.fixture.signed_request_json.clone(),
            },
        ),
    )
    .await;
    assert!(
        matches!(
            creation,
            Err(GroupRelayError::Rejected(
                ChatProtocolErrorCode::InvalidRequest
            ))
        ),
        "a creation relayed as a transition: {creation:?}"
    );
    assert_nothing_persisted(&pool, &before, "refused").await;
    assert_nothing_persisted(&seq_pool, &seq_before, "refused").await;

    let (status, _, replayed) = submit().await;
    assert_eq!(
        (status, &replayed),
        (StatusCode::OK, &sequenced),
        "the identical retry replays the sequenced answer"
    );
}

/// Creating a conversation with a remote member while the gate is closed
/// answers the declared retryable `RelationshipPolicyUnavailable` (503,
/// `Retry-After: 5`) unsent and persists nothing. Reopened, the same signed
/// creation stages the member's home-vouched device and routes it home.
#[cfg(feature = "sim")]
#[tokio::test]
async fn closed_federation_gate_answers_a_creation_with_a_remote_member_retryably_and_unsent() {
    let _gate = FEDERATION_GATE.lock().await;
    let database = common::fresh_db::fresh_fully_migrated_db("chat_fedrouting_").await;
    let pool = database.connect(4).await;
    allowlist(&pool, PEER_DS_DID).await;
    let trusted_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&pool)
            .await
            .expect("sample timestamp");
    let invitee = random_did();
    let fixture = build_test_creation_fixture(trusted_at, Some(&invitee), "group");
    let dpop_key = random_p256();
    let dpop_jwk = public_jwk(&dpop_key);
    let dpop_jkt = jwk_thumbprint(&dpop_jwk);
    seed_device_for_creation(
        &pool,
        &fixture.actor_did,
        fixture.actor_device_id,
        &fixture.actor_key_id,
        &fixture.actor_ed25519_public_key,
        &dpop_key,
        &dpop_jkt,
    )
    .await;
    let rt = runtime(&pool, true).await;
    cache_home(&rt, &fixture.actor_did, false).await;
    cache_home(&rt, &invitee, true).await;
    catbird_server::chat_protocol::test_support::seed_deterministic_creation_fallback(
        &pool,
        &fixture.actor_did,
        vec![fixture.actor_did.clone(), invitee.clone()],
        vec![invitee.clone()],
        catbird_server::chat_protocol::test_support::AdmissionOperation::Group,
    )
    .await
    .expect("seed relationship fallback");
    let router = chat_router::<TestState>().with_state(TestState {
        pool: pool.clone(),
        runtime: rt,
    });
    let remote = RemoteHome::default();
    let invitee_key = Ed25519SigningKey::from_bytes(&[0x38; 32])
        .verifying_key()
        .to_bytes();
    let world = remote_invitee_world(&invitee, Uuid::new_v4(), invitee_key, &remote);
    let create = || {
        catbird_server::sim_hooks::scope_sim_ds(
            world.clone(),
            send_answer(
                router.clone(),
                build_authenticated_request(
                    &fixture.actor_did,
                    fixture.actor_device_id,
                    &dpop_key,
                    &dpop_jwk,
                    &dpop_jkt,
                    json!({ "signedRequest": fixture.signed_request_json }),
                ),
            ),
        )
    };

    let before = durable_rows(&pool).await;
    for (kill_switch, attempt) in [(false, "mode off"), (true, "kill switch")] {
        close_federation(kill_switch);
        assert_retryable(&create().await, attempt);
        assert_eq!(
            remote.network(),
            0,
            "{attempt}: nothing may leave this home"
        );
        assert_nothing_persisted(&pool, &before, attempt).await;
    }
    open_federation();
    let (status, _, body) = create().await;
    assert_eq!(status, StatusCode::OK, "reopened: {body}");
    assert_eq!(
        participant_home(&pool, fixture.cid, &invitee).await,
        Some(PEER_DS_DID.to_owned())
    );
}

/// A transition on a group sequenced elsewhere is forwarded to its sequencer
/// (`submitCommit`). While the gate is closed (mode `off`, or the kill switch)
/// the forward is refused before the sequencer is even resolved: the declared
/// retryable `RelationshipPolicyUnavailable` (503, `Retry-After: 5`), nothing
/// sent, nothing persisted. Reopened, the same signed transition reaches the
/// sequencer: its own closed gate (503) decided nothing, and its refusal (403)
/// stays `NotAuthorized`.
#[tokio::test]
async fn closed_federation_gate_answers_a_forwarded_transition_retryably_and_unsent() {
    use p256::pkcs8::{EncodePrivateKey as _, LineEnding};
    use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering::SeqCst};
    let _gate = FEDERATION_GATE.lock().await;
    let database = common::fresh_db::fresh_fully_migrated_db("chat_fedrouting_").await;
    let pool = database.connect(4).await;

    // The sequencer: a loopback peer answering every call with `answer`.
    let (hits, answer) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicU16::new(503)));
    let sequencer = Router::new().fallback({
        let (hits, answer) = (hits.clone(), answer.clone());
        move || {
            hits.fetch_add(1, SeqCst);
            let status = answer.load(SeqCst);
            async move {
                let error = if status == 503 {
                    "FederationDisabled"
                } else {
                    "UnauthorizedParticipantDs"
                };
                (
                    StatusCode::from_u16(status).unwrap(),
                    axum::Json(json!({ "error": error, "message": error })),
                )
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, sequencer).await;
    });
    let resolutions = Arc::new(AtomicUsize::new(0));
    let counted = resolutions.clone();
    let resolver = Arc::new(
        catbird_server::federation::resolver::DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            SELF_DS_DID.to_owned(),
            EXTERNAL_BASE.to_owned(),
            None,
            300,
        )
        .with_destination_resolver_hook(Arc::new(move |_endpoint| {
            counted.fetch_add(1, SeqCst);
            Some(Box::pin(async move {
                Ok(
                    catbird_server::federation::resolver::ValidatedRemoteDestination {
                        url: url::Url::parse(&format!("http://{addr}")).unwrap(),
                        host: "127.0.0.1".to_owned(),
                        addrs: vec![addr],
                    },
                )
            }))
        })),
    );
    let service_auth = catbird_server::federation::service_auth::ServiceAuthClient::from_es256_pem(
        SELF_DS_DID.to_owned(),
        random_p256()
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .as_bytes(),
        None,
    )
    .unwrap();
    let submitter = catbird_server::federation::commit_submitter::RemoteCommitSubmitter::new(
        resolver.clone(),
        Arc::new(catbird_server::federation::outbound::OutboundClient::new(
            2, 2,
        )),
        Arc::new(service_auth),
        catbird_server::auth::AuthMiddleware::new(),
    );
    ensure_verifier_env(&pool).await;
    std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    let rt = Arc::new(
        ChatRuntime::from_env(Arc::new(catbird_server::realtime::SseState::new(8)))
            .expect("build clean-chat runtime")
            .with_resolver(resolver)
            .with_commit_submitter(Arc::new(submitter)),
    );
    let home = group_home(&pool, rt).await;
    // The group's sequencing moved to the peer: this home now holds a mirror.
    sqlx::query(
        "UPDATE chat.conversations SET is_remote = TRUE, sequencer_ds = $2, sequencer_term = 1 \
          WHERE conversation_id = $1",
    )
    .bind(home.fixture.cid)
    .bind(PEER_DS_DID)
    .execute(&pool)
    .await
    .expect("hand the group's sequencing to the peer");
    // A local invitee: nothing is staged, so only the forward federates.
    let invitee = random_did();
    cache_home(&home.rt, &invitee, false).await;
    let signed = home.policy_add(&invitee);
    let submit = || send_answer(home.router.clone(), home.submit(&signed));
    let calls = || (resolutions.load(SeqCst), hits.load(SeqCst));

    let before = durable_rows(&pool).await;
    for (kill_switch, attempt) in [(false, "mode off"), (true, "kill switch")] {
        close_federation(kill_switch);
        assert_retryable(&submit().await, attempt);
        assert_eq!(calls(), (0, 0), "{attempt}: sequencer resolved or called");
        assert_nothing_persisted(&pool, &before, attempt).await;
    }
    open_federation();
    assert_retryable(&submit().await, "sequencer gate closed");
    assert_eq!(
        calls(),
        (1, 1),
        "the reopened gate forwards the same transition"
    );
    assert_nothing_persisted(&pool, &before, "sequencer gate closed").await;

    answer.store(403, SeqCst);
    let (status, retry_after, body) = submit().await;
    assert_eq!(
        (status, retry_after, body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, None, Some("NotAuthorized")),
        "sequencer refusal: {body}"
    );
    assert_eq!(calls(), (2, 2));
    assert_nothing_persisted(&pool, &before, "sequencer refusal").await;
}

/// A participant home that could not be resolved now decided nothing: the
/// declared retryable `RelationshipPolicyUnavailable` (503, `Retry-After: 5`)
/// and no write. A resolution that refuses outright stays `NotAuthorized`.
#[tokio::test]
async fn unresolved_participant_home_is_retryable_only_while_resolution_cannot_answer() {
    use catbird_server::federation::errors::{FederationError, ResolutionFailureKind};
    use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
    let (pool, _disposable) =
        common::fresh_db::fresh_clean_protocol_db("chat_fedrouting_", 4).await;
    ensure_federation_peers_table(&pool).await;
    let trusted_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&pool)
            .await
            .expect("sample timestamp");
    let invitee = random_did();
    let fixture = build_test_creation_fixture_with_invitee(trusted_at, Some(&invitee));
    let dpop_key = random_p256();
    let dpop_jwk = public_jwk(&dpop_key);
    let dpop_jkt = jwk_thumbprint(&dpop_jwk);
    seed_device_for_creation(
        &pool,
        &fixture.actor_did,
        fixture.actor_device_id,
        &fixture.actor_key_id,
        &fixture.actor_ed25519_public_key,
        &dpop_key,
        &dpop_jkt,
    )
    .await;
    let transient = Arc::new(AtomicBool::new(true));
    let (outage, actor, unresolved) = (
        transient.clone(),
        fixture.actor_did.clone(),
        invitee.clone(),
    );
    let hook: catbird_server::federation::resolver::UserDidResolverFn =
        Arc::new(move |did: &str| {
            if did == actor {
                return Some(Ok(catbird_server::federation::resolver::DsEndpoint {
                    did: SELF_DS_DID.to_owned(),
                    endpoint: EXTERNAL_BASE.to_owned(),
                    supported_cipher_suites: None,
                    federation_capabilities: None,
                }));
            }
            (did == unresolved).then(|| {
                Err(FederationError::ResolutionFailed {
                    did: did.to_owned(),
                    kind: if outage.load(SeqCst) {
                        ResolutionFailureKind::ConnectionFailed("PLC unreachable".into())
                    } else {
                        ResolutionFailureKind::ServiceMissing("no delivery service".into())
                    },
                })
            })
        });
    ensure_verifier_env(&pool).await;
    std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    let resolver = Arc::new(
        catbird_server::federation::resolver::DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            SELF_DS_DID.to_owned(),
            EXTERNAL_BASE.to_owned(),
            None,
            300,
        )
        .with_user_did_resolver_hook(hook),
    );
    let router = chat_router::<TestState>().with_state(TestState {
        pool: pool.clone(),
        runtime: Arc::new(
            ChatRuntime::from_env(Arc::new(catbird_server::realtime::SseState::new(8)))
                .expect("build clean-chat runtime")
                .with_resolver(resolver),
        ),
    });
    let create = || {
        send_answer(
            router.clone(),
            build_authenticated_request(
                &fixture.actor_did,
                fixture.actor_device_id,
                &dpop_key,
                &dpop_jwk,
                &dpop_jkt,
                json!({ "signedRequest": fixture.signed_request_json }),
            ),
        )
    };

    let before = durable_rows(&pool).await;
    assert_retryable(&create().await, "resolution could not answer");
    assert_nothing_persisted(&pool, &before, "resolution could not answer").await;
    transient.store(false, SeqCst);
    let (status, retry_after, body) = create().await;
    assert_eq!(
        (status, retry_after, body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, None, Some("NotAuthorized")),
        "resolution refused: {body}"
    );
    assert_nothing_persisted(&pool, &before, "resolution refused").await;
}

#[tokio::test]
async fn test_resolver_failure_or_untrusted_peer_causes_zero_writes() {
    let (pool, _disposable) =
        common::fresh_db::fresh_clean_protocol_db("chat_fedrouting_", 4).await;
    ensure_federation_peers_table(&pool).await;
    let trusted_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&pool)
            .await
            .expect("sample timestamp");

    let untrusted_peer_did = "did:web:untrusted.hostile.net".to_string();
    let untrusted_invitee_did = random_did();

    let fixture =
        build_test_creation_fixture_with_invitee(trusted_at, Some(&untrusted_invitee_did));
    let dpop_key = random_p256();
    let dpop_jwk = public_jwk(&dpop_key);
    let dpop_jkt = jwk_thumbprint(&dpop_jwk);

    seed_device_for_creation(
        &pool,
        &fixture.actor_did,
        fixture.actor_device_id,
        &fixture.actor_key_id,
        &fixture.actor_ed25519_public_key,
        &dpop_key,
        &dpop_jkt,
    )
    .await;

    let rt = runtime(&pool, true).await;
    let self_did = "did:web:chat.catbird.blue".to_string();

    rt.resolver()
        .unwrap()
        .cache_mapping(
            &fixture.actor_did,
            &catbird_server::federation::resolver::DsEndpoint {
                did: self_did.clone(),
                endpoint: "https://chat.example.net".to_string(),
                supported_cipher_suites: None,
                federation_capabilities: None,
            },
        )
        .await
        .unwrap();

    rt.resolver()
        .unwrap()
        .cache_mapping(
            &untrusted_invitee_did,
            &catbird_server::federation::resolver::DsEndpoint {
                did: untrusted_peer_did.clone(),
                endpoint: "https://untrusted.hostile.net".to_string(),
                supported_cipher_suites: None,
                federation_capabilities: None,
            },
        )
        .await
        .unwrap();

    let router = chat_router::<TestState>().with_state(TestState {
        pool: pool.clone(),
        runtime: rt,
    });

    let payload = json!({
        "signedRequest": fixture.signed_request_json,
    });
    let request = build_authenticated_request(
        &fixture.actor_did,
        fixture.actor_device_id,
        &dpop_key,
        &dpop_jwk,
        &dpop_jkt,
        payload,
    );

    let (status, response_bytes) = send_raw(router, request).await;
    let body_text = String::from_utf8_lossy(&response_bytes);
    println!("Untrusted peer creation response status: {status}, body: {body_text}");
    assert!(
        status.is_client_error() || status.is_server_error(),
        "creation with untrusted peer must return an error status"
    );

    // Verify ZERO writes occurred in the database
    let convos_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.conversations WHERE conversation_id = $1")
            .bind(fixture.cid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(convos_count, 0, "conversations must have zero writes");

    let participants_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.participants WHERE conversation_id = $1")
            .bind(fixture.cid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(participants_count, 0, "participants must have zero writes");

    let idemp_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.idempotency_records WHERE operation_id = $1")
            .bind(fixture.transition_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(idemp_count, 0, "idempotency records must have zero writes");

    let claims_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.operation_claims WHERE operation_id = $1")
            .bind(fixture.transition_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(claims_count, 0, "operation claims must have zero writes");
}

#[tokio::test]
async fn test_routing_drift_after_real_locks_aborts_cleanly() {
    let (pool, _disposable) =
        common::fresh_db::fresh_clean_protocol_db("chat_fedrouting_", 4).await;
    ensure_federation_peers_table(&pool).await;
    let trusted_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&pool)
            .await
            .expect("sample timestamp");
    let invitee_did = random_did();
    let fixture = build_test_creation_fixture_with_invitee(trusted_at, Some(&invitee_did));
    let dpop_key = random_p256();
    let dpop_jwk = public_jwk(&dpop_key);
    let dpop_jkt = jwk_thumbprint(&dpop_jwk);

    seed_device_for_creation(
        &pool,
        &fixture.actor_did,
        fixture.actor_device_id,
        &fixture.actor_key_id,
        &fixture.actor_ed25519_public_key,
        &dpop_key,
        &dpop_jkt,
    )
    .await;
    let mut roster = vec![fixture.actor_did.clone(), invitee_did.clone()];
    roster.sort();
    catbird_server::chat_protocol::test_support::seed_deterministic_creation_fallback(
        &pool,
        &fixture.actor_did,
        roster.clone(),
        vec![invitee_did.clone()],
        catbird_server::chat_protocol::test_support::AdmissionOperation::Direct,
    )
    .await
    .expect("seed relationship fallback");

    let rt = runtime(&pool, true).await;

    let payload = json!({
        "signedRequest": fixture.signed_request_json,
    });
    let request = build_authenticated_request(
        &fixture.actor_did,
        fixture.actor_device_id,
        &dpop_key,
        &dpop_jwk,
        &dpop_jkt,
        payload,
    );

    let (parts, body) = request.into_parts();
    let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();

    // Begin real database transaction and lock operation claim & reservation under real locks
    let mut tx = pool.begin().await.unwrap();

    // Construct a drifted routing intent (omits invitee_did, creating a routing/manifest divergence)
    let mut drifted_routes = BTreeMap::new();
    drifted_routes.insert(fixture.actor_did.clone(), None);
    let drifted_intent = ConversationRoutingIntent::local_creation(drifted_routes);

    // Recheck against drifted intent must detect drift under real database locks
    let drift_err = drifted_intent
        .recheck_manifest_dids(&[fixture.actor_did.clone(), invitee_did.clone()])
        .expect_err("recheck_manifest_dids must reject drifted participant set");
    assert!(matches!(
        drift_err,
        FederationRoutingError::DriftDetected { .. }
    ));

    // Executing repository creation under lock with drifted intent must fail with InvalidCanonicalMaterial
    let creation_err =
        catbird_server::chat_protocol::test_support::execute_creation_with_routing_test(
            &mut tx,
            &pool,
            &rt,
            &parts.headers,
            &body_bytes,
            Some(drifted_intent),
        )
        .await
        .expect_err("creation repository operation with drifted routing must fail");

    assert!(
        creation_err.contains("InvalidCanonicalMaterial"),
        "error must indicate InvalidCanonicalMaterial from drift detection: {creation_err}"
    );
    // Roll back transaction and prove zero database writes occurred
    tx.rollback().await.unwrap();

    let convos_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.conversations WHERE conversation_id = $1")
            .bind(fixture.cid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(convos_count, 0, "conversations must have zero writes");

    let participants_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.participants WHERE conversation_id = $1")
            .bind(fixture.cid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(participants_count, 0, "participants must have zero writes");

    let idemp_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.idempotency_records WHERE operation_id = $1")
            .bind(fixture.transition_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(idemp_count, 0, "idempotency records must have zero writes");

    let claims_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.operation_claims WHERE operation_id = $1")
            .bind(fixture.transition_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(claims_count, 0, "operation claims must have zero writes");
}

#[tokio::test]
async fn test_real_reset_preserves_remote_sequencer_identity_and_term() {
    let (pool, _disposable) =
        common::fresh_db::fresh_clean_protocol_db("chat_fedrouting_", 4).await;
    let mut tx = pool.begin().await.unwrap();
    let convo_id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO chat.conversations(
            conversation_id, kind, lifecycle, current_generation,
            current_state_version, next_entry_seq, created_at,
            is_remote, sequencer_ds, sequencer_term
        ) VALUES ($1, 'group', 'active', 0, 0, 2, $2, TRUE, 'did:web:remote.catbird.blue', 4)
        "#,
    )
    .bind(convo_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .expect("insert initial conversation head");

    // Execute production head CAS advancing generation to 1 across reset
    catbird_server::chat_protocol::test_support::cas_conversation_head_test(
        &mut tx, convo_id, 0, 0, 2, 1, 0, 3,
    )
    .await
    .expect("production reset head CAS must succeed");
    let (is_remote, sequencer_ds, sequencer_term, current_gen, current_sv, next_seq): (
        bool,
        Option<String>,
        i64,
        i64,
        i64,
        i64,
    ) = sqlx::query_as(
        "SELECT is_remote, sequencer_ds, sequencer_term, current_generation, current_state_version, next_entry_seq FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(convo_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();

    assert_eq!(current_gen, 1, "generation must advance to 1");
    assert_eq!(current_sv, 0, "state version must be 0");
    assert_eq!(next_seq, 3, "next_entry_seq must advance to 3");
    assert_eq!(is_remote, true, "is_remote must remain true");
    assert_eq!(
        sequencer_ds,
        Some("did:web:remote.catbird.blue".to_string()),
        "sequencer_ds must be preserved"
    );
    assert_eq!(sequencer_term, 4, "sequencer_term must be preserved");

    // Stale generation CAS must fail with HeadConflict
    let stale_err = catbird_server::chat_protocol::test_support::cas_conversation_head_test(
        &mut tx, convo_id, 0, 0, 2, 2, 0, 4,
    )
    .await
    .expect_err("stale generation head CAS must fail");
    assert!(
        stale_err.contains("CompareAndSetConflict"),
        "stale generation head CAS must fail with CompareAndSetConflict: {stale_err}"
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn test_replay_counting_failing_resolver_proves_zero_calls() {
    // Production runs these handlers on the full catalog (`db::init_db`).
    let database = common::fresh_db::fresh_fully_migrated_db("chat_fedrouting_").await;
    let pool = database.connect(4).await;
    ensure_federation_peers_table(&pool).await;
    let trusted_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&pool)
            .await
            .expect("sample timestamp");
    let fixture = build_test_creation_fixture_with_invitee(trusted_at, None);
    let dpop_key = random_p256();
    let dpop_jwk = public_jwk(&dpop_key);
    let dpop_jkt = jwk_thumbprint(&dpop_jwk);

    seed_device_for_creation(
        &pool,
        &fixture.actor_did,
        fixture.actor_device_id,
        &fixture.actor_key_id,
        &fixture.actor_ed25519_public_key,
        &dpop_key,
        &dpop_jkt,
    )
    .await;

    // Install an observable resolver hook that counts resolution calls and fails on any call after the initial request
    let resolve_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls_clone = resolve_calls.clone();
    let self_did = "did:web:chat.catbird.blue".to_string();
    let hook: catbird_server::federation::resolver::UserDidResolverFn = Arc::new(
        move |user_did: &str| {
            let count = calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if count >= 1 {
                // Fail on any call after the initial participant resolution call
                Some(Err(
                    catbird_server::federation::errors::FederationError::ResolutionFailed {
                        did: user_did.to_string(),
                        kind:
                            catbird_server::federation::errors::ResolutionFailureKind::ConnectionFailed(
                                "injected test resolver failure: resolver must not be called during replay"
                                    .to_string(),
                            ),
                    },
                ))
            } else {
                Some(Ok(catbird_server::federation::resolver::DsEndpoint {
                    did: self_did.clone(),
                    endpoint: "https://chat.example.net".to_string(),
                    supported_cipher_suites: None,
                    federation_capabilities: None,
                }))
            }
        },
    );

    ensure_verifier_env(&pool).await;
    std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    let resolver = Arc::new(
        catbird_server::federation::resolver::DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:chat.catbird.blue".to_string(),
            "https://chat.example.net".to_string(),
            None,
            300,
        )
        .with_user_did_resolver_hook(hook),
    );

    let rt = Arc::new(
        ChatRuntime::from_env(Arc::new(catbird_server::realtime::SseState::new(8)))
            .expect("build clean-chat runtime")
            .with_resolver(resolver),
    );

    let router = chat_router::<TestState>().with_state(TestState {
        pool: pool.clone(),
        runtime: rt.clone(),
    });

    let payload = json!({
        "signedRequest": fixture.signed_request_json,
    });
    let request = build_authenticated_request(
        &fixture.actor_did,
        fixture.actor_device_id,
        &dpop_key,
        &dpop_jwk,
        &dpop_jkt,
        payload.clone(),
    );

    // First request executes creation with normal routing resolution
    let (first_status, first_response_bytes) = send_raw(router.clone(), request).await;
    assert_eq!(
        first_status,
        StatusCode::OK,
        "first request must succeed (200 OK)"
    );
    assert_eq!(
        resolve_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "first request must resolve exactly the 1 participant"
    );

    // On identical replay, preflight_completed_response is advisory and hits the idempotency record,
    // skipping routing resolution entirely.
    let replay_request = build_authenticated_request(
        &fixture.actor_did,
        fixture.actor_device_id,
        &dpop_key,
        &dpop_jwk,
        &dpop_jkt,
        payload,
    );

    let (replay_status, replay_response_bytes) = send_raw(router, replay_request).await;
    assert_eq!(
        replay_status,
        StatusCode::OK,
        "idempotent replay must return 200 OK without calling failing resolver"
    );
    assert_eq!(
        first_response_bytes, replay_response_bytes,
        "idempotent replay must return byte-identical response proving zero side effects"
    );
    assert_eq!(
        resolve_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "replay must make ZERO resolver calls (call count strictly unchanged)"
    );
}

// Compile the actual canonical encoder used by transcript.rs's request-view
// tests. An empty-byte stand-in cannot exercise its round-trip contract.
mod chat_protocol {
    pub(crate) use crate::read_projection;
    pub use catbird_server::chat_protocol::direct_request_transcript;
}
