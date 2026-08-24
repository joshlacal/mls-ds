//! Disposable-DB integration tests for clean-chat federation routing.
//!
//! Covers:
//! 1. Schema constraints and indexes (conversations_is_remote_shape_check, participants_ds_did_check)
//! 2. Allowlisted remote ds_did persisted end-to-end through createConversation handler
//! 3. Resolver failure / untrusted peer returns declared error and causes zero writes
//! 4. Routing drift detection under real database locks aborts cleanly
//! 5. Generation advance across real reset preserves remote sequencer identity and term
//! 6. Replay preflight proves zero resolver calls on idempotent replay

#![allow(dead_code)]

mod common;
pub use catbird_server::{auth, crypto};

#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
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
    blob_store: catbird_server::blob_store::BlobStore,
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

impl FromRef<TestState> for catbird_server::blob_store::BlobStore {
    fn from_ref(state: &TestState) -> catbird_server::blob_store::BlobStore {
        state.blob_store.clone()
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
    chat_router::<TestState>().with_state(TestState {
        pool,
        runtime: rt,
        blob_store: catbird_server::blob_store::BlobStore::for_route_tests(),
    })
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
        "conversationKind": if invitee_did.is_some() { "direct" } else { "group" },
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
                            "role": "member"
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
        service: None,
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
    let now = chrono::Utc::now().timestamp();
    let access_token = sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":format!("{user_did}#atproto")}),
        json!({
            "iss": user_did,
            "sub": user_did,
            "aud": AUDIENCE,
            "lxm": ENDPOINT,
            "iat": now,
            "exp": now + 60,
            "jti": Uuid::new_v4().to_string(),
            "cnf": {"jkt": dpop_jkt},
            "device_id": device_id.to_string(),
            "chat_instance": CHAT_INSTANCE,
        }),
        dpop_signing_key,
    );
    let htu = format!("{EXTERNAL_BASE}/xrpc/{ENDPOINT}");
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
        .uri(xrpc(ENDPOINT))
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

#[tokio::test]
async fn test_allowlisted_remote_ds_did_persisted_end_to_end() {
    let (pool, _disposable) =
        common::fresh_db::fresh_clean_protocol_db("chat_fedrouting_", 4).await;
    ensure_federation_peers_table(&pool).await;
    let trusted_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&pool)
            .await
            .expect("sample timestamp");
    let peer_ds_did = "did:web:remote.catbird.blue".to_string();

    // 1. Allowlist peer DS in federation_peers
    sqlx::query(
        r#"
        INSERT INTO federation_peers (
            ds_did, status, max_requests_per_minute, trust_score,
            rejected_request_count, invalid_token_count, created_at, updated_at
        ) VALUES ($1, 'allow', 100, 100, 0, 0, now(), now())
        ON CONFLICT (ds_did) DO UPDATE SET status = 'allow'
        "#,
    )
    .bind(&peer_ds_did)
    .execute(&pool)
    .await
    .expect("allowlist peer in federation_peers");

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

    let router = chat_router::<TestState>().with_state(TestState {
        pool: pool.clone(),
        runtime: rt.clone(),
        blob_store: catbird_server::blob_store::BlobStore::for_route_tests(),
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

    let (status, response_bytes) = send_raw(router.clone(), request).await;
    let text = String::from_utf8_lossy(&response_bytes);
    assert_eq!(
        status,
        StatusCode::OK,
        "createConversation must return 200 OK: {text}"
    );

    // Now add a remote participant via submitTransition (policy transition)
    let remote_invitee_did = random_did();
    sqlx::query(
        "INSERT INTO chat.principals (user_did, created_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(&remote_invitee_did)
    .bind(trusted_at)
    .execute(&pool)
    .await
    .expect("seed remote invitee principal");

    rt.resolver()
        .unwrap()
        .cache_mapping(
            &remote_invitee_did,
            &catbird_server::federation::resolver::DsEndpoint {
                did: peer_ds_did.clone(),
                endpoint: "https://remote.example.net".to_string(),
                supported_cipher_suites: None,
                federation_capabilities: None,
            },
        )
        .await
        .unwrap();

    let mut roster = vec![fixture.actor_did.clone(), remote_invitee_did.clone()];
    roster.sort();
    catbird_server::chat_protocol::test_support::seed_deterministic_pending_add_fallback(
        &pool,
        &fixture.actor_did,
        roster,
        vec![remote_invitee_did.clone()],
    )
    .await
    .expect("seed deterministic fallback relationship projection");

    let policy_transition_id = Uuid::new_v4();
    let signed_at = (trusted_at - chrono::Duration::milliseconds(500))
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let prior_coordinate = json!({
        "conversationId": fixture.cid.hyphenated().to_string(),
        "generation": 0,
        "stateVersion": 0,
        "groupId": STANDARD.encode(fixture.group_id),
        "epoch": 0,
        "groupContextHash": STANDARD.encode(fixture.group_context_hash),
        "confirmationTag": STANDARD.encode(fixture.confirmation_tag),
        "lifecycle": "active",
    });

    let next_coordinate = json!({
        "conversationId": fixture.cid.hyphenated().to_string(),
        "generation": 0,
        "stateVersion": 1,
        "groupId": STANDARD.encode(fixture.group_id),
        "epoch": 0,
        "groupContextHash": STANDARD.encode(fixture.group_context_hash),
        "confirmationTag": STANDARD.encode(fixture.confirmation_tag),
        "lifecycle": "active",
    });

    let participant_changes = vec![json!({
        "$type": "blue.catbird.chat.defs#addParticipant",
        "userDid": remote_invitee_did,
        "status": "pending",
        "role": "member",
        "invitationProvenance": {
            "invitedByDid": &fixture.actor_did,
            "invitedByDeviceId": fixture.actor_device_id.hyphenated().to_string(),
            "invitationTransitionId": policy_transition_id.hyphenated().to_string(),
        },
    })];

    let policy_body = json!({
        "$type": "blue.catbird.chat.defs#policyTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-POLICY\u{0000}",
        "transitionId": policy_transition_id.hyphenated().to_string(),
        "actorDid": &fixture.actor_did,
        "actorDeviceId": fixture.actor_device_id.hyphenated().to_string(),
        "keyId": &fixture.actor_key_id,
        "authGeneration": 1,
        "prior": prior_coordinate,
        "next": next_coordinate,
        "participantChanges": participant_changes,
        "idempotencyKey": policy_transition_id.hyphenated().to_string(),
        "signedAt": signed_at,
    });

    let mut policy_wrapper = json!({
        "body": policy_body,
        "signature": STANDARD.encode([0_u8; 64]),
    });
    let unsigned = serde_json::to_vec(&policy_wrapper).unwrap();
    let canonical = decode_canonical_signed_mutation(&unsigned).expect("canonicalize policy body");
    let signature = fixture
        .actor_ed25519_signing_key
        .sign(canonical.transcript_bytes());
    policy_wrapper["signature"] = json!(STANDARD.encode(signature.to_bytes()));

    let policy_payload = json!({
        "signedRequest": policy_wrapper,
    });

    let now = chrono::Utc::now().timestamp();
    let policy_access_token = sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":format!("{}#atproto", fixture.actor_did)}),
        json!({
            "iss": fixture.actor_did,
            "sub": fixture.actor_did,
            "aud": AUDIENCE,
            "lxm": "blue.catbird.chat.submitTransition",
            "iat": now,
            "exp": now + 60,
            "jti": Uuid::new_v4().to_string(),
            "cnf": {"jkt": dpop_jkt},
            "device_id": fixture.actor_device_id.to_string(),
            "chat_instance": CHAT_INSTANCE,
        }),
        &dpop_key,
    );
    let policy_proof = dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &format!("{EXTERNAL_BASE}/xrpc/blue.catbird.chat.submitTransition"),
        &policy_access_token,
        now,
        Uuid::new_v4().as_bytes(),
    );
    let policy_req = Request::builder()
        .method("POST")
        .uri(xrpc("blue.catbird.chat.submitTransition"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {policy_access_token}"))
        .header("dpop", policy_proof)
        .body(Body::from(serde_json::to_vec(&policy_payload).unwrap()))
        .expect("build policy request");

    let (policy_status, policy_bytes) = send_raw(router.clone(), policy_req).await;
    let policy_text = String::from_utf8_lossy(&policy_bytes);
    assert_eq!(
        policy_status,
        StatusCode::OK,
        "submitTransition policy-add must return 200 OK: {policy_text}"
    );

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
    let local_p_ds_did: Option<String> = sqlx::query_scalar(
        "SELECT ds_did FROM chat.participants WHERE conversation_id = $1 AND user_did = $2",
    )
    .bind(fixture.cid)
    .bind(&fixture.actor_did)
    .fetch_one(&pool)
    .await
    .expect("read local participant ds_did");
    assert!(
        local_p_ds_did.is_none(),
        "local creator must persist ds_did = NULL"
    );

    let remote_p_ds_did: Option<String> = sqlx::query_scalar(
        "SELECT ds_did FROM chat.participants WHERE conversation_id = $1 AND user_did = $2",
    )
    .bind(fixture.cid)
    .bind(&remote_invitee_did)
    .fetch_one(&pool)
    .await
    .expect("read remote participant ds_did");
    assert_eq!(
        remote_p_ds_did,
        Some(peer_ds_did),
        "remote invitee must persist allowlisted peer ds_did"
    );
    // Verify getConversations retrieval
    let get_convos_req = build_authenticated_get_request(
        &fixture.actor_did,
        fixture.actor_device_id,
        &dpop_key,
        &dpop_jwk,
        &dpop_jkt,
        "blue.catbird.chat.getConversations",
        &format!(
            "actorDeviceId={}&limit=50",
            fixture.actor_device_id.hyphenated()
        ),
    );
    let (get_status, get_response_bytes) = send_raw(router, get_convos_req).await;
    assert_eq!(get_status, StatusCode::OK);
    let get_body: Value = serde_json::from_slice(&get_response_bytes).unwrap();
    assert_eq!(
        get_body["items"][0]["state"]["coordinates"]["conversationId"],
        fixture.cid.hyphenated().to_string()
    );
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
        blob_store: catbird_server::blob_store::BlobStore::for_route_tests(),
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
    let stale_err =
        catbird_server::chat_protocol::test_support::cas_conversation_head_test(
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
    let (pool, _disposable) =
        common::fresh_db::fresh_clean_protocol_db("chat_fedrouting_", 4).await;
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
    let hook: catbird_server::federation::resolver::UserDidResolverFn =
        Arc::new(move |user_did: &str| {
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
        });

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
        blob_store: catbird_server::blob_store::BlobStore::for_route_tests(),
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
