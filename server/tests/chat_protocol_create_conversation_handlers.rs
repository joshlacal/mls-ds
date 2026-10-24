//! End-to-end handler tests for `blue.catbird.chat.createConversation`
//!
//! These tests exercise the full HTTP pipeline:
//! 1. Cutover gate enforcement (stateless)
//! 2. DPoP verification (stateless)
//! 3. Authenticated happy path with DID-typed participants (DB-gated)
//! 4. Verbatim idempotent replay (DB-gated)
//! 5. Negative validation cases returning declared 4xx codes rather than 500 (DB-gated)
//!
//! Run with:
//!   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_create_conversation_handlers -- --test-threads=1
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

#[allow(dead_code)]
#[path = "common/generated_transition_requests.rs"]
mod generated_transition_requests;

use std::{fs, path::Path, process::Command, sync::Arc};

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
use tower_util::ServiceExt;
use uuid::Uuid;

use catbird_server::handlers::chat::{chat_router, ChatRuntime};
use catbird_server::storage::DbPool;
use transcript::decode_canonical_signed_mutation;
use validation::ed25519_key_id;

use tls_codec::{Deserialize as _, VLBytes};

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestGroupInfoEnvelope {
    version: u16,
    wire_format: u16,
    group_info: TestGroupInfo,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestGroupInfo {
    context: TestGroupContext,
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

static RUNTIME_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

async fn runtime(pool: &DbPool, cutover_enabled: bool) -> Arc<ChatRuntime> {
    ensure_verifier_env(pool).await;
    let _guard = RUNTIME_ENV_LOCK.lock();
    if cutover_enabled {
        std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    } else {
        std::env::remove_var("CHAT_CUTOVER_ENABLED");
    }
    let rt = Arc::new(
        ChatRuntime::from_env(Arc::new(catbird_server::realtime::SseState::new(8)))
            .expect("build clean-chat runtime"),
    );
    std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    rt
}

async fn router_with(pool: DbPool, cutover_enabled: bool) -> Router {
    let rt = runtime(&pool, cutover_enabled).await;
    chat_router::<TestState>().with_state(TestState {
        pool,
        runtime: rt,
        blob_store: catbird_server::blob_store::BlobStore::for_route_tests(),
    })
}

async fn stateless_router(cutover_enabled: bool) -> Router {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://127.0.0.1/unused_clean_chat_gate")
        .expect("lazy pool");
    router_with(pool, cutover_enabled).await
}

fn xrpc(nsid: &str) -> String {
    format!("/xrpc/{nsid}")
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

async fn send_raw(router: Router, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = router.oneshot(request).await.expect("router response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("collect response body");
    (status, bytes.to_vec())
}

fn post_empty(nsid: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(xrpc(nsid))
        .header("content-type", "application/json")
        .body(Body::empty())
        .expect("build POST request")
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

fn build_test_creation_fixture(trusted_at: DateTime<Utc>) -> CreationTestFixture {
    build_test_creation_fixture_with_invitee(trusted_at, None)
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
            .context
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
        "conversationKind": "group",
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

async fn seed_device_for_creation(
    pool: &DbPool,
    user_did: &str,
    device_id: Uuid,
    key_id: &str,
    signing_public_key: &[u8],
    dpop_signing_key: &P256SigningKey,
    dpop_jkt: &str,
) {
    let now = chrono::Utc::now();
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
    body_json: Value,
) -> Request<Body> {
    build_authenticated_post_for_endpoint(
        user_did,
        device_id,
        dpop_signing_key,
        dpop_jwk,
        dpop_jkt,
        ENDPOINT,
        body_json,
    )
}

fn build_authenticated_post_for_endpoint(
    user_did: &str,
    device_id: Uuid,
    dpop_signing_key: &P256SigningKey,
    dpop_jwk: &Value,
    dpop_jkt: &str,
    endpoint: &str,
    body_json: Value,
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
            "device_id": device_id.to_string(),
            "chat_instance": CHAT_INSTANCE,
        }),
        dpop_signing_key,
    );

    let htu = format!("{EXTERNAL_BASE}/xrpc/{endpoint}");
    let proof = dpop_proof(
        dpop_signing_key,
        dpop_jwk,
        "POST",
        &htu,
        &access_token,
        now,
        Uuid::new_v4().as_bytes(),
    );

    let body_bytes = serde_json::to_vec(&body_json).expect("serialize body");
    Request::builder()
        .method("POST")
        .uri(xrpc(endpoint))
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
async fn create_conversation_cutover_disabled_returns_cutover_required() {
    let (status, body) = send(stateless_router(false).await, post_empty(ENDPOINT)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "CutoverRequired");
}

#[tokio::test]
async fn create_conversation_cutover_enabled_missing_auth_returns_not_authorized() {
    let (status, body) = send(stateless_router(true).await, post_empty(ENDPOINT)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn create_conversation_happy_path_with_did_typed_participants_accepts_and_replays() {
    let (pool, _disposable) =
        common::fresh_db::fresh_clean_protocol_db("chat_convhandlers_", 4).await;
    let ledger_rows: Vec<(i64, String, bool, Vec<u8>)> = sqlx::query_as(
        "SELECT version, description, success, checksum FROM public._sqlx_migrations ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .expect("read clean-chat migration ledger on fresh database");

    assert_eq!(
        ledger_rows.len(),
        common::chat_protocol::CLEAN_PROTOCOL_13_MANIFEST.len(),
        "fresh database ledger must contain exact reviewed migration manifest"
    );
    for (entry, row) in common::chat_protocol::CLEAN_PROTOCOL_13_MANIFEST
        .iter()
        .zip(ledger_rows.iter())
    {
        assert_eq!(row.0, entry.migration.version, "version matches");
        assert_eq!(
            &row.1,
            entry.migration.description.as_ref(),
            "description matches"
        );
        assert!(row.2, "migration succeeded");
        assert_eq!(
            row.3.as_slice(),
            entry.migration.checksum.as_ref(),
            "checksum matches"
        );
    }

    let trusted_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&pool)
            .await
            .expect("sample timestamp");

    let fixture = build_test_creation_fixture(trusted_at);
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

    let payload = json!({
        "signedRequest": fixture.signed_request_json,
    });
    let router = router_with(pool.clone(), true).await;
    let request = build_authenticated_request(
        &fixture.actor_did,
        fixture.actor_device_id,
        &dpop_key,
        &dpop_jwk,
        &dpop_jkt,
        payload.clone(),
    );
    let (status, first_response_bytes) = send_raw(router.clone(), request).await;
    let text = String::from_utf8_lossy(&first_response_bytes);
    println!("HTTP status: {status}, response: {text}");
    assert_eq!(
        status,
        StatusCode::OK,
        "first createConversation must succeed (200 OK), got {status}: {text}"
    );

    let first_body: Value =
        serde_json::from_slice(&first_response_bytes).expect("parse response json");
    assert_eq!(
        first_body["result"]["$type"],
        "blue.catbird.chat.defs#conversationCreatedResult"
    );
    assert_eq!(
        first_body["result"]["coordinates"]["conversationId"],
        fixture.cid.hyphenated().to_string()
    );
    assert_eq!(first_body["result"]["coordinates"]["generation"], 0);
    assert_eq!(first_body["result"]["coordinates"]["stateVersion"], 0);
    assert_eq!(first_body["result"]["coordinates"]["epoch"], 0);
    assert_eq!(first_body["result"]["coordinates"]["lifecycle"], "active");

    // Idempotent replay with the exact same request
    let replay_request = build_authenticated_request(
        &fixture.actor_did,
        fixture.actor_device_id,
        &dpop_key,
        &dpop_jwk,
        &dpop_jkt,
        payload,
    );

    let (replay_status, replay_response_bytes) = send_raw(router.clone(), replay_request).await;
    assert_eq!(
        replay_status,
        StatusCode::OK,
        "replayed createConversation must return 200 OK"
    );
    // Now call getConversations for the actor device!
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
    let (get_status, get_response_bytes) = send_raw(router.clone(), get_convos_req).await;
    let get_text = String::from_utf8_lossy(&get_response_bytes);
    println!("getConversations HTTP status: {get_status}, response: {get_text}");
    assert_eq!(
        get_status,
        StatusCode::OK,
        "getConversations must return 200 OK: {get_text}"
    );
    let get_body: Value =
        serde_json::from_slice(&get_response_bytes).expect("parse getConversations json");
    assert!(
        get_body["items"].is_array(),
        "items must be an array: {get_text}"
    );
    let items = get_body["items"].as_array().unwrap();
    assert_eq!(
        items[0]["state"]["coordinates"]["conversationId"],
        fixture.cid.hyphenated().to_string(),
        "conversationId must match created fixture cid"
    );
    assert_eq!(
        first_response_bytes, replay_response_bytes,
        "idempotent replay must return byte-identical response"
    );
    let (is_remote, sequencer_ds, sequencer_term): (bool, Option<String>, i64) = sqlx::query_as(
        "SELECT is_remote, sequencer_ds, sequencer_term \
             FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(fixture.cid)
    .fetch_one(&pool)
    .await
    .expect("read persisted local routing identity");
    assert!(!is_remote);
    assert!(sequencer_ds.is_none());
    assert_eq!(sequencer_term, 0);
    let participant_ds_dids: Vec<Option<String>> =
        sqlx::query_scalar("SELECT ds_did FROM chat.participants WHERE conversation_id = $1")
            .bind(fixture.cid)
            .fetch_all(&pool)
            .await
            .expect("read persisted participant routing identities");
    assert!(
        participant_ds_dids.iter().all(Option::is_none),
        "local participants must persist NULL ds_did"
    );
    let (completed_status, response_sha256, response_bytes): (i32, Vec<u8>, Vec<u8>) =
        sqlx::query_as(
            "SELECT completed_status, response_sha256, response_bytes \
             FROM chat.idempotency_records \
             WHERE principal_did = $1 AND endpoint_nsid = $2 AND operation_id = $3",
        )
        .bind(&fixture.actor_did)
        .bind(ENDPOINT)
        .bind(fixture.transition_id)
        .fetch_one(&pool)
        .await
        .expect("read canonical completed replay row");
    assert_eq!(completed_status, 200);
    assert_eq!(
        response_sha256.as_slice(),
        Sha256::digest(&response_bytes).as_slice(),
        "completed replay must carry a canonical response digest"
    );
    // Merged line: the record stores the generated-DTO bytes and every 200 is
    // served through the encrypted-requests read presentation, so the stored
    // record must present to exactly the bytes the client received.
    assert_eq!(
        catbird_server::chat_protocol::direct_request_transcript::present_endpoint_output(
            ENDPOINT,
            response_bytes,
        )
        .expect("present stored response"),
        first_response_bytes
    );
}

#[derive(Clone, Copy)]
enum GeneratedTransitionOrigin {
    Rust,
    Swift,
}

impl GeneratedTransitionOrigin {
    fn name(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Swift => "swift",
        }
    }
}

fn run_swift_transition_producer(args: &[&str], log_path: &Path) {
    let output = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/generated_transitions/reproduce.py"
        ))
        .args(args)
        .output()
        .expect("run required actual generated Swift producer");
    let mut log = output.stdout;
    log.extend_from_slice(&output.stderr);
    fs::write(log_path, &log).expect("retain Swift producer output");
    assert!(
        output.status.success(),
        "actual generated Swift producer failed; {}: {}",
        log_path.display(),
        String::from_utf8_lossy(&log)
    );
}

async fn signed_pending_add_for_generated_handler(
    pool: &DbPool,
    fixture: &CreationTestFixture,
    trusted_at: DateTime<Utc>,
) -> (Uuid, Value) {
    let transition_id = Uuid::new_v4();
    let invitee = random_did();
    sqlx::query("INSERT INTO chat.principals (user_did, created_at) VALUES ($1, $2)")
        .bind(&invitee)
        .bind(trusted_at)
        .execute(pool)
        .await
        .expect("seed generated-handler invitee");
    let mut roster = vec![fixture.actor_did.clone(), invitee.clone()];
    roster.sort();
    catbird_server::chat_protocol::test_support::seed_deterministic_pending_add_fallback(
        pool,
        &fixture.actor_did,
        roster,
        vec![invitee.clone()],
    )
    .await
    .expect("seed pending-add relationship fallback");
    let prior = json!({
        "conversationId": fixture.cid.to_string(),
        "generation": 0,
        "stateVersion": 0,
        "groupId": STANDARD.encode(fixture.group_id),
        "epoch": 0,
        "groupContextHash": STANDARD.encode(fixture.group_context_hash),
        "confirmationTag": STANDARD.encode(fixture.confirmation_tag),
        "lifecycle": "active",
    });
    let mut next = prior.clone();
    next["stateVersion"] = json!(1);
    let body = json!({
        "$type": "blue.catbird.chat.defs#policyTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-POLICY\u{0000}",
        "transitionId": transition_id.to_string(),
        "actorDid": fixture.actor_did,
        "actorDeviceId": fixture.actor_device_id.to_string(),
        "keyId": fixture.actor_key_id,
        "authGeneration": 1,
        "prior": prior,
        "next": next,
        "participantChanges": [{
            "$type": "blue.catbird.chat.defs#addParticipant",
            "userDid": invitee,
            "status": "pending",
            "role": "member",
            "invitationProvenance": {
                "invitedByDid": fixture.actor_did,
                "invitedByDeviceId": fixture.actor_device_id.to_string(),
                "invitationTransitionId": transition_id.to_string(),
            },
        }],
        "idempotencyKey": transition_id.to_string(),
        "signedAt": (trusted_at - chrono::Duration::milliseconds(500))
            .to_rfc3339_opts(SecondsFormat::Millis, true),
    });
    let mut wrapper = json!({"body": body, "signature": STANDARD.encode([0_u8; 64])});
    let canonical = decode_canonical_signed_mutation(&serde_json::to_vec(&wrapper).unwrap())
        .expect("canonical policy signing input");
    wrapper["signature"] = json!(STANDARD.encode(
        fixture
            .actor_ed25519_signing_key
            .sign(canonical.transcript_bytes())
            .to_bytes()
    ));
    (transition_id, wrapper)
}

async fn generated_handler_business_snapshot(
    pool: &DbPool,
    fixture: &CreationTestFixture,
) -> Value {
    // BYTEA stays hex in to_jsonb(row); never cast a signed payload to PG JSON,
    // whose parser rejects the signature domain's escaped NUL.
    sqlx::query_scalar(
        "SELECT jsonb_build_object(\
         'conversation', (SELECT to_jsonb(c) FROM chat.conversations c WHERE conversation_id=$1), \
         'participants', (SELECT jsonb_agg(to_jsonb(p) ORDER BY user_did) FROM chat.participants p WHERE conversation_id=$1), \
         'entries', (SELECT jsonb_agg(to_jsonb(e) ORDER BY seq) FROM chat.entries e WHERE conversation_id=$1), \
         'transitions', (SELECT jsonb_agg(to_jsonb(t) ORDER BY transition_id) FROM chat.transitions t WHERE conversation_id=$1), \
         'receipts', (SELECT jsonb_agg(to_jsonb(i) ORDER BY endpoint_nsid, operation_id) FROM chat.idempotency_records i WHERE principal_did=$2), \
         'claims', (SELECT jsonb_agg(to_jsonb(o) ORDER BY operation_id) FROM chat.operation_claims o WHERE principal_did=$2))",
    )
    .bind(fixture.cid)
    .bind(&fixture.actor_did)
    .fetch_one(pool)
    .await
    .expect("snapshot generated-handler durable business state")
}

async fn exercise_generated_transition_handler(origin: GeneratedTransitionOrigin) {
    use catbird_server::chat_protocol::transcript::{
        decode_and_verify_control_entry, rebind_persisted_control_entry,
    };

    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    const SUBMIT: &str = "blue.catbird.chat.submitTransition";
    let artifacts = std::env::var_os("CATBIRD_GENERATED_TRANSITION_ARTIFACT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts"))
        .join(format!(
            "generated-{}-handler-{}",
            origin.name(),
            Uuid::new_v4()
        ));
    fs::create_dir_all(&artifacts).expect("create retained handler artifacts");
    println!(
        "Generated {} handler artifacts: {}",
        origin.name(),
        artifacts.display()
    );
    let (pool, _disposable) =
        common::fresh_db::fresh_clean_protocol_db("chat_convhandlers_", 4).await;
    let trusted_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&pool)
            .await
            .expect("sample fixture timestamp");
    let fixture = build_test_creation_fixture(trusted_at);
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
    let router = router_with(pool.clone(), true).await;
    let (status, creation) = send_raw(
        router.clone(),
        build_authenticated_request(
            &fixture.actor_did,
            fixture.actor_device_id,
            &dpop_key,
            &dpop_jwk,
            &dpop_jkt,
            json!({"signedRequest": fixture.signed_request_json}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "creation: {}",
        String::from_utf8_lossy(&creation)
    );
    let (transition_id, canonical_wrapper) =
        signed_pending_add_for_generated_handler(&pool, &fixture, trusted_at).await;
    let canonical_path = artifacts.join("canonical-wrapper.json");
    fs::write(
        &canonical_path,
        serde_json::to_vec(&canonical_wrapper).unwrap(),
    )
    .unwrap();
    let request_bytes = match origin {
        GeneratedTransitionOrigin::Rust => generated_transition_requests::generated_request(
            &canonical_wrapper["body"],
            &STANDARD
                .decode(canonical_wrapper["signature"].as_str().unwrap())
                .unwrap(),
        ),
        GeneratedTransitionOrigin::Swift => {
            run_swift_transition_producer(
                &[
                    "--encode-wrapper",
                    "policy",
                    canonical_path.to_str().unwrap(),
                    artifacts.to_str().unwrap(),
                ],
                &artifacts.join("swift-encode.log"),
            );
            fs::read(artifacts.join("swift-policy.request.json"))
                .expect("actual Swift request bytes")
        }
    };
    fs::write(artifacts.join("submitted.request.json"), &request_bytes).unwrap();
    #[derive(serde::Deserialize)]
    struct RawEnvelope {
        #[serde(rename = "signedRequest")]
        signed_request: Box<serde_json::value::RawValue>,
    }
    let envelope: RawEnvelope = serde_json::from_slice(&request_bytes).unwrap();
    let raw_wrapper = envelope.signed_request.get().as_bytes();
    let wire_value: Value = serde_json::from_slice(&request_bytes).unwrap();
    assert_eq!(
        wire_value["signedRequest"]["$type"],
        "blue.catbird.chat.defs#signedPolicyTransition"
    );
    if matches!(origin, GeneratedTransitionOrigin::Rust) {
        assert!(
            wire_value["signedRequest"]["body"].get("$type").is_none(),
            "fresh Rust structs must not inherit a body tag through extra_data"
        );
    }
    let request = |bytes: &[u8]| {
        let mut request = build_authenticated_post_for_endpoint(
            &fixture.actor_did,
            fixture.actor_device_id,
            &dpop_key,
            &dpop_jwk,
            &dpop_jkt,
            SUBMIT,
            Value::Null,
        );
        // DPoP binds method/URL/token, not body. Preserve generated bytes exactly.
        *request.body_mut() = Body::from(bytes.to_vec());
        request
    };

    let before_invalid = generated_handler_business_snapshot(&pool, &fixture).await;
    let mut invalid = wire_value.clone();
    invalid["signedRequest"]["$type"] = json!("blue.catbird.chat.defs#signedMetadataTransition");
    let invalid_bytes = serde_json::to_vec(&invalid).unwrap();
    let (invalid_status, invalid_response) =
        send_raw(router.clone(), request(&invalid_bytes)).await;
    fs::write(artifacts.join("invalid-response.json"), &invalid_response).unwrap();
    assert_eq!(
        invalid_status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&invalid_response)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&invalid_response).unwrap()["error"],
        "InvalidRequest"
    );
    assert_eq!(before_invalid, generated_handler_business_snapshot(&pool, &fixture).await,
        "wrong generated discriminator must not mutate conversation, participants, entries, transitions, receipts or claims");

    let (status, first_response) = send_raw(router.clone(), request(&request_bytes)).await;
    fs::write(artifacts.join("submit-response.json"), &first_response).unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "generated {} submission: {}",
        origin.name(),
        String::from_utf8_lossy(&first_response)
    );
    let output: catbird_atproto::blue_catbird::chat::submit_transition::SubmitTransitionOutput =
        serde_json::from_slice(&first_response)
            .expect("generated Rust decodes actual submit response");
    assert_eq!(output.coordinates.state_version, 1);
    let first_value: Value = serde_json::from_slice(&first_response).unwrap();
    let before_replay = generated_handler_business_snapshot(&pool, &fixture).await;
    let (replay_status, replay_response) = send_raw(router.clone(), request(&request_bytes)).await;
    fs::write(artifacts.join("replay-response.json"), &replay_response).unwrap();
    assert_eq!(
        replay_status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&replay_response)
    );
    assert_eq!(
        first_response, replay_response,
        "exact request replay must return exact HTTP body bytes"
    );
    assert_eq!(
        before_replay,
        generated_handler_business_snapshot(&pool, &fixture).await
    );

    let legacy_request = serde_json::to_vec(&json!({"signedRequest": canonical_wrapper})).unwrap();
    assert_ne!(legacy_request, request_bytes);
    let (conflict_status, conflict_response) =
        send_raw(router.clone(), request(&legacy_request)).await;
    fs::write(
        artifacts.join("alternate-response.json"),
        &conflict_response,
    )
    .unwrap();
    assert_eq!(
        conflict_status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&conflict_response)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&conflict_response).unwrap()["error"],
        "IdempotencyConflict"
    );
    assert_eq!(
        before_replay,
        generated_handler_business_snapshot(&pool, &fixture).await,
        "semantically equal alternate bytes must not replace the accepted representation"
    );

    let (transition_raw, entry_raw, receipt_raw, durable, durable_hash, fingerprint):
        (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT t.signed_request_bytes, e.signed_request_bytes, i.accepted_request_bytes, \
         e.accepted_payload_bytes, e.accepted_payload_sha256, e.outer_entry_fingerprint \
         FROM chat.transitions t JOIN chat.entries e \
           ON e.conversation_id=t.conversation_id AND e.transition_id=t.transition_id AND e.seq=t.entry_seq \
         JOIN chat.idempotency_records i ON i.principal_did=t.actor_did \
           AND i.endpoint_nsid=$1 AND i.operation_id=t.transition_id WHERE t.transition_id=$2",
    ).bind(SUBMIT).bind(transition_id).fetch_one(&pool).await.expect("read accepted generated policy rows");
    assert_eq!(transition_raw, raw_wrapper);
    assert_eq!(entry_raw, raw_wrapper);
    assert_eq!(receipt_raw, raw_wrapper);
    assert_ne!(
        durable, raw_wrapper,
        "accepted payload is the complete durable control row"
    );
    assert_eq!(durable_hash.as_slice(), Sha256::digest(&durable).as_slice());
    assert_ne!(
        durable_hash.as_slice(),
        Sha256::digest(raw_wrapper).as_slice()
    );
    fs::write(artifacts.join("durable-control-row.json"), &durable).unwrap();
    fs::write(artifacts.join("retained-signed-wrapper.json"), &entry_raw).unwrap();
    let verified = decode_and_verify_control_entry(&durable, &fixture.actor_ed25519_public_key)
        .expect("production authority verifier accepts full durable row");
    assert_eq!(verified.outer_control_fingerprint().as_slice(), fingerprint);
    let rebound =
        rebind_persisted_control_entry(verified, &entry_raw, &fixture.actor_ed25519_public_key)
            .expect("historical rebinding preserves original generated wrapper");
    assert_eq!(
        rebound.mutation().accepted_wrapper_bytes(),
        Some(raw_wrapper)
    );

    let (read_status, read_response) = send_raw(
        router.clone(),
        build_authenticated_get_request(
            &fixture.actor_did,
            fixture.actor_device_id,
            &dpop_key,
            &dpop_jwk,
            &dpop_jkt,
            "blue.catbird.chat.getEntries",
            &format!(
                "actorDeviceId={}&conversationId={}&afterSeq=0&limit=100",
                fixture.actor_device_id, fixture.cid
            ),
        ),
    )
    .await;
    fs::write(artifacts.join("get-entries-response.json"), &read_response).unwrap();
    assert_eq!(
        read_status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&read_response)
    );
    let read_output: catbird_atproto::blue_catbird::chat::get_entries::GetEntriesOutput =
        serde_json::from_slice(&read_response)
            .expect("generated Rust decodes actual getEntries response");
    assert_eq!(read_output.entries.len(), 2);
    assert!(!read_output.has_more);
    let read_value: Value = serde_json::from_slice(&read_response).unwrap();
    let policy_entry = read_value["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["signedRequest"]["body"]["transitionId"] == transition_id.to_string())
        .expect("getEntries returned the generated policy transition");
    assert_eq!(
        policy_entry, &first_value["entry"],
        "ACK and canonical read expose the same complete entry"
    );
    let read_verified = decode_and_verify_control_entry(
        &serde_json::to_vec(policy_entry).unwrap(),
        &fixture.actor_ed25519_public_key,
    )
    .expect("production authority verifier accepts actual canonical read entry");
    assert_eq!(
        read_verified.outer_control_fingerprint(),
        rebound.outer_control_fingerprint()
    );
    assert_eq!(
        read_verified.mutation().request_digest(),
        rebound.mutation().request_digest()
    );
    let (state_status, state_response) = send_raw(
        router,
        build_authenticated_get_request(
            &fixture.actor_did,
            fixture.actor_device_id,
            &dpop_key,
            &dpop_jwk,
            &dpop_jkt,
            "blue.catbird.chat.getConversationState",
            &format!(
                "actorDeviceId={}&conversationId={}",
                fixture.actor_device_id, fixture.cid
            ),
        ),
    )
    .await;
    fs::write(artifacts.join("get-state-response.json"), &state_response).unwrap();
    assert_eq!(
        state_status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&state_response)
    );
    let state_output: catbird_atproto::blue_catbird::chat::get_conversation_state::GetConversationStateOutput =
        serde_json::from_slice(&state_response)
            .expect("generated Rust decodes actual getConversationState response");
    assert_eq!(state_output.state.coordinates, output.coordinates);
    assert_eq!(state_output.state.snapshot_seq, 2);
    if matches!(origin, GeneratedTransitionOrigin::Swift) {
        for (kind, file) in [
            ("submitTransition", "submit-response.json"),
            ("getEntries", "get-entries-response.json"),
            ("getConversationState", "get-state-response.json"),
        ] {
            run_swift_transition_producer(
                &[
                    "--decode-response",
                    kind,
                    artifacts.join(file).to_str().unwrap(),
                ],
                &artifacts.join(format!("swift-decode-{kind}.log")),
            );
        }
    }
    println!("Generated {}: accepted, exact replay, alternate conflict, no-mutation invalid tag, exact raw persistence, full-row digest, canonical getEntries/state and historical rebind verified", origin.name());
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and activation; required by the Linux compatibility gate"]
async fn generated_transition_handlers_preserve_raw_persistence_replay_and_canonical_reads() {
    exercise_generated_transition_handler(GeneratedTransitionOrigin::Rust).await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL, activation and actual pinned Swift SDK producer on macOS"]
async fn generated_swift_transition_handlers_preserve_raw_persistence_replay_and_canonical_reads() {
    exercise_generated_transition_handler(GeneratedTransitionOrigin::Swift).await;
}

#[tokio::test]
async fn submit_transition_policy_add_against_production_router_replays_byte_identically() {
    let (pool, _disposable) =
        common::fresh_db::fresh_clean_protocol_db("chat_convhandlers_", 4).await;
    let ledger_rows: Vec<(i64, String, bool, Vec<u8>)> = sqlx::query_as(
        "SELECT version, description, success, checksum FROM public._sqlx_migrations ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .expect("read clean-chat migration ledger on fresh database");

    assert_eq!(
        ledger_rows.len(),
        common::chat_protocol::CLEAN_PROTOCOL_13_MANIFEST.len(),
        "fresh database ledger must contain exact reviewed migration manifest"
    );
    for (entry, row) in common::chat_protocol::CLEAN_PROTOCOL_13_MANIFEST
        .iter()
        .zip(ledger_rows.iter())
    {
        assert_eq!(row.0, entry.migration.version, "version matches");
        assert_eq!(
            &row.1,
            entry.migration.description.as_ref(),
            "description matches"
        );
        assert!(row.2, "migration succeeded");
        assert_eq!(
            row.3.as_slice(),
            entry.migration.checksum.as_ref(),
            "checksum matches"
        );
    }

    let trusted_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&pool)
            .await
            .expect("sample timestamp");

    let fixture = build_test_creation_fixture(trusted_at);
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

    let payload = json!({
        "signedRequest": fixture.signed_request_json,
    });
    let router = router_with(pool.clone(), true).await;
    let create_request = build_authenticated_request(
        &fixture.actor_did,
        fixture.actor_device_id,
        &dpop_key,
        &dpop_jwk,
        &dpop_jkt,
        payload,
    );
    let (create_status, create_response_bytes) = send_raw(router.clone(), create_request).await;
    let create_text = String::from_utf8_lossy(&create_response_bytes);
    assert_eq!(
        create_status,
        StatusCode::OK,
        "createConversation must succeed (200 OK), got {create_status}: {create_text}"
    );

    let create_body: Value =
        serde_json::from_slice(&create_response_bytes).expect("parse create response json");
    let result_coords = &create_body["result"]["coordinates"];
    assert_eq!(
        result_coords["conversationId"],
        fixture.cid.hyphenated().to_string()
    );
    assert_eq!(result_coords["stateVersion"], 0);

    // Now construct policy transition adding Bob as pending member
    let policy_transition_id = Uuid::new_v4();
    let bob_did = random_did();
    sqlx::query(
        "INSERT INTO chat.principals (user_did, created_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(&bob_did)
    .bind(trusted_at)
    .execute(&pool)
    .await
    .expect("seed bob principal");

    let mut roster = vec![fixture.actor_did.clone(), bob_did.clone()];
    roster.sort();
    catbird_server::chat_protocol::test_support::seed_deterministic_pending_add_fallback(
        &pool,
        &fixture.actor_did,
        roster,
        vec![bob_did.clone()],
    )
    .await
    .expect("seed deterministic fallback relationship projection");
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
        "userDid": bob_did,
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

    let policy_request = build_authenticated_post_for_endpoint(
        &fixture.actor_did,
        fixture.actor_device_id,
        &dpop_key,
        &dpop_jwk,
        &dpop_jkt,
        "blue.catbird.chat.submitTransition",
        policy_payload.clone(),
    );
    let (status, first_response_bytes) = send_raw(router.clone(), policy_request).await;
    let text = String::from_utf8_lossy(&first_response_bytes);
    println!("Policy add HTTP status: {status}, response: {text}");
    assert_eq!(
        status,
        StatusCode::OK,
        "first submitTransition policy-add must succeed (200 OK), got {status}: {text}"
    );

    let first_body: Value =
        serde_json::from_slice(&first_response_bytes).expect("parse policy response json");
    assert_eq!(
        first_body["entry"]["$type"],
        "blue.catbird.chat.defs#policyEntry"
    );
    assert_eq!(first_body["coordinates"]["stateVersion"], 1);

    // Idempotent replay with the exact same request
    let replay_policy_request = build_authenticated_post_for_endpoint(
        &fixture.actor_did,
        fixture.actor_device_id,
        &dpop_key,
        &dpop_jwk,
        &dpop_jkt,
        "blue.catbird.chat.submitTransition",
        policy_payload,
    );

    let (replay_status, replay_response_bytes) =
        send_raw(router.clone(), replay_policy_request).await;
    let replay_text = String::from_utf8_lossy(&replay_response_bytes);
    assert_eq!(
        replay_status,
        StatusCode::OK,
        "replayed submitTransition policy-add must return 200 OK: {replay_text}"
    );
    assert_eq!(
        first_response_bytes, replay_response_bytes,
        "idempotent replay of submitTransition policy-add must return byte-identical response"
    );

    let (completed_status, response_sha256, response_bytes): (i32, Vec<u8>, Vec<u8>) =
        sqlx::query_as(
            "SELECT completed_status, response_sha256, response_bytes \
             FROM chat.idempotency_records \
             WHERE principal_did = $1 AND endpoint_nsid = $2 AND operation_id = $3",
        )
        .bind(&fixture.actor_did)
        .bind("blue.catbird.chat.submitTransition")
        .bind(policy_transition_id)
        .fetch_one(&pool)
        .await
        .expect("read canonical completed replay row for policy transition");
    assert_eq!(completed_status, 200);
    assert_eq!(
        response_sha256.as_slice(),
        Sha256::digest(&response_bytes).as_slice(),
        "completed policy replay must carry a canonical response digest"
    );
    // See the creation test: stored bytes present to the served bytes.
    assert_eq!(
        catbird_server::chat_protocol::direct_request_transcript::present_endpoint_output(
            "blue.catbird.chat.submitTransition",
            response_bytes,
        )
        .expect("present stored policy response"),
        first_response_bytes
    );
}
#[tokio::test]
#[ignore = "requires the dedicated clean-chat gate database"]
async fn create_then_list_returns_conversation_for_both_creator_and_invitee() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let trusted_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&pool)
            .await
            .expect("sample timestamp");

    let invitee_did = random_did();
    let invitee_device_id = Uuid::new_v4();
    let invitee_dpop_key = random_p256();
    let invitee_dpop_jwk = public_jwk(&invitee_dpop_key);
    let invitee_dpop_jkt = jwk_thumbprint(&invitee_dpop_jwk);
    let mut invitee_seed = [0_u8; 32];
    invitee_seed[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    invitee_seed[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    let invitee_ed_signing = Ed25519SigningKey::from_bytes(&invitee_seed);
    let invitee_key_id = ed25519_key_id(&invitee_ed_signing.verifying_key().to_bytes())
        .unwrap()
        .as_str()
        .to_string();

    seed_device_for_creation(
        &pool,
        &invitee_did,
        invitee_device_id,
        &invitee_key_id,
        &invitee_ed_signing.verifying_key().to_bytes(),
        &invitee_dpop_key,
        &invitee_dpop_jkt,
    )
    .await;

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

    let payload = json!({
        "signedRequest": fixture.signed_request_json,
    });
    let router = router_with(pool.clone(), true).await;
    let create_request = build_authenticated_request(
        &fixture.actor_did,
        fixture.actor_device_id,
        &dpop_key,
        &dpop_jwk,
        &dpop_jkt,
        payload.clone(),
    );
    let (status, create_bytes) = send_raw(router.clone(), create_request).await;
    let create_text = String::from_utf8_lossy(&create_bytes);
    assert_eq!(
        status,
        StatusCode::OK,
        "createConversation must succeed (200 OK): {create_text}"
    );

    // 1. Creator calls getConversations:
    let creator_list_req = build_authenticated_get_request(
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
    let (creator_status, creator_bytes) = send_raw(router.clone(), creator_list_req).await;
    let creator_text = String::from_utf8_lossy(&creator_bytes);
    assert_eq!(
        creator_status,
        StatusCode::OK,
        "creator getConversations must succeed: {creator_text}"
    );
    let creator_body: Value =
        serde_json::from_slice(&creator_bytes).expect("parse creator getConversations json");
    let creator_items = creator_body["items"]
        .as_array()
        .expect("creator items array");
    assert_eq!(
        creator_items.len(),
        1,
        "creator must see exactly 1 conversation: {creator_text}"
    );
    assert_eq!(
        creator_items[0]["state"]["coordinates"]["conversationId"],
        fixture.cid.hyphenated().to_string(),
        "creator must see the created conversation"
    );

    // 2. Invitee calls getConversations:
    let invitee_list_req = build_authenticated_get_request(
        &invitee_did,
        invitee_device_id,
        &invitee_dpop_key,
        &invitee_dpop_jwk,
        &invitee_dpop_jkt,
        "blue.catbird.chat.getConversations",
        &format!("actorDeviceId={}&limit=50", invitee_device_id.hyphenated()),
    );
    let (invitee_status, invitee_bytes) = send_raw(router.clone(), invitee_list_req).await;
    let invitee_text = String::from_utf8_lossy(&invitee_bytes);
    assert_eq!(
        invitee_status,
        StatusCode::OK,
        "invitee getConversations must succeed: {invitee_text}"
    );
    let invitee_body: Value =
        serde_json::from_slice(&invitee_bytes).expect("parse invitee getConversations json");
    let invitee_items = invitee_body["items"]
        .as_array()
        .expect("invitee items array");
    assert_eq!(
        invitee_items.len(),
        1,
        "invitee must see exactly 1 conversation: {invitee_text}"
    );
    assert_eq!(
        invitee_items[0]["state"]["coordinates"]["conversationId"],
        fixture.cid.hyphenated().to_string(),
        "invitee must see the created conversation"
    );
}

#[tokio::test]
#[ignore = "requires the dedicated clean-chat gate database"]
async fn create_conversation_negative_corrupted_signature_returns_invalid_signature() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let trusted_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&pool)
            .await
            .expect("sample timestamp");

    let fixture = build_test_creation_fixture(trusted_at);
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

    // Corrupt the signature in signedRequest
    let mut corrupted_request = fixture.signed_request_json.clone();
    corrupted_request["signature"] = json!(STANDARD.encode([0xff_u8; 64]));

    let payload = json!({
        "signedRequest": corrupted_request,
    });

    let router = router_with(pool, true).await;
    let request = build_authenticated_request(
        &fixture.actor_did,
        fixture.actor_device_id,
        &dpop_key,
        &dpop_jwk,
        &dpop_jkt,
        payload,
    );

    let (status, body) = send(router, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body["error"], "InvalidSignature",
        "corrupted signature must return declared InvalidSignature, not 500"
    );
}

#[tokio::test]
#[ignore = "requires the dedicated clean-chat gate database"]
async fn create_conversation_negative_idempotency_conflict_returns_declared_error() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let trusted_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&pool)
            .await
            .expect("sample timestamp");

    let fixture = build_test_creation_fixture(trusted_at);
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

    let payload = json!({
        "signedRequest": fixture.signed_request_json.clone(),
    });

    let router = router_with(pool, true).await;
    let request = build_authenticated_request(
        &fixture.actor_did,
        fixture.actor_device_id,
        &dpop_key,
        &dpop_jwk,
        &dpop_jkt,
        payload,
    );

    let (status, _) = send(router.clone(), request).await;
    assert_eq!(status, StatusCode::OK);

    // Reuse the same idempotency key / transitionId with a mutated signedRequest
    let mut mutated = fixture.signed_request_json.clone();
    mutated["body"]["signedAt"] = json!("2026-08-20T12:00:00.000Z");
    let mutated_payload = json!({
        "signedRequest": mutated,
    });

    let conflicting_request = build_authenticated_request(
        &fixture.actor_did,
        fixture.actor_device_id,
        &dpop_key,
        &dpop_jwk,
        &dpop_jkt,
        mutated_payload,
    );

    let (conflict_status, _conflict_body) = send(router, conflicting_request).await;
    assert!(
        conflict_status == StatusCode::BAD_REQUEST || conflict_status == StatusCode::UNAUTHORIZED,
        "mutated idempotency reuse must return 4xx, got {conflict_status}"
    );
    assert_ne!(
        conflict_status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "mutated idempotency reuse must NOT return 500"
    );
}

#[tokio::test]
#[ignore = "requires the dedicated clean-chat gate database"]
async fn submit_transition_negative_invalid_request_returns_declared_4xx() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let actor_did = random_did();
    let actor_device_id = Uuid::new_v4();
    let dpop_key = random_p256();
    let dpop_jwk = public_jwk(&dpop_key);
    let dpop_jkt = jwk_thumbprint(&dpop_jwk);
    let mut seed = [0_u8; 32];
    seed[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    seed[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    let ed_signing = Ed25519SigningKey::from_bytes(&seed);
    let actor_ed25519_public_key = ed_signing.verifying_key().to_bytes().to_vec();
    let actor_key_id = ed25519_key_id(&actor_ed25519_public_key)
        .unwrap()
        .as_str()
        .to_string();
    seed_device_for_creation(
        &pool,
        &actor_did,
        actor_device_id,
        &actor_key_id,
        &actor_ed25519_public_key,
        &dpop_key,
        &dpop_jkt,
    )
    .await;

    let router = router_with(pool, true).await;
    let request = build_authenticated_post_for_endpoint(
        &actor_did,
        actor_device_id,
        &dpop_key,
        &dpop_jwk,
        &dpop_jkt,
        "blue.catbird.chat.submitTransition",
        json!({ "signedRequest": { "invalid": true } }),
    );

    let (status, body) = send(router, request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["error"], "InvalidRequest",
        "malformed submitTransition payload must return declared InvalidRequest, not 500"
    );
}

#[tokio::test]
#[ignore = "requires the dedicated clean-chat gate database"]
async fn submit_transition_negative_corrupted_signature_returns_invalid_signature() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let actor_did = random_did();
    let actor_device_id = Uuid::new_v4();
    let dpop_key = random_p256();
    let dpop_jwk = public_jwk(&dpop_key);
    let dpop_jkt = jwk_thumbprint(&dpop_jwk);
    let mut seed = [0_u8; 32];
    seed[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    seed[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    let ed_signing = Ed25519SigningKey::from_bytes(&seed);
    let actor_ed25519_public_key = ed_signing.verifying_key().to_bytes().to_vec();
    let actor_key_id = ed25519_key_id(&actor_ed25519_public_key)
        .unwrap()
        .as_str()
        .to_string();

    seed_device_for_creation(
        &pool,
        &actor_did,
        actor_device_id,
        &actor_key_id,
        &actor_ed25519_public_key,
        &dpop_key,
        &dpop_jkt,
    )
    .await;

    let router = router_with(pool, true).await;
    let corrupted_signed_request = json!({
        "body": {
            "$type": "blue.catbird.chat.defs#commitTransitionBody",
            "actorDeviceId": actor_device_id.hyphenated().to_string(),
            "operationId": Uuid::new_v4().hyphenated().to_string(),
            "convoId": Uuid::new_v4().hyphenated().to_string(),
            "epoch": 0,
            "commit": STANDARD.encode([0x01_u8; 32]),
            "signedAt": "2026-08-21T00:00:00.000Z"
        },
        "deviceKeyId": actor_key_id,
        "signature": STANDARD.encode([0xff_u8; 64])
    });

    let request = build_authenticated_post_for_endpoint(
        &actor_did,
        actor_device_id,
        &dpop_key,
        &dpop_jwk,
        &dpop_jkt,
        "blue.catbird.chat.submitTransition",
        json!({ "signedRequest": corrupted_signed_request }),
    );

    let (status, body) = send(router, request).await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "corrupted signedRequest must return 4xx, got {status}: {body}"
    );
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "corrupted signedRequest must NOT return 500: {body}"
    );
}

// Encrypted-requests: transcript.rs test modules reference read_projection.
mod chat_protocol {
    pub mod read_projection {
        pub struct DummyCanonical;
        impl DummyCanonical {
            pub fn bytes(&self) -> &[u8] {
                &[]
            }
        }
        pub fn encode_canonical_generated_chat_json_v1<T: serde::Serialize>(
            _value: &T,
            _schema: &str,
        ) -> Result<DummyCanonical, String> {
            Ok(DummyCanonical)
        }
    }
}
