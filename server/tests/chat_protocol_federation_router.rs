//! Disposable-DB authenticated router integration tests for clean-chat federation endpoints.
//!
//! Covers:
//! 1. POST /xrpc/blue.catbird.mlsDS.deliverWelcome (positive, receipt persistence, replay, negative auth/conflict)
//! 2. POST /xrpc/blue.catbird.mlsDS.deliverMessage (positive, receipt persistence, replay, payload/claims check, negative auth/conflict)
//! 3. POST /xrpc/blue.catbird.mlsDS.deliverMessage with local attachment blob binding (positive, blob transition)
//! 4. POST /xrpc/blue.catbird.mlsDS.submitCommit (routing checks, sender authorization, conflict rejection, replay)
//! 5. Direct SQL immutability and operation claims + receipt completeness verification

#![allow(dead_code)]

mod common;
#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[allow(dead_code)]
#[path = "../src/chat_protocol/validation.rs"]
mod validation;
use p256::pkcs8::EncodePrivateKey;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::FromRef;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::post;
use axum::Router;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use catbird_atproto::generated::blue_catbird::chat::ConversationCoordinates;
use catbird_server::auth::{
    cache_test_did_document, DidDocument, PublicKeyJwk, VerificationMethod,
};
use catbird_server::federation::ack::AckSigner;
use catbird_server::federation::envelope::{
    compute_commit_envelope_digest, compute_message_envelope_digest,
    compute_welcome_envelope_digest, ValidatedEntryLocator, ValidatedEnvelopeHeader,
    DELIVER_MESSAGE_NSID, DELIVER_WELCOME_NSID, SUBMIT_COMMIT_NSID,
};
use catbird_server::federation::FederationMode;
use catbird_server::handlers::chat::ChatRuntime;
use catbird_server::storage::DbPool;
use chrono::{DateTime, SecondsFormat, Utc};
use common::fresh_db::{fresh_legacy_pool, DisposableDatabase};
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower_util::ServiceExt;
use transcript::{
    build_verified_application_entry, build_verified_control_entry,
    decode_and_verify_signed_mutation, decode_canonical_signed_mutation,
    CanonicalControlEntryProducts, CanonicalControlServerFields, ControlEntryKind,
};
use uuid::Uuid;
use validation::{
    ed25519_key_id, CanonicalTimestamp, CanonicalUuidV4, TrustedRequestInstant, ValidatedChatNsid,
};

const LOCAL_DS_DID: &str = "did:web:chat.catbird.blue";
const REMOTE_SEQUENCER_DID: &str = "did:web:sequencer.catbird.blue";
const AUDIENCE: &str = "did:web:chat.catbird.blue#atproto_mls";
const FED_ROUTER_DB_PREFIX: &str = "chat_fedrouter_";

#[derive(Clone)]
struct TestDsState {
    pool: DbPool,
    ack_signer: Option<Arc<AckSigner>>,
    runtime: Arc<ChatRuntime>,
    blob_store: catbird_server::blob_store::BlobStore,
}

impl FromRef<TestDsState> for DbPool {
    fn from_ref(state: &TestDsState) -> DbPool {
        state.pool.clone()
    }
}

impl FromRef<TestDsState> for Option<Arc<AckSigner>> {
    fn from_ref(state: &TestDsState) -> Option<Arc<AckSigner>> {
        state.ack_signer.clone()
    }
}

impl FromRef<TestDsState> for Arc<ChatRuntime> {
    fn from_ref(state: &TestDsState) -> Arc<ChatRuntime> {
        state.runtime.clone()
    }
}

impl FromRef<TestDsState> for catbird_server::blob_store::BlobStore {
    fn from_ref(state: &TestDsState) -> catbird_server::blob_store::BlobStore {
        state.blob_store.clone()
    }
}

fn build_federation_router(state: TestDsState) -> Router {
    Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.deliverMessage",
            post(catbird_server::handlers::ds::deliver_message),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.deliverWelcome",
            post(catbird_server::handlers::ds::deliver_welcome),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.submitCommit",
            post(catbird_server::handlers::ds::submit_commit),
        )
        .merge(catbird_server::handlers::chat::chat_router())
        .with_state(state)
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

fn sign_jwt(header: Value, claims: Value, key: &P256SigningKey) -> String {
    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{h_b64}.{c_b64}");
    let signature: P256Signature =
        p256::ecdsa::signature::Signer::sign(key, signing_input.as_bytes());
    let sig_bytes = signature.to_bytes();
    let s_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);
    format!("{signing_input}.{s_b64}")
}

async fn cache_did_key(did: &str, key: &P256SigningKey) {
    let point = key.verifying_key().to_encoded_point(false);
    let jwk_val = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    });
    let jwk: PublicKeyJwk = serde_json::from_value(jwk_val).unwrap();
    let doc = DidDocument {
        id: did.to_string(),
        verification_method: vec![VerificationMethod {
            id: format!("{did}#atproto"),
            key_type: "JsonWebKey2020".to_string(),
            controller: did.to_string(),
            public_key_jwk: Some(jwk),
            public_key_multibase: None,
        }],
        service: None,
    };
    cache_test_did_document(doc).await;
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

struct TestActor {
    did: String,
    device_id: Uuid,
    key_id: String,
    signing_key: Ed25519SigningKey,
    public_key: [u8; 32],
}

impl TestActor {
    fn generate() -> Self {
        let did = random_did();
        let device_id = Uuid::new_v4();
        let mut seed = [0_u8; 32];
        seed[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        seed[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        let signing_key = Ed25519SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let key_id = ed25519_key_id(&public_key).unwrap().as_str().to_owned();
        Self {
            did,
            device_id,
            key_id,
            signing_key,
            public_key,
        }
    }

    fn from_corpus_alice(manifest: &Value) -> Self {
        let alice_manifest = &manifest["identity"]["alice"];
        let did = alice_manifest["actorDid"].as_str().unwrap().to_string();
        let device_id = Uuid::parse_str(alice_manifest["deviceId"].as_str().unwrap()).unwrap();
        const ALICE_SIGNING_SEED: [u8; 32] = [
            0x38, 0x8f, 0x37, 0x73, 0x57, 0x9e, 0x8a, 0x2b, 0x5d, 0x57, 0x2d, 0x3b, 0x19, 0x85,
            0x55, 0xa6, 0x93, 0x6f, 0xb7, 0xf0, 0x13, 0xb8, 0x58, 0xe2, 0x69, 0xf6, 0x4f, 0x6e,
            0x8c, 0x6b, 0x12, 0x8d,
        ];
        let signing_key = Ed25519SigningKey::from_bytes(&ALICE_SIGNING_SEED);
        let public_key = signing_key.verifying_key().to_bytes();
        let key_id = alice_manifest["keyId"].as_str().unwrap().to_string();
        Self {
            did,
            device_id,
            key_id,
            signing_key,
            public_key,
        }
    }

    fn from_corpus_bob(manifest: &Value) -> Self {
        let bob_manifest = &manifest["identity"]["bob"];
        let did = bob_manifest["actorDid"].as_str().unwrap().to_string();
        let device_id = Uuid::parse_str(bob_manifest["deviceId"].as_str().unwrap()).unwrap();
        const BOB_SIGNING_SEED: [u8; 32] = [
            0xd4, 0xa1, 0xc4, 0x8e, 0x33, 0x92, 0x40, 0x8e, 0x24, 0x40, 0x90, 0x3f, 0xc5, 0x67,
            0x8d, 0xa5, 0x69, 0x98, 0xeb, 0x66, 0xeb, 0xb8, 0xa9, 0x64, 0xa7, 0xe4, 0xe4, 0xc2,
            0xad, 0x82, 0xe9, 0xb5,
        ];
        let signing_key = Ed25519SigningKey::from_bytes(&BOB_SIGNING_SEED);
        let public_key = signing_key.verifying_key().to_bytes();
        let key_id = bob_manifest["keyId"].as_str().unwrap().to_string();
        Self {
            did,
            device_id,
            key_id,
            signing_key,
            public_key,
        }
    }

    async fn seed(&self, pool: &DbPool, now: DateTime<Utc>) {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("INSERT INTO chat.principals (user_did, created_at) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(&self.did)
            .bind(now)
            .execute(&mut *tx)
            .await
            .unwrap();

        sqlx::query(
            r#"
            INSERT INTO chat.devices (
                user_did, device_id, device_name, status, dpop_jkt, auth_generation,
                capabilities, created_at, updated_at
            ) VALUES ($1, $2, 'test-device', 'active', NULL, 1, chat.protocol_capabilities(), $3, $3)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(&self.did)
        .bind(self.device_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();

        sqlx::query(
            r#"
            INSERT INTO chat.device_keys (
                user_did, device_id, key_id, signing_public_key, enrollment_auth_generation, created_at
            ) VALUES ($1, $2, $3, $4, 1, $5)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(&self.did)
        .bind(self.device_id)
        .bind(&self.key_id)
        .bind(&self.public_key[..])
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();

        tx.commit().await.unwrap();
    }
}

struct TestHarness {
    pool: DbPool,
    _db_guard: DisposableDatabase,
    router: Router,
    ack_signer: Arc<AckSigner>,
    sender_ds_did: String,
    sender_ds_key: P256SigningKey,
    sequencer_ds_did: String,
    sequencer_ds_key: P256SigningKey,
}

impl TestHarness {
    async fn new(sender_suffix: &str) -> Self {
        let (pool, db_guard) = fresh_legacy_pool(FED_ROUTER_DB_PREFIX, 8, 1).await;
        std::env::set_var("SERVICE_DID", LOCAL_DS_DID);
        std::env::set_var("CHAT_NEST_AUDIENCE", AUDIENCE);
        std::env::set_var("CHAT_CUTOVER_ENABLED", "true");
        std::env::set_var("FEDERATION_MODE", "allowlist");
        FederationMode::set_runtime_override(Some(FederationMode::Allowlist));
        let sender_ds_did = format!(
            "did:web:remote-{}-{}.catbird.blue",
            sender_suffix,
            Uuid::new_v4()
        );
        let ack_key = random_p256();
        let ack_signer = Arc::new(AckSigner::new(ack_key, LOCAL_DS_DID.to_string()));
        let sender_ds_key = random_p256();
        cache_did_key(&sender_ds_did, &sender_ds_key).await;

        // The remote sequencer DS is the authenticated sender for deliverMessage / deliverWelcome
        // mailboxes. It must be unique per harness: the process-global DID document cache is
        // shared across tests, and parallel tests would overwrite one another's key if they all
        // used the constant REMOTE_SEQUENCER_DID.
        let sequencer_ds_did = format!(
            "did:web:sequencer-{}-{}.catbird.blue",
            sender_suffix,
            Uuid::new_v4()
        );
        let sequencer_ds_key = random_p256();
        cache_did_key(&sequencer_ds_did, &sequencer_ds_key).await;

        // Seed peer policy
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
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            INSERT INTO federation_peers (ds_did, status, updated_at)
            VALUES ($1, 'allow', NOW())
            ON CONFLICT (ds_did) DO UPDATE SET status = 'allow', updated_at = NOW()
            "#,
        )
        .bind(&sender_ds_did)
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            INSERT INTO federation_peers (ds_did, status, updated_at)
            VALUES ($1, 'allow', NOW())
            ON CONFLICT (ds_did) DO UPDATE SET status = 'allow', updated_at = NOW()
            "#,
        )
        .bind(&sequencer_ds_did)
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            INSERT INTO federation_peers (ds_did, status, updated_at)
            VALUES ($1, 'allow', NOW())
            ON CONFLICT (ds_did) DO UPDATE SET status = 'allow', updated_at = NOW()
            "#,
        )
        .bind(LOCAL_DS_DID)
        .execute(&pool)
        .await
        .unwrap();
        let inst_id = Uuid::new_v4();
        let key = sqlx::query_scalar::<_, String>("SELECT chat.ed25519_key_id($1)")
            .bind(vec![0x51_u8; 32])
            .fetch_one(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING")
            .bind(inst_id)
            .bind(&key)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO chat.event_retention(protocol_instance_id,retained_floor,updated_at) VALUES($1,0,clock_timestamp()) ON CONFLICT DO NOTHING")
            .bind(inst_id)
            .execute(&pool)
            .await
            .unwrap();
        std::env::set_var("CHAT_CURSOR_KEY_ID", &key);
        std::env::set_var(
            "CHAT_CURSOR_SEALING_SECRET",
            URL_SAFE_NO_PAD.encode([0xA5_u8; 32]),
        );
        std::env::set_var(
            "CHAT_SUBSCRIPTION_ENDPOINT",
            "wss://chat.example.net/xrpc/blue.catbird.chat.subscribeEvents",
        );

        let runtime = Arc::new(
            ChatRuntime::from_env(Arc::new(catbird_server::realtime::SseState::new(8)))
                .expect("build chat runtime"),
        );

        let state = TestDsState {
            pool: pool.clone(),
            ack_signer: Some(ack_signer.clone()),
            runtime,
            blob_store: catbird_server::blob_store::BlobStore::for_route_tests(),
        };
        let router = build_federation_router(state);

        Self {
            pool,
            _db_guard: db_guard,
            router,
            ack_signer,
            sender_ds_did,
            sender_ds_key,
            sequencer_ds_did,
            sequencer_ds_key,
        }
    }

    fn mint_jwt(&self, endpoint_nsid: &str) -> String {
        self.mint_jwt_for(&self.sender_ds_did, &self.sender_ds_key, endpoint_nsid)
    }

    fn mint_jwt_for(&self, did: &str, key: &P256SigningKey, endpoint_nsid: &str) -> String {
        let now = Utc::now().timestamp();
        sign_jwt(
            json!({"alg":"ES256","typ":"JWT","kid":format!("{}#atproto", did)}),
            json!({
                "iss": did,
                "sub": did,
                "aud": LOCAL_DS_DID,
                "lxm": endpoint_nsid,
                "iat": now,
                "exp": now + 60,
                "jti": Uuid::new_v4().to_string(),
            }),
            key,
        )
    }

    async fn send_json(
        &self,
        uri: &str,
        jwt: Option<&str>,
        body: &Value,
    ) -> (StatusCode, Value, HeaderMap) {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = jwt {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let body_bytes = serde_json::to_vec(body).unwrap();
        let request = builder.body(Body::from(body_bytes)).unwrap();
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("router response");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("collect response body");
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, value, headers)
    }
}
fn make_tree_summary_bytes(
    tree_hash: &[u8; 32],
    leaves: &[(u32, &[u8], &[u8], &[u8])],
) -> (Vec<u8>, [u8; 32]) {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"CBTSUM01");
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(tree_hash);
    bytes.extend_from_slice(&(leaves.len() as u16).to_be_bytes());
    for (leaf_index, cred, sig_key, enc_key) in leaves {
        bytes.extend_from_slice(&leaf_index.to_be_bytes());
        bytes.extend_from_slice(&(cred.len() as u16).to_be_bytes());
        bytes.extend_from_slice(cred);
        bytes.extend_from_slice(sig_key);
        bytes.extend_from_slice(enc_key);
    }
    let sha256: [u8; 32] = Sha256::digest(&bytes).into();
    (bytes, sha256)
}

fn corpus_file(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/crypto-wire")
        .join(name);
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("failed to read corpus file {name} at {path:?}: {e}"))
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value)
        .expect("valid hex string")
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N}-byte array"))
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> &'a [u8] {
    let slice = &bytes[*offset..*offset + len];
    *offset += len;
    slice
}

fn take_u16(bytes: &[u8], offset: &mut usize) -> u16 {
    u16::from_be_bytes(take(bytes, offset, 2).try_into().expect("two bytes"))
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> u32 {
    u32::from_be_bytes(take(bytes, offset, 4).try_into().expect("four bytes"))
}

fn snapshot_records(bytes: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut offset = 0;
    let _magic: [u8; 8] = take(bytes, &mut offset, 8).try_into().expect("magic");
    let _schema = take_u16(bytes, &mut offset);
    let openmls_len = usize::from(take_u16(bytes, &mut offset));
    let _openmls = take(bytes, &mut offset, openmls_len).to_vec();
    let storage_len = usize::from(take_u16(bytes, &mut offset));
    let _storage = take(bytes, &mut offset, storage_len).to_vec();
    let count = usize::try_from(take_u32(bytes, &mut offset)).expect("record count");
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let key_len = usize::try_from(take_u32(bytes, &mut offset)).expect("key length");
        let key = take(bytes, &mut offset, key_len).to_vec();
        let value_len = usize::try_from(take_u32(bytes, &mut offset)).expect("value length");
        let value = take(bytes, &mut offset, value_len).to_vec();
        records.push((key, value));
    }
    assert_eq!(offset, bytes.len(), "frozen snapshot is exact");
    records
}

fn json_bytes(value: &serde_json::Value) -> Vec<u8> {
    value
        .as_array()
        .expect("byte array")
        .iter()
        .map(|byte| u8::try_from(byte.as_u64().expect("byte")).expect("u8"))
        .collect()
}

fn extract_tree_summary_from_snapshot(encoded: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let records = snapshot_records(encoded);
    let group_context: serde_json::Value = records
        .iter()
        .find(|(key, _)| key.starts_with(b"GroupContext"))
        .map(|(_, value)| serde_json::from_slice(value).expect("GroupContext json"))
        .expect("GroupContext record");
    let tree_hash: [u8; 32] = json_bytes(&group_context["tree_hash"]["vec"])
        .try_into()
        .expect("32-byte tree hash");
    let tree: serde_json::Value = records
        .iter()
        .find(|(key, _)| key.starts_with(b"Tree"))
        .map(|(_, value)| serde_json::from_slice(value).expect("Tree json"))
        .expect("Tree record");
    let mut leaves: Vec<(u32, Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    for (leaf_index, stored) in tree["tree"]["leaf_nodes"]
        .as_array()
        .expect("leaf array")
        .iter()
        .enumerate()
    {
        if let Some(node) = stored.get("node") {
            if !node.is_null() {
                let payload = &node["payload"];
                let cred =
                    json_bytes(&payload["credential"]["serialized_credential_content"]["vec"]);
                let sig_key = json_bytes(&payload["signature_key"]["value"]["vec"]);
                let enc_key = json_bytes(&payload["encryption_key"]["key"]["vec"]);
                leaves.push((
                    u32::try_from(leaf_index).expect("leaf index"),
                    cred,
                    sig_key,
                    enc_key,
                ));
            }
        }
    }
    let leaf_slices: Vec<(u32, &[u8], &[u8], &[u8])> = leaves
        .iter()
        .map(|(idx, c, s, e)| (*idx, c.as_slice(), s.as_slice(), e.as_slice()))
        .collect();
    make_tree_summary_bytes(&tree_hash, &leaf_slices)
}
async fn seed_corpus_conversation_at_added(
    pool: &DbPool,
    sender_ds_did: &str,
    sequencer_ds: Option<&str>,
    now: DateTime<Utc>,
) -> (
    Uuid,
    Uuid,
    Uuid,
    TestActor,
    TestActor,
    Vec<u8>,
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
) {
    let manifest_bytes = corpus_file("manifest.json");
    let manifest: Value = serde_json::from_slice(&manifest_bytes).expect("parse manifest.json");

    // Verify manifest artifact checksums and lengths before use
    for (file_name, expected_sha, expected_len) in [
        (
            "genesis-public-state.bin",
            "121f07a1fad006427587a544509ce0948775870023a1ca9bdf4d94ace5804c74",
            6849,
        ),
        (
            "committed-public-state.bin",
            "dff1863e208b53d428e97e57fb35b8367c5a43d911f2aeb0ddd67f9564c5a4c5",
            16731,
        ),
        (
            "commit-generic-public.mls",
            "c7dfa6ffe408d0b7f3443726e98ee874267ffd55dcee60b898c933f5a6dbd36f",
            4369,
        ),
        (
            "group-info.mls",
            "5aa545909adf7a81ab77f48094590a38b92edaf2a2eac74fd08236e703e17395",
            2838,
        ),
    ] {
        let bytes = corpus_file(file_name);
        assert_eq!(
            bytes.len(),
            expected_len,
            "corpus file {file_name} length mismatch"
        );
        let digest = hex::encode(Sha256::digest(&bytes));
        assert_eq!(
            digest, expected_sha,
            "corpus file {file_name} sha256 mismatch"
        );
    }

    let creation_time = now - chrono::Duration::minutes(2);
    let actor_seed_time = creation_time - chrono::Duration::minutes(5);

    let alice = TestActor::from_corpus_alice(&manifest);
    alice.seed(pool, actor_seed_time).await;

    let bob = TestActor::from_corpus_bob(&manifest);
    bob.seed(pool, actor_seed_time).await;
    let chain = &manifest["chain"];
    let convo_id =
        Uuid::parse_str(manifest["identifiers"]["conversationId"].as_str().unwrap()).unwrap();
    let group_id: [u8; 32] = hex_array(chain["groupIdHex"].as_str().unwrap());
    let genesis_group_context_hash: [u8; 32] =
        hex_array(chain["genesisGroupContextHashHex"].as_str().unwrap());
    let genesis_confirmation_tag: [u8; 32] =
        hex_array(chain["genesisConfirmationTagHex"].as_str().unwrap());
    let committed_group_context_hash: [u8; 32] =
        hex_array(chain["committedGroupContextHashHex"].as_str().unwrap());
    let committed_confirmation_tag: [u8; 32] =
        hex_array(chain["committedConfirmationTagHex"].as_str().unwrap());
    let generic_group_context_hash: [u8; 32] = hex_array(
        chain["genericCommittedGroupContextHashHex"]
            .as_str()
            .unwrap(),
    );
    let generic_confirmation_tag: [u8; 32] = hex_array(
        chain["genericCommittedConfirmationTagHex"]
            .as_str()
            .unwrap(),
    );
    let key_package_ref: [u8; 32] = hex_array(chain["innerKeyPackageRefHex"].as_str().unwrap());
    let key_package_wrapper = vec![0x77u8; 32];
    let creation_transition_id =
        Uuid::parse_str(manifest["creation"]["transitionId"].as_str().unwrap()).unwrap();
    let creation_entry_id = creation_transition_id;
    let generic_transition_id = Uuid::parse_str(
        manifest["identifiers"]["genericTransitionId"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    let genesis_snapshot = corpus_file("genesis-public-state.bin");
    let committed_snapshot = corpus_file("committed-public-state.bin");
    let group_info = corpus_file("group-info.mls");

    let (genesis_tree_summary, genesis_tree_summary_sha) =
        extract_tree_summary_from_snapshot(&genesis_snapshot);
    let (committed_tree_summary, committed_tree_summary_sha) =
        extract_tree_summary_from_snapshot(&committed_snapshot);

    let alice_period_id = Uuid::new_v4();
    let bob_period_id = Uuid::new_v4();
    let alice_leaf_period_id = Uuid::new_v4();
    let bob_leaf_period_id = Uuid::new_v4();
    let metadata_snapshot_id = Uuid::new_v4();
    let metadata_ciphertext = vec![0x88u8; 48];
    let (_, signed_req_bytes) = make_creation_body_with_invitee(
        convo_id,
        creation_entry_id,
        &alice,
        Some(&bob),
        &group_id,
        &genesis_group_context_hash,
        &genesis_confirmation_tag,
        &group_info,
        &metadata_ciphertext,
        creation_time,
    );
    let mutation = decode_and_verify_signed_mutation(&signed_req_bytes, &alice.public_key).unwrap();
    let signed_request = signed_req_bytes.clone();
    let request_digest = mutation.request_digest().to_vec();
    let signature = mutation.signature().to_vec();
    let unsigned_projection = mutation.canonical_projection().to_vec();
    let signing_transcript = mutation.transcript_bytes().to_vec();

    let received_at = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&creation_time.to_rfc3339_opts(SecondsFormat::Millis, true))
            .unwrap(),
    );
    let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.createConversation").unwrap();
    let server_fields = CanonicalControlServerFields::empty(ControlEntryKind::Creation).unwrap();
    let built = build_verified_control_entry(
        mutation,
        &endpoint,
        CanonicalUuidV4::parse(&creation_entry_id.to_string()).unwrap(),
        CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
        1,
        &received_at,
        server_fields,
    )
    .unwrap();
    let products = CanonicalControlEntryProducts::mint(&built).unwrap();
    let entry_bytes = products.durable_json().to_vec();
    let outer_fp = *built.outer_control_fingerprint();
    let creation_fingerprint = outer_fp.to_vec();
    let accepted_payload = entry_bytes.clone();

    let inv_transition_id = Uuid::new_v4();
    let inv_entry_id = Uuid::new_v4();
    let _sv1_metadata_snapshot_id = Uuid::new_v4();

    let acc_transition_id = Uuid::new_v4();
    let acc_entry_id = Uuid::new_v4();
    let _sv2_metadata_snapshot_id = Uuid::new_v4();

    let add_transition_id = Uuid::new_v4();
    let add_entry_id = Uuid::new_v4();
    let sv3_metadata_snapshot_id = Uuid::new_v4();
    let recovery_request_id = Uuid::new_v4();
    let _recovery_req_time = now - chrono::Duration::minutes(1);

    let (_, acc_signed_req_bytes) = make_acceptance_body(
        convo_id,
        acc_transition_id,
        recovery_request_id,
        creation_transition_id,
        &bob,
        &alice,
        &group_id,
        &genesis_group_context_hash,
        &genesis_confirmation_tag,
        creation_time,
    );
    let acc_mutation =
        decode_and_verify_signed_mutation(&acc_signed_req_bytes, &bob.public_key).unwrap();
    let acc_signed_request = acc_signed_req_bytes.clone();
    let acc_received_at = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&creation_time.to_rfc3339_opts(SecondsFormat::Millis, true))
            .unwrap(),
    );
    let acc_endpoint = ValidatedChatNsid::parse("blue.catbird.chat.acceptConversation").unwrap();
    let recovery_json = serde_json::json!({
        "recovery": {
            "recoveryRequestId": recovery_request_id.to_string(),
            "conversationId": convo_id.to_string(),
            "requesterDid": bob.did,
            "requesterDeviceId": bob.device_id.to_string(),
            "recoveryKind": "add",
            "boundCoordinate": {
                "conversationId": convo_id.to_string(),
                "generation": 0,
                "stateVersion": 2,
                "groupId": { "$bytes": STANDARD.encode(&group_id) },
                "epoch": 0,
                "groupContextHash": { "$bytes": STANDARD.encode(&genesis_group_context_hash) },
                "confirmationTag": { "$bytes": STANDARD.encode(&genesis_confirmation_tag) },
                "lifecycle": "active"
            },
            "reservation": {
                "recoveryRequestId": recovery_request_id.to_string(),
                "conversationId": convo_id.to_string(),
                "boundCoordinate": {
                    "conversationId": convo_id.to_string(),
                    "generation": 0,
                    "stateVersion": 2,
                    "groupId": { "$bytes": STANDARD.encode(&group_id) },
                    "epoch": 0,
                    "groupContextHash": { "$bytes": STANDARD.encode(&genesis_group_context_hash) },
                    "confirmationTag": { "$bytes": STANDARD.encode(&genesis_confirmation_tag) },
                    "lifecycle": "active"
                },
                "requesterDid": bob.did,
                "requesterDeviceId": bob.device_id.to_string(),
                "requesterKeyId": bob.key_id,
                "requesterAuthGeneration": 1,
                "keyPackageRef": { "$bytes": STANDARD.encode(&key_package_ref) },
                "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                "purpose": "leafRecovery",
                "status": "active",
                "expiresAt": (creation_time + chrono::Duration::minutes(5)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "keyPackage": {
                    "framing": "mlsMessage",
                    "contentType": "keyPackage",
                    "bytes": { "$bytes": STANDARD.encode(&key_package_wrapper) },
                    "sha256": { "$bytes": STANDARD.encode(Sha256::digest(&key_package_wrapper)) },
                    "keyPackageRef": { "$bytes": STANDARD.encode(&key_package_ref) }
                }
            },
            "status": "open",
            "requestedAt": creation_time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expiresAt": (creation_time + chrono::Duration::minutes(5)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        }
    });
    let acc_server_fields = CanonicalControlServerFields::decode(
        ControlEntryKind::ParticipantAcceptance,
        &serde_json::to_vec(&recovery_json).unwrap(),
    )
    .unwrap();
    let acc_built = build_verified_control_entry(
        acc_mutation,
        &acc_endpoint,
        CanonicalUuidV4::parse(&acc_entry_id.to_string()).unwrap(),
        CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
        3,
        &acc_received_at,
        acc_server_fields,
    )
    .unwrap();
    let acc_products = CanonicalControlEntryProducts::mint(&acc_built).unwrap();
    let acc_entry_bytes = acc_products.durable_json().to_vec();
    let acc_outer_fp = *acc_built.outer_control_fingerprint();
    let add_commit_bytes = corpus_file("commit-public.mls");
    let welcome_id = Uuid::new_v4();
    let (_, add_signed_req_bytes) = make_corpus_leaf_recovery_fulfillment_body(
        convo_id,
        add_transition_id,
        recovery_request_id,
        welcome_id,
        creation_transition_id,
        &alice,
        &bob,
        &group_id,
        &genesis_group_context_hash,
        &genesis_confirmation_tag,
        &committed_group_context_hash,
        &committed_confirmation_tag,
        &key_package_ref,
        &add_commit_bytes,
        &metadata_ciphertext,
        now,
    );
    let add_mutation =
        decode_and_verify_signed_mutation(&add_signed_req_bytes, &alice.public_key).unwrap();
    let add_signed_request = add_signed_req_bytes.clone();
    let add_received_at = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&now.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
    );
    let add_endpoint = ValidatedChatNsid::parse("blue.catbird.chat.submitTransition").unwrap();
    let add_server_fields =
        CanonicalControlServerFields::empty(ControlEntryKind::LeafRecoveryFulfillment).unwrap();
    let add_built = build_verified_control_entry(
        add_mutation,
        &add_endpoint,
        CanonicalUuidV4::parse(&add_entry_id.to_string()).unwrap(),
        CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
        4,
        &add_received_at,
        add_server_fields,
    )
    .unwrap();
    let add_products = CanonicalControlEntryProducts::mint(&add_built).unwrap();
    let add_entry_bytes = add_products.durable_json().to_vec();
    let add_outer_fp = *add_built.outer_control_fingerprint();

    let mut tx = pool.begin().await.unwrap();
    let is_remote = sequencer_ds.is_some();
    sqlx::query(
        r#"
        INSERT INTO chat.conversations (
            conversation_id, kind, lifecycle, current_generation, current_state_version,
            next_entry_seq, created_at, is_remote, sequencer_ds, sequencer_term
        ) VALUES (
            $1, 'group', 'active', 0, 3,
            5, $2, $3, $4, 1
        )
        "#,
    )
    .bind(convo_id)
    .bind(creation_time)
    .bind(is_remote)
    .bind(sequencer_ds)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.generations (
            conversation_id, generation, group_id, lifecycle, genesis_group_info_bytes,
            genesis_group_info_sha256, current_state_version, activated_seq, activated_at
        ) VALUES (
            $1, 0, $2, 'active', $3, $4, 3, 1, $5
        )
        "#,
    )
    .bind(convo_id)
    .bind(&group_id[..])
    .bind(&group_info)
    .bind(Sha256::digest(&group_info).to_vec())
    .bind(creation_time)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Transition 1: creation (state version 0, seq 1)
    sqlx::query(
        r#"
        INSERT INTO chat.transitions (
            transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id,
            actor_auth_generation, actor_role, actor_device_status, signed_request_bytes,
            unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature,
            next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at
        ) VALUES (
            $1, $2, 'creation', $3, $4, $5,
            1, 'admin', 'active', $6,
            $7, $8, $9, $10,
            0, 0, $11, 1, $12
        )
        "#,
    )
    .bind(creation_transition_id)
    .bind(convo_id)
    .bind(&alice.did)
    .bind(alice.device_id)
    .bind(&alice.key_id)
    .bind(&signed_request)
    .bind(&unsigned_projection)
    .bind(&signing_transcript)
    .bind(&request_digest)
    .bind(&signature)
    .bind(metadata_snapshot_id)
    .bind(creation_time)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Transition 2: invitation policy (state version 1, seq 2)
    sqlx::query(
        r#"
        INSERT INTO chat.transitions (
            transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id,
            actor_auth_generation, actor_role, actor_device_status, signed_request_bytes,
            unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature,
            prior_generation, prior_state_version,
            next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at
        ) VALUES (
            $1, $2, 'policy', $3, $4, $5,
            1, 'admin', 'active', $6,
            $7, $8, $9, $10,
            0, 0,
            0, 1, NULL, 2, $11
        )
        "#,
    )
    .bind(inv_transition_id)
    .bind(convo_id)
    .bind(&alice.did)
    .bind(alice.device_id)
    .bind(&alice.key_id)
    .bind(&signed_request)
    .bind(&unsigned_projection)
    .bind(&signing_transcript)
    .bind(&request_digest)
    .bind(&signature)
    .bind(creation_time)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Transition 3: acceptance (state version 2, seq 3)
    sqlx::query(
        r#"
        INSERT INTO chat.transitions (
            transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id,
            actor_auth_generation, actor_role, actor_device_status, signed_request_bytes,
            unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature,
            prior_generation, prior_state_version,
            next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at
        ) VALUES (
            $1, $2, 'acceptConversation', $3, $4, $5,
            1, 'member', 'active', $6,
            $7, $8, $9, $10,
            0, 1,
            0, 2, NULL, 3, $11
        )
        "#,
    )
    .bind(acc_transition_id)
    .bind(convo_id)
    .bind(&bob.did)
    .bind(bob.device_id)
    .bind(&bob.key_id)
    .bind(&acc_signed_request)
    .bind(acc_built.mutation().canonical_projection())
    .bind(acc_built.mutation().transcript_bytes())
    .bind(acc_built.mutation().request_digest().as_slice())
    .bind(acc_built.mutation().signature().as_slice())
    .bind(creation_time)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Transition 4: add commit (state version 3, seq 4)
    sqlx::query(
        r#"
        INSERT INTO chat.transitions (
            transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id,
            actor_auth_generation, actor_role, actor_device_status, signed_request_bytes,
            unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature,
            prior_generation, prior_state_version,
            next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at
        ) VALUES (
            $1, $2, 'leafRecovery', $3, $4, $5,
            1, 'admin', 'active', $6,
            $7, $8, $9, $10,
            0, 2,
            0, 3, $11, 4, $12
        )
        "#,
    )
    .bind(add_transition_id)
    .bind(convo_id)
    .bind(&alice.did)
    .bind(alice.device_id)
    .bind(&alice.key_id)
    .bind(&add_signed_request)
    .bind(add_built.mutation().canonical_projection())
    .bind(add_built.mutation().transcript_bytes())
    .bind(add_built.mutation().request_digest().as_slice())
    .bind(add_built.mutation().signature().as_slice())
    .bind(sv3_metadata_snapshot_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // State version 0 (creation)
    sqlx::query(
        r#"
        INSERT INTO chat.generation_states (
            conversation_id, generation, state_version, group_id, epoch,
            group_context_hash, confirmation_tag, lifecycle, state_kind,
            producing_transition_id, public_snapshot_bytes, snapshot_sha256,
            tree_summary_bytes, tree_summary_sha256, leaf_count, created_at
        ) VALUES (
            $1, 0, 0, $2, 0,
            $3, $4, 'active', 'creation',
            $5, $6, $7,
            $8, $9, 1, $10
        )
        "#,
    )
    .bind(convo_id)
    .bind(&group_id[..])
    .bind(&genesis_group_context_hash[..])
    .bind(&genesis_confirmation_tag[..])
    .bind(creation_transition_id)
    .bind(&genesis_snapshot)
    .bind(Sha256::digest(&genesis_snapshot).to_vec())
    .bind(&genesis_tree_summary)
    .bind(&genesis_tree_summary_sha[..])
    .bind(creation_time)
    .execute(&mut *tx)
    .await
    .unwrap();

    // State version 1 (invitation)
    sqlx::query(
        r#"
        INSERT INTO chat.generation_states (
            conversation_id, generation, state_version, group_id, epoch,
            group_context_hash, confirmation_tag, lifecycle, state_kind,
            producing_transition_id, public_snapshot_bytes, snapshot_sha256,
            tree_summary_bytes, tree_summary_sha256, leaf_count, created_at
        ) VALUES (
            $1, 0, 1, $2, 0,
            $3, $4, 'active', 'policy',
            $5, $6, $7,
            $8, $9, 1, $10
        )
        "#,
    )
    .bind(convo_id)
    .bind(&group_id[..])
    .bind(&genesis_group_context_hash[..])
    .bind(&genesis_confirmation_tag[..])
    .bind(inv_transition_id)
    .bind(&genesis_snapshot)
    .bind(Sha256::digest(&genesis_snapshot).to_vec())
    .bind(&genesis_tree_summary)
    .bind(&genesis_tree_summary_sha[..])
    .bind(creation_time)
    .execute(&mut *tx)
    .await
    .unwrap();

    // State version 2 (acceptance)
    sqlx::query(
        r#"
        INSERT INTO chat.generation_states (
            conversation_id, generation, state_version, group_id, epoch,
            group_context_hash, confirmation_tag, lifecycle, state_kind,
            producing_transition_id, public_snapshot_bytes, snapshot_sha256,
            tree_summary_bytes, tree_summary_sha256, leaf_count, created_at
        ) VALUES (
            $1, 0, 2, $2, 0,
            $3, $4, 'active', 'acceptConversation',
            $5, $6, $7,
            $8, $9, 1, $10
        )
        "#,
    )
    .bind(convo_id)
    .bind(&group_id[..])
    .bind(&genesis_group_context_hash[..])
    .bind(&genesis_confirmation_tag[..])
    .bind(acc_transition_id)
    .bind(&genesis_snapshot)
    .bind(Sha256::digest(&genesis_snapshot).to_vec())
    .bind(&genesis_tree_summary)
    .bind(&genesis_tree_summary_sha[..])
    .bind(creation_time)
    .execute(&mut *tx)
    .await
    .unwrap();

    // State version 3 (added)
    sqlx::query(
        r#"
        INSERT INTO chat.generation_states (
            conversation_id, generation, state_version, group_id, epoch,
            group_context_hash, confirmation_tag, lifecycle, state_kind,
            producing_transition_id, public_snapshot_bytes, snapshot_sha256,
            tree_summary_bytes, tree_summary_sha256, leaf_count, created_at
        ) VALUES (
            $1, 0, 3, $2, 1,
            $3, $4, 'active', 'commit',
            $5, $6, $7,
            $8, $9, 2, $10
        )
        "#,
    )
    .bind(convo_id)
    .bind(&group_id[..])
    .bind(&committed_group_context_hash[..])
    .bind(&committed_confirmation_tag[..])
    .bind(add_transition_id)
    .bind(&committed_snapshot)
    .bind(Sha256::digest(&committed_snapshot).to_vec())
    .bind(&committed_tree_summary)
    .bind(&committed_tree_summary_sha[..])
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Participants: Alice (admin, routed to sender_ds_did) and Bob (admin)
    sqlx::query(
        r#"
        INSERT INTO chat.participants (
            participant_period_id, conversation_id, user_did, status, role,
            role_transition_id, role_changed_at, created_by_did, created_by_device_id,
            current_membership, created_at, ds_did
        ) VALUES (
            $1, $2, $3, 'active', 'admin',
            $4, $5, $3, $6,
            TRUE, $5, $7
        )
        "#,
    )
    .bind(alice_period_id)
    .bind(convo_id)
    .bind(&alice.did)
    .bind(creation_transition_id)
    .bind(creation_time)
    .bind(alice.device_id)
    .bind(Some(sender_ds_did))
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.participants (
            participant_period_id, conversation_id, user_did, status, role,
            role_transition_id, role_changed_at, created_by_did, created_by_device_id,
            invitation_transition_id, invitation_entry_id, invited_at,
            acceptance_transition_id, acceptance_entry_id, accepted_at,
            current_membership, created_at, ds_did
        ) VALUES (
            $1, $2, $3, 'active', 'member',
            $4, $5, $6, $7,
            $4, $8, $5,
            $9, $10, $5,
            TRUE, $5, NULL
        )
        "#,
    )
    .bind(bob_period_id)
    .bind(convo_id)
    .bind(&bob.did)
    .bind(creation_transition_id)
    .bind(creation_time)
    .bind(&alice.did)
    .bind(alice.device_id)
    .bind(creation_entry_id)
    .bind(acc_transition_id)
    .bind(acc_entry_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.leaf_recovery_requests (
            recovery_request_id, conversation_id, generation, requester_did,
            requester_device_id, requester_key_id, requester_auth_generation,
            recovery_kind, source, bound_state_version, bound_group_id, bound_epoch,
            bound_group_context_hash, bound_confirmation_tag, reservation_request_id,
            status, fulfilling_transition_id, terminal_at,
            signed_request_bytes, signing_transcript_bytes, request_digest, signature,
            requested_at, expires_at
        ) VALUES (
            $1, $2, 0, $3,
            $4, $5, 1,
            'add', 'acceptConversation', 2, $6, 0,
            $7, $8, $1,
            'fulfilled', $9, $10,
            $11, $12, $13, $14,
            $15, $15 + INTERVAL '5 minutes'
        )
        "#,
    )
    .bind(recovery_request_id)
    .bind(convo_id)
    .bind(&bob.did)
    .bind(bob.device_id)
    .bind(&bob.key_id)
    .bind(&group_id[..])
    .bind(&genesis_group_context_hash[..])
    .bind(&genesis_confirmation_tag[..])
    .bind(add_transition_id)
    .bind(now)
    .bind(&acc_signed_request)
    .bind(acc_built.mutation().transcript_bytes())
    .bind(acc_built.mutation().request_digest().as_slice())
    .bind(acc_built.mutation().signature().as_slice())
    .bind(creation_time)
    .execute(&mut *tx)
    .await
    .unwrap();

    let alice_cred = format!("{}#{}", alice.did, alice.device_id).into_bytes();
    sqlx::query(
        r#"
        INSERT INTO chat.member_devices (
            leaf_period_id, participant_period_id, conversation_id, generation,
            user_did, device_id, leaf_index, basic_credential,
            leaf_signature_key, leaf_key_id, leaf_auth_generation, origin,
            joined_state_version, joined_transition_id, joined_seq, active, created_at
        ) VALUES (
            $1, $2, $3, 0,
            $4, $5, 0, $6,
            $7, $8, 1, 'genesis',
            0, $9, 1, TRUE, $10
        )
        "#,
    )
    .bind(alice_leaf_period_id)
    .bind(alice_period_id)
    .bind(convo_id)
    .bind(&alice.did)
    .bind(alice.device_id)
    .bind(&alice_cred)
    .bind(&alice.public_key[..])
    .bind(&alice.key_id)
    .bind(creation_transition_id)
    .bind(creation_time)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO chat.key_packages (
            key_package_ref, wrapper_bytes, wrapper_sha256, init_key,
            owner_did, owner_device_id, owner_key_id, owner_auth_generation,
            not_before, not_after, status, terminal_transition_id, terminal_at, created_at
        ) VALUES (
            $1, $2, $3, $4,
            $5, $6, $7, 1,
            $8 - INTERVAL '5 minutes', $8 + INTERVAL '24 hours', 'consumed', $9, $8, $8
        )
        "#,
    )
    .bind(&key_package_ref[..])
    .bind(&key_package_wrapper)
    .bind(Sha256::digest(&key_package_wrapper).to_vec())
    .bind(vec![0x6bu8; 32])
    .bind(&bob.did)
    .bind(bob.device_id)
    .bind(&bob.key_id)
    .bind(now)
    .bind(add_transition_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.key_package_reservations (
            recovery_request_id, key_package_ref, conversation_id, generation, requester_did,
            requester_device_id, requester_key_id, requester_auth_generation, recipient_did,
            recipient_device_id, bound_state_version, bound_group_id, bound_epoch,
            bound_group_context_hash, bound_confirmation_tag, purpose, expires_at, status,
            consumed_transition_id, terminal_at, created_at
        ) VALUES (
            $1, $2, $3, 0, $4,
            $5, $6, 1, $4,
            $5, 2, $7, 0,
            $8, $9, 'leafRecovery', $12 + INTERVAL '5 minutes', 'consumed',
            $11, $10, $12
        )
        "#,
    )
    .bind(recovery_request_id)
    .bind(&key_package_ref[..])
    .bind(convo_id)
    .bind(&bob.did)
    .bind(bob.device_id)
    .bind(&bob.key_id)
    .bind(&group_id[..])
    .bind(&genesis_group_context_hash[..])
    .bind(&genesis_confirmation_tag[..])
    .bind(now)
    .bind(add_transition_id)
    .bind(creation_time)
    .execute(&mut *tx)
    .await
    .unwrap();
    let welcome_bytes = vec![0x33u8; 64];
    let welcome_sha256: [u8; 32] = Sha256::digest(&welcome_bytes).into();
    sqlx::query(
        r#"
        INSERT INTO chat.welcome_bundles (
            welcome_id, conversation_id, transition_id, entry_seq, generation, state_version,
            group_id, epoch, group_context_hash, confirmation_tag,
            wrapper_bytes, wrapper_sha256, created_at
        ) VALUES (
            $1, $2, $3, 4, 0, 3,
            $4, 1, $5, $6,
            $7, $8, $9
        )
        "#,
    )
    .bind(welcome_id)
    .bind(convo_id)
    .bind(add_transition_id)
    .bind(&group_id[..])
    .bind(&committed_group_context_hash[..])
    .bind(&committed_confirmation_tag[..])
    .bind(&welcome_bytes)
    .bind(&welcome_sha256[..])
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.welcome_deliveries (
            welcome_id, recipient_did, recipient_device_id, recovery_request_id,
            key_package_ref, expires_at, status, terminal_at
        ) VALUES (
            $1, $2, $3, $4,
            $5, $6 + INTERVAL '24 hours', 'pending', NULL
        )
        "#,
    )
    .bind(welcome_id)
    .bind(&bob.did)
    .bind(bob.device_id)
    .bind(recovery_request_id)
    .bind(&key_package_ref[..])
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();
    let bob_cred = format!("{}#{}", bob.did, bob.device_id).into_bytes();
    sqlx::query(
        r#"
        INSERT INTO chat.member_devices (
            leaf_period_id, participant_period_id, conversation_id, generation,
            user_did, device_id, leaf_index, basic_credential,
            leaf_signature_key, leaf_key_id, leaf_auth_generation, origin,
            joined_state_version, joined_transition_id, joined_seq, active,
            join_key_package_ref, created_at
        ) VALUES (
            $1, $2, $3, 0,
            $4, $5, 1, $6,
            $7, $8, 1, 'keyPackage',
            3, $9, 4, TRUE,
            $10, $11
        )
        "#,
    )
    .bind(bob_leaf_period_id)
    .bind(bob_period_id)
    .bind(convo_id)
    .bind(&bob.did)
    .bind(bob.device_id)
    .bind(&bob_cred)
    .bind(&bob.public_key[..])
    .bind(&bob.key_id)
    .bind(add_transition_id)
    .bind(&key_package_ref[..])
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Metadata snapshots at state versions 0..=3
    sqlx::query(
        r#"
        INSERT INTO chat.metadata_snapshots (
            metadata_snapshot_id, conversation_id, generation, state_version,
            group_id, epoch, group_context_hash, confirmation_tag,
            producing_transition_id, origin_transition_id, metadata_version,
            nonce, ciphertext, ciphertext_sha256, ciphertext_size,
            author_did, author_device_id, author_key_id, author_public_key,
            author_auth_generation, author_origin_seq, author_role, author_device_status, created_at
        ) VALUES (
            $1, $2, 0, 0,
            $3, 0, $4, $5,
            $6, $6, 1,
            $7, $8, $9, $10,
            $11, $12, $13, $14,
            1, 1, 'admin', 'active', $15
        )
        "#,
    )
    .bind(metadata_snapshot_id)
    .bind(convo_id)
    .bind(&group_id[..])
    .bind(&genesis_group_context_hash[..])
    .bind(&genesis_confirmation_tag[..])
    .bind(creation_transition_id)
    .bind(vec![0x73u8; 12])
    .bind(&metadata_ciphertext)
    .bind(Sha256::digest(&metadata_ciphertext).to_vec())
    .bind(metadata_ciphertext.len() as i64)
    .bind(&alice.did)
    .bind(alice.device_id)
    .bind(&alice.key_id)
    .bind(&alice.public_key[..])
    .bind(creation_time)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO chat.metadata_snapshots (
            metadata_snapshot_id, conversation_id, generation, state_version,
            group_id, epoch, group_context_hash, confirmation_tag,
            producing_transition_id, origin_transition_id, metadata_version,
            nonce, ciphertext, ciphertext_sha256, ciphertext_size,
            author_did, author_device_id, author_key_id, author_public_key,
            author_auth_generation, author_origin_seq, author_role, author_device_status, created_at
        ) VALUES (
            $1, $2, 0, 3,
            $3, 1, $4, $5,
            $6, $7, 1,
            $8, $9, $10, $11,
            $12, $13, $14, $15,
            1, 1, 'admin', 'active', $16
        )
        "#,
    )
    .bind(sv3_metadata_snapshot_id)
    .bind(convo_id)
    .bind(&group_id[..])
    .bind(&committed_group_context_hash[..])
    .bind(&committed_confirmation_tag[..])
    .bind(add_transition_id)
    .bind(creation_transition_id)
    .bind(vec![0x77u8; 12])
    .bind(&metadata_ciphertext)
    .bind(Sha256::digest(&metadata_ciphertext).to_vec())
    .bind(metadata_ciphertext.len() as i64)
    .bind(&alice.did)
    .bind(alice.device_id)
    .bind(&alice.key_id)
    .bind(&alice.public_key[..])
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Entries 1..=4
    sqlx::query(
        r#"
        INSERT INTO chat.entries (
            conversation_id, seq, entry_id, entry_kind,
            accepted_payload_bytes, accepted_payload_sha256,
            signed_request_bytes, request_digest, signature,
            server_fields_bytes, outer_entry_fingerprint,
            actor_did, actor_device_id, actor_key_id, actor_auth_generation,
            generation, state_version, transition_id, received_at
        ) VALUES (
            $1, 1, $2, 'blue.catbird.chat.defs#creationEntry',
            $3, $4,
            $5, $6, $7,
            repeat('0', 1)::bytea, $8,
            $9, $10, $11, 1,
            0, 0, $12, $13
        )
        "#,
    )
    .bind(convo_id)
    .bind(creation_entry_id)
    .bind(&accepted_payload)
    .bind(Sha256::digest(&accepted_payload).to_vec())
    .bind(&signed_request)
    .bind(&request_digest)
    .bind(&signature)
    .bind(&creation_fingerprint)
    .bind(&alice.did)
    .bind(alice.device_id)
    .bind(&alice.key_id)
    .bind(creation_transition_id)
    .bind(creation_time)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.entries (
            conversation_id, seq, entry_id, entry_kind,
            accepted_payload_bytes, accepted_payload_sha256,
            signed_request_bytes, request_digest, signature,
            server_fields_bytes, outer_entry_fingerprint,
            actor_did, actor_device_id, actor_key_id, actor_auth_generation,
            generation, state_version, transition_id, received_at
        ) VALUES (
            $1, 2, $2, 'blue.catbird.chat.defs#policyEntry',
            $3, $4,
            $5, $6, $7,
            repeat('0', 1)::bytea, $8,
            $9, $10, $11, 1,
            0, 1, $12, $13
        )
        "#,
    )
    .bind(convo_id)
    .bind(inv_entry_id)
    .bind(&accepted_payload)
    .bind(Sha256::digest(&accepted_payload).to_vec())
    .bind(&signed_request)
    .bind(&request_digest)
    .bind(&signature)
    .bind(&creation_fingerprint)
    .bind(&alice.did)
    .bind(alice.device_id)
    .bind(&alice.key_id)
    .bind(inv_transition_id)
    .bind(creation_time)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.entries (
            conversation_id, seq, entry_id, entry_kind,
            accepted_payload_bytes, accepted_payload_sha256,
            signed_request_bytes, request_digest, signature,
            server_fields_bytes, outer_entry_fingerprint,
            actor_did, actor_device_id, actor_key_id, actor_auth_generation,
            generation, state_version, transition_id, received_at
        ) VALUES (
            $1, 3, $2, 'blue.catbird.chat.defs#participantAcceptanceEntry',
            $3, $4,
            $5, $6, $7,
            repeat('0', 1)::bytea, $8,
            $9, $10, $11, 1,
            0, 2, $12, $13
        )
        "#,
    )
    .bind(convo_id)
    .bind(acc_entry_id)
    .bind(&acc_entry_bytes)
    .bind(Sha256::digest(&acc_entry_bytes).to_vec())
    .bind(&acc_signed_request)
    .bind(acc_built.mutation().request_digest().as_slice())
    .bind(acc_built.mutation().signature().as_slice())
    .bind(&acc_outer_fp[..])
    .bind(&bob.did)
    .bind(bob.device_id)
    .bind(&bob.key_id)
    .bind(acc_transition_id)
    .bind(creation_time)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.entries (
            conversation_id, seq, entry_id, entry_kind,
            accepted_payload_bytes, accepted_payload_sha256,
            signed_request_bytes, request_digest, signature,
            server_fields_bytes, outer_entry_fingerprint,
            actor_did, actor_device_id, actor_key_id, actor_auth_generation,
            generation, state_version, transition_id, received_at
        ) VALUES (
            $1, 4, $2, 'blue.catbird.chat.defs#leafRecoveryFulfillmentEntry',
            $3, $4,
            $5, $6, $7,
            repeat('0', 1)::bytea, $8,
            $9, $10, $11, 1,
            0, 3, $12, $13
        )
        "#,
    )
    .bind(convo_id)
    .bind(add_entry_id)
    .bind(&add_entry_bytes)
    .bind(Sha256::digest(&add_entry_bytes).to_vec())
    .bind(&add_signed_request)
    .bind(add_built.mutation().request_digest().as_slice())
    .bind(add_built.mutation().signature().as_slice())
    .bind(&add_outer_fp[..])
    .bind(&alice.did)
    .bind(alice.device_id)
    .bind(&alice.key_id)
    .bind(add_transition_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Application intervals for Alice and Bob
    sqlx::query(
        r#"
        INSERT INTO chat.application_intervals (
            membership_interval_id, conversation_id, generation, recipient_did, recipient_device_id,
            start_seq, opening_kind, opening_transition_id, opening_outer_entry_fingerprint,
            opening_state_version, opening_group_id, opening_epoch, opening_group_context_hash,
            opening_confirmation_tag, opening_leaf_period_id, created_at
        ) VALUES (
            $1, $2, 0, $3, $4,
            1, 'creation', $1, $5,
            0, $6, 0, $7,
            $8, $9, $10
        )
        "#,
    )
    .bind(creation_transition_id)
    .bind(convo_id)
    .bind(&alice.did)
    .bind(alice.device_id)
    .bind(&creation_fingerprint)
    .bind(&group_id[..])
    .bind(&genesis_group_context_hash[..])
    .bind(&genesis_confirmation_tag[..])
    .bind(alice_leaf_period_id)
    .bind(creation_time)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.application_intervals (
            membership_interval_id, conversation_id, generation, recipient_did, recipient_device_id,
            start_seq, opening_kind, opening_transition_id, opening_outer_entry_fingerprint,
            opening_state_version, opening_group_id, opening_epoch, opening_group_context_hash,
            opening_confirmation_tag, opening_leaf_period_id, created_at
        ) VALUES (
            $1, $2, 0, $3, $4,
            4, 'add', $1, $5,
            3, $6, 1, $7,
            $8, $9, $10
        )
        "#,
    )
    .bind(add_transition_id)
    .bind(convo_id)
    .bind(&bob.did)
    .bind(bob.device_id)
    .bind(&add_outer_fp[..])
    .bind(&group_id[..])
    .bind(&committed_group_context_hash[..])
    .bind(&committed_confirmation_tag[..])
    .bind(bob_leaf_period_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    tx.commit().await.unwrap();

    (
        convo_id,
        creation_transition_id,
        generic_transition_id,
        alice,
        bob,
        group_id.to_vec(),
        committed_group_context_hash,
        committed_confirmation_tag,
        generic_group_context_hash,
        generic_confirmation_tag,
    )
}

async fn seed_conversation_structure(
    pool: &DbPool,
    convo_id: Uuid,
    group_id: &[u8],
    is_remote: bool,
    sequencer_ds: Option<&str>,
    sequencer_term: i64,
    creator: &TestActor,
    creator_ds_did: Option<&str>,
    now: DateTime<Utc>,
) -> (Uuid, Uuid, Vec<u8>, Vec<u8>, [u8; 32], [u8; 32]) {
    let mut tx = pool.begin().await.unwrap();
    let creation_transition_id = Uuid::new_v4();
    let creation_entry_id = creation_transition_id;
    let participant_period_id = Uuid::new_v4();
    let leaf_period_id = Uuid::new_v4();
    let metadata_snapshot_id = Uuid::new_v4();
    let group_context_hash = vec![0u8; 32];
    let confirmation_tag = vec![0u8; 32];
    let group_info = vec![0x99u8; 16];
    let snapshot = vec![0x88u8; 16];
    let metadata_ciphertext = vec![0x77u8; 16];
    let basic_credential = format!("{}#{}", creator.did, creator.device_id).into_bytes();
    let enc_key = vec![0x64u8; 1216];
    let (tree_summary, tree_summary_sha) = make_tree_summary_bytes(
        &[0x63u8; 32],
        &[(0, &basic_credential, &creator.public_key, &enc_key)],
    );

    let (_, signed_req_bytes) =
        make_creation_body(convo_id, creation_entry_id, creator, group_id, now);
    let mutation =
        decode_and_verify_signed_mutation(&signed_req_bytes, &creator.public_key).unwrap();
    let signed_request = signed_req_bytes.clone();
    let request_digest = mutation.request_digest().to_vec();
    let signature = mutation.signature().to_vec();
    let unsigned_projection = mutation.canonical_projection().to_vec();
    let signing_transcript = mutation.transcript_bytes().to_vec();

    let received_at = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&now.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
    );
    let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.createConversation").unwrap();
    let server_fields = CanonicalControlServerFields::empty(ControlEntryKind::Creation).unwrap();
    let built = build_verified_control_entry(
        mutation,
        &endpoint,
        CanonicalUuidV4::parse(&creation_entry_id.to_string()).unwrap(),
        CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
        1,
        &received_at,
        server_fields,
    )
    .unwrap();
    let products = CanonicalControlEntryProducts::mint(&built).unwrap();
    let entry_bytes = products.durable_json().to_vec();
    let entry_sha256: [u8; 32] = Sha256::digest(&entry_bytes).into();
    let outer_fp = *built.outer_control_fingerprint();
    let creation_fingerprint = outer_fp.to_vec();
    let accepted_payload = entry_bytes.clone();

    let seq_ds = if is_remote { sequencer_ds } else { None };

    sqlx::query(
        r#"
        INSERT INTO chat.conversations (
            conversation_id, kind, lifecycle, current_generation, current_state_version,
            next_entry_seq, created_at, is_remote, sequencer_ds, sequencer_term
        ) VALUES (
            $1, 'group', 'active', 0, 0,
            2, $2, $3, $4, $5
        )
        "#,
    )
    .bind(convo_id)
    .bind(now)
    .bind(is_remote)
    .bind(seq_ds)
    .bind(sequencer_term)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.generations (
            conversation_id, generation, group_id, lifecycle, genesis_group_info_bytes,
            genesis_group_info_sha256, current_state_version, activated_seq, activated_at
        ) VALUES (
            $1, 0, $2, 'active', $3, $4, 0, 1, $5
        )
        "#,
    )
    .bind(convo_id)
    .bind(group_id)
    .bind(&group_info)
    .bind(Sha256::digest(&group_info).to_vec())
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.transitions (
            transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id,
            actor_auth_generation, actor_role, actor_device_status, signed_request_bytes,
            unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature,
            next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at
        ) VALUES (
            $1, $2, 'creation', $3, $4, $5,
            1, 'admin', 'active', $6,
            $7, $8, $9, $10,
            0, 0, $11, 1, $12
        )
        "#,
    )
    .bind(creation_transition_id)
    .bind(convo_id)
    .bind(&creator.did)
    .bind(creator.device_id)
    .bind(&creator.key_id)
    .bind(&signed_request)
    .bind(&unsigned_projection)
    .bind(&signing_transcript)
    .bind(&request_digest)
    .bind(&signature)
    .bind(metadata_snapshot_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.generation_states (
            conversation_id, generation, state_version, group_id, epoch,
            group_context_hash, confirmation_tag, lifecycle, state_kind,
            producing_transition_id, public_snapshot_bytes, snapshot_sha256,
            tree_summary_bytes, tree_summary_sha256, leaf_count, created_at
        ) VALUES (
            $1, 0, 0, $2, 0,
            $3, $4, 'active', 'creation',
            $5, $6, $7,
            $8, $9, 1, $10
        )
        "#,
    )
    .bind(convo_id)
    .bind(group_id)
    .bind(&group_context_hash)
    .bind(&confirmation_tag)
    .bind(creation_transition_id)
    .bind(&snapshot)
    .bind(Sha256::digest(&snapshot).to_vec())
    .bind(&tree_summary)
    .bind(&tree_summary_sha[..])
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.participants (
            participant_period_id, conversation_id, user_did, status, role,
            role_transition_id, role_changed_at, created_by_did, created_by_device_id,
            current_membership, created_at, ds_did
        ) VALUES (
            $1, $2, $3, 'active', 'admin',
            $4, $5, $3, $6,
            TRUE, $5, $7
        )
        "#,
    )
    .bind(participant_period_id)
    .bind(convo_id)
    .bind(&creator.did)
    .bind(creation_transition_id)
    .bind(now)
    .bind(creator.device_id)
    .bind(creator_ds_did)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.member_devices (
            leaf_period_id, participant_period_id, conversation_id, generation,
            user_did, device_id, leaf_index, basic_credential,
            leaf_signature_key, leaf_key_id, leaf_auth_generation, origin,
            joined_state_version, joined_transition_id, joined_seq, active, created_at
        ) VALUES (
            $1, $2, $3, 0,
            $4, $5, 0, $6,
            $7, $8, 1, 'genesis',
            0, $9, 1, TRUE, $10
        )
        "#,
    )
    .bind(leaf_period_id)
    .bind(participant_period_id)
    .bind(convo_id)
    .bind(&creator.did)
    .bind(creator.device_id)
    .bind(&basic_credential)
    .bind(&creator.public_key[..])
    .bind(&creator.key_id)
    .bind(creation_transition_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.metadata_snapshots (
            metadata_snapshot_id, conversation_id, generation, state_version,
            group_id, epoch, group_context_hash, confirmation_tag,
            producing_transition_id, origin_transition_id, metadata_version,
            nonce, ciphertext, ciphertext_sha256, ciphertext_size,
            author_did, author_device_id, author_key_id, author_public_key,
            author_auth_generation, author_origin_seq, author_role, author_device_status, created_at
        ) VALUES (
            $1, $2, 0, 0,
            $3, 0, $4, $5,
            $6, $6, 1,
            repeat('n', 12)::bytea, $7, $8, 16,
            $9, $10, $11, $12,
            1, 1, 'admin', 'active', $13
        )
        "#,
    )
    .bind(metadata_snapshot_id)
    .bind(convo_id)
    .bind(group_id)
    .bind(&group_context_hash)
    .bind(&confirmation_tag)
    .bind(creation_transition_id)
    .bind(&metadata_ciphertext)
    .bind(Sha256::digest(&metadata_ciphertext).to_vec())
    .bind(&creator.did)
    .bind(creator.device_id)
    .bind(&creator.key_id)
    .bind(&creator.public_key[..])
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.entries (
            conversation_id, seq, entry_id, entry_kind,
            accepted_payload_bytes, accepted_payload_sha256,
            signed_request_bytes, request_digest, signature,
            server_fields_bytes, outer_entry_fingerprint,
            actor_did, actor_device_id, actor_key_id, actor_auth_generation,
            generation, state_version, transition_id, received_at
        ) VALUES (
            $1, 1, $2, 'blue.catbird.chat.defs#creationEntry',
            $3, $4,
            $5, $6, $7,
            repeat('0', 1)::bytea, $8,
            $9, $10, $11, 1,
            0, 0, $12, $13
        )
        "#,
    )
    .bind(convo_id)
    .bind(creation_entry_id)
    .bind(&accepted_payload)
    .bind(Sha256::digest(&accepted_payload).to_vec())
    .bind(&signed_request)
    .bind(&request_digest)
    .bind(&signature)
    .bind(&creation_fingerprint)
    .bind(&creator.did)
    .bind(creator.device_id)
    .bind(&creator.key_id)
    .bind(creation_transition_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.application_intervals (
            membership_interval_id, conversation_id, generation, recipient_did, recipient_device_id,
            start_seq, opening_kind, opening_transition_id, opening_outer_entry_fingerprint,
            opening_state_version, opening_group_id, opening_epoch, opening_group_context_hash,
            opening_confirmation_tag, opening_leaf_period_id, created_at
        ) VALUES (
            $1, $2, 0, $3, $4,
            1, 'creation', $1, $5,
            0, $6, 0, $7,
            $8, $9, $10
        )
        "#,
    )
    .bind(creation_transition_id)
    .bind(convo_id)
    .bind(&creator.did)
    .bind(creator.device_id)
    .bind(&creation_fingerprint)
    .bind(group_id)
    .bind(&group_context_hash)
    .bind(&confirmation_tag)
    .bind(leaf_period_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    tx.commit().await.unwrap();
    (
        creation_transition_id,
        creation_entry_id,
        signed_req_bytes,
        entry_bytes,
        entry_sha256,
        outer_fp,
    )
}

fn make_envelope_header_json(
    delivery_id: Uuid,
    convo_id: Uuid,
    sender_ds: &str,
    receiver_ds: &str,
    sequencer_ds: &str,
    sequencer_term: i64,
    payload_sha256: &[u8; 32],
) -> Value {
    json!({
        "protocolVersion": "1",
        "deliveryId": delivery_id.to_string(),
        "conversationId": convo_id.to_string(),
        "senderDsDid": sender_ds,
        "receiverDsDid": receiver_ds,
        "sequencerDid": sequencer_ds,
        "sequencerTerm": sequencer_term,
        "payloadSha256": { "$bytes": STANDARD.encode(payload_sha256) },
    })
}

fn make_entry_locator_json(
    entry_id: Uuid,
    seq: i64,
    accepted_payload_sha256: &[u8; 32],
    outer_entry_fingerprint: &[u8; 32],
) -> Value {
    json!({
        "entryId": entry_id.to_string(),
        "seq": seq,
        "acceptedPayloadSha256": { "$bytes": STANDARD.encode(accepted_payload_sha256) },
        "outerEntryFingerprint": { "$bytes": STANDARD.encode(outer_entry_fingerprint) },
    })
}

fn make_coordinates_json(convo_id: Uuid, group_id: &[u8], state_version: i64, epoch: i64) -> Value {
    let hash = if state_version == 0 {
        [0u8; 32]
    } else {
        [0x32u8; 32]
    };
    json!({
        "conversationId": convo_id.to_string(),
        "generation": 0,
        "stateVersion": state_version,
        "groupId": { "$bytes": STANDARD.encode(group_id) },
        "epoch": epoch,
        "groupContextHash": { "$bytes": STANDARD.encode(hash) },
        "confirmationTag": { "$bytes": STANDARD.encode(hash) },
        "lifecycle": "active"
    })
}
fn make_creation_body(
    convo_id: Uuid,
    entry_id: Uuid,
    creator: &TestActor,
    group_id: &[u8],
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    make_creation_body_with_invitee(
        convo_id,
        entry_id,
        creator,
        None,
        group_id,
        &[0u8; 32],
        &[0u8; 32],
        &[0x99u8; 16],
        &[0x77u8; 16],
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn make_creation_body_with_invitee(
    convo_id: Uuid,
    entry_id: Uuid,
    creator: &TestActor,
    invitee: Option<&TestActor>,
    group_id: &[u8],
    genesis_group_context_hash: &[u8; 32],
    genesis_confirmation_tag: &[u8; 32],
    genesis_group_info: &[u8],
    metadata_ciphertext: &[u8],
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let mut participants = vec![json!({
        "userDid": creator.did,
        "status": "active",
        "role": "admin"
    })];
    if let Some(inv) = invitee {
        participants.push(json!({
            "userDid": inv.did,
            "status": "pending",
            "role": "member",
            "invitationProvenance": {
                "invitationTransitionId": entry_id.to_string(),
                "invitedByDid": creator.did,
                "invitedByDeviceId": creator.device_id.to_string()
            }
        }));
    }
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#creationBody",
        "signatureDomain": "CATBIRD-CHAT-CREATE\u{0000}",
        "conversationId": convo_id.to_string(),
        "conversationKind": "group",
        "transitionId": entry_id.to_string(),
        "idempotencyKey": entry_id.to_string(),
        "actorDid": creator.did,
        "actorDeviceId": creator.device_id.to_string(),
        "keyId": creator.key_id,
        "authGeneration": 1,
        "absence": true,
        "next": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 0,
            "groupId": STANDARD.encode(group_id),
            "epoch": 0,
            "groupContextHash": STANDARD.encode(genesis_group_context_hash),
            "confirmationTag": STANDARD.encode(genesis_confirmation_tag),
            "lifecycle": "active"
        },
        "manifest": {
            "actorLeaf": {
                "userDid": creator.did,
                "deviceId": creator.device_id.to_string(),
                "leafOrigin": "genesis"
            },
            "participants": participants
        },
        "genesisGroupInfo": {
            "framing": "mlsMessage",
            "contentType": "groupInfo",
            "bytes": STANDARD.encode(genesis_group_info),
            "sha256": STANDARD.encode(Sha256::digest(genesis_group_info))
        },
        "metadataSnapshot": {
            "coordinate": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": 0,
                "groupId": STANDARD.encode(group_id),
                "epoch": 0,
                "groupContextHash": STANDARD.encode(genesis_group_context_hash),
                "confirmationTag": STANDARD.encode(genesis_confirmation_tag),
            },
            "originTransitionId": entry_id.to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode([0x73_u8; 12]),
            "ciphertext": STANDARD.encode(metadata_ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(metadata_ciphertext)),
            "ciphertextSize": metadata_ciphertext.len(),
            "authorProof": {
                "authorDid": creator.did,
                "authorDeviceId": creator.device_id.to_string(),
                "authorKeyId": creator.key_id,
                "signaturePublicKey": STANDARD.encode(&creator.public_key),
                "authGenerationAtOrigin": 1,
                "originTransitionId": entry_id.to_string(),
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active",
            },
        },
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
    });

    let mut wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode([0u8; 64]),
    });
    let unsigned_bytes = serde_json::to_vec(&wrapper).unwrap();
    let mutation = decode_canonical_signed_mutation(&unsigned_bytes).unwrap();
    let sig = creator.signing_key.sign(mutation.transcript_bytes());

    wrapper["signature"] = Value::String(STANDARD.encode(sig.to_bytes()));
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

fn make_leaf_recovery_fulfillment_body(
    convo_id: Uuid,
    transition_id: Uuid,
    recovery_request_id: Uuid,
    origin_transition_id: Uuid,
    actor: &TestActor,
    group_id: &[u8],
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let commit_bytes = vec![0x5au8; 8];
    let ciphertext = vec![0x5au8; 16];
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
        "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\u{0000}",
        "transitionId": transition_id.to_string(),
        "recoveryRequestId": recovery_request_id.to_string(),
        "idempotencyKey": transition_id.to_string(),
        "actorDid": actor.did,
        "actorDeviceId": actor.device_id.to_string(),
        "keyId": actor.key_id,
        "authGeneration": 1,
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "prior": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 0,
            "groupId": STANDARD.encode(group_id),
            "epoch": 0,
            "groupContextHash": STANDARD.encode([0u8; 32]),
            "confirmationTag": STANDARD.encode([0u8; 32]),
            "lifecycle": "active"
        },
        "next": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 1,
            "groupId": STANDARD.encode(group_id),
            "epoch": 1,
            "groupContextHash": STANDARD.encode([0x32u8; 32]),
            "confirmationTag": STANDARD.encode([0x32u8; 32]),
            "lifecycle": "active"
        },
        "aad": {
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(convo_id.as_bytes()),
            "generation": 0,
            "transitionId": STANDARD.encode(transition_id.as_bytes()),
            "prior": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": 0,
                "stateVersion": 0,
                "groupId": STANDARD.encode(group_id),
                "epoch": 0,
                "groupContextHash": STANDARD.encode([0u8; 32]),
                "confirmationTag": STANDARD.encode([0u8; 32]),
                "lifecycle": "active"
            }
        },
        "manifest": {
            "participantChanges": [],
            "leafChanges": [],
            "leafRecoveryRequestId": recovery_request_id.to_string(),
            "welcomeBundle": {
                "welcomeId": Uuid::new_v4().to_string(),
                "framing": "mlsMessage",
                "contentType": "welcome",
                "opaqueWelcome": STANDARD.encode([0x33u8; 64]),
                "sha256": STANDARD.encode(Sha256::digest([0x33u8; 64])),
                "deliveries": [{
                    "recipientDid": actor.did,
                    "recipientDeviceId": actor.device_id.to_string(),
                    "provenance": {
                        "recoveryRequestId": recovery_request_id.to_string(),
                        "keyPackageRef": STANDARD.encode([0u8; 32])
                    }
                }]
            }
        },
        "commit": {
            "framing": "mlsMessage",
            "contentType": "publicMessageCommit",
            "bytes": STANDARD.encode(&commit_bytes),
            "sha256": STANDARD.encode(Sha256::digest(&commit_bytes))
        },
        "metadataSnapshot": {
            "coordinate": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": 0,
                "groupId": STANDARD.encode(group_id),
                "epoch": 1,
                "groupContextHash": STANDARD.encode([0x32u8; 32]),
                "confirmationTag": STANDARD.encode([0x32u8; 32]),
            },
            "originTransitionId": transition_id.to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode([0xE1_u8; 12]),
            "ciphertext": STANDARD.encode(&ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(&ciphertext)),
            "ciphertextSize": ciphertext.len(),
            "authorProof": {
                "authorDid": actor.did,
                "authorDeviceId": actor.device_id.to_string(),
                "authorKeyId": actor.key_id,
                "signaturePublicKey": STANDARD.encode(&actor.public_key),
                "authGenerationAtOrigin": 1,
                "originTransitionId": origin_transition_id.to_string(),
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active"
            }
        }
    });

    let mut wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode([0u8; 64]),
    });
    let unsigned_bytes = serde_json::to_vec(&wrapper).unwrap();
    let mutation = decode_canonical_signed_mutation(&unsigned_bytes).unwrap();
    let sig = actor.signing_key.sign(mutation.transcript_bytes());

    wrapper["signature"] = Value::String(STANDARD.encode(sig.to_bytes()));
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

#[allow(clippy::too_many_arguments)]
fn make_acceptance_body(
    convo_id: Uuid,
    transition_id: Uuid,
    recovery_request_id: Uuid,
    invitation_transition_id: Uuid,
    actor: &TestActor,
    inviter: &TestActor,
    group_id: &[u8],
    prior_group_context_hash: &[u8; 32],
    prior_confirmation_tag: &[u8; 32],
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#participantAcceptanceBody",
        "signatureDomain": "CATBIRD-CHAT-ACCEPT\u{0000}",
        "transitionId": transition_id.to_string(),
        "recoveryRequestId": recovery_request_id.to_string(),
        "idempotencyKey": transition_id.to_string(),
        "actorDid": actor.did,
        "actorDeviceId": actor.device_id.to_string(),
        "keyId": actor.key_id,
        "authGeneration": 1,
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "prior": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 1,
            "groupId": STANDARD.encode(group_id),
            "epoch": 0,
            "groupContextHash": STANDARD.encode(prior_group_context_hash),
            "confirmationTag": STANDARD.encode(prior_confirmation_tag),
            "lifecycle": "active"
        },
        "next": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 2,
            "groupId": STANDARD.encode(group_id),
            "epoch": 0,
            "groupContextHash": STANDARD.encode(prior_group_context_hash),
            "confirmationTag": STANDARD.encode(prior_confirmation_tag),
            "lifecycle": "active"
        },
        "invitationProvenance": {
            "invitationTransitionId": invitation_transition_id.to_string(),
            "invitedByDid": inviter.did,
            "invitedByDeviceId": inviter.device_id.to_string()
        }
    });

    let mut wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode([0u8; 64]),
    });
    let unsigned_bytes = serde_json::to_vec(&wrapper).unwrap();
    let mutation = decode_canonical_signed_mutation(&unsigned_bytes).unwrap();
    let sig = actor.signing_key.sign(mutation.transcript_bytes());

    wrapper["signature"] = Value::String(STANDARD.encode(sig.to_bytes()));
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

#[allow(clippy::too_many_arguments)]
fn make_corpus_leaf_recovery_fulfillment_body(
    convo_id: Uuid,
    transition_id: Uuid,
    recovery_request_id: Uuid,
    welcome_id: Uuid,
    creation_transition_id: Uuid,
    actor: &TestActor,
    target: &TestActor,
    group_id: &[u8],
    prior_group_context_hash: &[u8; 32],
    prior_confirmation_tag: &[u8; 32],
    committed_group_context_hash: &[u8; 32],
    committed_confirmation_tag: &[u8; 32],
    key_package_ref: &[u8; 32],
    commit_bytes: &[u8],
    metadata_ciphertext: &[u8],
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
        "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\u{0000}",
        "transitionId": transition_id.to_string(),
        "recoveryRequestId": recovery_request_id.to_string(),
        "idempotencyKey": transition_id.to_string(),
        "actorDid": actor.did,
        "actorDeviceId": actor.device_id.to_string(),
        "keyId": actor.key_id,
        "authGeneration": 1,
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "prior": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 2,
            "groupId": STANDARD.encode(group_id),
            "epoch": 0,
            "groupContextHash": STANDARD.encode(prior_group_context_hash),
            "confirmationTag": STANDARD.encode(prior_confirmation_tag),
            "lifecycle": "active"
        },
        "next": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 3,
            "groupId": STANDARD.encode(group_id),
            "epoch": 1,
            "groupContextHash": STANDARD.encode(committed_group_context_hash),
            "confirmationTag": STANDARD.encode(committed_confirmation_tag),
            "lifecycle": "active"
        },
        "aad": {
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(convo_id.as_bytes()),
            "generation": 0,
            "transitionId": STANDARD.encode(transition_id.as_bytes()),
            "prior": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": 0,
                "stateVersion": 2,
                "groupId": STANDARD.encode(group_id),
                "epoch": 0,
                "groupContextHash": STANDARD.encode(prior_group_context_hash),
                "confirmationTag": STANDARD.encode(prior_confirmation_tag),
                "lifecycle": "active"
            }
        },
        "manifest": {
            "participantChanges": [],
            "leafChanges": [
                {
                    "$type": "blue.catbird.chat.defs#addLeafByRecovery",
                    "userDid": target.did,
                    "deviceId": target.device_id.to_string(),
                    "recoveryRequestId": recovery_request_id.to_string(),
                    "keyPackageRef": STANDARD.encode(key_package_ref)
                }
            ],
            "leafRecoveryRequestId": recovery_request_id.to_string(),
            "welcomeBundle": {
                "welcomeId": welcome_id.to_string(),
                "framing": "mlsMessage",
                "contentType": "welcome",
                "opaqueWelcome": STANDARD.encode([0x33u8; 64]),
                "sha256": STANDARD.encode(Sha256::digest([0x33u8; 64])),
                "deliveries": [{
                    "recipientDid": target.did,
                    "recipientDeviceId": target.device_id.to_string(),
                    "provenance": {
                        "recoveryRequestId": recovery_request_id.to_string(),
                        "keyPackageRef": STANDARD.encode(key_package_ref)
                    }
                }]
            }
        },
        "commit": {
            "framing": "mlsMessage",
            "contentType": "publicMessageCommit",
            "bytes": STANDARD.encode(commit_bytes),
            "sha256": STANDARD.encode(Sha256::digest(commit_bytes))
        },
        "metadataSnapshot": {
            "coordinate": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": 0,
                "groupId": STANDARD.encode(group_id),
                "epoch": 1,
                "groupContextHash": STANDARD.encode(committed_group_context_hash),
                "confirmationTag": STANDARD.encode(committed_confirmation_tag),
            },
            "originTransitionId": creation_transition_id.to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode([0x77_u8; 12]),
            "ciphertext": STANDARD.encode(metadata_ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(metadata_ciphertext)),
            "ciphertextSize": metadata_ciphertext.len(),
            "authorProof": {
                "authorDid": actor.did,
                "authorDeviceId": actor.device_id.to_string(),
                "authorKeyId": actor.key_id,
                "signaturePublicKey": STANDARD.encode(&actor.public_key),
                "authGenerationAtOrigin": 1,
                "originTransitionId": creation_transition_id.to_string(),
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active"
            }
        }
    });

    let mut wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode([0u8; 64]),
    });
    let unsigned_bytes = serde_json::to_vec(&wrapper).unwrap();
    let mutation = decode_canonical_signed_mutation(&unsigned_bytes).unwrap();
    let sig = actor.signing_key.sign(mutation.transcript_bytes());

    wrapper["signature"] = Value::String(STANDARD.encode(sig.to_bytes()));
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}
fn make_message_body(
    convo_id: Uuid,
    message_id: Uuid,
    actor: &TestActor,
    group_id: &[u8],
    attachments: Vec<Value>,
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let msg_bytes = vec![0x31u8; 8];
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#applicationSendBody",
        "signatureDomain": "CATBIRD-CHAT-MESSAGE\u{0}",
        "messageId": message_id.to_string(),
        "actorDid": actor.did,
        "actorDeviceId": actor.device_id.to_string(),
        "keyId": actor.key_id,
        "authGeneration": 1,
        "prior": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 0,
            "groupId": STANDARD.encode(group_id),
            "epoch": 0,
            "groupContextHash": STANDARD.encode([0u8; 32]),
            "confirmationTag": STANDARD.encode([0u8; 32]),
            "lifecycle": "active"
        },
        "aad": {
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(convo_id.as_bytes()),
            "generation": 0,
            "messageId": STANDARD.encode(message_id.as_bytes()),
            "prior": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": 0,
                "stateVersion": 0,
                "groupId": STANDARD.encode(group_id),
                "epoch": 0,
                "groupContextHash": STANDARD.encode([0u8; 32]),
                "confirmationTag": STANDARD.encode([0u8; 32]),
                "lifecycle": "active"
            }
        },
        "applicationMessage": {
            "framing": "mlsMessage",
            "contentType": "privateMessageApplication",
            "bytes": STANDARD.encode(&msg_bytes),
            "sha256": STANDARD.encode(Sha256::digest(&msg_bytes))
        },
        "blobBindings": attachments,
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
    });

    let mut wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode([0u8; 64]),
    });
    let unsigned_bytes = serde_json::to_vec(&wrapper).unwrap();
    let mutation = decode_canonical_signed_mutation(&unsigned_bytes).unwrap();
    let sig = actor.signing_key.sign(mutation.transcript_bytes());

    wrapper["signature"] = Value::String(STANDARD.encode(sig.to_bytes()));
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

fn make_commit_body(
    convo_id: Uuid,
    transition_id: Uuid,
    actor: &TestActor,
    group_id: &[u8],
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let commit_bytes = vec![0x5au8; 8];
    let ciphertext = vec![0x5au8; 16];
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#commitTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-COMMIT\u{0}",
        "transitionId": transition_id.to_string(),
        "idempotencyKey": transition_id.to_string(),
        "actorDid": actor.did,
        "actorDeviceId": actor.device_id.to_string(),
        "keyId": actor.key_id,
        "authGeneration": 1,
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "prior": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 0,
            "groupId": STANDARD.encode(group_id),
            "epoch": 0,
            "groupContextHash": STANDARD.encode([0u8; 32]),
            "confirmationTag": STANDARD.encode([0u8; 32]),
            "lifecycle": "active"
        },
        "next": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 1,
            "groupId": STANDARD.encode(group_id),
            "epoch": 1,
            "groupContextHash": STANDARD.encode([0x33u8; 32]),
            "confirmationTag": STANDARD.encode([0xabu8; 32]),
            "lifecycle": "active"
        },
        "aad": {
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(convo_id.as_bytes()),
            "generation": 0,
            "transitionId": STANDARD.encode(transition_id.as_bytes()),
            "prior": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": 0,
                "stateVersion": 0,
                "groupId": STANDARD.encode(group_id),
                "epoch": 0,
                "groupContextHash": STANDARD.encode([0u8; 32]),
                "confirmationTag": STANDARD.encode([0u8; 32]),
                "lifecycle": "active"
            }
        },
        "manifest": {
            "participantChanges": [],
            "leafChanges": []
        },
        "commit": {
            "framing": "mlsMessage",
            "contentType": "publicMessageCommit",
            "bytes": STANDARD.encode(&commit_bytes),
            "sha256": STANDARD.encode(Sha256::digest(&commit_bytes))
        },
        "metadataSnapshot": {
            "coordinate": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": 0,
                "groupId": STANDARD.encode(group_id),
                "epoch": 1,
                "groupContextHash": STANDARD.encode([0x33u8; 32]),
                "confirmationTag": STANDARD.encode([0xabu8; 32]),
            },
            "originTransitionId": transition_id.to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode([0xE1_u8; 12]),
            "ciphertext": STANDARD.encode(&ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(&ciphertext)),
            "ciphertextSize": ciphertext.len(),
            "authorProof": {
                "authorDid": actor.did,
                "authorDeviceId": actor.device_id.to_string(),
                "authorKeyId": actor.key_id,
                "signaturePublicKey": STANDARD.encode(&actor.public_key),
                "authGenerationAtOrigin": 1,
                "originTransitionId": transition_id.to_string(),
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active"
            }
        }
    });

    let mut wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode([0u8; 64]),
    });
    let unsigned_bytes = serde_json::to_vec(&wrapper).unwrap();
    let mutation = decode_canonical_signed_mutation(&unsigned_bytes).unwrap();
    let sig = actor.signing_key.sign(mutation.transcript_bytes());

    wrapper["signature"] = Value::String(STANDARD.encode(sig.to_bytes()));
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

#[allow(clippy::too_many_arguments)]
fn make_corpus_commit_body(
    convo_id: Uuid,
    transition_id: Uuid,
    creation_transition_id: Uuid,
    actor_did: &str,
    actor_device_id: Uuid,
    actor_key_id: &str,
    actor_public_key: &[u8],
    actor_signing_key: &Ed25519SigningKey,
    group_id: &[u8],
    prior_group_context_hash: &[u8],
    prior_confirmation_tag: &[u8],
    next_group_context_hash: &[u8],
    next_confirmation_tag: &[u8],
    commit_bytes: &[u8],
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let ciphertext = vec![0x88u8; 48];
    let nonce = vec![0x78u8; 12];
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#commitTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-COMMIT\u{0000}",
        "transitionId": transition_id.to_string(),
        "idempotencyKey": transition_id.to_string(),
        "actorDid": actor_did,
        "actorDeviceId": actor_device_id.to_string(),
        "keyId": actor_key_id,
        "authGeneration": 1,
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "prior": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 3,
            "groupId": STANDARD.encode(group_id),
            "epoch": 1,
            "groupContextHash": STANDARD.encode(prior_group_context_hash),
            "confirmationTag": STANDARD.encode(prior_confirmation_tag),
            "lifecycle": "active"
        },
        "next": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 4,
            "groupId": STANDARD.encode(group_id),
            "epoch": 2,
            "groupContextHash": STANDARD.encode(next_group_context_hash),
            "confirmationTag": STANDARD.encode(next_confirmation_tag),
            "lifecycle": "active"
        },
        "aad": {
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(convo_id.as_bytes()),
            "generation": 0,
            "transitionId": STANDARD.encode(transition_id.as_bytes()),
            "prior": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": 0,
                "stateVersion": 3,
                "groupId": STANDARD.encode(group_id),
                "epoch": 1,
                "groupContextHash": STANDARD.encode(prior_group_context_hash),
                "confirmationTag": STANDARD.encode(prior_confirmation_tag),
                "lifecycle": "active"
            }
        },
        "manifest": {
            "participantChanges": [],
            "leafChanges": []
        },
        "commit": {
            "framing": "mlsMessage",
            "contentType": "publicMessageCommit",
            "bytes": STANDARD.encode(commit_bytes),
            "sha256": STANDARD.encode(Sha256::digest(commit_bytes))
        },
        "metadataSnapshot": {
            "coordinate": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": 0,
                "groupId": STANDARD.encode(group_id),
                "epoch": 2,
                "groupContextHash": STANDARD.encode(next_group_context_hash),
                "confirmationTag": STANDARD.encode(next_confirmation_tag),
            },
            "originTransitionId": creation_transition_id.to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode(&nonce),
            "ciphertext": STANDARD.encode(&ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(&ciphertext)),
            "ciphertextSize": ciphertext.len(),
            "authorProof": {
                "authorDid": actor_did,
                "authorDeviceId": actor_device_id.to_string(),
                "authorKeyId": actor_key_id,
                "signaturePublicKey": STANDARD.encode(actor_public_key),
                "authGenerationAtOrigin": 1,
                "originTransitionId": creation_transition_id.to_string(),
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active"
            }
        }
    });

    let mut wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode([0u8; 64]),
    });
    let unsigned_bytes = serde_json::to_vec(&wrapper).unwrap();
    let mutation = decode_canonical_signed_mutation(&unsigned_bytes).unwrap();
    let sig = actor_signing_key.sign(mutation.transcript_bytes());

    wrapper["signature"] = Value::String(STANDARD.encode(sig.to_bytes()));
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

// =============================================================================
// Test 1: deliverWelcome Authenticated Positive & Replay
// =============================================================================

#[tokio::test]
async fn test_deliver_welcome_router_authenticated_positive_and_replay() {
    let harness = TestHarness::new("welcome").await;
    let now = Utc::now();
    let convo_id = Uuid::new_v4();
    let group_id = vec![0x11u8; 32];
    let creator = TestActor::generate();
    creator.seed(&harness.pool, now).await;

    let mut recipient = TestActor::generate();
    recipient.did = creator.did.clone();
    recipient.seed(&harness.pool, now).await;

    let (creation_transition_id, _creation_entry_id, _, _, _, _) = seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        1,
        &creator,
        None,
        now,
    )
    .await;

    let fulfillment_transition_id = Uuid::new_v4();
    let fulfillment_entry_id = fulfillment_transition_id;
    let _recipient_period_id = Uuid::new_v4();
    let welcome_id = Uuid::new_v4();
    let recovery_request_id = Uuid::new_v4();
    let welcome_bytes = corpus_file("welcome.mls");
    let welcome_sha256: [u8; 32] = Sha256::digest(&welcome_bytes).into();
    let manifest_bytes = corpus_file("manifest.json");
    let manifest: Value = serde_json::from_slice(&manifest_bytes).expect("parse manifest.json");
    let key_package_ref = hex_array(manifest["chain"]["innerKeyPackageRefHex"].as_str().unwrap());
    let public_snapshot_bytes = vec![0x88u8; 16];
    let public_snapshot_sha256: [u8; 32] = Sha256::digest(&public_snapshot_bytes).into();
    let creator_credential = format!("{}#{}", creator.did, creator.device_id).into_bytes();
    let recipient_credential = format!("{}#{}", recipient.did, recipient.device_id).into_bytes();
    let enc_key = vec![0x64u8; 1216];
    let (tree_summary_bytes, tree_summary_sha256) = make_tree_summary_bytes(
        &[0x63u8; 32],
        &[
            (0, &creator_credential, &creator.public_key, &enc_key),
            (1, &recipient_credential, &recipient.public_key, &enc_key),
        ],
    );

    let (_, signed_req_bytes) = make_leaf_recovery_fulfillment_body(
        convo_id,
        fulfillment_transition_id,
        recovery_request_id,
        creation_transition_id,
        &creator,
        &group_id,
        now,
    );
    let mutation =
        decode_and_verify_signed_mutation(&signed_req_bytes, creator.public_key.as_slice())
            .unwrap();
    let received_at = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&now.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
    );
    let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.submitTransition").unwrap();
    let server_fields =
        CanonicalControlServerFields::empty(ControlEntryKind::LeafRecoveryFulfillment).unwrap();
    let built = build_verified_control_entry(
        mutation,
        &endpoint,
        CanonicalUuidV4::parse(&fulfillment_entry_id.to_string()).unwrap(),
        CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
        2,
        &received_at,
        server_fields,
    )
    .unwrap();
    let products = CanonicalControlEntryProducts::mint(&built).unwrap();
    let entry_bytes = products.durable_json().to_vec();
    let entry_sha256: [u8; 32] = Sha256::digest(&entry_bytes).into();
    let outer_fp = *built.outer_control_fingerprint();

    let mut tx = harness.pool.begin().await.unwrap();
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *tx)
        .await
        .unwrap();
    // 2. Seed key package (consumed)
    sqlx::query(
        r#"
        INSERT INTO chat.key_packages (
            key_package_ref, wrapper_bytes, wrapper_sha256, init_key,
            owner_did, owner_device_id, owner_key_id, owner_auth_generation,
            not_before, not_after, status, terminal_transition_id, terminal_at, created_at
        ) VALUES (
            $1, repeat('w', 32)::bytea, digest(repeat('w', 32)::bytea, 'sha256'), repeat('k', 32)::bytea,
            $2, $3, $4, 1,
            $5 - INTERVAL '5 minutes', $5 + INTERVAL '1 hour', 'consumed', $6, $5, $5
        )
        "#,
    )
    .bind(&key_package_ref[..])
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(&recipient.key_id)
    .bind(now)
    .bind(fulfillment_transition_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    // 3. Seed leaf recovery request (fulfilled)
    sqlx::query(
        r#"
        INSERT INTO chat.leaf_recovery_requests (
            recovery_request_id, conversation_id, generation, requester_did,
            requester_device_id, requester_key_id, requester_auth_generation,
            recovery_kind, source, bound_state_version, bound_group_id, bound_epoch,
            bound_group_context_hash, bound_confirmation_tag, reservation_request_id,
            status, fulfilling_transition_id, terminal_at,
            signed_request_bytes, signing_transcript_bytes, request_digest, signature,
            requested_at, expires_at
        ) VALUES (
            $1, $2, 0, $3,
            $4, $5, 1,
            'add', 'acceptConversation', 0, $6, 0,
            $7, $7, $1,
            'fulfilled', $8, $9,
            repeat('r', 32)::bytea, repeat('t', 32)::bytea, digest(repeat('t', 32)::bytea, 'sha256'), repeat('s', 64)::bytea,
            $9, $9 + INTERVAL '5 minutes'
        )
        "#,
    )
    .bind(recovery_request_id)
    .bind(convo_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(&recipient.key_id)
    .bind(&group_id)
    .bind(&[0u8; 32])
    .bind(fulfillment_transition_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // 4. Seed key package reservation (consumed)
    sqlx::query(
        r#"
        INSERT INTO chat.key_package_reservations (
            recovery_request_id, key_package_ref, conversation_id, generation, requester_did,
            requester_device_id, requester_key_id, requester_auth_generation, recipient_did,
            recipient_device_id, bound_state_version, bound_group_id, bound_epoch,
            bound_group_context_hash, bound_confirmation_tag, purpose, expires_at, status,
            consumed_transition_id, terminal_at, created_at
        ) VALUES (
            $1, $2, $3, 0, $4,
            $5, $6, 1, $4,
            $5, 0, $7, 0,
            $8, $8, 'leafRecovery', $9 + INTERVAL '5 minutes', 'consumed',
            $10, $9, $9
        )
        "#,
    )
    .bind(recovery_request_id)
    .bind(&key_package_ref[..])
    .bind(convo_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(&recipient.key_id)
    .bind(&group_id)
    .bind(&[0u8; 32])
    .bind(now)
    .bind(fulfillment_transition_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    // 5. Seed metadata_snapshot for state_version 1
    let metadata_snapshot_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO chat.metadata_snapshots (
            metadata_snapshot_id, conversation_id, generation, state_version,
            group_id, epoch, group_context_hash, confirmation_tag,
            producing_transition_id, origin_transition_id, metadata_version,
            nonce, ciphertext, ciphertext_sha256, ciphertext_size,
            author_did, author_device_id, author_key_id, author_public_key,
            author_auth_generation, author_origin_seq, author_role, author_device_status, created_at
        ) VALUES (
            $1, $2, 0, 1,
            $3, 1, $4, $4,
            $5, $6, 1,
            $12, repeat('c', 16)::bytea, digest(repeat('c', 16)::bytea, 'sha256'), 16,
            $7, $8, $9, $10,
            1, 1, 'admin', 'active', $11
        )
        "#,
    )
    .bind(metadata_snapshot_id)
    .bind(convo_id)
    .bind(&group_id)
    .bind(&[0x32u8; 32])
    .bind(fulfillment_transition_id)
    .bind(creation_transition_id)
    .bind(&creator.did)
    .bind(creator.device_id)
    .bind(&creator.key_id)
    .bind(&creator.public_key[..])
    .bind(now)
    .bind(&[0xE1_u8; 12])
    .execute(&mut *tx)
    .await
    .unwrap();

    // 6. Seed fulfillment transition at seq 2
    sqlx::query(
        r#"
        INSERT INTO chat.transitions (
            transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id,
            actor_auth_generation, actor_role, actor_device_status, signed_request_bytes,
            unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature,
            prior_generation, prior_state_version, next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at
        ) VALUES (
            $1, $2, 'leafRecovery', $3, $4, $5,
            1, 'admin', 'active', $6,
            $7, $8, $9, $10,
            0, 0, 0, 1, $11, 2, $12
        )
        "#,
    )
    .bind(fulfillment_transition_id)
    .bind(convo_id)
    .bind(&creator.did)
    .bind(creator.device_id)
    .bind(&creator.key_id)
    .bind(&signed_req_bytes)
    .bind(built.mutation().canonical_projection())
    .bind(built.mutation().transcript_bytes())
    .bind(built.mutation().request_digest().as_slice())
    .bind(built.mutation().signature().as_slice())
    .bind(metadata_snapshot_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // 6. Seed entry at seq 2
    sqlx::query(
        r#"
        INSERT INTO chat.entries (
            conversation_id, seq, entry_id, entry_kind,
            accepted_payload_bytes, accepted_payload_sha256,
            signed_request_bytes, request_digest, signature,
            server_fields_bytes, outer_entry_fingerprint,
            actor_did, actor_device_id, actor_key_id, actor_auth_generation,
            generation, state_version, transition_id, received_at
        ) VALUES (
            $1, 2, $2, 'blue.catbird.chat.defs#leafRecoveryFulfillmentEntry',
            $3, $4,
            $5, $6, $7,
            repeat('0', 1)::bytea, $8,
            $9, $10, $11, 1,
            0, 1, $12, $13
        )
        "#,
    )
    .bind(convo_id)
    .bind(fulfillment_entry_id)
    .bind(&entry_bytes)
    .bind(&entry_sha256[..])
    .bind(&signed_req_bytes)
    .bind(built.mutation().request_digest().as_slice())
    .bind(built.mutation().signature().as_slice())
    .bind(&outer_fp[..])
    .bind(&creator.did)
    .bind(creator.device_id)
    .bind(&creator.key_id)
    .bind(fulfillment_transition_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // 7. Update conversation & generation current_state_version = 1, next_entry_seq = 3
    sqlx::query(
        r#"
        UPDATE chat.conversations
           SET current_state_version = 1,
               next_entry_seq = 3
         WHERE conversation_id = $1
        "#,
    )
    .bind(convo_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        UPDATE chat.generations
           SET current_state_version = 1
         WHERE conversation_id = $1 AND generation = 0
        "#,
    )
    .bind(convo_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    // 8. Seed generation_states for state_version 1
    sqlx::query(
        r#"
        INSERT INTO chat.generation_states (
            conversation_id, generation, state_version, group_id, epoch,
            group_context_hash, confirmation_tag, lifecycle, state_kind,
            producing_transition_id, public_snapshot_bytes, snapshot_sha256,
            tree_summary_bytes, tree_summary_sha256, leaf_count, created_at
        ) VALUES (
            $1, 0, 1, $2, 1,
            $5, $5, 'active', 'commit',
            $3, $6, $7,
            $8, $9, 2, $4
        )
        "#,
    )
    .bind(convo_id)
    .bind(&group_id)
    .bind(fulfillment_transition_id)
    .bind(now)
    .bind(&[0x32u8; 32])
    .bind(&public_snapshot_bytes)
    .bind(&public_snapshot_sha256[..])
    .bind(&tree_summary_bytes)
    .bind(&tree_summary_sha256[..])
    .execute(&mut *tx)
    .await
    .unwrap();

    // 9. Seed application_intervals & member_devices row for recipient
    let recipient_leaf_id = Uuid::new_v4();
    let _recipient_interval_id = Uuid::new_v4();
    let recipient_credential = format!("{}#{}", recipient.did, recipient.device_id).into_bytes();

    sqlx::query(
        r#"
        INSERT INTO chat.member_devices (
            leaf_period_id, participant_period_id, conversation_id, generation,
            user_did, device_id, leaf_index, basic_credential,
            leaf_signature_key, leaf_key_id, leaf_auth_generation, origin,
            join_key_package_ref, joined_state_version, joined_transition_id, joined_seq, active, created_at
        ) VALUES (
            $1, (SELECT participant_period_id FROM chat.participants WHERE conversation_id = $2 AND user_did = $3 AND current_membership), $2, 0,
            $3, $4, 1, $5,
            $6, $7, 1, 'keyPackage',
            $8, 1, $9, 2, TRUE, $10
        )
        "#,
    )
    .bind(recipient_leaf_id)
    .bind(convo_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(&recipient_credential)
    .bind(&recipient.public_key[..])
    .bind(&recipient.key_id)
    .bind(&key_package_ref[..])
    .bind(fulfillment_transition_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.application_intervals (
            membership_interval_id, conversation_id, generation, recipient_did, recipient_device_id,
            start_seq, opening_kind, opening_transition_id, opening_outer_entry_fingerprint,
            opening_state_version, opening_group_id, opening_epoch, opening_group_context_hash,
            opening_confirmation_tag, opening_leaf_period_id, created_at
        ) VALUES (
            $1, $2, 0, $3, $4,
            2, 'add', $5, $6,
            1, $7, 1, $8,
            $8, $9, $10
        )
        "#,
    )
    .bind(fulfillment_transition_id)
    .bind(convo_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(fulfillment_transition_id)
    .bind(&outer_fp[..])
    .bind(&group_id)
    .bind(&[0x32u8; 32])
    .bind(recipient_leaf_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();
    // 10. Seed welcome bundle
    sqlx::query(
        r#"
        INSERT INTO chat.welcome_bundles (
            welcome_id, conversation_id, transition_id, entry_seq, generation, state_version,
            group_id, epoch, group_context_hash, confirmation_tag,
            wrapper_bytes, wrapper_sha256, created_at
        ) VALUES (
            $1, $2, $3, 2, 0, 1,
            $4, 1, $7, $7,
            $5, $6, $8
        )
        "#,
    )
    .bind(welcome_id)
    .bind(convo_id)
    .bind(fulfillment_transition_id)
    .bind(&group_id)
    .bind(&welcome_bytes)
    .bind(&welcome_sha256[..])
    .bind(&[0x32u8; 32])
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // 11. Seed welcome delivery
    sqlx::query(
        r#"
        INSERT INTO chat.welcome_deliveries (
            welcome_id, recipient_did, recipient_device_id, recovery_request_id,
            key_package_ref, expires_at, status
        ) VALUES (
            $1, $2, $3, $4,
            $5, $6 + INTERVAL '1 hour', 'pending'
        )
        "#,
    )
    .bind(welcome_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(recovery_request_id)
    .bind(&key_package_ref[..])
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let delivery_id = Uuid::new_v4();
    let mut header_model = ValidatedEnvelopeHeader {
        protocol_version: "1".to_string(),
        delivery_id,
        conversation_id: convo_id,
        sender_ds_did: harness.sequencer_ds_did.clone(),
        receiver_ds_did: LOCAL_DS_DID.to_string(),
        sequencer_did: harness.sequencer_ds_did.clone(),
        sequencer_term: 1,
        payload_sha256: [0u8; 32],
    };
    let locator_model = ValidatedEntryLocator {
        entry_id: fulfillment_entry_id,
        seq: 2,
        accepted_payload_sha256: entry_sha256,
        outer_entry_fingerprint: outer_fp,
    };
    let coordinates_dto = ConversationCoordinates {
        conversation_id: jacquard_common::deps::smol_str::SmolStr::from(convo_id.to_string()),
        generation: 0,
        state_version: 1,
        group_id: jacquard_common::deps::bytes::Bytes::copy_from_slice(&group_id),
        epoch: 1,
        group_context_hash: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0x32u8; 32]),
        confirmation_tag: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0x32u8; 32]),
        lifecycle: jacquard_common::deps::smol_str::SmolStr::from("active"),
        extra_data: None,
    };

    let welcome_digest = compute_welcome_envelope_digest(
        &header_model,
        &recipient.did,
        recipient.device_id,
        welcome_id,
        recovery_request_id,
        &key_package_ref,
        &welcome_bytes,
        &welcome_sha256,
        &entry_bytes,
        &signed_req_bytes,
        &locator_model,
        &coordinates_dto,
        &public_snapshot_sha256,
        &tree_summary_sha256,
    )
    .unwrap();
    header_model.payload_sha256 = welcome_digest;

    let header_json = make_envelope_header_json(
        delivery_id,
        convo_id,
        &harness.sequencer_ds_did,
        LOCAL_DS_DID,
        &harness.sequencer_ds_did,
        1,
        &welcome_digest,
    );
    let locator_json = make_entry_locator_json(fulfillment_entry_id, 2, &entry_sha256, &outer_fp);
    let coordinates_json = make_coordinates_json(convo_id, &group_id, 1, 1);
    let deliver_welcome_body = json!({
        "header": header_json,
        "entryLocator": locator_json,
        "coordinates": coordinates_json,
        "welcomeId": welcome_id.to_string(),
        "recoveryRequestId": recovery_request_id.to_string(),
        "keyPackageRef": { "$bytes": STANDARD.encode(key_package_ref) },
        "recipientDid": recipient.did,
        "recipientDeviceId": recipient.device_id.to_string(),
        "welcomeBytes": { "$bytes": STANDARD.encode(&welcome_bytes) },
        "welcomeSha256": { "$bytes": STANDARD.encode(welcome_sha256) },
        "publicSnapshotSha256": { "$bytes": STANDARD.encode(public_snapshot_sha256) },
        "treeSummarySha256": { "$bytes": STANDARD.encode(tree_summary_sha256) },
        "entryBytes": { "$bytes": STANDARD.encode(&entry_bytes) },
        "signedRequestBytes": { "$bytes": STANDARD.encode(&signed_req_bytes) },
    });

    // On deliveries the authenticated sender MUST equal the header sequencerDid.
    let jwt = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        DELIVER_WELCOME_NSID,
    );

    // 1. Positive authenticated delivery
    let (status, body, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverWelcome",
            Some(&jwt),
            &deliver_welcome_body,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "deliverWelcome must succeed: {body:?}"
    );
    assert_eq!(body["accepted"], true);
    assert_eq!(body["receipt"]["deliveryId"], delivery_id.to_string());

    // 2. Verify receipt persisted in DB
    let receipt_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.federation_delivery_receipts WHERE delivery_id = $1",
    )
    .bind(delivery_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert_eq!(
        receipt_count, 1,
        "exactly one delivery receipt row must be stored"
    );

    // 3. Idempotent replay with fresh JWT and same delivery ID & payload -> returns 200 OK with identical receipt
    let jwt2 = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        DELIVER_WELCOME_NSID,
    );
    let (status2, body2, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverWelcome",
            Some(&jwt2),
            &deliver_welcome_body,
        )
        .await;
    assert_eq!(
        status2,
        StatusCode::OK,
        "replay must succeed with stored receipt: {body2:?}"
    );
    assert_eq!(body2, body, "replay body must be identical to original");

    // 4. Negative: missing auth -> 401
    let (status_no_auth, _, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverWelcome",
            None,
            &deliver_welcome_body,
        )
        .await;
    assert_eq!(status_no_auth, StatusCode::UNAUTHORIZED);
}

// =============================================================================
// Test 2: deliverMessage Authenticated Positive, Replay & Idempotency
// =============================================================================

#[tokio::test]
async fn test_deliver_message_router_authenticated_positive_replay_and_idempotency() {
    let harness = TestHarness::new("message").await;
    let now = Utc::now();
    let convo_id = Uuid::new_v4();
    let group_id = vec![0x22u8; 32];

    let recipient = TestActor::generate();
    recipient.seed(&harness.pool, now).await;

    seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        1,
        &recipient,
        None,
        now,
    )
    .await;

    let actor = TestActor::generate();
    actor.seed(&harness.pool, now).await;

    let message_id = Uuid::new_v4();
    let msg_entry_id = Uuid::new_v4();
    let (_, signed_req_bytes) =
        make_message_body(convo_id, message_id, &actor, &group_id, vec![], now);

    let mutation =
        decode_and_verify_signed_mutation(&signed_req_bytes, actor.public_key.as_slice()).unwrap();
    let received_at = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&now.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
    );
    let built = build_verified_application_entry(
        mutation,
        CanonicalUuidV4::parse(&msg_entry_id.to_string()).unwrap(),
        CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
        2,
        &received_at,
    )
    .unwrap();
    let entry_bytes = built.canonical_entry_bytes().to_vec();
    let entry_sha256 = *built.accepted_payload_sha256();
    let outer_fp = *built.outer_application_fingerprint();

    let delivery_id = Uuid::new_v4();
    let mut header_model = ValidatedEnvelopeHeader {
        protocol_version: "1".to_string(),
        delivery_id,
        conversation_id: convo_id,
        sender_ds_did: harness.sequencer_ds_did.clone(),
        receiver_ds_did: LOCAL_DS_DID.to_string(),
        sequencer_did: harness.sequencer_ds_did.clone(),
        sequencer_term: 1,
        payload_sha256: [0u8; 32],
    };
    let locator_model = ValidatedEntryLocator {
        entry_id: msg_entry_id,
        seq: 2,
        accepted_payload_sha256: entry_sha256,
        outer_entry_fingerprint: outer_fp,
    };

    let msg_digest = compute_message_envelope_digest(
        &header_model,
        &recipient.did,
        &locator_model,
        &entry_bytes,
        &signed_req_bytes,
    )
    .unwrap();
    header_model.payload_sha256 = msg_digest;

    let header_json = make_envelope_header_json(
        delivery_id,
        convo_id,
        &harness.sequencer_ds_did,
        LOCAL_DS_DID,
        &harness.sequencer_ds_did,
        1,
        &msg_digest,
    );
    let locator_json = make_entry_locator_json(msg_entry_id, 2, &entry_sha256, &outer_fp);

    let deliver_msg_body = json!({
        "header": header_json,
        "entryLocator": locator_json,
        "recipientDid": recipient.did,
        "entryBytes": { "$bytes": STANDARD.encode(&entry_bytes) },
        "signedRequestBytes": { "$bytes": STANDARD.encode(&signed_req_bytes) },
    });

    let jwt = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        DELIVER_MESSAGE_NSID,
    );

    // 1. Positive authenticated delivery
    let (status, body, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverMessage",
            Some(&jwt),
            &deliver_msg_body,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "deliverMessage must succeed: {body:?}"
    );
    assert_eq!(body["accepted"], true);
    assert_eq!(body["receipt"]["deliveryId"], delivery_id.to_string());

    // 2. Verify chat.entries has the appended row
    let entry_row: (i64, String, Vec<u8>) = sqlx::query_as(
        "SELECT seq, entry_kind, accepted_payload_sha256 FROM chat.entries WHERE conversation_id = $1 AND seq = 2",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert_eq!(entry_row.0, 2);
    assert_eq!(entry_row.1, "blue.catbird.chat.defs#applicationEntry");
    assert_eq!(entry_row.2, entry_sha256.to_vec());

    // 3. Verify shared operation claim created (deliverMessage shares the chat.sendMessage operation claim)
    let claim_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.operation_claims WHERE operation_id = $1 AND endpoint_nsid = 'blue.catbird.chat.sendMessage'",
    )
    .bind(message_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert_eq!(
        claim_count, 1,
        "shared operation claim must be recorded for delivery message"
    );

    // 4. Idempotent replay with fresh JWT and same delivery ID & payload
    let jwt2 = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        DELIVER_MESSAGE_NSID,
    );
    let (status2, body2, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverMessage",
            Some(&jwt2),
            &deliver_msg_body,
        )
        .await;
    assert_eq!(
        status2,
        StatusCode::OK,
        "replay must return 200 OK: {body2:?}"
    );
    assert_eq!(body2, body, "replay body must match original");

    // 5. Replay conflict: same delivery_id but changed payload & locator seq -> 409
    let mut conflicted_locator = locator_model.clone();
    conflicted_locator.seq = 3;
    let conflicted_digest = compute_message_envelope_digest(
        &header_model,
        &recipient.did,
        &conflicted_locator,
        &entry_bytes,
        &signed_req_bytes,
    )
    .unwrap();
    let mut conflicted_body = deliver_msg_body.clone();
    conflicted_body["header"]["payloadSha256"] =
        json!({ "$bytes": STANDARD.encode(conflicted_digest) });
    conflicted_body["entryLocator"]["seq"] = json!(3);
    let jwt3 = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        DELIVER_MESSAGE_NSID,
    );
    let (status_conflict, body_conflict, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverMessage",
            Some(&jwt3),
            &conflicted_body,
        )
        .await;
    assert_eq!(
        status_conflict,
        StatusCode::CONFLICT,
        "conflicting delivery replay must fail with 409: {body_conflict:?}"
    );
}

// =============================================================================
// Test 3: deliverMessage with Attachment Blob Binding
// =============================================================================

#[tokio::test]
async fn test_deliver_message_router_with_attachment_binding() {
    let harness = TestHarness::new("attachment").await;
    let now = Utc::now();
    let convo_id = Uuid::new_v4();
    let group_id = vec![0x33u8; 32];

    let recipient = TestActor::generate();
    recipient.seed(&harness.pool, now).await;

    seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        1,
        &recipient,
        None,
        now,
    )
    .await;

    let actor = TestActor::generate();
    actor.seed(&harness.pool, now).await;

    let blob_id = Uuid::new_v4();
    let blob_hash = vec![0x44u8; 32];

    // Seed completedUnbound blob + ticket inside a single transaction to satisfy deferred constraint triggers
    let mut tx = harness.pool.begin().await.unwrap();
    sqlx::query(
        r#"
        INSERT INTO chat.blobs (
            blob_id, owner_did, owner_device_id, owner_key_id, owner_auth_generation,
            purpose, media_type, plaintext_size, ciphertext_size, ciphertext_sha256,
            object_store_key, status, prepared_at, uploaded_at, upload_expires_at, unbound_expires_at
        ) VALUES (
            $1, $2, $3, $4, 1,
            'attachment', 'image/png', 32, 48, $5,
            'mock-key', 'completedUnbound',
            $6 - INTERVAL '2 minutes', $6 - INTERVAL '1 minute',
            $6 + INTERVAL '3 minutes', $6 + INTERVAL '59 minutes'
        )
        "#,
    )
    .bind(blob_id)
    .bind(&actor.did)
    .bind(actor.device_id)
    .bind(&actor.key_id)
    .bind(&blob_hash)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.blob_upload_tickets (
            ticket_hash, blob_id, owner_did, owner_device_id,
            created_at, expires_at, consumed_at
        ) VALUES (
            digest(decode('feed', 'hex'), 'sha256'), $1, $2, $3,
            $4 - INTERVAL '2 minutes', $4 + INTERVAL '3 minutes', $4 - INTERVAL '1 minute'
        )
        "#,
    )
    .bind(blob_id)
    .bind(&actor.did)
    .bind(actor.device_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    tx.commit().await.unwrap();

    let attachments = vec![json!({
        "blobId": blob_id.to_string(),
        "ciphertextSha256": STANDARD.encode(&blob_hash),
        "ciphertextSize": 48,
        "purpose": "attachment"
    })];

    let message_id = Uuid::new_v4();
    let msg_entry_id = Uuid::new_v4();
    let (_, signed_req_bytes) =
        make_message_body(convo_id, message_id, &actor, &group_id, attachments, now);

    let mutation =
        decode_and_verify_signed_mutation(&signed_req_bytes, actor.public_key.as_slice()).unwrap();
    let received_at = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&now.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
    );
    let built = build_verified_application_entry(
        mutation,
        CanonicalUuidV4::parse(&msg_entry_id.to_string()).unwrap(),
        CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
        2,
        &received_at,
    )
    .unwrap();
    let entry_bytes = built.canonical_entry_bytes().to_vec();
    let entry_sha256 = *built.accepted_payload_sha256();
    let outer_fp = *built.outer_application_fingerprint();

    let delivery_id = Uuid::new_v4();
    let mut header_model = ValidatedEnvelopeHeader {
        protocol_version: "1".to_string(),
        delivery_id,
        conversation_id: convo_id,
        sender_ds_did: harness.sequencer_ds_did.clone(),
        receiver_ds_did: LOCAL_DS_DID.to_string(),
        sequencer_did: harness.sequencer_ds_did.clone(),
        sequencer_term: 1,
        payload_sha256: [0u8; 32],
    };
    let locator_model = ValidatedEntryLocator {
        entry_id: msg_entry_id,
        seq: 2,
        accepted_payload_sha256: entry_sha256,
        outer_entry_fingerprint: outer_fp,
    };

    let msg_digest = compute_message_envelope_digest(
        &header_model,
        &recipient.did,
        &locator_model,
        &entry_bytes,
        &signed_req_bytes,
    )
    .unwrap();
    header_model.payload_sha256 = msg_digest;

    let header_json = make_envelope_header_json(
        delivery_id,
        convo_id,
        &harness.sequencer_ds_did,
        LOCAL_DS_DID,
        &harness.sequencer_ds_did,
        1,
        &msg_digest,
    );
    let locator_json = make_entry_locator_json(msg_entry_id, 2, &entry_sha256, &outer_fp);

    let deliver_msg_body = json!({
        "header": header_json,
        "entryLocator": locator_json,
        "recipientDid": recipient.did,
        "entryBytes": { "$bytes": STANDARD.encode(&entry_bytes) },
        "signedRequestBytes": { "$bytes": STANDARD.encode(&signed_req_bytes) },
    });

    let jwt = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        DELIVER_MESSAGE_NSID,
    );

    let (status, body, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverMessage",
            Some(&jwt),
            &deliver_msg_body,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "deliverMessage with attachment must succeed: {body:?}"
    );

    // Verify blob binding transitioned to bound
    let blob_status: String =
        sqlx::query_scalar("SELECT status FROM chat.blobs WHERE blob_id = $1")
            .bind(blob_id)
            .fetch_one(&harness.pool)
            .await
            .unwrap();
    assert_eq!(
        blob_status, "bound",
        "blob must be bound after deliverMessage"
    );

    let binding_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.blob_bindings WHERE blob_id = $1 AND conversation_id = $2 AND entry_seq = 2)",
    )
    .bind(blob_id)
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert!(binding_exists, "blob binding record must exist in DB");
}

// =============================================================================
// Test 4: submitCommit Authenticated Routing & Replay
// =============================================================================

#[tokio::test]
async fn test_submit_commit_router_authenticated_positive_and_replay() {
    let harness = TestHarness::new("commit").await;
    let now = Utc::now();

    let (
        convo_id,
        creation_transition_id,
        generic_transition_id,
        alice,
        _bob,
        group_id,
        committed_group_context_hash,
        committed_confirmation_tag,
        generic_group_context_hash,
        generic_confirmation_tag,
    ) = seed_corpus_conversation_at_added(&harness.pool, &harness.sender_ds_did, None, now).await;

    let commit_bytes = corpus_file("commit-generic-public.mls");
    let (_, signed_req_bytes) = make_corpus_commit_body(
        convo_id,
        generic_transition_id,
        creation_transition_id,
        &alice.did,
        alice.device_id,
        &alice.key_id,
        &alice.public_key,
        &alice.signing_key,
        &group_id,
        &committed_group_context_hash,
        &committed_confirmation_tag,
        &generic_group_context_hash,
        &generic_confirmation_tag,
        &commit_bytes,
        now,
    );

    let delivery_id = Uuid::new_v4();
    let mut header_model = ValidatedEnvelopeHeader {
        protocol_version: "1".to_string(),
        delivery_id,
        conversation_id: convo_id,
        sender_ds_did: harness.sender_ds_did.clone(),
        receiver_ds_did: LOCAL_DS_DID.to_string(),
        sequencer_did: LOCAL_DS_DID.to_string(),
        sequencer_term: 1,
        payload_sha256: [0u8; 32],
    };

    let commit_digest = compute_commit_envelope_digest(&header_model, &signed_req_bytes).unwrap();
    header_model.payload_sha256 = commit_digest;

    let header_json = make_envelope_header_json(
        delivery_id,
        convo_id,
        &harness.sender_ds_did,
        LOCAL_DS_DID,
        LOCAL_DS_DID,
        1,
        &commit_digest,
    );

    let submit_commit_body = json!({
        "header": header_json,
        "signedRequestBytes": { "$bytes": STANDARD.encode(&signed_req_bytes) },
    });

    let jwt = harness.mint_jwt(SUBMIT_COMMIT_NSID);

    // 1. Missing auth -> 401 Unauthorized
    let (status_unauth, _, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.submitCommit",
            None,
            &submit_commit_body,
        )
        .await;
    assert_eq!(status_unauth, StatusCode::UNAUTHORIZED);

    // 2. Positive authenticated submitCommit
    let (status, body, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.submitCommit",
            Some(&jwt),
            &submit_commit_body,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "submitCommit must succeed: {body:?}"
    );
    assert_eq!(body["receipt"]["deliveryId"], delivery_id.to_string());

    // 3. Verify receipt in DB
    let receipt_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.federation_delivery_receipts WHERE delivery_id = $1",
    )
    .bind(delivery_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert_eq!(receipt_count, 1, "receipt must be persisted");

    // 4. Idempotent replay
    let jwt2 = harness.mint_jwt(SUBMIT_COMMIT_NSID);
    let (status2, body2, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.submitCommit",
            Some(&jwt2),
            &submit_commit_body,
        )
        .await;
    assert_eq!(status2, StatusCode::OK, "replay must succeed: {body2:?}");
    assert_eq!(body2, body, "replay body must match original");
}

#[tokio::test]
async fn test_submit_commit_router_rejects_mock_and_corrupted_bytes() {
    let harness = TestHarness::new("commit-reject").await;
    let now = Utc::now();

    let (
        convo_id,
        _creation_transition_id,
        _generic_transition_id,
        alice,
        _bob,
        group_id,
        _committed_group_context_hash,
        _committed_confirmation_tag,
        _generic_group_context_hash,
        _generic_confirmation_tag,
    ) = seed_corpus_conversation_at_added(&harness.pool, &harness.sender_ds_did, None, now).await;

    // 1. Mock bytes (8 dummy bytes 0x5a) must be rejected by canonical validation and NOT succeed
    let mock_transition_id = Uuid::new_v4();
    let (_, mock_signed_req_bytes) =
        make_commit_body(convo_id, mock_transition_id, &alice, &group_id, now);
    let delivery_id_mock = Uuid::new_v4();
    let header_model_mock = ValidatedEnvelopeHeader {
        protocol_version: "1".to_string(),
        delivery_id: delivery_id_mock,
        conversation_id: convo_id,
        sender_ds_did: harness.sender_ds_did.clone(),
        receiver_ds_did: LOCAL_DS_DID.to_string(),
        sequencer_did: LOCAL_DS_DID.to_string(),
        sequencer_term: 1,
        payload_sha256: [0u8; 32],
    };
    let mock_digest =
        compute_commit_envelope_digest(&header_model_mock, &mock_signed_req_bytes).unwrap();
    let mock_header_json = make_envelope_header_json(
        delivery_id_mock,
        convo_id,
        &harness.sender_ds_did,
        LOCAL_DS_DID,
        LOCAL_DS_DID,
        1,
        &mock_digest,
    );
    let mock_body = json!({
        "header": mock_header_json,
        "signedRequestBytes": { "$bytes": STANDARD.encode(&mock_signed_req_bytes) },
    });
    let jwt_mock = harness.mint_jwt(SUBMIT_COMMIT_NSID);
    let (status_mock, body_mock, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.submitCommit",
            Some(&jwt_mock),
            &mock_body,
        )
        .await;
    assert_ne!(
        status_mock,
        StatusCode::OK,
        "mock bytes commit MUST NOT succeed: {body_mock:?}"
    );

    // Verify NO delivery receipt was written for the rejected mock commit
    let receipt_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.federation_delivery_receipts WHERE delivery_id = $1",
    )
    .bind(delivery_id_mock)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert_eq!(
        receipt_count, 0,
        "rejected mock commit must not leave delivery receipt"
    );
}

// =============================================================================
// Test 5: Direct SQL Immutability & Completeness Verification
// =============================================================================

#[tokio::test]
async fn test_direct_sql_immutability_and_operation_claims_completeness() {
    let harness = TestHarness::new("immutability").await;
    let now = Utc::now();
    let delivery_id = Uuid::new_v4();
    let convo_id = Uuid::new_v4();
    let sender_ds = harness.sender_ds_did.clone();

    // Seed conversation first to satisfy FK
    let creator = TestActor::generate();
    creator.seed(&harness.pool, now).await;
    let group_id = vec![0x99u8; 32];
    seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        1,
        &creator,
        None,
        now,
    )
    .await;

    // Reuse the creation entry seeded by seed_conversation_structure (seq 1) as the
    // mandatory non-null source locator for the direct receipt insert.
    let (src_entry_id, src_entry_seq, src_fp): (Uuid, i64, Vec<u8>) = sqlx::query_as(
        "SELECT entry_id, seq, outer_entry_fingerprint FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.federation_delivery_receipts (
            delivery_id, endpoint_nsid, conversation_id, sender_ds_did, receiver_ds_did,
            sequencer_did, sequencer_term, envelope_sha256, result_sha256,
            source_entry_id, source_entry_seq, source_entry_fingerprint,
            response_bytes, response_sha256, receipt_signature, completed_at
        ) VALUES (
            $1, 'blue.catbird.mlsDS.deliverMessage', $2, $3, $4,
            $4, 1, repeat('d', 32)::bytea, repeat('s', 32)::bytea,
            $6, $7, $8,
            '{"status":"delivered"}'::bytea, repeat('p', 32)::bytea, repeat('r', 64)::bytea, $5
        )
        "#,
    )
    .bind(delivery_id)
    .bind(convo_id)
    .bind(&sender_ds)
    .bind(LOCAL_DS_DID)
    .bind(now)
    .bind(src_entry_id)
    .bind(src_entry_seq)
    .bind(&src_fp)
    .execute(&harness.pool)
    .await
    .unwrap();

    // Immutability: UPDATE must fail via trigger
    let update_err = sqlx::query(
        "UPDATE chat.federation_delivery_receipts SET sender_ds_did = 'did:web:evil.com' WHERE delivery_id = $1",
    )
    .bind(delivery_id)
    .execute(&harness.pool)
    .await
    .unwrap_err();
    assert!(
        update_err.to_string().contains("immutable")
            || update_err.to_string().contains("cannot be modified"),
        "UPDATE on federation_delivery_receipts must be rejected by trigger: {update_err}"
    );

    // Immutability: DELETE must fail via trigger
    let delete_err =
        sqlx::query("DELETE FROM chat.federation_delivery_receipts WHERE delivery_id = $1")
            .bind(delivery_id)
            .execute(&harness.pool)
            .await
            .unwrap_err();
    assert!(
        delete_err.to_string().contains("immutable")
            || delete_err.to_string().contains("cannot be modified"),
        "DELETE on federation_delivery_receipts must be rejected by trigger: {delete_err}"
    );

    // Deliveries share the client operation-claim endpoints: deliverMessage uses
    // blue.catbird.chat.sendMessage and submitCommit uses blue.catbird.chat.submitTransition.
    // Migration 00004 is strictly additive and does not rewrite the shared classifiers.
    let check_def: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'operation_claims_endpoint_check'",
    )
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert!(check_def.contains("blue.catbird.chat.sendMessage"));
    assert!(check_def.contains("blue.catbird.chat.submitTransition"));

    // The migration 00004 no longer rewrites the shared operation claim / idempotency
    // endpoint classifiers; it is strictly additive. Verify that a receipt with a NULL
    // source locator is rejected by the CHECK.
    let null_locator_err = sqlx::query(
        r#"
        INSERT INTO chat.federation_delivery_receipts (
            delivery_id, endpoint_nsid, conversation_id, sender_ds_did, receiver_ds_did,
            sequencer_did, sequencer_term, envelope_sha256, result_sha256,
            source_entry_id, source_entry_seq, source_entry_fingerprint,
            response_bytes, response_sha256, receipt_signature, completed_at
        ) VALUES (
            $1, 'blue.catbird.mlsDS.deliverMessage', $2, $3, $4,
            $4, 1, repeat('d', 32)::bytea, repeat('s', 32)::bytea,
            NULL, NULL, NULL,
            '{"status":"delivered"}'::bytea, repeat('p', 32)::bytea, repeat('r', 64)::bytea, $5
        )
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(convo_id)
    .bind(&sender_ds)
    .bind(LOCAL_DS_DID)
    .bind(now)
    .execute(&harness.pool)
    .await
    .unwrap_err();
    assert!(
        null_locator_err.to_string().contains("source_entry_id")
            || null_locator_err.to_string().contains("not-null"),
        "NULL source locator must be rejected: {null_locator_err}"
    );
}

#[tokio::test]
async fn test_deliver_message_router_concurrency_revocation_fails_closed() {
    let harness = TestHarness::new("msg-revoc").await;
    let now = Utc::now();
    let convo_id = Uuid::new_v4();
    let group_id = vec![0x22u8; 32];

    let recipient = TestActor::generate();
    recipient.seed(&harness.pool, now).await;

    seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        1,
        &recipient,
        None,
        now,
    )
    .await;

    let actor = TestActor::generate();
    actor.seed(&harness.pool, now).await;

    let message_id = Uuid::new_v4();
    let msg_entry_id = Uuid::new_v4();
    let (_, signed_req_bytes) =
        make_message_body(convo_id, message_id, &actor, &group_id, vec![], now);

    let mutation =
        decode_and_verify_signed_mutation(&signed_req_bytes, actor.public_key.as_slice()).unwrap();
    let received_at = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&now.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
    );
    let built = build_verified_application_entry(
        mutation,
        CanonicalUuidV4::parse(&msg_entry_id.to_string()).unwrap(),
        CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
        2,
        &received_at,
    )
    .unwrap();
    let entry_bytes = built.canonical_entry_bytes().to_vec();
    let entry_sha256 = *built.accepted_payload_sha256();
    let outer_fp = *built.outer_application_fingerprint();

    let delivery_id = Uuid::new_v4();
    let mut header_model = ValidatedEnvelopeHeader {
        protocol_version: "1".to_string(),
        delivery_id,
        conversation_id: convo_id,
        sender_ds_did: harness.sequencer_ds_did.clone(),
        receiver_ds_did: LOCAL_DS_DID.to_string(),
        sequencer_did: harness.sequencer_ds_did.clone(),
        sequencer_term: 1,
        payload_sha256: [0u8; 32],
    };
    let locator_model = ValidatedEntryLocator {
        entry_id: msg_entry_id,
        seq: 2,
        accepted_payload_sha256: entry_sha256,
        outer_entry_fingerprint: outer_fp,
    };

    let msg_digest = compute_message_envelope_digest(
        &header_model,
        &recipient.did,
        &locator_model,
        &entry_bytes,
        &signed_req_bytes,
    )
    .unwrap();
    header_model.payload_sha256 = msg_digest;

    let header_json = make_envelope_header_json(
        delivery_id,
        convo_id,
        &harness.sequencer_ds_did,
        LOCAL_DS_DID,
        &harness.sequencer_ds_did,
        1,
        &msg_digest,
    );
    let locator_json = make_entry_locator_json(msg_entry_id, 2, &entry_sha256, &outer_fp);

    let deliver_msg_body = json!({
        "header": header_json,
        "entryLocator": locator_json,
        "recipientDid": recipient.did,
        "entryBytes": { "$bytes": STANDARD.encode(&entry_bytes) },
        "signedRequestBytes": { "$bytes": STANDARD.encode(&signed_req_bytes) },
    });

    let jwt = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        DELIVER_MESSAGE_NSID,
    );

    // 1. Begin a concurrent transaction that locks the recipient's active leaf FOR UPDATE
    //    and deactivates it (simulating concurrent leaf revocation).
    let mut tx_revoke = harness.pool.begin().await.unwrap();
    sqlx::query(
        "UPDATE chat.devices \
         SET status = 'revoked', revoked_at = NOW() \
         WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .execute(&mut *tx_revoke)
    .await
    .unwrap();
    tx_revoke.commit().await.unwrap();
    // 2. Deliver message must fail closed because recipient has no active member leaf
    let (status, body, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverMessage",
            Some(&jwt),
            &deliver_msg_body,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "deliverMessage to revoked/deactivated leaf must fail with 403: {body:?}"
    );
    assert_eq!(body["error"], "UnauthorizedRecipient");
}

#[tokio::test]
async fn test_deliver_welcome_router_concurrency_revocation_fails_closed() {
    let harness = TestHarness::new("welcome-revoc").await;
    let now = Utc::now();
    let convo_id = Uuid::new_v4();
    let group_id = vec![0x11u8; 32];
    let creator = TestActor::generate();
    creator.seed(&harness.pool, now).await;

    let mut recipient = TestActor::generate();
    recipient.did = creator.did.clone();
    recipient.seed(&harness.pool, now).await;

    let (creation_transition_id, _creation_entry_id, _, _, _, _) = seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        1,
        &creator,
        None,
        now,
    )
    .await;

    let fulfillment_transition_id = Uuid::new_v4();
    let fulfillment_entry_id = fulfillment_transition_id;
    let welcome_id = Uuid::new_v4();
    let recovery_request_id = Uuid::new_v4();
    let welcome_bytes = corpus_file("welcome.mls");
    let welcome_sha256: [u8; 32] = Sha256::digest(&welcome_bytes).into();
    let manifest_bytes = corpus_file("manifest.json");
    let manifest: Value = serde_json::from_slice(&manifest_bytes).expect("parse manifest.json");
    let key_package_ref = hex_array(manifest["chain"]["innerKeyPackageRefHex"].as_str().unwrap());
    let public_snapshot_bytes = vec![0x88u8; 16];
    let public_snapshot_sha256: [u8; 32] = Sha256::digest(&public_snapshot_bytes).into();
    let creator_credential = format!("{}#{}", creator.did, creator.device_id).into_bytes();
    let recipient_credential = format!("{}#{}", recipient.did, recipient.device_id).into_bytes();
    let enc_key = vec![0x64u8; 1216];
    let (tree_summary_bytes, tree_summary_sha256) = make_tree_summary_bytes(
        &[0x63u8; 32],
        &[
            (0, &creator_credential, &creator.public_key, &enc_key),
            (1, &recipient_credential, &recipient.public_key, &enc_key),
        ],
    );

    let (_, signed_req_bytes) = make_leaf_recovery_fulfillment_body(
        convo_id,
        fulfillment_transition_id,
        recovery_request_id,
        creation_transition_id,
        &creator,
        &group_id,
        now,
    );
    let mutation =
        decode_and_verify_signed_mutation(&signed_req_bytes, creator.public_key.as_slice())
            .unwrap();
    let received_at = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&now.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
    );
    let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.submitTransition").unwrap();
    let server_fields =
        CanonicalControlServerFields::empty(ControlEntryKind::LeafRecoveryFulfillment).unwrap();
    let built = build_verified_control_entry(
        mutation,
        &endpoint,
        CanonicalUuidV4::parse(&fulfillment_entry_id.to_string()).unwrap(),
        CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
        2,
        &received_at,
        server_fields,
    )
    .unwrap();
    let products = CanonicalControlEntryProducts::mint(&built).unwrap();
    let entry_bytes = products.durable_json().to_vec();
    let entry_sha256: [u8; 32] = Sha256::digest(&entry_bytes).into();
    let outer_fp = *built.outer_control_fingerprint();

    let mut tx = harness.pool.begin().await.unwrap();
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *tx)
        .await
        .unwrap();

    // Seed key package
    sqlx::query(
        r#"
        INSERT INTO chat.key_packages (
            key_package_ref, wrapper_bytes, wrapper_sha256, init_key,
            owner_did, owner_device_id, owner_key_id, owner_auth_generation,
            not_before, not_after, status, terminal_transition_id, terminal_at, created_at
        ) VALUES (
            $1, repeat('w', 32)::bytea, digest(repeat('w', 32)::bytea, 'sha256'), repeat('k', 32)::bytea,
            $2, $3, $4, 1,
            $5 - INTERVAL '5 minutes', $5 + INTERVAL '1 hour', 'consumed', $6, $5, $5
        )
        "#,
    )
    .bind(&key_package_ref[..])
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(&recipient.key_id)
    .bind(now)
    .bind(fulfillment_transition_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Seed leaf recovery request
    sqlx::query(
        r#"
        INSERT INTO chat.leaf_recovery_requests (
            recovery_request_id, conversation_id, generation, requester_did,
            requester_device_id, requester_key_id, requester_auth_generation,
            recovery_kind, source, bound_state_version, bound_group_id, bound_epoch,
            bound_group_context_hash, bound_confirmation_tag, reservation_request_id,
            status, fulfilling_transition_id, terminal_at,
            signed_request_bytes, signing_transcript_bytes, request_digest, signature,
            requested_at, expires_at
        ) VALUES (
            $1, $2, 0, $3,
            $4, $5, 1,
            'add', 'acceptConversation', 0, $6, 0,
            $7, $7, $1,
            'fulfilled', $8, $9,
            repeat('r', 32)::bytea, repeat('t', 32)::bytea, digest(repeat('t', 32)::bytea, 'sha256'), repeat('s', 64)::bytea,
            $9, $9 + INTERVAL '5 minutes'
        )
        "#,
    )
    .bind(recovery_request_id)
    .bind(convo_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(&recipient.key_id)
    .bind(&group_id)
    .bind(&[0u8; 32])
    .bind(fulfillment_transition_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Seed key package reservation
    sqlx::query(
        r#"
        INSERT INTO chat.key_package_reservations (
            recovery_request_id, key_package_ref, conversation_id, generation, requester_did,
            requester_device_id, requester_key_id, requester_auth_generation, recipient_did,
            recipient_device_id, bound_state_version, bound_group_id, bound_epoch,
            bound_group_context_hash, bound_confirmation_tag, purpose, expires_at, status,
            consumed_transition_id, terminal_at, created_at
        ) VALUES (
            $1, $2, $3, 0, $4,
            $5, $6, 1, $4,
            $5, 0, $7, 0,
            $8, $8, 'leafRecovery', $9 + INTERVAL '5 minutes', 'consumed',
            $10, $9, $9
        )
        "#,
    )
    .bind(recovery_request_id)
    .bind(&key_package_ref[..])
    .bind(convo_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(&recipient.key_id)
    .bind(&group_id)
    .bind(&[0u8; 32])
    .bind(now)
    .bind(fulfillment_transition_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Seed generation_states for state_version 1
    sqlx::query(
        r#"
        INSERT INTO chat.generation_states (
            conversation_id, generation, state_version, group_id, epoch,
            group_context_hash, confirmation_tag, lifecycle, state_kind,
            producing_transition_id, public_snapshot_bytes, snapshot_sha256,
            tree_summary_bytes, tree_summary_sha256, leaf_count, created_at
        ) VALUES (
            $1, 0, 1, $2, 1,
            $5, $5, 'active', 'commit',
            $3, $6, $7,
            $8, $9, 2, $4
        )
        "#,
    )
    .bind(convo_id)
    .bind(&group_id)
    .bind(fulfillment_transition_id)
    .bind(now)
    .bind(&[0x32u8; 32])
    .bind(&public_snapshot_bytes)
    .bind(&public_snapshot_sha256[..])
    .bind(&tree_summary_bytes)
    .bind(&tree_summary_sha256[..])
    .execute(&mut *tx)
    .await
    .unwrap();

    let metadata_snapshot_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO chat.metadata_snapshots (
            metadata_snapshot_id, conversation_id, generation, state_version,
            group_id, epoch, group_context_hash, confirmation_tag,
            producing_transition_id, origin_transition_id, metadata_version,
            nonce, ciphertext, ciphertext_sha256, ciphertext_size,
            author_did, author_device_id, author_key_id, author_public_key,
            author_auth_generation, author_origin_seq, author_role, author_device_status, created_at
        ) VALUES (
            $1, $2, 0, 1,
            $3, 1, $4, $4,
            $5, $6, 1,
            $12, repeat('c', 16)::bytea, digest(repeat('c', 16)::bytea, 'sha256'), 16,
            $7, $8, $9, $10,
            1, 1, 'admin', 'active', $11
        )
        "#,
    )
    .bind(metadata_snapshot_id)
    .bind(convo_id)
    .bind(&group_id)
    .bind(&[0x32u8; 32])
    .bind(fulfillment_transition_id)
    .bind(creation_transition_id)
    .bind(&creator.did)
    .bind(creator.device_id)
    .bind(&creator.key_id)
    .bind(&creator.public_key[..])
    .bind(now)
    .bind(&[0xE1_u8; 12])
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.transitions (
            transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id,
            actor_auth_generation, actor_role, actor_device_status, signed_request_bytes,
            unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature,
            prior_generation, prior_state_version, next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at
        ) VALUES (
            $1, $2, 'leafRecovery', $3, $4, $5,
            1, 'admin', 'active', $6,
            $7, $8, $9, $10,
            0, 0, 0, 1, $11, 2, $12
        )
        "#,
    )
    .bind(fulfillment_transition_id)
    .bind(convo_id)
    .bind(&creator.did)
    .bind(creator.device_id)
    .bind(&creator.key_id)
    .bind(&signed_req_bytes)
    .bind(built.mutation().canonical_projection())
    .bind(built.mutation().transcript_bytes())
    .bind(built.mutation().request_digest().as_slice())
    .bind(built.mutation().signature().as_slice())
    .bind(metadata_snapshot_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Seed entries
    // Seed entries
    sqlx::query(
        r#"
        INSERT INTO chat.entries (
            conversation_id, seq, entry_id, entry_kind,
            accepted_payload_bytes, accepted_payload_sha256,
            signed_request_bytes, request_digest, signature,
            server_fields_bytes, outer_entry_fingerprint,
            actor_did, actor_device_id, actor_key_id, actor_auth_generation,
            generation, state_version, transition_id, received_at
        ) VALUES (
            $1, 2, $2, 'blue.catbird.chat.defs#leafRecoveryFulfillmentEntry',
            $3, $4,
            $5, $6, $7,
            repeat('0', 1)::bytea, $8,
            $9, $10, $11, 1,
            0, 1, $12, $13
        )
        "#,
    )
    .bind(convo_id)
    .bind(fulfillment_entry_id)
    .bind(&entry_bytes)
    .bind(&entry_sha256[..])
    .bind(&signed_req_bytes)
    .bind(built.mutation().request_digest().as_slice())
    .bind(built.mutation().signature().as_slice())
    .bind(&outer_fp[..])
    .bind(&creator.did)
    .bind(creator.device_id)
    .bind(&creator.key_id)
    .bind(fulfillment_transition_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Update conversation & generation current_state_version = 1, next_entry_seq = 3
    sqlx::query("UPDATE chat.conversations SET current_state_version = 1, next_entry_seq = 3 WHERE conversation_id = $1")
        .bind(convo_id)
        .execute(&mut *tx)
        .await
        .unwrap();

    sqlx::query("UPDATE chat.generations SET current_state_version = 1 WHERE conversation_id = $1")
        .bind(convo_id)
        .execute(&mut *tx)
        .await
        .unwrap();

    let recipient_leaf_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO chat.member_devices (
            leaf_period_id, participant_period_id, conversation_id, generation,
            user_did, device_id, leaf_index, basic_credential, leaf_signature_key,
            leaf_key_id, leaf_auth_generation, origin,
            join_key_package_ref, joined_state_version, joined_transition_id,
            joined_seq, active, created_at
        ) VALUES (
            $1, (SELECT participant_period_id FROM chat.participants WHERE conversation_id = $2 AND user_did = $3),
            $2, 0, $3, $4, 1, $5,
            $6, $7, 1, 'keyPackage',
            $8, 1, $9, 2, TRUE, $10
        )
        "#,
    )
    .bind(recipient_leaf_id)
    .bind(convo_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(&recipient_credential)
    .bind(&recipient.public_key[..])
    .bind(&recipient.key_id)
    .bind(&key_package_ref[..])
    .bind(fulfillment_transition_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.application_intervals (
            membership_interval_id, conversation_id, generation, recipient_did, recipient_device_id,
            start_seq, opening_kind, opening_transition_id, opening_outer_entry_fingerprint,
            opening_state_version, opening_group_id, opening_epoch, opening_group_context_hash,
            opening_confirmation_tag, opening_leaf_period_id, created_at
        ) VALUES (
            $1, $2, 0, $3, $4,
            2, 'add', $5, $6,
            1, $7, 1, $8,
            $8, $9, $10
        )
        "#,
    )
    .bind(fulfillment_transition_id)
    .bind(convo_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(fulfillment_transition_id)
    .bind(&outer_fp[..])
    .bind(&group_id)
    .bind(&[0x32u8; 32])
    .bind(recipient_leaf_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Seed welcome bundle
    sqlx::query(
        r#"
        INSERT INTO chat.welcome_bundles (
            welcome_id, conversation_id, transition_id, entry_seq, generation, state_version,
            group_id, epoch, group_context_hash, confirmation_tag,
            wrapper_bytes, wrapper_sha256, created_at
        ) VALUES (
            $1, $2, $3, 2, 0, 1,
            $4, 1, $7, $7,
            $5, $6, $8
        )
        "#,
    )
    .bind(welcome_id)
    .bind(convo_id)
    .bind(fulfillment_transition_id)
    .bind(&group_id)
    .bind(&welcome_bytes)
    .bind(&welcome_sha256[..])
    .bind(&[0x32u8; 32])
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // 11. Seed welcome delivery
    sqlx::query(
        r#"
        INSERT INTO chat.welcome_deliveries (
            welcome_id, recipient_did, recipient_device_id, recovery_request_id,
            key_package_ref, expires_at, status
        ) VALUES (
            $1, $2, $3, $4,
            $5, $6 + INTERVAL '1 hour', 'pending'
        )
        "#,
    )
    .bind(welcome_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(recovery_request_id)
    .bind(&key_package_ref[..])
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    tx.commit().await.unwrap();

    let delivery_id = Uuid::new_v4();
    let mut header_model = ValidatedEnvelopeHeader {
        protocol_version: "1".to_string(),
        delivery_id,
        conversation_id: convo_id,
        sender_ds_did: harness.sequencer_ds_did.clone(),
        receiver_ds_did: LOCAL_DS_DID.to_string(),
        sequencer_did: harness.sequencer_ds_did.clone(),
        sequencer_term: 1,
        payload_sha256: [0u8; 32],
    };
    let locator_model = ValidatedEntryLocator {
        entry_id: fulfillment_entry_id,
        seq: 2,
        accepted_payload_sha256: entry_sha256,
        outer_entry_fingerprint: outer_fp,
    };
    let coordinates_dto = ConversationCoordinates {
        conversation_id: jacquard_common::deps::smol_str::SmolStr::from(convo_id.to_string()),
        generation: 0,
        state_version: 1,
        group_id: jacquard_common::deps::bytes::Bytes::copy_from_slice(&group_id),
        epoch: 1,
        group_context_hash: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0x32u8; 32]),
        confirmation_tag: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0x32u8; 32]),
        lifecycle: jacquard_common::deps::smol_str::SmolStr::from("active"),
        extra_data: None,
    };

    let welcome_digest = compute_welcome_envelope_digest(
        &header_model,
        &recipient.did,
        recipient.device_id,
        welcome_id,
        recovery_request_id,
        &key_package_ref,
        &welcome_bytes,
        &welcome_sha256,
        &entry_bytes,
        &signed_req_bytes,
        &locator_model,
        &coordinates_dto,
        &public_snapshot_sha256,
        &tree_summary_sha256,
    )
    .unwrap();
    header_model.payload_sha256 = welcome_digest;

    let header_json = make_envelope_header_json(
        delivery_id,
        convo_id,
        &harness.sequencer_ds_did,
        LOCAL_DS_DID,
        &harness.sequencer_ds_did,
        1,
        &welcome_digest,
    );
    let locator_json = make_entry_locator_json(fulfillment_entry_id, 2, &entry_sha256, &outer_fp);

    let deliver_welcome_body = json!({
        "header": header_json,
        "recipientDid": recipient.did,
        "recipientDeviceId": recipient.device_id.to_string(),
        "recoveryRequestId": recovery_request_id.to_string(),
        "welcomeId": welcome_id.to_string(),
        "welcomeBytes": { "$bytes": STANDARD.encode(&welcome_bytes) },
        "welcomeSha256": { "$bytes": STANDARD.encode(&welcome_sha256) },
        "keyPackageRef": { "$bytes": STANDARD.encode(&key_package_ref) },
        "coordinates": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 1,
            "epoch": 1,
            "groupId": { "$bytes": STANDARD.encode(&group_id) },
            "groupContextHash": { "$bytes": STANDARD.encode(&[0x32u8; 32]) },
            "confirmationTag": { "$bytes": STANDARD.encode(&[0x32u8; 32]) },
            "lifecycle": "active",
        },
        "publicSnapshotSha256": { "$bytes": STANDARD.encode(&public_snapshot_sha256) },
        "treeSummarySha256": { "$bytes": STANDARD.encode(&tree_summary_sha256) },
        "entryLocator": locator_json,
        "signedRequestBytes": { "$bytes": STANDARD.encode(&signed_req_bytes) },
        "entryBytes": { "$bytes": STANDARD.encode(&entry_bytes) },
    });

    let jwt = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        DELIVER_WELCOME_NSID,
    );

    let mut tx_revoke = harness.pool.begin().await.unwrap();
    sqlx::query(
        "UPDATE chat.devices \
         SET status = 'revoked', revoked_at = NOW() \
         WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .execute(&mut *tx_revoke)
    .await
    .unwrap();
    tx_revoke.commit().await.unwrap();
    // Welcome delivery must fail closed with 400 MailboxNotProvisioned because leaf is not active
    let (status, body, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverWelcome",
            Some(&jwt),
            &deliver_welcome_body,
        )
        .await;
    println!("deliver_welcome response: status={status}, body={body:?}");
    assert!(
        status.is_client_error(),
        "deliverWelcome with revoked leaf must fail with client error: {body:?}"
    );
}

#[tokio::test]
async fn test_deliver_welcome_router_cancelled_or_stale_welcome_rejects() {
    let harness = TestHarness::new("welcome-stale").await;
    let now = Utc::now();
    let convo_id = Uuid::new_v4();
    let group_id = vec![0x11u8; 32];
    let creator = TestActor::generate();
    creator.seed(&harness.pool, now).await;

    let mut recipient = TestActor::generate();
    recipient.did = creator.did.clone();
    recipient.seed(&harness.pool, now).await;

    let (creation_transition_id, _creation_entry_id, _, _, _, _) = seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        1,
        &creator,
        None,
        now,
    )
    .await;

    let fulfillment_transition_id = Uuid::new_v4();
    let fulfillment_entry_id = fulfillment_transition_id;
    let welcome_id = Uuid::new_v4();
    let recovery_request_id = Uuid::new_v4();
    let welcome_bytes = corpus_file("welcome.mls");
    let welcome_sha256: [u8; 32] = Sha256::digest(&welcome_bytes).into();
    let manifest_bytes = corpus_file("manifest.json");
    let manifest: Value = serde_json::from_slice(&manifest_bytes).expect("parse manifest.json");
    let key_package_ref = hex_array(manifest["chain"]["innerKeyPackageRefHex"].as_str().unwrap());
    let public_snapshot_bytes = vec![0x88u8; 16];
    let public_snapshot_sha256: [u8; 32] = Sha256::digest(&public_snapshot_bytes).into();
    let creator_credential = format!("{}#{}", creator.did, creator.device_id).into_bytes();
    let recipient_credential = format!("{}#{}", recipient.did, recipient.device_id).into_bytes();
    let enc_key = vec![0x64u8; 1216];
    let (tree_summary_bytes, tree_summary_sha256) = make_tree_summary_bytes(
        &[0x63u8; 32],
        &[
            (0, &creator_credential, &creator.public_key, &enc_key),
            (1, &recipient_credential, &recipient.public_key, &enc_key),
        ],
    );

    let (_, signed_req_bytes) = make_leaf_recovery_fulfillment_body(
        convo_id,
        fulfillment_transition_id,
        recovery_request_id,
        creation_transition_id,
        &creator,
        &group_id,
        now,
    );
    let mutation =
        decode_and_verify_signed_mutation(&signed_req_bytes, creator.public_key.as_slice())
            .unwrap();
    let received_at = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&now.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
    );
    let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.submitTransition").unwrap();
    let server_fields =
        CanonicalControlServerFields::empty(ControlEntryKind::LeafRecoveryFulfillment).unwrap();
    let built = build_verified_control_entry(
        mutation,
        &endpoint,
        CanonicalUuidV4::parse(&fulfillment_entry_id.to_string()).unwrap(),
        CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
        2,
        &received_at,
        server_fields,
    )
    .unwrap();
    let products = CanonicalControlEntryProducts::mint(&built).unwrap();
    let entry_bytes = products.durable_json().to_vec();
    let entry_sha256: [u8; 32] = Sha256::digest(&entry_bytes).into();
    let outer_fp = *built.outer_control_fingerprint();

    let mut tx = harness.pool.begin().await.unwrap();
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *tx)
        .await
        .unwrap();

    // Seed key package
    sqlx::query(
        r#"
        INSERT INTO chat.key_packages (
            key_package_ref, wrapper_bytes, wrapper_sha256, init_key,
            owner_did, owner_device_id, owner_key_id, owner_auth_generation,
            not_before, not_after, status, terminal_transition_id, terminal_at, created_at
        ) VALUES (
            $1, repeat('w', 32)::bytea, digest(repeat('w', 32)::bytea, 'sha256'), repeat('k', 32)::bytea,
            $2, $3, $4, 1,
            $5 - INTERVAL '5 minutes', $5 + INTERVAL '1 hour', 'consumed', $6, $5, $5
        )
        "#,
    )
    .bind(&key_package_ref[..])
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(&recipient.key_id)
    .bind(now)
    .bind(fulfillment_transition_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    // 3. Seed leaf recovery request (fulfilled)
    sqlx::query(
        r#"
        INSERT INTO chat.leaf_recovery_requests (
            recovery_request_id, conversation_id, generation, requester_did,
            requester_device_id, requester_key_id, requester_auth_generation,
            recovery_kind, source, bound_state_version, bound_group_id, bound_epoch,
            bound_group_context_hash, bound_confirmation_tag, reservation_request_id,
            status, fulfilling_transition_id, terminal_at,
            signed_request_bytes, signing_transcript_bytes, request_digest, signature,
            requested_at, expires_at
        ) VALUES (
            $1, $2, 0, $3,
            $4, $5, 1,
            'add', 'acceptConversation', 0, $6, 0,
            $7, $7, $1,
            'fulfilled', $8, $9,
            repeat('r', 32)::bytea, repeat('t', 32)::bytea, digest(repeat('t', 32)::bytea, 'sha256'), repeat('s', 64)::bytea,
            $9, $9 + INTERVAL '5 minutes'
        )
        "#,
    )
    .bind(recovery_request_id)
    .bind(convo_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(&recipient.key_id)
    .bind(&group_id)
    .bind(&[0u8; 32])
    .bind(fulfillment_transition_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // 4. Seed key package reservation (consumed)
    sqlx::query(
        r#"
        INSERT INTO chat.key_package_reservations (
            recovery_request_id, key_package_ref, conversation_id, generation, requester_did,
            requester_device_id, requester_key_id, requester_auth_generation, recipient_did,
            recipient_device_id, bound_state_version, bound_group_id, bound_epoch,
            bound_group_context_hash, bound_confirmation_tag, purpose, expires_at, status,
            consumed_transition_id, terminal_at, created_at
        ) VALUES (
            $1, $2, $3, 0, $4,
            $5, $6, 1, $4,
            $5, 0, $7, 0,
            $8, $8, 'leafRecovery', $9 + INTERVAL '5 minutes', 'consumed',
            $10, $9, $9
        )
        "#,
    )
    .bind(recovery_request_id)
    .bind(&key_package_ref[..])
    .bind(convo_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(&recipient.key_id)
    .bind(&group_id)
    .bind(&[0u8; 32])
    .bind(now)
    .bind(fulfillment_transition_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    let metadata_snapshot_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO chat.metadata_snapshots (
            metadata_snapshot_id, conversation_id, generation, state_version,
            group_id, epoch, group_context_hash, confirmation_tag,
            producing_transition_id, origin_transition_id, metadata_version,
            nonce, ciphertext, ciphertext_sha256, ciphertext_size,
            author_did, author_device_id, author_key_id, author_public_key,
            author_auth_generation, author_origin_seq, author_role, author_device_status, created_at
        ) VALUES (
            $1, $2, 0, 1,
            $3, 1, $4, $4,
            $5, $6, 1,
            $12, repeat('c', 16)::bytea, digest(repeat('c', 16)::bytea, 'sha256'), 16,
            $7, $8, $9, $10,
            1, 1, 'admin', 'active', $11
        )
        "#,
    )
    .bind(metadata_snapshot_id)
    .bind(convo_id)
    .bind(&group_id)
    .bind(&[0x32u8; 32])
    .bind(fulfillment_transition_id)
    .bind(creation_transition_id)
    .bind(&creator.did)
    .bind(creator.device_id)
    .bind(&creator.key_id)
    .bind(&creator.public_key[..])
    .bind(now)
    .bind(&[0xE1_u8; 12])
    .execute(&mut *tx)
    .await
    .unwrap();

    // Seed transition
    sqlx::query(
        r#"
        INSERT INTO chat.transitions (
            transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id,
            actor_auth_generation, actor_role, actor_device_status, signed_request_bytes,
            unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature,
            prior_generation, prior_state_version, next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at
        ) VALUES (
            $1, $2, 'leafRecovery', $3, $4, $5,
            1, 'admin', 'active', $6,
            $7, $8, $9, $10,
            0, 0, 0, 1, $11, 2, $12
        )
        "#,
    )
    .bind(fulfillment_transition_id)
    .bind(convo_id)
    .bind(&creator.did)
    .bind(creator.device_id)
    .bind(&creator.key_id)
    .bind(&signed_req_bytes)
    .bind(built.mutation().canonical_projection())
    .bind(built.mutation().transcript_bytes())
    .bind(built.mutation().request_digest().as_slice())
    .bind(built.mutation().signature().as_slice())
    .bind(metadata_snapshot_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Seed entry
    sqlx::query(
        r#"
        INSERT INTO chat.entries (
            conversation_id, seq, entry_id, entry_kind,
            accepted_payload_bytes, accepted_payload_sha256,
            signed_request_bytes, request_digest, signature,
            server_fields_bytes, outer_entry_fingerprint,
            actor_did, actor_device_id, actor_key_id, actor_auth_generation,
            generation, state_version, transition_id, received_at
        ) VALUES (
            $1, 2, $2, 'blue.catbird.chat.defs#leafRecoveryFulfillmentEntry',
            $3, $4,
            $5, $6, $7,
            repeat('0', 1)::bytea, $8,
            $9, $10, $11, 1,
            0, 1, $12, $13
        )
        "#,
    )
    .bind(convo_id)
    .bind(fulfillment_entry_id)
    .bind(&entry_bytes)
    .bind(&entry_sha256[..])
    .bind(&signed_req_bytes)
    .bind(built.mutation().request_digest().as_slice())
    .bind(built.mutation().signature().as_slice())
    .bind(&outer_fp[..])
    .bind(&creator.did)
    .bind(creator.device_id)
    .bind(&creator.key_id)
    .bind(fulfillment_transition_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        UPDATE chat.conversations
           SET current_state_version = 1,
               next_entry_seq = 3
         WHERE conversation_id = $1
        "#,
    )
    .bind(convo_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        UPDATE chat.generations
           SET current_state_version = 1
         WHERE conversation_id = $1 AND generation = 0
        "#,
    )
    .bind(convo_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    // 8. Seed generation_states for state_version 1
    sqlx::query(
        r#"
        INSERT INTO chat.generation_states (
            conversation_id, generation, state_version, group_id, epoch,
            group_context_hash, confirmation_tag, lifecycle, state_kind,
            producing_transition_id, public_snapshot_bytes, snapshot_sha256,
            tree_summary_bytes, tree_summary_sha256, leaf_count, created_at
        ) VALUES (
            $1, 0, 1, $2, 1,
            $5, $5, 'active', 'commit',
            $3, $6, $7,
            $8, $9, 2, $4
        )
        "#,
    )
    .bind(convo_id)
    .bind(&group_id)
    .bind(fulfillment_transition_id)
    .bind(now)
    .bind(&[0x32u8; 32])
    .bind(&public_snapshot_bytes)
    .bind(&public_snapshot_sha256[..])
    .bind(&tree_summary_bytes)
    .bind(&tree_summary_sha256[..])
    .execute(&mut *tx)
    .await
    .unwrap();

    // Seed welcome bundle and delivery
    let recipient_leaf_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO chat.member_devices (
            leaf_period_id, participant_period_id, conversation_id, generation,
            user_did, device_id, leaf_index, basic_credential,
            leaf_signature_key, leaf_key_id, leaf_auth_generation, origin,
            join_key_package_ref, joined_state_version, joined_transition_id, joined_seq, active, created_at
        ) VALUES (
            $1, (SELECT participant_period_id FROM chat.participants WHERE conversation_id = $2 AND user_did = $3 AND current_membership), $2, 0,
            $3, $4, 1, $5,
            $6, $7, 1, 'keyPackage',
            $8, 1, $9, 2, TRUE, $10
        )
        "#,
    )
    .bind(recipient_leaf_id)
    .bind(convo_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(&recipient_credential)
    .bind(&recipient.public_key[..])
    .bind(&recipient.key_id)
    .bind(&key_package_ref[..])
    .bind(fulfillment_transition_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.application_intervals (
            membership_interval_id, conversation_id, generation, recipient_did, recipient_device_id,
            start_seq, opening_kind, opening_transition_id, opening_outer_entry_fingerprint,
            opening_state_version, opening_group_id, opening_epoch, opening_group_context_hash,
            opening_confirmation_tag, opening_leaf_period_id, created_at
        ) VALUES (
            $1, $2, 0, $3, $4,
            2, 'add', $5, $6,
            1, $7, 1, $8,
            $8, $9, $10
        )
        "#,
    )
    .bind(fulfillment_transition_id)
    .bind(convo_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(fulfillment_transition_id)
    .bind(&outer_fp[..])
    .bind(&group_id)
    .bind(&[0x32u8; 32])
    .bind(recipient_leaf_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Seed welcome bundle
    sqlx::query(
        r#"
        INSERT INTO chat.welcome_bundles (
            welcome_id, conversation_id, transition_id, entry_seq, generation, state_version,
            group_id, epoch, group_context_hash, confirmation_tag,
            wrapper_bytes, wrapper_sha256, created_at
        ) VALUES (
            $1, $2, $3, 2, 0, 1,
            $4, 1, $7, $7,
            $5, $6, $8
        )
        "#,
    )
    .bind(welcome_id)
    .bind(convo_id)
    .bind(fulfillment_transition_id)
    .bind(&group_id)
    .bind(&welcome_bytes)
    .bind(&welcome_sha256[..])
    .bind(&[0x32u8; 32])
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Seed welcome delivery
    sqlx::query(
        r#"
        INSERT INTO chat.welcome_deliveries (
            welcome_id, recipient_did, recipient_device_id, recovery_request_id,
            key_package_ref, expires_at, status
        ) VALUES (
            $1, $2, $3, $4,
            $5, $6 + INTERVAL '1 hour', 'pending'
        )
        "#,
    )
    .bind(welcome_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(recovery_request_id)
    .bind(&key_package_ref[..])
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let welcome_digest = compute_welcome_envelope_digest(
        &ValidatedEnvelopeHeader {
            protocol_version: "1".to_string(),
            delivery_id: Uuid::new_v4(),
            conversation_id: convo_id,
            sender_ds_did: harness.sequencer_ds_did.clone(),
            receiver_ds_did: LOCAL_DS_DID.to_string(),
            sequencer_did: harness.sequencer_ds_did.clone(),
            sequencer_term: 1,
            payload_sha256: [0u8; 32],
        },
        &recipient.did,
        recipient.device_id,
        welcome_id,
        recovery_request_id,
        &key_package_ref,
        &welcome_bytes,
        &welcome_sha256,
        &entry_bytes,
        &signed_req_bytes,
        &ValidatedEntryLocator {
            entry_id: fulfillment_entry_id,
            seq: 2,
            accepted_payload_sha256: entry_sha256,
            outer_entry_fingerprint: outer_fp,
        },
        &ConversationCoordinates {
            conversation_id: jacquard_common::deps::smol_str::SmolStr::from(
                convo_id.hyphenated().to_string(),
            ),
            generation: 0,
            state_version: 1,
            epoch: 1,
            group_id: jacquard_common::deps::bytes::Bytes::copy_from_slice(&group_id),
            group_context_hash: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0x32u8; 32]),
            confirmation_tag: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0x32u8; 32]),
            lifecycle: jacquard_common::deps::smol_str::SmolStr::from("active"),
            extra_data: None,
        },
        &public_snapshot_sha256,
        &tree_summary_sha256,
    )
    .unwrap();

    let delivery_id = Uuid::new_v4();
    let header_json = make_envelope_header_json(
        delivery_id,
        convo_id,
        &harness.sequencer_ds_did,
        LOCAL_DS_DID,
        &harness.sequencer_ds_did,
        1,
        &welcome_digest,
    );
    let locator_json = make_entry_locator_json(fulfillment_entry_id, 2, &entry_sha256, &outer_fp);

    let deliver_welcome_body = json!({
        "header": header_json,
        "recipientDid": recipient.did,
        "recipientDeviceId": recipient.device_id.to_string(),
        "recoveryRequestId": recovery_request_id.to_string(),
        "welcomeId": welcome_id.to_string(),
        "welcomeBytes": { "$bytes": STANDARD.encode(&welcome_bytes) },
        "welcomeSha256": { "$bytes": STANDARD.encode(&welcome_sha256) },
        "keyPackageRef": { "$bytes": STANDARD.encode(&key_package_ref) },
        "coordinates": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 1,
            "epoch": 1,
            "groupId": { "$bytes": STANDARD.encode(&group_id) },
            "groupContextHash": { "$bytes": STANDARD.encode(&[0x32u8; 32]) },
            "confirmationTag": { "$bytes": STANDARD.encode(&[0x32u8; 32]) },
            "lifecycle": "active",
        },
        "publicSnapshotSha256": { "$bytes": STANDARD.encode(&public_snapshot_sha256) },
        "treeSummarySha256": { "$bytes": STANDARD.encode(&tree_summary_sha256) },
        "entryLocator": locator_json,
        "signedRequestBytes": { "$bytes": STANDARD.encode(&signed_req_bytes) },
        "entryBytes": { "$bytes": STANDARD.encode(&entry_bytes) },
    });

    let jwt = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        DELIVER_WELCOME_NSID,
    );

    // 1. Delivering welcome with stale / mismatched recoveryRequestId must fail with client error (400)
    let mut stale_recovery_body = deliver_welcome_body.clone();
    stale_recovery_body["recoveryRequestId"] = json!(Uuid::new_v4().to_string());
    let (status_stale, body_stale, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverWelcome",
            Some(&jwt),
            &stale_recovery_body,
        )
        .await;
    assert!(
        status_stale.is_client_error(),
        "deliverWelcome with stale recoveryRequestId must fail: status={status_stale}, body={body_stale:?}"
    );

    // 2. Delivering welcome with stale / mismatched keyPackageRef must fail with client error (400)
    let mut stale_kp_body = deliver_welcome_body.clone();
    stale_kp_body["keyPackageRef"] = json!({ "$bytes": STANDARD.encode([0xEEu8; 32]) });
    let (status_kp, body_kp, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverWelcome",
            Some(&jwt),
            &stale_kp_body,
        )
        .await;
    assert!(
        status_kp.is_client_error(),
        "deliverWelcome with mismatched keyPackageRef must fail: status={status_kp}, body={body_kp:?}"
    );

    // 3. Concurrently revoking the device before deliverWelcome arrives must fail with client error
    let mut tx_revoke = harness.pool.begin().await.unwrap();
    sqlx::query(
        "UPDATE chat.devices \
         SET status = 'revoked', revoked_at = NOW() \
         WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .execute(&mut *tx_revoke)
    .await
    .unwrap();
    tx_revoke.commit().await.unwrap();

    let (status_revoked, body_revoked, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverWelcome",
            Some(&jwt),
            &deliver_welcome_body,
        )
        .await;
    assert!(
        status_revoked.is_client_error(),
        "deliverWelcome for revoked device must fail: status={status_revoked}, body={body_revoked:?}"
    );
}

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct ReceiptRowSnapshot {
    delivery_id: Uuid,
    endpoint_nsid: String,
    conversation_id: Uuid,
    sender_ds_did: String,
    receiver_ds_did: String,
    sequencer_did: String,
    sequencer_term: i64,
    envelope_sha256: Vec<u8>,
    result_sha256: Vec<u8>,
    source_entry_id: Uuid,
    source_entry_seq: i64,
    source_entry_fingerprint: Vec<u8>,
    response_bytes: Vec<u8>,
    response_sha256: Vec<u8>,
    receipt_signature: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct MailboxStateSnapshot {
    conversations: Vec<(
        Uuid,
        String,
        String,
        i64,
        i64,
        i64,
        bool,
        Option<String>,
        i64,
    )>,
    entries: Vec<(Uuid, i64, Uuid, String, Vec<u8>, Vec<u8>)>,
    generation_states: Vec<(Uuid, i64, i64, i64, Vec<u8>, Vec<u8>, Vec<u8>)>,
    operation_claims: Vec<(Uuid, String, String, String, Vec<u8>, Vec<u8>, Vec<u8>)>,
    idempotency_records: Vec<(String, String, Uuid, i32, Vec<u8>, Vec<u8>)>,
    events: Vec<(i64, Uuid, String, Vec<u8>, Vec<u8>, Uuid)>,
    delivery_receipts: Vec<ReceiptRowSnapshot>,
    outbox: Vec<(String, String, String, Vec<u8>, i32, Option<String>, String)>,
    queue: Vec<(
        String,
        String,
        String,
        String,
        Vec<u8>,
        String,
        String,
        i32,
        Option<String>,
    )>,
}

async fn capture_mailbox_snapshot(pool: &DbPool) -> MailboxStateSnapshot {
    let conversations = sqlx::query_as::<_, (Uuid, String, String, i64, i64, i64, bool, Option<String>, i64)>(
        "SELECT conversation_id, kind, lifecycle, current_generation, current_state_version, next_entry_seq, is_remote, sequencer_ds, sequencer_term FROM chat.conversations ORDER BY conversation_id"
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let entries = sqlx::query_as::<_, (Uuid, i64, Uuid, String, Vec<u8>, Vec<u8>)>(
        "SELECT conversation_id, seq, entry_id, entry_kind, accepted_payload_sha256, outer_entry_fingerprint FROM chat.entries ORDER BY conversation_id, seq"
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let generation_states = sqlx::query_as::<_, (Uuid, i64, i64, i64, Vec<u8>, Vec<u8>, Vec<u8>)>(
        "SELECT conversation_id, generation, state_version, epoch, group_id, group_context_hash, confirmation_tag FROM chat.generation_states ORDER BY conversation_id, generation, state_version"
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let operation_claims = sqlx::query_as::<_, (Uuid, String, String, String, Vec<u8>, Vec<u8>, Vec<u8>)>(
        "SELECT operation_id, principal_did, endpoint_nsid, mutation_kind, request_digest, accepted_request_sha256, signature FROM chat.operation_claims ORDER BY operation_id"
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let idempotency_records = sqlx::query_as::<_, (String, String, Uuid, i32, Vec<u8>, Vec<u8>)>(
        "SELECT principal_did, endpoint_nsid, operation_id, completed_status, response_bytes, response_sha256 FROM chat.idempotency_records ORDER BY principal_did, endpoint_nsid, operation_id"
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let events = sqlx::query_as::<_, (i64, Uuid, String, Vec<u8>, Vec<u8>, Uuid)>(
        "SELECT event_position, event_id, event_kind, payload_bytes, payload_sha256, protocol_instance_id FROM chat.events ORDER BY event_position",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let delivery_receipts = sqlx::query_as::<_, ReceiptRowSnapshot>(
        "SELECT delivery_id, endpoint_nsid, conversation_id, sender_ds_did, receiver_ds_did, sequencer_did, sequencer_term, envelope_sha256, result_sha256, source_entry_id, source_entry_seq, source_entry_fingerprint, response_bytes, response_sha256, receipt_signature FROM chat.federation_delivery_receipts ORDER BY delivery_id"
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let outbox = sqlx::query_as::<_, (String, String, String, Vec<u8>, i32, Option<String>, String)>(
        "SELECT id, conversation_id, status, payload, attempts, last_error, target_service_did FROM federation_outbox ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let queue = sqlx::query_as::<_, (String, String, String, String, Vec<u8>, String, String, i32, Option<String>)>(
        "SELECT id, target_ds_did, target_endpoint, method, payload, convo_id, status, retry_count, last_error FROM outbound_queue ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    MailboxStateSnapshot {
        conversations,
        entries,
        generation_states,
        operation_claims,
        idempotency_records,
        events,
        delivery_receipts,
        outbox,
        queue,
    }
}

fn make_test_receipt_did_doc(
    did: &str,
    key: &p256::ecdsa::VerifyingKey,
) -> catbird_server::auth::DidDocument {
    let mut multikey = vec![0x80, 0x24];
    multikey.extend_from_slice(key.to_encoded_point(true).as_bytes());
    let public_key_multibase = multibase::encode(multibase::Base::Base58Btc, multikey);
    catbird_server::auth::DidDocument {
        id: did.to_string(),
        verification_method: vec![catbird_server::auth::VerificationMethod {
            id: catbird_server::federation::RECEIPT_VERIFICATION_METHOD.to_string(),
            key_type: "Multikey".to_string(),
            controller: did.to_string(),
            public_key_multibase: Some(public_key_multibase),
            public_key_jwk: None,
        }],
        service: None,
    }
}

async fn send_json_to_router(
    router: &Router,
    uri: &str,
    jwt: Option<&str>,
    body: &Value,
) -> (StatusCode, Value, HeaderMap) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = jwt {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let body_bytes = serde_json::to_vec(body).unwrap();
    let request = builder.body(Body::from(body_bytes)).unwrap();
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("collect response body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value, headers)
}

#[tokio::test]
async fn test_remote_commit_rejected_order_leaves_mailbox_state_byte_for_byte_unchanged() {
    use catbird_server::auth::AuthMiddleware;
    use catbird_server::federation::commit_submitter::RemoteCommitSubmitter;
    use catbird_server::federation::outbound::OutboundClient;
    use catbird_server::federation::resolver::{DsResolver, ValidatedRemoteDestination};
    use catbird_server::federation::service_auth::ServiceAuthClient;

    let harness = TestHarness::new("reject").await;
    let now = Utc::now();

    let (
        convo_id,
        creation_transition_id,
        generic_transition_id,
        alice,
        _bob,
        group_id,
        committed_group_context_hash,
        committed_confirmation_tag,
        generic_group_context_hash,
        generic_confirmation_tag,
    ) = seed_corpus_conversation_at_added(
        &harness.pool,
        &harness.sender_ds_did,
        Some(&harness.sequencer_ds_did),
        now,
    )
    .await;

    // Set up mock HTTP sequencer returning 409 Conflict
    let conflict_resp = serde_json::json!({
        "error": "CommitConflict",
        "message": "Commit conflict on conversation: current epoch is 2"
    });
    let conflict_bytes = serde_json::to_vec(&conflict_resp).unwrap();
    let app = axum::Router::new().fallback(axum::routing::post(move |_: axum::body::Bytes| {
        let b = conflict_bytes.clone();
        async move {
            axum::response::Response::builder()
                .status(409)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(b))
                .unwrap()
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let resolver = Arc::new(
        DsResolver::new(
            harness.pool.clone(),
            reqwest::Client::new(),
            harness.sender_ds_did.clone(),
            "https://self.example.com".to_string(),
            None,
            3600,
        )
        .with_destination_resolver_hook(Arc::new(move |_endpoint| {
            let port = local_addr.port();
            Some(Box::pin(async move {
                Ok(ValidatedRemoteDestination {
                    url: url::Url::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
                    host: "127.0.0.1".to_string(),
                    addrs: vec![local_addr],
                })
            }))
        })),
    );

    let pem_str = harness
        .sender_ds_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();
    let service_auth = Arc::new(
        ServiceAuthClient::from_es256_pem(harness.sender_ds_did.clone(), pem_str.as_bytes(), None)
            .unwrap(),
    );
    let outbound = Arc::new(OutboundClient::new(2, 2));
    let auth_mw = AuthMiddleware::new();
    let commit_submitter = Arc::new(RemoteCommitSubmitter::new(
        harness.pool.clone(),
        resolver.clone(),
        outbound,
        service_auth,
        auth_mw,
    ));

    let runtime = Arc::new(
        ChatRuntime::from_env(Arc::new(catbird_server::realtime::SseState::new(8)))
            .expect("build chat runtime")
            .with_resolver(resolver)
            .with_commit_submitter(commit_submitter),
    );

    let test_state = TestDsState {
        pool: harness.pool.clone(),
        ack_signer: Some(harness.ack_signer.clone()),
        runtime,
        blob_store: catbird_server::blob_store::BlobStore::for_route_tests(),
    };
    let custom_router = build_federation_router(test_state);

    let before = capture_mailbox_snapshot(&harness.pool).await;

    let commit_bytes = corpus_file("commit-generic-public.mls");
    let (wrapper, _) = make_corpus_commit_body(
        convo_id,
        generic_transition_id,
        creation_transition_id,
        &alice.did,
        alice.device_id,
        &alice.key_id,
        &alice.public_key,
        &alice.signing_key,
        &group_id,
        &committed_group_context_hash,
        &committed_confirmation_tag,
        &generic_group_context_hash,
        &generic_confirmation_tag,
        &commit_bytes,
        now,
    );

    let client_body = json!({ "signedRequest": wrapper });
    let alice_p256 = random_p256();
    cache_did_key(&alice.did, &alice_p256).await;
    let now_ts = Utc::now().timestamp();
    let jwt = sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":format!("{}#atproto", alice.did)}),
        json!({
            "iss": alice.did,
            "sub": alice.did,
            "aud": AUDIENCE,
            "lxm": "blue.catbird.chat.submitTransition",
            "iat": now_ts,
            "exp": now_ts + 60,
            "jti": Uuid::new_v4().to_string(),
        }),
        &alice_p256,
    );

    let (status, body, _) = send_json_to_router(
        &custom_router,
        "/xrpc/blue.catbird.chat.submitTransition",
        Some(&jwt),
        &client_body,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "remote rejected order must return 400 Bad Request: {body:?}"
    );
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("StaleCoordinates"),
        "error wire code must be StaleCoordinates"
    );

    let after = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(
        after, before,
        "rejected remote commit must leave all mailbox tables byte-for-byte unchanged"
    );
}

#[tokio::test]
async fn test_remote_commit_rejected_403_returns_not_authorized_and_leaves_mailbox_state_unchanged()
{
    use catbird_server::auth::AuthMiddleware;
    use catbird_server::federation::commit_submitter::RemoteCommitSubmitter;
    use catbird_server::federation::outbound::OutboundClient;
    use catbird_server::federation::resolver::{DsResolver, ValidatedRemoteDestination};
    use catbird_server::federation::service_auth::ServiceAuthClient;

    let harness = TestHarness::new("reject403").await;
    let now = Utc::now();

    let (
        convo_id,
        creation_transition_id,
        generic_transition_id,
        alice,
        _bob,
        group_id,
        committed_group_context_hash,
        committed_confirmation_tag,
        generic_group_context_hash,
        generic_confirmation_tag,
    ) = seed_corpus_conversation_at_added(
        &harness.pool,
        &harness.sender_ds_did,
        Some(&harness.sequencer_ds_did),
        now,
    )
    .await;

    // Set up mock HTTP sequencer returning 403 Forbidden
    let forbidden_resp = serde_json::json!({
        "error": "UnauthorizedParticipantDs",
        "message": "Participant DS is not authorized for this conversation"
    });
    let forbidden_bytes = serde_json::to_vec(&forbidden_resp).unwrap();
    let app = axum::Router::new().fallback(axum::routing::post(move |_: axum::body::Bytes| {
        let b = forbidden_bytes.clone();
        async move {
            axum::response::Response::builder()
                .status(403)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(b))
                .unwrap()
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let resolver = Arc::new(
        DsResolver::new(
            harness.pool.clone(),
            reqwest::Client::new(),
            harness.sender_ds_did.clone(),
            "https://self.example.com".to_string(),
            None,
            3600,
        )
        .with_destination_resolver_hook(Arc::new(move |_endpoint| {
            let port = local_addr.port();
            Some(Box::pin(async move {
                Ok(ValidatedRemoteDestination {
                    url: url::Url::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
                    host: "127.0.0.1".to_string(),
                    addrs: vec![local_addr],
                })
            }))
        })),
    );

    let pem_str = harness
        .sender_ds_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();
    let service_auth = Arc::new(
        ServiceAuthClient::from_es256_pem(harness.sender_ds_did.clone(), pem_str.as_bytes(), None)
            .unwrap(),
    );
    let outbound = Arc::new(OutboundClient::new(2, 2));
    let auth_mw = AuthMiddleware::new();
    let commit_submitter = Arc::new(RemoteCommitSubmitter::new(
        harness.pool.clone(),
        resolver.clone(),
        outbound,
        service_auth,
        auth_mw,
    ));

    let runtime = Arc::new(
        ChatRuntime::from_env(Arc::new(catbird_server::realtime::SseState::new(8)))
            .expect("build chat runtime")
            .with_resolver(resolver)
            .with_commit_submitter(commit_submitter),
    );

    let test_state = TestDsState {
        pool: harness.pool.clone(),
        ack_signer: Some(harness.ack_signer.clone()),
        runtime,
        blob_store: catbird_server::blob_store::BlobStore::for_route_tests(),
    };
    let custom_router = build_federation_router(test_state);

    let before = capture_mailbox_snapshot(&harness.pool).await;

    let commit_bytes = corpus_file("commit-generic-public.mls");
    let (wrapper, _) = make_corpus_commit_body(
        convo_id,
        generic_transition_id,
        creation_transition_id,
        &alice.did,
        alice.device_id,
        &alice.key_id,
        &alice.public_key,
        &alice.signing_key,
        &group_id,
        &committed_group_context_hash,
        &committed_confirmation_tag,
        &generic_group_context_hash,
        &generic_confirmation_tag,
        &commit_bytes,
        now,
    );

    let client_body = json!({ "signedRequest": wrapper });
    let alice_p256 = random_p256();
    cache_did_key(&alice.did, &alice_p256).await;
    let now_ts = Utc::now().timestamp();
    let jwt = sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":format!("{}#atproto", alice.did)}),
        json!({
            "iss": alice.did,
            "sub": alice.did,
            "aud": AUDIENCE,
            "lxm": "blue.catbird.chat.submitTransition",
            "iat": now_ts,
            "exp": now_ts + 60,
            "jti": Uuid::new_v4().to_string(),
        }),
        &alice_p256,
    );

    let (status, body, _) = send_json_to_router(
        &custom_router,
        "/xrpc/blue.catbird.chat.submitTransition",
        Some(&jwt),
        &client_body,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "remote 403 nonparticipant rejection must return 401 NotAuthorized: {body:?}"
    );
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("NotAuthorized"),
        "error wire code must be NotAuthorized"
    );

    let after = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(
        after, before,
        "rejected 403 remote commit must leave all mailbox tables byte-for-byte unchanged"
    );
}

#[tokio::test]
async fn test_remote_commit_dropped_first_response_replay_applies_exactly_once() {
    use catbird_server::auth::AuthMiddleware;
    use catbird_server::federation::commit_submitter::RemoteCommitSubmitter;
    use catbird_server::federation::outbound::OutboundClient;
    use catbird_server::federation::resolver::{DsResolver, ValidatedRemoteDestination};
    use catbird_server::federation::service_auth::ServiceAuthClient;
    use parking_lot::Mutex;

    let harness = TestHarness::new("replay").await;
    let now = Utc::now();

    let (
        convo_id,
        creation_transition_id,
        generic_transition_id,
        alice,
        _bob,
        group_id,
        committed_group_context_hash,
        committed_confirmation_tag,
        generic_group_context_hash,
        generic_confirmation_tag,
    ) = seed_corpus_conversation_at_added(&harness.pool, LOCAL_DS_DID, Some(LOCAL_DS_DID), now)
        .await;

    let commit_bytes = corpus_file("commit-generic-public.mls");
    let (wrapper, _signed_req_bytes) = make_corpus_commit_body(
        convo_id,
        generic_transition_id,
        creation_transition_id,
        &alice.did,
        alice.device_id,
        &alice.key_id,
        &alice.public_key,
        &alice.signing_key,
        &group_id,
        &committed_group_context_hash,
        &committed_confirmation_tag,
        &generic_group_context_hash,
        &generic_confirmation_tag,
        &commit_bytes,
        now,
    );

    use p256::pkcs8::EncodePrivateKey;
    let local_ds_key = random_p256();
    let pem_str = local_ds_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();

    // Setup real sequencer node on its own database
    let (seq_pool, _seq_guard) = fresh_legacy_pool(FED_ROUTER_DB_PREFIX, 8, 1).await;
    seed_corpus_conversation_at_added(&seq_pool, LOCAL_DS_DID, None, now).await;
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
    .execute(&seq_pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, updated_at) \
         VALUES ($1, 'allow', NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET status = 'allow', updated_at = NOW()",
    )
    .bind(LOCAL_DS_DID)
    .execute(&seq_pool)
    .await
    .unwrap();

    let inst_id = Uuid::new_v4();
    let key = sqlx::query_scalar::<_, String>("SELECT chat.ed25519_key_id($1)")
        .bind(vec![0x51_u8; 32])
        .fetch_one(&seq_pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING")
        .bind(inst_id)
        .bind(&key)
        .execute(&seq_pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO chat.event_retention(protocol_instance_id,retained_floor,updated_at) VALUES($1,0,clock_timestamp()) ON CONFLICT DO NOTHING")
        .bind(inst_id)
        .execute(&seq_pool)
        .await
        .unwrap();

    let seq_ack_signer = Arc::new(AckSigner::new(
        local_ds_key.clone(),
        LOCAL_DS_DID.to_string(),
    ));
    let seq_runtime = Arc::new(
        ChatRuntime::from_env(Arc::new(catbird_server::realtime::SseState::new(8)))
            .expect("build sequencer chat runtime"),
    );
    let call_counts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let received_delivery_ids: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let counts_clone = call_counts.clone();
    let ids_clone = received_delivery_ids.clone();
    let pool_clone = seq_pool.clone();
    let signer_clone = seq_ack_signer.clone();
    let runtime_clone = seq_runtime.clone();

    let app = axum::Router::new().route(
        "/xrpc/blue.catbird.mlsDS.submitCommit",
        axum::routing::post(
            move |_headers: HeaderMap, body: axum::body::Bytes| {
                let counts = counts_clone.clone();
                let ids = ids_clone.clone();
                let pool = pool_clone.clone();
                let signer = signer_clone.clone();
                let runtime = runtime_clone.clone();
                async move {
                    let count = counts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;

                    use catbird_atproto::generated::blue_catbird::mlsDS::submit_commit::SubmitCommit;
                    use catbird_server::chat_protocol::test_support::repository::submit_commit_sequencing;
                    use catbird_server::federation::envelope::validate_envelope_header;
                    use jacquard_common::DefaultStr;

                    let msg: SubmitCommit<DefaultStr> =
                        serde_json::from_slice(&body).unwrap();
                    let header = validate_envelope_header(&msg.header).unwrap();

                    {
                        let mut guard = ids.lock();
                        guard.push(header.delivery_id.to_string());
                    }

                    let mut tx = pool.begin().await.unwrap();
                    let output = submit_commit_sequencing(
                        &mut tx,
                        signer.as_ref(),
                        header,
                        msg.signed_request_bytes.to_vec(),
                        runtime.relationship_authority_for_test().as_ref(),
                    )
                    .await
                    .unwrap();
                    tx.commit().await.unwrap();

                    let resp_bytes = serde_json::to_vec(&output).unwrap();

                    if count == 1 {
                        // Sequencer ordered and committed the transition in its database,
                        // but the network dropped the response to the mailbox DS!
                        axum::response::Response::builder()
                            .status(503)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(
                                b"{\"error\":\"RelationshipPolicyUnavailable\"}".to_vec(),
                            ))
                            .unwrap()
                    } else {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(resp_bytes))
                            .unwrap()
                    }
                }
            },
        ),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let resolver = Arc::new(
        DsResolver::new(
            harness.pool.clone(),
            reqwest::Client::new(),
            LOCAL_DS_DID.to_string(),
            "https://self.example.com".to_string(),
            None,
            3600,
        )
        .with_destination_resolver_hook(Arc::new(move |_endpoint| {
            let port = local_addr.port();
            Some(Box::pin(async move {
                Ok(ValidatedRemoteDestination {
                    url: url::Url::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
                    host: "127.0.0.1".to_string(),
                    addrs: vec![local_addr],
                })
            }))
        })),
    );

    let service_auth = Arc::new(
        ServiceAuthClient::from_es256_pem(LOCAL_DS_DID.to_string(), pem_str.as_bytes(), None)
            .unwrap(),
    );
    let outbound = Arc::new(OutboundClient::new(2, 2));
    let auth_mw = AuthMiddleware::new();
    let seq_did_doc = make_test_receipt_did_doc(LOCAL_DS_DID, &local_ds_key.verifying_key());
    auth_mw.cache_did_document(seq_did_doc).await;

    let commit_submitter = Arc::new(RemoteCommitSubmitter::new(
        harness.pool.clone(),
        resolver.clone(),
        outbound,
        service_auth,
        auth_mw,
    ));

    let runtime = Arc::new(
        ChatRuntime::from_env(Arc::new(catbird_server::realtime::SseState::new(8)))
            .expect("build chat runtime")
            .with_resolver(resolver)
            .with_commit_submitter(commit_submitter),
    );

    let test_state = TestDsState {
        pool: harness.pool.clone(),
        ack_signer: Some(harness.ack_signer.clone()),
        runtime,
        blob_store: catbird_server::blob_store::BlobStore::for_route_tests(),
    };
    let custom_router = build_federation_router(test_state);

    let before = capture_mailbox_snapshot(&harness.pool).await;

    let client_body = json!({ "signedRequest": wrapper });
    let alice_p256 = random_p256();
    cache_did_key(&alice.did, &alice_p256).await;
    let now_ts = Utc::now().timestamp();
    let jwt1 = sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":format!("{}#atproto", alice.did)}),
        json!({
            "iss": alice.did,
            "sub": alice.did,
            "aud": AUDIENCE,
            "lxm": "blue.catbird.chat.submitTransition",
            "iat": now_ts,
            "exp": now_ts + 60,
            "jti": Uuid::new_v4().to_string(),
        }),
        &alice_p256,
    );
    let (status1, body1, _) = send_json_to_router(
        &custom_router,
        "/xrpc/blue.catbird.chat.submitTransition",
        Some(&jwt1),
        &client_body,
    )
    .await;
    assert_eq!(
        status1,
        StatusCode::SERVICE_UNAVAILABLE,
        "Call 1 must fail due to dropped response: status={status1}, body={body1:?}"
    );
    // Mailbox state must be completely unchanged after Call 1 rollback
    let middle = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(
        middle, before,
        "Mailbox state must be completely unchanged after dropped response rollback"
    );

    // Call 2: Client retries with fresh service auth token but identical signedRequest
    let jwt2 = sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":format!("{}#atproto", alice.did)}),
        json!({
            "iss": alice.did,
            "sub": alice.did,
            "aud": AUDIENCE,
            "lxm": "blue.catbird.chat.submitTransition",
            "iat": now_ts + 1,
            "exp": now_ts + 61,
            "jti": Uuid::new_v4().to_string(),
        }),
        &alice_p256,
    );

    let (status2, body2, _) = send_json_to_router(
        &custom_router,
        "/xrpc/blue.catbird.chat.submitTransition",
        Some(&jwt2),
        &client_body,
    )
    .await;
    assert_eq!(
        status2,
        StatusCode::OK,
        "Call 2 retry must succeed: body={body2:?}"
    );

    let after = capture_mailbox_snapshot(&harness.pool).await;
    assert_ne!(after, before, "Mailbox state must be applied after Call 2");
    // State version must advance to 4
    let (state_version, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version, next_entry_seq FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert_eq!(state_version, 4, "stateVersion must advance to 4");
    assert_eq!(next_seq, 6, "next_entry_seq must advance to 6");

    // Assert exact same delivery ID was received twice at sequencer
    {
        let ids = received_delivery_ids.lock();
        assert_eq!(ids.len(), 2, "sequencer must receive exactly 2 requests");
        assert_eq!(
            ids[0], ids[1],
            "both attempts must use identical canonical delivery ID"
        );
    }
    assert_eq!(
        call_counts.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "sequencer must receive exactly 2 remote calls"
    );

    let delivery_id =
        catbird_server::chat_protocol::test_support::repository::derive_submit_commit_delivery_id(
            convo_id,
            generic_transition_id,
            LOCAL_DS_DID,
        );
    let receipt_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.federation_delivery_receipts WHERE delivery_id = $1",
    )
    .bind(delivery_id)
    .fetch_one(&seq_pool)
    .await
    .unwrap();
    assert_eq!(
        receipt_count, 1,
        "exactly 1 delivery receipt stored on sequencer"
    );

    // Assert zero asynchronous submitCommit jobs in outbox or queue on mailbox DS
    let outbox_cnt: i64 = sqlx::query_scalar("SELECT count(*) FROM federation_outbox")
        .fetch_one(&harness.pool)
        .await
        .unwrap();
    assert_eq!(outbox_cnt, 0, "must be 0 outbox jobs on mailbox DS");
    let queue_cnt: i64 = sqlx::query_scalar("SELECT count(*) FROM outbound_queue")
        .fetch_one(&harness.pool)
        .await
        .unwrap();
    assert_eq!(queue_cnt, 0, "must be 0 queue jobs on mailbox DS");

    // Call 3: Idempotent replay of completed operation
    let jwt3 = sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":format!("{}#atproto", alice.did)}),
        json!({
            "iss": alice.did,
            "sub": alice.did,
            "aud": AUDIENCE,
            "lxm": "blue.catbird.chat.submitTransition",
            "iat": now_ts + 2,
            "exp": now_ts + 62,
            "jti": Uuid::new_v4().to_string(),
        }),
        &alice_p256,
    );

    let (status3, body3, _) = send_json_to_router(
        &custom_router,
        "/xrpc/blue.catbird.chat.submitTransition",
        Some(&jwt3),
        &client_body,
    )
    .await;
    assert_eq!(
        status3,
        StatusCode::OK,
        "Call 3 replay must succeed: body={body3:?}"
    );
    assert_eq!(body3, body2, "Call 3 replay body must equal Call 2");

    let final_snap = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(final_snap, after, "Call 3 must not mutate state further");
}
