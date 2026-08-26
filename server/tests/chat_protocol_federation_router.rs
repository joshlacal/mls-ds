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
use catbird_server::federation::outbound::OutboundClient;
use catbird_server::federation::resolver::{DsResolver, ValidatedRemoteDestination};
use catbird_server::federation::FederationMode;
use catbird_server::handlers::chat::ChatRuntime;
use catbird_server::handlers::ds::get_convo_digest::{
    compute_clean_convo_digest, CleanDigestRow, GetConvoDigestOutput,
};
use catbird_server::storage::DbPool;
use chrono::{DateTime, SecondsFormat, Utc};
use common::fresh_db::{fresh_legacy_pool, DisposableDatabase};
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row as _;
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
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest",
            axum::routing::get(catbird_server::handlers::ds::get_convo_digest),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoEvents",
            axum::routing::get(catbird_server::handlers::ds::get_convo_events),
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
        let short_id = &Uuid::new_v4().simple().to_string()[..8];
        let clean_suffix = &sender_suffix[..sender_suffix.len().min(8)];
        let sender_ds_did = format!("did:web:r-{clean_suffix}-{short_id}.catbird.blue");
        let ack_key = random_p256();
        let ack_signer = Arc::new(AckSigner::new(ack_key, LOCAL_DS_DID.to_string()));
        let sender_ds_key = random_p256();
        cache_did_key(&sender_ds_did, &sender_ds_key).await;

        // The remote sequencer DS is the authenticated sender for deliverMessage / deliverWelcome
        // mailboxes. It must be unique per harness: the process-global DID document cache is
        // shared across tests, and parallel tests would overwrite one another's key if they all
        // used the constant REMOTE_SEQUENCER_DID.
        let sequencer_ds_did = format!("did:web:s-{clean_suffix}-{short_id}.catbird.blue");
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
    received_at: &str,
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
        "receivedAt": received_at,
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
fn make_message_body_with_coordinates(
    convo_id: Uuid,
    message_id: Uuid,
    actor: &TestActor,
    group_id: &[u8],
    state_version: i64,
    epoch: i64,
    group_context_hash: &[u8; 32],
    confirmation_tag: &[u8; 32],
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
            "stateVersion": state_version,
            "groupId": STANDARD.encode(group_id),
            "epoch": epoch,
            "groupContextHash": STANDARD.encode(group_context_hash),
            "confirmationTag": STANDARD.encode(confirmation_tag),
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
                "stateVersion": state_version,
                "groupId": STANDARD.encode(group_id),
                "epoch": epoch,
                "groupContextHash": STANDARD.encode(group_context_hash),
                "confirmationTag": STANDARD.encode(confirmation_tag),
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
    let sig: ed25519_dalek::Signature = actor.signing_key.sign(mutation.transcript_bytes());
    wrapper["signature"] = Value::String(STANDARD.encode(sig.to_bytes()));
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

fn make_typing_body(
    convo_id: Uuid,
    typing_id: Uuid,
    actor: &TestActor,
    group_id: &[u8],
    state_version: i64,
    epoch: i64,
    group_context_hash: &[u8; 32],
    confirmation_tag: &[u8; 32],
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#typingBody",
        "signatureDomain": "CATBIRD-CHAT-TYPING\u{0}",
        "typingId": typing_id.to_string(),
        "actorDid": actor.did,
        "actorDeviceId": actor.device_id.to_string(),
        "keyId": actor.key_id,
        "authGeneration": 1,
        "coordinates": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": state_version,
            "groupId": STANDARD.encode(group_id),
            "epoch": epoch,
            "groupContextHash": STANDARD.encode(group_context_hash),
            "confirmationTag": STANDARD.encode(confirmation_tag),
            "lifecycle": "active"
        },
        "isTyping": true,
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
    });

    let mut wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode([0u8; 64]),
    });
    let unsigned_bytes = serde_json::to_vec(&wrapper).unwrap();
    let mutation = decode_canonical_signed_mutation(&unsigned_bytes).unwrap();
    let sig: ed25519_dalek::Signature = actor.signing_key.sign(mutation.transcript_bytes());
    wrapper["signature"] = json!(STANDARD.encode(sig.to_bytes()));
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

fn make_leave_request_body(
    convo_id: Uuid,
    leave_req_id: Uuid,
    actor: &TestActor,
    group_id: &[u8],
    state_version: i64,
    epoch: i64,
    group_context_hash: &[u8; 32],
    confirmation_tag: &[u8; 32],
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#leaveRequestBody",
        "signatureDomain": "CATBIRD-CHAT-LEAVE-REQUEST\u{0}",
        "leaveRequestId": leave_req_id.to_string(),
        "actorDid": actor.did,
        "actorDeviceId": actor.device_id.to_string(),
        "keyId": actor.key_id,
        "authGeneration": 1,
        "prior": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": state_version,
            "groupId": STANDARD.encode(group_id),
            "epoch": epoch,
            "groupContextHash": STANDARD.encode(group_context_hash),
            "confirmationTag": STANDARD.encode(confirmation_tag),
            "lifecycle": "active"
        },
        "idempotencyKey": leave_req_id.to_string(),
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
    });

    let mut wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode([0u8; 64]),
    });
    let unsigned_bytes = serde_json::to_vec(&wrapper).unwrap();
    let mutation = decode_canonical_signed_mutation(&unsigned_bytes).unwrap();
    let sig: ed25519_dalek::Signature = actor.signing_key.sign(mutation.transcript_bytes());
    wrapper["signature"] = json!(STANDARD.encode(sig.to_bytes()));
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

fn make_device_revocation_body(
    actor: &TestActor,
    target_device_id: Uuid,
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let idemp = Uuid::new_v4();
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#deviceRevocationBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REVOKE\u{0}",
        "actorDid": actor.did,
        "actorDeviceId": actor.device_id.to_string(),
        "keyId": actor.key_id,
        "authGeneration": 1,
        "targetDeviceId": target_device_id.to_string(),
        "targetAuthGeneration": 1,
        "idempotencyKey": idemp.to_string(),
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
    });

    let mut wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode([0u8; 64]),
    });
    let unsigned_bytes = serde_json::to_vec(&wrapper).unwrap();
    let mutation = decode_canonical_signed_mutation(&unsigned_bytes).unwrap();
    let sig: ed25519_dalek::Signature = actor.signing_key.sign(mutation.transcript_bytes());
    wrapper["signature"] = json!(STANDARD.encode(sig.to_bytes()));
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

fn make_welcome_acknowledgement_body(
    convo_id: Uuid,
    welcome_id: Uuid,
    transition_seq: i64,
    actor: &TestActor,
    group_id: &[u8],
    state_version: i64,
    epoch: i64,
    group_context_hash: &[u8; 32],
    confirmation_tag: &[u8; 32],
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let idemp = Uuid::new_v4();
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#welcomeAcknowledgementBody",
        "signatureDomain": "CATBIRD-CHAT-WELCOME-ACK\u{0}",
        "welcomeId": welcome_id.to_string(),
        "transitionSeq": transition_seq,
        "actorDid": actor.did,
        "actorDeviceId": actor.device_id.to_string(),
        "keyId": actor.key_id,
        "authGeneration": 1,
        "coordinates": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": state_version,
            "groupId": STANDARD.encode(group_id),
            "epoch": epoch,
            "groupContextHash": STANDARD.encode(group_context_hash),
            "confirmationTag": STANDARD.encode(confirmation_tag),
            "lifecycle": "active"
        },
        "idempotencyKey": idemp.to_string(),
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
    });

    let mut wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode([0u8; 64]),
    });
    let unsigned_bytes = serde_json::to_vec(&wrapper).unwrap();
    let mutation = decode_canonical_signed_mutation(&unsigned_bytes).unwrap();
    let sig: ed25519_dalek::Signature = actor.signing_key.sign(mutation.transcript_bytes());
    wrapper["signature"] = json!(STANDARD.encode(sig.to_bytes()));
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

async fn assert_applied_suffix_entry_and_message_send_exact_fields(
    pool: &DbPool,
    convo_id: Uuid,
    expected_seq: i64,
    expected_entry_id: Uuid,
    expected_message_id: Uuid,
    expected_actor: &TestActor,
    expected_entry_bytes: &[u8],
    expected_entry_sha256: &[u8],
    expected_signed_req_bytes: &[u8],
    expected_outer_fp: &[u8],
    expected_transcript_bytes: &[u8],
    expected_request_digest: &[u8],
    expected_signature: &[u8],
    expected_received_at: DateTime<Utc>,
) {
    let row = sqlx::query(
        r#"
        SELECT CAST(seq AS BIGINT) AS seq, CAST(COALESCE(generation, 0) AS BIGINT) AS epoch,
               entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256,
               signed_request_bytes, request_digest, signature, outer_entry_fingerprint,
               actor_did, actor_device_id, actor_key_id, actor_auth_generation,
               generation, message_id, received_at
        FROM chat.entries
        WHERE conversation_id = $1 AND seq = $2
        "#,
    )
    .bind(convo_id)
    .bind(expected_seq)
    .fetch_one(pool)
    .await
    .unwrap();

    let seq: i64 = row.get("seq");
    let epoch: i64 = row.get("epoch");
    let entry_id: Uuid = row.get("entry_id");
    let entry_kind: String = row.get("entry_kind");
    let accepted_payload_bytes: Vec<u8> = row.get("accepted_payload_bytes");
    let accepted_payload_sha256: Vec<u8> = row.get("accepted_payload_sha256");
    let signed_request_bytes: Vec<u8> = row.get("signed_request_bytes");
    let request_digest: Vec<u8> = row.get("request_digest");
    let signature: Vec<u8> = row.get("signature");
    let outer_entry_fingerprint: Vec<u8> = row.get("outer_entry_fingerprint");
    let actor_did: String = row.get("actor_did");
    let actor_device_id: Uuid = row.get("actor_device_id");
    let actor_key_id: String = row.get("actor_key_id");
    let actor_auth_generation: i64 = row.get("actor_auth_generation");
    let generation: i64 = row.get("generation");
    let message_id: Uuid = row.get("message_id");
    let received_at: DateTime<Utc> = row.get("received_at");
    assert_eq!(
        received_at.timestamp_millis(),
        expected_received_at.timestamp_millis(),
        "received_at timestamp mismatch at seq {expected_seq}"
    );
    assert_eq!(seq, expected_seq, "seq mismatch at seq {expected_seq}");
    assert_eq!(epoch, 0, "epoch mismatch at seq {expected_seq}");
    assert_eq!(
        entry_id, expected_entry_id,
        "entry_id mismatch at seq {expected_seq}"
    );
    assert_eq!(
        entry_kind, "blue.catbird.chat.defs#applicationEntry",
        "entry_kind mismatch at seq {expected_seq}"
    );
    assert_eq!(
        accepted_payload_bytes.as_slice(),
        expected_entry_bytes,
        "accepted_payload_bytes mismatch at seq {expected_seq}"
    );
    assert_eq!(
        accepted_payload_sha256.as_slice(),
        expected_entry_sha256,
        "accepted_payload_sha256 mismatch at seq {expected_seq}"
    );
    assert_eq!(
        signed_request_bytes.as_slice(),
        expected_signed_req_bytes,
        "signed_request_bytes mismatch at seq {expected_seq}"
    );
    assert_eq!(
        request_digest.as_slice(),
        expected_request_digest,
        "request_digest mismatch at seq {expected_seq}"
    );
    assert_eq!(
        signature.as_slice(),
        expected_signature,
        "signature mismatch at seq {expected_seq}"
    );
    assert_eq!(
        outer_entry_fingerprint.as_slice(),
        expected_outer_fp,
        "outer_entry_fingerprint mismatch at seq {expected_seq}"
    );
    assert_eq!(
        actor_did, expected_actor.did,
        "actor_did mismatch at seq {expected_seq}"
    );
    assert_eq!(
        actor_device_id, expected_actor.device_id,
        "actor_device_id mismatch at seq {expected_seq}"
    );
    assert_eq!(
        actor_key_id, expected_actor.key_id,
        "actor_key_id mismatch at seq {expected_seq}"
    );
    assert_eq!(
        actor_auth_generation, 1,
        "actor_auth_generation mismatch at seq {expected_seq}"
    );
    assert_eq!(generation, 0, "generation mismatch at seq {expected_seq}");
    assert_eq!(
        message_id, expected_message_id,
        "message_id mismatch at seq {expected_seq}"
    );

    let expected_outcome_bytes = serde_json::to_vec(&serde_json::json!({
        "entry": {
            "entryId": expected_entry_id.to_string(),
            "conversationId": convo_id.to_string(),
            "seq": expected_seq,
            "signedRequest": serde_json::from_slice::<serde_json::Value>(expected_signed_req_bytes).unwrap_or(serde_json::Value::Null),
            "receivedAt": expected_received_at.to_rfc3339_opts(SecondsFormat::Millis, true)
        }
    }))
    .unwrap();

    let expected_outcome_sha256 = Sha256::digest(&expected_outcome_bytes).to_vec();

    let send: (
        Uuid,
        Uuid,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        String,
        i64,
        Vec<u8>,
        Vec<u8>,
    ) = sqlx::query_as(
        r#"
        SELECT conversation_id, message_id, signed_request_bytes,
               signing_transcript_bytes, request_digest, signature,
               status, accepted_entry_seq, outcome_bytes, outcome_sha256
        FROM chat.message_sends
        WHERE conversation_id = $1 AND message_id = $2
        "#,
    )
    .bind(convo_id)
    .bind(expected_message_id)
    .fetch_one(pool)
    .await
    .unwrap();

    assert_eq!(
        send.0, convo_id,
        "message_sends conversation_id mismatch at seq {expected_seq}"
    );
    assert_eq!(
        send.1, expected_message_id,
        "message_sends message_id mismatch at seq {expected_seq}"
    );
    assert_eq!(
        send.2, expected_signed_req_bytes,
        "message_sends signed_request_bytes mismatch at seq {expected_seq}"
    );
    assert_eq!(
        send.3.as_slice(),
        expected_transcript_bytes,
        "message_sends signing_transcript_bytes mismatch at seq {expected_seq}"
    );
    assert_eq!(
        send.4.as_slice(),
        expected_request_digest,
        "message_sends request_digest mismatch at seq {expected_seq}"
    );
    assert_eq!(
        send.5.as_slice(),
        expected_signature,
        "message_sends signature mismatch at seq {expected_seq}"
    );
    assert_eq!(
        send.6, "accepted",
        "message_sends status mismatch at seq {expected_seq}"
    );
    assert_eq!(
        send.7, expected_seq,
        "message_sends accepted_entry_seq mismatch at seq {expected_seq}"
    );
    assert_eq!(
        send.8, expected_outcome_bytes,
        "message_sends outcome_bytes mismatch at seq {expected_seq}"
    );
    assert_eq!(
        send.9.as_slice(),
        expected_outcome_sha256.as_slice(),
        "message_sends outcome_sha256 mismatch at seq {expected_seq}"
    );
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
        received_at: catbird_server::chat_protocol::test_support::CanonicalTimestamp::parse(
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
        )
        .unwrap(),
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
        &now.to_rfc3339_opts(SecondsFormat::Millis, true),
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
        received_at: catbird_server::chat_protocol::test_support::CanonicalTimestamp::parse(
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
        )
        .unwrap(),
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
        &now.to_rfc3339_opts(SecondsFormat::Millis, true),
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
        received_at: catbird_server::chat_protocol::test_support::CanonicalTimestamp::parse(
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
        )
        .unwrap(),
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
        &now.to_rfc3339_opts(SecondsFormat::Millis, true),
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
        received_at: catbird_server::chat_protocol::test_support::CanonicalTimestamp::parse(
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
        )
        .unwrap(),
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
        &now.to_rfc3339_opts(SecondsFormat::Millis, true),
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
        received_at: catbird_server::chat_protocol::test_support::CanonicalTimestamp::parse(
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
        )
        .unwrap(),
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
        &now.to_rfc3339_opts(SecondsFormat::Millis, true),
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
        received_at: catbird_server::chat_protocol::test_support::CanonicalTimestamp::parse(
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
        )
        .unwrap(),
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
        &now.to_rfc3339_opts(SecondsFormat::Millis, true),
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
        received_at: catbird_server::chat_protocol::test_support::CanonicalTimestamp::parse(
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
        )
        .unwrap(),
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
        &now.to_rfc3339_opts(SecondsFormat::Millis, true),
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
            received_at: catbird_server::chat_protocol::test_support::CanonicalTimestamp::parse(
                &now.to_rfc3339_opts(SecondsFormat::Millis, true),
            )
            .unwrap(),
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
        &now.to_rfc3339_opts(SecondsFormat::Millis, true),
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

#[derive(Debug, PartialEq, Eq)]
struct MailboxStateSnapshot {
    conversations: Vec<String>,
    generations: Vec<String>,
    participants: Vec<String>,
    entries: Vec<String>,
    transitions: Vec<String>,
    generation_states: Vec<String>,
    metadata_snapshots: Vec<String>,
    entry_recipients: Vec<String>,
    events: Vec<String>,
    event_recipients: Vec<String>,
    member_devices: Vec<String>,
    application_intervals: Vec<String>,
    operation_claims: Vec<String>,
    idempotency_records: Vec<String>,
    delivery_receipts: Vec<String>,
    recovery_work_items: Vec<String>,
    welcome_bundles: Vec<String>,
    welcome_deliveries: Vec<String>,
    welcome_dispositions: Vec<String>,
    reset_requests: Vec<String>,
    leave_requests: Vec<String>,
    leaf_recovery_requests: Vec<String>,
    chat_outbox: Vec<String>,
    outbox: Vec<String>,
    queue: Vec<String>,
    message_sends: Vec<String>,
}

async fn capture_mailbox_snapshot(pool: &DbPool) -> MailboxStateSnapshot {
    let conversations = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.conversations ORDER BY conversation_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let generations = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.generations ORDER BY conversation_id, generation) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let participants = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.participants ORDER BY participant_period_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let entries = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.entries ORDER BY conversation_id, seq) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let transitions = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.transitions ORDER BY transition_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let generation_states = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.generation_states ORDER BY conversation_id, generation, state_version) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let metadata_snapshots = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.metadata_snapshots ORDER BY metadata_snapshot_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let entry_recipients = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.entry_recipients ORDER BY conversation_id, seq, user_did, device_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let events = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.events ORDER BY event_position) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let event_recipients = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.event_recipients ORDER BY event_position, user_did, device_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let member_devices = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.member_devices ORDER BY leaf_period_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let application_intervals = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.application_intervals ORDER BY membership_interval_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let operation_claims = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.operation_claims ORDER BY operation_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let idempotency_records = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.idempotency_records ORDER BY principal_did, endpoint_nsid, operation_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let delivery_receipts = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.federation_delivery_receipts ORDER BY delivery_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let recovery_work_items = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.recovery_work_items ORDER BY recovery_work_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let welcome_bundles = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.welcome_bundles ORDER BY welcome_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let welcome_deliveries = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.welcome_deliveries ORDER BY welcome_id, recipient_did, recipient_device_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let welcome_dispositions = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.welcome_dispositions ORDER BY welcome_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let reset_requests = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.reset_requests ORDER BY reset_request_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let leave_requests = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.leave_requests ORDER BY leave_request_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let leaf_recovery_requests = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.leaf_recovery_requests ORDER BY recovery_request_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let chat_outbox = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.outbox ORDER BY event_position) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let outbox = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM federation_outbox ORDER BY id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let queue = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM outbound_queue ORDER BY id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let message_sends = sqlx::query_scalar::<_, String>(
        "SELECT to_jsonb(t)::text FROM (SELECT * FROM chat.message_sends ORDER BY conversation_id, message_id) t",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    MailboxStateSnapshot {
        conversations,
        generations,
        participants,
        entries,
        transitions,
        generation_states,
        metadata_snapshots,
        entry_recipients,
        events,
        event_recipients,
        member_devices,
        application_intervals,
        operation_claims,
        idempotency_records,
        delivery_receipts,
        recovery_work_items,
        welcome_bundles,
        welcome_deliveries,
        welcome_dispositions,
        reset_requests,
        leave_requests,
        leaf_recovery_requests,
        chat_outbox,
        outbox,
        queue,
        message_sends,
    }
}

fn make_test_receipt_did_doc(
    did: &str,
    key: &p256::ecdsa::VerifyingKey,
) -> catbird_server::auth::DidDocument {
    let mut multikey = vec![0x80, 0x24];
    multikey.extend_from_slice(key.to_encoded_point(true).as_bytes());
    let public_key_multibase = multibase::encode(multibase::Base::Base58Btc, multikey);
    let point = key.to_encoded_point(false);
    let jwk_val = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    });
    let jwk: PublicKeyJwk = serde_json::from_value(jwk_val).unwrap();
    catbird_server::auth::DidDocument {
        id: did.to_string(),
        verification_method: vec![
            catbird_server::auth::VerificationMethod {
                id: catbird_server::federation::RECEIPT_VERIFICATION_METHOD.to_string(),
                key_type: "Multikey".to_string(),
                controller: did.to_string(),
                public_key_multibase: Some(public_key_multibase),
                public_key_jwk: None,
            },
            catbird_server::auth::VerificationMethod {
                id: format!("{did}#atproto"),
                key_type: "JsonWebKey2020".to_string(),
                controller: did.to_string(),
                public_key_jwk: Some(jwk),
                public_key_multibase: None,
            },
        ],
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

/// Like [`send_json_to_router`] but returns the raw response body bytes.
async fn send_json_to_router_raw(
    router: &Router,
    uri: &str,
    jwt: Option<&str>,
    body: &Value,
) -> (StatusCode, Vec<u8>) {
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
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("collect response body");
    (status, bytes.to_vec())
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
async fn test_remote_commit_canonical_mismatch_fails_and_rolls_back() {
    use catbird_server::auth::AuthMiddleware;
    use catbird_server::federation::commit_submitter::RemoteCommitSubmitter;
    use catbird_server::federation::outbound::OutboundClient;
    use catbird_server::federation::resolver::{DsResolver, ValidatedRemoteDestination};
    use catbird_server::federation::service_auth::ServiceAuthClient;

    let harness = TestHarness::new("mismatch").await;
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

    use p256::pkcs8::EncodePrivateKey;
    let local_ds_key = random_p256();
    cache_did_key(LOCAL_DS_DID, &local_ds_key).await;
    let pem_str = local_ds_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();

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
    let seq_test_state = TestDsState {
        pool: seq_pool.clone(),
        ack_signer: Some(seq_ack_signer.clone()),
        runtime: seq_runtime.clone(),
        blob_store: catbird_server::blob_store::BlobStore::for_route_tests(),
    };
    let seq_router = build_federation_router(seq_test_state);

    let signer_clone = seq_ack_signer.clone();
    let app = axum::Router::new().route(
        "/xrpc/blue.catbird.mlsDS.submitCommit",
        axum::routing::post(move |headers: HeaderMap, body: axum::body::Bytes| {
            let signer = signer_clone.clone();
            let router = seq_router.clone();
            async move {
                use catbird_atproto::generated::blue_catbird::mlsDS::submit_commit::{
                    SubmitCommit, SubmitCommitOutput,
                };
                use catbird_server::federation::envelope::sign_receipt;
                use catbird_server::federation::envelope::validate_envelope_header;
                use jacquard_common::DefaultStr;

                let msg: SubmitCommit<DefaultStr> = serde_json::from_slice(&body).unwrap();
                let header = validate_envelope_header(&msg.header).unwrap();

                let mut req = Request::builder()
                    .method("POST")
                    .uri("/xrpc/blue.catbird.mlsDS.submitCommit")
                    .header("content-type", "application/json");
                for (k, v) in headers.iter() {
                    req = req.header(k, v);
                }
                let response = router
                    .oneshot(req.body(Body::from(body)).unwrap())
                    .await
                    .unwrap();
                let resp_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();

                let mut output: SubmitCommitOutput = serde_json::from_slice(&resp_bytes).unwrap();
                // Coordinates, entryId, seq, and locator hashes match perfectly.
                // Mutate received_at so that only full byte-for-byte canonical response equality detects the mismatch.
                output.commit_entry.received_at =
                    catbird_server::sqlx_jacquard::chrono_to_datetime(now - chrono::Duration::seconds(100));
                let st_output = catbird_atproto::generated::blue_catbird::chat::submit_transition::SubmitTransitionOutput {
                    coordinates: output.coordinates.clone(),
                    entry: catbird_atproto::generated::blue_catbird::chat::ConversationEntry::CommitEntry(Box::new(output.commit_entry.clone())),
                    welcomes: vec![],
                    extra_data: None,
                };
                let st_bytes = serde_json::to_vec(&st_output).unwrap();
                let result_sha256 = Sha256::digest(&st_bytes);

                let source_locator = catbird_server::federation::envelope::ValidatedEntryLocator {
                    entry_id: generic_transition_id,
                    seq: 5,
                    accepted_payload_sha256: output
                        .receipt
                        .source_locator
                        .accepted_payload_sha256
                        .as_ref()
                        .try_into()
                        .unwrap(),
                    outer_entry_fingerprint: output
                        .receipt
                        .source_locator
                        .outer_entry_fingerprint
                        .as_ref()
                        .try_into()
                        .unwrap(),
                };
                let receipt = sign_receipt(
                    signer.as_ref(),
                    SUBMIT_COMMIT_NSID,
                    header.delivery_id,
                    header.conversation_id,
                    &header.sender_ds_did,
                    LOCAL_DS_DID,
                    LOCAL_DS_DID,
                    header.sequencer_term,
                    header.payload_sha256,
                    result_sha256.into(),
                    source_locator,
                    Utc::now(),
                )
                .unwrap();
                output.receipt = receipt;

                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&output).unwrap()))
                    .unwrap()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let seq_did_doc = make_test_receipt_did_doc(LOCAL_DS_DID, &local_ds_key.verifying_key());
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
        "canonical response mismatch must return 400 InvalidRequest: {body:?}"
    );
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("InvalidRequest"),
        "error code must be InvalidRequest"
    );

    let after = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(
        after, before,
        "mismatched remote commit must leave all mailbox tables byte-for-byte unchanged"
    );
}

#[tokio::test]
async fn test_remote_commit_receipt_locator_payload_hash_mismatch_fails_and_rolls_back() {
    use catbird_server::auth::AuthMiddleware;
    use catbird_server::federation::commit_submitter::RemoteCommitSubmitter;
    use catbird_server::federation::outbound::OutboundClient;
    use catbird_server::federation::resolver::{DsResolver, ValidatedRemoteDestination};
    use catbird_server::federation::service_auth::ServiceAuthClient;

    let harness = TestHarness::new("loc_payload_mismatch").await;
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

    use p256::pkcs8::EncodePrivateKey;
    let local_ds_key = random_p256();
    cache_did_key(LOCAL_DS_DID, &local_ds_key).await;
    let pem_str = local_ds_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();

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
    let seq_test_state = TestDsState {
        pool: seq_pool.clone(),
        ack_signer: Some(seq_ack_signer.clone()),
        runtime: seq_runtime.clone(),
        blob_store: catbird_server::blob_store::BlobStore::for_route_tests(),
    };
    let seq_router = build_federation_router(seq_test_state);

    let signer_clone = seq_ack_signer.clone();
    let app = axum::Router::new().route(
        "/xrpc/blue.catbird.mlsDS.submitCommit",
        axum::routing::post(move |headers: HeaderMap, body: axum::body::Bytes| {
            let signer = signer_clone.clone();
            let router = seq_router.clone();
            async move {
                use catbird_atproto::generated::blue_catbird::mlsDS::submit_commit::{
                    SubmitCommit, SubmitCommitOutput,
                };
                use catbird_server::federation::envelope::sign_receipt;
                use catbird_server::federation::envelope::validate_envelope_header;
                use jacquard_common::DefaultStr;

                let msg: SubmitCommit<DefaultStr> = serde_json::from_slice(&body).unwrap();
                let header = validate_envelope_header(&msg.header).unwrap();

                let mut req = Request::builder()
                    .method("POST")
                    .uri("/xrpc/blue.catbird.mlsDS.submitCommit")
                    .header("content-type", "application/json");
                for (k, v) in headers.iter() {
                    req = req.header(k, v);
                }
                let response = router
                    .oneshot(req.body(Body::from(body)).unwrap())
                    .await
                    .unwrap();
                let resp_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();

                let mut output: SubmitCommitOutput = serde_json::from_slice(&resp_bytes).unwrap();

                let st_output = catbird_atproto::generated::blue_catbird::chat::submit_transition::SubmitTransitionOutput {
                    coordinates: output.coordinates.clone(),
                    entry: catbird_atproto::generated::blue_catbird::chat::ConversationEntry::CommitEntry(Box::new(output.commit_entry.clone())),
                    welcomes: vec![],
                    extra_data: None,
                };
                let st_bytes = serde_json::to_vec(&st_output).unwrap();
                let result_sha256 = Sha256::digest(&st_bytes);

                // Intentionally mutate source_locator accepted_payload_sha256
                let source_locator = catbird_server::federation::envelope::ValidatedEntryLocator {
                    entry_id: generic_transition_id,
                    seq: 5,
                    accepted_payload_sha256: [0xee; 32],
                    outer_entry_fingerprint: output
                        .receipt
                        .source_locator
                        .outer_entry_fingerprint
                        .as_ref()
                        .try_into()
                        .unwrap(),
                };
                let receipt = sign_receipt(
                    signer.as_ref(),
                    SUBMIT_COMMIT_NSID,
                    header.delivery_id,
                    header.conversation_id,
                    &header.sender_ds_did,
                    LOCAL_DS_DID,
                    LOCAL_DS_DID,
                    header.sequencer_term,
                    header.payload_sha256,
                    result_sha256.into(),
                    source_locator,
                    Utc::now(),
                )
                .unwrap();
                output.receipt = receipt;

                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&output).unwrap()))
                    .unwrap()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let seq_did_doc = make_test_receipt_did_doc(LOCAL_DS_DID, &local_ds_key.verifying_key());
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
        "receipt locator accepted_payload_sha256 mismatch must return 400 InvalidRequest: {body:?}"
    );
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("InvalidRequest"),
        "error code must be InvalidRequest"
    );

    let after = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(
        after, before,
        "rejected remote commit must leave all mailbox tables byte-for-byte unchanged"
    );
}

#[tokio::test]
async fn test_remote_commit_receipt_locator_fingerprint_mismatch_fails_and_rolls_back() {
    use catbird_server::auth::AuthMiddleware;
    use catbird_server::federation::commit_submitter::RemoteCommitSubmitter;
    use catbird_server::federation::outbound::OutboundClient;
    use catbird_server::federation::resolver::{DsResolver, ValidatedRemoteDestination};
    use catbird_server::federation::service_auth::ServiceAuthClient;

    let harness = TestHarness::new("loc_fp_mismatch").await;
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

    use p256::pkcs8::EncodePrivateKey;
    let local_ds_key = random_p256();
    cache_did_key(LOCAL_DS_DID, &local_ds_key).await;
    let pem_str = local_ds_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();

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
    let seq_test_state = TestDsState {
        pool: seq_pool.clone(),
        ack_signer: Some(seq_ack_signer.clone()),
        runtime: seq_runtime.clone(),
        blob_store: catbird_server::blob_store::BlobStore::for_route_tests(),
    };
    let seq_router = build_federation_router(seq_test_state);

    let signer_clone = seq_ack_signer.clone();
    let app = axum::Router::new().route(
        "/xrpc/blue.catbird.mlsDS.submitCommit",
        axum::routing::post(move |headers: HeaderMap, body: axum::body::Bytes| {
            let signer = signer_clone.clone();
            let router = seq_router.clone();
            async move {
                use catbird_atproto::generated::blue_catbird::mlsDS::submit_commit::{
                    SubmitCommit, SubmitCommitOutput,
                };
                use catbird_server::federation::envelope::sign_receipt;
                use catbird_server::federation::envelope::validate_envelope_header;
                use jacquard_common::DefaultStr;

                let msg: SubmitCommit<DefaultStr> = serde_json::from_slice(&body).unwrap();
                let header = validate_envelope_header(&msg.header).unwrap();

                let mut req = Request::builder()
                    .method("POST")
                    .uri("/xrpc/blue.catbird.mlsDS.submitCommit")
                    .header("content-type", "application/json");
                for (k, v) in headers.iter() {
                    req = req.header(k, v);
                }
                let response = router
                    .oneshot(req.body(Body::from(body)).unwrap())
                    .await
                    .unwrap();
                let resp_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();

                let mut output: SubmitCommitOutput = serde_json::from_slice(&resp_bytes).unwrap();

                let st_output = catbird_atproto::generated::blue_catbird::chat::submit_transition::SubmitTransitionOutput {
                    coordinates: output.coordinates.clone(),
                    entry: catbird_atproto::generated::blue_catbird::chat::ConversationEntry::CommitEntry(Box::new(output.commit_entry.clone())),
                    welcomes: vec![],
                    extra_data: None,
                };
                let st_bytes = serde_json::to_vec(&st_output).unwrap();
                let result_sha256 = Sha256::digest(&st_bytes);

                // Intentionally mutate source_locator outer_entry_fingerprint
                let source_locator = catbird_server::federation::envelope::ValidatedEntryLocator {
                    entry_id: generic_transition_id,
                    seq: 5,
                    accepted_payload_sha256: output
                        .receipt
                        .source_locator
                        .accepted_payload_sha256
                        .as_ref()
                        .try_into()
                        .unwrap(),
                    outer_entry_fingerprint: [0xff; 32],
                };
                let receipt = sign_receipt(
                    signer.as_ref(),
                    SUBMIT_COMMIT_NSID,
                    header.delivery_id,
                    header.conversation_id,
                    &header.sender_ds_did,
                    LOCAL_DS_DID,
                    LOCAL_DS_DID,
                    header.sequencer_term,
                    header.payload_sha256,
                    result_sha256.into(),
                    source_locator,
                    Utc::now(),
                )
                .unwrap();
                output.receipt = receipt;

                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&output).unwrap()))
                    .unwrap()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let seq_did_doc = make_test_receipt_did_doc(LOCAL_DS_DID, &local_ds_key.verifying_key());
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
        "receipt locator outer_entry_fingerprint mismatch must return 400 InvalidRequest: {body:?}"
    );
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("InvalidRequest"),
        "error code must be InvalidRequest"
    );

    let after = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(
        after, before,
        "rejected remote commit must leave all mailbox tables byte-for-byte unchanged"
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
    cache_did_key(LOCAL_DS_DID, &local_ds_key).await;
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
    let seq_test_state = TestDsState {
        pool: seq_pool.clone(),
        ack_signer: Some(seq_ack_signer.clone()),
        runtime: seq_runtime.clone(),
        blob_store: catbird_server::blob_store::BlobStore::for_route_tests(),
    };
    let seq_router = build_federation_router(seq_test_state);
    let call_counts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let received_delivery_ids: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let counts_clone = call_counts.clone();
    let ids_clone = received_delivery_ids.clone();
    let router_clone = seq_router.clone();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    // Raw TCP wrapper: reads request, invokes real router oneshot (committing to DB),
    // and on call 1 immediately closes the TCP stream with ZERO HTTP bytes sent.
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let router = router_clone.clone();
            let counts = counts_clone.clone();
            let ids = ids_clone.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 131072];
                let mut total_read = 0;
                loop {
                    let n = stream.read(&mut buf[total_read..]).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    total_read += n;
                    let s = String::from_utf8_lossy(&buf[..total_read]);
                    if let Some(pos) = s.find("\r\n\r\n") {
                        let header_part = &s[..pos];
                        let content_length: usize = header_part
                            .lines()
                            .find_map(|line| {
                                let lower = line.to_lowercase();
                                if lower.starts_with("content-length:") {
                                    line.split_once(':')
                                        .and_then(|(_, v)| v.trim().parse().ok())
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0);
                        if total_read >= pos + 4 + content_length {
                            break;
                        }
                    }
                }
                if total_read == 0 {
                    return;
                }
                let req_bytes = &buf[..total_read];
                let req_str = String::from_utf8_lossy(req_bytes);
                let body_start = req_str.find("\r\n\r\n").map(|idx| idx + 4).unwrap_or(0);
                let body_bytes = &req_bytes[body_start..];

                let count = counts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;

                use catbird_atproto::generated::blue_catbird::mlsDS::submit_commit::SubmitCommit;
                use catbird_server::federation::envelope::validate_envelope_header;
                use jacquard_common::DefaultStr;

                if let Ok(msg) = serde_json::from_slice::<SubmitCommit<DefaultStr>>(body_bytes) {
                    if let Ok(header) = validate_envelope_header(&msg.header) {
                        let mut guard = ids.lock();
                        guard.push(header.delivery_id.to_string());
                    }
                }

                let mut req_builder = Request::builder()
                    .method("POST")
                    .uri("/xrpc/blue.catbird.mlsDS.submitCommit")
                    .header("content-type", "application/json");
                if let Some(header_part) = req_str.get(..body_start.saturating_sub(4)) {
                    for line in header_part.lines().skip(1) {
                        if let Some((k, v)) = line.split_once(':') {
                            let k_trimmed = k.trim();
                            let v_trimmed = v.trim();
                            if let (Ok(name), Ok(val)) = (
                                axum::http::header::HeaderName::from_bytes(k_trimmed.as_bytes()),
                                axum::http::HeaderValue::from_str(v_trimmed),
                            ) {
                                req_builder = req_builder.header(name, val);
                            }
                        }
                    }
                }
                let axum_req = req_builder.body(Body::from(body_bytes.to_vec())).unwrap();
                let response = router.oneshot(axum_req).await.unwrap();
                let status = response.status();
                let resp_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();

                if count == 1 {
                    // Call 1 transport drop: shutdown socket with ZERO HTTP bytes sent
                    let _ = stream.shutdown().await;
                    drop(stream);
                } else {
                    let http_response = format!(
                        "HTTP/1.1 {} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        status.as_u16(),
                        resp_bytes.len()
                    );
                    let _ = stream.write_all(http_response.as_bytes()).await;
                    let _ = stream.write_all(&resp_bytes).await;
                    let _ = stream.flush().await;
                }
            });
        }
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
        "Call 1 must fail due to dropped transport response: status={status1}, body={body1:?}"
    );
    // Mailbox state must be completely unchanged after Call 1 rollback
    let middle = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(
        middle, before,
        "Mailbox state must be completely unchanged after dropped response rollback"
    );

    // Call 2: Client retries with fresh service auth token but identical signedRequest.
    // The sequencer already committed the entry on call 1 (its response was dropped),
    // so the retry must succeed and apply exactly once.
    let jwt2 = sign_jwt(
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

    let (status2_raw, body2_raw) = send_json_to_router_raw(
        &custom_router,
        "/xrpc/blue.catbird.chat.submitTransition",
        Some(&jwt2),
        &client_body,
    )
    .await;
    let body2: Value = serde_json::from_slice(&body2_raw).unwrap_or(Value::Null);
    assert_eq!(
        status2_raw,
        StatusCode::OK,
        "Call 2 retry after dropped response must succeed: status={status2_raw}, body={body2:?}"
    );
    assert!(
        body2.get("error").is_none(),
        "Call 2 must not carry an error code: body={body2:?}"
    );

    // Call 2 applied exactly once: mailbox state is now committed.
    let after_call2 = capture_mailbox_snapshot(&harness.pool).await;

    let delivery_id =
        catbird_server::chat_protocol::test_support::repository::derive_submit_commit_delivery_id(
            convo_id,
            generic_transition_id,
            LOCAL_DS_DID,
        );
    let delivery_id_str = delivery_id.to_string();

    // Both remote calls must carry the deterministic delivery ID.
    {
        let ids = received_delivery_ids.lock();
        assert_eq!(
            ids.len(),
            2,
            "sequencer must have received exactly 2 envelopes (call 1 dropped, call 2 retried)"
        );
        for id in ids.iter() {
            assert_eq!(
                id, &delivery_id_str,
                "every remote envelope must carry the deterministic delivery ID"
            );
        }
    }

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
    let chat_outbox_cnt: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.outbox")
        .fetch_one(&harness.pool)
        .await
        .unwrap();
    assert_eq!(
        chat_outbox_cnt, 2,
        "commit apply must schedule exactly the 2 expected chat.outbox delivery work rows (stream + notification)"
    );

    // "Applied exactly once": the seeded corpus has 4 entries + 4 transitions;
    // the single commit apply adds exactly 1 of each.
    let transition_cnt: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.transitions")
        .fetch_one(&harness.pool)
        .await
        .unwrap();
    assert_eq!(
        transition_cnt, 5,
        "exactly 1 transition added by the commit apply"
    );
    let entry_cnt: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.entries")
        .fetch_one(&harness.pool)
        .await
        .unwrap();
    assert_eq!(entry_cnt, 5, "exactly 1 entry added by the commit apply");

    assert_eq!(
        call_counts.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "sequencer received 2 calls (call 1 dropped, call 2 retried and answered by replay logic)"
    );

    // Call 3: local mailbox replay of the same signedRequest must return the
    // byte-identical response WITHOUT any new remote call.
    let jwt3 = sign_jwt(
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
    let (status3_raw, body3_raw) = send_json_to_router_raw(
        &custom_router,
        "/xrpc/blue.catbird.chat.submitTransition",
        Some(&jwt3),
        &client_body,
    )
    .await;
    assert_eq!(
        status3_raw,
        StatusCode::OK,
        "Call 3 local replay must succeed: status={status3_raw}"
    );
    assert_eq!(
        body3_raw, body2_raw,
        "Call 3 local replay must return byte-identical raw response to Call 2"
    );
    // Local replay must not write anything: mailbox state after Call 3 equals
    // the state after Call 2's single apply.
    let after_call3 = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(
        after_call3, after_call2,
        "Call 3 local replay must leave mailbox state byte-for-byte unchanged"
    );
    assert_eq!(
        call_counts.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "Call 3 local replay must NOT trigger a new remote call"
    );
}

#[tokio::test]
async fn test_reconciliation_local_prefix_matches_and_suffix_applies_and_converges() {
    let harness = TestHarness::new("recon-suffix").await;
    let now = Utc::now();

    let convo_id = Uuid::new_v4();
    let group_id = vec![0x42u8; 32];
    let alice = TestActor::generate();
    alice.seed(&harness.pool, now).await;
    seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        0,
        &alice,
        Some(&harness.sender_ds_did),
        now,
    )
    .await;

    let msg_id_2 = Uuid::new_v4();
    let msg_entry_id_2 = Uuid::new_v4();
    let (_msg_val, signed_req_bytes_2) =
        make_message_body(convo_id, msg_id_2, &alice, &group_id, vec![], now);
    let mutation_2 =
        decode_and_verify_signed_mutation(&signed_req_bytes_2, &alice.public_key).unwrap();
    let received_at_2 = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&now.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
    );
    let built_2 = build_verified_application_entry(
        mutation_2,
        CanonicalUuidV4::parse(&msg_entry_id_2.to_string()).unwrap(),
        CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
        2,
        &received_at_2,
    )
    .unwrap();
    let ciphertext_2 = built_2.canonical_entry_bytes().to_vec();
    let payload_sha256_2 = built_2.accepted_payload_sha256().to_vec();
    let outer_fp_2 = built_2.outer_application_fingerprint().to_vec();

    let local_row_1: CleanDigestRow = sqlx::query_as(
        "SELECT CAST(seq AS BIGINT) AS seq, CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
                entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, \
                signed_request_bytes, outer_entry_fingerprint, received_at \
         FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();

    let remote_row_2 = CleanDigestRow {
        seq: 2,
        epoch: 0,
        entry_id: msg_entry_id_2,
        entry_kind: "blue.catbird.chat.defs#applicationEntry".to_string(),
        accepted_payload_bytes: ciphertext_2.clone(),
        accepted_payload_sha256: payload_sha256_2.clone(),
        signed_request_bytes: signed_req_bytes_2.clone(),
        outer_entry_fingerprint: outer_fp_2.clone(),
        received_at: now,
    };

    let remote_rows = vec![
        CleanDigestRow {
            seq: local_row_1.seq,
            epoch: local_row_1.epoch,
            entry_id: local_row_1.entry_id,
            entry_kind: local_row_1.entry_kind.clone(),
            accepted_payload_bytes: local_row_1.accepted_payload_bytes.clone(),
            accepted_payload_sha256: local_row_1.accepted_payload_sha256.clone(),
            signed_request_bytes: local_row_1.signed_request_bytes.clone(),
            outer_entry_fingerprint: local_row_1.outer_entry_fingerprint.clone(),
            received_at: local_row_1.received_at,
        },
        remote_row_2,
    ];
    let remote_digest_sha256 = compute_clean_convo_digest(&remote_rows);

    let convo_id_str = convo_id.to_string();
    let seq_did_clone = harness.sequencer_ds_did.clone();
    let digest_output = GetConvoDigestOutput {
        convo_id: convo_id_str.clone(),
        sequencer_ds_did: seq_did_clone.clone(),
        sequencer_term: 0,
        epoch: 0,
        last_seq: 2,
        event_count: 2,
        digest_sha256: remote_digest_sha256.clone(),
        generated_at: now,
    };

    let events_output = serde_json::json!({
        "convoId": convo_id_str,
        "fromSeqExclusive": 0,
        "toSeqInclusive": 2,
        "events": [
            {
                "seq": 1,
                "epoch": local_row_1.epoch,
                "msgId": local_row_1.entry_id.to_string(),
                "messageType": local_row_1.entry_kind,
                "ciphertext": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_bytes)},
                "paddedSize": local_row_1.accepted_payload_bytes.len() as i64,
                "createdAt": local_row_1.received_at.to_rfc3339_opts(SecondsFormat::Millis, true),
                "entryId": local_row_1.entry_id.to_string(),
                "entryKind": local_row_1.entry_kind,
                "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_sha256)},
                "signedRequest": {"$bytes": STANDARD.encode(&local_row_1.signed_request_bytes)},
                "outerFingerprint": {"$bytes": STANDARD.encode(&local_row_1.outer_entry_fingerprint)}
            },
            {
                "seq": 2,
                "epoch": 0,
                "msgId": msg_id_2.to_string(),
                "messageType": "blue.catbird.chat.defs#applicationEntry",
                "ciphertext": {"$bytes": STANDARD.encode(&ciphertext_2)},
                "paddedSize": ciphertext_2.len() as i64,
                "createdAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
                "entryId": msg_entry_id_2.to_string(),
                "entryKind": "blue.catbird.chat.defs#applicationEntry",
                "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&payload_sha256_2)},
                "signedRequest": {"$bytes": STANDARD.encode(&signed_req_bytes_2)},
                "outerFingerprint": {"$bytes": STANDARD.encode(&outer_fp_2)}
            }
        ]
    });

    let app = axum::Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest",
            axum::routing::get({
                let d = serde_json::to_vec(&digest_output).unwrap();
                move || {
                    let b = d.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoEvents",
            axum::routing::get({
                let e = serde_json::to_vec(&events_output).unwrap();
                move || {
                    let b = e.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.healthCheck",
            axum::routing::get(|| async {
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"status":"ok","capabilities":["reconciliation-v1","blue.catbird.mlsDS.reconciliation.v1"]}"#,
                    ))
                    .unwrap()
            }),
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

    let outbound = Arc::new(OutboundClient::new(2, 2));
    let auth_sign = Arc::new(move |_target: &str, _nsid: &str| Ok("test-token".to_string()));

    let res = catbird_server::federation::reconciliation::reconcile_conversation(
        &harness.pool,
        &resolver,
        &outbound,
        auth_sign.as_ref(),
        &convo_id_str,
        &harness.sequencer_ds_did,
    )
    .await;

    assert!(
        res.is_ok(),
        "reconcile_conversation must succeed: {:?}",
        res
    );

    let entry_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chat.entries WHERE conversation_id = $1")
            .bind(convo_id)
            .fetch_one(&harness.pool)
            .await
            .unwrap();
    assert_eq!(entry_count, 2, "suffix entry must be applied to DS2");

    assert_applied_suffix_entry_and_message_send_exact_fields(
        &harness.pool,
        convo_id,
        2,
        msg_entry_id_2,
        msg_id_2,
        &alice,
        &ciphertext_2,
        &payload_sha256_2,
        &signed_req_bytes_2,
        &outer_fp_2,
        built_2.mutation().transcript_bytes(),
        built_2.mutation().request_digest().as_slice(),
        built_2.mutation().signature().as_slice(),
        now,
    )
    .await;
    let sync_state: (String, i64, Option<String>) = sqlx::query_as(
        "SELECT status, last_seq, quarantine_reason FROM federation_sync_state WHERE convo_id = $1",
    )
    .bind(&convo_id_str)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert_eq!(sync_state.0, "healthy");
    assert_eq!(sync_state.1, 2);
    assert_eq!(sync_state.2, None);
}

#[tokio::test]
async fn test_reconciliation_same_last_seq_differing_fingerprint_quarantines_without_clean_table_mutation(
) {
    let harness = TestHarness::new("recon-mismatch").await;
    let now = Utc::now();

    let convo_id = Uuid::new_v4();
    let group_id = vec![0x42u8; 32];
    let alice = TestActor::generate();
    alice.seed(&harness.pool, now).await;
    seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        0,
        &alice,
        Some(&harness.sender_ds_did),
        now,
    )
    .await;

    // Seed an entry at seq 2 on local DS2
    let msg_id_2_local = Uuid::new_v4();
    let (_msg_val, signed_req_bytes_2_local) =
        make_message_body(convo_id, msg_id_2_local, &alice, &group_id, vec![], now);
    let ciphertext_2_local = vec![0x31u8; 8];
    let payload_sha256_2_local = Sha256::digest(&ciphertext_2_local).to_vec();

    let mutation_local = decode_canonical_signed_mutation(&signed_req_bytes_2_local).unwrap();
    let req_digest_local = mutation_local.request_digest().to_vec();
    let sig_bytes_local = mutation_local.signature().to_vec();
    let transcript_local = mutation_local.transcript_bytes().to_vec();

    let outcome_bytes_local = serde_json::to_vec(&serde_json::json!({
        "entry": {
            "entryId": msg_id_2_local.to_string(),
            "conversationId": convo_id.to_string(),
            "seq": 2,
            "signedRequest": serde_json::from_slice::<serde_json::Value>(&signed_req_bytes_2_local).unwrap(),
            "receivedAt": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        }
    }))
    .unwrap();
    let outcome_sha_local = Sha256::digest(&outcome_bytes_local).to_vec();

    let mut tx = harness.pool.begin().await.unwrap();
    sqlx::query(
        r#"
        INSERT INTO chat.entries (
            conversation_id, seq, entry_id, entry_kind,
            accepted_payload_bytes, accepted_payload_sha256, signed_request_bytes,
            request_digest, signature, server_fields_bytes, outer_entry_fingerprint,
            actor_did, actor_device_id, actor_key_id, actor_auth_generation,
            generation, message_id, received_at
        ) VALUES (
            $1, 2, $2, 'blue.catbird.chat.defs#applicationEntry',
            $3, $4, $5,
            $6, $7, '\xa0', $8,
            $9, $10, $11, 1,
            0, $2, $12
        )
        "#,
    )
    .bind(convo_id)
    .bind(msg_id_2_local)
    .bind(&ciphertext_2_local)
    .bind(&payload_sha256_2_local)
    .bind(&signed_req_bytes_2_local)
    .bind(&req_digest_local)
    .bind(&sig_bytes_local)
    .bind(&payload_sha256_2_local)
    .bind(&alice.did)
    .bind(alice.device_id)
    .bind(&alice.key_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.message_sends (
            conversation_id, message_id, signed_request_bytes,
            signing_transcript_bytes, request_digest, signature, status,
            accepted_entry_seq, outcome_bytes, outcome_sha256, received_at
        ) VALUES ($1, $2, $3, $4, $5, $6, 'accepted', 2, $7, $8, $9)
        "#,
    )
    .bind(convo_id)
    .bind(msg_id_2_local)
    .bind(&signed_req_bytes_2_local)
    .bind(&transcript_local)
    .bind(&req_digest_local)
    .bind(&sig_bytes_local)
    .bind(&outcome_bytes_local)
    .bind(&outcome_sha_local)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query("UPDATE chat.conversations SET next_entry_seq = 3 WHERE conversation_id = $1")
        .bind(convo_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Sequencer DS1 has seq 2 with DIFFERENT payload
    let msg_id_2_remote = Uuid::new_v4();
    let (_msg_val, signed_req_bytes_2_remote) =
        make_message_body(convo_id, msg_id_2_remote, &alice, &group_id, vec![], now);
    let ciphertext_2_remote = vec![0x99u8; 8];
    let payload_sha256_2_remote = Sha256::digest(&ciphertext_2_remote).to_vec();

    let local_row_1: CleanDigestRow = sqlx::query_as(
        "SELECT CAST(seq AS BIGINT) AS seq, CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
                entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, \
                signed_request_bytes, outer_entry_fingerprint, received_at \
         FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();

    let remote_row_2 = CleanDigestRow {
        seq: 2,
        epoch: 0,
        entry_id: msg_id_2_remote,
        entry_kind: "blue.catbird.chat.defs#applicationEntry".to_string(),
        accepted_payload_bytes: ciphertext_2_remote.clone(),
        accepted_payload_sha256: payload_sha256_2_remote.clone(),
        signed_request_bytes: signed_req_bytes_2_remote.clone(),
        outer_entry_fingerprint: payload_sha256_2_remote.clone(),
        received_at: now,
    };

    let remote_rows = vec![
        CleanDigestRow {
            seq: local_row_1.seq,
            epoch: local_row_1.epoch,
            entry_id: local_row_1.entry_id,
            entry_kind: local_row_1.entry_kind.clone(),
            accepted_payload_bytes: local_row_1.accepted_payload_bytes.clone(),
            accepted_payload_sha256: local_row_1.accepted_payload_sha256.clone(),
            signed_request_bytes: local_row_1.signed_request_bytes.clone(),
            outer_entry_fingerprint: local_row_1.outer_entry_fingerprint.clone(),
            received_at: local_row_1.received_at,
        },
        remote_row_2,
    ];
    let remote_digest_sha256 = compute_clean_convo_digest(&remote_rows);

    let convo_id_str = convo_id.to_string();
    let seq_did_clone = harness.sequencer_ds_did.clone();
    let digest_output = GetConvoDigestOutput {
        convo_id: convo_id_str.clone(),
        sequencer_ds_did: seq_did_clone.clone(),
        sequencer_term: 0,
        epoch: 0,
        last_seq: 2,
        event_count: 2,
        digest_sha256: remote_digest_sha256.clone(),
        generated_at: now,
    };

    let events_output = serde_json::json!({
        "convoId": convo_id_str,
        "fromSeqExclusive": 0,
        "toSeqInclusive": 2,
        "events": [
            {
                "seq": 1,
                "epoch": local_row_1.epoch,
                "msgId": local_row_1.entry_id.to_string(),
                "messageType": local_row_1.entry_kind,
                "ciphertext": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_bytes)},
                "paddedSize": local_row_1.accepted_payload_bytes.len() as i64,
                "createdAt": local_row_1.received_at.to_rfc3339_opts(SecondsFormat::Millis, true),
                "entryId": local_row_1.entry_id.to_string(),
                "entryKind": local_row_1.entry_kind,
                "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_sha256)},
                "signedRequest": {"$bytes": STANDARD.encode(&local_row_1.signed_request_bytes)},
                "outerFingerprint": {"$bytes": STANDARD.encode(&local_row_1.outer_entry_fingerprint)}
            },
            {
                "seq": 2,
                "epoch": 0,
                "msgId": msg_id_2_remote.to_string(),
                "messageType": "blue.catbird.chat.defs#applicationEntry",
                "ciphertext": {"$bytes": STANDARD.encode(&ciphertext_2_remote)},
                "paddedSize": ciphertext_2_remote.len() as i64,
                "createdAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
                "entryId": msg_id_2_remote.to_string(),
                "entryKind": "blue.catbird.chat.defs#applicationEntry",
                "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&payload_sha256_2_remote)},
                "signedRequest": {"$bytes": STANDARD.encode(&signed_req_bytes_2_remote)},
                "outerFingerprint": {"$bytes": STANDARD.encode(&payload_sha256_2_remote)}
            }
        ]
    });

    let app = axum::Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest",
            axum::routing::get({
                let d = serde_json::to_vec(&digest_output).unwrap();
                move || {
                    let b = d.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoEvents",
            axum::routing::get({
                let e = serde_json::to_vec(&events_output).unwrap();
                move || {
                    let b = e.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.healthCheck",
            axum::routing::get(|| async {
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"status":"ok","capabilities":["reconciliation-v1","blue.catbird.mlsDS.reconciliation.v1"]}"#,
                    ))
                    .unwrap()
            }),
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

    let outbound = Arc::new(OutboundClient::new(2, 2));
    let auth_sign = Arc::new(move |_target: &str, _nsid: &str| Ok("test-token".to_string()));

    let before = capture_mailbox_snapshot(&harness.pool).await;

    let res = catbird_server::federation::reconciliation::reconcile_conversation(
        &harness.pool,
        &resolver,
        &outbound,
        auth_sign.as_ref(),
        &convo_id_str,
        &harness.sequencer_ds_did,
    )
    .await;
    assert!(
        res.is_ok(),
        "reconcile_conversation must succeed (quarantine recorded): {:?}",
        res
    );

    let sync_state: (String, Option<String>, Option<i64>) = sqlx::query_as(
        "SELECT status, quarantine_reason, first_mismatch_seq FROM federation_sync_state WHERE convo_id = $1",
    )
    .bind(&convo_id_str)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert_eq!(sync_state.0, "quarantined");
    assert_eq!(sync_state.1.as_deref(), Some("prefix_mismatch"));
    assert_eq!(sync_state.2, Some(2));

    let after = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(
        after, before,
        "quarantined conversation must leave all clean tables byte-for-byte unchanged"
    );
}

#[tokio::test]
async fn test_reconciliation_local_ahead_of_sequencer_quarantines_without_truncation_or_overwrite()
{
    let harness = TestHarness::new("recon-ahead").await;
    let now = Utc::now();
    let convo_id = Uuid::new_v4();
    let group_id = vec![0x42u8; 32];
    let alice = TestActor::generate();
    alice.seed(&harness.pool, now).await;
    seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        0,
        &alice,
        Some(&harness.sender_ds_did),
        now,
    )
    .await;

    // Seed entry at seq 2 on local DS2
    let msg_id_2_local = Uuid::new_v4();
    let (_msg_val, signed_req_bytes_2_local) =
        make_message_body(convo_id, msg_id_2_local, &alice, &group_id, vec![], now);
    let ciphertext_2_local = vec![0x31u8; 8];
    let payload_sha256_2_local = Sha256::digest(&ciphertext_2_local).to_vec();

    let mutation_local = decode_canonical_signed_mutation(&signed_req_bytes_2_local).unwrap();
    let req_digest_local = mutation_local.request_digest().to_vec();
    let sig_bytes_local = mutation_local.signature().to_vec();
    let transcript_local = mutation_local.transcript_bytes().to_vec();

    let outcome_bytes_local = serde_json::to_vec(&serde_json::json!({
        "entry": {
            "entryId": msg_id_2_local.to_string(),
            "conversationId": convo_id.to_string(),
            "seq": 2,
            "signedRequest": serde_json::from_slice::<serde_json::Value>(&signed_req_bytes_2_local).unwrap(),
            "receivedAt": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        }
    }))
    .unwrap();
    let outcome_sha_local = Sha256::digest(&outcome_bytes_local).to_vec();

    let mut tx = harness.pool.begin().await.unwrap();
    sqlx::query(
        r#"
        INSERT INTO chat.entries (
            conversation_id, seq, entry_id, entry_kind,
            accepted_payload_bytes, accepted_payload_sha256, signed_request_bytes,
            request_digest, signature, server_fields_bytes, outer_entry_fingerprint,
            actor_did, actor_device_id, actor_key_id, actor_auth_generation,
            generation, message_id, received_at
        ) VALUES (
            $1, 2, $2, 'blue.catbird.chat.defs#applicationEntry',
            $3, $4, $5,
            $6, $7, '\xa0', $8,
            $9, $10, $11, 1,
            0, $2, $12
        )
        "#,
    )
    .bind(convo_id)
    .bind(msg_id_2_local)
    .bind(&ciphertext_2_local)
    .bind(&payload_sha256_2_local)
    .bind(&signed_req_bytes_2_local)
    .bind(&req_digest_local)
    .bind(&sig_bytes_local)
    .bind(&payload_sha256_2_local)
    .bind(&alice.did)
    .bind(alice.device_id)
    .bind(&alice.key_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.message_sends (
            conversation_id, message_id, signed_request_bytes,
            signing_transcript_bytes, request_digest, signature, status,
            accepted_entry_seq, outcome_bytes, outcome_sha256, received_at
        ) VALUES ($1, $2, $3, $4, $5, $6, 'accepted', 2, $7, $8, $9)
        "#,
    )
    .bind(convo_id)
    .bind(msg_id_2_local)
    .bind(&signed_req_bytes_2_local)
    .bind(&transcript_local)
    .bind(&req_digest_local)
    .bind(&sig_bytes_local)
    .bind(&outcome_bytes_local)
    .bind(&outcome_sha_local)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query("UPDATE chat.conversations SET next_entry_seq = 3 WHERE conversation_id = $1")
        .bind(convo_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Sequencer DS1 has only seq 1
    let local_row_1: CleanDigestRow = sqlx::query_as(
        "SELECT CAST(seq AS BIGINT) AS seq, CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
                entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, \
                signed_request_bytes, outer_entry_fingerprint, received_at \
         FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();

    let remote_rows = vec![CleanDigestRow {
        seq: local_row_1.seq,
        epoch: local_row_1.epoch,
        entry_id: local_row_1.entry_id,
        entry_kind: local_row_1.entry_kind.clone(),
        accepted_payload_bytes: local_row_1.accepted_payload_bytes.clone(),
        accepted_payload_sha256: local_row_1.accepted_payload_sha256.clone(),
        signed_request_bytes: local_row_1.signed_request_bytes.clone(),
        outer_entry_fingerprint: local_row_1.outer_entry_fingerprint.clone(),
        received_at: local_row_1.received_at,
    }];
    let remote_digest_sha256 = compute_clean_convo_digest(&remote_rows);

    let convo_id_str = convo_id.to_string();
    let seq_did_clone = harness.sequencer_ds_did.clone();
    let digest_output = GetConvoDigestOutput {
        convo_id: convo_id_str.clone(),
        sequencer_ds_did: seq_did_clone.clone(),
        sequencer_term: 0,
        epoch: 0,
        last_seq: 1,
        event_count: 1,
        digest_sha256: remote_digest_sha256.clone(),
        generated_at: now,
    };

    let events_output = serde_json::json!({
        "convoId": convo_id_str,
        "fromSeqExclusive": 0,
        "toSeqInclusive": 1,
        "events": [
            {
                "seq": 1,
                "epoch": local_row_1.epoch,
                "msgId": local_row_1.entry_id.to_string(),
                "messageType": local_row_1.entry_kind,
                "ciphertext": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_bytes)},
                "paddedSize": local_row_1.accepted_payload_bytes.len() as i64,
                "createdAt": local_row_1.received_at.to_rfc3339_opts(SecondsFormat::Millis, true),
                "entryId": local_row_1.entry_id.to_string(),
                "entryKind": local_row_1.entry_kind,
                "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_sha256)},
                "signedRequest": {"$bytes": STANDARD.encode(&local_row_1.signed_request_bytes)},
                "outerFingerprint": {"$bytes": STANDARD.encode(&local_row_1.outer_entry_fingerprint)}
            }
        ]
    });

    let app = axum::Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest",
            axum::routing::get({
                let d = serde_json::to_vec(&digest_output).unwrap();
                move || {
                    let b = d.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoEvents",
            axum::routing::get({
                let e = serde_json::to_vec(&events_output).unwrap();
                move || {
                    let b = e.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.healthCheck",
            axum::routing::get(|| async {
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"status":"ok","capabilities":["reconciliation-v1","blue.catbird.mlsDS.reconciliation.v1"]}"#,
                    ))
                    .unwrap()
            }),
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

    let outbound = Arc::new(OutboundClient::new(2, 2));
    let auth_sign = Arc::new(move |_target: &str, _nsid: &str| Ok("test-token".to_string()));

    let before = capture_mailbox_snapshot(&harness.pool).await;

    let res = catbird_server::federation::reconciliation::reconcile_conversation(
        &harness.pool,
        &resolver,
        &outbound,
        auth_sign.as_ref(),
        &convo_id_str,
        &harness.sequencer_ds_did,
    )
    .await;

    assert!(
        res.is_ok(),
        "reconcile_conversation must succeed (quarantine recorded): {:?}",
        res
    );

    let sync_state: (String, Option<String>, Option<i64>) = sqlx::query_as(
        "SELECT status, quarantine_reason, first_mismatch_seq FROM federation_sync_state WHERE convo_id = $1",
    )
    .bind(&convo_id_str)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert_eq!(sync_state.0, "quarantined");
    assert_eq!(sync_state.1.as_deref(), Some("local_ahead"));
    assert_eq!(sync_state.2, Some(2));

    let after = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(
        after, before,
        "quarantined local-ahead conversation must leave all clean tables byte-for-byte unchanged"
    );
}

#[tokio::test]
async fn test_quarantine_vs_blocked_mailbox_writer_ordering_rejects_and_preserves_state() {
    let harness = TestHarness::new("lock-order").await;
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
        received_at: catbird_server::chat_protocol::test_support::CanonicalTimestamp::parse(
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
        )
        .unwrap(),
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
        &now.to_rfc3339_opts(SecondsFormat::Millis, true),
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

    let before = capture_mailbox_snapshot(&harness.pool).await;

    // 1. Hold the row lock on chat.conversations and record the holder's backend PID
    let mut tx_lock = harness.pool.begin().await.unwrap();
    let (holder_pid,): (i32,) = sqlx::query_as("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx_lock)
        .await
        .unwrap();

    let _: (bool,) = sqlx::query_as(
        "SELECT is_remote FROM chat.conversations WHERE conversation_id = $1 FOR UPDATE",
    )
    .bind(convo_id)
    .fetch_one(&mut *tx_lock)
    .await
    .unwrap();

    // 2. Spawn writer in background - will block on the row lock
    let router_clone = harness.router.clone();
    let jwt_clone = jwt.clone();
    let body_clone = deliver_msg_body.clone();
    let writer_handle = tokio::spawn(async move {
        send_json_to_router(
            &router_clone,
            "/xrpc/blue.catbird.mlsDS.deliverMessage",
            Some(&jwt_clone),
            &body_clone,
        )
        .await
    });

    // Poll PostgreSQL lock state until the writer backend is blocked by the holder PID
    let start = std::time::Instant::now();
    let mut blocked = false;
    let mut blocked_pid = 0;
    while start.elapsed() < std::time::Duration::from_secs(5) {
        let blocked_row: Option<(i32,)> = sqlx::query_as(
            r#"
            SELECT pid
            FROM pg_stat_activity
            WHERE $1 = ANY(pg_blocking_pids(pid))
              AND pid != $1
            "#,
        )
        .bind(holder_pid)
        .fetch_optional(&harness.pool)
        .await
        .unwrap();

        if let Some((pid,)) = blocked_row {
            blocked = true;
            blocked_pid = pid;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        blocked,
        "production writer (pid {}) must be blocked by holder pid {} on chat.conversations row lock",
        blocked_pid,
        holder_pid
    );

    // 3. Update federation_sync_state to quarantined
    sqlx::query(
        r#"
        INSERT INTO federation_sync_state
            (convo_id, sequencer_ds_did, sequencer_term, last_seq, last_epoch, last_digest, last_reconciled_at, drift_count, updated_at, status, quarantined_at, quarantine_reason, first_mismatch_seq)
        VALUES ($1, $2, 1, 1, 0, '\x00', NOW(), 1, NOW(), 'quarantined', NOW(), 'prefix_mismatch', 2)
        ON CONFLICT (convo_id, sequencer_ds_did) DO UPDATE SET
            status = 'quarantined',
            quarantined_at = NOW(),
            quarantine_reason = 'prefix_mismatch',
            first_mismatch_seq = 2,
            updated_at = NOW()
        "#,
    )
    .bind(convo_id.to_string())
    .bind(&harness.sequencer_ds_did)
    .execute(&harness.pool)
    .await
    .unwrap();

    // 4. Release the row lock
    tx_lock.commit().await.unwrap();
    let (status, body, _) = writer_handle.await.unwrap();
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body["error"].as_str(),
        Some("DeliveryConflict"),
        "expected DeliveryConflict, got: {:?}",
        body
    );

    // 6. Verify clean conversation state unchanged
    let after = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(
        after, before,
        "blocked writer must leave all clean tables byte-for-byte unchanged after quarantine"
    );
}

#[tokio::test]
async fn test_reconciliation_two_event_suffix_with_second_event_malformed_rolls_back_atomically() {
    let harness = TestHarness::new("recon-rollback").await;
    let now = Utc::now();
    let convo_id = Uuid::new_v4();
    let group_id = vec![0x44u8; 32];
    let alice = TestActor::generate();
    alice.seed(&harness.pool, now).await;
    seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        0,
        &alice,
        Some(&harness.sender_ds_did),
        now,
    )
    .await;

    // Event 1: valid application entry at seq 2
    let msg_id_2 = Uuid::new_v4();
    let msg_entry_id_2 = Uuid::new_v4();
    let (_, signed_req_bytes_2) =
        make_message_body(convo_id, msg_id_2, &alice, &group_id, vec![], now);
    let mutation_2 =
        decode_and_verify_signed_mutation(&signed_req_bytes_2, &alice.public_key).unwrap();
    let received_at_2 = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&now.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
    );
    let built_2 = build_verified_application_entry(
        mutation_2,
        CanonicalUuidV4::parse(&msg_entry_id_2.to_string()).unwrap(),
        CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
        2,
        &received_at_2,
    )
    .unwrap();
    let ciphertext_2 = built_2.canonical_entry_bytes().to_vec();
    let payload_sha256_2 = built_2.accepted_payload_sha256().to_vec();
    let outer_fp_2 = built_2.outer_application_fingerprint().to_vec();

    // Event 2: malformed application entry at seq 3 (signed for a DIFFERENT conversation ID)
    let different_convo_id = Uuid::new_v4();
    let msg_id_3 = Uuid::new_v4();
    let msg_entry_id_3 = Uuid::new_v4();
    let (_, signed_req_bytes_3) =
        make_message_body(different_convo_id, msg_id_3, &alice, &group_id, vec![], now);
    let mutation_3 =
        decode_and_verify_signed_mutation(&signed_req_bytes_3, &alice.public_key).unwrap();
    let built_3 = build_verified_application_entry(
        mutation_3,
        CanonicalUuidV4::parse(&msg_entry_id_3.to_string()).unwrap(),
        CanonicalUuidV4::parse(&different_convo_id.to_string()).unwrap(),
        3,
        &received_at_2,
    )
    .unwrap();
    let ciphertext_3 = built_3.canonical_entry_bytes().to_vec();
    let payload_sha256_3 = built_3.accepted_payload_sha256().to_vec();
    let outer_fp_3 = built_3.outer_application_fingerprint().to_vec();

    let local_row_1: CleanDigestRow = sqlx::query_as(
        "SELECT CAST(seq AS BIGINT) AS seq, CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
                entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, \
                signed_request_bytes, outer_entry_fingerprint, received_at \
         FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();

    let remote_row_2 = CleanDigestRow {
        seq: 2,
        epoch: 0,
        entry_id: msg_entry_id_2,
        entry_kind: "blue.catbird.chat.defs#applicationEntry".to_string(),
        accepted_payload_bytes: ciphertext_2.clone(),
        accepted_payload_sha256: payload_sha256_2.clone(),
        signed_request_bytes: signed_req_bytes_2.clone(),
        outer_entry_fingerprint: outer_fp_2.clone(),
        received_at: now,
    };

    let remote_row_3 = CleanDigestRow {
        seq: 3,
        epoch: 0,
        entry_id: msg_entry_id_3,
        entry_kind: "blue.catbird.chat.defs#applicationEntry".to_string(),
        accepted_payload_bytes: ciphertext_3.clone(),
        accepted_payload_sha256: payload_sha256_3.clone(),
        signed_request_bytes: signed_req_bytes_3.clone(),
        outer_entry_fingerprint: outer_fp_3.clone(),
        received_at: now,
    };

    let remote_rows = vec![
        CleanDigestRow {
            seq: local_row_1.seq,
            epoch: local_row_1.epoch,
            entry_id: local_row_1.entry_id,
            entry_kind: local_row_1.entry_kind.clone(),
            accepted_payload_bytes: local_row_1.accepted_payload_bytes.clone(),
            accepted_payload_sha256: local_row_1.accepted_payload_sha256.clone(),
            signed_request_bytes: local_row_1.signed_request_bytes.clone(),
            outer_entry_fingerprint: local_row_1.outer_entry_fingerprint.clone(),
            received_at: local_row_1.received_at,
        },
        remote_row_2,
        remote_row_3,
    ];
    let remote_digest_sha256 = compute_clean_convo_digest(&remote_rows);

    let convo_id_str = convo_id.to_string();
    let seq_did_clone = harness.sequencer_ds_did.clone();
    let digest_output = GetConvoDigestOutput {
        convo_id: convo_id_str.clone(),
        sequencer_ds_did: seq_did_clone.clone(),
        sequencer_term: 0,
        epoch: 0,
        last_seq: 3,
        event_count: 3,
        digest_sha256: remote_digest_sha256.clone(),
        generated_at: now,
    };

    let events_output = serde_json::json!({
        "convoId": convo_id_str,
        "fromSeqExclusive": 0,
        "toSeqInclusive": 3,
        "events": [
            {
                "seq": 1,
                "epoch": local_row_1.epoch,
                "msgId": local_row_1.entry_id.to_string(),
                "messageType": local_row_1.entry_kind,
                "ciphertext": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_bytes)},
                "paddedSize": local_row_1.accepted_payload_bytes.len() as i64,
                "createdAt": local_row_1.received_at.to_rfc3339_opts(SecondsFormat::Millis, true),
                "entryId": local_row_1.entry_id.to_string(),
                "entryKind": local_row_1.entry_kind,
                "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_sha256)},
                "signedRequest": {"$bytes": STANDARD.encode(&local_row_1.signed_request_bytes)},
                "outerFingerprint": {"$bytes": STANDARD.encode(&local_row_1.outer_entry_fingerprint)}
            },
            {
                "seq": 2,
                "epoch": 0,
                "msgId": msg_id_2.to_string(),
                "messageType": "blue.catbird.chat.defs#applicationEntry",
                "ciphertext": {"$bytes": STANDARD.encode(&ciphertext_2)},
                "paddedSize": ciphertext_2.len() as i64,
                "createdAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
                "entryId": msg_entry_id_2.to_string(),
                "entryKind": "blue.catbird.chat.defs#applicationEntry",
                "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&payload_sha256_2)},
                "signedRequest": {"$bytes": STANDARD.encode(&signed_req_bytes_2)},
                "outerFingerprint": {"$bytes": STANDARD.encode(&outer_fp_2)}
            },
            {
                "seq": 3,
                "epoch": 0,
                "msgId": msg_id_3.to_string(),
                "messageType": "blue.catbird.chat.defs#applicationEntry",
                "ciphertext": {"$bytes": STANDARD.encode(&ciphertext_3)},
                "paddedSize": ciphertext_3.len() as i64,
                "createdAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
                "entryId": msg_entry_id_3.to_string(),
                "entryKind": "blue.catbird.chat.defs#applicationEntry",
                "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&payload_sha256_3)},
                "signedRequest": {"$bytes": STANDARD.encode(&signed_req_bytes_3)},
                "outerFingerprint": {"$bytes": STANDARD.encode(&outer_fp_3)}
            }
        ]
    });

    let app = axum::Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest",
            axum::routing::get({
                let d = serde_json::to_vec(&digest_output).unwrap();
                move || {
                    let b = d.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoEvents",
            axum::routing::get({
                let e = serde_json::to_vec(&events_output).unwrap();
                move || {
                    let b = e.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.healthCheck",
            axum::routing::get(|| async {
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"status":"ok","capabilities":["reconciliation-v1","blue.catbird.mlsDS.reconciliation.v1"]}"#,
                    ))
                    .unwrap()
            }),
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

    let outbound = Arc::new(OutboundClient::new(2, 2));
    let auth_sign = Arc::new(move |_target: &str, _nsid: &str| Ok("test-token".to_string()));

    let before = capture_mailbox_snapshot(&harness.pool).await;

    let res = catbird_server::federation::reconciliation::reconcile_conversation(
        &harness.pool,
        &resolver,
        &outbound,
        auth_sign.as_ref(),
        &convo_id_str,
        &harness.sequencer_ds_did,
    )
    .await;

    assert!(
        res.is_err(),
        "reconciliation must fail on malformed second event: {:?}",
        res
    );

    // Prove atomicity: Event 1 was rolled back completely
    let entry_2_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.entries WHERE conversation_id = $1 AND seq >= 2",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert_eq!(
        entry_2_count, 0,
        "event 1 must be rolled back from chat.entries"
    );

    let sends_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.message_sends WHERE conversation_id = $1")
            .bind(convo_id)
            .fetch_one(&harness.pool)
            .await
            .unwrap();
    assert_eq!(
        sends_count, 0,
        "message_sends side projection must be rolled back"
    );

    let next_seq: i64 = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert_eq!(next_seq, 2, "next_entry_seq must not have advanced");

    let sync_state: Option<(String,)> =
        sqlx::query_as("SELECT status FROM federation_sync_state WHERE convo_id = $1")
            .bind(&convo_id_str)
            .fetch_optional(&harness.pool)
            .await
            .unwrap();
    assert!(
        sync_state.is_none() || sync_state.unwrap().0 != "quarantined",
        "malformed suffix is a no-write protocol failure, not quarantine"
    );

    let after = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(
        after, before,
        "failed suffix apply must leave all clean tables byte-for-byte unchanged"
    );
}

#[tokio::test]
async fn test_reconciliation_multi_page_bounded_pagination_and_progress() {
    let harness = TestHarness::new("recon-multipage").await;
    let now = Utc::now();
    let convo_id = Uuid::new_v4();
    let group_id = vec![0x55u8; 32];
    let alice = TestActor::generate();
    alice.seed(&harness.pool, now).await;
    seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        0,
        &alice,
        Some(&harness.sender_ds_did),
        now,
    )
    .await;

    let local_row_1: CleanDigestRow = sqlx::query_as(
        "SELECT CAST(seq AS BIGINT) AS seq, CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
                entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, \
                signed_request_bytes, outer_entry_fingerprint, received_at \
         FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();

    struct GeneratedSuffix {
        seq: i64,
        msg_entry_id: Uuid,
        msg_id: Uuid,
        ciphertext: Vec<u8>,
        payload_sha256: [u8; 32],
        signed_req_bytes: Vec<u8>,
        outer_fp: [u8; 32],
        transcript_bytes: Vec<u8>,
        request_digest: [u8; 32],
        signature: [u8; 64],
    }

    // Generate 505 suffix events (seq 2..=506)
    let mut all_events = Vec::with_capacity(506);
    all_events.push(serde_json::json!({
        "seq": 1,
        "epoch": local_row_1.epoch,
        "msgId": local_row_1.entry_id.to_string(),
        "messageType": local_row_1.entry_kind,
        "ciphertext": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_bytes)},
        "paddedSize": local_row_1.accepted_payload_bytes.len() as i64,
        "createdAt": local_row_1.received_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "entryId": local_row_1.entry_id.to_string(),
        "entryKind": local_row_1.entry_kind,
        "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_sha256)},
        "signedRequest": {"$bytes": STANDARD.encode(&local_row_1.signed_request_bytes)},
        "outerFingerprint": {"$bytes": STANDARD.encode(&local_row_1.outer_entry_fingerprint)}
    }));

    let mut all_digest_rows = Vec::with_capacity(506);
    all_digest_rows.push(local_row_1);

    let mut generated_suffix = Vec::with_capacity(505);

    for seq in 2..=506 {
        let msg_id = Uuid::new_v4();
        let msg_entry_id = Uuid::new_v4();
        let (_, signed_req_bytes) =
            make_message_body(convo_id, msg_id, &alice, &group_id, vec![], now);
        let mutation =
            decode_and_verify_signed_mutation(&signed_req_bytes, &alice.public_key).unwrap();
        let transcript_bytes = mutation.transcript_bytes().to_vec();
        let request_digest = *mutation.request_digest();
        let signature = *mutation.signature();
        let received_at = TrustedRequestInstant::from_canonical_for_test(
            CanonicalTimestamp::parse(&now.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
        );
        let built = build_verified_application_entry(
            mutation,
            CanonicalUuidV4::parse(&msg_entry_id.to_string()).unwrap(),
            CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
            seq as u64,
            &received_at,
        )
        .unwrap();
        let ciphertext = built.canonical_entry_bytes().to_vec();
        let payload_sha256 = *built.accepted_payload_sha256();
        let outer_fp = *built.outer_application_fingerprint();

        all_digest_rows.push(CleanDigestRow {
            seq: seq as i64,
            epoch: 0,
            entry_id: msg_entry_id,
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_string(),
            accepted_payload_bytes: ciphertext.clone(),
            accepted_payload_sha256: payload_sha256.to_vec(),
            signed_request_bytes: signed_req_bytes.clone(),
            outer_entry_fingerprint: outer_fp.to_vec(),
            received_at: now,
        });

        all_events.push(serde_json::json!({
            "seq": seq,
            "epoch": 0,
            "msgId": msg_id.to_string(),
            "messageType": "blue.catbird.chat.defs#applicationEntry",
            "ciphertext": {"$bytes": STANDARD.encode(&ciphertext)},
            "paddedSize": ciphertext.len() as i64,
            "createdAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
            "entryId": msg_entry_id.to_string(),
            "entryKind": "blue.catbird.chat.defs#applicationEntry",
            "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&payload_sha256)},
            "signedRequest": {"$bytes": STANDARD.encode(&signed_req_bytes)},
            "outerFingerprint": {"$bytes": STANDARD.encode(&outer_fp)}
        }));
        generated_suffix.push(GeneratedSuffix {
            seq: seq as i64,
            msg_entry_id,
            msg_id,
            ciphertext,
            payload_sha256,
            signed_req_bytes,
            outer_fp,
            transcript_bytes,
            request_digest,
            signature,
        });
    }

    let total_digest_sha256 = compute_clean_convo_digest(&all_digest_rows);
    let convo_id_str = convo_id.to_string();
    let seq_did_clone = harness.sequencer_ds_did.clone();

    let digest_output = GetConvoDigestOutput {
        convo_id: convo_id_str.clone(),
        sequencer_ds_did: seq_did_clone.clone(),
        sequencer_term: 0,
        epoch: 0,
        last_seq: 506,
        event_count: 506,
        digest_sha256: total_digest_sha256.clone(),
        generated_at: now,
    };

    // 4 pages: 0..130, 130..260, 260..390, 390..506
    let page1_events = all_events[0..130].to_vec();
    let page2_events = all_events[130..260].to_vec();
    let page3_events = all_events[260..390].to_vec();
    let page4_events = all_events[390..506].to_vec();

    let pagination_requests: Arc<tokio::sync::Mutex<Vec<(i64, i64)>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let pagination_requests_clone = pagination_requests.clone();

    let convo_id_clone = convo_id_str.clone();
    let app = axum::Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest",
            axum::routing::get({
                let d = serde_json::to_vec(&digest_output).unwrap();
                let exp_cid = convo_id_clone.clone();
                move |headers: axum::http::HeaderMap, axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>| {
                    let b = d.clone();
                    let exp_c = exp_cid.clone();
                    async move {
                        let auth_hdr = headers.get("authorization").and_then(|h| h.to_str().ok()).unwrap_or("");
                        if auth_hdr != "Bearer test-token" {
                            return axum::response::Response::builder()
                                .status(StatusCode::UNAUTHORIZED)
                                .header("content-type", "application/json")
                                .body(axum::body::Body::from(r#"{"error":"NotAuthorized","message":"invalid token"}"#))
                                .unwrap();
                        }
                        if params.get("convoId").map(|s| s.as_str()) != Some(&exp_c) {
                            return axum::response::Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .header("content-type", "application/json")
                                .body(axum::body::Body::from(r#"{"error":"InvalidRequest","message":"invalid convoId"}"#))
                                .unwrap();
                        }
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoEvents",
            axum::routing::get({
                let p1 = page1_events.clone();
                let p2 = page2_events.clone();
                let p3 = page3_events.clone();
                let p4 = page4_events.clone();
                let exp_cid = convo_id_clone.clone();
                let req_recorder = pagination_requests_clone.clone();
                move |headers: axum::http::HeaderMap, axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>| {
                    let p1_c = p1.clone();
                    let p2_c = p2.clone();
                    let p3_c = p3.clone();
                    let p4_c = p4.clone();
                    let exp_c = exp_cid.clone();
                    let recorder = req_recorder.clone();
                    async move {
                        let auth_hdr = headers.get("authorization").and_then(|h| h.to_str().ok()).unwrap_or("");
                        if auth_hdr != "Bearer test-token" {
                            return axum::response::Response::builder()
                                .status(StatusCode::UNAUTHORIZED)
                                .header("content-type", "application/json")
                                .body(axum::body::Body::from(r#"{"error":"NotAuthorized","message":"invalid token"}"#))
                                .unwrap();
                        }
                        if params.get("convoId").map(|s| s.as_str()) != Some(&exp_c) {
                            return axum::response::Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .header("content-type", "application/json")
                                .body(axum::body::Body::from(r#"{"error":"InvalidRequest","message":"invalid convoId"}"#))
                                .unwrap();
                        }
                        let limit: i64 = match params.get("limit").and_then(|s| s.parse().ok()) {
                            Some(l) if l > 0 && l <= 500 => l,
                            _ => {
                                return axum::response::Response::builder()
                                    .status(StatusCode::BAD_REQUEST)
                                    .header("content-type", "application/json")
                                    .body(axum::body::Body::from(r#"{"error":"InvalidRequest","message":"invalid limit"}"#))
                                    .unwrap();
                            }
                        };
                        let from_seq: i64 = match params.get("afterSeq").or_else(|| params.get("fromSeqExclusive")).and_then(|s| s.parse().ok()) {
                            Some(s) => s,
                            None => {
                                return axum::response::Response::builder()
                                    .status(StatusCode::BAD_REQUEST)
                                    .header("content-type", "application/json")
                                    .body(axum::body::Body::from(r#"{"error":"InvalidRequest","message":"missing afterSeq"}"#))
                                    .unwrap();
                            }
                        };

                        let (events, to_seq) = if from_seq == 0 {
                            (p1_c, 130)
                        } else if from_seq == 130 {
                            (p2_c, 260)
                        } else if from_seq == 260 {
                            (p3_c, 390)
                        } else if from_seq == 390 {
                            (p4_c, 506)
                        } else {
                            return axum::response::Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .header("content-type", "application/json")
                                .body(axum::body::Body::from(r#"{"error":"InvalidRequest","message":"unexpected afterSeq"}"#))
                                .unwrap();
                        };

                        recorder.lock().await.push((from_seq, limit));

                        let payload = serde_json::json!({
                            "convoId": exp_c,
                            "fromSeqExclusive": from_seq,
                            "toSeqInclusive": to_seq,
                            "events": events
                        });
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(serde_json::to_vec(&payload).unwrap()))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.healthCheck",
            axum::routing::get(|| async {
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"status":"ok","capabilities":["reconciliation-v1","blue.catbird.mlsDS.reconciliation.v1"]}"#,
                    ))
                    .unwrap()
            }),
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

    let outbound = Arc::new(OutboundClient::new(2, 2));
    let auth_sign = Arc::new(move |_target: &str, _nsid: &str| Ok("test-token".to_string()));

    // Multi-pass reconciliation: bounded chunks applied per pass until convergence
    let mut passes = 0;
    loop {
        passes += 1;
        let res = catbird_server::federation::reconciliation::reconcile_conversation(
            &harness.pool,
            &resolver,
            &outbound,
            auth_sign.as_ref(),
            &convo_id_str,
            &harness.sequencer_ds_did,
        )
        .await;
        assert!(res.is_ok(), "pass {} failed: {:?}", passes, res);

        let current_sync: (String, i64) = sqlx::query_as(
            "SELECT status, last_seq FROM federation_sync_state WHERE convo_id = $1",
        )
        .bind(&convo_id_str)
        .fetch_one(&harness.pool)
        .await
        .unwrap();

        assert_eq!(current_sync.0, "healthy");
        if current_sync.1 == 506 {
            break;
        }
        assert!(
            passes < 50,
            "reconciliation exceeded 50 passes without converging"
        );
    }
    assert!(
        passes > 1,
        "reconciliation of 506 events must take multiple bounded passes, took {}",
        passes
    );

    // Verify exact authenticated pagination sequence
    let reqs = pagination_requests.lock().await.clone();
    assert_eq!(
        reqs,
        vec![
            (0, 500),
            (130, 500),
            (260, 500),
            (390, 500),
            (0, 500),
            (130, 500),
            (260, 500),
            (390, 500)
        ],
        "pagination requests must match exact two-pass chunked sequence"
    );
    let final_next_seq: i64 = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert_eq!(final_next_seq, 507, "next_entry_seq must advance to 507");

    // Suffix fidelity: verify all 505 suffix rows match full immutable fields in chat.entries and chat.message_sends
    let entry_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.entries WHERE conversation_id = $1")
            .bind(convo_id)
            .fetch_one(&harness.pool)
            .await
            .unwrap();
    assert_eq!(entry_count, 506);

    for item in &generated_suffix {
        assert_applied_suffix_entry_and_message_send_exact_fields(
            &harness.pool,
            convo_id,
            item.seq,
            item.msg_entry_id,
            item.msg_id,
            &alice,
            &item.ciphertext,
            &item.payload_sha256,
            &item.signed_req_bytes,
            &item.outer_fp,
            &item.transcript_bytes,
            &item.request_digest,
            &item.signature,
            now,
        )
        .await;
    }
}

#[tokio::test]
async fn test_reconciliation_inconsistent_remote_digest_gives_zero_writes_and_no_quarantine() {
    let harness = TestHarness::new("recon-inconsistent").await;
    let now = Utc::now();
    let convo_id = Uuid::new_v4();
    let group_id = vec![0x66u8; 32];
    let alice = TestActor::generate();
    alice.seed(&harness.pool, now).await;
    seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        0,
        &alice,
        Some(&harness.sender_ds_did),
        now,
    )
    .await;

    let local_row_1: CleanDigestRow = sqlx::query_as(
        "SELECT CAST(seq AS BIGINT) AS seq, CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
                entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, \
                signed_request_bytes, outer_entry_fingerprint, received_at \
         FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();

    // Advertised digest SHA does NOT match the events stream
    let convo_id_str = convo_id.to_string();
    let seq_did_clone = harness.sequencer_ds_did.clone();
    let digest_output = GetConvoDigestOutput {
        convo_id: convo_id_str.clone(),
        sequencer_ds_did: seq_did_clone.clone(),
        sequencer_term: 0,
        epoch: 0,
        last_seq: 1,
        event_count: 1,
        digest_sha256: "0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(), // Inconsistent!
        generated_at: now,
    };

    let events_output = serde_json::json!({
        "convoId": convo_id_str,
        "fromSeqExclusive": 0,
        "toSeqInclusive": 1,
        "events": [
            {
                "seq": 1,
                "epoch": local_row_1.epoch,
                "msgId": local_row_1.entry_id.to_string(),
                "messageType": local_row_1.entry_kind,
                "ciphertext": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_bytes)},
                "paddedSize": local_row_1.accepted_payload_bytes.len() as i64,
                "createdAt": local_row_1.received_at.to_rfc3339_opts(SecondsFormat::Millis, true),
                "entryId": local_row_1.entry_id.to_string(),
                "entryKind": local_row_1.entry_kind,
                "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_sha256)},
                "signedRequest": {"$bytes": STANDARD.encode(&local_row_1.signed_request_bytes)},
                "outerFingerprint": {"$bytes": STANDARD.encode(&local_row_1.outer_entry_fingerprint)}
            }
        ]
    });

    let app = axum::Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest",
            axum::routing::get({
                let d = serde_json::to_vec(&digest_output).unwrap();
                move || {
                    let b = d.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoEvents",
            axum::routing::get({
                let e = serde_json::to_vec(&events_output).unwrap();
                move || {
                    let b = e.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.healthCheck",
            axum::routing::get(|| async {
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"status":"ok","capabilities":["reconciliation-v1","blue.catbird.mlsDS.reconciliation.v1"]}"#,
                    ))
                    .unwrap()
            }),
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

    let outbound = Arc::new(OutboundClient::new(2, 2));
    let auth_sign = Arc::new(move |_target: &str, _nsid: &str| Ok("test-token".to_string()));

    let before = capture_mailbox_snapshot(&harness.pool).await;

    let res = catbird_server::federation::reconciliation::reconcile_conversation(
        &harness.pool,
        &resolver,
        &outbound,
        auth_sign.as_ref(),
        &convo_id_str,
        &harness.sequencer_ds_did,
    )
    .await;

    assert!(
        res.is_err(),
        "reconciliation must fail on inconsistent digest"
    );

    let sync_state: Option<(String,)> =
        sqlx::query_as("SELECT status FROM federation_sync_state WHERE convo_id = $1")
            .bind(&convo_id_str)
            .fetch_optional(&harness.pool)
            .await
            .unwrap();
    assert!(
        sync_state.is_none() || sync_state.unwrap().0 != "quarantined",
        "inconsistent remote snapshot must NOT quarantine"
    );

    let after = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(
        after, before,
        "inconsistent remote digest must leave all clean tables byte-for-byte unchanged"
    );
}

#[tokio::test]
async fn test_reconciliation_oversized_peer_page_gives_zero_writes_and_no_quarantine() {
    let harness = TestHarness::new("recon-oversized").await;
    let now = Utc::now();
    let convo_id = Uuid::new_v4();
    let group_id = vec![0x67u8; 32];
    let alice = TestActor::generate();
    alice.seed(&harness.pool, now).await;
    seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        0,
        &alice,
        Some(&harness.sender_ds_did),
        now,
    )
    .await;

    let local_row_1: CleanDigestRow = sqlx::query_as(
        "SELECT CAST(seq AS BIGINT) AS seq, CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
                entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, \
                signed_request_bytes, outer_entry_fingerprint, received_at \
         FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();

    // Generate 501 events in one page (> 500 limit)
    let mut oversized_events = Vec::with_capacity(501);
    oversized_events.push(serde_json::json!({
        "seq": 1,
        "epoch": local_row_1.epoch,
        "msgId": local_row_1.entry_id.to_string(),
        "messageType": local_row_1.entry_kind,
        "ciphertext": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_bytes)},
        "paddedSize": local_row_1.accepted_payload_bytes.len() as i64,
        "createdAt": local_row_1.received_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "entryId": local_row_1.entry_id.to_string(),
        "entryKind": local_row_1.entry_kind,
        "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_sha256)},
        "signedRequest": {"$bytes": STANDARD.encode(&local_row_1.signed_request_bytes)},
        "outerFingerprint": {"$bytes": STANDARD.encode(&local_row_1.outer_entry_fingerprint)}
    }));

    let mut hasher = catbird_server::handlers::ds::get_convo_digest::CleanConvoDigestHasher::new();
    hasher.update_row(&local_row_1);

    for seq in 2..=501 {
        let msg_id = Uuid::new_v4();
        let msg_entry_id = Uuid::new_v4();
        let ciphertext = vec![0x31u8; 8];
        let signed_req_bytes = vec![0x32u8; 8];
        let outer_fp = vec![0x33u8; 32];

        hasher.update_event(
            seq,
            0,
            msg_entry_id,
            "blue.catbird.chat.defs#applicationEntry",
            &ciphertext,
            &signed_req_bytes,
            &outer_fp,
            now,
        );

        let payload_sha256: [u8; 32] = Sha256::digest(&ciphertext).into();
        oversized_events.push(serde_json::json!({
            "seq": seq,
            "epoch": 0,
            "msgId": msg_id.to_string(),
            "messageType": "blue.catbird.chat.defs#applicationEntry",
            "ciphertext": {"$bytes": STANDARD.encode(&ciphertext)},
            "paddedSize": ciphertext.len() as i64,
            "createdAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
            "entryId": msg_entry_id.to_string(),
            "entryKind": "blue.catbird.chat.defs#applicationEntry",
            "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&payload_sha256)},
            "signedRequest": {"$bytes": STANDARD.encode(&signed_req_bytes)},
            "outerFingerprint": {"$bytes": STANDARD.encode(&outer_fp)}
        }));
    }
    let calculated_digest_sha256 = hasher.finalize();

    let convo_id_str = convo_id.to_string();
    let seq_did_clone = harness.sequencer_ds_did.clone();
    let digest_output = GetConvoDigestOutput {
        convo_id: convo_id_str.clone(),
        sequencer_ds_did: seq_did_clone.clone(),
        sequencer_term: 0,
        epoch: 0,
        last_seq: 501,
        event_count: 501,
        digest_sha256: calculated_digest_sha256,
        generated_at: now,
    };

    let events_output = serde_json::json!({
        "convoId": convo_id_str,
        "fromSeqExclusive": 0,
        "toSeqInclusive": 501,
        "events": oversized_events
    });

    let app = axum::Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest",
            axum::routing::get({
                let d = serde_json::to_vec(&digest_output).unwrap();
                move || {
                    let b = d.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoEvents",
            axum::routing::get({
                let e = serde_json::to_vec(&events_output).unwrap();
                move || {
                    let b = e.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.healthCheck",
            axum::routing::get(|| async {
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"status":"ok","capabilities":["reconciliation-v1","blue.catbird.mlsDS.reconciliation.v1"]}"#,
                    ))
                    .unwrap()
            }),
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

    let outbound = Arc::new(OutboundClient::new(2, 2));
    let auth_sign = Arc::new(move |_target: &str, _nsid: &str| Ok("test-token".to_string()));

    let before = capture_mailbox_snapshot(&harness.pool).await;

    let res = catbird_server::federation::reconciliation::reconcile_conversation(
        &harness.pool,
        &resolver,
        &outbound,
        auth_sign.as_ref(),
        &convo_id_str,
        &harness.sequencer_ds_did,
    )
    .await;

    let err = res.expect_err("reconciliation must fail on oversized peer page (>500 limit)");
    assert!(
        err.contains("events page exceeded requested limit: got 501, max 500"),
        "expected page limit error, got: {err}"
    );

    let sync_state: Option<(String,)> =
        sqlx::query_as("SELECT status FROM federation_sync_state WHERE convo_id = $1")
            .bind(&convo_id_str)
            .fetch_optional(&harness.pool)
            .await
            .unwrap();
    assert!(
        sync_state.is_none() || sync_state.unwrap().0 != "quarantined",
        "oversized peer page must NOT quarantine"
    );

    let after = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(
        after, before,
        "oversized peer page must leave all clean tables byte-for-byte unchanged"
    );
}

#[tokio::test]
async fn test_reconciliation_discontinuous_or_out_of_order_peer_page_gives_zero_writes_and_no_quarantine(
) {
    let harness = TestHarness::new("recon-discont").await;
    let now = Utc::now();
    let convo_id = Uuid::new_v4();
    let group_id = vec![0x68u8; 32];
    let alice = TestActor::generate();
    alice.seed(&harness.pool, now).await;
    seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        0,
        &alice,
        Some(&harness.sender_ds_did),
        now,
    )
    .await;

    let local_row_1: CleanDigestRow = sqlx::query_as(
        "SELECT CAST(seq AS BIGINT) AS seq, CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
                entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, \
                signed_request_bytes, outer_entry_fingerprint, received_at \
         FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();

    let msg_id_3 = Uuid::new_v4();
    let msg_entry_id_3 = Uuid::new_v4();
    let (_, signed_req_bytes_3) =
        make_message_body(convo_id, msg_id_3, &alice, &group_id, vec![], now);
    let mutation_3 =
        decode_and_verify_signed_mutation(&signed_req_bytes_3, &alice.public_key).unwrap();
    let received_at_3 = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&now.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
    );
    let built_3 = build_verified_application_entry(
        mutation_3,
        CanonicalUuidV4::parse(&msg_entry_id_3.to_string()).unwrap(),
        CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
        3, // Note seq 3 skipping seq 2!
        &received_at_3,
    )
    .unwrap();
    let ciphertext_3 = built_3.canonical_entry_bytes().to_vec();
    let payload_sha256_3 = built_3.accepted_payload_sha256().to_vec();
    let outer_fp_3 = built_3.outer_application_fingerprint().to_vec();
    let mut hasher = catbird_server::handlers::ds::get_convo_digest::CleanConvoDigestHasher::new();
    hasher.update_row(&local_row_1);
    hasher.update_event(
        3,
        0,
        msg_entry_id_3,
        "blue.catbird.chat.defs#applicationEntry",
        &ciphertext_3,
        &signed_req_bytes_3,
        &outer_fp_3,
        now,
    );
    let calculated_digest_sha256 = hasher.finalize();

    let convo_id_str = convo_id.to_string();
    let seq_did_clone = harness.sequencer_ds_did.clone();
    let digest_output = GetConvoDigestOutput {
        convo_id: convo_id_str.clone(),
        sequencer_ds_did: seq_did_clone.clone(),
        sequencer_term: 0,
        epoch: 0,
        last_seq: 3,
        event_count: 2,
        digest_sha256: calculated_digest_sha256,
        generated_at: now,
    };

    // Events page has sequence 1 followed by sequence 3 (discontinuous!)
    let events_output = serde_json::json!({
        "convoId": convo_id_str,
        "fromSeqExclusive": 0,
        "toSeqInclusive": 3,
        "events": [
            {
                "seq": 1,
                "epoch": local_row_1.epoch,
                "msgId": local_row_1.entry_id.to_string(),
                "messageType": local_row_1.entry_kind,
                "ciphertext": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_bytes)},
                "paddedSize": local_row_1.accepted_payload_bytes.len() as i64,
                "createdAt": local_row_1.received_at.to_rfc3339_opts(SecondsFormat::Millis, true),
                "entryId": local_row_1.entry_id.to_string(),
                "entryKind": local_row_1.entry_kind,
                "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_sha256)},
                "signedRequest": {"$bytes": STANDARD.encode(&local_row_1.signed_request_bytes)},
                "outerFingerprint": {"$bytes": STANDARD.encode(&local_row_1.outer_entry_fingerprint)}
            },
            {
                "seq": 3, // Discontinuous: expected 2, got 3
                "epoch": 0,
                "msgId": msg_id_3.to_string(),
                "messageType": "blue.catbird.chat.defs#applicationEntry",
                "ciphertext": {"$bytes": STANDARD.encode(&ciphertext_3)},
                "paddedSize": ciphertext_3.len() as i64,
                "createdAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
                "entryId": msg_entry_id_3.to_string(),
                "entryKind": "blue.catbird.chat.defs#applicationEntry",
                "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&payload_sha256_3)},
                "signedRequest": {"$bytes": STANDARD.encode(&signed_req_bytes_3)},
                "outerFingerprint": {"$bytes": STANDARD.encode(&outer_fp_3)}
            }
        ]
    });

    let app = axum::Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest",
            axum::routing::get({
                let d = serde_json::to_vec(&digest_output).unwrap();
                move || {
                    let b = d.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoEvents",
            axum::routing::get({
                let e = serde_json::to_vec(&events_output).unwrap();
                move || {
                    let b = e.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.healthCheck",
            axum::routing::get(|| async {
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"status":"ok","capabilities":["reconciliation-v1","blue.catbird.mlsDS.reconciliation.v1"]}"#,
                    ))
                    .unwrap()
            }),
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

    let outbound = Arc::new(OutboundClient::new(2, 2));
    let auth_sign = Arc::new(move |_target: &str, _nsid: &str| Ok("test-token".to_string()));

    let before = capture_mailbox_snapshot(&harness.pool).await;

    let res = catbird_server::federation::reconciliation::reconcile_conversation(
        &harness.pool,
        &resolver,
        &outbound,
        auth_sign.as_ref(),
        &convo_id_str,
        &harness.sequencer_ds_did,
    )
    .await;

    let err = res.expect_err("reconciliation must fail on discontinuous peer page");
    assert!(
        err.contains("events page sequence discontinuity: expected 2, got 3"),
        "expected sequence discontinuity error, got: {err}"
    );
    let sync_state: Option<(String,)> =
        sqlx::query_as("SELECT status FROM federation_sync_state WHERE convo_id = $1")
            .bind(&convo_id_str)
            .fetch_optional(&harness.pool)
            .await
            .unwrap();
    assert!(
        sync_state.is_none() || sync_state.unwrap().0 != "quarantined",
        "discontinuous peer page must NOT quarantine"
    );

    let after = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(
        after, before,
        "discontinuous peer page must leave all clean tables byte-for-byte unchanged"
    );
}

#[tokio::test]
async fn test_reconciliation_concurrent_local_head_movement_aborts_without_writes_or_quarantine() {
    let harness = TestHarness::new("recon-concur-head").await;
    let now = Utc::now();
    let convo_id = Uuid::new_v4();
    let group_id = vec![0x77u8; 32];
    let alice = TestActor::generate();
    alice.seed(&harness.pool, now).await;
    seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        0,
        &alice,
        None,
        now,
    )
    .await;

    let msg_id_2 = Uuid::new_v4();
    let msg_entry_id_2 = Uuid::new_v4();
    let (_, signed_req_bytes_2) =
        make_message_body(convo_id, msg_id_2, &alice, &group_id, vec![], now);
    let mutation_2 =
        decode_and_verify_signed_mutation(&signed_req_bytes_2, &alice.public_key).unwrap();
    let received_at_2 = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&now.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
    );
    let built_2 = build_verified_application_entry(
        mutation_2,
        CanonicalUuidV4::parse(&msg_entry_id_2.to_string()).unwrap(),
        CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
        2,
        &received_at_2,
    )
    .unwrap();
    let ciphertext_2 = built_2.canonical_entry_bytes().to_vec();
    let payload_sha256_2 = built_2.accepted_payload_sha256().to_vec();
    let outer_fp_2 = built_2.outer_application_fingerprint().to_vec();

    let local_row_1: CleanDigestRow = sqlx::query_as(
        "SELECT CAST(seq AS BIGINT) AS seq, CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
                entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, \
                signed_request_bytes, outer_entry_fingerprint, received_at \
         FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();

    let remote_row_2 = CleanDigestRow {
        seq: 2,
        epoch: 0,
        entry_id: msg_entry_id_2,
        entry_kind: "blue.catbird.chat.defs#applicationEntry".to_string(),
        accepted_payload_bytes: ciphertext_2.clone(),
        accepted_payload_sha256: payload_sha256_2.clone(),
        signed_request_bytes: signed_req_bytes_2.clone(),
        outer_entry_fingerprint: outer_fp_2.clone(),
        received_at: now,
    };

    let remote_rows = vec![
        CleanDigestRow {
            seq: local_row_1.seq,
            epoch: local_row_1.epoch,
            entry_id: local_row_1.entry_id,
            entry_kind: local_row_1.entry_kind.clone(),
            accepted_payload_bytes: local_row_1.accepted_payload_bytes.clone(),
            accepted_payload_sha256: local_row_1.accepted_payload_sha256.clone(),
            signed_request_bytes: local_row_1.signed_request_bytes.clone(),
            outer_entry_fingerprint: local_row_1.outer_entry_fingerprint.clone(),
            received_at: local_row_1.received_at,
        },
        remote_row_2,
    ];
    let remote_digest_sha256 = compute_clean_convo_digest(&remote_rows);

    let convo_id_str = convo_id.to_string();
    let seq_did_clone = harness.sequencer_ds_did.clone();
    let digest_output = GetConvoDigestOutput {
        convo_id: convo_id_str.clone(),
        sequencer_ds_did: seq_did_clone.clone(),
        sequencer_term: 0,
        epoch: 0,
        last_seq: 2,
        event_count: 2,
        digest_sha256: remote_digest_sha256.clone(),
        generated_at: now,
    };

    let events_output = serde_json::json!({
        "convoId": convo_id_str,
        "fromSeqExclusive": 0,
        "toSeqInclusive": 2,
        "events": [
            {
                "seq": 1,
                "epoch": local_row_1.epoch,
                "msgId": local_row_1.entry_id.to_string(),
                "messageType": local_row_1.entry_kind,
                "ciphertext": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_bytes)},
                "paddedSize": local_row_1.accepted_payload_bytes.len() as i64,
                "createdAt": local_row_1.received_at.to_rfc3339_opts(SecondsFormat::Millis, true),
                "entryId": local_row_1.entry_id.to_string(),
                "entryKind": local_row_1.entry_kind,
                "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&local_row_1.accepted_payload_sha256)},
                "signedRequest": {"$bytes": STANDARD.encode(&local_row_1.signed_request_bytes)},
                "outerFingerprint": {"$bytes": STANDARD.encode(&local_row_1.outer_entry_fingerprint)}
            },
            {
                "seq": 2,
                "epoch": 0,
                "msgId": msg_id_2.to_string(),
                "messageType": "blue.catbird.chat.defs#applicationEntry",
                "ciphertext": {"$bytes": STANDARD.encode(&ciphertext_2)},
                "paddedSize": ciphertext_2.len() as i64,
                "createdAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
                "entryId": msg_entry_id_2.to_string(),
                "entryKind": "blue.catbird.chat.defs#applicationEntry",
                "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&payload_sha256_2)},
                "signedRequest": {"$bytes": STANDARD.encode(&signed_req_bytes_2)},
                "outerFingerprint": {"$bytes": STANDARD.encode(&outer_fp_2)}
            }
        ]
    });

    let delivery_id_c = Uuid::new_v4();
    let mut header_model_c = ValidatedEnvelopeHeader {
        protocol_version: "1".to_string(),
        delivery_id: delivery_id_c,
        conversation_id: convo_id,
        sender_ds_did: harness.sequencer_ds_did.clone(),
        receiver_ds_did: LOCAL_DS_DID.to_string(),
        sequencer_did: harness.sequencer_ds_did.clone(),
        sequencer_term: 0,
        received_at: catbird_server::chat_protocol::test_support::CanonicalTimestamp::parse(
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
        )
        .unwrap(),
        payload_sha256: [0u8; 32],
    };
    let locator_model_c = ValidatedEntryLocator {
        entry_id: msg_entry_id_2,
        seq: 2,
        accepted_payload_sha256: *built_2.accepted_payload_sha256(),
        outer_entry_fingerprint: *built_2.outer_application_fingerprint(),
    };
    let msg_digest_c = compute_message_envelope_digest(
        &header_model_c,
        &alice.did,
        &locator_model_c,
        &ciphertext_2,
        &signed_req_bytes_2,
    )
    .unwrap();
    header_model_c.payload_sha256 = msg_digest_c;

    let deliver_msg_body_c = json!({
        "header": make_envelope_header_json(
            delivery_id_c,
            convo_id,
            &harness.sequencer_ds_did,
            LOCAL_DS_DID,
            &harness.sequencer_ds_did,
            0,
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
            &msg_digest_c,
        ),
        "entryLocator": make_entry_locator_json(msg_entry_id_2, 2, built_2.accepted_payload_sha256(), built_2.outer_application_fingerprint()),
        "recipientDid": alice.did,
        "entryBytes": { "$bytes": STANDARD.encode(&ciphertext_2) },
        "signedRequestBytes": { "$bytes": STANDARD.encode(&signed_req_bytes_2) },
    });
    let jwt_c = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        DELIVER_MESSAGE_NSID,
    );

    let router_for_hook = harness.router.clone();
    let app = axum::Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest",
            axum::routing::get({
                let d = serde_json::to_vec(&digest_output).unwrap();
                move || {
                    let b = d.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoEvents",
            axum::routing::get({
                let events_bytes = serde_json::to_vec(&events_output).unwrap();
                let shared_ctx = Arc::new((
                    router_for_hook,
                    jwt_c,
                    deliver_msg_body_c,
                    events_bytes,
                ));
                move || {
                    let ctx = shared_ctx.clone();
                    async move {
                        // Concurrent local entry insertion through the production router during events fetch!
                        let (r, jwt_h, deliver_body_h, b) = &*ctx;
                        let (status, body, _) = send_json_to_router(
                            r,
                            "/xrpc/blue.catbird.mlsDS.deliverMessage",
                            Some(jwt_h),
                            deliver_body_h,
                        )
                        .await;
                        assert_eq!(
                            status,
                            StatusCode::OK,
                            "concurrent deliverMessage via production router must succeed: {body:?}"
                        );

                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b.clone()))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.healthCheck",
            axum::routing::get(|| async {
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"status":"ok","capabilities":["reconciliation-v1","blue.catbird.mlsDS.reconciliation.v1"]}"#,
                    ))
                    .unwrap()
            }),
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

    let outbound = Arc::new(OutboundClient::new(2, 2));
    let auth_sign = Arc::new(move |_target: &str, _nsid: &str| Ok("test-token".to_string()));

    let res = catbird_server::federation::reconciliation::reconcile_conversation(
        &harness.pool,
        &resolver,
        &outbound,
        auth_sign.as_ref(),
        &convo_id_str,
        &harness.sequencer_ds_did,
    )
    .await;

    assert!(
        res.is_err(),
        "reconciliation must fail retryably on concurrent local head movement: {:?}",
        res
    );
    assert!(
        res.unwrap_err().contains("concurrent local head movement"),
        "expected concurrent local head movement error"
    );

    let sync_state: Option<(String,)> =
        sqlx::query_as("SELECT status FROM federation_sync_state WHERE convo_id = $1")
            .bind(&convo_id_str)
            .fetch_optional(&harness.pool)
            .await
            .unwrap();
    assert!(
        sync_state.is_none() || sync_state.unwrap().0 != "quarantined",
        "concurrent local head movement must not quarantine"
    );
}

#[tokio::test]
async fn test_reconciliation_sticky_quarantine_is_retained_across_later_reconciliations() {
    let harness = TestHarness::new("recon-sticky").await;
    let now = Utc::now();
    let convo_id = Uuid::new_v4();
    let group_id = vec![0x88u8; 32];
    let alice = TestActor::generate();
    alice.seed(&harness.pool, now).await;
    seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        0,
        &alice,
        Some(&harness.sender_ds_did),
        now,
    )
    .await;

    let convo_id_str = convo_id.to_string();
    // Manually install initial quarantine
    sqlx::query(
        r#"
        INSERT INTO federation_sync_state
            (convo_id, sequencer_ds_did, sequencer_term, last_seq, last_epoch, last_digest, last_reconciled_at, drift_count, updated_at, status, quarantined_at, quarantine_reason, first_mismatch_seq)
        VALUES ($1, $2, 0, 1, 0, '\x00', NOW(), 1, NOW(), 'quarantined', NOW(), 'prefix_mismatch', 2)
        "#,
    )
    .bind(&convo_id_str)
    .bind(&harness.sequencer_ds_did)
    .execute(&harness.pool)
    .await
    .unwrap();

    let local_row_1: CleanDigestRow = sqlx::query_as(
        "SELECT CAST(seq AS BIGINT) AS seq, CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
                entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, \
                signed_request_bytes, outer_entry_fingerprint, received_at \
         FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();

    let remote_rows = vec![local_row_1.clone()];
    let remote_digest_sha256 = compute_clean_convo_digest(&remote_rows);

    let seq_did_clone = harness.sequencer_ds_did.clone();
    let digest_output = GetConvoDigestOutput {
        convo_id: convo_id_str.clone(),
        sequencer_ds_did: seq_did_clone.clone(),
        sequencer_term: 0,
        epoch: 0,
        last_seq: 1,
        event_count: 1,
        digest_sha256: remote_digest_sha256.clone(),
        generated_at: now,
    };

    let app = axum::Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest",
            axum::routing::get({
                let d = serde_json::to_vec(&digest_output).unwrap();
                move || {
                    let b = d.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(b))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.healthCheck",
            axum::routing::get(|| async {
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"status":"ok","capabilities":["reconciliation-v1","blue.catbird.mlsDS.reconciliation.v1"]}"#,
                    ))
                    .unwrap()
            }),
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

    let outbound = Arc::new(OutboundClient::new(2, 2));
    let auth_sign = Arc::new(move |_target: &str, _nsid: &str| Ok("test-token".to_string()));

    let _ = catbird_server::federation::reconciliation::reconcile_conversation(
        &harness.pool,
        &resolver,
        &outbound,
        auth_sign.as_ref(),
        &convo_id_str,
        &harness.sequencer_ds_did,
    )
    .await;

    // Status MUST remain quarantined
    let sync_state: (String, Option<String>, Option<i64>) = sqlx::query_as(
        "SELECT status, quarantine_reason, first_mismatch_seq FROM federation_sync_state WHERE convo_id = $1",
    )
    .bind(&convo_id_str)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert_eq!(sync_state.0, "quarantined", "quarantine must be sticky");
    assert_eq!(sync_state.1.as_deref(), Some("prefix_mismatch"));
    assert_eq!(sync_state.2, Some(2));
}

#[tokio::test]
async fn test_quarantined_conversation_rejects_all_shared_writers_with_generic_conflicts() {
    let harness = TestHarness::new("recon-writer-reject").await;
    let now = Utc::now();
    let convo_id = Uuid::new_v4();
    let group_id = vec![0x99u8; 32];

    let creator = TestActor::generate();
    creator.seed(&harness.pool, now).await;

    let mut recipient = TestActor::generate();
    recipient.did = creator.did.clone();
    recipient.seed(&harness.pool, now).await;

    let (creation_transition_id, _, _, _, _, _) = seed_conversation_structure(
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

    let creator_p256 = random_p256();
    cache_did_key(&creator.did, &creator_p256).await;

    let mint_client_jwt = |endpoint_nsid: &str| {
        let now_ts = Utc::now().timestamp();
        sign_jwt(
            json!({"alg":"ES256","typ":"JWT","kid":format!("{}#atproto", creator.did)}),
            json!({
                "iss": creator.did,
                "sub": creator.did,
                "aud": AUDIENCE,
                "lxm": endpoint_nsid,
                "iat": now_ts,
                "exp": now_ts + 60,
                "jti": Uuid::new_v4().to_string(),
            }),
            &creator_p256,
        )
    };

    // Seed welcome provenance tables so deliverWelcome passes provenance checks and tests the quarantine gate
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
    let public_snapshot_sha256: [u8; 32] = Sha256::digest(&public_snapshot_bytes).into();
    let (_, signed_req_bytes_w) = make_leaf_recovery_fulfillment_body(
        convo_id,
        fulfillment_transition_id,
        recovery_request_id,
        creation_transition_id,
        &creator,
        &group_id,
        now,
    );
    let mutation_w =
        decode_and_verify_signed_mutation(&signed_req_bytes_w, &creator.public_key).unwrap();
    let rec_at_w = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&now.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
    );
    let endpoint_w = ValidatedChatNsid::parse("blue.catbird.chat.submitTransition").unwrap();
    let s_fields_w =
        CanonicalControlServerFields::empty(ControlEntryKind::LeafRecoveryFulfillment).unwrap();
    let built_w = build_verified_control_entry(
        mutation_w,
        &endpoint_w,
        CanonicalUuidV4::parse(&fulfillment_entry_id.to_string()).unwrap(),
        CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
        2,
        &rec_at_w,
        s_fields_w,
    )
    .unwrap();
    let products_w = CanonicalControlEntryProducts::mint(&built_w).unwrap();
    let entry_bytes_w = products_w.durable_json().to_vec();
    let entry_sha256_w: [u8; 32] = Sha256::digest(&entry_bytes_w).into();
    let outer_fp_w = *built_w.outer_control_fingerprint();

    let mut tx_w = harness.pool.begin().await.unwrap();
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *tx_w)
        .await
        .unwrap();
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
    .execute(&mut *tx_w)
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
    .execute(&mut *tx_w)
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
    .execute(&mut *tx_w)
    .await
    .unwrap();

    let meta_snap_id = Uuid::new_v4();
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
    .bind(meta_snap_id)
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
    .execute(&mut *tx_w)
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
    .bind(&signed_req_bytes_w)
    .bind(built_w.mutation().canonical_projection())
    .bind(built_w.mutation().transcript_bytes())
    .bind(built_w.mutation().request_digest().as_slice())
    .bind(built_w.mutation().signature().as_slice())
    .bind(meta_snap_id)
    .bind(now)
    .execute(&mut *tx_w)
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
    .bind(&entry_bytes_w)
    .bind(&entry_sha256_w[..])
    .bind(&signed_req_bytes_w)
    .bind(built_w.mutation().request_digest().as_slice())
    .bind(built_w.mutation().signature().as_slice())
    .bind(&outer_fp_w[..])
    .bind(&creator.did)
    .bind(creator.device_id)
    .bind(&creator.key_id)
    .bind(fulfillment_transition_id)
    .bind(now)
    .execute(&mut *tx_w)
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
    .execute(&mut *tx_w)
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
    .execute(&mut *tx_w)
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
    .execute(&mut *tx_w)
    .await
    .unwrap();

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
    .execute(&mut *tx_w)
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
    .bind(&outer_fp_w[..])
    .bind(&group_id)
    .bind(&[0x32u8; 32])
    .bind(recipient_leaf_id)
    .bind(now)
    .execute(&mut *tx_w)
    .await
    .unwrap();

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
    .execute(&mut *tx_w)
    .await
    .unwrap();

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
    .execute(&mut *tx_w)
    .await
    .unwrap();

    tx_w.commit().await.unwrap();

    // Quarantine the conversation
    sqlx::query(
        r#"
        INSERT INTO federation_sync_state
            (convo_id, sequencer_ds_did, sequencer_term, last_seq, last_epoch, last_digest, last_reconciled_at, drift_count, updated_at, status, quarantined_at, quarantine_reason, first_mismatch_seq)
        VALUES ($1, $2, 1, 2, 0, '\x00', NOW(), 1, NOW(), 'quarantined', NOW(), 'prefix_mismatch', 3)
        "#,
    )
    .bind(convo_id.to_string())
    .bind(&harness.sequencer_ds_did)
    .execute(&harness.pool)
    .await
    .unwrap();

    let before = capture_mailbox_snapshot(&harness.pool).await;
    // 1. DS deliverMessage against quarantined conversation -> 409 DeliveryConflict
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
        3,
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
        received_at: catbird_server::chat_protocol::test_support::CanonicalTimestamp::parse(
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
        )
        .unwrap(),
        payload_sha256: [0u8; 32],
    };
    let locator_model = ValidatedEntryLocator {
        entry_id: msg_entry_id,
        seq: 3,
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

    let deliver_msg_body = json!({
        "header": make_envelope_header_json(
            delivery_id,
            convo_id,
            &harness.sequencer_ds_did,
            LOCAL_DS_DID,
            &harness.sequencer_ds_did,
            1,
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
            &msg_digest,
        ),
        "entryLocator": make_entry_locator_json(msg_entry_id, 3, &entry_sha256, &outer_fp),
        "recipientDid": recipient.did,
        "entryBytes": { "$bytes": STANDARD.encode(&entry_bytes) },
        "signedRequestBytes": { "$bytes": STANDARD.encode(&signed_req_bytes) },
    });
    let jwt_ds_msg = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        DELIVER_MESSAGE_NSID,
    );
    let (status, body, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverMessage",
            Some(&jwt_ds_msg),
            &deliver_msg_body,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"].as_str(), Some("DeliveryConflict"));

    // 2. DS deliverWelcome against quarantined conversation -> 409 DeliveryConflict
    let mut header_model_w = ValidatedEnvelopeHeader {
        protocol_version: "1".to_string(),
        delivery_id: Uuid::new_v4(),
        conversation_id: convo_id,
        sender_ds_did: harness.sequencer_ds_did.clone(),
        receiver_ds_did: LOCAL_DS_DID.to_string(),
        sequencer_did: harness.sequencer_ds_did.clone(),
        sequencer_term: 1,
        received_at: catbird_server::chat_protocol::test_support::CanonicalTimestamp::parse(
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
        )
        .unwrap(),
        payload_sha256: [0u8; 32],
    };
    let locator_model_w = ValidatedEntryLocator {
        entry_id: fulfillment_entry_id,
        seq: 2,
        accepted_payload_sha256: entry_sha256_w,
        outer_entry_fingerprint: outer_fp_w,
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
        &header_model_w,
        &recipient.did,
        recipient.device_id,
        welcome_id,
        recovery_request_id,
        &key_package_ref,
        &welcome_bytes,
        &welcome_sha256,
        &entry_bytes_w,
        &signed_req_bytes_w,
        &locator_model_w,
        &coordinates_dto,
        &public_snapshot_sha256,
        &tree_summary_sha256,
    )
    .unwrap();
    header_model_w.payload_sha256 = welcome_digest;
    let coordinates_json = make_coordinates_json(convo_id, &group_id, 1, 1);
    let deliver_welcome_body = json!({
        "header": make_envelope_header_json(
            header_model_w.delivery_id,
            convo_id,
            &harness.sequencer_ds_did,
            LOCAL_DS_DID,
            &harness.sequencer_ds_did,
            1,
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
            &welcome_digest,
        ),
        "entryLocator": make_entry_locator_json(fulfillment_entry_id, 2, &entry_sha256_w, &outer_fp_w),
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
        "entryBytes": { "$bytes": STANDARD.encode(&entry_bytes_w) },
        "signedRequestBytes": { "$bytes": STANDARD.encode(&signed_req_bytes_w) },
    });
    let jwt_ds_w = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        DELIVER_WELCOME_NSID,
    );
    let (status_w, body_w, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverWelcome",
            Some(&jwt_ds_w),
            &deliver_welcome_body,
        )
        .await;
    assert_eq!(
        status_w,
        StatusCode::CONFLICT,
        "deliverWelcome failed: {body_w:?}"
    );
    assert_eq!(body_w["error"].as_str(), Some("DeliveryConflict"));

    // 3. Client sendMessage against quarantined conversation -> 409 IdempotencyConflict
    let client_msg_id = Uuid::new_v4();
    let (client_msg_body, _) = make_message_body_with_coordinates(
        convo_id,
        client_msg_id,
        &creator,
        &group_id,
        1,
        1,
        &[0x32u8; 32],
        &[0x32u8; 32],
        vec![],
        now,
    );
    let jwt_send = mint_client_jwt("blue.catbird.chat.sendMessage");
    let (status_send, body_send, _) = send_json_to_router(
        &harness.router,
        "/xrpc/blue.catbird.chat.sendMessage",
        Some(&jwt_send),
        &json!({ "signedRequest": client_msg_body }),
    )
    .await;
    assert_eq!(
        status_send,
        StatusCode::BAD_REQUEST,
        "sendMessage failed: {body_send:?}"
    );
    assert_eq!(body_send["error"].as_str(), Some("IdempotencyConflict"));

    // 4. Client publishTyping against quarantined conversation -> 409 IdempotencyConflict
    let typing_id = Uuid::new_v4();
    let (typing_body, _) = make_typing_body(
        convo_id,
        typing_id,
        &creator,
        &group_id,
        1,
        1,
        &[0x32u8; 32],
        &[0x32u8; 32],
        now,
    );
    let jwt_typing = mint_client_jwt("blue.catbird.chat.publishTyping");
    let (status_typing, body_typing, _) = send_json_to_router(
        &harness.router,
        "/xrpc/blue.catbird.chat.publishTyping",
        Some(&jwt_typing),
        &json!({ "signedRequest": typing_body }),
    )
    .await;
    assert_eq!(
        status_typing,
        StatusCode::BAD_REQUEST,
        "publishTyping failed: {body_typing:?}"
    );
    assert_eq!(body_typing["error"].as_str(), Some("IdempotencyConflict"));

    // 5. Client acceptConversation against quarantined conversation -> 409 StaleCoordinates
    let acc_tr_id = Uuid::new_v4();
    let rec_req_id = Uuid::new_v4();
    let (acc_body, _) = make_acceptance_body(
        convo_id,
        acc_tr_id,
        rec_req_id,
        creation_transition_id,
        &creator,
        &creator,
        &group_id,
        &[0x32u8; 32],
        &[0x32u8; 32],
        now,
    );
    let jwt_acc = mint_client_jwt("blue.catbird.chat.acceptConversation");
    let (status_acc, body_acc, _) = send_json_to_router(
        &harness.router,
        "/xrpc/blue.catbird.chat.acceptConversation",
        Some(&jwt_acc),
        &json!({ "signedRequest": acc_body }),
    )
    .await;
    assert_eq!(
        status_acc,
        StatusCode::BAD_REQUEST,
        "acceptConversation failed: {body_acc:?}"
    );
    assert_eq!(body_acc["error"].as_str(), Some("StaleCoordinates"));

    // 6. Client requestLeave against quarantined conversation -> 409 StaleCoordinates
    let leave_id = Uuid::new_v4();
    let (leave_body, _) = make_leave_request_body(
        convo_id,
        leave_id,
        &creator,
        &group_id,
        1,
        1,
        &[0x32u8; 32],
        &[0x32u8; 32],
        now,
    );
    let jwt_leave = mint_client_jwt("blue.catbird.chat.requestLeave");
    let (status_leave, body_leave, _) = send_json_to_router(
        &harness.router,
        "/xrpc/blue.catbird.chat.requestLeave",
        Some(&jwt_leave),
        &json!({ "signedRequest": leave_body }),
    )
    .await;
    assert_eq!(
        status_leave,
        StatusCode::BAD_REQUEST,
        "requestLeave failed: {body_leave:?}"
    );
    assert_eq!(body_leave["error"].as_str(), Some("StaleCoordinates"));

    // 7. Client revokeDevice against quarantined conversation -> 409 IdempotencyConflict
    let (revoke_body, _) = make_device_revocation_body(&creator, creator.device_id, now);
    let jwt_revoke = mint_client_jwt("blue.catbird.chat.revokeDevice");
    let (status_revoke, body_revoke, _) = send_json_to_router(
        &harness.router,
        "/xrpc/blue.catbird.chat.revokeDevice",
        Some(&jwt_revoke),
        &json!({ "signedRequest": revoke_body }),
    )
    .await;
    assert_eq!(
        status_revoke,
        StatusCode::BAD_REQUEST,
        "revokeDevice failed: {body_revoke:?}"
    );
    assert_eq!(body_revoke["error"].as_str(), Some("IdempotencyConflict"));

    // 8. Client acknowledgeWelcome against quarantined conversation -> 409 AcknowledgementConflict
    let ack_welcome_id = Uuid::new_v4();
    let (ack_body, _) = make_welcome_acknowledgement_body(
        convo_id,
        ack_welcome_id,
        2,
        &creator,
        &group_id,
        1,
        1,
        &[0x32u8; 32],
        &[0x32u8; 32],
        now,
    );
    let jwt_ack = mint_client_jwt("blue.catbird.chat.acknowledgeWelcome");
    let (status_ack, body_ack, _) = send_json_to_router(
        &harness.router,
        "/xrpc/blue.catbird.chat.acknowledgeWelcome",
        Some(&jwt_ack),
        &json!({ "signedRequest": ack_body }),
    )
    .await;
    assert_eq!(
        status_ack,
        StatusCode::BAD_REQUEST,
        "acknowledgeWelcome failed: {body_ack:?}"
    );
    assert_eq!(body_ack["error"].as_str(), Some("AcknowledgementConflict"));
    // 9. GET getConvoDigest against quarantined conversation -> 409 DeliveryConflict
    let digest_jwt = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        "blue.catbird.mlsDS.getConvoDigest",
    );
    let req_d = Request::builder()
        .method("GET")
        .uri(format!(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest?convoId={}",
            convo_id
        ))
        .header("authorization", format!("Bearer {digest_jwt}"))
        .body(Body::empty())
        .unwrap();
    let resp_d = harness.router.clone().oneshot(req_d).await.unwrap();
    assert_eq!(resp_d.status(), StatusCode::CONFLICT);

    // 10. GET getConvoEvents against quarantined conversation -> 409 DeliveryConflict
    let events_jwt = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        "blue.catbird.mlsDS.getConvoEvents",
    );
    let req_e = Request::builder()
        .method("GET")
        .uri(format!(
            "/xrpc/blue.catbird.mlsDS.getConvoEvents?convoId={}&fromSeqExclusive=0",
            convo_id
        ))
        .header("authorization", format!("Bearer {events_jwt}"))
        .body(Body::empty())
        .unwrap();
    let resp_e = harness.router.clone().oneshot(req_e).await.unwrap();
    assert_eq!(resp_e.status(), StatusCode::CONFLICT);

    // Full mailbox state must be byte-for-byte unchanged after all rejected calls
    let after = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(
        after, before,
        "quarantined conversation must reject all shared writers and readers with generic conflicts while preserving state byte-for-byte"
    );
}

#[tokio::test]
async fn test_ds_delivery_replay_cannot_bypass_quarantine() {
    let harness = TestHarness::new("recon-replay-quar").await;
    let now = Utc::now();
    let convo_id = Uuid::new_v4();
    let group_id = vec![0xAAu8; 32];
    let creator = TestActor::generate();
    creator.seed(&harness.pool, now).await;

    let mut recipient = TestActor::generate();
    recipient.did = creator.did.clone();
    recipient.seed(&harness.pool, now).await;

    let (creation_transition_id, _, _, _, _, _) = seed_conversation_structure(
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
    let actor = TestActor::generate();
    actor.seed(&harness.pool, now).await;

    // A. Setup deliverMessage
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
        received_at: catbird_server::chat_protocol::test_support::CanonicalTimestamp::parse(
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
        )
        .unwrap(),
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

    let deliver_msg_body = json!({
        "header": make_envelope_header_json(
            delivery_id,
            convo_id,
            &harness.sequencer_ds_did,
            LOCAL_DS_DID,
            &harness.sequencer_ds_did,
            1,
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
            &msg_digest,
        ),
        "entryLocator": make_entry_locator_json(msg_entry_id, 2, &entry_sha256, &outer_fp),
        "recipientDid": recipient.did,
        "entryBytes": { "$bytes": STANDARD.encode(&entry_bytes) },
        "signedRequestBytes": { "$bytes": STANDARD.encode(&signed_req_bytes) },
    });
    let jwt_msg = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        DELIVER_MESSAGE_NSID,
    );

    // 1. Initial message delivery succeeds and records delivery receipt
    let (status1, _, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverMessage",
            Some(&jwt_msg),
            &deliver_msg_body,
        )
        .await;
    assert_eq!(status1, StatusCode::OK);

    // B. Setup deliverWelcome at seq 3
    let welcome_id = Uuid::new_v4();
    let recovery_request_id = Uuid::new_v4();
    let fulfillment_transition_id = Uuid::new_v4();
    let fulfillment_entry_id = fulfillment_transition_id;
    let welcome_bytes = corpus_file("welcome.mls");
    let welcome_sha256: [u8; 32] = Sha256::digest(&welcome_bytes).into();
    let manifest_bytes = corpus_file("manifest.json");
    let manifest: Value = serde_json::from_slice(&manifest_bytes).expect("parse manifest.json");
    let key_package_ref = hex_array(manifest["chain"]["innerKeyPackageRefHex"].as_str().unwrap());
    let public_snapshot_bytes = vec![0x88u8; 16];
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
    let public_snapshot_sha256: [u8; 32] = Sha256::digest(&public_snapshot_bytes).into();
    let (_, signed_req_bytes_w) = make_leaf_recovery_fulfillment_body(
        convo_id,
        fulfillment_transition_id,
        recovery_request_id,
        creation_transition_id,
        &creator,
        &group_id,
        now,
    );
    let mutation_w =
        decode_and_verify_signed_mutation(&signed_req_bytes_w, &creator.public_key).unwrap();
    let rec_at_w = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse(&now.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
    );
    let endpoint_w = ValidatedChatNsid::parse("blue.catbird.chat.submitTransition").unwrap();
    let s_fields_w =
        CanonicalControlServerFields::empty(ControlEntryKind::LeafRecoveryFulfillment).unwrap();
    let built_w = build_verified_control_entry(
        mutation_w,
        &endpoint_w,
        CanonicalUuidV4::parse(&fulfillment_entry_id.to_string()).unwrap(),
        CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
        3,
        &rec_at_w,
        s_fields_w,
    )
    .unwrap();
    let products_w = CanonicalControlEntryProducts::mint(&built_w).unwrap();
    let entry_bytes_w = products_w.durable_json().to_vec();
    let entry_sha256_w: [u8; 32] = Sha256::digest(&entry_bytes_w).into();
    let outer_fp_w = *built_w.outer_control_fingerprint();
    let mut tx_w = harness.pool.begin().await.unwrap();
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *tx_w)
        .await
        .unwrap();
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
    .execute(&mut *tx_w)
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
    .execute(&mut *tx_w)
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
    .execute(&mut *tx_w)
    .await
    .unwrap();
    let meta_snap_id = Uuid::new_v4();
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
    .bind(meta_snap_id)
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
    .execute(&mut *tx_w)
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
            0, 0, 0, 1, $11, 3, $12
        )
        "#,
    )
    .bind(fulfillment_transition_id)
    .bind(convo_id)
    .bind(&creator.did)
    .bind(creator.device_id)
    .bind(&creator.key_id)
    .bind(&signed_req_bytes_w)
    .bind(built_w.mutation().canonical_projection())
    .bind(built_w.mutation().transcript_bytes())
    .bind(built_w.mutation().request_digest().as_slice())
    .bind(built_w.mutation().signature().as_slice())
    .bind(meta_snap_id)
    .bind(now)
    .execute(&mut *tx_w)
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
            $1, 3, $2, 'blue.catbird.chat.defs#leafRecoveryFulfillmentEntry',
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
    .bind(&entry_bytes_w)
    .bind(&entry_sha256_w[..])
    .bind(&signed_req_bytes_w)
    .bind(built_w.mutation().request_digest().as_slice())
    .bind(built_w.mutation().signature().as_slice())
    .bind(&outer_fp_w[..])
    .bind(&creator.did)
    .bind(creator.device_id)
    .bind(&creator.key_id)
    .bind(fulfillment_transition_id)
    .bind(now)
    .execute(&mut *tx_w)
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
    .execute(&mut *tx_w)
    .await
    .unwrap();

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
            $8, 1, $9, 3, TRUE, $10
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
    .execute(&mut *tx_w)
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
            3, 'add', $5, $6,
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
    .bind(&outer_fp_w[..])
    .bind(&group_id)
    .bind(&[0x32u8; 32])
    .bind(recipient_leaf_id)
    .bind(now)
    .execute(&mut *tx_w)
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
    .execute(&mut *tx_w)
    .await
    .unwrap();

    sqlx::query(
        r#"
        UPDATE chat.conversations
           SET current_state_version = 1,
               next_entry_seq = 4
         WHERE conversation_id = $1
        "#,
    )
    .bind(convo_id)
    .execute(&mut *tx_w)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO chat.welcome_bundles (
            welcome_id, conversation_id, transition_id, entry_seq, generation, state_version,
            group_id, epoch, group_context_hash, confirmation_tag,
            wrapper_bytes, wrapper_sha256, created_at
        ) VALUES (
            $1, $2, $3, 3, 0, 1,
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
    .execute(&mut *tx_w)
    .await
    .unwrap();

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
    .execute(&mut *tx_w)
    .await
    .unwrap();

    tx_w.commit().await.unwrap();

    let mut header_model_w = ValidatedEnvelopeHeader {
        protocol_version: "1".to_string(),
        delivery_id: Uuid::new_v4(),
        conversation_id: convo_id,
        sender_ds_did: harness.sequencer_ds_did.clone(),
        receiver_ds_did: LOCAL_DS_DID.to_string(),
        sequencer_did: harness.sequencer_ds_did.clone(),
        sequencer_term: 1,
        received_at: catbird_server::chat_protocol::test_support::CanonicalTimestamp::parse(
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
        )
        .unwrap(),
        payload_sha256: [0u8; 32],
    };
    let locator_model_w = ValidatedEntryLocator {
        entry_id: fulfillment_entry_id,
        seq: 3,
        accepted_payload_sha256: entry_sha256_w,
        outer_entry_fingerprint: outer_fp_w,
    };
    let coordinates_dto_w = ConversationCoordinates {
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
        &header_model_w,
        &recipient.did,
        recipient.device_id,
        welcome_id,
        recovery_request_id,
        &key_package_ref,
        &welcome_bytes,
        &welcome_sha256,
        &entry_bytes_w,
        &signed_req_bytes_w,
        &locator_model_w,
        &coordinates_dto_w,
        &public_snapshot_sha256,
        &tree_summary_sha256,
    )
    .unwrap();
    header_model_w.payload_sha256 = welcome_digest;
    let coordinates_json = make_coordinates_json(convo_id, &group_id, 1, 1);
    let deliver_welcome_body = json!({
        "header": make_envelope_header_json(
            header_model_w.delivery_id,
            convo_id,
            &harness.sequencer_ds_did,
            LOCAL_DS_DID,
            &harness.sequencer_ds_did,
            1,
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
            &welcome_digest,
        ),
        "entryLocator": make_entry_locator_json(fulfillment_entry_id, 3, &entry_sha256_w, &outer_fp_w),
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
        "entryBytes": { "$bytes": STANDARD.encode(&entry_bytes_w) },
        "signedRequestBytes": { "$bytes": STANDARD.encode(&signed_req_bytes_w) },
    });
    let jwt_w = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        DELIVER_WELCOME_NSID,
    );

    // 2. Initial welcome delivery succeeds and records delivery receipt
    let (status_w, _, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverWelcome",
            Some(&jwt_w),
            &deliver_welcome_body,
        )
        .await;
    assert_eq!(status_w, StatusCode::OK);

    // 3. Quarantine conversation
    sqlx::query(
        r#"
        INSERT INTO federation_sync_state
            (convo_id, sequencer_ds_did, sequencer_term, last_seq, last_epoch, last_digest, last_reconciled_at, drift_count, updated_at, status, quarantined_at, quarantine_reason, first_mismatch_seq)
        VALUES ($1, $2, 1, 3, 0, '\x00', NOW(), 1, NOW(), 'quarantined', NOW(), 'prefix_mismatch', 4)
        ON CONFLICT (convo_id, sequencer_ds_did) DO UPDATE SET
            status = 'quarantined',
            quarantined_at = NOW(),
            quarantine_reason = 'prefix_mismatch',
            first_mismatch_seq = 4,
            updated_at = NOW()
        "#,
    )
    .bind(convo_id.to_string())
    .bind(&harness.sequencer_ds_did)
    .execute(&harness.pool)
    .await
    .unwrap();

    let before_replay = capture_mailbox_snapshot(&harness.pool).await;

    // 4. Replay deliverMessage: MUST reject with 409 DeliveryConflict, NOT return cached success
    let jwt_replay_msg = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        DELIVER_MESSAGE_NSID,
    );
    let (status2_m, body2_m, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverMessage",
            Some(&jwt_replay_msg),
            &deliver_msg_body,
        )
        .await;
    assert_eq!(status2_m, StatusCode::CONFLICT);
    assert_eq!(body2_m["error"].as_str(), Some("DeliveryConflict"));

    // 5. Replay deliverWelcome: MUST reject with 409 DeliveryConflict, NOT return cached success
    let jwt_replay_w = harness.mint_jwt_for(
        &harness.sequencer_ds_did,
        &harness.sequencer_ds_key,
        DELIVER_WELCOME_NSID,
    );
    let (status2_w, body2_w, _) = harness
        .send_json(
            "/xrpc/blue.catbird.mlsDS.deliverWelcome",
            Some(&jwt_replay_w),
            &deliver_welcome_body,
        )
        .await;
    assert_eq!(status2_w, StatusCode::CONFLICT);
    assert_eq!(body2_w["error"].as_str(), Some("DeliveryConflict"));

    // State snapshot must remain unchanged after delivery replays on quarantined conversation
    let after_replay = capture_mailbox_snapshot(&harness.pool).await;
    assert_eq!(
        after_replay, before_replay,
        "replaying delivery on quarantined conversation must leave state byte-for-byte unchanged"
    );
}

#[tokio::test]
async fn test_local_sequencer_negative_control_remains_writable() {
    let harness = TestHarness::new("local-writable").await;
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

    // A local conversation is not quarantined
    let is_quarantined: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM federation_sync_state WHERE convo_id = $1 AND status = 'quarantined')",
    )
    .bind(convo_id.to_string())
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert!(
        !is_quarantined,
        "local sequencer conversation must not be quarantined"
    );

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
        received_at: catbird_server::chat_protocol::test_support::CanonicalTimestamp::parse(
            &now.to_rfc3339_opts(SecondsFormat::Millis, true),
        )
        .unwrap(),
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
        &now.to_rfc3339_opts(SecondsFormat::Millis, true),
        &commit_digest,
    );

    let submit_commit_body = json!({
        "header": header_json,
        "signedRequestBytes": { "$bytes": STANDARD.encode(&signed_req_bytes) },
    });

    let jwt = harness.mint_jwt_for(
        &harness.sender_ds_did,
        &harness.sender_ds_key,
        SUBMIT_COMMIT_NSID,
    );

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
        "submitCommit on local sequencer conversation must succeed: {body:?}"
    );

    let next_seq: i64 = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert_eq!(next_seq, 6, "next_entry_seq must advance to 6");

    let entry_kind: String = sqlx::query_scalar(
        "SELECT entry_kind FROM chat.entries WHERE conversation_id = $1 AND seq = 5",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert_eq!(entry_kind, "blue.catbird.chat.defs#commitEntry");
}

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct FullMailboxEntryRow {
    conversation_id: Uuid,
    seq: i64,
    generation: Option<i64>,
    entry_id: Uuid,
    entry_kind: String,
    accepted_payload_bytes: Vec<u8>,
    accepted_payload_sha256: Vec<u8>,
    signed_request_bytes: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
    outer_entry_fingerprint: Vec<u8>,
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_auth_generation: i64,
}

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct FullMailboxConversationRow {
    conversation_id: Uuid,
    kind: String,
    lifecycle: String,
    current_generation: i64,
    current_state_version: i64,
    next_entry_seq: i64,
}

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct FullMailboxMessageSendRow {
    conversation_id: Uuid,
    message_id: Uuid,
    signed_request_bytes: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
    status: String,
    accepted_entry_seq: Option<i64>,
}

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct FullMailboxEventRow {
    event_position: i64,
    event_id: Uuid,
    event_kind: String,
    payload_bytes: Vec<u8>,
    payload_sha256: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct FullMailboxSyncStateRow {
    convo_id: String,
    sequencer_ds_did: String,
    sequencer_term: i64,
    last_seq: i64,
    last_epoch: i64,
    last_digest: Vec<u8>,
    status: String,
    quarantine_reason: Option<String>,
    first_mismatch_seq: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
struct FullMailboxSnapshot {
    entries: Vec<FullMailboxEntryRow>,
    conversations: Vec<FullMailboxConversationRow>,
    message_sends: Vec<FullMailboxMessageSendRow>,
    events: Vec<FullMailboxEventRow>,
    sync_states: Vec<FullMailboxSyncStateRow>,
}

async fn capture_full_mailbox_snapshot(pool: &DbPool, convo_id: Uuid) -> FullMailboxSnapshot {
    let entries = sqlx::query_as::<_, FullMailboxEntryRow>(
        "SELECT conversation_id, CAST(seq AS BIGINT) AS seq, CAST(generation AS BIGINT) AS generation, \
                entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, \
                signed_request_bytes, request_digest, signature, outer_entry_fingerprint, \
                actor_did, actor_device_id, actor_key_id, CAST(actor_auth_generation AS BIGINT) AS actor_auth_generation \
         FROM chat.entries WHERE conversation_id = $1 ORDER BY seq ASC",
    )
    .bind(convo_id)
    .fetch_all(pool)
    .await
    .unwrap();

    let conversations = sqlx::query_as::<_, FullMailboxConversationRow>(
        "SELECT conversation_id, kind, lifecycle, \
                CAST(current_generation AS BIGINT) AS current_generation, \
                CAST(current_state_version AS BIGINT) AS current_state_version, \
                CAST(next_entry_seq AS BIGINT) AS next_entry_seq \
         FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(convo_id)
    .fetch_all(pool)
    .await
    .unwrap();

    let message_sends = sqlx::query_as::<_, FullMailboxMessageSendRow>(
        "SELECT conversation_id, message_id, signed_request_bytes, \
                request_digest, signature, status, CAST(accepted_entry_seq AS BIGINT) AS accepted_entry_seq \
         FROM chat.message_sends WHERE conversation_id = $1 ORDER BY message_id ASC",
    )
    .bind(convo_id)
    .fetch_all(pool)
    .await
    .unwrap();

    let events = sqlx::query_as::<_, FullMailboxEventRow>(
        "SELECT CAST(event_position AS BIGINT) AS event_position, event_id, event_kind, \
                payload_bytes, payload_sha256 \
         FROM chat.events ORDER BY event_position ASC",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let convo_id_str = convo_id.to_string();
    let sync_states = sqlx::query_as::<_, FullMailboxSyncStateRow>(
        "SELECT convo_id, sequencer_ds_did, CAST(sequencer_term AS BIGINT) AS sequencer_term, \
                CAST(last_seq AS BIGINT) AS last_seq, CAST(last_epoch AS BIGINT) AS last_epoch, \
                last_digest, status, quarantine_reason, CAST(first_mismatch_seq AS BIGINT) AS first_mismatch_seq \
         FROM federation_sync_state WHERE convo_id = $1",
    )
    .bind(&convo_id_str)
    .fetch_all(pool)
    .await
    .unwrap();

    FullMailboxSnapshot {
        entries,
        conversations,
        message_sends,
        events,
        sync_states,
    }
}

fn clean_event_json(row: &CleanDigestRow, msg_id: Uuid) -> Value {
    json!({
        "seq": row.seq,
        "epoch": row.epoch,
        "msgId": msg_id.to_string(),
        "messageType": row.entry_kind.as_str(),
        "ciphertext": {"$bytes": STANDARD.encode(&row.accepted_payload_bytes)},
        "paddedSize": row.accepted_payload_bytes.len() as i64,
        "createdAt": row.received_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "entryId": row.entry_id.to_string(),
        "entryKind": row.entry_kind.as_str(),
        "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&row.accepted_payload_sha256)},
        "signedRequest": {"$bytes": STANDARD.encode(&row.signed_request_bytes)},
        "outerFingerprint": {"$bytes": STANDARD.encode(&row.outer_entry_fingerprint)}
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InvalidCleanHashLocation {
    Suffix,
    Overlap,
}

#[derive(Clone, Copy, Debug)]
enum InvalidCleanHash {
    Missing,
    Mismatched,
}

impl InvalidCleanHash {
    fn error_fragment(self) -> &'static str {
        match self {
            Self::Missing => "acceptedPayloadSha256",
            Self::Mismatched => "accepted payload hash mismatch",
        }
    }
}

async fn assert_reconciliation_rejects_invalid_accepted_payload_hash(
    test_name: &str,
    location: InvalidCleanHashLocation,
    invalid_hash: InvalidCleanHash,
) {
    let harness = TestHarness::new(test_name).await;
    let now = Utc::now();
    let convo_id = Uuid::new_v4();
    let group_id = vec![0x42u8; 32];
    let alice = TestActor::generate();
    alice.seed(&harness.pool, now).await;
    seed_conversation_structure(
        &harness.pool,
        convo_id,
        &group_id,
        true,
        Some(&harness.sequencer_ds_did),
        0,
        &alice,
        Some(&harness.sender_ds_did),
        now,
    )
    .await;

    let local_row: CleanDigestRow = sqlx::query_as(
        "SELECT CAST(seq AS BIGINT) AS seq, CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
                entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, \
                signed_request_bytes, outer_entry_fingerprint, received_at \
         FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(convo_id)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    let pre_snapshot = capture_full_mailbox_snapshot(&harness.pool, convo_id).await;

    let mut remote_rows = vec![local_row.clone()];
    let mut events = vec![clean_event_json(&local_row, local_row.entry_id)];
    if location == InvalidCleanHashLocation::Suffix {
        let message_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();
        let (_, signed_request) =
            make_message_body(convo_id, message_id, &alice, &group_id, vec![], now);
        let mutation =
            decode_and_verify_signed_mutation(&signed_request, &alice.public_key).unwrap();
        let received_at = TrustedRequestInstant::from_canonical_for_test(
            CanonicalTimestamp::parse(&now.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap(),
        );
        let built = build_verified_application_entry(
            mutation,
            CanonicalUuidV4::parse(&entry_id.to_string()).unwrap(),
            CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
            2,
            &received_at,
        )
        .unwrap();
        let remote_row = CleanDigestRow {
            seq: 2,
            epoch: 0,
            entry_id,
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_string(),
            accepted_payload_bytes: built.canonical_entry_bytes().to_vec(),
            accepted_payload_sha256: built.accepted_payload_sha256().to_vec(),
            signed_request_bytes: signed_request,
            outer_entry_fingerprint: built.outer_application_fingerprint().to_vec(),
            received_at: now,
        };
        events.push(clean_event_json(&remote_row, message_id));
        remote_rows.push(remote_row);
    }

    let faulty_event = events
        .last_mut()
        .and_then(Value::as_object_mut)
        .expect("test event must be an object");
    match invalid_hash {
        InvalidCleanHash::Missing => {
            faulty_event.remove("acceptedPayloadSha256");
        }
        InvalidCleanHash::Mismatched => {
            faulty_event.insert(
                "acceptedPayloadSha256".to_string(),
                json!({"$bytes": STANDARD.encode([0xeeu8; 32])}),
            );
        }
    }

    let last_seq = remote_rows.last().unwrap().seq;
    let digest_sha256 = match location {
        InvalidCleanHashLocation::Suffix => compute_clean_convo_digest(&remote_rows),
        InvalidCleanHashLocation::Overlap => "0".repeat(64),
    };
    let convo_id_string = convo_id.to_string();
    let digest_output = GetConvoDigestOutput {
        convo_id: convo_id_string.clone(),
        sequencer_ds_did: harness.sequencer_ds_did.clone(),
        sequencer_term: 0,
        epoch: 0,
        last_seq,
        event_count: remote_rows.len() as i64,
        digest_sha256,
        generated_at: now,
    };
    let events_output = json!({
        "convoId": convo_id_string,
        "fromSeqExclusive": 0,
        "toSeqInclusive": last_seq,
        "events": events,
    });

    let app = axum::Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest",
            axum::routing::get({
                let body = serde_json::to_vec(&digest_output).unwrap();
                move || {
                    let body = body.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(body))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoEvents",
            axum::routing::get({
                let body = serde_json::to_vec(&events_output).unwrap();
                move || {
                    let body = body.clone();
                    async move {
                        axum::response::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(body))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.healthCheck",
            axum::routing::get(|| async {
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"status":"ok","capabilities":["reconciliation-v1","blue.catbird.mlsDS.reconciliation.v1"]}"#,
                    ))
                    .unwrap()
            }),
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
            harness.sender_ds_did.clone(),
            "https://self.example.com".to_string(),
            None,
            3600,
        )
        .with_destination_resolver_hook(Arc::new(move |_endpoint| {
            Some(Box::pin(async move {
                Ok(ValidatedRemoteDestination {
                    url: url::Url::parse(&format!("http://{local_addr}")).unwrap(),
                    host: "127.0.0.1".to_string(),
                    addrs: vec![local_addr],
                })
            }))
        })),
    );
    let outbound = Arc::new(OutboundClient::new(2, 2));
    let auth_sign = |_target: &str, _nsid: &str| Ok("test-token".to_string());

    let error = catbird_server::federation::reconciliation::reconcile_conversation(
        &harness.pool,
        &resolver,
        &outbound,
        &auth_sign,
        &convo_id_string,
        &harness.sequencer_ds_did,
    )
    .await
    .expect_err("invalid acceptedPayloadSha256 must fail reconciliation");
    assert!(
        error.contains(invalid_hash.error_fragment()),
        "error must cite {}, got: {error}",
        invalid_hash.error_fragment()
    );
    assert_eq!(
        pre_snapshot,
        capture_full_mailbox_snapshot(&harness.pool, convo_id).await,
        "full mailbox rows must be byte-for-byte unchanged after rejection"
    );
}

#[tokio::test]
async fn test_reconciliation_missing_accepted_payload_sha256_suffix_fails_before_clean_import_or_comparison_write(
) {
    assert_reconciliation_rejects_invalid_accepted_payload_hash(
        "recon-missing-hash",
        InvalidCleanHashLocation::Suffix,
        InvalidCleanHash::Missing,
    )
    .await;
}

#[tokio::test]
async fn test_reconciliation_mismatched_accepted_payload_sha256_suffix_fails_before_clean_import_or_comparison_write(
) {
    assert_reconciliation_rejects_invalid_accepted_payload_hash(
        "recon-mismatched-hash",
        InvalidCleanHashLocation::Suffix,
        InvalidCleanHash::Mismatched,
    )
    .await;
}

#[tokio::test]
async fn test_reconciliation_missing_accepted_payload_sha256_overlap_fails_before_comparison_write()
{
    assert_reconciliation_rejects_invalid_accepted_payload_hash(
        "recon-missing-hash-ovl",
        InvalidCleanHashLocation::Overlap,
        InvalidCleanHash::Missing,
    )
    .await;
}

#[tokio::test]
async fn test_reconciliation_mismatched_accepted_payload_sha256_overlap_fails_before_comparison_write(
) {
    assert_reconciliation_rejects_invalid_accepted_payload_hash(
        "recon-mismatched-hash-ovl",
        InvalidCleanHashLocation::Overlap,
        InvalidCleanHash::Mismatched,
    )
    .await;
}
