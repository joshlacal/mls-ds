#![allow(dead_code)]

use std::future::Future;
use std::sync::{Arc, Mutex, Once};

use axum::{body::Body, extract::FromRef, http::Request, Router};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_server::{
    blob_store::BlobStore,
    handlers::chat::{chat_router, ChatRuntime},
    realtime::SseState,
    storage::DbPool,
};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower_util::ServiceExt;
use uuid::Uuid;

pub const ISSUER: &str = "did:web:api.catbird.blue";
pub const AUDIENCE: &str = "did:web:chat.catbird.blue#atproto_mls";
pub const CHAT_INSTANCE: &str = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
pub const EXTERNAL_BASE: &str = "https://chat.example.net";
pub const NEST_KEY_ID: &str = "http-acceptance";

#[derive(Clone)]
pub struct TestState {
    pub pool: DbPool,
    pub runtime: Arc<ChatRuntime>,
    pub blob_store: BlobStore,
}

impl FromRef<TestState> for DbPool {
    fn from_ref(state: &TestState) -> Self {
        state.pool.clone()
    }
}
impl FromRef<TestState> for Arc<ChatRuntime> {
    fn from_ref(state: &TestState) -> Self {
        state.runtime.clone()
    }
}
impl FromRef<TestState> for BlobStore {
    fn from_ref(state: &TestState) -> Self {
        state.blob_store.clone()
    }
}

pub struct Device {
    pub did: String,
    pub device_id: Uuid,
    pub signing: SigningKey,
    pub jwk: Value,
    pub jkt: String,
}

pub fn random_did() -> String {
    let bytes = [
        Uuid::new_v4().as_bytes().to_vec(),
        Uuid::new_v4().as_bytes().to_vec(),
    ]
    .concat();
    let suffix: String = bytes
        .iter()
        .take(24)
        .map(|b| b"abcdefghijklmnopqrstuvwxyz234567"[(*b as usize) % 32] as char)
        .collect();
    format!("did:plc:{suffix}")
}

pub fn random_p256() -> SigningKey {
    loop {
        let seed = [
            Uuid::new_v4().as_bytes().to_vec(),
            Uuid::new_v4().as_bytes().to_vec(),
        ]
        .concat();
        if let Ok(key) = SigningKey::from_slice(&seed) {
            return key;
        }
    }
}

pub fn public_jwk(key: &SigningKey) -> Value {
    let point = key.verifying_key().to_encoded_point(false);
    serde_json::json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap())})
}

pub fn jwk_thumbprint(jwk: &Value) -> String {
    let canonical = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap()
    );
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn nest_key() -> SigningKey {
    SigningKey::from_bytes((&[0x5a_u8; 32]).into()).expect("nest key")
}

fn sign_jwt(header: Value, claims: Value, key: &SigningKey) -> String {
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let input = format!("{h}.{c}");
    let sig: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

fn dpop_proof(
    key: &SigningKey,
    jwk: &Value,
    method: &str,
    htu: &str,
    token: &str,
    now: i64,
) -> String {
    sign_jwt(
        serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":jwk}),
        serde_json::json!({"htm":method,"htu":htu,"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())),"iat":now,"jti":URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes())}),
        key,
    )
}

fn htu(nsid: &str) -> String {
    format!("{EXTERNAL_BASE}/xrpc/{nsid}")
}

pub fn seed_device(pool: &DbPool) -> impl Future<Output = Device> + '_ {
    async move {
        let signing = random_p256();
        let jwk = public_jwk(&signing);
        let jkt = jwk_thumbprint(&jwk);
        let did = random_did();
        let device_id = Uuid::new_v4();
        let key = [
            Uuid::new_v4().as_bytes().to_vec(),
            Uuid::new_v4().as_bytes().to_vec(),
        ]
        .concat();
        let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(pool)
            .await
            .expect("clock");
        sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
            .bind(&did)
            .bind(now)
            .execute(pool)
            .await
            .expect("principal");
        let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
            .bind(&key)
            .fetch_one(pool)
            .await
            .expect("key id");
        sqlx::query("INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'http-test','active',$3,1,chat.protocol_capabilities(),$4,$4)").bind(&did).bind(device_id).bind(&jkt).bind(now).execute(pool).await.expect("device");
        sqlx::query("INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,$5)").bind(&did).bind(device_id).bind(&key_id).bind(&key).bind(now).execute(pool).await.expect("device key");

        let point = signing.verifying_key().to_encoded_point(false);
        let jwk_val = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        });
        let jwk_parsed: catbird_server::auth::PublicKeyJwk =
            serde_json::from_value(jwk_val).unwrap();
        let doc = catbird_server::auth::DidDocument {
            id: did.clone(),
            verification_method: vec![catbird_server::auth::VerificationMethod {
                id: format!("{did}#atproto"),
                key_type: "JsonWebKey2020".to_string(),
                controller: did.clone(),
                public_key_jwk: Some(jwk_parsed),
                public_key_multibase: None,
            }],
            service: None,
        };
        catbird_server::auth::cache_test_did_document(doc).await;

        Device {
            did,
            device_id,
            signing,
            jwk,
            jkt,
        }
    }
}

pub async fn ensure_fence(pool: &DbPool) {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS auth_jti_nonce (
            issuer_did TEXT NOT NULL,
            jti TEXT NOT NULL,
            endpoint_nsid TEXT NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (issuer_did, jti)
        )",
    )
    .execute(pool)
    .await
    .expect("auth_jti_nonce table");
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS chat.service_auth_admissions (
            admission_id UUID PRIMARY KEY,
            issuer_did TEXT NOT NULL,
            endpoint_nsid TEXT NOT NULL,
            device_id UUID NOT NULL,
            jti_sha256 BYTEA NOT NULL,
            token_sha256 BYTEA NOT NULL,
            token_iat TIMESTAMPTZ NOT NULL,
            token_exp TIMESTAMPTZ NOT NULL,
            consumed_at TIMESTAMPTZ NOT NULL,
            CONSTRAINT service_auth_admissions_jti_once UNIQUE (issuer_did, jti_sha256)
        )",
    )
    .execute(pool)
    .await
    .expect("service_auth_admissions table");
    let key: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(vec![0x51_u8; 32])
        .fetch_one(pool)
        .await
        .expect("cursor key");
    sqlx::query("INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING").bind(Uuid::new_v4()).bind(&key).execute(pool).await.expect("protocol fence");
    let id: Uuid = sqlx::query_scalar(
        "SELECT protocol_instance_id FROM chat.protocol_instances WHERE singleton=TRUE",
    )
    .fetch_one(pool)
    .await
    .expect("instance");
    sqlx::query("INSERT INTO chat.event_retention(protocol_instance_id,retained_floor,updated_at) VALUES($1,0,clock_timestamp()) ON CONFLICT DO NOTHING").bind(id).execute(pool).await.expect("retention");
}

/// Build the route harness with the pre-cutover fence held by default.
pub async fn router(pool: DbPool) -> Router {
    build_router(pool, false, None).await
}

/// The named authenticated acceptance cases exercise routes gated behind the
/// chat cutover. The environment override is scoped to runtime construction;
/// the process-level value is restored to the explicit pre-cutover value
/// immediately afterward.
pub async fn router_for_authenticated_acceptance(pool: DbPool) -> Router {
    build_router(pool, true, None).await
}

pub async fn router_for_authenticated_acceptance_with_blob_store(
    pool: DbPool,
    blob_store: BlobStore,
) -> Router {
    build_router(pool, true, Some(blob_store)).await
}

async fn build_router(
    pool: DbPool,
    cutover_enabled: bool,
    blob_store: Option<BlobStore>,
) -> Router {
    let key_id: String = sqlx::query_scalar(
        "SELECT cursor_key_id FROM chat.protocol_instances WHERE singleton=TRUE",
    )
    .fetch_one(&pool)
    .await
    .expect("cursor key");
    static ENV: Once = Once::new();
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().expect("env lock");
    ENV.call_once(|| {
        let point = nest_key().verifying_key().to_encoded_point(false);
        std::env::set_var("CHAT_NEST_ISSUER", ISSUER);
        std::env::set_var("CHAT_NEST_AUDIENCE", AUDIENCE);
        std::env::set_var("CHAT_NEST_KEY_ID", NEST_KEY_ID);
        std::env::set_var("CHAT_NEST_VERIFYING_KEY", STANDARD.encode(point.as_bytes()));
        std::env::set_var("CHAT_INSTANCE_ID", CHAT_INSTANCE);
        std::env::set_var("CHAT_EXTERNAL_BASE", EXTERNAL_BASE);
        std::env::set_var(
            "CHAT_CURSOR_SEALING_SECRET",
            URL_SAFE_NO_PAD.encode([0xA5_u8; 32]),
        );
        std::env::set_var(
            "CHAT_SUBSCRIPTION_ENDPOINT",
            "wss://chat.example.net/xrpc/blue.catbird.chat.subscribeEvents",
        );
    });
    let point = nest_key().verifying_key().to_encoded_point(false);
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
    std::env::set_var("CHAT_CURSOR_KEY_ID", key_id);
    std::env::set_var(
        "CHAT_SUBSCRIPTION_ENDPOINT",
        "wss://chat.example.net/xrpc/blue.catbird.chat.subscribeEvents",
    );
    std::env::set_var(
        "CHAT_CUTOVER_ENABLED",
        if cutover_enabled { "1" } else { "0" },
    );
    let runtime = Arc::new(ChatRuntime::from_env(Arc::new(SseState::new(64))).expect("runtime"));
    std::env::set_var("CHAT_CUTOVER_ENABLED", "0");
    chat_router::<TestState>().with_state(TestState {
        pool,
        runtime,
        blob_store: blob_store.unwrap_or_else(BlobStore::for_route_tests),
    })
}

pub fn unsigned_request(device: &Device, nsid: &str, method: &str, query: &str) -> Request<Body> {
    unsigned_request_as(
        device,
        nsid,
        method,
        query,
        &device.did,
        device.device_id,
        &device.jkt,
        &device.signing,
        &device.jwk,
    )
}

pub fn unsigned_request_as(
    device: &Device,
    nsid: &str,
    method: &str,
    query: &str,
    subject: &str,
    _device_id: Uuid,
    _token_jkt: &str,
    _proof_key: &SigningKey,
    _proof_jwk: &Value,
) -> Request<Body> {
    let now = chrono::Utc::now().timestamp();
    let token = sign_jwt(
        serde_json::json!({"alg":"ES256","typ":"JWT","kid":format!("{subject}#atproto")}),
        serde_json::json!({"iss":subject,"aud":AUDIENCE,"lxm":nsid,"iat":now,"exp":now+60,"jti":Uuid::new_v4().to_string()}),
        &device.signing,
    );
    Request::builder()
        .method(method)
        .uri(format!("/xrpc/{nsid}{query}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request")
}

pub fn unsigned_json_request(device: &Device, nsid: &str, body: Vec<u8>) -> Request<Body> {
    let now = chrono::Utc::now().timestamp();
    let token = sign_jwt(
        serde_json::json!({"alg":"ES256","typ":"JWT","kid":format!("{}#atproto", device.did)}),
        serde_json::json!({"iss":device.did,"aud":AUDIENCE,"lxm":nsid,"iat":now,"exp":now+60,"jti":Uuid::new_v4().to_string()}),
        &device.signing,
    );
    Request::builder()
        .method("POST")
        .uri(format!("/xrpc/{nsid}"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body))
        .expect("JSON request")
}
pub fn websocket_request(nsid: &str, query: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!("/xrpc/{nsid}{query}"))
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-key", "x3JJHMbDL1EzLkh9GBhXDw==")
        .header("sec-websocket-version", "13")
        .body(Body::empty())
        .expect("websocket request")
}

pub async fn send(router: Router, request: Request<Body>) -> (axum::http::StatusCode, Value) {
    let response = router.oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
pub async fn send_bytes(
    router: Router,
    request: Request<Body>,
) -> (axum::http::StatusCode, Vec<u8>) {
    let response = router.oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, bytes.to_vec())
}
