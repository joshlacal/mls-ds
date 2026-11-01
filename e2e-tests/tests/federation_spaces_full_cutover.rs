//! Comprehensive 2-DS + ATProto Spaces Federation & Clean-Slate Cutover Integration Suite
//! (`Spec §7` `G3`, `G4`, `G6`, `Gate 10`, `I1`–`I16`, `D1`–`D4`, `C33`, `1A`, `3A`).
//!
//! Boots TWO independent `clean_slate_federation_fixture` OS server processes over two freshly
//! migrated PostgreSQL 16 databases:
//! - `ds-a` (`did:web:ds-a.federation.catbird.blue`)
//! - `ds-b` (`did:plc:dsbfederationlocal24char`)
//!
//! Plus loopback `Swan`-profile Spaces PDS, `bluesky-social/atproto#5187` reference Spaces PDS,
//! non-Spaces legacy PDS (`501 Not Implemented` for `I15`), and `nest`-profile Push Gateway (`D2`).

#![cfg(feature = "labyrinth")]

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::{BufRead as _, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};

use aes_gcm::{
    aead::{Aead as _, KeyInit as _},
    Aes256Gcm, Nonce as AesNonce,
};
use anyhow::{Context, Result};
use atproto_spaces::{
    http_signature::{sign_credential_request, verify_credential_request},
    kem::{decapsulate_p256, encapsulate_p256, encode_p256_did_key},
    mac::{
        compute_commit_mac, format_commit_mac_header, format_want_mac_header,
        parse_want_mac_header, verify_commit_mac, COMMIT_MAC_TYPE, SPACE_MAC_HEADER_NAME,
        SPACE_WANT_MAC_HEADER_NAME,
    },
    tokens::{
        mint_space_token, verify_space_token, SpaceKeyResolver, SpaceSigningKey, SpaceTokenClaims,
        SpaceTokenKind, SpaceVerifyingKey,
    },
};
use axum::{
    body::Bytes as AxumBytes,
    extract::{Query, State},
    http::{header::CONTENT_TYPE, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use bird_daemon::bot::{BotLlmResponder, FederatedBirdBot, FederatedBotConfig};
use catbird_mls::{
    client::{
        CatbirdMlsClient, CatbirdMlsClientConfig, PlatformHttpHeader, PlatformHttpRequest,
        PlatformHttpResponse, PlatformKeyStore, PlatformTransport, REQUIRED_LABYRINTH_OAUTH_SCOPES,
    },
    groups::{
        lifecycle::MemberRole,
        metadata_v1::{
            maybe_rehost_avatar_on_setter_leave, validate_metadata_snapshot_size,
            SpaceAvatarPointer,
        },
    },
    metadata::GroupMetadataV1,
    requests::c33::archive_accepted_opening_messages,
    storage::RequestRow,
    MLSError,
};
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signature as Ed25519Signature, Signer as _, SigningKey as Ed25519SigningKey};
use hmac::{Hmac, Mac};
use labyrinth::{
    device::DeviceSecrets, epoch::open_genesis, records::defs::EpochPublicDef,
    sign::TransportSigner,
};
use labyrinth_protocol::receipt::{verify_sequencer_receipt_sec1, SignedSequencerReceipt};
use p256::{
    ecdsa::{
        Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
    },
    pkcs8::{EncodePrivateKey as _, LineEnding},
    SecretKey as P256Secret,
};
use rand::RngCore;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tokio_postgres::{Client as PgClient, NoTls};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const S2S_SECRET: &[u8] = b"clean-slate-federation-s2s-secret-32b!";
const DS_A_DID: &str = "did:web:ds-a.federation.catbird.blue";
const DS_B_DID: &str = "did:plc:dsbfederationlocal24char";
const PUSH_GATEWAY_SIGNATURE_DOMAIN: &[u8] = b"CATBIRD-CHAT-PUSH-GATEWAY\0";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PushGatewayTranscriptPayload<'a> {
    app_id: &'a str,
    auth_generation: i64,
    device_id: String,
    enabled: bool,
    gateway_url: &'a str,
    key_id: &'a str,
    push_key: &'a str,
    signed_at: &'a str,
}

#[allow(clippy::too_many_arguments)]
fn build_push_gateway_transcript(
    device_id: &Uuid,
    key_id: &str,
    auth_generation: i64,
    gateway_url: &str,
    app_id: &str,
    push_key: &str,
    enabled: bool,
    signed_at: &str,
) -> Result<Vec<u8>> {
    let payload = PushGatewayTranscriptPayload {
        app_id,
        auth_generation,
        device_id: device_id.to_string(),
        enabled,
        gateway_url,
        key_id,
        push_key,
        signed_at,
    };
    let cbor = serde_ipld_dagcbor::to_vec(&payload)?;
    let mut out = Vec::with_capacity(PUSH_GATEWAY_SIGNATURE_DOMAIN.len() + cbor.len());
    out.extend_from_slice(PUSH_GATEWAY_SIGNATURE_DOMAIN);
    out.extend_from_slice(&cbor);
    Ok(out)
}

async fn pg_connect(url: &str) -> Result<PgClient> {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .with_context(|| format!("connect postgres {url}"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

fn fixture_binary_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_target = manifest_dir
        .parent()
        .expect("mls-ds root")
        .join("target/debug/clean_slate_federation_fixture");
    assert!(
        workspace_target.exists(),
        "expected compiled clean_slate_federation_fixture at {}",
        workspace_target.display()
    );
    workspace_target
}

fn pg_admin_url() -> String {
    std::env::var("CLEAN_SLATE_PG_ADMIN_URL")
        .unwrap_or_else(|_| "postgresql://127.0.0.1:5432/postgres".to_string())
}

fn p256_to_pem(sk: &P256SigningKey) -> String {
    let secret = P256Secret::from_slice(&sk.to_bytes()).expect("p256 secret");
    secret
        .to_pkcs8_pem(LineEnding::LF)
        .expect("pkcs8 pem")
        .to_string()
}

fn p256_public_jwk(vk: &P256VerifyingKey) -> Value {
    let pt = vk.to_encoded_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(pt.x().expect("x")),
        "y": URL_SAFE_NO_PAD.encode(pt.y().expect("y")),
    })
}

fn mint_es256_service_jwt(sk: &P256SigningKey, iss: &str, aud: &str, lxm: &str) -> String {
    let now = Utc::now().timestamp();
    let hdr = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "ES256",
            "typ": "JWT",
            "kid": format!("{iss}#atproto"),
        }))
        .unwrap(),
    );
    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "iss": iss,
            "aud": aud,
            "lxm": lxm,
            "iat": now,
            "exp": now + 60,
            "jti": Uuid::new_v4().to_string(),
        }))
        .unwrap(),
    );
    let signing_input = format!("{hdr}.{claims}");
    let sig: P256Signature = sk.sign(signing_input.as_bytes());
    let norm = sig.normalize_s().unwrap_or(sig);
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(norm.to_bytes())
    )
}

fn compute_s2s_mac(caller_did: &str, target_did: &str, lxm: &str, body: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(S2S_SECRET).expect("hmac");
    mac.update(b"CATBIRD-S2S-GROUP-RELAY\0");
    mac.update(caller_did.as_bytes());
    mac.update(&[0]);
    mac.update(target_did.as_bytes());
    mac.update(&[0]);
    mac.update(lxm.as_bytes());
    mac.update(&[0]);
    mac.update(body);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

struct CleanSlateDsProcess {
    db_name: String,
    db_url: String,
    service_did: String,
    base_url: String,
    signing_key: P256SigningKey,
    receipt_key: P256SigningKey,
    did_document: Value,
    pool: PgClient,
    child: Option<Child>,
}

impl CleanSlateDsProcess {
    async fn spawn(service_did: &str) -> Result<Self> {
        let admin_pool = pg_connect(&pg_admin_url())
            .await
            .context("connect postgres admin db")?;
        let db_name = format!("clean_slate_fed_{}", Uuid::new_v4().simple());
        admin_pool
            .batch_execute(&format!("CREATE DATABASE \"{db_name}\""))
            .await
            .with_context(|| format!("create database {db_name}"))?;

        let db_url = format!("postgresql://127.0.0.1:5432/{db_name}");
        let signing_key = P256SigningKey::random(&mut rand::rngs::OsRng);
        let receipt_key = P256SigningKey::random(&mut rand::rngs::OsRng);

        let mut child = Command::new(fixture_binary_path())
            .env("APP_ENV", "test")
            .env("TEST_DATABASE_URL", &db_url)
            .env("SERVICE_DID", service_did)
            .env("SIGNING_KEY_PEM", p256_to_pem(&signing_key))
            .env("RECEIPT_SIGNING_KEY_PEM", p256_to_pem(&receipt_key))
            .env(
                "FEDERATION_GROUP_RELAY_HMAC_SECRET",
                std::str::from_utf8(S2S_SECRET).unwrap(),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("spawn clean_slate_federation_fixture")?;

        let stdout = child.stdout.take().context("capture child stdout")?;
        let readiness_line = tokio::task::spawn_blocking(move || -> Result<String> {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            reader.read_line(&mut line)?;
            Ok(line)
        })
        .await??;

        let ready: Value = serde_json::from_str(readiness_line.trim())
            .with_context(|| format!("parse fixture readiness JSON: {readiness_line}"))?;
        let base_url = ready["baseUrl"]
            .as_str()
            .context("missing baseUrl")?
            .to_string();
        let did_document = ready["didDocument"].clone();

        let pool = pg_connect(&db_url).await.context("connect test pool")?;

        Ok(Self {
            db_name,
            db_url,
            service_did: service_did.to_string(),
            base_url,
            signing_key,
            receipt_key,
            did_document,
            pool,
            child: Some(child),
        })
    }
}

impl Drop for CleanSlateDsProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let db_name = self.db_name.clone();
        let _ = std::thread::spawn(move || {
            if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                rt.block_on(async {
                    if let Ok(admin) = pg_connect(&pg_admin_url()).await {
                        let _ = admin
                            .execute(
                                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
                                &[&db_name],
                            )
                            .await;
                        let _ = admin
                            .batch_execute(&format!("DROP DATABASE IF EXISTS \"{db_name}\""))
                            .await;
                    }
                });
            }
        })
        .join();
    }
}

// ============================================================================
// Loopback Spaces PDS (`Swan` profile & `bluesky-social/atproto#5187` profile)
// ============================================================================

#[derive(Clone)]
struct InMemoryKeyResolver {
    keys: Arc<RwLock<HashMap<String, SpaceVerifyingKey>>>,
}

impl InMemoryKeyResolver {
    fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn insert(&self, did: &str, vk: &P256VerifyingKey) {
        self.keys
            .write()
            .unwrap()
            .insert(did.to_string(), SpaceVerifyingKey::P256(*vk));
    }
}

#[async_trait::async_trait(?Send)]
impl SpaceKeyResolver for InMemoryKeyResolver {
    async fn resolve_atproto_key(
        &self,
        did: &str,
        _force_refresh: bool,
    ) -> atproto_spaces::Result<SpaceVerifyingKey> {
        let bare = did.split('#').next().unwrap_or(did);
        self.keys
            .read()
            .unwrap()
            .get(bare)
            .cloned()
            .ok_or_else(|| atproto_spaces::SpacesError::DidResolution(format!("unknown DID {did}")))
    }
}

#[derive(Clone)]
struct StoredSpaceRepoState {
    rev: String,
    data_cid: [u8; 32],
    ops: Vec<Value>,
}

type SpaceBlobKey = (String, String, String);

#[derive(Clone)]
struct LoopbackSpacesPdsState {
    pds_did: String,
    supports_spaces: bool,
    resolver: InMemoryKeyResolver,
    author_kem_secrets: Arc<RwLock<HashMap<String, P256Secret>>>,
    staged_blobs: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    space_blobs: Arc<RwLock<HashMap<SpaceBlobKey, Vec<u8>>>>,
    personal_spaces: Arc<RwLock<HashSet<String>>>,
    repo_states: Arc<RwLock<HashMap<(String, String), StoredSpaceRepoState>>>,
    revoked_jtis: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    deleted_spaces: Arc<RwLock<HashSet<String>>>,
    tid_seq: Arc<AtomicUsize>,
}

struct LoopbackSpacesPds {
    pds_did: String,
    base_url: String,
    signing_key: P256SigningKey,
    state: LoopbackSpacesPdsState,
}

impl LoopbackSpacesPds {
    async fn start(pds_did: &str, supports_spaces: bool, resolver: InMemoryKeyResolver) -> Self {
        let signing_key = P256SigningKey::random(&mut rand::rngs::OsRng);
        resolver.insert(pds_did, signing_key.verifying_key());

        let state = LoopbackSpacesPdsState {
            pds_did: pds_did.to_string(),
            supports_spaces,
            resolver,
            author_kem_secrets: Arc::new(RwLock::new(HashMap::new())),
            staged_blobs: Arc::new(RwLock::new(HashMap::new())),
            space_blobs: Arc::new(RwLock::new(HashMap::new())),
            personal_spaces: Arc::new(RwLock::new(HashSet::new())),
            repo_states: Arc::new(RwLock::new(HashMap::new())),
            revoked_jtis: Arc::new(RwLock::new(HashMap::new())),
            deleted_spaces: Arc::new(RwLock::new(HashSet::new())),
            tid_seq: Arc::new(AtomicUsize::new(1)),
        };

        let app = Router::new()
            .route("/xrpc/com.atproto.repo.uploadBlob", post(pds_upload_blob))
            .route(
                "/xrpc/com.atproto.sync.getBlob",
                get(pds_public_sync_get_blob),
            )
            .route(
                "/xrpc/com.atproto.space.putSpace",
                put(pds_put_space).post(pds_put_space),
            )
            .route("/xrpc/com.atproto.space.getSpace", get(pds_get_space))
            .route(
                "/xrpc/com.atproto.space.applyWrites",
                post(pds_apply_writes),
            )
            .route(
                "/xrpc/com.atproto.space.listRepoOps",
                get(pds_list_repo_ops),
            )
            .route("/xrpc/com.atproto.space.getBlob", get(pds_space_get_blob))
            .route(
                "/xrpc/com.atproto.space.notifyCredentialRevoked",
                post(pds_notify_credential_revoked),
            )
            .route(
                "/xrpc/com.atproto.space.notifySpaceDeleted",
                post(pds_notify_space_deleted),
            )
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Self {
            pds_did: pds_did.to_string(),
            base_url: format!("http://{addr}"),
            signing_key,
            state,
        }
    }

    fn register_writer_kem(&self, writer_did: &str) -> String {
        let sk = P256Secret::random(&mut rand::rngs::OsRng);
        let did_key = encode_p256_did_key(&sk.public_key());
        self.state
            .author_kem_secrets
            .write()
            .unwrap()
            .insert(writer_did.to_string(), sk);
        did_key
    }
}

fn pds_not_supported() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "error": "XRPCNotSupported",
            "message": "ATProto Spaces not supported on legacy PDS"
        })),
    )
        .into_response()
}

async fn pds_upload_blob(
    State(state): State<LoopbackSpacesPdsState>,
    headers: HeaderMap,
    body: AxumBytes,
) -> Response {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if !auth.starts_with("Bearer ") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "AuthMissing" })),
        )
            .into_response();
    }
    let digest = Sha256::digest(&body);
    let cid = format!("bafkrei{}", hex::encode(&digest[..16]));
    state
        .staged_blobs
        .write()
        .unwrap()
        .insert(cid.clone(), body.to_vec());
    let mime = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    (
        StatusCode::OK,
        Json(json!({
            "blob": {
                "$type": "blob",
                "ref": { "$link": cid },
                "mimeType": mime,
                "size": body.len(),
            }
        })),
    )
        .into_response()
}

async fn pds_public_sync_get_blob(State(_state): State<LoopbackSpacesPdsState>) -> Response {
    // Gate 10 / Spec §6.1: `.staged` and `.space` blobs NEVER enter public blob storage!
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": "BlobNotFound",
            "message": "staged and Space-scoped blobs are never served via com.atproto.sync.getBlob"
        })),
    )
        .into_response()
}

async fn pds_put_space(
    State(state): State<LoopbackSpacesPdsState>,
    Json(body): Json<Value>,
) -> Response {
    if !state.supports_spaces {
        return pds_not_supported();
    }
    let uri = body["space"]
        .as_str()
        .or_else(|| body["uri"].as_str())
        .unwrap_or_default()
        .to_string();
    state.personal_spaces.write().unwrap().insert(uri.clone());
    (StatusCode::OK, Json(json!({ "uri": uri }))).into_response()
}

async fn pds_get_space(
    State(state): State<LoopbackSpacesPdsState>,
    headers: HeaderMap,
    Query(q): Query<BTreeMap<String, String>>,
) -> Response {
    if !state.supports_spaces {
        return pds_not_supported();
    }
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if auth.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "AuthMissing" })),
        )
            .into_response();
    }
    let space = q.get("space").cloned().unwrap_or_default();
    if state.deleted_spaces.read().unwrap().contains(&space) {
        return (StatusCode::GONE, Json(json!({ "error": "SpaceDeleted" }))).into_response();
    }
    (
        StatusCode::OK,
        Json(json!({
            "uri": space,
            "personalExists": state.personal_spaces.read().unwrap().contains(&space),
        })),
    )
        .into_response()
}

fn next_pds_tid(seq: &AtomicUsize) -> String {
    const S32: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
    let bump = seq.fetch_add(1, Ordering::SeqCst) as u64;
    let micros = (Utc::now().timestamp().max(0) as u64)
        .saturating_mul(1_000_000)
        .saturating_add(bump);
    let mut val = (micros << 10) & ((1_u64 << 63) - 1);
    let mut chars = [b'2'; 13];
    for idx in (0..13).rev() {
        chars[idx] = S32[(val & 0x1f) as usize];
        val >>= 5;
    }
    String::from_utf8(chars.to_vec()).unwrap()
}

async fn pds_apply_writes(
    State(state): State<LoopbackSpacesPdsState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !state.supports_spaces {
        return pds_not_supported();
    }
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if !auth.starts_with("Bearer ") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "AuthMissing" })),
        )
            .into_response();
    }

    let space = body["space"].as_str().unwrap_or_default().to_string();
    let repo = body["repo"].as_str().unwrap_or_default().to_string();
    if state.deleted_spaces.read().unwrap().contains(&space) {
        return (StatusCode::GONE, Json(json!({ "error": "SpaceDeleted" }))).into_response();
    }

    let writes = body["writes"].as_array().cloned().unwrap_or_default();
    for w in &writes {
        // Promote any referenced `.staged` blobs into `(space, repo, cid)` `.space` storage!
        promote_blobs_in_value(&state, &space, &repo, w);
    }

    let rev = next_pds_tid(&state.tid_seq);
    let commit_bytes = serde_json::to_vec(&json!({
        "space": space,
        "repo": repo,
        "rev": rev,
        "writes": writes,
    }))
    .unwrap();
    let data_cid: [u8; 32] = Sha256::digest(&commit_bytes).into();

    let mut repos = state.repo_states.write().unwrap();
    let entry = repos
        .entry((space.clone(), repo.clone()))
        .or_insert_with(|| StoredSpaceRepoState {
            rev: rev.clone(),
            data_cid,
            ops: Vec::new(),
        });
    entry.rev = rev.clone();
    entry.data_cid = data_cid;
    for w in writes {
        entry.ops.push(w);
    }

    (
        StatusCode::OK,
        Json(json!({
            "commit": {
                "rev": rev,
                "data": { "$bytes": STANDARD.encode(data_cid) },
            }
        })),
    )
        .into_response()
}

fn promote_blobs_in_value(state: &LoopbackSpacesPdsState, space: &str, repo: &str, val: &Value) {
    match val {
        Value::Object(map) => {
            if map.get("$type").and_then(Value::as_str) == Some("blob") {
                if let Some(cid) = map
                    .get("ref")
                    .and_then(|r| r.get("$link"))
                    .and_then(Value::as_str)
                {
                    if let Some(bytes) = state.staged_blobs.write().unwrap().remove(cid) {
                        state.space_blobs.write().unwrap().insert(
                            (space.to_string(), repo.to_string(), cid.to_string()),
                            bytes,
                        );
                    }
                }
            }
            for v in map.values() {
                promote_blobs_in_value(state, space, repo, v);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                promote_blobs_in_value(state, space, repo, v);
            }
        }
        _ => {}
    }
}

#[allow(clippy::result_large_err)]
async fn verify_pds_space_credential(
    state: &LoopbackSpacesPdsState,
    headers: &HeaderMap,
    space: &str,
) -> Result<SpaceTokenClaims, Response> {
    if state.deleted_spaces.read().unwrap().contains(space) {
        return Err((
            StatusCode::GONE,
            Json(json!({ "error": "SpaceDeleted", "message": "space deleted" })),
        )
            .into_response());
    }

    let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "AuthMissing", "message": "missing Authorization" })),
        )
            .into_response());
    };
    let prefix = "atproto-space-credential ";
    if auth.len() <= prefix.len() || !auth[..prefix.len()].eq_ignore_ascii_case(prefix) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "InvalidSpaceCredential" })),
        )
            .into_response());
    }
    let cred_jwt = auth[prefix.len()..].trim();
    let now_sec = Utc::now().timestamp().max(0) as u64;
    let resolver = state.resolver.clone();
    let claims = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(verify_space_token(
            SpaceTokenKind::Credential,
            cred_jwt,
            &resolver,
            now_sec,
        ))
    })
    .map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "InvalidSpaceCredential", "message": e.to_string() })),
        )
            .into_response()
    })?;

    if claims.sub != space {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Forbidden", "message": "credential sub mismatch" })),
        )
            .into_response());
    }

    if state
        .revoked_jtis
        .read()
        .unwrap()
        .get(space)
        .is_some_and(|set| set.contains(&claims.jti))
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "CredentialRevoked",
                "message": "credential jti revoked via notifyCredentialRevoked"
            })),
        )
            .into_response());
    }

    let cnf_kid = claims.cnf_kid.as_deref().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "InvalidSpaceCredential", "message": "missing cnf.kid" })),
        )
            .into_response()
    })?;
    let verified = verify_credential_request(headers, cnf_kid, now_sec).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "BadSpaceSignature", "message": e.to_string() })),
        )
            .into_response()
    })?;
    if verified.audience_did != state.pds_did {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "BadSpaceSignature", "message": "audience mismatch" })),
        )
            .into_response());
    }

    Ok(claims)
}

async fn pds_list_repo_ops(
    State(state): State<LoopbackSpacesPdsState>,
    headers: HeaderMap,
    Query(q): Query<BTreeMap<String, String>>,
) -> Response {
    if !state.supports_spaces {
        return pds_not_supported();
    }
    let space = q.get("space").cloned().unwrap_or_default();
    let repo = q.get("repo").cloned().unwrap_or_default();
    if let Err(resp) = verify_pds_space_credential(&state, &headers, &space).await {
        return resp;
    }

    let Some(repo_state) = state
        .repo_states
        .read()
        .unwrap()
        .get(&(space.clone(), repo.clone()))
        .cloned()
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "RepoNotFound" })),
        )
            .into_response();
    };

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        "access-control-expose-headers",
        HeaderValue::from_static("DPoP-Nonce, WWW-Authenticate, Atproto-Space-Mac"),
    );

    if let Some(want_mac) = headers
        .get(SPACE_WANT_MAC_HEADER_NAME)
        .and_then(|v| v.to_str().ok())
    {
        let Ok(key_share) = parse_want_mac_header(want_mac, COMMIT_MAC_TYPE) else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "BadSpaceMac" })),
            )
                .into_response();
        };
        let Some(author_sk) = state.author_kem_secrets.read().unwrap().get(&repo).cloned() else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "BadSpaceMac", "message": "missing author KEM key" })),
            )
                .into_response();
        };
        let Ok(shared_secret) = decapsulate_p256(&author_sk, &key_share) else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "BadSpaceMac" })),
            )
                .into_response();
        };
        let mac = compute_commit_mac(
            &shared_secret,
            &space,
            &repo,
            &repo_state.rev,
            &repo_state.data_cid,
        )
        .unwrap();
        let mac_hdr = format_commit_mac_header(&mac);
        resp_headers.insert(
            SPACE_MAC_HEADER_NAME,
            HeaderValue::from_str(&mac_hdr).unwrap(),
        );
    }

    (
        StatusCode::OK,
        resp_headers,
        Json(json!({
            "ops": repo_state.ops,
            "commit": {
                "ver": 1,
                "repo": repo,
                "space": space,
                "rev": repo_state.rev,
                "data": { "$bytes": STANDARD.encode(repo_state.data_cid) },
            }
        })),
    )
        .into_response()
}

async fn pds_space_get_blob(
    State(state): State<LoopbackSpacesPdsState>,
    headers: HeaderMap,
    Query(q): Query<BTreeMap<String, String>>,
) -> Response {
    if !state.supports_spaces {
        return pds_not_supported();
    }
    let space = q.get("space").cloned().unwrap_or_default();
    let repo = q.get("repo").cloned().unwrap_or_default();
    let cid = q.get("cid").cloned().unwrap_or_default();
    if let Err(resp) = verify_pds_space_credential(&state, &headers, &space).await {
        return resp;
    }

    let Some(bytes) = state
        .space_blobs
        .read()
        .unwrap()
        .get(&(space, repo, cid))
        .cloned()
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "BlobNotFound" })),
        )
            .into_response();
    };

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    resp_headers.insert(
        "access-control-expose-headers",
        HeaderValue::from_static("DPoP-Nonce, WWW-Authenticate, Atproto-Space-Mac"),
    );
    (StatusCode::OK, resp_headers, bytes).into_response()
}

async fn pds_notify_credential_revoked(
    State(state): State<LoopbackSpacesPdsState>,
    Json(body): Json<Value>,
) -> Response {
    let space = body["space"].as_str().unwrap_or_default().to_string();
    let creds = body["credentials"].as_array().cloned().unwrap_or_default();
    let mut guard = state.revoked_jtis.write().unwrap();
    let set = guard.entry(space).or_default();
    for c in creds {
        if let Some(jti) = c["jti"].as_str() {
            set.insert(jti.to_string());
        }
    }
    (StatusCode::OK, Json(json!({}))).into_response()
}

async fn pds_notify_space_deleted(
    State(state): State<LoopbackSpacesPdsState>,
    Json(body): Json<Value>,
) -> Response {
    let space = body["space"].as_str().unwrap_or_default().to_string();
    state.deleted_spaces.write().unwrap().insert(space.clone());
    state
        .space_blobs
        .write()
        .unwrap()
        .retain(|(sp, _, _), _| sp != &space);
    state
        .repo_states
        .write()
        .unwrap()
        .retain(|(sp, _), _| sp != &space);
    (StatusCode::OK, Json(json!({}))).into_response()
}

// ============================================================================
// Loopback Push Gateway (`nest` profile — `D2`, `I12`)
// ============================================================================

#[derive(Clone, Debug)]
struct CapturedPushWake {
    auth_header: String,
    body: Value,
}

struct LoopbackPushGateway {
    canonical_https_url: String,
    loopback_http_url: String,
    wakes: Arc<Mutex<Vec<CapturedPushWake>>>,
}

impl LoopbackPushGateway {
    async fn start() -> Self {
        let wakes: Arc<Mutex<Vec<CapturedPushWake>>> = Arc::new(Mutex::new(Vec::new()));
        let wakes_clone = wakes.clone();
        let app = Router::new().route(
            "/xrpc/blue.catbird.push.deliver",
            post(move |headers: HeaderMap, Json(body): Json<Value>| {
                let wakes = wakes_clone.clone();
                async move {
                    let auth_header = headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    wakes
                        .lock()
                        .unwrap()
                        .push(CapturedPushWake { auth_header, body });
                    (
                        StatusCode::OK,
                        Json(json!({
                            "results": [{
                                "pushKey": "pk",
                                "status": "delivered"
                            }]
                        })),
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Self {
            canonical_https_url:
                "https://nest-push.federation.catbird.blue/xrpc/blue.catbird.push.deliver"
                    .to_string(),
            loopback_http_url: format!("http://{addr}/xrpc/blue.catbird.push.deliver"),
            wakes,
        }
    }
}

// ============================================================================
// D1 Client Transport Firewall (`FirewalledClientTransport`)
// ============================================================================

struct FirewalledClientTransport {
    allowed_origins: Vec<String>,
    http: reqwest::Client,
    blocked_attempts: AtomicUsize,
}

impl FirewalledClientTransport {
    fn new(allowed_origins: Vec<String>) -> Self {
        Self {
            allowed_origins: allowed_origins
                .into_iter()
                .map(|u| u.trim_end_matches('/').to_string())
                .collect(),
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap(),
            blocked_attempts: AtomicUsize::new(0),
        }
    }

    fn assert_allowed(&self, url: &str) -> Result<()> {
        let allowed = self
            .allowed_origins
            .iter()
            .any(|origin| url.starts_with(origin));
        if !allowed {
            self.blocked_attempts.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("D1 client firewall blocked direct outbound request to {url}");
        }
        Ok(())
    }

    async fn post_json_with_headers(
        &self,
        url: &str,
        headers: &[(&str, String)],
        body: &Value,
    ) -> Result<(u16, HeaderMap, Vec<u8>)> {
        self.assert_allowed(url)?;
        let mut req = self
            .http
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .json(body);
        for (k, v) in headers {
            req = req.header(*k, v);
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let hdrs = resp.headers().clone();
        let bytes = resp.bytes().await?.to_vec();
        Ok((status, hdrs, bytes))
    }

    async fn get_with_headers(
        &self,
        url: &str,
        headers: &[(&str, String)],
    ) -> Result<(u16, HeaderMap, Vec<u8>)> {
        self.assert_allowed(url)?;
        let mut req = self.http.get(url);
        for (k, v) in headers {
            req = req.header(*k, v);
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let hdrs = resp.headers().clone();
        let bytes = resp.bytes().await?.to_vec();
        Ok((status, hdrs, bytes))
    }
}

impl PlatformTransport for FirewalledClientTransport {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        self.assert_allowed(&request.url)
            .map_err(|e| MLSError::Internal(e.to_string()))?;
        let http = self.http.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            rt.block_on(async move {
                let method = reqwest::Method::from_bytes(request.method.as_bytes())
                    .map_err(|e| MLSError::invalid_input(e.to_string()))?;
                let mut builder = http.request(method, &request.url);
                let mut has_auth = false;
                for h in &request.headers {
                    if h.name.eq_ignore_ascii_case("authorization") {
                        has_auth = true;
                    }
                    builder = builder.header(&h.name, &h.value);
                }
                if !has_auth && request.url.contains("/xrpc/com.atproto.space.applyWrites") {
                    builder = builder.header("authorization", "Bearer sdk-pds-oauth");
                }
                if let Some(b) = request.body {
                    builder = builder.body(b);
                }
                let resp = builder
                    .send()
                    .await
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                let status = resp.status().as_u16();
                let headers = resp
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| {
                        v.to_str().ok().map(|val| PlatformHttpHeader {
                            name: k.as_str().to_string(),
                            value: val.to_string(),
                        })
                    })
                    .collect();
                let body = resp
                    .bytes()
                    .await
                    .map_err(|e| MLSError::Internal(e.to_string()))?
                    .to_vec();
                Ok(PlatformHttpResponse {
                    status,
                    headers,
                    body,
                })
            })
        })
        .join()
        .map_err(|_| MLSError::Internal("transport panic".into()))?
    }

    fn connect_realtime_stream(&self, url: String, _cursor: Option<i64>) -> Result<(), MLSError> {
        self.assert_allowed(&url)
            .map_err(|e| MLSError::Internal(e.to_string()))
    }

    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        Ok(())
    }
}

struct MemoryKeyStore {
    keys: Mutex<HashMap<String, Vec<u8>>>,
    dpop: Mutex<HashMap<String, (String, i64)>>,
}

impl MemoryKeyStore {
    fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
            dpop: Mutex::new(HashMap::new()),
        }
    }
}

impl PlatformKeyStore for MemoryKeyStore {
    fn load_or_create_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        let mut g = self.keys.lock().unwrap();
        Ok(g.entry(format!("db:{account_did_hash}"))
            .or_insert_with(|| {
                let mut k = vec![0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut k);
                k
            })
            .clone())
    }

    fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.keys.lock().unwrap().get(&key_id).cloned())
    }

    fn store_signature_keypair(
        &self,
        key_id: String,
        keypair_bytes: Vec<u8>,
    ) -> Result<(), MLSError> {
        self.keys.lock().unwrap().insert(key_id, keypair_bytes);
        Ok(())
    }

    fn delete_account_keys(&self, account_did_hash: String) -> Result<(), MLSError> {
        let mut g = self.keys.lock().unwrap();
        g.remove(&format!("db:{account_did_hash}"));
        g.remove(&format!("mls-signer:{account_did_hash}"));
        self.dpop.lock().unwrap().remove(&account_did_hash);
        Ok(())
    }

    fn load_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
    ) -> Result<Option<String>, MLSError> {
        let now_ms = Utc::now().timestamp_millis();
        Ok(self
            .dpop
            .lock()
            .unwrap()
            .get(&account_did_hash)
            .and_then(|(tok, exp)| (*exp > now_ms).then(|| tok.clone())))
    }

    fn store_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
        token: String,
        expires_at_ms: i64,
    ) -> Result<(), MLSError> {
        self.dpop
            .lock()
            .unwrap()
            .insert(account_did_hash, (token, expires_at_ms));
        Ok(())
    }
}

struct Ed25519TransportSigner {
    sk: Ed25519SigningKey,
}

impl TransportSigner for Ed25519TransportSigner {
    fn transport_public_key(&self) -> [u8; 32] {
        self.sk.verifying_key().to_bytes()
    }

    fn sign_transport(&self, message: &[u8]) -> [u8; 64] {
        self.sk.sign(message).to_bytes()
    }
}

struct DeterministicBirdResponder;

#[async_trait::async_trait]
impl BotLlmResponder for DeterministicBirdResponder {
    async fn generate_reply(&self, sender_did: &str, text: &str) -> anyhow::Result<String> {
        Ok(format!(
            "chirp! federated reply to {sender_did} ({} bytes)",
            text.len()
        ))
    }
}

async fn count_ds_operational_rows(pool: &PgClient) -> Result<i64> {
    let tables = [
        "chat.conversations",
        "chat.entries",
        "chat.transitions",
        "chat.conversation_spaces",
        "chat.space_credential_jtis",
        "chat.space_delegation_jtis",
        "chat.conversation_space_writers",
        "labyrinth.epoch_heads",
        "labyrinth.operations",
    ];
    let mut total = 0_i64;
    for tbl in tables {
        let row = pool
            .query_one(&format!("SELECT COUNT(*) FROM {tbl}"), &[])
            .await?;
        let n: i64 = row.get(0);
        total += n;
    }
    Ok(total)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn federation_spaces_full_cutover_end_to_end() -> Result<()> {
    // ========================================================================
    // Boot Topology: 2 Real `clean_slate_federation_fixture` Processes +
    // `Swan` PDS + `atproto#5187` Reference PDS + Legacy Non-Spaces PDS + Push Gateway
    // ========================================================================
    let mut ds_a = CleanSlateDsProcess::spawn(DS_A_DID).await?;
    let ds_b = CleanSlateDsProcess::spawn(DS_B_DID).await?;

    let resolver = InMemoryKeyResolver::new();
    resolver.insert(&ds_a.service_did, ds_a.signing_key.verifying_key());
    resolver.insert(&ds_b.service_did, ds_b.signing_key.verifying_key());

    let swan_pds = LoopbackSpacesPds::start(
        "did:web:swan.federation.catbird.blue",
        true,
        resolver.clone(),
    )
    .await;
    let ref_pds = LoopbackSpacesPds::start(
        "did:web:spaces-ref.federation.catbird.blue",
        true,
        resolver.clone(),
    )
    .await;
    let legacy_pds = LoopbackSpacesPds::start(
        "did:web:legacy.federation.catbird.blue",
        false,
        resolver.clone(),
    )
    .await;
    let push_gw = LoopbackPushGateway::start().await;

    let admin_http = reqwest::Client::new();

    // Verify `ds-a` (`did:web`) serves `/.well-known/did.json` with `#atproto_mls` + `#mls-receipt-1`
    let did_doc_resp: Value = admin_http
        .get(format!("{}/.well-known/did.json", ds_a.base_url))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(did_doc_resp["id"], DS_A_DID);
    assert!(
        did_doc_resp["verificationMethod"]
            .as_array()
            .unwrap()
            .iter()
            .any(|vm| vm["id"] == format!("{DS_A_DID}#mls-receipt-1")),
        "ds-a DID document must advertise #mls-receipt-1"
    );
    assert!(
        ds_b.did_document["verificationMethod"]
            .as_array()
            .unwrap()
            .iter()
            .any(|vm| vm["id"] == format!("{DS_B_DID}#mls-receipt-1")),
        "ds-b (did:plc) DID document must advertise #mls-receipt-1"
    );

    // Register cross-DS & Push Gateway overrides on both servers
    for ds in [&ds_a, &ds_b] {
        admin_http
            .post(format!(
                "{}/_test/clean-slate/register-push-override",
                ds.base_url
            ))
            .json(&json!({
                "canonicalHttpsUrl": push_gw.canonical_https_url,
                "loopbackHttpUrl": push_gw.loopback_http_url,
            }))
            .send()
            .await?
            .error_for_status()?;
        admin_http
            .post(format!("{}/_test/clean-slate/register-did", ds.base_url))
            .json(&json!({
                "did": ds_a.service_did,
                "p256Jwk": p256_public_jwk(ds_a.signing_key.verifying_key()),
                "endpointUrl": ds_a.base_url,
            }))
            .send()
            .await?
            .error_for_status()?;
        admin_http
            .post(format!("{}/_test/clean-slate/register-did", ds.base_url))
            .json(&json!({
                "did": ds_b.service_did,
                "p256Jwk": p256_public_jwk(ds_b.signing_key.verifying_key()),
                "endpointUrl": ds_b.base_url,
            }))
            .send()
            .await?
            .error_for_status()?;
        admin_http
            .post(format!("{}/_test/clean-slate/register-did", ds.base_url))
            .json(&json!({
                "did": swan_pds.pds_did,
                "p256Jwk": p256_public_jwk(swan_pds.signing_key.verifying_key()),
                "endpointUrl": swan_pds.base_url,
            }))
            .send()
            .await?
            .error_for_status()?;
        admin_http
            .post(format!("{}/_test/clean-slate/register-did", ds.base_url))
            .json(&json!({
                "did": ref_pds.pds_did,
                "p256Jwk": p256_public_jwk(ref_pds.signing_key.verifying_key()),
                "endpointUrl": ref_pds.base_url,
            }))
            .send()
            .await?
            .error_for_status()?;
    }

    // ========================================================================
    // Scenario 1: Federated Enrollment (`did:web` + `did:plc`), `I15` Spaces Gate,
    // Personal Mailbox Space, and `publishEpochHead` -> `getEpochHead` Witness Chain
    // ========================================================================
    let temp_root = tempfile::tempdir()?;
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    // Negative `I15` check: account on `legacy_pds` (non-Spaces PDS) is cleanly blocked with zero KP upload
    let legacy_transport = Arc::new(FirewalledClientTransport::new(vec![
        ds_a.base_url.clone(),
        legacy_pds.base_url.clone(),
    ]));
    let carol_legacy_client = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: temp_root
                .path()
                .join("carol-legacy")
                .to_string_lossy()
                .into(),
            account_did: "did:plc:carollegacynonspaces24ch".into(),
            device_id: Uuid::new_v4().to_string(),
            home_ds_did: DS_A_DID.into(),
            home_ds_endpoint: ds_a.base_url.clone(),
            pds_endpoint: legacy_pds.base_url.clone(),
        },
        Arc::new(MemoryKeyStore::new()),
        legacy_transport,
        None,
    )?;
    let legacy_elig = carol_legacy_client.check_spaces_eligibility(&scopes)?;
    assert!(
        !legacy_elig.eligible,
        "I15: legacy PDS without Spaces MUST block MLS eligibility"
    );
    assert!(
        carol_legacy_client.enroll_device(&scopes).is_err(),
        "I15: enroll_device MUST fail closed on non-Spaces PDS"
    );

    // Seed an active conversation on `ds-b` (`did:plc`) with Alice homed on `ds-a` (`did:web`),
    // Bob homed on `ds-b` (`did:plc`), and Eve on `ref_pds` (`atproto#5187`)
    let archive_commitment = [0x7A_u8; 32];
    let eve_did = "did:plc:eveatprotospacesref24chr";
    let seeded_b: Value = admin_http
        .post(format!(
            "{}/_test/clean-slate/seed-group-fixture",
            ds_b.base_url
        ))
        .json(&json!({
            "direct": false,
            "recipientServiceDid": DS_A_DID,
            "archiveCommitmentHex": hex::encode(archive_commitment),
            "extraMembers": []
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let convo_id = Uuid::parse_str(seeded_b["conversationId"].as_str().unwrap())?;
    let space_uri = seeded_b["spaceUri"].as_str().unwrap().to_string();
    assert_eq!(
        space_uri,
        format!("at://{DS_B_DID}/space/blue.catbird.labyrinth.conversation/{convo_id}-0"),
        "Conversation Space URI must be rooted at sequencing DS (ds-b did:plc)"
    );

    // Note: in `seed_clean_slate_application_fixture`:
    // - `senderDid` (requester) is conversation admin
    // - `recipientDid` (fulfiller) is homed on `recipientServiceDid` (`DS_A_DID`)
    let bob_admin_did = seeded_b["senderDid"].as_str().unwrap().to_string();
    let bob_device_id = Uuid::parse_str(seeded_b["senderDeviceId"].as_str().unwrap())?;
    let bob_key_id = seeded_b["senderKeyId"].as_str().unwrap().to_string();
    let bob_ed_seed: [u8; 32] = STANDARD
        .decode(seeded_b["senderEd25519SeedB64"].as_str().unwrap())?
        .try_into()
        .unwrap();
    let bob_ed_sk = Ed25519SigningKey::from_bytes(&bob_ed_seed);

    let alice_remote_did = seeded_b["recipientDid"].as_str().unwrap().to_string();
    let alice_device_id = Uuid::parse_str(seeded_b["recipientDeviceId"].as_str().unwrap())?;
    let alice_key_id = seeded_b["recipientKeyId"].as_str().unwrap().to_string();
    let alice_ed_seed: [u8; 32] = STANDARD
        .decode(seeded_b["recipientEd25519SeedB64"].as_str().unwrap())?
        .try_into()
        .unwrap();
    let alice_ed_sk = Ed25519SigningKey::from_bytes(&alice_ed_seed);

    // Register P-256 `#atproto` DID keys + PDS endpoints for Alice (`swan_pds`), Bob (`swan_pds`), and Eve (`ref_pds`)
    let alice_p256 = P256SigningKey::random(&mut rand::rngs::OsRng);
    let bob_p256 = P256SigningKey::random(&mut rand::rngs::OsRng);
    let eve_p256 = P256SigningKey::random(&mut rand::rngs::OsRng);
    resolver.insert(&alice_remote_did, alice_p256.verifying_key());
    resolver.insert(&bob_admin_did, bob_p256.verifying_key());
    resolver.insert(eve_did, eve_p256.verifying_key());

    let alice_kem_did_key = swan_pds.register_writer_kem(&alice_remote_did);
    let bob_kem_did_key = swan_pds.register_writer_kem(&bob_admin_did);
    let eve_kem_did_key = ref_pds.register_writer_kem(eve_did);

    for ds in [&ds_a, &ds_b] {
        for (did, sk, pds_url) in [
            (
                alice_remote_did.as_str(),
                &alice_p256,
                swan_pds.base_url.as_str(),
            ),
            (
                bob_admin_did.as_str(),
                &bob_p256,
                swan_pds.base_url.as_str(),
            ),
            (eve_did, &eve_p256, ref_pds.base_url.as_str()),
        ] {
            admin_http
                .post(format!("{}/_test/clean-slate/register-did", ds.base_url))
                .json(&json!({
                    "did": did,
                    "p256Jwk": p256_public_jwk(sk.verifying_key()),
                    "endpointUrl": pds_url,
                }))
                .send()
                .await?
                .error_for_status()?;
        }
    }

    // Replicate Alice's active chat device + device_key on her home `ds-a` (`D1` / `D2` / `3A`)
    let alice_pub_slice = alice_ed_sk.verifying_key().to_bytes();
    let alice_pub_bytes: &[u8] = alice_pub_slice.as_slice();
    {
        let tx = ds_a.pool.transaction().await?;
        tx.execute(
            "INSERT INTO chat.principals (user_did, created_at) \
             VALUES ($1, clock_timestamp()) ON CONFLICT DO NOTHING",
            &[&alice_remote_did],
        )
        .await?;
        tx.execute(
            "INSERT INTO chat.devices ( \
                 user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at \
             ) VALUES ($1, $2, 'alice-home-fixture', 'active', $3, 1, chat.protocol_capabilities(), clock_timestamp(), clock_timestamp()) \
             ON CONFLICT DO NOTHING",
            &[&alice_remote_did, &alice_device_id, &alice_key_id],
        )
        .await?;
        tx.execute(
            "INSERT INTO chat.device_keys ( \
                 user_did, device_id, key_id, signing_public_key, enrollment_auth_generation, created_at \
             ) VALUES ($1, $2, $3, $4, 1, clock_timestamp()) \
             ON CONFLICT DO NOTHING",
            &[&alice_remote_did, &alice_device_id, &alice_key_id, &alice_pub_bytes],
        )
        .await?;
        tx.commit().await?;
    }

    // Alice's D1-firewalled transport ONLY permits her home `ds-a` and her own `swan_pds`!
    let alice_firewall = Arc::new(FirewalledClientTransport::new(vec![
        ds_a.base_url.clone(),
        swan_pds.base_url.clone(),
    ]));

    // Enroll Alice's `CatbirdMlsClient` (`MLS_256_XWING` + `D4` default-on Labyrinth) and provision personal mailbox Space
    let alice_sdk = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: temp_root.path().join("alice-sdk").to_string_lossy().into(),
            account_did: alice_remote_did.clone(),
            device_id: alice_device_id.to_string(),
            home_ds_did: DS_A_DID.into(),
            home_ds_endpoint: ds_a.base_url.clone(),
            pds_endpoint: swan_pds.base_url.clone(),
        },
        Arc::new(MemoryKeyStore::new()),
        alice_firewall.clone(),
        None,
    )?;
    let alice_enroll = alice_sdk.enroll_device(&scopes)?;
    assert!(
        alice_enroll
            .direct_request_kp_bytes
            .windows(2)
            .any(|w| w == [0x00, 0x4d]),
        "I16: enrolled KeyPackage must carry MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 (0x004D)"
    );
    assert!(
        alice_enroll.labyrinth_backup_enabled,
        "D4: Labyrinth must be default-on"
    );
    assert_eq!(
        alice_enroll.mailbox_space_uri,
        format!("at://{alice_remote_did}/space/blue.catbird.labyrinth.mailbox/self")
    );

    let (put_space_status, _, _) = alice_firewall
        .post_json_with_headers(
            &format!("{}/xrpc/com.atproto.space.putSpace", swan_pds.base_url),
            &[("authorization", "Bearer alice-pds-oauth".into())],
            &json!({ "space": alice_enroll.mailbox_space_uri }),
        )
        .await?;
    assert_eq!(put_space_status, 200);

    // Publish real signed `EpochPublic` (epoch 0) for Alice to `ds-a`'s `publishEpochHead` and verify via `getEpochHead` (`Gate 6`, `L-F01`)
    let alice_lab_secrets = DeviceSecrets::generate()?;
    let alice_transport_signer = Ed25519TransportSigner {
        sk: alice_ed_sk.clone(),
    };
    let (_pending_ep0, new_ep0) = open_genesis(
        &alice_remote_did,
        &alice_lab_secrets,
        &alice_transport_signer,
    )?;
    let ep0_def = EpochPublicDef::from_public(&new_ep0.record.public);
    let publish_body_bytes = serde_json::to_vec(&json!({ "epoch": ep0_def }))?;
    let publish_sha = hex::encode(Sha256::digest(&publish_body_bytes));
    let op_id = hex::encode(Uuid::new_v4().as_bytes());
    let write_body_bytes = serde_json::to_vec(&json!({
        "operationId": op_id,
        "actorDeviceId": alice_device_id.to_string(),
        "endpointNsid": "blue.catbird.labyrinth.publishEpochHead",
        "payloadSha256": publish_sha,
        "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
    }))?;
    let write_sig: Ed25519Signature =
        alice_ed_sk.sign(&[b"CATBIRD-LABYRINTH-WRITE\0".as_slice(), &write_body_bytes].concat());
    let alice_pub_jwt = mint_es256_service_jwt(
        &alice_p256,
        &alice_remote_did,
        &format!("{DS_A_DID}#atproto_mls"),
        "blue.catbird.labyrinth.publishEpochHead",
    );
    let pub_resp = admin_http
        .post(format!(
            "{}/xrpc/blue.catbird.labyrinth.publishEpochHead",
            ds_a.base_url
        ))
        .header("authorization", format!("Bearer {alice_pub_jwt}"))
        .header(CONTENT_TYPE, "application/json")
        .header(
            "catbird-labyrinth-write",
            URL_SAFE_NO_PAD.encode(&write_body_bytes),
        )
        .header(
            "catbird-labyrinth-write-signature",
            URL_SAFE_NO_PAD.encode(write_sig.to_bytes()),
        )
        .body(publish_body_bytes)
        .send()
        .await?;
    assert_eq!(
        pub_resp.status(),
        reqwest::StatusCode::OK,
        "publishEpochHead must succeed"
    );

    // Query `getEpochHead` with device-signed read header (`Gate 6` + `L-F01` `chain` + `floorSeq`)
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ReadClaim<'a> {
        v: u8,
        nsid: &'a str,
        query: &'a str,
        did: &'a str,
        device_id: String,
        issued_at: i64,
    }
    let raw_query = format!(
        "actorDeviceId={}&did={}&epochNumber=0",
        alice_device_id,
        urlencoding::encode(&alice_remote_did)
    );
    let mut query_pairs: Vec<(String, String)> = url::form_urlencoded::parse(raw_query.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    query_pairs.sort();
    let canon_query = query_pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let read_claim_bytes = serde_json::to_vec(&ReadClaim {
        v: 1,
        nsid: "blue.catbird.labyrinth.getEpochHead",
        query: &canon_query,
        did: &alice_remote_did,
        device_id: alice_device_id.to_string(),
        issued_at: Utc::now().timestamp_millis(),
    })?;
    let read_sig: Ed25519Signature =
        alice_ed_sk.sign(&[b"CATBIRD-LABYRINTH-READ\0".as_slice(), &read_claim_bytes].concat());
    let alice_get_head_jwt = mint_es256_service_jwt(
        &alice_p256,
        &alice_remote_did,
        &format!("{DS_A_DID}#atproto_mls"),
        "blue.catbird.labyrinth.getEpochHead",
    );
    let (head_status, _, head_bytes) = alice_firewall
        .get_with_headers(
            &format!(
                "{}/xrpc/blue.catbird.labyrinth.getEpochHead?{raw_query}",
                ds_a.base_url
            ),
            &[
                ("authorization", format!("Bearer {alice_get_head_jwt}")),
                (
                    "catbird-labyrinth-read",
                    URL_SAFE_NO_PAD.encode(&read_claim_bytes),
                ),
                (
                    "catbird-labyrinth-read-signature",
                    URL_SAFE_NO_PAD.encode(read_sig.to_bytes()),
                ),
            ],
        )
        .await?;
    assert_eq!(head_status, 200);
    let head_json: Value = serde_json::from_slice(&head_bytes)?;
    assert_eq!(head_json["epoch"]["epochNumber"], 0);
    assert_eq!(head_json["floorSeq"], 0);
    assert_eq!(
        head_json["chain"].as_array().unwrap().len(),
        1,
        "L-F01: getEpochHead must return contiguous verified chain"
    );

    // ========================================================================
    // Scenario 2: `C33` Direct Request Lifecycle, Pending Space Exclusion,
    // 30-Day Expiry Release, and Bidirectional DM + Labyrinth Flush
    // ========================================================================
    let c33_res: Value = admin_http
        .post(format!(
            "{}/_test/clean-slate/c33-expire-and-recheck",
            ds_a.base_url
        ))
        .json(&json!({}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(
        c33_res["pendingActiveWriters"], 0,
        "C33: pending target MUST NOT appear as an active writer before acceptance"
    );
    assert!(c33_res["sweptCount"].as_u64().unwrap() >= 1);
    assert_eq!(c33_res["conversationLifecycle"], "superseded");
    assert_eq!(c33_res["consent"], "expired");
    assert_eq!(
        c33_res["reRequestConflict"], false,
        "C33: pair-owner fence MUST release after 30-day expiry so clean re-request succeeds"
    );

    // Live `CatbirdMlsClient` DM request -> accept -> opening message Space archival + Labyrinth outbox drain
    let bob_sdk = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: temp_root.path().join("bob-sdk").to_string_lossy().into(),
            account_did: bob_admin_did.clone(),
            device_id: bob_device_id.to_string(),
            home_ds_did: DS_B_DID.into(),
            home_ds_endpoint: ds_b.base_url.clone(),
            pds_endpoint: swan_pds.base_url.clone(),
        },
        Arc::new(MemoryKeyStore::new()),
        Arc::new(FirewalledClientTransport::new(vec![
            ds_b.base_url.clone(),
            swan_pds.base_url.clone(),
        ])),
        None,
    )?;
    bob_sdk.enroll_device(&scopes)?;
    alice_sdk.create_group("convo-c33-live", DS_A_DID, Some("C33 DM".into()), None)?;
    bob_sdk.create_group("convo-c33-live", DS_A_DID, Some("C33 DM".into()), None)?;
    let alice_opening_msg = alice_sdk.send_message(
        "convo-c33-live",
        "msg-c33-opening",
        "Hey Bob, federated C33 request!",
    )?;
    let c33_now_ms = Utc::now().timestamp_millis();
    let pending_req = RequestRow {
        request_id: "req-c33-live".into(),
        conversation_id: "convo-c33-live".into(),
        sender_did: alice_remote_did.clone(),
        recipient_did: bob_admin_did.clone(),
        consent: "pending".into(),
        first_message_id: Some(alice_opening_msg.message_id.clone()),
        first_message_archived: false,
        payload_json: json!({ "openingText": "Hey Bob, federated C33 request!" }).to_string(),
        expires_at_ms: c33_now_ms + 30 * 86_400_000,
        updated_at_ms: c33_now_ms,
    };
    alice_sdk
        .db()
        .write_tx(|tx| tx.upsert_request(&pending_req))?;
    bob_sdk
        .db()
        .write_tx(|tx| tx.upsert_request(&pending_req))?;
    assert_eq!(bob_sdk.list_requests(Some("pending"))?.len(), 1);
    bob_sdk.accept_direct_request("req-c33-live")?;
    assert_eq!(bob_sdk.list_requests(Some("accepted"))?.len(), 1);
    alice_sdk.accept_direct_request("req-c33-live")?;
    let archived_opening =
        archive_accepted_opening_messages(alice_sdk.db(), |_cid, msg| async move {
            assert!(msg
                .plaintext_json
                .contains("Hey Bob, federated C33 request!"));
            Ok(())
        })
        .await?;
    assert_eq!(
        archived_opening, 1,
        "C33: sender must archive opening message upon acceptance"
    );
    let alice_dm_msg =
        alice_sdk.send_message("convo-c33-live", "msg-c33-1", "Hello after C33 accept!")?;
    assert!(alice_dm_msg
        .plaintext_json
        .contains("Hello after C33 accept!"));
    let bob_dm_msg = bob_sdk.send_message("convo-c33-live", "msg-c33-2", "Hi Alice from ds-b!")?;
    assert!(bob_dm_msg.plaintext_json.contains("Hi Alice from ds-b!"));
    assert!(alice_sdk.flush_labyrinth_queue()? >= 1);
    assert!(bob_sdk.flush_labyrinth_queue()? >= 1);

    // ========================================================================
    // Scenario 3: `D1` Cross-Server Group Relay (`relayGroupMutation` / `deliverGroupEntry`),
    // `I13` ES256 Receipt Verification (`did:plc`), `D2` Push Gateway Inline vs Fetch-Required,
    // `409` Epoch Conflict, and `D3` Admin-Only Removal
    // ========================================================================
    // Alice registers her Push Gateway ONLY on her home `ds-a` (`D2`: `ds-b` has 0 push bindings for Alice)
    let pg_signed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let pg_push_key = "opaque-push-key-alice-device-0001";
    let pg_transcript = build_push_gateway_transcript(
        &alice_device_id,
        &alice_key_id,
        1,
        &push_gw.canonical_https_url,
        "blue.catbird.ios",
        pg_push_key,
        true,
        &pg_signed_at,
    )?;
    let pg_sig: Ed25519Signature = alice_ed_sk.sign(&pg_transcript);
    let alice_pg_jwt = mint_es256_service_jwt(
        &alice_p256,
        &alice_remote_did,
        &format!("{DS_A_DID}#atproto_mls"),
        "blue.catbird.chat.registerPushGateway",
    );
    let (pg_status, _, _) = alice_firewall
        .post_json_with_headers(
            &format!(
                "{}/xrpc/blue.catbird.chat.registerPushGateway",
                ds_a.base_url
            ),
            &[("authorization", format!("Bearer {alice_pg_jwt}"))],
            &json!({
                "deviceId": alice_device_id.to_string(),
                "gatewayUrl": push_gw.canonical_https_url,
                "appId": "blue.catbird.ios",
                "pushKey": pg_push_key,
                "enabled": true,
                "keyId": alice_key_id,
                "authGeneration": 1,
                "signedAt": pg_signed_at,
                "signature": { "$bytes": STANDARD.encode(pg_sig.to_bytes()) },
            }),
        )
        .await?;
    assert_eq!(
        pg_status, 200,
        "D2: registerPushGateway on home ds-a must return 200"
    );

    let alice_bindings_on_ds_b: i64 = ds_b
        .pool
        .query_one(
            "SELECT COUNT(*) FROM chat.push_gateway_bindings WHERE user_did = $1",
            &[&alice_remote_did],
        )
        .await?
        .get(0);
    assert_eq!(
        alice_bindings_on_ds_b, 0,
        "D2: sequencing ds-b MUST hold zero push gateway bindings for remote member Alice"
    );

    // Relay Bob's signed group application message over S2S `relayGroupMutation` to `ds-b` (`did:plc`)
    let relay_req = json!({
        "conversationId": convo_id,
        "endpoint": "blue.catbird.chat.sendMessage",
        "actorDid": bob_admin_did,
        "actorDeviceId": bob_device_id,
        "signedRequest": seeded_b["signedRequest"],
    });
    let relay_req_bytes = serde_json::to_vec(&relay_req)?;
    let relay_mac = compute_s2s_mac(
        DS_A_DID,
        DS_B_DID,
        "blue.catbird.mlsDS.relayGroupMutation",
        &relay_req_bytes,
    );
    let relay_resp = admin_http
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.relayGroupMutation",
            ds_b.base_url
        ))
        .header(CONTENT_TYPE, "application/json")
        .header("x-catbird-s2s-caller-did", DS_A_DID)
        .header("x-catbird-s2s-target-did", DS_B_DID)
        .header("x-catbird-s2s-mac", relay_mac)
        .body(relay_req_bytes)
        .send()
        .await?;
    assert_eq!(relay_resp.status(), reqwest::StatusCode::OK);
    let relay_out: Value = relay_resp.json().await?;
    let sequenced_entry = relay_out["entry"].clone();
    let sequenced_seq = sequenced_entry["seq"].as_i64().unwrap();
    assert!(sequenced_seq >= 2);

    // Verify `I13` ES256 `sequencerReceipt` under `ds-b`'s (`did:plc`) `#mls-receipt-1` key!
    let mut rcpt_wire = sequenced_entry["sequencerReceipt"].clone();
    assert_eq!(rcpt_wire["sequencerDid"], DS_B_DID);
    assert_eq!(rcpt_wire["kid"], format!("{DS_B_DID}#mls-receipt-1"));
    for bytes_field in ["groupId", "archiveCommitment", "signature"] {
        if let Some(b64) = rcpt_wire[bytes_field].as_str().map(str::to_owned) {
            rcpt_wire[bytes_field] = json!({ "$bytes": b64.trim_end_matches('=') });
        }
    }
    let rcpt_def: labyrinth::records::defs::SequencerReceiptDef =
        serde_json::from_value(rcpt_wire)?;
    let archived_rcpt = rcpt_def.to_archived()?;
    assert_eq!(
        archived_rcpt.signed.payload.archive_commitment, archive_commitment,
        "I13: federated sequencerReceipt MUST sign the sender's AAD archiveCommitment"
    );
    let signed_rcpt = SignedSequencerReceipt {
        payload: archived_rcpt.signed.payload,
        key_id: archived_rcpt.signed.key_id,
        signature: archived_rcpt.signed.signature,
    };
    let ds_b_rcpt_uncompressed = ds_b
        .receipt_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    verify_sequencer_receipt_sec1(&ds_b_rcpt_uncompressed, DS_B_DID, &signed_rcpt)
        .expect("I13: ES256 sequencerReceipt from did:plc ds-b MUST verify");

    // Stale-epoch conflict (`409 StaleCoordinates`) on `relayGroupMutation`
    let mut stale_signed_req = seeded_b["signedRequest"].clone();
    stale_signed_req["body"]["messageId"] = json!(Uuid::new_v4());
    stale_signed_req["body"]["prior"]["epoch"] = json!(999);
    let stale_body_val = stale_signed_req["body"].clone();
    let stale_wrapped: Value = admin_http
        .post(format!("{}/_test/clean-slate/sign-mutation", ds_b.base_url))
        .json(&json!({
            "body": stale_body_val,
            "ed25519SeedB64": STANDARD.encode(bob_ed_sk.to_bytes()),
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let stale_relay = json!({
        "conversationId": convo_id,
        "endpoint": "blue.catbird.chat.sendMessage",
        "actorDid": bob_admin_did,
        "actorDeviceId": bob_device_id,
        "signedRequest": stale_wrapped,
    });
    let stale_bytes = serde_json::to_vec(&stale_relay)?;
    let stale_mac = compute_s2s_mac(
        DS_A_DID,
        DS_B_DID,
        "blue.catbird.mlsDS.relayGroupMutation",
        &stale_bytes,
    );
    let stale_resp = admin_http
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.relayGroupMutation",
            ds_b.base_url
        ))
        .header(CONTENT_TYPE, "application/json")
        .header("x-catbird-s2s-caller-did", DS_A_DID)
        .header("x-catbird-s2s-target-did", DS_B_DID)
        .header("x-catbird-s2s-mac", stale_mac)
        .body(stale_bytes)
        .send()
        .await?;
    assert_eq!(
        stale_resp.status(),
        reqwest::StatusCode::CONFLICT,
        "stale epoch relayed mutation must return 409 StaleCoordinates"
    );

    // Fan out `deliverGroupEntry` from `ds-b` (`did:plc`) -> `ds-a` (`did:web`):
    // 1) Small ciphertext (`<= 2,200` B) -> `deliveryMode == "inline"` with `ciphertext`
    let deliver_small = json!({
        "conversationId": convo_id,
        "generation": 0,
        "spaceUri": space_uri,
        "recipientDids": [alice_remote_did],
        "recipientDevices": [[alice_remote_did, alice_device_id]],
        "entry": sequenced_entry,
    });
    let deliver_small_bytes = serde_json::to_vec(&deliver_small)?;
    let deliver_small_mac = compute_s2s_mac(
        DS_B_DID,
        DS_A_DID,
        "blue.catbird.mlsDS.deliverGroupEntry",
        &deliver_small_bytes,
    );
    admin_http
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.deliverGroupEntry",
            ds_a.base_url
        ))
        .header(CONTENT_TYPE, "application/json")
        .header("x-catbird-s2s-caller-did", DS_B_DID)
        .header("x-catbird-s2s-target-did", DS_A_DID)
        .header("x-catbird-s2s-mac", deliver_small_mac)
        .body(deliver_small_bytes)
        .send()
        .await?
        .error_for_status()?;

    // 2) Large ciphertext (`> 2,200` B) -> `deliveryMode == "fetch_required"` with `ciphertext == null`
    let mut large_entry = sequenced_entry.clone();
    large_entry["seq"] = json!(sequenced_seq + 1);
    large_entry["entryId"] = json!(Uuid::new_v4());
    large_entry["signedRequest"]["body"]["applicationMessage"]["bytes"] =
        json!(STANDARD.encode(vec![0xAB_u8; 3000]));
    let deliver_large = json!({
        "conversationId": convo_id,
        "generation": 0,
        "spaceUri": space_uri,
        "recipientDids": [alice_remote_did],
        "recipientDevices": [[alice_remote_did, alice_device_id]],
        "entry": large_entry,
    });
    let deliver_large_bytes = serde_json::to_vec(&deliver_large)?;
    let deliver_large_mac = compute_s2s_mac(
        DS_B_DID,
        DS_A_DID,
        "blue.catbird.mlsDS.deliverGroupEntry",
        &deliver_large_bytes,
    );
    admin_http
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.deliverGroupEntry",
            ds_a.base_url
        ))
        .header(CONTENT_TYPE, "application/json")
        .header("x-catbird-s2s-caller-did", DS_B_DID)
        .header("x-catbird-s2s-target-did", DS_A_DID)
        .header("x-catbird-s2s-mac", deliver_large_mac)
        .body(deliver_large_bytes)
        .send()
        .await?
        .error_for_status()?;

    {
        let wakes = push_gw.wakes.lock().unwrap();
        assert_eq!(
            wakes.len(),
            2,
            "D2: home ds-a must dispatch both push wakes"
        );
        assert!(wakes[0].auth_header.starts_with("Bearer "));
        assert_eq!(wakes[0].body["payload"]["wakeKind"], "applicationMessage");
        assert!(
            wakes[0].body["payload"]["ciphertext"].is_object()
                || wakes[0].body["payload"]["ciphertext"].is_string(),
            "I12: <=2200B wake MUST embed inline ciphertext"
        );
        assert_eq!(wakes[1].body["payload"]["wakeKind"], "applicationMessage");
        assert!(
            wakes[1].body["payload"].get("ciphertext").is_none()
                || wakes[1].body["payload"]["ciphertext"].is_null(),
            "I12: >2200B wake MUST omit inline ciphertext (fetch-required)"
        );
        for w in wakes.iter() {
            let raw = serde_json::to_string(&w.body)?;
            assert!(
                !raw.contains(&bob_admin_did),
                "D2: zero sender DID in push wake"
            );
            assert!(
                !raw.contains("senderHandle"),
                "D2: zero sender handle in push wake"
            );
            assert!(
                !raw.contains("groupName"),
                "D2: zero group title in push wake"
            );
        }
    }

    admin_http
        .post(format!(
            "{}/_test/clean-slate/add-zero-leaf-member",
            ds_b.base_url
        ))
        .json(&json!({
            "conversationId": convo_id,
            "adminDid": bob_admin_did,
            "memberDid": eve_did,
        }))
        .send()
        .await?
        .error_for_status()?;

    // `D3` / `M-F01` admin-only removal: non-admin Alice (`role = 'member'`) MUST be rejected with 403!
    let non_admin_kick = admin_http
        .post(format!("{}/_test/clean-slate/remove-member", ds_b.base_url))
        .json(&json!({
            "conversationId": convo_id,
            "actorDid": alice_remote_did,
            "targetDid": eve_did,
        }))
        .send()
        .await?;
    assert_eq!(
        non_admin_kick.status(),
        reqwest::StatusCode::FORBIDDEN,
        "D3/M-F01: non-admin member removal MUST be rejected with 403 Forbidden"
    );

    // ========================================================================
    // Scenario 5 & Scenario 6: `.staged` -> `.space` Media Privacy, `3A` Stateless
    // Home-`mls-ds` Space Relays (`relaySpaceCredential` & `relaySpaceRead`),
    // HPKE `Atproto-Space-Mac`, and `Gate 10` Immediate Removed-Member Eviction
    // ========================================================================
    // Upload encrypted media to both `swan_pds` (Bob's avatar) and `ref_pds` (Eve's attachment)
    let avatar_sym_key = [0x42_u8; 32];
    let avatar_cipher = Aes256Gcm::new_from_slice(&avatar_sym_key)
        .unwrap()
        .encrypt(
            AesNonce::from_slice(&[0x11_u8; 12]),
            b"group-avatar-png-bytes".as_ref(),
        )
        .expect("encrypt avatar");
    let avatar_sha256: [u8; 32] = Sha256::digest(&avatar_cipher).into();

    let bob_upload: Value = admin_http
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            swan_pds.base_url
        ))
        .header("authorization", "Bearer bob-pds-oauth")
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(avatar_cipher.clone())
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let bob_avatar_cid = bob_upload["blob"]["ref"]["$link"]
        .as_str()
        .unwrap()
        .to_string();

    // Gate 10: `.staged` blob MUST return 404 on public `com.atproto.sync.getBlob` BEFORE promotion
    let staged_public_resp = admin_http
        .get(format!(
            "{}/xrpc/com.atproto.sync.getBlob?did={}&cid={}",
            swan_pds.base_url,
            urlencoding::encode(&bob_admin_did),
            urlencoding::encode(&bob_avatar_cid)
        ))
        .send()
        .await?;
    assert_eq!(staged_public_resp.status(), reqwest::StatusCode::NOT_FOUND);

    // Promote Bob's avatar into Conversation Space on `swan_pds` + notify `ds-b` (`notifyWrite`)
    let bob_apply: Value = admin_http
        .post(format!(
            "{}/xrpc/com.atproto.space.applyWrites",
            swan_pds.base_url
        ))
        .header("authorization", "Bearer bob-pds-oauth")
        .json(&json!({
            "space": space_uri,
            "repo": bob_admin_did,
            "writes": [{
                "$type": "com.atproto.space.applyWrites#create",
                "collection": "blue.catbird.labyrinth.msg",
                "rkey": "avatar-op-1",
                "value": {
                    "$type": "blue.catbird.labyrinth.msg",
                    "avatar": bob_upload["blob"],
                }
            }]
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let bob_notify_jwt = mint_es256_service_jwt(
        &bob_p256,
        &bob_admin_did,
        DS_B_DID,
        "com.atproto.space.notifyWrite",
    );
    admin_http
        .post(format!(
            "{}/xrpc/com.atproto.space.notifyWrite",
            ds_b.base_url
        ))
        .header("authorization", format!("Bearer {bob_notify_jwt}"))
        .json(&json!({
            "space": space_uri,
            "repo": bob_admin_did,
            "repoRev": bob_apply["commit"]["rev"],
            "data": bob_apply["commit"]["data"],
        }))
        .send()
        .await?
        .error_for_status()?;

    // Gate 10: `.space` blob MUST STILL return 404 on public `com.atproto.sync.getBlob` AFTER promotion
    let promoted_public_resp = admin_http
        .get(format!(
            "{}/xrpc/com.atproto.sync.getBlob?did={}&cid={}",
            swan_pds.base_url,
            urlencoding::encode(&bob_admin_did),
            urlencoding::encode(&bob_avatar_cid)
        ))
        .send()
        .await?;
    assert_eq!(
        promoted_public_resp.status(),
        reqwest::StatusCode::NOT_FOUND
    );

    // Eve uploads + promotes an attachment on `ref_pds` (`bluesky-social/atproto#5187`) and notifies `ds-b`
    let eve_media_cipher = vec![0xEE_u8; 512];
    let eve_upload: Value = admin_http
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            ref_pds.base_url
        ))
        .header("authorization", "Bearer eve-pds-oauth")
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(eve_media_cipher.clone())
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let eve_blob_cid = eve_upload["blob"]["ref"]["$link"]
        .as_str()
        .unwrap()
        .to_string();
    let eve_apply: Value = admin_http
        .post(format!(
            "{}/xrpc/com.atproto.space.applyWrites",
            ref_pds.base_url
        ))
        .header("authorization", "Bearer eve-pds-oauth")
        .json(&json!({
            "space": space_uri,
            "repo": eve_did,
            "writes": [{
                "$type": "com.atproto.space.applyWrites#create",
                "collection": "blue.catbird.labyrinth.msg",
                "rkey": "eve-msg-1",
                "value": {
                    "$type": "blue.catbird.labyrinth.msg",
                    "attachment": eve_upload["blob"],
                }
            }]
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let eve_notify_jwt = mint_es256_service_jwt(
        &eve_p256,
        eve_did,
        DS_B_DID,
        "com.atproto.space.notifyWrite",
    );
    admin_http
        .post(format!(
            "{}/xrpc/com.atproto.space.notifyWrite",
            ds_b.base_url
        ))
        .header("authorization", format!("Bearer {eve_notify_jwt}"))
        .json(&json!({
            "space": space_uri,
            "repo": eve_did,
            "repoRev": eve_apply["commit"]["rev"],
            "data": eve_apply["commit"]["data"],
        }))
        .send()
        .await?
        .error_for_status()?;

    // Unauthenticated & outsider reads MUST be rejected (401 & 403)
    let unauth_blob = admin_http
        .get(format!(
            "{}/xrpc/com.atproto.space.getBlob?space={}&repo={}&cid={}",
            ref_pds.base_url,
            urlencoding::encode(&space_uri),
            urlencoding::encode(eve_did),
            urlencoding::encode(&eve_blob_cid)
        ))
        .send()
        .await?;
    assert_eq!(unauth_blob.status(), reqwest::StatusCode::UNAUTHORIZED);

    let outsider_did = "did:plc:outsidernonmember24chars";
    let outsider_p256 = P256SigningKey::random(&mut rand::rngs::OsRng);
    admin_http
        .post(format!("{}/_test/clean-slate/register-did", ds_b.base_url))
        .json(&json!({
            "did": outsider_did,
            "p256Jwk": p256_public_jwk(outsider_p256.verifying_key()),
            "endpointUrl": swan_pds.base_url,
        }))
        .send()
        .await?
        .error_for_status()?;
    let outsider_eph = P256Secret::random(&mut rand::rngs::OsRng);
    let outsider_cnf = encode_p256_did_key(&outsider_eph.public_key());
    let now_sec = Utc::now().timestamp() as u64;
    let ds_b_pds_aud = format!("{DS_B_DID}#atproto_pds");
    let outsider_del = mint_space_token(
        SpaceTokenKind::Delegation,
        &SpaceSigningKey::P256 {
            signing_key: outsider_p256,
            kid: "#atproto".into(),
        },
        &SpaceTokenClaims {
            iss: outsider_did.into(),
            sub: space_uri.clone(),
            aud: Some(ds_b_pds_aud.clone()),
            iat: now_sec,
            exp: now_sec + 60,
            jti: Uuid::new_v4().to_string(),
            cnf_kid: None,
        },
    )?;
    let outsider_cred_resp = admin_http
        .get(format!(
            "{}/xrpc/com.atproto.space.getSpaceCredential?space={}&delegationToken={}&credentialKid={}",
            ds_b.base_url,
            urlencoding::encode(&space_uri),
            urlencoding::encode(&outsider_del),
            urlencoding::encode(&outsider_cnf),
        ))
        .send()
        .await?;
    assert_eq!(
        outsider_cred_resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "non-member delegation token MUST be rejected with 403 Forbidden"
    );

    // Mint Eve's active 10-minute Space credential on BOTH `swan_pds` and `ref_pds` use-cases
    let eve_eph = P256Secret::random(&mut rand::rngs::OsRng);
    let eve_cnf = encode_p256_did_key(&eve_eph.public_key());
    let eve_del = mint_space_token(
        SpaceTokenKind::Delegation,
        &SpaceSigningKey::P256 {
            signing_key: eve_p256.clone(),
            kid: "#atproto".into(),
        },
        &SpaceTokenClaims {
            iss: eve_did.into(),
            sub: space_uri.clone(),
            aud: Some(ds_b_pds_aud.clone()),
            iat: now_sec,
            exp: now_sec + 60,
            jti: Uuid::new_v4().to_string(),
            cnf_kid: None,
        },
    )?;
    let eve_cred_json: Value = admin_http
        .get(format!(
            "{}/xrpc/com.atproto.space.getSpaceCredential?space={}&delegationToken={}&credentialKid={}",
            ds_b.base_url,
            urlencoding::encode(&space_uri),
            urlencoding::encode(&eve_del),
            urlencoding::encode(&eve_cnf),
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let eve_cred = eve_cred_json["credential"].as_str().unwrap().to_string();

    // Verify Eve CAN read both `swan_pds` and `ref_pds` BEFORE removal
    for (pds_did, pds_url, writer, cid) in [
        (
            &swan_pds.pds_did,
            &swan_pds.base_url,
            bob_admin_did.as_str(),
            bob_avatar_cid.as_str(),
        ),
        (
            &ref_pds.pds_did,
            &ref_pds.base_url,
            eve_did,
            eve_blob_cid.as_str(),
        ),
    ] {
        let signed_hdrs = sign_credential_request(
            &eve_eph,
            &eve_cred,
            pds_did,
            Utc::now().timestamp() as u64,
            &Uuid::new_v4().to_string(),
        )?;
        let pre_resp = admin_http
            .get(format!(
                "{pds_url}/xrpc/com.atproto.space.getBlob?space={}&repo={}&cid={}",
                urlencoding::encode(&space_uri),
                urlencoding::encode(writer),
                urlencoding::encode(cid),
            ))
            .header("authorization", &signed_hdrs.authorization)
            .header(
                "atproto-space-audience",
                &signed_hdrs.atproto_space_audience,
            )
            .header("signature-input", &signed_hdrs.signature_input)
            .header("signature", &signed_hdrs.signature)
            .send()
            .await?;
        assert_eq!(pre_resp.status(), reqwest::StatusCode::OK);
    }

    // `3A` Stateless Home-`mls-ds` Relays (`relaySpaceCredential` & `relaySpaceRead`) for Alice via `ds-a`!
    // Snapshot row counts on `ds-a` BEFORE `relaySpaceCredential` + `relaySpaceRead`
    let ds_a_rows_before_relay = count_ds_operational_rows(&ds_a.pool).await?;

    let alice_eph = P256Secret::random(&mut rand::rngs::OsRng);
    let alice_cnf = encode_p256_did_key(&alice_eph.public_key());
    let alice_del = mint_space_token(
        SpaceTokenKind::Delegation,
        &SpaceSigningKey::P256 {
            signing_key: alice_p256.clone(),
            kid: "#atproto".into(),
        },
        &SpaceTokenClaims {
            iss: alice_remote_did.clone(),
            sub: space_uri.clone(),
            aud: Some(ds_b_pds_aud.clone()),
            iat: now_sec,
            exp: now_sec + 60,
            jti: Uuid::new_v4().to_string(),
            cnf_kid: None,
        },
    )?;
    let alice_relay_cred_jwt = mint_es256_service_jwt(
        &alice_p256,
        &alice_remote_did,
        &format!("{DS_A_DID}#atproto_mls"),
        "blue.catbird.chat.relaySpaceCredential",
    );
    let (rc_status, _, rc_bytes) = alice_firewall
        .post_json_with_headers(
            &format!(
                "{}/xrpc/blue.catbird.chat.relaySpaceCredential",
                ds_a.base_url
            ),
            &[("authorization", format!("Bearer {alice_relay_cred_jwt}"))],
            &json!({
                "actorDeviceId": alice_device_id.to_string(),
                "authorityDid": DS_B_DID,
                "space": space_uri,
                "delegationToken": alice_del,
                "cnfKey": alice_cnf,
            }),
        )
        .await?;
    assert_eq!(
        rc_status, 200,
        "3A: relaySpaceCredential through ds-a to did:plc ds-b must succeed"
    );
    let rc_json: Value = serde_json::from_slice(&rc_bytes)?;
    let alice_cred = rc_json["credential"].as_str().unwrap().to_string();

    // Negative `3A` NSID allowlist check: `com.atproto.space.putRecord` -> `400 InvalidNsid`
    let bad_nsid_jwt = mint_es256_service_jwt(
        &alice_p256,
        &alice_remote_did,
        &format!("{DS_A_DID}#atproto_mls"),
        "blue.catbird.chat.relaySpaceRead",
    );
    let (bad_nsid_status, _, bad_nsid_body) = alice_firewall
        .post_json_with_headers(
            &format!("{}/xrpc/blue.catbird.chat.relaySpaceRead", ds_a.base_url),
            &[("authorization", format!("Bearer {bad_nsid_jwt}"))],
            &json!({
                "actorDeviceId": alice_device_id.to_string(),
                "targetDid": ref_pds.pds_did,
                "nsid": "com.atproto.space.putRecord",
                "credential": alice_cred,
                "spaceAudience": ref_pds.pds_did,
                "signatureInput": "sig1=()",
                "signature": "sig1=:AA==:",
            }),
        )
        .await?;
    assert_eq!(bad_nsid_status, 400);
    assert!(String::from_utf8_lossy(&bad_nsid_body).contains("InvalidNsid"));

    // Negative `3A` SSRF checks: `did:web:169.254.169.254` and `did:web:10.0.0.1` -> `400 InvalidTargetEndpoint`
    for ssrf_did in ["did:web:169.254.169.254", "did:web:10.0.0.1"] {
        let ssrf_jwt = mint_es256_service_jwt(
            &alice_p256,
            &alice_remote_did,
            &format!("{DS_A_DID}#atproto_mls"),
            "blue.catbird.chat.relaySpaceRead",
        );
        let (ssrf_status, _, ssrf_body) = alice_firewall
            .post_json_with_headers(
                &format!("{}/xrpc/blue.catbird.chat.relaySpaceRead", ds_a.base_url),
                &[("authorization", format!("Bearer {ssrf_jwt}"))],
                &json!({
                    "actorDeviceId": alice_device_id.to_string(),
                    "targetDid": ssrf_did,
                    "nsid": "com.atproto.space.getSpace",
                    "query": format!("space={}", urlencoding::encode(&space_uri)),
                    "credential": alice_cred,
                    "spaceAudience": ssrf_did,
                    "signatureInput": "sig1=()",
                    "signature": "sig1=:AA==:",
                }),
            )
            .await?;
        assert_eq!(ssrf_status, 400);
        assert!(
            String::from_utf8_lossy(&ssrf_body).contains("InvalidTargetEndpoint"),
            "3A/M-F06: SSRF target {ssrf_did} must be blocked with InvalidTargetEndpoint"
        );
    }

    // Gate 10: Admin Bob removes Eve (`200 OK`) -> `ds-b` revokes Eve's credential & fans out
    // `notifyCredentialRevoked` to BOTH `swan_pds` and `ref_pds`!
    let kick_eve_resp: Value = admin_http
        .post(format!("{}/_test/clean-slate/remove-member", ds_b.base_url))
        .json(&json!({
            "conversationId": convo_id,
            "actorDid": bob_admin_did,
            "targetDid": eve_did,
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(kick_eve_resp["removed"], true);
    assert!(
        kick_eve_resp["notifiedWriterHosts"].as_u64().unwrap() >= 2,
        "Gate 10: notifyCredentialRevoked must fan out to both Swan and atproto#5187 PDS hosts"
    );

    // Gate 10: Eve's unexpired 10-minute credential MUST NOW IMMEDIATELY FAIL with `401 CredentialRevoked`
    // on `ds-b` (`listRepos`), `swan_pds` (`getBlob` & `listRepoOps`), AND `ref_pds` (`getBlob` & `listRepoOps`),
    // AND re-minting via `getSpaceCredential` MUST return `403 Forbidden`!
    let eve_ds_b_pop = sign_credential_request(
        &eve_eph,
        &eve_cred,
        DS_B_DID,
        Utc::now().timestamp() as u64,
        &Uuid::new_v4().to_string(),
    )?;
    let evicted_list_repos = admin_http
        .get(format!(
            "{}/xrpc/com.atproto.space.listRepos?space={}",
            ds_b.base_url,
            urlencoding::encode(&space_uri),
        ))
        .header("authorization", &eve_ds_b_pop.authorization)
        .header(
            "atproto-space-audience",
            &eve_ds_b_pop.atproto_space_audience,
        )
        .header("signature-input", &eve_ds_b_pop.signature_input)
        .header("signature", &eve_ds_b_pop.signature)
        .send()
        .await?;
    assert_eq!(
        evicted_list_repos.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Gate 10: removed member Eve's cached credential must fail with 401 on ds-b listRepos"
    );

    let eve_remint_del = mint_space_token(
        SpaceTokenKind::Delegation,
        &SpaceSigningKey::P256 {
            signing_key: eve_p256.clone(),
            kid: "#atproto".into(),
        },
        &SpaceTokenClaims {
            iss: eve_did.into(),
            sub: space_uri.clone(),
            aud: Some(ds_b_pds_aud.clone()),
            iat: Utc::now().timestamp() as u64,
            exp: Utc::now().timestamp() as u64 + 60,
            jti: Uuid::new_v4().to_string(),
            cnf_kid: None,
        },
    )?;
    let eve_remint_resp = admin_http
        .get(format!(
            "{}/xrpc/com.atproto.space.getSpaceCredential?space={}&delegationToken={}&credentialKid={}",
            ds_b.base_url,
            urlencoding::encode(&space_uri),
            urlencoding::encode(&eve_remint_del),
            urlencoding::encode(&eve_cnf),
        ))
        .send()
        .await?;
    assert_eq!(
        eve_remint_resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "Gate 10: removed member Eve re-minting getSpaceCredential MUST fail with 403 Forbidden"
    );

    for (pds_did, pds_url, writer, cid) in [
        (
            &swan_pds.pds_did,
            &swan_pds.base_url,
            bob_admin_did.as_str(),
            bob_avatar_cid.as_str(),
        ),
        (
            &ref_pds.pds_did,
            &ref_pds.base_url,
            eve_did,
            eve_blob_cid.as_str(),
        ),
    ] {
        let h1 = sign_credential_request(
            &eve_eph,
            &eve_cred,
            pds_did,
            Utc::now().timestamp() as u64,
            &Uuid::new_v4().to_string(),
        )?;
        let evicted_blob = admin_http
            .get(format!(
                "{pds_url}/xrpc/com.atproto.space.getBlob?space={}&repo={}&cid={}",
                urlencoding::encode(&space_uri),
                urlencoding::encode(writer),
                urlencoding::encode(cid),
            ))
            .header("authorization", &h1.authorization)
            .header("atproto-space-audience", &h1.atproto_space_audience)
            .header("signature-input", &h1.signature_input)
            .header("signature", &h1.signature)
            .send()
            .await?;
        assert_eq!(
            evicted_blob.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "Gate 10: removed member Eve's cached credential must fail with 401 on {pds_did}"
        );

        let h2 = sign_credential_request(
            &eve_eph,
            &eve_cred,
            pds_did,
            Utc::now().timestamp() as u64,
            &Uuid::new_v4().to_string(),
        )?;
        let evicted_ops = admin_http
            .get(format!(
                "{pds_url}/xrpc/com.atproto.space.listRepoOps?space={}&repo={}",
                urlencoding::encode(&space_uri),
                urlencoding::encode(writer),
            ))
            .header("authorization", &h2.authorization)
            .header("atproto-space-audience", &h2.atproto_space_audience)
            .header("signature-input", &h2.signature_input)
            .header("signature", &h2.signature)
            .send()
            .await?;
        assert_eq!(evicted_ops.status(), reqwest::StatusCode::UNAUTHORIZED);
    }

    // Remaining member Alice reads `listRepos` on `ds-b` AND Eve's historical repo ops + blob on `ref_pds`
    // EXCLUSIVELY through her home `ds-a`'s stateless `relaySpaceRead` (`3A` + `D1` firewall)!
    let list_repos_pop = sign_credential_request(
        &alice_eph,
        &alice_cred,
        DS_B_DID,
        Utc::now().timestamp() as u64,
        &Uuid::new_v4().to_string(),
    )?;
    let lr_jwt = mint_es256_service_jwt(
        &alice_p256,
        &alice_remote_did,
        &format!("{DS_A_DID}#atproto_mls"),
        "blue.catbird.chat.relaySpaceRead",
    );
    let (lr_status, _, lr_bytes) = alice_firewall
        .post_json_with_headers(
            &format!("{}/xrpc/blue.catbird.chat.relaySpaceRead", ds_a.base_url),
            &[("authorization", format!("Bearer {lr_jwt}"))],
            &json!({
                "actorDeviceId": alice_device_id.to_string(),
                "targetDid": DS_B_DID,
                "nsid": "com.atproto.space.listRepos",
                "query": format!("space={}", urlencoding::encode(&space_uri)),
                "credential": alice_cred,
                "spaceAudience": DS_B_DID,
                "signatureInput": list_repos_pop.signature_input,
                "signature": list_repos_pop.signature,
            }),
        )
        .await?;
    assert_eq!(lr_status, 200);
    let lr_json: Value = serde_json::from_slice(&lr_bytes)?;
    let repo_dids: Vec<&str> = lr_json["repos"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["did"].as_str())
        .collect();
    assert!(
        repo_dids.contains(&eve_did),
        "Historical writer Eve MUST remain listed in listRepos after removal"
    );

    // Alice reads Eve's `listRepoOps` on `ref_pds` via `ds-a` `relaySpaceRead` with HPKE `Atproto-Space-Want-Mac`
    // and cryptographically verifies `Atproto-Space-Mac` + CORS `Access-Control-Expose-Headers`!
    let encap_eve = encapsulate_p256(&eve_kem_did_key)?;
    let want_mac_eve = format_want_mac_header(&encap_eve.key_share_did_key, COMMIT_MAC_TYPE)?;
    let ops_pop = sign_credential_request(
        &alice_eph,
        &alice_cred,
        &ref_pds.pds_did,
        Utc::now().timestamp() as u64,
        &Uuid::new_v4().to_string(),
    )?;
    let ops_jwt = mint_es256_service_jwt(
        &alice_p256,
        &alice_remote_did,
        &format!("{DS_A_DID}#atproto_mls"),
        "blue.catbird.chat.relaySpaceRead",
    );
    let (ops_status, ops_hdrs, ops_bytes) = alice_firewall
        .post_json_with_headers(
            &format!("{}/xrpc/blue.catbird.chat.relaySpaceRead", ds_a.base_url),
            &[("authorization", format!("Bearer {ops_jwt}"))],
            &json!({
                "actorDeviceId": alice_device_id.to_string(),
                "targetDid": ref_pds.pds_did,
                "nsid": "com.atproto.space.listRepoOps",
                "query": format!(
                    "space={}&repo={}",
                    urlencoding::encode(&space_uri),
                    urlencoding::encode(eve_did)
                ),
                "credential": alice_cred,
                "spaceAudience": ref_pds.pds_did,
                "wantMac": want_mac_eve,
                "signatureInput": ops_pop.signature_input,
                "signature": ops_pop.signature,
            }),
        )
        .await?;
    assert_eq!(ops_status, 200);
    let exposed_hdr = ops_hdrs
        .get("access-control-expose-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        exposed_hdr.contains("Atproto-Space-Mac"),
        "3A/Gate 7: relaySpaceRead must expose Atproto-Space-Mac via CORS"
    );
    let space_mac_hdr = ops_hdrs
        .get(SPACE_MAC_HEADER_NAME)
        .and_then(|v| v.to_str().ok())
        .expect("Atproto-Space-Mac header preserved by relaySpaceRead");
    let ops_json: Value = serde_json::from_slice(&ops_bytes)?;
    let commit_rev = ops_json["commit"]["rev"].as_str().unwrap();
    let commit_data: [u8; 32] = STANDARD
        .decode(ops_json["commit"]["data"]["$bytes"].as_str().unwrap())?
        .try_into()
        .unwrap();
    verify_commit_mac(
        &encap_eve.shared_secret,
        space_mac_hdr,
        &space_uri,
        eve_did,
        commit_rev,
        &commit_data,
    )
    .expect("Gate 7: end-to-end HPKE Atproto-Space-Mac must verify through relaySpaceRead");

    // Verify `3A` statelessness: ZERO operational rows added on `ds-a` across `relaySpaceCredential` & `relaySpaceRead`!
    let ds_a_rows_after_relay = count_ds_operational_rows(&ds_a.pool).await?;
    assert_eq!(
        ds_a_rows_before_relay, ds_a_rows_after_relay,
        "3A: relaySpaceCredential and relaySpaceRead MUST write zero operational rows on home mls-ds"
    );
    assert_eq!(
        alice_firewall.blocked_attempts.load(Ordering::SeqCst),
        0,
        "D1: Alice made zero direct connections to ds-b or ref_pds"
    );
    let _ = (&alice_kem_did_key, &bob_kem_did_key, &bob_key_id);

    // ========================================================================
    // Scenario 4: `1A` `GroupMetadataV1` (`<= 16 KiB` Cap, `> 16 KiB` -> `413`),
    // Space-Backed Avatar Pointer, and Automatic Admin Avatar Re-Host on Leave
    // ========================================================================
    let meta_v1 = GroupMetadataV1 {
        version: 1,
        title: "Clean-Slate Federated Group".into(),
        description: String::new(),
        avatar_blob_locator: None,
        avatar_content_type: Some("image/png".into()),
        space_avatar: Some(SpaceAvatarPointer {
            setter_did: bob_admin_did.clone(),
            space_blob_cid: bob_avatar_cid.clone(),
            sym_key: avatar_sym_key.to_vec(),
            sha256: avatar_sha256.to_vec(),
            mime_type: Some("image/png".into()),
        }),
    };
    let meta_plain = serde_json::to_vec(&meta_v1)?;
    let meta_key = [0x55_u8; 32];
    let meta_cipher = Aes256Gcm::new_from_slice(&meta_key)
        .unwrap()
        .encrypt(AesNonce::from_slice(&[0x22_u8; 12]), meta_plain.as_slice())
        .unwrap();
    validate_metadata_snapshot_size(&meta_cipher)?;

    let set_meta_res: Value = admin_http
        .post(format!(
            "{}/_test/clean-slate/set-group-metadata",
            ds_b.base_url
        ))
        .json(&json!({
            "conversationId": convo_id,
            "epoch": 0,
            "ciphertextB64": STANDARD.encode(&meta_cipher),
            "actorDid": bob_admin_did,
            "actorDeviceId": bob_device_id,
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(set_meta_res["stored"], true);
    let mv_initial = set_meta_res["metadataVersion"].as_u64().unwrap();

    // Oversized `> 16 KiB` (`16_385` B) snapshot MUST fail with `413 Payload Too Large` and DB constraint proof
    let oversized_bytes = vec![0xCC_u8; 16_385];
    assert!(validate_metadata_snapshot_size(&oversized_bytes).is_err());
    let oversized_resp = admin_http
        .post(format!(
            "{}/_test/clean-slate/set-group-metadata",
            ds_b.base_url
        ))
        .json(&json!({
            "conversationId": convo_id,
            "epoch": 0,
            "ciphertextB64": STANDARD.encode(&oversized_bytes),
            "actorDid": bob_admin_did,
            "actorDeviceId": bob_device_id,
        }))
        .send()
        .await?;
    assert_eq!(
        oversized_resp.status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE
    );
    let oversized_json: Value = oversized_resp.json().await?;
    assert_eq!(oversized_json["rejectedByDbConstraint"], true);

    // Promote Alice to co-admin before Bob voluntarily leaves, then Bob voluntarily leaves
    admin_http
        .post(format!("{}/_test/clean-slate/promote-admin", ds_b.base_url))
        .json(&json!({
            "conversationId": convo_id,
            "actorDid": bob_admin_did,
            "targetDid": alice_remote_did,
        }))
        .send()
        .await?
        .error_for_status()?;

    let leave_res: Value = admin_http
        .post(format!(
            "{}/_test/clean-slate/voluntary-leave",
            ds_b.base_url
        ))
        .json(&json!({
            "conversationId": convo_id,
            "actorDid": bob_admin_did,
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(leave_res["left"], true);

    // Active admin Alice automatically re-hosts Bob's Space avatar into Alice's own `.space` repo (`maybe_rehost_avatar_on_setter_leave`)!
    let rehosted = maybe_rehost_avatar_on_setter_leave(
        &meta_v1,
        mv_initial,
        &bob_admin_did,
        &alice_remote_did,
        MemberRole::Admin,
        |setter_did, cid| {
            let swan_url = swan_pds.base_url.clone();
            let swan_did = swan_pds.pds_did.clone();
            let sp = space_uri.clone();
            let cred = alice_cred.clone();
            let eph_bytes = alice_eph.to_bytes();
            let http = admin_http.clone();
            async move {
                let eph = P256Secret::from_slice(&eph_bytes).unwrap();
                let pop = sign_credential_request(
                    &eph,
                    &cred,
                    &swan_did,
                    Utc::now().timestamp() as u64,
                    &Uuid::new_v4().to_string(),
                )
                .map_err(|e| MLSError::Internal(e.to_string()))?;
                let bytes = http
                    .get(format!(
                        "{swan_url}/xrpc/com.atproto.space.getBlob?space={}&repo={}&cid={}",
                        urlencoding::encode(&sp),
                        urlencoding::encode(&setter_did),
                        urlencoding::encode(&cid),
                    ))
                    .header("authorization", &pop.authorization)
                    .header("atproto-space-audience", &pop.atproto_space_audience)
                    .header("signature-input", &pop.signature_input)
                    .header("signature", &pop.signature)
                    .send()
                    .await
                    .map_err(|e| MLSError::Internal(e.to_string()))?
                    .error_for_status()
                    .map_err(|e| MLSError::Internal(e.to_string()))?
                    .bytes()
                    .await
                    .map_err(|e| MLSError::Internal(e.to_string()))?
                    .to_vec();
                Ok(bytes)
            }
        },
        |new_owner_did, ct_bytes, mime| {
            let swan_url = swan_pds.base_url.clone();
            let sp = space_uri.clone();
            let http = admin_http.clone();
            async move {
                let up: Value = http
                    .post(format!("{swan_url}/xrpc/com.atproto.repo.uploadBlob"))
                    .header("authorization", "Bearer alice-pds-oauth")
                    .header(
                        CONTENT_TYPE,
                        mime.as_deref().unwrap_or("application/octet-stream"),
                    )
                    .body(ct_bytes)
                    .send()
                    .await
                    .map_err(|e| MLSError::Internal(e.to_string()))?
                    .error_for_status()
                    .map_err(|e| MLSError::Internal(e.to_string()))?
                    .json()
                    .await
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                let cid = up["blob"]["ref"]["$link"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                http.post(format!("{swan_url}/xrpc/com.atproto.space.applyWrites"))
                    .header("authorization", "Bearer alice-pds-oauth")
                    .json(&json!({
                        "space": sp,
                        "repo": new_owner_did,
                        "writes": [{
                            "$type": "com.atproto.space.applyWrites#create",
                            "collection": "blue.catbird.labyrinth.msg",
                            "rkey": "rehosted-avatar-1",
                            "value": { "avatar": up["blob"] }
                        }]
                    }))
                    .send()
                    .await
                    .map_err(|e| MLSError::Internal(e.to_string()))?
                    .error_for_status()
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                Ok(cid)
            }
        },
    )
    .await?
    .expect("1A: active admin Alice must re-host departing setter Bob's Space avatar");

    assert_eq!(rehosted.next_metadata_version, mv_initial + 1);
    assert_eq!(
        rehosted.metadata.space_avatar.as_ref().unwrap().setter_did,
        alice_remote_did
    );

    let rehosted_cipher = Aes256Gcm::new_from_slice(&meta_key)
        .unwrap()
        .encrypt(
            AesNonce::from_slice(&[0x33_u8; 12]),
            serde_json::to_vec(&rehosted.metadata)?.as_slice(),
        )
        .unwrap();
    let set_meta_rehosted: Value = admin_http
        .post(format!(
            "{}/_test/clean-slate/set-group-metadata",
            ds_b.base_url
        ))
        .json(&json!({
            "conversationId": convo_id,
            "epoch": 0,
            "ciphertextB64": STANDARD.encode(&rehosted_cipher),
            "actorDid": alice_remote_did,
            "actorDeviceId": alice_device_id,
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(
        set_meta_rehosted["metadataVersion"].as_u64(),
        Some(mv_initial + 1)
    );

    // ========================================================================
    // Scenario 7: `BIRDaemon` `nest`-Free Federated Group Participation (`G3`)
    // ========================================================================
    assert!(
        std::env::var("BIRD_NEST_BASE_URL").is_err(),
        "G3: BIRD_NEST_BASE_URL must be completely unset"
    );
    let bird_did = "did:plc:birdaemonfederated24chrs";
    let bird_bot = FederatedBirdBot::open_and_enroll(
        FederatedBotConfig {
            storage_root: temp_root.path().join("bird-bot"),
            bot_did: bird_did.to_string(),
            bot_handle: "bird.catbird.blue".to_string(),
            device_id: Uuid::new_v4().to_string(),
            home_ds_did: DS_B_DID.to_string(),
            home_ds_endpoint: ds_b.base_url.clone(),
            pds_endpoint: swan_pds.base_url.clone(),
            pds_supports_spaces: true,
            granted_oauth_scopes: scopes.clone(),
            accept_chat_requests: true,
            reply_to_all_messages: false,
            max_reply_characters: 500,
        },
        Arc::new(DeterministicBirdResponder),
    )?;
    bird_bot.set_auth_tokens(Some("bird-ds-jwt".into()), Some("bird-pds-oauth".into()));
    assert!(bird_bot
        .enrollment_receipt()
        .direct_request_kp_bytes
        .windows(2)
        .any(|w| w == [0x00, 0x4d]));
    assert!(bird_bot.enrollment_receipt().labyrinth_backup_enabled);
    bird_bot.create_group(&convo_id.to_string(), Some("Federated Bird Group".into()))?;
    let bird_reply = bird_bot
        .handle_incoming_group_text(
            &convo_id.to_string(),
            &alice_remote_did,
            "Hey @bird.catbird.blue status check over federated DS!",
        )
        .await?
        .expect("G3: FederatedBirdBot must reply to @bird.catbird.blue mention with zero nest URL");
    assert!(bird_reply.plaintext_json.contains("chirp! federated reply"));
    assert!(bird_bot.flush_labyrinth_queue()? >= 1);

    // ========================================================================
    // Scenario 8: `G6` & `I14` Zero-Content Retention & PostgreSQL Schema Audit
    // Across BOTH `ds-a` and `ds-b`
    // ========================================================================
    // Seed a dedicated conversation on `ds-a`, sequence an application send, ACK from both leaf
    // devices via `acknowledgeEntries`, and prove `accepted_payload_bytes IS NULL` while `1..N`
    // seq contiguity and control entries remain intact!
    let prune_seed: Value = admin_http
        .post(format!(
            "{}/_test/clean-slate/seed-group-fixture",
            ds_a.base_url
        ))
        .json(&json!({
            "direct": false,
            "recipientServiceDid": DS_A_DID,
            "archiveCommitmentHex": hex::encode([0x5A_u8; 32]),
            "extraMembers": []
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let prune_cid = Uuid::parse_str(prune_seed["conversationId"].as_str().unwrap())?;
    let p_sender_did = prune_seed["senderDid"].as_str().unwrap().to_string();
    let p_sender_dev = Uuid::parse_str(prune_seed["senderDeviceId"].as_str().unwrap())?;
    let p_sender_kid = prune_seed["senderKeyId"].as_str().unwrap().to_string();
    let p_sender_ed = Ed25519SigningKey::from_bytes(
        &STANDARD
            .decode(prune_seed["senderEd25519SeedB64"].as_str().unwrap())?
            .try_into()
            .unwrap(),
    );
    let p_rcpt_did = prune_seed["recipientDid"].as_str().unwrap().to_string();
    let p_rcpt_dev = Uuid::parse_str(prune_seed["recipientDeviceId"].as_str().unwrap())?;
    let p_rcpt_kid = prune_seed["recipientKeyId"].as_str().unwrap().to_string();
    let p_rcpt_ed = Ed25519SigningKey::from_bytes(
        &STANDARD
            .decode(prune_seed["recipientEd25519SeedB64"].as_str().unwrap())?
            .try_into()
            .unwrap(),
    );
    let p_sender_p256 = P256SigningKey::random(&mut rand::rngs::OsRng);
    let p_rcpt_p256 = P256SigningKey::random(&mut rand::rngs::OsRng);
    for (did, sk) in [(&p_sender_did, &p_sender_p256), (&p_rcpt_did, &p_rcpt_p256)] {
        admin_http
            .post(format!("{}/_test/clean-slate/register-did", ds_a.base_url))
            .json(&json!({
                "did": did,
                "p256Jwk": p256_public_jwk(sk.verifying_key()),
                "endpointUrl": swan_pds.base_url,
            }))
            .send()
            .await?
            .error_for_status()?;
    }

    // Sequence an applicationEntry on `ds-a`
    let prune_send_req = json!({
        "conversationId": prune_cid,
        "endpoint": "blue.catbird.chat.sendMessage",
        "actorDid": p_sender_did,
        "actorDeviceId": p_sender_dev,
        "signedRequest": prune_seed["signedRequest"],
    });
    let prune_send_bytes = serde_json::to_vec(&prune_send_req)?;
    let prune_send_mac = compute_s2s_mac(
        DS_B_DID,
        DS_A_DID,
        "blue.catbird.mlsDS.relayGroupMutation",
        &prune_send_bytes,
    );
    let prune_send_out: Value = admin_http
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.relayGroupMutation",
            ds_a.base_url
        ))
        .header(CONTENT_TYPE, "application/json")
        .header("x-catbird-s2s-caller-did", DS_B_DID)
        .header("x-catbird-s2s-target-did", DS_A_DID)
        .header("x-catbird-s2s-mac", prune_send_mac)
        .body(prune_send_bytes)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let app_seq = prune_send_out["entry"]["seq"].as_i64().unwrap();

    // Both active leaf devices call `blue.catbird.chat.acknowledgeEntries` (`upToSeq = app_seq`)
    for (did, dev_id, kid, ed_sk, p256_sk) in [
        (
            &p_sender_did,
            p_sender_dev,
            &p_sender_kid,
            &p_sender_ed,
            &p_sender_p256,
        ),
        (
            &p_rcpt_did,
            p_rcpt_dev,
            &p_rcpt_kid,
            &p_rcpt_ed,
            &p_rcpt_p256,
        ),
    ] {
        let ack_signed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        #[derive(serde::Serialize)]
        struct AckPayload<'a> {
            #[serde(rename = "keyId")]
            key_id: &'a str,
            #[serde(rename = "upToSeq")]
            up_to_seq: i64,
            #[serde(rename = "signedAt")]
            signed_at: &'a str,
            generation: i64,
            #[serde(rename = "actorDeviceId")]
            actor_device_id: String,
            #[serde(rename = "authGeneration")]
            auth_generation: i64,
            #[serde(rename = "conversationId")]
            conversation_id: String,
        }
        let cbor = serde_ipld_dagcbor::to_vec(&AckPayload {
            key_id: kid,
            up_to_seq: app_seq,
            signed_at: &ack_signed_at,
            generation: 0,
            actor_device_id: dev_id.to_string(),
            auth_generation: 1,
            conversation_id: prune_cid.to_string(),
        })?;
        let ack_sig: Ed25519Signature =
            ed_sk.sign(&[b"CATBIRD-CHAT-ACK-ENTRIES\0".as_slice(), &cbor].concat());
        let ack_jwt = mint_es256_service_jwt(
            p256_sk,
            did,
            &format!("{DS_A_DID}#atproto_mls"),
            "blue.catbird.chat.acknowledgeEntries",
        );
        admin_http
            .post(format!(
                "{}/xrpc/blue.catbird.chat.acknowledgeEntries",
                ds_a.base_url
            ))
            .header("authorization", format!("Bearer {ack_jwt}"))
            .header(CONTENT_TYPE, "application/json")
            .json(&json!({
                "conversationId": prune_cid,
                "generation": 0,
                "actorDeviceId": dev_id,
                "keyId": kid,
                "authGeneration": 1,
                "upToSeq": app_seq,
                "signedAt": ack_signed_at,
                "signature": STANDARD.encode(ack_sig.to_bytes()),
            }))
            .send()
            .await?
            .error_for_status()?;
    }

    let prune_row = ds_a
        .pool
        .query_one(
            "SELECT accepted_payload_bytes IS NULL, payload_pruned_at IS NOT NULL \
               FROM chat.entries WHERE conversation_id = $1 AND seq = $2",
            &[&prune_cid, &app_seq],
        )
        .await?;
    let pruned_payload_null: bool = prune_row.get(0);
    let pruned_at_set: bool = prune_row.get(1);
    assert!(
        pruned_payload_null && pruned_at_set,
        "I14/G6: applicationEntry ciphertext MUST be pruned immediately once all active leaf devices ACK"
    );

    let seq_rows = ds_a
        .pool
        .query(
            "SELECT seq FROM chat.entries WHERE conversation_id = $1 ORDER BY seq ASC",
            &[&prune_cid],
        )
        .await?;
    let seqs: Vec<i64> = seq_rows.into_iter().map(|r| r.get(0)).collect();
    assert_eq!(
        seqs,
        (1..=app_seq).collect::<Vec<_>>(),
        "I14: entry sequence numbers 1..N must remain strictly contiguous after ciphertext pruning"
    );

    // Close & wipe `convo_id` on `ds-b`: prove active conversation refuses premature wipe,
    // `notifySpaceDeleted` fans out (`410 SpaceDeleted`), and operational rows are wiped!
    let wipe_res: Value = admin_http
        .post(format!(
            "{}/_test/clean-slate/close-and-wipe-conversation",
            ds_b.base_url
        ))
        .json(&json!({ "conversationId": convo_id }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(wipe_res["refusedWhileActive"], true);
    assert!(wipe_res["notifiedSpaceDeleted"].as_u64().unwrap() >= 2);
    assert_eq!(wipe_res["wiped"], true);

    let remaining_entries_b: i64 = ds_b
        .pool
        .query_one(
            "SELECT COUNT(*) FROM chat.entries WHERE conversation_id = $1",
            &[&convo_id],
        )
        .await?
        .get(0);
    assert_eq!(
        remaining_entries_b, 0,
        "G6/I14: chat.wipe_closed_conversation_operational_rows must wipe all operational entries"
    );

    // Verify `swan_pds` and `ref_pds` received `notifySpaceDeleted` and now return `410 SpaceDeleted`
    for pds_url in [&swan_pds.base_url, &ref_pds.base_url] {
        let del_resp = admin_http
            .get(format!(
                "{pds_url}/xrpc/com.atproto.space.getSpace?space={}",
                urlencoding::encode(&space_uri)
            ))
            .header("authorization", "Bearer check")
            .send()
            .await?;
        assert_eq!(del_resp.status(), reqwest::StatusCode::GONE);
    }

    // Account deletion on `ds-a`: wipes `labyrinth.epoch_heads` while preserving `labyrinth.epoch_head_floors` (`Gate 6`)
    let del_acct: Value = admin_http
        .post(format!(
            "{}/_test/clean-slate/delete-account",
            ds_a.base_url
        ))
        .json(&json!({ "did": alice_remote_did }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(del_acct["deleted"], true);
    let alice_heads_after: i64 = ds_a
        .pool
        .query_one(
            "SELECT COUNT(*) FROM labyrinth.epoch_heads WHERE did = $1",
            &[&alice_remote_did],
        )
        .await?
        .get(0);
    let alice_floors_after: i64 = ds_a
        .pool
        .query_one(
            "SELECT COUNT(*) FROM labyrinth.epoch_head_floors WHERE did = $1",
            &[&alice_remote_did],
        )
        .await?
        .get(0);
    assert_eq!(
        alice_heads_after, 0,
        "deleteAccountData must purge epoch_heads"
    );
    assert_eq!(
        alice_floors_after, 1,
        "Gate 6: deleteAccountData MUST preserve epoch_head_floors rollback floor"
    );

    // Final `G6` / `I14` PostgreSQL catalog scan across BOTH `ds-a` and `ds-b`:
    for ds in [&ds_a, &ds_b] {
        let blob_tables: i64 = ds
            .pool
            .query_one(
                "SELECT COUNT(*) FROM information_schema.tables \
                  WHERE table_schema = 'chat' AND table_name LIKE 'blob%'",
                &[],
            )
            .await?
            .get(0);
        assert_eq!(
            blob_tables, 0,
            "G6: zero chat.blob* tables on {}",
            ds.service_did
        );

        let push_token_cols: i64 = ds
            .pool
            .query_one(
                "SELECT COUNT(*) FROM information_schema.columns \
                  WHERE table_schema IN ('public', 'chat', 'labyrinth') \
                    AND column_name LIKE '%push_token%'",
                &[],
            )
            .await?
            .get(0);
        assert_eq!(
            push_token_cols, 0,
            "I12: zero raw push_token columns on {}",
            ds.service_did
        );

        let lab_rows = ds
            .pool
            .query(
                "SELECT table_name FROM information_schema.tables \
                  WHERE table_schema = 'labyrinth' ORDER BY table_name ASC",
                &[],
            )
            .await?;
        let mut lab_tables: Vec<String> = lab_rows.into_iter().map(|r| r.get(0)).collect();
        lab_tables.sort();
        assert_eq!(
            lab_tables,
            vec!["epoch_head_floors", "epoch_heads", "operations"],
            "G6: labyrinth schema on {} must contain strictly epoch_heads, epoch_head_floors, operations",
            ds.service_did
        );

        let pub_rows = ds
            .pool
            .query(
                "SELECT table_name FROM information_schema.tables \
                  WHERE table_schema = 'public' ORDER BY table_name ASC",
                &[],
            )
            .await?;
        let pub_tables: Vec<String> = pub_rows.into_iter().map(|r| r.get(0)).collect();
        assert_eq!(
            pub_tables,
            vec![
                "_sqlx_migrations",
                "auth_jti_nonce",
                "did_ds_mappings",
                "ds_endpoints",
                "federation_outbox",
                "federation_peer_policy_audit_log",
                "federation_peers",
                "federation_sync_state",
                "outbound_queue",
            ],
            "G6: public schema on {} must hold strictly S2S federation/nonce tables + _sqlx_migrations",
            ds.service_did
        );
    }

    let _ = &ds_a.db_url;
    Ok(())
}
