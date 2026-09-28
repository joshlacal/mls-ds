//! Debug-only synthetic session/PDS gateway to the real guarded delivery service.
#[cfg(not(debug_assertions))]
compile_error!("client_runtime_gateway must never be built in release mode");

use anyhow::{ensure, Context, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use mls_e2e_tests::local_runtime_fixture::{
    connect_guarded_request_database, seed_service_device, HttpsDidFixture, ServiceIdentity,
    ShippingServerFixture,
};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    future::IntoFuture,
    io::{BufRead, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;
const INPUT_MAX: usize = 16 * 1024 * 1024;
const OUTPUT_MAX: usize = 32 * 1024 * 1024;
const COLLECTION: &str = "blue.catbird.chat.device";
const CID: &str = "bafkreigh2akiscaildc5uysbroqbuq43uqudpjxckcmchwwyk7r6xnsgma";
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Config {
    output_dir: PathBuf,
    cors_origin: String,
    #[serde(default = "lifetime")]
    lifetime_seconds: u64,
    #[serde(default)]
    foreign_bob_authority: bool,
    #[serde(default)]
    withhold_first_foreign_prepare_response: bool,
    #[serde(
        default,
        alias = "two_authorities",
        alias = "two_authority_mode",
        alias = "two_authority",
        alias = "federated_two_authority"
    )]
    two_authority_federation: bool,
}
fn lifetime() -> u64 {
    1800
}
fn validate_config(c: &Config) -> Result<()> {
    ensure!(
        c.output_dir.is_absolute() && !c.output_dir.exists(),
        "output directory must be new and absolute"
    );
    ensure!(
        (1..=3600).contains(&c.lifetime_seconds),
        "lifetime must be 1..3600 seconds"
    );
    ensure!(
        !c.withhold_first_foreign_prepare_response || c.foreign_bob_authority,
        "response loss requires foreign Bob authority"
    );
    ensure!(
        !c.two_authority_federation || !c.foreign_bob_authority,
        "two_authority_federation and foreign_bob_authority are mutually exclusive"
    );
    ensure!(
        !c.two_authority_federation || !c.withhold_first_foreign_prepare_response,
        "response loss is only valid for foreign_bob_authority mode"
    );
    let u = url::Url::parse(&c.cors_origin)?;
    ensure!(
        matches!(u.scheme(), "http" | "https")
            && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none()
            && u.path() == "/"
            && u.origin().ascii_serialization() == c.cors_origin,
        "CORS must be one exact loopback origin without path"
    );
    Ok(())
}
fn protected_write(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}
struct Actor {
    identity: ServiceIdentity,
    session: String,
    records: Mutex<BTreeMap<String, Value>>,
    blocks: Mutex<BTreeMap<String, Value>>,
    seeded: Mutex<Option<Vec<u8>>>,
}
struct Proxy {
    actors: Vec<Arc<Actor>>,
    documents: Mutex<BTreeMap<String, Value>>,
    service: Mutex<Option<String>>,
    actor_services: BTreeMap<String, String>,
    actor_db_urls: BTreeMap<String, String>,
    two_authority_federation: bool,
    ds1_did: String,
    ds2_did: String,
    http: reqwest::Client,
    origin: String,
    foreign_recipient_did: Option<String>,
    withhold_first_foreign_prepare_response: AtomicBool,
    https_root: Option<PathBuf>,
}
const MAINTENANCE_URL: &str = "postgresql://127.0.0.1:5432/postgres";

struct DedicatedDatabase(String);

impl Drop for DedicatedDatabase {
    fn drop(&mut self) {
        let name = &self.0;
        let _ = psql_maintenance(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{name}' AND pid<>pg_backend_pid()"
        ));
        let _ = psql_maintenance(&format!("DROP DATABASE IF EXISTS {name}"));
    }
}

fn psql_maintenance(sql: &str) -> Result<()> {
    let output = Command::new("psql")
        .args([MAINTENANCE_URL, "-X", "-q", "-v", "ON_ERROR_STOP=1", "-c", sql])
        .output()?;
    ensure!(
        output.status.success(),
        "psql maintenance failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn psql_on(db_url: &str, sql: &str) -> Result<()> {
    let output = Command::new("psql")
        .args([db_url, "-X", "-q", "-v", "ON_ERROR_STOP=1", "-c", sql])
        .output()?;
    ensure!(
        output.status.success(),
        "psql on {db_url} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn psql_value(db_url: &str, sql: &str) -> Result<String> {
    let output = Command::new("psql")
        .args([db_url, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql])
        .output()?;
    ensure!(
        output.status.success(),
        "psql query failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn create_database_clone(source: &str, target: &str) -> Result<DedicatedDatabase> {
    psql_maintenance(&format!("CREATE DATABASE {target} TEMPLATE {source}"))?;
    Ok(DedicatedDatabase(target.to_string()))
}

fn bootstrap_federation_tables(db_url: &str) -> Result<()> {
    psql_on(
        db_url,
        "CREATE TABLE IF NOT EXISTS ds_endpoints( \
            did TEXT PRIMARY KEY, endpoint TEXT NOT NULL, supported_cipher_suites TEXT, \
            resolved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
            expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour')",
    )?;
    psql_on(
        db_url,
        "CREATE TABLE IF NOT EXISTS outbound_queue( \
            id TEXT PRIMARY KEY, target_ds_did TEXT NOT NULL, target_endpoint TEXT NOT NULL, \
            method TEXT NOT NULL, payload BYTEA NOT NULL, convo_id TEXT NOT NULL, \
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
            next_retry_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
            retry_count INTEGER NOT NULL DEFAULT 0, max_retries INTEGER NOT NULL DEFAULT 5, \
            last_error TEXT, status TEXT NOT NULL DEFAULT 'pending')",
    )?;
    for migration in [
        include_str!("../../server/migrations/20260214000001_federation_peer_policy.sql"),
        include_str!("../../server/migrations/20260214000002_auth_jti_nonce.sql"),
        include_str!("../../server/migrations/20260222000001_federation_peer_policy_audit_log.sql"),
    ] {
        psql_on(db_url, migration)?;
    }
    Ok(())
}

fn prepare_dedicated_federation_database(db_url: &str) -> Result<()> {
    if psql_value(db_url, "SELECT to_regclass('chat.direct_request_remote_leases') IS NULL")? == "t" {
        psql_on(
            db_url,
            include_str!("../../server/migrations/20260919000022_federated_transport_inbox.sql"),
        )?;
    }
    if psql_value(
        db_url,
        "SELECT to_regclass('chat.direct_request_outbound_routes_actor_recent') IS NULL",
    )? == "t"
    {
        psql_on(
            db_url,
            include_str!("../../server/migrations/20260919000023_expired_federated_lease_release.sql"),
        )?;
    }
    psql_on(
        db_url,
        include_str!("../../server/migrations/20260919000024_c33_coordinator_hardening.sql"),
    )?;
    psql_on(
        db_url,
        include_str!("../../server/migrations/20260919000025_federated_inventory_conversation_items.sql"),
    )?;
    bootstrap_federation_tables(db_url)?;
    psql_on(db_url, "TRUNCATE chat.direct_request_receipt_keys")?;
    let cursor_key_id = psql_value(
        db_url,
        "SELECT cursor_key_id FROM chat.protocol_instances WHERE singleton=TRUE",
    ).unwrap_or_default();
    if cursor_key_id.is_empty() {
        let key = URL_SAFE_NO_PAD.encode([0xC1_u8; 32]);
        psql_on(
            db_url,
            &format!(
                "BEGIN; \
                 INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) \
                 VALUES(TRUE,'1','00000000-0000-4000-8000-000000000001','{key}') \
                 ON CONFLICT(singleton) DO NOTHING; \
                 INSERT INTO chat.event_retention(protocol_instance_id,retained_floor,updated_at) \
                 SELECT protocol_instance_id,0,clock_timestamp() FROM chat.protocol_instances WHERE singleton=TRUE \
                 ON CONFLICT(protocol_instance_id) DO NOTHING; COMMIT;",
            ),
        )?;
    }
    Ok(())
}

fn quote(part: &str) -> String {
    part.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"_.-~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn jwk_thumbprint(jwk: &Value) -> Result<String> {
    let canonical = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk["x"].as_str().context("JWK x")?,
        jwk["y"].as_str().context("JWK y")?
    );
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

fn seed_into_dedicated_database(
    db_url: &str,
    identity: &ServiceIdentity,
    mls_public_key: &[u8],
) -> Result<()> {
    let jkt = jwk_thumbprint(&identity.jwt_jwk)?;
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(mls_public_key));
    let public_hex = hex::encode(mls_public_key);
    psql_on(
        db_url,
        &format!(
            "BEGIN; \
             INSERT INTO chat.principals(user_did,created_at) VALUES('{did}',clock_timestamp()) ON CONFLICT DO NOTHING; \
             INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
             VALUES('{did}','{device}','c33-gateway-fixture','active','{jkt}',1,chat.protocol_capabilities(),clock_timestamp(),clock_timestamp()) \
             ON CONFLICT(user_did,device_id) DO NOTHING; \
             INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
             VALUES('{did}','{device}','{key_id}',decode('{public_hex}','hex'),1,clock_timestamp()) \
             ON CONFLICT(user_did,device_id,key_id) DO NOTHING; COMMIT;",
            did = identity.did,
            device = identity.device_id,
        ),
    )?;
    Ok(())
}

fn sync_device_key_policy(root: &Path, did: &str, key: &[u8]) {
    let dir = root.join("_policy").join("deviceKeys");
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(
        dir.join(quote(did)),
        serde_json::to_vec(&json!({
            "records": [{
                "value": {
                    "algorithm": "ed25519",
                    "mlsSignaturePublicKey": {"$bytes": STANDARD.encode(key)},
                    "createdAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                }
            }]
        })).unwrap_or_default(),
    );
}

fn ds_did_document(
    did: &str,
    server_url: &str,
    seed_byte: u8,
) -> Result<(Value, Vec<u8>, String)> {
    let receipt_key = SigningKey::from_bytes((&[seed_byte; 32]).into())?;
    let service_key = SigningKey::from_bytes((&[seed_byte + 1; 32]).into())?;
    let receipt_point = receipt_key.verifying_key().to_encoded_point(true);
    let receipt_key_id = format!(
        "{}#chat-request-receipt-{}",
        did,
        hex::encode(Sha256::digest(receipt_point.as_bytes()))
    );

    let mut multikey = vec![0x80, 0x24];
    multikey.extend_from_slice(receipt_point.as_bytes());

    let service_point = service_key.verifying_key().to_encoded_point(false);
    let service_jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(service_point.x().expect("P256 x")),
        "y": URL_SAFE_NO_PAD.encode(service_point.y().expect("P256 y"))
    });

    let doc = json!({
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{did}#atproto"),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": service_jwk
            },
            {
                "id": receipt_key_id.clone(),
                "controller": did,
                "type": "Multikey",
                "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, multikey)
            }
        ],
        "service": [{
            "id": format!("{did}#atproto_mls"),
            "type": "AtprotoMLSDeliveryService",
            "serviceEndpoint": server_url
        }]
    });
    let receipt_public_key = receipt_point.as_bytes().to_vec();
    Ok((doc, receipt_public_key, receipt_key_id))
}

fn declare_chat_authority(root: &Path, did: &str, delivery_service: &str) -> Result<()> {
    let dir = root.join("_policy").join("catbirdDeclaration");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join(quote(did)),
        serde_json::to_vec(&json!({
            "$type": "blue.catbird.chat.declaration",
            "allowIncoming": "all",
            "deliveryService": delivery_service,
            "protocolVersion": "1",
            "createdAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        }))?,
    )?;
    Ok(())
}

fn home_document(identity: &ServiceIdentity, endpoint: &str) -> Value {
    let mut doc = identity.did_document();
    if let Some(services) = doc["service"].as_array_mut() {
        services.push(json!({
            "id": format!("{}#atproto_mls", identity.did),
            "type": "AtprotoMLSDeliveryService",
            "serviceEndpoint": endpoint
        }));
    }
    doc
}

fn resolve_server_fixture_binary(require_env_sha: bool) -> Result<(PathBuf, String)> {
    let binary = std::env::var("REQUEST_SERVER_FIXTURE_BINARY")
        .map(PathBuf::from)
        .or_else(|_| {
            let mut path = std::env::current_exe()?;
            path.pop();
            path.push("encrypted_request_server_fixture");
            if path.exists() {
                Ok(path)
            } else {
                anyhow::bail!(
                    "REQUEST_SERVER_FIXTURE_BINARY not set and encrypted_request_server_fixture not found next to current exe"
                );
            }
        })?;
    ensure!(binary.is_file(), "server fixture binary not found at {:?}", binary);
    let bytes = std::fs::read(&binary)?;
    let actual_sha = hex::encode(Sha256::digest(&bytes));
    let expected_sha_env = std::env::var("REQUEST_SERVER_FIXTURE_SHA256")
        .or_else(|_| std::env::var("FINAL_SERVER_SHA256"))
        .or_else(|_| std::env::var("FINAL_REQUEST_SERVER_FIXTURE_SHA256"))
        .or_else(|_| std::env::var("EXPECTED_SERVER_FIXTURE_SHA256"))
        .ok();
    if require_env_sha {
        let expected_sha = expected_sha_env.context(
            "two-authority federation requires REQUEST_SERVER_FIXTURE_SHA256 or FINAL_SERVER_SHA256 environment variable set to current rebuilt server fixture SHA-256"
        )?;
        ensure!(
            actual_sha.eq_ignore_ascii_case(&expected_sha),
            "server fixture SHA-256 mismatch: actual {actual_sha} != expected {expected_sha}"
        );
    } else if let Some(expected_sha) = expected_sha_env {
        ensure!(
            actual_sha.eq_ignore_ascii_case(&expected_sha),
            "server fixture SHA-256 mismatch: actual {actual_sha} != expected {expected_sha}"
        );
    }
    Ok((binary, actual_sha))
}

fn spawn_server_fixture(
    binary: &Path,
    did: &str,
    port: u16,
    db_url: &str,
    https: &HttpsDidFixture,
    seed_byte: u8,
    receipt_document: &[u8],
) -> Result<(Child, String)> {
    let self_endpoint = format!("http://127.0.0.1:{port}");
    let receipt_key = SigningKey::from_bytes((&[seed_byte; 32]).into())?;
    let service_key = SigningKey::from_bytes((&[seed_byte + 1; 32]).into())?;
    let cursor_key_id = psql_value(
        db_url,
        "SELECT cursor_key_id FROM chat.protocol_instances WHERE singleton=TRUE",
    )?;
    ensure!(!cursor_key_id.is_empty(), "fixture database lacks protocol identity");

    let mut command = Command::new(binary);
    command
        .env("TEST_DATABASE_URL", db_url)
        .env("SERVICE_DID", did)
        .env("REQUEST_FIXTURE_LISTEN", format!("127.0.0.1:{port}"))
        .env("SELF_ENDPOINT", &self_endpoint)
        .env("REQUEST_FIXTURE_DID_HOSTS", https.hosts.join(","))
        .env("REQUEST_FIXTURE_DID_PORT", https.port.to_string())
        .env("REQUEST_FIXTURE_DID_CA_PEM", &https.ca_pem)
        .env("DID_RESOLUTION_HOST_ALLOWLIST", https.hosts.join(","))
        .env("CHAT_CUTOVER_ENABLED", "1")
        .env("CHAT_DIRECT_REQUESTS_ENABLED", "1")
        .env("CHAT_SUBSCRIPTION_ENDPOINT", "wss://chat.example.test/xrpc/blue.catbird.chat.subscribeEvents")
        .env("FEDERATION_ALLOW_INSECURE_HTTP", "true")
        .env("FEDERATION_MODE", "open_intelligent")
        .env("CHAT_CURSOR_KEY_ID", &cursor_key_id)
        .env("CHAT_CURSOR_SEALING_SECRET", URL_SAFE_NO_PAD.encode([0xA5_u8; 32]))
        .env(
            "CHAT_REQUEST_RECEIPT_SIGNING_KEY_PEM",
            receipt_key.to_pkcs8_pem(LineEnding::LF)?.as_str(),
        )
        .env(
            "SIGNING_KEY_PEM",
            service_key.to_pkcs8_pem(LineEnding::LF)?.as_str(),
        )
        .env(
            "CHAT_REQUEST_RECEIPT_DID_DOCUMENT_JSON",
            String::from_utf8(receipt_document.to_vec())?,
        )
        .env("REQUEST_FIXTURE_OUTBOUND_WORKER", "1")
        .env("OUTBOUND_QUEUE_TICK_INTERVAL_MS", "100")
        .env("OUTBOUND_QUEUE_RETRY_DELAY_MS", "200")
        .env("RUST_LOG", "warn")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let mut child = command.spawn().context("spawn server fixture")?;
    let mut reader = std::io::BufReader::new(child.stdout.take().context("take server stdout")?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let ready: Value = serde_json::from_str(&line)?;
    let base_url = ready["baseUrl"].as_str().context("missing baseUrl")?.to_owned();
    ensure!(
        base_url == self_endpoint,
        "server fixture bound to {base_url} but expected {self_endpoint}"
    );
    Ok((child, base_url))
}
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn profile(actor: &Actor) -> Value {
    let label = actor
        .identity
        .did
        .trim_start_matches("did:web:")
        .split('-')
        .next()
        .unwrap_or("Synthetic");
    json!({"did":actor.identity.did,"handle":actor.identity.did.trim_start_matches("did:web:"),"displayName":format!("{label} request fixture"),"description":"Synthetic local request qualification account"})
}
fn chat_declaration(authority: &str) -> Value {
    json!({
        "$type": "blue.catbird.chat.declaration",
        "allowIncoming": "all",
        "deliveryService": authority,
        "protocolVersion": "1",
        "createdAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    })
}

fn response(status: StatusCode, value: Value) -> Response {
    (status, axum::Json(value)).into_response()
}
fn error(status: StatusCode, code: &str) -> Response {
    response(status, json!({"error":code}))
}
fn params(query: &str) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        ensure!(
            result.insert(k.into_owned(), v.into_owned()).is_none(),
            "duplicate query field"
        );
    }
    Ok(result)
}
fn actor_for_session(proxy: &Proxy, request: &Request) -> Option<Arc<Actor>> {
    let bearer = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let cookies = request
        .headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let matches = cookies
        .split(';')
        .filter_map(|v| v.trim().strip_prefix("catbird_session="))
        .collect::<Vec<_>>();
    if matches.len() > 1 || bearer.is_some() && matches.first().is_some_and(|v| Some(*v) != bearer)
    {
        return None;
    }
    let token = bearer.or_else(|| matches.first().copied());
    proxy
        .actors
        .iter()
        .find(|a| Some(a.session.as_str()) == token)
        .cloned()
}
fn decode_key(value: &Value) -> Result<Vec<u8>> {
    let s = if value.is_string() {
        value.as_str()
    } else {
        value
            .as_object()
            .filter(|v| v.len() == 1)
            .and_then(|v| v.get("$bytes"))
            .and_then(Value::as_str)
    }
    .context("public key encoding")?;
    let bytes = STANDARD.decode(s)?;
    ensure!(
        bytes.len() == 32 && STANDARD.encode(&bytes) == s,
        "canonical 32-byte key required"
    );
    Ok(bytes)
}
fn declaration(actor: &Actor, device: &str, key: &[u8]) -> Value {
    json!({"uri":format!("at://{}/{COLLECTION}/{device}",actor.identity.did),"cid":CID,"value":{"$type":COLLECTION,"algorithm":"ed25519","createdAt":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis,true),"mlsSignaturePublicKey":{"$bytes":STANDARD.encode(key)}}})
}
fn set_declaration(
    actor: &Actor,
    device: &str,
    key: &[u8],
    supplied: Option<Value>,
) -> Result<Value> {
    ensure!(
        Uuid::parse_str(device)?.get_version_num() == 4
            && Uuid::parse_str(device)?.get_variant() == uuid::Variant::RFC4122
            && Uuid::parse_str(device)?.to_string() == device,
        "canonical v4 device required"
    );
    let mut records = actor.records.lock().unwrap();
    if let Some(old) = records.get(device) {
        ensure!(
            decode_key(&old["value"]["mlsSignaturePublicKey"])? == key,
            "device key replacement forbidden"
        );
        return Ok(old.clone());
    }
    ensure!(records.len() < 16, "fixture device bound exceeded");
    let record = supplied.unwrap_or_else(|| declaration(actor, device, key));
    records.insert(device.to_owned(), record.clone());
    Ok(record)
}
async fn serve(State(proxy): State<Arc<Proxy>>, request: Request) -> Response {
    let origin = request
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if origin.as_ref().is_some_and(|o| o != &proxy.origin) {
        return error(StatusCode::FORBIDDEN, "FixtureOriginMismatch");
    }
    let preflight = request.method() == Method::OPTIONS;
    let mut result = if preflight {
        let method = request
            .headers()
            .get("access-control-request-method")
            .and_then(|v| v.to_str().ok());
        let headers = request
            .headers()
            .get("access-control-request-headers")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if origin.is_none()
            || !matches!(method, Some("GET" | "POST"))
            || headers
                .split(',')
                .map(|v| v.trim().to_ascii_lowercase())
                .any(|h| {
                    !h.is_empty()
                        && !["authorization", "content-type", "atproto-proxy"].contains(&h.as_str())
                })
        {
            error(StatusCode::FORBIDDEN, "InvalidPreflight")
        } else {
            StatusCode::NO_CONTENT.into_response()
        }
    } else {
        serve_inner(&proxy, request).await
    };
    if origin.is_some() {
        let h = result.headers_mut();
        h.insert("access-control-allow-origin", proxy.origin.parse().unwrap());
        h.insert("access-control-allow-credentials", "true".parse().unwrap());
        h.insert("vary", "Origin".parse().unwrap());
        h.insert(
            "access-control-allow-methods",
            "GET, POST, OPTIONS".parse().unwrap(),
        );
        h.insert(
            "access-control-allow-headers",
            "authorization, content-type, atproto-proxy"
                .parse()
                .unwrap(),
        );
    }
    result
}
async fn serve_inner(proxy: &Proxy, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or("").to_owned();
    if query.len() > 8192 {
        return error(StatusCode::URI_TOO_LONG, "TooLarge");
    }
    let host = request
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_owned();
    if !proxy.documents.lock().unwrap().contains_key(&host) {
        return error(StatusCode::BAD_REQUEST, "FixtureHostMismatch");
    }
    // Fixture evidence records endpoint names only, never query, auth or body.
    if path.starts_with("/xrpc/") {
        eprintln!(
            "fixture-xrpc-path-only {:?}",
            if path.len() <= 256 { path.as_str() } else { "<overlong>" }
        );
    }
    let method = request.method().clone();
    if path == "/.well-known/did.json" && method == Method::GET {
        return response(
            StatusCode::OK,
            proxy.documents.lock().unwrap()[&host].clone(),
        );
    }
    // Canonical XRPC arrays deliberately repeat keys (for example protocol
    // versions). Forward those exact query bytes to the shipping parser.
    let q = if path.starts_with("/xrpc/blue.catbird.chat.")
        || path == "/xrpc/app.bsky.actor.getProfiles"
    {
        BTreeMap::new()
    } else {
        match params(&query) {
            Ok(q) => q,
            Err(_) => return error(StatusCode::BAD_REQUEST, "InvalidQuery"),
        }
    };
    let public_actor = proxy.actors.iter().find(|a| {
        host == a.identity.did.trim_start_matches("did:web:")
            && q.get("repo") == Some(&a.identity.did)
    });
    if path == "/xrpc/com.atproto.repo.listRecords" && method == Method::GET {
        let owned_actor = public_actor.or_else(|| {
            let session = actor_for_session(proxy, &request)?;
            proxy
                .actors
                .iter()
                .find(|a| a.identity.did == session.identity.did && q.get("repo") == Some(&a.identity.did))
        });
        let Some(a) = owned_actor else {
            return error(StatusCode::FORBIDDEN, "InvalidRepo");
        };
        let coll = q.get("collection").map(String::as_str);
        if !matches!(coll, Some(COLLECTION) | Some("app.bsky.graph.block"))
            || q.keys()
                .any(|k| !["repo", "collection", "limit", "cursor"].contains(&k.as_str()))
            || q.get("limit")
                .is_some_and(|s| s.parse::<usize>().map_or(true, |n| !(1..=100).contains(&n)))
        {
            return error(StatusCode::BAD_REQUEST, "InvalidQuery");
        }
        if coll == Some("app.bsky.graph.block") {
            let recs: Vec<Value> = a.blocks.lock().unwrap().values().cloned().collect();
            return response(StatusCode::OK, json!({"records": recs}));
        }
        return response(
            StatusCode::OK,
            json!({"records":a.records.lock().unwrap().values().cloned().collect::<Vec<_>>()}),
        );
    }
    if path == "/xrpc/com.atproto.repo.getRecord" && method == Method::GET {
        if public_actor.is_none()
            || q.get("rkey").map(String::as_str) != Some("self")
            || q.len() != 3
        {
            return error(StatusCode::BAD_REQUEST, "InvalidQuery");
        }
        if q.get("collection").map(String::as_str) == Some("chat.bsky.actor.declaration") {
            return response(
                StatusCode::OK,
                json!({"uri":format!("at://{}/chat.bsky.actor.declaration/self",q["repo"]),"value":{"$type":"chat.bsky.actor.declaration","allowIncoming":"all"}}),
            );
        }
        if q.get("collection").map(String::as_str) == Some("blue.catbird.chat.declaration") {
            let authority = if proxy.two_authority_federation {
                if q.get("repo").map(String::as_str) == Some(proxy.actors[0].identity.did.as_str()) {
                    &proxy.ds1_did
                } else if q.get("repo").map(String::as_str) == Some(proxy.actors[1].identity.did.as_str()) {
                    &proxy.ds2_did
                } else {
                    &proxy.ds1_did
                }
            } else if proxy.foreign_recipient_did.as_deref() == Some(q["repo"].as_str()) {
                "did:web:chat.federated-peer.org"
            } else {
                "did:web:chat.catbird.blue"
            };
            return response(
                StatusCode::OK,
                json!({
                    "uri": format!("at://{}/blue.catbird.chat.declaration/self", q["repo"]),
                    "value": chat_declaration(authority)
                }),
            );
        }
        return error(StatusCode::BAD_REQUEST, "InvalidQuery");
    }
    if path == "/xrpc/app.bsky.graph.getRelationships" && method == Method::GET {
        if !q
            .get("actor")
            .is_some_and(|d| proxy.actors.iter().any(|a| &a.identity.did == d))
            || !q
                .get("others")
                .is_some_and(|d| proxy.actors.iter().any(|a| &a.identity.did == d))
            || q.len() != 2
        {
            return error(StatusCode::BAD_REQUEST, "InvalidQuery");
        }
        let actor_did = &q["actor"];
        let other_did = &q["others"];
        let actor = proxy.actors.iter().find(|a| &a.identity.did == actor_did).unwrap();
        let blocking_uri = actor.blocks.lock().unwrap().values().find_map(|r| {
            if r["value"]["subject"] == *other_did {
                r["uri"].as_str().map(str::to_owned)
            } else {
                None
            }
        });
        let mut rel = json!({"$type":"app.bsky.graph.defs#relationship","did":other_did});
        if let Some(uri) = blocking_uri {
            rel["blocking"] = json!(uri);
        }
        return response(
            StatusCode::OK,
            json!({"actor":actor_did,"relationships":[rel]}),
        );
    }
    let Some(actor) = actor_for_session(proxy, &request) else {
        return error(StatusCode::UNAUTHORIZED, "AuthenticationRequired");
    };
    if path == "/auth/session" && method == Method::GET {
        return response(
            StatusCode::OK,
            json!({"did":actor.identity.did,"handle":actor.identity.did.trim_start_matches("did:web:")}),
        );
    }
    if path == "/xrpc/app.bsky.actor.getProfiles" && method == Method::GET {
        let values = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect::<Vec<_>>();
        if values.is_empty()
            || values.len() > 25
            || values
                .iter()
                .any(|(k, v)| k != "actors" || !proxy.actors.iter().any(|a| &a.identity.did == v))
        {
            return error(StatusCode::BAD_REQUEST, "InvalidFixtureProfiles");
        }
        return response(
            StatusCode::OK,
            json!({"profiles":values.iter().map(|(_,did)|profile(proxy.actors.iter().find(|a|&a.identity.did==did).unwrap())).collect::<Vec<_>>()}),
        );
    }
    if matches!(
        path.as_str(),
        "/xrpc/app.bsky.actor.searchActors" | "/xrpc/app.bsky.actor.searchActorsTypeahead"
    ) && method == Method::GET
    {
        if q.keys().any(|k| !["q", "limit"].contains(&k.as_str()))
            || q.get("q").is_none_or(|v| v.len() > 256)
            || q.get("limit")
                .is_some_and(|v| v.parse::<usize>().map_or(true, |n| !(1..=100).contains(&n)))
        {
            return error(StatusCode::BAD_REQUEST, "InvalidFixtureSearch");
        }
        let term = q["q"].to_ascii_lowercase();
        let limit = q.get("limit").and_then(|v| v.parse().ok()).unwrap_or(25);
        return response(
            StatusCode::OK,
            json!({"actors":proxy.actors.iter().filter(|a|a.identity.did.contains(&term)).take(limit).map(|a|profile(a)).collect::<Vec<_>>()}),
        );
    }
    if path == "/xrpc/app.bsky.actor.getProfile" && method == Method::GET {
        let Some(a) = proxy
            .actors
            .iter()
            .find(|a| q.get("actor") == Some(&a.identity.did))
        else {
            return error(StatusCode::NOT_FOUND, "UnknownActor");
        };
        return response(StatusCode::OK, profile(a));
    }
    if path == "/xrpc/app.bsky.graph.getBlocks" && method == Method::GET {
        let Some(actor) = actor_for_session(proxy, &request) else {
            return error(StatusCode::UNAUTHORIZED, "AuthenticationRequired");
        };
        let blocks_map = actor.blocks.lock().unwrap();
        let blocks: Vec<Value> = blocks_map
            .values()
            .filter_map(|r| {
                let subject = r["value"]["subject"].as_str()?;
                let a = proxy.actors.iter().find(|a| a.identity.did == subject)?;
                Some(profile(a))
            })
            .collect();
        return response(StatusCode::OK, json!({"blocks": blocks}));
    }
    if path == "/xrpc/app.bsky.actor.getPreferences" && method == Method::GET {
        return response(StatusCode::OK, json!({"preferences":[]}));
    }
    if path == "/xrpc/chat.bsky.convo.listConvos" && method == Method::GET {
        return response(StatusCode::OK, json!({"convos":[]}));
    }
    if !matches!(method, Method::GET | Method::POST) {
        return error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed");
    }
    let bytes = match to_bytes(request.into_body(), INPUT_MAX).await {
        Ok(b) => b,
        Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "TooLarge"),
    };
    if method == Method::GET && !bytes.is_empty() {
        return error(StatusCode::BAD_REQUEST, "GetBodyForbidden");
    }
    if matches!(
        path.as_str(),
        "/fixture/enroll" | "/xrpc/com.atproto.repo.putRecord" | "/xrpc/com.atproto.repo.createRecord" | "/xrpc/com.atproto.repo.deleteRecord"
    ) && catbird_mls::chat_v2::transcript::decode_strict_json(&bytes).is_err()
    {
        return error(StatusCode::BAD_REQUEST, "InvalidJson");
    }
    // Bluesky block published before a request is closed ("Block and Close").
    // Only the authenticated actor may block a known fixture actor.
    if path == "/xrpc/com.atproto.repo.createRecord" && method == Method::POST {
        let Ok(v) = serde_json::from_slice::<Value>(&bytes) else {
            return error(StatusCode::BAD_REQUEST, "InvalidJson");
        };
        let known = |did: &Value| {
            did.as_str().is_some_and(|d| proxy.actors.iter().any(|a| a.identity.did == d))
        };
        let subject = v["record"]["subject"].as_str().unwrap_or("");
        eprintln!(
            "createRecord check: repo={:?} actor={:?} coll={:?} type={:?} subject={:?} known={:?}",
            v["repo"].as_str(),
            Some(actor.identity.did.as_str()),
            v["collection"].as_str(),
            v["record"]["$type"].as_str(),
            subject,
            known(&v["record"]["subject"]),
        );
        if v["repo"].as_str() != Some(actor.identity.did.as_str())
            || v["collection"].as_str() != Some("app.bsky.graph.block")
            || v["record"]["$type"].as_str() != Some("app.bsky.graph.block")
            || !known(&v["record"]["subject"])
            || subject == actor.identity.did
            || v["record"]["createdAt"].as_str().is_none()
        {
            return error(StatusCode::BAD_REQUEST, "UnsupportedRecord");
        }
        let rkey = uuid::Uuid::new_v4().simple().to_string();
        let uri = format!("at://{}/app.bsky.graph.block/{}", actor.identity.did, rkey);
        let record = json!({
            "uri": uri.clone(),
            "cid": CID,
            "value": v["record"],
        });
        actor.blocks.lock().unwrap().insert(rkey, record);
        return response(
            StatusCode::OK,
            json!({"uri": uri, "cid": CID}),
        );
    }
    if path == "/xrpc/com.atproto.repo.deleteRecord" && method == Method::POST {
        let Ok(v) = serde_json::from_slice::<Value>(&bytes) else {
            return error(StatusCode::BAD_REQUEST, "InvalidJson");
        };
        if v["repo"] != actor.identity.did
            || v["collection"] != "app.bsky.graph.block"
            || v["rkey"].as_str().is_none()
        {
            return error(StatusCode::BAD_REQUEST, "UnsupportedRecord");
        }
        let rkey = v["rkey"].as_str().unwrap();
        actor.blocks.lock().unwrap().remove(rkey);
        return response(StatusCode::OK, json!({}));
    }
    if path == "/fixture/enroll" && method == Method::POST {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Seed {
            device_id: String,
            signature_public_key: Value,
        }
        let Ok(s) = serde_json::from_slice::<Seed>(&bytes) else {
            return error(StatusCode::BAD_REQUEST, "InvalidSeed");
        };
        let Ok(key) = decode_key(&s.signature_public_key) else {
            return error(StatusCode::BAD_REQUEST, "InvalidSeed");
        };
        if s.device_id != actor.identity.device_id.to_string() {
            return error(StatusCode::FORBIDDEN, "ReservedDeviceMismatch");
        }
        let mut seeded = actor.seeded.lock().unwrap();
        if seeded.as_ref().is_some_and(|old| old != &key) {
            return error(StatusCode::CONFLICT, "KeyReplacementForbidden");
        }
        // Validate the immutable public declaration before any test seeding.
        if set_declaration(&actor, &s.device_id, &key, None).is_err() {
            return error(StatusCode::CONFLICT, "DeclarationConflict");
        }
        if let Some(root) = proxy.https_root.as_deref() {
            sync_device_key_policy(root, &actor.identity.did, &key);
        }
        if seeded.is_none() {
            if proxy.two_authority_federation {
                let Some(db_url) = proxy.actor_db_urls.get(&actor.identity.did) else {
                    return error(StatusCode::BAD_GATEWAY, "MissingActorDb");
                };
                if seed_into_dedicated_database(db_url, &actor.identity, &key).is_err() {
                    return error(StatusCode::BAD_GATEWAY, "SeedFailed");
                }
            } else {
                if seed_service_device(&actor.identity, &key).is_err() {
                    return error(StatusCode::BAD_GATEWAY, "SeedFailed");
                }
            }
            *seeded = Some(key.clone());
        }
        return response(
            StatusCode::OK,
            json!({"did":actor.identity.did,"deviceId":s.device_id,"seeded":true}),
        );
    }
    if path == "/xrpc/com.atproto.repo.putRecord" && method == Method::POST {
        let result = (|| -> Result<Value> {
            let v: Value = serde_json::from_slice(&bytes)?;
            let collection = v["collection"].as_str().context("collection")?;
            if collection == "blue.catbird.chat.declaration" {
                return Ok(json!({
                    "uri": format!("at://{}/blue.catbird.chat.declaration/{}", actor.identity.did, v["rkey"].as_str().unwrap_or("self")),
                    "cid": CID,
                }));
            }
            let o = v.as_object().context("object")?;
            ensure!(
                o.keys()
                    .all(|k| ["repo", "collection", "rkey", "swapRecord", "record"]
                        .contains(&k.as_str()))
                    && v["repo"] == actor.identity.did
                    && v["collection"] == COLLECTION
                    && v["swapRecord"].is_null(),
                "record identity"
            );
            let r = v["record"].as_object().context("record")?;
            ensure!(
                r.len() == 4
                    && v["record"]["$type"] == COLLECTION
                    && v["record"]["algorithm"] == "ed25519",
                "record schema"
            );
            chrono::DateTime::parse_from_rfc3339(
                v["record"]["createdAt"].as_str().context("time")?,
            )?;
            let key = decode_key(&v["record"]["mlsSignaturePublicKey"])?;
            let device = v["rkey"].as_str().context("rkey")?;
            let record = set_declaration(
                &actor,
                device,
                &key,
                Some(
                    json!({"uri":format!("at://{}/{COLLECTION}/{device}",actor.identity.did),"cid":CID,"value":v["record"]}),
                ),
            )?;
            if let Some(root) = proxy.https_root.as_deref() {
                sync_device_key_policy(root, &actor.identity.did, &key);
            }
            Ok(record)
        })();
        return match result {
            Ok(r) => response(StatusCode::OK, json!({"uri":r["uri"],"cid":r["cid"]})),
            Err(_) => error(StatusCode::BAD_REQUEST, "InvalidRecord"),
        };
    }
    let Some(nsid) = path
        .strip_prefix("/xrpc/")
        .filter(|s| s.starts_with("blue.catbird.chat."))
    else {
        return error(StatusCode::NOT_FOUND, "UnsupportedFixtureEndpoint");
    };
    if nsid == "blue.catbird.chat.enrollDevice" {
        // Publish only public declaration material. No seed_service_device call:
        // the real shipping handler must verify and create this device itself.
        let result = (|| -> Result<()> {
            ensure!(method == Method::POST, "enrollment method");
            catbird_mls::chat_v2::transcript::decode_strict_json(&bytes)
                .map_err(|_| anyhow::anyhow!("strict enrollment JSON"))?;
            let v: Value = serde_json::from_slice(&bytes)?;
            let b = &v["signedRequest"]["body"];
            ensure!(
                b["actorDid"] == actor.identity.did && b["expectedAuthGeneration"] == 0,
                "enrollment identity"
            );
            let device = b["deviceId"].as_str().context("device")?;
            let key = decode_key(&b["signaturePublicKey"])?;
            set_declaration(&actor, device, &key, None)?;
            if let Some(root) = proxy.https_root.as_deref() {
                sync_device_key_policy(root, &actor.identity.did, &key);
            }
            Ok(())
        })();
        if result.is_err() {
            return error(StatusCode::BAD_REQUEST, "InvalidEnrollmentDeclaration");
        }
    }
    let service = if proxy.two_authority_federation {
        proxy
            .actor_services
            .get(&actor.identity.did)
            .cloned()
            .or_else(|| proxy.service.lock().unwrap().clone())
    } else {
        proxy.service.lock().unwrap().clone()
    };
    let Some(service) = service else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "Starting");
    };
    match actor
        .identity
        .forward_exact_service_request(
            &proxy.http,
            &service,
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
            nsid,
            Some(&query),
            if method == Method::GET {
                None
            } else {
                Some(&bytes)
            },
        )
        .await
    {
        Ok((status, body)) => {
            if nsid == "blue.catbird.chat.prepareDirectRequest"
                && status == reqwest::StatusCode::OK
                && serde_json::from_slice::<Value>(&body)
                    .ok()
                    .is_some_and(|v| v["outcome"]["body"]["receipt"]["code"] == "RecipientAuthorityUnsupported")
                && proxy.withhold_first_foreign_prepare_response.swap(false, Ordering::SeqCst)
            {
                return error(StatusCode::SERVICE_UNAVAILABLE, "FixtureWithheldSignedRefusal");
            }
            Response::builder()
                .status(status.as_u16())
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap()
        }
        Err(_) => error(StatusCode::BAD_GATEWAY, "FixtureUpstreamFailed"),
    }
}
// The signing helper retains private service keys. This intermediary caps the
// response stream before that helper's buffered receive can allocate it.
async fn bounded_forward(
    State((client, upstream)): State<(reqwest::Client, String)>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let raw = match to_bytes(body, INPUT_MAX).await {
        Ok(b) => b,
        Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "TooLarge"),
    };
    let Some(auth) = parts.headers.get("authorization") else {
        return error(StatusCode::UNAUTHORIZED, "AuthenticationRequired");
    };
    let mut call = client
        .request(parts.method, format!("{upstream}{}", parts.uri))
        .header("authorization", auth)
        .header("content-type", "application/json");
    if !raw.is_empty() {
        call = call.body(raw);
    }
    let Ok(mut r) = call.send().await else {
        return error(StatusCode::BAD_GATEWAY, "UpstreamFailed");
    };
    let status = r.status();
    let mut bytes = Vec::new();
    loop {
        match r.chunk().await {
            Ok(Some(c)) if bytes.len() + c.len() <= OUTPUT_MAX => bytes.extend_from_slice(&c),
            Ok(None) => break,
            _ => return error(StatusCode::BAD_GATEWAY, "UpstreamTooLarge"),
        }
    }
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(bytes))
        .unwrap()
}
#[tokio::main]
async fn main() -> Result<()> {
    let mut input = Vec::new();
    std::io::stdin().take(16385).read_to_end(&mut input)?;
    ensure!(input.len() <= 16384, "configuration exceeds 16 KiB");
    let config: Config = serde_json::from_slice(&input)?;
    validate_config(&config)?;
    if !config.two_authority_federation {
        connect_guarded_request_database(5).await?;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&config.output_dir)?;
        let run = Uuid::new_v4().simple().to_string();
        let gateway = format!("gateway-{run}.request-fixture.catbird.blue");
        let actors = ["alice", "bob"]
            .into_iter()
            .map(|label| {
                Arc::new(Actor {
                    identity: ServiceIdentity::new(format!(
                        "did:web:{label}-{run}.request-fixture.catbird.blue"
                    )),
                    session: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
                    records: Mutex::new(BTreeMap::new()),
                    blocks: Mutex::new(BTreeMap::new()),
                    seeded: Mutex::new(None),
                })
            })
            .collect::<Vec<_>>();
        let mut docs = actors
            .iter()
            .map(|a| (a.identity.did.clone(), a.identity.did_document()))
            .collect::<Vec<_>>();
        docs.push((
            "did:web:chat.catbird.blue".into(),
            json!({"id":"did:web:chat.catbird.blue"}),
        ));
        docs.push((
            format!("did:web:{gateway}"),
            json!({"id":format!("did:web:{gateway}")}),
        ));
        let mut https = HttpsDidFixture::start(HttpsDidFixture::reserve_port()?, &docs)?;
        if config.foreign_bob_authority {
            let directory = https.root.join("_policy").join("catbirdDeclaration");
            std::fs::create_dir_all(&directory)?;
            let bob = &actors[1].identity.did;
            let encoded = url::form_urlencoded::byte_serialize(bob.as_bytes()).collect::<String>();
            std::fs::write(
                directory.join(encoded),
                serde_json::to_vec(&chat_declaration("did:web:chat.federated-peer.org"))?,
            )?;
        }
        let tls_port = HttpsDidFixture::reserve_port()?;
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(40))
            .build()?;
        let mut documents = docs
            .into_iter()
            .map(|(did, v)| (did.trim_start_matches("did:web:").to_owned(), v))
            .collect::<BTreeMap<_, _>>();
        for h in &https.hosts {
            documents
                .entry(h.clone())
                .or_insert_with(|| json!({"id":format!("did:web:{h}")}));
        }
        let proxy = Arc::new(Proxy {
            foreign_recipient_did: config.foreign_bob_authority.then(|| actors[1].identity.did.clone()),
            withhold_first_foreign_prepare_response: AtomicBool::new(config.withhold_first_foreign_prepare_response),
            actors,
            documents: Mutex::new(documents),
            service: Mutex::new(None),
            actor_services: BTreeMap::new(),
            actor_db_urls: BTreeMap::new(),
            two_authority_federation: false,
            ds1_did: String::new(),
            ds2_did: String::new(),
            http: http.clone(),
            origin: config.cors_origin.clone(),
            https_root: Some(https.root.clone()),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let upstream = listener.local_addr()?.port();
        let gateway_task = tokio::spawn(
            axum::serve(
                listener,
                Router::new().fallback(serve).with_state(proxy.clone()),
            )
            .into_future(),
        );
        let hosts_path = config.output_dir.join("tls-hosts.json");
        protected_write(&hosts_path, &serde_json::to_vec(&https.hosts)?)?;
        let ws_config = config.output_dir.join("websocket-target.json");
        let mut tls = Command::new("python3")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("support/client_runtime_tls.py"))
            .arg(https.root.join("server.pem"))
            .arg(https.root.join("server-key.pem"))
            .arg(tls_port.to_string())
            .arg(upstream.to_string())
            .arg(&hosts_path)
            .arg(&ws_config)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut ready = String::new();
        std::io::BufReader::new(tls.stdout.take().context("TLS stdout")?).read_line(&mut ready)?;
        ensure!(
            serde_json::from_str::<Value>(&ready)?["port"] == tls_port,
            "TLS readiness mismatch"
        );
        let _tls = ChildGuard(tls);
        https.port = tls_port;
        let server = ShippingServerFixture::start_with_client_runtime(
            &https,
            "wss://chat.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents",
        )?;
        let service_url = url::Url::parse(&server.base_url)?;
        ensure!(
            service_url.scheme() == "http" && service_url.host_str() == Some("127.0.0.1"),
            "shipping WebSocket target must be exact loopback"
        );
        protected_write(
            &ws_config,
            &serde_json::to_vec(
                &json!({"port":service_url.port().context("shipping port")?,"origin":config.cors_origin}),
            )?,
        )?;
        proxy.documents.lock().unwrap().insert(
            "chat.catbird.blue".into(),
            serde_json::from_slice(&server.receipt_document)?,
        );
        let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let relay_url = format!("http://{}", relay.local_addr()?);
        let relay_task = tokio::spawn(
            axum::serve(
                relay,
                Router::new()
                    .fallback(bounded_forward)
                    .with_state((http, server.base_url.clone())),
            )
            .into_future(),
        );
        *proxy.service.lock().unwrap() = Some(relay_url);
        let origin = format!("https://{gateway}");
        let mapping = https
            .hosts
            .iter()
            .map(|h| (h.clone(), format!("127.0.0.1:{tls_port}")))
            .collect::<BTreeMap<_, _>>();
        protected_write(
            &config.output_dir.join("sessions.json"),
            &serde_json::to_vec_pretty(
                &json!({"accounts":proxy.actors.iter().zip(["alice","bob"]).map(|(a,label)|json!({"label":label,"did":a.identity.did,"deviceId":a.identity.device_id.to_string(),"session":a.session})).collect::<Vec<_>>()}),
            )?,
        )?;
        protected_write(
            &config.output_dir.join("ca.pem"),
            &std::fs::read(&https.ca_pem)?,
        )?;
        let tls_certificate = config.output_dir.join("tls-certificate.pem");
        protected_write(
            &tls_certificate,
            &std::fs::read(https.root.join("server.pem"))?,
        )?;
        let public_pem = Command::new("openssl")
            .args(["x509", "-pubkey", "-noout", "-in"])
            .arg(&tls_certificate)
            .output()?;
        ensure!(
            public_pem.status.success(),
            "fixture certificate public key extraction failed"
        );
        let mut spki = Command::new("openssl")
            .args(["pkey", "-pubin", "-outform", "DER"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        spki.stdin
            .take()
            .context("SPKI input")?
            .write_all(&public_pem.stdout)?;
        let spki = spki.wait_with_output()?;
        ensure!(
            spki.status.success(),
            "fixture certificate SPKI extraction failed"
        );
        let tls_spki_sha256 = STANDARD.encode(Sha256::digest(&spki.stdout));
        let public = json!({"fixtureOnly":true,"origin":origin,"corsOrigin":config.cors_origin,"caPem":config.output_dir.join("ca.pem"),"tlsCertificatePem":tls_certificate,"tlsSpkiSha256":tls_spki_sha256,"hosts":mapping,"accounts":proxy.actors.iter().zip(["alice","bob"]).map(|(a,label)|json!({"label":label,"did":a.identity.did,"deviceId":a.identity.device_id.to_string()})).collect::<Vec<_>>()});
        let address = format!("127.0.0.1:{tls_port}").parse()?;
        let untrusted = reqwest::Client::builder()
            .no_proxy()
            .resolve(&gateway, address)
            .timeout(Duration::from_secs(5))
            .build()?;
        ensure!(
            untrusted
                .get(format!("{origin}/auth/session"))
                .send()
                .await
                .is_err(),
            "untrusted fixture CA accepted"
        );
        let certificate = reqwest::Certificate::from_pem(&std::fs::read(&https.ca_pem)?)?;
        let trusted = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(certificate.clone())
            .resolve(&gateway, address)
            .timeout(Duration::from_secs(5))
            .build()?;
        ensure!(
            trusted
                .get(format!("{origin}/auth/session"))
                .send()
                .await?
                .status()
                == StatusCode::UNAUTHORIZED,
            "missing session accepted"
        );
        ensure!(
            trusted
                .get(format!("{origin}/auth/session"))
                .bearer_auth(&proxy.actors[0].session)
                .header("origin", "https://untrusted.invalid")
                .send()
                .await?
                .status()
                == StatusCode::FORBIDDEN,
            "wrong origin accepted"
        );
        let restored: Value = trusted
            .get(format!("{origin}/auth/session"))
            .bearer_auth(&proxy.actors[0].session)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        ensure!(
            restored["did"] == proxy.actors[0].identity.did,
            "session account mismatch"
        );
        let wrong = "wrong-name.request-fixture.catbird.blue";
        let wrong_host = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(certificate)
            .resolve(wrong, address)
            .timeout(Duration::from_secs(5))
            .build()?;
        ensure!(
            wrong_host
                .get(format!("https://{wrong}/auth/session"))
                .send()
                .await
                .is_err(),
            "wrong certificate hostname accepted"
        );
        let manifest = config.output_dir.join("manifest.json");
        protected_write(&manifest, &serde_json::to_vec_pretty(&public)?)?;
        println!("{}", json!({"manifest":manifest}));
        tokio::select! {_ = tokio::signal::ctrl_c()=>{},_=tokio::time::sleep(Duration::from_secs(config.lifetime_seconds))=>{}}
        gateway_task.abort();
        relay_task.abort();
        drop(server);
        drop(https);
        return Ok(());
    }

    // === Two-Authority Federation Mode ===
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&config.output_dir)?;
    let run = Uuid::new_v4().simple().to_string();
    let gateway = format!("gateway-{run}.request-fixture.catbird.blue");
    let (binary, server_fixture_sha) = resolve_server_fixture_binary(true)?;
    // Fixed guarded synthetic template; never interpolate an environment-supplied identifier into SQL.
    let template_db = "catbird_direct_requests_test_20260919";

    let db1_name = format!(
        "catbird_direct_requests_fault_{}",
        &Uuid::new_v4().simple().to_string()[..16]
    );
    let db2_name = format!(
        "catbird_direct_requests_fault_{}",
        &Uuid::new_v4().simple().to_string()[..16]
    );
    let db1_url = format!("postgresql://127.0.0.1:5432/{db1_name}");
    let db2_url = format!("postgresql://127.0.0.1:5432/{db2_name}");

    let _db1 = create_database_clone(&template_db, &db1_name)?;
    let _db2 = create_database_clone(&template_db, &db2_name)?;
    prepare_dedicated_federation_database(&db1_url)?;
    prepare_dedicated_federation_database(&db2_url)?;

    let ds1_did = format!("did:web:ds1-{run}.request-fixture.catbird.blue");
    let ds2_did = format!("did:web:ds2-{run}.request-fixture.catbird.blue");
    let ds1_host = ds1_did.trim_start_matches("did:web:").to_owned();
    let ds2_host = ds2_did.trim_start_matches("did:web:").to_owned();

    psql_on(
        &db1_url,
        &format!("INSERT INTO federation_peers(ds_did, status) VALUES('{ds2_did}', 'allow') ON CONFLICT DO NOTHING;"),
    )?;
    psql_on(
        &db2_url,
        &format!("INSERT INTO federation_peers(ds_did, status) VALUES('{ds1_did}', 'allow') ON CONFLICT DO NOTHING;"),
    )?;

    let port_a = HttpsDidFixture::reserve_port()?;
    let port_b = HttpsDidFixture::reserve_port()?;
    let server_a_url = format!("http://127.0.0.1:{port_a}");
    let server_b_url = format!("http://127.0.0.1:{port_b}");

    let (ds1_doc, _ds1_receipt_pub, _ds1_receipt_id) =
        ds_did_document(&ds1_did, &server_a_url, 61)?;
    let (ds2_doc, _ds2_receipt_pub, _ds2_receipt_id) =
        ds_did_document(&ds2_did, &server_b_url, 71)?;
    let ds1_receipt_doc_bytes = serde_json::to_vec(&ds1_doc)?;
    let ds2_receipt_doc_bytes = serde_json::to_vec(&ds2_doc)?;

    let alice_identity = ServiceIdentity::new(format!(
        "did:web:alice-{run}.request-fixture.catbird.blue"
    ))
    .with_audience(&ds1_did);
    let bob_identity = ServiceIdentity::new(format!(
        "did:web:bob-{run}.request-fixture.catbird.blue"
    ))
    .with_audience(&ds2_did);

    let alice_actor = Arc::new(Actor {
        identity: alice_identity,
        session: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
        records: Mutex::new(BTreeMap::new()),
        blocks: Mutex::new(BTreeMap::new()),
        seeded: Mutex::new(None),
    });
    let bob_actor = Arc::new(Actor {
        identity: bob_identity,
        session: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
        records: Mutex::new(BTreeMap::new()),
        blocks: Mutex::new(BTreeMap::new()),
        seeded: Mutex::new(None),
    });
    let actors = vec![alice_actor.clone(), bob_actor.clone()];

    let alice_doc = home_document(&actors[0].identity, &server_a_url);
    let bob_doc = home_document(&actors[1].identity, &server_b_url);

    let docs = vec![
        (actors[0].identity.did.clone(), alice_doc),
        (actors[1].identity.did.clone(), bob_doc),
        (ds1_did.clone(), ds1_doc.clone()),
        (ds2_did.clone(), ds2_doc.clone()),
        ("did:web:chat.catbird.blue".into(), ds1_doc.clone()),
        (
            format!("did:web:{gateway}"),
            json!({"id": format!("did:web:{gateway}")}),
        ),
    ];
    let mut https = HttpsDidFixture::start(HttpsDidFixture::reserve_port()?, &docs)?;

    declare_chat_authority(&https.root, &actors[0].identity.did, &ds1_did)?;
    declare_chat_authority(&https.root, &actors[1].identity.did, &ds2_did)?;

    let tls_port = HttpsDidFixture::reserve_port()?;
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(40))
        .build()?;
    let mut documents = docs
        .into_iter()
        .map(|(did, v)| (did.trim_start_matches("did:web:").to_owned(), v))
        .collect::<BTreeMap<_, _>>();
    for h in &https.hosts {
        documents
            .entry(h.clone())
            .or_insert_with(|| json!({"id": format!("did:web:{h}")}));
    }

    let relay_a = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let relay_a_url = format!("http://{}", relay_a.local_addr()?);
    let relay_task_a = tokio::spawn(
        axum::serve(
            relay_a,
            Router::new()
                .fallback(bounded_forward)
                .with_state((http.clone(), server_a_url.clone())),
        )
        .into_future(),
    );

    let relay_b = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let relay_b_url = format!("http://{}", relay_b.local_addr()?);
    let relay_task_b = tokio::spawn(
        axum::serve(
            relay_b,
            Router::new()
                .fallback(bounded_forward)
                .with_state((http.clone(), server_b_url.clone())),
        )
        .into_future(),
    );

    let mut actor_services = BTreeMap::new();
    actor_services.insert(actors[0].identity.did.clone(), relay_a_url.clone());
    actor_services.insert(actors[1].identity.did.clone(), relay_b_url.clone());

    let mut actor_db_urls = BTreeMap::new();
    actor_db_urls.insert(actors[0].identity.did.clone(), db1_url.clone());
    actor_db_urls.insert(actors[1].identity.did.clone(), db2_url.clone());

    let proxy = Arc::new(Proxy {
        foreign_recipient_did: None,
        withhold_first_foreign_prepare_response: AtomicBool::new(false),
        actors,
        documents: Mutex::new(documents),
        service: Mutex::new(Some(relay_a_url.clone())),
        actor_services,
        actor_db_urls,
        two_authority_federation: true,
        ds1_did: ds1_did.clone(),
        ds2_did: ds2_did.clone(),
        http: http.clone(),
        origin: config.cors_origin.clone(),
        https_root: Some(https.root.clone()),
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let upstream = listener.local_addr()?.port();
    let gateway_task = tokio::spawn(
        axum::serve(
            listener,
            Router::new().fallback(serve).with_state(proxy.clone()),
        )
        .into_future(),
    );

    let hosts_path = config.output_dir.join("tls-hosts.json");
    protected_write(&hosts_path, &serde_json::to_vec(&https.hosts)?)?;
    let ws_config = config.output_dir.join("websocket-target.json");
    let mut tls = Command::new("python3")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("support/client_runtime_tls.py"))
        .arg(https.root.join("server.pem"))
        .arg(https.root.join("server-key.pem"))
        .arg(tls_port.to_string())
        .arg(upstream.to_string())
        .arg(&hosts_path)
        .arg(&ws_config)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut ready = String::new();
    std::io::BufReader::new(tls.stdout.take().context("TLS stdout")?).read_line(&mut ready)?;
    ensure!(
        serde_json::from_str::<Value>(&ready)?["port"] == tls_port,
        "TLS readiness mismatch"
    );
    let _tls = ChildGuard(tls);
    https.port = tls_port;

    protected_write(
        &ws_config,
        &serde_json::to_vec(&json!({"port": port_a, "origin": config.cors_origin}))?,
    )?;

    let (child_a, _base_a) = spawn_server_fixture(
        &binary,
        &ds1_did,
        port_a,
        &db1_url,
        &https,
        61,
        &ds1_receipt_doc_bytes,
    )?;
    let _server_a = ChildGuard(child_a);

    let (child_b, _base_b) = spawn_server_fixture(
        &binary,
        &ds2_did,
        port_b,
        &db2_url,
        &https,
        71,
        &ds2_receipt_doc_bytes,
    )?;
    let _server_b = ChildGuard(child_b);

    proxy
        .documents
        .lock()
        .unwrap()
        .insert(ds1_host.clone(), ds1_doc.clone());
    proxy
        .documents
        .lock()
        .unwrap()
        .insert(ds2_host.clone(), ds2_doc.clone());
    proxy
        .documents
        .lock()
        .unwrap()
        .insert("chat.catbird.blue".into(), ds1_doc.clone());

    let origin = format!("https://{gateway}");
    let mapping = https
        .hosts
        .iter()
        .map(|h| (h.clone(), format!("127.0.0.1:{tls_port}")))
        .collect::<BTreeMap<_, _>>();

    protected_write(
        &config.output_dir.join("sessions.json"),
        &serde_json::to_vec_pretty(&json!({
            "accounts": [
                {
                    "label": "alice",
                    "did": proxy.actors[0].identity.did,
                    "deviceId": proxy.actors[0].identity.device_id.to_string(),
                    "session": proxy.actors[0].session,
                    "deliveryService": ds1_did,
                    "serviceEndpoint": server_a_url,
                },
                {
                    "label": "bob",
                    "did": proxy.actors[1].identity.did,
                    "deviceId": proxy.actors[1].identity.device_id.to_string(),
                    "session": proxy.actors[1].session,
                    "deliveryService": ds2_did,
                    "serviceEndpoint": server_b_url,
                }
            ]
        }))?,
    )?;

    protected_write(
        &config.output_dir.join("ca.pem"),
        &std::fs::read(&https.ca_pem)?,
    )?;
    let tls_certificate = config.output_dir.join("tls-certificate.pem");
    protected_write(
        &tls_certificate,
        &std::fs::read(https.root.join("server.pem"))?,
    )?;
    let public_pem = Command::new("openssl")
        .args(["x509", "-pubkey", "-noout", "-in"])
        .arg(&tls_certificate)
        .output()?;
    ensure!(
        public_pem.status.success(),
        "fixture certificate public key extraction failed"
    );
    let mut spki = Command::new("openssl")
        .args(["pkey", "-pubin", "-outform", "DER"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    spki.stdin
        .take()
        .context("SPKI input")?
        .write_all(&public_pem.stdout)?;
    let spki = spki.wait_with_output()?;
    ensure!(
        spki.status.success(),
        "fixture certificate SPKI extraction failed"
    );
    let tls_spki_sha256 = STANDARD.encode(Sha256::digest(&spki.stdout));

    let public = json!({
        "fixtureOnly": true,
        "origin": origin,
        "corsOrigin": config.cors_origin,
        "caPem": config.output_dir.join("ca.pem"),
        "tlsCertificatePem": tls_certificate,
        "tlsSpkiSha256": tls_spki_sha256,
        "hosts": mapping,
        "accounts": [
            {
                "label": "alice",
                "did": proxy.actors[0].identity.did,
                "deviceId": proxy.actors[0].identity.device_id.to_string(),
                "deliveryService": ds1_did,
                "serviceEndpoint": server_a_url,
            },
            {
                "label": "bob",
                "did": proxy.actors[1].identity.did,
                "deviceId": proxy.actors[1].identity.device_id.to_string(),
                "deliveryService": ds2_did,
                "serviceEndpoint": server_b_url,
            }
        ],
        "twoAuthorityFederation": true,
        "deliveryServices": [
            {
                "id": ds1_did,
                "did": ds1_did,
                "endpoint": server_a_url,
                "serviceEndpoint": server_a_url,
                "database": db1_name,
                "actor": "alice",
                "actorDid": proxy.actors[0].identity.did,
            },
            {
                "id": ds2_did,
                "did": ds2_did,
                "endpoint": server_b_url,
                "serviceEndpoint": server_b_url,
                "database": db2_name,
                "actor": "bob",
                "actorDid": proxy.actors[1].identity.did,
            }
        ],
        "binaryHashes": {
            "serverFixture": server_fixture_sha,
        }
    });

    let address = format!("127.0.0.1:{tls_port}").parse()?;
    let untrusted = reqwest::Client::builder()
        .no_proxy()
        .resolve(&gateway, address)
        .timeout(Duration::from_secs(5))
        .build()?;
    ensure!(
        untrusted
            .get(format!("{origin}/auth/session"))
            .send()
            .await
            .is_err(),
        "untrusted fixture CA accepted"
    );
    let certificate = reqwest::Certificate::from_pem(&std::fs::read(&https.ca_pem)?)?;
    let trusted = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(certificate.clone())
        .resolve(&gateway, address)
        .timeout(Duration::from_secs(5))
        .build()?;
    ensure!(
        trusted
            .get(format!("{origin}/auth/session"))
            .send()
            .await?
            .status()
            == StatusCode::UNAUTHORIZED,
        "missing session accepted"
    );
    ensure!(
        trusted
            .get(format!("{origin}/auth/session"))
            .bearer_auth(&proxy.actors[0].session)
            .header("origin", "https://untrusted.invalid")
            .send()
            .await?
            .status()
            == StatusCode::FORBIDDEN,
        "wrong origin accepted"
    );
    let restored_alice: Value = trusted
        .get(format!("{origin}/auth/session"))
        .bearer_auth(&proxy.actors[0].session)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(
        restored_alice["did"] == proxy.actors[0].identity.did,
        "session account mismatch for alice"
    );
    let restored_bob: Value = trusted
        .get(format!("{origin}/auth/session"))
        .bearer_auth(&proxy.actors[1].session)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(
        restored_bob["did"] == proxy.actors[1].identity.did,
        "session account mismatch for bob"
    );

    let manifest = config.output_dir.join("manifest.json");
    protected_write(&manifest, &serde_json::to_vec_pretty(&public)?)?;
    println!("{}", json!({"manifest":manifest}));

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = tokio::time::sleep(Duration::from_secs(config.lifetime_seconds)) => {}
    }
    gateway_task.abort();
    relay_task_a.abort();
    relay_task_b.abort();
    drop(_server_a);
    drop(_server_b);
    drop(_db1);
    drop(_db2);
    drop(https);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_rejects_remote_origin_reuse_and_unbounded_lifetime() {
        let c = Config {
            output_dir: PathBuf::from("/tmp").join(format!("never-created-{}", Uuid::new_v4())),
            cors_origin: "http://127.0.0.1:5173".into(),
            lifetime_seconds: 60,
            foreign_bob_authority: false,
            withhold_first_foreign_prepare_response: false,
            two_authority_federation: false,
        };
        assert!(validate_config(&c).is_ok());
        let two_auth = Config {
            two_authority_federation: true,
            ..c.clone()
        };
        assert!(validate_config(&two_auth).is_ok());
        let conflict = Config {
            two_authority_federation: true,
            foreign_bob_authority: true,
            ..c.clone()
        };
        assert!(
            validate_config(&conflict).is_err(),
            "two_authority_federation and foreign_bob_authority conflict"
        );
        let loss = Config {
            output_dir: c.output_dir.clone(),
            cors_origin: c.cors_origin.clone(),
            lifetime_seconds: c.lifetime_seconds,
            foreign_bob_authority: false,
            withhold_first_foreign_prepare_response: true,
            two_authority_federation: false,
        };
        assert!(validate_config(&loss).is_err(), "never withhold a canonical recipient response");
        assert!(validate_config(&Config { foreign_bob_authority: true, ..loss.clone() }).is_ok());
        assert!(validate_config(&Config { two_authority_federation: true, ..loss }).is_err());
        for seconds in [0, 3601] {
            assert!(validate_config(&Config {
                output_dir: c.output_dir.clone(),
                cors_origin: c.cors_origin.clone(),
                lifetime_seconds: seconds,
                foreign_bob_authority: false,
                withhold_first_foreign_prepare_response: false,
                two_authority_federation: false,
            })
            .is_err());
        }
        for origin in [
            "https://example.com",
            "http://127.0.0.1:5173/",
            "http://user@localhost:5173",
            "null",
        ] {
            assert!(validate_config(&Config {
                cors_origin: origin.into(),
                ..Config {
                    output_dir: c.output_dir.clone(),
                    cors_origin: c.cors_origin.clone(),
                    lifetime_seconds: 60,
                    foreign_bob_authority: false,
                    withhold_first_foreign_prepare_response: false,
                    two_authority_federation: false,
                }
            })
            .is_err());
        }
        assert!(validate_config(&Config {
            output_dir: PathBuf::from("/tmp"),
            cors_origin: c.cors_origin,
            lifetime_seconds: 60,
            foreign_bob_authority: false,
            withhold_first_foreign_prepare_response: false,
            two_authority_federation: false,
        })
        .is_err());
    }
    #[test]
    fn key_and_query_guards() {
        assert!(decode_key(&json!(STANDARD.encode([7; 32]))).is_ok());
        assert!(decode_key(&json!({"$bytes":STANDARD.encode([7;32]),"extra":true})).is_err());
        assert!(decode_key(&json!(STANDARD.encode([7; 31]))).is_err());
        assert!(params("repo=a&repo=b").is_err());
    }
    #[test]
    fn public_declarations_are_immutable_and_account_bound() {
        let actor = Actor {
            identity: ServiceIdentity::new("did:web:alice.request-fixture.catbird.blue".into()),
            session: "opaque".into(),
            records: Mutex::new(BTreeMap::new()),
            blocks: Mutex::new(BTreeMap::new()),
            seeded: Mutex::new(None),
        };
        let id = Uuid::new_v4().to_string();
        let first = set_declaration(&actor, &id, &[7; 32], None).unwrap();
        assert_eq!(
            first["uri"],
            format!("at://{}/{COLLECTION}/{id}", actor.identity.did)
        );
        assert_eq!(set_declaration(&actor, &id, &[7; 32], None).unwrap(), first);
        assert!(set_declaration(&actor, &id, &[8; 32], None).is_err());
        assert!(set_declaration(&actor, "not-a-device", &[7; 32], None).is_err());
        assert!(actor.seeded.lock().unwrap().is_none());
    }
    #[tokio::test]
    async fn unauthorized_and_wrong_origin_requests_cannot_publish_declarations() {
        let identity = ServiceIdentity::new("did:web:alice.request-fixture.catbird.blue".into());
        let host = identity.did.trim_start_matches("did:web:").to_owned();
        let actor = Arc::new(Actor {
            identity,
            session: "opaque".into(),
            records: Mutex::new(BTreeMap::new()),
            blocks: Mutex::new(BTreeMap::new()),
            seeded: Mutex::new(None),
        });
        let proxy = Arc::new(Proxy {
            actors: vec![actor.clone()],
            documents: Mutex::new(BTreeMap::from([(host.clone(), json!({}))])),
            service: Mutex::new(None),
            actor_services: BTreeMap::new(),
            actor_db_urls: BTreeMap::new(),
            two_authority_federation: false,
            ds1_did: String::new(),
            ds2_did: String::new(),
            foreign_recipient_did: None,
            withhold_first_foreign_prepare_response: AtomicBool::new(false),
            http: reqwest::Client::new(),
            origin: "http://127.0.0.1:5173".into(),
            https_root: None,
        });
        let missing = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.repo.putRecord")
            .header("host", &host)
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(
            serve(State(proxy.clone()), missing).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let wrong = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.repo.putRecord")
            .header("host", &host)
            .header("authorization", "Bearer opaque")
            .header("origin", "https://wrong.invalid")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(
            serve(State(proxy.clone()), wrong).await.status(),
            StatusCode::FORBIDDEN
        );
        let arrays=Request::builder().uri("/xrpc/blue.catbird.chat.getConversations?supportedProtocolVersions=1&supportedProtocolVersions=2").header("host",&host).header("authorization","Bearer opaque").body(Body::empty()).unwrap();
        assert_eq!(
            serve(State(proxy), arrays).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(actor.records.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn foreign_bob_declaration_requires_explicit_fixture_option() {
        let actors: Vec<_> = ["alice", "bob"].into_iter().map(|label| {
            Arc::new(Actor {
                identity: ServiceIdentity::new(format!("did:web:{label}.request-fixture.catbird.blue")),
                session: "opaque".into(),
                records: Mutex::new(BTreeMap::new()),
                blocks: Mutex::new(BTreeMap::new()),
                seeded: Mutex::new(None),
            })
        }).collect();
        let bob = actors[1].identity.did.clone();
        for foreign in [false, true] {
            let proxy = Arc::new(Proxy {
                documents: Mutex::new(actors.iter().map(|actor| (
                    actor.identity.did.trim_start_matches("did:web:").to_owned(),
                    json!({"id": actor.identity.did}),
                )).collect()),
                foreign_recipient_did: foreign.then(|| bob.clone()),
                withhold_first_foreign_prepare_response: AtomicBool::new(false),
                actors: actors.clone(),
                service: Mutex::new(None),
                actor_services: BTreeMap::new(),
                actor_db_urls: BTreeMap::new(),
                two_authority_federation: false,
                ds1_did: String::new(),
                ds2_did: String::new(),
                http: reqwest::Client::new(),
                origin: "http://127.0.0.1:5173".into(),
                https_root: None,
            });
            for actor in &actors {
                let request = Request::builder()
                    .uri(format!("/xrpc/com.atproto.repo.getRecord?repo={}&collection=blue.catbird.chat.declaration&rkey=self", actor.identity.did))
                    .header("host", actor.identity.did.trim_start_matches("did:web:"))
                    .body(Body::empty())
                    .unwrap();
                let result = serve(State(proxy.clone()), request).await;
                assert_eq!(result.status(), StatusCode::OK);
                let bytes = to_bytes(result.into_body(), 4096).await.unwrap();
                let record: Value = serde_json::from_slice(&bytes).unwrap();
                let expected = if foreign && actor.identity.did == bob {
                    "did:web:chat.federated-peer.org"
                } else {
                    "did:web:chat.catbird.blue"
                };
                assert_eq!(record["value"]["deliveryService"], expected);
            }
        }
    }
    #[tokio::test]
    async fn two_authority_federation_declarations_and_routing() {
        let actors: Vec<_> = ["alice", "bob"]
            .into_iter()
            .map(|label| {
                Arc::new(Actor {
                    identity: ServiceIdentity::new(format!(
                        "did:web:{label}.request-fixture.catbird.blue"
                    )),
                    session: format!("session-{label}"),
                    records: Mutex::new(BTreeMap::new()),
                    blocks: Mutex::new(BTreeMap::new()),
                    seeded: Mutex::new(None),
                })
            })
            .collect();
        let ds1_did = "did:web:ds1.catbird.blue".to_string();
        let ds2_did = "did:web:ds2.catbird.blue".to_string();
        let proxy = Arc::new(Proxy {
            documents: Mutex::new(
                actors
                    .iter()
                    .map(|actor| {
                        (
                            actor.identity.did.trim_start_matches("did:web:").to_owned(),
                            json!({"id": actor.identity.did}),
                        )
                    })
                    .collect(),
            ),
            foreign_recipient_did: None,
            withhold_first_foreign_prepare_response: AtomicBool::new(false),
            actors: actors.clone(),
            service: Mutex::new(Some("http://127.0.0.1:9001".into())),
            actor_services: BTreeMap::from([
                (actors[0].identity.did.clone(), "http://127.0.0.1:9001".into()),
                (actors[1].identity.did.clone(), "http://127.0.0.1:9002".into()),
            ]),
            actor_db_urls: BTreeMap::new(),
            two_authority_federation: true,
            ds1_did: ds1_did.clone(),
            ds2_did: ds2_did.clone(),
            http: reqwest::Client::new(),
            origin: "http://127.0.0.1:5173".into(),
            https_root: None,
        });

        // Check Alice's declaration returns DS1
        let req_alice = Request::builder()
            .uri(format!(
                "/xrpc/com.atproto.repo.getRecord?repo={}&collection=blue.catbird.chat.declaration&rkey=self",
                actors[0].identity.did
            ))
            .header("host", actors[0].identity.did.trim_start_matches("did:web:"))
            .body(Body::empty())
            .unwrap();
        let res_alice = serve(State(proxy.clone()), req_alice).await;
        assert_eq!(res_alice.status(), StatusCode::OK);
        let bytes_alice = to_bytes(res_alice.into_body(), 4096).await.unwrap();
        let rec_alice: Value = serde_json::from_slice(&bytes_alice).unwrap();
        assert_eq!(rec_alice["value"]["deliveryService"], ds1_did);

        // Check Bob's declaration returns DS2
        let req_bob = Request::builder()
            .uri(format!(
                "/xrpc/com.atproto.repo.getRecord?repo={}&collection=blue.catbird.chat.declaration&rkey=self",
                actors[1].identity.did
            ))
            .header("host", actors[1].identity.did.trim_start_matches("did:web:"))
            .body(Body::empty())
            .unwrap();
        let res_bob = serve(State(proxy.clone()), req_bob).await;
        assert_eq!(res_bob.status(), StatusCode::OK);
        let bytes_bob = to_bytes(res_bob.into_body(), 4096).await.unwrap();
        let rec_bob: Value = serde_json::from_slice(&bytes_bob).unwrap();
        assert_eq!(rec_bob["value"]["deliveryService"], ds2_did);
    }
}
