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
use base64::{engine::general_purpose::STANDARD, Engine as _};
use mls_e2e_tests::local_runtime_fixture::{
    connect_guarded_request_database, seed_service_device, HttpsDidFixture, ServiceIdentity,
    ShippingServerFixture,
};
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
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;
const INPUT_MAX: usize = 16 * 1024 * 1024;
const OUTPUT_MAX: usize = 32 * 1024 * 1024;
const COLLECTION: &str = "blue.catbird.chat.device";
const CID: &str = "bafkreigh2akiscaildc5uysbroqbuq43uqudpjxckcmchwwyk7r6xnsgma";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    output_dir: PathBuf,
    cors_origin: String,
    #[serde(default = "lifetime")]
    lifetime_seconds: u64,
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
    seeded: Mutex<Option<Vec<u8>>>,
}
struct Proxy {
    actors: Vec<Arc<Actor>>,
    documents: Mutex<BTreeMap<String, Value>>,
    service: Mutex<Option<String>>,
    http: reqwest::Client,
    origin: String,
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
        let Some(a) = public_actor else {
            return error(StatusCode::FORBIDDEN, "InvalidRepo");
        };
        if q.get("collection").map(String::as_str) != Some(COLLECTION)
            || q.keys()
                .any(|k| !["repo", "collection", "limit"].contains(&k.as_str()))
            || q.get("limit")
                .is_some_and(|s| s.parse::<usize>().map_or(true, |n| !(1..=100).contains(&n)))
        {
            return error(StatusCode::BAD_REQUEST, "InvalidQuery");
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
            return response(
                StatusCode::OK,
                json!({
                    "uri": format!("at://{}/blue.catbird.chat.declaration/self", q["repo"]),
                    "value": {
                        "$type": "blue.catbird.chat.declaration",
                        "allowIncoming": "all",
                        "deliveryService": "did:web:chat.catbird.blue",
                        "protocolVersion": "1",
                        "createdAt": "2026-09-24T00:00:00.000Z"
                    }
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
        return response(
            StatusCode::OK,
            json!({"actor":q["actor"],"relationships":[{"$type":"app.bsky.graph.defs#relationship","did":q["others"]}]}),
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
        return response(StatusCode::OK, json!({"blocks":[]}));
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
        "/fixture/enroll" | "/xrpc/com.atproto.repo.putRecord" | "/xrpc/com.atproto.repo.createRecord"
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
        let known = |did: &Value| proxy.actors.iter().any(|a| *did == a.identity.did);
        if v["repo"] != actor.identity.did
            || v["collection"] != "app.bsky.graph.block"
            || v["record"]["$type"] != "app.bsky.graph.block"
            || !known(&v["record"]["subject"])
            || v["record"]["subject"] == actor.identity.did
            || v["record"]["createdAt"].as_str().is_none()
        {
            return error(StatusCode::BAD_REQUEST, "UnsupportedRecord");
        }
        return response(
            StatusCode::OK,
            json!({"uri": format!("at://{}/app.bsky.graph.block/{}", actor.identity.did, uuid::Uuid::new_v4().simple()), "cid": CID}),
        );
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
        if seeded.is_none() {
            if seed_service_device(&actor.identity, &key).is_err() {
                return error(StatusCode::BAD_GATEWAY, "SeedFailed");
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
            set_declaration(
                &actor,
                device,
                &key,
                Some(
                    json!({"uri":format!("at://{}/{COLLECTION}/{device}",actor.identity.did),"cid":CID,"value":v["record"]}),
                ),
            )
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
            Ok(())
        })();
        if result.is_err() {
            return error(StatusCode::BAD_REQUEST, "InvalidEnrollmentDeclaration");
        }
    }
    let Some(service) = proxy.service.lock().unwrap().clone() else {
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
        Ok((status, body)) => Response::builder()
            .status(status.as_u16())
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap(),
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
    // Receipt document is deterministic and populated after service startup.
    let proxy = Arc::new(Proxy {
        actors,
        documents: Mutex::new(documents),
        service: Mutex::new(None),
        http: http.clone(),
        origin: config.cors_origin.clone(),
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
    // Readiness means strict TLS and session/origin guards have actually run.
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
        };
        assert!(validate_config(&c).is_ok());
        for seconds in [0, 3601] {
            assert!(validate_config(&Config {
                output_dir: c.output_dir.clone(),
                cors_origin: c.cors_origin.clone(),
                lifetime_seconds: seconds
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
                    lifetime_seconds: 60
                }
            })
            .is_err());
        }
        assert!(validate_config(&Config {
            output_dir: PathBuf::from("/tmp"),
            cors_origin: c.cors_origin,
            lifetime_seconds: 60
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
            seeded: Mutex::new(None),
        });
        let proxy = Arc::new(Proxy {
            actors: vec![actor.clone()],
            documents: Mutex::new(BTreeMap::from([(host.clone(), json!({}))])),
            service: Mutex::new(None),
            http: reqwest::Client::new(),
            origin: "http://127.0.0.1:5173".into(),
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
}
