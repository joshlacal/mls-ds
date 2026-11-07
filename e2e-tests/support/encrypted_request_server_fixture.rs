use std::{io::Write as _, sync::Arc};

use anyhow::{Context, Result};
use axum::{extract::FromRef, Router};
use catbird_server::{
    auth::install_test_https_did_resolver,
    federation::{
        outbound::OutboundClient, receipt::I13ReceiptSigner, DsResolver, ServiceAuthClient,
    },
    handlers::chat::{chat_router, install_test_https_relationship_resolver, ChatRuntime},
    handlers::labyrinth::labyrinth_router,
    realtime::SseState,
    storage::DbPool,
};
use p256::pkcs8::DecodePrivateKey as _;
use sqlx::postgres::PgPoolOptions;

const EXACT_DATABASE_URL: &str =
    "postgresql://127.0.0.1:5432/catbird_direct_requests_test_20260919";

/// Same predicate as the e2e harness `dedicated_request_database_name`: a
/// faketime cluster (127.0.0.1, never port 5432) or a fault clone
/// (127.0.0.1:5432, `_fault_<16 lowercase hex>`) are the only other targets.
fn is_dedicated_database_url(url: &str) -> bool {
    let Some((port, name)) = url
        .strip_prefix("postgresql://127.0.0.1:")
        .and_then(|rest| rest.split_once('/'))
    else {
        return false;
    };
    let Some(port) = port
        .bytes()
        .all(|b| b.is_ascii_digit())
        .then(|| port.parse::<u16>().ok())
        .flatten()
    else {
        return false;
    };
    if let Some(suffix) = name.strip_prefix("catbird_direct_requests_faketime_") {
        port != 0
            && port != 5432
            && (1..=40).contains(&suffix.len())
            && suffix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    } else if let Some(suffix) = name.strip_prefix("catbird_direct_requests_fault_") {
        url == format!("postgresql://127.0.0.1:5432/{name}")
            && suffix.len() == 16
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    } else {
        false
    }
}

#[derive(Clone)]
struct FixtureState {
    pool: DbPool,
    runtime: Arc<ChatRuntime>,
    /// Federation handles the Labyrinth router needs (`LABYRINTH_ENABLED`).
    /// Fixture conversations are all local, so no peer is ever contacted.
    resolver: Arc<DsResolver>,
    outbound: Arc<OutboundClient>,
}

impl FromRef<FixtureState> for DbPool {
    fn from_ref(state: &FixtureState) -> Self {
        state.pool.clone()
    }
}

impl FromRef<FixtureState> for Arc<ChatRuntime> {
    fn from_ref(state: &FixtureState) -> Self {
        state.runtime.clone()
    }
}

impl FromRef<FixtureState> for Arc<DsResolver> {
    fn from_ref(state: &FixtureState) -> Self {
        state.resolver.clone()
    }
}

impl FromRef<FixtureState> for Arc<OutboundClient> {
    fn from_ref(state: &FixtureState) -> Self {
        state.outbound.clone()
    }
}

/// No server-to-server identity: the fixture never relays Labyrinth
/// operations to another DS.
impl FromRef<FixtureState> for Option<Arc<ServiceAuthClient>> {
    fn from_ref(_: &FixtureState) -> Self {
        None
    }
}

/// Same predicate as `main.rs` `truthy_env_var`.
fn truthy_env_var(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PushGatewayOverride {
    canonical_https_url: String,
    loopback_http_url: String,
}

/// Test-only D2 routing (same hook as `clean_slate_federation_fixture`): the
/// shipping SSRF validator never resolves fixture gateway hosts, so a test maps
/// one exact canonical HTTPS gateway URL to its own loopback fake gateway.
async fn register_push_override(
    axum::Json(input): axum::Json<PushGatewayOverride>,
) -> axum::http::StatusCode {
    if !input.loopback_http_url.starts_with("http://127.0.0.1:") {
        return axum::http::StatusCode::BAD_REQUEST;
    }
    catbird_server::push_gateway::ssrf::register_test_gateway_override(
        &input.canonical_https_url,
        input.loopback_http_url,
    );
    axum::http::StatusCode::OK
}

/// Drive one publication's wake through the production worker until it is
/// terminal: an attempt the gateway deferred is retried once its durable
/// backoff is due, exactly as the background worker would retry it.
async fn drive_push_event(
    pool: &DbPool,
    runtime: &ChatRuntime,
    event_id: uuid::Uuid,
) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(25);
    let mut deferred = Vec::new();
    loop {
        match catbird_server::workers::run_request_push_event_once_for_test(pool, runtime, event_id)
            .await
        {
            Ok(run) if run.claimed == 1 => {
                return serde_json::json!({
                    "eventId": event_id,
                    "ok": true,
                    "claimed": run.claimed,
                    "attempts": deferred.len() + 1,
                    "woken": run.woken,
                    "suppressed": run.suppressed == 1,
                    "deferred": deferred,
                });
            }
            // Nothing was due: either the event is not pending at all, or
            // its retry backoff has not elapsed yet.
            Ok(_) if deferred.is_empty() => {
                return serde_json::json!({"eventId": event_id, "ok": false, "claimed": 0});
            }
            Ok(_) => {}
            Err(error) => deferred.push(error),
        }
        if tokio::time::Instant::now() >= deadline {
            return serde_json::json!({
                "eventId": event_id,
                "ok": false,
                "error": "retry deadline",
                "deferred": deferred,
            });
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let database_url =
        std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL is required")?;
    anyhow::ensure!(
        database_url == EXACT_DATABASE_URL || is_dedicated_database_url(&database_url),
        "server fixture refuses every database except {EXACT_DATABASE_URL} and dedicated faketime/fault request databases"
    );
    let resolver_hosts = std::env::var("REQUEST_FIXTURE_DID_HOSTS")
        .context("REQUEST_FIXTURE_DID_HOSTS is required")?
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        !resolver_hosts.is_empty(),
        "REQUEST_FIXTURE_DID_HOSTS is empty"
    );
    let resolver_port = std::env::var("REQUEST_FIXTURE_DID_PORT")
        .context("REQUEST_FIXTURE_DID_PORT is required")?
        .parse::<u16>()
        .context("REQUEST_FIXTURE_DID_PORT is not a u16")?;
    let resolver_ca_path = std::env::var("REQUEST_FIXTURE_DID_CA_PEM")
        .context("REQUEST_FIXTURE_DID_CA_PEM is required")?;
    let resolver_ca = std::fs::read(&resolver_ca_path)
        .with_context(|| format!("read resolver CA {resolver_ca_path}"))?;
    install_test_https_did_resolver(&resolver_hosts, resolver_port, &resolver_ca)
        .map_err(anyhow::Error::msg)?;
    install_test_https_relationship_resolver(&resolver_hosts, resolver_port, &resolver_ca)
        .map_err(anyhow::Error::msg)?;

    let pool = PgPoolOptions::new()
        .max_connections(32)
        .test_before_acquire(false)
        .idle_timeout(None)
        .max_lifetime(None)
        .acquire_timeout(std::time::Duration::from_secs(60))
        .connect(&database_url)
        .await
        .context("connect guarded request database")?;
    let mut runtime =
        ChatRuntime::from_env(Arc::new(SseState::new(64))).map_err(anyhow::Error::msg)?;
    // The server binary takes its receipt signer from validated startup
    // configuration; this fixture issues with the key its harness hands it.
    if let Ok(pem) = std::env::var("RECEIPT_SIGNING_KEY_PEM") {
        let method = std::env::var("RECEIPT_VERIFICATION_METHOD")
            .context("RECEIPT_VERIFICATION_METHOD is required with RECEIPT_SIGNING_KEY_PEM")?;
        let service_did = std::env::var("SERVICE_DID").context("SERVICE_DID is required")?;
        let key = p256::ecdsa::SigningKey::from_pkcs8_pem(&pem)
            .context("RECEIPT_SIGNING_KEY_PEM is not a P-256 PKCS#8 key")?;
        runtime = runtime.with_i13_receipt_signer(
            I13ReceiptSigner::new_with_key_id(key, service_did, method)
                .map_err(anyhow::Error::msg)?,
        );
    }
    // D2: the targeted worker signs with this DS's Push Gateway client
    // (SERVICE_DID + SIGNING_KEY_PEM) and wakes the gateway each device
    // registered through registerPushGateway.
    let push_event = match std::env::var("REQUEST_FIXTURE_PUSH_EVENT_ID") {
        Ok(event_id) => {
            let event_id = event_id
                .parse::<uuid::Uuid>()
                .context("REQUEST_FIXTURE_PUSH_EVENT_ID is invalid")?;
            let client = runtime.push_gateway_client().cloned().context(
                "push fixture requires the Push Gateway client (SERVICE_DID, SIGNING_KEY_PEM)",
            )?;
            let trigger = std::path::PathBuf::from(
                std::env::var("REQUEST_FIXTURE_PUSH_TRIGGER")
                    .context("REQUEST_FIXTURE_PUSH_TRIGGER is required")?,
            );
            let result = std::path::PathBuf::from(
                std::env::var("REQUEST_FIXTURE_PUSH_RESULT")
                    .context("REQUEST_FIXTURE_PUSH_RESULT is required")?,
            );
            anyhow::ensure!(
                trigger.is_absolute() && result.is_absolute(),
                "push fixture paths must be absolute"
            );
            Some((event_id, client, trigger, result))
        }
        Err(_) => None,
    };
    let runtime = Arc::new(runtime);
    runtime
        .validate_protocol_fence(&pool)
        .await
        .map_err(anyhow::Error::msg)?;
    // The production sweeper expires every due row in its database, so it may
    // only run against a dedicated (faketime/fault) request database.
    if std::env::var("REQUEST_FIXTURE_EXPIRY_SWEEP").as_deref() == Ok("1") {
        anyhow::ensure!(
            is_dedicated_database_url(&database_url),
            "REQUEST_FIXTURE_EXPIRY_SWEEP requires a dedicated request database"
        );
        tokio::spawn(catbird_server::handlers::chat::run_chat_expiry_sweeper(
            pool.clone(),
            runtime.clone(),
        ));
    }
    if std::env::var("REQUEST_FIXTURE_OUTBOUND_WORKER").as_deref() == Ok("1") {
        anyhow::ensure!(
            is_dedicated_database_url(&database_url),
            "REQUEST_FIXTURE_OUTBOUND_WORKER requires a dedicated request database"
        );
        // Main's queue takes the resolver explicitly; build the same one the
        // encrypted-requests queue constructed internally.
        let cache_ttl: u64 = std::env::var("ENDPOINT_CACHE_TTL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600);
        let resolver = Arc::new(
            catbird_server::federation::DsResolver::with_default_endpoint(
                pool.clone(),
                catbird_server::federation::resolver::build_resolver_http_client(),
                catbird_server::identity::service_did(),
                catbird_server::identity::self_endpoint(),
                std::env::var("DEFAULT_DS_ENDPOINT").ok(),
                cache_ttl,
            ),
        );
        let queue = Arc::new(catbird_server::federation::queue::OutboundQueue::new(
            pool.clone(),
            catbird_server::auth::AuthMiddleware::new(),
            resolver,
        ));
        let outbound = Arc::new(catbird_server::federation::outbound::OutboundClient::new(
            10, 30,
        ));
        let auth_fn: Arc<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync> =
            Arc::new(|target: &str, method: &str| {
                catbird_server::federation::canonical_relay::mint_s2s_auth_token(target, method)
                    .map_err(|e| e.to_string())
            });
        let shutdown = tokio_util::sync::CancellationToken::new();
        tokio::spawn(async move {
            queue.run_worker(outbound, auth_fn, shutdown).await;
        });
    }
    if let Some((event_id, _client, trigger, result)) = push_event {
        let push_pool = pool.clone();
        let push_runtime = runtime.clone();
        tokio::spawn(async move {
            for _ in 0..9_000 {
                if trigger.exists() {
                    let value = drive_push_event(&push_pool, &push_runtime, event_id).await;
                    let _ = std::fs::write(&result, serde_json::to_vec(&value).unwrap());
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            let _ = std::fs::write(&result, b"{\"ok\":false,\"error\":\"trigger timeout\"}");
        });
    }

    // The shipping server merges the Labyrinth router only when
    // `LABYRINTH_ENABLED` is set (`main.rs`); the fixture mirrors that gate.
    let labyrinth_enabled = truthy_env_var("LABYRINTH_ENABLED");
    // Only the Labyrinth router reads the resolver. Without it the fixture
    // must not touch the fail-loudly SERVICE_DID accessor, so callers that
    // set no SERVICE_DID (the C34 compatible reader) start as before.
    let (service_did, self_endpoint) = if labyrinth_enabled {
        (
            catbird_server::identity::service_did(),
            catbird_server::identity::self_endpoint(),
        )
    } else {
        (
            "did:web:labyrinth-disabled.invalid".to_owned(),
            "https://labyrinth-disabled.invalid".to_owned(),
        )
    };
    let resolver = Arc::new(DsResolver::with_default_endpoint(
        pool.clone(),
        catbird_server::federation::resolver::build_resolver_http_client(),
        service_did,
        self_endpoint,
        None,
        3600,
    ));
    let router = if labyrinth_enabled {
        chat_router::<FixtureState>().merge(labyrinth_router::<FixtureState>())
    } else {
        chat_router::<FixtureState>()
    };
    let router = router.route(
        "/_test/request-fixture/register-push-override",
        axum::routing::post(register_push_override),
    );
    let app: Router = router.with_state(FixtureState {
        pool,
        runtime,
        resolver,
        outbound: Arc::new(OutboundClient::new(10, 30)),
    });
    let configured_listen = std::env::var("REQUEST_FIXTURE_LISTEN").ok();
    let listen: std::net::SocketAddr = configured_listen
        .as_deref()
        .unwrap_or("127.0.0.1:0")
        .parse()
        .context("REQUEST_FIXTURE_LISTEN must be a numeric socket address")?;
    anyhow::ensure!(
        listen.ip().is_loopback(),
        "REQUEST_FIXTURE_LISTEN must be loopback"
    );
    anyhow::ensure!(
        configured_listen.is_none() || listen.port() != 0,
        "configured REQUEST_FIXTURE_LISTEN must use a nonzero reserved port"
    );
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind {listen}"))?;
    let address = listener.local_addr().context("read fixture address")?;
    println!(
        "{}",
        serde_json::json!({"baseUrl": format!("http://{address}")})
    );
    std::io::stdout().flush().context("flush readiness")?;
    axum::serve(listener, app).await.context("serve router")?;
    Ok(())
}
