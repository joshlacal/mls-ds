// Mirror the surviving lib.rs crate-level allows for the bin target —
// clippy treats them as separate compilation units. See lib.rs for the full
// rationale (each entry has a concrete TODO(phase-2.5-cleanup-*) follow-up).
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::should_implement_trait)]
#![allow(deprecated)]
// `dead_code` is load-bearing in the bin namespace because main.rs declares
// `mod device_utils;` and `mod jobs;` which both duplicate the same source
// files compiled into `lib.rs`. The bin-local copies expose the same items
// but call only a subset (e.g. `parse_device_did` is only used by lib-side
// handlers). Removing this allow requires either deleting the duplicate
// `mod` declarations and routing main.rs through `catbird_server::*` (deep
// refactor, breaks the bin/lib seam) or splitting the workers into a
// bin-only crate.
// TODO(phase-2.5-cleanup-bin-lib-dedup): collapse the bin/lib module
// duplication so this allow can be retired.
#![allow(dead_code)]

#[cfg(debug_assertions)]
use axum::routing::any;
use axum::{
    body::HttpBody as _,
    extract::{DefaultBodyLimit, FromRef},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use once_cell::sync::Lazy;
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    sync::Semaphore,
    time::{interval, timeout, Duration, Instant},
};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Import from library crate instead of re-declaring modules
use catbird_server::{
    actors, auth, blob_store, block_sync, config, crypto, db, federation, handlers, health,
    metrics, middleware, models, realtime, workers,
};

// These modules are only in main.rs (not in lib.rs)
mod device_utils;
mod jobs;
mod xrpc_proxy;

// Composite state for Axum 0.7
#[derive(Clone, FromRef)]
struct AppState {
    db_pool: PgPool,
    sse_state: Arc<realtime::SseState>,
    actor_registry: Arc<actors::ActorRegistry>,
    /// Phase 2 (B5) — config for the inline 409-burst trigger that bypasses
    /// the periodic sweep's poll latency. Wrapped in Arc so the handler can
    /// extract it via `State<Arc<InlineTriggerConfig>>` without cloning the
    /// struct on every request.
    inline_trigger_cfg: Arc<config::InlineTriggerConfig>,
    notification_service: Option<Arc<catbird_server::notifications::NotificationService>>,
    block_sync: Arc<block_sync::BlockSyncService>,
    // Federation
    federation_config: federation::FederationConfig,
    resolver: Arc<federation::DsResolver>,
    service_auth: Option<Arc<federation::ServiceAuthClient>>,
    outbound: Arc<federation::outbound::OutboundClient>,
    outbound_queue: Arc<federation::queue::OutboundQueue>,
    sequencer: Arc<federation::Sequencer>,
    sequencer_transfer: Arc<federation::SequencerTransfer>,
    federated_backend: Arc<federation::FederatedBackend>,
    upstream_manager: Option<Arc<federation::UpstreamManager>>,
    ack_signer: Option<Arc<federation::AckSigner>>,
    device_client: Arc<federation::DeviceRecordClient>,
    blob_store: blob_store::BlobStore,
    // Clean-cutover chat (`blue.catbird.chat.*`) shared runtime: cutover gate +
    // trusted Nest verifier. Extracted by chat handlers via
    // `State<Arc<ChatRuntime>>` through `#[derive(FromRef)]`.
    chat_runtime: Arc<catbird_server::handlers::chat::ChatRuntime>,
}

fn receipt_did_document_router<S>(document: Option<serde_json::Value>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let Some(document) = document else {
        return Router::new();
    };
    let document = Arc::new(document);
    Router::new().route(
        catbird_server::identity::DID_WEB_WELL_KNOWN_PATH,
        get(move || {
            let document = document.clone();
            async move { axum::Json((*document).clone()).into_response() }
        }),
    )
}

fn truthy_env_var(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn is_production_environment() -> bool {
    let explicit_env = std::env::var("APP_ENV")
        .or_else(|_| std::env::var("ENVIRONMENT"))
        .or_else(|_| std::env::var("RUST_ENV"))
        .or_else(|_| std::env::var("DEPLOY_ENV"))
        .ok()
        .map(|v| v.to_ascii_lowercase());

    match explicit_env.as_deref() {
        Some("prod") | Some("production") => true,
        Some("dev") | Some("development") | Some("test") | Some("testing") | Some("staging") => {
            false
        }
        Some(_) => !cfg!(debug_assertions),
        None => !cfg!(debug_assertions),
    }
}

const DEFAULT_REQUEST_BODY_LIMIT_BYTES: usize = 4 * 1024 * 1024;
const BLOB_UPLOAD_BODY_LIMIT_BYTES: usize = 11 * 1024 * 1024;
// MLS JSON encodes `bytes` fields as base64. A valid 10 MiB ciphertext or
// GroupInfo therefore needs nearly 13.34 MiB on the wire before the small JSON
// envelope is counted. Keep the ordinary 4 MiB default, but preserve the
// existing MLS contracts on routes that carry one or more large artifacts.
const SINGLE_MLS_ARTIFACT_BODY_LIMIT_BYTES: usize = 15 * 1024 * 1024;
// Clean-chat enroll/replenish carry up to 100 KeyPackages
// (`blue.catbird.chat.defs#keyPackageArtifact.bytes` maxLength 65536 ×
// `keyPackages` maxLength 100), which base64-expand (4/3) to ~8.4 MiB of JSON
// plus the signed-request envelope; 12 MiB gives headroom without truncating a
// valid maximal batch (OQ-10).
const CHAT_KEY_PACKAGE_BATCH_BODY_LIMIT_BYTES: usize = 12 * 1024 * 1024;
const INGRESS_BODY_BUDGET_MIB: usize = 64;
const BYTES_PER_INGRESS_PERMIT: usize = 1024 * 1024;
const DEFAULT_REQUEST_BODY_READ_TIMEOUT_MS: u64 = 15_000;
const MAX_REQUEST_BODY_READ_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_REQUEST_BODY_TOTAL_TIMEOUT_MS: u64 = 120_000;
const DEFAULT_BLOB_UPLOAD_TOTAL_TIMEOUT_MS: u64 = 300_000;
const MAX_REQUEST_BODY_TOTAL_TIMEOUT_MS: u64 = 600_000;
const BLOB_UPLOAD_PATH: &str = "/xrpc/blue.catbird.chat.uploadBlob";
static INGRESS_BODY_BUDGET: Lazy<Arc<Semaphore>> =
    Lazy::new(|| Arc::new(Semaphore::new(INGRESS_BODY_BUDGET_MIB)));

#[derive(Clone)]
struct IngressBodyPolicy {
    budget: Arc<Semaphore>,
    read_idle_timeout: Duration,
    read_total_timeout: Duration,
    blob_upload_total_timeout: Duration,
}

impl IngressBodyPolicy {
    fn new(budget: Arc<Semaphore>, read_idle_timeout: Duration) -> Self {
        Self {
            budget,
            read_idle_timeout,
            read_total_timeout: Duration::from_millis(DEFAULT_REQUEST_BODY_TOTAL_TIMEOUT_MS),
            blob_upload_total_timeout: Duration::from_millis(DEFAULT_BLOB_UPLOAD_TOTAL_TIMEOUT_MS),
        }
    }

    #[cfg(test)]
    fn with_timeouts(
        budget: Arc<Semaphore>,
        read_idle_timeout: Duration,
        read_total_timeout: Duration,
    ) -> Self {
        Self {
            budget,
            read_idle_timeout,
            read_total_timeout,
            blob_upload_total_timeout: read_total_timeout,
        }
    }

    fn from_env() -> Self {
        let timeout_ms = std::env::var("REQUEST_BODY_READ_IDLE_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| (1..=MAX_REQUEST_BODY_READ_TIMEOUT_MS).contains(value))
            .unwrap_or(DEFAULT_REQUEST_BODY_READ_TIMEOUT_MS);

        let total_timeout_ms = std::env::var("REQUEST_BODY_READ_TOTAL_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| (1..=MAX_REQUEST_BODY_TOTAL_TIMEOUT_MS).contains(value))
            .unwrap_or(DEFAULT_REQUEST_BODY_TOTAL_TIMEOUT_MS);
        let blob_total_timeout_ms = std::env::var("BLOB_UPLOAD_READ_TOTAL_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| (1..=MAX_REQUEST_BODY_TOTAL_TIMEOUT_MS).contains(value))
            .unwrap_or(DEFAULT_BLOB_UPLOAD_TOTAL_TIMEOUT_MS);

        Self {
            budget: INGRESS_BODY_BUDGET.clone(),
            read_idle_timeout: Duration::from_millis(timeout_ms),
            read_total_timeout: Duration::from_millis(total_timeout_ms),
            blob_upload_total_timeout: Duration::from_millis(blob_total_timeout_ms),
        }
    }

    fn total_timeout(&self, path: &str) -> Duration {
        // Large base64 MLS envelopes need the same slow-client allowance as a
        // raw blob upload. The idle timeout still rejects stalled senders.
        if request_body_limit(path) > DEFAULT_REQUEST_BODY_LIMIT_BYTES {
            self.blob_upload_total_timeout
        } else {
            self.read_total_timeout
        }
    }
}

fn request_body_limit(path: &str) -> usize {
    match path {
        BLOB_UPLOAD_PATH => BLOB_UPLOAD_BODY_LIMIT_BYTES,
        "/xrpc/blue.catbird.chat.enrollDevice" | "/xrpc/blue.catbird.chat.replenishKeyPackages" => {
            CHAT_KEY_PACKAGE_BATCH_BODY_LIMIT_BYTES
        }
        "/xrpc/blue.catbird.mlsDS.deliverMessage"
        | "/xrpc/blue.catbird.mlsDS.deliverWelcome"
        | "/xrpc/blue.catbird.mlsDS.submitCommit" => SINGLE_MLS_ARTIFACT_BODY_LIMIT_BYTES,
        _ => DEFAULT_REQUEST_BODY_LIMIT_BYTES,
    }
}

fn method_has_no_application_body(method: &axum::http::Method) -> bool {
    matches!(
        *method,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    )
}

fn ingress_body_permits(request: &axum::extract::Request) -> u32 {
    if method_has_no_application_body(request.method()) {
        return 0;
    }

    let limit = request_body_limit(request.uri().path());
    let has_transfer_encoding = request
        .headers()
        .contains_key(axum::http::header::TRANSFER_ENCODING);
    let declared_length = request
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    let hinted_length = request
        .body()
        .size_hint()
        .upper()
        .map(|value| value as usize);

    let reserved_bytes = if has_transfer_encoding {
        limit
    } else {
        declared_length
            .into_iter()
            .chain(hinted_length)
            .max()
            .map(|length| length.min(limit))
            .unwrap_or(limit)
    };

    if reserved_bytes == 0 {
        0
    } else {
        reserved_bytes.div_ceil(BYTES_PER_INGRESS_PERMIT) as u32
    }
}

async fn enforce_ingress_body_budget(
    axum::extract::State(policy): axum::extract::State<IngressBodyPolicy>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    let permits = ingress_body_permits(&request);
    let _reservation = if permits == 0 {
        None
    } else {
        Some(
            policy
                .budget
                .try_acquire_many_owned(permits)
                .map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?,
        )
    };

    Ok(next.run(request).await)
}

async fn buffer_limited_request_body(
    axum::extract::State(policy): axum::extract::State<IngressBodyPolicy>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    if method_has_no_application_body(request.method()) {
        return Ok(next.run(request).await);
    }

    let limit = request_body_limit(request.uri().path());
    if let Some(raw_length) = request.headers().get(axum::http::header::CONTENT_LENGTH) {
        let declared_length = raw_length
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(axum::http::StatusCode::BAD_REQUEST)?;

        if declared_length > limit as u64 {
            return Err(axum::http::StatusCode::PAYLOAD_TOO_LARGE);
        }
    }

    let total_timeout = policy.total_timeout(request.uri().path());
    let (mut parts, body) = request.into_parts();
    let mut stream = body.into_data_stream();
    let mut bytes = bytes::BytesMut::new();
    let started_at = Instant::now();
    let mut last_progress_at = started_at;
    loop {
        let now = Instant::now();
        let idle_remaining = policy
            .read_idle_timeout
            .saturating_sub(now.duration_since(last_progress_at));
        let total_remaining = total_timeout.saturating_sub(now.duration_since(started_at));
        let wait_for_progress = idle_remaining.min(total_remaining);
        if wait_for_progress.is_zero() {
            return Err(axum::http::StatusCode::REQUEST_TIMEOUT);
        }

        let chunk = timeout(wait_for_progress, futures::StreamExt::next(&mut stream))
            .await
            .map_err(|_| axum::http::StatusCode::REQUEST_TIMEOUT)?;
        let Some(chunk) = chunk else {
            break;
        };
        let chunk = chunk.map_err(|_| axum::http::StatusCode::PAYLOAD_TOO_LARGE)?;
        if chunk.is_empty() {
            continue;
        }
        let next_length = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or(axum::http::StatusCode::PAYLOAD_TOO_LARGE)?;
        if next_length > limit {
            return Err(axum::http::StatusCode::PAYLOAD_TOO_LARGE);
        }
        bytes.extend_from_slice(&chunk);
        last_progress_at = Instant::now();
    }
    let bytes = bytes.freeze();
    parts.headers.remove(axum::http::header::TRANSFER_ENCODING);
    parts.headers.insert(
        axum::http::header::CONTENT_LENGTH,
        axum::http::HeaderValue::from_str(&bytes.len().to_string())
            .map_err(|_| axum::http::StatusCode::BAD_REQUEST)?,
    );
    let request = axum::extract::Request::from_parts(parts, axum::body::Body::from(bytes));

    Ok(next.run(request).await)
}

fn merge_application_routers(
    base_router: Router,
    ds_router: Router,
    db_pool: PgPool,
    ingress_body_policy: IngressBodyPolicy,
) -> Router {
    base_router
        .merge(ds_router)
        .layer(axum::middleware::from_fn_with_state(
            middleware::idempotency::IdempotencyLayer::new(db_pool),
            middleware::idempotency::idempotency_middleware,
        ))
        // The path-aware outer buffer enforces the narrower effective limit.
        // Configure the extractor ceiling to the largest valid route (15 MiB for DS single artifact)
        // so it cannot re-reject a body already accepted by that policy.
        .layer(DefaultBodyLimit::max(SINGLE_MLS_ARTIFACT_BODY_LIMIT_BYTES))
        .layer(axum::middleware::from_fn_with_state(
            ingress_body_policy.clone(),
            buffer_limited_request_body,
        ))
        .layer(axum::middleware::from_fn_with_state(
            ingress_body_policy,
            enforce_ingress_body_budget,
        ))
        .layer(axum::middleware::from_fn(
            middleware::rate_limit::rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn(
            middleware::response_content_type::response_content_type_middleware,
        ))
        .layer(axum::middleware::from_fn(
            middleware::logging::log_headers_middleware,
        ))
        .layer(TraceLayer::new_for_http())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    // Initialize tracing with production-safe defaults
    // Default to warn in production, debug in development
    let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| {
        #[cfg(debug_assertions)]
        {
            "debug".to_string()
        }

        #[cfg(not(debug_assertions))]
        {
            "warn".to_string()
        }
    });

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&log_level))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    tracing::info!("Starting Catbird MLS Server");

    let is_production = is_production_environment();
    tracing::info!(is_production, "Runtime environment detected");

    // Log authentication configuration at startup
    tracing::info!(
        enforce_lxm = %std::env::var("ENFORCE_LXM").unwrap_or_else(|_| "true".to_string()),
        enforce_jti = %std::env::var("ENFORCE_JTI").unwrap_or_else(|_| "true".to_string()),
        jti_ttl_seconds = %std::env::var("JTI_TTL_SECONDS").unwrap_or_else(|_| "120".to_string()),
        "Authentication configuration loaded"
    );

    if is_production {
        if truthy_env_var("ALLOW_UNSAFE_AUTH") {
            panic!(
                "Refusing to start in production: ALLOW_UNSAFE_AUTH=true is forbidden in production."
            );
        }
        if truthy_env_var("FEDERATION_ALLOW_INSECURE_HTTP") {
            panic!(
                "Refusing to start in production: FEDERATION_ALLOW_INSECURE_HTTP=true is forbidden."
            );
        }
        if std::env::var("REDIS_ENCRYPTION_KEY").is_err() {
            panic!("Refusing to start in production: REDIS_ENCRYPTION_KEY is required.");
        }
        if std::env::var("SERVICE_DID")
            .map(|v| v.is_empty())
            .unwrap_or(true)
        {
            panic!(
                "Refusing to start in production: SERVICE_DID is not configured. \
                 This is required for JWT audience validation."
            );
        }
    }

    // Check LXM/JTI enforcement safety
    let enforce_lxm = std::env::var("ENFORCE_LXM")
        .map(|value| auth::auth_enforcement_flag_enabled(&value))
        .unwrap_or(true);
    let enforce_jti = std::env::var("ENFORCE_JTI")
        .map(|value| auth::auth_enforcement_flag_enabled(&value))
        .unwrap_or(true);

    if !enforce_lxm || !enforce_jti {
        let allow_unsafe = truthy_env_var("ALLOW_UNSAFE_AUTH");
        if allow_unsafe {
            if is_production {
                panic!(
                    "Refusing to start in production with LXM/JTI disabled and ALLOW_UNSAFE_AUTH=true."
                );
            }
            tracing::warn!(
                enforce_lxm,
                enforce_jti,
                "⚠️ AUTH SAFETY OVERRIDE: LXM/JTI enforcement disabled with ALLOW_UNSAFE_AUTH=true. This is NOT safe for production."
            );
        } else {
            panic!(
                "Refusing to start: LXM enforcement={}, JTI enforcement={}. \
                 Anti-replay protections are disabled. Set ALLOW_UNSAFE_AUTH=true to override (NOT recommended for production).",
                enforce_lxm, enforce_jti
            );
        }
    }

    // Parse and install the closed device-auth rollout mode once at startup.
    // Invalid values fail before external dependencies or the listener are
    // initialized, and request handling never re-reads mutable environment.
    let device_auth_mode = config::DeviceAuthMode::from_env()?;
    middleware::device_auth::install_device_auth_mode(device_auth_mode)?;
    tracing::info!(?device_auth_mode, "Device-auth rollout mode installed");

    // Load offline test DID document fixtures if configured (strictly gated to APP_ENV=test)
    if let Err(e) = auth::load_test_did_fixtures_from_env().await {
        panic!("Failed to load test DID document fixtures: {e}");
    }

    // Parse the listener host before initializing external dependencies so a
    // malformed or non-IP SERVER_HOST fails startup rather than falling back
    // to an unexpectedly broad bind. Production APP_ENV safety checks above
    // remain authoritative and run first.
    let server_bind = config::ServerBindConfig::from_env()?;

    // Initialize metrics
    let metrics_recorder = metrics::MetricsRecorder::new();
    let metrics_handle = metrics_recorder.handle().clone();
    tracing::info!("Metrics initialized");

    // Initialize database
    let db_pool = db::init_db_default().await?;

    tracing::info!("Database initialized");

    // Initialize SSE state for realtime events
    let sse_buffer_size = std::env::var("SSE_BUFFER_SIZE")
        .unwrap_or_else(|_| "5000".to_string())
        .parse()
        .unwrap_or(5000);
    let sse_state = Arc::new(realtime::SseState::new(sse_buffer_size));
    tracing::info!("SSE state initialized with buffer size {}", sse_buffer_size);

    // Spawn compaction worker - Temporarily disabled - requires new DB schema
    // let compaction_pool = db_pool.clone();
    // let compaction_config = jobs::CompactionConfig::default();
    // tokio::spawn(async move {
    //     jobs::run_compaction_worker(compaction_pool, compaction_config).await;
    // });
    // tracing::info!("Compaction worker started");

    // Initialize notification service
    let notification_service = Some(Arc::new(
        catbird_server::notifications::NotificationService::new(),
    ));
    tracing::info!("Notification service initialized");

    // Initialize actor registry
    let actor_registry = Arc::new(actors::ActorRegistry::new(
        db_pool.clone(),
        sse_state.clone(),
        notification_service.clone(),
    ));
    tracing::info!("Actor registry initialized");

    // Phase 2 (Stage 4) — server-side sweep that auto-resets operationally
    // dead conversations even when no client is online to vote (Path B).
    // Cooldown + circuit-breaker gates are enforced both in the sweep query
    // and inside the actor's `TriggerSystemReset` handler (defense in depth).
    {
        let sweep_cfg = config::SweepConfig::from_env();
        let sweep_pool = db_pool.clone();
        let sweep_registry = actor_registry.clone();
        tokio::spawn(async move {
            jobs::auto_detect_failed_groups::run_failed_group_sweep(
                sweep_pool,
                sweep_registry,
                sweep_cfg,
            )
            .await;
        });
        tracing::info!("spawned auto_detect_failed_groups sweep worker");
    }

    // Phase 2 (B5) — inline trigger config, read once at startup. Stored on
    // AppState so handlers can extract it via Axum `State<Arc<InlineTriggerConfig>>`
    // without re-reading the env on every request.
    let inline_trigger_cfg = Arc::new(config::InlineTriggerConfig::from_env());
    tracing::info!(
        min_409_threshold = inline_trigger_cfg.min_409_threshold,
        reset_cooldown_secs = inline_trigger_cfg.reset_cooldown_secs,
        min_groupinfo_404_threshold = inline_trigger_cfg.min_groupinfo_404_threshold,
        "inline-trigger config loaded (Phase 2 B5 + B10)"
    );

    // Spawn idempotency cache cleanup worker
    let cleanup_pool = db_pool.clone();
    tokio::spawn(async move {
        let mut interval_timer = interval(Duration::from_secs(3600)); // Every hour
        loop {
            interval_timer.tick().await;
            if let Err(e) = middleware::idempotency::cleanup_expired_entries(&cleanup_pool).await {
                tracing::error!("Failed to cleanup idempotency cache: {}", e);
            } else {
                tracing::debug!("Idempotency cache cleanup completed");
            }
        }
    });
    tracing::info!("Idempotency cache cleanup worker started");

    // Spawn data compaction worker (messages, events, welcome messages)
    let compaction_pool = db_pool.clone();
    tokio::spawn(async move {
        jobs::run_data_compaction_worker(compaction_pool).await;
    });
    tracing::info!("Data compaction worker started");

    // Spawn key package cleanup worker
    let key_package_pool = db_pool.clone();
    tokio::spawn(async move {
        jobs::run_key_package_cleanup_worker(key_package_pool).await;
    });
    tracing::info!("Key package cleanup worker started");

    // Spawn delivery ACKs cleanup worker
    let acks_cleanup_pool = db_pool.clone();
    tokio::spawn(async move {
        jobs::run_delivery_acks_cleanup_worker(acks_cleanup_pool).await;
    });
    tracing::info!("Delivery ACKs cleanup worker started");

    // Phase 2.5 §7 R3 — backstop reminder worker for stuck reset_requested
    // sessions. Re-broadcasts `crypto_session_reset_requested` at 1h/6h/24h
    // when no client has activated; emits an admin-alert log on exhaustion.
    let reset_reminder_pool = db_pool.clone();
    let reset_reminder_sse = sse_state.clone();
    tokio::spawn(async move {
        jobs::run_reset_reminder_worker(reset_reminder_pool, reset_reminder_sse).await;
    });
    tracing::info!("Reset-reminder worker started (Phase 2.5 §7 R3)");

    // Phase 3 — durable outbox workers. Drain rows that the chokepoint
    // wrote in the same Postgres tx as `delivery_events`, surviving a
    // SIGKILL between commit and broadcast send.
    let federation_outbox_pool = db_pool.clone();
    tokio::spawn(async move {
        workers::run_federation_outbox_worker(federation_outbox_pool).await;
    });
    tracing::info!("Federation outbox worker started (Phase 3)");

    let notification_outbox_pool = db_pool.clone();
    tokio::spawn(async move {
        workers::run_notification_outbox_worker(notification_outbox_pool).await;
    });
    tracing::info!("Notification outbox worker started (Phase 3)");

    // Spawn rate limiter cleanup worker (clean up stale buckets every 5 minutes)
    tokio::spawn(async move {
        let mut interval_timer = interval(Duration::from_secs(300)); // Every 5 minutes
        loop {
            interval_timer.tick().await;
            // Cleanup buckets not accessed in the last 10 minutes
            let max_age = Duration::from_secs(600);
            middleware::rate_limit::DID_RATE_LIMITER
                .cleanup_old_buckets(max_age)
                .await;
            middleware::rate_limit::FEDERATION_DS_RATE_LIMITER
                .cleanup_old_buckets(max_age)
                .await;
            middleware::rate_limit::IP_LIMITER
                .cleanup_old_buckets(max_age)
                .await;
            tracing::debug!("Rate limiter cleanup completed");
        }
    });
    tracing::info!("Rate limiter cleanup worker started");

    // Cleanup shared JTI replay store entries
    let replay_cleanup_pool = db_pool.clone();
    tokio::spawn(async move {
        let mut interval_timer = interval(Duration::from_secs(300)); // Every 5 minutes
        loop {
            interval_timer.tick().await;
            match auth::cleanup_expired_jti_nonces(&replay_cleanup_pool).await {
                Ok(rows) => tracing::debug!(rows, "Shared JTI nonce cleanup completed"),
                Err(e) => tracing::warn!(error = %e, "Shared JTI nonce cleanup failed"),
            }
        }
    });
    tracing::info!("Shared JTI cleanup worker started");

    // Cleanup expired device-auth DPoP replays and enrollment challenges.
    // Enrollment deliberately bypasses the generic idempotency cache, so its
    // one-time replay material has an independent bounded-retention worker.
    let device_auth_cleanup_pool = db_pool.clone();
    tokio::spawn(async move {
        let mut interval_timer = interval(Duration::from_secs(300)); // Every 5 minutes
        loop {
            interval_timer.tick().await;
            match auth::device_auth::cleanup_expired_auth_material(&device_auth_cleanup_pool).await
            {
                Ok(rows) => tracing::debug!(rows, "Device-auth replay cleanup completed"),
                Err(e) => tracing::warn!(error = %e, "Device-auth replay cleanup failed"),
            }
        }
    });
    tracing::info!("Device-auth replay cleanup worker started");

    // Create composite app state
    let block_sync_service = Arc::new(block_sync::BlockSyncService::new());
    tracing::info!("Block sync service initialized");

    // ── Federation setup ──────────────────────────────────────────────
    let fed_config = federation::FederationConfig::from_env();
    tracing::info!(
        federation_enabled = fed_config.enabled,
        federation_mode = fed_config.mode.as_str(),
        self_did = %fed_config.self_did,
        self_endpoint = %fed_config.self_endpoint,
        "Federation config loaded"
    );

    let http_client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(
            fed_config.outbound_connect_timeout_secs,
        ))
        .timeout(std::time::Duration::from_secs(
            fed_config.outbound_timeout_secs,
        ))
        .user_agent("catbird-mls-ds/1.0")
        .build()
        .expect("Failed to build HTTP client");

    let resolver = Arc::new(federation::DsResolver::new(
        db_pool.clone(),
        http_client.clone(),
        fed_config.self_did.clone(),
        fed_config.self_endpoint.clone(),
        fed_config.default_ds.clone(),
        fed_config.endpoint_cache_ttl_secs,
    ));

    let service_auth = if let Some(key_pem) = &fed_config.signing_key_pem {
        match federation::ServiceAuthClient::from_es256_pem(
            fed_config.self_did.clone(),
            key_pem.as_bytes(),
            None,
        ) {
            Ok(auth) => {
                tracing::info!(
                    self_did = %fed_config.self_did,
                    "Federation service auth client initialized"
                );
                Some(Arc::new(auth))
            }
            Err(e) => {
                panic!(
                    "Failed to create federation service auth client from configured signing key: {}",
                    e
                );
            }
        }
    } else {
        None
    };

    if is_production && fed_config.enabled && service_auth.is_none() {
        panic!(
            "Refusing to start in production: federation is enabled but SIGNING_KEY_PEM is not configured."
        );
    }

    // Build AckSigner from the same ES256 PEM key (only available with ES256, not shared secret)
    let ack_signer = fed_config.signing_key_pem.as_ref().and_then(|key_pem| {
        match federation::AckSigner::from_pem(key_pem, fed_config.self_did.clone()) {
            Ok(signer) => {
                tracing::info!("AckSigner initialized for delivery acknowledgments");
                Some(Arc::new(signer))
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to create AckSigner, delivery acks disabled");
                None
            }
        }
    });

    let outbound = Arc::new(federation::outbound::OutboundClient::new(
        fed_config.outbound_connect_timeout_secs,
        fed_config.outbound_timeout_secs,
    ));

    let outbound_queue = Arc::new(federation::queue::OutboundQueue::new(
        db_pool.clone(),
        auth::AuthMiddleware::new(),
        resolver.clone(),
    ));

    // Receipt issuance has its own key and fixed DID verification method.
    // Issue mode fails startup closed; SIGNING_KEY_PEM is comparison-only and
    // is never used as a receipt-signing fallback.
    let receipt_signer = federation::configured_receipt_signer(
        fed_config.receipt_issuance_mode.as_deref(),
        fed_config.receipt_signing_key_pem.as_deref(),
        fed_config.receipt_verification_method.as_deref(),
        fed_config.signing_key_pem.as_deref(),
        &fed_config.self_did,
        fed_config.receipt_did_document_json.as_deref(),
    )
    .unwrap_or_else(|error| panic!("Invalid sequencer receipt configuration: {error}"));
    let receipt_did_document = if receipt_signer.is_some() {
        Some(
            serde_json::from_str(
                fed_config
                    .receipt_did_document_json
                    .as_deref()
                    .expect("validated issue mode has a DID document"),
            )
            .expect("validated issue-mode DID document is JSON"),
        )
    } else {
        None
    };
    if receipt_signer.is_some() {
        tracing::info!(
            verification_method = federation::RECEIPT_VERIFICATION_METHOD,
            "Dedicated receipt signer initialized"
        );
    }

    let sequencer = Arc::new(
        federation::Sequencer::new(db_pool.clone(), fed_config.self_did.clone())
            .with_receipt_signer(receipt_signer),
    );

    let sequencer_transfer = Arc::new(federation::SequencerTransfer::new(
        db_pool.clone(),
        fed_config.self_did.clone(),
    ));

    let federated_backend = Arc::new(federation::FederatedBackend::new(
        db_pool.clone(),
        fed_config.self_did.clone(),
        fed_config.enabled,
    ));

    tracing::info!("Federation components initialized");

    // Device record client for fetching MLS device records from users' PDSes
    let device_client = Arc::new(federation::DeviceRecordClient::new(
        http_client.clone(),
        resolver.clone(),
    ));

    // Initialize blob store (S3-compatible storage for encrypted image blobs)
    let blob_store = blob_store::BlobStore::new().await;
    tracing::info!("Blob store initialized");

    // Blob cleanup worker — TTL expiration, S3 purge, orphan metadata cleanup
    tokio::spawn(jobs::run_blob_cleanup_worker(
        db_pool.clone(),
        blob_store.clone(),
    ));
    tracing::info!("Blob cleanup worker started");

    // Shared shutdown token for federation workers
    let shutdown_token = tokio_util::sync::CancellationToken::new();

    // ── UpstreamManager (WS proxy for remote sequencer conversations) ──
    let ws_proxy_enabled = std::env::var("FEDERATION_WS_PROXY")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let upstream_manager = if fed_config.enabled && ws_proxy_enabled {
        if let Some(ref auth) = service_auth {
            let manager = federation::UpstreamManager::new(
                db_pool.clone(),
                resolver.clone(),
                auth.clone(),
                fed_config.self_did.clone(),
                fed_config.self_endpoint.clone(),
                shutdown_token.child_token(),
                sse_buffer_size,
            );
            tracing::info!("UpstreamManager initialized (WS proxy enabled)");
            Some(Arc::new(manager))
        } else {
            tracing::warn!(
                "FEDERATION_WS_PROXY enabled but no service auth; UpstreamManager not created"
            );
            None
        }
    } else {
        None
    };

    // Clean-cutover chat runtime. The fixed relationship authority is mandatory
    // in every mode and construction failure aborts startup. Pre-cutover this
    // needs no Nest configuration; once CHAT_CUTOVER_ENABLED is set the verifier
    // config becomes mandatory and its absence fails startup loudly rather than
    // silently 500-ing requests.
    let chat_runtime = Arc::new(
        catbird_server::handlers::chat::ChatRuntime::from_env_with_resolver(
            sse_state.clone(),
            resolver.clone(),
        )
        .unwrap_or_else(|error| {
            tracing::error!("clean-chat runtime configuration rejected: {error}");
            std::process::exit(1);
        }),
    );

    // Clean-chat expiry sweeper. Overdue OPEN leaf-recovery requests and overdue
    // PENDING Welcome deliveries hold reserved key packages and block their
    // owner's re-request; nothing clears them on a quiet conversation. This is
    // the only clean-chat background worker, and it is gated on the SAME cutover
    // flag as every chat route: while `CHAT_CUTOVER_ENABLED` is off the task is
    // never spawned, so no timer exists and nothing ever reads `chat.*`. (The
    // worker re-checks the flag itself, so a future caller that spawns it
    // unconditionally still performs zero chat access — unlike the device-auth
    // cleanup worker above, which is unconditional and is its own known problem.)
    if chat_runtime.cutover_enabled() {
        chat_runtime
            .validate_protocol_fence(&db_pool)
            .await
            .unwrap_or_else(|error| {
                tracing::error!("clean-chat protocol fence rejected: {error}");
                std::process::exit(1);
            });
        let chat_expiry_pool = db_pool.clone();
        let chat_expiry_runtime = chat_runtime.clone();
        let chat_expiry_blob_store = blob_store.clone();
        tokio::spawn(async move {
            catbird_server::handlers::chat::run_chat_expiry_sweeper_with_blob_store(
                chat_expiry_pool,
                chat_expiry_runtime,
                chat_expiry_blob_store,
            )
            .await;
        });
        tracing::info!("Clean-chat expiry sweeper worker started (cutover enabled)");
    } else {
        tracing::info!(
            "Clean-chat expiry sweeper worker NOT started (CHAT_CUTOVER_ENABLED is off)"
        );
    }

    let app_state = AppState {
        db_pool: db_pool.clone(),
        sse_state,
        actor_registry,
        inline_trigger_cfg,
        notification_service,
        block_sync: block_sync_service,
        federation_config: fed_config.clone(),
        resolver,
        service_auth: service_auth.clone(),
        outbound: outbound.clone(),
        outbound_queue: outbound_queue.clone(),
        sequencer,
        sequencer_transfer,
        federated_backend,
        upstream_manager: upstream_manager.clone(),
        ack_signer,
        device_client,
        blob_store: blob_store.clone(),
        chat_runtime,
    };

    // Start federation queue worker (only when federation is enabled)
    if fed_config.enabled {
        if let Some(ref auth) = service_auth {
            let queue_clone = outbound_queue.clone();
            let outbound_clone = outbound.clone();
            let auth_clone = auth.clone();
            let worker_shutdown = shutdown_token.child_token();

            let auth_fn: Arc<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync> =
                Arc::new(move |target: &str, method: &str| {
                    auth_clone
                        .sign_request(target, method)
                        .map_err(|e| e.to_string())
                });

            tokio::spawn(async move {
                queue_clone
                    .run_worker(outbound_clone, auth_fn, worker_shutdown)
                    .await;
            });
            tracing::info!("Federation outbound queue worker started");

            let reconcile_pool = db_pool.clone();
            let reconcile_resolver = app_state.resolver.clone();
            let reconcile_outbound = outbound.clone();
            let reconcile_shutdown = shutdown_token.child_token();
            let reconcile_self_did = fed_config.self_did.clone();
            let auth_clone = auth.clone();
            let reconcile_auth_fn: Arc<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync> =
                Arc::new(move |target: &str, method: &str| {
                    auth_clone
                        .sign_request(target, method)
                        .map_err(|e| e.to_string())
                });

            tokio::spawn(async move {
                federation::reconciliation::run_reconciliation_worker(
                    reconcile_pool,
                    reconcile_resolver,
                    reconcile_outbound,
                    reconcile_auth_fn,
                    reconcile_self_did,
                    reconcile_shutdown,
                )
                .await;
            });
            tracing::info!("Federation reconciliation worker started");
        } else {
            tracing::warn!(
                "Federation enabled but no service auth configured; federation workers not started"
            );
        }
    }

    // Build application router
    // Only expose metrics when explicitly enabled
    let metrics_router = if matches!(
        std::env::var("ENABLE_METRICS").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    ) {
        Router::new()
            .route("/metrics", get(metrics::metrics_handler))
            .with_state(metrics_handle)
    } else {
        Router::new()
    };

    let base_router = Router::new()
        // Health check endpoints
        .route("/health", get(health::health))
        .route("/health/live", get(health::liveness))
        .route("/health/ready", get(health::readiness))
        .merge(receipt_did_document_router(receipt_did_document))
        .merge(metrics_router)
        .with_state(app_state.clone());

    // ⚠️ SECURITY: Developer-only direct XRPC proxy - NEVER enable in production
    // This is gated with #[cfg(debug_assertions)] to prevent accidental production use
    #[cfg(debug_assertions)]
    let base_router = {
        let mut base_router = base_router;
        if matches!(
            std::env::var("ENABLE_DIRECT_XRPC_PROXY").as_deref(),
            Ok("1") | Ok("true") | Ok("TRUE")
        ) {
            let upstream = std::env::var("UPSTREAM_XRPC_BASE")
                .unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
            let proxy_state = xrpc_proxy::ProxyState {
                client: reqwest::Client::new(),
                base: upstream,
            };
            let proxy_router = Router::new()
                .route("/xrpc/*rest", any(xrpc_proxy::proxy))
                .with_state(proxy_state);
            base_router = base_router.merge(proxy_router);
            tracing::warn!("⚠️  ENABLE_DIRECT_XRPC_PROXY is enabled (DEBUG BUILD ONLY); forward-all /xrpc/* is active");
        }
        base_router
    };

    // Refuse to start if proxy is requested in release mode
    #[cfg(not(debug_assertions))]
    if std::env::var("ENABLE_DIRECT_XRPC_PROXY").is_ok() {
        panic!(
            "SECURITY ERROR: ENABLE_DIRECT_XRPC_PROXY is set in a RELEASE build. \
             This debug-only feature exposes all XRPC traffic and must never be enabled in production. \
             Remove the environment variable to proceed."
        );
    }

    // DS-to-DS federation routes (mlsDS namespace)
    let ds_router = Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.deliverMessage",
            post(handlers::ds::deliver_message),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.deliverWelcome",
            post(handlers::ds::deliver_welcome),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.submitCommit",
            post(handlers::ds::submit_commit),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.fetchKeyPackage",
            get(handlers::ds::fetch_key_package),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest",
            get(handlers::ds::get_convo_digest),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoEvents",
            get(handlers::ds::get_convo_events),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.transferSequencer",
            post(handlers::ds::transfer_sequencer),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.healthCheck",
            get(handlers::ds::health_check),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getFederationPeers",
            get(handlers::get_federation_peers),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.upsertFederationPeer",
            post(handlers::upsert_federation_peer),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.deleteFederationPeer",
            post(handlers::delete_federation_peer),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getFederationMode",
            get(handlers::get_federation_mode),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.setFederationMode",
            post(handlers::set_federation_mode),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.resolveDeliveryService",
            get(handlers::resolve_delivery_service::resolve),
        )
        .with_state(app_state.clone());

    // Clean-cutover chat router (`blue.catbird.chat.*`), isolated from the
    // superseded mlsChat namespace. Merged into base so it inherits the shared
    // idempotency/body-budget/content-type/logging middleware stack.
    let chat_router =
        catbird_server::handlers::chat::chat_router::<AppState>().with_state(app_state.clone());
    let base_router = base_router.merge(chat_router);

    let app = merge_application_routers(
        base_router,
        ds_router,
        db_pool.clone(),
        IngressBodyPolicy::from_env(),
    );

    let addr = server_bind.socket_addr();
    tracing::info!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    let upstream_for_shutdown = upstream_manager;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to install SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => tracing::info!("Received SIGINT, shutting down"),
                _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
            tracing::info!("Received SIGINT, shutting down");
        }

        shutdown_token.cancel();
        if let Some(ref mgr) = upstream_for_shutdown {
            mgr.shutdown().await;
        }
    })
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, Bytes},
        http::{Method, Request, StatusCode},
    };
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use tower_util::ServiceExt;

    async fn consume_body(body: Bytes) -> StatusCode {
        let _ = body;
        StatusCode::NO_CONTENT
    }

    #[test]
    fn clean_chat_body_limit_tiers_match_declared_artifact_sizes() {
        // enroll/replenish carry up to 100 KeyPackages
        // (`blue.catbird.chat.defs#keyPackageArtifact.bytes` maxLength 65536 ×
        // `keyPackages` maxLength 100), base64-expanded — the 12 MiB tier (OQ-10).
        assert_eq!(
            request_body_limit("/xrpc/blue.catbird.chat.enrollDevice"),
            CHAT_KEY_PACKAGE_BATCH_BODY_LIMIT_BYTES
        );
        assert_eq!(
            request_body_limit("/xrpc/blue.catbird.chat.replenishKeyPackages"),
            CHAT_KEY_PACKAGE_BATCH_BODY_LIMIT_BYTES
        );
        // Small signed-body procedures fall through to the default tier.
        assert_eq!(
            request_body_limit("/xrpc/blue.catbird.chat.revokeDevice"),
            DEFAULT_REQUEST_BODY_LIMIT_BYTES
        );
    }

    #[tokio::test]
    async fn receipt_did_route_serves_only_the_startup_validated_document() {
        let document = serde_json::json!({
            "id": "did:web:chat.catbird.blue",
            "verificationMethod": [{
                "id": federation::RECEIPT_VERIFICATION_METHOD,
                "controller": "did:web:chat.catbird.blue",
                "type": "Multikey",
                "publicKeyMultibase": "zPublishedByOperations"
            }]
        });
        let app: Router = receipt_did_document_router(Some(document.clone()));
        let response = app
            .oneshot(
                Request::get(catbird_server::identity::DID_WEB_WELL_KNOWN_PATH)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("bounded response body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("DID JSON"),
            document
        );

        let disabled: Router = receipt_did_document_router(None);
        let response = disabled
            .oneshot(
                Request::get(catbird_server::identity::DID_WEB_WELL_KNOWN_PATH)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    async fn require_normalized_framing(headers: axum::http::HeaderMap, body: Bytes) -> StatusCode {
        let content_length = headers
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        if headers.contains_key(axum::http::header::TRANSFER_ENCODING)
            || content_length != Some(body.len())
        {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::NO_CONTENT
        }
    }

    fn lazy_test_pool() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
            .expect("lazy pool")
    }

    fn test_ingress_policy() -> IngressBodyPolicy {
        IngressBodyPolicy::new(
            Arc::new(Semaphore::new(INGRESS_BODY_BUDGET_MIB)),
            Duration::from_secs(1),
        )
    }

    #[test]
    fn empty_mutation_reserves_no_memory_budget() {
        let empty = Request::post("/write")
            .body(Body::empty())
            .expect("request");
        let nonempty = Request::post("/write")
            .body(Body::from("{}"))
            .expect("request");

        assert_eq!(ingress_body_permits(&empty), 0);
        assert_eq!(ingress_body_permits(&nonempty), 1);
    }

    #[test]
    fn large_mls_json_routes_preserve_binary_contracts() {
        const MAX_MLS_ARTIFACT_BYTES: usize = 10 * 1024 * 1024;
        let base64_bytes = 4 * MAX_MLS_ARTIFACT_BYTES.div_ceil(3);
        assert!(SINGLE_MLS_ARTIFACT_BODY_LIMIT_BYTES > base64_bytes);

        for path in [
            "/xrpc/blue.catbird.mlsDS.deliverMessage",
            "/xrpc/blue.catbird.mlsDS.deliverWelcome",
            "/xrpc/blue.catbird.mlsDS.submitCommit",
        ] {
            assert_eq!(
                request_body_limit(path),
                SINGLE_MLS_ARTIFACT_BODY_LIMIT_BYTES
            );
        }
        for path in [
            "/xrpc/blue.catbird.chat.enrollDevice",
            "/xrpc/blue.catbird.chat.replenishKeyPackages",
        ] {
            assert_eq!(
                request_body_limit(path),
                CHAT_KEY_PACKAGE_BATCH_BODY_LIMIT_BYTES
            );
        }
    }

    #[test]
    fn large_route_caps_fit_weighted_global_budget() {
        for (path, expected_permits) in [
            ("/xrpc/blue.catbird.mlsDS.deliverMessage", 15),
            ("/xrpc/blue.catbird.chat.enrollDevice", 12),
        ] {
            let limit = request_body_limit(path);
            let request = Request::post(path)
                .header(axum::http::header::CONTENT_LENGTH, limit)
                .body(Body::empty())
                .expect("request");
            assert_eq!(ingress_body_permits(&request), expected_permits, "{path}");
            assert!(expected_permits <= INGRESS_BODY_BUDGET_MIB as u32, "{path}");
        }
    }

    #[test]
    fn large_mls_routes_receive_extended_total_timeout() {
        let policy = IngressBodyPolicy {
            budget: Arc::new(Semaphore::new(INGRESS_BODY_BUDGET_MIB)),
            read_idle_timeout: Duration::from_secs(1),
            read_total_timeout: Duration::from_secs(2),
            blob_upload_total_timeout: Duration::from_secs(3),
        };

        assert_eq!(policy.total_timeout("/ordinary"), Duration::from_secs(2));
        for path in [
            BLOB_UPLOAD_PATH,
            "/xrpc/blue.catbird.mlsDS.deliverMessage",
            "/xrpc/blue.catbird.chat.enrollDevice",
        ] {
            assert_eq!(policy.total_timeout(path), Duration::from_secs(3), "{path}");
        }
    }

    #[tokio::test]
    async fn body_limit_covers_every_merged_router() {
        let base_router = Router::new().route("/base", post(consume_body));
        let ds_router = Router::new().route("/ds", post(consume_body));
        let app = merge_application_routers(
            base_router,
            ds_router,
            lazy_test_pool(),
            test_ingress_policy(),
        );

        for path in ["/base", "/ds"] {
            let response = app
                .clone()
                .oneshot(
                    Request::post(path)
                        .body(Body::from(vec![0_u8; 4 * 1024 * 1024 + 1]))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE, "{path}");
        }
    }

    #[tokio::test]
    async fn clean_chat_enroll_body_limit_tier_is_enforced_through_merged_router() {
        // M-5: the 12 MiB key-package-batch tier (OQ-10) is not merely returned by
        // `request_body_limit` — it is actually ENFORCED by the merged router's
        // body-limit layer. `chat_router` is merged into the base router before
        // `merge_application_routers`, so register the enroll route on the base
        // router exactly as production assembly does.
        let base_router =
            Router::new().route("/xrpc/blue.catbird.chat.enrollDevice", post(consume_body));
        let app = merge_application_routers(
            base_router,
            Router::new(),
            lazy_test_pool(),
            test_ingress_policy(),
        );

        // Over the 12 MiB tier → 413.
        let over = app
            .clone()
            .oneshot(
                Request::post("/xrpc/blue.catbird.chat.enrollDevice")
                    .body(Body::from(vec![
                        0_u8;
                        CHAT_KEY_PACKAGE_BATCH_BODY_LIMIT_BYTES + 1
                    ]))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(over.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // Above the 4 MiB default but within the 12 MiB tier → admitted (204),
        // proving the elevated tier is applied to this route, not the default.
        let within = app
            .clone()
            .oneshot(
                Request::post("/xrpc/blue.catbird.chat.enrollDevice")
                    .body(Body::from(vec![0_u8; 4 * 1024 * 1024 + 1]))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(within.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn idempotency_policy_preserves_optional_contract_and_enrollment_bypass() {
        let base_router = Router::new()
            .route("/xrpc/blue.catbird.chat.sendMessage", post(consume_body))
            .route("/xrpc/blue.catbird.chat.enrollDevice", post(consume_body))
            .route(
                "/xrpc/blue.catbird.mlsDS.deliverMessage",
                post(consume_body),
            );
        let app = merge_application_routers(
            base_router,
            Router::new(),
            lazy_test_pool(),
            test_ingress_policy(),
        );

        for path in [
            "/xrpc/blue.catbird.chat.enrollDevice",
            "/xrpc/blue.catbird.chat.sendMessage",
            "/xrpc/blue.catbird.mlsDS.deliverMessage",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::post(path)
                        .header("Idempotency-Key", "   ")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::NO_CONTENT, "{path}");
        }
    }

    #[tokio::test]
    async fn oversized_mls_write_is_rejected_before_idempotency() {
        let base_router =
            Router::new().route("/xrpc/blue.catbird.chat.testPolicy", post(consume_body));
        let app = merge_application_routers(
            base_router,
            Router::new(),
            lazy_test_pool(),
            test_ingress_policy(),
        );

        let body_length = DEFAULT_REQUEST_BODY_LIMIT_BYTES + 1;
        let response = app
            .oneshot(
                Request::post("/xrpc/blue.catbird.chat.testPolicy")
                    .header(axum::http::header::CONTENT_LENGTH, body_length)
                    .body(Body::from(vec![0_u8; body_length]))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn unknown_length_mls_write_is_bounded_before_idempotency() {
        let base_router =
            Router::new().route("/xrpc/blue.catbird.chat.testPolicy", post(consume_body));
        let app = merge_application_routers(
            base_router,
            Router::new(),
            lazy_test_pool(),
            test_ingress_policy(),
        );

        let response = app
            .oneshot(
                Request::post("/xrpc/blue.catbird.chat.testPolicy")
                    .body(Body::from(vec![0_u8; DEFAULT_REQUEST_BODY_LIMIT_BYTES + 1]))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn unknown_length_body_is_consumed_before_idempotency_early_return() {
        let base_router =
            Router::new().route("/xrpc/blue.catbird.chat.testPolicy", post(consume_body));
        let app = merge_application_routers(
            base_router,
            Router::new(),
            lazy_test_pool(),
            test_ingress_policy(),
        );
        let body_was_polled = Arc::new(AtomicBool::new(false));
        let body_was_polled_by_stream = body_was_polled.clone();
        let body = Body::from_stream(futures::stream::once(async move {
            body_was_polled_by_stream.store(true, Ordering::SeqCst);
            Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(b"{}"))
        }));

        let response = app
            .oneshot(
                Request::post("/xrpc/blue.catbird.chat.testPolicy")
                    .body(body)
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(body_was_polled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn route_specific_upload_limit_reaches_idempotency_above_default() {
        let base_router = Router::new().route(
            BLOB_UPLOAD_PATH,
            post(consume_body).layer(DefaultBodyLimit::max(11 * 1024 * 1024)),
        );
        let app = merge_application_routers(
            base_router,
            Router::new(),
            lazy_test_pool(),
            test_ingress_policy(),
        );

        let response = app
            .oneshot(
                Request::post(BLOB_UPLOAD_PATH)
                    .body(Body::from(vec![0_u8; 4 * 1024 * 1024 + 1]))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn valid_large_mls_wire_body_is_not_rejected_by_default_limit() {
        let path = "/xrpc/blue.catbird.mlsDS.deliverMessage";
        let ds_router = Router::new().route(path, post(consume_body));
        let app = merge_application_routers(
            Router::new(),
            ds_router,
            lazy_test_pool(),
            test_ingress_policy(),
        );

        let response = app
            .oneshot(
                Request::post(path)
                    .body(Body::from(vec![0_u8; DEFAULT_REQUEST_BODY_LIMIT_BYTES + 1]))
                    .expect("request"),
            )
            .await
            .expect("response");

        // A 413 here would prove the shared body limit still breaks the
        // established MLS wire contract. Missing idempotency remains valid.
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn large_mls_route_still_rejects_above_its_wire_budget() {
        let path = "/xrpc/blue.catbird.mlsDS.deliverMessage";
        let ds_router = Router::new().route(path, post(consume_body));
        let app = merge_application_routers(
            Router::new(),
            ds_router,
            lazy_test_pool(),
            test_ingress_policy(),
        );
        let body_length = SINGLE_MLS_ARTIFACT_BODY_LIMIT_BYTES + 1;

        let response = app
            .oneshot(
                Request::post(path)
                    .header(axum::http::header::CONTENT_LENGTH, body_length)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn recovery_mode_cannot_bypass_ingress_budget_or_poll_body() {
        let path = "/xrpc/blue.catbird.chat.replenishKeyPackages";
        let base_router = Router::new().route(path, post(consume_body));
        let exhausted_budget = Arc::new(Semaphore::new(1));
        let _held = exhausted_budget
            .clone()
            .try_acquire_owned()
            .expect("reserve test budget");
        let app = merge_application_routers(
            base_router,
            Router::new(),
            lazy_test_pool(),
            IngressBodyPolicy::new(exhausted_budget, Duration::from_secs(1)),
        );
        let body_was_polled = Arc::new(AtomicBool::new(false));
        let body_was_polled_by_stream = body_was_polled.clone();
        let body = Body::from_stream(futures::stream::once(async move {
            body_was_polled_by_stream.store(true, Ordering::SeqCst);
            Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(b"{}"))
        }));

        let response = app
            .oneshot(
                Request::post(path)
                    .header(middleware::rate_limit::RECOVERY_MODE_HEADER, "true")
                    .body(body)
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!body_was_polled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn bodyless_methods_bypass_exhausted_budget_and_body_buffering() {
        let exhausted_budget = Arc::new(Semaphore::new(1));
        let _held = exhausted_budget
            .clone()
            .try_acquire_owned()
            .expect("reserve test budget");
        let safe_routes = get(|| async { StatusCode::OK })
            .head(|| async { StatusCode::OK })
            .options(|| async { StatusCode::NO_CONTENT });
        let app = merge_application_routers(
            Router::new().route("/safe", safe_routes),
            Router::new(),
            lazy_test_pool(),
            IngressBodyPolicy::new(exhausted_budget, Duration::from_millis(20)),
        );

        for (method, expected) in [
            (Method::GET, StatusCode::OK),
            (Method::HEAD, StatusCode::OK),
            (Method::OPTIONS, StatusCode::NO_CONTENT),
        ] {
            let pending_body = Body::from_stream(futures::stream::pending::<
                Result<Bytes, std::convert::Infallible>,
            >());
            let response = tokio::time::timeout(
                Duration::from_secs(1),
                app.clone().oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri("/safe")
                        .body(pending_body)
                        .expect("request"),
                ),
            )
            .await
            .expect("bodyless method must not poll a pending body")
            .expect("response");

            assert_eq!(response.status(), expected, "{method}");
        }
    }

    #[tokio::test]
    async fn progressing_body_may_exceed_one_idle_window_in_total() {
        let path = "/xrpc/blue.catbird.chat.enrollDevice";
        let base_router = Router::new().route(path, post(consume_body));
        let app = merge_application_routers(
            base_router,
            Router::new(),
            lazy_test_pool(),
            IngressBodyPolicy::new(
                Arc::new(Semaphore::new(INGRESS_BODY_BUDGET_MIB)),
                Duration::from_millis(100),
            ),
        );
        let body = Body::from_stream(futures::stream::unfold(0_u8, |index| async move {
            if index == 4 {
                None
            } else {
                tokio::time::sleep(Duration::from_millis(40)).await;
                Some((
                    Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(b"x")),
                    index + 1,
                ))
            }
        }));

        let response = tokio::time::timeout(
            Duration::from_secs(1),
            app.oneshot(Request::post(path).body(body).expect("request")),
        )
        .await
        .expect("progressing body must finish")
        .expect("response");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn empty_frames_do_not_reset_idle_timeout() {
        let path = "/xrpc/blue.catbird.chat.enrollDevice";
        let budget = Arc::new(Semaphore::new(12));
        let base_router = Router::new().route(path, post(consume_body));
        let app = merge_application_routers(
            base_router,
            Router::new(),
            lazy_test_pool(),
            IngressBodyPolicy::with_timeouts(
                budget.clone(),
                Duration::from_millis(60),
                Duration::from_millis(500),
            ),
        );
        let body = Body::from_stream(futures::stream::unfold((), |_| async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Some((Ok::<Bytes, std::convert::Infallible>(Bytes::new()), ()))
        }));

        let response = tokio::time::timeout(
            Duration::from_secs(1),
            app.oneshot(Request::post(path).body(body).expect("request")),
        )
        .await
        .expect("empty-frame stream must hit idle timeout")
        .expect("response");

        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(budget.available_permits(), 12);
    }

    #[tokio::test]
    async fn progress_trickle_hits_total_timeout_and_releases_budget() {
        let path = "/xrpc/blue.catbird.chat.enrollDevice";
        let budget = Arc::new(Semaphore::new(12));
        let base_router = Router::new()
            .route("/normal", get(|| async { StatusCode::OK }))
            .route(path, post(consume_body));
        let app = merge_application_routers(
            base_router,
            Router::new(),
            lazy_test_pool(),
            IngressBodyPolicy::with_timeouts(
                budget.clone(),
                Duration::from_millis(100),
                Duration::from_millis(130),
            ),
        );
        let body = Body::from_stream(futures::stream::unfold((), |_| async {
            tokio::time::sleep(Duration::from_millis(40)).await;
            Some((
                Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(b"x")),
                (),
            ))
        }));

        let response = tokio::time::timeout(
            Duration::from_secs(1),
            app.clone()
                .oneshot(Request::post(path).body(body).expect("request")),
        )
        .await
        .expect("trickle stream must hit total timeout")
        .expect("response");

        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(budget.available_permits(), 12);

        let normal = app
            .oneshot(
                Request::get("/normal")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(normal.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn timed_out_body_releases_ingress_budget_for_later_request() {
        let budget = Arc::new(Semaphore::new(
            DEFAULT_REQUEST_BODY_LIMIT_BYTES / 1024 / 1024,
        ));
        let policy = IngressBodyPolicy::new(budget.clone(), Duration::from_millis(20));
        let base_router = Router::new()
            .route("/normal", get(|| async { StatusCode::OK }))
            .route("/slow", post(consume_body));
        let app = merge_application_routers(base_router, Router::new(), lazy_test_pool(), policy);
        let stalled_body = Body::from_stream(futures::stream::pending::<
            Result<Bytes, std::convert::Infallible>,
        >());

        let timed_out = tokio::time::timeout(
            Duration::from_secs(1),
            app.clone()
                .oneshot(Request::post("/slow").body(stalled_body).expect("request")),
        )
        .await
        .expect("body deadline must complete the request")
        .expect("response");

        assert_eq!(timed_out.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(budget.available_permits(), 4);

        let normal = app
            .oneshot(
                Request::get("/normal")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(normal.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn buffered_body_replaces_stale_framing_headers() {
        let base_router = Router::new().route("/normalized", post(require_normalized_framing));
        let app = merge_application_routers(
            base_router,
            Router::new(),
            lazy_test_pool(),
            test_ingress_policy(),
        );

        let response = app
            .oneshot(
                Request::post("/normalized")
                    .header(axum::http::header::CONTENT_LENGTH, "99")
                    .header(axum::http::header::TRANSFER_ENCODING, "chunked")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
