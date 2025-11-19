use axum::{
    extract::FromRef,
    routing::{any, get, post},
    Router,
};
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tokio::time::{interval, Duration};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Import from library crate instead of re-declaring modules
use catbird_server::{
    actors, auth, crypto, db, fanout, handlers, health, metrics, middleware, models, realtime,
    storage, util,
};

// These modules are only in main.rs (not in lib.rs)
mod device_utils;
mod jobs;
mod admin_system;
mod xrpc_proxy;

// Composite state for Axum 0.7
#[derive(Clone, FromRef)]
struct AppState {
    db_pool: PgPool,
    sse_state: Arc<realtime::SseState>,
    actor_registry: Arc<actors::ActorRegistry>,
    notification_service: Option<Arc<catbird_server::notifications::NotificationService>>,
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

    // Log authentication configuration at startup
    tracing::info!(
        enforce_lxm = %std::env::var("ENFORCE_LXM").unwrap_or_else(|_| "true".to_string()),
        enforce_jti = %std::env::var("ENFORCE_JTI").unwrap_or_else(|_| "true".to_string()),
        jti_ttl_seconds = %std::env::var("JTI_TTL_SECONDS").unwrap_or_else(|_| "120".to_string()),
        jwt_secret_configured = std::env::var("JWT_SECRET").is_ok(),
        "Authentication configuration loaded"
    );

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

    // Initialize actor registry
    let actor_registry = Arc::new(actors::ActorRegistry::new(db_pool.clone()));
    tracing::info!("Actor registry initialized");

    // Initialize notification service
    let notification_service = Some(Arc::new(catbird_server::notifications::NotificationService::new()));
    tracing::info!("Notification service initialized");

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

    // Spawn rate limiter cleanup worker (clean up stale buckets every 5 minutes)
    tokio::spawn(async move {
        let mut interval_timer = interval(Duration::from_secs(300)); // Every 5 minutes
        loop {
            interval_timer.tick().await;
            // Cleanup buckets not accessed in the last 10 minutes
            let max_age = Duration::from_secs(600);
            middleware::rate_limit::DID_RATE_LIMITER.cleanup_old_buckets(max_age).await;
            tracing::debug!("Rate limiter cleanup completed");
        }
    });
    tracing::info!("Rate limiter cleanup worker started");

    // Create composite app state
    let app_state = AppState {
        db_pool: db_pool.clone(),
        sse_state,
        actor_registry,
        notification_service,
    };

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

    let mut base_router = Router::new()
        // Health check endpoints
        .route("/health", get(health::health))
        .route("/health/live", get(health::liveness))
        .route("/health/ready", get(health::readiness))
        // XRPC routes under /xrpc namespace
        .route(
            "/xrpc/blue.catbird.mls.createConvo",
            post(handlers::create_convo),
        )
        .route(
            "/xrpc/blue.catbird.mls.addMembers",
            post(handlers::add_members),
        )
        .route(
            "/xrpc/blue.catbird.mls.sendMessage",
            post(handlers::send_message),
        )
        .route(
            "/xrpc/blue.catbird.mls.leaveConvo",
            post(handlers::leave_convo),
        )
        .route(
            "/xrpc/blue.catbird.mls.getMessages",
            get(handlers::get_messages),
        )
        .route(
            "/xrpc/blue.catbird.mls.getConvos",
            get(handlers::get_convos),
        )
        .route(
            "/xrpc/blue.catbird.mls.publishKeyPackage",
            post(handlers::publish_key_package),
        )
        .route(
            "/xrpc/blue.catbird.mls.publishKeyPackages",
            post(handlers::publish_key_packages),
        )
        .route(
            "/xrpc/blue.catbird.mls.getKeyPackages",
            get(handlers::get_key_packages),
        )
        .route(
            "/xrpc/blue.catbird.mls.getKeyPackageStats",
            get(handlers::get_key_package_stats),
        )
        .route(
            "/xrpc/blue.catbird.mls.getKeyPackageHistory",
            get(handlers::get_key_package_history),
        )
        .route(
            "/xrpc/blue.catbird.mls.getKeyPackageStatus",
            get(handlers::get_key_package_status),
        )
        .route(
            "/xrpc/blue.catbird.mls.registerDevice",
            post(handlers::register_device),
        )
        .route(
            "/xrpc/blue.catbird.mls.deleteDevice",
            post(handlers::delete_device),
        )
        .route(
            "/xrpc/blue.catbird.mls.listDevices",
            get(handlers::list_devices),
        )
        .route(
            "/xrpc/blue.catbird.mls.registerDeviceToken",
            post(handlers::register_device_token),
        )
        .route(
            "/xrpc/blue.catbird.mls.unregisterDeviceToken",
            post(handlers::unregister_device_token),
        )
        .route(
            "/xrpc/blue.catbird.mls.getEpoch",
            get(handlers::get_epoch),
        )
        .route(
            "/xrpc/blue.catbird.mls.getWelcome",
            get(handlers::get_welcome),
        )
        .route(
            "/xrpc/blue.catbird.mls.confirmWelcome",
            post(handlers::confirm_welcome),
        )
        .route(
            "/xrpc/blue.catbird.mls.requestRejoin",
            post(handlers::request_rejoin),
        )
        .route(
            "/xrpc/blue.catbird.mls.getExpectedConversations",
            get(handlers::get_expected_conversations),
        )
        .route(
            "/xrpc/blue.catbird.mls.validateDeviceState",
            get(handlers::validate_device_state),
        )
        .route(
            "/xrpc/blue.catbird.mls.getCommits",
            get(handlers::get_commits),
        )
        // Bluesky blocks integration endpoints
        .route(
            "/xrpc/blue.catbird.mls.checkBlocks",
            get(handlers::check_blocks),
        )
        .route(
            "/xrpc/blue.catbird.mls.getBlockStatus",
            get(handlers::get_block_status),
        )
        .route(
            "/xrpc/blue.catbird.mls.handleBlockChange",
            post(handlers::handle_block_change),
        )
        // Hybrid messaging endpoints
        .route(
            "/xrpc/blue.catbird.mls.streamConvoEvents",
            get(realtime::subscribe_convo_events),
        )
        .route(
            "/xrpc/blue.catbird.mls.updateCursor",
            post(handlers::update_cursor),
        )
        .merge(metrics_router)
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(middleware::logging::log_headers_middleware))
        // DID-based rate limiter for authenticated requests, IP-based backstop for unauthenticated
        .layer(axum::middleware::from_fn(middleware::rate_limit::rate_limit_middleware))
        .layer(axum::middleware::from_fn_with_state(
            middleware::idempotency::IdempotencyLayer::new(db_pool.clone()),
            middleware::idempotency::idempotency_middleware,
        ))
        .with_state(app_state.clone());

    // Admin & moderation endpoints (server-side authorization; content stays E2EE)
    let admin_router = Router::new()
        .route(
            "/xrpc/blue.catbird.mls.promoteAdmin",
            post(admin_system::promote_admin),
        )
        .route(
            "/xrpc/blue.catbird.mls.demoteAdmin",
            post(admin_system::demote_admin),
        )
        .route(
            "/xrpc/blue.catbird.mls.removeMember",
            post(admin_system::remove_member),
        )
        .route(
            "/xrpc/blue.catbird.mls.reportMember",
            post(admin_system::report_member),
        )
        .route(
            "/xrpc/blue.catbird.mls.getReports",
            get(admin_system::get_reports),
        )
        .route(
            "/xrpc/blue.catbird.mls.resolveReport",
            post(admin_system::resolve_report),
        )
        .with_state(app_state.clone());

    // ⚠️ SECURITY: Developer-only direct XRPC proxy - NEVER enable in production
    // This is gated with #[cfg(debug_assertions)] to prevent accidental production use
    #[cfg(debug_assertions)]
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

    // Refuse to start if proxy is requested in release mode
    #[cfg(not(debug_assertions))]
    if std::env::var("ENABLE_DIRECT_XRPC_PROXY").is_ok() {
        panic!(
            "SECURITY ERROR: ENABLE_DIRECT_XRPC_PROXY is set in a RELEASE build. \
             This debug-only feature exposes all XRPC traffic and must never be enabled in production. \
             Remove the environment variable to proceed."
        );
    }

    let app = base_router.merge(admin_router);

    let port = std::env::var("SERVER_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
