use axum::{
    extract::FromRef,
    routing::{any, get, post},
    Router,
};
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod crypto;
mod db;
mod fanout;
mod handlers;
mod health;
mod jobs;
mod metrics;
mod middleware;
mod models;
mod realtime;
mod storage;
mod util;
mod xrpc_proxy;

// Composite state for Axum 0.7
#[derive(Clone, FromRef)]
struct AppState {
    db_pool: PgPool,
    sse_state: Arc<realtime::SseState>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "catbird_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    tracing::info!("Starting Catbird MLS Server");

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

    // Create composite app state
    let app_state = AppState {
        db_pool: db_pool.clone(),
        sse_state,
    };

    // Build application router
    let metrics_router = Router::new()
        .route("/metrics", get(metrics::metrics_handler))
        .with_state(metrics_handle);

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
            "/xrpc/blue.catbird.mls.getKeyPackages",
            get(handlers::get_key_packages),
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
        .with_state(app_state);

    // Optional: developer-only direct XRPC proxy (off by default).
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
        tracing::warn!("ENABLE_DIRECT_XRPC_PROXY is enabled; forward-all /xrpc/* is active");
    }

    let app = base_router;

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
