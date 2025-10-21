use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod crypto;
mod handlers;
mod models;
mod storage;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "catbird_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    tracing::info!("Starting Catbird MLS Server");

    // Initialize database
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite::memory:".to_string());
    let db_pool = storage::init_db(&db_url).await?;
    
    tracing::info!("Database initialized");

    // Build application router
    let app = Router::new()
        .route("/health", get(health_check))
        // XRPC routes under /xrpc namespace
        .route("/xrpc/blue.catbird.mls.createConvo", post(handlers::create_convo))
        .route("/xrpc/blue.catbird.mls.addMembers", post(handlers::add_members))
        .route("/xrpc/blue.catbird.mls.sendMessage", post(handlers::send_message))
        .route("/xrpc/blue.catbird.mls.leaveConvo", post(handlers::leave_convo))
        .route("/xrpc/blue.catbird.mls.getMessages", get(handlers::get_messages))
        .route("/xrpc/blue.catbird.mls.publishKeyPackage", post(handlers::publish_keypackage))
        .route("/xrpc/blue.catbird.mls.getKeyPackages", get(handlers::get_keypackages))
        .route("/xrpc/blue.catbird.mls.uploadBlob", post(handlers::upload_blob))
        .layer(TraceLayer::new_for_http())
        .with_state(db_pool);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("Server listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}
