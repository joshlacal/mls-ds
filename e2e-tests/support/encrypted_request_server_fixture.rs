use std::{io::Write as _, sync::Arc};

use anyhow::{Context, Result};
use axum::{extract::FromRef, Router};
use catbird_server::{
    auth::install_test_https_did_resolver,
    blob_store::BlobStore,
    handlers::chat::{chat_router, ChatRuntime},
    realtime::SseState,
    storage::DbPool,
};
use sqlx::postgres::PgPoolOptions;

const EXACT_DATABASE_URL: &str =
    "postgresql://127.0.0.1:5432/catbird_direct_requests_test_20260919";

#[derive(Clone)]
struct FixtureState {
    pool: DbPool,
    runtime: Arc<ChatRuntime>,
    blob_store: BlobStore,
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

impl FromRef<FixtureState> for BlobStore {
    fn from_ref(state: &FixtureState) -> Self {
        state.blob_store.clone()
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
        database_url == EXACT_DATABASE_URL,
        "server fixture refuses every database except {EXACT_DATABASE_URL}"
    );
    let resolver_host = std::env::var("REQUEST_FIXTURE_DID_HOST")
        .context("REQUEST_FIXTURE_DID_HOST is required")?;
    let resolver_port = std::env::var("REQUEST_FIXTURE_DID_PORT")
        .context("REQUEST_FIXTURE_DID_PORT is required")?
        .parse::<u16>()
        .context("REQUEST_FIXTURE_DID_PORT is not a u16")?;
    let resolver_ca_path = std::env::var("REQUEST_FIXTURE_DID_CA_PEM")
        .context("REQUEST_FIXTURE_DID_CA_PEM is required")?;
    let resolver_ca = std::fs::read(&resolver_ca_path)
        .with_context(|| format!("read resolver CA {resolver_ca_path}"))?;
    install_test_https_did_resolver(&resolver_host, resolver_port, &resolver_ca)
        .map_err(anyhow::Error::msg)?;

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .context("connect guarded request database")?;
    let runtime =
        Arc::new(ChatRuntime::from_env(Arc::new(SseState::new(64))).map_err(anyhow::Error::msg)?);
    runtime
        .validate_protocol_fence(&pool)
        .await
        .map_err(anyhow::Error::msg)?;

    let app: Router = chat_router::<FixtureState>().with_state(FixtureState {
        pool,
        runtime,
        blob_store: BlobStore::for_route_tests(),
    });
    let listen =
        std::env::var("REQUEST_FIXTURE_LISTEN").unwrap_or_else(|_| "127.0.0.1:0".to_owned());
    let listener = tokio::net::TcpListener::bind(&listen)
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
