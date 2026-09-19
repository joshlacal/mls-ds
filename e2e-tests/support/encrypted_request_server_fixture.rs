use std::{io::Write as _, sync::Arc};

use anyhow::{Context, Result};
use axum::{extract::FromRef, Router};
use catbird_server::{
    auth::install_test_https_did_resolver,
    blob_store::BlobStore,
    handlers::chat::{chat_router, install_test_https_relationship_resolver, ChatRuntime},
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
        .max_connections(4)
        .connect(&database_url)
        .await
        .context("connect guarded request database")?;
    let mut runtime =
        ChatRuntime::from_env(Arc::new(SseState::new(64))).map_err(anyhow::Error::msg)?;
    let push_event = match std::env::var("REQUEST_FIXTURE_PUSH_EVENT_URL") {
        Ok(endpoint) => {
            let bearer = std::env::var("REQUEST_FIXTURE_PUSH_ELIGIBILITY_BEARER")
                .context("REQUEST_FIXTURE_PUSH_ELIGIBILITY_BEARER is required")?;
            runtime = runtime
                .with_test_request_push_loopback(&endpoint, &bearer)
                .map_err(anyhow::Error::msg)?;
            let event_id = std::env::var("REQUEST_FIXTURE_PUSH_EVENT_ID")
                .context("REQUEST_FIXTURE_PUSH_EVENT_ID is required")?
                .parse::<uuid::Uuid>()
                .context("REQUEST_FIXTURE_PUSH_EVENT_ID is invalid")?;
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
            Some((event_id, trigger, result))
        }
        Err(_) => None,
    };
    let runtime = Arc::new(runtime);
    runtime
        .validate_protocol_fence(&pool)
        .await
        .map_err(anyhow::Error::msg)?;
    if let Some((event_id, trigger, result)) = push_event {
        let push_pool = pool.clone();
        let push_runtime = runtime.clone();
        tokio::spawn(async move {
            for _ in 0..9_000 {
                if trigger.exists() {
                    let outcome = catbird_server::workers::run_request_push_event_once_for_test(
                        &push_pool,
                        &push_runtime,
                        event_id,
                    )
                    .await;
                    let value = match outcome {
                        Ok(claimed) => {
                            serde_json::json!({"eventId":event_id,"claimed":claimed,"ok":claimed==1})
                        }
                        Err(error) => {
                            serde_json::json!({"eventId":event_id,"ok":false,"error":error})
                        }
                    };
                    let _ = std::fs::write(&result, serde_json::to_vec(&value).unwrap());
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            let _ = std::fs::write(&result, b"{\"ok\":false,\"error\":\"trigger timeout\"}");
        });
    }

    let app: Router = chat_router::<FixtureState>().with_state(FixtureState {
        pool,
        runtime,
        blob_store: BlobStore::for_route_tests(),
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
