use axum::{
    extract::{DefaultBodyLimit, FromRef},
    routing::{any, get, post},
    Router,
};
use jacquard_axum::IntoRouter;
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tokio::time::{interval, Duration};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Import from library crate instead of re-declaring modules
use catbird_server::{
    actors, auth, blob_store, block_sync, config, crypto, db, fanout, federation, handlers, health,
    metrics, middleware, models, realtime, storage, util,
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
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(true);
    let enforce_jti = std::env::var("ENFORCE_JTI")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
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
        "inline-trigger config loaded (Phase 2 B5)"
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
        fed_config.default_ds_endpoint.clone(),
        fed_config.endpoint_cache_ttl_secs,
    ));

    let service_auth = if let Some(ref key_pem) = fed_config.signing_key_pem {
        match federation::ServiceAuthClient::from_es256_pem(
            fed_config.self_did.clone(),
            key_pem.as_bytes(),
            None,
        ) {
            Ok(auth) => Some(Arc::new(auth)),
            Err(e) => {
                tracing::warn!(error = %e, "Failed to create service auth client, federation outbound disabled");
                None
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
    ));

    // Build receipt signer from the same PEM key used for service auth (if available).
    let receipt_signer = fed_config.signing_key_pem.as_ref().and_then(|pem| {
        use p256::pkcs8::DecodePrivateKey;
        match p256::ecdsa::SigningKey::from_pkcs8_pem(pem) {
            Ok(sk) => {
                tracing::info!("Receipt signer initialized");
                Some(federation::ReceiptSigner::new(
                    sk,
                    fed_config.self_did.clone(),
                ))
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse signing key for receipt signer");
                None
            }
        }
    });

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

    let mut base_router = Router::new()
        // Health check endpoints
        .route("/health", get(health::health))
        .route("/health/live", get(health::liveness))
        .route("/health/ready", get(health::readiness))
        .merge(metrics_router)
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024)) // 4 MB
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(
            middleware::logging::log_headers_middleware,
        ))
        // DID-based rate limiter for authenticated requests, IP-based backstop for unauthenticated
        .layer(axum::middleware::from_fn(
            middleware::rate_limit::rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            middleware::idempotency::IdempotencyLayer::new(db_pool.clone()),
            middleware::idempotency::idempotency_middleware,
        ))
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

    // mlsChat consolidated endpoints (PDSS federation prep)
    // All endpoints use IntoRouter for type-safe routing from lexicon-generated types.
    use catbird_server::generated::blue_catbird::mlsChat::{
        bootstrap_reset_group::BootstrapResetGroupRequest, check_blocks::CheckBlocksRequest,
        commit_group_change::CommitGroupChangeRequest, create_convo::CreateConvoRequest,
        delete_blob::DeleteBlobRequest, get_blob_usage::GetBlobUsageRequest,
        get_block_status::GetBlockStatusRequest, get_convo_settings::GetConvoSettingsRequest,
        get_convos::GetConvosRequest, get_group_state::GetGroupStateRequest,
        get_key_package_status::GetKeyPackageStatusRequest,
        get_key_packages::GetKeyPackagesRequest, get_messages::GetMessagesRequest,
        get_pending_devices::GetPendingDevicesRequest,
        get_subscription_ticket::GetSubscriptionTicketRequest, leave_convo::LeaveConvoRequest,
        list_devices::ListDevicesRequest, opt_in::OptInRequest,
        publish_key_packages::PublishKeyPackagesRequest, register_device::RegisterDeviceRequest,
        remove_device::RemoveDeviceRequest, report_spam::ReportSpamRequest,
        send_message::SendMessageRequest, update_convo::UpdateConvoRequest,
        update_cursor::UpdateCursorRequest,
    };
    use jacquard_axum::IntoRouter;

    let mls_chat_router = Router::new()
        // Identity & Devices
        .merge(RegisterDeviceRequest::into_router(
            handlers::mls_chat::register_device_post,
        ))
        .merge(PublishKeyPackagesRequest::into_router(
            handlers::mls_chat::publish_key_packages_post,
        ))
        .merge(ListDevicesRequest::into_router(
            handlers::mls_chat::list_devices,
        ))
        .merge(GetPendingDevicesRequest::into_router(
            handlers::mls_chat::get_pending_devices,
        ))
        .merge(GetKeyPackageStatusRequest::into_router(
            handlers::mls_chat::get_key_package_status,
        ))
        .merge(GetKeyPackagesRequest::into_router(
            handlers::mls_chat::get_key_packages,
        ))
        .merge(RemoveDeviceRequest::into_router(
            handlers::mls_chat::remove_device,
        ))
        // Conversations & Messaging
        .merge(CreateConvoRequest::into_router(
            handlers::mls_chat::create_convo,
        ))
        .merge(BootstrapResetGroupRequest::into_router(
            handlers::mls_chat::bootstrap_reset_group::bootstrap_reset_group,
        ))
        .merge(GetConvosRequest::into_router(
            handlers::mls_chat::get_convos,
        ))
        .merge(SendMessageRequest::into_router(
            handlers::mls_chat::send_message,
        ))
        .merge(GetMessagesRequest::into_router(
            handlers::mls_chat::get_messages,
        ))
        .merge(UpdateCursorRequest::into_router(
            handlers::mls_chat::update_cursor,
        ))
        // Group State
        .merge(GetGroupStateRequest::into_router(
            handlers::mls_chat::get_group_state,
        ))
        .merge(CommitGroupChangeRequest::into_router(
            handlers::mls_chat::commit_group_change,
        ))
        // Conversation Management
        .merge(UpdateConvoRequest::into_router(
            handlers::mls_chat::update_convo,
        ))
        .merge(GetConvoSettingsRequest::into_router(
            handlers::mls_chat::get_convo_settings,
        ))
        .merge(LeaveConvoRequest::into_router(
            handlers::mls_chat::leave_convo,
        ))
        // Moderation & Blocks
        .merge(ReportSpamRequest::into_router(
            handlers::mls_chat::report_spam_post,
        ))
        .merge(CheckBlocksRequest::into_router(
            handlers::mls_chat::check_blocks::check_blocks_post,
        ))
        .merge(GetBlockStatusRequest::into_router(
            handlers::mls_chat::get_block_status::get_block_status_post,
        ))
        .merge(OptInRequest::into_router(handlers::mls_chat::opt_in_post))
        // Subscriptions
        .merge(GetSubscriptionTicketRequest::into_router(
            handlers::mls_chat::get_subscription_ticket,
        ))
        // WebSocket subscription endpoints (lexicon + legacy NSIDs)
        .route(
            "/xrpc/blue.catbird.mlsChat.subscribeEvents",
            get(realtime::websocket::subscribe_convo_events),
        )
        // Group Reset
        .route(
            "/xrpc/blue.catbird.mlsChat.resetGroup",
            post(handlers::mls_chat::reset_group),
        )
        // Recovery Failure Reporting
        .route(
            "/xrpc/blue.catbird.mlsChat.reportRecoveryFailure",
            post(handlers::mls_chat::report_recovery_failure),
        )
        // Federation
        .route(
            "/xrpc/blue.catbird.mlsChat.requestFailover",
            post(handlers::mls_chat::request_failover),
        )
        // Group Health
        .route(
            "/xrpc/blue.catbird.mlsChat.getGroupHealth",
            get(handlers::mls_chat::get_group_health),
        )
        // Delivery Status
        .route(
            "/xrpc/blue.catbird.mlsChat.getDeliveryStatus",
            get(handlers::mls_chat::get_delivery_status),
        )
        // Blob Storage
        .route(
            "/xrpc/blue.catbird.mlsChat.uploadBlob",
            post(handlers::mls_chat::upload_blob).layer(DefaultBodyLimit::max(11 * 1024 * 1024)), // 11MB (10MB + overhead)
        )
        .route(
            "/xrpc/blue.catbird.mlsChat.getBlob",
            get(handlers::mls_chat::get_blob),
        )
        .merge(GetBlobUsageRequest::into_router(
            handlers::mls_chat::get_blob_usage,
        ))
        .merge(DeleteBlobRequest::into_router(
            handlers::mls_chat::delete_blob,
        ))
        // Group Metadata Blob Storage
        .route(
            "/xrpc/blue.catbird.mlsChat.putGroupMetadataBlob",
            post(handlers::mls_chat::put_group_metadata_blob)
                .layer(DefaultBodyLimit::max(2 * 1024 * 1024)), // 2MB (1MB + overhead)
        )
        .route(
            "/xrpc/blue.catbird.mlsChat.getGroupMetadataBlob",
            get(handlers::mls_chat::get_group_metadata_blob),
        )
        // ── Spec §11 route aliases ──
        // POST aliases: spec-named endpoints that delegate to consolidated handlers.
        // The request body already contains the `action` field for dispatch.
        .route(
            "/xrpc/blue.catbird.mlsChat.addMembers",
            post(handlers::mls_chat::commit_group_change),
        )
        .route(
            "/xrpc/blue.catbird.mlsChat.removeMembers",
            post(handlers::mls_chat::commit_group_change),
        )
        .route(
            "/xrpc/blue.catbird.mlsChat.processExternalCommit",
            post(handlers::mls_chat::commit_group_change),
        )
        .route(
            "/xrpc/blue.catbird.mlsChat.publishGroupInfo",
            post(handlers::mls_chat::commit_group_change),
        )
        .route(
            "/xrpc/blue.catbird.mlsChat.syncKeyPackages",
            post(handlers::mls_chat::publish_key_packages_post),
        )
        // GET aliases: spec-named endpoints that delegate to consolidated handlers
        .route(
            "/xrpc/blue.catbird.mlsChat.getGroupInfo",
            get(handlers::mls_chat::get_group_state),
        )
        .route(
            "/xrpc/blue.catbird.mlsChat.getKeyPackageStats",
            get(handlers::mls_chat::get_key_package_status),
        )
        .with_state(app_state.clone());

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

    // Final outermost layer: ensure every response has a Content-Type header.
    // Handlers that return bare `StatusCode::X` (120+ call sites across the mls_chat
    // handlers) produce empty-body, header-less responses. Clients like Petrel's
    // generated XRPC layer validate Content-Type and throw on empty headers before
    // they can inspect the status code. Applying this to the merged app covers all
    // three sub-routers without having to patch every handler.
    let app = base_router
        .merge(mls_chat_router)
        .merge(ds_router)
        .layer(axum::middleware::from_fn(
            middleware::response_content_type::response_content_type_middleware,
        ));

    let port = std::env::var("SERVER_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
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
