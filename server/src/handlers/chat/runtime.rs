//! Process-wide runtime configuration for the clean-chat handler layer.
//!
//! Account authorization is verified by the standard service-auth layer; this
//! runtime intentionally carries no Nest key, token, or DPoP authority.

use serde_json::Value;
use std::{fmt, sync::Arc};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use url::Url;
use zeroize::Zeroizing;

use crate::chat_protocol::repository::relationship::load_fixed_relationship_authority_startup_guard;
use crate::chat_protocol::{relationship_policy::ProductionRelationshipAuthority, CursorSealer};
use crate::labyrinth::recovery_crypto::RecoveryCrypto;
use crate::labyrinth::recovery_tombstones::RecoveryTombstones;

#[cfg(feature = "test-support")]
pub fn install_test_https_relationship_resolver(
    hosts: &[String],
    port: u16,
    ca_certificate_pem: &[u8],
) -> Result<(), String> {
    crate::chat_protocol::relationship_policy::install_test_https_relationship_transport(
        hosts,
        port,
        ca_certificate_pem,
    )
}
use crate::db::DbPool;
use crate::realtime::{SseState, StreamEvent};

pub const MAX_WS_PER_DEVICE: usize = 4;
pub const MAX_WS_PER_DID: usize = 16;
pub const MAX_WS_GLOBAL: usize = 8_192;

#[derive(Default)]
struct WsRegistryState {
    total: usize,
    per_did: std::collections::HashMap<String, usize>,
    per_device: std::collections::HashMap<
        (String, uuid::Uuid),
        Vec<(u64, tokio::sync::watch::Sender<bool>)>,
    >,
    next_conn_id: u64,
}

/// RAII guard for an active `subscribeEvents` WebSocket connection (`M-F05`, `M-F08`).
pub struct WsSlotGuard {
    registry: Arc<std::sync::Mutex<WsRegistryState>>,
    did: String,
    device_id: uuid::Uuid,
    conn_id: u64,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
}

impl WsSlotGuard {
    pub async fn cancelled(&mut self) {
        if *self.cancel_rx.borrow() {
            return;
        }
        let _ = self.cancel_rx.changed().await;
    }
}

impl Drop for WsSlotGuard {
    fn drop(&mut self) {
        let mut guard = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        guard.total = guard.total.saturating_sub(1);
        if let Some(count) = guard.per_did.get_mut(&self.did) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                guard.per_did.remove(&self.did);
            }
        }
        let key = (self.did.clone(), self.device_id);
        if let Some(entries) = guard.per_device.get_mut(&key) {
            entries.retain(|(id, _)| *id != self.conn_id);
            if entries.is_empty() {
                guard.per_device.remove(&key);
            }
        }
    }
}

/// Shared, immutable clean-chat runtime, stored in `AppState` and extracted by
/// every chat handler as `State<Arc<ChatRuntime>>`.
pub struct ChatRuntime {
    cutover_enabled: bool,
    request_producers_enabled: bool,
    request_receipt_signer: Option<
        Arc<crate::chat_protocol::repository::direct_request_receipts::DirectRequestReceiptSigner>,
    >,
    i13_receipt_signer: Option<Arc<crate::federation::receipt::I13ReceiptSigner>>,
    require_signed_reads: bool,
    ws_registry: Arc<std::sync::Mutex<WsRegistryState>>,
    events_notify: Arc<tokio::sync::Notify>,
    request_push_enabled: bool,
    requests_ready: std::sync::atomic::AtomicBool,
    relationship_authority: Arc<ProductionRelationshipAuthority>,
    sse_state: Arc<SseState>,
    cursor_sealer: Option<CursorSealer>,
    recovery_crypto: Option<Arc<RecoveryCrypto>>,
    recovery_tombstones: Option<Arc<RecoveryTombstones>>,
    subscription_endpoint: Option<String>,
    resolver: Option<Arc<crate::federation::DsResolver>>,
    commit_submitter: Option<Arc<crate::federation::commit_submitter::RemoteCommitSubmitter>>,
    space_host_config: Option<crate::space_host::SpaceHostConfig>,
    push_gateway_client: Option<Arc<crate::push_gateway::client::PushGatewayClient>>,
    clock: Arc<dyn crate::sim_hooks::DsClock>,
    spawner: Arc<dyn crate::sim_hooks::TaskSpawner>,
    #[cfg(feature = "sim")]
    sim_hooks: Option<Arc<crate::sim_hooks::SimDsHooks>>,
}

impl fmt::Debug for ChatRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChatRuntime")
            .field("cutover_enabled", &self.cutover_enabled)
            .field("relationship_authority", &"fixed-production-authority")
            .field("request_push_enabled", &self.request_push_enabled)
            .field(
                "i13_receipt_signer_configured",
                &self.i13_receipt_signer.is_some(),
            )
            .field("require_signed_reads", &self.require_signed_reads)
            .field("sse_state", &"conversation-filtered")
            .field("cursor_sealer_configured", &self.cursor_sealer.is_some())
            .field(
                "recovery_crypto_configured",
                &self.recovery_crypto.is_some(),
            )
            .field(
                "recovery_tombstones_configured",
                &self.recovery_tombstones.is_some(),
            )
            .field(
                "subscription_endpoint_configured",
                &self.subscription_endpoint.is_some(),
            )
            .field("resolver_configured", &self.resolver.is_some())
            .field(
                "commit_submitter_configured",
                &self.commit_submitter.is_some(),
            )
            .field("space_host_configured", &self.space_host_config.is_some())
            .field(
                "push_gateway_client_configured",
                &self.push_gateway_client.is_some(),
            )
            .finish()
    }
}

impl ChatRuntime {
    /// Build the runtime from the process environment.
    ///
    /// - `CHAT_CUTOVER_ENABLED` (bool, default `false`) — the global cutover
    ///   gate predicate (OQ-2).
    /// - Nest verifier vars (`CHAT_NEST_ISSUER`, `CHAT_NEST_AUDIENCE`,
    ///   `CHAT_NEST_KEY_ID`, `CHAT_NEST_VERIFYING_KEY`, `CHAT_INSTANCE_ID`,
    ///   `CHAT_EXTERNAL_BASE`, optional `CHAT_EXTERNAL_BASE_ALLOWED_PORTS`).
    ///   When `CHAT_NEST_ISSUER` is unset the verifier is absent; otherwise
    ///   every field is required.
    ///
    /// Returns `Err` when cutover is enabled without a fully configured
    /// verifier, or when any verifier field is malformed.
    pub fn from_env(sse_state: Arc<SseState>) -> Result<Self, String> {
        let cutover_enabled = env_flag("CHAT_CUTOVER_ENABLED");
        let cursor_sealer = build_cursor_sealer_from_env()?;
        let subscription_endpoint = parse_subscription_endpoint_from_env()?;
        #[cfg(feature = "test-support")]
        let relationship_authority = if std::env::var("FEDERATION_TEST_ALLOW_ALL_RELATIONSHIPS")
            .as_deref()
            == Ok("true")
        {
            if std::env::var("APP_ENV").as_deref() != Ok("test") {
                return Err(
                    "FEDERATION_TEST_ALLOW_ALL_RELATIONSHIPS requires APP_ENV=test".to_owned(),
                );
            }
            Arc::new(
                ProductionRelationshipAuthority::federation_allow_all_for_test().map_err(
                    |error| format!("federation test relationship authority rejected: {error:?}"),
                )?,
            )
        } else {
            Arc::new(ProductionRelationshipAuthority::from_startup_guard(
                load_fixed_relationship_authority_startup_guard()
                    .map_err(|error| format!("fixed relationship authority rejected: {error:?}"))?,
            ))
        };
        #[cfg(not(feature = "test-support"))]
        let relationship_authority = Arc::new(ProductionRelationshipAuthority::from_startup_guard(
            load_fixed_relationship_authority_startup_guard()
                .map_err(|error| format!("fixed relationship authority rejected: {error:?}"))?,
        ));
        if cutover_enabled && cursor_sealer.is_none() {
            return Err(
                "CHAT_CUTOVER_ENABLED is set but the clean-chat cursor sealer is not configured \
                 (set CHAT_CURSOR_KEY_ID and CHAT_CURSOR_SEALING_SECRET as canonical base64url 32-byte values)"
                    .to_owned(),
            );
        }
        if cutover_enabled && subscription_endpoint.is_none() {
            return Err(
                "CHAT_CUTOVER_ENABLED is set but CHAT_SUBSCRIPTION_ENDPOINT is not configured"
                    .to_owned(),
            );
        }
        let request_producers_enabled = env_flag("CHAT_DIRECT_REQUESTS_ENABLED");
        let request_push_enabled = env_flag("CHAT_REQUEST_PUSH_ENABLED");
        let request_receipt_signer = if request_producers_enabled
            || std::env::var_os("CHAT_REQUEST_RECEIPT_SIGNING_KEY_PEM").is_some()
        {
            if !cutover_enabled {
                return Err("direct requests require chat cutover".into());
            }
            let receipt_pem = std::env::var("CHAT_REQUEST_RECEIPT_SIGNING_KEY_PEM")
                .map_err(|_| "missing dedicated request receipt key")?;
            let service_pem = std::env::var("SIGNING_KEY_PEM")
                .map_err(|_| "missing service signing key for separation check")?;
            let document = std::env::var("CHAT_REQUEST_RECEIPT_DID_DOCUMENT_JSON")
                .map_err(|_| "missing request receipt authority document")?;
            Some(Arc::new(crate::chat_protocol::repository::direct_request_receipts::DirectRequestReceiptSigner::configured(&receipt_pem,&service_pem,&document)?))
        } else {
            None
        };
        if request_push_enabled && !cutover_enabled {
            return Err("request push requires chat cutover".into());
        }
        let require_signed_reads = env_flag("CHAT_REQUIRE_SIGNED_READS");
        let space_host_config = crate::space_host::SpaceHostConfig::from_env();
        let push_gateway_client = space_host_config.as_ref().map(|cfg| {
            Arc::new(crate::push_gateway::client::PushGatewayClient::new_es256(
                cfg.authority_did.clone(),
                cfg.signing_key.clone(),
            ))
        });
        if request_push_enabled && push_gateway_client.is_none() {
            return Err(
                "CHAT_REQUEST_PUSH_ENABLED requires the Push Gateway client (SERVICE_DID and SIGNING_KEY_PEM)"
                    .into(),
            );
        }
        Ok(Self {
            cutover_enabled,
            request_producers_enabled,
            request_receipt_signer,
            // Only startup's validated signer issues receipts (`from_env_with_federation`).
            i13_receipt_signer: None,
            require_signed_reads,
            ws_registry: Arc::new(std::sync::Mutex::new(WsRegistryState::default())),
            events_notify: Arc::new(tokio::sync::Notify::new()),
            request_push_enabled,
            requests_ready: std::sync::atomic::AtomicBool::new(false),
            relationship_authority,
            sse_state,
            cursor_sealer,
            recovery_crypto: None,
            recovery_tombstones: None,
            subscription_endpoint,
            resolver: None,
            commit_submitter: None,
            space_host_config,
            push_gateway_client,
            clock: Arc::new(crate::sim_hooks::SystemDsClock),
            spawner: Arc::new(crate::sim_hooks::TokioTaskSpawner),
            #[cfg(feature = "sim")]
            sim_hooks: crate::sim_hooks::active_sim_ds(),
        })
    }

    pub fn with_clock(mut self, clock: Arc<dyn crate::sim_hooks::DsClock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn clock(&self) -> &Arc<dyn crate::sim_hooks::DsClock> {
        &self.clock
    }

    #[cfg(feature = "sim")]
    pub fn with_sim_hooks(mut self, hooks: Arc<crate::sim_hooks::SimDsHooks>) -> Self {
        self.sim_hooks = Some(hooks);
        self
    }

    #[cfg(feature = "sim")]
    pub(crate) fn sim_hooks(&self) -> Option<Arc<crate::sim_hooks::SimDsHooks>> {
        self.sim_hooks.clone()
    }

    pub fn with_push_gateway_client(
        mut self,
        client: Arc<crate::push_gateway::client::PushGatewayClient>,
    ) -> Self {
        self.push_gateway_client = Some(client);
        self
    }

    pub fn with_spawner(mut self, spawner: Arc<dyn crate::sim_hooks::TaskSpawner>) -> Self {
        self.sse_state.set_spawner(Arc::clone(&spawner));
        self.spawner = spawner;
        self
    }

    pub fn spawner(&self) -> &Arc<dyn crate::sim_hooks::TaskSpawner> {
        &self.spawner
    }

    pub fn with_space_host_config(mut self, config: crate::space_host::SpaceHostConfig) -> Self {
        self.push_gateway_client = Some(Arc::new(
            crate::push_gateway::client::PushGatewayClient::new_es256(
                config.authority_did.clone(),
                config.signing_key.clone(),
            ),
        ));
        self.space_host_config = Some(config);
        self
    }

    /// Configure an offline deterministic allow-all relationship authority for the
    /// simulation harness without modifying production `from_env` startup guards.
    /// Absent from production builds.
    #[cfg(any(test, feature = "test-support", feature = "sim"))]
    pub fn with_sim_allow_all_relationships(mut self) -> Result<Self, String> {
        self.relationship_authority = Arc::new(
            ProductionRelationshipAuthority::sim_allow_all()
                .map_err(|e| format!("sim relationship authority rejected: {e:?}"))?,
        );
        Ok(self)
    }

    /// [`Self::with_sim_allow_all_relationships`] whose public sources answer
    /// `fault` instead while a test sets it. Absent from production builds.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_sim_faulty_relationships(
        mut self,
        fault: crate::chat_protocol::relationship_policy::SimSourceFault,
    ) -> Result<Self, String> {
        self.relationship_authority = Arc::new(
            ProductionRelationshipAuthority::sim_fault(fault)
                .map_err(|e| format!("sim relationship authority rejected: {e:?}"))?,
        );
        Ok(self)
    }

    pub fn from_env_with_resolver(
        sse_state: Arc<SseState>,
        resolver: Arc<crate::federation::DsResolver>,
    ) -> Result<Self, String> {
        let mut runtime = Self::from_env(sse_state)?;
        runtime.resolver = Some(resolver);
        Ok(runtime)
    }

    pub fn with_resolver(mut self, resolver: Arc<crate::federation::DsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Install the startup-validated KEK and replayed external erasure journal.
    pub fn with_recovery_shares(
        mut self,
        crypto: Arc<RecoveryCrypto>,
        tombstones: Arc<RecoveryTombstones>,
    ) -> Self {
        self.recovery_crypto = Some(crypto);
        self.recovery_tombstones = Some(tombstones);
        self
    }

    pub fn recovery_crypto(&self) -> Option<&Arc<RecoveryCrypto>> {
        self.recovery_crypto.as_ref()
    }

    pub fn recovery_tombstones(&self) -> Option<&Arc<RecoveryTombstones>> {
        self.recovery_tombstones.as_ref()
    }

    pub fn resolver(&self) -> Option<&Arc<crate::federation::DsResolver>> {
        self.resolver.as_ref()
    }

    /// The production runtime: `i13_receipt_signer` is the one validated signer
    /// startup also gives the commit sequencer and the group relay.
    pub fn from_env_with_federation(
        sse_state: Arc<SseState>,
        resolver: Arc<crate::federation::DsResolver>,
        commit_submitter: Option<Arc<crate::federation::commit_submitter::RemoteCommitSubmitter>>,
        i13_receipt_signer: Option<Arc<crate::federation::receipt::I13ReceiptSigner>>,
    ) -> Result<Self, String> {
        let mut runtime = Self::from_env_with_resolver(sse_state, resolver)?;
        runtime.commit_submitter = commit_submitter;
        runtime.i13_receipt_signer = i13_receipt_signer;
        Ok(runtime)
    }

    pub fn with_commit_submitter(
        mut self,
        submitter: Arc<crate::federation::commit_submitter::RemoteCommitSubmitter>,
    ) -> Self {
        self.commit_submitter = Some(submitter);
        self
    }

    pub fn commit_submitter(
        &self,
    ) -> Option<&Arc<crate::federation::commit_submitter::RemoteCommitSubmitter>> {
        self.commit_submitter.as_ref()
    }

    /// The global cutover gate (OQ-2). `pub` so the binary crate can decide, at
    /// startup, whether to spawn the clean-chat background workers at all: while
    /// the gate is off nothing in this tree may touch `chat.*`, and a worker that
    /// was merely spawned-and-no-opping would still hold a timer.
    pub fn cutover_enabled(&self) -> bool {
        self.cutover_enabled
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn relationship_authority_for_test(&self) -> &Arc<ProductionRelationshipAuthority> {
        &self.relationship_authority
    }

    pub(crate) fn relationship_authority(&self) -> &Arc<ProductionRelationshipAuthority> {
        &self.relationship_authority
    }
    pub(crate) fn cursor_sealer(&self) -> Option<&CursorSealer> {
        self.cursor_sealer.as_ref()
    }

    pub(crate) fn subscription_endpoint(&self) -> Option<&str> {
        self.subscription_endpoint.as_deref()
    }

    /// Validate the process' clean-chat protocol fence against PostgreSQL.
    ///
    /// The protocol instance and event-retention rows form one immutable
    /// deployment fence. A runtime with no configured sealer, a missing
    /// singleton, a missing retention row, or a key-id mismatch must fail
    /// closed before any clean-chat worker or route is started. The singleton
    /// schema intentionally has no live key rotation: changing the cursor key
    /// requires an explicit protocol migration/cutover that invalidates the
    /// old runtime rather than accepting a second key here.
    pub async fn validate_protocol_fence(&self, pool: &DbPool) -> Result<(), String> {
        let sealer = self.cursor_sealer.as_ref().ok_or_else(|| {
            "clean-chat protocol fence cannot be validated without a cursor sealer".to_owned()
        })?;
        let expected_key_id = URL_SAFE_NO_PAD.encode(sealer.key_id());
        let mut conn = pool.acquire().await.map_err(|error| {
            format!("failed to acquire connection for clean-chat protocol fence: {error}")
        })?;

        let protocol = sqlx::query_as::<_, (uuid::Uuid, String)>(
            "SELECT p.protocol_instance_id, p.cursor_key_id \
             FROM chat.protocol_instances AS p \
             WHERE p.singleton = TRUE",
        )
        .fetch_optional(&mut *conn)
        .await
        .map_err(|error| format!("failed to load clean-chat protocol instance fence: {error}"))?
        .ok_or_else(|| "clean-chat protocol instance singleton is missing".to_owned())?;

        if protocol.1 != expected_key_id {
            return Err(format!(
                "clean-chat cursor key id does not match the durable protocol fence \
                 (runtime={expected_key_id}, database={})",
                protocol.1
            ));
        }

        let retention_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM chat.event_retention \
             WHERE protocol_instance_id = $1)",
        )
        .bind(protocol.0)
        .fetch_one(&mut *conn)
        .await
        .map_err(|error| format!("failed to load clean-chat event-retention fence: {error}"))?;
        if !retention_exists {
            return Err(format!(
                "clean-chat event-retention row is missing for protocol instance {}",
                protocol.0
            ));
        }
        drop(conn);
        if self.request_receipt_signer.is_none() {
            let schema_present: bool = sqlx::query_scalar(
                "SELECT to_regclass('chat.direct_request_attempts') IS NOT NULL",
            )
            .fetch_one(pool)
            .await
            .map_err(|_| "request rollback schema check")?;
            if schema_present {
                let durable: bool =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM chat.direct_request_attempts)")
                        .fetch_one(pool)
                        .await
                        .map_err(|_| "request rollback authority check")?;
                if durable {
                    return Err("durable requests require receipt authority for cancellation, outcome, and consent even when producers are disabled".into());
                }
            }
        }
        if let Some(signer) = &self.request_receipt_signer {
            signer.validate_and_retain_keys(pool).await?;
            self.requests_ready
                .store(true, std::sync::atomic::Ordering::Release);
        }
        Ok(())
    }

    pub(crate) fn request_producers_enabled(&self) -> bool {
        self.request_producers_enabled
            && self
                .requests_ready
                .load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn request_receipt_signer(
        &self,
    ) -> Option<
        &crate::chat_protocol::repository::direct_request_receipts::DirectRequestReceiptSigner,
    > {
        self.requests_ready
            .load(std::sync::atomic::Ordering::Acquire)
            .then_some(self.request_receipt_signer.as_deref())
            .flatten()
    }

    /// Direct-request wakes run only with `CHAT_REQUEST_PUSH_ENABLED` and the
    /// D2 Push Gateway client this DS signs `blue.catbird.push.deliver` with.
    pub fn request_push_enabled(&self) -> bool {
        self.request_push_client().is_some()
    }

    pub(crate) fn request_push_client(
        &self,
    ) -> Option<&Arc<crate::push_gateway::client::PushGatewayClient>> {
        self.request_push_enabled
            .then_some(self.push_gateway_client.as_ref())
            .flatten()
    }

    pub fn sse_state(&self) -> &Arc<SseState> {
        &self.sse_state
    }

    pub(crate) async fn subscribe_typing(
        &self,
        conversation_id: &str,
    ) -> tokio::sync::broadcast::Receiver<StreamEvent> {
        self.sse_state
            .get_channel(conversation_id)
            .await
            .subscribe()
    }

    pub(crate) async fn publish_typing(&self, event: Value) {
        // The clean handler already produced the generated DTO. Deserialize
        // that exact payload instead of reducing it to the legacy cursor/DID
        // shape: actor device, expiry, and typing id are protocol fields.
        let Ok(typing) = serde_json::from_value::<
            catbird_atproto::generated::blue_catbird::chat::TypingEvent,
        >(event) else {
            return;
        };
        let conversation_id = typing.conversation_id.to_string();
        self.sse_state.enqueue(
            &conversation_id,
            StreamEvent::CleanTypingEvent {
                actor_device_id: typing.actor_device_id,
                actor_did: typing.actor_did,
                conversation_id: typing.conversation_id,
                expires_at: typing.expires_at,
                is_typing: typing.is_typing,
                typing_id: typing.typing_id,
            },
        );
    }

    pub fn with_i13_receipt_signer(
        mut self,
        signer: crate::federation::receipt::I13ReceiptSigner,
    ) -> Self {
        self.i13_receipt_signer = Some(Arc::new(signer));
        self
    }

    /// Supply a node-local C33 authority before validating the simulation pool.
    #[cfg(feature = "sim")]
    pub fn with_request_receipt_keys(
        mut self,
        receipt_pem: &str,
        service_pem: &str,
        document_json: &str,
    ) -> Result<Self, String> {
        let signer = crate::chat_protocol::repository::direct_request_receipts::DirectRequestReceiptSigner::configured(
            receipt_pem, service_pem, document_json,
        )?;
        self.request_receipt_signer = Some(Arc::new(signer));
        self.requests_ready
            .store(false, std::sync::atomic::Ordering::Release);
        Ok(self)
    }

    /// Enable request producers on a simulated node, as `CHAT_DIRECT_REQUESTS_ENABLED`
    /// does for a process; they still wait for the validated receipt authority.
    #[cfg(feature = "sim")]
    pub fn with_request_producers(mut self) -> Self {
        self.request_producers_enabled = true;
        self
    }

    pub fn i13_receipt_signer(&self) -> Option<&crate::federation::receipt::I13ReceiptSigner> {
        self.i13_receipt_signer.as_deref()
    }

    pub fn with_require_signed_reads(mut self, required: bool) -> Self {
        self.require_signed_reads = required;
        self
    }

    pub fn require_signed_reads(&self) -> bool {
        self.require_signed_reads
    }

    /// Acquire a bounded WebSocket slot (`<= 4` per device, `<= 16` per DID,
    /// `<= 8192` global) or fail closed for `RateLimited` (`M-F05`).
    pub fn acquire_ws_slot(&self, did: &str, device_id: uuid::Uuid) -> Result<WsSlotGuard, ()> {
        let mut guard = self.ws_registry.lock().unwrap_or_else(|e| e.into_inner());
        let did_count = guard.per_did.get(did).copied().unwrap_or(0);
        let key = (did.to_owned(), device_id);
        let dev_count = guard.per_device.get(&key).map(Vec::len).unwrap_or(0);
        if guard.total >= MAX_WS_GLOBAL
            || did_count >= MAX_WS_PER_DID
            || dev_count >= MAX_WS_PER_DEVICE
        {
            return Err(());
        }
        guard.total += 1;
        *guard.per_did.entry(did.to_owned()).or_insert(0) += 1;
        guard.next_conn_id += 1;
        let conn_id = guard.next_conn_id;
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        guard
            .per_device
            .entry(key)
            .or_default()
            .push((conn_id, cancel_tx));
        Ok(WsSlotGuard {
            registry: Arc::clone(&self.ws_registry),
            did: did.to_owned(),
            device_id,
            conn_id,
            cancel_rx,
        })
    }

    /// Evict all active WebSocket connections for `(did, device_id)` (`M-F08`).
    pub fn disconnect_device_ws(&self, did: &str, device_id: uuid::Uuid) -> usize {
        let guard = self.ws_registry.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entries) = guard.per_device.get(&(did.to_owned(), device_id)) else {
            return 0;
        };
        for (_, tx) in entries {
            let _ = tx.send(true);
        }
        entries.len()
    }

    /// Wake all `subscribeEvents` loops immediately after durable event commits (`M-F05`).
    pub fn notify_events(&self) {
        self.events_notify.notify_waiters();
    }

    /// Wait for either `notify_events()` or `timeout` fallback (`M-F05`).
    pub async fn wait_for_events_or_timeout(&self, timeout_dur: std::time::Duration) -> bool {
        tokio::time::timeout(timeout_dur, self.events_notify.notified())
            .await
            .is_ok()
    }

    pub fn push_gateway_client(
        &self,
    ) -> Option<&Arc<crate::push_gateway::client::PushGatewayClient>> {
        self.push_gateway_client.as_ref()
    }

    /// Post-commit (`M-F04`) Space credential revocation + webhook fan-out across all active Spaces
    /// for `did` when one of `did`'s devices is revoked (`revokeDevice`).
    pub fn spawn_post_commit_device_revoked(&self, pool: &DbPool, did: &str) {
        let Some(cfg) = self.space_host_config.clone() else {
            return;
        };
        let pool = pool.clone();
        let did = did.to_owned();
        let clock = Arc::clone(&self.clock);
        #[cfg(feature = "sim")]
        let sim_hooks = self.sim_hooks.clone();
        self.spawner.spawn_box(
            "chat.post_commit.device_revoked",
            Box::pin(async move {
                let fut = crate::sim_hooks::scope_ds_clock(clock, async move {
                    let host = crate::space_host::SpaceHostRuntime::new(pool, cfg);
                    let _ = crate::space_host::revocation_fanout::revoke_user_space_credentials_across_conversations(
                        &host,
                        &did,
                    )
                    .await;
                });
                #[cfg(feature = "sim")]
                {
                    crate::sim_hooks::scope_optional_sim_ds(sim_hooks, fut).await;
                }
                #[cfg(not(feature = "sim"))]
                {
                    fut.await;
                }
            }),
        );
    }

    /// Post-commit (`M-F04`) Space deletion fan-out when `closeConversation` closes a generation.
    pub fn spawn_post_commit_close_conversation(
        &self,
        pool: &DbPool,
        endpoint: crate::chat_protocol::error::ChatEndpoint,
        response_bytes: &[u8],
        prepared_space: Option<crate::space_host::revocation_fanout::PreparedSpaceDeletedFanout>,
    ) {
        if endpoint != crate::chat_protocol::error::ChatEndpoint::CloseConversation {
            return;
        }
        let Some(cfg) = self.space_host_config.clone() else {
            return;
        };
        if let Some(prepared) = prepared_space {
            let pool = pool.clone();
            let clock = Arc::clone(&self.clock);
            #[cfg(feature = "sim")]
            let sim_hooks = self.sim_hooks.clone();
            self.spawner.spawn_box(
                "chat.post_commit.close_conversation",
                Box::pin(async move {
                    let fut = crate::sim_hooks::scope_ds_clock(clock, async move {
                        let host = crate::space_host::SpaceHostRuntime::new(pool, cfg);
                        let _ =
                            crate::space_host::revocation_fanout::deliver_prepared_space_deleted(
                                &host, prepared,
                            )
                            .await;
                    });
                    #[cfg(feature = "sim")]
                    {
                        crate::sim_hooks::scope_optional_sim_ds(sim_hooks, fut).await;
                    }
                    #[cfg(not(feature = "sim"))]
                    {
                        fut.await;
                    }
                }),
            );
            return;
        }
        let Ok(val) = serde_json::from_slice::<Value>(response_bytes) else {
            return;
        };
        let Some(cid) = val
            .pointer("/result/entry/conversationId")
            .or_else(|| val.pointer("/entry/conversationId"))
            .and_then(Value::as_str)
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
        else {
            return;
        };
        let gen = val
            .pointer("/result/entry/signedRequest/body/prior/generation")
            .or_else(|| val.pointer("/entry/generation"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let pool = pool.clone();
        let clock = Arc::clone(&self.clock);
        #[cfg(feature = "sim")]
        let sim_hooks = self.sim_hooks.clone();
        self.spawner.spawn_box(
            "chat.post_commit.close_conversation",
            Box::pin(async move {
                let fut = crate::sim_hooks::scope_ds_clock(clock, async move {
                    let host = crate::space_host::SpaceHostRuntime::new(pool, cfg);
                    let _ =
                        crate::space_host::revocation_fanout::fan_out_space_deleted_for_conversation(
                            &host, cid, gen,
                        )
                        .await;
                });
                #[cfg(feature = "sim")]
                {
                    crate::sim_hooks::scope_optional_sim_ds(sim_hooks, fut).await;
                }
                #[cfg(not(feature = "sim"))]
                {
                    fut.await;
                }
            }),
        );
    }

    /// Post-commit (`M-F04`) Space credential revocation + webhook fan-out when a membership transition
    /// (`commit`, `policy`, `leaveCommit`, zero-leaf `leavePolicy`) removes or closes a participant period.
    pub fn spawn_post_commit_membership_transition(&self, pool: &DbPool, response_bytes: &[u8]) {
        let Some(cfg) = self.space_host_config.clone() else {
            return;
        };
        let Ok(val) = serde_json::from_slice::<Value>(response_bytes) else {
            return;
        };
        let Some(cid) = val
            .pointer("/entry/conversationId")
            .or_else(|| val.pointer("/conversationId"))
            .and_then(Value::as_str)
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
        else {
            return;
        };
        let gen = val
            .pointer("/entry/generation")
            .or_else(|| val.pointer("/generation"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let pool = pool.clone();
        let clock = Arc::clone(&self.clock);
        #[cfg(feature = "sim")]
        let sim_hooks = self.sim_hooks.clone();
        self.spawner.spawn_box(
            "chat.post_commit.membership_transition",
            Box::pin(async move {
                let fut = crate::sim_hooks::scope_ds_clock(clock, async move {
                    let host = crate::space_host::SpaceHostRuntime::new(pool, cfg);
                    let _ = crate::space_host::revocation_fanout::revoke_inactive_space_credentials_for_conversation(
                        &host,
                        cid,
                        gen,
                    )
                    .await;
                });
                #[cfg(feature = "sim")]
                {
                    crate::sim_hooks::scope_optional_sim_ds(sim_hooks, fut).await;
                }
                #[cfg(not(feature = "sim"))]
                {
                    fut.await;
                }
            }),
        );
    }

    /// Post-commit S2S `deliverGroupEntry` fan-out to remote member home `mls-ds` nodes (`D1`, `I13`, `I14`).
    pub fn spawn_post_commit_group_entry_fanout(
        &self,
        pool: &DbPool,
        prepared: crate::federation::group_fanout::PreparedGroupEntryFanout,
    ) {
        let pool = pool.clone();
        let resolver = self.resolver.clone();
        let clock = Arc::clone(&self.clock);
        #[cfg(feature = "sim")]
        let sim_hooks = self.sim_hooks.clone();
        self.spawner.spawn_box(
            "chat.post_commit.group_entry_fanout",
            Box::pin(async move {
                let fut = crate::sim_hooks::scope_ds_clock(clock, async move {
                    let _ = prepared.deliver(&pool, resolver.as_deref()).await;
                });
                #[cfg(feature = "sim")]
                {
                    crate::sim_hooks::scope_optional_sim_ds(sim_hooks, fut).await;
                }
                #[cfg(not(feature = "sim"))]
                {
                    fut.await;
                }
            }),
        );
    }

    /// Post-commit push wakes for this DS's own recipient devices (`D2`, `I12`).
    pub fn spawn_post_commit_local_push(
        &self,
        pool: &DbPool,
        prepared: crate::push_gateway::client::PreparedLocalWake,
    ) {
        let Some(client) = self.push_gateway_client.clone() else {
            return;
        };
        let pool = pool.clone();
        let clock = Arc::clone(&self.clock);
        #[cfg(feature = "sim")]
        let sim_hooks = self.sim_hooks.clone();
        self.spawner.spawn_box(
            "chat.post_commit.local_push",
            Box::pin(async move {
                let fut = crate::sim_hooks::scope_ds_clock(clock, async move {
                    let _ = prepared.dispatch(&pool, &client).await;
                });
                #[cfg(feature = "sim")]
                {
                    crate::sim_hooks::scope_optional_sim_ds(sim_hooks, fut).await;
                }
                #[cfg(not(feature = "sim"))]
                {
                    fut.await;
                }
            }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_subscription_endpoint, ChatRuntime};
    use crate::realtime::{SseState, StreamEvent};
    use serde_json::json;
    use std::sync::Arc;

    #[cfg(feature = "sim")]
    #[test]
    fn sim_request_receipt_authority_is_node_local_and_requires_validation() {
        use p256::pkcs8::{EncodePrivateKey, LineEnding};
        let receipt = p256::ecdsa::SigningKey::from_bytes((&[0x31; 32]).into()).unwrap();
        let service = p256::ecdsa::SigningKey::from_bytes((&[0x32; 32]).into()).unwrap();
        let authority = "did:web:ds-b.catbird.blue";
        let public = receipt.verifying_key().to_encoded_point(true);
        let key_id = crate::chat_protocol::direct_request_transcript::direct_request_receipt_key_id_for_authority(
            authority, public.as_bytes(),
        ).unwrap();
        let mut multikey = vec![0x80, 0x24];
        multikey.extend_from_slice(public.as_bytes());
        let document = json!({
            "id": authority,
            "verificationMethod": [{
                "id": key_id,
                "controller": authority,
                "type": "Multikey",
                "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, multikey),
            }],
        });
        let runtime = ChatRuntime::from_env(Arc::new(SseState::new(8))).unwrap();
        runtime
            .requests_ready
            .store(true, std::sync::atomic::Ordering::Release);
        let runtime = runtime
            .with_request_receipt_keys(
                receipt.to_pkcs8_pem(LineEnding::LF).unwrap().as_str(),
                service.to_pkcs8_pem(LineEnding::LF).unwrap().as_str(),
                &document.to_string(),
            )
            .unwrap();
        assert_eq!(
            runtime
                .request_receipt_signer
                .as_ref()
                .unwrap()
                .authority_did(),
            authority
        );
        assert!(runtime.request_receipt_signer().is_none());
    }

    #[tokio::test]
    async fn sse_typing_fanout_is_filtered_by_conversation() {
        let runtime = ChatRuntime::from_env(Arc::new(SseState::new(8))).unwrap();
        let mut first = runtime.subscribe_typing("convo-a").await;
        let mut other = runtime.subscribe_typing("convo-b").await;
        runtime
            .publish_typing(json!({
                "$type": "blue.catbird.chat.defs#typingEvent",
                "conversationId": "convo-a",
                "actorDid": "did:plc:actor",
                "actorDeviceId": "device-a",
                "isTyping": true,
                "expiresAt": "2026-08-16T12:00:08.000Z",
                "typingId": "typing-a"
            }))
            .await;
        assert!(
            matches!(first.recv().await.unwrap(), StreamEvent::CleanTypingEvent {
                ref conversation_id,
                ref actor_did,
                ref actor_device_id,
                ref expires_at,
                is_typing: true,
                ref typing_id,
            } if conversation_id == "convo-a"
                && actor_did.to_string() == "did:plc:actor"
                && actor_device_id == "device-a"
                && expires_at.to_string() == "2026-08-16T12:00:08.000Z"
                && typing_id == "typing-a")
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), other.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn protocol_fence_validation_fails_closed_without_a_cursor_sealer() {
        let mut runtime = ChatRuntime::from_env(Arc::new(SseState::new(8))).unwrap();
        // Sibling suites configure a process-wide sealer through the env.
        runtime.cursor_sealer = None;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://invalid/clean_chat")
            .unwrap();

        let error = runtime.validate_protocol_fence(&pool).await.unwrap_err();
        assert!(error.contains("without a cursor sealer"), "{error}");
    }

    #[test]
    fn subscription_endpoint_requires_the_canonical_secure_xrpc_uri() {
        let endpoint = "wss://chat.example.test/xrpc/blue.catbird.chat.subscribeEvents";
        assert_eq!(parse_subscription_endpoint(endpoint).unwrap(), endpoint);
    }

    #[test]
    fn subscription_endpoint_rejects_noncanonical_or_unsafe_variants() {
        for endpoint in [
            "https://chat.example.test/xrpc/blue.catbird.chat.subscribeEvents",
            "ws://chat.example.test/xrpc/blue.catbird.chat.subscribeEvents",
            "wss://user:password@chat.example.test/xrpc/blue.catbird.chat.subscribeEvents",
            "wss://chat.example.test/xrpc/blue.catbird.chat.subscribeEvents?cursor=1",
            "wss://chat.example.test/xrpc/blue.catbird.chat.subscribeEvents#fragment",
            "wss://chat.example.test/xrpc/blue.catbird.chat.getSubscriptionTicket",
            "wss://chat.example.test/xrpc/blue.catbird.chat.subscribeEvents/",
        ] {
            assert!(
                parse_subscription_endpoint(endpoint).is_err(),
                "endpoint should be rejected: {endpoint}"
            );
        }
    }
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

fn build_cursor_sealer_from_env() -> Result<Option<CursorSealer>, String> {
    let key_id = match std::env::var("CHAT_CURSOR_KEY_ID") {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let secret = require_var("CHAT_CURSOR_SEALING_SECRET")?;
    let key_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key_id.trim())
        .map_err(|_| "CHAT_CURSOR_KEY_ID is not canonical base64url".to_owned())?;
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(secret.trim())
        .map_err(|_| "CHAT_CURSOR_SEALING_SECRET is not canonical base64url".to_owned())?;
    let key_id: [u8; 32] = key_id
        .try_into()
        .map_err(|_| "CHAT_CURSOR_KEY_ID must decode to 32 bytes".to_owned())?;
    let secret: [u8; 32] = secret
        .try_into()
        .map_err(|_| "CHAT_CURSOR_SEALING_SECRET must decode to 32 bytes".to_owned())?;
    CursorSealer::new(key_id, Zeroizing::new(secret))
        .map(Some)
        .map_err(|_| "CHAT_CURSOR_SEALING_SECRET cannot be all zero".to_owned())
}

fn parse_subscription_endpoint_from_env() -> Result<Option<String>, String> {
    let Ok(raw) = std::env::var("CHAT_SUBSCRIPTION_ENDPOINT") else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    parse_subscription_endpoint(&raw).map(Some)
}

/// Parse the one canonical endpoint used by clean-chat subscription clients.
///
/// This deliberately accepts only the exact XRPC `wss` URI shape. In
/// particular, credentials and URI decorations cannot smuggle a different
/// authority or route into startup configuration.
fn parse_subscription_endpoint(raw: &str) -> Result<String, String> {
    let url =
        Url::parse(raw).map_err(|_| "CHAT_SUBSCRIPTION_ENDPOINT is not a valid URI".to_owned())?;
    if url.scheme() != "wss"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/xrpc/blue.catbird.chat.subscribeEvents"
        || url.as_str() != raw
    {
        return Err(
            "CHAT_SUBSCRIPTION_ENDPOINT must be the exact canonical wss URI \
             wss://<host>/xrpc/blue.catbird.chat.subscribeEvents without credentials, \
             query, or fragment"
                .to_owned(),
        );
    }
    Ok(raw.to_owned())
}

fn require_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} must be configured"))
}
