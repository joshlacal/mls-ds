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
use crate::db::DbPool;
use crate::realtime::{SseState, StreamEvent};

/// Shared, immutable clean-chat runtime, stored in `AppState` and extracted by
/// every chat handler as `State<Arc<ChatRuntime>>`.
pub struct ChatRuntime {
    cutover_enabled: bool,
    relationship_authority: Arc<ProductionRelationshipAuthority>,
    sse_state: Arc<SseState>,
    cursor_sealer: Option<CursorSealer>,
    subscription_endpoint: Option<String>,
    resolver: Option<Arc<crate::federation::DsResolver>>,
    commit_submitter: Option<Arc<crate::federation::commit_submitter::RemoteCommitSubmitter>>,
}

impl fmt::Debug for ChatRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChatRuntime")
            .field("cutover_enabled", &self.cutover_enabled)
            .field("relationship_authority", &"fixed-production-authority")
            .field("sse_state", &"conversation-filtered")
            .field("cursor_sealer_configured", &self.cursor_sealer.is_some())
            .field(
                "subscription_endpoint_configured",
                &self.subscription_endpoint.is_some(),
            )
            .field("resolver_configured", &self.resolver.is_some())
            .field(
                "commit_submitter_configured",
                &self.commit_submitter.is_some(),
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
        Ok(Self {
            cutover_enabled,
            relationship_authority,
            sse_state,
            cursor_sealer,
            subscription_endpoint,
            resolver: None,
            commit_submitter: None,
        })
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

    pub fn resolver(&self) -> Option<&Arc<crate::federation::DsResolver>> {
        self.resolver.as_ref()
    }

    pub fn from_env_with_federation(
        sse_state: Arc<SseState>,
        resolver: Arc<crate::federation::DsResolver>,
        commit_submitter: Option<Arc<crate::federation::commit_submitter::RemoteCommitSubmitter>>,
    ) -> Result<Self, String> {
        let mut runtime = Self::from_env_with_resolver(sse_state, resolver)?;
        runtime.commit_submitter = commit_submitter;
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

        let protocol = sqlx::query_as::<_, (uuid::Uuid, String)>(
            "SELECT p.protocol_instance_id, p.cursor_key_id \
             FROM chat.protocol_instances AS p \
             WHERE p.singleton = TRUE",
        )
        .fetch_optional(pool)
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
        .fetch_one(pool)
        .await
        .map_err(|error| format!("failed to load clean-chat event-retention fence: {error}"))?;
        if !retention_exists {
            return Err(format!(
                "clean-chat event-retention row is missing for protocol instance {}",
                protocol.0
            ));
        }
        Ok(())
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
}

#[cfg(test)]
mod tests {
    use super::{parse_subscription_endpoint, ChatRuntime};
    use crate::realtime::{SseState, StreamEvent};
    use serde_json::json;
    use std::sync::Arc;

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
        let runtime = ChatRuntime::from_env(Arc::new(SseState::new(8))).unwrap();
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
