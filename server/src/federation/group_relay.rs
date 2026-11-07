//! `D1` Cross-Server Group Mutation Relay & Group Entry Fan-Out (`relayGroupMutation` / `deliverGroupEntry`).
//!
//! Ensures every client communicates strictly with its own home `mls-ds`:
//! - When a group member homed on `home_b` sends a group `sendMessage` (or transition), `home_b`
//!   relays the signed mutation over S2S (`blue.catbird.mlsDS.relayGroupMutation`) to the group's
//!   authoritative sequencing `mls-ds`.
//! - The sequencing `mls-ds` verifies the device's Ed25519 signature, sequences the entry at the
//!   authoritative `seq`, signs an `I13` ES256 `sequencerReceipt` when configured, and fans out
//!   `blue.catbird.mlsDS.deliverGroupEntry` to each remote member's home `mls-ds`.
//! - Each remote home `mls-ds` stores the replicated entry in `chat.direct_request_transport_entries`
//!   and wakes only its own local devices (`D2`).

use std::{collections::BTreeMap, future::Future, sync::Arc, time::Duration};

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::SecondsFormat;
#[cfg(any(test, feature = "test-support"))]
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use uuid::Uuid;

use super::receipt::I13ReceiptSigner;
use crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority;
use crate::{
    push_gateway::client::{PushGatewayClient, PushWakeDispatch, PushWakeKind},
    storage::DbPool,
    SINGLE_MLS_ARTIFACT_BODY_LIMIT_BYTES,
};

#[path = "group_membership.rs"]
mod membership;
pub(crate) use membership::{
    active_device_key, stage_remote_group_participants, stage_verified_remote_device,
    try_relay_group_state, try_relay_home_group_operation, try_relay_index_only_welcome,
    try_relay_labyrinth_directory, try_relay_labyrinth_member_devices,
};

#[path = "remote_group_index.rs"]
mod remote_group_index;
pub(crate) use remote_group_index::{
    append_relayed_inventory_items, forget_pending_welcomes, RemoteInventory,
};

#[path = "entry_ack_relay.rs"]
mod entry_ack_relay;
pub(crate) use entry_ack_relay::{
    account_deletion_relay::enqueue_account_deletion_relays, enqueue_entry_ack_relay,
    transport_control_entry::enqueue_transport_control_entry,
};
// The expiry sweep is also compiled into integration-test crates.
pub use entry_ack_relay::{
    enqueue_entries_pruned_notices, transport_control_entry::C33PeerHomes, SignedRelayError,
};

#[cfg(any(test, feature = "test-support"))]
type HmacSha256 = Hmac<Sha256>;

#[cfg(any(test, feature = "test-support"))]
const S2S_CALLER_DID_HEADER: &str = "x-catbird-s2s-caller-did";
#[cfg(any(test, feature = "test-support"))]
const S2S_TARGET_DID_HEADER: &str = "x-catbird-s2s-target-did";
#[cfg(any(test, feature = "test-support"))]
const S2S_MAC_HEADER: &str = "x-catbird-s2s-mac";

/// Relay fan-out and push wakes are awaited inline within the request's clock scope.
#[derive(Clone)]
pub struct GroupRelayState {
    pool: DbPool,
    self_did: String,
    #[cfg(any(test, feature = "test-support"))]
    s2s_shared_secret: Option<Arc<Vec<u8>>>,
    i13_receipt_signer: Option<Arc<I13ReceiptSigner>>,
    push_gateway_client: Option<Arc<PushGatewayClient>>,
    clock: Arc<dyn crate::sim_hooks::DsClock>,
    relationship_authority: Option<Arc<ProductionRelationshipAuthority>>,
    #[cfg(feature = "sim")]
    sim_hooks: Option<Arc<crate::sim_hooks::SimDsHooks>>,
}

impl GroupRelayState {
    pub fn new(
        pool: DbPool,
        self_did: String,
        i13_receipt_signer: Option<Arc<I13ReceiptSigner>>,
        push_gateway_client: Option<Arc<PushGatewayClient>>,
    ) -> Self {
        #[cfg(any(test, feature = "test-support"))]
        let s2s_shared_secret =
            configured_group_relay_hmac_secret().map(|s| Arc::new(s.into_bytes()));
        Self {
            pool,
            self_did: crate::identity::canonical_did(&self_did).to_string(),
            #[cfg(any(test, feature = "test-support"))]
            s2s_shared_secret,
            i13_receipt_signer,
            push_gateway_client,
            clock: Arc::new(crate::sim_hooks::SystemDsClock),
            relationship_authority: None,
            #[cfg(feature = "sim")]
            sim_hooks: crate::sim_hooks::active_sim_ds(),
        }
    }

    pub fn with_clock(mut self, clock: Arc<dyn crate::sim_hooks::DsClock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn clock(&self) -> &Arc<dyn crate::sim_hooks::DsClock> {
        &self.clock
    }

    /// Admit relayed group operations under `runtime`'s relationship
    /// authority, the one this process's local chat handlers use.
    pub fn with_relationship_authority_of(
        mut self,
        runtime: &crate::handlers::chat::ChatRuntime,
    ) -> Self {
        self.relationship_authority = Some(Arc::clone(runtime.relationship_authority()));
        self
    }

    /// The configured relationship authority; a state built without a chat
    /// runtime admits under the deterministic simulation authority or the
    /// fixed production one.
    fn relationship_authority(&self) -> Result<Arc<ProductionRelationshipAuthority>, String> {
        if let Some(authority) = &self.relationship_authority {
            return Ok(Arc::clone(authority));
        }
        if let Some(simulated) =
            ProductionRelationshipAuthority::for_deterministic_clock(self.clock.as_ref())
        {
            return simulated.map(Arc::new).map_err(|e| format!("{e:?}"));
        }
        crate::chat_protocol::repository::relationship::load_fixed_relationship_authority_startup_guard()
            .map(|guard| Arc::new(ProductionRelationshipAuthority::from_startup_guard(guard)))
            .map_err(|e| format!("{e:?}"))
    }

    #[cfg(feature = "sim")]
    pub fn with_sim_hooks(mut self, hooks: Arc<crate::sim_hooks::SimDsHooks>) -> Self {
        self.self_did = crate::identity::canonical_did(&hooks.service_did).to_string();
        #[cfg(any(test, feature = "test-support"))]
        {
            self.s2s_shared_secret = hooks
                .group_relay_hmac_secret
                .as_ref()
                .filter(|secret| !secret.is_empty())
                .map(|secret| Arc::new(secret.as_bytes().to_vec()));
        }
        self.sim_hooks = Some(hooks);
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(
        pool: DbPool,
        self_did: String,
        s2s_secret: &[u8],
        i13_receipt_signer: Option<Arc<I13ReceiptSigner>>,
    ) -> Self {
        Self::for_test_with_push(pool, self_did, s2s_secret, i13_receipt_signer, None)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test_with_push(
        pool: DbPool,
        self_did: String,
        s2s_secret: &[u8],
        i13_receipt_signer: Option<Arc<I13ReceiptSigner>>,
        push_gateway_client: Option<Arc<PushGatewayClient>>,
    ) -> Self {
        Self {
            pool,
            self_did: crate::identity::canonical_did(&self_did).to_string(),
            s2s_shared_secret: Some(Arc::new(s2s_secret.to_vec())),
            i13_receipt_signer,
            push_gateway_client,
            clock: Arc::new(crate::sim_hooks::SystemDsClock),
            relationship_authority: None,
            #[cfg(feature = "sim")]
            sim_hooks: crate::sim_hooks::active_sim_ds(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayGroupMutationRequest {
    pub conversation_id: Uuid,
    pub endpoint: String,
    pub actor_did: String,
    pub actor_device_id: Uuid,
    pub signed_request: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayGroupMutationOutput {
    pub entry: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinates: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcomes: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverGroupEntryRequest {
    pub conversation_id: Uuid,
    pub generation: i64,
    pub space_uri: String,
    pub recipient_dids: Vec<String>,
    pub recipient_devices: Vec<(String, Uuid)>,
    pub entry: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_authority: Option<super::receipt::TerminalCloseAuthority>,
}

#[derive(Clone, Copy)]
struct ClockScoped<H>(H);

impl<H, T> axum::handler::Handler<T, GroupRelayState> for ClockScoped<H>
where
    H: axum::handler::Handler<T, GroupRelayState>,
    T: 'static,
{
    type Future = std::pin::Pin<Box<dyn Future<Output = Response> + Send>>;

    fn call(self, req: axum::extract::Request, state: GroupRelayState) -> Self::Future {
        let clock = Arc::clone(state.clock());
        #[cfg(feature = "sim")]
        let sim_hooks = state.sim_hooks.clone();
        let inner = self.0.call(req, state);
        #[cfg(feature = "sim")]
        let inner = crate::sim_hooks::scope_optional_sim_ds(sim_hooks, inner);
        Box::pin(async move {
            let deterministic = clock.is_deterministic();
            let scoped = crate::sim_hooks::scope_ds_clock(clock, inner);
            if deterministic {
                crate::sim_hooks::drive_sim_io(scoped).await
            } else {
                scoped.await
            }
        })
    }
}

pub fn group_relay_router(state: GroupRelayState) -> Router {
    Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.relayGroupMutation",
            post(ClockScoped(handle_relay_group_mutation))
                .layer(DefaultBodyLimit::max(SINGLE_MLS_ARTIFACT_BODY_LIMIT_BYTES)),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.deliverGroupEntry",
            post(ClockScoped(handle_deliver_group_entry))
                .layer(DefaultBodyLimit::max(SINGLE_MLS_ARTIFACT_BODY_LIMIT_BYTES)),
        )
        .merge(membership::routes())
        .merge(entry_ack_relay::routes())
        .with_state(state)
}

/// Optional simulation-only HMAC configuration. Production builds never read
/// or accept a shared group-relay secret.
pub fn configured_group_relay_hmac_secret() -> Option<String> {
    #[cfg(any(test, feature = "test-support"))]
    {
        #[cfg(feature = "sim")]
        if let Some(hooks) = crate::sim_hooks::active_sim_ds() {
            return hooks
                .group_relay_hmac_secret
                .clone()
                .filter(|secret| !secret.is_empty());
        }
        return std::env::var("FEDERATION_GROUP_RELAY_HMAC_SECRET")
            .ok()
            .filter(|secret| !secret.is_empty());
    }
    #[cfg(not(any(test, feature = "test-support")))]
    None
}

#[cfg(any(test, feature = "test-support"))]
fn compute_s2s_mac(
    secret: &[u8],
    caller_did: &str,
    target_did: &str,
    lxm: &str,
    body: &[u8],
) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(b"CATBIRD-S2S-GROUP-RELAY\0");
    mac.update(caller_did.as_bytes());
    mac.update(&[0]);
    mac.update(target_did.as_bytes());
    mac.update(&[0]);
    mac.update(lxm.as_bytes());
    mac.update(&[0]);
    mac.update(body);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

#[derive(Deserialize)]
struct ExactS2sScope<'a> {
    aud: &'a str,
    lxm: Option<&'a str>,
}

/// Reject every token not scoped to this exact DS and method before replay
/// admission. Signature and issuer-key verification still happen in
/// `verify_mls_service_principal` below.
fn require_exact_s2s_scope(
    headers: &HeaderMap,
    target_did: &str,
    lxm: &str,
) -> Result<(), crate::auth::AuthError> {
    use crate::auth::AuthError;

    let authorization = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthError::MissingAuthHeader)?;
    let token = authorization
        .strip_prefix("Bearer ")
        .ok_or(AuthError::InvalidAuthFormat)?;
    let mut segments = token.split('.');
    let (Some(header), Some(payload), Some(signature)) =
        (segments.next(), segments.next(), segments.next())
    else {
        return Err(AuthError::InvalidToken("malformed service JWT".into()));
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() || segments.next().is_some()
    {
        return Err(AuthError::InvalidToken("malformed service JWT".into()));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| AuthError::InvalidToken("malformed service JWT payload".into()))?;
    let claims: ExactS2sScope<'_> = serde_json::from_slice(&payload)
        .map_err(|_| AuthError::InvalidToken("malformed service JWT claims".into()))?;
    if claims.aud != target_did {
        return Err(AuthError::InvalidToken(
            "service JWT audience does not exactly match this DS".into(),
        ));
    }
    match claims.lxm {
        Some(method) if method == lxm => Ok(()),
        Some(_) => Err(AuthError::LxmMismatch),
        None => Err(AuthError::MissingLxm),
    }
}

async fn verify_s2s_caller(
    state: &GroupRelayState,
    headers: &HeaderMap,
    lxm: &str,
    body: &[u8],
) -> Result<String, Response> {
    super::peer_policy::ensure_federation_open().map_err(IntoResponse::into_response)?;
    #[cfg(not(any(test, feature = "test-support")))]
    let _ = body;
    #[cfg(any(test, feature = "test-support"))]
    if let Some(ref secret) = state.s2s_shared_secret {
        let caller = headers
            .get(S2S_CALLER_DID_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .unwrap_or_default();
        let target = headers
            .get(S2S_TARGET_DID_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .unwrap_or_default();
        let mac_hdr = headers
            .get(S2S_MAC_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .unwrap_or_default();
        if !caller.is_empty() && !mac_hdr.is_empty() {
            if crate::identity::canonical_did(target) != state.self_did {
                return Err(s2s_err(
                    StatusCode::UNAUTHORIZED,
                    "NotAuthorized",
                    "target DID mismatch",
                ));
            }
            let expected = compute_s2s_mac(secret, caller, &state.self_did, lxm, body);
            if mac_hdr == expected {
                return authorize_s2s_peer(state, caller).await;
            }
            return Err(s2s_err(
                StatusCode::UNAUTHORIZED,
                "NotAuthorized",
                "invalid S2S MAC",
            ));
        }
    }

    require_exact_s2s_scope(headers, &state.self_did, lxm).map_err(s2s_auth_failure)?;
    let principal = crate::auth::verify_mls_service_principal(headers, &state.pool, lxm)
        .await
        .map_err(s2s_auth_failure)?;
    authorize_s2s_peer(state, principal.did()).await
}

/// A caller's token checked against the issuer's DID document and this DS's
/// replay store. The store failing (`AuthError::Internal`) is this DS's own
/// failure (500); a document or rate limit that could not answer now
/// (`AuthError::is_retryable`) decided nothing (503). Either keeps the
/// caller's ordered delivery queued, where a 4xx ends it.
fn s2s_auth_failure(error: crate::auth::AuthError) -> Response {
    match error {
        crate::auth::AuthError::Internal(message) => s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            message,
        ),
        error if error.is_retryable() => s2s_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            error.to_string(),
        ),
        error => s2s_err(StatusCode::UNAUTHORIZED, "NotAuthorized", error.to_string()),
    }
}

/// This DS's peer-policy store failing decided nothing (500); a policy that
/// refuses the authenticated caller is `403 NotAuthorized`.
async fn authorize_s2s_peer(state: &GroupRelayState, caller: &str) -> Result<String, Response> {
    let caller = crate::identity::canonical_did(caller).to_string();
    super::peer_policy::enforce_inbound_peer_policy(&state.pool, &caller)
        .await
        .map_err(|error| match error {
            super::errors::FederationError::Database(_) => s2s_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                error.to_string(),
            ),
            error => s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", error.to_string()),
        })?;
    Ok(caller)
}

fn s2s_err(status: StatusCode, code: &str, msg: impl Into<String>) -> Response {
    (
        status,
        Json(json!({
            "error": code,
            "message": msg.into(),
        })),
    )
        .into_response()
}

/// A key, home or device lookup that could not answer now
/// (`FederationError::is_retryable`) decided nothing: `503` keeps the caller's
/// ordered delivery queued, where a 4xx ends it. Anything else is a refusal.
fn lookup_failure(error: super::errors::FederationError) -> Response {
    if error.is_retryable() {
        s2s_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            error.to_string(),
        )
    } else {
        s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", error.to_string())
    }
}

/// A relayed add's new member could not be routed or staged. This store
/// failing, or a closed gate, member home or resolver that could not answer
/// now (`FederationError::is_retryable`), decided nothing: the caller's home
/// answers its client retryably. Every other refusal stays `NotAuthorized`.
fn added_member_failure(error: &super::errors::FederationError, message: String) -> Response {
    match error {
        super::errors::FederationError::Database(_) => s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            message,
        ),
        error if error.is_retryable() => s2s_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "RelationshipPolicyUnavailable",
            message,
        ),
        _ => s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", message),
    }
}

/// Why a relayed group operation was not completed by its sequencer.
#[derive(Debug)]
pub enum GroupRelayError {
    /// The sequencer answered with a declared clean-chat protocol error, or
    /// the route to it is permanently refused here (`NotAuthorized`).
    Rejected(crate::chat_protocol::error::ChatProtocolErrorCode),
    /// The gate, the sequencer or its route could not answer now.
    Unavailable(String),
    /// This DS's own store or configuration failed.
    Internal(String),
}

impl GroupRelayError {
    /// Classify a non-success sequencer answer: a 5xx or 429 decided nothing;
    /// any other 4xx, or a refused redirect, is definitive.
    fn from_response(status: u16, body: &[u8]) -> Self {
        if status >= 500 || status == 429 {
            return Self::Unavailable(format!("HTTP {status}: {}", String::from_utf8_lossy(body)));
        }
        Self::Rejected(
            remote_protocol_code(body)
                .filter(|_| (400..500).contains(&status))
                .unwrap_or(crate::chat_protocol::error::ChatProtocolErrorCode::InvalidRequest),
        )
    }

    /// A failure on this side of the relay. `Database` is matched before
    /// `is_retryable`, which also holds for it; any other failure of this DS
    /// (`status_code` 5xx: configuration, signer) is internal; a permanently
    /// unroutable sequencer is refused like any unroutable participant.
    pub(crate) fn from_local(error: super::errors::FederationError) -> Self {
        match error {
            super::errors::FederationError::Database(error) => Self::Internal(error.to_string()),
            error if error.is_retryable() => Self::Unavailable(error.to_string()),
            error if error.status_code().is_server_error() => Self::Internal(error.to_string()),
            _ => Self::Rejected(crate::chat_protocol::error::ChatProtocolErrorCode::NotAuthorized),
        }
    }

    /// A rejection keeps the sequencer's code; unavailability maps to the
    /// endpoint's declared retryable code; this DS failing is storage.
    pub(crate) fn into_failure(
        self,
        endpoint: crate::chat_protocol::error::ChatEndpoint,
    ) -> crate::handlers::chat::ChatFailure {
        use crate::handlers::chat::ChatFailure;
        match self {
            Self::Rejected(code) => ChatFailure::protocol(endpoint, code),
            Self::Unavailable(_) => ChatFailure::unavailable(endpoint),
            Self::Internal(_) => ChatFailure::storage(endpoint),
        }
    }
}

/// The protocol error name carried by a peer's JSON error body.
fn remote_protocol_code(body: &[u8]) -> Option<crate::chat_protocol::error::ChatProtocolErrorCode> {
    serde_json::from_slice::<Value>(body)
        .ok()?
        .get("error")?
        .as_str()?
        .parse()
        .ok()
}

/// Outbound S2S client helper: relay a group mutation from the member's home `mls-ds` to `sequencer_ds`.
pub async fn relay_group_mutation_to_sequencer(
    sequencer_endpoint: &str,
    caller_home_did: &str,
    sequencer_did: &str,
    s2s_secret: &[u8],
    request: &RelayGroupMutationRequest,
) -> Result<RelayGroupMutationOutput, GroupRelayError> {
    let internal = |error: String| GroupRelayError::Internal(error);
    let unavailable = |error: String| GroupRelayError::Unavailable(error);
    let body_bytes = serde_json::to_vec(request).map_err(|e| internal(e.to_string()))?;
    let caller_norm = crate::identity::canonical_did(caller_home_did);
    let target_norm = crate::identity::canonical_did(sequencer_did);
    let url = format!(
        "{}/xrpc/blue.catbird.mlsDS.relayGroupMutation",
        sequencer_endpoint.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| internal(e.to_string()))?;
    let mut req = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json");
    req = attach_group_s2s_auth(
        req,
        caller_norm,
        target_norm,
        "blue.catbird.mlsDS.relayGroupMutation",
        s2s_secret,
        &body_bytes,
    )
    .map_err(GroupRelayError::from_local)?;
    let resp = crate::sim_hooks::send_reqwest(req.body(body_bytes))
        .await
        .map_err(|e| unavailable(format!("relayGroupMutation POST failed: {e}")))?;
    let status = resp.status();
    let resp_bytes = resp.bytes().await.map_err(|e| unavailable(e.to_string()))?;
    if !status.is_success() {
        return Err(GroupRelayError::from_response(status.as_u16(), &resp_bytes));
    }
    serde_json::from_slice(&resp_bytes).map_err(|e| unavailable(e.to_string()))
}

/// Relay a strict-home member's group transition to the group's sequencer.
///
/// Returns `None` unless this DS holds the conversation as a remote group
/// mirror. `mailbox_commit` keeps mirrored CommitTransitions on the
/// `RemoteCommitSubmitter` path. The bytes are the sequencer's
/// `submitTransition` output.
pub(crate) async fn relay_remote_group_submit_transition(
    pool: &DbPool,
    resolver: &super::DsResolver,
    actor_did: &str,
    actor_device_id: Uuid,
    mailbox_commit: bool,
    body: &[u8],
) -> Result<Option<Vec<u8>>, GroupRelayError> {
    let Ok(body_json) = serde_json::from_slice::<Value>(body) else {
        return Ok(None);
    };
    let signed_req = body_json.get("signedRequest").unwrap_or(&body_json);
    let Some(convo_id) = signed_conversation_id(signed_req) else {
        return Ok(None);
    };
    let local_convo: Option<(String, bool, Option<String>)> = sqlx::query_as(
        "SELECT kind, is_remote, sequencer_ds FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(convo_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| GroupRelayError::Internal(e.to_string()))?;
    let seq_ds = match local_convo {
        Some((kind, true, Some(seq_ds))) if kind == "group" => seq_ds,
        _ => return Ok(None),
    };
    // Only the sequencer can sequence a mirror's transition: a closed gate
    // decided nothing, and refuses before the sequencer is resolved.
    super::peer_policy::ensure_federation_open().map_err(GroupRelayError::from_local)?;
    if mailbox_commit {
        return Ok(None);
    }
    let secret = configured_group_relay_hmac_secret();
    if secret.is_none() && super::canonical_relay::configured_s2s_signing_key_pem().is_err() {
        return Ok(None);
    }
    if signed_req.pointer("/body/actorDid").and_then(Value::as_str) != Some(actor_did) {
        return Err(GroupRelayError::Rejected(
            crate::chat_protocol::error::ChatProtocolErrorCode::NotAuthorized,
        ));
    }
    let dest = resolver
        .resolve_ds_destination_uncached(&seq_ds)
        .await
        .map_err(GroupRelayError::from_local)?;
    let secret_bytes = secret.as_deref().map(str::as_bytes).unwrap_or(&[]);
    let out = relay_group_mutation_to_sequencer(
        dest.url.as_str(),
        &crate::identity::service_did(),
        &seq_ds,
        secret_bytes,
        &RelayGroupMutationRequest {
            conversation_id: convo_id,
            endpoint: "blue.catbird.chat.submitTransition".to_string(),
            actor_did: actor_did.to_string(),
            actor_device_id,
            signed_request: signed_req.clone(),
        },
    )
    .await?;
    let output = json!({
        "coordinates": out.coordinates.unwrap_or_else(|| signed_req["body"]["next"].clone()),
        "entry": out.entry,
        "welcomes": out.welcomes.unwrap_or_else(|| json!([])),
    });
    serde_json::to_vec(&output)
        .map(Some)
        .map_err(|e| GroupRelayError::Internal(e.to_string()))
}

/// The conversation a signed transition targets, from its canonical body.
fn signed_conversation_id(signed_req: &Value) -> Option<Uuid> {
    let uuid_bytes = |encoded: &str| {
        STANDARD
            .decode(encoded)
            .ok()
            .and_then(|bytes| <[u8; 16]>::try_from(bytes.as_slice()).ok())
            .map(Uuid::from_bytes)
    };
    let parse = |value: &Value| match value.as_str() {
        Some(text) => Uuid::parse_str(text).ok().or_else(|| uuid_bytes(text)),
        None => value
            .pointer("/$bytes")
            .and_then(Value::as_str)
            .and_then(uuid_bytes),
    };
    signed_req
        .pointer("/body/prior/conversationId")
        .and_then(parse)
        .or_else(|| signed_req.pointer("/body/conversationId").and_then(parse))
        .or_else(|| {
            signed_req
                .pointer("/body/aad/conversationId")
                .and_then(parse)
        })
}

/// Outbound S2S client helper: fan out a sequenced group entry from the
/// sequencing `mls-ds` to a remote home `mls-ds`. A closed gate
/// (`FederationDisabled`) or a send that did not complete (`RequestFailed`) is
/// retryable; a non-2xx answer keeps its status and its declared `error` and
/// `reasonCode` identifiers (`RemoteError`); this DS failing to build the
/// request is `InvalidResponse`.
pub async fn deliver_group_entry_to_remote_home(
    remote_home_endpoint: &str,
    sequencer_did: &str,
    remote_home_did: &str,
    s2s_secret: &[u8],
    request: &DeliverGroupEntryRequest,
) -> Result<(), super::outbound::OutboundError> {
    use super::outbound::OutboundError;
    const METHOD: &str = "blue.catbird.mlsDS.deliverGroupEntry";
    let local = |reason: String| OutboundError::InvalidResponse { reason };
    let body_bytes = serde_json::to_vec(request).map_err(|e| local(e.to_string()))?;
    let caller_norm = crate::identity::canonical_did(sequencer_did);
    let target_norm = crate::identity::canonical_did(remote_home_did);
    let url = format!(
        "{}/xrpc/{METHOD}",
        remote_home_endpoint.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| local(e.to_string()))?;
    let mut req = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json");
    req = attach_group_s2s_auth(
        req,
        caller_norm,
        target_norm,
        METHOD,
        s2s_secret,
        &body_bytes,
    )
    .map_err(|error| match error {
        super::errors::FederationError::FederationDisabled { reason } => {
            OutboundError::FederationDisabled { reason }
        }
        error => local(error.to_string()),
    })?;
    let resp = crate::sim_hooks::send_reqwest(req.body(body_bytes))
        .await
        .map_err(|reason| OutboundError::RequestFailed {
            endpoint: url.clone(),
            reason,
        })?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let body = resp.text().await.unwrap_or_default();
    let parsed = serde_json::from_str::<Value>(&body).ok();
    let identifier = |field: &str, underscore: bool| -> Option<String> {
        let value = parsed.as_ref()?.get(field)?.as_str()?;
        ((1..=64).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || (underscore && byte == b'_')))
        .then(|| value.to_owned())
    };
    Err(OutboundError::RemoteError {
        status: status.as_u16(),
        error_name: identifier("error", false),
        reason_code: identifier("reasonCode", true),
        body,
        endpoint: url,
        method: METHOD.to_owned(),
    })
}

fn attach_group_s2s_auth(
    request: reqwest::RequestBuilder,
    caller_did: &str,
    target_did: &str,
    method: &str,
    s2s_secret: &[u8],
    body_bytes: &[u8],
) -> Result<reqwest::RequestBuilder, super::errors::FederationError> {
    // Every inline group S2S send (relayGroupMutation, deliverGroupEntry) is
    // built here; a closed federation gate stops it before the network.
    super::peer_policy::ensure_federation_open()?;
    #[cfg(any(test, feature = "test-support"))]
    if !s2s_secret.is_empty() {
        let mac = compute_s2s_mac(s2s_secret, caller_did, target_did, method, body_bytes);
        return Ok(request
            .header(S2S_CALLER_DID_HEADER, caller_did)
            .header(S2S_TARGET_DID_HEADER, target_did)
            .header(S2S_MAC_HEADER, mac));
    }
    #[cfg(not(any(test, feature = "test-support")))]
    let _ = (s2s_secret, body_bytes);
    let signing_key_pem = super::canonical_relay::configured_s2s_signing_key_pem()?;
    let client = super::service_auth::ServiceAuthClient::from_es256_pem(
        caller_did.to_string(),
        signing_key_pem.as_bytes(),
        Some("#atproto".to_string()),
    )?;
    let token = client.mint_token(target_did, method)?;
    Ok(request.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}")))
}

async fn handle_relay_group_mutation(
    State(state): State<GroupRelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller_ds = match verify_s2s_caller(
        &state,
        &headers,
        "blue.catbird.mlsDS.relayGroupMutation",
        &body,
    )
    .await
    {
        Ok(d) => d,
        Err(resp) => return resp,
    };

    let req: RelayGroupMutationRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };

    if matches!(
        req.endpoint.as_str(),
        "blue.catbird.chat.acceptConversation"
            | "blue.catbird.chat.acknowledgeWelcome"
            | "blue.catbird.chat.rejectWelcome"
    ) {
        return membership::relay_membership(&state, &caller_ds, &req).await;
    }
    let res = match req.endpoint.as_str() {
        "blue.catbird.chat.sendMessage" => {
            sequence_relayed_group_application_send(&state, &caller_ds, &req).await
        }
        "blue.catbird.chat.submitTransition" => {
            sequence_relayed_group_submit_transition(&state, &caller_ds, &req).await
        }
        _ => Err(s2s_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            format!("unsupported relayed group endpoint: {}", req.endpoint),
        )),
    };
    match res {
        Ok(out) => (StatusCode::OK, Json(out)).into_response(),
        Err(resp) => resp,
    }
}

async fn sequence_relayed_group_submit_transition(
    state: &GroupRelayState,
    caller_ds: &str,
    req: &RelayGroupMutationRequest,
) -> Result<RelayGroupMutationOutput, Response> {
    let body_actor = req
        .signed_request
        .pointer("/body/actorDid")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let body_device = req
        .signed_request
        .pointer("/body/actorDeviceId")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok());
    if body_actor != req.actor_did || body_device != Some(req.actor_device_id) {
        return Err(s2s_err(
            StatusCode::UNAUTHORIZED,
            "NotAuthorized",
            "actor identity mismatch",
        ));
    }
    let signed_bytes = serde_json::to_vec(&req.signed_request)
        .map_err(|e| s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()))?;
    let canonical = crate::chat_protocol::transcript::decode_canonical_signed_mutation(
        &signed_bytes,
    )
    .map_err(|e| {
        s2s_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            format!("invalid signedRequest: {e}"),
        )
    })?;
    let add_principals = canonical.policy_addition_dids().unwrap_or_default();
    let routing_intent = if !add_principals.is_empty() {
        let http = super::resolver::build_resolver_http_client();
        let resolver = super::resolver::DsResolver::new(
            state.pool.clone(),
            http,
            state.self_did.clone(),
            crate::identity::self_endpoint(),
            None,
            300,
        );
        let routes =
            crate::chat_protocol::federation_routing::resolve_participant_routing_authoritative(
                &state.pool,
                Some(&resolver),
                &add_principals,
            )
            .await
            .map_err(|e| {
                use crate::chat_protocol::federation_routing::FederationRoutingError;
                let message = format!("participant routing failed: {e}");
                match &e {
                    FederationRoutingError::ResolutionFailed { source, .. }
                    | FederationRoutingError::UntrustedPeer { source, .. } => {
                        added_member_failure(source, message)
                    }
                    FederationRoutingError::DriftDetected { .. } => {
                        s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", message)
                    }
                }
            })?;
        stage_remote_group_participants(&state.pool, &routes)
            .await
            .map_err(|e| added_member_failure(&e, e.to_string()))?;
        Some(crate::chat_protocol::federation_routing::ParticipantRoutingIntent::new(routes))
    } else {
        None
    };
    let relationship_authority = state.relationship_authority().map_err(|e| {
        s2s_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "RelationshipPolicyUnavailable",
            e,
        )
    })?;
    let mut tx = state.pool.begin().await.map_err(|e| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;
    let out_bytes =
        crate::chat_protocol::repository::federation::sequence_relayed_group_transition(
            &mut tx,
            caller_ds,
            req.conversation_id,
            signed_bytes,
            routing_intent,
            relationship_authority.as_ref(),
        )
        .await
        .map_err(|err| match err {
            super::errors::FederationError::CommitConflict { .. }
            | super::errors::FederationError::DeliveryConflict { .. }
            | super::errors::FederationError::SequenceConflict { .. } => {
                s2s_err(StatusCode::CONFLICT, "StaleCoordinates", err.to_string())
            }
            super::errors::FederationError::UnauthorizedParticipantDs { .. }
            | super::errors::FederationError::AuthFailed { .. } => {
                s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", err.to_string())
            }
            super::errors::FederationError::ConversationNotFound { .. } => s2s_err(
                StatusCode::NOT_FOUND,
                "ConversationNotFound",
                err.to_string(),
            ),
            // This store failing decided nothing: a 5xx keeps the caller's
            // answer retryable, where a 4xx would be its client's terminal one.
            super::errors::FederationError::Database(_) => s2s_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                err.to_string(),
            ),
            // The new member's relationship source could not answer now, as
            // this sequencer's own authority being unavailable above.
            super::errors::FederationError::RelationshipPolicyUnavailable { .. } => s2s_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "RelationshipPolicyUnavailable",
                err.to_string(),
            ),
            // A relationship policy refusal, as the local transition answers
            // it: neither an invalid request nor an authentication failure.
            super::errors::FederationError::BlockedRelationship => s2s_err(
                StatusCode::BAD_REQUEST,
                "BlockedRelationship",
                "BlockedRelationship",
            ),
            other => s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", other.to_string()),
        })?;
    let out_val: Value = serde_json::from_slice(&out_bytes).map_err(|e| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;
    let fanout = super::group_fanout::prepare_group_entry_fanout(&mut tx, &out_val)
        .await
        .map_err(|e| s2s_err(StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", e))?;
    let local_wake = match &state.push_gateway_client {
        Some(_) => crate::push_gateway::client::prepare_local_entry_wake(&mut tx, &out_val)
            .await
            .map_err(|e| {
                s2s_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerError",
                    e.to_string(),
                )
            })?,
        None => None,
    };
    tx.commit().await.map_err(|e| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;
    if let Some(fanout) = fanout {
        let _ = fanout.deliver(&state.pool, None).await;
    }
    if let (Some(wake), Some(client)) = (local_wake, &state.push_gateway_client) {
        let _ = wake.dispatch(&state.pool, client).await;
    }
    Ok(RelayGroupMutationOutput {
        entry: out_val["entry"].clone(),
        coordinates: out_val.get("coordinates").cloned(),
        welcomes: out_val.get("welcomes").cloned(),
    })
}

/// A relayed application send's traffic relationship check failed, answered
/// as a local send answers it: a block is the declared `BlockedRelationship`
/// refusal, never an authentication failure; a source that could not answer
/// now, or a policy this DS could not evaluate, decided nothing (503); this
/// store failing is 500.
fn relayed_traffic_failure(
    error: crate::chat_protocol::repository::message_delivery::MessageDeliveryError,
) -> Response {
    use crate::chat_protocol::repository::message_delivery::MessageDeliveryError as E;
    let (status, code) = match error {
        E::BlockedRelationship => (StatusCode::BAD_REQUEST, "BlockedRelationship"),
        E::RelationshipSourceUnavailable | E::RelationshipPolicyUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "RelationshipPolicyUnavailable",
        ),
        error => {
            tracing::error!(?error, "relayed send traffic check failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError")
        }
    };
    s2s_err(status, code, code)
}

async fn sequence_relayed_group_application_send(
    state: &GroupRelayState,
    caller_ds: &str,
    req: &RelayGroupMutationRequest,
) -> Result<RelayGroupMutationOutput, Response> {
    let actor_did = req.actor_did.as_str();
    let actor_device_id = req.actor_device_id;
    let conversation_id = req.conversation_id;

    let body_actor = req
        .signed_request
        .pointer("/body/actorDid")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let body_device = req
        .signed_request
        .pointer("/body/actorDeviceId")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok());
    let key_id = req
        .signed_request
        .pointer("/body/keyId")
        .and_then(Value::as_str)
        .ok_or_else(|| s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", "missing keyId"))?;
    let message_id = req
        .signed_request
        .pointer("/body/messageId")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            s2s_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "invalid messageId",
            )
        })?;

    if body_actor != actor_did || body_device != Some(actor_device_id) {
        return Err(s2s_err(
            StatusCode::UNAUTHORIZED,
            "NotAuthorized",
            "actor identity mismatch",
        ));
    }

    let mut tx = state.pool.begin().await.map_err(|e| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;

    let head_row = sqlx::query(
        "SELECT c.next_entry_seq, c.current_generation, c.current_state_version, \
                g.group_id, s.epoch, s.group_context_hash, s.confirmation_tag, \
                c.lifecycle, c.kind, c.is_remote \
           FROM chat.conversations c \
           JOIN chat.generations g \
             ON g.conversation_id = c.conversation_id AND g.generation = c.current_generation \
           JOIN chat.generation_states s \
             ON s.conversation_id = c.conversation_id \
            AND s.generation = c.current_generation \
            AND s.state_version = c.current_state_version \
          WHERE c.conversation_id = $1 FOR UPDATE",
    )
    .bind(conversation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?
    .ok_or_else(|| {
        s2s_err(
            StatusCode::NOT_FOUND,
            "ConversationNotFound",
            "conversation not found",
        )
    })?;

    let is_remote: bool = head_row.try_get("is_remote").unwrap_or(true);
    let lifecycle: String = head_row.try_get("lifecycle").unwrap_or_default();
    let kind: String = head_row.try_get("kind").unwrap_or_default();
    if is_remote || lifecycle != "active" || kind != "group" {
        return Err(s2s_err(
            StatusCode::UNAUTHORIZED,
            "NotAuthorized",
            "local DS is not the active sequencer for this conversation",
        ));
    }
    let key_row: Option<(Option<String>, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT p.ds_did, k.signing_public_key, d.auth_generation \
           FROM chat.participants p \
           JOIN chat.conversations c USING (conversation_id) \
           JOIN chat.member_devices m \
             ON m.conversation_id = p.conversation_id AND m.user_did = p.user_did \
            AND m.generation = c.current_generation AND m.device_id = $3 AND m.active \
           JOIN chat.devices d ON d.user_did = m.user_did AND d.device_id = m.device_id \
           JOIN chat.device_keys k ON k.user_did = d.user_did AND k.device_id = d.device_id \
          WHERE p.conversation_id = $1 AND p.user_did = $2 \
            AND p.current_membership AND p.status = 'active' \
            AND d.status = 'active' AND d.revoked_at IS NULL \
            AND k.key_id = $4 AND k.revoked_at IS NULL \
            AND k.enrollment_auth_generation <= d.auth_generation \
            AND NOT EXISTS (SELECT 1 FROM chat.device_keys newer \
                 WHERE newer.user_did = d.user_did AND newer.device_id = d.device_id \
                   AND newer.enrollment_auth_generation <= d.auth_generation \
                   AND newer.enrollment_auth_generation > k.enrollment_auth_generation) \
          FOR SHARE OF p, m, d, k",
    )
    .bind(conversation_id)
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(key_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            error.to_string(),
        )
    })?;
    let Some((actor_home, signing_public_key, auth_generation)) = key_row else {
        return Err(s2s_err(
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "actor is not an active group leaf with a current signing key",
        ));
    };
    if actor_home
        .as_deref()
        .is_none_or(|home| !crate::identity::dids_equivalent(home, caller_ds))
    {
        return Err(s2s_err(
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "caller is not the participant's home DS",
        ));
    }

    let signed_bytes = serde_json::to_vec(&req.signed_request)
        .map_err(|e| s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()))?;
    let verified = crate::chat_protocol::transcript::decode_and_verify_signed_mutation(
        &signed_bytes,
        &signing_public_key,
    )
    .map_err(|e| {
        s2s_err(
            StatusCode::UNAUTHORIZED,
            "InvalidSignature",
            format!("{e:?}"),
        )
    })?;
    if verified.auth_generation() != auth_generation as u64 {
        return Err(s2s_err(
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "signed mutation does not match the current device generation",
        ));
    }

    let projection = match verified.projection() {
        crate::chat_protocol::transcript::VerifiedMutationProjection::ApplicationSend(p) => p,
        _ => {
            return Err(s2s_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "mutation is not applicationSendBody",
            ))
        }
    };
    if !matches!(
        projection.prior().get("conversationId"),
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Uuid(value))
            if value.as_bytes() == conversation_id.as_bytes()
    ) {
        return Err(s2s_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "signed application conversationId mismatch",
        ));
    }

    let app_msg = projection.application_message();
    let msg_bytes = match app_msg.get("bytes") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(b)) => b.to_vec(),
        _ => {
            return Err(s2s_err(
                StatusCode::BAD_REQUEST,
                "InvalidApplicationMessage",
                "missing applicationMessage.bytes",
            ))
        }
    };
    let msg_sha256: [u8; 32] = match app_msg.get("sha256") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(b)) if b.len() == 32 => {
            b.try_into().unwrap()
        }
        _ => {
            return Err(s2s_err(
                StatusCode::BAD_REQUEST,
                "InvalidApplicationMessage",
                "missing applicationMessage.sha256",
            ))
        }
    };
    if Sha256::digest(&msg_bytes).as_slice() != msg_sha256.as_slice() {
        return Err(s2s_err(
            StatusCode::BAD_REQUEST,
            "InvalidApplicationMessage",
            "applicationMessage sha256 mismatch",
        ));
    }

    // Idempotent replay check
    let existing_send: Option<(String, Vec<u8>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT status, request_digest, outcome_bytes \
           FROM chat.message_sends \
          WHERE conversation_id = $1 AND message_id = $2",
    )
    .bind(conversation_id)
    .bind(message_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;

    if let Some((status, stored_digest, outcome_bytes)) = existing_send {
        if stored_digest != verified.request_digest() {
            return Err(s2s_err(
                StatusCode::CONFLICT,
                "IdempotencyConflict",
                "message_id digest conflict",
            ));
        }
        if status == "accepted" {
            // A pruned send (O7) replays as its entry exactly as `getEntries`
            // serves it, `payloadPruned`: the accepted outcome, with no
            // ciphertext left to fan out.
            let Some(outcome_bytes) = outcome_bytes else {
                let entry = crate::chat_protocol::repository::entry_read::sent_application_entry(
                    &mut tx,
                    conversation_id,
                    message_id,
                    &stored_digest,
                )
                .await
                .map_err(|e| {
                    s2s_err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalServerError",
                        e.to_string(),
                    )
                })?
                .ok_or_else(|| {
                    s2s_err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalServerError",
                        "accepted message entry is missing",
                    )
                })?;
                return Ok(RelayGroupMutationOutput {
                    entry,
                    coordinates: None,
                    welcomes: None,
                });
            };
            let resp_val: Value = serde_json::from_slice(&outcome_bytes).map_err(|e| {
                s2s_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerError",
                    e.to_string(),
                )
            })?;
            let replay_entry = resp_val["entry"].clone();
            let prepared_fanout =
                super::group_fanout::prepare_group_entry_fanout(&mut tx, &replay_entry)
                    .await
                    .map_err(|e| {
                        s2s_err(StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", e)
                    })?;
            tx.commit().await.map_err(|e| {
                s2s_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerError",
                    e.to_string(),
                )
            })?;
            if let Some(fanout) = prepared_fanout {
                let _ = fanout.deliver(&state.pool, None).await;
            }
            return Ok(RelayGroupMutationOutput {
                entry: replay_entry,
                coordinates: None,
                welcomes: None,
            });
        }
    }

    let head_generation: i64 = head_row.try_get("current_generation").unwrap();
    let head_state_version: i64 = head_row.try_get("current_state_version").unwrap();
    let head_group_id: Vec<u8> = head_row.try_get("group_id").unwrap();
    let head_epoch: i64 = head_row.try_get("epoch").unwrap();
    let head_gch: Vec<u8> = head_row.try_get("group_context_hash").unwrap();
    let head_confirm_tag: Vec<u8> = head_row.try_get("confirmation_tag").unwrap();
    let next_seq: i64 = head_row.try_get("next_entry_seq").unwrap();

    let prior = projection.prior();
    let prior_gen = match prior.get("generation") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Integer(v)) => {
            i64::try_from(v).ok()
        }
        _ => None,
    };
    let prior_ver = match prior.get("stateVersion") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Integer(v)) => {
            i64::try_from(v).ok()
        }
        _ => None,
    };
    let prior_epoch = match prior.get("epoch") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Integer(v)) => {
            i64::try_from(v).ok()
        }
        _ => None,
    };
    let prior_group_id = match prior.get("groupId") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(v)) => Some(v),
        _ => None,
    };
    let prior_gch = match prior.get("groupContextHash") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(v)) => Some(v),
        _ => None,
    };
    let prior_tag = match prior.get("confirmationTag") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(v)) => Some(v),
        _ => None,
    };
    if prior_gen != Some(head_generation)
        || prior_ver != Some(head_state_version)
        || prior_epoch != Some(head_epoch)
        || prior_group_id != Some(head_group_id.as_slice())
        || prior_gch != Some(head_gch.as_slice())
        || prior_tag != Some(head_confirm_tag.as_slice())
    {
        return Err(s2s_err(
            StatusCode::CONFLICT,
            "StaleCoordinates",
            "group coordinates stale",
        ));
    }
    let send_counter = i64::try_from(projection.send_counter()).map_err(|_| {
        s2s_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "invalid sendCounter",
        )
    })?;

    let trusted_instant = crate::chat_protocol::validation::TrustedRequestInstant::capture()
        .map_err(|_| {
            s2s_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "instant",
            )
        })?;
    let trusted_now = trusted_instant.datetime();
    let canonical_now_str = trusted_now.to_rfc3339_opts(SecondsFormat::Millis, true);

    let entry_id = crate::sim_hooks::mint_entry_uuid_v4(
        b"mlsDS.relayGroupMutation",
        &[conversation_id.as_bytes(), &signed_bytes],
    );
    let entry_id_str = entry_id.to_string();
    let canon_entry_id = crate::chat_protocol::validation::CanonicalUuidV4::parse(&entry_id_str)
        .map_err(|_| {
            s2s_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "entry_id",
            )
        })?;
    let canon_convo_id =
        crate::chat_protocol::validation::CanonicalUuidV4::parse(&conversation_id.to_string())
            .map_err(|_| {
                s2s_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerError",
                    "convo_id",
                )
            })?;

    // The traffic relationship check a local send runs, for the actor this
    // verified signature and home binding admitted, under this transaction's
    // head and device locks; nothing is written before it passes.
    let relationship_authority = state.relationship_authority().map_err(|error| {
        tracing::error!(%error, "relayed send relationship authority unavailable");
        s2s_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "RelationshipPolicyUnavailable",
            "RelationshipPolicyUnavailable",
        )
    })?;
    crate::chat_protocol::repository::message_delivery::require_relayed_traffic_policy(
        &mut tx,
        conversation_id,
        caller_ds,
        &verified,
        message_id,
        entry_id,
        &signed_bytes,
        trusted_now,
        relationship_authority.as_ref(),
    )
    .await
    .map_err(relayed_traffic_failure)?;

    let archive = crate::chat_protocol::transcript::verify_application_archive_attestation(
        projection.aad(),
        actor_did,
        actor_device_id,
        &signing_public_key,
        conversation_id,
        message_id,
    )
    .map_err(|error| {
        s2s_err(
            StatusCode::BAD_REQUEST,
            "InvalidApplicationMessage",
            error.to_string(),
        )
    })?;

    let entry_product = crate::chat_protocol::transcript::build_verified_application_entry(
        verified,
        canon_entry_id,
        canon_convo_id,
        next_seq as u64,
        &trusted_instant,
    )
    .map_err(|e| s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", format!("{e:?}")))?;

    let accepted_payload_bytes = entry_product.canonical_entry_bytes().to_vec();
    let accepted_payload_sha256 = entry_product.accepted_payload_sha256().to_vec();
    let request_digest = entry_product.mutation().request_digest().to_vec();
    let signature = entry_product.mutation().signature().to_vec();
    let fingerprint = entry_product.outer_application_fingerprint().to_vec();
    let server_fields =
        serde_ipld_dagcbor::to_vec(&BTreeMap::<String, String>::new()).map_err(|_| {
            s2s_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "cbor",
            )
        })?;

    let receipt_json = match (archive, state.i13_receipt_signer.as_ref()) {
        (Some(archive), Some(signer)) => {
            let signed_rcpt = signer
                .sign_application_receipt(
                    &conversation_id.to_string(),
                    &head_group_id,
                    head_epoch as u64,
                    actor_did,
                    &actor_device_id.to_string(),
                    &entry_id_str,
                    archive.commitment(),
                    next_seq as u64,
                    trusted_now.timestamp_millis(),
                )
                .map_err(|e| {
                    s2s_err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalServerError",
                        e.to_string(),
                    )
                })?;
            Some(I13ReceiptSigner::receipt_wire_json(
                &signed_rcpt,
                head_generation as u64,
                actor_did,
                &actor_device_id.to_string(),
            ))
        }
        _ => None,
    };

    let mut entry_json = json!({
        "$type": "blue.catbird.chat.defs#applicationEntry",
        "entryId": entry_id_str,
        "conversationId": conversation_id.to_string(),
        "seq": next_seq,
        "signedRequest": req.signed_request,
        "receivedAt": canonical_now_str,
    });
    if let Some(ref rcpt) = receipt_json {
        entry_json["sequencerReceipt"] = rcpt.clone();
    }
    let outcome_json = json!({ "entry": entry_json });
    let outcome_bytes = serde_json::to_vec(&outcome_json).map_err(|e| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;

    let append_entry = crate::chat_protocol::repository::delivery::AppendEntry {
        conversation_id,
        entry_id,
        entry_kind: "blue.catbird.chat.defs#applicationEntry".to_string(),
        accepted_payload_bytes,
        accepted_payload_sha256,
        signed_request_bytes: signed_bytes,
        request_digest,
        signature,
        server_fields_bytes: server_fields,
        outer_entry_fingerprint: fingerprint,
        actor_did: actor_did.to_string(),
        actor_device_id,
        actor_key_id: key_id.to_string(),
        actor_auth_generation: auth_generation,
        generation: Some(head_generation),
        state_version: Some(head_state_version),
        transition_id: None,
        message_id: Some(message_id),
        received_at: trusted_now,
    };

    let app_send = crate::chat_protocol::repository::delivery::ApplicationSend {
        entry: append_entry,
        signing_transcript_bytes: entry_product.mutation().transcript_bytes().to_vec(),
        outcome_bytes,
        epoch: head_epoch,
        send_counter,
    };

    let send_outcome = crate::chat_protocol::repository::delivery::resolve_application_send(
        &mut tx,
        &app_send,
        crate::chat_protocol::repository::delivery::ApplicationSendDisposition::Accept,
    )
    .await
    .map_err(|e| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            format!("{e:?}"),
        )
    })?;

    let seq = match send_outcome {
        crate::chat_protocol::repository::delivery::ApplicationSendOutcome::Accepted { seq } => seq,
        crate::chat_protocol::repository::delivery::ApplicationSendOutcome::Stale => {
            return Err(s2s_err(
                StatusCode::CONFLICT,
                "StaleCoordinates",
                "stale application coordinates",
            ));
        }
        // The member's home answers its client this declared code.
        crate::chat_protocol::repository::delivery::ApplicationSendOutcome::StaleSend => {
            return Err(s2s_err(
                StatusCode::CONFLICT,
                "StaleSend",
                "send is not newer than the device's last accepted send",
            ));
        }
    };

    if let Some(ref rcpt) = receipt_json {
        let rcpt_bytes = serde_json::to_vec(rcpt).map_err(|e| {
            s2s_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                e.to_string(),
            )
        })?;
        crate::chat_protocol::repository::delivery::set_entry_sequencer_receipt(
            &mut tx,
            conversation_id,
            seq as u64,
            &rcpt_bytes,
        )
        .await
        .map_err(|e| {
            s2s_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                format!("{e:?}"),
            )
        })?;
    }

    let _ = crate::chat_protocol::repository::message_event::append_message_available_event(
        &mut tx,
        conversation_id,
        0,
        seq,
        trusted_now,
    )
    .await;

    entry_json["seq"] = json!(seq);
    let prepared_fanout = super::group_fanout::prepare_group_entry_fanout(&mut tx, &entry_json)
        .await
        .map_err(|e| s2s_err(StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", e))?;
    let local_wake = match &state.push_gateway_client {
        Some(_) => crate::push_gateway::client::prepare_local_entry_wake(&mut tx, &entry_json)
            .await
            .map_err(|e| {
                s2s_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerError",
                    e.to_string(),
                )
            })?,
        None => None,
    };
    tx.commit().await.map_err(|e| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;
    if let Some(fanout) = prepared_fanout {
        let _ = fanout.deliver(&state.pool, None).await;
    }
    if let (Some(wake), Some(client)) = (local_wake, &state.push_gateway_client) {
        let _ = wake.dispatch(&state.pool, client).await;
    }

    Ok(RelayGroupMutationOutput {
        entry: entry_json,
        coordinates: None,
        welcomes: None,
    })
}

async fn handle_deliver_group_entry(
    State(state): State<GroupRelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let sequencer_ds = match verify_s2s_caller(
        &state,
        &headers,
        "blue.catbird.mlsDS.deliverGroupEntry",
        &body,
    )
    .await
    {
        Ok(d) => d,
        Err(resp) => return resp,
    };

    let req: DeliverGroupEntryRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };

    let Some(seq) = req.entry.get("seq").and_then(Value::as_i64) else {
        return s2s_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "missing entry.seq",
        );
    };
    let Some(entry_id) = req
        .entry
        .get("entryId")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
    else {
        return s2s_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "missing entry.entryId",
        );
    };
    if req.conversation_id.get_version_num() != 4
        || req.generation < 0
        || seq < 1
        || entry_id.get_version_num() != 4
        || req
            .entry
            .get("conversationId")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            != Some(req.conversation_id)
    {
        return s2s_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "entry identity or conversation binding is invalid",
        );
    }

    let entry_bytes = match serde_json::to_vec(&req.entry) {
        Ok(b) => b,
        Err(e) => return s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };

    let entry_type = req.entry.get("$type").and_then(Value::as_str);
    let body_type = req
        .entry
        .pointer("/signedRequest/body/$type")
        .and_then(Value::as_str);
    let is_close_entry = entry_type == Some("blue.catbird.chat.defs#conversationCloseEntry")
        || body_type == Some("blue.catbird.chat.defs#conversationCloseBody");

    if is_close_entry {
        // Boxed, like the catch-up and evidence futures below: inline, these
        // would size every await of this handler (and every caller holding it).
        let close_recipients = match Box::pin(verify_and_wipe_remote_closed_conversation(
            &state,
            &sequencer_ds,
            &req,
            &entry_bytes,
        ))
        .await
        {
            Ok(recipients) => recipients,
            Err(response) => return response,
        };
        if let Some(push_client) = &state.push_gateway_client {
            let epoch = req
                .entry
                .pointer("/signedRequest/body/prior/epoch")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let _ = push_client
                .dispatch_for_local_recipients(
                    &state.pool,
                    &close_recipients,
                    PushWakeDispatch {
                        wake_kind: PushWakeKind::ControlTransition,
                        conversation_id: req.conversation_id,
                        generation: req.generation,
                        seq,
                        epoch,
                        ciphertext: None,
                    },
                )
                .await;
        }
        return (StatusCode::OK, Json(json!({ "accepted": true }))).into_response();
    }
    if entry_type == Some("blue.catbird.chat.defs#accountDeletedEntry") {
        if let Err(response) = verify_account_deletion(&state, &sequencer_ds, &req).await {
            return response;
        }
    }

    let membership_entry = matches!(
        body_type,
        Some("blue.catbird.chat.defs#creationBody")
            | Some("blue.catbird.chat.defs#conversationCreationBody")
            | Some("blue.catbird.chat.defs#policyTransitionBody")
            | Some("blue.catbird.chat.defs#participantAcceptanceBody")
            | Some("blue.catbird.chat.defs#leafRecoveryFulfillmentBody")
    ) || matches!(
        entry_type,
        Some("blue.catbird.chat.defs#creationEntry")
            | Some("blue.catbird.chat.defs#policyEntry")
            | Some("blue.catbird.chat.defs#participantAcceptanceEntry")
            | Some("blue.catbird.chat.defs#leafRecoveryFulfillmentEntry")
    );
    if membership_entry {
        // Mirror membership only while a local participant still awaits a
        // leaf or the entry names a local recipient the mirror lacks; joined
        // members consume replicated entries directly.
        let recipient_dids: Vec<&str> = req
            .recipient_devices
            .iter()
            .map(|(did, _)| did.as_str())
            .collect();
        let catch_up: Result<(bool, bool), sqlx::Error> = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM chat.conversations WHERE conversation_id = $1), \
                    EXISTS(SELECT 1 FROM chat.participants p \
                            WHERE p.conversation_id = $1 AND p.current_membership \
                              AND p.ds_did IS NULL \
                              AND NOT EXISTS(SELECT 1 FROM chat.member_devices m \
                                              WHERE m.conversation_id = p.conversation_id \
                                                AND m.user_did = p.user_did AND m.active)) \
                 OR EXISTS(SELECT 1 FROM unnest($2::text[]) AS r(user_did) \
                            WHERE NOT EXISTS(SELECT 1 FROM chat.participants p \
                                              WHERE p.conversation_id = $1 \
                                                AND p.user_did = r.user_did \
                                                AND p.current_membership))",
        )
        .bind(req.conversation_id)
        .bind(&recipient_dids)
        .fetch_one(&state.pool)
        .await;
        let (mirrored, awaiting_leaf) = match catch_up {
            Ok(row) => row,
            Err(e) => {
                return s2s_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerError",
                    e.to_string(),
                )
            }
        };
        if !mirrored || awaiting_leaf {
            use membership::RelayFailure;
            match Box::pin(membership::bootstrap_home_group(
                &state.pool,
                req.conversation_id,
                &sequencer_ds,
            ))
            .await
            {
                Ok(()) => {}
                // This store failing decided nothing: the sequencer keeps the
                // ordered delivery queued for the identical retry.
                Err(failure @ RelayFailure::Storage(_)) => return failure.into_response(),
                // Without a mirror the entry has nowhere to land: the catch-up
                // is required, so its answer is the entry's.
                Err(failure) if !mirrored => return failure.into_response(),
                // A mirror whose catch-up could not complete now, or whose
                // clean graph cannot replay the group's history, still takes
                // the entry: the remote-group index tracks accounts homed here
                // and their grants, and their reads relay to the sequencer.
                Err(failure) => tracing::warn!(
                    conversation_id = %req.conversation_id,
                    ?failure,
                    "remote group membership catch-up failed; the remote-group index tracks it"
                ),
            }
        }
    }
    let route: Result<(bool, bool), sqlx::Error> = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM chat.conversations WHERE conversation_id = $1), \
                EXISTS(SELECT 1 FROM chat.conversations \
                        WHERE conversation_id = $1 AND kind = 'group' AND is_remote \
                          AND sequencer_ds = $2)",
    )
    .bind(req.conversation_id)
    .bind(&sequencer_ds)
    .fetch_one(&state.pool)
    .await;
    let (mirrored, routed) = match route {
        Ok(route) => route,
        Err(e) => {
            return s2s_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                e.to_string(),
            )
        }
    };
    if !routed {
        // No mirror yet means the membership entry that provisions it has not
        // arrived: a gap the sequencer retries in order, never invented here.
        if !mirrored {
            return s2s_err(
                StatusCode::CONFLICT,
                super::errors::PREDECESSOR_MISSING_ERROR,
                "group mirror is not provisioned: predecessor membership entry missing",
            );
        }
        return s2s_err(
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "caller is not the group's sequencer",
        );
    }
    // Membership the stored sequencer proves for accounts homed here; key and
    // home resolution complete before the persisting transaction.
    let evidence = match Box::pin(remote_group_index::verify_membership_evidence(
        &state,
        &req,
        &entry_bytes,
        seq,
        entry_id,
    ))
    .await
    {
        Ok(evidence) => evidence,
        Err(response) => return response,
    };

    let persist = async {
        let mut tx = state.pool.begin().await?;
        // Readers lock their device row before any conversation head. The
        // grants and Welcome markers below reference local device rows (their
        // foreign keys take `FOR KEY SHARE`), so take those locks first, in
        // canonical order, or a reader holding one deadlocks on this head.
        let (dids, devices): (Vec<String>, Vec<Uuid>) = req
            .recipient_devices
            .iter()
            .cloned()
            .chain(evidence.iter().flat_map(|e| e.welcome_devices()))
            .unzip();
        sqlx::query(
            "SELECT 1 FROM chat.devices d \
               JOIN unnest($1::text[], $2::uuid[]) AS r(user_did, device_id) \
                 USING (user_did, device_id) \
              ORDER BY convert_to(d.user_did, 'UTF8'), uuid_send(d.device_id) \
                FOR KEY SHARE OF d",
        )
        .bind(&dids)
        .bind(&devices)
        .fetch_all(&mut *tx)
        .await?;
        let routed: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM chat.conversations \
              WHERE conversation_id = $1 AND kind = 'group' AND is_remote AND sequencer_ds = $2 \
              FOR UPDATE",
        )
        .bind(req.conversation_id)
        .bind(&sequencer_ds)
        .fetch_optional(&mut *tx)
        .await?;
        if routed.is_none() {
            return Err(sqlx::Error::Protocol("remote group authority changed".into()));
        }
        use crate::chat_protocol::repository::delivery::{
            insert_transport_entry, TransportEntryInsert,
        };
        let inserted = match insert_transport_entry(
            &mut tx,
            req.conversation_id,
            seq,
            entry_id,
            &entry_bytes,
            crate::sim_hooks::current_utc(),
        )
        .await?
        {
            TransportEntryInsert::Inserted => true,
            TransportEntryInsert::Duplicate => false,
            TransportEntryInsert::Conflict => {
                return Err(sqlx::Error::Protocol("conflicting replicated group entry".into()));
            }
        };
        if let Some(evidence) = &evidence {
            remote_group_index::apply_membership_evidence(
                &mut tx,
                req.conversation_id,
                &sequencer_ds,
                evidence,
                crate::sim_hooks::current_utc(),
            )
            .await?;
        }
        if inserted {
            // The sequencer's frozen audience, limited to active local devices
            // of members this home knows: a clean-graph leaf or a pending or
            // active index member. A removed account is granted nothing.
            let (dids, devices): (Vec<_>, Vec<_>) =
                req.recipient_devices.iter().cloned().unzip();
            sqlx::query(
                "INSERT INTO chat.group_transport_entry_recipients (conversation_id, seq, user_did, device_id) \
                 SELECT DISTINCT $1, $2, d.user_did, d.device_id \
                   FROM unnest($3::text[], $4::uuid[]) AS r(user_did, device_id) \
                   JOIN chat.devices d USING (user_did, device_id) \
                  WHERE d.status = 'active' AND d.revoked_at IS NULL \
                    AND (EXISTS(SELECT 1 FROM chat.member_devices m \
                              WHERE m.conversation_id = $1 AND m.user_did = d.user_did \
                                AND m.device_id = d.device_id) \
                         OR EXISTS(SELECT 1 FROM chat.remote_group_memberships rm \
                              WHERE rm.conversation_id = $1 AND rm.user_did = d.user_did \
                                AND rm.status IN ('pending', 'active'))) \
                    AND NOT EXISTS(SELECT 1 FROM chat.remote_group_memberships rm \
                         WHERE rm.conversation_id = $1 AND rm.user_did = d.user_did \
                           AND rm.status = 'removed')",
            )
            .bind(req.conversation_id)
            .bind(seq)
            .bind(&dids)
            .bind(&devices)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await
    }
    .await;
    if let Err(e) = persist {
        return s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        );
    }

    if let Some(push_client) = &state.push_gateway_client {
        let is_application = entry_type == Some("blue.catbird.chat.defs#applicationEntry")
            || body_type == Some("blue.catbird.chat.defs#applicationSendBody");
        let ct = is_application
            .then(|| {
                req.entry
                    .pointer("/signedRequest/body/applicationMessage/bytes")
                    .and_then(|v| {
                        v.as_str()
                            .or_else(|| v.get("$bytes").and_then(Value::as_str))
                    })
                    .and_then(|s| {
                        STANDARD
                            .decode(s)
                            .or_else(|_| URL_SAFE_NO_PAD.decode(s))
                            .ok()
                    })
            })
            .flatten();
        let epoch = req
            .entry
            .pointer("/signedRequest/body/prior/epoch")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let _ = push_client
            .dispatch_for_local_recipients(
                &state.pool,
                &req.recipient_devices,
                PushWakeDispatch {
                    wake_kind: if is_application {
                        PushWakeKind::ApplicationMessage
                    } else {
                        PushWakeKind::ControlTransition
                    },
                    conversation_id: req.conversation_id,
                    generation: req.generation,
                    seq,
                    epoch,
                    ciphertext: ct,
                },
            )
            .await;
    }

    (StatusCode::OK, Json(json!({ "accepted": true }))).into_response()
}

/// A replicated `accountDeletedEntry` is its sequencer's signed evidence: only the exact
/// entry, bound to this conversation and signed with the calling sequencer's resolved
/// `#mls-receipt-1` key, is stored, verbatim. Resolution completes before any transaction.
async fn verify_account_deletion(
    state: &GroupRelayState,
    sequencer_ds: &str,
    req: &DeliverGroupEntryRequest,
) -> Result<(), Response> {
    let forbidden = |error: String| s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", error);
    let (deletion, authority) =
        super::receipt::AccountDeletion::from_entry(&req.entry).map_err(forbidden)?;
    if deletion.conversation_id != req.conversation_id
        || !crate::identity::dids_equivalent(&deletion.sequencer_did, sequencer_ds)
    {
        return Err(forbidden(
            "account deletion is not this conversation's sequencer's".to_string(),
        ));
    }
    let key_bytes = super::resolver::DsResolver::new(
        state.pool.clone(),
        super::resolver::build_resolver_http_client(),
        state.self_did.clone(),
        crate::identity::self_endpoint(),
        None,
        300,
    )
    .resolve_i13_receipt_key(sequencer_ds)
    .await
    .map_err(lookup_failure)?;
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key_bytes)
        .map_err(|error| forbidden(error.to_string()))?;
    authority.verify(&key, &deletion).map_err(forbidden)
}

async fn verify_and_wipe_remote_closed_conversation(
    state: &GroupRelayState,
    sequencer_ds: &str,
    req: &DeliverGroupEntryRequest,
    entry_bytes: &[u8],
) -> Result<Vec<(String, Uuid)>, Response> {
    let storage = |error: sqlx::Error| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            error.to_string(),
        )
    };
    let actor_did = req
        .entry
        .pointer("/signedRequest/body/actorDid")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            s2s_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "missing actorDid",
            )
        })?;
    let actor_device_id = req
        .entry
        .pointer("/signedRequest/body/actorDeviceId")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| {
            s2s_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "invalid actorDeviceId",
            )
        })?;
    let key_id = req
        .entry
        .pointer("/signedRequest/body/keyId")
        .and_then(Value::as_str)
        .ok_or_else(|| s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", "missing keyId"))?;
    let conversation_kind = req
        .entry
        .pointer("/signedRequest/body/conversationKind")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            s2s_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "missing conversationKind",
            )
        })?;
    let terminal_seq = req
        .entry
        .get("seq")
        .and_then(Value::as_i64)
        .filter(|seq| *seq > 0)
        .ok_or_else(|| {
            s2s_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "invalid close seq",
            )
        })?;
    // M-F04: DID and device-key resolution needs HTTP and other pooled connections, so it
    // completes before the terminal transaction. Its outcome is consulted only after the
    // retained-redelivery check inside that transaction.
    let resolver = super::resolver::DsResolver::new(
        state.pool.clone(),
        super::resolver::build_resolver_http_client(),
        state.self_did.clone(),
        crate::identity::self_endpoint(),
        None,
        300,
    );
    let proof_check: Result<(), Response> = async {
        if conversation_kind != "group" {
            return Ok(());
        }
        let proof = req.close_authority.as_ref().ok_or_else(|| {
            s2s_err(
                StatusCode::FORBIDDEN,
                "NotAuthorized",
                "group close lacks terminal final-admin authority",
            )
        })?;
        let key_bytes = resolver
            .resolve_i13_receipt_key(sequencer_ds)
            .await
            .map_err(lookup_failure)?;
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key_bytes)
            .map_err(|error| s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", error.to_string()))?;
        proof
            .verify(&key, sequencer_ds, req.conversation_id, &req.entry)
            .map_err(|error| s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", error))
    }
    .await;
    // `None`: the actor is homed here and its current key is read under the transaction lock.
    let remote_actor_key: Result<Option<(Vec<u8>, i64)>, Response> = async {
        let actor_home = resolver
            .resolve_authoritative_ds(actor_did)
            .await
            .map_err(lookup_failure)?;
        if crate::identity::dids_equivalent(&actor_home.did, &state.self_did) {
            return Ok(None);
        }
        membership::active_device_key(&state.pool, actor_did, actor_device_id, key_id)
            .await
            .map(Some)
            .map_err(lookup_failure)
    }
    .await;
    let mut tx = state.pool.begin().await.map_err(storage)?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended( \
             'conversation-close-terminal:' || $1::uuid::text, 0))",
    )
    .bind(req.conversation_id)
    .execute(&mut *tx)
    .await
    .map_err(storage)?;

    let terminal_schema_ready: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_attribute \
          WHERE attrelid = to_regclass('chat.conversation_close_terminal_entries') \
            AND attname = 'source_ds_did' AND NOT attisdropped)",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(storage)?;
    if !terminal_schema_ready {
        return Err(s2s_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "MailboxNotProvisioned",
            "remote terminal authority storage is not provisioned",
        ));
    }
    let recorded: Option<(Vec<u8>, Option<String>)> = sqlx::query_as(
        "SELECT terminal.entry_bytes, terminal.source_ds_did \
           FROM chat.conversation_close_terminal_entries terminal \
           JOIN chat.events event USING (event_position) \
          WHERE event.event_kind = 'conversationClosed' \
            AND convert_from(event.payload_bytes, 'UTF8')::jsonb->>'conversationId' = $1 \
          ORDER BY event.event_position DESC LIMIT 1",
    )
    .bind(req.conversation_id.to_string())
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?;
    if let Some((recorded_entry, recorded_source)) = recorded {
        if recorded_entry == entry_bytes
            && recorded_source
                .as_deref()
                .is_some_and(|source| crate::identity::dids_equivalent(source, sequencer_ds))
        {
            // An identical redelivery has no append, wipe, or repeated push effects.
            return Ok(Vec::new());
        }
        return Err(s2s_err(
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "terminal close differs from this home's retained authority",
        ));
    }

    let convo_row: Option<(bool, Option<String>, i64, i64, String)> = sqlx::query_as(
        "SELECT is_remote, sequencer_ds, current_generation, current_state_version, kind \
           FROM chat.conversations WHERE conversation_id = $1 FOR UPDATE",
    )
    .bind(req.conversation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?;
    if let Some((is_remote, stored_sequencer, _, _, kind)) = &convo_row {
        if !is_remote
            || kind != conversation_kind
            || stored_sequencer
                .as_deref()
                .is_none_or(|source| !crate::identity::dids_equivalent(source, sequencer_ds))
        {
            return Err(s2s_err(
                StatusCode::FORBIDDEN,
                "NotAuthorized",
                "caller is not the stored sequencer of this remote conversation",
            ));
        }
        if kind == "direct" {
            let active_participant: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM chat.participants \
                  WHERE conversation_id = $1 AND user_did = $2 \
                    AND current_membership AND status IN ('pending', 'active'))",
            )
            .bind(req.conversation_id)
            .bind(actor_did)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
            if !active_participant {
                return Err(s2s_err(
                    StatusCode::FORBIDDEN,
                    "NotAuthorized",
                    "close actor is not a current direct participant",
                ));
            }
        }
    } else {
        // Transport-only C33 homes have no conversation row. Their retained pair
        // and coordinator are the authority; a terminal event cannot create it.
        let inboxes: Vec<(String, String, String, String)> = sqlx::query_as(
            "SELECT coordinator_did, sender_did, recipient_did, status \
               FROM chat.direct_request_transport_inbox \
              WHERE conversation_id = $1 ORDER BY delivery_id FOR UPDATE",
        )
        .bind(req.conversation_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(storage)?;
        if inboxes.is_empty() {
            return Err(s2s_err(
                StatusCode::NOT_FOUND,
                "ConversationNotFound",
                "close has no retained conversation or direct-request authority",
            ));
        }
        if conversation_kind != "direct"
            || inboxes
                .iter()
                .any(|(coordinator, sender, recipient, status)| {
                    !crate::identity::dids_equivalent(coordinator, sequencer_ds)
                        || (actor_did != sender && actor_did != recipient)
                        || !matches!(status.as_str(), "pending" | "accepted")
                })
        {
            return Err(s2s_err(
                StatusCode::FORBIDDEN,
                "NotAuthorized",
                "caller or actor is outside the retained C33 pair",
            ));
        }
    }

    proof_check?;
    let (signing_public_key, auth_generation) = match remote_actor_key? {
        Some(remote) => remote,
        None => {
            let key: Option<(Vec<u8>, i64)> = sqlx::query_as(
                "SELECT k.signing_public_key, d.auth_generation \
                   FROM chat.devices d JOIN chat.device_keys k USING (user_did, device_id) \
                  WHERE d.user_did = $1 AND d.device_id = $2 AND k.key_id = $3 \
                    AND d.status = 'active' AND d.revoked_at IS NULL AND k.revoked_at IS NULL \
                    AND k.enrollment_auth_generation <= d.auth_generation \
                    AND NOT EXISTS(SELECT 1 FROM chat.device_keys newer \
                         WHERE newer.user_did = d.user_did AND newer.device_id = d.device_id \
                           AND newer.enrollment_auth_generation <= d.auth_generation \
                           AND newer.enrollment_auth_generation > k.enrollment_auth_generation) \
                  FOR SHARE OF d, k",
            )
            .bind(actor_did)
            .bind(actor_device_id)
            .bind(key_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?;
            key.ok_or_else(|| {
                s2s_err(
                    StatusCode::FORBIDDEN,
                    "NotAuthorized",
                    "close actor device or key is inactive, revoked, or superseded",
                )
            })?
        }
    };
    let control_entry = crate::chat_protocol::transcript::decode_and_verify_control_entry(
        entry_bytes,
        &signing_public_key,
    )
    .map_err(|error| {
        s2s_err(
            StatusCode::UNAUTHORIZED,
            "InvalidSignature",
            format!("invalid close: {error:?}"),
        )
    })?;
    let verified_close = control_entry.mutation();
    let close = match verified_close.projection() {
        crate::chat_protocol::transcript::VerifiedMutationProjection::ConversationClose(close) => {
            close
        }
        _ => {
            return Err(s2s_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "expected conversationClose",
            ))
        }
    };
    let prior = crate::chat_protocol::state_machine::closed_coordinate(&close.prior()).map_err(
        |error| {
            s2s_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                format!("{error:?}"),
            )
        },
    )?;
    let retired = crate::chat_protocol::state_machine::closed_coordinate(&close.retired())
        .map_err(|error| {
            s2s_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                format!("{error:?}"),
            )
        })?;
    let expected_retired = crate::chat_protocol::state_machine::retired_coordinate(&prior)
        .map_err(|error| {
            s2s_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                format!("{error:?}"),
            )
        })?;
    if prior.conversation_id() != req.conversation_id.as_bytes()
        || retired.conversation_id() != req.conversation_id.as_bytes()
        || prior.generation() != req.generation as u64
        || verified_close.auth_generation() != auth_generation as u64
        || prior.lifecycle() != crate::chat_protocol::snapshot::PublicGroupSnapshotLifecycle::Active
        || retired != expected_retired
    {
        return Err(s2s_err(
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "close coordinates or device generation are not current authority",
        ));
    }
    if let Some((_, _, generation, state_version, _)) = &convo_row {
        if prior.generation() < *generation as u64
            || (prior.generation() == *generation as u64
                && prior.state_version() < *state_version as u64)
        {
            return Err(s2s_err(
                StatusCode::CONFLICT,
                "StaleCoordinates",
                "close predates the mirror",
            ));
        }
    }

    let (recipient_dids, recipient_devices): (Vec<_>, Vec<_>) =
        req.recipient_devices.iter().cloned().unzip();
    let audience: Vec<(String, Uuid)> = if convo_row.is_some() {
        sqlx::query_as(
            "SELECT DISTINCT r.user_did, r.device_id \
               FROM unnest($2::text[], $3::uuid[]) r(user_did, device_id) \
               JOIN chat.devices d USING (user_did, device_id) \
              WHERE d.status = 'active' AND d.revoked_at IS NULL \
                AND ((EXISTS(SELECT 1 FROM chat.participants p \
                       WHERE p.conversation_id = $1 AND p.user_did = r.user_did \
                         AND p.ds_did IS NULL) \
                      AND (EXISTS(SELECT 1 FROM chat.member_devices m \
                            WHERE m.conversation_id = $1 AND m.user_did = r.user_did \
                              AND m.device_id = r.device_id) \
                           OR EXISTS(SELECT 1 FROM chat.participants p \
                            WHERE p.conversation_id = $1 AND p.user_did = r.user_did \
                              AND p.current_membership))) \
                     OR EXISTS(SELECT 1 FROM chat.remote_group_memberships rm \
                          WHERE rm.conversation_id = $1 AND rm.user_did = r.user_did \
                            AND rm.status IN ('pending', 'active'))) \
                AND NOT EXISTS(SELECT 1 FROM chat.remote_group_memberships rm \
                     WHERE rm.conversation_id = $1 AND rm.user_did = r.user_did \
                       AND rm.status = 'removed') \
              ORDER BY r.user_did, r.device_id",
        )
        .bind(req.conversation_id)
        .bind(&recipient_dids)
        .bind(&recipient_devices)
        .fetch_all(&mut *tx)
        .await
        .map_err(storage)?
    } else {
        sqlx::query_as(
            "SELECT DISTINCT r.user_did, r.device_id \
               FROM unnest($2::text[], $3::uuid[]) r(user_did, device_id) \
               JOIN chat.devices d USING (user_did, device_id) \
              WHERE d.status = 'active' AND d.revoked_at IS NULL \
                AND EXISTS(SELECT 1 FROM chat.direct_request_transport_inbox inbox \
                     WHERE inbox.conversation_id = $1 \
                       AND ((inbox.recipient_did = r.user_did AND inbox.recipient_device_id = r.device_id) \
                         OR (inbox.sender_did = r.user_did AND inbox.sender_device_id = r.device_id))) \
              ORDER BY r.user_did, r.device_id",
        )
        .bind(req.conversation_id)
        .bind(&recipient_dids)
        .bind(&recipient_devices)
        .fetch_all(&mut *tx)
        .await
        .map_err(storage)?
    };
    let proof_bytes = req
        .close_authority
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|error| s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", error.to_string()))?;
    crate::chat_protocol::repository::close_terminal::append_remote_close_event(
        &mut tx,
        req.conversation_id,
        sequencer_ds,
        proof_bytes.as_deref(),
        conversation_kind,
        terminal_seq,
        &audience,
        &req.entry,
        crate::sim_hooks::current_utc(),
    )
    .await
    .map_err(|error| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            format!("{error:?}"),
        )
    })?;
    if let Some((_, _, generation, state_version, _)) = convo_row {
        sqlx::query("SELECT chat.open_conversation_wipe_scope()")
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        sqlx::query(
            "UPDATE chat.conversations SET lifecycle = 'superseded', close_transition_id = $2, \
                    close_generation = $3, close_state_version = $4, close_seq = $5, closed_at = $6 \
              WHERE conversation_id = $1",
        )
        .bind(req.conversation_id)
        .bind(Uuid::from_bytes(*close.transition_id().as_bytes()))
        .bind(generation)
        .bind(state_version)
        .bind(terminal_seq)
        .bind(crate::sim_hooks::current_utc())
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    }
    let wiped: bool =
        sqlx::query_scalar("SELECT chat.wipe_closed_conversation_operational_rows($1)")
            .bind(req.conversation_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
    if !wiped {
        return Err(s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "authorized close was not wiped",
        ));
    }
    // The remote-group index ends with the conversation; Welcome markers cascade.
    sqlx::query("DELETE FROM chat.remote_group_memberships WHERE conversation_id = $1")
        .bind(req.conversation_id)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    Ok(audience)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim_hooks::{scope_ds_clock, ManualDsClock};
    use axum::{body::Body, http::Request};

    /// A sequencer that rate-limits (429) or fails (5xx) a relayed operation
    /// decided nothing: the client gets its endpoint's declared retryable 503
    /// with `Retry-After: 5`, and an accept's exported package is kept. Any
    /// other 4xx is the sequencer's definitive refusal.
    #[test]
    fn a_sequencer_429_or_5xx_is_unavailable_and_its_4xx_definitive() {
        use crate::chat_protocol::error::{ChatEndpoint, ChatProtocolErrorCode};
        let body = br#"{"error":"RateLimited","message":"slow down"}"#;
        for status in [429, 500, 503] {
            let failure = GroupRelayError::from_response(status, body);
            assert!(
                matches!(failure, GroupRelayError::Unavailable(_)),
                "{status}: {failure:?}"
            );
            let response = failure
                .into_failure(ChatEndpoint::SubmitTransition)
                .into_response();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                response
                    .headers()
                    .get(axum::http::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok()),
                Some("5")
            );
        }
        assert!(matches!(
            GroupRelayError::from_response(403, br#"{"error":"NotAuthorized"}"#),
            GroupRelayError::Rejected(ChatProtocolErrorCode::NotAuthorized)
        ));
        assert!(matches!(
            GroupRelayError::from_response(302, b""),
            GroupRelayError::Rejected(ChatProtocolErrorCode::InvalidRequest)
        ));
    }

    #[tokio::test]
    async fn another_peer_hmac_cannot_forge_the_caller_did() {
        crate::federation::open_federation_for_test();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://127.0.0.1/group_hmac_forgery_test")
            .unwrap();
        let state = GroupRelayState::for_test(
            pool,
            "did:web:target.example".to_string(),
            b"target-test-secret",
            None,
        );
        let body = b"{}";
        let caller = "did:web:trusted-sequencer.example";
        let method = "blue.catbird.mlsDS.deliverGroupEntry";
        let mut headers = HeaderMap::new();
        headers.insert(S2S_CALLER_DID_HEADER, caller.parse().unwrap());
        headers.insert(
            S2S_TARGET_DID_HEADER,
            "did:web:target.example".parse().unwrap(),
        );
        headers.insert(
            S2S_MAC_HEADER,
            compute_s2s_mac(
                b"another-peer-test-secret",
                caller,
                "did:web:target.example",
                method,
                body,
            )
            .parse()
            .unwrap(),
        );

        let response = verify_s2s_caller(&state, &headers, method, body)
            .await
            .expect_err("another peer's secret must not authenticate a forged caller DID");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    use tower_util::ServiceExt;

    #[tokio::test]
    async fn group_relay_handler_keeps_state_clock_across_awaits() {
        let now = chrono::DateTime::from_timestamp(1_600_000_000, 0).unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://127.0.0.1/group_clock_test")
            .unwrap();
        let state = GroupRelayState::for_test(
            pool,
            "did:web:group-clock.test".to_string(),
            b"group-clock-secret",
            None,
        )
        .with_clock(Arc::new(ManualDsClock::new(now)));
        let router = Router::new()
            .route(
                "/clock",
                post(ClockScoped(|| async {
                    let before = crate::sim_hooks::current_utc();
                    tokio::task::yield_now().await;
                    assert_eq!(crate::sim_hooks::current_utc(), before);
                    before.timestamp_millis().to_string()
                })),
            )
            .with_state(state);
        let request = Request::builder()
            .method("POST")
            .uri("/clock")
            .body(Body::empty())
            .unwrap();
        let ambient = Arc::new(ManualDsClock::new(now + chrono::Duration::days(1)));
        let response = scope_ds_clock(ambient, router.oneshot(request))
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(
            bytes.as_ref(),
            now.timestamp_millis().to_string().as_bytes()
        );
    }
}

#[cfg(all(test, feature = "test-support", feature = "sim"))]
#[path = "group_relay_security_tests.rs"]
mod security_tests;

#[cfg(all(test, feature = "test-support", feature = "sim"))]
#[path = "s2s_stream_tests.rs"]
mod s2s_stream_tests;
