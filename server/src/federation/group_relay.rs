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
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use uuid::Uuid;

use super::receipt::I13ReceiptSigner;
use crate::{
    push_gateway::client::{PushGatewayClient, PushWakeDispatch, PushWakeKind},
    storage::DbPool,
    SINGLE_MLS_ARTIFACT_BODY_LIMIT_BYTES,
};

#[path = "group_membership.rs"]
mod membership;
pub(crate) use membership::{
    stage_remote_group_participants, try_relay_group_state, try_relay_home_group_operation,
    try_relay_labyrinth_directory,
};

type HmacSha256 = Hmac<Sha256>;

const S2S_CALLER_DID_HEADER: &str = "x-catbird-s2s-caller-did";
const S2S_TARGET_DID_HEADER: &str = "x-catbird-s2s-target-did";
const S2S_MAC_HEADER: &str = "x-catbird-s2s-mac";

/// Relay fan-out and push wakes are awaited inline within the request's clock scope.
#[derive(Clone)]
pub struct GroupRelayState {
    pool: DbPool,
    self_did: String,
    s2s_shared_secret: Option<Arc<Vec<u8>>>,
    i13_receipt_signer: Option<Arc<I13ReceiptSigner>>,
    push_gateway_client: Option<Arc<PushGatewayClient>>,
    clock: Arc<dyn crate::sim_hooks::DsClock>,
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
        let s2s_shared_secret =
            configured_group_relay_hmac_secret().map(|s| Arc::new(s.into_bytes()));
        Self {
            pool,
            self_did: crate::identity::canonical_did(&self_did).to_string(),
            s2s_shared_secret,
            i13_receipt_signer,
            push_gateway_client,
            clock: Arc::new(crate::sim_hooks::SystemDsClock),
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

    #[cfg(feature = "sim")]
    pub fn with_sim_hooks(mut self, hooks: Arc<crate::sim_hooks::SimDsHooks>) -> Self {
        self.self_did = crate::identity::canonical_did(&hooks.service_did).to_string();
        self.s2s_shared_secret = hooks
            .group_relay_hmac_secret
            .as_ref()
            .filter(|secret| !secret.is_empty())
            .map(|secret| Arc::new(secret.as_bytes().to_vec()));
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
        .with_state(state)
}

/// Optional HMAC federation configuration, scoped per delivery service in simulations.
pub fn configured_group_relay_hmac_secret() -> Option<String> {
    #[cfg(feature = "sim")]
    if let Some(hooks) = crate::sim_hooks::active_sim_ds() {
        return hooks
            .group_relay_hmac_secret
            .clone()
            .filter(|secret| !secret.is_empty());
    }
    std::env::var("FEDERATION_GROUP_RELAY_HMAC_SECRET")
        .ok()
        .filter(|secret| !secret.is_empty())
}

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

async fn verify_s2s_caller(
    state: &GroupRelayState,
    headers: &HeaderMap,
    lxm: &str,
    body: &[u8],
) -> Result<String, Response> {
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
                return Ok(crate::identity::canonical_did(caller).to_string());
            }
            return Err(s2s_err(
                StatusCode::UNAUTHORIZED,
                "NotAuthorized",
                "invalid S2S MAC",
            ));
        }
    }

    if let Ok(principal) =
        crate::auth::verify_mls_service_principal(headers, &state.pool, lxm).await
    {
        return Ok(crate::identity::canonical_did(principal.did()).to_string());
    }
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            s2s_err(
                StatusCode::UNAUTHORIZED,
                "NotAuthorized",
                "missing Bearer token",
            )
        })?;
    let claims = crate::auth::shared_auth_middleware()
        .verify_jwt_for_audience(token, Some(&state.self_did))
        .await
        .map_err(|e| s2s_err(StatusCode::UNAUTHORIZED, "NotAuthorized", e.to_string()))?;
    crate::auth::enforce_standard_with_replay_store(&claims, lxm, &state.pool)
        .await
        .map_err(|e| s2s_err(StatusCode::UNAUTHORIZED, "NotAuthorized", e.to_string()))?;
    Ok(crate::identity::canonical_did(&claims.iss).to_string())
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

/// Why a relayed group operation was not completed by its sequencer.
#[derive(Debug)]
pub enum GroupRelayError {
    /// The sequencer answered with a declared clean-chat protocol error.
    Rejected(crate::chat_protocol::error::ChatProtocolErrorCode),
    /// The sequencer was unreachable or failed without a protocol answer.
    Unavailable(String),
}

impl GroupRelayError {
    /// Classify a non-success sequencer answer; every 4xx is definitive.
    fn from_response(status: u16, body: &[u8]) -> Self {
        if !(400..500).contains(&status) {
            return Self::Unavailable(format!("HTTP {status}: {}", String::from_utf8_lossy(body)));
        }
        Self::Rejected(
            remote_protocol_code(body)
                .unwrap_or(crate::chat_protocol::error::ChatProtocolErrorCode::InvalidRequest),
        )
    }

    /// A rejection keeps the sequencer's code; unavailability maps to the
    /// endpoint's declared retryable code.
    pub(crate) fn into_failure(
        self,
        endpoint: crate::chat_protocol::error::ChatEndpoint,
    ) -> crate::handlers::chat::ChatFailure {
        use crate::chat_protocol::error::{ChatProtocolErrorCode as C, EndpointProtocolError};
        use crate::handlers::chat::ChatFailure;
        match self {
            Self::Rejected(code) => ChatFailure::protocol(endpoint, code),
            Self::Unavailable(_) => [C::RelationshipPolicyUnavailable, C::CapacityUnavailable]
                .into_iter()
                .find(|code| EndpointProtocolError::new(endpoint, *code).is_ok())
                .map_or_else(
                    || ChatFailure::storage(endpoint),
                    |code| ChatFailure::protocol_with_retry(endpoint, code, Some(5)),
                ),
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
    let unavailable = |error: String| GroupRelayError::Unavailable(error);
    let body_bytes = serde_json::to_vec(request).map_err(|e| unavailable(e.to_string()))?;
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
        .map_err(|e| unavailable(e.to_string()))?;
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
    .map_err(unavailable)?;
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
    if !super::FederationMode::effective().allows_remote_traffic() {
        return Ok(None);
    }
    let secret = configured_group_relay_hmac_secret();
    if secret.is_none() && super::canonical_relay::configured_s2s_signing_key_pem().is_err() {
        return Ok(None);
    }
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
    .map_err(|e| GroupRelayError::Unavailable(e.to_string()))?;
    let seq_ds = match local_convo {
        Some((kind, true, Some(seq_ds))) if kind == "group" && !mailbox_commit => seq_ds,
        _ => return Ok(None),
    };
    if signed_req.pointer("/body/actorDid").and_then(Value::as_str) != Some(actor_did) {
        return Err(GroupRelayError::Rejected(
            crate::chat_protocol::error::ChatProtocolErrorCode::NotAuthorized,
        ));
    }
    let dest = resolver
        .resolve_ds_destination_uncached(&seq_ds)
        .await
        .map_err(|_| GroupRelayError::Unavailable("sequencer destination unresolved".into()))?;
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
        .map_err(|e| GroupRelayError::Unavailable(e.to_string()))
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

/// Outbound S2S client helper: fan out a sequenced group entry from the sequencing `mls-ds` to a remote home `mls-ds`.
pub async fn deliver_group_entry_to_remote_home(
    remote_home_endpoint: &str,
    sequencer_did: &str,
    remote_home_did: &str,
    s2s_secret: &[u8],
    request: &DeliverGroupEntryRequest,
) -> Result<(), String> {
    let body_bytes = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    let caller_norm = crate::identity::canonical_did(sequencer_did);
    let target_norm = crate::identity::canonical_did(remote_home_did);
    let url = format!(
        "{}/xrpc/blue.catbird.mlsDS.deliverGroupEntry",
        remote_home_endpoint.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json");
    req = attach_group_s2s_auth(
        req,
        caller_norm,
        target_norm,
        "blue.catbird.mlsDS.deliverGroupEntry",
        s2s_secret,
        &body_bytes,
    )?;
    let resp = crate::sim_hooks::send_reqwest(req.body(body_bytes))
        .await
        .map_err(|e| format!("deliverGroupEntry POST failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(format!(
            "deliverGroupEntry returned HTTP {}: {txt}",
            status.as_u16()
        ));
    }
    Ok(())
}

fn attach_group_s2s_auth(
    request: reqwest::RequestBuilder,
    caller_did: &str,
    target_did: &str,
    method: &str,
    s2s_secret: &[u8],
    body_bytes: &[u8],
) -> Result<reqwest::RequestBuilder, String> {
    if !s2s_secret.is_empty() {
        let mac = compute_s2s_mac(s2s_secret, caller_did, target_did, method, body_bytes);
        return Ok(request
            .header(S2S_CALLER_DID_HEADER, caller_did)
            .header(S2S_TARGET_DID_HEADER, target_did)
            .header(S2S_MAC_HEADER, mac));
    }
    let signing_key_pem = super::canonical_relay::configured_s2s_signing_key_pem()
        .map_err(|error| error.to_string())?;
    let client = super::service_auth::ServiceAuthClient::from_es256_pem(
        caller_did.to_string(),
        signing_key_pem.as_bytes(),
        Some("#atproto".to_string()),
    )
    .map_err(|error| error.to_string())?;
    let token = client
        .mint_token(target_did, method)
        .map_err(|error| error.to_string())?;
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
            | "blue.catbird.chat.acknowledgeEntries"
    ) {
        return membership::relay_membership(&state, &caller_ds, &req).await;
    }
    let res = match req.endpoint.as_str() {
        "blue.catbird.chat.sendMessage" => {
            sequence_relayed_group_application_send(&state, &req).await
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
        let routes = crate::chat_protocol::federation_routing::resolve_participant_routing(
            &state.pool,
            Some(&resolver),
            &add_principals,
        )
        .await
        .map_err(|e| {
            s2s_err(
                StatusCode::FORBIDDEN,
                "NotAuthorized",
                format!("participant routing failed: {e}"),
            )
        })?;
        stage_remote_group_participants(&state.pool, &routes)
            .await
            .map_err(|e| s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", e))?;
        Some(crate::chat_protocol::federation_routing::ParticipantRoutingIntent::new(routes))
    } else {
        None
    };
    let relationship_authority = if state.clock.is_deterministic() {
        crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority::sim_allow_all()
            .map_err(|e| {
                s2s_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerError",
                    format!("{e:?}"),
                )
            })?
    } else {
        crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority::from_startup_guard(
            crate::chat_protocol::repository::relationship::load_fixed_relationship_authority_startup_guard()
                .map_err(|e| {
                    s2s_err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "RelationshipPolicyUnavailable",
                        format!("{e:?}"),
                    )
                })?,
        )
    };
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
            &relationship_authority,
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

async fn sequence_relayed_group_application_send(
    state: &GroupRelayState,
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

    // Active member check in chat.participants
    let active_member: bool = sqlx::query_scalar(
        "SELECT EXISTS( \
             SELECT 1 FROM chat.participants \
              WHERE conversation_id = $1 AND user_did = $2 \
                AND current_membership = TRUE AND status = 'active' \
         )",
    )
    .bind(conversation_id)
    .bind(actor_did)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;
    if !active_member {
        return Err(s2s_err(
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "actor is not an active group participant",
        ));
    }

    // Verify device Ed25519 key & canonical mutation signature
    let key_row: Option<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT k.signing_public_key, k.enrollment_auth_generation \
           FROM chat.device_keys k \
           JOIN chat.devices d ON d.user_did = k.user_did AND d.device_id = k.device_id \
          WHERE k.user_did = $1 AND k.device_id = $2 AND k.key_id = $3 \
            AND k.revoked_at IS NULL AND d.status = 'active'",
    )
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(key_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;

    let Some((signing_public_key, auth_generation)) = key_row else {
        return Err(s2s_err(
            StatusCode::UNAUTHORIZED,
            "InvalidSignature",
            "active device signing key not found on sequencer",
        ));
    };

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
    if is_remote || lifecycle != "active" {
        return Err(s2s_err(
            StatusCode::UNAUTHORIZED,
            "NotAuthorized",
            "local DS is not the active sequencer for this conversation",
        ));
    }

    // Idempotent replay check
    let existing_send: Option<(String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
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

    let receipt_commitment: [u8; 32] = match projection.aad().get("archiveCommitment") {
        None => msg_sha256,
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(v)) if v.len() == 32 => {
            v.try_into().expect("32-byte archiveCommitment")
        }
        Some(_) => {
            return Err(s2s_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "archiveCommitment must be 32 bytes",
            ));
        }
    };

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

    let receipt_json = if let Some(ref signer) = state.i13_receipt_signer {
        let signed_rcpt = signer
            .sign_application_receipt(
                &conversation_id.to_string(),
                &head_group_id,
                head_epoch as u64,
                actor_did,
                &actor_device_id.to_string(),
                &entry_id_str,
                &receipt_commitment,
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
    } else {
        None
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
        if let Err(resp) =
            verify_and_wipe_remote_closed_conversation(&state, &sequencer_ds, &req, &entry_bytes)
                .await
        {
            return resp;
        }
        if let Some(push_client) = &state.push_gateway_client {
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
            if let Err(e) =
                membership::bootstrap_home_group(&state.pool, req.conversation_id, &sequencer_ds)
                    .await
            {
                if !mirrored {
                    return s2s_err(StatusCode::SERVICE_UNAVAILABLE, "MailboxNotProvisioned", e);
                }
                tracing::warn!(
                    conversation_id = %req.conversation_id,
                    error = %e,
                    "remote group membership catch-up failed"
                );
            }
        }
    }
    let routed: bool = match sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.conversations \
          WHERE conversation_id = $1 AND kind = 'group' AND is_remote AND sequencer_ds = $2)",
    )
    .bind(req.conversation_id)
    .bind(&sequencer_ds)
    .fetch_one(&state.pool)
    .await
    {
        Ok(routed) => routed,
        Err(e) => {
            return s2s_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                e.to_string(),
            )
        }
    };
    if !routed {
        return s2s_err(
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "caller is not the group's sequencer",
        );
    }

    let persist = async {
        let mut tx = state.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT INTO chat.direct_request_transport_entries ( \
                 conversation_id, seq, entry_id, entry_bytes, created_at \
             ) VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (conversation_id, seq) DO NOTHING",
        )
        .bind(req.conversation_id)
        .bind(seq)
        .bind(entry_id)
        .bind(&entry_bytes)
        .bind(crate::sim_hooks::current_utc())
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() == 1 {
            let (dids, devices): (Vec<_>, Vec<_>) = req.recipient_devices.iter().cloned().unzip();
            sqlx::query(
                "INSERT INTO chat.group_transport_entry_recipients (conversation_id, seq, user_did, device_id) \
                 SELECT DISTINCT $1, $2, d.user_did, d.device_id \
                   FROM unnest($3::text[], $4::uuid[]) AS r(user_did, device_id) \
                   JOIN chat.devices d USING (user_did, device_id) \
                  WHERE d.status = 'active' AND d.revoked_at IS NULL \
                    AND EXISTS(SELECT 1 FROM chat.member_devices m \
                         WHERE m.conversation_id = $1 AND m.user_did = d.user_did \
                           AND m.device_id = d.device_id)",
            )
            .bind(req.conversation_id)
            .bind(seq)
            .bind(&dids)
            .bind(&devices)
            .execute(&mut *tx)
            .await?;
        } else {
            let existing: Vec<u8> = sqlx::query_scalar(
                "SELECT entry_bytes FROM chat.direct_request_transport_entries \
                  WHERE conversation_id = $1 AND seq = $2",
            )
            .bind(req.conversation_id)
            .bind(seq)
            .fetch_one(&mut *tx)
            .await?;
            if existing != entry_bytes {
                return Err(sqlx::Error::Protocol("conflicting replicated group entry".into()));
            }
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

async fn verify_and_wipe_remote_closed_conversation(
    state: &GroupRelayState,
    sequencer_ds: &str,
    req: &DeliverGroupEntryRequest,
    entry_bytes: &[u8],
) -> Result<(), Response> {
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
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            s2s_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "missing actorDeviceId",
            )
        })?;
    let key_id = req
        .entry
        .pointer("/signedRequest/body/keyId")
        .and_then(Value::as_str)
        .ok_or_else(|| s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", "missing keyId"))?;
    let signed_wrapper_val = req.entry.get("signedRequest").ok_or_else(|| {
        s2s_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "missing signedRequest",
        )
    })?;
    let signed_wrapper_bytes = serde_json::to_vec(signed_wrapper_val)
        .map_err(|e| s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()))?;

    let local_key: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT k.signing_public_key \
           FROM chat.device_keys k \
          WHERE k.user_did = $1 AND k.device_id = $2 AND k.key_id = $3 \
            AND k.revoked_at IS NULL",
    )
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(key_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;

    let signing_public_key = if let Some(pk) = local_key {
        pk
    } else {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| {
                s2s_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerError",
                    e.to_string(),
                )
            })?;
        let resolver = Arc::new(super::resolver::DsResolver::new(
            state.pool.clone(),
            http.clone(),
            state.self_did.clone(),
            crate::identity::self_endpoint(),
            None,
            300,
        ));
        let dev_client = super::declaration_client::DeviceRecordClient::new(http, resolver);
        let records = dev_client
            .fetch_device_records(actor_did)
            .await
            .map_err(|e| {
                s2s_err(
                    StatusCode::UNAUTHORIZED,
                    "InvalidSignature",
                    format!("actor PDS device key lookup failed: {e}"),
                )
            })?;
        let target_rkey = actor_device_id.hyphenated().to_string();
        let mut matched_pk: Option<Vec<u8>> = None;
        for rec in records {
            let rkey = rec.uri.rsplit('/').next().unwrap_or("");
            if !rkey.eq_ignore_ascii_case(&target_rkey) {
                continue;
            }
            let Some(wrapper) = &rec.value.mls_signature_public_key else {
                continue;
            };
            let Ok(pk) = STANDARD
                .decode(wrapper.bytes.trim())
                .or_else(|_| URL_SAFE_NO_PAD.decode(wrapper.bytes.trim()))
            else {
                continue;
            };
            if pk.len() == 32 && URL_SAFE_NO_PAD.encode(Sha256::digest(&pk)) == key_id {
                matched_pk = Some(pk);
                break;
            }
        }
        matched_pk.ok_or_else(|| {
            s2s_err(
                StatusCode::UNAUTHORIZED,
                "InvalidSignature",
                "actor close signing key not authorized",
            )
        })?
    };

    let control_entry;
    let signed_mutation;
    let verified_close = if req.entry.get("$type").is_some() && req.entry.get("tombstone").is_some()
    {
        control_entry = crate::chat_protocol::transcript::decode_and_verify_control_entry(
            entry_bytes,
            &signing_public_key,
        )
        .map_err(|e| {
            s2s_err(
                StatusCode::UNAUTHORIZED,
                "InvalidSignature",
                format!("invalid close control entry: {e:?}"),
            )
        })?;
        control_entry.mutation()
    } else {
        signed_mutation = crate::chat_protocol::transcript::decode_and_verify_signed_mutation(
            &signed_wrapper_bytes,
            &signing_public_key,
        )
        .map_err(|e| {
            s2s_err(
                StatusCode::UNAUTHORIZED,
                "InvalidSignature",
                format!("invalid close signedRequest: {e:?}"),
            )
        })?;
        &signed_mutation
    };

    if verified_close.kind()
        != crate::chat_protocol::transcript::SignedMutationKind::ConversationClose
    {
        return Err(s2s_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "expected conversationClose mutation",
        ));
    }
    let prior_convo = req
        .entry
        .pointer("/signedRequest/body/prior/conversationId")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok());
    if prior_convo != Some(req.conversation_id) {
        return Err(s2s_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "close conversationId mismatch",
        ));
    }

    let mut tx = state.pool.begin().await.map_err(|e| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;

    let convo_row: Option<(bool, Option<String>, i64, i64)> = sqlx::query_as(
        "SELECT is_remote, sequencer_ds, current_generation, current_state_version \
           FROM chat.conversations \
          WHERE conversation_id = $1 \
          FOR UPDATE",
    )
    .bind(req.conversation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;

    // Peers homed here learn the authenticated close through getEntries/events
    // after the wipe instead of observing a silently missing conversation.
    let conversation_kind = req
        .entry
        .pointer("/signedRequest/body/conversationKind")
        .and_then(Value::as_str)
        .unwrap_or("group");
    let terminal_seq = req
        .entry
        .get("seq")
        .and_then(Value::as_i64)
        .ok_or_else(|| {
            s2s_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "missing close entry.seq",
            )
        })?;
    crate::chat_protocol::repository::close_terminal::append_remote_close_event(
        &mut tx,
        req.conversation_id,
        conversation_kind,
        terminal_seq,
        &req.recipient_devices,
        &req.entry,
        crate::sim_hooks::current_utc(),
    )
    .await
    .map_err(|e| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            format!("{e:?}"),
        )
    })?;
    if let Some((is_remote, stored_seq_ds, cur_gen, cur_sv)) = convo_row {
        if !is_remote
            || stored_seq_ds
                .as_deref()
                .is_none_or(|ds| !crate::identity::dids_equivalent(ds, sequencer_ds))
        {
            return Err(s2s_err(
                StatusCode::UNAUTHORIZED,
                "NotAuthorized",
                "caller is not the authoritative sequencer for this remote conversation",
            ));
        }
        let close_tid = req
            .entry
            .pointer("/signedRequest/body/transitionId")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
            .unwrap_or_else(Uuid::new_v4);
        let close_seq = req.entry.get("seq").and_then(Value::as_i64).unwrap_or(1);
        let now = crate::sim_hooks::current_utc();
        sqlx::query("SELECT chat.open_conversation_wipe_scope()")
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                s2s_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerError",
                    e.to_string(),
                )
            })?;
        sqlx::query(
            "UPDATE chat.conversations \
                SET lifecycle = 'superseded', \
                    close_transition_id = $2, \
                    close_generation = $3, \
                    close_state_version = $4, \
                    close_seq = $5, \
                    closed_at = $6 \
              WHERE conversation_id = $1",
        )
        .bind(req.conversation_id)
        .bind(close_tid)
        .bind(cur_gen)
        .bind(cur_sv)
        .bind(close_seq)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            s2s_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                e.to_string(),
            )
        })?;
    }
    let _: bool = sqlx::query_scalar("SELECT chat.wipe_closed_conversation_operational_rows($1)")
        .bind(req.conversation_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            s2s_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                e.to_string(),
            )
        })?;

    tx.commit().await.map_err(|e| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim_hooks::{scope_ds_clock, ManualDsClock};
    use axum::{body::Body, http::Request};
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
