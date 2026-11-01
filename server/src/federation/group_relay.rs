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

use std::{collections::BTreeMap, sync::Arc, time::Duration};

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

type HmacSha256 = Hmac<Sha256>;

const S2S_CALLER_DID_HEADER: &str = "x-catbird-s2s-caller-did";
const S2S_TARGET_DID_HEADER: &str = "x-catbird-s2s-target-did";
const S2S_MAC_HEADER: &str = "x-catbird-s2s-mac";

#[derive(Clone)]
pub struct GroupRelayState {
    pool: DbPool,
    self_did: String,
    s2s_shared_secret: Option<Arc<Vec<u8>>>,
    i13_receipt_signer: Option<Arc<I13ReceiptSigner>>,
    push_gateway_client: Option<Arc<PushGatewayClient>>,
}

impl GroupRelayState {
    pub fn new(
        pool: DbPool,
        self_did: String,
        i13_receipt_signer: Option<Arc<I13ReceiptSigner>>,
        push_gateway_client: Option<Arc<PushGatewayClient>>,
    ) -> Self {
        let s2s_shared_secret = std::env::var("FEDERATION_GROUP_RELAY_HMAC_SECRET")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| Arc::new(s.into_bytes()));
        Self {
            pool,
            self_did: crate::identity::canonical_did(&self_did).to_string(),
            s2s_shared_secret,
            i13_receipt_signer,
            push_gateway_client,
        }
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

pub fn group_relay_router(state: GroupRelayState) -> Router {
    Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.relayGroupMutation",
            post(handle_relay_group_mutation)
                .layer(DefaultBodyLimit::max(SINGLE_MLS_ARTIFACT_BODY_LIMIT_BYTES)),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.deliverGroupEntry",
            post(handle_deliver_group_entry)
                .layer(DefaultBodyLimit::max(SINGLE_MLS_ARTIFACT_BODY_LIMIT_BYTES)),
        )
        .with_state(state)
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

    let principal = crate::auth::verify_mls_service_principal(headers, &state.pool, lxm)
        .await
        .map_err(|e| s2s_err(StatusCode::UNAUTHORIZED, "NotAuthorized", e.to_string()))?;
    Ok(crate::identity::canonical_did(principal.did()).to_string())
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

/// Outbound S2S client helper: relay a group mutation from the member's home `mls-ds` to `sequencer_ds`.
pub async fn relay_group_mutation_to_sequencer(
    sequencer_endpoint: &str,
    caller_home_did: &str,
    sequencer_did: &str,
    s2s_secret: &[u8],
    request: &RelayGroupMutationRequest,
) -> Result<RelayGroupMutationOutput, String> {
    let body_bytes = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    let caller_norm = crate::identity::canonical_did(caller_home_did);
    let target_norm = crate::identity::canonical_did(sequencer_did);
    let mac = compute_s2s_mac(
        s2s_secret,
        caller_norm,
        target_norm,
        "blue.catbird.mlsDS.relayGroupMutation",
        &body_bytes,
    );
    let url = format!(
        "{}/xrpc/blue.catbird.mlsDS.relayGroupMutation",
        sequencer_endpoint.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(S2S_CALLER_DID_HEADER, caller_norm)
        .header(S2S_TARGET_DID_HEADER, target_norm)
        .header(S2S_MAC_HEADER, mac)
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| format!("relayGroupMutation POST failed: {e}"))?;
    let status = resp.status();
    let resp_bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!(
            "relayGroupMutation returned HTTP {}: {}",
            status.as_u16(),
            String::from_utf8_lossy(&resp_bytes)
        ));
    }
    serde_json::from_slice(&resp_bytes).map_err(|e| e.to_string())
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
    let mac = compute_s2s_mac(
        s2s_secret,
        caller_norm,
        target_norm,
        "blue.catbird.mlsDS.deliverGroupEntry",
        &body_bytes,
    );
    let url = format!(
        "{}/xrpc/blue.catbird.mlsDS.deliverGroupEntry",
        remote_home_endpoint.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(S2S_CALLER_DID_HEADER, caller_norm)
        .header(S2S_TARGET_DID_HEADER, target_norm)
        .header(S2S_MAC_HEADER, mac)
        .body(body_bytes)
        .send()
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

async fn handle_relay_group_mutation(
    State(state): State<GroupRelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let _caller_ds = match verify_s2s_caller(
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

    if req.endpoint != "blue.catbird.chat.sendMessage" {
        return s2s_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            format!("unsupported relayed group endpoint: {}", req.endpoint),
        );
    }

    match sequence_relayed_group_application_send(&state, &req).await {
        Ok(out) => (StatusCode::OK, Json(out)).into_response(),
        Err(resp) => resp,
    }
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
            tx.commit().await.map_err(|e| {
                s2s_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerError",
                    e.to_string(),
                )
            })?;
            return Ok(RelayGroupMutationOutput {
                entry: resp_val["entry"].clone(),
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

    let entry_id = Uuid::new_v4();
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

    tx.commit().await.map_err(|e| {
        s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;

    entry_json["seq"] = json!(seq);
    Ok(RelayGroupMutationOutput { entry: entry_json })
}

async fn handle_deliver_group_entry(
    State(state): State<GroupRelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let _sequencer_ds = match verify_s2s_caller(
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

    if let Err(e) = sqlx::query(
        "INSERT INTO chat.direct_request_transport_entries ( \
             conversation_id, seq, entry_id, entry_bytes, created_at \
         ) VALUES ($1, $2, $3, $4, clock_timestamp()) \
         ON CONFLICT (conversation_id, seq) DO NOTHING",
    )
    .bind(req.conversation_id)
    .bind(seq)
    .bind(entry_id)
    .bind(&entry_bytes)
    .execute(&state.pool)
    .await
    {
        return s2s_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        );
    }

    if let Some(ref push_client) = state.push_gateway_client {
        let ct = req
            .entry
            .pointer("/signedRequest/body/applicationMessage/bytes")
            .and_then(Value::as_str)
            .and_then(|s| STANDARD.decode(s).ok());
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
                    wake_kind: PushWakeKind::ApplicationMessage,
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
