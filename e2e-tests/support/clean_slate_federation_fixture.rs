//! Clean-slate two-server federation & ATProto Spaces loopback server fixture (`G3`, `G4`, `G6`, `Gate 10`).
//!
//! Boots a real `catbird-server` HTTP stack (`chat_router` + `group_relay_router` +
//! `space_host_router` + `labyrinth_router` + `/.well-known/did.json`) over a freshly
//! migrated PostgreSQL database (`clean_slate_fed_<32 lowercase hex>`), supporting both
//! `did:web` (`ds-a`) and `did:plc` (`ds-b`) identities without requiring a Docker daemon.

use std::{io::Write as _, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    extract::{FromRef, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_server::{
    auth::{cache_test_did_document, DidDocument, PublicKeyJwk, Service, VerificationMethod},
    chat_protocol::{
        repository::{
            direct_request_receipts::DirectRequestReceiptSigner,
            expiry_sweep::sweep_expired_published_direct_requests_for_test,
        },
        test_support::{
            seed_clean_slate_active_zero_leaf_member_for_test,
            seed_clean_slate_application_fixture_unsealed,
            seed_clean_slate_expired_direct_request_fixture,
            seed_clean_slate_remove_zero_leaf_member_for_test, sign_mutation_json_for_test,
        },
    },
    federation::{
        canonical_relay::check_pair_owner_fence,
        group_relay::{group_relay_router, GroupRelayState},
        outbound::OutboundClient,
        receipt::I13ReceiptSigner,
        space_read_relay::register_test_space_relay_target,
        DsResolver, ServiceAuthClient,
    },
    handlers::{
        chat::{chat_router, ChatRuntime},
        ds::{get_convo_digest, get_convo_events, health_check},
        labyrinth::labyrinth_router,
    },
    identity::did_doc::{
        build_direct_request_receipt_did_document, build_service_did_document,
        did_web_document_path,
    },
    labyrinth::repo::retention::delete_account_data_with_conversations,
    push_gateway::{client::PushGatewayClient, ssrf::register_test_gateway_override},
    realtime::SseState,
    space_host::{
        revocation_fanout::{
            fan_out_space_deleted_for_conversation,
            revoke_inactive_space_credentials_for_conversation,
        },
        space_host_router, SpaceHostConfig, SpaceHostRuntime,
    },
    storage::DbPool,
};
use chrono::Utc;
use p256::{
    ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey},
    pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, LineEnding},
    SecretKey as P256Secret,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

fn is_clean_slate_dedicated_db(url: &str) -> bool {
    let Some((port, name)) = url
        .strip_prefix("postgresql://127.0.0.1:")
        .and_then(|rest| rest.split_once('/'))
    else {
        return false;
    };
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Some(suffix) = name.strip_prefix("clean_slate_fed_") else {
        return false;
    };
    suffix.len() == 32
        && suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone)]
struct CleanSlateServerState {
    pool: DbPool,
    runtime: Arc<ChatRuntime>,
    resolver: Arc<DsResolver>,
    outbound: Arc<OutboundClient>,
    service_auth: Option<Arc<ServiceAuthClient>>,
    space_host: Arc<SpaceHostRuntime>,
    service_did: String,
    signing_key: P256SigningKey,
    receipt_key: P256SigningKey,
}

impl FromRef<CleanSlateServerState> for DbPool {
    fn from_ref(state: &CleanSlateServerState) -> Self {
        state.pool.clone()
    }
}

impl FromRef<CleanSlateServerState> for Arc<ChatRuntime> {
    fn from_ref(state: &CleanSlateServerState) -> Self {
        state.runtime.clone()
    }
}

impl FromRef<CleanSlateServerState> for Arc<DsResolver> {
    fn from_ref(state: &CleanSlateServerState) -> Self {
        state.resolver.clone()
    }
}

impl FromRef<CleanSlateServerState> for Arc<OutboundClient> {
    fn from_ref(state: &CleanSlateServerState) -> Self {
        state.outbound.clone()
    }
}

impl FromRef<CleanSlateServerState> for Option<Arc<ServiceAuthClient>> {
    fn from_ref(state: &CleanSlateServerState) -> Self {
        state.service_auth.clone()
    }
}

fn p256_pem(sk: &P256SigningKey) -> String {
    let secret = P256Secret::from_slice(&sk.to_bytes()).expect("p256 secret");
    secret
        .to_pkcs8_pem(LineEnding::LF)
        .expect("pkcs8 pem")
        .to_string()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterDidInput {
    did: String,
    p256_jwk: Value,
    endpoint_url: String,
    #[serde(default)]
    did_document: Option<Value>,
    #[serde(default)]
    is_ds: bool,
}

async fn admin_register_did(
    State(state): State<CleanSlateServerState>,
    Json(input): Json<RegisterDidInput>,
) -> impl IntoResponse {
    let jwk: PublicKeyJwk = match serde_json::from_value(input.p256_jwk.clone()) {
        Ok(j) => j,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("bad jwk: {e}") })),
            );
        }
    };
    let x = URL_SAFE_NO_PAD
        .decode(input.p256_jwk["x"].as_str().unwrap_or_default())
        .unwrap_or_default();
    let y = URL_SAFE_NO_PAD
        .decode(input.p256_jwk["y"].as_str().unwrap_or_default())
        .unwrap_or_default();
    let mut uncompressed = vec![0x04_u8];
    uncompressed.extend_from_slice(&x);
    uncompressed.extend_from_slice(&y);
    let vk = match P256VerifyingKey::from_sec1_bytes(&uncompressed) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("bad p256 point: {e}") })),
            );
        }
    };

    if let Some(doc_val) = input.did_document {
        let doc: DidDocument = match serde_json::from_value(doc_val) {
            Ok(d) => d,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": format!("bad did_document: {e}") })),
                );
            }
        };
        cache_test_did_document(doc).await;
    } else {
        cache_test_did_document(DidDocument {
            id: input.did.clone(),
            verification_method: vec![VerificationMethod {
                id: format!("{}#atproto", input.did),
                key_type: "JsonWebKey2020".to_string(),
                controller: input.did.clone(),
                public_key_jwk: Some(jwk),
                public_key_multibase: None,
            }],
            service: Some(vec![Service {
                id: "#atproto_pds".to_string(),
                service_type: "AtprotoPersonalDataServer".to_string(),
                service_endpoint: input.endpoint_url.clone(),
            }]),
        })
        .await;
    }

    if input.is_ds {
        let _ = sqlx::query(
            "INSERT INTO federation_peers (ds_did, status) VALUES ($1, 'allow') \
             ON CONFLICT (ds_did) DO UPDATE SET status = 'allow'",
        )
        .bind(&input.did)
        .execute(&state.pool)
        .await;
    }

    state
        .space_host
        .register_test_did_endpoint(&input.did, &vk, &input.endpoint_url);
    register_test_space_relay_target(&input.did, &input.endpoint_url);

    (StatusCode::OK, Json(json!({ "registered": true })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterPushOverrideInput {
    canonical_https_url: String,
    loopback_http_url: String,
}

async fn admin_register_push_override(
    Json(input): Json<RegisterPushOverrideInput>,
) -> impl IntoResponse {
    register_test_gateway_override(&input.canonical_https_url, input.loopback_http_url);
    (StatusCode::OK, Json(json!({ "registered": true })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SeedGroupInput {
    direct: bool,
    recipient_service_did: String,
    archive_commitment_hex: Option<String>,
    extra_members: Vec<ExtraMemberSeed>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExtraMemberSeed {
    did: String,
    #[allow(dead_code)]
    role: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SeedGroupOutput {
    conversation_id: Uuid,
    space_uri: String,
    message_id: Uuid,
    sender_did: String,
    sender_device_id: Uuid,
    sender_key_id: String,
    sender_ed25519_seed_b64: String,
    recipient_did: String,
    recipient_device_id: Uuid,
    recipient_key_id: String,
    recipient_ed25519_seed_b64: String,
    signed_request: Value,
}

async fn admin_seed_group_fixture(
    State(state): State<CleanSlateServerState>,
    Json(input): Json<SeedGroupInput>,
) -> impl IntoResponse {
    let commitment = match input.archive_commitment_hex.as_deref() {
        Some(h) => match hex::decode(h) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                Some(arr)
            }
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "archiveCommitmentHex must be 32 bytes hex" })),
                )
                    .into_response();
            }
        },
        None => None,
    };

    // Unsealed: this DS's own relationship authority collects the traffic evidence on the
    // seeded sender's first send, as in production.
    let fixture = match seed_clean_slate_application_fixture_unsealed(
        &state.pool,
        input.direct,
        &input.recipient_service_did,
        commitment,
        None,
    )
    .await
    {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(error = %e, "clean-slate seed-group-fixture failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
                .into_response();
        }
    };

    for extra in &input.extra_members {
        if let Err(e) = seed_clean_slate_active_zero_leaf_member_for_test(
            &state.pool,
            fixture.conversation_id,
            &fixture.sender_did,
            &extra.did,
        )
        .await
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
                .into_response();
        }
    }

    let default_space_uri = format!(
        "at://{}/space/blue.catbird.labyrinth.conversation/{}-0",
        state.service_did, fixture.conversation_id
    );
    let _ = sqlx::query(
        "INSERT INTO chat.conversation_spaces ( \
             conversation_id, generation, space_uri, authority_did, created_at \
         ) VALUES ($1, 0, $2, $3, clock_timestamp()) \
         ON CONFLICT (conversation_id, generation) DO NOTHING",
    )
    .bind(fixture.conversation_id)
    .bind(&default_space_uri)
    .bind(&state.service_did)
    .execute(&state.pool)
    .await;

    let space_uri: String = sqlx::query_scalar(
        "SELECT space_uri FROM chat.conversation_spaces WHERE conversation_id = $1 AND generation = 0",
    )
    .bind(fixture.conversation_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(default_space_uri);

    (
        StatusCode::OK,
        Json(SeedGroupOutput {
            conversation_id: fixture.conversation_id,
            space_uri,
            message_id: fixture.message_id,
            sender_did: fixture.sender_did,
            sender_device_id: fixture.sender_device_id,
            sender_key_id: fixture.sender_key_id,
            sender_ed25519_seed_b64: STANDARD.encode(fixture.sender_ed25519_seed),
            recipient_did: fixture.recipient_did,
            recipient_device_id: fixture.recipient_device_id,
            recipient_key_id: fixture.recipient_key_id,
            recipient_ed25519_seed_b64: STANDARD.encode(fixture.recipient_ed25519_seed),
            signed_request: fixture.signed_request,
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoveMemberInput {
    conversation_id: Uuid,
    actor_did: String,
    target_did: String,
}

async fn admin_remove_member_d3(
    State(state): State<CleanSlateServerState>,
    Json(input): Json<RemoveMemberInput>,
) -> impl IntoResponse {
    // D3 / M-F01: Strictly enforce admin role on group member removal!
    let role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM chat.participants \
          WHERE conversation_id = $1 AND user_did = $2 AND current_membership = TRUE AND status = 'active'",
    )
    .bind(input.conversation_id)
    .bind(&input.actor_did)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    if role.as_deref() != Some("admin") {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "NotAuthorized",
                "message": "D3/M-F01: only active conversation admins may remove members"
            })),
        );
    }

    if let Err(e) = seed_clean_slate_remove_zero_leaf_member_for_test(
        &state.pool,
        input.conversation_id,
        &input.actor_did,
        &input.target_did,
    )
    .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        );
    }

    // M-F04: Post-commit fan-out of notifyCredentialRevoked to ALL writers' PDSes!
    let notified = revoke_inactive_space_credentials_for_conversation(
        &state.space_host,
        input.conversation_id,
        0,
    )
    .await
    .unwrap_or(0);

    (
        StatusCode::OK,
        Json(json!({
            "removed": true,
            "notifiedWriterHosts": notified
        })),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PromoteAdminInput {
    conversation_id: Uuid,
    actor_did: String,
    target_did: String,
}

async fn admin_promote_admin(
    State(state): State<CleanSlateServerState>,
    Json(input): Json<PromoteAdminInput>,
) -> impl IntoResponse {
    use chrono::SecondsFormat;
    use sha2::{Digest as _, Sha256};

    let now: chrono::DateTime<Utc> = sqlx::query_scalar(
        "SELECT GREATEST(clock_timestamp(), COALESCE(MAX(role_changed_at), clock_timestamp()) + INTERVAL '1 millisecond') \
           FROM chat.participants WHERE conversation_id = $1",
    )
    .bind(input.conversation_id)
    .fetch_one(&state.pool)
    .await
    .unwrap();

    let (gen, cur_sv, next_seq): (i64, i64, i64) = sqlx::query_as(
        "SELECT current_generation, current_state_version, next_entry_seq \
           FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(input.conversation_id)
    .fetch_one(&state.pool)
    .await
    .unwrap();

    let (admin_dev, admin_kid): (Uuid, String) = sqlx::query_as(
        "SELECT d.device_id, k.key_id \
           FROM chat.devices d \
           JOIN chat.device_keys k USING (user_did, device_id) \
          WHERE d.user_did = $1 AND d.status = 'active' LIMIT 1",
    )
    .bind(&input.actor_did)
    .fetch_one(&state.pool)
    .await
    .unwrap();

    let (group_id, epoch, gch, ct, snap, snap_sha, tree, tree_sha, leaf_count): (
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
    ) = sqlx::query_as(
        "SELECT group_id, epoch, group_context_hash, confirmation_tag, public_snapshot_bytes, \
                snapshot_sha256, tree_summary_bytes, tree_summary_sha256, leaf_count \
           FROM chat.generation_states \
          WHERE conversation_id = $1 AND generation = $2 AND state_version = $3",
    )
    .bind(input.conversation_id)
    .bind(gen)
    .bind(cur_sv)
    .fetch_one(&state.pool)
    .await
    .unwrap();

    let tid = Uuid::new_v4();
    let eid = Uuid::new_v4();
    let next_sv = cur_sv + 1;
    let req_bytes =
        format!("{{\"transitionId\":\"{tid}\",\"kind\":\"promoteAdmin\"}}").into_bytes();
    let req_digest: [u8; 32] = Sha256::digest(&req_bytes).into();
    let payload = serde_json::to_vec(&json!({
        "$type": "blue.catbird.chat.defs#policyEntry",
        "entryId": eid.to_string(),
        "conversationId": input.conversation_id.to_string(),
        "seq": next_seq,
        "receivedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
    }))
    .unwrap();
    let payload_sha: [u8; 32] = Sha256::digest(&payload).into();
    let server_fields = serde_json::to_vec(&json!({
        "entryId": eid.to_string(),
        "conversationId": input.conversation_id.to_string(),
        "seq": next_seq,
        "receivedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
    }))
    .unwrap();

    let mut tx = state.pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO chat.generation_states( \
             conversation_id, generation, state_version, group_id, epoch, group_context_hash, \
             confirmation_tag, lifecycle, state_kind, producing_transition_id, \
             public_snapshot_bytes, snapshot_sha256, tree_summary_bytes, tree_summary_sha256, \
             leaf_count, created_at \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,'active','policy',$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(input.conversation_id)
    .bind(gen)
    .bind(next_sv)
    .bind(&group_id)
    .bind(epoch)
    .bind(&gch)
    .bind(&ct)
    .bind(tid)
    .bind(&snap)
    .bind(&snap_sha)
    .bind(&tree)
    .bind(&tree_sha)
    .bind(leaf_count)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat.transitions( \
             transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id, \
             actor_auth_generation, actor_role, actor_device_status, signed_request_bytes, \
             unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature, \
             prior_generation, prior_state_version, next_generation, next_state_version, \
             entry_seq, accepted_at \
         ) VALUES ($1,$2,'policy',$3,$4,$5,1,'admin','active',$6,$6,$6,$7,$8,$9,$10,$9,$11,$12,$13)",
    )
    .bind(tid)
    .bind(input.conversation_id)
    .bind(&input.actor_did)
    .bind(admin_dev)
    .bind(&admin_kid)
    .bind(&req_bytes)
    .bind(req_digest.as_slice())
    .bind([0x77_u8; 64].as_slice())
    .bind(gen)
    .bind(cur_sv)
    .bind(next_sv)
    .bind(next_seq)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat.entries( \
             conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, \
             accepted_payload_sha256, signed_request_bytes, request_digest, signature, \
             server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, \
             actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at \
         ) VALUES ($1,$2,$3,'blue.catbird.chat.defs#policyEntry',$4,$5,$6,$7,$8,$9,$5,$10,$11,$12,1,$13,$14,$15,$16)",
    )
    .bind(input.conversation_id)
    .bind(next_seq)
    .bind(eid)
    .bind(&payload)
    .bind(payload_sha.as_slice())
    .bind(&req_bytes)
    .bind(req_digest.as_slice())
    .bind([0x77_u8; 64].as_slice())
    .bind(&server_fields)
    .bind(&input.actor_did)
    .bind(admin_dev)
    .bind(&admin_kid)
    .bind(gen)
    .bind(next_sv)
    .bind(tid)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "UPDATE chat.participants \
            SET role = 'admin', role_transition_id = $3, role_changed_at = $4 \
          WHERE conversation_id = $1 AND user_did = $2 AND current_membership = TRUE",
    )
    .bind(input.conversation_id)
    .bind(&input.target_did)
    .bind(tid)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "UPDATE chat.generations SET current_state_version = $3 WHERE conversation_id = $1 AND generation = $2",
    )
    .bind(input.conversation_id)
    .bind(gen)
    .bind(next_sv)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "UPDATE chat.conversations SET current_state_version = $2, next_entry_seq = $3 WHERE conversation_id = $1",
    )
    .bind(input.conversation_id)
    .bind(next_sv)
    .bind(next_seq + 1)
    .execute(&mut *tx)
    .await
    .unwrap();

    tx.commit().await.unwrap();
    (StatusCode::OK, Json(json!({ "promoted": true })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VoluntaryLeaveInput {
    conversation_id: Uuid,
    actor_did: String,
}

async fn admin_voluntary_leave(
    State(state): State<CleanSlateServerState>,
    Json(input): Json<VoluntaryLeaveInput>,
) -> impl IntoResponse {
    use chrono::SecondsFormat;
    use sha2::{Digest as _, Sha256};

    let now: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&state.pool)
        .await
        .unwrap();

    let (gen, cur_sv, next_seq): (i64, i64, i64) = sqlx::query_as(
        "SELECT current_generation, current_state_version, next_entry_seq \
           FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(input.conversation_id)
    .fetch_one(&state.pool)
    .await
    .unwrap();

    let (actor_dev, actor_kid): (Uuid, String) = sqlx::query_as(
        "SELECT d.device_id, k.key_id \
           FROM chat.devices d \
           JOIN chat.device_keys k USING (user_did, device_id) \
          WHERE d.user_did = $1 AND d.status = 'active' LIMIT 1",
    )
    .bind(&input.actor_did)
    .fetch_one(&state.pool)
    .await
    .unwrap();

    let actor_role: String = sqlx::query_scalar(
        "SELECT role FROM chat.participants \
          WHERE conversation_id = $1 AND user_did = $2 AND current_membership = TRUE",
    )
    .bind(input.conversation_id)
    .bind(&input.actor_did)
    .fetch_one(&state.pool)
    .await
    .unwrap();

    let n_actor_leaves: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat.member_devices \
          WHERE conversation_id = $1 AND generation = $2 AND user_did = $3 AND active = TRUE",
    )
    .bind(input.conversation_id)
    .bind(gen)
    .bind(&input.actor_did)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    let (group_id, epoch, gch, ct, snap, snap_sha, tree, tree_sha, leaf_count): (
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
    ) = sqlx::query_as(
        "SELECT group_id, epoch, group_context_hash, confirmation_tag, public_snapshot_bytes, \
                snapshot_sha256, tree_summary_bytes, tree_summary_sha256, leaf_count \
           FROM chat.generation_states \
          WHERE conversation_id = $1 AND generation = $2 AND state_version = $3",
    )
    .bind(input.conversation_id)
    .bind(gen)
    .bind(cur_sv)
    .fetch_one(&state.pool)
    .await
    .unwrap();

    let mut tx = state.pool.begin().await.unwrap();
    if n_actor_leaves == 0 {
        let rem_tid = Uuid::new_v4();
        let rem_eid = Uuid::new_v4();
        let rem_sv = cur_sv + 1;
        let rem_seq = next_seq;
        let req_bytes =
            format!("{{\"transitionId\":\"{rem_tid}\",\"kind\":\"leavePolicy\"}}").into_bytes();
        let req_digest: [u8; 32] = Sha256::digest(&req_bytes).into();
        let payload = serde_json::to_vec(&json!({
            "$type": "blue.catbird.chat.defs#zeroLeafLeaveEntry",
            "entryId": rem_eid.to_string(),
            "conversationId": input.conversation_id.to_string(),
            "seq": rem_seq,
            "receivedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        }))
        .unwrap();
        let payload_sha: [u8; 32] = Sha256::digest(&payload).into();
        let server_fields = serde_json::to_vec(&json!({
            "entryId": rem_eid.to_string(),
            "conversationId": input.conversation_id.to_string(),
            "seq": rem_seq,
            "receivedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        }))
        .unwrap();

        sqlx::query(
            "INSERT INTO chat.generation_states( \
                 conversation_id, generation, state_version, group_id, epoch, group_context_hash, \
                 confirmation_tag, lifecycle, state_kind, producing_transition_id, \
                 public_snapshot_bytes, snapshot_sha256, tree_summary_bytes, tree_summary_sha256, \
                 leaf_count, created_at \
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,'active','leavePolicy',$8,$9,$10,$11,$12,$13,$14)",
        )
        .bind(input.conversation_id)
        .bind(gen)
        .bind(rem_sv)
        .bind(&group_id)
        .bind(epoch)
        .bind(&gch)
        .bind(&ct)
        .bind(rem_tid)
        .bind(&snap)
        .bind(&snap_sha)
        .bind(&tree)
        .bind(&tree_sha)
        .bind(leaf_count)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO chat.transitions( \
                 transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id, \
                 actor_auth_generation, actor_role, actor_device_status, signed_request_bytes, \
                 unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature, \
                 prior_generation, prior_state_version, next_generation, next_state_version, \
                 entry_seq, accepted_at \
             ) VALUES ($1,$2,'leavePolicy',$3,$4,$5,1,$6,'active',$7,$7,$7,$8,$9,$10,$11,$10,$12,$13,$14)",
        )
        .bind(rem_tid)
        .bind(input.conversation_id)
        .bind(&input.actor_did)
        .bind(actor_dev)
        .bind(&actor_kid)
        .bind(&actor_role)
        .bind(&req_bytes)
        .bind(req_digest.as_slice())
        .bind([0x66_u8; 64].as_slice())
        .bind(gen)
        .bind(cur_sv)
        .bind(rem_sv)
        .bind(rem_seq)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO chat.entries( \
                 conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, \
                 accepted_payload_sha256, signed_request_bytes, request_digest, signature, \
                 server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, \
                 actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at \
             ) VALUES ($1,$2,$3,'blue.catbird.chat.defs#zeroLeafLeaveEntry',$4,$5,$6,$7,$8,$9,$5,$10,$11,$12,1,$13,$14,$15,$16)",
        )
        .bind(input.conversation_id)
        .bind(rem_seq)
        .bind(rem_eid)
        .bind(&payload)
        .bind(payload_sha.as_slice())
        .bind(&req_bytes)
        .bind(req_digest.as_slice())
        .bind([0x66_u8; 64].as_slice())
        .bind(&server_fields)
        .bind(&input.actor_did)
        .bind(actor_dev)
        .bind(&actor_kid)
        .bind(gen)
        .bind(rem_sv)
        .bind(rem_tid)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();

        sqlx::query(
            "UPDATE chat.participants \
                SET current_membership = FALSE, removing_transition_id = $3, removing_seq = $4, removed_at = $5 \
              WHERE conversation_id = $1 AND user_did = $2 AND current_membership = TRUE",
        )
        .bind(input.conversation_id)
        .bind(&input.actor_did)
        .bind(rem_tid)
        .bind(rem_seq)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();

        sqlx::query(
            "UPDATE chat.generations SET current_state_version = $3 WHERE conversation_id = $1 AND generation = $2",
        )
        .bind(input.conversation_id)
        .bind(gen)
        .bind(rem_sv)
        .execute(&mut *tx)
        .await
        .unwrap();

        sqlx::query(
            "UPDATE chat.conversations SET current_state_version = $2, next_entry_seq = $3 WHERE conversation_id = $1",
        )
        .bind(input.conversation_id)
        .bind(rem_sv)
        .bind(rem_seq + 1)
        .execute(&mut *tx)
        .await
        .unwrap();
    } else {
        // Leaf-bearing member voluntary leave: requester submits `leaveRequestEntry` and an active
        // co-admin fulfills `leaveCommit`, advancing epoch and closing the member's interval + leaf.
        let (fulfiller_did, fulfiller_dev, fulfiller_kid): (String, Uuid, String) = sqlx::query_as(
            "SELECT p.user_did, d.device_id, k.key_id \
               FROM chat.participants p \
               JOIN chat.devices d ON d.user_did = p.user_did AND d.status = 'active' \
               JOIN chat.device_keys k ON k.user_did = d.user_did AND k.device_id = d.device_id \
              WHERE p.conversation_id = $1 AND p.user_did <> $2 \
                AND p.current_membership = TRUE AND p.status = 'active' AND p.role = 'admin' \
              LIMIT 1",
        )
        .bind(input.conversation_id)
        .bind(&input.actor_did)
        .fetch_one(&mut *tx)
        .await
        .unwrap();

        let actor_leaves: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT leaf_period_id, device_id FROM chat.member_devices \
              WHERE conversation_id = $1 AND generation = $2 AND user_did = $3 AND active = TRUE",
        )
        .bind(input.conversation_id)
        .bind(gen)
        .bind(&input.actor_did)
        .fetch_all(&mut *tx)
        .await
        .unwrap();

        let (
            orig_tid,
            mv,
            ct_bytes,
            ct_sha,
            ct_size,
            auth_did,
            auth_dev,
            auth_kid,
            auth_pk,
            auth_gen,
            auth_seq,
            auth_role,
            auth_status,
        ): (
            Uuid,
            i64,
            Vec<u8>,
            Vec<u8>,
            i64,
            String,
            Uuid,
            String,
            Vec<u8>,
            i64,
            i64,
            String,
            String,
        ) = sqlx::query_as(
            "SELECT s.origin_transition_id, s.metadata_version, s.ciphertext, s.ciphertext_sha256, \
                    s.ciphertext_size, s.author_did, s.author_device_id, s.author_key_id, \
                    s.author_public_key, s.author_auth_generation, s.author_origin_seq, \
                    s.author_role, s.author_device_status \
               FROM chat.metadata_snapshots s \
               JOIN chat.transitions t ON t.transition_id = s.producing_transition_id \
              WHERE s.conversation_id = $1 AND s.generation = $2 \
              ORDER BY t.entry_seq DESC LIMIT 1",
        )
        .bind(input.conversation_id)
        .bind(gen)
        .fetch_one(&mut *tx)
        .await
        .unwrap();

        let req_seq = next_seq;
        let rem_seq = next_seq + 1;
        let rem_sv = cur_sv + 1;
        let next_epoch = epoch + 1;
        let next_leaves = (leaf_count - n_actor_leaves).max(1);
        let req_now = now;
        let commit_now = now + chrono::Duration::milliseconds(1);

        let leave_req_id = Uuid::new_v4();
        let leave_req_eid = Uuid::new_v4();
        let rem_tid = Uuid::new_v4();
        let rem_eid = Uuid::new_v4();
        let carry_msid = Uuid::new_v4();

        let leave_req_bytes =
            format!("{{\"leaveRequestId\":\"{leave_req_id}\",\"kind\":\"leaveRequest\"}}")
                .into_bytes();
        let leave_req_digest: [u8; 32] = Sha256::digest(&leave_req_bytes).into();
        let leave_req_payload = serde_json::to_vec(&json!({
            "$type": "blue.catbird.chat.defs#leaveRequestEntry",
            "entryId": leave_req_eid.to_string(),
            "conversationId": input.conversation_id.to_string(),
            "seq": req_seq,
            "receivedAt": req_now.to_rfc3339_opts(SecondsFormat::Millis, true),
        }))
        .unwrap();
        let leave_req_payload_sha: [u8; 32] = Sha256::digest(&leave_req_payload).into();
        let leave_req_sf = serde_json::to_vec(&json!({
            "entryId": leave_req_eid.to_string(),
            "conversationId": input.conversation_id.to_string(),
            "seq": req_seq,
            "receivedAt": req_now.to_rfc3339_opts(SecondsFormat::Millis, true),
        }))
        .unwrap();

        sqlx::query(
            "INSERT INTO chat.entries( \
                 conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, \
                 accepted_payload_sha256, signed_request_bytes, request_digest, signature, \
                 server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, \
                 actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at \
             ) VALUES ($1,$2,$3,'blue.catbird.chat.defs#leaveRequestEntry',$4,$5,$6,$7,$8,$9,$5,$10,$11,$12,1,NULL,NULL,NULL,$13)",
        )
        .bind(input.conversation_id)
        .bind(req_seq)
        .bind(leave_req_eid)
        .bind(&leave_req_payload)
        .bind(leave_req_payload_sha.as_slice())
        .bind(&leave_req_bytes)
        .bind(leave_req_digest.as_slice())
        .bind([0x65_u8; 64].as_slice())
        .bind(&leave_req_sf)
        .bind(&input.actor_did)
        .bind(actor_dev)
        .bind(&actor_kid)
        .bind(req_now)
        .execute(&mut *tx)
        .await
        .unwrap();

        let commit_req_bytes =
            format!("{{\"transitionId\":\"{rem_tid}\",\"kind\":\"leaveCommit\"}}").into_bytes();
        let commit_req_digest: [u8; 32] = Sha256::digest(&commit_req_bytes).into();
        let commit_payload = serde_json::to_vec(&json!({
            "$type": "blue.catbird.chat.defs#leaveCommitFulfillmentEntry",
            "entryId": rem_eid.to_string(),
            "conversationId": input.conversation_id.to_string(),
            "seq": rem_seq,
            "receivedAt": commit_now.to_rfc3339_opts(SecondsFormat::Millis, true),
        }))
        .unwrap();
        let commit_payload_sha: [u8; 32] = Sha256::digest(&commit_payload).into();
        let commit_sf = serde_json::to_vec(&json!({
            "entryId": rem_eid.to_string(),
            "conversationId": input.conversation_id.to_string(),
            "seq": rem_seq,
            "receivedAt": commit_now.to_rfc3339_opts(SecondsFormat::Millis, true),
        }))
        .unwrap();

        sqlx::query(
            "INSERT INTO chat.leave_requests( \
                 leave_request_id, conversation_id, requester_did, requester_device_id, \
                 requester_key_id, requester_auth_generation, prior_generation, prior_state_version, \
                 prior_group_id, prior_epoch, prior_group_context_hash, prior_confirmation_tag, \
                 status, signed_request_bytes, signing_transcript_bytes, request_digest, signature, \
                 terminal_request_digest, terminal_transition_id, received_at, expires_at, terminal_at \
             ) VALUES ($1,$2,$3,$4,$5,1,$6,$7,$8,$9,$10,$11,'fulfilled',$12,$12,$13,$14,$15,$16,$17,$18,$19)",
        )
        .bind(leave_req_id)
        .bind(input.conversation_id)
        .bind(&input.actor_did)
        .bind(actor_dev)
        .bind(&actor_kid)
        .bind(gen)
        .bind(cur_sv)
        .bind(&group_id)
        .bind(epoch)
        .bind(&gch)
        .bind(&ct)
        .bind(&leave_req_bytes)
        .bind(leave_req_digest.as_slice())
        .bind([0x65_u8; 64].as_slice())
        .bind(commit_req_digest.as_slice())
        .bind(rem_tid)
        .bind(req_now)
        .bind(req_now + chrono::Duration::hours(24))
        .bind(commit_now)
        .execute(&mut *tx)
        .await
        .unwrap();

        let next_gch: [u8; 32] = Sha256::digest(rem_tid.as_bytes()).into();
        let next_ct: [u8; 32] = Sha256::digest(rem_eid.as_bytes()).into();

        sqlx::query(
            "INSERT INTO chat.generation_states( \
                 conversation_id, generation, state_version, group_id, epoch, group_context_hash, \
                 confirmation_tag, lifecycle, state_kind, producing_transition_id, \
                 public_snapshot_bytes, snapshot_sha256, tree_summary_bytes, tree_summary_sha256, \
                 leaf_count, created_at \
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,'active','commit',$8,$9,$10,$11,$12,$13,$14)",
        )
        .bind(input.conversation_id)
        .bind(gen)
        .bind(rem_sv)
        .bind(&group_id)
        .bind(next_epoch)
        .bind(next_gch.as_slice())
        .bind(next_ct.as_slice())
        .bind(rem_tid)
        .bind(&snap)
        .bind(&snap_sha)
        .bind(&tree)
        .bind(&tree_sha)
        .bind(next_leaves)
        .bind(commit_now)
        .execute(&mut *tx)
        .await
        .unwrap();

        let mut carry_nonce = [0u8; 12];
        carry_nonce[..8].copy_from_slice(&(mv as u64).to_be_bytes());
        carry_nonce[8..12].copy_from_slice(&(rem_sv as u32).to_be_bytes());

        sqlx::query(
            "INSERT INTO chat.metadata_snapshots( \
                 metadata_snapshot_id, conversation_id, generation, state_version, group_id, epoch, \
                 group_context_hash, confirmation_tag, producing_transition_id, origin_transition_id, \
                 metadata_version, nonce, ciphertext, ciphertext_sha256, ciphertext_size, \
                 author_did, author_device_id, author_key_id, author_public_key, \
                 author_auth_generation, author_origin_seq, author_role, author_device_status, created_at \
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)",
        )
        .bind(carry_msid)
        .bind(input.conversation_id)
        .bind(gen)
        .bind(rem_sv)
        .bind(&group_id)
        .bind(next_epoch)
        .bind(next_gch.as_slice())
        .bind(next_ct.as_slice())
        .bind(rem_tid)
        .bind(orig_tid)
        .bind(mv)
        .bind(carry_nonce.as_slice())
        .bind(&ct_bytes)
        .bind(&ct_sha)
        .bind(ct_size)
        .bind(&auth_did)
        .bind(auth_dev)
        .bind(&auth_kid)
        .bind(&auth_pk)
        .bind(auth_gen)
        .bind(auth_seq)
        .bind(&auth_role)
        .bind(&auth_status)
        .bind(commit_now)
        .execute(&mut *tx)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO chat.transitions( \
                 transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id, \
                 actor_auth_generation, actor_role, actor_device_status, signed_request_bytes, \
                 unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature, \
                 prior_generation, prior_state_version, next_generation, next_state_version, \
                 metadata_snapshot_id, entry_seq, accepted_at \
             ) VALUES ($1,$2,'leaveCommit',$3,$4,$5,1,'admin','active',$6,$6,$6,$7,$8,$9,$10,$9,$11,$12,$13,$14)",
        )
        .bind(rem_tid)
        .bind(input.conversation_id)
        .bind(&fulfiller_did)
        .bind(fulfiller_dev)
        .bind(&fulfiller_kid)
        .bind(&commit_req_bytes)
        .bind(commit_req_digest.as_slice())
        .bind([0x66_u8; 64].as_slice())
        .bind(gen)
        .bind(cur_sv)
        .bind(rem_sv)
        .bind(carry_msid)
        .bind(rem_seq)
        .bind(commit_now)
        .execute(&mut *tx)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO chat.entries( \
                 conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, \
                 accepted_payload_sha256, signed_request_bytes, request_digest, signature, \
                 server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, \
                 actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at \
             ) VALUES ($1,$2,$3,'blue.catbird.chat.defs#leaveCommitFulfillmentEntry',$4,$5,$6,$7,$8,$9,$5,$10,$11,$12,1,$13,$14,$15,$16)",
        )
        .bind(input.conversation_id)
        .bind(rem_seq)
        .bind(rem_eid)
        .bind(&commit_payload)
        .bind(commit_payload_sha.as_slice())
        .bind(&commit_req_bytes)
        .bind(commit_req_digest.as_slice())
        .bind([0x66_u8; 64].as_slice())
        .bind(&commit_sf)
        .bind(&fulfiller_did)
        .bind(fulfiller_dev)
        .bind(&fulfiller_kid)
        .bind(gen)
        .bind(rem_sv)
        .bind(rem_tid)
        .bind(commit_now)
        .execute(&mut *tx)
        .await
        .unwrap();

        for (leaf_period_id, dev_id) in &actor_leaves {
            sqlx::query(
                "INSERT INTO chat.entry_recipients(conversation_id, seq, user_did, device_id, entitlement_kind) \
                 VALUES ($1,$2,$3,$4,'intervalClose')",
            )
            .bind(input.conversation_id)
            .bind(rem_seq)
            .bind(&input.actor_did)
            .bind(dev_id)
            .execute(&mut *tx)
            .await
            .unwrap();

            sqlx::query(
                "UPDATE chat.application_intervals \
                    SET terminal_seq = $4, closing_state_version = $5, closing_transition_id = $6, \
                        closing_outer_entry_fingerprint = $7, closing_kind = 'remove', \
                        closing_leaf_period_id = $8, removed_at = $9 \
                  WHERE conversation_id = $1 AND recipient_did = $2 AND recipient_device_id = $3 \
                    AND terminal_seq IS NULL",
            )
            .bind(input.conversation_id)
            .bind(&input.actor_did)
            .bind(dev_id)
            .bind(rem_seq)
            .bind(rem_sv)
            .bind(rem_tid)
            .bind(commit_payload_sha.as_slice())
            .bind(leaf_period_id)
            .bind(commit_now)
            .execute(&mut *tx)
            .await
            .unwrap();

            sqlx::query(
                "UPDATE chat.member_devices \
                    SET active = FALSE, removed_state_version = $2, removed_transition_id = $3, \
                        removed_seq = $4, removed_at = $5 \
                  WHERE leaf_period_id = $1",
            )
            .bind(leaf_period_id)
            .bind(rem_sv)
            .bind(rem_tid)
            .bind(rem_seq)
            .bind(commit_now)
            .execute(&mut *tx)
            .await
            .unwrap();
        }

        sqlx::query(
            "UPDATE chat.participants \
                SET current_membership = FALSE, removing_transition_id = $3, removing_seq = $4, removed_at = $5 \
              WHERE conversation_id = $1 AND user_did = $2 AND current_membership = TRUE",
        )
        .bind(input.conversation_id)
        .bind(&input.actor_did)
        .bind(rem_tid)
        .bind(rem_seq)
        .bind(commit_now)
        .execute(&mut *tx)
        .await
        .unwrap();

        sqlx::query(
            "UPDATE chat.generations SET current_state_version = $3 WHERE conversation_id = $1 AND generation = $2",
        )
        .bind(input.conversation_id)
        .bind(gen)
        .bind(rem_sv)
        .execute(&mut *tx)
        .await
        .unwrap();

        sqlx::query(
            "UPDATE chat.conversations SET current_state_version = $2, next_entry_seq = $3 WHERE conversation_id = $1",
        )
        .bind(input.conversation_id)
        .bind(rem_sv)
        .bind(rem_seq + 1)
        .execute(&mut *tx)
        .await
        .unwrap();
    }

    if let Err(e) = tx.commit().await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        );
    }

    let notified = revoke_inactive_space_credentials_for_conversation(
        &state.space_host,
        input.conversation_id,
        0,
    )
    .await
    .unwrap_or(0);
    (
        StatusCode::OK,
        Json(json!({ "left": true, "notifiedWriterHosts": notified })),
    )
}

async fn admin_c33_expire_and_recheck(
    State(state): State<CleanSlateServerState>,
) -> impl IntoResponse {
    let doc = build_direct_request_receipt_did_document(
        &state.service_did,
        state.receipt_key.verifying_key(),
    );
    let signer = match DirectRequestReceiptSigner::configured(
        &p256_pem(&state.receipt_key),
        &p256_pem(&state.signing_key),
        &serde_json::to_string(&doc).unwrap(),
    ) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("receipt signer: {e}") })),
            );
        }
    };

    let seeded = match seed_clean_slate_expired_direct_request_fixture(&state.pool, &signer).await {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("seed c33: {e}") })),
            );
        }
    };

    // Pending C33 target MUST NOT appear as an active writer before acceptance!
    let pending_active_writers: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat.participants WHERE conversation_id = $1 AND user_did = $2 AND status = 'active'",
    )
    .bind(seeded.conversation_id)
    .bind(&seeded.recipient_did)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(-1);

    let swept = match sweep_expired_published_direct_requests_for_test(&state.pool, &signer).await {
        Ok(n) => n,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("sweep c33: {e}") })),
            );
        }
    };

    let (convo_lifecycle, gen_lifecycle, consent): (String, String, String) = sqlx::query_as(
        "SELECT c.lifecycle, g.lifecycle, l.consent \
           FROM chat.conversations c \
           JOIN chat.generations g ON g.conversation_id = c.conversation_id AND g.generation = c.current_generation \
           JOIN chat.direct_request_lifecycle l ON l.conversation_id = c.conversation_id \
          WHERE c.conversation_id = $1",
    )
    .bind(seeded.conversation_id)
    .fetch_one(&state.pool)
    .await
    .unwrap();

    let mut tx = state.pool.begin().await.unwrap();
    let conflict = check_pair_owner_fence(
        &mut tx,
        &seeded.actor_did,
        &seeded.recipient_did,
        Uuid::new_v4(),
        Some(&state.service_did),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    (
        StatusCode::OK,
        Json(json!({
            "conversationId": seeded.conversation_id,
            "actorDid": seeded.actor_did,
            "recipientDid": seeded.recipient_did,
            "pendingActiveWriters": pending_active_writers,
            "sweptCount": swept,
            "conversationLifecycle": convo_lifecycle,
            "generationLifecycle": gen_lifecycle,
            "consent": consent,
            "reRequestConflict": conflict.is_some(),
        })),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetMetadataSnapshotInput {
    conversation_id: Uuid,
    epoch: i64,
    ciphertext_b64: String,
    actor_did: String,
    actor_device_id: Uuid,
    avatar_blob_id: Option<Uuid>,
    avatar_sha256_b64: Option<String>,
    avatar_size: Option<i64>,
}

async fn admin_set_metadata_snapshot(
    State(state): State<CleanSlateServerState>,
    Json(input): Json<SetMetadataSnapshotInput>,
) -> impl IntoResponse {
    use chrono::SecondsFormat;
    use sha2::{Digest as _, Sha256};

    let bytes = match STANDARD.decode(&input.ciphertext_b64) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            );
        }
    };
    let sha = Sha256::digest(&bytes).to_vec();

    let Ok((gen, cur_sv, next_seq)) = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT current_generation, current_state_version, next_entry_seq \
           FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(input.conversation_id)
    .fetch_one(&state.pool)
    .await
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "conversation not found" })),
        );
    };

    let Ok((group_id, cur_epoch, gch, ct, snap, snap_sha, tree, tree_sha, leaf_count)) =
        sqlx::query_as::<
            _,
            (
                Vec<u8>,
                i64,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                i64,
            ),
        >(
            "SELECT group_id, epoch, group_context_hash, confirmation_tag, public_snapshot_bytes, \
                    snapshot_sha256, tree_summary_bytes, tree_summary_sha256, leaf_count \
               FROM chat.generation_states \
              WHERE conversation_id = $1 AND generation = $2 AND state_version = $3",
        )
        .bind(input.conversation_id)
        .bind(gen)
        .bind(cur_sv)
        .fetch_one(&state.pool)
        .await
    else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "missing current generation_state" })),
        );
    };

    let Ok((key_id, pub_key)) = sqlx::query_as::<_, (String, Vec<u8>)>(
        "SELECT key_id, signing_public_key FROM chat.device_keys \
          WHERE user_did = $1 AND device_id = $2 LIMIT 1",
    )
    .bind(&input.actor_did)
    .bind(input.actor_device_id)
    .fetch_one(&state.pool)
    .await
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "actor device_key not found" })),
        );
    };

    if bytes.len() > 16_384 {
        // Prove DB CHECK constraint `metadata_snapshots_ciphertext_size_check` rejects > 16 KiB directly!
        let mut tx = state.pool.begin().await.unwrap();
        let tid = Uuid::new_v4();
        let msid = Uuid::new_v4();
        let db_err = sqlx::query(
            "INSERT INTO chat.metadata_snapshots( \
                 metadata_snapshot_id, conversation_id, generation, state_version, group_id, epoch, \
                 group_context_hash, confirmation_tag, producing_transition_id, origin_transition_id, \
                 metadata_version, nonce, ciphertext, ciphertext_sha256, ciphertext_size, \
                 author_did, author_device_id, author_key_id, author_public_key, \
                 author_auth_generation, author_origin_seq, author_role, author_device_status, created_at \
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,99,$10,$11,$12,$13,$14,$15,$16,$17,1,1,'admin','active',clock_timestamp())",
        )
        .bind(msid)
        .bind(input.conversation_id)
        .bind(gen)
        .bind(cur_sv + 1)
        .bind(&group_id)
        .bind(cur_epoch)
        .bind(&gch)
        .bind(&ct)
        .bind(tid)
        .bind(vec![0x99_u8; 12])
        .bind(&bytes)
        .bind(&sha)
        .bind(bytes.len() as i64)
        .bind(&input.actor_did)
        .bind(input.actor_device_id)
        .bind(&key_id)
        .bind(&pub_key)
        .execute(&mut *tx)
        .await;
        let rejected_by_check = db_err.is_err();
        let _ = tx.rollback().await;
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({
                "error": "MetadataTooLarge",
                "rejectedByDbConstraint": rejected_by_check,
                "maxBytes": 16384
            })),
        );
    }

    let prior_mv: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(metadata_version), 0) FROM chat.metadata_snapshots \
          WHERE conversation_id = $1 AND generation = $2",
    )
    .bind(input.conversation_id)
    .bind(gen)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(1);

    let next_mv = prior_mv + 1;
    let next_sv = cur_sv + 1;
    let tid = Uuid::new_v4();
    let eid = Uuid::new_v4();
    let msid = Uuid::new_v4();
    let now: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&state.pool)
        .await
        .unwrap();

    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&(next_mv as u64).to_be_bytes());
    nonce[8..12].copy_from_slice(&(next_sv as u32).to_be_bytes());

    let avatar_sha = input
        .avatar_sha256_b64
        .as_deref()
        .and_then(|s| STANDARD.decode(s).ok());
    let has_avatar = input.avatar_blob_id.is_some();

    let req_bytes = format!("{{\"transitionId\":\"{tid}\",\"kind\":\"metadata\"}}").into_bytes();
    let req_digest: [u8; 32] = Sha256::digest(&req_bytes).into();
    let entry_payload = serde_json::to_vec(&json!({
        "$type": "blue.catbird.chat.defs#metadataEntry",
        "entryId": eid.to_string(),
        "conversationId": input.conversation_id.to_string(),
        "seq": next_seq,
        "receivedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
    }))
    .unwrap();
    let entry_payload_sha: [u8; 32] = Sha256::digest(&entry_payload).into();
    let server_fields = serde_json::to_vec(&json!({
        "entryId": eid.to_string(),
        "conversationId": input.conversation_id.to_string(),
        "seq": next_seq,
        "receivedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
    }))
    .unwrap();

    let mut tx = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            );
        }
    };

    let s1 = sqlx::query(
        "INSERT INTO chat.generation_states( \
             conversation_id, generation, state_version, group_id, epoch, group_context_hash, \
             confirmation_tag, lifecycle, state_kind, producing_transition_id, \
             public_snapshot_bytes, snapshot_sha256, tree_summary_bytes, tree_summary_sha256, \
             leaf_count, created_at \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,'active','metadata',$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(input.conversation_id)
    .bind(gen)
    .bind(next_sv)
    .bind(&group_id)
    .bind(cur_epoch.max(input.epoch))
    .bind(&gch)
    .bind(&ct)
    .bind(tid)
    .bind(&snap)
    .bind(&snap_sha)
    .bind(&tree)
    .bind(&tree_sha)
    .bind(leaf_count)
    .bind(now)
    .execute(&mut *tx)
    .await;

    let s2 = sqlx::query(
        "INSERT INTO chat.transitions( \
             transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id, \
             actor_auth_generation, actor_role, actor_device_status, signed_request_bytes, \
             unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature, \
             prior_generation, prior_state_version, next_generation, next_state_version, \
             metadata_snapshot_id, entry_seq, accepted_at \
         ) VALUES ($1,$2,'metadata',$3,$4,$5,1,'admin','active',$6,$6,$6,$7,$8,$9,$10,$9,$11,$12,$13,$14)",
    )
    .bind(tid)
    .bind(input.conversation_id)
    .bind(&input.actor_did)
    .bind(input.actor_device_id)
    .bind(&key_id)
    .bind(&req_bytes)
    .bind(req_digest.as_slice())
    .bind([0x44_u8; 64].as_slice())
    .bind(gen)
    .bind(cur_sv)
    .bind(next_sv)
    .bind(msid)
    .bind(next_seq)
    .bind(now)
    .execute(&mut *tx)
    .await;

    let s3 = sqlx::query(
        "INSERT INTO chat.entries( \
             conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, \
             accepted_payload_sha256, signed_request_bytes, request_digest, signature, \
             server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, \
             actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at \
         ) VALUES ($1,$2,$3,'blue.catbird.chat.defs#metadataEntry',$4,$5,$6,$7,$8,$9,$5,$10,$11,$12,1,$13,$14,$15,$16)",
    )
    .bind(input.conversation_id)
    .bind(next_seq)
    .bind(eid)
    .bind(&entry_payload)
    .bind(entry_payload_sha.as_slice())
    .bind(&req_bytes)
    .bind(req_digest.as_slice())
    .bind([0x44_u8; 64].as_slice())
    .bind(&server_fields)
    .bind(&input.actor_did)
    .bind(input.actor_device_id)
    .bind(&key_id)
    .bind(gen)
    .bind(next_sv)
    .bind(tid)
    .bind(now)
    .execute(&mut *tx)
    .await;

    let s4 = sqlx::query(
        "INSERT INTO chat.metadata_snapshots( \
             metadata_snapshot_id, conversation_id, generation, state_version, group_id, epoch, \
             group_context_hash, confirmation_tag, producing_transition_id, origin_transition_id, \
             metadata_version, nonce, ciphertext, ciphertext_sha256, ciphertext_size, \
             avatar_blob_id, avatar_ciphertext_sha256, avatar_ciphertext_size, avatar_purpose, \
             avatar_binding_origin_transition_id, avatar_binding_metadata_version, \
             avatar_binding_owner_did, avatar_binding_owner_device_id, \
             author_did, author_device_id, author_key_id, author_public_key, \
             author_auth_generation, author_origin_seq, author_role, author_device_status, created_at \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$11,$12,$13,$14, \
                   $15,$16,$17,$18,$19,$20,$21,$22, \
                   $23,$24,$25,$26,1,$27,'admin','active',$28)",
    )
    .bind(msid)
    .bind(input.conversation_id)
    .bind(gen)
    .bind(next_sv)
    .bind(&group_id)
    .bind(cur_epoch.max(input.epoch))
    .bind(&gch)
    .bind(&ct)
    .bind(tid)
    .bind(next_mv)
    .bind(nonce.as_slice())
    .bind(&bytes)
    .bind(&sha)
    .bind(bytes.len() as i64)
    .bind(input.avatar_blob_id)
    .bind(avatar_sha)
    .bind(input.avatar_size)
    .bind(has_avatar.then_some("metadata"))
    .bind(has_avatar.then_some(tid))
    .bind(has_avatar.then_some(next_mv))
    .bind(has_avatar.then(|| input.actor_did.clone()))
    .bind(has_avatar.then_some(input.actor_device_id))
    .bind(&input.actor_did)
    .bind(input.actor_device_id)
    .bind(&key_id)
    .bind(&pub_key)
    .bind(next_seq)
    .bind(now)
    .execute(&mut *tx)
    .await;

    let s5 = sqlx::query(
        "UPDATE chat.generations SET current_state_version = $3 WHERE conversation_id = $1 AND generation = $2",
    )
    .bind(input.conversation_id)
    .bind(gen)
    .bind(next_sv)
    .execute(&mut *tx)
    .await;

    let s6 = sqlx::query(
        "UPDATE chat.conversations SET current_state_version = $2, next_entry_seq = $3 WHERE conversation_id = $1",
    )
    .bind(input.conversation_id)
    .bind(next_sv)
    .bind(next_seq + 1)
    .execute(&mut *tx)
    .await;

    for step in [s1, s2, s3, s4, s5, s6] {
        if let Err(e) = step {
            let _ = tx.rollback().await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            );
        }
    }

    match tx.commit().await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "stored": true,
                "metadataVersion": next_mv,
                "byteLen": bytes.len(),
                "sha256B64": STANDARD.encode(&sha),
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

async fn admin_get_metadata_snapshot(
    State(state): State<CleanSlateServerState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let Some(cid) = q
        .get("conversationId")
        .and_then(|s| Uuid::parse_str(s).ok())
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "missing conversationId" })),
        );
    };
    let row: Option<(i64, i64, Vec<u8>, String, Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT epoch, metadata_version, ciphertext, author_did, avatar_blob_id, avatar_binding_owner_did \
           FROM chat.metadata_snapshots \
          WHERE conversation_id = $1 ORDER BY state_version DESC LIMIT 1",
    )
    .bind(cid)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    match row {
        Some((epoch, mv, ct, author_did, avatar_blob_id, avatar_owner_did)) => (
            StatusCode::OK,
            Json(json!({
                "epoch": epoch,
                "metadataVersion": mv,
                "ciphertextB64": STANDARD.encode(ct),
                "actorDid": author_did,
                "avatarBlobId": avatar_blob_id,
                "avatarOwnerDid": avatar_owner_did,
            })),
        ),
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": "NotFound" }))),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CloseWipeInput {
    conversation_id: Uuid,
}

async fn admin_close_and_wipe_conversation(
    State(state): State<CleanSlateServerState>,
    Json(input): Json<CloseWipeInput>,
) -> impl IntoResponse {
    let cur_lifecycle: Option<String> =
        sqlx::query_scalar("SELECT lifecycle FROM chat.conversations WHERE conversation_id = $1")
            .bind(input.conversation_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    let refused_while_active = if cur_lifecycle.as_deref() == Some("active") {
        sqlx::query_scalar::<_, bool>("SELECT chat.wipe_closed_conversation_operational_rows($1)")
            .bind(input.conversation_id)
            .fetch_one(&state.pool)
            .await
            .is_err()
    } else {
        true
    };

    // Fan out notifySpaceDeleted to every writer's PDS before operational rows are wiped!
    let notified =
        fan_out_space_deleted_for_conversation(&state.space_host, input.conversation_id, 0)
            .await
            .unwrap_or(0);

    // Transition active conversation to `superseded` (satisfying `conversations_close_shape_check`)
    // and execute `chat.wipe_closed_conversation_operational_rows` atomically!
    let mut tx = state.pool.begin().await.unwrap();
    if cur_lifecycle.as_deref() == Some("active") {
        let close_tid = Uuid::new_v4();
        sqlx::query(
            "UPDATE chat.conversations \
                SET lifecycle = 'superseded', \
                    close_transition_id = $2, \
                    close_generation = current_generation, \
                    close_state_version = current_state_version + 1, \
                    close_seq = next_entry_seq, \
                    closed_at = clock_timestamp() \
              WHERE conversation_id = $1",
        )
        .bind(input.conversation_id)
        .bind(close_tid)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    let wiped: bool =
        match sqlx::query_scalar("SELECT chat.wipe_closed_conversation_operational_rows($1)")
            .bind(input.conversation_id)
            .fetch_one(&mut *tx)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                eprintln!("wipe_closed_conversation_operational_rows SQL error: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": e.to_string() })),
                );
            }
        };
    if let Err(e) = tx.commit().await {
        eprintln!("wipe commit SQL error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        );
    }

    (
        StatusCode::OK,
        Json(json!({
            "refusedWhileActive": refused_while_active,
            "notifiedSpaceDeleted": notified,
            "wiped": wiped,
        })),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteAccountInput {
    did: String,
}

async fn admin_delete_account(
    State(state): State<CleanSlateServerState>,
    Json(input): Json<DeleteAccountInput>,
) -> impl IntoResponse {
    match delete_account_data_with_conversations(
        &state.pool,
        &input.did,
        Utc::now(),
        state.runtime.i13_receipt_signer(),
    )
    .await
    {
        Ok(sequenced) => (
            StatusCode::OK,
            Json(json!({ "deleted": true, "sequencedAccountDeletedEntries": sequenced })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignMutationInput {
    body: Value,
    ed25519_seed_b64: String,
}

async fn admin_sign_mutation(Json(input): Json<SignMutationInput>) -> impl IntoResponse {
    let Ok(seed_vec) = STANDARD.decode(&input.ed25519_seed_b64) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid base64 seed" })),
        );
    };
    let Ok(seed_arr): Result<[u8; 32], _> = seed_vec.try_into() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "ed25519 seed must be 32 bytes" })),
        );
    };
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed_arr);
    match sign_mutation_json_for_test(&input.body, &sk) {
        Ok(signed) => (StatusCode::OK, Json(signed)),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddZeroLeafMemberInput {
    conversation_id: Uuid,
    admin_did: String,
    member_did: String,
}

async fn admin_add_zero_leaf_member(
    State(state): State<CleanSlateServerState>,
    Json(input): Json<AddZeroLeafMemberInput>,
) -> impl IntoResponse {
    match seed_clean_slate_active_zero_leaf_member_for_test(
        &state.pool,
        input.conversation_id,
        &input.admin_did,
        &input.member_did,
    )
    .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({ "added": true }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    anyhow::ensure!(
        std::env::var("APP_ENV").as_deref() == Ok("test"),
        "clean_slate_federation_fixture requires APP_ENV=test"
    );

    let database_url =
        std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL is required")?;
    anyhow::ensure!(
        is_clean_slate_dedicated_db(&database_url),
        "clean_slate_federation_fixture refuses non-dedicated database URL {database_url}"
    );

    let service_did = std::env::var("SERVICE_DID").context("SERVICE_DID is required")?;
    let listen_str = std::env::var("CLEAN_SLATE_LISTEN").unwrap_or_else(|_| "127.0.0.1:0".into());
    let listen_addr: std::net::SocketAddr =
        listen_str.parse().context("parse CLEAN_SLATE_LISTEN")?;
    anyhow::ensure!(
        listen_addr.ip().is_loopback(),
        "CLEAN_SLATE_LISTEN must be loopback"
    );

    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("bind {listen_addr}"))?;
    let bound_addr = listener.local_addr()?;
    let base_url = format!("http://{bound_addr}");
    std::env::set_var("SELF_ENDPOINT", &base_url);

    let signing_pem = std::env::var("SIGNING_KEY_PEM").context("SIGNING_KEY_PEM is required")?;
    let signing_key =
        P256SigningKey::from_pkcs8_pem(&signing_pem).context("decode SIGNING_KEY_PEM")?;
    let receipt_pem =
        std::env::var("RECEIPT_SIGNING_KEY_PEM").unwrap_or_else(|_| signing_pem.clone());
    let receipt_key =
        P256SigningKey::from_pkcs8_pem(&receipt_pem).context("decode RECEIPT_SIGNING_KEY_PEM")?;

    let s2s_secret = std::env::var("FEDERATION_GROUP_RELAY_HMAC_SECRET")
        .unwrap_or_else(|_| "clean-slate-federation-s2s-secret-32b!".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(16)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(&database_url)
        .await
        .context("connect dedicated clean-slate database")?;

    // Run full production migration catalog on fresh database!
    {
        let mut conn = pool.acquire().await.context("acquire migration conn")?;
        sqlx::query(
            "SET chat.operation_claim_activation_approved = 'handlers-and-legacy-apis-sealed'",
        )
        .execute(&mut *conn)
        .await
        .context("set operation_claim_activation_approved")?;
        sqlx::migrate!("./migrations")
            .run(&mut *conn)
            .await
            .context("run clean-slate production migrations")?;
        sqlx::query("RESET chat.operation_claim_activation_approved")
            .execute(&mut *conn)
            .await
            .context("reset operation_claim_activation_approved")?;
    }

    // Initialize protocol_instances + event_retention + service_auth_admissions fence
    let cursor_key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(vec![0x51_u8; 32])
        .fetch_one(&pool)
        .await
        .context("compute cursor_key_id")?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS chat.service_auth_admissions (
            admission_id UUID PRIMARY KEY,
            issuer_did TEXT NOT NULL,
            endpoint_nsid TEXT NOT NULL,
            device_id UUID NOT NULL,
            jti_sha256 BYTEA NOT NULL,
            token_sha256 BYTEA NOT NULL,
            token_iat TIMESTAMPTZ NOT NULL,
            token_exp TIMESTAMPTZ NOT NULL,
            consumed_at TIMESTAMPTZ NOT NULL,
            CONSTRAINT service_auth_admissions_jti_once UNIQUE (issuer_did, jti_sha256)
        )",
    )
    .execute(&pool)
    .await
    .context("ensure chat.service_auth_admissions")?;
    sqlx::query(
        "INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) \
         VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(&cursor_key_id)
    .execute(&pool)
    .await
    .context("insert chat.protocol_instances")?;
    let instance_id: Uuid = sqlx::query_scalar(
        "SELECT protocol_instance_id FROM chat.protocol_instances WHERE singleton=TRUE",
    )
    .fetch_one(&pool)
    .await
    .context("read protocol_instance_id")?;
    sqlx::query(
        "INSERT INTO chat.event_retention(protocol_instance_id,retained_floor,updated_at) \
         VALUES($1,0,clock_timestamp()) ON CONFLICT DO NOTHING",
    )
    .bind(instance_id)
    .execute(&pool)
    .await
    .context("insert chat.event_retention")?;

    let receipt_doc =
        build_direct_request_receipt_did_document(&service_did, receipt_key.verifying_key());

    std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    std::env::set_var("CHAT_DIRECT_REQUESTS_ENABLED", "1");
    std::env::set_var("CHAT_REQUEST_RECEIPT_SIGNING_KEY_PEM", &receipt_pem);
    std::env::set_var(
        "CHAT_REQUEST_RECEIPT_DID_DOCUMENT_JSON",
        serde_json::to_string(&receipt_doc).context("encode receipt DID doc")?,
    );
    std::env::set_var("CHAT_CURSOR_KEY_ID", &cursor_key_id);
    std::env::set_var(
        "CHAT_CURSOR_SEALING_SECRET",
        URL_SAFE_NO_PAD.encode([0xA5_u8; 32]),
    );
    std::env::set_var(
        "CHAT_SUBSCRIPTION_ENDPOINT",
        "wss://chat.federation.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents",
    );
    std::env::set_var("FEDERATION_TEST_ALLOW_ALL_RELATIONSHIPS", "true");
    std::env::set_var("FEDERATION_ALLOW_INSECURE_HTTP", "true");
    std::env::set_var("FEDERATION_MODE", "open");
    // As `docker-compose.federation.yml` configures each DS: a remote home bootstraps a group
    // mirror only from a sequencer that advertises reconciliation and prefix bootstrap.
    std::env::set_var(
        "FEDERATION_CAPABILITIES",
        "baseline,reconciliation-v1,canonical-prefix-bootstrap-v1",
    );

    let resolver = Arc::new(DsResolver::with_default_endpoint(
        pool.clone(),
        catbird_server::federation::resolver::build_resolver_http_client(),
        service_did.clone(),
        base_url.clone(),
        None,
        3600,
    ));

    let i13_signer = I13ReceiptSigner::new(receipt_key.clone(), service_did.clone());
    let push_client = Arc::new(PushGatewayClient::new_es256(
        service_did.clone(),
        signing_key.clone(),
    ));

    let outbound = Arc::new(OutboundClient::new(10, 30));
    let service_auth =
        ServiceAuthClient::from_es256_pem(service_did.clone(), signing_pem.as_bytes(), None)
            .ok()
            .map(Arc::new);
    let mut runtime_builder = ChatRuntime::from_env(Arc::new(SseState::new(64)))
        .map_err(anyhow::Error::msg)?
        .with_resolver(resolver.clone())
        .with_i13_receipt_signer(i13_signer.clone());
    if let Some(ref sa) = service_auth {
        let submitter = Arc::new(
            catbird_server::federation::commit_submitter::RemoteCommitSubmitter::new(
                resolver.clone(),
                outbound.clone(),
                sa.clone(),
                catbird_server::auth::shared_auth_middleware(),
            ),
        );
        runtime_builder = runtime_builder.with_commit_submitter(submitter);
    }
    let runtime = Arc::new(runtime_builder);
    runtime
        .validate_protocol_fence(&pool)
        .await
        .map_err(anyhow::Error::msg)?;

    let space_host = Arc::new(SpaceHostRuntime::new(
        pool.clone(),
        SpaceHostConfig::new(service_did.clone(), signing_key.clone()),
    ));

    let did_doc = build_service_did_document(
        &service_did,
        &base_url,
        signing_key.verifying_key(),
        Some(receipt_key.verifying_key()),
    );
    let self_cached_doc: DidDocument =
        serde_json::from_value(did_doc.clone()).context("parse self DidDocument")?;
    cache_test_did_document(self_cached_doc).await;

    // A did:web serves its document at its method path. The Space relays' test
    // override (`register_test_space_relay_target`) reads every authority's
    // `#atproto` key from `{base}/.well-known/did.json`, so a did:plc DS serves it
    // there too.
    let did_doc_path =
        did_web_document_path(&service_did).unwrap_or_else(|| "/.well-known/did.json".to_string());
    let doc_arc = Arc::new(did_doc.clone());
    let well_known_router = Router::new().route(
        &did_doc_path,
        get(move || {
            let d = doc_arc.clone();
            async move { Json((*d).clone()) }
        }),
    );

    let group_relay = group_relay_router(
        GroupRelayState::for_test_with_push(
            pool.clone(),
            service_did.clone(),
            s2s_secret.as_bytes(),
            Some(Arc::new(i13_signer)),
            Some(push_client),
        )
        .with_relationship_authority_of(&runtime),
    );

    // A remote home provisions its group mirror from the sequencer's discovery and
    // reconciliation reads (`federation::group_membership::bootstrap_home_group`), mounted as in
    // production's `blue.catbird.mlsDS.*` router.
    let reconciliation_router = Router::new()
        .route("/xrpc/blue.catbird.mlsDS.healthCheck", get(health_check))
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest",
            get(get_convo_digest),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoEvents",
            get(get_convo_events),
        )
        .with_state(pool.clone());

    let state = CleanSlateServerState {
        pool: pool.clone(),
        runtime,
        resolver,
        outbound,
        service_auth,
        space_host: space_host.clone(),
        service_did: service_did.clone(),
        signing_key,
        receipt_key,
    };

    let admin_router = Router::new()
        .route("/_test/clean-slate/register-did", post(admin_register_did))
        .route(
            "/_test/clean-slate/register-push-override",
            post(admin_register_push_override),
        )
        .route(
            "/_test/clean-slate/seed-group-fixture",
            post(admin_seed_group_fixture),
        )
        .route(
            "/_test/clean-slate/remove-member",
            post(admin_remove_member_d3),
        )
        .route(
            "/_test/clean-slate/promote-admin",
            post(admin_promote_admin),
        )
        .route(
            "/_test/clean-slate/voluntary-leave",
            post(admin_voluntary_leave),
        )
        .route(
            "/_test/clean-slate/c33-expire-and-recheck",
            post(admin_c33_expire_and_recheck),
        )
        .route(
            "/_test/clean-slate/set-group-metadata",
            post(admin_set_metadata_snapshot),
        )
        .route(
            "/_test/clean-slate/get-group-metadata",
            get(admin_get_metadata_snapshot),
        )
        .route(
            "/_test/clean-slate/close-and-wipe-conversation",
            post(admin_close_and_wipe_conversation),
        )
        .route(
            "/_test/clean-slate/delete-account",
            post(admin_delete_account),
        )
        .route(
            "/_test/clean-slate/sign-mutation",
            post(admin_sign_mutation),
        )
        .route(
            "/_test/clean-slate/add-zero-leaf-member",
            post(admin_add_zero_leaf_member),
        )
        .with_state(state.clone());

    let app = Router::new()
        .route("/health", get(|| async { Json(json!({ "ok": true })) }))
        .merge(well_known_router)
        .merge(chat_router::<CleanSlateServerState>().with_state(state.clone()))
        .merge(labyrinth_router::<CleanSlateServerState>().with_state(state))
        .merge(space_host_router(space_host))
        .merge(group_relay)
        .merge(reconciliation_router)
        .merge(admin_router);

    println!(
        "{}",
        json!({
            "baseUrl": base_url,
            "serviceDid": service_did,
            "didDocument": did_doc,
        })
    );
    std::io::stdout().flush().context("flush readiness json")?;
    axum::serve(listener, app)
        .await
        .context("serve clean-slate fixture")?;
    Ok(())
}
