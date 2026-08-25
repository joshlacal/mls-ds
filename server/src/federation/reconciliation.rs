use std::{sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::{
    outbound::OutboundClient, peer_policy,
    resolver::{self, DsResolver, ValidatedRemoteDestination},
    CAPABILITY_RECONCILIATION_V1,
};
use crate::identity::canonical_did;
use crate::util::outbound_body::{
    decode_json_bounded, ResponseBodyBudget, ORDINARY_DS_CONTROL_MAX_BYTES,
};

const DIGEST_NSID: &str = "blue.catbird.mlsDS.getConvoDigest";
const EVENTS_NSID: &str = "blue.catbird.mlsDS.getConvoEvents";
const HEALTH_CHECK_NSID: &str = "blue.catbird.mlsDS.healthCheck";
const EVENTS_PAGE_LIMIT: i64 = 500;


/// Decoded `getConvoDigest` response from a peer DS.
///
/// `convo_id` and `generated_at` are deserialized for shape validation and
/// future audit logging but currently unused in the reconciliation algorithm,
/// which keys off `(epoch, last_seq, digest_sha256)`. Keeping the fields
/// avoids a re-emit if/when we add cross-DS digest staleness checks.
/// TODO(phase-2.5-cleanup): wire `generated_at` into staleness rejection or drop.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct RemoteConvoDigest {
    convo_id: String,
    sequencer_ds_did: String,
    sequencer_term: i64,
    epoch: i64,
    last_seq: i64,
    event_count: i64,
    digest_sha256: String,
    generated_at: DateTime<Utc>,
}

/// Decoded `getConvoEvents` response from a peer DS.
///
/// `convo_id` and `from_seq_exclusive` are echoed back by the peer for the
/// caller's benefit; the reconciliation loop already tracks the requested
/// range, so they're inspected for Debug/log purposes only.
/// TODO(phase-2.5-cleanup): assert echoed values match the request, or drop.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct RemoteConvoEvents {
    convo_id: String,
    from_seq_exclusive: i64,
    to_seq_inclusive: i64,
    events: Vec<RemoteEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RemoteEvent {
    pub seq: i64,
    pub epoch: i64,
    pub msg_id: String,
    pub message_type: String,
    #[serde(with = "crate::atproto_bytes")]
    pub ciphertext: Vec<u8>,
    pub padded_size: i64,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub entry_id: Option<String>,
    #[serde(default)]
    pub entry_kind: Option<String>,
    #[serde(default, with = "crate::atproto_bytes::option")]
    pub signed_request: Option<Vec<u8>>,
    #[serde(default, with = "crate::atproto_bytes::option")]
    pub outer_fingerprint: Option<Vec<u8>>,
}

#[derive(Debug)]
struct LocalDigestState {
    last_seq: i64,
    last_epoch: i64,
    event_count: i64,
    digest_sha256: String,
}
pub async fn run_reconciliation_worker(
    pool: PgPool,
    resolver: Arc<DsResolver>,
    outbound: Arc<OutboundClient>,
    auth_sign: Arc<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>,
    self_did: String,
    shutdown: CancellationToken,
) {
    let interval_secs = std::env::var("RECONCILIATION_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30);
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    info!("Federation reconciliation worker started");

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(e) = run_once(&pool, &resolver, &outbound, auth_sign.as_ref(), &self_did).await {
                    warn!(error = %e, "Reconciliation worker iteration failed");
                }
            }
            _ = shutdown.cancelled() => {
                info!("Federation reconciliation worker shutting down");
                break;
            }
        }
    }
}

async fn run_once(
    pool: &PgPool,
    resolver: &DsResolver,
    outbound: &OutboundClient,
    auth_sign: &(dyn Fn(&str, &str) -> Result<String, String> + Send + Sync),
    self_did: &str,
) -> Result<(), String> {
    if !super::local_supports_capability(CAPABILITY_RECONCILIATION_V1) {
        debug!(
            capability = CAPABILITY_RECONCILIATION_V1,
            "Skipping reconciliation worker iteration; local capability is disabled"
        );
        return Ok(());
    }

    // 1. Reconcile clean chat conversations from chat.conversations
    let clean_rows: Vec<(uuid::Uuid, String)> = sqlx::query_as(
        "SELECT conversation_id, split_part(sequencer_ds, '#', 1) \
         FROM chat.conversations \
         WHERE is_remote = TRUE AND sequencer_ds IS NOT NULL",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("failed to list clean remote conversations: {e}"))?;

    for (convo_uuid, sequencer_ds_raw) in clean_rows {
        let sequencer_ds = canonical_did(&sequencer_ds_raw).to_string();
        if canonical_did(&sequencer_ds) == canonical_did(self_did) {
            continue;
        }
        let convo_id_str = convo_uuid.to_string();
        if let Err(e) = reconcile_conversation_internal(
            pool,
            resolver,
            outbound,
            auth_sign,
            &convo_id_str,
            &sequencer_ds,
            true,
        )
        .await
        {
            warn!(
                convo_id = %convo_uuid,
                sequencer_ds = %crate::crypto::redact_for_log(&sequencer_ds),
                error = %e,
                "Failed to reconcile clean conversation"
            );
        }
    }

    // 2. Reconcile legacy conversations from conversations (public schema)
    let legacy_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, split_part(sequencer_ds, '#', 1) \
         FROM conversations \
         WHERE is_remote = TRUE AND sequencer_ds IS NOT NULL",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("failed to list legacy remote conversations: {e}"))?;

    for (convo_id, sequencer_ds_raw) in legacy_rows {
        let sequencer_ds = canonical_did(&sequencer_ds_raw).to_string();
        if canonical_did(&sequencer_ds) == canonical_did(self_did) {
            continue;
        }
        if let Err(e) = reconcile_conversation_internal(
            pool,
            resolver,
            outbound,
            auth_sign,
            &convo_id,
            &sequencer_ds,
            false,
        )
        .await
        {
            warn!(
                convo_id = %crate::crypto::redact_for_log(&convo_id),
                sequencer_ds = %crate::crypto::redact_for_log(&sequencer_ds),
                error = %e,
                "Failed to reconcile legacy conversation"
            );
        }
    }

    Ok(())
}

pub async fn reconcile_conversation(
    pool: &PgPool,
    resolver: &DsResolver,
    outbound: &OutboundClient,
    auth_sign: &(dyn Fn(&str, &str) -> Result<String, String> + Send + Sync),
    convo_id: &str,
    sequencer_ds: &str,
) -> Result<(), String> {
    let is_clean = uuid::Uuid::parse_str(convo_id).is_ok();
    reconcile_conversation_internal(
        pool,
        resolver,
        outbound,
        auth_sign,
        convo_id,
        sequencer_ds,
        is_clean,
    )
    .await
}

async fn reconcile_conversation_internal(
    pool: &PgPool,
    resolver: &DsResolver,
    outbound: &OutboundClient,
    auth_sign: &(dyn Fn(&str, &str) -> Result<String, String> + Send + Sync),
    convo_id: &str,
    sequencer_ds: &str,
    is_clean: bool,
) -> Result<(), String> {
    peer_policy::enforce_outbound_peer_policy(pool, sequencer_ds)
        .await
        .map_err(|e| format!("peer policy denied outbound reconciliation: {e}"))?;
    let endpoint = resolver
        .resolve_ds_did(sequencer_ds)
        .await
        .map_err(|e| format!("resolve sequencer endpoint failed: {e}"))?;
    let destination = resolver
        .resolve_ds_destination(sequencer_ds)
        .await
        .map_err(|e| format!("resolve sequencer destination failed: {e}"))?;
    let discovery_payload = fetch_discovery_payload(&destination).await;
    if !super::target_supports_capability(
        CAPABILITY_RECONCILIATION_V1,
        endpoint.federation_capabilities.as_deref(),
        discovery_payload.as_ref(),
    ) {
        let known_caps = super::known_target_capabilities(
            endpoint.federation_capabilities.as_deref(),
            discovery_payload.as_ref(),
        )
        .unwrap_or_default();
        return Err(format!(
            "target DS missing required capability '{CAPABILITY_RECONCILIATION_V1}' (did={}, advertised={:?})",
            crate::crypto::redact_for_log(sequencer_ds),
            known_caps
        ));
    }

    let digest_token = auth_sign(sequencer_ds, DIGEST_NSID)
        .map_err(|e| format!("failed to sign digest request: {e}"))?;
    let digest_json = outbound
        .call_query_json_pinned(
            &destination,
            DIGEST_NSID,
            &digest_token,
            &[("convoId", convo_id)],
        )
        .await
        .map_err(|e| format!("digest query failed: {e}"))?;
    let remote_digest: RemoteConvoDigest =
        serde_json::from_value(digest_json).map_err(|e| format!("invalid digest response: {e}"))?;

    let mut local_state = if is_clean {
        let convo_uuid = uuid::Uuid::parse_str(convo_id).map_err(|e| e.to_string())?;
        local_clean_digest_state(pool, convo_uuid)
            .await
            .map_err(|e| format!("local clean digest failed: {e}"))?
    } else {
        local_legacy_digest_state(pool, convo_id)
            .await
            .map_err(|e| format!("local legacy digest failed: {e}"))?
    };
    let drifted = local_state.digest_sha256 != remote_digest.digest_sha256
        || local_state.last_seq != remote_digest.last_seq
        || local_state.event_count != remote_digest.event_count;

    if drifted {
        metrics::counter!("federation_reconciliation_drift_total", 1, "convo_id" => convo_id.to_string());
        debug!(
            convo_id = %crate::crypto::redact_for_log(convo_id),
            local_last_seq = local_state.last_seq,
            remote_last_seq = remote_digest.last_seq,
            "Reconciliation drift detected; fetching missing events"
        );

        let mut after_seq = local_state.last_seq;
        loop {
            let events_token = auth_sign(sequencer_ds, EVENTS_NSID)
                .map_err(|e| format!("failed to sign events request: {e}"))?;
            let after_seq_s = after_seq.to_string();
            let limit_s = EVENTS_PAGE_LIMIT.to_string();
            let events_json = outbound
                .call_query_json_pinned(
                    &destination,
                    EVENTS_NSID,
                    &events_token,
                    &[
                        ("convoId", convo_id),
                        ("afterSeq", &after_seq_s),
                        ("limit", &limit_s),
                    ],
                )
                .await
                .map_err(|e| format!("events query failed: {e}"))?;
            let page: RemoteConvoEvents = serde_json::from_value(events_json)
                .map_err(|e| format!("invalid events response: {e}"))?;

            if page.events.is_empty() {
                break;
            }
            if page.to_seq_inclusive <= after_seq {
                return Err(format!(
                    "events page did not advance reconciliation cursor (after_seq={after_seq}, to_seq_inclusive={})",
                    page.to_seq_inclusive
                ));
            }
            if is_clean {
                let convo_uuid = uuid::Uuid::parse_str(convo_id).map_err(|e| e.to_string())?;
                apply_remote_clean_events(pool, convo_uuid, &page.events)
                    .await
                    .map_err(|e| format!("apply clean events failed: {e}"))?;
            } else {
                apply_remote_events(pool, convo_id, &page.events)
                    .await
                    .map_err(|e| format!("apply legacy events failed: {e}"))?;
            }
            after_seq = page.to_seq_inclusive;
            if page.events.len() < EVENTS_PAGE_LIMIT as usize {
                break;
            }
        }

        if is_clean {
            let convo_uuid = uuid::Uuid::parse_str(convo_id).map_err(|e| e.to_string())?;
            sqlx::query(
                "UPDATE chat.conversations \
                 SET sequencer_term = GREATEST(sequencer_term, $2), \
                     sequencer_ds = $3 \
                 WHERE conversation_id = $1",
            )
            .bind(convo_uuid)
            .bind(remote_digest.sequencer_term)
            .bind(canonical_did(&remote_digest.sequencer_ds_did))
            .execute(pool)
            .await
            .map_err(|e| {
                format!("failed to update chat.conversations after reconciliation: {e}")
            })?;

            local_state = local_clean_digest_state(pool, convo_uuid)
                .await
                .map_err(|e| format!("local clean digest after reconcile failed: {e}"))?;
        } else {
            sqlx::query(
                "UPDATE conversations \
                 SET current_epoch = GREATEST(current_epoch, $2), \
                     sequencer_term = GREATEST(COALESCE(sequencer_term, 0), $3), \
                     sequencer_ds = $4 \
                 WHERE id = $1",
            )
            .bind(convo_id)
            .bind(remote_digest.epoch)
            .bind(remote_digest.sequencer_term)
            .bind(canonical_did(&remote_digest.sequencer_ds_did))
            .execute(pool)
            .await
            .map_err(|e| {
                format!("failed to update conversation state after reconciliation: {e}")
            })?;

            local_state = local_legacy_digest_state(pool, convo_id)
                .await
                .map_err(|e| format!("local legacy digest after reconcile failed: {e}"))?;
        }
    }

    let drift_increment = if drifted { 1_i64 } else { 0_i64 };
    sqlx::query(
        "INSERT INTO federation_sync_state \
            (convo_id, sequencer_ds_did, sequencer_term, last_seq, last_epoch, last_digest, last_reconciled_at, drift_count, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7, NOW()) \
         ON CONFLICT (convo_id, sequencer_ds_did) DO UPDATE SET \
            sequencer_term = EXCLUDED.sequencer_term, \
            last_seq = EXCLUDED.last_seq, \
            last_epoch = EXCLUDED.last_epoch, \
            last_digest = EXCLUDED.last_digest, \
            last_reconciled_at = NOW(), \
            drift_count = federation_sync_state.drift_count + EXCLUDED.drift_count, \
            updated_at = NOW()",
    )
    .bind(convo_id)
    .bind(canonical_did(&remote_digest.sequencer_ds_did))
    .bind(remote_digest.sequencer_term)
    .bind(local_state.last_seq)
    .bind(local_state.last_epoch)
    .bind(&local_state.digest_sha256)
    .bind(drift_increment)
    .execute(pool)
    .await
    .map_err(|e| format!("failed to update federation_sync_state: {e}"))?;

    Ok(())
}

async fn fetch_discovery_payload(
    destination: &ValidatedRemoteDestination,
) -> Option<serde_json::Value> {
    fetch_discovery_payload_with_timeout(destination, Duration::from_secs(10)).await
}

async fn fetch_discovery_payload_with_timeout(
    destination: &ValidatedRemoteDestination,
    timeout: Duration,
) -> Option<serde_json::Value> {
    let deadline = tokio::time::Instant::now().checked_add(timeout)?;
    let endpoint = destination.url.as_str().trim_end_matches('/');
    let url = format!("{}/xrpc/{}", endpoint, HEALTH_CHECK_NSID);
    let parsed_url = url::Url::parse(&url).ok()?;
    let discovery_dest = ValidatedRemoteDestination {
        url: parsed_url,
        host: destination.host.clone(),
        addrs: destination.addrs.clone(),
    };
    let resp = resolver::send_hardened_resolution_request(
        &discovery_dest,
        deadline,
        &destination.host,
        "healthCheck discovery",
    )
    .await
    .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    decode_json_bounded(
        resp,
        ResponseBodyBudget::new(ORDINARY_DS_CONTROL_MAX_BYTES, deadline),
    )
    .await
    .ok()
}

async fn apply_remote_events(
    pool: &PgPool,
    convo_id: &str,
    events: &[RemoteEvent],
) -> Result<(), sqlx::Error> {
    for event in events {
        let wire_epoch = if event.message_type == "commit" {
            crate::crypto::commit_inspect::inspect_commit_shape(&event.ciphertext)
                .ok()
                .map(|shape| shape.epoch as i64)
        } else {
            None
        };

        sqlx::query(
            "INSERT INTO messages \
                (id, convo_id, sender_did, message_type, epoch, wire_epoch, seq, ciphertext, padded_size, created_at, msg_id) \
             VALUES ($1, $2, NULL, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (id) DO UPDATE SET \
                message_type = EXCLUDED.message_type, \
                epoch = EXCLUDED.epoch, \
                wire_epoch = EXCLUDED.wire_epoch, \
                seq = EXCLUDED.seq, \
                ciphertext = EXCLUDED.ciphertext, \
                padded_size = EXCLUDED.padded_size, \
                created_at = EXCLUDED.created_at, \
                msg_id = EXCLUDED.msg_id",
        )
        .bind(&event.msg_id)
        .bind(convo_id)
        .bind(&event.message_type)
        .bind(event.epoch)
        .bind(wire_epoch)
        .bind(event.seq)
        .bind(&event.ciphertext)
        .bind(event.padded_size)
        .bind(event.created_at)
        .bind(&event.msg_id)
        .execute(pool)
        .await?;
    }
    Ok(())
}
async fn apply_remote_clean_events(
    pool: &PgPool,
    convo_id: uuid::Uuid,
    events: &[RemoteEvent],
) -> Result<(), String> {
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;

    for event in events {
        let seq_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM chat.entries WHERE conversation_id = $1 AND seq = $2)",
        )
        .bind(convo_id)
        .bind(event.seq)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        if seq_exists {
            continue;
        }

        let entry_id = if let Some(ref eid) = event.entry_id {
            uuid::Uuid::parse_str(eid).map_err(|e| e.to_string())?
        } else if let Ok(u) = uuid::Uuid::parse_str(&event.msg_id) {
            u
        } else {
            uuid::Uuid::new_v4()
        };

        let message_id = if event.message_type == "blue.catbird.chat.defs#applicationEntry"
            || event.message_type == "app"
        {
            uuid::Uuid::parse_str(&event.msg_id).ok()
        } else {
            None
        };

        let entry_kind = if event.message_type == "app" {
            "blue.catbird.chat.defs#applicationEntry".to_string()
        } else if event.message_type == "commit" {
            "blue.catbird.chat.defs#commitEntry".to_string()
        } else {
            event.message_type.clone()
        };

        let payload_sha256: [u8; 32] = Sha256::digest(&event.ciphertext).into();
        let signed_req = event.signed_request.clone().unwrap_or_default();
        let outer_fp = event
            .outer_fingerprint
            .clone()
            .unwrap_or_else(|| payload_sha256.to_vec());

        let empty_server_fields =
            serde_ipld_dagcbor::to_vec(&std::collections::BTreeMap::<String, String>::new())
                .unwrap_or_default();

        // For an application entry, the wire protocol carries only the signed
        // request. The `chat.message_sends` side row that the deferred
        // `entries_message_send_fk` requires is derived deterministically from
        // the canonical signed mutation (transcript, request digest, signature)
        // and the delivered payload — mirroring `deliver_message_replication`'s
        // `append_exact_application_entry` side row. This is the same material
        // the sequencer DS persisted when it accepted the send, so a remote
        // mailbox reconciles to a byte-identical row.
        let mut actor_did_final = "did:web:unknown.actor".to_string();
        let mut actor_device_id_final = uuid::Uuid::nil();
        let mut actor_key_id_final = "unknown".to_string();
        let mut actor_auth_gen_final = 1i64;
        let mut request_digest_bytes = Sha256::digest(&signed_req).to_vec();
        let mut signature_bytes = vec![0u8; 64];
        let mut transcript_bytes: Vec<u8> = Vec::new();
        if !signed_req.is_empty() {
            if let Ok(mutation) =
                crate::chat_protocol::transcript::decode_canonical_signed_mutation(&signed_req)
            {
                actor_did_final = mutation.actor_did().as_str().to_string();
                actor_device_id_final =
                    uuid::Uuid::from_bytes(*mutation.actor_device_id().as_bytes());
                actor_key_id_final = mutation.key_id().as_str().to_string();
                actor_auth_gen_final = mutation.auth_generation() as i64;
                request_digest_bytes = mutation.request_digest().to_vec();
                signature_bytes = mutation.signature().to_vec();
                transcript_bytes = mutation.transcript_bytes().to_vec();
            }
        }
        let req_digest = request_digest_bytes;
        let signature = signature_bytes;

        sqlx::query(
            r#"
            INSERT INTO chat.entries (
                conversation_id, seq, entry_id, entry_kind,
                accepted_payload_bytes, accepted_payload_sha256, signed_request_bytes,
                request_digest, signature, server_fields_bytes, outer_entry_fingerprint,
                actor_did, actor_device_id, actor_key_id, actor_auth_generation,
                generation, message_id, received_at
            ) VALUES (
                $1, $2, $3, $4,
                $5, $6, $7,
                $8, $9, $10, $11,
                $12, $13, $14, $15,
                $16, $17, $18
            )
            ON CONFLICT (conversation_id, seq) DO NOTHING
            "#,
        )
        .bind(convo_id)
        .bind(event.seq)
        .bind(entry_id)
        .bind(&entry_kind)
        .bind(&event.ciphertext)
        .bind(&payload_sha256[..])
        .bind(&signed_req)
        .bind(&req_digest)
        .bind(&signature)
        .bind(&empty_server_fields)
        .bind(&outer_fp)
        .bind(&actor_did_final)
        .bind(actor_device_id_final)
        .bind(&actor_key_id_final)
        .bind(actor_auth_gen_final)
        .bind(event.epoch)
        .bind(message_id)
        .bind(event.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        // Mirror the accepted send's `chat.message_sends` row so the deferred
        // `entries_message_send_fk` (and the `message_sends_application_entry_fk`
        // back-reference) hold. The `entries_message_identity_uq` on the entry
        // guarantees at most one send per (conversation, message), so this
        // insert is idempotent under replay.
        if let Some(mid) = message_id {
            let outcome_bytes = serde_json::to_vec(&serde_json::json!({
                "entry": {
                    "entryId": entry_id.to_string(),
                    "conversationId": convo_id.to_string(),
                    "seq": event.seq,
                    "signedRequest": serde_json::from_slice::<serde_json::Value>(&signed_req)
                        .unwrap_or(serde_json::Value::Null),
                    "receivedAt": event.created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                }
            }))
            .map_err(|e| format!("failed to serialize reconciled send outcome: {e}"))?;
            let outcome_sha = Sha256::digest(&outcome_bytes).to_vec();
            sqlx::query(
                r#"
                INSERT INTO chat.message_sends (
                    conversation_id, message_id, signed_request_bytes,
                    signing_transcript_bytes, request_digest, signature, status,
                    accepted_entry_seq, outcome_bytes, outcome_sha256, received_at
                ) VALUES ($1, $2, $3, $4, $5, $6, 'accepted', $7, $8, $9, $10)
                ON CONFLICT (conversation_id, message_id) DO NOTHING
                "#,
            )
            .bind(convo_id)
            .bind(mid)
            .bind(&signed_req)
            .bind(&transcript_bytes)
            .bind(&req_digest)
            .bind(&signature)
            .bind(event.seq)
            .bind(&outcome_bytes)
            .bind(&outcome_sha)
            .bind(event.created_at)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("failed to insert reconciled message_sends row: {e}"))?;
        }

        // Advance next_entry_seq in chat.conversations
        sqlx::query(
            r#"
            UPDATE chat.conversations
               SET next_entry_seq = GREATEST(next_entry_seq, $2 + 1)
             WHERE conversation_id = $1
            "#,
        )
        .bind(convo_id)
        .bind(event.seq)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    }

    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn local_clean_digest_state(
    pool: &PgPool,
    convo_id: uuid::Uuid,
) -> Result<LocalDigestState, sqlx::Error> {
    let stats = sqlx::query(
        "SELECT \
           CAST(COALESCE(MAX(seq), 0) AS BIGINT) AS last_seq, \
           CAST(COALESCE(MAX(generation), 0) AS BIGINT) AS last_epoch, \
           CAST(COUNT(*) AS BIGINT) AS event_count \
         FROM chat.entries WHERE conversation_id = $1",
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await?;
    let last_seq: i64 = stats.try_get("last_seq")?;
    let last_epoch: i64 = stats.try_get("last_epoch")?;
    let event_count: i64 = stats.try_get("event_count")?;

    let rows: Vec<crate::handlers::ds::get_convo_digest::CleanDigestRow> =
        sqlx::query_as::<_, crate::handlers::ds::get_convo_digest::CleanDigestRow>(
            "SELECT \
           CAST(seq AS BIGINT) AS seq, \
           CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
           entry_id, \
           entry_kind, \
           accepted_payload_bytes, \
           signed_request_bytes, \
           outer_entry_fingerprint, \
           received_at \
         FROM chat.entries \
         WHERE conversation_id = $1 \
         ORDER BY seq ASC",
        )
        .bind(convo_id)
        .fetch_all(pool)
        .await?;

    let digest_sha256 = crate::handlers::ds::get_convo_digest::compute_clean_convo_digest(&rows);

    Ok(LocalDigestState {
        last_seq,
        last_epoch,
        event_count,
        digest_sha256,
    })
}

async fn local_legacy_digest_state(
    pool: &PgPool,
    convo_id: &str,
) -> Result<LocalDigestState, sqlx::Error> {
    let stats = sqlx::query(
        "SELECT \
           CAST(COALESCE(MAX(seq), 0) AS BIGINT) AS last_seq, \
           CAST(COALESCE(MAX(epoch), 0) AS BIGINT) AS last_epoch, \
           CAST(COUNT(*) AS BIGINT) AS event_count \
         FROM messages WHERE convo_id = $1",
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await?;
    let last_seq: i64 = stats.try_get("last_seq")?;
    let last_epoch: i64 = stats.try_get("last_epoch")?;
    let event_count: i64 = stats.try_get("event_count")?;

    let rows: Vec<crate::handlers::ds::get_convo_digest::LegacyDigestRow> =
        sqlx::query_as::<_, crate::handlers::ds::get_convo_digest::LegacyDigestRow>(
            "SELECT \
           CAST(seq AS BIGINT) AS seq, \
           CAST(epoch AS BIGINT) AS epoch, \
           COALESCE(msg_id, id) AS msg_id, \
           message_type, \
           ciphertext, \
           CAST(COALESCE(padded_size, 0) AS BIGINT) AS padded_size, \
           created_at \
         FROM messages \
         WHERE convo_id = $1 \
         ORDER BY seq ASC",
        )
        .bind(convo_id)
        .fetch_all(pool)
        .await?;

    let digest_sha256 = crate::handlers::ds::get_convo_digest::compute_legacy_convo_digest(&rows);

    Ok(LocalDigestState {
        last_seq,
        last_epoch,
        event_count,
        digest_sha256,
    })
}

#[allow(dead_code)]
async fn local_digest_state(
    pool: &PgPool,
    convo_id: &str,
) -> Result<LocalDigestState, sqlx::Error> {
    local_legacy_digest_state(pool, convo_id).await
}
fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::resolver::ValidatedRemoteDestination;
    use axum::{
        body::Body,
        http::{Response, StatusCode},
        routing::get,
        Router,
    };
    use bytes::Bytes;
    use futures::stream;
    use serde_json::json;
    use std::convert::Infallible;
    use tokio::net::TcpListener;

    async fn spawn_discovery_server(router: Router) -> ValidatedRemoteDestination {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        ValidatedRemoteDestination {
            url: url::Url::parse(&format!("http://127.0.0.1:{}/", address.port())).unwrap(),
            host: "127.0.0.1".to_string(),
            addrs: vec![address],
        }
    }

    #[tokio::test]
    async fn valid_bounded_discovery_json_succeeds() {
        let expected = json!({ "capabilities": [CAPABILITY_RECONCILIATION_V1] });
        let body = expected.to_string();
        let endpoint = spawn_discovery_server(Router::new().route(
            &format!("/xrpc/{HEALTH_CHECK_NSID}"),
            get(move || {
                let body = body.clone();
                async move { Body::from(body) }
            }),
        ))
        .await;

        let discovery = fetch_discovery_payload(&endpoint).await;
        assert_eq!(discovery, Some(expected));
        assert!(crate::federation::target_supports_capability(
            CAPABILITY_RECONCILIATION_V1,
            None,
            discovery.as_ref(),
        ));
    }

    #[tokio::test]
    async fn declared_discovery_body_over_one_mib_returns_none() {
        let body = json!({
            "capabilities": [CAPABILITY_RECONCILIATION_V1],
            "padding": "x".repeat(ORDINARY_DS_CONTROL_MAX_BYTES),
        })
        .to_string();
        assert!(body.len() > ORDINARY_DS_CONTROL_MAX_BYTES);
        let endpoint = spawn_discovery_server(Router::new().route(
            &format!("/xrpc/{HEALTH_CHECK_NSID}"),
            get(move || {
                let body = body.clone();
                async move {
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-length", body.len().to_string())
                        .body(Body::from(body))
                        .unwrap()
                }
            }),
        ))
        .await;

        assert_eq!(fetch_discovery_payload(&endpoint).await, None);
    }

    #[tokio::test]
    async fn chunked_discovery_body_over_one_mib_returns_none() {
        let prefix = format!(r#"{{"capabilities":["{CAPABILITY_RECONCILIATION_V1}"],"padding":""#);
        let chunks = vec![
            Ok::<_, Infallible>(Bytes::from(prefix)),
            Ok(Bytes::from(vec![b'x'; ORDINARY_DS_CONTROL_MAX_BYTES])),
            Ok(Bytes::from_static(br#""}"#)),
        ];
        let endpoint = spawn_discovery_server(Router::new().route(
            &format!("/xrpc/{HEALTH_CHECK_NSID}"),
            get(move || {
                let chunks = chunks.clone();
                async move {
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from_stream(stream::iter(chunks)))
                        .unwrap()
                }
            }),
        ))
        .await;

        assert_eq!(fetch_discovery_payload(&endpoint).await, None);
    }

    #[tokio::test]
    async fn non_success_and_malformed_discovery_keep_best_effort_none() {
        const CANARY: &str = "cookie=discovery-canary token=discovery-secret";
        let unavailable = spawn_discovery_server(Router::new().route(
            &format!("/xrpc/{HEALTH_CHECK_NSID}"),
            get(|| async {
                Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from(CANARY))
                    .unwrap()
            }),
        ))
        .await;
        assert_eq!(fetch_discovery_payload(&unavailable).await, None);

        let malformed = spawn_discovery_server(Router::new().route(
            &format!("/xrpc/{HEALTH_CHECK_NSID}"),
            get(|| async { Body::from(format!(r#"{{"secret":"{CANARY}""#)) }),
        ))
        .await;
        assert_eq!(fetch_discovery_payload(&malformed).await, None);
    }

    #[tokio::test]
    async fn discovery_headers_and_body_share_one_pre_send_deadline() {
        let endpoint = spawn_discovery_server(Router::new().route(
            &format!("/xrpc/{HEALTH_CHECK_NSID}"),
            get(|| async {
                tokio::time::sleep(Duration::from_millis(45)).await;
                let chunks = stream::once(async {
                    tokio::time::sleep(Duration::from_millis(45)).await;
                    Ok::<_, Infallible>(Bytes::from_static(
                        br#"{"capabilities":["reconciliation-v1"]}"#,
                    ))
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from_stream(chunks))
                    .unwrap()
            }),
        ))
        .await;

        assert_eq!(
            fetch_discovery_payload_with_timeout(&endpoint, Duration::from_millis(70)).await,
            None
        );
    }

    #[tokio::test]
    async fn reconciliation_discovery_uses_pinned_destination() {
        use axum::http::HeaderMap;

        let expected = json!({ "capabilities": [CAPABILITY_RECONCILIATION_V1] });
        let body = expected.to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new().route(
            &format!("/xrpc/{HEALTH_CHECK_NSID}"),
            get(move |headers: HeaderMap| {
                let body = body.clone();
                async move {
                    let host = headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or("");
                    assert!(
                        host == "peer.example.com" || host.starts_with("peer.example.com:"),
                        "host header must retain original host, got {host}"
                    );
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from(body))
                        .unwrap()
                }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let destination = ValidatedRemoteDestination {
            url: url::Url::parse(&format!("http://peer.example.com:{}/", addr.port())).unwrap(),
            host: "peer.example.com".to_string(),
            addrs: vec![addr],
        };

        // Note: fetch_discovery_payload in production will accept &ValidatedRemoteDestination
        // For now, let's call fetch_discovery_payload with destination endpoint to watch it fail or type check
        let discovery = fetch_discovery_payload(&destination).await;
        assert_eq!(discovery, Some(expected));
    }

    #[test]
    fn reconciliation_does_not_contain_unpinned_http_client() {
        let source = include_str!("reconciliation.rs");
        let discovery_client_sym = ["DISCOVERY", "_CLIENT"].concat();
        let client_builder_sym = ["Client::", "builder"].concat();
        let unpinned_get_sym = [".get(&", "url).send()"].concat();
        assert!(!source.contains(&discovery_client_sym), "must not contain discovery client static");
        assert!(!source.contains(&client_builder_sym), "must not build client");
        assert!(!source.contains(&unpinned_get_sym), "must not send unpinned get");
    }

    #[test]
    fn discovery_has_no_unbounded_collector_and_event_queries_remain_separate() {
        let source = include_str!("reconciliation.rs");
        let query_call = [".call_query", "_json_pinned("].concat();
        assert_eq!(source.matches(&query_call).count(), 2);
        for suffix in [".json()", ".bytes()", ".text()"] {
            let needle = ["resp", suffix].concat();
            assert!(!source.contains(&needle), "found {needle}");
        }

        let discovery_start = source
            .find("async fn fetch_discovery_payload_with_timeout")
            .unwrap();
        let discovery_end = source[discovery_start..]
            .find("\nasync fn apply_remote_events")
            .unwrap();
        let discovery = &source[discovery_start..discovery_start + discovery_end];
        for log_macro in ["debug!(", "info!(", "warn!(", "error!("] {
            assert!(!discovery.contains(log_macro));
        }
    }

    #[test]
    fn reconciliation_rejects_a_full_page_without_cursor_progress() {
        let source = include_str!("reconciliation.rs");
        let silent_max = ["after_seq = page.to_seq_inclusive.", "max(after_seq);"].concat();
        assert!(
            source.contains("page.to_seq_inclusive <= after_seq"),
            "a malicious peer must not keep the worker in a non-progress loop"
        );
        assert!(
            !source.contains(&silent_max),
            "max() silently accepts a full page that does not advance the cursor"
        );
    }
}
