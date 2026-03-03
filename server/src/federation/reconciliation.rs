use std::{sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::{
    outbound::OutboundClient, peer_policy, resolver::DsResolver, CAPABILITY_RECONCILIATION_V1,
};
use crate::identity::canonical_did;

const DIGEST_NSID: &str = "blue.catbird.mlsDS.getConvoDigest";
const EVENTS_NSID: &str = "blue.catbird.mlsDS.getConvoEvents";
const HEALTH_CHECK_NSID: &str = "blue.catbird.mlsDS.healthCheck";
const EVENTS_PAGE_LIMIT: i64 = 500;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteConvoEvents {
    convo_id: String,
    from_seq_exclusive: i64,
    to_seq_inclusive: i64,
    events: Vec<RemoteEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteEvent {
    seq: i64,
    epoch: i64,
    msg_id: String,
    message_type: String,
    #[serde(with = "crate::atproto_bytes")]
    ciphertext: Vec<u8>,
    padded_size: i64,
    created_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct LocalDigestRow {
    seq: i64,
    epoch: i64,
    msg_id: Option<String>,
    message_type: String,
    ciphertext: Vec<u8>,
    padded_size: i64,
    created_at: DateTime<Utc>,
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
    let mut interval = tokio::time::interval(Duration::from_secs(30));
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

    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, split_part(sequencer_ds, '#', 1) \
         FROM conversations \
         WHERE is_remote = TRUE AND sequencer_ds IS NOT NULL",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("failed to list remote conversations: {e}"))?;

    for (convo_id, sequencer_ds_raw) in rows {
        let sequencer_ds = canonical_did(&sequencer_ds_raw).to_string();
        if canonical_did(&sequencer_ds) == canonical_did(self_did) {
            continue;
        }
        if let Err(e) = reconcile_conversation(
            pool,
            resolver,
            outbound,
            auth_sign,
            &convo_id,
            &sequencer_ds,
        )
        .await
        {
            warn!(
                convo_id = %crate::crypto::redact_for_log(&convo_id),
                sequencer_ds = %crate::crypto::redact_for_log(&sequencer_ds),
                error = %e,
                "Failed to reconcile conversation"
            );
        }
    }

    Ok(())
}

async fn reconcile_conversation(
    pool: &PgPool,
    resolver: &DsResolver,
    outbound: &OutboundClient,
    auth_sign: &(dyn Fn(&str, &str) -> Result<String, String> + Send + Sync),
    convo_id: &str,
    sequencer_ds: &str,
) -> Result<(), String> {
    peer_policy::enforce_outbound_peer_policy(pool, sequencer_ds)
        .await
        .map_err(|e| format!("peer policy denied outbound reconciliation: {e}"))?;

    let endpoint = resolver
        .resolve(sequencer_ds)
        .await
        .map_err(|e| format!("resolve sequencer endpoint failed: {e}"))?;
    let discovery_payload = fetch_discovery_payload(&endpoint.endpoint).await;
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
    let endpoint = endpoint.endpoint;

    let digest_token = auth_sign(sequencer_ds, DIGEST_NSID)
        .map_err(|e| format!("failed to sign digest request: {e}"))?;
    let digest_json = outbound
        .call_query_json(
            &endpoint,
            DIGEST_NSID,
            &digest_token,
            &[("convoId", convo_id)],
        )
        .await
        .map_err(|e| format!("digest query failed: {e}"))?;
    let remote_digest: RemoteConvoDigest =
        serde_json::from_value(digest_json).map_err(|e| format!("invalid digest response: {e}"))?;

    let mut local_state = local_digest_state(pool, convo_id)
        .await
        .map_err(|e| format!("local digest failed: {e}"))?;
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
                .call_query_json(
                    &endpoint,
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
            apply_remote_events(pool, convo_id, &page.events)
                .await
                .map_err(|e| format!("apply events failed: {e}"))?;
            after_seq = page.to_seq_inclusive.max(after_seq);
            if page.events.len() < EVENTS_PAGE_LIMIT as usize {
                break;
            }
        }

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
        .map_err(|e| format!("failed to update conversation state after reconciliation: {e}"))?;

        local_state = local_digest_state(pool, convo_id)
            .await
            .map_err(|e| format!("local digest after reconcile failed: {e}"))?;
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

async fn fetch_discovery_payload(endpoint: &str) -> Option<serde_json::Value> {
    let url = format!(
        "{}/xrpc/{}",
        endpoint.trim_end_matches('/'),
        HEALTH_CHECK_NSID
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .ok()?;
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<serde_json::Value>().await.ok()
}

async fn apply_remote_events(
    pool: &PgPool,
    convo_id: &str,
    events: &[RemoteEvent],
) -> Result<(), sqlx::Error> {
    for event in events {
        sqlx::query(
            "INSERT INTO messages \
                (id, convo_id, sender_did, message_type, epoch, seq, ciphertext, padded_size, created_at, msg_id) \
             VALUES ($1, $2, NULL, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (id) DO UPDATE SET \
                message_type = EXCLUDED.message_type, \
                epoch = EXCLUDED.epoch, \
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

async fn local_digest_state(
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

    let rows: Vec<LocalDigestRow> = sqlx::query_as::<_, LocalDigestRow>(
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

    let mut hasher = Sha256::new();
    hasher.update(b"CATBIRD-CONVO-DIGEST-V1:");
    for row in rows {
        hasher.update(row.seq.to_be_bytes());
        hasher.update(row.epoch.to_be_bytes());
        let msg_id = row.msg_id.as_deref().unwrap_or_default();
        hash_len_prefixed(&mut hasher, msg_id.as_bytes());
        hash_len_prefixed(&mut hasher, row.message_type.as_bytes());
        hash_len_prefixed(&mut hasher, &row.ciphertext);
        hasher.update(row.padded_size.to_be_bytes());
        hasher.update(row.created_at.timestamp_millis().to_be_bytes());
    }

    Ok(LocalDigestState {
        last_seq,
        last_epoch,
        event_count,
        digest_sha256: hex::encode(hasher.finalize()),
    })
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}
