use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

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
use crate::util::outbound_body::{
    decode_json_bounded, ResponseBodyBudget, ORDINARY_DS_CONTROL_MAX_BYTES,
};

const DIGEST_NSID: &str = "blue.catbird.mlsDS.getConvoDigest";
const EVENTS_NSID: &str = "blue.catbird.mlsDS.getConvoEvents";
const HEALTH_CHECK_NSID: &str = "blue.catbird.mlsDS.healthCheck";
const EVENTS_PAGE_LIMIT: i64 = 500;

static DISCOVERY_CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();

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
            if page.to_seq_inclusive <= after_seq {
                return Err(format!(
                    "events page did not advance reconciliation cursor (after_seq={after_seq}, to_seq_inclusive={})",
                    page.to_seq_inclusive
                ));
            }
            apply_remote_events(pool, convo_id, &page.events)
                .await
                .map_err(|e| format!("apply events failed: {e}"))?;
            after_seq = page.to_seq_inclusive;
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
    fetch_discovery_payload_with_timeout(endpoint, Duration::from_secs(10)).await
}

fn discovery_client() -> Option<&'static reqwest::Client> {
    DISCOVERY_CLIENT
        .get_or_init(|| reqwest::Client::builder().build().ok())
        .as_ref()
}

async fn fetch_discovery_payload_with_timeout(
    endpoint: &str,
    timeout: Duration,
) -> Option<serde_json::Value> {
    let deadline = tokio::time::Instant::now().checked_add(timeout)?;
    let url = format!(
        "{}/xrpc/{}",
        endpoint.trim_end_matches('/'),
        HEALTH_CHECK_NSID
    );
    let client = discovery_client()?;
    let resp = tokio::time::timeout_at(deadline, client.get(&url).send())
        .await
        .ok()?
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
            crate::handlers::mls_chat::commit_inspect::inspect_commit_shape(&event.ciphertext)
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

#[cfg(test)]
mod tests {
    use super::*;
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

    async fn spawn_discovery_server(router: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{address}")
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

    #[test]
    fn discovery_has_no_unbounded_collector_and_event_queries_remain_separate() {
        let source = include_str!("reconciliation.rs");
        let query_call = [".call_query", "_json("].concat();
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
    fn discovery_client_is_process_reused_and_fallible() {
        let source = include_str!("reconciliation.rs");
        let fallible_static = ["OnceLock<Option<", "reqwest::Client>>"].concat();
        assert_eq!(source.matches(&fallible_static).count(), 1);

        let first = discovery_client().expect("test client should build");
        let second = discovery_client().expect("test client should remain available");
        assert!(std::ptr::eq(first, second));
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
