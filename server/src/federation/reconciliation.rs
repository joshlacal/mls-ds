use std::{sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::{
    outbound::OutboundClient,
    peer_policy,
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

pub(crate) use crate::chat_protocol::transcript::CleanEntryKind;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum StrictCleanRemoteEventError {
    #[error("missing required clean event field: {0}")]
    MissingField(&'static str),
    #[error("invalid entry id: {0}")]
    InvalidEntryId(String),
    #[error("invalid or unknown entry kind: {0}")]
    InvalidEntryKind(String),
    #[error("invalid accepted payload hash length: expected 32, got {0}")]
    InvalidAcceptedPayloadHashLength(usize),
    #[error("accepted payload hash mismatch")]
    AcceptedPayloadHashMismatch,
    #[error("invalid signed request length: {0}")]
    InvalidSignedRequestLength(usize),
    #[error("invalid outer fingerprint length: expected 32, got {0}")]
    InvalidOuterFingerprintLength(usize),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct StrictCleanRemoteEvent {
    seq: i64,
    generation: i64,
    entry_id: uuid::Uuid,
    entry_kind: CleanEntryKind,
    accepted_payload_bytes: Vec<u8>,
    accepted_payload_sha256: [u8; 32],
    signed_request: Vec<u8>,
    outer_fingerprint: [u8; 32],
    received_at: DateTime<Utc>,
}

impl StrictCleanRemoteEvent {
    pub(crate) fn seq(&self) -> i64 {
        self.seq
    }

    pub(crate) fn generation(&self) -> i64 {
        self.generation
    }

    pub(crate) fn entry_id(&self) -> uuid::Uuid {
        self.entry_id
    }

    pub(crate) fn entry_kind(&self) -> &CleanEntryKind {
        &self.entry_kind
    }

    pub(crate) fn entry_kind_str(&self) -> &'static str {
        self.entry_kind.as_str()
    }

    pub(crate) fn accepted_payload_bytes(&self) -> &[u8] {
        &self.accepted_payload_bytes
    }

    pub(crate) fn accepted_payload_sha256(&self) -> &[u8; 32] {
        &self.accepted_payload_sha256
    }

    pub(crate) fn signed_request(&self) -> &[u8] {
        &self.signed_request
    }

    pub(crate) fn outer_fingerprint(&self) -> &[u8; 32] {
        &self.outer_fingerprint
    }

    pub(crate) fn received_at(&self) -> DateTime<Utc> {
        self.received_at
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        i64,
        i64,
        uuid::Uuid,
        CleanEntryKind,
        Vec<u8>,
        [u8; 32],
        Vec<u8>,
        [u8; 32],
        DateTime<Utc>,
    ) {
        (
            self.seq,
            self.generation,
            self.entry_id,
            self.entry_kind,
            self.accepted_payload_bytes,
            self.accepted_payload_sha256,
            self.signed_request,
            self.outer_fingerprint,
            self.received_at,
        )
    }
}

impl TryFrom<RemoteEvent> for StrictCleanRemoteEvent {
    type Error = StrictCleanRemoteEventError;

    fn try_from(event: RemoteEvent) -> Result<Self, Self::Error> {
        let entry_id_str = event
            .entry_id
            .ok_or(StrictCleanRemoteEventError::MissingField("entryId"))?;
        let entry_id = uuid::Uuid::parse_str(&entry_id_str)
            .map_err(|_| StrictCleanRemoteEventError::InvalidEntryId(entry_id_str.clone()))?;
        if entry_id.to_string() != entry_id_str {
            return Err(StrictCleanRemoteEventError::InvalidEntryId(entry_id_str));
        }
        let entry_kind_str = event
            .entry_kind
            .ok_or(StrictCleanRemoteEventError::MissingField("entryKind"))?;
        let entry_kind = CleanEntryKind::from_type_id(&entry_kind_str)
            .ok_or_else(|| StrictCleanRemoteEventError::InvalidEntryKind(entry_kind_str))?;

        let hash_bytes =
            event
                .accepted_payload_sha256
                .ok_or(StrictCleanRemoteEventError::MissingField(
                    "acceptedPayloadSha256",
                ))?;
        if hash_bytes.len() != 32 {
            return Err(
                StrictCleanRemoteEventError::InvalidAcceptedPayloadHashLength(hash_bytes.len()),
            );
        }
        let mut accepted_payload_sha256 = [0u8; 32];
        accepted_payload_sha256.copy_from_slice(&hash_bytes);

        use sha2::Digest;
        let computed_hash: [u8; 32] = sha2::Sha256::digest(&event.ciphertext).into();
        if computed_hash != accepted_payload_sha256 {
            return Err(StrictCleanRemoteEventError::AcceptedPayloadHashMismatch);
        }

        let signed_request = event
            .signed_request
            .ok_or(StrictCleanRemoteEventError::MissingField("signedRequest"))?;
        if signed_request.is_empty() || signed_request.len() > 1_048_576 {
            return Err(StrictCleanRemoteEventError::InvalidSignedRequestLength(
                signed_request.len(),
            ));
        }

        let fp_bytes = event
            .outer_fingerprint
            .ok_or(StrictCleanRemoteEventError::MissingField(
                "outerFingerprint",
            ))?;
        if fp_bytes.len() != 32 {
            return Err(StrictCleanRemoteEventError::InvalidOuterFingerprintLength(
                fp_bytes.len(),
            ));
        }
        let mut outer_fingerprint = [0u8; 32];
        outer_fingerprint.copy_from_slice(&fp_bytes);

        Ok(StrictCleanRemoteEvent {
            seq: event.seq,
            generation: event.epoch,
            entry_id,
            entry_kind,
            accepted_payload_bytes: event.ciphertext,
            accepted_payload_sha256,
            signed_request,
            outer_fingerprint,
            received_at: event.created_at,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
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
    pub accepted_payload_sha256: Option<Vec<u8>>,
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
        if let Err(e) = reconcile_conversation(
            pool,
            resolver,
            outbound,
            auth_sign,
            &convo_id_str,
            &sequencer_ds,
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

#[derive(Debug, PartialEq, Eq)]
pub enum CleanDriftDecision {
    InSync,
    ApplySuffix {
        after_seq: i64,
    },
    Quarantine {
        first_mismatch_seq: i64,
        reason: &'static str,
    },
}

pub async fn reconcile_conversation(
    pool: &PgPool,
    resolver: &DsResolver,
    outbound: &OutboundClient,
    auth_sign: &(dyn Fn(&str, &str) -> Result<String, String> + Send + Sync),
    convo_id: &str,
    sequencer_ds: &str,
) -> Result<(), String> {
    if let Ok(convo_uuid) = uuid::Uuid::parse_str(convo_id) {
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
        reconcile_clean_conversation(
            pool,
            convo_uuid,
            sequencer_ds,
            &destination,
            outbound,
            auth_sign,
        )
        .await
    } else {
        reconcile_conversation_internal(
            pool,
            resolver,
            outbound,
            auth_sign,
            convo_id,
            sequencer_ds,
            false,
        )
        .await
    }
}
async fn query_remote_digest(
    outbound: &OutboundClient,
    destination: &ValidatedRemoteDestination,
    token: &str,
    convo_id: &str,
) -> Result<RemoteConvoDigest, String> {
    let json = outbound
        .call_query_json_pinned(destination, DIGEST_NSID, token, &[("convoId", convo_id)])
        .await
        .map_err(|e| format!("digest query failed: {e}"))?;
    serde_json::from_value(json).map_err(|e| format!("invalid digest response: {e}"))
}

async fn query_remote_events(
    outbound: &OutboundClient,
    destination: &ValidatedRemoteDestination,
    token: &str,
    convo_id: &str,
    after_seq: i64,
    limit: i64,
) -> Result<RemoteConvoEvents, String> {
    let after_seq_s = after_seq.to_string();
    let limit_s = limit.to_string();
    let json = outbound
        .call_query_json_pinned(
            destination,
            EVENTS_NSID,
            token,
            &[
                ("convoId", convo_id),
                ("afterSeq", &after_seq_s),
                ("limit", &limit_s),
            ],
        )
        .await
        .map_err(|e| format!("events query failed: {e}"))?;
    serde_json::from_value(json).map_err(|e| format!("invalid events response: {e}"))
}

async fn reconcile_clean_conversation(
    pool: &PgPool,
    convo_uuid: uuid::Uuid,
    sequencer_ds: &str,
    destination: &ValidatedRemoteDestination,
    outbound: &OutboundClient,
    auth_sign: &(dyn Fn(&str, &str) -> Result<String, String> + Send + Sync),
) -> Result<(), String> {
    let convo_id = convo_uuid.to_string();

    // 1. Validate remote digest
    let digest_token = auth_sign(sequencer_ds, DIGEST_NSID)
        .map_err(|e| format!("failed to sign digest request: {e}"))?;
    let remote_digest =
        query_remote_digest(outbound, destination, &digest_token, &convo_id).await?;

    let stored_routing: Option<(bool, Option<String>, i64)> = sqlx::query_as(
        "SELECT is_remote, sequencer_ds, sequencer_term FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(convo_uuid)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;

    let Some((is_remote, stored_seq_ds, stored_term)) = stored_routing else {
        return Err(format!("clean conversation {convo_id} not found locally"));
    };

    if !is_remote {
        return Err(format!(
            "clean conversation {convo_id} is not a remote mailbox"
        ));
    }

    if remote_digest.convo_id != convo_id {
        return Err(format!(
            "remote digest convo_id mismatch: expected {}, got {}",
            convo_id, remote_digest.convo_id
        ));
    }

    let stored_seq_ds_str = stored_seq_ds.unwrap_or_default();
    if canonical_did(&remote_digest.sequencer_ds_did) != canonical_did(&stored_seq_ds_str) {
        return Err(format!(
            "remote digest sequencer DID mismatch: expected {}, got {}",
            stored_seq_ds_str, remote_digest.sequencer_ds_did
        ));
    }

    if remote_digest.sequencer_term != stored_term {
        return Err(format!(
            "remote digest sequencer term mismatch: expected {}, got {}",
            stored_term, remote_digest.sequencer_term
        ));
    }

    // 2. Compute local clean snapshot in Phase A
    let local_snapshot = local_clean_digest_state(pool, convo_uuid)
        .await
        .map_err(|e| format!("local clean digest failed: {e}"))?;
    let is_same = local_snapshot.digest_sha256 == remote_digest.digest_sha256
        && local_snapshot.last_seq == remote_digest.last_seq
        && local_snapshot.last_epoch == remote_digest.epoch
        && local_snapshot.event_count == remote_digest.event_count;

    if is_same {
        let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
        let locked_convo: Option<(bool, Option<String>, i64)> = sqlx::query_as(
            "SELECT is_remote, sequencer_ds, sequencer_term FROM chat.conversations WHERE conversation_id = $1 FOR UPDATE",
        )
        .bind(convo_uuid)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        let Some((is_rem, locked_ds, locked_term)) = locked_convo else {
            return Err(format!("conversation {convo_id} missing under lock"));
        };
        if !is_rem
            || canonical_did(&locked_ds.unwrap_or_default()) != canonical_did(&stored_seq_ds_str)
            || locked_term != stored_term
        {
            return Err(format!(
                "conversation {convo_id} routing changed concurrently"
            ));
        }

        if crate::chat_protocol::repository::core::is_conversation_quarantined(&mut tx, convo_uuid)
            .await
            .map_err(|e| e.to_string())?
        {
            return Err(format!("conversation {convo_id} is quarantined"));
        }

        let current_local = local_clean_digest_state_tx(&mut tx, convo_uuid)
            .await
            .map_err(|e| e.to_string())?;
        if current_local.last_seq != local_snapshot.last_seq
            || current_local.last_epoch != local_snapshot.last_epoch
            || current_local.event_count != local_snapshot.event_count
            || current_local.digest_sha256 != local_snapshot.digest_sha256
        {
            return Err(format!(
                "concurrent local head movement during in-sync confirmation"
            ));
        }

        sqlx::query(
            r#"
            INSERT INTO federation_sync_state
                (convo_id, sequencer_ds_did, sequencer_term, last_seq, last_epoch, last_digest, last_reconciled_at, drift_count, updated_at, status)
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), 0, NOW(), 'healthy')
             ON CONFLICT (convo_id, sequencer_ds_did) DO UPDATE SET
                sequencer_term = EXCLUDED.sequencer_term,
                last_seq = EXCLUDED.last_seq,
                last_epoch = EXCLUDED.last_epoch,
                last_digest = EXCLUDED.last_digest,
                last_reconciled_at = NOW(),
                updated_at = NOW()
             WHERE federation_sync_state.status = 'healthy'
            "#,
        )
        .bind(&convo_id)
        .bind(canonical_did(&remote_digest.sequencer_ds_did))
        .bind(remote_digest.sequencer_term)
        .bind(local_snapshot.last_seq)
        .bind(local_snapshot.last_epoch)
        .bind(hex::decode(&local_snapshot.digest_sha256).unwrap_or_default())
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        tx.commit().await.map_err(|e| e.to_string())?;
        return Ok(());
    }

    metrics::counter!("federation_reconciliation_drift_total", 1, "convo_id" => convo_id.clone());

    let mut remote_hasher = crate::handlers::ds::get_convo_digest::CleanConvoDigestHasher::new();
    let mut remote_scanned_count = 0_i64;
    let mut remote_last_seq = 0_i64;
    let mut remote_last_epoch = 0_i64;

    let mut first_mismatch: Option<(i64, &'static str)> = None;
    let mut retained_suffix_chunk: Vec<StrictCleanRemoteEvent> = Vec::new();
    let mut retained_bytes: usize = 0;

    let mut cursor = 0_i64;
    while cursor < remote_digest.last_seq {
        let events_token = auth_sign(sequencer_ds, EVENTS_NSID)
            .map_err(|e| format!("failed to sign events request: {e}"))?;
        let page = query_remote_events(
            outbound,
            destination,
            &events_token,
            &convo_id,
            cursor,
            EVENTS_PAGE_LIMIT,
        )
        .await?;

        if page.events.is_empty() {
            return Err(format!(
                "events page was empty before reaching remote head (cursor={cursor}, remote_last_seq={})",
                remote_digest.last_seq
            ));
        }

        if page.events.len() > EVENTS_PAGE_LIMIT as usize {
            return Err(format!(
                "events page exceeded requested limit: got {}, max {}",
                page.events.len(),
                EVENTS_PAGE_LIMIT
            ));
        }

        if page.convo_id != convo_id {
            return Err(format!("events page convo_id mismatch"));
        }

        if page.from_seq_exclusive != cursor {
            return Err(format!("events page from_seq_exclusive mismatch"));
        }

        if page.to_seq_inclusive > remote_digest.last_seq || page.to_seq_inclusive <= cursor {
            return Err(format!("events page to_seq_inclusive out of bounds"));
        }

        let overlap_start = cursor;
        let overlap_end = std::cmp::min(page.to_seq_inclusive, local_snapshot.last_seq);
        let local_chunk_map: std::collections::BTreeMap<
            i64,
            crate::handlers::ds::get_convo_digest::CleanDigestRow,
        > = if overlap_end > overlap_start && first_mismatch.is_none() {
            let local_chunk: Vec<crate::handlers::ds::get_convo_digest::CleanDigestRow> =
                sqlx::query_as(
                    "SELECT CAST(seq AS BIGINT) AS seq, CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
                            entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, \
                            signed_request_bytes, outer_entry_fingerprint, received_at \
                     FROM chat.entries WHERE conversation_id = $1 AND seq > $2 AND seq <= $3 ORDER BY seq ASC",
                )
                .bind(convo_uuid)
                .bind(overlap_start)
                .bind(overlap_end)
                .fetch_all(pool)
                .await
                .map_err(|e| e.to_string())?;
            local_chunk.into_iter().map(|r| (r.seq, r)).collect()
        } else {
            std::collections::BTreeMap::new()
        };

        let mut expected_seq = cursor + 1;
        for event in page.events {
            let strict_event = StrictCleanRemoteEvent::try_from(event)
                .map_err(|e| format!("clean remote event failed strict conversion: {e}"))?;

            if strict_event.seq() != expected_seq {
                return Err(format!(
                    "events page sequence discontinuity: expected {expected_seq}, got {}",
                    strict_event.seq()
                ));
            }
            expected_seq += 1;

            remote_hasher.update_event(
                strict_event.seq(),
                strict_event.generation(),
                strict_event.entry_id(),
                strict_event.entry_kind_str(),
                strict_event.accepted_payload_bytes(),
                strict_event.signed_request(),
                strict_event.outer_fingerprint(),
                strict_event.received_at(),
            );
            remote_scanned_count += 1;
            remote_last_seq = strict_event.seq();
            remote_last_epoch = strict_event.generation();

            if strict_event.seq() <= local_snapshot.last_seq {
                if first_mismatch.is_none() {
                    let local_row = local_chunk_map.get(&strict_event.seq());
                    let mismatch = match local_row {
                        None => true,
                        Some(lr) => {
                            lr.seq != strict_event.seq()
                                || lr.entry_id != strict_event.entry_id()
                                || lr.epoch != strict_event.generation()
                                || lr.entry_kind != strict_event.entry_kind_str()
                                || lr.accepted_payload_bytes
                                    != strict_event.accepted_payload_bytes()
                                || lr.signed_request_bytes != strict_event.signed_request()
                                || lr.outer_entry_fingerprint != strict_event.outer_fingerprint()
                                || lr.accepted_payload_sha256
                                    != strict_event.accepted_payload_sha256().as_slice()
                                || lr.received_at.timestamp_millis()
                                    != strict_event.received_at().timestamp_millis()
                        }
                    };
                    if mismatch {
                        first_mismatch = Some((strict_event.seq(), "prefix_mismatch"));
                    }
                }
            } else {
                if first_mismatch.is_none()
                    && retained_suffix_chunk.len() < EVENTS_PAGE_LIMIT as usize
                {
                    let event_len = strict_event.accepted_payload_bytes().len()
                        + strict_event.signed_request().len()
                        + strict_event.outer_fingerprint().len()
                        + 200;
                    if retained_bytes + event_len <= ORDINARY_DS_CONTROL_MAX_BYTES {
                        retained_bytes += event_len;
                        retained_suffix_chunk.push(strict_event);
                    }
                }
            }
        }

        if expected_seq - 1 != page.to_seq_inclusive {
            return Err(format!(
                "events page last seq mismatch with to_seq_inclusive"
            ));
        }

        cursor = page.to_seq_inclusive;
    }

    if remote_scanned_count != remote_digest.event_count
        || remote_last_seq != remote_digest.last_seq
        || (remote_digest.last_seq > 0 && remote_last_epoch != remote_digest.epoch)
    {
        return Err(format!(
            "scanned remote events do not match remote digest counts"
        ));
    }

    let computed_remote_digest = remote_hasher.finalize();
    if computed_remote_digest != remote_digest.digest_sha256 {
        return Err(format!(
            "recomputed remote digest does not match advertised digest"
        ));
    }

    let decision = if let Some((mismatch_seq, reason)) = first_mismatch {
        CleanDriftDecision::Quarantine {
            first_mismatch_seq: mismatch_seq,
            reason,
        }
    } else if remote_digest.last_seq < local_snapshot.last_seq {
        CleanDriftDecision::Quarantine {
            first_mismatch_seq: remote_digest.last_seq + 1,
            reason: "local_ahead",
        }
    } else if remote_digest.last_seq > local_snapshot.last_seq {
        CleanDriftDecision::ApplySuffix {
            after_seq: local_snapshot.last_seq,
        }
    } else {
        CleanDriftDecision::InSync
    };

    match decision {
        CleanDriftDecision::InSync => Ok(()),
        CleanDriftDecision::Quarantine {
            first_mismatch_seq,
            reason,
        } => {
            let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
            let locked_convo: Option<(bool, Option<String>, i64)> = sqlx::query_as(
                "SELECT is_remote, sequencer_ds, sequencer_term FROM chat.conversations WHERE conversation_id = $1 FOR UPDATE",
            )
            .bind(convo_uuid)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;

            let Some((is_rem, locked_ds, locked_term)) = locked_convo else {
                return Err(format!("conversation {convo_id} missing under lock"));
            };

            if !is_rem
                || canonical_did(&locked_ds.unwrap_or_default())
                    != canonical_did(&stored_seq_ds_str)
                || locked_term != stored_term
            {
                return Err(format!(
                    "concurrent conversation routing modification during quarantine"
                ));
            }

            let current_local = local_clean_digest_state_tx(&mut tx, convo_uuid)
                .await
                .map_err(|e| e.to_string())?;
            if current_local.last_seq != local_snapshot.last_seq
                || current_local.digest_sha256 != local_snapshot.digest_sha256
            {
                return Err(format!("concurrent local head movement during quarantine"));
            }

            sqlx::query(
                r#"
                INSERT INTO federation_sync_state
                    (convo_id, sequencer_ds_did, sequencer_term, last_seq, last_epoch, last_digest, last_reconciled_at, drift_count, updated_at, status, quarantined_at, quarantine_reason, first_mismatch_seq)
                 VALUES ($1, $2, $3, $4, $5, $6, NOW(), 1, NOW(), 'quarantined', NOW(), $7, $8)
                 ON CONFLICT (convo_id, sequencer_ds_did) DO UPDATE SET
                    quarantined_at = COALESCE(federation_sync_state.quarantined_at, EXCLUDED.quarantined_at),
                    quarantine_reason = COALESCE(federation_sync_state.quarantine_reason, EXCLUDED.quarantine_reason),
                    first_mismatch_seq = COALESCE(federation_sync_state.first_mismatch_seq, EXCLUDED.first_mismatch_seq),
                    status = 'quarantined',
                    drift_count = federation_sync_state.drift_count + 1,
                    updated_at = NOW()
                "#,
            )
            .bind(&convo_id)
            .bind(canonical_did(&remote_digest.sequencer_ds_did))
            .bind(remote_digest.sequencer_term)
            .bind(local_snapshot.last_seq)
            .bind(local_snapshot.last_epoch)
            .bind(hex::decode(&local_snapshot.digest_sha256).unwrap_or_default())
            .bind(reason)
            .bind(first_mismatch_seq)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;

            tx.commit().await.map_err(|e| e.to_string())?;
            metrics::counter!("federation_reconciliation_quarantine_total", 1, "convo_id" => convo_id.clone(), "reason" => reason.to_string());
            Ok(())
        }
        CleanDriftDecision::ApplySuffix { after_seq } => {
            let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
            let locked_convo: Option<(bool, Option<String>, i64)> = sqlx::query_as(
                "SELECT is_remote, sequencer_ds, sequencer_term FROM chat.conversations WHERE conversation_id = $1 FOR UPDATE",
            )
            .bind(convo_uuid)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;

            let Some((is_rem, locked_ds, locked_term)) = locked_convo else {
                return Err(format!("conversation {convo_id} missing under lock"));
            };
            if !is_rem
                || canonical_did(&locked_ds.unwrap_or_default())
                    != canonical_did(&stored_seq_ds_str)
                || locked_term != stored_term
            {
                return Err(format!(
                    "conversation {convo_id} routing changed concurrently"
                ));
            }

            if crate::chat_protocol::repository::core::is_conversation_quarantined(
                &mut tx, convo_uuid,
            )
            .await
            .map_err(|e| e.to_string())?
            {
                return Err(format!("conversation {convo_id} is quarantined"));
            }

            let current_local = local_clean_digest_state_tx(&mut tx, convo_uuid)
                .await
                .map_err(|e| e.to_string())?;
            if current_local.last_seq != local_snapshot.last_seq
                || current_local.digest_sha256 != local_snapshot.digest_sha256
            {
                return Err(format!(
                    "concurrent local head movement during suffix apply"
                ));
            }

            apply_remote_clean_events(&mut tx, convo_uuid, &retained_suffix_chunk).await?;

            let new_last_seq = retained_suffix_chunk.last().map_or(after_seq, |e| e.seq());
            sqlx::query(
                "UPDATE chat.conversations SET next_entry_seq = GREATEST(next_entry_seq, $2 + 1) WHERE conversation_id = $1",
            )
            .bind(convo_uuid)
            .bind(new_last_seq)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;

            let new_local = local_clean_digest_state_tx(&mut tx, convo_uuid)
                .await
                .map_err(|e| e.to_string())?;

            let update_res = sqlx::query(
                r#"
                INSERT INTO federation_sync_state
                    (convo_id, sequencer_ds_did, sequencer_term, last_seq, last_epoch, last_digest, last_reconciled_at, drift_count, updated_at, status)
                 VALUES ($1, $2, $3, $4, $5, $6, NOW(), 1, NOW(), 'healthy')
                 ON CONFLICT (convo_id, sequencer_ds_did) DO UPDATE SET
                    sequencer_term = EXCLUDED.sequencer_term,
                    last_seq = EXCLUDED.last_seq,
                    last_epoch = EXCLUDED.last_epoch,
                    last_digest = EXCLUDED.last_digest,
                    last_reconciled_at = NOW(),
                    drift_count = federation_sync_state.drift_count + 1,
                    updated_at = NOW()
                 WHERE federation_sync_state.status = 'healthy'
                "#,
            )
            .bind(&convo_id)
            .bind(canonical_did(&remote_digest.sequencer_ds_did))
            .bind(remote_digest.sequencer_term)
            .bind(new_local.last_seq)
            .bind(new_local.last_epoch)
            .bind(hex::decode(&new_local.digest_sha256).unwrap_or_default())
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;

            if update_res.rows_affected() == 0 {
                return Err(format!(
                    "failed to update healthy sync state (quarantined concurrently)"
                ));
            }

            tx.commit().await.map_err(|e| e.to_string())?;
            metrics::counter!("federation_reconciliation_applied_total", 1, "convo_id" => convo_id.clone());
            Ok(())
        }
    }
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
    let remote_digest =
        query_remote_digest(outbound, &destination, &digest_token, convo_id).await?;
    let mut local_state = local_legacy_digest_state(pool, convo_id)
        .await
        .map_err(|e| format!("local legacy digest failed: {e}"))?;
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
            let page = query_remote_events(
                outbound,
                &destination,
                &events_token,
                convo_id,
                after_seq,
                EVENTS_PAGE_LIMIT,
            )
            .await?;
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
                .map_err(|e| format!("apply legacy events failed: {e}"))?;
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

        local_state = local_legacy_digest_state(pool, convo_id)
            .await
            .map_err(|e| format!("local legacy digest after reconcile failed: {e}"))?;
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
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    convo_id: uuid::Uuid,
    events: &[StrictCleanRemoteEvent],
) -> Result<(), String> {
    let convo_id_string = convo_id.to_string();
    for event in events {
        let entry_id = event.entry_id();
        let entry_id_str = entry_id.to_string();

        if *event.entry_kind() != CleanEntryKind::Application {
            return Err(format!(
                "unsupported clean event kind during reconciliation: {}",
                event.entry_kind_str()
            ));
        }

        let signed_req = event.signed_request();
        let outer_fp = event.outer_fingerprint();

        let mutation =
            crate::chat_protocol::transcript::decode_canonical_signed_mutation(signed_req)
                .map_err(|e| format!("invalid signedRequest for seq {}: {e:?}", event.seq()))?;

        let actor_did = mutation.actor_did().as_str();
        let actor_device_id = uuid::Uuid::from_bytes(*mutation.actor_device_id().as_bytes());
        let actor_key_id = mutation.key_id().as_str();
        let actor_auth_gen = mutation.auth_generation() as i64;
        let payload_sha256 = event.accepted_payload_sha256();

        let key_row: Option<(Vec<u8>, i64)> = sqlx::query_as(
            r#"
            SELECT dk.signing_public_key, dk.enrollment_auth_generation
              FROM chat.device_keys dk
              JOIN chat.devices d ON d.user_did = dk.user_did AND d.device_id = dk.device_id
             WHERE dk.user_did = $1 AND dk.device_id = $2 AND dk.key_id = $3
               AND dk.revoked_at IS NULL AND d.status = 'active' AND d.revoked_at IS NULL
             FOR UPDATE
            "#,
        )
        .bind(actor_did)
        .bind(actor_device_id)
        .bind(actor_key_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| format!("failed to fetch device key for seq {}: {e}", event.seq()))?;

        let Some((actor_public_key, enrollment_auth_generation)) = key_row else {
            return Err(format!(
                "actor device key {actor_key_id} not provisioned or revoked on destination DS for seq {}",
                event.seq()
            ));
        };

        if actor_auth_gen != enrollment_auth_generation {
            return Err(format!(
                "auth_generation mismatch for seq {}: expected {enrollment_auth_generation}, got {actor_auth_gen}",
                event.seq()
            ));
        }

        let verified_entry = crate::chat_protocol::transcript::decode_and_verify_application_entry(
            event.accepted_payload_bytes(),
            &actor_public_key,
        )
        .map_err(|e| {
            format!(
                "application entry verification failed for seq {}: {e:?}",
                event.seq()
            )
        })?;

        let outer_fp_32 = *event.outer_fingerprint();
        let req_digest_32: &[u8; 32] = mutation.request_digest();
        let sig_64: &[u8; 64] = mutation.signature();

        let rebound_entry = crate::chat_protocol::transcript::rebind_persisted_application_entry(
            verified_entry,
            event.accepted_payload_bytes(),
            payload_sha256,
            signed_req,
            req_digest_32,
            sig_64,
            &outer_fp_32,
            &actor_public_key,
        )
        .map_err(|e| {
            format!(
                "application entry rebind failed for seq {}: {e:?}",
                event.seq()
            )
        })?;

        let projection = match rebound_entry.mutation().projection() {
            crate::chat_protocol::transcript::VerifiedMutationProjection::ApplicationSend(p) => p,
            _ => {
                return Err(format!(
                    "not an application send mutation for seq {}",
                    event.seq()
                ))
            }
        };
        let message_id = uuid::Uuid::from_bytes(*projection.message_id().as_bytes());

        if rebound_entry.conversation_id().as_str() != convo_id_string {
            return Err(format!(
                "verified entry conversation_id {} does not match convo_id {} for seq {}",
                rebound_entry.conversation_id().as_str(),
                convo_id,
                event.seq()
            ));
        }

        if rebound_entry.seq() != event.seq() as u64 {
            return Err(format!(
                "verified entry seq {} does not match event seq {} for seq {}",
                rebound_entry.seq(),
                event.seq(),
                event.seq()
            ));
        }

        if rebound_entry.entry_id().as_str() != entry_id_str {
            return Err(format!(
                "verified entry entry_id {} does not match event entry_id {entry_id_str} for seq {}",
                rebound_entry.entry_id().as_str(),
                event.seq()
            ));
        }

        if rebound_entry.received_at().datetime().timestamp_millis()
            != event.received_at().timestamp_millis()
        {
            return Err(format!(
                "verified entry received_at {} does not match event created_at {} for seq {}",
                rebound_entry.received_at().as_str(),
                event
                    .received_at()
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                event.seq()
            ));
        }

        if rebound_entry.outer_application_fingerprint() != &outer_fp_32 {
            return Err(format!(
                "verified entry outer fingerprint mismatch for seq {}",
                event.seq()
            ));
        }

        if rebound_entry.accepted_payload_sha256() != payload_sha256 {
            return Err(format!(
                "verified entry payload sha256 mismatch for seq {}",
                event.seq()
            ));
        }

        let server_fields_bytes =
            serde_ipld_dagcbor::to_vec(&std::collections::BTreeMap::<String, String>::new())
                .map_err(|e| format!("server fields serialization failed: {e}"))?;

        let append_entry = crate::chat_protocol::repository::delivery::AppendEntry {
            conversation_id: convo_id,
            entry_id,
            entry_kind: event.entry_kind_str().to_string(),
            accepted_payload_bytes: rebound_entry.canonical_entry_bytes().to_vec(),
            accepted_payload_sha256: rebound_entry.accepted_payload_sha256().to_vec(),
            signed_request_bytes: signed_req.to_vec(),
            request_digest: rebound_entry.mutation().request_digest().to_vec(),
            signature: rebound_entry.mutation().signature().to_vec(),
            server_fields_bytes,
            outer_entry_fingerprint: rebound_entry.outer_application_fingerprint().to_vec(),
            actor_did: rebound_entry.mutation().actor_did().as_str().to_string(),
            actor_device_id: uuid::Uuid::from_bytes(
                *rebound_entry.mutation().actor_device_id().as_bytes(),
            ),
            actor_key_id: rebound_entry.mutation().key_id().as_str().to_string(),
            actor_auth_generation: rebound_entry.mutation().auth_generation() as i64,
            generation: Some(event.generation()),
            state_version: None,
            transition_id: None,
            message_id: Some(message_id),
            received_at: rebound_entry.received_at().datetime(),
        };

        crate::chat_protocol::repository::delivery::append_entry_at(
            tx,
            &append_entry,
            event.seq() as u64,
        )
        .await
        .map_err(|e| format!("failed to append entry at seq {}: {e:?}", event.seq()))?;

        let outcome_bytes = serde_json::to_vec(&serde_json::json!({
            "entry": {
                "entryId": rebound_entry.entry_id().as_str(),
                "conversationId": convo_id_string.as_str(),
                "seq": event.seq(),
                "signedRequest": serde_json::from_slice::<serde_json::Value>(signed_req)
                    .unwrap_or(serde_json::Value::Null),
                "receivedAt": rebound_entry.received_at().as_str()
            }
        }))
        .map_err(|e| format!("failed to serialize reconciled send outcome: {e}"))?;
        let outcome_sha256 = Sha256::digest(&outcome_bytes).to_vec();

        sqlx::query(
            r#"
            INSERT INTO chat.message_sends (
                conversation_id, message_id, signed_request_bytes,
                signing_transcript_bytes, request_digest, signature, status,
                accepted_entry_seq, outcome_bytes, outcome_sha256, received_at
            ) VALUES ($1, $2, $3, $4, $5, $6, 'accepted', $7, $8, $9, $10)
            "#,
        )
        .bind(convo_id)
        .bind(message_id)
        .bind(signed_req)
        .bind(mutation.transcript_bytes())
        .bind(&append_entry.request_digest)
        .bind(&append_entry.signature)
        .bind(event.seq())
        .bind(&outcome_bytes)
        .bind(&outcome_sha256)
        .bind(rebound_entry.received_at().datetime())
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            format!(
                "failed to insert message_sends for seq {}: {e}",
                event.seq()
            )
        })?;
    }
    Ok(())
}

async fn local_clean_digest_state(
    pool: &PgPool,
    convo_id: uuid::Uuid,
) -> Result<LocalDigestState, sqlx::Error> {
    use futures::StreamExt;
    let mut rows = sqlx::query_as::<_, crate::handlers::ds::get_convo_digest::CleanDigestRow>(
        "SELECT \
       CAST(seq AS BIGINT) AS seq, \
       CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
       entry_id, \
       entry_kind, \
       accepted_payload_bytes, \
       accepted_payload_sha256, \
       signed_request_bytes, \
       outer_entry_fingerprint, \
       received_at \
     FROM chat.entries \
     WHERE conversation_id = $1 \
     ORDER BY seq ASC",
    )
    .bind(convo_id)
    .fetch(pool);

    let mut hasher = crate::handlers::ds::get_convo_digest::CleanConvoDigestHasher::new();
    let mut last_seq = 0_i64;
    let mut last_epoch = 0_i64;
    let mut event_count = 0_i64;

    while let Some(row) = rows.next().await {
        let row = row?;
        last_seq = row.seq;
        last_epoch = row.epoch;
        event_count += 1;
        hasher.update_row(&row);
    }

    Ok(LocalDigestState {
        last_seq,
        last_epoch,
        event_count,
        digest_sha256: hasher.finalize(),
    })
}

async fn local_clean_digest_state_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    convo_id: uuid::Uuid,
) -> Result<LocalDigestState, sqlx::Error> {
    use futures::StreamExt;
    let mut rows = sqlx::query_as::<_, crate::handlers::ds::get_convo_digest::CleanDigestRow>(
        "SELECT \
       CAST(seq AS BIGINT) AS seq, \
       CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
       entry_id, \
       entry_kind, \
       accepted_payload_bytes, \
       accepted_payload_sha256, \
       signed_request_bytes, \
       outer_entry_fingerprint, \
       received_at \
     FROM chat.entries \
     WHERE conversation_id = $1 \
     ORDER BY seq ASC",
    )
    .bind(convo_id)
    .fetch(&mut **tx);

    let mut hasher = crate::handlers::ds::get_convo_digest::CleanConvoDigestHasher::new();
    let mut last_seq = 0_i64;
    let mut last_epoch = 0_i64;
    let mut event_count = 0_i64;

    while let Some(row) = rows.next().await {
        let row = row?;
        last_seq = row.seq;
        last_epoch = row.epoch;
        event_count += 1;
        hasher.update_row(&row);
    }

    Ok(LocalDigestState {
        last_seq,
        last_epoch,
        event_count,
        digest_sha256: hasher.finalize(),
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
                    let host = headers
                        .get("host")
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or("");
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

        let discovery = fetch_discovery_payload(&destination).await;
        assert_eq!(discovery, Some(expected));
    }

    #[test]
    fn reconciliation_does_not_contain_unpinned_http_client() {
        let source = include_str!("reconciliation.rs");
        let discovery_client_sym = ["DISCOVERY", "_CLIENT"].concat();
        let client_builder_sym = ["Client::", "builder"].concat();
        let unpinned_get_sym = [".get(&", "url).send()"].concat();
        assert!(
            !source.contains(&discovery_client_sym),
            "must not contain discovery client static"
        );
        assert!(
            !source.contains(&client_builder_sym),
            "must not build client"
        );
        assert!(
            !source.contains(&unpinned_get_sym),
            "must not send unpinned get"
        );
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

    #[test]
    fn clean_entry_kind_parses_all_fourteen_kinds_and_rejects_shorthand() {
        assert_eq!(CleanEntryKind::ALL.len(), 14);
        for kind in CleanEntryKind::ALL {
            let type_id = kind.type_id();
            assert!(type_id.starts_with("blue.catbird.chat.defs#"));
            assert_eq!(CleanEntryKind::from_type_id(type_id), Some(kind));
        }

        // Shorthand and unknown kinds must fail closed
        assert_eq!(CleanEntryKind::from_type_id("applicationEntry"), None);
        assert_eq!(CleanEntryKind::from_type_id("creationEntry"), None);
        assert_eq!(
            CleanEntryKind::from_type_id("blue.catbird.chat.defs#unknownEntry"),
            None
        );
        assert_eq!(CleanEntryKind::from_type_id(""), None);
    }

    #[test]
    fn strict_clean_remote_event_from_complete_clean_event_succeeds() {
        use sha2::Digest;
        let ciphertext = vec![10, 20, 30, 40];
        let payload_hash: [u8; 32] = sha2::Sha256::digest(&ciphertext).into();
        let event = RemoteEvent {
            seq: 1,
            epoch: 0,
            msg_id: "msg-1".to_string(),
            message_type: "blue.catbird.chat.defs#creationEntry".to_string(),
            ciphertext: ciphertext.clone(),
            padded_size: 4,
            created_at: Utc::now(),
            entry_id: Some("00000000-0000-0000-0000-000000000001".to_string()),
            entry_kind: Some("blue.catbird.chat.defs#creationEntry".to_string()),
            accepted_payload_sha256: Some(payload_hash.to_vec()),
            signed_request: Some(vec![1; 64]),
            outer_fingerprint: Some(vec![2; 32]),
        };

        let strict = StrictCleanRemoteEvent::try_from(event).expect("must convert strictly");
        assert_eq!(strict.seq(), 1);
        assert_eq!(strict.generation(), 0);
        assert_eq!(
            strict.entry_id(),
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
        );
        assert_eq!(*strict.entry_kind(), CleanEntryKind::Creation);
        assert_eq!(
            strict.entry_kind_str(),
            "blue.catbird.chat.defs#creationEntry"
        );
        assert_eq!(strict.accepted_payload_bytes(), ciphertext.as_slice());
        assert_eq!(*strict.accepted_payload_sha256(), payload_hash);
        assert_eq!(strict.signed_request(), vec![1; 64].as_slice());
        assert_eq!(*strict.outer_fingerprint(), [2u8; 32]);
    }

    #[test]
    fn strict_clean_remote_event_missing_any_field_fails() {
        use sha2::Digest;
        let ciphertext = vec![1, 2, 3];
        let payload_hash: [u8; 32] = sha2::Sha256::digest(&ciphertext).into();
        let base_event = RemoteEvent {
            seq: 1,
            epoch: 0,
            msg_id: "msg-1".to_string(),
            message_type: "blue.catbird.chat.defs#applicationEntry".to_string(),
            ciphertext,
            padded_size: 3,
            created_at: Utc::now(),
            entry_id: Some("00000000-0000-0000-0000-000000000001".to_string()),
            entry_kind: Some("blue.catbird.chat.defs#applicationEntry".to_string()),
            accepted_payload_sha256: Some(payload_hash.to_vec()),
            signed_request: Some(vec![1; 64]),
            outer_fingerprint: Some(vec![2; 32]),
        };

        // Missing entry_id
        let mut e = base_event.clone();
        e.entry_id = None;
        assert!(matches!(
            StrictCleanRemoteEvent::try_from(e),
            Err(StrictCleanRemoteEventError::MissingField("entryId"))
        ));

        // Missing entry_kind
        let mut e = base_event.clone();
        e.entry_kind = None;
        assert!(matches!(
            StrictCleanRemoteEvent::try_from(e),
            Err(StrictCleanRemoteEventError::MissingField("entryKind"))
        ));

        // Missing accepted_payload_sha256
        let mut e = base_event.clone();
        e.accepted_payload_sha256 = None;
        assert!(matches!(
            StrictCleanRemoteEvent::try_from(e),
            Err(StrictCleanRemoteEventError::MissingField(
                "acceptedPayloadSha256"
            ))
        ));

        // Missing signed_request
        let mut e = base_event.clone();
        e.signed_request = None;
        assert!(matches!(
            StrictCleanRemoteEvent::try_from(e),
            Err(StrictCleanRemoteEventError::MissingField("signedRequest"))
        ));

        // Missing outer_fingerprint
        let mut e = base_event.clone();
        e.outer_fingerprint = None;
        assert!(matches!(
            StrictCleanRemoteEvent::try_from(e),
            Err(StrictCleanRemoteEventError::MissingField(
                "outerFingerprint"
            ))
        ));
    }

    #[test]
    fn strict_clean_remote_event_validation_negatives() {
        use sha2::Digest;
        let ciphertext = vec![1, 2, 3];
        let payload_hash: [u8; 32] = sha2::Sha256::digest(&ciphertext).into();
        let base = RemoteEvent {
            seq: 1,
            epoch: 0,
            msg_id: "msg-1".to_string(),
            message_type: "blue.catbird.chat.defs#applicationEntry".to_string(),
            ciphertext,
            padded_size: 3,
            created_at: Utc::now(),
            entry_id: Some("00000000-0000-0000-0000-000000000001".to_string()),
            entry_kind: Some("blue.catbird.chat.defs#applicationEntry".to_string()),
            accepted_payload_sha256: Some(payload_hash.to_vec()),
            signed_request: Some(vec![1; 64]),
            outer_fingerprint: Some(vec![2; 32]),
        };

        // Invalid entry_id (not a UUID)
        let mut e = base.clone();
        e.entry_id = Some("not-a-uuid".to_string());
        assert!(matches!(
            StrictCleanRemoteEvent::try_from(e),
            Err(StrictCleanRemoteEventError::InvalidEntryId(_))
        ));

        // Non-canonical UUID: uppercase
        let mut e = base.clone();
        e.entry_id = Some("00000000-0000-0000-0000-00000000000a".to_uppercase());
        assert!(matches!(
            StrictCleanRemoteEvent::try_from(e),
            Err(StrictCleanRemoteEventError::InvalidEntryId(_))
        ));

        // Non-canonical UUID: simple (no hyphens)
        let mut e = base.clone();
        e.entry_id = Some("00000000000000000000000000000001".to_string());
        assert!(matches!(
            StrictCleanRemoteEvent::try_from(e),
            Err(StrictCleanRemoteEventError::InvalidEntryId(_))
        ));

        // Non-canonical UUID: braced
        let mut e = base.clone();
        e.entry_id = Some("{00000000-0000-0000-0000-000000000001}".to_string());
        assert!(matches!(
            StrictCleanRemoteEvent::try_from(e),
            Err(StrictCleanRemoteEventError::InvalidEntryId(_))
        ));

        // Non-canonical UUID: URN
        let mut e = base.clone();
        e.entry_id = Some("urn:uuid:00000000-0000-0000-0000-000000000001".to_string());
        assert!(matches!(
            StrictCleanRemoteEvent::try_from(e),
            Err(StrictCleanRemoteEventError::InvalidEntryId(_))
        ));

        // Shorthand entry_kind
        let mut e = base.clone();
        e.entry_kind = Some("applicationEntry".to_string());
        assert!(matches!(
            StrictCleanRemoteEvent::try_from(e),
            Err(StrictCleanRemoteEventError::InvalidEntryKind(_))
        ));

        // Unknown entry_kind
        let mut e = base.clone();
        e.entry_kind = Some("blue.catbird.chat.defs#unknownEntry".to_string());
        assert!(matches!(
            StrictCleanRemoteEvent::try_from(e),
            Err(StrictCleanRemoteEventError::InvalidEntryKind(_))
        ));

        // Wrong accepted_payload_sha256 length (31 bytes)
        let mut e = base.clone();
        e.accepted_payload_sha256 = Some(vec![0; 31]);
        assert!(matches!(
            StrictCleanRemoteEvent::try_from(e),
            Err(StrictCleanRemoteEventError::InvalidAcceptedPayloadHashLength(31))
        ));

        // Wrong outer_fingerprint length (33 bytes)
        let mut e = base.clone();
        e.outer_fingerprint = Some(vec![0; 33]);
        assert!(matches!(
            StrictCleanRemoteEvent::try_from(e),
            Err(StrictCleanRemoteEventError::InvalidOuterFingerprintLength(
                33
            ))
        ));

        // Empty signed_request (0 bytes)
        let mut e = base.clone();
        e.signed_request = Some(vec![]);
        assert!(matches!(
            StrictCleanRemoteEvent::try_from(e),
            Err(StrictCleanRemoteEventError::InvalidSignedRequestLength(0))
        ));

        // Oversized signed_request (> 1_048_576 bytes)
        let mut e = base.clone();
        e.signed_request = Some(vec![0; 1_048_577]);
        assert!(matches!(
            StrictCleanRemoteEvent::try_from(e),
            Err(StrictCleanRemoteEventError::InvalidSignedRequestLength(
                1_048_577
            ))
        ));

        // Accepted payload hash mismatch
        let mut e = base.clone();
        e.accepted_payload_sha256 = Some(vec![0xFF; 32]);
        assert!(matches!(
            StrictCleanRemoteEvent::try_from(e),
            Err(StrictCleanRemoteEventError::AcceptedPayloadHashMismatch)
        ));
    }
}
