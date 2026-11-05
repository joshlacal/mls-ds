//! Sequencer-to-home S2S fan-out for accepted group entries (`D1`, `I13`, `I14`).
//!
//! Captures exact remote recipient homes and devices inside the sequencer's
//! transaction (before any `I14` operational wipe on `closeConversation`) and
//! durably queues `blue.catbird.mlsDS.deliverGroupEntry` for each home in that
//! same transaction. Every send leaves through one ordered stream per
//! (conversation, home): only its lowest pending entry is ever claimed, an
//! in-flight head blocks its successors, and a failed head backs off in place.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::{
    group_relay::{
        configured_group_relay_hmac_secret, deliver_group_entry_to_remote_home,
        DeliverGroupEntryRequest,
    },
    outbound::OutboundError,
    queue::{
        backoff_delay, claim_due_heads, is_outbound_predecessor_gap, mark_item_dead,
        mark_item_delivered, schedule_item_retry, OutboundQueue, StreamHead,
    },
    receipt::I13ReceiptSigner,
    resolver::DsResolver,
};
use crate::{
    identity::{canonical_did, dids_equivalent, self_endpoint, service_did_base},
    storage::DbPool,
};

const DELIVER_GROUP_ENTRY_NSID: &str = "blue.catbird.mlsDS.deliverGroupEntry";

#[derive(Debug, Clone)]
struct RemoteHomeTarget {
    remote_home_did: String,
    request: DeliverGroupEntryRequest,
}

#[derive(Debug, Clone)]
pub struct PreparedGroupEntryFanout {
    sequencer_did: String,
    targets: Vec<RemoteHomeTarget>,
    /// Per home, the lease of a delivery a close's operational wipe discards
    /// while in flight; the close is not due before it ends.
    not_before: BTreeMap<String, DateTime<Utc>>,
}

/// Capture exact remote-home group entry recipients inside `tx` while durable
/// conversation, interval, and control-recipient rows are still present, and
/// queue each home's delivery in `tx`. A close is queued by
/// [`PreparedGroupEntryFanout::enqueue`] after its operational wipe, which
/// empties the conversation's queue.
pub async fn prepare_group_entry_fanout(
    tx: &mut Transaction<'_, Postgres>,
    entry_or_response: &Value,
) -> Result<Option<PreparedGroupEntryFanout>, String> {
    prepare_fanout(tx, entry_or_response, None).await
}

/// [`prepare_group_entry_fanout`] for a close of a direct pair this DS
/// coordinates (C33). A C33 coordinator records no home for a party, so
/// `peer`'s devices in the close's audience are addressed at `home`, its
/// transport-only home resolved from its declaration before the close's
/// transaction (M-F04).
pub async fn prepare_c33_close_fanout(
    tx: &mut Transaction<'_, Postgres>,
    close_response: &Value,
    peer: &str,
    home: &str,
) -> Result<Option<PreparedGroupEntryFanout>, String> {
    prepare_fanout(tx, close_response, Some((peer, home))).await
}

async fn prepare_fanout(
    tx: &mut Transaction<'_, Postgres>,
    entry_or_response: &Value,
    c33: Option<(&str, &str)>,
) -> Result<Option<PreparedGroupEntryFanout>, String> {
    let raw_entry = entry_or_response
        .pointer("/result/entry")
        .or_else(|| entry_or_response.get("entry"))
        .unwrap_or(entry_or_response);
    let Some(convo_id) = raw_entry
        .get("conversationId")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
    else {
        return Ok(None);
    };
    let Some(seq) = raw_entry.get("seq").and_then(Value::as_i64) else {
        return Ok(None);
    };

    let head: Option<(String, bool, i64)> = sqlx::query_as(
        "SELECT kind, is_remote, current_generation \
           FROM chat.conversations \
          WHERE conversation_id = $1",
    )
    .bind(convo_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| format!("group fanout head lookup failed: {e}"))?;
    let Some((kind, is_remote, current_generation)) = head else {
        return Ok(None);
    };
    if is_remote {
        return Ok(None);
    }

    let sequencer_did = service_did_base();
    let generation = raw_entry
        .get("generation")
        .or_else(|| raw_entry.pointer("/signedRequest/body/prior/generation"))
        .and_then(Value::as_i64)
        .unwrap_or(current_generation);

    let mut entry = raw_entry.clone();
    let is_application = entry.get("$type").and_then(Value::as_str)
        == Some("blue.catbird.chat.defs#applicationEntry")
        || (entry.get("$type").is_none()
            && entry
                .pointer("/signedRequest/body/$type")
                .and_then(Value::as_str)
                == Some("blue.catbird.chat.defs#applicationSendBody"));
    if is_application && entry.get("$type").is_none() {
        entry["$type"] = json!("blue.catbird.chat.defs#applicationEntry");
    }
    let is_close = entry.get("$type").and_then(Value::as_str)
        == Some("blue.catbird.chat.defs#conversationCloseEntry")
        || entry
            .pointer("/signedRequest/body/$type")
            .and_then(Value::as_str)
            == Some("blue.catbird.chat.defs#conversationCloseBody");
    if kind != "group" && !is_close {
        return Ok(None);
    }
    let (c33_peer, c33_home) = c33.filter(|_| kind == "direct" && is_close).unzip();

    let rows: Vec<(String, Uuid, String)> = if is_application {
        sqlx::query_as(
            "SELECT DISTINCT ai.recipient_did, ai.recipient_device_id, p.ds_did \
               FROM chat.application_intervals ai \
               JOIN chat.participants p \
                 ON p.conversation_id = ai.conversation_id \
                AND p.user_did = ai.recipient_did \
              WHERE ai.conversation_id = $1 \
                AND ai.generation = $2 \
                AND ai.start_seq <= $3 \
                AND (ai.terminal_seq IS NULL OR $3 <= ai.terminal_seq) \
                AND p.ds_did IS NOT NULL \
              ORDER BY ai.recipient_did ASC, ai.recipient_device_id ASC",
        )
        .bind(convo_id)
        .bind(generation)
        .bind(seq)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| format!("group application fanout audience query failed: {e}"))?
    } else {
        sqlx::query_as(
            "SELECT er.user_did, er.device_id, \
                    COALESCE(p.ds_did, CASE WHEN p.user_did = $3 THEN $4 END) \
               FROM chat.entry_recipients er \
               JOIN chat.participants p \
                 ON p.conversation_id = er.conversation_id \
                AND p.user_did = er.user_did \
              WHERE er.conversation_id = $1 AND er.seq = $2 \
                AND COALESCE(p.ds_did, CASE WHEN p.user_did = $3 THEN $4 END) IS NOT NULL \
             UNION \
             SELECT p.user_did, d.device_id, \
                    COALESCE(p.ds_did, CASE WHEN p.user_did = $3 THEN $4 END) \
               FROM chat.participants p JOIN chat.devices d ON d.user_did = p.user_did \
              WHERE p.conversation_id = $1 AND p.current_membership \
                AND COALESCE(p.ds_did, CASE WHEN p.user_did = $3 THEN $4 END) IS NOT NULL \
                AND NOT EXISTS(SELECT 1 FROM chat.member_devices m \
                                WHERE m.conversation_id = p.conversation_id \
                                  AND m.user_did = p.user_did AND m.active) \
                AND d.status = 'active' AND d.revoked_at IS NULL \
             ORDER BY 1, 2",
        )
        .bind(convo_id)
        .bind(seq)
        .bind(c33_peer)
        .bind(c33_home)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| format!("group control fanout audience query failed: {e}"))?
    };

    let mut by_ds: BTreeMap<String, (BTreeSet<String>, Vec<(String, Uuid)>)> = BTreeMap::new();
    for (user_did, device_id, raw_ds_did) in rows {
        let ds_norm = canonical_did(&raw_ds_did).to_string();
        if ds_norm.is_empty() || dids_equivalent(&ds_norm, &sequencer_did) {
            continue;
        }
        let bucket = by_ds.entry(ds_norm).or_default();
        bucket.0.insert(user_did.clone());
        if !bucket
            .1
            .iter()
            .any(|(d, dev)| d == &user_did && *dev == device_id)
        {
            bucket.1.push((user_did, device_id));
        }
    }

    if by_ds.is_empty() {
        return Ok(None);
    }

    let space_uri: String = sqlx::query_scalar(
        "SELECT space_uri FROM chat.conversation_spaces \
          WHERE conversation_id = $1 AND generation = $2",
    )
    .bind(convo_id)
    .bind(generation)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| format!("group fanout space lookup failed: {e}"))?
    .unwrap_or_else(|| {
        format!("at://{sequencer_did}/space/blue.catbird.labyrinth.conversation/{convo_id}-{generation}")
    });

    let targets = by_ds
        .into_iter()
        .map(|(remote_home_did, (dids, devices))| RemoteHomeTarget {
            remote_home_did,
            request: DeliverGroupEntryRequest {
                conversation_id: convo_id,
                generation,
                space_uri: space_uri.clone(),
                recipient_dids: dids.into_iter().collect(),
                recipient_devices: devices,
                entry: entry.clone(),
                close_authority: None,
            },
        })
        .collect();
    let mut fanout = PreparedGroupEntryFanout {
        sequencer_did,
        targets,
        not_before: BTreeMap::new(),
    };
    if !is_close {
        fanout.enqueue(tx).await?;
        return Ok(Some(fanout));
    }
    // The close's wipe discards this conversation's queue. Lock it so no
    // delivery starts unseen, and keep each home's in-flight lease.
    let queued: Vec<(String, String, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT target_ds_did, status, claim_expires_at FROM outbound_queue \
          WHERE convo_id = $1 FOR UPDATE",
    )
    .bind(convo_id.to_string())
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| format!("group close queue lock failed: {e}"))?;
    for (home, status, lease) in queued {
        if let (true, Some(lease)) = (status == "in_flight", lease) {
            let due = fanout.not_before.entry(home).or_insert(lease);
            *due = (*due).max(lease);
        }
    }
    Ok(Some(fanout))
}

/// Attach terminal authority only after the local sequencer has applied the
/// authorized group close, while its complete roster/device graph is locked.
pub async fn attach_close_authority(
    tx: &mut Transaction<'_, Postgres>,
    fanout: &mut PreparedGroupEntryFanout,
    close_entry: &Value,
    signer: &I13ReceiptSigner,
) -> Result<(), String> {
    let uuid_at = |path: &str| {
        close_entry
            .pointer(path)
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or_else(|| format!("invalid terminal close {path}"))
    };
    let conversation_id = uuid_at("/conversationId")?;
    let transition_id = uuid_at("/signedRequest/body/transitionId")?;
    let actor_device_id = uuid_at("/signedRequest/body/actorDeviceId")?;
    let actor_did = close_entry
        .pointer("/signedRequest/body/actorDid")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing terminal close actorDid".to_string())?;
    let actor_key_id = close_entry
        .pointer("/signedRequest/body/keyId")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing terminal close keyId".to_string())?;
    let auth_generation = close_entry
        .pointer("/signedRequest/body/authGeneration")
        .and_then(Value::as_i64)
        .ok_or_else(|| "missing terminal close authGeneration".to_string())?;
    let terminal_seq = close_entry
        .get("seq")
        .and_then(Value::as_i64)
        .ok_or_else(|| "missing terminal close seq".to_string())?;
    let generation = close_entry
        .pointer("/signedRequest/body/retired/generation")
        .and_then(Value::as_i64)
        .ok_or_else(|| "missing terminal close generation".to_string())?;
    let state_version = close_entry
        .pointer("/signedRequest/body/retired/stateVersion")
        .and_then(Value::as_i64)
        .ok_or_else(|| "missing terminal close stateVersion".to_string())?;
    let closed_at = close_entry
        .get("receivedAt")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<chrono::DateTime<chrono::Utc>>().ok())
        .ok_or_else(|| "missing terminal close receivedAt".to_string())?;
    if signer.sequencer_did() != fanout.sequencer_did
        || fanout.targets.iter().any(|target| {
            target.request.conversation_id != conversation_id
                || target.request.generation != generation
                || &target.request.entry != close_entry
        })
    {
        return Err("terminal close fanout or receipt-signer mismatch".to_string());
    }

    // Local heads deliberately store sequencer_ds=NULL. Their identity is the
    // runtime service DID frozen by prepare_group_entry_fanout, not a caller DID.
    let applied: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM chat.conversations \
          WHERE conversation_id = $1 AND kind = 'group' AND NOT is_remote \
            AND sequencer_ds IS NULL AND lifecycle = 'superseded' \
            AND close_transition_id = $2 AND close_seq = $3 \
            AND close_generation = $4 AND close_state_version = $5 AND closed_at = $6 \
          FOR UPDATE",
    )
    .bind(conversation_id)
    .bind(transition_id)
    .bind(terminal_seq)
    .bind(generation)
    .bind(state_version)
    .bind(closed_at)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| format!("terminal close applied-head lookup failed: {error}"))?;
    if applied.is_none() {
        return Err("terminal close has not been applied by this sequencer".to_string());
    }
    let roster: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT user_did, status, role FROM chat.participants \
          WHERE conversation_id = $1 AND current_membership \
          ORDER BY convert_to(user_did, 'UTF8') FOR SHARE",
    )
    .bind(conversation_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| format!("terminal close final-roster lookup failed: {error}"))?;
    if !matches!(roster.as_slice(), [(did, status, role)]
        if did == actor_did && status == "active" && role == "admin")
    {
        return Err("terminal group close requires its sole active administrator".to_string());
    }
    let signing_key: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT k.signing_public_key \
           FROM chat.devices d \
           JOIN chat.device_keys k ON k.user_did = d.user_did AND k.device_id = d.device_id \
          WHERE d.user_did = $1 AND d.device_id = $2 \
            AND d.status = 'active' AND d.revoked_at IS NULL AND d.auth_generation = $3 \
            AND k.key_id = $4 AND k.revoked_at IS NULL \
            AND k.enrollment_auth_generation <= d.auth_generation \
            AND NOT EXISTS (SELECT 1 FROM chat.device_keys newer \
                 WHERE newer.user_did = d.user_did AND newer.device_id = d.device_id \
                   AND newer.enrollment_auth_generation <= d.auth_generation \
                   AND newer.enrollment_auth_generation > k.enrollment_auth_generation) \
          FOR SHARE OF d, k",
    )
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(auth_generation)
    .bind(actor_key_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| format!("terminal close current-device lookup failed: {error}"))?;
    let signing_key = signing_key.ok_or_else(|| {
        "terminal close actor does not have the current active signing key".to_string()
    })?;
    let entry_bytes = serde_json::to_vec(close_entry).map_err(|error| error.to_string())?;
    let verified = crate::chat_protocol::transcript::decode_and_verify_control_entry(
        &entry_bytes,
        &signing_key,
    )
    .map_err(|error| format!("terminal close current-device signature failed: {error:?}"))?;
    if verified.mutation().kind()
        != crate::chat_protocol::transcript::SignedMutationKind::ConversationClose
    {
        return Err("terminal close authority requires a close control entry".to_string());
    }
    let authority = signer.sign_terminal_close_authority(conversation_id, close_entry)?;
    for target in &mut fanout.targets {
        target.request.close_authority = Some(authority.clone());
    }
    Ok(())
}

#[cfg(test)]
impl PreparedGroupEntryFanout {
    /// One home's capture of `request`, as `prepare_group_entry_fanout` makes it.
    pub(crate) fn for_test(
        sequencer_did: &str,
        remote_home_did: &str,
        request: DeliverGroupEntryRequest,
    ) -> Self {
        Self {
            sequencer_did: canonical_did(sequencer_did).to_string(),
            targets: vec![RemoteHomeTarget {
                remote_home_did: remote_home_did.to_string(),
                request,
            }],
            not_before: BTreeMap::new(),
        }
    }
}

impl PreparedGroupEntryFanout {
    /// Queue each home's delivery in `tx`, the entry's sequencing transaction,
    /// due now or, for a close, once any delivery its wipe discarded in flight
    /// has ended. A replay re-queues nothing still queued.
    pub async fn enqueue(&self, tx: &mut Transaction<'_, Postgres>) -> Result<(), String> {
        let now = crate::sim_hooks::current_utc();
        for target in &self.targets {
            let home = canonical_did(&target.remote_home_did);
            let conversation_id = target.request.conversation_id;
            let seq = target
                .request
                .entry
                .get("seq")
                .and_then(Value::as_i64)
                .ok_or("group entry without seq")?;
            let payload = serde_json::to_vec(&target.request).map_err(|e| e.to_string())?;
            let due = self
                .not_before
                .get(home)
                .map_or(now, |lease| now.max(*lease));
            sqlx::query(
                "INSERT INTO outbound_queue (id, target_ds_did, target_endpoint, method, payload, convo_id, next_retry_at, created_at) \
                 SELECT $1, $2, '', $3, $4, $5, $6, $7 \
                  WHERE NOT EXISTS (SELECT 1 FROM outbound_queue WHERE id = $1) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(format!("group-entry-{conversation_id}-{seq}-{home}"))
            .bind(home)
            .bind(DELIVER_GROUP_ENTRY_NSID)
            .bind(payload)
            .bind(conversation_id.to_string())
            .bind(due)
            .bind(now)
            .execute(&mut **tx)
            .await
            .map_err(|e| format!("queue group entry for {home}: {e}"))?;
        }
        Ok(())
    }

    /// Post-commit: drain each home's stream from its head. This never sends
    /// an entry while an earlier one of its stream is pending, in flight or
    /// backing off; the queue worker retries whatever is left.
    pub async fn deliver(self, pool: &DbPool, resolver: Option<&DsResolver>) -> Result<(), String> {
        let owned_resolver = if resolver.is_none() {
            let http = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .map_err(|e| e.to_string())?;
            Some(DsResolver::new(
                pool.clone(),
                http,
                self.sequencer_did.clone(),
                self_endpoint(),
                None,
                300,
            ))
        } else {
            None
        };
        let eff_resolver = resolver.or(owned_resolver.as_ref()).expect("resolver");
        let secret = configured_group_relay_hmac_secret().unwrap_or_default();

        let mut first_err: Option<String> = None;
        for target in &self.targets {
            let home = canonical_did(&target.remote_home_did);
            let conversation_id = target.request.conversation_id.to_string();
            let stream = StreamHead {
                convo_id: &conversation_id,
                target_ds_did: home,
                method: DELIVER_GROUP_ENTRY_NSID,
            };
            if let Err(error) =
                drain_stream(pool, eff_resolver, &self.sequencer_did, &secret, stream).await
            {
                tracing::warn!(
                    remote_home_did = %home,
                    conversation_id = %conversation_id,
                    %error,
                    "deliverGroupEntry fan-out failed"
                );
                first_err.get_or_insert(error);
            }
        }
        first_err.map_or(Ok(()), Err)
    }
}

/// Send `stream`'s due head, then each successor, until the stream is empty,
/// its head is in flight elsewhere or not yet due, or a send fails.
async fn drain_stream(
    pool: &DbPool,
    resolver: &DsResolver,
    sequencer_did: &str,
    secret: &str,
    stream: StreamHead<'_>,
) -> Result<(), String> {
    // Paused while the federation gate is closed: the stream stays pending
    // for the outbound worker, which sends it once the gate reopens.
    if super::peer_policy::ensure_federation_open().is_err() {
        return Ok(());
    }
    let home = stream.target_ds_did;
    while let Some(item) = claim_due_heads(pool, 1, Some(stream))
        .await
        .map_err(|e| e.to_string())?
        .pop()
    {
        let sent = match serde_json::from_slice::<DeliverGroupEntryRequest>(&item.payload) {
            Ok(request) => match resolver.resolve_ds_destination_uncached(home).await {
                Ok(dest) => {
                    deliver_group_entry_to_remote_home(
                        dest.url.as_str(),
                        sequencer_did,
                        home,
                        secret.as_bytes(),
                        &request,
                    )
                    .await
                }
                Err(err) => Err(OutboundQueue::outbound_error_from_federation_error(
                    &err, home,
                )),
            },
            Err(err) => Err(OutboundError::InvalidResponse {
                reason: format!("invalid queued group entry: {err}"),
            }),
        };
        if let Err(error) = sent {
            let reason = error.to_string();
            // A federation gate that closed mid-drain, or a predecessor gap at
            // the home, is retried in order without consuming an attempt; any
            // other failure that could not answer now is retried with backoff
            // however often it recurs. A permanent answer ends the entry.
            let unconsumed = matches!(error, OutboundError::FederationDisabled { .. })
                || is_outbound_predecessor_gap(&error);
            if unconsumed || error.is_retryable() {
                schedule_item_retry(
                    pool,
                    &item.id,
                    item.claim_token,
                    item.retry_count + i32::from(!unconsumed),
                    &reason,
                    backoff_delay(item.retry_count),
                )
                .await
                .map_err(|e| e.to_string())?;
            } else {
                mark_item_dead(pool, &item.id, item.claim_token, &reason)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            return Err(reason);
        }
        mark_item_delivered(pool, &item.id, item.claim_token)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
