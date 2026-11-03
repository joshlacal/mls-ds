//! Sequencer-to-home S2S fan-out for accepted group entries (`D1`, `I13`, `I14`).
//!
//! Captures exact remote recipient homes and devices inside the sequencer's
//! transaction (before any `I14` operational wipe on `closeConversation`) and
//! dispatches `blue.catbird.mlsDS.deliverGroupEntry` strictly post-commit.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::{
    canonical_relay::configured_s2s_signing_key_pem,
    group_relay::{
        configured_group_relay_hmac_secret, deliver_group_entry_to_remote_home,
        DeliverGroupEntryRequest,
    },
    resolver::DsResolver,
    FederationMode,
};
use crate::{
    identity::{canonical_did, dids_equivalent, self_endpoint, service_did_base},
    storage::DbPool,
};

#[derive(Debug, Clone)]
struct RemoteHomeTarget {
    remote_home_did: String,
    request: DeliverGroupEntryRequest,
}

#[derive(Debug, Clone)]
pub struct PreparedGroupEntryFanout {
    sequencer_did: String,
    targets: Vec<RemoteHomeTarget>,
}

/// Capture exact remote-home group entry recipients inside `tx` while durable
/// conversation, interval, and control-recipient rows are still present.
pub async fn prepare_group_entry_fanout(
    tx: &mut Transaction<'_, Postgres>,
    entry_or_response: &Value,
) -> Result<Option<PreparedGroupEntryFanout>, String> {
    if !FederationMode::effective().allows_remote_traffic() {
        return Ok(None);
    }
    let has_s2s_auth =
        configured_group_relay_hmac_secret().is_some() || configured_s2s_signing_key_pem().is_ok();
    if !has_s2s_auth {
        return Ok(None);
    }

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
            "SELECT er.user_did, er.device_id, p.ds_did \
               FROM chat.entry_recipients er \
               JOIN chat.participants p \
                 ON p.conversation_id = er.conversation_id \
                AND p.user_did = er.user_did \
              WHERE er.conversation_id = $1 AND er.seq = $2 AND p.ds_did IS NOT NULL \
             UNION \
             SELECT p.user_did, d.device_id, p.ds_did \
               FROM chat.participants p JOIN chat.devices d ON d.user_did = p.user_did \
              WHERE p.conversation_id = $1 AND p.current_membership AND p.ds_did IS NOT NULL \
                AND NOT EXISTS(SELECT 1 FROM chat.member_devices m \
                                WHERE m.conversation_id = p.conversation_id \
                                  AND m.user_did = p.user_did AND m.active) \
                AND d.status = 'active' AND d.revoked_at IS NULL \
             ORDER BY 1, 2",
        )
        .bind(convo_id)
        .bind(seq)
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
            },
        })
        .collect();

    Ok(Some(PreparedGroupEntryFanout {
        sequencer_did,
        targets,
    }))
}

impl PreparedGroupEntryFanout {
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
        for target in self.targets {
            let endpoint = match eff_resolver
                .resolve_ds_destination_uncached(&target.remote_home_did)
                .await
            {
                Ok(dest) => dest.url.to_string(),
                Err(err) => {
                    let msg = format!(
                        "resolve remote home {} failed: {err}",
                        target.remote_home_did
                    );
                    tracing::warn!("{msg}");
                    if first_err.is_none() {
                        first_err = Some(msg);
                    }
                    continue;
                }
            };
            if let Err(err) = deliver_group_entry_to_remote_home(
                &endpoint,
                &self.sequencer_did,
                &target.remote_home_did,
                secret.as_bytes(),
                &target.request,
            )
            .await
            {
                tracing::warn!(
                    remote_home_did = %target.remote_home_did,
                    conversation_id = %target.request.conversation_id,
                    error = %err,
                    "deliverGroupEntry fan-out failed"
                );
                if let Ok(payload) = serde_json::to_vec(&target.request) {
                    let seq = target
                        .request
                        .entry
                        .get("seq")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    let queue_id = format!(
                        "group-entry-{}-{seq}-{}",
                        target.request.conversation_id,
                        canonical_did(&target.remote_home_did)
                    );
                    let _ = sqlx::query(
                        "INSERT INTO outbound_queue (id, target_ds_did, target_endpoint, method, payload, convo_id, last_error, next_retry_at, created_at) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8 + INTERVAL '5 seconds', $8) \
                         ON CONFLICT (id) DO NOTHING",
                    )
                    .bind(&queue_id)
                    .bind(canonical_did(&target.remote_home_did))
                    .bind(&endpoint)
                    .bind("blue.catbird.mlsDS.deliverGroupEntry")
                    .bind(payload)
                    .bind(target.request.conversation_id.to_string())
                    .bind(&err)
                    .bind(crate::sim_hooks::current_utc())
                    .execute(pool)
                    .await;
                }
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
        }
        if let Some(err) = first_err {
            return Err(err);
        }
        Ok(())
    }
}
