// Repository-owned `getEntries` read composition.

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::delivery::{self, DeliveredEntryRow, DeliveryRepositoryError};
use crate::chat_protocol::{
    dpop::VerifiedReadAdmission,
    read_authority::{self, EntryReadAuthority, ReadAuthorityError},
    read_projection::encode_canonical_generated_chat_json_v1,
};
use crate::federation::receipt::{
    AccountDeletion, AccountDeletionActorWrite, AccountDeletionAuthority, AccountDeletionEvidence,
};

/// `chat.entries.server_fields_bytes` of an `accountDeletedEntry` (DAG-CBOR): what its
/// signed entry holds beyond the row, so every read rebuilds exactly what was signed.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AccountDeletedServerFields {
    pub(crate) deleted_did: String,
    pub(crate) sequencer_did: String,
    pub(crate) sequencer_authority: AccountDeletionAuthority,
    /// Optional lexicon `actorWrite`, stored verbatim when present. Absent on rows
    /// written without it, which keep their exact stored bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) actor_write: Option<AccountDeletionActorWrite>,
    /// Optional lexicon `keyProof`, stored verbatim when present.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::atproto_bytes::option"
    )]
    pub(crate) key_proof: Option<Vec<u8>>,
    /// Optional lexicon `revocationProof`, stored verbatim when present.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::atproto_bytes::option"
    )]
    pub(crate) revocation_proof: Option<Vec<u8>>,
}

impl AccountDeletedServerFields {
    /// The signed entry of the row `(conversation_id, seq, entry_id, received_at)`.
    pub(crate) fn entry(
        self,
        conversation_id: Uuid,
        seq: i64,
        entry_id: Uuid,
        received_at: DateTime<Utc>,
    ) -> Value {
        AccountDeletion {
            sequencer_did: self.sequencer_did,
            conversation_id,
            deleted_did: self.deleted_did,
            seq,
            entry_id,
            deleted_at: received_at,
            // Stored `keyProof` / `revocationProof` only ever accompany `actorWrite`.
            evidence: self.actor_write.map(|actor_write| AccountDeletionEvidence {
                actor_write,
                key_proof: self.key_proof,
                revocation_proof: self.revocation_proof,
            }),
        }
        .entry(&self.sequencer_authority)
    }
}

// A home's standing in its sequencer-authenticated remote-group membership
// index (`chat.remote_group_memberships`, written by the federation layer).
/// A home's read standing for `user_did` in remote group `conversation_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteGroupStanding {
    /// No index row: the clean graph alone decides.
    Untracked,
    /// A pending or active member the clean graph also lists.
    CleanMember,
    /// A pending or active member only the index knows.
    IndexOnly,
    /// Removed, left or deleted: it reads nothing here.
    Removed,
}

/// Classify `user_did` in `conversation_id` without failing on a pinned
/// schema that predates the index.
pub(crate) async fn remote_group_standing(
    executor: &mut sqlx::PgConnection,
    conversation_id: Uuid,
    user_did: &str,
) -> Result<RemoteGroupStanding, sqlx::Error> {
    let indexed: bool =
        sqlx::query_scalar("SELECT to_regclass('chat.remote_group_memberships') IS NOT NULL")
            .fetch_one(&mut *executor)
            .await?;
    if !indexed {
        return Ok(RemoteGroupStanding::Untracked);
    }
    let row: Option<(String, bool)> = sqlx::query_as(
        "SELECT m.status, EXISTS(SELECT 1 FROM chat.participants p \
                 WHERE p.conversation_id = m.conversation_id AND p.user_did = m.user_did \
                   AND p.current_membership) \
           FROM chat.remote_group_memberships m \
           JOIN chat.conversations c \
             ON c.conversation_id = m.conversation_id AND c.kind = 'group' AND c.is_remote \
            AND c.sequencer_ds = m.sequencer_did \
          WHERE m.conversation_id = $1 AND m.user_did = $2",
    )
    .bind(conversation_id)
    .bind(user_did)
    .fetch_optional(&mut *executor)
    .await?;
    Ok(match row {
        None => RemoteGroupStanding::Untracked,
        Some((status, _)) if status == "removed" => RemoteGroupStanding::Removed,
        Some((_, true)) => RemoteGroupStanding::CleanMember,
        Some((_, false)) => RemoteGroupStanding::IndexOnly,
    })
}

#[derive(Debug)]
pub(crate) enum EntryReadFacadeError {
    AccessOutsideMembershipInterval,
    ConversationNotFound,
    DeviceRevoked,
    InvitationNotPending,
    InvalidRequest,
    NotEntitled,
    Storage,
    Invariant,
}

pub(crate) struct CanonicalEntriesResponse {
    response_bytes: Vec<u8>,
}

impl CanonicalEntriesResponse {
    pub(crate) fn into_response_bytes(self) -> Vec<u8> {
        self.response_bytes
    }
}

pub(crate) async fn get_entries_for_admission(
    pool: &sqlx::PgPool,
    admission: VerifiedReadAdmission,
    conversation_id: Uuid,
    after_seq: u64,
    limit: i64,
) -> Result<CanonicalEntriesResponse, EntryReadFacadeError> {
    let admission = read_authority::into_single_read_admission(
        admission,
        read_authority::OrdinaryReadEndpoint::GetEntries,
    )
    .map_err(|e| {
        tracing::error!("into_single_read_admission failed: {:?}", e);
        EntryReadFacadeError::Invariant
    })?
    .into_attempt();
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| EntryReadFacadeError::Storage)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .map_err(|_| EntryReadFacadeError::Storage)?;

    let result = read_entries_in_transaction(
        &mut transaction,
        admission,
        conversation_id,
        after_seq,
        limit,
    )
    .await;
    let _ = transaction.rollback().await;
    result
}

async fn read_entries_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    attempt: crate::chat_protocol::dpop::ReadAdmissionAttempt,
    conversation_id: Uuid,
    after_seq: u64,
    limit: i64,
) -> Result<CanonicalEntriesResponse, EntryReadFacadeError> {
    let device = read_authority::lock_read_device_authority_once(transaction, attempt)
        .await
        .map_err(|e| {
            tracing::error!("lock_read_device_authority_once failed: {:?}", e);
            map_authority_error(e)
        })?;
    let (is_local_convo, has_group_grants, has_transport_inbox): (bool, bool, bool) =
        sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM chat.conversations WHERE conversation_id = $1), \
                to_regclass('chat.group_transport_entry_recipients') IS NOT NULL, \
                to_regclass('chat.direct_request_transport_inbox') IS NOT NULL",
        )
        .bind(conversation_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| EntryReadFacadeError::Storage)?;
    // A remote group member only the home's index knows reads exactly its
    // per-entry transport grants; a removed index member reads nothing.
    let standing = if is_local_convo {
        remote_group_standing(&mut **transaction, conversation_id, device.user_did())
            .await
            .map_err(|_| EntryReadFacadeError::Storage)?
    } else {
        RemoteGroupStanding::Untracked
    };
    if standing == RemoteGroupStanding::Removed {
        return Err(EntryReadFacadeError::ConversationNotFound);
    }
    let index_only = standing == RemoteGroupStanding::IndexOnly;
    if !is_local_convo || index_only {
        let actor_did = device.user_did().to_owned();
        let actor_device_uuid = device.device_id();
        let inbox_opt: Option<(
            String,
            String,
            Option<Uuid>,
            String,
            Uuid,
            chrono::DateTime<Utc>,
        )> = if has_transport_inbox && !index_only {
            sqlx::query_as(
                "SELECT status, sender_did, sender_device_id, recipient_did, recipient_device_id, import_until \
                 FROM chat.direct_request_transport_inbox \
                 WHERE conversation_id = $1 \
                   AND ((recipient_did = $2 AND recipient_device_id = $3) \
                        OR (sender_did = $2 AND sender_device_id = $3)) \
                 LIMIT 1",
            )
            .bind(conversation_id)
            .bind(&actor_did)
            .bind(actor_device_uuid)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|_| EntryReadFacadeError::Storage)?
        } else {
            None
        };

        let is_transport_inbox = inbox_opt.is_some();
        if let Some((
            status,
            sender_did,
            sender_device_id,
            recipient_did,
            recipient_device_id,
            import_until,
        )) = inbox_opt
        {
            let is_sender = actor_did == sender_did;
            let is_recipient = actor_did == recipient_did;
            if !is_sender && !is_recipient {
                return Err(EntryReadFacadeError::ConversationNotFound);
            }
            if is_recipient && actor_device_uuid != recipient_device_id {
                return Err(EntryReadFacadeError::NotEntitled);
            }
            if is_sender
                && sender_device_id
                    .is_some_and(|expected_sender_dev| actor_device_uuid != expected_sender_dev)
            {
                return Err(EntryReadFacadeError::NotEntitled);
            }
            if status == "pending" {
                if crate::sim_hooks::current_utc() > import_until {
                    return Err(EntryReadFacadeError::InvitationNotPending);
                }
            } else if status != "accepted" {
                return Err(EntryReadFacadeError::ConversationNotFound);
            }
        } else {
            let has_replicated_group = if has_group_grants {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM chat.group_transport_entry_recipients \
                      WHERE conversation_id = $1 AND user_did = $2 AND device_id = $3)",
                )
                .bind(conversation_id)
                .bind(&actor_did)
                .bind(actor_device_uuid)
                .fetch_one(&mut **transaction)
                .await
                .map_err(|_| EntryReadFacadeError::Storage)?
            } else {
                false
            };
            if !has_replicated_group {
                // After the I14 close wipe, a device in the close event's frozen
                // audience still receives the authenticated terminal entry.
                let Some(entry) = super::close_terminal::retained_close_entry_for_device(
                    transaction,
                    conversation_id,
                    &actor_did,
                    actor_device_uuid,
                )
                .await
                .map_err(|_| EntryReadFacadeError::Storage)?
                else {
                    return Err(EntryReadFacadeError::ConversationNotFound);
                };
                let terminal_seq = entry
                    .get("seq")
                    .and_then(Value::as_u64)
                    .ok_or(EntryReadFacadeError::Invariant)?;
                let entries = if terminal_seq > after_seq {
                    vec![entry]
                } else {
                    Vec::new()
                };
                let body = json!({
                    "entries": entries,
                    "nextAfterSeq": terminal_seq.max(after_seq),
                    "hasMore": false,
                });
                let response_bytes =
                    serde_json::to_vec(&body).map_err(|_| EntryReadFacadeError::Invariant)?;
                return Ok(CanonicalEntriesResponse { response_bytes });
            }
        }

        // A C33 inbox is already exact-device authorized above and predates
        // group grants. Never parse a query naming the optional grant table on
        // that path; group transport always requires a persisted device grant.
        let sql = if is_transport_inbox {
            "SELECT entry_bytes FROM chat.direct_request_transport_entries \
             WHERE conversation_id = $1 AND seq > $2 ORDER BY seq ASC LIMIT $3"
        } else {
            "SELECT e.entry_bytes FROM chat.direct_request_transport_entries e \
              JOIN chat.group_transport_entry_recipients r \
                ON r.conversation_id = e.conversation_id AND r.seq = e.seq \
             WHERE e.conversation_id = $1 AND e.seq > $2 \
               AND r.user_did = $4 AND r.device_id = $5 \
             ORDER BY e.seq ASC LIMIT $3"
        };
        let mut query = sqlx::query_scalar(sql)
            .bind(conversation_id)
            .bind(after_seq as i64)
            .bind(limit + 1);
        if !is_transport_inbox {
            query = query.bind(&actor_did).bind(actor_device_uuid);
        }
        let stored_entries: Vec<Vec<u8>> = query
            .fetch_all(&mut **transaction)
            .await
            .map_err(|_| EntryReadFacadeError::Storage)?;

        let has_more = stored_entries.len() > limit as usize;
        let entries: Vec<Value> = stored_entries
            .into_iter()
            .take(limit as usize)
            .map(|bytes| {
                let mut val: Value =
                    serde_json::from_slice(&bytes).map_err(|_| EntryReadFacadeError::Invariant)?;
                if val.get("$type").is_none() {
                    let inferred = match val
                        .pointer("/signedRequest/body/$type")
                        .and_then(Value::as_str)
                    {
                        Some("blue.catbird.chat.defs#applicationSendBody") => {
                            Some("blue.catbird.chat.defs#applicationEntry")
                        }
                        Some("blue.catbird.chat.defs#commitTransitionBody") => {
                            Some("blue.catbird.chat.defs#commitEntry")
                        }
                        Some("blue.catbird.chat.defs#metadataTransitionBody") => {
                            Some("blue.catbird.chat.defs#metadataEntry")
                        }
                        Some("blue.catbird.chat.defs#policyTransitionBody") => {
                            Some("blue.catbird.chat.defs#policyEntry")
                        }
                        Some("blue.catbird.chat.defs#leafRecoveryFulfillmentBody") => {
                            Some("blue.catbird.chat.defs#leafRecoveryFulfillmentEntry")
                        }
                        Some("blue.catbird.chat.defs#leaveCommitFulfillmentBody") => {
                            Some("blue.catbird.chat.defs#leaveCommitFulfillmentEntry")
                        }
                        _ => None,
                    };
                    if let Some(ty) = inferred {
                        val["$type"] = json!(ty);
                    }
                }
                let presented = if let Ok(canonical) = encode_canonical_generated_chat_json_v1(
                    &val,
                    "blue.catbird.chat.defs#conversationEntry",
                ) {
                    serde_json::from_slice(canonical.bytes())
                        .map_err(|_| EntryReadFacadeError::Invariant)?
                } else {
                    crate::chat_protocol::direct_request_transcript::present_read_presentation(
                        "conversationEntry",
                        &mut val,
                    )
                    .map_err(|_| EntryReadFacadeError::Invariant)?;
                    val
                };
                Ok(presented)
            })
            .collect::<Result<_, EntryReadFacadeError>>()?;

        let next_after_seq = entries
            .last()
            .and_then(|e| e.get("seq").and_then(|v| v.as_u64()))
            .unwrap_or(after_seq);
        let body = json!({
            "entries": entries,
            "nextAfterSeq": next_after_seq,
            "hasMore": has_more,
        });
        let response_bytes =
            serde_json::to_vec(&body).map_err(|_| EntryReadFacadeError::Invariant)?;
        return Ok(CanonicalEntriesResponse { response_bytes });
    }
    let authority = read_authority::authorize_entries(transaction, device, conversation_id)
        .await
        .map_err(|e| {
            tracing::error!("authorize_entries failed: {:?}", e);
            map_authority_error(e)
        })?;
    let page = delivery::get_entries_with_terminal_control_interval(
        transaction,
        conversation_id,
        authority.conversation().user_did(),
        authority.conversation().device_id(),
        after_seq,
        limit,
        authority.terminal_control_interval(),
    )
    .await
    .map_err(map_delivery_error)?;

    let mut entries = page
        .entries
        .iter()
        .map(entry_json)
        .collect::<Result<Vec<_>, _>>()?;
    let mut next_after_seq = page.next_after_seq;
    let mut has_more = page.has_more;

    let is_remote_convo: bool = sqlx::query_scalar(
        "SELECT COALESCE((SELECT is_remote FROM chat.conversations WHERE conversation_id = $1), FALSE)",
    )
    .bind(conversation_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| EntryReadFacadeError::Storage)?;
    if is_remote_convo && has_group_grants {
        let replicated_rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT e.seq, e.entry_bytes FROM chat.direct_request_transport_entries e \
              JOIN chat.group_transport_entry_recipients r \
                ON r.conversation_id = e.conversation_id AND r.seq = e.seq \
             WHERE e.conversation_id = $1 AND e.seq > $2 \
               AND r.user_did = $4 AND r.device_id = $5 \
             ORDER BY e.seq ASC LIMIT $3",
        )
        .bind(conversation_id)
        .bind(after_seq as i64)
        .bind(limit + 1)
        .bind(authority.conversation().user_did())
        .bind(authority.conversation().device_id())
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| EntryReadFacadeError::Storage)?;
        if !replicated_rows.is_empty() {
            let mut by_seq = std::collections::BTreeMap::<u64, Value>::new();
            for item in entries {
                if let Some(s) = item.get("seq").and_then(Value::as_u64) {
                    by_seq.insert(s, item);
                }
            }
            for (seq_i64, bytes) in replicated_rows {
                let Ok(seq_u64) = u64::try_from(seq_i64) else {
                    continue;
                };
                let mut val: Value =
                    serde_json::from_slice(&bytes).map_err(|_| EntryReadFacadeError::Invariant)?;
                if let Some(local) = by_seq.get_mut(&seq_u64) {
                    preserve_replicated_receipt_on_pruned_local(local, &val);
                }
                if !replicated_entry_supersedes_local(by_seq.get(&seq_u64), &val) {
                    continue;
                }
                if val.get("$type").is_none() {
                    let inferred = match val
                        .pointer("/signedRequest/body/$type")
                        .and_then(Value::as_str)
                    {
                        Some("blue.catbird.chat.defs#applicationSendBody") => {
                            Some("blue.catbird.chat.defs#applicationEntry")
                        }
                        Some("blue.catbird.chat.defs#commitTransitionBody") => {
                            Some("blue.catbird.chat.defs#commitEntry")
                        }
                        Some("blue.catbird.chat.defs#metadataTransitionBody") => {
                            Some("blue.catbird.chat.defs#metadataEntry")
                        }
                        Some("blue.catbird.chat.defs#policyTransitionBody") => {
                            Some("blue.catbird.chat.defs#policyEntry")
                        }
                        Some("blue.catbird.chat.defs#leafRecoveryFulfillmentBody") => {
                            Some("blue.catbird.chat.defs#leafRecoveryFulfillmentEntry")
                        }
                        Some("blue.catbird.chat.defs#leaveCommitFulfillmentBody") => {
                            Some("blue.catbird.chat.defs#leaveCommitFulfillmentEntry")
                        }
                        _ => None,
                    };
                    if let Some(ty) = inferred {
                        val["$type"] = json!(ty);
                    }
                }
                let presented = if let Ok(canonical) = encode_canonical_generated_chat_json_v1(
                    &val,
                    "blue.catbird.chat.defs#conversationEntry",
                ) {
                    serde_json::from_slice(canonical.bytes())
                        .map_err(|_| EntryReadFacadeError::Invariant)?
                } else {
                    let _ =
                        crate::chat_protocol::direct_request_transcript::present_read_presentation(
                            "conversationEntry",
                            &mut val,
                        );
                    val
                };
                by_seq.insert(seq_u64, presented);
            }
            has_more = has_more || by_seq.len() > limit as usize;
            entries = by_seq.into_values().take(limit as usize).collect();
            next_after_seq = entries
                .last()
                .and_then(|e| e.get("seq").and_then(Value::as_u64))
                .unwrap_or(after_seq);
        }
    }

    let body = json!({
        "entries": entries,
        "nextAfterSeq": next_after_seq,
        "hasMore": has_more,
    });
    let response_bytes = serde_json::to_vec(&body).map_err(|_| EntryReadFacadeError::Invariant)?;
    Ok(CanonicalEntriesResponse { response_bytes })
}

pub(super) fn replicated_entry_supersedes_local(local: Option<&Value>, replicated: &Value) -> bool {
    // Ciphertext pruning is terminal in either copy. A late full-payload
    // replica must not resurrect a pruned local entry, or vice versa.
    if replicated.get("payloadPruned").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    local.is_none_or(|entry| {
        entry.get("payloadPruned").and_then(Value::as_bool) != Some(true)
            && entry.get("sequencerReceipt").is_none()
            && replicated.get("sequencerReceipt").is_some()
    })
}

fn preserve_replicated_receipt_on_pruned_local(local: &mut Value, replicated: &Value) {
    if local.get("payloadPruned").and_then(Value::as_bool) == Some(true)
        && local.get("sequencerReceipt").is_none()
    {
        if let Some(receipt) = replicated.get("sequencerReceipt") {
            local["sequencerReceipt"] = receipt.clone();
        }
    }
}

/// The application entry the send `(conversation_id, message_id, request_digest)`
/// appended, exactly as `getEntries` serves it: `payloadPruned` without
/// `signedRequest` once its ciphertext is pruned (O7). `None` when no entry
/// holds that send.
pub(crate) async fn sent_application_entry(
    connection: &mut sqlx::PgConnection,
    conversation_id: Uuid,
    message_id: Uuid,
    request_digest: &[u8],
) -> Result<Option<Value>, sqlx::Error> {
    let row: Option<DeliveredEntryRow> = sqlx::query_as(
        "SELECT conversation_id, seq, entry_id, entry_kind, signed_request_bytes, \
                request_digest, signature, server_fields_bytes, outer_entry_fingerprint, \
                payload_pruned_at, sequencer_receipt_bytes, received_at \
           FROM chat.entries \
          WHERE conversation_id = $1 AND message_id = $2 AND request_digest = $3 \
            AND entry_kind = $4",
    )
    .bind(conversation_id)
    .bind(message_id)
    .bind(request_digest)
    .bind(delivery::APPLICATION_ENTRY_KIND)
    .fetch_optional(&mut *connection)
    .await?;
    row.as_ref()
        .map(entry_json)
        .transpose()
        .map_err(|_| sqlx::Error::Protocol("stored application entry cannot be served".into()))
}

#[cfg(any(test, feature = "test-support"))]
pub async fn entry_json_for_test(
    pool: &sqlx::PgPool,
    conversation_id: Uuid,
    seq: i64,
) -> Result<Value, String> {
    let row: DeliveredEntryRow = sqlx::query_as(
        "SELECT conversation_id, seq, entry_id, entry_kind, signed_request_bytes, \
                request_digest, signature, server_fields_bytes, outer_entry_fingerprint, \
                payload_pruned_at, sequencer_receipt_bytes, received_at \
           FROM chat.entries WHERE conversation_id = $1 AND seq = $2",
    )
    .bind(conversation_id)
    .bind(seq)
    .fetch_one(pool)
    .await
    .map_err(|error| error.to_string())?;
    entry_json(&row).map_err(|error| format!("{error:?}"))
}

/// A just-applied control entry exactly as delivery serves it, including its
/// sequencer receipt. Used before commit to prepare remote-home fan-out.
pub(crate) async fn entry_for_fanout(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    entry_id: Uuid,
) -> Result<Option<Value>, String> {
    let row: Option<DeliveredEntryRow> = sqlx::query_as(
        "SELECT conversation_id, seq, entry_id, entry_kind, signed_request_bytes, \
                request_digest, signature, server_fields_bytes, outer_entry_fingerprint, \
                payload_pruned_at, sequencer_receipt_bytes, received_at \
           FROM chat.entries WHERE conversation_id=$1 AND entry_id=$2",
    )
    .bind(conversation_id)
    .bind(entry_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| error.to_string())?;
    row.as_ref()
        .map(entry_json)
        .transpose()
        .map_err(|error| format!("{error:?}"))
}

/// `sendMessage`'s accepted outcome for its served `entry`: `{entry,
/// sequencerReceipt}`, the I13 receipt repeated as a first response carries it.
pub(crate) fn accepted_send_outcome(entry: Value) -> Value {
    let receipt = entry.get("sequencerReceipt").cloned();
    let mut outcome = json!({ "entry": entry });
    if let Some(receipt) = receipt {
        outcome["sequencerReceipt"] = receipt;
    }
    outcome
}

fn entry_json(row: &DeliveredEntryRow) -> Result<Value, EntryReadFacadeError> {
    let is_direct_request_entry = matches!(
        row.entry_kind.as_str(),
        "blue.catbird.chat.defs#directRequestEntry"
            | "blue.catbird.chat.defs#directRequestAcceptanceEntry"
    );
    let mut entry = if row.entry_kind == delivery::APPLICATION_ENTRY_KIND {
        let mut obj = if row.payload_pruned_at.is_some() || row.signed_request_bytes.is_none() {
            json!({
                "$type": row.entry_kind,
                "conversationId": row.conversation_id.hyphenated().to_string(),
                "entryId": row.entry_id.hyphenated().to_string(),
                "payloadPruned": true,
                "receivedAt": row.received_at.to_rfc3339_opts(SecondsFormat::Millis, true),
                "seq": row.seq,
            })
        } else {
            let signed_bytes = row
                .signed_request_bytes
                .as_deref()
                .ok_or(EntryReadFacadeError::Invariant)?;
            let signed_request: Value = serde_json::from_slice(signed_bytes)
                .map_err(|_| EntryReadFacadeError::Invariant)?;
            json!({
                "$type": row.entry_kind,
                "conversationId": row.conversation_id.hyphenated().to_string(),
                "entryId": row.entry_id.hyphenated().to_string(),
                "receivedAt": row.received_at.to_rfc3339_opts(SecondsFormat::Millis, true),
                "seq": row.seq,
                "signedRequest": signed_request,
            })
        };
        if let Some(rcpt_bytes) = &row.sequencer_receipt_bytes {
            let rcpt: Value =
                serde_json::from_slice(rcpt_bytes).map_err(|_| EntryReadFacadeError::Invariant)?;
            obj["sequencerReceipt"] = rcpt;
        }
        obj
    } else if row.entry_kind == "blue.catbird.chat.defs#directRequestEntry" {
        // The frozen opening includes both the I13 receipt and its signed
        // publication outcome. Reconstructing from the mutation alone drops
        // that evidence and prevents a recipient from authenticating Welcome.
        // Once its ciphertext is pruned the retained redacted row still carries
        // both receipts verbatim, served without `signedRequest` (O7).
        let retained = if row.payload_pruned_at.is_some() {
            row.pruned_payload_bytes.as_deref()
        } else {
            row.accepted_payload_bytes.as_deref()
        }
        .ok_or(EntryReadFacadeError::Invariant)?;
        let retained: Value =
            serde_json::from_slice(retained).map_err(|_| EntryReadFacadeError::Invariant)?;
        if retained.get("$type").and_then(Value::as_str) != Some(row.entry_kind.as_str())
            || retained
                .get("entryId")
                .and_then(Value::as_str)
                .and_then(|id| Uuid::parse_str(id).ok())
                != Some(row.entry_id)
            || retained
                .get("conversationId")
                .and_then(Value::as_str)
                .and_then(|id| Uuid::parse_str(id).ok())
                != Some(row.conversation_id)
            || retained.get("seq").and_then(Value::as_i64) != Some(row.seq)
            || retained
                .get("publicationReceipt")
                .and_then(Value::as_object)
                .is_none()
            || retained
                .get("sequencerReceipt")
                .and_then(Value::as_object)
                .is_none()
        {
            return Err(EntryReadFacadeError::Invariant);
        }
        if row.payload_pruned_at.is_some() {
            super::direct_request_opening::pruned_opening_entry(&retained)
        } else {
            retained
        }
    } else if is_direct_request_entry {
        let signed_bytes = row
            .signed_request_bytes
            .as_deref()
            .ok_or(EntryReadFacadeError::Invariant)?;
        let signed_request: Value =
            serde_json::from_slice(signed_bytes).map_err(|_| EntryReadFacadeError::Invariant)?;
        json!({
            "$type": row.entry_kind,
            "conversationId": row.conversation_id.hyphenated().to_string(),
            "entryId": row.entry_id.hyphenated().to_string(),
            "receivedAt": row.received_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            "seq": row.seq,
            "signedRequest": signed_request,
        })
    } else if row.entry_kind == "blue.catbird.chat.defs#accountDeletedEntry" {
        // Exactly the entry its sequencer signed, `sequencerAuthority` included.
        serde_ipld_dagcbor::from_slice::<AccountDeletedServerFields>(&row.server_fields_bytes)
            .map_err(|_| EntryReadFacadeError::Invariant)?
            .entry(row.conversation_id, row.seq, row.entry_id, row.received_at)
    } else {
        let signed_bytes = row
            .signed_request_bytes
            .as_deref()
            .ok_or(EntryReadFacadeError::Invariant)?;
        let bytes = crate::chat_protocol::transcript::persisted_control_entry_response_json(
            &row.entry_kind,
            &row.entry_id.hyphenated().to_string(),
            &row.conversation_id.hyphenated().to_string(),
            u64::try_from(row.seq).map_err(|_| EntryReadFacadeError::Invariant)?,
            &row.received_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            signed_bytes,
            &row.server_fields_bytes,
        )
        .map_err(|_| EntryReadFacadeError::Invariant)?;
        serde_json::from_slice(&bytes).map_err(|_| EntryReadFacadeError::Invariant)?
    };
    if is_direct_request_entry {
        let acceptance_receipt =
            if row.entry_kind == "blue.catbird.chat.defs#directRequestAcceptanceEntry" {
                row.sequencer_receipt_bytes
                    .as_deref()
                    .map(serde_json::from_slice::<Value>)
                    .transpose()
                    .map_err(|_| EntryReadFacadeError::Invariant)?
            } else {
                None
            };
        // Encrypted-request entries echo their retained signed wrapper; the
        // encrypted-requests presentation bridge emits their declared bytes as
        // lexicon `{"$bytes"}` at read time only.
        crate::chat_protocol::direct_request_transcript::present_read_presentation(
            "conversationEntry",
            &mut entry,
        )
        .map_err(|_| EntryReadFacadeError::Invariant)?;
        if let Some(receipt) = acceptance_receipt {
            let receipt = encode_canonical_generated_chat_json_v1(
                &receipt,
                "blue.catbird.chat.defs#sequencerReceipt",
            )
            .map_err(|_| EntryReadFacadeError::Invariant)?;
            entry["sequencerReceipt"] = serde_json::from_slice(receipt.bytes())
                .map_err(|_| EntryReadFacadeError::Invariant)?;
        }
        return Ok(entry);
    }
    let canonical =
        encode_canonical_generated_chat_json_v1(&entry, "blue.catbird.chat.defs#conversationEntry")
            .map_err(|error| {
                tracing::error!("entry response canonicalization failed: {error}");
                EntryReadFacadeError::Invariant
            })?;
    let mut presented: Value =
        serde_json::from_slice(canonical.bytes()).map_err(|_| EntryReadFacadeError::Invariant)?;
    if let Some(receipt_bytes) = &row.sequencer_receipt_bytes {
        let receipt: Value =
            serde_json::from_slice(receipt_bytes).map_err(|_| EntryReadFacadeError::Invariant)?;
        let receipt = encode_canonical_generated_chat_json_v1(
            &receipt,
            "blue.catbird.chat.defs#sequencerReceipt",
        )
        .map_err(|_| EntryReadFacadeError::Invariant)?;
        presented["sequencerReceipt"] =
            serde_json::from_slice(receipt.bytes()).map_err(|_| EntryReadFacadeError::Invariant)?;
    }
    Ok(presented)
}

fn map_authority_error(error: ReadAuthorityError) -> EntryReadFacadeError {
    tracing::error!("get_entries map_authority_error: {:?}", error);
    match error {
        ReadAuthorityError::AccessOutsideMembershipInterval => {
            EntryReadFacadeError::AccessOutsideMembershipInterval
        }
        ReadAuthorityError::ConversationNotFound => EntryReadFacadeError::ConversationNotFound,
        ReadAuthorityError::DeviceRevoked => EntryReadFacadeError::DeviceRevoked,
        ReadAuthorityError::NotEntitled => EntryReadFacadeError::NotEntitled,
        ReadAuthorityError::Storage => EntryReadFacadeError::Storage,
        ReadAuthorityError::Invariant => EntryReadFacadeError::Invariant,
    }
}

fn map_delivery_error(error: DeliveryRepositoryError) -> EntryReadFacadeError {
    tracing::error!("get_entries map_delivery_error: {:?}", error);
    match error {
        DeliveryRepositoryError::SequenceOverflow | DeliveryRepositoryError::EntryKindMismatch => {
            EntryReadFacadeError::Invariant
        }
        _ => EntryReadFacadeError::Invariant,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    #[test]
    fn entry_json_control_entry_projects_type_and_entry_id_without_transposition() {
        let conversation_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let body = json!({
            "$type": "blue.catbird.chat.defs#leaveCancellationBody",
            "signatureDomain": "CATBIRD-CHAT-LEAVE-CANCEL\0",
            "conversationId": conversation_id.hyphenated().to_string(),
            "leaveRequestId": Uuid::new_v4().hyphenated().to_string(),
            "actorDid": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
            "actorDeviceId": Uuid::new_v4().hyphenated().to_string(),
            "keyId": crate::chat_protocol::validation::ed25519_key_id(&signing_key.verifying_key().to_bytes()).unwrap().as_str(),
            "authGeneration": 1,
            "idempotencyKey": Uuid::new_v4().hyphenated().to_string(),
            "signedAt": "2026-08-20T12:00:00.000Z",
        });
        let mut wrapper = json!({
            "body": body,
            "signature": STANDARD.encode([0u8; 64]),
        });
        let unsigned = serde_json::to_vec(&wrapper).unwrap();
        let canonical =
            crate::chat_protocol::transcript::decode_canonical_signed_mutation(&unsigned).unwrap();
        let signature = signing_key.sign(canonical.transcript_bytes()).to_bytes();
        wrapper["signature"] = json!(STANDARD.encode(signature));
        let signed_request_bytes = serde_json::to_vec(&wrapper).unwrap();
        let row = DeliveredEntryRow {
            conversation_id,
            seq: 2,
            entry_id,
            entry_kind: "blue.catbird.chat.defs#leaveCancellationEntry".to_string(),
            accepted_payload_bytes: None,
            signed_request_bytes: Some(signed_request_bytes),
            request_digest: Sha256::digest(canonical.transcript_bytes()).to_vec(),
            signature: signature.to_vec(),
            server_fields_bytes: vec![0xA0],
            outer_entry_fingerprint: vec![0x11; 32],
            payload_pruned_at: None,
            sequencer_receipt_bytes: None,
            pruned_payload_bytes: None,
            received_at: "2026-08-20T12:00:01.000Z".parse().unwrap(),
        };

        let json = entry_json(&row).expect("entry_json projects valid control entry");
        assert_eq!(
            json["$type"].as_str(),
            Some("blue.catbird.chat.defs#leaveCancellationEntry"),
            "$type must match row.entry_kind"
        );
        assert_eq!(
            json["entryId"].as_str(),
            Some(entry_id.hyphenated().to_string().as_str()),
            "entryId must match row.entry_id"
        );
        assert_eq!(
            json["conversationId"].as_str(),
            Some(conversation_id.hyphenated().to_string().as_str()),
            "conversationId must match row.conversation_id"
        );
        assert_eq!(json["seq"].as_u64(), Some(2));
        assert_eq!(
            json["signedRequest"]["signature"]["$bytes"],
            STANDARD.encode(signature),
            "control-entry bytes must use lexicon $bytes objects"
        );
    }

    #[test]
    fn late_receipted_replica_repairs_pruned_local_without_restoring_payload() {
        let mut local = json!({
            "seq": 4,
            "payloadPruned": true,
            "acceptedPayloadSha256": {"$bytes": STANDARD.encode([0x11_u8; 32])},
        });
        let replicated = json!({
            "seq": 4,
            "signedRequest": {"body": {"applicationMessage": {"bytes": "ciphertext"}}},
            "sequencerReceipt": {
                "kid": "did:web:sequencer.example#mls-receipt-1",
                "signature": STANDARD.encode([0x22_u8; 64]),
            },
        });

        preserve_replicated_receipt_on_pruned_local(&mut local, &replicated);

        assert_eq!(local["sequencerReceipt"], replicated["sequencerReceipt"]);
        assert_eq!(local["payloadPruned"], true);
        assert!(local.get("signedRequest").is_none());
    }

    #[test]
    fn entry_json_application_entry_emits_lexicon_bytes_objects() {
        let conversation_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
        let coordinates = json!({
            "conversationId": conversation_id.hyphenated().to_string(),
            "generation": 1,
            "stateVersion": 2,
            "groupId": STANDARD.encode([0x22_u8; 32]),
            "epoch": 1,
            "groupContextHash": STANDARD.encode([0x23_u8; 32]),
            "confirmationTag": STANDARD.encode([0x24_u8; 32]),
            "lifecycle": "active"
        });
        let signed_request = json!({
            "body": {
                "$type": "blue.catbird.chat.defs#applicationSendBody",
                "signatureDomain": "CATBIRD-CHAT-MESSAGE\u{0000}",
                "messageId": "51515151-5151-4151-9151-515151515151",
                "actorDid": "did:plc:alicefixtureaaaaaaaaaaaa",
                "actorDeviceId": "70707070-7070-4070-b070-707070707070",
                "keyId": "If4x36FUomFia_hUBG_SJxt77UtqvkWqWId-9H-XIbk",
                "authGeneration": 1,
                "sendCounter": 1,
                "prior": coordinates.clone(),
                "aad": {
                    "protocolVersion": "1",
                    "conversationId": STANDARD.encode([0x11_u8; 16]),
                    "generation": 1,
                    "messageId": STANDARD.encode([0x51_u8; 16]),
                    "prior": {
                        "conversationId": STANDARD.encode([0x11_u8; 16]),
                        "generation": 1,
                        "stateVersion": 2,
                        "groupId": STANDARD.encode([0x22_u8; 32]),
                        "epoch": 1,
                        "groupContextHash": STANDARD.encode([0x23_u8; 32]),
                        "confirmationTag": STANDARD.encode([0x24_u8; 32]),
                        "lifecycle": "active"
                    }
                },
                "applicationMessage": {
                    "framing": "mlsMessage",
                    "contentType": "privateMessageApplication",
                    "bytes": STANDARD.encode([0x31_u8; 8]),
                    "sha256": STANDARD.encode(Sha256::digest([0x31_u8; 8]))
                },
                "blobBindings": [],
                "signedAt": "2026-07-22T12:34:55.000Z"
            },
            "signature": STANDARD.encode([0_u8; 64])
        });
        let receipt = json!({
            "conversationId": conversation_id.hyphenated().to_string(),
            "generation": 1,
            "groupId": STANDARD.encode([0x22_u8; 32]),
            "epoch": 1,
            "entryId": "51515151-5151-4151-9151-515151515151",
            "seq": 2,
            "senderDid": "did:plc:alicefixtureaaaaaaaaaaaa",
            "senderDeviceId": "70707070-7070-4070-b070-707070707070",
            "archiveCommitment": STANDARD.encode([0x25_u8; 32]),
            "issuedAtMs": 1_752_000_000_000_i64,
            "sequencerDid": "did:web:chat.catbird.blue",
            "kid": "did:web:chat.catbird.blue#mls-receipt-1",
            "signature": STANDARD.encode([0x26_u8; 64]),
        });
        let row = DeliveredEntryRow {
            conversation_id,
            seq: 2,
            entry_id: Uuid::parse_str("51515151-5151-4151-9151-515151515151").unwrap(),
            entry_kind: delivery::APPLICATION_ENTRY_KIND.to_owned(),
            accepted_payload_bytes: None,
            signed_request_bytes: Some(serde_json::to_vec(&signed_request).unwrap()),
            request_digest: vec![0x11; 32],
            signature: vec![0x22; 64],
            server_fields_bytes: vec![0xA0],
            outer_entry_fingerprint: vec![0x33; 32],
            payload_pruned_at: None,
            sequencer_receipt_bytes: Some(serde_json::to_vec(&receipt).unwrap()),
            pruned_payload_bytes: None,
            received_at: "2026-07-22T12:34:56.000Z".parse().unwrap(),
        };

        let value = entry_json(&row).expect("application entry projects");
        assert_eq!(
            value["signedRequest"]["body"]["prior"]["groupId"]["$bytes"],
            STANDARD.encode([0x22_u8; 32])
        );
        assert_eq!(
            value["signedRequest"]["body"]["applicationMessage"]["bytes"]["$bytes"],
            STANDARD.encode([0x31_u8; 8])
        );
        assert_eq!(
            value["signedRequest"]["signature"]["$bytes"],
            STANDARD.encode([0_u8; 64])
        );
        assert_eq!(
            value["sequencerReceipt"]["signature"]["$bytes"],
            STANDARD.encode([0x26_u8; 64])
        );
    }

    fn stored_account_deletion_authority() -> AccountDeletionAuthority {
        AccountDeletionAuthority {
            sequencer_did: "did:web:sequencer.example".to_string(),
            key_id: "did:web:sequencer.example#receipt-1".to_string(),
            signature: vec![0x5a; 64],
        }
    }

    #[test]
    fn account_deleted_server_fields_decode_rows_stored_before_optional_fields() {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct StoredRow {
            deleted_did: String,
            sequencer_did: String,
            sequencer_authority: AccountDeletionAuthority,
        }
        let stored = serde_ipld_dagcbor::to_vec(&StoredRow {
            deleted_did: "did:plc:deleteddeleteddeleted0".to_string(),
            sequencer_did: "did:web:sequencer.example".to_string(),
            sequencer_authority: stored_account_deletion_authority(),
        })
        .unwrap();

        let fields: AccountDeletedServerFields = serde_ipld_dagcbor::from_slice(&stored).unwrap();
        assert_eq!(
            serde_ipld_dagcbor::to_vec(&fields).unwrap(),
            stored,
            "a stored row re-encodes to the same bytes"
        );

        let conversation_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();
        let received_at = DateTime::parse_from_rfc3339("2026-11-16T12:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let entry = fields.entry(conversation_id, 7, entry_id, received_at);
        let keys: Vec<&str> = entry
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert!(
            !keys.contains(&"actorWrite") && !keys.contains(&"keyProof"),
            "a stored row without the optional fields rebuilds an entry without them: {keys:?}"
        );
        let (deletion, authority) =
            crate::federation::receipt::AccountDeletion::from_entry(&entry).unwrap();
        assert_eq!(deletion.seq, 7);
        assert_eq!(authority, stored_account_deletion_authority());
    }

    #[test]
    fn account_deleted_server_fields_decode_rows_carrying_actor_write_and_key_proof() {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct ActorWrite {
            #[serde(with = "crate::atproto_bytes")]
            write_body: Vec<u8>,
            #[serde(with = "crate::atproto_bytes")]
            signature: Vec<u8>,
        }
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct StoredRow {
            deleted_did: String,
            sequencer_did: String,
            sequencer_authority: AccountDeletionAuthority,
            actor_write: ActorWrite,
            #[serde(with = "crate::atproto_bytes")]
            key_proof: Vec<u8>,
            #[serde(
                default,
                skip_serializing_if = "Option::is_none",
                with = "crate::atproto_bytes::option"
            )]
            revocation_proof: Option<Vec<u8>>,
        }
        let stored = serde_ipld_dagcbor::to_vec(&StoredRow {
            deleted_did: "did:plc:deleteddeleteddeleted0".to_string(),
            sequencer_did: "did:web:sequencer.example".to_string(),
            sequencer_authority: stored_account_deletion_authority(),
            actor_write: ActorWrite {
                write_body: br#"{"operationId":"op"}"#.to_vec(),
                signature: vec![0x11; 64],
            },
            key_proof: vec![0x22; 128],
            revocation_proof: Some(vec![0x33; 128]),
        })
        .unwrap();

        let fields = serde_ipld_dagcbor::from_slice::<AccountDeletedServerFields>(&stored).expect(
            "a row carrying the optional actor write, key proof, and revocation proof decodes",
        );
        assert_eq!(
            serde_ipld_dagcbor::to_vec(&fields).unwrap(),
            stored,
            "the optional fields survive a decode and re-encode unchanged"
        );
    }
}
