//! Signed S2S relays of ACK effects between a conversation's homes and its
//! sequencer.
//!
//! - `blue.catbird.mlsDS.relayEntryAck` (home to sequencer). A sequencer prunes
//!   an application payload only after every device in its frozen audience
//!   acknowledged it, but a device ACKs only at its own home. A home recording a
//!   local ACK for a conversation sequenced elsewhere queues, in that ACK's
//!   transaction, one relay of the device's stored watermark signed with the
//!   home's `#atproto` service key. The sequencer accepts only a relay its
//!   authenticated caller signed for a participant homed there, raises that
//!   device's watermark monotonically, and runs the local ACK's prune.
//! - `blue.catbird.mlsDS.notifyEntriesPruned` (sequencer to home). Pruning is
//!   authoritative at the sequencer. A group mirror never learns a removal, so
//!   it would wait forever on a removed device's ACK. Each sequencer prune
//!   instead queues, in its transaction, a signed notice of the pruned sequences
//!   to every home they were fanned out to, and that mirror prunes exactly them.
//!
//! A DS without its S2S signing key refuses any effect that needs a relay or
//! notice ([`SignedRelayError::SignerUnavailable`]): its transaction rolls back.

use super::*;
use chrono::{DateTime, Utc};
use p256::ecdsa::{
    signature::{Signer as _, Verifier as _},
    Signature, SigningKey,
};
use p256::pkcs8::DecodePrivateKey as _;
use sqlx::{Postgres, Transaction};

use crate::chat_protocol::repository::delivery;

#[path = "account_deletion_relay.rs"]
pub(super) mod account_deletion_relay;
#[path = "transport_control_entry.rs"]
pub(super) mod transport_control_entry;

pub(crate) const RELAY_ENTRY_ACK_NSID: &str = "blue.catbird.mlsDS.relayEntryAck";
pub(crate) const NOTIFY_ENTRIES_PRUNED_NSID: &str = "blue.catbird.mlsDS.notifyEntriesPruned";
const RELAY_SIGNING_DOMAIN: &[u8] = b"CATBIRD-MLSDS-ENTRY-ACK-RELAY-V1\0";
const NOTICE_SIGNING_DOMAIN: &[u8] = b"CATBIRD-MLSDS-ENTRIES-PRUNED-NOTICE-V1\0";
/// Sequences per notice; a larger prune queues several notices.
const MAX_NOTICE_SEQS: usize = 1_000;

/// One device's acknowledged-through watermark, signed by its home.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EntryAckRelay {
    pub(crate) home_did: String,
    pub(crate) sequencer_did: String,
    pub(crate) conversation_id: Uuid,
    pub(crate) generation: i64,
    pub(crate) user_did: String,
    pub(crate) device_id: Uuid,
    pub(crate) acked_through_seq: i64,
    /// Base64 low-S ES256 `r || s` over [`EntryAckRelay::signing_bytes`].
    pub(crate) signature: String,
}

impl EntryAckRelay {
    /// Domain-separated, length-prefixed bytes binding every relayed field.
    pub(crate) fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = RELAY_SIGNING_DOMAIN.to_vec();
        for field in [&self.home_did, &self.sequencer_did, &self.user_did] {
            push_field(&mut bytes, field);
        }
        bytes.extend_from_slice(self.conversation_id.as_bytes());
        bytes.extend_from_slice(self.device_id.as_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.acked_through_seq.to_be_bytes());
        bytes
    }
}

/// Application sequences a group's sequencer pruned, signed for one home.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EntriesPrunedNotice {
    pub(crate) sequencer_did: String,
    pub(crate) home_did: String,
    pub(crate) conversation_id: Uuid,
    pub(crate) generation: i64,
    /// Strictly ascending pruned sequences.
    pub(crate) seqs: Vec<i64>,
    /// Base64 low-S ES256 `r || s` over [`EntriesPrunedNotice::signing_bytes`].
    pub(crate) signature: String,
}

impl EntriesPrunedNotice {
    /// Domain-separated, length-prefixed bytes binding every notified field.
    pub(crate) fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = NOTICE_SIGNING_DOMAIN.to_vec();
        for field in [&self.sequencer_did, &self.home_did] {
            push_field(&mut bytes, field);
        }
        bytes.extend_from_slice(self.conversation_id.as_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&(self.seqs.len() as u32).to_be_bytes());
        for seq in &self.seqs {
            bytes.extend_from_slice(&seq.to_be_bytes());
        }
        bytes
    }
}

fn push_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

/// Why a required signed relay or notice was not queued; the effect needing it
/// must roll back.
#[derive(Debug)]
pub enum SignedRelayError {
    /// This DS has no usable S2S signing key.
    SignerUnavailable,
    Storage(String),
}

impl From<sqlx::Error> for SignedRelayError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

fn service_signing_key() -> Result<SigningKey, SignedRelayError> {
    let pem = crate::federation::canonical_relay::configured_s2s_signing_key_pem()
        .map_err(|_| SignedRelayError::SignerUnavailable)?;
    SigningKey::from_pkcs8_pem(&pem).map_err(|_| SignedRelayError::SignerUnavailable)
}

/// Base64 low-S ES256 `r || s`; RFC 6979 nonces keep it deterministic.
fn sign(key: &SigningKey, bytes: &[u8]) -> String {
    let signature: Signature = key.sign(bytes);
    STANDARD.encode(signature.normalize_s().unwrap_or(signature).to_bytes())
}

/// Queue a signed payload, due now. A deterministic id makes a replay add nothing.
async fn queue_signed(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    target_did: &str,
    method: &str,
    payload: &[u8],
    conversation_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), SignedRelayError> {
    sqlx::query(
        "INSERT INTO outbound_queue \
           (id, target_ds_did, target_endpoint, method, payload, convo_id, next_retry_at, created_at) \
         SELECT $1, $2, '', $3, $4, $5, $6, $6 \
          WHERE NOT EXISTS (SELECT 1 FROM outbound_queue WHERE id = $1) \
         ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(target_did)
    .bind(method)
    .bind(payload)
    .bind(conversation_id.to_string())
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Queue this home's signed relay of one device's stored ACK watermark to the
/// conversation's sequencer, inside the ACK's own transaction. The id is
/// deterministic, so an unchanged watermark adds nothing; a newer watermark
/// supersedes the device's older relays that are still only pending, since the
/// sequencer keeps the greatest.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn enqueue_entry_ack_relay(
    tx: &mut Transaction<'_, Postgres>,
    sequencer_did: &str,
    conversation_id: Uuid,
    generation: i64,
    user_did: &str,
    device_id: Uuid,
    acked_through_seq: i64,
    now: DateTime<Utc>,
) -> Result<(), SignedRelayError> {
    let mut relay = EntryAckRelay {
        home_did: crate::identity::service_did_base(),
        sequencer_did: crate::identity::canonical_did(sequencer_did).to_owned(),
        conversation_id,
        generation,
        user_did: user_did.to_owned(),
        device_id,
        acked_through_seq,
        signature: String::new(),
    };
    relay.signature = sign(&service_signing_key()?, &relay.signing_bytes());
    let payload =
        serde_json::to_vec(&relay).map_err(|error| SignedRelayError::Storage(error.to_string()))?;
    let device_prefix = format!("entry-ack-{conversation_id}-{device_id}-");
    let id = format!("{device_prefix}{acked_through_seq:020}");
    sqlx::query(
        "DELETE FROM outbound_queue \
          WHERE status = 'pending' AND method = $1 AND starts_with(id, $2) AND id < $3",
    )
    .bind(RELAY_ENTRY_ACK_NSID)
    .bind(&device_prefix)
    .bind(&id)
    .execute(&mut **tx)
    .await?;
    queue_signed(
        tx,
        &id,
        &relay.sequencer_did,
        RELAY_ENTRY_ACK_NSID,
        &payload,
        conversation_id,
        now,
    )
    .await
}

/// Queue this sequencer's signed notice of `pruned_seqs` (ascending) to every
/// other home they were fanned out to, inside the pruning transaction: the
/// homes of their application audience, current or since removed, exactly as
/// `prepare_group_entry_fanout` addressed them. A home never sent a sequence is
/// never told of it. The queue keeps each notice behind that home's entries.
pub async fn enqueue_entries_pruned_notices(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    generation: i64,
    pruned_seqs: &[i64],
    now: DateTime<Utc>,
) -> Result<(), SignedRelayError> {
    if pruned_seqs.is_empty() {
        return Ok(());
    }
    let self_did = crate::identity::service_did_base();
    let homes: Vec<(String, Vec<i64>)> = sqlx::query_as(
        "SELECT split_part(p.ds_did, '#', 1), array_agg(DISTINCT s.seq ORDER BY s.seq) \
           FROM unnest($2::bigint[]) AS s(seq) \
           JOIN chat.conversations c \
             ON c.conversation_id = $1 AND c.kind = 'group' AND NOT c.is_remote \
           JOIN chat.application_intervals ai \
             ON ai.conversation_id = $1 AND ai.generation = $3 \
            AND ai.start_seq <= s.seq AND (ai.terminal_seq IS NULL OR s.seq <= ai.terminal_seq) \
           JOIN chat.participants p \
             ON p.conversation_id = $1 AND p.user_did = ai.recipient_did \
          WHERE p.ds_did IS NOT NULL \
          GROUP BY 1 \
          ORDER BY 1",
    )
    .bind(conversation_id)
    .bind(pruned_seqs)
    .bind(generation)
    .fetch_all(&mut **tx)
    .await?;
    for (home, seqs) in homes
        .iter()
        .filter(|(home, _)| !crate::identity::dids_equivalent(home, &self_did))
    {
        enqueue_entries_pruned_notice(tx, home, conversation_id, generation, seqs, now).await?;
    }
    Ok(())
}

/// Queue one home's signed notices of `seqs` (ascending), at most
/// [`MAX_NOTICE_SEQS`] each. A sequence is pruned once, so a notice's first
/// sequence names it.
pub(crate) async fn enqueue_entries_pruned_notice(
    tx: &mut Transaction<'_, Postgres>,
    home_did: &str,
    conversation_id: Uuid,
    generation: i64,
    seqs: &[i64],
    now: DateTime<Utc>,
) -> Result<(), SignedRelayError> {
    let key = service_signing_key()?;
    for seqs in seqs.chunks(MAX_NOTICE_SEQS) {
        let mut notice = EntriesPrunedNotice {
            sequencer_did: crate::identity::service_did_base(),
            home_did: crate::identity::canonical_did(home_did).to_owned(),
            conversation_id,
            generation,
            seqs: seqs.to_vec(),
            signature: String::new(),
        };
        notice.signature = sign(&key, &notice.signing_bytes());
        let payload = serde_json::to_vec(&notice)
            .map_err(|error| SignedRelayError::Storage(error.to_string()))?;
        let id = format!(
            "entries-pruned-{conversation_id}-{:020}-{}",
            seqs[0], notice.home_did
        );
        queue_signed(
            tx,
            &id,
            &notice.home_did,
            NOTIFY_ENTRIES_PRUNED_NSID,
            &payload,
            conversation_id,
            now,
        )
        .await?;
    }
    Ok(())
}

pub(super) fn routes() -> Router<GroupRelayState> {
    Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.relayEntryAck",
            post(ClockScoped(relay_entry_ack)).layer(DefaultBodyLimit::max(16_384)),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.notifyEntriesPruned",
            post(ClockScoped(notify_entries_pruned)).layer(DefaultBodyLimit::max(65_536)),
        )
        .merge(account_deletion_relay::routes())
        .merge(transport_control_entry::routes())
}

async fn relay_entry_ack(
    State(state): State<GroupRelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match verify_s2s_caller(&state, &headers, RELAY_ENTRY_ACK_NSID, &body).await {
        Ok(caller) => respond(accept_entry_ack_relay(&state, &caller, &body).await),
        Err(response) => response,
    }
}

async fn notify_entries_pruned(
    State(state): State<GroupRelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match verify_s2s_caller(&state, &headers, NOTIFY_ENTRIES_PRUNED_NSID, &body).await {
        Ok(caller) => respond(accept_entries_pruned_notice(&state, &caller, &body).await),
        Err(response) => response,
    }
}

fn respond(outcome: Result<Value, Response>) -> Response {
    match outcome {
        Ok(output) => (StatusCode::OK, Json(output)).into_response(),
        Err(response) => response,
    }
}

// Only a dependency failure answers 5xx; every rejection is a definitive 4xx.
fn invalid(message: &str) -> Response {
    s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", message)
}

fn denied(message: &str) -> Response {
    s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", message)
}

fn missing(message: &str) -> Response {
    s2s_err(StatusCode::NOT_FOUND, "ConversationNotFound", message)
}

fn unavailable(error: impl std::fmt::Display) -> Response {
    s2s_err(
        StatusCode::SERVICE_UNAVAILABLE,
        "ServiceUnavailable",
        error.to_string(),
    )
}

fn storage(error: impl std::fmt::Display) -> Response {
    s2s_err(
        StatusCode::INTERNAL_SERVER_ERROR,
        "InternalServerError",
        error.to_string(),
    )
}

/// The participant's authoritative home could not be established: this DS's
/// own fault (database, configuration), an answer that could not come now, or
/// a definitive refusal (the caller is then not proven the participant's home).
fn authority_lookup_failure(error: crate::federation::FederationError) -> Response {
    match error {
        crate::federation::FederationError::Database(_) => storage(error),
        error if error.is_retryable() => unavailable(error),
        error if error.status_code().is_server_error() => storage(error),
        error => denied(&error.to_string()),
    }
}

/// A signer DID document that could not be fetched now decided nothing; any
/// other failure refuses the signature.
fn signer_lookup_failure(error: crate::auth::AuthError) -> Response {
    if error.is_retryable() {
        unavailable(error)
    } else {
        s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", error.to_string())
    }
}

/// The relayed ACK's prune needs a signed notice this DS cannot sign: refuse it
/// with a declared, retryable error, so nothing is committed.
fn signed_relay_failure(error: SignedRelayError) -> Response {
    match error {
        SignedRelayError::SignerUnavailable => s2s_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "SignerUnavailable",
            "this sequencer cannot sign the entries-pruned notice its prune requires",
        ),
        SignedRelayError::Storage(error) => storage(error),
    }
}

/// Apply a relayed ACK from an authenticated `caller` at this sequencer.
pub(super) async fn accept_entry_ack_relay(
    state: &GroupRelayState,
    caller: &str,
    body: &[u8],
) -> Result<Value, Response> {
    let relay: EntryAckRelay =
        serde_json::from_slice(body).map_err(|error| invalid(&error.to_string()))?;
    if relay.conversation_id.get_version_num() != 4
        || relay.device_id.get_version_num() != 4
        || relay.generation < 0
        || relay.acked_through_seq < 1
        || crate::chat_protocol::validation::BareDid::parse(&relay.user_did).is_err()
    {
        return Err(invalid("invalid entry ACK relay"));
    }
    if relay.home_did != caller || relay.sequencer_did != state.self_did {
        return Err(denied("relay is not bound to this caller and sequencer"));
    }
    verify_service_signature(&relay.home_did, &relay.signing_bytes(), &relay.signature).await?;

    if participant_home(state, relay.conversation_id, &relay.user_did).await? != caller {
        return Err(denied("caller is not the participant's home"));
    }

    let now = crate::sim_hooks::current_utc();
    let mut tx = state.pool.begin().await.map_err(storage)?;
    let head: Option<(i64, bool)> = sqlx::query_as(
        "SELECT next_entry_seq, is_remote FROM chat.conversations \
          WHERE conversation_id = $1 FOR UPDATE",
    )
    .bind(relay.conversation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?;
    let Some((next_entry_seq, false)) = head else {
        return Err(missing("conversation is not sequenced here"));
    };
    if relay.acked_through_seq >= next_entry_seq {
        return Err(invalid("watermark is beyond the sequenced head"));
    }
    let in_audience: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.application_intervals \
                        WHERE conversation_id = $1 AND generation = $2 \
                          AND recipient_did = $3 AND recipient_device_id = $4) \
             OR EXISTS(SELECT 1 FROM chat.member_devices \
                        WHERE conversation_id = $1 AND generation = $2 \
                          AND user_did = $3 AND device_id = $4)",
    )
    .bind(relay.conversation_id)
    .bind(relay.generation)
    .bind(&relay.user_did)
    .bind(relay.device_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(storage)?;
    if !in_audience {
        return Err(denied("device is outside the conversation audience"));
    }
    let acked_seq: i64 = sqlx::query_scalar(
        "INSERT INTO chat.device_entry_acks ( \
             conversation_id, user_did, device_id, acked_through_seq, updated_at \
         ) VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (conversation_id, user_did, device_id) DO UPDATE \
           SET acked_through_seq = GREATEST(chat.device_entry_acks.acked_through_seq, EXCLUDED.acked_through_seq), \
               updated_at = EXCLUDED.updated_at \
         RETURNING acked_through_seq",
    )
    .bind(relay.conversation_id)
    .bind(&relay.user_did)
    .bind(relay.device_id)
    .bind(relay.acked_through_seq)
    .bind(crate::chat_protocol::device_activity::coarse_activity_day(now))
    .fetch_one(&mut *tx)
    .await
    .map_err(storage)?;
    sqlx::query(
        "UPDATE chat.devices \
            SET last_active_at = GREATEST(last_active_at, $3), \
                dormant_at = NULL \
          WHERE user_did = $1 AND device_id = $2 \
            AND (last_active_at < $3 OR dormant_at IS NOT NULL)",
    )
    .bind(&relay.user_did)
    .bind(relay.device_id)
    .bind(crate::chat_protocol::device_activity::coarse_activity_day(
        now,
    ))
    .execute(&mut *tx)
    .await
    .map_err(storage)?;
    let pruned = delivery::prune_acknowledged_application_payloads(
        &mut tx,
        relay.conversation_id,
        relay.generation,
        acked_seq,
        false,
        now,
    )
    .await
    .map_err(|error| storage(format!("{error:?}")))?;
    enqueue_entries_pruned_notices(
        &mut tx,
        relay.conversation_id,
        relay.generation,
        &pruned,
        now,
    )
    .await
    .map_err(signed_relay_failure)?;
    tx.commit().await.map_err(storage)?;
    Ok(json!({
        "accepted": true,
        "acknowledgedSeq": acked_seq,
        "prunedCount": pruned.len(),
    }))
}

/// The home of `user_did`, a participant of a conversation this DS sequences:
/// its recorded participant home, else a C33 pair's declared DS, else this DS.
/// Any other conversation or user is refused.
async fn participant_home(
    state: &GroupRelayState,
    conversation_id: Uuid,
    user_did: &str,
) -> Result<String, Response> {
    let routing: Option<(String, bool, bool, Option<String>)> = sqlx::query_as(
        "SELECT c.kind, c.is_remote, p.user_did IS NOT NULL, p.ds_did \
           FROM chat.conversations c \
           LEFT JOIN LATERAL ( \
               SELECT user_did, ds_did FROM chat.participants \
                WHERE conversation_id = c.conversation_id AND user_did = $2 \
                ORDER BY current_membership DESC, created_at DESC LIMIT 1 \
           ) p ON TRUE \
          WHERE c.conversation_id = $1",
    )
    .bind(conversation_id)
    .bind(user_did)
    .fetch_optional(&state.pool)
    .await
    .map_err(storage)?;
    let (kind, ds_did) = match routing {
        Some((kind, false, true, ds_did)) => (kind, ds_did),
        Some((_, true, _, _)) => return Err(denied("this DS does not sequence the conversation")),
        Some(_) => return Err(denied("user is not a participant")),
        None => return Err(missing("conversation is not sequenced here")),
    };
    Ok(match ds_did {
        Some(ds_did) => crate::identity::canonical_did(&ds_did).to_owned(),
        // A C33 coordinator records no participant home; the pair's authority
        // is the user's declared DS, exactly as the C33 relay resolves it.
        None if kind == "direct" => {
            let resolver = crate::federation::resolver::DsResolver::new(
                state.pool.clone(),
                crate::federation::resolver::build_resolver_http_client(),
                state.self_did.clone(),
                crate::identity::self_endpoint(),
                None,
                300,
            );
            let home = resolver
                .resolve_authoritative_ds(user_did)
                .await
                .map_err(authority_lookup_failure)?;
            crate::identity::canonical_did(&home.did).to_owned()
        }
        None => state.self_did.clone(),
    })
}

/// Apply a sequencer's notice at this home's mirror of its group: prune exactly
/// the notified application sequences, keeping their immutable evidence.
pub(super) async fn accept_entries_pruned_notice(
    state: &GroupRelayState,
    caller: &str,
    body: &[u8],
) -> Result<Value, Response> {
    let notice: EntriesPrunedNotice =
        serde_json::from_slice(body).map_err(|error| invalid(&error.to_string()))?;
    if notice.conversation_id.get_version_num() != 4
        || notice.generation < 0
        || notice.seqs.first().is_none_or(|first| *first < 1)
        || notice.seqs.len() > MAX_NOTICE_SEQS
        || notice.seqs.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid("invalid entries-pruned notice"));
    }
    if notice.sequencer_did != caller || notice.home_did != state.self_did {
        return Err(denied("notice is not bound to this caller and home"));
    }
    verify_service_signature(
        &notice.sequencer_did,
        &notice.signing_bytes(),
        &notice.signature,
    )
    .await?;

    let now = crate::sim_hooks::current_utc();
    let mut tx = state.pool.begin().await.map_err(storage)?;
    let mirror: Option<(String, bool, Option<String>)> = sqlx::query_as(
        "SELECT kind, is_remote, sequencer_ds FROM chat.conversations \
          WHERE conversation_id = $1 FOR UPDATE",
    )
    .bind(notice.conversation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?;
    match mirror {
        Some((kind, true, Some(sequencer)))
            if kind == "group" && crate::identity::canonical_did(&sequencer) == caller => {}
        Some(_) => return Err(denied("conversation is not this sequencer's group mirror")),
        None => return Err(missing("conversation is not mirrored here")),
    }
    let pruned = delivery::prune_transport_payloads_pruned_by_sequencer(
        &mut tx,
        notice.conversation_id,
        notice.generation,
        &notice.seqs,
        now,
    )
    .await
    .map_err(|error| storage(format!("{error:?}")))?;
    tx.commit().await.map_err(storage)?;
    Ok(json!({ "accepted": true, "prunedCount": pruned.len() }))
}

/// Verify `signature` over `bytes` with `signer_did`'s `#atproto` P-256 key,
/// resolved exactly as the queue resolves a receiver's `FederationReceiptV1` key.
async fn verify_service_signature(
    signer_did: &str,
    bytes: &[u8],
    signature: &str,
) -> Result<(), Response> {
    let document = crate::auth::shared_auth_middleware()
        .resolve_did(signer_did)
        .await
        .map_err(signer_lookup_failure)?;
    let key = crate::auth::select_verification_method(&document, Some("#atproto"))
        .and_then(crate::auth::extract_p256_key_from_vm)
        .map_err(|error| s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", error.to_string()))?;
    let signature = STANDARD
        .decode(signature)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or_else(|| {
            s2s_err(
                StatusCode::BAD_REQUEST,
                "InvalidSignature",
                "malformed signature",
            )
        })?;
    key.verify(bytes, &signature).map_err(|_| {
        s2s_err(
            StatusCode::FORBIDDEN,
            "InvalidSignature",
            "signature does not verify",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthError;
    use crate::federation::{FederationError, ResolutionFailureKind};

    fn resolution(kind: ResolutionFailureKind) -> FederationError {
        FederationError::ResolutionFailed {
            did: "did:plc:participant".into(),
            kind,
        }
    }

    /// A relay whose participant home cannot be looked up now must stay queued
    /// at its home (5xx); only a definitive refusal is a 4xx it dead-letters.
    #[test]
    fn authority_lookup_answers_503_when_unavailable_500_on_storage_and_403_when_refused() {
        for (error, status) in [
            (
                resolution(ResolutionFailureKind::DnsTemporary("x".into())),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                FederationError::DsUnreachable {
                    endpoint: "https://pds.example".into(),
                    reason: "connect".into(),
                },
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                FederationError::Database(sqlx::Error::PoolTimedOut),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                resolution(ResolutionFailureKind::InvalidConfiguration("x".into())),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                FederationError::Unsupported("declaration absent".into()),
                StatusCode::FORBIDDEN,
            ),
            (
                resolution(ResolutionFailureKind::InvalidDeclaration("x".into())),
                StatusCode::FORBIDDEN,
            ),
        ] {
            let label = error.to_string();
            assert_eq!(authority_lookup_failure(error).status(), status, "{label}");
        }
    }

    /// The same split for the signer's DID document.
    #[test]
    fn signer_lookup_answers_503_only_when_the_document_could_not_be_fetched_now() {
        for (error, status) in [
            (
                AuthError::DidResolutionUnavailable("timeout".into()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                AuthError::RateLimitExceeded {
                    retry_after_secs: 1,
                },
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                AuthError::DidResolutionFailed("404".into()),
                StatusCode::FORBIDDEN,
            ),
            (AuthError::InvalidDid("x".into()), StatusCode::FORBIDDEN),
        ] {
            let label = error.to_string();
            assert_eq!(signer_lookup_failure(error).status(), status, "{label}");
        }
    }
}

#[cfg(test)]
#[path = "entry_ack_relay_c2_unit_tests.rs"]
mod c2_unit_tests;
