//! `blue.catbird.mlsDS.deliverTransportControlEntry` (C33 coordinator to the
//! peer's transport-only home). A transport home keeps no seq chain of its own:
//! it stores the I13-receipted control and application entries its pair's
//! coordinator delivers. Every control delivery is queued in the transaction
//! that sequences it, ordered by seq, and has a deterministic id.
//!
//! Before any effect the home verifies the recorded coordinator, the receipt
//! method named by its own `kid`, every signed receipt binding, and continuity
//! with the stored seq chain. Account deletion additionally verifies its
//! retained deletion authority and prunes the deleted account's held
//! ciphertext. Entries are stored verbatim so `getEntries` returns the receipt.

use super::*;
use std::collections::BTreeMap;

use crate::federation::receipt::{verify_control_receipt, AccountDeletion, I13ControlReceiptInput};
use crate::federation::resolver::{build_resolver_http_client, DsResolver};
use crate::federation::FederationError;

pub(crate) const DELIVER_TRANSPORT_CONTROL_ENTRY_NSID: &str =
    "blue.catbird.mlsDS.deliverTransportControlEntry";

/// One signed control entry for a C33 transport-only home.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeliverTransportControlEntry {
    pub(crate) entry: Value,
}

/// The transport-only home each C33 pair's deletion entry is owed, resolved
/// from the peer's declaration before the deletion's transaction (M-F04). It
/// names every active direct conversation this DS sequences for the account:
/// `None` where the peer is homed here, declares no home, or is itself deleted
/// in that conversation.
#[derive(Debug, Default)]
pub struct C33PeerHomes(BTreeMap<Uuid, Option<String>>);

pub(crate) struct C33TransitionPeer {
    pub(crate) home: Option<String>,
    pub(crate) deleted: bool,
}

impl C33PeerHomes {
    /// Resolve the peer's home in every active direct conversation this DS
    /// sequences for `deleted_did`. A transient failure refuses the deletion
    /// rather than strand its entry.
    pub async fn resolve(pool: &DbPool, deleted_did: &str) -> Result<Self, FederationError> {
        let peers: Vec<(Uuid, Option<String>)> = sqlx::query_as(
            "SELECT DISTINCT c.conversation_id, \
                    CASE WHEN c.direct_did_low = $1 THEN c.direct_did_high ELSE c.direct_did_low END \
               FROM chat.participants p \
               JOIN chat.conversations c ON c.conversation_id = p.conversation_id \
              WHERE p.user_did = $1 AND p.current_membership AND p.status = 'active' \
                AND c.kind = 'direct' AND NOT c.is_remote AND c.lifecycle = 'active' \
              ORDER BY 1",
        )
        .bind(deleted_did)
        .fetch_all(pool)
        .await?;
        let resolver = resolver(pool);
        let mut homes = BTreeMap::new();
        for (conversation_id, peer) in peers {
            let home = match peer {
                None => None,
                Some(peer) => home_in(pool, &resolver, conversation_id, &peer).await?,
            };
            homes.insert(conversation_id, home);
        }
        Ok(Self(homes))
    }

    /// `peer`'s transport-only home in one direct pair, as [`Self::resolve`]
    /// resolves it; a C33 close resolves its peer's home with it.
    pub async fn peer_home(
        pool: &DbPool,
        conversation_id: Uuid,
        peer: &str,
    ) -> Result<Option<String>, FederationError> {
        home_in(pool, &resolver(pool), conversation_id, peer).await
    }

    /// `None` when `conversation_id` was not resolved, so its peer is unknown.
    pub fn home(&self, conversation_id: Uuid) -> Option<Option<&str>> {
        self.0.get(&conversation_id).map(Option::as_deref)
    }
    /// Resolve the peer routing state for a local C33 direct pair. Keeping the
    /// deletion bit separate lets a relayed transition suppress its receipt
    /// delivery even when the peer's ordinary home would also be local.
    pub(crate) async fn transition_peer(
        pool: &DbPool,
        conversation_id: Uuid,
        actor: &str,
    ) -> Result<Option<C33TransitionPeer>, FederationError> {
        let pair: Option<(String, String)> = sqlx::query_as(
            "SELECT direct_did_low,direct_did_high \
               FROM chat.conversations \
              WHERE conversation_id=$1 AND kind='direct' AND NOT is_remote \
                AND lifecycle='active' \
                AND direct_did_low IS NOT NULL AND direct_did_high IS NOT NULL",
        )
        .bind(conversation_id)
        .fetch_optional(pool)
        .await?;
        let Some((requester, recipient)) = pair else {
            return Ok(None);
        };
        let actor = crate::identity::canonical_did(actor);
        let peer = if crate::identity::canonical_did(&requester) == actor {
            recipient
        } else if crate::identity::canonical_did(&recipient) == actor {
            requester
        } else {
            return Err(FederationError::InvalidRequest(
                "control actor is not a party of the C33 pair".to_owned(),
            ));
        };
        if crate::federation::canonical_relay::account_deleted_in(pool, conversation_id, &peer)
            .await?
        {
            return Ok(Some(C33TransitionPeer {
                home: None,
                deleted: true,
            }));
        }
        let resolver = resolver(pool);
        let actor_home = resolver.resolve_authoritative_ds(actor).await?;
        let home = home_of(&resolver, &peer)
            .await?
            .filter(|peer_home| !crate::identity::dids_equivalent(&actor_home.did, peer_home));
        Ok(Some(C33TransitionPeer {
            home,
            deleted: false,
        }))
    }

    /// Resolve the transport-only home owed a control entry for a local C33
    /// direct pair. Ordinary Direct and Group conversations return `None`.
    pub(crate) async fn transition_peer_home(
        pool: &DbPool,
        conversation_id: Uuid,
        actor: &str,
    ) -> Result<Option<String>, FederationError> {
        Ok(Self::transition_peer(pool, conversation_id, actor)
            .await?
            .and_then(|peer| peer.home))
    }
}

fn resolver(pool: &DbPool) -> DsResolver {
    DsResolver::new(
        pool.clone(),
        build_resolver_http_client(),
        crate::identity::service_did_base(),
        crate::identity::self_endpoint(),
        None,
        300,
    )
}

/// `peer`'s home in `conversation_id`: `None` once `peer`'s own
/// `accountDeletedEntry` is sequenced there, since its home is owed none of
/// that conversation's later entries; otherwise [`home_of`].
async fn home_in(
    pool: &DbPool,
    resolver: &DsResolver,
    conversation_id: Uuid,
    peer: &str,
) -> Result<Option<String>, FederationError> {
    if crate::federation::canonical_relay::account_deleted_in(pool, conversation_id, peer).await? {
        return Ok(None);
    }
    home_of(resolver, peer).await
}

/// `peer`'s declared home: `None` where that is this DS or `peer` declares no
/// home. Any other failure, transient included, is returned.
async fn home_of(resolver: &DsResolver, peer: &str) -> Result<Option<String>, FederationError> {
    // ponytail: a peer whose DID or declaration is gone is owed nothing;
    // persist the owed delivery if a later re-declared home must get it.
    match resolver.resolve_did_to_pds(peer).await {
        Err(error) if error.is_retryable() => Err(error),
        Err(_) => Ok(None),
        Ok(_) => match resolver.resolve_authoritative_ds(peer).await {
            Ok(home) => Ok(Some(crate::identity::canonical_did(&home.did).to_owned())
                .filter(|home| !crate::identity::dids_equivalent(home, resolver.self_did()))),
            Err(FederationError::Unsupported(_)) => Ok(None),
            Err(error) => Err(error),
        },
    }
}

#[derive(Clone, Copy)]
struct TransportControlLocator {
    conversation_id: Uuid,
    entry_id: Uuid,
    seq: i64,
}

fn transport_control_locator(entry: &Value) -> Result<TransportControlLocator, String> {
    let conversation_id = entry
        .get("conversationId")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| "invalid control entry conversationId".to_owned())?;
    let entry_id = entry
        .get("entryId")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| "invalid control entry entryId".to_owned())?;
    let seq = entry
        .get("seq")
        .and_then(Value::as_u64)
        .and_then(|value| i64::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| "invalid control entry seq".to_owned())?;
    Ok(TransportControlLocator {
        conversation_id,
        entry_id,
        seq,
    })
}

/// Queue, in the transaction that sequenced it, the exact receipted control
/// `entry` owed to a C33 peer's transport-only `home`.
pub(crate) async fn enqueue_transport_control_entry(
    tx: &mut Transaction<'_, Postgres>,
    home: &str,
    entry: &Value,
    now: DateTime<Utc>,
) -> Result<(), SignedRelayError> {
    let locator = transport_control_locator(entry).map_err(SignedRelayError::Storage)?;
    let payload = serde_json::to_vec(&DeliverTransportControlEntry {
        entry: entry.clone(),
    })
    .map_err(|error| SignedRelayError::Storage(error.to_string()))?;
    queue_signed(
        tx,
        &format!(
            "transport-control-{}-{}",
            locator.conversation_id, locator.seq
        ),
        crate::identity::canonical_did(home),
        DELIVER_TRANSPORT_CONTROL_ENTRY_NSID,
        &payload,
        locator.conversation_id,
        now,
    )
    .await
}

/// Extract and queue the exact I13-receipted entry from a canonical endpoint
/// response. A signer-less response is never allowed to commit for a remote
/// C33 peer.
pub(crate) async fn enqueue_transport_control_response(
    tx: &mut Transaction<'_, Postgres>,
    home: &str,
    response_bytes: &[u8],
    now: DateTime<Utc>,
) -> Result<(), SignedRelayError> {
    let response: Value = serde_json::from_slice(response_bytes)
        .map_err(|error| SignedRelayError::Storage(error.to_string()))?;
    let entry = response
        .pointer("/entry")
        .or_else(|| response.pointer("/result/entry"))
        .filter(|entry| entry["sequencerReceipt"].is_object())
        .ok_or_else(|| {
            SignedRelayError::Storage("C33 control response has no I13 receipt".to_owned())
        })?;
    enqueue_transport_control_entry(tx, home, entry, now).await
}

pub(super) fn routes() -> Router<GroupRelayState> {
    Router::new().route(
        "/xrpc/blue.catbird.mlsDS.deliverTransportControlEntry",
        post(ClockScoped(deliver_transport_control_entry)).layer(DefaultBodyLimit::max(
            crate::request_body_limit("/xrpc/blue.catbird.mlsDS.deliverTransportControlEntry"),
        )),
    )
}

async fn deliver_transport_control_entry(
    State(state): State<GroupRelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match verify_s2s_caller(
        &state,
        &headers,
        DELIVER_TRANSPORT_CONTROL_ENTRY_NSID,
        &body,
    )
    .await
    {
        Ok(caller) => respond(accept_transport_control_entry(&state, &caller, &body).await),
        Err(response) => response,
    }
}
fn is_relayed_control_kind(kind: crate::chat_protocol::transcript::SignedMutationKind) -> bool {
    use crate::chat_protocol::transcript::SignedMutationKind;
    matches!(
        kind,
        SignedMutationKind::CommitTransition
            | SignedMutationKind::PolicyTransition
            | SignedMutationKind::MetadataTransition
            | SignedMutationKind::ResetRequest
            | SignedMutationKind::ResetActivation
            | SignedMutationKind::LeafRecoveryRequest
            | SignedMutationKind::LeafRecoveryCancellation
            | SignedMutationKind::LeafRecoveryFulfillment
            | SignedMutationKind::ConversationClose
            | SignedMutationKind::LeaveRequest
            | SignedMutationKind::ZeroLeafLeave
            | SignedMutationKind::LeaveCancellation
            | SignedMutationKind::LeaveCommitFulfillment
    )
}

async fn resolve_control_receipt_key(
    resolver: &DsResolver,
    caller: &str,
    entry: &Value,
) -> Result<p256::ecdsa::VerifyingKey, Response> {
    let key_id = entry
        .pointer("/sequencerReceipt/kid")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("control receipt has no kid"))?;
    let key = resolver
        .resolve_i13_receipt_key(caller, key_id)
        .await
        .map_err(|error| {
            if error.is_retryable() {
                unavailable(error)
            } else {
                s2s_err(StatusCode::FORBIDDEN, "InvalidSignature", error.to_string())
            }
        })?;
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&key)
        .map_err(|_| denied("coordinator receipt key is not P-256"))
}

fn stored_entry_receipt_coordinate(entry: &Value) -> Option<&Value> {
    let body = entry.pointer("/signedRequest/body")?.as_object()?;
    let kind = entry
        .get("$type")
        .and_then(Value::as_str)
        .and_then(crate::chat_protocol::transcript::ControlEntryKind::from_type_id);
    match kind {
        Some(kind) => {
            crate::federation::receipt::control_receipt_coordinate(kind.signed_kind(), body, None)
                .ok()
        }
        None => body.get("prior").filter(|value| value.is_object()),
    }
}

enum ControlReceiptError {
    Invalid(String),
    InvalidSignature(String),
}

impl ControlReceiptError {
    fn into_response(self) -> Response {
        match self {
            Self::Invalid(message) => invalid(&message),
            Self::InvalidSignature(message) => {
                s2s_err(StatusCode::FORBIDDEN, "InvalidSignature", message)
            }
        }
    }
}

fn verify_receipted_control_entry(
    entry: &Value,
    caller: &str,
    locator: TransportControlLocator,
    predecessor_coordinate: Option<&Value>,
    key: &p256::ecdsa::VerifyingKey,
) -> Result<(), ControlReceiptError> {
    let receipt = entry.get("sequencerReceipt").ok_or_else(|| {
        ControlReceiptError::Invalid("control entry has no sequencer receipt".into())
    })?;
    let mut actor_entry = entry.clone();
    actor_entry
        .as_object_mut()
        .ok_or_else(|| ControlReceiptError::Invalid("control entry is not an object".into()))?
        .remove("sequencerReceipt");
    let bytes = serde_json::to_vec(&actor_entry)
        .map_err(|error| ControlReceiptError::Invalid(error.to_string()))?;
    let mutation =
        crate::chat_protocol::transcript::decode_control_entry_mutation_unverified(&bytes)
            .map_err(|error| {
                ControlReceiptError::Invalid(format!("invalid control entry: {error:?}"))
            })?;
    if !is_relayed_control_kind(mutation.kind()) {
        return Err(ControlReceiptError::Invalid(
            "entry kind is not a relayed control entry".into(),
        ));
    }
    let body = entry
        .pointer("/signedRequest/body")
        .and_then(Value::as_object)
        .ok_or_else(|| ControlReceiptError::Invalid("control entry has no signed body".into()))?;
    let coordinate = crate::federation::receipt::control_receipt_coordinate(
        mutation.kind(),
        body,
        predecessor_coordinate,
    )
    .map_err(ControlReceiptError::Invalid)?;
    let received_at = entry
        .get("receivedAt")
        .and_then(Value::as_str)
        .ok_or_else(|| ControlReceiptError::Invalid("control entry has no receivedAt".into()))?;
    let input = I13ControlReceiptInput::from_fields(
        &locator.conversation_id.to_string(),
        &locator.entry_id.to_string(),
        u64::try_from(locator.seq)
            .map_err(|_| ControlReceiptError::Invalid("invalid control entry seq".into()))?,
        received_at,
        mutation.actor_did().as_str(),
        mutation.actor_device_id().as_str(),
        *mutation.request_digest(),
    )
    .map_err(ControlReceiptError::Invalid)?;
    verify_control_receipt(receipt, key, caller, &input, coordinate)
        .map_err(ControlReceiptError::InvalidSignature)
}

/// Apply a C33 coordinator's signed control entry at this transport-only home.
/// Every check precedes every effect; an entry that does not yet continue the
/// stored seq chain is refused retryably, as a predecessor gap.
pub(crate) async fn accept_transport_control_entry(
    state: &GroupRelayState,
    caller: &str,
    body: &[u8],
) -> Result<Value, Response> {
    let request: DeliverTransportControlEntry =
        serde_json::from_slice(body).map_err(|error| invalid(&error.to_string()))?;
    let locator = transport_control_locator(&request.entry).map_err(|error| invalid(&error))?;
    if crate::identity::dids_equivalent(caller, &state.self_did) {
        return Err(denied("entry is not sequenced by a remote caller"));
    }
    let conversation_id = locator.conversation_id;
    let (sequenced_here, pairs): (bool, Vec<(String, String, String, String)>) = (
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM chat.conversations WHERE conversation_id = $1)",
        )
        .bind(conversation_id)
        .fetch_one(&state.pool)
        .await
        .map_err(storage)?,
        sqlx::query_as(
            "SELECT coordinator_did, sender_did, recipient_did, status \
               FROM chat.direct_request_transport_inbox \
              WHERE conversation_id = $1 AND status IN ('pending', 'accepted')",
        )
        .bind(conversation_id)
        .fetch_all(&state.pool)
        .await
        .map_err(storage)?,
    );
    if sequenced_here {
        return Err(denied("this DS is not the pair's transport-only home"));
    }
    let Some((_, sender, recipient, _)) = pairs.first() else {
        return Err(missing("conversation is not held here"));
    };
    if pairs.iter().any(|(coordinator, s, r, _)| {
        !crate::identity::dids_equivalent(coordinator, caller) || s != sender || r != recipient
    }) {
        return Err(denied("caller is not the pair's recorded coordinator"));
    }

    let resolver = DsResolver::new(
        state.pool.clone(),
        build_resolver_http_client(),
        state.self_did.clone(),
        crate::identity::self_endpoint(),
        None,
        300,
    );
    let deletion = match AccountDeletion::from_entry(&request.entry) {
        Ok((deletion, authority)) => {
            if !crate::identity::dids_equivalent(&deletion.sequencer_did, caller) {
                return Err(denied("entry is not sequenced by this caller"));
            }
            let party = if deletion.deleted_did == *sender {
                recipient
            } else if deletion.deleted_did == *recipient {
                sender
            } else {
                return Err(denied("deleted account is not a party of the pair"));
            };
            // A C33 coordinator is one of the pair's two homes. The other
            // party must therefore be homed here before deletion may prune.
            match resolver.resolve_authoritative_ds(party).await {
                Ok(home) if crate::identity::dids_equivalent(&home.did, &state.self_did) => {}
                Ok(_) => return Err(denied("deleted account is this home's own party")),
                Err(error) if error.is_retryable() => return Err(unavailable(error)),
                Err(error) => return Err(denied(&error.to_string())),
            }
            let key = resolver
                .resolve_i13_receipt_key(caller, &authority.key_id)
                .await
                .map_err(|error| {
                    if error.is_retryable() {
                        unavailable(error)
                    } else {
                        s2s_err(StatusCode::FORBIDDEN, "InvalidSignature", error.to_string())
                    }
                })?;
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key)
                .map_err(|_| denied("coordinator receipt key is not P-256"))?;
            authority
                .verify(&key, &deletion)
                .map_err(|error| s2s_err(StatusCode::FORBIDDEN, "InvalidSignature", error))?;
            let signed_at = super::account_deletion_relay::verify_user_deletion(
                &resolver,
                &deletion.deleted_did,
                deletion.evidence.as_ref(),
            )
            .await?;
            if signed_at - deletion.deleted_at
                > chrono::Duration::seconds(crate::labyrinth::auth::WRITE_SKEW_SECONDS)
            {
                return Err(denied("device deletion postdates sequencer entry"));
            }
            Some(deletion)
        }
        Err(_) => None,
    };
    if deletion.is_none() && !pairs.iter().any(|(_, _, _, status)| status == "accepted") {
        return Err(missing("conversation is not accepted here"));
    }
    let receipt_key = if deletion.is_none() {
        Some(resolve_control_receipt_key(&resolver, caller, &request.entry).await?)
    } else {
        None
    };

    let now = crate::sim_hooks::current_utc();
    let mut tx = state.pool.begin().await.map_err(storage)?;
    sqlx::query(
        "SELECT 1 FROM chat.direct_request_transport_inbox \
          WHERE conversation_id = $1 ORDER BY delivery_id FOR UPDATE",
    )
    .bind(conversation_id)
    .execute(&mut *tx)
    .await
    .map_err(storage)?;
    let (occupied, continues): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM chat.direct_request_transport_entries \
                        WHERE conversation_id = $1 AND seq = $2), \
                EXISTS(SELECT 1 FROM chat.direct_request_transport_entries \
                        WHERE conversation_id = $1 AND seq = $2 - 1)",
    )
    .bind(conversation_id)
    .bind(locator.seq)
    .fetch_one(&mut *tx)
    .await
    .map_err(storage)?;
    if !occupied && !continues {
        return Err(s2s_err(
            StatusCode::CONFLICT,
            crate::federation::errors::PREDECESSOR_MISSING_ERROR,
            "the entry's predecessor is not stored here yet",
        ));
    }
    let predecessor: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT entry_bytes FROM chat.direct_request_transport_entries \
          WHERE conversation_id=$1 AND seq=$2-1",
    )
    .bind(conversation_id)
    .bind(locator.seq)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?;
    let predecessor = predecessor
        .as_deref()
        .map(serde_json::from_slice::<Value>)
        .transpose()
        .map_err(|error| storage(format!("stored predecessor is invalid: {error}")))?;
    if deletion.is_none() {
        let predecessor_coordinate = predecessor
            .as_ref()
            .and_then(stored_entry_receipt_coordinate);
        verify_receipted_control_entry(
            &request.entry,
            caller,
            locator,
            predecessor_coordinate,
            receipt_key
                .as_ref()
                .expect("non-deletion receipt key was resolved before the inbox lock"),
        )
        .map_err(ControlReceiptError::into_response)?;
    }
    let entry_bytes =
        serde_json::to_vec(&request.entry).map_err(|error| storage(error.to_string()))?;
    match delivery::insert_transport_entry(
        &mut tx,
        conversation_id,
        locator.seq,
        locator.entry_id,
        &entry_bytes,
        now,
    )
    .await
    .map_err(storage)?
    {
        delivery::TransportEntryInsert::Inserted => {}
        delivery::TransportEntryInsert::Duplicate => {
            return Ok(json!({ "accepted": true, "applied": false, "prunedCount": 0 }));
        }
        delivery::TransportEntryInsert::Conflict => {
            return Err(s2s_err(
                StatusCode::CONFLICT,
                "EntryConflict",
                "another entry holds this seq",
            ));
        }
    }
    match request
        .entry
        .pointer("/signedRequest/body/$type")
        .and_then(Value::as_str)
    {
        Some("blue.catbird.chat.defs#leafRecoveryCancellationBody")
        | Some("blue.catbird.chat.defs#leafRecoveryFulfillmentBody") => {
            if let Some(request_id) = request
                .entry
                .pointer("/signedRequest/body/recoveryRequestId")
                .and_then(Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok())
            {
                sqlx::query(
                    "DELETE FROM chat.remote_lifecycle_recovery_bindings \
                     WHERE recovery_request_id=$1",
                )
                .bind(request_id)
                .execute(&mut *tx)
                .await
                .map_err(storage)?;
            }
        }
        Some("blue.catbird.chat.defs#conversationCloseBody") => {
            sqlx::query(
                "DELETE FROM chat.remote_lifecycle_recovery_bindings WHERE conversation_id=$1",
            )
            .bind(conversation_id)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        }
        _ => {}
    }
    let pruned = match &deletion {
        Some(deletion) => prune_deleted_account_payloads(&mut tx, deletion, now).await?,
        None => 0,
    };
    tx.commit().await.map_err(storage)?;
    Ok(json!({ "accepted": true, "applied": true, "prunedCount": pruned }))
}

/// Prune every application payload and direct-request opening the deleted
/// account sent that this home holds, exactly as the sequencer's prune notice
/// does.
async fn prune_deleted_account_payloads(
    tx: &mut Transaction<'_, Postgres>,
    deletion: &AccountDeletion,
    now: DateTime<Utc>,
) -> Result<usize, Response> {
    let evidence = deletion
        .evidence
        .as_ref()
        .ok_or_else(|| denied("missing deletion authority"))?;
    let signed_at = evidence.signed_at().map_err(|err| invalid(&err))?;
    // On a C33 mirror receivedAt is the sequencer instant, which may lag the original home.
    // The peer only removes entries within both the signed time and ordered entry boundary.
    let cutoff = deletion
        .deleted_at
        .min(signed_at + chrono::Duration::seconds(crate::labyrinth::auth::WRITE_SKEW_SECONDS));
    if !super::account_deletion_relay::claim_deletion_operation(
        tx,
        deletion.conversation_id,
        &deletion.deleted_did,
        evidence,
        cutoff,
        deletion.seq,
    )
    .await?
    {
        return Ok(0);
    }
    let pruned = delivery::prune_transport_applications_sent_before(
        tx,
        deletion.conversation_id,
        &deletion.deleted_did,
        deletion.seq,
        cutoff,
        now,
    )
    .await
    .map_err(|error| storage(format!("{error:?}")))?;
    // The deleted account's direct-request opening carries application ciphertext
    // too (O7): its copies go here as well, outside the application count.
    crate::chat_protocol::repository::direct_request_opening::prune_transport_openings_sent_before(
        tx,
        deletion.conversation_id,
        &deletion.deleted_did,
        deletion.seq,
        cutoff,
        now,
    )
    .await
    .map_err(storage)?;
    Ok(pruned)
}
