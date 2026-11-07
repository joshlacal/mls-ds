//! `blue.catbird.mlsDS.deliverTransportControlEntry` (C33 coordinator to the
//! peer's transport-only home). That home keeps no seq chain of its own: it
//! stores what its pair's coordinator delivers, and `deliverMessageEntry`
//! carries application entries only. When an account the coordinator homes is
//! deleted, the coordinator queues, in the transaction that sequences its signed
//! `accountDeletedEntry`, that exact entry to the peer's home, ordered behind
//! the pair's earlier deliveries there and retried until delivered. Before any
//! effect the home verifies that its caller is the pair's recorded coordinator
//! and the entry's sequencer, that the deleted account is its party's
//! counterparty, the coordinator's receipt authority under the retained method
//! its `keyId` names, and that the entry continues its stored seq chain. It
//! then stores the entry verbatim, so `getEntries` returns it, and prunes the
//! account's held ciphertext exactly as a sequencer's prune notice would.

use super::*;
use std::collections::BTreeMap;

use crate::federation::receipt::AccountDeletion;
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

/// Queue, in the transaction that sequenced it, the signed `entry` of a C33
/// pair this DS coordinates to the peer's transport-only `home`. The queue
/// keeps it behind the pair's earlier deliveries there by `seq`, and its id is
/// deterministic, so a replay adds nothing.
pub(crate) async fn enqueue_transport_control_entry(
    tx: &mut Transaction<'_, Postgres>,
    home: &str,
    entry: &Value,
    now: DateTime<Utc>,
) -> Result<(), SignedRelayError> {
    let (deletion, _) = AccountDeletion::from_entry(entry).map_err(SignedRelayError::Storage)?;
    let payload = serde_json::to_vec(&DeliverTransportControlEntry {
        entry: entry.clone(),
    })
    .map_err(|error| SignedRelayError::Storage(error.to_string()))?;
    queue_signed(
        tx,
        &format!(
            "transport-control-{}-{}",
            deletion.conversation_id, deletion.seq
        ),
        crate::identity::canonical_did(home),
        DELIVER_TRANSPORT_CONTROL_ENTRY_NSID,
        &payload,
        deletion.conversation_id,
        now,
    )
    .await
}

pub(super) fn routes() -> Router<GroupRelayState> {
    Router::new().route(
        "/xrpc/blue.catbird.mlsDS.deliverTransportControlEntry",
        post(ClockScoped(deliver_transport_control_entry)).layer(DefaultBodyLimit::max(16_384)),
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
    let (deletion, authority) =
        AccountDeletion::from_entry(&request.entry).map_err(|error| invalid(&error))?;
    if deletion.sequencer_did != caller || caller == state.self_did {
        return Err(denied("entry is not sequenced by this caller"));
    }
    let conversation_id = deletion.conversation_id;
    let (sequenced_here, pairs): (bool, Vec<(String, String, String)>) = (
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM chat.conversations WHERE conversation_id = $1)",
        )
        .bind(conversation_id)
        .fetch_one(&state.pool)
        .await
        .map_err(storage)?,
        sqlx::query_as(
            "SELECT coordinator_did, sender_did, recipient_did \
               FROM chat.direct_request_transport_inbox WHERE conversation_id = $1",
        )
        .bind(conversation_id)
        .fetch_all(&state.pool)
        .await
        .map_err(storage)?,
    );
    if sequenced_here {
        return Err(denied("this DS is not the pair's transport-only home"));
    }
    let Some((_, sender, recipient)) = pairs.first() else {
        return Err(missing("conversation is not held here"));
    };
    if pairs.iter().any(|(coordinator, s, r)| {
        crate::identity::canonical_did(coordinator) != caller || s != sender || r != recipient
    }) {
        return Err(denied("caller is not the pair's recorded coordinator"));
    }
    let party = if deletion.deleted_did == *sender {
        recipient
    } else if deletion.deleted_did == *recipient {
        sender
    } else {
        return Err(denied("deleted account is not a party of the pair"));
    };

    // The pair's other party must be homed here. A C33 coordinator is one of
    // the pair's two homes, so the deleted account is then homed at the caller.
    let resolver = DsResolver::new(
        state.pool.clone(),
        build_resolver_http_client(),
        state.self_did.clone(),
        crate::identity::self_endpoint(),
        None,
        300,
    );
    match resolver.resolve_authoritative_ds(party).await {
        Ok(home) if crate::identity::dids_equivalent(&home.did, &state.self_did) => {}
        Ok(_) => return Err(denied("deleted account is this home's own party")),
        Err(error) if error.is_retryable() => return Err(unavailable(error)),
        Err(error) => return Err(denied(&error.to_string())),
    }
    // The caller is the pair's coordinator; what remains is its evidence. The
    // authority names its own receipt method, so one the coordinator does not
    // retain is an authority that does not verify, like any altered signed field.
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
    .bind(deletion.seq)
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
    let entry_bytes =
        serde_json::to_vec(&request.entry).map_err(|error| storage(error.to_string()))?;
    match delivery::insert_transport_entry(
        &mut tx,
        conversation_id,
        deletion.seq,
        deletion.entry_id,
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
    let pruned = prune_deleted_account_payloads(&mut tx, &deletion, now).await?;
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
    let pruned = delivery::prune_transport_applications_sent_by(
        tx,
        deletion.conversation_id,
        &deletion.deleted_did,
        now,
    )
    .await
    .map_err(|error| storage(format!("{error:?}")))?;
    // The deleted account's direct-request opening carries application ciphertext
    // too (O7): its copies go here as well, outside the application count.
    crate::chat_protocol::repository::direct_request_opening::prune_transport_openings_sent_by(
        tx,
        deletion.conversation_id,
        &deletion.deleted_did,
        now,
    )
    .await
    .map_err(storage)?;
    Ok(pruned)
}
