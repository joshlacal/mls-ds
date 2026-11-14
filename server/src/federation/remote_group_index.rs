//! A home DS's sequencer-authenticated membership index for remote groups
//! (`chat.remote_group_memberships`, migration `20261104000001`).
//!
//! The clean mirror graph replays only the historical prefix grammar. Once a
//! group's history holds a generic Commit, a metadata change or a removal, an
//! account homed here that joins later can never enter that graph. The index
//! records only what the group's stored sequencer proves about accounts homed
//! here: each row comes from a `deliverGroupEntry` the mirror's sequencer
//! authenticated, whose control entry verifies under its actor's key at the
//! exact signed authentication generation, applied in sequence order.
//!
//! An index member whose clean graph lacks it is served by relaying its
//! conversation-state and pending-Welcome reads to the sequencer; its
//! replicated entries are readable through their per-entry device grants. A
//! removed member reads nothing.

use chrono::{DateTime, Utc};

use super::*;
use crate::chat_protocol::transcript::{
    decode_and_verify_control_entry, decode_control_entry_mutation_unverified,
};

const ADD_PARTICIPANT: &str = "blue.catbird.chat.defs#addParticipant";
const REMOVE_PARTICIPANT: &str = "blue.catbird.chat.defs#removeParticipant";
const CREATION_BODY: &str = "blue.catbird.chat.defs#creationBody";
const ACCEPTANCE_BODY: &str = "blue.catbird.chat.defs#participantAcceptanceBody";
const ACCOUNT_DELETED_ENTRY: &str = "blue.catbird.chat.defs#accountDeletedEntry";
const CONVERSATION_INVENTORY_STATE: &str = "blue.catbird.chat.defs#conversationInventoryState";
/// `getConversations` / `getPendingWelcomes` lexicon `items.maxLength`.
const MAX_INVENTORY_ITEMS: usize = 100;

/// What one verified entry proves about the membership of accounts homed here.
#[derive(Debug, Default)]
pub(super) struct MembershipEvidence {
    seq: i64,
    entry_id: Uuid,
    invited: Vec<String>,
    active: Vec<String>,
    removed: Vec<String>,
    /// `(recipient DID, recipient device, Welcome ID)` of a recovery fulfilment.
    welcomes: Vec<(String, Uuid, Uuid)>,
}

impl MembershipEvidence {
    fn is_empty(&self) -> bool {
        self.invited.is_empty()
            && self.active.is_empty()
            && self.removed.is_empty()
            && self.welcomes.is_empty()
    }

    /// `(recipient DID, recipient device)` of each recorded Welcome.
    pub(super) fn welcome_devices(&self) -> impl Iterator<Item = (String, Uuid)> + '_ {
        self.welcomes
            .iter()
            .map(|(did, device, _)| (did.clone(), *device))
    }
}

/// The membership effects an entry's signed body claims, before any check.
fn claimed_evidence(body: &Value, seq: i64, entry_id: Uuid) -> MembershipEvidence {
    let text = |value: &Value, key: &str| value.get(key).and_then(Value::as_str).map(str::to_owned);
    let mut claimed = MembershipEvidence {
        seq,
        entry_id,
        ..MembershipEvidence::default()
    };
    match body.get("$type").and_then(Value::as_str) {
        Some(CREATION_BODY) => {
            for participant in body
                .pointer("/manifest/participants")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if participant.get("status").and_then(Value::as_str) == Some("pending") {
                    claimed.invited.extend(text(participant, "userDid"));
                }
            }
        }
        Some(ACCEPTANCE_BODY) => claimed.active.extend(text(body, "actorDid")),
        _ => {}
    }
    for change in body
        .get("participantChanges")
        .or_else(|| body.pointer("/manifest/participantChanges"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        match change.get("$type").and_then(Value::as_str) {
            Some(ADD_PARTICIPANT) => claimed.invited.extend(text(change, "userDid")),
            Some(REMOVE_PARTICIPANT) => claimed.removed.extend(text(change, "userDid")),
            _ => {}
        }
    }
    if let Some(bundle) = body.pointer("/manifest/welcomeBundle") {
        let welcome = bundle
            .get("welcomeId")
            .and_then(Value::as_str)
            .and_then(|id| Uuid::parse_str(id).ok());
        for delivery in bundle
            .get("deliveries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let device = delivery
                .get("recipientDeviceId")
                .and_then(Value::as_str)
                .and_then(|id| Uuid::parse_str(id).ok());
            if let (Some(did), Some(device), Some(welcome)) =
                (text(delivery, "recipientDid"), device, welcome)
            {
                claimed.welcomes.push((did, device, welcome));
            }
        }
    }
    claimed
}

/// Reduce `req`'s claimed membership effects to accounts homed here and, when
/// any remain, verify the control entry under its actor's key at the exact
/// signed authentication generation. Runs before the persisting transaction:
/// resolution and key directory reads are HTTP.
///
/// The caller has already authenticated the stored sequencer as the caller and,
/// for an `accountDeletedEntry`, verified its sequencer authority.
/// The actor signs the closed control-entry projection; the sequencer appends I13 evidence after
/// sequencing. Verify the former without teaching the closed actor transcript about server fields.
fn actor_signed_control_entry_bytes(
    entry_bytes: &[u8],
) -> Result<Vec<u8>, (StatusCode, &'static str, String)> {
    let mut entry: serde_json::Value = serde_json::from_slice(entry_bytes).map_err(|error| {
        (
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            format!("membership evidence JSON: {error}"),
        )
    })?;
    let fields = entry.as_object_mut().ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "membership evidence is not an object".to_owned(),
        )
    })?;
    if fields
        .remove("sequencerReceipt")
        .is_some_and(|receipt| !receipt.is_object())
    {
        return Err((
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "membership evidence sequencerReceipt is not an object".to_owned(),
        ));
    }
    serde_json::to_vec(&entry).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            error.to_string(),
        )
    })
}

pub(super) async fn verify_membership_evidence(
    state: &GroupRelayState,
    req: &DeliverGroupEntryRequest,
    entry_bytes: &[u8],
    seq: i64,
    entry_id: Uuid,
) -> Result<Option<MembershipEvidence>, Response> {
    let unavailable =
        |error: String| s2s_err(StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable", error);
    let storage = |error: sqlx::Error| unavailable(error.to_string());
    let tracked = |dids: Vec<String>| async move {
        if dids.is_empty() {
            return Ok(dids);
        }
        sqlx::query_scalar::<_, String>(
            "SELECT user_did FROM chat.remote_group_memberships \
              WHERE conversation_id = $1 AND user_did = ANY($2) ORDER BY user_did",
        )
        .bind(req.conversation_id)
        .bind(&dids)
        .fetch_all(&state.pool)
        .await
    };

    if req.entry.get("$type").and_then(Value::as_str) == Some(ACCOUNT_DELETED_ENTRY) {
        let deleted = req
            .entry
            .get("deletedDid")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .into_iter()
            .collect();
        let removed = tracked(deleted).await.map_err(storage)?;
        let evidence = MembershipEvidence {
            seq,
            entry_id,
            removed,
            ..MembershipEvidence::default()
        };
        return Ok((!evidence.is_empty()).then_some(evidence));
    }
    let Some(body) = req.entry.pointer("/signedRequest/body") else {
        return Ok(None);
    };
    let claimed = claimed_evidence(body, seq, entry_id);
    if claimed.is_empty() {
        return Ok(None);
    }

    // Only accounts homed here enter the index; acceptances, removals and
    // Welcomes only ever touch rows an earlier invitation created.
    let resolver = super::super::resolver::DsResolver::new(
        state.pool.clone(),
        super::super::resolver::build_resolver_http_client(),
        state.self_did.clone(),
        crate::identity::self_endpoint(),
        None,
        300,
    );
    let mut invited = Vec::new();
    for did in claimed.invited {
        let home = resolver
            .resolve_authoritative_ds(&did)
            .await
            .map_err(lookup_failure)?;
        if crate::identity::dids_equivalent(&home.did, &state.self_did) {
            invited.push(did);
        }
    }
    let known = tracked(
        claimed
            .active
            .iter()
            .chain(&claimed.removed)
            .chain(claimed.welcomes.iter().map(|(did, _, _)| did))
            .cloned()
            .collect(),
    )
    .await
    .map_err(storage)?;
    let is_known = |did: &String| known.contains(did) || invited.contains(did);
    let evidence = MembershipEvidence {
        seq,
        entry_id,
        active: claimed.active.into_iter().filter(is_known).collect(),
        removed: claimed.removed.into_iter().filter(is_known).collect(),
        welcomes: claimed
            .welcomes
            .into_iter()
            .filter(|(did, _, _)| is_known(did))
            .collect(),
        invited,
    };
    if evidence.is_empty() {
        return Ok(None);
    }

    let forbidden = |error: String| s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", error);
    let actor_entry_bytes = actor_signed_control_entry_bytes(entry_bytes)
        .map_err(|(status, code, message)| s2s_err(status, code, message))?;
    let mutation = decode_control_entry_mutation_unverified(&actor_entry_bytes)
        .map_err(|error| forbidden(format!("membership evidence: {error:?}")))?;
    let generation = i64::try_from(mutation.auth_generation())
        .map_err(|_| forbidden("membership evidence generation".into()))?;
    let actor = mutation.actor_did().as_str().to_owned();
    let device = Uuid::from_bytes(*mutation.actor_device_id().as_bytes());
    let key_id = mutation.key_id().as_str().to_owned();
    let key = actor_signing_key(state, &actor, device, &key_id, generation).await?;
    let verified = decode_and_verify_control_entry(&actor_entry_bytes, &key).map_err(|error| {
        s2s_err(
            StatusCode::UNAUTHORIZED,
            "InvalidSignature",
            format!("membership evidence: {error:?}"),
        )
    })?;
    if verified.seq() != seq as u64
        || verified.entry_id().as_bytes() != entry_id.as_bytes()
        || verified.conversation_id().as_bytes() != req.conversation_id.as_bytes()
    {
        return Err(forbidden(
            "membership evidence is bound to another entry".into(),
        ));
    }
    Ok(Some(evidence))
}

/// The actor key that was current at `generation`: retained here, or vouched
/// for by the actor's home when this DS never staged that device.
async fn actor_signing_key(
    state: &GroupRelayState,
    actor: &str,
    device: Uuid,
    key_id: &str,
    generation: i64,
) -> Result<Vec<u8>, Response> {
    let retained: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT k.signing_public_key FROM chat.device_keys k \
           JOIN chat.devices d USING (user_did, device_id) \
          WHERE k.user_did = $1 AND k.device_id = $2 AND k.key_id = $3 \
            AND k.revoked_at IS NULL AND d.status = 'active' AND d.revoked_at IS NULL \
            AND k.enrollment_auth_generation <= $4 AND $4 <= d.auth_generation \
            AND NOT EXISTS(SELECT 1 FROM chat.device_keys newer \
                 WHERE newer.user_did = k.user_did AND newer.device_id = k.device_id \
                   AND newer.enrollment_auth_generation > k.enrollment_auth_generation \
                   AND newer.enrollment_auth_generation <= $4)",
    )
    .bind(actor)
    .bind(device)
    .bind(key_id)
    .bind(generation)
    .fetch_optional(&state.pool)
    .await
    .map_err(|error| {
        s2s_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            error.to_string(),
        )
    })?;
    if let Some(key) = retained {
        return Ok(key);
    }
    let (key, current) = membership::active_device_key(&state.pool, actor, device, key_id)
        .await
        .map_err(|error| {
            s2s_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                error.to_string(),
            )
        })?;
    if current != generation {
        return Err(s2s_err(
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "membership evidence actor generation is not current",
        ));
    }
    Ok(key)
}

/// Apply verified `evidence` from `sequencer_did` in the transaction that
/// persists its entry. An older entry never overwrites newer evidence.
pub(super) async fn apply_membership_evidence(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    conversation_id: Uuid,
    sequencer_did: &str,
    evidence: &MembershipEvidence,
    now: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    if !evidence.invited.is_empty() {
        sqlx::query(
            "INSERT INTO chat.remote_group_memberships AS m \
                 (conversation_id, user_did, sequencer_did, status, evidence_seq, \
                  evidence_entry_id, updated_at) \
             SELECT $1, invited, $3, 'pending', $4, $5, $6 FROM unnest($2::text[]) AS invited \
             ON CONFLICT (conversation_id, user_did) DO UPDATE \
                SET status = 'pending', evidence_seq = EXCLUDED.evidence_seq, \
                    evidence_entry_id = EXCLUDED.evidence_entry_id, updated_at = EXCLUDED.updated_at \
              WHERE m.sequencer_did = EXCLUDED.sequencer_did \
                AND m.evidence_seq < EXCLUDED.evidence_seq",
        )
        .bind(conversation_id)
        .bind(&evidence.invited)
        .bind(sequencer_did)
        .bind(evidence.seq)
        .bind(evidence.entry_id)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    }
    for (status, dids) in [("active", &evidence.active), ("removed", &evidence.removed)] {
        if dids.is_empty() {
            continue;
        }
        sqlx::query(
            "UPDATE chat.remote_group_memberships \
                SET status = $4, evidence_seq = $5, evidence_entry_id = $6, updated_at = $7 \
              WHERE conversation_id = $1 AND user_did = ANY($2) AND sequencer_did = $3 \
                AND evidence_seq < $5",
        )
        .bind(conversation_id)
        .bind(dids)
        .bind(sequencer_did)
        .bind(status)
        .bind(evidence.seq)
        .bind(evidence.entry_id)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    }
    if !evidence.removed.is_empty() {
        sqlx::query(
            "DELETE FROM chat.remote_group_pending_welcomes \
              WHERE conversation_id = $1 AND user_did = ANY($2)",
        )
        .bind(conversation_id)
        .bind(&evidence.removed)
        .execute(&mut **tx)
        .await?;
    }
    for (did, device, welcome) in &evidence.welcomes {
        sqlx::query(
            "INSERT INTO chat.remote_group_pending_welcomes \
                 (conversation_id, user_did, device_id, welcome_id, evidence_seq, created_at) \
             SELECT $1, $2, $3, $4, $5, $6 \
              WHERE EXISTS(SELECT 1 FROM chat.remote_group_memberships m \
                     WHERE m.conversation_id = $1 AND m.user_did = $2 AND m.sequencer_did = $7 \
                       AND m.status IN ('pending', 'active')) \
                AND EXISTS(SELECT 1 FROM chat.devices d \
                     WHERE d.user_did = $2 AND d.device_id = $3 \
                       AND d.status = 'active' AND d.revoked_at IS NULL) \
             ON CONFLICT DO NOTHING",
        )
        .bind(conversation_id)
        .bind(did)
        .bind(device)
        .bind(welcome)
        .bind(evidence.seq)
        .bind(now)
        .bind(sequencer_did)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Which inventory read a final page belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteInventory {
    Conversations,
    Welcomes,
}

/// Append, to a final inventory page, the sequencer-relayed items of the
/// device's index-only remote groups (`getConversations`) or of the pending
/// Welcomes a verified fulfilment addressed to it (`getPendingWelcomes`).
/// Relays run after the inventory transaction; an unreachable sequencer only
/// omits its items from this read.
pub(crate) async fn append_relayed_inventory_items(
    pool: &DbPool,
    user_did: &str,
    device_id: Uuid,
    inventory: RemoteInventory,
    response: Vec<u8>,
) -> Vec<u8> {
    let Ok(mut page) = serde_json::from_slice::<Value>(&response) else {
        return response;
    };
    if page.get("hasMore") != Some(&Value::Bool(false)) {
        return response;
    }
    let appended = match inventory {
        RemoteInventory::Conversations => {
            relayed_conversations(pool, user_did, device_id, &page).await
        }
        RemoteInventory::Welcomes => relayed_welcomes(pool, user_did, device_id, &page).await,
    };
    let Some(items) = page.get_mut("items").and_then(Value::as_array_mut) else {
        return response;
    };
    let room = MAX_INVENTORY_ITEMS.saturating_sub(items.len());
    if appended.len() > room {
        tracing::warn!(
            omitted = appended.len() - room,
            "final inventory page is full; relayed remote-group items omitted"
        );
    }
    if appended.is_empty() || room == 0 {
        return response;
    }
    items.extend(appended.into_iter().take(room));
    serde_json::to_vec(&page).unwrap_or(response)
}

async fn relayed_conversations(
    pool: &DbPool,
    user_did: &str,
    device_id: Uuid,
    page: &Value,
) -> Vec<Value> {
    let listed: Vec<&str> = page["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.pointer("/state/coordinates/conversationId")?.as_str())
        .collect();
    let groups: Vec<Uuid> = match sqlx::query_scalar(
        "SELECT m.conversation_id FROM chat.remote_group_memberships m \
           JOIN chat.conversations c \
             ON c.conversation_id = m.conversation_id AND c.kind = 'group' AND c.is_remote \
            AND c.sequencer_ds = m.sequencer_did \
          WHERE m.user_did = $1 AND m.status IN ('pending', 'active') \
            AND NOT EXISTS(SELECT 1 FROM chat.participants p \
                 WHERE p.conversation_id = m.conversation_id AND p.user_did = m.user_did \
                   AND p.current_membership) \
          ORDER BY m.conversation_id",
    )
    .bind(user_did)
    .fetch_all(pool)
    .await
    {
        Ok(groups) => groups,
        Err(error) => {
            tracing::warn!(%error, "remote group index read failed");
            return Vec::new();
        }
    };
    let mut items = Vec::new();
    for conversation_id in groups {
        if listed.contains(&conversation_id.to_string().as_str()) {
            continue;
        }
        match membership::try_relay_group_state(pool, user_did, device_id, conversation_id).await {
            Ok(Some(bytes)) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(mut body) if body.get("state").is_some() => items.push(json!({
                    "$type": CONVERSATION_INVENTORY_STATE,
                    "state": body["state"].take(),
                })),
                _ => {
                    tracing::warn!(conversation_id = %crate::crypto::redact_for_log(&conversation_id.to_string()), "relayed group state is malformed")
                }
            },
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(conversation_id = %crate::crypto::redact_for_log(&conversation_id.to_string()), ?error, "relayed group state unavailable")
            }
        }
    }
    items
}

async fn relayed_welcomes(
    pool: &DbPool,
    user_did: &str,
    device_id: Uuid,
    page: &Value,
) -> Vec<Value> {
    let listed: Vec<String> = page["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("welcomeId")?.as_str().map(str::to_owned))
        .collect();
    let markers: Vec<(Uuid, Vec<Uuid>)> = match sqlx::query_as(
        "SELECT w.conversation_id, array_agg(w.welcome_id ORDER BY w.welcome_id) \
           FROM chat.remote_group_pending_welcomes w \
           JOIN chat.remote_group_memberships m \
             ON m.conversation_id = w.conversation_id AND m.user_did = w.user_did \
            AND m.status IN ('pending', 'active') \
          WHERE w.user_did = $1 AND w.device_id = $2 \
          GROUP BY w.conversation_id ORDER BY w.conversation_id",
    )
    .bind(user_did)
    .bind(device_id)
    .fetch_all(pool)
    .await
    {
        Ok(markers) => markers,
        Err(error) => {
            tracing::warn!(%error, "remote group Welcome index read failed");
            return Vec::new();
        }
    };
    let mut items = Vec::new();
    for (conversation_id, welcomes) in markers {
        let views = match membership::try_relay_group_pending_welcomes(
            pool,
            user_did,
            device_id,
            conversation_id,
        )
        .await
        {
            Ok(Some(views)) => views,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(conversation_id = %crate::crypto::redact_for_log(&conversation_id.to_string()), ?error, "relayed pending Welcomes unavailable");
                continue;
            }
        };
        let pending: Vec<Uuid> = views
            .iter()
            .filter_map(|view| view.get("welcomeId")?.as_str()?.parse().ok())
            .collect();
        // The sequencer no longer holds the rest pending: acknowledged,
        // rejected, superseded or expired.
        let settled: Vec<Uuid> = welcomes
            .into_iter()
            .filter(|welcome| !pending.contains(welcome))
            .collect();
        if !settled.is_empty() {
            if let Err(error) =
                forget_pending_welcomes(pool, conversation_id, user_did, device_id, &settled).await
            {
                tracing::warn!(conversation_id = %crate::crypto::redact_for_log(&conversation_id.to_string()), %error, "settled Welcome markers were not cleared");
            }
        }
        for view in views {
            let new = view
                .get("welcomeId")
                .and_then(Value::as_str)
                .is_some_and(|id| !listed.iter().any(|listed| listed == id));
            if new {
                items.push(view);
            }
        }
    }
    items
}

/// Drop Welcome markers the sequencer settled or the device answered.
pub(crate) async fn forget_pending_welcomes(
    pool: &DbPool,
    conversation_id: Uuid,
    user_did: &str,
    device_id: Uuid,
    welcomes: &[Uuid],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM chat.remote_group_pending_welcomes \
          WHERE conversation_id = $1 AND user_did = $2 AND device_id = $3 \
            AND welcome_id = ANY($4)",
    )
    .bind(conversation_id)
    .bind(user_did)
    .bind(device_id)
    .bind(welcomes)
    .execute(pool)
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITEE: &str = "did:plc:inviteeaaaaaaaaaaaaaaaaa";
    #[test]
    fn sequencer_receipt_is_not_part_of_the_actor_signed_projection() {
        let entry = json!({
            "$type": "blue.catbird.chat.defs#commitEntry",
            "entryId": Uuid::new_v4(),
            "signedRequest": {"body": {"actorDid": MEMBER}},
            "sequencerReceipt": {"seq": 3, "signature": {"$bytes": "AA=="}},
        });
        let projected =
            actor_signed_control_entry_bytes(&serde_json::to_vec(&entry).unwrap()).unwrap();
        let projected: serde_json::Value = serde_json::from_slice(&projected).unwrap();
        assert!(projected.get("sequencerReceipt").is_none());
        assert_eq!(projected["signedRequest"], entry["signedRequest"]);
    }

    const MEMBER: &str = "did:plc:memberaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn every_membership_body_claims_exactly_its_accounts() {
        let entry = Uuid::new_v4();
        let creation = claimed_evidence(
            &json!({
                "$type": CREATION_BODY,
                "actorDid": MEMBER,
                "manifest": {"participants": [
                    {"userDid": MEMBER, "role": "admin", "status": "active"},
                    {"userDid": INVITEE, "role": "member", "status": "pending"},
                ]},
            }),
            1,
            entry,
        );
        assert_eq!(creation.invited, [INVITEE]);
        assert!(creation.active.is_empty() && creation.removed.is_empty());

        let acceptance = claimed_evidence(
            &json!({"$type": ACCEPTANCE_BODY, "actorDid": INVITEE}),
            2,
            entry,
        );
        assert_eq!(acceptance.active, [INVITEE]);
        assert!(acceptance.invited.is_empty() && acceptance.welcomes.is_empty());

        let device = Uuid::new_v4();
        let welcome = Uuid::new_v4();
        let fulfilment = claimed_evidence(
            &json!({
                "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
                "actorDid": MEMBER,
                "manifest": {
                    "participantChanges": [],
                    "leafChanges": [],
                    "welcomeBundle": {
                        "welcomeId": welcome,
                        "deliveries": [{"recipientDid": INVITEE, "recipientDeviceId": device}],
                    },
                },
            }),
            3,
            entry,
        );
        assert_eq!(fulfilment.welcomes, [(INVITEE.to_owned(), device, welcome)]);
        assert!(fulfilment.invited.is_empty() && fulfilment.active.is_empty());

        let policy = claimed_evidence(
            &json!({
                "$type": "blue.catbird.chat.defs#policyTransitionBody",
                "participantChanges": [
                    {"$type": ADD_PARTICIPANT, "userDid": INVITEE},
                    {"$type": REMOVE_PARTICIPANT, "userDid": MEMBER},
                    {"$type": "blue.catbird.chat.defs#changeParticipantRole", "userDid": MEMBER},
                ],
            }),
            4,
            entry,
        );
        assert_eq!(
            (policy.invited, policy.removed),
            (vec![INVITEE.to_owned()], vec![MEMBER.to_owned()])
        );

        let leave = claimed_evidence(
            &json!({
                "$type": "blue.catbird.chat.defs#leaveCommitFulfillmentBody",
                "manifest": {"participantChanges": [{"$type": REMOVE_PARTICIPANT, "userDid": MEMBER}]},
            }),
            5,
            entry,
        );
        assert_eq!(leave.removed, [MEMBER]);

        for body in [
            json!({"$type": "blue.catbird.chat.defs#metadataTransitionBody"}),
            json!({"$type": "blue.catbird.chat.defs#applicationSendBody"}),
            json!({"$type": "blue.catbird.chat.defs#commitTransitionBody", "manifest": {"participantChanges": [], "leafChanges": []}}),
        ] {
            assert!(claimed_evidence(&body, 6, entry).is_empty(), "{body}");
        }
    }
}
