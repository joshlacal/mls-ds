//! `blue.catbird.mlsDS.relayAccountDeletion` (home to sequencer). A deleted
//! account's home sequences its `accountDeletedEntry` and prunes its
//! ciphertext only in the conversations it sequences; it never writes a
//! mirror's seq chain. For every group mirror or C33 transport-only
//! conversation the account takes or took part in, it instead queues, in the
//! deletion's transaction, one relay of the deletion signed with its
//! `#atproto` service key, retried until delivered. The sequencer accepts only
//! a relay its authenticated caller signed for a participant homed there, and
//! applies it exactly as a local deletion: `accountDeletedEntry` once, fanned
//! out to every home in seq order, and the account's held application
//! ciphertext pruned with signed entries-pruned notices.

use super::*;
use chrono::SecondsFormat;

use crate::federation::receipt::AccountDeletionEvidence;
use crate::federation::resolver::{build_resolver_http_client, DsResolver};
use crate::labyrinth::repo::retention;

pub(crate) const RELAY_ACCOUNT_DELETION_NSID: &str = "blue.catbird.mlsDS.relayAccountDeletion";
const SIGNING_DOMAIN: &[u8] = b"CATBIRD-MLSDS-ACCOUNT-DELETION-RELAY-V1\0";
/// Room for a relay carrying the largest `actorWrite`, `keyProof`, and `revocationProof`.
const RELAY_ACCOUNT_DELETION_BODY_LIMIT_BYTES: usize = 98_304;

/// One account deletion, signed by the account's home for one conversation's
/// sequencer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AccountDeletionRelay {
    pub(crate) home_did: String,
    pub(crate) sequencer_did: String,
    pub(crate) conversation_id: Uuid,
    pub(crate) deleted_did: String,
    /// The home's deletion instant, RFC 3339 UTC with milliseconds.
    pub(crate) deleted_at: String,
    /// The deleting device's signed write and repository proof, exactly as the
    /// home verified them; the sequencer stores them in the entry it sequences.
    /// Absent from relays queued before entries carried them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) evidence: Option<AccountDeletionEvidence>,
    /// Base64 low-S ES256 `r || s` over [`AccountDeletionRelay::signing_bytes`].
    pub(crate) signature: String,
}

impl AccountDeletionRelay {
    /// Domain-separated, length-prefixed bytes binding every relayed field.
    pub(crate) fn signing_bytes(&self) -> Vec<u8> {
        self.encode_signing_bytes(true)
    }

    pub(crate) fn encode_signing_bytes(&self, tagged: bool) -> Vec<u8> {
        let mut bytes = SIGNING_DOMAIN.to_vec();
        for field in [
            &self.home_did,
            &self.sequencer_did,
            &self.deleted_did,
            &self.deleted_at,
        ] {
            push_field(&mut bytes, field);
        }
        bytes.extend_from_slice(self.conversation_id.as_bytes());
        // Appended only when present, so a relay without evidence signs exactly
        // the bytes it always did; a zero length marks an absent `keyProof`.
        // `revocationProof` appends only when present to keep existing test
        // transcripts byte-identical.
        if let Some(evidence) = &self.evidence {
            for field in [
                evidence.actor_write.write_body.as_slice(),
                &evidence.actor_write.signature,
                evidence.key_proof.as_deref().unwrap_or_default(),
            ] {
                bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
                bytes.extend_from_slice(field);
            }
            for field in [
                &evidence.revocation_proof,
                &evidence.actor_write.payload_bytes,
            ] {
                if tagged {
                    bytes.push(u8::from(field.is_some()));
                }
                if let Some(field) = field {
                    bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
                    bytes.extend_from_slice(field);
                }
            }
        }
        bytes
    }
}

fn canonical_instant(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Queue, in the deletion's transaction, `deleted_did`'s signed relay to the
/// sequencer of every group mirror or C33 transport-only conversation it takes
/// or took part in, including remote groups only this home's membership index
/// records. Each id is deterministic, so a replay adds nothing. With no such
/// conversation no signer is needed. The account's index rows end here.
pub(crate) async fn enqueue_account_deletion_relays(
    tx: &mut Transaction<'_, Postgres>,
    deleted_did: &str,
    deleted_at: DateTime<Utc>,
    evidence: Option<&AccountDeletionEvidence>,
) -> Result<(), SignedRelayError> {
    let home_did = crate::identity::service_did_base();
    let indexed: bool =
        sqlx::query_scalar("SELECT to_regclass('chat.remote_group_memberships') IS NOT NULL")
            .fetch_one(&mut **tx)
            .await?;
    let index_arm = if indexed {
        " UNION \
         SELECT m.conversation_id, m.sequencer_did FROM chat.remote_group_memberships m \
          WHERE m.user_did = $1"
    } else {
        ""
    };
    let sequenced_elsewhere: Vec<(Uuid, String)> = sqlx::query_as(&format!(
        "SELECT c.conversation_id, c.sequencer_ds FROM chat.participants p \
           JOIN chat.conversations c ON c.conversation_id = p.conversation_id \
          WHERE p.user_did = $1 AND c.is_remote AND c.sequencer_ds IS NOT NULL \
         UNION \
         SELECT i.conversation_id, i.coordinator_did FROM chat.direct_request_transport_inbox i \
          WHERE $1 IN (i.sender_did, i.recipient_did) \
            AND NOT EXISTS(SELECT 1 FROM chat.conversations c \
                            WHERE c.conversation_id = i.conversation_id){index_arm} \
         ORDER BY 1, 2"
    ))
    .bind(deleted_did)
    .fetch_all(&mut **tx)
    .await?;
    if indexed {
        sqlx::query("DELETE FROM chat.remote_group_memberships WHERE user_did = $1")
            .bind(deleted_did)
            .execute(&mut **tx)
            .await?;
    }
    let sequenced_elsewhere: Vec<(Uuid, String)> = sequenced_elsewhere
        .into_iter()
        .filter(|(_, sequencer)| !crate::identity::dids_equivalent(sequencer, &home_did))
        .collect();
    if sequenced_elsewhere.is_empty() {
        return Ok(());
    }
    let key = service_signing_key()?;
    let deleted_at_text = canonical_instant(deleted_at);
    let operation_key = match evidence {
        Some(evidence) => hex::encode(evidence.operation_id().map_err(SignedRelayError::Storage)?),
        None => deleted_at_text.clone(),
    };
    for (conversation_id, sequencer) in sequenced_elsewhere {
        let mut relay = AccountDeletionRelay {
            home_did: home_did.clone(),
            sequencer_did: crate::identity::canonical_did(&sequencer).to_owned(),
            conversation_id,
            deleted_did: deleted_did.to_owned(),
            deleted_at: deleted_at_text.clone(),
            evidence: evidence.cloned(),
            signature: String::new(),
        };
        relay.signature = sign(&key, &relay.signing_bytes());
        let payload = serde_json::to_vec(&relay)
            .map_err(|error| SignedRelayError::Storage(error.to_string()))?;
        queue_signed(
            tx,
            &format!("account-deletion-{conversation_id}-{deleted_did}-{operation_key}"),
            &relay.sequencer_did,
            RELAY_ACCOUNT_DELETION_NSID,
            &payload,
            conversation_id,
            deleted_at,
        )
        .await?;
    }
    Ok(())
}

pub(super) fn routes() -> Router<GroupRelayState> {
    Router::new().route(
        "/xrpc/blue.catbird.mlsDS.relayAccountDeletion",
        post(ClockScoped(relay_account_deletion)).layer(DefaultBodyLimit::max(
            RELAY_ACCOUNT_DELETION_BODY_LIMIT_BYTES,
        )),
    )
}

async fn relay_account_deletion(
    State(state): State<GroupRelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match verify_s2s_caller(&state, &headers, RELAY_ACCOUNT_DELETION_NSID, &body).await {
        Ok(caller) => respond(accept_account_deletion_relay(&state, &caller, &body).await),
        Err(response) => response,
    }
}

/// Resolve the user's own repository key before any SQL mutation. A home or sequencer
/// attestation cannot substitute for device authority on a destructive operation.
pub(super) async fn verify_user_deletion(
    resolver: &DsResolver,
    did: &str,
    evidence: Option<&AccountDeletionEvidence>,
) -> Result<chrono::DateTime<chrono::Utc>, Response> {
    let evidence = evidence.ok_or_else(|| denied("account deletion requires device evidence"))?;
    if evidence.key_proof.is_none() || evidence.revocation_proof.is_none() {
        return Err(denied("account deletion requires both repository proofs"));
    }
    let key = resolver
        .resolve_did_to_atproto_key(did)
        .await
        .map_err(|error| {
            if error.is_retryable() {
                unavailable(error)
            } else {
                denied("cannot resolve the deleting account's repository key")
            }
        })?
        .ok_or_else(|| denied("missing account repository key"))?;
    crate::federation::space_read_relay::verify_account_deletion_evidence(did, evidence, &key)
        .map_err(|_| denied("device deletion authority did not verify"))
}

/// Record the first scope an authorized operation acquired. Duplicate delivery is an
/// acknowledgement, including when a former participant no longer needs a sequence entry.
pub(super) async fn claim_deletion_operation(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    did: &str,
    evidence: &AccountDeletionEvidence,
    cutoff: DateTime<Utc>,
    before_seq: i64,
) -> Result<bool, Response> {
    let operation = evidence.operation_id().map_err(|err| invalid(&err))?;
    let result = sqlx::query(
        "INSERT INTO chat.account_deletion_operations
            (conversation_id, deleted_did, operation_id, cutoff, before_seq)
         VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
    )
    .bind(conversation_id)
    .bind(did)
    .bind(operation.as_slice())
    .bind(cutoff)
    .bind(before_seq)
    .execute(&mut **tx)
    .await
    .map_err(storage)?;
    Ok(result.rows_affected() == 1)
}

/// Apply a relayed account deletion from an authenticated `caller` at this
/// sequencer exactly as a local deletion, once per deletion.
pub(crate) async fn accept_account_deletion_relay(
    state: &GroupRelayState,
    caller: &str,
    body: &[u8],
) -> Result<Value, Response> {
    let mut relay: AccountDeletionRelay =
        serde_json::from_slice(body).map_err(|error| invalid(&error.to_string()))?;
    let deleted_at = DateTime::parse_from_rfc3339(&relay.deleted_at)
        .ok()
        .map(|at| at.with_timezone(&Utc))
        .filter(|at| canonical_instant(*at) == relay.deleted_at);
    let Some(deleted_at) = deleted_at.filter(|_| {
        relay.conversation_id.get_version_num() == 4
            && crate::chat_protocol::validation::BareDid::parse(&relay.deleted_did).is_ok()
    }) else {
        return Err(invalid("invalid account deletion relay"));
    };
    // Reject malformed evidence before resolving the home and device authorities.
    if let Some(evidence) = &relay.evidence {
        if evidence.actor_write.payload_bytes.is_none() {
            return Err(invalid("actorWrite.payloadBytes is required"));
        }
        let signed_at = evidence
            .check_shape()
            .and_then(|()| evidence.signed_at())
            .map_err(|error| invalid(&error))?;
        if (signed_at - deleted_at).num_seconds().abs() > crate::labyrinth::auth::WRITE_SKEW_SECONDS
        {
            return Err(invalid(
                "actorWrite was not signed within the deletion's write window",
            ));
        }
    }
    if relay.home_did != caller || relay.sequencer_did != state.self_did {
        return Err(denied("relay is not bound to this caller and sequencer"));
    }
    if let Err(err) =
        verify_service_signature(&relay.home_did, &relay.signing_bytes(), &relay.signature).await
    {
        // Honor a queued pre-tag envelope only after checking the original service
        // signature. Every destructive field is independently authenticated below.
        if err.status() != StatusCode::FORBIDDEN || relay.evidence.is_none() {
            return Err(err);
        }
        verify_service_signature(
            &relay.home_did,
            &relay.encode_signing_bytes(false),
            &relay.signature,
        )
        .await?;
    }

    if participant_home(state, relay.conversation_id, &relay.deleted_did).await? != caller {
        return Err(denied("caller is not the participant's home"));
    }

    let resolver = DsResolver::new(
        state.pool.clone(),
        build_resolver_http_client(),
        state.self_did.clone(),
        crate::identity::self_endpoint(),
        None,
        300,
    );
    let evidence = relay
        .evidence
        .as_mut()
        .ok_or_else(|| denied("account deletion requires device evidence"))?;
    if evidence.revocation_proof.is_none() {
        // A pre-Track-A outbox could carry a device write and key CAR but no revocation CAR.
        // Recover its missing authority from the account's PDS; unresolved legacy entries remain unpruned.
        let key_car = evidence
            .key_proof
            .as_deref()
            .ok_or_else(|| denied("missing deleting device key proof"))?;
        let write: crate::labyrinth::auth::WriteBodyWire =
            serde_json::from_slice(&evidence.actor_write.write_body)
                .map_err(|_| denied("malformed deleting device write"))?;
        let repository_key = resolver
            .resolve_did_to_atproto_key(&relay.deleted_did)
            .await
            .map_err(|error| {
                if error.is_retryable() {
                    unavailable(error)
                } else {
                    denied("cannot resolve account repository key")
                }
            })?
            .ok_or_else(|| denied("missing account repository key"))?;
        let (device_key, _) = crate::federation::space_read_relay::chat_device_key_and_creation(
            key_car,
            &relay.deleted_did,
            &write.actor_device_id,
            &repository_key,
        )
        .map_err(|_| denied("invalid deleting device proof"))?;
        evidence.revocation_proof = Some(
            crate::federation::space_read_relay::fetch_chat_device_revocation_proof(
                &resolver,
                &relay.deleted_did,
                &write.actor_device_id,
                &device_key,
                &evidence.operation_id().map_err(|e| invalid(&e))?,
                evidence.signed_at().map_err(|e| invalid(&e))?,
            )
            .await
            .map_err(|error| match error {
                crate::federation::space_read_relay::SpaceRelayError::DeviceRevoked(_) => {
                    denied("device revocation rejected deletion")
                }
                _ => unavailable(error),
            })?,
        );
    }
    let signed_at = verify_user_deletion(&resolver, &relay.deleted_did, Some(evidence)).await?;
    let cutoff = deleted_at
        .min(signed_at + chrono::Duration::seconds(crate::labyrinth::auth::WRITE_SKEW_SECONDS));
    let now = crate::sim_hooks::current_utc();
    let mut tx = state.pool.begin().await.map_err(storage)?;
    let before_seq: Option<i64> = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id = $1 AND NOT is_remote FOR UPDATE",
    )
    .bind(relay.conversation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?;
    let before_seq = before_seq.ok_or_else(|| missing("conversation is not sequenced here"))?;
    if !claim_deletion_operation(
        &mut tx,
        relay.conversation_id,
        &relay.deleted_did,
        evidence,
        cutoff,
        before_seq,
    )
    .await?
    {
        return Ok(json!({"accepted": true, "sequenced": false, "prunedCount": 0}));
    }
    // A deletion this sequencer cannot sign answers 503, so the home's relay retries.
    let sequenced = retention::sequence_account_deleted_entry(
        &mut tx,
        relay.conversation_id,
        &relay.deleted_did,
        deleted_at,
        now,
        state.i13_receipt_signer.as_deref(),
        relay.evidence.as_ref(),
    )
    .await
    .map_err(|error| s2s_err(error.status(), error.name(), error.message()))?
    .is_some();
    let pruned = retention::prune_account_ciphertext_before(
        &mut tx,
        relay.conversation_id,
        &relay.deleted_did,
        before_seq,
        cutoff,
        now,
    )
    .await
    .map_err(signed_relay_failure)?;
    tx.commit().await.map_err(storage)?;
    Ok(json!({
        "accepted": true,
        "sequenced": sequenced,
        "prunedCount": pruned,
    }))
}
