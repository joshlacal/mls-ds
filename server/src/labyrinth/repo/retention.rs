//! Retention for the clean-slate `labyrinth` directory (`purgeMailbox`, `deleteAccountData`,
//! and 7-day idempotency GC on `labyrinth.operations`).

use axum::http::StatusCode;
use chrono::{DateTime, Duration, SecondsFormat, SubsecRound as _, Utc};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sqlx::{Connection as _, PgConnection, Postgres, Transaction};
use uuid::Uuid;

use crate::chat_protocol::repository::{delivery, entry_read::AccountDeletedServerFields};
use crate::federation::group_relay::{
    enqueue_entries_pruned_notices, enqueue_transport_control_entry, C33PeerHomes, SignedRelayError,
};
use crate::federation::receipt::{AccountDeletion, AccountDeletionEvidence, I13ReceiptSigner};
use crate::federation::FederationError;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::recovery_tombstones::RecoveryTombstones;
use crate::labyrinth::repo::recovery_shares;
use crate::storage::DbPool;

/// Idempotency records in `labyrinth.operations` are kept for 7 days.
pub const OPERATION_RETENTION_DAYS: i64 = 7;

const ACCOUNT_DELETED_ENTRY_KIND: &str = "blue.catbird.chat.defs#accountDeletedEntry";

/// `purgeMailbox`: raise `labyrinth.epoch_head_floors` to `MAX(epoch_number)` and delete
/// `labyrinth.epoch_heads` for `did` so any reset must restart strictly at `floor + 1` (`L-F01`).
pub async fn purge_mailbox(conn: &mut PgConnection, did: &str) -> LabyrinthResult<()> {
    super::advisory_lock(conn, &format!("labyrinth.epoch_heads:{did}")).await?;
    sqlx::query("SELECT labyrinth.purge_mailbox($1)")
        .bind(did)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// `deleteAccountData`: sequence `blue.catbird.chat.defs#accountDeletedEntry`, signed by
/// `receipt_signer`, across every active conversation this DS sequences where `did`
/// currently holds active membership, queueing each C33 pair's entry to the peer's
/// transport-only home `c33_peers` names, and queue the deletion's signed relay to the
/// sequencer of every group mirror or C33 transport-only conversation `did` takes or took
/// part in, which applies it there; a mirror is never written here. Prune the ciphertext
/// of every application message `did` sent through a conversation this DS sequences, and
/// of every direct-request opening `did` sent that this DS holds as the pair's coordinator
/// or transport-only home, and erase the payload of every `sendMessage` receipt `did`
/// completed here, purge
/// push gateway bindings for `did`, and purge the account's epoch-head directory chain
/// while retaining 7-day `labyrinth.operations` idempotency records. A DS that cannot sign
/// an owed entry or relay refuses the whole deletion (`SignerUnavailable`), as does a C33
/// pair `c33_peers` did not resolve (`PeerHomeUnavailable`).
pub async fn purge_account(
    conn: &mut PgConnection,
    did: &str,
    at: DateTime<Utc>,
    receipt_signer: Option<&I13ReceiptSigner>,
    c33_peers: &C33PeerHomes,
    evidence: Option<&AccountDeletionEvidence>,
) -> LabyrinthResult<usize> {
    purge_account_with_recovery(conn, did, at, receipt_signer, c33_peers, evidence, None).await
}

/// Account deletion with the external erasure journal. The journal syncs each
/// share tombstone before SQL clears its KEK ciphertext. A caller without the
/// journal cannot delete an account that has live shares.
pub async fn purge_account_with_recovery(
    conn: &mut PgConnection,
    did: &str,
    at: DateTime<Utc>,
    receipt_signer: Option<&I13ReceiptSigner>,
    c33_peers: &C33PeerHomes,
    evidence: Option<&AccountDeletionEvidence>,
    recovery_journal: Option<&RecoveryTombstones>,
) -> LabyrinthResult<usize> {
    if recovery_journal.is_none() {
        let live: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM labyrinth.recovery_shares \
             WHERE owner_did=$1 AND deleted_at IS NULL)",
        )
        .bind(did)
        .fetch_one(&mut *conn)
        .await?;
        if live {
            return Err(LabyrinthError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                "recovery-share tombstone journal is required for account deletion",
            ));
        }
    }
    let mut tx = conn.begin().await?;
    let sequenced =
        sequence_account_deleted_entries(&mut tx, did, at, receipt_signer, c33_peers, evidence)
            .await?;
    crate::federation::group_relay::enqueue_account_deletion_relays(&mut tx, did, at, evidence)
        .await
        .map_err(relay_failure)?;
    tx.commit().await?;
    prune_application_ciphertext(conn, did, at).await?;
    // Where this DS holds `did`'s C33 pairs only as a transport-only home, the
    // pair's coordinator never relays this deletion back: prune `did`'s openings
    // (O7) and its application copies there here. Every `sendMessage` receipt
    // `did` completed here loses its ciphertext too, wherever its entry is.
    let mut tx = conn.begin().await?;
    crate::chat_protocol::repository::direct_request_opening::prune_held_transport_openings_sent_by(
        &mut tx, did, at,
    )
    .await?;
    delivery::prune_held_transport_applications_sent_by(&mut tx, did, at)
        .await
        .map_err(|error| {
            tracing::error!(?error, "prune held transport application payloads");
            LabyrinthError::internal()
        })?;
    delivery::erase_idempotency_payloads(&mut tx, delivery::ReceiptErasure::Principal(did), at)
        .await?;
    tx.commit().await?;
    sqlx::query("DELETE FROM chat.push_gateway_bindings WHERE user_did = $1")
        .bind(did)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM chat.conversation_space_records WHERE writer_did = $1")
        .bind(did)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM chat.managed_space_members WHERE member_did = $1")
        .bind(did)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM chat.conversation_space_writers WHERE writer_did = $1")
        .bind(did)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "UPDATE chat.space_credential_jtis \
            SET revoked_at = COALESCE(revoked_at, $2) \
          WHERE writer_did = $1",
    )
    .bind(did)
    .bind(at)
    .execute(&mut *conn)
    .await?;
    if let Some(journal) = recovery_journal {
        recovery_shares::purge(conn, did, at, journal).await?;
    }
    purge_mailbox(conn, did).await?;
    Ok(sequenced)
}

/// Pool-level helper that resolves `did`'s C33 peer homes, then atomically sequences
/// `accountDeletedEntry` across active conversations, queues the relays for
/// remote-sequenced ones and the C33 peers' entries, prunes the account's application
/// ciphertext, deletes `push_gateway_bindings`, and purges the Labyrinth epoch-head chain.
pub async fn delete_account_data_with_conversations(
    pool: &DbPool,
    did: &str,
    at: DateTime<Utc>,
    receipt_signer: Option<&I13ReceiptSigner>,
) -> LabyrinthResult<usize> {
    delete_account_data_with_evidence(pool, did, at, receipt_signer, None).await
}

/// [`delete_account_data_with_conversations`] for a deletion its device signed:
/// every `accountDeletedEntry` sequenced here, and every relay queued for one
/// sequenced elsewhere, carries `evidence` exactly.
pub async fn delete_account_data_with_evidence(
    pool: &DbPool,
    did: &str,
    at: DateTime<Utc>,
    receipt_signer: Option<&I13ReceiptSigner>,
    evidence: Option<&AccountDeletionEvidence>,
) -> LabyrinthResult<usize> {
    let c33_peers = resolve_c33_peer_homes(pool, did).await?;
    let mut tx = pool.begin().await?;
    let sequenced = purge_account(&mut tx, did, at, receipt_signer, &c33_peers, evidence).await?;
    tx.commit().await?;
    Ok(sequenced)
}

/// Resolve, before the deletion's transaction (M-F04), the transport-only home each C33
/// pair `did` takes part in here is owed its entry. A peer home that does not resolve
/// holds the deletion back: retried, it reaches that home; while its source could not
/// answer now the refusal carries a retry hint. This DS's own store failing decided
/// nothing about any peer: a storage failure.
pub async fn resolve_c33_peer_homes(pool: &DbPool, did: &str) -> LabyrinthResult<C33PeerHomes> {
    C33PeerHomes::resolve(pool, did)
        .await
        .map_err(|error| match error {
            // Matched first: `FederationError::is_retryable` holds for `Database`.
            FederationError::Database(error) => LabyrinthError::from(error),
            FederationError::Storage(error) => {
                tracing::error!(%error, "deleteAccountData: C33 peer home lookup failed in storage");
                LabyrinthError::internal()
            }
            error if error.is_retryable() => {
                tracing::warn!(%error, "deleteAccountData refused: a C33 peer's home cannot answer now");
                peer_home_unavailable().with_retry_after(5)
            }
            error => {
                tracing::warn!(%error, "deleteAccountData refused: a C33 peer's home did not resolve");
                peer_home_unavailable()
            }
        })
}

fn peer_home_unavailable() -> LabyrinthError {
    LabyrinthError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "PeerHomeUnavailable",
        "the home of a direct conversation's peer could not be resolved; retry the deletion",
    )
}

/// An `accountDeletedEntry` is signed evidence: one this DS owes but cannot sign refuses
/// the deletion before anything is written.
fn receipt_signer_unavailable() -> LabyrinthError {
    tracing::error!("accountDeletedEntry refused: no #mls-receipt-1 signer");
    LabyrinthError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "SignerUnavailable",
        "this DS cannot sign the accountDeletedEntry a conversation it sequences requires",
    )
}

/// A relay the deletion owes but this DS cannot sign refuses it, so nothing commits.
fn relay_failure(error: SignedRelayError) -> LabyrinthError {
    match error {
        SignedRelayError::SignerUnavailable => {
            tracing::error!(
                "deleteAccountData refused: no S2S signing key for its account-deletion relay"
            );
            LabyrinthError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "SignerUnavailable",
                "this DS cannot sign the account-deletion relay a remote conversation requires",
            )
        }
        SignedRelayError::Storage(error) => {
            tracing::error!(%error, "queue account-deletion relays");
            LabyrinthError::internal()
        }
    }
}

/// Prune `did`'s application ciphertext in every conversation this DS sequences, including
/// ones it left, so a member that has not fetched one of its messages can never decrypt,
/// show or witness-archive it. Each conversation commits under its own savepoint; one whose
/// entries-pruned notice this DS cannot sign keeps its ciphertext, as in the 30-day sweep.
async fn prune_application_ciphertext(
    conn: &mut PgConnection,
    did: &str,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    let held: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT e.conversation_id \
           FROM chat.entries e \
           JOIN chat.conversations c ON c.conversation_id = e.conversation_id \
          WHERE e.conversation_id IN \
                (SELECT conversation_id FROM chat.participants WHERE user_did = $1) \
            AND NOT c.is_remote \
            AND e.actor_did = $1 \
            AND e.entry_kind IN ($2, 'blue.catbird.chat.defs#directRequestEntry') \
            AND e.payload_pruned_at IS NULL \
          ORDER BY e.conversation_id",
    )
    .bind(did)
    .bind(delivery::APPLICATION_ENTRY_KIND)
    .fetch_all(&mut *conn)
    .await?;
    for conversation_id in held {
        let mut savepoint = conn.begin().await?;
        match prune_account_ciphertext(&mut savepoint, conversation_id, did, at).await {
            Ok(_) => savepoint.commit().await?,
            Err(SignedRelayError::SignerUnavailable) => {
                tracing::error!(
                    conversation_id = %crate::crypto::redact_for_log(&conversation_id.to_string()),
                    "deleted account prune refused: no S2S signing key for its entries-pruned notice"
                );
                savepoint.rollback().await?;
            }
            Err(SignedRelayError::Storage(error)) => {
                tracing::error!(%error, conversation_id = %crate::crypto::redact_for_log(&conversation_id.to_string()), "deleted account prune failed");
                return Err(LabyrinthError::internal());
            }
        }
    }
    Ok(())
}

/// Prune `did`'s held application ciphertext in one conversation this DS sequences exactly
/// as an ACK prune does: the `seq` skeleton, digests and I13 receipt stay, and every home
/// the entries were fanned out to is queued its signed entries-pruned notice in `tx`.
/// Pruned rows are skipped, so a retry prunes and notifies nothing more. Returns how many
/// entries it pruned.
pub(crate) async fn prune_account_ciphertext(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    did: &str,
    at: DateTime<Utc>,
) -> Result<usize, SignedRelayError> {
    let held: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT e.generation, e.seq \
           FROM chat.entries e \
           JOIN chat.conversations c ON c.conversation_id = e.conversation_id \
          WHERE e.conversation_id = $1 \
            AND NOT c.is_remote \
            AND e.actor_did = $2 \
            AND e.entry_kind = $3 \
            AND e.payload_pruned_at IS NULL \
          ORDER BY e.generation, e.seq",
    )
    .bind(conversation_id)
    .bind(did)
    .bind(delivery::APPLICATION_ENTRY_KIND)
    .fetch_all(&mut **tx)
    .await?;
    let mut pruned_count = 0;
    for generation_held in held.chunk_by(|a, b| a.0 == b.0) {
        let generation = generation_held[0].0;
        let mut pruned = Vec::with_capacity(generation_held.len());
        for &(_, seq) in generation_held {
            if delivery::prune_application_entry_payload(tx, conversation_id, seq, at)
                .await
                .map_err(|error| SignedRelayError::Storage(format!("{error:?}")))?
            {
                pruned.push(seq);
            }
        }
        enqueue_entries_pruned_notices(tx, conversation_id, generation, &pruned, at).await?;
        pruned_count += pruned.len();
    }
    // `did`'s direct-request openings carry application ciphertext too (O7). Their
    // peers' transport-only homes prune theirs on the pair's control entry.
    crate::chat_protocol::repository::direct_request_opening::prune_coordinator_openings_sent_by(
        tx,
        conversation_id,
        did,
        at,
    )
    .await?;
    Ok(pruned_count)
}

async fn sequence_account_deleted_entries(
    tx: &mut Transaction<'_, Postgres>,
    did: &str,
    at: DateTime<Utc>,
    receipt_signer: Option<&I13ReceiptSigner>,
    c33_peers: &C33PeerHomes,
    evidence: Option<&AccountDeletionEvidence>,
) -> LabyrinthResult<usize> {
    // `coordinated`: a direct pair this DS coordinates, exactly as `C33PeerHomes` resolves.
    let active_convos: Vec<(Uuid, bool)> = sqlx::query_as(
        "SELECT DISTINCT p.conversation_id, c.kind = 'direct' AND NOT c.is_remote \
           FROM chat.participants p \
           JOIN chat.conversations c ON c.conversation_id = p.conversation_id \
          WHERE p.user_did = $1 \
            AND p.current_membership \
            AND p.status = 'active' \
            AND c.lifecycle = 'active' \
          ORDER BY p.conversation_id ASC",
    )
    .bind(did)
    .fetch_all(&mut **tx)
    .await?;

    let mut sequenced = 0_usize;
    for (conversation_id, coordinated) in active_convos {
        let entry = sequence_account_deleted_entry(
            tx,
            conversation_id,
            did,
            at,
            at,
            receipt_signer,
            evidence,
        )
        .await?;
        let home = if coordinated {
            // A pair `c33_peers` did not resolve (one created since) decided
            // nothing: the identical retry resolves it.
            c33_peers
                .home(conversation_id)
                .ok_or_else(|| peer_home_unavailable().with_retry_after(5))?
        } else {
            None
        };
        if let (Some(entry), Some(home)) = (&entry, home) {
            enqueue_transport_control_entry(tx, home, entry, at)
                .await
                .map_err(relay_failure)?;
        }
        sequenced += usize::from(entry.is_some());
    }
    Ok(sequenced)
}

/// Sequence `accountDeletedEntry(did)` in one active conversation this DS sequences where
/// `did` still holds active membership, with `receipt_signer`'s `sequencerAuthority`, and
/// queue its ordered delivery to every remote home in `tx`. The entry id derives from the
/// deletion instant `deleted_at`, so replaying one deletion (a duplicate relay) sequences
/// nothing more; `at` stamps the entry. Returns the exact signed entry it sequenced; one
/// it owes but cannot sign is refused (`SignerUnavailable`) before any write.
pub(crate) async fn sequence_account_deleted_entry(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    did: &str,
    deleted_at: DateTime<Utc>,
    at: DateTime<Utc>,
    receipt_signer: Option<&I13ReceiptSigner>,
    evidence: Option<&AccountDeletionEvidence>,
) -> LabyrinthResult<Option<Value>> {
    // A remote sequencer owns a mirror's seq chain: it learns of the deletion by relay.
    let head: Option<(i64, i64, i64)> = sqlx::query_as(
        "SELECT current_generation, current_state_version, next_entry_seq \
           FROM chat.conversations \
          WHERE conversation_id = $1 AND lifecycle = 'active' AND NOT is_remote \
          FOR UPDATE",
    )
    .bind(conversation_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((generation, state_version, seq)) = head else {
        return Ok(None);
    };
    let entry_id = account_deleted_entry_id(conversation_id, did, deleted_at);
    let (member, already_sequenced): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM chat.participants \
                        WHERE conversation_id = $1 AND user_did = $2 \
                          AND current_membership AND status = 'active'), \
                EXISTS(SELECT 1 FROM chat.entries WHERE entry_id = $3)",
    )
    .bind(conversation_id)
    .bind(did)
    .bind(entry_id)
    .fetch_one(&mut **tx)
    .await?;
    if !member || already_sequenced {
        return Ok(None);
    }
    let actor_leaf: Option<(Uuid, String, i64)> = sqlx::query_as(
        "SELECT md.device_id, md.leaf_key_id, md.leaf_auth_generation \
           FROM chat.member_devices md \
          WHERE md.conversation_id = $1 AND md.generation = $2 AND md.user_did = $3 \
          ORDER BY md.active DESC, md.joined_seq DESC \
          LIMIT 1",
    )
    .bind(conversation_id)
    .bind(generation)
    .bind(did)
    .fetch_optional(&mut **tx)
    .await?;
    let actor_info: Option<(Uuid, String, i64)> = match actor_leaf {
        Some(v) => Some(v),
        None => {
            sqlx::query_as(
                "SELECT k.device_id,k.key_id,d.auth_generation \
                   FROM chat.device_keys k JOIN chat.devices d USING(user_did,device_id) \
                  WHERE k.user_did=$1 AND k.enrollment_auth_generation<=d.auth_generation \
                    AND NOT EXISTS(SELECT 1 FROM chat.device_keys newer \
                        WHERE newer.user_did=k.user_did AND newer.device_id=k.device_id \
                          AND newer.enrollment_auth_generation>k.enrollment_auth_generation \
                          AND newer.enrollment_auth_generation<=d.auth_generation) \
                  ORDER BY k.revoked_at IS NULL DESC,k.created_at DESC LIMIT 1",
            )
            .bind(did)
            .fetch_optional(&mut **tx)
            .await?
        }
    };
    let Some((actor_device_id, actor_key_id, actor_auth_generation)) = actor_info else {
        return Ok(None);
    };

    // The conversation is sequenced here, so this DS's receipt key is its authority.
    let signer = receipt_signer.ok_or_else(receipt_signer_unavailable)?;
    // `receivedAt` is signed at millisecond precision; the row holds exactly that instant.
    let at = at.trunc_subsecs(3);
    let received_at = at.to_rfc3339_opts(SecondsFormat::Millis, true);
    let deletion = AccountDeletion {
        sequencer_did: signer.sequencer_did().to_owned(),
        conversation_id,
        deleted_did: did.to_owned(),
        seq,
        entry_id,
        deleted_at: at,
        evidence: evidence.cloned(),
    };
    let sequencer_authority = signer.sign_account_deletion(&deletion).map_err(|error| {
        tracing::error!(%error, conversation_id = %crate::crypto::redact_for_log(&conversation_id.to_string()), "sign accountDeletedEntry");
        LabyrinthError::internal()
    })?;
    let entry = deletion.entry(&sequencer_authority);
    let (actor_write, key_proof, revocation_proof) =
        deletion.evidence.map_or((None, None, None), |evidence| {
            (
                Some(evidence.actor_write),
                evidence.key_proof,
                evidence.revocation_proof,
            )
        });
    let server_fields_bytes = serde_ipld_dagcbor::to_vec(&AccountDeletedServerFields {
        deleted_did: deletion.deleted_did,
        sequencer_did: deletion.sequencer_did,
        sequencer_authority,
        actor_write,
        key_proof,
        revocation_proof,
    })
    .map_err(|_| LabyrinthError::internal())?;

    let accepted_payload_bytes = serde_json::to_vec(&serde_json::json!({
        "$type": ACCOUNT_DELETED_ENTRY_KIND,
        "entryId": entry_id,
        "conversationId": conversation_id,
        "seq": seq,
        "generation": generation,
        "stateVersion": state_version,
        "deletedDid": did,
        "sequencerDid": signer.sequencer_did(),
        "receivedAt": received_at,
    }))
    .map_err(|_| LabyrinthError::internal())?;
    let accepted_payload_sha256 = Sha256::digest(&accepted_payload_bytes).to_vec();
    let request_digest = accepted_payload_sha256.clone();
    let zero_signature = vec![0_u8; 64];
    let outer_entry_fingerprint = Sha256::digest(
        [
            b"CATBIRD-CHAT-ACCOUNT-DELETED-ENTRY\0".as_slice(),
            conversation_id.as_bytes().as_slice(),
            &seq.to_be_bytes(),
            &server_fields_bytes,
        ]
        .concat(),
    )
    .to_vec();

    sqlx::query(
        "UPDATE chat.conversations \
            SET next_entry_seq = $2 \
          WHERE conversation_id = $1 AND next_entry_seq = $3",
    )
    .bind(conversation_id)
    .bind(seq + 1)
    .bind(seq)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        "INSERT INTO chat.entries ( \
             conversation_id, seq, entry_id, entry_kind, \
             accepted_payload_bytes, accepted_payload_sha256, \
             signed_request_bytes, request_digest, signature, \
             server_fields_bytes, outer_entry_fingerprint, \
             actor_did, actor_device_id, actor_key_id, actor_auth_generation, \
             generation, state_version, received_at \
         ) VALUES ( \
             $1, $2, $3, 'blue.catbird.chat.defs#accountDeletedEntry', \
             $4, $5, $4, $6, $7, $8, $9, \
             $10, $11, $12, $13, \
             $14, $15, $16 \
         )",
    )
    .bind(conversation_id)
    .bind(seq)
    .bind(entry_id)
    .bind(&accepted_payload_bytes)
    .bind(&accepted_payload_sha256)
    .bind(&request_digest)
    .bind(&zero_signature)
    .bind(&server_fields_bytes)
    .bind(&outer_entry_fingerprint)
    .bind(did)
    .bind(actor_device_id)
    .bind(&actor_key_id)
    .bind(actor_auth_generation)
    .bind(generation)
    .bind(state_version)
    .bind(at)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        "INSERT INTO chat.entry_recipients (conversation_id, seq, user_did, device_id, entitlement_kind) \
         SELECT DISTINCT m.conversation_id, $2, m.user_did, m.device_id, 'control' \
           FROM chat.member_devices m \
          WHERE m.conversation_id = $1 AND m.generation = $3 AND m.active \
         ON CONFLICT DO NOTHING",
    )
    .bind(conversation_id)
    .bind(seq)
    .bind(generation)
    .execute(&mut **tx)
    .await?;

    // Every remote home gets the signed entry in seq order, exactly as `getEntries`
    // presents it.
    crate::federation::group_fanout::prepare_group_entry_fanout(tx, &entry)
        .await
        .map_err(|error| {
            tracing::error!(%error, conversation_id = %crate::crypto::redact_for_log(&conversation_id.to_string()), "queue accountDeletedEntry fan-out");
            LabyrinthError::internal()
        })?;
    Ok(Some(entry))
}

/// One deletion's entry id in one conversation, so its replay names the same entry.
fn account_deleted_entry_id(conversation_id: Uuid, did: &str, deleted_at: DateTime<Utc>) -> Uuid {
    let digest = Sha256::digest(
        [
            b"CATBIRD-CHAT-ACCOUNT-DELETED-ENTRY-ID\0".as_slice(),
            conversation_id.as_bytes().as_slice(),
            &deleted_at.timestamp_millis().to_be_bytes(),
            did.as_bytes(),
        ]
        .concat(),
    );
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}

/// Counts removed by one retention GC pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GcCounts {
    pub operations: i64,
}

/// Expire `labyrinth.operations` older than [`OPERATION_RETENTION_DAYS`], up to `batch` rows.
pub async fn run_gc(pool: &DbPool, now: DateTime<Utc>, batch: i32) -> LabyrinthResult<GcCounts> {
    let mut tx = pool.begin().await?;
    let operations: i32 = sqlx::query_scalar("SELECT labyrinth.gc_operations($1, $2)")
        .bind(now - Duration::days(OPERATION_RETENTION_DAYS))
        .bind(batch)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(GcCounts {
        operations: i64::from(operations),
    })
}

/// Run [`run_gc`] every `interval` for the life of the process.
pub async fn gc_worker(pool: DbPool, interval: std::time::Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        match run_gc(&pool, Utc::now(), 500).await {
            Ok(counts) if counts != GcCounts::default() => {
                tracing::info!(?counts, "labyrinth retention pass");
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "labyrinth retention pass failed"),
        }
    }
}
