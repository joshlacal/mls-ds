//! Retention for the clean-slate `labyrinth` directory (`purgeMailbox`, `deleteAccountData`,
//! and 7-day idempotency GC on `labyrinth.operations`).

use chrono::{DateTime, Duration, Utc};
use sqlx::PgConnection;

use crate::labyrinth::error::LabyrinthResult;
use crate::storage::DbPool;

/// Idempotency records in `labyrinth.operations` are kept for 7 days.
pub const OPERATION_RETENTION_DAYS: i64 = 7;

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

/// `deleteAccountData`: sequence `blue.catbird.chat.defs#accountDeletedEntry` across every
/// active conversation where `did` currently holds active membership, purge push gateway
/// bindings for `did`, and purge the account's epoch-head directory chain while retaining
/// 7-day `labyrinth.operations` idempotency records.
pub async fn purge_account(
    conn: &mut PgConnection,
    did: &str,
    at: DateTime<Utc>,
) -> LabyrinthResult<usize> {
    let sequenced = sequence_account_deleted_entries(conn, did, at).await?;
    sqlx::query("DELETE FROM chat.push_gateway_bindings WHERE user_did = $1")
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
    purge_mailbox(conn, did).await?;
    Ok(sequenced)
}

/// Pool-level helper that atomically sequences `accountDeletedEntry` across active
/// conversations, deletes `push_gateway_bindings`, and purges the Labyrinth epoch-head chain.
pub async fn delete_account_data_with_conversations(
    pool: &DbPool,
    did: &str,
    at: DateTime<Utc>,
) -> LabyrinthResult<usize> {
    let mut tx = pool.begin().await?;
    let sequenced = purge_account(&mut tx, did, at).await?;
    tx.commit().await?;
    Ok(sequenced)
}

async fn sequence_account_deleted_entries(
    conn: &mut PgConnection,
    did: &str,
    at: DateTime<Utc>,
) -> LabyrinthResult<usize> {
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    let sequencer_did = crate::identity::service_did_base();
    let active_convos: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT p.conversation_id \
           FROM chat.participants p \
           JOIN chat.conversations c ON c.conversation_id = p.conversation_id \
          WHERE p.user_did = $1 \
            AND p.current_membership \
            AND p.status = 'active' \
            AND c.lifecycle = 'active' \
          ORDER BY p.conversation_id ASC",
    )
    .bind(did)
    .fetch_all(&mut *conn)
    .await?;

    let mut sequenced = 0_usize;
    for conversation_id in active_convos {
        let head: Option<(i64, i64, i64, Option<String>)> = sqlx::query_as(
            "SELECT current_generation, current_state_version, next_entry_seq, sequencer_ds \
               FROM chat.conversations \
              WHERE conversation_id = $1 AND lifecycle = 'active' \
              FOR UPDATE",
        )
        .bind(conversation_id)
        .fetch_optional(&mut *conn)
        .await?;
        let Some((generation, state_version, seq, conv_seq_ds)) = head else {
            continue;
        };
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
        .fetch_optional(&mut *conn)
        .await?;
        let actor_info: Option<(Uuid, String, i64)> = match actor_leaf {
            Some(v) => Some(v),
            None => {
                sqlx::query_as(
                    "SELECT k.device_id, k.key_id, k.enrollment_auth_generation \
                       FROM chat.device_keys k \
                      WHERE k.user_did = $1 \
                      ORDER BY k.revoked_at IS NULL DESC, k.created_at DESC \
                      LIMIT 1",
                )
                .bind(did)
                .fetch_optional(&mut *conn)
                .await?
            }
        };
        let Some((actor_device_id, actor_key_id, actor_auth_generation)) = actor_info else {
            continue;
        };

        let effective_sequencer = conv_seq_ds.unwrap_or_else(|| sequencer_did.clone());
        let entry_id = Uuid::new_v4();

        let mut cbor_map = BTreeMap::<&str, &str>::new();
        cbor_map.insert("deletedDid", did);
        cbor_map.insert("sequencerDid", effective_sequencer.as_str());
        let server_fields_bytes = serde_ipld_dagcbor::to_vec(&cbor_map)
            .map_err(|_| crate::labyrinth::error::LabyrinthError::internal())?;

        let accepted_payload_bytes = serde_json::to_vec(&serde_json::json!({
            "$type": "blue.catbird.chat.defs#accountDeletedEntry",
            "entryId": entry_id,
            "conversationId": conversation_id,
            "seq": seq,
            "generation": generation,
            "stateVersion": state_version,
            "deletedDid": did,
            "sequencerDid": effective_sequencer,
            "receivedAt": at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        }))
        .map_err(|_| crate::labyrinth::error::LabyrinthError::internal())?;
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
        .execute(&mut *conn)
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
        .execute(&mut *conn)
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
        .execute(&mut *conn)
        .await?;

        sequenced += 1;
    }
    Ok(sequenced)
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
