//! The verifying `EpochPublic` head directory and MLS device views (`Gate 6`, `L-F01`).

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use super::{advisory_lock, PageReq};
use crate::labyrinth::auth::Caller;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::heads::{check_chain_link, verify_epoch_public, verify_prev_sig};
use crate::labyrinth::wire::records::EpochPublic;

/// Maximum `chain` length returned by `getEpochHead` (`lexicon/blue.catbird.labyrinth.getEpochHead.json`).
const MAX_CHAIN_HEADERS: i64 = 1024;

/// The key id of `did`'s *current* chat device key `key`, if any.
pub async fn current_chat_key_id(
    conn: &mut PgConnection,
    did: &str,
    key: &[u8; 32],
) -> LabyrinthResult<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT k.key_id FROM chat.device_keys k \
           JOIN chat.devices d ON d.user_did = k.user_did AND d.device_id = k.device_id \
          WHERE k.user_did = $1 AND k.signing_public_key = $2 \
            AND k.revoked_at IS NULL AND d.status='active' AND d.revoked_at IS NULL \
            AND k.enrollment_auth_generation<=d.auth_generation \
            AND NOT EXISTS(SELECT 1 FROM chat.device_keys newer \
                WHERE newer.user_did=k.user_did AND newer.device_id=k.device_id \
                  AND newer.enrollment_auth_generation>k.enrollment_auth_generation \
                  AND newer.enrollment_auth_generation<=d.auth_generation)",
    )
    .bind(did)
    .bind(key.as_slice())
    .fetch_optional(&mut *conn)
    .await?)
}

fn not_caller() -> LabyrinthError {
    LabyrinthError::new(
        axum::http::StatusCode::BAD_REQUEST,
        "AttestationNotCaller",
        "the head must be attested by the calling chat device's own key",
    )
}

fn head_conflict() -> LabyrinthError {
    LabyrinthError::new(
        axum::http::StatusCode::CONFLICT,
        "EpochHeadConflict",
        "a different head is already recorded for this epoch",
    )
}

fn promotion_lock_error(error: sqlx::Error) -> LabyrinthError {
    if matches!(&error, sqlx::Error::Database(db) if db.code().as_deref() == Some("55P03")) {
        return LabyrinthError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "device state is changing; retry the restore",
        )
        .with_retry_after(1);
    }
    error.into()
}

pub(crate) fn parse_stored(text: &str) -> LabyrinthResult<EpochPublic> {
    serde_json::from_str(text).map_err(|error| {
        tracing::error!(?error, "stored epoch head does not parse");
        LabyrinthError::internal()
    })
}

/// The pending device's durable notice must be at least the configured hold old.
async fn require_pending_notice_hold(
    conn: &mut PgConnection,
    did: &str,
    device_id: Uuid,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    let notice_at: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT recorded_at FROM chat.device_promotion_audit \
          WHERE user_did = $1 AND device_id = $2 AND event_kind = 'pending_notice'",
    )
    .bind(did)
    .bind(device_id)
    .fetch_optional(&mut *conn)
    .await?;
    let cutoff = chrono::Duration::try_hours(
        crate::chat_protocol::device_activity::pending_device_hold_hours(),
    )
    .and_then(|hold| at.checked_sub_signed(hold));
    if !matches!((notice_at, cutoff), (Some(notice), Some(cutoff)) if notice <= cutoff) {
        return Err(LabyrinthError::not_authorized(
            "pending device recovery hold is not complete",
        ));
    }
    Ok(())
}

/// Promote a pending device whose fresh `publishEpochHead` just succeeded.
///
/// `chained_proof` is true when the head extends an existing chain with a
/// verified `prevSig`, which only a holder of the account's recovery secret
/// (recovery code or backup passkey) can produce.
///
/// A chained proof promotes at once, whatever other devices are registered:
/// the account owner chose the recovery code or backup passkey as enough on
/// its own. A genesis head proves nothing, so it keeps the 72-hour hold that
/// lets a sibling see and deny the pending device, and an awake sibling
/// vetoes it.
async fn promote_pending_device(
    conn: &mut PgConnection,
    did: &str,
    device_id: Uuid,
    at: DateTime<Utc>,
    chained_proof: bool,
) -> LabyrinthResult<()> {
    // Enrollment and sibling revocation take this principal lock before device
    // rows. Authentication already holds the pending requester row, so NOWAIT
    // lets those earlier operations win without reversing their lock order.
    let _: String = sqlx::query_scalar(
        "SELECT user_did FROM chat.principals WHERE user_did = $1 FOR UPDATE NOWAIT",
    )
    .bind(did)
    .fetch_one(&mut *conn)
    .await
    .map_err(promotion_lock_error)?;

    // Lock every active local sibling, including dormant ones. NOWAIT makes a
    // concurrent sibling wake/revocation win instead of deadlocking with the
    // pending caller's device lock acquired by request authentication.
    // Full-loss recovery has its own 72-hour visible notice and sibling activity
    // check. The 60-day delivery-retention window must not delay recovery.
    // Preserve the previous 48 hours of true inactivity plus the coarse-day margin.
    let recovery_activity_cutoff = at - chrono::Duration::hours(72);
    let siblings: Vec<(bool,)> = sqlx::query_as(
        "SELECT last_active_at > $3 FROM chat.devices \
          WHERE user_did = $1 AND device_id <> $2 \
            AND status = 'active' AND revoked_at IS NULL \
            AND NOT (dpop_jkt IS NULL AND device_name = 'federated-group-device') \
          FOR SHARE NOWAIT",
    )
    .bind(did)
    .bind(device_id)
    .bind(recovery_activity_cutoff)
    .fetch_all(&mut *conn)
    .await
    .map_err(promotion_lock_error)?;
    // A chained head proves the recovery secret (recovery code or backup
    // passkey). The owner chose that proof over sibling approval and the hold,
    // so it promotes at once.
    if !chained_proof {
        if siblings.iter().any(|(awake,)| *awake) {
            return Err(LabyrinthError::not_authorized(
                "an active sibling must approve or deny the pending device",
            ));
        }
        require_pending_notice_hold(conn, did, device_id, at).await?;
    }

    let promoted = sqlx::query(
        "UPDATE chat.devices \
            SET status = 'active', \
                updated_at = GREATEST(updated_at, $3) \
          WHERE user_did = $1 \
            AND device_id = $2 \
            AND status = 'pending_approval' AND revoked_at IS NULL",
    )
    .bind(did)
    .bind(device_id)
    .bind(at)
    .execute(&mut *conn)
    .await?;
    if promoted.rows_affected() != 1 {
        return Err(LabyrinthError::not_authorized(
            "pending device was revoked or already changed",
        ));
    }
    sqlx::query(
        "INSERT INTO chat.device_promotion_audit \
         (user_did, device_id, event_kind, recorded_at) \
         VALUES ($1, $2, 'recovery_promoted', $3)",
    )
    .bind(did)
    .bind(device_id)
    .bind(at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Accept `epoch` into the caller DID's head chain (`Gate 3`, `Gate 6`, `L-F01`).
///
/// Recomputes `epochHead` (with `membersHash`), verifies XEdDSA `selfSig` and the calling
/// chat device's Ed25519 attestation, enforces the monotonic `labyrinth.epoch_head_floors`
/// rollback floor, and verifies `prevSig` under the previous epoch's signing key.
/// Re-sending an identical head is idempotent; a different head at the same epoch number
/// returns `409 EpochHeadConflict`.
///
/// A `pending_approval` device may publish a fresh head only after its
/// sibling-visible 72-hour hold, when no other local device remains awake.
/// An existing head requires a verified `prevSig` chain; a principal with no
/// head may begin at genesis (or the next post-purge floor). Neither form
/// bypasses a live sibling's approval or denial.
pub async fn record_head(
    conn: &mut PgConnection,
    caller: &Caller,
    epoch: &EpochPublic,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    let did = caller.did.as_str();
    let parts = verify_epoch_public(did, epoch)?;
    if parts.attestation_key != caller.signing_key {
        return Err(not_caller());
    }
    advisory_lock(conn, &format!("labyrinth.epoch_heads:{did}")).await?;
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT epoch_public::text FROM labyrinth.epoch_heads \
          WHERE did = $1 AND epoch_number = $2",
    )
    .bind(did)
    .bind(parts.epoch_number as i64)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(text) = existing {
        if &parse_stored(&text)? != epoch {
            return Err(head_conflict());
        }
        if caller.status == "pending_approval" {
            return Err(LabyrinthError::not_authorized(
                "pending device requires a fresh chained epoch rotation",
            ));
        }
        return Ok(());
    }
    let latest: Option<(i64, Vec<u8>, String)> = sqlx::query_as(
        "SELECT epoch_number, epoch_head, epoch_public::text FROM labyrinth.epoch_heads \
          WHERE did = $1 ORDER BY epoch_number DESC LIMIT 1",
    )
    .bind(did)
    .fetch_optional(&mut *conn)
    .await?;
    let latest = latest
        .map(|(n, head, text)| -> LabyrinthResult<_> {
            let head: [u8; 32] = head
                .as_slice()
                .try_into()
                .map_err(|_| LabyrinthError::internal())?;
            let signing = parse_stored(&text)?
                .signing_pubkey
                .array::<32>("signingPubkey")?;
            Ok((n as u64, head, signing))
        })
        .transpose()?;
    if caller.status == "pending_approval"
        && latest.is_some()
        && (parts.epoch_number == 0 || parts.prev_sig.is_none())
    {
        return Err(LabyrinthError::not_authorized(
            "pending device requires a chained epoch rotation with prevSig",
        ));
    }
    let floor: Option<i64> = sqlx::query_scalar(
        "SELECT max_epoch_number FROM labyrinth.epoch_head_floors WHERE did = $1",
    )
    .bind(did)
    .fetch_optional(&mut *conn)
    .await?;
    let floor = floor
        .map(|f| u64::try_from(f).map_err(|_| LabyrinthError::internal()))
        .transpose()?;
    check_chain_link(&parts, latest.map(|(n, head, _)| (n, head)), floor)?;
    if let Some((_, _, previous_signing_key)) = latest {
        verify_prev_sig(&parts, &previous_signing_key)?;
    }
    let text = serde_json::to_string(epoch).map_err(|_| LabyrinthError::internal())?;
    sqlx::query(
        "INSERT INTO labyrinth.epoch_heads \
           (did, epoch_number, epoch_head, previous_epoch_head, epoch_public, \
            epoch_public_bytes, attestation_key_id, received_at) \
         VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)",
    )
    .bind(did)
    .bind(parts.epoch_number as i64)
    .bind(parts.head.as_slice())
    .bind(parts.previous_head.map(|h| h.to_vec()))
    .bind(&text)
    .bind(text.len() as i32)
    .bind(&caller.key_id)
    .bind(at)
    .execute(&mut *conn)
    .await?;
    if caller.status == "pending_approval" {
        promote_pending_device(conn, did, caller.device_id, at, latest.is_some()).await?;
    }
    Ok(())
}

/// Verified `getEpochHead` response payload (`Gate 6` + `L-F01`).
pub struct EpochHeadLookup {
    pub epoch: serde_json::Value,
    pub chain: Vec<serde_json::Value>,
    pub floor_seq: u64,
    pub received_at: DateTime<Utc>,
}

/// `getEpochHead`: returns the target `epoch`, contiguous verified `chain` from
/// `floorSeq..=epoch.epochNumber` (up to 1,024 headers), `floorSeq`, and `receivedAt`.
pub async fn get_head(
    conn: &mut PgConnection,
    did: &str,
    n: Option<u64>,
) -> LabyrinthResult<Option<EpochHeadLookup>> {
    let row: Option<(i64, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT epoch_number, epoch_public::text, received_at FROM labyrinth.epoch_heads \
          WHERE did = $1 AND ($2::bigint IS NULL OR epoch_number = $2) \
          ORDER BY epoch_number DESC LIMIT 1",
    )
    .bind(did)
    .bind(n.map(|n| n as i64))
    .fetch_optional(&mut *conn)
    .await?;
    let Some((target_seq, text, received_at)) = row else {
        return Ok(None);
    };
    let epoch = super::stored_json(&text)?;

    let mut chain_rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT epoch_number, epoch_public::text FROM labyrinth.epoch_heads \
          WHERE did = $1 AND epoch_number <= $2 \
          ORDER BY epoch_number DESC LIMIT $3",
    )
    .bind(did)
    .bind(target_seq)
    .bind(MAX_CHAIN_HEADERS)
    .fetch_all(&mut *conn)
    .await?;
    chain_rows.reverse();

    let floor_seq = chain_rows
        .first()
        .map(|(seq, _)| u64::try_from(*seq).unwrap_or(0))
        .unwrap_or(target_seq.max(0) as u64);
    let mut chain = Vec::with_capacity(chain_rows.len());
    for (_, item_text) in chain_rows {
        chain.push(super::stored_json(&item_text)?);
    }

    Ok(Some(EpochHeadLookup {
        epoch,
        chain,
        floor_seq,
        received_at,
    }))
}

/// One `getChatDeviceKeys` item.
pub struct ChatKeyRow {
    pub key_id: String,
    pub signing_public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Every chat device key of `did`, revoked ones included (with the time).
/// The cursor is the last `keyId`.
pub async fn chat_device_keys(
    conn: &mut PgConnection,
    did: &str,
    page: &PageReq,
) -> LabyrinthResult<(Vec<ChatKeyRow>, Option<String>)> {
    let mut rows: Vec<(String, Vec<u8>, DateTime<Utc>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT k.key_id, k.signing_public_key, k.created_at, \
                COALESCE(k.revoked_at, d.revoked_at) \
           FROM chat.device_keys k \
           JOIN chat.devices d ON d.user_did = k.user_did AND d.device_id = k.device_id \
          WHERE k.user_did = $1 AND k.key_id > $2 \
          ORDER BY k.key_id LIMIT $3",
    )
    .bind(did)
    .bind(page.cursor.clone().unwrap_or_default())
    .bind(page.limit() + 1)
    .fetch_all(&mut *conn)
    .await?;
    let more = rows.len() as i64 > page.limit();
    rows.truncate(page.limit() as usize);
    let cursor = more.then(|| rows.last().map(|r| r.0.clone())).flatten();
    let items = rows
        .into_iter()
        .map(
            |(key_id, signing_public_key, created_at, revoked_at)| ChatKeyRow {
                key_id,
                signing_public_key,
                created_at,
                revoked_at,
            },
        )
        .collect();
    Ok((items, cursor))
}

/// Whether `did` has an accepted participant period (`active`, `left`, or `removed`) in `conversation_id`.
pub async fn ever_participant(
    conn: &mut PgConnection,
    conversation_id: Uuid,
    did: &str,
) -> LabyrinthResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.participants \
                        WHERE conversation_id = $1 AND user_did = $2 \
                          AND status IN ('active', 'left', 'removed'))",
    )
    .bind(conversation_id)
    .bind(did)
    .fetch_one(&mut *conn)
    .await?)
}

/// One `getMemberDevices` item: a device leaf period of `did`.
pub struct MemberDeviceRow {
    pub key_id: String,
    pub signing_public_key: Vec<u8>,
    pub joined_seq: i64,
    pub removed_seq: Option<i64>,
}

/// `did`'s device leaves in the conversation with the chat seqs that added
/// and removed each. Only a past or present accepted participant may read a
/// conversation's leaf view; anyone else sees `ConversationNotFound`.
pub async fn member_devices(
    conn: &mut PgConnection,
    conversation_id: Uuid,
    did: &str,
    caller_did: &str,
    page: &PageReq,
) -> LabyrinthResult<(Vec<MemberDeviceRow>, Option<String>)> {
    let route: Option<(bool, Option<String>)> = sqlx::query_as(
        "SELECT is_remote, sequencer_ds FROM chat.conversations \
          WHERE conversation_id = $1 FOR SHARE",
    )
    .bind(conversation_id)
    .fetch_optional(&mut *conn)
    .await?;
    match route {
        None => return Err(LabyrinthError::not_found("ConversationNotFound")),
        Some((false, None)) => {}
        Some(_) => {
            return Err(LabyrinthError::forbidden(
                "NotAuthorized",
                "member device history is served only by the conversation sequencer",
            ))
        }
    }
    if !ever_participant(conn, conversation_id, caller_did).await? {
        return Err(LabyrinthError::not_found("ConversationNotFound"));
    }
    let offset = page.seq_cursor()?;
    let mut rows: Vec<(String, Vec<u8>, i64, Option<i64>)> = sqlx::query_as(
        "SELECT leaf_key_id, leaf_signature_key, joined_seq, removed_seq \
           FROM chat.member_devices \
          WHERE conversation_id = $1 AND user_did = $2 \
          ORDER BY joined_seq, uuid_send(device_id), leaf_period_id OFFSET $3 LIMIT $4",
    )
    .bind(conversation_id)
    .bind(did)
    .bind(offset)
    .bind(page.limit() + 1)
    .fetch_all(&mut *conn)
    .await?;
    let more = rows.len() as i64 > page.limit();
    rows.truncate(page.limit() as usize);
    let cursor = more.then(|| offset.saturating_add(page.limit()).to_string());
    let items = rows
        .into_iter()
        .map(
            |(key_id, signing_public_key, joined_seq, removed_seq)| MemberDeviceRow {
                key_id,
                signing_public_key,
                joined_seq,
                removed_seq,
            },
        )
        .collect();
    Ok((items, cursor))
}
