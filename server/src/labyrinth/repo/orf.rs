//! ORF server states (labyrinth SPEC §8, [CB-17]; design §2 "ORF and
//! attachments"). All rows belong to the caller DID. Attachment references
//! live in `attachments`.

use chrono::{DateTime, Utc};
use sqlx::PgConnection;

use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::orf::{server_evolve, server_init};

/// Most ORF states one account keeps here. A Space account registers
/// without a bound device, so only this bounds its rows; a real account
/// holds one per physical or virtual device plus short-lived one-time-code
/// states.
pub const MAX_ORF_STATES: i64 = 1024;

pub(super) fn orf_not_found() -> LabyrinthError {
    LabyrinthError::not_found("OrfStateNotFound")
}

pub(super) async fn state(
    conn: &mut PgConnection,
    owner: &str,
    device_key: &[u8; 32],
) -> LabyrinthResult<Option<[u8; 32]>> {
    let row: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT server_state FROM labyrinth.orf_states \
          WHERE owner_did = $1 AND device_key = $2 FOR SHARE",
    )
    .bind(owner)
    .bind(device_key.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    row.map(|s| {
        s.as_slice()
            .try_into()
            .map_err(|_| LabyrinthError::internal())
    })
    .transpose()
}

/// Register `device_key`'s state: fresh without a parent, else evolved from
/// the parent's state with the client's evolve token.
pub async fn register(
    conn: &mut PgConnection,
    owner: &str,
    device_key: &[u8; 32],
    parent: Option<([u8; 32], [u8; 32])>,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    if state(conn, owner, device_key).await?.is_some() {
        return Err(LabyrinthError::already_exists());
    }
    // Every caller holds the owner's mailbox lock (`binding::lock_mailbox`,
    // taken by `hosts_mailbox` or the createVirtualDevice charge), so
    // concurrent registrations cannot both pass the count.
    let held: i64 =
        sqlx::query_scalar("SELECT count(*) FROM labyrinth.orf_states WHERE owner_did = $1")
            .bind(owner)
            .fetch_one(&mut *conn)
            .await?;
    if held >= MAX_ORF_STATES {
        return Err(LabyrinthError::quota(
            "too many ORF states for this account",
        ));
    }
    let new_state = match parent {
        None => server_init(),
        Some((parent_key, token)) => {
            let parent_state = state(conn, owner, &parent_key)
                .await?
                .ok_or_else(orf_not_found)?;
            server_evolve(parent_state, token)?
        }
    };
    let inserted = sqlx::query(
        "INSERT INTO labyrinth.orf_states (owner_did, device_key, server_state, created_at) \
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(owner)
    .bind(device_key.as_slice())
    .bind(new_state.as_slice())
    .bind(at)
    .execute(&mut *conn)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(LabyrinthError::already_exists());
    }
    Ok(())
}

/// Delete `device_key`'s state (revocation). Idempotent. The deletion
/// leaves a tombstone; the retention pass releases the references created
/// through the state (migration `20261004100009`).
pub async fn delete(
    conn: &mut PgConnection,
    owner: &str,
    device_key: &[u8; 32],
) -> LabyrinthResult<()> {
    super::open_retention_scope(conn).await?;
    sqlx::query("DELETE FROM labyrinth.orf_states WHERE owner_did = $1 AND device_key = $2")
        .bind(owner)
        .bind(device_key.as_slice())
        .execute(&mut *conn)
        .await?;
    Ok(())
}
