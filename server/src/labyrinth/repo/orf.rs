//! ORF server states (labyrinth SPEC §8, [CB-17]; design §2 "ORF and
//! attachments"). All rows belong to the caller DID. Attachment references
//! live in `attachments`.

use chrono::{DateTime, Utc};
use sqlx::PgConnection;

use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::orf::{server_evolve, server_init};

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

/// Delete `device_key`'s state (revocation). Idempotent.
pub async fn delete(
    conn: &mut PgConnection,
    owner: &str,
    device_key: &[u8; 32],
) -> LabyrinthResult<()> {
    sqlx::query("DELETE FROM labyrinth.orf_states WHERE owner_did = $1 AND device_key = $2")
        .bind(owner)
        .bind(device_key.as_slice())
        .execute(&mut *conn)
        .await?;
    Ok(())
}
