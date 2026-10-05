//! SQL for the `labyrinth` schema. Every function runs inside the caller's
//! request transaction (`auth::RequestTx`), which already holds the calling
//! device's lock.

pub mod attachments;
pub mod binding;
pub mod directory;
pub mod liveness;
pub mod lookup;
pub mod mailbox;
pub mod orf;
pub mod outbox;
pub mod retention;
pub mod thread;

use chrono::{DateTime, Utc};
use sqlx::PgConnection;

use super::error::{LabyrinthError, LabyrinthResult};
use super::wire::io::{datetime, ServerOrder};

/// Most items any list returns per page (design §2).
pub const MAX_PAGE: i64 = 100;

/// A page request: an opaque cursor, a 1..=100 limit and, for
/// `seq`-ordered lists, the direction (`reverse` = newest first).
#[derive(Clone, Debug, Default)]
pub struct PageReq {
    pub cursor: Option<String>,
    pub limit: Option<i64>,
    pub reverse: bool,
}

impl PageReq {
    pub fn limit(&self) -> i64 {
        self.limit.unwrap_or(MAX_PAGE).clamp(1, MAX_PAGE)
    }

    /// The cursor as a sequence number (`seq`-ordered lists).
    pub fn seq_cursor(&self) -> LabyrinthResult<i64> {
        match &self.cursor {
            None => Ok(0),
            Some(c) => c
                .parse::<i64>()
                .ok()
                .filter(|n| *n >= 0)
                .ok_or_else(|| LabyrinthError::invalid("cursor is not valid")),
        }
    }

    /// The `seq` bound of this page in direction order: rows strictly after
    /// it are `<seq column> {seq_cmp} bound`. A reverse page with no cursor
    /// starts above every seq.
    pub fn seq_bound(&self) -> LabyrinthResult<i64> {
        match (self.reverse, &self.cursor) {
            (true, None) => Ok(i64::MAX),
            _ => self.seq_cursor(),
        }
    }

    /// The comparison that keeps rows after [`seq_bound`](Self::seq_bound).
    pub fn seq_cmp(&self) -> &'static str {
        if self.reverse {
            "<"
        } else {
            ">"
        }
    }

    /// The `ORDER BY` direction.
    pub fn seq_dir(&self) -> &'static str {
        if self.reverse {
            "DESC"
        } else {
            "ASC"
        }
    }
}

/// `TimeRange` of the list queries: items with `from <= ts < until` by the
/// sender's timestamp, and records the server received in
/// `since <= receivedAt < until` (the server clock, `serverOrder`).
#[derive(Clone, Copy, Debug, Default)]
pub struct TimeRange {
    pub from_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

impl TimeRange {
    pub fn contains(&self, ts: u64) -> bool {
        let ts = ts as i64;
        self.from_ms.is_none_or(|f| ts >= f) && self.until_ms.is_none_or(|u| ts < u)
    }
}

/// A `serverOrder` stamp from stored columns.
pub fn order(seq: i64, chat_seq: Option<i64>, received_at: DateTime<Utc>) -> ServerOrder {
    ServerOrder {
        seq,
        chat_seq,
        received_at: datetime(received_at),
    }
}

/// Parse a stored JSONB record back into a JSON value for a response.
pub fn stored_json(text: &str) -> LabyrinthResult<serde_json::Value> {
    serde_json::from_str(text).map_err(|error| {
        tracing::error!(?error, "stored labyrinth record is not JSON");
        LabyrinthError::internal()
    })
}

/// Serialize the session's advisory lock for one key, held to commit.
pub async fn advisory_lock(conn: &mut PgConnection, key: &str) -> LabyrinthResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(key)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Open the transaction-bound retention scope (migration `20261004100006`):
/// every DELETE of a labyrinth row must run inside it.
pub async fn open_retention_scope(conn: &mut PgConnection) -> LabyrinthResult<()> {
    sqlx::query("SELECT labyrinth.open_retention_scope()")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Constant-time equality for MACs.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
