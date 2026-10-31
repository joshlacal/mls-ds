//! SQL for the clean-slate `labyrinth` schema (`epoch_heads`, `epoch_head_floors`, `operations`).

pub mod directory;
pub mod retention;

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use super::error::{LabyrinthError, LabyrinthResult};

/// Most items any list returns per page.
pub const MAX_PAGE: i64 = 100;

/// A page request: an opaque cursor, a `1..=100` limit, and direction.
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
}

/// Time window parameters (`fromMs`, `untilMs`, `since`, `until`).
#[derive(Clone, Copy, Debug, Default)]
pub struct TimeRange {
    pub from_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

/// Parse a canonical lowercase UUIDv4 conversation/thread identifier.
pub fn parse_thread_id(value: &str) -> LabyrinthResult<Uuid> {
    let id = Uuid::parse_str(value)
        .map_err(|_| LabyrinthError::invalid("threadId must be a canonical lowercase UUIDv4"))?;
    if id.hyphenated().to_string() != value || id.get_version_num() != 4 {
        return Err(LabyrinthError::invalid(
            "threadId must be a canonical lowercase UUIDv4",
        ));
    }
    Ok(id)
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

/// Open the transaction-bound retention scope: every DELETE of a labyrinth row
/// must run inside it.
pub async fn open_retention_scope(conn: &mut PgConnection) -> LabyrinthResult<()> {
    sqlx::query("SELECT labyrinth.open_retention_scope()")
        .execute(&mut *conn)
        .await?;
    Ok(())
}
