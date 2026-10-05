//! Direct lookups (whitepaper "Database Abstraction": by inbox, by thread,
//! by message id, by time range). Time ranges and newest-first paging live
//! on `listBatches` / `listOwnerBatches`; this module holds the rest:
//!
//! - `getMessages`: the batches of one thread holding any of a set of
//!   message ids, through the `batch_items` index, authorized per MEK like
//!   `listBatches` (redacted items included, as stored);
//! - `listThreads`: the conversations in which the caller wrote a MEK or
//!   was addressed by one (leavers keep theirs, [CB-22]);
//! - `listOwnerThreads`: the threads of the caller's own owner archive.

use std::collections::BTreeSet;

use sqlx::PgConnection;
use uuid::Uuid;

use super::thread::{
    authored_row, batch_readable, page_of, AuthoredRow, BatchTuple, BATCH_COLUMNS,
};
use super::PageReq;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};

/// Most message ids one `getMessages` call names.
pub const MAX_MESSAGE_IDS: usize = 100;

/// `getMessages`: readable batches of `conversation_id` holding an item
/// whose id is in `message_ids`, in seq order. The cursor is the last
/// returned seq.
pub async fn get_messages(
    conn: &mut PgConnection,
    reader: &str,
    conversation_id: Uuid,
    message_ids: &[String],
    page: &PageReq,
) -> LabyrinthResult<(Vec<AuthoredRow>, Option<String>)> {
    let sql = format!(
        "SELECT {BATCH_COLUMNS} FROM labyrinth.batches b \
          WHERE b.conversation_id = $1 AND b.seq > $3 \
            AND (b.author_did, b.rkey) IN ( \
                 SELECT bi.author_did, bi.rkey FROM labyrinth.batch_items bi \
                  WHERE bi.conversation_id = $1 AND bi.message_id = ANY($4)) \
            AND {} \
          ORDER BY b.seq LIMIT $5",
        batch_readable("$2")
    );
    let rows: Vec<BatchTuple> = sqlx::query_as(&sql)
        .bind(conversation_id)
        .bind(reader)
        .bind(page.seq_cursor()?)
        .bind(message_ids)
        .bind(page.limit() + 1)
        .fetch_all(&mut *conn)
        .await?;
    let (rows, cursor) = page_of(rows, page, |r| r.0);
    let items = rows
        .into_iter()
        .map(authored_row)
        .collect::<LabyrinthResult<_>>()?;
    Ok((items, cursor))
}

/// Parse a `listThreads` cursor: the last returned conversation id.
pub fn thread_cursor(page: &PageReq) -> LabyrinthResult<Option<Uuid>> {
    page.cursor
        .as_deref()
        .map(|c| {
            super::thread::parse_thread_id(c)
                .map_err(|_| LabyrinthError::invalid("cursor is not valid"))
        })
        .transpose()
}

/// `listThreads` on this DS: conversations after the cursor, ascending by
/// id, in which `reader` wrote a MEK or is a MEK recipient. Returns up to
/// `limit + 1` ids (the caller pages and merges). When `home_ds` is given
/// (a relayed call), only conversations sequenced here in which that DS is
/// the reader's home DS (its latest participant period) are listed, exactly
/// the conversations `labyrinthRelay` would admit one by one.
pub async fn list_threads(
    conn: &mut PgConnection,
    reader: &str,
    after: Option<Uuid>,
    home_ds: Option<&str>,
    limit: i64,
) -> LabyrinthResult<Vec<Uuid>> {
    Ok(sqlx::query_scalar(
        "SELECT t.conversation_id FROM ( \
             SELECT conversation_id FROM labyrinth.mek_recipients WHERE recipient_did = $1 \
             UNION SELECT conversation_id FROM labyrinth.meks WHERE author_did = $1) t \
          WHERE ($2::uuid IS NULL OR t.conversation_id > $2) \
            AND ($3::text IS NULL OR ( \
                 EXISTS (SELECT 1 FROM chat.conversations c \
                          WHERE c.conversation_id = t.conversation_id AND NOT c.is_remote) \
                 AND split_part($3, '#', 1) = ( \
                     SELECT split_part(p.ds_did, '#', 1) FROM chat.participants p \
                      WHERE p.conversation_id = t.conversation_id AND p.user_did = $1 \
                      ORDER BY p.created_at DESC, p.participant_period_id DESC LIMIT 1))) \
          ORDER BY t.conversation_id LIMIT $4",
    )
    .bind(reader)
    .bind(after)
    .bind(home_ds)
    .bind(limit)
    .fetch_all(&mut *conn)
    .await?)
}

/// Merge per-DS `listThreads` pages (each the smallest ids after the same
/// cursor, ascending) into one page of `limit`. `more` is whether any
/// source reported further ids.
pub fn merge_thread_pages(
    pages: Vec<Vec<Uuid>>,
    more: bool,
    limit: i64,
) -> (Vec<Uuid>, Option<String>) {
    let all: BTreeSet<Uuid> = pages.into_iter().flatten().collect();
    let more = more || all.len() as i64 > limit;
    let ids: Vec<Uuid> = all.into_iter().take(limit as usize).collect();
    let cursor = more
        .then(|| ids.last().map(|id| id.hyphenated().to_string()))
        .flatten();
    (ids, cursor)
}

/// `listOwnerThreads`: the threads of `owner`'s archive, by the seq of
/// their first owner batch (stable: owner batches are only ever removed
/// all together, by `purgeMailbox`). The cursor is that seq.
pub async fn list_owner_threads(
    conn: &mut PgConnection,
    owner: &str,
    page: &PageReq,
) -> LabyrinthResult<(Vec<String>, Option<String>)> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT thread_id, min(seq) AS first FROM labyrinth.owner_batches \
          WHERE owner_did = $1 GROUP BY thread_id HAVING min(seq) > $2 \
          ORDER BY first LIMIT $3",
    )
    .bind(owner)
    .bind(page.seq_cursor()?)
    .bind(page.limit() + 1)
    .fetch_all(&mut *conn)
    .await?;
    let (rows, cursor) = page_of(rows, page, |r| r.1);
    Ok((rows.into_iter().map(|r| r.0).collect(), cursor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merged_thread_pages_are_the_smallest_ids_after_the_cursor() {
        let ids: Vec<Uuid> = (1..=5u128).map(Uuid::from_u128).collect();
        let (page, cursor) = merge_thread_pages(
            vec![vec![ids[0], ids[3]], vec![ids[1], ids[3], ids[4]]],
            false,
            3,
        );
        assert_eq!(page, vec![ids[0], ids[1], ids[3]]);
        assert_eq!(cursor, Some(ids[3].hyphenated().to_string()));
        let (page, cursor) = merge_thread_pages(vec![vec![ids[2]], vec![]], false, 3);
        assert_eq!((page, cursor), (vec![ids[2]], None));
        let (_, cursor) = merge_thread_pages(vec![vec![ids[2]]], true, 3);
        assert_eq!(cursor, Some(ids[2].hyphenated().to_string()));
    }
}
