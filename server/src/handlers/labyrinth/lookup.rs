//! Lookup endpoints (`crate::labyrinth::repo::lookup`): `getMessages`,
//! `listThreads` and `listOwnerThreads`.
//!
//! `getMessages` names one thread, so it runs like `listBatches`: locally,
//! or on the conversation's sequencer through `labyrinthRelay`.
//! `listThreads` spans conversations sequenced anywhere: the home DS lists
//! its own, asks every remote sequencer of a conversation the caller takes
//! or took part in for the same page (`labyrinthRelay listThreads`), and
//! merges. A sequencer that cannot answer in time is listed in the
//! response's `incomplete` instead of failing the call. `listOwnerThreads` reads the
//! caller's own mailbox, which is always local.

use std::sync::Arc;

use axum::{
    extract::{RawQuery, State},
    http::HeaderMap,
    response::Response,
};
use serde_json::json;
use uuid::Uuid;

use super::params::{admit_query, Params};
use super::relay_client::{Forwarded, Relay};
use super::respond;
use super::thread::{read, read_params};
use crate::handlers::chat::ChatRuntime;
use crate::labyrinth::auth::begin_read;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::relay::RelayOp;
use crate::labyrinth::repo::{lookup as repo, retention};
use crate::labyrinth::wire::bytes::check_str;
use crate::labyrinth::wire::io::{to_bytes, Page};
use crate::storage::DbPool;

type Pool = State<DbPool>;
type Runtime = State<Arc<ChatRuntime>>;

/// The `messageIds` of a `getMessages` call: 1..=100 ids of 1..=128 bytes.
pub(super) fn message_ids(p: &Params) -> LabyrinthResult<&[String]> {
    let ids = p.all("messageIds");
    if ids.is_empty() || ids.len() > repo::MAX_MESSAGE_IDS {
        return Err(LabyrinthError::invalid("messageIds must name 1..=100 ids"));
    }
    for id in ids {
        check_str("messageIds", id, 128)?;
    }
    Ok(ids)
}

/// A `listThreads` response page from per-DS id lists.
pub(super) fn threads_page(
    pages: Vec<Vec<Uuid>>,
    more: bool,
    limit: i64,
    incomplete: &[String],
) -> LabyrinthResult<Vec<u8>> {
    let (ids, cursor) = repo::merge_thread_pages(pages, more, limit);
    let items: Vec<_> = ids
        .into_iter()
        .map(|id| json!({ "threadId": id.hyphenated().to_string() }))
        .collect();
    let mut out = json!({ "items": items });
    if let Some(cursor) = cursor {
        out["cursor"] = json!(cursor);
    }
    if !incomplete.is_empty() {
        out["incomplete"] = json!(incomplete);
    }
    to_bytes(&out)
}

/// One remote sequencer's `listThreads` page: its ids and whether it has more.
fn remote_page(bytes: &[u8]) -> LabyrinthResult<(Vec<Uuid>, bool)> {
    #[derive(serde::Deserialize)]
    struct Item {
        #[serde(rename = "threadId")]
        thread_id: String,
    }
    #[derive(serde::Deserialize)]
    struct Wire {
        items: Vec<Item>,
        #[serde(default)]
        cursor: Option<String>,
    }
    let page: Wire = serde_json::from_slice(bytes).map_err(|error| {
        tracing::warn!(%error, "labyrinth relay listThreads answer does not parse");
        LabyrinthError::relay_unavailable()
    })?;
    let ids = page
        .items
        .iter()
        .map(|i| {
            crate::labyrinth::repo::thread::parse_thread_id(&i.thread_id)
                .map_err(|_| LabyrinthError::relay_unavailable())
        })
        .collect::<LabyrinthResult<_>>()?;
    Ok((ids, page.cursor.is_some()))
}

/// Remote sequencers asked at once by one `listThreads` call.
const FANOUT_CONCURRENCY: usize = 8;
/// Remote sequencers asked at all by one call; the rest are reported
/// incomplete.
const FANOUT_MAX_SEQUENCERS: usize = 64;
/// Per-sequencer deadline.
const FANOUT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Largest per-sequencer answer (100 thread ids fit in well under this).
const FANOUT_MAX_RESPONSE: usize = 64 * 1024;

/// `listThreads` (finding 4): the local page merged with every remote
/// sequencer's, asked in parallel (bounded concurrency, per-sequencer
/// timeout and response cap). A sequencer that fails, times out or is past
/// the fan-out cap is named in `incomplete` instead of failing the call.
async fn list_threads_all(
    pool: &DbPool,
    rt: &ChatRuntime,
    relay: &Relay,
    headers: &HeaderMap,
    query: Option<&str>,
) -> LabyrinthResult<Vec<u8>> {
    use futures::stream::{self, StreamExt};
    let op = RelayOp::ListThreads;
    let (adm, p) = admit_query(pool, rt, op.name(), headers, query, read_params(op)).await?;
    let page = p.page()?;
    let after = repo::thread_cursor(&page)?;
    let mut r = begin_read(pool, adm.clone()).await?;
    let local = repo::list_threads(&mut r.tx, &r.caller.did, after, None, page.limit() + 1).await?;
    let mut sequencers = retention::remote_sequencers(&mut r.tx, &r.caller.did).await?;
    r.finish_read().await?;
    let mut incomplete: Vec<String> = sequencers
        .split_off(sequencers.len().min(FANOUT_MAX_SEQUENCERS));
    let query = query.unwrap_or_default();
    let answers: Vec<(String, LabyrinthResult<(Vec<Uuid>, bool)>)> = stream::iter(sequencers)
        .map(|sequencer| {
            let adm = &adm;
            async move {
                let call = relay.forward_capped(
                    pool,
                    &sequencer,
                    op,
                    adm,
                    Forwarded::Read { query },
                    FANOUT_MAX_RESPONSE,
                );
                let result = match tokio::time::timeout(FANOUT_TIMEOUT, call).await {
                    Ok(Ok(bytes)) => remote_page(&bytes),
                    Ok(Err(e)) => Err(e),
                    Err(_) => Err(LabyrinthError::relay_unavailable()),
                };
                (sequencer, result)
            }
        })
        .buffer_unordered(FANOUT_CONCURRENCY)
        .collect()
        .await;
    let mut pages = vec![local];
    let mut more = false;
    for (sequencer, result) in answers {
        match result {
            Ok((ids, has_more)) => {
                more |= has_more;
                pages.push(ids);
            }
            Err(error) => {
                tracing::warn!(%sequencer, %error, "listThreads: sequencer incomplete");
                incomplete.push(sequencer);
            }
        }
    }
    incomplete.sort();
    threads_page(pages, more, page.limit(), &incomplete)
}

pub async fn list_threads(
    State(pool): Pool,
    State(rt): Runtime,
    relay: Relay,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
) -> Response {
    respond(list_threads_all(&pool, &rt, &relay, &headers, q.as_deref()).await)
}

pub async fn get_messages(
    State(pool): Pool,
    State(rt): Runtime,
    relay: Relay,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
) -> Response {
    respond(
        read(
            &pool,
            &rt,
            &relay,
            RelayOp::GetMessages,
            &headers,
            q.as_deref(),
        )
        .await,
    )
}

pub async fn list_owner_threads(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
) -> Response {
    respond(
        async {
            let (adm, p) = admit_query(
                &pool,
                &rt,
                "listOwnerThreads",
                &headers,
                q.as_deref(),
                &["cursor", "limit"],
            )
            .await?;
            let page = p.page()?;
            let mut r = begin_read(&pool, adm).await?;
            let (threads, cursor) =
                repo::list_owner_threads(&mut r.tx, &r.caller.did, &page).await?;
            r.finish_read().await?;
            let items = threads
                .into_iter()
                .map(|t| json!({ "threadId": t }))
                .collect();
            to_bytes(&Page { items, cursor })
        }
        .await,
    )
}
