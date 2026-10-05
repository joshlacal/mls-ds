//! Lookup endpoints (`crate::labyrinth::repo::lookup`): `getMessages`,
//! `listThreads` and `listOwnerThreads`.
//!
//! `getMessages` names one thread, so it runs like `listBatches`: locally,
//! or on the conversation's sequencer through `labyrinthRelay`.
//! `listThreads` spans conversations sequenced anywhere: the home DS lists
//! its own, asks every remote sequencer of a conversation the caller takes
//! or took part in for the same page (`labyrinthRelay listThreads`), and
//! merges. One unreachable sequencer fails the call (`RelayUnavailable`)
//! rather than answer an incomplete list. `listOwnerThreads` reads the
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
) -> LabyrinthResult<Vec<u8>> {
    let (ids, cursor) = repo::merge_thread_pages(pages, more, limit);
    let items = ids
        .into_iter()
        .map(|id| json!({ "threadId": id.hyphenated().to_string() }))
        .collect();
    to_bytes(&Page { items, cursor })
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

async fn list_threads_all(
    pool: &DbPool,
    rt: &ChatRuntime,
    relay: &Relay,
    headers: &HeaderMap,
    query: Option<&str>,
) -> LabyrinthResult<Vec<u8>> {
    let op = RelayOp::ListThreads;
    let (adm, p) = admit_query(pool, rt, op.name(), headers, query, read_params(op)).await?;
    let page = p.page()?;
    let after = repo::thread_cursor(&page)?;
    let mut r = begin_read(pool, adm.clone()).await?;
    let local = repo::list_threads(&mut r.tx, &r.caller.did, after, None, page.limit() + 1).await?;
    let sequencers = retention::remote_sequencers(&mut r.tx, &r.caller.did).await?;
    r.finish_read().await?;
    let mut pages = vec![local];
    let mut more = false;
    // The device was verified current above (begin_read).
    for sequencer in &sequencers {
        let forwarded = Forwarded::Read {
            query: query.unwrap_or_default(),
        };
        let bytes = relay.forward(pool, sequencer, op, &adm, forwarded).await?;
        let (ids, has_more) = remote_page(&bytes)?;
        more |= has_more;
        pages.push(ids);
    }
    threads_page(pages, more, page.limit())
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
