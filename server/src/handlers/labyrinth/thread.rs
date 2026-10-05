//! Thread endpoints (`ThreadStore`; `threadId` is the chat conversation id).
//!
//! Each endpoint admits the device, then either runs locally ([`exec_write`]
//! / [`exec_read`]) or, when the conversation is sequenced by another DS,
//! forwards it there through `labyrinthRelay` (design Y3). The sequencer
//! runs the same `exec_*` code for a relayed request.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    http::HeaderMap,
    response::Response,
};
use serde_json::json;
use uuid::Uuid;

use super::params::{admit_procedure, admit_query, begin_write, Params};
use super::relay_client::{remote_sequencer, Forwarded, Relay};
use super::respond;
use crate::handlers::chat::ChatRuntime;
use crate::labyrinth::auth::{self, begin_read, Admission};
use crate::labyrinth::error::LabyrinthResult;
use crate::labyrinth::relay::RelayOp;
use crate::labyrinth::repo::lookup;
use crate::labyrinth::repo::retention::{self, RedactionIn};
use crate::labyrinth::repo::thread::{self as repo, parse_thread_id, AuthoredRow};
use crate::labyrinth::wire::bytes::{check_did, check_str, hex_array};
use crate::labyrinth::wire::io::{body, to_bytes, Page, Received, RecordIn};
use crate::labyrinth::wire::records::{Batch, Mek};
use crate::storage::DbPool;

type Pool = State<DbPool>;
type Runtime = State<Arc<ChatRuntime>>;

fn authored(rows: Vec<AuthoredRow>) -> Vec<serde_json::Value> {
    rows.into_iter()
        .map(
            |r| json!({ "author": r.author, "rkey": r.rkey, "record": r.record, "order": r.order }),
        )
        .collect()
}

/// `redactMessage` input.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RedactMessageIn {
    thread_id: String,
    message_id: String,
    redaction: RedactionIn,
}

/// Query parameters each read accepts (besides `actorDeviceId`).
pub(super) fn read_params(op: RelayOp) -> &'static [&'static str] {
    match op {
        RelayOp::FindMeks => &["threadId", "mekId", "cursor", "limit"],
        RelayOp::ListBatches => &[
            "threadId", "sender", "fromMs", "untilMs", "since", "until", "reverse", "cursor",
            "limit",
        ],
        RelayOp::GetMessages => &["threadId", "messageIds", "cursor", "limit"],
        RelayOp::ListThreads => &["cursor", "limit"],
        RelayOp::MessageLive => &["threadId", "messageId"],
        _ => &[],
    }
}

/// The conversation a write names, when its payload names one at all (an
/// unparsable payload is left to the endpoint's own validation).
pub(super) fn write_thread(op: RelayOp, payload: &[u8]) -> Option<Uuid> {
    let value: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let thread = match op {
        RelayOp::CreateMek | RelayOp::AppendBatch => value.get("record")?.get("threadId")?,
        RelayOp::RedactMessage => value.get("threadId")?,
        _ => return None,
    };
    parse_thread_id(thread.as_str()?).ok()
}

/// Run a thread write on this DS (the conversation's sequencer).
pub(super) async fn exec_write(
    pool: &DbPool,
    op: RelayOp,
    adm: Admission,
    bytes: &[u8],
    home_ds: Option<&str>,
) -> LabyrinthResult<Vec<u8>> {
    let mut w = begin_write!(pool, adm);
    let (caller, at) = (w.caller.clone(), w.instant);
    let response = match op {
        RelayOp::CreateMek => {
            let input: RecordIn = body(bytes)?;
            let rec = Received::<Mek>::parse(&input.record, "record")?;
            let (rkey, order) = repo::create_mek(&mut w.tx, &caller, &rec, at).await?;
            json!({ "rkey": rkey, "order": order })
        }
        RelayOp::AppendBatch => {
            let input: RecordIn = body(bytes)?;
            let rec = Received::<Batch>::parse(&input.record, "record")?;
            let (rkey, order) = repo::append_batch(&mut w.tx, &caller, &rec, at).await?;
            json!({ "rkey": rkey, "order": order })
        }
        RelayOp::RedactMessage => {
            let input: RedactMessageIn = body(bytes)?;
            let redacted = retention::redact_message(
                &mut w.tx,
                &caller,
                &input.thread_id,
                &input.message_id,
                &input.redaction,
                at,
            )
            .await?;
            json!({ "redacted": redacted })
        }
        RelayOp::PurgeAuthor => {
            let home = home_ds.ok_or_else(crate::labyrinth::error::LabyrinthError::internal)?;
            retention::redact_author(&mut w.tx, &caller.did, Some(home), at).await?;
            json!({})
        }
        RelayOp::FindMeks
        | RelayOp::ListBatches
        | RelayOp::GetMessages
        | RelayOp::ListThreads
        | RelayOp::MessageLive => return Err(crate::labyrinth::error::LabyrinthError::internal()),
    };
    w.finish_write(to_bytes(&response)?).await
}

/// Run a thread read on this DS. `home_ds` is the requesting DS of a
/// relayed `listThreads` (see `lookup::list_threads`).
pub(super) async fn exec_read(
    pool: &DbPool,
    op: RelayOp,
    adm: Admission,
    query: Option<&str>,
    home_ds: Option<&str>,
) -> LabyrinthResult<Vec<u8>> {
    let p = Params::parse(query, read_params(op))?;
    if op == RelayOp::ListThreads {
        let page = p.page()?;
        let mut r = begin_read(pool, adm).await?;
        let ids = lookup::list_threads(
            &mut r.tx,
            &r.caller.did,
            lookup::thread_cursor(&page)?,
            home_ds,
            page.limit() + 1,
        )
        .await?;
        r.finish_read().await?;
        return super::lookup::threads_page(vec![ids], false, page.limit());
    }
    let thread = parse_thread_id(p.req("threadId")?)?;
    match op {
        RelayOp::FindMeks => {
            let mek_id = hex_array::<12>("mekId", p.req("mekId")?)?;
            let page = p.page()?;
            let mut r = begin_read(pool, adm).await?;
            let (rows, cursor) =
                repo::find_meks(&mut r.tx, &r.caller.did, thread, &mek_id, &page).await?;
            r.finish_read().await?;
            to_bytes(&Page {
                items: authored(rows),
                cursor,
            })
        }
        RelayOp::ListBatches => {
            let sender = p.opt("sender").map(str::to_owned);
            if let Some(s) = &sender {
                check_did("sender", s)?;
            }
            let (range, page) = (p.range()?, p.page()?);
            let mut r = begin_read(pool, adm).await?;
            let (rows, cursor) = repo::list_batches(
                &mut r.tx,
                &r.caller.did,
                thread,
                sender.as_deref(),
                range,
                &page,
            )
            .await?;
            r.finish_read().await?;
            to_bytes(&Page {
                items: authored(rows),
                cursor,
            })
        }
        RelayOp::GetMessages => {
            let ids = super::lookup::message_ids(&p)?;
            let page = p.page()?;
            let mut r = begin_read(pool, adm).await?;
            let (rows, cursor) =
                lookup::get_messages(&mut r.tx, &r.caller.did, thread, ids, &page).await?;
            r.finish_read().await?;
            to_bytes(&Page {
                items: authored(rows),
                cursor,
            })
        }
        RelayOp::MessageLive => {
            let message_id = p.req("messageId")?;
            check_str("messageId", message_id, 128)?;
            let mut r = begin_read(pool, adm).await?;
            let live: bool = sqlx::query_scalar("SELECT labyrinth.message_live_for($1, $2, $3)")
                .bind(&r.caller.did)
                .bind(thread)
                .bind(message_id)
                .fetch_one(&mut *r.tx)
                .await?;
            r.finish_read().await?;
            to_bytes(&json!({ "live": live }))
        }
        _ => Err(crate::labyrinth::error::LabyrinthError::internal()),
    }
}

async fn write(
    pool: &DbPool,
    rt: &ChatRuntime,
    relay: &Relay,
    op: RelayOp,
    headers: &HeaderMap,
    bytes: &[u8],
) -> LabyrinthResult<Vec<u8>> {
    let adm = admit_procedure(pool, rt, op.name(), headers, bytes).await?;
    if let Some(thread) = write_thread(op, bytes) {
        if let Some(sequencer) = remote_sequencer(pool, thread).await? {
            let (write_body, write_signature) = auth::write_headers(headers)?;
            let forwarded = Forwarded::Write {
                payload: bytes,
                write_body,
                write_signature,
            };
            return relay.forward(pool, &sequencer, op, &adm, forwarded).await;
        }
    }
    exec_write(pool, op, adm, bytes, None).await
}

pub(super) async fn read(
    pool: &DbPool,
    rt: &ChatRuntime,
    relay: &Relay,
    op: RelayOp,
    headers: &HeaderMap,
    query: Option<&str>,
) -> LabyrinthResult<Vec<u8>> {
    let (adm, p) = admit_query(pool, rt, op.name(), headers, query, read_params(op)).await?;
    let thread = parse_thread_id(p.req("threadId")?)?;
    if let Some(sequencer) = remote_sequencer(pool, thread).await? {
        // The home DS vouches for its device: it must be current here.
        let mut conn = pool.acquire().await?;
        auth::load_current_device(&mut conn, &adm.did, adm.device_id, false).await?;
        drop(conn);
        let forwarded = Forwarded::Read {
            query: query.unwrap_or_default(),
        };
        return relay.forward(pool, &sequencer, op, &adm, forwarded).await;
    }
    exec_read(pool, op, adm, query, None).await
}

pub async fn create_mek(
    State(pool): Pool,
    State(rt): Runtime,
    relay: Relay,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(write(&pool, &rt, &relay, RelayOp::CreateMek, &headers, &bytes).await)
}

pub async fn append_batch(
    State(pool): Pool,
    State(rt): Runtime,
    relay: Relay,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(write(&pool, &rt, &relay, RelayOp::AppendBatch, &headers, &bytes).await)
}

pub async fn redact_message(
    State(pool): Pool,
    State(rt): Runtime,
    relay: Relay,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(write(&pool, &rt, &relay, RelayOp::RedactMessage, &headers, &bytes).await)
}

pub async fn find_meks(
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
            RelayOp::FindMeks,
            &headers,
            q.as_deref(),
        )
        .await,
    )
}

pub async fn list_batches(
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
            RelayOp::ListBatches,
            &headers,
            q.as_deref(),
        )
        .await,
    )
}
