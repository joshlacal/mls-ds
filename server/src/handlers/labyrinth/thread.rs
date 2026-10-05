//! Thread endpoints (`ThreadStore`; `threadId` is the chat conversation id).

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    http::HeaderMap,
    response::Response,
};
use serde_json::json;

use super::params::{admit_procedure, admit_query, begin_write};
use super::respond;
use crate::handlers::chat::ChatRuntime;
use crate::labyrinth::auth::begin_read;
use crate::labyrinth::repo::retention::{self, RedactionIn};
use crate::labyrinth::repo::thread::{self as repo, parse_thread_id, AuthoredRow};
use crate::labyrinth::wire::bytes::{check_did, hex_array};
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

pub async fn create_mek(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "createMek", &headers, &bytes).await?;
            let input: RecordIn = body(&bytes)?;
            let rec = Received::<Mek>::parse(&input.record, "record")?;
            let mut w = begin_write!(&pool, adm);
            let caller = w.caller.clone();
            let (rkey, order) = repo::create_mek(&mut w.tx, &caller, &rec, w.instant).await?;
            w.finish_write(to_bytes(&json!({ "rkey": rkey, "order": order }))?)
                .await
        }
        .await,
    )
}

pub async fn find_meks(
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
                "findMeks",
                &headers,
                q.as_deref(),
                &["threadId", "mekId", "cursor", "limit"],
            )
            .await?;
            let thread = parse_thread_id(p.req("threadId")?)?;
            let mek_id = hex_array::<12>("mekId", p.req("mekId")?)?;
            let page = p.page()?;
            let mut r = begin_read(&pool, adm).await?;
            let (rows, cursor) =
                repo::find_meks(&mut r.tx, &r.caller.did, thread, &mek_id, &page).await?;
            r.finish_read().await?;
            to_bytes(&Page {
                items: authored(rows),
                cursor,
            })
        }
        .await,
    )
}

pub async fn append_batch(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "appendBatch", &headers, &bytes).await?;
            let input: RecordIn = body(&bytes)?;
            let rec = Received::<Batch>::parse(&input.record, "record")?;
            let mut w = begin_write!(&pool, adm);
            let caller = w.caller.clone();
            let (rkey, order) = repo::append_batch(&mut w.tx, &caller, &rec, w.instant).await?;
            w.finish_write(to_bytes(&json!({ "rkey": rkey, "order": order }))?)
                .await
        }
        .await,
    )
}

pub async fn list_batches(
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
                "listBatches",
                &headers,
                q.as_deref(),
                &["threadId", "sender", "fromMs", "untilMs", "cursor", "limit"],
            )
            .await?;
            let thread = parse_thread_id(p.req("threadId")?)?;
            let sender = p.opt("sender").map(str::to_owned);
            if let Some(s) = &sender {
                check_did("sender", s)?;
            }
            let (range, page) = (p.range()?, p.page()?);
            let mut r = begin_read(&pool, adm).await?;
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
        .await,
    )
}

/// `redactMessage` input.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RedactMessageIn {
    thread_id: String,
    message_id: String,
    redaction: RedactionIn,
}

pub async fn redact_message(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "redactMessage", &headers, &bytes).await?;
            let input: RedactMessageIn = body(&bytes)?;
            let mut w = begin_write!(&pool, adm);
            let (caller, at) = (w.caller.clone(), w.instant);
            let redacted = retention::redact_message(
                &mut w.tx,
                &caller,
                &input.thread_id,
                &input.message_id,
                &input.redaction,
                at,
            )
            .await?;
            w.finish_write(to_bytes(&json!({ "redacted": redacted }))?)
                .await
        }
        .await,
    )
}
