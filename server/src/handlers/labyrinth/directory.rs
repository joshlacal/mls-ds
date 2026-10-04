//! Directory endpoints (`MailboxDirectory`; the caller is any authenticated
//! chat device).

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
use crate::labyrinth::error::LabyrinthError;
use crate::labyrinth::repo::directory as repo;
use crate::labyrinth::repo::thread::parse_thread_id;
use crate::labyrinth::wire::bytes::{check_did, Bytes as AtBytes, MAX_EPOCH_NUMBER};
use crate::labyrinth::wire::io::{body, datetime, to_bytes, Page, PublishHeadIn, Received};
use crate::labyrinth::wire::records::EpochPublic;
use crate::storage::DbPool;

type Pool = State<DbPool>;
type Runtime = State<Arc<ChatRuntime>>;

pub async fn publish_epoch_head(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "publishEpochHead", &headers, &bytes).await?;
            let input: PublishHeadIn = body(&bytes)?;
            let epoch = Received::<EpochPublic>::parse(&input.epoch, "epoch")?;
            let mut w = begin_write!(&pool, adm);
            repo::record_head(&mut w.tx, &w.caller.did, &epoch.value, w.instant).await?;
            w.finish_write(to_bytes(&json!({}))?).await
        }
        .await,
    )
}

pub async fn get_epoch_head(
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
                "getEpochHead",
                &headers,
                q.as_deref(),
                &["did", "epochNumber"],
            )
            .await?;
            let did = p.req("did")?.to_owned();
            check_did("did", &did)?;
            let n = p.int("epochNumber", MAX_EPOCH_NUMBER)?;
            let mut r = begin_read(&pool, adm).await?;
            let (epoch, received_at) = repo::get_head(&mut r.tx, &did, n)
                .await?
                .ok_or_else(|| LabyrinthError::not_found("EpochNotFound"))?;
            r.finish_read().await?;
            to_bytes(&json!({ "epoch": epoch, "receivedAt": datetime(received_at) }))
        }
        .await,
    )
}

pub async fn get_chat_device_keys(
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
                "getChatDeviceKeys",
                &headers,
                q.as_deref(),
                &["did", "cursor", "limit"],
            )
            .await?;
            let did = p.req("did")?.to_owned();
            check_did("did", &did)?;
            let page = p.page()?;
            let mut r = begin_read(&pool, adm).await?;
            let (rows, cursor) = repo::chat_device_keys(&mut r.tx, &did, &page).await?;
            r.finish_read().await?;
            let items: Vec<_> = rows
                .into_iter()
                .map(|k| {
                    let mut v = json!({
                        "keyId": k.key_id,
                        "signingPublicKey": AtBytes(k.signing_public_key),
                        "createdAt": datetime(k.created_at),
                    });
                    if let Some(at) = k.revoked_at {
                        v["revokedAt"] = json!(datetime(at));
                    }
                    v
                })
                .collect();
            to_bytes(&Page { items, cursor })
        }
        .await,
    )
}

pub async fn get_member_devices(
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
                "getMemberDevices",
                &headers,
                q.as_deref(),
                &["threadId", "did", "cursor", "limit"],
            )
            .await?;
            let thread = parse_thread_id(p.req("threadId")?)?;
            let did = p.req("did")?.to_owned();
            check_did("did", &did)?;
            let page = p.page()?;
            let mut r = begin_read(&pool, adm).await?;
            let caller = r.caller.did.clone();
            let (rows, cursor) =
                repo::member_devices(&mut r.tx, thread, &did, &caller, &page).await?;
            r.finish_read().await?;
            let items: Vec<_> = rows
                .into_iter()
                .map(|m| {
                    let mut v = json!({
                        "keyId": m.key_id,
                        "signingPublicKey": AtBytes(m.signing_public_key),
                        "joinedSeq": m.joined_seq,
                    });
                    if let Some(seq) = m.removed_seq {
                        v["removedSeq"] = json!(seq);
                    }
                    v
                })
                .collect();
            to_bytes(&Page { items, cursor })
        }
        .await,
    )
}
