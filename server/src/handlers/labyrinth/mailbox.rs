//! Mailbox endpoints (`MailboxStore`; the caller is a chat device of the
//! mailbox owner, and every call reads or writes the caller DID's mailbox).

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
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::repo::mailbox as repo;
use crate::labyrinth::wire::bytes::{hex_array, MAX_EPOCH_NUMBER};
use crate::labyrinth::wire::io::{
    body, to_bytes, CreateEpochIn, CreateVirtualDeviceIn, MarkRevokedIn, Received, RecordIn,
};
use crate::labyrinth::wire::records::{Device, Epoch, EpochMember, OwnerBatch, VirtualDevice};
use crate::storage::DbPool;

type Pool = State<DbPool>;
type Runtime = State<Arc<ChatRuntime>>;

pub async fn create_device(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "createDevice", &headers, &bytes).await?;
            let input: RecordIn = body(&bytes)?;
            let rec = Received::<Device>::parse(&input.record, "record")?;
            let mut w = begin_write!(&pool, adm);
            let caller = w.caller.clone();
            let rkey = repo::create_device(&mut w.tx, &caller, &rec, w.instant).await?;
            w.finish_write(to_bytes(&json!({ "rkey": rkey }))?).await
        }
        .await,
    )
}

pub async fn mark_device_revoked(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "markDeviceRevoked", &headers, &bytes).await?;
            let input: MarkRevokedIn = body(&bytes)?;
            let key = input.device_key_pubkey.array::<32>("deviceKeyPubkey")?;
            let mut w = begin_write!(&pool, adm);
            let caller = w.caller.clone();
            repo::mark_device_revoked(&mut w.tx, &caller, &key, &input.revoked_at).await?;
            w.finish_write(to_bytes(&json!({}))?).await
        }
        .await,
    )
}

pub async fn get_device(
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
                "getDevice",
                &headers,
                q.as_deref(),
                &["deviceKeyPubkey"],
            )
            .await?;
            let key = hex_array::<32>("deviceKeyPubkey", p.req("deviceKeyPubkey")?)?;
            let mut r = begin_read(&pool, adm).await?;
            let record = repo::get_device(&mut r.tx, &r.caller.did, &key)
                .await?
                .ok_or_else(|| LabyrinthError::not_found("DeviceNotFound"))?;
            r.finish_read().await?;
            to_bytes(&json!({ "record": record }))
        }
        .await,
    )
}

pub async fn list_devices(
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
                "listDevices",
                &headers,
                q.as_deref(),
                &["cursor", "limit"],
            )
            .await?;
            let page = p.page()?;
            let mut r = begin_read(&pool, adm).await?;
            let (items, cursor) = repo::list_devices(&mut r.tx, &r.caller.did, &page).await?;
            r.finish_read().await?;
            page_bytes(items, cursor)
        }
        .await,
    )
}

fn page_bytes<T: serde::Serialize>(
    items: Vec<T>,
    cursor: Option<String>,
) -> LabyrinthResult<Vec<u8>> {
    to_bytes(&crate::labyrinth::wire::io::Page { items, cursor })
}

pub async fn create_epoch(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "createEpoch", &headers, &bytes).await?;
            let input: CreateEpochIn = body(&bytes)?;
            let epoch = Received::<Epoch>::parse(&input.epoch, "epoch")?;
            let members = input
                .members
                .iter()
                .map(|m| Received::<EpochMember>::parse(m, "members"))
                .collect::<LabyrinthResult<Vec<_>>>()?;
            let mut w = begin_write!(&pool, adm);
            let caller = w.caller.clone();
            let (epoch_id, n) =
                repo::create_epoch(&mut w.tx, &caller, &epoch, &members, w.instant).await?;
            let out = json!({ "epochId": epoch_id.to_string(), "epochNumber": n });
            w.finish_write(to_bytes(&out)?).await
        }
        .await,
    )
}

pub async fn get_epoch(
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
                "getEpoch",
                &headers,
                q.as_deref(),
                &["epochNumber"],
            )
            .await?;
            let n = p
                .int("epochNumber", MAX_EPOCH_NUMBER)?
                .ok_or_else(|| LabyrinthError::invalid("missing parameter epochNumber"))?;
            let mut r = begin_read(&pool, adm).await?;
            let (epoch_id, record) = repo::get_epoch(&mut r.tx, &r.caller.did, n)
                .await?
                .ok_or_else(|| LabyrinthError::not_found("EpochNotFound"))?;
            r.finish_read().await?;
            to_bytes(&json!({ "epochId": epoch_id, "record": record }))
        }
        .await,
    )
}

pub async fn list_epochs(
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
                "listEpochs",
                &headers,
                q.as_deref(),
                &["cursor", "limit"],
            )
            .await?;
            let page = p.page()?;
            let mut r = begin_read(&pool, adm).await?;
            let (items, cursor) = repo::list_epochs(&mut r.tx, &r.caller.did, &page).await?;
            r.finish_read().await?;
            let items: Vec<_> = items
                .into_iter()
                .map(|(epoch_id, record)| json!({ "epochId": epoch_id, "record": record }))
                .collect();
            page_bytes(items, cursor)
        }
        .await,
    )
}

pub async fn create_epoch_member(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "createEpochMember", &headers, &bytes).await?;
            let input: RecordIn = body(&bytes)?;
            let rec = Received::<EpochMember>::parse(&input.record, "record")?;
            let mut w = begin_write!(&pool, adm);
            let caller = w.caller.clone();
            repo::create_epoch_member(&mut w.tx, &caller, &rec, w.instant).await?;
            w.finish_write(to_bytes(&json!({}))?).await
        }
        .await,
    )
}

pub async fn list_epoch_members(
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
                "listEpochMembers",
                &headers,
                q.as_deref(),
                &["epochNumber", "cursor", "limit"],
            )
            .await?;
            let n = p
                .int("epochNumber", MAX_EPOCH_NUMBER)?
                .ok_or_else(|| LabyrinthError::invalid("missing parameter epochNumber"))?;
            let page = p.page()?;
            let mut r = begin_read(&pool, adm).await?;
            let (items, cursor) =
                repo::list_epoch_members(&mut r.tx, &r.caller.did, n, &page).await?;
            r.finish_read().await?;
            page_bytes(items, cursor)
        }
        .await,
    )
}

pub async fn create_virtual_device(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "createVirtualDevice", &headers, &bytes).await?;
            let input: CreateVirtualDeviceIn = body(&bytes)?;
            let rec = Received::<VirtualDevice>::parse(&input.record, "record")?;
            let member = input
                .member
                .as_deref()
                .map(|m| Received::<EpochMember>::parse(m, "member"))
                .transpose()?;
            let orf = input
                .orf
                .as_ref()
                .map(|o| -> LabyrinthResult<_> {
                    Ok((
                        o.device_key_pubkey.array::<32>("orf.deviceKeyPubkey")?,
                        o.evolve_token.array::<32>("orf.evolveToken")?,
                    ))
                })
                .transpose()?;
            let mut w = begin_write!(&pool, adm);
            let caller = w.caller.clone();
            repo::create_virtual_device(&mut w.tx, &caller, &rec, member.as_ref(), orf, w.instant)
                .await?;
            w.finish_write(to_bytes(&json!({}))?).await
        }
        .await,
    )
}

pub async fn get_virtual_device(
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
                "getVirtualDevice",
                &headers,
                q.as_deref(),
                &["vdeviceId"],
            )
            .await?;
            let id = hex_array::<16>("vdeviceId", p.req("vdeviceId")?)?;
            let mut r = begin_read(&pool, adm).await?;
            let record = repo::get_virtual_device(&mut r.tx, &r.caller.did, &id, r.instant)
                .await?
                .ok_or_else(|| LabyrinthError::not_found("VirtualDeviceNotFound"))?;
            r.finish_read().await?;
            to_bytes(&json!({ "record": record }))
        }
        .await,
    )
}

pub async fn list_virtual_devices(
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
                "listVirtualDevices",
                &headers,
                q.as_deref(),
                &["cursor", "limit"],
            )
            .await?;
            let page = p.page()?;
            let mut r = begin_read(&pool, adm).await?;
            let (items, cursor) =
                repo::list_virtual_devices(&mut r.tx, &r.caller.did, &page).await?;
            r.finish_read().await?;
            page_bytes(items, cursor)
        }
        .await,
    )
}

pub async fn append_owner_batch(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "appendOwnerBatch", &headers, &bytes).await?;
            let input: RecordIn = body(&bytes)?;
            let rec = Received::<OwnerBatch>::parse(&input.record, "record")?;
            let mut w = begin_write!(&pool, adm);
            let caller = w.caller.clone();
            let (rkey, order) =
                repo::append_owner_batch(&mut w.tx, &caller, &rec, w.instant).await?;
            w.finish_write(to_bytes(&json!({ "rkey": rkey, "order": order }))?)
                .await
        }
        .await,
    )
}

pub async fn list_owner_batches(
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
                "listOwnerBatches",
                &headers,
                q.as_deref(),
                &[
                    "threadId", "fromMs", "untilMs", "since", "until", "reverse", "cursor", "limit",
                ],
            )
            .await?;
            let thread_id = p.req("threadId")?.to_owned();
            crate::labyrinth::wire::bytes::check_str("threadId", &thread_id, 256)?;
            let (range, page) = (p.range()?, p.page()?);
            let mut r = begin_read(&pool, adm).await?;
            let (rows, cursor) =
                repo::list_owner_batches(&mut r.tx, &r.caller.did, &thread_id, range, &page)
                    .await?;
            r.finish_read().await?;
            let items: Vec<_> = rows
                .into_iter()
                .map(|b| json!({ "rkey": b.rkey, "record": b.record, "order": b.order }))
                .collect();
            page_bytes(items, cursor)
        }
        .await,
    )
}
