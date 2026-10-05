//! Retention endpoints (decisions J1, J2; `crate::labyrinth::repo::retention`):
//! `purgeMailbox`, `deleteAccountData`, `deleteVirtualDevice` and
//! `touchVirtualDevice`. Unsend (`redactMessage`) is a thread endpoint.

use std::sync::Arc;

use axum::{body::Bytes, extract::State, http::HeaderMap, response::Response};
use serde::Deserialize;
use serde_json::json;

use super::params::{admit_procedure, begin_write};
use super::respond;
use crate::handlers::chat::ChatRuntime;
use crate::labyrinth::repo::retention as repo;
use crate::labyrinth::wire::bytes::Bytes as AtBytes;
use crate::labyrinth::wire::io::{body, to_bytes};
use crate::storage::DbPool;

type Pool = State<DbPool>;
type Runtime = State<Arc<ChatRuntime>>;

/// An input object with no fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyIn {}

/// `{vdeviceId}`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VirtualDeviceIdIn {
    vdevice_id: AtBytes,
}

pub async fn purge_mailbox(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "purgeMailbox", &headers, &bytes).await?;
            let EmptyIn {} = body(&bytes)?;
            let mut w = begin_write!(&pool, adm);
            let did = w.caller.did.clone();
            repo::purge_mailbox(&mut w.tx, &did).await?;
            w.finish_write(to_bytes(&json!({}))?).await
        }
        .await,
    )
}

pub async fn delete_virtual_device(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm =
                admit_procedure(&pool, &rt, "deleteVirtualDevice", &headers, &bytes).await?;
            let input: VirtualDeviceIdIn = body(&bytes)?;
            let id = input.vdevice_id.array::<16>("vdeviceId")?;
            let mut w = begin_write!(&pool, adm);
            let did = w.caller.did.clone();
            repo::delete_virtual_device(&mut w.tx, &did, &id).await?;
            w.finish_write(to_bytes(&json!({}))?).await
        }
        .await,
    )
}

pub async fn touch_virtual_device(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "touchVirtualDevice", &headers, &bytes).await?;
            let input: VirtualDeviceIdIn = body(&bytes)?;
            let id = input.vdevice_id.array::<16>("vdeviceId")?;
            let mut w = begin_write!(&pool, adm);
            let (did, at) = (w.caller.did.clone(), w.instant);
            repo::touch_virtual_device(&mut w.tx, &did, &id, at).await?;
            w.finish_write(to_bytes(&json!({}))?).await
        }
        .await,
    )
}

pub async fn delete_account_data(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "deleteAccountData", &headers, &bytes).await?;
            let EmptyIn {} = body(&bytes)?;
            let mut w = begin_write!(&pool, adm);
            let (did, at) = (w.caller.did.clone(), w.instant);
            if !repo::remote_sequencers(&mut w.tx, &did).await?.is_empty() {
                // Thread records on other sequencers are purged through the
                // relay (labyrinthRelay purgeAuthor).
                return Err(crate::labyrinth::error::LabyrinthError::relay_unavailable());
            }
            repo::purge_account(&mut w.tx, &did, at).await?;
            w.finish_write(to_bytes(&json!({}))?).await
        }
        .await,
    )
}
