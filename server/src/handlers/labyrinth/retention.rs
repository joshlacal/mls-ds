//! Retention endpoints (decisions J1, J2; `crate::labyrinth::repo::retention`):
//! `purgeMailbox`, `deleteAccountData`, `deleteVirtualDevice` and
//! `touchVirtualDevice`. Unsend (`redactMessage`) is a thread endpoint.

use std::sync::Arc;

use axum::{body::Bytes, extract::State, http::HeaderMap, response::Response};
use serde::Deserialize;
use serde_json::json;

use super::params::{admit_procedure, begin_write};
use super::relay_client::{Forwarded, Relay};
use super::respond;
use crate::handlers::chat::ChatRuntime;
use crate::labyrinth::auth;
use crate::labyrinth::relay::RelayOp;
use crate::labyrinth::repo::binding;
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
            let caller = w.caller.clone();
            binding::require_bound(&mut w.tx, &caller, None).await?;
            repo::purge_mailbox(&mut w.tx, &caller.did).await?;
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
            let adm = admit_procedure(&pool, &rt, "deleteVirtualDevice", &headers, &bytes).await?;
            let input: VirtualDeviceIdIn = body(&bytes)?;
            let id = input.vdevice_id.array::<16>("vdeviceId")?;
            let mut w = begin_write!(&pool, adm);
            let caller = w.caller.clone();
            binding::require_bound(&mut w.tx, &caller, None).await?;
            repo::delete_virtual_device(&mut w.tx, &caller.did, &id).await?;
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

/// `deleteAccountData`: first every remote sequencer redacts the DID's
/// items there (`labyrinthRelay purgeAuthor`, the device's own signed write
/// re-verified by each), then the local purge commits. A sequencer that
/// cannot be reached fails the call before anything local changes; a retry
/// replays the sequencers that already finished.
pub async fn delete_account_data(
    State(pool): Pool,
    State(rt): Runtime,
    relay: Relay,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "deleteAccountData", &headers, &bytes).await?;
            let EmptyIn {} = body(&bytes)?;
            let sequencers = {
                let mut conn = pool.acquire().await?;
                let caller =
                    auth::load_current_device(&mut conn, &adm.did, adm.device_id, false).await?;
                binding::require_bound(&mut conn, &caller, None).await?;
                repo::remote_sequencers(&mut conn, &adm.did).await?
            };
            for sequencer in &sequencers {
                let (write_body, write_signature) = auth::write_headers(&headers)?;
                let forwarded = Forwarded::Write {
                    payload: &bytes,
                    write_body,
                    write_signature,
                };
                relay
                    .forward(&pool, sequencer, RelayOp::PurgeAuthor, &adm, forwarded)
                    .await?;
            }
            let mut w = begin_write!(&pool, adm);
            let (caller, at) = (w.caller.clone(), w.instant);
            binding::require_bound(&mut w.tx, &caller, None).await?;
            repo::purge_account(&mut w.tx, &caller.did, at).await?;
            w.finish_write(to_bytes(&json!({}))?).await
        }
        .await,
    )
}
