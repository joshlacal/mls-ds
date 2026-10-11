//! Retention endpoints (decisions J1, J2; `crate::labyrinth::repo::retention`):
//! `purgeMailbox`, `deleteAccountData`, `deleteVirtualDevice` and
//! `touchVirtualDevice`. Unsend (`redactMessage`) is a thread endpoint.
//! Every destructive endpoint requires a bound Labyrinth device (finding 6),
//! except that an account whose mailbox lives in its PDS Space has none
//! here: any of its chat devices may purge what this DS holds for it (its
//! head chain, ORF states and authored thread items). A chat device could
//! reach the same result by enrolling a device first.

use std::sync::Arc;

use axum::{body::Bytes, extract::State, http::HeaderMap, response::Response};
use serde::Deserialize;
use serde_json::json;

use super::params::{admit_procedure, begin_write};
use super::respond;
use crate::handlers::chat::ChatRuntime;
use crate::labyrinth::auth;
use crate::labyrinth::relay::{RelayOp, RelayRequest};
use crate::labyrinth::repo::outbox;
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
            if binding::hosts_mailbox(&mut w.tx, &caller.did).await? {
                binding::require_bound(&mut w.tx, &caller, None).await?;
            }
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

/// `deleteAccountData` (finding 4): the local purge and redaction commit
/// first, in one transaction that also enqueues a durable `purgeAuthor` job
/// for every remote sequencer of a conversation the account takes or took
/// part in (departed ones included: they still hold its authored items).
/// The outbox worker delivers those jobs with retries, so an unreachable DS
/// neither blocks the deletion nor loses its remote part.
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
            let (write_body, write_signature) = auth::write_headers(&headers)?;
            let mut w = begin_write!(&pool, adm);
            let (caller, at) = (w.caller.clone(), w.instant);
            if binding::hosts_mailbox(&mut w.tx, &caller.did).await? {
                binding::require_bound(&mut w.tx, &caller, None).await?;
            }
            repo::purge_account(&mut w.tx, &caller.did, at).await?;
            let request = RelayRequest {
                op: RelayOp::PurgeAuthor.name().to_owned(),
                actor_did: caller.did.clone(),
                actor_device_id: Some(caller.device_id.hyphenated().to_string()),
                query: None,
                payload: Some(AtBytes(bytes.to_vec())),
                write_body: Some(write_body),
                write_signature: Some(write_signature),
                read_header: None,
                read_signature: None,
            };
            for sequencer in repo::remote_sequencers(&mut w.tx, &caller.did).await? {
                outbox::enqueue(&mut w.tx, &sequencer, &request, at).await?;
            }
            w.finish_write(to_bytes(&json!({}))?).await
        }
        .await,
    )
}
