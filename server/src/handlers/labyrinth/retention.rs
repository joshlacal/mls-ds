//! Retention endpoints (`purgeMailbox`, `deleteAccountData`).

use std::sync::Arc;

use axum::{body::Bytes, extract::State, http::HeaderMap, response::Response};
use serde::Deserialize;
use serde_json::json;

use super::params::{admit_procedure, begin_write};
use super::respond;
use crate::handlers::chat::ChatRuntime;
use crate::labyrinth::repo::retention as repo;
use crate::labyrinth::wire::io::{body, to_bytes};
use crate::storage::DbPool;

type Pool = State<DbPool>;
type Runtime = State<Arc<ChatRuntime>>;

/// An input object with no fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyIn {}

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
            repo::purge_mailbox(&mut w.tx, &caller.did).await?;
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
            let (caller, at) = (w.caller.clone(), w.instant);
            let sequenced = repo::purge_account(&mut w.tx, &caller.did, at).await?;
            let resp = w.finish_write(to_bytes(&json!({}))?).await?;
            if sequenced > 0 {
                rt.notify_events();
            }
            Ok(resp)
        }
        .await,
    )
}
