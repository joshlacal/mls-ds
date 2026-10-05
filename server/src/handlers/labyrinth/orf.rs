//! ORF and attachment endpoints (SPEC §8, [CB-17]). mls-ds applies
//! `orf_server_map` itself with the caller device's state; there is no raw
//! map oracle.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    http::{header::CONTENT_TYPE, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::params::{admit_procedure, admit_query, begin_write, Params};
use super::relay_client::{Forwarded, Relay};
use super::respond;
use crate::blob_store::BlobStore;
use crate::handlers::chat::ChatRuntime;
use crate::labyrinth::auth::begin_read;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::relay::RelayOp;
use crate::labyrinth::repo::attachments::{self, Blinded, MessageRef};
use crate::labyrinth::repo::liveness;
use crate::labyrinth::repo::binding;
use crate::labyrinth::repo::orf as repo;
use crate::labyrinth::wire::bytes::hex_array;
use crate::labyrinth::wire::io::{
    body, datetime, to_bytes, AttachmentIndexIn, DeviceKeyIn, PutAttachmentRefIn, RegisterOrfIn,
};
use crate::storage::DbPool;

type Pool = State<DbPool>;
type Runtime = State<Arc<ChatRuntime>>;

pub async fn register_orf_state(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "registerOrfState", &headers, &bytes).await?;
            let input: RegisterOrfIn = body(&bytes)?;
            let key = input.device_key_pubkey.array::<32>("deviceKeyPubkey")?;
            let parent = input
                .parent
                .as_ref()
                .map(|p| -> LabyrinthResult<_> {
                    Ok((
                        p.device_key_pubkey.array::<32>("parent.deviceKeyPubkey")?,
                        p.evolve_token.array::<32>("parent.evolveToken")?,
                    ))
                })
                .transpose()?;
            let mut w = begin_write!(&pool, adm);
            repo::register(&mut w.tx, &w.caller.did, &key, parent, w.instant).await?;
            w.finish_write(to_bytes(&json!({}))?).await
        }
        .await,
    )
}

pub async fn delete_orf_state(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "deleteOrfState", &headers, &bytes).await?;
            let input: DeviceKeyIn = body(&bytes)?;
            let key = input.device_key_pubkey.array::<32>("deviceKeyPubkey")?;
            let mut w = begin_write!(&pool, adm);
            let caller = w.caller.clone();
            binding::require_bound(&mut w.tx, &caller, None).await?;
            repo::delete(&mut w.tx, &caller.did, &key).await?;
            w.finish_write(to_bytes(&json!({}))?).await
        }
        .await,
    )
}

pub async fn put_attachment_ref(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "putAttachmentRef", &headers, &bytes).await?;
            let input: PutAttachmentRefIn = body(&bytes)?;
            let blinded = Blinded {
                device_key: input.device_key_pubkey.array::<32>("deviceKeyPubkey")?,
                index: input.blinded_index.array::<32>("blindedIndex")?,
                token_salt: input.blinded_token_salt.array::<32>("blindedTokenSalt")?,
            };
            let msg = MessageRef {
                thread_id: input.thread_id,
                message_id: input.message_id,
            };
            let mut w = begin_write!(&pool, adm);
            let caller = w.caller.clone();
            attachments::put(
                &mut w.tx,
                &caller,
                &blinded,
                &msg,
                &input.blob_id,
                w.instant,
            )
            .await?;
            w.finish_write(to_bytes(&json!({}))?).await
        }
        .await,
    )
}

pub async fn delete_attachment_ref(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "deleteAttachmentRef", &headers, &bytes).await?;
            let input: AttachmentIndexIn = body(&bytes)?;
            let key = input.device_key_pubkey.array::<32>("deviceKeyPubkey")?;
            let index = input.blinded_index.array::<32>("blindedIndex")?;
            let mut w = begin_write!(&pool, adm);
            let caller = w.caller.clone();
            attachments::delete(&mut w.tx, &caller, &key, index).await?;
            w.finish_write(to_bytes(&json!({}))?).await
        }
        .await,
    )
}

fn key_and_index(p: &Params) -> LabyrinthResult<([u8; 32], [u8; 32])> {
    Ok((
        hex_array::<32>("deviceKeyPubkey", p.req("deviceKeyPubkey")?)?,
        hex_array::<32>("blindedIndex", p.req("blindedIndex")?)?,
    ))
}

pub async fn get_attachment_ref(
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
                "getAttachmentRef",
                &headers,
                q.as_deref(),
                &["deviceKeyPubkey", "blindedIndex"],
            )
            .await?;
            let (key, index) = key_and_index(&p)?;
            let mut r = begin_read(&pool, adm).await?;
            let caller = r.caller.clone();
            let at = attachments::created_at(&mut r.tx, &caller, &key, index).await?;
            r.finish_read().await?;
            to_bytes(&json!({ "createdAt": datetime(at) }))
        }
        .await,
    )
}

/// The attachment bytes for a device that holds the reference's token. This
/// is how a restored device, which has no `chat.application_intervals` row
/// at the attachment's entry, reads it (design §2).
pub async fn get_attachment_blob(
    State(pool): Pool,
    State(rt): Runtime,
    State(store): State<BlobStore>,
    relay: Relay,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
) -> Response {
    let result: LabyrinthResult<Vec<u8>> = async {
        let (adm, p) = admit_query(
            &pool,
            &rt,
            "getAttachmentBlob",
            &headers,
            q.as_deref(),
            &[
                "deviceKeyPubkey",
                "blindedIndex",
                "blindedTokenSalt",
                "threadId",
                "messageId",
            ],
        )
        .await?;
        let (key, index) = key_and_index(&p)?;
        let blinded = Blinded {
            device_key: key,
            index,
            token_salt: hex_array::<32>("blindedTokenSalt", p.req("blindedTokenSalt")?)?,
        };
        let msg = MessageRef {
            thread_id: p.req("threadId")?.to_owned(),
            message_id: p.req("messageId")?.to_owned(),
        };
        let mut r = begin_read(&pool, adm.clone()).await?;
        let caller = r.caller.clone();
        let object = attachments::authorize(&mut r.tx, &caller, &blinded, &msg).await?;
        r.finish_read().await?;
        if let Some(check) = &object.pending_remote {
            // Another author's message lives on the sequencer; even the
            // author's own archive copy only counts if it was not unsent.
            let query = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("threadId", &msg.thread_id)
                .append_pair("messageId", &msg.message_id)
                .append_pair("author", &check.author)
                .finish();
            let reply = relay
                .forward(
                    &pool,
                    &check.sequencer,
                    RelayOp::MessageLive,
                    &adm,
                    Forwarded::Read { query: &query },
                )
                .await?;
            let state = serde_json::from_slice::<serde_json::Value>(&reply).ok();
            let flag = |k: &str| state.as_ref().and_then(|v| v[k].as_bool());
            let (Some(live), Some(redacted)) = (flag("live"), flag("redacted")) else {
                return Err(LabyrinthError::relay_unavailable());
            };
            if !liveness::decide(live, redacted, check.own_copy) {
                return Err(LabyrinthError::not_found("NotFound"));
            }
        }
        let data = store
            .get_committed(&object.object_store_key)
            .await
            .map_err(|_| LabyrinthError::not_found("NotFound"))?;
        let digest: [u8; 32] = Sha256::digest(&data).into();
        if data.len() as i64 != object.ciphertext_size
            || digest.as_slice() != object.ciphertext_sha256.as_slice()
        {
            tracing::error!("labyrinth attachment object does not match its blob commitment");
            return Err(LabyrinthError::internal());
        }
        Ok(data)
    }
    .await;
    match result {
        Ok(data) => {
            let mut response = Response::new(axum::body::Body::from(data));
            response.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            response
        }
        Err(error) => error.into_response(),
    }
}
