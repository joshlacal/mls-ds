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
use super::respond;
use crate::blob_store::BlobStore;
use crate::handlers::chat::ChatRuntime;
use crate::labyrinth::auth::begin_read;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::repo::orf::{self as repo, NewAttachmentRef};
use crate::labyrinth::wire::bytes::{hex_array, Bytes as AtBytes};
use crate::labyrinth::wire::io::{body, to_bytes, DeviceKeyIn, PutAttachmentRefIn, RegisterOrfIn};
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
            repo::delete(&mut w.tx, &w.caller.did, &key).await?;
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
            let new = NewAttachmentRef {
                device_key: input.device_key_pubkey.array::<32>("deviceKeyPubkey")?,
                blinded_index: input.blinded_index.array::<32>("blindedIndex")?,
                blinded_token: input.blinded_token.array::<32>("blindedToken")?,
                conversation_id: input.conversation_id,
                blob_id: input.blob_id,
                message_id: input.message_id,
            };
            let mut w = begin_write!(&pool, adm);
            repo::put_attachment_ref(&mut w.tx, &w.caller.did, &new, w.instant).await?;
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
            let found = repo::get_attachment_ref(&mut r.tx, &r.caller.did, &key, index).await?;
            r.finish_read().await?;
            to_bytes(&json!({
                "conversationId": found.conversation_id.to_string(),
                "blobId": found.blob_id.to_string(),
                "messageId": found.message_id,
                "tokenMac": AtBytes::from_slice(&found.token_mac),
            }))
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
            &["deviceKeyPubkey", "blindedIndex", "blindedToken"],
        )
        .await?;
        let (key, index) = key_and_index(&p)?;
        let token = hex_array::<32>("blindedToken", p.req("blindedToken")?)?;
        let mut r = begin_read(&pool, adm).await?;
        let object =
            repo::authorize_attachment_blob(&mut r.tx, &r.caller.did, &key, index, token).await?;
        r.finish_read().await?;
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
