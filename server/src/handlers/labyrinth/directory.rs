//! Directory endpoints (`publishEpochHead`, `getEpochHead`, `getChatDeviceKeys`, `getMemberDevices`).

use std::sync::Arc;

use axum::{
    body::{Body, Bytes},
    extract::{RawQuery, State},
    http::{header::CONTENT_TYPE, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;

use super::params::{
    admit_fixed_query_allowing_pending, admit_procedure_allowing_pending, admit_query,
    admit_query_allowing_pending, begin_write_allowing_pending,
};
use super::respond;
use crate::federation::space_read_relay::{relay_mailbox_keys_record, SpaceRelayError};
use crate::handlers::chat::ChatRuntime;
use crate::labyrinth::auth::{begin_read, begin_read_allowing_pending, Admission};
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::repo::{directory as repo, parse_thread_id};
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
            let adm =
                admit_procedure_allowing_pending(&pool, &rt, "publishEpochHead", &headers, &bytes)
                    .await?;
            let input: PublishHeadIn = body(&bytes)?;
            let epoch = Received::<EpochPublic>::parse(&input.epoch, "epoch")?;
            let mut w = begin_write_allowing_pending!(&pool, adm);
            let caller = w.caller.clone();
            repo::record_head(&mut w.tx, &caller, &epoch.value, w.instant).await?;
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
            let (adm, p) = admit_query_allowing_pending(
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
            if adm.caller_status == "pending_approval" && did != adm.did {
                return Err(LabyrinthError::not_authorized("device is pending approval"));
            }
            let n = p.int("epochNumber", MAX_EPOCH_NUMBER)?;
            if let Some(bytes) = crate::federation::group_relay::try_relay_labyrinth_directory(
                &pool,
                rt.resolver().map(Arc::as_ref),
                &adm,
                &did,
                "blue.catbird.labyrinth.getEpochHead",
                q.as_deref(),
            )
            .await?
            {
                return Ok(bytes);
            }
            epoch_response_with_pending(&pool, adm, &did, n, true).await
        }
        .await,
    )
}

pub async fn get_mailbox_keys_record(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
) -> Response {
    let result: LabyrinthResult<Bytes> = async {
        let (admission, params) = admit_fixed_query_allowing_pending(
            &pool,
            &rt,
            "getMailboxKeysRecord",
            &headers,
            q.as_deref(),
            &["did", "rkey"],
        )
        .await?;
        let did = params.req("did")?;
        check_did("did", did)?;
        if admission.caller_status == "pending_approval" && did != admission.did {
            return Err(LabyrinthError::not_authorized("device is pending approval"));
        }
        let rkey = params.req("rkey")?;
        let resolver = rt
            .resolver()
            .map(Arc::as_ref)
            .ok_or_else(LabyrinthError::relay_unavailable)?;
        relay_mailbox_keys_record(resolver, did, rkey)
            .await
            .map_err(mailbox_relay_error)?
            .ok_or_else(|| LabyrinthError::not_found("RecordNotFound"))
    }
    .await;
    match result {
        Ok(bytes) => {
            let mut response = Response::new(Body::from(bytes));
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            response
        }
        Err(error) => error.into_response(),
    }
}

fn mailbox_relay_error(error: SpaceRelayError) -> LabyrinthError {
    match error {
        SpaceRelayError::InvalidRequest(message) => LabyrinthError::invalid(message),
        SpaceRelayError::UpstreamUnavailable(_) => LabyrinthError::relay_unavailable(),
        SpaceRelayError::InvalidNsid(_)
        | SpaceRelayError::InvalidTargetEndpoint(_)
        | SpaceRelayError::InvalidDelegationToken(_)
        | SpaceRelayError::Forbidden(_)
        | SpaceRelayError::UpstreamError(_)
        | SpaceRelayError::DeviceRevoked(_) => LabyrinthError::new(
            StatusCode::BAD_GATEWAY,
            "UpstreamError",
            "the target PDS returned an invalid mailboxKeys record",
        ),
    }
}

pub async fn get_chat_device_keys(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
) -> Response {
    respond(
        async {
            let (adm, p) = admit_query_allowing_pending(
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
            if adm.caller_status == "pending_approval" && did != adm.did {
                return Err(LabyrinthError::not_authorized("device is pending approval"));
            }
            let page = p.page()?;
            if let Some(bytes) = crate::federation::group_relay::try_relay_labyrinth_directory(
                &pool,
                rt.resolver().map(Arc::as_ref),
                &adm,
                &did,
                "blue.catbird.labyrinth.getChatDeviceKeys",
                q.as_deref(),
            )
            .await?
            {
                return Ok(bytes);
            }
            keys_response_with_pending(&pool, adm, &did, &page, true).await
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
            if let Some(bytes) = crate::federation::group_relay::try_relay_labyrinth_member_devices(
                &pool,
                rt.resolver().map(Arc::as_ref),
                &adm,
                thread,
                &did,
                q.as_deref(),
            )
            .await?
            {
                return Ok(bytes);
            }
            member_devices_response(&pool, adm, thread, &did, &page).await
        }
        .await,
    )
}

async fn epoch_response(
    pool: &DbPool,
    admission: Admission,
    did: &str,
    epoch_number: Option<u64>,
) -> LabyrinthResult<Vec<u8>> {
    epoch_response_with_pending(pool, admission, did, epoch_number, false).await
}

async fn epoch_response_with_pending(
    pool: &DbPool,
    admission: Admission,
    did: &str,
    epoch_number: Option<u64>,
    allow_pending: bool,
) -> LabyrinthResult<Vec<u8>> {
    let mut read = if allow_pending {
        begin_read_allowing_pending(pool, admission).await?
    } else {
        begin_read(pool, admission).await?
    };
    let lookup = repo::get_head(&mut read.tx, did, epoch_number)
        .await?
        .ok_or_else(|| LabyrinthError::not_found("EpochNotFound"))?;
    read.finish_read().await?;
    to_bytes(&json!({
        "epoch": lookup.epoch,
        "chain": lookup.chain,
        "floorSeq": lookup.floor_seq,
        "receivedAt": datetime(lookup.received_at),
    }))
}

async fn keys_response(
    pool: &DbPool,
    admission: Admission,
    did: &str,
    page: &crate::labyrinth::repo::PageReq,
) -> LabyrinthResult<Vec<u8>> {
    keys_response_with_pending(pool, admission, did, page, false).await
}

async fn keys_response_with_pending(
    pool: &DbPool,
    admission: Admission,
    did: &str,
    page: &crate::labyrinth::repo::PageReq,
    allow_pending: bool,
) -> LabyrinthResult<Vec<u8>> {
    let mut read = if allow_pending {
        begin_read_allowing_pending(pool, admission).await?
    } else {
        begin_read(pool, admission).await?
    };
    let (rows, cursor) = repo::chat_device_keys(&mut read.tx, did, page).await?;
    read.finish_read().await?;
    let items: Vec<_> = rows
        .into_iter()
        .map(|key| {
            let mut item = json!({
                "keyId": key.key_id,
                "signingPublicKey": AtBytes(key.signing_public_key),
                "createdAt": datetime(key.created_at),
            });
            if let Some(revoked_at) = key.revoked_at {
                item["revokedAt"] = json!(datetime(revoked_at));
            }
            item
        })
        .collect();
    to_bytes(&Page { items, cursor })
}

async fn member_devices_response(
    pool: &DbPool,
    admission: Admission,
    thread: uuid::Uuid,
    did: &str,
    page: &crate::labyrinth::repo::PageReq,
) -> LabyrinthResult<Vec<u8>> {
    let mut read = begin_read(pool, admission).await?;
    let caller = read.caller.did.clone();
    let (rows, cursor) = repo::member_devices(&mut read.tx, thread, did, &caller, page).await?;
    read.finish_read().await?;
    let items: Vec<_> = rows
        .into_iter()
        .map(|member| {
            let mut item = json!({
                "keyId": member.key_id,
                "signingPublicKey": AtBytes(member.signing_public_key),
                "joinedSeq": member.joined_seq,
            });
            if let Some(seq) = member.removed_seq {
                item["removedSeq"] = json!(seq);
            }
            item
        })
        .collect();
    to_bytes(&Page { items, cursor })
}

pub(crate) async fn read_federated_directory(
    pool: &DbPool,
    endpoint: &str,
    query: &str,
    actor: &str,
    device: uuid::Uuid,
    proof: crate::labyrinth::read_auth::ReadProof,
) -> LabyrinthResult<Vec<u8>> {
    let allowed: &[&str] = match endpoint {
        "blue.catbird.labyrinth.getEpochHead" => &["did", "epochNumber"],
        "blue.catbird.labyrinth.getChatDeviceKeys" => &["did", "cursor", "limit"],
        "blue.catbird.labyrinth.getMemberDevices" => &["threadId", "did", "cursor", "limit"],
        _ => return Err(LabyrinthError::invalid("unsupported directory endpoint")),
    };
    let params = super::params::Params::parse(Some(query), allowed)?;
    let did = params.req("did")?;
    check_did("did", did)?;
    if crate::labyrinth::auth::actor_device_from_query(Some(query))? != device {
        return Err(LabyrinthError::invalid(
            "actorDeviceId does not match the relay",
        ));
    }
    let canonical = crate::labyrinth::read_auth::canonical_query(Some(query));
    let (admission, _) = crate::labyrinth::auth::relayed_read(
        pool,
        proof,
        crate::labyrinth::read_auth::Expected {
            did: actor,
            nsid: endpoint,
            query: Some(&canonical),
        },
        &device.to_string(),
    )
    .await?;
    match endpoint {
        "blue.catbird.labyrinth.getEpochHead" => {
            epoch_response(
                pool,
                admission,
                did,
                params.int("epochNumber", MAX_EPOCH_NUMBER)?,
            )
            .await
        }
        "blue.catbird.labyrinth.getChatDeviceKeys" => {
            keys_response(pool, admission, did, &params.page()?).await
        }
        "blue.catbird.labyrinth.getMemberDevices" => {
            member_devices_response(
                pool,
                admission,
                parse_thread_id(params.req("threadId")?)?,
                did,
                &params.page()?,
            )
            .await
        }
        _ => unreachable!("endpoint was matched above"),
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn federated_directory_rejects_procedures_before_touching_storage() {
        let pool = crate::storage::DbPool::connect_lazy("postgres://127.0.0.1/unused").unwrap();
        let result = super::read_federated_directory(
            &pool,
            "blue.catbird.labyrinth.purgeMailbox",
            "",
            "did:web:actor.catbird.blue",
            uuid::Uuid::new_v4(),
            crate::labyrinth::read_auth::ReadProof {
                header: String::new(),
                signature: String::new(),
            },
        )
        .await;
        assert_eq!(result.unwrap_err().name(), "InvalidRequest");
    }
}
