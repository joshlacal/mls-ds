//! Clean-chat opaque blob custody routes.
//!
//! The route layer only composes the sealed authentication/prelude/repository
//! boundaries. It never accepts an object-store key, trusts a client content
//! length, or falls back to the legacy `blobs` table.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    http::{header::CONTENT_TYPE, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
};
use catbird_atproto::generated::blue_catbird::chat as chat_dto;
use chrono::Duration;
use jacquard_common::{deps::bytes::Bytes as JacquardBytes, deps::smol_str::SmolStr, DefaultStr};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    blob_store::{BlobStore, BlobStoreError},
    chat_protocol::{
        error::{ChatEndpoint, ChatProtocolErrorCode},
        read_authority::OrdinaryReadEndpoint,
        repository::{
            blobs::{self, BlobMediaType, BlobPurpose, BlobRepositoryError, PrepareBlobRequest},
            prelude::{self, PreparedBlobOperation},
        },
        transcript::SignedMutationKind,
        validation::CanonicalHttpMethod,
    },
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

use super::{context, errors::ChatFailure, runtime::ChatRuntime};

const GET_BLOB: ChatEndpoint = ChatEndpoint::GetBlob;
const GET_USAGE: ChatEndpoint = ChatEndpoint::GetBlobUsage;
const PREPARE: ChatEndpoint = ChatEndpoint::PrepareBlobUpload;
const UPLOAD: ChatEndpoint = ChatEndpoint::UploadBlob;
const DELETE: ChatEndpoint = ChatEndpoint::DeleteBlob;

pub(super) async fn get_blob(
    State(pool): State<DbPool>,
    State(blob_store): State<BlobStore>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let result = async {
        let admission = context::admit_unsigned_read(
            &pool,
            &runtime,
            GET_BLOB,
            CanonicalHttpMethod::parse("GET").map_err(|_| ChatFailure::invariant(GET_BLOB))?,
            &headers,
        )
        .await?;
        let blob_id = parse_uuid_query(query.as_deref(), "blobId")
            .ok_or_else(|| ChatFailure::protocol(GET_BLOB, ChatProtocolErrorCode::BlobNotFound))?;
        let actor =
            blobs::read_actor_for_admission(&pool, admission, OrdinaryReadEndpoint::GetBlob)
                .await
                .map_err(|error| map_read_failure(GET_BLOB, error))?;
        let capability = blobs::authorize_blob_fetch_for_actor(&pool, &actor, blob_id)
            .await
            .map_err(|error| map_read_failure(GET_BLOB, error))?;
        let bytes = blob_store
            .get_authorized(&pool, capability)
            .await
            .map_err(|error| map_store_failure(GET_BLOB, error))?;
        let mut response = Response::new(axum::body::Body::from(bytes));
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        Ok::<_, ChatFailure>(response)
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

pub(super) async fn get_blob_usage(
    State(pool): State<DbPool>,
    State(blob_store): State<BlobStore>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
) -> Response {
    let result = async {
        let admission = context::admit_unsigned_read(
            &pool,
            &runtime,
            GET_USAGE,
            CanonicalHttpMethod::parse("GET").map_err(|_| ChatFailure::invariant(GET_USAGE))?,
            &headers,
        )
        .await?;
        let actor =
            blobs::read_actor_for_admission(&pool, admission, OrdinaryReadEndpoint::GetBlobUsage)
                .await
                .map_err(|error| map_read_failure(GET_USAGE, error))?;
        let usage = blobs::read_blob_usage(&pool, &actor)
            .await
            .map_err(|error| map_read_failure(GET_USAGE, error))?;
        let output = chat_dto::get_blob_usage::GetBlobUsageOutput::<DefaultStr> {
            usage: chat_dto::BlobUsageView {
                blob_count: usage.blob_count,
                live_unbound_count: usage.live_unbound_count,
                quota_bytes: blob_store.quota_bytes(),
                reserved_bytes: usage.reserved_bytes,
                used_bytes: usage.used_bytes,
                extra_data: None,
            },
            extra_data: None,
        };
        let bytes = serde_json::to_vec(&output).map_err(|_| ChatFailure::invariant(GET_USAGE))?;
        Ok::<_, ChatFailure>(context::json_ok(bytes))
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

pub(super) async fn prepare_blob_upload(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result = prepare_blob_upload_inner(&pool, &runtime, &headers, &body).await;
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn prepare_blob_upload_inner(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    let admission =
        context::admit_signed_operation_only(pool, runtime, PREPARE, headers, body).await?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(PREPARE))?;
    let prepared = prelude::prepare_blob_operation(
        &mut transaction,
        admission,
        PREPARE.nsid(),
        SignedMutationKind::BlobUploadPreparation,
    )
    .await
    .map_err(|_| ChatFailure::invariant(PREPARE))?;
    let PreparedBlobOperation::First(prepared) = prepared else {
        let PreparedBlobOperation::Replay(response) = prepared else {
            unreachable!()
        };
        transaction
            .commit()
            .await
            .map_err(|_| ChatFailure::storage(PREPARE))?;
        return Ok(context::replay_response(&response));
    };
    let authority = prepared.authority();
    let mutation = authority
        .mutation()
        .ok_or_else(|| ChatFailure::invariant(PREPARE))?;
    let projection = match mutation.projection() {
        crate::chat_protocol::transcript::VerifiedMutationProjection::BlobUploadPreparation(p) => p,
        _ => return Err(ChatFailure::invariant(PREPARE)),
    };
    let blob_id = uuid_from_canonical(projection.blob_id(), PREPARE)?;
    let conversation_id = uuid_from_canonical(projection.conversation_id(), PREPARE)?;
    // Preparation reserves storage only; it does not advance a conversation
    // head. Still bind the signed prior to the explicit conversation id here.
    // The send/bind compositor performs the stronger remaining coordinate/head
    // check when the blob becomes message data.
    if uuid_from_canonical(projection.prior_conversation_id(), PREPARE)? != conversation_id {
        return Err(ChatFailure::protocol(
            PREPARE,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }
    let purpose = parse_purpose(projection.purpose())?;
    let media_type = BlobMediaType::parse(projection.media_type())
        .ok_or_else(|| ChatFailure::protocol(PREPARE, ChatProtocolErrorCode::InvalidRequest))?;
    let hash: [u8; 32] = projection
        .ciphertext_sha256()
        .try_into()
        .map_err(|_| ChatFailure::protocol(PREPARE, ChatProtocolErrorCode::InvalidRequest))?;
    let plaintext_size = i64::try_from(projection.plaintext_size())
        .map_err(|_| ChatFailure::protocol(PREPARE, ChatProtocolErrorCode::InvalidRequest))?;
    let ciphertext_size = i64::try_from(projection.ciphertext_size())
        .map_err(|_| ChatFailure::protocol(PREPARE, ChatProtocolErrorCode::InvalidRequest))?;
    let owner_device_id = uuid_from_canonical(authority.device_id(), PREPARE)?;
    let owner_auth_generation =
        i64::try_from(mutation.auth_generation()).map_err(|_| ChatFailure::invariant(PREPARE))?;
    let ticket = random_ticket();
    let ticket_hash = Sha256::digest(ticket.as_bytes()).to_vec();
    let member: Option<Uuid> = sqlx::query_scalar(
        "SELECT device_id FROM chat.member_devices WHERE conversation_id=$1\
          AND user_did=$2 AND device_id=$3 AND active",
    )
    .bind(conversation_id)
    .bind(authority.subject().as_str())
    .bind(owner_device_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ChatFailure::storage(PREPARE))?;
    if member.is_none() {
        return Err(ChatFailure::protocol(
            PREPARE,
            ChatProtocolErrorCode::NotAuthorized,
        ));
    }
    blobs::prepare_blob(
        &mut transaction,
        &PrepareBlobRequest {
            blob_id,
            owner_did: authority.subject().as_str().to_owned(),
            owner_device_id,
            owner_key_id: mutation.key_id().as_str().to_owned(),
            owner_auth_generation,
            purpose,
            media_type,
            plaintext_size,
            ciphertext_size,
            ciphertext_sha256: hash.to_vec(),
            ticket_hash,
            prepared_at: authority.trusted_instant().datetime(),
        },
    )
    .await
    .map_err(|error| map_prepare_failure(error))?;
    let expires_at = authority.trusted_instant().datetime() + Duration::minutes(5);
    let output = chat_dto::prepare_blob_upload::PrepareBlobUploadOutput::<DefaultStr> {
        upload: chat_dto::BlobUploadView {
            blob_id: SmolStr::from(blob_id.to_string()),
            ciphertext_sha256: JacquardBytes::from(hash.to_vec()),
            ciphertext_size,
            expires_at: chrono_to_datetime(expires_at),
            purpose: SmolStr::from(purpose.as_str()),
            upload_ticket: SmolStr::from(ticket),
            extra_data: None,
        },
        extra_data: None,
    };
    let response_bytes =
        serde_json::to_vec(&output).map_err(|_| ChatFailure::invariant(PREPARE))?;
    let (authority, scope, completion) = prepared.into_execution_parts();
    prelude::complete_operation(
        &mut transaction,
        &authority,
        scope,
        completion,
        200,
        &response_bytes,
        None,
    )
    .await
    .map_err(|_| ChatFailure::invariant(PREPARE))?;
    transaction
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(PREPARE))?;
    Ok(context::json_ok(response_bytes))
}

pub(super) async fn upload_blob(
    State(pool): State<DbPool>,
    State(blob_store): State<BlobStore>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let result = upload_blob_inner(
        &pool,
        &blob_store,
        &runtime,
        &headers,
        query.as_deref(),
        body,
    )
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn upload_blob_inner(
    pool: &DbPool,
    blob_store: &BlobStore,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    query: Option<&str>,
    body: Bytes,
) -> Result<Response, ChatFailure> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if content_type != Some("application/octet-stream") {
        return Err(ChatFailure::protocol(
            UPLOAD,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }
    let ticket = query_param(query, "uploadTicket")
        .filter(|value| (32..=512).contains(&value.len()))
        .ok_or_else(|| ChatFailure::protocol(UPLOAD, ChatProtocolErrorCode::InvalidRequest))?;
    let admission = context::admit_unsigned_read(
        pool,
        runtime,
        UPLOAD,
        CanonicalHttpMethod::parse("POST").map_err(|_| ChatFailure::invariant(UPLOAD))?,
        headers,
    )
    .await?;
    let actor = blobs::read_actor_for_admission(pool, admission, OrdinaryReadEndpoint::UploadBlob)
        .await
        .map_err(|error| map_read_failure(UPLOAD, error))?;
    let ticket_hash: [u8; 32] = Sha256::digest(ticket.as_bytes()).into();
    let material = blobs::load_upload_ticket(pool, &ticket_hash)
        .await
        .map_err(|error| map_upload_failure(error))?;
    if actor.did != material.owner_did || actor.device_id != material.owner_device_id {
        return Err(ChatFailure::protocol(
            UPLOAD,
            ChatProtocolErrorCode::UploadTicketNotFound,
        ));
    }
    if i64::try_from(body.len()).ok() != Some(material.ciphertext_size) {
        return Err(ChatFailure::protocol(
            UPLOAD,
            ChatProtocolErrorCode::BlobSizeMismatch,
        ));
    }
    blob_store
        .put_for_blob(
            material.blob_id,
            body.to_vec(),
            &material.ciphertext_sha256,
            &material.media_type,
        )
        .await
        .map_err(|error| map_store_failure(UPLOAD, error))?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(UPLOAD))?;
    let uploaded_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ChatFailure::storage(UPLOAD))?;
    blobs::complete_upload(
        &mut transaction,
        material.blob_id,
        &material.owner_did,
        material.owner_device_id,
        material.ciphertext_size,
        &ticket_hash,
        uploaded_at,
        &blobs::derive_blob_cid(material.blob_id, &material.ciphertext_sha256),
    )
    .await
    .map_err(|error| map_upload_failure(error))?;
    let output = chat_dto::upload_blob::UploadBlobOutput::<DefaultStr> {
        binding: chat_dto::UploadedBlobBinding {
            blob_id: SmolStr::from(material.blob_id.to_string()),
            ciphertext_sha256: JacquardBytes::from(material.ciphertext_sha256.to_vec()),
            ciphertext_size: material.ciphertext_size,
            purpose: SmolStr::from(material.purpose.as_str()),
            extra_data: None,
        },
        uploaded_at: chrono_to_datetime(uploaded_at),
        extra_data: None,
    };
    let bytes = serde_json::to_vec(&output).map_err(|_| ChatFailure::invariant(UPLOAD))?;
    transaction
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(UPLOAD))?;
    Ok(context::json_ok(bytes))
}

pub(super) async fn delete_blob(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result = delete_blob_inner(&pool, &runtime, &headers, &body).await;
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn delete_blob_inner(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    let admission =
        context::admit_signed_operation_only(pool, runtime, DELETE, headers, body).await?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(DELETE))?;
    let prepared = prelude::prepare_blob_operation(
        &mut transaction,
        admission,
        DELETE.nsid(),
        SignedMutationKind::BlobDeletion,
    )
    .await
    .map_err(|_| ChatFailure::invariant(DELETE))?;
    let PreparedBlobOperation::First(prepared) = prepared else {
        let PreparedBlobOperation::Replay(response) = prepared else {
            unreachable!()
        };
        transaction
            .commit()
            .await
            .map_err(|_| ChatFailure::storage(DELETE))?;
        return Ok(context::replay_response(&response));
    };
    let authority = prepared.authority();
    let mutation = authority
        .mutation()
        .ok_or_else(|| ChatFailure::invariant(DELETE))?;
    let projection = match mutation.projection() {
        crate::chat_protocol::transcript::VerifiedMutationProjection::BlobDeletion(p) => p,
        _ => return Err(ChatFailure::invariant(DELETE)),
    };
    let blob_id = uuid_from_canonical(projection.blob_id(), DELETE)?;
    let owner_device_id = uuid_from_canonical(authority.device_id(), DELETE)?;
    let row: Option<i64> = sqlx::query_scalar(
        "SELECT ciphertext_size FROM chat.blobs WHERE blob_id=$1 AND owner_did=$2 AND owner_device_id=$3",
    )
    .bind(blob_id)
    .bind(authority.subject().as_str())
    .bind(owner_device_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ChatFailure::storage(DELETE))?;
    let ciphertext_size =
        row.ok_or_else(|| ChatFailure::protocol(DELETE, ChatProtocolErrorCode::BlobNotFound))?;
    let deleted_at = authority.trusted_instant().datetime();
    blobs::delete_blob(
        &mut transaction,
        blob_id,
        authority.subject().as_str(),
        owner_device_id,
        ciphertext_size,
        deleted_at,
    )
    .await
    .map_err(|error| map_delete_failure(error))?;
    let output = chat_dto::delete_blob::DeleteBlobOutput::<DefaultStr> {
        blob_id: SmolStr::from(blob_id.to_string()),
        deleted_at: chrono_to_datetime(deleted_at),
        extra_data: None,
    };
    let bytes = serde_json::to_vec(&output).map_err(|_| ChatFailure::invariant(DELETE))?;
    let (authority, scope, completion) = prepared.into_execution_parts();
    prelude::complete_operation(
        &mut transaction,
        &authority,
        scope,
        completion,
        200,
        &bytes,
        None,
    )
    .await
    .map_err(|_| ChatFailure::invariant(DELETE))?;
    transaction
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(DELETE))?;
    Ok(context::json_ok(bytes))
}

fn random_ticket() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn query_param(query: Option<&str>, wanted: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == wanted).then(|| value.to_owned())
    })
}

fn parse_uuid_query(query: Option<&str>, wanted: &str) -> Option<Uuid> {
    let value = query_param(query, wanted)?;
    let uuid = Uuid::parse_str(&value).ok()?;
    (uuid.get_version_num() == 4 && uuid.hyphenated().to_string() == value).then_some(uuid)
}

fn uuid_from_canonical(
    value: &crate::chat_protocol::validation::CanonicalUuidV4,
    endpoint: ChatEndpoint,
) -> Result<Uuid, ChatFailure> {
    Uuid::parse_str(value.as_str()).map_err(|_| ChatFailure::invariant(endpoint))
}

fn parse_purpose(value: &str) -> Result<BlobPurpose, ChatFailure> {
    match value {
        "attachment" => Ok(BlobPurpose::Attachment),
        "metadata" => Ok(BlobPurpose::Metadata),
        _ => Err(ChatFailure::protocol(
            PREPARE,
            ChatProtocolErrorCode::InvalidRequest,
        )),
    }
}

fn map_read_failure(endpoint: ChatEndpoint, error: BlobRepositoryError) -> ChatFailure {
    match error {
        BlobRepositoryError::NotAuthorized
        | BlobRepositoryError::FetchAlreadyConsumed
        | BlobRepositoryError::TransactionBindingMismatch => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized)
        }
        BlobRepositoryError::BlobExpired | BlobRepositoryError::ObjectStoreKeyMissing => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::BlobNotFound)
        }
        BlobRepositoryError::Database(_) | BlobRepositoryError::Commit(_) => {
            ChatFailure::storage(endpoint)
        }
        _ => ChatFailure::invariant(endpoint),
    }
}

fn map_store_failure(endpoint: ChatEndpoint, error: BlobStoreError) -> ChatFailure {
    match error {
        BlobStoreError::NotFound => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::BlobNotFound)
        }
        BlobStoreError::Authorization(error) => map_read_failure(endpoint, error),
        BlobStoreError::S3Error(_) => ChatFailure::storage(endpoint),
        BlobStoreError::TooLarge(_)
        | BlobStoreError::InvalidExpectedSize
        | BlobStoreError::Truncated { .. }
        | BlobStoreError::Oversize { .. }
        | BlobStoreError::HashMismatch
        | BlobStoreError::MetadataMismatch(_) => ChatFailure::invariant(endpoint),
    }
}

fn map_prepare_failure(error: BlobRepositoryError) -> ChatFailure {
    match error {
        BlobRepositoryError::BlobAlreadyExists => {
            ChatFailure::protocol(PREPARE, ChatProtocolErrorCode::BlobAlreadyExists)
        }
        BlobRepositoryError::QuotaExceeded => {
            ChatFailure::protocol(PREPARE, ChatProtocolErrorCode::BlobQuotaExceeded)
        }
        BlobRepositoryError::MediaTypeNotAllowedForPurpose
        | BlobRepositoryError::CiphertextSizeRelation
        | BlobRepositoryError::CiphertextTooLarge
        | BlobRepositoryError::PlaintextSizeInvalid => {
            ChatFailure::protocol(PREPARE, ChatProtocolErrorCode::InvalidRequest)
        }
        BlobRepositoryError::Database(_) => ChatFailure::storage(PREPARE),
        _ => ChatFailure::invariant(PREPARE),
    }
}

fn map_upload_failure(error: BlobRepositoryError) -> ChatFailure {
    match error {
        BlobRepositoryError::UploadTicketExpired => {
            ChatFailure::protocol(UPLOAD, ChatProtocolErrorCode::UploadTicketExpired)
        }
        BlobRepositoryError::UploadTicketNotFound => {
            ChatFailure::protocol(UPLOAD, ChatProtocolErrorCode::UploadTicketNotFound)
        }
        BlobRepositoryError::CompareAndSetConflict => {
            ChatFailure::protocol(UPLOAD, ChatProtocolErrorCode::BlobConflict)
        }
        BlobRepositoryError::Database(_) => ChatFailure::storage(UPLOAD),
        _ => ChatFailure::invariant(UPLOAD),
    }
}

fn map_delete_failure(error: BlobRepositoryError) -> ChatFailure {
    match error {
        BlobRepositoryError::CompareAndSetConflict => {
            ChatFailure::protocol(DELETE, ChatProtocolErrorCode::BlobBound)
        }
        BlobRepositoryError::Database(_) => ChatFailure::storage(DELETE),
        _ => ChatFailure::invariant(DELETE),
    }
}
