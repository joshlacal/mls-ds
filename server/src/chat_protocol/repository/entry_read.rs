//! Repository-owned `getEntries` read composition.

use chrono::{SecondsFormat, Utc};
use serde_json::{json, Map, Value};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::delivery::{self, DeliveredEntryRow, DeliveryRepositoryError};
use crate::chat_protocol::{
    dpop::VerifiedReadAdmission,
    read_authority::{self, EntryReadAuthority, ReadAuthorityError},
};

#[derive(Debug)]
pub(crate) enum EntryReadFacadeError {
    AccessOutsideMembershipInterval,
    ConversationNotFound,
    DeviceRevoked,
    InvalidRequest,
    NotEntitled,
    Storage,
    Invariant,
}

pub(crate) struct CanonicalEntriesResponse {
    response_bytes: Vec<u8>,
}

impl CanonicalEntriesResponse {
    pub(crate) fn into_response_bytes(self) -> Vec<u8> {
        self.response_bytes
    }
}

pub(crate) async fn get_entries_for_admission(
    pool: &sqlx::PgPool,
    admission: VerifiedReadAdmission,
    conversation_id: Uuid,
    after_seq: u64,
    limit: i64,
) -> Result<CanonicalEntriesResponse, EntryReadFacadeError> {
    let admission = read_authority::into_single_read_admission(
        admission,
        read_authority::OrdinaryReadEndpoint::GetEntries,
    )
    .map_err(|_| EntryReadFacadeError::Invariant)?
    .into_attempt();

    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| EntryReadFacadeError::Storage)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .map_err(|_| EntryReadFacadeError::Storage)?;

    let result = read_entries_in_transaction(
        &mut transaction,
        admission,
        conversation_id,
        after_seq,
        limit,
    )
    .await;
    let _ = transaction.rollback().await;
    result
}

async fn read_entries_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    attempt: crate::chat_protocol::dpop::ReadAdmissionAttempt,
    conversation_id: Uuid,
    after_seq: u64,
    limit: i64,
) -> Result<CanonicalEntriesResponse, EntryReadFacadeError> {
    let device = read_authority::lock_read_device_authority_once(transaction, attempt)
        .await
        .map_err(map_authority_error)?;
    let authority = read_authority::authorize_entries(transaction, device, conversation_id)
        .await
        .map_err(map_authority_error)?;
    let page = delivery::get_entries(
        transaction,
        conversation_id,
        authority.conversation().user_did(),
        authority.conversation().device_id(),
        after_seq,
        limit,
    )
    .await
    .map_err(map_delivery_error)?;

    let entries = page
        .entries
        .iter()
        .map(entry_json)
        .collect::<Result<Vec<_>, _>>()?;
    let body = json!({
        "entries": entries,
        "nextAfterSeq": page.next_after_seq,
        "hasMore": page.has_more,
    });
    let response_bytes = serde_json::to_vec(&body).map_err(|_| EntryReadFacadeError::Invariant)?;
    Ok(CanonicalEntriesResponse { response_bytes })
}

fn entry_json(row: &DeliveredEntryRow) -> Result<Value, EntryReadFacadeError> {
    let signed_request: Value = serde_json::from_slice(&row.signed_request_bytes)
        .map_err(|_| EntryReadFacadeError::Invariant)?;
    let mut object = Map::new();
    object.insert("$type".into(), Value::String(row.entry_kind.clone()));
    object.insert(
        "conversationId".into(),
        Value::String(row.conversation_id.hyphenated().to_string()),
    );
    object.insert(
        "entryId".into(),
        Value::String(row.entry_id.hyphenated().to_string()),
    );
    object.insert(
        "receivedAt".into(),
        Value::String(row.received_at.to_rfc3339_opts(SecondsFormat::Millis, true)),
    );
    object.insert("seq".into(), Value::Number(row.seq.into()));
    object.insert("signedRequest".into(), signed_request);
    if row.entry_kind != delivery::APPLICATION_ENTRY_KIND {
        return crate::chat_protocol::transcript::persisted_control_entry_response_json(
            &row.entry_kind,
            &row.entry_id.hyphenated().to_string(),
            &row.conversation_id.hyphenated().to_string(),
            u64::try_from(row.seq).map_err(|_| EntryReadFacadeError::Invariant)?,
            &row.received_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            &row.signed_request_bytes,
            &row.server_fields_bytes,
        )
        .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| EntryReadFacadeError::Invariant))
        .map_err(|_| EntryReadFacadeError::Invariant)?;
    }
    Ok(Value::Object(object))
}

fn map_authority_error(error: ReadAuthorityError) -> EntryReadFacadeError {
    match error {
        ReadAuthorityError::AccessOutsideMembershipInterval => {
            EntryReadFacadeError::AccessOutsideMembershipInterval
        }
        ReadAuthorityError::ConversationNotFound => EntryReadFacadeError::ConversationNotFound,
        ReadAuthorityError::DeviceRevoked => EntryReadFacadeError::DeviceRevoked,
        ReadAuthorityError::NotEntitled => EntryReadFacadeError::NotEntitled,
        ReadAuthorityError::Storage => EntryReadFacadeError::Storage,
        ReadAuthorityError::Invariant => EntryReadFacadeError::Invariant,
    }
}

fn map_delivery_error(error: DeliveryRepositoryError) -> EntryReadFacadeError {
    match error {
        DeliveryRepositoryError::Database(_) => EntryReadFacadeError::Storage,
        DeliveryRepositoryError::SequenceOverflow | DeliveryRepositoryError::EntryKindMismatch => {
            EntryReadFacadeError::Invariant
        }
        _ => EntryReadFacadeError::Invariant,
    }
}
