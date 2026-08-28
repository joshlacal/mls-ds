// Repository-owned `getEntries` read composition.

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
    .map_err(|e| {
        tracing::error!("into_single_read_admission failed: {:?}", e);
        EntryReadFacadeError::Invariant
    })?
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
        .map_err(|e| {
            tracing::error!("lock_read_device_authority_once failed: {:?}", e);
            map_authority_error(e)
        })?;
    let authority = read_authority::authorize_entries(transaction, device, conversation_id)
        .await
        .map_err(|e| {
            tracing::error!("authorize_entries failed: {:?}", e);
            map_authority_error(e)
        })?;
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
    tracing::error!("get_entries map_authority_error: {:?}", error);
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
    tracing::error!("get_entries map_delivery_error: {:?}", error);
    match error {
        DeliveryRepositoryError::SequenceOverflow | DeliveryRepositoryError::EntryKindMismatch => {
            EntryReadFacadeError::Invariant
        }
        _ => EntryReadFacadeError::Invariant,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    #[test]
    fn entry_json_control_entry_projects_type_and_entry_id_without_transposition() {
        let conversation_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let body = json!({
            "$type": "blue.catbird.chat.defs#leaveCancellationBody",
            "signatureDomain": "CATBIRD-CHAT-LEAVE-CANCEL\0",
            "conversationId": conversation_id.hyphenated().to_string(),
            "leaveRequestId": Uuid::new_v4().hyphenated().to_string(),
            "actorDid": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
            "actorDeviceId": Uuid::new_v4().hyphenated().to_string(),
            "keyId": crate::chat_protocol::validation::ed25519_key_id(&signing_key.verifying_key().to_bytes()).unwrap().as_str(),
            "authGeneration": 1,
            "idempotencyKey": Uuid::new_v4().hyphenated().to_string(),
            "signedAt": "2026-08-20T12:00:00.000Z",
        });
        let mut wrapper = json!({
            "body": body,
            "signature": STANDARD.encode([0u8; 64]),
        });
        let unsigned = serde_json::to_vec(&wrapper).unwrap();
        let canonical =
            crate::chat_protocol::transcript::decode_canonical_signed_mutation(&unsigned).unwrap();
        let signature = signing_key.sign(canonical.transcript_bytes()).to_bytes();
        wrapper["signature"] = json!(STANDARD.encode(signature));
        let signed_request_bytes = serde_json::to_vec(&wrapper).unwrap();
        let row = DeliveredEntryRow {
            conversation_id,
            seq: 2,
            entry_id,
            entry_kind: "blue.catbird.chat.defs#leaveCancellationEntry".to_string(),
            signed_request_bytes,
            request_digest: Sha256::digest(canonical.transcript_bytes()).to_vec(),
            signature: signature.to_vec(),
            server_fields_bytes: vec![0xA0],
            outer_entry_fingerprint: vec![0x11; 32],
            received_at: "2026-08-20T12:00:01.000Z".parse().unwrap(),
        };

        let json = entry_json(&row).expect("entry_json projects valid control entry");
        assert_eq!(
            json["$type"].as_str(),
            Some("blue.catbird.chat.defs#leaveCancellationEntry"),
            "$type must match row.entry_kind"
        );
        assert_eq!(
            json["entryId"].as_str(),
            Some(entry_id.hyphenated().to_string().as_str()),
            "entryId must match row.entry_id"
        );
        assert_eq!(
            json["conversationId"].as_str(),
            Some(conversation_id.hyphenated().to_string().as_str()),
            "conversationId must match row.conversation_id"
        );
        assert_eq!(json["seq"].as_u64(), Some(2));
    }
}
