use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::{auth::AuthUser, federation::FederationError, storage::DbPool};

use super::get_convo_digest::authorize_convo_read;

const NSID: &str = "blue.catbird.mlsDS.getConvoEvents";
const DEFAULT_LIMIT: i64 = 200;
const MAX_LIMIT: i64 = 1000;

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetConvoEventsParams {
    pub convo_id: String,
    pub after_seq: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConvoEventEntry {
    pub seq: i64,
    pub epoch: i64,
    pub msg_id: String,
    pub message_type: String,
    #[serde(with = "crate::atproto_bytes")]
    pub ciphertext: Vec<u8>,
    pub padded_size: i64,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_kind: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::atproto_bytes::option"
    )]
    pub accepted_payload_sha256: Option<Vec<u8>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::atproto_bytes::option"
    )]
    pub signed_request: Option<Vec<u8>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::atproto_bytes::option"
    )]
    pub outer_fingerprint: Option<Vec<u8>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::atproto_bytes::option"
    )]
    pub sequencer_receipt: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_deleted_entry: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetConvoEventsOutput {
    pub convo_id: String,
    pub from_seq_exclusive: i64,
    pub to_seq_inclusive: i64,
    pub events: Vec<ConvoEventEntry>,
}

#[derive(Debug, sqlx::FromRow)]
struct CleanEventRow {
    seq: i64,
    epoch: i64,
    entry_id: uuid::Uuid,
    message_id: Option<uuid::Uuid>,
    entry_kind: String,
    accepted_payload_bytes: Vec<u8>,
    accepted_payload_sha256: Vec<u8>,
    signed_request_bytes: Vec<u8>,
    outer_entry_fingerprint: Vec<u8>,
    sequencer_receipt_bytes: Option<Vec<u8>>,
    server_fields_bytes: Vec<u8>,
    received_at: DateTime<Utc>,
}

/// GET /xrpc/blue.catbird.mlsDS.getConvoEvents
#[tracing::instrument(skip(pool, auth_user, query))]
pub async fn get_convo_events(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    axum::extract::Query(query): axum::extract::Query<GetConvoEventsParams>,
) -> Result<Json<GetConvoEventsOutput>, FederationError> {
    let security =
        super::deliver_message::enforce_ds_request_security(&pool, &auth_user, NSID, None).await?;
    let requester_ds = security.requester_ds.clone();

    let result: Result<Json<GetConvoEventsOutput>, FederationError> = async {
        let state = authorize_convo_read(&pool, &query.convo_id, &requester_ds).await?;
        let from_seq = query.after_seq.unwrap_or(0).max(0);
        let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

        let convo_uuid = uuid::Uuid::parse_str(&query.convo_id).map_err(|_| {
            FederationError::ConversationNotFound {
                convo_id: query.convo_id.clone(),
            }
        })?;

        let rows: Vec<CleanEventRow> = sqlx::query_as::<_, CleanEventRow>(
            "SELECT \
               CAST(seq AS BIGINT) AS seq, \
               CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
               entry_id, \
               message_id, \
               entry_kind, \
               COALESCE(accepted_payload_bytes, ''::bytea) AS accepted_payload_bytes, \
               accepted_payload_sha256, \
               COALESCE(signed_request_bytes, ''::bytea) AS signed_request_bytes, \
               outer_entry_fingerprint, \
               sequencer_receipt_bytes, \
               server_fields_bytes, \
               received_at \
             FROM chat.entries \
             WHERE conversation_id = $1 AND seq > $2 \
             ORDER BY seq ASC \
             LIMIT $3",
        )
        .bind(convo_uuid)
        .bind(from_seq)
        .bind(limit)
        .fetch_all(&pool)
        .await
        .map_err(FederationError::Database)?;

        let events: Vec<ConvoEventEntry> = rows
            .into_iter()
            .map(|row| {
                let account_deleted_entry = if row.entry_kind
                    == crate::chat_protocol::transcript::ACCOUNT_DELETED_ENTRY_TYPE_ID
                {
                    Some(
                        serde_ipld_dagcbor::from_slice::<
                            crate::chat_protocol::repository::entry_read::AccountDeletedServerFields,
                        >(&row.server_fields_bytes)
                        .map_err(|_| {
                            FederationError::Invariant(format!(
                                "account-deletion entry {} at seq {} has invalid authority fields",
                                row.entry_id, row.seq
                            ))
                        })?
                        .entry(convo_uuid, row.seq, row.entry_id, row.received_at),
                    )
                } else {
                    None
                };
                let sequencer_receipt = match (
                    account_deleted_entry.is_some(),
                    row.sequencer_receipt_bytes,
                ) {
                    (true, None) => None,
                    (false, Some(receipt)) => Some(receipt),
                    (true, Some(_)) => {
                        return Err(FederationError::Invariant(format!(
                            "account-deletion entry {} at seq {} unexpectedly has a sequencer receipt",
                            row.entry_id, row.seq
                        )));
                    }
                    (false, None) => {
                        return Err(FederationError::Invariant(format!(
                            "clean entry {} at seq {} has no sequencer receipt",
                            row.entry_id, row.seq
                        )));
                    }
                };
                let msg_id = row
                    .message_id
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| row.entry_id.to_string());
                let padded_size = row.accepted_payload_bytes.len() as i64;
                Ok(ConvoEventEntry {
                    seq: row.seq,
                    epoch: row.epoch,
                    msg_id,
                    message_type: row.entry_kind.clone(),
                    ciphertext: row.accepted_payload_bytes,
                    padded_size,
                    created_at: row.received_at,
                    entry_id: Some(row.entry_id.to_string()),
                    entry_kind: Some(row.entry_kind),
                    accepted_payload_sha256: Some(row.accepted_payload_sha256),
                    signed_request: Some(row.signed_request_bytes),
                    outer_fingerprint: Some(row.outer_entry_fingerprint),
                    sequencer_receipt,
                    account_deleted_entry,
                })
            })
            .collect::<Result<_, FederationError>>()?;
        let to_seq_inclusive = events.last().map(|event| event.seq).unwrap_or(from_seq);
        Ok(Json(GetConvoEventsOutput {
            convo_id: state.convo_id,
            from_seq_exclusive: from_seq,
            to_seq_inclusive,
            events,
        }))
    }
    .await;

    super::deliver_message::record_ds_outcome(&pool, &requester_ds, &result).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    #[test]
    fn clean_event_serialization_emits_all_six_fields_with_atproto_bytes() {
        let entry = ConvoEventEntry {
            seq: 1,
            epoch: 0,
            msg_id: "00000000-0000-0000-0000-000000000001".to_string(),
            message_type: "blue.catbird.chat.defs#creationEntry".to_string(),
            ciphertext: vec![1, 2, 3, 4],
            padded_size: 4,
            created_at: Utc.timestamp_opt(1700000000, 0).unwrap(),
            entry_id: Some("00000000-0000-0000-0000-000000000001".to_string()),
            entry_kind: Some("blue.catbird.chat.defs#creationEntry".to_string()),
            accepted_payload_sha256: Some(vec![5; 32]),
            signed_request: Some(vec![6; 20]),
            outer_fingerprint: Some(vec![7; 32]),
            sequencer_receipt: Some(br#"{"seq":1}"#.to_vec()),
            account_deleted_entry: None,
        };

        let serialized = serde_json::to_value(&entry).expect("must serialize");
        let obj = serialized.as_object().expect("must be object");

        assert_eq!(obj.get("seq"), Some(&json!(1)));
        assert_eq!(obj.get("epoch"), Some(&json!(0)));
        assert_eq!(
            obj.get("entryId"),
            Some(&json!("00000000-0000-0000-0000-000000000001"))
        );
        assert_eq!(
            obj.get("entryKind"),
            Some(&json!("blue.catbird.chat.defs#creationEntry"))
        );

        for field in [
            "ciphertext",
            "acceptedPayloadSha256",
            "signedRequest",
            "outerFingerprint",
            "sequencerReceipt",
        ] {
            assert!(
                obj[field].get("$bytes").is_some(),
                "{field} must use an ATProto byte object"
            );
        }
    }

    #[test]
    fn clean_event_round_trip_preserves_separately_stored_receipt_bytes() {
        let wire = json!({
            "seq": 1,
            "epoch": 0,
            "msgId": "00000000-0000-0000-0000-000000000001",
            "messageType": "blue.catbird.chat.defs#creationEntry",
            "ciphertext": {"$bytes": "AQIDBA=="},
            "paddedSize": 4,
            "createdAt": "2023-11-14T22:13:20Z",
            "entryId": "00000000-0000-0000-0000-000000000001",
            "entryKind": "blue.catbird.chat.defs#creationEntry",
            "acceptedPayloadSha256": {"$bytes": "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU="},
            "signedRequest": {"$bytes": "BgYGBgYGBgYGBgYGBgYGBgYGBgY="},
            "outerFingerprint": {"$bytes": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="},
            "sequencerReceipt": {"$bytes": "eyJzZXEiOjF9"},
        });

        let entry: ConvoEventEntry =
            serde_json::from_value(wire.clone()).expect("event wire shape");
        let serialized = serde_json::to_value(entry).expect("event serialization");
        assert_eq!(
            serialized["sequencerReceipt"], wire["sequencerReceipt"],
            "the separately stored I13 receipt must survive getConvoEvents"
        );
    }

    #[test]
    fn legacy_event_serialization_omits_all_six_clean_fields() {
        let entry = ConvoEventEntry {
            seq: 2,
            epoch: 1,
            msg_id: "legacy-msg-1".to_string(),
            message_type: "app".to_string(),
            ciphertext: vec![9, 8, 7],
            padded_size: 3,
            created_at: Utc.timestamp_opt(1700000000, 0).unwrap(),
            entry_id: None,
            entry_kind: None,
            accepted_payload_sha256: None,
            signed_request: None,
            outer_fingerprint: None,
            sequencer_receipt: None,
            account_deleted_entry: None,
        };

        let serialized = serde_json::to_value(&entry).expect("must serialize");
        let obj = serialized.as_object().expect("must be object");

        assert_eq!(obj.get("seq"), Some(&json!(2)));
        assert_eq!(obj.get("epoch"), Some(&json!(1)));
        for field in [
            "entryId",
            "entryKind",
            "acceptedPayloadSha256",
            "signedRequest",
            "outerFingerprint",
            "sequencerReceipt",
        ] {
            assert!(obj.get(field).is_none(), "{field} must be omitted");
        }

        let deserialized: ConvoEventEntry =
            serde_json::from_value(serialized).expect("must deserialize");
        assert_eq!(deserialized.seq, 2);
        assert_eq!(
            (
                deserialized.entry_id,
                deserialized.entry_kind,
                deserialized.accepted_payload_sha256,
                deserialized.signed_request,
                deserialized.outer_fingerprint,
                deserialized.sequencer_receipt,
            ),
            (None, None, None, None, None, None)
        );
    }
}
