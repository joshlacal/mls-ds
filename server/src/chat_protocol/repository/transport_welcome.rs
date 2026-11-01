//! Repository helper for `direct_request_transport_inbox` Welcome dispositions.

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::json;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::welcome_terminal::WelcomeTerminalFacadeError;
use crate::chat_protocol::error::ChatEndpoint;

pub(crate) async fn try_complete_transport_inbox_welcome(
    transaction: &mut Transaction<'_, Postgres>,
    endpoint: ChatEndpoint,
    actor_did: &str,
    actor_device_id: Uuid,
    body: &[u8],
) -> Result<Option<Vec<u8>>, WelcomeTerminalFacadeError> {
    let body_json: Option<serde_json::Value> = serde_json::from_slice(body).ok();
    let signed_req = body_json
        .as_ref()
        .and_then(|v| v.get("signedRequest"))
        .unwrap_or(body_json.as_ref().unwrap_or(&serde_json::Value::Null));
    let welcome_id_str = signed_req
        .pointer("/body/welcomeId")
        .or_else(|| signed_req.pointer("/body/id"))
        .and_then(|v| v.as_str());
    let Some(welcome_str) = welcome_id_str else {
        return Ok(None);
    };
    let Ok(welcome_id) = Uuid::parse_str(welcome_str) else {
        return Ok(None);
    };

    let in_transport_inbox: Option<(String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT status, updated_at FROM chat.direct_request_transport_inbox \
          WHERE request_id = $1 AND recipient_did = $2 AND recipient_device_id = $3 \
          FOR UPDATE",
    )
    .bind(welcome_id)
    .bind(actor_did)
    .bind(actor_device_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|e| {
        WelcomeTerminalFacadeError::Retention(
            super::direct_request_retention::RetentionError::Database(e),
        )
    })?;

    let Some((existing_status, updated_at)) = in_transport_inbox else {
        return Ok(None);
    };

    let now = Utc::now();
    let (target_status, output_dto) = match endpoint {
        ChatEndpoint::AcknowledgeWelcome => {
            let ts = if existing_status == "accepted" {
                updated_at
            } else {
                now
            };
            (
                "accepted",
                json!({
                    "status": "acknowledged",
                    "acknowledgedAt": ts.to_rfc3339_opts(SecondsFormat::Millis, true)
                }),
            )
        }
        ChatEndpoint::RejectWelcome => {
            let ts = if existing_status == "rejected" {
                updated_at
            } else {
                now
            };
            (
                "rejected",
                json!({
                    "status": "rejected",
                    "rejectedAt": ts.to_rfc3339_opts(SecondsFormat::Millis, true)
                }),
            )
        }
        _ => return Err(WelcomeTerminalFacadeError::InvalidRequest),
    };

    if existing_status != target_status {
        sqlx::query(
            "UPDATE chat.direct_request_transport_inbox \
                SET status = $1, updated_at = $2 \
              WHERE request_id = $3 AND recipient_did = $4 AND recipient_device_id = $5",
        )
        .bind(target_status)
        .bind(now)
        .bind(welcome_id)
        .bind(actor_did)
        .bind(actor_device_id)
        .execute(&mut **transaction)
        .await
        .map_err(|e| {
            WelcomeTerminalFacadeError::Retention(
                super::direct_request_retention::RetentionError::Database(e),
            )
        })?;
    }

    let resp_bytes =
        serde_json::to_vec(&output_dto).map_err(|_| WelcomeTerminalFacadeError::InvalidRequest)?;
    Ok(Some(resp_bytes))
}
