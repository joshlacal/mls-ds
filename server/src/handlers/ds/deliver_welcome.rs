use axum::{Json, extract::State};
use serde_json::json;
use std::sync::Arc;
use tracing::debug;
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    crypto::redact_for_log,
    federation::{AckSigner, FederationError},
    storage::DbPool,
};

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeliverWelcome<'a> {
    #[serde(borrow)]
    convo_id: jacquard_common::CowStr<'a>,
    #[serde(borrow)]
    recipient_did: jacquard_common::CowStr<'a>,
    #[serde(borrow)]
    sender_ds_did: jacquard_common::CowStr<'a>,
    #[serde(borrow)]
    key_package_hash: jacquard_common::CowStr<'a>,
    #[serde(with = "jacquard_common::serde_bytes_helper")]
    welcome_data: bytes::Bytes,
    initial_epoch: i64,
}

const NSID: &str = "blue.catbird.mlsDS.deliverWelcome";

/// POST /xrpc/blue.catbird.mlsDS.deliverWelcome
///
/// Accept a Welcome message for a new member from a remote DS.
#[tracing::instrument(skip(pool, ack_signer, auth_user, body))]
pub async fn deliver_welcome(
    State(pool): State<DbPool>,
    State(ack_signer): State<Option<Arc<AckSigner>>>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<serde_json::Value>, FederationError> {
    let welcome: DeliverWelcome<'_> = serde_json::from_str(&body).map_err(|_| {
        FederationError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid DeliverWelcome body",
        )))
    })?;

    let recipient_did = welcome.recipient_did.as_ref();
    let convo_id = welcome.convo_id.as_ref();
    let sender_ds = welcome.sender_ds_did.as_ref();
    let key_package_hash = welcome.key_package_hash.as_ref();
    let initial_epoch = welcome.initial_epoch;

    let security = super::deliver_message::enforce_ds_request_security(
        &pool,
        &auth_user,
        NSID,
        Some(sender_ds),
    )
    .await?;
    let requester_ds = security.requester_ds.clone();

    let result: Result<Json<serde_json::Value>, FederationError> = async {
        // Verify recipient is a local user
        let user_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM users WHERE did = $1) \
             OR EXISTS(SELECT 1 FROM devices WHERE user_did = $1 OR credential_did = $1)",
        )
        .bind(recipient_did)
        .fetch_one(&pool)
        .await
        .map_err(FederationError::Database)?;

        if !user_exists {
            return Err(FederationError::RecipientNotFound {
                did: recipient_did.to_string(),
            });
        }

        let mut sequencer_term: u64 = 0;
        if let Some(sequencer_state) =
            super::deliver_message::load_convo_sequencer_state_optional(&pool, convo_id).await?
        {
            if requester_ds != sequencer_state.expected_sequencer {
                return Err(FederationError::AuthFailed {
                    reason: format!(
                        "DS {} is not the sequencer for {} (expected {})",
                        requester_ds, convo_id, sequencer_state.expected_sequencer
                    ),
                });
            }
            sequencer_term = sequencer_state.current_term;
        }

        // Store the welcome data.
        let welcome_id = Uuid::new_v4().to_string();
        let key_package_hash_bytes = if key_package_hash.is_empty() {
            None
        } else {
            Some(key_package_hash.as_bytes())
        };
        sqlx::query(
            "INSERT INTO welcome_messages \
             (id, convo_id, recipient_did, recipient_device_id, welcome_data, key_package_hash, created_by_did, created_at, consumed) \
             VALUES ($1, $2, $3, NULL, $4, $5, $6, NOW(), false) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&welcome_id)
        .bind(convo_id)
        .bind(recipient_did)
        .bind(welcome.welcome_data.as_ref())
        .bind(key_package_hash_bytes)
        .bind(&requester_ds)
        .execute(&pool)
        .await
        .map_err(FederationError::Database)?;

        debug!(
            convo = %redact_for_log(convo_id),
            recipient = %redact_for_log(recipient_did),
            sender_ds = %redact_for_log(sender_ds),
            "Accepted federated welcome"
        );

        let mut response = json!({ "accepted": true });
        if let Some(ref signer) = ack_signer {
            let ack = signer.sign_ack(&welcome_id, convo_id, initial_epoch as i32, sequencer_term);
            response["ack"] = serde_json::to_value(&ack).unwrap_or_default();
        }

        Ok(Json(response))
    }
    .await;

    super::deliver_message::record_ds_outcome(&pool, &requester_ds, result.is_ok()).await;
    result
}
