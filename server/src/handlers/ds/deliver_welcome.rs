use axum::{extract::State, Json};
use serde_json::json;
use std::sync::Arc;
use tracing::debug;
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    federation::{AckSigner, FederationError},
    identity::canonical_did,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mls.ds.deliverWelcome";

/// POST /xrpc/blue.catbird.mls.ds.deliverWelcome
///
/// Accept a Welcome message for a new member from a remote DS.
#[tracing::instrument(skip(pool, ack_signer, auth_user, body))]
pub async fn deliver_welcome(
    State(pool): State<DbPool>,
    State(ack_signer): State<Option<Arc<AckSigner>>>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<serde_json::Value>, FederationError> {
    let welcome = crate::jacquard_json::from_json_body::<
        crate::generated::blue_catbird::mls::ds::deliver_welcome::DeliverWelcome<'_>,
    >(&body)
    .map_err(|_| {
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

        // If conversation already exists locally, enforce sequencer binding.
        let sequencer_ds = sqlx::query_scalar::<_, Option<String>>(
            "SELECT sequencer_ds FROM conversations WHERE id = $1",
        )
        .bind(convo_id)
        .fetch_optional(&pool)
        .await
        .map_err(FederationError::Database)?;
        if let Some(seq) = sequencer_ds {
            let self_did = std::env::var("SERVICE_DID")
                .unwrap_or_else(|_| "did:web:mls.catbird.blue".to_string());
            let expected_sequencer = canonical_did(&seq.unwrap_or(self_did)).to_string();
            if requester_ds != expected_sequencer {
                return Err(FederationError::AuthFailed {
                    reason: format!(
                        "DS {} is not the sequencer for {} (expected {})",
                        requester_ds, convo_id, expected_sequencer
                    ),
                });
            }
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
             (id, convo_id, recipient_did, welcome_data, key_package_hash, created_by_did, created_at, consumed) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), false) \
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
            convo_id,
            recipient_did, sender_ds, "Accepted federated welcome"
        );

        let mut response = json!({ "accepted": true });
        if let Some(ref signer) = ack_signer {
            let ack = signer.sign_ack(&welcome_id, convo_id, initial_epoch as i32);
            response["ack"] = serde_json::to_value(&ack).unwrap_or_default();
        }

        Ok(Json(response))
    }
    .await;

    super::deliver_message::record_ds_outcome(&pool, &requester_ds, result.is_ok()).await;
    result
}
