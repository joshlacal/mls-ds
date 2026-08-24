use std::str::FromStr;
use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use catbird_atproto::generated::blue_catbird::mlsDS::deliver_welcome::DeliverWelcome;
use jacquard_common::DefaultStr;
use tracing::debug;
use uuid::Uuid;

use super::deliver_message::{enforce_ds_request_security, record_ds_outcome};
use crate::auth::AuthUser;
use crate::chat_protocol::repository::federation::deliver_welcome_mailbox;
use crate::chat_protocol::validation::CanonicalUuidV4;
use crate::federation::envelope::{
    validate_entry_locator, validate_envelope_header, DELIVER_WELCOME_NSID,
};
use crate::federation::{AckSigner, FederationError};
use crate::identity::{dids_equivalent, service_did_base};
use crate::storage::DbPool;

/// POST /xrpc/blue.catbird.mlsDS.deliverWelcome
///
/// Deliver a federated MLS Welcome message to complete local preprovisioned participant addition (Choice C).
#[tracing::instrument(skip(pool, ack_signer, auth_user, body))]
pub async fn deliver_welcome(
    State(pool): State<DbPool>,
    State(ack_signer): State<Option<Arc<AckSigner>>>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<serde_json::Value>, FederationError> {
    let Some(signer) = ack_signer.as_deref() else {
        return Err(FederationError::SignerUnavailable);
    };

    let msg: DeliverWelcome<DefaultStr> = serde_json::from_str(&body).map_err(|e| {
        FederationError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid DeliverWelcome body: {e}"),
        )))
    })?;

    if msg.extra_data.as_ref().is_some_and(|m| !m.is_empty()) {
        return Err(FederationError::InvalidEnvelope {
            reason: "unknown fields in DeliverWelcome request".to_string(),
        });
    }

    let header = validate_envelope_header(&msg.header)?;
    let locator = validate_entry_locator(&msg.entry_locator)?;

    let self_base_did = service_did_base();
    if !dids_equivalent(&header.receiver_ds_did, &self_base_did) {
        return Err(FederationError::InvalidEnvelope {
            reason: format!(
                "receiverDsDid '{}' does not match local service DID '{}'",
                header.receiver_ds_did, self_base_did
            ),
        });
    }

    let recipient_device_id_canonical =
        CanonicalUuidV4::parse(msg.recipient_device_id.as_str()).map_err(|e| {
            FederationError::InvalidEnvelope {
                reason: format!("invalid recipientDeviceId: {e}"),
            }
        })?;
    let recipient_device_id =
        Uuid::from_str(recipient_device_id_canonical.as_str()).map_err(|_| {
            FederationError::InvalidEnvelope {
                reason: "invalid recipientDeviceId UUID".to_string(),
            }
        })?;

    let welcome_id_canonical =
        CanonicalUuidV4::parse(msg.welcome_id.as_str()).map_err(|e| {
            FederationError::InvalidEnvelope {
                reason: format!("invalid welcomeId: {e}"),
            }
        })?;
    let welcome_id = Uuid::from_str(welcome_id_canonical.as_str()).map_err(|_| {
        FederationError::InvalidEnvelope {
            reason: "invalid welcomeId UUID".to_string(),
        }
    })?;

    let recovery_request_id_canonical =
        CanonicalUuidV4::parse(msg.recovery_request_id.as_str()).map_err(|e| {
            FederationError::InvalidEnvelope {
                reason: format!("invalid recoveryRequestId: {e}"),
            }
        })?;
    let recovery_request_id =
        Uuid::from_str(recovery_request_id_canonical.as_str()).map_err(|_| {
            FederationError::InvalidEnvelope {
                reason: "invalid recoveryRequestId UUID".to_string(),
            }
        })?;

    if msg.key_package_ref.len() != 32 {
        return Err(FederationError::InvalidEnvelope {
            reason: "keyPackageRef must be exactly 32 bytes".to_string(),
        });
    }
    let mut key_package_ref = [0u8; 32];
    key_package_ref.copy_from_slice(&msg.key_package_ref);

    if msg.welcome_sha256.len() != 32 {
        return Err(FederationError::InvalidEnvelope {
            reason: "welcomeSha256 must be exactly 32 bytes".to_string(),
        });
    }
    let mut welcome_sha256 = [0u8; 32];
    welcome_sha256.copy_from_slice(&msg.welcome_sha256);

    if msg.public_snapshot_sha256.len() != 32 {
        return Err(FederationError::InvalidEnvelope {
            reason: "publicSnapshotSha256 must be exactly 32 bytes".to_string(),
        });
    }
    let mut public_snapshot_sha256 = [0u8; 32];
    public_snapshot_sha256.copy_from_slice(&msg.public_snapshot_sha256);

    if msg.tree_summary_sha256.len() != 32 {
        return Err(FederationError::InvalidEnvelope {
            reason: "treeSummarySha256 must be exactly 32 bytes".to_string(),
        });
    }
    let mut tree_summary_sha256 = [0u8; 32];
    tree_summary_sha256.copy_from_slice(&msg.tree_summary_sha256);

    let security = enforce_ds_request_security(
        &pool,
        &auth_user,
        DELIVER_WELCOME_NSID,
        Some(&header.sender_ds_did),
    )
    .await?;
    let requester_ds = security.requester_ds.clone();

    let result: Result<Json<serde_json::Value>, FederationError> = async {
        let mut tx = pool.begin().await.map_err(FederationError::Database)?;

        let output = deliver_welcome_mailbox(
            &mut tx,
            signer,
            header,
            msg.recipient_did.as_str().to_string(),
            recipient_device_id,
            welcome_id,
            recovery_request_id,
            key_package_ref,
            msg.welcome_bytes.to_vec(),
            welcome_sha256,
            msg.entry_bytes.to_vec(),
            msg.signed_request_bytes.to_vec(),
            locator,
            msg.coordinates,
            public_snapshot_sha256,
            tree_summary_sha256,
        )
        .await?;

        tx.commit().await.map_err(FederationError::Database)?;

        debug!(
            delivery_id = %output.receipt.delivery_id,
            convo = %output.receipt.conversation_id,
            "Accepted federated welcome"
        );

        let value = serde_json::to_value(output).map_err(FederationError::Json)?;
        Ok(Json(value))
    }
    .await;

    record_ds_outcome(&pool, &requester_ds, result.is_ok()).await;
    result
}
