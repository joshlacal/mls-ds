use axum::{extract::State, Json};
use serde_json::json;
use tracing::{debug, warn};

use crate::{
    auth::AuthUser, crypto::redact_for_log, federation::FederationError, identity::canonical_did,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsDS.fetchKeyPackage";

/// GET /xrpc/blue.catbird.mlsDS.fetchKeyPackage
///
/// Return and consume a key package for a local user, requested by a remote DS.
#[tracing::instrument(skip(pool, auth_user, query))]
pub async fn fetch_key_package(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    axum::extract::Query(query): axum::extract::Query<FetchKeyPackageParams>,
) -> Result<Json<serde_json::Value>, FederationError> {
    let security =
        super::deliver_message::enforce_ds_request_security(&pool, &auth_user, NSID, None).await?;
    let requester_ds = security.requester_ds.clone();

    let recipient_did = &query.recipient_did;
    let convo_id = &query.convo_id;
    // N31: fail-loudly service identity — no hardcoded fallback DID.
    let self_did = crate::identity::service_did_base();

    let result: Result<Json<serde_json::Value>, FederationError> = async {
        // Greenfield strict mode: convoId is required and caller must be authorized for that convo.
        let row = sqlx::query_as::<_, (Option<String>, bool, bool)>(
            "SELECT \
               c.sequencer_ds, \
               EXISTS( \
                 SELECT 1 FROM members recipient \
                 WHERE recipient.convo_id = c.id \
                   AND recipient.left_at IS NULL \
                   AND (recipient.member_did = $4 OR recipient.user_did = $4) \
               ) AS recipient_is_member, \
               EXISTS( \
                 SELECT 1 FROM members requester \
                 WHERE requester.convo_id = c.id \
                   AND requester.left_at IS NULL \
                   AND COALESCE(split_part(requester.ds_did, '#', 1), $2) = $3 \
               ) AS caller_is_member_ds \
             FROM conversations c \
             WHERE c.id = $1",
        )
        .bind(convo_id)
        .bind(&self_did)
        .bind(&requester_ds)
        .bind(recipient_did)
        .fetch_optional(&pool)
        .await
        .map_err(FederationError::Database)?;

        let Some((sequencer_ds, recipient_is_member, caller_is_member_ds)) = row else {
            return Err(FederationError::ConversationNotFound {
                convo_id: convo_id.to_string(),
            });
        };

        if !recipient_is_member {
            return Err(FederationError::RecipientNotFound {
                did: recipient_did.clone(),
            });
        }

        let expected_sequencer =
            canonical_did(&sequencer_ds.unwrap_or(self_did.clone())).to_string();
        let caller_is_authorized = requester_ds == expected_sequencer || caller_is_member_ds;
        if !caller_is_authorized {
            return Err(FederationError::AuthFailed {
                reason: format!(
                    "DS {} is not authorized to fetch key packages for {} in convo {}",
                    requester_ds, recipient_did, convo_id
                ),
            });
        }

        // Atomic regular claim: state='available' -> 'claimed'. The inner
        // SELECT uses FOR UPDATE SKIP LOCKED so concurrent federation requests
        // don't contend on the same row, and the outer UPDATE re-checks
        // `state = 'available'` so the transition is the atomic gate. Try
        // regular pool first, then fall through to reusable last-resort.
        let claim_one = |last_resort: bool| {
            let pool = pool.clone();
            let recipient = recipient_did.clone();
            let convo = convo_id.to_string();
            async move {
                if last_resort {
                    sqlx::query_as::<_, (Vec<u8>, String)>(
                        "SELECT key_package, key_package_hash \
                         FROM key_packages \
                         WHERE owner_did = $1 \
                           AND state = 'available' \
                           AND expires_at > NOW() \
                           AND is_last_resort = true \
                         ORDER BY created_at ASC \
                         LIMIT 1",
                    )
                    .bind(&recipient)
                    .fetch_optional(&pool)
                    .await
                } else {
                    sqlx::query_as::<_, (Vec<u8>, String)>(
                        "WITH claimed AS ( \
                           SELECT id, key_package, key_package_hash \
                           FROM key_packages \
                           WHERE owner_did = $1 \
                             AND state = 'available' \
                             AND expires_at > NOW() \
                             AND is_last_resort = false \
                           ORDER BY created_at ASC \
                           LIMIT 1 \
                           FOR UPDATE SKIP LOCKED \
                         ) \
                         UPDATE key_packages \
                         SET state = 'claimed', \
                             consumed_at = NOW(), \
                             consumed_for_convo_id = $2 \
                         FROM claimed \
                         WHERE key_packages.id = claimed.id \
                           AND key_packages.state = 'available' \
                           AND key_packages.is_last_resort = false \
                         RETURNING claimed.key_package, claimed.key_package_hash",
                    )
                    .bind(&recipient)
                    .bind(&convo)
                    .fetch_optional(&pool)
                    .await
                }
            }
        };

        let row = claim_one(false).await.map_err(FederationError::Database)?;

        let row = match row {
            Some(r) => Some(r),
            None => {
                let lr_row = claim_one(true).await.map_err(FederationError::Database)?;
                if lr_row.is_some() {
                    crate::metrics::record_key_package_last_resort_use();
                }
                lr_row
            }
        };

        match row {
            Some((key_package_data, key_package_hash)) => {
                crate::metrics::record_key_package_claim("claimed");
                debug!(
                    recipient = %redact_for_log(recipient_did),
                    key_package_hash = %redact_for_log(&key_package_hash),
                    requester = %redact_for_log(&requester_ds),
                    convo = %redact_for_log(convo_id),
                    "Key package consumed for federation"
                );

                let encoded = base64::engine::general_purpose::STANDARD.encode(&key_package_data);

                Ok(Json(json!({
                    "keyPackage": encoded,
                    "keyPackageHash": key_package_hash
                })))
            }
            None => {
                crate::metrics::record_key_package_claim("no_match");
                crate::metrics::record_key_package_exhaustion();
                warn!(
                    recipient = %redact_for_log(recipient_did),
                    "No available key packages for federation request"
                );
                Err(FederationError::NoKeyPackagesAvailable {
                    did: recipient_did.clone(),
                })
            }
        }
    }
    .await;

    super::deliver_message::record_ds_outcome(&pool, &requester_ds, result.is_ok()).await;
    result
}

use base64::Engine;

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchKeyPackageParams {
    pub recipient_did: String,
    pub convo_id: String,
}
