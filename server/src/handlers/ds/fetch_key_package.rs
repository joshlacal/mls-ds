use axum::{extract::State, Json};
use base64::Engine;
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::{
    auth::AuthUser, crypto::redact_for_log, federation::FederationError, identity::canonical_did,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsDS.fetchKeyPackage";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanFederationKeyPackageClaim {
    Claimed(Vec<u8>, String),
    RejectedCandidate,
    Exhausted,
}

pub async fn claim_authorized_clean_key_package_candidate(
    pool: &DbPool,
    recipient_did: &str,
    authoritative_keys: &[Vec<u8>],
) -> Result<CleanFederationKeyPackageClaim, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let candidate: Option<(Vec<u8>, Vec<u8>, Vec<u8>, uuid::Uuid, String, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT key_package_ref, wrapper_bytes, wrapper_sha256, owner_device_id, owner_key_id, not_after \
               FROM chat.key_packages \
              WHERE owner_did = $1 \
                AND status = 'available' \
              ORDER BY created_at ASC, key_package_ref ASC \
              LIMIT 1 \
              FOR UPDATE SKIP LOCKED",
        )
        .bind(recipient_did)
        .fetch_optional(&mut *tx)
        .await?;

    let Some((kp_ref, wrapper_bytes, wrapper_sha256, owner_device_id, owner_key_id, not_after)) =
        candidate
    else {
        tx.rollback().await.ok();
        return Ok(CleanFederationKeyPackageClaim::Exhausted);
    };

    // Lock the device row before rechecking clock_timestamp() and key authorization.
    let device_signing_key: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT k.signing_public_key \
           FROM chat.devices d \
           JOIN chat.device_keys k \
             ON k.user_did = d.user_did \
            AND k.device_id = d.device_id \
          WHERE d.user_did = $1 \
            AND d.device_id = $2 \
            AND k.key_id = $3 \
            AND d.status = 'active' \
            AND d.revoked_at IS NULL \
            AND k.revoked_at IS NULL \
          FOR SHARE OF d",
    )
    .bind(recipient_did)
    .bind(owner_device_id)
    .bind(&owner_key_id)
    .fetch_optional(&mut *tx)
    .await?;

    let still_unexpired: bool =
        sqlx::query_scalar("SELECT $1::timestamptz > clock_timestamp()")
            .bind(not_after)
            .fetch_one(&mut *tx)
            .await?;

    if !still_unexpired {
        sqlx::query(
            "UPDATE chat.key_packages \
                SET status = 'expired', terminal_at = not_after \
              WHERE key_package_ref = $1 AND status = 'available'",
        )
        .bind(&kp_ref)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(CleanFederationKeyPackageClaim::RejectedCandidate);
    }

    let key_is_authoritative = device_signing_key
        .as_ref()
        .is_some_and(|sig_key| authoritative_keys.iter().any(|k| k == sig_key));
    if !key_is_authoritative {
        tx.rollback().await.ok();
        return Ok(CleanFederationKeyPackageClaim::Exhausted);
    }

    let updated = sqlx::query(
        "UPDATE chat.key_packages \
            SET status = 'reserved' \
          WHERE key_package_ref = $1 \
            AND status = 'available' \
            AND not_after > clock_timestamp()",
    )
    .bind(&kp_ref)
    .execute(&mut *tx)
    .await?;

    if updated.rows_affected() != 1 {
        tx.rollback().await.ok();
        return Ok(CleanFederationKeyPackageClaim::RejectedCandidate);
    }

    tx.commit().await?;
    Ok(CleanFederationKeyPackageClaim::Claimed(
        wrapper_bytes,
        hex::encode(wrapper_sha256),
    ))
}

async fn claim_current_authorized_key_package(
    pool: &DbPool,
    resolver: &crate::federation::DsResolver,
    recipient_did: &str,
) -> Result<Option<(Vec<u8>, String)>, FederationError> {
    claim_current_authorized_key_package_with(pool, recipient_did, || {
        resolver.resolve_authorized_device_keys(recipient_did)
    })
    .await
}

async fn claim_current_authorized_key_package_with<Resolve, ResolveFuture>(
    pool: &DbPool,
    recipient_did: &str,
    mut resolve_authoritative_keys: Resolve,
) -> Result<Option<(Vec<u8>, String)>, FederationError>
where
    Resolve: FnMut() -> ResolveFuture,
    ResolveFuture:
        std::future::Future<Output = Result<Vec<Vec<u8>>, crate::federation::FederationError>>,
{
    loop {
        let authoritative_keys = resolve_authoritative_keys().await.map_err(|_| {
            warn!(
                recipient = %redact_for_log(recipient_did),
                "Authoritative device resolution failed for federated KeyPackage fetch"
            );
            FederationError::AuthFailed {
                reason: "recipient device authority is unavailable".to_string(),
            }
        })?;
        if authoritative_keys.is_empty() {
            return Err(FederationError::AuthFailed {
                reason: "recipient has no authoritative MLS device".to_string(),
            });
        }

        match claim_authorized_clean_key_package_candidate(
            pool,
            recipient_did,
            &authoritative_keys,
        )
        .await
        .map_err(|_| FederationError::ConfigError {
            reason: "authorized KeyPackage claim failed".to_string(),
        })? {
            CleanFederationKeyPackageClaim::Claimed(bytes, hash) => {
                return Ok(Some((bytes, hash)));
            }
            CleanFederationKeyPackageClaim::RejectedCandidate => continue,
            CleanFederationKeyPackageClaim::Exhausted => return Ok(None),
        }
    }
}

/// GET /xrpc/blue.catbird.mlsDS.fetchKeyPackage
///
/// Return and reserve a key package for a local user, requested by an authorized remote DS.
#[tracing::instrument(skip(pool, resolver, auth_user, query))]
pub async fn fetch_key_package(
    State(pool): State<DbPool>,
    State(resolver): State<Arc<crate::federation::DsResolver>>,
    auth_user: AuthUser,
    axum::extract::Query(query): axum::extract::Query<FetchKeyPackageParams>,
) -> Result<Json<serde_json::Value>, FederationError> {
    let security =
        super::deliver_message::enforce_ds_request_security(&pool, &auth_user, NSID, None).await?;
    let requester_ds = security.requester_ds.clone();

    let recipient_did = &query.recipient_did;
    let convo_id = &query.convo_id;
    let self_did = crate::identity::service_did_base();

    let result: Result<Json<serde_json::Value>, FederationError> = async {
        let convo_uuid =
            uuid::Uuid::parse_str(convo_id).map_err(|_| FederationError::ConversationNotFound {
                convo_id: convo_id.to_string(),
            })?;

        let row = sqlx::query_as::<_, (bool, Option<String>, bool, bool)>(
            "SELECT \
               c.is_remote, \
               c.sequencer_ds, \
               EXISTS( \
                 SELECT 1 FROM chat.participants recipient \
                 WHERE recipient.conversation_id = c.conversation_id \
                   AND recipient.current_membership = TRUE \
                   AND recipient.user_did = $4 \
               ) AS recipient_is_member, \
               EXISTS( \
                 SELECT 1 FROM chat.participants requester \
                 WHERE requester.conversation_id = c.conversation_id \
                   AND requester.current_membership = TRUE \
                   AND COALESCE(requester.ds_did, $2) = $3 \
               ) AS caller_is_member_ds \
             FROM chat.conversations c \
             WHERE c.conversation_id = $1",
        )
        .bind(convo_uuid)
        .bind(&self_did)
        .bind(&requester_ds)
        .bind(recipient_did)
        .fetch_optional(&pool)
        .await
        .map_err(FederationError::Database)?;

        let Some((is_remote, sequencer_ds, recipient_is_member, caller_is_member_ds)) = row else {
            return Err(FederationError::ConversationNotFound {
                convo_id: convo_id.to_string(),
            });
        };

        if !recipient_is_member {
            return Err(FederationError::RecipientNotFound {
                did: recipient_did.clone(),
            });
        }

        let expected_sequencer = if is_remote {
            canonical_did(&sequencer_ds.unwrap_or_else(|| self_did.clone())).to_string()
        } else {
            canonical_did(&self_did).to_string()
        };
        let caller_is_authorized = requester_ds == expected_sequencer || caller_is_member_ds;
        if !caller_is_authorized {
            return Err(FederationError::AuthFailed {
                reason: "requesting delivery service is not authorized for this conversation"
                    .to_string(),
            });
        }

        match claim_current_authorized_key_package(&pool, &resolver, recipient_did).await? {
            Some((key_package_data, key_package_hash)) => {
                crate::metrics::record_key_package_claim("claimed");
                debug!(
                    recipient = %redact_for_log(recipient_did),
                    key_package_hash = %redact_for_log(&key_package_hash),
                    requester = %redact_for_log(&requester_ds),
                    convo = %redact_for_log(convo_id),
                    "Key package reserved for federation"
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

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchKeyPackageParams {
    pub recipient_did: String,
    pub convo_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn incomplete_authority_returns_auth_failed_without_touching_pool() {
        let pool = DbPool::connect_lazy("postgres://127.0.0.1:5432/unused").expect("lazy pool");
        let result = claim_current_authorized_key_package_with(
            &pool,
            "did:plc:w2incomplete",
            || async {
                Err(FederationError::ResolutionFailed {
                    did: String::new(),
                    kind: crate::federation::ResolutionFailureKind::InvalidPayload(
                        "pagination incomplete".to_string(),
                    ),
                })
            },
        )
        .await;
        assert!(matches!(result, Err(FederationError::AuthFailed { .. })));
    }

    #[tokio::test]
    async fn empty_authority_returns_auth_failed_without_touching_pool() {
        let pool = DbPool::connect_lazy("postgres://127.0.0.1:5432/unused").expect("lazy pool");
        let result =
            claim_current_authorized_key_package_with(&pool, "did:plc:w2empty", || async {
                Ok(Vec::new())
            })
            .await;
        assert!(matches!(result, Err(FederationError::AuthFailed { .. })));
    }
}
