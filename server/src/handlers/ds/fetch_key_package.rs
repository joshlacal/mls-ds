use axum::{extract::State, Json};
use base64::Engine;
use serde_json::json;
use std::{future::Future, sync::Arc};
use tracing::{debug, warn};

use crate::{
    auth::AuthUser, crypto::redact_for_log, federation::FederationError, identity::canonical_did,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsDS.fetchKeyPackage";

async fn claim_current_authorized_key_package(
    pool: &DbPool,
    resolver: &crate::federation::DsResolver,
    recipient_did: &str,
    requester_ds: &str,
) -> Result<Option<(Vec<u8>, String)>, FederationError> {
    claim_current_authorized_key_package_with(pool, recipient_did, requester_ds, || {
        resolver.resolve_authorized_device_keys(recipient_did)
    })
    .await
}

async fn claim_current_authorized_key_package_with<Resolve, ResolveFuture>(
    pool: &DbPool,
    recipient_did: &str,
    requester_ds: &str,
    resolve_authoritative_keys: Resolve,
) -> Result<Option<(Vec<u8>, String)>, FederationError>
where
    Resolve: FnOnce() -> ResolveFuture,
    ResolveFuture: Future<Output = Result<Vec<Vec<u8>>, crate::federation::FederationError>>,
{
    let authoritative_keys = resolve_authoritative_keys().await.map_err(|error| {
        warn!(
            recipient = %redact_for_log(recipient_did),
            retryable = error.is_retryable(),
            reason = error.reason_code(),
            "Authoritative device resolution failed for federated KeyPackage fetch"
        );
        match error {
            // This DS's own store, or an authority that could not answer now,
            // decided nothing: its own 5xx keeps the requesting DS retrying.
            FederationError::Database(_) | FederationError::Storage(_) => error,
            error if error.is_retryable() => error,
            _ => FederationError::AuthFailed {
                reason: "recipient device authority is unavailable".to_string(),
            },
        }
    })?;
    if authoritative_keys.is_empty() {
        return Err(FederationError::AuthFailed {
            reason: "recipient has no authoritative MLS device".to_string(),
        });
    }

    let claim_failed = |_| FederationError::ConfigError {
        reason: "authorized KeyPackage claim failed".to_string(),
    };
    let mut tx = pool.begin().await.map_err(claim_failed)?;
    let reserved = crate::chat_protocol::repository::key_packages::reserve_federated_key_package(
        &mut tx,
        recipient_did,
        requester_ds,
        &authoritative_keys,
        crate::sim_hooks::current_utc(),
    )
    .await
    .map_err(claim_failed)?;
    let Some((bytes, sha256)) = reserved else {
        return Ok(None);
    };
    tx.commit().await.map_err(claim_failed)?;
    Ok(Some((bytes, hex::encode(sha256))))
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

        match claim_current_authorized_key_package(&pool, &resolver, recipient_did, &requester_ds)
            .await?
        {
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

    super::deliver_message::record_ds_outcome(&pool, &requester_ds, &result).await;
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
            "did:web:requester.example.com",
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
        let result = claim_current_authorized_key_package_with(
            &pool,
            "did:plc:w2empty",
            "did:web:requester.example.com",
            || async { Ok(Vec::new()) },
        )
        .await;
        assert!(matches!(result, Err(FederationError::AuthFailed { .. })));
    }

    /// A device authority that could not answer now, or this DS's own store,
    /// decided nothing: the requesting DS gets this DS's retryable 5xx (its
    /// own status: 502 for an authority page that answered 5xx, 503 for a
    /// 503 relayed as such, 500 for the store), never the definitive 401, and
    /// nothing is claimed.
    #[tokio::test]
    async fn an_authority_that_cannot_answer_now_is_a_retryable_5xx() {
        use axum::http::StatusCode;
        let pool = DbPool::connect_lazy("postgres://127.0.0.1:5432/unused").expect("lazy pool");
        for (error, status) in [
            (
                FederationError::ResolutionFailed {
                    did: String::new(),
                    kind: crate::federation::ResolutionFailureKind::HttpStatus {
                        status: 503,
                        message: "PDS device-record page returned status 503".to_string(),
                    },
                },
                StatusCode::BAD_GATEWAY,
            ),
            (
                FederationError::RemoteError {
                    status: 503,
                    body: String::new(),
                },
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                FederationError::Database(sqlx::Error::PoolTimedOut),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            let failed = claim_current_authorized_key_package_with(
                &pool,
                "did:plc:w2transient",
                "did:web:requester.example.com",
                move || async move { Err(error) },
            )
            .await
            .expect_err("nothing is claimed");
            assert_eq!(failed.status_code(), status, "{failed}");
        }
    }
}
