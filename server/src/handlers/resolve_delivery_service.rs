use axum::{extract::State, Json};
use tracing::debug;

use crate::{
    auth::AuthUser,
    federation::{DsResolver, FederationError},
    storage::DbPool,
};

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveDeliveryServiceOutput<'a> {
    did: jacquard_common::types::string::Did,
    endpoint: jacquard_common::CowStr<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supported_cipher_suites: Option<Vec<jacquard_common::CowStr<'a>>>,
}

/// GET /xrpc/blue.catbird.chat.resolveDeliveryService
///
/// Client-facing endpoint to resolve a user's delivery service endpoint.
#[tracing::instrument(skip(pool, _auth_user, query))]
pub async fn resolve(
    State(pool): State<DbPool>,
    _auth_user: AuthUser,
    axum::extract::Query(query): axum::extract::Query<ResolveParams>,
) -> Result<Json<ResolveDeliveryServiceOutput<'static>>, FederationError> {
    let user_did = &query.did;

    // N31: fail-loudly service identity — no hardcoded fallback DID/endpoint.
    let self_did = crate::identity::service_did();
    let self_endpoint = crate::identity::self_endpoint();
    let default_ds = std::env::var("DEFAULT_DS_ENDPOINT").ok();
    let cache_ttl: u64 = std::env::var("ENDPOINT_CACHE_TTL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);

    let resolver = DsResolver::new(
        pool.clone(),
        reqwest::Client::new(),
        self_did,
        self_endpoint,
        default_ds,
        cache_ttl,
    );

    let ds_endpoint = resolver.resolve(user_did).await?;

    let did = crate::sqlx_jacquard::try_string_to_did(user_did).map_err(|e| {
        FederationError::ResolutionFailed {
            did: user_did.clone(),
            reason: e,
        }
    })?;

    let endpoint =
        jacquard_common::types::string::UriValue::<jacquard_common::DefaultStr>::new_owned(
            &ds_endpoint.endpoint,
        )
        .map_err(|e| FederationError::ResolutionFailed {
            did: user_did.clone(),
            reason: format!("Invalid endpoint URI: {}", e),
        })?;

    let supported_cipher_suites = ds_endpoint.supported_cipher_suites.map(|suites| {
        suites
            .into_iter()
            .map(jacquard_common::CowStr::from)
            .collect()
    });

    debug!(
        user_did = %crate::crypto::redact_for_log(user_did),
        endpoint = %crate::crypto::redact_for_log(&ds_endpoint.endpoint),
        "Resolved delivery service"
    );

    Ok(Json(ResolveDeliveryServiceOutput {
        did,
        endpoint: jacquard_common::CowStr::Owned(endpoint.as_str().into()),
        supported_cipher_suites,
    }))
}

#[derive(Debug, serde::Deserialize)]
pub struct ResolveParams {
    pub did: String,
}
