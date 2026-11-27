use axum::{extract::State, Json};
use std::sync::Arc;
use tracing::debug;

use crate::{
    auth::AuthUser,
    federation::{DsResolver, FederationError},
};

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveDeliveryServiceOutput {
    did: petrel_core::Did,
    endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    supported_cipher_suites: Option<Vec<String>>,
}

/// GET /xrpc/blue.catbird.chat.resolveDeliveryService
///
/// Client-facing endpoint to resolve a user's delivery service endpoint.
#[tracing::instrument(skip(resolver, _auth_user, query))]
pub async fn resolve(
    State(resolver): State<Arc<DsResolver>>,
    _auth_user: AuthUser,
    axum::extract::Query(query): axum::extract::Query<ResolveParams>,
) -> Result<Json<ResolveDeliveryServiceOutput>, FederationError> {
    let user_did = &query.did;
    let ds_endpoint = resolver.resolve(user_did).await?;

    let did = crate::atproto_conv::try_string_to_did(user_did).map_err(|e| {
        FederationError::ResolutionFailed {
            did: user_did.clone(),
            kind: crate::federation::ResolutionFailureKind::InvalidDid(e),
        }
    })?;

    let endpoint =
        petrel_core::Uri::parse(ds_endpoint.endpoint.as_str())
        .map_err(|e| FederationError::ResolutionFailed {
            did: user_did.clone(),
            kind: crate::federation::ResolutionFailureKind::InvalidUrl(format!(
                "Invalid endpoint URI: {}",
                e
            )),
        })?;

    let supported_cipher_suites = ds_endpoint.supported_cipher_suites.map(|suites| {
        suites
            .into_iter()
            .collect()
    });

    debug!(
        user_did = %crate::crypto::redact_for_log(user_did),
        endpoint = %crate::crypto::redact_for_log(&ds_endpoint.endpoint),
        "Resolved delivery service"
    );

    Ok(Json(ResolveDeliveryServiceOutput {
        did,
        endpoint: endpoint.into_string(),
        supported_cipher_suites,
    }))
}

#[derive(Debug, serde::Deserialize)]
pub struct ResolveParams {
    pub did: String,
}
