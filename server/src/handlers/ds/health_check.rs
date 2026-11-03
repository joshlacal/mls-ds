use axum::Json;
use serde_json::json;
use tracing::debug;

use crate::federation::FederationError;

/// GET /xrpc/blue.catbird.mlsDS.healthCheck
///
/// Simple health/status endpoint for DS-to-DS discovery.
/// No authentication required.
pub async fn health_check() -> Result<Json<serde_json::Value>, FederationError> {
    crate::federation::peer_policy::ensure_federation_open()?;

    // N31: fail-loudly service identity — no hardcoded fallback DID.
    let did = crate::identity::service_did();

    // Uptime of the scoped DS clock, so a simulated DS replays it exactly.
    let uptime = crate::sim_hooks::uptime_secs();
    let federation_capabilities = crate::federation::local_federation_capabilities();

    debug!("DS health check requested");

    Ok(Json(json!({
        "did": did,
        "version": "1.0.0",
        "uptime": uptime,
        "federationCapabilities": federation_capabilities
    })))
}
