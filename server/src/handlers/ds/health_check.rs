use axum::Json;
use serde_json::json;
use tracing::debug;

use crate::federation::FederationError;

/// GET /xrpc/blue.catbird.mlsDS.healthCheck
///
/// Simple health/status endpoint for DS-to-DS discovery.
/// No authentication required.
pub async fn health_check() -> Result<Json<serde_json::Value>, FederationError> {
    if !crate::federation::FederationMode::effective().allows_remote_traffic() {
        return Err(FederationError::AuthFailed {
            reason: "Federation mode is off".to_string(),
        });
    }

    // N31: fail-loudly service identity — no hardcoded fallback DID.
    let did = crate::identity::service_did();

    // Approximate uptime via process start (lazy_static would be cleaner,
    // but env-based is acceptable for Phase 1)
    let uptime = PROCESS_START.elapsed().as_secs() as i64;
    let federation_capabilities = crate::federation::local_federation_capabilities();

    debug!("DS health check requested");

    Ok(Json(json!({
        "did": did,
        "version": "1.0.0",
        "uptime": uptime,
        "federationCapabilities": federation_capabilities
    })))
}

use once_cell::sync::Lazy;
use std::time::Instant;

static PROCESS_START: Lazy<Instant> = Lazy::new(Instant::now);
