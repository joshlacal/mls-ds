use axum::Json;
use serde_json::json;
use tracing::debug;

use crate::federation::FederationError;

/// GET /xrpc/blue.catbird.mls.ds.healthCheck
///
/// Simple health/status endpoint for DS-to-DS discovery.
/// No authentication required.
pub async fn health_check() -> Result<Json<serde_json::Value>, FederationError> {
    let did =
        std::env::var("SERVICE_DID").unwrap_or_else(|_| "did:web:mls.catbird.blue".to_string());

    // Approximate uptime via process start (lazy_static would be cleaner,
    // but env-based is acceptable for Phase 1)
    let uptime = PROCESS_START.elapsed().as_secs() as i64;

    debug!("DS health check requested");

    Ok(Json(json!({
        "did": did,
        "version": "1.0.0",
        "uptime": uptime
    })))
}

use once_cell::sync::Lazy;
use std::time::Instant;

static PROCESS_START: Lazy<Instant> = Lazy::new(Instant::now);
