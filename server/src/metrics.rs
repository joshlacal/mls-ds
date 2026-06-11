use axum::{http::StatusCode, response::IntoResponse};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::time::Duration;

pub struct MetricsRecorder {
    handle: PrometheusHandle,
}

impl Default for MetricsRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRecorder {
    pub fn new() -> Self {
        let handle = PrometheusBuilder::new()
            .install_recorder()
            .expect("failed to install Prometheus recorder");

        // Initialize metrics
        metrics::describe_counter!("http_requests_total", "Total number of HTTP requests");
        metrics::describe_histogram!(
            "http_request_duration_seconds",
            "HTTP request duration in seconds"
        );
        metrics::describe_gauge!(
            "database_connections_active",
            "Number of active database connections"
        );
        metrics::describe_counter!("database_queries_total", "Total number of database queries");
        metrics::describe_counter!(
            "mls_messages_sent_total",
            "Total number of MLS messages sent"
        );
        metrics::describe_counter!(
            "mls_groups_created_total",
            "Total number of MLS groups created"
        );
        metrics::describe_gauge!(
            "process_resident_memory_bytes",
            "Process resident memory in bytes"
        );
        metrics::describe_gauge!(
            "process_cpu_seconds_total",
            "Total user and system CPU time"
        );

        // Actor system metrics
        metrics::describe_counter!("actor_spawns_total", "Total number of actors spawned");
        metrics::describe_counter!("actor_stops_total", "Total number of actors stopped");
        metrics::describe_counter!("actor_restarts_total", "Total number of actor restarts");
        metrics::describe_gauge!(
            "actor_mailbox_depth",
            "Number of messages waiting in actor mailbox"
        );
        metrics::describe_histogram!(
            "actor_message_duration_seconds",
            "Time spent processing actor messages"
        );
        metrics::describe_counter!(
            "actor_message_drops_total",
            "Number of messages dropped due to full mailbox"
        );
        metrics::describe_counter!(
            "actor_mailbox_full_events_total",
            "Number of times actor mailbox became full"
        );

        // Epoch safety metrics
        metrics::describe_histogram!(
            "epoch_increment_duration_seconds",
            "Time spent incrementing epoch"
        );
        metrics::describe_counter!(
            "epoch_conflicts_total",
            "Number of detected epoch conflicts"
        );

        // Idempotency metrics
        metrics::describe_counter!(
            "idempotency_cache_hits_total",
            "Total number of idempotency cache hits"
        );
        metrics::describe_counter!(
            "idempotency_cache_misses_total",
            "Total number of idempotency cache misses"
        );
        metrics::describe_counter!(
            "idempotency_requests_without_key_total",
            "Total number of write requests without an idempotency key"
        );
        metrics::describe_counter!(
            "idempotency_cache_check_errors_total",
            "Total number of idempotency cache check errors"
        );
        metrics::describe_counter!(
            "idempotency_cache_stores_total",
            "Total number of responses stored in the idempotency cache"
        );
        metrics::describe_counter!(
            "idempotency_cache_store_errors_total",
            "Total number of idempotency cache store errors"
        );
        metrics::describe_counter!(
            "idempotency_cache_skipped_total",
            "Total number of responses skipped for idempotency caching"
        );
        metrics::describe_counter!(
            "idempotency_cache_cleanup_deleted_total",
            "Total number of idempotency cache entries deleted during cleanup"
        );
        metrics::describe_histogram!(
            "idempotency_cache_check_duration_seconds",
            "Idempotency cache check duration in seconds"
        );
        metrics::describe_histogram!(
            "idempotency_cache_store_duration_seconds",
            "Idempotency cache store duration in seconds"
        );
        metrics::describe_counter!(
            "federation_auto_quarantine_total",
            "Total number of federation peers automatically quarantined"
        );
        metrics::describe_counter!(
            "federation_rejections_total",
            "Total number of federation rejection outcomes by category"
        );
        metrics::describe_counter!(
            "federation_queue_capacity_rejections_total",
            "Total number of outbound federation queue capacity rejections"
        );
        metrics::describe_counter!(
            "federation_risk_transitions_total",
            "Total number of federation peer risk tier transitions"
        );
        metrics::describe_counter!(
            "federation_trust_transitions_total",
            "Total number of federation trust score transitions"
        );
        metrics::describe_counter!(
            "ds_resolve_outcome_total",
            "Total number of DS resolution exits, labeled by outcome (self | cache_fresh | did_doc | profile_record | cache_stale_degraded | default_fallback | hard_failure)"
        );

        // Fan-out failure metrics
        metrics::describe_counter!(
            "fanout_failures_total",
            "Total number of fan-out failures by stage"
        );

        // Key package safety metrics
        metrics::describe_counter!(
            "key_package_claim_total",
            "Total number of key package claim attempts, labeled by state_after (claimed | no_match)"
        );
        metrics::describe_counter!(
            "key_package_exhaustion_total",
            "Total number of times a claim found no available key packages for the requested DID"
        );
        metrics::describe_counter!(
            "key_package_last_resort_use_total",
            "Total number of times a last-resort key package was claimed because no regular available rows existed"
        );
        metrics::describe_counter!(
            "key_package_enumeration_suspected_total",
            "Total getKeyPackages calls flagged by the per-caller unique-target-DID cardinality detector (N26 detection half)"
        );

        Self { handle }
    }

    pub fn handle(&self) -> &PrometheusHandle {
        &self.handle
    }
}

/// Handler for Prometheus metrics endpoint
///
/// # Security
/// This endpoint is protected by:
/// 1. ENABLE_METRICS environment variable (must be explicitly enabled)
/// 2. Optional METRICS_TOKEN bearer token authentication
/// 3. Should be served on internal-only network or behind auth proxy
///
/// If METRICS_TOKEN is set, requests must include: `Authorization: Bearer <token>`
pub async fn metrics_handler(
    handle: axum::extract::State<PrometheusHandle>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Check if metrics token authentication is required
    if let Ok(expected_token) = std::env::var("METRICS_TOKEN") {
        if expected_token.is_empty() {
            tracing::warn!("METRICS_TOKEN is set but empty - treating as no auth required");
        } else {
            // Extract bearer token from Authorization header
            let auth_header = headers.get(axum::http::header::AUTHORIZATION);
            let provided_token = auth_header
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "));

            match provided_token {
                Some(token) if token == expected_token => {
                    // Token matches - proceed
                }
                Some(_) => {
                    tracing::warn!("Metrics endpoint accessed with invalid token");
                    return (
                        StatusCode::UNAUTHORIZED,
                        "Invalid metrics token".to_string(),
                    )
                        .into_response();
                }
                None => {
                    tracing::warn!("Metrics endpoint accessed without authentication");
                    return (
                        StatusCode::UNAUTHORIZED,
                        "Missing or malformed Authorization header".to_string(),
                    )
                        .into_response();
                }
            }
        }
    }

    let metrics = handle.render();
    (StatusCode::OK, metrics).into_response()
}

/// Middleware to track HTTP request metrics
#[allow(dead_code)]
pub async fn track_request_metrics(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> impl IntoResponse {
    let start = std::time::Instant::now();

    let response = next.run(req).await;

    let duration = start.elapsed();

    // Record basic metrics
    metrics::counter!("http_requests_total", 1);
    metrics::histogram!("http_request_duration_seconds", duration.as_secs_f64());

    response
}

/// Record database query metrics
#[allow(dead_code)]
pub fn record_db_query(_query_type: &str, duration: Duration, _success: bool) {
    metrics::counter!("database_queries_total", 1);
    metrics::histogram!("database_query_duration_seconds", duration.as_secs_f64());
}

/// Record MLS-specific metrics
#[allow(dead_code)]
pub fn record_mls_message_sent() {
    metrics::counter!("mls_messages_sent_total", 1);
}

#[allow(dead_code)]
pub fn record_mls_group_created() {
    metrics::counter!("mls_groups_created_total", 1);
}

#[allow(dead_code)]
pub fn record_mls_member_added() {
    metrics::counter!("mls_members_added_total", 1);
}

/// Record realtime metrics
#[allow(dead_code)]
pub fn record_realtime_queue_depth(_convo_id: &str, depth: i64) {
    // Avoid high-cardinality labels; record aggregate only
    metrics::gauge!("realtime_queue_depth", depth as f64);
}

#[allow(dead_code)]
pub fn record_fanout_operation(provider: &str, success: bool) {
    let status = if success { "success" } else { "error" };
    metrics::counter!(
        "fanout_operations_total",
        1,
        "provider" => provider.to_string(),
        "status" => status.to_string()
    );
}

#[allow(dead_code)]
pub fn record_envelope_write_duration(_convo_id: &str, duration: Duration) {
    // Avoid high-cardinality labels; record aggregate only
    metrics::histogram!("envelope_write_duration_seconds", duration.as_secs_f64());
}

#[allow(dead_code)]
pub fn record_cursor_operation(operation: &str, success: bool) {
    let status = if success { "success" } else { "error" };
    metrics::counter!("cursor_operations_total", 1, "operation" => operation.to_string(), "status" => status.to_string());
}

#[allow(dead_code)]
pub fn record_rate_limit_drop(endpoint: &str) {
    metrics::counter!("rate_limit_drops_total", 1, "endpoint" => endpoint.to_string());
}

#[allow(dead_code)]
pub fn record_federation_auto_quarantine(trigger: &str) {
    metrics::counter!(
        "federation_auto_quarantine_total",
        1,
        "trigger" => trigger.to_string()
    );
}

#[allow(dead_code)]
pub fn record_federation_rejection_reason(reason_category: &str) {
    metrics::counter!(
        "federation_rejections_total",
        1,
        "reason_category" => reason_category.to_string()
    );
}

#[allow(dead_code)]
pub fn record_federation_queue_capacity_rejection(scope: &str, risk_tier: &str) {
    metrics::counter!(
        "federation_queue_capacity_rejections_total",
        1,
        "scope" => scope.to_string(),
        "risk_tier" => risk_tier.to_string()
    );
}

#[allow(dead_code)]
pub fn record_federation_risk_transition(from: &str, to: &str, status: &str) {
    metrics::counter!(
        "federation_risk_transitions_total",
        1,
        "from" => from.to_string(),
        "to" => to.to_string(),
        "status" => status.to_string()
    );
}

#[allow(dead_code)]
pub fn record_federation_trust_transition(
    direction: &str,
    from_risk_tier: &str,
    to_risk_tier: &str,
) {
    metrics::counter!(
        "federation_trust_transitions_total",
        1,
        "direction" => direction.to_string(),
        "from_risk_tier" => from_risk_tier.to_string(),
        "to_risk_tier" => to_risk_tier.to_string()
    );
}

#[allow(dead_code)]
pub fn record_event_stream_size(size_bytes: i64) {
    metrics::gauge!("event_stream_size_bytes", size_bytes as f64);
}

#[allow(dead_code)]
pub fn record_active_sse_connections(_convo_id: &str, count: i64) {
    metrics::gauge!("active_sse_connections", count as f64);
}

/// Update system resource metrics
pub fn update_system_metrics() {
    // Basic system metrics - can be enhanced with platform-specific monitoring
    // For production, integrate with system monitoring tools
}

// ============================================================================
// Actor System Metrics
// ============================================================================

/// Record actor spawn event
#[allow(dead_code)]
pub fn record_actor_spawn(actor_type: &str) {
    metrics::counter!("actor_spawns_total", 1, "actor_type" => actor_type.to_string());
}

/// Record actor stop event
#[allow(dead_code)]
pub fn record_actor_stop(actor_type: &str, reason: &str) {
    metrics::counter!("actor_stops_total", 1,
        "actor_type" => actor_type.to_string(),
        "reason" => reason.to_string()
    );
}

/// Record actor restart event
#[allow(dead_code)]
pub fn record_actor_restart(actor_type: &str, reason: &str) {
    metrics::counter!("actor_restarts_total", 1,
        "actor_type" => actor_type.to_string(),
        "reason" => reason.to_string()
    );
}

/// Record actor mailbox depth
/// Note: convo_id removed from labels per security hardening (high cardinality)
#[allow(dead_code)]
pub fn record_actor_mailbox_depth(actor_type: &str, _convo_id: &str, depth: i64) {
    metrics::gauge!("actor_mailbox_depth", depth as f64,
        "actor_type" => actor_type.to_string()
    );
}

/// Record actor message processing duration
#[allow(dead_code)]
pub fn record_actor_message_duration(actor_type: &str, message_type: &str, duration: Duration) {
    metrics::histogram!("actor_message_duration_seconds", duration.as_secs_f64(),
        "actor_type" => actor_type.to_string(),
        "message_type" => message_type.to_string()
    );
}

/// Record actor message drop event (due to full mailbox or other reasons)
#[allow(dead_code)]
pub fn record_actor_message_drop(actor_type: &str, reason: &str) {
    metrics::counter!("actor_message_drops_total", 1,
        "actor_type" => actor_type.to_string(),
        "reason" => reason.to_string()
    );
}

/// Record actor mailbox full event
/// Note: convo_id removed from labels per security hardening (high cardinality)
#[allow(dead_code)]
pub fn record_actor_mailbox_full(_convo_id: &str) {
    metrics::counter!("actor_mailbox_full_events_total", 1);
}

// ============================================================================
// Epoch Safety Metrics
// ============================================================================

/// Record epoch increment operation duration
/// Note: convo_id removed from labels per security hardening (high cardinality)
#[allow(dead_code)]
pub fn record_epoch_increment(_convo_id: &str, duration: Duration) {
    metrics::histogram!("epoch_increment_duration_seconds", duration.as_secs_f64());
}

/// Record epoch conflict detection
/// Note: convo_id removed from labels per security hardening (high cardinality)
#[allow(dead_code)]
pub fn record_epoch_conflict(_convo_id: &str) {
    metrics::counter!("epoch_conflicts_total", 1);
}

// ============================================================================
// Key Package Safety Metrics
// ============================================================================

/// Record a key-package claim outcome.
/// `state_after` is one of "claimed" (atomic transition succeeded) or
/// "no_match" (the row was already claimed/expired/revoked or no `available`
/// row existed for the request).
#[allow(dead_code)]
pub fn record_key_package_claim(state_after: &'static str) {
    metrics::counter!(
        "key_package_claim_total",
        1,
        "state_after" => state_after
    );
}

/// Record an exhaustion event — a claim was attempted for a DID that has zero
/// `available` key packages (regular or last-resort).
#[allow(dead_code)]
pub fn record_key_package_exhaustion() {
    metrics::counter!("key_package_exhaustion_total", 1);
}

/// Record that the claim path fell through to a last-resort key package.
#[allow(dead_code)]
pub fn record_key_package_last_resort_use() {
    metrics::counter!("key_package_last_resort_use_total", 1);
}

/// Record a getKeyPackages call flagged by the enumeration detector (N26):
/// the caller's unique-target-DID cardinality over the sliding window
/// exceeded the configured threshold. Detection-only signal.
#[allow(dead_code)]
pub fn record_key_package_enumeration_suspected() {
    metrics::counter!("key_package_enumeration_suspected_total", 1);
}
