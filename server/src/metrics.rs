use axum::{http::StatusCode, response::IntoResponse};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::time::Duration;

pub struct MetricsRecorder {
    handle: PrometheusHandle,
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
        metrics::describe_counter!(
            "actor_spawns_total",
            "Total number of actors spawned"
        );
        metrics::describe_counter!(
            "actor_stops_total",
            "Total number of actors stopped"
        );
        metrics::describe_counter!(
            "actor_restarts_total",
            "Total number of actor restarts"
        );
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
                    return (StatusCode::UNAUTHORIZED, "Invalid metrics token".to_string()).into_response();
                }
                None => {
                    tracing::warn!("Metrics endpoint accessed without authentication");
                    return (StatusCode::UNAUTHORIZED, "Missing or malformed Authorization header".to_string()).into_response();
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
