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
        metrics::describe_counter!(
            "http_requests_total",
            "Total number of HTTP requests"
        );
        metrics::describe_histogram!(
            "http_request_duration_seconds",
            "HTTP request duration in seconds"
        );
        metrics::describe_gauge!(
            "database_connections_active",
            "Number of active database connections"
        );
        metrics::describe_counter!(
            "database_queries_total",
            "Total number of database queries"
        );
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

        Self { handle }
    }

    pub fn handle(&self) -> &PrometheusHandle {
        &self.handle
    }
}

/// Handler for Prometheus metrics endpoint
pub async fn metrics_handler(handle: axum::extract::State<PrometheusHandle>) -> impl IntoResponse {
    let metrics = handle.render();
    (StatusCode::OK, metrics)
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

/// Update system resource metrics
pub fn update_system_metrics() {
    // Basic system metrics - can be enhanced with platform-specific monitoring
    // For production, integrate with system monitoring tools
}
