use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::time::SystemTime;

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    status: String,
    timestamp: u64,
    version: String,
    checks: HealthChecks,
}

#[derive(Debug, Serialize)]
pub struct HealthChecks {
    database: CheckStatus,
    memory: CheckStatus,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Healthy,
    Unhealthy,
    Degraded,
}

#[derive(Debug, Serialize)]
pub struct ReadinessResponse {
    ready: bool,
    checks: ReadinessChecks,
}

#[derive(Debug, Serialize)]
pub struct ReadinessChecks {
    database: bool,
}

/// Liveness probe - checks if the application is running
/// Should return 200 OK if the application is alive
pub async fn liveness() -> (StatusCode, &'static str) {
    (StatusCode::OK, "OK")
}

/// Readiness probe - checks if the application is ready to serve traffic
/// Checks database connectivity and other critical dependencies
pub async fn readiness(State(pool): State<PgPool>) -> (StatusCode, Json<ReadinessResponse>) {
    let db_ready = check_database(&pool).await;

    let ready = db_ready;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(ReadinessResponse {
            ready,
            checks: ReadinessChecks {
                database: db_ready,
            },
        }),
    )
}

/// Health endpoint - detailed health information
/// Returns comprehensive health status including database and system metrics
pub async fn health(State(pool): State<PgPool>) -> (StatusCode, Json<HealthResponse>) {
    let db_status = if check_database(&pool).await {
        CheckStatus::Healthy
    } else {
        CheckStatus::Unhealthy
    };

    let memory_status = check_memory();

    let overall_healthy = matches!(db_status, CheckStatus::Healthy);
    let status = if overall_healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    };

    (
        status,
        Json(HealthResponse {
            status: if overall_healthy {
                "healthy".to_string()
            } else {
                "unhealthy".to_string()
            },
            timestamp,
            version: env!("CARGO_PKG_VERSION").to_string(),
            checks: HealthChecks {
                database: db_status,
                memory: memory_status,
            },
        }),
    )
}

async fn check_database(pool: &PgPool) -> bool {
    sqlx::query("SELECT 1")
        .execute(pool)
        .await
        .is_ok()
}

fn check_memory() -> CheckStatus {
    // Basic memory check - can be enhanced with actual memory usage monitoring
    CheckStatus::Healthy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_liveness() {
        let (status, body) = liveness().await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "OK");
    }
}
