use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use sqlx::PgPool;
use std::{sync::Arc, time::SystemTime};

use crate::actors::ActorRegistry;

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
    actors: ActorHealthStatus,
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
    actors: bool,
}

/// Health status for the actor system.
///
/// Provides metrics about conversation actors, including the count of
/// active actors and overall system health.
#[derive(Debug, Serialize)]
pub struct ActorHealthStatus {
    /// Number of currently active conversation actors
    active_actors: usize,
    /// Overall health status of the actor system
    status: CheckStatus,
    /// Whether the actor system is healthy (for backwards compatibility)
    healthy: bool,
}

/// Liveness probe - checks if the application is running
/// Should return 200 OK if the application is alive
pub async fn liveness() -> (StatusCode, &'static str) {
    (StatusCode::OK, "OK")
}

/// Readiness probe - checks if the application is ready to serve traffic.
///
/// Checks database connectivity and actor system health. Returns 200 OK
/// if all systems are operational, 503 SERVICE_UNAVAILABLE otherwise.
pub async fn readiness(
    State(pool): State<PgPool>,
    State(actor_registry): State<Arc<ActorRegistry>>,
) -> (StatusCode, Json<ReadinessResponse>) {
    let db_ready = check_database(&pool).await;
    let actor_health = check_actor_system_health(&actor_registry).await;
    let actors_ready = actor_health.healthy;

    let ready = db_ready && actors_ready;
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
                actors: actors_ready,
            },
        }),
    )
}

/// Health endpoint - detailed health information.
///
/// Returns comprehensive health status including database, memory, and
/// actor system metrics. Returns 200 OK if all systems are healthy,
/// 503 SERVICE_UNAVAILABLE if any critical system is unhealthy.
pub async fn health(
    State(pool): State<PgPool>,
    State(actor_registry): State<Arc<ActorRegistry>>,
) -> (StatusCode, Json<HealthResponse>) {
    let db_status = if check_database(&pool).await {
        CheckStatus::Healthy
    } else {
        CheckStatus::Unhealthy
    };

    let memory_status = check_memory();
    let actor_health = check_actor_system_health(&actor_registry).await;

    let overall_healthy = matches!(db_status, CheckStatus::Healthy)
        && matches!(actor_health.status, CheckStatus::Healthy);
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
                actors: actor_health,
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

/// Checks the health of the actor system.
///
/// Currently returns basic metrics including the number of active actors.
/// Future enhancements may include:
/// - Detection of stuck actors (actors not processing messages)
/// - Mailbox depth monitoring (actors with large message queues)
/// - Actor restart counts
///
/// # Arguments
///
/// - `registry`: Reference to the actor registry
///
/// # Returns
///
/// [`ActorHealthStatus`] containing metrics and health status.
async fn check_actor_system_health(registry: &ActorRegistry) -> ActorHealthStatus {
    let active_actors = registry.actor_count();

    // For now, the actor system is always considered healthy
    // TODO: Add stuck actor detection
    // TODO: Add mailbox depth checks
    // TODO: Add threshold-based health status (e.g., degraded if > 10000 actors)

    let status = CheckStatus::Healthy;
    let healthy = true;

    ActorHealthStatus {
        active_actors,
        status,
        healthy,
    }
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
