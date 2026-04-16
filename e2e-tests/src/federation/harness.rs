//! Two-node federation harness.
//!
//! Spins up a 2-DS federated cluster via docker-compose for integration
//! testing. See `mls-ds/e2e-tests/docker-compose.federation.yml` for the
//! container topology and `mls-ds/scripts/federation-two-node.compose.yml`
//! for the existing shell-driven reference.
//!
//! ## Design goals (for Cluster E)
//! - Boot DS1 + DS2 + two Postgres instances on distinct ports.
//! - Wait for `/health/ready` on each DS before returning.
//! - Provide a [`TestClient`](crate::TestClient) pre-configured for each DS
//!   so tests can register users and exchange messages.
//! - Tear down the cluster on drop (or in an explicit `shutdown()` call).
//! - Respect `FED_HARNESS_PROJECT_NAME` and the port overrides already used
//!   by `federation-two-node-e2e.sh` so the same env works for both entry
//!   points.
//!
//! This file is **scaffolding only**. The function bodies are `todo!()` or
//! return dummy structs; Cluster E will wire them to real docker-compose
//! invocations.

use std::time::Duration;

use crate::TestClient;

/// Default exposed ports — aligned with the existing shell harness so the
/// two entry points don't collide.
pub const DS1_DEFAULT_PORT: u16 = 3101;
pub const DS2_DEFAULT_PORT: u16 = 3102;

/// Result of booting a two-DS federated cluster.
///
/// Holds the compose project handle so the cluster is torn down on drop.
/// Cluster E: replace this with a real struct carrying the compose project
/// name, a kill-on-drop guard, and any Postgres credentials needed for
/// direct DB inspection.
#[derive(Debug)]
pub struct TwoNodeCluster {
    pub ds1_url: String,
    pub ds2_url: String,
    pub ds1_jwt_secret: String,
    pub ds2_jwt_secret: String,
    /// Name of the `docker compose -p <name>` project. Used for teardown.
    pub compose_project: String,
}

impl TwoNodeCluster {
    /// Build a [`TestClient`] targeting DS1.
    pub fn ds1_client(&self) -> TestClient {
        TestClient::new(&self.ds1_url, &self.ds1_jwt_secret)
    }

    /// Build a [`TestClient`] targeting DS2.
    pub fn ds2_client(&self) -> TestClient {
        TestClient::new(&self.ds2_url, &self.ds2_jwt_secret)
    }

    /// Tear down the cluster (best-effort). Cluster E: wire to
    /// `docker compose -p <project> down --volumes --remove-orphans`.
    pub async fn shutdown(self) {
        // TODO(Cluster E): invoke docker compose down
        tracing::warn!(
            compose_project = %self.compose_project,
            "TwoNodeCluster::shutdown is a no-op stub — Cluster E to implement",
        );
    }
}

/// Configuration for booting the cluster.
#[derive(Debug, Clone)]
pub struct HarnessConfig {
    pub ds1_port: u16,
    pub ds2_port: u16,
    pub jwt_secret: String,
    pub boot_timeout: Duration,
    /// docker-compose file path, relative to `mls-ds/e2e-tests/`.
    pub compose_file: String,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        Self {
            ds1_port: DS1_DEFAULT_PORT,
            ds2_port: DS2_DEFAULT_PORT,
            jwt_secret: "test-jwt-secret-cluster-d-placeholder".to_string(),
            boot_timeout: Duration::from_secs(90),
            compose_file: "docker-compose.federation.yml".to_string(),
        }
    }
}

/// Boot a two-DS federated cluster via docker-compose.
///
/// **Stub.** Cluster E will implement this by:
///   1. Shelling out to `docker compose -f <file> -p <project> up -d`.
///   2. Polling `/health/ready` on both DSes until green or timeout.
///   3. Returning a [`TwoNodeCluster`] whose `Drop` impl tears the stack down.
///
/// Until then, calling this function panics with `todo!()`. The placeholder
/// test in `mod.rs` is marked `#[ignore]` so nothing actually triggers it.
pub async fn boot_two_node_cluster() -> TwoNodeCluster {
    boot_two_node_cluster_with(HarnessConfig::default()).await
}

/// Variant that takes explicit configuration. Same stub semantics.
pub async fn boot_two_node_cluster_with(_config: HarnessConfig) -> TwoNodeCluster {
    todo!(
        "Cluster D scaffold: Cluster E to implement docker-compose boot + \
         health check loop. See mls-ds/e2e-tests/docker-compose.federation.yml \
         and mls-ds/scripts/federation-two-node-harness.sh for reference."
    );
}
