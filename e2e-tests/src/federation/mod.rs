//! Multi-DS federation test harness (Rust).
//!
//! This module is the *authoritative* federation test suite per invariant E2
//! (`docs/program/01-INVARIANTS.md`). The shell-based smoke test
//! `mls-ds/e2e-tests/federation-two-node-e2e.sh` continues to live alongside
//! it but is not the source of truth.
//!
//! Current status: **scaffolding only**. Cluster E (Echo) is expected to
//! populate this module with real tests that:
//!   1. Spin up the two-node docker-compose stack via `boot_two_node_cluster`.
//!   2. Register users against DS1 and DS2.
//!   3. Exercise cross-DS welcome, commit, sendMessage, and failover flows.
//!   4. Tear the stack down even on panics.
//!
//! Delta-nonsec (Cluster D) is responsible only for the harness skeleton and
//! placeholder test so Cluster E can add scenarios without first having to
//! set up the plumbing.

pub mod harness;

pub use harness::{boot_two_node_cluster, TwoNodeCluster};

/// Placeholder federation test — proves the module is wired into the test
/// runner and compiles. Ignored by default because booting two DSes + two
/// Postgres instances requires Docker, which is not available in every CI
/// environment.
///
/// Cluster E: replace this with real federated flow tests.
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "TODO(Cluster E): wire up real two-node federation scenario"]
    async fn two_node_smoke_placeholder() {
        // Intentionally left as a placeholder. The harness below is a
        // `todo!()`-bodied stub that Cluster E will implement. Do NOT call
        // `boot_two_node_cluster` from this test body until the stub is
        // replaced with a real implementation, or the test will panic
        // (which is fine — it's behind `#[ignore]`).
        let _ = std::hint::black_box(boot_two_node_cluster);
    }
}
