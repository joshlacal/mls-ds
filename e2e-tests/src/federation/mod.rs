//! Multi-DS federation test module.
//!
//! Exposes the [`TwoNodeCluster`] harness and helper functions for
//! running federated integration tests.

pub mod harness;

pub use harness::{
    boot_two_node_cluster, boot_two_node_cluster_with, ensure_docker_available, HarnessConfig,
    TwoNodeCluster, DIGEST_ALLOWED_TABLES, DS1_DEFAULT_SERVICE_DID, DS2_DEFAULT_SERVICE_DID,
    MLS_APPVIEW_SERVICE_REF,
};
