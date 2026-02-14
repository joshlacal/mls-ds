pub mod ack;
pub mod errors;
pub mod mailbox;
pub mod outbound;
pub mod peer_policy;
pub mod queue;
pub mod receipt;
pub mod resolver;
pub mod sequencer;
pub mod service_auth;
pub mod transfer;
pub mod upstream;

pub use ack::*;
pub use errors::FederationError;
pub use mailbox::FederatedBackend;
pub use receipt::*;
pub use resolver::DsResolver;
pub use sequencer::{CommitResult, Sequencer};
pub use service_auth::ServiceAuthClient;
pub use transfer::{SequencerTransfer, TransferError, TransferResult};
pub use upstream::UpstreamManager;

/// Configuration for federation features.
#[derive(Debug, Clone)]
pub struct FederationConfig {
    pub enabled: bool,
    pub self_did: String,
    pub self_endpoint: String,
    /// PEM-encoded ES256 private key for signing outbound service auth JWTs.
    pub signing_key_pem: Option<String>,
    /// Fallback DS endpoint for users without a `blue.catbird.mls.profile` record.
    pub default_ds_endpoint: Option<String>,
    pub endpoint_cache_ttl_secs: u64,
    pub outbound_timeout_secs: u64,
    pub outbound_connect_timeout_secs: u64,
}

impl FederationConfig {
    pub fn from_env() -> Self {
        Self {
            enabled: std::env::var("FEDERATION_ENABLED")
                .map(|v| v == "true")
                .unwrap_or(false),
            self_did: std::env::var("SERVICE_DID")
                .unwrap_or_else(|_| "did:web:mls.catbird.blue".to_string()),
            self_endpoint: std::env::var("SELF_ENDPOINT")
                .unwrap_or_else(|_| "https://mls.catbird.blue".to_string()),
            signing_key_pem: std::env::var("SIGNING_KEY_PEM").ok(),
            default_ds_endpoint: std::env::var("DEFAULT_DS_ENDPOINT").ok(),
            endpoint_cache_ttl_secs: std::env::var("ENDPOINT_CACHE_TTL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            outbound_timeout_secs: std::env::var("OUTBOUND_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            outbound_connect_timeout_secs: std::env::var("OUTBOUND_CONNECT_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
        }
    }
}
