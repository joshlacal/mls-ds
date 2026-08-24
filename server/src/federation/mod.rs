pub mod ack;
pub mod declaration_client;
pub mod envelope;
pub mod errors;
pub mod mailbox;
pub mod outbound;
pub mod peer_policy;
pub mod queue;
pub mod receipt;
pub mod reconciliation;
pub mod resolver;
pub mod sequencer;
pub mod service_auth;
pub mod transfer;
pub mod upstream;

pub use ack::*;
pub use declaration_client::{DeviceRecord, DeviceRecordClient, DeviceRecordValue, MLSChatPolicy};
pub use envelope::*;
pub use errors::{FederationError, ResolutionFailureKind};
pub use mailbox::FederatedBackend;
pub use receipt::{
    configured_receipt_signer, hash_commit, validate_receipt_did_document, ReceiptConfigError,
    ReceiptDidDocumentError, ReceiptSigner, SequencerReceipt, RECEIPT_VERIFICATION_METHOD,
};
pub use resolver::{DsEndpoint, DsResolver};
pub use sequencer::{CommitResult, Sequencer};
pub use service_auth::ServiceAuthClient;
use std::collections::BTreeSet;
use std::sync::{OnceLock, RwLock};
pub use transfer::{SequencerTransfer, TransferError, TransferResult};
pub use upstream::UpstreamManager;

/// Runtime federation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationMode {
    Off,
    Allowlist,
    OpenIntelligent,
}

impl FederationMode {
    pub fn try_from_str(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "allowlist" => Some(Self::Allowlist),
            "open_intelligent" => Some(Self::OpenIntelligent),
            _ => None,
        }
    }

    pub fn from_str(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" | "disabled" => Self::Off,
            "allowlist" => Self::Allowlist,
            "open_intelligent" | "open-intelligent" | "open" => Self::OpenIntelligent,
            _ => Self::Off,
        }
    }

    pub fn from_env() -> Self {
        let raw = std::env::var("FEDERATION_MODE").unwrap_or_else(|_| "off".to_string());
        Self::from_str(&raw)
    }

    pub fn runtime_override() -> Option<Self> {
        federation_mode_override()
            .read()
            .ok()
            .and_then(|guard| *guard)
    }

    pub fn set_runtime_override(mode: Option<Self>) {
        if let Ok(mut guard) = federation_mode_override().write() {
            *guard = mode;
        }
    }

    pub fn effective() -> Self {
        Self::runtime_override().unwrap_or_else(Self::from_env)
    }

    pub fn allows_remote_traffic(self) -> bool {
        !matches!(self, Self::Off)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Allowlist => "allowlist",
            Self::OpenIntelligent => "open_intelligent",
        }
    }
}

fn federation_mode_override() -> &'static RwLock<Option<FederationMode>> {
    static MODE_OVERRIDE: OnceLock<RwLock<Option<FederationMode>>> = OnceLock::new();
    MODE_OVERRIDE.get_or_init(|| RwLock::new(None))
}

pub const CAPABILITY_BASELINE: &str = "baseline";
pub const CAPABILITY_RECONCILIATION_V1: &str = "reconciliation-v1";
const DEFAULT_FEDERATION_CAPABILITIES: &[&str] = &[CAPABILITY_BASELINE];

fn normalize_capability(raw: &str) -> Option<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

pub(crate) fn parse_capabilities_csv(raw: &str) -> Vec<String> {
    let mut normalized = BTreeSet::new();
    for cap in raw.split(',') {
        if let Some(cap) = normalize_capability(cap) {
            normalized.insert(cap);
        }
    }
    normalized.into_iter().collect()
}

pub(crate) fn parse_capabilities_from_json_array(
    value: Option<&serde_json::Value>,
) -> Option<Vec<String>> {
    let caps = value.and_then(|v| v.as_array()).map(|arr| {
        let mut normalized = BTreeSet::new();
        for cap in arr {
            if let Some(cap) = cap.as_str().and_then(normalize_capability) {
                normalized.insert(cap);
            }
        }
        normalized.into_iter().collect::<Vec<_>>()
    })?;
    if caps.is_empty() {
        None
    } else {
        Some(caps)
    }
}

pub fn local_federation_capabilities() -> Vec<String> {
    let configured = std::env::var("FEDERATION_CAPABILITIES")
        .ok()
        .map(|raw| parse_capabilities_csv(&raw))
        .unwrap_or_default();
    if configured.is_empty() {
        DEFAULT_FEDERATION_CAPABILITIES
            .iter()
            .map(|cap| cap.to_string())
            .collect()
    } else {
        configured
    }
}

fn capabilities_contain(capabilities: &[String], required: &str) -> bool {
    let Some(required) = normalize_capability(required) else {
        return false;
    };
    capabilities.iter().any(|cap| {
        cap.eq(&required) || normalize_capability(cap).as_deref() == Some(required.as_str())
    })
}

pub fn local_supports_capability(required: &str) -> bool {
    capabilities_contain(&local_federation_capabilities(), required)
}

pub fn discovery_payload_capabilities(payload: &serde_json::Value) -> Option<Vec<String>> {
    parse_capabilities_from_json_array(payload.get("federationCapabilities"))
        .or_else(|| parse_capabilities_from_json_array(payload.get("capabilities")))
}

pub fn known_target_capabilities(
    resolver_capabilities: Option<&[String]>,
    discovery_payload: Option<&serde_json::Value>,
) -> Option<Vec<String>> {
    let mut normalized = BTreeSet::new();

    if let Some(capabilities) = resolver_capabilities {
        for cap in capabilities {
            if let Some(cap) = normalize_capability(cap) {
                normalized.insert(cap);
            }
        }
    }

    if let Some(discovery_caps) = discovery_payload.and_then(discovery_payload_capabilities) {
        for cap in discovery_caps {
            normalized.insert(cap);
        }
    }

    if normalized.is_empty() {
        None
    } else {
        Some(normalized.into_iter().collect())
    }
}

pub fn target_supports_capability(
    required: &str,
    resolver_capabilities: Option<&[String]>,
    discovery_payload: Option<&serde_json::Value>,
) -> bool {
    known_target_capabilities(resolver_capabilities, discovery_payload)
        .is_some_and(|capabilities| capabilities_contain(&capabilities, required))
}

#[cfg(test)]
mod tests {
    use super::{parse_capabilities_csv, target_supports_capability, FederationMode};
    use serde_json::json;

    #[test]
    fn federation_mode_parsing_defaults_to_off() {
        assert_eq!(FederationMode::from_str(""), FederationMode::Off);
        assert_eq!(FederationMode::from_str("unknown"), FederationMode::Off);
        assert_eq!(FederationMode::from_str("off"), FederationMode::Off);
    }

    #[test]
    fn federation_mode_parsing_supports_allowlist_and_open() {
        assert_eq!(
            FederationMode::from_str("allowlist"),
            FederationMode::Allowlist
        );
        assert_eq!(
            FederationMode::from_str("open_intelligent"),
            FederationMode::OpenIntelligent
        );
        assert_eq!(
            FederationMode::from_str("open"),
            FederationMode::OpenIntelligent
        );
    }

    #[test]
    fn parse_capabilities_normalizes_and_dedupes() {
        assert_eq!(
            parse_capabilities_csv("  BASELINE, reconciliation-v1,baseline ,, "),
            vec!["baseline".to_string(), "reconciliation-v1".to_string()]
        );
    }

    #[test]
    fn target_supports_capability_from_discovery_payload() {
        let payload = json!({
            "federationCapabilities": ["baseline", "reconciliation-v1"]
        });
        assert!(target_supports_capability(
            "reconciliation-v1",
            None,
            Some(&payload)
        ));
        assert!(!target_supports_capability(
            "external-commits-v1",
            None,
            Some(&payload)
        ));
    }
}

/// Configuration for federation features.
#[derive(Debug, Clone)]
pub struct FederationConfig {
    pub enabled: bool,
    pub mode: FederationMode,
    pub self_did: String,
    pub self_endpoint: String,
    /// PEM-encoded ES256 private key for signing outbound service auth JWTs.
    pub signing_key_pem: Option<String>,
    /// `disabled` (default) or `issue`. Issue mode fails startup closed unless
    /// the dedicated receipt key and fixed verification method are valid.
    pub receipt_issuance_mode: Option<String>,
    /// Dedicated ES256 receipt key. This must never reuse `signing_key_pem`.
    pub receipt_signing_key_pem: Option<String>,
    /// Fixed DID verification method used by receipt verifiers.
    pub receipt_verification_method: Option<String>,
    /// Exact DID document served at the shared did:web well-known route.
    /// Issue mode validates this document against both configured signing
    /// keys before startup can complete.
    pub receipt_did_document_json: Option<String>,
    /// Explicit fallback DS pair (DID, URL) for actors without a declaration or profile record.
    /// Configured only when both DEFAULT_DS_DID and DEFAULT_DS_ENDPOINT are present and valid.
    pub default_ds: Option<(String, String)>,
    pub endpoint_cache_ttl_secs: u64,
    pub outbound_timeout_secs: u64,
    pub outbound_connect_timeout_secs: u64,
}

impl FederationConfig {
    pub fn from_env() -> Self {
        let mode = FederationMode::from_env();
        let enabled_from_env = std::env::var("FEDERATION_ENABLED")
            .map(|v| v == "true")
            .unwrap_or(false);
        Self {
            enabled: enabled_from_env && mode.allows_remote_traffic(),
            mode,
            // N31: fail-loudly identity — no hardcoded fallback DID/endpoint.
            self_did: crate::identity::service_did(),
            self_endpoint: crate::identity::self_endpoint(),
            signing_key_pem: match std::env::var("SIGNING_KEY_PEM") {
                Ok(pem) if !pem.trim().is_empty() => Some(pem),
                _ => match std::env::var("SIGNING_KEY_PATH")
                    .or_else(|_| std::env::var("SIGNING_KEY_FILE"))
                {
                    Ok(path) if !path.trim().is_empty() => {
                        let content = std::fs::read_to_string(&path).unwrap_or_else(|err| {
                            panic!(
                                "Configured signing key file '{}' could not be read: {}",
                                path, err
                            );
                        });
                        Some(content)
                    }
                    _ => None,
                },
            },
            receipt_issuance_mode: std::env::var("RECEIPT_ISSUANCE_MODE").ok(),
            receipt_signing_key_pem: std::env::var("RECEIPT_SIGNING_KEY_PEM").ok(),
            receipt_verification_method: std::env::var("RECEIPT_VERIFICATION_METHOD").ok(),
            receipt_did_document_json: std::env::var("RECEIPT_DID_DOCUMENT_JSON").ok(),
            default_ds: {
                let did_opt = std::env::var("DEFAULT_DS_DID")
                    .ok()
                    .filter(|v| !v.trim().is_empty());
                let ep_opt = std::env::var("DEFAULT_DS_ENDPOINT")
                    .ok()
                    .filter(|v| !v.trim().is_empty());
                match (did_opt, ep_opt) {
                    (Some(did), Some(endpoint)) => {
                        let valid_did = crate::federation::resolver::validate_canonical_did(&did)
                            .unwrap_or_else(|e| {
                                panic!("Invalid DEFAULT_DS_DID configuration '{did}': {e}");
                            });
                        let _valid_endpoint = crate::federation::resolver::validate_endpoint_url(
                            &endpoint,
                        )
                        .unwrap_or_else(|e| {
                            panic!("Invalid DEFAULT_DS_ENDPOINT configuration '{endpoint}': {e}");
                        });
                        Some((valid_did, endpoint))
                    }
                    (None, None) => None,
                    (Some(did), None) => {
                        panic!("DEFAULT_DS_DID was set ('{did}') but DEFAULT_DS_ENDPOINT was missing. Both must be set or neither.");
                    }
                    (None, Some(endpoint)) => {
                        panic!("DEFAULT_DS_ENDPOINT was set ('{endpoint}') but DEFAULT_DS_DID was missing. Both must be set or neither.");
                    }
                }
            },
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

    pub fn default_ds_did(&self) -> Option<&str> {
        self.default_ds.as_ref().map(|(did, _)| did.as_str())
    }

    pub fn default_ds_endpoint(&self) -> Option<&str> {
        self.default_ds.as_ref().map(|(_, ep)| ep.as_str())
    }
}
