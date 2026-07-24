//! Process-wide runtime configuration for the clean-chat handler layer.
//!
//! Holds the two pieces of shared state every `blue.catbird.chat.*` route
//! needs: the global cutover flag (ruling OQ-2) and the trusted Nest token
//! verifier the DPoP auth extractor calls. The verifier is optional so the
//! server still boots before cutover — pre-cutover, every chat route
//! short-circuits at the cutover gate and never reaches the verifier. When
//! cutover is enabled the verifier configuration is mandatory and its absence
//! is a hard startup error.

use std::collections::BTreeSet;

use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdsa::VerifyingKey;

use crate::chat_protocol::{
    dpop::TrustedNestVerifier,
    validation::{CanonicalUuidV4, TrustedExternalBase},
};

/// Shared, immutable clean-chat runtime, stored in `AppState` and extracted by
/// every chat handler as `State<Arc<ChatRuntime>>`.
#[derive(Debug)]
pub struct ChatRuntime {
    cutover_enabled: bool,
    nest_verifier: Option<TrustedNestVerifier>,
}

impl ChatRuntime {
    /// Build the runtime from the process environment.
    ///
    /// - `CHAT_CUTOVER_ENABLED` (bool, default `false`) — the global cutover
    ///   gate predicate (OQ-2).
    /// - Nest verifier vars (`CHAT_NEST_ISSUER`, `CHAT_NEST_AUDIENCE`,
    ///   `CHAT_NEST_KEY_ID`, `CHAT_NEST_VERIFYING_KEY`, `CHAT_INSTANCE_ID`,
    ///   `CHAT_EXTERNAL_BASE`, optional `CHAT_EXTERNAL_BASE_ALLOWED_PORTS`).
    ///   When `CHAT_NEST_ISSUER` is unset the verifier is absent; otherwise
    ///   every field is required.
    ///
    /// Returns `Err` when cutover is enabled without a fully configured
    /// verifier, or when any verifier field is malformed.
    pub fn from_env() -> Result<Self, String> {
        let cutover_enabled = env_flag("CHAT_CUTOVER_ENABLED");
        let nest_verifier = build_verifier_from_env()?;
        if cutover_enabled && nest_verifier.is_none() {
            return Err(
                "CHAT_CUTOVER_ENABLED is set but the clean-chat Nest verifier is not configured \
                 (set CHAT_NEST_ISSUER, CHAT_NEST_AUDIENCE, CHAT_NEST_KEY_ID, \
                 CHAT_NEST_VERIFYING_KEY, CHAT_INSTANCE_ID, CHAT_EXTERNAL_BASE)"
                    .to_owned(),
            );
        }
        Ok(Self {
            cutover_enabled,
            nest_verifier,
        })
    }

    pub(crate) fn cutover_enabled(&self) -> bool {
        self.cutover_enabled
    }

    /// The trusted Nest verifier, present only once the cutover configuration
    /// is complete.
    pub(crate) fn nest_verifier(&self) -> Option<&TrustedNestVerifier> {
        self.nest_verifier.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        cutover_enabled: bool,
        nest_verifier: Option<TrustedNestVerifier>,
    ) -> Self {
        Self {
            cutover_enabled,
            nest_verifier,
        }
    }
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

fn build_verifier_from_env() -> Result<Option<TrustedNestVerifier>, String> {
    let Ok(issuer) = std::env::var("CHAT_NEST_ISSUER") else {
        return Ok(None);
    };
    let audience = require_var("CHAT_NEST_AUDIENCE")?;
    let key_id = require_var("CHAT_NEST_KEY_ID")?;
    let verifying_key_b64 = require_var("CHAT_NEST_VERIFYING_KEY")?;
    let chat_instance_raw = require_var("CHAT_INSTANCE_ID")?;
    let external_base_raw = require_var("CHAT_EXTERNAL_BASE")?;

    let chat_instance = CanonicalUuidV4::parse(&chat_instance_raw)
        .map_err(|_| "CHAT_INSTANCE_ID is not a canonical UUIDv4".to_owned())?;

    let allowed_ports = parse_allowed_ports()?;
    let external_base = TrustedExternalBase::parse(&external_base_raw, &allowed_ports)
        .map_err(|_| "CHAT_EXTERNAL_BASE is not a valid trusted external base".to_owned())?;

    let key_bytes = STANDARD
        .decode(verifying_key_b64.trim())
        .map_err(|_| "CHAT_NEST_VERIFYING_KEY is not valid base64".to_owned())?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&key_bytes)
        .map_err(|_| "CHAT_NEST_VERIFYING_KEY is not a valid SEC1 P-256 public key".to_owned())?;

    let verifier = TrustedNestVerifier::new(
        &issuer,
        &audience,
        chat_instance,
        &key_id,
        verifying_key,
        external_base,
    )
    .map_err(|_| "clean-chat Nest verifier configuration was rejected".to_owned())?;
    Ok(Some(verifier))
}

fn require_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} must be set when CHAT_NEST_ISSUER is set"))
}

fn parse_allowed_ports() -> Result<BTreeSet<u16>, String> {
    let Ok(raw) = std::env::var("CHAT_EXTERNAL_BASE_ALLOWED_PORTS") else {
        return Ok(BTreeSet::new());
    };
    let mut ports = BTreeSet::new();
    for token in raw.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        let port = token.parse::<u16>().map_err(|_| {
            format!("CHAT_EXTERNAL_BASE_ALLOWED_PORTS contains a non-port: {token}")
        })?;
        ports.insert(port);
    }
    Ok(ports)
}
