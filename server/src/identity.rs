/// Canonicalize a DID-like identifier by stripping an optional `#fragment`.
///
/// For federation DS identity, `did:web:example.com#service` and
/// `did:web:example.com` map to the same principal for policy/rate checks.
pub fn canonical_did(value: &str) -> &str {
    value.split('#').next().unwrap_or(value)
}

/// Compare two DID-like identifiers after canonicalization.
pub fn dids_equivalent(left: &str, right: &str) -> bool {
    canonical_did(left) == canonical_did(right)
}

/// Fail-loudly accessor for this DS's configured `SERVICE_DID` (N31, WS-1.4).
///
/// Returns the raw configured value (which may carry a `#fragment`).
/// Panics with an actionable message when `SERVICE_DID` is unset or empty —
/// the previous per-call-site hardcoded production-host fallbacks let a
/// wrong identity silently flow through federation authz, sequencer
/// comparisons, and ticket issuance in non-production modes. Production
/// startup already refuses to boot without `SERVICE_DID` (`main.rs`), so
/// this panic is only reachable on dev/test misconfiguration.
///
/// Pattern lifted from the tested `system_reset_did` helper in
/// `actors/conversation.rs`, which now delegates here.
pub fn service_did() -> String {
    service_did_from_env_value(std::env::var("SERVICE_DID"))
}

fn service_did_from_env_value(raw: Result<String, std::env::VarError>) -> String {
    let raw = raw.expect(
        "SERVICE_DID must be configured (e.g. did:web:<host> of this delivery service); \
         refusing to fall back to a hardcoded identity",
    );
    let trimmed = raw.trim();
    assert!(
        !trimmed.is_empty(),
        "SERVICE_DID must not be empty; configure the did:web identity of this delivery service"
    );
    trimmed.to_string()
}

/// Fragment-stripped (base) form of [`service_did`], for client-facing DID
/// fields and canonical sequencer/authz comparisons.
pub fn service_did_base() -> String {
    canonical_did(&service_did()).to_string()
}

/// Fail-loudly accessor for this DS's public HTTPS endpoint.
///
/// Resolution order:
/// 1. explicit `SELF_ENDPOINT` env var (trimmed), when non-empty;
/// 2. derived from a `did:web` `SERVICE_DID` (`did:web:host` -> `https://host`).
///
/// Panics when neither source is available — same fail-loudly rationale as
/// [`service_did`]; never silently advertises someone else's endpoint.
pub fn self_endpoint() -> String {
    self_endpoint_from_env_values(std::env::var("SELF_ENDPOINT"), &service_did())
}

fn self_endpoint_from_env_values(
    raw: Result<String, std::env::VarError>,
    service_did: &str,
) -> String {
    if let Ok(value) = raw {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    did_web_service_endpoint(service_did).unwrap_or_else(|| {
        panic!(
            "SELF_ENDPOINT must be configured when SERVICE_DID ({service_did}) is not a \
             resolvable did:web; refusing to fall back to a hardcoded endpoint"
        )
    })
}

/// Parse a `did:web` into `(host_port, path_segments)`.
///
/// Handles encoded host ports such as `did:web:example.com%3A8443`.
pub fn parse_did_web(did: &str) -> Option<(String, Vec<String>)> {
    let method_specific = canonical_did(did).strip_prefix("did:web:")?;
    let mut parts = method_specific.split(':');
    let host_port = urlencoding::decode(parts.next()?.trim()).ok()?.into_owned();
    if host_port.is_empty() {
        return None;
    }
    let path = parts
        .filter(|segment| !segment.trim().is_empty())
        .map(|segment| {
            urlencoding::decode(segment.trim())
                .ok()
                .map(|s| s.into_owned())
        })
        .collect::<Option<Vec<String>>>()?;
    Some((host_port, path))
}

/// Build a root service endpoint from `did:web`.
///
/// - `did:web:example.com` -> `https://example.com`
/// - `did:web:example.com:user:alice` -> `https://example.com/user/alice`
pub fn did_web_service_endpoint(did: &str) -> Option<String> {
    let (host_port, path) = parse_did_web(did)?;
    if path.is_empty() {
        return Some(format!("https://{host_port}"));
    }
    Some(format!("https://{host_port}/{}", path.join("/")))
}

/// Build DID document URL from `did:web` per method rules.
///
/// - `did:web:example.com` -> `https://example.com/.well-known/did.json`
/// - `did:web:example.com:user:alice` -> `https://example.com/user/alice/did.json`
pub fn did_web_document_url(did: &str) -> Option<String> {
    let (host_port, path) = parse_did_web(did)?;
    if path.is_empty() {
        return Some(format!("https://{host_port}/.well-known/did.json"));
    }
    Some(format!("https://{host_port}/{}/did.json", path.join("/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalization_strips_fragment() {
        assert_eq!(
            canonical_did("did:web:ds.example.com#atproto_mls"),
            "did:web:ds.example.com"
        );
    }

    #[test]
    fn did_web_root_urls() {
        assert_eq!(
            did_web_document_url("did:web:example.com"),
            Some("https://example.com/.well-known/did.json".to_string())
        );
        assert_eq!(
            did_web_service_endpoint("did:web:example.com"),
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn did_web_path_urls() {
        assert_eq!(
            did_web_document_url("did:web:example.com:user:alice"),
            Some("https://example.com/user/alice/did.json".to_string())
        );
        assert_eq!(
            did_web_service_endpoint("did:web:example.com:user:alice"),
            Some("https://example.com/user/alice".to_string())
        );
    }

    #[test]
    fn service_did_from_env_value_returns_trimmed_value_with_fragment() {
        assert_eq!(
            service_did_from_env_value(Ok("  did:web:example.test#atproto_mls ".to_string())),
            "did:web:example.test#atproto_mls"
        );
        // Base form strips the fragment (system_reset_did contract).
        assert_eq!(
            canonical_did(&service_did_from_env_value(Ok(
                "did:web:example.test#atproto_mls".to_string()
            ))),
            "did:web:example.test"
        );
    }

    #[test]
    #[should_panic(expected = "SERVICE_DID must be configured")]
    fn service_did_from_env_value_panics_when_missing() {
        let _ = service_did_from_env_value(Err(std::env::VarError::NotPresent));
    }

    #[test]
    #[should_panic(expected = "SERVICE_DID must not be empty")]
    fn service_did_from_env_value_panics_when_empty() {
        let _ = service_did_from_env_value(Ok("   ".to_string()));
    }

    #[test]
    fn self_endpoint_prefers_explicit_env_value() {
        assert_eq!(
            self_endpoint_from_env_values(
                Ok(" https://ds.example.test ".to_string()),
                "did:web:other.example.test"
            ),
            "https://ds.example.test"
        );
    }

    #[test]
    fn self_endpoint_derives_from_did_web_when_unset() {
        assert_eq!(
            self_endpoint_from_env_values(
                Err(std::env::VarError::NotPresent),
                "did:web:ds.example.test#atproto_mls"
            ),
            "https://ds.example.test"
        );
    }

    #[test]
    #[should_panic(expected = "SELF_ENDPOINT must be configured")]
    fn self_endpoint_panics_when_unset_and_did_not_web() {
        let _ =
            self_endpoint_from_env_values(Err(std::env::VarError::NotPresent), "did:plc:abc123xyz");
    }

    #[test]
    fn did_web_encoded_port_urls() {
        assert_eq!(
            did_web_document_url("did:web:example.com%3A8443"),
            Some("https://example.com:8443/.well-known/did.json".to_string())
        );
        assert_eq!(
            did_web_service_endpoint("did:web:example.com%3A8443:mls"),
            Some("https://example.com:8443/mls".to_string())
        );
    }
}
