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
    #[cfg(feature = "sim")]
    if let Some(hooks) = crate::sim_hooks::active_sim_ds() {
        return service_did_from_env_value(Ok(hooks.service_did.clone()));
    }
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

/// Non-panicking variant of [`service_did_base`] for client-facing
/// *projection* paths (ADR-010 D4 / WS-4 rung 2: `convoView.sequencerDid`).
///
/// Rung 2 exposes the sequencer DID for observability only — nothing routes
/// on it yet — so a dev/test server without `SERVICE_DID` must omit the
/// field (with a one-time warning) rather than fail `getConvos`/`createConvo`
/// (ADR-010 ambiguity A5). Authz, federation, and ticket-issuance paths keep
/// the fail-loudly [`service_did`] accessor (N31, WS-1.4). Once clients
/// route on `sequencerDid` (WS-4 rung 3), revisit per D4 rule 2.
pub fn service_did_base_opt() -> Option<String> {
    #[cfg(feature = "sim")]
    if let Some(hooks) = crate::sim_hooks::active_sim_ds() {
        return service_did_base_opt_from_env_value(Ok(hooks.service_did.clone()));
    }
    service_did_base_opt_from_env_value(std::env::var("SERVICE_DID"))
}

fn service_did_base_opt_from_env_value(raw: Result<String, std::env::VarError>) -> Option<String> {
    let value = raw
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    if value.is_none() {
        static WARN_ONCE: std::sync::Once = std::sync::Once::new();
        WARN_ONCE.call_once(|| {
            tracing::warn!(
                "SERVICE_DID is unset/empty; convoView.sequencerDid will be omitted \
                 (ADR-010 D4 rung-2 projection). Configure SERVICE_DID for production."
            );
        });
    }
    value.map(|v| canonical_did(&v).to_string())
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
    #[cfg(feature = "sim")]
    if let Some(hooks) = crate::sim_hooks::active_sim_ds() {
        return self_endpoint_from_env_values(Ok(hooks.self_endpoint.clone()), &service_did());
    }
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

fn valid_did_web_host_port(host_port: &str) -> bool {
    if host_port.is_empty()
        || host_port.bytes().any(|b| {
            b.is_ascii_whitespace()
                || b.is_ascii_control()
                || matches!(b, b'@' | b'/' | b'\\' | b'?' | b'#')
        })
    {
        return false;
    }
    url::Url::parse(&format!("https://{host_port}"))
        .ok()
        .is_some_and(|u| {
            u.username().is_empty()
                && u.password().is_none()
                && u.host_str().is_some()
                && u.path() == "/"
                && u.query().is_none()
                && u.fragment().is_none()
        })
}

fn valid_did_web_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && !segment
            .bytes()
            .any(|b| b.is_ascii_control() || matches!(b, b'/' | b'\\' | b'?' | b'#' | b'@'))
}

/// Parse a `did:web` into `(host_port, path_segments)`.
///
/// Handles encoded host ports such as `did:web:example.com%3A8443`.
pub fn parse_did_web(did: &str) -> Option<(String, Vec<String>)> {
    let method_specific = canonical_did(did).strip_prefix("did:web:")?;
    let mut parts = method_specific.split(':');
    let host_port = urlencoding::decode(parts.next()?.trim()).ok()?.into_owned();
    if !valid_did_web_host_port(&host_port) {
        return None;
    }
    let path = parts
        .filter(|segment| !segment.trim().is_empty())
        .map(|segment| {
            urlencoding::decode(segment.trim())
                .ok()
                .map(|s| s.into_owned())
                .filter(|s| valid_did_web_segment(s))
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

pub mod did_doc;

/// Canonical root DID document path shared by URL resolution and serving.
pub const DID_WEB_WELL_KNOWN_PATH: &str = "/.well-known/did.json";

/// Build the HTTP route path at which a `did:web` serves its DID document, or `None` for non-`did:web` (`did:plc`).
///
/// - `did:web:example.com` -> `Some("/.well-known/did.json")`
/// - `did:web:example.com:chat:ds1` -> `Some("/chat/ds1/did.json")`
/// - `did:plc:...` -> `None`
pub fn did_web_document_path(did: &str) -> Option<String> {
    let (_host_port, path) = parse_did_web(did)?;
    if path.is_empty() {
        return Some(DID_WEB_WELL_KNOWN_PATH.to_string());
    }
    Some(format!("/{}/did.json", path.join("/")))
}

/// Build DID document URL from `did:web` per method rules.
///
/// - `did:web:example.com` -> `https://example.com/.well-known/did.json`
/// - `did:web:example.com:user:alice` -> `https://example.com/user/alice/did.json`
pub fn did_web_document_url(did: &str) -> Option<String> {
    let (host_port, path) = parse_did_web(did)?;
    if path.is_empty() {
        return Some(format!("https://{host_port}{DID_WEB_WELL_KNOWN_PATH}"));
    }
    Some(format!("https://{host_port}/{}/did.json", path.join("/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_did_path_is_exact_and_shared() {
        assert_eq!(DID_WEB_WELL_KNOWN_PATH, "/.well-known/did.json");
    }

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
    fn service_did_base_opt_strips_fragment_and_trims() {
        assert_eq!(
            service_did_base_opt_from_env_value(Ok(
                " did:web:example.test#atproto_mls ".to_string()
            )),
            Some("did:web:example.test".to_string())
        );
    }

    #[test]
    fn service_did_base_opt_none_when_missing_or_empty() {
        assert_eq!(
            service_did_base_opt_from_env_value(Err(std::env::VarError::NotPresent)),
            None
        );
        assert_eq!(
            service_did_base_opt_from_env_value(Ok("   ".to_string())),
            None
        );
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

    #[test]
    fn mf02_parse_did_web_rejects_userinfo_slashes_dot_segments_and_query_or_fragment_injection() {
        for malicious in [
            "did:web:user%40evil.com",
            "did:web:evil.com%2F..%2Fadmin",
            "did:web:evil.com%5Cadmin",
            "did:web:evil.com%3Ffoo%3Dbar",
            "did:web:evil.com%23frag",
            "did:web:evil.com:..:secret",
            "did:web:evil.com:.:secret",
            "did:web:evil.com:foo%2Fbar",
            "did:web:evil.com:foo%5Cbar",
            "did:web:evil.com:foo%3Fbar",
        ] {
            assert!(
                parse_did_web(malicious).is_none(),
                "expected malicious did:web {malicious} to be rejected"
            );
            assert!(did_web_document_url(malicious).is_none());
        }
        assert_eq!(
            parse_did_web("did:web:example.com%3A8443:user:alice"),
            Some((
                "example.com:8443".to_string(),
                vec!["user".to_string(), "alice".to_string()],
            ))
        );
    }
}
