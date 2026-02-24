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
