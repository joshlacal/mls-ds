/// Canonicalize a DID-like identifier by stripping an optional `#fragment`.
///
/// For federation DS identity, `did:web:example.com#service` and
/// `did:web:example.com` should map to the same principal for policy/rate
/// enforcement.
pub fn canonical_did(value: &str) -> &str {
    value.split('#').next().unwrap_or(value)
}

/// Compare two DID-like identifiers after canonicalization.
pub fn dids_equivalent(left: &str, right: &str) -> bool {
    canonical_did(left) == canonical_did(right)
}
