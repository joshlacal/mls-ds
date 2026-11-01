//! DNS-pinned SSRF validator for outbound Push Gateway and Space-relay URLs (`M-F06`, `3A`).
//!
//! Enforces:
//! - `https` scheme only (port `443` only, no explicit non-443 port, no userinfo, no fragment),
//! - exact `/xrpc/blue.catbird.push.deliver` path with no query string for Push Gateways,
//! - DNS resolution and strict rejection of loopback, RFC 1918 private, link-local / cloud metadata
//!   (`169.254.0.0/16`, `fe80::/10`), CGNAT (`100.64.0.0/10`), benchmarking (`198.18.0.0/15`),
//!   documentation, multicast, broadcast, unspecified, IPv6 unique-local (`fc00::/7`), and
//!   IPv4-mapped non-global addresses,
//! - returns `pinned_addrs: Vec<SocketAddr>` so `reqwest::ClientBuilder::resolve_to_addrs` connects
//!   strictly to the validated IP addresses (eliminating TOCTOU DNS rebinding).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use url::Url;

pub const PUSH_DELIVER_PATH: &str = "/xrpc/blue.catbird.push.deliver";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedGatewayTarget {
    pub url: Url,
    pub host: String,
    pub pinned_addrs: Vec<SocketAddr>,
    pub effective_url: String,
    pub is_test_override: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PushGatewaySsrfError {
    #[error("invalid URL syntax: {0}")]
    InvalidUrl(String),
    #[error("HTTPS on port 443 is required")]
    NonHttpsOrBadPort,
    #[error("unexpected URL path, query, fragment, or credentials")]
    InvalidPathOrQuery,
    #[error("missing or forbidden hostname")]
    MissingHost,
    #[error("DNS resolution failed for {0}")]
    DnsResolutionFailed(String),
    #[error("resolved IP {0} is non-global / private / metadata (SSRF blocked)")]
    ForbiddenIp(IpAddr),
}

#[cfg(any(test, feature = "test-support"))]
fn test_gateway_overrides() -> &'static std::sync::RwLock<std::collections::HashMap<String, String>>
{
    static OVERRIDES: once_cell::sync::Lazy<
        std::sync::RwLock<std::collections::HashMap<String, String>>,
    > = once_cell::sync::Lazy::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));
    &OVERRIDES
}

/// Register a test-only loopback transport override for a canonical `https://<host>/xrpc/blue.catbird.push.deliver` URL.
#[cfg(any(test, feature = "test-support"))]
pub fn register_test_gateway_override(canonical_https_url: &str, loopback_http_url: String) {
    if let Ok(mut map) = test_gateway_overrides().write() {
        map.insert(canonical_https_url.to_string(), loopback_http_url);
    }
}

/// Returns `true` iff `ip` is a publicly routable global unicast address safe for outbound server relay.
pub fn is_publicly_routable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_publicly_routable_ipv4(v4),
        IpAddr::V6(v6) => is_publicly_routable_ipv6(v6),
    }
}

fn is_publicly_routable_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
    {
        return false;
    }
    // 0.0.0.0/8 ("this network")
    if o[0] == 0 {
        return false;
    }
    // 100.64.0.0/10 (Carrier-Grade NAT, RFC 6598)
    if o[0] == 100 && (o[1] & 0b1100_0000) == 64 {
        return false;
    }
    // 169.254.0.0/16 (link-local / cloud metadata 169.254.169.254)
    if o[0] == 169 && o[1] == 254 {
        return false;
    }
    // 192.0.0.0/24 (IETF protocol assignments)
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return false;
    }
    // 198.18.0.0/15 (benchmarking, RFC 2544)
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return false;
    }
    // 240.0.0.0/4 (reserved class E)
    if o[0] >= 240 {
        return false;
    }
    true
}

fn is_publicly_routable_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    if let Some(mapped_v4) = ip.to_ipv4_mapped() {
        return is_publicly_routable_ipv4(mapped_v4);
    }
    let seg = ip.segments();
    // Unique local fc00::/7
    if (seg[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    // Link-local fe80::/10
    if (seg[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    // Documentation 2001:db8::/32
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return false;
    }
    // Discard-only 100::/64
    if seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 {
        return false;
    }
    true
}

/// Validate a Push Gateway URL (`https://<host>/xrpc/blue.catbird.push.deliver`) using system DNS.
pub fn validate_push_gateway_url(
    raw_url: &str,
) -> Result<ValidatedGatewayTarget, PushGatewaySsrfError> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(override_url) = test_gateway_overrides()
        .read()
        .ok()
        .and_then(|m| m.get(raw_url).cloned())
    {
        let parsed =
            Url::parse(raw_url).map_err(|e| PushGatewaySsrfError::InvalidUrl(e.to_string()))?;
        let host = parsed
            .host_str()
            .ok_or(PushGatewaySsrfError::MissingHost)?
            .to_string();
        return Ok(ValidatedGatewayTarget {
            url: parsed,
            host,
            pinned_addrs: Vec::new(),
            effective_url: override_url,
            is_test_override: true,
        });
    }

    validate_push_gateway_url_with_resolver(raw_url, system_dns_resolve)
}

/// Validate a Push Gateway URL with an explicit hostname -> IP resolver (deterministic unit/integration testing).
pub fn validate_push_gateway_url_with_resolver<F>(
    raw_url: &str,
    resolve_host: F,
) -> Result<ValidatedGatewayTarget, PushGatewaySsrfError>
where
    F: FnOnce(&str) -> Result<Vec<IpAddr>, String>,
{
    validate_https_url_with_resolver(raw_url, Some(PUSH_DELIVER_PATH), false, resolve_host)
}

/// General HTTPS `:443` DNS-pinned SSRF validator reusable for Push Gateways, Space read relays, and Space notification webhooks.
pub fn validate_https_url_with_resolver<F>(
    raw_url: &str,
    required_exact_path: Option<&str>,
    allow_query: bool,
    resolve_host: F,
) -> Result<ValidatedGatewayTarget, PushGatewaySsrfError>
where
    F: FnOnce(&str) -> Result<Vec<IpAddr>, String>,
{
    let parsed =
        Url::parse(raw_url).map_err(|e| PushGatewaySsrfError::InvalidUrl(e.to_string()))?;
    if parsed.scheme() != "https" {
        return Err(PushGatewaySsrfError::NonHttpsOrBadPort);
    }
    if let Some(explicit_port) = parsed.port() {
        if explicit_port != 443 {
            return Err(PushGatewaySsrfError::NonHttpsOrBadPort);
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return Err(PushGatewaySsrfError::InvalidPathOrQuery);
    }
    if !allow_query && parsed.query().is_some() {
        return Err(PushGatewaySsrfError::InvalidPathOrQuery);
    }
    if let Some(expected_path) = required_exact_path {
        if parsed.path() != expected_path {
            return Err(PushGatewaySsrfError::InvalidPathOrQuery);
        }
    }
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or(PushGatewaySsrfError::MissingHost)?
        .to_string();

    if host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".localhost")
        || host.ends_with(".internal")
    {
        return Err(PushGatewaySsrfError::MissingHost);
    }

    let ips = if let Ok(literal_ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        vec![literal_ip]
    } else {
        resolve_host(&host).map_err(|_| PushGatewaySsrfError::DnsResolutionFailed(host.clone()))?
    };

    if ips.is_empty() {
        return Err(PushGatewaySsrfError::DnsResolutionFailed(host));
    }

    let mut pinned_addrs = Vec::with_capacity(ips.len());
    for ip in ips {
        if !is_publicly_routable_ip(ip) {
            return Err(PushGatewaySsrfError::ForbiddenIp(ip));
        }
        pinned_addrs.push(SocketAddr::new(ip, 443));
    }

    Ok(ValidatedGatewayTarget {
        effective_url: parsed.to_string(),
        url: parsed,
        host,
        pinned_addrs,
        is_test_override: false,
    })
}

pub fn system_dns_resolve(host: &str) -> Result<Vec<IpAddr>, String> {
    let addrs: Vec<IpAddr> = (host, 443u16)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .map(|sa| sa.ip())
        .collect();
    if addrs.is_empty() {
        return Err("no A/AAAA records".to_string());
    }
    Ok(addrs)
}
