use once_cell::sync::Lazy;
use sqlx::PgPool;
use std::time::Duration;
use tracing::{debug, info};

use super::errors::FederationError;
use crate::identity::canonical_did;

/// Cached DS endpoint information.
#[derive(Debug, Clone)]
pub struct DsEndpoint {
    pub did: String,
    pub endpoint: String,
    pub supported_cipher_suites: Option<Vec<String>>,
}

/// Resolves a user's DID to their DS endpoint.
pub struct DsResolver {
    pool: PgPool,
    http: reqwest::Client,
    self_did: String,
    self_endpoint: String,
    default_ds: Option<String>,
    cache_ttl_secs: i64,
}

impl DsResolver {
    pub fn new(
        pool: PgPool,
        http: reqwest::Client,
        self_did: String,
        self_endpoint: String,
        default_ds: Option<String>,
        cache_ttl_secs: u64,
    ) -> Self {
        Self {
            pool,
            http,
            self_did,
            self_endpoint,
            default_ds,
            cache_ttl_secs: cache_ttl_secs as i64,
        }
    }

    /// Check if a DID refers to this DS.
    pub fn is_self(&self, ds_did: &str) -> bool {
        canonical_did(ds_did) == canonical_did(&self.self_did)
    }

    /// Get this DS's DID.
    pub fn self_did(&self) -> &str {
        &self.self_did
    }

    /// Get this DS's endpoint URL.
    pub fn self_endpoint(&self) -> &str {
        &self.self_endpoint
    }

    /// Resolve a user's DS endpoint. Cache-first, then repo record, then fallback.
    pub async fn resolve(&self, user_did: &str) -> Result<DsEndpoint, FederationError> {
        // Check if it's us
        if canonical_did(user_did) == canonical_did(&self.self_did) {
            return Ok(DsEndpoint {
                did: self.self_did.clone(),
                endpoint: self.self_endpoint.clone(),
                supported_cipher_suites: None,
            });
        }

        // Check cache
        if let Some(cached) = self.get_cached(user_did).await? {
            return Ok(cached);
        }

        // Resolve from repo record (blue.catbird.mls.profile)
        match self.resolve_from_repo(user_did).await {
            Ok(endpoint) => {
                self.cache_endpoint(&endpoint).await?;
                return Ok(endpoint);
            }
            Err(e) => {
                debug!(did = %crate::crypto::redact_for_log(user_did), error = %e, "Repo resolution failed, trying fallback");
            }
        }

        // Fallback to default DS
        if let Some(ref default) = self.default_ds {
            info!(
                did = %crate::crypto::redact_for_log(user_did),
                default_ds = default,
                "Using default DS fallback"
            );
            return Ok(DsEndpoint {
                did: user_did.to_string(),
                endpoint: default.clone(),
                supported_cipher_suites: None,
            });
        }

        Err(FederationError::EndpointNotFound {
            did: user_did.to_string(),
        })
    }

    /// Resolve multiple DIDs, returning a vec of (DID, result) pairs.
    pub async fn resolve_many(
        &self,
        dids: &[String],
    ) -> Vec<(String, Result<DsEndpoint, FederationError>)> {
        let mut results = Vec::with_capacity(dids.len());
        for did in dids {
            let result = self.resolve(did).await;
            results.push((did.clone(), result));
        }
        results
    }

    async fn get_cached(&self, did: &str) -> Result<Option<DsEndpoint>, FederationError> {
        let row = sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT did, endpoint, supported_cipher_suites \
       FROM ds_endpoints WHERE did = $1 AND expires_at > NOW()",
        )
        .bind(did)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(did, endpoint, suites)| DsEndpoint {
            did,
            endpoint,
            supported_cipher_suites: suites.and_then(|s| serde_json::from_str(&s).ok()),
        }))
    }

    async fn cache_endpoint(&self, endpoint: &DsEndpoint) -> Result<(), FederationError> {
        let suites_json = endpoint
            .supported_cipher_suites
            .as_ref()
            .and_then(|s| serde_json::to_string(s).ok());

        sqlx::query(
      "INSERT INTO ds_endpoints (did, endpoint, supported_cipher_suites, resolved_at, expires_at) \
       VALUES ($1, $2, $3, NOW(), NOW() + make_interval(secs => $4)) \
       ON CONFLICT (did) DO UPDATE SET \
         endpoint = $2, \
         supported_cipher_suites = $3, \
         resolved_at = NOW(), \
         expires_at = NOW() + make_interval(secs => $4)",
    )
    .bind(&endpoint.did)
    .bind(&endpoint.endpoint)
    .bind(&suites_json)
    .bind(self.cache_ttl_secs as f64)
    .execute(&self.pool)
    .await?;

        Ok(())
    }

    /// Resolve DS endpoint from the user's repo record (blue.catbird.mls.profile).
    async fn resolve_from_repo(&self, user_did: &str) -> Result<DsEndpoint, FederationError> {
        let pds_endpoint = self.resolve_did_to_pds(user_did).await?;

        let profile_url = format!(
      "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection=blue.catbird.mls.profile&rkey=self",
      pds_endpoint,
      urlencoding::encode(user_did)
    );

        let resp = self
            .http
            .get(&profile_url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| FederationError::ResolutionFailed {
                did: user_did.to_string(),
                reason: format!("HTTP request failed: {e}"),
            })?;

        if !resp.status().is_success() {
            return Err(FederationError::ResolutionFailed {
                did: user_did.to_string(),
                reason: format!("PDS returned status {}", resp.status()),
            });
        }

        let body: serde_json::Value =
            resp.json()
                .await
                .map_err(|e| FederationError::ResolutionFailed {
                    did: user_did.to_string(),
                    reason: format!("Invalid JSON response: {e}"),
                })?;

        let value = body
            .get("value")
            .ok_or_else(|| FederationError::ResolutionFailed {
                did: user_did.to_string(),
                reason: "No 'value' field in record response".to_string(),
            })?;

        let delivery_service = value
            .get("deliveryService")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FederationError::ResolutionFailed {
                did: user_did.to_string(),
                reason: "No 'deliveryService' in profile record".to_string(),
            })?;

        self.validate_remote_url(delivery_service).await?;

        let suites = value
            .get("supportedCipherSuites")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            });

        Ok(DsEndpoint {
            did: user_did.to_string(),
            endpoint: delivery_service.to_string(),
            supported_cipher_suites: suites,
        })
    }

    /// Resolve a DID to its PDS endpoint via DID document.
    async fn resolve_did_to_pds(&self, did: &str) -> Result<String, FederationError> {
        let did_doc_url = if did.starts_with("did:web:") {
            let domain = did.strip_prefix("did:web:").unwrap_or(did);
            format!("https://{}/.well-known/did.json", domain.replace(':', "/"))
        } else if did.starts_with("did:plc:") {
            format!("https://plc.directory/{did}")
        } else {
            return Err(FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: format!("Unsupported DID method: {did}"),
            });
        };

        self.validate_remote_url(&did_doc_url).await?;

        let resp = self
            .http
            .get(&did_doc_url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: format!("DID resolution HTTP error: {e}"),
            })?;

        if !resp.status().is_success() {
            return Err(FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: format!("DID document server returned status {}", resp.status()),
            });
        }

        let doc: serde_json::Value =
            resp.json()
                .await
                .map_err(|e| FederationError::ResolutionFailed {
                    did: did.to_string(),
                    reason: format!("Invalid DID document JSON: {e}"),
                })?;

        let services = doc
            .get("service")
            .and_then(|s| s.as_array())
            .ok_or_else(|| FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: "No 'service' array in DID document".to_string(),
            })?;

        for svc in services {
            let svc_id = svc.get("id").and_then(|v| v.as_str()).unwrap_or("");
            if svc_id.ends_with("#atproto_pds") || svc_id == "#atproto_pds" {
                if let Some(endpoint) = svc.get("serviceEndpoint").and_then(|v| v.as_str()) {
                    self.validate_remote_url(endpoint).await?;
                    return Ok(endpoint.to_string());
                }
            }
        }

        Err(FederationError::ResolutionFailed {
            did: did.to_string(),
            reason: "No #atproto_pds service in DID document".to_string(),
        })
    }

    /// Invalidate cache entry for a DID.
    pub async fn invalidate(&self, did: &str) -> Result<(), FederationError> {
        sqlx::query("DELETE FROM ds_endpoints WHERE did = $1")
            .bind(did)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Clean up expired cache entries.
    pub async fn cleanup_expired(&self) -> Result<u64, FederationError> {
        let result = sqlx::query("DELETE FROM ds_endpoints WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn validate_remote_url(&self, url_str: &str) -> Result<(), FederationError> {
        let parsed = validate_endpoint_url(url_str)?;
        validate_resolved_host_is_public(&parsed).await
    }
}

/// Returns `true` if the IP is private, loopback, link-local, or unspecified.
fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_unspecified()
                || v4.is_link_local()
                || v4.is_multicast()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
        }
    }
}

fn allow_insecure_http() -> bool {
    std::env::var("FEDERATION_ALLOW_INSECURE_HTTP")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

static FEDERATION_HOST_ALLOWLIST: Lazy<Option<Vec<String>>> = Lazy::new(|| {
    std::env::var("FEDERATION_OUTBOUND_HOST_ALLOWLIST")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(|entry| entry.trim().to_ascii_lowercase())
                .filter(|entry| !entry.is_empty())
                .collect::<Vec<_>>()
        })
        .filter(|entries| !entries.is_empty())
});

fn federation_dns_timeout() -> Duration {
    let timeout_ms = std::env::var("FEDERATION_DNS_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(3000);
    Duration::from_millis(timeout_ms)
}

fn host_is_allowlisted(host: &str, allowlist: &[String]) -> bool {
    let host_lc = host.to_ascii_lowercase();
    allowlist
        .iter()
        .any(|allowed| host_lc == *allowed || host_lc.ends_with(&format!(".{allowed}")))
}

/// Validate a DS endpoint URL for SSRF protection.
fn validate_endpoint_url(url_str: &str) -> Result<url::Url, FederationError> {
    validate_endpoint_url_with_policy(url_str, allow_insecure_http())
}

fn validate_endpoint_url_with_policy(
    url_str: &str,
    allow_http: bool,
) -> Result<url::Url, FederationError> {
    let parsed = url::Url::parse(url_str).map_err(|e| FederationError::ResolutionFailed {
        did: String::new(),
        reason: format!("Invalid URL: {e}"),
    })?;

    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && allow_http) {
        return Err(FederationError::ResolutionFailed {
            did: String::new(),
            reason: if parsed.scheme() == "http" {
                "HTTP federation endpoint rejected; set FEDERATION_ALLOW_INSECURE_HTTP=true only in trusted development"
          .to_string()
            } else {
                format!("URL scheme must be https, got {}", parsed.scheme())
            },
        });
    }

    if let Some(host) = parsed.host_str() {
        let host_lc = host.to_ascii_lowercase();
        let blocked = ["localhost", "127.0.0.1", "0.0.0.0", "::1"];
        if blocked.contains(&host_lc.as_str()) || host_lc.ends_with(".localhost") {
            return Err(FederationError::ResolutionFailed {
                did: String::new(),
                reason: format!("Blocked private address: {host}"),
            });
        }
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if is_private_ip(&ip) {
                return Err(FederationError::ResolutionFailed {
                    did: String::new(),
                    reason: format!("Blocked non-global IP: {ip}"),
                });
            }
        }
        if let Some(allowlist) = FEDERATION_HOST_ALLOWLIST.as_ref() {
            if !host_is_allowlisted(host, allowlist) {
                return Err(FederationError::ResolutionFailed {
                    did: String::new(),
                    reason: format!("Host {host} is not in FEDERATION_OUTBOUND_HOST_ALLOWLIST"),
                });
            }
        }
    }

    Ok(parsed)
}

async fn validate_resolved_host_is_public(parsed: &url::Url) -> Result<(), FederationError> {
    let Some(host) = parsed.host_str() else {
        return Err(FederationError::ResolutionFailed {
            did: String::new(),
            reason: "URL host is missing".to_string(),
        });
    };

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_private_ip(&ip) {
            return Err(FederationError::ResolutionFailed {
                did: String::new(),
                reason: format!("Blocked non-global IP: {ip}"),
            });
        }
        return Ok(());
    }

    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs = tokio::time::timeout(
        federation_dns_timeout(),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| FederationError::ResolutionFailed {
        did: String::new(),
        reason: format!("DNS lookup timed out for host {host}"),
    })?
    .map_err(|e| FederationError::ResolutionFailed {
        did: String::new(),
        reason: format!("Failed to resolve host {host}: {e}"),
    })?;

    let mut resolved_any = false;
    for addr in addrs {
        resolved_any = true;
        if is_private_ip(&addr.ip()) {
            return Err(FederationError::ResolutionFailed {
                did: String::new(),
                reason: format!("Host {host} resolved to blocked IP {}", addr.ip()),
            });
        }
    }

    if !resolved_any {
        return Err(FederationError::ResolutionFailed {
            did: String::new(),
            reason: format!("Host {host} did not resolve to any address"),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    // -- is_private_ip tests --

    #[test]
    fn test_loopback_v4_is_private() {
        assert!(is_private_ip(&"127.0.0.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_10_x_is_private() {
        assert!(is_private_ip(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"10.255.255.255".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_192_168_is_private() {
        assert!(is_private_ip(&"192.168.1.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_172_16_is_private() {
        assert!(is_private_ip(&"172.16.0.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_unspecified_is_private() {
        assert!(is_private_ip(&"0.0.0.0".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_link_local_is_private() {
        assert!(is_private_ip(&"169.254.1.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_loopback_v6_is_private() {
        assert!(is_private_ip(&"::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_unspecified_v6_is_private() {
        assert!(is_private_ip(&"::".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_public_ip_not_private() {
        assert!(!is_private_ip(&"8.8.8.8".parse::<IpAddr>().unwrap()));
        assert!(!is_private_ip(&"1.1.1.1".parse::<IpAddr>().unwrap()));
    }

    // -- validate_endpoint_url tests --

    #[test]
    fn test_valid_https_endpoint() {
        assert!(validate_endpoint_url("https://ds.example.com").is_ok());
    }

    #[test]
    fn test_rejects_http_by_default() {
        assert!(validate_endpoint_url_with_policy("http://ds.example.com", false).is_err());
    }

    #[test]
    fn test_allows_http_with_override() {
        assert!(validate_endpoint_url_with_policy("http://ds.example.com", true).is_ok());
    }

    #[test]
    fn test_rejects_ftp_scheme() {
        let result = validate_endpoint_url("ftp://ds.example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_localhost() {
        let result = validate_endpoint_url("https://localhost");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_127_0_0_1() {
        let result = validate_endpoint_url("https://127.0.0.1");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_0_0_0_0() {
        let result = validate_endpoint_url("https://0.0.0.0");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_private_ip_10() {
        let result = validate_endpoint_url("https://10.0.0.1");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_private_ip_192_168() {
        let result = validate_endpoint_url("https://192.168.1.1");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_ipv6_loopback() {
        let result = validate_endpoint_url("https://[::1]");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_invalid_url() {
        let result = validate_endpoint_url("not a url");
        assert!(result.is_err());
    }

    // -- DsEndpoint struct tests --

    #[test]
    fn test_ds_endpoint_clone() {
        let ep = DsEndpoint {
            did: "did:web:ds.example.com".to_string(),
            endpoint: "https://ds.example.com".to_string(),
            supported_cipher_suites: Some(vec![
                "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string()
            ]),
        };
        let cloned = ep.clone();
        assert_eq!(cloned.did, ep.did);
        assert_eq!(cloned.endpoint, ep.endpoint);
        assert_eq!(cloned.supported_cipher_suites, ep.supported_cipher_suites);
    }
}
