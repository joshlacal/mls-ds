use once_cell::sync::Lazy;
use sqlx::PgPool;
use std::collections::HashSet;
use std::future::Future;
use std::time::Duration;
use tracing::{debug, info};

use super::errors::FederationError;
use crate::identity::{canonical_did, did_web_document_url};

const PROFILE_COLLECTION: &str = "blue.catbird.mlsChat.profile";
const PROFILE_RKEY: &str = "self";
const AUTHORITY_PAGE_SIZE: usize = 100;
const AUTHORITY_PAGE_SIZE_PARAM: &str = "100";
const MAX_AUTHORITY_PAGES: usize = 10;
const MAX_AUTHORITY_RECORDS: usize = AUTHORITY_PAGE_SIZE * MAX_AUTHORITY_PAGES;

fn profile_record_url(pds_endpoint: &str, user_did: &str) -> String {
    format!(
        "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection={PROFILE_COLLECTION}&rkey={PROFILE_RKEY}",
        pds_endpoint,
        urlencoding::encode(user_did)
    )
}

/// Cached DS endpoint information.
#[derive(Debug, Clone)]
pub struct DsEndpoint {
    pub did: String,
    pub endpoint: String,
    pub supported_cipher_suites: Option<Vec<String>>,
    pub federation_capabilities: Option<Vec<String>>,
}

/// Resolves a user's DID to their DS endpoint.
#[derive(Debug)]
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

    /// Resolve a user's DS endpoint.
    ///
    /// Ordering (ADR-010 D2): self → fresh cache → `#atproto_mls` DID-document
    /// service entry → legacy `blue.catbird.mlsChat.profile` repo record →
    /// expired-cache degraded mode → default DS → not found.
    ///
    /// An unexpired cache row counts as "fresh resolution" (the TTL defines
    /// freshness); expired rows are only consulted in degraded mode after all
    /// live resolution paths have failed.
    pub async fn resolve(&self, user_did: &str) -> Result<DsEndpoint, FederationError> {
        let (result, outcome) = self.resolve_with_outcome(user_did).await;
        // D2 telemetry: exactly one structured event per resolution exit, with
        // a stable `outcome` discriminator so E5 can set alert thresholds.
        tracing::info!(
            target: "federation::resolve",
            did = %crate::crypto::redact_for_log(user_did),
            outcome = outcome,
            "DS resolution outcome"
        );
        metrics::counter!("ds_resolve_outcome_total", 1, "outcome" => outcome);
        result
    }

    async fn resolve_with_outcome(
        &self,
        user_did: &str,
    ) -> (Result<DsEndpoint, FederationError>, &'static str) {
        // Check if it's us
        if canonical_did(user_did) == canonical_did(&self.self_did) {
            return (
                Ok(DsEndpoint {
                    did: self.self_did.clone(),
                    endpoint: self.self_endpoint.clone(),
                    supported_cipher_suites: None,
                    federation_capabilities: Some(super::local_federation_capabilities()),
                }),
                "self",
            );
        }

        // Fresh cache (TTL-bounded; an unexpired row counts as fresh
        // resolution per ADR-010 D2/A2)
        match self.get_cached(user_did).await {
            Ok(Some(cached)) => return (Ok(cached), "cache_fresh"),
            Ok(None) => {}
            Err(e) => return (Err(e), "hard_failure"),
        }

        // `#atproto_mls` service entry in the user's DID document (ADR-010 D1)
        match self.resolve_from_did_doc(user_did).await {
            Ok(endpoint) => {
                if let Err(e) = self.cache_endpoint(&endpoint).await {
                    return (Err(e), "hard_failure");
                }
                return (Ok(endpoint), "did_doc");
            }
            Err(e) => {
                debug!(did = %crate::crypto::redact_for_log(user_did), error = %e, "DID-document #atproto_mls resolution failed, trying profile record");
            }
        }

        // Legacy fallback: repo record (blue.catbird.mlsChat.profile)
        match self.resolve_from_repo(user_did).await {
            Ok(endpoint) => {
                if let Err(e) = self.cache_endpoint(&endpoint).await {
                    return (Err(e), "hard_failure");
                }
                return (Ok(endpoint), "profile_record");
            }
            Err(e) => {
                debug!(did = %crate::crypto::redact_for_log(user_did), error = %e, "Repo resolution failed, trying fallback");
            }
        }

        // Degraded mode (ADR-010 D2): all live resolution paths failed — fall
        // back to an expired cache row if one exists. The row stays expired,
        // so the next resolve attempt naturally retries live resolution.
        match self.get_cached_any(user_did).await {
            Ok(Some(cached)) => {
                tracing::warn!(
                    did = %crate::crypto::redact_for_log(user_did),
                    endpoint = %cached.endpoint,
                    "Live DS resolution failed; using expired cached endpoint (degraded mode)"
                );
                return (Ok(cached), "cache_stale_degraded");
            }
            Ok(None) => {}
            Err(e) => {
                debug!(did = %crate::crypto::redact_for_log(user_did), error = %e, "Expired-cache lookup failed");
            }
        }

        // Fallback to default DS
        if let Some(ref default) = self.default_ds {
            info!(
                did = %crate::crypto::redact_for_log(user_did),
                default_ds = default,
                "Using default DS fallback"
            );
            return (
                Ok(DsEndpoint {
                    did: user_did.to_string(),
                    endpoint: default.clone(),
                    supported_cipher_suites: None,
                    federation_capabilities: None,
                }),
                "default_fallback",
            );
        }

        (
            Err(FederationError::EndpointNotFound {
                did: user_did.to_string(),
            }),
            "hard_failure",
        )
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
            federation_capabilities: None,
        }))
    }

    /// Like [`Self::get_cached`], but ignores `expires_at`. Used only for the
    /// degraded-mode fallback after all live resolution paths have failed
    /// (ADR-010 D2).
    async fn get_cached_any(&self, did: &str) -> Result<Option<DsEndpoint>, FederationError> {
        let row = sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT did, endpoint, supported_cipher_suites \
       FROM ds_endpoints WHERE did = $1",
        )
        .bind(did)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(did, endpoint, suites)| DsEndpoint {
            did,
            endpoint,
            supported_cipher_suites: suites.and_then(|s| serde_json::from_str(&s).ok()),
            federation_capabilities: None,
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

    /// Resolve the user's DS endpoint from the `#atproto_mls` service entry in
    /// their DID document (ADR-010 D1).
    ///
    /// The service entry must have type `AtprotoMLSDeliveryService` and an
    /// HTTPS `serviceEndpoint` (origin/base URL; clients append
    /// `/xrpc/<nsid>`). An `#atproto_mls` entry with the wrong `type` is
    /// logged and treated as not found.
    async fn resolve_from_did_doc(&self, user_did: &str) -> Result<DsEndpoint, FederationError> {
        let doc = self.fetch_did_document(user_did).await?;

        let endpoint = extract_service(&doc, "atproto_mls", Some("AtprotoMLSDeliveryService"))
            .ok_or_else(|| FederationError::ResolutionFailed {
                did: user_did.to_string(),
                reason: "No #atproto_mls service in DID document".to_string(),
            })?
            .to_string();

        self.validate_remote_url(&endpoint).await?;

        // D1 rules 4-6: record the *base* DS DID (no fragment). The user's
        // DID doc only carries the endpoint, so derive `did:web:<host>` for
        // did:web-style deployments. Serving the DS DID document from mls-ds
        // itself is ADR-010 Stage 4; non-did:web DSes are out of scope until
        // then. When derivation fails (path components, non-HTTPS), fall back
        // to keying the cache row by the *user* DID, exactly as the legacy
        // profile-record path does.
        let ds_did =
            derive_ds_did_from_https_endpoint(&endpoint).unwrap_or_else(|| user_did.to_string());

        Ok(DsEndpoint {
            did: ds_did,
            endpoint,
            supported_cipher_suites: None,
            federation_capabilities: None,
        })
    }

    /// Resolve DS endpoint from the user's repo record (blue.catbird.mlsChat.profile).
    async fn resolve_from_repo(&self, user_did: &str) -> Result<DsEndpoint, FederationError> {
        let pds_endpoint = self.resolve_did_to_pds(user_did).await?;

        let profile_url = profile_record_url(&pds_endpoint, user_did);

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
        let federation_capabilities =
            super::parse_capabilities_from_json_array(value.get("federationCapabilities"))
                .or_else(|| super::parse_capabilities_from_json_array(value.get("capabilities")));

        Ok(DsEndpoint {
            did: user_did.to_string(),
            endpoint: delivery_service.to_string(),
            supported_cipher_suites: suites,
            federation_capabilities,
        })
    }

    /// Resolve a DID to its PDS endpoint via DID document.
    pub(crate) async fn resolve_did_to_pds(&self, did: &str) -> Result<String, FederationError> {
        let doc = self.fetch_did_document(did).await?;

        let endpoint = extract_service(&doc, "atproto_pds", None).ok_or_else(|| {
            FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: "No #atproto_pds service in DID document".to_string(),
            }
        })?;

        self.validate_remote_url(endpoint).await?;
        Ok(endpoint.to_string())
    }

    /// Fetch and parse a DID document (did:web or did:plc), with SSRF
    /// validation of the document URL.
    async fn fetch_did_document(&self, did: &str) -> Result<serde_json::Value, FederationError> {
        let did_doc_url = if did.starts_with("did:web:") {
            did_web_document_url(did).ok_or_else(|| FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: format!("Invalid did:web identifier: {did}"),
            })?
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

        resp.json()
            .await
            .map_err(|e| FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: format!("Invalid DID document JSON: {e}"),
            })
    }

    /// Resolve authorized device keys for a DID via its PDS.
    pub async fn resolve_authorized_device_keys(
        &self,
        did: &str,
    ) -> Result<Vec<Vec<u8>>, FederationError> {
        let deadline = outbound_timeout();
        let resolution = complete_authority_resolution_with_deadline(
            || self.resolve_did_to_pds(did),
            |pds_endpoint| async move {
                let list_records_url = format!(
                    "{}/xrpc/com.atproto.repo.listRecords",
                    pds_endpoint.trim_end_matches('/')
                );
                let did_owned = did.to_string();
                let http = self.http.clone();

                collect_authoritative_device_key_pages(
                    move |cursor| {
                        let http = http.clone();
                        let list_records_url = list_records_url.clone();
                        let did = did_owned.clone();
                        async move {
                            let mut request = http.get(list_records_url).query(&[
                                ("repo", did.as_str()),
                                ("collection", "blue.catbird.mlsChat.device"),
                                ("limit", AUTHORITY_PAGE_SIZE_PARAM),
                            ]);
                            if let Some(cursor) = cursor.as_deref() {
                                request = request.query(&[("cursor", cursor)]);
                            }

                            let response = request.send().await.map_err(|_| ())?;
                            if !response.status().is_success() {
                                return Err(());
                            }
                            response.json().await.map_err(|_| ())
                        }
                    },
                    deadline,
                )
                .await
                .map_err(|_| FederationError::ResolutionFailed {
                    did: did.to_string(),
                    reason: "PDS device-record pagination was incomplete".to_string(),
                })
            },
            deadline,
        )
        .await;

        resolution.map_err(|_| FederationError::ResolutionFailed {
            did: did.to_string(),
            reason: "PDS device authority resolution exceeded its deadline".to_string(),
        })?
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

fn outbound_timeout() -> Duration {
    let timeout_secs = std::env::var("OUTBOUND_TIMEOUT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(30);
    Duration::from_secs(timeout_secs)
}

async fn complete_authority_resolution_with_deadline<
    ResolvePds,
    ResolveFuture,
    Paginate,
    PaginateFuture,
    PdsEndpoint,
    Output,
    Error,
>(
    resolve_pds: ResolvePds,
    paginate: Paginate,
    deadline: Duration,
) -> Result<Result<Output, Error>, ()>
where
    ResolvePds: FnOnce() -> ResolveFuture,
    ResolveFuture: Future<Output = Result<PdsEndpoint, Error>>,
    Paginate: FnOnce(PdsEndpoint) -> PaginateFuture,
    PaginateFuture: Future<Output = Result<Output, Error>>,
{
    tokio::time::timeout(deadline, async move {
        let pds_endpoint = resolve_pds().await?;
        paginate(pds_endpoint).await
    })
    .await
    .map_err(|_| ())
}

async fn collect_authoritative_device_key_pages<Fetch, FetchFuture>(
    mut fetch_page: Fetch,
    deadline: Duration,
) -> Result<Vec<Vec<u8>>, ()>
where
    Fetch: FnMut(Option<String>) -> FetchFuture,
    FetchFuture: Future<Output = Result<serde_json::Value, ()>>,
{
    tokio::time::timeout(deadline, async move {
        let mut cursor = None;
        let mut seen_cursors = HashSet::new();
        let mut record_count = 0usize;
        let mut authorized_keys = Vec::new();

        for _ in 0..MAX_AUTHORITY_PAGES {
            let body = fetch_page(cursor.clone()).await?;
            let records = body
                .get("records")
                .and_then(serde_json::Value::as_array)
                .ok_or(())?;
            record_count = record_count.checked_add(records.len()).ok_or(())?;
            if record_count > MAX_AUTHORITY_RECORDS {
                return Err(());
            }
            authorized_keys.extend(parse_authoritative_device_keys(&body)?);

            match body.get("cursor") {
                None => return Ok(authorized_keys),
                Some(value) => {
                    let next_cursor = value.as_str().filter(|value| !value.is_empty()).ok_or(())?;
                    if !seen_cursors.insert(next_cursor.to_string()) {
                        return Err(());
                    }
                    cursor = Some(next_cursor.to_string());
                }
            }
        }

        Err(())
    })
    .await
    .map_err(|_| ())?
}

fn parse_authoritative_device_keys(body: &serde_json::Value) -> Result<Vec<Vec<u8>>, ()> {
    use base64::Engine as _;

    let records = body
        .get("records")
        .and_then(|value| value.as_array())
        .ok_or(())?;
    records
        .iter()
        .map(|record| {
            let value = record.get("value").ok_or(())?;
            let algorithm = value
                .get("algorithm")
                .and_then(|value| value.as_str())
                .ok_or(())?;
            let created_at = value
                .get("createdAt")
                .and_then(|value| value.as_str())
                .ok_or(())?;
            chrono::DateTime::parse_from_rfc3339(created_at).map_err(|_| ())?;

            let encoded = value
                .get("mlsSignaturePublicKey")
                .and_then(|value| value.get("$bytes"))
                .and_then(|value| value.as_str())
                .ok_or(())?;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded))
                .map_err(|_| ())?;
            match algorithm {
                "ed25519" => (decoded.len() == 32).then_some(Some(decoded)).ok_or(()),
                "p256" => matches!(decoded.len(), 33 | 65).then_some(None).ok_or(()),
                _ => Err(()),
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|keys| keys.into_iter().flatten().collect())
}

/// Extract the `serviceEndpoint` of the DID-document service whose `id` is
/// `#<fragment>` or `<did>#<fragment>` (suffix match, same semantics as the
/// pre-existing `#atproto_pds` loop). When `required_type` is `Some`, the
/// service's `type` must match exactly; a matching id with the wrong type is
/// logged and treated as not found (ADR-010 D1 rule 2).
fn extract_service<'a>(
    doc: &'a serde_json::Value,
    fragment: &str,
    required_type: Option<&str>,
) -> Option<&'a str> {
    let services = doc.get("service")?.as_array()?;
    let suffix = format!("#{fragment}");
    for svc in services {
        let svc_id = svc.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if !svc_id.ends_with(&suffix) {
            continue;
        }
        if let Some(required) = required_type {
            let svc_type = svc.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if svc_type != required {
                tracing::warn!(
                    service_id = svc_id,
                    service_type = svc_type,
                    required_type = required,
                    "DID document service entry has wrong type; treating as not found"
                );
                continue;
            }
        }
        if let Some(endpoint) = svc.get("serviceEndpoint").and_then(|v| v.as_str()) {
            return Some(endpoint);
        }
    }
    None
}

/// Derive a `did:web` DID from an HTTPS DS endpoint (ADR-010 D1 rules 4-6).
///
/// `https://ds.example.com` → `did:web:ds.example.com`;
/// `https://ds.example.com:8443` → `did:web:ds.example.com%3A8443` (did:web
/// percent-encodes the port colon). Hosts are lowercased. Endpoints with path
/// components or non-HTTPS schemes return `None` — the caller then falls back
/// to legacy user-DID cache keying. Authoritative DS-DID discovery from the
/// mls-ds served well-known DID document is ADR-010 Stage 4; non-did:web DSes
/// are out of scope until then.
fn derive_ds_did_from_https_endpoint(endpoint: &str) -> Option<String> {
    let parsed = url::Url::parse(endpoint).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    let host = parsed.host_str()?.to_ascii_lowercase();
    if !matches!(parsed.path(), "" | "/") {
        return None;
    }
    match parsed.port() {
        Some(port) => Some(format!("did:web:{host}%3A{port}")),
        None => Some(format!("did:web:{host}")),
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
pub(crate) fn validate_endpoint_url(url_str: &str) -> Result<url::Url, FederationError> {
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
        // IPv6 hosts are returned by `host_str()` as bracketed
        // strings (e.g. `[::1]`), which do NOT parse as
        // `std::net::IpAddr`. Use `parsed.host()` to access the typed
        // host enum and inspect the IP variant directly. Without this
        // path, `https://[::1]` slips through the SSRF check.
        let typed_ip: Option<std::net::IpAddr> = match parsed.host() {
            Some(url::Host::Ipv4(v4)) => Some(std::net::IpAddr::V4(v4)),
            Some(url::Host::Ipv6(v6)) => Some(std::net::IpAddr::V6(v6)),
            _ => host.parse::<std::net::IpAddr>().ok(),
        };
        if let Some(ip) = typed_ip {
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

pub(crate) async fn validate_resolved_host_is_public(
    parsed: &url::Url,
) -> Result<(), FederationError> {
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
    use base64::Engine as _;

    fn authoritative_record(key: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "value": {
                "mlsSignaturePublicKey": {
                    "$bytes": base64::engine::general_purpose::STANDARD.encode(key)
                },
                "algorithm": "ed25519",
                "createdAt": "2026-07-15T12:00:00Z"
            }
        })
    }

    #[test]
    fn authoritative_device_keys_accept_complete_ed25519_record() {
        let body = serde_json::json!({"records": [authoritative_record(&[0x41; 32])]});
        assert_eq!(
            parse_authoritative_device_keys(&body),
            Ok(vec![vec![0x41; 32]])
        );
    }

    #[test]
    fn authoritative_device_keys_skip_valid_p256_record_in_mixed_set() {
        let p256 = serde_json::json!({
            "value": {
                "mlsSignaturePublicKey": {
                    "$bytes": base64::engine::general_purpose::STANDARD.encode([0x04; 65])
                },
                "algorithm": "p256",
                "createdAt": "2026-07-15T12:00:00Z"
            }
        });
        let body = serde_json::json!({
            "records": [p256, authoritative_record(&[0x41; 32])]
        });
        assert_eq!(
            parse_authoritative_device_keys(&body),
            Ok(vec![vec![0x41; 32]])
        );
    }

    #[test]
    fn authoritative_device_keys_return_empty_for_p256_only_set() {
        let body = serde_json::json!({
            "records": [{
                "value": {
                    "mlsSignaturePublicKey": {
                        "$bytes": base64::engine::general_purpose::STANDARD.encode([0x04; 65])
                    },
                    "algorithm": "p256",
                    "createdAt": "2026-07-15T12:00:00Z"
                }
            }]
        });
        assert_eq!(parse_authoritative_device_keys(&body), Ok(Vec::new()));
    }

    #[tokio::test]
    async fn authoritative_pagination_retains_ed25519_key_from_second_page() {
        let requested_cursors = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let cursors = requested_cursors.clone();
        let keys = collect_authoritative_device_key_pages(
            move |cursor| {
                cursors.lock().expect("cursor lock").push(cursor.clone());
                std::future::ready(match cursor.as_deref() {
                    None => Ok(serde_json::json!({
                        "records": [{
                            "value": {
                                "mlsSignaturePublicKey": {
                                    "$bytes": base64::engine::general_purpose::STANDARD.encode([0x04; 65])
                                },
                                "algorithm": "p256",
                                "createdAt": "2026-07-15T12:00:00Z"
                            }
                        }],
                        "cursor": "page-2"
                    })),
                    Some("page-2") => Ok(serde_json::json!({
                        "records": [authoritative_record(&[0x42; 32])]
                    })),
                    _ => Err(()),
                })
            },
            std::time::Duration::from_secs(1),
        )
        .await;

        assert_eq!(keys, Ok(vec![vec![0x42; 32]]));
        assert_eq!(
            *requested_cursors.lock().expect("cursor lock"),
            vec![None, Some("page-2".to_string())]
        );
    }

    #[tokio::test]
    async fn authoritative_pagination_rejects_non_progressing_cursor() {
        let result = collect_authoritative_device_key_pages(
            |_| {
                std::future::ready(Ok(serde_json::json!({
                    "records": [],
                    "cursor": "loop"
                })))
            },
            std::time::Duration::from_secs(1),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn authoritative_pagination_rejects_repeated_cursor_cycle() {
        let result = collect_authoritative_device_key_pages(
            |cursor| {
                std::future::ready(Ok(serde_json::json!({
                    "records": [],
                    "cursor": match cursor.as_deref() {
                        None => "page-1",
                        Some("page-1") => "page-2",
                        _ => "page-1",
                    }
                })))
            },
            std::time::Duration::from_secs(1),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn authoritative_pagination_rejects_page_limit_overflow() {
        let page_counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = page_counter.clone();
        let page_limit = collect_authoritative_device_key_pages(
            move |_| {
                let page = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                std::future::ready(Ok(serde_json::json!({
                    "records": [],
                    "cursor": format!("page-{}", page + 1)
                })))
            },
            std::time::Duration::from_secs(1),
        )
        .await;
        assert!(page_limit.is_err());
    }

    #[tokio::test]
    async fn authoritative_pagination_rejects_record_limit_overflow() {
        let records = vec![authoritative_record(&[0x41; 32]); MAX_AUTHORITY_RECORDS + 1];
        let record_limit = collect_authoritative_device_key_pages(
            move |_| {
                let records = records.clone();
                std::future::ready(Ok(serde_json::json!({
                    "records": records
                })))
            },
            std::time::Duration::from_secs(1),
        )
        .await;
        assert!(record_limit.is_err());
    }

    #[tokio::test]
    async fn authoritative_pagination_enforces_overall_deadline() {
        let result = collect_authoritative_device_key_pages(
            |_| std::future::pending::<Result<serde_json::Value, ()>>(),
            std::time::Duration::from_millis(1),
        )
        .await;
        assert!(result.is_err());
    }

    #[allow(clippy::redundant_closure)]
    #[tokio::test]
    async fn authority_deadline_includes_pre_pagination_resolution() {
        let pagination_started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started = pagination_started.clone();
        let result = complete_authority_resolution_with_deadline(
            || std::future::pending::<Result<String, ()>>(),
            move |_| {
                started.store(true, std::sync::atomic::Ordering::SeqCst);
                std::future::ready(Ok(()))
            },
            std::time::Duration::from_millis(1),
        )
        .await;
        assert!(result.is_err());
        assert!(!pagination_started.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn authoritative_device_keys_reject_mixed_valid_and_malformed_records() {
        let body = serde_json::json!({
            "records": [
                authoritative_record(&[0x41; 32]),
                {"value": {"mlsSignaturePublicKey": {"$bytes": "not-base64"}}}
            ]
        });
        assert!(parse_authoritative_device_keys(&body).is_err());
    }

    #[test]
    fn authoritative_device_keys_reject_missing_or_wrong_length_keys() {
        for body in [
            serde_json::json!({"records": [{"value": {}}]}),
            serde_json::json!({"records": [{"value": {"mlsSignaturePublicKey": {"$bytes": base64::engine::general_purpose::STANDARD.encode([0x41; 31])}}}]}),
            serde_json::json!({}),
        ] {
            assert!(parse_authoritative_device_keys(&body).is_err());
        }
    }

    #[test]
    fn authoritative_device_keys_reject_missing_or_invalid_metadata() {
        let encoded = base64::engine::general_purpose::STANDARD.encode([0x41; 32]);
        for body in [
            serde_json::json!({"records": [{"value": {"mlsSignaturePublicKey": {"$bytes": encoded}, "createdAt": "2026-07-15T12:00:00Z"}}]}),
            serde_json::json!({"records": [{"value": {"mlsSignaturePublicKey": {"$bytes": encoded}, "algorithm": "p256", "createdAt": "2026-07-15T12:00:00Z"}}]}),
            serde_json::json!({"records": [{"value": {"mlsSignaturePublicKey": {"$bytes": encoded}, "algorithm": "ed25519"}}]}),
            serde_json::json!({"records": [{"value": {"mlsSignaturePublicKey": {"$bytes": encoded}, "algorithm": "ed25519", "createdAt": "not-a-datetime"}}]}),
        ] {
            assert!(parse_authoritative_device_keys(&body).is_err());
        }
    }
    use sqlx::postgres::PgPoolOptions;
    use std::net::IpAddr;
    use uuid::Uuid;

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
                "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".to_string()
            ]),
            federation_capabilities: Some(vec![
                "baseline".to_string(),
                "reconciliation-v1".to_string(),
            ]),
        };
        let cloned = ep.clone();
        assert_eq!(cloned.did, ep.did);
        assert_eq!(cloned.endpoint, ep.endpoint);
        assert_eq!(cloned.supported_cipher_suites, ep.supported_cipher_suites);
        assert_eq!(cloned.federation_capabilities, ep.federation_capabilities);
    }

    #[test]
    fn test_profile_record_url_uses_supported_collection_and_rkey() {
        let url = profile_record_url("https://pds.example.com", "did:plc:alice:123");
        let parsed = url::Url::parse(&url).expect("valid URL");
        let query: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();

        assert_eq!(query.get("repo"), Some(&"did:plc:alice:123".to_string()));
        assert_eq!(
            query.get("collection"),
            Some(&PROFILE_COLLECTION.to_string())
        );
        assert_eq!(query.get("rkey"), Some(&PROFILE_RKEY.to_string()));
    }

    // -- extract_service tests --

    fn doc_with_services(services: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "id": "did:plc:alice", "service": services })
    }

    #[test]
    fn test_extract_service_relative_id() {
        let doc = doc_with_services(serde_json::json!([
            {
                "id": "#atproto_mls",
                "type": "AtprotoMLSDeliveryService",
                "serviceEndpoint": "https://ds.example.com"
            }
        ]));
        assert_eq!(
            extract_service(&doc, "atproto_mls", Some("AtprotoMLSDeliveryService")),
            Some("https://ds.example.com")
        );
    }

    #[test]
    fn test_extract_service_absolute_id() {
        let doc = doc_with_services(serde_json::json!([
            {
                "id": "did:plc:alice#atproto_mls",
                "type": "AtprotoMLSDeliveryService",
                "serviceEndpoint": "https://ds.example.com"
            }
        ]));
        assert_eq!(
            extract_service(&doc, "atproto_mls", Some("AtprotoMLSDeliveryService")),
            Some("https://ds.example.com")
        );
    }

    #[test]
    fn test_extract_service_wrong_type_skipped() {
        let doc = doc_with_services(serde_json::json!([
            {
                "id": "#atproto_mls",
                "type": "SomeOtherService",
                "serviceEndpoint": "https://ds.example.com"
            }
        ]));
        assert_eq!(
            extract_service(&doc, "atproto_mls", Some("AtprotoMLSDeliveryService")),
            None
        );
    }

    #[test]
    fn test_extract_service_wrong_type_then_correct_entry() {
        let doc = doc_with_services(serde_json::json!([
            {
                "id": "did:plc:alice#atproto_mls",
                "type": "SomeOtherService",
                "serviceEndpoint": "https://wrong.example.com"
            },
            {
                "id": "#atproto_mls",
                "type": "AtprotoMLSDeliveryService",
                "serviceEndpoint": "https://right.example.com"
            }
        ]));
        assert_eq!(
            extract_service(&doc, "atproto_mls", Some("AtprotoMLSDeliveryService")),
            Some("https://right.example.com")
        );
    }

    #[test]
    fn test_extract_service_missing_entry() {
        let doc = doc_with_services(serde_json::json!([
            {
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://pds.example.com"
            }
        ]));
        assert_eq!(
            extract_service(&doc, "atproto_mls", Some("AtprotoMLSDeliveryService")),
            None
        );
    }

    #[test]
    fn test_extract_service_no_service_array() {
        let doc = serde_json::json!({ "id": "did:plc:alice" });
        assert_eq!(extract_service(&doc, "atproto_mls", None), None);
    }

    #[test]
    fn test_extract_service_atproto_pds_without_type_check() {
        // The refactored resolve_did_to_pds path: no type requirement,
        // suffix-match id semantics preserved.
        let doc = doc_with_services(serde_json::json!([
            {
                "id": "did:web:user.example.com#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://pds.example.com"
            }
        ]));
        assert_eq!(
            extract_service(&doc, "atproto_pds", None),
            Some("https://pds.example.com")
        );
    }

    // -- derive_ds_did_from_https_endpoint tests --

    #[test]
    fn test_derive_ds_did_simple_host() {
        assert_eq!(
            derive_ds_did_from_https_endpoint("https://ds.example.com"),
            Some("did:web:ds.example.com".to_string())
        );
    }

    #[test]
    fn test_derive_ds_did_lowercases_host() {
        assert_eq!(
            derive_ds_did_from_https_endpoint("https://DS.Example.COM"),
            Some("did:web:ds.example.com".to_string())
        );
    }

    #[test]
    fn test_derive_ds_did_encodes_port() {
        assert_eq!(
            derive_ds_did_from_https_endpoint("https://ds.example.com:8443"),
            Some("did:web:ds.example.com%3A8443".to_string())
        );
    }

    #[test]
    fn test_derive_ds_did_rejects_path() {
        assert_eq!(
            derive_ds_did_from_https_endpoint("https://ds.example.com/mls"),
            None
        );
    }

    #[test]
    fn test_derive_ds_did_allows_bare_trailing_slash() {
        assert_eq!(
            derive_ds_did_from_https_endpoint("https://ds.example.com/"),
            Some("did:web:ds.example.com".to_string())
        );
    }

    #[test]
    fn test_derive_ds_did_rejects_http() {
        assert_eq!(
            derive_ds_did_from_https_endpoint("http://ds.example.com"),
            None
        );
    }

    // -- resolve ordering tests --

    #[tokio::test]
    async fn test_resolve_self_outcome() {
        // The self path never touches the pool, so a lazy (unconnected) pool
        // is sufficient.
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/nonexistent_resolver_test")
            .expect("lazy pool");
        let resolver = DsResolver::new(
            pool,
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
            3600,
        );
        let (result, outcome) = resolver
            .resolve_with_outcome("did:web:self.example.com")
            .await;
        assert_eq!(outcome, "self");
        let endpoint = result.expect("self resolution succeeds");
        assert_eq!(endpoint.endpoint, "https://self.example.com");
        assert!(endpoint.federation_capabilities.is_some());
    }

    #[tokio::test]
    async fn test_resolve_fresh_cache_short_circuits() {
        let Some(pool) = setup_cache_test_pool().await else {
            eprintln!("Skipping cache test: TEST_DATABASE_URL not set");
            return;
        };

        let resolver = DsResolver::new(
            pool,
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            Some("https://default-ds.example.com".to_string()),
            3600,
        );

        // did:key is an unsupported DID method: if the fresh-cache
        // short-circuit failed, the live paths would error without touching
        // the network, and we'd see a different outcome.
        let did = format!("did:key:{}", Uuid::new_v4().as_simple());
        resolver
            .cache_endpoint(&DsEndpoint {
                did: did.clone(),
                endpoint: "https://cached-ds.example.com".to_string(),
                supported_cipher_suites: None,
                federation_capabilities: None,
            })
            .await
            .expect("cache insert succeeds");

        let (result, outcome) = resolver.resolve_with_outcome(&did).await;
        assert_eq!(outcome, "cache_fresh");
        assert_eq!(
            result.expect("resolution succeeds").endpoint,
            "https://cached-ds.example.com"
        );
    }

    #[tokio::test]
    async fn test_resolve_expired_cache_degraded_after_live_failure() {
        let Some(pool) = setup_cache_test_pool().await else {
            eprintln!("Skipping cache test: TEST_DATABASE_URL not set");
            return;
        };

        let resolver = DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            // default_ds is set: degraded mode must win over the default.
            Some("https://default-ds.example.com".to_string()),
            3600,
        );

        // Unsupported DID method → both live paths fail fast, offline.
        let did = format!("did:key:{}", Uuid::new_v4().as_simple());
        sqlx::query(
            "INSERT INTO ds_endpoints (did, endpoint, supported_cipher_suites, resolved_at, expires_at) \
             VALUES ($1, $2, NULL, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour')",
        )
        .bind(&did)
        .bind("https://stale-ds.example.com")
        .execute(&pool)
        .await
        .expect("expired row insert succeeds");

        let (result, outcome) = resolver.resolve_with_outcome(&did).await;
        assert_eq!(outcome, "cache_stale_degraded");
        assert_eq!(
            result.expect("degraded resolution succeeds").endpoint,
            "https://stale-ds.example.com"
        );
    }

    #[tokio::test]
    async fn test_resolve_default_fallback_when_no_cache() {
        let Some(pool) = setup_cache_test_pool().await else {
            eprintln!("Skipping cache test: TEST_DATABASE_URL not set");
            return;
        };

        let resolver = DsResolver::new(
            pool,
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            Some("https://default-ds.example.com".to_string()),
            3600,
        );

        let did = format!("did:key:{}", Uuid::new_v4().as_simple());
        let (result, outcome) = resolver.resolve_with_outcome(&did).await;
        assert_eq!(outcome, "default_fallback");
        assert_eq!(
            result.expect("default fallback succeeds").endpoint,
            "https://default-ds.example.com"
        );
    }

    #[tokio::test]
    async fn test_resolve_hard_failure_without_default() {
        let Some(pool) = setup_cache_test_pool().await else {
            eprintln!("Skipping cache test: TEST_DATABASE_URL not set");
            return;
        };

        let resolver = DsResolver::new(
            pool,
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
            3600,
        );

        let did = format!("did:key:{}", Uuid::new_v4().as_simple());
        let (result, outcome) = resolver.resolve_with_outcome(&did).await;
        assert_eq!(outcome, "hard_failure");
        assert!(matches!(
            result,
            Err(FederationError::EndpointNotFound { .. })
        ));
    }

    async fn setup_cache_test_pool() -> Option<PgPool> {
        let database_url = std::env::var("TEST_DATABASE_URL").ok()?;
        let pool = match PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
        {
            Ok(pool) => pool,
            Err(err) => {
                eprintln!("Skipping cache test: failed to connect to TEST_DATABASE_URL ({err})");
                return None;
            }
        };

        if let Err(err) = sqlx::query(
            "CREATE TABLE IF NOT EXISTS ds_endpoints (
                did TEXT PRIMARY KEY,
                endpoint TEXT NOT NULL,
                supported_cipher_suites TEXT,
                resolved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour'
            )",
        )
        .execute(&pool)
        .await
        {
            eprintln!("Skipping cache test: unable to ensure ds_endpoints table ({err})");
            return None;
        }

        Some(pool)
    }

    #[tokio::test]
    async fn test_cache_refresh_and_invalidate() {
        let Some(pool) = setup_cache_test_pool().await else {
            eprintln!("Skipping cache test: TEST_DATABASE_URL not set");
            return;
        };

        let resolver = DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
            3600,
        );

        let did = format!("did:plc:{}", Uuid::new_v4().as_simple());
        let first = DsEndpoint {
            did: did.clone(),
            endpoint: "https://ds-one.example.com".to_string(),
            supported_cipher_suites: Some(vec!["suite-a".to_string()]),
            federation_capabilities: Some(vec!["baseline".to_string()]),
        };
        resolver
            .cache_endpoint(&first)
            .await
            .expect("cache insert succeeds");
        let cached = resolver
            .get_cached(&did)
            .await
            .expect("cache read succeeds")
            .expect("cache entry exists");
        assert_eq!(cached.endpoint, first.endpoint);

        let refreshed = DsEndpoint {
            did: did.clone(),
            endpoint: "https://ds-two.example.com".to_string(),
            supported_cipher_suites: Some(vec!["suite-b".to_string(), "suite-c".to_string()]),
            federation_capabilities: Some(vec!["reconciliation-v1".to_string()]),
        };
        resolver
            .cache_endpoint(&refreshed)
            .await
            .expect("cache refresh succeeds");
        let cached_refreshed = resolver
            .get_cached(&did)
            .await
            .expect("cache read succeeds")
            .expect("cache entry exists");
        assert_eq!(cached_refreshed.endpoint, refreshed.endpoint);
        assert_eq!(
            cached_refreshed.supported_cipher_suites,
            refreshed.supported_cipher_suites
        );
        assert!(cached_refreshed.federation_capabilities.is_none());

        resolver
            .invalidate(&did)
            .await
            .expect("cache invalidation succeeds");
        let after_invalidate = resolver
            .get_cached(&did)
            .await
            .expect("cache read succeeds");
        assert!(after_invalidate.is_none());
    }
}
