use sqlx::PgPool;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tracing::{debug, info};

use super::errors::{FederationError, ResolutionFailureKind};
use crate::identity::{canonical_did, did_web_document_url, did_web_service_endpoint};
use crate::util::outbound_body::{
    decode_json_bounded, ResponseBodyBudget, DID_DOCUMENT_MAX_BYTES, PROFILE_OR_DEVICE_MAX_BYTES,
};

const DECLARATION_COLLECTION: &str = "blue.catbird.chat.declaration";
const DECLARATION_RKEY: &str = "self";
const PROFILE_COLLECTION: &str = "blue.catbird.chat.profile";
const PROFILE_RKEY: &str = "self";
const AUTHORITY_PAGE_SIZE: usize = 100;
const AUTHORITY_PAGE_SIZE_PARAM: &str = "100";
const MAX_AUTHORITY_PAGES: usize = 10;
const MAX_AUTHORITY_RECORDS: usize = AUTHORITY_PAGE_SIZE * MAX_AUTHORITY_PAGES;

fn repo_record_url(pds_endpoint: &str, user_did: &str, collection: &str, rkey: &str) -> String {
    format!(
        "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection={}&rkey={}",
        pds_endpoint.trim_end_matches('/'),
        urlencoding::encode(user_did),
        urlencoding::encode(collection),
        urlencoding::encode(rkey)
    )
}

fn profile_record_url(pds_endpoint: &str, user_did: &str) -> String {
    repo_record_url(pds_endpoint, user_did, PROFILE_COLLECTION, PROFILE_RKEY)
}

fn declaration_record_url(pds_endpoint: &str, user_did: &str) -> String {
    repo_record_url(
        pds_endpoint,
        user_did,
        DECLARATION_COLLECTION,
        DECLARATION_RKEY,
    )
}

/// Validate a canonical DID identifier according to ATProto and federation rules.
///
/// Rules:
/// 1. Must be non-empty, trimmed, with no whitespace or fragment (`#`).
/// 2. Must not have trailing colon (`:`).
/// 3. Must parse via ATProto parser (`jacquard_common::types::string::Did`).
/// 4. Supported DID methods: exact `did:plc:` and hostname-level `did:web:`.
/// 5. `did:plc:` must have exactly 24 lowercase base32 characters (`did:plc:[a-z2-7]{24}`).
/// 6. `did:web:` must be hostname-level only (no path segments).
///    - No public port in production; development port on localhost allowed only under APP_ENV=test.
///    - Hostname must be valid with no special or malformed characters.
/// 7. Canonical round-trip must match: `canonical_did(raw) == raw`.
pub fn validate_canonical_did_web_host(host: &str, raw: &str) -> Result<String, FederationError> {
    if host.is_empty() {
        return Err(FederationError::ResolutionFailed {
            did: raw.to_string(),
            kind: ResolutionFailureKind::InvalidDid(format!("Empty host in did:web: '{raw}'")),
        });
    }

    // Reject uppercase characters
    if host.chars().any(char::is_uppercase) {
        return Err(FederationError::ResolutionFailed {
            did: raw.to_string(),
            kind: ResolutionFailureKind::InvalidDid(format!(
                "did:web host must be lowercase ASCII: '{raw}'"
            )),
        });
    }

    // Reject percent-encoding
    if host.contains('%') {
        return Err(FederationError::ResolutionFailed {
            did: raw.to_string(),
            kind: ResolutionFailureKind::InvalidDid(format!(
                "did:web host must not contain percent-encoding: '{raw}'"
            )),
        });
    }

    // Reject path, query, fragment, auth delimiters
    if host.contains('/')
        || host.contains('\\')
        || host.contains('?')
        || host.contains('#')
        || host.contains('@')
    {
        return Err(FederationError::ResolutionFailed {
            did: raw.to_string(),
            kind: ResolutionFailureKind::InvalidDid(format!(
                "did:web host contains forbidden path/auth delimiter: '{raw}'"
            )),
        });
    }

    // Check for port in production vs test
    let (hostname, port_opt) = if let Some((h, p_str)) = host.split_once(':') {
        let p = p_str
            .parse::<u16>()
            .map_err(|_| FederationError::ResolutionFailed {
                did: raw.to_string(),
                kind: ResolutionFailureKind::InvalidDid(format!(
                    "Invalid port in did:web: '{raw}'"
                )),
            })?;
        if p == 0 {
            return Err(FederationError::ResolutionFailed {
                did: raw.to_string(),
                kind: ResolutionFailureKind::InvalidDid(format!("Zero port in did:web: '{raw}'")),
            });
        }
        (h, Some(p))
    } else {
        (host, None)
    };

    let is_app_env_test = std::env::var("APP_ENV")
        .map(|v| v.eq_ignore_ascii_case("test"))
        .unwrap_or(false);
    let is_localhost = hostname.eq_ignore_ascii_case("localhost")
        || hostname == "127.0.0.1"
        || hostname.to_ascii_lowercase().ends_with(".localhost");

    if port_opt.is_some() {
        if !(is_app_env_test && allow_insecure_http() && is_localhost) {
            return Err(FederationError::ResolutionFailed {
                did: raw.to_string(),
                kind: ResolutionFailureKind::InvalidDid(format!(
                    "Port in did:web is only allowed for localhost in test environment: '{raw}'"
                )),
            });
        }
    }

    // Reject trailing dot, leading dot, consecutive dots
    if hostname.starts_with('.') || hostname.ends_with('.') {
        return Err(FederationError::ResolutionFailed {
            did: raw.to_string(),
            kind: ResolutionFailureKind::InvalidDid(format!(
                "did:web host must not have leading or trailing dot: '{raw}'"
            )),
        });
    }

    if hostname.contains("..") {
        return Err(FederationError::ResolutionFailed {
            did: raw.to_string(),
            kind: ResolutionFailureKind::InvalidDid(format!(
                "did:web host must not contain empty labels: '{raw}'"
            )),
        });
    }

    if hostname.len() > 253 {
        return Err(FederationError::ResolutionFailed {
            did: raw.to_string(),
            kind: ResolutionFailureKind::InvalidDid(format!(
                "did:web host exceeds 253 characters: '{raw}'"
            )),
        });
    }

    // Validate DNS labels
    let labels: Vec<&str> = hostname.split('.').collect();
    if labels.is_empty() {
        return Err(FederationError::ResolutionFailed {
            did: raw.to_string(),
            kind: ResolutionFailureKind::InvalidDid(format!("did:web host has no labels: '{raw}'")),
        });
    }

    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err(FederationError::ResolutionFailed {
                did: raw.to_string(),
                kind: ResolutionFailureKind::InvalidDid(format!(
                    "Invalid label length in did:web host: '{raw}'"
                )),
            });
        }

        // Reject underscores
        if label.contains('_') {
            return Err(FederationError::ResolutionFailed {
                did: raw.to_string(),
                kind: ResolutionFailureKind::InvalidDid(format!(
                    "did:web host labels must not contain underscores: '{raw}'"
                )),
            });
        }

        // Reject leading or trailing hyphens in labels
        if label.starts_with('-') || label.ends_with('-') {
            return Err(FederationError::ResolutionFailed {
                did: raw.to_string(),
                kind: ResolutionFailureKind::InvalidDid(format!(
                    "did:web host label has leading or trailing hyphen: '{raw}'"
                )),
            });
        }

        // Reject non-alphanumeric/hyphen characters
        if !label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(FederationError::ResolutionFailed {
                did: raw.to_string(),
                kind: ResolutionFailureKind::InvalidDid(format!(
                    "did:web host label contains invalid characters: '{raw}'"
                )),
            });
        }
    }

    // Lowercase / IDNA roundtrip check via url::Host parser
    let host_parsed =
        url::Host::parse(hostname).map_err(|e| FederationError::ResolutionFailed {
            did: raw.to_string(),
            kind: ResolutionFailureKind::InvalidDid(format!(
                "IDNA host parsing failed for did:web host '{hostname}': {e}"
            )),
        })?;
    if let url::Host::Domain(domain) = &host_parsed {
        if domain != hostname {
            return Err(FederationError::ResolutionFailed {
                did: raw.to_string(),
                kind: ResolutionFailureKind::InvalidDid(format!("did:web host does not match canonical IDNA ASCII representation: '{hostname}' vs '{domain}'")),
            });
        }
    }

    // URL parser check
    let check_url = url::Url::parse(&format!("https://{host}")).map_err(|e| {
        FederationError::ResolutionFailed {
            did: raw.to_string(),
            kind: ResolutionFailureKind::InvalidDid(format!(
                "URL parsing failed for did:web host '{host}': {e}"
            )),
        }
    })?;
    if check_url.host_str().unwrap_or("") != hostname {
        return Err(FederationError::ResolutionFailed {
            did: raw.to_string(),
            kind: ResolutionFailureKind::InvalidDid(format!(
                "URL parsed host does not match did:web host: '{host}'"
            )),
        });
    }

    let canonical = crate::identity::canonical_did(raw);
    if canonical != raw {
        return Err(FederationError::ResolutionFailed {
            did: raw.to_string(),
            kind: ResolutionFailureKind::InvalidDid(format!(
                "did:web not in canonical form: '{raw}'"
            )),
        });
    }

    Ok(canonical.to_string())
}

pub fn validate_canonical_did(raw: &str) -> Result<String, FederationError> {
    if raw.is_empty() || raw.trim() != raw || raw.chars().any(char::is_whitespace) {
        return Err(FederationError::ResolutionFailed {
            did: raw.to_string(),
            kind: ResolutionFailureKind::InvalidDid(format!(
                "DID cannot contain whitespace or be empty: '{raw}'"
            )),
        });
    }

    if raw.contains('#') {
        return Err(FederationError::ResolutionFailed {
            did: raw.to_string(),
            kind: ResolutionFailureKind::InvalidDid(format!(
                "DID must be a base DID without fragment: '{raw}'"
            )),
        });
    }

    if raw.ends_with(':') {
        return Err(FederationError::ResolutionFailed {
            did: raw.to_string(),
            kind: ResolutionFailureKind::InvalidDid(format!(
                "DID cannot have trailing colon: '{raw}'"
            )),
        });
    }

    // 1. ATProto DID parser check
    let _parsed = jacquard_common::types::string::Did::new(raw).map_err(|e| {
        FederationError::ResolutionFailed {
            did: raw.to_string(),
            kind: ResolutionFailureKind::InvalidDid(format!("Invalid ATProto DID syntax: {e}")),
        }
    })?;

    // 2. Exact did:plc validation
    if let Some(plc_suffix) = raw.strip_prefix("did:plc:") {
        if plc_suffix.len() != 24
            || !plc_suffix
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
        {
            return Err(FederationError::ResolutionFailed {
                did: raw.to_string(),
                kind: ResolutionFailureKind::InvalidDid(format!("Invalid did:plc format: '{raw}'")),
            });
        }
        return Ok(raw.to_string());
    }

    // 3. Hostname-level did:web validation
    if let Some(web_suffix) = raw.strip_prefix("did:web:") {
        return validate_canonical_did_web_host(web_suffix, raw);
    }

    Err(FederationError::ResolutionFailed {
        did: raw.to_string(),
        kind: ResolutionFailureKind::InvalidDid(format!("Unsupported DID method: '{raw}'")),
    })
}
/// Validate a declaration record's `deliveryService` field.
pub fn validate_declaration_delivery_service(raw: &str) -> Result<String, FederationError> {
    validate_canonical_did(raw)
}

/// Validate a `blue.catbird.chat.declaration` record value object.
///
/// Returns `(canonical_delivery_service_did, allow_incoming)` on success.
pub fn validate_declaration_record_value(
    value: &serde_json::Map<String, serde_json::Value>,
) -> Result<(String, String), FederationError> {
    // 1. Exact $type: bare NSID only
    let record_type = value.get("$type").and_then(|t| t.as_str()).ok_or_else(|| {
        FederationError::ResolutionFailed {
            did: String::new(),
            kind: ResolutionFailureKind::InvalidDeclaration(
                "Declaration record missing $type".to_string(),
            ),
        }
    })?;
    if record_type != "blue.catbird.chat.declaration" {
        return Err(FederationError::ResolutionFailed {
            did: String::new(),
            kind: ResolutionFailureKind::InvalidDeclaration(format!(
                "Declaration record invalid $type: '{record_type}' (expected exact 'blue.catbird.chat.declaration')"
            )),
        });
    }

    // 2. protocolVersion == "1"
    let protocol_version = value
        .get("protocolVersion")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::ResolutionFailed {
            did: String::new(),
            kind: ResolutionFailureKind::InvalidDeclaration(
                "Declaration record missing protocolVersion".to_string(),
            ),
        })?;
    if protocol_version != "1" {
        return Err(FederationError::ResolutionFailed {
            did: String::new(),
            kind: ResolutionFailureKind::InvalidDeclaration(format!(
                "Unsupported declaration protocolVersion: '{protocol_version}'"
            )),
        });
    }

    // 3. createdAt RFC3339 datetime
    let created_at = value
        .get("createdAt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::ResolutionFailed {
            did: String::new(),
            kind: ResolutionFailureKind::InvalidDeclaration(
                "Declaration record missing createdAt".to_string(),
            ),
        })?;
    if chrono::DateTime::parse_from_rfc3339(created_at).is_err() {
        return Err(FederationError::ResolutionFailed {
            did: String::new(),
            kind: ResolutionFailureKind::InvalidDeclaration(format!(
                "Declaration record invalid RFC3339 createdAt: '{created_at}'"
            )),
        });
    }

    // 4. allowIncoming required field (schema verification only, not routing authz)
    let allow_incoming = value
        .get("allowIncoming")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::ResolutionFailed {
            did: String::new(),
            kind: ResolutionFailureKind::InvalidDeclaration(
                "Declaration record missing allowIncoming".to_string(),
            ),
        })?;

    // 5. deliveryService base DID
    let delivery_service_raw = value
        .get("deliveryService")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::ResolutionFailed {
            did: String::new(),
            kind: ResolutionFailureKind::InvalidDeclaration(
                "Declaration record missing deliveryService".to_string(),
            ),
        })?;

    let canonical_ds_did = validate_declaration_delivery_service(delivery_service_raw)?;

    Ok((canonical_ds_did, allow_incoming.to_string()))
}

/// Cached DS endpoint information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsEndpoint {
    pub did: String,
    pub endpoint: String,
    pub supported_cipher_suites: Option<Vec<String>>,
    pub federation_capabilities: Option<Vec<String>>,
}

pub type DestinationResolverFn = Arc<
    dyn Fn(
            &str,
        ) -> Option<
            Pin<
                Box<
                    dyn Future<Output = Result<ValidatedRemoteDestination, FederationError>> + Send,
                >,
            >,
        > + Send
        + Sync,
>;

/// Resolves a user's DID to their DS endpoint.
#[derive(Clone)]
pub struct DsResolver {
    pool: PgPool,
    http: reqwest::Client,
    self_did: String,
    self_endpoint: String,
    default_ds_did: Option<String>,
    default_ds_endpoint: Option<String>,
    cache_ttl_secs: i64,
    destination_resolver: Option<DestinationResolverFn>,
}

impl std::fmt::Debug for DsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DsResolver")
            .field("self_did", &self.self_did)
            .field("self_endpoint", &self.self_endpoint)
            .field("default_ds_did", &self.default_ds_did)
            .field("default_ds_endpoint", &self.default_ds_endpoint)
            .field("cache_ttl_secs", &self.cache_ttl_secs)
            .finish()
    }
}

impl DsResolver {
    pub fn new(
        pool: PgPool,
        http: reqwest::Client,
        self_did: String,
        self_endpoint: String,
        default_ds: Option<(String, String)>,
        cache_ttl_secs: u64,
    ) -> Self {
        let (resolved_default_did, resolved_default_endpoint) = match default_ds {
            Some((did, ep)) => (Some(canonical_did(&did).to_string()), Some(ep)),
            None => (None, None),
        };

        Self {
            pool,
            http,
            self_did,
            self_endpoint,
            default_ds_did: resolved_default_did,
            default_ds_endpoint: resolved_default_endpoint,
            cache_ttl_secs: cache_ttl_secs as i64,
            destination_resolver: None,
        }
    }

    pub fn with_destination_resolver_hook(mut self, hook: DestinationResolverFn) -> Self {
        self.destination_resolver = Some(hook);
        self
    }

    pub fn with_defaults(
        pool: PgPool,
        http: reqwest::Client,
        self_did: String,
        self_endpoint: String,
        default_ds_did: Option<String>,
        default_ds_endpoint: Option<String>,
        cache_ttl_secs: u64,
    ) -> Self {
        let default_ds = match (default_ds_did, default_ds_endpoint) {
            (Some(did), Some(ep)) => Some((did, ep)),
            (Some(did), None) => {
                let ep = did_web_service_endpoint(&did).unwrap_or_else(|| format!("https://{did}"));
                Some((did, ep))
            }
            (None, Some(ep)) => {
                let derived = derive_ds_did_from_https_endpoint(&ep).unwrap_or_else(|| {
                    let host = ep
                        .trim_start_matches("https://")
                        .trim_start_matches("http://")
                        .trim_end_matches('/');
                    format!("did:web:{host}")
                });
                Some((derived, ep))
            }
            (None, None) => None,
        };
        Self::new(
            pool,
            http,
            self_did,
            self_endpoint,
            default_ds,
            cache_ttl_secs,
        )
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
    /// service entry → `blue.catbird.chat.declaration` repo record →
    /// `blue.catbird.chat.profile` legacy repo record →
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
                if let Err(e) = self.cache_mapping(user_did, &endpoint).await {
                    return (Err(e), "hard_failure");
                }
                return (Ok(endpoint), "did_doc");
            }
            Err(e) => {
                debug!(did = %crate::crypto::redact_for_log(user_did), error = %e, "DID-document #atproto_mls resolution failed, trying declaration record");
            }
        }

        // Declaration record (blue.catbird.chat.declaration/self)
        match self.resolve_from_declaration(user_did).await {
            Ok(endpoint) => {
                if let Err(e) = self.cache_mapping(user_did, &endpoint).await {
                    return (Err(e), "hard_failure");
                }
                return (Ok(endpoint), "declaration");
            }
            Err(e) => {
                debug!(did = %crate::crypto::redact_for_log(user_did), error = %e, "Declaration record resolution failed, trying legacy profile record");
            }
        }

        // Profile record fallback (blue.catbird.chat.profile)
        match self.resolve_from_repo(user_did).await {
            Ok(endpoint) => {
                if let Err(e) = self.cache_mapping(user_did, &endpoint).await {
                    return (Err(e), "hard_failure");
                }
                return (Ok(endpoint), "profile_record");
            }
            Err(e) => {
                debug!(did = %crate::crypto::redact_for_log(user_did), error = %e, "Repo profile resolution failed, trying fallback");
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

        // Fallback to default DS (ACTOR default ONLY)
        if let (Some(default_did), Some(default_ep)) =
            (&self.default_ds_did, &self.default_ds_endpoint)
        {
            info!(
                did = %crate::crypto::redact_for_log(user_did),
                default_ds_did = %default_did,
                default_ds_endpoint = %default_ep,
                "Using default DS fallback for actor"
            );
            return (
                Ok(DsEndpoint {
                    did: default_did.clone(),
                    endpoint: default_ep.clone(),
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

    /// Resolve a DS DID directly to a DS endpoint without default fallback.
    ///
    /// Required by reconciliation, upstream, and outbound retry queue.
    /// Returns an error if the DS DID cannot be resolved.
    pub async fn resolve_ds_did(&self, ds_did: &str) -> Result<DsEndpoint, FederationError> {
        let canonical = canonical_did(ds_did);
        if canonical.is_empty() {
            return Err(FederationError::ResolutionFailed {
                did: ds_did.to_string(),
                kind: ResolutionFailureKind::InvalidDid("Empty DS DID".to_string()),
            });
        }

        // 1. Self check
        if self.is_self(canonical) {
            return Ok(DsEndpoint {
                did: self.self_did.clone(),
                endpoint: self.self_endpoint.clone(),
                supported_cipher_suites: None,
                federation_capabilities: Some(super::local_federation_capabilities()),
            });
        }

        // 2. Fresh cache check directly on ds_endpoints
        if let Ok(Some(cached)) = self.get_cached_ds_endpoint(canonical).await {
            if cached.did == canonical {
                return Ok(cached);
            }
        }
        // 3. Live resolution
        let endpoint_url = self.resolve_ds_did_to_endpoint(canonical).await?;
        let endpoint = DsEndpoint {
            did: canonical.to_string(),
            endpoint: endpoint_url,
            supported_cipher_suites: None,
            federation_capabilities: None,
        };

        // Cache in ds_endpoints
        let _ = self.cache_endpoint(&endpoint).await;

        Ok(endpoint)
    }

    /// Resolve a DS DID to a validated remote destination with pinned socket addrs.
    pub async fn resolve_ds_destination(
        &self,
        ds_did: &str,
    ) -> Result<ValidatedRemoteDestination, FederationError> {
        if let Some(hook) = &self.destination_resolver {
            if let Some(fut) = hook(ds_did) {
                return fut.await;
            }
        }
        let endpoint = self.resolve_ds_did(ds_did).await?;
        if let Some(hook) = &self.destination_resolver {
            if let Some(fut) = hook(&endpoint.endpoint) {
                return fut.await;
            }
        }
        validate_and_resolve_destination(&endpoint.endpoint, None).await
    }

    /// Resolve an endpoint URL directly to a validated remote destination with pinned socket addrs.
    pub async fn resolve_endpoint_destination(
        &self,
        endpoint_url: &str,
    ) -> Result<ValidatedRemoteDestination, FederationError> {
        if let Some(hook) = &self.destination_resolver {
            if let Some(fut) = hook(endpoint_url) {
                return fut.await;
            }
        }
        validate_and_resolve_destination(endpoint_url, None).await
    }

    /// Look up cached endpoint for an actor DID from did_ds_mappings joined with ds_endpoints.
    async fn get_cached(&self, actor_did: &str) -> Result<Option<DsEndpoint>, FederationError> {
        let canonical = canonical_did(actor_did);
        let row = sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT e.did, e.endpoint, e.supported_cipher_suites \
             FROM did_ds_mappings m \
             JOIN ds_endpoints e ON m.ds_did = e.did \
             WHERE m.actor_did = $1 AND m.expires_at > NOW() AND e.expires_at > NOW()",
        )
        .bind(&canonical)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(ds_did, endpoint, suites)| DsEndpoint {
            did: ds_did,
            endpoint,
            supported_cipher_suites: suites.and_then(|s| serde_json::from_str(&s).ok()),
            federation_capabilities: None,
        }))
    }

    /// Look up degraded cached endpoint for an actor DID ignoring expires_at.
    async fn get_cached_any(&self, actor_did: &str) -> Result<Option<DsEndpoint>, FederationError> {
        let canonical = canonical_did(actor_did);
        let row = sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT e.did, e.endpoint, e.supported_cipher_suites \
             FROM did_ds_mappings m \
             JOIN ds_endpoints e ON m.ds_did = e.did \
             WHERE m.actor_did = $1",
        )
        .bind(&canonical)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(ds_did, endpoint, suites)| DsEndpoint {
            did: ds_did,
            endpoint,
            supported_cipher_suites: suites.and_then(|s| serde_json::from_str(&s).ok()),
            federation_capabilities: None,
        }))
    }

    /// Look up cached endpoint directly from ds_endpoints by target DS DID.
    pub(crate) async fn get_cached_ds_endpoint(
        &self,
        ds_did: &str,
    ) -> Result<Option<DsEndpoint>, FederationError> {
        let canonical = canonical_did(ds_did);
        let row = sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT did, endpoint, supported_cipher_suites \
             FROM ds_endpoints WHERE did = $1 AND expires_at > NOW()",
        )
        .bind(&canonical)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(did, endpoint, suites)| DsEndpoint {
            did,
            endpoint,
            supported_cipher_suites: suites.and_then(|s| serde_json::from_str(&s).ok()),
            federation_capabilities: None,
        }))
    }

    /// Look up degraded cached endpoint directly from ds_endpoints by target DS DID.
    pub(crate) async fn get_cached_ds_endpoint_any(
        &self,
        ds_did: &str,
    ) -> Result<Option<DsEndpoint>, FederationError> {
        let canonical = canonical_did(ds_did);
        let row = sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT did, endpoint, supported_cipher_suites \
             FROM ds_endpoints WHERE did = $1",
        )
        .bind(&canonical)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(did, endpoint, suites)| DsEndpoint {
            did,
            endpoint,
            supported_cipher_suites: suites.and_then(|s| serde_json::from_str(&s).ok()),
            federation_capabilities: None,
        }))
    }

    pub async fn cache_mapping(
        &self,
        actor_did: &str,
        endpoint: &DsEndpoint,
    ) -> Result<(), FederationError> {
        let canonical_actor = canonical_did(actor_did);
        let canonical_ds = canonical_did(&endpoint.did);
        let suites_json = endpoint
            .supported_cipher_suites
            .as_ref()
            .and_then(|s| serde_json::to_string(s).ok());

        // 1. Insert/update ds_endpoints
        sqlx::query(
            "INSERT INTO ds_endpoints (did, endpoint, supported_cipher_suites, resolved_at, expires_at) \
             VALUES ($1, $2, $3, NOW(), NOW() + make_interval(secs => $4)) \
             ON CONFLICT (did) DO UPDATE SET \
               endpoint = $2, \
               supported_cipher_suites = $3, \
               resolved_at = NOW(), \
               expires_at = NOW() + make_interval(secs => $4)",
        )
        .bind(&canonical_ds)
        .bind(&endpoint.endpoint)
        .bind(&suites_json)
        .bind(self.cache_ttl_secs as f64)
        .execute(&self.pool)
        .await?;

        // 2. Insert/update did_ds_mappings
        sqlx::query(
            "INSERT INTO did_ds_mappings (actor_did, ds_did, resolved_at, expires_at) \
             VALUES ($1, $2, NOW(), NOW() + make_interval(secs => $3)) \
             ON CONFLICT (actor_did) DO UPDATE SET \
               ds_did = $2, \
               resolved_at = NOW(), \
               expires_at = NOW() + make_interval(secs => $3)",
        )
        .bind(&canonical_actor)
        .bind(&canonical_ds)
        .bind(self.cache_ttl_secs as f64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn cache_endpoint(&self, endpoint: &DsEndpoint) -> Result<(), FederationError> {
        let canonical_ds = canonical_did(&endpoint.did);
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
        .bind(&canonical_ds)
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
                kind: ResolutionFailureKind::ServiceMissing(
                    "No #atproto_mls service in DID document".to_string(),
                ),
            })?
            .to_string();

        self.validate_remote_url(&endpoint).await?;

        let ds_did = derive_ds_did_from_https_endpoint(&endpoint).ok_or_else(|| {
            FederationError::ResolutionFailed {
                did: user_did.to_string(),
                kind: ResolutionFailureKind::InvalidDid(format!(
                    "Could not derive DS DID from endpoint '{endpoint}'"
                )),
            }
        })?;
        Ok(DsEndpoint {
            did: ds_did,
            endpoint,
            supported_cipher_suites: None,
            federation_capabilities: None,
        })
    }

    /// Fetch a bounded repo record from the user's PDS.
    pub(crate) async fn fetch_repo_record(
        &self,
        pds_endpoint: &str,
        user_did: &str,
        collection: &str,
        rkey: &str,
        deadline: tokio::time::Instant,
    ) -> Result<serde_json::Value, FederationError> {
        let url = repo_record_url(pds_endpoint, user_did, collection, rkey);
        let dest = validate_and_resolve_destination(&url, None).await?;
        let resp =
            send_hardened_resolution_request(&dest, deadline, user_did, "HTTP request failed")
                .await?;

        if !resp.status().is_success() {
            return Err(FederationError::ResolutionFailed {
                did: user_did.to_string(),
                kind: ResolutionFailureKind::HttpStatus {
                    status: resp.status().as_u16(),
                    message: format!(
                        "PDS returned status {} for record {collection}/{rkey}",
                        resp.status()
                    ),
                },
            });
        }

        decode_resolution_json(
            resp,
            PROFILE_OR_DEVICE_MAX_BYTES,
            deadline,
            user_did,
            "Invalid JSON response",
        )
        .await
    }

    /// Convert a declared DS DID into an SSRF-validated endpoint without recursive actor mapping.
    pub(crate) async fn resolve_ds_did_to_endpoint(
        &self,
        ds_did: &str,
    ) -> Result<String, FederationError> {
        if self.is_self(ds_did) {
            return Ok(self.self_endpoint.clone());
        }

        let canonical_ds = canonical_did(ds_did);
        if !canonical_ds.starts_with("did:web:") && !canonical_ds.starts_with("did:plc:") {
            return Err(FederationError::ResolutionFailed {
                did: ds_did.to_string(),
                kind: ResolutionFailureKind::InvalidDid(format!(
                    "Unsupported DS DID method: '{ds_did}'"
                )),
            });
        }

        // If did:web, validate host/port
        if let Some((host_port, _)) = crate::identity::parse_did_web(&canonical_ds) {
            if let Some((_, p_str)) = host_port.split_once(':') {
                let port = p_str
                    .parse::<u16>()
                    .map_err(|_| FederationError::ResolutionFailed {
                        did: ds_did.to_string(),
                        kind: ResolutionFailureKind::InvalidDid(format!(
                            "Invalid port in did:web: '{ds_did}'"
                        )),
                    })?;
                if port == 0 {
                    return Err(FederationError::ResolutionFailed {
                        did: ds_did.to_string(),
                        kind: ResolutionFailureKind::InvalidDid(format!(
                            "Zero port in did:web: '{ds_did}'"
                        )),
                    });
                }
            }
        }

        // Try resolving the DS's DID document for #atproto_mls service (exact type AtprotoMLSDeliveryService only)
        if let Ok(doc) = self.fetch_did_document(&canonical_ds).await {
            if let Some(endpoint) =
                extract_service(&doc, "atproto_mls", Some("AtprotoMLSDeliveryService"))
            {
                self.validate_remote_url(endpoint).await?;
                return Ok(endpoint.to_string());
            }
        }

        // Fall back to direct did:web service endpoint derivation
        if let Some(derived) = did_web_service_endpoint(&canonical_ds) {
            self.validate_remote_url(&derived).await?;
            return Ok(derived);
        }

        Err(FederationError::ResolutionFailed {
            did: ds_did.to_string(),
            kind: ResolutionFailureKind::ServiceMissing(format!(
                "Could not resolve DS DID {ds_did} to an HTTPS endpoint"
            )),
        })
    }

    /// Resolve DS endpoint from the user's declaration record (blue.catbird.chat.declaration).
    async fn resolve_from_declaration(
        &self,
        user_did: &str,
    ) -> Result<DsEndpoint, FederationError> {
        let pds_endpoint = self.resolve_did_to_pds(user_did).await?;
        let deadline = checked_outbound_deadline(user_did, Duration::from_secs(10))?;

        let body = self
            .fetch_repo_record(
                &pds_endpoint,
                user_did,
                DECLARATION_COLLECTION,
                DECLARATION_RKEY,
                deadline,
            )
            .await?;

        let value = body
            .get("value")
            .and_then(|v| v.as_object())
            .ok_or_else(|| FederationError::ResolutionFailed {
                did: user_did.to_string(),
                kind: ResolutionFailureKind::InvalidPayload(
                    "No 'value' object in declaration response".to_string(),
                ),
            })?;

        let (canonical_ds_did, _allow_incoming) = validate_declaration_record_value(value)
            .map_err(|e| match e {
                FederationError::ResolutionFailed { kind, .. } => {
                    FederationError::ResolutionFailed {
                        did: user_did.to_string(),
                        kind,
                    }
                }
                other => other,
            })?;
        // Convert declared DS DID to SSRF-validated endpoint without recursive actor mapping
        let endpoint = self.resolve_ds_did_to_endpoint(&canonical_ds_did).await?;

        Ok(DsEndpoint {
            did: canonical_ds_did,
            endpoint,
            supported_cipher_suites: None,
            federation_capabilities: None,
        })
    }

    /// Resolve DS endpoint from the user's legacy profile record (blue.catbird.chat.profile).
    async fn resolve_from_repo(&self, user_did: &str) -> Result<DsEndpoint, FederationError> {
        let pds_endpoint = self.resolve_did_to_pds(user_did).await?;
        let deadline = checked_outbound_deadline(user_did, Duration::from_secs(10))?;

        let body = self
            .fetch_repo_record(
                &pds_endpoint,
                user_did,
                PROFILE_COLLECTION,
                PROFILE_RKEY,
                deadline,
            )
            .await?;

        let value = body
            .get("value")
            .ok_or_else(|| FederationError::ResolutionFailed {
                did: user_did.to_string(),
                kind: ResolutionFailureKind::InvalidPayload(
                    "No 'value' field in record response".to_string(),
                ),
            })?;

        let delivery_service = value
            .get("deliveryService")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FederationError::ResolutionFailed {
                did: user_did.to_string(),
                kind: ResolutionFailureKind::InvalidPayload(
                    "No 'deliveryService' in profile record".to_string(),
                ),
            })?;

        let (ds_did, endpoint_url) = if delivery_service.starts_with("did:") {
            let canonical = canonical_did(delivery_service).to_string();
            let ep = self.resolve_ds_did_to_endpoint(&canonical).await?;
            (canonical, ep)
        } else {
            self.validate_remote_url(delivery_service).await?;
            let derived = derive_ds_did_from_https_endpoint(delivery_service).ok_or_else(|| {
                FederationError::ResolutionFailed {
                    did: user_did.to_string(),
                    kind: ResolutionFailureKind::InvalidDid(format!(
                        "Could not derive DS DID from endpoint '{delivery_service}'"
                    )),
                }
            })?;
            (derived, delivery_service.to_string())
        };

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
            did: ds_did,
            endpoint: endpoint_url,
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
                kind: ResolutionFailureKind::ServiceMissing(
                    "No #atproto_pds service in DID document".to_string(),
                ),
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
                kind: ResolutionFailureKind::InvalidDid(format!(
                    "Invalid did:web identifier: {did}"
                )),
            })?
        } else if did.starts_with("did:plc:") {
            format!("https://plc.directory/{did}")
        } else {
            return Err(FederationError::ResolutionFailed {
                did: did.to_string(),
                kind: ResolutionFailureKind::InvalidDid(format!("Unsupported DID method: {did}")),
            });
        };

        let dest = validate_and_resolve_destination(&did_doc_url, None).await?;
        let deadline = checked_outbound_deadline(did, Duration::from_secs(10))?;

        let resp =
            send_hardened_resolution_request(&dest, deadline, did, "DID resolution HTTP error")
                .await?;

        if !resp.status().is_success() {
            return Err(FederationError::ResolutionFailed {
                did: did.to_string(),
                kind: ResolutionFailureKind::HttpStatus {
                    status: resp.status().as_u16(),
                    message: format!("DID document server returned status {}", resp.status()),
                },
            });
        }

        decode_resolution_json(
            resp,
            DID_DOCUMENT_MAX_BYTES,
            deadline,
            did,
            "Invalid DID document JSON",
        )
        .await
    }

    /// Resolve authorized device keys for a DID via its PDS.
    pub async fn resolve_authorized_device_keys(
        &self,
        did: &str,
    ) -> Result<Vec<Vec<u8>>, FederationError> {
        let deadline = checked_outbound_deadline(did, outbound_timeout())?;
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
                                ("collection", "blue.catbird.chat.device"),
                                ("limit", AUTHORITY_PAGE_SIZE_PARAM),
                            ]);
                            if let Some(cursor) = cursor.as_deref() {
                                request = request.query(&[("cursor", cursor)]);
                            }

                            let response = tokio::time::timeout_at(deadline, request.send())
                                .await
                                .map_err(|_| ())?
                                .map_err(|_| ())?;
                            if !response.status().is_success() {
                                return Err(());
                            }
                            decode_json_bounded(
                                response,
                                ResponseBodyBudget::new(PROFILE_OR_DEVICE_MAX_BYTES, deadline),
                            )
                            .await
                            .map_err(|_| ())
                        }
                    },
                    deadline,
                )
                .await
                .map_err(|_| FederationError::ResolutionFailed {
                    did: did.to_string(),
                    kind: ResolutionFailureKind::InvalidPayload(
                        "PDS device-record pagination was incomplete".to_string(),
                    ),
                })
            },
            deadline,
        )
        .await;

        resolution.map_err(|_| FederationError::ResolutionFailed {
            did: did.to_string(),
            kind: ResolutionFailureKind::Timeout(
                "PDS device authority resolution exceeded its deadline".to_string(),
            ),
        })?
    }

    /// Invalidate cache entry for a DID (actor DID or DS DID).
    pub async fn invalidate(&self, did: &str) -> Result<(), FederationError> {
        let canonical = canonical_did(did);
        sqlx::query("DELETE FROM did_ds_mappings WHERE actor_did = $1 OR ds_did = $1")
            .bind(&canonical)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM ds_endpoints WHERE did = $1")
            .bind(&canonical)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Clean up expired cache entries from both mappings and endpoints tables.
    pub async fn cleanup_expired(&self) -> Result<u64, FederationError> {
        let mut deleted = 0;
        let r1 = sqlx::query("DELETE FROM did_ds_mappings WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;
        deleted += r1.rows_affected();
        let r2 = sqlx::query("DELETE FROM ds_endpoints WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;
        deleted += r2.rows_affected();
        Ok(deleted)
    }

    async fn validate_remote_url(&self, url_str: &str) -> Result<(), FederationError> {
        validate_and_resolve_destination(url_str, None)
            .await
            .map(|_| ())
    }
}

fn checked_outbound_deadline(
    did: &str,
    timeout: Duration,
) -> Result<tokio::time::Instant, FederationError> {
    tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| FederationError::ResolutionFailed {
            did: did.to_string(),
            kind: ResolutionFailureKind::Timeout(
                "Outbound resolution deadline overflowed".to_string(),
            ),
        })
}

async fn send_resolution_request(
    request: reqwest::RequestBuilder,
    deadline: tokio::time::Instant,
    did: &str,
    context: &str,
) -> Result<reqwest::Response, FederationError> {
    tokio::time::timeout_at(deadline, request.send())
        .await
        .map_err(|_| FederationError::ResolutionFailed {
            did: did.to_string(),
            kind: ResolutionFailureKind::Timeout(format!("{context}: deadline exceeded")),
        })?
        .map_err(|error| {
            if error.is_timeout() {
                FederationError::ResolutionFailed {
                    did: did.to_string(),
                    kind: ResolutionFailureKind::Timeout(format!("{context}: {error}")),
                }
            } else if error.is_connect() {
                FederationError::ResolutionFailed {
                    did: did.to_string(),
                    kind: ResolutionFailureKind::ConnectionFailed(format!("{context}: {error}")),
                }
            } else if let Some(status) = error.status() {
                FederationError::ResolutionFailed {
                    did: did.to_string(),
                    kind: ResolutionFailureKind::HttpStatus {
                        status: status.as_u16(),
                        message: format!("{context}: {error}"),
                    },
                }
            } else {
                FederationError::Http(error)
            }
        })
}

async fn decode_resolution_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    max_bytes: usize,
    deadline: tokio::time::Instant,
    did: &str,
    context: &str,
) -> Result<T, FederationError> {
    decode_json_bounded(response, ResponseBodyBudget::new(max_bytes, deadline))
        .await
        .map_err(|error| match error {
            crate::util::outbound_body::OutboundBodyError::DeadlineExceeded => {
                FederationError::ResolutionFailed {
                    did: did.to_string(),
                    kind: ResolutionFailureKind::Timeout(format!(
                        "{context}: response body read deadline exceeded"
                    )),
                }
            }
            crate::util::outbound_body::OutboundBodyError::ReadFailed(source) => {
                if source.is_timeout() {
                    FederationError::ResolutionFailed {
                        did: did.to_string(),
                        kind: ResolutionFailureKind::Timeout(format!(
                            "{context}: response body read timed out: {source}"
                        )),
                    }
                } else {
                    FederationError::ResolutionFailed {
                        did: did.to_string(),
                        kind: ResolutionFailureKind::ConnectionFailed(format!(
                            "{context}: response body read failed: {source}"
                        )),
                    }
                }
            }
            crate::util::outbound_body::OutboundBodyError::InvalidJson(msg) => {
                FederationError::ResolutionFailed {
                    did: did.to_string(),
                    kind: ResolutionFailureKind::InvalidPayload(format!(
                        "{context}: invalid JSON response: {msg}"
                    )),
                }
            }
            other => FederationError::ResolutionFailed {
                did: did.to_string(),
                kind: ResolutionFailureKind::InvalidPayload(format!(
                    "{context}: response body rejected: {other}"
                )),
            },
        })
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
    deadline: tokio::time::Instant,
) -> Result<Result<Output, Error>, ()>
where
    ResolvePds: FnOnce() -> ResolveFuture,
    ResolveFuture: Future<Output = Result<PdsEndpoint, Error>>,
    Paginate: FnOnce(PdsEndpoint) -> PaginateFuture,
    PaginateFuture: Future<Output = Result<Output, Error>>,
{
    tokio::time::timeout_at(deadline, async move {
        let pds_endpoint = resolve_pds().await?;
        paginate(pds_endpoint).await
    })
    .await
    .map_err(|_| ())
}

async fn collect_authoritative_device_key_pages<Fetch, FetchFuture>(
    mut fetch_page: Fetch,
    deadline: tokio::time::Instant,
) -> Result<Vec<Vec<u8>>, ()>
where
    Fetch: FnMut(Option<String>) -> FetchFuture,
    FetchFuture: Future<Output = Result<serde_json::Value, ()>>,
{
    tokio::time::timeout_at(deadline, async move {
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
            if records.len() > AUTHORITY_PAGE_SIZE {
                return Err(());
            }
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
/// components or non-HTTPS schemes return `None` — the caller then fails
/// resolution rather than substituting an actor DID.
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

/// Returns `true` if an IPv4 address is non-global (private, loopback, link-local, unspecified, CGNAT, documentation, benchmarking, multicast, or reserved/broadcast).
pub fn is_non_global_ipv4(v4: &std::net::Ipv4Addr) -> bool {
    let octets = v4.octets();
    // 0.0.0.0/8 (unspecified / "this host on this network", RFC 1122)
    octets[0] == 0
        // 10.0.0.0/8 (RFC 1918 private)
        || octets[0] == 10
        // 127.0.0.0/8 (loopback, RFC 1122)
        || octets[0] == 127
        // 100.64.0.0/10 (CGNAT / Shared Address Space, RFC 6598: 100.64.0.0 - 100.127.255.255)
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        // 169.254.0.0/16 (link-local, RFC 3927)
        || (octets[0] == 169 && octets[1] == 254)
        // 172.16.0.0/12 (RFC 1918 private: 172.16.0.0 - 172.31.255.255)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        // 192.0.0.0/24 (IETF protocol assignments, RFC 6890)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        // 192.0.2.0/24 (TEST-NET-1 documentation, RFC 5737)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        // 192.88.99.0/24 (6to4 Relay Anycast deprecated, RFC 7526)
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        // 192.168.0.0/16 (RFC 1918 private)
        || (octets[0] == 192 && octets[1] == 168)
        // 198.18.0.0/15 (benchmarking, RFC 2544: 198.18.0.0 - 198.19.255.255)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        // 198.51.100.0/24 (TEST-NET-2 documentation, RFC 5737)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        // 203.0.113.0/24 (TEST-NET-3 documentation, RFC 5737)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        // 224.0.0.0/4 (multicast, RFC 5771) & 240.0.0.0/4 (reserved / Class E / broadcast, RFC 1112)
        || octets[0] >= 224
}

/// Returns `true` if an IPv6 address is non-global (private, loopback, link-local, unspecified, unique local, IPv4-mapped/compatible non-global, NAT64 non-global, documentation, benchmarking, or discard).
pub fn is_non_global_ipv6(v6: &std::net::Ipv6Addr) -> bool {
    let segments = v6.segments();
    // 1. IPv4-mapped IPv6: ::ffff:0:0/96 (RFC 4291)
    if let Some(mapped_v4) = v6.to_ipv4_mapped() {
        return is_non_global_ipv4(&mapped_v4);
    }
    if let [0, 0, 0, 0, 0, 0xffff, high, low] = segments {
        let v4 =
            std::net::Ipv4Addr::new((high >> 8) as u8, high as u8, (low >> 8) as u8, low as u8);
        return is_non_global_ipv4(&v4);
    }
    // 2. IPv4-compatible IPv6 (deprecated RFC 4291): [0, 0, 0, 0, 0, 0, high, low]
    if let [0, 0, 0, 0, 0, 0, high, low] = segments {
        if high == 0 && low == 1 {
            return true; // ::1 loopback
        }
        if high == 0 && low == 0 {
            return true; // :: unspecified
        }
        let v4 =
            std::net::Ipv4Addr::new((high >> 8) as u8, high as u8, (low >> 8) as u8, low as u8);
        return is_non_global_ipv4(&v4);
    }
    // 3. NAT64 well-known prefix: 64:ff9b::/96 (RFC 6052)
    if let [0x64, 0xff9b, 0, 0, 0, 0, high, low] = segments {
        let v4 =
            std::net::Ipv4Addr::new((high >> 8) as u8, high as u8, (low >> 8) as u8, low as u8);
        return is_non_global_ipv4(&v4);
    }
    // 4. Standard IPv6 checks
    if v6.is_unspecified()
        || v6.is_loopback()
        || v6.is_multicast()
        || v6.is_unicast_link_local()
        || (segments[0] & 0xfe00) == 0xfc00 // Unique Local (fc00::/7)
        || (segments[0] & 0xffc0) == 0xfec0 // Site-Local (fec0::/10)
        || matches!(segments, [0x0100, 0, 0, 0, ..]) // Discard prefix (100::/64)
        || matches!(segments, [0x2001, 0x0db8, ..]) // Documentation (2001:db8::/32)
        || matches!(segments, [0x2001, 0x0002, ..]) // Benchmarking (2001:2::/48)
        || matches!(segments, [0x2002, ..])
    // 6to4 (2002::/16)
    {
        return true;
    }
    // Global unicast space must be within 2000::/3
    (segments[0] & 0xe000) != 0x2000
}

/// Returns `true` if the IP is private, loopback, link-local, or unspecified.
pub fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_non_global_ipv4(v4),
        std::net::IpAddr::V6(v6) => is_non_global_ipv6(v6),
    }
}

fn allow_insecure_http() -> bool {
    std::env::var("FEDERATION_ALLOW_INSECURE_HTTP")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

static FEDERATION_HOST_ALLOWLIST: LazyLock<Option<Vec<String>>> = LazyLock::new(|| {
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

#[derive(Debug, Clone)]
pub struct ValidatedRemoteDestination {
    pub url: url::Url,
    pub host: String,
    pub addrs: Vec<std::net::SocketAddr>,
}

/// Validate a DS endpoint URL for SSRF protection with optional injected allowlist.
pub(crate) fn validate_endpoint_url_with_allowlist(
    url_str: &str,
    allow_http: bool,
    allowlist: Option<&[String]>,
) -> Result<url::Url, FederationError> {
    let is_app_env_test = std::env::var("APP_ENV")
        .map(|v| v.eq_ignore_ascii_case("test"))
        .unwrap_or(false);
    validate_endpoint_url_with_custom_policy(url_str, allow_http, allowlist, is_app_env_test)
}

pub fn classify_dns_io_error(e: &std::io::Error, host: &str) -> ResolutionFailureKind {
    match e.kind() {
        std::io::ErrorKind::TimedOut => {
            ResolutionFailureKind::DnsTimeout(format!("DNS lookup timed out for host {host}: {e}"))
        }
        std::io::ErrorKind::NotFound => {
            ResolutionFailureKind::DnsNxdomain(format!("Host {host} not found (NXDOMAIN): {e}"))
        }
        std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::NotConnected
        | std::io::ErrorKind::BrokenPipe => ResolutionFailureKind::ConnectionFailed(format!(
            "Connection error resolving host {host}: {e}"
        )),
        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock => {
            ResolutionFailureKind::DnsTemporary(format!(
                "Temporary DNS failure resolving host {host}: {e}"
            ))
        }
        _ => {
            let msg = e.to_string().to_ascii_lowercase();
            if msg.contains("temporary")
                || msg.contains("eai_again")
                || msg.contains("try again")
                || msg.contains("servfail")
            {
                ResolutionFailureKind::DnsTemporary(format!(
                    "Temporary failure in name resolution for {host}: {e}"
                ))
            } else if msg.contains("not found")
                || msg.contains("no such host")
                || msg.contains("nxdomain")
                || msg.contains("eai_noname")
                || msg.contains("eai_nodata")
                || msg.contains("unknown host")
                || msg.contains("does not exist")
                || msg.contains("no address associated")
            {
                ResolutionFailureKind::DnsNxdomain(format!("Host {host} not found (NXDOMAIN): {e}"))
            } else {
                ResolutionFailureKind::DnsTemporary(format!("Failed to resolve host {host}: {e}"))
            }
        }
    }
}

pub(crate) fn validate_endpoint_url_with_custom_policy(
    url_str: &str,
    allow_http: bool,
    allowlist: Option<&[String]>,
    is_app_env_test: bool,
) -> Result<url::Url, FederationError> {
    let parsed = url::Url::parse(url_str).map_err(|e| FederationError::ResolutionFailed {
        did: String::new(),
        kind: ResolutionFailureKind::InvalidUrl(format!("Invalid URL: {e}")),
    })?;

    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && allow_http) {
        return Err(FederationError::ResolutionFailed {
            did: String::new(),
            kind: ResolutionFailureKind::SsrfBlocked(if parsed.scheme() == "http" {
                "HTTP federation endpoint rejected; set FEDERATION_ALLOW_INSECURE_HTTP=true only in trusted development"
                    .to_string()
            } else {
                format!("URL scheme must be https, got {}", parsed.scheme())
            }),
        });
    }

    if let Some(host) = parsed.host_str() {
        let host_lc = host.to_ascii_lowercase();

        // 1. Hostname allowlist check if configured
        let effective_allowlist = allowlist.or_else(|| FEDERATION_HOST_ALLOWLIST.as_deref());
        if let Some(allowed) = effective_allowlist {
            if !host_is_allowlisted(host, allowed) {
                return Err(FederationError::ResolutionFailed {
                    did: String::new(),
                    kind: ResolutionFailureKind::AllowlistBlocked(format!(
                        "Host {host} is not in FEDERATION_OUTBOUND_HOST_ALLOWLIST"
                    )),
                });
            }
        }

        let blocked = ["localhost", "127.0.0.1", "0.0.0.0", "::1"];
        if blocked.contains(&host_lc.as_str()) || host_lc.ends_with(".localhost") {
            if !(is_app_env_test && allow_http) {
                return Err(FederationError::ResolutionFailed {
                    did: String::new(),
                    kind: ResolutionFailureKind::SsrfBlocked(format!(
                        "Blocked private address: {host}"
                    )),
                });
            }
        }

        // IPv6 hosts are returned by `host_str()` as bracketed strings (e.g. `[::1]`)
        let typed_ip: Option<std::net::IpAddr> = match parsed.host() {
            Some(url::Host::Ipv4(v4)) => Some(std::net::IpAddr::V4(v4)),
            Some(url::Host::Ipv6(v6)) => Some(std::net::IpAddr::V6(v6)),
            _ => host.parse::<std::net::IpAddr>().ok(),
        };
        if let Some(ip) = typed_ip {
            if is_private_ip(&ip) && !(is_app_env_test && allow_http) {
                return Err(FederationError::ResolutionFailed {
                    did: String::new(),
                    kind: ResolutionFailureKind::SsrfBlocked(format!(
                        "Blocked non-global IP: {ip}"
                    )),
                });
            }
        }
    }

    Ok(parsed)
}

pub(crate) fn validate_endpoint_url_with_policy(
    url_str: &str,
    allow_http: bool,
) -> Result<url::Url, FederationError> {
    validate_endpoint_url_with_allowlist(url_str, allow_http, None)
}

pub(crate) fn validate_endpoint_url(url_str: &str) -> Result<url::Url, FederationError> {
    validate_endpoint_url_with_allowlist(url_str, allow_insecure_http(), None)
}

pub(crate) async fn validate_and_resolve_destination(
    url_str: &str,
    allowlist: Option<&[String]>,
) -> Result<ValidatedRemoteDestination, FederationError> {
    let allow_http = allow_insecure_http();
    let is_app_env_test = std::env::var("APP_ENV")
        .map(|v| v.eq_ignore_ascii_case("test"))
        .unwrap_or(false);
    validate_and_resolve_destination_with_policy(url_str, allow_http, allowlist, is_app_env_test)
        .await
}

pub(crate) async fn validate_and_resolve_destination_with_policy(
    url_str: &str,
    allow_http: bool,
    allowlist: Option<&[String]>,
    is_app_env_test: bool,
) -> Result<ValidatedRemoteDestination, FederationError> {
    let parsed =
        validate_endpoint_url_with_custom_policy(url_str, allow_http, allowlist, is_app_env_test)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| FederationError::ResolutionFailed {
            did: String::new(),
            kind: ResolutionFailureKind::InvalidUrl("URL host is missing".to_string()),
        })?
        .to_string();

    let port = parsed
        .port_or_known_default()
        .unwrap_or(if parsed.scheme() == "http" { 80 } else { 443 });

    // Hostname allowlist check
    let effective_allowlist = allowlist.or_else(|| FEDERATION_HOST_ALLOWLIST.as_deref());
    if let Some(allowed) = effective_allowlist {
        if !host_is_allowlisted(&host, allowed) {
            return Err(FederationError::ResolutionFailed {
                did: String::new(),
                kind: ResolutionFailureKind::AllowlistBlocked(format!(
                    "Host {host} is not in FEDERATION_OUTBOUND_HOST_ALLOWLIST"
                )),
            });
        }
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_private_ip(&ip) && !(is_app_env_test && allow_http) {
            return Err(FederationError::ResolutionFailed {
                did: String::new(),
                kind: ResolutionFailureKind::SsrfBlocked(format!("Blocked non-global IP: {ip}")),
            });
        }
        let sock_addr = std::net::SocketAddr::new(ip, port);
        return Ok(ValidatedRemoteDestination {
            url: parsed,
            host,
            addrs: vec![sock_addr],
        });
    }

    let addrs_iter = match tokio::time::timeout(
        federation_dns_timeout(),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(addrs)) => addrs,
        Ok(Err(e)) => {
            let kind = classify_dns_io_error(&e, &host);
            return Err(FederationError::ResolutionFailed {
                did: String::new(),
                kind,
            });
        }
        Err(_) => {
            return Err(FederationError::ResolutionFailed {
                did: String::new(),
                kind: ResolutionFailureKind::DnsTimeout(format!(
                    "DNS lookup timed out for host {host}"
                )),
            });
        }
    };

    let mut addrs: Vec<std::net::SocketAddr> = addrs_iter.collect();
    addrs.sort_unstable();
    addrs.dedup();

    if addrs.is_empty() {
        return Err(FederationError::ResolutionFailed {
            did: String::new(),
            kind: ResolutionFailureKind::DnsNxdomain(format!(
                "Host {host} did not resolve to any address"
            )),
        });
    }

    // Reject mixed/private: ALL addresses must be public
    for addr in &addrs {
        if is_private_ip(&addr.ip()) && !(is_app_env_test && allow_http) {
            return Err(FederationError::ResolutionFailed {
                did: String::new(),
                kind: ResolutionFailureKind::SsrfBlocked(format!(
                    "Host {host} resolved to blocked IP {}",
                    addr.ip()
                )),
            });
        }
    }

    Ok(ValidatedRemoteDestination {
        url: parsed,
        host,
        addrs,
    })
}

pub(crate) async fn validate_resolved_host_is_public(
    parsed: &url::Url,
) -> Result<(), FederationError> {
    validate_and_resolve_destination(parsed.as_str(), None)
        .await
        .map(|_| ())
}

pub(crate) async fn send_hardened_resolution_request(
    destination: &ValidatedRemoteDestination,
    deadline: tokio::time::Instant,
    did: &str,
    context: &str,
) -> Result<reqwest::Response, FederationError> {
    let client = reqwest::Client::builder()
        .user_agent("catbird-mls-ds/1.0")
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(&destination.host, &destination.addrs)
        .build()
        .map_err(|e| FederationError::ResolutionFailed {
            did: did.to_string(),
            kind: ResolutionFailureKind::InvalidConfiguration(format!(
                "{context}: client build failed: {e}"
            )),
        })?;

    let resp = tokio::time::timeout_at(deadline, client.get(destination.url.clone()).send())
        .await
        .map_err(|_| FederationError::ResolutionFailed {
            did: did.to_string(),
            kind: ResolutionFailureKind::Timeout(format!("{context}: deadline exceeded")),
        })?
        .map_err(|error| {
            if error.is_timeout() {
                FederationError::ResolutionFailed {
                    did: did.to_string(),
                    kind: ResolutionFailureKind::Timeout(format!("{context}: {error}")),
                }
            } else if error.is_connect() {
                FederationError::ResolutionFailed {
                    did: did.to_string(),
                    kind: ResolutionFailureKind::ConnectionFailed(format!("{context}: {error}")),
                }
            } else if let Some(status) = error.status() {
                FederationError::ResolutionFailed {
                    did: did.to_string(),
                    kind: ResolutionFailureKind::HttpStatus {
                        status: status.as_u16(),
                        message: format!("{context}: {error}"),
                    },
                }
            } else {
                FederationError::Http(error)
            }
        })?;

    if resp.status().is_redirection() {
        return Err(FederationError::ResolutionFailed {
            did: did.to_string(),
            kind: ResolutionFailureKind::RedirectRejected(format!(
                "{context}: redirect rejected ({})",
                resp.status()
            )),
        });
    }

    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    async fn response_from_raw(raw: Vec<u8>) -> reqwest::Response {
        use tokio::io::AsyncReadExt as _;
        use tokio::io::AsyncWriteExt as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept test request");
            let mut request = [0u8; 1024];
            let bytes_read = stream.read(&mut request).await.expect("read test request");
            assert!(bytes_read > 0, "test client sent a request");
            stream.write_all(&raw).await.expect("write test response");
        });

        reqwest::Client::new()
            .get(format!("http://{address}/"))
            .send()
            .await
            .expect("receive test response")
    }

    async fn declared_response(length: usize) -> reqwest::Response {
        response_from_raw(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
            )
            .into_bytes(),
        )
        .await
    }

    async fn chunked_response(body: &[u8]) -> reqwest::Response {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response.extend_from_slice(b"\r\n0\r\n\r\n");
        response_from_raw(response).await
    }

    async fn delayed_body_response(delay: Duration) -> reqwest::Response {
        use tokio::io::AsyncReadExt as _;
        use tokio::io::AsyncWriteExt as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept test request");
            let mut request = [0u8; 1024];
            let bytes_read = stream.read(&mut request).await.expect("read test request");
            assert!(bytes_read > 0, "test client sent a request");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write test headers");
            tokio::time::sleep(delay).await;
            let _ = stream.write_all(b"{}").await;
        });

        reqwest::Client::new()
            .get(format!("http://{address}/"))
            .send()
            .await
            .expect("receive test response headers")
    }

    #[tokio::test]
    async fn resolver_json_rejects_declared_did_body_over_limit() {
        let response = declared_response(DID_DOCUMENT_MAX_BYTES + 1).await;
        let result: Result<serde_json::Value, _> = decode_resolution_json(
            response,
            DID_DOCUMENT_MAX_BYTES,
            tokio::time::Instant::now() + Duration::from_secs(30),
            "did:plc:test",
            "Invalid DID document JSON",
        )
        .await;

        let error = result.expect_err("oversized DID document must fail");
        assert!(error.to_string().contains("exceeding limit"));
    }

    #[tokio::test]
    async fn resolver_json_preserves_valid_bounded_response() {
        let response = response_from_raw(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                .to_vec(),
        )
        .await;
        let value: serde_json::Value = decode_resolution_json(
            response,
            DID_DOCUMENT_MAX_BYTES,
            tokio::time::Instant::now() + Duration::from_secs(30),
            "did:plc:test",
            "Invalid DID document JSON",
        )
        .await
        .expect("valid bounded JSON remains accepted");

        assert_eq!(value, serde_json::json!({}));
    }

    #[tokio::test]
    async fn resolver_json_rejects_chunked_did_body_over_limit_before_json() {
        let response = chunked_response(&vec![b'x'; DID_DOCUMENT_MAX_BYTES + 1]).await;
        let result: Result<serde_json::Value, _> = decode_resolution_json(
            response,
            DID_DOCUMENT_MAX_BYTES,
            tokio::time::Instant::now() + Duration::from_secs(30),
            "did:plc:test",
            "Invalid DID document JSON",
        )
        .await;

        let error = result.expect_err("oversized chunked DID document must fail");
        assert!(
            error.to_string().contains("exceeding limit"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn resolver_json_rejects_profile_and_device_bodies_over_limit() {
        for context in ["Invalid profile JSON", "Invalid device-page JSON"] {
            let response = declared_response(PROFILE_OR_DEVICE_MAX_BYTES + 1).await;
            let result: Result<serde_json::Value, _> = decode_resolution_json(
                response,
                PROFILE_OR_DEVICE_MAX_BYTES,
                tokio::time::Instant::now() + Duration::from_secs(30),
                "did:plc:test",
                context,
            )
            .await;

            let error = result.expect_err("oversized profile/device body must fail");
            assert!(error.to_string().contains("exceeding limit"));
        }
    }

    #[tokio::test]
    async fn resolver_json_body_cannot_reset_presend_deadline() {
        let response = delayed_body_response(Duration::from_millis(50)).await;
        let result: Result<serde_json::Value, _> = decode_resolution_json(
            response,
            DID_DOCUMENT_MAX_BYTES,
            tokio::time::Instant::now() + Duration::from_millis(5),
            "did:plc:test",
            "Invalid DID document JSON",
        )
        .await;

        let error = result.expect_err("slow body must not reset the request deadline");
        assert!(error.to_string().contains("deadline exceeded"));
    }

    #[tokio::test]
    async fn resolver_request_headers_cannot_outlive_presend_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept test request");
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let result = send_resolution_request(
            reqwest::Client::new().get(format!("http://{address}/")),
            tokio::time::Instant::now() + Duration::from_millis(5),
            "did:plc:test",
            "DID resolution HTTP error",
        )
        .await;

        let error = result.expect_err("slow headers must not reset the request deadline");
        assert!(error.to_string().contains("deadline exceeded"));
    }

    #[test]
    fn resolver_deadline_rejects_overflow() {
        assert!(checked_outbound_deadline("did:plc:test", Duration::MAX).is_err());
    }

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
            tokio::time::Instant::now() + Duration::from_secs(1),
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
            tokio::time::Instant::now() + Duration::from_secs(1),
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
            tokio::time::Instant::now() + Duration::from_secs(1),
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
            tokio::time::Instant::now() + Duration::from_secs(1),
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
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await;
        assert!(record_limit.is_err());
    }

    #[tokio::test]
    async fn authoritative_pagination_rejects_101_records_in_one_page() {
        let records = vec![authoritative_record(&[0x41; 32]); AUTHORITY_PAGE_SIZE + 1];
        let result = collect_authoritative_device_key_pages(
            move |_| {
                let records = records.clone();
                std::future::ready(Ok(serde_json::json!({ "records": records })))
            },
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn authoritative_pagination_accepts_ten_pages_of_100_records() {
        let page_counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = page_counter.clone();
        let records = vec![authoritative_record(&[0x41; 32]); AUTHORITY_PAGE_SIZE];
        let result = collect_authoritative_device_key_pages(
            move |_| {
                let page = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let cursor = (page + 1 < MAX_AUTHORITY_PAGES).then(|| format!("page-{}", page + 1));
                let records = records.clone();
                let mut body = serde_json::json!({ "records": records });
                if let Some(cursor) = cursor {
                    body["cursor"] = serde_json::Value::String(cursor);
                }
                std::future::ready(Ok(body))
            },
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await;

        assert_eq!(
            result.expect("ten full pages remain valid").len(),
            MAX_AUTHORITY_RECORDS
        );
        assert_eq!(
            page_counter.load(std::sync::atomic::Ordering::SeqCst),
            MAX_AUTHORITY_PAGES
        );
    }

    #[tokio::test]
    async fn authoritative_pagination_enforces_overall_deadline() {
        let result = collect_authoritative_device_key_pages(
            |_| std::future::pending::<Result<serde_json::Value, ()>>(),
            tokio::time::Instant::now() + Duration::from_millis(1),
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
            tokio::time::Instant::now() + Duration::from_millis(1),
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
        assert!(is_private_ip(&"127.1.2.3".parse::<IpAddr>().unwrap()));
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
        assert!(is_private_ip(&"172.31.255.254".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_ipv4_cgnat_and_link_local_and_nonglobal() {
        // CGNAT (100.64.0.0/10)
        assert!(is_private_ip(&"100.64.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"100.127.255.254".parse::<IpAddr>().unwrap()));
        // Link-local
        assert!(is_private_ip(&"169.254.1.1".parse::<IpAddr>().unwrap()));
        // Documentation / benchmarking / multicast / broadcast / 0.0.0.0
        assert!(is_private_ip(&"0.0.0.0".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"192.0.2.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"198.18.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"198.51.100.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"203.0.113.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"224.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"240.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"255.255.255.255".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_is_properly_classified_and_rejected() {
        // Mapped loopback
        assert!(is_private_ip(
            &"::ffff:127.0.0.1".parse::<IpAddr>().unwrap()
        ));
        assert!(is_private_ip(
            &"::ffff:127.0.0.2".parse::<IpAddr>().unwrap()
        ));
        // Mapped RFC 1918
        assert!(is_private_ip(&"::ffff:10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(
            &"::ffff:172.16.0.1".parse::<IpAddr>().unwrap()
        ));
        assert!(is_private_ip(
            &"::ffff:192.168.1.1".parse::<IpAddr>().unwrap()
        ));
        // Mapped link-local
        assert!(is_private_ip(
            &"::ffff:169.254.1.1".parse::<IpAddr>().unwrap()
        ));
        // Mapped CGNAT
        assert!(is_private_ip(
            &"::ffff:100.64.0.1".parse::<IpAddr>().unwrap()
        ));
        assert!(is_private_ip(
            &"::ffff:100.127.255.254".parse::<IpAddr>().unwrap()
        ));
        // Mapped non-global / doc / multicast / 0.0.0.0
        assert!(is_private_ip(&"::ffff:0.0.0.0".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(
            &"::ffff:192.0.2.1".parse::<IpAddr>().unwrap()
        ));
        assert!(is_private_ip(
            &"::ffff:198.18.0.1".parse::<IpAddr>().unwrap()
        ));
        assert!(is_private_ip(
            &"::ffff:198.51.100.1".parse::<IpAddr>().unwrap()
        ));
        assert!(is_private_ip(
            &"::ffff:203.0.113.1".parse::<IpAddr>().unwrap()
        ));
        assert!(is_private_ip(
            &"::ffff:224.0.0.1".parse::<IpAddr>().unwrap()
        ));
        assert!(is_private_ip(
            &"::ffff:240.0.0.1".parse::<IpAddr>().unwrap()
        ));
        assert!(is_private_ip(
            &"::ffff:255.255.255.255".parse::<IpAddr>().unwrap()
        ));

        // Mapped public global IPs must NOT be private
        assert!(!is_private_ip(&"::ffff:8.8.8.8".parse::<IpAddr>().unwrap()));
        assert!(!is_private_ip(
            &"::ffff:93.184.216.34".parse::<IpAddr>().unwrap()
        ));
        assert!(!is_private_ip(&"::ffff:1.1.1.1".parse::<IpAddr>().unwrap()));
    }

    #[tokio::test]
    async fn test_ssrf_rejects_direct_private_ip_even_if_allowlisted() {
        let allowlist = vec!["127.0.0.1".to_string()];
        // In production environment (is_app_env_test = false, allow_http = false), private IP must fail even if in allowlist
        let result = validate_and_resolve_destination_with_policy(
            "https://127.0.0.1:8443",
            false,
            Some(&allowlist),
            false,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ssrf_injected_allowlist_enforcement() {
        let allowlist = vec!["allowed.example.com".to_string()];
        // Not in allowlist
        let res1 = validate_endpoint_url_with_allowlist(
            "https://disallowed.example.com",
            false,
            Some(&allowlist),
        );
        assert!(res1.is_err());
        assert!(res1
            .unwrap_err()
            .to_string()
            .contains("not in FEDERATION_OUTBOUND_HOST_ALLOWLIST"));

        // In allowlist
        let res2 = validate_endpoint_url_with_allowlist(
            "https://allowed.example.com",
            false,
            Some(&allowlist),
        );
        assert!(res2.is_ok());
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
        let result = validate_endpoint_url_with_policy("https://localhost", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_127_0_0_1() {
        let result = validate_endpoint_url_with_policy("https://127.0.0.1", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_0_0_0_0() {
        let result = validate_endpoint_url_with_policy("https://0.0.0.0", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_private_ip_10() {
        let result = validate_endpoint_url_with_policy("https://10.0.0.1", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_private_ip_192_168() {
        let result = validate_endpoint_url_with_policy("https://192.168.1.1", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_ipv6_loopback() {
        let result = validate_endpoint_url_with_policy("https://[::1]", false);
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
        let pool = setup_cache_test_pool().await;

        let resolver = DsResolver::new(
            pool,
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            Some((
                "did:web:default-ds.example.com".to_string(),
                "https://default-ds.example.com".to_string(),
            )),
            3600,
        );

        let actor_did = format!("did:key:{}", Uuid::new_v4().as_simple());
        let target_endpoint = DsEndpoint {
            did: "did:web:cached-ds.example.com".to_string(),
            endpoint: "https://cached-ds.example.com".to_string(),
            supported_cipher_suites: None,
            federation_capabilities: None,
        };
        resolver
            .cache_mapping(&actor_did, &target_endpoint)
            .await
            .expect("cache insert succeeds");

        let (result, outcome) = resolver.resolve_with_outcome(&actor_did).await;
        assert_eq!(outcome, "cache_fresh");
        assert_eq!(
            result.expect("resolution succeeds").endpoint,
            "https://cached-ds.example.com"
        );
    }

    #[tokio::test]
    async fn test_resolve_expired_cache_degraded_after_live_failure() {
        let pool = setup_cache_test_pool().await;

        let resolver = DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            Some((
                "did:web:default-ds.example.com".to_string(),
                "https://default-ds.example.com".to_string(),
            )),
            3600,
        );

        let actor_did = format!("did:key:{}", Uuid::new_v4().as_simple());
        let ds_did = format!(
            "did:web:stale-ds-{}.example.com",
            Uuid::new_v4().as_simple()
        );
        let stale_endpoint = format!(
            "https://stale-ds-{}.example.com",
            Uuid::new_v4().as_simple()
        );
        sqlx::query(
            "INSERT INTO ds_endpoints (did, endpoint, supported_cipher_suites, resolved_at, expires_at) \
             VALUES ($1, $2, NULL, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour')",
        )
        .bind(&ds_did)
        .bind(&stale_endpoint)
        .execute(&pool)
        .await
        .expect("expired endpoint insert succeeds");
        sqlx::query(
            "INSERT INTO did_ds_mappings (actor_did, ds_did, resolved_at, expires_at) \
             VALUES ($1, $2, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour')",
        )
        .bind(&actor_did)
        .bind(&ds_did)
        .execute(&pool)
        .await
        .expect("expired mapping insert succeeds");

        let (result, outcome) = resolver.resolve_with_outcome(&actor_did).await;
        assert_eq!(outcome, "cache_stale_degraded");
        assert_eq!(
            result.expect("degraded resolution succeeds").endpoint,
            stale_endpoint
        );
    }

    #[tokio::test]
    async fn test_resolve_default_fallback_when_no_cache() {
        let pool = setup_cache_test_pool().await;

        let resolver = DsResolver::new(
            pool,
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            Some((
                "did:web:default-ds.example.com".to_string(),
                "https://default-ds.example.com".to_string(),
            )),
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
        let pool = setup_cache_test_pool().await;

        let resolver = DsResolver::with_defaults(
            pool,
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
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

    async fn setup_cache_test_pool() -> PgPool {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for database integration tests");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("failed to connect to TEST_DATABASE_URL");

        let mut conn = pool.acquire().await.expect("acquire migration connection");
        let _ = sqlx::query(
            "SET chat.operation_claim_activation_approved = 'handlers-and-legacy-apis-sealed'",
        )
        .execute(&mut *conn)
        .await;
        sqlx::migrate!("./migrations")
            .run(&mut *conn)
            .await
            .expect("migration run failed in setup_cache_test_pool");
        let _ = sqlx::query("RESET chat.operation_claim_activation_approved")
            .execute(&mut *conn)
            .await;

        pool
    }

    #[tokio::test]
    async fn test_cache_refresh_and_invalidate() {
        let pool = setup_cache_test_pool().await;

        let resolver = DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
            3600,
        );

        let actor_did = format!("did:plc:{}", Uuid::new_v4().as_simple());
        let ds_did_one = "did:web:ds-one.example.com";
        let first = DsEndpoint {
            did: ds_did_one.to_string(),
            endpoint: "https://ds-one.example.com".to_string(),
            supported_cipher_suites: Some(vec!["suite-a".to_string()]),
            federation_capabilities: Some(vec!["baseline".to_string()]),
        };
        resolver
            .cache_mapping(&actor_did, &first)
            .await
            .expect("cache mapping succeeds");
        let cached = resolver
            .get_cached(&actor_did)
            .await
            .expect("cache read succeeds")
            .expect("cache entry exists");
        assert_eq!(cached.endpoint, first.endpoint);

        let ds_did_two = "did:web:ds-two.example.com";
        let refreshed = DsEndpoint {
            did: ds_did_two.to_string(),
            endpoint: "https://ds-two.example.com".to_string(),
            supported_cipher_suites: Some(vec!["suite-b".to_string(), "suite-c".to_string()]),
            federation_capabilities: Some(vec!["reconciliation-v1".to_string()]),
        };
        resolver
            .cache_mapping(&actor_did, &refreshed)
            .await
            .expect("cache refresh succeeds");
        let cached_refreshed = resolver
            .get_cached(&actor_did)
            .await
            .expect("cache read succeeds")
            .expect("cache entry exists");
        assert_eq!(cached_refreshed.endpoint, refreshed.endpoint);
        assert_eq!(
            cached_refreshed.supported_cipher_suites,
            refreshed.supported_cipher_suites
        );

        resolver
            .invalidate(&actor_did)
            .await
            .expect("cache invalidation succeeds");
        let after_invalidate = resolver
            .get_cached(&actor_did)
            .await
            .expect("cache read succeeds");
        assert!(after_invalidate.is_none());
    }

    #[tokio::test]
    async fn test_two_table_cache_actor_mapping_and_ds_queue_lookup() {
        let pool = setup_cache_test_pool().await;

        let resolver = DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
            3600,
        );

        let actor_did = format!("did:plc:actor-{}", Uuid::new_v4().as_simple());
        let ds_did = format!("did:web:ds-{}.example.com", Uuid::new_v4().as_simple());
        let endpoint_url = format!("https://ds-{}.example.com", Uuid::new_v4().as_simple());

        let target_endpoint = DsEndpoint {
            did: ds_did.clone(),
            endpoint: endpoint_url.clone(),
            supported_cipher_suites: Some(vec!["suite-1".to_string()]),
            federation_capabilities: None,
        };

        // Cache the mapping: actor_did -> ds_did -> endpoint_url
        resolver
            .cache_mapping(&actor_did, &target_endpoint)
            .await
            .expect("cache_mapping succeeds");

        // 1. Verify actor DID lookup returns the DS DID and endpoint
        let cached_for_actor = resolver
            .get_cached(&actor_did)
            .await
            .expect("get_cached succeeds")
            .expect("actor mapping exists");
        assert_eq!(cached_for_actor.did, ds_did);
        assert_eq!(cached_for_actor.endpoint, endpoint_url);

        let cached_for_ds = resolver
            .get_cached_ds_endpoint(&ds_did)
            .await
            .expect("get_cached_ds_endpoint succeeds")
            .expect("ds endpoint exists");
        assert_eq!(cached_for_ds.did, ds_did);
        assert_eq!(cached_for_ds.endpoint, endpoint_url);

        // 3. Verify the outbound queue's exact SQL lookup finds the endpoint by target DS DID
        let queue_lookup = sqlx::query_scalar::<_, String>(
            "SELECT endpoint FROM ds_endpoints WHERE did = $1 AND expires_at > NOW()",
        )
        .bind(&ds_did)
        .fetch_optional(&pool)
        .await
        .expect("queue query succeeds");
        assert_eq!(queue_lookup.as_deref(), Some(endpoint_url.as_str()));

        // 4. Verify did_ds_mappings contains the expected row
        let mapping_row = sqlx::query_scalar::<_, String>(
            "SELECT ds_did FROM did_ds_mappings WHERE actor_did = $1 AND expires_at > NOW()",
        )
        .bind(&actor_did)
        .fetch_optional(&pool)
        .await
        .expect("mapping query succeeds");
        assert_eq!(mapping_row.as_deref(), Some(ds_did.as_str()));

        // 5. Invalidation by actor_did removes both mapping and ds_endpoints
        resolver
            .invalidate(&actor_did)
            .await
            .expect("invalidation succeeds");
        assert!(resolver.get_cached(&actor_did).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_default_fallback_has_real_ds_identity() {
        let pool = setup_cache_test_pool().await;

        // 1. Test HTTPS URL fallback derives did:web:<host>
        let resolver = DsResolver::with_defaults(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
            Some("https://default-ds.example.com".to_string()),
            3600,
        );

        let actor_did = format!("did:key:{}", Uuid::new_v4().as_simple());
        let (result, outcome) = resolver.resolve_with_outcome(&actor_did).await;
        assert_eq!(outcome, "default_fallback");
        let endpoint = result.expect("default fallback succeeds");
        assert_eq!(endpoint.did, "did:web:default-ds.example.com");
        assert_ne!(endpoint.did, actor_did);
        assert_eq!(endpoint.endpoint, "https://default-ds.example.com");

        // 2. Test explicit DID fallback uses canonical DID
        let resolver_did = DsResolver::with_defaults(
            pool,
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            Some("did:web:custom-default.example.com".to_string()),
            Some("https://custom-default.example.com".to_string()),
            3600,
        );
        let (result_did, outcome_did) = resolver_did.resolve_with_outcome(&actor_did).await;
        assert_eq!(outcome_did, "default_fallback");
        let endpoint_did = result_did.expect("default fallback succeeds");
        assert_eq!(endpoint_did.did, "did:web:custom-default.example.com");
    }

    // -- Production Helper Tests: Delivery Service Base DID Validation --

    #[test]
    fn test_production_helper_delivery_service_validation() {
        // Valid did:web
        assert_eq!(
            validate_declaration_delivery_service("did:web:chat.catbird.blue").unwrap(),
            "did:web:chat.catbird.blue"
        );
        assert_eq!(
            validate_declaration_delivery_service("did:web:ds1.local").unwrap(),
            "did:web:ds1.local"
        );
        assert_eq!(
            validate_declaration_delivery_service("did:web:example.com").unwrap(),
            "did:web:example.com"
        );
        // Valid did:plc
        assert_eq!(
            validate_declaration_delivery_service("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap(),
            "did:plc:z72i7hdynmk6r22z27h6tvur"
        );

        // Rejections for Finding 3:
        // Uppercase rejected
        assert!(validate_declaration_delivery_service("did:web:Chat.Catbird.blue").is_err());
        assert!(validate_declaration_delivery_service("did:web:CHAT.CATBIRD.BLUE").is_err());
        assert!(validate_declaration_delivery_service("did:web:chat.Catbird.blue").is_err());

        // Trailing dot rejected
        assert!(validate_declaration_delivery_service("did:web:chat.catbird.blue.").is_err());
        // Leading dot rejected
        assert!(validate_declaration_delivery_service("did:web:.chat.catbird.blue").is_err());
        // Empty labels / double dot rejected
        assert!(validate_declaration_delivery_service("did:web:chat..catbird.blue").is_err());

        // Underscores rejected
        assert!(
            validate_declaration_delivery_service("did:web:chat_service.catbird.blue").is_err()
        );
        assert!(validate_declaration_delivery_service("did:web:_chat.catbird.blue").is_err());

        // Hyphen violations (leading/trailing in label) rejected
        assert!(validate_declaration_delivery_service("did:web:-chat.catbird.blue").is_err());
        assert!(validate_declaration_delivery_service("did:web:chat-.catbird.blue").is_err());
        assert!(validate_declaration_delivery_service("did:web:-.catbird.blue").is_err());
        // Internal hyphens are valid
        assert_eq!(
            validate_declaration_delivery_service("did:web:chat-service.catbird.blue").unwrap(),
            "did:web:chat-service.catbird.blue"
        );

        // Path rejected
        assert!(validate_declaration_delivery_service("did:web:chat.catbird.blue/path").is_err());
        assert!(validate_declaration_delivery_service("did:web:chat.catbird.blue/").is_err());

        // Port in did:web rejected in production
        assert!(validate_declaration_delivery_service("did:web:chat.catbird.blue:8443").is_err());
        assert!(validate_declaration_delivery_service("did:web:chat.catbird.blue%3A8443").is_err());

        // Percent encoding rejected
        assert!(validate_declaration_delivery_service("did:web:chat%2ecatbird.blue").is_err());
        assert!(validate_declaration_delivery_service("did:web:chat%20catbird.blue").is_err());

        // Fragment not allowed
        assert!(
            validate_declaration_delivery_service("did:web:chat.catbird.blue#atproto_mls").is_err()
        );
        assert!(
            validate_declaration_delivery_service("did:plc:z72i7hdynmk6r22z27h6tvur#fragment")
                .is_err()
        );

        // URL instead of DID
        assert!(validate_declaration_delivery_service("https://chat.catbird.blue").is_err());

        // Empty / whitespace
        assert!(validate_declaration_delivery_service("").is_err());
        assert!(validate_declaration_delivery_service(" did:web:chat.catbird.blue ").is_err());
        assert!(validate_declaration_delivery_service("did:web:chat .catbird.blue").is_err());

        // Unsupported method
        assert!(validate_declaration_delivery_service(
            "did:key:z6MkhaXgBZDvotDkL5257faiz4zZbcw51635Q6phWoqnVJJN"
        )
        .is_err());
        assert!(validate_declaration_delivery_service("did:ion:12345").is_err());

        // Invalid did:plc length or chars
        assert!(validate_declaration_delivery_service("did:plc:short").is_err());
        assert!(validate_declaration_delivery_service("did:plc:z72i7hdynmk6r22z27h6tvu8").is_err());
        // '8' is not base32 [a-z2-7]
    }
    // -- Production Helper Tests: Declaration Record Value Validation --

    #[test]
    fn test_production_helper_declaration_exact_raw_validation() {
        // 1. Valid declaration
        let valid = serde_json::json!({
            "$type": "blue.catbird.chat.declaration",
            "protocolVersion": "1",
            "allowIncoming": "all",
            "deliveryService": "did:web:chat.catbird.blue",
            "createdAt": "2026-08-24T12:00:00Z"
        });
        let (ds_did, allow) =
            validate_declaration_record_value(valid.as_object().unwrap()).unwrap();
        assert_eq!(ds_did, "did:web:chat.catbird.blue");
        assert_eq!(allow, "all");

        // 2. Reject #main type tag (exact bare NSID required)
        let with_main_tag = serde_json::json!({
            "$type": "blue.catbird.chat.declaration#main",
            "protocolVersion": "1",
            "allowIncoming": "following",
            "deliveryService": "did:web:ds2.example.com",
            "createdAt": "2026-08-24T12:00:00.123456Z"
        });
        assert!(validate_declaration_record_value(with_main_tag.as_object().unwrap()).is_err());

        // 3. Missing $type
        let missing_type = serde_json::json!({
            "protocolVersion": "1",
            "allowIncoming": "all",
            "deliveryService": "did:web:chat.catbird.blue",
            "createdAt": "2026-08-24T12:00:00Z"
        });
        assert!(validate_declaration_record_value(missing_type.as_object().unwrap()).is_err());

        // 4. Wrong $type
        let wrong_type = serde_json::json!({
            "$type": "blue.catbird.chat.wrong",
            "protocolVersion": "1",
            "allowIncoming": "all",
            "deliveryService": "did:web:chat.catbird.blue",
            "createdAt": "2026-08-24T12:00:00Z"
        });
        assert!(validate_declaration_record_value(wrong_type.as_object().unwrap()).is_err());

        // 5. Unsupported protocolVersion ("2")
        let wrong_version = serde_json::json!({
            "$type": "blue.catbird.chat.declaration",
            "protocolVersion": "2",
            "allowIncoming": "all",
            "deliveryService": "did:web:chat.catbird.blue",
            "createdAt": "2026-08-24T12:00:00Z"
        });
        assert!(validate_declaration_record_value(wrong_version.as_object().unwrap()).is_err());

        // 6. Invalid createdAt (not RFC3339)
        let invalid_date = serde_json::json!({
            "$type": "blue.catbird.chat.declaration",
            "protocolVersion": "1",
            "allowIncoming": "all",
            "deliveryService": "did:web:chat.catbird.blue",
            "createdAt": "not-a-datetime"
        });
        assert!(validate_declaration_record_value(invalid_date.as_object().unwrap()).is_err());

        // 7. Missing allowIncoming
        let missing_allow = serde_json::json!({
            "$type": "blue.catbird.chat.declaration",
            "protocolVersion": "1",
            "deliveryService": "did:web:chat.catbird.blue",
            "createdAt": "2026-08-24T12:00:00Z"
        });
        assert!(validate_declaration_record_value(missing_allow.as_object().unwrap()).is_err());

        // 8. Missing deliveryService
        let missing_ds = serde_json::json!({
            "$type": "blue.catbird.chat.declaration",
            "protocolVersion": "1",
            "allowIncoming": "all",
            "createdAt": "2026-08-24T12:00:00Z"
        });
        assert!(validate_declaration_record_value(missing_ds.as_object().unwrap()).is_err());

        // 9. deliveryService with URL instead of DID
        let url_ds = serde_json::json!({
            "$type": "blue.catbird.chat.declaration",
            "protocolVersion": "1",
            "allowIncoming": "all",
            "deliveryService": "https://chat.catbird.blue",
            "createdAt": "2026-08-24T12:00:00Z"
        });
        assert!(validate_declaration_record_value(url_ds.as_object().unwrap()).is_err());

        // 10. deliveryService with fragment
        let fragment_ds = serde_json::json!({
            "$type": "blue.catbird.chat.declaration",
            "protocolVersion": "1",
            "allowIncoming": "all",
            "deliveryService": "did:web:chat.catbird.blue#atproto_mls",
            "createdAt": "2026-08-24T12:00:00Z"
        });
        assert!(validate_declaration_record_value(fragment_ds.as_object().unwrap()).is_err());
    }

    #[test]
    fn test_declaration_allow_incoming_values_accepted() {
        for consent in ["all", "following", "none"] {
            let record = serde_json::json!({
                "$type": "blue.catbird.chat.declaration",
                "protocolVersion": "1",
                "allowIncoming": consent,
                "deliveryService": "did:web:ds.example.com",
                "createdAt": "2026-08-24T12:00:00Z"
            });

            let (_, allow_incoming) =
                validate_declaration_record_value(record.as_object().unwrap()).unwrap();
            assert_eq!(allow_incoming, consent);
        }
    }

    #[tokio::test]
    async fn test_resolve_ds_did_to_endpoint_non_recursive() {
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

        // Self DID resolves to self_endpoint immediately
        let self_endpoint = resolver
            .resolve_ds_did_to_endpoint("did:web:self.example.com")
            .await
            .expect("self DS DID resolves to self endpoint");
        assert_eq!(self_endpoint, "https://self.example.com");

        // Public IP did:web resolves to direct endpoint without DNS
        let remote_endpoint = resolver
            .resolve_ds_did_to_endpoint("did:web:8.8.8.8")
            .await
            .expect("public ip did:web resolves to https endpoint");
        assert_eq!(remote_endpoint, "https://8.8.8.8");
    }

    #[tokio::test]
    async fn test_resolve_ds_did_has_no_default_fallback() {
        // 1. Test offline resolution method rejects unresolvable DS DID without network/DB
        let pool_lazy = PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/nonexistent_resolver_test")
            .expect("lazy pool");
        let resolver_lazy = DsResolver::new(
            pool_lazy,
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            Some((
                "did:web:default-ds.example.com".to_string(),
                "https://default-ds.example.com".to_string(),
            )),
            3600,
        );
        let err_direct = resolver_lazy
            .resolve_ds_did_to_endpoint("did:key:unresolvable")
            .await
            .unwrap_err();
        assert!(matches!(
            err_direct,
            FederationError::ResolutionFailed { .. }
        ));
        let pool = setup_cache_test_pool().await;
        let resolver = DsResolver::new(
            pool,
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            Some((
                "did:web:default-ds.example.com".to_string(),
                "https://default-ds.example.com".to_string(),
            )),
            3600,
        );
        let err = resolver
            .resolve_ds_did("did:key:unresolvable")
            .await
            .unwrap_err();
        assert!(matches!(err, FederationError::ResolutionFailed { .. }));
    }

    #[tokio::test]
    async fn test_untrusted_peer_resolves_in_naming_layer() {
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

        // Naming layer resolves untrusted peer DS successfully (peer policy is enforced at use)
        let endpoint = resolver
            .resolve_ds_did_to_endpoint("did:web:1.1.1.1")
            .await
            .expect("naming resolution succeeds for untrusted peer");
        assert_eq!(endpoint, "https://1.1.1.1");
    }

    #[tokio::test]
    async fn test_fetch_repo_record_mock_pds_and_declaration_flow() {
        std::env::set_var("FEDERATION_ALLOW_INSECURE_HTTP", "true");
        std::env::set_var("APP_ENV", "test");
        use axum::extract::Query;
        use axum::http::StatusCode;
        use axum::response::{IntoResponse, Json};
        use axum::routing::get;
        use axum::Router;
        use std::collections::HashMap;
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.getRecord",
            get(|Query(params): Query<HashMap<String, String>>| async move {
                let collection = params.get("collection").map(String::as_str).unwrap_or("");
                let rkey = params.get("rkey").map(String::as_str).unwrap_or("");

                match (collection, rkey) {
                    ("blue.catbird.chat.declaration", "self") => (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "uri": "at://did:plc:alice/blue.catbird.chat.declaration/self",
                            "cid": "cid-declaration-1",
                            "value": {
                                "$type": "blue.catbird.chat.declaration",
                                "protocolVersion": "1",
                                "allowIncoming": "all",
                                "deliveryService": "did:web:8.8.8.8",
                                "createdAt": "2026-08-24T12:00:00Z"
                            }
                        })),
                    )
                        .into_response(),
                    ("blue.catbird.chat.profile", "self") => (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "uri": "at://did:plc:alice/blue.catbird.chat.profile/self",
                            "cid": "cid-profile-1",
                            "value": {
                                "deliveryService": "https://8.8.8.8",
                                "supportedCipherSuites": ["MLS_128_HPKE_P256_AES128GCM_SHA256_Ed25519"]
                            }
                        })),
                    )
                        .into_response(),
                    _ => (StatusCode::NOT_FOUND, "Record not found").into_response(),
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let pds_endpoint = format!("http://{addr}");
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

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

        // 1. Fetch declaration record from mock PDS
        let decl_body = resolver
            .fetch_repo_record(
                &pds_endpoint,
                "did:plc:alice",
                DECLARATION_COLLECTION,
                DECLARATION_RKEY,
                deadline,
            )
            .await
            .expect("fetch declaration record succeeds");

        let decl_val = decl_body.get("value").and_then(|v| v.as_object()).unwrap();
        let (decl_ds, _) = validate_declaration_record_value(decl_val).expect("valid declaration");
        assert_eq!(decl_ds, "did:web:8.8.8.8");

        // Convert declared DS to endpoint without recursive actor mapping
        let ds_endpoint = resolver
            .resolve_ds_did_to_endpoint(&decl_ds)
            .await
            .expect("resolve declared DS DID succeeds");
        assert_eq!(ds_endpoint, "https://8.8.8.8");

        // 2. Fetch nonexistent record returns 404 error
        let err = resolver
            .fetch_repo_record(
                &pds_endpoint,
                "did:plc:alice",
                "nonexistent.collection",
                "self",
                deadline,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("PDS returned status 404"));
    }

    #[tokio::test]
    async fn test_declaration_wrong_type_falls_through_to_profile() {
        std::env::set_var("FEDERATION_ALLOW_INSECURE_HTTP", "true");
        std::env::set_var("APP_ENV", "test");

        use axum::extract::Query;
        use axum::http::StatusCode;
        use axum::response::{IntoResponse, Json};
        use axum::routing::get;
        use axum::Router;
        use std::collections::HashMap;
        // Mock PDS returns declaration with wrong $type (#main) and a valid profile
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.getRecord",
            get(|Query(params): Query<HashMap<String, String>>| async move {
                let collection = params.get("collection").map(String::as_str).unwrap_or("");
                match collection {
                    "blue.catbird.chat.declaration" => (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "uri": "at://did:plc:alice/blue.catbird.chat.declaration/self",
                            "cid": "cid-declaration-wrong",
                            "value": {
                                "$type": "blue.catbird.chat.declaration#main",
                                "protocolVersion": "1",
                                "allowIncoming": "all",
                                "deliveryService": "did:web:declaration-wrong.example.com",
                                "createdAt": "2026-08-24T12:00:00Z"
                            }
                        })),
                    )
                        .into_response(),
                    "blue.catbird.chat.profile" => (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "uri": "at://did:plc:alice/blue.catbird.chat.profile/self",
                            "cid": "cid-profile-1",
                            "value": {
                                "deliveryService": "https://8.8.8.8",
                                "supportedCipherSuites": ["MLS_128_HPKE_P256_AES128GCM_SHA256_Ed25519"]
                            }
                        })),
                    )
                        .into_response(),
                    _ => (StatusCode::NOT_FOUND, "Record not found").into_response(),
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let pds_endpoint = format!("http://{addr}");
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

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

        // Fetching declaration directly and validating fails
        let decl_body = resolver
            .fetch_repo_record(
                &pds_endpoint,
                "did:plc:alice",
                DECLARATION_COLLECTION,
                DECLARATION_RKEY,
                deadline,
            )
            .await
            .expect("fetch declaration record succeeds");
        let decl_val = decl_body.get("value").and_then(|v| v.as_object()).unwrap();
        assert!(validate_declaration_record_value(decl_val).is_err());

        // Profile record fetch succeeds
        let profile_body = resolver
            .fetch_repo_record(
                &pds_endpoint,
                "did:plc:alice",
                PROFILE_COLLECTION,
                PROFILE_RKEY,
                deadline,
            )
            .await
            .expect("fetch profile record succeeds");
        assert!(profile_body.get("value").is_some());
    }

    #[tokio::test]
    async fn test_migration_purges_legacy_actor_keyed_ds_endpoints_row() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for migration test");

        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect to test db must succeed when TEST_DATABASE_URL is set");
        let mut conn = pool
            .acquire()
            .await
            .expect("acquire connection for migration test");
        let schema_name = format!("test_mig_{}", Uuid::new_v4().as_simple());
        sqlx::query(&format!("CREATE SCHEMA {schema_name};"))
            .execute(&mut *conn)
            .await
            .expect("create test schema");

        sqlx::query(&format!("SET search_path TO {schema_name};"))
            .execute(&mut *conn)
            .await
            .expect("set search path");

        // Seed pre-migration table definition in isolated schema
        sqlx::query(
            "CREATE TABLE ds_endpoints (
                did TEXT PRIMARY KEY,
                endpoint TEXT NOT NULL,
                supported_cipher_suites TEXT,
                resolved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour'
            );",
        )
        .execute(&mut *conn)
        .await
        .expect("create pre-migration table");

        let actor_did = format!("did:plc:legacy{}", Uuid::new_v4().as_simple())[..32].to_string();
        sqlx::query(
            "INSERT INTO ds_endpoints (did, endpoint, supported_cipher_suites, resolved_at, expires_at)
             VALUES ($1, 'https://legacy.example.com', NULL, NOW(), NOW() + INTERVAL '1 hour');",
        )
        .bind(&actor_did)
        .execute(&mut *conn)
        .await
        .expect("insert legacy actor-keyed row");

        // Apply target migration SQL once into the isolated schema
        let migration_sql =
            include_str!("../../migrations/20260824000002_chat_actor_ds_mapping.sql");
        sqlx::raw_sql(migration_sql)
            .execute(&mut *conn)
            .await
            .expect("applying migration SQL in isolated schema must succeed");

        // Assert legacy row is gone from ds_endpoints
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ds_endpoints WHERE did = $1")
            .bind(&actor_did)
            .fetch_one(&mut *conn)
            .await
            .expect("query count of legacy row");
        assert_eq!(
            count, 0,
            "legacy actor-keyed row must be purged by migration"
        );

        // Cleanup isolated schema
        let _ = sqlx::query(&format!("DROP SCHEMA {schema_name} CASCADE;"))
            .execute(&mut *conn)
            .await;
    }
}
