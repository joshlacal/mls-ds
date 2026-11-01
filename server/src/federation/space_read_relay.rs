//! `3A` Stateless Home-`mls-ds` Space Credential & Space Read Relays (`D1`, `3A`).
//!
//! Preserves metadata privacy when a client accesses a remote Space Authority or remote writer PDS:
//! - The client connects ONLY to its own home `mls-ds` (`blue.catbird.chat.relaySpaceCredential`
//!   and `blue.catbird.chat.relaySpaceRead`).
//! - The home `mls-ds` resolves the target DID's HTTPS `:443` endpoint, enforces DNS-pinned SSRF
//!   protection (`M-F06`), enforces a strict read-only `com.atproto.space.*` NSID allowlist,
//!   forwards the client's RFC 9421 PoP headers (`Authorization`, `Atproto-Space-Audience`,
//!   `Atproto-Space-Want-Mac`, `Signature-Input`, `Signature`) untouched, preserves upstream
//!   `Atproto-Space-Mac`, sets `Access-Control-Expose-Headers: Atproto-Space-Mac`, and writes
//!   ZERO operational database rows on the home `mls-ds`!

use std::{collections::HashMap, net::SocketAddr, sync::RwLock, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::push_gateway::ssrf::{system_dns_resolve, validate_https_url_with_resolver};

/// Closed allowlist of read-only `com.atproto.space.*` NSIDs permitted through `relaySpaceRead` (`3A`).
pub const ALLOWED_SPACE_READ_NSIDS: &[&str] = &[
    "com.atproto.space.listRepos",
    "com.atproto.space.getSpace",
    "com.atproto.space.listRecords",
    "com.atproto.space.getRecord",
    "com.atproto.space.listRepoOps",
    "com.atproto.space.getLatestCommit",
    "com.atproto.space.getRepo",
    "com.atproto.space.getBlob",
];

pub fn is_allowed_space_read_nsid(nsid: &str) -> bool {
    ALLOWED_SPACE_READ_NSIDS.contains(&nsid)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpaceRelayError {
    #[error("disallowed Space read NSID: {0}")]
    InvalidNsid(String),
    #[error("invalid or SSRF-blocked target endpoint: {0}")]
    InvalidTargetEndpoint(String),
    #[error("invalid delegation token rejected upstream: {0}")]
    InvalidDelegationToken(String),
    #[error("upstream Space endpoint error: {0}")]
    UpstreamError(String),
}

#[derive(Debug, Clone)]
struct ResolvedRelayEndpoint {
    base_url: String,
    host: String,
    pinned_addrs: Vec<SocketAddr>,
    is_test_override: bool,
}

#[cfg(any(test, feature = "test-support"))]
fn test_relay_targets() -> &'static RwLock<HashMap<String, String>> {
    static TARGETS: once_cell::sync::Lazy<RwLock<HashMap<String, String>>> =
        once_cell::sync::Lazy::new(|| RwLock::new(HashMap::new()));
    &TARGETS
}

/// Register a test-only loopback Space target endpoint for `target_did`.
#[cfg(any(test, feature = "test-support"))]
pub fn register_test_space_relay_target(target_did: &str, loopback_base_url: &str) {
    let norm = crate::identity::canonical_did(target_did).to_string();
    if let Ok(mut guard) = test_relay_targets().write() {
        guard.insert(norm, loopback_base_url.trim_end_matches('/').to_string());
    }
}

async fn resolve_ssrf_safe_space_endpoint(
    target_did: &str,
) -> Result<ResolvedRelayEndpoint, SpaceRelayError> {
    let bare_did = crate::identity::canonical_did(target_did).to_string();

    #[cfg(any(test, feature = "test-support"))]
    if let Some(loopback) = test_relay_targets()
        .read()
        .ok()
        .and_then(|m| m.get(&bare_did).cloned())
    {
        return Ok(ResolvedRelayEndpoint {
            base_url: loopback,
            host: "127.0.0.1".to_string(),
            pinned_addrs: Vec::new(),
            is_test_override: true,
        });
    }

    if bare_did.starts_with("did:web:") {
        let base_url = crate::identity::did_web_service_endpoint(&bare_did).ok_or_else(|| {
            SpaceRelayError::InvalidTargetEndpoint(format!("bad did:web: {bare_did}"))
        })?;
        let trimmed = base_url.trim_end_matches('/').to_string();
        let validated = validate_https_url_with_resolver(&trimmed, None, false, system_dns_resolve)
            .map_err(|e| SpaceRelayError::InvalidTargetEndpoint(e.to_string()))?;
        return Ok(ResolvedRelayEndpoint {
            base_url: trimmed,
            host: validated.host,
            pinned_addrs: validated.pinned_addrs,
            is_test_override: false,
        });
    }

    if bare_did.starts_with("did:plc:") {
        let plc_base = std::env::var("PLC_DIRECTORY_URL")
            .unwrap_or_else(|_| "https://plc.directory".to_string());
        let plc_url = format!("{}/{}", plc_base.trim_end_matches('/'), bare_did);
        let validated_plc =
            validate_https_url_with_resolver(&plc_url, None, false, system_dns_resolve)
                .map_err(|e| SpaceRelayError::InvalidTargetEndpoint(e.to_string()))?;
        let plc_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .resolve_to_addrs(&validated_plc.host, &validated_plc.pinned_addrs)
            .build()
            .map_err(|e| SpaceRelayError::UpstreamError(e.to_string()))?;
        let doc_resp = plc_client
            .get(&validated_plc.effective_url)
            .send()
            .await
            .map_err(|e| SpaceRelayError::UpstreamError(e.to_string()))?;
        if !doc_resp.status().is_success() {
            return Err(SpaceRelayError::InvalidTargetEndpoint(format!(
                "PLC resolution HTTP {}",
                doc_resp.status().as_u16()
            )));
        }
        let doc: Value = doc_resp
            .json()
            .await
            .map_err(|e| SpaceRelayError::InvalidTargetEndpoint(e.to_string()))?;
        let svc_ep = doc
            .get("service")
            .and_then(Value::as_array)
            .and_then(|arr| {
                arr.iter().find_map(|s| {
                    let id = s.get("id").and_then(Value::as_str)?;
                    if id.ends_with("#atproto_pds") || id.ends_with("#atproto_mls") {
                        s.get("serviceEndpoint").and_then(Value::as_str)
                    } else {
                        None
                    }
                })
            })
            .ok_or_else(|| {
                SpaceRelayError::InvalidTargetEndpoint(
                    "missing #atproto_pds/#atproto_mls service".into(),
                )
            })?
            .trim_end_matches('/')
            .to_string();

        let validated = validate_https_url_with_resolver(&svc_ep, None, false, system_dns_resolve)
            .map_err(|e| SpaceRelayError::InvalidTargetEndpoint(e.to_string()))?;
        return Ok(ResolvedRelayEndpoint {
            base_url: svc_ep,
            host: validated.host,
            pinned_addrs: validated.pinned_addrs,
            is_test_override: false,
        });
    }

    Err(SpaceRelayError::InvalidTargetEndpoint(format!(
        "unsupported DID method: {bare_did}"
    )))
}

fn build_pinned_client(target: &ResolvedRelayEndpoint) -> Result<reqwest::Client, SpaceRelayError> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15));
    if !target.is_test_override && !target.pinned_addrs.is_empty() {
        builder = builder.resolve_to_addrs(&target.host, &target.pinned_addrs);
    }
    builder
        .build()
        .map_err(|e| SpaceRelayError::UpstreamError(e.to_string()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayedCredentialOutput {
    pub credential: String,
    pub expires_at: String,
}

/// Statelessly exchange a PDS delegation token at `authority_did` via `com.atproto.space.getSpaceCredential`.
pub async fn relay_space_credential_stateless(
    authority_did: &str,
    space_uri: &str,
    delegation_token: &str,
    cnf_key: Option<&str>,
) -> Result<RelayedCredentialOutput, SpaceRelayError> {
    let target = resolve_ssrf_safe_space_endpoint(authority_did).await?;
    let client = build_pinned_client(&target)?;

    let mut url = format!(
        "{}/xrpc/com.atproto.space.getSpaceCredential?space={}&delegationToken={}",
        target.base_url,
        urlencoding::encode(space_uri),
        urlencoding::encode(delegation_token),
    );
    if let Some(kid) = cnf_key {
        url.push_str("&credentialKid=");
        url.push_str(&urlencoding::encode(kid));
    }

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| SpaceRelayError::UpstreamError(e.to_string()))?;
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| SpaceRelayError::UpstreamError(e.to_string()))?;

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(SpaceRelayError::InvalidDelegationToken(
            String::from_utf8_lossy(&bytes).into_owned(),
        ));
    }
    if !status.is_success() {
        return Err(SpaceRelayError::UpstreamError(format!(
            "upstream getSpaceCredential HTTP {}: {}",
            status.as_u16(),
            String::from_utf8_lossy(&bytes)
        )));
    }

    serde_json::from_slice::<RelayedCredentialOutput>(&bytes)
        .map_err(|e| SpaceRelayError::UpstreamError(e.to_string()))
}

pub struct RelayedSpaceReadResponse {
    pub status: u16,
    pub content_type: String,
    pub space_mac: Option<String>,
    pub body: Vec<u8>,
}

/// Statelessly relay an RFC 9421 PoP-signed `com.atproto.space.*` read request to `target_did`.
pub async fn relay_space_read_stateless(
    target_did: &str,
    nsid: &str,
    query: Option<&str>,
    credential: &str,
    space_audience: &str,
    want_mac: Option<&str>,
    signature_input: &str,
    signature: &str,
) -> Result<RelayedSpaceReadResponse, SpaceRelayError> {
    if !is_allowed_space_read_nsid(nsid) {
        return Err(SpaceRelayError::InvalidNsid(nsid.to_string()));
    }

    let target = resolve_ssrf_safe_space_endpoint(target_did).await?;
    let client = build_pinned_client(&target)?;

    let mut url = format!("{}/xrpc/{nsid}", target.base_url);
    if let Some(q) = query.filter(|s| !s.is_empty()) {
        if q.contains('\r') || q.contains('\n') || q.contains('#') {
            return Err(SpaceRelayError::InvalidTargetEndpoint(
                "malformed query string".into(),
            ));
        }
        url.push('?');
        url.push_str(q.trim_start_matches('?'));
    }

    let mut req = client
        .get(&url)
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Atproto-Space-Credential {}", credential.trim()),
        )
        .header("atproto-space-audience", space_audience.trim())
        .header("signature-input", signature_input.trim())
        .header("signature", signature.trim());
    if let Some(wm) = want_mac.filter(|s| !s.is_empty()) {
        req = req.header("atproto-space-want-mac", wm.trim());
    }

    let resp = req
        .send()
        .await
        .map_err(|e| SpaceRelayError::UpstreamError(e.to_string()))?;
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let space_mac = resp
        .headers()
        .get("atproto-space-mac")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = resp
        .bytes()
        .await
        .map_err(|e| SpaceRelayError::UpstreamError(e.to_string()))?
        .to_vec();

    if status >= 500 {
        return Err(SpaceRelayError::UpstreamError(format!(
            "upstream {nsid} returned HTTP {status}"
        )));
    }

    Ok(RelayedSpaceReadResponse {
        status,
        content_type,
        space_mac,
        body,
    })
}
