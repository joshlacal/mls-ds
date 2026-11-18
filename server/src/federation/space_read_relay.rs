//! Stateless Home-`mls-ds` Space Credential, Space Read, & Signed `mailboxKeys` Relays.
//!
//! Preserves metadata privacy when a client accesses a remote Space Authority or remote writer PDS:
//! - The client connects ONLY to its own home `mls-ds` (`blue.catbird.chat.relaySpaceCredential`,
//!   `blue.catbird.chat.relaySpaceRead`, and `blue.catbird.labyrinth.getMailboxKeysRecord`).
//! - The home `mls-ds` resolves the target DID's HTTPS `:443` endpoint, enforces DNS-pinned SSRF
//!   protection (`M-F06`), enforces a strict read-only `com.atproto.space.*` NSID allowlist,
//!   forwards the client's RFC 9421 PoP headers (`Authorization`, `Atproto-Space-Audience`,
//!   `Atproto-Space-Want-Mac`, `Accept-Signature`, `Signature-Input`, `Signature`) untouched,
//!   preserves upstream `Atproto-Space-Commit`, `Atproto-Space-Record`, `Signature-Input`,
//!   `Signature`, `Vary`, and `Atproto-Space-Mac` headers, and writes ZERO operational database
//!   rows on the home `mls-ds`.
//! - `relay_mailbox_keys_record` fetches `com.atproto.sync.getRecord` (`application/vnd.ipld.car`),
//!   verifies CARv1 block CIDs, canonical IPLD DAG-CBOR encoding, the ATProto v3 root commit
//!   signature under `targetDid`'s resolved `#atproto` key, and authenticated MST inclusion or
//!   non-inclusion before accepting any record or `404 RecordNotFound`.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::Cursor,
    net::SocketAddr,
    sync::RwLock,
    time::Duration,
};

use atproto_spaces::{
    did_resolver::DidDocument,
    kem::decode_p256_did_key,
    lthash::compute_dagcbor_cid,
    tokens::{verify_space_token, SpaceKeyResolver, SpaceTokenKind, SpaceVerifyingKey},
    SpaceUri, SpacesError,
};
use catbird_atproto::generated::blue_catbird::labyrinth::mailbox_keys::{
    MailboxKeys, MailboxKeysBackend,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

use crate::{
    federation::{
        errors::FederationError,
        resolver::{send_hardened_resolution_request, DsResolver},
    },
    push_gateway::ssrf::{
        system_dns_resolve, validate_https_url_with_resolver, PushGatewaySsrfError,
    },
    util::outbound_body::{
        collect_bounded, OutboundBodyError, ResponseBodyBudget, DID_DOCUMENT_MAX_BYTES,
        ERROR_RESPONSE_MAX_BYTES, ORDINARY_DS_CONTROL_MAX_BYTES, PROFILE_OR_DEVICE_MAX_BYTES,
    },
};

/// Closed allowlist of read-only `com.atproto.space.*` NSIDs permitted through `relaySpaceRead`.
pub const ALLOWED_SPACE_READ_NSIDS: &[&str] = &[
    "com.atproto.space.listWriters",
    "com.atproto.space.getSpace",
    "com.atproto.space.listRecords",
    "com.atproto.space.getRecord",
    "com.atproto.space.listRepoOps",
    "com.atproto.space.getLatestCommit",
    "com.atproto.space.getRepo",
    "com.atproto.space.getBlob",
];

/// Blob reads cover the client's 10 MiB encrypted-attachment ceiling plus
/// framing overhead. Repository exports are larger but still explicitly
/// bounded because this relay currently returns one in-memory HTTP body.
const SPACE_BLOB_RESPONSE_MAX_BYTES: usize = 16 * 1024 * 1024;
const SPACE_REPO_RESPONSE_MAX_BYTES: usize = 64 * 1024 * 1024;
const MAILBOX_KEYS_RECORD_MAX_BYTES: usize = 1024 * 1024;
/// `accountDeletedEntry.keyProof` and `accountDeletedEntry.revocationProof` lexicon ceiling, including CAR framing.
const CHAT_DEVICE_KEY_PROOF_MAX_BYTES: usize = 16 * 1024;
const CHAT_DEVICE_REVOCATION_PROOF_MAX_BYTES: usize = 16 * 1024;
const PDS_DEVICE_REVOCATION_DOMAIN: &[u8] = b"CATBIRD-CHAT-PDS-DEVICE-REVOCATION-V1\0";
const CAR_HEADER_MAX_BYTES: usize = 64 * 1024;
const CAR_MAX_BLOCKS: usize = 512;
const MST_MAX_DEPTH: usize = 64;
const DAGCBOR_MAX_DEPTH: usize = 32;
const DAG_CBOR_CODEC: u64 = 0x71;
const MAX_MAILBOX_EPOCH_NUMBER: i64 = 999_999_999_999;

fn space_read_response_max_bytes(nsid: &str, status: reqwest::StatusCode) -> usize {
    if !status.is_success() {
        return ERROR_RESPONSE_MAX_BYTES;
    }
    match nsid {
        "com.atproto.space.getBlob" => SPACE_BLOB_RESPONSE_MAX_BYTES,
        "com.atproto.space.getRepo" => SPACE_REPO_RESPONSE_MAX_BYTES,
        _ => ORDINARY_DS_CONTROL_MAX_BYTES,
    }
}

fn body_read_was_transient(error: &OutboundBodyError) -> bool {
    matches!(
        error,
        OutboundBodyError::DeadlineExceeded | OutboundBodyError::ReadFailed(_)
    )
}

pub fn is_allowed_space_read_nsid(nsid: &str) -> bool {
    ALLOWED_SPACE_READ_NSIDS.contains(&nsid)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpaceRelayError {
    #[error("invalid Space relay request: {0}")]
    InvalidRequest(String),
    #[error("disallowed Space read NSID: {0}")]
    InvalidNsid(String),
    #[error("invalid or SSRF-blocked target endpoint: {0}")]
    InvalidTargetEndpoint(String),
    #[error("invalid delegation token rejected upstream: {0}")]
    InvalidDelegationToken(String),
    /// The Space authority authenticated the request and denied it (HTTP 403): its exact
    /// response body, which a signed refusal must reach the client in unchanged.
    #[error("Space authority denied the credential")]
    Forbidden(bytes::Bytes),
    /// The target answered definitively but unusably (4xx, malformed or
    /// unverifiable response).
    #[error("upstream Space endpoint error: {0}")]
    UpstreamError(String),
    /// The target or a document it needs could not answer now (DNS, connect,
    /// timeout, body read, or HTTP 5xx/429). Nothing was decided: retry.
    #[error("upstream Space endpoint unavailable: {0}")]
    UpstreamUnavailable(String),
    /// A verified PDS repository proof establishes that the device was already revoked
    /// by a sibling or does not match the delete operation being attempted.
    #[error("device revocation proof rejected device authority: {0}")]
    DeviceRevoked(String),
}

/// A failed DNS lookup decided nothing; every other refusal is permanent.
fn target_endpoint_error(error: PushGatewaySsrfError) -> SpaceRelayError {
    match error {
        PushGatewaySsrfError::DnsResolutionFailed(_) => {
            SpaceRelayError::UpstreamUnavailable(error.to_string())
        }
        PushGatewaySsrfError::InvalidUrl(_)
        | PushGatewaySsrfError::NonHttpsOrBadPort
        | PushGatewaySsrfError::InvalidPathOrQuery
        | PushGatewaySsrfError::MissingHost
        | PushGatewaySsrfError::ForbiddenIp(_) => {
            SpaceRelayError::InvalidTargetEndpoint(error.to_string())
        }
    }
}

/// An upstream 5xx or 429 decided nothing.
fn retryable_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS
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
///
/// Credential fixtures must also serve the authority's `#atproto` DID document at the loopback
/// base URL's `/.well-known/did.json` (did-web-test); overriding transport never skips JWT
/// verification.
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
            .map_err(target_endpoint_error)?;
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
                .map_err(target_endpoint_error)?;
        let plc_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .resolve_to_addrs(&validated_plc.host, &validated_plc.pinned_addrs)
            .build()
            .map_err(|e| SpaceRelayError::UpstreamUnavailable(e.to_string()))?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let doc_resp = crate::sim_hooks::send_reqwest(plc_client.get(&validated_plc.effective_url))
            .await
            .map_err(SpaceRelayError::UpstreamUnavailable)?;
        let status = doc_resp.status();
        if !status.is_success() {
            let reason = format!("PLC resolution HTTP {}", status.as_u16());
            return Err(if retryable_status(status) {
                SpaceRelayError::UpstreamUnavailable(reason)
            } else {
                SpaceRelayError::InvalidTargetEndpoint(reason)
            });
        }
        let doc_bytes = collect_bounded(
            doc_resp,
            ResponseBodyBudget::new(DID_DOCUMENT_MAX_BYTES, deadline),
        )
        .await
        .map_err(|error| {
            if body_read_was_transient(&error) {
                SpaceRelayError::UpstreamUnavailable(error.to_string())
            } else {
                SpaceRelayError::InvalidTargetEndpoint(error.to_string())
            }
        })?;
        let doc: Value = serde_json::from_slice(&doc_bytes)
            .map_err(|error| SpaceRelayError::InvalidTargetEndpoint(error.to_string()))?;
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
            .map_err(target_endpoint_error)?;
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
    if target.is_test_override || target.pinned_addrs.is_empty() {
        static UNPINNED_SPACE_RELAY_CLIENT: std::sync::OnceLock<reqwest::Client> =
            std::sync::OnceLock::new();
        return Ok(UNPINNED_SPACE_RELAY_CLIENT
            .get_or_init(|| {
                reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(15))
                    .build()
                    .expect("build unpinned space relay HTTP client")
            })
            .clone());
    }
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .resolve_to_addrs(&target.host, &target.pinned_addrs)
        .build()
        .map_err(|e| SpaceRelayError::UpstreamUnavailable(e.to_string()))
}

async fn resolve_space_credential_key(
    authority_did: &str,
    target: &ResolvedRelayEndpoint,
) -> Result<SpaceVerifyingKey, SpaceRelayError> {
    let document_url = if target.is_test_override {
        // The test-only loopback override serves every authority's document here.
        format!(
            /* did-web-test */ "{}/.well-known/did.json",
            target.base_url
        )
    } else if authority_did.starts_with("did:web:") {
        crate::identity::did_web_document_url(authority_did).ok_or_else(|| {
            SpaceRelayError::InvalidTargetEndpoint("invalid authority did:web".into())
        })?
    } else {
        let plc_base = std::env::var("PLC_DIRECTORY_URL")
            .unwrap_or_else(|_| "https://plc.directory".to_string());
        format!("{}/{}", plc_base.trim_end_matches('/'), authority_did)
    };
    let (document_url, client) = if target.is_test_override {
        (document_url, build_pinned_client(target)?)
    } else {
        let validated =
            validate_https_url_with_resolver(&document_url, None, false, system_dns_resolve)
                .map_err(target_endpoint_error)?;
        let document_target = ResolvedRelayEndpoint {
            base_url: validated.effective_url,
            host: validated.host,
            pinned_addrs: validated.pinned_addrs,
            is_test_override: false,
        };
        let client = build_pinned_client(&document_target)?;
        (document_target.base_url, client)
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let response = crate::sim_hooks::send_reqwest(client.get(&document_url))
        .await
        .map_err(SpaceRelayError::UpstreamUnavailable)?;
    let status = response.status();
    if !status.is_success() {
        let reason = format!("authority DID document HTTP {}", status.as_u16());
        return Err(if retryable_status(status) {
            SpaceRelayError::UpstreamUnavailable(reason)
        } else {
            SpaceRelayError::UpstreamError(reason)
        });
    }
    let bytes = collect_bounded(
        response,
        ResponseBodyBudget::new(DID_DOCUMENT_MAX_BYTES, deadline),
    )
    .await
    .map_err(|e| match e {
        OutboundBodyError::DeadlineExceeded | OutboundBodyError::ReadFailed(_) => {
            SpaceRelayError::UpstreamUnavailable(e.to_string())
        }
        OutboundBodyError::DeclaredTooLarge { .. }
        | OutboundBodyError::StreamedTooLarge { .. }
        | OutboundBodyError::LengthOverflow
        | OutboundBodyError::InvalidJson(_) => SpaceRelayError::UpstreamError(e.to_string()),
    })?;
    DidDocument::parse_json(authority_did, &bytes)
        .map_err(|e| SpaceRelayError::UpstreamError(e.to_string()))?
        .atproto_key
        .ok_or_else(|| {
            SpaceRelayError::UpstreamError("authority has no #atproto signing key".into())
        })
}

struct CredentialAuthorityKey<'a> {
    authority_did: &'a str,
    key: SpaceVerifyingKey,
}

#[async_trait::async_trait(?Send)]
impl SpaceKeyResolver for CredentialAuthorityKey<'_> {
    async fn resolve_atproto_key(
        &self,
        did_or_issuer: &str,
        _force_refresh: bool,
    ) -> atproto_spaces::Result<SpaceVerifyingKey> {
        if did_or_issuer != self.authority_did {
            return Err(SpacesError::InvalidSpaceCredential(
                "credential issuer does not match requested authority".into(),
            ));
        }
        Ok(self.key.clone())
    }
}

/// Optional Nov-12 `authorizeSpaceSync` inputs forwarded through `relaySpaceCredential`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RelayCredentialOptions<'a> {
    pub client_attestation: Option<&'a str>,
    pub notify: Option<(&'a str, &'a str)>,
    pub space_rev: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamNotifyTarget<'a> {
    endpoint: &'a str,
    token: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamCredentialRequest<'a> {
    space: &'a str,
    credential_key: &'a str,
    delegation_token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_attestation: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notify: Option<UpstreamNotifyTarget<'a>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamCredentialOutput {
    credential: String,
    #[serde(default)]
    space_rev: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayedCredentialOutput {
    pub credential: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_rev: Option<String>,
}

/// Exchange via standard POST JSON (`com.atproto.space.authorizeSpaceSync`) and return only an
/// authority-verified, PoP-bound credential.
pub async fn relay_space_credential_stateless(
    authority_did: &str,
    space_uri: &str,
    delegation_token: &str,
    credential_key: &str,
) -> Result<RelayedCredentialOutput, SpaceRelayError> {
    relay_space_credential_with_options(
        authority_did,
        space_uri,
        delegation_token,
        credential_key,
        RelayCredentialOptions::default(),
    )
    .await
}

/// Exchange via standard POST JSON (`com.atproto.space.authorizeSpaceSync`) with optional Nov-12
/// `clientAttestation`, `notify`, and `spaceRev` parameters.
pub async fn relay_space_credential_with_options(
    authority_did: &str,
    space_uri: &str,
    delegation_token: &str,
    credential_key: &str,
    options: RelayCredentialOptions<'_>,
) -> Result<RelayedCredentialOutput, SpaceRelayError> {
    let authority_did = crate::identity::canonical_did(authority_did);
    let space = SpaceUri::parse_hedged(space_uri)
        .map_err(|e| SpaceRelayError::InvalidRequest(e.to_string()))?;
    if space.authority != authority_did {
        return Err(SpaceRelayError::InvalidRequest(
            "Space authority does not match authorityDid".into(),
        ));
    }
    decode_p256_did_key(credential_key)
        .map_err(|e| SpaceRelayError::InvalidRequest(e.to_string()))?;
    if let Some(rev) = options.space_rev {
        if crate::space_host::decode_tid_micros(rev).is_none() {
            return Err(SpaceRelayError::InvalidRequest(
                "spaceRev must be a canonical 13-character TID".into(),
            ));
        }
    }

    let target = resolve_ssrf_safe_space_endpoint(authority_did).await?;
    let client = build_pinned_client(&target)?;

    let url = format!(
        "{}/xrpc/com.atproto.space.authorizeSpaceSync",
        target.base_url
    );
    let request = UpstreamCredentialRequest {
        space: space.as_str(),
        credential_key,
        delegation_token,
        client_attestation: options.client_attestation.filter(|s| !s.is_empty()),
        notify: options
            .notify
            .map(|(endpoint, token)| UpstreamNotifyTarget { endpoint, token }),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let resp = crate::sim_hooks::send_reqwest(client.post(&url).json(&request))
        .await
        .map_err(SpaceRelayError::UpstreamUnavailable)?;
    let status = resp.status();
    let max_bytes = if status.is_success() {
        PROFILE_OR_DEVICE_MAX_BYTES
    } else {
        ERROR_RESPONSE_MAX_BYTES
    };
    let bytes = collect_bounded(resp, ResponseBodyBudget::new(max_bytes, deadline))
        .await
        .map_err(|error| {
            let reason = error.to_string();
            if retryable_status(status) || body_read_was_transient(&error) {
                SpaceRelayError::UpstreamUnavailable(reason)
            } else if status == reqwest::StatusCode::UNAUTHORIZED {
                SpaceRelayError::InvalidDelegationToken(reason)
            } else if status == reqwest::StatusCode::FORBIDDEN {
                // An unreadable refusal carries no signature the client could verify.
                SpaceRelayError::Forbidden(bytes::Bytes::new())
            } else {
                SpaceRelayError::UpstreamError(reason)
            }
        })?;

    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(SpaceRelayError::InvalidDelegationToken(
            String::from_utf8_lossy(&bytes).into_owned(),
        ));
    }
    if status == reqwest::StatusCode::FORBIDDEN {
        return Err(SpaceRelayError::Forbidden(bytes));
    }
    if !status.is_success() {
        let reason = format!(
            "upstream authorizeSpaceSync HTTP {}: {}",
            status.as_u16(),
            String::from_utf8_lossy(&bytes)
        );
        return Err(if retryable_status(status) {
            SpaceRelayError::UpstreamUnavailable(reason)
        } else {
            SpaceRelayError::UpstreamError(reason)
        });
    }

    let upstream: UpstreamCredentialOutput = serde_json::from_slice(&bytes)
        .map_err(|e| SpaceRelayError::UpstreamError(e.to_string()))?;
    if let Some(ref rev) = upstream.space_rev {
        if crate::space_host::decode_tid_micros(rev).is_none() {
            return Err(SpaceRelayError::UpstreamError(
                "upstream authorizeSpaceSync returned malformed spaceRev".into(),
            ));
        }
    }

    let resolver = CredentialAuthorityKey {
        authority_did,
        key: resolve_space_credential_key(authority_did, &target).await?,
    };
    let now_sec = crate::sim_hooks::current_utc().timestamp().max(0) as u64;
    // The token API's resolver future is !Send; this pre-resolved key performs no I/O.
    let claims = futures::executor::block_on(verify_space_token(
        SpaceTokenKind::Credential,
        &upstream.credential,
        &resolver,
        now_sec,
    ))
    .map_err(|e| SpaceRelayError::UpstreamError(e.to_string()))?;
    let claim_space = SpaceUri::parse_hedged(&claims.sub).ok();
    if claims.iss != authority_did
        || claim_space.as_ref() != Some(&space)
        || claims.cnf_kid.as_deref() != Some(credential_key)
        || claims.exp <= now_sec
    {
        return Err(SpaceRelayError::UpstreamError(
            "credential failed issuer/Space/PoP-key/expiry binding checks".into(),
        ));
    }
    let expires_at = i64::try_from(claims.exp)
        .ok()
        .and_then(|exp| chrono::DateTime::from_timestamp(exp, 0))
        .ok_or_else(|| SpaceRelayError::UpstreamError("invalid credential expiry".into()))?
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    Ok(RelayedCredentialOutput {
        credential: upstream.credential,
        expires_at,
        space_rev: upstream.space_rev,
    })
}

fn valid_record_key(rkey: &str) -> bool {
    (1..=512).contains(&rkey.len())
        && rkey != "."
        && rkey != ".."
        && rkey.is_ascii()
        && rkey.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'~' | b'-')
        })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CarHeader {
    roots: Vec<cid::Cid>,
    version: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedAtprotoCommitV3 {
    did: String,
    rev: String,
    data: cid::Cid,
    prev: Option<cid::Cid>,
    version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedAtprotoCommitV3 {
    did: String,
    rev: String,
    #[serde(with = "serde_bytes")]
    sig: Vec<u8>,
    data: cid::Cid,
    prev: Option<cid::Cid>,
    version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MstTreeEntry {
    #[serde(with = "serde_bytes")]
    k: Vec<u8>,
    p: usize,
    t: Option<cid::Cid>,
    v: cid::Cid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MstNodeData {
    e: Vec<MstTreeEntry>,
    l: Option<cid::Cid>,
}

fn read_uvarint(bytes: &[u8], pos: &mut usize) -> Result<u64, SpaceRelayError> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for _ in 0..9 {
        let byte = *bytes
            .get(*pos)
            .ok_or_else(|| SpaceRelayError::UpstreamError("truncated CAR varint".into()))?;
        *pos += 1;
        if byte < 0x80 {
            if shift > 0 && byte == 0 {
                return Err(SpaceRelayError::UpstreamError(
                    "non-minimal CAR varint".into(),
                ));
            }
            return Ok(value | ((byte as u64) << shift));
        }
        value |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
    }
    Err(SpaceRelayError::UpstreamError("CAR varint overflow".into()))
}

fn read_cbor_uint(bytes: &[u8], pos: &mut usize, info: u8) -> Result<u64, SpaceRelayError> {
    match info {
        0..=23 => Ok(info as u64),
        24 => {
            let v = *bytes
                .get(*pos)
                .ok_or_else(|| SpaceRelayError::UpstreamError("truncated CBOR uint8".into()))?;
            *pos += 1;
            if v < 24 {
                return Err(SpaceRelayError::UpstreamError(
                    "non-canonical CBOR uint8".into(),
                ));
            }
            Ok(v as u64)
        }
        25 => {
            let slice = bytes
                .get(*pos..pos.saturating_add(2))
                .filter(|s| s.len() == 2)
                .ok_or_else(|| SpaceRelayError::UpstreamError("truncated CBOR uint16".into()))?;
            *pos += 2;
            let v = u16::from_be_bytes([slice[0], slice[1]]);
            if v <= u8::MAX as u16 {
                return Err(SpaceRelayError::UpstreamError(
                    "non-canonical CBOR uint16".into(),
                ));
            }
            Ok(v as u64)
        }
        26 => {
            let slice = bytes
                .get(*pos..pos.saturating_add(4))
                .filter(|s| s.len() == 4)
                .ok_or_else(|| SpaceRelayError::UpstreamError("truncated CBOR uint32".into()))?;
            *pos += 4;
            let v = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
            if v <= u16::MAX as u32 {
                return Err(SpaceRelayError::UpstreamError(
                    "non-canonical CBOR uint32".into(),
                ));
            }
            Ok(v as u64)
        }
        27 => {
            let slice = bytes
                .get(*pos..pos.saturating_add(8))
                .filter(|s| s.len() == 8)
                .ok_or_else(|| SpaceRelayError::UpstreamError("truncated CBOR uint64".into()))?;
            *pos += 8;
            let v = u64::from_be_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ]);
            if v <= u32::MAX as u64 {
                return Err(SpaceRelayError::UpstreamError(
                    "non-canonical CBOR uint64".into(),
                ));
            }
            Ok(v)
        }
        _ => Err(SpaceRelayError::UpstreamError(
            "indefinite or reserved CBOR additional info".into(),
        )),
    }
}

fn verify_canonical_dagcbor_item(
    bytes: &[u8],
    pos: &mut usize,
    depth: usize,
) -> Result<(), SpaceRelayError> {
    if depth > DAGCBOR_MAX_DEPTH {
        return Err(SpaceRelayError::UpstreamError(
            "DAG-CBOR nesting depth exceeded".into(),
        ));
    }
    let head = *bytes
        .get(*pos)
        .ok_or_else(|| SpaceRelayError::UpstreamError("truncated DAG-CBOR item".into()))?;
    *pos += 1;
    let major = head >> 5;
    let info = head & 0x1f;
    match major {
        0 | 1 => {
            read_cbor_uint(bytes, pos, info)?;
            Ok(())
        }
        2 => {
            let len = usize::try_from(read_cbor_uint(bytes, pos, info)?)
                .map_err(|_| SpaceRelayError::UpstreamError("CBOR bytes length overflow".into()))?;
            let end = pos
                .checked_add(len)
                .filter(|&end| end <= bytes.len())
                .ok_or_else(|| SpaceRelayError::UpstreamError("truncated CBOR bytes".into()))?;
            *pos = end;
            Ok(())
        }
        3 => {
            let len = usize::try_from(read_cbor_uint(bytes, pos, info)?)
                .map_err(|_| SpaceRelayError::UpstreamError("CBOR text length overflow".into()))?;
            let end = pos
                .checked_add(len)
                .filter(|&end| end <= bytes.len())
                .ok_or_else(|| SpaceRelayError::UpstreamError("truncated CBOR text".into()))?;
            std::str::from_utf8(&bytes[*pos..end])
                .map_err(|_| SpaceRelayError::UpstreamError("invalid UTF-8 in CBOR text".into()))?;
            *pos = end;
            Ok(())
        }
        4 => {
            let count = usize::try_from(read_cbor_uint(bytes, pos, info)?)
                .map_err(|_| SpaceRelayError::UpstreamError("CBOR array length overflow".into()))?;
            for _ in 0..count {
                verify_canonical_dagcbor_item(bytes, pos, depth + 1)?;
            }
            Ok(())
        }
        5 => {
            let count = usize::try_from(read_cbor_uint(bytes, pos, info)?)
                .map_err(|_| SpaceRelayError::UpstreamError("CBOR map length overflow".into()))?;
            let mut prev_key: Option<&[u8]> = None;
            for _ in 0..count {
                let key_head = *bytes.get(*pos).ok_or_else(|| {
                    SpaceRelayError::UpstreamError("truncated CBOR map key".into())
                })?;
                if (key_head >> 5) != 3 {
                    return Err(SpaceRelayError::UpstreamError(
                        "DAG-CBOR map key must be a UTF-8 string".into(),
                    ));
                }
                *pos += 1;
                let key_len = usize::try_from(read_cbor_uint(bytes, pos, key_head & 0x1f)?)
                    .map_err(|_| {
                        SpaceRelayError::UpstreamError("CBOR map key length overflow".into())
                    })?;
                let key_end = pos
                    .checked_add(key_len)
                    .filter(|&end| end <= bytes.len())
                    .ok_or_else(|| {
                        SpaceRelayError::UpstreamError("truncated CBOR map key".into())
                    })?;
                let key_slice = &bytes[*pos..key_end];
                std::str::from_utf8(key_slice).map_err(|_| {
                    SpaceRelayError::UpstreamError("invalid UTF-8 in CBOR map key".into())
                })?;
                if let Some(prev) = prev_key {
                    if (prev.len(), prev) >= (key_slice.len(), key_slice) {
                        return Err(SpaceRelayError::UpstreamError(
                            "non-canonical or duplicate DAG-CBOR map key order".into(),
                        ));
                    }
                }
                prev_key = Some(key_slice);
                *pos = key_end;
                verify_canonical_dagcbor_item(bytes, pos, depth + 1)?;
            }
            Ok(())
        }
        6 => {
            let tag = read_cbor_uint(bytes, pos, info)?;
            if tag != 42 {
                return Err(SpaceRelayError::UpstreamError(
                    "unsupported CBOR tag in DAG-CBOR".into(),
                ));
            }
            let payload_head = *bytes
                .get(*pos)
                .ok_or_else(|| SpaceRelayError::UpstreamError("truncated CBOR CID tag".into()))?;
            if (payload_head >> 5) != 2 {
                return Err(SpaceRelayError::UpstreamError(
                    "DAG-CBOR tag 42 payload must be byte string".into(),
                ));
            }
            *pos += 1;
            let len = usize::try_from(read_cbor_uint(bytes, pos, payload_head & 0x1f)?).map_err(
                |_| SpaceRelayError::UpstreamError("CBOR CID tag length overflow".into()),
            )?;
            let end = pos
                .checked_add(len)
                .filter(|&end| end <= bytes.len())
                .ok_or_else(|| SpaceRelayError::UpstreamError("truncated CBOR CID bytes".into()))?;
            let cid_bytes = &bytes[*pos..end];
            if cid_bytes.first() != Some(&0x00) {
                return Err(SpaceRelayError::UpstreamError(
                    "DAG-CBOR tag 42 CID missing identity multibase prefix".into(),
                ));
            }
            let parsed = cid::Cid::try_from(&cid_bytes[1..])
                .map_err(|_| SpaceRelayError::UpstreamError("invalid CID inside tag 42".into()))?;
            if parsed.to_bytes().as_slice() != &cid_bytes[1..] {
                return Err(SpaceRelayError::UpstreamError(
                    "non-canonical CID bytes inside tag 42".into(),
                ));
            }
            *pos = end;
            Ok(())
        }
        7 => match info {
            20..=22 => Ok(()),
            _ => Err(SpaceRelayError::UpstreamError(
                "floats and undefined are forbidden in ATProto DAG-CBOR".into(),
            )),
        },
        _ => Err(SpaceRelayError::UpstreamError("invalid CBOR major".into())),
    }
}

fn verify_canonical_dagcbor(bytes: &[u8]) -> Result<(), SpaceRelayError> {
    let mut pos = 0usize;
    verify_canonical_dagcbor_item(bytes, &mut pos, 0)?;
    if pos != bytes.len() {
        return Err(SpaceRelayError::UpstreamError(
            "trailing bytes after DAG-CBOR block".into(),
        ));
    }
    Ok(())
}

fn parse_verified_car_v1(
    car_bytes: &[u8],
    max_bytes: usize,
) -> Result<(cid::Cid, HashMap<cid::Cid, Vec<u8>>), SpaceRelayError> {
    if car_bytes.is_empty() || car_bytes.len() > max_bytes {
        return Err(SpaceRelayError::UpstreamError(
            "CARv1 response empty or exceeds size ceiling".into(),
        ));
    }
    let mut pos = 0usize;
    let header_len = usize::try_from(read_uvarint(car_bytes, &mut pos)?)
        .map_err(|_| SpaceRelayError::UpstreamError("CAR header length overflow".into()))?;
    if !(1..=CAR_HEADER_MAX_BYTES).contains(&header_len) {
        return Err(SpaceRelayError::UpstreamError(
            "CAR header length outside [1, 65536]".into(),
        ));
    }
    let header_end = pos
        .checked_add(header_len)
        .filter(|&end| end <= car_bytes.len())
        .ok_or_else(|| SpaceRelayError::UpstreamError("truncated CAR header".into()))?;
    let header_bytes = &car_bytes[pos..header_end];
    pos = header_end;
    verify_canonical_dagcbor(header_bytes)?;
    let header: CarHeader = serde_ipld_dagcbor::from_slice(header_bytes)
        .map_err(|_| SpaceRelayError::UpstreamError("malformed CARv1 header".into()))?;
    if header.version != 1 || header.roots.len() != 1 {
        return Err(SpaceRelayError::UpstreamError(
            "CARv1 header must have version 1 and exactly 1 root CID".into(),
        ));
    }
    let root_cid = header.roots[0];

    let mut blocks = HashMap::new();
    while pos < car_bytes.len() {
        if blocks.len() >= CAR_MAX_BLOCKS {
            return Err(SpaceRelayError::UpstreamError(
                "CARv1 block count exceeds 512".into(),
            ));
        }
        let section_len = usize::try_from(read_uvarint(car_bytes, &mut pos)?)
            .map_err(|_| SpaceRelayError::UpstreamError("CAR section length overflow".into()))?;
        if section_len == 0 {
            return Err(SpaceRelayError::UpstreamError(
                "empty CAR block section".into(),
            ));
        }
        let section_end = pos
            .checked_add(section_len)
            .filter(|&end| end <= car_bytes.len())
            .ok_or_else(|| SpaceRelayError::UpstreamError("truncated CAR block section".into()))?;
        let section = &car_bytes[pos..section_end];
        pos = section_end;

        let mut reader = Cursor::new(section);
        let block_cid = cid::Cid::read_bytes(&mut reader)
            .map_err(|_| SpaceRelayError::UpstreamError("malformed CID in CAR section".into()))?;
        let cid_len = usize::try_from(reader.position())
            .map_err(|_| SpaceRelayError::UpstreamError("CAR CID length overflow".into()))?;
        let _data_len = section_len
            .checked_sub(cid_len)
            .ok_or_else(|| SpaceRelayError::UpstreamError("CAR section shorter than CID".into()))?;
        if block_cid.to_bytes().as_slice() != &section[..cid_len] {
            return Err(SpaceRelayError::UpstreamError(
                "non-canonical CID encoding in CAR block".into(),
            ));
        }
        if block_cid.version() != cid::Version::V1 || block_cid.codec() != DAG_CBOR_CODEC {
            return Err(SpaceRelayError::UpstreamError(
                "CAR block must use CIDv1 dag-cbor (0x71)".into(),
            ));
        }
        let block_data = &section[cid_len..];
        verify_canonical_dagcbor(block_data)?;
        if compute_dagcbor_cid(block_data) != block_cid {
            return Err(SpaceRelayError::UpstreamError(
                "CAR block CID digest mismatch".into(),
            ));
        }
        if blocks.insert(block_cid, block_data.to_vec()).is_some() {
            return Err(SpaceRelayError::UpstreamError(
                "duplicate CID block in CAR proof".into(),
            ));
        }
    }

    if !blocks.contains_key(&root_cid) {
        return Err(SpaceRelayError::UpstreamError(
            "CARv1 proof missing root commit block".into(),
        ));
    }
    Ok((root_cid, blocks))
}

fn verify_atproto_v3_commit(
    commit_bytes: &[u8],
    expected_did: &str,
    atproto_key: &SpaceVerifyingKey,
) -> Result<cid::Cid, SpaceRelayError> {
    let (root, authenticated) = atproto_commit_signature(commit_bytes, expected_did, atproto_key)?;
    require_current_signature(authenticated)?;
    Ok(root)
}

fn require_current_signature(authenticated: bool) -> Result<(), SpaceRelayError> {
    if authenticated {
        Ok(())
    } else {
        Err(SpaceRelayError::UpstreamError(
            "ATProto commit signature failed verification under target #atproto key".into(),
        ))
    }
}

fn atproto_commit_signature(
    commit_bytes: &[u8],
    expected_did: &str,
    atproto_key: &SpaceVerifyingKey,
) -> Result<(cid::Cid, bool), SpaceRelayError> {
    let commit: SignedAtprotoCommitV3 = serde_ipld_dagcbor::from_slice(commit_bytes)
        .map_err(|_| SpaceRelayError::UpstreamError("malformed ATProto v3 commit".into()))?;
    if commit.version != 3 {
        return Err(SpaceRelayError::UpstreamError(
            "ATProto commit version must be 3".into(),
        ));
    }
    if commit.did != expected_did {
        return Err(SpaceRelayError::UpstreamError(
            "ATProto commit DID does not match target DID".into(),
        ));
    }
    if crate::space_host::decode_tid_micros(&commit.rev).is_none() {
        return Err(SpaceRelayError::UpstreamError(
            "ATProto commit rev is not a valid TID".into(),
        ));
    }
    if commit.sig.len() != 64 {
        return Err(SpaceRelayError::UpstreamError(
            "ATProto commit signature must be 64 bytes".into(),
        ));
    }
    let unsigned = UnsignedAtprotoCommitV3 {
        did: commit.did,
        rev: commit.rev,
        data: commit.data,
        prev: commit.prev,
        version: commit.version,
    };
    let unsigned_bytes = serde_ipld_dagcbor::to_vec(&unsigned).map_err(|_| {
        SpaceRelayError::UpstreamError("failed to encode unsigned ATProto commit".into())
    })?;
    Ok((
        commit.data,
        atproto_key.verify_raw(atproto_key.expected_alg(), &unsigned_bytes, &commit.sig),
    ))
}

fn walk_mst_proof(
    blocks: &HashMap<cid::Cid, Vec<u8>>,
    node_cid: cid::Cid,
    target_key: &[u8],
    lower_bound: Option<&[u8]>,
    upper_bound: Option<&[u8]>,
    visited: &mut HashSet<cid::Cid>,
    depth: usize,
) -> Result<Option<cid::Cid>, SpaceRelayError> {
    if depth > MST_MAX_DEPTH {
        return Err(SpaceRelayError::UpstreamError(
            "MST proof exceeded maximum depth".into(),
        ));
    }
    if !visited.insert(node_cid) {
        return Err(SpaceRelayError::UpstreamError(
            "cycle detected in MST proof".into(),
        ));
    }
    let node_bytes = blocks.get(&node_cid).ok_or_else(|| {
        SpaceRelayError::UpstreamError("missing MST node block in CAR proof".into())
    })?;
    let node: MstNodeData = serde_ipld_dagcbor::from_slice(node_bytes)
        .map_err(|_| SpaceRelayError::UpstreamError("malformed MST node block".into()))?;
    if depth > 0 && node.e.is_empty() {
        return Err(SpaceRelayError::UpstreamError(
            "non-root MST node cannot be empty".into(),
        ));
    }

    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(node.e.len());
    for (idx, entry) in node.e.iter().enumerate() {
        if entry.k.is_empty() {
            return Err(SpaceRelayError::UpstreamError(
                "MST entry key suffix cannot be empty".into(),
            ));
        }
        let full_key = if idx == 0 {
            if entry.p != 0 {
                return Err(SpaceRelayError::UpstreamError(
                    "first MST entry must have zero prefix length".into(),
                ));
            }
            entry.k.clone()
        } else {
            let prev = &keys[idx - 1];
            if entry.p > prev.len() {
                return Err(SpaceRelayError::UpstreamError(
                    "MST entry prefix length exceeds previous key".into(),
                ));
            }
            if entry.p < prev.len() && prev[entry.p] == entry.k[0] {
                return Err(SpaceRelayError::UpstreamError(
                    "non-canonical MST entry prefix length".into(),
                ));
            }
            let mut full = Vec::with_capacity(entry.p + entry.k.len());
            full.extend_from_slice(&prev[..entry.p]);
            full.extend_from_slice(&entry.k);
            if prev.as_slice() >= full.as_slice() {
                return Err(SpaceRelayError::UpstreamError(
                    "MST entries are not in strict lexicographic order".into(),
                ));
            }
            full
        };
        if std::str::from_utf8(&full_key).is_err() {
            return Err(SpaceRelayError::UpstreamError(
                "MST entry key is not valid UTF-8".into(),
            ));
        }
        if let Some(lo) = lower_bound {
            if full_key.as_slice() <= lo {
                return Err(SpaceRelayError::UpstreamError(
                    "MST entry key violates parent lower bound".into(),
                ));
            }
        }
        if let Some(hi) = upper_bound {
            if full_key.as_slice() >= hi {
                return Err(SpaceRelayError::UpstreamError(
                    "MST entry key violates parent upper bound".into(),
                ));
            }
        }
        keys.push(full_key);
    }

    if keys.is_empty() {
        return match node.l {
            Some(left_cid) => walk_mst_proof(
                blocks,
                left_cid,
                target_key,
                lower_bound,
                upper_bound,
                visited,
                depth + 1,
            ),
            None => Ok(None),
        };
    }

    match keys.binary_search_by(|candidate| candidate.as_slice().cmp(target_key)) {
        Ok(idx) => Ok(Some(node.e[idx].v)),
        Err(0) => match node.l {
            Some(left_cid) => walk_mst_proof(
                blocks,
                left_cid,
                target_key,
                lower_bound,
                Some(keys[0].as_slice()),
                visited,
                depth + 1,
            ),
            None => Ok(None),
        },
        Err(insert_pos) => {
            let idx = insert_pos - 1;
            let next_upper = keys.get(insert_pos).map(Vec::as_slice).or(upper_bound);
            match node.e[idx].t {
                Some(sub_cid) => walk_mst_proof(
                    blocks,
                    sub_cid,
                    target_key,
                    Some(keys[idx].as_slice()),
                    next_upper,
                    visited,
                    depth + 1,
                ),
                None => Ok(None),
            }
        }
    }
}

fn validate_mailbox_keys_cbor_value(
    record_bytes: &[u8],
    record_cid: cid::Cid,
    target_did: &str,
    rkey: &str,
) -> Result<bytes::Bytes, SpaceRelayError> {
    let typed: MailboxKeys<String> =
        serde_ipld_dagcbor::from_slice(record_bytes).map_err(|_| {
            SpaceRelayError::UpstreamError("malformed mailboxKeys DAG-CBOR record".into())
        })?;
    if matches!(typed.backend, Some(MailboxKeysBackend::Other(_))) {
        return Err(SpaceRelayError::UpstreamError(
            "unknown mailboxKeys backend variant".into(),
        ));
    }
    if typed.extra_data.as_ref().is_some_and(|m| !m.is_empty())
        || typed
            .current
            .extra_data
            .as_ref()
            .is_some_and(|m| !m.is_empty())
        || typed
            .current
            .attestation
            .extra_data
            .as_ref()
            .is_some_and(|m| !m.is_empty())
    {
        return Err(SpaceRelayError::UpstreamError(
            "unexpected unknown fields in mailboxKeys record".into(),
        ));
    }

    let current = &typed.current;
    let exact_lengths = [
        (current.auth_pubkey.len(), 32usize),
        (current.encryption_pubkey.len(), 1216),
        (current.signing_pubkey.len(), 32),
        (current.members_hash.len(), 32),
        (current.epoch_head.len(), 32),
        (current.self_sig.len(), 64),
        (current.attestation.transport_pubkey.len(), 32),
        (current.attestation.sig.len(), 64),
    ];
    if !(0..=MAX_MAILBOX_EPOCH_NUMBER).contains(&current.epoch_number)
        || exact_lengths
            .iter()
            .any(|(actual, expected)| actual != expected)
        || current
            .previous_epoch_head
            .as_ref()
            .is_some_and(|value| value.len() != 32)
        || current
            .prev_sig
            .as_ref()
            .is_some_and(|value| value.len() != 64)
    {
        return Err(SpaceRelayError::UpstreamError(
            "mailboxKeys value violates the epoch schema".into(),
        ));
    }
    if rkey != "self" && rkey.len() == 12 && rkey.bytes().all(|b| b.is_ascii_digit()) {
        let expected_epoch = rkey
            .parse::<i64>()
            .map_err(|_| SpaceRelayError::UpstreamError("invalid numeric rkey".into()))?;
        if current.epoch_number != expected_epoch {
            return Err(SpaceRelayError::UpstreamError(
                "mailboxKeys epochNumber does not match 12-digit rkey".into(),
            ));
        }
    }

    let expected_uri = format!("at://{target_did}/blue.catbird.labyrinth.mailboxKeys/{rkey}");
    let envelope = json!({
        "uri": expected_uri,
        "cid": record_cid.to_string(),
        "value": typed,
    });
    let out = serde_json::to_vec(&envelope).map_err(|_| {
        SpaceRelayError::UpstreamError("failed to encode verified mailboxKeys JSON".into())
    })?;
    Ok(bytes::Bytes::from(out))
}

fn verify_mailbox_keys_car_proof(
    car_bytes: &[u8],
    target_did: &str,
    rkey: &str,
    atproto_key: &SpaceVerifyingKey,
) -> Result<Option<bytes::Bytes>, SpaceRelayError> {
    let (root_cid, blocks) = parse_verified_car_v1(car_bytes, MAILBOX_KEYS_RECORD_MAX_BYTES)?;
    let commit_bytes = blocks
        .get(&root_cid)
        .ok_or_else(|| SpaceRelayError::UpstreamError("missing root commit block".into()))?;
    let mst_root_cid = verify_atproto_v3_commit(commit_bytes, target_did, atproto_key)?;
    let mst_key = format!("blue.catbird.labyrinth.mailboxKeys/{rkey}");
    let mut visited = HashSet::new();
    let Some(record_cid) = walk_mst_proof(
        &blocks,
        mst_root_cid,
        mst_key.as_bytes(),
        None,
        None,
        &mut visited,
        0,
    )?
    else {
        return Ok(None);
    };
    let record_bytes = blocks.get(&record_cid).ok_or_else(|| {
        SpaceRelayError::UpstreamError(
            "MST included mailboxKeys CID but CAR omitted record block".into(),
        )
    })?;
    let json_bytes = validate_mailbox_keys_cbor_value(record_bytes, record_cid, target_did, rkey)?;
    Ok(Some(json_bytes))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChatDeviceRecordProof {
    #[serde(rename = "$type")]
    record_type: String,
    #[serde(with = "serde_bytes")]
    mls_signature_public_key: Vec<u8>,
    algorithm: String,
    created_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChatDeviceRevocationRecordProof {
    #[serde(rename = "$type")]
    record_type: String,
    target_device_id: String,
    actor_device_id: String,
    #[serde(with = "serde_bytes")]
    signer_public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    created_at: String,
}

#[derive(Serialize)]
struct PdsDeviceRevocationTranscriptPayload<'a> {
    // Ordered strictly by DAG-CBOR map key `(byte_len, utf8_bytes)`:
    // "repoDid" (7), "createdAt" (9), "actorDeviceId" (13), "targetDeviceId" (14).
    #[serde(rename = "repoDid")]
    repo_did: &'a str,
    #[serde(rename = "createdAt")]
    created_at: &'a str,
    #[serde(rename = "actorDeviceId")]
    actor_device_id: &'a str,
    #[serde(rename = "targetDeviceId")]
    target_device_id: &'a str,
}

fn check_canonical_device_id(device_id: &str) -> Result<(), SpaceRelayError> {
    if !valid_record_key(device_id)
        || uuid::Uuid::parse_str(device_id)
            .map(|id| id.to_string() != device_id)
            .unwrap_or(true)
    {
        return Err(SpaceRelayError::InvalidRequest(
            "actorDeviceId is not a canonical UUID record key".into(),
        ));
    }
    Ok(())
}

fn verify_signed_device_rkey_car<T: for<'de> Deserialize<'de>>(
    car_bytes: &[u8],
    did: &str,
    collection: &str,
    device_id: &str,
    max_bytes: usize,
    atproto_key: &SpaceVerifyingKey,
    absent_label: &str,
) -> Result<T, SpaceRelayError> {
    let (record, authenticated) = device_record_and_signature(
        car_bytes,
        did,
        collection,
        device_id,
        max_bytes,
        atproto_key,
        absent_label,
    )?;
    require_current_signature(authenticated)?;
    serde_ipld_dagcbor::from_slice(&record)
        .map_err(|_| SpaceRelayError::UpstreamError(format!("malformed {absent_label}")))
}

fn device_record_and_signature(
    car_bytes: &[u8],
    did: &str,
    collection: &str,
    device_id: &str,
    max_bytes: usize,
    atproto_key: &SpaceVerifyingKey,
    absent_label: &str,
) -> Result<(Vec<u8>, bool), SpaceRelayError> {
    check_canonical_device_id(device_id)?;
    let (root_cid, mut blocks) = parse_verified_car_v1(car_bytes, max_bytes)?;
    let commit_bytes = blocks
        .get(&root_cid)
        .ok_or_else(|| SpaceRelayError::UpstreamError("missing root commit block".into()))?;
    let (mst_root_cid, authenticated) = atproto_commit_signature(commit_bytes, did, atproto_key)?;
    let mst_key = format!("{collection}/{device_id}");
    let mut visited = HashSet::new();
    let record_cid = walk_mst_proof(
        &blocks,
        mst_root_cid,
        mst_key.as_bytes(),
        None,
        None,
        &mut visited,
        0,
    )?
    .ok_or_else(|| SpaceRelayError::UpstreamError(format!("{absent_label} is absent from MST")))?;
    let record_bytes = blocks.remove(&record_cid).ok_or_else(|| {
        SpaceRelayError::UpstreamError(format!(
            "MST included {absent_label} CID but CAR omitted record"
        ))
    })?;
    Ok((record_bytes, authenticated))
}

/// When the original commit no longer verifies under the account's current key, require
/// the authoritative PDS to prove the identical record bytes at the same DID and MST key.
async fn reanchor_device_car<'a>(
    resolver: &DsResolver,
    supplied: &'a [u8],
    did: &str,
    collection: &str,
    device_id: &str,
    maximum: usize,
    current_key: &SpaceVerifyingKey,
) -> Result<std::borrow::Cow<'a, [u8]>, SpaceRelayError> {
    let (original, signed) = device_record_and_signature(
        supplied,
        did,
        collection,
        device_id,
        maximum,
        current_key,
        collection,
    )?;
    if signed {
        return Ok(std::borrow::Cow::Borrowed(supplied));
    }
    let (current, _) =
        fetch_chat_device_repo_car(resolver, did, collection, device_id, maximum).await?;
    let (record, signed) = device_record_and_signature(
        &current,
        did,
        collection,
        device_id,
        maximum,
        current_key,
        collection,
    )?;
    require_current_signature(signed)?;
    if original != record {
        return Err(SpaceRelayError::DeviceRevoked(
            "current repository record differs from deletion evidence".into(),
        ));
    }
    Ok(std::borrow::Cow::Owned(current))
}

/// Retain the original evidence for replication. The temporary current proofs only
/// authorize identical device records when the original repository key has rotated.
pub(super) async fn verify_peer_deletion_evidence(
    resolver: &DsResolver,
    did: &str,
    evidence: &crate::federation::receipt::AccountDeletionEvidence,
    key: &SpaceVerifyingKey,
) -> Result<chrono::DateTime<chrono::Utc>, SpaceRelayError> {
    evidence
        .check_shape()
        .map_err(SpaceRelayError::InvalidRequest)?;
    let write: crate::labyrinth::auth::WriteBodyWire =
        serde_json::from_slice(&evidence.actor_write.write_body)
            .map_err(|_| SpaceRelayError::InvalidRequest("malformed actorWrite".into()))?;
    let mut authenticated = evidence.clone();
    let key_car = evidence
        .key_proof
        .as_deref()
        .ok_or_else(|| SpaceRelayError::InvalidRequest("missing device key proof".into()))?;
    if let std::borrow::Cow::Owned(current) =
        reanchor_device_key_car(resolver, key_car, did, &write.actor_device_id, key).await?
    {
        authenticated.key_proof = Some(current);
    }
    let revoked = evidence
        .revocation_proof
        .as_deref()
        .ok_or_else(|| SpaceRelayError::InvalidRequest("missing revocation proof".into()))?;
    if let std::borrow::Cow::Owned(current) = reanchor_device_car(
        resolver,
        revoked,
        did,
        "blue.catbird.chat.deviceRevocation",
        &write.actor_device_id,
        CHAT_DEVICE_REVOCATION_PROOF_MAX_BYTES,
        key,
    )
    .await?
    {
        authenticated.revocation_proof = Some(current);
    }
    verify_account_deletion_evidence(did, &authenticated, key)
}

pub(super) async fn reanchor_device_key_car<'a>(
    resolver: &DsResolver,
    supplied: &'a [u8],
    did: &str,
    device_id: &str,
    key: &SpaceVerifyingKey,
) -> Result<std::borrow::Cow<'a, [u8]>, SpaceRelayError> {
    reanchor_device_car(
        resolver,
        supplied,
        did,
        "blue.catbird.chat.device",
        device_id,
        CHAT_DEVICE_KEY_PROOF_MAX_BYTES,
        key,
    )
    .await
}

/// Verify the exact signed repository commit, MST inclusion path, and device record
/// against the DID's independently resolved `#atproto` key. The returned CAR is
/// suitable for copying into `accountDeletedEntry.keyProof` unchanged.
pub fn verify_chat_device_key_proof(
    car_bytes: &[u8],
    did: &str,
    device_id: &str,
    signing_key: &[u8; 32],
    atproto_key: &SpaceVerifyingKey,
) -> Result<(), SpaceRelayError> {
    let (key, _) = chat_device_key_and_creation(car_bytes, did, device_id, atproto_key)?;
    if key != *signing_key {
        return Err(SpaceRelayError::UpstreamError(
            "chat device record does not bind the admitted signing key".into(),
        ));
    }
    Ok(())
}

/// Recover the signing key and enrollment instant from the account's signed record.
pub(crate) fn chat_device_key_and_creation(
    car_bytes: &[u8],
    did: &str,
    device_id: &str,
    atproto_key: &SpaceVerifyingKey,
) -> Result<([u8; 32], chrono::DateTime<chrono::Utc>), SpaceRelayError> {
    let record: ChatDeviceRecordProof = verify_signed_device_rkey_car(
        car_bytes,
        did,
        "blue.catbird.chat.device",
        device_id,
        CHAT_DEVICE_KEY_PROOF_MAX_BYTES,
        atproto_key,
        "chat device record",
    )?;
    if record.record_type != "blue.catbird.chat.device"
        || !record.algorithm.eq_ignore_ascii_case("ed25519")
    {
        return Err(SpaceRelayError::InvalidRequest(
            "unsupported device record".into(),
        ));
    }
    let key = record
        .mls_signature_public_key
        .try_into()
        .map_err(|_| SpaceRelayError::InvalidRequest("invalid device key length".into()))?;
    let created = chrono::DateTime::parse_from_rfc3339(&record.created_at)
        .map_err(|_| SpaceRelayError::InvalidRequest("invalid enrollment timestamp".into()))?;
    Ok((key, created.with_timezone(&chrono::Utc)))
}

/// Independently authorize a destructive federated action with the account's repository key.
/// Only fully proven, device-signed writes over the exact deletion payload establish a cutoff.
pub(crate) fn verify_account_deletion_evidence(
    did: &str,
    evidence: &crate::federation::receipt::AccountDeletionEvidence,
    atproto_key: &SpaceVerifyingKey,
) -> Result<chrono::DateTime<chrono::Utc>, SpaceRelayError> {
    evidence
        .check_shape()
        .map_err(SpaceRelayError::InvalidRequest)?;
    if evidence.actor_write.payload_bytes.is_none() {
        return Err(SpaceRelayError::InvalidRequest(
            "missing signed deletion payload".into(),
        ));
    }
    let write: crate::labyrinth::auth::WriteBodyWire =
        serde_json::from_slice(&evidence.actor_write.write_body)
            .map_err(|_| SpaceRelayError::InvalidRequest("malformed actorWrite".into()))?;
    let key_car = evidence
        .key_proof
        .as_deref()
        .ok_or_else(|| SpaceRelayError::InvalidRequest("missing device key proof".into()))?;
    let revocation_car = evidence
        .revocation_proof
        .as_deref()
        .ok_or_else(|| SpaceRelayError::InvalidRequest("missing device revocation proof".into()))?;
    let signed_at = evidence
        .signed_at()
        .map_err(SpaceRelayError::InvalidRequest)?;
    let operation_id = evidence
        .operation_id()
        .map_err(SpaceRelayError::InvalidRequest)?;
    let (device_key, enrolled_at) =
        chat_device_key_and_creation(key_car, did, &write.actor_device_id, atproto_key)?;
    if enrolled_at > signed_at {
        return Err(SpaceRelayError::InvalidRequest(
            "deletion predates device enrollment".into(),
        ));
    }
    let key = ed25519_dalek::VerifyingKey::from_bytes(&device_key)
        .map_err(|_| SpaceRelayError::InvalidRequest("invalid device key".into()))?;
    let signature = ed25519_dalek::Signature::from_slice(&evidence.actor_write.signature)
        .map_err(|_| SpaceRelayError::InvalidRequest("invalid deletion signature length".into()))?;
    let bytes = [
        crate::labyrinth::auth::WRITE_DOMAIN,
        evidence.actor_write.write_body.as_slice(),
    ]
    .concat();
    key.verify_strict(&bytes, &signature)
        .map_err(|_| SpaceRelayError::InvalidRequest("invalid device deletion signature".into()))?;
    let revoked_at = verified_device_revocation_instant(
        revocation_car,
        did,
        &write.actor_device_id,
        &device_key,
        &operation_id,
        signed_at,
        atproto_key,
    )?;
    if revoked_at < enrolled_at {
        return Err(SpaceRelayError::DeviceRevoked(
            "device revocation predates enrollment".into(),
        ));
    }
    Ok(signed_at)
}

/// Verify the exact signed repository commit, MST inclusion path, and self-deletion
/// `blue.catbird.chat.deviceRevocation/{device_id}` record against the DID's
/// independently resolved `#atproto` key.
///
/// Rejects sibling-authored, prior, mismatched-operation, or invalidly signed revocation
/// records with [`SpaceRelayError::DeviceRevoked`]. Missing MST inclusion returns
/// [`SpaceRelayError::UpstreamError`] so the deletion handler fails closed retryably
/// (`503 ServiceUnavailable`) before any purge occurs.
pub fn verify_chat_device_revocation_proof(
    car_bytes: &[u8],
    did: &str,
    device_id: &str,
    signing_key: &[u8; 32],
    expected_operation_id: &[u8; 16],
    expected_signed_at: chrono::DateTime<chrono::Utc>,
    atproto_key: &SpaceVerifyingKey,
) -> Result<(), SpaceRelayError> {
    verified_device_revocation_instant(
        car_bytes,
        did,
        device_id,
        signing_key,
        expected_operation_id,
        expected_signed_at,
        atproto_key,
    )
    .map(|_| ())
}

fn verified_device_revocation_instant(
    car_bytes: &[u8],
    did: &str,
    device_id: &str,
    signing_key: &[u8; 32],
    expected_operation_id: &[u8; 16],
    expected_signed_at: chrono::DateTime<chrono::Utc>,
    atproto_key: &SpaceVerifyingKey,
) -> Result<chrono::DateTime<chrono::Utc>, SpaceRelayError> {
    let record: ChatDeviceRevocationRecordProof = verify_signed_device_rkey_car(
        car_bytes,
        did,
        "blue.catbird.chat.deviceRevocation",
        device_id,
        CHAT_DEVICE_REVOCATION_PROOF_MAX_BYTES,
        atproto_key,
        "deviceRevocation record",
    )?;
    if record.record_type != "blue.catbird.chat.deviceRevocation" {
        return Err(SpaceRelayError::UpstreamError(
            "deviceRevocation record has unexpected $type".into(),
        ));
    }
    let expected_reason = format!("deleteAccountData:{}", hex::encode(expected_operation_id));
    if record.target_device_id != device_id
        || record.actor_device_id != device_id
        || record.signer_public_key.as_slice() != signing_key.as_slice()
        || record.reason.as_deref() != Some(expected_reason.as_str())
    {
        return Err(SpaceRelayError::DeviceRevoked(
            "deviceRevocation binds another actor or operation".into(),
        ));
    }
    if let Some(alg) = &record.algorithm {
        if !alg.eq_ignore_ascii_case("ed25519") {
            return Err(SpaceRelayError::DeviceRevoked(
                "unsupported deviceRevocation algorithm".into(),
            ));
        }
    }
    let created_at = chrono::DateTime::parse_from_rfc3339(&record.created_at)
        .map_err(|_| SpaceRelayError::DeviceRevoked("invalid deviceRevocation createdAt".into()))?;
    if created_at.with_timezone(&chrono::Utc) > expected_signed_at {
        return Err(SpaceRelayError::DeviceRevoked(
            "deviceRevocation createdAt postdates deletion signedAt".into(),
        ));
    }
    let sig_64: [u8; 64] =
        record.signature.as_slice().try_into().map_err(|_| {
            SpaceRelayError::DeviceRevoked("deviceRevocation signature length".into())
        })?;
    let payload = PdsDeviceRevocationTranscriptPayload {
        repo_did: did,
        created_at: &record.created_at,
        actor_device_id: device_id,
        target_device_id: device_id,
    };
    let cbor = serde_ipld_dagcbor::to_vec(&payload).map_err(|error| {
        SpaceRelayError::UpstreamError(format!("encode deviceRevocation DAG-CBOR: {error}"))
    })?;
    let mut transcript = Vec::with_capacity(PDS_DEVICE_REVOCATION_DOMAIN.len() + cbor.len());
    transcript.extend_from_slice(PDS_DEVICE_REVOCATION_DOMAIN);
    transcript.extend_from_slice(&cbor);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(signing_key)
        .map_err(|_| SpaceRelayError::DeviceRevoked("invalid device verifying key".into()))?;
    vk.verify_strict(&transcript, &ed25519_dalek::Signature::from_bytes(&sig_64))
        .map_err(|_| {
            SpaceRelayError::DeviceRevoked("deviceRevocation signature does not verify".into())
        })?;
    Ok(created_at.with_timezone(&chrono::Utc))
}

/// Validate a caller-supplied pre-deletion CAR using a fresh DID document.
/// A PDS service is not required because the repository may already be gone.
pub async fn verify_supplied_chat_device_key_proof(
    resolver: &DsResolver,
    did: &str,
    device_id: &str,
    signing_key: &[u8; 32],
    car_bytes: &[u8],
) -> Result<(), SpaceRelayError> {
    let atproto_key = resolver
        .resolve_did_to_atproto_key(did)
        .await
        .map_err(mailbox_resolution_error)?
        .ok_or_else(|| {
            SpaceRelayError::UpstreamError("deleted DID has no #atproto signing key".into())
        })?;
    verify_chat_device_key_proof(car_bytes, did, device_id, signing_key, &atproto_key)
}

/// Validate a caller-supplied `revocationProof` CAR using a fresh DID document.
pub async fn verify_supplied_chat_device_revocation_proof(
    resolver: &DsResolver,
    did: &str,
    device_id: &str,
    signing_key: &[u8; 32],
    expected_operation_id: &[u8; 16],
    expected_signed_at: chrono::DateTime<chrono::Utc>,
    car_bytes: &[u8],
) -> Result<(), SpaceRelayError> {
    let atproto_key = resolver
        .resolve_did_to_atproto_key(did)
        .await
        .map_err(mailbox_resolution_error)?
        .ok_or_else(|| {
            SpaceRelayError::UpstreamError("deleted DID has no #atproto signing key".into())
        })?;
    verify_chat_device_revocation_proof(
        car_bytes,
        did,
        device_id,
        signing_key,
        expected_operation_id,
        expected_signed_at,
        &atproto_key,
    )
}

async fn fetch_chat_device_repo_car(
    resolver: &DsResolver,
    did: &str,
    collection: &str,
    device_id: &str,
    max_bytes: usize,
) -> Result<(Vec<u8>, SpaceVerifyingKey), SpaceRelayError> {
    if crate::identity::canonical_did(did) != did
        || !atproto_spaces::is_valid_did(did)
        || !(did.starts_with("did:plc:") || did.starts_with("did:web:"))
    {
        return Err(SpaceRelayError::InvalidRequest(
            "deleted DID must be one canonical bare did:plc or did:web".into(),
        ));
    }
    check_canonical_device_id(device_id)?;
    let (pds, atproto_key_opt) = resolver
        .resolve_did_to_pds_and_atproto_key(did)
        .await
        .map_err(mailbox_resolution_error)?;
    let atproto_key = atproto_key_opt.ok_or_else(|| {
        SpaceRelayError::UpstreamError("deleted DID has no #atproto signing key".into())
    })?;
    let mut url = Url::parse(&format!(
        "{}/xrpc/com.atproto.sync.getRecord",
        pds.trim_end_matches('/')
    ))
    .map_err(|error| SpaceRelayError::InvalidTargetEndpoint(error.to_string()))?;
    url.query_pairs_mut()
        .append_pair("did", did)
        .append_pair("collection", collection)
        .append_pair("rkey", device_id);
    let destination = resolver
        .resolve_endpoint_destination(url.as_str())
        .await
        .map_err(mailbox_resolution_error)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let response = send_hardened_resolution_request(
        &destination,
        deadline,
        did,
        "chat device CAR proof read failed",
    )
    .await
    .map_err(mailbox_resolution_error)?;
    let status = response.status();
    let response_cap = if status.is_success() {
        max_bytes
    } else {
        ERROR_RESPONSE_MAX_BYTES
    };
    let body = collect_bounded(response, ResponseBodyBudget::new(response_cap, deadline))
        .await
        .map_err(|error| {
            if retryable_status(status) || body_read_was_transient(&error) {
                SpaceRelayError::UpstreamUnavailable(error.to_string())
            } else {
                SpaceRelayError::UpstreamError(error.to_string())
            }
        })?;
    if !status.is_success() {
        let reason = format!(
            "chat device sync.getRecord ({collection}) returned HTTP {}",
            status.as_u16()
        );
        return Err(if retryable_status(status) {
            SpaceRelayError::UpstreamUnavailable(reason)
        } else {
            SpaceRelayError::UpstreamError(reason)
        });
    }
    Ok((body.to_vec(), atproto_key))
}

/// Fetch a missing proof before deleting the account's server data. The PDS URL
/// comes only from the DID document, is DNS-pinned, and receives no caller headers.
/// An unsigned HTTP 404 cannot prove the record absent and is never accepted.
pub async fn fetch_chat_device_key_proof(
    resolver: &DsResolver,
    did: &str,
    device_id: &str,
    signing_key: &[u8; 32],
) -> Result<Vec<u8>, SpaceRelayError> {
    let (body, atproto_key) = fetch_chat_device_repo_car(
        resolver,
        did,
        "blue.catbird.chat.device",
        device_id,
        CHAT_DEVICE_KEY_PROOF_MAX_BYTES,
    )
    .await?;
    verify_chat_device_key_proof(&body, did, device_id, signing_key, &atproto_key)?;
    Ok(body)
}

/// Fetch and verify a missing self-deletion `blue.catbird.chat.deviceRevocation`
/// CARv1 proof from the deleting account's resolved PDS before purging data.
pub async fn fetch_chat_device_revocation_proof(
    resolver: &DsResolver,
    did: &str,
    device_id: &str,
    signing_key: &[u8; 32],
    expected_operation_id: &[u8; 16],
    expected_signed_at: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<u8>, SpaceRelayError> {
    let (body, atproto_key) = fetch_chat_device_repo_car(
        resolver,
        did,
        "blue.catbird.chat.deviceRevocation",
        device_id,
        CHAT_DEVICE_REVOCATION_PROOF_MAX_BYTES,
    )
    .await?;
    verify_chat_device_revocation_proof(
        &body,
        did,
        device_id,
        signing_key,
        expected_operation_id,
        expected_signed_at,
        &atproto_key,
    )?;
    Ok(body)
}

fn mailbox_resolution_error(error: FederationError) -> SpaceRelayError {
    if error.is_retryable() {
        SpaceRelayError::UpstreamUnavailable(error.to_string())
    } else {
        SpaceRelayError::InvalidTargetEndpoint(error.to_string())
    }
}

/// Read and cryptographically verify one public `mailboxKeys` record through the authenticated
/// caller's home service via `com.atproto.sync.getRecord` (`application/vnd.ipld.car`).
///
/// Only `target_did` and `rkey` influence the outbound request: the PDS endpoint and `#atproto`
/// signing key are live-resolved and DNS-pinned, the collection is fixed to
/// `blue.catbird.labyrinth.mailboxKeys`, and no caller URL, authorization, headers, or token are
/// forwarded. Unsigned HTTP `404`/`400` responses are NEVER trusted as `RecordNotFound`.
pub async fn relay_mailbox_keys_record(
    resolver: &DsResolver,
    target_did: &str,
    rkey: &str,
) -> Result<Option<bytes::Bytes>, SpaceRelayError> {
    if crate::identity::canonical_did(target_did) != target_did
        || !atproto_spaces::is_valid_did(target_did)
        || !(target_did.starts_with("did:plc:") || target_did.starts_with("did:web:"))
    {
        return Err(SpaceRelayError::InvalidRequest(
            "target DID must be one canonical bare did:plc or did:web".into(),
        ));
    }
    if !valid_record_key(rkey) {
        return Err(SpaceRelayError::InvalidRequest(
            "invalid mailboxKeys record key".into(),
        ));
    }

    let (pds, atproto_key_opt) = resolver
        .resolve_did_to_pds_and_atproto_key(target_did)
        .await
        .map_err(mailbox_resolution_error)?;
    let atproto_key = atproto_key_opt.ok_or_else(|| {
        SpaceRelayError::UpstreamError("target DID document has no #atproto signing key".into())
    })?;

    let mut url = Url::parse(&format!(
        "{}/xrpc/com.atproto.sync.getRecord",
        pds.trim_end_matches('/')
    ))
    .map_err(|error| SpaceRelayError::InvalidTargetEndpoint(error.to_string()))?;
    url.query_pairs_mut()
        .append_pair("did", target_did)
        .append_pair("collection", "blue.catbird.labyrinth.mailboxKeys")
        .append_pair("rkey", rkey);
    let destination = resolver
        .resolve_endpoint_destination(url.as_str())
        .await
        .map_err(mailbox_resolution_error)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let response = send_hardened_resolution_request(
        &destination,
        deadline,
        target_did,
        "mailboxKeys CAR proof read failed",
    )
    .await
    .map_err(mailbox_resolution_error)?;
    let status = response.status();
    let max_bytes = if status.is_success() {
        MAILBOX_KEYS_RECORD_MAX_BYTES
    } else {
        ERROR_RESPONSE_MAX_BYTES
    };
    let body = collect_bounded(response, ResponseBodyBudget::new(max_bytes, deadline))
        .await
        .map_err(|error| {
            if retryable_status(status) || body_read_was_transient(&error) {
                SpaceRelayError::UpstreamUnavailable(error.to_string())
            } else {
                SpaceRelayError::UpstreamError(error.to_string())
            }
        })?;
    if !status.is_success() {
        let reason = format!(
            "mailboxKeys sync.getRecord returned HTTP {}",
            status.as_u16()
        );
        return Err(if retryable_status(status) {
            SpaceRelayError::UpstreamUnavailable(reason)
        } else {
            SpaceRelayError::UpstreamError(reason)
        });
    }
    verify_mailbox_keys_car_proof(&body, target_did, rkey, &atproto_key)
}

pub struct RelayedSpaceReadResponse {
    pub status: u16,
    pub content_type: String,
    pub space_mac: Option<String>,
    pub space_commit: Option<String>,
    pub space_record: Option<String>,
    pub signature_input: Option<String>,
    pub signature: Option<String>,
    pub vary: Option<String>,
    pub body: bytes::Bytes,
}

/// Statelessly relay an RFC 9421 PoP-signed `com.atproto.space.*` read request to `target_did`.
#[allow(clippy::too_many_arguments)]
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
    relay_space_read_with_headers(
        target_did,
        nsid,
        query,
        credential,
        space_audience,
        want_mac,
        None,
        signature_input,
        signature,
    )
    .await
}

/// Statelessly relay an RFC 9421 PoP-signed `com.atproto.space.*` read request, including optional
/// `Accept-Signature` negotiation and preserving signed response proof headers.
#[allow(clippy::too_many_arguments)]
pub async fn relay_space_read_with_headers(
    target_did: &str,
    nsid: &str,
    query: Option<&str>,
    credential: &str,
    space_audience: &str,
    want_mac: Option<&str>,
    accept_signature: Option<&str>,
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
    if let Some(accept_sig) = accept_signature.filter(|s| !s.is_empty()) {
        req = req.header("accept-signature", accept_sig.trim());
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let resp = crate::sim_hooks::send_reqwest(req)
        .await
        .map_err(SpaceRelayError::UpstreamUnavailable)?;
    let status = resp.status();
    let header_str = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let space_mac = header_str("atproto-space-mac");
    let space_commit = header_str("atproto-space-commit");
    let space_record = header_str("atproto-space-record");
    let resp_signature_input = header_str("signature-input");
    let resp_signature = header_str("signature");
    let vary = header_str("vary");
    let max_bytes = space_read_response_max_bytes(nsid, status);
    let body = collect_bounded(resp, ResponseBodyBudget::new(max_bytes, deadline))
        .await
        .map_err(|error| {
            if retryable_status(status) || body_read_was_transient(&error) {
                SpaceRelayError::UpstreamUnavailable(error.to_string())
            } else {
                SpaceRelayError::UpstreamError(error.to_string())
            }
        })?;
    let status = status.as_u16();

    // A 5xx/429 decided nothing; any other status is the target's answer.
    if status >= 500 || status == 429 {
        return Err(SpaceRelayError::UpstreamUnavailable(format!(
            "upstream {nsid} returned HTTP {status}"
        )));
    }

    Ok(RelayedSpaceReadResponse {
        status,
        content_type,
        space_mac,
        space_commit,
        space_record,
        signature_input: resp_signature_input,
        signature: resp_signature,
        vary,
        body,
    })
}

/// Test-support builder for canonical DAG-CBOR + CARv1 + signed ATProto v3 commit + MST proofs.
#[cfg(any(test, feature = "test-support"))]
pub mod test_car_builder {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    /// Build a complete device-authorized operation for the federated retention fixtures.
    pub fn deletion_evidence(
        did: &str,
        device: uuid::Uuid,
        operation: [u8; 16],
        at: chrono::DateTime<chrono::Utc>,
    ) -> crate::federation::receipt::AccountDeletionEvidence {
        deletion_evidence_with_repository(
            did,
            device,
            operation,
            at,
            &p256::SecretKey::from_slice(&[0x5b; 32]).unwrap(),
        )
    }

    pub fn deletion_evidence_with_repository(
        did: &str,
        device: uuid::Uuid,
        operation: [u8; 16],
        at: chrono::DateTime<chrono::Utc>,
        repository: &p256::SecretKey,
    ) -> crate::federation::receipt::AccountDeletionEvidence {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[0x5d; 32]);
        let id = device.to_string();
        let created = at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let pk = STANDARD.encode(signer.verifying_key().to_bytes());
        let payload = PdsDeviceRevocationTranscriptPayload {
            repo_did: did,
            created_at: &created,
            actor_device_id: &id,
            target_device_id: &id,
        };
        let cbor = serde_ipld_dagcbor::to_vec(&payload).unwrap();
        let signature = signer.sign(&[PDS_DEVICE_REVOCATION_DOMAIN, cbor.as_slice()].concat());
        let device_record = json!({"$type":"blue.catbird.chat.device", "mlsSignaturePublicKey":{"$bytes":pk}, "createdAt":created, "algorithm":"ed25519"});
        let revoked = json!({"$type":"blue.catbird.chat.deviceRevocation", "actorDeviceId":id, "targetDeviceId":id,
            "signerPublicKey":{"$bytes":pk}, "signature":{"$bytes":STANDARD.encode(signature.to_bytes())}, "createdAt":created,
            "reason":format!("deleteAccountData:{}",hex::encode(operation)), "algorithm":"ed25519"});
        let car = |collection: &str, value: &Value| {
            build_signed_repo_car(
                did,
                "3l2aaaaaaaaaa",
                repository,
                &[(&format!("{collection}/{id}"), value)],
            )
            .0
        };
        crate::federation::receipt::AccountDeletionEvidence::signed_for_test(
            &signer,
            device,
            operation,
            at,
            0,
            Some(car("blue.catbird.chat.device", &device_record)),
        )
        .with_revocation_proof(Some(car("blue.catbird.chat.deviceRevocation", &revoked)))
    }

    pub fn local_deletion_evidence(
        did: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> crate::federation::receipt::AccountDeletionEvidence {
        let mut operation = [0; 16];
        operation[..8].copy_from_slice(&at.timestamp_millis().to_be_bytes());
        deletion_evidence(
            did,
            uuid::uuid!("00000000-0000-4000-8000-000000000001"),
            operation,
            at,
        )
    }

    pub fn deletion_repository_method(did: &str) -> crate::auth::VerificationMethod {
        let repo_key = SigningKey::from_slice(&[0x5b; 32]).unwrap();
        crate::auth::VerificationMethod {
            id: format!("{did}#atproto"),
            key_type: "Multikey".into(),
            controller: did.to_string(),
            public_key_jwk: None,
            public_key_multibase: Some(crate::identity::did_doc::encode_p256_multikey(
                repo_key.verifying_key(),
            )),
        }
    }

    pub async fn cache_deletion_repository(did: &str) {
        let previous = crate::auth::get_cached_test_did_document_json(did)
            .await
            .and_then(|v| serde_json::from_value::<crate::auth::DidDocument>(v).ok());
        #[cfg(feature = "sim")]
        let previous = if previous.is_none() && crate::sim_hooks::active_sim_ds().is_some() {
            crate::auth::shared_auth_middleware()
                .resolve_did(did)
                .await
                .ok()
        } else {
            previous
        };
        crate::auth::cache_test_did_document(crate::auth::DidDocument {
            id: did.to_owned(),
            service: Some(previous.and_then(|doc| doc.service).unwrap_or_default()),
            verification_method: vec![deletion_repository_method(did)],
        })
        .await;
    }

    fn write_cbor_head(out: &mut Vec<u8>, major: u8, val: u64) {
        let prefix = major << 5;
        if val < 24 {
            out.push(prefix | (val as u8));
        } else if val <= u8::MAX as u64 {
            out.push(prefix | 24);
            out.push(val as u8);
        } else if val <= u16::MAX as u64 {
            out.push(prefix | 25);
            out.extend_from_slice(&(val as u16).to_be_bytes());
        } else if val <= u32::MAX as u64 {
            out.push(prefix | 26);
            out.extend_from_slice(&(val as u32).to_be_bytes());
        } else {
            out.push(prefix | 27);
            out.extend_from_slice(&val.to_be_bytes());
        }
    }

    pub fn encode_uvarint(mut val: u64, out: &mut Vec<u8>) {
        while val >= 0x80 {
            out.push(((val as u8) & 0x7f) | 0x80);
            val >>= 7;
        }
        out.push(val as u8);
    }

    pub fn encode_cid_link(cid: &cid::Cid, out: &mut Vec<u8>) {
        write_cbor_head(out, 6, 42);
        let raw = cid.to_bytes();
        write_cbor_head(out, 2, (raw.len() + 1) as u64);
        out.push(0x00);
        out.extend_from_slice(&raw);
    }

    /// Encode an ATProto JSON value (`{"$bytes": ...}`, `{"$link": ...}`, primitives, arrays,
    /// objects) as canonical IPLD DAG-CBOR with `(key.len(), key)` sorted map keys.
    pub fn json_to_canonical_dagcbor(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        encode_json_item(value, &mut out);
        out
    }

    fn encode_json_item(value: &Value, out: &mut Vec<u8>) {
        match value {
            Value::Null => out.push(0xf6),
            Value::Bool(false) => out.push(0xf4),
            Value::Bool(true) => out.push(0xf5),
            Value::Number(n) => {
                if let Some(u) = n.as_u64() {
                    write_cbor_head(out, 0, u);
                } else if let Some(i) = n.as_i64() {
                    assert!(i < 0);
                    let mag = (-1i128 - (i as i128)) as u64;
                    write_cbor_head(out, 1, mag);
                } else {
                    panic!("floats not allowed in ATProto DAG-CBOR");
                }
            }
            Value::String(s) => {
                write_cbor_head(out, 3, s.len() as u64);
                out.extend_from_slice(s.as_bytes());
            }
            Value::Array(arr) => {
                write_cbor_head(out, 4, arr.len() as u64);
                for item in arr {
                    encode_json_item(item, out);
                }
            }
            Value::Object(map) => {
                if map.len() == 1 {
                    if let Some(Value::String(b64)) = map.get("$bytes") {
                        let raw = STANDARD.decode(b64).expect("valid $bytes base64");
                        write_cbor_head(out, 2, raw.len() as u64);
                        out.extend_from_slice(&raw);
                        return;
                    }
                    if let Some(Value::String(cid_str)) = map.get("$link") {
                        let parsed: cid::Cid = cid_str.parse().expect("valid $link CID");
                        encode_cid_link(&parsed, out);
                        return;
                    }
                }
                let mut entries: Vec<(&str, &Value)> =
                    map.iter().map(|(k, v)| (k.as_str(), v)).collect();
                entries.sort_by(|(a, _), (b, _)| {
                    (a.len(), a.as_bytes()).cmp(&(b.len(), b.as_bytes()))
                });
                write_cbor_head(out, 5, entries.len() as u64);
                for (k, v) in entries {
                    write_cbor_head(out, 3, k.len() as u64);
                    out.extend_from_slice(k.as_bytes());
                    encode_json_item(v, out);
                }
            }
        }
    }

    /// Build a signed CARv1 proof over a flat MST leaf containing `records` (sorted automatically
    /// by `collection/rkey`), signed by `p256_secret` (`#atproto`).
    pub fn build_signed_repo_car(
        did: &str,
        rev: &str,
        p256_secret: &p256::SecretKey,
        records: &[(&str, &Value)],
    ) -> (Vec<u8>, BTreeMap<String, cid::Cid>) {
        let mut sorted: Vec<(&str, &Value)> = records.to_vec();
        sorted.sort_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));

        let mut blocks: Vec<(cid::Cid, Vec<u8>)> = Vec::new();
        let mut record_cids = BTreeMap::new();
        let mut entries_json = Vec::new();
        let mut prev_key: &[u8] = &[];

        for (full_key, val) in sorted {
            let rec_cbor = json_to_canonical_dagcbor(val);
            let rec_cid = compute_dagcbor_cid(&rec_cbor);
            blocks.push((rec_cid, rec_cbor));
            record_cids.insert(full_key.to_string(), rec_cid);

            let key_bytes = full_key.as_bytes();
            let prefix_len = prev_key
                .iter()
                .zip(key_bytes.iter())
                .take_while(|(a, b)| a == b)
                .count();
            let suffix = &key_bytes[prefix_len..];
            entries_json.push(json!({
                "p": prefix_len,
                "k": { "$bytes": STANDARD.encode(suffix) },
                "v": { "$link": rec_cid.to_string() },
                "t": Value::Null,
            }));
            prev_key = key_bytes;
        }

        let mst_cbor = json_to_canonical_dagcbor(&json!({
            "l": Value::Null,
            "e": entries_json,
        }));
        let mst_cid = compute_dagcbor_cid(&mst_cbor);
        blocks.push((mst_cid, mst_cbor));

        let unsigned_cbor = json_to_canonical_dagcbor(&json!({
            "did": did,
            "version": 3,
            "data": { "$link": mst_cid.to_string() },
            "rev": rev,
            "prev": Value::Null,
        }));
        let signing_key = SigningKey::from(p256_secret);
        let sig: Signature = signing_key.sign(&unsigned_cbor);
        let sig = sig.normalize_s().unwrap_or(sig);
        let commit_cbor = json_to_canonical_dagcbor(&json!({
            "did": did,
            "version": 3,
            "data": { "$link": mst_cid.to_string() },
            "rev": rev,
            "prev": Value::Null,
            "sig": { "$bytes": STANDARD.encode(sig.to_bytes()) },
        }));
        let commit_cid = compute_dagcbor_cid(&commit_cbor);
        blocks.insert(0, (commit_cid, commit_cbor));

        let header_cbor = json_to_canonical_dagcbor(&json!({
            "version": 1,
            "roots": [{ "$link": commit_cid.to_string() }],
        }));

        let mut car = Vec::new();
        encode_uvarint(header_cbor.len() as u64, &mut car);
        car.extend_from_slice(&header_cbor);
        for (cid, data) in blocks {
            let cid_bytes = cid.to_bytes();
            encode_uvarint((cid_bytes.len() + data.len()) as u64, &mut car);
            car.extend_from_slice(&cid_bytes);
            car.extend_from_slice(&data);
        }
        (car, record_cids)
    }
}

#[cfg(test)]
mod tests {
    use super::test_car_builder::{
        build_signed_repo_car, encode_uvarint, json_to_canonical_dagcbor,
    };
    use super::*;
    use crate::federation::resolver::ValidatedRemoteDestination;
    use atproto_spaces::{
        kem::encode_p256_did_key,
        tokens::{mint_space_token, SpaceSigningKey, SpaceTokenClaims},
    };
    use axum::{
        extract::{OriginalUri, Query},
        http::HeaderMap,
        response::IntoResponse,
        routing::{get, post},
        Json, Router,
    };
    use base64::{
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
        Engine as _,
    };
    use serde_json::json;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    };

    const NOW: u64 = 1_700_000_000;

    fn sample_mailbox_value(epoch_number: i64) -> Value {
        let bytes = |len| json!({ "$bytes": STANDARD.encode(vec![0x42u8; len]) });
        json!({
            "$type": "blue.catbird.labyrinth.mailboxKeys",
            "current": {
                "epochNumber": epoch_number,
                "authPubkey": bytes(32),
                "encryptionPubkey": bytes(1216),
                "signingPubkey": bytes(32),
                "membersHash": bytes(32),
                "epochHead": bytes(32),
                "selfSig": bytes(64),
                "attestation": {
                    "transportPubkey": bytes(32),
                    "sig": bytes(64),
                },
            },
            "updatedAt": "2026-11-04T00:00:00Z",
        })
    }

    #[test]
    fn only_a_failed_dns_lookup_of_the_target_is_retryable() {
        let dns = PushGatewaySsrfError::DnsResolutionFailed("space.example".into());
        assert!(matches!(
            target_endpoint_error(dns),
            SpaceRelayError::UpstreamUnavailable(_)
        ));
        for refusal in [
            PushGatewaySsrfError::ForbiddenIp("169.254.169.254".parse().unwrap()),
            PushGatewaySsrfError::NonHttpsOrBadPort,
            PushGatewaySsrfError::MissingHost,
            PushGatewaySsrfError::InvalidUrl("not a url".into()),
        ] {
            assert!(matches!(
                target_endpoint_error(refusal),
                SpaceRelayError::InvalidTargetEndpoint(_)
            ));
        }
    }

    #[test]
    fn read_body_budgets_are_explicit_per_response_class() {
        assert_eq!(
            space_read_response_max_bytes("com.atproto.space.listRecords", reqwest::StatusCode::OK),
            ORDINARY_DS_CONTROL_MAX_BYTES
        );
        assert_eq!(
            space_read_response_max_bytes("com.atproto.space.getBlob", reqwest::StatusCode::OK),
            SPACE_BLOB_RESPONSE_MAX_BYTES
        );
        assert_eq!(
            space_read_response_max_bytes("com.atproto.space.getRepo", reqwest::StatusCode::OK),
            SPACE_REPO_RESPONSE_MAX_BYTES
        );
        assert_eq!(
            space_read_response_max_bytes(
                "com.atproto.space.getRepo",
                reqwest::StatusCode::BAD_GATEWAY
            ),
            ERROR_RESPONSE_MAX_BYTES
        );
    }

    #[test]
    fn signed_car_proof_verifies_inclusion_non_inclusion_and_rejects_tampering() {
        let did = "did:web:mailbox.example";
        let secret = p256::SecretKey::from_slice(&[0x51; 32]).unwrap();
        let vk = SpaceVerifyingKey::P256(p256::ecdsa::VerifyingKey::from(secret.public_key()));
        let wrong_secret = p256::SecretKey::from_slice(&[0x52; 32]).unwrap();
        let wrong_vk =
            SpaceVerifyingKey::P256(p256::ecdsa::VerifyingKey::from(wrong_secret.public_key()));

        let val_7 = sample_mailbox_value(7);
        let (car, cids) = build_signed_repo_car(
            did,
            "3l2aaaaaaaaaa",
            &secret,
            &[("blue.catbird.labyrinth.mailboxKeys/000000000007", &val_7)],
        );
        let verified = verify_mailbox_keys_car_proof(&car, did, "000000000007", &vk)
            .expect("valid inclusion proof")
            .expect("record present");
        let parsed: Value = serde_json::from_slice(&verified).unwrap();
        assert_eq!(
            parsed["uri"],
            format!("at://{did}/blue.catbird.labyrinth.mailboxKeys/000000000007")
        );
        assert_eq!(
            parsed["cid"],
            cids["blue.catbird.labyrinth.mailboxKeys/000000000007"].to_string()
        );
        assert_eq!(parsed["value"]["current"]["epochNumber"], 7);

        // Authenticated non-inclusion for `self` in the same signed MST returns `Ok(None)`.
        assert!(verify_mailbox_keys_car_proof(&car, did, "self", &vk)
            .expect("valid non-inclusion proof")
            .is_none());

        // Wrong DID or wrong signing key fails closed.
        assert!(
            verify_mailbox_keys_car_proof(&car, "did:web:other.example", "000000000007", &vk)
                .is_err()
        );
        assert!(verify_mailbox_keys_car_proof(&car, did, "000000000007", &wrong_vk).is_err());

        // Numeric 12-digit rkey mismatch with epochNumber fails closed.
        let (mismatch_car, _) = build_signed_repo_car(
            did,
            "3l2aaaaaaaaaa",
            &secret,
            &[("blue.catbird.labyrinth.mailboxKeys/000000000008", &val_7)],
        );
        assert!(verify_mailbox_keys_car_proof(&mismatch_car, did, "000000000008", &vk).is_err());

        // epochNumber > 999_999_999_999 fails closed.
        let val_overflow = sample_mailbox_value(1_000_000_000_000);
        let (overflow_car, _) = build_signed_repo_car(
            did,
            "3l2aaaaaaaaaa",
            &secret,
            &[("blue.catbird.labyrinth.mailboxKeys/self", &val_overflow)],
        );
        assert!(verify_mailbox_keys_car_proof(&overflow_car, did, "self", &vk).is_err());

        // Truncated CAR block section shorter than CID fails closed without panic/underflow.
        let header = json_to_canonical_dagcbor(&json!({
            "version": 1,
            "roots": [{ "$link": cids["blue.catbird.labyrinth.mailboxKeys/000000000007"].to_string() }],
        }));
        let mut truncated = Vec::new();
        encode_uvarint(header.len() as u64, &mut truncated);
        truncated.extend_from_slice(&header);
        encode_uvarint(3, &mut truncated);
        truncated.extend_from_slice(&[0x01, 0x71, 0x12]);
        assert!(verify_mailbox_keys_car_proof(&truncated, did, "self", &vk).is_err());

        assert_eq!(MAILBOX_KEYS_RECORD_MAX_BYTES, 1024 * 1024);
        for invalid in ["", ".", "..", "bad/key", "bad key", &"x".repeat(513)] {
            assert!(!valid_record_key(invalid), "{invalid:?}");
        }
        for valid in ["self", "000000000007", "a.b_c:d~e-f"] {
            assert!(valid_record_key(valid), "{valid:?}");
        }
    }

    #[test]
    fn device_key_car_proof_binds_did_record_key_and_admitted_signer() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let did = "did:web:deleting.example";
        let device_id = "f65aa2fd-6fae-4fc9-955b-088ce430f8d6";
        let secret = p256::SecretKey::from_slice(&[0x59; 32]).unwrap();
        let vk = SpaceVerifyingKey::P256(p256::ecdsa::VerifyingKey::from(secret.public_key()));
        let wrong_secret = p256::SecretKey::from_slice(&[0x5a; 32]).unwrap();
        let wrong_vk =
            SpaceVerifyingKey::P256(p256::ecdsa::VerifyingKey::from(wrong_secret.public_key()));
        let signing_key = [0x42; 32];
        let record = json!({
            "$type": "blue.catbird.chat.device",
            "mlsSignaturePublicKey": { "$bytes": STANDARD.encode(signing_key) },
            "algorithm": "ed25519",
            "createdAt": "2026-11-16T00:00:00Z",
        });
        let key = format!("blue.catbird.chat.device/{device_id}");
        let (car, _) =
            build_signed_repo_car(did, "3l2aaaaaaaaaa", &secret, &[(key.as_str(), &record)]);
        verify_chat_device_key_proof(&car, did, device_id, &signing_key, &vk).unwrap();
        assert!(verify_chat_device_key_proof(&car, did, device_id, &[0x43; 32], &vk).is_err());
        assert!(
            verify_chat_device_key_proof(&car, did, device_id, &signing_key, &wrong_vk).is_err()
        );
        assert!(verify_chat_device_key_proof(
            &car,
            did,
            "a3814970-35ec-4d0e-b37a-c39f87849469",
            &signing_key,
            &vk,
        )
        .is_err());
        assert!(verify_chat_device_key_proof(
            &car,
            "did:web:other.example",
            device_id,
            &signing_key,
            &vk
        )
        .is_err());
        let mut corrupt = car.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(verify_chat_device_key_proof(&corrupt, did, device_id, &signing_key, &vk).is_err());
        let oversized = vec![0; CHAT_DEVICE_KEY_PROOF_MAX_BYTES + 1];
        assert!(
            verify_chat_device_key_proof(&oversized, did, device_id, &signing_key, &vk).is_err()
        );
    }

    #[test]
    fn device_revocation_car_proof_binds_self_deletion_and_rejects_sibling() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use ed25519_dalek::Signer as _;

        let did = "did:web:deleting-rev.example";
        let device_id = "f65aa2fd-6fae-4fc9-955b-088ce430f8d6";
        let sibling_id = "a3814970-35ec-4d0e-b37a-c39f87849469";
        let secret = p256::SecretKey::from_slice(&[0x5b; 32]).unwrap();
        let vk = SpaceVerifyingKey::P256(p256::ecdsa::VerifyingKey::from(secret.public_key()));
        let ed_sk = ed25519_dalek::SigningKey::from_bytes(&[0x44; 32]);
        let ed_pk = ed_sk.verifying_key().to_bytes();
        let op_id = [0x9A; 16];
        let signed_at_str = "2026-11-17T03:00:00.123Z";
        let signed_at = chrono::DateTime::parse_from_rfc3339(signed_at_str)
            .unwrap()
            .with_timezone(&chrono::Utc);

        let sign_record = |actor: &str, signer: &ed25519_dalek::SigningKey, reason: &str| {
            let payload = PdsDeviceRevocationTranscriptPayload {
                repo_did: did,
                created_at: signed_at_str,
                actor_device_id: actor,
                target_device_id: device_id,
            };
            let cbor = serde_ipld_dagcbor::to_vec(&payload).unwrap();
            let transcript = [PDS_DEVICE_REVOCATION_DOMAIN, cbor.as_slice()].concat();
            let sig = signer.sign(&transcript).to_bytes();
            let record = json!({
                "$type": "blue.catbird.chat.deviceRevocation",
                "targetDeviceId": device_id,
                "actorDeviceId": actor,
                "signerPublicKey": { "$bytes": STANDARD.encode(signer.verifying_key().to_bytes()) },
                "signature": { "$bytes": STANDARD.encode(sig) },
                "algorithm": "ed25519",
                "reason": reason,
                "createdAt": signed_at_str,
            });
            let key = format!("blue.catbird.chat.deviceRevocation/{device_id}");
            build_signed_repo_car(did, "3l2aaaaaaaaaa", &secret, &[(key.as_str(), &record)]).0
        };

        let valid = sign_record(
            device_id,
            &ed_sk,
            &format!("deleteAccountData:{}", hex::encode(op_id)),
        );
        verify_chat_device_revocation_proof(&valid, did, device_id, &ed_pk, &op_id, signed_at, &vk)
            .unwrap();

        // Sibling revocation -> DeviceRevoked (non-retryable)
        let sibling_sk = ed25519_dalek::SigningKey::from_bytes(&[0x45; 32]);
        let sibling_car = sign_record(sibling_id, &sibling_sk, "revoked_by_sibling");
        assert!(matches!(
            verify_chat_device_revocation_proof(
                &sibling_car,
                did,
                device_id,
                &ed_pk,
                &op_id,
                signed_at,
                &vk
            ),
            Err(SpaceRelayError::DeviceRevoked(_))
        ));

        // Mismatched operation id -> DeviceRevoked
        assert!(matches!(
            verify_chat_device_revocation_proof(
                &valid,
                did,
                device_id,
                &ed_pk,
                &[0x9B; 16],
                signed_at,
                &vk
            ),
            Err(SpaceRelayError::DeviceRevoked(_))
        ));

        // Retry with write signedAt > record createdAt succeeds when operationId matches;
        // createdAt postdating write signedAt is rejected.
        let later_retry = signed_at + chrono::TimeDelta::seconds(600);
        verify_chat_device_revocation_proof(
            &valid,
            did,
            device_id,
            &ed_pk,
            &op_id,
            later_retry,
            &vk,
        )
        .expect("retry after 300s skew window with prior createdAt succeeds");
        let earlier_write = signed_at - chrono::TimeDelta::seconds(1);
        assert!(matches!(
            verify_chat_device_revocation_proof(
                &valid,
                did,
                device_id,
                &ed_pk,
                &op_id,
                earlier_write,
                &vk
            ),
            Err(SpaceRelayError::DeviceRevoked(_))
        ));
    }

    #[tokio::test]
    async fn mailbox_relay_resolves_the_pds_and_verifies_signed_sync_get_record_car() {
        let target = "did:web:peer.example";
        let pds_secret = p256::SecretKey::from_slice(&[0x61; 32]).unwrap();
        let pds_did_key = encode_p256_did_key(&pds_secret.public_key());
        let mode = Arc::new(AtomicUsize::new(0)); // 0 = valid CAR, 1 = unsigned 404 JSON, 2 = oversized
        let record_hits = Arc::new(AtomicUsize::new(0));
        let val = sample_mailbox_value(1);
        let (valid_car, cids) = build_signed_repo_car(
            target,
            "3l2aaaaaaaaaa",
            &pds_secret,
            &[("blue.catbird.labyrinth.mailboxKeys/self", &val)],
        );
        let valid_car = Arc::new(valid_car);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new()
            .route(
                "/.well-known/did.json",
                get({
                    let multibase = pds_did_key.strip_prefix("did:key:").unwrap().to_string();
                    move || {
                        let multibase = multibase.clone();
                        async move {
                            Json(json!({
                                "id": target,
                                "verificationMethod": [{
                                    "id": format!("{target}#atproto"),
                                    "type": "Multikey",
                                    "controller": target,
                                    "publicKeyMultibase": multibase,
                                }],
                                "service": [{
                                    "id": "#atproto_pds",
                                    "type": "AtprotoPersonalDataServer",
                                    "serviceEndpoint": "https://peer-pds.example",
                                }],
                            }))
                        }
                    }
                }),
            )
            .route(
                "/xrpc/com.atproto.sync.getRecord",
                get({
                    let mode = mode.clone();
                    let record_hits = record_hits.clone();
                    let valid_car = valid_car.clone();
                    move |Query(query): Query<std::collections::BTreeMap<String, String>>,
                          headers: HeaderMap| {
                        let mode = mode.clone();
                        let record_hits = record_hits.clone();
                        let valid_car = valid_car.clone();
                        async move {
                            record_hits.fetch_add(1, Ordering::SeqCst);
                            assert_eq!(query.len(), 3);
                            assert_eq!(query.get("did").map(String::as_str), Some(target));
                            assert_eq!(
                                query.get("collection").map(String::as_str),
                                Some("blue.catbird.labyrinth.mailboxKeys")
                            );
                            for forbidden in [
                                "authorization",
                                "cookie",
                                "atproto-proxy",
                                "x-forwarded-for",
                            ] {
                                assert!(headers.get(forbidden).is_none(), "{forbidden}");
                            }
                            match mode.load(Ordering::SeqCst) {
                                1 => (
                                    axum::http::StatusCode::NOT_FOUND,
                                    Json(json!({"error": "RecordNotFound"})),
                                )
                                    .into_response(),
                                2 => http::Response::builder()
                                    .status(200)
                                    .header(
                                        http::header::CONTENT_LENGTH,
                                        (MAILBOX_KEYS_RECORD_MAX_BYTES + 1).to_string(),
                                    )
                                    .body(axum::body::Body::empty())
                                    .unwrap(),
                                _ => (
                                    [(http::header::CONTENT_TYPE, "application/vnd.ipld.car")],
                                    valid_car.as_ref().clone(),
                                )
                                    .into_response(),
                            }
                        }
                    }
                }),
            );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/nonexistent_mailbox_relay_test")
            .unwrap();
        let resolver = DsResolver::new(
            pool,
            reqwest::Client::new(),
            "did:web:home.example".to_owned(),
            "https://home.example".to_owned(),
            None,
            300,
        )
        .with_destination_resolver_hook(Arc::new(move |target_url: &str| {
            let remote = Url::parse(target_url).unwrap();
            let mut local = Url::parse(&format!("http://127.0.0.1:{}/", addr.port())).unwrap();
            local.set_path(remote.path());
            local.set_query(remote.query());
            Some(Box::pin(async move {
                Ok(ValidatedRemoteDestination {
                    url: local,
                    host: "127.0.0.1".to_owned(),
                    addrs: vec![addr],
                })
            }))
        }));

        let relayed = relay_mailbox_keys_record(&resolver, target, "self")
            .await
            .unwrap()
            .expect("verified record");
        let parsed: Value = serde_json::from_slice(&relayed).unwrap();
        assert_eq!(
            parsed["cid"],
            cids["blue.catbird.labyrinth.mailboxKeys/self"].to_string()
        );
        assert_eq!(record_hits.load(Ordering::SeqCst), 1);

        // Authenticated non-inclusion in signed MST returns None (`404 RecordNotFound` downstream).
        assert!(relay_mailbox_keys_record(&resolver, target, "000000000009")
            .await
            .unwrap()
            .is_none());
        assert_eq!(record_hits.load(Ordering::SeqCst), 2);

        // Unsigned HTTP 404 RecordNotFound JSON is NEVER trusted — fails closed with UpstreamError!
        mode.store(1, Ordering::SeqCst);
        assert!(matches!(
            relay_mailbox_keys_record(&resolver, target, "self").await,
            Err(SpaceRelayError::UpstreamError(_))
        ));
        assert_eq!(record_hits.load(Ordering::SeqCst), 3);

        // Invalid inputs fail before touching upstream.
        for (did, rkey) in [
            ("did:web:peer.example#fragment", "self"),
            (target, "bad/key"),
        ] {
            assert!(matches!(
                relay_mailbox_keys_record(&resolver, did, rkey).await,
                Err(SpaceRelayError::InvalidRequest(_))
            ));
        }
        assert_eq!(record_hits.load(Ordering::SeqCst), 3);

        mode.store(2, Ordering::SeqCst);
        assert!(matches!(
            relay_mailbox_keys_record(&resolver, target, "self").await,
            Err(SpaceRelayError::UpstreamError(_))
        ));
        assert_eq!(record_hits.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn read_relay_rejects_a_declared_body_over_the_nsid_budget() {
        let target = "did:web:space-read-budget.example";
        let router = Router::new().route(
            "/xrpc/com.atproto.space.listWriters",
            get(|| async {
                let declared_bytes = ORDINARY_DS_CONTROL_MAX_BYTES + 1;
                http::Response::builder()
                    .status(200)
                    .header(http::header::CONTENT_LENGTH, declared_bytes.to_string())
                    .body(axum::body::Body::from(vec![0; declared_bytes]))
                    .unwrap()
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        register_test_space_relay_target(
            target,
            &format!("http://{}", listener.local_addr().unwrap()),
        );
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

        let error = relay_space_read_stateless(
            target,
            "com.atproto.space.listWriters",
            None,
            "credential",
            "space",
            None,
            "sig1=(\"@method\")",
            "sig1=:AA==:",
        )
        .await
        .err()
        .expect("declared oversized response must be refused");
        assert!(matches!(error, SpaceRelayError::UpstreamError(_)));
        server.abort();
    }

    fn credential_fixture(authority: &str) -> (SpaceSigningKey, SpaceTokenClaims, Value) {
        let secret = p256::SecretKey::from_slice(&[0x21; 32]).unwrap();
        let pop = p256::SecretKey::from_slice(&[0x31; 32]).unwrap();
        let kem = p256::SecretKey::from_slice(&[0x22; 32]).unwrap();
        let public_key = encode_p256_did_key(&secret.public_key());
        let kem_key = encode_p256_did_key(&kem.public_key());
        let document = json!({
            "id": authority,
            "verificationMethod": [
                {
                    "id": "#atproto_kem", "type": "Multikey", "controller": authority,
                    "publicKeyMultibase": kem_key.strip_prefix("did:key:").unwrap(),
                },
                {
                    "id": format!("{authority}#atproto"), "type": "Multikey",
                    "controller": authority,
                    "publicKeyMultibase": public_key.strip_prefix("did:key:").unwrap(),
                },
            ],
        });
        (
            SpaceSigningKey::from_p256_secret(&secret, "#atproto"),
            SpaceTokenClaims {
                iss: authority.into(),
                sub: format!("at://{authority}/space/blue.catbird.labyrinth.mailbox/self"),
                aud: None,
                iat: NOW,
                exp: NOW + 600,
                jti: "credential-relay-test".into(),
                cnf_kid: Some(encode_p256_did_key(&pop.public_key())),
            },
            document,
        )
    }

    #[tokio::test]
    async fn standard_post_verifies_jwt_only_response_and_all_credential_bindings() {
        let authority = "did:web:credential-relay-post.example";
        let (signing_key, claims, document) = credential_fixture(authority);
        let jwt = mint_space_token(SpaceTokenKind::Credential, &signing_key, &claims).unwrap();
        let response = Arc::new(Mutex::new(
            json!({"credential": jwt, "spaceRev": "3l2aaaaaaaaaa"}),
        ));
        let document = Arc::new(Mutex::new(document));
        let requests = Arc::new(AtomicUsize::new(0));
        let expected_body = json!({
            "space": claims.sub,
            "credentialKey": claims.cnf_kid,
            "delegationToken": "secret-delegation.jwt",
        });
        let router = Router::new()
            .route(
                "/xrpc/com.atproto.space.authorizeSpaceSync",
                post({
                    let response = response.clone();
                    let requests = requests.clone();
                    move |OriginalUri(uri): OriginalUri,
                          headers: HeaderMap,
                          Json(body): Json<Value>| {
                        let response = response.clone();
                        let requests = requests.clone();
                        let expected_body = expected_body.clone();
                        async move {
                            assert!(uri.query().is_none(), "delegation must never enter the URL");
                            assert_eq!(headers["content-type"], "application/json");
                            assert_eq!(body, expected_body);
                            requests.fetch_add(1, Ordering::SeqCst);
                            Json(response.lock().unwrap().clone())
                        }
                    }
                }),
            )
            .route(
                /* did-web-test */ "/.well-known/did.json",
                get({
                    let document = document.clone();
                    move || {
                        let document = document.clone();
                        async move { Json(document.lock().unwrap().clone()) }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        register_test_space_relay_target(
            authority,
            &format!("http://{}", listener.local_addr().unwrap()),
        );
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let clock = Arc::new(crate::sim_hooks::ManualDsClock::new(
            chrono::DateTime::from_timestamp(NOW as i64, 0).unwrap(),
        ));
        crate::sim_hooks::scope_ds_clock(clock.clone(), async {
            let kid = claims.cnf_kid.as_deref().unwrap();
            let exchange = || {
                relay_space_credential_stateless(
                    authority,
                    &claims.sub,
                    "secret-delegation.jwt",
                    kid,
                )
            };
            let output = exchange()
                .await
                .expect("standard POST with JWT-only response");
            assert_eq!(output.credential, jwt);
            let expected_expiry = chrono::DateTime::from_timestamp(claims.exp as i64, 0)
                .unwrap()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            assert_eq!(output.expires_at, expected_expiry);
            assert!(output.expires_at.ends_with(".000Z"));
            assert_eq!(output.space_rev.as_deref(), Some("3l2aaaaaaaaaa"));

            response.lock().unwrap()["expiresAt"] = json!("9999-01-01T00:00:00.000Z");
            assert_eq!(exchange().await.unwrap().expires_at, expected_expiry);

            let attacker = p256::SecretKey::from_slice(&[0x22; 32]).unwrap();
            let attacker_key = SpaceSigningKey::from_p256_secret(&attacker, "#atproto");
            let forged =
                mint_space_token(SpaceTokenKind::Credential, &attacker_key, &claims).unwrap();
            let parts: Vec<_> = jwt.split('.').collect();
            let mut unsigned: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
            unsigned["exp"] = json!(NOW + 1200);
            let tampered_expiry = format!(
                "{}.{}.{}",
                parts[0],
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&unsigned).unwrap()),
                parts[2]
            );
            let mut wrong_space = claims.clone();
            wrong_space.sub =
                format!("at://{authority}/space/blue.catbird.labyrinth.mailbox/other");
            let mut wrong_pop = claims.clone();
            wrong_pop.cnf_kid = Some(encode_p256_did_key(&attacker.public_key()));
            let mut wrong_authority = claims.clone();
            wrong_authority.iss = "did:web:another-authority.example".into();
            wrong_authority.sub =
                "at://did:web:another-authority.example/space/blue.catbird.labyrinth.mailbox/self"
                    .into();
            let mut expired = claims.clone();
            expired.iat = NOW - 600;
            expired.exp = NOW - 1;
            for invalid in [
                forged,
                tampered_expiry,
                mint_space_token(SpaceTokenKind::Credential, &signing_key, &wrong_space).unwrap(),
                mint_space_token(SpaceTokenKind::Credential, &signing_key, &wrong_pop).unwrap(),
                mint_space_token(SpaceTokenKind::Credential, &signing_key, &wrong_authority)
                    .unwrap(),
                mint_space_token(SpaceTokenKind::Credential, &signing_key, &expired).unwrap(),
            ] {
                *response.lock().unwrap() =
                    json!({"credential": invalid, "expiresAt": expected_expiry});
                assert!(matches!(
                    exchange().await,
                    Err(SpaceRelayError::UpstreamError(_))
                ));
            }
            *response.lock().unwrap() = json!({"credential": jwt});
            document.lock().unwrap()["id"] = json!("did:web:unrelated-document.example");
            assert!(matches!(
                exchange().await,
                Err(SpaceRelayError::UpstreamError(_))
            ));
            document.lock().unwrap()["id"] = json!(authority);
            clock.set_utc(chrono::DateTime::from_timestamp(claims.exp as i64, 0).unwrap());
            assert!(matches!(
                exchange().await,
                Err(SpaceRelayError::UpstreamError(_))
            ));
            clock.set_utc(chrono::DateTime::from_timestamp(NOW as i64, 0).unwrap());
            assert!(exchange().await.is_ok());

            let before = requests.load(Ordering::SeqCst);
            let at_space_scheme = claims.sub.replacen("at://", "at-space://", 1);
            let record_uri = format!(
                "{}/did:plc:alice/blue.catbird.labyrinth.entry/3l2aaaaaaaaaa",
                claims.sub
            );
            for (target, space, pop_key) in [
                (authority, claims.sub.as_str(), "not-a-P256-did-key"),
                (authority, at_space_scheme.as_str(), kid),
                (authority, record_uri.as_str(), kid),
                ("did:web:wrong-target.example", claims.sub.as_str(), kid),
            ] {
                assert!(
                    matches!(
                        relay_space_credential_stateless(
                            target,
                            space,
                            "secret-delegation.jwt",
                            pop_key
                        )
                        .await,
                        Err(SpaceRelayError::InvalidRequest(_))
                    ),
                    "{target} {space} {pop_key}"
                );
            }
            assert_eq!(
                requests.load(Ordering::SeqCst),
                before,
                "invalid inputs must not forward delegation"
            );
        })
        .await;
        server.abort();
    }

    #[tokio::test]
    async fn credential_exchange_does_not_follow_redirects() {
        let authority = "did:web:credential-relay-redirect.example";
        let (_, claims, _) = credential_fixture(authority);
        let followed = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .route(
                "/xrpc/com.atproto.space.authorizeSpaceSync",
                post(|| async {
                    (
                        axum::http::StatusCode::TEMPORARY_REDIRECT,
                        [("location", "/leak")],
                    )
                }),
            )
            .route(
                "/leak",
                post({
                    let followed = followed.clone();
                    move || {
                        let followed = followed.clone();
                        async move {
                            followed.fetch_add(1, Ordering::SeqCst);
                            "must not forward delegation"
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        register_test_space_relay_target(
            authority,
            &format!("http://{}", listener.local_addr().unwrap()),
        );
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        assert!(matches!(
            relay_space_credential_stateless(
                authority,
                &claims.sub,
                "private-delegation",
                claims.cnf_kid.as_deref().unwrap()
            )
            .await,
            Err(SpaceRelayError::UpstreamError(_))
        ));
        assert_eq!(followed.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[cfg(feature = "sim")]
    #[tokio::test]
    async fn credential_post_and_did_lookup_use_scoped_simulator_transport() {
        let authority = "did:web:credential-relay-sim.example";
        let (key, claims, document) = credential_fixture(authority);
        let jwt = mint_space_token(SpaceTokenKind::Credential, &key, &claims).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let hooks = Arc::new(crate::sim_hooks::SimDsHooks {
            service_did: "did:web:home-relay-sim.example".into(),
            self_endpoint: "https://home-relay-sim.example".into(),
            signing_key_pem: None,
            group_relay_hmac_secret: None,
            http_transport: Arc::new({
                let requests = requests.clone();
                let jwt = jwt.clone();
                let expected_space = claims.sub.clone();
                let expected_kid = claims.cnf_kid.clone().unwrap();
                move |request| {
                    let requests = requests.clone();
                    let jwt = jwt.clone();
                    let document = document.clone();
                    let expected_space = expected_space.clone();
                    let expected_kid = expected_kid.clone();
                    Box::pin(async move {
                        assert!(request.url.query().is_none());
                        requests
                            .lock()
                            .unwrap()
                            .push((request.method.clone(), request.url.path().to_string()));
                        let body = match request.url.path() {
                            "/xrpc/com.atproto.space.authorizeSpaceSync" => {
                                assert_eq!(request.method, http::Method::POST);
                                assert_eq!(
                                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                                    json!({
                                        "space": expected_space, "credentialKey": expected_kid,
                                        "delegationToken": "simulated-private-delegation",
                                    })
                                );
                                json!({"credential": jwt})
                            }
                            path if path == /* did-web-test */ "/.well-known/did.json" => {
                                assert_eq!(request.method, http::Method::GET);
                                document
                            }
                            path => panic!("unexpected outbound request: {path}"),
                        };
                        Ok(http::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(serde_json::to_vec(&body).unwrap())
                            .unwrap())
                    })
                }
            }),
            dns_resolver: Arc::new(|_| Ok(vec!["93.184.216.34".parse().unwrap()])),
            retain_application_ciphertext: false,
        });
        let clock = Arc::new(crate::sim_hooks::ManualDsClock::new(
            chrono::DateTime::from_timestamp(NOW as i64, 0).unwrap(),
        ));
        let output = crate::sim_hooks::scope_ds_clock(
            clock,
            crate::sim_hooks::scope_sim_ds(
                hooks,
                relay_space_credential_stateless(
                    authority,
                    &claims.sub,
                    "simulated-private-delegation",
                    claims.cnf_kid.as_deref().unwrap(),
                ),
            ),
        )
        .await
        .unwrap();
        assert_eq!(output.credential, jwt);
        assert_eq!(requests.lock().unwrap().len(), 2);
    }
}
