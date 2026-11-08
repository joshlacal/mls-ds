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
//!
//! Credential exchange uses standard POST JSON (never a delegation token in the URL).
//! The home response's `expiresAt` comes from the authority-signed credential after exact
//! issuer, Space, PoP-key, and current scoped-clock expiry checks. The authority's signed
//! refusal (403 `NotAuthorized` carrying `denial`) reaches the client byte for byte; only the
//! client's check of that signature makes a refusal removal proof.

use std::{collections::HashMap, net::SocketAddr, sync::RwLock, time::Duration};

use atproto_spaces::{
    did_resolver::DidDocument,
    kem::decode_p256_did_key,
    tokens::{verify_space_token, SpaceKeyResolver, SpaceTokenKind, SpaceVerifyingKey},
    SpaceUri, SpacesError,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
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

/// Blob reads cover the client's 10 MiB encrypted-attachment ceiling plus
/// framing overhead. Repository exports are larger but still explicitly
/// bounded because this relay currently returns one in-memory HTTP body.
const SPACE_BLOB_RESPONSE_MAX_BYTES: usize = 16 * 1024 * 1024;
const SPACE_REPO_RESPONSE_MAX_BYTES: usize = 64 * 1024 * 1024;
const MAILBOX_KEYS_RECORD_MAX_BYTES: usize = 1024 * 1024;

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
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15));
    if !target.is_test_override && !target.pinned_addrs.is_empty() {
        builder = builder.resolve_to_addrs(&target.host, &target.pinned_addrs);
    }
    builder
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamCredentialRequest<'a> {
    space: &'a str,
    credential_kid: &'a str,
    delegation_token: &'a str,
}

#[derive(Deserialize)]
struct UpstreamCredentialOutput {
    credential: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayedCredentialOutput {
    pub credential: String,
    pub expires_at: String,
}

/// Exchange via standard POST JSON and return only an authority-verified, PoP-bound credential.
pub async fn relay_space_credential_stateless(
    authority_did: &str,
    space_uri: &str,
    delegation_token: &str,
    credential_kid: &str,
) -> Result<RelayedCredentialOutput, SpaceRelayError> {
    let authority_did = crate::identity::canonical_did(authority_did);
    let space =
        SpaceUri::parse(space_uri).map_err(|e| SpaceRelayError::InvalidRequest(e.to_string()))?;
    if space.authority != authority_did {
        return Err(SpaceRelayError::InvalidRequest(
            "Space authority does not match authorityDid".into(),
        ));
    }
    decode_p256_did_key(credential_kid)
        .map_err(|e| SpaceRelayError::InvalidRequest(e.to_string()))?;

    let target = resolve_ssrf_safe_space_endpoint(authority_did).await?;
    let client = build_pinned_client(&target)?;

    let url = format!(
        "{}/xrpc/com.atproto.space.getSpaceCredential",
        target.base_url
    );
    let request = UpstreamCredentialRequest {
        space: space_uri,
        credential_kid,
        delegation_token,
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
            "upstream getSpaceCredential HTTP {}: {}",
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
    if claims.iss != authority_did
        || claims.sub != space_uri
        || claims.cnf_kid.as_deref() != Some(credential_kid)
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
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    Ok(RelayedCredentialOutput {
        credential: upstream.credential,
        expires_at,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MailboxKeysRecordEnvelope {
    uri: String,
    cid: String,
    #[serde(rename = "value")]
    _value: catbird_atproto::generated::blue_catbird::labyrinth::mailbox_keys::MailboxKeys<String>,
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

fn validate_mailbox_keys_record(
    body: &[u8],
    target_did: &str,
    rkey: &str,
) -> Result<(), SpaceRelayError> {
    let envelope: MailboxKeysRecordEnvelope = serde_json::from_slice(body)
        .map_err(|_| SpaceRelayError::UpstreamError("malformed mailboxKeys record".into()))?;
    let expected_uri = format!("at://{target_did}/blue.catbird.labyrinth.mailboxKeys/{rkey}");
    if envelope.uri != expected_uri {
        return Err(SpaceRelayError::UpstreamError(
            "mailboxKeys record URI does not match target DID and rkey".into(),
        ));
    }
    let current = &envelope._value.current;
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
    if !(0..=1_099_511_627_776).contains(&current.epoch_number)
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
    let cid = envelope
        .cid
        .parse::<cid::Cid>()
        .map_err(|_| SpaceRelayError::UpstreamError("invalid mailboxKeys record CID".into()))?;
    let canonical = serde_ipld_dagcbor::to_vec(&envelope._value).map_err(|_| {
        SpaceRelayError::UpstreamError("mailboxKeys value is not canonical DAG-CBOR data".into())
    })?;
    if atproto_spaces::lthash::compute_dagcbor_cid(&canonical) != cid {
        return Err(SpaceRelayError::UpstreamError(
            "mailboxKeys record CID does not match its value".into(),
        ));
    }
    Ok(())
}

fn mailbox_resolution_error(error: FederationError) -> SpaceRelayError {
    if error.is_retryable() {
        SpaceRelayError::UpstreamUnavailable(error.to_string())
    } else {
        SpaceRelayError::InvalidTargetEndpoint(error.to_string())
    }
}

/// Read one public `mailboxKeys` record through the authenticated caller's
/// home service. Only the target DID and rkey influence the outbound request:
/// the PDS endpoint is live-resolved and DNS-pinned, the collection is fixed,
/// and no caller URL, authorization, headers, or token are forwarded.
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

    let pds = resolver
        .resolve_did_to_pds(target_did)
        .await
        .map_err(mailbox_resolution_error)?;
    let mut url = Url::parse(&format!(
        "{}/xrpc/com.atproto.repo.getRecord",
        pds.trim_end_matches('/')
    ))
    .map_err(|error| SpaceRelayError::InvalidTargetEndpoint(error.to_string()))?;
    url.query_pairs_mut()
        .append_pair("repo", target_did)
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
        "mailboxKeys record read failed",
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
    if matches!(
        status,
        reqwest::StatusCode::BAD_REQUEST | reqwest::StatusCode::NOT_FOUND
    ) && serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .as_deref()
        == Some("RecordNotFound")
    {
        return Ok(None);
    }
    if !status.is_success() {
        let reason = format!("mailboxKeys PDS returned HTTP {}", status.as_u16());
        return Err(if retryable_status(status) {
            SpaceRelayError::UpstreamUnavailable(reason)
        } else {
            SpaceRelayError::UpstreamError(reason)
        });
    }
    validate_mailbox_keys_record(&body, target_did, rkey)?;
    Ok(Some(body))
}

pub struct RelayedSpaceReadResponse {
    pub status: u16,
    pub content_type: String,
    pub space_mac: Option<String>,
    pub body: bytes::Bytes,
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

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let resp = crate::sim_hooks::send_reqwest(req)
        .await
        .map_err(SpaceRelayError::UpstreamUnavailable)?;
    let status = resp.status();
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
        body,
    })
}

#[cfg(test)]
mod tests {
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

    fn mailbox_value_cid(value: &Value) -> String {
        let typed: catbird_atproto::generated::blue_catbird::labyrinth::mailbox_keys::MailboxKeys<
            String,
        > = serde_json::from_value(value.clone()).unwrap();
        let canonical = serde_ipld_dagcbor::to_vec(&typed).unwrap();
        atproto_spaces::lthash::compute_dagcbor_cid(&canonical).to_string()
    }

    /// Only a failed DNS lookup of the target decided nothing; every other
    /// endpoint refusal stays the permanent `InvalidTargetEndpoint`.
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
    fn mailbox_record_validation_binds_selector_cid_and_typed_value() {
        let did = "did:web:mailbox.example";
        let rkey = "000000000007";
        let bytes = |len| json!({ "$bytes": STANDARD.encode(vec![0u8; len]) });
        let mut record = json!({
            "uri": format!("at://{did}/blue.catbird.labyrinth.mailboxKeys/{rkey}"),
            "cid": "",
            "value": {
                "$type": "blue.catbird.labyrinth.mailboxKeys",
                "current": {
                    "epochNumber": 7,
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
            },
        });
        let cid = mailbox_value_cid(&record["value"]);
        record["cid"] = json!(&cid);
        let encode = |value: &Value| serde_json::to_vec(value).unwrap();
        assert!(validate_mailbox_keys_record(&encode(&record), did, rkey).is_ok());

        record["uri"] =
            json!("at://did:web:attacker.example/blue.catbird.labyrinth.mailboxKeys/other");
        assert!(validate_mailbox_keys_record(&encode(&record), did, rkey).is_err());
        record["uri"] = json!(format!(
            "at://{did}/blue.catbird.labyrinth.mailboxKeys/{rkey}"
        ));
        record["cid"] = json!("not-a-cid");
        assert!(validate_mailbox_keys_record(&encode(&record), did, rkey).is_err());
        record["cid"] = json!(cid);
        record["value"]["updatedAt"] = json!("2026-11-05T00:00:00Z");
        assert!(validate_mailbox_keys_record(&encode(&record), did, rkey).is_err());
        record["value"]["updatedAt"] = json!("2026-11-04T00:00:00Z");
        record["value"]["current"]["authPubkey"] = bytes(31);
        record["cid"] = json!(mailbox_value_cid(&record["value"]));
        assert!(validate_mailbox_keys_record(&encode(&record), did, rkey).is_err());
        record["value"].as_object_mut().unwrap().remove("current");
        assert!(validate_mailbox_keys_record(&encode(&record), did, rkey).is_err());

        assert_eq!(MAILBOX_KEYS_RECORD_MAX_BYTES, 1024 * 1024);
        for invalid in ["", ".", "..", "bad/key", "bad key", &"x".repeat(513)] {
            assert!(!valid_record_key(invalid), "{invalid:?}");
        }
        for valid in ["self", "000000000007", "a.b_c:d~e-f"] {
            assert!(valid_record_key(valid), "{valid:?}");
        }
    }

    #[tokio::test]
    async fn mailbox_relay_resolves_the_pds_and_forwards_only_the_fixed_public_selector() {
        let target = "did:web:peer.example";
        let oversized = Arc::new(AtomicBool::new(false));
        let record_hits = Arc::new(AtomicUsize::new(0));
        let bytes = |len| json!({ "$bytes": STANDARD.encode(vec![0u8; len]) });
        let mut record = json!({
            "uri": format!("at://{target}/blue.catbird.labyrinth.mailboxKeys/self"),
            "cid": "",
            "value": {
                "$type": "blue.catbird.labyrinth.mailboxKeys",
                "current": {
                    "epochNumber": 1,
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
            },
        });
        record["cid"] = json!(mailbox_value_cid(&record["value"]));
        let record = Arc::new(record);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new()
            .route(
                "/.well-known/did.json",
                get(move || async move {
                    Json(json!({
                        "id": target,
                        "service": [{
                            "id": "#atproto_pds",
                            "type": "AtprotoPersonalDataServer",
                            "serviceEndpoint": "https://peer-pds.example",
                        }],
                    }))
                }),
            )
            .route(
                "/xrpc/com.atproto.repo.getRecord",
                get({
                    let oversized = oversized.clone();
                    let record_hits = record_hits.clone();
                    let record = record.clone();
                    move |Query(query): Query<std::collections::BTreeMap<String, String>>,
                          headers: HeaderMap| {
                        let oversized = oversized.clone();
                        let record_hits = record_hits.clone();
                        let record = record.clone();
                        async move {
                            record_hits.fetch_add(1, Ordering::SeqCst);
                            assert_eq!(query.len(), 3);
                            assert_eq!(query.get("repo").map(String::as_str), Some(target));
                            assert_eq!(
                                query.get("collection").map(String::as_str),
                                Some("blue.catbird.labyrinth.mailboxKeys")
                            );
                            assert_eq!(query.get("rkey").map(String::as_str), Some("self"));
                            for forbidden in [
                                "authorization",
                                "cookie",
                                "atproto-proxy",
                                "x-forwarded-for",
                            ] {
                                assert!(headers.get(forbidden).is_none(), "{forbidden}");
                            }
                            if oversized.load(Ordering::SeqCst) {
                                return http::Response::builder()
                                    .status(200)
                                    .header(
                                        http::header::CONTENT_LENGTH,
                                        (MAILBOX_KEYS_RECORD_MAX_BYTES + 1).to_string(),
                                    )
                                    .body(axum::body::Body::empty())
                                    .unwrap();
                            }
                            Json(record.as_ref().clone()).into_response()
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
            .expect("record");
        assert_eq!(serde_json::from_slice::<Value>(&relayed).unwrap(), *record);
        assert_eq!(record_hits.load(Ordering::SeqCst), 1);
        for (did, rkey) in [
            ("did:web:peer.example#fragment", "self"),
            (target, "bad/key"),
        ] {
            assert!(matches!(
                relay_mailbox_keys_record(&resolver, did, rkey).await,
                Err(SpaceRelayError::InvalidRequest(_))
            ));
        }
        assert_eq!(record_hits.load(Ordering::SeqCst), 1);

        oversized.store(true, Ordering::SeqCst);
        assert!(matches!(
            relay_mailbox_keys_record(&resolver, target, "self").await,
            Err(SpaceRelayError::UpstreamError(_))
        ));
        assert_eq!(record_hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn read_relay_rejects_a_declared_body_over_the_nsid_budget() {
        let target = "did:web:space-read-budget.example";
        let router = Router::new().route(
            "/xrpc/com.atproto.space.listRepos",
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
            "com.atproto.space.listRepos",
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
        let response = Arc::new(Mutex::new(json!({"credential": jwt})));
        let document = Arc::new(Mutex::new(document));
        let requests = Arc::new(AtomicUsize::new(0));
        let expected_body = json!({
            "space": claims.sub,
            "credentialKid": claims.cnf_kid,
            "delegationToken": "secret-delegation.jwt",
        });
        let router = Router::new()
            .route(
                "/xrpc/com.atproto.space.getSpaceCredential",
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
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            assert_eq!(output.expires_at, expected_expiry);

            response.lock().unwrap()["expiresAt"] = json!("9999-01-01T00:00:00Z");
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
            expired.exp = NOW - 1; // The shared verifier's skew must not make an expired relay result usable.
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
            // The PoP key must be a P-256 did:key, and only the exact
            // at://{authorityDid}/space/{spaceType}/{skey} form names the Space.
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
                "/xrpc/com.atproto.space.getSpaceCredential",
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
                            "/xrpc/com.atproto.space.getSpaceCredential" => {
                                assert_eq!(request.method, http::Method::POST);
                                assert_eq!(
                                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                                    json!({
                                        "space": expected_space, "credentialKid": expected_kid,
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
