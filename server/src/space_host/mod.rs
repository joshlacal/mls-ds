//! Option A Conversation `SpaceHost` (`atproto#5187` / Spec §6.1, §6.2, §6.5).
//!
//! Each sequencing `mls-ds` (`did:web` or `did:plc`) acts as the Space Authority and
//! Space Host for conversation Spaces (`at://{authority_did}/space/blue.catbird.labyrinth.conversation/{conversation_id}-{generation}`).
//!
//! Key security & federation invariants:
//! - Zero `NOT c.is_remote` local-only guards anywhere in `space_host`.
//! - `getSpaceCredential` and `notifyWrite` require `status = 'active'` in `chat.participants`
//!   (excluding `'pending'` / declined `C33` direct-request targets and `'left'` / `'removed'` ex-members).
//! - `listRepos` includes historical writers with `status IN ('active', 'left', 'removed')` in
//!   ascending `spaceRev` order while strictly excluding `'pending'` `C33` targets and deleted accounts.
//! - Single-use 60s delegation `jti` replay cache (`chat.space_delegation_jtis`) and 10m credential
//!   `jti` ledger (`chat.space_credential_jtis`).
//! - Post-commit revocation & Space-deletion webhook fan-out (`M-F04`: never inside an open SQL transaction).

pub mod handlers;
pub mod revocation_fanout;

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};

use atproto_spaces::tokens::{
    inspect_untrusted_space_token, mint_space_token, verify_space_token, SpaceKeyResolver,
    SpaceSigningKey, SpaceTokenClaims, SpaceTokenKind, SpaceVerifyingKey,
};
use axum::Router;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use p256::ecdsa::{
    signature::Signer, Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{push_gateway::ssrf::validate_https_url_with_resolver, storage::DbPool};

pub use handlers::space_host_router;

#[derive(Debug, Clone)]
pub struct SpaceHostConfig {
    pub authority_did: String,
    pub signing_key: P256SigningKey,
}

impl SpaceHostConfig {
    pub fn new(authority_did: String, signing_key: P256SigningKey) -> Self {
        Self {
            authority_did: crate::identity::canonical_did(&authority_did).to_string(),
            signing_key,
        }
    }

    pub fn for_test(authority_did: String, signing_key: P256SigningKey) -> Self {
        Self::new(authority_did, signing_key)
    }

    pub fn from_env() -> Option<Self> {
        use p256::pkcs8::DecodePrivateKey as _;
        let authority_did = crate::identity::service_did_base_opt()?;
        let pem = std::env::var("SPACE_HOST_SIGNING_KEY_PEM")
            .or_else(|_| std::env::var("SIGNING_KEY_PEM"))
            .ok()?;
        let signing_key = P256SigningKey::from_pkcs8_pem(&pem).ok()?;
        Some(Self::new(authority_did, signing_key))
    }
}

#[derive(Debug, Clone)]
struct CachedDidEntry {
    verifying_key: SpaceVerifyingKey,
    endpoint_url: String,
    fetched_at: Instant,
}

pub struct SpaceHostRuntime {
    pool: DbPool,
    config: SpaceHostConfig,
    tid_counter: AtomicU64,
    did_cache: RwLock<HashMap<String, CachedDidEntry>>,
    #[cfg(any(test, feature = "test-support"))]
    test_did_overrides: RwLock<HashMap<String, (SpaceVerifyingKey, String)>>,
}

impl SpaceHostRuntime {
    pub fn new(pool: DbPool, config: SpaceHostConfig) -> Self {
        Self {
            pool,
            config,
            tid_counter: AtomicU64::new(0),
            did_cache: RwLock::new(HashMap::new()),
            #[cfg(any(test, feature = "test-support"))]
            test_did_overrides: RwLock::new(HashMap::new()),
        }
    }

    pub fn pool(&self) -> &DbPool {
        &self.pool
    }

    pub fn authority_did(&self) -> &str {
        &self.config.authority_did
    }

    pub fn space_signing_key(&self) -> SpaceSigningKey {
        SpaceSigningKey::P256 {
            signing_key: self.config.signing_key.clone(),
            kid: "#atproto".to_string(),
        }
    }

    pub fn authority_verifying_key(&self) -> SpaceVerifyingKey {
        SpaceVerifyingKey::P256(*self.config.signing_key.verifying_key())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn register_test_did_endpoint(
        &self,
        did: &str,
        verifying_key: &P256VerifyingKey,
        endpoint_url: &str,
    ) {
        let canonical = crate::identity::canonical_did(did).to_string();
        if let Ok(mut guard) = self.test_did_overrides.write() {
            guard.insert(
                canonical,
                (
                    SpaceVerifyingKey::P256(*verifying_key),
                    endpoint_url.trim_end_matches('/').to_string(),
                ),
            );
        }
    }

    pub fn mint_credential(
        &self,
        claims: &SpaceTokenClaims,
    ) -> Result<String, atproto_spaces::SpacesError> {
        mint_space_token(
            SpaceTokenKind::Credential,
            &self.space_signing_key(),
            claims,
        )
    }

    pub fn mint_service_jwt(&self, aud: &str, lxm: &str) -> Result<String, String> {
        let now = Utc::now().timestamp();
        let header = URL_SAFE_NO_PAD.encode(br##"{"alg":"ES256","typ":"JWT","kid":"#atproto"}"##);
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "iss": self.config.authority_did,
                "aud": aud,
                "lxm": lxm,
                "iat": now,
                "exp": now + 60,
                "jti": Uuid::new_v4().to_string(),
            }))
            .map_err(|e| e.to_string())?,
        );
        let signing_input = format!("{header}.{claims}");
        let sig: Signature = self.config.signing_key.sign(signing_input.as_bytes());
        let norm = sig.normalize_s().unwrap_or(sig);
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(norm.to_bytes())
        ))
    }

    /// Generate a strictly monotonic 13-character ATProto base32-sortable TID (`> prev_rev` if present).
    pub fn next_monotonic_tid(&self, now_sec: u64, prev_rev: Option<&str>) -> String {
        let bump = self.tid_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let mut micros = now_sec
            .saturating_mul(1_000_000)
            .saturating_add(bump % 1_000_000);
        if let Some(prev) = prev_rev.and_then(decode_tid_micros) {
            if micros <= prev {
                micros = prev.saturating_add(1);
            }
        }
        encode_tid_micros(micros, 0)
    }

    /// Resolve a DID's `#atproto` verification key + service endpoint URL in a `Send`-safe async context.
    pub async fn resolve_did_entry(
        &self,
        did_or_ref: &str,
        force_refresh: bool,
    ) -> Result<(SpaceVerifyingKey, String, bool), atproto_spaces::SpacesError> {
        let bare_did = crate::identity::canonical_did(did_or_ref).to_string();
        if bare_did == self.config.authority_did {
            let self_ep = std::env::var("SELF_ENDPOINT")
                .unwrap_or_else(|_| "https://chat.catbird.blue".to_string());
            return Ok((self.authority_verifying_key(), self_ep, false));
        }

        #[cfg(any(test, feature = "test-support"))]
        if let Some((vk, ep)) = self
            .test_did_overrides
            .read()
            .ok()
            .and_then(|m| m.get(&bare_did).cloned())
        {
            return Ok((vk, ep, true));
        }

        if !force_refresh {
            if let Some(cached) = self
                .did_cache
                .read()
                .ok()
                .and_then(|c| c.get(&bare_did).cloned())
            {
                if cached.fetched_at.elapsed() < Duration::from_secs(300) {
                    return Ok((cached.verifying_key, cached.endpoint_url, false));
                }
            }
        }

        let doc_url = if bare_did.starts_with("did:plc:") {
            let plc_base = std::env::var("PLC_DIRECTORY_URL")
                .unwrap_or_else(|_| "https://plc.directory".to_string());
            format!("{}/{}", plc_base.trim_end_matches('/'), bare_did)
        } else if bare_did.starts_with("did:web:") {
            crate::identity::did_web_document_url(&bare_did).ok_or_else(|| {
                atproto_spaces::SpacesError::DidResolution(format!("invalid did:web: {bare_did}"))
            })?
        } else {
            return Err(atproto_spaces::SpacesError::InvalidDid(bare_did));
        };

        let validated = validate_https_url_with_resolver(
            &doc_url,
            None,
            false,
            crate::push_gateway::ssrf::system_dns_resolve,
        )
        .map_err(|e| atproto_spaces::SpacesError::DidResolution(e.to_string()))?;

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .resolve_to_addrs(&validated.host, &validated.pinned_addrs)
            .build()
            .map_err(|e| atproto_spaces::SpacesError::DidResolution(e.to_string()))?;

        let resp = client
            .get(&validated.effective_url)
            .send()
            .await
            .map_err(|e| atproto_spaces::SpacesError::DidResolution(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(atproto_spaces::SpacesError::DidResolution(format!(
                "DID document HTTP {}",
                resp.status().as_u16()
            )));
        }
        let doc: Value = resp
            .json()
            .await
            .map_err(|e| atproto_spaces::SpacesError::DidResolution(e.to_string()))?;

        let vk = extract_atproto_verifying_key(&doc, &bare_did)?;
        let fragment = did_or_ref
            .split_once('#')
            .map(|(_, f)| format!("#{f}"))
            .unwrap_or_else(|| "#atproto_pds".to_string());
        let ep = extract_service_endpoint(&doc, &fragment)
            .or_else(|| extract_service_endpoint(&doc, "#atproto_pds"))
            .or_else(|| extract_service_endpoint(&doc, "#atproto_sync"))
            .unwrap_or_default();

        if let Ok(mut guard) = self.did_cache.write() {
            guard.insert(
                bare_did,
                CachedDidEntry {
                    verifying_key: vk.clone(),
                    endpoint_url: ep.clone(),
                    fetched_at: Instant::now(),
                },
            );
        }
        Ok((vk, ep, false))
    }

    /// `Send`-safe wrapper around `atproto_spaces::tokens::verify_space_token` with one-shot key refresh.
    pub async fn verify_space_token_send(
        &self,
        kind: SpaceTokenKind,
        jwt: &str,
        now_sec: u64,
    ) -> Result<SpaceTokenClaims, atproto_spaces::SpacesError> {
        let (_kid, untrusted) = inspect_untrusted_space_token(kind, jwt, now_sec)?;
        let (vk, _, _) = self.resolve_did_entry(&untrusted.iss, false).await?;
        let resolver = SinglePreResolvedKey(vk);
        match futures::executor::block_on(verify_space_token(kind, jwt, &resolver, now_sec)) {
            Ok(claims) => Ok(claims),
            Err(_) => {
                let (refreshed_vk, _, _) = self.resolve_did_entry(&untrusted.iss, true).await?;
                let refreshed = SinglePreResolvedKey(refreshed_vk);
                futures::executor::block_on(verify_space_token(kind, jwt, &refreshed, now_sec))
            }
        }
    }
}

struct SinglePreResolvedKey(SpaceVerifyingKey);

#[async_trait::async_trait(?Send)]
impl SpaceKeyResolver for SinglePreResolvedKey {
    async fn resolve_atproto_key(
        &self,
        _did_or_issuer: &str,
        _force_refresh: bool,
    ) -> atproto_spaces::Result<SpaceVerifyingKey> {
        Ok(self.0.clone())
    }
}

fn extract_atproto_verifying_key(
    doc: &Value,
    bare_did: &str,
) -> Result<SpaceVerifyingKey, atproto_spaces::SpacesError> {
    let methods = doc
        .get("verificationMethod")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            atproto_spaces::SpacesError::DidResolution("missing verificationMethod".into())
        })?;
    let full_id = format!("{bare_did}#atproto");
    let method = methods
        .iter()
        .find(|m| {
            matches!(
                m.get("id").and_then(Value::as_str),
                Some("#atproto") | Some(_) if m.get("id").and_then(Value::as_str) == Some("#atproto")
                    || m.get("id").and_then(Value::as_str) == Some(full_id.as_str())
            )
        })
        .ok_or_else(|| {
            atproto_spaces::SpacesError::DidResolution("missing #atproto verificationMethod".into())
        })?;
    let multibase_str = method
        .get("publicKeyMultibase")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            atproto_spaces::SpacesError::DidResolution("missing publicKeyMultibase".into())
        })?;
    let (_, raw) = multibase::decode(multibase_str)
        .map_err(|e| atproto_spaces::SpacesError::DidResolution(e.to_string()))?;
    if raw.starts_with(&[0x80, 0x24]) && raw.len() == 35 {
        let vk = P256VerifyingKey::from_sec1_bytes(&raw[2..])
            .map_err(|e| atproto_spaces::SpacesError::DidResolution(e.to_string()))?;
        Ok(SpaceVerifyingKey::P256(vk))
    } else if raw.starts_with(&[0xe7, 0x01]) && raw.len() == 35 {
        let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&raw[2..])
            .map_err(|e| atproto_spaces::SpacesError::DidResolution(e.to_string()))?;
        Ok(SpaceVerifyingKey::K256(vk))
    } else {
        Err(atproto_spaces::SpacesError::DidResolution(
            "unsupported #atproto multicodec".into(),
        ))
    }
}

fn extract_service_endpoint(doc: &Value, fragment: &str) -> Option<String> {
    let services = doc.get("service")?.as_array()?;
    for svc in services {
        let id = svc.get("id")?.as_str()?;
        if id == fragment || id.ends_with(fragment) {
            if let Some(ep) = svc.get("serviceEndpoint").and_then(Value::as_str) {
                return Some(ep.trim_end_matches('/').to_string());
            }
        }
    }
    None
}

const TID_CHARS: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

pub(crate) fn encode_tid_micros(micros: u64, clock_id: u16) -> String {
    let val = ((micros & 0x1fff_ffff_ffff_ffff) << 10) | u64::from(clock_id & 0x03ff);
    let mut out = [b'2'; 13];
    for i in (0..13).rev() {
        let shift = (12 - i) * 5;
        let idx = ((val >> shift) & 0x1f) as usize;
        out[i] = TID_CHARS[idx];
    }
    String::from_utf8(out.to_vec()).expect("ASCII TID")
}

pub(crate) fn decode_tid_micros(tid: &str) -> Option<u64> {
    if tid.len() != 13 {
        return None;
    }
    let bytes = tid.as_bytes();
    if bytes[0] > b'j' {
        return None;
    }
    let mut val = 0_u64;
    for &b in bytes {
        let digit = match b {
            b'2'..=b'7' => u64::from(b - b'2'),
            b'a'..=b'z' => u64::from(b - b'a' + 6),
            _ => return None,
        };
        val = (val << 5) | digit;
    }
    Some(val >> 10)
}
