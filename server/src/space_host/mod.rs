//! Option A Conversation `SpaceHost` (`atproto#5187` / Spec §6.1, §6.2, §6.5).
//!
//! Each sequencing `mls-ds` (`did:web` or `did:plc`) acts as the Space Authority and
//! Space Host for conversation Spaces (`at:space/{authority_did}/blue.catbird.labyrinth.conversation/{conversation_id}-{generation}`).
//!
//! Key security & federation invariants:
//! - Zero `NOT c.is_remote` local-only guards anywhere in `space_host`.
//! - `authorizeSpaceSync` and `notifyRepoUpdate` require `status = 'active'` in `chat.participants`
//!   (excluding `'pending'` / declined `C33` direct-request targets and `'left'` / `'removed'` ex-members).
//! - `listWriters` includes historical writers with `status IN ('active', 'left', 'removed')` in
//!   ascending `spaceRev` order (plus `#repoRemoved` tombstones within 72h) while strictly excluding
//!   `'pending'` `C33` targets and deleted accounts.
//! - Single-use 60s delegation `jti` replay cache (`chat.space_delegation_jtis`) and 10m credential
//!   `jti` ledger (`chat.space_credential_jtis`).
//! - Post-commit revocation & Space-update/deletion webhook fan-out (`M-F04`: never inside an open SQL transaction).

pub mod handlers;
pub mod revocation_fanout;
pub(crate) mod tokens;
mod wire;
#[cfg(feature = "test-support")]
pub use wire::add_inventory_entry;

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};

use axum::Router;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use p256::ecdsa::{
    signature::Signer, Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p256::SecretKey as P256SecretKey;
use petrel_crypto::{ATProtoJWTVerificationKey as SpaceVerifyingKey, ATProtoKeyCurve, PublicKey};
use petrel_spaces::{SigningKeyPair, SpaceError, SpaceRef};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tokens::{ParsedToken, SpaceTokenClaims, SpaceTokenKind};

use crate::{push_gateway::ssrf::validate_https_url_with_resolver, storage::DbPool};

pub use handlers::space_host_router;

/// JOSE `typ` of the authority's signed refusal of a Space credential. It names a token the
/// same `#atproto` key signs for no other purpose (credentials, service auth).
pub const SPACE_DENIAL_JWT_TYP: &str = "catbird-space-denial+jwt";
/// The one refusal the authority signs: the requester is not an active member of the Space.
pub const SPACE_DENIAL_REASON: &str = "notActiveMember";
/// A refusal answers one credential request and is removal proof only this long.
pub const SPACE_DENIAL_LIFETIME_SECS: u64 = 60;

#[derive(Debug, Clone)]
pub struct SpaceHostConfig {
    pub authority_did: String,
    pub signing_key: P256SigningKey,
    kem_key: P256SecretKey,
    inventory_cursor_key: [u8; 32],
}

impl SpaceHostConfig {
    pub fn new(authority_did: String, signing_key: P256SigningKey) -> Self {
        let kem_key = P256SecretKey::from_slice(&signing_key.to_bytes())
            .expect("a valid P-256 signing scalar is a valid P-256 KEM scalar");
        let mut cursor_hasher = Sha256::new();
        cursor_hasher.update(b"catbird-space-inventory-cursor-v1");
        cursor_hasher.update(signing_key.to_bytes());
        let inventory_cursor_key = cursor_hasher.finalize().into();
        Self {
            authority_did: crate::identity::canonical_did(&authority_did).to_string(),
            signing_key,
            kem_key,
            inventory_cursor_key,
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

#[derive(Debug, Clone)]
pub(crate) struct SimCachedDidEntry {
    verifying_key: SpaceVerifyingKey,
    endpoint_url: String,
    fetched_at: DateTime<Utc>,
}

pub struct SpaceHostRuntime {
    pool: DbPool,
    config: SpaceHostConfig,
    clock: Arc<dyn crate::sim_hooks::DsClock>,
    tid_counter: AtomicU64,
    did_cache: RwLock<HashMap<String, CachedDidEntry>>,
    client_key_cache: RwLock<HashMap<String, (SpaceVerifyingKey, Instant)>>,
    #[cfg(any(test, feature = "test-support"))]
    test_did_overrides: RwLock<HashMap<String, (SpaceVerifyingKey, String)>>,
    #[cfg(any(test, feature = "test-support"))]
    test_client_keys: RwLock<HashMap<String, SpaceVerifyingKey>>,
}

impl SpaceHostRuntime {
    pub fn new(pool: DbPool, config: SpaceHostConfig) -> Self {
        Self {
            pool,
            config,
            clock: Arc::new(crate::sim_hooks::SystemDsClock),
            tid_counter: AtomicU64::new(0),
            did_cache: RwLock::new(HashMap::new()),
            client_key_cache: RwLock::new(HashMap::new()),
            #[cfg(any(test, feature = "test-support"))]
            test_did_overrides: RwLock::new(HashMap::new()),
            #[cfg(any(test, feature = "test-support"))]
            test_client_keys: RwLock::new(HashMap::new()),
        }
    }

    /// Set the clock scoped across every request served by [`space_host_router`].
    pub fn with_clock(mut self, clock: Arc<dyn crate::sim_hooks::DsClock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn clock(&self) -> &Arc<dyn crate::sim_hooks::DsClock> {
        &self.clock
    }

    pub fn pool(&self) -> &DbPool {
        &self.pool
    }

    pub fn authority_did(&self) -> &str {
        &self.config.authority_did
    }

    pub(crate) fn kem_key(&self) -> &P256SecretKey {
        &self.config.kem_key
    }

    pub(crate) fn inventory_cursor_key(&self) -> &[u8; 32] {
        &self.config.inventory_cursor_key
    }

    pub fn authority_verifying_key(&self) -> SpaceVerifyingKey {
        p256_verification_key(self.config.signing_key.verifying_key())
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
                    p256_verification_key(verifying_key),
                    endpoint_url.trim_end_matches('/').to_string(),
                ),
            );
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn register_test_client_attestation_key(
        &self,
        client_id_url: &str,
        kid: &str,
        verifying_key: &P256VerifyingKey,
    ) {
        if let Ok(mut guard) = self.test_client_keys.write() {
            guard.insert(
                format!("{client_id_url}#{kid}"),
                p256_verification_key(verifying_key),
            );
        }
    }

    fn mint_credential_jti(&self, space_uri: &str, writer_did: &str) -> String {
        crate::sim_hooks::mint_outbound_jti_uuid_v4(
            b"space_host.credential",
            &[
                self.authority_did().as_bytes(),
                space_uri.as_bytes(),
                writer_did.as_bytes(),
            ],
        )
        .to_string()
    }

    pub(crate) fn mint_credential(&self, claims: &SpaceTokenClaims) -> Result<String, SpaceError> {
        let key = SigningKeyPair::from_p256_bytes(&self.config.signing_key.to_bytes())?;
        petrel_spaces::mint_credential_token(
            &key,
            &petrel_core::Did::parse(&claims.iss)
                .map_err(|e| SpaceError::InvalidDid(e.to_string()))?,
            &petrel_spaces::parse_space_ref(&claims.sub)?,
            claims.cnf_kid().ok_or(SpaceError::InvalidTokenFormat)?,
            claims
                .iat
                .try_into()
                .map_err(|_| SpaceError::InvalidTokenFormat)?,
            claims
                .exp
                .try_into()
                .map_err(|_| SpaceError::InvalidTokenFormat)?,
            Some(&claims.jti),
            Some("#atproto"),
        )
    }

    pub fn mint_service_jwt(&self, aud: &str, lxm: &str) -> Result<String, String> {
        let now = crate::sim_hooks::current_utc().timestamp();
        let jti = crate::sim_hooks::mint_outbound_jti_uuid_v4(
            b"space_host.service_jwt",
            &[aud.as_bytes(), lxm.as_bytes()],
        );
        self.sign_compact_jws(
            r##"{"alg":"ES256","typ":"JWT","kid":"#atproto"}"##,
            &json!({
                "iss": self.config.authority_did,
                "aud": aud,
                "lxm": lxm,
                "iat": now,
                "exp": now + 60,
                "jti": jti.to_string(),
            }),
        )
    }

    /// Sign the refusal of one credential request: `requester` is not an active member of
    /// `space_uri` (conversation `conversation_id`, `generation`, MLS `group_id`). `cnf.kid` is
    /// the request's fresh proof-of-possession key, so the refusal answers that request only.
    pub(crate) fn mint_space_denial(
        &self,
        space_uri: &str,
        requester: &str,
        credential_kid: &str,
        coordinates: (uuid::Uuid, i64, &[u8]),
        now_sec: u64,
    ) -> Result<String, String> {
        let (conversation_id, generation, group_id) = coordinates;
        let jti = crate::sim_hooks::mint_outbound_jti_uuid_v4(
            b"space_host.denial",
            &[
                self.authority_did().as_bytes(),
                space_uri.as_bytes(),
                requester.as_bytes(),
                credential_kid.as_bytes(),
            ],
        );
        self.sign_compact_jws(
            &format!(r##"{{"alg":"ES256","typ":"{SPACE_DENIAL_JWT_TYP}","kid":"#atproto"}}"##),
            &json!({
                "iss": self.authority_did(),
                "sub": space_uri,
                "aud": requester,
                "iat": now_sec,
                "exp": now_sec + SPACE_DENIAL_LIFETIME_SECS,
                "jti": jti.to_string(),
                "cnf": { "kid": credential_kid },
                "conversationId": conversation_id,
                "generation": generation,
                "groupId": hex::encode(group_id),
                "reason": SPACE_DENIAL_REASON,
            }),
        )
    }

    /// Compact low-S ES256 JWS of `header` (exact JSON) and `claims` under the `#atproto` key.
    fn sign_compact_jws(&self, header: &str, claims: &Value) -> Result<String, String> {
        let header = URL_SAFE_NO_PAD.encode(header);
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|e| e.to_string())?);
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
    ) -> Result<(SpaceVerifyingKey, String, bool), SpaceError> {
        let bare_did = crate::identity::canonical_did(did_or_ref).to_string();
        if bare_did == self.config.authority_did {
            #[cfg(feature = "sim")]
            if let Some(hooks) = crate::sim_hooks::active_sim_ds() {
                return Ok((
                    self.authority_verifying_key(),
                    hooks.self_endpoint.clone(),
                    false,
                ));
            }
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

        let sim_clock = crate::sim_hooks::active_scoped_clock()
            .filter(|clock| clock.is_deterministic())
            .or_else(|| {
                self.clock
                    .is_deterministic()
                    .then(|| Arc::clone(&self.clock))
            });
        if !force_refresh {
            if let Some(clock) = &sim_clock {
                let cached = clock
                    .simulation_counters()
                    .expect("deterministic clocks own simulation counters")
                    .space_did_cache
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(self.authority_did())
                    .and_then(|cache| cache.get(&bare_did))
                    .cloned();
                if let Some(cached) = cached {
                    if (clock.now_utc() - cached.fetched_at)
                        .to_std()
                        .is_ok_and(|age| age < Duration::from_secs(300))
                    {
                        return Ok((cached.verifying_key, cached.endpoint_url, false));
                    }
                }
            } else if let Some(cached) = self
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
                SpaceError::DidResolutionFailed(format!("invalid did:web: {bare_did}"))
            })?
        } else {
            return Err(SpaceError::InvalidDid(bare_did));
        };

        let validated = validate_https_url_with_resolver(
            &doc_url,
            None,
            false,
            crate::push_gateway::ssrf::system_dns_resolve,
        )
        .map_err(|e| SpaceError::DidResolutionFailed(e.to_string()))?;

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .resolve_to_addrs(&validated.host, &validated.pinned_addrs)
            .build()
            .map_err(|e| SpaceError::DidResolutionFailed(e.to_string()))?;

        let resp = crate::sim_hooks::send_reqwest(client.get(&validated.effective_url))
            .await
            .map_err(SpaceError::DidResolutionFailed)?;
        if !resp.status().is_success() {
            return Err(SpaceError::DidResolutionFailed(format!(
                "DID document HTTP {}",
                resp.status().as_u16()
            )));
        }
        let doc: Value = resp
            .json()
            .await
            .map_err(|e| SpaceError::DidResolutionFailed(e.to_string()))?;

        let vk = extract_atproto_verifying_key(&doc, &bare_did)?;
        let fragment = did_or_ref
            .split_once('#')
            .map(|(_, f)| format!("#{f}"))
            .unwrap_or_else(|| "#atproto_pds".to_string());
        let ep = extract_service_endpoint(&doc, &fragment)
            .or_else(|| extract_service_endpoint(&doc, "#atproto_pds"))
            .or_else(|| extract_service_endpoint(&doc, "#atproto_sync"))
            .unwrap_or_default();

        if let Some(clock) = sim_clock {
            clock
                .simulation_counters()
                .expect("deterministic clocks own simulation counters")
                .space_did_cache
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .entry(self.authority_did().to_string())
                .or_default()
                .insert(
                    bare_did,
                    SimCachedDidEntry {
                        verifying_key: vk.clone(),
                        endpoint_url: ep.clone(),
                        fetched_at: clock.now_utc(),
                    },
                );
        } else if let Ok(mut guard) = self.did_cache.write() {
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

    async fn resolve_client_attestation_key(
        &self,
        client_id_url: &str,
        kid: &str,
        force_refresh: bool,
    ) -> Result<SpaceVerifyingKey, SpaceError> {
        let cache_key = format!("{client_id_url}#{kid}");

        #[cfg(any(test, feature = "test-support"))]
        if let Some(vk) = self
            .test_client_keys
            .read()
            .ok()
            .and_then(|m| m.get(&cache_key).cloned())
        {
            return Ok(vk);
        }

        if !force_refresh {
            if let Some((vk, fetched_at)) = self
                .client_key_cache
                .read()
                .ok()
                .and_then(|m| m.get(&cache_key).cloned())
            {
                if fetched_at.elapsed() < Duration::from_secs(300) {
                    return Ok(vk);
                }
            }
        }

        let allow_loopback = revocation_fanout::allow_loopback_space_endpoint(client_id_url);
        let validated = validate_https_url_with_resolver(
            client_id_url,
            None,
            allow_loopback,
            crate::push_gateway::ssrf::system_dns_resolve,
        )
        .map_err(|e| SpaceError::Unauthorized(e.to_string()))?;

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .resolve_to_addrs(&validated.host, &validated.pinned_addrs)
            .build()
            .map_err(|e| SpaceError::Unauthorized(e.to_string()))?;

        let resp = crate::sim_hooks::send_reqwest(client.get(&validated.effective_url))
            .await
            .map_err(SpaceError::Unauthorized)?;
        if !resp.status().is_success() {
            return Err(SpaceError::Unauthorized(format!(
                "client metadata HTTP {}",
                resp.status().as_u16()
            )));
        }
        let meta: Value = resp
            .json()
            .await
            .map_err(|e| SpaceError::Unauthorized(e.to_string()))?;
        if meta.get("client_id").and_then(Value::as_str) != Some(client_id_url) {
            return Err(SpaceError::Unauthorized(
                "client metadata client_id mismatch".into(),
            ));
        }

        let keys_val = if let Some(keys) = meta
            .get("jwks")
            .and_then(|j| j.get("keys"))
            .and_then(Value::as_array)
        {
            keys.clone()
        } else if let Some(jwks_uri) = meta.get("jwks_uri").and_then(Value::as_str) {
            let allow_jwks_loopback = revocation_fanout::allow_loopback_space_endpoint(jwks_uri);
            let jwks_validated = validate_https_url_with_resolver(
                jwks_uri,
                None,
                allow_jwks_loopback,
                crate::push_gateway::ssrf::system_dns_resolve,
            )
            .map_err(|e| SpaceError::Unauthorized(e.to_string()))?;
            let jwks_client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .resolve_to_addrs(&jwks_validated.host, &jwks_validated.pinned_addrs)
                .build()
                .map_err(|e| SpaceError::Unauthorized(e.to_string()))?;
            let jwks_resp =
                crate::sim_hooks::send_reqwest(jwks_client.get(&jwks_validated.effective_url))
                    .await
                    .map_err(SpaceError::Unauthorized)?;
            if !jwks_resp.status().is_success() {
                return Err(SpaceError::Unauthorized(format!(
                    "client jwks_uri HTTP {}",
                    jwks_resp.status().as_u16()
                )));
            }
            let jwks_doc: Value = jwks_resp
                .json()
                .await
                .map_err(|e| SpaceError::Unauthorized(e.to_string()))?;
            jwks_doc
                .get("keys")
                .and_then(Value::as_array)
                .cloned()
                .ok_or_else(|| {
                    SpaceError::Unauthorized("client jwks_uri missing keys array".into())
                })?
        } else {
            return Err(SpaceError::Unauthorized(
                "client metadata missing jwks and jwks_uri".into(),
            ));
        };

        let vk = extract_client_jwk_verifying_key(&keys_val, kid)?;
        if let Ok(mut guard) = self.client_key_cache.write() {
            guard.insert(cache_key, (vk.clone(), Instant::now()));
        }
        Ok(vk)
    }

    /// Resolve the issuer key once and refresh it once on a signature mismatch.
    pub(crate) async fn verify_space_token_send(
        &self,
        kind: SpaceTokenKind,
        jwt: &str,
        now: u64,
    ) -> Result<SpaceTokenClaims, SpaceError> {
        let token = ParsedToken::parse(kind, jwt, now)?;
        for refresh in [false, true] {
            let key = if kind == SpaceTokenKind::ClientAttestation {
                self.resolve_client_attestation_key(
                    &token.claims.iss,
                    token
                        .header
                        .kid
                        .as_deref()
                        .ok_or(SpaceError::InvalidTokenFormat)?,
                    refresh,
                )
                .await?
            } else {
                self.resolve_did_entry(&token.claims.iss, refresh).await?.0
            };
            if token.verify(&key) {
                return Ok(token.claims);
            }
        }
        Err(SpaceError::InvalidSignature)
    }
}

fn extract_client_jwk_verifying_key(
    keys: &[Value],
    expected_kid: &str,
) -> Result<SpaceVerifyingKey, SpaceError> {
    for jwk in keys {
        if jwk.get("kid").and_then(Value::as_str) != Some(expected_kid) {
            continue;
        }
        if jwk.get("kty").and_then(Value::as_str) != Some("EC")
            || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
        {
            return Err(SpaceError::Unauthorized(
                "client attestation JWK must be EC P-256".into(),
            ));
        }
        if let Some(alg) = jwk.get("alg").and_then(Value::as_str) {
            if alg != "ES256" {
                return Err(SpaceError::Unauthorized(format!(
                    "unsupported client attestation JWK alg {alg}"
                )));
            }
        }
        let x_b64 = jwk
            .get("x")
            .and_then(Value::as_str)
            .ok_or_else(|| SpaceError::Unauthorized("JWK missing x".into()))?;
        let y_b64 = jwk
            .get("y")
            .and_then(Value::as_str)
            .ok_or_else(|| SpaceError::Unauthorized("JWK missing y".into()))?;
        let x = URL_SAFE_NO_PAD
            .decode(x_b64)
            .map_err(|e| SpaceError::Unauthorized(e.to_string()))?;
        let y = URL_SAFE_NO_PAD
            .decode(y_b64)
            .map_err(|e| SpaceError::Unauthorized(e.to_string()))?;
        if x.len() != 32 || y.len() != 32 {
            return Err(SpaceError::Unauthorized(
                "P-256 JWK coordinates must be 32 bytes".into(),
            ));
        }
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(&x);
        sec1[33..65].copy_from_slice(&y);
        let vk = P256VerifyingKey::from_sec1_bytes(&sec1)
            .map_err(|e| SpaceError::Unauthorized(e.to_string()))?;
        return Ok(p256_verification_key(&vk));
    }
    Err(SpaceError::Unauthorized(format!(
        "client metadata JWKS has no key matching kid {expected_kid}"
    )))
}

pub(crate) fn p256_verification_key(key: &P256VerifyingKey) -> SpaceVerifyingKey {
    let encoded = key.to_encoded_point(true);
    let public_key = PublicKey::from_sec1(ATProtoKeyCurve::P256, encoded.as_bytes())
        .expect("validated P-256 point");
    SpaceVerifyingKey::from_public_key(&public_key)
}

fn extract_atproto_verifying_key(
    doc: &Value,
    bare_did: &str,
) -> Result<SpaceVerifyingKey, SpaceError> {
    let methods = doc
        .get("verificationMethod")
        .and_then(Value::as_array)
        .ok_or_else(|| SpaceError::DidResolutionFailed("missing verificationMethod".into()))?;
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
            SpaceError::DidResolutionFailed("missing #atproto verificationMethod".into())
        })?;
    let multibase_str = method
        .get("publicKeyMultibase")
        .and_then(Value::as_str)
        .ok_or_else(|| SpaceError::DidResolutionFailed("missing publicKeyMultibase".into()))?;
    let (_, raw) = multibase::decode(multibase_str)
        .map_err(|e| SpaceError::DidResolutionFailed(e.to_string()))?;
    if raw.starts_with(&[0x80, 0x24]) && raw.len() == 35 {
        let vk = P256VerifyingKey::from_sec1_bytes(&raw[2..])
            .map_err(|e| SpaceError::DidResolutionFailed(e.to_string()))?;
        Ok(p256_verification_key(&vk))
    } else if raw.starts_with(&[0xe7, 0x01]) && raw.len() == 35 {
        let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&raw[2..])
            .map_err(|e| SpaceError::DidResolutionFailed(e.to_string()))?;
        SpaceVerifyingKey::from_secp256k1_public_key(vk.to_encoded_point(true).as_bytes())
            .map_err(|e| SpaceError::DidResolutionFailed(e.to_string()))
    } else {
        Err(SpaceError::DidResolutionFailed(
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

pub(crate) fn parse_strict_space_ref(raw: &str) -> Option<SpaceRef> {
    SpaceRef::parse(raw).ok()
}

pub fn conversation_space_ref(
    authority: &str,
    key: &str,
) -> Result<SpaceRef, petrel_core::SyntaxError> {
    SpaceRef::from_parts(
        &petrel_core::Did::parse(authority)?,
        &petrel_core::Nsid::parse("blue.catbird.labyrinth.conversation")?,
        &petrel_core::RecordKey::parse(key)?,
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim_hooks::{with_ds_clock, ManualDsClock};

    #[test]
    fn strict_space_ref_accepts_only_the_at_space_form() {
        let space = "at:space/did:web:authority.example/blue.catbird.labyrinth.conversation/c-0";
        let parsed = parse_strict_space_ref(space).expect("canonical Space ref");
        assert_eq!(parsed.space_did().as_str(), "did:web:authority.example");
        assert_eq!(
            parsed.space_type().as_str(),
            "blue.catbird.labyrinth.conversation"
        );
        assert_eq!(parsed.skey().as_str(), "c-0");
        for rejected in [
            "at://did:web:authority.example/space/blue.catbird.labyrinth.conversation/c-0",
            "at:space/authority.example/blue.catbird.labyrinth.conversation/c-0",
            "at-space://did:web:authority.example/blue.catbird.labyrinth.conversation/c-0",
            "at://space/did:web:authority.example/blue.catbird.labyrinth.conversation/c-0",
            "at://did:web:authority.example/com.atproto.space.space/blue.catbird.labyrinth.conversation:c-0",
            "at:space/did:web:authority.example/blue.catbird.labyrinth.conversation/c-0/did:plc:a/b.c.d/3l2a",
            "at:space/did:web:authority.example/blue.catbird.labyrinth.conversation/c-0/",
        ] {
            assert!(parse_strict_space_ref(rejected).is_none(), "{rejected}");
        }
    }

    #[tokio::test]
    async fn space_credential_jtis_and_tokens_replay_per_clock() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://127.0.0.1/unused_space_credential_test")
            .unwrap();
        let runtime = SpaceHostRuntime::new(
            pool,
            SpaceHostConfig::new(
                "did:web:authority.example".to_string(),
                P256SigningKey::from_slice(&[3; 32]).unwrap(),
            ),
        );
        let now = DateTime::from_timestamp(1_600_000_000, 0).unwrap();
        let clock = Arc::new(ManualDsClock::new(now));
        let space_uri =
            "at:space/did:web:authority.example/blue.catbird.labyrinth.conversation/test-0";
        let credential_kid = petrel_spaces::encode_p256_did_key(
            runtime
                .config
                .signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap();
        let mint = || {
            let claims = SpaceTokenClaims {
                iss: runtime.authority_did().to_string(),
                sub: space_uri.to_string(),
                aud: None,
                iat: now.timestamp() as u64,
                exp: now.timestamp() as u64 + 600,
                jti: runtime.mint_credential_jti(space_uri, "did:web:writer.example"),
                cnf: Some(petrel_spaces::CnfClaim {
                    kid: credential_kid.clone(),
                }),
            };
            let jwt = runtime.mint_credential(&claims).unwrap();
            (claims.jti, jwt)
        };
        let baseline = with_ds_clock(clock.clone(), mint);
        assert_ne!(with_ds_clock(clock.clone(), mint), baseline);
        clock.reset_counters();
        assert_eq!(with_ds_clock(clock, mint), baseline);
        assert_eq!(
            with_ds_clock(Arc::new(ManualDsClock::new(now)), mint),
            baseline
        );
        let verified = runtime
            .verify_space_token_send(
                SpaceTokenKind::Credential,
                &baseline.1,
                now.timestamp() as u64,
            )
            .await
            .unwrap();
        assert_eq!(verified.jti, baseline.0);
    }

    #[cfg(feature = "sim")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn did_resolution_http_calls_are_isolated_per_run_and_follow_sim_ttl() {
        use crate::sim_hooks::{scope_ds_clock, scope_sim_ds, SimDsHooks};

        const TARGET: &str = "did:web:scoped-space-cache.example";
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://127.0.0.1/unused_space_cache_test")
            .unwrap();
        let runtime = Arc::new(SpaceHostRuntime::new(
            pool,
            SpaceHostConfig::new(
                "did:web:authority.example".to_string(),
                P256SigningKey::from_slice(&[3; 32]).unwrap(),
            ),
        ));
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let spawn_run = |key_byte: u8| {
            let runtime = Arc::clone(&runtime);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                let clock = Arc::new(ManualDsClock::new(
                    DateTime::from_timestamp(1_600_000_000, 0).unwrap(),
                ));
                let key = P256SigningKey::from_slice(&[key_byte; 32]).unwrap();
                let endpoint = format!("https://writer-{key_byte}.example");
                let document = serde_json::to_vec(&json!({
                    "id": TARGET,
                    "verificationMethod": [{
                        "id": "#atproto",
                        "type": "Multikey",
                        "controller": TARGET,
                        "publicKeyMultibase": crate::identity::did_doc::encode_p256_multikey(key.verifying_key()),
                    }],
                    "service": [{
                        "id": "#atproto_pds",
                        "type": "AtprotoPersonalDataServer",
                        "serviceEndpoint": endpoint,
                    }],
                }))
                .unwrap();
                let calls = Arc::new(AtomicU64::new(0));
                let transport_calls = Arc::clone(&calls);
                let hooks = Arc::new(SimDsHooks {
                    service_did: runtime.authority_did().to_string(),
                    self_endpoint: "https://authority.example".to_string(),
                    signing_key_pem: None,
                    group_relay_hmac_secret: None,
                    http_transport: Arc::new(move |_| {
                        transport_calls.fetch_add(1, Ordering::SeqCst);
                        let body = document.clone();
                        Box::pin(async move {
                            Ok(http::Response::builder()
                                .header("content-type", "application/json")
                                .body(body)
                                .unwrap())
                        })
                    }),
                    dns_resolver: Arc::new(|_| Ok(vec!["93.184.216.34".parse().unwrap()])),
                    retain_application_ciphertext: false,
                });
                scope_ds_clock(
                    clock.clone(),
                    scope_sim_ds(hooks, async {
                        let auth = crate::auth::shared_auth_middleware();
                        barrier.wait().await;
                        for _ in 0..2 {
                            let doc = auth.resolve_did(TARGET).await.unwrap();
                            assert_eq!(doc.service.unwrap()[0].service_endpoint, endpoint);
                            let (_, ep, _) =
                                runtime.resolve_did_entry(TARGET, false).await.unwrap();
                            assert_eq!(ep, endpoint);
                        }
                        assert_eq!(calls.load(Ordering::SeqCst), 2, "one miss per cache");
                        tokio::task::yield_now().await;
                        let (_, ep, _) = runtime.resolve_did_entry(TARGET, false).await.unwrap();
                        assert_eq!(
                            ep, endpoint,
                            "another worker must not replace this run's key"
                        );
                        assert_eq!(calls.load(Ordering::SeqCst), 2);
                        clock.advance(chrono::TimeDelta::seconds(300));
                        auth.resolve_did(TARGET).await.unwrap();
                        runtime.resolve_did_entry(TARGET, false).await.unwrap();
                        assert_eq!(
                            calls.load(Ordering::SeqCst),
                            4,
                            "sim time expires both caches"
                        );
                        runtime.resolve_did_entry(TARGET, true).await.unwrap();
                        assert_eq!(
                            calls.load(Ordering::SeqCst),
                            5,
                            "forced key refresh still resolves"
                        );
                        clock.reset_counters();
                        auth.resolve_did(TARGET).await.unwrap();
                        runtime.resolve_did_entry(TARGET, false).await.unwrap();
                        assert_eq!(calls.load(Ordering::SeqCst), 7, "reset starts cold");
                    }),
                )
                .await;
            })
        };
        let (first, second) = tokio::join!(spawn_run(5), spawn_run(7));
        first.unwrap();
        second.unwrap();
        assert!(runtime.did_cache.read().unwrap().is_empty());
    }
}
