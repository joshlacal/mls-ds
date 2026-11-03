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
use chrono::{DateTime, Utc};
use p256::ecdsa::{
    signature::Signer, Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use serde_json::{json, Value};

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
    #[cfg(any(test, feature = "test-support"))]
    test_did_overrides: RwLock<HashMap<String, (SpaceVerifyingKey, String)>>,
}

impl SpaceHostRuntime {
    pub fn new(pool: DbPool, config: SpaceHostConfig) -> Self {
        Self {
            pool,
            config,
            clock: Arc::new(crate::sim_hooks::SystemDsClock),
            tid_counter: AtomicU64::new(0),
            did_cache: RwLock::new(HashMap::new()),
            #[cfg(any(test, feature = "test-support"))]
            test_did_overrides: RwLock::new(HashMap::new()),
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
        let now = crate::sim_hooks::current_utc().timestamp();
        let jti = crate::sim_hooks::mint_outbound_jti_uuid_v4(
            b"space_host.service_jwt",
            &[aud.as_bytes(), lxm.as_bytes()],
        );
        let header = URL_SAFE_NO_PAD.encode(br##"{"alg":"ES256","typ":"JWT","kid":"#atproto"}"##);
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "iss": self.config.authority_did,
                "aud": aud,
                "lxm": lxm,
                "iat": now,
                "exp": now + 60,
                "jti": jti.to_string(),
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

        let resp = crate::sim_hooks::send_reqwest(client.get(&validated.effective_url))
            .await
            .map_err(atproto_spaces::SpacesError::DidResolution)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim_hooks::{with_ds_clock, ManualDsClock};

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
            "at://did:web:authority.example/space/blue.catbird.labyrinth.conversation/test-0";
        let credential_kid = atproto_spaces::kem::encode_p256_did_key(&p256::PublicKey::from(
            runtime.config.signing_key.verifying_key(),
        ));
        let mint = || {
            let claims = SpaceTokenClaims {
                iss: runtime.authority_did().to_string(),
                sub: space_uri.to_string(),
                aud: None,
                iat: now.timestamp() as u64,
                exp: now.timestamp() as u64 + 600,
                jti: runtime.mint_credential_jti(space_uri, "did:web:writer.example"),
                cnf_kid: Some(credential_kid.clone()),
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
