//! Wave-2 (`W2-D`) unified integration suite covering:
//! 1. `D-2` Multi-device sibling enrollment approval (`pending_approval` -> `approveDevice`,
//!    `CATBIRD-CHAT-DEVICE-APPROVE\0`, `#deviceView` `deviceName` / coarse UTC-day `lastActiveAt` /
//!    `dormantAt`, fail-closed admission on unapproved devices across chat + Space relay +
//!    Labyrinth, `getDevices` exclusion vs `getOwnDevices` inclusion, idempotent replay,
//!    `DeviceAlreadyActive`, and direct `pending_approval -> revoked` sibling revocation).
//! 2. `Y-7` & `PI-META-MIN` ephemeral `#applicationEntry` pruning (recipient ACK
//!    quorum after the 72-hour floor, fail-closed archive qualification, no vacuous
//!    revoke/dormancy pruning, federated `notifyEntriesPruned` on eligible prunes,
//!    and the 30-day ceiling while preserving control entries).
//! 3. Nov-12 `space_host` + `FC-03` Space credential & read relays (`relaySpaceCredential`
//!    forwarding `clientAttestation` / `notify` / `spaceRev` with `confirmRegistration` challenge
//!    and signed `403` `denial` passthrough + subscriber withdrawal; `relaySpaceRead` allowing
//!    `com.atproto.space.listWriters`, forwarding `acceptSignature`, and preserving response proof
//!    headers; `removeWriter` emitting `#repoRemoved` and `notifySpaceUpdate`).
//! 4. `D-1` Signed `blue.catbird.labyrinth.getMailboxKeysRecord` CARv1 + ATProto v3 commit + MST
//!    inclusion/non-inclusion proof verification over HTTP (`200` verified inclusion, `404`
//!    authenticated MST non-inclusion, `502 UpstreamError` on unsigned `404`/`200` JSON, bad
//!    commit signature, tampered record block, or `epochNumber > 999_999_999_999`, plus strict
//!    lowercase RFC 4122 UUIDv4 `actorDeviceId` enforcement).

mod common;

use catbird_server::chat_protocol;

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use atproto_spaces::{
    http_signature::sign_credential_request,
    kem::{encapsulate_p256, encode_p256_did_key},
    mac::{
        format_accept_signature, verify_commit_mac, verify_record_mac, MacProfile,
        ACCEPT_SIGNATURE_HEADER,
    },
    star::read_star_repo_authenticated,
    tokens::{mint_space_token, SpaceSigningKey, SpaceTokenClaims, SpaceTokenKind},
};
use axum::{
    body::Body,
    extract::{FromRef, Query, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_server::{
    chat_protocol::{
        repository::expiry_sweep::{mark_inactive_devices, prune_expired_application_payloads},
        test_support::{
            seed_clean_slate_active_zero_leaf_member_for_test,
            seed_clean_slate_application_fixture, seed_clean_slate_application_fixture_unsealed,
            seed_clean_slate_remove_zero_leaf_member_for_test, sign_mutation_json_for_test,
            sign_reset_activation_for_test,
        },
    },
    federation::{
        outbound::OutboundClient,
        resolver::{DsResolver, ValidatedRemoteDestination},
        space_read_relay::{
            register_test_space_relay_target, test_car_builder::build_signed_repo_car,
        },
        ServiceAuthClient,
    },
    handlers::{
        chat::{chat_router, ChatRuntime},
        labyrinth::labyrinth_router,
    },
    labyrinth::{
        heads::{attestation_message, compute_epoch_head},
        read_auth::{canonical_query, signing_input, ReadClaim},
    },
    realtime::SseState,
    space_host::{space_host_router, SpaceHostConfig, SpaceHostRuntime},
    storage::DbPool,
};
use chrono::{Duration, SecondsFormat, Utc};
use common::http_acceptance as http;
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use p256::{
    ecdsa::{signature::Signer as _, Signature as P256Signature, SigningKey as P256SigningKey},
    pkcs8::EncodePrivateKey as _,
    PublicKey as P256PublicKey, SecretKey as P256Secret,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tokio::net::TcpListener;
use tower_util::ServiceExt;
use url::Url;
use uuid::Uuid;

static W2D_ENV_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

#[derive(Clone)]
struct UnifiedState {
    pool: DbPool,
    runtime: Arc<ChatRuntime>,
    resolver: Arc<DsResolver>,
    outbound: Arc<OutboundClient>,
    service_auth: Option<Arc<ServiceAuthClient>>,
}

impl FromRef<UnifiedState> for DbPool {
    fn from_ref(state: &UnifiedState) -> Self {
        state.pool.clone()
    }
}

impl FromRef<UnifiedState> for Arc<ChatRuntime> {
    fn from_ref(state: &UnifiedState) -> Self {
        state.runtime.clone()
    }
}

impl FromRef<UnifiedState> for Arc<DsResolver> {
    fn from_ref(state: &UnifiedState) -> Self {
        state.resolver.clone()
    }
}

impl FromRef<UnifiedState> for Arc<OutboundClient> {
    fn from_ref(state: &UnifiedState) -> Self {
        state.outbound.clone()
    }
}

impl FromRef<UnifiedState> for Option<Arc<ServiceAuthClient>> {
    fn from_ref(state: &UnifiedState) -> Self {
        state.service_auth.clone()
    }
}

async fn build_unified_router(pool: DbPool, resolver: Option<Arc<DsResolver>>) -> Router {
    http::ensure_fence(&pool).await;
    let r_for_runtime = resolver.clone();
    let resolver_arc = resolver.unwrap_or_else(|| {
        Arc::new(DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:chat.catbird.blue".to_owned(),
            "https://chat.example.net".to_owned(),
            None,
            300,
        ))
    });
    let (_chat_only, runtime) =
        http::router_and_runtime_for_authenticated_acceptance_with(pool.clone(), move |rt| {
            if let Some(r) = r_for_runtime {
                rt.with_resolver(r)
            } else {
                rt
            }
        })
        .await;
    let state = UnifiedState {
        pool,
        runtime,
        resolver: resolver_arc,
        outbound: Arc::new(OutboundClient::new(2, 10)),
        service_auth: None,
    };
    chat_router::<UnifiedState>()
        .with_state(state.clone())
        .merge(labyrinth_router::<UnifiedState>().with_state(state))
}

struct MlsKeyPackageFixture {
    wrapped: Vec<u8>,
    key_package_ref: Vec<u8>,
}

fn build_key_package(
    device_signing: &Ed25519SigningKey,
    credential: &[u8],
    not_before: u64,
    not_after: u64,
) -> MlsKeyPackageFixture {
    use openmls::prelude::{tls_codec::Serialize as TlsSerialize, *};
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::OpenMlsProvider;

    let provider = openmls_libcrux_crypto::Provider::new().expect("libcrux provider");
    let ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
    let signer = SignatureKeyPair::from_raw(
        ciphersuite.signature_algorithm(),
        device_signing.to_bytes().to_vec(),
        device_signing.verifying_key().to_bytes().to_vec(),
    );
    signer.store(provider.storage()).expect("store signer");

    let capabilities = Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[ciphersuite]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    );
    let bundle = KeyPackage::builder()
        .key_package_lifetime(Lifetime::init(not_before, not_after))
        .leaf_node_capabilities(capabilities)
        .build(
            ciphersuite,
            &provider,
            &signer,
            CredentialWithKey {
                credential: BasicCredential::new(credential.to_vec()).into(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .expect("build XWing KeyPackage");
    let wrapped = MlsMessageOut::from(bundle.key_package().clone())
        .tls_serialize_detached()
        .expect("serialize wire-format-5 MLSMessage");
    let key_package_ref = bundle
        .key_package()
        .hash_ref(provider.crypto())
        .expect("hash_ref")
        .as_slice()
        .to_vec();
    MlsKeyPackageFixture {
        wrapped,
        key_package_ref,
    }
}

fn capability_profile() -> Value {
    json!({
        "protocolVersion": "1",
        "mlsVersion": "1.0",
        "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "credentialType": "basic",
        "addByValue": "supported",
        "updatePath": "supported",
        "removeByValue": "supported",
        "ratchetTreeGroupInfo": "supported",
        "externalPubGroupInfo": "presentButExternalCommitsForbidden",
        "applicationFrameProfile": "dagCborApplication1",
        "controlProfile": "publicGroup1",
        "attachmentProfile": "aes256GcmBlob1",
        "metadataProfile": "exporterAes256Gcm1",
        "typingProfile": "signedClearEphemeral1"
    })
}

fn sign_chat_body(body: Value, key: &Ed25519SigningKey) -> Vec<u8> {
    use chat_protocol::transcript::decode_canonical_signed_mutation;
    let mut wrapper = json!({
        "body": body,
        "signature": STANDARD.encode([0_u8; 64]),
    });
    let unsigned = serde_json::to_vec(&wrapper).unwrap();
    let canonical = decode_canonical_signed_mutation(&unsigned).expect("canonical signed body");
    let signature = key.sign(canonical.transcript_bytes());
    wrapper["signature"] = json!(STANDARD.encode(signature.to_bytes()));
    serde_json::to_vec(&wrapper).unwrap()
}

fn sign_es256_jwt(header: Value, claims: Value, key: &P256SigningKey) -> String {
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let input = format!("{h}.{c}");
    let sig: P256Signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

fn dpop_proof(
    key: &P256SigningKey,
    jwk: &Value,
    htm: &str,
    htu: &str,
    access_token: &str,
    iat: i64,
) -> String {
    sign_es256_jwt(
        json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}),
        json!({
            "htm": htm,
            "htu": htu,
            "ath": URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes())),
            "iat": iat,
            "jti": URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes()),
        }),
        key,
    )
}

fn htu_for(nsid: &str) -> String {
    format!("{}/xrpc/{nsid}", http::EXTERNAL_BASE)
}

struct AccountIdentity {
    did: String,
    atproto_signing: P256SigningKey,
}

impl AccountIdentity {
    async fn create() -> Self {
        let did = http::random_did();
        let atproto_signing = http::random_p256();
        let jwk_val = http::public_jwk(&atproto_signing);
        let jwk: catbird_server::auth::PublicKeyJwk = serde_json::from_value(jwk_val).unwrap();
        catbird_server::auth::cache_test_did_document(catbird_server::auth::DidDocument {
            id: did.clone(),
            verification_method: vec![catbird_server::auth::VerificationMethod {
                id: format!("{did}#atproto"),
                key_type: "JsonWebKey2020".to_string(),
                controller: did.clone(),
                public_key_jwk: Some(jwk),
                public_key_multibase: None,
            }],
            service: None,
        })
        .await;
        Self {
            did,
            atproto_signing,
        }
    }
}

struct DeviceIdentity {
    did: String,
    account_signing: P256SigningKey,
    dpop_signing: P256SigningKey,
    dpop_jwk: Value,
    dpop_jkt: String,
    device_signing: Ed25519SigningKey,
    device_id: Uuid,
    device_name: String,
    key_id: String,
    signing_key_hash: [u8; 32],
    transcript_hash: [u8; 32],
    enrollment_raw: Vec<u8>,
}

impl DeviceIdentity {
    fn build(account: &AccountIdentity, device_name: &str, package_count: usize) -> Self {
        use chat_protocol::{
            transcript::decode_and_verify_enrollment_body, validation::ed25519_key_id,
        };

        let mut seed = [0_u8; 32];
        seed[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        seed[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        let device_signing = Ed25519SigningKey::from_bytes(&seed);

        let dpop_signing = http::random_p256();
        let dpop_jwk = http::public_jwk(&dpop_signing);
        let dpop_jkt = http::jwk_thumbprint(&dpop_jwk);

        let device_id = Uuid::new_v4();
        let credential = format!("{}#{device_id}", account.did);
        let now = Utc::now().timestamp();
        let key_id = ed25519_key_id(device_signing.verifying_key().as_bytes())
            .expect("key_id")
            .as_str()
            .to_owned();

        let mut built: Vec<MlsKeyPackageFixture> = (0..package_count)
            .map(|idx| {
                build_key_package(
                    &device_signing,
                    credential.as_bytes(),
                    (now - 300) as u64,
                    (now + 3_600 + idx as i64) as u64,
                )
            })
            .collect();
        built.sort_by(|a, b| a.key_package_ref.cmp(&b.key_package_ref));
        let packages: Vec<Value> = built
            .iter()
            .map(|kp| {
                json!({
                    "framing": "mlsMessage",
                    "contentType": "keyPackage",
                    "bytes": STANDARD.encode(&kp.wrapped),
                    "sha256": STANDARD.encode(Sha256::digest(&kp.wrapped)),
                    "keyPackageRef": STANDARD.encode(&kp.key_package_ref),
                })
            })
            .collect();

        let signed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let body = json!({
            "$type": "blue.catbird.chat.defs#deviceEnrollmentBody",
            "signatureDomain": "CATBIRD-CHAT-DEVICE-ENROLL\u{0}",
            "actorDid": account.did,
            "deviceId": device_id.to_string(),
            "deviceName": device_name,
            "keyId": key_id,
            "signaturePublicKey": STANDARD.encode(device_signing.verifying_key().as_bytes()),
            "expectedAuthGeneration": 0,
            "capability": capability_profile(),
            "keyPackages": packages,
            "idempotencyKey": Uuid::new_v4().to_string(),
            "signedAt": signed_at,
        });
        let enrollment_raw = sign_chat_body(body, &device_signing);
        let verified =
            decode_and_verify_enrollment_body(&enrollment_raw).expect("verify enrollment body");

        Self {
            did: account.did.clone(),
            account_signing: account.atproto_signing.clone(),
            dpop_signing,
            dpop_jwk,
            dpop_jkt,
            device_signing,
            device_id,
            device_name: device_name.to_owned(),
            key_id: verified.key_id().as_str().to_owned(),
            signing_key_hash: *verified.signing_key_sha256(),
            transcript_hash: *verified.enrollment_transcript_sha256(),
            enrollment_raw,
        }
    }

    fn enroll_request(&self) -> Request<Body> {
        let nsid = "blue.catbird.chat.enrollDevice";
        let now = Utc::now().timestamp();
        let token = sign_es256_jwt(
            json!({"alg": "ES256", "typ": "JWT", "kid": format!("{}#atproto", self.did)}),
            json!({
                "iss": self.did,
                "sub": self.did,
                "aud": http::AUDIENCE,
                "lxm": nsid,
                "iat": now,
                "exp": now + 60,
                "jti": Uuid::new_v4().to_string(),
                "cnf": {"jkt": self.dpop_jkt},
                "device_id": self.device_id.to_string(),
                "chat_instance": http::CHAT_INSTANCE,
                "key_id": self.key_id,
                "signing_key_sha256": URL_SAFE_NO_PAD.encode(self.signing_key_hash),
                "enrollment_transcript_sha256": URL_SAFE_NO_PAD.encode(self.transcript_hash),
                "auth_time": now,
                "auth_txn": Uuid::new_v4().to_string(),
            }),
            &self.account_signing,
        );
        let proof = dpop_proof(
            &self.dpop_signing,
            &self.dpop_jwk,
            "POST",
            &htu_for(nsid),
            &token,
            now,
        );
        let wrapper: Value = serde_json::from_slice(&self.enrollment_raw).unwrap();
        let body_bytes = serde_json::to_vec(&json!({ "signedRequest": wrapper })).unwrap();
        Request::builder()
            .method("POST")
            .uri(format!("/xrpc/{nsid}"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .header("dpop", proof)
            .body(Body::from(body_bytes))
            .expect("enroll request")
    }

    fn dpop_get_request(&self, nsid: &str, extra_query: &str) -> Request<Body> {
        let now = Utc::now().timestamp();
        let token = sign_es256_jwt(
            json!({"alg": "ES256", "typ": "JWT", "kid": format!("{}#atproto", self.did)}),
            json!({
                "iss": self.did,
                "sub": self.did,
                "aud": http::AUDIENCE,
                "lxm": nsid,
                "iat": now,
                "exp": now + 60,
                "jti": Uuid::new_v4().to_string(),
                "cnf": {"jkt": self.dpop_jkt},
                "device_id": self.device_id.to_string(),
                "chat_instance": http::CHAT_INSTANCE,
            }),
            &self.account_signing,
        );
        let proof = dpop_proof(
            &self.dpop_signing,
            &self.dpop_jwk,
            "GET",
            &htu_for(nsid),
            &token,
            now,
        );
        let suffix = extra_query.strip_prefix('?').unwrap_or(extra_query);
        let query = if suffix.is_empty() {
            format!("?actorDeviceId={}", self.device_id)
        } else {
            format!("?actorDeviceId={}&{suffix}", self.device_id)
        };
        Request::builder()
            .method("GET")
            .uri(format!("/xrpc/{nsid}{query}"))
            .header("authorization", format!("Bearer {token}"))
            .header("dpop", proof)
            .body(Body::empty())
            .expect("dpop GET request")
    }

    fn dpop_signed_post_request(&self, nsid: &str, signed_wrapper: &[u8]) -> Request<Body> {
        let now = Utc::now().timestamp();
        let token = sign_es256_jwt(
            json!({"alg": "ES256", "typ": "JWT", "kid": format!("{}#atproto", self.did)}),
            json!({
                "iss": self.did,
                "sub": self.did,
                "aud": http::AUDIENCE,
                "lxm": nsid,
                "iat": now,
                "exp": now + 60,
                "jti": Uuid::new_v4().to_string(),
                "cnf": {"jkt": self.dpop_jkt},
                "device_id": self.device_id.to_string(),
                "chat_instance": http::CHAT_INSTANCE,
            }),
            &self.account_signing,
        );
        let proof = dpop_proof(
            &self.dpop_signing,
            &self.dpop_jwk,
            "POST",
            &htu_for(nsid),
            &token,
            now,
        );
        let wrapper: Value = serde_json::from_slice(signed_wrapper).unwrap();
        let body_bytes = serde_json::to_vec(&json!({ "signedRequest": wrapper })).unwrap();
        Request::builder()
            .method("POST")
            .uri(format!("/xrpc/{nsid}"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .header("dpop", proof)
            .body(Body::from(body_bytes))
            .expect("dpop POST request")
    }

    fn bearer_get_request(&self, nsid: &str, raw_query: &str) -> Request<Body> {
        let now = Utc::now().timestamp();
        let aud = catbird_server::auth::expected_mls_service_ref();
        let token = sign_es256_jwt(
            json!({"alg": "ES256", "typ": "JWT", "kid": format!("{}#atproto", self.did)}),
            json!({
                "iss": self.did,
                "aud": aud,
                "lxm": nsid,
                "iat": now,
                "exp": now + 60,
                "jti": Uuid::new_v4().to_string(),
            }),
            &self.account_signing,
        );
        Request::builder()
            .method("GET")
            .uri(format!("/xrpc/{nsid}?{raw_query}"))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("bearer GET request")
    }

    fn bearer_post_request(&self, nsid: &str, payload: &Value) -> Request<Body> {
        let now = Utc::now().timestamp();
        let aud = catbird_server::auth::expected_mls_service_ref();
        let token = sign_es256_jwt(
            json!({"alg": "ES256", "typ": "JWT", "kid": format!("{}#atproto", self.did)}),
            json!({
                "iss": self.did,
                "aud": aud,
                "lxm": nsid,
                "iat": now,
                "exp": now + 60,
                "jti": Uuid::new_v4().to_string(),
            }),
            &self.account_signing,
        );
        Request::builder()
            .method("POST")
            .uri(format!("/xrpc/{nsid}"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(serde_json::to_vec(payload).unwrap()))
            .expect("bearer POST request")
    }

    fn labyrinth_get_request(&self, name: &str, extra_params: &[(&str, &str)]) -> Request<Body> {
        self.labyrinth_get_request_with_raw_actor_id(
            name,
            &self.device_id.to_string(),
            extra_params,
        )
    }

    fn labyrinth_fixed_get_request(&self, name: &str, params: &[(&str, &str)]) -> Request<Body> {
        self.labyrinth_fixed_get_request_with_raw_device_id(
            name,
            &self.device_id.to_string(),
            params,
        )
    }

    fn labyrinth_fixed_get_request_with_raw_device_id(
        &self,
        name: &str,
        raw_device_id: &str,
        params: &[(&str, &str)],
    ) -> Request<Body> {
        let nsid = format!("blue.catbird.labyrinth.{name}");
        let mut qs = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in params {
            qs.append_pair(k, v);
        }
        let query = qs.finish();
        let claim = ReadClaim {
            v: 1,
            nsid: nsid.clone(),
            query: canonical_query(Some(&query)),
            did: self.did.clone(),
            device_id: raw_device_id.to_owned(),
            issued_at: Utc::now().timestamp_millis(),
        };
        let claim_bytes = serde_json::to_vec(&claim).unwrap();
        let sig = self.device_signing.sign(&signing_input(&claim_bytes));
        let now = Utc::now().timestamp();
        let aud = catbird_server::auth::expected_mls_service_ref();
        let token = sign_es256_jwt(
            json!({"alg": "ES256", "typ": "JWT", "kid": format!("{}#atproto", self.did)}),
            json!({
                "iss": self.did,
                "sub": self.did,
                "aud": aud,
                "lxm": nsid,
                "iat": now,
                "exp": now + 60,
                "jti": Uuid::new_v4().to_string(),
            }),
            &self.account_signing,
        );
        Request::builder()
            .method("GET")
            .uri(format!("/xrpc/{nsid}?{query}"))
            .header("authorization", format!("Bearer {token}"))
            .header(
                "catbird-labyrinth-read",
                URL_SAFE_NO_PAD.encode(&claim_bytes),
            )
            .header(
                "catbird-labyrinth-read-signature",
                URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            )
            .body(Body::empty())
            .expect("labyrinth fixed GET request")
    }

    fn labyrinth_get_request_with_raw_actor_id(
        &self,
        name: &str,
        raw_actor_id: &str,
        extra_params: &[(&str, &str)],
    ) -> Request<Body> {
        let nsid = format!("blue.catbird.labyrinth.{name}");
        let mut qs = url::form_urlencoded::Serializer::new(String::new());
        qs.append_pair("actorDeviceId", raw_actor_id);
        for (k, v) in extra_params {
            qs.append_pair(k, v);
        }
        let query = qs.finish();
        let claim = ReadClaim {
            v: 1,
            nsid: nsid.clone(),
            query: canonical_query(Some(&query)),
            did: self.did.clone(),
            device_id: raw_actor_id.to_owned(),
            issued_at: Utc::now().timestamp_millis(),
        };
        let claim_bytes = serde_json::to_vec(&claim).unwrap();
        let sig = self.device_signing.sign(&signing_input(&claim_bytes));
        let now = Utc::now().timestamp();
        let aud = catbird_server::auth::expected_mls_service_ref();
        let token = sign_es256_jwt(
            json!({"alg": "ES256", "typ": "JWT", "kid": format!("{}#atproto", self.did)}),
            json!({
                "iss": self.did,
                "sub": self.did,
                "aud": aud,
                "lxm": nsid,
                "iat": now,
                "exp": now + 60,
                "jti": Uuid::new_v4().to_string(),
            }),
            &self.account_signing,
        );
        Request::builder()
            .method("GET")
            .uri(format!("/xrpc/{nsid}?{query}"))
            .header("authorization", format!("Bearer {token}"))
            .header(
                "catbird-labyrinth-read",
                URL_SAFE_NO_PAD.encode(&claim_bytes),
            )
            .header(
                "catbird-labyrinth-read-signature",
                URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            )
            .body(Body::empty())
            .expect("labyrinth GET request")
    }

    fn labyrinth_post_request(&self, name: &str, payload: &Value) -> Request<Body> {
        let nsid = format!("blue.catbird.labyrinth.{name}");
        let body = serde_json::to_vec(payload).unwrap();
        let operation_id = *Uuid::new_v4().as_bytes();
        let signed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let write_claim = serde_json::to_vec(&json!({
            "operationId": hex::encode(operation_id),
            "actorDeviceId": self.device_id.to_string(),
            "endpointNsid": nsid,
            "payloadSha256": hex::encode(Sha256::digest(&body)),
            "signedAt": signed_at,
        }))
        .unwrap();
        let sig = self
            .device_signing
            .sign(&[b"CATBIRD-LABYRINTH-WRITE\0".as_slice(), &write_claim].concat());
        let now = Utc::now().timestamp();
        let aud = catbird_server::auth::expected_mls_service_ref();
        let token = sign_es256_jwt(
            json!({"alg": "ES256", "typ": "JWT", "kid": format!("{}#atproto", self.did)}),
            json!({
                "iss": self.did,
                "sub": self.did,
                "aud": aud,
                "lxm": nsid,
                "iat": now,
                "exp": now + 60,
                "jti": Uuid::new_v4().to_string(),
            }),
            &self.account_signing,
        );
        Request::builder()
            .method("POST")
            .uri(format!("/xrpc/{nsid}"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .header(
                "catbird-labyrinth-write",
                URL_SAFE_NO_PAD.encode(&write_claim),
            )
            .header(
                "catbird-labyrinth-write-signature",
                URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            )
            .body(Body::from(body))
            .expect("labyrinth POST request")
    }

    fn approval_wrapper(
        &self,
        target: &DeviceIdentity,
        target_auth_generation: u64,
        idempotency_key: Uuid,
    ) -> Vec<u8> {
        let signed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let body = json!({
            "$type": "blue.catbird.chat.defs#deviceApprovalBody",
            "signatureDomain": "CATBIRD-CHAT-DEVICE-APPROVE\u{0}",
            "actorDid": self.did,
            "actorDeviceId": self.device_id.to_string(),
            "keyId": self.key_id,
            "authGeneration": 1,
            "targetDeviceId": target.device_id.to_string(),
            "targetKeyId": target.key_id,
            "targetSignaturePublicKey": STANDARD.encode(target.device_signing.verifying_key().as_bytes()),
            "targetAuthGeneration": target_auth_generation,
            "idempotencyKey": idempotency_key.to_string(),
            "signedAt": signed_at,
        });
        sign_chat_body(body, &self.device_signing)
    }

    fn revocation_wrapper(&self, target_device_id: Uuid, target_auth_generation: u64) -> Vec<u8> {
        let signed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let body = json!({
            "$type": "blue.catbird.chat.defs#deviceRevocationBody",
            "signatureDomain": "CATBIRD-CHAT-DEVICE-REVOKE\u{0}",
            "actorDid": self.did,
            "actorDeviceId": self.device_id.to_string(),
            "keyId": self.key_id,
            "authGeneration": 1,
            "targetDeviceId": target_device_id.to_string(),
            "targetAuthGeneration": target_auth_generation,
            "idempotencyKey": Uuid::new_v4().to_string(),
            "signedAt": signed_at,
        });
        sign_chat_body(body, &self.device_signing)
    }
}

fn sign_ack_entries_request(
    actor_device_id: Uuid,
    key_id: &str,
    auth_generation: i64,
    signing_key: &Ed25519SigningKey,
    conversation_id: Uuid,
    generation: i64,
    up_to_seq: i64,
) -> Value {
    #[derive(serde::Serialize)]
    struct AckTranscriptPayload<'a> {
        #[serde(rename = "keyId")]
        key_id: &'a str,
        #[serde(rename = "upToSeq")]
        up_to_seq: i64,
        #[serde(rename = "signedAt")]
        signed_at: &'a str,
        generation: i64,
        #[serde(rename = "actorDeviceId")]
        actor_device_id: String,
        #[serde(rename = "authGeneration")]
        auth_generation: i64,
        #[serde(rename = "conversationId")]
        conversation_id: String,
    }
    let signed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let payload = AckTranscriptPayload {
        key_id,
        up_to_seq,
        signed_at: &signed_at,
        generation,
        actor_device_id: actor_device_id.to_string(),
        auth_generation,
        conversation_id: conversation_id.to_string(),
    };
    let cbor = serde_ipld_dagcbor::to_vec(&payload).expect("ack cbor");
    let mut transcript = b"CATBIRD-CHAT-ACK-ENTRIES\0".to_vec();
    transcript.extend_from_slice(&cbor);
    let sig = signing_key.sign(&transcript);
    json!({
        "conversationId": conversation_id,
        "generation": generation,
        "actorDeviceId": actor_device_id,
        "keyId": key_id,
        "authGeneration": auth_generation,
        "upToSeq": up_to_seq,
        "signedAt": signed_at,
        "signature": { "$bytes": STANDARD.encode(sig.to_bytes()) }
    })
}

async fn age_entry_past_prune_floor(pool: &sqlx::PgPool, conversation_id: Uuid, seq: i64) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE chat.entries SET received_at = clock_timestamp() - INTERVAL '73 hours' \
          WHERE conversation_id = $1 AND seq = $2",
    )
    .bind(conversation_id)
    .bind(seq)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE chat.message_sends send \
            SET received_at = entry.received_at \
           FROM chat.entries entry \
          WHERE entry.conversation_id = $1 AND entry.seq = $2 \
            AND send.conversation_id = entry.conversation_id \
            AND send.message_id = entry.message_id",
    )
    .bind(conversation_id)
    .bind(seq)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

// =============================================================================
// 1. D-2 Multi-Device Sibling Approval & #deviceView End-to-End
// =============================================================================

#[tokio::test]
async fn d2_multidevice_enrollment_approval_and_device_view_end_to_end() {
    let _env_guard = W2D_ENV_LOCK.lock().await;
    std::env::set_var("SERVICE_DID", "did:web:chat.catbird.blue");
    std::env::set_var("SELF_ENDPOINT", "https://chat.catbird.blue");

    let db = common::fresh_db::fresh_fully_migrated_db("chat_w2d_").await;
    let pool = db.connect(6).await;
    let router = build_unified_router(pool.clone(), None).await;

    let alice_acct = AccountIdentity::create().await;
    let bob_acct = AccountIdentity::create().await;

    let alice_d1 = DeviceIdentity::build(&alice_acct, "Alice iPhone", 2);
    let alice_d2 = DeviceIdentity::build(&alice_acct, "Alice MacBook", 2);
    let alice_d3 = DeviceIdentity::build(&alice_acct, "Alice iPad", 1);
    let bob_d1 = DeviceIdentity::build(&bob_acct, "Bob Pixel", 2);

    // 1. First device on Alice and Bob bootstrap directly to `status == "active"`.
    let (s_a1, b_a1) = http::send(router.clone(), alice_d1.enroll_request()).await;
    assert_eq!(s_a1, StatusCode::OK, "Alice d1 enroll failed: {b_a1}");
    assert_eq!(b_a1["device"]["status"], "active");
    assert_eq!(b_a1["device"]["deviceName"], "Alice iPhone");
    assert!(
        b_a1["device"]["lastActiveAt"]
            .as_str()
            .expect("lastActiveAt string")
            .ends_with("T00:00:00.000000Z"),
        "PI-META-MIN: lastActiveAt must be truncated to coarse UTC day: {}",
        b_a1["device"]["lastActiveAt"]
    );
    assert!(
        b_a1["device"].get("dormantAt").is_none(),
        "active device must omit dormantAt"
    );

    let (s_b1, b_b1) = http::send(router.clone(), bob_d1.enroll_request()).await;
    assert_eq!(s_b1, StatusCode::OK, "Bob d1 enroll failed: {b_b1}");
    assert_eq!(b_b1["device"]["status"], "active");

    // 2. Second device on Alice enrolls into `pending_approval`.
    let (s_a2, b_a2) = http::send(router.clone(), alice_d2.enroll_request()).await;
    assert_eq!(s_a2, StatusCode::OK, "Alice d2 enroll failed: {b_a2}");
    assert_eq!(b_a2["device"]["status"], "pending_approval");
    assert_eq!(b_a2["device"]["deviceName"], "Alice MacBook");
    assert!(b_a2["device"]["lastActiveAt"]
        .as_str()
        .unwrap()
        .ends_with("T00:00:00.000000Z"));

    // 3. Unapproved Device 2 CAN read its own sibling inventory (`getOwnDevices`) and self-DID
    //    Labyrinth bootstrap (`getEpochHead`), while remaining fail-closed (`401 NotAuthorized`)
    //    on chat conversations, public `getDevices`, Space relays, and foreign-DID Labyrinth reads!
    let (pending_own_status, pending_own_body) = http::send(
        router.clone(),
        alice_d2.dpop_get_request("blue.catbird.chat.getOwnDevices", ""),
    )
    .await;
    assert_eq!(
        pending_own_status,
        StatusCode::OK,
        "pending_approval getOwnDevices must succeed for recovery/enrollment inspection: {pending_own_body}"
    );
    assert_eq!(pending_own_body["items"].as_array().unwrap().len(), 2);

    let (unauth_dir_status, unauth_dir_body) = http::send(
        router.clone(),
        alice_d2.dpop_get_request(
            "blue.catbird.chat.getDevices",
            &format!("userDids={}", bob_acct.did),
        ),
    )
    .await;
    assert_eq!(unauth_dir_status, StatusCode::UNAUTHORIZED);
    assert_eq!(unauth_dir_body["error"], "NotAuthorized");

    let (unauth_convos_status, unauth_convos_body) = http::send(
        router.clone(),
        alice_d2.bearer_get_request(
            "blue.catbird.chat.getConversations",
            &format!("actorDeviceId={}", alice_d2.device_id),
        ),
    )
    .await;
    assert_eq!(unauth_convos_status, StatusCode::UNAUTHORIZED);
    assert_eq!(unauth_convos_body["error"], "NotAuthorized");

    let (unauth_space_cred_status, unauth_space_cred_body) = http::send(
        router.clone(),
        alice_d2.bearer_post_request(
            "blue.catbird.chat.relaySpaceCredential",
            &json!({
                "actorDeviceId": alice_d2.device_id,
                "authorityDid": "did:web:chat.catbird.blue",
                "space": format!("at://{}/space/blue.catbird.labyrinth.mailbox/self", alice_acct.did),
                "delegationToken": "header.payload.sig",
                "cnfKey": "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
            }),
        ),
    )
    .await;
    assert_eq!(unauth_space_cred_status, StatusCode::UNAUTHORIZED);
    assert_eq!(unauth_space_cred_body["error"], "NotAuthorized");

    let (unauth_space_read_status, unauth_space_read_body) = http::send(
        router.clone(),
        alice_d2.bearer_post_request(
            "blue.catbird.chat.relaySpaceRead",
            &json!({
                "actorDeviceId": alice_d2.device_id,
                "targetDid": "did:web:chat.catbird.blue",
                "nsid": "com.atproto.space.listWriters",
                "credential": "header.payload.sig",
                "spaceAudience": "did:web:chat.catbird.blue",
                "signatureInput": "sig1=(\"@method\")",
                "signature": "sig1=:AA==:",
            }),
        ),
    )
    .await;
    assert_eq!(unauth_space_read_status, StatusCode::UNAUTHORIZED);
    assert_eq!(unauth_space_read_body["error"], "NotAuthorized");

    let (unauth_lab_status, unauth_lab_body) = http::send(
        router.clone(),
        alice_d2.labyrinth_get_request("getEpochHead", &[("did", &bob_acct.did)]),
    )
    .await;
    assert_eq!(unauth_lab_status, StatusCode::UNAUTHORIZED);
    assert_eq!(unauth_lab_body["error"], "NotAuthorized");

    let (unauth_mb_status, unauth_mb_body) = http::send(
        router.clone(),
        alice_d2.labyrinth_fixed_get_request(
            "getMailboxKeysRecord",
            &[("did", &bob_acct.did), ("rkey", "self")],
        ),
    )
    .await;
    assert_eq!(unauth_mb_status, StatusCode::UNAUTHORIZED);
    assert_eq!(unauth_mb_body["error"], "NotAuthorized");

    // Self-approval by unapproved Device 2 is rejected at authority admission (`NotAuthorized`).
    let self_by_d2 = alice_d2.approval_wrapper(&alice_d2, 1, Uuid::new_v4());
    let (self_d2_status, self_d2_body) = http::send(
        router.clone(),
        alice_d2.dpop_signed_post_request("blue.catbird.chat.approveDevice", &self_by_d2),
    )
    .await;
    assert_eq!(self_d2_status, StatusCode::UNAUTHORIZED);
    assert_eq!(self_d2_body["error"], "NotAuthorized");

    // 4. Public `getDevices` (queried by Bob) excludes `pending_approval` Device 2, while
    //    Alice's own `getOwnDevices` includes BOTH Device 1 (`active`) and Device 2 (`pending_approval`)!
    let (pub_dir_status, pub_dir_body) = http::send(
        router.clone(),
        bob_d1.dpop_get_request(
            "blue.catbird.chat.getDevices",
            &format!("userDids={}", alice_acct.did),
        ),
    )
    .await;
    assert_eq!(
        pub_dir_status,
        StatusCode::OK,
        "getDevices failed: {pub_dir_body}"
    );
    let pub_items = pub_dir_body["devices"]
        .as_array()
        .expect("getDevices devices");
    assert_eq!(
        pub_items.len(),
        1,
        "pending_approval device must be excluded from public getDevices"
    );
    assert_eq!(pub_items[0]["deviceId"], alice_d1.device_id.to_string());

    let (own_status, own_body) = http::send(
        router.clone(),
        alice_d1.dpop_get_request("blue.catbird.chat.getOwnDevices", ""),
    )
    .await;
    assert_eq!(
        own_status,
        StatusCode::OK,
        "getOwnDevices failed: {own_body}"
    );
    let own_items = own_body["items"].as_array().expect("getOwnDevices items");
    assert_eq!(
        own_items.len(),
        2,
        "getOwnDevices must include pending sibling"
    );
    let d2_in_own = own_items
        .iter()
        .find(|item| item["device"]["deviceId"] == alice_d2.device_id.to_string())
        .expect("d2 visible in getOwnDevices");
    assert_eq!(d2_in_own["device"]["status"], "pending_approval");
    assert_eq!(d2_in_own["device"]["deviceName"], "Alice MacBook");

    // 5. Self-approval by active Device 1 (`actorDeviceId == targetDeviceId`) is rejected (`InvalidRequest`).
    let self_by_d1 = alice_d1.approval_wrapper(&alice_d1, 1, Uuid::new_v4());
    let (self_d1_status, self_d1_body) = http::send(
        router.clone(),
        alice_d1.dpop_signed_post_request("blue.catbird.chat.approveDevice", &self_by_d1),
    )
    .await;
    assert_eq!(self_d1_status, StatusCode::BAD_REQUEST);
    assert_eq!(self_d1_body["error"], "InvalidRequest");

    // Wrong `targetAuthGeneration` is rejected with `400 AuthenticationGenerationConflict` (XRPC default 400).
    let bad_gen = alice_d1.approval_wrapper(&alice_d2, 2, Uuid::new_v4());
    let (bad_gen_status, bad_gen_body) = http::send(
        router.clone(),
        alice_d1.dpop_signed_post_request("blue.catbird.chat.approveDevice", &bad_gen),
    )
    .await;
    assert_eq!(bad_gen_status, StatusCode::BAD_REQUEST);
    assert_eq!(bad_gen_body["error"], "AuthenticationGenerationConflict");

    // 6. Active sibling Device 1 approves Device 2 -> promotes to `active`, records `chat.device_approvals`,
    //    replays byte-for-byte on retry, and rejects a fresh approval of already-active Device 2 with `409 DeviceAlreadyActive`.
    let approve_idem = Uuid::new_v4();
    let approve_wrap = alice_d1.approval_wrapper(&alice_d2, 1, approve_idem);
    let (app_status_1, app_bytes_1) = http::send_bytes(
        router.clone(),
        alice_d1.dpop_signed_post_request("blue.catbird.chat.approveDevice", &approve_wrap),
    )
    .await;
    assert_eq!(
        app_status_1,
        StatusCode::OK,
        "approveDevice failed: {}",
        String::from_utf8_lossy(&app_bytes_1)
    );
    let app_json_1: Value = serde_json::from_slice(&app_bytes_1).unwrap();
    assert_eq!(
        app_json_1["device"]["deviceId"],
        alice_d2.device_id.to_string()
    );
    assert_eq!(app_json_1["device"]["status"], "active");
    assert_eq!(app_json_1["device"]["deviceName"], "Alice MacBook");

    let approval_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.device_approvals WHERE target_did = $1 AND target_device_id = $2 AND actor_device_id = $3",
    )
    .bind(&alice_acct.did)
    .bind(alice_d2.device_id)
    .bind(alice_d1.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        approval_rows, 1,
        "chat.device_approvals audit row must be committed"
    );

    // Idempotent replay returns verbatim stored response bytes.
    let (app_status_2, app_bytes_2) = http::send_bytes(
        router.clone(),
        alice_d1.dpop_signed_post_request("blue.catbird.chat.approveDevice", &approve_wrap),
    )
    .await;
    assert_eq!(app_status_2, StatusCode::OK);
    assert_eq!(
        app_bytes_1, app_bytes_2,
        "approveDevice idempotent replay must return byte-identical response"
    );

    // Fresh approval against already-active Device 2 returns `400 DeviceAlreadyActive`.
    let dup_approve = alice_d1.approval_wrapper(&alice_d2, 1, Uuid::new_v4());
    let (dup_status, dup_body) = http::send(
        router.clone(),
        alice_d1.dpop_signed_post_request("blue.catbird.chat.approveDevice", &dup_approve),
    )
    .await;
    assert_eq!(dup_status, StatusCode::BAD_REQUEST);
    assert_eq!(dup_body["error"], "DeviceAlreadyActive");

    // 7. Newly approved Device 2 now passes auth across chat & Labyrinth and appears in public `getDevices`!
    let (d2_own_status, d2_own_body) = http::send(
        router.clone(),
        alice_d2.dpop_get_request("blue.catbird.chat.getOwnDevices", ""),
    )
    .await;
    assert_eq!(
        d2_own_status,
        StatusCode::OK,
        "approved d2 getOwnDevices: {d2_own_body}"
    );

    let (d2_lab_status, d2_lab_body) = http::send(
        router.clone(),
        alice_d2.labyrinth_get_request("getChatDeviceKeys", &[("did", &alice_acct.did)]),
    )
    .await;
    assert_eq!(
        d2_lab_status,
        StatusCode::OK,
        "approved d2 Labyrinth: {d2_lab_body}"
    );
    assert_eq!(d2_lab_body["items"].as_array().unwrap().len(), 2);

    let (pub_after_status, pub_after_body) = http::send(
        router.clone(),
        bob_d1.dpop_get_request(
            "blue.catbird.chat.getDevices",
            &format!("userDids={}", alice_acct.did),
        ),
    )
    .await;
    assert_eq!(pub_after_status, StatusCode::OK);
    assert_eq!(
        pub_after_body["devices"].as_array().unwrap().len(),
        2,
        "approved Device 2 must appear in public getDevices"
    );

    // Verify `DeviceView.status == "dormant"` over HTTP (`getOwnDevices` from active sibling `alice_d1`)
    // when `alice_d2` crosses `60d` inactivity, and wake-up back to `"active"` when `alice_d2` authenticates!
    let dorm_ref = Utc::now();
    sqlx::query(
        "UPDATE chat.devices SET last_active_at = $3 WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&alice_acct.did)
    .bind(alice_d1.device_id)
    .bind(dorm_ref)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE chat.devices SET last_active_at = $3 WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&alice_acct.did)
    .bind(alice_d2.device_id)
    .bind(dorm_ref - Duration::days(61))
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(mark_inactive_devices(&pool, dorm_ref).await.unwrap(), 1);
    let (dorm_own_status, dorm_own_body) = http::send(
        router.clone(),
        alice_d1.dpop_get_request("blue.catbird.chat.getOwnDevices", ""),
    )
    .await;
    assert_eq!(dorm_own_status, StatusCode::OK);
    let d2_dorm_view = dorm_own_body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["device"]["deviceId"] == alice_d2.device_id.to_string())
        .expect("d2 in getOwnDevices");
    assert_eq!(d2_dorm_view["device"]["status"], "dormant");

    // `alice_d2` authenticates -> wakes from dormancy (`status == "active"`)!
    let (wake_status, wake_body) = http::send(
        router.clone(),
        alice_d2.dpop_get_request("blue.catbird.chat.getOwnDevices", ""),
    )
    .await;
    assert_eq!(wake_status, StatusCode::OK);
    let d2_wake_view = wake_body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["device"]["deviceId"] == alice_d2.device_id.to_string())
        .expect("woken d2 in getOwnDevices");
    assert_eq!(d2_wake_view["device"]["status"], "active");

    // 8. Enrolling a 3rd device (`pending_approval`) and calling `revokeDevice` from active sibling
    //    Device 1 transitions Device 3 directly `pending_approval -> revoked`!
    let (s_a3, b_a3) = http::send(router.clone(), alice_d3.enroll_request()).await;
    assert_eq!(s_a3, StatusCode::OK);
    assert_eq!(b_a3["device"]["status"], "pending_approval");

    let revoke_d3 = alice_d1.revocation_wrapper(alice_d3.device_id, 1);
    let (rev_status, rev_body) = http::send(
        router.clone(),
        alice_d1.dpop_signed_post_request("blue.catbird.chat.revokeDevice", &revoke_d3),
    )
    .await;
    assert_eq!(
        rev_status,
        StatusCode::OK,
        "revoke pending_approval d3: {rev_body}"
    );
    assert_eq!(rev_body["device"]["status"], "revoked");

    let approve_revoked = alice_d1.approval_wrapper(&alice_d3, 1, Uuid::new_v4());
    let (app_rev_status, app_rev_body) = http::send(
        router.clone(),
        alice_d1.dpop_signed_post_request("blue.catbird.chat.approveDevice", &approve_revoked),
    )
    .await;
    assert_eq!(
        app_rev_status,
        StatusCode::UNAUTHORIZED,
        "revoked target status: {app_rev_body}"
    );
    assert_eq!(app_rev_body["error"], "DeviceRevoked");

    pool.close().await;
}

// =============================================================================
// 2. Y-7 Ephemeral Pruning, Recipient ACK floor, 30-day ceiling, and 60-day dormancy
// =============================================================================

#[tokio::test]
async fn y7_pruning_requires_recipient_quorum_after_72h_or_the_30d_ceiling() {
    let _env_guard = W2D_ENV_LOCK.lock().await;
    let self_did = "did:web:chat.catbird.blue";
    let s2s_secret = P256Secret::from_slice(&[0x59_u8; 32]).unwrap();
    let s2s_pem = s2s_secret
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();
    std::env::set_var("SERVICE_DID", self_did);
    std::env::set_var("SELF_ENDPOINT", "https://chat.catbird.blue");
    std::env::set_var("SIGNING_KEY_PEM", s2s_pem);
    std::env::set_var("APP_ENV", "test");
    std::env::set_var("FEDERATION_TEST_ALLOW_ALL_RELATIONSHIPS", "true");

    let db = common::fresh_db::fresh_fully_migrated_db("chat_w2d_").await;
    let pool = db.connect(6).await;
    let router = build_unified_router(pool.clone(), None).await;

    let fixture = seed_clean_slate_application_fixture_unsealed(
        &pool,
        false,
        self_did,
        Some([0x51; 32]),
        None,
    )
    .await
    .expect("application fixture");
    let remote_ds_did = "did:web:remote-peer-ds.catbird.blue";

    let sender_p256 = http::random_p256();
    let sender_jwk = http::public_jwk(&sender_p256);
    let sender_jkt = http::jwk_thumbprint(&sender_jwk);
    let recipient_p256 = http::random_p256();
    let recipient_jwk = http::public_jwk(&recipient_p256);
    let recipient_jkt = http::jwk_thumbprint(&recipient_jwk);
    {
        let mut dtx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *dtx)
            .await
            .unwrap();
        sqlx::query("UPDATE chat.devices SET dpop_jkt = $3 WHERE user_did = $1 AND device_id = $2")
            .bind(&fixture.sender_did)
            .bind(fixture.sender_device_id)
            .bind(&sender_jkt)
            .execute(&mut *dtx)
            .await
            .unwrap();
        sqlx::query("UPDATE chat.devices SET dpop_jkt = $3 WHERE user_did = $1 AND device_id = $2")
            .bind(&fixture.recipient_did)
            .bind(fixture.recipient_device_id)
            .bind(&recipient_jkt)
            .execute(&mut *dtx)
            .await
            .unwrap();
        dtx.commit().await.unwrap();
    }
    let sender_dev = http::Device {
        did: fixture.sender_did.clone(),
        device_id: fixture.sender_device_id,
        jkt: sender_jkt,
        signing: sender_p256,
        jwk: sender_jwk,
    };
    http::cache_device_did(&sender_dev).await;
    let recipient_dev = http::Device {
        did: fixture.recipient_did.clone(),
        device_id: fixture.recipient_device_id,
        jkt: recipient_jkt.clone(),
        signing: recipient_p256.clone(),
        jwk: recipient_jwk.clone(),
    };
    http::cache_device_did(&recipient_dev).await;

    // 1. Send `#applicationEntry` (`seq = app_seq`) on the real 2-leaf conversation.
    let (send_status, send_body) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &sender_dev,
            "blue.catbird.chat.sendMessage",
            serde_json::to_vec(&json!({ "signedRequest": fixture.signed_request })).unwrap(),
        ),
    )
    .await;
    assert_eq!(
        send_status,
        StatusCode::OK,
        "sendMessage failed: {send_body}"
    );
    let app_seq = send_body["entry"]["seq"].as_i64().unwrap();

    // 2. `sender_d1` acknowledges `app_seq` -> NOT pruned because `recipient_d1` is active & unacked!
    let sender_ed = Ed25519SigningKey::from_bytes(&fixture.sender_ed25519_seed);
    let ack_s1 = sign_ack_entries_request(
        fixture.sender_device_id,
        &fixture.sender_key_id,
        1,
        &sender_ed,
        fixture.conversation_id,
        0,
        app_seq,
    );
    let (s_ack1, b_ack1) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &sender_dev,
            "blue.catbird.chat.acknowledgeEntries",
            serde_json::to_vec(&ack_s1).unwrap(),
        ),
    )
    .await;
    assert_eq!(s_ack1, StatusCode::OK);
    assert_eq!(b_ack1["prunedCount"], 0);

    let recipient_ed = Ed25519SigningKey::from_bytes(&fixture.recipient_ed25519_seed);

    // Mark `sender_did`'s participant home DS as `remote_ds_did` so when `recipient_d1` is revoked
    // below, `enqueue_entries_pruned_notices` signs and enqueues a federated S2S
    // `blue.catbird.mlsDS.notifyEntriesPruned` notice into `outbound_queue`!
    {
        let mut rtx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *rtx)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE chat.participants SET ds_did = $3 WHERE conversation_id = $1 AND user_did = $2",
        )
        .bind(fixture.conversation_id)
        .bind(&fixture.sender_did)
        .bind(remote_ds_did)
        .execute(&mut *rtx)
        .await
        .unwrap();
        rtx.commit().await.unwrap();
    }

    // 3. `recipient_d1` self-revokes. With no remaining non-sender recipient
    // device ACK and no verified archive, revocation must not turn the recipient
    // quorum into an empty set or enqueue a false prune notice.
    let revoke_body = json!({
        "$type": "blue.catbird.chat.defs#deviceRevocationBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REVOKE\u{0}",
        "actorDid": fixture.recipient_did,
        "actorDeviceId": fixture.recipient_device_id.to_string(),
        "keyId": fixture.recipient_key_id,
        "authGeneration": 1,
        "targetDeviceId": fixture.recipient_device_id.to_string(),
        "targetAuthGeneration": 1,
        "idempotencyKey": Uuid::new_v4().to_string(),
        "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
    });
    let revoke_wrapper = sign_chat_body(revoke_body, &recipient_ed);
    let now_ts = Utc::now().timestamp();
    let rev_token = sign_es256_jwt(
        json!({"alg": "ES256", "typ": "JWT", "kid": format!("{}#atproto", fixture.recipient_did)}),
        json!({
            "iss": fixture.recipient_did,
            "sub": fixture.recipient_did,
            "aud": http::AUDIENCE,
            "lxm": "blue.catbird.chat.revokeDevice",
            "iat": now_ts,
            "exp": now_ts + 60,
            "jti": Uuid::new_v4().to_string(),
            "cnf": {"jkt": recipient_jkt},
            "device_id": fixture.recipient_device_id.to_string(),
            "chat_instance": http::CHAT_INSTANCE,
        }),
        &recipient_p256,
    );
    let rev_proof = dpop_proof(
        &recipient_p256,
        &recipient_jwk,
        "POST",
        &htu_for("blue.catbird.chat.revokeDevice"),
        &rev_token,
        now_ts,
    );
    let rev_req = Request::builder()
        .method("POST")
        .uri("/xrpc/blue.catbird.chat.revokeDevice")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {rev_token}"))
        .header("dpop", rev_proof)
        .body(Body::from(
            serde_json::to_vec(&json!({
                "signedRequest": serde_json::from_slice::<Value>(&revoke_wrapper).unwrap()
            }))
            .unwrap(),
        ))
        .unwrap();
    let (rev_status, rev_resp) = http::send(router.clone(), rev_req).await;
    assert_eq!(
        rev_status,
        StatusCode::OK,
        "revokeDevice failed: {rev_resp}"
    );

    let (app_pruned, ctrl_pruned): (bool, bool) = sqlx::query_as(
        "SELECT \
            (SELECT payload_pruned_at IS NOT NULL AND accepted_payload_bytes IS NULL AND signed_request_bytes IS NULL \
             FROM chat.entries WHERE conversation_id = $1 AND seq = $2), \
            (SELECT payload_pruned_at IS NOT NULL \
             FROM chat.entries WHERE conversation_id = $1 AND seq = 1)",
    )
    .bind(fixture.conversation_id)
    .bind(app_seq)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        !app_pruned,
        "revoking the only unacked recipient must retain the unarchived payload"
    );
    assert!(!ctrl_pruned, "control entry at seq=1 must NEVER be pruned");

    let outbox_prune_notices: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbound_queue \
         WHERE convo_id = $1 AND target_ds_did = $2 AND method = 'blue.catbird.mlsDS.notifyEntriesPruned'",
    )
    .bind(fixture.conversation_id.to_string())
    .bind(remote_ds_did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        outbox_prune_notices, 0,
        "no entriesPruned notice may be emitted for a retained payload"
    );

    // 3b. One non-dormant enrolled leaf ACK per non-sender participant is the
    // recipient quorum. A second active sibling on the same DID does not expand
    // that participant-level quorum, but the 72-hour floor still applies.
    let db_m = common::fresh_db::fresh_fully_migrated_db("chat_w2d_").await;
    let pool_m = db_m.connect(4).await;
    let router_m = build_unified_router(pool_m.clone(), None).await;
    let fix_m = seed_clean_slate_application_fixture_unsealed(
        &pool_m,
        false,
        self_did,
        Some([0x54; 32]),
        None,
    )
    .await
    .expect("multi fixture");
    let sm_p256 = http::random_p256();
    let sm_jwk = http::public_jwk(&sm_p256);
    let sm_dev = http::Device {
        did: fix_m.sender_did.clone(),
        device_id: fix_m.sender_device_id,
        jkt: http::jwk_thumbprint(&sm_jwk),
        signing: sm_p256,
        jwk: sm_jwk,
    };
    http::cache_device_did(&sm_dev).await;
    let rm1_p256 = http::random_p256();
    let rm1_jwk = http::public_jwk(&rm1_p256);
    let rm1_dev = http::Device {
        did: fix_m.recipient_did.clone(),
        device_id: fix_m.recipient_device_id,
        jkt: http::jwk_thumbprint(&rm1_jwk),
        signing: rm1_p256,
        jwk: rm1_jwk,
    };
    http::cache_device_did(&rm1_dev).await;

    let (stm, sbm) = http::send(
        router_m.clone(),
        http::unsigned_json_request(
            &sm_dev,
            "blue.catbird.chat.sendMessage",
            serde_json::to_vec(&json!({ "signedRequest": fix_m.signed_request })).unwrap(),
        ),
    )
    .await;
    assert_eq!(stm, StatusCode::OK);
    let seq_m = sbm["entry"]["seq"].as_i64().unwrap();
    age_entry_past_prune_floor(&pool_m, fix_m.conversation_id, seq_m).await;

    // Add active sibling leaf `rm2` + open `chat.application_intervals` row on `fix_m.recipient_did`.
    let rm2_id = Uuid::new_v4();
    let rm2_ed = Ed25519SigningKey::from_bytes(&[0x63; 32]);
    let rm2_pub = rm2_ed.verifying_key().to_bytes();
    let rm2_key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(rm2_pub.as_slice())
        .fetch_one(&pool_m)
        .await
        .unwrap();
    let rm2_p256 = http::random_p256();
    let rm2_jwk = http::public_jwk(&rm2_p256);
    let rm2_jkt = http::jwk_thumbprint(&rm2_jwk);
    let now_m: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&pool_m)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at, last_active_at) \
         VALUES ($1, $2, 'Recipient Sibling', 'active', $3, 1, chat.protocol_capabilities(), $4, $4, $4)",
    )
    .bind(&fix_m.recipient_did)
    .bind(rm2_id)
    .bind(&rm2_jkt)
    .bind(now_m)
    .execute(&pool_m)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO chat.device_keys (user_did, device_id, key_id, signing_public_key, enrollment_auth_generation, created_at) \
         VALUES ($1, $2, $3, $4, 1, $5)",
    )
    .bind(&fix_m.recipient_did)
    .bind(rm2_id)
    .bind(&rm2_key_id)
    .bind(rm2_pub.as_slice())
    .bind(now_m)
    .execute(&pool_m)
    .await
    .unwrap();
    let rm_period_id: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants WHERE conversation_id = $1 AND user_did = $2 AND current_membership = TRUE",
    )
    .bind(fix_m.conversation_id)
    .bind(&fix_m.recipient_did)
    .fetch_one(&pool_m)
    .await
    .unwrap();
    let rm2_leaf_id = Uuid::new_v4();
    let rm2_transition_id = Uuid::new_v4();
    {
        let mut mtx = pool_m.begin().await.unwrap();
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *mtx)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO chat.member_devices (leaf_period_id, participant_period_id, conversation_id, generation, user_did, device_id, leaf_index, basic_credential, leaf_signature_key, leaf_key_id, leaf_auth_generation, origin, joined_state_version, joined_transition_id, joined_seq, active, created_at) \
             VALUES ($1, $2, $3, 0, $4, $5, 99, $6, $7, $8, 1, 'genesis', 1, $9, 1, TRUE, $10)",
        )
        .bind(rm2_leaf_id)
        .bind(rm_period_id)
        .bind(fix_m.conversation_id)
        .bind(&fix_m.recipient_did)
        .bind(rm2_id)
        .bind(format!("{}#{rm2_id}", fix_m.recipient_did).into_bytes())
        .bind(rm2_pub.as_slice())
        .bind(&rm2_key_id)
        .bind(rm2_transition_id)
        .bind(now_m)
        .execute(&mut *mtx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO chat.application_intervals ( \
                 membership_interval_id, conversation_id, generation, recipient_did, \
                 recipient_device_id, start_seq, opening_kind, opening_transition_id, \
                 opening_outer_entry_fingerprint, opening_state_version, opening_group_id, \
                 opening_epoch, opening_group_context_hash, opening_confirmation_tag, \
                 opening_leaf_period_id, created_at \
             ) \
             SELECT $1, conversation_id, generation, recipient_did, \
                    $2, start_seq, opening_kind, $1, \
                    opening_outer_entry_fingerprint, opening_state_version, opening_group_id, \
                    opening_epoch, opening_group_context_hash, opening_confirmation_tag, \
                    $3, created_at \
               FROM chat.application_intervals \
              WHERE conversation_id = $4 AND recipient_did = $5 AND recipient_device_id = $6",
        )
        .bind(rm2_transition_id)
        .bind(rm2_id)
        .bind(rm2_leaf_id)
        .bind(fix_m.conversation_id)
        .bind(&fix_m.recipient_did)
        .bind(fix_m.recipient_device_id)
        .execute(&mut *mtx)
        .await
        .unwrap();
        mtx.commit().await.unwrap();
    }
    let rm2_dev = http::Device {
        did: fix_m.recipient_did.clone(),
        device_id: rm2_id,
        jkt: rm2_jkt,
        signing: rm2_p256,
        jwk: rm2_jwk,
    };

    let sm_ed = Ed25519SigningKey::from_bytes(&fix_m.sender_ed25519_seed);
    let rm1_ed = Ed25519SigningKey::from_bytes(&fix_m.recipient_ed25519_seed);
    let (st_m_s, bm_s) = http::send(
        router_m.clone(),
        http::unsigned_json_request(
            &sm_dev,
            "blue.catbird.chat.acknowledgeEntries",
            serde_json::to_vec(&sign_ack_entries_request(
                fix_m.sender_device_id,
                &fix_m.sender_key_id,
                1,
                &sm_ed,
                fix_m.conversation_id,
                0,
                seq_m,
            ))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(st_m_s, StatusCode::OK, "sender ACK failed: {bm_s}");
    assert_eq!(bm_s["prunedCount"], 0);

    let (st_m_r1, bm_r1) = http::send(
        router_m.clone(),
        http::unsigned_json_request(
            &rm1_dev,
            "blue.catbird.chat.acknowledgeEntries",
            serde_json::to_vec(&sign_ack_entries_request(
                fix_m.recipient_device_id,
                &fix_m.recipient_key_id,
                1,
                &rm1_ed,
                fix_m.conversation_id,
                0,
                seq_m,
            ))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(st_m_r1, StatusCode::OK, "recipient ACK failed: {bm_r1}");
    assert_eq!(
        bm_r1["prunedCount"], 1,
        "one awake recipient leaf ACK satisfies its participant after the 72-hour floor"
    );

    // The test DID cache holds one document per DID. Switch it to the sibling's
    // service-auth key only after the first leaf has finished authenticating.
    http::cache_device_did(&rm2_dev).await;
    let (st_r2, bm_r2) = http::send(
        router_m.clone(),
        http::unsigned_json_request(
            &rm2_dev,
            "blue.catbird.chat.acknowledgeEntries",
            serde_json::to_vec(&sign_ack_entries_request(
                rm2_id,
                &rm2_key_id,
                1,
                &rm2_ed,
                fix_m.conversation_id,
                0,
                seq_m,
            ))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(st_r2, StatusCode::OK);
    assert_eq!(
        bm_r2["prunedCount"], 0,
        "a later sibling ACK cannot prune the already-retained skeleton twice"
    );
    pool_m.close().await;

    // 4. Now test the 60-day dormancy threshold and 30-day application ceiling!
    let db2 = common::fresh_db::fresh_fully_migrated_db("chat_w2d_").await;
    let pool2 = db2.connect(4).await;
    let router2 = build_unified_router(pool2.clone(), None).await;
    let fix2 = seed_clean_slate_application_fixture_unsealed(
        &pool2,
        false,
        self_did,
        Some([0x52; 32]),
        None,
    )
    .await
    .expect("fixture 2");

    let s2_p256 = http::random_p256();
    let s2_jwk = http::public_jwk(&s2_p256);
    let s2_dev = http::Device {
        did: fix2.sender_did.clone(),
        device_id: fix2.sender_device_id,
        jkt: http::jwk_thumbprint(&s2_jwk),
        signing: s2_p256,
        jwk: s2_jwk,
    };
    http::cache_device_did(&s2_dev).await;

    let (st2, sb2) = http::send(
        router2.clone(),
        http::unsigned_json_request(
            &s2_dev,
            "blue.catbird.chat.sendMessage",
            serde_json::to_vec(&json!({ "signedRequest": fix2.signed_request })).unwrap(),
        ),
    )
    .await;
    assert_eq!(st2, StatusCode::OK);
    let seq_a = sb2["entry"]["seq"].as_i64().unwrap();

    // Sender acks `seq_a`, recipient does NOT ack.
    let s2_ed = Ed25519SigningKey::from_bytes(&fix2.sender_ed25519_seed);
    let ack_s2 = sign_ack_entries_request(
        fix2.sender_device_id,
        &fix2.sender_key_id,
        1,
        &s2_ed,
        fix2.conversation_id,
        0,
        seq_a,
    );
    let (st_ack, _) = http::send(
        router2.clone(),
        http::unsigned_json_request(
            &s2_dev,
            "blue.catbird.chat.acknowledgeEntries",
            serde_json::to_vec(&ack_s2).unwrap(),
        ),
    )
    .await;
    assert_eq!(st_ack, StatusCode::OK);

    // Keep sender fresh, set recipient just inside the 60-day inactivity window plus its UTC-day allowance -> NOT dormant yet!
    let ref_now = Utc::now();
    sqlx::query(
        "UPDATE chat.devices SET last_active_at = $3 WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&fix2.sender_did)
    .bind(fix2.sender_device_id)
    .bind(ref_now)
    .execute(&pool2)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE chat.devices SET last_active_at = $3 WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&fix2.recipient_did)
    .bind(fix2.recipient_device_id)
    .bind(ref_now - Duration::days(61) + Duration::minutes(1))
    .execute(&pool2)
    .await
    .unwrap();
    assert_eq!(mark_inactive_devices(&pool2, ref_now).await.unwrap(), 0);

    // Just past the 61-day coarse cutoff marks the recipient
    // dormant, but neither an empty ACK quorum nor an unqualified archive
    // watermark may prune the payload.
    sqlx::query(
        "UPDATE chat.devices SET last_active_at = $3 WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&fix2.recipient_did)
    .bind(fix2.recipient_device_id)
    .bind(ref_now - Duration::days(61) - Duration::minutes(1))
    .execute(&pool2)
    .await
    .unwrap();
    assert_eq!(mark_inactive_devices(&pool2, ref_now).await.unwrap(), 1);

    let (rec_status, rec_dormant_set, seq_a_pruned_unarchived): (String, bool, bool) =
        sqlx::query_as(
            "SELECT d.status, d.dormant_at IS NOT NULL, \
                (SELECT payload_pruned_at IS NOT NULL FROM chat.entries WHERE conversation_id = $3 AND seq = $4) \
             FROM chat.devices d WHERE d.user_did = $1 AND d.device_id = $2",
        )
        .bind(&fix2.recipient_did)
        .bind(fix2.recipient_device_id)
        .bind(fix2.conversation_id)
        .bind(seq_a)
        .fetch_one(&pool2)
        .await
        .unwrap();
    assert_eq!(rec_status, "active");
    assert!(
        rec_dormant_set,
        "dormant_at must be populated on dormancy transition"
    );
    assert!(
        !seq_a_pruned_unarchived,
        "B1(a–b): 60-day dormancy transition must NOT prune un-archived conversation when all recipient devices are dormant"
    );

    // A directly injected legacy watermark is not verified archive-content
    // evidence. Re-sending the sender ACK after 72h must still retain the
    // payload while the only recipient is dormant.
    let fix2_space_uri = format!(
        "at://{self_did}/space/blue.catbird.labyrinth.conversation/{}-0",
        fix2.conversation_id
    );
    sqlx::query(
        "INSERT INTO chat.conversation_spaces \
             (conversation_id, generation, space_uri, authority_did, archived_through_seq, created_at) \
         VALUES ($1, 0, $2, $3, $4, $5) \
         ON CONFLICT (conversation_id, generation) DO UPDATE SET archived_through_seq = EXCLUDED.archived_through_seq",
    )
    .bind(fix2.conversation_id)
    .bind(&fix2_space_uri)
    .bind(self_did)
    .bind(seq_a)
    .bind(ref_now)
    .execute(&pool2)
    .await
    .unwrap();
    age_entry_past_prune_floor(&pool2, fix2.conversation_id, seq_a).await;
    let ack_s2_after_archive = sign_ack_entries_request(
        fix2.sender_device_id,
        &fix2.sender_key_id,
        1,
        &s2_ed,
        fix2.conversation_id,
        0,
        seq_a,
    );
    let (st_ack2, body_ack2) = http::send(
        router2.clone(),
        http::unsigned_json_request(
            &s2_dev,
            "blue.catbird.chat.acknowledgeEntries",
            serde_json::to_vec(&ack_s2_after_archive).unwrap(),
        ),
    )
    .await;
    assert_eq!(st_ack2, StatusCode::OK);
    assert_eq!(
        body_ack2["prunedCount"], 0,
        "an unqualified archive watermark cannot replace the dormant recipient ACK"
    );

    // Verify the fail-closed `720h` (`30d`) application ceiling.
    let db3 = common::fresh_db::fresh_fully_migrated_db("chat_w2d_").await;
    let pool3 = db3.connect(4).await;
    let router3 = build_unified_router(pool3.clone(), None).await;
    let fix3 = seed_clean_slate_application_fixture_unsealed(
        &pool3,
        false,
        self_did,
        Some([0x53; 32]),
        None,
    )
    .await
    .expect("fixture 3");
    let s3_p256 = http::random_p256();
    let s3_jwk = http::public_jwk(&s3_p256);
    let s3_dev = http::Device {
        did: fix3.sender_did.clone(),
        device_id: fix3.sender_device_id,
        jkt: http::jwk_thumbprint(&s3_jwk),
        signing: s3_p256,
        jwk: s3_jwk,
    };
    http::cache_device_did(&s3_dev).await;
    let (st3, sb3) = http::send(
        router3.clone(),
        http::unsigned_json_request(
            &s3_dev,
            "blue.catbird.chat.sendMessage",
            serde_json::to_vec(&json!({ "signedRequest": fix3.signed_request })).unwrap(),
        ),
    )
    .await;
    assert_eq!(st3, StatusCode::OK);
    let unacked_seq = sb3["entry"]["seq"].as_i64().unwrap();

    // Un-archived at +73h and +719h: NOT pruned (`< 720h` 30d default I14 TTL)!
    assert_eq!(
        prune_expired_application_payloads(&pool3, Utc::now() + Duration::hours(73))
            .await
            .unwrap(),
        0,
        "B1(d): un-archived conversation must NOT expire at 73h"
    );
    assert_eq!(
        prune_expired_application_payloads(&pool3, Utc::now() + Duration::hours(719))
            .await
            .unwrap(),
        0,
        "B1(d): un-archived conversation must NOT expire before 720h (30d)"
    );
    // At +721h (`> 720h` 30d default TTL): pruned, while genesis control entry at `seq = 1` stays intact!
    assert_eq!(
        prune_expired_application_payloads(&pool3, Utc::now() + Duration::hours(721))
            .await
            .unwrap(),
        1
    );
    let (unacked_pruned, ctrl3_pruned): (bool, bool) = sqlx::query_as(
        "SELECT \
            (SELECT payload_pruned_at IS NOT NULL FROM chat.entries WHERE conversation_id = $1 AND seq = $2), \
            (SELECT payload_pruned_at IS NOT NULL FROM chat.entries WHERE conversation_id = $1 AND seq = 1)",
    )
    .bind(fix3.conversation_id)
    .bind(unacked_seq)
    .fetch_one(&pool3)
    .await
    .unwrap();
    assert!(
        unacked_pruned,
        "unacked applicationEntry > 720h (30d) must be pruned"
    );
    assert!(
        !ctrl3_pruned,
        "control entry at seq=1 must survive TTL sweep"
    );

    pool.close().await;
    pool2.close().await;
    pool3.close().await;
    std::env::remove_var("FEDERATION_TEST_ALLOW_ALL_RELATIONSHIPS");
    std::env::remove_var("APP_ENV");
}

// =============================================================================
// 3. Nov-12 SpaceHost + FC-03 Space Credential & Read Relays End-to-End
// =============================================================================

#[derive(Clone, Default)]
struct RecordedWebhook {
    path: String,
    body: Value,
}

#[tokio::test]
async fn nov12_space_host_and_fc03_space_relays_end_to_end() {
    let _env_guard = W2D_ENV_LOCK.lock().await;
    let authority_did = "did:web:remote-space-w2d.catbird.blue";
    let home_did = "did:web:home-space-w2d.catbird.blue";
    std::env::set_var("SERVICE_DID", home_did);
    std::env::set_var("SELF_ENDPOINT", "https://home-space-w2d.catbird.blue");

    // Start mock PDS + Space webhook receiver (`confirmRegistration` + `notifySpaceUpdate`).
    let webhooks: Arc<Mutex<Vec<RecordedWebhook>>> = Arc::new(Mutex::new(Vec::new()));
    let wh_state = Arc::clone(&webhooks);
    let webhook_router =
        Router::new()
            .route(
                "/xrpc/com.atproto.space.confirmRegistration",
                post(
                    |State(log): State<Arc<Mutex<Vec<RecordedWebhook>>>>,
                     Json(body): Json<Value>| async move {
                        let challenge = body["challenge"].as_str().unwrap_or_default().to_owned();
                        log.lock().unwrap().push(RecordedWebhook {
                            path: "/xrpc/com.atproto.space.confirmRegistration".into(),
                            body,
                        });
                        (StatusCode::OK, Json(json!({ "challenge": challenge })))
                    },
                ),
            )
            .route(
                "/xrpc/com.atproto.space.notifySpaceUpdate",
                post(
                    |State(log): State<Arc<Mutex<Vec<RecordedWebhook>>>>,
                     Json(body): Json<Value>| async move {
                        log.lock().unwrap().push(RecordedWebhook {
                            path: "/xrpc/com.atproto.space.notifySpaceUpdate".into(),
                            body,
                        });
                        StatusCode::OK
                    },
                ),
            )
            .route(
                "/xrpc/com.atproto.space.notifyCredentialsRevoked",
                post(|| async { StatusCode::OK }),
            )
            .with_state(wh_state);
    let wh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wh_addr = wh_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(wh_listener, webhook_router).await.unwrap();
    });
    let webhook_base_url = format!("http://{wh_addr}");

    // Remote `space_host` database + router (`SERVICE_DID` = `authority_did` while seeding remote Space).
    std::env::set_var("SERVICE_DID", authority_did);
    std::env::set_var("SELF_ENDPOINT", "https://remote-space-w2d.catbird.blue");
    let db_remote = common::fresh_db::fresh_fully_migrated_db("chat_w2d_").await;
    let pool_remote = db_remote.connect(4).await;
    http::ensure_fence(&pool_remote).await;
    let remote_fixture =
        seed_clean_slate_application_fixture(&pool_remote, false, authority_did, None)
            .await
            .unwrap();
    std::env::set_var("SERVICE_DID", home_did);
    std::env::set_var("SELF_ENDPOINT", "https://home-space-w2d.catbird.blue");
    let space_uri: String = sqlx::query_scalar(
        "SELECT space_uri FROM chat.conversation_spaces WHERE conversation_id = $1 AND generation = 0",
    )
    .bind(remote_fixture.conversation_id)
    .fetch_one(&pool_remote)
    .await
    .unwrap();

    let charlie_did = "did:web:charlie-space-w2d.catbird.blue";
    seed_clean_slate_active_zero_leaf_member_for_test(
        &pool_remote,
        remote_fixture.conversation_id,
        &remote_fixture.sender_did,
        charlie_did,
    )
    .await
    .expect("seed active zero-leaf member charlie");

    let authority_key = P256SigningKey::from_bytes((&[0x71_u8; 32]).into()).unwrap();
    let sender_pds_key = P256SigningKey::from_bytes((&[0x72_u8; 32]).into()).unwrap();
    let recipient_pds_key = P256SigningKey::from_bytes((&[0x73_u8; 32]).into()).unwrap();
    let charlie_pds_key = P256SigningKey::from_bytes((&[0x75_u8; 32]).into()).unwrap();
    let authority_kem = encode_p256_did_key(&P256PublicKey::from(authority_key.verifying_key()));
    let authority_doc = json!({
        "id": authority_did,
        "verificationMethod": [
            {
                "id": format!("{authority_did}#atproto"),
                "type": "Multikey",
                "controller": authority_did,
                "publicKeyMultibase": authority_kem.strip_prefix("did:key:").unwrap(),
            },
            {
                "id": "#atproto_kem",
                "type": "Multikey",
                "controller": authority_did,
                "publicKeyMultibase": authority_kem.strip_prefix("did:key:").unwrap(),
            }
        ]
    });

    let remote_host = Arc::new(SpaceHostRuntime::new(
        pool_remote.clone(),
        SpaceHostConfig::for_test(authority_did.to_owned(), authority_key.clone()),
    ));
    remote_host.register_test_did_endpoint(
        authority_did,
        authority_key.verifying_key(),
        &webhook_base_url,
    );
    remote_host.register_test_did_endpoint(
        &remote_fixture.sender_did,
        sender_pds_key.verifying_key(),
        &webhook_base_url,
    );
    remote_host.register_test_did_endpoint(
        &remote_fixture.recipient_did,
        recipient_pds_key.verifying_key(),
        &webhook_base_url,
    );
    remote_host.register_test_did_endpoint(
        charlie_did,
        charlie_pds_key.verifying_key(),
        &webhook_base_url,
    );
    let remote_router = space_host_router(Arc::clone(&remote_host)).route(
        "/.well-known/did.json",
        get({
            let doc = authority_doc.clone();
            move || {
                let doc = doc.clone();
                async move { Json(doc) }
            }
        }),
    );
    let remote_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(remote_listener, remote_router).await.unwrap();
    });
    register_test_space_relay_target(authority_did, &format!("http://{remote_addr}"));

    // Home `mls-ds` database + router for `sender_did` and `charlie_did`.
    let db_home = common::fresh_db::fresh_fully_migrated_db("chat_w2d_").await;
    let pool_home = db_home.connect(4).await;
    let home_router = build_unified_router(pool_home.clone(), None).await;
    let user_did = remote_fixture.sender_did.clone();
    let home_dev_id = Uuid::new_v4();
    let home_p256 = http::random_p256();
    let home_jwk = http::public_jwk(&home_p256);
    let home_jkt = http::jwk_thumbprint(&home_jwk);
    sqlx::query(
        "INSERT INTO chat.principals (user_did, created_at) VALUES ($1, clock_timestamp()) ON CONFLICT DO NOTHING",
    )
    .bind(&user_did)
    .execute(&pool_home)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at) \
         VALUES ($1, $2, 'Home Mac', 'active', $3, 1, chat.protocol_capabilities(), clock_timestamp(), clock_timestamp())",
    )
    .bind(&user_did)
    .bind(home_dev_id)
    .bind(&home_jkt)
    .execute(&pool_home)
    .await
    .unwrap();
    let home_dev = http::Device {
        did: user_did.clone(),
        device_id: home_dev_id,
        jkt: home_jkt,
        signing: home_p256,
        jwk: home_jwk,
    };
    http::cache_device_did(&home_dev).await;

    let charlie_dev_id = Uuid::new_v4();
    let charlie_p256 = http::random_p256();
    let charlie_jwk = http::public_jwk(&charlie_p256);
    let charlie_jkt = http::jwk_thumbprint(&charlie_jwk);
    sqlx::query(
        "INSERT INTO chat.principals (user_did, created_at) VALUES ($1, clock_timestamp()) ON CONFLICT DO NOTHING",
    )
    .bind(charlie_did)
    .execute(&pool_home)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at) \
         VALUES ($1, $2, 'Charlie Phone', 'active', $3, 1, chat.protocol_capabilities(), clock_timestamp(), clock_timestamp())",
    )
    .bind(charlie_did)
    .bind(charlie_dev_id)
    .bind(&charlie_jkt)
    .execute(&pool_home)
    .await
    .unwrap();
    let charlie_home_dev = http::Device {
        did: charlie_did.to_owned(),
        device_id: charlie_dev_id,
        jkt: charlie_jkt,
        signing: charlie_p256,
        jwk: charlie_jwk,
    };
    http::cache_device_did(&charlie_home_dev).await;

    // 1. `relaySpaceCredential` with `notify` triggers `confirmRegistration` challenge and returns
    //    millisecond `.000Z` `expiresAt`.
    let now_sec = Utc::now().timestamp() as u64;
    let pop_key = P256SigningKey::from_bytes((&[0x74_u8; 32]).into()).unwrap();
    let cnf_kid = encode_p256_did_key(&P256PublicKey::from(pop_key.verifying_key()));
    let del_token = mint_space_token(
        SpaceTokenKind::Delegation,
        &SpaceSigningKey::P256 {
            signing_key: sender_pds_key.clone(),
            kid: "#atproto".to_string(),
        },
        &SpaceTokenClaims {
            iss: user_did.clone(),
            sub: space_uri.clone(),
            aud: Some(format!("{authority_did}#atproto_pds")),
            iat: now_sec,
            exp: now_sec + 60,
            jti: "w2d-del-1".into(),
            cnf_kid: None,
        },
    )
    .unwrap();

    let syncer_token = "w2d-subscriber-token-0123456789abcdef";
    let (cred_status, cred_body) = http::send(
        home_router.clone(),
        http::unsigned_json_request(
            &home_dev,
            "blue.catbird.chat.relaySpaceCredential",
            serde_json::to_vec(&json!({
                "actorDeviceId": home_dev_id,
                "authorityDid": authority_did,
                "space": space_uri,
                "delegationToken": del_token,
                "cnfKey": cnf_kid,
                "notify": {
                    "endpoint": webhook_base_url,
                    "token": syncer_token,
                },
            }))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(
        cred_status,
        StatusCode::OK,
        "relaySpaceCredential failed: {cred_body}"
    );
    let cred_jwt = cred_body["credential"].as_str().unwrap().to_owned();
    assert!(
        cred_body["expiresAt"].as_str().unwrap().ends_with(".000Z"),
        "expiresAt must use Nov-12 .000Z format: {}",
        cred_body["expiresAt"]
    );
    assert!(
        webhooks
            .lock()
            .unwrap()
            .iter()
            .any(|w| w.path == "/xrpc/com.atproto.space.confirmRegistration"),
        "authorizeSpaceSync must challenge notify endpoint via confirmRegistration"
    );

    // Publish writer repo updates from `sender_did` and `charlie_did` so `spaceRev` advances and
    // `notifySpaceUpdate` (`#repoWrite`) is pushed to the confirmed subscriber!
    for (writer_did, writer_key, repo_rev, fill) in [
        (user_did.as_str(), &sender_pds_key, "3k2aaaaaaaaaa", 0x11_u8),
        (charlie_did, &charlie_pds_key, "3k2aaaaaaaaab", 0x22_u8),
    ] {
        let now = Utc::now().timestamp();
        let nw_jwt = sign_es256_jwt(
            json!({"alg": "ES256", "typ": "JWT"}),
            json!({
                "iss": writer_did,
                "aud": format!("{authority_did}#atproto_mls"),
                "lxm": "com.atproto.space.notifyRepoUpdate",
                "iat": now,
                "exp": now + 60,
                "jti": Uuid::new_v4().to_string(),
            }),
            writer_key,
        );
        let nw_resp = reqwest::Client::new()
            .post(format!(
                "http://{remote_addr}/xrpc/com.atproto.space.notifyRepoUpdate"
            ))
            .header("authorization", format!("Bearer {nw_jwt}"))
            .json(&json!({
                "space": space_uri,
                "repo": writer_did,
                "repoRev": repo_rev,
                "data": { "$bytes": STANDARD.encode([fill; 32]) },
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(nw_resp.status(), reqwest::StatusCode::OK);
    }

    // Subsequent `relaySpaceCredential` returns the populated `spaceRev`!
    let del_token_rev = mint_space_token(
        SpaceTokenKind::Delegation,
        &SpaceSigningKey::P256 {
            signing_key: sender_pds_key.clone(),
            kid: "#atproto".to_string(),
        },
        &SpaceTokenClaims {
            iss: user_did.clone(),
            sub: space_uri.clone(),
            aud: Some(format!("{authority_did}#atproto_pds")),
            iat: now_sec,
            exp: now_sec + 60,
            jti: "w2d-del-spacerev".into(),
            cnf_kid: None,
        },
    )
    .unwrap();
    let (cred2_status, cred2_body) = http::send(
        home_router.clone(),
        http::unsigned_json_request(
            &home_dev,
            "blue.catbird.chat.relaySpaceCredential",
            serde_json::to_vec(&json!({
                "actorDeviceId": home_dev_id,
                "authorityDid": authority_did,
                "space": space_uri,
                "delegationToken": del_token_rev,
                "cnfKey": cnf_kid,
            }))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(cred2_status, StatusCode::OK);
    assert!(
        cred2_body["spaceRev"].as_str().is_some(),
        "authorizeSpaceSync must return current spaceRev once writers publish: {cred2_body}"
    );

    // 2. `relaySpaceRead` allows `com.atproto.space.listWriters`, forwards `acceptSignature`, and
    //    preserves `Atproto-Space-Commit`, `Signature-Input`, `Signature`, and `Vary`!
    let encap = encapsulate_p256(&authority_kem).expect("encapsulate P-256");
    let accept_sig = format_accept_signature(MacProfile::Commit, &encap.key_share_did_key).unwrap();
    let pop_secret = P256Secret::from_slice(&pop_key.to_bytes()).unwrap();
    let signed_hdrs = sign_credential_request(
        &pop_secret,
        &cred_jwt,
        authority_did,
        now_sec,
        "w2d-list-writers-1",
    )
    .unwrap();
    let list_req = http::unsigned_json_request(
        &home_dev,
        "blue.catbird.chat.relaySpaceRead",
        serde_json::to_vec(&json!({
            "actorDeviceId": home_dev_id,
            "targetDid": authority_did,
            "nsid": "com.atproto.space.listWriters",
            "query": format!("space={}&limit=20", urlencoding::encode(&space_uri)),
            "credential": cred_jwt,
            "spaceAudience": authority_did,
            "acceptSignature": accept_sig,
            "signatureInput": signed_hdrs.signature_input,
            "signature": signed_hdrs.signature,
        }))
        .unwrap(),
    );
    let list_resp = home_router.clone().oneshot(list_req).await.unwrap();
    assert_eq!(list_resp.status(), StatusCode::OK);
    for expected_header in [
        "atproto-space-commit",
        "signature-input",
        "signature",
        "vary",
    ] {
        assert!(
            list_resp.headers().get(expected_header).is_some(),
            "relaySpaceRead must preserve response header {expected_header}"
        );
    }
    let list_bytes = axum::body::to_bytes(list_resp.into_body(), 65_536)
        .await
        .unwrap();
    let list_json: Value = serde_json::from_slice(&list_bytes).unwrap();
    assert_eq!(
        list_json["repos"].as_array().unwrap().len(),
        2,
        "listWriters must return published writers: {list_json}"
    );

    // 3. `removeWriter` on remote `space_host` emits `#repoRemoved` tombstone and pushes
    //    `notifySpaceUpdate` (`#repoRemoved`) to the confirmed subscriber; removing `charlie_did`
    //    from conversation membership causes `relaySpaceCredential` to return HTTP `403` forwarding
    //    the authority's signed `denial` JWT byte-for-byte!
    webhooks.lock().unwrap().clear();
    let owner_jwt = {
        let now = Utc::now().timestamp();
        sign_es256_jwt(
            json!({"alg": "ES256", "typ": "JWT"}),
            json!({
                "iss": authority_did,
                "aud": format!("{authority_did}#atproto_mls"),
                "lxm": "com.atproto.space.removeWriter",
                "iat": now,
                "exp": now + 60,
                "jti": Uuid::new_v4().to_string(),
            }),
            &authority_key,
        )
    };
    let rm_resp = reqwest::Client::new()
        .post(format!(
            "http://{remote_addr}/xrpc/com.atproto.space.removeWriter"
        ))
        .header("authorization", format!("Bearer {owner_jwt}"))
        .json(&json!({
            "space": space_uri,
            "repo": charlie_did,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rm_resp.status(), reqwest::StatusCode::OK);

    for _ in 0..20 {
        if webhooks
            .lock()
            .unwrap()
            .iter()
            .any(|w| w.path == "/xrpc/com.atproto.space.notifySpaceUpdate")
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(
        webhooks
            .lock()
            .unwrap()
            .iter()
            .any(|w| w.path == "/xrpc/com.atproto.space.notifySpaceUpdate"),
        "removeWriter must fan out notifySpaceUpdate to registered subscriber"
    );

    seed_clean_slate_remove_zero_leaf_member_for_test(
        &pool_remote,
        remote_fixture.conversation_id,
        &remote_fixture.sender_did,
        charlie_did,
    )
    .await
    .expect("remove charlie from conversation membership");

    let del_token_2 = mint_space_token(
        SpaceTokenKind::Delegation,
        &SpaceSigningKey::P256 {
            signing_key: charlie_pds_key,
            kid: "#atproto".to_string(),
        },
        &SpaceTokenClaims {
            iss: charlie_did.to_owned(),
            sub: space_uri.clone(),
            aud: Some(format!("{authority_did}#atproto_pds")),
            iat: now_sec,
            exp: now_sec + 60,
            jti: "w2d-del-removed".into(),
            cnf_kid: None,
        },
    )
    .unwrap();
    let (denied_status, denied_bytes) = http::send_bytes(
        home_router.clone(),
        http::unsigned_json_request(
            &charlie_home_dev,
            "blue.catbird.chat.relaySpaceCredential",
            serde_json::to_vec(&json!({
                "actorDeviceId": charlie_dev_id,
                "authorityDid": authority_did,
                "space": space_uri,
                "delegationToken": del_token_2,
                "cnfKey": cnf_kid,
                "notify": {
                    "endpoint": webhook_base_url,
                    "token": syncer_token,
                },
            }))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(
        denied_status,
        StatusCode::FORBIDDEN,
        "removed member relaySpaceCredential must return 403 Forbidden"
    );
    let denied_json: Value = serde_json::from_slice(&denied_bytes).unwrap();
    assert_eq!(denied_json["error"], "NotAuthorized");
    assert!(
        denied_json["denial"]
            .as_str()
            .is_some_and(|jws| jws.split('.').count() == 3),
        "403 refusal must forward signed Space denial JWT byte-for-byte: {denied_json}"
    );

    pool_home.close().await;
    pool_remote.close().await;
}

// =============================================================================
// 4. D-1 Signed getMailboxKeysRecord CARv1 + ATProto v3 Commit + MST Proofs Over HTTP
// =============================================================================

fn sample_mailbox_value(epoch_number: i64) -> Value {
    let bytes = |len| json!({ "$bytes": STANDARD.encode(vec![0x42_u8; len]) });
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
        "updatedAt": "2026-11-14T00:00:00Z",
    })
}

#[tokio::test]
async fn d1_get_mailbox_keys_record_verifies_signed_car_proofs_over_http() {
    let _env_guard = W2D_ENV_LOCK.lock().await;
    std::env::set_var("SERVICE_DID", "did:web:chat.catbird.blue");
    std::env::set_var("SELF_ENDPOINT", "https://chat.catbird.blue");

    let target_did = "did:web:mailbox-target-w2d.catbird.blue";
    let pds_secret = P256Secret::from_slice(&[0x81_u8; 32]).unwrap();
    let wrong_secret = P256Secret::from_slice(&[0x82_u8; 32]).unwrap();
    let pds_did_key = encode_p256_did_key(&pds_secret.public_key());

    let val_7 = sample_mailbox_value(7);
    let (valid_car, valid_cids) = build_signed_repo_car(
        target_did,
        "3l2aaaaaaaaaa",
        &pds_secret,
        &[("blue.catbird.labyrinth.mailboxKeys/000000000007", &val_7)],
    );
    let (wrong_sig_car, _) = build_signed_repo_car(
        target_did,
        "3l2aaaaaaaaaa",
        &wrong_secret,
        &[("blue.catbird.labyrinth.mailboxKeys/000000000007", &val_7)],
    );
    let mut tampered_car = valid_car.clone();
    if let Some(last) = tampered_car.last_mut() {
        *last ^= 0xff;
    }
    let val_overflow = sample_mailbox_value(1_000_000_000_000);
    let (overflow_car, _) = build_signed_repo_car(
        target_did,
        "3l2aaaaaaaaaa",
        &pds_secret,
        &[("blue.catbird.labyrinth.mailboxKeys/self", &val_overflow)],
    );

    // Modes:
    // 0 -> valid signed CARv1 (includes `000000000007`, proves non-inclusion for `self`)
    // 1 -> unsigned 404 JSON (`{"error":"RecordNotFound"}`)
    // 2 -> unsigned 200 JSON (`{"uri":...,"value":...}`)
    // 3 -> CARv1 signed by wrong `#atproto` key
    // 4 -> tampered CARv1 block bytes
    // 5 -> CARv1 with `epochNumber = 1_000_000_000_000` (`> 999_999_999_999`)
    let mode = Arc::new(AtomicUsize::new(0));
    let upstream_hits = Arc::new(AtomicUsize::new(0));

    let pds_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pds_addr = pds_listener.local_addr().unwrap();
    let multibase = pds_did_key.strip_prefix("did:key:").unwrap().to_owned();
    let pds_router = Router::new()
        .route(
            "/.well-known/did.json",
            get({
                let multibase = multibase.clone();
                move || {
                    let multibase = multibase.clone();
                    async move {
                        Json(json!({
                            "id": target_did,
                            "verificationMethod": [{
                                "id": format!("{target_did}#atproto"),
                                "type": "Multikey",
                                "controller": target_did,
                                "publicKeyMultibase": multibase,
                            }],
                            "service": [{
                                "id": "#atproto_pds",
                                "type": "AtprotoPersonalDataServer",
                                "serviceEndpoint": "https://mailbox-pds-w2d.catbird.blue",
                            }],
                        }))
                    }
                }
            }),
        )
        .route(
            "/xrpc/com.atproto.sync.getRecord",
            get({
                let mode = Arc::clone(&mode);
                let hits = Arc::clone(&upstream_hits);
                let valid_car = Arc::new(valid_car);
                let wrong_sig_car = Arc::new(wrong_sig_car);
                let tampered_car = Arc::new(tampered_car);
                let overflow_car = Arc::new(overflow_car);
                let val_7 = val_7.clone();
                move |Query(q): Query<BTreeMap<String, String>>, headers: HeaderMap| {
                    let mode = Arc::clone(&mode);
                    let hits = Arc::clone(&hits);
                    let valid_car = Arc::clone(&valid_car);
                    let wrong_sig_car = Arc::clone(&wrong_sig_car);
                    let tampered_car = Arc::clone(&tampered_car);
                    let overflow_car = Arc::clone(&overflow_car);
                    let val_7 = val_7.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(q.get("did").map(String::as_str), Some(target_did));
                        assert_eq!(
                            q.get("collection").map(String::as_str),
                            Some("blue.catbird.labyrinth.mailboxKeys")
                        );
                        assert!(
                            headers.get("authorization").is_none(),
                            "caller auth must never leak to remote PDS"
                        );
                        match mode.load(Ordering::SeqCst) {
                            1 => (
                                StatusCode::NOT_FOUND,
                                Json(json!({"error": "RecordNotFound"})),
                            )
                                .into_response(),
                            2 => (
                                StatusCode::OK,
                                Json(json!({
                                    "uri": format!("at://{target_did}/blue.catbird.labyrinth.mailboxKeys/000000000007"),
                                    "cid": "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                    "value": val_7,
                                })),
                            )
                                .into_response(),
                            3 => (
                                [(axum::http::header::CONTENT_TYPE, "application/vnd.ipld.car")],
                                wrong_sig_car.as_ref().clone(),
                            )
                                .into_response(),
                            4 => (
                                [(axum::http::header::CONTENT_TYPE, "application/vnd.ipld.car")],
                                tampered_car.as_ref().clone(),
                            )
                                .into_response(),
                            5 => (
                                [(axum::http::header::CONTENT_TYPE, "application/vnd.ipld.car")],
                                overflow_car.as_ref().clone(),
                            )
                                .into_response(),
                            _ => (
                                [(axum::http::header::CONTENT_TYPE, "application/vnd.ipld.car")],
                                valid_car.as_ref().clone(),
                            )
                                .into_response(),
                        }
                    }
                }
            }),
        );
    tokio::spawn(async move {
        axum::serve(pds_listener, pds_router).await.unwrap();
    });

    let db = common::fresh_db::fresh_fully_migrated_db("chat_w2d_").await;
    let pool = db.connect(4).await;
    let resolver = Arc::new(
        DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:chat.catbird.blue".to_owned(),
            "https://chat.example.net".to_owned(),
            None,
            300,
        )
        .with_destination_resolver_hook(Arc::new(move |target_url: &str| {
            let remote = Url::parse(target_url).unwrap();
            let mut local = Url::parse(&format!("http://127.0.0.1:{}/", pds_addr.port())).unwrap();
            local.set_path(remote.path());
            local.set_query(remote.query());
            Some(Box::pin(async move {
                Ok(ValidatedRemoteDestination {
                    url: local,
                    host: "127.0.0.1".to_owned(),
                    addrs: vec![pds_addr],
                })
            }))
        })),
    );
    let router = build_unified_router(pool.clone(), Some(resolver)).await;

    let caller_acct = AccountIdentity::create().await;
    let caller_dev = DeviceIdentity::build(&caller_acct, "Caller iPhone", 1);
    let (en_st, en_body) = http::send(router.clone(), caller_dev.enroll_request()).await;
    assert_eq!(en_st, StatusCode::OK, "caller enroll: {en_body}");

    // 1. Valid signed CARv1 + ATProto v3 commit + MST inclusion -> `200 OK` `{ uri, cid, value }`!
    let (ok_status, ok_body) = http::send(
        router.clone(),
        caller_dev.labyrinth_fixed_get_request(
            "getMailboxKeysRecord",
            &[("did", target_did), ("rkey", "000000000007")],
        ),
    )
    .await;
    assert_eq!(
        ok_status,
        StatusCode::OK,
        "verified CAR inclusion must return 200 OK: {ok_body}"
    );
    assert_eq!(
        ok_body["uri"],
        format!("at://{target_did}/blue.catbird.labyrinth.mailboxKeys/000000000007")
    );
    assert_eq!(
        ok_body["cid"],
        valid_cids["blue.catbird.labyrinth.mailboxKeys/000000000007"].to_string()
    );
    assert_eq!(ok_body["value"]["current"]["epochNumber"], 7);

    // 2. Valid signed CARv1 + ATProto v3 commit + MST non-inclusion (`rkey = "self"`) -> `404 RecordNotFound`!
    let (nf_status, nf_body) = http::send(
        router.clone(),
        caller_dev.labyrinth_fixed_get_request(
            "getMailboxKeysRecord",
            &[("did", target_did), ("rkey", "self")],
        ),
    )
    .await;
    assert_eq!(nf_status, StatusCode::NOT_FOUND);
    assert_eq!(nf_body["error"], "RecordNotFound");

    // 3. Unsigned `404` JSON, unsigned `200` JSON, wrong commit signature, tampered block, and
    //    `epochNumber > 999_999_999_999` ALL fail closed with `502 UpstreamError`!
    for (bad_mode, bad_rkey, label) in [
        (1usize, "000000000007", "unsigned 404 RecordNotFound JSON"),
        (2usize, "000000000007", "unsigned 200 getRecord JSON"),
        (3usize, "000000000007", "wrong #atproto commit signature"),
        (4usize, "000000000007", "tampered CAR block bytes"),
        (5usize, "self", "epochNumber > 999_999_999_999"),
    ] {
        mode.store(bad_mode, Ordering::SeqCst);
        let (bad_status, bad_body) = http::send(
            router.clone(),
            caller_dev.labyrinth_fixed_get_request(
                "getMailboxKeysRecord",
                &[("did", target_did), ("rkey", bad_rkey)],
            ),
        )
        .await;
        assert_eq!(
            bad_status,
            StatusCode::BAD_GATEWAY,
            "{label} must fail closed with 502 Bad Gateway: {bad_body}"
        );
        assert_eq!(bad_body["error"], "UpstreamError", "{label}: {bad_body}");
    }

    // 4. Strict lowercase RFC 4122 UUIDv4 device-ID check (`D-01/D-08`) rejects uppercase UUID
    //    and nil/v1 UUID with `400 InvalidRequest` across fixed-query ReadClaim, query-param
    //    `actorDeviceId`, and `relaySpaceRead` BEFORE touching upstream!
    let hits_before = upstream_hits.load(Ordering::SeqCst);
    let upper_id = caller_dev.device_id.to_string().to_ascii_uppercase();
    for bad_actor_id in [
        upper_id.as_str(),
        "00000000-0000-0000-0000-000000000000",
        "550e8400-e29b-11d4-a716-446655440000",
    ] {
        let (fixed_st, fixed_body) = http::send(
            router.clone(),
            caller_dev.labyrinth_fixed_get_request_with_raw_device_id(
                "getMailboxKeysRecord",
                bad_actor_id,
                &[("did", target_did), ("rkey", "000000000007")],
            ),
        )
        .await;
        assert_eq!(
            fixed_st,
            StatusCode::BAD_REQUEST,
            "non-canonical ReadClaim deviceId {bad_actor_id} must be rejected: {fixed_body}"
        );
        assert_eq!(fixed_body["error"], "InvalidRequest");

        let (query_st, query_body) = http::send(
            router.clone(),
            caller_dev.labyrinth_get_request_with_raw_actor_id(
                "getChatDeviceKeys",
                bad_actor_id,
                &[("did", &caller_acct.did)],
            ),
        )
        .await;
        assert_eq!(
            query_st,
            StatusCode::BAD_REQUEST,
            "non-canonical query actorDeviceId {bad_actor_id} must be rejected: {query_body}"
        );
        assert_eq!(query_body["error"], "InvalidRequest");

        let (space_st, space_body) = http::send(
            router.clone(),
            caller_dev.bearer_post_request(
                "blue.catbird.chat.relaySpaceRead",
                &json!({
                    "actorDeviceId": bad_actor_id,
                    "targetDid": "did:web:chat.catbird.blue",
                    "nsid": "com.atproto.space.listWriters",
                    "credential": "header.payload.sig",
                    "spaceAudience": "did:web:chat.catbird.blue",
                    "signatureInput": "sig1=(\"@method\")",
                    "signature": "sig1=:AA==:",
                }),
            ),
        )
        .await;
        assert_eq!(
            space_st,
            StatusCode::BAD_REQUEST,
            "non-canonical Space relay actorDeviceId {bad_actor_id} must be rejected: {space_body}"
        );
        assert_eq!(space_body["error"], "InvalidRequest");
    }
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        hits_before,
        "invalid actorDeviceId must fail before any outbound PDS request"
    );

    pool.close().await;
}

// ===========================================================================
// R2 Regression Suites (`#69` Findings 1–5)
// ===========================================================================

#[derive(Clone, Copy)]
struct EpochLink {
    signing_seed: [u8; 32],
    head: [u8; 32],
}

fn xeddsa_pub(k: [u8; 32]) -> [u8; 32] {
    use curve25519_dalek::montgomery::MontgomeryPoint;
    MontgomeryPoint::mul_base_clamped(k).to_bytes()
}

fn xeddsa_sign(k: [u8; 32], msg: &[u8]) -> [u8; 64] {
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::scalar::{clamp_integer, Scalar};
    use sha2::Sha512;

    let mut a = Scalar::from_bytes_mod_order(clamp_integer(k));
    let mut a_point = EdwardsPoint::mul_base(&a);
    if a_point.compress().as_bytes()[31] >> 7 == 1 {
        a = -a;
        a_point = -a_point;
    }
    let nonce: [u8; 64] = Sha512::digest([&k[..], msg].concat()).into();
    let r = Scalar::from_bytes_mod_order_wide(&nonce);
    let r_bytes = EdwardsPoint::mul_base(&r).compress().to_bytes();
    let mut h = Sha512::new();
    h.update(r_bytes);
    h.update(a_point.compress().as_bytes());
    h.update(msg);
    let h = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice((r + h * a).as_bytes());
    sig
}

fn build_epoch_public_for_device(
    dev: &DeviceIdentity,
    epoch_number: u64,
    signing_seed: [u8; 32],
    prev: Option<EpochLink>,
    prev_signer_override: Option<[u8; 32]>,
) -> (Value, EpochLink) {
    let bytes_json = |raw: &[u8]| json!({ "$bytes": STANDARD.encode(raw) });
    let auth = [epoch_number as u8 ^ signing_seed[0] ^ 0x21; 32];
    let enc = vec![epoch_number as u8 ^ signing_seed[0] ^ 0x42; 1216];
    let signing = xeddsa_pub(signing_seed);
    let members_hash = [epoch_number as u8 ^ signing_seed[0] ^ 0x55; 32];
    let head = compute_epoch_head(
        epoch_number,
        &auth,
        &enc,
        &signing,
        &members_hash,
        prev.as_ref().map(|p| &p.head),
        &dev.did,
    );
    let self_sig = xeddsa_sign(
        signing_seed,
        &[
            b"minos.unstructured_signature.epoch_self:".as_slice(),
            &head,
        ]
        .concat(),
    );
    let chat_pub = dev.device_signing.verifying_key().to_bytes();
    let att_sig = dev
        .device_signing
        .sign(&attestation_message(&dev.did, &head))
        .to_bytes();
    let mut val = json!({
        "epochNumber": epoch_number,
        "authPubkey": bytes_json(&auth),
        "encryptionPubkey": bytes_json(&enc),
        "signingPubkey": bytes_json(&signing),
        "membersHash": bytes_json(&members_hash),
        "epochHead": bytes_json(&head),
        "selfSig": bytes_json(&self_sig),
        "attestation": {
            "transportPubkey": bytes_json(&chat_pub),
            "sig": bytes_json(&att_sig),
        },
    });
    if let Some(p) = prev {
        let signer = prev_signer_override.unwrap_or(p.signing_seed);
        let prev_sig = xeddsa_sign(
            signer,
            &[
                b"minos.unstructured_signature.epoch_prev:".as_slice(),
                &head,
            ]
            .concat(),
        );
        val["previousEpochHead"] = bytes_json(&p.head);
        val["prevSig"] = bytes_json(&prev_sig);
    }
    (val, EpochLink { signing_seed, head })
}

#[tokio::test]
async fn r2_pending_approval_get_own_devices_labyrinth_self_reads_and_epoch_self_promotion() {
    let _env_guard = W2D_ENV_LOCK.lock().await;
    std::env::set_var("SERVICE_DID", "did:web:chat.catbird.blue");
    std::env::set_var("SELF_ENDPOINT", "https://chat.example.net");

    let db = common::fresh_db::fresh_fully_migrated_db("chat_w2d_").await;
    let pool = db.connect(6).await;

    let alice_did = "did:web:alice-recovery-r2.catbird.blue".to_owned();
    let pds_secret = P256Secret::from_slice(&[0x61_u8; 32]).unwrap();
    let alice_signing = p256::ecdsa::SigningKey::from_slice(&[0x61_u8; 32]).unwrap();
    let pds_multibase = encode_p256_did_key(&pds_secret.public_key())
        .strip_prefix("did:key:")
        .unwrap()
        .to_owned();
    catbird_server::auth::cache_test_did_document(catbird_server::auth::DidDocument {
        id: alice_did.clone(),
        verification_method: vec![catbird_server::auth::VerificationMethod {
            id: format!("{alice_did}#atproto"),
            key_type: "Multikey".to_string(),
            controller: alice_did.clone(),
            public_key_jwk: None,
            public_key_multibase: Some(pds_multibase.clone()),
        }],
        service: Some(vec![catbird_server::auth::Service {
            id: "#atproto_pds".to_string(),
            service_type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: "https://alice-pds-r2.catbird.blue".to_string(),
        }]),
    })
    .await;
    let alice_acct = AccountIdentity {
        did: alice_did,
        atproto_signing: alice_signing,
    };
    let bob_acct = AccountIdentity::create().await;

    // Spin up a signed CARv1 PDS stub for `alice_acct.did` so `getMailboxKeysRecord` self-read
    // exercises full CARv1 + ATProto v3 commit verification on a `pending_approval` device.
    let mbx_val = sample_mailbox_value(1);
    let (car_bytes, _) = build_signed_repo_car(
        &alice_acct.did,
        "3l2aaaaaaaaaa",
        &pds_secret,
        &[("blue.catbird.labyrinth.mailboxKeys/self", &mbx_val)],
    );
    let pds_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pds_addr = pds_listener.local_addr().unwrap();
    let pds_did = alice_acct.did.clone();
    let did_doc_handler = {
        let multibase = pds_multibase;
        let did = pds_did.clone();
        move || {
            let multibase = multibase.clone();
            let did = did.clone();
            async move {
                Json(json!({
                    "id": did,
                    "verificationMethod": [{
                        "id": format!("{did}#atproto"),
                        "type": "Multikey",
                        "controller": did,
                        "publicKeyMultibase": multibase,
                    }],
                    "service": [
                        {
                            "id": "#atproto_pds",
                            "type": "AtprotoPersonalDataServer",
                            "serviceEndpoint": "https://alice-pds-r2.catbird.blue",
                        },
                        {
                            "id": "#catbird_mls_ds",
                            "type": "CatbirdMlsDeliveryService",
                            "serviceEndpoint": "https://chat.example.net",
                        }
                    ],
                }))
            }
        }
    };
    let pds_router = Router::new()
        .route("/.well-known/did.json", get(did_doc_handler.clone()))
        .route(&format!("/{pds_did}"), get(did_doc_handler))
        .route(
            "/xrpc/com.atproto.sync.getRecord",
            get({
                let car = Arc::new(car_bytes);
                move || {
                    let car = Arc::clone(&car);
                    async move {
                        (
                            [(axum::http::header::CONTENT_TYPE, "application/vnd.ipld.car")],
                            car.as_ref().clone(),
                        )
                            .into_response()
                    }
                }
            }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(pds_listener, pds_router).await;
    });

    let resolver = Arc::new(
        DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:chat.catbird.blue".to_owned(),
            "https://chat.example.net".to_owned(),
            None,
            300,
        )
        .with_user_did_resolver_hook(Arc::new(|_did| {
            Some(Ok(catbird_server::federation::resolver::DsEndpoint {
                did: "did:web:chat.catbird.blue".to_owned(),
                endpoint: "https://chat.example.net".to_owned(),
                supported_cipher_suites: None,
                federation_capabilities: None,
            }))
        }))
        .with_destination_resolver_hook(Arc::new(move |target_url: &str| {
            let remote = Url::parse(target_url).unwrap();
            let mut local = Url::parse(&format!("http://127.0.0.1:{}/", pds_addr.port())).unwrap();
            local.set_path(remote.path());
            local.set_query(remote.query());
            Some(Box::pin(async move {
                Ok(ValidatedRemoteDestination {
                    url: local,
                    host: "127.0.0.1".to_owned(),
                    addrs: vec![pds_addr],
                })
            }))
        })),
    );
    let router = build_unified_router(pool.clone(), Some(resolver)).await;

    // 1. Genesis `epoch = 0` self-promotion guard on Bob (`latest.is_none()`):
    //    Enroll `bob_d1` (`active`, 0 epoch heads published) and `bob_d2` (`pending_approval`).
    //    `bob_d2` MUST be rejected (`401 NotAuthorized`) on genesis while the
    //    notice hold is fresh and while Bob's first device remains awake.
    let bob_d1 = DeviceIdentity::build(&bob_acct, "Bob Phone", 2);
    let bob_d2 = DeviceIdentity::build(&bob_acct, "Bob Unapproved", 2);
    let (st_b1, b1_body) = http::send(router.clone(), bob_d1.enroll_request()).await;
    assert_eq!(st_b1, StatusCode::OK, "{b1_body}");
    assert_eq!(b1_body["device"]["status"], "active");
    let (st_b2, b2_body) = http::send(router.clone(), bob_d2.enroll_request()).await;
    assert_eq!(st_b2, StatusCode::OK, "{b2_body}");
    assert_eq!(b2_body["device"]["status"], "pending_approval");

    let (bob_genesis_epoch, _bob_link0) =
        build_epoch_public_for_device(&bob_d2, 0, [0x11_u8; 32], None, None);
    let (st_bob_gen, bob_gen_body) = http::send(
        router.clone(),
        bob_d2.labyrinth_post_request(
            "publishEpochHead",
            &json!({ "epoch": bob_genesis_epoch.clone() }),
        ),
    )
    .await;
    assert_eq!(
        st_bob_gen,
        StatusCode::UNAUTHORIZED,
        "pending genesis must wait for the notice hold: {bob_gen_body}"
    );
    assert_eq!(bob_gen_body["error"], "NotAuthorized");
    let bob_d2_status_db: String = sqlx::query_scalar(
        "SELECT status FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&bob_acct.did)
    .bind(bob_d2.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(bob_d2_status_db, "pending_approval");

    {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE chat.device_promotion_audit \
                SET recorded_at = clock_timestamp() - interval '73 hours' \
              WHERE user_did = $1 AND device_id = $2 AND event_kind = 'pending_notice'",
        )
        .bind(&bob_acct.did)
        .bind(bob_d2.device_id)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let (bob_aged_status, bob_aged_body) = http::send(
        router.clone(),
        bob_d2.labyrinth_post_request("publishEpochHead", &json!({ "epoch": bob_genesis_epoch })),
    )
    .await;
    assert_eq!(bob_aged_status, StatusCode::UNAUTHORIZED, "{bob_aged_body}");

    // Have `bob_d1` (`active`) publish Bob's genesis epoch head (`epoch = 0`) so foreign-DID read tests have data.
    let (bob_valid_gen, _) = build_epoch_public_for_device(&bob_d1, 0, [0x12_u8; 32], None, None);
    let (st_bob_ok, bob_ok_body) = http::send(
        router.clone(),
        bob_d1.labyrinth_post_request("publishEpochHead", &json!({ "epoch": bob_valid_gen })),
    )
    .await;
    assert_eq!(st_bob_ok, StatusCode::OK, "{bob_ok_body}");

    // 2. Alice enrolls `alice_d1` (`active`) and publishes genesis `epoch = 0`.
    let alice_d1 = DeviceIdentity::build(&alice_acct, "Alice Lost iPhone", 2);
    let (st_a1, a1_body) = http::send(router.clone(), alice_d1.enroll_request()).await;
    assert_eq!(st_a1, StatusCode::OK, "{a1_body}");
    assert_eq!(a1_body["device"]["status"], "active");

    let (alice_ep0, alice_link0) =
        build_epoch_public_for_device(&alice_d1, 0, [0x21_u8; 32], None, None);
    let (st_ep0, ep0_body) = http::send(
        router.clone(),
        alice_d1.labyrinth_post_request("publishEpochHead", &json!({ "epoch": alice_ep0 })),
    )
    .await;
    assert_eq!(st_ep0, StatusCode::OK, "alice genesis epoch=0: {ep0_body}");

    // Alice loses `alice_d1` and enrolls replacement `alice_d2` -> lands in `pending_approval`.
    let alice_d2 = DeviceIdentity::build(&alice_acct, "Alice Recovery iPhone", 2);
    let (st_a2, a2_body) = http::send(router.clone(), alice_d2.enroll_request()).await;
    assert_eq!(st_a2, StatusCode::OK, "{a2_body}");
    assert_eq!(a2_body["device"]["status"], "pending_approval");

    // 3. `pending_approval` `getOwnDevices` succeeds (`200 OK`), lists both devices with accurate
    //    statuses, and does NOT touch `last_active_at` or clear `dormant_at`.
    let sentinel_ts = Utc::now() - Duration::days(10);
    sqlx::query(
        "UPDATE chat.devices SET last_active_at = $3, dormant_at = $3 WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&alice_acct.did)
    .bind(alice_d2.device_id)
    .bind(sentinel_ts)
    .execute(&pool)
    .await
    .unwrap();

    let (st_own, own_body) = http::send(
        router.clone(),
        alice_d2.dpop_get_request("blue.catbird.chat.getOwnDevices", ""),
    )
    .await;
    assert_eq!(
        st_own,
        StatusCode::OK,
        "pending_approval getOwnDevices must succeed: {own_body}"
    );
    let own_devices = own_body["items"].as_array().expect("items array");
    assert_eq!(own_devices.len(), 2);
    let own_d2 = own_devices
        .iter()
        .find(|d| d["device"]["deviceId"] == alice_d2.device_id.to_string())
        .expect("alice_d2 in getOwnDevices");
    assert_eq!(own_d2["device"]["status"], "pending_approval");

    let (d2_dormant_still_set, d2_last_active): (bool, chrono::DateTime<Utc>) = sqlx::query_as(
        "SELECT dormant_at IS NOT NULL, last_active_at FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&alice_acct.did)
    .bind(alice_d2.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        d2_dormant_still_set,
        "pending_approval getOwnDevices must not clear dormant_at"
    );
    assert_eq!(
        d2_last_active.timestamp(),
        sentinel_ts.timestamp(),
        "pending_approval getOwnDevices must not bump last_active_at"
    );
    // Reset `dormant_at` back to NULL on `alice_d2` so normal enrollment state resumes.
    sqlx::query("UPDATE chat.devices SET dormant_at = NULL WHERE user_did = $1 AND device_id = $2")
        .bind(&alice_acct.did)
        .bind(alice_d2.device_id)
        .execute(&pool)
        .await
        .unwrap();

    // 4. Self-targeted Labyrinth recovery bootstrap reads (`did == alice_acct.did`) succeed (`200 OK`)!
    let (st_self_head, self_head_body) = http::send(
        router.clone(),
        alice_d2.labyrinth_get_request("getEpochHead", &[("did", &alice_acct.did)]),
    )
    .await;
    assert_eq!(
        st_self_head,
        StatusCode::OK,
        "self getEpochHead on pending_approval: {self_head_body}"
    );
    assert_eq!(self_head_body["epoch"]["epochNumber"], 0);

    let (st_self_keys, self_keys_body) = http::send(
        router.clone(),
        alice_d2.labyrinth_get_request("getChatDeviceKeys", &[("did", &alice_acct.did)]),
    )
    .await;
    assert_eq!(
        st_self_keys,
        StatusCode::OK,
        "self getChatDeviceKeys on pending_approval: {self_keys_body}"
    );

    let (st_self_mbx, self_mbx_body) = http::send(
        router.clone(),
        alice_d2.labyrinth_fixed_get_request(
            "getMailboxKeysRecord",
            &[("did", &alice_acct.did), ("rkey", "self")],
        ),
    )
    .await;
    assert_eq!(
        st_self_mbx,
        StatusCode::OK,
        "self getMailboxKeysRecord on pending_approval: {self_mbx_body}"
    );

    // 5. Foreign-DID Labyrinth reads AND privileged writes (`deleteAccountData`, `purgeMailbox`,
    //    `getConversations`, `getDevices`) MUST all fail closed (`401 NotAuthorized`)!
    for (label, req) in [
        (
            "foreign getEpochHead",
            alice_d2.labyrinth_get_request("getEpochHead", &[("did", &bob_acct.did)]),
        ),
        (
            "foreign getChatDeviceKeys",
            alice_d2.labyrinth_get_request("getChatDeviceKeys", &[("did", &bob_acct.did)]),
        ),
        (
            "foreign getMailboxKeysRecord",
            alice_d2.labyrinth_fixed_get_request(
                "getMailboxKeysRecord",
                &[("did", &bob_acct.did), ("rkey", "self")],
            ),
        ),
        (
            "deleteAccountData",
            alice_d2.labyrinth_post_request("deleteAccountData", &json!({})),
        ),
        (
            "purgeMailbox",
            alice_d2.labyrinth_post_request("purgeMailbox", &json!({})),
        ),
        (
            "chat getConversations",
            alice_d2.dpop_get_request("blue.catbird.chat.getConversations", ""),
        ),
        (
            "chat getDevices",
            alice_d2.dpop_get_request(
                "blue.catbird.chat.getDevices",
                &format!("userDids={}", bob_acct.did),
            ),
        ),
    ] {
        let (st, err_body) = http::send(router.clone(), req).await;
        assert_eq!(
            st,
            StatusCode::UNAUTHORIZED,
            "{label} must reject pending_approval with 401: {err_body}"
        );
        assert_eq!(err_body["error"], "NotAuthorized", "{label}: {err_body}");
    }

    // 6. Forged `prevSig` at `epoch = 1` (without Epoch 0's XEdDSA secret) fails closed (`400`)
    //    and leaves `alice_d2` in `pending_approval`!
    let (forged_ep1, _) = build_epoch_public_for_device(
        &alice_d2,
        1,
        [0x31_u8; 32],
        Some(alice_link0),
        Some([0x99_u8; 32]),
    );
    let (st_forged, forged_body) = http::send(
        router.clone(),
        alice_d2.labyrinth_post_request("publishEpochHead", &json!({ "epoch": forged_ep1 })),
    )
    .await;
    assert_eq!(st_forged, StatusCode::BAD_REQUEST, "{forged_body}");
    assert_eq!(forged_body["error"], "InvalidRequest");
    assert!(
        forged_body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("prevSig"),
        "expected prevSig rejection message: {forged_body}"
    );
    let status_after_forged: String = sqlx::query_scalar(
        "SELECT status FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&alice_acct.did)
    .bind(alice_d2.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status_after_forged, "pending_approval");

    // 7. A valid chained restore is still refused while another device is
    //    awake. A correct prevSig does not override sibling approval.
    let (valid_ep1, alice_link1) =
        build_epoch_public_for_device(&alice_d2, 1, [0x32_u8; 32], Some(alice_link0), None);
    let (awake_status, awake_body) = http::send(
        router.clone(),
        alice_d2.labyrinth_post_request("publishEpochHead", &json!({ "epoch": valid_ep1.clone() })),
    )
    .await;
    assert_eq!(awake_status, StatusCode::UNAUTHORIZED, "{awake_body}");
    let unpublished_epoch: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM labyrinth.epoch_heads WHERE did = $1 AND epoch_number = 1",
    )
    .bind(&alice_acct.did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        unpublished_epoch, 0,
        "refused promotion must roll back head"
    );

    // The lost sibling becomes dormant. Before the 72h notice hold expires,
    // an explicit restore action still cannot promote the replacement.
    sqlx::query(
        "UPDATE chat.devices SET last_active_at = $3, dormant_at = NULL \
          WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&alice_acct.did)
    .bind(alice_d1.device_id)
    .bind(Utc::now() - Duration::hours(100))
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(mark_inactive_devices(&pool, Utc::now()).await.unwrap(), 0);
    let (early_status, early_body) = http::send(
        router.clone(),
        alice_d2.labyrinth_post_request("publishEpochHead", &json!({ "epoch": valid_ep1.clone() })),
    )
    .await;
    assert_eq!(early_status, StatusCode::UNAUTHORIZED, "{early_body}");

    // Age the durable notice, not just the device row. The audit table's
    // immutability trigger is bypassed only in this isolated test database.
    {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE chat.device_promotion_audit \
                SET recorded_at = clock_timestamp() - interval '73 hours' \
              WHERE user_did = $1 AND device_id = $2 AND event_kind = 'pending_notice'",
        )
        .bind(&alice_acct.did)
        .bind(alice_d2.device_id)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let (no_auto_status, _) = http::send(
        router.clone(),
        alice_d2.dpop_get_request(
            "blue.catbird.chat.getDevices",
            &format!("userDids={}", bob_acct.did),
        ),
    )
    .await;
    assert_eq!(no_auto_status, StatusCode::UNAUTHORIZED);

    // A sibling using only Labyrinth becomes awake again before the restore
    // action, so an attacker cannot exploit a chat-only activity stamp.
    let (wake_status, wake_body) = http::send(
        router.clone(),
        alice_d1.labyrinth_get_request("getEpochHead", &[("did", &alice_acct.did)]),
    )
    .await;
    assert_eq!(wake_status, StatusCode::OK, "{wake_body}");
    let d1_awake: bool = sqlx::query_scalar(
        "SELECT dormant_at IS NULL FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&alice_acct.did)
    .bind(alice_d1.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        d1_awake,
        "authenticated Labyrinth activity must wake its device"
    );
    let (returned_status, returned_body) = http::send(
        router.clone(),
        alice_d2.labyrinth_post_request("publishEpochHead", &json!({ "epoch": valid_ep1.clone() })),
    )
    .await;
    assert_eq!(returned_status, StatusCode::UNAUTHORIZED, "{returned_body}");

    // Simulate full loss again; now the aged notice plus a fresh explicit
    // chained restore promotes the replacement atomically.
    sqlx::query(
        "UPDATE chat.devices SET last_active_at = $3, dormant_at = NULL \
          WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&alice_acct.did)
    .bind(alice_d1.device_id)
    .bind(Utc::now() - Duration::hours(100))
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(mark_inactive_devices(&pool, Utc::now()).await.unwrap(), 0);
    let (st_ep1, ep1_body) = http::send(
        router.clone(),
        alice_d2.labyrinth_post_request("publishEpochHead", &json!({ "epoch": valid_ep1.clone() })),
    )
    .await;
    assert_eq!(
        st_ep1,
        StatusCode::OK,
        "valid recovery publishEpochHead must succeed: {ep1_body}"
    );

    // Idempotent replay of `epoch = 1` also succeeds (`200 OK`).
    let (st_ep1_replay, ep1_replay_body) = http::send(
        router.clone(),
        alice_d2.labyrinth_post_request("publishEpochHead", &json!({ "epoch": valid_ep1 })),
    )
    .await;
    assert_eq!(st_ep1_replay, StatusCode::OK, "{ep1_replay_body}");

    let status_after_promote: String = sqlx::query_scalar(
        "SELECT status FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&alice_acct.did)
    .bind(alice_d2.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        status_after_promote, "active",
        "aged full-loss restore must atomically promote pending_approval -> active"
    );
    let promotion_audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.device_promotion_audit \
          WHERE user_did = $1 AND device_id = $2 AND event_kind = 'recovery_promoted'",
    )
    .bind(&alice_acct.did)
    .bind(alice_d2.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(promotion_audit_count, 1);

    // Now promoted `alice_d2` can read foreign-DID `getEpochHead` and `chat.getConversations`!
    let (st_foreign_ok, foreign_ok_body) = http::send(
        router.clone(),
        alice_d2.labyrinth_get_request("getEpochHead", &[("did", &bob_acct.did)]),
    )
    .await;
    assert_eq!(st_foreign_ok, StatusCode::OK, "{foreign_ok_body}");
    let (st_conv_ok, conv_ok_body) = http::send(
        router.clone(),
        alice_d2.dpop_get_request("blue.catbird.chat.getConversations", ""),
    )
    .await;
    assert_eq!(st_conv_ok, StatusCode::OK, "{conv_ok_body}");

    // A later enrollment after every old device is revoked is a restore, not
    // a brand-new account. It starts pending, so it reads nothing foreign.
    for target in [alice_d1.device_id, alice_d2.device_id] {
        let signed_revoke = alice_d2.revocation_wrapper(target, 1);
        let (status, body) = http::send(
            router.clone(),
            alice_d2.dpop_signed_post_request("blue.catbird.chat.revokeDevice", &signed_revoke),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let alice_d3 = DeviceIdentity::build(&alice_acct, "Alice Full-Loss Restore", 2);
    let (d3_status, d3_body) = http::send(router.clone(), alice_d3.enroll_request()).await;
    assert_eq!(d3_status, StatusCode::OK, "{d3_body}");
    assert_eq!(d3_body["device"]["status"], "pending_approval");
    let (d3_early, _) = http::send(
        router.clone(),
        alice_d3.dpop_get_request(
            "blue.catbird.chat.getDevices",
            &format!("userDids={}", bob_acct.did),
        ),
    )
    .await;
    assert_eq!(d3_early, StatusCode::UNAUTHORIZED);
    // No active sibling is left to see a notice or approve. A chained head
    // proves the recovery secret (code or backup passkey), so the restore
    // promotes at once instead of stranding the account behind the hold.
    let (alice_ep2, _) =
        build_epoch_public_for_device(&alice_d3, 2, [0x33_u8; 32], Some(alice_link1), None);
    let (d3_restore_status, d3_restore_body) = http::send(
        router.clone(),
        alice_d3.labyrinth_post_request("publishEpochHead", &json!({ "epoch": alice_ep2 })),
    )
    .await;
    assert_eq!(d3_restore_status, StatusCode::OK, "{d3_restore_body}");
    let d3_final_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&alice_acct.did)
    .bind(alice_d3.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(d3_final_status, "active");
    let d3_promotions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.device_promotion_audit \
          WHERE user_did = $1 AND device_id = $2 AND event_kind = 'recovery_promoted'",
    )
    .bind(&alice_acct.did)
    .bind(alice_d3.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(d3_promotions, 1);

    // A genesis head proves no recovery secret. Even with every old device
    // revoked (here by self-revocation), it still waits for the notice hold.
    let dave_acct = AccountIdentity::create().await;
    let dave_d1 = DeviceIdentity::build(&dave_acct, "Dave Signed-Out Mac", 2);
    let dave_d2 = DeviceIdentity::build(&dave_acct, "Dave Replacement", 2);
    let (dv1_status, dv1_body) = http::send(router.clone(), dave_d1.enroll_request()).await;
    assert_eq!(dv1_status, StatusCode::OK, "{dv1_body}");
    let dave_self_revoke = dave_d1.revocation_wrapper(dave_d1.device_id, 1);
    let (dv1_rev_status, dv1_rev_body) = http::send(
        router.clone(),
        dave_d1.dpop_signed_post_request("blue.catbird.chat.revokeDevice", &dave_self_revoke),
    )
    .await;
    assert_eq!(dv1_rev_status, StatusCode::OK, "{dv1_rev_body}");
    let (dv2_status, dv2_body) = http::send(router.clone(), dave_d2.enroll_request()).await;
    assert_eq!(dv2_status, StatusCode::OK, "{dv2_body}");
    assert_eq!(dv2_body["device"]["status"], "pending_approval");
    let (dave_genesis, _) = build_epoch_public_for_device(&dave_d2, 0, [0x55_u8; 32], None, None);
    let (dv_early_status, dv_early_body) = http::send(
        router.clone(),
        dave_d2.labyrinth_post_request(
            "publishEpochHead",
            &json!({ "epoch": dave_genesis.clone() }),
        ),
    )
    .await;
    assert_eq!(dv_early_status, StatusCode::UNAUTHORIZED, "{dv_early_body}");
    {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE chat.device_promotion_audit \
                SET recorded_at = clock_timestamp() - interval '73 hours' \
              WHERE user_did = $1 AND device_id = $2 AND event_kind = 'pending_notice'",
        )
        .bind(&dave_acct.did)
        .bind(dave_d2.device_id)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let (dv_aged_status, dv_aged_body) = http::send(
        router.clone(),
        dave_d2.labyrinth_post_request("publishEpochHead", &json!({ "epoch": dave_genesis })),
    )
    .await;
    assert_eq!(dv_aged_status, StatusCode::OK, "{dv_aged_body}");

    // A never-initialized Labyrinth account has no prior head to chain. The
    // same full-loss gate admits explicit genesis only after the notice hold.
    let carol_acct = AccountIdentity::create().await;
    let carol_d1 = DeviceIdentity::build(&carol_acct, "Carol Lost Phone", 2);
    let carol_d2 = DeviceIdentity::build(&carol_acct, "Carol Recovery Phone", 2);
    let (c1_status, _) = http::send(router.clone(), carol_d1.enroll_request()).await;
    assert_eq!(c1_status, StatusCode::OK);
    let (c2_status, c2_body) = http::send(router.clone(), carol_d2.enroll_request()).await;
    assert_eq!(c2_status, StatusCode::OK, "{c2_body}");
    assert_eq!(c2_body["device"]["status"], "pending_approval");
    sqlx::query(
        "UPDATE chat.devices SET last_active_at = $3, dormant_at = NULL \
          WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&carol_acct.did)
    .bind(carol_d1.device_id)
    .bind(Utc::now() - Duration::hours(100))
    .execute(&pool)
    .await
    .unwrap();
    let _ = mark_inactive_devices(&pool, Utc::now()).await.unwrap();
    let carol_d1_dormant: bool = sqlx::query_scalar(
        "SELECT dormant_at IS NOT NULL FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&carol_acct.did)
    .bind(carol_d1.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        !carol_d1_dormant,
        "recovery eligibility must not shorten the delivery dormancy window"
    );
    let (carol_genesis, _) = build_epoch_public_for_device(&carol_d2, 0, [0x44_u8; 32], None, None);
    let (c_early_status, c_early_body) = http::send(
        router.clone(),
        carol_d2.labyrinth_post_request(
            "publishEpochHead",
            &json!({ "epoch": carol_genesis.clone() }),
        ),
    )
    .await;
    assert_eq!(c_early_status, StatusCode::UNAUTHORIZED, "{c_early_body}");
    {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE chat.device_promotion_audit \
                SET recorded_at = clock_timestamp() - interval '73 hours' \
              WHERE user_did = $1 AND device_id = $2 AND event_kind = 'pending_notice'",
        )
        .bind(&carol_acct.did)
        .bind(carol_d2.device_id)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let (c_restore_status, c_restore_body) = http::send(
        router.clone(),
        carol_d2.labyrinth_post_request("publishEpochHead", &json!({ "epoch": carol_genesis })),
    )
    .await;
    assert_eq!(c_restore_status, StatusCode::OK, "{c_restore_body}");
    let c_final_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&carol_acct.did)
    .bind(carol_d2.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(c_final_status, "active");

    pool.close().await;
}

#[tokio::test]
async fn r2_dormancy_coarse_day_margin_zero_ack_and_post_reset_generation_pruning() {
    let _env_guard = W2D_ENV_LOCK.lock().await;
    let self_did = "did:web:chat.catbird.blue";
    std::env::set_var("SERVICE_DID", self_did);
    std::env::set_var("SELF_ENDPOINT", "https://chat.example.net");

    // Part A: `+24h` coarse UTC-day dormancy margin + `0`-ack dormancy pruning (`#69` Findings 2 & 3).
    let db_a = common::fresh_db::fresh_fully_migrated_db("chat_w2d_").await;
    let pool_a = db_a.connect(4).await;
    let router_a = build_unified_router(pool_a.clone(), None).await;

    let fix_a = seed_clean_slate_application_fixture_unsealed(
        &pool_a,
        false,
        self_did,
        Some([0x81; 32]),
        None,
    )
    .await
    .expect("fixture A");
    let sa_p256 = http::random_p256();
    let sa_jwk = http::public_jwk(&sa_p256);
    let sa_dev = http::Device {
        did: fix_a.sender_did.clone(),
        device_id: fix_a.sender_device_id,
        jkt: http::jwk_thumbprint(&sa_jwk),
        signing: sa_p256,
        jwk: sa_jwk,
    };
    http::cache_device_did(&sa_dev).await;

    let (st_send_a, body_send_a) = http::send(
        router_a.clone(),
        http::unsigned_json_request(
            &sa_dev,
            "blue.catbird.chat.sendMessage",
            serde_json::to_vec(&json!({ "signedRequest": fix_a.signed_request })).unwrap(),
        ),
    )
    .await;
    assert_eq!(st_send_a, StatusCode::OK, "{body_send_a}");
    let seq_a = body_send_a["entry"]["seq"].as_i64().unwrap();

    // Confirm `0` rows exist in `chat.device_entry_acks` for this conversation!
    let ack_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat.device_entry_acks WHERE conversation_id = $1",
    )
    .bind(fix_a.conversation_id)
    .fetch_one(&pool_a)
    .await
    .unwrap();
    assert_eq!(ack_rows, 0);

    // Suppose both devices were active at `2026-11-10T23:59:59Z`, which `PI-META-MIN` truncated
    // to `2026-11-10T00:00:00Z`.
    let coarse_day0 = chrono::DateTime::parse_from_rfc3339("2026-11-10T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    // Seed the legacy 48-hour sweep result on the existing devices.
    sqlx::query("UPDATE chat.devices SET last_active_at = $1, dormant_at = $2")
        .bind(coarse_day0)
        .bind(coarse_day0 + Duration::days(3))
        .execute(&pool_a)
        .await
        .unwrap();

    // Just inside the 60-day window for a last interaction at the end of Day 0.
    let before_cutoff = coarse_day0 + Duration::days(61) - Duration::minutes(2);
    assert_eq!(
        mark_inactive_devices(&pool_a, before_cutoff).await.unwrap(),
        0
    );
    let still_marked: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.devices WHERE dormant_at IS NOT NULL")
            .fetch_one(&pool_a)
            .await
            .unwrap();
    assert_eq!(still_marked, 0, "premature legacy dormancy must be cleared");
    // Once every possible instant of the coarse day is older than 60 days,
    // both devices are dormant. Dormancy by itself cannot authorize pruning.
    let after_cutoff = coarse_day0 + Duration::days(61) + Duration::minutes(1);
    let marked_a = mark_inactive_devices(&pool_a, after_cutoff).await.unwrap();
    assert_eq!(
        marked_a, 2,
        "both devices marked dormant after the 60-day window and coarse-day allowance"
    );

    let (pruned_a, payload_null_a): (bool, bool) = sqlx::query_as(
        "SELECT payload_pruned_at IS NOT NULL, accepted_payload_bytes IS NULL \
         FROM chat.entries WHERE conversation_id = $1 AND seq = $2",
    )
    .bind(fix_a.conversation_id)
    .bind(seq_a)
    .fetch_one(&pool_a)
    .await
    .unwrap();
    assert!(
        !pruned_a && !payload_null_a,
        "B1(a)/(b): 0-ack un-archived conversation must NOT prune when all open-interval devices go dormant"
    );
    pool_a.close().await;

    // Part B: Post-`ActivateReset` generation-0 pruning while generation-1 has open intervals (`#69` Finding 3).
    let db_b = common::fresh_db::fresh_fully_migrated_db("chat_w2d_").await;
    let pool_b = db_b.connect(4).await;
    let router_b = build_unified_router(pool_b.clone(), None).await;

    let fix_b = seed_clean_slate_application_fixture_unsealed(
        &pool_b,
        false,
        self_did,
        Some([0x82; 32]),
        None,
    )
    .await
    .expect("fixture B");
    let sb_p256 = http::random_p256();
    let sb_jwk = http::public_jwk(&sb_p256);
    let sb_dev = http::Device {
        did: fix_b.sender_did.clone(),
        device_id: fix_b.sender_device_id,
        jkt: http::jwk_thumbprint(&sb_jwk),
        signing: sb_p256,
        jwk: sb_jwk,
    };
    http::cache_device_did(&sb_dev).await;
    let rb_p256 = http::random_p256();
    let rb_jwk = http::public_jwk(&rb_p256);
    let rb_dev = http::Device {
        did: fix_b.recipient_did.clone(),
        device_id: fix_b.recipient_device_id,
        jkt: http::jwk_thumbprint(&rb_jwk),
        signing: rb_p256,
        jwk: rb_jwk,
    };
    http::cache_device_did(&rb_dev).await;

    // Send an application message in generation `0` with `0` acks.
    let (st_send_b, body_send_b) = http::send(
        router_b.clone(),
        http::unsigned_json_request(
            &sb_dev,
            "blue.catbird.chat.sendMessage",
            serde_json::to_vec(&json!({ "signedRequest": fix_b.signed_request })).unwrap(),
        ),
    )
    .await;
    assert_eq!(st_send_b, StatusCode::OK, "{body_send_b}");
    let seq_g0 = body_send_b["entry"]["seq"].as_i64().unwrap();

    // Submit `requestReset` + `activateReset` to supersede generation `0` with generation `1`.
    let reset_request_id = Uuid::new_v4();
    let reset_req_signed = sign_mutation_json_for_test(
        &json!({
            "$type": "blue.catbird.chat.defs#resetRequestBody",
            "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\u{0000}",
            "resetRequestId": reset_request_id,
            "idempotencyKey": reset_request_id,
            "actorDid": fix_b.sender_did,
            "actorDeviceId": fix_b.sender_device_id,
            "keyId": fix_b.sender_key_id,
            "authGeneration": 1,
            "prior": fix_b.signed_request["body"]["prior"],
            "reason": "manualRecovery",
            "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        }),
        &Ed25519SigningKey::from_bytes(&fix_b.sender_ed25519_seed),
    )
    .unwrap();
    let (st_rr, body_rr) = http::send(
        router_b.clone(),
        http::unsigned_json_request(
            &sb_dev,
            "blue.catbird.chat.requestReset",
            serde_json::to_vec(&json!({ "signedRequest": reset_req_signed })).unwrap(),
        ),
    )
    .await;
    assert_eq!(st_rr, StatusCode::OK, "requestReset failed: {body_rr}");

    let participant_rows: Vec<(String, String, String, Option<Uuid>, String, Uuid)> =
        sqlx::query_as(
            "SELECT user_did,status,role,invitation_transition_id,created_by_did,created_by_device_id \
             FROM chat.participants WHERE conversation_id=$1 AND current_membership ORDER BY convert_to(user_did,'UTF8')",
        )
        .bind(fix_b.conversation_id)
        .fetch_all(&pool_b)
        .await
        .unwrap();
    let participants: Vec<Value> = participant_rows
        .into_iter()
        .map(
            |(did, status, role, invitation, invited_by, invited_device)| {
                let mut value = json!({"userDid": did, "status": status, "role": role});
                if let Some(inv) = invitation {
                    value["invitationProvenance"] = json!({
                        "invitationTransitionId": inv,
                        "invitedByDid": invited_by,
                        "invitedByDeviceId": invited_device,
                    });
                }
                value
            },
        )
        .collect();
    let next_seq: i64 = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(fix_b.conversation_id)
    .fetch_one(&pool_b)
    .await
    .unwrap();
    let reset_act_signed = sign_reset_activation_for_test(
        reset_request_id,
        &fix_b.signed_request["body"]["prior"],
        json!(participants),
        next_seq as u64,
        &fix_b.sender_did,
        fix_b.sender_device_id,
        &fix_b.sender_key_id,
        fix_b.sender_ed25519_seed,
    )
    .unwrap();
    let (st_ar, body_ar) = http::send(
        router_b.clone(),
        http::unsigned_json_request(
            &sb_dev,
            "blue.catbird.chat.activateReset",
            serde_json::to_vec(&json!({ "signedRequest": reset_act_signed })).unwrap(),
        ),
    )
    .await;
    assert_eq!(st_ar, StatusCode::OK, "activateReset failed: {body_ar}");

    // Generation `1` has open intervals, while generation `0`'s unacknowledged
    // payload remains retained across `activateReset`. Its now-terminal
    // generation-0 intervals still define the ACK audience after the 72h floor.
    let open_gen1_intervals: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat.application_intervals \
         WHERE conversation_id = $1 AND generation = 1 AND terminal_seq IS NULL",
    )
    .bind(fix_b.conversation_id)
    .fetch_one(&pool_b)
    .await
    .unwrap();
    assert_eq!(open_gen1_intervals, 1);

    let (gen0_pruned, gen0_payload_null): (bool, bool) = sqlx::query_as(
        "SELECT payload_pruned_at IS NOT NULL, accepted_payload_bytes IS NULL \
         FROM chat.entries WHERE conversation_id = $1 AND seq = $2",
    )
    .bind(fix_b.conversation_id)
    .bind(seq_g0)
    .fetch_one(&pool_b)
    .await
    .unwrap();
    assert!(
        !gen0_pruned && !gen0_payload_null,
        "B10: superseded generation-0 un-acked application payload must NOT be wiped immediately on ActivateReset"
    );
    age_entry_past_prune_floor(&pool_b, fix_b.conversation_id, seq_g0).await;
    let sender_ed = Ed25519SigningKey::from_bytes(&fix_b.sender_ed25519_seed);
    let (_, sender_ack) = http::send(
        router_b.clone(),
        http::unsigned_json_request(
            &sb_dev,
            "blue.catbird.chat.acknowledgeEntries",
            serde_json::to_vec(&sign_ack_entries_request(
                fix_b.sender_device_id,
                &fix_b.sender_key_id,
                1,
                &sender_ed,
                fix_b.conversation_id,
                0,
                seq_g0,
            ))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(
        sender_ack["prunedCount"], 0,
        "the old-generation recipient interval must still block sender-only ACK"
    );
    let recipient_ed = Ed25519SigningKey::from_bytes(&fix_b.recipient_ed25519_seed);
    let (recipient_ack_status, recipient_ack) = http::send(
        router_b.clone(),
        http::unsigned_json_request(
            &rb_dev,
            "blue.catbird.chat.acknowledgeEntries",
            serde_json::to_vec(&sign_ack_entries_request(
                fix_b.recipient_device_id,
                &fix_b.recipient_key_id,
                1,
                &recipient_ed,
                fix_b.conversation_id,
                0,
                seq_g0,
            ))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(recipient_ack_status, StatusCode::OK, "{recipient_ack}");
    assert_eq!(
        recipient_ack["prunedCount"], 1,
        "terminal generation-0 intervals must accept their recipient ACK despite open generation-1 intervals"
    );

    pool_b.close().await;
}

#[tokio::test]
async fn r2_spaces_nov12_client_attestation_notify_null_memberspace_check_access_and_hosted_star_repo(
) {
    let _env_guard = W2D_ENV_LOCK.lock().await;
    std::env::set_var("SERVICE_DID", "did:web:chat.catbird.blue");
    std::env::set_var("SELF_ENDPOINT", "https://chat.example.net");

    let authority_did = "did:web:spaces-r2-authority.catbird.blue";

    // Webhook listener for `confirmRegistration` challenges.
    let webhook_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let webhook_addr = webhook_listener.local_addr().unwrap();
    let webhook_base_url = format!("http://{webhook_addr}");
    let webhook_router = Router::new()
        .route(
            "/xrpc/com.atproto.space.confirmRegistration",
            post(|Json(body): Json<Value>| async move {
                let challenge = body["challenge"].as_str().unwrap_or_default().to_owned();
                Json(json!({ "challenge": challenge }))
            }),
        )
        .route(
            "/xrpc/com.atproto.space.notifySpaceUpdate",
            post(|| async { StatusCode::OK }),
        )
        .route(
            "/xrpc/com.atproto.space.notifyCredentialsRevoked",
            post(|| async { StatusCode::OK }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(webhook_listener, webhook_router).await;
    });

    std::env::set_var("SERVICE_DID", authority_did);
    std::env::set_var("SELF_ENDPOINT", "https://spaces-r2-authority.catbird.blue");
    let db_remote = common::fresh_db::fresh_fully_migrated_db("chat_w2d_").await;
    let pool_remote = db_remote.connect(6).await;
    http::ensure_fence(&pool_remote).await;

    let remote_fixture =
        seed_clean_slate_application_fixture(&pool_remote, false, authority_did, Some([0x91; 32]))
            .await
            .expect("remote fixture");
    std::env::set_var("SERVICE_DID", "did:web:chat.catbird.blue");
    std::env::set_var("SELF_ENDPOINT", "https://chat.example.net");
    let space_uri: String = sqlx::query_scalar(
        "SELECT space_uri FROM chat.conversation_spaces WHERE conversation_id = $1 AND generation = 0",
    )
    .bind(remote_fixture.conversation_id)
    .fetch_one(&pool_remote)
    .await
    .unwrap();

    let authority_key = P256SigningKey::from_bytes((&[0x92_u8; 32]).into()).unwrap();
    let sender_pds_key = P256SigningKey::from_bytes((&[0x93_u8; 32]).into()).unwrap();
    let outsider_did = "did:web:outsider-memberspace-r2.catbird.blue";
    let outsider_pds_key = P256SigningKey::from_bytes((&[0x94_u8; 32]).into()).unwrap();
    let client_id = "https://app.catbird.blue/client-metadata.json";
    let client_att_key = P256SigningKey::from_bytes((&[0x95_u8; 32]).into()).unwrap();
    let wrong_att_key = P256SigningKey::from_bytes((&[0x96_u8; 32]).into()).unwrap();

    let authority_kem = encode_p256_did_key(&P256PublicKey::from(authority_key.verifying_key()));
    let authority_doc = json!({
        "id": authority_did,
        "verificationMethod": [
            {
                "id": format!("{authority_did}#atproto"),
                "type": "Multikey",
                "controller": authority_did,
                "publicKeyMultibase": authority_kem.strip_prefix("did:key:").unwrap(),
            },
            {
                "id": "#atproto_kem",
                "type": "Multikey",
                "controller": authority_did,
                "publicKeyMultibase": authority_kem.strip_prefix("did:key:").unwrap(),
            }
        ]
    });

    let remote_host = Arc::new(SpaceHostRuntime::new(
        pool_remote.clone(),
        SpaceHostConfig::for_test(authority_did.to_owned(), authority_key.clone()),
    ));
    remote_host.register_test_did_endpoint(
        authority_did,
        authority_key.verifying_key(),
        &webhook_base_url,
    );
    remote_host.register_test_did_endpoint(
        &remote_fixture.sender_did,
        sender_pds_key.verifying_key(),
        &webhook_base_url,
    );
    remote_host.register_test_did_endpoint(
        outsider_did,
        outsider_pds_key.verifying_key(),
        &webhook_base_url,
    );
    remote_host.register_test_client_attestation_key(
        client_id,
        "oauth-client-k1",
        client_att_key.verifying_key(),
    );

    let remote_router = space_host_router(Arc::clone(&remote_host)).route(
        "/.well-known/did.json",
        get({
            let doc = authority_doc;
            move || {
                let doc = doc.clone();
                async move { Json(doc) }
            }
        }),
    );
    let remote_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(remote_listener, remote_router).await;
    });
    register_test_space_relay_target(authority_did, &format!("http://{remote_addr}"));

    // Home `mls-ds` router for `sender_did` (`relaySpaceCredential` + `relaySpaceRead`).
    let db_home = common::fresh_db::fresh_fully_migrated_db("chat_w2d_").await;
    let pool_home = db_home.connect(4).await;
    let home_router = build_unified_router(pool_home.clone(), None).await;
    let user_did = remote_fixture.sender_did.clone();
    let home_dev_id = Uuid::new_v4();
    let home_p256 = http::random_p256();
    let home_jwk = http::public_jwk(&home_p256);
    let home_jkt = http::jwk_thumbprint(&home_jwk);
    sqlx::query(
        "INSERT INTO chat.principals (user_did, created_at) VALUES ($1, clock_timestamp())",
    )
    .bind(&user_did)
    .execute(&pool_home)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at) \
         VALUES ($1, $2, 'Home R2 Device', 'active', $3, 1, chat.protocol_capabilities(), clock_timestamp(), clock_timestamp())",
    )
    .bind(&user_did)
    .bind(home_dev_id)
    .bind(&home_jkt)
    .execute(&pool_home)
    .await
    .unwrap();
    let home_dev = http::Device {
        did: user_did.clone(),
        device_id: home_dev_id,
        jkt: home_jkt,
        signing: home_p256,
        jwk: home_jwk,
    };
    http::cache_device_did(&home_dev).await;

    let now_sec = Utc::now().timestamp() as u64;
    let pop_key = P256SigningKey::from_bytes((&[0x97_u8; 32]).into()).unwrap();
    let pop_secret = P256Secret::from_slice(&pop_key.to_bytes()).unwrap();
    let cnf_kid = encode_p256_did_key(&P256PublicKey::from(pop_key.verifying_key()));

    let mint_del = |issuer: &str, sk: &P256SigningKey, jti: &str| {
        mint_space_token(
            SpaceTokenKind::Delegation,
            &SpaceSigningKey::P256 {
                signing_key: sk.clone(),
                kid: "#atproto".to_string(),
            },
            &SpaceTokenClaims {
                iss: issuer.to_owned(),
                sub: space_uri.clone(),
                aud: Some(format!("{authority_did}#atproto_pds")),
                iat: now_sec,
                exp: now_sec + 60,
                jti: jti.to_owned(),
                cnf_kid: None,
            },
        )
        .unwrap()
    };

    // 1. Finding 4 + Finding 5(a):
    //    - Direct `authorizeSpaceSync` with unknown `"spaceRev"` input fails `400 InvalidRequest`
    //      (`#[serde(deny_unknown_fields)]`), matching `Swan`.
    //    - `relaySpaceCredential` WITH `"spaceRev": "3k2aaaaaaaaaa"` + valid `clientAttestation`
    //      succeeds (`200 OK`) because `relaySpaceCredential` validates `spaceRev` locally and
    //      strips it from the upstream `authorizeSpaceSync` body!
    //    - Forged `clientAttestation` fails `400 InvalidClientAttestation`!
    let http_client = reqwest::Client::new();
    let unknown_field_resp = http_client
        .post(format!(
            "http://{remote_addr}/xrpc/com.atproto.space.authorizeSpaceSync"
        ))
        .json(&json!({
            "space": space_uri,
            "delegationToken": mint_del(&user_did, &sender_pds_key, "r2-del-unknown"),
            "credentialKey": cnf_kid,
            "spaceRev": "3k2aaaaaaaaaa",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        unknown_field_resp.status(),
        reqwest::StatusCode::BAD_REQUEST
    );

    let bad_client_att = mint_space_token(
        SpaceTokenKind::ClientAttestation,
        &SpaceSigningKey::P256 {
            signing_key: wrong_att_key,
            kid: "oauth-client-k1".to_string(),
        },
        &SpaceTokenClaims {
            iss: client_id.to_owned(),
            sub: client_id.to_owned(),
            aud: Some(format!("{authority_did}#atproto_pds")),
            iat: now_sec,
            exp: now_sec + 120,
            jti: "r2-bad-att-1".to_owned(),
            cnf_kid: None,
        },
    )
    .unwrap();
    let bad_att_resp = http_client
        .post(format!(
            "http://{remote_addr}/xrpc/com.atproto.space.authorizeSpaceSync"
        ))
        .json(&json!({
            "space": space_uri,
            "delegationToken": mint_del(&user_did, &sender_pds_key, "r2-del-bad-att"),
            "credentialKey": cnf_kid,
            "clientAttestation": bad_client_att,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_att_resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let bad_att_json: Value = bad_att_resp.json().await.unwrap();
    assert_eq!(bad_att_json["error"], "InvalidClientAttestation");

    let valid_client_att = mint_space_token(
        SpaceTokenKind::ClientAttestation,
        &SpaceSigningKey::P256 {
            signing_key: client_att_key,
            kid: "oauth-client-k1".to_string(),
        },
        &SpaceTokenClaims {
            iss: client_id.to_owned(),
            sub: client_id.to_owned(),
            aud: Some(format!("{authority_did}#atproto_pds")),
            iat: now_sec,
            exp: now_sec + 120,
            jti: "r2-ok-att-1".to_owned(),
            cnf_kid: None,
        },
    )
    .unwrap();
    let (st_relay_cred, relay_cred_body) = http::send(
        home_router.clone(),
        http::unsigned_json_request(
            &home_dev,
            "blue.catbird.chat.relaySpaceCredential",
            serde_json::to_vec(&json!({
                "actorDeviceId": home_dev_id,
                "authorityDid": authority_did,
                "space": space_uri,
                "delegationToken": mint_del(&user_did, &sender_pds_key, "r2-del-ok-att"),
                "cnfKey": cnf_kid,
                "clientAttestation": valid_client_att,
                "spaceRev": "3k2aaaaaaaaaa",
                "notify": {
                    "endpoint": webhook_base_url,
                    "token": "r2-subscriber-token-0123456789abcdef",
                },
            }))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(
        st_relay_cred,
        StatusCode::OK,
        "relaySpaceCredential with valid clientAttestation + spaceRev must succeed: {relay_cred_body}"
    );
    let cred_jwt = relay_cred_body["credential"].as_str().unwrap().to_owned();

    // 2. Finding 5(b): Explicit `"notify": null` is rejected (`400 InvalidRequest`), while omitted
    //    `notify` renews cleanly and preserves the existing subscriber in `chat.conversation_space_subscribers`!
    let null_notify_resp = http_client
        .post(format!(
            "http://{remote_addr}/xrpc/com.atproto.space.authorizeSpaceSync"
        ))
        .json(&json!({
            "space": space_uri,
            "delegationToken": mint_del(&user_did, &sender_pds_key, "r2-del-null-notify"),
            "credentialKey": cnf_kid,
            "notify": null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(null_notify_resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let null_notify_json: Value = null_notify_resp.json().await.unwrap();
    assert_eq!(null_notify_json["error"], "InvalidRequest");

    let omit_notify_resp = http_client
        .post(format!(
            "http://{remote_addr}/xrpc/com.atproto.space.authorizeSpaceSync"
        ))
        .json(&json!({
            "space": space_uri,
            "delegationToken": mint_del(&user_did, &sender_pds_key, "r2-del-omit-notify"),
            "credentialKey": cnf_kid,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(omit_notify_resp.status(), reqwest::StatusCode::OK);
    let sub_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat.conversation_space_subscribers WHERE space_uri = $1",
    )
    .bind(&space_uri)
    .fetch_one(&pool_remote)
    .await
    .unwrap();
    assert_eq!(
        sub_count, 1,
        "omitting notify on renewal must preserve existing subscriber"
    );

    // 3. Finding 5(c) Part 1: `com.atproto.managedspace.checkAccess` +
    //    `com.atproto.memberspace.{putMembers,listMembers,removeMembers}`!
    let mint_service_jwt = |iss: &str, sk: &P256SigningKey, lxm: &str| {
        let now = Utc::now().timestamp();
        sign_es256_jwt(
            json!({"alg": "ES256", "typ": "JWT"}),
            json!({
                "iss": iss,
                "aud": format!("{authority_did}#atproto_mls"),
                "lxm": lxm,
                "iat": now,
                "exp": now + 60,
                "jti": Uuid::new_v4().to_string(),
            }),
            sk,
        )
    };

    // Before `putMembers`, `outsider_did` has `read: false, write: false`.
    let chk_before: Value = http_client
        .get(format!(
            "http://{remote_addr}/xrpc/com.atproto.managedspace.checkAccess"
        ))
        .query(&[
            ("space", space_uri.as_str()),
            ("repo", outsider_did),
            ("clientId", client_id),
        ])
        .header(
            "authorization",
            format!(
                "Bearer {}",
                mint_service_jwt(
                    authority_did,
                    &authority_key,
                    "com.atproto.managedspace.checkAccess"
                )
            ),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(chk_before, json!({ "read": false, "write": false }));

    // Authority grants `outsider_did` read + write via `com.atproto.memberspace.putMembers`.
    let put_mem_resp = http_client
        .post(format!(
            "http://{remote_addr}/xrpc/com.atproto.memberspace.putMembers"
        ))
        .header(
            "authorization",
            format!(
                "Bearer {}",
                mint_service_jwt(
                    authority_did,
                    &authority_key,
                    "com.atproto.memberspace.putMembers"
                )
            ),
        )
        .json(&json!({
            "space": space_uri,
            "members": [{ "did": outsider_did, "read": true, "write": true }],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(put_mem_resp.status(), reqwest::StatusCode::OK);

    // `checkAccess` now returns `read: true, write: true` and `listMembers` includes `outsider_did`!
    let chk_after: Value = http_client
        .get(format!(
            "http://{remote_addr}/xrpc/com.atproto.managedspace.checkAccess"
        ))
        .query(&[("space", space_uri.as_str()), ("repo", outsider_did)])
        .header(
            "authorization",
            format!(
                "Bearer {}",
                mint_service_jwt(
                    authority_did,
                    &authority_key,
                    "com.atproto.managedspace.checkAccess"
                )
            ),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(chk_after, json!({ "read": true, "write": true }));

    let list_mem: Value = http_client
        .get(format!(
            "http://{remote_addr}/xrpc/com.atproto.memberspace.listMembers"
        ))
        .query(&[("space", space_uri.as_str())])
        .header(
            "authorization",
            format!(
                "Bearer {}",
                mint_service_jwt(
                    &user_did,
                    &sender_pds_key,
                    "com.atproto.memberspace.listMembers"
                )
            ),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        list_mem["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["did"] == outsider_did && m["read"] == true && m["write"] == true),
        "listMembers must include managed member: {list_mem}"
    );

    // `outsider_did` can mint a Space credential while granted, and `removeMembers` immediately
    // revokes that credential!
    let out_cred_resp = http_client
        .post(format!(
            "http://{remote_addr}/xrpc/com.atproto.space.authorizeSpaceSync"
        ))
        .json(&json!({
            "space": space_uri,
            "delegationToken": mint_del(outsider_did, &outsider_pds_key, "r2-del-outsider"),
            "credentialKey": cnf_kid,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(out_cred_resp.status(), reqwest::StatusCode::OK);
    let out_cred_jwt = out_cred_resp.json::<Value>().await.unwrap()["credential"]
        .as_str()
        .unwrap()
        .to_owned();

    let rm_mem_resp = http_client
        .post(format!(
            "http://{remote_addr}/xrpc/com.atproto.memberspace.removeMembers"
        ))
        .header(
            "authorization",
            format!(
                "Bearer {}",
                mint_service_jwt(
                    authority_did,
                    &authority_key,
                    "com.atproto.memberspace.removeMembers"
                )
            ),
        )
        .json(&json!({
            "space": space_uri,
            "dids": [outsider_did],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rm_mem_resp.status(), reqwest::StatusCode::OK);

    let out_hdrs = sign_credential_request(
        &pop_secret,
        &out_cred_jwt,
        authority_did,
        now_sec,
        "r2-outsider-revoked",
    )
    .unwrap();
    let revoked_get_space = http_client
        .get(format!(
            "http://{remote_addr}/xrpc/com.atproto.space.getSpace"
        ))
        .query(&[("space", space_uri.as_str())])
        .header("authorization", out_hdrs.authorization)
        .header("signature-input", out_hdrs.signature_input)
        .header("signature", out_hdrs.signature)
        .send()
        .await
        .unwrap();
    assert_eq!(
        revoked_get_space.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let reauth_after_rm = http_client
        .post(format!(
            "http://{remote_addr}/xrpc/com.atproto.space.authorizeSpaceSync"
        ))
        .json(&json!({
            "space": space_uri,
            "delegationToken": mint_del(outsider_did, &outsider_pds_key, "r2-del-outsider-reauth"),
            "credentialKey": cnf_kid,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reauth_after_rm.status(), reqwest::StatusCode::FORBIDDEN);

    // 4. Finding 5(c) Part 2: Hosted `com.atproto.space.{putRecord,getRecord,getRepo}`
    //    with `STAR` v0.2 (`application/vnd.dasl.star`) + `Atproto-Space-Record` / `Atproto-Space-Commit` MACs!
    let collection = "blue.catbird.labyrinth.archive";
    let mut cids = Vec::new();
    for (rkey, payload_byte) in [("3k2rec0000001", 0xA1_u8), ("3k2rec0000002", 0xB2_u8)] {
        let put_resp = http_client
            .post(format!(
                "http://{remote_addr}/xrpc/com.atproto.space.putRecord"
            ))
            .header(
                "authorization",
                format!(
                    "Bearer {}",
                    mint_service_jwt(&user_did, &sender_pds_key, "com.atproto.space.putRecord")
                ),
            )
            .json(&json!({
                "space": space_uri,
                "repo": user_did,
                "collection": collection,
                "rkey": rkey,
                "record": {
                    "$type": collection,
                    "ciphertext": { "$bytes": STANDARD.encode([payload_byte; 48]) },
                    "epoch": 1,
                },
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(put_resp.status(), reqwest::StatusCode::OK);
        let put_json: Value = put_resp.json().await.unwrap();
        cids.push((
            rkey.to_owned(),
            put_json["uri"].as_str().unwrap().to_owned(),
            put_json["cid"].as_str().unwrap().to_owned(),
        ));
    }

    // Verify `com.atproto.space.getRecord` via `relaySpaceRead` + `Atproto-Space-Record` MAC!
    let encap_rec = encapsulate_p256(&authority_kem).expect("encap record MAC");
    let accept_rec =
        format_accept_signature(MacProfile::Record, &encap_rec.key_share_did_key).unwrap();
    let rec_hdrs = sign_credential_request(
        &pop_secret,
        &cred_jwt,
        &user_did,
        now_sec,
        "r2-get-record-1",
    )
    .unwrap();
    let get_rec_query = format!(
        "space={}&repo={}&collection={}&rkey={}",
        urlencoding::encode(&space_uri),
        urlencoding::encode(&user_did),
        urlencoding::encode(collection),
        urlencoding::encode(&cids[0].0),
    );
    let get_rec_req = http::unsigned_json_request(
        &home_dev,
        "blue.catbird.chat.relaySpaceRead",
        serde_json::to_vec(&json!({
            "actorDeviceId": home_dev_id,
            "targetDid": authority_did,
            "nsid": "com.atproto.space.getRecord",
            "query": get_rec_query,
            "credential": cred_jwt,
            "spaceAudience": user_did,
            "acceptSignature": accept_rec,
            "signatureInput": rec_hdrs.signature_input,
            "signature": rec_hdrs.signature,
        }))
        .unwrap(),
    );
    let get_rec_resp = home_router.clone().oneshot(get_rec_req).await.unwrap();
    assert_eq!(get_rec_resp.status(), StatusCode::OK);
    verify_record_mac(
        &encap_rec.shared_secret,
        &encap_rec.key_share_did_key,
        get_rec_resp.headers(),
        &cids[0].1,
        &cids[0].2,
    )
    .expect("Atproto-Space-Record MAC must verify cryptographically");
    let rec_body_bytes = axum::body::to_bytes(get_rec_resp.into_body(), 65_536)
        .await
        .unwrap();
    let rec_json: Value = serde_json::from_slice(&rec_body_bytes).unwrap();
    assert_eq!(rec_json["uri"], cids[0].1);
    assert_eq!(rec_json["cid"], cids[0].2);
    assert_eq!(
        rec_json["value"]["ciphertext"]["$bytes"],
        STANDARD.encode([0xA1_u8; 48])
    );

    // Verify `com.atproto.space.getRepo` via `relaySpaceRead` -> `application/vnd.dasl.star`
    // + `Atproto-Space-Commit` MAC + `read_star_repo_authenticated` LtHash1024 verification!
    let encap_commit = encapsulate_p256(&authority_kem).expect("encap commit MAC");
    let accept_commit =
        format_accept_signature(MacProfile::Commit, &encap_commit.key_share_did_key).unwrap();
    let repo_hdrs =
        sign_credential_request(&pop_secret, &cred_jwt, &user_did, now_sec, "r2-get-repo-1")
            .unwrap();
    let get_repo_query = format!(
        "space={}&repo={}",
        urlencoding::encode(&space_uri),
        urlencoding::encode(&user_did),
    );
    let get_repo_req = http::unsigned_json_request(
        &home_dev,
        "blue.catbird.chat.relaySpaceRead",
        serde_json::to_vec(&json!({
            "actorDeviceId": home_dev_id,
            "targetDid": authority_did,
            "nsid": "com.atproto.space.getRepo",
            "query": get_repo_query,
            "credential": cred_jwt,
            "spaceAudience": user_did,
            "acceptSignature": accept_commit,
            "signatureInput": repo_hdrs.signature_input,
            "signature": repo_hdrs.signature,
        }))
        .unwrap(),
    );
    let get_repo_resp = home_router.clone().oneshot(get_repo_req).await.unwrap();
    assert_eq!(get_repo_resp.status(), StatusCode::OK);
    assert_eq!(
        get_repo_resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/vnd.dasl.star")
    );
    let resp_headers = get_repo_resp.headers().clone();
    let star_bytes = axum::body::to_bytes(get_repo_resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let parsed_star = read_star_repo_authenticated(&star_bytes, &space_uri, &user_did, |meta| {
        verify_commit_mac(
            &encap_commit.shared_secret,
            &encap_commit.key_share_did_key,
            &resp_headers,
            &space_uri,
            &user_did,
            &meta.rev,
            &meta.data,
        )
    })
    .expect("STAR v0.2 archive + Atproto-Space-Commit MAC + LtHash1024 must verify");
    assert_eq!(parsed_star.records.len(), 2);
    assert_eq!(parsed_star.records[0].rkey, "3k2rec0000001");
    assert_eq!(parsed_star.records[1].rkey, "3k2rec0000002");

    pool_home.close().await;
    pool_remote.close().await;
}

// =============================================================================
// 6. Wave-2 R2 Remediation (`B1`, `B10`, `A6`) End-to-End Regression Suite
// =============================================================================

#[tokio::test]
async fn b1_b10_a6_r2_remediation_end_to_end() {
    let _env_guard = W2D_ENV_LOCK.lock().await;
    let authority_did = "did:web:chat.catbird.blue";
    std::env::set_var("SERVICE_DID", authority_did);
    std::env::set_var("SELF_ENDPOINT", "https://chat.catbird.blue");
    std::env::set_var("FEDERATION_TEST_ALLOW_ALL_RELATIONSHIPS", "true");
    std::env::set_var("APP_ENV", "test");

    let db = common::fresh_db::fresh_fully_migrated_db("chat_w2d_").await;
    let pool = db.connect(6).await;
    let router = build_unified_router(pool.clone(), None).await;

    let fix = seed_clean_slate_application_fixture_unsealed(
        &pool,
        false,
        authority_did,
        Some([0x81; 32]),
        None,
    )
    .await
    .expect("seed B1/B10/A6 fixture");

    let s_p256 = http::random_p256();
    let s_jwk = http::public_jwk(&s_p256);
    let s_dev = http::Device {
        did: fix.sender_did.clone(),
        device_id: fix.sender_device_id,
        jkt: http::jwk_thumbprint(&s_jwk),
        signing: s_p256,
        jwk: s_jwk,
    };
    http::cache_device_did(&s_dev).await;

    let r1_p256 = http::random_p256();
    let r1_jwk = http::public_jwk(&r1_p256);
    let r1_dev = http::Device {
        did: fix.recipient_did.clone(),
        device_id: fix.recipient_device_id,
        jkt: http::jwk_thumbprint(&r1_jwk),
        signing: r1_p256,
        jwk: r1_jwk,
    };
    http::cache_device_did(&r1_dev).await;

    // Publish an `#applicationEntry` (`seq_app`).
    let (st_send, sb_send) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &s_dev,
            "blue.catbird.chat.sendMessage",
            serde_json::to_vec(&json!({ "signedRequest": fix.signed_request })).unwrap(),
        ),
    )
    .await;
    assert_eq!(st_send, StatusCode::OK, "sendMessage failed: {sb_send}");
    let seq_app = sb_send["entry"]["seq"].as_i64().unwrap();
    let real_msg_id: Uuid = sqlx::query_scalar(
        "SELECT message_id FROM chat.entries WHERE conversation_id = $1 AND seq = $2",
    )
    .bind(fix.conversation_id)
    .bind(seq_app)
    .fetch_one(&pool)
    .await
    .unwrap();
    let high_signed_request = fix.next_sender_signed_request();
    let (st_high, sb_high) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &s_dev,
            "blue.catbird.chat.sendMessage",
            serde_json::to_vec(&json!({ "signedRequest": high_signed_request })).unwrap(),
        ),
    )
    .await;
    assert_eq!(
        st_high,
        StatusCode::OK,
        "second sendMessage failed: {sb_high}"
    );
    let seq_high = sb_high["entry"]["seq"].as_i64().unwrap();
    assert!(seq_high > seq_app);
    let high_msg_id: Uuid = sqlx::query_scalar(
        "SELECT message_id FROM chat.entries WHERE conversation_id = $1 AND seq = $2",
    )
    .bind(fix.conversation_id)
    .bind(seq_high)
    .fetch_one(&pool)
    .await
    .unwrap();

    // -------------------------------------------------------------------------
    // Part A (`A6`): `prepare_local_entry_wake` queries `(actor_did, actor_device_id)`
    // from `chat.entries` inside `tx` and excludes the producing sender device
    // even when `signedRequest` has been stripped from the outbound entry JSON!
    // -------------------------------------------------------------------------
    for (did, dev_id, key_id, push_key) in [
        (
            &fix.sender_did,
            fix.sender_device_id,
            &fix.sender_key_id,
            "pk_sender_0123456789abcdef",
        ),
        (
            &fix.recipient_did,
            fix.recipient_device_id,
            &fix.recipient_key_id,
            "pk_recip_0123456789abcdef0",
        ),
    ] {
        sqlx::query(
            "INSERT INTO chat.push_gateway_bindings \
                (user_did, device_id, gateway_url, app_id, push_key, key_id, auth_generation, signed_at, updated_at) \
             VALUES ($1, $2, 'https://nest.catbird.blue/xrpc/blue.catbird.push.deliver', 'blue.catbird.ios', $3, $4, 1, clock_timestamp(), clock_timestamp())",
        )
        .bind(did)
        .bind(dev_id)
        .bind(push_key)
        .bind(key_id)
        .execute(&pool)
        .await
        .unwrap();
    }
    let stripped_entry = json!({
        "$type": "blue.catbird.chat.defs#applicationEntry",
        "conversationId": fix.conversation_id.to_string(),
        "seq": seq_app,
        "generation": 0,
    });
    let mut wake_tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *wake_tx)
        .await
        .unwrap();
    sqlx::query("UPDATE chat.participants SET ds_did = NULL WHERE conversation_id = $1")
        .bind(fix.conversation_id)
        .execute(&mut *wake_tx)
        .await
        .unwrap();
    let prepared_wake = catbird_server::push_gateway::client::prepare_local_entry_wake(
        &mut wake_tx,
        &stripped_entry,
    )
    .await
    .expect("prepare_local_entry_wake")
    .expect("must return wake for recipient");
    wake_tx.rollback().await.unwrap();
    assert_eq!(
        prepared_wake.candidates(),
        &[(fix.recipient_did.clone(), fix.recipient_device_id)],
        "A6: stripped entry JSON must still exclude producing sender device and wake only recipient"
    );

    // -------------------------------------------------------------------------
    // Part B (`B1(c)`): Un-archived conversation with active `R1` (acked) +
    // dormant `R2` (unacked) must NOT prune before `received_at <= now - 72h`,
    // and prunes once `received_at` ages past the `72h` minimum retention floor!
    // -------------------------------------------------------------------------
    let r2_id = Uuid::new_v4();
    let r2_ed = Ed25519SigningKey::from_bytes(&[0x82; 32]);
    let r2_pub = r2_ed.verifying_key().to_bytes();
    let r2_key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(r2_pub.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
    let r2_p256 = http::random_p256();
    let r2_jwk = http::public_jwk(&r2_p256);
    let r2_jkt = http::jwk_thumbprint(&r2_jwk);
    let now_ts: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let dormant_ts = now_ts - Duration::days(62);
    sqlx::query(
        "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at, last_active_at, dormant_at) \
         VALUES ($1, $2, 'Recipient Dormant iPad', 'active', $3, 1, chat.protocol_capabilities(), $4, $4, $4, $4)",
    )
    .bind(&fix.recipient_did)
    .bind(r2_id)
    .bind(&r2_jkt)
    .bind(dormant_ts)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO chat.device_keys (user_did, device_id, key_id, signing_public_key, enrollment_auth_generation, created_at) \
         VALUES ($1, $2, $3, $4, 1, $5)",
    )
    .bind(&fix.recipient_did)
    .bind(r2_id)
    .bind(&r2_key_id)
    .bind(r2_pub.as_slice())
    .bind(dormant_ts)
    .execute(&pool)
    .await
    .unwrap();
    let r_period_id: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants WHERE conversation_id = $1 AND user_did = $2 AND current_membership = TRUE",
    )
    .bind(fix.conversation_id)
    .bind(&fix.recipient_did)
    .fetch_one(&pool)
    .await
    .unwrap();
    let r2_leaf_id = Uuid::new_v4();
    let r2_tx_id = Uuid::new_v4();
    {
        let mut mtx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *mtx)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO chat.member_devices (leaf_period_id, participant_period_id, conversation_id, generation, user_did, device_id, leaf_index, basic_credential, leaf_signature_key, leaf_key_id, leaf_auth_generation, origin, joined_state_version, joined_transition_id, joined_seq, active, created_at) \
             VALUES ($1, $2, $3, 0, $4, $5, 98, $6, $7, $8, 1, 'genesis', 1, $9, 1, TRUE, $10)",
        )
        .bind(r2_leaf_id)
        .bind(r_period_id)
        .bind(fix.conversation_id)
        .bind(&fix.recipient_did)
        .bind(r2_id)
        .bind(format!("{}#{r2_id}", fix.recipient_did).into_bytes())
        .bind(r2_pub.as_slice())
        .bind(&r2_key_id)
        .bind(r2_tx_id)
        .bind(dormant_ts)
        .execute(&mut *mtx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO chat.application_intervals ( \
                 membership_interval_id, conversation_id, generation, recipient_did, \
                 recipient_device_id, start_seq, opening_kind, opening_transition_id, \
                 opening_outer_entry_fingerprint, opening_state_version, opening_group_id, \
                 opening_epoch, opening_group_context_hash, opening_confirmation_tag, \
                 opening_leaf_period_id, created_at \
             ) \
             SELECT $1, conversation_id, generation, recipient_did, \
                    $2, start_seq, opening_kind, $1, \
                    opening_outer_entry_fingerprint, opening_state_version, opening_group_id, \
                    opening_epoch, opening_group_context_hash, opening_confirmation_tag, \
                    $3, created_at \
               FROM chat.application_intervals \
              WHERE conversation_id = $4 AND recipient_did = $5 AND recipient_device_id = $6",
        )
        .bind(r2_tx_id)
        .bind(r2_id)
        .bind(r2_leaf_id)
        .bind(fix.conversation_id)
        .bind(&fix.recipient_did)
        .bind(fix.recipient_device_id)
        .execute(&mut *mtx)
        .await
        .unwrap();
        mtx.commit().await.unwrap();
    }

    let s_ed = Ed25519SigningKey::from_bytes(&fix.sender_ed25519_seed);
    let r1_ed = Ed25519SigningKey::from_bytes(&fix.recipient_ed25519_seed);
    let (_, ack_s) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &s_dev,
            "blue.catbird.chat.acknowledgeEntries",
            serde_json::to_vec(&sign_ack_entries_request(
                fix.sender_device_id,
                &fix.sender_key_id,
                1,
                &s_ed,
                fix.conversation_id,
                0,
                seq_app,
            ))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(ack_s["prunedCount"], 0);

    // Active `R1` acks while `received_at` is fresh and `R2` is dormant & unacked -> must hold (`0` pruned)!
    let (_, ack_r1_fresh) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &r1_dev,
            "blue.catbird.chat.acknowledgeEntries",
            serde_json::to_vec(&sign_ack_entries_request(
                fix.recipient_device_id,
                &fix.recipient_key_id,
                1,
                &r1_ed,
                fix.conversation_id,
                0,
                seq_app,
            ))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(
        ack_r1_fresh["prunedCount"], 0,
        "B1(c): fresh un-archived entry must NOT prune while dormant sibling R2 has not acked"
    );

    // -------------------------------------------------------------------------
    // Part C (`B1` hosted-record fail-closed validation + 30d ceiling):
    // This exercises the authority's hosted/simulator putRecord path only; the
    // production PDS-to-authority evidence bridge and content-proof design are
    // separate release blockers. Neither live ciphertext nor a signed redaction
    // directly qualifies archive coverage.
    // -------------------------------------------------------------------------
    let space_uri: String = sqlx::query_scalar(
        "SELECT space_uri FROM chat.conversation_spaces WHERE conversation_id = $1 AND generation = 0",
    )
    .bind(fix.conversation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let authority_key = P256SigningKey::from_bytes((&[0x83_u8; 32]).into()).unwrap();
    let sender_pds_key = P256SigningKey::from_bytes((&[0x84_u8; 32]).into()).unwrap();
    let recipient_pds_key = P256SigningKey::from_bytes((&[0x85_u8; 32]).into()).unwrap();
    let host_rt = Arc::new(SpaceHostRuntime::new(
        pool.clone(),
        SpaceHostConfig::for_test(authority_did.to_owned(), authority_key.clone()),
    ));
    host_rt.register_test_did_endpoint(
        &fix.sender_did,
        sender_pds_key.verifying_key(),
        "https://sender.example.test",
    );
    host_rt.register_test_did_endpoint(
        &fix.recipient_did,
        recipient_pds_key.verifying_key(),
        "https://recipient.example.test",
    );
    let host_router = space_host_router(host_rt);

    let mint_put_jwt = |did: &str, key: &P256SigningKey| {
        let now = Utc::now().timestamp();
        sign_es256_jwt(
            json!({"alg": "ES256", "typ": "JWT"}),
            json!({
                "iss": did,
                "aud": format!("{authority_did}#atproto_mls"),
                "lxm": "com.atproto.space.putRecord",
                "iat": now,
                "exp": now + 60,
                "jti": Uuid::new_v4().to_string(),
            }),
            key,
        )
    };
    let watermark = || {
        let pool = pool.clone();
        let space_uri = space_uri.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT archived_through_seq FROM chat.conversation_spaces WHERE space_uri = $1",
            )
            .bind(space_uri)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };

    // A peer cannot claim another sender's accepted message coordinates.
    let forged_req = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.space.putRecord")
        .header("content-type", "application/json")
        .header(
            "authorization",
            format!(
                "Bearer {}",
                mint_put_jwt(&fix.recipient_did, &recipient_pds_key)
            ),
        )
        .body(Body::from(
            serde_json::to_vec(&json!({
                "space": space_uri,
                "repo": fix.recipient_did,
                "collection": "blue.catbird.labyrinth.batch",
                "rkey": "3k2forged0001",
                "record": {
                    "$type": "blue.catbird.labyrinth.batch",
                    "createdAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                    "threadId": fix.conversation_id.to_string(),
                    "items": [{
                        "messageId": real_msg_id.to_string(),
                        "seq": seq_app,
                        "signedEncMessage": { "$bytes": STANDARD.encode([0xEE_u8; 32]) },
                    }],
                },
            }))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        host_router
            .clone()
            .oneshot(forged_req)
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(watermark().await, 0);

    let mut archive_receipt = sb_send["sequencerReceipt"].clone();
    archive_receipt["originalSenderAttestation"] = fix
        .signed_request
        .pointer("/body/aad/originalSenderAttestation")
        .expect("accepted send has original sender attestation")
        .clone();
    let sender_archive_key = Ed25519SigningKey::from_bytes(&fix.sender_ed25519_seed);
    let sender_archive_pubkey = sender_archive_key.verifying_key().to_bytes();
    let timestamp = Utc::now().timestamp_millis();
    let base_item = json!({
        "messageId": real_msg_id.to_string(),
        "seq": seq_app,
        "timestamp": timestamp,
        "mekId": { "$bytes": STANDARD.encode([0xA4_u8; 12]) },
        "senderTransportPubkey": { "$bytes": STANDARD.encode(sender_archive_pubkey) },
        "sequencerReceipt": archive_receipt,
    });
    let signed_author_redaction = |message_id: Uuid| {
        let transcript = format!(
            "catbird.labyrinth.redaction:did={};message_id={message_id};thread_id={}",
            fix.sender_did,
            hex::encode(fix.conversation_id.to_string().as_bytes())
        );
        json!({
            "transportPubkey": { "$bytes": STANDARD.encode(sender_archive_pubkey) },
            "sig": { "$bytes": STANDARD.encode(sender_archive_key.sign(transcript.as_bytes()).to_bytes()) },
            "redactedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        })
    };

    let mut high_archive_receipt = sb_high["sequencerReceipt"].clone();
    high_archive_receipt["originalSenderAttestation"] = high_signed_request
        .pointer("/body/aad/originalSenderAttestation")
        .expect("second accepted send has original sender attestation")
        .clone();
    let high_item = json!({
        "messageId": high_msg_id.to_string(),
        "seq": seq_high,
        "timestamp": timestamp,
        "mekId": { "$bytes": STANDARD.encode([0xA4_u8; 12]) },
        "senderTransportPubkey": { "$bytes": STANDARD.encode(sender_archive_pubkey) },
        "sequencerReceipt": high_archive_receipt,
        "signedEncMessage": { "$bytes": "" },
        "redaction": signed_author_redaction(high_msg_id),
    });

    // Even a correctly authenticated PDS writer cannot turn opaque live
    // ciphertext into archive evidence without the private commitment witness.
    let mut malformed_item = base_item.clone();
    let mut malformed_envelope = vec![0xCC_u8; 64 + 73];
    malformed_envelope[64] = 0x02;
    malformed_item["signedEncMessage"] = json!({ "$bytes": STANDARD.encode(malformed_envelope) });
    let malformed_archive_req = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.space.putRecord")
        .header("content-type", "application/json")
        .header(
            "authorization",
            format!("Bearer {}", mint_put_jwt(&fix.sender_did, &sender_pds_key)),
        )
        .body(Body::from(
            serde_json::to_vec(&json!({
                "space": space_uri,
                "repo": fix.sender_did,
                "collection": "blue.catbird.labyrinth.batch",
                "rkey": "3k2malformed01",
                "record": {
                    "$type": "blue.catbird.labyrinth.batch",
                    "createdAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                    "threadId": fix.conversation_id.to_string(),
                    "items": [malformed_item],
                },
            }))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        host_router
            .clone()
            .oneshot(malformed_archive_req)
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(watermark().await, 0);

    // A bare/server redaction is not an author unsend and cannot stand in for
    // archived ciphertext.
    let mut malformed_redaction_item = base_item.clone();
    malformed_redaction_item["signedEncMessage"] = json!({ "$bytes": "" });
    malformed_redaction_item["redaction"] = json!({
        "redactedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
    });
    let malformed_redaction_req = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.space.putRecord")
        .header("content-type", "application/json")
        .header(
            "authorization",
            format!("Bearer {}", mint_put_jwt(&fix.sender_did, &sender_pds_key)),
        )
        .body(Body::from(
            serde_json::to_vec(&json!({
                "space": space_uri,
                "repo": fix.sender_did,
                "collection": "blue.catbird.labyrinth.batch",
                "rkey": "3k2redaction01",
                "record": {
                    "$type": "blue.catbird.labyrinth.batch",
                    "createdAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                    "threadId": fix.conversation_id.to_string(),
                    "items": [malformed_redaction_item],
                },
            }))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        host_router
            .clone()
            .oneshot(malformed_redaction_req)
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(watermark().await, 0);

    // A generation claim that differs from the accepted entry cannot be mixed
    // into this generation's archive coverage.
    let mut mixed_generation_item = high_item.clone();
    mixed_generation_item["sequencerReceipt"]["generation"] = json!(1);
    let mixed_generation_req = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.space.putRecord")
        .header("content-type", "application/json")
        .header(
            "authorization",
            format!("Bearer {}", mint_put_jwt(&fix.sender_did, &sender_pds_key)),
        )
        .body(Body::from(
            serde_json::to_vec(&json!({
                "space": space_uri,
                "repo": fix.sender_did,
                "collection": "blue.catbird.labyrinth.batch",
                "rkey": "3k2mixedgen001",
                "record": {
                    "$type": "blue.catbird.labyrinth.batch",
                    "createdAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                    "threadId": fix.conversation_id.to_string(),
                    "items": [mixed_generation_item],
                },
            }))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        host_router
            .clone()
            .oneshot(mixed_generation_req)
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(watermark().await, 0);

    // Even a correctly signed high-seq redaction is not archive-content proof
    // and cannot advance direct putRecord coverage.
    let sparse_high_req = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.space.putRecord")
        .header("content-type", "application/json")
        .header(
            "authorization",
            format!("Bearer {}", mint_put_jwt(&fix.sender_did, &sender_pds_key)),
        )
        .body(Body::from(
            serde_json::to_vec(&json!({
                "space": space_uri,
                "repo": fix.sender_did,
                "collection": "blue.catbird.labyrinth.batch",
                "rkey": "3k2sparsehigh1",
                "record": {
                    "$type": "blue.catbird.labyrinth.batch",
                    "createdAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                    "threadId": fix.conversation_id.to_string(),
                    "items": [high_item],
                },
            }))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        host_router
            .clone()
            .oneshot(sparse_high_req)
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        watermark().await,
        0,
        "an author-signed redaction is not substitute archive qualification"
    );
    assert_eq!(
        sqlx::query(
            "UPDATE chat.conversation_space_records SET archived_seqs = $4 \
              WHERE space_uri = $1 AND writer_did = $2 AND rkey = $3",
        )
        .bind(&space_uri)
        .bind(&fix.sender_did)
        .bind("3k2sparsehigh1")
        .bind(vec![seq_high])
        .execute(&pool)
        .await
        .unwrap()
        .rows_affected(),
        1,
        "seed the future reviewed evidence path, not direct putRecord"
    );

    let mut authentic_item = base_item;
    authentic_item["signedEncMessage"] = json!({ "$bytes": "" });
    authentic_item["redaction"] = signed_author_redaction(real_msg_id);
    let authentic_req = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.space.putRecord")
        .header("content-type", "application/json")
        .header(
            "authorization",
            format!("Bearer {}", mint_put_jwt(&fix.sender_did, &sender_pds_key)),
        )
        .body(Body::from(
            serde_json::to_vec(&json!({
                "space": space_uri,
                "repo": fix.sender_did,
                "collection": "blue.catbird.labyrinth.batch",
                "rkey": "3k2sender0001",
                "record": {
                    "$type": "blue.catbird.labyrinth.batch",
                    "createdAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                    "threadId": fix.conversation_id.to_string(),
                    "items": [authentic_item],
                },
            }))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        host_router
            .clone()
            .oneshot(authentic_req)
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        watermark().await,
        seq_app - 1,
        "trusted sparse high coverage must stop before the omitted application; the signed redaction adds none"
    );
    assert_eq!(
        sqlx::query(
            "UPDATE chat.conversation_space_records SET archived_seqs = $4 \
              WHERE space_uri = $1 AND writer_did = $2 AND rkey = $3",
        )
        .bind(&space_uri)
        .bind(&fix.sender_did)
        .bind("3k2sparsehigh1")
        .bind(vec![seq_app, seq_high])
        .execute(&pool)
        .await
        .unwrap()
        .rows_affected(),
        1
    );
    let recompute_req = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.space.putRecord")
        .header("content-type", "application/json")
        .header(
            "authorization",
            format!("Bearer {}", mint_put_jwt(&fix.sender_did, &sender_pds_key)),
        )
        .body(Body::from(
            serde_json::to_vec(&json!({
                "space": space_uri,
                "repo": fix.sender_did,
                "collection": "blue.catbird.labyrinth.batch",
                "rkey": "3k2recompute01",
                "record": {
                    "$type": "blue.catbird.labyrinth.batch",
                    "createdAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                    "threadId": fix.conversation_id.to_string(),
                    "items": [],
                },
            }))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        host_router
            .clone()
            .oneshot(recompute_req)
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        watermark().await,
        seq_high,
        "trusted coverage can cross metadata gaps only after every application entry is covered"
    );

    // Synthetic coverage exercises contiguity bookkeeping only. Receipt-based
    // 72h pruning remains disabled until archive contents are provable.
    sqlx::query("DELETE FROM chat.device_entry_acks WHERE conversation_id = $1")
        .bind(fix.conversation_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        prune_expired_application_payloads(&pool, Utc::now() + Duration::hours(73))
            .await
            .unwrap(),
        0,
        "archive watermark alone must not activate 72h early pruning"
    );
    assert_eq!(
        prune_expired_application_payloads(&pool, Utc::now() + Duration::hours(721))
            .await
            .unwrap(),
        2,
        "the 30-day ceiling still prunes both application payloads"
    );

    // -------------------------------------------------------------------------
    // Part D (`B10`):
    // 1) `federated-group-device` (`dpop_jkt IS NULL`) aged 90d is NOT marked dormant by `mark_inactive_devices`.
    // 2) Aging a pending sibling never auto-promotes it on auth or sweep. Its
    //    active sibling can see and deny it even after the old 72h boundary.
    // -------------------------------------------------------------------------
    let fed_dev_id = Uuid::new_v4();
    let aged_90d = Utc::now() - Duration::days(90);
    sqlx::query("INSERT INTO chat.principals (user_did, created_at) VALUES ('did:web:r2-fed-peer.catbird.blue', $1) ON CONFLICT DO NOTHING")
        .bind(aged_90d)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at, last_active_at, dormant_at) \
         VALUES ('did:web:r2-fed-peer.catbird.blue', $1, 'federated-group-device', 'active', NULL, 1, chat.protocol_capabilities(), $2, $2, $2, NULL)",
    )
    .bind(fed_dev_id)
    .bind(aged_90d)
    .execute(&pool)
    .await
    .unwrap();
    let _ = mark_inactive_devices(&pool, Utc::now()).await.unwrap();
    let fed_dormant: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT dormant_at FROM chat.devices WHERE user_did = 'did:web:r2-fed-peer.catbird.blue' AND device_id = $1",
    )
    .bind(fed_dev_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        fed_dormant.is_none(),
        "B10: federated-group-device (dpop_jkt IS NULL) must never be marked dormant by local inactivity sweep"
    );

    let alice_acct = AccountIdentity::create().await;
    let alice_d1 = DeviceIdentity::build(&alice_acct, "Alice Primary", 2);
    let alice_d2 = DeviceIdentity::build(&alice_acct, "Alice Hold Sibling", 2);
    let (st_d1, _) = http::send(router.clone(), alice_d1.enroll_request()).await;
    assert_eq!(st_d1, StatusCode::OK);
    let (st_d2, b_d2) = http::send(router.clone(), alice_d2.enroll_request()).await;
    assert_eq!(st_d2, StatusCode::OK);
    assert_eq!(b_d2["device"]["status"], "pending_approval");

    // At 71h (`< 72h` hold): still `pending_approval` (`401 NotAuthorized`).
    {
        let mut tx71 = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *tx71)
            .await
            .unwrap();
        sqlx::query("UPDATE chat.devices SET created_at = clock_timestamp() - interval '71 hours' WHERE user_did = $1 AND device_id = $2")
            .bind(&alice_acct.did)
            .bind(alice_d2.device_id)
            .execute(&mut *tx71)
            .await
            .unwrap();
        tx71.commit().await.unwrap();
    }
    let (st_71h, _) = http::send(
        router.clone(),
        alice_d2.dpop_get_request(
            "blue.catbird.chat.getDevices",
            &format!("userDids={}", fix.recipient_did),
        ),
    )
    .await;
    assert_eq!(
        st_71h,
        StatusCode::UNAUTHORIZED,
        "B10: pending_approval sibling < 72h must stay gated"
    );

    // At 73h the pending device still has no authority. Neither a background
    // sweep nor ordinary authentication is a recovery approval action.
    {
        let mut tx73 = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *tx73)
            .await
            .unwrap();
        sqlx::query("UPDATE chat.devices SET created_at = clock_timestamp() - interval '73 hours' WHERE user_did = $1 AND device_id = $2")
            .bind(&alice_acct.did)
            .bind(alice_d2.device_id)
            .execute(&mut *tx73)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE chat.device_promotion_audit \
                SET recorded_at = clock_timestamp() - interval '73 hours' \
              WHERE user_did = $1 AND device_id = $2 AND event_kind = 'pending_notice'",
        )
        .bind(&alice_acct.did)
        .bind(alice_d2.device_id)
        .execute(&mut *tx73)
        .await
        .unwrap();
        tx73.commit().await.unwrap();
    }
    let _ = mark_inactive_devices(&pool, Utc::now()).await.unwrap();
    let still_pending: String = sqlx::query_scalar(
        "SELECT status FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&alice_acct.did)
    .bind(alice_d2.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(still_pending, "pending_approval");
    let (st_73h_dir, _) = http::send(
        router.clone(),
        alice_d2.dpop_get_request(
            "blue.catbird.chat.getDevices",
            &format!("userDids={}", fix.recipient_did),
        ),
    )
    .await;
    assert_eq!(
        st_73h_dir,
        StatusCode::UNAUTHORIZED,
        "pending sibling must not silently promote on DPoP auth after 72h"
    );
    let (st_73h_convos, _) = http::send(
        router.clone(),
        alice_d2.bearer_get_request(
            "blue.catbird.chat.getConversations",
            &format!("actorDeviceId={}", alice_d2.device_id),
        ),
    )
    .await;
    assert_eq!(
        st_73h_convos,
        StatusCode::UNAUTHORIZED,
        "pending sibling must not silently promote on Bearer read authority"
    );

    let (own_status, own_body) = http::send(
        router.clone(),
        alice_d1.dpop_get_request("blue.catbird.chat.getOwnDevices", ""),
    )
    .await;
    assert_eq!(own_status, StatusCode::OK);
    assert!(own_body["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |item| item["device"]["deviceId"] == alice_d2.device_id.to_string()
                && item["device"]["status"] == "pending_approval"
        ));
    let pending_notice_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.device_promotion_audit \
          WHERE user_did = $1 AND device_id = $2 AND event_kind = 'pending_notice'",
    )
    .bind(&alice_acct.did)
    .bind(alice_d2.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        pending_notice_count, 1,
        "pending enrollment must be audited"
    );

    let deny = alice_d1.revocation_wrapper(alice_d2.device_id, 1);
    let (deny_status, deny_body) = http::send(
        router.clone(),
        alice_d1.dpop_signed_post_request("blue.catbird.chat.revokeDevice", &deny),
    )
    .await;
    assert_eq!(deny_status, StatusCode::OK, "{deny_body}");
    assert_eq!(deny_body["device"]["status"], "revoked");
    let promoted_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.device_promotion_audit \
          WHERE user_did = $1 AND device_id = $2 AND event_kind = 'recovery_promoted'",
    )
    .bind(&alice_acct.did)
    .bind(alice_d2.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(promoted_count, 0, "a denied device must not be promoted");

    pool.close().await;
    std::env::remove_var("FEDERATION_TEST_ALLOW_ALL_RELATIONSHIPS");
    std::env::remove_var("APP_ENV");
}
