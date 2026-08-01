//! End-to-end handler tests for the clean-chat device-lifecycle endpoints
//! (`blue.catbird.chat.{enrollDevice,replenishKeyPackages,rebindDeviceAuthentication,
//! getDevices,getOwnDevices}`) plus the cutover-gated `revokeDevice` stub.
//!
//! These fire real HTTP requests at the real `chat_router` (through the shared
//! admit spine + error mapper) so the handler wiring, cutover gate, DPoP
//! extraction, and repository composition are all exercised end to end. The
//! authenticated cases build the full Nest ES256 token + DPoP proof + canonical
//! Ed25519-signed body + real MLS key-package fixtures (modelled on
//! `chat_protocol_auth.rs`) and assert the RULED conformance conditions by reading
//! the certified `device_directory` projection back after the call.
//!
//! Timestamps are wall-clock relative because the handler captures a real trusted
//! instant; every token/proof/body is minted around `Utc::now()` so the captured
//! instant lands inside the protocol bounds. Every authenticated case uses fresh
//! random DID / device / jti / auth_txn values so the never-truncated clean-chat
//! gate database accumulates no cross-run collisions.
//!
//! The authenticated (database) cases are `#[ignore]`d like the other clean-chat
//! live suites; run them explicitly against the dedicated database:
//!   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_device_handlers -- --ignored --test-threads=1

#![allow(dead_code)]

mod common;

#[allow(dead_code)]
#[path = "../src/chat_protocol/cursor.rs"]
mod cursor;
#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[allow(dead_code)]
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

mod chat_protocol {
    pub mod model {
        pub use crate::model::*;
    }

    pub mod transcript {
        pub use crate::transcript::*;
    }

    pub mod validation {
        pub use crate::validation::*;
    }

    pub mod cursor {
        pub use crate::cursor::*;
    }

    // Enumerated per-module rather than including `repository/mod.rs` wholesale:
    // that file opens with an inner `//!` doc comment, which is not accepted in
    // `include!` position, and it would additionally declare every sibling module
    // whose own `super::super::*` references this shim does not carry.
    pub mod repository {
        pub mod device_directory {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/device_directory.rs"
            ));
        }
        pub mod auth {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/auth.rs"
            ));
        }
        pub mod inventory {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/inventory.rs"
            ));
        }
    }

    pub mod dpop {
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/dpop.rs"
        ));
    }
}

mod repository {
    pub(crate) use crate::chat_protocol::repository::*;
}

use std::sync::{Arc, Once};

use axum::{
    body::Body,
    extract::FromRef,
    http::{Request, StatusCode},
    Router,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use p256::ecdsa::SigningKey;
use serde_json::Value;
use tower_util::ServiceExt;

use catbird_server::handlers::chat::{chat_router, ChatRuntime};
use catbird_server::storage::DbPool;

const ISSUER: &str = "did:web:api.catbird.blue";
const AUDIENCE: &str = "did:web:chat.catbird.blue";
const NEST_KEY_ID: &str = "nest-key-1";
const CHAT_INSTANCE: &str = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
const EXTERNAL_BASE: &str = "https://chat.example.net";

// =============================================================================
// Test application state + router assembly
// =============================================================================

#[derive(Clone)]
struct TestState {
    pool: DbPool,
    runtime: Arc<ChatRuntime>,
}

impl FromRef<TestState> for DbPool {
    fn from_ref(state: &TestState) -> DbPool {
        state.pool.clone()
    }
}

impl FromRef<TestState> for Arc<ChatRuntime> {
    fn from_ref(state: &TestState) -> Arc<ChatRuntime> {
        state.runtime.clone()
    }
}

/// The fixed Nest signing key; its public half is the verifier's trusted key.
fn nest_signing_key() -> SigningKey {
    SigningKey::from_bytes((&[0x5a_u8; 32]).into()).expect("nest signing key")
}

/// Configure the clean-chat Nest verifier environment exactly once. The verifying
/// key is the public half of [`nest_signing_key`], so authenticated fixtures that
/// sign with that key verify.
fn ensure_verifier_env() {
    static ENV: Once = Once::new();
    ENV.call_once(|| {
        let point = nest_signing_key().verifying_key().to_encoded_point(false);
        std::env::set_var("CHAT_NEST_ISSUER", ISSUER);
        std::env::set_var("CHAT_NEST_AUDIENCE", AUDIENCE);
        std::env::set_var("CHAT_NEST_KEY_ID", NEST_KEY_ID);
        std::env::set_var("CHAT_NEST_VERIFYING_KEY", STANDARD.encode(point.as_bytes()));
        std::env::set_var("CHAT_INSTANCE_ID", CHAT_INSTANCE);
        std::env::set_var("CHAT_EXTERNAL_BASE", EXTERNAL_BASE);
    });
}

/// Build a runtime with the cutover flag set as requested and the shared trusted
/// Nest verifier configured. The env toggle + `from_env` read is serialized so
/// concurrent constructions cannot observe each other's cutover flag.
fn runtime(cutover_enabled: bool) -> Arc<ChatRuntime> {
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    ensure_verifier_env();
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    if cutover_enabled {
        std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    } else {
        std::env::remove_var("CHAT_CUTOVER_ENABLED");
    }
    Arc::new(ChatRuntime::from_env().expect("build clean-chat runtime"))
}

fn router_with(pool: DbPool, cutover_enabled: bool) -> Router {
    chat_router::<TestState>().with_state(TestState {
        pool,
        runtime: runtime(cutover_enabled),
    })
}

/// A router with a pool that is never touched (cutover/gate/stub cases short
/// circuit before any database access).
fn stateless_router(cutover_enabled: bool) -> Router {
    // A lazily-connected pool that is never queried; `connect_lazy` performs no IO.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://127.0.0.1/unused_clean_chat_gate")
        .expect("lazy pool");
    router_with(pool, cutover_enabled)
}

fn xrpc(nsid: &str) -> String {
    format!("/xrpc/{nsid}")
}

async fn send(router: Router, request: Request<Body>) -> (StatusCode, Value) {
    let (status, bytes) = send_raw(router, request).await;
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

/// Like [`send`] but returns the exact response bytes, so a test can assert
/// byte-identical idempotent replay (not merely structurally-equal JSON) — the
/// OQ-3 verbatim-replay contract (M-1).
async fn send_raw(router: Router, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = router.oneshot(request).await.expect("router response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("collect response body");
    (status, bytes.to_vec())
}

fn get(nsid: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(xrpc(nsid))
        .body(Body::empty())
        .expect("build GET request")
}

fn post_empty(nsid: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(xrpc(nsid))
        .header("content-type", "application/json")
        .body(Body::empty())
        .expect("build POST request")
}

const DEVICE_POST_ENDPOINTS: &[&str] = &[
    "blue.catbird.chat.enrollDevice",
    "blue.catbird.chat.replenishKeyPackages",
    "blue.catbird.chat.rebindDeviceAuthentication",
    "blue.catbird.chat.revokeDevice",
];
const DEVICE_GET_ENDPOINTS: &[&str] = &[
    "blue.catbird.chat.getDevices",
    "blue.catbird.chat.getOwnDevices",
];

// =============================================================================
// Task 7 — handler authority composition (no database)
// =============================================================================

/// The active device writers must keep idempotent response bytes opaque until
/// their endpoint-specific prelude has re-established terminal authority in the
/// handler-owned transaction.  This deliberately pins the composition seam:
/// the retired receipt-only helpers cannot re-enter a production handler.
#[test]
fn active_device_handlers_use_consuming_operation_preludes_not_legacy_receipts() {
    for (source, admission, preparation, completion) in [
        (
            include_str!("../src/handlers/chat/enroll_device.rs"),
            "admit_enrollment_operation_only",
            "prepare_enrollment_operation",
            "complete_enrollment_bootstrap_operation",
        ),
        (
            include_str!("../src/handlers/chat/rebind_device_authentication.rs"),
            "admit_rebind_operation_only",
            "prepare_rebind_operation",
            "complete_rebind_bootstrap_operation",
        ),
        (
            include_str!("../src/handlers/chat/replenish_key_packages.rs"),
            "admit_replenishment_operation_only",
            "prepare_replenishment_operation",
            "complete_replenishment_operation",
        ),
    ] {
        assert!(
            source.contains(admission),
            "missing operation-only admission: {admission}"
        );
        assert!(
            source.contains(preparation),
            "missing endpoint-aware operation preparation: {preparation}"
        );
        assert!(
            source.contains("into_completion_guard"),
            "completion guard was not consumed"
        );
        assert!(
            source.contains(completion),
            "missing consuming completion: {completion}"
        );
        for legacy in [
            "arbitrate_business_idempotency",
            "recheck_business_authority",
            "record_completed_idempotency",
            "prepare_enrollment_business",
            "prepare_rebind_business",
            "persist_enrollment_and_completion",
            "persist_rebind_and_completion",
        ] {
            assert!(
                !source.contains(legacy),
                "legacy receipt helper remains in an active handler: {legacy}"
            );
        }
        for repository_internal in [
            "VerifiedChatDeviceRequest",
            "OperationReplayGuard",
            "OperationReservationGuard",
            "validate_enrollment_operation_replay",
            "validate_rebind_operation_replay",
            "validate_replenishment_operation_replay",
        ] {
            assert!(
                !source.contains(repository_internal),
                "repository authority escaped into active handler: {repository_internal}"
            );
        }
    }
}

// =============================================================================
// Tier 1 — cutover gate, revokeDevice stub, DPoP extraction (no database)
// =============================================================================

#[tokio::test]
async fn cutover_disabled_returns_declared_cutover_required_for_every_device_endpoint() {
    for nsid in DEVICE_POST_ENDPOINTS {
        let (status, body) = send(stateless_router(false), post_empty(nsid)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{nsid} POST status");
        assert_eq!(body["error"], "CutoverRequired", "{nsid} POST error");
    }
    for nsid in DEVICE_GET_ENDPOINTS {
        let (status, body) = send(stateless_router(false), get(nsid)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{nsid} GET status");
        assert_eq!(body["error"], "CutoverRequired", "{nsid} GET error");
    }
}

#[tokio::test]
async fn revoke_device_stub_is_cutover_required_before_cutover() {
    let (status, body) = send(
        stateless_router(false),
        post_empty("blue.catbird.chat.revokeDevice"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "CutoverRequired");
}

#[tokio::test]
async fn revoke_device_requires_dpop_after_cutover() {
    // revokeDevice IS implemented: `chat_router` registers the real `revoke_device::handle`
    // under `cfg(not(test))`, which is the arm an integration test links (cargo builds the
    // library without `--test`), so the shared `not_implemented` stub is never registered
    // for it. Post-cutover the request therefore runs ordinary signed-operation admission —
    // the cutover gate opens, then DPoP header extraction rejects a request carrying none
    // with the declared `InvalidDPoP`, exactly as for every other implemented endpoint.
    let (status, body) = send(
        stateless_router(true),
        post_empty("blue.catbird.chat.revokeDevice"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "InvalidDPoP");
}

#[tokio::test]
async fn cutover_enabled_missing_dpop_headers_is_invalid_dpop() {
    // Enrollment (POST) and getDevices (GET) both fail DPoP header extraction with
    // the declared InvalidDPoP once the cutover gate is open.
    let (status, body) = send(
        stateless_router(true),
        post_empty("blue.catbird.chat.enrollDevice"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "InvalidDPoP");

    let (status, body) = send(stateless_router(true), get("blue.catbird.chat.getDevices")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "InvalidDPoP");
}

// =============================================================================
// MLS key-package fixtures
// =============================================================================

use ed25519_dalek::SigningKey as Ed25519SigningKey;

/// A real, validatable wire-format-5 MLS `KeyPackage` whose leaf is signed by, and
/// carries, `device_signing`'s Ed25519 key (so `wire::validate_key_package`
/// accepts it under `expected_signature_key = device_signing public`), with the
/// `BasicCredential` identity `credential`.
struct MlsKeyPackage {
    wrapped: Vec<u8>,
    key_package_ref: Vec<u8>,
    not_before: u64,
    not_after: u64,
}

fn build_key_package(
    device_signing: &Ed25519SigningKey,
    credential: &[u8],
    not_before: u64,
    not_after: u64,
) -> MlsKeyPackage {
    use openmls::prelude::{tls_codec::Serialize as TlsSerialize, *};
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::OpenMlsProvider;

    let provider = openmls_libcrux_crypto::Provider::new().expect("libcrux provider");
    let ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
    // The leaf signer IS the device's Ed25519 key: private = 32-byte seed, public
    // = 32-byte verifying key.
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
    MlsKeyPackage {
        wrapped,
        key_package_ref,
        not_before,
        not_after,
    }
}

#[test]
fn built_key_package_validates_under_the_device_signing_key() {
    use catbird_server::chat_protocol::wire::{validate_key_package, KeyPackageValidationPolicy};
    let device = Ed25519SigningKey::from_bytes(&[0x11_u8; 32]);
    let now = chrono::Utc::now().timestamp() as u64;
    let credential = b"did:plc:selftest#3b241101-e2bb-4255-8caf-4136c566a962".to_vec();
    let kp = build_key_package(&device, &credential, now - 300, now + 3_600);
    let device_public = device.verifying_key().to_bytes();
    let policy = KeyPackageValidationPolicy {
        expected_basic_credential: &credential,
        expected_signature_key: &device_public,
        now_unix_seconds: now,
        max_bytes: 65536,
    };
    let validated = validate_key_package(&kp.wrapped, policy).expect("KP validates");
    assert_eq!(validated.key_package_ref().as_slice(), kp.key_package_ref);
}

// =============================================================================
// Nest token / DPoP proof / signed-body fixtures (wall-clock relative)
// =============================================================================

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{signature::Signer as _, Signature as P256Signature};
use sha2::{Digest, Sha256};

use transcript::decode_and_verify_enrollment_body;
use validation::{ed25519_key_id, TrustedExternalBase, ValidatedChatNsid};

/// A random, always-valid P-256 signing key (rejection-sampled from two UUIDs so
/// no all-same-byte scalar can slip through and panic).
fn random_p256() -> SigningKey {
    loop {
        let mut seed = [0_u8; 32];
        seed[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        seed[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        if let Ok(key) = SigningKey::from_slice(&seed) {
            return key;
        }
    }
}

fn public_jwk(key: &SigningKey) -> Value {
    let point = key.verifying_key().to_encoded_point(false);
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    })
}

fn jwk_thumbprint(jwk: &Value) -> String {
    let canonical = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap()
    );
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn sign_jwt(header: Value, claims: Value, key: &SigningKey) -> String {
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature: P256Signature = key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn dpop_proof(
    key: &SigningKey,
    jwk: &Value,
    htm: &str,
    htu: &str,
    access_token: &str,
    iat: i64,
    jti_bytes: &[u8],
) -> String {
    sign_jwt(
        serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":jwk}),
        serde_json::json!({
            "htm": htm,
            "htu": htu,
            "ath": URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes())),
            "iat": iat,
            "jti": URL_SAFE_NO_PAD.encode(jti_bytes),
        }),
        key,
    )
}

/// Sign a `{ "$type": "…Body", … }` object into the `{ body, signature }` wrapper,
/// signing the exact canonical transcript the decoders reconstruct.
fn sign_chat_body(body: Value, key: &Ed25519SigningKey) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    use transcript::decode_canonical_signed_mutation;
    let mut wrapper = serde_json::json!({
        "body": body,
        "signature": STANDARD.encode([0_u8; 64]),
    });
    let unsigned = serde_json::to_vec(&wrapper).unwrap();
    if let Ok(canonical) = decode_canonical_signed_mutation(&unsigned) {
        let signature = key.sign(canonical.transcript_bytes());
        wrapper["signature"] = serde_json::json!(STANDARD.encode(signature.to_bytes()));
    }
    serde_json::to_vec(&wrapper).unwrap()
}

/// The server-pinned device capability profile (mirrors `chat.protocol_capabilities()`).
fn capability_profile() -> Value {
    serde_json::json!({
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

fn canonical_timestamp(seconds_from_now: i64) -> String {
    let dt = chrono::Utc::now() + chrono::Duration::seconds(seconds_from_now);
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn random_did() -> String {
    let bytes: [u8; 15] = uuid::Uuid::new_v4().as_bytes()[..15].try_into().unwrap();
    let mut alphabet_bytes = uuid::Uuid::new_v4().as_bytes()[1..16].to_vec();
    alphabet_bytes[..15].copy_from_slice(&bytes);
    let suffix: String = (0..24)
        .map(|i| {
            let value = (bytes[i % 15] as usize + i * 7) % 32;
            char::from(b"abcdefghijklmnopqrstuvwxyz234567"[value])
        })
        .collect();
    format!("did:plc:{suffix}")
}

fn htu_for(nsid: &str) -> String {
    let base = TrustedExternalBase::parse(EXTERNAL_BASE, &std::collections::BTreeSet::new())
        .expect("external base");
    let parsed = ValidatedChatNsid::parse(nsid).expect("nsid");
    base.htu(&parsed)
}

/// A persistent enrollDevice scenario: the device identity and the exact signed
/// enrollment body are fixed, but each [`EnrollScenario::fresh_request`] mints a
/// new Nest token + DPoP proof + `auth_txn` (as the enrollment grant contract
/// requires for a response-loss retry), so the same body can be replayed.
struct EnrollScenario {
    device_signing: Ed25519SigningKey,
    proof_signing: SigningKey,
    proof_jwk: Value,
    proof_jkt: String,
    did: String,
    device_id: uuid::Uuid,
    enrollment_raw: Vec<u8>,
    body_key_id: String,
    signing_key_hash: [u8; 32],
    transcript_hash: [u8; 32],
    key_package_count: usize,
}

impl EnrollScenario {
    fn build(package_count: usize) -> Self {
        let device_signing = Ed25519SigningKey::from_bytes(&uuid_seed());
        let proof_signing = random_p256();
        let proof_jwk = public_jwk(&proof_signing);
        let proof_jkt = jwk_thumbprint(&proof_jwk);

        let did = random_did();
        let device_id = uuid::Uuid::new_v4();
        let credential = format!("{did}#{device_id}");
        let now = chrono::Utc::now().timestamp();
        let key_id = ed25519_key_id(device_signing.verifying_key().as_bytes())
            .expect("key id")
            .as_str()
            .to_owned();

        // Strictly increasing, duplicate-free by computed raw KeyPackageRef.
        let mut built: Vec<MlsKeyPackage> = (0..package_count)
            .map(|index| {
                build_key_package(
                    &device_signing,
                    credential.as_bytes(),
                    (now - 300) as u64,
                    (now + 3_600 + index as i64) as u64,
                )
            })
            .collect();
        built.sort_by(|a, b| a.key_package_ref.cmp(&b.key_package_ref));
        let packages: Vec<Value> = built
            .iter()
            .map(|kp| {
                serde_json::json!({
                    "framing": "mlsMessage",
                    "contentType": "keyPackage",
                    "bytes": STANDARD.encode(&kp.wrapped),
                    "sha256": STANDARD.encode(Sha256::digest(&kp.wrapped)),
                    "keyPackageRef": STANDARD.encode(&kp.key_package_ref),
                })
            })
            .collect();

        let body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#deviceEnrollmentBody",
            "signatureDomain": "CATBIRD-CHAT-DEVICE-ENROLL\u{0}",
            "actorDid": did,
            "deviceId": device_id.to_string(),
            "deviceName": "Test device",
            "keyId": key_id,
            "signaturePublicKey": STANDARD.encode(device_signing.verifying_key().as_bytes()),
            "dpopJkt": proof_jkt,
            "expectedAuthGeneration": 0,
            "capability": capability_profile(),
            "keyPackages": packages,
            "idempotencyKey": uuid::Uuid::new_v4().to_string(),
            "signedAt": canonical_timestamp(0),
        });
        let enrollment_raw = sign_chat_body(body, &device_signing);
        let verified = decode_and_verify_enrollment_body(&enrollment_raw).expect("enrollment body");
        Self {
            device_signing,
            proof_signing,
            proof_jwk,
            proof_jkt,
            did,
            device_id,
            body_key_id: verified.key_id().as_str().to_owned(),
            signing_key_hash: *verified.signing_key_sha256(),
            transcript_hash: *verified.enrollment_transcript_sha256(),
            key_package_count: package_count,
            enrollment_raw,
        }
    }

    /// Mint a fresh-grant HTTP request for the fixed enrollment body.
    fn fresh_request(&self) -> Request<Body> {
        let nsid = "blue.catbird.chat.enrollDevice";
        let now = chrono::Utc::now().timestamp();
        let token = sign_jwt(
            serde_json::json!({"alg":"ES256","typ":"JWT","kid": NEST_KEY_ID}),
            serde_json::json!({
                "iss": ISSUER,
                "sub": self.did,
                "aud": AUDIENCE,
                "lxm": nsid,
                "iat": now,
                "exp": now + 120,
                "jti": uuid::Uuid::new_v4().to_string(),
                "cnf": {"jkt": self.proof_jkt},
                "device_id": self.device_id.to_string(),
                "chat_instance": CHAT_INSTANCE,
                "key_id": self.body_key_id,
                "signing_key_sha256": URL_SAFE_NO_PAD.encode(self.signing_key_hash),
                "enrollment_transcript_sha256": URL_SAFE_NO_PAD.encode(self.transcript_hash),
                "auth_time": now,
                "auth_txn": uuid::Uuid::new_v4().to_string(),
            }),
            &nest_signing_key(),
        );
        let proof = dpop_proof(
            &self.proof_signing,
            &self.proof_jwk,
            "POST",
            &htu_for(nsid),
            &token,
            now,
            uuid::Uuid::new_v4().as_bytes(),
        );
        let wrapper: Value = serde_json::from_slice(&self.enrollment_raw).unwrap();
        let body_bytes =
            serde_json::to_vec(&serde_json::json!({ "signedRequest": wrapper })).unwrap();
        Request::builder()
            .method("POST")
            .uri(xrpc(nsid))
            .header("content-type", "application/json")
            .header("authorization", format!("DPoP {token}"))
            .header("dpop", proof)
            .body(Body::from(body_bytes))
            .expect("enroll request")
    }
}

fn uuid_seed() -> [u8; 32] {
    let mut seed = [0_u8; 32];
    seed[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    seed[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    seed
}

fn rand_byte() -> u8 {
    uuid::Uuid::new_v4().as_bytes()[0] | 1
}

// =============================================================================
// Tier 2 — authenticated end-to-end handler cases (dedicated gate database)
// =============================================================================

use repository::device_directory::read_device_view;

#[tokio::test]
#[ignore]
async fn enroll_device_happy_path_publishes_batch_and_conforms_to_read_back() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let scenario = EnrollScenario::build(3);
    let did = scenario.did.clone();
    let device_id = scenario.device_id;
    let count = scenario.key_package_count as i64;

    let (status, body) = send(router_with(pool.clone(), true), scenario.fresh_request()).await;
    assert_eq!(status, StatusCode::OK, "enroll failed: {body}");
    let device = &body["device"];
    assert_eq!(device["availablePackageCount"], count);
    assert_eq!(device["reservedPackageCount"], 0);
    assert_eq!(device["authGeneration"], 1);
    assert_eq!(device["status"], "active");
    assert_eq!(device["deviceId"], device_id.to_string());

    // Full-field-set conformance (M-4): the enroll deviceView carries exactly the
    // declared deviceView fields — no missing field, no extra.
    let device_obj = device.as_object().expect("device object");
    for field in DEVICE_VIEW_FIELDS {
        assert!(
            device_obj.contains_key(*field),
            "deviceView missing {field}"
        );
    }
    assert_eq!(
        device_obj.len(),
        DEVICE_VIEW_FIELDS.len(),
        "no extra deviceView fields"
    );

    // RULED conformance: the post-enroll device_directory read must report exactly
    // the counts the response returned.
    let mut tx = pool.begin().await.expect("begin read-back");
    let view = read_device_view(&mut tx, &did, device_id)
        .await
        .expect("read-back ok")
        .expect("device present after enroll");
    assert_eq!(view.available_package_count, count);
    assert_eq!(view.reserved_package_count, 0);
    assert_eq!(
        device["availablePackageCount"].as_i64().unwrap(),
        view.available_package_count,
        "returned availablePackageCount == read-back"
    );
    assert_eq!(
        device["reservedPackageCount"].as_i64().unwrap(),
        view.reserved_package_count
    );
    // M-4: assert the WHOLE deviceView field set against the stored row (parity
    // with the rebind read-back), not just the counts — keyId, signaturePublicKey,
    // dpopJkt, status, authGeneration, and createdAt must equal the persisted
    // device (Option A builds this view by hand, so this pins every hand-set field
    // to the certified projection).
    assert_eq!(view.key_id, device["keyId"].as_str().unwrap());
    assert_eq!(view.dpop_jkt, device["dpopJkt"].as_str().unwrap());
    assert_eq!(view.status, device["status"].as_str().unwrap());
    assert_eq!(
        view.auth_generation,
        device["authGeneration"].as_i64().unwrap()
    );
    assert_eq!(
        device["signaturePublicKey"]["$bytes"].as_str().unwrap(),
        STANDARD.encode(&view.signing_public_key),
        "returned signaturePublicKey == stored signing key"
    );
    assert_eq!(
        device["createdAt"],
        jacquard_created_at(&view),
        "returned createdAt == stored created_at"
    );
    tx.rollback().await.ok();
}

#[tokio::test]
#[ignore]
async fn enroll_device_replay_returns_verbatim_stored_bytes() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let scenario = EnrollScenario::build(2);
    // Same enrollment body, fresh grant each time (response-loss retry). The second
    // call is an idempotent replay returning the exact stored response bytes.
    let (status_1, bytes_1) =
        send_raw(router_with(pool.clone(), true), scenario.fresh_request()).await;
    assert_eq!(status_1, StatusCode::OK, "first enroll status");
    let (status_2, bytes_2) =
        send_raw(router_with(pool.clone(), true), scenario.fresh_request()).await;
    assert_eq!(status_2, StatusCode::OK, "replay enroll status");
    // OQ-3 verbatim contract (M-1): assert byte-for-byte equality, not merely a
    // structural JSON compare (two different serializations parsing to the same
    // Value would pass a Value-compare but violate the byte-stable replay contract).
    assert_eq!(
        bytes_1, bytes_2,
        "idempotent replay returns byte-identical stored response"
    );
}

// -----------------------------------------------------------------------------
// Follow-on request builders (an enrolled device authenticates the rest)
// -----------------------------------------------------------------------------

/// Enroll a fresh device through the handler and assert success, returning the
/// scenario so follow-on requests can authenticate as that device.
async fn enroll_fresh_device(pool: &DbPool, package_count: usize) -> EnrollScenario {
    let scenario = EnrollScenario::build(package_count);
    let (status, body) = send(router_with(pool.clone(), true), scenario.fresh_request()).await;
    assert_eq!(status, StatusCode::OK, "setup enroll failed: {body}");
    scenario
}

fn ordinary_claims(did: &str, device_id: uuid::Uuid, jkt: &str, nsid: &str, now: i64) -> Value {
    serde_json::json!({
        "iss": ISSUER,
        "sub": did,
        "aud": AUDIENCE,
        "lxm": nsid,
        "iat": now,
        "exp": now + 120,
        "jti": uuid::Uuid::new_v4().to_string(),
        "cnf": {"jkt": jkt},
        "device_id": device_id.to_string(),
        "chat_instance": CHAT_INSTANCE,
    })
}

fn jwt_header() -> Value {
    serde_json::json!({"alg":"ES256","typ":"JWT","kid": NEST_KEY_ID})
}

/// A signed-body procedure request authenticated by the enrolled device's own
/// (unchanged) DPoP key.
fn signed_request(scenario: &EnrollScenario, nsid: &str, signed_wrapper: &[u8]) -> Request<Body> {
    signed_request_with_token_jkt(scenario, nsid, signed_wrapper, &scenario.proof_jkt)
}

/// Test-only variant used by replay-drift coverage to prove the Nest-token JKT
/// remains bound to the DPoP key before any replay response can be released.
fn signed_request_with_token_jkt(
    scenario: &EnrollScenario,
    nsid: &str,
    signed_wrapper: &[u8],
    token_jkt: &str,
) -> Request<Body> {
    let now = chrono::Utc::now().timestamp();
    let token = sign_jwt(
        jwt_header(),
        ordinary_claims(&scenario.did, scenario.device_id, token_jkt, nsid, now),
        &nest_signing_key(),
    );
    let proof = dpop_proof(
        &scenario.proof_signing,
        &scenario.proof_jwk,
        "POST",
        &htu_for(nsid),
        &token,
        now,
        uuid::Uuid::new_v4().as_bytes(),
    );
    let wrapper: Value = serde_json::from_slice(signed_wrapper).unwrap();
    let body_bytes = serde_json::to_vec(&serde_json::json!({ "signedRequest": wrapper })).unwrap();
    Request::builder()
        .method("POST")
        .uri(xrpc(nsid))
        .header("content-type", "application/json")
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", proof)
        .body(Body::from(body_bytes))
        .expect("signed request")
}

/// An unsigned (DPoP-only) query request authenticated by the enrolled device.
fn query_request(scenario: &EnrollScenario, nsid: &str, query_suffix: &str) -> Request<Body> {
    let now = chrono::Utc::now().timestamp();
    let token = sign_jwt(
        jwt_header(),
        ordinary_claims(
            &scenario.did,
            scenario.device_id,
            &scenario.proof_jkt,
            nsid,
            now,
        ),
        &nest_signing_key(),
    );
    let proof = dpop_proof(
        &scenario.proof_signing,
        &scenario.proof_jwk,
        "GET",
        &htu_for(nsid),
        &token,
        now,
        uuid::Uuid::new_v4().as_bytes(),
    );
    Request::builder()
        .method("GET")
        .uri(format!("{}{}", xrpc(nsid), query_suffix))
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", proof)
        .body(Body::empty())
        .expect("query request")
}

/// Build a signed replenishment body carrying `count` fresh, real key packages
/// signed under the device's registered key, with a fresh random idempotency key.
fn replenishment_wrapper(scenario: &EnrollScenario, count: usize) -> Vec<u8> {
    replenishment_wrapper_keyed(scenario, count, &uuid::Uuid::new_v4().to_string())
}

/// Like [`replenishment_wrapper`] but with a caller-pinned `idempotency_key`, so a
/// test can send two DIFFERENT bodies under the SAME key to exercise the
/// request-binding-mismatch path (M-2).
fn replenishment_wrapper_keyed(
    scenario: &EnrollScenario,
    count: usize,
    idempotency_key: &str,
) -> Vec<u8> {
    let credential = format!("{}#{}", scenario.did, scenario.device_id);
    let now = chrono::Utc::now().timestamp();
    let mut built: Vec<MlsKeyPackage> = (0..count)
        .map(|index| {
            build_key_package(
                &scenario.device_signing,
                credential.as_bytes(),
                (now - 300) as u64,
                (now + 3_600 + index as i64) as u64,
            )
        })
        .collect();
    built.sort_by(|a, b| a.key_package_ref.cmp(&b.key_package_ref));
    let packages: Vec<Value> = built
        .iter()
        .map(|kp| {
            serde_json::json!({
                "framing": "mlsMessage",
                "contentType": "keyPackage",
                "bytes": STANDARD.encode(&kp.wrapped),
                "sha256": STANDARD.encode(Sha256::digest(&kp.wrapped)),
                "keyPackageRef": STANDARD.encode(&kp.key_package_ref),
            })
        })
        .collect();
    let key_id = ed25519_key_id(scenario.device_signing.verifying_key().as_bytes())
        .unwrap()
        .as_str()
        .to_owned();
    let body = serde_json::json!({
        "$type": "blue.catbird.chat.defs#keyPackageReplenishmentBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REPLENISH\u{0}",
        "actorDid": scenario.did,
        "actorDeviceId": scenario.device_id.to_string(),
        "authGeneration": 1,
        "dpopJkt": scenario.proof_jkt,
        "keyId": key_id,
        "keyPackages": packages,
        "signaturePublicKey": STANDARD.encode(scenario.device_signing.verifying_key().as_bytes()),
        "idempotencyKey": idempotency_key,
        "signedAt": canonical_timestamp(0),
    });
    sign_chat_body(body, &scenario.device_signing)
}

/// Build a rebind body rotating to `new_proof`'s DPoP key, signed by the device's
/// registered key.
fn rebind_request(scenario: &EnrollScenario, new_proof: &SigningKey) -> Request<Body> {
    let nsid = "blue.catbird.chat.rebindDeviceAuthentication";
    let now = chrono::Utc::now().timestamp();
    let new_jwk = public_jwk(new_proof);
    let new_jkt = jwk_thumbprint(&new_jwk);
    let key_id = ed25519_key_id(scenario.device_signing.verifying_key().as_bytes())
        .unwrap()
        .as_str()
        .to_owned();
    let body = serde_json::json!({
        "$type": "blue.catbird.chat.defs#deviceAuthenticationRebindBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REBIND\u{0}",
        "actorDid": scenario.did,
        "actorDeviceId": scenario.device_id.to_string(),
        "keyId": key_id,
        "expectedAuthGeneration": 1,
        "currentDpopJkt": scenario.proof_jkt,
        "newDpopJkt": new_jkt,
        "idempotencyKey": uuid::Uuid::new_v4().to_string(),
        "signedAt": canonical_timestamp(0),
    });
    let raw = sign_chat_body(body, &scenario.device_signing);
    let token = sign_jwt(
        jwt_header(),
        ordinary_claims(&scenario.did, scenario.device_id, &new_jkt, nsid, now),
        &nest_signing_key(),
    );
    let proof = dpop_proof(
        new_proof,
        &new_jwk,
        "POST",
        &htu_for(nsid),
        &token,
        now,
        uuid::Uuid::new_v4().as_bytes(),
    );
    let wrapper: Value = serde_json::from_slice(&raw).unwrap();
    let body_bytes = serde_json::to_vec(&serde_json::json!({ "signedRequest": wrapper })).unwrap();
    Request::builder()
        .method("POST")
        .uri(xrpc(nsid))
        .header("content-type", "application/json")
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", proof)
        .body(Body::from(body_bytes))
        .expect("rebind request")
}

const DEVICE_VIEW_FIELDS: &[&str] = &[
    "authGeneration",
    "availablePackageCount",
    "createdAt",
    "deviceId",
    "dpopJkt",
    "keyId",
    "reservedPackageCount",
    "signaturePublicKey",
    "status",
    "updatedAt",
];

#[tokio::test]
#[ignore]
async fn replenish_key_packages_adds_to_inventory_and_matches_wire_golden() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let scenario = enroll_fresh_device(&pool, 2).await;

    let wrapper = replenishment_wrapper(&scenario, 3);
    let request = signed_request(
        &scenario,
        "blue.catbird.chat.replenishKeyPackages",
        &wrapper,
    );
    let (status, body) = send(router_with(pool.clone(), true), request).await;
    assert_eq!(status, StatusCode::OK, "replenish failed: {body}");

    // Wire golden: the response is exactly a deviceView with the full field set and
    // the single post-publish count source (2 enrolled + 3 replenished).
    let device = body["device"].as_object().expect("device object");
    for field in DEVICE_VIEW_FIELDS {
        assert!(device.contains_key(*field), "deviceView missing {field}");
    }
    assert_eq!(
        device.len(),
        DEVICE_VIEW_FIELDS.len(),
        "no extra deviceView fields"
    );
    assert_eq!(body["device"]["availablePackageCount"], 5);
    assert_eq!(body["device"]["reservedPackageCount"], 0);
    assert!(body["device"]["signaturePublicKey"]["$bytes"].is_string());

    let mut tx = pool.begin().await.unwrap();
    let view = read_device_view(&mut tx, &scenario.did, scenario.device_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        view.available_package_count, 5,
        "read-back == returned count"
    );
    tx.rollback().await.ok();
}

#[tokio::test]
#[ignore]
async fn replenish_same_idempotency_key_different_body_is_invalid_request() {
    // Negative idempotency at the handler boundary (M-2): a second signed request
    // that reuses a completed idempotency key but carries a DIFFERENT body must not
    // replay the stored response — the repository rejects the conflicting reuse and
    // the handler surfaces the declared `IdempotencyConflict` (the observed repo
    // mapping for a same-key/different-body reuse; `IdempotencyConflict` is declared
    // by replenishKeyPackages). This locks the handler↔repo mapping one layer above
    // the certified `chat_protocol_auth` coverage.
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let scenario = enroll_fresh_device(&pool, 2).await;
    let idempotency_key = uuid::Uuid::new_v4().to_string();
    let nsid = "blue.catbird.chat.replenishKeyPackages";

    // First request under key K: three fresh packages, succeeds.
    let first = replenishment_wrapper_keyed(&scenario, 3, &idempotency_key);
    let (status, body) = send(
        router_with(pool.clone(), true),
        signed_request(&scenario, nsid, &first),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first replenish: {body}");

    // Same key K, a DIFFERENT body (two distinct fresh packages) with a fresh DPoP
    // grant: not a verbatim replay, so the binding check rejects it.
    let second = replenishment_wrapper_keyed(&scenario, 2, &idempotency_key);
    let (status, body) = send(
        router_with(pool.clone(), true),
        signed_request(&scenario, nsid, &second),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "mismatched-body replay status: {body}"
    );
    assert_eq!(
        body["error"], "IdempotencyConflict",
        "mismatched-body replay error"
    );
}

#[tokio::test]
#[ignore]
async fn rebind_device_authentication_rotates_and_conforms_to_read_back() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let scenario = enroll_fresh_device(&pool, 2).await;
    let new_proof = random_p256();
    let new_jkt = jwk_thumbprint(&public_jwk(&new_proof));

    let request = rebind_request(&scenario, &new_proof);
    let (status, body) = send(router_with(pool.clone(), true), request).await;
    assert_eq!(status, StatusCode::OK, "rebind failed: {body}");
    let device = &body["device"];
    assert_eq!(device["dpopJkt"], new_jkt, "rotated to the new thumbprint");
    assert_eq!(device["authGeneration"], 2, "generation incremented");
    assert_eq!(
        device["availablePackageCount"], 2,
        "counts unchanged by rebind"
    );
    assert_eq!(device["reservedPackageCount"], 0);

    // RULED conformance: post-rebind read_device_view matches the response on
    // counts + keyId + createdAt.
    let mut tx = pool.begin().await.unwrap();
    let view = read_device_view(&mut tx, &scenario.did, scenario.device_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        view.available_package_count,
        device["availablePackageCount"].as_i64().unwrap()
    );
    assert_eq!(
        view.reserved_package_count,
        device["reservedPackageCount"].as_i64().unwrap()
    );
    assert_eq!(view.key_id, device["keyId"].as_str().unwrap());
    assert_eq!(view.auth_generation, 2, "read-back reflects the rotation");
    // createdAt is preserved by a rebind: the response createdAt equals the stored
    // device's created_at.
    let created_at = jacquard_created_at(&view);
    assert_eq!(device["createdAt"], created_at, "createdAt preserved");
    tx.rollback().await.ok();
}

#[tokio::test]
#[ignore]
async fn get_devices_returns_addressable_view_for_the_requested_did() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let scenario = enroll_fresh_device(&pool, 4).await;
    let suffix = format!("?userDids={}", scenario.did);
    let request = query_request(&scenario, "blue.catbird.chat.getDevices", &suffix);
    let (status, body) = send(router_with(pool.clone(), true), request).await;
    assert_eq!(status, StatusCode::OK, "getDevices failed: {body}");
    let devices = body["devices"].as_array().expect("devices array");
    let device = devices
        .iter()
        .find(|d| d["deviceId"] == scenario.device_id.to_string())
        .expect("enrolled device present in addressable set");
    assert_eq!(device["availablePackageCount"], 4);
    assert_eq!(device["userDid"], scenario.did);
    assert!(device["keyId"].is_string());
    // The pinned capability decoded into the DTO, not a hardcoded profile.
    assert_eq!(
        device["capability"]["cipherSuite"],
        "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"
    );
}

#[tokio::test]
#[ignore]
async fn get_own_devices_materializes_single_page_snapshot() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let scenario = enroll_fresh_device(&pool, 2).await;
    let request = query_request(&scenario, "blue.catbird.chat.getOwnDevices", "");
    let (status, body) = send(router_with(pool.clone(), true), request).await;
    assert_eq!(status, StatusCode::OK, "getOwnDevices failed: {body}");
    assert_eq!(body["hasMore"], false, "whole own-device set is one page");
    assert!(body.get("nextPageCursor").is_none_or(|c| c.is_null()));
    assert!(body["snapshotExpiresAt"].is_string());
    let items = body["items"].as_array().expect("items array");
    let own = items
        .iter()
        .find(|item| item["device"]["deviceId"] == scenario.device_id.to_string())
        .expect("own device present");
    assert_eq!(own["device"]["availablePackageCount"], 2);
    assert_eq!(own["device"]["status"], "active");
}

/// Render a directory row's `created_at` the same way the handler does, so the
/// conformance assertion compares like for like.
fn jacquard_created_at(view: &repository::device_directory::DeviceDirectoryView) -> String {
    let datetime = jacquard_common::types::string::Datetime::new(view.created_at.fixed_offset());
    serde_json::to_value(&datetime)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

// =============================================================================
// Task 7 — failure atomicity and replay-drift gate (dedicated database only)
// =============================================================================

/// The Task 7 handlers must reject replay when its authenticated device binding,
/// Nest-token binding, or immutable operation claim no longer matches. Every
/// branch uses a legal operation sequence; this fixture never hand-edits an
/// immutable claim or device/key-package state.
#[tokio::test]
#[ignore = "requires the dedicated clean-chat gate database"]
async fn task7_replay_rejects_registered_jkt_token_and_claim_mismatch() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;

    // A successful legal rebind changes the registered JKT and generation. An
    // old replenishment retry signed by the prior DPoP key cannot release bytes.
    let scenario = enroll_fresh_device(&pool, 2).await;
    let idempotency_key = uuid::Uuid::new_v4().to_string();
    let wrapper = replenishment_wrapper_keyed(&scenario, 1, &idempotency_key);
    let nsid = "blue.catbird.chat.replenishKeyPackages";
    let (status, body) = send(
        router_with(pool.clone(), true),
        signed_request(&scenario, nsid, &wrapper),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "initial replenish failed: {body}");
    let new_proof = random_p256();
    let (rebind_status, rebind_body) = send(
        router_with(pool.clone(), true),
        rebind_request(&scenario, &new_proof),
    )
    .await;
    assert_eq!(
        rebind_status,
        StatusCode::OK,
        "legal rebind failed: {rebind_body}"
    );
    let (status, _) = send(
        router_with(pool.clone(), true),
        signed_request(&scenario, nsid, &wrapper),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "drifted JKT must not replay");

    // A fresh scenario isolates the Nest-token `cnf.jkt` mismatch from the
    // registered-device drift above.
    let token_scenario = enroll_fresh_device(&pool, 2).await;
    let token_wrapper = replenishment_wrapper(&token_scenario, 1);
    let (status, _) = send(
        router_with(pool.clone(), true),
        signed_request_with_token_jkt(
            &token_scenario,
            nsid,
            &token_wrapper,
            "task7-token-jkt-drift",
        ),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "drifted token JKT must not replay");

    // The immutable claim is exercised honestly: a distinct signed body with
    // the same operation ID conflicts rather than being admitted as a replay.
    let claim_scenario = enroll_fresh_device(&pool, 2).await;
    let claim_key = uuid::Uuid::new_v4().to_string();
    let first = replenishment_wrapper_keyed(&claim_scenario, 1, &claim_key);
    let second = replenishment_wrapper_keyed(&claim_scenario, 2, &claim_key);
    let (status, body) = send(
        router_with(pool.clone(), true),
        signed_request(&claim_scenario, nsid, &first),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "claim fixture first write failed: {body}"
    );
    let (status, _) = send(
        router_with(pool.clone(), true),
        signed_request(&claim_scenario, nsid, &second),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "claim mismatch must not replay");
}

/// SQL fail triggers make the real HTTP handler abort at exact durable
/// boundaries. Every failed request must leave neither its effect graph nor its
/// operation completion graph committed. These are deliberately ignored: they
/// create and remove trigger functions in the dedicated owner-controlled DB.
#[tokio::test]
#[ignore = "requires the dedicated clean-chat gate database"]
async fn task7_injected_claim_effect_and_completion_failures_rollback_the_whole_graph() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;

    for (phase, table, function, trigger) in [
        (
            "claim",
            "chat.operation_claims",
            "task7_fail_claim_write",
            "task7_fail_claim_write_trigger",
        ),
        (
            "effects",
            "chat.key_packages",
            "task7_fail_effect_write",
            "task7_fail_effect_write_trigger",
        ),
        (
            "completion",
            "chat.idempotency_records",
            "task7_fail_completion_write",
            "task7_fail_completion_write_trigger",
        ),
    ] {
        let scenario = EnrollScenario::build(1);
        install_task7_failure_trigger(&pool, table, function, trigger).await;
        let (status, body) = send(router_with(pool.clone(), true), scenario.fresh_request()).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "{phase} injection unexpectedly succeeded: {body}"
        );
        remove_task7_failure_trigger(&pool, table, function, trigger).await;

        for relation in [
            "chat.principals",
            "chat.devices",
            "chat.device_keys",
            "chat.key_packages",
            "chat.operation_claims",
            "chat.idempotency_records",
        ] {
            let count = task7_graph_row_count(&pool, relation, &scenario.did).await;
            assert_eq!(count, 0, "{phase} failure left partial {relation} graph");
        }
    }
}

async fn task7_graph_row_count(pool: &DbPool, relation: &str, did: &str) -> i64 {
    let statement = match relation {
        "chat.principals" => "SELECT count(*) FROM chat.principals WHERE user_did = $1",
        "chat.devices" => "SELECT count(*) FROM chat.devices WHERE user_did = $1",
        "chat.device_keys" => "SELECT count(*) FROM chat.device_keys WHERE user_did = $1",
        "chat.key_packages" => "SELECT count(*) FROM chat.key_packages WHERE owner_did = $1",
        "chat.operation_claims" => {
            "SELECT count(*) FROM chat.operation_claims WHERE principal_did = $1"
        }
        "chat.idempotency_records" => {
            "SELECT count(*) FROM chat.idempotency_records WHERE principal_did = $1"
        }
        _ => panic!("unknown Task 7 graph relation: {relation}"),
    };
    sqlx::query_scalar(statement)
        .bind(did)
        .fetch_one(pool)
        .await
        .expect("count durable graph")
}

async fn install_task7_failure_trigger(pool: &DbPool, table: &str, function: &str, trigger: &str) {
    sqlx::query(&format!(
        "CREATE OR REPLACE FUNCTION chat.{function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'task7 injected failure'; END; $$"
    ))
    .execute(pool)
    .await
    .expect("create Task 7 fail function");
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger} BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION chat.{function}()"
    ))
    .execute(pool)
    .await
    .expect("create Task 7 fail trigger");
}

async fn remove_task7_failure_trigger(pool: &DbPool, table: &str, function: &str, trigger: &str) {
    sqlx::query(&format!("DROP TRIGGER IF EXISTS {trigger} ON {table}"))
        .execute(pool)
        .await
        .expect("drop Task 7 fail trigger");
    sqlx::query(&format!("DROP FUNCTION IF EXISTS chat.{function}()"))
        .execute(pool)
        .await
        .expect("drop Task 7 fail function");
}
