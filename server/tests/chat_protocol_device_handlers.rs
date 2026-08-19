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

// There is deliberately NO crate-level `#![allow(dead_code)]` here. A blanket
// allow is what let two zero-caller negative-path proof helpers survive
// unnoticed in the sibling entitlement suite (review finding F-2): rustc would
// have flagged them on the first build, and the attribute silenced it, so the
// defect was found only by counting references by hand. Any dead item that is
// genuinely inherited scaffolding carries its own narrow `#[allow(dead_code)]`
// with a reason; anything else must fail to be silent.

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
    blob_store: catbird_server::blob_store::BlobStore,
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

impl FromRef<TestState> for catbird_server::blob_store::BlobStore {
    fn from_ref(state: &TestState) -> catbird_server::blob_store::BlobStore {
        state.blob_store.clone()
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
        std::env::set_var(
            "CHAT_CURSOR_KEY_ID",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x11_u8; 32]),
        );
        std::env::set_var(
            "CHAT_CURSOR_SEALING_SECRET",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xA5_u8; 32]),
        );
        std::env::set_var(
            "CHAT_SUBSCRIPTION_ENDPOINT",
            "wss://chat.example.net/xrpc/blue.catbird.chat.subscribeEvents",
        );
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
    Arc::new(
        ChatRuntime::from_env(Arc::new(catbird_server::realtime::SseState::new(8)))
            .expect("build clean-chat runtime"),
    )
}

fn router_with(pool: DbPool, cutover_enabled: bool) -> Router {
    chat_router::<TestState>().with_state(TestState {
        pool,
        runtime: runtime(cutover_enabled),
        blob_store: catbird_server::blob_store::BlobStore::for_route_tests(),
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
    /// Inherited Stage-T scaffolding: the lifetime bounds are recorded by the
    /// builder but no assertion reads them back. Narrowly allowed rather than
    /// removed, because Stage-T successor bytes are preserved outside the
    /// reviewed B-auth additions.
    #[allow(dead_code)]
    not_before: u64,
    /// Inherited Stage-T scaffolding — see `not_before` above.
    #[allow(dead_code)]
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

/// Inherited Stage-T scaffolding with no caller. Narrowly allowed rather than
/// removed, because Stage-T successor bytes are preserved outside the reviewed
/// B-auth additions; the allow is scoped to this item so a NEW zero-caller
/// helper in this file still fails to be silent.
#[allow(dead_code)]
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
    query_request_parts(scenario, nsid, query_suffix).0
}

/// Like [`query_request`], but also returns the exact Nest token and DPoP proof
/// it minted. A redaction sweep over a read-path failure needs the material the
/// request actually carried, not a reconstruction of it.
fn query_request_parts(
    scenario: &EnrollScenario,
    nsid: &str,
    query_suffix: &str,
) -> (Request<Body>, String, String) {
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
    let request = Request::builder()
        .method("GET")
        .uri(format!("{}{}", xrpc(nsid), query_suffix))
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", proof.clone())
        .body(Body::empty())
        .expect("query request");
    (request, token, proof)
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
#[ignore = "requires a disposable clean-chat database"]
async fn task7_injected_claim_effect_and_completion_failures_rollback_the_whole_graph() {
    let (pool, _database) = common::fresh_db::fresh_clean_protocol_db("chat_devhandlers_", 4).await;

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

// =============================================================================
// Stage B (B-auth), Task B4 — existing-device READ authority: the facade half
//
// `getDevices` and `getOwnDevices` are now thin handlers over the two
// repository-owned facades in `chat_protocol::repository::inventory`. Those
// facades are compiled `#[cfg(not(test))]`, because ten integration test crates
// `include!` `inventory.rs` and three of them provide no `dpop` module at all.
//
// THE CONSEQUENCE FOR EVERY TEST BELOW IS ABSOLUTE:
// the facade DOES NOT EXIST in this crate's path-included `mod inventory`.
// Reaching for `repository::inventory::read_addressable_devices_for_admission`
// here would not fail to compile — it would silently bind to a copy of the
// module that has no such item, or worse, in a future edit, to a look-alike that
// production never runs. Every behavioural assertion therefore goes through the
// REAL library: `chat_router` from `catbird_server::handlers::chat`, which cargo
// builds WITHOUT `--test` and which therefore links the real, gated facade.
// Structural claims go through `include_str!` over the production source text.
// There is no third path, and a test that invents one is testing nothing.
// =============================================================================

/// Strip whole-line `//` and `///` comments so a source guard asserts over CODE
/// rather than prose.
///
/// This is load-bearing, not hygiene: both handler doc comments legitimately
/// contain the words "SQL" and "transaction" while promising the code contains
/// neither. A naive `source.contains("SQL")` guard would fail on the very
/// comment that documents the guarantee. `b4_comment_stripper_is_load_bearing`
/// below proves this stripper actually removes something on every run, so these
/// guards can never pass vacuously.
fn b4_code_only(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Count call-shaped occurrences of `name` (the identifier immediately followed
/// by an open paren), so a `use` import is never miscounted as a call site.
fn b4_call_count(source: &str, name: &str) -> usize {
    let mut count = 0;
    let mut rest = source;
    while let Some(at) = rest.find(name) {
        let after = &rest[at + name.len()..];
        if after.trim_start().starts_with('(') {
            count += 1;
        }
        rest = &rest[at + name.len()..];
    }
    count
}

/// Extract the paren-balanced body of `CONSTRAINT <constraint_name> CHECK (...)`
/// from a migration source, honoring nested parens (the real constraints this is
/// used against, e.g. `devices_revocation_shape_check`, nest a `(status = ...)`
/// group per disjunct). Panics with a descriptive message if the constraint or
/// its closing paren cannot be found, so a missing constraint fails loudly at
/// the call site rather than returning an empty/wrong slice.
fn b4_balanced_check_body<'a>(source: &'a str, constraint_name: &str) -> &'a str {
    let marker = format!("CONSTRAINT {constraint_name} CHECK (");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("{constraint_name} constraint not found"));
    let body_start = start + marker.len();
    let bytes = source.as_bytes();
    let mut depth = 1i32;
    let mut i = body_start;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return &source[body_start..i];
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!("{constraint_name}: CHECK body has no balanced closing paren");
}

/// The exact tokens a thin read handler must not contain, sealed as a named
/// constant rather than written inline, so the guard and its control run the
/// SAME predicate over the SAME list. A control that re-typed the list would
/// prove nothing about the guard.
const B4_FORBIDDEN_HANDLER_TOKENS: &[&str] = &[
    // SQL / transaction control
    "sqlx",
    "SELECT",
    "FOR UPDATE",
    "pool.begin",
    ".begin()",
    "SET TRANSACTION",
    "txid_current",
    ".rollback()",
    ".commit()",
    "Transaction<",
    // DTO projection + canonical serialization
    "serde_json::to_vec",
    "serde_json::from_slice",
    "GetDevicesOutput",
    "GetOwnDevicesOutput",
    "OwnDeviceView",
    "AddressableDevice",
    "DeviceCapability",
    "payload_bytes",
    // durable session request + direct repository reads
    "CreateDeviceInventorySessionRequest",
    "DeviceInventorySubject",
    "read_device_view",
    "list_own_device_views",
    "device_directory",
    // handler-driven retry + handler-owned session policy
    "MAX_ATTEMPTS",
    "SESSION_TTL",
    "Duration::minutes",
    // raw authority getters
    ".subject()",
    ".dpop_jkt()",
    ".trusted_instant()",
    ".auth_generation()",
    ".locked_",
];

/// The forbidden-token guard's predicate, factored out so the control below can
/// run the predicate ITSELF against a deliberately violating string instead of
/// re-running `contains` over a literal it just built. Returns the first
/// forbidden token present, or `None` for clean code.
fn b4_first_forbidden_token(code: &str) -> Option<&'static str> {
    B4_FORBIDDEN_HANDLER_TOKENS
        .iter()
        .copied()
        .find(|token| code.contains(token))
}

/// Assert that a clean-chat failure response is *structurally closed*: an object
/// whose only keys are `error`/`message` and whose values are bare, purely
/// alphabetic enum names.
///
/// This is the load-bearing half of the redaction proof, and it is deliberately
/// structural rather than needle-based. `errors.rs:88-115` renders exactly
/// `{"error": <Name>, "message": <Name>}` for a declared protocol code and
/// `{"error": "InternalServerError"}` for a code-less internal failure; nothing
/// else may appear. An alphabetic-only body excludes **every** banned sentinel
/// category at once, including the two that no useful needle can express:
/// an authentication generation IS a digit string, and a key digest is
/// base64url/hex — both are excluded by "no non-alphabetic character", whereas
/// `!body.contains("1")` would be noise. A DID carries `:`, a device UUID and a
/// JKT carry digits and `-`/`_`, and a token, proof, or replay identifier
/// carries `.`/`-`.
fn b4_assert_failure_body_is_closed(label: &str, body: &Value) {
    let object = body
        .as_object()
        .unwrap_or_else(|| panic!("{label}: failure body must be a JSON object; got {body}"));
    assert!(
        !object.is_empty(),
        "{label}: an empty failure body makes the closure check vacuous"
    );
    for (key, value) in object {
        assert!(
            matches!(key.as_str(), "error" | "message"),
            "{label}: unexpected failure-body key {key:?}; the renderer emits only \
             `error`/`message` (body {body})"
        );
        let text = value
            .as_str()
            .unwrap_or_else(|| panic!("{label}: failure-body {key} must be a string; got {value}"));
        assert!(
            !text.is_empty(),
            "{label}: failure-body {key} is empty — the charset check would be vacuous"
        );
        assert!(
            text.chars()
                .all(|character| character.is_ascii_alphabetic()),
            "{label}: failure-body {key} = {text:?} carries a non-alphabetic character. A bare \
             enum name cannot, but every banned sentinel does: DID, device UUID, JKT, \
             authentication generation, key digest, token/proof, and replay identifier"
        );
    }
}

/// Read a string claim out of a compact JWS, so a redaction needle is taken from
/// the request that was ACTUALLY sent rather than assumed to be in it. Panics if
/// the claim is absent, which stops a silently-missing needle from turning a
/// sweep vacuous.
fn b4_jwt_claim(jwt: &str, claim: &str) -> String {
    let payload = jwt
        .split('.')
        .nth(1)
        .expect("compact JWS carries a payload segment");
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .expect("JWS payload is base64url");
    let claims: Value = serde_json::from_slice(&decoded).expect("JWS payload is JSON");
    claims[claim]
        .as_str()
        .unwrap_or_else(|| panic!("{claim} claim is absent from the request JWT"))
        .to_owned()
}

/// The same trusted-Nest verifier the router builds from the environment,
/// constructed directly so a cryptographic negative can be driven as a pure
/// function — no router, no pool, no admission, no database.
fn b4_trusted_verifier() -> chat_protocol::dpop::TrustedNestVerifier {
    ensure_verifier_env();
    let chat_instance =
        validation::CanonicalUuidV4::parse(CHAT_INSTANCE).expect("canonical chat instance");
    let base = TrustedExternalBase::parse(EXTERNAL_BASE, &std::collections::BTreeSet::new())
        .expect("trusted external base");
    chat_protocol::dpop::TrustedNestVerifier::new(
        ISSUER,
        AUDIENCE,
        chat_instance,
        NEST_KEY_ID,
        *nest_signing_key().verifying_key(),
        base,
    )
    .expect("trusted Nest verifier")
}

const B4_GET_DEVICES_SOURCE: &str = include_str!("../src/handlers/chat/get_devices.rs");
const B4_GET_OWN_DEVICES_SOURCE: &str = include_str!("../src/handlers/chat/get_own_devices.rs");
const B4_INVENTORY_SOURCE: &str = include_str!("../src/chat_protocol/repository/inventory.rs");
/// The CORE migration — the one that owns `chat.devices`. Deliberately named so
/// nobody reaches for the delivery migration (`…000002`) when asking a question
/// about the device table, which is precisely the scope error that produced a
/// false absence claim during authoring.
const B4_CORE_MIGRATION_SOURCE: &str =
    include_str!("../migrations/20260722000001_chat_protocol_core.sql");

/// The B-auth facade section of `inventory.rs`, isolated so guards over the new
/// read path cannot be satisfied — or broken — by the pre-existing inventory
/// SQL above it (which legitimately uses joined `FOR UPDATE OF`).
fn b4_facade_section() -> &'static str {
    let marker = "// B-auth: the two repository-owned existing-device READ facades.";
    let at = B4_INVENTORY_SOURCE
        .find(marker)
        .expect("B-auth facade section present in inventory.rs");
    &B4_INVENTORY_SOURCE[at..]
}

/// The read handlers must expose no raw admission, receipt, or requester detail
/// — in source, and in what actually crosses the wire.
///
/// This is the only nonignored test of the six, so it is the one that runs in
/// the no-database gate. It carries its own positive controls: each guard is
/// paired with an assertion that the guard's machinery can still detect the
/// thing it is looking for, so a silently-broken predicate fails loudly instead
/// of passing vacuously.
#[tokio::test]
async fn existing_device_read_handlers_expose_no_raw_admission_or_receipt_details() {
    // -- CONTROL 0: the comment stripper must actually remove something. -------
    // If this ever stops holding, every "not in code" guard below becomes a
    // guard over prose and would pass no matter what the code did.
    for (name, source) in [
        ("get_devices.rs", B4_GET_DEVICES_SOURCE),
        ("get_own_devices.rs", B4_GET_OWN_DEVICES_SOURCE),
    ] {
        let code = b4_code_only(source);
        assert!(
            code.len() < source.len(),
            "{name}: comment stripper removed nothing — every source guard below would be vacuous"
        );
        // The exact words the doc comments use to PROMISE the absence. Their
        // presence in the raw text and absence from the stripped text is the
        // control that proves the stripper is doing the work.
        for promised in ["SQL", "transaction"] {
            assert!(
                source.contains(promised),
                "{name}: expected the doc comment to mention {promised:?}; guard control is stale"
            );
            assert!(
                !code.contains(promised),
                "{name}: {promised:?} survived comment stripping — it is in CODE, not prose"
            );
        }
    }

    // -- No handler SQL, transaction, retry loop, projection, or serializer. ---
    let get_devices = b4_code_only(B4_GET_DEVICES_SOURCE);
    let get_own_devices = b4_code_only(B4_GET_OWN_DEVICES_SOURCE);
    for (name, code) in [
        ("get_devices.rs", &get_devices),
        ("get_own_devices.rs", &get_own_devices),
    ] {
        assert_eq!(
            b4_first_forbidden_token(code),
            None,
            "{name} contains a token the facade owns"
        );
    }

    // -- CONTROL 1: the forbidden-token PREDICATE must be able to fire. --------
    // This runs `b4_first_forbidden_token` — the exact predicate the guard above
    // depends on — against a copy of the real handler source with one violation
    // injected, and against a clean string.
    //
    // The earlier form of this control asserted `control_code.contains("sqlx")`
    // over a string it had just built from the literal `sqlx`, so it could not
    // fail no matter what the predicate did; it validated `contains`, not the
    // guard. Both directions are asserted here because a predicate that always
    // returned `Some` would make the guard above fail loudly, but a predicate
    // that always returned `None` would make it pass silently — which is the
    // dangerous direction.
    let control_code = format!("{get_devices}\nlet _ = sqlx::query(\"SELECT 1\");\n");
    assert_eq!(
        b4_first_forbidden_token(&control_code),
        Some("sqlx"),
        "the forbidden-token predicate failed to detect an injected violation"
    );
    assert_eq!(
        b4_first_forbidden_token("fn handle() -> Response { context::json_ok(bytes) }"),
        None,
        "the forbidden-token predicate reported a violation in clean handler code"
    );

    // -- Exactly one admission, exactly one facade call, exactly one json_ok. --
    for (name, code, facade) in [
        (
            "get_devices.rs",
            &get_devices,
            "read_addressable_devices_for_admission",
        ),
        (
            "get_own_devices.rs",
            &get_own_devices,
            "create_own_device_snapshot_for_admission",
        ),
    ] {
        assert_eq!(
            b4_call_count(code, "context::admit_unsigned_read"),
            1,
            "{name} must admit exactly once"
        );
        assert_eq!(
            b4_call_count(code, facade),
            1,
            "{name} must transfer the admission into the facade exactly once"
        );
        assert_eq!(
            b4_call_count(code, "into_response_bytes"),
            1,
            "{name} must consume the facade result exactly once"
        );
        assert_eq!(
            b4_call_count(code, "context::json_ok"),
            1,
            "{name} must render exactly once"
        );
        // The retired raw bridge is gone, and `admit_unsigned_read` is not a
        // loophole for it: every occurrence of the old name must be part of the
        // new one.
        assert_eq!(
            code.matches("admit_unsigned").count(),
            code.matches("admit_unsigned_read").count(),
            "{name} still references the retired raw `admit_unsigned` bridge"
        );
    }

    // -- CONTROL 2: the call counter must distinguish a call from an import. ---
    assert_eq!(
        b4_call_count("use foo::bar;\nbar(1);\nbar(2);", "bar"),
        2,
        "call counter must count calls, not the `use` import"
    );
    assert_eq!(
        b4_call_count("use foo::bar;", "bar"),
        0,
        "call counter must not count a bare import as a call"
    );

    // -- The facade's ordered locks and sole constructor site. -----------------
    let facade = b4_code_only(b4_facade_section());
    assert_eq!(
        b4_call_count(&facade, "from_repository_lock"),
        1,
        "exactly one production `from_repository_lock` callsite, and it is here"
    );
    assert_eq!(
        b4_call_count(&facade, "consume_verify_locked_row"),
        1,
        "exactly one consuming verification"
    );
    // Device-then-key barriers: two SEPARATE single-table statements, never a
    // joined `FOR UPDATE OF`, and ISSUED in that order.
    //
    // THIS MEASURES ISSUANCE, NOT DECLARATION — and that is a correction.
    // The previous form took `facade.find("LOCK_READ_REQUESTER_DEVICE_SQL")`,
    // which returns the FIRST occurrence: the `const` at `inventory.rs:2956`,
    // not the `sqlx::query_as` at `:3050`. It therefore compared the order in
    // which two constants are typed. Swapping the two real lock statements left
    // it green; relocating the two `const` blocks failed it with zero
    // behavioural change — falsifiable only by the wrong mutation. The offsets
    // below are the `query_as` CALL sites, taken inside
    // `lock_and_verify_read_requester`, which is the only place either constant
    // is executed.
    let lock_fn = facade
        .find("async fn lock_and_verify_read_requester")
        .expect("lock/verify function");
    let device_lock = lock_fn
        + facade[lock_fn..]
            .find("sqlx::query_as(LOCK_READ_REQUESTER_DEVICE_SQL)")
            .expect("the device lock is ISSUED inside lock_and_verify_read_requester");
    let key_lock = lock_fn
        + facade[lock_fn..]
            .find("sqlx::query_as(LOCK_READ_REQUESTER_DEVICE_KEY_SQL)")
            .expect("the key lock is ISSUED inside lock_and_verify_read_requester");
    assert!(
        device_lock < key_lock,
        "the device lock must be ISSUED before the key lock"
    );
    // Each constant is issued exactly once, so the two offsets above are the
    // whole issuance order rather than the first of several.
    for issuance in [
        "sqlx::query_as(LOCK_READ_REQUESTER_DEVICE_SQL)",
        "sqlx::query_as(LOCK_READ_REQUESTER_DEVICE_KEY_SQL)",
    ] {
        assert_eq!(
            facade.matches(issuance).count(),
            1,
            "the requester lock {issuance} must be issued exactly once in the facade"
        );
    }
    for (label, marker) in [
        ("device", "const LOCK_READ_REQUESTER_DEVICE_SQL"),
        ("key", "const LOCK_READ_REQUESTER_DEVICE_KEY_SQL"),
    ] {
        let at = facade.find(marker).expect("lock statement constant");
        let end = facade[at..].find("\"#;").expect("lock statement end") + at;
        let statement = &facade[at..end];
        assert!(
            statement.contains("FOR UPDATE"),
            "{label} lock must actually lock"
        );
        assert!(
            !statement.contains("FOR UPDATE OF"),
            "{label} lock must not be a joined `FOR UPDATE OF` — that is not proof of order"
        );
        assert!(
            !statement.contains("JOIN"),
            "{label} lock must be single-table"
        );
    }
    // Constructor-without-verifier denial, positionally: the constructor call
    // is reached only after both ISSUED locks, and its result is consumed by
    // the verifier rather than used directly.
    let constructor = facade[lock_fn..]
        .find("from_repository_lock")
        .expect("constructor call")
        + lock_fn;
    let verifier = facade[lock_fn..]
        .find("consume_verify_locked_row")
        .expect("verifier call")
        + lock_fn;
    assert!(
        key_lock < constructor && constructor < verifier,
        "order must be device lock -> key lock -> constructor -> verifier"
    );

    // -- Why the nonpositive-generation branch is unreachable from a real row. -
    //
    // The constructor and the verifier both reject a nonpositive
    // `auth_generation`. Neither branch can be driven from a durable
    // `chat.devices` row, because the schema declares a floor of 1. That fact is
    // asserted HERE, in the nonignored gate, for two reasons:
    //
    //   1. it is the stated reason the database half asserts schema rejection
    //      instead of a drift case, so the reason must be checked, not trusted;
    //   2. this exact fact was got WRONG during authoring — an absence was
    //      claimed after looking only at the delivery migration
    //      (`…000002`), which carries three other `auth_generation >= 1`
    //      constraints and not this one. If the floor is ever dropped, the
    //      branch becomes reachable and this assertion fires.
    assert!(
        B4_CORE_MIGRATION_SOURCE.contains("CONSTRAINT devices_auth_generation_check"),
        "chat.devices must declare an auth_generation constraint"
    );
    let floor_at = B4_CORE_MIGRATION_SOURCE
        .find("CONSTRAINT devices_auth_generation_check")
        .expect("devices auth_generation constraint");
    let floor_end = B4_CORE_MIGRATION_SOURCE[floor_at..]
        .find('\n')
        .expect("constraint line end")
        + floor_at;
    let floor = &B4_CORE_MIGRATION_SOURCE[floor_at..floor_end];
    assert!(
        floor.contains("auth_generation >= 1"),
        "chat.devices must floor auth_generation at 1; found: {floor}"
    );
    // CONTROL: the needle must be specific enough to be about chat.devices and
    // not satisfied by a same-named check on another table. The delivery
    // migration carries three other `auth_generation >= 1` constraints; none of
    // them is named `devices_auth_generation_check`.
    assert_eq!(
        B4_CORE_MIGRATION_SOURCE
            .matches("CONSTRAINT devices_auth_generation_check")
            .count(),
        1,
        "exactly one chat.devices auth_generation constraint"
    );
    // The facade passes the LOCKED ROW's own generation to the constructor, so
    // the constructor's positivity check governs the value the database actually
    // holds rather than anything the admission remembered.
    let constructor_args = &facade[constructor..verifier];
    assert!(
        constructor_args.contains("device.auth_generation"),
        "the constructor must receive the locked row's own auth_generation"
    );

    // -- Why the Tier-2 revoked-device fixture's bare `UPDATE` does not trip
    //    `devices_revocation_shape_check` despite never setting `revocation_id`. -
    //
    // `get_devices_revocation_jkt_generation_and_key_drift_fail_before_read`
    // (Tier 2, ignored, case 1) revokes a device with
    // `UPDATE chat.devices SET status = 'revoked', revoked_at = now() ...` and
    // never touches `revocation_id`. That LOOKS like the same mistake the
    // auth_generation guard above exists to catch: `chat.devices` declares
    //
    //     CONSTRAINT devices_revocation_shape_check CHECK (
    //         (status = 'active' AND revoked_at IS NULL AND revocation_id IS NULL)
    //         OR (status = 'revoked' AND revoked_at IS NOT NULL
    //             AND chat.is_uuid_v4(revocation_id))
    //     )
    //
    // and the fixture leaves a `status = 'revoked'` row with `revocation_id`
    // still NULL. It is nonetheless NOT a violation: PostgreSQL only rejects a
    // row when a CHECK expression evaluates to FALSE — an UNKNOWN (NULL) result
    // satisfies the constraint. `chat.is_uuid_v4` is declared STRICT, so
    // `is_uuid_v4(NULL)` is NULL, making `revoked_at IS NOT NULL AND
    // chat.is_uuid_v4(revocation_id)` collapse to `TRUE AND NULL = NULL` for
    // this row, and `FALSE OR NULL = NULL` overall — not FALSE, so the write
    // succeeds. This holds ONLY because (a) the constraint gates
    // `revocation_id` through `is_uuid_v4` alone, with no separate
    // `revocation_id IS NOT NULL` conjunct, and (b) `is_uuid_v4` stays STRICT.
    // Both facts are pinned here, in the nonignored gate, rather than trusted:
    // if either changes, the fixture's `.expect("revoke device")` starts
    // failing for real, and case 1 must switch to writing a canonical v4
    // `revocation_id` (the way `cas_registration_revoke` in
    // `src/chat_protocol/repository/transition.rs` does for a real revocation)
    // instead of relying on this NULL-pass.
    assert_eq!(
        B4_CORE_MIGRATION_SOURCE
            .matches("CONSTRAINT devices_revocation_shape_check")
            .count(),
        1,
        "exactly one chat.devices revocation-shape constraint"
    );
    let shape_body =
        b4_balanced_check_body(B4_CORE_MIGRATION_SOURCE, "devices_revocation_shape_check");
    assert!(
        shape_body.contains("status = 'revoked'") && shape_body.contains("revoked_at IS NOT NULL"),
        "devices_revocation_shape_check must still require revoked_at on a revoked row; \
         found: {shape_body}"
    );
    assert!(
        shape_body.contains("chat.is_uuid_v4(revocation_id)"),
        "devices_revocation_shape_check must still gate revocation_id through is_uuid_v4; \
         found: {shape_body}"
    );
    // CONTROL: the shape must not have been tightened to an explicit
    // `revocation_id IS NOT NULL` conjunct — that would turn the STRICT
    // NULL-pass above into a real FALSE and break the Tier-2 fixture's write.
    assert!(
        !shape_body.contains("revocation_id IS NOT NULL"),
        "devices_revocation_shape_check now explicitly requires revocation_id IS NOT NULL — \
         the case-1 direct-UPDATE fixture that omits revocation_id will now be rejected by \
         the database; it must be updated to set a canonical v4 revocation_id"
    );
    let uuid_v4_fn_at = B4_CORE_MIGRATION_SOURCE
        .find("CREATE FUNCTION chat.is_uuid_v4")
        .expect("chat.is_uuid_v4 function definition present");
    let uuid_v4_fn_end = B4_CORE_MIGRATION_SOURCE[uuid_v4_fn_at..]
        .find("$$;")
        .expect("chat.is_uuid_v4 function body end")
        + uuid_v4_fn_at;
    let uuid_v4_fn = &B4_CORE_MIGRATION_SOURCE[uuid_v4_fn_at..uuid_v4_fn_end];
    assert!(
        uuid_v4_fn.contains("STRICT"),
        "chat.is_uuid_v4 must stay STRICT for the NULL-pass derivation above to hold; \
         found: {uuid_v4_fn}"
    );
    // CONTROL: the balanced-paren extractor must stop at the constraint's own
    // closing paren (not an earlier or later one) when the body itself
    // contains nested parens, exactly like the real constraint's two
    // `(status = ...)` disjunct groups.
    let control_source =
        "CONSTRAINT x_check CHECK ((a AND (b OR c)) OR (d AND e)) ,\nCONSTRAINT y_check CHECK (f)";
    assert_eq!(
        b4_balanced_check_body(control_source, "x_check"),
        "(a AND (b OR c)) OR (d AND e)",
        "balanced-paren extractor must match nested parens correctly"
    );

    // -- No protected query before verification. ------------------------------
    //
    // ONE GUARD PER PROTECTED QUERY, STRICTLY ALTERNATING — and that is a
    // correction. The previous form asked, per protected query, only that SOME
    // `guard_protected_query(&lock)` appear somewhere earlier than it and later
    // than the last mint (`rfind`). That ACCEPTS A DELETED GUARD: remove the
    // per-row directory-enrichment guard at `inventory.rs:3250` and the audience
    // read's guard at `:3242` still satisfies `guard > mint`, so the assertion
    // stays green while the same-transaction check is gone from the loop body.
    //
    // The section comment claims each protected query is IMMEDIATELY preceded by
    // a guard. The falsifiable form of that claim is a 1:1 interleaving: collect
    // every guard call and every protected query by position and require the
    // merged sequence to alternate guard, protected, guard, protected, …
    // Deleting any single guard turns the sequence into … guard, protected,
    // protected … and fails here.
    const B4_GUARD_CALL: &str = "guard_protected_query(&lock)";
    const B4_PROTECTED_QUERIES: [&str; 4] = [
        "get_devices(transaction",
        "read_device_view(",
        "list_own_device_views(",
        "create_device_inventory_session(",
    ];
    let mut events: Vec<(usize, &'static str)> = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = facade[from..].find(B4_GUARD_CALL) {
        let at = from + rel;
        events.push((at, "guard"));
        from = at + B4_GUARD_CALL.len();
    }
    let guards = events.len();
    assert!(
        guards > 0,
        "the same-transaction guard is never called in the facade"
    );
    for protected in B4_PROTECTED_QUERIES {
        let mut from = 0usize;
        let mut seen = 0usize;
        while let Some(rel) = facade[from..].find(protected) {
            let at = from + rel;
            events.push((at, "protected"));
            seen += 1;
            from = at + protected.len();
        }
        assert!(
            seen > 0,
            "protected query {protected:?} not found in facade"
        );
    }
    assert_eq!(
        guards,
        events.len() - guards,
        "the facade must call the same-transaction guard exactly once per \
         protected query: {guards} guard(s) for {} protected quer(ies)",
        events.len() - guards
    );
    events.sort_by_key(|(at, _)| *at);
    for (index, (at, kind)) in events.iter().enumerate() {
        let expected = if index % 2 == 0 { "guard" } else { "protected" };
        assert_eq!(
            *kind, expected,
            "the facade's guard/protected-query sequence must strictly \
             alternate; position {at} is a {kind} where a {expected} was \
             required (a deleted guard, or a second query under one guard)"
        );
    }

    // -- The 503 + `Retry-After: 1` ceiling survives, with no invented code. ---
    //
    // THIS IS A SOURCE-TEXT STRUCTURAL CLAIM AND NOTHING MORE. It is stated that
    // way on purpose: there is no executed assertion anywhere in this file that
    // observes an HTTP 503 or a `Retry-After` header, because the facade's
    // `RetryCeiling` outcome is unreachable in production — the only constructor
    // of the retryable `InventoryRepositoryError::SnapshotConflict` has no
    // production callsite, so `create_own_device_snapshot_for_admission` never
    // produces `Retry` and never exhausts its three attempts. That condition is
    // inherited, not introduced here, and this lane is ruled out of building a
    // fault-injection seam to force it. What CAN be checked without inventing a
    // path is that the ceiling arm is wired to the exact transport surface, so
    // that when the path does become reachable it is already correct. Anything
    // stronger in this file would be `.contains` dressed up as behaviour.
    let ceiling_at = get_own_devices
        .find("fn retry_ceiling_response()")
        .expect("the ceiling renderer must still exist");
    let ceiling = &get_own_devices[ceiling_at..];
    assert!(
        ceiling.contains("StatusCode::SERVICE_UNAVAILABLE"),
        "the ceiling renderer must return HTTP 503"
    );
    assert!(
        ceiling.contains("RETRY_AFTER"),
        "the ceiling renderer must set a `Retry-After` header"
    );
    assert!(
        ceiling.contains("RETRY_AFTER_SECONDS"),
        "the ceiling renderer must use the pinned `Retry-After` value, not a literal"
    );
    assert!(
        B4_GET_OWN_DEVICES_SOURCE.contains("const RETRY_AFTER_SECONDS: &str = \"1\";"),
        "the ceiling must advertise exactly `Retry-After: 1`"
    );
    // ...and the ceiling is reached from the facade's `RetryCeiling` arm rather
    // than from an arbitrary error, so the 503 cannot be emitted for a drift or
    // storage failure. Positional, not documentary.
    let ceiling_arm = get_own_devices
        .find("ExistingDeviceReadFacadeError::RetryCeiling) => Ok(retry_ceiling_response())")
        .expect("the 503 must be reached only from the facade's RetryCeiling outcome");
    assert!(
        ceiling_arm < ceiling_at,
        "the ceiling arm must dispatch to the renderer defined below it"
    );
    // CONTROL: the slice really is a slice. If `find` ever returned 0 (whole
    // file) the three assertions above would silently widen to the entire
    // handler, where `SERVICE_UNAVAILABLE` also appears in the doc comment.
    assert!(
        ceiling.len() < get_own_devices.len(),
        "the ceiling slice did not narrow the corpus — the assertions above would be file-wide"
    );

    // -- The sanitized facade vocabulary cannot carry data. -------------------
    // Every variant of the facade error is a unit variant, so no `Debug` render,
    // log line, or panic message can print requester material.
    let error_at = b4_facade_section()
        .find("pub(crate) enum ExistingDeviceReadFacadeError")
        .expect("facade error enum");
    let error_end = b4_facade_section()[error_at..]
        .find("\n}")
        .expect("facade error enum end")
        + error_at;
    let variants: Vec<&str> = b4_facade_section()[error_at..error_end]
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty() && !line.starts_with("//") && !line.starts_with("pub(crate) enum")
        })
        .collect();
    assert!(!variants.is_empty(), "facade error enum has no variants");
    for variant in &variants {
        assert!(
            !variant.contains('(') && !variant.contains('{'),
            "facade error variant {variant:?} carries data — `Debug` could leak it"
        );
    }

    // -- RUNTIME REDACTION: nothing authority-bearing crosses the wire. --------
    // A fully-formed Nest token and DPoP proof carrying this device's real DID,
    // device UUID, JKT, and key id, rejected at DPoP binding — which happens
    // BEFORE any database access, so this needs no database and no admission
    // ever succeeds. The exact request material must appear nowhere in the
    // response bytes.
    let scenario = EnrollScenario::build(1);
    let nsid = "blue.catbird.chat.getOwnDevices";
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
    // A proof under a FOREIGN key: it parses completely, so the whole token and
    // proof are in memory, and it then fails the confirmation binding.
    let foreign = random_p256();
    let foreign_jwk = public_jwk(&foreign);
    let proof = dpop_proof(
        &foreign,
        &foreign_jwk,
        "GET",
        &htu_for(nsid),
        &token,
        now,
        uuid::Uuid::new_v4().as_bytes(),
    );
    let request = Request::builder()
        .method("GET")
        .uri(xrpc(nsid))
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", proof.clone())
        .body(Body::empty())
        .expect("redaction probe request");
    let (status, bytes) = send_raw(stateless_router(true), request).await;
    assert_ne!(status, StatusCode::OK, "the redaction probe must fail");
    let body = String::from_utf8_lossy(&bytes).into_owned();

    // CONTROL 3: the response must be non-empty and recognisable, otherwise
    // "contains no secret" would be trivially true of an empty body.
    assert!(
        !body.is_empty(),
        "empty response makes the redaction check vacuous"
    );
    assert!(
        body.contains("InvalidDPoP"),
        "expected the declared DPoP failure; got {body}"
    );

    // The replay identifiers are read back OUT of the exact bytes that were
    // sent, so "this needle was in the request" is measured rather than assumed
    // — the failure mode the DID/device/JKT needles above cannot have, because
    // they come from the scenario, but a `jti` minted inside `dpop_proof` could.
    let token_replay_id = b4_jwt_claim(&token, "jti");
    let proof_replay_id = b4_jwt_claim(&proof, "jti");
    let device_id = scenario.device_id.to_string();
    for (label, secret) in [
        ("requester DID", scenario.did.as_str()),
        ("device UUID", device_id.as_str()),
        ("DPoP JKT", scenario.proof_jkt.as_str()),
        ("key id", scenario.body_key_id.as_str()),
        ("Nest token", token.as_str()),
        ("DPoP proof", proof.as_str()),
        ("token replay id", token_replay_id.as_str()),
        ("proof replay id", proof_replay_id.as_str()),
    ] {
        assert!(
            !secret.is_empty(),
            "{label} probe value is empty — the redaction check would be vacuous"
        );
        assert!(
            !body.contains(secret),
            "{label} leaked into the HTTP response body: {body}"
        );
    }
    // CONTROL 4: the leak detector must be able to fire. Prove `contains` finds
    // a string that genuinely IS in this very body.
    assert!(
        body.contains("error"),
        "leak detector failed its own positive control on this response"
    );
    // Structural closure. The eight needles above are the high-entropy
    // categories; the remaining two sentinels the authority names — the
    // authentication GENERATION and the KEY DIGEST — cannot be expressed as
    // useful needles here (a generation is a one- or two-digit string, and this
    // probe never carries a digest because it is refused before any row is
    // read). They are discharged instead by proving the whole body is closed and
    // purely alphabetic, which admits no digit and no encoded material at all.
    let redaction_value: Value = serde_json::from_slice(&bytes).expect("failure body is JSON");
    b4_assert_failure_body_is_closed("wire redaction probe", &redaction_value);

    // -- CONTROL 5: the closure helper must REJECT sentinel-bearing bodies. ----
    // Without this, every closed-body assertion in this file is inert — and
    // four of them live in database-marked tests that cannot run in this gate,
    // so this is the only place their predicate can be exercised at all. Each
    // synthetic body is exactly the shape the renderer would have if it leaked,
    // one sentinel category at a time, including the two categories no needle
    // sweep can usefully express.
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    for (category, leaked) in [
        ("requester DID", "did:plc:abcdefghijklmnopqrstuvwx"),
        ("device UUID", "3b241101-e2bb-4255-8caf-4136c566a962"),
        ("authentication generation", "7"),
        ("key digest", "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"),
    ] {
        let leaked_body = serde_json::json!({ "error": "Invariant", "message": leaked });
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            b4_assert_failure_body_is_closed("closure control", &leaked_body)
        }));
        assert!(
            caught.is_err(),
            "the closure helper accepted a failure body leaking a {category}"
        );
    }
    // ...and it must ACCEPT the exact two shapes `errors.rs` emits, or the
    // assertions above would be failing for the wrong reason.
    for shape in [
        serde_json::json!({ "error": "InvalidDPoP", "message": "InvalidDPoP" }),
        serde_json::json!({ "error": "InternalServerError" }),
    ] {
        b4_assert_failure_body_is_closed("closure control", &shape);
    }
    std::panic::set_hook(previous_hook);

    // -- CRYPTOGRAPHIC WRONG-METHOD, refused before the repository. -----------
    //
    // The amendment's phase manifest requires
    // `get_own_devices_endpoint_or_method_substitution_fails_before_sql` to open
    // with a "cryptographic wrong-method subcase [that] stops before
    // repository". That test is database-marked and runs in Task B6; this is the
    // same shape with no database at all, so the property is EXECUTED in the
    // no-database gate too — and, unlike a status code on its own, it shows that
    // the METHOD is what caused the refusal.
    //
    // Leg 1 is pure. `dpop::verify_ordinary_request_auth` is the exact function
    // the admission spine calls (`context.rs:143`) BEFORE its first repository
    // call (`context.rs:152`). Two proofs identical in every byte except `htm`
    // are pushed through it against the endpoint-owned canonical method. Wrong
    // `htm` must fail, right `htm` must succeed; without the second leg the
    // first proves nothing about the method. No pool, no admission, no database.
    //
    // Leg 2 is the same wrong-`htm` proof at the real router, over real HTTP.
    //
    // WHAT MAKES "BEFORE THE REPOSITORY" A MEASUREMENT HERE — corrected, because
    // the reason previously given was false. It was: "a failure raised inside
    // `authorize_unsigned_request` or the facade is rendered code-less, so
    // `InvalidDPoP` can only have come from the pre-repository verifier." That
    // is wrong. `handlers/chat/context.rs:353` maps
    // `AuthRepositoryError::ReplayDetected | DpopBindingMismatch` to
    // `ChatProtocolErrorCode::InvalidDPoP`, and both are produced by
    // `authorize_unsigned_request` AFTER it has called `pool.begin()` and
    // INSERTed a `chat.dpop_replays` row (`repository/auth.rs:1108-1117`).
    // `InvalidDPoP` is therefore a post-repository code too, and on a router
    // with a live pool it discriminates nothing.
    //
    // The discriminator that actually holds is the ROUTER, and it is asserted
    // rather than assumed. `stateless_router` carries a lazily-connected pool
    // aimed at a database that does not exist, so ANY request that reaches
    // `authorize_unsigned_request` fails at `pool.begin()` with
    // `AuthRepositoryError::Database`, which `context.rs:349` turns into
    // `ChatFailure::storage` — HTTP 500 `{"error":"InternalServerError"}`, with
    // no protocol code at all. `401 InvalidDPoP` on THIS router therefore
    // excludes the repository path. The positive control below sends the
    // byte-identical fixture with the CORRECT `htm` through the same router and
    // asserts exactly that 500, so the discriminator is executed, not argued.
    let method_probe = EnrollScenario::build(1);
    let method_now = chrono::Utc::now().timestamp();
    let method_token = sign_jwt(
        jwt_header(),
        ordinary_claims(
            &method_probe.did,
            method_probe.device_id,
            &method_probe.proof_jkt,
            nsid,
            method_now,
        ),
        &nest_signing_key(),
    );
    let method_jti = uuid::Uuid::new_v4();
    let wrong_htm_proof = dpop_proof(
        &method_probe.proof_signing,
        &method_probe.proof_jwk,
        "POST",
        &htu_for(nsid),
        &method_token,
        method_now,
        method_jti.as_bytes(),
    );
    let right_htm_proof = dpop_proof(
        &method_probe.proof_signing,
        &method_probe.proof_jwk,
        "GET",
        &htu_for(nsid),
        &method_token,
        method_now,
        method_jti.as_bytes(),
    );

    let trust = b4_trusted_verifier();
    let read_endpoint = ValidatedChatNsid::parse(nsid).expect("read endpoint nsid");
    let canonical_get = validation::CanonicalHttpMethod::parse("GET").expect("canonical GET");
    let verification_instant =
        validation::TrustedRequestInstant::capture().expect("trusted request instant");
    let authorization = format!("DPoP {method_token}");
    assert!(
        chat_protocol::dpop::verify_ordinary_request_auth(
            &trust,
            &authorization,
            &wrong_htm_proof,
            &read_endpoint,
            &canonical_get,
            &verification_instant,
        )
        .is_err(),
        "a DPoP proof bound to POST must not verify against the GET-only getOwnDevices profile"
    );
    assert!(
        chat_protocol::dpop::verify_ordinary_request_auth(
            &trust,
            &authorization,
            &right_htm_proof,
            &read_endpoint,
            &canonical_get,
            &verification_instant,
        )
        .is_ok(),
        "the identical fixture with the correct htm must verify — otherwise the negative above \
         is not evidence about the METHOD"
    );

    let wrong_method_request = Request::builder()
        .method("GET")
        .uri(xrpc(nsid))
        .header("authorization", authorization.as_str())
        .header("dpop", wrong_htm_proof)
        .body(Body::empty())
        .expect("wrong-method probe request");
    let (method_status, method_body) = send(stateless_router(true), wrong_method_request).await;
    assert_eq!(
        method_status,
        StatusCode::UNAUTHORIZED,
        "the cryptographic wrong-method probe must be refused: {method_body}"
    );
    assert_eq!(
        method_body["error"], "InvalidDPoP",
        "a wrong-method proof must be refused with the endpoint's declared DPoP \
         code: {method_body}"
    );
    b4_assert_failure_body_is_closed("wrong-method probe", &method_body);

    // POSITIVE CONTROL FOR THE DISCRIMINATOR. The identical fixture with the
    // CORRECT `htm` passes `verify_ordinary_request_auth` and goes on to
    // `authorize_unsigned_request`, whose `pool.begin()` cannot reach the
    // nonexistent database this router names. It must therefore come back 500
    // `InternalServerError` — a rendering the wrong-method probe above did NOT
    // produce. Without this leg, "401 InvalidDPoP means it stopped before the
    // repository" would be an argument about `context.rs`; with it, the two
    // outcomes are observed to differ on the same router with the same
    // credentials, differing only in `htm`.
    let reached_repository_request = Request::builder()
        .method("GET")
        .uri(xrpc(nsid))
        .header("authorization", authorization.as_str())
        .header("dpop", right_htm_proof)
        .body(Body::empty())
        .expect("repository-reaching control request");
    let (reached_status, reached_body) =
        send(stateless_router(true), reached_repository_request).await;
    assert_eq!(
        reached_status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a request that PASSES the pre-repository verifier must reach the \
         unreachable pool and render 500, or `401 InvalidDPoP` above \
         discriminates nothing: {reached_body}"
    );
    assert_eq!(
        reached_body["error"], "InternalServerError",
        "a repository-reaching failure carries no protocol code: {reached_body}"
    );
    b4_assert_failure_body_is_closed("repository-reaching control", &reached_body);
}

// -----------------------------------------------------------------------------
// Durable-state helpers for the ignored database cases below.
// -----------------------------------------------------------------------------

/// Every committed own-device inventory session for a principal, newest last:
/// `(session_id, complete, item_count, created_at, expires_at)`.
async fn b4_device_sessions(
    pool: &DbPool,
    did: &str,
) -> Vec<(
    uuid::Uuid,
    bool,
    Option<i64>,
    chrono::DateTime<chrono::Utc>,
    chrono::DateTime<chrono::Utc>,
)> {
    sqlx::query_as(
        "SELECT device_inventory_session_id, complete, item_count, created_at, expires_at \
           FROM chat.device_inventory_sessions WHERE user_did = $1 ORDER BY created_at",
    )
    .bind(did)
    .fetch_all(pool)
    .await
    .expect("read device inventory sessions")
}

/// Every committed `chat.dpop_replays` row, whatever transaction wrote it.
///
/// THIS IS THE ROLLBACK-IMMUNE BEFORE-SQL INSTRUMENT, and it is the reason it
/// exists rather than a status code. `commit_semantic_decision`
/// (`repository/auth.rs:3953-3967`) rolls the authority transaction back ONLY on
/// `AuthRepositoryError::Database`; every semantic refusal COMMITS. So a request
/// that reached `authorize_unsigned_request` leaves rows here even though its
/// transaction produced no authority, while a request refused by
/// `dpop::verify_ordinary_request_auth` — which runs before `pool.begin()` and
/// takes no pool — leaves none. Row ABSENCE elsewhere (a durable session, an
/// inventory row) cannot make that distinction, because a rolled-back write is
/// also absent; this counter can, because it is never rolled back.
async fn b4_consumed_replay_rows(pool: &DbPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM chat.dpop_replays")
        .fetch_one(pool)
        .await
        .expect("count committed dpop replay rows")
}

/// The retained per-item payload bytes for a session, in ordinal order.
async fn b4_device_items(pool: &DbPool, session: uuid::Uuid) -> Vec<(i64, uuid::Uuid, Vec<u8>)> {
    sqlx::query_as(
        "SELECT ordinal, subject_device_id, payload_bytes \
           FROM chat.device_inventory_items WHERE device_inventory_session_id = $1 ORDER BY ordinal",
    )
    .bind(session)
    .fetch_all(pool)
    .await
    .expect("read device inventory items")
}

/// An unsigned query request whose Nest-token `lxm`, DPoP `htu`, DPoP `htm`,
/// HTTP method, and request path can each be set independently, so
/// endpoint/method substitution can be exercised honestly rather than simulated.
///
/// `proof_htm` is deliberately separate from `method`. Binding them together —
/// as an earlier version did — makes a "method substitution" case send a real
/// POST at a `get`-only route, which axum answers with a bodiless 405 before the
/// handler, the admission spine, or any cryptography runs. That case would then
/// assert nothing about the endpoint's method binding: it would assert that
/// axum routes by method.
fn b4_substituted_request(
    scenario: &EnrollScenario,
    token_lxm: &str,
    proof_htu_nsid: &str,
    proof_htm: &str,
    method: &str,
    path_nsid: &str,
) -> Request<Body> {
    let now = chrono::Utc::now().timestamp();
    let token = sign_jwt(
        jwt_header(),
        ordinary_claims(
            &scenario.did,
            scenario.device_id,
            &scenario.proof_jkt,
            token_lxm,
            now,
        ),
        &nest_signing_key(),
    );
    let proof = dpop_proof(
        &scenario.proof_signing,
        &scenario.proof_jwk,
        proof_htm,
        &htu_for(proof_htu_nsid),
        &token,
        now,
        uuid::Uuid::new_v4().as_bytes(),
    );
    Request::builder()
        .method(method)
        .uri(xrpc(path_nsid))
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", proof)
        .body(Body::empty())
        .expect("substituted request")
}

/// `getDevices` projects only the endpoint's exact `addressableDevice` wire
/// fields, and refuses a requester with no registered device.
///
/// RENAMED, AND THE NAME IS THE FIX. This was
/// `get_devices_consumes_opaque_admission_before_directory_read`, which claims
/// an ORDERING — admission consumed before the directory read — that nothing in
/// the body measures. Both legs here are end-state observations of the HTTP
/// response: the exact key set of a successful projection, and the refusal of an
/// unregistered requester. Neither can distinguish "the admission was spent
/// first" from "the directory was read first and the admission checked after".
/// The ordering claim is a source-position claim, and it is measured where it
/// can be: the guard/protected-query alternation over the facade section in
/// `existing_device_read_handlers_expose_no_raw_admission_or_receipt_details`.
///
/// NOTE FOR THE COORDINATOR: this rename changes a sealed test NAME. The
/// database gate command that names it with `--exact` must be updated. The
/// per-file test COUNT is unchanged (21) and no name was added or removed.
#[tokio::test]
#[ignore = "requires the dedicated clean-chat gate database"]
async fn get_devices_projects_exact_addressable_fields_and_refuses_an_unregistered_requester() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let scenario = enroll_fresh_device(&pool, 4).await;

    let suffix = format!("?userDids={}", scenario.did);
    let (status, body) = send(
        router_with(pool.clone(), true),
        query_request(&scenario, "blue.catbird.chat.getDevices", &suffix),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "getDevices failed: {body}");

    let devices = body["devices"].as_array().expect("devices array");
    let device = devices
        .iter()
        .find(|d| d["deviceId"] == scenario.device_id.to_string())
        .expect("enrolled device present");

    // The facade builds ONLY the exact generated `addressableDevice` fields. The
    // directory row it read carries generation, JKT, signing key, status, and
    // timestamps; none of them may be projected here.
    let object = device.as_object().expect("addressableDevice object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "availablePackageCount",
            "capability",
            "deviceId",
            "keyId",
            "userDid"
        ],
        "addressableDevice carries exactly the endpoint's wire fields"
    );
    // NO PER-FIELD ABSENCE LOOP HERE — DELIBERATELY. Seven
    // `assert!(object.get(leaked).is_none())` calls stood below this exact-key
    // equality, for `authGeneration`, `dpopJkt`, `status`, `createdAt`,
    // `updatedAt`, `reservedPackageCount`, and `signaturePublicKey`. None of the
    // seven names is in the five-key set the assertion above pins, so whenever
    // the loop ran all seven were `None` by construction; any input that could
    // have populated one of them fails the stricter equality first and the loop
    // never executes. Seven assertions with no reachable failing state. The
    // exact-key equality is strictly stronger — it also catches a leaked field
    // nobody thought to list.
    // No separately distinguished requester value or marker at the output level.
    let output = body.as_object().expect("output object");
    assert_eq!(
        output.keys().count(),
        1,
        "getDevices output carries only `devices`"
    );

    // A principal with no registered device cannot spend an admission at all, so
    // the audience read is never reached. `EnrollScenario::build` mints a fresh
    // identity WITHOUT enrolling it.
    let stranger = EnrollScenario::build(1);
    let (status, body) = send(
        router_with(pool.clone(), true),
        query_request(&stranger, "blue.catbird.chat.getDevices", &suffix),
    )
    .await;
    // The EXACT declared refusal, not merely "not 200". `lock_device_and_key`
    // (`repository/auth.rs:3728`) finds no `chat.devices` row and returns
    // `DeviceNotRegistered`, which `context.rs:354` maps to the code
    // `getDevices` declares (`error.rs:409-415`) and `errors.rs:120-124` renders
    // at 401. A bare `assert_ne!(status, OK)` was satisfied by a routing 404, a
    // storage 500, or any other failure, so it did not measure this refusal.
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unregistered requester must be refused at the authority lock: {body}"
    );
    assert_eq!(
        body["error"], "DeviceNotRegistered",
        "an unregistered requester must be refused with the declared code: {body}"
    );
    // No separate `body.get("devices").is_none()` — the closure assertion above
    // already pins the key set to a subset of {`error`, `message`}, which is
    // strictly stronger; a `devices` key fails there first.
    b4_assert_failure_body_is_closed("unregistered requester", &body);
}

/// Revocation, JKT drift, generation drift, and key drift are terminal at the
/// requester lock — never a retryable snapshot conflict — and none of them may
/// emit a directory payload.
#[tokio::test]
#[ignore = "requires the dedicated clean-chat gate database"]
async fn get_devices_revocation_jkt_generation_and_key_drift_fail_before_read() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;

    // Each case gets its own enrolled device so the drifts cannot mask one
    // another, and each asserts the SAME two properties: the read fails, and no
    // directory payload is produced.
    /// `expected_error` is the EXACT declared code the case must be refused
    /// with, derived from the production path rather than left as "not 200".
    ///
    /// WHY AN EXACT CODE, AND WHERE THE REFUSAL ACTUALLY HAPPENS — both are
    /// corrections. The previous form asserted only `assert_ne!(status, OK)`
    /// plus the absence of a `devices` key, which every failure in the system
    /// satisfies: a routing 404, a storage 500, an unrelated 400. It could not
    /// fail on anything except success.
    ///
    /// And the previous comment claimed this failure "is produced INSIDE
    /// `lock_and_verify_read_requester`, after a real admission, against a real
    /// locked row". That is false for every case below. `admit_unsigned_read`
    /// calls `auth::authorize_unsigned_request` (`context.rs:152`) BEFORE the
    /// facade, and `lock_device_and_key` (`repository/auth.rs:3711-3757`)
    /// already rejects a non-`active` device (`DeviceRevoked`), a revoked key
    /// (`DeviceKeyRevoked`), and — via `lock_existing_authority:3705` — a
    /// registered JKT that no longer matches the proof (`DpopBindingMismatch`).
    /// All three drift shapes exercised here are therefore terminal at the
    /// AUTHORITY lock, one layer above the read facade, and the read facade's
    /// locked row is never reached. That is still "fail before read", which is
    /// what the test is named for — but the redaction sweep below runs over an
    /// authority-layer refusal, not over a drifted locked row, and the earlier
    /// claim that this is "the only place the requester's committed generation
    /// and key digest are in scope" does not hold. The remaining gap is recorded
    /// rather than papered over: the facade's own drift branch
    /// (`consume_verify_locked_row` refusing a generation that moved while the
    /// JKT did not) is reachable in principle — `lock_existing_authority` checks
    /// the JKT but never the generation — and no case here drives it.
    async fn assert_drift_is_terminal(
        pool: &DbPool,
        scenario: &EnrollScenario,
        case: &str,
        expected_error: &str,
    ) {
        let suffix = format!("?userDids={}", scenario.did);
        let (request, token, proof) =
            query_request_parts(scenario, "blue.catbird.chat.getDevices", &suffix);
        let (status, body) = send(router_with(pool.clone(), true), request).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{case}: drift must be refused at the authority lock with the \
             endpoint's declared authentication status: {body}"
        );
        assert_eq!(
            body["error"], expected_error,
            "{case}: drift must be refused with exactly {expected_error} — a \
             different code means the refusal moved to a different layer: {body}"
        );

        // REDACTION ON THE AUTHORITY PATH, against a real registered device and
        // a real committed row. Unlike the wire probe in the nonignored gate,
        // which is refused by the cryptographic verifier before any row is read,
        // this refusal is produced after `lock_device_and_key` has SELECTed the
        // requester's `chat.devices` and `chat.device_keys` rows, so the row's
        // status, JKT, generation, key id, and signing key are all in scope in
        // the failing frame.
        //
        // Closure first: the response must be a bare, purely alphabetic
        // `error`/`message` object. That single structural fact excludes the
        // generation (digits) and the key digest (base64url) that no useful
        // needle expresses, and it would fail on any row value whatsoever.
        b4_assert_failure_body_is_closed(case, &body);
        // Then the high-entropy request material, including the two replay
        // identifiers read back out of the bytes that were actually sent.
        let rendered = body.to_string();
        let device_id = scenario.device_id.to_string();
        let token_replay_id = b4_jwt_claim(&token, "jti");
        let proof_replay_id = b4_jwt_claim(&proof, "jti");
        for (label, secret) in [
            ("requester DID", scenario.did.as_str()),
            ("device UUID", device_id.as_str()),
            ("DPoP JKT", scenario.proof_jkt.as_str()),
            ("key id", scenario.body_key_id.as_str()),
            ("Nest token", token.as_str()),
            ("DPoP proof", proof.as_str()),
            ("token replay id", token_replay_id.as_str()),
            ("proof replay id", proof_replay_id.as_str()),
        ] {
            assert!(
                !secret.is_empty(),
                "{case}: {label} needle is empty — the read-path sweep would be vacuous"
            );
            assert!(
                !rendered.contains(secret),
                "{case}: {label} leaked into the read-path failure response: {rendered}"
            );
        }
    }

    // 1. Inactive / revoked device.
    //
    //    This deliberately never sets `revocation_id`. `chat.devices` declares
    //    `devices_revocation_shape_check`, which on its face looks like it
    //    should reject a `status = 'revoked'` row with a NULL `revocation_id`
    //    — but it does not: `chat.is_uuid_v4` is STRICT, so
    //    `is_uuid_v4(NULL)` is NULL, the constraint's second disjunct
    //    collapses to NULL rather than FALSE, and PostgreSQL only rejects a
    //    CHECK that evaluates to FALSE (NULL satisfies it). The nonignored
    //    `existing_device_read_handlers_expose_no_raw_admission_or_receipt_details`
    //    gate pins both facts this depends on (the constraint's exact shape
    //    and `is_uuid_v4`'s STRICT-ness); if either ever changes, that gate
    //    fails first, before this `.expect("revoke device")` starts rejecting
    //    for real.
    let revoked = enroll_fresh_device(&pool, 1).await;
    sqlx::query(
        "UPDATE chat.devices SET status = 'revoked', revoked_at = now() \
          WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&revoked.did)
    .bind(revoked.device_id)
    .execute(&pool)
    .await
    .expect("revoke device");
    // `lock_device_and_key:3729` — `device.status != "active"` is
    // `DeviceRevoked`, declared by `getDevices` and rendered at 401.
    assert_drift_is_terminal(&pool, &revoked, "revoked device", "DeviceRevoked").await;

    // 2. JKT drift, produced by a LEGAL rebind: the registered JKT and the
    //    authentication generation both move, and the stale credentials the
    //    scenario still holds no longer match the locked row.
    let rebound = enroll_fresh_device(&pool, 1).await;
    let new_proof = random_p256();
    let (rebind_status, rebind_body) = send(
        router_with(pool.clone(), true),
        rebind_request(&rebound, &new_proof),
    )
    .await;
    assert_eq!(
        rebind_status,
        StatusCode::OK,
        "legal rebind failed: {rebind_body}"
    );
    // `lock_existing_authority:3705` — the registered `dpop_jkt` no longer
    // matches the stale proof, which is `DpopBindingMismatch` and maps to the
    // declared `InvalidDPoP` (`context.rs:353`). The generation moved too, but
    // the JKT check is reached first and the authority layer never inspects the
    // generation at all, so this case cannot reach the facade's generation
    // branch.
    assert_drift_is_terminal(&pool, &rebound, "drifted JKT and generation", "InvalidDPoP").await;

    // 3. Non-positive authentication generation is UNREACHABLE from a durable
    //    row, and this case proves that rather than pretending otherwise.
    //
    //    An earlier draft of this test drove the branch by forcing
    //    `auth_generation = 0` with a direct `UPDATE`. That was wrong:
    //    `migrations/20260722000001_chat_protocol_core.sql:324` declares
    //
    //        CONSTRAINT devices_auth_generation_check
    //            CHECK (chat.is_safe_integer(auth_generation) AND auth_generation >= 1)
    //
    //    so PostgreSQL rejects the write and the case would have failed on a
    //    constraint violation without ever exercising the read path.
    //
    //    The honest assertion is the one below: the floor is ENFORCED by the
    //    live database, which is exactly why the nonpositive-generation branch
    //    in the constructor and the verifier cannot be reached from a real row.
    //    Generation DRIFT, which IS reachable, is covered by case 2 above.
    let floored = enroll_fresh_device(&pool, 1).await;
    let before: i64 = sqlx::query_scalar(
        "SELECT auth_generation FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&floored.did)
    .bind(floored.device_id)
    .fetch_one(&pool)
    .await
    .expect("read the enrolled generation");
    assert!(
        before >= 1,
        "the enrolled generation must satisfy the floor"
    );

    let rejected = sqlx::query(
        "UPDATE chat.devices SET auth_generation = 0 WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&floored.did)
    .bind(floored.device_id)
    .execute(&pool)
    .await;
    assert!(
        rejected.is_err(),
        "devices_auth_generation_check must reject a nonpositive generation; \
         if this ever passes, the schema floor is gone and the nonpositive branch \
         has become reachable from a durable row — this test must then grow a real case"
    );

    // The rejected write changed nothing, so the device is still healthy and a
    // read still succeeds. That is the control: it proves this case's failure
    // mode is the SCHEMA refusing the write, not a broken fixture.
    let after: i64 = sqlx::query_scalar(
        "SELECT auth_generation FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&floored.did)
    .bind(floored.device_id)
    .fetch_one(&pool)
    .await
    .expect("re-read the generation");
    assert_eq!(
        after, before,
        "the rejected UPDATE must have changed nothing"
    );
    let suffix = format!("?userDids={}", floored.did);
    let (status, body) = send(
        router_with(pool.clone(), true),
        query_request(&floored, "blue.catbird.chat.getDevices", &suffix),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an undamaged device must still read successfully: {body}"
    );

    // 4. Revoked device key. Device status and key revocation are SEPARATE
    //    checks, so this case leaves the device row active on purpose.
    let keyless = enroll_fresh_device(&pool, 1).await;
    sqlx::query(
        "UPDATE chat.device_keys SET revoked_at = now() WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&keyless.did)
    .bind(keyless.device_id)
    .execute(&pool)
    .await
    .expect("revoke device key");
    let still_active: String = sqlx::query_scalar(
        "SELECT status FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&keyless.did)
    .bind(keyless.device_id)
    .fetch_one(&pool)
    .await
    .expect("device status");
    assert_eq!(
        still_active, "active",
        "this case must isolate KEY revocation from device status"
    );
    // `lock_device_and_key:3746` — a revoked key row is `DeviceKeyRevoked`,
    // which `context.rs:356` also maps to the declared `DeviceRevoked`. The
    // device row stays active, so this case isolates the key check.
    assert_drift_is_terminal(&pool, &keyless, "revoked device key", "DeviceRevoked").await;
}

/// `getOwnDevices` materializes from the locked admission alone: the handler
/// supplies no coordinates, the retained payload bytes are byte-identical to the
/// returned items, the session is committed before any byte is emitted, and the
/// committed expiry is the one the response advertises.
#[tokio::test]
#[ignore = "requires the dedicated clean-chat gate database"]
async fn get_own_devices_materializes_from_locked_admission_without_handler_coordinates() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let scenario = enroll_fresh_device(&pool, 3).await;

    let (status, body) = send(
        router_with(pool.clone(), true),
        query_request(&scenario, "blue.catbird.chat.getOwnDevices", ""),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "getOwnDevices failed: {body}");

    // Single page, generated shape.
    assert_eq!(body["hasMore"], false);
    assert!(body.get("nextPageCursor").is_none_or(Value::is_null));
    let items = body["items"].as_array().expect("items array").clone();
    assert!(!items.is_empty(), "own-device set must not be empty");

    // EXACTLY ONE final session, and it is committed with matching evidence —
    // the response could not have been emitted before that commit.
    let sessions = b4_device_sessions(&pool, &scenario.did).await;
    assert_eq!(sessions.len(), 1, "exactly one own-device session");
    let (session_id, complete, item_count, created_at, expires_at) = sessions[0];
    assert!(complete, "the session must be committed complete");
    assert_eq!(
        item_count,
        Some(items.len() as i64),
        "committed item_count must match the returned page"
    );

    // The committed expiry is the one advertised, and it is the repository-owned
    // bounded window (ten minutes) rather than anything a caller supplied.
    let advertised = body["snapshotExpiresAt"]
        .as_str()
        .expect("snapshotExpiresAt string");
    let advertised = chrono::DateTime::parse_from_rfc3339(advertised)
        .expect("parse snapshotExpiresAt")
        .with_timezone(&chrono::Utc);
    assert_eq!(
        advertised, expires_at,
        "the response expiry must be the COMMITTED expiry"
    );
    assert_eq!(
        expires_at - created_at,
        chrono::Duration::minutes(10),
        "the repository-owned bounded window"
    );
    assert_eq!(
        created_at.timestamp_subsec_nanos(),
        0,
        "the durable row rejects sub-second precision"
    );

    // CANONICAL RETAINED/RETURNED ITEM IDENTITY: each retained payload
    // deserializes to exactly the corresponding returned item, and
    // re-serializing that item reproduces the retained bytes byte for byte.
    let retained = b4_device_items(&pool, session_id).await;
    assert_eq!(
        retained.len(),
        items.len(),
        "one retained item per returned item"
    );
    for (index, (ordinal, subject_device_id, payload_bytes)) in retained.iter().enumerate() {
        assert_eq!(*ordinal, index as i64, "canonical ordinals are 0..n-1");
        let decoded: Value =
            serde_json::from_slice(payload_bytes).expect("retained payload is canonical JSON");
        assert_eq!(
            decoded, items[index],
            "retained payload must equal the returned item"
        );
        let reserialized = serde_json::to_vec(&items[index]).expect("re-serialize returned item");
        assert_eq!(
            &reserialized, payload_bytes,
            "re-serializing the returned item must reproduce the retained bytes"
        );
        assert_eq!(
            decoded["device"]["deviceId"],
            subject_device_id.to_string(),
            "each item describes its own subject device"
        );
    }

    // The legitimate directory-row fields REMAIN response data...
    let own = items
        .iter()
        .find(|item| item["device"]["deviceId"] == scenario.device_id.to_string())
        .expect("own device present");
    assert!(
        own["device"]["dpopJkt"].is_string(),
        "dpopJkt is a legitimate directory-row field"
    );
    assert!(
        own["device"]["authGeneration"].is_number(),
        "authGeneration is a legitimate directory-row field"
    );
    // ...but nothing marks WHICH row matched the hidden requester coordinate.
    let output = body.as_object().expect("output object");
    let mut output_keys: Vec<&str> = output.keys().map(String::as_str).collect();
    output_keys.sort_unstable();
    assert_eq!(
        output_keys,
        vec!["hasMore", "items", "snapshotExpiresAt"],
        "no requester field, marker, or cursor at the output level"
    );
    for item in &items {
        let keys: Vec<&str> = item
            .as_object()
            .expect("ownDeviceView object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, vec!["device"], "no per-item requester marker");
    }
}

/// The facade owns the pool and its own transaction boundary: a failed
/// materialization rolls back with NO residue, and the next call proceeds on a
/// fresh transaction and a fresh attempt to exactly one committed session.
#[tokio::test]
#[ignore = "requires the dedicated clean-chat gate database"]
async fn get_own_devices_retry_uses_fresh_transaction_and_attempt() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let scenario = enroll_fresh_device(&pool, 2).await;

    // Force every attempt inside the facade to abort at the durable item write.
    // The facade opens a FRESH transaction per attempt, so a rolled-back attempt
    // must leave neither a session row nor an item row behind.
    install_task7_failure_trigger(
        &pool,
        "chat.device_inventory_items",
        "b4_fail_device_inventory_item",
        "b4_fail_device_inventory_item_trigger",
    )
    .await;
    let (status, body) = send(
        router_with(pool.clone(), true),
        query_request(&scenario, "blue.catbird.chat.getOwnDevices", ""),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "an aborted materialization must not succeed"
    );
    assert!(
        body.get("items").is_none(),
        "no response items may escape before commit"
    );
    remove_task7_failure_trigger(
        &pool,
        "chat.device_inventory_items",
        "b4_fail_device_inventory_item",
        "b4_fail_device_inventory_item_trigger",
    )
    .await;

    // FIRST-ATTEMPT ROLLBACK, NO RESIDUE.
    let after_failure = b4_device_sessions(&pool, &scenario.did).await;
    assert!(
        after_failure.is_empty(),
        "a rolled-back attempt left {} session row(s) behind",
        after_failure.len()
    );
    let orphan_items: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.device_inventory_items WHERE requester_did = $1",
    )
    .bind(&scenario.did)
    .fetch_one(&pool)
    .await
    .expect("count orphan items");
    assert_eq!(orphan_items, 0, "a rolled-back attempt left item residue");

    // FRESH TRANSACTION AND ATTEMPT: the very next call succeeds and commits
    // exactly one session. The prior failure retained no authority.
    let (status, body) = send(
        router_with(pool.clone(), true),
        query_request(&scenario, "blue.catbird.chat.getOwnDevices", ""),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a fresh call after a failed one must succeed: {body}"
    );
    let after_success = b4_device_sessions(&pool, &scenario.did).await;
    assert_eq!(
        after_success.len(),
        1,
        "exactly ONE committed session survives the failed attempt plus the successful call"
    );
    assert!(after_success[0].1, "the surviving session is complete");

    // Each successful call is its own transaction and its own session; the
    // earlier committed session is untouched by the later one.
    let (status, _) = send(
        router_with(pool.clone(), true),
        query_request(&scenario, "blue.catbird.chat.getOwnDevices", ""),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let two = b4_device_sessions(&pool, &scenario.did).await;
    assert_eq!(two.len(), 2, "a second call mints its own session");
    assert_eq!(
        two[0].0, after_success[0].0,
        "the first committed session is not rewritten by the second call"
    );
    assert!(
        two.iter().all(|session| session.1),
        "both sessions complete"
    );
}

/// Substituting the endpoint or the method fails before any SQL runs: no
/// device-inventory session is created by a substituted request.
#[tokio::test]
#[ignore = "requires the dedicated clean-chat gate database"]
async fn get_own_devices_endpoint_or_method_substitution_fails_before_sql() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let scenario = enroll_fresh_device(&pool, 2).await;
    let own = "blue.catbird.chat.getOwnDevices";
    let other = "blue.catbird.chat.getDevices";

    // WHAT THIS TEST PROVES, AND WHAT IT DOES NOT — stated exactly, because an
    // earlier version of this comment deferred a required case to the
    // entitlement suite, which does not carry it either. A deferral to a place
    // that does not implement the case is worse than an admitted gap: it reads
    // as covered.
    //
    // PROVEN HERE. Cases 1-3 substitute the ENDPOINT along each of its three
    // independent carriers (Nest-token `lxm`, DPoP `htu`, request path). Case 4
    // is the amendment's CRYPTOGRAPHIC WRONG-METHOD subcase: a real GET whose
    // DPoP proof is bound to POST, so it reaches the real handler and is refused
    // by `verify_ordinary_request_auth` (`context.rs:143`) before
    // `authorize_unsigned_request` (`context.rs:152`) issues any SQL. It is a
    // GET on purpose — sending an actual POST would be answered by axum's
    // method router with a bodiless 405 and would never reach the endpoint's
    // method binding at all.
    //
    // HOW "BEFORE SQL" IS MEASURED — corrected, because the previous instrument
    // was not a discriminator. It was: "each case asserts the DECLARED
    // `InvalidDPoP`; a refusal raised inside the repository or the facade is
    // rendered code-less, so `InvalidDPoP` can only have come from the
    // pre-repository cryptographic verifier." That premise is false.
    // `context.rs:353` maps `AuthRepositoryError::ReplayDetected |
    // DpopBindingMismatch` to `InvalidDPoP`, and `authorize_unsigned_request`
    // (`repository/auth.rs:1108-1117`) calls `pool.begin()` and INSERTs replay
    // rows before either can be produced. A 401 `InvalidDPoP` is therefore
    // produced by two distinguishable paths, one of which has already written to
    // the database, and the assertion cannot tell them apart. Concretely
    // undetected: move the `lxm`/`htu`/`htm` binding checks out of
    // `verify_ordinary_request_auth` and let the repository's
    // `DpopBindingMismatch` catch them instead — every assertion still passed
    // while every substituted request opened a transaction and committed rows.
    //
    // The instrument is now `chat.dpop_replays`, sampled around EACH
    // substituted request. It is committed unconditionally on every semantic
    // refusal and rolled back only on a `Database` fault, so it distinguishes
    // "never issued SQL" from "issued SQL and rolled back" — which row-absence
    // in `chat.device_inventory_sessions` structurally cannot. The unsubstituted
    // control at the end must MOVE that same counter, so a zero delta is a
    // measurement rather than a broken fixture. The declared `InvalidDPoP` is
    // still asserted, as what it actually is: the endpoint's wire vocabulary.
    //
    // NOT PROVEN HERE, AND NOT PROVABLE OVER HTTP. The facade's own closed
    // endpoint/budget binding — `into_get_devices_read_admission` and
    // `into_get_own_devices_read_admission` refusing an admission sealed for the
    // other endpoint. Each handler seals its admission with its OWN
    // `ChatEndpoint` and hands it to its OWN facade, so no HTTP request can
    // present a `getDevices` admission to the `getOwnDevices` budget; the
    // mismatch arm is unreachable through the router by construction. Reaching
    // it requires calling the conversions directly, which only the entitlement
    // suite's test-crate bridge can do. That leg is OPEN and reported as open,
    // not deferred.
    for (case, request) in [
        (
            "token lxm names the other read endpoint",
            b4_substituted_request(&scenario, other, own, "GET", "GET", own),
        ),
        (
            "proof htu names the other read endpoint",
            b4_substituted_request(&scenario, own, other, "GET", "GET", own),
        ),
        (
            "own-devices credentials replayed at the other endpoint",
            b4_substituted_request(&scenario, own, own, "GET", "GET", other),
        ),
        (
            "cryptographic wrong-method: the proof is bound to POST",
            b4_substituted_request(&scenario, own, own, "POST", "GET", own),
        ),
    ] {
        let replays_before = b4_consumed_replay_rows(&pool).await;
        let (status, body) = send(router_with(pool.clone(), true), request).await;
        // BEFORE SQL, MEASURED. `authorize_unsigned_request` commits its replay
        // set on every semantic outcome, so reaching it is visible here whether
        // or not its transaction rolled back. An unchanged count is the only
        // available proof that no SQL was issued at all.
        assert_eq!(
            b4_consumed_replay_rows(&pool).await,
            replays_before,
            "{case}: the substituted request committed replay rows, so it \
             reached `authorize_unsigned_request` and did NOT stop before SQL"
        );
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{case}: substitution must be refused: {body}"
        );
        assert_eq!(
            body["error"], "InvalidDPoP",
            "{case}: substitution must be refused with the endpoint's declared \
             DPoP code: {body}"
        );
        // Strictly stronger than a `body.get("items").is_none()` check, which
        // stood here and could not fail once the body was known closed: this
        // pins the key set to a subset of {`error`, `message`}.
        b4_assert_failure_body_is_closed(case, &body);
    }

    // Durable corroboration, from the other side: not one substituted request
    // created a session. This is NOT a before-SQL proof on its own — a session
    // written and rolled back is equally absent — but combined with the
    // unchanged replay counter above it pins both "no SQL issued" and "nothing
    // durable produced".
    let sessions = b4_device_sessions(&pool, &scenario.did).await;
    assert!(
        sessions.is_empty(),
        "a substituted request reached the durable session write ({} row(s))",
        sessions.len()
    );

    // POSITIVE CONTROL FOR BOTH INSTRUMENTS. The same scenario with NO
    // substitution must move the replay counter AND commit exactly one session,
    // so neither zero above can be the product of a dead fixture or a counter
    // that never moves.
    let replays_before_control = b4_consumed_replay_rows(&pool).await;
    let (status, body) = send(
        router_with(pool.clone(), true),
        query_request(&scenario, own, ""),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "unsubstituted control failed: {body}"
    );
    assert!(
        b4_consumed_replay_rows(&pool).await > replays_before_control,
        "the unsubstituted control committed no replay rows — the before-SQL \
         instrument above cannot move and proves nothing"
    );
    assert_eq!(
        b4_device_sessions(&pool, &scenario.did).await.len(),
        1,
        "the unsubstituted control must commit exactly one session"
    );
}
