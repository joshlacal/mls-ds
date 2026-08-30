//! Adversarial Challenger M4: Empirical Verification Suite for Cryptographic & Security Gates
//!
//! Verifies:
//! 1. DPoP token parsing and claim validation (unknown fields rejection, JKT mismatch, expired tokens, skew > 60s, corrupted signatures)
//! 2. Enrollment grant expiry formula `exp == min(iat + 120, auth_time + 300)` with edge cases and arithmetic overflow
//! 3. Rebind Ed25519 signature checks vs new DPoP JKTs
//! 4. 32 `blue.catbird.chat.*` endpoints cutover rejection (`CHAT_CUTOVER_ENABLED=false`)

mod common;

pub use catbird_server::{auth, crypto, federation, handlers, identity, sqlx_jacquard, util};

#[path = "common/chat_protocol_harness.rs"]
mod chat_protocol;

mod repository {
    pub(crate) use crate::chat_protocol::repository::*;
}

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex, Once},
};

use axum::{
    body::Body,
    extract::FromRef,
    http::{Request, StatusCode},
    Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use catbird_server::{
    blob_store::BlobStore,
    chat_protocol::error::ChatEndpoint,
    handlers::chat::{chat_router, ChatRuntime},
    realtime::SseState,
    storage::DbPool,
};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::ecdsa::{signature::Signer, Signature as P256Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower_util::ServiceExt;

use chat_protocol::dpop::{
    verify_enrollment_request_auth, verify_ordinary_request_auth, TrustedNestVerifier,
};
use chat_protocol::transcript::{
    decode_and_verify_enrollment_body, decode_canonical_signed_mutation,
};
use chat_protocol::validation::{
    self, ed25519_key_id, enrollment_grant_expiry, CanonicalHttpMethod, CanonicalTimestamp,
    CanonicalUuidV4, NumericDate, TrustedExternalBase, TrustedRequestInstant, ValidatedChatNsid,
};

const DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
const DEVICE_ID: &str = "3b241101-e2bb-4255-8caf-4136c566a962";
const CHAT_INSTANCE: &str = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
const TOKEN_JTI: &str = "8cb4f5d2-0d31-4b6f-a9c2-7e18f5403d61";
const AUTH_TXN: &str = "36e5e67b-98d1-4c47-96d5-44c09bc2b921";
const ISSUER: &str = "did:web:api.catbird.blue";
const AUDIENCE: &str = "did:web:chat.catbird.blue";

fn signing_key_p256(fill: u8) -> SigningKey {
    SigningKey::from_bytes((&[fill; 32]).into()).unwrap()
}

fn public_jwk(key: &SigningKey) -> Value {
    let point = key.verifying_key().to_encoded_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap())
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
        json!({"typ":"dpop+jwt","alg":"ES256","jwk":jwk}),
        json!({
            "htm": htm,
            "htu": htu,
            "ath": URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes())),
            "iat": iat,
            "jti": URL_SAFE_NO_PAD.encode(jti_bytes)
        }),
        key,
    )
}

fn sign_chat_body(body: Value, key: &Ed25519SigningKey) -> Vec<u8> {
    let mut wrapper = json!({
        "body": body,
        "signature": STANDARD.encode([0_u8; 64]),
    });
    let unsigned = serde_json::to_vec(&wrapper).unwrap();
    if let Ok(canonical) = decode_canonical_signed_mutation(&unsigned) {
        let signature = key.sign(canonical.transcript_bytes());
        wrapper["signature"] = json!(STANDARD.encode(signature.to_bytes()));
    }
    serde_json::to_vec(&wrapper).unwrap()
}

fn enrollment_body(_dpop_jkt: &str, signing_key: &Ed25519SigningKey, package_refs: &[u8]) -> Value {
    let key_id = ed25519_key_id(signing_key.verifying_key().as_bytes()).unwrap();
    let key_packages: Vec<_> = package_refs
        .iter()
        .map(|fill| {
            let bytes = [*fill; 8];
            json!({
                "framing": "mlsMessage",
                "contentType": "keyPackage",
                "bytes": STANDARD.encode(bytes),
                "sha256": STANDARD.encode(Sha256::digest(bytes)),
                "keyPackageRef": STANDARD.encode([*fill; 32]),
            })
        })
        .collect();
    json!({
        "$type": "blue.catbird.chat.defs#deviceEnrollmentBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-ENROLL\u{0}",
        "actorDid": DID,
        "deviceId": DEVICE_ID,
        "deviceName": "Alice's iPhone",
        "keyId": key_id.as_str(),
        "signaturePublicKey": STANDARD.encode(signing_key.verifying_key().as_bytes()),
        "expectedAuthGeneration": 0,
        "capability": {
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
        },
        "keyPackages": key_packages,
        "idempotencyKey": CHAT_INSTANCE,
        "signedAt": "2023-11-14T22:18:15.000Z"
    })
}

// ---------------------------------------------------------------------------
// Challenge 1: DPoP Token Parsing & Claim Validation
// ---------------------------------------------------------------------------

#[test]
fn challenge_1_unknown_fields_rejection_across_all_structures() {
    let nest_signing = signing_key_p256(7);
    let proof_signing = signing_key_p256(9);
    let allowlisted = BTreeSet::new();
    let origin = TrustedExternalBase::parse("https://chat.example.net", &allowlisted).unwrap();
    let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.getEntries").unwrap();
    let method = CanonicalHttpMethod::parse("GET").unwrap();
    let now = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse("2023-11-14T22:14:20.000Z").unwrap(),
    );
    let proof_jwk = public_jwk(&proof_signing);
    let proof_jkt = jwk_thumbprint(&proof_jwk);
    let trust = TrustedNestVerifier::new(
        ISSUER,
        AUDIENCE,
        CanonicalUuidV4::parse(CHAT_INSTANCE).unwrap(),
        "nest-key-1",
        nest_signing.verifying_key().to_owned(),
        origin.clone(),
    )
    .unwrap();

    let valid_token_header = json!({"alg":"ES256","typ":"JWT","kid":"nest-key-1"});
    let valid_claims = json!({
        "iss": ISSUER,
        "sub": DID,
        "aud": AUDIENCE,
        "lxm": endpoint.as_str(),
        "iat": 1_700_000_000_i64,
        "exp": 1_700_000_120_i64,
        "jti": TOKEN_JTI,
        "cnf": {"jkt": proof_jkt},
        "device_id": DEVICE_ID,
        "chat_instance": CHAT_INSTANCE
    });

    // 1.1: Unknown field in Token Header
    let mut bad_header = valid_token_header.clone();
    bad_header["unknown_header_field"] = json!("malicious_value");
    let bad_token = sign_jwt(bad_header, valid_claims.clone(), &nest_signing);
    let proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &origin.htu(&endpoint),
        &bad_token,
        1_700_000_060,
        &[1; 12],
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {bad_token}"),
            &proof,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject unknown field in Token Header"
    );

    // 1.2: Unknown field in ConfirmationClaim (cnf)
    let mut bad_claims = valid_claims.clone();
    bad_claims["cnf"] = json!({"jkt": proof_jkt, "unknown_cnf_field": "injected"});
    let bad_token = sign_jwt(valid_token_header.clone(), bad_claims, &nest_signing);
    let proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &origin.htu(&endpoint),
        &bad_token,
        1_700_000_060,
        &[1; 12],
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {bad_token}"),
            &proof,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject unknown field in cnf claim"
    );

    // 1.3: Unknown field in OrdinaryClaims
    let mut bad_claims = valid_claims.clone();
    bad_claims["injected_claim"] = json!(true);
    let bad_token = sign_jwt(valid_token_header.clone(), bad_claims, &nest_signing);
    let proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &origin.htu(&endpoint),
        &bad_token,
        1_700_000_060,
        &[1; 12],
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {bad_token}"),
            &proof,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject unknown field in OrdinaryClaims"
    );

    // 1.4: Unknown field in DPoP Header
    let valid_token = sign_jwt(
        valid_token_header.clone(),
        valid_claims.clone(),
        &nest_signing,
    );
    let bad_proof = sign_jwt(
        json!({"typ":"dpop+jwt","alg":"ES256","jwk":proof_jwk,"extra_dpop_header":"malicious"}),
        json!({
            "htm": "GET",
            "htu": origin.htu(&endpoint),
            "ath": URL_SAFE_NO_PAD.encode(Sha256::digest(valid_token.as_bytes())),
            "iat": 1_700_000_060_i64,
            "jti": URL_SAFE_NO_PAD.encode([1_u8; 12])
        }),
        &proof_signing,
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {valid_token}"),
            &bad_proof,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject unknown field in DPoP Header"
    );

    // 1.5: Unknown field in PublicP256Jwk
    let mut bad_jwk = proof_jwk.clone();
    bad_jwk["kid"] = json!("extra_metadata_forbidden");
    let bad_proof = sign_jwt(
        json!({"typ":"dpop+jwt","alg":"ES256","jwk":bad_jwk}),
        json!({
            "htm": "GET",
            "htu": origin.htu(&endpoint),
            "ath": URL_SAFE_NO_PAD.encode(Sha256::digest(valid_token.as_bytes())),
            "iat": 1_700_000_060_i64,
            "jti": URL_SAFE_NO_PAD.encode([1_u8; 12])
        }),
        &proof_signing,
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {valid_token}"),
            &bad_proof,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject unknown field in PublicP256Jwk"
    );

    // 1.6: Unknown field in DpopClaims
    let bad_proof = sign_jwt(
        json!({"typ":"dpop+jwt","alg":"ES256","jwk":proof_jwk}),
        json!({
            "htm": "GET",
            "htu": origin.htu(&endpoint),
            "ath": URL_SAFE_NO_PAD.encode(Sha256::digest(valid_token.as_bytes())),
            "iat": 1_700_000_060_i64,
            "jti": URL_SAFE_NO_PAD.encode([1_u8; 12]),
            "unknown_dpop_claim": "injected"
        }),
        &proof_signing,
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {valid_token}"),
            &bad_proof,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject unknown field in DpopClaims"
    );
}

#[test]
fn challenge_1_jkt_mismatch_and_key_substitution() {
    let nest_signing = signing_key_p256(7);
    let proof_signing_a = signing_key_p256(11);
    let proof_signing_b = signing_key_p256(13);
    let origin = TrustedExternalBase::parse("https://chat.example.net", &BTreeSet::new()).unwrap();
    let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.getEntries").unwrap();
    let method = CanonicalHttpMethod::parse("GET").unwrap();
    let now = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse("2023-11-14T22:14:20.000Z").unwrap(),
    );
    let jwk_a = public_jwk(&proof_signing_a);
    let jkt_a = jwk_thumbprint(&jwk_a);
    let jwk_b = public_jwk(&proof_signing_b);
    let jkt_b = jwk_thumbprint(&jwk_b);
    assert_ne!(jkt_a, jkt_b);

    let trust = TrustedNestVerifier::new(
        ISSUER,
        AUDIENCE,
        CanonicalUuidV4::parse(CHAT_INSTANCE).unwrap(),
        "nest-key-1",
        nest_signing.verifying_key().to_owned(),
        origin.clone(),
    )
    .unwrap();

    // Token signed with cnf.jkt = jkt_a
    let token = sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":"nest-key-1"}),
        json!({
            "iss": ISSUER,
            "sub": DID,
            "aud": AUDIENCE,
            "lxm": endpoint.as_str(),
            "iat": 1_700_000_000_i64,
            "exp": 1_700_000_120_i64,
            "jti": TOKEN_JTI,
            "cnf": {"jkt": jkt_a},
            "device_id": DEVICE_ID,
            "chat_instance": CHAT_INSTANCE
        }),
        &nest_signing,
    );

    // Proof presented signed by key B (jkt_b)
    let proof_b = dpop_proof(
        &proof_signing_b,
        &jwk_b,
        "GET",
        &origin.htu(&endpoint),
        &token,
        1_700_000_060,
        &[1; 12],
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {token}"),
            &proof_b,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject when DPoP proof key JKT != token cnf.jkt"
    );

    // Proof presented with jwk_a in header but signed by key B
    let fake_proof = sign_jwt(
        json!({"typ":"dpop+jwt","alg":"ES256","jwk":jwk_a}),
        json!({
            "htm": "GET",
            "htu": origin.htu(&endpoint),
            "ath": URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())),
            "iat": 1_700_000_060_i64,
            "jti": URL_SAFE_NO_PAD.encode([1_u8; 12])
        }),
        &proof_signing_b,
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {token}"),
            &fake_proof,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject DPoP proof when signature does not match embedded JWK"
    );
}

#[test]
fn challenge_1_token_expiration_lifetime_and_clock_skew() {
    let nest_signing = signing_key_p256(7);
    let proof_signing = signing_key_p256(9);
    let origin = TrustedExternalBase::parse("https://chat.example.net", &BTreeSet::new()).unwrap();
    let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.getEntries").unwrap();
    let method = CanonicalHttpMethod::parse("GET").unwrap();
    let now_ts = 1_700_000_050_i64; // now = 1700000050
    let now = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse("2023-11-14T22:14:10.000Z").unwrap(),
    );
    let proof_jwk = public_jwk(&proof_signing);
    let proof_jkt = jwk_thumbprint(&proof_jwk);
    let trust = TrustedNestVerifier::new(
        ISSUER,
        AUDIENCE,
        CanonicalUuidV4::parse(CHAT_INSTANCE).unwrap(),
        "nest-key-1",
        nest_signing.verifying_key().to_owned(),
        origin.clone(),
    )
    .unwrap();

    let make_token = |iat: i64, exp: i64| {
        sign_jwt(
            json!({"alg":"ES256","typ":"JWT","kid":"nest-key-1"}),
            json!({
                "iss": ISSUER,
                "sub": DID,
                "aud": AUDIENCE,
                "lxm": endpoint.as_str(),
                "iat": iat,
                "exp": exp,
                "jti": TOKEN_JTI,
                "cnf": {"jkt": proof_jkt},
                "device_id": DEVICE_ID,
                "chat_instance": CHAT_INSTANCE
            }),
            &nest_signing,
        )
    };

    // 1. Token not yet active (now < iat)
    let token = make_token(now_ts + 1, now_ts + 120);
    let proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &origin.htu(&endpoint),
        &token,
        now_ts,
        &[1; 12],
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {token}"),
            &proof,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject token with now < iat"
    );

    // 2. Token expired (now == exp boundary: now >= exp is invalid)
    let token = make_token(now_ts - 120, now_ts);
    let proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &origin.htu(&endpoint),
        &token,
        now_ts,
        &[1; 12],
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {token}"),
            &proof,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject token with now == exp (expired boundary)"
    );

    // 3. Token expired (now > exp)
    let token = make_token(now_ts - 125, now_ts - 5);
    let proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &origin.htu(&endpoint),
        &token,
        now_ts,
        &[1; 12],
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {token}"),
            &proof,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject token with now > exp"
    );

    // 4. Token lifetime > 120s (exp - iat = 121)
    let token = make_token(now_ts - 10, now_ts + 111);
    let proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &origin.htu(&endpoint),
        &token,
        now_ts,
        &[1; 12],
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {token}"),
            &proof,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject token with lifetime > 120s"
    );

    // 5. Reversed lifetime (exp < iat)
    let token = make_token(now_ts + 50, now_ts - 50);
    let proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &origin.htu(&endpoint),
        &token,
        now_ts,
        &[1; 12],
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {token}"),
            &proof,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject token with exp < iat"
    );

    // 6. Proof skew testing against now_ts (1700000050)
    let valid_token = make_token(now_ts - 10, now_ts + 110);
    // 6a. proof_iat == now + 60 (accepted boundary)
    let proof_p60 = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &origin.htu(&endpoint),
        &valid_token,
        now_ts + 60,
        &[2; 12],
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {valid_token}"),
            &proof_p60,
            &endpoint,
            &method,
            &now
        )
        .is_ok(),
        "Proof at now + 60s boundary must pass"
    );

    // 6b. proof_iat == now - 60 (accepted boundary)
    let proof_m60 = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &origin.htu(&endpoint),
        &valid_token,
        now_ts - 60,
        &[3; 12],
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {valid_token}"),
            &proof_m60,
            &endpoint,
            &method,
            &now
        )
        .is_ok(),
        "Proof at now - 60s boundary must pass"
    );

    // 6c. proof_iat == now + 61 (rejected skew)
    let proof_p61 = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &origin.htu(&endpoint),
        &valid_token,
        now_ts + 61,
        &[4; 12],
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {valid_token}"),
            &proof_p61,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Proof at now + 61s skew must be rejected"
    );

    // 6d. proof_iat == now - 61 (rejected skew)
    let proof_m61 = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &origin.htu(&endpoint),
        &valid_token,
        now_ts - 61,
        &[5; 12],
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {valid_token}"),
            &proof_m61,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Proof at now - 61s skew must be rejected"
    );
}

#[test]
fn challenge_1_signature_tampering_and_algorithm_confusion() {
    let nest_signing = signing_key_p256(7);
    let proof_signing = signing_key_p256(9);
    let origin = TrustedExternalBase::parse("https://chat.example.net", &BTreeSet::new()).unwrap();
    let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.getEntries").unwrap();
    let method = CanonicalHttpMethod::parse("GET").unwrap();
    let now = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse("2023-11-14T22:14:20.000Z").unwrap(),
    );
    let proof_jwk = public_jwk(&proof_signing);
    let proof_jkt = jwk_thumbprint(&proof_jwk);
    let trust = TrustedNestVerifier::new(
        ISSUER,
        AUDIENCE,
        CanonicalUuidV4::parse(CHAT_INSTANCE).unwrap(),
        "nest-key-1",
        nest_signing.verifying_key().to_owned(),
        origin.clone(),
    )
    .unwrap();

    let valid_token = sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":"nest-key-1"}),
        json!({
            "iss": ISSUER,
            "sub": DID,
            "aud": AUDIENCE,
            "lxm": endpoint.as_str(),
            "iat": 1_700_000_000_i64,
            "exp": 1_700_000_120_i64,
            "jti": TOKEN_JTI,
            "cnf": {"jkt": proof_jkt},
            "device_id": DEVICE_ID,
            "chat_instance": CHAT_INSTANCE
        }),
        &nest_signing,
    );
    let valid_proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &origin.htu(&endpoint),
        &valid_token,
        1_700_000_060,
        &[1; 12],
    );

    // 1. Corrupt token signature
    let (token_body, _) = valid_token.rsplit_once('.').unwrap();
    let corrupt_token_sig = format!("{token_body}.{}", URL_SAFE_NO_PAD.encode([0xAA_u8; 64]));
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {corrupt_token_sig}"),
            &valid_proof,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject corrupted token signature"
    );

    // 2. Corrupt proof signature
    let (proof_body, _) = valid_proof.rsplit_once('.').unwrap();
    let corrupt_proof_sig = format!("{proof_body}.{}", URL_SAFE_NO_PAD.encode([0xBB_u8; 64]));
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {valid_token}"),
            &corrupt_proof_sig,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject corrupted proof signature"
    );

    // 3. Algorithm confusion: alg = "none"
    let none_alg_token = format!("{}.{}.",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"alg":"none","typ":"JWT","kid":"nest-key-1"})).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"iss":ISSUER,"sub":DID,"aud":AUDIENCE,"lxm":endpoint.as_str(),"iat":1_700_000_000_i64,"exp":1_700_000_120_i64,"jti":TOKEN_JTI,"cnf":{"jkt":proof_jkt},"device_id":DEVICE_ID,"chat_instance":CHAT_INSTANCE})).unwrap())
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {none_alg_token}"),
            &valid_proof,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject alg: 'none'"
    );

    // 4. Algorithm confusion: typ = "dpop+jwt" on token, or typ = "JWT" on proof
    let bad_typ_token = sign_jwt(
        json!({"alg":"ES256","typ":"dpop+jwt","kid":"nest-key-1"}),
        json!({"iss":ISSUER,"sub":DID,"aud":AUDIENCE,"lxm":endpoint.as_str(),"iat":1_700_000_000_i64,"exp":1_700_000_120_i64,"jti":TOKEN_JTI,"cnf":{"jkt":proof_jkt},"device_id":DEVICE_ID,"chat_instance":CHAT_INSTANCE}),
        &nest_signing,
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {bad_typ_token}"),
            &valid_proof,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject token with typ != 'JWT'"
    );

    let bad_typ_proof = sign_jwt(
        json!({"typ":"JWT","alg":"ES256","jwk":proof_jwk}),
        json!({"htm":"GET","htu":origin.htu(&endpoint),"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(valid_token.as_bytes())),"iat":1_700_000_060_i64,"jti":URL_SAFE_NO_PAD.encode([1_u8; 12])}),
        &proof_signing,
    );
    assert!(
        verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {valid_token}"),
            &bad_typ_proof,
            &endpoint,
            &method,
            &now
        )
        .is_err(),
        "Must reject proof with typ != 'dpop+jwt'"
    );
}

// ---------------------------------------------------------------------------
// Challenge 2: Enrollment Grant Expiry Formula & Arithmetic Overflow
// ---------------------------------------------------------------------------

#[test]
fn challenge_2_enrollment_grant_expiry_formula_and_overflow_invariants() {
    // Formula: exp == min(iat + 120, auth_time + 300)
    // 1. iat + 120 is strictly smaller
    let iat = NumericDate::new(1_000).unwrap();
    let auth_time = NumericDate::new(1_000).unwrap();
    assert_eq!(
        enrollment_grant_expiry(iat, auth_time).unwrap().get(),
        1_120
    );

    // 2. auth_time + 300 is strictly smaller
    let iat = NumericDate::new(1_200).unwrap();
    let auth_time = NumericDate::new(1_000).unwrap();
    assert_eq!(
        enrollment_grant_expiry(iat, auth_time).unwrap().get(),
        1_300
    );

    // 3. Exact boundary equality (1180 + 120 == 1000 + 300 == 1300)
    let iat = NumericDate::new(1_180).unwrap();
    let auth_time = NumericDate::new(1_000).unwrap();
    assert_eq!(
        enrollment_grant_expiry(iat, auth_time).unwrap().get(),
        1_300
    );

    // 4. Arithmetic overflow safety: MAX_SAFE_INTEGER = 9_007_199_254_740_991
    let max_safe = NumericDate::new(validation::MAX_SAFE_INTEGER).unwrap();
    assert!(
        max_safe.checked_add(1).is_err(),
        "checked_add past MAX_SAFE_INTEGER must fail"
    );

    let overflow_iat = NumericDate::new(validation::MAX_SAFE_INTEGER - 50).unwrap();
    assert!(
        enrollment_grant_expiry(overflow_iat, auth_time).is_err(),
        "enrollment_grant_expiry with overflowing iat must error safely"
    );

    let overflow_auth = NumericDate::new(validation::MAX_SAFE_INTEGER - 150).unwrap();
    assert!(
        enrollment_grant_expiry(iat, overflow_auth).is_err(),
        "enrollment_grant_expiry with overflowing auth_time must error safely"
    );

    // 5. Negative numbers and i64::MAX reject at construction
    assert!(
        NumericDate::new(-1).is_err(),
        "Negative NumericDate must error"
    );
    assert!(NumericDate::new(i64::MIN).is_err(), "i64::MIN must error");
    assert!(
        NumericDate::new(i64::MAX).is_err(),
        "i64::MAX past MAX_SAFE_INTEGER must error"
    );
}

#[test]
fn challenge_2_enrollment_claims_auth_time_window_validation() {
    let nest_signing = signing_key_p256(17);
    let proof_signing = signing_key_p256(19);
    let body_signing = Ed25519SigningKey::from_bytes(&[23_u8; 32]);
    let origin = TrustedExternalBase::parse("https://chat.example.net", &BTreeSet::new()).unwrap();
    let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.enrollDevice").unwrap();
    let now_ts = 1_700_000_300_i64;
    let now = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse("2023-11-14T22:18:20.000Z").unwrap(),
    );
    let proof_jwk = public_jwk(&proof_signing);
    let proof_jkt = jwk_thumbprint(&proof_jwk);
    let enrollment_raw = sign_chat_body(
        enrollment_body(&proof_jkt, &body_signing, &[1_u8]),
        &body_signing,
    );
    let body = decode_and_verify_enrollment_body(&enrollment_raw).unwrap();
    let trust = TrustedNestVerifier::new(
        ISSUER,
        AUDIENCE,
        CanonicalUuidV4::parse(CHAT_INSTANCE).unwrap(),
        "nest-key-1",
        nest_signing.verifying_key().to_owned(),
        origin.clone(),
    )
    .unwrap();

    let make_enrollment_token = |iat: i64, exp: i64, auth_time: i64| {
        sign_jwt(
            json!({"alg":"ES256","typ":"JWT","kid":"nest-key-1"}),
            json!({
                "iss": ISSUER,
                "sub": DID,
                "aud": AUDIENCE,
                "lxm": endpoint.as_str(),
                "iat": iat,
                "exp": exp,
                "jti": TOKEN_JTI,
                "cnf": {"jkt": proof_jkt},
                "device_id": DEVICE_ID,
                "chat_instance": CHAT_INSTANCE,
                "key_id": body.key_id().as_str(),
                "signing_key_sha256": URL_SAFE_NO_PAD.encode(body.signing_key_sha256()),
                "enrollment_transcript_sha256": URL_SAFE_NO_PAD.encode(body.enrollment_transcript_sha256()),
                "auth_time": auth_time,
                "auth_txn": AUTH_TXN
            }),
            &nest_signing,
        )
    };

    // Case 1: Wrong formula in token (exp is computed incorrectly)
    // Correct exp for iat=1700000290, auth_time=1700000000 is min(1700000410, 1700000300) = 1700000300
    // Try token with exp = 1700000350
    let bad_exp_token = make_enrollment_token(1_700_000_290, 1_700_000_350, 1_700_000_000);
    let proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "POST",
        &origin.htu(&endpoint),
        &bad_exp_token,
        1_700_000_295,
        &[1; 12],
    );
    assert!(
        verify_enrollment_request_auth(
            &trust,
            &format!("DPoP {bad_exp_token}"),
            &proof,
            decode_and_verify_enrollment_body(&enrollment_raw).unwrap(),
            &now
        )
        .is_err(),
        "Must reject enrollment token where exp does not equal formula min(iat+120, auth_time+300)"
    );

    // Case 2: auth_time in future (auth_time > now_ts)
    let future_auth_token = make_enrollment_token(now_ts, now_ts + 120, now_ts + 10);
    let proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "POST",
        &origin.htu(&endpoint),
        &future_auth_token,
        now_ts,
        &[1; 12],
    );
    assert!(
        verify_enrollment_request_auth(
            &trust,
            &format!("DPoP {future_auth_token}"),
            &proof,
            decode_and_verify_enrollment_body(&enrollment_raw).unwrap(),
            &now
        )
        .is_err(),
        "Must reject enrollment where auth_time is in future"
    );

    // Case 3: auth_time outside 300s window (now_ts - auth_time = 301)
    let old_auth = now_ts - 301;
    let old_auth_exp = std::cmp::min(now_ts + 60, old_auth + 300);
    let old_auth_token = make_enrollment_token(now_ts - 10, old_auth_exp, old_auth);
    let proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "POST",
        &origin.htu(&endpoint),
        &old_auth_token,
        now_ts,
        &[1; 12],
    );
    assert!(
        verify_enrollment_request_auth(
            &trust,
            &format!("DPoP {old_auth_token}"),
            &proof,
            decode_and_verify_enrollment_body(&enrollment_raw).unwrap(),
            &now
        )
        .is_err(),
        "Must reject enrollment where now - auth_time > 300s"
    );
}

// ---------------------------------------------------------------------------
// Challenge 4: 32 `blue.catbird.chat.*` Endpoints Cutover Rejection
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct RouteTestState {
    pool: DbPool,
    runtime: Arc<ChatRuntime>,
    blob_store: BlobStore,
}

impl FromRef<RouteTestState> for DbPool {
    fn from_ref(state: &RouteTestState) -> Self {
        state.pool.clone()
    }
}

impl FromRef<RouteTestState> for Arc<ChatRuntime> {
    fn from_ref(state: &RouteTestState) -> Self {
        state.runtime.clone()
    }
}

impl FromRef<RouteTestState> for BlobStore {
    fn from_ref(state: &RouteTestState) -> Self {
        state.blob_store.clone()
    }
}

fn test_runtime(cutover_enabled: bool) -> Arc<ChatRuntime> {
    static INIT: Once = Once::new();
    static LOCK: Mutex<()> = Mutex::new(());
    INIT.call_once(|| {
        let key = SigningKey::from_bytes((&[0x5a_u8; 32]).into()).expect("signing key");
        std::env::set_var("CHAT_NEST_ISSUER", "did:web:api.catbird.blue");
        std::env::set_var("CHAT_NEST_AUDIENCE", "did:web:chat.catbird.blue");
        std::env::set_var("CHAT_NEST_KEY_ID", "route-inventory");
        std::env::set_var(
            "CHAT_NEST_VERIFYING_KEY",
            STANDARD.encode(key.verifying_key().to_encoded_point(false).as_bytes()),
        );
        std::env::set_var("CHAT_INSTANCE_ID", "018f3f6a-7b2c-4d91-8a5e-0f123456789a");
        std::env::set_var("CHAT_EXTERNAL_BASE", "https://chat.example.net");
        std::env::set_var("CHAT_CURSOR_KEY_ID", URL_SAFE_NO_PAD.encode([0x11_u8; 32]));
        std::env::set_var(
            "CHAT_CURSOR_SEALING_SECRET",
            URL_SAFE_NO_PAD.encode([0x22_u8; 32]),
        );
        std::env::set_var(
            "CHAT_SUBSCRIPTION_ENDPOINT",
            "wss://chat.example.net/xrpc/blue.catbird.chat.subscribeEvents",
        );
    });
    let _guard = LOCK.lock().expect("runtime env lock");
    if cutover_enabled {
        std::env::set_var("CHAT_CUTOVER_ENABLED", "true");
    } else {
        std::env::remove_var("CHAT_CUTOVER_ENABLED");
    }
    let rt =
        Arc::new(ChatRuntime::from_env(Arc::new(SseState::new(64))).expect("clean-chat runtime"));
    std::env::remove_var("CHAT_CUTOVER_ENABLED");
    rt
}

fn test_router(cutover_enabled: bool) -> Router {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://127.0.0.1/clean_chat_route_inventory")
        .expect("lazy pool");
    chat_router::<RouteTestState>().with_state(RouteTestState {
        pool,
        runtime: test_runtime(cutover_enabled),
        blob_store: BlobStore::for_route_tests(),
    })
}

fn is_get_endpoint(endpoint: ChatEndpoint) -> bool {
    matches!(
        endpoint,
        ChatEndpoint::GetBlob
            | ChatEndpoint::GetBlobUsage
            | ChatEndpoint::GetConversationState
            | ChatEndpoint::GetConversations
            | ChatEndpoint::GetDevices
            | ChatEndpoint::GetEntries
            | ChatEndpoint::GetLeafRecoveryInbox
            | ChatEndpoint::GetOwnDevices
            | ChatEndpoint::GetPendingWelcomes
            | ChatEndpoint::SubscribeEvents
    )
}

#[tokio::test]
async fn challenge_4_all_32_endpoints_cutover_disabled_rejection() {
    assert_eq!(
        ChatEndpoint::ALL.len(),
        32,
        "Must contain exactly 32 endpoints"
    );

    for endpoint in ChatEndpoint::ALL {
        let method = if is_get_endpoint(*endpoint) {
            "GET"
        } else {
            "POST"
        };
        let body = if *endpoint == ChatEndpoint::GetSubscriptionTicket {
            Body::from(
                r#"{"inventorySessionId":"00000000-0000-4000-8000-000000000001","eventCursor":"route-test"}"#,
            )
        } else {
            Body::empty()
        };
        let request = Request::builder()
            .method(method)
            .uri(format!("/xrpc/{}", endpoint.nsid()))
            .header("content-type", "application/json")
            .body(body)
            .expect("request");

        let response = test_router(false)
            .oneshot(request)
            .await
            .expect("route response");
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Endpoint {} must return 400 Bad Request when cutover is disabled",
            endpoint.nsid()
        );

        if *endpoint == ChatEndpoint::SubscribeEvents {
            continue;
        }

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        let body: Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|err| panic!("Non-JSON body from {}: {err}", endpoint.nsid()));

        let expected_error = "CutoverRequired";
        assert_eq!(
            body["error"],
            expected_error,
            "Endpoint {} must reject with error '{}' before database work",
            endpoint.nsid(),
            expected_error
        );
    }
}

#[tokio::test]
async fn challenge_4_all_32_endpoints_method_enforcement() {
    for endpoint in ChatEndpoint::ALL {
        // Send opposite method
        let wrong_method = if is_get_endpoint(*endpoint) {
            "POST"
        } else {
            "GET"
        };
        let request = Request::builder()
            .method(wrong_method)
            .uri(format!("/xrpc/{}", endpoint.nsid()))
            .body(Body::empty())
            .expect("request");

        let response = test_router(false)
            .oneshot(request)
            .await
            .expect("route response");
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "Endpoint {} must return 405 Method Not Allowed when accessed with wrong method {}",
            endpoint.nsid(),
            wrong_method
        );
    }
}
