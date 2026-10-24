//! Verify the federation harness's actual signer against production authentication.
//!
//! This covers signature, issuer and audience verification. It does not claim
//! enrollment-handler, replay-store, database, or full federation execution.

#[path = "../../e2e-tests/src/federation/service_auth_fixture.rs"]
mod service_auth_fixture;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use catbird_server::auth::{AuthError, AuthMiddleware};
use p256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use serde_json::Value;

const ENROLL_DEVICE: &str = "blue.catbird.chat.enrollDevice";
const ACTORS: [(&str, &str); 2] = [
    (
        include_str!("../../e2e-tests/fixtures/alice-did.json"),
        include_str!("../../e2e-tests/fixtures/alice-key.pem"),
    ),
    (
        include_str!("../../e2e-tests/fixtures/bob-did.json"),
        include_str!("../../e2e-tests/fixtures/bob-key.pem"),
    ),
];
const DESTINATIONS: [&str; 2] = [
    include_str!("../../e2e-tests/fixtures/ds1-did.json"),
    include_str!("../../e2e-tests/fixtures/ds2-did.json"),
];

fn destination(document: &str) -> (String, String) {
    let value: Value = serde_json::from_str(document).unwrap();
    // Expectations come from the independent DID fixtures, not the signer.
    (
        value["id"].as_str().unwrap().to_owned(),
        value["service"][0]["id"].as_str().unwrap().to_owned(),
    )
}

async fn actor(document: &str, pem: &str) -> (AuthMiddleware, String, SigningKey) {
    let value: Value = serde_json::from_str(document).unwrap();
    let issuer = value["id"].as_str().unwrap().to_owned();
    let verifier = AuthMiddleware::new();
    verifier
        .cache_did_document(serde_json::from_str(document).unwrap())
        .await;
    (verifier, issuer, SigningKey::from_pkcs8_pem(pem).unwrap())
}

#[tokio::test]
async fn chat_fixture_tokens_verify_for_each_destination_service() {
    for (document, pem) in ACTORS {
        let (verifier, issuer, key) = actor(document, pem).await;
        for destination_document in DESTINATIONS {
            let (destination_did, expected_audience) = destination(destination_document);
            let token =
                service_auth_fixture::mint_chat_jwt(&issuer, &key, &destination_did, ENROLL_DEVICE);
            let claims = verifier
                .verify_jwt_for_audience(&token, Some(&expected_audience))
                .await
                .expect("actual fixture signer must pass production signature and audience checks");
            assert_eq!(claims.iss, issuer);
            assert_eq!(claims.sub.as_deref(), Some(issuer.as_str()));
            assert_eq!(claims.aud, expected_audience);
            assert_eq!(claims.lxm.as_deref(), Some(ENROLL_DEVICE));
            assert_eq!(claims.exp - claims.iat.expect("issued-at"), 50);
            assert!(!claims.jti.as_deref().unwrap().is_empty());

            let next =
                service_auth_fixture::mint_chat_jwt(&issuer, &key, &destination_did, ENROLL_DEVICE);
            let next_claims = verifier
                .verify_jwt_for_audience(&next, Some(&expected_audience))
                .await
                .unwrap();
            assert_ne!(
                claims.jti, next_claims.jti,
                "each request needs a fresh nonce"
            );
        }
    }
}

#[tokio::test]
async fn chat_fixture_tokens_reject_wrong_node_and_stale_shared_audiences() {
    for (document, pem) in ACTORS {
        let (verifier, issuer, key) = actor(document, pem).await;
        for (index, destination_document) in DESTINATIONS.iter().enumerate() {
            let (destination_did, expected_audience) = destination(destination_document);
            let (_, other_audience) = destination(DESTINATIONS[1 - index]);
            let token =
                service_auth_fixture::mint_chat_jwt(&issuer, &key, &destination_did, ENROLL_DEVICE);
            let wrong_node = verifier
                .verify_jwt_for_audience(&token, Some(&other_audience))
                .await
                .unwrap_err();
            assert!(matches!(wrong_node, AuthError::InvalidToken(ref message)
                if message == &format!("aud does not match {other_audience}")));

            let stale = service_auth_fixture::mint_jwt_with_lifetime(
                &issuer,
                &key,
                "did:web:chat.catbird.blue#atproto_mls",
                ENROLL_DEVICE,
                None,
                50,
            );
            let stale_audience = verifier
                .verify_jwt_for_audience(&stale, Some(&expected_audience))
                .await
                .unwrap_err();
            assert!(
                matches!(stale_audience, AuthError::InvalidToken(ref message)
                if message == &format!("aud does not match {expected_audience}"))
            );
        }
    }
}

#[tokio::test]
async fn chat_fixture_tokens_reject_tampered_signatures() {
    let (verifier, issuer, key) = actor(ACTORS[0].0, ACTORS[0].1).await;
    let (destination_did, expected_audience) = destination(DESTINATIONS[0]);
    let token = service_auth_fixture::mint_chat_jwt(&issuer, &key, &destination_did, ENROLL_DEVICE);
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    let mut signature = URL_SAFE_NO_PAD.decode(&parts[2]).unwrap();
    signature[12] ^= 1;
    parts[2] = URL_SAFE_NO_PAD.encode(signature);
    let result = verifier
        .verify_jwt_for_audience(&parts.join("."), Some(&expected_audience))
        .await;
    assert!(matches!(result, Err(AuthError::InvalidSignature)));
}
