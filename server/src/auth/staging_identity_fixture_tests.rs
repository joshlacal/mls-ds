use super::*;
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::{EncodePrivateKey, LineEnding},
};
use std::{
    collections::HashSet,
    sync::{atomic::AtomicUsize, atomic::Ordering, Arc, Mutex},
};

const GATEWAY_DID: &str = "did:web:dev-api.catbird.blue";
const MLS_DID: &str = "did:web:dev-api.catbird.blue:mls";
const USER_DID: &str = "did:plc:wave1-staging-user";
const ENDPOINT: &str = "blue.catbird.chat.getConversations";
const OTHER_ENDPOINT: &str = "blue.catbird.chat.sendMessage";
const GATEWAY_KID: &str = "catbird-key-1";

fn strict_fixture_policy() -> AuthEnforcementPolicy {
    AuthEnforcementPolicy::strict_for_test()
}

fn fixture_signing_key(last_byte: u8) -> SigningKey {
    let mut scalar = [0_u8; 32];
    scalar[31] = last_byte;
    SigningKey::from_slice(&scalar).expect("fixture scalar is a valid P-256 private key")
}

fn jwk_document(did: &str, fragment: &str, key: &SigningKey) -> DidDocument {
    let point = key.verifying_key().to_encoded_point(false);
    DidDocument {
        id: did.to_string(),
        verification_method: vec![VerificationMethod {
            id: format!("{did}#{fragment}"),
            key_type: "JsonWebKey2020".to_string(),
            controller: did.to_string(),
            public_key_multibase: None,
            public_key_jwk: Some(PublicKeyJwk {
                kty: "EC".to_string(),
                crv: "P-256".to_string(),
                x: URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point has x")),
                y: Some(URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point has y"))),
            }),
        }],
        service: None,
    }
}

fn multikey_document(did: &str, fragment: &str, key: &SigningKey) -> DidDocument {
    let mut multicodec_key = vec![0x80, 0x24];
    multicodec_key.extend_from_slice(key.verifying_key().to_encoded_point(true).as_bytes());
    DidDocument {
        id: did.to_string(),
        verification_method: vec![VerificationMethod {
            id: format!("{did}#{fragment}"),
            key_type: "Multikey".to_string(),
            controller: did.to_string(),
            public_key_multibase: Some(multibase::encode(
                multibase::Base::Base58Btc,
                multicodec_key,
            )),
            public_key_jwk: None,
        }],
        service: None,
    }
}

async fn middleware_with_document(did_doc: DidDocument) -> AuthMiddleware {
    let middleware = AuthMiddleware::with_config(300, 100, 60).with_test_service_did(MLS_DID);
    middleware
        .did_cache
        .insert(
            did_doc.id.clone(),
            CachedDidDoc {
                doc: did_doc,
                cached_at: Utc::now(),
            },
        )
        .await;
    middleware
}

async fn middleware_with_dynamic_service_did(
    did_doc: DidDocument,
    service_did: Arc<Mutex<Option<String>>>,
) -> AuthMiddleware {
    let service_did_source = Arc::clone(&service_did);
    let middleware = AuthMiddleware::with_config(300, 100, 60).with_test_service_did_source(
        Arc::new(move || {
            service_did_source
                .lock()
                .expect("fixture service DID source lock")
                .clone()
        }),
    );
    middleware
        .did_cache
        .insert(
            did_doc.id.clone(),
            CachedDidDoc {
                doc: did_doc,
                cached_at: Utc::now(),
            },
        )
        .await;
    middleware
}

fn delegated_claims(issuer: &str, audience: &str, lxm: &str, jti: &str) -> AtProtoClaims {
    let now = Utc::now().timestamp();
    AtProtoClaims {
        iss: issuer.to_string(),
        aud: audience.to_string(),
        exp: now + 120,
        iat: Some(now),
        sub: Some(USER_DID.to_string()),
        lxm: Some(lxm.to_string()),
        jti: Some(jti.to_string()),
    }
}

fn sign_token(key: &SigningKey, kid: Option<&str>, claims: &AtProtoClaims) -> String {
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({"alg": "ES256", "typ": "JWT", "kid": kid}))
            .expect("serialize fixture JWT header"),
    );
    let payload =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("serialize fixture JWT claims"));
    let signing_input = format!("{header}.{payload}");
    let signature: Signature = key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

#[tokio::test]
async fn service_did_set_after_middleware_construction_is_enforced_at_verification_time() {
    let gateway_key = fixture_signing_key(7);
    let service_did = Arc::new(Mutex::new(None));
    let middleware = middleware_with_dynamic_service_did(
        jwk_document(GATEWAY_DID, GATEWAY_KID, &gateway_key),
        Arc::clone(&service_did),
    )
    .await;

    *service_did.lock().expect("fixture service DID lock") = Some(MLS_DID.to_string());
    let wrong_audience = sign_token(
        &gateway_key,
        Some(GATEWAY_KID),
        &delegated_claims(
            GATEWAY_DID,
            "did:web:stale-mls.example",
            ENDPOINT,
            "wave1-staging-late-service-did-jti-0001",
        ),
    );

    assert!(matches!(
        middleware.verify_jwt(&wrong_audience).await,
        Err(AuthError::InvalidToken(message)) if message.contains("aud does not match")
    ));
}

#[tokio::test]
async fn service_did_swap_rejects_stale_audience_and_accepts_current_audience() {
    let gateway_key = fixture_signing_key(8);
    let stale_service_did = "did:web:stale-mls.example";
    let service_did = Arc::new(Mutex::new(Some(stale_service_did.to_string())));
    let middleware = middleware_with_dynamic_service_did(
        jwk_document(GATEWAY_DID, GATEWAY_KID, &gateway_key),
        Arc::clone(&service_did),
    )
    .await;

    *service_did.lock().expect("fixture service DID lock") = Some(MLS_DID.to_string());
    let stale_audience = sign_token(
        &gateway_key,
        Some(GATEWAY_KID),
        &delegated_claims(
            GATEWAY_DID,
            stale_service_did,
            ENDPOINT,
            "wave1-staging-stale-service-did-jti-0001",
        ),
    );
    assert!(matches!(
        middleware.verify_jwt(&stale_audience).await,
        Err(AuthError::InvalidToken(message)) if message.contains("aud does not match")
    ));

    let current_audience = sign_token(
        &gateway_key,
        Some(GATEWAY_KID),
        &delegated_claims(
            GATEWAY_DID,
            MLS_DID,
            ENDPOINT,
            "wave1-staging-current-service-did-jti-0001",
        ),
    );
    middleware
        .verify_jwt(&current_audience)
        .await
        .expect("request-time SERVICE_DID accepts the current exact audience");
}

#[derive(Default)]
struct FixtureReplayStore {
    consumed: Mutex<HashSet<(String, String)>>,
    attempts: Mutex<Vec<FixtureReplayAttempt>>,
    calls: AtomicUsize,
}

#[derive(Debug, PartialEq, Eq)]
struct FixtureReplayAttempt {
    issuer_did: String,
    jti: String,
    endpoint_nsid: String,
    ttl_seconds: u64,
}

#[async_trait::async_trait]
impl JtiReplayStore for FixtureReplayStore {
    async fn insert_if_absent(
        &self,
        issuer_did: &str,
        jti: &str,
        endpoint_nsid: &str,
        ttl_seconds: u64,
    ) -> Result<bool, AuthError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.attempts
            .lock()
            .expect("fixture replay attempt lock")
            .push(FixtureReplayAttempt {
                issuer_did: issuer_did.to_string(),
                jti: jti.to_string(),
                endpoint_nsid: endpoint_nsid.to_string(),
                ttl_seconds,
            });
        Ok(self
            .consumed
            .lock()
            .expect("fixture replay store lock")
            .insert((issuer_did.to_string(), jti.to_string())))
    }
}

#[tokio::test]
async fn wave1_staging_gateway_jwk_verifies_and_delegates_only_with_exact_bindings() {
    let gateway_key = fixture_signing_key(1);
    let other_key = fixture_signing_key(2);
    let middleware =
        middleware_with_document(jwk_document(GATEWAY_DID, GATEWAY_KID, &gateway_key)).await;
    let claims = delegated_claims(
        GATEWAY_DID,
        MLS_DID,
        ENDPOINT,
        "wave1-staging-gateway-jti-0001",
    );
    let token = sign_token(&gateway_key, Some(GATEWAY_KID), &claims);

    let verified = middleware
        .verify_jwt(&token)
        .await
        .expect("staging gateway token verifies against its exact JWK");
    enforce_standard_with_policy(&verified, ENDPOINT, strict_fixture_policy())
        .expect("audience-bound token is endpoint-bound");
    assert_eq!(
        resolve_authenticated_principal(&verified, Some(GATEWAY_DID))
            .expect("configured staging gateway may delegate"),
        USER_DID
    );

    let wrong_kid = sign_token(&gateway_key, Some("other-key"), &claims);
    assert!(matches!(
        middleware.verify_jwt(&wrong_kid).await,
        Err(AuthError::InvalidToken(message)) if message.contains("No verification method matches")
    ));

    let wrong_key = sign_token(&other_key, Some(GATEWAY_KID), &claims);
    assert!(matches!(
        middleware.verify_jwt(&wrong_key).await,
        Err(AuthError::InvalidSignature)
    ));

    let wrong_audience_claims = delegated_claims(
        GATEWAY_DID,
        "did:web:wrong-mls.example",
        ENDPOINT,
        "wave1-staging-gateway-jti-0002",
    );
    let wrong_audience = sign_token(&gateway_key, Some(GATEWAY_KID), &wrong_audience_claims);
    assert!(matches!(
        middleware.verify_jwt(&wrong_audience).await,
        Err(AuthError::InvalidToken(message)) if message.contains("aud does not match")
    ));

    let wrong_lxm_claims = delegated_claims(
        GATEWAY_DID,
        MLS_DID,
        "blue.catbird.mlsChat.sendMessage",
        "wave1-staging-gateway-jti-0003",
    );
    let wrong_lxm = sign_token(&gateway_key, Some(GATEWAY_KID), &wrong_lxm_claims);
    let wrong_lxm = middleware
        .verify_jwt(&wrong_lxm)
        .await
        .expect("signature and audience remain valid");
    assert!(matches!(
        enforce_standard_with_policy(&wrong_lxm, ENDPOINT, strict_fixture_policy()),
        Err(AuthError::LxmMismatch)
    ));

    let replay_key = format!("{}|{}", GATEWAY_DID, claims.jti.as_deref().unwrap());
    JTI_CACHE.invalidate(&replay_key);
    let replay_store = FixtureReplayStore::default();
    enforce_standard_with_store(&verified, ENDPOINT, &replay_store, strict_fixture_policy())
        .await
        .expect("fresh jti is atomically recorded");
    JTI_CACHE.invalidate(&replay_key);
    assert!(matches!(
        enforce_standard_with_store(&verified, ENDPOINT, &replay_store, strict_fixture_policy(),)
            .await,
        Err(AuthError::ReplayDetected)
    ));
    assert_eq!(replay_store.calls.load(Ordering::SeqCst), 2);
    assert!(replay_store
        .consumed
        .lock()
        .expect("fixture replay store lock")
        .contains(&(GATEWAY_DID.to_string(), claims.jti.clone().unwrap())));
    JTI_CACHE.invalidate(&replay_key);
}

#[tokio::test]
async fn persisted_replay_is_issuer_and_jti_scoped_across_endpoints() {
    let jti = "wave1-staging-cross-endpoint-jti-0001";
    let first_claims = delegated_claims(GATEWAY_DID, MLS_DID, ENDPOINT, jti);
    let replay_claims = delegated_claims(GATEWAY_DID, MLS_DID, OTHER_ENDPOINT, jti);
    let replay_key = format!("{GATEWAY_DID}|{jti}");
    let replay_store = FixtureReplayStore::default();

    JTI_CACHE.invalidate(&replay_key);
    enforce_standard_with_store(
        &first_claims,
        ENDPOINT,
        &replay_store,
        strict_fixture_policy(),
    )
    .await
    .expect("first issuer+jti use is atomically recorded");

    JTI_CACHE.invalidate(&replay_key);
    assert!(matches!(
        enforce_standard_with_store(
            &replay_claims,
            OTHER_ENDPOINT,
            &replay_store,
            strict_fixture_policy(),
        )
        .await,
        Err(AuthError::ReplayDetected)
    ));
    assert_eq!(replay_store.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        *replay_store
            .attempts
            .lock()
            .expect("fixture replay attempt lock"),
        vec![
            FixtureReplayAttempt {
                issuer_did: GATEWAY_DID.to_string(),
                jti: jti.to_string(),
                endpoint_nsid: ENDPOINT.to_string(),
                ttl_seconds: 120,
            },
            FixtureReplayAttempt {
                issuer_did: GATEWAY_DID.to_string(),
                jti: jti.to_string(),
                endpoint_nsid: OTHER_ENDPOINT.to_string(),
                ttl_seconds: 120,
            },
        ]
    );
    JTI_CACHE.invalidate(&replay_key);
}

#[tokio::test]
async fn arbitrary_issuer_cannot_use_staging_gateway_delegation_policy() {
    let attacker_did = "did:web:attacker.example";
    let attacker_key = fixture_signing_key(3);
    let middleware =
        middleware_with_document(jwk_document(attacker_did, GATEWAY_KID, &attacker_key)).await;
    let token = sign_token(
        &attacker_key,
        Some(GATEWAY_KID),
        &delegated_claims(
            attacker_did,
            MLS_DID,
            ENDPOINT,
            "wave1-staging-attacker-jti-0001",
        ),
    );

    let verified = middleware
        .verify_jwt(&token)
        .await
        .expect("attacker controls its own valid DID key");
    assert!(matches!(
        resolve_authenticated_principal(&verified, Some(GATEWAY_DID)),
        Err(AuthError::InvalidToken(message)) if message.contains("untrusted issuer")
    ));
}

#[tokio::test]
async fn wave1_staging_mls_atproto_jwk_verifies_outbound_token_without_kid() {
    let mls_key = fixture_signing_key(4);
    let decoy_key = fixture_signing_key(6);
    let mut did_doc = jwk_document(MLS_DID, "decoy", &decoy_key);
    did_doc
        .verification_method
        .extend(jwk_document(MLS_DID, "atproto", &mls_key).verification_method);
    let middleware = middleware_with_document(did_doc).await;
    let pem = mls_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode deterministic MLS fixture key as PKCS#8 PEM");
    let client = crate::federation::ServiceAuthClient::from_es256_pem(
        MLS_DID.to_string(),
        pem.as_bytes(),
        None,
    )
    .expect("construct the production outbound service-auth signer");
    let token = client
        .sign_request(MLS_DID, ENDPOINT)
        .expect("sign outbound service-auth token without kid");

    let verified = middleware
        .verify_jwt(&token)
        .await
        .expect("no-kid token selects the #atproto JWK");
    assert_eq!(verified.iss, MLS_DID);
    assert_eq!(verified.aud, MLS_DID);
    assert_eq!(verified.lxm.as_deref(), Some(ENDPOINT));
    assert!(verified.jti.as_deref().is_some_and(|jti| !jti.is_empty()));
    enforce_standard_with_policy(&verified, ENDPOINT, strict_fixture_policy())
        .expect("outbound token is endpoint-bound");
    assert_eq!(
        resolve_authenticated_principal(&verified, Some(GATEWAY_DID))
            .expect("service token without sub remains issuer-bound"),
        MLS_DID
    );
}

#[tokio::test]
async fn es256_multikey_only_document_is_rejected_by_current_verifier() {
    let mls_key = fixture_signing_key(5);
    let middleware =
        middleware_with_document(multikey_document(MLS_DID, "atproto", &mls_key)).await;
    let claims = AtProtoClaims {
        sub: None,
        ..delegated_claims(
            MLS_DID,
            MLS_DID,
            ENDPOINT,
            "wave1-staging-multikey-jti-0001",
        )
    };
    let token = sign_token(&mls_key, None, &claims);

    assert!(matches!(
        middleware.verify_jwt(&token).await,
        Err(AuthError::MissingVerificationMethod)
    ));
}
