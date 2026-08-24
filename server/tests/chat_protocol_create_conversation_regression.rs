use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_server::chat_protocol::wire::{
    validate_group_info, GroupInfoValidationPolicy, WireValidationError,
    MAX_KEY_PACKAGE_LIFETIME_SECONDS,
};
use serde_json::Value;

mod common;

#[test]
fn genesis_group_info_rejects_excessive_leaf_lifetime_as_declared_error() {
    let fixture_raw =
        std::fs::read_to_string("tests/fixtures/captured_create_conversation_request.json")
            .expect("read captured fixture");
    let fixture: Value = serde_json::from_str(&fixture_raw).expect("parse fixture json");

    let group_info_b64 = fixture["body"]["signedRequest"]["body"]["genesisGroupInfo"]["bytes"]
        .as_str()
        .unwrap();
    let group_info_bytes = STANDARD.decode(group_info_b64).unwrap();

    let user_did = fixture["body"]["signedRequest"]["body"]["actorDid"]
        .as_str()
        .unwrap();
    let device_id = fixture["body"]["signedRequest"]["body"]["actorDeviceId"]
        .as_str()
        .unwrap();
    let basic_credential = format!("{}#{}", user_did, device_id).into_bytes();

    let pubkey_b64 = fixture["body"]["signedRequest"]["body"]["metadataSnapshot"]["authorProof"]
        ["signaturePublicKey"]
        .as_str()
        .unwrap();
    let pubkey_bytes = STANDARD.decode(pubkey_b64).unwrap();

    let policy = GroupInfoValidationPolicy {
        expected_basic_credential: &basic_credential,
        expected_signature_key: &pubkey_bytes,
        now_unix_seconds: chrono::Utc::now().timestamp() as u64,
        max_bytes: 65536,
        max_ratchet_tree_bytes: 65536,
        max_members: 100,
    };

    let result = validate_group_info(&group_info_bytes, policy);
    assert!(
        matches!(result, Err(WireValidationError::LifetimeTooLong)),
        "Genesis GroupInfo with >30-day leaf lifetime must fail validation with LifetimeTooLong, got: {:?}",
        result
    );
}
#[test]
fn validate_latest_captured_create_conversation() {
    if let Ok(fixture_raw) =
        std::fs::read_to_string("/tmp/last_blue.catbird.chat.createConversation_body.json")
    {
        let fixture: Value = serde_json::from_str(&fixture_raw).expect("parse fixture json");
        let group_info_b64 = fixture["signedRequest"]["body"]["genesisGroupInfo"]["bytes"]
            .as_str()
            .unwrap();
        let group_info_bytes = STANDARD.decode(group_info_b64).unwrap();

        let user_did = fixture["signedRequest"]["body"]["actorDid"]
            .as_str()
            .unwrap();
        let device_id = fixture["signedRequest"]["body"]["actorDeviceId"]
            .as_str()
            .unwrap();
        let basic_credential = format!("{}#{}", user_did, device_id).into_bytes();

        let pubkey_b64 = fixture["signedRequest"]["body"]["metadataSnapshot"]["authorProof"]
            ["signaturePublicKey"]
            .as_str()
            .unwrap();
        let pubkey_bytes = STANDARD.decode(pubkey_b64).unwrap();

        let policy = GroupInfoValidationPolicy {
            expected_basic_credential: &basic_credential,
            expected_signature_key: &pubkey_bytes,
            now_unix_seconds: chrono::Utc::now().timestamp() as u64,
            max_bytes: 65536,
            max_ratchet_tree_bytes: 65536,
            max_members: 100,
        };

        let result = validate_group_info(&group_info_bytes, policy);
        println!("validate_group_info result: {:?}", result);
        assert!(result.is_ok(), "validate_group_info failed: {:?}", result);
    }
}
#[tokio::test]
async fn replay_create_conversation_against_router() {
    use axum::body::Body;
    use axum::http::Request;
    use common::http_acceptance as http;

    let pool = common::chat_protocol::setup_chat_protocol_db(5).await;
    http::ensure_fence(&pool).await;

    if let Ok(fixture_raw) =
        std::fs::read_to_string("/tmp/last_blue.catbird.chat.createConversation_body.json")
    {
        let fixture: Value = serde_json::from_str(&fixture_raw).expect("parse fixture json");
        let actor_did = fixture["signedRequest"]["body"]["actorDid"]
            .as_str()
            .unwrap();
        let actor_device_id: uuid::Uuid = fixture["signedRequest"]["body"]["actorDeviceId"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let actor_key_id = fixture["signedRequest"]["body"]["keyId"].as_str().unwrap();
        let pubkey_b64 = fixture["signedRequest"]["body"]["metadataSnapshot"]["authorProof"]
            ["signaturePublicKey"]
            .as_str()
            .unwrap();
        let actor_pubkey = STANDARD.decode(pubkey_b64).unwrap();
        let signed_at_str = fixture["signedRequest"]["body"]["signedAt"]
            .as_str()
            .unwrap();
        let now: chrono::DateTime<chrono::Utc> =
            chrono::DateTime::parse_from_rfc3339(signed_at_str)
                .unwrap()
                .with_timezone(&chrono::Utc);
        // Offset now slightly to be within 1 second of signed_at
        let now = now + chrono::Duration::milliseconds(100);
        // Seed actor principal, device, and device_key
        sqlx::query(
            "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(actor_did)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
        let p256_key = http::random_p256();
        let point = p256_key.verifying_key().to_encoded_point(false);
        let jwk_val = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        });
        let jkt = http::jwk_thumbprint(&jwk_val);

        sqlx::query("INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'actor-dev','active',$3,1,chat.protocol_capabilities(),$4,$4) ON CONFLICT DO NOTHING")
            .bind(actor_did)
            .bind(actor_device_id)
            .bind(&jkt)
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,$5) ON CONFLICT DO NOTHING")
            .bind(actor_did)
            .bind(actor_device_id)
            .bind(actor_key_id)
            .bind(&actor_pubkey)
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();

        // Also seed recipient participant principal
        let participants = fixture["signedRequest"]["body"]["manifest"]["participants"]
            .as_array()
            .unwrap();
        for p in participants {
            let p_did = p["userDid"].as_str().unwrap();
            sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING")
                .bind(p_did)
                .bind(now)
                .execute(&pool)
                .await
                .unwrap();
        }

        // Seed DID document for service auth
        let p256_key = http::random_p256();
        let point = p256_key.verifying_key().to_encoded_point(false);
        let jwk_val = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        });
        let jwk_parsed: catbird_server::auth::PublicKeyJwk =
            serde_json::from_value(jwk_val).unwrap();
        let doc = catbird_server::auth::DidDocument {
            id: actor_did.to_string(),
            verification_method: vec![catbird_server::auth::VerificationMethod {
                id: format!("{actor_did}#atproto"),
                key_type: "JsonWebKey2020".to_string(),
                controller: actor_did.to_string(),
                public_key_jwk: Some(jwk_parsed),
                public_key_multibase: None,
            }],
            service: None,
        };
        catbird_server::auth::cache_test_did_document(doc).await;

        let token_now = chrono::Utc::now().timestamp();
        let header =
            serde_json::json!({"alg":"ES256","typ":"JWT","kid":format!("{actor_did}#atproto")});
        let claims = serde_json::json!({
            "iss": actor_did,
            "aud": http::AUDIENCE,
            "lxm": "blue.catbird.chat.createConversation",
            "iat": token_now,
            "exp": token_now + 60,
            "jti": uuid::Uuid::new_v4().to_string(),
        });
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let c = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap());
        let input = format!("{h}.{c}");
        use p256::ecdsa::signature::Signer as _;
        let sig: p256::ecdsa::Signature = p256_key.sign(input.as_bytes());
        let bearer = format!(
            "{input}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes())
        );

        let router = http::router_for_authenticated_acceptance(pool.clone()).await;
        let req = Request::builder()
            .method("POST")
            .uri("/xrpc/blue.catbird.chat.createConversation")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {bearer}"))
            .body(Body::from(fixture_raw))
            .unwrap();

        let (status, body) = http::send(router, req).await;
        println!(
            "Replay createConversation status: {:?}, body: {:?}",
            status, body
        );
        assert_eq!(status, axum::http::StatusCode::OK);
    }
}
