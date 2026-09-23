//! Dedicated receipt configuration and durable rotation trust checks.
#![allow(dead_code)]
pub use catbird_server::chat_protocol::direct_request_transcript;
#[path = "common/chat_protocol.rs"]
pub mod chat_protocol_baseline;
mod common {
    pub use super::chat_protocol_baseline as chat_protocol;
    pub mod direct_request_database;
}
mod repository {
    pub mod receipts {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/direct_request_receipts.rs"
        ));
    }
}
use p256::{
    ecdsa::SigningKey,
    pkcs8::{EncodePrivateKey, LineEnding},
};
use repository::receipts::DirectRequestReceiptSigner;
fn document(keys: &[&SigningKey]) -> String {
    let methods=keys.iter().map(|key| {
        let public=key.verifying_key().to_encoded_point(true);
        let mut multikey=vec![0x80,0x24];multikey.extend_from_slice(public.as_bytes());
        serde_json::json!({"id":direct_request_transcript::direct_request_receipt_key_id(public.as_bytes()).unwrap(),"controller":"did:web:chat.catbird.blue","type":"Multikey","publicKeyMultibase":multibase::encode(multibase::Base::Base58Btc,multikey)})
    }).collect::<Vec<_>>();
    serde_json::json!({"id":"did:web:chat.catbird.blue","verificationMethod":methods}).to_string()
}
#[tokio::test]
async fn restart_and_rotation_retain_historical_receipt_trust() {
    let pool = common::direct_request_database::setup().await;
    let old = SigningKey::from_bytes((&[31; 32]).into()).unwrap();
    let new = SigningKey::from_bytes((&[32; 32]).into()).unwrap();
    let service = SigningKey::from_bytes((&[33; 32]).into()).unwrap();
    let old_pem = old.to_pkcs8_pem(LineEnding::LF).unwrap();
    let new_pem = new.to_pkcs8_pem(LineEnding::LF).unwrap();
    let service_pem = service.to_pkcs8_pem(LineEnding::LF).unwrap();
    // The shared guarded database can also contain real HTTP fixture receipt
    // methods. Preserve their public bytes in this test's configured document;
    // dropping any historical method must continue to fail closed.
    let mut all: serde_json::Value = serde_json::from_str(&document(&[&old, &new])).unwrap();
    let retained: Vec<(String, Vec<u8>)> =
        sqlx::query_as("SELECT key_id,public_key FROM chat.direct_request_receipt_keys")
            .fetch_all(&pool)
            .await
            .unwrap();
    let methods = all["verificationMethod"].as_array_mut().unwrap();
    for (id, public) in retained {
        if methods
            .iter()
            .any(|method| method["id"].as_str() == Some(id.as_str()))
        {
            continue;
        }
        let mut multikey = vec![0x80, 0x24];
        multikey.extend_from_slice(&public);
        methods.push(serde_json::json!({"id":id,"controller":"did:web:chat.catbird.blue","type":"Multikey","publicKeyMultibase":multibase::encode(multibase::Base::Base58Btc,multikey)}));
    }
    let all = all.to_string();
    let old_signer =
        DirectRequestReceiptSigner::configured(old_pem.as_str(), service_pem.as_str(), &all)
            .unwrap();
    old_signer.validate_and_retain_keys(&pool).await.unwrap();
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/direct_request_vectors.json")).unwrap();
    let mut body = fixture["signed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| {
            v["body"]["receipt"]["$type"] == "blue.catbird.chat.defs#directRequestCancelledReceipt"
        })
        .unwrap()["body"]
        .clone();
    body["keyId"] = serde_json::json!(old_signer.key_id());
    let receipt = old_signer.seal_outcome(body).unwrap();
    let exact = receipt.bytes().to_vec();
    let new_signer =
        DirectRequestReceiptSigner::configured(new_pem.as_str(), service_pem.as_str(), &all)
            .unwrap();
    new_signer.validate_and_retain_keys(&pool).await.unwrap();
    let restart =
        DirectRequestReceiptSigner::configured(new_pem.as_str(), service_pem.as_str(), &all)
            .unwrap();
    restart.validate_and_retain_keys(&pool).await.unwrap();
    direct_request_transcript::verify_signed_request(
        direct_request_transcript::DirectRequestKind::Outcome,
        &exact,
        old.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    assert_eq!(exact, receipt.bytes());
    let missing = DirectRequestReceiptSigner::configured(
        new_pem.as_str(),
        service_pem.as_str(),
        &document(&[&new]),
    )
    .unwrap();
    assert!(missing.validate_and_retain_keys(&pool).await.is_err());
}
#[path = "../src/chat_protocol/request_push.rs"]
pub mod request_push;

#[path = "../src/chat_protocol/validation.rs"]
pub mod validation;

#[path = "../src/chat_protocol/model.rs"]
pub mod model;

#[tokio::test]
async fn variable_authority_direct_request_receipt_signer_persists_and_verifies() {
    let pool = common::direct_request_database::setup().await;
    let receipt_key = SigningKey::from_bytes((&[55; 32]).into()).unwrap();
    let service_key = SigningKey::from_bytes((&[56; 32]).into()).unwrap();
    let receipt_pem = receipt_key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let service_pem = service_key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let authority_did = "did:web:federated-node.example.org";

    let public = receipt_key.verifying_key().to_encoded_point(true);
    let mut multikey = vec![0x80, 0x24];
    multikey.extend_from_slice(public.as_bytes());
    let key_id = direct_request_transcript::direct_request_receipt_key_id_for_authority(
        authority_did,
        public.as_bytes(),
    )
    .unwrap();
    let methods = vec![serde_json::json!({
        "id": key_id,
        "controller": authority_did,
        "type": "Multikey",
        "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, multikey)
    })];
    let doc = serde_json::json!({
        "id": authority_did,
        "verificationMethod": methods
    })
    .to_string();

    let signer = DirectRequestReceiptSigner::configured(
        receipt_pem.as_str(),
        service_pem.as_str(),
        &doc,
    )
    .unwrap();

    assert_eq!(signer.authority_did(), authority_did);
    assert_eq!(signer.key_id(), key_id);
    signer.validate_and_retain_keys(&pool).await.unwrap();

    // Ensure DB entry has the variable authority_did and valid fingerprint
    let db_row: (String, String, Vec<u8>) = sqlx::query_as(
        "SELECT key_id, authority_did, public_key FROM chat.direct_request_receipt_keys WHERE key_id = $1",
    )
    .bind(&key_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(db_row.0, key_id);
    assert_eq!(db_row.1, authority_did);
    assert_eq!(db_row.2, public.as_bytes());

    let body = serde_json::json!({
        "$type": "blue.catbird.chat.defs#directRequestReceiptBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-OUTCOME\0",
        "protocolVersion": "2",
        "authorityDid": authority_did,
        "keyId": signer.key_id(),
        "receipt": {
            "$type": "blue.catbird.chat.defs#directRequestCancelledReceipt",
            "requestId": "018f3f6a-7b2c-4d91-8a5e-0f123456789a",
            "actorDid": "did:plc:sender11111111111111111",
            "actorDeviceId": "018f3f6a-7b2c-4d91-8a5e-0f123456789b",
            "cancelledAt": "2026-09-19T00:00:00Z"
        }
    });
    let receipt = signer.seal_outcome(body).unwrap();
    let verified = direct_request_transcript::verify_signed_request(
        direct_request_transcript::DirectRequestKind::Outcome,
        receipt.bytes(),
        public.as_bytes(),
    )
    .unwrap();
    assert_eq!(verified.body()["authorityDid"], authority_did);
}
