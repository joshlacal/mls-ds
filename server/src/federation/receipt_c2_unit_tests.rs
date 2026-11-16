//! Fast pure C2 unit tests for `receipt.rs` unscored helpers (`result_bytes_for_receipt`,
//! `validate_receipt_did_document_method_for_service`, `retained_receipt_key`,
//! `configured_receipt_signer`, and `sign_control_receipt_at`).

use super::*;
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey as _, LineEnding};
use serde_json::json;

#[test]
fn c2_result_bytes_for_receipt_and_control_coordinate_mismatch() {
    assert_eq!(
        result_bytes_for_receipt(DELIVER_WELCOME_NSID, b"ignored").unwrap(),
        b"{\"accepted\":true}"
    );
    assert_eq!(
        result_bytes_for_receipt(DELIVER_MESSAGE_NSID, b"ignored").unwrap(),
        b"{\"accepted\":true}"
    );
    assert!(matches!(
        result_bytes_for_receipt(SUBMIT_COMMIT_NSID, b"not-json"),
        Err(FederationError::InvalidEnvelope { .. })
    ));
    assert!(matches!(
        result_bytes_for_receipt("blue.catbird.mlsDS.unknown", b"{}"),
        Err(FederationError::InvalidEnvelope { .. })
    ));

    // `sign_control_receipt_at` refuses a coordinate whose conversationId differs from `input`.
    let signer = I13ReceiptSigner::from_signing_key_for_test(
        "did:web:seq-receipt.example.com".to_owned(),
        SigningKey::from_slice(&[0x31; 32]).unwrap(),
    );
    assert_eq!(signer.sequencer_did(), "did:web:seq-receipt.example.com");
    let input = I13ControlReceiptInput::from_fields(
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        1,
        "2026-11-13T12:00:00.000Z",
        "did:plc:abcdefghijklmnopqrstuvwx",
        "33333333-3333-4333-8333-333333333333",
        [0x22; 32],
    )
    .unwrap();
    assert!(signer
        .sign_control_receipt_at(
            &input,
            "44444444-4444-4444-8444-444444444444",
            0,
            &[0x11; 32],
            0
        )
        .is_err());
}

#[test]
fn c2_receipt_did_document_history_and_signer_config_boundaries() {
    let owner = "did:web:receipt-doc.example.com";
    let key1 = SigningKey::from_slice(&[0x41; 32]).unwrap();
    let key2 = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let service_key = SigningKey::from_slice(&[0x43; 32]).unwrap();

    let method_json = |gen_num: u64, controller: &str, key: &SigningKey| {
        json!({
            "id": format!("{owner}#mls-receipt-{gen_num}"),
            "type": "Multikey",
            "controller": controller,
            "publicKeyMultibase": crate::identity::did_doc::encode_p256_multikey(key.verifying_key()),
        })
    };

    let valid_two_gen = json!({
        "id": owner,
        "verificationMethod": [
            method_json(1, owner, &key1),
            method_json(2, owner, &key2),
        ]
    });
    validate_receipt_did_document_method_for_service(
        &valid_two_gen.to_string(),
        owner,
        &format!("{owner}#mls-receipt-2"),
        key2.verifying_key(),
        Some(service_key.verifying_key()),
    )
    .expect("current rotated generation 2 validates");

    // Retained historical key 1 resolves cleanly while generation 2 is current.
    assert_eq!(
        retained_receipt_key(&valid_two_gen, owner, &format!("{owner}#mls-receipt-1")).unwrap(),
        *key1.verifying_key()
    );

    // Configured generation 1 when 2 exists -> ConfiguredMethodNotCurrent.
    assert_eq!(
        validate_receipt_did_document_method_for_service(
            &valid_two_gen.to_string(),
            owner,
            &format!("{owner}#mls-receipt-1"),
            key1.verifying_key(),
            None,
        ),
        Err(ReceiptDidDocumentError::ConfiguredMethodNotCurrent)
    );

    // Wrong expected key -> SignerKeyMismatch.
    assert_eq!(
        validate_receipt_did_document_method_for_service(
            &valid_two_gen.to_string(),
            owner,
            &format!("{owner}#mls-receipt-2"),
            key1.verifying_key(),
            None,
        ),
        Err(ReceiptDidDocumentError::SignerKeyMismatch)
    );

    // Service-auth key reuse -> ServiceAuthKeyReuse.
    assert_eq!(
        validate_receipt_did_document_method_for_service(
            &valid_two_gen.to_string(),
            owner,
            &format!("{owner}#mls-receipt-2"),
            key2.verifying_key(),
            Some(key1.verifying_key()),
        ),
        Err(ReceiptDidDocumentError::ServiceAuthKeyReuse)
    );

    // Gap in generations (1 and 3 without 2) -> ReceiptHistoryGap.
    let gapped = json!({
        "id": owner,
        "verificationMethod": [
            method_json(1, owner, &key1),
            method_json(3, owner, &key2),
        ]
    });
    assert_eq!(
        validate_receipt_did_document_method_for_service(
            &gapped.to_string(),
            owner,
            &format!("{owner}#mls-receipt-3"),
            key2.verifying_key(),
            None,
        ),
        Err(ReceiptDidDocumentError::ReceiptHistoryGap)
    );

    // Duplicate generation -> AmbiguousReceiptMethod.
    let duplicate = json!({
        "id": owner,
        "verificationMethod": [
            method_json(1, owner, &key1),
            method_json(1, owner, &key2),
        ]
    });
    assert_eq!(
        validate_receipt_did_document_method_for_service(
            &duplicate.to_string(),
            owner,
            &format!("{owner}#mls-receipt-1"),
            key1.verifying_key(),
            None,
        ),
        Err(ReceiptDidDocumentError::AmbiguousReceiptMethod)
    );

    // Controller mismatch -> ControllerMismatch.
    let wrong_controller = json!({
        "id": owner,
        "verificationMethod": [
            method_json(1, "did:web:other.example.com", &key1),
        ]
    });
    assert_eq!(
        validate_receipt_did_document_method_for_service(
            &wrong_controller.to_string(),
            owner,
            &format!("{owner}#mls-receipt-1"),
            key1.verifying_key(),
            None,
        ),
        Err(ReceiptDidDocumentError::ControllerMismatch)
    );

    // configured_receipt_signer owner mismatch and unsupported DID prefix.
    let receipt_pem = key1.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let service_pem = service_key
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .to_string();
    assert!(matches!(
        configured_receipt_signer(
            Some("issue"),
            Some(&receipt_pem),
            Some("did:web:other.example.com#mls-receipt-1"),
            Some(&service_pem),
            owner,
            None,
        ),
        Err(ReceiptConfigError::VerificationMethodOwnerMismatch)
    ));
    assert!(matches!(
        configured_receipt_signer(
            Some("issue"),
            Some(&receipt_pem),
            Some("did:key:z6Mkexample#mls-receipt-1"),
            Some(&service_pem),
            "did:key:z6Mkexample",
            None,
        ),
        Err(ReceiptConfigError::UnexpectedVerificationMethod)
    ));
}
