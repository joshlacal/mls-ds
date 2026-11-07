//! Focused production-runtime construction proof for the clean-chat
//! relationship authority.

use catbird_server::handlers::chat::ChatRuntime;

#[test]
fn runtime_owns_the_fixed_relationship_authority_without_an_injection_path() {
    std::env::remove_var("CHAT_CUTOVER_ENABLED");
    std::env::remove_var("CHAT_NEST_ISSUER");

    let runtime = ChatRuntime::from_env(std::sync::Arc::new(
        catbird_server::realtime::SseState::new(8),
    ))
    .expect("fixed relationship authority constructs");
    assert!(
        format!("{runtime:?}").contains("fixed-production-authority"),
        "the mandatory fixed authority must be present in runtime state"
    );

    let source = include_str!("../src/handlers/chat/runtime.rs");
    assert!(source.contains("relationship_authority: Arc<ProductionRelationshipAuthority>"));
    assert!(source.contains("load_fixed_relationship_authority_startup_guard()"));
    assert!(!source.contains("Option<ProductionRelationshipAuthority>"));
    assert!(!source.contains("relationship_authority: Option<"));
    assert!(!source.contains("fn for_test("));
}

/// MLS-R3-03: startup builds the one receipt signer from the validated
/// federation configuration, and the chat runtime never reads the receipt key.
/// Disabled issuance with a configured key leaves every issuer without a
/// signer, so nothing is signed; issue mode signs only with the exact current
/// method and refuses startup when the published history has a gap.
#[test]
fn receipt_issuance_has_one_validated_startup_source() {
    use catbird_server::federation::{
        FederationConfig, ReceiptConfigError, ReceiptDidDocumentError,
    };
    use catbird_server::identity::did_doc::encode_p256_multikey;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::{EncodePrivateKey as _, LineEnding};

    const DID: &str = "did:web:receipt-startup.example.com";
    let key = |byte: u8| SigningKey::from_slice(&[byte; 32]).unwrap();
    let (service, first, second) = (key(0x51), key(0x52), key(0x53));
    let pem = |key: &SigningKey| key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let document = |methods: &[(u8, &SigningKey)]| {
        let methods: Vec<_> = methods
            .iter()
            .map(|(generation, key)| {
                serde_json::json!({
                    "id": format!("{DID}#mls-receipt-{generation}"),
                    "type": "Multikey",
                    "controller": DID,
                    "publicKeyMultibase": encode_p256_multikey(key.verifying_key()),
                })
            })
            .collect();
        serde_json::json!({ "id": DID, "verificationMethod": methods }).to_string()
    };
    std::env::set_var("SERVICE_DID", DID);
    std::env::set_var("SIGNING_KEY_PEM", pem(&service));
    std::env::set_var("RECEIPT_SIGNING_KEY_PEM", pem(&second));
    std::env::set_var(
        "RECEIPT_VERIFICATION_METHOD",
        format!("{DID}#mls-receipt-2"),
    );
    std::env::set_var(
        "RECEIPT_DID_DOCUMENT_JSON",
        document(&[(1, &first), (2, &second)]),
    );

    std::env::set_var("RECEIPT_ISSUANCE_MODE", "disabled");
    assert!(FederationConfig::from_env()
        .receipt_signer()
        .unwrap()
        .is_none());
    let runtime = ChatRuntime::from_env(std::sync::Arc::new(
        catbird_server::realtime::SseState::new(8),
    ))
    .expect("runtime constructs with a configured but disabled receipt key");
    assert!(runtime.i13_receipt_signer().is_none());

    std::env::set_var("RECEIPT_ISSUANCE_MODE", "issue");
    let signer = FederationConfig::from_env()
        .receipt_signer()
        .unwrap()
        .expect("issue mode signer");
    assert_eq!(signer.key_id(), format!("{DID}#mls-receipt-2"));
    std::env::set_var("RECEIPT_DID_DOCUMENT_JSON", document(&[(2, &second)]));
    assert_eq!(
        FederationConfig::from_env().receipt_signer().err(),
        Some(ReceiptConfigError::InvalidPublishedDidDocument(
            ReceiptDidDocumentError::ReceiptHistoryGap
        ))
    );
}
