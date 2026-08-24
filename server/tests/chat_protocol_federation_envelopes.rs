//! Integration and unit test suite for clean federation envelopes, digests, and receipts.

use catbird_atproto::generated::blue_catbird::chat::ConversationCoordinates;
use catbird_atproto::generated::blue_catbird::mlsDS::{
    EntryLocatorV1, EnvelopeHeaderV1, FederationReceiptV1,
};
use chrono::{SecondsFormat, Utc};
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use catbird_server::federation::ack::AckSigner;
use catbird_server::federation::envelope::{
    canonical_receipt_bytes, compute_commit_envelope_digest, compute_message_envelope_digest,
    compute_welcome_envelope_digest, sign_receipt, validate_entry_locator,
    validate_envelope_header, verify_receipt, DELIVER_MESSAGE_NSID, DELIVER_WELCOME_NSID,
    SUBMIT_COMMIT_NSID,
};
use catbird_server::federation::errors::FederationError;

fn test_signer(did: &str) -> (AckSigner, p256::ecdsa::VerifyingKey) {
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::random(&mut rng);
    let verifying_key = *signing_key.verifying_key();
    let signer = AckSigner::new(signing_key, did.to_string());
    (signer, verifying_key)
}

fn sample_header() -> EnvelopeHeaderV1 {
    EnvelopeHeaderV1 {
        protocol_version: jacquard_common::deps::smol_str::SmolStr::from("1"),
        delivery_id: jacquard_common::deps::smol_str::SmolStr::from(
            Uuid::new_v4().hyphenated().to_string(),
        ),
        conversation_id: jacquard_common::deps::smol_str::SmolStr::from(
            Uuid::new_v4().hyphenated().to_string(),
        ),
        sender_ds_did: jacquard_common::types::string::Did::new_owned(
            "did:web:ds1.example.com".to_string(),
        )
        .unwrap(),
        receiver_ds_did: jacquard_common::types::string::Did::new_owned(
            "did:web:ds2.example.com".to_string(),
        )
        .unwrap(),
        sequencer_did: jacquard_common::types::string::Did::new_owned(
            "did:web:ds1.example.com".to_string(),
        )
        .unwrap(),
        sequencer_term: 1,
        payload_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[42u8; 32]),
        extra_data: None,
    }
}

fn sample_locator() -> EntryLocatorV1 {
    EntryLocatorV1 {
        entry_id: jacquard_common::deps::smol_str::SmolStr::from(
            Uuid::new_v4().hyphenated().to_string(),
        ),
        seq: 1,
        accepted_payload_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[1u8; 32]),
        outer_entry_fingerprint: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[2u8; 32]),
        extra_data: None,
    }
}

#[test]
fn test_envelope_header_validation_positive() {
    let header = sample_header();
    let validated = validate_envelope_header(&header).expect("valid header must pass");
    assert_eq!(validated.protocol_version, "1");
    assert_eq!(validated.sender_ds_did, "did:web:ds1.example.com");
    assert_eq!(validated.receiver_ds_did, "did:web:ds2.example.com");
    assert_eq!(validated.sequencer_term, 1);
    assert_eq!(validated.payload_sha256, [42u8; 32]);
}

#[test]
fn test_envelope_header_validation_negative_version() {
    let mut header = sample_header();
    header.protocol_version = jacquard_common::deps::smol_str::SmolStr::from("2");
    let err = validate_envelope_header(&header).expect_err("version != 1 must fail");
    assert!(matches!(err, FederationError::InvalidEnvelope { .. }));
}

#[test]
fn test_envelope_header_validation_negative_uuid() {
    let mut header = sample_header();
    header.delivery_id = jacquard_common::deps::smol_str::SmolStr::from("not-a-uuid");
    let err = validate_envelope_header(&header).expect_err("bad deliveryId must fail");
    assert!(matches!(err, FederationError::InvalidEnvelope { .. }));
}

#[test]
fn test_envelope_header_validation_negative_did() {
    let mut header = sample_header();
    header.sender_ds_did =
        jacquard_common::types::string::Did::new_owned("did:invalid:bad".to_string()).unwrap();
    let err = validate_envelope_header(&header).expect_err("bad DID must fail");
    assert!(matches!(err, FederationError::InvalidEnvelope { .. }));
}

#[test]
fn test_envelope_header_validation_negative_extra_data() {
    let mut header = sample_header();
    let mut extra = std::collections::BTreeMap::new();
    extra.insert(
        jacquard_common::deps::smol_str::SmolStr::from("unknownField"),
        jacquard_common::types::value::Data::Null,
    );
    header.extra_data = Some(extra);
    let err = validate_envelope_header(&header).expect_err("extra fields must fail");
    assert!(matches!(err, FederationError::InvalidEnvelope { .. }));
}

#[test]
fn test_entry_locator_validation_positive() {
    let locator = sample_locator();
    let validated = validate_entry_locator(&locator).expect("valid locator must pass");
    assert_eq!(validated.seq, 1);
    assert_eq!(validated.accepted_payload_sha256, [1u8; 32]);
    assert_eq!(validated.outer_entry_fingerprint, [2u8; 32]);
}

#[test]
fn test_entry_locator_validation_negative_seq_zero() {
    let mut locator = sample_locator();
    locator.seq = 0;
    let err = validate_entry_locator(&locator).expect_err("seq 0 must fail");
    assert!(matches!(err, FederationError::InvalidEnvelope { .. }));
}

#[test]
fn test_message_envelope_digest_determinism() {
    let header_dto = sample_header();
    let header = validate_envelope_header(&header_dto).unwrap();
    let locator_dto = sample_locator();
    let locator = validate_entry_locator(&locator_dto).unwrap();

    let entry_bytes = b"canonical_entry_bytes_here";
    let signed_req = b"{\"signed\":true}";

    let digest1 = compute_message_envelope_digest(
        &header,
        "did:web:user1.example.com",
        &locator,
        entry_bytes,
        signed_req,
    )
    .expect("compute digest 1");

    let digest2 = compute_message_envelope_digest(
        &header,
        "did:web:user1.example.com",
        &locator,
        entry_bytes,
        signed_req,
    )
    .expect("compute digest 2");

    assert_eq!(digest1, digest2);

    // Mutating any field changes digest
    let digest_other_user = compute_message_envelope_digest(
        &header,
        "did:web:user2.example.com",
        &locator,
        entry_bytes,
        signed_req,
    )
    .expect("compute digest other user");
    assert_ne!(digest1, digest_other_user);
}

#[test]
fn test_commit_envelope_digest_determinism() {
    let header_dto = sample_header();
    let header = validate_envelope_header(&header_dto).unwrap();
    let signed_req = b"{\"commit\":true}";

    let digest1 = compute_commit_envelope_digest(&header, signed_req).unwrap();
    let digest2 = compute_commit_envelope_digest(&header, signed_req).unwrap();
    assert_eq!(digest1, digest2);

    let digest_other = compute_commit_envelope_digest(&header, b"{\"commit\":false}").unwrap();
    assert_ne!(digest1, digest_other);
}

#[test]
fn test_receipt_signing_and_verification() {
    let (signer, verifying_key) = test_signer("did:web:ds2.example.com");

    let delivery_id = Uuid::new_v4();
    let convo_id = Uuid::new_v4();
    let envelope_sha256 = [3u8; 32];
    let result_sha256 = [4u8; 32];
    let locator_dto = sample_locator();
    let locator = validate_entry_locator(&locator_dto).unwrap();
    let now = Utc::now();

    let receipt = sign_receipt(
        &signer,
        DELIVER_MESSAGE_NSID,
        delivery_id,
        convo_id,
        "did:web:ds1.example.com",
        "did:web:ds2.example.com",
        "did:web:ds1.example.com",
        1,
        envelope_sha256,
        result_sha256,
        Some(locator),
        now,
    )
    .expect("sign receipt");

    assert_eq!(receipt.protocol_version.as_str(), "1");
    assert_eq!(receipt.endpoint.as_str(), DELIVER_MESSAGE_NSID);

    let is_valid = verify_receipt(&receipt, &verifying_key).expect("verify receipt");
    assert!(is_valid, "freshly signed receipt must verify");

    // Negative: verify with wrong key fails
    let (_, wrong_key) = test_signer("did:web:wrong.example.com");
    let is_valid_wrong = verify_receipt(&receipt, &wrong_key).expect("verify with wrong key");
    assert!(!is_valid_wrong, "receipt must not verify with wrong key");

    // Negative: tampered receipt fails
    let mut tampered = receipt.clone();
    tampered.sequencer_term = 999;
    let is_valid_tampered = verify_receipt(&tampered, &verifying_key).expect("verify tampered");
    assert!(!is_valid_tampered, "tampered receipt must not verify");
}
