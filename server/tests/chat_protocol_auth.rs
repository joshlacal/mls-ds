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

mod repository {
    pub(crate) use crate::chat_protocol::repository::inventory;
}

mod chat_protocol {
    pub mod cursor {
        pub use crate::cursor::*;
    }

    pub mod model {
        pub use crate::model::*;
    }

    pub mod transcript {
        pub use crate::transcript::*;
    }

    pub mod validation {
        pub use crate::validation::*;
    }

    pub mod repository {
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

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::ecdsa::{signature::Signer, Signature as P256Signature, SigningKey};
use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use chat_protocol::dpop::{
    verify_enrollment_request_auth, verify_ordinary_request_auth, verify_rebind_request_auth,
    TrustedNestVerifier, MAX_TRUSTED_NEST_AUDIENCE_BYTES, MAX_TRUSTED_NEST_ISSUER_BYTES,
    MAX_TRUSTED_NEST_KEY_ID_BYTES,
};
use transcript::{
    build_verified_control_entry, decode_and_verify_control_entry,
    decode_and_verify_enrollment_body, decode_and_verify_signed_mutation,
    decode_canonical_signed_mutation, decode_control_fingerprint, decode_rebind_bootstrap,
    verify_signed_mutation, CanonicalControlServerFields, ControlEntryKind, SignedMutationKind,
    VerifiedMutationProjection,
};
use validation::{
    basic_credential_identity, ed25519_key_id, enrollment_grant_expiry,
    validate_first_execution_signed_at, BareDid, CanonicalHttpMethod, CanonicalTimestamp,
    CanonicalUuidV4, DpopAuthorization, KeyThumbprint, NumericDate, ProofJti, TrustedExternalBase,
    TrustedRequestInstant, ValidatedChatNsid,
};

const DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
const DEVICE_ID: &str = "3b241101-e2bb-4255-8caf-4136c566a962";
const CHAT_INSTANCE: &str = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
const TOKEN_JTI: &str = "8cb4f5d2-0d31-4b6f-a9c2-7e18f5403d61";
const AUTH_TXN: &str = "36e5e67b-98d1-4c47-96d5-44c09bc2b921";
const RETRY_TOKEN_JTI: &str = "44444444-4444-4444-8444-444444444444";
const RETRY_AUTH_TXN: &str = "55555555-5555-4555-8555-555555555555";
const KEY_ID: &str = "If4x36FUomFia_hUBG_SJxt77UtqvkWqWId-9H-XIbk";
const ISSUER: &str = "did:web:api.catbird.blue";
const AUDIENCE: &str = "did:web:chat.catbird.blue";

fn control_endpoint(kind: ControlEntryKind) -> &'static str {
    match kind {
        ControlEntryKind::Creation => "blue.catbird.chat.createConversation",
        ControlEntryKind::ParticipantAcceptance => "blue.catbird.chat.acceptConversation",
        ControlEntryKind::ConversationClose => "blue.catbird.chat.closeConversation",
        ControlEntryKind::ResetRequest => "blue.catbird.chat.requestReset",
        ControlEntryKind::ResetActivation => "blue.catbird.chat.activateReset",
        ControlEntryKind::LeaveRequest => "blue.catbird.chat.requestLeave",
        ControlEntryKind::LeaveCancellation => "blue.catbird.chat.cancelLeave",
        ControlEntryKind::Commit
        | ControlEntryKind::Policy
        | ControlEntryKind::Metadata
        | ControlEntryKind::LeafRecoveryFulfillment
        | ControlEntryKind::ZeroLeafLeave
        | ControlEntryKind::LeaveCommitFulfillment => "blue.catbird.chat.submitTransition",
    }
}

#[test]
fn trusted_nest_configuration_has_explicit_ascii_byte_bounds() {
    let accepts = |issuer: &str, audience: &str, key_id: &str| {
        TrustedNestVerifier::new(
            issuer,
            audience,
            CanonicalUuidV4::parse(CHAT_INSTANCE).unwrap(),
            key_id,
            signing_key(7).verifying_key().to_owned(),
            TrustedExternalBase::parse("https://chat.example.net", &BTreeSet::new()).unwrap(),
        )
        .is_ok()
    };

    assert!(accepts(
        &"i".repeat(MAX_TRUSTED_NEST_ISSUER_BYTES),
        &"a".repeat(MAX_TRUSTED_NEST_AUDIENCE_BYTES),
        &"k".repeat(MAX_TRUSTED_NEST_KEY_ID_BYTES),
    ));
    assert!(!accepts(
        &"i".repeat(MAX_TRUSTED_NEST_ISSUER_BYTES + 1),
        AUDIENCE,
        "nest-key-1",
    ));
    assert!(!accepts(
        ISSUER,
        &"a".repeat(MAX_TRUSTED_NEST_AUDIENCE_BYTES + 1),
        "nest-key-1",
    ));
    assert!(!accepts(
        ISSUER,
        AUDIENCE,
        &"k".repeat(MAX_TRUSTED_NEST_KEY_ID_BYTES + 1),
    ));
    assert!(!accepts(ISSUER, AUDIENCE, "nést-key"));
}

#[test]
fn closed_identifier_timestamp_and_numeric_date_grammars() {
    let max_host = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let max_did = format!("did:web:{max_host}");
    assert_eq!(max_did.len(), 261);

    for valid in [
        "did:web:a.co",
        DID,
        "did:web:alice.example.net",
        max_did.as_str(),
    ] {
        assert_eq!(BareDid::parse(valid).unwrap().as_str(), valid);
    }
    for invalid in [
        "did:web:a.c",
        "did:plc:EWVI7NXZYOUN6ZHXHRS64OIZ",
        "did:web:Chat.example.com",
        "did:web:alice.example.com:path",
        "did:web:alice.example.com:443",
        "did:web:alice%2eexample.com",
        "did:web:127.0.0.1",
        "did:web:localhost",
        "did:web:a.test",
        "did:key:z6Mkabc",
    ] {
        assert!(BareDid::parse(invalid).is_err(), "accepted {invalid}");
    }
    assert!(BareDid::parse(&format!("did:web:{max_host}x")).is_err());

    let device_id = CanonicalUuidV4::parse(DEVICE_ID).unwrap();
    assert_eq!(
        basic_credential_identity(&BareDid::parse("did:web:a.co").unwrap(), &device_id).len(),
        49
    );
    assert_eq!(
        basic_credential_identity(&BareDid::parse(&max_did).unwrap(), &device_id).len(),
        298
    );

    assert_eq!(
        CanonicalUuidV4::parse(CHAT_INSTANCE).unwrap().to_string(),
        CHAT_INSTANCE
    );
    for invalid in [
        "018F3F6A-7B2C-4D91-8A5E-0F123456789A",
        "018f3f6a7b2c4d918a5e0f123456789a",
        "018f3f6a-7b2c-3d91-8a5e-0f123456789a",
        "018f3f6a-7b2c-4d91-7a5e-0f123456789a",
    ] {
        assert!(CanonicalUuidV4::parse(invalid).is_err());
    }

    for valid in ["2026-07-22T14:05:09.123Z", "0001-01-01T00:00:00.000Z"] {
        assert_eq!(CanonicalTimestamp::parse(valid).unwrap().as_str(), valid);
    }
    for invalid in [
        "2026-07-22T14:05:09Z",
        "2026-07-22t14:05:09.123z",
        "2026-07-22T14:05:09.12Z",
        "2026-07-22T14:05:60.000Z",
        "2026-02-30T14:05:09.123Z",
        "2026-07-22T10:05:09.123-04:00",
    ] {
        assert!(CanonicalTimestamp::parse(invalid).is_err());
    }

    assert_eq!(NumericDate::new(0).unwrap().get(), 0);
    assert_eq!(
        NumericDate::new(9_007_199_254_740_991).unwrap().get(),
        9_007_199_254_740_991
    );
    assert!(NumericDate::new(-1).is_err());
    assert!(NumericDate::new(9_007_199_254_740_992).is_err());
    assert_eq!(
        enrollment_grant_expiry(
            NumericDate::new(1_700_000_290).unwrap(),
            NumericDate::new(1_700_000_000).unwrap()
        )
        .unwrap()
        .get(),
        1_700_000_300
    );
    assert_eq!(
        enrollment_grant_expiry(
            NumericDate::new(1_700_000_000).unwrap(),
            NumericDate::new(1_699_999_900).unwrap()
        )
        .unwrap()
        .get(),
        1_700_000_120
    );
    assert_eq!(
        enrollment_grant_expiry(
            NumericDate::new(1_700_000_180).unwrap(),
            NumericDate::new(1_700_000_000).unwrap()
        )
        .unwrap()
        .get(),
        1_700_000_300
    );
    assert!(enrollment_grant_expiry(
        NumericDate::new(9_007_199_254_740_900).unwrap(),
        NumericDate::new(1_700_000_000).unwrap()
    )
    .is_err());
}

#[test]
fn key_and_jti_values_are_canonical_base64url_with_exact_decoded_bounds() {
    assert_eq!(
        KeyThumbprint::parse(&"A".repeat(43)).unwrap().as_str(),
        "A".repeat(43)
    );
    assert!(KeyThumbprint::parse(&("A".repeat(43) + "=")).is_err());
    assert!(KeyThumbprint::parse(&"A".repeat(42)).is_err());
    assert!(KeyThumbprint::parse(&format!("{}+", "A".repeat(42))).is_err());
    assert!(KeyThumbprint::parse(&format!("{}B", "A".repeat(42))).is_err());
    let ed25519_public_key =
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
    assert_eq!(
        ed25519_key_id(&ed25519_public_key).unwrap().as_str(),
        KEY_ID
    );
    assert!(ed25519_key_id(&ed25519_public_key[..31]).is_err());

    let min = ProofJti::parse("AAAAAAAAAAAAAAAA").unwrap();
    assert_eq!(min.as_str(), "AAAAAAAAAAAAAAAA");
    assert_eq!(min.decoded().len(), 12);
    let max_text = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    let max = ProofJti::parse(&max_text).unwrap();
    assert_eq!(max.decoded().len(), 32);
    for invalid in [
        "short".to_string(),
        "AAAAAAAAAAAAAAAA=".to_string(),
        "AAAAAAAAAAAAAAA+".to_string(),
        "AAAAAAAAAAA".to_string(),
        URL_SAFE_NO_PAD.encode([0_u8; 33]),
    ] {
        assert!(ProofJti::parse(&invalid).is_err(), "accepted {invalid}");
    }
}

#[test]
fn one_captured_instant_drives_signed_time_boundaries() {
    let now = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse("2026-07-22T12:00:00.000Z").unwrap(),
    );
    for valid in [
        "2026-07-22T11:55:00.000Z",
        "2026-07-22T12:00:00.000Z",
        "2026-07-22T12:01:00.000Z",
    ] {
        validate_first_execution_signed_at(&CanonicalTimestamp::parse(valid).unwrap(), &now)
            .unwrap();
    }
    for invalid in ["2026-07-22T11:54:59.999Z", "2026-07-22T12:01:00.001Z"] {
        assert!(validate_first_execution_signed_at(
            &CanonicalTimestamp::parse(invalid).unwrap(),
            &now,
        )
        .is_err());
    }
    assert!(validate_first_execution_signed_at(
        &CanonicalTimestamp::parse("2020-01-01T00:00:00.000Z").unwrap(),
        &now,
    )
    .is_err());
}

#[test]
fn trusted_origin_and_endpoint_make_htu_without_request_authority_input() {
    let allowlisted = BTreeSet::from([8443_u16]);
    let default_port =
        TrustedExternalBase::parse("https://chat.example.net:443", &allowlisted).unwrap();
    let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.getEntries").unwrap();
    assert_eq!(default_port.as_str(), "https://chat.example.net");
    assert_eq!(
        default_port.htu(&endpoint),
        "https://chat.example.net/xrpc/blue.catbird.chat.getEntries"
    );

    let explicit =
        TrustedExternalBase::parse("https://chat.example.net:8443", &allowlisted).unwrap();
    assert_eq!(
        explicit.htu(&endpoint),
        "https://chat.example.net:8443/xrpc/blue.catbird.chat.getEntries"
    );
    for invalid in [
        "http://chat.example.net",
        "https://Chat.example.net",
        "https://chat.example.net.",
        "https://user@chat.example.net",
        "https://chat.example.net/path",
        "https://chat.example.net?x=1",
        "https://chat.example.net#fragment",
        "https://chat.example.net:9443",
        "https://chat.example.net:0443",
        "https://chat.example.net/",
        "https://café.example.net",
    ] {
        assert!(
            TrustedExternalBase::parse(invalid, &allowlisted).is_err(),
            "accepted {invalid}"
        );
    }
    assert!(ValidatedChatNsid::parse("blue.catbird.chat.notAnEndpoint").is_err());
    assert!(ValidatedChatNsid::parse("blue.catbird.mlsChat.getEntries").is_err());
    assert_eq!(CanonicalHttpMethod::parse("POST").unwrap().as_str(), "POST");
    assert!(CanonicalHttpMethod::parse("post").is_err());
    assert_eq!(
        DpopAuthorization::parse("DPoP abc.def.ghi")
            .unwrap()
            .token(),
        "abc.def.ghi"
    );
    assert!(DpopAuthorization::parse("Bearer abc.def.ghi").is_err());
}

#[test]
fn every_dpop_endpoint_owns_its_exact_http_method_profile() {
    for endpoint in [
        "blue.catbird.chat.getDevices",
        "blue.catbird.chat.getOwnDevices",
        "blue.catbird.chat.getConversations",
        "blue.catbird.chat.getConversationState",
        "blue.catbird.chat.getEntries",
        "blue.catbird.chat.getPendingWelcomes",
        "blue.catbird.chat.getLeafRecoveryInbox",
        "blue.catbird.chat.getBlob",
        "blue.catbird.chat.getBlobUsage",
    ] {
        assert_eq!(
            ValidatedChatNsid::parse(endpoint)
                .unwrap()
                .dpop_method()
                .unwrap()
                .as_str(),
            "GET"
        );
    }
    for endpoint in [
        "blue.catbird.chat.enrollDevice",
        "blue.catbird.chat.replenishKeyPackages",
        "blue.catbird.chat.rebindDeviceAuthentication",
        "blue.catbird.chat.revokeDevice",
        "blue.catbird.chat.createConversation",
        "blue.catbird.chat.acceptConversation",
        "blue.catbird.chat.closeConversation",
        "blue.catbird.chat.submitTransition",
        "blue.catbird.chat.sendMessage",
        "blue.catbird.chat.publishTyping",
        "blue.catbird.chat.acknowledgeWelcome",
        "blue.catbird.chat.rejectWelcome",
        "blue.catbird.chat.requestLeafRecovery",
        "blue.catbird.chat.cancelLeafRecovery",
        "blue.catbird.chat.requestReset",
        "blue.catbird.chat.activateReset",
        "blue.catbird.chat.requestLeave",
        "blue.catbird.chat.cancelLeave",
        "blue.catbird.chat.prepareBlobUpload",
        "blue.catbird.chat.uploadBlob",
        "blue.catbird.chat.deleteBlob",
        "blue.catbird.chat.getSubscriptionTicket",
    ] {
        assert_eq!(
            ValidatedChatNsid::parse(endpoint)
                .unwrap()
                .dpop_method()
                .unwrap()
                .as_str(),
            "POST"
        );
    }
    assert!(
        ValidatedChatNsid::parse("blue.catbird.chat.subscribeEvents")
            .unwrap()
            .dpop_method()
            .is_err()
    );
}

#[test]
fn closed_contract_decoder_matches_frozen_vector_and_rejects_raw_ambiguity() {
    let public_key =
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
    let signature = hex::decode("ad48db3b77336d8c383e86436ff13d3576d5942c2b623edf1525289a562886da8ffb68453536bb58457ebaf7c8ea71f9bbfd4e8b0da7e11ec7b8209c256ce009").unwrap();
    let wrapper = json!({
        "body": {
            "$type": "blue.catbird.chat.defs#blobDeletionBody",
            "signatureDomain": "CATBIRD-CHAT-BLOB-DELETE\u{0}",
            "blobId": CHAT_INSTANCE,
            "actorDid": DID,
            "actorDeviceId": DEVICE_ID,
            "keyId": KEY_ID,
            "authGeneration": 1,
            "idempotencyKey": TOKEN_JTI,
            "signedAt": "2026-07-22T14:05:09.123Z"
        },
        "signature": STANDARD.encode(&signature)
    });
    let raw = serde_json::to_vec(&wrapper).unwrap();
    let verified = decode_and_verify_signed_mutation(&raw, &public_key).unwrap();
    assert_eq!(verified.accepted_wrapper_bytes(), Some(raw.as_slice()));
    let exact_replay = decode_and_verify_signed_mutation(&raw, &public_key).unwrap();
    assert_eq!(
        exact_replay.accepted_wrapper_bytes(),
        verified.accepted_wrapper_bytes()
    );
    let whitespace_variant = serde_json::to_vec_pretty(&wrapper).unwrap();
    let whitespace_verified =
        decode_and_verify_signed_mutation(&whitespace_variant, &public_key).unwrap();
    assert_eq!(
        whitespace_verified.request_digest(),
        verified.request_digest()
    );
    assert_eq!(whitespace_verified.signature(), verified.signature());
    assert_eq!(
        whitespace_verified.accepted_wrapper_bytes(),
        Some(whitespace_variant.as_slice())
    );
    assert_ne!(
        whitespace_verified.accepted_wrapper_bytes(),
        verified.accepted_wrapper_bytes()
    );
    assert_eq!(verified.kind(), SignedMutationKind::BlobDeletion);
    assert_eq!(
        verified.type_id(),
        "blue.catbird.chat.defs#blobDeletionBody"
    );
    assert_eq!(verified.domain(), b"CATBIRD-CHAT-BLOB-DELETE\0");
    assert_eq!(
        hex::encode(verified.canonical_projection()),
        "a96524747970657827626c75652e636174626972642e636861742e6465667323626c6f6244656c6574696f6e426f6479656b65794964782b49663478333646556f6d4669615f685542475f534a78743737557471766b57715749642d39482d5849626b66626c6f62496450018f3f6a7b2c4d918a5e0f123456789a686163746f7244696478206469643a706c633a65777669376e787a796f756e367a687872687336346f697a687369676e656441747818323032362d30372d32325431343a30353a30392e3132335a6d6163746f724465766963654964503b241101e2bb42558caf4136c566a9626e6175746847656e65726174696f6e016e6964656d706f74656e63794b6579508cb4f5d20d314b6fa9c27e18f5403d616f7369676e6174757265446f6d61696e7819434154424952442d434841542d424c4f422d44454c45544500"
    );
    assert_eq!(
        hex::encode(verified.request_digest()),
        "9225776f6d0658e0aed1d7fe96e1299714c510e2c1b755fc8d31cda251588be4"
    );
    assert_eq!(verified.signature(), signature.as_slice());

    let zero_signature = STANDARD.encode([0_u8; 64]);
    let duplicate = format!(
        r#"{{"body":{{"$type":"blue.catbird.chat.defs#blobDeletionBody","signatureDomain":"CATBIRD-CHAT-BLOB-DELETE\u0000","blobId":"{CHAT_INSTANCE}","blobId":"{CHAT_INSTANCE}","actorDid":"{DID}","actorDeviceId":"{DEVICE_ID}","keyId":"{KEY_ID}","authGeneration":1,"idempotencyKey":"{TOKEN_JTI}","signedAt":"2026-07-22T14:05:09.123Z"}},"signature":"{zero_signature}"}}"#
    );
    assert!(decode_canonical_signed_mutation(duplicate.as_bytes()).is_err());

    for mutation in [
        ("unknown", json!(true)),
        ("blobId", Value::Null),
        ("blobId", json!("018f3f6a-7b2c-4d91-8a5e-0f123456789b")),
    ] {
        let mut changed = wrapper.clone();
        changed["body"][mutation.0] = mutation.1;
        assert!(decode_and_verify_signed_mutation(
            &serde_json::to_vec(&changed).unwrap(),
            &public_key
        )
        .is_err());
    }

    let mismatched_signer = Ed25519SigningKey::from_bytes(&[57_u8; 32]);
    let mismatched_key_id = sign_chat_body(wrapper["body"].clone(), &mismatched_signer);
    assert!(decode_and_verify_signed_mutation(
        &mismatched_key_id,
        mismatched_signer.verifying_key().as_bytes(),
    )
    .is_err());

    let enrollment_signing = Ed25519SigningKey::from_bytes(&[43_u8; 32]);
    let signed_enrollment = sign_chat_body(
        enrollment_body(KEY_ID, &enrollment_signing, &[1]),
        &enrollment_signing,
    );
    let negative_zero = String::from_utf8(signed_enrollment).unwrap().replace(
        "\"expectedAuthGeneration\":0",
        "\"expectedAuthGeneration\":-0",
    );
    assert!(negative_zero.contains("\"expectedAuthGeneration\":-0"));
    assert!(decode_canonical_signed_mutation(negative_zero.as_bytes()).is_err());
}

#[test]
fn all_frozen_signed_mutation_contracts_have_owned_type_and_domain() {
    let expected = [
        (
            SignedMutationKind::DeviceEnrollment,
            "deviceEnrollmentBody",
            "CATBIRD-CHAT-DEVICE-ENROLL\0",
        ),
        (
            SignedMutationKind::KeyPackageReplenishment,
            "keyPackageReplenishmentBody",
            "CATBIRD-CHAT-DEVICE-REPLENISH\0",
        ),
        (
            SignedMutationKind::DeviceAuthenticationRebind,
            "deviceAuthenticationRebindBody",
            "CATBIRD-CHAT-DEVICE-REBIND\0",
        ),
        (
            SignedMutationKind::DeviceRevocation,
            "deviceRevocationBody",
            "CATBIRD-CHAT-DEVICE-REVOKE\0",
        ),
        (
            SignedMutationKind::BlobUploadPreparation,
            "blobUploadPreparationBody",
            "CATBIRD-CHAT-BLOB-PREPARE\0",
        ),
        (
            SignedMutationKind::BlobDeletion,
            "blobDeletionBody",
            "CATBIRD-CHAT-BLOB-DELETE\0",
        ),
        (
            SignedMutationKind::Creation,
            "creationBody",
            "CATBIRD-CHAT-CREATE\0",
        ),
        (
            SignedMutationKind::CommitTransition,
            "commitTransitionBody",
            "CATBIRD-CHAT-COMMIT\0",
        ),
        (
            SignedMutationKind::PolicyTransition,
            "policyTransitionBody",
            "CATBIRD-CHAT-POLICY\0",
        ),
        (
            SignedMutationKind::ParticipantAcceptance,
            "participantAcceptanceBody",
            "CATBIRD-CHAT-ACCEPT\0",
        ),
        (
            SignedMutationKind::ApplicationSend,
            "applicationSendBody",
            "CATBIRD-CHAT-MESSAGE\0",
        ),
        (
            SignedMutationKind::Typing,
            "typingBody",
            "CATBIRD-CHAT-TYPING\0",
        ),
        (
            SignedMutationKind::MetadataTransition,
            "metadataTransitionBody",
            "CATBIRD-CHAT-METADATA\0",
        ),
        (
            SignedMutationKind::ResetRequest,
            "resetRequestBody",
            "CATBIRD-CHAT-RESET-REQUEST\0",
        ),
        (
            SignedMutationKind::ResetActivation,
            "resetActivationBody",
            "CATBIRD-CHAT-RESET-ACTIVATE\0",
        ),
        (
            SignedMutationKind::LeafRecoveryRequest,
            "leafRecoveryRequestBody",
            "CATBIRD-CHAT-LEAF-RECOVERY-REQUEST\0",
        ),
        (
            SignedMutationKind::LeafRecoveryCancellation,
            "leafRecoveryCancellationBody",
            "CATBIRD-CHAT-LEAF-RECOVERY-CANCEL\0",
        ),
        (
            SignedMutationKind::LeafRecoveryFulfillment,
            "leafRecoveryFulfillmentBody",
            "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\0",
        ),
        (
            SignedMutationKind::ConversationClose,
            "conversationCloseBody",
            "CATBIRD-CHAT-CLOSE\0",
        ),
        (
            SignedMutationKind::LeaveRequest,
            "leaveRequestBody",
            "CATBIRD-CHAT-LEAVE-REQUEST\0",
        ),
        (
            SignedMutationKind::ZeroLeafLeave,
            "zeroLeafLeaveBody",
            "CATBIRD-CHAT-LEAVE-ZERO-LEAF\0",
        ),
        (
            SignedMutationKind::LeaveCancellation,
            "leaveCancellationBody",
            "CATBIRD-CHAT-LEAVE-CANCEL\0",
        ),
        (
            SignedMutationKind::LeaveCommitFulfillment,
            "leaveCommitFulfillmentBody",
            "CATBIRD-CHAT-LEAVE-FULFILL-COMMIT\0",
        ),
        (
            SignedMutationKind::WelcomeAcknowledgement,
            "welcomeAcknowledgementBody",
            "CATBIRD-CHAT-WELCOME-ACK\0",
        ),
        (
            SignedMutationKind::WelcomeRejection,
            "welcomeRejectionBody",
            "CATBIRD-CHAT-WELCOME-REJECT\0",
        ),
    ];
    assert_eq!(SignedMutationKind::ALL.len(), expected.len());
    for (kind, body_name, domain) in expected {
        assert!(SignedMutationKind::ALL.contains(&kind));
        assert_eq!(
            kind.type_id(),
            format!("blue.catbird.chat.defs#{body_name}")
        );
        assert_eq!(kind.domain(), domain.as_bytes());
    }
}

#[test]
fn blob_upload_preparation_projection_requires_exact_media_metadata() {
    let body = json!({
        "$type": "blue.catbird.chat.defs#blobUploadPreparationBody",
        "signatureDomain": "CATBIRD-CHAT-BLOB-PREPARE\u{0000}",
        "blobId": CHAT_INSTANCE,
        "conversationId": CHAT_INSTANCE,
        "actorDid": DID,
        "actorDeviceId": DEVICE_ID,
        "keyId": KEY_ID,
        "authGeneration": 1,
        "prior": {
            "conversationId": CHAT_INSTANCE,
            "generation": 0,
            "stateVersion": 0,
            "groupId": STANDARD.encode([1_u8; 32]),
            "epoch": 0,
            "groupContextHash": STANDARD.encode([2_u8; 32]),
            "confirmationTag": STANDARD.encode([3_u8; 32]),
            "lifecycle": "active"
        },
        "ciphertextSha256": STANDARD.encode([4_u8; 32]),
        "ciphertextSize": 17,
        "mediaType": "image/png",
        "plaintextSize": 1,
        "purpose": "attachment",
        "idempotencyKey": TOKEN_JTI,
        "signedAt": "2026-07-22T14:05:09.123Z"
    });
    let wrapper = |body: Value| {
        json!({
            "body": body,
            "signature": STANDARD.encode([0_u8; 64])
        })
    };

    assert!(
        decode_canonical_signed_mutation(&serde_json::to_vec(&wrapper(body.clone())).unwrap())
            .is_ok()
    );
    for field in ["mediaType", "plaintextSize"] {
        let mut missing = body.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            decode_canonical_signed_mutation(&serde_json::to_vec(&wrapper(missing)).unwrap())
                .is_err(),
            "accepted missing required {field}"
        );
    }
}

#[test]
fn blob_prepare_projection_exposes_signed_prior_conversation_identity() {
    let signing = Ed25519SigningKey::from_bytes(&[61_u8; 32]);
    let key_id = ed25519_key_id(signing.verifying_key().as_bytes()).unwrap();
    let body = json!({
        "$type": "blue.catbird.chat.defs#blobUploadPreparationBody",
        "signatureDomain": "CATBIRD-CHAT-BLOB-PREPARE\u{0000}",
        "blobId": CHAT_INSTANCE,
        "conversationId": CHAT_INSTANCE,
        "actorDid": DID,
        "actorDeviceId": DEVICE_ID,
        "keyId": key_id.as_str(),
        "authGeneration": 1,
        "prior": {
            "conversationId": CHAT_INSTANCE,
            "generation": 0,
            "stateVersion": 0,
            "groupId": STANDARD.encode([1_u8; 32]),
            "epoch": 0,
            "groupContextHash": STANDARD.encode([2_u8; 32]),
            "confirmationTag": STANDARD.encode([3_u8; 32]),
            "lifecycle": "active"
        },
        "ciphertextSha256": STANDARD.encode([4_u8; 32]),
        "ciphertextSize": 17,
        "mediaType": "image/png",
        "plaintextSize": 1,
        "purpose": "attachment",
        "idempotencyKey": TOKEN_JTI,
        "signedAt": "2026-07-22T14:05:09.123Z"
    });
    let raw = sign_chat_body(body, &signing);
    let verified =
        decode_and_verify_signed_mutation(&raw, signing.verifying_key().as_bytes()).unwrap();

    match verified.projection() {
        VerifiedMutationProjection::BlobUploadPreparation(projection) => {
            assert_eq!(
                projection.conversation_id().as_str(),
                projection.prior_conversation_id().as_str()
            );
        }
        _ => panic!("expected blob preparation projection"),
    }
}

#[test]
fn canonical_participant_changes_reject_reversal_and_duplicates_instead_of_sorting() {
    let low = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    let high = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
    assert!(decode_canonical_signed_mutation(&unsigned_policy_request(&[low, high])).is_ok());
    assert!(decode_canonical_signed_mutation(&unsigned_policy_request(&[high, low])).is_err());
    assert!(decode_canonical_signed_mutation(&unsigned_policy_request(&[low, low])).is_err());
}

#[test]
fn canonical_leaf_changes_accept_remove_then_add_for_same_device_replace() {
    let device_id = "11111111-1111-4111-8111-111111111111";
    let leaf_changes = vec![
        remove_leaf(DID, device_id),
        add_leaf_by_recovery(DID, device_id),
    ];
    assert!(
        decode_canonical_signed_mutation(&unsigned_leaf_recovery_fulfillment_request(leaf_changes))
            .is_ok()
    );
}

#[test]
fn canonical_leaf_changes_reject_add_then_remove_for_same_device_replace() {
    let device_id = "11111111-1111-4111-8111-111111111111";
    let leaf_changes = vec![
        add_leaf_by_recovery(DID, device_id),
        remove_leaf(DID, device_id),
    ];
    assert!(
        decode_canonical_signed_mutation(&unsigned_leaf_recovery_fulfillment_request(leaf_changes))
            .is_err()
    );
}

#[test]
fn canonical_leaf_changes_reject_duplicate_remove_for_same_device() {
    let device_id = "11111111-1111-4111-8111-111111111111";
    let leaf_changes = vec![
        remove_leaf(DID, device_id),
        remove_leaf(DID, device_id),
        add_leaf_by_recovery(DID, device_id),
    ];
    assert!(
        decode_canonical_signed_mutation(&unsigned_leaf_recovery_fulfillment_request(leaf_changes))
            .is_err()
    );
}

#[test]
fn canonical_leaf_changes_reject_duplicate_add_for_same_device() {
    let device_id = "11111111-1111-4111-8111-111111111111";
    let leaf_changes = vec![
        remove_leaf(DID, device_id),
        add_leaf_by_recovery(DID, device_id),
        add_leaf_by_recovery(DID, device_id),
    ];
    assert!(
        decode_canonical_signed_mutation(&unsigned_leaf_recovery_fulfillment_request(leaf_changes))
            .is_err()
    );
}

#[test]
fn canonical_leaf_changes_preserve_cross_device_ordering() {
    let low = "11111111-1111-4111-8111-111111111111";
    let high = "22222222-2222-4222-8222-222222222222";
    assert!(decode_canonical_signed_mutation(&unsigned_commit_request(&[low, high])).is_ok());
    assert!(decode_canonical_signed_mutation(&unsigned_commit_request(&[high, low])).is_err());
}

#[test]
fn canonical_leaf_changes_order_by_did_before_uuid() {
    let low_did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    let high_did = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
    let low_device = "11111111-1111-4111-8111-111111111111";
    let high_device = "22222222-2222-4222-8222-222222222222";
    let ordered = vec![
        remove_leaf(low_did, high_device),
        remove_leaf(high_did, low_device),
    ];
    let reversed = vec![
        remove_leaf(high_did, low_device),
        remove_leaf(low_did, high_device),
    ];
    assert!(
        decode_canonical_signed_mutation(&unsigned_leaf_recovery_fulfillment_request(ordered))
            .is_ok()
    );
    assert!(
        decode_canonical_signed_mutation(&unsigned_leaf_recovery_fulfillment_request(reversed))
            .is_err()
    );
}

#[test]
fn all_thirteen_control_fingerprint_variants_are_closed_and_match_the_frozen_corpus() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/mls_chat_contract_vectors.json")).unwrap();
    let contract: Value = serde_json::from_str(include_str!(
        "../../lexicon/blue/catbird/chat/blue.catbird.chat.defs.json"
    ))
    .unwrap();
    let definitions = contract["defs"].as_object().unwrap();
    let cases = fixture["controlEntryFingerprints"]["cases"]
        .as_array()
        .unwrap();
    assert_eq!(cases.len(), 13);
    assert_eq!(ControlEntryKind::ALL.len(), 13);
    let mut corpus_issues = Vec::new();
    for case in cases {
        let projection = json!({
            "entryKind": case["entryKind"],
            "entryId": case["entryId"],
            "conversationId": case["conversationId"],
            "seq": case["seq"],
            "requestDigest": case["requestDigest"],
            "signature": case["signature"],
            "serverFields": case["serverFields"],
            "receivedAt": case["receivedAt"]
        });
        let decoded =
            decode_control_fingerprint(&serde_json::to_vec(&projection).unwrap()).unwrap();
        assert_eq!(
            hex::encode(decoded.canonical_projection()),
            case["canonicalDagCborHex"]
        );
        assert_eq!(
            hex::encode(decoded.fingerprint()),
            case["fingerprintSha256Hex"]
        );

        let body_cbor = hex::decode(
            case["unsignedSigningProjectionCanonicalDagCborHex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let body: FixtureDagValue = serde_ipld_dagcbor::from_slice(&body_cbor).unwrap();
        let signed_name = case["signedRequestRef"]
            .as_str()
            .unwrap()
            .strip_prefix("blue.catbird.chat.defs#")
            .unwrap();
        let body_name = definitions[signed_name]["properties"]["body"]["refs"][0]
            .as_str()
            .unwrap()
            .strip_prefix('#')
            .unwrap();
        let signing_body = body.into_json_for_schema(&definitions[body_name], definitions);
        let public_key_ref = case["historicalPublicKeyRef"].as_str().unwrap();
        let public_key = hex::decode(
            fixture["controlEntryFingerprints"]["historicalPublicKeys"][public_key_ref]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let entry_kind = case["entryKind"].as_str().unwrap();
        let issue_count = corpus_issues.len();
        collect_key_binding_issues(&signing_body, "body", entry_kind, &mut corpus_issues);
        let expected_signer_key_id = ed25519_key_id(&public_key).unwrap();
        if signing_body["keyId"].as_str() != Some(expected_signer_key_id.as_str()) {
            corpus_issues.push(format!(
                "{entry_kind}: body.keyId does not bind historicalPublicKeyRef {public_key_ref}"
            ));
        }
        if body_name == "creationBody" && signing_body["absence"].as_bool() != Some(true) {
            corpus_issues.push(format!(
                "{entry_kind}: body.absence is not the required constant true"
            ));
        }
        if corpus_issues.len() != issue_count {
            let mut repaired_for_schema_audit = signing_body.clone();
            repair_embedded_key_bindings_for_schema_audit(&mut repaired_for_schema_audit);
            if body_name == "creationBody" {
                repaired_for_schema_audit["absence"] = json!(true);
            }
            let repaired_wrapper = json!({
                "body": repaired_for_schema_audit,
                "signature": case["signature"],
            });
            if let Err(error) =
                decode_canonical_signed_mutation(&serde_json::to_vec(&repaired_wrapper).unwrap())
            {
                corpus_issues.push(format!(
                    "{entry_kind}: strict canonical decode still fails after repairing embedded key binding: {error:?}"
                ));
            }
            continue;
        }
        let signed_request = json!({
            "body": signing_body,
            "signature": case["signature"],
        });
        let verified_request = match decode_and_verify_signed_mutation(
            &serde_json::to_vec(&signed_request).unwrap(),
            &public_key,
        ) {
            Ok(value) => value,
            Err(error) => {
                corpus_issues.push(format!(
                    "{entry_kind}: strict signed decode failed: {error:?}"
                ));
                continue;
            }
        };
        assert_eq!(
            hex::encode(verified_request.canonical_projection()),
            case["unsignedSigningProjectionCanonicalDagCborHex"]
        );
        assert_eq!(
            STANDARD.encode(verified_request.request_digest()),
            case["requestDigest"]
        );

        let control_kind = ControlEntryKind::ALL
            .into_iter()
            .find(|kind| kind.type_id() == entry_kind)
            .unwrap();
        let server_fields = CanonicalControlServerFields::decode(
            control_kind,
            &serde_json::to_vec(&case["serverFields"]).unwrap(),
        )
        .unwrap();
        let received_at = TrustedRequestInstant::from_canonical_for_test(
            CanonicalTimestamp::parse(case["receivedAt"].as_str().unwrap()).unwrap(),
        );
        let built = build_verified_control_entry(
            verified_request,
            &ValidatedChatNsid::parse(control_endpoint(control_kind)).unwrap(),
            CanonicalUuidV4::parse(case["entryId"].as_str().unwrap()).unwrap(),
            CanonicalUuidV4::parse(case["conversationId"].as_str().unwrap()).unwrap(),
            case["seq"].as_u64().unwrap(),
            &received_at,
            server_fields,
        )
        .unwrap();
        assert_eq!(
            hex::encode(built.outer_control_fingerprint()),
            case["fingerprintSha256Hex"]
        );
        assert!(built.mutation().accepted_wrapper_bytes().is_some());

        let mut row = json!({
            "$type": case["entryKind"],
            "entryId": case["entryId"],
            "conversationId": case["conversationId"],
            "seq": case["seq"],
            "signedRequest": signed_request,
            "receivedAt": case["receivedAt"],
        });
        row.as_object_mut().unwrap().extend(
            case["serverFields"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(name, value)| (name.clone(), value.clone())),
        );
        let verified_row =
            decode_and_verify_control_entry(&serde_json::to_vec(&row).unwrap(), &public_key)
                .unwrap();
        assert_eq!(verified_row.kind().type_id(), case["entryKind"]);
        assert_eq!(
            hex::encode(verified_row.outer_control_fingerprint()),
            case["fingerprintSha256Hex"]
        );

        let mut unknown = projection.clone();
        unknown["unknown"] = json!(true);
        assert!(decode_control_fingerprint(&serde_json::to_vec(&unknown).unwrap()).is_err());
    }
    assert!(
        corpus_issues.is_empty(),
        "frozen corpus is not executable:\n{}",
        corpus_issues.join("\n")
    );
}

#[test]
fn verified_control_row_retains_exact_outer_identity_and_sealed_signed_projection() {
    let body_signing = Ed25519SigningKey::from_bytes(&[41_u8; 32]);
    let key_id = ed25519_key_id(body_signing.verifying_key().as_bytes()).unwrap();
    let signed_request: Value = serde_json::from_slice(&sign_chat_body(
        json!({
            "$type": "blue.catbird.chat.defs#leaveCancellationBody",
            "signatureDomain": "CATBIRD-CHAT-LEAVE-CANCEL\u{0}",
            "conversationId": CHAT_INSTANCE,
            "leaveRequestId": TOKEN_JTI,
            "actorDid": DID,
            "actorDeviceId": DEVICE_ID,
            "keyId": key_id.as_str(),
            "authGeneration": 1,
            "idempotencyKey": AUTH_TXN,
            "signedAt": "2026-07-22T14:05:09.123Z"
        }),
        &body_signing,
    ))
    .unwrap();
    let row = json!({
        "$type": "blue.catbird.chat.defs#leaveCancellationEntry",
        "entryId": "11111111-1111-4111-8111-111111111111",
        "conversationId": CHAT_INSTANCE,
        "seq": 7,
        "signedRequest": signed_request,
        "receivedAt": "2026-07-22T14:05:10.123Z"
    });

    let verified = decode_and_verify_control_entry(
        &serde_json::to_vec(&row).unwrap(),
        body_signing.verifying_key().as_bytes(),
    )
    .unwrap();
    assert_eq!(verified.kind(), ControlEntryKind::LeaveCancellation);
    assert_eq!(
        verified.entry_id().as_str(),
        "11111111-1111-4111-8111-111111111111"
    );
    assert_eq!(verified.conversation_id().as_str(), CHAT_INSTANCE);
    assert_eq!(verified.seq(), 7);
    assert_eq!(verified.received_at().as_str(), "2026-07-22T14:05:10.123Z");
    assert_eq!(verified.server_fields().canonical_dag_cbor(), [0xa0]);
    assert_ne!(verified.outer_control_fingerprint(), &[0_u8; 32]);
    assert_eq!(
        verified.mutation().kind(),
        SignedMutationKind::LeaveCancellation
    );
    assert_eq!(verified.mutation().actor_did().as_str(), DID);
    assert_eq!(verified.mutation().actor_device_id().as_str(), DEVICE_ID);
    assert_eq!(verified.mutation().key_id(), &key_id);
    assert_eq!(verified.mutation().auth_generation(), 1);
    assert_eq!(verified.mutation().accepted_wrapper_bytes(), None);
    assert_eq!(
        verified.mutation().signed_at().as_str(),
        "2026-07-22T14:05:09.123Z"
    );
    match verified.mutation().projection() {
        VerifiedMutationProjection::LeaveCancellation(projection) => {
            assert_eq!(projection.conversation_id().as_str(), CHAT_INSTANCE);
            assert_eq!(projection.leave_request_id().as_str(), TOKEN_JTI);
        }
        _ => panic!("wrong sealed mutation projection"),
    }

    let mut cross_conversation = row.clone();
    cross_conversation["conversationId"] = json!("22222222-2222-4222-8222-222222222222");
    assert!(decode_and_verify_control_entry(
        &serde_json::to_vec(&cross_conversation).unwrap(),
        body_signing.verifying_key().as_bytes(),
    )
    .is_err());

    let mut unknown = row;
    unknown["unknown"] = json!(true);
    assert!(decode_and_verify_control_entry(
        &serde_json::to_vec(&unknown).unwrap(),
        body_signing.verifying_key().as_bytes(),
    )
    .is_err());
}

#[test]
fn sealed_control_builder_rejects_endpoint_conversation_seq_and_server_field_mismatches() {
    let body_signing = Ed25519SigningKey::from_bytes(&[42_u8; 32]);
    let key_id = ed25519_key_id(body_signing.verifying_key().as_bytes()).unwrap();
    let signed_raw = sign_chat_body(
        json!({
            "$type": "blue.catbird.chat.defs#leaveCancellationBody",
            "signatureDomain": "CATBIRD-CHAT-LEAVE-CANCEL\u{0}",
            "conversationId": CHAT_INSTANCE,
            "leaveRequestId": TOKEN_JTI,
            "actorDid": DID,
            "actorDeviceId": DEVICE_ID,
            "keyId": key_id.as_str(),
            "authGeneration": 1,
            "idempotencyKey": AUTH_TXN,
            "signedAt": "2026-07-22T14:05:09.123Z"
        }),
        &body_signing,
    );
    let mutation = || {
        decode_and_verify_signed_mutation(&signed_raw, body_signing.verifying_key().as_bytes())
            .unwrap()
    };
    let entry_id = || CanonicalUuidV4::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let conversation_id = || CanonicalUuidV4::parse(CHAT_INSTANCE).unwrap();
    let received_at = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse("2026-07-22T14:05:10.123Z").unwrap(),
    );

    assert!(build_verified_control_entry(
        mutation(),
        &ValidatedChatNsid::parse("blue.catbird.chat.submitTransition").unwrap(),
        entry_id(),
        conversation_id(),
        7,
        &received_at,
        CanonicalControlServerFields::empty(ControlEntryKind::LeaveCancellation).unwrap(),
    )
    .is_err());
    assert!(build_verified_control_entry(
        mutation(),
        &ValidatedChatNsid::parse("blue.catbird.chat.cancelLeave").unwrap(),
        entry_id(),
        CanonicalUuidV4::parse("22222222-2222-4222-8222-222222222222").unwrap(),
        7,
        &received_at,
        CanonicalControlServerFields::empty(ControlEntryKind::LeaveCancellation).unwrap(),
    )
    .is_err());
    assert!(build_verified_control_entry(
        mutation(),
        &ValidatedChatNsid::parse("blue.catbird.chat.cancelLeave").unwrap(),
        entry_id(),
        conversation_id(),
        0,
        &received_at,
        CanonicalControlServerFields::empty(ControlEntryKind::LeaveCancellation).unwrap(),
    )
    .is_err());
    assert!(build_verified_control_entry(
        mutation(),
        &ValidatedChatNsid::parse("blue.catbird.chat.cancelLeave").unwrap(),
        entry_id(),
        conversation_id(),
        7,
        &received_at,
        CanonicalControlServerFields::empty(ControlEntryKind::Commit).unwrap(),
    )
    .is_err());

    assert!(CanonicalControlServerFields::empty(ControlEntryKind::ParticipantAcceptance).is_err());
    assert!(CanonicalControlServerFields::empty(ControlEntryKind::ConversationClose).is_err());
    assert!(CanonicalControlServerFields::decode(
        ControlEntryKind::LeaveCancellation,
        br#"{"unexpected":true}"#,
    )
    .is_err());
    assert!(CanonicalControlServerFields::decode(
        ControlEntryKind::ParticipantAcceptance,
        br#"{}"#,
    )
    .is_err());
}

#[test]
fn ordinary_nest_token_and_dpop_proof_verify_as_one_bound_request() {
    let nest_signing = signing_key(7);
    let proof_signing = signing_key(9);
    let allowlisted = BTreeSet::new();
    let origin = TrustedExternalBase::parse("https://chat.example.net", &allowlisted).unwrap();
    let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.getEntries").unwrap();
    let method = CanonicalHttpMethod::parse("GET").unwrap();
    let now = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse("2023-11-14T22:14:20.000Z").unwrap(),
    );
    let proof_jwk = public_jwk(&proof_signing);
    let proof_jkt = jwk_thumbprint(&proof_jwk);
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
            "cnf": {"jkt": proof_jkt},
            "device_id": DEVICE_ID,
            "chat_instance": CHAT_INSTANCE
        }),
        &nest_signing,
    );
    let htu = origin.htu(&endpoint);
    let proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &htu,
        &token,
        1_700_000_060,
        &[1; 12],
    );
    let trust = TrustedNestVerifier::new(
        ISSUER,
        AUDIENCE,
        CanonicalUuidV4::parse(CHAT_INSTANCE).unwrap(),
        "nest-key-1",
        nest_signing.verifying_key().to_owned(),
        origin,
    )
    .unwrap();
    let verified = verify_ordinary_request_auth(
        &trust,
        &format!("DPoP {token}"),
        &proof,
        &endpoint,
        &method,
        &now,
    )
    .unwrap();

    assert_eq!(verified.subject().as_str(), DID);
    assert_eq!(verified.device_id().as_str(), DEVICE_ID);
    assert_eq!(verified.dpop_jkt().as_str(), proof_jkt);
    assert_eq!(verified.token_replay().issuer(), ISSUER);
    assert_eq!(verified.token_replay().jti().as_str(), TOKEN_JTI);
    assert_eq!(verified.proof_replay().jkt().as_str(), proof_jkt);
    assert_eq!(verified.proof_replay().jti_bytes(), &[1; 12]);
    assert!(verified.auth_transaction_replay().is_none());
    assert_eq!(
        verified.token_sha256(),
        &Sha256::digest(token.as_bytes())[..]
    );
    assert_eq!(
        verified.proof_sha256(),
        &Sha256::digest(proof.as_bytes())[..]
    );
    assert_eq!(verified.endpoint().as_str(), "blue.catbird.chat.getEntries");
    assert_eq!(verified.method().as_str(), "GET");
    assert_eq!(verified.htu(), htu);
    assert_eq!(verified.chat_instance().as_str(), CHAT_INSTANCE);
    assert_eq!(verified.token_iat().get(), 1_700_000_000);
    assert_eq!(verified.token_exp().get(), 1_700_000_120);
    assert_eq!(verified.proof_iat().get(), 1_700_000_060);
    assert_eq!(verified.trusted_instant().as_str(), now.as_str());
    assert!(verified.requires_atomic_replay_consumption());

    let repeated = verify_ordinary_request_auth(
        &trust,
        &format!("DPoP {token}"),
        &proof,
        &endpoint,
        &method,
        &now,
    )
    .unwrap();
    assert_eq!(repeated.token_replay().jti(), verified.token_replay().jti());
    assert_eq!(
        repeated.proof_replay().jti_bytes(),
        verified.proof_replay().jti_bytes()
    );
    assert!(repeated.requires_atomic_replay_consumption());

    assert!(verify_ordinary_request_auth(
        &trust,
        &format!("Bearer {token}"),
        &proof,
        &endpoint,
        &method,
        &now,
    )
    .is_err());
    let (proof_without_signature, _) = proof.rsplit_once('.').unwrap();
    let oversized_signature_proof = format!("{proof_without_signature}.{}", "A".repeat(87));
    assert!(verify_ordinary_request_auth(
        &trust,
        &format!("DPoP {token}"),
        &oversized_signature_proof,
        &endpoint,
        &method,
        &now,
    )
    .is_err());
    let wrong_method = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "POST",
        &htu,
        &token,
        1_700_000_060,
        &[2; 12],
    );
    assert!(verify_ordinary_request_auth(
        &trust,
        &format!("DPoP {token}"),
        &wrong_method,
        &endpoint,
        &method,
        &now,
    )
    .is_err());
    assert!(verify_ordinary_request_auth(
        &trust,
        &format!("DPoP {token}"),
        &wrong_method,
        &endpoint,
        &CanonicalHttpMethod::parse("POST").unwrap(),
        &now,
    )
    .is_err());
    let wrong_ath = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &htu,
        "different-token",
        1_700_000_060,
        &[3; 12],
    );
    assert!(verify_ordinary_request_auth(
        &trust,
        &format!("DPoP {token}"),
        &wrong_ath,
        &endpoint,
        &method,
        &now,
    )
    .is_err());

    let base_claims = decode_payload(&token);
    for (field, replacement) in [
        ("iss", json!("did:web:other.example.net")),
        ("aud", json!("did:web:other.example.net")),
        ("lxm", json!("blue.catbird.chat.getBlob")),
        (
            "chat_instance",
            json!("11111111-1111-4111-9111-111111111111"),
        ),
        ("device_id", json!("not-a-device")),
        ("jti", json!("not-a-token-jti")),
        ("exp", json!(1_700_000_121_i64)),
    ] {
        let mut claims = base_claims.clone();
        claims
            .as_object_mut()
            .unwrap()
            .insert(field.to_owned(), replacement);
        let changed_token = sign_jwt(
            json!({"alg":"ES256","typ":"JWT","kid":"nest-key-1"}),
            claims,
            &nest_signing,
        );
        let changed_proof = dpop_proof(
            &proof_signing,
            &proof_jwk,
            "GET",
            &htu,
            &changed_token,
            1_700_000_060,
            &[4; 12],
        );
        assert!(
            verify_ordinary_request_auth(
                &trust,
                &format!("DPoP {changed_token}"),
                &changed_proof,
                &endpoint,
                &method,
                &now,
            )
            .is_err(),
            "accepted changed {field}"
        );
    }

    let mut enrollment_shaped_claims = base_claims.clone();
    enrollment_shaped_claims.as_object_mut().unwrap().extend([
        ("key_id".to_owned(), json!(KEY_ID)),
        (
            "signing_key_sha256".to_owned(),
            json!(URL_SAFE_NO_PAD.encode([1_u8; 32])),
        ),
        (
            "enrollment_transcript_sha256".to_owned(),
            json!(URL_SAFE_NO_PAD.encode([2_u8; 32])),
        ),
        ("auth_time".to_owned(), json!(1_700_000_000_i64)),
        ("auth_txn".to_owned(), json!(AUTH_TXN)),
    ]);
    let enrollment_shaped_token = sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":"nest-key-1"}),
        enrollment_shaped_claims,
        &nest_signing,
    );
    let enrollment_shaped_proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &htu,
        &enrollment_shaped_token,
        1_700_000_060,
        &[5; 12],
    );
    assert!(verify_ordinary_request_auth(
        &trust,
        &format!("DPoP {enrollment_shaped_token}"),
        &enrollment_shaped_proof,
        &endpoint,
        &method,
        &now,
    )
    .is_err());

    let wrong_htu = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        "https://evil.example.net/xrpc/blue.catbird.chat.getEntries",
        &token,
        1_700_000_060,
        &[7; 12],
    );
    assert!(verify_ordinary_request_auth(
        &trust,
        &format!("DPoP {token}"),
        &wrong_htu,
        &endpoint,
        &method,
        &now,
    )
    .is_err());
    let stale_proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &htu,
        &token,
        1_699_999_999,
        &[8; 12],
    );
    assert!(verify_ordinary_request_auth(
        &trust,
        &format!("DPoP {token}"),
        &stale_proof,
        &endpoint,
        &method,
        &now,
    )
    .is_err());
    let short_jti = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "GET",
        &htu,
        &token,
        1_700_000_060,
        &[9; 11],
    );
    assert!(verify_ordinary_request_auth(
        &trust,
        &format!("DPoP {token}"),
        &short_jti,
        &endpoint,
        &method,
        &now,
    )
    .is_err());

    let mut extra_jwk = proof_jwk.clone();
    extra_jwk["kid"] = json!("forbidden-metadata");
    let extra_jwk_proof = dpop_proof(
        &proof_signing,
        &extra_jwk,
        "GET",
        &htu,
        &token,
        1_700_000_060,
        &[10; 12],
    );
    assert!(verify_ordinary_request_auth(
        &trust,
        &format!("DPoP {token}"),
        &extra_jwk_proof,
        &endpoint,
        &method,
        &now,
    )
    .is_err());

    let other_proof_key = signing_key(11);
    let other_jwk = public_jwk(&other_proof_key);
    let ath_alone = dpop_proof(
        &other_proof_key,
        &other_jwk,
        "GET",
        &htu,
        &token,
        1_700_000_060,
        &[11; 12],
    );
    assert!(verify_ordinary_request_auth(
        &trust,
        &format!("DPoP {token}"),
        &ath_alone,
        &endpoint,
        &method,
        &now,
    )
    .is_err());

    let duplicate_jti_payload = format!(
        "{{\"htm\":\"GET\",\"htu\":\"{htu}\",\"ath\":\"{}\",\"iat\":1700000060,\"jti\":\"{}\",\"jti\":\"{}\"}}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())),
        URL_SAFE_NO_PAD.encode([12_u8; 12]),
        URL_SAFE_NO_PAD.encode([13_u8; 12]),
    );
    let duplicate_jti_proof = sign_jwt_raw_payload(
        json!({"typ":"dpop+jwt","alg":"ES256","jwk":proof_jwk}),
        &duplicate_jti_payload,
        &proof_signing,
    );
    assert!(verify_ordinary_request_auth(
        &trust,
        &format!("DPoP {token}"),
        &duplicate_jti_proof,
        &endpoint,
        &method,
        &now,
    )
    .is_err());

    let subscription_endpoint =
        ValidatedChatNsid::parse("blue.catbird.chat.subscribeEvents").unwrap();
    assert!(verify_ordinary_request_auth(
        &trust,
        &format!("DPoP {token}"),
        &proof,
        &subscription_endpoint,
        &method,
        &now,
    )
    .is_err());

    for special in [
        "blue.catbird.chat.enrollDevice",
        "blue.catbird.chat.rebindDeviceAuthentication",
    ] {
        assert!(verify_ordinary_request_auth(
            &trust,
            &format!("DPoP {token}"),
            &proof,
            &ValidatedChatNsid::parse(special).unwrap(),
            &method,
            &now,
        )
        .is_err());
    }
}

#[test]
fn enrollment_grant_has_exact_claims_formula_bindings_and_third_replay_identity() {
    let nest_signing = signing_key(17);
    let proof_signing = signing_key(19);
    let body_signing = Ed25519SigningKey::from_bytes(&[23_u8; 32]);
    let origin = TrustedExternalBase::parse("https://chat.example.net", &BTreeSet::new()).unwrap();
    let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.enrollDevice").unwrap();
    let now = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse("2023-11-14T22:18:15.000Z").unwrap(),
    );
    let proof_jwk = public_jwk(&proof_signing);
    let proof_jkt = jwk_thumbprint(&proof_jwk);
    let enrollment_raw = sign_chat_body(
        enrollment_body(&proof_jkt, &body_signing, &[1_u8, 2_u8]),
        &body_signing,
    );
    let body = decode_and_verify_enrollment_body(&enrollment_raw).unwrap();
    let signing_key_hash = *body.signing_key_sha256();
    let transcript_hash = *body.enrollment_transcript_sha256();
    let body_key_id = body.key_id().as_str().to_owned();
    let token = sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":"nest-key-1"}),
        json!({
            "iss": ISSUER,
            "sub": DID,
            "aud": AUDIENCE,
            "lxm": endpoint.as_str(),
            "iat": 1_700_000_290_i64,
            "exp": 1_700_000_300_i64,
            "jti": TOKEN_JTI,
            "cnf": {"jkt": proof_jkt},
            "device_id": DEVICE_ID,
            "chat_instance": CHAT_INSTANCE,
            "key_id": body_key_id,
            "signing_key_sha256": URL_SAFE_NO_PAD.encode(signing_key_hash),
            "enrollment_transcript_sha256": URL_SAFE_NO_PAD.encode(transcript_hash),
            "auth_time": 1_700_000_000_i64,
            "auth_txn": AUTH_TXN
        }),
        &nest_signing,
    );
    let proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "POST",
        &origin.htu(&endpoint),
        &token,
        1_700_000_295,
        &[5; 12],
    );
    let trust = TrustedNestVerifier::new(
        ISSUER,
        AUDIENCE,
        CanonicalUuidV4::parse(CHAT_INSTANCE).unwrap(),
        "nest-key-1",
        nest_signing.verifying_key().to_owned(),
        origin,
    )
    .unwrap();
    let verified =
        verify_enrollment_request_auth(&trust, &format!("DPoP {token}"), &proof, body, &now)
            .unwrap();
    verified
        .validate_enrollment_first_execution_signed_at()
        .unwrap();
    let auth_txn = verified.auth_transaction_replay().unwrap();
    assert_eq!(auth_txn.issuer(), ISSUER);
    assert_eq!(auth_txn.auth_txn().as_str(), AUTH_TXN);
    assert_eq!(verified.auth_time().unwrap().get(), 1_700_000_000);
    let enrollment = verified.enrollment().unwrap();
    let carried_body = verified.enrollment_body().unwrap();
    assert_eq!(carried_body.idempotency_key().as_str(), CHAT_INSTANCE);
    assert_eq!(carried_body.accepted_wrapper_bytes(), enrollment_raw);
    assert!(matches!(
        carried_body.mutation().projection(),
        VerifiedMutationProjection::DeviceEnrollment(_)
    ));
    assert_eq!(enrollment.key_id(), carried_body.key_id());
    assert_eq!(enrollment.signing_key_sha256(), &signing_key_hash);
    assert_eq!(enrollment.enrollment_transcript_sha256(), &transcript_hash);
    assert_eq!(carried_body.request_digest(), &transcript_hash);

    let mut claims = decode_payload(&token);
    claims
        .as_object_mut()
        .unwrap()
        .insert("unknown".into(), json!(true));
    let extra_claim_token = sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":"nest-key-1"}),
        claims,
        &nest_signing,
    );
    let extra_proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "POST",
        &trust.external_base().htu(&endpoint),
        &extra_claim_token,
        1_700_000_295,
        &[6; 12],
    );
    assert!(verify_enrollment_request_auth(
        &trust,
        &format!("DPoP {extra_claim_token}"),
        &extra_proof,
        decode_and_verify_enrollment_body(&enrollment_raw).unwrap(),
        &now,
    )
    .is_err());

    let mut bad_signature: Value = serde_json::from_slice(&enrollment_raw).unwrap();
    bad_signature["signature"] = json!(STANDARD.encode([0_u8; 64]));
    assert!(
        decode_and_verify_enrollment_body(&serde_json::to_vec(&bad_signature).unwrap()).is_err()
    );

    let reversed = sign_chat_body(
        enrollment_body(&proof_jkt, &body_signing, &[2_u8, 1_u8]),
        &body_signing,
    );
    assert!(decode_and_verify_enrollment_body(&reversed).is_err());
    let duplicate = sign_chat_body(
        enrollment_body(&proof_jkt, &body_signing, &[1_u8, 1_u8]),
        &body_signing,
    );
    assert!(decode_and_verify_enrollment_body(&duplicate).is_err());

    let mut overlong_utf8_name = enrollment_body(&proof_jkt, &body_signing, &[1_u8]);
    overlong_utf8_name["deviceName"] = json!("é".repeat(65));
    let overlong_utf8_name = sign_chat_body(overlong_utf8_name, &body_signing);
    assert!(decode_and_verify_enrollment_body(&overlong_utf8_name).is_err());

    let mut stale_exact_json = enrollment_body(&proof_jkt, &body_signing, &[1_u8, 2_u8]);
    stale_exact_json["signedAt"] = json!("2023-11-14T22:13:15.000Z");
    let stale_exact_raw = sign_chat_body(stale_exact_json, &body_signing);
    let stale_exact_body = decode_and_verify_enrollment_body(&stale_exact_raw).unwrap();
    validate_first_execution_signed_at(stale_exact_body.signed_at(), &now).unwrap();
    let stale_exact_token = sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":"nest-key-1"}),
        json!({
            "iss": ISSUER,
            "sub": DID,
            "aud": AUDIENCE,
            "lxm": endpoint.as_str(),
            "iat": 1_700_000_290_i64,
            "exp": 1_700_000_300_i64,
            "jti": RETRY_TOKEN_JTI,
            "cnf": {"jkt": proof_jkt},
            "device_id": DEVICE_ID,
            "chat_instance": CHAT_INSTANCE,
            "key_id": stale_exact_body.key_id().as_str(),
            "signing_key_sha256": URL_SAFE_NO_PAD.encode(stale_exact_body.signing_key_sha256()),
            "enrollment_transcript_sha256": URL_SAFE_NO_PAD.encode(stale_exact_body.enrollment_transcript_sha256()),
            "auth_time": 1_700_000_000_i64,
            "auth_txn": RETRY_AUTH_TXN
        }),
        &nest_signing,
    );
    let stale_exact_proof = dpop_proof(
        &proof_signing,
        &proof_jwk,
        "POST",
        &trust.external_base().htu(&endpoint),
        &stale_exact_token,
        1_700_000_296,
        &[7; 12],
    );
    let retry_instant = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse("2023-11-14T22:18:16.000Z").unwrap(),
    );
    let stale_exact_pre_replay = verify_enrollment_request_auth(
        &trust,
        &format!("DPoP {stale_exact_token}"),
        &stale_exact_proof,
        stale_exact_body,
        &retry_instant,
    )
    .unwrap();
    assert_eq!(
        stale_exact_pre_replay.token_replay().jti().as_str(),
        RETRY_TOKEN_JTI
    );
    assert_eq!(
        stale_exact_pre_replay
            .auth_transaction_replay()
            .unwrap()
            .auth_txn()
            .as_str(),
        RETRY_AUTH_TXN
    );
    assert_ne!(
        stale_exact_pre_replay.token_replay().jti(),
        verified.token_replay().jti()
    );
    assert_ne!(
        stale_exact_pre_replay.proof_replay().jti_bytes(),
        verified.proof_replay().jti_bytes()
    );
    assert!(stale_exact_pre_replay
        .validate_enrollment_first_execution_signed_at()
        .is_err());
}

#[test]
fn maximum_key_package_batch_is_not_rejected_by_a_smaller_global_json_cap() {
    let signing = Ed25519SigningKey::from_bytes(&[47_u8; 32]);
    let package_refs: Vec<u8> = (0_u8..100).collect();
    let mut body = enrollment_body(KEY_ID, &signing, &package_refs);
    for (index, package) in body["keyPackages"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .enumerate()
    {
        let bytes = vec![index as u8; 65_536];
        package["bytes"] = json!(STANDARD.encode(&bytes));
        package["sha256"] = json!(STANDARD.encode(Sha256::digest(&bytes)));
    }
    let raw = sign_chat_body(body, &signing);
    assert!(raw.len() > 8 * 1024 * 1024);
    assert!(raw.len() < 16 * 1024 * 1024);
    decode_and_verify_enrollment_body(&raw).unwrap();
}

#[test]
fn rebind_bootstrap_uses_signed_new_jkt_but_remains_pre_repository_authority() {
    let nest_signing = signing_key(27);
    let current_proof_signing = signing_key(29);
    let new_proof_signing = signing_key(31);
    let body_signing = Ed25519SigningKey::from_bytes(&[33_u8; 32]);
    let current_jwk = public_jwk(&current_proof_signing);
    let current_jkt = jwk_thumbprint(&current_jwk);
    let new_jwk = public_jwk(&new_proof_signing);
    let new_jkt = jwk_thumbprint(&new_jwk);
    let raw = sign_chat_body(
        rebind_body(&current_jkt, &new_jkt, &body_signing),
        &body_signing,
    );
    let bootstrap = decode_rebind_bootstrap(&raw).unwrap();
    assert_eq!(bootstrap.new_dpop_jkt().as_str(), new_jkt);
    assert_eq!(bootstrap.current_dpop_jkt().as_str(), current_jkt);
    assert_eq!(bootstrap.expected_auth_generation(), 1);
    assert_eq!(bootstrap.idempotency_key().as_str(), CHAT_INSTANCE);
    assert_eq!(bootstrap.accepted_wrapper_bytes(), raw);

    let verified_body = verify_signed_mutation(
        decode_canonical_signed_mutation(&raw).unwrap(),
        body_signing.verifying_key().as_bytes(),
    )
    .unwrap();
    assert_eq!(
        verified_body.kind(),
        SignedMutationKind::DeviceAuthenticationRebind
    );

    let origin = TrustedExternalBase::parse("https://chat.example.net", &BTreeSet::new()).unwrap();
    let endpoint =
        ValidatedChatNsid::parse("blue.catbird.chat.rebindDeviceAuthentication").unwrap();
    let now = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse("2023-11-14T22:14:20.000Z").unwrap(),
    );
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
            "cnf": {"jkt": new_jkt},
            "device_id": DEVICE_ID,
            "chat_instance": CHAT_INSTANCE
        }),
        &nest_signing,
    );
    let proof = dpop_proof(
        &new_proof_signing,
        &new_jwk,
        "POST",
        &origin.htu(&endpoint),
        &token,
        1_700_000_060,
        &[17; 12],
    );
    let trust = TrustedNestVerifier::new(
        ISSUER,
        AUDIENCE,
        CanonicalUuidV4::parse(CHAT_INSTANCE).unwrap(),
        "nest-key-1",
        nest_signing.verifying_key().to_owned(),
        origin,
    )
    .unwrap();
    let pre_replay =
        verify_rebind_request_auth(&trust, &format!("DPoP {token}"), &proof, bootstrap, &now)
            .unwrap();
    assert_eq!(pre_replay.dpop_jkt().as_str(), new_jkt);
    assert!(pre_replay.requires_atomic_replay_consumption());
    assert_eq!(pre_replay.trusted_instant().as_str(), now.as_str());
    let carried_bootstrap = pre_replay.rebind_bootstrap().unwrap();
    assert_eq!(carried_bootstrap.current_dpop_jkt().as_str(), current_jkt);
    assert_eq!(carried_bootstrap.new_dpop_jkt().as_str(), new_jkt);
    assert_eq!(carried_bootstrap.expected_auth_generation(), 1);
    assert_eq!(
        carried_bootstrap.request_digest(),
        verified_body.request_digest()
    );
    assert_eq!(carried_bootstrap.signature(), verified_body.signature());
    pre_replay
        .validate_rebind_first_execution_signed_at()
        .unwrap();
    pre_replay
        .verify_rebind_stored_signing_key(body_signing.verifying_key().as_bytes())
        .unwrap();

    let wrong_token = sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":"nest-key-1"}),
        json!({
            "iss": ISSUER,
            "sub": DID,
            "aud": AUDIENCE,
            "lxm": endpoint.as_str(),
            "iat": 1_700_000_000_i64,
            "exp": 1_700_000_120_i64,
            "jti": AUTH_TXN,
            "cnf": {"jkt": current_jkt},
            "device_id": DEVICE_ID,
            "chat_instance": CHAT_INSTANCE
        }),
        &nest_signing,
    );
    let wrong_proof = dpop_proof(
        &current_proof_signing,
        &current_jwk,
        "POST",
        &trust.external_base().htu(&endpoint),
        &wrong_token,
        1_700_000_060,
        &[18; 12],
    );
    assert!(verify_rebind_request_auth(
        &trust,
        &format!("DPoP {wrong_token}"),
        &wrong_proof,
        decode_rebind_bootstrap(&raw).unwrap(),
        &now,
    )
    .is_err());

    let mut stale_body = rebind_body(&current_jkt, &new_jkt, &body_signing);
    stale_body["signedAt"] = json!("2020-01-01T00:00:00.000Z");
    let stale_raw = sign_chat_body(stale_body, &body_signing);
    let stale_pre_replay = verify_rebind_request_auth(
        &trust,
        &format!("DPoP {token}"),
        &proof,
        decode_rebind_bootstrap(&stale_raw).unwrap(),
        &now,
    )
    .unwrap();
    assert!(stale_pre_replay
        .validate_rebind_first_execution_signed_at()
        .is_err());
    assert_ne!(
        stale_pre_replay
            .rebind_bootstrap()
            .unwrap()
            .request_digest(),
        pre_replay.rebind_bootstrap().unwrap().request_digest()
    );
}

fn unsigned_policy_request(participant_dids: &[&str]) -> Vec<u8> {
    let changes: Vec<_> = participant_dids
        .iter()
        .map(|did| {
            json!({
                "$type": "blue.catbird.chat.defs#removeParticipant",
                "userDid": did,
            })
        })
        .collect();
    serde_json::to_vec(&json!({
        "body": {
            "$type": "blue.catbird.chat.defs#policyTransitionBody",
            "signatureDomain": "CATBIRD-CHAT-POLICY\u{0}",
            "transitionId": TOKEN_JTI,
            "actorDid": DID,
            "actorDeviceId": DEVICE_ID,
            "keyId": KEY_ID,
            "authGeneration": 1,
            "prior": coordinates(0),
            "next": coordinates(1),
            "participantChanges": changes,
            "idempotencyKey": CHAT_INSTANCE,
            "signedAt": "2026-07-22T14:05:09.123Z"
        },
        "signature": STANDARD.encode([0_u8; 64])
    }))
    .unwrap()
}

fn unsigned_commit_request(device_ids: &[&str]) -> Vec<u8> {
    let leaf_changes: Vec<_> = device_ids
        .iter()
        .map(|device_id| {
            json!({
                "$type": "blue.catbird.chat.defs#removeLeaf",
                "userDid": DID,
                "deviceId": device_id,
            })
        })
        .collect();
    let commit_bytes = [0x31_u8; 8];
    let ciphertext = [0x32_u8; 16];
    let transition_id_bytes = uuid::Uuid::parse_str(TOKEN_JTI).unwrap();
    let conversation_id_bytes = uuid::Uuid::parse_str(CHAT_INSTANCE).unwrap();
    let prior_mls = json!({
        "conversationId": STANDARD.encode(conversation_id_bytes.as_bytes()),
        "generation": 0,
        "stateVersion": 0,
        "groupId": STANDARD.encode([0x21_u8; 32]),
        "epoch": 0,
        "groupContextHash": STANDARD.encode([0x22_u8; 32]),
        "confirmationTag": STANDARD.encode([0x23_u8; 32]),
        "lifecycle": "active"
    });
    let metadata_snapshot = json!({
        "coordinate": {
            "conversationId": STANDARD.encode(conversation_id_bytes.as_bytes()),
            "generation": 0,
            "groupId": STANDARD.encode([0x21_u8; 32]),
            "epoch": 1,
            "groupContextHash": STANDARD.encode([0x24_u8; 32]),
            "confirmationTag": STANDARD.encode([0x25_u8; 32])
        },
        "originTransitionId": TOKEN_JTI,
        "metadataVersion": 1,
        "nonce": STANDARD.encode([0x26_u8; 12]),
        "ciphertext": STANDARD.encode(ciphertext),
        "ciphertextSha256": STANDARD.encode(Sha256::digest(ciphertext)),
        "ciphertextSize": 16,
        "authorProof": {
            "authorDid": DID,
            "authorDeviceId": DEVICE_ID,
            "authorKeyId": KEY_ID,
            "signaturePublicKey": STANDARD.encode([0x27_u8; 32]),
            "authGenerationAtOrigin": 1,
            "originTransitionId": TOKEN_JTI,
            "originSeq": 1,
            "roleAtOrigin": "admin",
            "deviceStatusAtOrigin": "active"
        }
    });
    serde_json::to_vec(&json!({
        "body": {
            "$type": "blue.catbird.chat.defs#commitTransitionBody",
            "signatureDomain": "CATBIRD-CHAT-COMMIT\u{0}",
            "transitionId": TOKEN_JTI,
            "actorDid": DID,
            "actorDeviceId": DEVICE_ID,
            "keyId": KEY_ID,
            "authGeneration": 1,
            "prior": coordinates(0),
            "next": {
                "conversationId": CHAT_INSTANCE,
                "generation": 0,
                "stateVersion": 1,
                "groupId": STANDARD.encode([0x21_u8; 32]),
                "epoch": 1,
                "groupContextHash": STANDARD.encode([0x24_u8; 32]),
                "confirmationTag": STANDARD.encode([0x25_u8; 32]),
                "lifecycle": "active"
            },
            "aad": {
                "protocolVersion": "1",
                "conversationId": STANDARD.encode(conversation_id_bytes.as_bytes()),
                "generation": 0,
                "transitionId": STANDARD.encode(transition_id_bytes.as_bytes()),
                "prior": prior_mls
            },
            "manifest": {
                "participantChanges": [],
                "leafChanges": leaf_changes
            },
            "commit": {
                "framing": "mlsMessage",
                "contentType": "publicMessageCommit",
                "bytes": STANDARD.encode(commit_bytes),
                "sha256": STANDARD.encode(Sha256::digest(commit_bytes))
            },
            "metadataSnapshot": metadata_snapshot,
            "idempotencyKey": CHAT_INSTANCE,
            "signedAt": "2026-07-22T14:05:09.123Z"
        },
        "signature": STANDARD.encode([0_u8; 64])
    }))
    .unwrap()
}

fn unsigned_leaf_recovery_fulfillment_request(leaf_changes: Vec<Value>) -> Vec<u8> {
    let mut wrapper: Value = serde_json::from_slice(&unsigned_commit_request(&[])).unwrap();
    let body = wrapper["body"].as_object_mut().unwrap();
    body.insert(
        "$type".to_owned(),
        json!("blue.catbird.chat.defs#leafRecoveryFulfillmentBody"),
    );
    body.insert(
        "signatureDomain".to_owned(),
        json!("CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\u{0}"),
    );
    body.insert("recoveryRequestId".to_owned(), json!(TOKEN_JTI));
    let manifest = body["manifest"].as_object_mut().unwrap();
    manifest.insert("leafChanges".to_owned(), Value::Array(leaf_changes));
    manifest.insert("leafRecoveryRequestId".to_owned(), json!(TOKEN_JTI));
    let opaque_welcome = [0x41_u8; 8];
    manifest.insert(
        "welcomeBundle".to_owned(),
        json!({
            "welcomeId": RETRY_TOKEN_JTI,
            "framing": "mlsMessage",
            "contentType": "welcome",
            "opaqueWelcome": STANDARD.encode(opaque_welcome),
            "sha256": STANDARD.encode(Sha256::digest(opaque_welcome)),
            "deliveries": [{
                "recipientDid": DID,
                "recipientDeviceId": "11111111-1111-4111-8111-111111111111",
                "provenance": {
                    "recoveryRequestId": TOKEN_JTI,
                    "keyPackageRef": STANDARD.encode([0x42_u8; 32]),
                }
            }]
        }),
    );
    serde_json::to_vec(&wrapper).unwrap()
}

fn remove_leaf(user_did: &str, device_id: &str) -> Value {
    json!({
        "$type": "blue.catbird.chat.defs#removeLeaf",
        "userDid": user_did,
        "deviceId": device_id,
    })
}

fn add_leaf_by_recovery(user_did: &str, device_id: &str) -> Value {
    json!({
        "$type": "blue.catbird.chat.defs#addLeafByRecovery",
        "userDid": user_did,
        "deviceId": device_id,
        "recoveryRequestId": TOKEN_JTI,
        "keyPackageRef": STANDARD.encode([0x42_u8; 32]),
    })
}

fn coordinates(state_version: u64) -> Value {
    json!({
        "conversationId": CHAT_INSTANCE,
        "generation": 0,
        "stateVersion": state_version,
        "groupId": STANDARD.encode([0x21_u8; 32]),
        "epoch": 0,
        "groupContextHash": STANDARD.encode([0x22_u8; 32]),
        "confirmationTag": STANDARD.encode([0x23_u8; 32]),
        "lifecycle": "active"
    })
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

fn enrollment_body(dpop_jkt: &str, signing_key: &Ed25519SigningKey, package_refs: &[u8]) -> Value {
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
        "deviceName": "Test device",
        "keyId": key_id.as_str(),
        "signaturePublicKey": STANDARD.encode(signing_key.verifying_key().as_bytes()),
        "dpopJkt": dpop_jkt,
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

fn rebind_body(
    current_dpop_jkt: &str,
    new_dpop_jkt: &str,
    signing_key: &Ed25519SigningKey,
) -> Value {
    let key_id = ed25519_key_id(signing_key.verifying_key().as_bytes()).unwrap();
    json!({
        "$type": "blue.catbird.chat.defs#deviceAuthenticationRebindBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REBIND\u{0}",
        "actorDid": DID,
        "actorDeviceId": DEVICE_ID,
        "keyId": key_id.as_str(),
        "expectedAuthGeneration": 1,
        "currentDpopJkt": current_dpop_jkt,
        "newDpopJkt": new_dpop_jkt,
        "idempotencyKey": CHAT_INSTANCE,
        "signedAt": "2023-11-14T22:14:20.000Z"
    })
}

enum FixtureDagValue {
    String(String),
    Integer(u64),
    Bool(bool),
    Bytes(Vec<u8>),
    Array(Vec<Self>),
    Map(BTreeMap<String, Self>),
}

impl<'de> Deserialize<'de> for FixtureDagValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(FixtureDagVisitor)
    }
}

struct FixtureDagVisitor;

impl<'de> Visitor<'de> for FixtureDagVisitor {
    type Value = FixtureDagValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the frozen clean-chat DAG-CBOR value profile")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(FixtureDagValue::Bool(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(FixtureDagValue::Integer(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        u64::try_from(value)
            .map(FixtureDagValue::Integer)
            .map_err(|_| E::custom("negative fixture integer"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(FixtureDagValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(FixtureDagValue::String(value))
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E> {
        Ok(FixtureDagValue::Bytes(value.to_vec()))
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        Ok(FixtureDagValue::Bytes(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(FixtureDagValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some((key, value)) = map.next_entry()? {
            values.insert(key, value);
        }
        Ok(FixtureDagValue::Map(values))
    }
}

impl FixtureDagValue {
    fn into_json_for_schema(
        self,
        schema: &Value,
        definitions: &serde_json::Map<String, Value>,
    ) -> Value {
        match schema["type"].as_str().unwrap() {
            "ref" => {
                let definition_name = schema["ref"].as_str().unwrap().strip_prefix('#').unwrap();
                if matches!(definition_name, "operationId" | "deviceId") {
                    let Self::Bytes(value) = self else {
                        panic!("frozen UUID projection was not DAG-CBOR bytes");
                    };
                    Value::String(
                        uuid::Uuid::from_slice(&value)
                            .unwrap()
                            .hyphenated()
                            .to_string(),
                    )
                } else {
                    self.into_json_for_schema(&definitions[definition_name], definitions)
                }
            }
            "union" => {
                let definition_name = {
                    let Self::Map(values) = &self else {
                        panic!("frozen union projection was not a DAG-CBOR map");
                    };
                    let Some(Self::String(type_id)) = values.get("$type") else {
                        panic!("frozen union projection omitted its type tag");
                    };
                    type_id
                        .strip_prefix("blue.catbird.chat.defs#")
                        .unwrap()
                        .to_owned()
                };
                let allowed =
                    schema["refs"].as_array().unwrap().iter().any(|reference| {
                        reference.as_str() == Some(&format!("#{definition_name}"))
                    });
                assert!(allowed, "frozen union selected a disallowed type");
                self.into_json_for_schema(&definitions[definition_name.as_str()], definitions)
            }
            "object" => {
                let Self::Map(values) = self else {
                    panic!("frozen object projection was not a DAG-CBOR map");
                };
                let properties = schema["properties"].as_object().unwrap();
                Value::Object(
                    values
                        .into_iter()
                        .map(|(name, value)| {
                            let value = if name == "$type" {
                                let Self::String(type_id) = value else {
                                    panic!("frozen object type tag was not text");
                                };
                                Value::String(type_id)
                            } else {
                                value.into_json_for_schema(&properties[&name], definitions)
                            };
                            (name, value)
                        })
                        .collect(),
                )
            }
            "string" => {
                let Self::String(value) = self else {
                    panic!("frozen string projection was not DAG-CBOR text");
                };
                Value::String(value)
            }
            "bytes" => {
                let Self::Bytes(value) = self else {
                    panic!("frozen byte projection was not DAG-CBOR bytes");
                };
                Value::String(STANDARD.encode(value))
            }
            "integer" => {
                let Self::Integer(value) = self else {
                    panic!("frozen integer projection was not a DAG-CBOR integer");
                };
                json!(value)
            }
            "boolean" => {
                let Self::Bool(value) = self else {
                    panic!("frozen boolean projection was not a DAG-CBOR boolean");
                };
                json!(value)
            }
            "array" => {
                let Self::Array(values) = self else {
                    panic!("frozen array projection was not a DAG-CBOR array");
                };
                Value::Array(
                    values
                        .into_iter()
                        .map(|value| value.into_json_for_schema(&schema["items"], definitions))
                        .collect(),
                )
            }
            other => panic!("unsupported frozen fixture schema type {other}"),
        }
    }
}

fn collect_key_binding_issues(
    value: &Value,
    path: &str,
    entry_kind: &str,
    issues: &mut Vec<String>,
) {
    match value {
        Value::Object(fields) => {
            for key_name in ["keyId", "authorKeyId", "requesterKeyId"] {
                if let Some(Value::String(key_id)) = fields.get(key_name) {
                    if KeyThumbprint::parse(key_id).is_err() {
                        issues.push(format!(
                            "{entry_kind}: {path}.{key_name} is not canonical base64url SHA-256"
                        ));
                    }
                }
            }
            for key_name in ["keyId", "authorKeyId", "requesterKeyId"] {
                let (Some(Value::String(key_id)), Some(Value::String(public_key))) =
                    (fields.get(key_name), fields.get("signaturePublicKey"))
                else {
                    continue;
                };
                let Ok(public_key) = STANDARD.decode(public_key) else {
                    continue;
                };
                let Ok(derived) = ed25519_key_id(&public_key) else {
                    continue;
                };
                if derived.as_str() != key_id {
                    issues.push(format!(
                        "{entry_kind}: {path}.{key_name} does not bind {path}.signaturePublicKey"
                    ));
                }
            }
            for (name, child) in fields {
                collect_key_binding_issues(child, &format!("{path}.{name}"), entry_kind, issues);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                collect_key_binding_issues(child, &format!("{path}[{index}]"), entry_kind, issues);
            }
        }
        _ => {}
    }
}

fn repair_embedded_key_bindings_for_schema_audit(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            let derived = fields
                .get("signaturePublicKey")
                .and_then(Value::as_str)
                .and_then(|value| STANDARD.decode(value).ok())
                .and_then(|value| ed25519_key_id(&value).ok())
                .map(|value| value.as_str().to_owned());
            if let Some(derived) = derived {
                for key_name in ["keyId", "authorKeyId", "requesterKeyId"] {
                    if fields.contains_key(key_name) {
                        fields.insert(key_name.to_owned(), Value::String(derived.clone()));
                    }
                }
            }
            for child in fields.values_mut() {
                repair_embedded_key_bindings_for_schema_audit(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                repair_embedded_key_bindings_for_schema_audit(child);
            }
        }
        _ => {}
    }
}

fn signing_key(fill: u8) -> SigningKey {
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

fn sign_jwt_raw_payload(header: Value, payload: &str, key: &SigningKey) -> String {
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let encoded_claims = URL_SAFE_NO_PAD.encode(payload.as_bytes());
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

fn decode_payload(token: &str) -> Value {
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}
