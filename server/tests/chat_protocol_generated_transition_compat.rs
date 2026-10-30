//! Actual generated Rust and Swift wire products against the production decoder.
//! Frozen signing products remain independent of the representation adapter.

use base64::{engine::general_purpose::STANDARD, Engine};
// Follow the established signing-vector target: compile the actual private
// authority source and its real canonical encoder, without widening the
// production API or substituting an encoder stub.
#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../src/chat_protocol/read_projection.rs"]
mod read_projection;
#[allow(dead_code)]
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[allow(dead_code)]
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

mod chat_protocol {
    pub(crate) use crate::read_projection;
    pub use catbird_server::chat_protocol::direct_request_transcript;
}
use serde::Deserialize;
use serde_json::{json, value::RawValue, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

#[path = "common/generated_transition_requests.rs"]
mod generated_transition_requests;

#[derive(Deserialize)]
struct RequestEnvelope<'a> {
    #[serde(borrow, rename = "signedRequest")]
    signed_request: &'a RawValue,
}

fn signed_wrapper(request: &[u8]) -> &[u8] {
    serde_json::from_slice::<RequestEnvelope<'_>>(request)
        .expect("actual generated request envelope")
        .signed_request
        .get()
        .as_bytes()
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/generated_transitions")
}

fn swift_cases() -> Vec<Value> {
    let manifest: Value = serde_json::from_slice(
        &fs::read(fixture_dir().join("swift-fixtures.json")).expect("Swift serializer manifest"),
    )
    .expect("Swift serializer manifest JSON");
    manifest["cases"].as_array().unwrap().clone()
}

fn assert_frozen_products(raw: &[u8], public_key: &[u8], expected: &Value) {
    let verified = transcript::decode_and_verify_signed_mutation(raw, public_key)
        .expect("actual production decoder verifies generated wire bytes");
    assert_eq!(verified.accepted_wrapper_bytes(), Some(raw));
    assert_eq!(
        hex::encode(verified.canonical_projection()),
        expected["unsignedSigningProjectionCanonicalDagCborHex"]
    );
    assert_eq!(
        hex::encode(verified.transcript_bytes()),
        expected["signingTranscriptHex"]
    );
    assert_eq!(
        STANDARD.encode(verified.request_digest()),
        expected["requestDigest"]
    );
    assert_eq!(STANDARD.encode(verified.signature()), expected["signature"]);
}

#[test]
fn actual_swift_encoder_products_preserve_all_five_frozen_signing_domains() {
    let cases = swift_cases();
    assert!(cases.len() >= 5);
    for case in cases
        .iter()
        .filter(|case| case["name"] != "recovery-nonempty")
    {
        let request = fs::read(fixture_dir().join(case["requestFile"].as_str().unwrap())).unwrap();
        let raw = signed_wrapper(&request);
        let wrapper = fs::read(fixture_dir().join(case["wrapperFile"].as_str().unwrap())).unwrap();
        assert_eq!(raw, wrapper);
        assert_eq!(hex::encode(Sha256::digest(&request)), case["requestSHA256"]);
        assert_eq!(hex::encode(Sha256::digest(raw)), case["wrapperSHA256"]);
        let public_key = hex::decode(case["expected"]["publicKeyHex"].as_str().unwrap()).unwrap();
        assert_frozen_products(raw, &public_key, &case["expected"]);
    }
    assert_eq!(
        cases
            .iter()
            .filter(|case| case["name"] != "recovery-nonempty")
            .count(),
        5
    );
}

#[test]
fn fresh_rust_dtos_preserve_all_five_frozen_signing_domains_without_extra_data() {
    let cases = generated_transition_requests::frozen_cases();
    assert_eq!(cases.len(), 5);
    for case in cases {
        let raw = signed_wrapper(&case.generated_request);
        let generated: Value = serde_json::from_slice(raw).unwrap();
        assert!(generated["$type"].is_string(), "{}", case.name);
        assert!(generated["body"].get("$type").is_none(), "{}", case.name);
        assert!(
            generated["signature"]["$bytes"].is_string(),
            "{}",
            case.name
        );
        assert_frozen_products(raw, &case.public_key, &case.expected);
        assert_frozen_products(&case.legacy_wrapper, &case.public_key, &case.expected);
        assert_ne!(raw, case.legacy_wrapper);
    }
}

#[test]
fn generated_adapter_rejects_wrong_discriminators_fields_and_signatures() {
    let case = generated_transition_requests::frozen_cases().remove(0);
    let original: Value = serde_json::from_slice(signed_wrapper(&case.generated_request)).unwrap();
    let mut invalid = Vec::new();
    for tag in [
        json!("blue.catbird.chat.defs#signedCreation"),
        json!("blue.catbird.chat.defs#signedPolicyTransition"),
        json!("unknown"),
        json!(1),
    ] {
        let mut value = original.clone();
        value["$type"] = tag;
        invalid.push(value);
    }
    let mut value = original.clone();
    value["unexpected"] = json!(true);
    invalid.push(value);
    let mut value = original.clone();
    value["body"]["$type"] = json!("blue.catbird.chat.defs#policyTransitionBody");
    invalid.push(value);
    let mut value = original.clone();
    value["body"]["prior"]["$type"] = json!("blue.catbird.chat.defs#metadataSnapshot");
    invalid.push(value);
    let mut value = original.clone();
    value["body"]["prior"]["unexpected"] = json!(true);
    invalid.push(value);
    let mut value = original.clone();
    value["body"]["signatureDomain"] = json!("CATBIRD-CHAT-POLICY\0");
    invalid.push(value);
    for scalar in [
        Value::Null,
        json!(1.5),
        json!(-1),
        json!(9007199254740992_u64),
    ] {
        let mut value = original.clone();
        value["body"]["authGeneration"] = scalar;
        invalid.push(value);
    }
    for signature in [
        json!({"$bytes":"AA==","extra":1}),
        json!({"$bytes":"AA"}),
        json!({"$bytes":STANDARD.encode([0; 63])}),
    ] {
        let mut value = original.clone();
        value["signature"] = signature;
        invalid.push(value);
    }
    for value in invalid {
        assert!(
            transcript::decode_canonical_signed_mutation(&serde_json::to_vec(&value).unwrap())
                .is_err()
        );
    }
    let mut tampered = original.clone();
    let mut signature = STANDARD
        .decode(tampered["signature"]["$bytes"].as_str().unwrap())
        .unwrap();
    signature[0] ^= 1;
    tampered["signature"]["$bytes"] = json!(STANDARD.encode(signature));
    assert!(transcript::decode_and_verify_signed_mutation(
        &serde_json::to_vec(&tampered).unwrap(),
        &case.public_key
    )
    .is_err());
    let mut tampered = original;
    tampered["body"]["authGeneration"] = json!(2);
    assert!(transcript::decode_and_verify_signed_mutation(
        &serde_json::to_vec(&tampered).unwrap(),
        &case.public_key
    )
    .is_err());
}

#[test]
fn nonempty_generated_recovery_preserves_nested_union_and_reference_semantics() {
    let rust = generated_transition_requests::recovery_nonempty_case();
    assert_frozen_products(
        signed_wrapper(&rust.generated_request),
        &rust.public_key,
        &rust.expected,
    );
    let swift = swift_cases()
        .into_iter()
        .find(|case| case["name"] == "recovery-nonempty")
        .expect("maintained nonempty Swift recovery fixture");
    let request = fs::read(fixture_dir().join(swift["requestFile"].as_str().unwrap())).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&request)),
        swift["requestSHA256"]
    );
    assert_eq!(swift["expected"], rust.expected);
    assert_frozen_products(signed_wrapper(&request), &rust.public_key, &rust.expected);

    for raw in [
        signed_wrapper(&rust.generated_request),
        signed_wrapper(&request),
    ] {
        let original: Value = serde_json::from_slice(raw).unwrap();
        for tag in [
            None,
            Some(json!("blue.catbird.chat.defs#removeLeaf")),
            Some(json!(7)),
        ] {
            let mut invalid = original.clone();
            let leaf = invalid["body"]["manifest"]["leafChanges"][0]
                .as_object_mut()
                .unwrap();
            match tag {
                None => {
                    leaf.remove("$type");
                }
                Some(tag) => {
                    leaf.insert("$type".to_owned(), tag);
                }
            }
            assert!(transcript::decode_canonical_signed_mutation(
                &serde_json::to_vec(&invalid).unwrap()
            )
            .is_err());
        }
        let mut invalid = original;
        invalid["body"]["manifest"]["welcomeBundle"]["deliveries"][0]["provenance"]["$type"] =
            json!("blue.catbird.chat.defs#addWelcomeProvenance");
        assert!(transcript::decode_canonical_signed_mutation(
            &serde_json::to_vec(&invalid).unwrap()
        )
        .is_err());
    }
}

#[test]
fn generated_raw_json_and_legacy_boundary_remain_strict() {
    let case = generated_transition_requests::frozen_cases().remove(0);
    let generated = std::str::from_utf8(signed_wrapper(&case.generated_request)).unwrap();
    let duplicate_type = format!(
        "{{\"$type\":\"blue.catbird.chat.defs#signedCommitTransition\",{}",
        &generated[1..]
    );
    let duplicate_signature = format!(
        "{{\"signature\":{{\"$bytes\":\"{}\"}},{}}}",
        STANDARD.encode([0; 64]),
        &generated[1..generated.len() - 1]
    );
    for raw in [
        duplicate_type,
        duplicate_signature,
        format!("{generated} null"),
    ] {
        assert!(transcript::decode_canonical_signed_mutation(raw.as_bytes()).is_err());
    }

    let legacy: Value = serde_json::from_slice(&case.legacy_wrapper).unwrap();
    let mut invalid = legacy.clone();
    invalid["body"].as_object_mut().unwrap().remove("$type");
    assert!(
        transcript::decode_canonical_signed_mutation(&serde_json::to_vec(&invalid).unwrap())
            .is_err()
    );
    let mut invalid = legacy.clone();
    invalid["signature"] = json!({"$bytes": invalid["signature"]});
    assert!(
        transcript::decode_canonical_signed_mutation(&serde_json::to_vec(&invalid).unwrap())
            .is_err()
    );
    let mut invalid = legacy;
    invalid["body"]["prior"]["$type"] = json!("blue.catbird.chat.defs#conversationCoordinates");
    assert!(
        transcript::decode_canonical_signed_mutation(&serde_json::to_vec(&invalid).unwrap())
            .is_err()
    );
}

#[test]
fn generated_and_legacy_origins_share_canonical_reads_and_preserve_historical_bytes() {
    use transcript::{
        build_verified_control_entry, decode_and_verify_control_entry,
        decode_and_verify_signed_mutation, rebind_persisted_control_entry,
        CanonicalControlEntryProducts, CanonicalControlServerFields, ControlEntryKind,
    };
    use validation::{
        CanonicalTimestamp, CanonicalUuidV4, TrustedRequestInstant, ValidatedChatNsid,
    };

    let mut cases = generated_transition_requests::frozen_cases();
    let mut supplemental = generated_transition_requests::recovery_nonempty_case();
    // Reuse the recovery row identity/server fields for this representation
    // comparison. Its new semantic body has no independent frozen fingerprint;
    // do not relabel the derived supplemental products as such an oracle.
    let recovery_row = cases.iter().find(|case| case.name == "recovery").unwrap();
    for field in [
        "entryKind",
        "entryId",
        "conversationId",
        "seq",
        "receivedAt",
        "serverFields",
    ] {
        supplemental.expected[field] = recovery_row.expected[field].clone();
    }
    cases.push(supplemental);
    for case in cases {
        let expected = &case.expected;
        let kind = ControlEntryKind::ALL
            .into_iter()
            .find(|kind| Some(kind.type_id()) == expected["entryKind"].as_str())
            .unwrap();
        let swift = swift_cases()
            .into_iter()
            .find(|entry| entry["name"] == case.name)
            .unwrap();
        let swift_raw =
            fs::read(fixture_dir().join(swift["wrapperFile"].as_str().unwrap())).unwrap();
        let mut first_response = None;
        for (origin, raw) in [
            ("legacy", case.legacy_wrapper.as_slice()),
            ("rust", signed_wrapper(&case.generated_request)),
            ("swift", swift_raw.as_slice()),
        ] {
            let mutation = decode_and_verify_signed_mutation(raw, &case.public_key).unwrap();
            let server_fields = CanonicalControlServerFields::decode(
                kind,
                &serde_json::to_vec(&expected["serverFields"]).unwrap(),
            )
            .unwrap();
            let received_at = TrustedRequestInstant::from_canonical_for_test(
                CanonicalTimestamp::parse(expected["receivedAt"].as_str().unwrap()).unwrap(),
            );
            let built = build_verified_control_entry(
                mutation,
                &ValidatedChatNsid::parse("blue.catbird.chat.submitTransition").unwrap(),
                CanonicalUuidV4::parse(expected["entryId"].as_str().unwrap()).unwrap(),
                CanonicalUuidV4::parse(expected["conversationId"].as_str().unwrap()).unwrap(),
                expected["seq"].as_u64().unwrap(),
                &received_at,
                server_fields,
            )
            .unwrap();
            if case.name != "recovery-nonempty" {
                assert_eq!(
                    hex::encode(built.outer_control_fingerprint()),
                    expected["fingerprintSha256Hex"]
                );
                assert_eq!(
                    hex::encode(built.outer_control_projection()),
                    expected["canonicalDagCborHex"]
                );
            }
            let products = CanonicalControlEntryProducts::mint(&built).unwrap();
            let durable =
                decode_and_verify_control_entry(products.durable_json(), &case.public_key).unwrap();
            let rebound = rebind_persisted_control_entry(durable, raw, &case.public_key).unwrap();
            assert_eq!(rebound.mutation().accepted_wrapper_bytes(), Some(raw));
            assert_eq!(
                rebound.outer_control_fingerprint(),
                built.outer_control_fingerprint()
            );
            let wrong_key = ed25519_dalek::SigningKey::from_bytes(&[0x7d; 32]);
            assert!(rebind_persisted_control_entry(
                decode_and_verify_control_entry(products.durable_json(), &case.public_key).unwrap(),
                raw,
                wrong_key.verifying_key().as_bytes()
            )
            .is_err());

            // This is the exact persisted-row reconstruction and canonical
            // encoder used by entry_read; no response encoder stub is involved.
            let response = transcript::persisted_control_entry_response_json(
                kind.type_id(),
                expected["entryId"].as_str().unwrap(),
                expected["conversationId"].as_str().unwrap(),
                expected["seq"].as_u64().unwrap(),
                expected["receivedAt"].as_str().unwrap(),
                raw,
                &built.server_fields_dag_cbor().unwrap(),
            )
            .unwrap();
            let response_value: Value = serde_json::from_slice(&response).unwrap();
            let canonical = read_projection::encode_canonical_generated_chat_json_v1(
                &response_value,
                "blue.catbird.chat.defs#conversationEntry",
            )
            .unwrap();
            let dto: catbird_atproto::blue_catbird::chat::ConversationEntry =
                serde_json::from_slice(canonical.bytes()).unwrap();
            let from_dto = read_projection::encode_canonical_generated_chat_json_v1(
                &dto,
                "blue.catbird.chat.defs#conversationEntry",
            )
            .unwrap();
            assert_eq!(from_dto.bytes(), canonical.bytes());
            if let Some(first) = &first_response {
                assert_eq!(first, canonical.bytes());
            } else {
                first_response = Some(canonical.bytes().to_vec());
            }
            let wire: Value = serde_json::from_slice(canonical.bytes()).unwrap();
            assert!(wire.get("acceptedPayloadSha256").is_none());
            assert!(wire.get("acceptedRequestBytes").is_none());
            assert_eq!(
                wire["signedRequest"]["signature"]["$bytes"],
                expected["signature"]
            );

            if let Ok(directory) = std::env::var("CATBIRD_GENERATED_TRANSITION_RESPONSE_DIR") {
                let directory = PathBuf::from(directory);
                fs::create_dir_all(&directory).unwrap();
                let envelope =
                    json!({"entries":[wire], "nextAfterSeq":expected["seq"], "hasMore":false});
                let bytes = serde_json::to_vec(&envelope).unwrap();
                let _: catbird_atproto::blue_catbird::chat::get_entries::GetEntriesOutput =
                    serde_json::from_slice(&bytes).unwrap();
                fs::write(
                    directory.join(format!("{}-{origin}.get-entries.json", case.name)),
                    bytes,
                )
                .unwrap();
            }
        }
    }
}

#[test]
#[ignore = "explicitly regenerates the additional Swift test input; never runs in normal CI"]
fn export_recovery_nonempty_swift_input_when_requested() {
    assert_eq!(
        std::env::var("CATBIRD_WRITE_GENERATED_TRANSITION_INPUTS").as_deref(),
        Ok("1")
    );
    generated_transition_requests::write_recovery_nonempty_inputs(&fixture_dir().join("inputs"));
}
