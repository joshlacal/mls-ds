//! Known-answer vectors for the ten active signing domains that no control-entry
//! case covers.
//!
//! `mls_chat_contract_vectors.json` pins fourteen of the twenty-five signing
//! domains: the thirteen control entries, plus `CATBIRD-CHAT-BLOB-DELETE` from
//! its one `signedMutator` case. The other ten — `CATBIRD-CHAT-MESSAGE`, the
//! application-send domain, above all — had no server vector anywhere, so every
//! client's copy of those domain strings rested on a hand transcription. A
//! single wrong byte there produces signatures that verify locally and nowhere
//! else.
//!
//! # The vectors are server products, not test arithmetic
//!
//! Nothing here re-implements the signing construction. Each body is handed to
//! [`decode_canonical_signed_mutation`] — the same entry point the live handlers
//! call — which picks the domain from `SignedMutationKind`, projects the body
//! through the closed lexicon contract, and builds the transcript. The harness
//! signs *those* bytes and then re-enters through
//! [`decode_and_verify_signed_mutation`], so every emitted case is one the
//! server has actually accepted. A body the live contract rejects fails the run.
//!
//! # Why a separate fixture file
//!
//! These cases deliberately do **not** extend `mls_chat_contract_vectors.json`.
//! That file's bytes are hashed into frozen generated-artifact provenance
//! (`docs/generated-artifacts/chat-application-v1/manifest.json`, via its
//! `contractSources` list), and editing it desyncs that record silently — the
//! guard that would catch it cannot even run from a checkout where the artifact
//! tree is absent. A sibling fixture adds coverage without touching a hashed
//! input.
//!
//! # Regenerating
//!
//! ```sh
//! CATBIRD_REGENERATE_SIGNING_DOMAIN_VECTORS=1 cargo test --test \
//!     chat_protocol_signing_domain_vectors
//! ```
//!
//! Regeneration rewrites the fixture from the current server code. If a value
//! moves, that is a protocol change to explain, not a diff to accept.

#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[allow(dead_code)]
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

#[path = "common/signing_domain_bodies.rs"]
mod bodies;

use std::{collections::BTreeSet, fs, path::PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use transcript::{
    decode_and_verify_enrollment_body, decode_and_verify_signed_mutation,
    decode_canonical_signed_mutation, ControlEntryKind, SignedMutationKind,
    VerifiedMutationProjection,
};
use validation::ed25519_key_id;

const FIXTURE: &str = include_str!("fixtures/mls_chat_signing_domain_vectors.json");
const REGENERATE_ENV: &str = "CATBIRD_REGENERATE_SIGNING_DOMAIN_VECTORS";
const CANONICAL_LEXICON: &[u8] =
    include_bytes!("../../lexicon/blue/catbird/chat/blue.catbird.chat.defs.json");
const CANONICAL_LEXICON_PATH: &str = "lexicon/blue/catbird/chat/blue.catbird.chat.defs.json";
const CANONICAL_SOURCE_LEXICON_PATH: &str =
    "PetrelCatbird/lexicons/blue/catbird/chat/blue.catbird.chat.defs.json";
const CANONICAL_SOURCE_LEXICON_REVISION: &str = "8ec8acaa1137b68b57b78ebfaea9404d5923305b";
const CANONICAL_SOURCE_CORPUS_REVISION: &str = "a063ed8f995031fa0cf122bca3f4f82c89f08c90";
const CANONICAL_SOURCE_LEXICON_SHA256: &str =
    "dea9b6e72128d71d70f8c05036bf90889c2f91987c7a11fb82904a3e63df6caf";

/// A fixed, test-only Ed25519 seed. It is not the RFC 8032 seed the existing
/// `signedMutator` vector uses, so a case cross-wired between the two fixtures
/// fails its key-id binding rather than silently verifying.
const SIGNING_SEED: [u8; 32] = [0x5c; 32];

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mls_chat_signing_domain_vectors.json")
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&SIGNING_SEED)
}

fn canonical_lexicon_sha256() -> String {
    hex::encode(Sha256::digest(CANONICAL_LEXICON))
}

fn frozen_case(body_name: &str) -> Value {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("the fixture parses");
    fixture["cases"]
        .as_array()
        .expect("fixture cases")
        .iter()
        .find(|case| case["bodyName"] == body_name)
        .cloned()
        .unwrap_or_else(|| panic!("missing frozen case {body_name}"))
}

fn frozen_wrapper(body_name: &str) -> (Value, Vec<u8>, [u8; 32]) {
    let case = frozen_case(body_name);
    let wrapper = case["wrapper"].clone();
    let wrapper_bytes = serde_json::to_vec(&wrapper).expect("wrapper serializes");
    let public_key: [u8; 32] = hex::decode(
        case["publicKeyHex"]
            .as_str()
            .expect("fixture public key hex"),
    )
    .expect("fixture public key hex decodes")
    .try_into()
    .expect("fixture public key is 32 bytes");
    (case, wrapper_bytes, public_key)
}

/// The body names with no control entry, derived rather than transcribed: every
/// signed-mutation kind that is not also a control-entry kind and is not the
/// blob-deletion case the existing fixture already pins.
fn unpinned_body_names() -> Vec<&'static str> {
    let control: BTreeSet<&'static str> = ControlEntryKind::ALL
        .into_iter()
        .map(|kind| kind.signed_kind().body_name())
        .collect();
    SignedMutationKind::ALL
        .into_iter()
        .filter(|kind| {
            *kind != SignedMutationKind::BlobDeletion
                && *kind != SignedMutationKind::DeviceAuthenticationRebind
                && !control.contains(kind.body_name())
        })
        .map(SignedMutationKind::body_name)
        .collect()
}

fn existing_contract_fixture_body_names() -> BTreeSet<String> {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/mls_chat_contract_vectors.json"))
            .expect("existing contract fixture parses");
    let contract: Value = serde_json::from_str(include_str!(
        "../../lexicon/blue/catbird/chat/blue.catbird.chat.defs.json"
    ))
    .expect("canonical chat lexicon parses");
    let mut names = BTreeSet::new();
    for case in fixture["controlEntryFingerprints"]["cases"]
        .as_array()
        .expect("control cases")
    {
        let signed_name = case["signedRequestRef"]
            .as_str()
            .expect("signed request ref")
            .rsplit('#')
            .next()
            .expect("signed request name");
        names.insert(
            contract["defs"][signed_name]["properties"]["body"]["refs"][0]
                .as_str()
                .expect("signed body ref")
                .trim_start_matches('#')
                .to_owned(),
        );
    }
    names.insert(
        fixture["signedMutator"]["body"]["$type"]
            .as_str()
            .expect("signed mutator body type")
            .rsplit('#')
            .next()
            .expect("signed mutator body name")
            .to_owned(),
    );
    names
}

/// Signs `body` through the server's own projection and returns the wrapper
/// bytes together with the canonical products the server derived.
fn sign_through_production(body: &Value) -> (Value, Vec<u8>, Value) {
    let key = signing_key();
    let mut wrapper = json!({ "body": body, "signature": STANDARD.encode([0_u8; 64]) });

    let unsigned = decode_canonical_signed_mutation(&serde_json::to_vec(&wrapper).unwrap())
        .unwrap_or_else(|error| {
            panic!(
                "{} must satisfy the live contract: {error:?}",
                body["$type"]
            )
        });
    let signature = key.sign(unsigned.transcript_bytes()).to_bytes();
    wrapper["signature"] = json!(STANDARD.encode(signature));

    let wrapper_bytes = serde_json::to_vec(&wrapper).unwrap();
    let verified =
        decode_and_verify_signed_mutation(&wrapper_bytes, key.verifying_key().as_bytes())
            .unwrap_or_else(|error| panic!("the server must accept its own vector: {error:?}"));

    let products = json!({
        "canonicalUnsignedDagCborHex": hex::encode(verified.canonical_projection()),
        "transcriptHex": hex::encode(verified.transcript_bytes()),
        "canonicalRequestDigestHex": hex::encode(verified.request_digest()),
        "signatureHex": hex::encode(verified.signature()),
    });
    (wrapper, wrapper_bytes, products)
}

/// The top-level fields the server encoded as raw sixteen-byte UUIDs, read back
/// out of the canonical projection it produced rather than assumed from the
/// lexicon. A DAG-CBOR byte string of length sixteen is `0x50` followed by the
/// bytes.
fn uuid_byte_fields(body: &Value, canonical_projection_hex: &str) -> Vec<String> {
    let projection = hex::decode(canonical_projection_hex).expect("projection is hex");
    let mut fields: Vec<String> = body
        .as_object()
        .expect("a body is an object")
        .iter()
        .filter_map(|(name, value)| {
            let text = value.as_str()?;
            let parsed = uuid::Uuid::parse_str(text).ok()?;
            let mut needle = vec![0x50_u8];
            needle.extend_from_slice(parsed.as_bytes());
            projection
                .windows(needle.len())
                .any(|window| window == needle)
                .then(|| name.clone())
        })
        .collect();
    fields.sort_unstable();
    fields
}

fn case(body_name: &str, mutation_field: &str, body: Value) -> Value {
    let (wrapper, wrapper_bytes, products) = sign_through_production(&body);

    let mut mutated_body = body.clone();
    let original = body[mutation_field]
        .as_str()
        .expect("the mutated field is a string");
    let mutated_value = mutate(original);
    assert_ne!(
        original, mutated_value,
        "{body_name}: mutation must change the field"
    );
    mutated_body[mutation_field] = json!(mutated_value);

    let mutated_wrapper = json!({ "body": mutated_body, "signature": STANDARD.encode([0_u8; 64]) });
    let mutated = decode_canonical_signed_mutation(&serde_json::to_vec(&mutated_wrapper).unwrap())
        .unwrap_or_else(|error| {
            panic!("{body_name}: the mutated body must still decode: {error:?}")
        });

    let mut record = Map::new();
    record.insert("bodyName".to_owned(), json!(body_name));
    record.insert("signingDomain".to_owned(), body["signatureDomain"].clone());
    record.insert("body".to_owned(), body.clone());
    record.insert("wrapper".to_owned(), wrapper);
    record.insert(
        "wrapperJsonHex".to_owned(),
        json!(hex::encode(wrapper_bytes)),
    );
    record.insert(
        "uuidByteFields".to_owned(),
        json!(uuid_byte_fields(
            &body,
            products["canonicalUnsignedDagCborHex"].as_str().unwrap()
        )),
    );
    for (key, value) in products.as_object().unwrap() {
        record.insert(key.clone(), value.clone());
    }
    record.insert(
        "publicKeyHex".to_owned(),
        json!(hex::encode(signing_key().verifying_key().as_bytes())),
    );
    record.insert(
        "mutation".to_owned(),
        json!({ "field": mutation_field, "value": mutated_value }),
    );
    record.insert(
        "mutatedTranscriptHex".to_owned(),
        json!(hex::encode(mutated.transcript_bytes())),
    );
    record.insert(
        "mutatedRequestDigestHex".to_owned(),
        json!(hex::encode(mutated.request_digest())),
    );
    Value::Object(record)
}

/// Flips the last hex-ish character of an identifier, keeping its length and,
/// for UUIDs, its version and variant nibbles.
fn mutate(value: &str) -> String {
    let mut chars: Vec<char> = value.chars().collect();
    let last = chars.len() - 1;
    chars[last] = match chars[last] {
        'a' => 'b',
        _ => 'a',
    };
    chars.into_iter().collect()
}

fn generate() -> Value {
    let key = signing_key();
    let public_key = *key.verifying_key().as_bytes();
    let key_id = ed25519_key_id(&public_key).expect("a valid key has a thumbprint");

    let built = bodies::bodies(key_id.as_str(), &public_key);
    let expected = unpinned_body_names();
    let actual: Vec<&str> = built.iter().map(|(name, _, _)| *name).collect();
    assert_eq!(
        actual, expected,
        "the generated set must be exactly the domains no other fixture pins"
    );

    let cases: Vec<Value> = built
        .into_iter()
        .map(|(body_name, mutation_field, body)| case(body_name, mutation_field, body))
        .collect();

    json!({
        "schemaVersion": 1,
        "purpose": "Known-answer vectors for the ten active signing domains carried by no \
                    control entry. Produced by the server's own transcript code; see \
                    tests/chat_protocol_signing_domain_vectors.rs.",
        "regenerateCommand": format!(
            "{REGENERATE_ENV}=1 cargo test --test chat_protocol_signing_domain_vectors"
        ),
        "signatureAlgorithm": "Ed25519",
        "publicKeyHex": hex::encode(public_key),
        "keyId": key_id.as_str(),
        "provenance": {
            "sourceLexicon": CANONICAL_SOURCE_LEXICON_PATH,
            "sourceLexiconMirror": CANONICAL_LEXICON_PATH,
            "sourceLexiconRevision": CANONICAL_SOURCE_LEXICON_REVISION,
            "sourceCorpusRevision": CANONICAL_SOURCE_CORPUS_REVISION,
            "sourceLexiconSha256": canonical_lexicon_sha256()
        },
        "cases": cases,
    })
}

fn rendered(document: &Value) -> String {
    let mut text = serde_json::to_string_pretty(document).expect("the document serializes");
    text.push('\n');
    text
}

#[test]
fn the_ten_active_signing_domain_vectors_are_server_products_and_match_the_fixture() {
    let document = generate();
    let text = rendered(&document);

    if std::env::var_os(REGENERATE_ENV).is_some() {
        fs::write(fixture_path(), &text).expect("the fixture is writable");
        return;
    }

    assert_eq!(
        text, FIXTURE,
        "the frozen vectors no longer match what the server produces; regenerate with \
         `{REGENERATE_ENV}=1` only after explaining why a signing product moved"
    );
}

#[test]
fn every_signing_domain_now_has_a_server_vector() {
    // The accounting the vendoring clients rely on: fourteen domains were
    // already pinned by `mls_chat_contract_vectors.json`, these ten are the
    // remainder, and together they are the whole enum. Keep the expected set
    // explicit so adding an enum arm or silently dropping a fixture fails here.
    let expected = BTreeSet::from([
        "deviceEnrollmentBody",
        "keyPackageReplenishmentBody",
        "deviceRevocationBody",
        "blobUploadPreparationBody",
        "blobDeletionBody",
        "creationBody",
        "commitTransitionBody",
        "policyTransitionBody",
        "participantAcceptanceBody",
        "applicationSendBody",
        "typingBody",
        "metadataTransitionBody",
        "resetRequestBody",
        "resetActivationBody",
        "leafRecoveryRequestBody",
        "leafRecoveryCancellationBody",
        "leafRecoveryFulfillmentBody",
        "conversationCloseBody",
        "leaveRequestBody",
        "zeroLeafLeaveBody",
        "leaveCancellationBody",
        "leaveCommitFulfillmentBody",
        "welcomeAcknowledgementBody",
        "welcomeRejectionBody",
    ]);
    let enum_kinds: BTreeSet<&'static str> = SignedMutationKind::ALL
        .into_iter()
        .filter(|kind| *kind != SignedMutationKind::DeviceAuthenticationRebind)
        .map(SignedMutationKind::body_name)
        .collect();
    assert_eq!(enum_kinds, expected, "the enum operation set drifted");

    let control: BTreeSet<&'static str> = ControlEntryKind::ALL
        .into_iter()
        .map(|kind| kind.signed_kind().body_name())
        .collect();
    let unpinned = unpinned_body_names();
    assert_eq!(control.len(), 13);
    assert_eq!(unpinned.len(), 10);
    assert_eq!(
        control.len() + 1 + unpinned.len(),
        SignedMutationKind::ALL.len() - 1
    );
    assert_eq!(
        unpinned,
        vec![
            "deviceEnrollmentBody",
            "keyPackageReplenishmentBody",
            "deviceRevocationBody",
            "blobUploadPreparationBody",
            "applicationSendBody",
            "typingBody",
            "leafRecoveryRequestBody",
            "leafRecoveryCancellationBody",
            "welcomeAcknowledgementBody",
            "welcomeRejectionBody",
        ]
    );

    let mut fixture_kinds = existing_contract_fixture_body_names();
    assert_eq!(
        fixture_kinds.len(),
        14,
        "the existing corpus must cover 14 kinds"
    );
    let fixture: Value = serde_json::from_str(FIXTURE).expect("the vector fixture parses");
    for case in fixture["cases"].as_array().expect("ten cases") {
        fixture_kinds.insert(
            case["bodyName"]
                .as_str()
                .expect("case body name")
                .to_owned(),
        );
    }
    assert_eq!(
        fixture_kinds,
        expected.iter().map(|name| (*name).to_owned()).collect(),
        "the two server fixtures must cover every SignedMutationKind"
    );
}

#[test]
fn each_frozen_case_verifies_and_its_declared_mutation_breaks_the_signature() {
    use ed25519_dalek::{Signature, VerifyingKey};

    let fixture: Value = serde_json::from_str(FIXTURE).expect("the fixture parses");
    let cases = fixture["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 10);

    let public_key: [u8; 32] = hex::decode(fixture["publicKeyHex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let verifier = VerifyingKey::from_bytes(&public_key).unwrap();

    for case in cases {
        let name = case["bodyName"].as_str().unwrap();
        let domain = case["signingDomain"].as_str().unwrap().as_bytes();
        let transcript = hex::decode(case["transcriptHex"].as_str().unwrap()).unwrap();
        let mutated = hex::decode(case["mutatedTranscriptHex"].as_str().unwrap()).unwrap();
        let signature =
            Signature::from_slice(&hex::decode(case["signatureHex"].as_str().unwrap()).unwrap())
                .unwrap();

        assert_eq!(&transcript[..domain.len()], domain, "{name}: domain prefix");
        assert_eq!(domain.last(), Some(&0), "{name}: domain is NUL-terminated");
        verifier
            .verify_strict(&transcript, &signature)
            .unwrap_or_else(|error| panic!("{name}: frozen transcript must verify: {error}"));
        assert!(
            verifier.verify_strict(&mutated, &signature).is_err(),
            "{name}: the declared mutation must break the signature"
        );
        assert_ne!(
            transcript, mutated,
            "{name}: the mutation must change bytes"
        );
        assert!(
            !case["uuidByteFields"].as_array().unwrap().is_empty(),
            "{name}: every body carries at least one UUID-typed field"
        );
    }
}

#[test]
fn the_domains_are_distinct_and_none_collides_with_a_control_domain() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let mut seen = BTreeSet::new();
    for case in fixture["cases"].as_array().unwrap() {
        let domain = case["signingDomain"].as_str().unwrap();
        assert!(seen.insert(domain), "{domain} pinned twice");
        let kind = SignedMutationKind::ALL
            .into_iter()
            .find(|kind| kind.body_name() == case["bodyName"].as_str().unwrap())
            .expect("the body name names a live kind");
        assert_eq!(
            kind.domain(),
            domain.as_bytes(),
            "the fixture's domain must be the server's, NUL included"
        );
    }
    assert_eq!(seen.len(), 10);
}

#[test]
fn every_frozen_wrapper_strictly_decodes_to_its_declared_products() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("the fixture parses");
    let public_key: [u8; 32] = hex::decode(fixture["publicKeyHex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    for case in fixture["cases"].as_array().unwrap() {
        let name = case["bodyName"].as_str().unwrap();
        let wrapper = case["wrapper"].as_object().expect("exact wrapper object");
        assert_eq!(
            wrapper.len(),
            2,
            "{name}: wrapper must have exactly two fields"
        );
        let body = wrapper.get("body").expect("wrapper body");
        let signature = wrapper
            .get("signature")
            .and_then(Value::as_str)
            .expect("wrapper signature base64");
        assert_eq!(body, &case["body"], "{name}: wrapper body drift");
        assert_eq!(
            hex::encode(
                STANDARD
                    .decode(signature)
                    .expect("wrapper signature decodes")
            ),
            case["signatureHex"],
            "{name}: wrapper signature drift"
        );

        let wrapper_bytes = serde_json::to_vec(&Value::Object(wrapper.clone())).unwrap();
        assert_eq!(
            hex::encode(&wrapper_bytes),
            case["wrapperJsonHex"],
            "{name}: exact wrapper bytes drift"
        );
        let verified = decode_and_verify_signed_mutation(&wrapper_bytes, &public_key)
            .unwrap_or_else(|error| panic!("{name}: strict wrapper decode failed: {error:?}"));
        let kind = SignedMutationKind::ALL
            .into_iter()
            .find(|kind| kind.body_name() == name)
            .expect("fixture body names a live mutation kind");
        assert_eq!(verified.kind(), kind, "{name}: kind");
        assert_eq!(verified.type_id(), case["body"]["$type"], "{name}: type");
        assert_eq!(
            verified.domain(),
            case["signingDomain"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            hex::encode(verified.canonical_projection()),
            case["canonicalUnsignedDagCborHex"],
            "{name}: canonical projection"
        );
        assert_eq!(
            hex::encode(verified.transcript_bytes()),
            case["transcriptHex"],
            "{name}: signing transcript"
        );
        assert_eq!(
            hex::encode(verified.request_digest()),
            case["canonicalRequestDigestHex"],
            "{name}: request digest"
        );
        assert_eq!(
            hex::encode(verified.signature()),
            case["signatureHex"],
            "{name}: signature"
        );
    }
}

#[test]
fn frozen_fixture_records_the_canonical_lexicon_provenance() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("the fixture parses");
    assert_eq!(
        fixture["provenance"]["sourceLexicon"],
        CANONICAL_SOURCE_LEXICON_PATH
    );
    assert_eq!(
        fixture["provenance"]["sourceLexiconMirror"],
        CANONICAL_LEXICON_PATH
    );
    assert_eq!(
        fixture["provenance"]["sourceLexiconRevision"],
        CANONICAL_SOURCE_LEXICON_REVISION
    );
    assert_eq!(
        fixture["provenance"]["sourceCorpusRevision"],
        CANONICAL_SOURCE_CORPUS_REVISION
    );
    assert_eq!(
        fixture["provenance"]["sourceLexiconSha256"], CANONICAL_SOURCE_LEXICON_SHA256,
        "lexicon drift must invalidate the pinned fixture"
    );
    assert_eq!(
        canonical_lexicon_sha256(),
        CANONICAL_SOURCE_LEXICON_SHA256,
        "the server mirror must match the canonical PetrelCatbird source"
    );
}

#[test]
fn enrollment_vector_round_trips_through_strict_authority_and_derives_key_hash() {
    let (case, wrapper_bytes, public_key) = frozen_wrapper("deviceEnrollmentBody");
    let enrollment = decode_and_verify_enrollment_body(&wrapper_bytes)
        .expect("the frozen enrollment wrapper must pass strict authority verification");
    let body = &case["body"];
    let expected_key_hash: [u8; 32] = Sha256::digest(public_key).into();
    let derived_key_id = ed25519_key_id(&public_key).unwrap();

    assert_eq!(
        enrollment.subject().as_str(),
        body["actorDid"].as_str().unwrap()
    );
    assert_eq!(
        enrollment.device_id().as_str(),
        body["deviceId"].as_str().unwrap()
    );
    assert_eq!(
        enrollment.key_id().as_str(),
        body["keyId"].as_str().unwrap()
    );
    assert_eq!(enrollment.key_id(), &derived_key_id);
    assert_eq!(enrollment.signing_key_sha256(), &expected_key_hash);
    assert_eq!(
        hex::encode(enrollment.enrollment_transcript_sha256()),
        case["canonicalRequestDigestHex"]
    );
    assert_eq!(
        enrollment.accepted_wrapper_bytes(),
        wrapper_bytes.as_slice()
    );
}

#[test]
fn application_send_vector_operation_id_is_message_id_not_generic_idempotency() {
    let (case, wrapper_bytes, public_key) = frozen_wrapper("applicationSendBody");
    let mutation = decode_and_verify_signed_mutation(&wrapper_bytes, &public_key)
        .expect("the frozen application-send wrapper must pass strict verification");
    let canonical = decode_canonical_signed_mutation(&wrapper_bytes)
        .expect("the frozen application-send wrapper must pass strict decoding");
    let body = &case["body"];
    let expected = body["messageId"].as_str().expect("message ID");

    assert_eq!(mutation.kind(), SignedMutationKind::ApplicationSend);
    assert!(body.get("idempotencyKey").is_none());
    assert_eq!(canonical.operation_id().unwrap().as_str(), expected);
    match mutation.projection() {
        VerifiedMutationProjection::ApplicationSend(application) => {
            assert_eq!(application.message_id().as_str(), expected);
        }
        _ => panic!("unexpected application-send projection"),
    }
}
#[test]
fn participant_acceptance_server_fields_accepts_bytes_envelope() {
    use transcript::CanonicalControlServerFields;
    let bound_coord = serde_json::json!({
        "conversationId": "009ffa92-4bf9-4307-bf26-e7428d53d800",
        "generation": 0,
        "stateVersion": 1,
        "groupId": {
            "$bytes": "GTu3NbweIIBe3sJv720BZEA6YzwPxYTXjYBVB+7EB2M="
        },
        "epoch": 0,
        "groupContextHash": {
            "$bytes": "dNZwPlqizJADC1l9N2VV1Yna6sSzNnXdvkCiguL6B6k="
        },
        "confirmationTag": {
            "$bytes": "ixtwb78YjjWEJ/Y98+/2pCKNi4qpXyo6FVExKruDDRo="
        },
        "lifecycle": "active"
    });
    let recovery_json = serde_json::json!({
        "recovery": {
            "recoveryRequestId": "6e24c3fd-82b0-4bd4-ad50-8bfe56475481",
            "conversationId": "009ffa92-4bf9-4307-bf26-e7428d53d800",
            "requesterDid": "did:plc:z3rwldqwosuekdwpn45d6uly",
            "requesterDeviceId": "1ad34b5a-3c93-4201-a5c9-b0951b7bc92a",
            "recoveryKind": "add",
            "boundCoordinate": bound_coord,
            "reservation": {
                "recoveryRequestId": "6e24c3fd-82b0-4bd4-ad50-8bfe56475481",
                "conversationId": "009ffa92-4bf9-4307-bf26-e7428d53d800",
                "boundCoordinate": bound_coord,
                "requesterDid": "did:plc:z3rwldqwosuekdwpn45d6uly",
                "requesterDeviceId": "1ad34b5a-3c93-4201-a5c9-b0951b7bc92a",
                "requesterKeyId": "IMTxmsDtJ8LfOrIm1Ptfp_KCnOUyTwzVYRpnQwODXeE",
                "requesterAuthGeneration": 1,
                "keyPackageRef": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                "purpose": "leafRecovery",
                "status": "active",
                "expiresAt": "2026-08-21T08:30:00.000Z",
                "keyPackage": {
                    "framing": "mlsMessage",
                    "contentType": "keyPackage",
                    "bytes": "AQEBAQEBAQE=",
                    "sha256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "keyPackageRef": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                }
            },
            "status": "open",
            "requestedAt": "2026-08-21T08:21:23.455Z",
            "expiresAt": "2026-08-21T08:30:00.000Z"
        }
    });
    let sf = CanonicalControlServerFields::decode(
        ControlEntryKind::ParticipantAcceptance,
        &serde_json::to_vec(&recovery_json).unwrap(),
    )
    .expect("must decode serverFields with bytes envelopes");
    assert!(!sf.canonical_dag_cbor().is_empty());
}

#[test]
fn live_submit_transition_fulfillment_decodes_and_verifies() {
    let raw_file: serde_json::Value = serde_json::from_slice(
        &std::fs::read("/tmp/last_blue.catbird.chat.submitTransition_body.json")
            .expect("read last body"),
    )
    .unwrap();
    let signed_req_bytes = serde_json::to_vec(&raw_file["signedRequest"]).unwrap();
    let public_key =
        hex::decode("e39325e78052440a7b49e33c39c9a228309678e2cf0f69f67d734d245c7d416d").unwrap();
    let res = decode_and_verify_signed_mutation(&signed_req_bytes, &public_key);
    println!(
        "decode_and_verify_signed_mutation fulfillment result: {:?}",
        res
    );
    assert!(res.is_ok());
}
