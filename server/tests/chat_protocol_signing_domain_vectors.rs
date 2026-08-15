//! Known-answer vectors for the eleven signing domains that no control-entry
//! case covers.
//!
//! `mls_chat_contract_vectors.json` pins fourteen of the twenty-five signing
//! domains: the thirteen control entries, plus `CATBIRD-CHAT-BLOB-DELETE` from
//! its one `signedMutator` case. The other eleven — `CATBIRD-CHAT-MESSAGE`, the
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

use transcript::{
    decode_and_verify_signed_mutation, decode_canonical_signed_mutation, ControlEntryKind,
    SignedMutationKind,
};
use validation::ed25519_key_id;

const FIXTURE: &str = include_str!("fixtures/mls_chat_signing_domain_vectors.json");
const REGENERATE_ENV: &str = "CATBIRD_REGENERATE_SIGNING_DOMAIN_VECTORS";

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
            *kind != SignedMutationKind::BlobDeletion && !control.contains(kind.body_name())
        })
        .map(SignedMutationKind::body_name)
        .collect()
}

/// Signs `body` through the server's own projection and returns the wrapper
/// bytes together with the canonical products the server derived.
fn sign_through_production(body: &Value) -> (Vec<u8>, Value) {
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
    (wrapper_bytes, products)
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
    let (_, products) = sign_through_production(&body);

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
        "purpose": "Known-answer vectors for the eleven signing domains carried by no \
                    control entry. Produced by the server's own transcript code; see \
                    tests/chat_protocol_signing_domain_vectors.rs.",
        "regenerateCommand": format!(
            "{REGENERATE_ENV}=1 cargo test --test chat_protocol_signing_domain_vectors"
        ),
        "signatureAlgorithm": "Ed25519",
        "publicKeyHex": hex::encode(public_key),
        "keyId": key_id.as_str(),
        "cases": cases,
    })
}

fn rendered(document: &Value) -> String {
    let mut text = serde_json::to_string_pretty(document).expect("the document serializes");
    text.push('\n');
    text
}

#[test]
fn the_eleven_signing_domain_vectors_are_server_products_and_match_the_fixture() {
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
    // already pinned by `mls_chat_contract_vectors.json`, these eleven are the
    // remainder, and together they are the whole enum.
    let control: BTreeSet<&'static str> = ControlEntryKind::ALL
        .into_iter()
        .map(|kind| kind.signed_kind().body_name())
        .collect();
    let unpinned = unpinned_body_names();
    assert_eq!(control.len(), 13);
    assert_eq!(unpinned.len(), 11);
    assert_eq!(
        control.len() + 1 + unpinned.len(),
        SignedMutationKind::ALL.len()
    );
    assert_eq!(
        unpinned,
        vec![
            "deviceEnrollmentBody",
            "keyPackageReplenishmentBody",
            "deviceAuthenticationRebindBody",
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
}

#[test]
fn each_frozen_case_verifies_and_its_declared_mutation_breaks_the_signature() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let fixture: Value = serde_json::from_str(FIXTURE).expect("the fixture parses");
    let cases = fixture["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 11);

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
    assert_eq!(seen.len(), 11);
}
