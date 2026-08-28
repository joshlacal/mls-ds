//! Executable guard for the clean `blue.catbird.chat` and `blue.catbird.mlsDS` Lexicon corpora.
//!
//! The Python companion freezes semantic shapes and runs negative mutations.
//! This test additionally parses every document with the same Jacquard parser
//! used by this repository and enforces an exact canonical/server manifest.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jacquard_lexicon::lexicon::LexiconDoc;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const PREFIX: &str = "blue.catbird.chat";

fn mls_ds_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("server must be inside mls-ds")
        .to_path_buf()
}

fn stack_root() -> PathBuf {
    mls_ds_root()
        .parent()
        .expect("mls-ds must be inside the isolated stack")
        .to_path_buf()
}

fn canonical_root() -> PathBuf {
    stack_root().join("PetrelCatbird/lexicons/blue/catbird/chat")
}

fn mirror_root() -> PathBuf {
    mls_ds_root().join("lexicon/blue/catbird/chat")
}

fn canonical_mls_ds_root() -> PathBuf {
    stack_root().join("PetrelCatbird/lexicons/blue/catbird/mlsDS")
}

fn mirror_mls_ds_root() -> PathBuf {
    mls_ds_root().join("lexicon/blue/catbird/mlsDS")
}

fn corpus(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let entries =
        fs::read_dir(root).unwrap_or_else(|error| panic!("must read {}: {error}", root.display()));
    entries
        .map(|entry| {
            let path = entry.expect("directory entry must be readable").path();
            let name = path
                .file_name()
                .expect("entry must have a filename")
                .to_string_lossy()
                .into_owned();
            assert!(name.ends_with(".json"), "unexpected corpus entry: {name}");
            let bytes = fs::read(&path)
                .unwrap_or_else(|error| panic!("must read {}: {error}", path.display()));
            (name, bytes)
        })
        .collect()
}

fn validate_corpus(corpus: &BTreeMap<String, Vec<u8>>, label: &str) {
    assert_eq!(
        corpus.len(),
        36,
        "{label}: thirty-six chat lexicon files are required"
    );
    for (filename, bytes) in corpus {
        let source = std::str::from_utf8(bytes)
            .unwrap_or_else(|error| panic!("{label}/{filename} must be UTF-8: {error}"));
        let value: Value = serde_json::from_str(source)
            .unwrap_or_else(|error| panic!("{label}/{filename} must be JSON: {error}"));
        let reparsed = serde_json::to_value(
            serde_json::from_str::<LexiconDoc<'_>>(source).unwrap_or_else(|error| {
                panic!("{label}/{filename} must parse as a Jacquard Lexicon: {error}")
            }),
        )
        .unwrap_or_else(|error| panic!("{label}/{filename} Lexicon must serialize: {error}"));
        assert_eq!(
            reparsed["lexicon"], value["lexicon"],
            "{label}/{filename} Lexicon version drift"
        );
        assert_eq!(reparsed["id"], value["id"], "{label}/{filename} NSID drift");
        let id = value["id"]
            .as_str()
            .unwrap_or_else(|| panic!("{label}/{filename} must have a string id"));
        assert!(
            id.starts_with(&format!("{PREFIX}.")),
            "wrong namespace in {label}/{filename}"
        );
        assert!(
            !source.contains("blue.catbird.mlsChatV2"),
            "retired namespace in {label}/{filename}"
        );
        assert!(
            !source.contains("authorizeAndBootstrapReset"),
            "retired reset endpoint in {label}/{filename}"
        );
    }
}

#[test]
fn canonical_and_server_corpora_parse_and_match_exactly() {
    let canonical = corpus(&canonical_root());
    validate_corpus(&canonical, "canonical");
    let mirror = corpus(&mirror_root());
    validate_corpus(&mirror, "mirror");
    assert_eq!(
        canonical, mirror,
        "server corpus must be an exact byte mirror"
    );

    let canonical_mls_ds = corpus(&canonical_mls_ds_root());
    assert_eq!(
        canonical_mls_ds.len(),
        14,
        "canonical mlsDS: fourteen files required"
    );
    assert_eq!(
        canonical_mls_ds,
        corpus(&mirror_mls_ds_root()),
        "server mlsDS corpus must be an exact byte mirror"
    );
}

#[test]
fn rfc8032_ed25519_vector_accepts_and_single_bit_mutation_rejects() {
    let vectors: Value = serde_json::from_slice(
        &fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/mls_chat_contract_vectors.json"),
        )
        .expect("contract vectors must be readable"),
    )
    .expect("contract vectors must be JSON");
    let vector = &vectors["ed25519"];
    let public: [u8; 32] = hex::decode(vector["publicKeyHex"].as_str().expect("public key hex"))
        .expect("public key must be hex")
        .try_into()
        .expect("public key must be 32 bytes");
    let message = hex::decode(vector["messageHex"].as_str().expect("message hex"))
        .expect("message must be hex");
    let signature = Signature::from_slice(
        &hex::decode(vector["signatureHex"].as_str().expect("signature hex"))
            .expect("signature must be hex"),
    )
    .expect("signature must be 64 bytes");
    let mutated = Signature::from_slice(
        &hex::decode(
            vector["mutatedSignatureHex"]
                .as_str()
                .expect("mutated signature hex"),
        )
        .expect("mutated signature must be hex"),
    )
    .expect("mutated signature must be 64 bytes");
    let verifier = VerifyingKey::from_bytes(&public).expect("public key must be valid");
    verifier
        .verify_strict(&message, &signature)
        .expect("RFC 8032 vector must verify");
    assert!(
        verifier.verify(&message, &mutated).is_err(),
        "mutated signature must fail"
    );

    let mutator = &vectors["signedMutator"];
    let mutator_public: [u8; 32] = hex::decode(
        mutator["publicKeyHex"]
            .as_str()
            .expect("mutator public key hex"),
    )
    .expect("mutator public key must be hex")
    .try_into()
    .expect("mutator public key must be 32 bytes");
    let mutator_signature = Signature::from_slice(
        &hex::decode(
            mutator["signatureHex"]
                .as_str()
                .expect("mutator signature hex"),
        )
        .expect("mutator signature must be hex"),
    )
    .expect("mutator signature must be 64 bytes");
    let transcript = hex::decode(
        mutator["transcriptHex"]
            .as_str()
            .expect("mutator transcript hex"),
    )
    .expect("mutator transcript must be hex");
    let mutated_transcript = hex::decode(
        mutator["mutatedTranscriptHex"]
            .as_str()
            .expect("mutated transcript hex"),
    )
    .expect("mutated transcript must be hex");
    let mutator_verifier =
        VerifyingKey::from_bytes(&mutator_public).expect("mutator public key must be valid");
    mutator_verifier
        .verify_strict(&transcript, &mutator_signature)
        .expect("canonical signed-mutator transcript must verify");
    assert!(
        mutator_verifier
            .verify_strict(&mutated_transcript, &mutator_signature)
            .is_err(),
        "one-field mutator transcript mutation must fail"
    );
    assert_eq!(
        &transcript[..b"CATBIRD-CHAT-BLOB-DELETE\0".len()],
        b"CATBIRD-CHAT-BLOB-DELETE\0"
    );
    let blob_id = hex::decode("018f3f6a7b2c4d918a5e0f123456789a").unwrap();
    assert!(
        transcript
            .windows(blob_id.len())
            .any(|window| window == blob_id.as_slice()),
        "UUID-typed blobId must be raw bytes16 in the projection"
    );
}

#[test]
fn semantic_guard_and_negative_mutations_pass() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/mls_chat_lexicon_contract.py");
    let output = Command::new("python3")
        .arg("-B")
        .arg(&script)
        .output()
        .unwrap_or_else(|error| panic!("must run {}: {error}", script.display()));
    assert!(
        output.status.success(),
        "semantic contract guard failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
