#![cfg(feature = "test-support")]

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn get_fixture_binary_path() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_federation_fixture") {
        return PathBuf::from(path);
    }
    // Fallback: look in target directory relative to CARGO_MANIFEST_DIR
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let debug_path = manifest_dir
        .parent()
        .unwrap()
        .join("target/debug/federation_fixture");
    if debug_path.exists() {
        return debug_path;
    }
    let release_path = manifest_dir
        .parent()
        .unwrap()
        .join("target/release/federation_fixture");
    if release_path.exists() {
        return release_path;
    }
    PathBuf::from(env!("CARGO_BIN_EXE_federation_fixture"))
}

#[test]
fn app_env_must_be_test_before_file_access() {
    let bin = get_fixture_binary_path();
    // Non-existent path: if APP_ENV check didn't precede file open, this would fail with file not found.
    // With APP_ENV check preceding file access, it fails with APP_ENV error.
    let output = Command::new(&bin)
        .env("APP_ENV", "production")
        .arg("/nonexistent/file/path.json")
        .output()
        .expect("execute federation_fixture binary");

    assert!(!output.status.success(), "expected failure when APP_ENV is production");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("APP_ENV=test") || stderr.contains("APP_ENV"),
        "stderr should mention APP_ENV requirement; got: {stderr}"
    );
    assert!(
        !stderr.contains("failed to open fixture file"),
        "file open must not happen before APP_ENV check; got: {stderr}"
    );
}

#[test]
fn missing_argument_fails() {
    let bin = get_fixture_binary_path();
    let output = Command::new(&bin)
        .env("APP_ENV", "test")
        .output()
        .expect("execute federation_fixture binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing fixture file path argument"),
        "stderr should mention missing argument; got: {stderr}"
    );
}

#[test]
fn extra_arguments_fail() {
    let bin = get_fixture_binary_path();
    let output = Command::new(&bin)
        .env("APP_ENV", "test")
        .arg("arg1.json")
        .arg("arg2.json")
        .output()
        .expect("execute federation_fixture binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected extra arguments"),
        "stderr should mention unexpected extra arguments; got: {stderr}"
    );
}

#[test]
fn nonexistent_file_fails() {
    let bin = get_fixture_binary_path();
    let output = Command::new(&bin)
        .env("APP_ENV", "test")
        .arg("/path/that/does/not/exist/fixture.json")
        .output()
        .expect("execute federation_fixture binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to open fixture file"),
        "stderr should mention failed to open file; got: {stderr}"
    );
}

#[test]
fn file_exceeding_4096_bytes_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("overflow.json");
    let mut file = File::create(&file_path).expect("create file");
    // Write 4097 bytes of spaces
    file.write_all(&vec![b' '; 4097]).expect("write file");

    let bin = get_fixture_binary_path();
    let output = Command::new(&bin)
        .env("APP_ENV", "test")
        .arg(&file_path)
        .output()
        .expect("execute federation_fixture binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exceeds maximum allowed size of 4096 bytes"),
        "stderr should mention size limit; got: {stderr}"
    );
}

#[test]
fn unknown_fields_rejected_by_deny_unknown_fields() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("unknown_fields.json");
    let mut file = File::create(&file_path).expect("create file");
    let content = r#"{
        "conversationId": "00112233-4455-4677-8899-aabbccddeeff",
        "configuredSequencerDid": "did:web:ds1.catbird.blue",
        "configuredSequencerTerm": 0,
        "unexpectedExtraField": "malicious payload"
    }"#;
    file.write_all(content.as_bytes()).expect("write file");

    let bin = get_fixture_binary_path();
    let output = Command::new(&bin)
        .env("APP_ENV", "test")
        .arg(&file_path)
        .output()
        .expect("execute federation_fixture binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown field"),
        "stderr should mention unknown field error; got: {stderr}"
    );
}

#[test]
fn negative_sequencer_term_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("negative_term.json");
    let mut file = File::create(&file_path).expect("create file");
    let content = r#"{
        "conversationId": "00112233-4455-4677-8899-aabbccddeeff",
        "configuredSequencerDid": "did:web:ds1.catbird.blue",
        "configuredSequencerTerm": -1
    }"#;
    file.write_all(content.as_bytes()).expect("write file");

    let bin = get_fixture_binary_path();
    let output = Command::new(&bin)
        .env("APP_ENV", "test")
        .arg(&file_path)
        .output()
        .expect("execute federation_fixture binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("configuredSequencerTerm must be non-negative"),
        "stderr should mention non-negative requirement; got: {stderr}"
    );
}

#[test]
fn non_uuid_v4_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("nil_uuid.json");
    let mut file = File::create(&file_path).expect("create file");
    // Nil UUID (all zeros) has version 0, not 4
    let content = r#"{
        "conversationId": "00000000-0000-0000-0000-000000000000",
        "configuredSequencerDid": "did:web:ds1.catbird.blue",
        "configuredSequencerTerm": 0
    }"#;
    file.write_all(content.as_bytes()).expect("write file");

    let bin = get_fixture_binary_path();
    let output = Command::new(&bin)
        .env("APP_ENV", "test")
        .arg(&file_path)
        .output()
        .expect("execute federation_fixture binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("conversationId must be a UUIDv4"),
        "stderr should mention UUIDv4 requirement; got: {stderr}"
    );
}

#[test]
fn malformed_did_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("malformed_did.json");
    let mut file = File::create(&file_path).expect("create file");
    let content = r#"{
        "conversationId": "00112233-4455-4677-8899-aabbccddeeff",
        "configuredSequencerDid": "not-a-valid-did",
        "configuredSequencerTerm": 0
    }"#;
    file.write_all(content.as_bytes()).expect("write file");

    let bin = get_fixture_binary_path();
    let output = Command::new(&bin)
        .env("APP_ENV", "test")
        .arg(&file_path)
        .output()
        .expect("execute federation_fixture binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("configuredSequencerDid must start with 'did:web:' or 'did:plc:'"),
        "stderr should mention DID format requirement; got: {stderr}"
    );
}
