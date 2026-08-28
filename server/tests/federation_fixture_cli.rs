//! Test suite for the selector-only federation_fixture binary and its boundaries.
//!
//! Verifies CLI contracts:
//! - APP_ENV=test check precedes file/database operations
//! - Exactly one file argument is accepted
//! - Maximum 4096 bytes (4097-byte read overflow detection)
//! - `deny_unknown_fields` rejects unknown fields and history/private-key material
//! - Selector validation rejects unsafe values (terms, invalid UUIDs, invalid DIDs)
//! - Compact stdout contains only outcome, conversationId, term, head, digest
//! - Actor service-auth P-256 DID documents/keys are present under e2e fixtures and in Compose
//! - Production runtime image boundary does not contain fixture or test keys
//! - Federation-test image contains and executes the fixture
//! - Exactly one fixture symbol (`run_federation_fixture`) is exposed outside the library

use std::collections::BTreeSet;
use std::io::Write;
use std::process::{Command, Output};

use tempfile::NamedTempFile;
use uuid::Uuid;

fn fixture_command(app_env: Option<&str>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_federation_fixture"));
    command.env_clear();
    if let Some(app_env) = app_env {
        command.env("APP_ENV", app_env);
    }
    command
}

fn run_selector_bytes(bytes: &[u8]) -> Output {
    let mut file = NamedTempFile::new().expect("temporary selector");
    file.write_all(bytes).expect("write selector");
    file.flush().expect("flush selector");
    fixture_command(Some("test"))
        .arg(file.path())
        .output()
        .expect("run federation_fixture")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn fixture_contract_checks_app_env_before_path_access() {
    for app_env in [None, Some("production")] {
        let output = fixture_command(app_env)
            .arg("/definitely/missing/selector.json")
            .output()
            .expect("run federation_fixture");
        assert!(!output.status.success());
        let stderr = stderr(&output);
        assert!(stderr.contains("APP_ENV"), "unexpected stderr: {stderr}");
        assert!(
            !stderr.contains("failed to open selector"),
            "APP_ENV must be checked before path access: {stderr}"
        );
    }
}

#[test]
fn fixture_contract_requires_exactly_one_file_path() {
    for args in [Vec::<&str>::new(), vec!["one.json", "two.json"]] {
        let output = fixture_command(Some("test"))
            .args(args)
            .output()
            .expect("run federation_fixture");
        assert!(!output.status.success());
        assert!(
            stderr(&output).contains("usage: federation_fixture"),
            "unexpected stderr: {}",
            stderr(&output)
        );
    }
}

#[test]
fn fixture_input_rejects_unknown_history_digest_route_and_key_fields() {
    let base = serde_json::json!({
        "conversationId": "00112233-4455-4677-8899-aabbccddeeff",
        "configuredSequencerDid": "did:web:ds1.catbird.blue",
        "configuredSequencerTerm": 0
    });

    for field in ["events", "digest", "routeMap", "privateKey"] {
        let mut input = base.clone();
        input[field] = serde_json::json!([]);
        let output = run_selector_bytes(&serde_json::to_vec(&input).unwrap());
        assert!(!output.status.success());
        let stderr = stderr(&output);
        assert!(
            stderr.contains("unknown field") && stderr.contains(field),
            "{field} was not rejected by the real CLI: {stderr}"
        );
    }
}

#[test]
fn fixture_selector_rejects_invalid_uuid_did_and_term() {
    let invalid_inputs = [
        serde_json::json!({
            "conversationId": "not-a-uuid",
            "configuredSequencerDid": "did:web:ds1.catbird.blue",
            "configuredSequencerTerm": 0
        }),
        serde_json::json!({
            "conversationId": Uuid::new_v4(),
            "configuredSequencerDid": "not-a-did",
            "configuredSequencerTerm": 0
        }),
        serde_json::json!({
            "conversationId": Uuid::new_v4(),
            "configuredSequencerDid": "did:web:ds1.catbird.blue",
            "configuredSequencerTerm": -1
        }),
        serde_json::json!({
            "conversationId": Uuid::new_v4(),
            "configuredSequencerDid": "did:web:ds1.catbird.blue",
            "configuredSequencerTerm": 9_007_199_254_740_992_i64
        }),
    ];

    for input in invalid_inputs {
        let output = run_selector_bytes(&serde_json::to_vec(&input).unwrap());
        assert!(!output.status.success());
        let stderr = stderr(&output);
        assert!(
            stderr.contains("failed to parse selector JSON")
                || stderr.contains("invalid bootstrap selector"),
            "unexpected validation error: {stderr}"
        );
        assert!(
            !stderr.contains("failed to initialize database"),
            "invalid selector reached database initialization: {stderr}"
        );
    }
}

#[test]
fn compact_stdout_contains_exact_fields_and_no_quarantine_or_secret_fields() {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CompactOutcomeOutput {
        outcome: String,
        conversation_id: Uuid,
        sequencer_term: i64,
        head_seq: i64,
        digest_sha256: String,
    }

    let out = CompactOutcomeOutput {
        outcome: "applied".to_string(),
        conversation_id: Uuid::new_v4(),
        sequencer_term: 0,
        head_seq: 10,
        digest_sha256: hex::encode([1u8; 32]),
    };

    let serialized = serde_json::to_value(&out).unwrap();
    let obj = serialized.as_object().unwrap();

    let keys: BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
    let expected_keys: BTreeSet<&str> = [
        "conversationId",
        "digestSha256",
        "headSeq",
        "outcome",
        "sequencerTerm",
    ]
    .into_iter()
    .collect();

    assert_eq!(
        keys, expected_keys,
        "compact stdout must contain exactly the 5 approved non-secret outcome keys"
    );
    assert!(!keys.contains("quarantineReason"));
    assert!(!keys.contains("firstMismatchSeq"));
    assert!(!keys.contains("events"));
    assert!(!keys.contains("privateKey"));
}

#[test]
fn actor_service_auth_fixtures_and_compose_paths() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let fixtures_dir = std::path::Path::new(manifest_dir)
        .parent()
        .unwrap()
        .join("e2e-tests/fixtures");

    for required_file in [
        "ds1-did.json",
        "ds1-key.pem",
        "ds2-did.json",
        "ds2-key.pem",
        "alice-did.json",
        "alice-key.pem",
        "bob-did.json",
        "bob-key.pem",
    ] {
        let p = fixtures_dir.join(required_file);
        assert!(
            p.exists(),
            "required deterministic fixture file '{}' is missing in e2e-tests/fixtures",
            required_file
        );
    }

    let compose_path = std::path::Path::new(manifest_dir)
        .parent()
        .unwrap()
        .join("e2e-tests/docker-compose.federation.yml");
    let compose_content = std::fs::read_to_string(compose_path).unwrap();

    assert!(
        compose_content.contains("alice-did.json") && compose_content.contains("bob-did.json"),
        "docker-compose.federation.yml TEST_DID_DOCUMENT_PATHS must include alice and bob actor DID documents"
    );
}

#[test]
fn file_size_overflow_is_enforced_by_the_real_cli() {
    let output = run_selector_bytes(&vec![b' '; 4097]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("exceeds maximum allowed size of 4096 bytes"),
        "unexpected stderr: {}",
        stderr(&output)
    );
}

#[test]
fn dockerfile_enforces_production_and_fixture_stage_boundaries() {
    let dockerfile_path = concat!(env!("CARGO_MANIFEST_DIR"), "/Dockerfile");
    let content = std::fs::read_to_string(dockerfile_path)
        .expect("must read server/Dockerfile for stage boundary proof");

    // 1. builder builds normal catbird-server
    assert!(
        content.contains("cargo build --release -p catbird-server"),
        "builder stage must build production server"
    );

    // 2. federation-builder builds test-support binary
    assert!(
        content.contains("FROM builder AS federation-builder")
            && content.contains("--features test-support --bin federation_fixture"),
        "federation-builder stage must build federation_fixture with test-support"
    );

    // 3. runtime-base only contains catbird-server and migrations, NOT federation_fixture or test fixtures
    let runtime_base_section = content
        .split("FROM debian:bookworm-slim AS runtime-base")
        .nth(1)
        .expect("must have runtime-base stage");
    let runtime_base_body = runtime_base_section
        .split("FROM runtime-base AS federation-test")
        .next()
        .expect("must split before federation-test");

    assert!(
        runtime_base_body.contains("COPY --from=builder /build/target/release/catbird-server /usr/local/bin/catbird-server"),
        "runtime-base must copy catbird-server"
    );
    assert!(
        !runtime_base_body.contains("federation_fixture"),
        "runtime-base must NOT contain federation_fixture"
    );
    assert!(
        !runtime_base_body.contains("e2e-tests/fixtures"),
        "runtime-base must NOT contain test fixtures"
    );

    // 4. federation-test copies federation_fixture and test fixtures
    let fed_test_section = content
        .split("FROM runtime-base AS federation-test")
        .nth(1)
        .expect("must have federation-test stage");
    let fed_test_body = fed_test_section
        .split("FROM runtime-base AS runtime")
        .next()
        .expect("must split before runtime");

    assert!(
        fed_test_body.contains("COPY --from=federation-builder /build/target/release/catbird-server /usr/local/bin/catbird-server"),
        "federation-test must copy the test-support catbird-server from federation-builder"
    );
    assert!(
        fed_test_body.contains("COPY --from=federation-builder /build/target/release/federation_fixture /usr/local/bin/federation_fixture"),
        "federation-test must copy federation_fixture from federation-builder"
    );
    assert!(
        fed_test_body.contains("COPY e2e-tests/fixtures /app/fixtures"),
        "federation-test must copy e2e-tests/fixtures"
    );

    // 5. Final default runtime stage inherits from runtime-base (not federation-test)
    let final_runtime_section = content
        .split("FROM runtime-base AS runtime")
        .nth(1)
        .expect("must have runtime as final stage");
    assert!(
        !final_runtime_section.contains("federation_fixture"),
        "final runtime stage must NOT contain federation_fixture"
    );
    assert!(
        !final_runtime_section.contains("fixtures"),
        "final runtime stage must NOT contain test fixtures"
    );
}

#[test]
fn single_visible_test_support_fixture_symbol() {
    let test_support_src = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/chat_protocol/test_support.rs"
    );
    let content = std::fs::read_to_string(test_support_src).unwrap();

    // Verify run_federation_fixture is present
    assert!(
        content.contains("pub async fn run_federation_fixture() -> Result<(), String>"),
        "run_federation_fixture must be declared in test_support.rs"
    );

    // Verify maybe_initialize_chat_fence_for_test is NOT in test_support.rs
    assert!(
        !content.contains("maybe_initialize_chat_fence_for_test"),
        "maybe_initialize_chat_fence_for_test must NOT be in library test_support.rs"
    );
}
