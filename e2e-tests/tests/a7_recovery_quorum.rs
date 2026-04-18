//! ADR-002 §A7.5 — End-to-end quorum auto-reset scenario stub.
//!
//! This test drives the full RPC surface for the per-DID quorum auto-reset
//! flow: multiple users report recovery failures with valid
//! epoch_authenticators, and the server auto-resets the group on the 67%
//! threshold.
//!
//! Requires:
//!   - Running server at $E2E_BASE_URL (default: http://localhost:3001)
//!   - 20260418_001 migration applied (reset_votes + epoch_authenticators
//!     + auto_reset_history tables)
//!   - Test JWT secret in $E2E_JWT_SECRET
//!
//! Run with: cargo test --test a7_recovery_quorum -- --ignored
//!
//! This is a STUB — full MLS commit machinery isn't wired through
//! TestUser yet. The shape here documents what the full test must
//! eventually cover:
//!
//!   1. Three users create + join a convo. Each runs enough commits
//!      that commit_group_change persists known-good authenticators
//!      into epoch_authenticators.
//!   2. User1 calls reportRecoveryFailure with a valid authenticator.
//!      Expect { recorded: true, autoResetTriggered: false,
//!               failureCount: 1, memberCount: 3 }.
//!   3. User2 calls reportRecoveryFailure with a valid authenticator.
//!      Expect { recorded: true, autoResetTriggered: true,
//!               failureCount: 2, memberCount: 3 }.
//!      Server emits GroupResetEvent via SSE.
//!   4. Bonus: user without authenticator → reason=missing_authenticator;
//!      vote not counted, rate-limit slot not consumed.
//!   5. Bonus: authenticator from 4+ epochs ago →
//!      reason=stale_authenticator; vote not counted.

use mls_e2e_tests::{init_tracing, TestClient};

fn test_client() -> TestClient {
    let url = std::env::var("E2E_BASE_URL").unwrap_or_else(|_| "http://localhost:3001".into());
    let secret =
        std::env::var("E2E_JWT_SECRET").unwrap_or_else(|_| "***REDACTED_E2E_SECRET***".into());
    TestClient::new(&url, &secret)
}

/// Smoke test: the endpoint exists and accepts the new `epochAuthenticator`
/// input field. This verifies the lexicon + server wiring end-to-end without
/// requiring a full MLS setup.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires running mls-ds server with A7 migration applied"]
async fn test_report_recovery_failure_accepts_epoch_authenticator() {
    init_tracing();
    let client = test_client();

    let mut alice = client.test_user("a7-alice");
    let mut bob = client.test_user("a7-bob");
    alice.register_device().await.expect("alice register");
    bob.register_device().await.expect("bob register");
    alice.publish_key_packages(3).await.expect("alice keypkgs");
    bob.publish_key_packages(3).await.expect("bob keypkgs");

    let convo = alice
        .create_convo(&[bob.did.clone()], None)
        .await
        .expect("create_convo");
    let convo_id = convo["groupId"].as_str().expect("groupId").to_string();

    // Post with an obviously-synthetic authenticator: the server should accept
    // the wire (HTTP 200) and return reason="stale_authenticator" since we
    // haven't recorded any real authenticators yet.
    let body = serde_json::json!({
        "convoId": convo_id,
        "failureType": "external_commit_exhausted",
        "epochAuthenticator": "aa".repeat(32),
    });
    let resp = alice
        .raw_post_xrpc("blue.catbird.mlsChat.reportRecoveryFailure", &body)
        .await
        .expect("reportRecoveryFailure call");

    let status = resp.status();
    let json: serde_json::Value = resp.json().await.expect("json body");

    assert_eq!(status, 200, "should be HTTP 200");
    assert_eq!(
        json.get("recorded").and_then(|v| v.as_bool()),
        Some(false),
        "synthetic authenticator should NOT be recorded"
    );
    assert_eq!(
        json.get("reason").and_then(|v| v.as_str()),
        Some("stale_authenticator"),
        "expected stale_authenticator reason"
    );
}

/// Smoke test: old clients (no authenticator) get reason=missing_authenticator.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires running mls-ds server with A7 migration applied"]
async fn test_report_recovery_failure_missing_authenticator() {
    init_tracing();
    let client = test_client();

    let mut alice = client.test_user("a7-missing");
    let mut bob = client.test_user("a7-missing-bob");
    alice.register_device().await.expect("alice register");
    bob.register_device().await.expect("bob register");
    alice.publish_key_packages(3).await.expect("alice keypkgs");
    bob.publish_key_packages(3).await.expect("bob keypkgs");

    let convo = alice
        .create_convo(&[bob.did.clone()], None)
        .await
        .expect("create_convo");
    let convo_id = convo["groupId"].as_str().expect("groupId").to_string();

    // Pre-A7 client shape — no epochAuthenticator field.
    let body = serde_json::json!({
        "convoId": convo_id,
        "failureType": "external_commit_exhausted",
    });
    let resp = alice
        .raw_post_xrpc("blue.catbird.mlsChat.reportRecoveryFailure", &body)
        .await
        .expect("reportRecoveryFailure call");

    let status = resp.status();
    let json: serde_json::Value = resp.json().await.expect("json body");

    assert_eq!(status, 200, "should be HTTP 200 (not 400)");
    assert_eq!(
        json.get("reason").and_then(|v| v.as_str()),
        Some("missing_authenticator"),
    );
}
