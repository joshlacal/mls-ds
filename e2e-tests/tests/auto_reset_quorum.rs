//! Phase 5 Task 27 — E2E quorum auto-reset healing.
//!
//! Drives the full XRPC surface for the A7 quorum auto-reset flow against a
//! running mls-ds. Hybrid (b)+(c) per team-lead direction:
//!
//! - **Wire/behavior coverage** (executes when `--ignored` is passed):
//!   tests the XRPC paths exercised by the auto-reset machinery using only
//!   the existing `TestClient`/`TestUser` primitives. No new harness code.
//!
//! - **Stub coverage with Phase 6 verification comments** (also `#[ignore]`d):
//!   documents the full-quorum scenario shape and the journalctl assertions
//!   Phase 6 will run against the structured logs from task #21.
//!
//! Required for execution:
//!   - `E2E_BASE_URL` = http://localhost:3001 (or wherever mls-ds runs)
//!   - `E2E_JWT_SECRET` matches server `JWT_SECRET`
//!   - server env: `ENFORCE_LXM=false`, `ENFORCE_FAILURE_MODE_QUORUM=false`
//!     (interim posture per ADR-008 D1)
//!   - 20260418_001 migration applied (reset_votes, epoch_authenticators,
//!     auto_reset_history)
//!
//! Run: `cargo test --test auto_reset_quorum -- --ignored --nocapture`

use mls_e2e_tests::{init_tracing, TestClient};

fn test_client() -> TestClient {
    let url = std::env::var("E2E_BASE_URL").unwrap_or_else(|_| "http://localhost:3001".into());
    let secret =
        std::env::var("E2E_JWT_SECRET").unwrap_or_else(|_| "***REDACTED_E2E_SECRET***".into());
    TestClient::new(&url, &secret)
}

/// Wire test: 3-member convo, 2 of 3 members call reportRecoveryFailure with
/// synthetic (stale) epoch_authenticators. The server accepts the wire (HTTP
/// 200), returns `reason=stale_authenticator` for each, and does NOT fire an
/// auto-reset (votes don't count toward quorum without valid authenticators).
///
/// This exercises the dispatcher → actor → quorum-counting pipeline end-to-end
/// without requiring synthetic `commitGroupChange` runs to seed authenticators.
/// The full-quorum-with-real-authenticators scenario is covered by the
/// `#[ignore]`d stub below + Phase 6 deploy verification.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires running mls-ds server with A7 migration applied"]
async fn quorum_2of3_stale_authenticators_no_auto_reset() {
    init_tracing();
    let client = test_client();

    let mut alice = client.test_user("q2o3-alice");
    let mut bob = client.test_user("q2o3-bob");
    let mut carol = client.test_user("q2o3-carol");

    for u in [&mut alice, &mut bob, &mut carol] {
        u.register_device().await.expect("register_device");
        u.publish_key_packages(3).await.expect("publish_key_packages");
    }

    let convo = alice
        .create_convo(&[bob.did.clone(), carol.did.clone()], None)
        .await
        .expect("create_convo");
    let convo_id = convo["groupId"].as_str().expect("groupId").to_string();

    // Two members report unrecoverable failure with synthetic (stale)
    // authenticators. Each call must succeed at the wire level (HTTP 200) and
    // return reason=stale_authenticator (vote does not count toward quorum,
    // does not consume the per-DID 24h rate-limit slot).
    let mut stale_count = 0usize;
    for (label, voter) in [("alice", &alice), ("bob", &bob)] {
        let body = serde_json::json!({
            "convoId": convo_id,
            "failureType": "external_commit_exhausted",
            "epochAuthenticator": "aa".repeat(32),
        });
        let resp = voter
            .raw_post_xrpc("blue.catbird.mlsChat.reportRecoveryFailure", &body)
            .await
            .expect("reportRecoveryFailure call");
        assert_eq!(resp.status(), 200, "{} report should be HTTP 200", label);
        let json: serde_json::Value = resp.json().await.expect("json body");
        let reason = json.get("reason").and_then(|v| v.as_str()).unwrap_or("");
        let recorded = json.get("recorded").and_then(|v| v.as_bool()).unwrap_or(true);
        let auto_reset = json
            .get("autoResetTriggered")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        assert_eq!(reason, "stale_authenticator", "{} reason", label);
        assert!(!recorded, "{} should NOT be recorded with stale auth", label);
        assert!(
            !auto_reset,
            "{} stale-auth report must NOT trigger auto-reset",
            label
        );
        if reason == "stale_authenticator" {
            stale_count += 1;
        }
    }

    assert_eq!(
        stale_count, 2,
        "both stale-auth reports should classify as stale_authenticator"
    );

    // ASSERT (Phase 6, journalctl):
    //   journalctl -u catbird-mls-server -o cat | grep -c '"A7 vote recorded"' \
    //     | (each of the 2 reports emits exactly one "A7 vote recorded" with
    //        epoch_authenticator_match=false, rate_limited=false)
    //   journalctl -u catbird-mls-server -o cat | grep -c '"A7 auto-reset fired"' \
    //     | should be 0 — stale authenticators do not advance to firing
}

/// Stub: full-quorum auto-reset with valid authenticators. Documents the
/// shape of the scenario; full execution requires either (a) a TestUser
/// extension that runs `commit_group_change` to seed real authenticators or
/// (b) deploy-time verification against a real corrupted convo.
///
/// Phase 6 task #31 picks this up as a deploy-day journalctl assertion.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "STUB — full quorum needs real epoch_authenticators (Phase 6 deploy verification)"]
async fn quorum_full_auto_reset_heals_corrupted_conversation_stub() {
    // Scenario shape (executed at Phase 6 deploy time):
    //   1. Three users (alice, bob, carol) create + join a convo via the
    //      normal MLS flow. Each runs at least one commitGroupChange so the
    //      server persists known-good `epoch_authenticators` rows.
    //   2. Alice + Bob simulate unrecoverable failure: each calls
    //      reportRecoveryFailure with their last-good epoch_authenticator.
    //      First call returns {recorded:true, autoResetTriggered:false,
    //      failureCount:1, memberCount:3}.
    //      Second call hits the 67% quorum (2 of 3 distinct identity DIDs)
    //      and returns {recorded:true, autoResetTriggered:true,
    //      failureCount:2, memberCount:3, newGroupId:<hex>,
    //      resetGeneration:1}.
    //   3. Server emits SSE GroupResetEvent with the new group_id.
    //   4. Carol (the "lurker" not in the failure quorum) also receives the
    //      GroupResetEvent via SSE.
    //   5. One of {alice,bob,carol} wins the bootstrapResetGroup race; the
    //      other two see HTTP 409 AlreadyBootstrapped. (See Task #23 for
    //      the dedicated race test.)
    //
    // ASSERT (Phase 6, journalctl): the structured logs from task #21 fire
    //   in this order, exactly once per voter / per outcome:
    //
    //     # Two votes, both with epoch_authenticator_match=true
    //     journalctl -u catbird-mls-server -o cat \
    //       | grep -c '"A7 vote recorded".*epoch_authenticator_match=true' == 2
    //
    //     # Auto-reset fires exactly once
    //     journalctl -u catbird-mls-server -o cat \
    //       | grep -c '"A7 auto-reset fired"' == 1
    //
    //     # Post-reset state is NULL group_info exactly once
    //     journalctl -u catbird-mls-server -o cat \
    //       | grep -c '"A7 post-reset state".*group_info_present=false' == 1
    //
    //     # Exactly one client wins bootstrap, others see 409
    //     journalctl -u catbird-mls-server -o cat \
    //       | grep -c '"bootstrap_succeeded"' == 1
    //     journalctl -u catbird-mls-server -o cat \
    //       | grep -c '"bootstrap_409_already_bootstrapped"' >= 1
    //
    //     # group_info column should be non-NULL post-bootstrap
    //     psql -c "SELECT group_info IS NOT NULL FROM conversations \
    //              WHERE id = '<convo_id>'" → t

    // Execution gate: no-op until in-process commit_group_change wiring lands.
    // Marked #[ignore] so this never blocks CI; runs as a documentation anchor.
}
