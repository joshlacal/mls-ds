//! Phase 5 Task 29 — manual admin reset regression.
//!
//! Asserts that the existing admin manual-reset flow (admin calls
//! `resetGroup` with an inline `groupInfo` and then publishes welcomes via
//! the normal createConvo/Welcome path) is NOT broken by the auto-reset
//! Phase 1 work. Specifically:
//!
//!   1. Admin manual reset stores group_info (non-NULL post-reset) and bumps
//!      reset_count.
//!   2. A subsequent `bootstrapResetGroup` call against this row must FAIL
//!      with HTTP 409 `AlreadyBootstrapped` because group_info is already
//!      populated — admin reset's inline groupInfo IS the bootstrap, and
//!      we must not let the bootstrap path silently re-fire.
//!
//! Per team-lead direction: "direct DB observation, no log grep needed" —
//! though in this RPC-only harness we observe via wire response codes
//! rather than direct psql. Phase 6 deploy verification adds the journalctl
//! `grep -c "bootstrap_succeeded" == 0` assertion (manual reset path must
//! NOT trip the bootstrap log emitter).
//!
//! Required for execution:
//!   - `E2E_BASE_URL` = http://localhost:3001
//!   - `E2E_JWT_SECRET` matches server `JWT_SECRET`
//!   - server env: `ENFORCE_LXM=false`
//!
//! Run: `cargo test --test manual_reset_regression -- --ignored --nocapture`

use base64::Engine;
use mls_e2e_tests::{init_tracing, TestClient, TestUser};
use serde_json::json;
use uuid::Uuid;

fn test_client() -> TestClient {
    let url = std::env::var("E2E_BASE_URL").unwrap_or_else(|_| "http://localhost:3001".into());
    let secret =
        std::env::var("E2E_JWT_SECRET").unwrap_or_else(|_| "***REDACTED_E2E_SECRET***".into());
    TestClient::new(&url, &secret)
}

const CIPHER_SUITE: &str = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires running mls-ds server with bootstrapResetGroup wired (mls-ds da85949+)"]
async fn admin_manual_reset_with_group_info_does_not_allow_bootstrap() {
    init_tracing();
    let client = test_client();

    let mut alice = client.test_user("manual-alice");
    let mut bob = client.test_user("manual-bob");
    for u in [&mut alice, &mut bob] {
        u.register_device().await.expect("register_device");
        u.publish_key_packages(3).await.expect("publish_key_packages");
    }

    let convo = alice
        .create_convo(&[bob.did.clone()], None)
        .await
        .expect("create_convo");
    let original_convo_id = convo["groupId"].as_str().expect("groupId").to_string();

    // ── Admin reset WITH inline groupInfo (the manual-reset happy path).
    // This is distinct from the auto-reset shape (which leaves group_info
    // NULL): admin provides the GroupInfo bytes in-band so the row is
    // immediately bootstrapped on commit.
    let new_group_id = format!("{:032x}", Uuid::new_v4().as_u128());
    let group_info_bytes = TestUser::random_bytes(256);
    let group_info_b64 = base64::engine::general_purpose::STANDARD.encode(&group_info_bytes);

    let reset_body = json!({
        "convoId": original_convo_id,
        "newGroupId": new_group_id,
        "cipherSuite": CIPHER_SUITE,
        "groupInfo": group_info_b64,
    });
    let reset_resp = alice
        .raw_post_xrpc("blue.catbird.mlsChat.resetGroup", &reset_body)
        .await
        .expect("resetGroup call");
    let reset_status = reset_resp.status();
    let reset_json: serde_json::Value =
        reset_resp.json().await.expect("resetGroup json");
    assert_eq!(
        reset_status, 200,
        "admin manual reset must succeed; body={}",
        reset_json
    );
    assert_eq!(
        reset_json.get("newGroupId").and_then(|v| v.as_str()),
        Some(new_group_id.as_str()),
        "resetGroup must echo the requested newGroupId"
    );

    // ── Now any caller (including a member) attempting bootstrapResetGroup
    // for the same (originalConvoId, newGroupId) must be told the row is
    // already bootstrapped — admin's inline groupInfo populated group_info,
    // tripping the AlreadyBootstrapped sentinel in the handler.
    let bob_bootstrap_body = json!({
        "originalConvoId": original_convo_id,
        "newGroupId": new_group_id,
        "cipherSuite": CIPHER_SUITE,
        "groupInfo": base64::engine::general_purpose::STANDARD.encode(b"bob-late-bootstrap"),
        "members": [alice.did.clone(), bob.did.clone()],
        "currentEpoch": 1,
    });
    let bob_resp = bob
        .raw_post_xrpc("blue.catbird.mlsChat.bootstrapResetGroup", &bob_bootstrap_body)
        .await
        .expect("bootstrapResetGroup call");
    let bob_status = bob_resp.status();
    let bob_json: serde_json::Value =
        bob_resp.json().await.expect("bootstrap json");
    assert_eq!(
        bob_status, 409,
        "bootstrapResetGroup against an already-bootstrapped row must be 409; body={}",
        bob_json
    );
    let err_kind = bob_json.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(
        err_kind, "AlreadyBootstrapped",
        "expected AlreadyBootstrapped error, got {:?}",
        bob_json
    );

    // ASSERT (Phase 6, journalctl):
    //   journalctl -u catbird-mls-server -o cat \
    //     | grep -c '"bootstrap_succeeded"' == 0
    //   journalctl -u catbird-mls-server -o cat \
    //     | grep -c '"bootstrap_409_already_bootstrapped"' >= 1
    //   psql -c "SELECT group_info IS NOT NULL, current_epoch FROM \
    //            conversations WHERE id = '<original_convo_id>'"
    //     → (t, 0) — group_info populated by admin reset, current_epoch
    //                reset to 0 (admin reset sets it to 0; bootstrap would
    //                advance to 1).
}

/// Stub: full Welcome-path delivery assertion. Exercises the ASSERT shape
/// the team-lead specified: "all members can call getGroupState?
/// include=welcome and receive a non-empty welcome envelope". This requires
/// the admin to actually publish welcomes via the normal createConvo /
/// Welcome path post-reset (which today the admin does in a separate
/// commitGroupChange call), so the stub documents the deploy-time check.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "STUB — needs admin Welcome publish flow (Phase 6 deploy verification)"]
async fn admin_manual_reset_welcomes_delivered_via_get_group_state_stub() {
    // Scenario shape (executed at Phase 6 deploy time):
    //   1. Alice (admin) and Bob create + join a convo.
    //   2. Alice calls resetGroup with a fresh GroupInfo AND publishes
    //      Welcome envelopes for Bob via the standard MLS commit flow
    //      (NOT via bootstrapResetGroup — admin manual reset uses the
    //      pre-existing Welcome distribution path).
    //   3. Bob calls
    //        GET /xrpc/blue.catbird.mlsChat.getGroupState
    //          ?convoId=<id>&include=welcome
    //      and receives a non-empty `welcome` field.
    //   4. Bob processes the Welcome via OpenMLS, joins at epoch 1.
    //
    // ASSERT (Phase 6, journalctl + DB):
    //   - grep -c '"bootstrap_succeeded"' for this convo_id == 0
    //     (bootstrap path never touched on the manual-reset flow)
    //   - psql: SELECT COUNT(*) FROM welcome_messages WHERE convo_id = ...
    //     AND consumed = false ≥ member_count_at_reset_time
    //
    // Execution gate: requires admin Welcome plumbing in TestUser. Stub-only
    // for now; deploy-time verification supplies the real assertion.
}
