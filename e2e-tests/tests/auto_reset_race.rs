//! Phase 5 Task 28 — E2E first-responder bootstrap race tolerance.
//!
//! Three members race to call `bootstrapResetGroup` against the same
//! post-reset row. The server's `FOR UPDATE` + `group_info IS NULL` sentinel
//! (handler at `mls-ds/server/src/handlers/mls_chat/bootstrap_reset_group.rs`)
//! must serialize them so exactly one returns HTTP 200 and the others return
//! HTTP 409 `AlreadyBootstrapped`.
//!
//! Per team-lead: "fully testable without log grep" — response status alone
//! discriminates the race outcome.
//!
//! Setup uses the admin `resetGroup` endpoint (called WITHOUT inline
//! `groupInfo`) to produce the same post-reset state as the auto-reset path:
//! `id = originalConvoId`, `group_id = newGroupId`, `group_info = NULL`,
//! member roster preserved. This bypasses the quorum-pyramid setup (which
//! needs real epoch_authenticators) while exercising the exact bootstrap
//! handler path the auto-reset firing leads into.
//!
//! Required for execution:
//!   - `E2E_BASE_URL` = http://localhost:3001
//!   - `E2E_JWT_SECRET` matches server `JWT_SECRET`
//!   - server env: `ENFORCE_LXM=false`
//!
//! Run: `cargo test --test auto_reset_race -- --ignored --nocapture`

use base64::Engine;
use mls_e2e_tests::{init_tracing, TestClient};
use serde_json::json;
use std::sync::Arc;
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
async fn three_clients_race_to_bootstrap_one_wins_others_409() {
    init_tracing();
    let client = test_client();

    // ── 1. Three users create a convo (alice = admin/creator). ───────────
    let mut alice = client.test_user("race-alice");
    let mut bob = client.test_user("race-bob");
    let mut carol = client.test_user("race-carol");
    for u in [&mut alice, &mut bob, &mut carol] {
        u.register_device().await.expect("register_device");
        u.publish_key_packages(3).await.expect("publish_key_packages");
    }

    let convo = alice
        .create_convo(&[bob.did.clone(), carol.did.clone()], None)
        .await
        .expect("create_convo");
    let original_convo_id = convo["groupId"].as_str().expect("groupId").to_string();

    // ── 2. Admin (alice) triggers a manual reset WITHOUT inline groupInfo.
    //   Result: row sits at (id=originalConvoId, group_id=newGroupId,
    //   group_info=NULL) — same shape as a post-auto-reset row.
    let new_group_id = format!("{:032x}", Uuid::new_v4().as_u128());
    let reset_body = json!({
        "convoId": original_convo_id,
        "newGroupId": new_group_id,
        "cipherSuite": CIPHER_SUITE,
        // `groupInfo` deliberately omitted so server stores NULL.
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
        "admin resetGroup should succeed: body={}",
        reset_json
    );

    // ── 3. All three members race bootstrapResetGroup concurrently. ──────
    // Each client supplies its own arbitrary GroupInfo bytes. The server
    // can't validate cryptographically (DS-blind per RFC 9750 §5.2); race
    // arbitration is purely SQL-level.
    let make_body = |label: &str| {
        let group_info_bytes = format!("test-group-info-from-{}", label).into_bytes();
        let group_info_b64 = base64::engine::general_purpose::STANDARD.encode(&group_info_bytes);
        json!({
            "originalConvoId": original_convo_id,
            "newGroupId": new_group_id,
            "cipherSuite": CIPHER_SUITE,
            "groupInfo": group_info_b64,
            "members": [alice.did.clone(), bob.did.clone(), carol.did.clone()],
            "currentEpoch": 1,
        })
    };

    let alice_body = make_body("alice");
    let bob_body = make_body("bob");
    let carol_body = make_body("carol");

    let alice = Arc::new(alice);
    let bob = Arc::new(bob);
    let carol = Arc::new(carol);

    let alice_clone = Arc::clone(&alice);
    let bob_clone = Arc::clone(&bob);
    let carol_clone = Arc::clone(&carol);

    let (alice_resp, bob_resp, carol_resp) = tokio::join!(
        async move {
            alice_clone
                .raw_post_xrpc("blue.catbird.mlsChat.bootstrapResetGroup", &alice_body)
                .await
        },
        async move {
            bob_clone
                .raw_post_xrpc("blue.catbird.mlsChat.bootstrapResetGroup", &bob_body)
                .await
        },
        async move {
            carol_clone
                .raw_post_xrpc("blue.catbird.mlsChat.bootstrapResetGroup", &carol_body)
                .await
        },
    );

    let mut statuses: Vec<u16> = Vec::with_capacity(3);
    for (label, r) in [
        ("alice", alice_resp),
        ("bob", bob_resp),
        ("carol", carol_resp),
    ] {
        let resp = r.unwrap_or_else(|e| panic!("{} request errored: {:?}", label, e));
        statuses.push(resp.status().as_u16());
    }
    statuses.sort_unstable();

    let n_200 = statuses.iter().filter(|&&s| s == 200).count();
    let n_409 = statuses.iter().filter(|&&s| s == 409).count();
    let n_other = statuses.iter().filter(|&&s| s != 200 && s != 409).count();

    assert_eq!(
        n_200, 1,
        "exactly one bootstrap call must win (got statuses {:?})",
        statuses
    );
    assert!(
        n_409 >= 1,
        "at least one bootstrap call must lose with 409 AlreadyBootstrapped (got statuses {:?})",
        statuses
    );
    assert_eq!(
        n_other, 0,
        "all three responses must be 200 or 409 (got statuses {:?})",
        statuses
    );

    // ASSERT (Phase 6, journalctl):
    //   journalctl -u catbird-mls-server -o cat \
    //     | grep -c '"bootstrap_succeeded"' == 1
    //   journalctl -u catbird-mls-server -o cat \
    //     | grep -c '"bootstrap_409_already_bootstrapped"' == 2
    //   (or >= 1, depending on whether non-winning callers retry)
}
