//! Edge-case E2E tests for mls-ds.
//! Require a running server — run with: `cargo test --test edge_cases -- --ignored`

use mls_e2e_tests::{init_tracing, TestClient, TestUser};

fn test_client() -> TestClient {
    let url = std::env::var("E2E_BASE_URL").unwrap_or_else(|_| "http://localhost:3001".into());
    let secret =
        std::env::var("E2E_JWT_SECRET").unwrap_or_else(|_| "test-secret-for-e2e".into());
    TestClient::new(&url, &secret)
}

/// Sending a message without registering a device first should fail.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_message_without_device() {
    init_tracing();
    let client = test_client();

    // Set up a convo owner so we have a valid convo_id
    let mut owner = client.test_user("owner");
    owner.register_device().await.expect("owner register");

    let convo = owner
        .create_convo(&[], None)
        .await
        .expect("owner create_convo");
    let convo_id = convo["groupId"].as_str().expect("groupId").to_string();

    // Create a user who has NOT registered a device
    let unregistered = client.test_user("unregistered");
    let ct = TestUser::padded_ciphertext(b"should fail");

    let result = unregistered.send_message(&convo_id, &ct, 0).await;
    assert!(
        result.is_err(),
        "sending without device registration should error"
    );
}

/// Fetching messages from an empty conversation should return an empty array.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_empty_convo_messages() {
    init_tracing();
    let client = test_client();

    let mut alice = client.test_user("alice");
    alice.register_device().await.expect("register");

    let convo = alice
        .create_convo(&[], None)
        .await
        .expect("create_convo");
    let convo_id = convo["groupId"].as_str().expect("groupId");

    let resp = alice
        .get_messages(convo_id, None)
        .await
        .expect("get_messages on empty convo");
    let messages = resp["messages"].as_array().expect("messages array");
    assert!(
        messages.is_empty(),
        "expected 0 messages, got {}",
        messages.len()
    );
}

/// Registering the same user with different deviceUuids should yield different device IDs.
/// The mlsDid is `DID#deviceUuid`, so different devices produce different mlsDids.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_idempotent_device_registration() {
    init_tracing();
    let client = test_client();

    let mut user = client.test_user("idempotent");

    let r1 = user.register_device().await.expect("first register");
    let device_id_1 = r1["deviceId"].as_str().expect("deviceId 1").to_string();
    let mls_did_1 = user.mls_did.clone().expect("mlsDid after first register");

    // Register again — the library generates a new deviceUuid each time,
    // so the server should issue a new device_id.
    user.device_id = None;
    let r2 = user.register_device().await.expect("second register");
    let device_id_2 = r2["deviceId"].as_str().expect("deviceId 2").to_string();
    let mls_did_2 = user.mls_did.clone().expect("mlsDid after second register");

    // Both mlsDids should share the same DID prefix (before the # fragment)
    let prefix_1 = mls_did_1.split('#').next().unwrap();
    let prefix_2 = mls_did_2.split('#').next().unwrap();
    assert_eq!(
        prefix_1, prefix_2,
        "mlsDid DID prefix should be the same user DID across registrations"
    );

    // But the full mlsDid (DID#deviceUuid) will differ since each has a unique deviceUuid
    assert_ne!(
        mls_did_1, mls_did_2,
        "different deviceUuids should yield different mlsDids"
    );

    // Device IDs should differ since each has a unique deviceUuid
    assert_ne!(
        device_id_1, device_id_2,
        "different deviceUuids should yield different deviceIds"
    );
}

/// Sending a message at the maximum bucket size should succeed.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_large_message() {
    init_tracing();
    let client = test_client();

    let mut alice = client.test_user("alice");
    let mut bob = client.test_user("bob");
    alice.register_device().await.expect("alice register");
    bob.register_device().await.expect("bob register");

    let welcome = TestUser::random_bytes(256);
    let convo = alice
        .create_convo(&[bob.did.clone()], Some(&welcome))
        .await
        .expect("create_convo");
    let convo_id = convo["groupId"].as_str().expect("groupId");

    // 8192 * 10 = 81920 bytes — largest defined bucket
    let large_payload = TestUser::random_bytes(8192 * 10);
    let ct = TestUser::padded_ciphertext(&large_payload);
    assert_eq!(ct.len(), 81920, "should pad to 81920");

    alice
        .send_message(convo_id, &ct, 0)
        .await
        .expect("large message send should succeed");

    let resp = bob
        .get_messages(convo_id, None)
        .await
        .expect("bob get_messages");
    let messages = resp["messages"].as_array().expect("messages array");
    assert!(
        !messages.is_empty(),
        "bob should receive the large message"
    );
}

/// Pagination via sinceSeq: send many messages, then page through them.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_cursor_pagination() {
    init_tracing();
    let client = test_client();

    let mut alice = client.test_user("alice");
    let mut bob = client.test_user("bob");
    alice.register_device().await.expect("alice register");
    bob.register_device().await.expect("bob register");

    let welcome = TestUser::random_bytes(256);
    let convo = alice
        .create_convo(&[bob.did.clone()], Some(&welcome))
        .await
        .expect("create_convo");
    let convo_id = convo["groupId"].as_str().expect("groupId").to_string();

    // Send 10 messages (with small delay to avoid rate limiting)
    let total = 10;
    for i in 0..total {
        let payload = format!("msg-{i}");
        let ct = TestUser::padded_ciphertext(payload.as_bytes());
        alice
            .send_message(&convo_id, &ct, 0)
            .await
            .unwrap_or_else(|e| panic!("send msg {i}: {e}"));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Paginate through messages using sinceSeq
    let mut collected = Vec::new();
    let mut cursor: Option<i64> = None;
    let max_iterations = 50; // safety bound

    for _ in 0..max_iterations {
        let resp = bob
            .get_messages(&convo_id, cursor)
            .await
            .expect("paginated get_messages");
        let page = resp["messages"].as_array().expect("messages array");

        if page.is_empty() {
            break;
        }

        let last_seq = page.last().and_then(|m| m["seq"].as_i64());
        collected.extend(page.iter().cloned());

        match last_seq {
            Some(seq) => cursor = Some(seq),
            None => break,
        }

        // If we got fewer messages than the default page could hold, we're done
        if page.len() < 50 {
            break;
        }
    }

    assert!(
        collected.len() >= total,
        "expected at least {total} messages via pagination, got {}",
        collected.len()
    );

    // Verify sequence numbers are monotonically increasing
    let seqs: Vec<i64> = collected
        .iter()
        .filter_map(|m| m["seq"].as_i64())
        .collect();
    for window in seqs.windows(2) {
        assert!(
            window[0] < window[1],
            "sequence numbers should be monotonically increasing: {} >= {}",
            window[0],
            window[1]
        );
    }
}
