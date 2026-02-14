//! Happy-path E2E tests for mls-ds.
//! Require a running server — run with: `cargo test --test full_flow -- --ignored`

use mls_e2e_tests::{init_tracing, TestClient, TestUser};

fn test_client() -> TestClient {
    let url = std::env::var("E2E_BASE_URL").unwrap_or_else(|_| "http://localhost:3001".into());
    let secret =
        std::env::var("E2E_JWT_SECRET").unwrap_or_else(|_| "test-secret-for-e2e".into());
    TestClient::new(&url, &secret)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_full_messaging_flow() {
    init_tracing();
    let client = test_client();

    // 1. Create two users
    let mut alice = client.test_user("alice");
    let mut bob = client.test_user("bob");

    // 2. Register devices
    alice.register_device().await.expect("alice register_device");
    bob.register_device().await.expect("bob register_device");

    // 3. Publish extra key packages (5 each)
    alice
        .publish_key_packages(5)
        .await
        .expect("alice publish_key_packages");
    bob.publish_key_packages(5)
        .await
        .expect("bob publish_key_packages");

    // 4. Alice creates a conversation with Bob
    let welcome = TestUser::random_bytes(256);
    let convo = alice
        .create_convo(&[bob.did.clone()], Some(&welcome))
        .await
        .expect("alice create_convo");
    let convo_id = convo["groupId"]
        .as_str()
        .expect("groupId in response")
        .to_string();

    // 5. Alice sends 3 messages
    for i in 0..3 {
        let payload = format!("alice-msg-{i}");
        let ct = TestUser::padded_ciphertext(payload.as_bytes());
        alice
            .send_message(&convo_id, &ct, 0)
            .await
            .unwrap_or_else(|e| panic!("alice send_message {i}: {e}"));
    }

    // 6. Bob retrieves messages — verify count
    let msgs = bob
        .get_messages(&convo_id, None)
        .await
        .expect("bob get_messages");
    let messages = msgs["messages"].as_array().expect("messages array");
    assert!(
        messages.len() >= 3,
        "expected at least 3 messages, got {}",
        messages.len()
    );

    // Remember the last sequence number for later pagination
    let last_seq = messages
        .last()
        .and_then(|m| m["seq"].as_i64())
        .expect("seq on last message");

    // 7. Bob sends a reply
    let reply = TestUser::padded_ciphertext(b"bob-reply");
    bob.send_message(&convo_id, &reply, 0)
        .await
        .expect("bob send_message");

    // 8. Alice retrieves messages since the last seq she knew about
    let new_msgs = alice
        .get_messages(&convo_id, Some(last_seq))
        .await
        .expect("alice get_messages since seq");
    let new_messages = new_msgs["messages"].as_array().expect("messages array");
    assert!(
        !new_messages.is_empty(),
        "expected at least 1 new message from bob"
    );

    // 9. Both users list conversations — convo should appear
    let alice_convos = alice.get_convos().await.expect("alice get_convos");
    let alice_convo_list = alice_convos["conversations"].as_array().expect("conversations array");
    assert!(
        alice_convo_list.iter().any(|c| c["groupId"] == convo_id),
        "alice should see the conversation"
    );

    let bob_convos = bob.get_convos().await.expect("bob get_convos");
    let bob_convo_list = bob_convos["conversations"].as_array().expect("convos array");
    assert!(
        bob_convo_list.iter().any(|c| c["groupId"] == convo_id),
        "bob should see the conversation"
    );

    // 10. Update read cursors (using a generated ULID as cursor value)
    // The server expects ULID-format cursors from the event stream.
    // In a real flow, these would come from SSE/WS subscription events.
    // For now, generate a valid ULID to verify the endpoint works.
    let now_cursor = ulid::Ulid::new().to_string();
    alice
        .update_cursor(&convo_id, &now_cursor)
        .await
        .expect("alice update_cursor");
    bob.update_cursor(&convo_id, &now_cursor)
        .await
        .expect("bob update_cursor");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_register_multiple_devices() {
    init_tracing();
    let client = test_client();

    // Register 3 devices for the same DID by calling register_device multiple times.
    // Each call generates a fresh deviceUuid so the server should track them separately.
    let mut user = client.test_user("multi-device");

    let r1 = user
        .register_device()
        .await
        .expect("first register_device");
    let device_id_1 = r1["deviceId"]
        .as_str()
        .expect("deviceId in first response")
        .to_string();

    // Reset device_id so the next register generates a new UUID
    user.device_id = None;
    let r2 = user
        .register_device()
        .await
        .expect("second register_device");
    let device_id_2 = r2["deviceId"]
        .as_str()
        .expect("deviceId in second response")
        .to_string();

    user.device_id = None;
    let r3 = user
        .register_device()
        .await
        .expect("third register_device");
    let device_id_3 = r3["deviceId"]
        .as_str()
        .expect("deviceId in third response")
        .to_string();

    // All three device IDs should be distinct
    assert_ne!(device_id_1, device_id_2, "device 1 and 2 should differ");
    assert_ne!(device_id_2, device_id_3, "device 2 and 3 should differ");
    assert_ne!(device_id_1, device_id_3, "device 1 and 3 should differ");
}
