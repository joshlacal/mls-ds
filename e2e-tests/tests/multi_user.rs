//! Multi-user E2E tests for mls-ds.
//! Require a running server — run with: `cargo test --test multi_user -- --ignored`

use mls_e2e_tests::{init_tracing, TestClient, TestUser};

fn test_client() -> TestClient {
    let url = std::env::var("E2E_BASE_URL").unwrap_or_else(|_| "http://localhost:3001".into());
    let secret =
        std::env::var("E2E_JWT_SECRET").unwrap_or_else(|_| "test-secret-for-e2e".into());
    TestClient::new(&url, &secret)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_three_user_group() {
    init_tracing();
    let client = test_client();

    // 1. Create 3 users, register devices, publish key packages
    let mut alice = client.test_user("alice");
    let mut bob = client.test_user("bob");
    let mut charlie = client.test_user("charlie");

    alice.register_device().await.expect("alice register");
    bob.register_device().await.expect("bob register");
    charlie.register_device().await.expect("charlie register");

    for user in [&alice, &bob, &charlie] {
        
        user.publish_key_packages(3)
            .await
            .expect("publish_key_packages");
    }

    // 2. Alice creates a 3-person conversation
    let welcome = TestUser::random_bytes(256);
    let convo = alice
        .create_convo(&[bob.did.clone(), charlie.did.clone()], Some(&welcome))
        .await
        .expect("create 3-user convo");
    let convo_id = convo["groupId"]
        .as_str()
        .expect("groupId")
        .to_string();

    // 3. Each user sends a message
    let ct_alice = TestUser::padded_ciphertext(b"hello from alice");
    alice
        .send_message(&convo_id, &ct_alice, 0)
        .await
        .expect("alice send");

    let ct_bob = TestUser::padded_ciphertext(b"hello from bob");
    bob.send_message(&convo_id, &ct_bob, 0)
        .await
        .expect("bob send");

    let ct_charlie = TestUser::padded_ciphertext(b"hello from charlie");
    charlie
        .send_message(&convo_id, &ct_charlie, 0)
        .await
        .expect("charlie send");

    // 4. Each user retrieves messages — expect at least 3
    for (name, user) in [("alice", &alice), ("bob", &bob), ("charlie", &charlie)] {
        let resp = user
            .get_messages(&convo_id, None)
            .await
            .unwrap_or_else(|e| panic!("{name} get_messages: {e}"));
        let messages = resp["messages"].as_array().expect("messages array");
        assert!(
            messages.len() >= 3,
            "{name} expected >= 3 messages, got {}",
            messages.len()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_user_in_multiple_convos() {
    init_tracing();
    let client = test_client();

    // 1. Create 3 users
    let mut alice = client.test_user("alice");
    let mut bob = client.test_user("bob");
    let mut charlie = client.test_user("charlie");

    alice.register_device().await.expect("alice register");
    bob.register_device().await.expect("bob register");
    charlie.register_device().await.expect("charlie register");

    for user in [&alice, &bob, &charlie] {
        
        user.publish_key_packages(3)
            .await
            .expect("publish_key_packages");
    }

    // 2. Alice creates convo with Bob
    let welcome1 = TestUser::random_bytes(256);
    let convo1 = alice
        .create_convo(&[bob.did.clone()], Some(&welcome1))
        .await
        .expect("create convo with bob");
    let convo_id_1 = convo1["groupId"]
        .as_str()
        .expect("groupId 1")
        .to_string();

    // 3. Alice creates a separate convo with Charlie
    let welcome2 = TestUser::random_bytes(256);
    let convo2 = alice
        .create_convo(&[charlie.did.clone()], Some(&welcome2))
        .await
        .expect("create convo with charlie");
    let convo_id_2 = convo2["groupId"]
        .as_str()
        .expect("groupId 2")
        .to_string();

    // 4. Alice lists conversations — should see both
    let alice_convos = alice.get_convos().await.expect("alice get_convos");
    let convo_list = alice_convos["conversations"].as_array().expect("convos array");
    let ids: Vec<&str> = convo_list
        .iter()
        .filter_map(|c| c["groupId"].as_str())
        .collect();
    assert!(ids.contains(&convo_id_1.as_str()), "missing convo 1");
    assert!(ids.contains(&convo_id_2.as_str()), "missing convo 2");

    // 5. Send messages in both convos and verify isolation
    let ct1 = TestUser::padded_ciphertext(b"msg in convo1");
    alice
        .send_message(&convo_id_1, &ct1, 0)
        .await
        .expect("send to convo1");

    let ct2 = TestUser::padded_ciphertext(b"msg in convo2");
    alice
        .send_message(&convo_id_2, &ct2, 0)
        .await
        .expect("send to convo2");

    // Bob should see the message in convo1
    let bob_msgs = bob
        .get_messages(&convo_id_1, None)
        .await
        .expect("bob get_messages convo1");
    assert!(
        !bob_msgs["messages"]
            .as_array()
            .expect("array")
            .is_empty(),
        "bob should see messages in convo1"
    );

    // Charlie should see the message in convo2
    let charlie_msgs = charlie
        .get_messages(&convo_id_2, None)
        .await
        .expect("charlie get_messages convo2");
    assert!(
        !charlie_msgs["messages"]
            .as_array()
            .expect("array")
            .is_empty(),
        "charlie should see messages in convo2"
    );
}
