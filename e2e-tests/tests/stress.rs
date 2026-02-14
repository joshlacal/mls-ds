//! Stress tests for mls-ds.
//! Require a running server — run with: `cargo test --test stress -- --ignored`
//!
//! Configuration via environment variables:
//!   - `E2E_BASE_URL`     (default: http://localhost:3001)
//!   - `E2E_JWT_SECRET`   (default: test-secret-for-e2e)
//!   - `STRESS_USERS`     (default varies per test)
//!   - `STRESS_MESSAGES`  (default varies per test)

use mls_e2e_tests::{init_tracing, latency_stats, TestClient, TestUser};
use std::sync::Arc;
use std::time::Instant;
use tokio::task::JoinSet;

fn test_client() -> TestClient {
    let url = std::env::var("E2E_BASE_URL").unwrap_or_else(|_| "http://localhost:3001".into());
    let secret =
        std::env::var("E2E_JWT_SECRET").unwrap_or_else(|_| "test-secret-for-e2e".into());
    TestClient::new(&url, &secret)
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Stress test: N users sending M messages concurrently to the same conversation.
/// Measures throughput and latency.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn stress_message_throughput() {
    init_tracing();
    let client = test_client();
    let num_users = env_usize("STRESS_USERS", 10);
    let messages_per_user = env_usize("STRESS_MESSAGES", 50);

    // 1. Create N users, register devices, publish key packages
    let mut users = Vec::with_capacity(num_users);
    for i in 0..num_users {
        let mut user = client.test_user(&format!("stress-tput-{i}"));
        user.register_device()
            .await
            .unwrap_or_else(|e| panic!("register user {i}: {e}"));
        user.publish_key_packages(3)
            .await
            .unwrap_or_else(|e| panic!("publish kp user {i}: {e}"));
        users.push(user);
    }

    // 2. First user creates convo with all others
    let member_dids: Vec<String> = users[1..].iter().map(|u| u.did.clone()).collect();
    let welcome = TestUser::random_bytes(256);
    let convo = users[0]
        .create_convo(&member_dids, Some(&welcome))
        .await
        .expect("create convo");
    let convo_id = convo["groupId"].as_str().expect("groupId").to_string();

    // 3. All users send M messages concurrently
    let users: Vec<Arc<TestUser>> = users.into_iter().map(Arc::new).collect();
    let convo_id = Arc::new(convo_id);
    let total_messages = num_users * messages_per_user;

    let start = Instant::now();
    let mut set = JoinSet::new();

    for (user_idx, user) in users.iter().enumerate() {
        for msg_idx in 0..messages_per_user {
            let user = Arc::clone(user);
            let convo_id = Arc::clone(&convo_id);
            set.spawn(async move {
                let payload = format!("user{user_idx}-msg{msg_idx}");
                let ct = TestUser::padded_ciphertext(payload.as_bytes());
                let t = Instant::now();
                user.send_message(&convo_id, &ct, 0)
                    .await
                    .unwrap_or_else(|e| panic!("send user{user_idx} msg{msg_idx}: {e}"));
                t.elapsed()
            });
        }
    }

    let mut send_latencies = Vec::with_capacity(total_messages);
    while let Some(result) = set.join_next().await {
        send_latencies.push(result.expect("task panicked"));
    }
    let send_elapsed = start.elapsed();

    // 4. Each user retrieves all messages
    let mut read_latencies = Vec::with_capacity(num_users);
    let mut total_retrieved = 0;
    for (i, user) in users.iter().enumerate() {
        let t = Instant::now();
        let resp = user
            .get_messages(&convo_id, None)
            .await
            .unwrap_or_else(|e| panic!("get_messages user {i}: {e}"));
        read_latencies.push(t.elapsed());
        let count = resp["messages"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);
        total_retrieved += count;
    }

    // 5. Verify and report
    let msgs_per_sec = total_messages as f64 / send_elapsed.as_secs_f64();
    tracing::info!(
        "\n=== stress_message_throughput ===\n\
         {num_users} users × {messages_per_user} msgs = {total_messages} total\n\
         Send phase: {send_elapsed:?} ({msgs_per_sec:.1} msg/s)\n\
         Send latency: {}\n\
         Read latency: {}\n\
         Total messages retrieved across all users: {total_retrieved}\n\
         ================================",
        latency_stats(&mut send_latencies),
        latency_stats(&mut read_latencies),
    );

    // Each user should see all messages (they're all in the same convo)
    assert!(
        total_retrieved >= total_messages,
        "expected each user to see all {total_messages} messages, \
         but total retrieved across {num_users} users = {total_retrieved}"
    );
}

/// Stress test: Create a group with many members.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn stress_large_group() {
    init_tracing();
    let client = test_client();
    let num_members = env_usize("STRESS_USERS", 50);

    // 1. Create users, register devices, publish key packages
    let mut users = Vec::with_capacity(num_members);
    let reg_start = Instant::now();
    for i in 0..num_members {
        let mut user = client.test_user(&format!("stress-lg-{i}"));
        user.register_device()
            .await
            .unwrap_or_else(|e| panic!("register user {i}: {e}"));
        user.publish_key_packages(3)
            .await
            .unwrap_or_else(|e| panic!("publish kp user {i}: {e}"));
        users.push(user);
    }
    let reg_elapsed = reg_start.elapsed();

    // 2. First user creates convo with all others
    let member_dids: Vec<String> = users[1..].iter().map(|u| u.did.clone()).collect();
    let welcome = TestUser::random_bytes(256);
    let create_start = Instant::now();
    let convo = users[0]
        .create_convo(&member_dids, Some(&welcome))
        .await
        .expect("create large group convo");
    let create_elapsed = create_start.elapsed();
    let convo_id = convo["groupId"].as_str().expect("groupId").to_string();

    // 3. Send 10 messages from random members
    let num_messages = 10;
    let mut send_latencies = Vec::with_capacity(num_messages);
    for i in 0..num_messages {
        let user_idx = i % num_members;
        let ct = TestUser::padded_ciphertext(format!("large-group-msg-{i}").as_bytes());
        let t = Instant::now();
        users[user_idx]
            .send_message(&convo_id, &ct, 0)
            .await
            .unwrap_or_else(|e| panic!("send msg {i}: {e}"));
        send_latencies.push(t.elapsed());
    }

    // 4. All members retrieve messages
    let mut read_latencies = Vec::with_capacity(num_members);
    for (i, user) in users.iter().enumerate() {
        let t = Instant::now();
        let resp = user
            .get_messages(&convo_id, None)
            .await
            .unwrap_or_else(|e| panic!("get_messages user {i}: {e}"));
        read_latencies.push(t.elapsed());
        let count = resp["messages"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);
        assert!(
            count >= num_messages,
            "user {i} expected >= {num_messages} messages, got {count}"
        );
    }

    tracing::info!(
        "\n=== stress_large_group ===\n\
         {num_members} members\n\
         Registration: {reg_elapsed:?}\n\
         Group creation: {create_elapsed:?}\n\
         Send latency ({num_messages} msgs): {}\n\
         Read latency ({num_members} readers): {}\n\
         ============================",
        latency_stats(&mut send_latencies),
        latency_stats(&mut read_latencies),
    );
}

/// Stress test: Single user with many concurrent conversations.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn stress_many_convos() {
    init_tracing();
    let client = test_client();
    let num_convos = env_usize("STRESS_USERS", 100);

    // 1. Create main user + N other users
    let mut main_user = client.test_user("stress-mc-main");
    main_user.register_device().await.expect("register main");
    main_user
        .publish_key_packages(3)
        .await
        .expect("publish main kp");

    let mut others = Vec::with_capacity(num_convos);
    for i in 0..num_convos {
        let mut user = client.test_user(&format!("stress-mc-{i}"));
        user.register_device()
            .await
            .unwrap_or_else(|e| panic!("register other {i}: {e}"));
        user.publish_key_packages(3)
            .await
            .unwrap_or_else(|e| panic!("publish kp other {i}: {e}"));
        others.push(user);
    }

    // 2. Main user creates N separate 1:1 convos
    let mut convo_ids = Vec::with_capacity(num_convos);
    let mut create_latencies = Vec::with_capacity(num_convos);
    for (i, other) in others.iter().enumerate() {
        let welcome = TestUser::random_bytes(256);
        let t = Instant::now();
        let convo = main_user
            .create_convo(&[other.did.clone()], Some(&welcome))
            .await
            .unwrap_or_else(|e| panic!("create convo {i}: {e}"));
        create_latencies.push(t.elapsed());
        let cid = convo["groupId"].as_str().expect("groupId").to_string();
        convo_ids.push(cid);
    }

    // 3. Send a message in each convo concurrently
    let main_user = Arc::new(main_user);
    let convo_ids_arc: Vec<Arc<String>> = convo_ids.iter().map(|c| Arc::new(c.clone())).collect();

    let mut set = JoinSet::new();
    for (i, cid) in convo_ids_arc.iter().enumerate() {
        let user = Arc::clone(&main_user);
        let cid = Arc::clone(cid);
        set.spawn(async move {
            let ct = TestUser::padded_ciphertext(format!("convo-{i}-msg").as_bytes());
            let t = Instant::now();
            user.send_message(&cid, &ct, 0)
                .await
                .unwrap_or_else(|e| panic!("send to convo {i}: {e}"));
            t.elapsed()
        });
    }

    let mut send_latencies = Vec::with_capacity(num_convos);
    while let Some(result) = set.join_next().await {
        send_latencies.push(result.expect("task panicked"));
    }

    // 4. Main user calls get_convos — verify N convos
    let gc_start = Instant::now();
    let convos_resp = main_user.get_convos().await.expect("get_convos");
    let gc_elapsed = gc_start.elapsed();
    let convo_list = convos_resp["conversations"].as_array().expect("convos array");
    assert!(
        convo_list.len() >= num_convos,
        "expected >= {num_convos} convos, got {}",
        convo_list.len()
    );

    tracing::info!(
        "\n=== stress_many_convos ===\n\
         {num_convos} conversations\n\
         Create latency: {}\n\
         Send latency (concurrent): {}\n\
         get_convos latency: {gc_elapsed:?} ({} convos returned)\n\
         ============================",
        latency_stats(&mut create_latencies),
        latency_stats(&mut send_latencies),
        convo_list.len(),
    );
}

/// Stress test: Concurrent device registrations.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn stress_concurrent_registrations() {
    init_tracing();
    let client = test_client();
    let num_users = env_usize("STRESS_USERS", 100);

    // 1. Create users and register devices concurrently
    let start = Instant::now();
    let mut set = JoinSet::new();

    for i in 0..num_users {
        let client = client.clone();
        set.spawn(async move {
            let mut user = client.test_user(&format!("stress-reg-{i}"));
            let t = Instant::now();
            user.register_device()
                .await
                .unwrap_or_else(|e| panic!("register user {i}: {e}"));
            let reg_dur = t.elapsed();

            // Publish key packages
            let t2 = Instant::now();
            user.publish_key_packages(3)
                .await
                .unwrap_or_else(|e| panic!("publish kp user {i}: {e}"));
            let pub_dur = t2.elapsed();

            (reg_dur, pub_dur)
        });
    }

    let mut reg_latencies = Vec::with_capacity(num_users);
    let mut pub_latencies = Vec::with_capacity(num_users);
    while let Some(result) = set.join_next().await {
        let (reg, pub_dur) = result.expect("task panicked");
        reg_latencies.push(reg);
        pub_latencies.push(pub_dur);
    }
    let total_elapsed = start.elapsed();

    let regs_per_sec = num_users as f64 / total_elapsed.as_secs_f64();
    tracing::info!(
        "\n=== stress_concurrent_registrations ===\n\
         {num_users} users registered concurrently\n\
         Total: {total_elapsed:?} ({regs_per_sec:.1} reg/s)\n\
         Register latency: {}\n\
         Publish KP latency: {}\n\
         ========================================",
        latency_stats(&mut reg_latencies),
        latency_stats(&mut pub_latencies),
    );

    assert_eq!(reg_latencies.len(), num_users);
    assert_eq!(pub_latencies.len(), num_users);
}

/// Stress test: Message retrieval under load.
/// Sends many messages then hammers getMessages from multiple readers.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn stress_read_heavy() {
    init_tracing();
    let client = test_client();
    let num_messages = env_usize("STRESS_MESSAGES", 200);
    let num_readers = 20;

    // 1. Create 2 users, create convo
    let mut alice = client.test_user("stress-rh-alice");
    let mut bob = client.test_user("stress-rh-bob");
    alice.register_device().await.expect("alice register");
    bob.register_device().await.expect("bob register");

    for user in [&alice, &bob] {
        user.publish_key_packages(3).await.expect("publish kp");
    }

    let welcome = TestUser::random_bytes(256);
    let convo = alice
        .create_convo(&[bob.did.clone()], Some(&welcome))
        .await
        .expect("create convo");
    let convo_id = convo["groupId"].as_str().expect("groupId").to_string();

    // 2. Send N messages
    let write_start = Instant::now();
    for i in 0..num_messages {
        let ct = TestUser::padded_ciphertext(format!("rh-msg-{i}").as_bytes());
        let sender = if i % 2 == 0 { &alice } else { &bob };
        sender
            .send_message(&convo_id, &ct, 0)
            .await
            .unwrap_or_else(|e| panic!("send msg {i}: {e}"));
    }
    let write_elapsed = write_start.elapsed();

    // 3. Spawn concurrent readers calling get_messages
    let alice = Arc::new(alice);
    let bob = Arc::new(bob);
    let convo_id = Arc::new(convo_id);

    let read_start = Instant::now();
    let mut set = JoinSet::new();
    for i in 0..num_readers {
        let reader = if i % 2 == 0 {
            Arc::clone(&alice)
        } else {
            Arc::clone(&bob)
        };
        let cid = Arc::clone(&convo_id);
        set.spawn(async move {
            let t = Instant::now();
            // Paginate through all messages (server max per page is 100)
            let mut total = 0usize;
            let mut since_seq: Option<i64> = None;
            loop {
                let resp = reader
                    .get_messages_with_limit(&cid, since_seq, Some(100))
                    .await
                    .unwrap_or_else(|e| panic!("reader {i} get_messages: {e}"));
                let msgs = resp["messages"]
                    .as_array()
                    .map(|a| a.len())
                    .unwrap_or(0);
                if msgs == 0 {
                    break;
                }
                total += msgs;
                // Get the seq of the last message for pagination
                if let Some(last) = resp["messages"].as_array().and_then(|a| a.last()) {
                    since_seq = last["seq"].as_i64();
                } else {
                    break;
                }
            }
            let dur = t.elapsed();
            (dur, total)
        });
    }

    let mut read_latencies = Vec::with_capacity(num_readers);
    let mut min_count = usize::MAX;
    while let Some(result) = set.join_next().await {
        let (dur, count) = result.expect("task panicked");
        read_latencies.push(dur);
        min_count = min_count.min(count);
    }
    let read_elapsed = read_start.elapsed();

    tracing::info!(
        "\n=== stress_read_heavy ===\n\
         {num_messages} messages written in {write_elapsed:?}\n\
         {num_readers} concurrent readers\n\
         Read phase: {read_elapsed:?}\n\
         Read latency: {}\n\
         Min messages seen by any reader: {min_count}\n\
         ============================",
        latency_stats(&mut read_latencies),
    );

    assert!(
        min_count >= num_messages,
        "expected all readers to see >= {num_messages} messages, min was {min_count}"
    );
}
