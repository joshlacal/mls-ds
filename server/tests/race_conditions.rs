use std::sync::Arc;
use tokio::sync::Barrier;
use sqlx::PgPool;
use chrono::Utc;

// Test setup helper
async fn setup_test_db() -> PgPool {
    let db_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://catbird:changeme@localhost:5433/catbird".to_string());

    let config = catbird_server::db::DbConfig {
        database_url: db_url,
        max_connections: 20, // Higher for concurrent tests
        min_connections: 5,
        acquire_timeout: std::time::Duration::from_secs(10),
        idle_timeout: std::time::Duration::from_secs(60),
    };

    catbird_server::db::init_db(config)
        .await
        .expect("Failed to initialize test database")
}

async fn cleanup_test_data(pool: &PgPool, convo_id: &str) {
    // Clean up in reverse dependency order
    let _ = sqlx::query("DELETE FROM envelopes WHERE convo_id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM messages WHERE convo_id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM welcome_messages WHERE convo_id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM members WHERE convo_id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM conversations WHERE id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
}

async fn create_test_convo(pool: &PgPool, convo_id: &str, creator: &str) {
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at)
         VALUES ($1, $2, 0, $3, $3)
         ON CONFLICT (id) DO NOTHING"
    )
    .bind(convo_id)
    .bind(creator)
    .bind(&now)
    .execute(pool)
    .await
    .expect("Failed to create conversation");

    sqlx::query(
        "INSERT INTO members (convo_id, member_did, joined_at, unread_count)
         VALUES ($1, $2, $3, 0)
         ON CONFLICT (convo_id, member_did) DO NOTHING"
    )
    .bind(convo_id)
    .bind(creator)
    .bind(&now)
    .execute(pool)
    .await
    .expect("Failed to add creator as member");
}

async fn add_member_db(pool: &PgPool, convo_id: &str, member_did: &str) {
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO members (convo_id, member_did, joined_at, unread_count)
         VALUES ($1, $2, $3, 0)
         ON CONFLICT (convo_id, member_did) DO NOTHING"
    )
    .bind(convo_id)
    .bind(member_did)
    .bind(&now)
    .execute(pool)
    .await
    .expect("Failed to add member");
}

// Simulate add_members handler by directly manipulating the conversation actor
async fn simulate_add_members_via_actor(
    _pool: PgPool,
    actor_registry: Arc<catbird_server::actors::ActorRegistry>,
    convo_id: &str,
    did_list: Vec<String>,
) -> Result<u32, String> {
    use tokio::sync::oneshot;

    // Get or spawn conversation actor
    let actor_ref = actor_registry.get_or_spawn(convo_id).await
        .map_err(|e| format!("Failed to get actor: {}", e))?;

    // Send AddMembers message
    let (tx, rx) = oneshot::channel();
    actor_ref.send_message(catbird_server::actors::ConvoMessage::AddMembers {
        did_list,
        commit: None,
        welcome_message: None,
        key_package_hashes: None,
        reply: tx,
    }).map_err(|e| format!("Failed to send message: {:?}", e))?;

    // Await response
    let new_epoch = rx.await
        .map_err(|_| "Actor channel closed unexpectedly".to_string())?
        .map_err(|e| format!("Actor failed: {}", e))?;

    Ok(new_epoch)
}

// Simulate send_message via actor
async fn simulate_send_message_via_actor(
    actor_registry: Arc<catbird_server::actors::ActorRegistry>,
    convo_id: &str,
    sender_did: &str,
    ciphertext: Vec<u8>,
) -> Result<(), String> {
    use tokio::sync::oneshot;

    let actor_ref = actor_registry.get_or_spawn(convo_id).await
        .map_err(|e| format!("Failed to get actor: {}", e))?;

    let (tx, rx) = oneshot::channel();
    actor_ref.send_message(catbird_server::actors::ConvoMessage::SendMessage {
        sender_did: sender_did.to_string(),
        ciphertext,
        reply: tx,
    }).map_err(|e| format!("Failed to send message: {:?}", e))?;

    rx.await
        .map_err(|_| "Actor channel closed unexpectedly".to_string())?
        .map_err(|e| format!("Actor failed: {}", e))?;

    Ok(())
}

// Simulate get_messages handler (resets unread count)
async fn simulate_get_messages(pool: &PgPool, convo_id: &str, member_did: &str) -> Result<Vec<String>, String> {
    // Reset unread count
    sqlx::query(
        "UPDATE members SET unread_count = 0 WHERE convo_id = $1 AND member_did = $2"
    )
    .bind(convo_id)
    .bind(member_did)
    .execute(pool)
    .await
    .map_err(|e| format!("Failed to reset unread: {}", e))?;

    // Fetch message IDs
    let message_ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM messages WHERE convo_id = $1 ORDER BY created_at"
    )
    .bind(convo_id)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("Failed to fetch messages: {}", e))?;

    Ok(message_ids)
}

#[tokio::test]
async fn test_concurrent_add_members_no_duplicate_epochs() {
    // Skip if TEST_DATABASE_URL not set
    let Ok(_) = std::env::var("TEST_DATABASE_URL") else {
        println!("Skipping test: TEST_DATABASE_URL not set");
        return;
    };

    let pool = setup_test_db().await;
    let convo_id = "test-race-1";
    let creator = "did:plc:creator";

    cleanup_test_data(&pool, convo_id).await;
    create_test_convo(&pool, convo_id, creator).await;

    // Enable actor system
    std::env::set_var("ENABLE_ACTOR_SYSTEM", "true");

    // Create actor registry
    let actor_registry = Arc::new(catbird_server::actors::ActorRegistry::new(pool.clone()));

    // Barrier to synchronize all tasks to start simultaneously
    let barrier = Arc::new(Barrier::new(10));
    let mut handles = vec![];

    for i in 0..10 {
        let pool_clone = pool.clone();
        let actor_registry_clone = actor_registry.clone();
        let barrier_clone = barrier.clone();
        let did = format!("did:plc:member{}", i);
        let convo_id_str = convo_id.to_string();

        let handle = tokio::spawn(async move {
            // Wait for all tasks to be ready
            barrier_clone.wait().await;

            // Call add_members via actor
            simulate_add_members_via_actor(
                pool_clone,
                actor_registry_clone,
                &convo_id_str,
                vec![did],
            ).await
        });

        handles.push(handle);
    }

    // Wait for all tasks to complete
    let results: Vec<Result<Result<u32, String>, _>> = futures::future::join_all(handles).await;

    // Verify all succeeded
    let mut epochs = vec![];
    for (i, result) in results.iter().enumerate() {
        match result {
            Ok(Ok(epoch)) => {
                println!("Task {} completed with epoch: {}", i, epoch);
                epochs.push(*epoch);
            }
            Ok(Err(e)) => panic!("Task {} failed with error: {}", i, e),
            Err(e) => panic!("Task {} panicked: {:?}", i, e),
        }
    }

    // Verify all 10 operations succeeded
    assert_eq!(epochs.len(), 10, "All 10 add_members operations should succeed");

    // Verify epochs are sequential (1 through 10)
    epochs.sort();
    let expected: Vec<u32> = (1..=10).collect();
    assert_eq!(epochs, expected, "Epochs should be sequential from 1 to 10");

    // Verify no duplicate epochs in database
    let epoch_duplicates: Vec<(i32, i64)> = sqlx::query_as(
        "SELECT epoch, COUNT(*) as count FROM messages
         WHERE convo_id = $1 AND message_type = 'commit'
         GROUP BY epoch HAVING COUNT(*) > 1"
    )
    .bind(convo_id)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert!(epoch_duplicates.is_empty(), "Found duplicate epochs: {:?}", epoch_duplicates);

    // Verify final conversation epoch
    let final_epoch: i32 = sqlx::query_scalar(
        "SELECT current_epoch FROM conversations WHERE id = $1"
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(final_epoch, 10, "Final conversation epoch should be 10");

    println!("✅ Test passed: No duplicate epochs with concurrent add_members");

    cleanup_test_data(&pool, convo_id).await;
}

#[tokio::test]
async fn test_concurrent_send_and_read_unread_count_consistency() {
    // Skip if TEST_DATABASE_URL not set
    let Ok(_) = std::env::var("TEST_DATABASE_URL") else {
        println!("Skipping test: TEST_DATABASE_URL not set");
        return;
    };

    let pool = setup_test_db().await;
    let convo_id = "test-race-2";
    let alice = "did:plc:alice";
    let bob = "did:plc:bob";

    cleanup_test_data(&pool, convo_id).await;
    create_test_convo(&pool, convo_id, alice).await;
    add_member_db(&pool, convo_id, bob).await;

    // Enable actor system
    std::env::set_var("ENABLE_ACTOR_SYSTEM", "true");

    let actor_registry = Arc::new(catbird_server::actors::ActorRegistry::new(pool.clone()));

    // Spawn sender task: send 50 messages
    let sender_registry = actor_registry.clone();
    let sender_convo_id = convo_id.to_string();
    let sender = tokio::spawn(async move {
        for i in 0..50 {
            let msg = format!("test message {}", i).into_bytes();
            if let Err(e) = simulate_send_message_via_actor(
                sender_registry.clone(),
                &sender_convo_id,
                alice,
                msg,
            ).await {
                eprintln!("Failed to send message {}: {}", i, e);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        }
    });

    // Spawn reader task: read messages every 30ms
    let reader_pool = pool.clone();
    let reader_convo_id = convo_id.to_string();
    let reader = tokio::spawn(async move {
        for i in 0..10 {
            tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
            if let Err(e) = simulate_get_messages(&reader_pool, &reader_convo_id, bob).await {
                eprintln!("Failed to get messages {}: {}", i, e);
            }
        }
    });

    // Wait for both tasks to complete
    sender.await.unwrap();
    reader.await.unwrap();

    // Give a moment for any pending unread count updates
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Final read to reset unread
    simulate_get_messages(&pool, convo_id, bob).await.unwrap();

    // Verify unread count is 0 (all messages read)
    let unread: i32 = sqlx::query_scalar(
        "SELECT unread_count FROM members WHERE convo_id = $1 AND member_did = $2"
    )
    .bind(convo_id)
    .bind(bob)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(unread, 0, "Unread count should be 0 after reading all messages");

    // Verify we have exactly 50 messages
    let message_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM messages WHERE convo_id = $1 AND message_type = 'app'"
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(message_count, 50, "Should have exactly 50 messages");

    println!("✅ Test passed: Unread count consistency with concurrent send/read");

    cleanup_test_data(&pool, convo_id).await;
}

#[tokio::test]
async fn test_message_sequence_numbers_sequential() {
    // Skip if TEST_DATABASE_URL not set
    let Ok(_) = std::env::var("TEST_DATABASE_URL") else {
        println!("Skipping test: TEST_DATABASE_URL not set");
        return;
    };

    let pool = setup_test_db().await;
    let convo_id = "test-race-3";
    let creator = "did:plc:creator";

    cleanup_test_data(&pool, convo_id).await;
    create_test_convo(&pool, convo_id, creator).await;

    // Enable actor system
    std::env::set_var("ENABLE_ACTOR_SYSTEM", "true");

    let actor_registry = Arc::new(catbird_server::actors::ActorRegistry::new(pool.clone()));

    // Send 20 messages concurrently
    let barrier = Arc::new(Barrier::new(20));
    let mut handles = vec![];

    for i in 0..20 {
        let registry = actor_registry.clone();
        let barrier_clone = barrier.clone();
        let convo_id_str = convo_id.to_string();

        let handle = tokio::spawn(async move {
            barrier_clone.wait().await;

            let msg = format!("concurrent message {}", i).into_bytes();
            simulate_send_message_via_actor(
                registry,
                &convo_id_str,
                creator,
                msg,
            ).await
        });

        handles.push(handle);
    }

    let results: Vec<_> = futures::future::join_all(handles).await;

    // Verify all succeeded
    for (i, result) in results.iter().enumerate() {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("Task {} failed: {}", i, e),
            Err(e) => panic!("Task {} panicked: {:?}", i, e),
        }
    }

    // Verify sequence numbers are sequential (1 through 20)
    let sequences: Vec<i64> = sqlx::query_scalar(
        "SELECT seq FROM messages WHERE convo_id = $1 AND message_type = 'app' ORDER BY seq"
    )
    .bind(convo_id)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(sequences.len(), 20, "Should have 20 messages");

    let expected: Vec<i64> = (1..=20).collect();
    assert_eq!(sequences, expected, "Sequence numbers should be sequential 1-20");

    // Verify no duplicate sequence numbers
    let duplicates: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT seq, COUNT(*) FROM messages
         WHERE convo_id = $1 AND message_type = 'app'
         GROUP BY seq HAVING COUNT(*) > 1"
    )
    .bind(convo_id)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert!(duplicates.is_empty(), "Found duplicate sequence numbers: {:?}", duplicates);

    println!("✅ Test passed: Sequential message sequence numbers");

    cleanup_test_data(&pool, convo_id).await;
}

#[tokio::test]
async fn test_out_of_order_commits_prevented() {
    // Skip if TEST_DATABASE_URL not set
    let Ok(_) = std::env::var("TEST_DATABASE_URL") else {
        println!("Skipping test: TEST_DATABASE_URL not set");
        return;
    };

    let pool = setup_test_db().await;
    let convo_id = "test-race-4";
    let creator = "did:plc:creator";

    cleanup_test_data(&pool, convo_id).await;
    create_test_convo(&pool, convo_id, creator).await;

    // Enable actor system
    std::env::set_var("ENABLE_ACTOR_SYSTEM", "true");

    let actor_registry = Arc::new(catbird_server::actors::ActorRegistry::new(pool.clone()));

    // Send 5 commits with artificially delayed submission to simulate clock skew
    let mut handles = vec![];

    for i in 0..5 {
        let pool_clone = pool.clone();
        let registry = actor_registry.clone();
        let did = format!("did:plc:member{}", i);
        let convo_id_str = convo_id.to_string();

        let handle = tokio::spawn(async move {
            // Later commits delayed more to simulate clock skew
            if i > 2 {
                tokio::time::sleep(tokio::time::Duration::from_millis(50 * (i - 2) as u64)).await;
            }

            simulate_add_members_via_actor(
                pool_clone,
                registry,
                &convo_id_str,
                vec![did],
            ).await
        });

        handles.push(handle);
    }

    let results: Vec<_> = futures::future::join_all(handles).await;

    // Collect epochs
    let mut epochs = vec![];
    for (i, result) in results.iter().enumerate() {
        match result {
            Ok(Ok(epoch)) => epochs.push(*epoch),
            Ok(Err(e)) => eprintln!("Task {} failed: {}", i, e),
            Err(e) => eprintln!("Task {} panicked: {:?}", i, e),
        }
    }

    // Verify epochs are sequential regardless of submission order
    epochs.sort();
    assert_eq!(epochs.len(), 5);
    let expected: Vec<u32> = (1..=5).collect();
    assert_eq!(epochs, expected, "Epochs should be 1-5 regardless of clock skew");

    // Verify commits in DB are ordered by epoch, not just timestamp
    let commits: Vec<(i32, chrono::DateTime<Utc>)> = sqlx::query_as(
        "SELECT epoch::int4, created_at
         FROM messages
         WHERE convo_id = $1 AND message_type = 'commit'
         ORDER BY created_at"
    )
    .bind(convo_id)
    .fetch_all(&pool)
    .await
    .unwrap();

    // Even if timestamps are out of order, epochs should be sequential
    for (i, (epoch, _created_at)) in commits.iter().enumerate() {
        assert_eq!(*epoch as usize, i + 1,
            "Epoch should be {} but got {} at position {}", i + 1, epoch, i);
    }

    println!("✅ Test passed: Out-of-order commits prevented by actor serialization");

    cleanup_test_data(&pool, convo_id).await;
}

#[tokio::test]
async fn test_mixed_operations_no_race_conditions() {
    // Skip if TEST_DATABASE_URL not set
    let Ok(_) = std::env::var("TEST_DATABASE_URL") else {
        println!("Skipping test: TEST_DATABASE_URL not set");
        return;
    };

    let pool = setup_test_db().await;
    let convo_id = "test-race-5";
    let creator = "did:plc:creator";

    cleanup_test_data(&pool, convo_id).await;
    create_test_convo(&pool, convo_id, creator).await;

    // Enable actor system
    std::env::set_var("ENABLE_ACTOR_SYSTEM", "true");

    let actor_registry = Arc::new(catbird_server::actors::ActorRegistry::new(pool.clone()));

    // Mixed operations: add members AND send messages concurrently
    let mut add_handles = vec![];
    let mut msg_handles = vec![];

    // Add 5 members
    for i in 0..5 {
        let pool_clone = pool.clone();
        let registry = actor_registry.clone();
        let did = format!("did:plc:member{}", i);
        let convo_id_str = convo_id.to_string();

        let handle = tokio::spawn(async move {
            simulate_add_members_via_actor(
                pool_clone,
                registry,
                &convo_id_str,
                vec![did],
            ).await
        });

        add_handles.push(handle);
    }

    // Send 5 messages concurrently with member additions
    for i in 0..5 {
        let registry = actor_registry.clone();
        let convo_id_str = convo_id.to_string();

        let handle = tokio::spawn(async move {
            let msg = format!("message during member add {}", i).into_bytes();
            simulate_send_message_via_actor(
                registry,
                &convo_id_str,
                creator,
                msg,
            ).await
        });

        msg_handles.push(handle);
    }

    // Wait for all operations
    let _add_results: Vec<_> = futures::future::join_all(add_handles).await;
    let _msg_results: Vec<_> = futures::future::join_all(msg_handles).await;

    // Verify data consistency

    // 1. Check we have 5 commit messages (one per add_members)
    let commit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM messages WHERE convo_id = $1 AND message_type = 'commit'"
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(commit_count, 5, "Should have exactly 5 commit messages");

    // 2. Check we have 5 app messages
    let app_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM messages WHERE convo_id = $1 AND message_type = 'app'"
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(app_count, 5, "Should have exactly 5 app messages");

    // 3. Verify epochs are consistent (commits should have epochs 1-5)
    let commit_epochs: Vec<i32> = sqlx::query_scalar(
        "SELECT epoch::int4 FROM messages
         WHERE convo_id = $1 AND message_type = 'commit'
         ORDER BY epoch"
    )
    .bind(convo_id)
    .fetch_all(&pool)
    .await
    .unwrap();

    let expected_epochs: Vec<i32> = (1..=5).collect();
    assert_eq!(commit_epochs, expected_epochs, "Commit epochs should be 1-5");

    // 4. Verify all messages have valid epochs (not higher than current conversation epoch)
    let current_epoch: i32 = sqlx::query_scalar(
        "SELECT current_epoch FROM conversations WHERE id = $1"
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let invalid_epochs: Vec<i64> = sqlx::query_scalar(
        "SELECT epoch FROM messages
         WHERE convo_id = $1 AND epoch::int4 > $2"
    )
    .bind(convo_id)
    .bind(current_epoch)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert!(invalid_epochs.is_empty(),
        "No messages should have epoch > current conversation epoch. Found: {:?}", invalid_epochs);

    println!("✅ Test passed: Mixed operations maintain consistency");

    cleanup_test_data(&pool, convo_id).await;
}
