mod common;

use catbird_server::db::*;
use chrono::Utc;
use sqlx::PgPool;
use std::time::Duration;

async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/catbird_test".to_string());

    let config = DbConfig {
        database_url,
        max_connections: 10,
        min_connections: 2,
        acquire_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(600),
    };

    init_db(config)
        .await
        .expect("Failed to initialize test database")
}

async fn cleanup_test_data(pool: &PgPool) {
    sqlx::query("TRUNCATE TABLE messages, members, conversations, key_packages CASCADE")
        .execute(pool)
        .await
        .expect("Failed to cleanup test data");
}

/// The fixture model of this file is a DB-global reset: every test starts by
/// TRUNCATE-ing the shared tables via `cleanup_test_data`. That makes the
/// tests mutually exclusive by construction — two tests running concurrently
/// truncate each other's in-flight rows (this is the "shared IDs" fixture rot
/// that kept the file `#[ignore]`d). Serialize them with a static lock so the
/// file is correct under the default parallel test runner instead of relying
/// on callers remembering `--test-threads=1`.
static DB_FIXTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_conversation_crud() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let pool = setup_test_db().await;
    cleanup_test_data(&pool).await;

    // Create
    let convo = create_conversation(&pool, "did:plc:creator123")
        .await
        .expect("Failed to create conversation");

    assert_eq!(convo.creator_did, "did:plc:creator123");
    assert_eq!(convo.current_epoch, 0);

    // Read
    let fetched = get_conversation(&pool, &convo.id)
        .await
        .expect("Failed to get conversation")
        .expect("Conversation not found");

    assert_eq!(fetched.id, convo.id);
    assert_eq!(fetched.creator_did, "did:plc:creator123");

    // Update epoch
    update_conversation_epoch(&pool, &convo.id, 5)
        .await
        .expect("Failed to update epoch");

    let epoch = get_current_epoch(&pool, &convo.id)
        .await
        .expect("Failed to get epoch");

    assert_eq!(epoch, 5);

    // Delete
    delete_conversation(&pool, &convo.id)
        .await
        .expect("Failed to delete conversation");

    let deleted = get_conversation(&pool, &convo.id)
        .await
        .expect("Failed to get conversation");

    assert!(deleted.is_none());
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_member_operations() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let pool = setup_test_db().await;
    cleanup_test_data(&pool).await;

    let convo = create_conversation(&pool, "did:plc:creator")
        .await
        .expect("Failed to create conversation");

    // Add members
    add_member(&pool, &convo.id, "did:plc:alice")
        .await
        .expect("Failed to add alice");

    add_member(&pool, &convo.id, "did:plc:bob")
        .await
        .expect("Failed to add bob");

    // Check membership
    assert!(is_member(&pool, "did:plc:alice", &convo.id)
        .await
        .expect("Failed to check alice membership"));

    assert!(is_member(&pool, "did:plc:bob", &convo.id)
        .await
        .expect("Failed to check bob membership"));

    assert!(!is_member(&pool, "did:plc:charlie", &convo.id)
        .await
        .expect("Failed to check charlie membership"));

    // List members
    let members = list_members(&pool, &convo.id)
        .await
        .expect("Failed to list members");

    assert_eq!(members.len(), 2);

    // Get specific membership
    let alice_membership = get_membership(&pool, &convo.id, "did:plc:alice")
        .await
        .expect("Failed to get membership")
        .expect("Membership not found");

    assert_eq!(alice_membership.member_did, "did:plc:alice");
    assert!(alice_membership.is_active());

    // Update unread count
    update_unread_count(&pool, &convo.id, "did:plc:alice", 5)
        .await
        .expect("Failed to update unread count");

    let updated = get_membership(&pool, &convo.id, "did:plc:alice")
        .await
        .expect("Failed to get membership")
        .expect("Membership not found");

    assert_eq!(updated.unread_count, 5);

    // Reset unread count
    reset_unread_count(&pool, &convo.id, "did:plc:alice")
        .await
        .expect("Failed to reset unread count");

    let reset = get_membership(&pool, &convo.id, "did:plc:alice")
        .await
        .expect("Failed to get membership")
        .expect("Membership not found");

    assert_eq!(reset.unread_count, 0);

    // Remove member
    remove_member(&pool, &convo.id, "did:plc:bob")
        .await
        .expect("Failed to remove bob");

    assert!(!is_member(&pool, "did:plc:bob", &convo.id)
        .await
        .expect("Failed to check bob membership"));

    let active_members = list_members(&pool, &convo.id)
        .await
        .expect("Failed to list members");

    assert_eq!(active_members.len(), 1);
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_message_operations() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let pool = setup_test_db().await;
    cleanup_test_data(&pool).await;

    let convo = create_conversation(&pool, "did:plc:creator")
        .await
        .expect("Failed to create conversation");

    // Create messages
    let msg1 = create_message(
        &pool,
        &convo.id,
        "msg-alice-1",
        vec![1, 2, 3, 4],
        0,
        4,
        None,
    )
    .await
    .expect("Failed to create message 1");

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let msg2 = create_message(&pool, &convo.id, "msg-bob-1", vec![5, 6, 7, 8], 0, 4, None)
        .await
        .expect("Failed to create message 2");

    // Get message
    let fetched = get_message(&pool, &msg1.id)
        .await
        .expect("Failed to get message")
        .expect("Message not found");

    assert_eq!(fetched.ciphertext, vec![1, 2, 3, 4]);
    // sender_did is intentionally stored as NULL for privacy; clients
    // derive sender identity from decrypted MLS content.
    assert_eq!(fetched.sender_did, None);

    // List messages (current API: ASC by epoch/seq)
    let messages = list_messages(&pool, &convo.id, None, 10)
        .await
        .expect("Failed to list messages");

    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].id, msg1.id); // Oldest first under ASC ordering

    // List with pagination
    let page1 = list_messages(&pool, &convo.id, None, 1)
        .await
        .expect("Failed to list messages");

    assert_eq!(page1.len(), 1);
    assert_eq!(page1[0].id, msg1.id);

    let page2 = list_messages(&pool, &convo.id, Some(msg2.created_at), 1)
        .await
        .expect("Failed to list messages");

    assert_eq!(page2.len(), 1);
    assert_eq!(page2[0].id, msg1.id);

    // List since seq (replaces removed list_messages_since which keyed on time)
    let recent = list_messages_since_seq(&pool, &convo.id, msg1.seq, 10)
        .await
        .expect("Failed to list messages since");

    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].id, msg2.id);

    // Get count
    let count = get_message_count(&pool, &convo.id)
        .await
        .expect("Failed to get message count");

    assert_eq!(count, 2);

    // Delete message
    delete_message(&pool, &msg1.id)
        .await
        .expect("Failed to delete message");

    let deleted = get_message(&pool, &msg1.id)
        .await
        .expect("Failed to get message");

    assert!(deleted.is_none());
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_key_package_operations() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let pool = setup_test_db().await;
    cleanup_test_data(&pool).await;

    let cipher_suite = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";
    let expires_at = Utc::now() + chrono::Duration::hours(24);
    // store_key_package validates real KeyPackage bytes (and binds the
    // credential identity to the owner DID) — dummy bytes are rejected.
    let key_data1 = common::generate_key_package_bytes("did:plc:alice");
    let key_data2 = common::generate_key_package_bytes("did:plc:alice");

    // Store key packages
    store_key_package(
        &pool,
        "did:plc:alice",
        cipher_suite,
        key_data1.clone(),
        expires_at,
    )
    .await
    .expect("Failed to store key package 1");

    store_key_package(
        &pool,
        "did:plc:alice",
        cipher_suite,
        key_data2.clone(),
        expires_at,
    )
    .await
    .expect("Failed to store key package 2");

    // Count key packages
    let count = count_key_packages(&pool, "did:plc:alice", cipher_suite)
        .await
        .expect("Failed to count key packages");

    assert_eq!(count, 2);

    // Get key package (should return oldest first)
    let kp = get_key_package(&pool, "did:plc:alice", cipher_suite)
        .await
        .expect("Failed to get key package")
        .expect("Key package not found");

    assert_eq!(kp.key_data, key_data1);
    assert!(kp.is_valid());

    // Consume key package
    consume_key_package(&pool, "did:plc:alice", cipher_suite, &key_data1)
        .await
        .expect("Failed to consume key package");

    // Count should be 1 now
    let count_after = count_key_packages(&pool, "did:plc:alice", cipher_suite)
        .await
        .expect("Failed to count key packages");

    assert_eq!(count_after, 1);

    // Next fetch should return second key package
    let kp2 = get_key_package(&pool, "did:plc:alice", cipher_suite)
        .await
        .expect("Failed to get key package")
        .expect("Key package not found");

    assert_eq!(kp2.key_data, key_data2);
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_expired_key_package_cleanup() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let pool = setup_test_db().await;
    cleanup_test_data(&pool).await;

    let cipher_suite = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";
    let expired = Utc::now() - chrono::Duration::hours(1);
    let valid = Utc::now() + chrono::Duration::hours(24);
    let expired_bytes = common::generate_key_package_bytes("did:plc:bob");
    let valid_bytes = common::generate_key_package_bytes("did:plc:bob");

    // Store expired and valid key packages
    store_key_package(
        &pool,
        "did:plc:bob",
        cipher_suite,
        expired_bytes.clone(),
        expired,
    )
    .await
    .expect("Failed to store expired key package");

    store_key_package(
        &pool,
        "did:plc:bob",
        cipher_suite,
        valid_bytes.clone(),
        valid,
    )
    .await
    .expect("Failed to store valid key package");

    // Expired key package should not be returned
    let kp = get_key_package(&pool, "did:plc:bob", cipher_suite)
        .await
        .expect("Failed to get key package")
        .expect("Key package not found");

    assert_eq!(kp.key_data, valid_bytes);

    // Clean up expired
    let deleted = delete_expired_key_packages(&pool)
        .await
        .expect("Failed to delete expired key packages");

    assert!(deleted >= 1);
}

// Blob operations have been removed - system is now text-only with PostgreSQL storage

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_transaction_conversation_with_members() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let pool = setup_test_db().await;
    cleanup_test_data(&pool).await;

    // Create conversation with members in transaction
    let convo = create_conversation_with_members(
        &pool,
        "did:plc:creator",
        vec![
            "did:plc:alice".to_string(),
            "did:plc:bob".to_string(),
            "did:plc:charlie".to_string(),
        ],
    )
    .await
    .expect("Failed to create conversation with members");

    // Verify all members were added
    let members = list_members(&pool, &convo.id)
        .await
        .expect("Failed to list members");

    assert_eq!(members.len(), 3);

    let member_dids: Vec<&str> = members.iter().map(|m| m.member_did.as_str()).collect();
    assert!(member_dids.contains(&"did:plc:alice"));
    assert!(member_dids.contains(&"did:plc:bob"));
    assert!(member_dids.contains(&"did:plc:charlie"));
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_list_conversations_for_user() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let pool = setup_test_db().await;
    cleanup_test_data(&pool).await;

    // Create multiple conversations
    let convo1 = create_conversation(&pool, "did:plc:creator")
        .await
        .expect("Failed to create convo 1");

    let convo2 = create_conversation(&pool, "did:plc:creator")
        .await
        .expect("Failed to create convo 2");

    let convo3 = create_conversation(&pool, "did:plc:other")
        .await
        .expect("Failed to create convo 3");

    // Add user to conversations
    add_member(&pool, &convo1.id, "did:plc:alice")
        .await
        .unwrap();
    add_member(&pool, &convo2.id, "did:plc:alice")
        .await
        .unwrap();
    add_member(&pool, &convo3.id, "did:plc:alice")
        .await
        .unwrap();

    // List conversations for alice
    let convos = list_conversations(&pool, "did:plc:alice", 10, 0)
        .await
        .expect("Failed to list conversations");

    assert_eq!(convos.len(), 3);

    // Leave one conversation
    remove_member(&pool, &convo2.id, "did:plc:alice")
        .await
        .unwrap();

    // Should only see 2 now
    let active_convos = list_conversations(&pool, "did:plc:alice", 10, 0)
        .await
        .expect("Failed to list conversations");

    assert_eq!(active_convos.len(), 2);
}

#[tokio::test]
async fn test_health_check() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let pool = setup_test_db().await;

    let healthy = health_check(&pool).await.expect("Health check failed");

    assert!(healthy);
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_concurrent_operations() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let pool = setup_test_db().await;
    cleanup_test_data(&pool).await;

    let convo = create_conversation(&pool, "did:plc:creator")
        .await
        .expect("Failed to create conversation");

    // Concurrent message creation.
    //
    // `db::create_message` computes `seq` with a read-then-insert
    // (MAX(seq)+1), so concurrent writers on the same convo can collide on
    // the `messages_convo_seq_unique` constraint and get a clean error back.
    // Production never hits this: message writes are serialized
    // per-conversation by the ConversationActor (`actors/conversation.rs`),
    // and this helper has no production call sites. The DB constraint is the
    // integrity guarantee under test, so each task retries on a seq
    // collision exactly as a concurrent caller would have to.
    let mut handles = vec![];
    for i in 0..10 {
        let pool_clone = pool.clone();
        let convo_id = convo.id.clone();
        let handle = tokio::spawn(async move {
            let mut last_err = None;
            for _attempt in 0..32 {
                match create_message(
                    &pool_clone,
                    &convo_id,
                    &format!("concurrent-msg-{}", i),
                    vec![i as u8],
                    0,
                    1,
                    None,
                )
                .await
                {
                    Ok(msg) => return Ok(msg),
                    Err(e) => {
                        let is_seq_collision = e
                            .downcast_ref::<sqlx::Error>()
                            .and_then(|se| se.as_database_error())
                            .and_then(|dbe| dbe.constraint())
                            .map(|c| c == "messages_convo_seq_unique")
                            .unwrap_or(false);
                        if is_seq_collision {
                            last_err = Some(e);
                            continue;
                        }
                        return Err(e);
                    }
                }
            }
            Err(last_err.expect("retry loop exited without an error"))
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap().expect("Failed to create message");
    }

    let count = get_message_count(&pool, &convo.id)
        .await
        .expect("Failed to get count");

    assert_eq!(count, 10);
}
