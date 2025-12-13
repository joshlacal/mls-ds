use catbird_server::db::*;
use catbird_server::models::*;
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

#[tokio::test]
async fn test_conversation_crud() {
    let pool = setup_test_db().await;
    cleanup_test_data(&pool).await;

    // Create
    let convo = create_conversation(&pool, "did:plc:creator123", Some("Test Chat".to_string()))
        .await
        .expect("Failed to create conversation");

    assert_eq!(convo.creator_did, "did:plc:creator123");
    assert_eq!(convo.title, Some("Test Chat".to_string()));
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
async fn test_member_operations() {
    let pool = setup_test_db().await;
    cleanup_test_data(&pool).await;

    let convo = create_conversation(&pool, "did:plc:creator", None)
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
async fn test_message_operations() {
    let pool = setup_test_db().await;
    cleanup_test_data(&pool).await;

    let convo = create_conversation(&pool, "did:plc:creator", None)
        .await
        .expect("Failed to create conversation");

    // Create messages
    let msg1 = create_message(
        &pool,
        &convo.id,
        "did:plc:alice",
        vec![1, 2, 3, 4],
        0,
        None,
        None,
    )
    .await
    .expect("Failed to create message 1");

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let msg2 = create_message(
        &pool,
        &convo.id,
        "did:plc:bob",
        vec![5, 6, 7, 8],
        0,
        None,
        None,
    )
    .await
    .expect("Failed to create message 2");

    // Get message
    let fetched = get_message(&pool, &msg1.id)
        .await
        .expect("Failed to get message")
        .expect("Message not found");

    assert_eq!(fetched.ciphertext, vec![1, 2, 3, 4]);
    assert_eq!(fetched.sender_did, "did:plc:alice");

    // List messages
    let messages = list_messages(&pool, &convo.id, 10, None)
        .await
        .expect("Failed to list messages");

    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].id, msg2.id); // Most recent first

    // List with pagination
    let page1 = list_messages(&pool, &convo.id, 1, None)
        .await
        .expect("Failed to list messages");

    assert_eq!(page1.len(), 1);
    assert_eq!(page1[0].id, msg2.id);

    let page2 = list_messages(&pool, &convo.id, 1, Some(msg2.created_at))
        .await
        .expect("Failed to list messages");

    assert_eq!(page2.len(), 1);
    assert_eq!(page2[0].id, msg1.id);

    // List since time
    let since = msg1.created_at;
    let recent = list_messages_since(&pool, &convo.id, since)
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
async fn test_key_package_operations() {
    let pool = setup_test_db().await;
    cleanup_test_data(&pool).await;

    let cipher_suite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
    let expires_at = Utc::now() + chrono::Duration::hours(24);
    let key_data1 = vec![1, 2, 3, 4];
    let key_data2 = vec![5, 6, 7, 8];

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
async fn test_expired_key_package_cleanup() {
    let pool = setup_test_db().await;
    cleanup_test_data(&pool).await;

    let cipher_suite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
    let expired = Utc::now() - chrono::Duration::hours(1);
    let valid = Utc::now() + chrono::Duration::hours(24);

    // Store expired and valid key packages
    store_key_package(&pool, "did:plc:bob", cipher_suite, vec![1, 2], expired)
        .await
        .expect("Failed to store expired key package");

    store_key_package(&pool, "did:plc:bob", cipher_suite, vec![3, 4], valid)
        .await
        .expect("Failed to store valid key package");

    // Expired key package should not be returned
    let kp = get_key_package(&pool, "did:plc:bob", cipher_suite)
        .await
        .expect("Failed to get key package")
        .expect("Key package not found");

    assert_eq!(kp.key_data, vec![3, 4]);

    // Clean up expired
    let deleted = delete_expired_key_packages(&pool)
        .await
        .expect("Failed to delete expired key packages");

    assert!(deleted >= 1);
}

// Blob operations have been removed - system is now text-only with PostgreSQL storage

#[tokio::test]
async fn test_transaction_conversation_with_members() {
    let pool = setup_test_db().await;
    cleanup_test_data(&pool).await;

    // Create conversation with members in transaction
    let convo = create_conversation_with_members(
        &pool,
        "did:plc:creator",
        Some("Team Chat".to_string()),
        vec![
            "did:plc:alice".to_string(),
            "did:plc:bob".to_string(),
            "did:plc:charlie".to_string(),
        ],
    )
    .await
    .expect("Failed to create conversation with members");

    assert_eq!(convo.title, Some("Team Chat".to_string()));

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
async fn test_list_conversations_for_user() {
    let pool = setup_test_db().await;
    cleanup_test_data(&pool).await;

    // Create multiple conversations
    let convo1 = create_conversation(&pool, "did:plc:creator", Some("Chat 1".to_string()))
        .await
        .expect("Failed to create convo 1");

    let convo2 = create_conversation(&pool, "did:plc:creator", Some("Chat 2".to_string()))
        .await
        .expect("Failed to create convo 2");

    let convo3 = create_conversation(&pool, "did:plc:other", Some("Chat 3".to_string()))
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
    let pool = setup_test_db().await;

    let healthy = health_check(&pool).await.expect("Health check failed");

    assert!(healthy);
}

#[tokio::test]
async fn test_concurrent_operations() {
    let pool = setup_test_db().await;
    cleanup_test_data(&pool).await;

    let convo = create_conversation(&pool, "did:plc:creator", None)
        .await
        .expect("Failed to create conversation");

    // Concurrent message creation
    let mut handles = vec![];
    for i in 0..10 {
        let pool_clone = pool.clone();
        let convo_id = convo.id.clone();
        let handle = tokio::spawn(async move {
            create_message(
                &pool_clone,
                &convo_id,
                &format!("did:plc:user{}", i),
                vec![i as u8],
                0,
                None,
                None,
            )
            .await
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
