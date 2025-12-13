#[cfg(test)]
mod conversation_tests {
    use crate::actors::{ConversationActor, ConvoActorArgs, ConvoMessage, KeyPackageHashEntry};
    use ractor::Actor;
    use sqlx::PgPool;
    use std::time::Duration;
    use tokio::sync::oneshot;

    /// Test helper to set up a test database
    async fn setup_test_db() -> PgPool {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://catbird:changeme@localhost:5433/catbird".to_string());

        let config = crate::db::DbConfig {
            database_url,
            max_connections: 10,
            min_connections: 2,
            acquire_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
        };

        crate::db::init_db(config)
            .await
            .expect("Failed to initialize test database")
    }

    /// Test helper to clean up test data
    async fn cleanup_test_data(pool: &PgPool, convo_id: &str) {
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

    /// Test helper to create a test conversation
    async fn create_test_convo(pool: &PgPool, convo_id: &str, creator: &str) {
        let now = chrono::Utc::now();

        sqlx::query(
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at)
             VALUES ($1, $2, 0, $3, $3)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(convo_id)
        .bind(creator)
        .bind(&now)
        .execute(pool)
        .await
        .expect("Failed to create conversation");
    }

    #[tokio::test]
    async fn test_epoch_monotonicity() {
        let pool = setup_test_db().await;
        let convo_id = "test-epoch-monotonicity";
        cleanup_test_data(&pool, convo_id).await;
        create_test_convo(&pool, convo_id, "did:plc:creator").await;

        // Spawn actor
        let args = ConvoActorArgs {
            convo_id: convo_id.to_string(),
            db_pool: pool.clone(),
        };

        let (actor_ref, _handle) = Actor::spawn(None, ConversationActor, args)
            .await
            .expect("Failed to spawn actor");

        // Get initial epoch
        let (tx1, rx1) = oneshot::channel();
        actor_ref
            .cast(ConvoMessage::GetEpoch { reply: tx1 })
            .expect("Failed to send GetEpoch");
        let epoch1 = rx1.await.expect("Failed to receive epoch");
        assert_eq!(epoch1, 0);

        // Add members (should increment epoch)
        let (tx2, rx2) = oneshot::channel();
        actor_ref
            .cast(ConvoMessage::AddMembers {
                did_list: vec!["did:plc:alice".to_string()],
                commit: Some(vec![1, 2, 3]),
                welcome_message: None,
                key_package_hashes: None,
                reply: tx2,
            })
            .expect("Failed to send AddMembers");
        let result = rx2.await.expect("Failed to receive result");
        assert!(result.is_ok());
        let epoch2 = result.unwrap();
        assert_eq!(epoch2, 1);

        // Verify epoch increased
        let (tx3, rx3) = oneshot::channel();
        actor_ref
            .cast(ConvoMessage::GetEpoch { reply: tx3 })
            .expect("Failed to send GetEpoch");
        let epoch3 = rx3.await.expect("Failed to receive epoch");
        assert_eq!(epoch3, 1);

        // Remove member (should increment again)
        let (tx4, rx4) = oneshot::channel();
        actor_ref
            .cast(ConvoMessage::RemoveMember {
                member_did: "did:plc:alice".to_string(),
                commit: Some(vec![4, 5, 6]),
                reply: tx4,
            })
            .expect("Failed to send RemoveMember");
        let result2 = rx4.await.expect("Failed to receive result");
        assert!(result2.is_ok());
        let epoch4 = result2.unwrap();
        assert_eq!(epoch4, 2);

        // Final verification - epoch should be 2
        let (tx5, rx5) = oneshot::channel();
        actor_ref
            .cast(ConvoMessage::GetEpoch { reply: tx5 })
            .expect("Failed to send GetEpoch");
        let final_epoch = rx5.await.expect("Failed to receive epoch");
        assert_eq!(final_epoch, 2);

        // Cleanup
        actor_ref.stop(None);
        cleanup_test_data(&pool, convo_id).await;
    }

    #[tokio::test]
    async fn test_unread_count_updates() {
        let pool = setup_test_db().await;
        let convo_id = "test-unread-count";
        cleanup_test_data(&pool, convo_id).await;
        create_test_convo(&pool, convo_id, "did:plc:creator").await;

        // Add members to the database
        let now = chrono::Utc::now();
        for member in &["did:plc:alice", "did:plc:bob", "did:plc:charlie"] {
            sqlx::query(
                "INSERT INTO members (convo_id, member_did, joined_at, unread_count)
                 VALUES ($1, $2, $3, 0)
                 ON CONFLICT (convo_id, member_did) DO NOTHING",
            )
            .bind(convo_id)
            .bind(member)
            .bind(&now)
            .execute(&pool)
            .await
            .expect("Failed to add member");
        }

        // Spawn actor
        let args = ConvoActorArgs {
            convo_id: convo_id.to_string(),
            db_pool: pool.clone(),
        };

        let (actor_ref, _handle) = Actor::spawn(None, ConversationActor, args)
            .await
            .expect("Failed to spawn actor");

        // Increment unread counts (no reply channel - fire and forget)
        actor_ref
            .cast(ConvoMessage::IncrementUnread {
                sender_did: "did:plc:alice".to_string(),
            })
            .expect("Failed to send IncrementUnread");

        // Wait a bit for processing
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Reset unread count for bob
        let (tx, rx) = oneshot::channel();
        actor_ref
            .cast(ConvoMessage::ResetUnread {
                member_did: "did:plc:bob".to_string(),
                reply: tx,
            })
            .expect("Failed to send ResetUnread");
        let result = rx.await.expect("Failed to receive result");
        assert!(result.is_ok());

        // Verify bob's count is 0 in database
        let bob_count: i32 = sqlx::query_scalar(
            "SELECT unread_count FROM members WHERE convo_id = $1 AND member_did = $2",
        )
        .bind(convo_id)
        .bind("did:plc:bob")
        .fetch_one(&pool)
        .await
        .expect("Failed to get bob's unread count");
        assert_eq!(bob_count, 0);

        // Cleanup
        actor_ref.stop(None);
        cleanup_test_data(&pool, convo_id).await;
    }

    #[tokio::test]
    async fn test_state_persistence_on_shutdown() {
        let pool = setup_test_db().await;
        let convo_id = "test-state-persistence";
        cleanup_test_data(&pool, convo_id).await;
        create_test_convo(&pool, convo_id, "did:plc:creator").await;

        // Spawn actor
        let args = ConvoActorArgs {
            convo_id: convo_id.to_string(),
            db_pool: pool.clone(),
        };

        let (actor_ref, _handle) = Actor::spawn(None, ConversationActor, args)
            .await
            .expect("Failed to spawn actor");

        // Add members to increment epoch
        let (tx, rx) = oneshot::channel();
        actor_ref
            .cast(ConvoMessage::AddMembers {
                did_list: vec!["did:plc:member1".to_string()],
                commit: Some(vec![1, 2, 3]),
                welcome_message: None,
                key_package_hashes: None,
                reply: tx,
            })
            .expect("Failed to send AddMembers");
        rx.await
            .expect("Failed to receive result")
            .expect("AddMembers failed");

        // Send shutdown message
        actor_ref
            .cast(ConvoMessage::Shutdown)
            .expect("Failed to send Shutdown");

        // Wait for shutdown processing
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify epoch was persisted in database
        let db_epoch: i32 =
            sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
                .bind(convo_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to get epoch from database");
        assert_eq!(db_epoch, 1);

        // Cleanup
        actor_ref.stop(None);
        cleanup_test_data(&pool, convo_id).await;
    }

    #[tokio::test]
    async fn test_error_recovery() {
        let pool = setup_test_db().await;
        let convo_id = "test-error-recovery";
        cleanup_test_data(&pool, convo_id).await;
        create_test_convo(&pool, convo_id, "did:plc:creator").await;

        // Spawn actor
        let args = ConvoActorArgs {
            convo_id: convo_id.to_string(),
            db_pool: pool.clone(),
        };

        let (actor_ref, _handle) = Actor::spawn(None, ConversationActor, args)
            .await
            .expect("Failed to spawn actor");

        // Try to remove a non-existent member (should handle gracefully)
        let (tx, rx) = oneshot::channel();
        actor_ref
            .cast(ConvoMessage::RemoveMember {
                member_did: "did:plc:nonexistent".to_string(),
                commit: Some(vec![1, 2, 3]),
                reply: tx,
            })
            .expect("Failed to send RemoveMember");

        let result = rx.await.expect("Failed to receive result");
        // Actor should not crash, even if member doesn't exist
        assert!(result.is_ok());

        // Verify actor is still responsive
        let (tx2, rx2) = oneshot::channel();
        actor_ref
            .cast(ConvoMessage::GetEpoch { reply: tx2 })
            .expect("Failed to send GetEpoch");
        let epoch = rx2.await.expect("Failed to receive epoch");
        assert_eq!(epoch, 1); // Epoch was incremented despite no member to remove

        // Cleanup
        actor_ref.stop(None);
        cleanup_test_data(&pool, convo_id).await;
    }

    #[tokio::test]
    async fn test_concurrent_messages_serialized() {
        let pool = setup_test_db().await;
        let convo_id = "test-concurrent-serialization";
        cleanup_test_data(&pool, convo_id).await;
        create_test_convo(&pool, convo_id, "did:plc:creator").await;

        // Add a member first
        sqlx::query(
            "INSERT INTO members (convo_id, member_did, joined_at, unread_count)
             VALUES ($1, $2, $3, 0)
             ON CONFLICT (convo_id, member_did) DO NOTHING",
        )
        .bind(convo_id)
        .bind("did:plc:alice")
        .bind(&chrono::Utc::now())
        .execute(&pool)
        .await
        .expect("Failed to add alice");

        // Spawn actor
        let args = ConvoActorArgs {
            convo_id: convo_id.to_string(),
            db_pool: pool.clone(),
        };

        let (actor_ref, _handle) = Actor::spawn(None, ConversationActor, args)
            .await
            .expect("Failed to spawn actor");

        // Send 10 concurrent messages
        let mut handles = vec![];
        for i in 0..10 {
            let actor_ref_clone = actor_ref.clone();
            let handle = tokio::spawn(async move {
                let (tx, rx) = oneshot::channel();
                actor_ref_clone
                    .cast(ConvoMessage::SendMessage {
                        sender_did: "did:plc:alice".to_string(),
                        ciphertext: vec![i as u8; 10],
                        reply: tx,
                    })
                    .expect("Failed to send message");
                rx.await.expect("Failed to receive result")
            });
            handles.push(handle);
        }

        // Wait for all messages to complete
        for handle in handles {
            let result = handle.await.expect("Task failed");
            assert!(result.is_ok(), "Message sending failed");
        }

        // Wait for async fanout to complete
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify all messages were stored with sequential sequence numbers
        let messages: Vec<(i64,)> =
            sqlx::query_as("SELECT seq FROM messages WHERE convo_id = $1 ORDER BY seq ASC")
                .bind(convo_id)
                .fetch_all(&pool)
                .await
                .expect("Failed to get messages");

        assert_eq!(messages.len(), 10);

        // Verify sequences are 1..10 (no gaps, no duplicates)
        for (idx, (seq,)) in messages.iter().enumerate() {
            assert_eq!(*seq, (idx as i64) + 1);
        }

        // Cleanup
        actor_ref.stop(None);
        cleanup_test_data(&pool, convo_id).await;
    }
}
