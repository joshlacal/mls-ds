#[cfg(test)]
mod registry_tests {
    use crate::actors::{ActorRegistry, ConvoMessage};
    use sqlx::PgPool;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Barrier;
    use tokio::sync::oneshot;

    /// Test helper to set up a test database
    async fn setup_test_db() -> PgPool {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://catbird:changeme@localhost:5433/catbird".to_string());

        let config = crate::db::DbConfig {
            database_url,
            max_connections: 20, // Higher for concurrent tests
            min_connections: 5,
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
    async fn test_actor_spawn_and_reuse() {
        let pool = setup_test_db().await;
        let convo_id = "test-spawn-reuse";
        cleanup_test_data(&pool, convo_id).await;
        create_test_convo(&pool, convo_id, "did:plc:creator").await;

        let registry = ActorRegistry::new(pool.clone());

        // First access - should spawn new actor
        let initial_count = registry.actor_count();
        let actor1 = registry
            .get_or_spawn(convo_id)
            .await
            .expect("Failed to get or spawn actor");

        assert_eq!(registry.actor_count(), initial_count + 1);

        // Second access - should reuse existing actor
        let actor2 = registry
            .get_or_spawn(convo_id)
            .await
            .expect("Failed to get or spawn actor");

        // Should still be same count
        assert_eq!(registry.actor_count(), initial_count + 1);

        // Actors should be the same (same reference)
        let (tx1, rx1) = oneshot::channel();
        actor1
            .cast(ConvoMessage::GetEpoch { reply: tx1 })
            .expect("Failed to send to actor1");
        let epoch1 = rx1.await.expect("Failed to receive from actor1");

        let (tx2, rx2) = oneshot::channel();
        actor2
            .cast(ConvoMessage::GetEpoch { reply: tx2 })
            .expect("Failed to send to actor2");
        let epoch2 = rx2.await.expect("Failed to receive from actor2");

        assert_eq!(epoch1, epoch2);

        // Cleanup
        registry.shutdown_all().await;
        cleanup_test_data(&pool, convo_id).await;
    }

    #[tokio::test]
    async fn test_concurrent_get_or_spawn_no_duplicates() {
        let pool = setup_test_db().await;
        let convo_id = "test-concurrent-spawn";
        cleanup_test_data(&pool, convo_id).await;
        create_test_convo(&pool, convo_id, "did:plc:creator").await;

        let registry = Arc::new(ActorRegistry::new(pool.clone()));
        let barrier = Arc::new(Barrier::new(10));

        // Launch 10 concurrent tasks trying to get/spawn the same actor
        let mut handles = vec![];
        for i in 0..10 {
            let registry_clone = Arc::clone(&registry);
            let barrier_clone = Arc::clone(&barrier);
            let convo_id_clone = convo_id.to_string();

            let handle = tokio::spawn(async move {
                // Wait for all tasks to be ready
                barrier_clone.wait().await;

                // Try to get or spawn
                let actor = registry_clone
                    .get_or_spawn(&convo_id_clone)
                    .await
                    .expect("Failed to get or spawn");

                // Verify actor is responsive
                let (tx, rx) = oneshot::channel();
                actor
                    .cast(ConvoMessage::GetEpoch { reply: tx })
                    .expect("Failed to send GetEpoch");
                let epoch = rx.await.expect("Failed to receive epoch");

                (i, epoch)
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        let mut results = vec![];
        for handle in handles {
            let result = handle.await.expect("Task failed");
            results.push(result);
        }

        // All tasks should complete successfully
        assert_eq!(results.len(), 10);

        // Registry should have exactly 1 actor (no duplicates)
        assert_eq!(registry.actor_count(), 1);

        // All tasks should see the same epoch
        let first_epoch = results[0].1;
        for (_task_id, epoch) in results {
            assert_eq!(epoch, first_epoch);
        }

        // Cleanup
        registry.shutdown_all().await;
        cleanup_test_data(&pool, convo_id).await;
    }

    #[tokio::test]
    async fn test_cleanup_after_timeout() {
        let pool = setup_test_db().await;
        let convo_id = "test-cleanup-timeout";
        cleanup_test_data(&pool, convo_id).await;
        create_test_convo(&pool, convo_id, "did:plc:creator").await;

        let registry = ActorRegistry::new(pool.clone());

        // Spawn actor
        let actor = registry
            .get_or_spawn(convo_id)
            .await
            .expect("Failed to get or spawn actor");

        assert_eq!(registry.actor_count(), 1);

        // Manually remove actor (simulating cleanup)
        registry.remove_actor(convo_id);

        // Count should be 0 now
        assert_eq!(registry.actor_count(), 0);

        // Stop the actor
        actor.stop(None);

        // Try to get again - should spawn new instance
        let _actor2 = registry
            .get_or_spawn(convo_id)
            .await
            .expect("Failed to get or spawn actor");

        assert_eq!(registry.actor_count(), 1);

        // Cleanup
        registry.shutdown_all().await;
        cleanup_test_data(&pool, convo_id).await;
    }

    #[tokio::test]
    async fn test_actor_count() {
        let pool = setup_test_db().await;
        let registry = ActorRegistry::new(pool.clone());

        // Initially should be 0
        assert_eq!(registry.actor_count(), 0);

        // Create multiple conversations
        let convos = vec![
            "test-count-1",
            "test-count-2",
            "test-count-3",
        ];

        for convo_id in &convos {
            cleanup_test_data(&pool, convo_id).await;
            create_test_convo(&pool, convo_id, "did:plc:creator").await;
        }

        // Spawn actors for each
        for (idx, convo_id) in convos.iter().enumerate() {
            registry
                .get_or_spawn(convo_id)
                .await
                .expect("Failed to get or spawn actor");

            assert_eq!(registry.actor_count(), idx + 1);
        }

        // Should have 3 actors
        assert_eq!(registry.actor_count(), 3);

        // Shutdown all
        registry.shutdown_all().await;

        // Wait a bit for shutdown to complete
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should be 0 again
        assert_eq!(registry.actor_count(), 0);

        // Cleanup
        for convo_id in &convos {
            cleanup_test_data(&pool, convo_id).await;
        }
    }

    #[tokio::test]
    async fn test_multiple_registries_same_pool() {
        let pool = setup_test_db().await;
        let convo_id = "test-multi-registry";
        cleanup_test_data(&pool, convo_id).await;
        create_test_convo(&pool, convo_id, "did:plc:creator").await;

        // Create two separate registries with the same pool
        let registry1 = ActorRegistry::new(pool.clone());
        let registry2 = ActorRegistry::new(pool.clone());

        // Each registry spawns its own actor for the same conversation
        let actor1 = registry1
            .get_or_spawn(convo_id)
            .await
            .expect("Failed to spawn in registry1");

        let actor2 = registry2
            .get_or_spawn(convo_id)
            .await
            .expect("Failed to spawn in registry2");

        // Each registry should have 1 actor
        assert_eq!(registry1.actor_count(), 1);
        assert_eq!(registry2.actor_count(), 1);

        // Both actors should be able to work with the database
        let (tx1, rx1) = oneshot::channel();
        actor1
            .cast(ConvoMessage::GetEpoch { reply: tx1 })
            .expect("Failed to send to actor1");
        let epoch1 = rx1.await.expect("Failed to receive from actor1");

        let (tx2, rx2) = oneshot::channel();
        actor2
            .cast(ConvoMessage::GetEpoch { reply: tx2 })
            .expect("Failed to send to actor2");
        let epoch2 = rx2.await.expect("Failed to receive from actor2");

        // Both should see the same epoch from the database
        assert_eq!(epoch1, epoch2);

        // Cleanup
        registry1.shutdown_all().await;
        registry2.shutdown_all().await;
        cleanup_test_data(&pool, convo_id).await;
    }
}
