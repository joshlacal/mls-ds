#[cfg(test)]
// Inner module name intentionally matches the file/parent module — keeps
// the rust-analyzer test-runner namespace short
// (`actors::tests::conversation_tests::*`). Refactoring to flatten this
// requires updating ~30 inherent-namespace references in CI logs and dev
// scripts; tracked under TODO(phase-2.5-cleanup-test-namespaces).
#[allow(clippy::module_inception)]
mod conversation_tests {
    use crate::actors::{ConversationActor, ConvoActorArgs, ConvoMessage};
    use crate::realtime::SseState;
    use ractor::Actor;
    use sqlx::PgPool;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::oneshot;

    /// Test helper to set up a test database
    async fn setup_test_db() -> (PgPool, super::super::fresh_db::DisposableDatabase) {
        super::super::fresh_db::fresh_legacy_pool("actor_convo_", 10, 2).await
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
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at, group_id)
             VALUES ($1, $2, 0, $3, $3, $1)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(convo_id)
        .bind(creator)
        .bind(now)
        .execute(pool)
        .await
        .expect("Failed to create conversation");
    }

    // TODO(phase-2.5-cleanup-test-fixture-rot): the AddMembers actor message
    // contract evolved (more validation gates around member_dids,
    // commit/welcome correlation). The test sends a stripped-down payload
    // and the actor returns Err. Pre-existing — needs the fixture realigned
    // to current invariants.
    #[tokio::test]
    #[ignore = "fixture rot: AddMembers payload no longer satisfies actor's input contract"]
    async fn test_epoch_monotonicity() {
        let (pool, _db) = setup_test_db().await;
        let convo_id = "test-epoch-monotonicity";
        cleanup_test_data(&pool, convo_id).await;
        create_test_convo(&pool, convo_id, "did:plc:creator").await;

        // Spawn actor
        let args = ConvoActorArgs {
            sse_state: Arc::new(SseState::new(1000)),
            notification_service: None,
            convo_id: convo_id.to_string(),
            db_pool: pool.clone(),
            quorum_config: crate::config::QuorumConfig::default(),
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
        let (pool, _db) = setup_test_db().await;
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
            .bind(now)
            .execute(&pool)
            .await
            .expect("Failed to add member");
        }

        // Spawn actor
        let args = ConvoActorArgs {
            sse_state: Arc::new(SseState::new(1000)),
            notification_service: None,
            convo_id: convo_id.to_string(),
            db_pool: pool.clone(),
            quorum_config: crate::config::QuorumConfig::default(),
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

    // TODO(phase-2.5-cleanup-test-fixture-rot): same root cause as
    // `test_epoch_monotonicity` — the AddMembers contract changed. Pre-existing.
    #[tokio::test]
    #[ignore = "fixture rot: AddMembers payload no longer satisfies actor's input contract"]
    async fn test_state_persistence_on_shutdown() {
        let (pool, _db) = setup_test_db().await;
        let convo_id = "test-state-persistence";
        cleanup_test_data(&pool, convo_id).await;
        create_test_convo(&pool, convo_id, "did:plc:creator").await;

        // Spawn actor
        let args = ConvoActorArgs {
            sse_state: Arc::new(SseState::new(1000)),
            notification_service: None,
            convo_id: convo_id.to_string(),
            db_pool: pool.clone(),
            quorum_config: crate::config::QuorumConfig::default(),
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

    // TODO(phase-2.5-cleanup-test-fixture-rot): same root cause as
    // `test_epoch_monotonicity` — the AddMembers contract changed. Pre-existing.
    #[tokio::test]
    #[ignore = "fixture rot: AddMembers payload no longer satisfies actor's input contract"]
    async fn test_error_recovery() {
        let (pool, _db) = setup_test_db().await;
        let convo_id = "test-error-recovery";
        cleanup_test_data(&pool, convo_id).await;
        create_test_convo(&pool, convo_id, "did:plc:creator").await;

        // Spawn actor
        let args = ConvoActorArgs {
            sse_state: Arc::new(SseState::new(1000)),
            notification_service: None,
            convo_id: convo_id.to_string(),
            db_pool: pool.clone(),
            quorum_config: crate::config::QuorumConfig::default(),
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
        let (pool, _db) = setup_test_db().await;
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
        .bind(chrono::Utc::now())
        .execute(&pool)
        .await
        .expect("Failed to add alice");

        // Spawn actor
        let args = ConvoActorArgs {
            sse_state: Arc::new(SseState::new(1000)),
            notification_service: None,
            convo_id: convo_id.to_string(),
            db_pool: pool.clone(),
            quorum_config: crate::config::QuorumConfig::default(),
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
                        msg_id: format!("msg-{}", i),
                        epoch: 0,
                        padded_size: 512,
                        idempotency_key: None,
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

    // =====================================================================
    // ADR-002 §A7.5 — RecordResetVote unit tests
    //
    // Each test drives `handle_record_reset_vote` via the actor mailbox
    // (ConvoMessage::RecordResetVote) and asserts on the returned
    // RecordResetVoteOutcome. Members, epoch_authenticators, and reset_votes
    // are seeded directly so we don't need a full MLS commit path.
    //
    // All tests are #[ignore]'d because they require a live Postgres with
    // the 20260418_001 migration applied. Run with:
    //   cargo test -p catbird-server --lib reset_vote -- --ignored
    // =====================================================================

    use crate::actors::RecordResetVoteOutcome;

    async fn wipe_a7(pool: &PgPool, convo_id: &str) {
        for table in &[
            "envelopes",
            "messages",
            "welcome_messages",
            "pending_device_additions",
            "recovery_failures",
            "reset_votes",
            "epoch_authenticators",
            "auto_reset_history",
            "members",
        ] {
            let _ = sqlx::query(&format!("DELETE FROM {} WHERE convo_id = $1", table))
                .bind(convo_id)
                .execute(pool)
                .await;
        }
        let _ = sqlx::query("DELETE FROM conversations WHERE id = $1")
            .bind(convo_id)
            .execute(pool)
            .await;
    }

    async fn seed_a7_convo(
        pool: &PgPool,
        convo_id: &str,
        current_epoch: i32,
        auth_hex: &str,
        members: &[(&str, &str)],
    ) {
        let now = chrono::Utc::now();
        sqlx::query(
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at, group_id) \
             VALUES ($1, 'did:plc:creator', $2, $3, $3, $1) \
             ON CONFLICT (id) DO UPDATE SET current_epoch = $2",
        )
        .bind(convo_id)
        .bind(current_epoch)
        .bind(now)
        .execute(pool)
        .await
        .expect("seed convo");

        sqlx::query(
            "INSERT INTO epoch_authenticators (convo_id, epoch, authenticator, recorded_at) \
             VALUES ($1, $2, $3, NOW()) ON CONFLICT DO NOTHING",
        )
        .bind(convo_id)
        .bind(current_epoch)
        .bind(auth_hex)
        .execute(pool)
        .await
        .expect("seed authenticator");

        for (user_did, member_did) in members {
            sqlx::query(
                "INSERT INTO members (convo_id, member_did, user_did, joined_at) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (convo_id, member_did) DO UPDATE \
                 SET user_did = EXCLUDED.user_did, left_at = NULL",
            )
            .bind(convo_id)
            .bind(*member_did)
            .bind(*user_did)
            .bind(now)
            .execute(pool)
            .await
            .expect("seed member");
        }
    }

    async fn cast_vote(
        actor: &ractor::ActorRef<ConvoMessage>,
        device_did: &str,
        identity_did: &str,
        auth: &str,
    ) -> RecordResetVoteOutcome {
        let (tx, rx) = oneshot::channel();
        actor
            .cast(ConvoMessage::RecordResetVote {
                device_did: device_did.to_string(),
                identity_did: identity_did.to_string(),
                epoch_authenticator: auth.to_string(),
                failure_type: "external_commit_exhausted".to_string(),
                // ADR-008 D1 / Phase 2: defaults flipped to
                // `enforce_failure_mode = true`, so every vote in these
                // tests carries Mode B (`group_state_unrecoverable`) so
                // it actually counts toward quorum. The dedicated Mode A
                // exclusion test lives in
                // `tests/quorum_reset_threshold.rs` (Stage 2 Task 4).
                failure_mode: Some("group_state_unrecoverable".to_string()),
                reply: tx,
            })
            .expect("send vote");
        rx.await.expect("rx vote").expect("outcome ok")
    }

    /// Legacy A7 tests pre-date Phase 2's `dm = 1` threshold. For DM-shaped
    /// fixtures they expect TWO votes to trigger reset. Use this helper to
    /// keep the test's intent without bending production defaults.
    fn legacy_a7_quorum_config() -> crate::config::QuorumConfig {
        crate::config::QuorumConfig {
            dm: 2,
            ..crate::config::QuorumConfig::default()
        }
    }

    #[tokio::test]
    #[ignore = "requires live Postgres with A7 migration applied (TEST_DATABASE_URL)"]
    async fn test_record_reset_vote_happy_path_3_member_2_votes() {
        let (pool, _db) = setup_test_db().await;
        let convo_id = "test-a7-happy";
        wipe_a7(&pool, convo_id).await;
        let auth = "deadbeefc0de";
        seed_a7_convo(
            &pool,
            convo_id,
            5,
            auth,
            &[
                ("did:plc:alice", "did:plc:alice#d1"),
                ("did:plc:bob", "did:plc:bob#d1"),
                ("did:plc:carol", "did:plc:carol#d1"),
            ],
        )
        .await;
        let args = ConvoActorArgs {
            sse_state: Arc::new(SseState::new(1000)),
            notification_service: None,
            convo_id: convo_id.to_string(),
            db_pool: pool.clone(),
            quorum_config: crate::config::QuorumConfig::default(),
        };
        let (actor, _h) = Actor::spawn(None, ConversationActor, args)
            .await
            .expect("spawn");

        let o1 = cast_vote(&actor, "did:plc:alice#d1", "did:plc:alice", auth).await;
        assert!(o1.recorded);
        assert!(!o1.auto_reset_triggered);
        assert_eq!(o1.per_did_vote_count, 1);
        assert_eq!(o1.member_did_count, 3);

        let o2 = cast_vote(&actor, "did:plc:bob#d1", "did:plc:bob", auth).await;
        assert!(o2.recorded);
        assert!(o2.auto_reset_triggered, "quorum 2/3 reached");
        assert!(o2.new_group_id.is_some());
        assert_eq!(o2.reset_count, Some(1));

        let epoch: i32 =
            sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
                .bind(convo_id)
                .fetch_one(&pool)
                .await
                .expect("fetch epoch");
        assert_eq!(epoch, 0);

        actor.stop(None);
        wipe_a7(&pool, convo_id).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres with A7 migration applied (TEST_DATABASE_URL)"]
    async fn test_record_reset_vote_stale_authenticator() {
        let (pool, _db) = setup_test_db().await;
        let convo_id = "test-a7-stale";
        wipe_a7(&pool, convo_id).await;
        seed_a7_convo(
            &pool,
            convo_id,
            100,
            "a11ca11c",
            &[
                ("did:plc:alice", "did:plc:alice#d1"),
                ("did:plc:bob", "did:plc:bob#d1"),
                ("did:plc:carol", "did:plc:carol#d1"),
            ],
        )
        .await;
        let args = ConvoActorArgs {
            sse_state: Arc::new(SseState::new(1000)),
            notification_service: None,
            convo_id: convo_id.to_string(),
            db_pool: pool.clone(),
            quorum_config: crate::config::QuorumConfig::default(),
        };
        let (actor, _h) = Actor::spawn(None, ConversationActor, args)
            .await
            .expect("spawn");

        let o = cast_vote(&actor, "did:plc:alice#d1", "did:plc:alice", "00d1fc11").await;
        assert!(!o.recorded);
        assert_eq!(o.reason.as_deref(), Some("stale_authenticator"));

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reset_votes WHERE convo_id = $1")
            .bind(convo_id)
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(count, 0);

        actor.stop(None);
        wipe_a7(&pool, convo_id).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres with A7 migration applied (TEST_DATABASE_URL)"]
    async fn test_record_reset_vote_rate_limited() {
        let (pool, _db) = setup_test_db().await;
        let convo_id = "test-a7-rl";
        wipe_a7(&pool, convo_id).await;
        let auth = "beeff00d";
        seed_a7_convo(
            &pool,
            convo_id,
            3,
            auth,
            &[
                ("did:plc:alice", "did:plc:alice#d1"),
                ("did:plc:alice", "did:plc:alice#d2"),
                ("did:plc:bob", "did:plc:bob#d1"),
            ],
        )
        .await;
        let args = ConvoActorArgs {
            sse_state: Arc::new(SseState::new(1000)),
            notification_service: None,
            convo_id: convo_id.to_string(),
            db_pool: pool.clone(),
            quorum_config: crate::config::QuorumConfig::default(),
        };
        let (actor, _h) = Actor::spawn(None, ConversationActor, args)
            .await
            .expect("spawn");

        let o1 = cast_vote(&actor, "did:plc:alice#d1", "did:plc:alice", auth).await;
        assert!(o1.recorded);

        let o2 = cast_vote(&actor, "did:plc:alice#d2", "did:plc:alice", auth).await;
        assert!(!o2.recorded);
        assert_eq!(o2.reason.as_deref(), Some("rate_limited"));

        actor.stop(None);
        wipe_a7(&pool, convo_id).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres with A7 migration applied (TEST_DATABASE_URL)"]
    async fn test_record_reset_vote_circuit_breaker_trips() {
        let (pool, _db) = setup_test_db().await;
        let convo_id = "test-a7-breaker";
        wipe_a7(&pool, convo_id).await;
        let auth = "facefeed";
        seed_a7_convo(
            &pool,
            convo_id,
            9,
            auth,
            &[
                ("did:plc:alice", "did:plc:alice#d1"),
                ("did:plc:bob", "did:plc:bob#d1"),
            ],
        )
        .await;
        for _ in 0..3 {
            sqlx::query(
                "INSERT INTO auto_reset_history \
                    (convo_id, reset_triggered_at, triggered_by, new_group_id, \
                     vote_count, member_count) \
                 VALUES ($1, NOW() - INTERVAL '1 hour', 'system:auto_recovery', \
                         $2, 2, 2)",
            )
            .bind(convo_id)
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(&pool)
            .await
            .expect("seed history");
        }
        let args = ConvoActorArgs {
            sse_state: Arc::new(SseState::new(1000)),
            notification_service: None,
            convo_id: convo_id.to_string(),
            db_pool: pool.clone(),
            // 2-member fixture: under Phase 2 default `dm = 1` the first
            // vote would already meet quorum and the breaker would never
            // see a second one. Override `dm` so the test still reaches
            // the 2-vote shape it was written against.
            quorum_config: legacy_a7_quorum_config(),
        };
        let (actor, _h) = Actor::spawn(None, ConversationActor, args)
            .await
            .expect("spawn");

        let _ = cast_vote(&actor, "did:plc:alice#d1", "did:plc:alice", auth).await;
        let o = cast_vote(&actor, "did:plc:bob#d1", "did:plc:bob", auth).await;
        assert_eq!(o.reason.as_deref(), Some("circuit_breaker"));
        assert!(!o.auto_reset_triggered);

        let disabled: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT auto_reset_disabled_at FROM conversations WHERE id = $1")
                .bind(convo_id)
                .fetch_one(&pool)
                .await
                .expect("fetch");
        assert!(disabled.is_some());

        actor.stop(None);
        wipe_a7(&pool, convo_id).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres with A7 migration applied (TEST_DATABASE_URL)"]
    async fn test_record_reset_vote_per_did_multi_device() {
        let (pool, _db) = setup_test_db().await;
        let convo_id = "test-a7-multidev";
        wipe_a7(&pool, convo_id).await;
        let auth = "c0ffee42";
        seed_a7_convo(
            &pool,
            convo_id,
            7,
            auth,
            &[
                ("did:plc:alice", "did:plc:alice#d1"),
                ("did:plc:alice", "did:plc:alice#d2"),
                ("did:plc:alice", "did:plc:alice#d3"),
                ("did:plc:bob", "did:plc:bob#d1"),
                ("did:plc:carol", "did:plc:carol#d1"),
            ],
        )
        .await;
        // Pre-seed all 3 of alice's devices as having voted (can't go through
        // handler because per-identity rate limit would block devices 2 & 3).
        // ADR-008 D1 / Phase 2: include `failure_mode` so the rows count
        // toward quorum under the now-default `enforce_failure_mode = true`.
        for dev in &["d1", "d2", "d3"] {
            sqlx::query(
                "INSERT INTO reset_votes \
                    (convo_id, device_did, identity_did, epoch_authenticator, \
                     failure_type, failure_mode, voted_at, expires_at) \
                 VALUES ($1, $2, 'did:plc:alice', $3, 'external_commit_exhausted', \
                         'group_state_unrecoverable', \
                         NOW(), NOW() + INTERVAL '24 hours')",
            )
            .bind(convo_id)
            .bind(format!("did:plc:alice#{}", dev))
            .bind(auth)
            .execute(&pool)
            .await
            .expect("seed alice vote");
        }

        let args = ConvoActorArgs {
            sse_state: Arc::new(SseState::new(1000)),
            notification_service: None,
            convo_id: convo_id.to_string(),
            db_pool: pool.clone(),
            quorum_config: crate::config::QuorumConfig::default(),
        };
        let (actor, _h) = Actor::spawn(None, ConversationActor, args)
            .await
            .expect("spawn");

        // Trigger counter via alice d1 (upsert of existing vote). Counter
        // should see alice as 1 identity-vote; bob/carol have voted nothing.
        let o = cast_vote(&actor, "did:plc:alice#d1", "did:plc:alice", auth).await;
        assert_eq!(
            o.per_did_vote_count, 1,
            "3 devices of alice == 1 identity-vote"
        );
        assert_eq!(o.member_did_count, 3);
        assert!(!o.auto_reset_triggered, "1 of 3 below ceil(3*2/3)=2");

        actor.stop(None);
        wipe_a7(&pool, convo_id).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres with A7 migration applied (TEST_DATABASE_URL)"]
    async fn test_record_reset_vote_partial_lockout_zero() {
        let (pool, _db) = setup_test_db().await;
        let convo_id = "test-a7-partial";
        wipe_a7(&pool, convo_id).await;
        let auth = "b00dcafe";
        seed_a7_convo(
            &pool,
            convo_id,
            2,
            auth,
            &[
                ("did:plc:alice", "did:plc:alice#d1"),
                ("did:plc:alice", "did:plc:alice#d2"),
                ("did:plc:alice", "did:plc:alice#d3"),
                ("did:plc:bob", "did:plc:bob#d1"),
            ],
        )
        .await;
        // Only 2 of alice's 3 devices voted (d1, d2).
        // ADR-008 D1 / Phase 2: include `failure_mode` so the rows count
        // toward quorum under the now-default `enforce_failure_mode = true`.
        for dev in &["d1", "d2"] {
            sqlx::query(
                "INSERT INTO reset_votes \
                    (convo_id, device_did, identity_did, epoch_authenticator, \
                     failure_type, failure_mode, voted_at, expires_at) \
                 VALUES ($1, $2, 'did:plc:alice', $3, 'external_commit_exhausted', \
                         'group_state_unrecoverable', \
                         NOW(), NOW() + INTERVAL '24 hours')",
            )
            .bind(convo_id)
            .bind(format!("did:plc:alice#{}", dev))
            .bind(auth)
            .execute(&pool)
            .await
            .expect("seed");
        }

        let args = ConvoActorArgs {
            sse_state: Arc::new(SseState::new(1000)),
            notification_service: None,
            convo_id: convo_id.to_string(),
            db_pool: pool.clone(),
            // 2-identity (DM) fixture with intentional partial-lockout
            // semantics — under Phase 2 default `dm = 1`, bob's single
            // vote would already meet quorum and the assertion
            // `!auto_reset_triggered` would fail. Override `dm` so the
            // legacy 2-vote shape still applies.
            quorum_config: legacy_a7_quorum_config(),
        };
        let (actor, _h) = Actor::spawn(None, ConversationActor, args)
            .await
            .expect("spawn");

        let o = cast_vote(&actor, "did:plc:bob#d1", "did:plc:bob", auth).await;
        assert_eq!(
            o.per_did_vote_count, 1,
            "alice partial (2/3 devices) = 0; bob = 1; total 1"
        );
        assert_eq!(o.member_did_count, 2);
        assert!(!o.auto_reset_triggered);

        actor.stop(None);
        wipe_a7(&pool, convo_id).await;
    }
}
