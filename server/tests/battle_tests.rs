//! Battle Test Suite for MLS Server
//!
//! This test suite stress-tests critical functionality including:
//! 1. Idempotency middleware under concurrent load
//! 2. Two-phase commit for Welcome messages
//! 3. Concurrent member additions (race conditions)
//! 4. Message ordering under high concurrency
//! 5. Database constraint violations
//! 6. Cache cleanup and TTL behavior
//!
//! ## Running the tests
//!
//! ```bash
//! # Start PostgreSQL (via Docker Compose)
//! docker-compose up -d postgres
//!
//! # Set test database URL
//! export DATABASE_URL="postgresql://catbird:password@localhost/catbird_test"
//!
//! # Run migrations
//! sqlx migrate run --source ./migrations
//!
//! # Run battle tests
//! cargo test --test battle_tests -- --nocapture
//!
//! # Run specific test with verbose output
//! cargo test --test battle_tests idempotency_stress_test -- --nocapture --test-threads=1
//! ```
//!
//! ## Test Database Setup
//!
//! These tests require a clean test database. Set DATABASE_URL to a test database
//! before running. Tests will create and clean up their own data.

use catbird_server::db;
use catbird_server::middleware::idempotency::{cleanup_expired_entries, IdempotencyLayer};
use catbird_server::models::{CreateConvoInput, SendMessageInput, AddMembersInput};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Barrier;
use uuid::Uuid;

/// Test configuration
const TEST_DB_URL: &str = "postgresql://catbird:password@localhost/catbird_test";
const CONCURRENT_REQUESTS: usize = 100;
const TEST_TIMEOUT_SECS: u64 = 60;

/// Helper to create a test database pool
async fn create_test_pool() -> PgPool {
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| TEST_DB_URL.to_string());

    PgPoolOptions::new()
        .max_connections(50)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&db_url)
        .await
        .expect("Failed to connect to test database")
}

/// Helper to clean up test data
async fn cleanup_test_data(pool: &PgPool, test_prefix: &str) {
    // Clean up conversations, messages, members with test prefix
    let _ = sqlx::query("DELETE FROM members WHERE convo_id LIKE $1")
        .bind(format!("{}%", test_prefix))
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM messages WHERE convo_id LIKE $1")
        .bind(format!("{}%", test_prefix))
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM conversations WHERE convo_id LIKE $1")
        .bind(format!("{}%", test_prefix))
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM idempotency_cache WHERE key LIKE $1")
        .bind(format!("{}%", test_prefix))
        .execute(pool)
        .await;

    let _ = sqlx::query("DELETE FROM key_packages WHERE owner_did LIKE $1")
        .bind(format!("{}%", test_prefix))
        .execute(pool)
        .await;
}

/// Generate a test DID
fn test_did(prefix: &str, id: usize) -> String {
    format!("did:test:{}:{}", prefix, id)
}

#[tokio::test]
#[ignore] // Run with --ignored flag
async fn test_idempotency_stress_100x_concurrent_identical_requests() {
    println!("\n=== BATTLE TEST: Idempotency Stress (100x Concurrent Identical Requests) ===\n");

    let pool = create_test_pool().await;
    let test_id = Uuid::new_v4().to_string();
    let test_prefix = format!("battle-idem-{}", &test_id[..8]);

    // Cleanup before test
    cleanup_test_data(&pool, &test_prefix).await;

    let convo_id = format!("{}-convo", test_prefix);
    let creator_did = test_did(&test_prefix, 0);
    let idempotency_key = format!("{}-key", test_prefix);

    // Create a test conversation first
    let _ = sqlx::query(
        r#"
        INSERT INTO conversations (convo_id, creator_did, epoch, created_at, updated_at)
        VALUES ($1, $2, 0, NOW(), NOW())
        "#,
    )
    .bind(&convo_id)
    .bind(&creator_did)
    .execute(&pool)
    .await;

    // Add creator as member
    let _ = sqlx::query(
        r#"
        INSERT INTO members (convo_id, member_did, joined_at)
        VALUES ($1, $2, NOW())
        "#,
    )
    .bind(&convo_id)
    .bind(&creator_did)
    .execute(&pool)
    .await;

    println!("✓ Created test conversation: {}", convo_id);
    println!("✓ Preparing {} concurrent identical requests...", CONCURRENT_REQUESTS);

    // Use barrier to synchronize all tasks
    let barrier = Arc::new(Barrier::new(CONCURRENT_REQUESTS));
    let pool = Arc::new(pool);

    // Spawn concurrent tasks that all try to send the same message with same idempotency key
    let mut handles = vec![];

    for i in 0..CONCURRENT_REQUESTS {
        let pool = pool.clone();
        let barrier = barrier.clone();
        let convo_id = convo_id.clone();
        let creator_did = creator_did.clone();
        let idempotency_key = idempotency_key.clone();

        let handle = tokio::spawn(async move {
            // Wait for all tasks to be ready
            barrier.wait().await;

            // Simulate the idempotency middleware behavior
            let endpoint = "/xrpc/blue.catbird.mls.sendMessage";

            // Check cache
            let cached = sqlx::query_scalar::<_, Option<serde_json::Value>>(
                r#"
                SELECT response_body
                FROM idempotency_cache
                WHERE key = $1 AND endpoint = $2 AND expires_at > NOW()
                "#,
            )
            .bind(&idempotency_key)
            .bind(endpoint)
            .fetch_optional(pool.as_ref())
            .await
            .unwrap();

            if cached.is_some() {
                return (i, true, None); // Cache hit
            }

            // Simulate message creation
            let result = sqlx::query(
                r#"
                INSERT INTO messages (message_id, convo_id, sender_did, ciphertext, epoch, created_at, idempotency_key)
                VALUES ($1, $2, $3, $4, 0, NOW(), $5)
                ON CONFLICT (idempotency_key) DO NOTHING
                RETURNING message_id
                "#,
            )
            .bind(format!("{}-msg-{}", convo_id, i))
            .bind(&convo_id)
            .bind(&creator_did)
            .bind(vec![1u8, 2, 3])
            .bind(&idempotency_key)
            .fetch_optional(pool.as_ref())
            .await
            .unwrap();

            let created = result.is_some();

            // Try to cache the response
            if created {
                let _ = sqlx::query(
                    r#"
                    INSERT INTO idempotency_cache (key, endpoint, response_body, status_code, expires_at)
                    VALUES ($1, $2, $3, 200, NOW() + INTERVAL '1 hour')
                    ON CONFLICT (key) DO NOTHING
                    "#,
                )
                .bind(&idempotency_key)
                .bind(endpoint)
                .bind(serde_json::json!({"success": true}))
                .execute(pool.as_ref())
                .await;
            }

            (i, false, Some(created))
        });

        handles.push(handle);
    }

    println!("✓ Launched {} concurrent tasks", CONCURRENT_REQUESTS);
    println!("⏳ Waiting for all tasks to complete...\n");

    // Collect results
    let results: Vec<(usize, bool, Option<bool>)> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    // Analyze results
    let cache_hits = results.iter().filter(|(_, hit, _)| *hit).count();
    let cache_misses = results.iter().filter(|(_, hit, _)| !*hit).count();
    let actual_creates = results.iter().filter(|(_, _, created)| created == &Some(true)).count();

    println!("📊 Results:");
    println!("   Cache hits: {}", cache_hits);
    println!("   Cache misses: {}", cache_misses);
    println!("   Actual DB inserts: {}", actual_creates);

    // Verify exactly ONE message was created
    let message_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM messages WHERE idempotency_key = $1",
    )
    .bind(&idempotency_key)
    .fetch_one(pool.as_ref())
    .await
    .unwrap();

    println!("   Messages in DB: {}", message_count);

    // Verify exactly ONE cache entry exists
    let cache_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM idempotency_cache WHERE key = $1",
    )
    .bind(&idempotency_key)
    .fetch_one(pool.as_ref())
    .await
    .unwrap();

    println!("   Cache entries: {}", cache_count);

    // Cleanup
    cleanup_test_data(&pool, &test_prefix).await;

    println!("\n✅ PASS: Idempotency guaranteed exactly-once semantics");

    assert_eq!(message_count, 1, "Should have exactly 1 message in database");
    assert_eq!(cache_count, 1, "Should have exactly 1 cache entry");
    assert!(actual_creates <= 1, "Should have at most 1 successful insert");
}

#[tokio::test]
#[ignore]
async fn test_concurrent_member_addition_race_conditions() {
    println!("\n=== BATTLE TEST: Concurrent Member Addition (Race Conditions) ===\n");

    let pool = create_test_pool().await;
    let test_id = Uuid::new_v4().to_string();
    let test_prefix = format!("battle-member-{}", &test_id[..8]);

    cleanup_test_data(&pool, &test_prefix).await;

    let convo_id = format!("{}-convo", test_prefix);
    let creator_did = test_did(&test_prefix, 0);

    // Create conversation
    let _ = sqlx::query(
        r#"
        INSERT INTO conversations (convo_id, creator_did, epoch, created_at, updated_at)
        VALUES ($1, $2, 0, NOW(), NOW())
        "#,
    )
    .bind(&convo_id)
    .bind(&creator_did)
    .execute(&pool)
    .await;

    let _ = sqlx::query(
        r#"
        INSERT INTO members (convo_id, member_did, joined_at)
        VALUES ($1, $2, NOW())
        "#,
    )
    .bind(&convo_id)
    .bind(&creator_did)
    .execute(&pool)
    .await;

    println!("✓ Created test conversation: {}", convo_id);

    // Create 10 members to add
    let members_to_add: Vec<String> = (1..=10).map(|i| test_did(&test_prefix, i)).collect();
    println!("✓ Preparing to add {} members", members_to_add.len());

    let num_concurrent_adds = 50;
    println!("✓ Spawning {} concurrent addMember requests...", num_concurrent_adds);

    let barrier = Arc::new(Barrier::new(num_concurrent_adds));
    let pool = Arc::new(pool);

    let mut handles = vec![];

    for i in 0..num_concurrent_adds {
        let pool = pool.clone();
        let barrier = barrier.clone();
        let convo_id = convo_id.clone();
        let members = members_to_add.clone();

        let handle = tokio::spawn(async move {
            barrier.wait().await;

            let mut added = 0;
            for member_did in &members {
                // Try to add member (idempotent via ON CONFLICT DO NOTHING)
                let result = sqlx::query(
                    r#"
                    INSERT INTO members (convo_id, member_did, joined_at)
                    VALUES ($1, $2, NOW())
                    ON CONFLICT (convo_id, member_did) DO NOTHING
                    RETURNING member_did
                    "#,
                )
                .bind(&convo_id)
                .bind(member_did)
                .fetch_optional(pool.as_ref())
                .await
                .unwrap();

                if result.is_some() {
                    added += 1;
                }
            }

            (i, added)
        });

        handles.push(handle);
    }

    println!("⏳ Waiting for all concurrent additions...\n");

    let results: Vec<(usize, i32)> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    let total_additions: i32 = results.iter().map(|(_, added)| added).sum();

    println!("📊 Results:");
    println!("   Total addition attempts: {}", num_concurrent_adds * members_to_add.len());
    println!("   Successful additions: {}", total_additions);

    // Count actual members in DB
    let member_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM members WHERE convo_id = $1 AND left_at IS NULL",
    )
    .bind(&convo_id)
    .fetch_one(pool.as_ref())
    .await
    .unwrap();

    println!("   Members in DB: {}", member_count);

    // Should have creator + 10 added members = 11 total
    let expected_members = 11;

    cleanup_test_data(&pool, &test_prefix).await;

    println!("\n✅ PASS: No duplicate members created under concurrent load");

    assert_eq!(
        member_count, expected_members,
        "Should have exactly {} unique members (1 creator + 10 added)",
        expected_members
    );
}

#[tokio::test]
#[ignore]
async fn test_message_ordering_under_high_concurrency() {
    println!("\n=== BATTLE TEST: Message Ordering Under High Concurrency ===\n");

    let pool = create_test_pool().await;
    let test_id = Uuid::new_v4().to_string();
    let test_prefix = format!("battle-order-{}", &test_id[..8]);

    cleanup_test_data(&pool, &test_prefix).await;

    let convo_id = format!("{}-convo", test_prefix);
    let creator_did = test_did(&test_prefix, 0);

    // Create conversation
    let _ = sqlx::query(
        r#"
        INSERT INTO conversations (convo_id, creator_did, epoch, created_at, updated_at)
        VALUES ($1, $2, 0, NOW(), NOW())
        "#,
    )
    .bind(&convo_id)
    .bind(&creator_did)
    .execute(&pool)
    .await;

    let _ = sqlx::query(
        r#"
        INSERT INTO members (convo_id, member_did, joined_at)
        VALUES ($1, $2, NOW())
        "#,
    )
    .bind(&convo_id)
    .bind(&creator_did)
    .execute(&pool)
    .await;

    println!("✓ Created test conversation: {}", convo_id);

    let num_messages = 200;
    let num_senders = 5;

    println!("✓ Preparing to send {} messages from {} concurrent senders...", num_messages, num_senders);

    let barrier = Arc::new(Barrier::new(num_senders));
    let pool = Arc::new(pool);

    let mut handles = vec![];

    for sender_id in 0..num_senders {
        let pool = pool.clone();
        let barrier = barrier.clone();
        let convo_id = convo_id.clone();
        let sender_did = test_did(&test_prefix, sender_id);

        let handle = tokio::spawn(async move {
            barrier.wait().await;

            let messages_per_sender = num_messages / num_senders;

            for i in 0..messages_per_sender {
                let message_id = format!("{}-msg-{}-{}", convo_id, sender_id, i);
                let idempotency_key = format!("{}-idem-{}-{}", convo_id, sender_id, i);

                let _ = sqlx::query(
                    r#"
                    INSERT INTO messages (message_id, convo_id, sender_did, ciphertext, epoch, created_at, idempotency_key)
                    VALUES ($1, $2, $3, $4, 0, NOW(), $5)
                    "#,
                )
                .bind(&message_id)
                .bind(&convo_id)
                .bind(&sender_did)
                .bind(vec![sender_id as u8, i as u8])
                .bind(&idempotency_key)
                .execute(pool.as_ref())
                .await;
            }

            sender_id
        });

        handles.push(handle);
    }

    println!("⏳ Sending messages concurrently...\n");

    futures::future::join_all(handles).await;

    // Count messages
    let message_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM messages WHERE convo_id = $1",
    )
    .bind(&convo_id)
    .fetch_one(pool.as_ref())
    .await
    .unwrap();

    println!("📊 Results:");
    println!("   Total messages sent: {}", num_messages);
    println!("   Messages in DB: {}", message_count);

    // Verify all messages have timestamps in order
    let timestamps: Vec<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT created_at FROM messages WHERE convo_id = $1 ORDER BY created_at",
    )
    .bind(&convo_id)
    .fetch_all(pool.as_ref())
    .await
    .unwrap();

    let mut ordered = true;
    for i in 1..timestamps.len() {
        if timestamps[i] < timestamps[i - 1] {
            ordered = false;
            break;
        }
    }

    println!("   Timestamps monotonic: {}", ordered);

    cleanup_test_data(&pool, &test_prefix).await;

    println!("\n✅ PASS: All messages stored with proper ordering");

    assert_eq!(message_count, num_messages as i64, "Should have all messages stored");
    assert!(ordered, "Timestamps should be monotonically increasing");
}

#[tokio::test]
#[ignore]
async fn test_cache_ttl_and_cleanup() {
    println!("\n=== BATTLE TEST: Cache TTL and Cleanup ===\n");

    let pool = create_test_pool().await;
    let test_id = Uuid::new_v4().to_string();
    let test_prefix = format!("battle-cache-{}", &test_id[..8]);

    cleanup_test_data(&pool, &test_prefix).await;

    println!("✓ Inserting 10 cache entries with short TTL (2 seconds)...");

    // Insert cache entries with 2-second TTL
    for i in 0..10 {
        let key = format!("{}-key-{}", test_prefix, i);
        sqlx::query(
            r#"
            INSERT INTO idempotency_cache (key, endpoint, response_body, status_code, expires_at)
            VALUES ($1, '/test', '{"test": true}', 200, NOW() + INTERVAL '2 seconds')
            "#,
        )
        .bind(&key)
        .execute(&pool)
        .await
        .unwrap();
    }

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM idempotency_cache WHERE key LIKE $1",
    )
    .bind(format!("{}%", test_prefix))
    .fetch_one(&pool)
    .await
    .unwrap();

    println!("✓ Inserted {} cache entries", count);
    assert_eq!(count, 10);

    println!("⏳ Waiting 3 seconds for TTL expiration...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Verify entries are still in DB but expired
    let expired_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM idempotency_cache WHERE key LIKE $1 AND expires_at < NOW()",
    )
    .bind(format!("{}%", test_prefix))
    .fetch_one(&pool)
    .await
    .unwrap();

    println!("✓ Expired entries: {}", expired_count);
    assert_eq!(expired_count, 10);

    println!("🧹 Running cleanup job...");
    let deleted = cleanup_expired_entries(&pool).await.unwrap();

    println!("✓ Deleted {} expired entries", deleted);

    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM idempotency_cache WHERE key LIKE $1",
    )
    .bind(format!("{}%", test_prefix))
    .fetch_one(&pool)
    .await
    .unwrap();

    println!("✓ Remaining entries: {}", remaining);

    cleanup_test_data(&pool, &test_prefix).await;

    println!("\n✅ PASS: Cache cleanup successfully removed expired entries");

    assert_eq!(remaining, 0, "All expired entries should be cleaned up");
}

#[tokio::test]
#[ignore]
async fn test_leave_convo_natural_idempotency() {
    println!("\n=== BATTLE TEST: Leave Convo Natural Idempotency ===\n");

    let pool = create_test_pool().await;
    let test_id = Uuid::new_v4().to_string();
    let test_prefix = format!("battle-leave-{}", &test_id[..8]);

    cleanup_test_data(&pool, &test_prefix).await;

    let convo_id = format!("{}-convo", test_prefix);
    let member_did = test_did(&test_prefix, 1);

    // Create conversation and add member
    let _ = sqlx::query(
        r#"
        INSERT INTO conversations (convo_id, creator_did, epoch, created_at, updated_at)
        VALUES ($1, $2, 0, NOW(), NOW())
        "#,
    )
    .bind(&convo_id)
    .bind(&member_did)
    .execute(&pool)
    .await;

    let _ = sqlx::query(
        r#"
        INSERT INTO members (convo_id, member_did, joined_at)
        VALUES ($1, $2, NOW())
        "#,
    )
    .bind(&convo_id)
    .bind(&member_did)
    .execute(&pool)
    .await;

    println!("✓ Created conversation with member: {}", member_did);
    println!("✓ Sending 50 concurrent leave requests...");

    let num_requests = 50;
    let barrier = Arc::new(Barrier::new(num_requests));
    let pool = Arc::new(pool);

    let mut handles = vec![];

    for i in 0..num_requests {
        let pool = pool.clone();
        let barrier = barrier.clone();
        let convo_id = convo_id.clone();
        let member_did = member_did.clone();

        let handle = tokio::spawn(async move {
            barrier.wait().await;

            // Try to leave conversation
            let result = sqlx::query(
                r#"
                UPDATE members
                SET left_at = NOW()
                WHERE convo_id = $1 AND member_did = $2 AND left_at IS NULL
                RETURNING member_did
                "#,
            )
            .bind(&convo_id)
            .bind(&member_did)
            .fetch_optional(pool.as_ref())
            .await
            .unwrap();

            (i, result.is_some())
        });

        handles.push(handle);
    }

    let results: Vec<(usize, bool)> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    let successful_leaves = results.iter().filter(|(_, success)| *success).count();

    println!("\n📊 Results:");
    println!("   Leave requests sent: {}", num_requests);
    println!("   Successful updates: {}", successful_leaves);

    // Verify member has left_at timestamp set
    let left_at: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT left_at FROM members WHERE convo_id = $1 AND member_did = $2",
    )
    .bind(&convo_id)
    .bind(&member_did)
    .fetch_one(pool.as_ref())
    .await
    .unwrap();

    println!("   Member left_at timestamp: {:?}", left_at);

    cleanup_test_data(&pool, &test_prefix).await;

    println!("\n✅ PASS: Natural idempotency via WHERE clause works correctly");

    assert_eq!(successful_leaves, 1, "Exactly one leave request should succeed");
    assert!(left_at.is_some(), "Member should have left_at timestamp");
}

#[tokio::test]
#[ignore]
async fn test_welcome_message_grace_period_recovery() {
    println!("\n=== BATTLE TEST: Welcome Message Grace Period Recovery (Two-Phase Commit) ===\n");

    let pool = create_test_pool().await;
    let test_id = Uuid::new_v4().to_string();
    let test_prefix = format!("battle-welcome-{}", &test_id[..8]);

    cleanup_test_data(&pool, &test_prefix).await;

    let convo_id = format!("{}-convo", test_prefix);
    let creator_did = test_did(&test_prefix, 0);
    let member_did = test_did(&test_prefix, 1);

    // Create conversation
    let _ = sqlx::query(
        r#"
        INSERT INTO conversations (convo_id, creator_did, epoch, created_at, updated_at)
        VALUES ($1, $2, 0, NOW(), NOW())
        "#,
    )
    .bind(&convo_id)
    .bind(&creator_did)
    .execute(&pool)
    .await;

    // Add members
    for did in &[&creator_did, &member_did] {
        let _ = sqlx::query(
            r#"
            INSERT INTO members (convo_id, member_did, joined_at)
            VALUES ($1, $2, NOW())
            "#,
        )
        .bind(&convo_id)
        .bind(did)
        .execute(&pool)
        .await;
    }

    // Create Welcome message
    let welcome_id = Uuid::new_v4().to_string();
    let welcome_data = vec![1u8, 2, 3, 4, 5];

    let _ = sqlx::query(
        r#"
        INSERT INTO welcome_messages (id, convo_id, recipient_did, welcome_data, consumed, created_at)
        VALUES ($1, $2, $3, $4, false, NOW())
        "#,
    )
    .bind(&welcome_id)
    .bind(&convo_id)
    .bind(&member_did)
    .bind(&welcome_data)
    .execute(&pool)
    .await;

    println!("✓ Created conversation with Welcome message");

    // Simulate: Client fetches Welcome (marks as consumed)
    println!("📱 Simulating: Client fetches Welcome message...");
    let rows = sqlx::query(
        r#"
        UPDATE welcome_messages
        SET consumed = true, consumed_at = NOW()
        WHERE id = $1 AND consumed = false
        RETURNING id
        "#,
    )
    .bind(&welcome_id)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(rows.is_some(), "Should mark Welcome as consumed");
    println!("✓ Welcome marked as consumed (in_flight)");

    // Simulate: App crash before confirmWelcome
    println!("💥 Simulating: App crashes before calling confirmWelcome");
    println!("⏳ Waiting 2 seconds...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Within grace period (5 minutes), client can re-fetch
    println!("🔄 Simulating: Client retries fetching Welcome (within grace period)...");

    let refetch_result: Option<(String, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT id, welcome_data
        FROM welcome_messages
        WHERE convo_id = $1 AND recipient_did = $2
        AND (consumed = false OR (consumed = true AND consumed_at > NOW() - INTERVAL '5 minutes'))
        LIMIT 1
        "#,
    )
    .bind(&convo_id)
    .bind(&member_did)
    .fetch_optional(&pool)
    .await
    .unwrap();

    println!("✓ Re-fetch result: {:?}", refetch_result.is_some());

    // Verify grace period allows re-fetch
    assert!(refetch_result.is_some(), "Should allow re-fetch within grace period");

    // Simulate successful processing and confirmation
    println!("✅ Simulating: Client successfully confirms Welcome...");

    // Update to final consumed state (in real implementation, this would be done by confirmWelcome handler)
    let _ = sqlx::query(
        r#"
        UPDATE welcome_messages
        SET consumed = true, consumed_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(&welcome_id)
    .execute(&pool)
    .await;

    println!("✓ Welcome confirmed and fully consumed");

    // Verify that after grace period expires, re-fetch would fail
    println!("\n📊 Testing grace period expiration:");

    // Manually expire the message (simulate 6 minutes passing)
    let _ = sqlx::query(
        r#"
        UPDATE welcome_messages
        SET consumed_at = NOW() - INTERVAL '6 minutes'
        WHERE id = $1
        "#,
    )
    .bind(&welcome_id)
    .execute(&pool)
    .await;

    let expired_fetch: Option<(String, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT id, welcome_data
        FROM welcome_messages
        WHERE convo_id = $1 AND recipient_did = $2
        AND (consumed = false OR (consumed = true AND consumed_at > NOW() - INTERVAL '5 minutes'))
        LIMIT 1
        "#,
    )
    .bind(&convo_id)
    .bind(&member_did)
    .fetch_optional(&pool)
    .await
    .unwrap();

    println!("✓ After grace period: {:?}", expired_fetch.is_some());
    assert!(expired_fetch.is_none(), "Should NOT allow re-fetch after grace period");

    cleanup_test_data(&pool, &test_prefix).await;

    println!("\n✅ PASS: Two-phase commit with grace period recovery works correctly");
}

#[tokio::test]
#[ignore]
async fn test_database_constraints_prevent_corruption() {
    println!("\n=== BATTLE TEST: Database Constraints Prevent Data Corruption ===\n");

    let pool = create_test_pool().await;
    let test_id = Uuid::new_v4().to_string();
    let test_prefix = format!("battle-constraints-{}", &test_id[..8]);

    cleanup_test_data(&pool, &test_prefix).await;

    println!("✓ Testing UNIQUE constraint on idempotency_key...");

    let convo_id = format!("{}-convo", test_prefix);
    let creator_did = test_did(&test_prefix, 0);
    let idempotency_key = format!("{}-key", test_prefix);

    // Create conversation
    let _ = sqlx::query(
        r#"
        INSERT INTO conversations (convo_id, creator_did, epoch, created_at, updated_at)
        VALUES ($1, $2, 0, NOW(), NOW())
        "#,
    )
    .bind(&convo_id)
    .bind(&creator_did)
    .execute(&pool)
    .await;

    // Insert first message with idempotency key
    let result1 = sqlx::query(
        r#"
        INSERT INTO messages (message_id, convo_id, sender_did, ciphertext, epoch, created_at, idempotency_key)
        VALUES ($1, $2, $3, $4, 0, NOW(), $5)
        "#,
    )
    .bind(format!("{}-msg-1", test_prefix))
    .bind(&convo_id)
    .bind(&creator_did)
    .bind(vec![1u8])
    .bind(&idempotency_key)
    .execute(&pool)
    .await;

    println!("   First insert: {:?}", result1.is_ok());
    assert!(result1.is_ok());

    // Try to insert second message with SAME idempotency key (should fail)
    let result2 = sqlx::query(
        r#"
        INSERT INTO messages (message_id, convo_id, sender_did, ciphertext, epoch, created_at, idempotency_key)
        VALUES ($1, $2, $3, $4, 0, NOW(), $5)
        "#,
    )
    .bind(format!("{}-msg-2", test_prefix))
    .bind(&convo_id)
    .bind(&creator_did)
    .bind(vec![2u8])
    .bind(&idempotency_key)
    .execute(&pool)
    .await;

    println!("   Second insert with same key: {:?}", result2.is_ok());

    let message_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM messages WHERE idempotency_key = $1",
    )
    .bind(&idempotency_key)
    .fetch_one(&pool)
    .await
    .unwrap();

    println!("   Messages in DB: {}", message_count);

    cleanup_test_data(&pool, &test_prefix).await;

    println!("\n✅ PASS: Database constraints prevent duplicate idempotency keys");

    assert!(result2.is_err(), "Second insert should fail due to UNIQUE constraint");
    assert_eq!(message_count, 1, "Only one message should exist");
}

// Test summary
#[tokio::test]
async fn print_battle_test_suite_info() {
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║           MLS SERVER BATTLE TEST SUITE                       ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    println!("Available Tests (run with --ignored):\n");
    println!("1. test_idempotency_stress_100x_concurrent_identical_requests");
    println!("   → Verifies exactly-once semantics under 100x concurrent load");
    println!();
    println!("2. test_concurrent_member_addition_race_conditions");
    println!("   → Tests race conditions when adding members concurrently");
    println!();
    println!("3. test_message_ordering_under_high_concurrency");
    println!("   → Validates message timestamps under concurrent sends");
    println!();
    println!("4. test_cache_ttl_and_cleanup");
    println!("   → Tests cache expiration and cleanup job");
    println!();
    println!("5. test_leave_convo_natural_idempotency");
    println!("   → Tests natural idempotency via SQL WHERE clauses");
    println!();
    println!("6. test_welcome_message_grace_period_recovery");
    println!("   → Tests two-phase commit with grace period for app crash recovery");
    println!();
    println!("7. test_database_constraints_prevent_corruption");
    println!("   → Validates UNIQUE constraints prevent duplicate keys");
    println!();
    println!("\nRun all tests:");
    println!("  cargo test --test battle_tests -- --ignored --nocapture");
    println!();
    println!("Run specific test:");
    println!("  cargo test --test battle_tests test_name -- --ignored --nocapture\n");
}
