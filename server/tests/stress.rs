// Stress tests for load testing the actor system
// Run manually with: cargo test --test stress -- --ignored

use catbird_server::actors::{ActorRegistry, ConvoMessage, KeyPackageHashEntry};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// Test helper to set up a test database with higher connection pool
async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://catbird:changeme@localhost:5433/catbird".to_string());

    let config = catbird_server::db::DbConfig {
        database_url,
        max_connections: 50, // Higher for stress tests
        min_connections: 10,
        acquire_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(600),
    };

    catbird_server::db::init_db(config)
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

    // Add creator as member
    sqlx::query(
        "INSERT INTO members (convo_id, member_did, joined_at, unread_count)
         VALUES ($1, $2, $3, 0)
         ON CONFLICT (convo_id, member_did) DO NOTHING",
    )
    .bind(convo_id)
    .bind(creator)
    .bind(&now)
    .execute(pool)
    .await
    .expect("Failed to add creator as member");
}

/// Calculate percentile from sorted samples
fn percentile(sorted_samples: &[u128], p: f64) -> u128 {
    if sorted_samples.is_empty() {
        return 0;
    }
    let idx = ((sorted_samples.len() - 1) as f64 * p) as usize;
    sorted_samples[idx]
}

#[tokio::test]
#[ignore] // Run manually with: cargo test --test stress -- --ignored
async fn test_1000_conversations_concurrent() {
    println!("\n=== Stress Test: 1000 Conversations, 100 Messages Each ===\n");

    let pool = setup_test_db().await;
    let registry = Arc::new(ActorRegistry::new(pool.clone()));

    let num_conversations = 1000;
    let messages_per_conversation = 100;

    // Track metrics
    let mut latencies_ms = Vec::new();
    let overall_start = Instant::now();

    // Create all conversations first
    println!("Creating {} test conversations...", num_conversations);
    for i in 0..num_conversations {
        let convo_id = format!("stress-convo-{}", i);
        cleanup_test_data(&pool, &convo_id).await;
        create_test_convo(&pool, &convo_id, "did:plc:stress-test").await;
    }
    println!("Conversations created.\n");

    // Spawn all actors and send messages concurrently
    println!(
        "Spawning actors and sending {} messages to each...",
        messages_per_conversation
    );
    let mut handles = vec![];

    for i in 0..num_conversations {
        let registry_clone = Arc::clone(&registry);
        let convo_id = format!("stress-convo-{}", i);

        let handle = tokio::spawn(async move {
            let actor = registry_clone
                .get_or_spawn(&convo_id)
                .await
                .expect("Failed to spawn actor");

            let mut message_latencies = Vec::new();

            for msg_idx in 0..messages_per_conversation {
                let start = Instant::now();

                let (tx, rx) = oneshot::channel();
                actor
                    .cast(ConvoMessage::SendMessage {
                        sender_did: "did:plc:stress-test".to_string(),
                        ciphertext: vec![msg_idx as u8; 100], // 100 byte messages
                        reply: tx,
                    })
                    .expect("Failed to send message");

                let result = rx.await.expect("Failed to receive result");
                assert!(result.is_ok(), "Message failed");

                let latency = start.elapsed();
                message_latencies.push(latency.as_micros());
            }

            message_latencies
        });

        handles.push(handle);
    }

    // Collect all latencies
    println!("Waiting for all messages to complete...");
    for handle in handles {
        let message_latencies = handle.await.expect("Task failed");
        latencies_ms.extend(message_latencies);
    }

    let overall_duration = overall_start.elapsed();

    // Calculate statistics
    latencies_ms.sort_unstable();
    let total_messages = num_conversations * messages_per_conversation;

    let p50 = percentile(&latencies_ms, 0.50);
    let p95 = percentile(&latencies_ms, 0.95);
    let p99 = percentile(&latencies_ms, 0.99);
    let max_latency = latencies_ms.last().copied().unwrap_or(0);

    let throughput = (total_messages as f64) / overall_duration.as_secs_f64();

    // Print results
    println!("\n=== Results ===");
    println!("Total messages processed: {}", total_messages);
    println!("Total time: {:.2}s", overall_duration.as_secs_f64());
    println!("Throughput: {:.2} msg/sec", throughput);
    println!("\nLatency (microseconds):");
    println!("  p50: {} µs ({:.2} ms)", p50, p50 as f64 / 1000.0);
    println!("  p95: {} µs ({:.2} ms)", p95, p95 as f64 / 1000.0);
    println!("  p99: {} µs ({:.2} ms)", p99, p99 as f64 / 1000.0);
    println!(
        "  max: {} µs ({:.2} ms)",
        max_latency,
        max_latency as f64 / 1000.0
    );
    println!("\nActive actors: {}", registry.actor_count());

    // Performance assertions
    assert!(
        throughput > 100.0,
        "Throughput too low: {:.2} msg/sec",
        throughput
    );
    assert!(p99 < 1_000_000, "p99 latency too high: {} µs", p99); // Less than 1 second

    // Cleanup
    println!("\nCleaning up...");
    registry.shutdown_all().await;
    for i in 0..num_conversations {
        let convo_id = format!("stress-convo-{}", i);
        cleanup_test_data(&pool, &convo_id).await;
    }
    println!("Test complete.\n");
}

#[tokio::test]
#[ignore]
async fn test_sustained_load() {
    println!("\n=== Stress Test: Sustained Load (100 req/sec for 10 minutes) ===\n");

    let pool = setup_test_db().await;
    let registry = Arc::new(ActorRegistry::new(pool.clone()));

    let target_rps = 100; // Requests per second
    let duration_seconds = 60 * 10; // 10 minutes
    let num_conversations = 10; // Spread load across 10 conversations

    // Create conversations
    println!("Creating {} test conversations...", num_conversations);
    for i in 0..num_conversations {
        let convo_id = format!("sustained-convo-{}", i);
        cleanup_test_data(&pool, &convo_id).await;
        create_test_convo(&pool, &convo_id, "did:plc:sustained-test").await;
    }
    println!("Conversations created.\n");

    // Spawn actors
    let mut actors = Vec::new();
    for i in 0..num_conversations {
        let convo_id = format!("sustained-convo-{}", i);
        let actor = registry
            .get_or_spawn(&convo_id)
            .await
            .expect("Failed to spawn actor");
        actors.push((convo_id.clone(), actor));
    }

    // Track metrics
    let mut total_messages = 0;
    let mut error_count = 0;
    let interval = Duration::from_millis(1000 / target_rps as u64);
    let mut latencies = Vec::new();

    println!("Starting sustained load test...");
    println!(
        "Target: {} req/sec for {} seconds",
        target_rps, duration_seconds
    );
    println!("Interval between requests: {:?}\n", interval);

    let start = Instant::now();
    let mut next_tick = Instant::now();

    while start.elapsed().as_secs() < duration_seconds {
        next_tick += interval;

        // Select random conversation
        let idx = total_messages % num_conversations;
        let (_convo_id, actor) = &actors[idx];

        // Send message
        let msg_start = Instant::now();
        let (tx, rx) = oneshot::channel();
        if let Err(_) = actor.cast(ConvoMessage::SendMessage {
            sender_did: "did:plc:sustained-test".to_string(),
            ciphertext: vec![0u8; 100],
            reply: tx,
        }) {
            error_count += 1;
            continue;
        }

        // Don't wait for response to maintain throughput
        tokio::spawn(async move {
            let _ = rx.await;
        });

        let latency = msg_start.elapsed();
        latencies.push(latency.as_micros());
        total_messages += 1;

        // Print progress every 10 seconds
        if total_messages % (target_rps * 10) == 0 {
            let elapsed = start.elapsed().as_secs();
            let actual_rps = total_messages as f64 / elapsed as f64;
            println!(
                "  {}s: {} messages sent ({:.2} req/sec), {} errors, {} actors",
                elapsed,
                total_messages,
                actual_rps,
                error_count,
                registry.actor_count()
            );
        }

        // Sleep until next tick
        let now = Instant::now();
        if next_tick > now {
            tokio::time::sleep(next_tick - now).await;
        }
    }

    let total_duration = start.elapsed();

    // Calculate statistics
    latencies.sort_unstable();
    let p50 = percentile(&latencies, 0.50);
    let p95 = percentile(&latencies, 0.95);
    let p99 = percentile(&latencies, 0.99);
    let actual_rps = total_messages as f64 / total_duration.as_secs_f64();

    // Print results
    println!("\n=== Results ===");
    println!("Total messages sent: {}", total_messages);
    println!("Total errors: {}", error_count);
    println!("Total time: {:.2}s", total_duration.as_secs_f64());
    println!("Actual throughput: {:.2} req/sec", actual_rps);
    println!("\nLatency (microseconds):");
    println!("  p50: {} µs ({:.2} ms)", p50, p50 as f64 / 1000.0);
    println!("  p95: {} µs ({:.2} ms)", p95, p95 as f64 / 1000.0);
    println!("  p99: {} µs ({:.2} ms)", p99, p99 as f64 / 1000.0);
    println!("\nFinal actor count: {}", registry.actor_count());

    // Performance assertions
    assert_eq!(error_count, 0, "Should have no errors");
    assert!(
        actual_rps >= target_rps as f64 * 0.9,
        "Actual RPS too low: {:.2}",
        actual_rps
    );
    assert_eq!(
        registry.actor_count(),
        num_conversations,
        "Actor count should remain stable"
    );

    // Cleanup
    println!("\nCleaning up...");
    registry.shutdown_all().await;
    for i in 0..num_conversations {
        let convo_id = format!("sustained-convo-{}", i);
        cleanup_test_data(&pool, &convo_id).await;
    }
    println!("Test complete.\n");
}

#[tokio::test]
#[ignore]
async fn test_actor_restart_under_load() {
    println!("\n=== Stress Test: Actor Restart Under Load ===\n");

    let pool = setup_test_db().await;
    let registry = Arc::new(ActorRegistry::new(pool.clone()));

    let num_conversations = 100;
    let messages_per_convo = 50;
    let kill_percentage = 10; // Kill 10% of actors randomly

    // Create conversations
    println!("Creating {} test conversations...", num_conversations);
    for i in 0..num_conversations {
        let convo_id = format!("restart-convo-{}", i);
        cleanup_test_data(&pool, &convo_id).await;
        create_test_convo(&pool, &convo_id, "did:plc:restart-test").await;
    }
    println!("Conversations created.\n");

    let overall_start = Instant::now();
    let mut total_messages_sent = 0;
    let mut total_errors = 0;

    println!("Starting load test with random actor restarts...");

    // Spawn tasks
    let mut handles = vec![];
    for i in 0..num_conversations {
        let registry_clone = Arc::clone(&registry);
        let convo_id = format!("restart-convo-{}", i);
        let should_kill = (i % (100 / kill_percentage)) == 0; // Kill ~10% of actors

        let handle = tokio::spawn(async move {
            let mut messages_sent = 0;
            let mut errors = 0;

            for msg_idx in 0..messages_per_convo {
                // Get or spawn actor
                let actor = match registry_clone.get_or_spawn(&convo_id).await {
                    Ok(a) => a,
                    Err(_) => {
                        errors += 1;
                        continue;
                    }
                };

                // Kill actor randomly at midpoint
                if should_kill && msg_idx == messages_per_convo / 2 {
                    println!("  Killing actor for conversation: {}", convo_id);
                    actor.stop(None);
                    registry_clone.remove_actor(&convo_id);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }

                // Send message
                let (tx, rx) = oneshot::channel();
                if let Err(_) = actor.cast(ConvoMessage::SendMessage {
                    sender_did: "did:plc:restart-test".to_string(),
                    ciphertext: vec![msg_idx as u8; 50],
                    reply: tx,
                }) {
                    errors += 1;
                    continue;
                }

                match rx.await {
                    Ok(Ok(_)) => messages_sent += 1,
                    _ => errors += 1,
                }
            }

            (messages_sent, errors)
        });

        handles.push(handle);
    }

    // Collect results
    for handle in handles {
        let (sent, errors) = handle.await.expect("Task failed");
        total_messages_sent += sent;
        total_errors += errors;
    }

    let overall_duration = overall_start.elapsed();

    // Print results
    println!("\n=== Results ===");
    println!("Total messages sent: {}", total_messages_sent);
    println!("Total errors: {}", total_errors);
    println!("Total time: {:.2}s", overall_duration.as_secs_f64());
    println!("Final actor count: {}", registry.actor_count());

    // Verify actors can be restarted
    let expected_messages = num_conversations * messages_per_convo;
    let killed_messages = (num_conversations * kill_percentage / 100) * 1; // 1 message lost per killed actor
    let min_expected =
        expected_messages - killed_messages - (num_conversations * kill_percentage / 100);

    assert!(
        total_messages_sent >= min_expected,
        "Too many messages lost: sent {}, expected at least {}",
        total_messages_sent,
        min_expected
    );

    // Verify actors are still responsive after restart
    println!("\nVerifying all actors are responsive...");
    for i in 0..num_conversations {
        let convo_id = format!("restart-convo-{}", i);
        let actor = registry
            .get_or_spawn(&convo_id)
            .await
            .expect("Failed to get actor");

        let (tx, rx) = oneshot::channel();
        actor
            .cast(ConvoMessage::GetEpoch { reply: tx })
            .expect("Failed to send GetEpoch");
        let _epoch = rx.await.expect("Failed to receive epoch");
    }
    println!("All actors responsive!");

    // Cleanup
    println!("\nCleaning up...");
    registry.shutdown_all().await;
    for i in 0..num_conversations {
        let convo_id = format!("restart-convo-{}", i);
        cleanup_test_data(&pool, &convo_id).await;
    }
    println!("Test complete.\n");
}
