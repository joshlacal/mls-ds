# MLS Server Battle Test Suite

Comprehensive stress tests for critical MLS server functionality including idempotency, two-phase commits, and concurrent operations.

## Overview

The battle test suite validates the server's behavior under extreme conditions:

- **Idempotency**: 100x concurrent identical requests with same idempotency key
- **Concurrency**: Race conditions in member additions and message sending
- **Two-Phase Commit**: Welcome message grace period and crash recovery
- **Data Integrity**: Database constraints and natural idempotency patterns
- **Cache Management**: TTL expiration and cleanup jobs

## Prerequisites

### 1. PostgreSQL Database

You need a running PostgreSQL instance. Use Docker Compose:

```bash
# From the project root
docker-compose up -d postgres

# Verify it's running
docker-compose ps
```

### 2. Test Database Setup

Create a separate test database (recommended to avoid interfering with development data):

```bash
# Connect to PostgreSQL
docker-compose exec postgres psql -U catbird

# Create test database
CREATE DATABASE catbird_test;
\q
```

### 3. Environment Variables

Set the test database URL:

```bash
export DATABASE_URL="postgresql://catbird:password@localhost:5432/catbird_test"
```

### 4. Run Migrations

Apply database migrations to the test database:

```bash
cd server
sqlx migrate run --database-url $DATABASE_URL
```

## Running the Tests

### Run All Battle Tests

```bash
cd server
cargo test --test battle_tests -- --ignored --nocapture --test-threads=1
```

**Flags explained:**
- `--test battle_tests`: Run only the battle test suite
- `--ignored`: Run tests marked with `#[ignore]` attribute
- `--nocapture`: Show `println!` output for visibility
- `--test-threads=1`: Run tests sequentially to avoid database conflicts

### Run Specific Test

```bash
# Test idempotency under concurrent load
cargo test --test battle_tests test_idempotency_stress_100x_concurrent_identical_requests -- --ignored --nocapture

# Test concurrent member additions
cargo test --test battle_tests test_concurrent_member_addition_race_conditions -- --ignored --nocapture

# Test message ordering
cargo test --test battle_tests test_message_ordering_under_high_concurrency -- --ignored --nocapture

# Test cache TTL and cleanup
cargo test --test battle_tests test_cache_ttl_and_cleanup -- --ignored --nocapture

# Test natural idempotency (leave convo)
cargo test --test battle_tests test_leave_convo_natural_idempotency -- --ignored --nocapture

# Test two-phase commit recovery
cargo test --test battle_tests test_welcome_message_grace_period_recovery -- --ignored --nocapture

# Test database constraints
cargo test --test battle_tests test_database_constraints_prevent_corruption -- --ignored --nocapture
```

### View Test List

```bash
cargo test --test battle_tests print_battle_test_suite_info -- --nocapture
```

## Test Descriptions

### 1. Idempotency Stress Test

**File**: `server/tests/battle_tests.rs:54`

**What it tests**: Sends 100 concurrent identical requests with the same idempotency key to verify exactly-once semantics.

**Expected behavior**:
- Exactly 1 message is created in the database
- Exactly 1 cache entry exists
- All subsequent requests get cached responses
- No duplicate data is created

**Assertions**:
- `message_count == 1`
- `cache_count == 1`
- `actual_creates <= 1`

### 2. Concurrent Member Addition

**File**: `server/tests/battle_tests.rs:178`

**What it tests**: 50 concurrent requests trying to add the same 10 members to a conversation.

**Expected behavior**:
- No duplicate members created (natural idempotency via `ON CONFLICT DO NOTHING`)
- Final member count is exactly 11 (1 creator + 10 added)
- Database constraints prevent duplicates

**Assertions**:
- `member_count == 11`

### 3. Message Ordering Under High Concurrency

**File**: `server/tests/battle_tests.rs:290`

**What it tests**: 200 messages from 5 concurrent senders to verify message ordering and timestamps.

**Expected behavior**:
- All 200 messages are stored
- Timestamps are monotonically increasing
- No messages are lost or duplicated

**Assertions**:
- `message_count == 200`
- Timestamps are ordered

### 4. Cache TTL and Cleanup

**File**: `server/tests/battle_tests.rs:394`

**What it tests**: Inserts cache entries with 2-second TTL, waits for expiration, runs cleanup job.

**Expected behavior**:
- Entries expire after TTL
- Cleanup job successfully removes expired entries
- No active entries are accidentally removed

**Assertions**:
- `expired_count == 10`
- `remaining == 0` after cleanup

### 5. Leave Convo Natural Idempotency

**File**: `server/tests/battle_tests.rs:616`

**What it tests**: 50 concurrent requests to leave the same conversation (same user).

**Expected behavior**:
- Exactly 1 update succeeds (via `WHERE left_at IS NULL`)
- Member has `left_at` timestamp set
- Subsequent requests are no-ops (idempotent)

**Assertions**:
- `successful_leaves == 1`
- `left_at.is_some()`

### 6. Welcome Message Grace Period Recovery

**File**: `server/tests/battle_tests.rs:712`

**What it tests**: Two-phase commit for Welcome messages with app crash simulation.

**Expected behavior**:
- Client fetches Welcome (marks as consumed/in_flight)
- App crashes before confirmation
- Within 5-minute grace period, client can re-fetch
- After grace period expires, re-fetch fails

**Assertions**:
- Re-fetch succeeds within grace period
- Re-fetch fails after grace period

### 7. Database Constraints

**File**: `server/tests/battle_tests.rs:873`

**What it tests**: UNIQUE constraints on idempotency keys prevent duplicate data.

**Expected behavior**:
- First insert with idempotency key succeeds
- Second insert with same key fails with constraint violation
- Only 1 message exists in database

**Assertions**:
- `result2.is_err()` (second insert fails)
- `message_count == 1`

## Test Data Cleanup

Each test uses a unique prefix (e.g., `battle-idem-abc123`) to isolate test data. The `cleanup_test_data()` helper function removes all test data before and after each test.

**Manual cleanup** (if tests crash):

```sql
-- Connect to test database
psql $DATABASE_URL

-- Find test data
SELECT convo_id FROM conversations WHERE convo_id LIKE 'battle-%';

-- Clean up manually if needed
DELETE FROM members WHERE convo_id LIKE 'battle-%';
DELETE FROM messages WHERE convo_id LIKE 'battle-%';
DELETE FROM conversations WHERE convo_id LIKE 'battle-%';
DELETE FROM idempotency_cache WHERE key LIKE 'battle-%';
DELETE FROM key_packages WHERE owner_did LIKE 'did:test:battle-%';
```

## Performance Benchmarks

Expected test durations on a standard development machine:

| Test | Duration | Operations |
|------|----------|------------|
| Idempotency Stress | ~2-5s | 100 concurrent requests |
| Concurrent Member Addition | ~1-3s | 50 concurrent × 10 members |
| Message Ordering | ~3-8s | 200 messages from 5 senders |
| Cache TTL | ~5s | 2s wait + cleanup |
| Leave Convo | ~1-2s | 50 concurrent updates |
| Welcome Grace Period | ~5s | 2s wait + multiple fetches |
| Database Constraints | ~1s | 2 inserts |

**Total runtime**: ~20-30 seconds for all tests

## Troubleshooting

### "Failed to connect to test database"

**Problem**: Database URL is incorrect or PostgreSQL isn't running.

**Solution**:
```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# Start PostgreSQL
docker-compose up -d postgres

# Verify connection
psql $DATABASE_URL -c "SELECT 1"
```

### "Relation does not exist" errors

**Problem**: Migrations haven't been run on test database.

**Solution**:
```bash
# Run migrations
sqlx migrate run --database-url $DATABASE_URL
```

### Tests hang or timeout

**Problem**: Database connection pool exhausted or deadlock.

**Solution**:
```bash
# Kill hanging connections
docker-compose restart postgres

# Run tests with more verbose output
RUST_LOG=debug cargo test --test battle_tests -- --ignored --nocapture
```

### "Already exists" constraint violations

**Problem**: Test data from previous run wasn't cleaned up.

**Solution**:
```bash
# Connect to database
psql $DATABASE_URL

# Clean up test data
DELETE FROM members WHERE convo_id LIKE 'battle-%';
DELETE FROM messages WHERE convo_id LIKE 'battle-%';
DELETE FROM conversations WHERE convo_id LIKE 'battle-%';
DELETE FROM idempotency_cache WHERE key LIKE 'battle-%';
DELETE FROM welcome_messages WHERE convo_id LIKE 'battle-%';
```

## Interpreting Results

### Successful Test Output

```
=== BATTLE TEST: Idempotency Stress (100x Concurrent Identical Requests) ===

✓ Created test conversation: battle-idem-abc123-convo
✓ Preparing 100 concurrent identical requests...
✓ Launched 100 concurrent tasks
⏳ Waiting for all tasks to complete...

📊 Results:
   Cache hits: 94
   Cache misses: 6
   Actual DB inserts: 1
   Messages in DB: 1
   Cache entries: 1

✅ PASS: Idempotency guaranteed exactly-once semantics
```

**Key metrics**:
- **Cache hits**: Number of requests that found cached response
- **Cache misses**: Number of requests that proceeded to database
- **Actual DB inserts**: Should be exactly 1
- **Messages in DB**: Should be exactly 1 (verified in database)

### Failed Test Output

```
thread 'test_idempotency_stress_100x_concurrent_identical_requests' panicked at:
Should have exactly 1 message in database: left: `2`, right: `1`
```

**Indicates**: Idempotency failed; duplicate messages were created. This is a critical bug.

## Continuous Integration

Add to your CI pipeline:

```yaml
# .github/workflows/test.yml
name: Battle Tests

on: [push, pull_request]

jobs:
  battle-tests:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: catbird
          POSTGRES_PASSWORD: password
          POSTGRES_DB: catbird_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
      - uses: actions/checkout@v3

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Run migrations
        run: |
          cd server
          cargo install sqlx-cli --no-default-features --features postgres
          sqlx migrate run
        env:
          DATABASE_URL: postgresql://catbird:password@localhost:5432/catbird_test

      - name: Run battle tests
        run: |
          cd server
          cargo test --test battle_tests -- --ignored --nocapture --test-threads=1
        env:
          DATABASE_URL: postgresql://catbird:password@localhost:5432/catbird_test
```

## Next Steps

After verifying battle tests pass:

1. **Load Testing**: Use tools like `k6` or `wrk` for HTTP-level load testing
2. **Chaos Engineering**: Simulate network failures, database crashes
3. **Production Monitoring**: Set up alerts for idempotency cache hit rates
4. **Performance Profiling**: Use `cargo flamegraph` to identify bottlenecks

## Contributing

When adding new features that involve state changes:

1. Add a corresponding battle test
2. Verify idempotency if applicable
3. Test concurrent operations
4. Document expected behavior

## References

- [Idempotency Middleware](../src/middleware/idempotency.rs)
- [Two-Phase Commit (Welcome Messages)](../src/handlers/get_welcome.rs)
- [Database Schema](../migrations/)
