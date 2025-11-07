# Actor System Operations Runbook

**Version:** 1.0
**Last Updated:** 2025-11-02
**Status:** Production-Ready

---

## Table of Contents

1. [Monitoring Actor Health](#monitoring-actor-health)
2. [Common Failure Modes](#common-failure-modes)
3. [Remediation Procedures](#remediation-procedures)
4. [Tuning Parameters](#tuning-parameters)
5. [Debugging Guide](#debugging-guide)
6. [Performance Optimization](#performance-optimization)
7. [Alert Definitions](#alert-definitions)
8. [Incident Response](#incident-response)

---

## Monitoring Actor Health

### Key Metrics to Watch

**1. Active Actor Count**

```bash
# Check current actor count
curl http://localhost:8080/metrics | grep actor_registry_active_actors

# Expected ranges:
# Normal: 10-1000 actors
# High: 1000-5000 actors (peak traffic)
# Critical: 10,000+ actors (potential leak)
```

**Grafana query:**

```promql
actor_registry_active_actors
```

**Dashboard visualization:**
- Gauge (current value)
- Graph (historical trend over 24h)

**2. Actor Spawn Rate**

```bash
# Check spawn rate (last hour)
curl http://localhost:8080/metrics | grep actor_spawns_total

# Calculate rate:
rate(actor_spawns_total[1h])
```

**Expected values:**
- Normal: 1-10 spawns/minute
- High: 10-50 spawns/minute (new conversations)
- Critical: 100+ spawns/minute (potential spawn loop)

**3. Message Processing Latency**

```bash
# Check P95 message processing time
curl http://localhost:8080/metrics | grep actor_message_duration_p95

# Expected values:
# Fast: < 10ms (GetEpoch, IncrementUnread)
# Normal: 10-50ms (AddMembers, SendMessage)
# Slow: 50-200ms (large batches)
# Critical: > 200ms (database issues)
```

**Grafana query:**

```promql
histogram_quantile(0.95, rate(actor_message_duration_bucket[5m]))
```

**4. Error Rate**

```bash
# Check actor error count
curl http://localhost:8080/metrics | grep actor_errors_total

# Calculate error rate:
rate(actor_errors_total[5m]) / rate(actor_messages_total[5m])

# Expected: < 0.01% (1 error per 10,000 messages)
```

**5. Database Connection Pool Usage**

```bash
# Check pool utilization
curl http://localhost:8080/metrics | grep db_pool_connections_active

# Expected:
# Normal: 5-10 connections
# High: 10-20 connections
# Critical: 20+ connections (pool exhausted)
```

### Normal vs Abnormal Behavior

**Normal:**

```
actor_registry_active_actors: 500
actor_spawns_total: 1000 (rate: 5/min)
actor_message_duration_p95: 25ms
actor_errors_total: 0 (rate: 0%)
db_pool_connections_active: 8
```

**Abnormal (High Load):**

```
actor_registry_active_actors: 3000 ↑
actor_spawns_total: 5000 (rate: 20/min) ↑
actor_message_duration_p95: 150ms ↑
actor_errors_total: 50 (rate: 0.5%) ↑
db_pool_connections_active: 18 ↑
```

**Critical (System Degraded):**

```
actor_registry_active_actors: 15000 🔴
actor_spawns_total: 20000 (rate: 200/min) 🔴
actor_message_duration_p95: 500ms 🔴
actor_errors_total: 500 (rate: 5%) 🔴
db_pool_connections_active: 20 (maxed out) 🔴
```

### Grafana Dashboard Setup

**Create dashboard with these panels:**

**Panel 1: Actor Health Overview**

```json
{
  "title": "Actor Registry Health",
  "targets": [
    {"expr": "actor_registry_active_actors", "legendFormat": "Active Actors"},
    {"expr": "rate(actor_spawns_total[5m])", "legendFormat": "Spawn Rate"},
    {"expr": "rate(actor_stops_total[5m])", "legendFormat": "Stop Rate"}
  ],
  "type": "graph"
}
```

**Panel 2: Message Processing**

```json
{
  "title": "Message Processing Latency",
  "targets": [
    {"expr": "histogram_quantile(0.50, rate(actor_message_duration_bucket[5m]))", "legendFormat": "P50"},
    {"expr": "histogram_quantile(0.95, rate(actor_message_duration_bucket[5m]))", "legendFormat": "P95"},
    {"expr": "histogram_quantile(0.99, rate(actor_message_duration_bucket[5m]))", "legendFormat": "P99"}
  ],
  "type": "graph"
}
```

**Panel 3: Error Rate**

```json
{
  "title": "Actor Error Rate",
  "targets": [
    {"expr": "rate(actor_errors_total[5m])", "legendFormat": "{{error_type}}"}
  ],
  "type": "graph",
  "alert": {
    "conditions": [
      {"type": "query", "query": {"params": ["A", "5m", "now"]}, "reducer": {"type": "avg"}, "evaluator": {"type": "gt", "params": [0.01]}}
    ]
  }
}
```

**Panel 4: Resource Usage**

```json
{
  "title": "Database Connection Pool",
  "targets": [
    {"expr": "db_pool_connections_active", "legendFormat": "Active"},
    {"expr": "db_pool_connections_idle", "legendFormat": "Idle"},
    {"expr": "db_pool_connections_max", "legendFormat": "Max"}
  ],
  "type": "graph"
}
```

---

## Common Failure Modes

### 1. Actor Crash Loop

**Symptoms:**

```
ERROR Actor crashed: database transaction failed
INFO Spawning new actor for conversation <id>
ERROR Actor crashed: database transaction failed
INFO Spawning new actor for conversation <id>
...
```

**Causes:**

- Database connection timeout
- Invalid database state (e.g., missing conversation)
- Database constraint violation

**Detection:**

```bash
# Check for repeated crashes
docker logs catbird-mls-server 2>&1 | grep "Actor crashed" | wc -l

# Check for spawn loops
docker logs catbird-mls-server 2>&1 | grep "Spawning new actor" | uniq -c | sort -rn
```

**Remediation:** See [Handling Actor Crashes](#handling-actor-crashes)

### 2. Mailbox Backlog

**Symptoms:**

```
actor_mailbox_size: 10000+ (messages queued)
actor_message_duration_p95: 500ms+ (slow processing)
HTTP request timeout (clients)
```

**Causes:**

- Slow database queries
- Database connection pool exhausted
- High message rate (more messages arriving than processing)

**Detection:**

```bash
# Check mailbox size (not yet implemented)
# Workaround: check database active connections

docker exec catbird-postgres psql -U catbird -d catbird -c "
SELECT COUNT(*) FROM pg_stat_activity WHERE state = 'active';
"

# Expected: < 10
# Problem: 20+ (pool exhausted)
```

**Remediation:** See [Clearing Mailbox Backlog](#clearing-mailbox-backlog)

### 3. Epoch Conflicts

**Symptoms:**

```sql
SELECT convo_id, epoch, COUNT(*) FROM messages
WHERE message_type = 'commit'
GROUP BY convo_id, epoch
HAVING COUNT(*) > 1;

-- Returns rows (duplicate epochs)
```

**Causes:**

- Actor system disabled (`ENABLE_ACTOR_SYSTEM=false`)
- Multiple server instances without sticky sessions
- Database replication lag (if using replicas)

**Detection:**

```bash
# Check for duplicate epochs (last 1 hour)
docker exec catbird-postgres psql -U catbird -d catbird -c "
SELECT convo_id, epoch, COUNT(*) as count
FROM messages
WHERE message_type = 'commit'
  AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY convo_id, epoch
HAVING COUNT(*) > 1;
"

# Expected: 0 rows
# Problem: 1+ rows (epoch conflicts detected)
```

**Remediation:** See [Handling Epoch Conflicts](#handling-epoch-conflicts)

### 4. Memory Leak

**Symptoms:**

```bash
# Memory usage growing over time
docker stats catbird-mls-server
# Shows memory increasing from 200MB to 2GB+
```

**Causes:**

- Actors not being cleaned up (no TTL or inactivity timeout)
- Unread count hashmap growing unbounded
- Actor mailbox accumulating messages

**Detection:**

```bash
# Check actor count over time
curl http://localhost:8080/metrics | grep actor_registry_active_actors

# Check memory usage
docker stats catbird-mls-server --no-stream
```

**Remediation:** See [Memory Leak Mitigation](#memory-leak-mitigation)

---

## Remediation Procedures

### Handling Actor Crashes

**Step 1: Identify the crashing conversation**

```bash
# Find conversation IDs with repeated crashes
docker logs catbird-mls-server 2>&1 | grep "Actor crashed" | grep -oP 'conversation \K\S+' | sort | uniq -c | sort -rn

# Output:
# 45 convo-abc123
# 12 convo-def456
```

**Step 2: Inspect database state**

```bash
# Check if conversation exists and is valid
docker exec catbird-postgres psql -U catbird -d catbird -c "
SELECT id, creator_did, current_epoch, created_at
FROM conversations
WHERE id = 'convo-abc123';
"

# Check for orphaned data
docker exec catbird-postgres psql -U catbird -d catbird -c "
SELECT COUNT(*) FROM members WHERE convo_id = 'convo-abc123';
SELECT COUNT(*) FROM messages WHERE convo_id = 'convo-abc123';
"
```

**Step 3: Fix database state (if corrupted)**

```bash
# If conversation doesn't exist but has messages:
docker exec catbird-postgres psql -U catbird -d catbird -c "
-- Recreate conversation
INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at)
VALUES ('convo-abc123', 'did:plc:unknown', 0, NOW(), NOW())
ON CONFLICT (id) DO NOTHING;
"

# If epoch is out of sync:
docker exec catbird-postgres psql -U catbird -d catbird -c "
-- Reset epoch to max message epoch
UPDATE conversations
SET current_epoch = (
    SELECT COALESCE(MAX(epoch), 0) FROM messages WHERE convo_id = 'convo-abc123'
)
WHERE id = 'convo-abc123';
"
```

**Step 4: Restart server (actors will be re-spawned)**

```bash
docker restart catbird-mls-server
```

**Step 5: Monitor for recurrence**

```bash
# Watch logs for new crashes
docker logs -f catbird-mls-server | grep "Actor crashed"

# If crashes continue, escalate to engineering team
```

### Clearing Mailbox Backlog

**Step 1: Identify slow queries**

```bash
# Check PostgreSQL slow query log
docker logs catbird-postgres 2>&1 | grep "duration:"

# Find queries taking > 100ms
docker logs catbird-postgres 2>&1 | grep "duration:" | awk '$2 > 100'
```

**Step 2: Check database connection pool**

```bash
# Check active connections
docker exec catbird-postgres psql -U catbird -d catbird -c "
SELECT COUNT(*), state FROM pg_stat_activity GROUP BY state;
"

# Expected:
# active: 5-10
# idle: 0-5

# Problem:
# active: 20+ (pool exhausted)
```

**Step 3: Increase connection pool (temporary fix)**

```bash
# Increase max connections
export DATABASE_MAX_CONNECTIONS=30

# Restart server
docker restart catbird-mls-server
```

**Step 4: Optimize slow queries (permanent fix)**

```sql
-- Add indexes for common queries
CREATE INDEX CONCURRENTLY idx_messages_convo_epoch ON messages(convo_id, epoch);
CREATE INDEX CONCURRENTLY idx_members_convo_active ON members(convo_id) WHERE left_at IS NULL;
```

**Step 5: Monitor recovery**

```bash
# Check message processing latency
curl http://localhost:8080/metrics | grep actor_message_duration_p95

# Should decrease from 500ms to < 50ms
```

### Handling Epoch Conflicts

**Step 1: Verify actor system is enabled**

```bash
# Check environment variable
docker exec catbird-mls-server env | grep ENABLE_ACTOR_SYSTEM

# Should be: ENABLE_ACTOR_SYSTEM=true

# Check logs for confirmation
docker logs catbird-mls-server 2>&1 | grep "Using actor system"

# Should see: "Using actor system for add_members"
```

**Step 2: Fix duplicate epochs in database**

```bash
# Identify duplicate epochs
docker exec catbird-postgres psql -U catbird -d catbird -c "
SELECT convo_id, epoch, COUNT(*) as count
FROM messages
WHERE message_type = 'commit'
GROUP BY convo_id, epoch
HAVING COUNT(*) > 1;
"

# For each duplicate, keep the first and delete the rest:
docker exec catbird-postgres psql -U catbird -d catbird -c "
DELETE FROM messages
WHERE id IN (
    SELECT id FROM (
        SELECT id, ROW_NUMBER() OVER (PARTITION BY convo_id, epoch ORDER BY created_at) as rn
        FROM messages
        WHERE message_type = 'commit'
    ) t
    WHERE rn > 1
);
"
```

**Step 3: Reset conversation epoch**

```bash
# Update conversation epoch to max message epoch
docker exec catbird-postgres psql -U catbird -d catbird -c "
UPDATE conversations c
SET current_epoch = (
    SELECT COALESCE(MAX(epoch), 0)
    FROM messages
    WHERE convo_id = c.id
);
"
```

**Step 4: Restart actors**

```bash
# Restart server to re-spawn actors with correct state
docker restart catbird-mls-server
```

**Step 5: Monitor for new conflicts**

```bash
# Check for new duplicates (every 5 minutes)
while true; do
    docker exec catbird-postgres psql -U catbird -d catbird -c "
    SELECT COUNT(*) FROM (
        SELECT convo_id, epoch, COUNT(*) as count
        FROM messages
        WHERE message_type = 'commit' AND created_at > NOW() - INTERVAL '5 minutes'
        GROUP BY convo_id, epoch
        HAVING COUNT(*) > 1
    ) duplicates;
    "
    sleep 300
done

# Should always be 0
```

### Memory Leak Mitigation

**Step 1: Check actor count trend**

```bash
# Check current actor count
curl http://localhost:8080/metrics | grep actor_registry_active_actors

# Compare with historical data (1 hour ago, 1 day ago)
# If growing linearly, likely a leak
```

**Step 2: Identify stale actors**

```bash
# List all active conversations
docker exec catbird-postgres psql -U catbird -d catbird -c "
SELECT id, current_epoch, created_at,
       (SELECT MAX(created_at) FROM messages WHERE convo_id = conversations.id) as last_message
FROM conversations
WHERE (SELECT MAX(created_at) FROM messages WHERE convo_id = conversations.id) < NOW() - INTERVAL '7 days';
"

# Actors for these conversations can be cleaned up
```

**Step 3: Restart server (temporary fix)**

```bash
# Restart to clear all actors
docker restart catbird-mls-server

# Actor count should drop to 0, then grow as conversations are accessed
```

**Step 4: Implement actor TTL (permanent fix)**

```rust
// TODO: Add to ConversationActor
pub struct ActorConfig {
    pub inactivity_timeout: Duration, // e.g., 1 hour
}

// In actor handle():
// Check last message time
// If > inactivity_timeout, send Shutdown message
```

**Step 5: Schedule periodic restarts (workaround)**

```bash
# Add cron job to restart server daily
crontab -e

# Add line:
0 4 * * * docker restart catbird-mls-server

# Restart at 4am daily (low traffic time)
```

---

## Tuning Parameters

### Database Connection Pool

**Current settings:**

```rust
DbConfig {
    database_url: env::var("DATABASE_URL")?,
    max_connections: 10,      // ← Tune this
    min_connections: 2,
    acquire_timeout: Duration::from_secs(30),
    idle_timeout: Duration::from_secs(600),
}
```

**Tuning guidelines:**

| Metric | Value | Recommendation |
|--------|-------|----------------|
| Active connections | < 5 | Reduce to 5 (save resources) |
| Active connections | 5-10 | Current setting OK |
| Active connections | 10+ (maxed out) | Increase to 20 |
| Active connections | 20+ (maxed out) | Scale horizontally (add servers) |

**How to tune:**

```bash
# Increase max connections
export DATABASE_MAX_CONNECTIONS=20

# Restart server
docker restart catbird-mls-server

# Monitor connection usage
docker exec catbird-postgres psql -U catbird -d catbird -c "
SELECT COUNT(*), state FROM pg_stat_activity GROUP BY state;
"
```

### Message Processing Timeout

**Current settings:**

```rust
// No timeout implemented (messages wait indefinitely)
```

**Recommended settings:**

```rust
pub struct ActorConfig {
    pub message_timeout: Duration, // e.g., 30 seconds
}

// If message processing takes > timeout, cancel and return error
```

**How to tune:**

- **Fast operations (GetEpoch):** 1 second
- **Normal operations (AddMembers, SendMessage):** 30 seconds
- **Slow operations (large batches):** 60 seconds

### Actor Inactivity Cleanup

**Current settings:**

```rust
// No cleanup (actors live forever)
```

**Recommended settings:**

```rust
pub struct ActorConfig {
    pub inactivity_timeout: Duration, // e.g., 1 hour
    pub cleanup_interval: Duration,   // e.g., 5 minutes
}

// Every cleanup_interval:
// - Check last message time for each actor
// - If > inactivity_timeout, send Shutdown message
```

**How to tune:**

| Conversation activity | Inactivity timeout |
|-----------------------|--------------------|
| High (messages every minute) | 1 hour |
| Medium (messages every hour) | 24 hours |
| Low (messages every day) | 7 days |

---

## Debugging Guide

### Inspecting Actor State

**Current limitation:** Actor state is not directly inspectable

**Workaround: Query database for equivalent state**

```bash
# Get conversation epoch (actor's current_epoch)
docker exec catbird-postgres psql -U catbird -d catbird -c "
SELECT id, current_epoch FROM conversations WHERE id = '<convo_id>';
"

# Get member unread counts (actor's unread_counts hashmap)
docker exec catbird-postgres psql -U catbird -d catbird -c "
SELECT member_did, unread_count FROM members WHERE convo_id = '<convo_id>';
"
```

**Future enhancement:**

```rust
// Add debug message
ConvoMessage::GetState { reply: oneshot::Sender<ActorState> }

// Returns full actor state for debugging
```

### Tracing Message Flow

**Enable trace logging:**

```bash
export RUST_LOG=trace,catbird_server::actors=trace
docker restart catbird-mls-server
```

**Follow a request:**

```bash
# 1. Send request
curl -X POST http://localhost:8080/xrpc/blue.catbird.mls.addMembers \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"convo_id": "test-convo", "did_list": ["did:plc:member1"]}'

# 2. Search logs for request ID
docker logs catbird-mls-server 2>&1 | grep "test-convo"

# Expected trace:
# TRACE [add_members] START - convo: test-convo
# DEBUG Spawning new actor for conversation test-convo
# DEBUG ConversationActor test-convo starting at epoch 5
# TRACE Sending AddMembers message to actor
# TRACE Actor processing AddMembers
# DEBUG Adding 1 members to conversation test-convo
# DEBUG Members added, new epoch: 6 for conversation test-convo
# TRACE [add_members] COMPLETE - new_epoch: 6
```

### Database Consistency Checks

**Check 1: Epoch consistency**

```bash
# Verify conversation epoch matches max message epoch
docker exec catbird-postgres psql -U catbird -d catbird -c "
SELECT c.id, c.current_epoch, COALESCE(MAX(m.epoch), 0) as max_message_epoch
FROM conversations c
LEFT JOIN messages m ON c.id = m.convo_id
GROUP BY c.id, c.current_epoch
HAVING c.current_epoch != COALESCE(MAX(m.epoch), 0);
"

# Expected: 0 rows (all consistent)
# If rows returned, epochs are out of sync
```

**Check 2: No duplicate epochs**

```bash
docker exec catbird-postgres psql -U catbird -d catbird -c "
SELECT convo_id, epoch, COUNT(*) as count
FROM messages
WHERE message_type = 'commit'
GROUP BY convo_id, epoch
HAVING COUNT(*) > 1;
"

# Expected: 0 rows
```

**Check 3: Sequential message sequence numbers**

```bash
docker exec catbird-postgres psql -U catbird -d catbird -c "
SELECT convo_id, COUNT(*) as message_count, MAX(seq) as max_seq
FROM messages
WHERE message_type = 'app'
GROUP BY convo_id
HAVING MAX(seq) != COUNT(*);
"

# Expected: 0 rows (sequence is 1, 2, 3, ...)
```

**Check 4: Active members have no left_at**

```bash
docker exec catbird-postgres psql -U catbird -d catbird -c "
SELECT convo_id, member_did, left_at
FROM members
WHERE left_at IS NOT NULL
  AND unread_count > 0;
"

# Expected: 0 rows (left members shouldn't have unread counts)
```

### Performance Profiling

**Identify slow operations:**

```bash
# Check P95 latency by message type
curl http://localhost:8080/metrics | grep actor_message_duration | grep p95

# Output:
# actor_message_duration_p95{message_type="add_members"} 45.2
# actor_message_duration_p95{message_type="send_message"} 32.1
# actor_message_duration_p95{message_type="get_epoch"} 0.5
```

**Profile database queries:**

```bash
# Enable query logging
docker exec catbird-postgres psql -U postgres -c "
ALTER SYSTEM SET log_min_duration_statement = 100;
SELECT pg_reload_conf();
"

# Watch for slow queries
docker logs -f catbird-postgres | grep "duration:"
```

---

## Performance Optimization

### Identifying Bottlenecks

**1. Check database query performance:**

```sql
-- Find slowest queries
SELECT query, calls, mean_exec_time, max_exec_time
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;
```

**2. Check database connection pool:**

```bash
curl http://localhost:8080/metrics | grep db_pool

# If pool is maxed out, increase max_connections
```

**3. Check actor processing time:**

```bash
curl http://localhost:8080/metrics | grep actor_message_duration

# If > 100ms, investigate slow database queries
```

### Scaling Strategies

**Vertical scaling (single server):**

```bash
# Increase CPU/memory
# Increase database connection pool
export DATABASE_MAX_CONNECTIONS=30

# Tune PostgreSQL
docker exec catbird-postgres psql -U postgres -c "
ALTER SYSTEM SET max_connections = 100;
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
SELECT pg_reload_conf();
"
```

**Horizontal scaling (multiple servers):**

**Challenge:** Actors are local to each server

**Solution 1: Sticky sessions** (route same conversation to same server)

```nginx
# Nginx configuration
upstream mls_servers {
    ip_hash; # Route by client IP
    server server1:8080;
    server server2:8080;
    server server3:8080;
}
```

**Solution 2: Distributed actors** (future work)

```rust
// TODO: Implement distributed actor registry
// Use Redis or etcd for actor location tracking
// Use gRPC for inter-server actor communication
```

### Database Optimization

**Add indexes for actor queries:**

```sql
-- Speed up epoch lookup
CREATE INDEX CONCURRENTLY idx_messages_convo_epoch
ON messages(convo_id, epoch) WHERE message_type = 'commit';

-- Speed up member lookup
CREATE INDEX CONCURRENTLY idx_members_convo_active
ON members(convo_id) WHERE left_at IS NULL;

-- Speed up sequence number calculation
CREATE INDEX CONCURRENTLY idx_messages_convo_seq
ON messages(convo_id, seq) WHERE message_type = 'app';
```

**Optimize transaction isolation level:**

```rust
// Use READ COMMITTED instead of SERIALIZABLE
let mut tx = pool.begin().await?;
sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
    .execute(&mut *tx)
    .await?;
```

---

## Alert Definitions

### ActorRestartRateHigh

**Metric:** `rate(actor_spawns_total[5m]) > 10`

**Severity:** Warning

**Description:** Actors are being spawned at an unusually high rate, indicating potential crash loops.

**Remediation:**

1. Check logs for actor crashes
2. Identify problematic conversation IDs
3. Inspect database state for corrupted data
4. Fix database inconsistencies
5. Restart server if needed

### ActorMailboxBacklog

**Metric:** `actor_mailbox_size > 1000` (when implemented)

**Severity:** Critical

**Description:** Actor mailbox has accumulated 1000+ messages, indicating processing bottleneck.

**Remediation:**

1. Check database connection pool usage
2. Identify slow database queries
3. Increase connection pool size
4. Optimize slow queries
5. Consider horizontal scaling

### EpochConflictDetected

**SQL Query:**

```sql
SELECT COUNT(*) FROM (
    SELECT convo_id, epoch, COUNT(*) as count
    FROM messages
    WHERE message_type = 'commit' AND created_at > NOW() - INTERVAL '1 hour'
    GROUP BY convo_id, epoch
    HAVING COUNT(*) > 1
) duplicates;
```

**Threshold:** > 0

**Severity:** Critical

**Description:** Duplicate epochs detected, indicating race conditions or actor system failure.

**Remediation:**

1. Verify `ENABLE_ACTOR_SYSTEM=true`
2. Check if multiple servers are running (need sticky sessions)
3. Fix duplicate epochs in database
4. Restart server
5. Escalate if problem persists

### ActorUnresponsive

**Metric:** `actor_message_duration_p95 > 1000` (1 second)

**Severity:** Critical

**Description:** Actor message processing is taking > 1 second, indicating system degradation.

**Remediation:**

1. Check database health
2. Check connection pool utilization
3. Identify slow queries
4. Kill long-running database queries
5. Restart server if needed

### MemoryUsageHigh

**Metric:** `container_memory_usage_bytes > 2GB`

**Severity:** Warning

**Description:** Server memory usage is high, potentially due to actor leak.

**Remediation:**

1. Check actor count trend
2. Identify stale actors
3. Restart server to clear actors
4. Implement actor TTL (long-term fix)

---

## Incident Response

### On-Call Playbook

**Step 1: Assess severity**

- **SEV1 (Critical):** Service down, data loss, security breach
- **SEV2 (High):** Partial outage, high error rate, severe degradation
- **SEV3 (Medium):** Degraded performance, elevated error rate
- **SEV4 (Low):** Minor issues, warnings

**Step 2: Initial triage**

```bash
# Check service health
curl http://localhost:8080/health

# Check recent errors
docker logs catbird-mls-server --since 10m 2>&1 | grep ERROR

# Check metrics
curl http://localhost:8080/metrics | grep actor
```

**Step 3: Common issues and quick fixes**

| Symptom | Quick Fix | Time |
|---------|-----------|------|
| Actor spawn loop | Restart server | 30s |
| Database pool exhausted | Increase max_connections | 1min |
| Epoch conflicts | Disable actors, rollback | 2min |
| Memory leak | Restart server | 30s |
| Slow queries | Kill queries, add indexes | 5min |

**Step 4: Escalation criteria**

Escalate to engineering team if:

- Quick fixes don't work
- Problem recurs after fix
- Data corruption suspected
- Unclear root cause
- Security concerns

### Escalation Procedures

**Who to contact:**

1. **On-call engineer** (PagerDuty)
2. **Team lead** (Slack: @mls-team-lead)
3. **CTO** (for SEV1 only)

**What to provide:**

- Severity level (SEV1-4)
- Symptoms (errors, metrics, logs)
- Impact (users affected, data loss)
- Actions taken (what you tried)
- Timeline (when did it start)

**Communication channels:**

- **Slack:** #incidents
- **PagerDuty:** Automated alerts
- **Email:** incidents@catbird.com

### Post-Incident Review

**After resolving incident:**

1. **Document timeline** (what happened, when)
2. **Identify root cause** (why it happened)
3. **List contributing factors** (what made it worse)
4. **Propose action items** (how to prevent)
5. **Schedule post-mortem** (review with team)

**Post-mortem template:**

```
Incident: [Title]
Date: [YYYY-MM-DD]
Severity: [SEV1-4]
Duration: [X hours]

Timeline:
- HH:MM - Incident detected
- HH:MM - Mitigation started
- HH:MM - Incident resolved

Root Cause:
[Detailed explanation]

Contributing Factors:
- [Factor 1]
- [Factor 2]

Impact:
- [Users affected]
- [Requests failed]
- [Data loss]

Action Items:
- [ ] [Action 1] (Owner: @person, Due: YYYY-MM-DD)
- [ ] [Action 2] (Owner: @person, Due: YYYY-MM-DD)

Lessons Learned:
- [Lesson 1]
- [Lesson 2]
```

---

## Maintenance Tasks

### Daily

**1. Check metrics dashboard**

```bash
# Open Grafana
open http://grafana.catbird.com/d/actor-health

# Verify:
# - Actor count stable
# - Error rate < 0.01%
# - Latency < 50ms
```

**2. Review error logs**

```bash
# Check for new error patterns
docker logs catbird-mls-server --since 24h 2>&1 | grep ERROR | sort | uniq -c | sort -rn

# Investigate any errors with > 10 occurrences
```

### Weekly

**1. Database health check**

```bash
# Run consistency checks
./scripts/db-health-check.sh

# Expected: All checks pass
```

**2. Review actor count trend**

```bash
# Check if actor count is growing unbounded
curl http://localhost:8080/metrics | grep actor_registry_active_actors

# Compare with last week (should be similar)
```

**3. Performance review**

```bash
# Check P95 latency trend
curl http://localhost:8080/metrics | grep actor_message_duration_p95

# If degrading, investigate slow queries
```

### Monthly

**1. Capacity planning**

```bash
# Check peak actor count
# Check peak message rate
# Project growth for next 3 months
```

**2. Database optimization**

```sql
-- Update statistics
ANALYZE;

-- Vacuum
VACUUM ANALYZE;

-- Reindex
REINDEX DATABASE catbird;
```

**3. Security review**

```bash
# Update dependencies
cargo update

# Run security audit
cargo audit

# Apply patches
```

---

## Best Practices

### Operational Excellence

1. **Monitor proactively** (don't wait for alerts)
2. **Test rollbacks regularly** (ensure they work)
3. **Document incidents** (learn from failures)
4. **Automate common tasks** (reduce human error)
5. **Keep runbook updated** (as system evolves)

### On-Call Tips

1. **Know your tools** (practice before incident)
2. **Don't panic** (follow runbook systematically)
3. **Communicate clearly** (keep team informed)
4. **Take notes** (for post-mortem)
5. **Ask for help** (escalate when needed)

### Production Hygiene

1. **Never modify production database directly** (use migrations)
2. **Always test fixes in staging first** (prevent new issues)
3. **Take backups before risky operations** (enable rollback)
4. **Use feature flags** (for easy rollback)
5. **Monitor after deployments** (catch issues early)

---

## Resources

**Documentation:**

- [ACTOR_ARCHITECTURE.md](ACTOR_ARCHITECTURE.md) - Technical details
- [ACTOR_MIGRATION.md](ACTOR_MIGRATION.md) - Migration guide
- [DATABASE_SCHEMA.md](/home/ubuntu/mls/server/DATABASE_SCHEMA.md) - Database reference

**Tools:**

- Grafana: http://grafana.catbird.com
- PagerDuty: https://catbird.pagerduty.com
- Slack: #mls-server-ops

**Contacts:**

- On-call: Check PagerDuty
- Team lead: @mls-team-lead (Slack)
- CTO: @cto (Slack, SEV1 only)

---

## Appendix: Quick Reference

### Common Commands

```bash
# Check actor count
curl http://localhost:8080/metrics | grep actor_registry_active_actors

# Check for errors
docker logs catbird-mls-server 2>&1 | grep ERROR | tail -20

# Restart server
docker restart catbird-mls-server

# Check database connections
docker exec catbird-postgres psql -U catbird -d catbird -c "SELECT COUNT(*), state FROM pg_stat_activity GROUP BY state;"

# Check for epoch conflicts
docker exec catbird-postgres psql -U catbird -d catbird -c "SELECT convo_id, epoch, COUNT(*) FROM messages WHERE message_type = 'commit' GROUP BY convo_id, epoch HAVING COUNT(*) > 1;"

# Enable debug logging
export RUST_LOG=debug,catbird_server::actors=trace
docker restart catbird-mls-server
```

### Emergency Contacts

| Role | Contact | When to Use |
|------|---------|-------------|
| On-call Engineer | PagerDuty | Any incident |
| Team Lead | @mls-team-lead (Slack) | Escalation needed |
| Database Admin | @db-admin (Slack) | Database issues |
| Infrastructure | @infra-team (Slack) | Server/network issues |
| CTO | @cto (Slack) | SEV1 only |

---

**Last Updated:** 2025-11-02
**Version:** 1.0
**Maintained by:** MLS Server Team
