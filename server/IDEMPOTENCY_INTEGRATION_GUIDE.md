# Idempotency Middleware Integration Guide

## Overview

The idempotency middleware provides automatic deduplication of write operations using PostgreSQL-backed caching. When a client sends a request with an `idempotencyKey` in the JSON body, the middleware:

1. Checks if a cached response exists for that key
2. Returns the cached response immediately if found (cache HIT)
3. Otherwise, processes the request normally and caches the response (cache MISS)
4. Only caches successful (2xx) and client error (4xx) responses
5. Skips caching server errors (5xx) as they may be transient

## Files Created

### 1. Migration: `/home/ubuntu/mls/server/migrations/20251102_001_idempotency_cache.sql`

Creates the `idempotency_cache` table with:
- `key`: Primary key (the idempotency key from request)
- `endpoint`: The API endpoint path
- `response_body`: Cached JSON response
- `status_code`: HTTP status code
- `created_at`: When the entry was created
- `expires_at`: When the entry expires (TTL)

Also adds optional `idempotency_key` columns to `messages` and `conversations` tables for permanent tracking.

**Migration Status**: ✅ Successfully applied to database

### 2. Middleware: `/home/ubuntu/mls/server/src/middleware/idempotency.rs`

Contains:
- `IdempotencyLayer`: Configuration struct
- `idempotency_middleware`: The middleware function
- `cleanup_expired_entries`: Cleanup function for background task
- Helper functions for cache operations

### 3. Module Export: `/home/ubuntu/mls/server/src/middleware/mod.rs`

Updated to export the `idempotency` module.

## Integration Steps

### Step 1: Apply the Migration (Already Done)

The migration has been applied successfully to the database.

To verify:
```bash
docker exec catbird-postgres psql -U catbird -d catbird -c "\d idempotency_cache"
```

### Step 2: Add Middleware to Routes (Option A: Global)

Add the idempotency middleware globally to all POST/PUT/PATCH routes:

```rust
// In src/main.rs

use crate::middleware::idempotency::IdempotencyLayer;

// After creating app_state...
let app_state = AppState {
    db_pool: db_pool.clone(),
    sse_state,
    actor_registry,
};

// Create idempotency layer
let idempotency_layer = IdempotencyLayer::new(db_pool.clone());

let mut base_router = Router::new()
    // ... all your routes ...
    .layer(TraceLayer::new_for_http())
    .layer(axum::middleware::from_fn_with_state(
        idempotency_layer.clone(),
        crate::middleware::idempotency::idempotency_middleware
    ))
    .with_state(app_state);
```

### Step 2: Add Middleware to Routes (Option B: Selective)

Add the middleware only to specific routes that need idempotency:

```rust
// In src/main.rs

use crate::middleware::idempotency::IdempotencyLayer;
use axum::middleware::from_fn_with_state;

// Create idempotency layer
let idempotency_layer = IdempotencyLayer::new(db_pool.clone());

// Create separate routers for routes with/without idempotency
let idempotent_routes = Router::new()
    .route("/xrpc/blue.catbird.mls.sendMessage", post(handlers::send_message))
    .route("/xrpc/blue.catbird.mls.createConvo", post(handlers::create_convo))
    .route("/xrpc/blue.catbird.mls.addMembers", post(handlers::add_members))
    .route("/xrpc/blue.catbird.mls.publishKeyPackage", post(handlers::publish_key_package))
    .layer(from_fn_with_state(
        idempotency_layer,
        crate::middleware::idempotency::idempotency_middleware
    ));

let other_routes = Router::new()
    .route("/health", get(health::health))
    // ... other routes without idempotency ...
    ;

let mut base_router = Router::new()
    .merge(idempotent_routes)
    .merge(other_routes)
    .layer(TraceLayer::new_for_http())
    .with_state(app_state);
```

### Step 3: Add Cleanup Background Task

Add a background task to periodically clean up expired cache entries:

```rust
// In src/main.rs, after creating db_pool

use tokio::time::{interval, Duration};
use crate::middleware::idempotency::cleanup_expired_entries;

// Spawn cleanup worker
let cleanup_pool = db_pool.clone();
tokio::spawn(async move {
    let mut interval = interval(Duration::from_secs(3600)); // Every hour
    loop {
        interval.tick().await;
        if let Err(e) = cleanup_expired_entries(&cleanup_pool).await {
            tracing::error!("Failed to cleanup idempotency cache: {}", e);
        } else {
            tracing::debug!("Idempotency cache cleanup completed");
        }
    }
});
tracing::info!("Idempotency cleanup worker started");
```

### Step 4: Update Handler Input Types (Optional)

To track idempotency keys permanently in database records, update your input types:

```rust
// Example: src/models.rs or handler input structs

#[derive(Debug, Deserialize, Serialize)]
pub struct SendMessageInput {
    pub convo_id: String,
    pub sender_did: String,
    pub ciphertext: Vec<u8>,
    pub epoch: i64,

    // Add idempotency key (optional field)
    #[serde(default, rename = "idempotencyKey")]
    pub idempotency_key: Option<String>,
}

// In handler:
pub async fn send_message(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<SendMessageInput>,
) -> Result<Json<SendMessageOutput>, StatusCode> {
    // Store idempotency key in database if provided
    if let Some(ref idem_key) = input.idempotency_key {
        // Include in INSERT statement:
        sqlx::query(
            "INSERT INTO messages (..., idempotency_key) VALUES (..., $n)"
        )
        .bind(idem_key)
        // ...
        .execute(&pool)
        .await?;
    }

    // ... rest of handler
}
```

## Configuration Options

### Custom TTL

Change the cache TTL (default is 1 hour):

```rust
use std::time::Duration;

let idempotency_layer = IdempotencyLayer::with_ttl(
    db_pool.clone(),
    Duration::from_secs(7200) // 2 hours
);
```

### Environment Variables

You can make TTL and cleanup interval configurable:

```rust
let ttl_seconds = std::env::var("IDEMPOTENCY_TTL_SECONDS")
    .unwrap_or_else(|_| "3600".to_string())
    .parse()
    .unwrap_or(3600);

let idempotency_layer = IdempotencyLayer::with_ttl(
    db_pool.clone(),
    Duration::from_secs(ttl_seconds)
);

let cleanup_interval_seconds = std::env::var("IDEMPOTENCY_CLEANUP_INTERVAL")
    .unwrap_or_else(|_| "3600".to_string())
    .parse()
    .unwrap_or(3600);

let mut interval = interval(Duration::from_secs(cleanup_interval_seconds));
```

## Client Usage

Clients should include an `idempotencyKey` field in their JSON request body:

```json
{
  "idempotencyKey": "550e8400-e29b-41d4-a716-446655440000",
  "convoId": "...",
  "senderDid": "...",
  "ciphertext": "...",
  "epoch": 42
}
```

The idempotency key should be:
- A unique string (UUID recommended)
- Generated once per logical operation
- Reused on retry attempts
- Different for each distinct operation

## How It Works

### Request Flow

1. **Client sends request** with `idempotencyKey` in JSON body
2. **Middleware extracts** the idempotency key
3. **Cache check** queries PostgreSQL:
   ```sql
   SELECT response_body, status_code FROM idempotency_cache
   WHERE key = $1 AND endpoint = $2 AND expires_at > NOW()
   ```
4. **On cache HIT**: Return cached response immediately
5. **On cache MISS**: Process request normally
6. **After processing**: Store response in cache (if 2xx or 4xx)
   ```sql
   INSERT INTO idempotency_cache (key, endpoint, response_body, status_code, expires_at)
   VALUES (...)
   ON CONFLICT (key) DO UPDATE ...
   ```

### Caching Rules

**Cached**:
- Successful responses (200-299)
- Client errors (400-499) - prevents retrying invalid requests

**Not Cached**:
- Server errors (500-599) - may be transient, should be retried
- Requests without idempotency key
- Non-JSON responses

### Cleanup Process

The background task runs periodically (default: hourly) to remove expired entries:

```sql
DELETE FROM idempotency_cache WHERE expires_at < NOW()
```

This prevents unbounded growth of the cache table.

## Monitoring

### Logs

The middleware logs at different levels:

- `INFO`: Cache hits, cache stores, cleanup completions
- `DEBUG`: Cache misses, skipped requests
- `WARN`: Non-JSON responses
- `ERROR`: Database errors, body extraction failures

Example log output:
```
INFO  Idempotency cache HIT for key=550e8400-... endpoint=/xrpc/blue.catbird.mls.sendMessage status=200
INFO  Stored idempotency cache for key=660e8400-... endpoint=/xrpc/blue.catbird.mls.createConvo status=201 ttl=3600s
INFO  Cleaned up 42 expired idempotency cache entries
```

### Metrics (Future Enhancement)

Consider adding metrics for:
- Cache hit rate
- Cache miss rate
- Cache size
- Cleanup frequency
- Response time differences (cached vs uncached)

## Testing

### Manual Testing

```bash
# First request - should process normally (cache MISS)
curl -X POST http://localhost:8080/xrpc/blue.catbird.mls.sendMessage \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "idempotencyKey": "test-key-123",
    "convoId": "...",
    "senderDid": "...",
    "ciphertext": "...",
    "epoch": 1
  }'

# Second request with same key - should return cached response (cache HIT)
curl -X POST http://localhost:8080/xrpc/blue.catbird.mls.sendMessage \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "idempotencyKey": "test-key-123",
    "convoId": "...",
    "senderDid": "...",
    "ciphertext": "...",
    "epoch": 1
  }'
```

### Database Verification

```bash
# Check cached entries
docker exec catbird-postgres psql -U catbird -d catbird -c \
  "SELECT key, endpoint, status_code, created_at, expires_at FROM idempotency_cache;"

# Check cleanup works
docker exec catbird-postgres psql -U catbird -d catbird -c \
  "UPDATE idempotency_cache SET expires_at = NOW() - INTERVAL '1 hour';"

# Run cleanup manually
# Then verify entries were deleted
```

## Performance Considerations

1. **PostgreSQL Performance**: Each request with idempotency key adds one SELECT query (cache check). On cache hit, the handler is skipped entirely.

2. **Body Buffering**: The middleware reads the request body into memory. For large requests (e.g., large ciphertext), this adds memory overhead.

3. **Index Usage**: The `idx_idempotency_expires` index ensures cleanup is fast. The primary key index ensures cache lookups are O(1).

4. **Cleanup Frequency**: Adjust cleanup interval based on:
   - Cache entry creation rate
   - Database disk space
   - TTL duration

## Future Enhancements

1. **Redis Backend**: For higher performance, consider using Redis instead of PostgreSQL
2. **Distributed Locking**: For multi-instance deployments, add distributed locks to prevent concurrent processing
3. **Partial Matching**: Support wildcards or prefix matching for related operations
4. **Admin API**: Endpoints to view, clear, or manage cache entries
5. **Metrics Dashboard**: Grafana dashboard for cache performance

## Troubleshooting

### Cache Not Working

1. Check logs for errors
2. Verify migration was applied: `\d idempotency_cache`
3. Ensure middleware is properly attached to routes
4. Verify request includes `idempotencyKey` in JSON body
5. Check database connectivity

### Cache Not Expiring

1. Verify cleanup task is running (check logs)
2. Check cleanup interval configuration
3. Manually trigger cleanup: `cleanup_expired_entries(&pool).await`

### High Cache Hit Rate Issues

If cache hit rate is too high (returning stale data):
- Reduce TTL
- Use unique idempotency keys per operation
- Clear cache for specific endpoints if needed

### Performance Issues

If middleware adds too much latency:
- Monitor database query performance
- Consider Redis backend
- Adjust cleanup frequency
- Add database connection pooling
