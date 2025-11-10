# Idempotency Middleware Implementation Summary

## Created Files

### 1. Database Migration
**File**: `/home/ubuntu/mls/server/migrations/20251102_001_idempotency_cache.sql`

Creates the `idempotency_cache` table for storing cached responses with TTL support. Also adds optional `idempotency_key` columns to `messages` and `conversations` tables.

**Status**: ✅ Successfully applied to database

**Schema**:
```
                     Table "public.idempotency_cache"
    Column     |           Type           | Collation | Nullable | Default
---------------+--------------------------+-----------+----------+---------
 key           | text                     |           | not null |
 endpoint      | text                     |           | not null |
 response_body | jsonb                    |           | not null |
 status_code   | integer                  |           | not null |
 created_at    | timestamp with time zone |           | not null | now()
 expires_at    | timestamp with time zone |           | not null |
Indexes:
    "idempotency_cache_pkey" PRIMARY KEY, btree (key)
    "idx_idempotency_endpoint" btree (endpoint)
    "idx_idempotency_expires" btree (expires_at)
```

### 2. Idempotency Middleware
**File**: `/home/ubuntu/mls/server/src/middleware/idempotency.rs`

**Exports**:
- `IdempotencyLayer` - Configuration struct for the middleware
- `idempotency_middleware()` - The middleware function (to be used with `from_fn_with_state`)
- `cleanup_expired_entries()` - Background cleanup function

**Key Features**:
- Extracts `idempotencyKey` from JSON request body
- Queries PostgreSQL cache before processing request
- Returns cached response on cache HIT
- Stores response in cache on cache MISS
- Only caches 2xx and 4xx responses (skips 5xx server errors)
- Configurable TTL (default: 1 hour)
- Comprehensive tracing/logging

**Status**: ✅ Compiles successfully

### 3. Middleware Module Export
**File**: `/home/ubuntu/mls/server/src/middleware/mod.rs`

Updated to export the `idempotency` module:
```rust
pub mod rate_limit;
pub mod mls_auth;
pub mod idempotency;
```

### 4. Documentation Files

#### Integration Guide
**File**: `/home/ubuntu/mls/server/IDEMPOTENCY_INTEGRATION_GUIDE.md`

Comprehensive guide covering:
- How the middleware works
- Configuration options
- Client usage examples
- Monitoring and logging
- Testing procedures
- Performance considerations
- Troubleshooting

#### Main.rs Example
**File**: `/home/ubuntu/mls/server/IDEMPOTENCY_MAIN_RS_EXAMPLE.md`

Shows exact code changes needed in `main.rs` with two options:
- Option 1: Global idempotency (apply to all POST/PUT/PATCH routes)
- Option 2: Selective idempotency (apply to specific routes only)

## How It Works

### Request Flow

```
Client Request
    ↓
[Extract idempotencyKey from JSON body]
    ↓
[Query PostgreSQL idempotency_cache]
    ↓
┌─────────────────┬────────────────────┐
│   Cache HIT?    │    Cache MISS?     │
│                 │                    │
│ Return cached   │  Process request   │
│ response        │         ↓          │
│ immediately     │  Store response    │
│                 │  in cache (if 2xx  │
│                 │  or 4xx)           │
└─────────────────┴────────────────────┘
    ↓
Response to Client
```

### Caching Strategy

**Cached**:
- ✅ 2xx Success responses (200, 201, etc.)
- ✅ 4xx Client errors (400, 404, etc.) - prevents retrying invalid requests

**Not Cached**:
- ❌ 5xx Server errors - may be transient, should allow retries
- ❌ Requests without `idempotencyKey`
- ❌ Non-JSON responses

### Database Schema

**Primary Table**: `idempotency_cache`
- Stores temporary cached responses
- TTL-based expiration (default: 1 hour)
- Cleaned up by background task

**Optional Columns**: `messages.idempotency_key`, `conversations.idempotency_key`
- For permanent tracking of idempotency keys
- Indexed for fast lookups
- No UNIQUE constraints (to avoid breaking existing data)

## Integration Steps

### 1. Migration (Already Applied)

```bash
# Migration has been applied successfully
docker exec catbird-postgres psql -U catbird -d catbird -c "\d idempotency_cache"
```

### 2. Add to main.rs

Add three code blocks to `src/main.rs`:

**A. Imports** (top of file):
```rust
use crate::middleware::idempotency::{cleanup_expired_entries, IdempotencyLayer};
use tokio::time::{interval, Duration};
```

**B. Cleanup Worker** (after db_pool initialization):
```rust
let cleanup_pool = db_pool.clone();
tokio::spawn(async move {
    let mut interval = interval(Duration::from_secs(3600)); // Every hour
    loop {
        interval.tick().await;
        if let Err(e) = cleanup_expired_entries(&cleanup_pool).await {
            tracing::error!("Failed to cleanup idempotency cache: {}", e);
        }
    }
});
tracing::info!("Idempotency cleanup worker started");
```

**C. Middleware Layer** (in router construction):
```rust
let idempotency_layer = IdempotencyLayer::new(db_pool.clone());

let mut base_router = Router::new()
    // ... all routes ...
    .layer(TraceLayer::new_for_http())
    .layer(axum::middleware::from_fn_with_state(
        idempotency_layer,
        crate::middleware::idempotency::idempotency_middleware
    ))
    .with_state(app_state);
```

### 3. Optional: Environment Variables

Add to `.env`:
```env
IDEMPOTENCY_TTL_SECONDS=3600          # Cache TTL (default: 1 hour)
IDEMPOTENCY_CLEANUP_INTERVAL=3600     # Cleanup interval (default: 1 hour)
```

## Client Usage

Clients should include `idempotencyKey` in their JSON request body:

```json
{
  "idempotencyKey": "550e8400-e29b-41d4-a716-446655440000",
  "convoId": "abc123",
  "senderDid": "did:plc:xyz",
  "ciphertext": "...",
  "epoch": 42
}
```

**Best Practices**:
- Use UUID v4 for idempotency keys
- Generate once per logical operation
- Reuse same key on retry attempts
- Use different keys for different operations

## Testing

### Manual Test

```bash
# First request (cache MISS)
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

# Second request with same key (cache HIT - should be instant)
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

### Expected Logs

```
DEBUG Idempotency cache MISS for key=test-key-123 endpoint=/xrpc/blue.catbird.mls.sendMessage
INFO  Stored idempotency cache for key=test-key-123 endpoint=/xrpc/blue.catbird.mls.sendMessage status=200 ttl=3600s
```

Then on second request:
```
INFO  Idempotency cache HIT for key=test-key-123 endpoint=/xrpc/blue.catbird.mls.sendMessage status=200
```

### Database Verification

```bash
# View cached entries
docker exec catbird-postgres psql -U catbird -d catbird -c \
  "SELECT key, endpoint, status_code, created_at, expires_at FROM idempotency_cache LIMIT 10;"

# Count cached entries
docker exec catbird-postgres psql -U catbird -d catbird -c \
  "SELECT COUNT(*) FROM idempotency_cache;"

# View entries for specific endpoint
docker exec catbird-postgres psql -U catbird -d catbird -c \
  "SELECT * FROM idempotency_cache WHERE endpoint = '/xrpc/blue.catbird.mls.sendMessage';"
```

## Architecture Decisions

### Why PostgreSQL Instead of Redis?

**Pros of PostgreSQL**:
- ✅ Already in use - no new dependency
- ✅ Transactional guarantees
- ✅ Persistent storage (survives restarts)
- ✅ Easy to query and debug
- ✅ Automatic backups with database

**Future Redis Option**:
- Would provide better performance (in-memory)
- Simpler TTL management
- Can be added later as alternative backend

### Why JSON Body Extraction?

The idempotency key is in the request body (not headers) because:
- Consistent with XRPC patterns
- Easier for clients to manage
- Avoids header size limits
- Natural fit with JSON APIs

### Why Cache 4xx Errors?

Client errors (400, 404, etc.) are cached because:
- They indicate invalid requests that won't succeed on retry
- Prevents clients from hammering server with invalid requests
- Reduces server load from retry storms
- Still allows legitimate retries for transient 5xx errors

## Performance Impact

### Request Overhead

**Without Idempotency Key**:
- Zero overhead (middleware skips processing)

**With Idempotency Key**:
- Cache MISS: +1 SELECT query + 1 INSERT query
- Cache HIT: +1 SELECT query (handler not executed)

### Memory Overhead

- Request body buffered in memory (one copy)
- Response body buffered in memory (one copy)
- For large ciphertext, consider size limits

### Database Impact

- Minimal: Simple indexed lookups
- Cleanup task removes expired entries
- Table size proportional to request rate × TTL

## Monitoring

### Key Metrics to Track

1. **Cache hit rate**: `hits / (hits + misses)`
2. **Average response time**: Cached vs uncached
3. **Cache size**: Number of entries
4. **Cleanup efficiency**: Entries deleted per run

### Log Levels

- `INFO`: Cache hits, stores, cleanup completions
- `DEBUG`: Cache misses, skipped requests
- `WARN`: Non-JSON responses
- `ERROR`: Database errors, extraction failures

## Next Steps

1. **Apply migration** ✅ (Already done)
2. **Update main.rs** - See `IDEMPOTENCY_MAIN_RS_EXAMPLE.md`
3. **Rebuild and restart** - `cargo build && docker restart catbird-mls-server`
4. **Test manually** - Send requests with idempotencyKey
5. **Monitor logs** - Watch for cache hits/misses
6. **Update client code** - Add idempotencyKey to requests

## Files Reference

All files are in `/home/ubuntu/mls/server/`:

```
migrations/
  └── 20251102_001_idempotency_cache.sql     ← Database migration

src/middleware/
  ├── mod.rs                                  ← Updated to export idempotency
  └── idempotency.rs                          ← Middleware implementation

Documentation:
  ├── IDEMPOTENCY_INTEGRATION_GUIDE.md       ← Comprehensive guide
  ├── IDEMPOTENCY_MAIN_RS_EXAMPLE.md         ← Code examples for main.rs
  └── IDEMPOTENCY_SUMMARY.md                 ← This file
```

## Support

For questions or issues:
1. Check logs for error messages
2. Review `IDEMPOTENCY_INTEGRATION_GUIDE.md`
3. Verify database schema: `\d idempotency_cache`
4. Test with curl commands from documentation
