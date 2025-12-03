# Rate Limiting Implementation

This document describes the comprehensive rate limiting system implemented for the Catbird MLS Server.

## Overview

The server implements **two-tier rate limiting** to prevent abuse and DoS attacks:

1. **Per-IP Rate Limiting** (fallback for unauthenticated requests)
2. **Per-DID Endpoint-Specific Rate Limiting** (for authenticated requests)

## Architecture

### 1. Per-IP Rate Limiting (Unauthenticated)

**Purpose**: Protect against brute force attacks, preflight spam, and invalid token flooding.

**Implementation**: `server/src/middleware/rate_limit.rs`

**Default Limits**:
- 60 requests per minute per IP address
- Burst capacity: 6 requests (10% of per-minute limit)
- Window: 60 seconds (sliding)

**Headers Checked** (in order of precedence):
1. `X-Forwarded-For` (proxy/load balancer)
2. `CF-Connecting-IP` (Cloudflare)
3. `X-Real-IP` (Nginx)

**Configuration**:
```bash
# .env
RATE_LIMIT_IP_PER_MINUTE=60      # Requests per minute per IP
IP_RATE_BURST=6                   # Burst capacity
```

### 2. Per-DID Endpoint-Specific Rate Limiting (Authenticated)

**Purpose**: Prevent abuse from authenticated users with different limits for different operations.

**Implementation**: Integrated into `server/src/auth.rs` AuthUser extractor

**Endpoint-Specific Quotas** (per DID per minute):

| Endpoint | Limit | Rationale |
|----------|-------|-----------|
| `sendMessage` | 100/min | High frequency messaging |
| `publishKeyPackage` | 20/min | Batch key package uploads |
| `addMembers` | 10/min | Admin operations |
| `removeMember` | 10/min | Admin operations |
| `createConvo` | 5/min | Expensive database operations |
| `reportMember` | 5/min | Prevent report spam |
| Default | 200/min | Other operations |

**Configuration**:
```bash
# .env
RATE_LIMIT_SEND_MESSAGE=100
RATE_LIMIT_PUBLISH_KEY_PACKAGE=20
RATE_LIMIT_ADD_MEMBERS=10
RATE_LIMIT_CREATE_CONVO=5
RATE_LIMIT_REPORT_MEMBER=5
RATE_LIMIT_DID_DEFAULT=200
```

## Technical Details

### Token Bucket Algorithm

Both rate limiters use a **token bucket** algorithm with:
- Automatic refilling based on elapsed time
- Burst capacity for handling request spikes
- Memory-efficient sliding window implementation

**Key Features**:
- Lock-free reads (uses `RwLock` with optimized read paths)
- Automatic cleanup of stale buckets (every 5 minutes)
- Configurable via environment variables

### Rate Limit Flow

#### Unauthenticated Requests
```
Request → rate_limit_middleware → IP extraction → Token bucket check
                                                    ↓
                                                  Allowed? → Continue
                                                    ↓
                                               Rate limited? → 429 + Retry-After
```

#### Authenticated Requests
```
Request → rate_limit_middleware (IP check) → auth extractor → JWT validation
                                                                ↓
                                                            DID extraction
                                                                ↓
                                                    Endpoint-specific check
                                                                ↓
                                                            Allowed? → Handler
                                                                ↓
                                                        Rate limited? → 429
```

## Response Headers

When rate limited, the server returns:
- **Status Code**: `429 Too Many Requests`
- **Header**: `Retry-After: <seconds>` - Time until request quota refreshes

Example:
```http
HTTP/1.1 429 Too Many Requests
Retry-After: 42
Content-Length: 0
```

## Memory Management

### Cleanup Workers

The server spawns background tasks to prevent memory leaks:

**DID Rate Limiter Cleanup** (`main.rs`):
- Runs every 5 minutes
- Removes buckets not accessed in the last 10 minutes
- Prevents unbounded memory growth from one-time users

**IP Rate Limiter Cleanup** (built-in):
- Automatic cleanup on bucket access
- No separate worker needed

### Memory Footprint

Each rate limit bucket consumes approximately:
- 48 bytes (bucket metadata)
- 24 bytes (HashMap key)
- **Total**: ~72 bytes per active DID:endpoint or IP

**Example**: 10,000 active users × 5 endpoints = 50,000 buckets × 72 bytes = **3.6 MB**

## Testing

### Automated Test Suite

Run the comprehensive test suite:
```bash
cd server
./test_rate_limiting.sh
```

**Without authentication** (tests IP-based limits only):
```bash
SERVER_URL=http://localhost:8080 ./test_rate_limiting.sh
```

**With authentication** (tests DID-based limits):
```bash
SERVER_URL=http://localhost:8080 \
TEST_JWT="your-jwt-token-here" \
./test_rate_limiting.sh
```

### Manual Testing

#### Test Per-IP Limits (60/min)
```bash
# Should see 429 after ~60 requests
for i in {1..70}; do
    curl -s -w "%{http_code}\n" http://localhost:8080/health | tail -1
done | grep -c "429"
```

#### Test Per-DID sendMessage Limit (100/min)
```bash
# Should see 429 after ~100 requests
JWT="your-jwt-token"
for i in {1..110}; do
    curl -s -w "%{http_code}\n" \
        -H "Authorization: Bearer $JWT" \
        -X POST \
        -H "Content-Type: application/json" \
        -d '{"convoId":"test","message":"test"}' \
        http://localhost:8080/xrpc/blue.catbird.mls.sendMessage | tail -1
done | grep -c "429"
```

#### Test Per-DID createConvo Limit (5/min)
```bash
# Should see 429 after ~5 requests
JWT="your-jwt-token"
for i in {1..10}; do
    curl -s -w "%{http_code}\n" \
        -H "Authorization: Bearer $JWT" \
        -X POST \
        -H "Content-Type: application/json" \
        -d '{"name":"test","didList":["did:plc:test1"]}' \
        http://localhost:8080/xrpc/blue.catbird.mls.createConvo | tail -1
done | grep -c "429"
```

## Production Considerations

### Tuning for Production

**High-Traffic Environments**:
```bash
# Increase limits for high-volume legitimate users
RATE_LIMIT_SEND_MESSAGE=200
RATE_LIMIT_DID_DEFAULT=400
```

**Security-Focused Environments**:
```bash
# Stricter limits to prevent abuse
RATE_LIMIT_IP_PER_MINUTE=30
RATE_LIMIT_CREATE_CONVO=3
RATE_LIMIT_REPORT_MEMBER=3
```

### Behind a Load Balancer

Ensure the load balancer forwards client IPs:
- **Nginx**: `proxy_set_header X-Real-IP $remote_addr;`
- **Cloudflare**: Automatically sets `CF-Connecting-IP`
- **AWS ALB**: `X-Forwarded-For` header included

### Monitoring

**Key Metrics to Monitor**:
1. Rate of 429 responses (by endpoint)
2. Average `Retry-After` values
3. Memory usage of rate limiter buckets
4. Cleanup task execution time

**Logging**:
```bash
# Check rate limit warnings
sudo journalctl -u catbird-mls-server | grep "rate limit exceeded"

# Check cleanup task
sudo journalctl -u catbird-mls-server | grep "Rate limiter cleanup"
```

## Security Considerations

### IP Spoofing Prevention

The middleware checks headers in order of trustworthiness:
1. Trusted proxy headers (`X-Forwarded-For`, `CF-Connecting-IP`)
2. Fallback to connection IP
3. Never trusts client-provided custom headers

### DID Verification

DID-based rate limiting only applies **after JWT validation**:
1. JWT signature verified against DID document
2. Claims validated (exp, aud, lxm, jti)
3. Only then is the DID used for rate limiting

This prevents attackers from bypassing limits by forging DIDs.

### Attack Scenarios Covered

| Attack Type | Protection |
|-------------|------------|
| Brute force auth | Per-IP limits on auth endpoints |
| Token flooding | Per-IP limits for invalid tokens |
| Message spam | Per-DID sendMessage limits |
| Conversation spam | Per-DID createConvo limits |
| Report spam | Per-DID reportMember limits |
| Membership churn | Per-DID addMembers/removeMember limits |
| DDoS (unauthenticated) | Per-IP global limits |
| DDoS (authenticated) | Per-DID endpoint-specific limits |

## Implementation Files

- **`server/src/middleware/rate_limit.rs`**: Core rate limiting logic
- **`server/src/auth.rs`**: DID-based rate limit integration (line 645-658)
- **`server/src/main.rs`**: Cleanup worker initialization (line 132-143)
- **`server/test_rate_limiting.sh`**: Automated test suite
- **`server/RATE_LIMITING.md`**: This documentation

## Troubleshooting

### Rate Limits Not Working

1. Check if middleware is registered in `main.rs`:
   ```rust
   .layer(axum::middleware::from_fn(middleware::rate_limit::rate_limit_middleware))
   ```

2. Verify environment variables are loaded:
   ```bash
   cat .env | grep RATE_LIMIT
   ```

3. Check logs for rate limit warnings:
   ```bash
   sudo journalctl -u catbird-mls-server | grep -i "rate limit"
   ```

### False Positives

If legitimate users are being rate limited:

1. **Check if behind proxy**: Ensure `X-Forwarded-For` is set correctly
2. **Increase limits**: Adjust environment variables
3. **Check burst capacity**: May need higher burst for request spikes

### Memory Growth

If rate limiter memory grows unbounded:

1. Verify cleanup task is running:
   ```bash
   sudo journalctl -u catbird-mls-server | grep "Rate limiter cleanup"
   ```

2. Check cleanup frequency (default: 5 minutes)
3. Reduce max_age for bucket retention (default: 10 minutes)

## Future Enhancements

Potential improvements for future versions:

1. **Redis-backed rate limiting** for multi-instance deployments
2. **Per-user quotas** stored in database (override defaults)
3. **Rate limit exemptions** for verified/premium users
4. **Dynamic rate limits** based on server load
5. **Rate limit analytics** dashboard
6. **Gradual backoff** instead of hard cutoffs
7. **Whitelisting** for trusted IPs/DIDs

## References

- Token Bucket Algorithm: https://en.wikipedia.org/wiki/Token_bucket
- Axum Middleware: https://docs.rs/axum/latest/axum/middleware/
- HTTP 429 Status Code: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/429
