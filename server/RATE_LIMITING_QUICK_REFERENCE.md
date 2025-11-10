# Rate Limiting Quick Reference

## Default Limits

| Type | Scope | Limit | Window |
|------|-------|-------|--------|
| **IP** | Per IP address | 60 req | 60s |
| **DID** | sendMessage | 100 req | 60s |
| **DID** | publishKeyPackage | 20 req | 60s |
| **DID** | addMembers | 10 req | 60s |
| **DID** | createConvo | 5 req | 60s |
| **DID** | reportMember | 5 req | 60s |
| **DID** | Other endpoints | 200 req | 60s |

## Environment Variables

```bash
# Per-IP (unauthenticated)
RATE_LIMIT_IP_PER_MINUTE=60

# Per-DID (authenticated)
RATE_LIMIT_SEND_MESSAGE=100
RATE_LIMIT_PUBLISH_KEY_PACKAGE=20
RATE_LIMIT_ADD_MEMBERS=10
RATE_LIMIT_CREATE_CONVO=5
RATE_LIMIT_REPORT_MEMBER=5
RATE_LIMIT_DID_DEFAULT=200
```

## Testing

```bash
# Run test suite
cd server
./test_rate_limiting.sh

# With JWT
TEST_JWT="your-token" ./test_rate_limiting.sh

# Manual test
for i in {1..70}; do curl http://localhost:8080/health; done
```

## Monitoring

```bash
# Check rate limit logs
docker logs catbird-mls-server 2>&1 | grep "rate limit"

# Check cleanup task
docker logs catbird-mls-server 2>&1 | grep "Rate limiter cleanup"
```

## Response

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 45
```

## Files

- **Implementation**: `src/middleware/rate_limit.rs`
- **Integration**: `src/auth.rs` (line 645-658)
- **Cleanup**: `src/main.rs` (line 132-143)
- **Tests**: `test_rate_limiting.sh`
- **Docs**: `RATE_LIMITING.md`
