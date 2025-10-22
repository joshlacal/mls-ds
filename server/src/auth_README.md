# Authentication Middleware Documentation

## Overview

The `auth.rs` module provides comprehensive authentication middleware for the Catbird MLS server with AT Protocol JWT verification, DID validation, request signing verification, token caching, and rate limiting.

## Features

### 1. **AT Protocol JWT Verification**
- Decodes and validates JWT tokens following AT Protocol standards
- Extracts claims including issuer (DID), audience, expiration
- Verifies token signatures against DID public keys
- Checks token expiration

### 2. **DID Resolution and Validation**
- Supports `did:plc:` (via PLC directory) and `did:web:` DIDs
- Validates DID format before resolution
- Extracts public keys from DID documents for signature verification
- Handles verification methods and public key formats (JWK, multibase)

### 3. **Token Caching**
- Uses Moka for efficient in-memory caching of DID documents
- Configurable TTL (default: 5 minutes)
- Reduces repeated DID resolution requests
- Maximum capacity of 10,000 cached documents

### 4. **Rate Limiting per DID**
- Governor-based rate limiting
- Per-DID rate limits (default: 100 requests per minute)
- Configurable quota and burst allowance
- Prevents abuse and ensures fair resource usage

### 5. **Request Signing Verification**
- Verifies request signatures via `x-signature` header
- Timestamp-based replay attack protection (5-minute window)
- Ready for production signature verification implementation

## Architecture

### Error Types

```rust
pub enum AuthError {
    MissingAuthHeader,
    InvalidAuthFormat,
    InvalidToken(String),
    TokenExpired,
    InvalidDid(String),
    DidResolutionFailed(String),
    InvalidSignature,
    RateLimitExceeded,
    MissingVerificationMethod,
    UnsupportedKeyType(String),
    Internal(String),
}
```

All errors implement `thiserror::Error` and `IntoResponse` for proper HTTP error handling.

### Core Types

#### `AtProtoClaims`
```rust
pub struct AtProtoClaims {
    pub iss: String,    // Issuer (DID)
    pub aud: String,    // Audience (service DID or URL)
    pub exp: i64,       // Expiration time
    pub iat: Option<i64>, // Issued at
    pub sub: Option<String>, // Subject
}
```

#### `AuthUser`
```rust
pub struct AuthUser {
    pub did: String,
    pub claims: AtProtoClaims,
}
```

Extracted automatically via Axum's `FromRequestParts` trait.

#### `AuthMiddleware`
```rust
pub struct AuthMiddleware {
    did_cache: Cache<String, CachedDidDoc>,
    rate_limiters: Arc<RwLock<HashMap<String, Arc<RateLimiter<...>>>>>,
    http_client: reqwest::Client,
    cache_ttl_seconds: u64,
    rate_limit_quota: Quota,
}
```

## Usage

### Basic Usage in Handlers

```rust
use crate::auth::AuthUser;

pub async fn my_handler(
    State(pool): State<DbPool>,
    auth_user: AuthUser,  // Automatically extracts and validates
    Json(input): Json<MyInput>,
) -> Result<Json<MyOutput>, StatusCode> {
    let did = &auth_user.did;
    // Handler logic here...
    Ok(Json(response))
}
```

### Configuration

```rust
// Default configuration
let middleware = AuthMiddleware::new();

// Custom configuration
let middleware = AuthMiddleware::with_config(
    600,   // cache_ttl_seconds: 10 minutes
    200,   // rate_limit_requests: 200 per period
    60,    // rate_limit_period_seconds: 1 minute
);
```

### Manual JWT Verification

```rust
let middleware = AuthMiddleware::new();
let claims = middleware.verify_jwt(token).await?;
```

### DID Resolution

```rust
let middleware = AuthMiddleware::new();

// Resolve did:plc
let doc = middleware.resolve_did("did:plc:abc123").await?;

// Resolve did:web
let doc = middleware.resolve_did("did:web:example.com").await?;
```

### Rate Limiting

```rust
let middleware = AuthMiddleware::new();
middleware.check_rate_limit("did:plc:user123")?;
```

### Request Signature Verification

```rust
let middleware = AuthMiddleware::new();
middleware.verify_request_signature(&headers, body, "did:plc:user123")?;
```

## DID Resolution Flow

1. **Check Cache**: First checks if DID document is cached
2. **Validate Format**: Ensures DID starts with `did:` and uses supported method
3. **Resolve by Method**:
   - `did:plc:`: Fetches from `https://plc.directory/{did}`
   - `did:web:`: Fetches from `https://{domain}/.well-known/did.json`
4. **Parse Document**: Extracts verification methods and public keys
5. **Cache Result**: Stores in cache with TTL

## JWT Verification Flow

1. **Decode Header**: Extracts algorithm from JWT header
2. **Extract Claims**: Decodes JWT payload to get issuer DID
3. **Check Expiration**: Validates token hasn't expired
4. **Resolve DID**: Fetches DID document to get public key
5. **Extract Public Key**: Gets verification method from DID document
6. **Verify Signature**: Validates JWT signature using public key
7. **Return Claims**: Returns validated claims on success

## Rate Limiting

Rate limiting is enforced per DID:
- Each DID gets its own rate limiter instance
- Quota: Configurable requests per second
- Burst: 10% of rate limit
- Thread-safe via `RwLock`
- Automatic cleanup via Moka cache

## Security Considerations

### Current Implementation
- ✅ JWT signature verification
- ✅ Token expiration checks
- ✅ DID format validation
- ✅ Rate limiting per DID
- ✅ Replay attack protection (timestamp-based)
- ✅ HTTPS for DID resolution
- ✅ 10-second timeout on DID resolution

### Production Enhancements
- 🔲 Complete request signature verification
- 🔲 Revocation list checking
- 🔲 Additional key type support (Ed25519, secp256k1)
- 🔲 DID document caching persistence
- 🔲 Metrics and monitoring integration
- 🔲 Distributed rate limiting (Redis/similar)

## Testing

The module includes comprehensive tests:

```bash
cargo test --bin catbird-server
```

### Test Coverage

1. **DID Validation**: Tests invalid DID formats and unsupported methods
2. **Rate Limiting**: Tests quota enforcement and burst allowance
3. **Caching**: Tests DID document cache hits and misses
4. **JWT Claims**: Tests serialization/deserialization
5. **Request Signing**: Tests signature verification and replay protection
6. **Error Display**: Tests error message formatting

### Example Tests

```rust
#[tokio::test]
async fn test_did_validation() {
    let middleware = AuthMiddleware::new();
    assert!(matches!(
        middleware.resolve_did("not-a-did").await,
        Err(AuthError::InvalidDid(_))
    ));
}

#[test]
fn test_rate_limit_exceeded() {
    let middleware = AuthMiddleware::with_config(300, 2, 60);
    let did = "did:plc:test";
    
    assert!(middleware.check_rate_limit(did).is_ok());
    assert!(middleware.check_rate_limit(did).is_ok());
    assert!(matches!(
        middleware.check_rate_limit(did),
        Err(AuthError::RateLimitExceeded)
    ));
}
```

## Error Handling

All authentication errors are mapped to appropriate HTTP status codes:

| Error | HTTP Status | Description |
|-------|-------------|-------------|
| `MissingAuthHeader` | 401 | No authorization header |
| `InvalidAuthFormat` | 401 | Invalid header format |
| `InvalidToken` | 401 | JWT validation failed |
| `TokenExpired` | 401 | Token past expiration |
| `InvalidDid` | 400 | Malformed DID |
| `DidResolutionFailed` | 400 | Cannot fetch DID doc |
| `InvalidSignature` | 401 | Signature mismatch |
| `RateLimitExceeded` | 429 | Too many requests |

## Dependencies

- `jsonwebtoken`: JWT encoding/decoding
- `moka`: High-performance caching
- `governor`: Rate limiting
- `reqwest`: HTTP client for DID resolution
- `parking_lot`: Efficient synchronization
- `thiserror`: Error type definitions
- `axum`: Web framework integration

## Best Practices

1. **Always use AuthUser extractor** in handlers that require authentication
2. **Configure appropriate rate limits** based on expected traffic
3. **Monitor cache hit rates** for DID resolution performance
4. **Set cache TTL** based on DID document update frequency
5. **Use structured logging** with tracing for audit trails
6. **Handle all error cases** gracefully with proper status codes
7. **Test with realistic DIDs** from actual PLC directory

## Performance

- **DID Cache**: O(1) lookup, ~100ns per hit
- **Rate Limiting**: O(1) per check
- **JWT Verification**: Dominated by signature verification (~1-5ms)
- **DID Resolution**: Network-bound (~50-500ms depending on latency)

## Future Enhancements

1. **WebAuthn Support**: Add passwordless authentication
2. **OAuth2 Integration**: Support for third-party auth providers
3. **Session Management**: Persistent sessions with refresh tokens
4. **Audit Logging**: Comprehensive auth event logging
5. **Metrics**: Prometheus metrics for monitoring
6. **Key Rotation**: Support for rotating verification keys
7. **Multi-tenancy**: Per-tenant rate limiting and configuration
