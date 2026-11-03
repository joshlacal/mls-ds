# Rate limiting

`catbird-server` throttles requests at three points. Every limit is an in-process token bucket: each server process keeps its own buckets, and a restart resets them. A throttled request gets `429` with a `Retry-After` header. The code is in `src/middleware/rate_limit.rs` and `src/auth.rs`.

## 1. Per client IP, before authentication

`rate_limit_middleware` charges every request to its client IP.

- `RATE_LIMIT_IP_PER_MINUTE` (default 300) is the refill rate. `IP_RATE_BURST` (default: the larger of that value and 60) is the bucket size.
- The client IP is the TCP peer address. Only when the peer is inside `TRUSTED_PROXY_CIDRS` does the server read `CF-Connecting-IP`, then the right-most untrusted `X-Forwarded-For` hop, then `X-Real-IP`. The default trusted ranges are loopback and private: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1/128` and `fc00::/7`.
- The response body is `{"error":"RateLimitExceeded", ...}`.
- `RATE_LIMIT_IP_MAX_KEYS` (100,000) and `RATE_LIMIT_BUCKET_TTL_SECONDS` (600) bound the bucket cache.

## 2. Per account, after authentication

A `blue.catbird.chat.*` call first verifies the account's service-auth JWT, then charges two buckets for the issuer DID:

- `AUTH_RATE_LIMIT_PER_SECOND` (default 100, with a burst of one tenth of that), shared by all endpoints.
- A per-endpoint minute quota. Several variable names predate the clean-slate endpoint names.

| Endpoint | Variable | Default per minute |
|---|---|---:|
| `enrollDevice` | `RATE_LIMIT_DEVICE_AUTH_BINDING` | 10 |
| `sendMessage` | `RATE_LIMIT_SEND_MESSAGE` | 100 |
| `getEntries`, `getConversations`, `getConversationState` | `RATE_LIMIT_GET_MESSAGES` | 500 |
| `publishTyping` | `RATE_LIMIT_UPDATE_CURSOR` | 300 |
| `replenishKeyPackages` | `RATE_LIMIT_PUBLISH_KEY_PACKAGE` | 50 |
| `createConversation` | `RATE_LIMIT_CREATE_CONVO` | 5 |
| every other endpoint | `RATE_LIMIT_DID_DEFAULT` | 200 |

`RATE_LIMIT_DID_MAX_KEYS` (300,000) and `RATE_LIMIT_DID_BUCKET_TTL_SECONDS` (900) bound this cache.

## 3. Per calling DS

The original S2S routes (`deliverMessage`, `deliverWelcome`, `submitCommit`, GET `fetchKeyPackage`, `getConvoDigest`, `getConvoEvents`, `transferSequencer`) and the C33 direct-request S2S routes charge the calling DS:

| Route | Variable | Default per minute |
|---|---|---:|
| `deliverMessage` | `FEDERATION_RATE_LIMIT_DELIVER_MESSAGE` | 240 |
| `deliverWelcome` | `FEDERATION_RATE_LIMIT_DELIVER_WELCOME` | 120 |
| `submitCommit` | `FEDERATION_RATE_LIMIT_SUBMIT_COMMIT` | 120 |
| `fetchKeyPackage` | `FEDERATION_RATE_LIMIT_FETCH_KEY_PACKAGE` | 120 |
| `transferSequencer` | `FEDERATION_RATE_LIMIT_TRANSFER_SEQUENCER` | 30 |
| any other route | `FEDERATION_RATE_LIMIT_DEFAULT` | 180 |

A limit set on the peer's `federation_peers` row, scaled by its risk tier, replaces these defaults (see [../SELF_HOSTING.md](../SELF_HOSTING.md#3-federation-and-peer-policy)). The group, ACK, prune-notice, deletion and control routes are not charged here; peer policy alone gates them. `RATE_LIMIT_FEDERATION_MAX_KEYS` (100,000) and `RATE_LIMIT_FEDERATION_BUCKET_TTL_SECONDS` (900) bound this cache.

## Housekeeping and tests

A background task evicts idle buckets from the IP, account and peer caches every 5 minutes. The limiter's unit tests live in `src/middleware/rate_limit.rs`. The Space-authority limiter and its `RATE_LIMIT_SPACE_AUTHORITY_*` settings were removed with `getSpaceMembership` and `deleteSpaceGeneration`.

`test_rate_limiting.sh` checks a running server: the per-IP bucket on `/health` (set `IP_BURST` to the server's `IP_RATE_BURST`, default 300) and, when `TEST_JWT_CMD` names a command that prints a fresh service-auth JWT for a given NSID, the `sendMessage`, `createConversation` and `replenishKeyPackages` account quotas. The account checks need `CHAT_CUTOVER_ENABLED`. It exits non-zero when a check sees no `429`.
