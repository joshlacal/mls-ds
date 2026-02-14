# Federation Security Hardening (2026-02-14)

## Scope
Implemented DS federation hardening across authentication, authorization, resolver SSRF defenses, outbound federation wiring, and operational policy controls.

## Implemented Changes

### 1) DS auth fail-closed + shared replay store
- Added DS-route fail-closed enforcement in `AuthUser` extraction for `blue.catbird.mls.ds.*` routes:
  - strict `lxm` enforcement
  - strict `jti` enforcement
  - shared replay check via Postgres
- Added JWT issuer DID fragment handling (`did:...#service` -> DID resolution by base DID).
- Added `kid`-aware verification method selection for ES256/ES256K DID verification.
- Added background cleanup for shared nonce table.

Files:
- `server/src/auth.rs`
- `server/src/main.rs`
- `server/migrations/20260214000002_auth_jti_nonce.sql`

### 2) Payload issuer binding + DS endpoint security gate
- Added shared DS security gate used by DS handlers:
  - `validate_lxm` now requires `lxm`
  - issuer DID format check
  - payload binding (`senderDsDid == claims.iss`) when applicable
  - peer policy enforcement
  - per-source-DS federation rate limiting
  - success/reject behavior accounting

Files:
- `server/src/handlers/ds/deliver_message.rs`
- `server/src/handlers/ds/deliver_welcome.rs`
- `server/src/handlers/ds/submit_commit.rs`
- `server/src/handlers/ds/fetch_key_package.rs`
- `server/src/handlers/ds/transfer_sequencer.rs`

### 3) Sequencer/member authorization
- `deliverMessage`: verifies caller DS matches conversation sequencer binding.
- `submitCommit`: verifies local DS is sequencer and caller DS is a participant DS for convo.
- `fetchKeyPackage`: strict greenfield contract now requires `convoId`; caller must be sequencer or participant DS for that conversation, and recipient must be an active member.

Files:
- `server/src/handlers/ds/deliver_message.rs`
- `server/src/handlers/ds/submit_commit.rs`
- `server/src/handlers/ds/fetch_key_package.rs`

### 4) Explicit federation peer policy layer
- Added persistent `federation_peers` trust policy:
  - `status` (`allow` / `suspend` / `block`)
  - optional DS-specific rate limit override
  - behavior telemetry: `successful_request_count`, `rejected_request_count`, `invalid_token_count`
  - `trust_score` adjustments from outcomes

Files:
- `server/src/federation/peer_policy.rs`
- `server/src/federation/mod.rs`
- `server/migrations/20260214000001_federation_peer_policy.sql`

### 5) Resolver SSRF + transport hardening
- Enforced HTTPS-by-default for resolver targets.
- Added opt-in dev override for HTTP (`FEDERATION_ALLOW_INSECURE_HTTP=true`).
- Added DNS resolution checks to reject hosts resolving to private/loopback/link-local/multicast IPs.
- Applied URL validation to:
  - DID doc fetch URL
  - resolved PDS endpoint
  - profile `deliveryService` endpoint
- Added DID document non-success status handling.

Files:
- `server/src/federation/resolver.rs`

### 6) Outbound federation queue wiring fix
- Fixed federation enqueue method from `blue.catbird.mls.sendMessage` to `blue.catbird.mls.ds.deliverMessage`.
- Enqueue now stores full deliverMessage JSON payload, not raw ciphertext bytes.
- Queue worker now resolves missing endpoints via cache or `did:web` derivation.

Files:
- `server/src/handlers/send_message.rs`
- `server/src/federation/queue.rs`

### 7) DS identity canonicalization across federation policy/rate paths
- Added a shared DID canonicalization module and applied it to DS identity handling.
- Federation peer policy and telemetry now key on canonical DS DID (fragment-insensitive).
- DS rate-limiting and sender/issuer checks now treat `did:...` and `did:...#service` as the same peer identity.
- Sequencer comparisons were aligned to canonical DID matching in federation authorization paths.

Files:
- `server/src/identity.rs`
- `server/src/auth.rs`
- `server/src/federation/peer_policy.rs`
- `server/src/handlers/ds/deliver_message.rs`
- `server/src/federation/sequencer.rs`
- `server/src/federation/transfer.rs`
- `server/src/federation/mailbox.rs`
- `server/src/federation/resolver.rs`
- `server/src/handlers/send_message.rs`

### 8) Federation peer admin workflows/endpoints
- Added operator-managed lifecycle endpoints for federation peers:
  - `blue.catbird.mls.admin.getFederationPeers`
  - `blue.catbird.mls.admin.upsertFederationPeer`
  - `blue.catbird.mls.admin.deleteFederationPeer`
- Added admin DID gating via `FEDERATION_ADMIN_DIDS`.
- Added list/upsert/delete persistence helpers in `peer_policy`.

Files:
- `server/src/handlers/federation_peers_admin.rs`
- `server/src/handlers/mod.rs`
- `server/src/main.rs`
- `server/src/federation/peer_policy.rs`
- `server/.env.example`

### 9) Hostile-peer integration tests
- Added integration test suite for:
  - `deliverMessage` fragment-aware sequencer acceptance
  - replayed DS token rejection
  - per-DS rate limit enforcement across `iss` service fragments
  - `submitCommit` participant DS authorization
  - strict `fetchKeyPackage` (`convoId` required + authorization)
  - federation peer admin lifecycle endpoints

Files:
- `server/tests/federation_hostile_peers.rs`
- `server/Cargo.toml` (dev-only `tower-util` for route testing harness)

## New/Updated Runtime Controls
- `FEDERATION_ALLOW_INSECURE_HTTP` (default false)
- `FEDERATION_RATE_LIMIT_DELIVER_MESSAGE`
- `FEDERATION_RATE_LIMIT_DELIVER_WELCOME`
- `FEDERATION_RATE_LIMIT_SUBMIT_COMMIT`
- `FEDERATION_RATE_LIMIT_FETCH_KEY_PACKAGE`
- `FEDERATION_RATE_LIMIT_TRANSFER_SEQUENCER`
- `FEDERATION_RATE_LIMIT_DEFAULT`

Existing controls leveraged:
- `ENFORCE_LXM`
- `ENFORCE_JTI`
- `JTI_TTL_SECONDS`
- `SERVICE_DID`

## Migrations Added
- `server/migrations/20260214000001_federation_peer_policy.sql`
- `server/migrations/20260214000002_auth_jti_nonce.sql`
- `server/migrations/20260214000003_federation_commits.sql`

## Validation Performed
- `cargo fmt --all`
- `SQLX_OFFLINE=true cargo check -p catbird-server` (pass)
- `SQLX_OFFLINE=true cargo test -p catbird-server --test federation_hostile_peers --no-run` (pass)
- `SQLX_OFFLINE=true cargo test -p catbird-server --test federation_hostile_peers -- --nocapture` (pass; tests skip when `TEST_DATABASE_URL` is unset)

Notes:
- Non-offline `cargo check` requires live SQLx DB auth in this environment and failed due DB credentials.
- `cargo test` currently has unrelated pre-existing test compilation failures in legacy test code; no new failures specific to touched security paths were identified from check output.

## Residual Risks / Next Improvements
1. Add pre-auth middleware-level invalid-token attribution by source IP/peer to track malformed tokens before claim extraction.
2. Move DS per-peer rate limiting and replay store to Redis for lower DB write load at scale.
3. Add UI or CLI tooling for `federation_peers` workflows (status/quota/notes, audit views).
4. Add DB-level constraints for canonical DS DID storage in federation-related columns to avoid future drift.
5. Add CI job with `TEST_DATABASE_URL` set so hostile-peer integration tests execute against a live DB in automation.
