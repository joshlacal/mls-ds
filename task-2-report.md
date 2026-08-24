# Task 2 Report: Declaration-Aware Actor-to-DS Resolution

## Summary
Implemented Task 2 from `docs/superpowers/plans/2026-08-24-clean-chat-federation-container.md` in `/tmp/clean-fed-tree/mls-ds`.

### Key Changes
1. **Two-Table Caching Architecture**:
   - Added migration `20260824000002_chat_actor_ds_mapping.sql` creating `did_ds_mappings (actor_did PRIMARY KEY, ds_did, resolved_at, expires_at)`.
   - Maintained `ds_endpoints (did PRIMARY KEY, endpoint, supported_cipher_suites, resolved_at, expires_at)` keyed by target DS DID.
   - Updated `DsResolver::get_cached` and `get_cached_any` to query `did_ds_mappings` joined with `ds_endpoints` for actor lookups, while supporting direct DS DID lookups on `ds_endpoints` (matching outbound queue requirements).
   - Updated `cache_mapping` and `cache_endpoint` to atomically populate both tables.
   - Updated `invalidate` and `cleanup_expired` across both tables.

2. **Declaration Resolution Rung**:
   - Added `blue.catbird.chat.declaration/self` resolution rung after `#atproto_mls` DID document service entry and before the legacy `blue.catbird.chat.profile` record.
   - Generalized bounded repo-record fetching via `fetch_repo_record`.
   - Enforced exact raw validation:
     - `$type` must equal exact bare NSID `"blue.catbird.chat.declaration"`.
     - Required fields present: `allowIncoming`, `deliveryService`, `protocolVersion`, `createdAt`.
     - `protocolVersion` must equal `"1"`.
     - `createdAt` must parse as valid RFC3339 datetime (`chrono::DateTime::parse_from_rfc3339`).
     - `deliveryService` must be a valid base DID without fragment.
     - `allowIncoming` is verified for schema compliance but is **not** used as routing authorization.

3. **Non-Recursive DS DID Resolution & SSRF Protection**:
   - Added `resolve_ds_did_to_endpoint` to convert declared DS DID into an SSRF-validated HTTPS endpoint via its DID document `#atproto_mls` service or `did_web_service_endpoint` derivation without recursive actor mapping.
   - Enforced SSRF guards (`validate_endpoint_url` + `validate_resolved_host_is_public`).

4. **Real DS Identity for Default Fallback**:
   - Default fallback derives canonical DS DID (e.g. `did:web:<host>`), never the queried actor DID fiction.

5. **Naming vs Peer Policy Separation**:
   - Resolution succeeds for untrusted peers as pure naming data; peer policy trust checks are enforced at use.

---

## Fix Wave: Comprehensive Findings Resolution

### 1. Critical SSRF Early-Return Bypass Removed
- Removed the early-return `if host_is_allowlisted { return Ok(()); }` in `validate_resolved_host_is_public`.
- Hostname allowlist and public-IP checks are now strictly conjunctive: when `FEDERATION_OUTBOUND_HOST_ALLOWLIST` is configured, host must match the allowlist AND resolved IPs must not be private/loopback addresses.
- Docker private service exception is restricted strictly to `APP_ENV=test` and `allow_insecure_http()`, preserving full SSRF enforcement in production.

### 2. Legacy `ds_endpoints` Cache Purge & Migration Upgrade Verification
- Migration `20260824000002_chat_actor_ds_mapping.sql` includes `DELETE FROM ds_endpoints;` to purge legacy unclassifiable actor-keyed rows, and adds a canonical DID check constraint.
- `get_cached` for actor lookups exclusively joins `did_ds_mappings` with `ds_endpoints`, ensuring legacy actor-keyed rows can never be returned.
- Added `test_migration_purges_legacy_actor_keyed_ds_endpoints_row` executing real `sqlx::migrate!("./migrations")` runner against test database.

### 3. Exact Bare NSID `$type` and Production Helper for Base DID Validation
- `$type` requires exact bare NSID `"blue.catbird.chat.declaration"`; suffixes like `#main` are rejected.
- Introduced production helper `validate_declaration_delivery_service`: validates base DIDs without fragments, requires supported methods (`did:plc:` with 24-char base32, `did:web:` with valid numeric ports 1..=65535 and canonical round-trip), and rejects invalid/unsupported schemes.
- Introduced production helper `validate_declaration_record_value` returning `(canonical_ds_did, allow_incoming)`.
- All tests invoke these production helpers directly.

### 4. Removed Untyped `#atproto_mls` Service Fallback
- `resolve_ds_did_to_endpoint` and `resolve_from_did_doc` require exact service type `AtprotoMLSDeliveryService` when extracting `#atproto_mls`.
- Removed untyped `extract_service(&doc, "atproto_mls", None)` fallback.

### 5. Never Substitute Actor DID on Derivation Failure
- When `derive_ds_did_from_https_endpoint` fails (e.g. non-HTTPS or URLs with path components), the resolution rung fails with `FederationError::ResolutionFailed` instead of substituting the actor DID. The resolver then falls through to subsequent rungs cleanly.

### 6. Split Default Configuration & Added `resolve_ds_did`
- Split `DEFAULT_DS_DID` and `DEFAULT_DS_ENDPOINT` in `FederationConfig` and `DsResolver`.
- Default fallback applies exclusively to actor resolution (`resolve`), never DS DID resolution.
- Added `resolve_ds_did(&self, ds_did: &str) -> Result<DsEndpoint, FederationError>` for upstream, reconciliation, and outbound queue. It checks self, fresh cache on `ds_endpoints`, live resolution, and returns error without default fallback if resolution fails.
- Updated `upstream.rs` and `reconciliation.rs` to call `resolve_ds_did`.

### 7. Replaced Duplicated Tests with Production Helpers and Comprehensive Paths
- Replaced manual closures in tests with `validate_declaration_record_value` and `validate_declaration_delivery_service`.
- Added tests covering:
  - Exact declaration success (bare NSID, protocolVersion 1, valid RFC3339 datetime, valid base DID)
  - Rejection of wrong `$type` (including `#main`) with fallthrough
  - Rejection of unsupported protocol versions (e.g. "2") with fallthrough
  - Rejection of malformed records (missing fields, invalid datetimes) with fallthrough
  - Delivery service base DID validation (fragments, URLs, ports, invalid methods)
  - Conjunctive SSRF allowlist + public-IP checks
  - `resolve_ds_did` with no default fallback
  - Migration upgrade test verifying purge of legacy rows

## Verification
- `cargo test --lib federation::resolver`: 75 tests passed (0 failed).
- `cargo test --lib federation::`: 180 tests passed (0 failed).
- Container Task 1 smoke test (`scripts/federation-two-node-harness.sh up` & `smoke`):
  - Ephemeral ports: DS1=32836, DS2=32835
  - DS1 and DS2 readiness: OK
  - Federation endpoints and capabilities: OK
  - Service-auth and signer verification (unauthenticated, malformed, wrong audience, admin upsert, cross-DS calls): ALL PASSED
  - Clean teardown: OK

---

## Fix Round 2: Strict Finding Closures

### 1. SSRF Binding to Actual Request & Pinned Transport
- Replaced unpinned two-step validation with single-resolution pinned destination handling via `validate_and_resolve_destination` and `send_hardened_resolution_request`.
- Configured hardened client: `reqwest::redirect::Policy::none()`, `no_proxy()`, single DNS resolution via `tokio::net::lookup_host`, and pinned exact resolved socket addresses via `.resolve_to_addrs(&destination.host, &destination.addrs)`.
- Enforced strict rejection of mixed/private IP responses. Any private address in production fails the entire destination resolution immediately.
- Handled response redirection by rejecting HTTP 3xx status codes on the response.

### 2. Real DID Validation with ATProto Parser & Hostname-Only did:web
- Implemented `validate_canonical_did` using `jacquard_common::types::string::Did::new` to parse ATProto DIDs.
- Allowed only exact `did:plc:[a-z2-7]{24}` and hostname-level `did:web:`.
- Rejected `did:web` path segments, trailing colons, public ports in production, and malformed encoding.
- Permitted development ports only on localhost when `APP_ENV=test` and `FEDERATION_ALLOW_INSECURE_HTTP=true`.

### 3. Explicit Default Pair in FederationConfig (Both-or-Neither)
- Updated `FederationConfig` with `pub default_ds: Option<(String, String)>`.
- Enforced strict "both-or-neither" requirement on `DEFAULT_DS_DID` and `DEFAULT_DS_ENDPOINT` with startup validation.
- Updated `DsResolver::new` to take explicit `default_ds: Option<(String, String)>` with zero hidden `std::env::var` reads.
- Refactored `handlers/resolve_delivery_service.rs` and `handlers/ds/fetch_key_package.rs` to extract `State(resolver): State<Arc<DsResolver>>` from `AppState` rather than constructing local resolver instances.

### 4. Injected Shared DsResolver into OutboundQueue
- Updated `OutboundQueue::new` to accept `resolver: Arc<DsResolver>`.
- In `OutboundQueue::resolve_target_endpoint`, invoke `self.resolver.resolve_ds_did` for live `did:web` and `did:plc` resolution without actor fallback.
- Added unit test verifying `OutboundQueue` resolves endpoints via the injected resolver.

### 5. UpstreamManager Policy Check Before Resolution/Network
- Added `pool: PgPool` to `UpstreamManager`.
- In `UpstreamManager::subscribe`, call `peer_policy::enforce_outbound_peer_policy(&self.pool, canonical_sequencer)` before calling `resolve_ds_did` or opening any network socket.
- Added unit test `test_upstream_subscribe_denies_untrusted_peer_before_resolution`.

### 6. Mandatory DB Tests & Deterministic SSRF Policy Injection
- Refactored `test_migration_purges_legacy_actor_keyed_ds_endpoints_row` to create an isolated schema (`test_mig_<uuid>`), seed the legacy pre-migration `ds_endpoints` table, apply `20260824000002_chat_actor_ds_mapping.sql` once, assert the legacy row is purged, and clean up.
- Introduced `validate_endpoint_url_with_custom_policy` and `validate_and_resolve_destination_with_policy` to allow deterministic parameter injection in SSRF tests without process-wide environment variable mutation races.

## Verification
- `cargo check --bin catbird-server && cargo check --lib`: PASSED
- `cargo test --lib federation::`: 181 passed, 0 failed
- Container Task 1 smoke test (`scripts/federation-two-node-harness.sh up` & `smoke`):
  - Ephemeral ports: DS1=32854, DS2=32853
  - DS1 and DS2 readiness: OK
  - Federation endpoints and capabilities: OK
  - Service-auth and signer verification (unauthenticated, malformed, wrong audience, admin upsert, cross-DS calls): ALL PASSED
  - Clean teardown: OK
