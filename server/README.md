# Catbird MLS server (`catbird-server`)

The Rust/Axum delivery service behind `blue.catbird.chat`. Operators start with [../SELF_HOSTING.md](../SELF_HOSTING.md), which covers identity, keys, federation, retention, and what is sealed (R0) versus the unsealed Task 4 R1 provisional commits.

**Migrations are held.** Startup applies pending migrations to `DATABASE_URL` unless `SKIP_MIGRATIONS` is set. Never start this tree, `make deploy` or `make migrate` against a production database until the production migration is authorized. See [migrations/README.md](migrations/README.md).

## Build and run

From `server/` (default features `namespace-bluecatbird` and `server-bin`):

```sh
cargo build
cargo run
```

`CMAKE_POLICY_VERSION_MINIMUM=3.5` is set in the repository's `.cargo/config.toml`. Known pre-existing issue: on the maintainer's macOS toolchain a default `--release` build fails in `sqlx-macros` (stripped dylib); debug builds work.

## Routes

`src/main.rs` mounts these. Request bodies are limited to 4 MiB by default, 15 MiB on single-artifact MLS paths, and 16 MiB on direct-request publication paths; narrower route limits are noted below.

| Prefix | Mounted when | Notes |
|---|---|---|
| `/health`, `/health/live`, `/health/ready` | always | |
| `/metrics` | `ENABLE_METRICS` is truthy | `METRICS_TOKEN`, if set, is a required bearer token |
| `blue.catbird.chat.*` | always | 36 endpoints; each answers `CutoverRequired` until `CHAT_CUTOVER_ENABLED` is set |
| `blue.catbird.mlsDS.*` | always | 35 S2S and admin routes |
| `com.atproto.space.*` | `SERVICE_DID` and a P-256 Space-host key | 7 Space authority and host routes |
| `blue.catbird.labyrinth.*` | `LABYRINTH_ENABLED` is truthy | 6 directory and account-lifecycle routes |
| `did:web` document path | `RECEIPT_ISSUANCE_MODE=issue` | serves `RECEIPT_DID_DOCUMENT_JSON` |

### Client: `blue.catbird.chat.*`

Clients call only their home DS. Calls authenticate with an ATProto service-auth JWT for `{SERVICE_DID}#atproto_mls`: at most 60 s lifetime, exact `lxm`, unique `jti`. The `subscribeEvents` WebSocket instead presents a one-use ticket from `getSubscriptionTicket`. Mutations carry the device's signed request. With `CHAT_REQUIRE_SIGNED_READS`, GET reads must carry device-signed read headers too.

| Method (body limit) | Endpoints |
|---|---|
| GET | `getDirectRequestOutcome`, `getDeviceKey`, `getDevices`, `getOwnDevices`, `getConversationState`, `getEntries`, `getConversations`, `getPendingWelcomes`, `getLeafRecoveryInbox`, `subscribeEvents` (WebSocket) |
| POST (16 MiB) | `publishDirectRequestKeys`, `publishDirectRequest` |
| POST (15 MiB) | `createConversation`, `submitTransition`, `sendMessage` |
| POST (12 MiB) | `enrollDevice`, `replenishKeyPackages` |
| POST (64 KiB) | `prepareDirectRequest`, `cancelDirectRequestPreparation`, `registerPushGateway`, `relaySpaceCredential`, `relaySpaceRead`, `acknowledgeEntries` |
| POST (4 MiB) | `requestReset`, `activateReset`, `revokeDevice`, `acknowledgeWelcome`, `rejectWelcome`, `requestLeafRecovery`, `cancelLeafRecovery`, `requestLeave`, `cancelLeave`, `closeConversation`, `publishTyping`, `acceptConversation`, `getSubscriptionTicket` |

The list is pinned by `chat_protocol_route_inventory`. The pre-clean-slate `blue.catbird.mlsChat.*` and `blue.catbird.mls.*` APIs are gone; for example, `/xrpc/blue.catbird.mlsChat.updatePushToken` returns `404`.

### Server to server: `blue.catbird.mlsDS.*`

[../SELF_HOSTING.md](../SELF_HOSTING.md#3-federation-and-peer-policy) describes authentication, peer policy, and which routes the kill switch covers.

| Group | Routes |
|---|---|
| Original DS routes | POST `deliverMessage`, `deliverWelcome`, `submitCommit` (15 MiB each), `transferSequencer`; GET `fetchKeyPackage` (reserves a recovery KeyPackage for the calling DS), `getConvoDigest`, `getConvoEvents`, `healthCheck` (unauthenticated) |
| Peer administration | GET `getFederationPeers`, `getFederationMode`; POST `upsertFederationPeer`, `deleteFederationPeer`, `setFederationMode`. Callers must be in `FEDERATION_ADMIN_DIDS`. GET `resolveDeliveryService` needs any authenticated user. |
| Groups and cross-home effects | POST `relayGroupMutation`, `deliverGroupEntry` (15 MiB each); `resolveGroupDevices`; `fetchKeyPackage` (a group's recovery-package export under a 5-minute lease); `getLabyrinthDirectory`, `getGroupConversationState`, `getGroupPendingWelcomes`, `notifyEntriesPruned` (64 KiB each); `relayEntryAck`, `relayAccountDeletion`, `deliverTransportControlEntry` (16 KiB each) |
| C33 direct requests | POST `reserveRecipientBootstrap`, `releaseRecipientBootstrap`, `prepareDirectRequest`, `deliverAcceptance`, `deliverAcceptanceEntry` (64 KiB each); `publishDirectRequest`, `deliverDirectRequest` (16 MiB each); `relaySendMessage`, `deliverMessageEntry` (15 MiB each); GET `getDirectRequestOutcome` |

### Space host: `com.atproto.space.*`

POST `getSpaceCredential`, `notifyWrite`, `removeWriter`, `registerNotify`, `unregisterNotify`; GET `listRepos`, `getSpace`. Contracts are in [../SELF_HOSTING.md](../SELF_HOSTING.md#8-space-authority-host-and-relays-3a).

### Labyrinth directory: `blue.catbird.labyrinth.*`

POST `publishEpochHead`, `purgeMailbox`, `deleteAccountData`; GET `getEpochHead`, `getChatDeviceKeys`, `getMemberDevices` (64 KiB). For a remote subject, `getEpochHead` and `getChatDeviceKeys` relay the device-signed read to the subject's home over `getLabyrinthDirectory`. No archive storage, MEK, thread or Space-policy endpoint remains here: `appendBatch`, `getEpoch`, `getThreadStorage`, `appendSpaceBatch`, `listSpaceBatches`, `getSpaceMembership` and `deleteSpaceGeneration` are not mounted.

## Background workers

| Worker | Runs when |
|---|---|
| Federation outbox handoff | always |
| Outbound S2S queue and reconciliation | federation enabled and `SIGNING_KEY_PEM` set |
| Expiry sweeper (30-day pruning, request expiry), 60-day device dormancy | `CHAT_CUTOVER_ENABLED` |
| Direct-request push wakes | `CHAT_REQUEST_PUSH_ENABLED` |
| Labyrinth operation GC (hourly, 7-day retention) | `LABYRINTH_ENABLED` |
| Rate-limiter and JTI-replay cleanup | always, every 5 minutes |

## Configuration

[../SELF_HOSTING.md](../SELF_HOSTING.md#2-identity-and-keys) lists identity, key, chat, federation and push variables. Other server settings:

| Variable | Default | Notes |
|---|---|---|
| `SERVER_HOST`, `SERVER_PORT` | `0.0.0.0`, `8080` | `SERVER_HOST` must be an IP literal |
| `RUST_LOG` | `debug` (debug build), `warn` (release) | |
| `ENFORCE_LXM`, `ENFORCE_JTI` | `true` | Disabling either needs `ALLOW_UNSAFE_AUTH`, which production refuses |
| `JTI_TTL_SECONDS` | `360` | JTI replay window |
| `DEVICE_AUTH_MODE` | `observe` | `observe`, `enroll` or `require` |
| `SSE_BUFFER_SIZE` | `5000` | |
| `REQUEST_BODY_READ_IDLE_TIMEOUT_MS`, `REQUEST_BODY_READ_TOTAL_TIMEOUT_MS`, `LARGE_BODY_READ_TOTAL_TIMEOUT_MS` | `15000`, `120000`, `300000` | Capped at 60 000, 600 000 and 600 000 |
| `RATE_LIMIT_*`, `FEDERATION_RATE_LIMIT_*` | see [RATE_LIMITING.md](RATE_LIMITING.md) | |
| `FEDERATION_SEQUENCER_FAILOVER_MIN_STALE_SECS`, `FEDERATION_SEQUENCER_TRANSFER_MAX_TERM_JUMP` | `30`, `8` | Original `transferSequencer` path |
| `CHAT_DIRECT_REQUEST_MAX_RETAINED_ACCOUNT_BYTES` | `268435456` | Allowed range 64 MiB to 8 GiB |

## Tests

PostgreSQL 16 on `127.0.0.1:5432`, with a role that can create databases. Each test mints and drops its own database; the guarded URLs below name only the maintenance database and must match exactly.

| Suite | Environment |
|---|---|
| Disposable full-catalog tests (lib and most integration targets) | `TEST_DATABASE_URL=postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722` and `CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed` |
| Direct-request suites sharing the reviewed manifest in `tests/common/direct_request_migrations.rs` | `REQUEST_TEST_DATABASE_URL=postgresql://127.0.0.1:5432/catbird_direct_requests_test_20260919` |

Feature gates: `test-support` is required by the fixture binaries (`federation_fixture`, `encrypted_request_server_fixture`, `clean_slate_federation_fixture`) and by targets such as `federation_group_and_space_relay`, `chat_protocol_federation_routing`, `chat_protocol_federation_router`, `chat_protocol_federation_outbox_retry`, `chat_protocol_remote_prefix_bootstrap`, `federation_fixture_cli` and `federation_fixture_auth_profile`. `deterministic_server_clock_test` requires `sim`.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features sim,test-support -- -D warnings
cargo test --features test-support --test federation_group_and_space_relay
cargo test --features sim --test deterministic_server_clock_test
cargo test --test clean_chat_empty_preflight
```

`clean_chat_empty_preflight` runs `scripts/assert_clean_chat_empty.sql`, which accepts only a sealed migration catalog. The current seal is 143 migrations ending at `20261104000012`. After a migration change, reseal it from `server/`:

```sh
CLEAN_CHAT_PREFLIGHT_RESEAL=write cargo test --offline --test clean_chat_empty_preflight -- --ignored --exact reseal_clean_slate_catalog
```

`../scripts/federation-hostile-test-gate.sh` replaces the deleted `federation_hostile_peers` suite. It runs the current hostile-peer regressions (group relay security, peer policy, untrusted JWT issuers, hostile bootstrap admission, forged or mismatched receipts, untrusted-peer routing) and a lib check, and refuses to start without the database environment above.

Two-home end-to-end suite, from the repository root (`e2e-tests` is outside the workspace):

```sh
cargo build --locked --manifest-path server/Cargo.toml --features test-support --bin clean_slate_federation_fixture
cargo test --manifest-path e2e-tests/Cargo.toml --features labyrinth --test federation_spaces_full_cutover
```

It runs two `clean_slate_federation_fixture` processes from `target/debug/`, each over a fresh `clean_slate_fed_<hex>` database on `127.0.0.1:5432` (admin URL `CLEAN_SLATE_PG_ADMIN_URL`, default `postgresql://127.0.0.1:5432/postgres`), with loopback mock PDSes and a mock Push Gateway. The ignored Docker lifecycle test uses `e2e-tests/docker-compose.federation.yml` and the same deterministic `did:web` DS1 plus `did:plc` DS2 identity pair as the root local stack. It loads each service-auth and dedicated `#mls-receipt-1` key from its committed test fixture, resolves every DID and each user's DID-advertised PDS declaration through the loopback HTTPS fixture, leaves DS2 unprovisioned until the authenticated `deliverWelcome` worker fetches and binds the exact Direct prefix, verifies the signed `deliverWelcome`, `deliverMessage` and `submitCommit` receipt bodies and signer audiences, and requires `down --volumes` to leave no project container or volume:

```sh
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo test --locked --manifest-path e2e-tests/Cargo.toml --test federation_two_node -- --ignored --test-threads=1
```

`deliverWelcome` admits only the exact three-entry Direct opening (`Creation`, recipient `ParticipantAcceptance`, `LeafRecoveryFulfillment`). It applies that verified prefix and the Welcome mailbox receipt in one PostgreSQL transaction; the general remote-prefix path still rejects historical Direct conversations.

`e2e-tests/federation-two-node-e2e.sh` is the shorter Compose readiness, peer-authentication and receipt-configuration smoke. The local client gateway is documented in [../e2e-tests/CLIENT_RUNTIME_GATEWAY.md](../e2e-tests/CLIENT_RUNTIME_GATEWAY.md).

CI (`.github/workflows/mls-deploy.yml`) uses PostgreSQL 16 and runs a narrower set than the commands above: `--bins` unit tests, `chat_protocol_signing_domain_vectors`, `chat_protocol_route_inventory`, `federation_fixture_auth_profile` and `chat_protocol_generated_transition_compat`, the e2e `federation_two_node` lifecycle, the ignored `db_tests` cases, three handler regressions, `labyrinth_directory`, `labyrinth_retention` and `labyrinth_account_deletion`, and `deterministic_server_clock_test` (`sim`), all required. `scripts/test_ops_safety.py` checks the database reset guard, migration-log redaction, the test targets, features and filters of the workflow and hostile gate, and both federation Compose fixtures.

## Make targets

`make build`, `make run`, `make test` (`cargo test` only, not the feature-gated suites), `make logs`, `make status`, and the systemd `start`, `stop` and `restart`. `make migrate` runs `scripts/run-migrations.sh`, which prints the target host and database but never credentials. `make deploy` restarts the service on a new binary, whose startup applies pending migrations; both are held with the migrations. `make reset-dev-db URL=...` drops, recreates and migrates the `catbird` database of one local federation stack container (`localhost` or `127.0.0.1`, port `5433` or `5434`) through `scripts/reset-dev-db.sh`, which first requires the live server to report that container's `cluster_name`, refuses every other target and has no override. There is no production wipe target.

## Other documents

- [migrations/README.md](migrations/README.md): migration chain, gates, and per-migration contracts.
- [RATE_LIMITING.md](RATE_LIMITING.md): per-IP, per-DID and per-peer limits.
- [scripts/README.md](scripts/README.md): operational scripts.
- [docs/operation_claim_completeness_activation.sql](docs/operation_claim_completeness_activation.sql): reviewed byte-for-byte mirror of the gated `20260728000004` migration.
- [../docs/SPACE_CONVERSATION_STORAGE.md](../docs/SPACE_CONVERSATION_STORAGE.md): conversation Spaces, close, and account deletion.
- `DATABASE_SCHEMA.md`, `DB_*.md`, `DEPLOYMENT*.md`, `QUICK_REFERENCE.md` and `CLIENT_INTEGRATION_GUIDE.md` describe the pre-clean-slate `public` schema and `blue.catbird.mls*` APIs that migration `20261031200001` removed. They are historical.
