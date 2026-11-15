# Database migrations

SQL migrations for `catbird-server`, applied in version order by SQLx (`sqlx::migrate!("./migrations")`). They are forward-only: there are no `.down.sql` files, and a migration that has been applied anywhere is never edited.

## Status

- The R0 seal (bookmark `clean-slate-2026-10-31`, mls-ds `d5f6993c`) has 129 migrations, ending at `20261102000003_conversation_close_terminal_entries.sql`.
- The unsealed Task 4 R1 provisional commits add fourteen, for 143: `20261103000001` through `20261103000004`, `20261103000010`, and `20261104000001`, `000002`, `000005`, `000006`, `000007`, `000008`, `000010`, `000011` and `000012`. The seed-2323 fix adds `20261107000001`, for 144. The Round 4 lifecycle relay adds `20261113000001`, for 145. Wave 2 multi-device approval and Nov-12 Spaces adds `20261114000001`, for 146. Wave 2 R2 archive watermark adds `20261115000001`, for 147. Their contracts are in the sections below.
- **Held.** These migrations have run only against local disposable and guarded test databases. Do not apply them to a production database until R1 is sealed and the production migration is separately authorized. Server startup applies pending migrations, so the hold also covers starting this tree against a production database.
- `../scripts/assert_clean_chat_empty.sql`, run by the `clean_chat_empty_preflight` test, accepts only sealed catalogs: the frozen 75- and 84-migration seals, and the current clean-slate seal of 147 migrations ending at `20261115000001` (98 `chat` tables and one view). Reseal it after any migration change; the command is in [../README.md](../README.md#tests).

## Clean-Chat Operation Claim Rollout

The global operation-ID rollout is deliberately split across forward-only
migrations:

1. **20260728000001_chat_operation_claims.sql**
   - Creates `chat.operation_claims` and initially backfills it from completed
     idempotency receipts.
   - This migration has been installed in a gate database and is immutable.
   - Raw-file size: `6299` bytes.
   - SQLx SHA-384:
     `fd71f2eb5235226371f113b5738b752b27e901b72810e9ec1e1f201e979606e0b09a16be087103e4146b4fb9f8bdff8f`.

2. **20260728000002_exact_operation_claim_mutation_kind.sql**
   - Refines endpoint-family claims to exact signed mutation kinds.
   - Keeps receipt-to-claim completeness staged while handlers move to the
     shared operation prelude.

3. **20260728000003_defer_operation_claim_principal_fk.sql**
   - Changes only `operation_claims_principal_fk` to `DEFERRABLE INITIALLY
     DEFERRED`, allowing enrollment to claim an operation before creating a new
     principal in the same atomic transaction.
   - Locks the claim table and fails closed unless the installed constraint is
     the exact validated, immediate FK created by `00001`; a postflight proves
     the exact validated deferred replacement.
   - Before any successful application, PostgreSQL rejected the original source
     because it used the keyword `constraint` as an unquoted relation alias.
     The pre-application amendment changes only that alias to `constraint_row`;
     see
     [`../docs/20260729-operation-claim-principal-fk-migration-amendment.md`](../docs/20260729-operation-claim-principal-fk-migration-amendment.md).
   - Raw-file size: `6722` bytes.
   - SQLx SHA-384:
     `d42c64d98f6af2042ecf5d08b925aaadae01efcd7d1f6d1887c5485e0862d80304bb9ba54506a1876eba54b505d4114a`.
   - The normalized live constraint-catalog fingerprint remains pending a
     reviewed fresh-database refresh.

4. **20260728000004_activate_operation_claim_completeness.sql**
   - Activates future-row receipt-to-claim completeness after the production
     writer drain.
   - Corrects the endpoint-kind mapping forward-only: `requestLeave` accepts
     both `leaveRequestBody` and `zeroLeafLeaveBody`, while
     `submitTransition` excludes `zeroLeafLeaveBody`.
   - Under exclusive locks on both writer tables, records the exact bounded
     legacy orphan set as a count plus a domain-separated SHA-256 over the
     sorted immutable operation IDs, then recomputes both values fail-closed
     after classification.
   - Drains exactly the two preexisting `INITIALLY DEFERRED`
     `idempotency_records` row-integrity constraints after populated legacy
     classification, then restores their deferred mode before adding generated
     columns. This avoids PostgreSQL's pending-trigger-event prohibition
     without weakening the constraints or widening the drain.
   - Task-9 migration lineage is explicitly reopened for this populated-upgrade
     repair. The previously sealed `15837`-byte source had SQLx SHA-384
     `d7f92b96421a33f0385789f44c0fc2986321e8c7487e79e96c9c4880a1853e4c9d7d32f36bf3dfd22ff07a1cd6fb1674`;
     the repaired source below is the candidate reseal.
   - **No deployed reset action:** do not delete or rewrite any deployed
     `_sqlx_migrations` row, do not reapply `00004`, and do not represent the
     repaired checksum as already installed. A database carrying the old
     checksum requires a separately reviewed forward lineage decision. This
     repair has been exercised only against the explicitly authorized local
     test database; no remote database was touched.
   - Leaves the future-row `CHECK (operation_claim_required)` intentionally
     `NOT VALID` so bounded retained legacy rows remain representable, while
     validating the new `MATCH FULL` receipt-to-claim FK.
   - Raw-file size: `16432` bytes.
   - SQLx SHA-384:
     `7de97f6f84a9cfcbf535b990b5aec87930450cf6661c7d8cf11920bdf53fd0fe94623e9ed222a8eeb562c1ee596c5bd6`.
   - The normalized live column, constraint, index, function, trigger, and
     sequence fingerprints after the complete G7 migration chain are pinned by
     `tests/chat_protocol_schema.rs`.

The reviewed source at
[`../docs/operation_claim_completeness_activation.sql`](../docs/operation_claim_completeness_activation.sql)
must remain byte-for-byte identical to `00004`. Never edit `00001` through
`00003` to perform activation.

## G7 Inventory Entitlement Migration

**20260729000001_chat_g7_inventory_entitlement.sql** is the thirteenth
clean-chat migration. It replaces implicit conversation-inventory entitlement
with one immutable, typed provenance arm per retained item:

- `blue.catbird.chat.defs#conversationInventoryState` binds the exact
  participant period selected for current state.
- `blue.catbird.chat.defs#conversationRemovalTombstone` binds the exact closed
  application interval and its terminal provenance.
- `blue.catbird.chat.defs#conversationCloseTombstone` retains the existing
  exact schedule-terminal proof.

The forward backfill treats each legacy non-close item as an active-leaf
selection and requires exactly one participant/interval source valid at the
inventory session's `created_at`. It aborts on absent, ambiguous, incomplete,
or mismatched provenance. It recomputes provenance-inclusive digests and byte
sums without rewriting or deleting any retained payload bytes.

Legacy cursor plaintext cannot be re-sealed by SQL, so the migration explicitly
expires every pre-G7 inventory session and removes plaintext cursor columns.
New page and event receipt tables retain only lookup hashes plus AEAD-sealed
successor/cursor ciphertext. Materialization (`*_complete`) remains separate
from exact-client consumption (`*_consumed`), and ticket eligibility requires
all three domains to be both complete and consumed.

Source precedence is checked only when an immutable conversation inventory item
is inserted. Removal provenance must name the latest finite interval at the
inventory snapshot, ordered by `(start_seq DESC, membership_interval_id DESC)`;
the UUID coordinate is the deterministic authority tie-break when two retained
intervals have the same start sequence. Open re-add intervals reject an older
removal only when they are valid at the same snapshot. Never add an UPDATE-time
or deferred historical source revalidation: later participant removal or
interval closure must not invalidate an already retained, otherwise unexpired
page.

- Raw-file size: `76836` bytes.
- SQLx SHA-384:
  `2c00fc11f1d96b79c3c86320e769d70d52fecb477a8a2bc351151fd2d01e3d4c5df19cbf7a3ac482edbe16a33a0dd60e`.

This digest is provisional until the separately reviewed Task 10 addendum is
amended. The previously approved addendum digest does not authorize these
round-two fail-closed and catalog-authority repairs.

The fixed-target schema gates never repair, reset, or replay migrations. They
first require the exact reviewed thirteen-row SQLx ledger, run only that
reviewed migration set (which is therefore a no-op), and then require the
ledger to be byte-for-byte unchanged. A0 fingerprint inputs are embedded in
the test crate with reviewed hashes, so validation does not depend on files
outside this repository.

### Authorizing migration `20260728000004`

`00004` fails before taking table locks unless its exact migration connection
has the custom GUC value
`chat.operation_claim_activation_approved=handlers-and-legacy-apis-sealed`.
Do not set this globally or weaken the gate.

For `sqlx-cli`, set the value only on the newly opened migration connection:

```bash
PGOPTIONS="-c chat.operation_claim_activation_approved=handlers-and-legacy-apis-sealed" \
  sqlx migrate run
```

For a runner that exposes the exact transaction connection, set the local value
on that same transaction before invoking the migration:

```sql
SET LOCAL chat.operation_claim_activation_approved = 'handlers-and-legacy-apis-sealed';
```

Setting the GUC on some other pooled connection does not authorize the
migration. Automatic startup migration must likewise inject the value into the
connection that actually executes `00004`.

## Running migrations

Production application is held (see [Status](#status)). On local and test databases:

- **Server startup** (`db::init_db_default`) repairs the ten April 2026 legacy version rows, then applies every pending migration. Setting `SKIP_MIGRATIONS` to any value skips both. Startup sets the activation GUC only when `CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed`; otherwise a fresh database commits every migration before `20260728000004` and then stops on it. An applied version missing from this directory also stops startup.
- **`../scripts/run-migrations.sh [DATABASE_URL]`** (`make migrate`) installs `sqlx-cli` if needed and applies `../scripts/repair-2026-04-migration-versions.sql` when `_sqlx_migrations` exists. If `20260728000004` is still pending, it refuses before applying anything unless `CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed` is set, and then runs `sqlx migrate run` with the GUC scoped to that one connection. Its log line shows only the target host, port and database, never credentials or query parameters.
- **By hand:**

```bash
PGOPTIONS="-c chat.operation_claim_activation_approved=handlers-and-legacy-apis-sealed" \
  sqlx migrate run --database-url "$DATABASE_URL"
sqlx migrate info --database-url "$DATABASE_URL"
```

## Creating new migrations

```bash
sqlx migrate add <migration_name>   # creates migrations/YYYYMMDDHHMMSS_<migration_name>.sql
```

In the same change:

1. Use the 14-digit version form (below).
2. Add the file and its SQLx SHA-384 to `reviewed_request_migrations()` in `../tests/common/direct_request_migrations.rs`. That shared manifest rejects any migration at or after `20261004000001` it does not list.
3. Reseal the clean-slate preflight catalog (see [Status](#status)).
4. Document the migration's contract in this README.

## Migration Best Practices

1. **Never modify existing migrations** - Once applied, migrations are immutable
2. **Always test migrations** - Test on a copy of production data
3. **Use transactions** - Migrations should be atomic
4. **Add indexes carefully** - Consider CONCURRENTLY for large tables
5. **Document changes** - Add comments to explain complex migrations

### Filename format (READ THIS BEFORE NAMING A NEW MIGRATION)

sqlx parses everything **before the first underscore** in a migration
filename as the integer version. This means:

| Filename                                      | Parsed version |
|-----------------------------------------------|----------------|
| `20251125000001_opt_in_table.sql`             | `20251125000001` (good) |
| `20260403_001_drop_read_receipts.sql`         | `20260403`        (BAD — sorts before earlier 14-digit migrations) |
| `20260403100000_drop_read_receipts.sql`       | `20260403100000`  (good) |

**Always use the 14-digit `YYYYMMDDNNNNNN_*.sql` form**, even if you only
need one migration today. Reserve `100000`, `200000`, … for the
within-day suffix (`000000` is conventionally the first / system-generated
slot). Never use the `YYYYMMDD_NNN_*.sql` form — sqlx will silently sort
those migrations far before the 14-digit ones, breaking fresh-DB bring-up.

This rule was retroactively enforced in `chore/ci-cleanup` (April 2026)
when 10 legacy `YYYYMMDD_001_*` migrations were renamed. The companion
production-DB repair script lives at
`scripts/repair-2026-04-migration-versions.sql` and must be run **before**
deploying any commit on or after that PR to a database that already has
the old version numbers in `_sqlx_migrations`.

## Schema Version Tracking

sqlx maintains a `_sqlx_migrations` table to track applied migrations:

```sql
SELECT * FROM _sqlx_migrations ORDER BY version;
```

## Per-device application send order

`20261107000001_application_send_order.sql` adds `chat.application_send_order`:
one row per `(conversation_id, actor_did, actor_device_id)` holding the last
accepted send's signed `(generation, epoch, sendCounter)`. A sequencer resolving
a `messageId` for the first time (local `sendMessage`, the group relay, or the
C33 coordinator relay) accepts it only if its triple is lexicographically
greater, advancing the row with one conditional upsert under the conversation
head lock. Otherwise it answers `StaleSend` and writes nothing. An exact replay
of an accepted send is answered from `chat.message_sends` before this check.
A mirror records the same triple for every application entry it appends from
its sequencer (`deliverMessage` replication and reconciliation or bootstrap
import) and keeps the later one, so a mirror that takes over sequencing
(`federation::transfer`) refuses a send its replicated history already passed.
Rows cascade with their conversation, so the close wipe removes them.

The migration also backfills the table from the accepted application entries a
sequencer or mirror already holds: under `LOCK TABLE chat.entries IN SHARE
MODE`, each device starts at the greatest triple its retained signed requests
carry, so a held lower send is `StaleSend` after the upgrade and after a
populated mirror takes over. Entries signed before `sendCounter` existed order
nothing, and a pruned entry's triple left with its signed request. Signing
domains end in an escaped NUL (`\u0000`) that `jsonb` refuses, so a
`regexp_replace` that consumes escapes pairwise drops exactly those escapes
before the cast. Raw-file size: `3524` bytes. SQLx SHA-384:
`457b8d78861a458425a5ed617874a8397547e03fdf2a7038f3ead6737f5cb156b5e9b3fa5df40442a152d72b1279c1c1`.
The R3 cut (`dc18b03f`) shipped this version without the backfill (SHA-384
`0883b7dc…e649`); a local database that applied it must be recreated, because
SQLx refuses the changed checksum (`VersionMismatch`). Nothing outside local
test databases ever applied it.

## PostgreSQL churn and terminal-history partitions

`20261104000012_postgres_churn_partitions.sql` converts only the two public
transport queues with age-expired terminal history. Active `pending` and
`in_flight` rows have `terminal_at IS NULL` and stay in each table's DEFAULT
partition. The first terminal transition stamps `terminal_at`; later terminal
updates preserve it. PostgreSQL routes those immutable rows into UTC calendar
month partitions. The maintenance function fixes its own timezone to UTC, so
manual clients and the workers use identical interval arithmetic. It takes the
partition parent lock before DEFAULT, matching producer parent-to-child order.
The workers call
`public.maintain_transport_partitions(regclass, interval, timestamptz)` every
five minutes, keep the current and next two months ready, and drop only a whole
month whose upper bound is at least seven days old. A missed maintenance window
is safe: finite rows land in DEFAULT and the next call moves them before
attaching the month. The upgrade call creates and routes partitions with
`drop_expired=FALSE`, so applying the migration itself deletes no rows.
Raw-file size: `17470` bytes. SQLx SHA-384:
`e9700954fc90dd3f99c47eb93eddac7f233e2e2f274f01882c49144b2c9d7499ac60e277f3629039019555c6df9aaa80`.


PostgreSQL requires every partitioned unique constraint to include the
partition key. Because active rows need a nullable key, the physical constraint
is `UNIQUE NULLS NOT DISTINCT (id, terminal_at)`. A guarded trigger retains the
old global `id` invariant across months. It transaction-serializes inserts by
the parent OID plus deterministic ID, then performs a fresh global existence
check; a replay returns no row, preserving `ON CONFLICT DO NOTHING` even when
the winner moved to a terminal partition. A shape check forbids an active row
with a finite key; BEFORE UPDATE and AFTER INSERT triggers guarantee every
terminal row receives one while preserving an existing terminal month. Neither
table has an inbound foreign key at this migration tip.

| Relation | Time/identity and query indexes | Existing retention semantics | Decision |
|---|---|---|---|
| `public.outbound_queue` | Logical ID `id`; `created_at`; new nullable `terminal_at`; due, lease and `convo_id` indexes | Mutable while pending/leased; delivered, failed and dead history was row-deleted after seven days | DEFAULT for live state; monthly terminal partitions; whole-partition drop |
| `public.federation_outbox` | Logical ID `id`; `created_at`/`updated_at`; new nullable `terminal_at`; due, lease and `conversation_id` indexes; no remaining delivery-event FK | Mutable while pending/leased; terminal handoff history, with dead rows previously row-deleted after seven days | DEFAULT for live state; monthly done/failed/dead partitions; seven-day whole-partition drop |
| `chat.outbox` | PK `outbox_id`; unique `(event_position, work_kind)`; FK to `chat.events`; due/lease indexes | Live event work and retained protocol evidence; no age deletion | Not partitioned |
| `chat.direct_request_transport_wakes` | PK/FK `delivery_id` to transport inbox; lease/due timestamps and indexes | Live pending/leased/delivered/failed wake state; removed with its inbox | Not partitioned |
| `chat.direct_request_transport_inbox` | PK `delivery_id`, unique request/recipient device; `created_at`, `updated_at`, `import_until`; referenced by inventory and wake rows | Live import/relationship state; close wipe, not age deletion | Not partitioned |
| `chat.direct_request_transport_entries` | PK `delivery_id`, unique `(conversation_id, seq)`; `created_at`; referenced by recipient grants | Ciphertext is pruned after 30 days, but the ordered skeleton remains until close | Not partitioned: dropping a month would delete live transcript identity |
| `chat.entries` | PK `(conversation_id, seq)`, unique `entry_id` plus retained coordinate uniques; `received_at`; multiple protocol FKs/indexes | Ciphertext-only 30-day pruning; sequence skeleton retained | Not partitioned |
| `chat.federation_delivery_receipts` | PK `delivery_id`; `completed_at`; FKs to conversation and entry; lookup by delivery ID | Replay/idempotency evidence retained until conversation close; no age TTL | Not partitioned |
| `chat.inventory_page_receipts`, `chat.event_cursor_receipts` | 15-minute `expires_at`; PK/global unique cursor hashes; self/session FKs and session indexes | Deleted as one exact inventory-session graph | Not partitioned: self/global constraints and atomic graph deletion are authoritative |
| Legacy `event_stream`, `delivery_events`, `delivery_acks`, `notification_outbox` | Legacy timestamps and indexes | Removed by the clean-slate migration | Absent; no fake partition shells |

The migration also pins both autovacuum vacuum and analyze scale factors to
`0.01` on every live KeyPackage/reservation churn table and sets
`chat.conversations` to `fillfactor=70`. Inspect with
`pg_options_to_table(pg_class.reloptions)`. Operators can invoke maintenance
manually after downtime:

```sql
SELECT public.maintain_transport_partitions(
  'public.outbound_queue'::regclass, interval '7 days'
);
SELECT public.maintain_transport_partitions(
  'public.federation_outbox'::regclass, interval '7 days'
);
```

Current clean-slate encrypted payloads continue to use their existing SHA-256
columns and database checks. The former `chat.blobs`/object-store queue was
removed by the clean-slate migration, so this change adds neither a generic
`StorageBackend` nor a second content-addressing scheme. Existing repository
transactions and the database function are the narrow test seams. Geographic
or tenant sharding is a day-two design only; no routing or shard abstraction is
introduced here.

## Rollback strategy

There are no down migrations, and `sqlx migrate revert` does not apply here. Undo a change with a new forward migration. Where a data-preserving reverse script was reviewed, it lives in `../scripts/` (for example `rollback-20260905000001-chat-historical-recovery-package-mapping.sql`). `../scripts/rollback.sh` restores the previous binary only, never the schema.

## Development and production

Development and test databases can be dropped and recreated (below). Production migration is held (see [Status](#status)): do not run any command in this README against a production database until it is authorized.

## Troubleshooting

### A migration fails midway

Each migration runs in its own transaction, so a failure leaves the earlier migrations committed and the failing one unapplied. Fix the cause and run again. Never insert, delete or rewrite `_sqlx_migrations` rows by hand; a checksum mismatch needs a separately reviewed forward decision (see `20260728000004` above).

### `20260728000004` refuses with SQLSTATE 55000

The migrating connection lacks the activation GUC. See [Authorizing migration `20260728000004`](#authorizing-migration-20260728000004).

### Reset a development database

```bash
sqlx database drop --database-url "$DATABASE_URL"
sqlx database create --database-url "$DATABASE_URL"
PGOPTIONS="-c chat.operation_claim_activation_approved=handlers-and-legacy-apis-sealed" \
  sqlx migrate run --database-url "$DATABASE_URL"
```

`../scripts/reset-dev-db.sh <URL>` (`make reset-dev-db URL=...`) runs the same three steps for the local federation stack's databases only (`catbird` on `localhost` or `127.0.0.1` port `5433` or `5434`, whose server reports `cluster_name` `catbird-federation-ds1` or `catbird-federation-ds2`) and refuses any other target. It then invokes the existing Compose `peer-fixtures` service with `--no-deps`, restoring both homes' idempotent peer allowlist rows before the reset home is restarted. `sqlx migrate info` lists applied and pending migrations with their checksums.

## Index Creation

For large tables in production, consider using `CONCURRENTLY`:

```sql
-- Instead of:
CREATE INDEX idx_name ON table(column);

-- Use:
CREATE INDEX CONCURRENTLY idx_name ON table(column);
```

Note: sqlx migrations run in transactions, so `CONCURRENTLY` requires special handling.

## See also

- [../../SELF_HOSTING.md](../../SELF_HOSTING.md): operator guide and current status.
- [../README.md](../README.md): routes, workers and test commands.
- [SQLx `migrate!`](https://docs.rs/sqlx/latest/sqlx/macro.migrate.html)

## Generated transition wrapper compatibility

`20261025000001_generated_transition_wrapper_kind.sql` replaces only the exact
wrapper-kind extractor. The five canonical tagged `submitTransition` variants
may omit their singleton body tag, as the generated Rust serializer does. A
present body tag must agree with its exact outer tag. Untagged native wrappers
keep the explicit body-tag requirement. Original request bytes and all deferred
claim, transcript, endpoint, digest and signature checks remain unchanged.

The local `chat_protocol_generated_transition_migration` target covers a fresh
full catalog, an upgraded catalog with an existing native receipt, SQL reapply
idempotency, malformed authority fields and unchanged unrelated constraints.
The authenticated generated Rust and Swift policy handler tests cover the full
cryptographic and persistence path separately. Applied migration files are
unchanged; production application of this migration is a separate operator gate.

## Replicated group entry audiences

`20261102000001_group_transport_entry_recipients.sql` retains the exact local
device audience supplied by authenticated group fan-out. Replicated group reads
require a grant for each sequence; merely knowing the conversation ID is not
enough. Duplicate deliveries cannot widen the stored audience. The grant rows
cascade when operational entries are wiped on close. The simulation migrator
loads the complete migration catalog, and its schema-discovered reset includes
this `chat` table automatically.

## Strict-home group membership

Group creation and pending-participant policy changes resolve and stage remote
device authority from the participant's home DS and its PDS device directory.
Only the participant's home receives the client request. Authenticated
`deliverGroupEntry` fan-out triggers verified prefix bootstrap there, including
pending-invitation and acceptance-only prefixes. Existing exact prefixes admit
verified membership suffixes in source order; mismatching overlaps still
quarantine.

`getConversations` and `getConversationState` therefore expose a remote pending
invitation at the home DS. Its normal `acceptConversation` request relays to the
sequencer, which obtains the exact device's recovery KeyPackage through S2S
`fetchKeyPackage`. Migration `20261102000002_group_key_package_exports.sql` adds
a short request-bound home lease so concurrent recovery cannot select that
still-available package before the accepted prefix is mirrored. These leases
cascade on conversation deletion and are removed on close.

A group's remote homes receive every entry, application entries included, only
through the sequencer's ordered `deliverGroupEntry` stream; groups queue no
`deliverMessage` or federated `deliverWelcome` (direct and C33 conversations
keep both). A home's verified prefix provisions a Welcome from the fulfillment
itself, and a member the prefix cannot reach reads its Welcome through the
sequencer (below). `getPendingWelcomes`, `acknowledgeWelcome`, and
`acknowledgeEntries` stay at the home endpoint; acknowledgements also relay to
the sequencer, while local mailbox dispositions and watermarks remain durable at
home. No client needs to enroll its device or publish KeyPackages on another DS.

The sequencer sends every control entry to the home of each remote participant
that is still waiting for its first leaf, whether it is invited or has already
accepted. While a local participant is waiting, a membership entry (creation,
add policy, acceptance, or recovery fulfillment) makes the home apply the
verified suffix to its existing mirror.
That suffix never reseals the immutable historical cutoff; replicated
application entries after the cutoff use the ordinary reconciled-send mapping.
Once every local participant has a leaf, the home stores replicated entries
without further membership catch-up. For `getConversationState` on a remote
group, the home relays the read to the sequencer over S2S
`getGroupConversationState`, so the roster, coordinates, and `sequencerDid` stay
current across commits, metadata changes, and removals. A C33 transport-only
home relays the read to its pair's coordinator the same way. The sequencer
applies its own read authority, and its rejections pass through. Only when it is
unreachable does a home serve its mirror; a home with no mirror fails the read
retryably.

Relayed group operations keep the sequencer's answer. This covers membership
operations, `sendMessage`, and `submitTransition`. Any 4xx protocol rejection,
such as `StaleCoordinates` or `KeyPackageUnavailable`, reaches the client
unchanged, so the client can resync and retry. A rejected acceptance also frees
its exported KeyPackage lease. An authority failure on either DS returns
`NotAuthorized`. An unreachable sequencer or a 5xx answer returns the endpoint's
declared retryable code: `RelationshipPolicyUnavailable`, or
`CapacityUnavailable` for Welcome dispositions. `acknowledgeEntries` declares
neither, so it returns an internal error.

Historical mirroring still supports only creation, add-only policy, acceptance,
recovery fulfillment, and application entries, so a mirror whose source history
holds a generic Commit, metadata change, removal or role policy, reset, leave,
or close cannot admit an account that joins later.
`20261104000001_remote_group_memberships.sql` adds the home's remote-group
membership index for that case. The home's `deliverGroupEntry` handler writes it
only for accounts homed here, only from the mirror's stored sequencer, only
after the control entry verifies under its actor's key at the exact signed
authentication generation, and only in sequence order: an invitation (creation
or add policy) records `pending`, the account's acceptance `active`, a removal
or the sequencer's `accountDeletedEntry` `removed`, and a recovery fulfillment
the pending Welcome of the exact device it names. A close wipe and the
account's own deletion delete its rows; the deletion first relays to each
indexed sequencer. An index member the clean graph lacks is served from the
sequencer: the final `getConversations` page appends its relayed
`getGroupConversationState` view, and the final `getPendingWelcomes` page its
device's Welcomes read over S2S `getGroupPendingWelcomes` (the sequencer checks
the caller is the account's home and the account a current participant homed
there). Pages are capped at the 100-item lexicon bound. Its replicated entries
are read through their per-entry grants, which admit active local devices of
pending or active index members, and its exported KeyPackage requires the same
standing. A removed index member reads nothing: no grants, entry reads,
KeyPackage exports, or relayed Welcomes. While the sequencer is unreachable,
`getConversationState` fails retryably for an index-only member instead of
serving a mirror that does not list it.

A remote invitation changes no local `chat.events` head, so the scoped inventory
session identity also digests the account's `remote_group_memberships` rows
`(conversation_id, status, evidence_seq)` and the device's
`remote_group_pending_welcomes` rows, in a stable order. An index change
therefore starts a new 15-minute inventory session instead of serving the
pre-invite snapshot; an account with no rows keeps its session identity.
`deliverGroupEntry` locks the local device rows its grants and Welcome markers
reference (`FOR KEY SHARE`, ordered by DID bytes, then device UUID bytes) before
the conversation row, which is the order readers use.

Two-DS simulations configure a dedicated request receipt signer on each
`ChatRuntime` using the sim-only `with_request_receipt_keys` builder before
protocol-fence validation. C33 chooses the lexicographically smaller canonical
home DID as coordinator; that node's receipt authority and published
`#chat-request-receipt-*` method must agree with its own DID, not a process-global
receipt document belonging to the other node.

Remote Labyrinth directory reads also stay on the caller's home endpoint.
`getEpochHead` and `getChatDeviceKeys` resolve the subject's declared DS and
forward the original device-signed read claim through the authenticated,
read-only `getLabyrinthDirectory` S2S endpoint. The authoritative home rechecks
the caller-home binding and the device's current PDS-authorized key, verifies
the exact endpoint/query claim, and serves its live epoch chain or device roster.
Local replicated keys never substitute for the remote subject's current roster;
no home database connection remains held during federation I/O.

Outbound group federation requires a per-issuer ES256 DS-to-DS service JWT:
`aud` is exactly the target's canonical bare DID, `lxm` is exactly the called
`blue.catbird.mlsDS.*` method, and the token lifetime is at most 60 s. The
receiver verifies the issuer's live DID key and replay admission before inbound
peer policy. Production has no shared-secret group-relay HMAC configuration.

## Remote ciphertext pruning and device key history

`20261103000001_remote_application_ciphertext_pruning.sql` extends `I14` to
`chat.direct_request_transport_entries`. Acknowledgements are durable on both
group mirrors and transport-only C33 homes. An application waits for its frozen
local audience's active, non-dormant devices, then loses its ciphertext in both
transport and mirrored entry storage in one transaction. Independently, the
30-day expiry sweep prunes every transport copy this home stored more than 30
days ago, acknowledged or not. Its original digest, signature-bearing metadata,
sequence and `I13` receipt remain immutable. Pruned reads use
`payloadPruned: true`; duplicate delivery cannot restore bytes.

Signed requests end their signature domains in `\u0000`, which PostgreSQL
`json`/`jsonb` reject, so the migration and its triggers never parse entry JSON.
The single Rust writer derives the message id, request digest, metadata,
prior generation and pruned projection; SQL only digests raw bytes and allows
exactly one prune to that captured projection. Rows stored before the migration
carry `evidence_pending` until the sweep records their evidence once.

`20261103000010_direct_request_opening_pruning.sql` extends this to the C33
opening: the published direct request's `initialCiphertext`. Once every frozen
device that can still read the opening acknowledged its seq, or its sender's
account is deleted, each home drops every copy. The coordinator nulls the entry,
the publication transition and the publication row's signed publication, request
entry and initial ciphertext in one transaction, and drops a queued delivery. A
transport-only home prunes the opening's transport entry to the projection
captured at insert and trades each inbox row's opening for a redacted entry.
Digests, the sender signature, both receipts and that redacted entry (the
ciphertext replaced by its SHA-256) stay; triggers allow exactly one prune and
no restore. Reads serve `{…, payloadPruned: true}` without `signedRequest`.
Coordinator hydration binds the redacted body to the coordinator's own signed
publication receipt, since the sender signature cannot be re-verified.

The same prune also runs, irreversibly and with the same evidence, when the
coordinator expires the request (in the expiry transaction), at the 30-day
ceiling on both homes, and from a transport-only home's periodic sweep once no
device can import or read the opening any more (the ACK rule with an empty
audience). A close wipes every row of the conversation on each home.
`20261104000002_direct_request_opening_pruned_bytes.sql` records the bytes an
opening prune clears from its publication row (`opening_pruned_bytes`, set by
trigger in the prune's own update and never changed), and the terminal prune
adds them to its release, so an early prune no longer leaks retained capacity.
`20261104000010_wipe_returns_whole_retained_charge.sql` corrects the close
wipe's budget accounting. `chat.direct_request_budget.retained_bytes` carries
each retained charge whole and a terminal prune only appends its release, which
`chat.direct_request_effective_budget` subtracts. The wipe deletes a request's
charge together with its release, so it now takes the whole charge off the
counter; taking `charged - released` off left every released byte counted.

`20261104000005_idempotency_payload_erasure.sql` extends O7 to operation
receipts. A `sendMessage` receipt in `chat.idempotency_records` holds its
message's ciphertext in `accepted_request_bytes`, `signing_transcript_bytes` and
`response_bytes`; it is the only receipt endpoint that does (`publishDirectRequest`
keeps no row there, and its signed outcome receipt holds digests and the I13
receipt only). Every prune of that ciphertext on this DS nulls the three columns
and sets `payload_erased_at` in the same transaction: an ACK, sequencer-notice or
30-day prune of the application entry, a close wipe, and the sender's account
deletion (all of its receipts here). The 30-day sweep also erases every receipt
completed before the ceiling, including one whose entry an older release pruned.
The digests, signature, status, event position, JKTs and operation claim stay; the
claim mapping checks an erased receipt against its claim's stored digests and kind.
Erasure is one-way: the table's trigger allows exactly that change, never a
restore or a receipt inserted already erased. An erased receipt still matches
its request by the digests and signature it keeps: the same signed send replays
as its accepted outcome, the entry exactly as `getEntries` serves it
(`payloadPruned`, no `signedRequest`) with its I13 receipt, and executes nothing;
another request under its key is refused with `IdempotencyConflict`.
The P8 `retain_application_ciphertext` plant keeps receipts as well.

The same application-entry prune drops the entry's queued copies that nothing
sends again: every `outbound_queue` row delivered, failed or dead and every
`federation_outbox` job done, failed or dead whose payload names (`"entryId"`) a
pruned entry. A copy still pending or in flight stays whole until it settles: no
receiver accepts a pruned copy (`deliverGroupEntry` and C33 `deliverMessageEntry`
need the signed request, a legacy `deliverMessage` envelope binds its bytes), and
dropping it would break the home's seq contiguity or the predecessor its later
deliveries require. Its settle (delivered, failed, dead, or an outbox job handed
off) then deletes it rather than keeping it for `cleanup_old`. An opening's
queued `deliverDirectRequest` goes with the opening, which no later delivery
needs.
`20261104000008_queued_copy_conversation_indexes.sql` restores the outbound
queue's conversation index (dropped by `20260824000005`) and gives the federation
outbox one, so those prunes and every close wipe find a conversation's rows
without scanning the queues.

`20261103000004_federated_key_package_reservations.sql` backs GET
`blue.catbird.mlsDS.fetchKeyPackage`. One transaction locks the recipient's
principal, then its authorized devices, then one recovery KeyPackage with
`SKIP LOCKED`, which is the order recovery, enrollment, replenishment and
direct requests use. The package becomes `reserved` with a
`chat.federated_key_package_reservations` row naming the requesting DS, so it
never returns to the pool. The reservation mapping accepts that row in place
of an active recovery reservation.

`20261103000002_remote_device_key_history.sql` preserves old signing keys when a
remote device advances its authentication generation. The current key is the
latest activation at or before that generation; a revoked key is never skipped
in favor of an older key. Changed-key activation appends history, while a
same-key rebind advances the device generation without rewriting key evidence.
Historical foreign keys remain valid, and device revocation remains terminal.

## Authenticated remote terminal closes

`20261103000003_remote_close_authority.sql` retains the source DS and its terminal
authority proof alongside the immutable signed close entry. Before any terminal
append or wipe, the receiver requires the stored remote sequencer, or the
retained C33 coordinator and logical participant pair, plus the actor's active
device and current signing generation. Unknown conversation IDs are rejected
without creating terminal evidence.

A group close also carries `DeliverGroupEntryRequest.closeAuthority`, signed
with the sequencer's dedicated `#mls-receipt-1` key. The source derives it only
after the real close has checked the sole remaining active administrator. The
proof binds the exact close entry and final roster digest, allowing a removed
home with an intentionally stale mirror to authenticate the close without
fetching post-removal history. Terminal evidence survives an empty local
audience. Only the identical entry from the retained source is an idempotent
redelivery after the operational wipe; an existing event alone grants no new
close authority. The transition ID comes from the verified signed body.

All group S2S credentials pass inbound peer policy. Relayed application sends
also bind the caller to the participant's home and require an active exact
member device, an unrevoked current key, and the signed authentication generation.

## Direct-request wakes (D2)

A device registers its Push Gateway with `blue.catbird.chat.registerPushGateway`
(`chat.push_gateway_bindings`: opaque `pushKey` and `gatewayUrl`, no native
token). Only the device's home DS wakes it, with `blue.catbird.push.deliver`
`wakeKind=directRequest` carrying coordinates only. A coordinator publication
already commits its durable wake as the `chat.outbox` notification row mapped
by `chat.direct_request_push_events`.
`20261104000006_direct_request_transport_wakes.sql` gives a transport-only
recipient home the same: each `deliverDirectRequest` inbox row enqueues one
`chat.direct_request_transport_wakes` row (outbox lease/retry shape) by trigger
in its insert transaction, and a replayed delivery inserts nothing. Inbox rows
that predate the migration are never woken.
`20261104000007_drop_request_push_bindings.sql` drops `chat.request_push_bindings`
(`updatePushToken`'s token-hash bindings) and its guard function: nothing wrote
or read it, and device revocation no longer deletes from it.
The wake worker's eligibility and live block checks, and its retry limits, are
in [../../SELF_HOSTING.md](../../SELF_HOSTING.md#9-push-wakes-d2).

## Direct-request route answers

`20261104000011_direct_request_route_answers.sql` adds `answered_at` and
`binding_expires_at` to `chat.direct_request_outbound_routes`, the route a
sender home records before relaying `prepareDirectRequest` to a remote pair
coordinator.

- **Unanswered.** The home records the route with `answered_at` NULL and
  `binding_expires_at` set from the signed prepare it authenticated: its
  `signedAt`, plus the 300 seconds a coordinator still admits it
  (`require_fresh_at`), plus the 300-second preparation lease. No preparation
  made from those bytes can be live after that instant. An identical retry
  never changes the value. `check_pair_owner_fence` lets such a route bind its
  pair only while `now < binding_expires_at`.
- **Answered.** When the coordinator answers, or the relay fails for a reason
  no retry cures, the home sets `answered_at` and clears `binding_expires_at`:
  NULL means the route binds its pair permanently. `publishDirectRequest`
  records its route only after an answer, already answered.

A check constraint keeps exactly one of the two columns set. Existing routes
recorded no answer and bound their pairs permanently, so the migration marks
them answered (`answered_at = created_at`); none is left unanswered. Every
route still counts toward the 20-per-hour route quota by `created_at`. The
expiry sweeper deletes an unanswered route an hour after `created_at`, using
the partial index on unanswered rows; it never deletes an answered route.

## Remote lifecycle recovery bindings

`20261113000001_remote_lifecycle_recovery_bindings.sql` retains the immutable,
indexed route and exact response for a leaf-recovery request relayed through a
member's home to the remote sequencer. A transport-only C33 home has no
`chat.conversations` row, so the binding deliberately owns its conversation ID
without a foreign key. Cancellation resolves only by the request-ID primary key
plus actor/device binding; no transport entry scan is involved. Fulfilment,
cancellation, conversation close and the sequencer-issued expiry delete the
route.

The same migration retains each completed relayed lifecycle operation's exact
response for 24 hours, matching direct API idempotency retention. Its primary
key binds actor, device, endpoint and operation ID; a signed-request SHA-256
rejects operation-ID reuse with different bytes. Close removes routing state but
not this bounded replay. The expiry sweeper deletes both due tables.
Raw-file size: `4702` bytes. SQLx SHA-384:
`78975bab32bfaa527ee1233ad49b36956d91fb4c9fef47533365cabd6c98778b50709a57fda8fa5c5933fab388e9e596`.

## Credential and opening evidence contracts

Space credential relays use standard upstream POST JSON
`{space, credentialKey, delegationToken, clientAttestation?, notify?}` against `com.atproto.space.authorizeSpaceSync`. They verify the returned credential's
authority, Space, proof-of-possession key and expiry before formatting the home
response's `expiresAt` in `.xxxZ` millisecond RFC 3339; delegation tokens never appear in the URL.

## Wave 2 multi-device approval and Nov-12 Spaces

`20261114000001_wave2_multidevice_and_spaces_nov12.sql` adds the `'pending_approval'`
lifecycle status on `chat.devices` (`pending_approval -> active | revoked`), the
immutable `chat.device_approvals` provenance table and `blue.catbird.chat.approveDevice`
operation-claim / idempotency / DPoP constraints, and the Nov-12 Space host operational
columns and tables (`prev_space_rev` and `removed_at` on `chat.conversation_space_writers`,
`chat.conversation_space_subscribers`, `chat.managed_space_members`, and
`chat.conversation_space_records`). Raw-file size: `21548` bytes. SQLx SHA-384:
`f32c9403bbcd7ed6bde26a463912c83f0d95aecffcf7040d5622d4db9e1eb6263db4e0d6edaf7062217098eaa13fe133`.

`20261115000001_wave2_r2_archive_watermark.sql` adds the attested Space archive
watermark `archived_through_seq` on `chat.conversation_spaces` and verified per-batch
sequence tracking `archived_seqs` on `chat.conversation_space_records` (`B1`).
Raw-file size: `681` bytes. SQLx SHA-384:
`a9e60f360a413ff8bcc8a2a1cc083de17c569a0f293cc9c52ac21bd9aacaee6ce3e1762894cb54ef259c7d2d3911cb92`.

C33 publication requires the signed `archiveCommitment` for the encrypted
canonical opening frame. The initial entry retains both its genuine `I13`
`sequencerReceipt` and tagged `publicationReceipt`, including on local and
federated reads. The dedicated receipt signer is required; the coordinator's
request-outcome signer and service-auth key are not substitutes.

## Scoped simulation identity caches

Deterministic server clocks own their DID caches as well as generated IDs and
timestamps. Seed DID documents inside `scope_ds_clock` after schema/counter
reset, including both service DIDs in a two-DS run. A shared authentication
middleware instance does not share those scoped caches. Production clocks,
entropy and ordinary cache behavior remain unchanged.
