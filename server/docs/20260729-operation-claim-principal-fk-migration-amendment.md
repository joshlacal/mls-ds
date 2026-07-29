# Operation-claim principal-FK migration amendment

Date: 2026-07-29  
Sealed parent: `cbf9d784fe28257561735e4d37ec7f0af7deabfb`  
Migration: `20260728000003_defer_operation_claim_principal_fk.sql`

## Decision

Amending `00003` in place is safe in this exceptional pre-application case.
The sealed source was syntactically unappliable on PostgreSQL because both
catalog probes used the keyword `constraint` as an unquoted relation alias.
PostgreSQL rejected the first `DO` block before either `ALTER TABLE` statement,
so those exact bytes could not have completed successfully.

The amendment changes only that alias and its qualified references from
`constraint` to `constraint_row`. It does not change a table, constraint,
predicate, lock, error code, transaction boundary, migration version, or
filename.

## Pre-amendment evidence

The original frozen bytes were:

- Length: `6570` bytes.
- SQLx SHA-384:
  `67cd6f9033b97d206f478a2baeee31dbd337a4e6d5e3bb5158467afc95064b91a6a81b202e11eae86f8d909de040b467`.

The authorized dedicated local database was
`catbird_chat_protocol_test_20260722`. It had no other sessions. Its Task 9
SQLx-ledger range was empty because the prior executor had staged the schema
manually through `00002`. Source-state checks showed:

- `chat.operation_claims` existed.
- `operation_claims_principal_fk` was validated, non-deferrable, and initially
  immediate, which is the `00001` precondition and proves `00003` had not
  changed it.
- `chat.operation_claim_completeness_cutover` did not exist, proving `00004`
  had not applied.

The exact original source was then executed atomically:

```sh
psql -X -1 -d catbird_chat_protocol_test_20260722 \
  -v ON_ERROR_STOP=1 \
  -f server/migrations/20260728000003_defer_operation_claim_principal_fk.sql
```

PostgreSQL rejected it:

```text
ERROR:  syntax error at or near "constraint"
LINE 18:         constraint.oid,
```

The command failed at migration line 92. `-1` and `ON_ERROR_STOP=1` kept the
probe atomic; a follow-up catalog query again showed the exact immediate FK and
no cutover table. No `00003` effect or SQLx ledger row survived.

## Amended byte freeze

- Length: `6722` bytes.
- SQLx SHA-384:
  `d42c64d98f6af2042ecf5d08b925aaadae01efcd7d1f6d1887c5485e0862d80304bb9ba54506a1876eba54b505d4114a`.
- `openssl dgst -sha384` and the Rust `Sha384::digest(include_bytes!(...))`
  source gate agree.

`chat_protocol_operation_claims.rs` now rejects either form of the reserved
alias, requires both catalog probes to use `constraint_row`, freezes the exact
new byte length and SHA-384, and requires the migration inventory documentation
to carry the same freeze.

## Verification

Source and compile gates:

```text
cargo fmt --all -- --check
PASS

cargo test --test chat_protocol_operation_claims \
  enrollment_claim_fk_deferral_migration_is_frozen_fail_closed_and_narrow \
  -- --exact
PASS: 1 passed

cargo test --test chat_protocol_operation_claims \
  operation_claim_rollout_inventory_orders_deferral_before_activation \
  -- --exact
PASS: 1 passed

cargo check
PASS
```

`cargo check --all-targets` was also attempted. It remains red on unrelated
existing test-target compilation defects, including test builds that hide
`repository::core`, `repository::execution_context`, and
`repository::relationship` behind `cfg(not(test))`, plus existing
`ExecutionContext` fixtures missing `metadata_avatar`. The focused amended test
target compiles and passes, and the normal server compile gate is green.

## Fresh local migration proof

The coordinator paused the other Task 9 executor and authorized recreation of
only the dedicated local database. A final session query found zero users, and
the database was recreated with:

```sh
dropdb --if-exists catbird_chat_protocol_test_20260722
createdb catbird_chat_protocol_test_20260722
PGOPTIONS="-c chat.operation_claim_activation_approved=handlers-and-legacy-apis-sealed" \
  DATABASE_URL="postgres://localhost/catbird_chat_protocol_test_20260722" \
  sqlx migrate run
```

The production SQLx migrator applied the complete fresh migration set and
reported all four Task 9 migrations installed in order through `00004`.
The retained database ledger records:

| Version | Success | SHA-384 |
| --- | --- | --- |
| `20260728000001` | `true` | `fd71f2eb5235226371f113b5738b752b27e901b72810e9ec1e1f201e979606e0b09a16be087103e4146b4fb9f8bdff8f` |
| `20260728000002` | `true` | `a5c0225818e350415e0ad3a88c5016d621a75bb64563f97023de9d27498cf113d8ef9d95c98621036c15ac3398dbee17` |
| `20260728000003` | `true` | `d42c64d98f6af2042ecf5d08b925aaadae01efcd7d1f6d1887c5485e0862d80304bb9ba54506a1876eba54b505d4114a` |
| `20260728000004` | `true` | `d7f92b96421a33f0385789f44c0fc2986321e8c7487e79e96c9c4880a1853e4c9d7d32f36bf3dfd22ff07a1cd6fb1674` |

Postflight catalog evidence:

- `operation_claims_principal_fk` is validated, deferrable, and initially
  deferred.
- Its definition is exactly
  `FOREIGN KEY (principal_did) REFERENCES chat.principals(user_did) DEFERRABLE INITIALLY DEFERRED`.
- Both `chat.operation_claims` and
  `chat.operation_claim_completeness_cutover` exist.
- The activation GUC was absent on the verification connection.
- `sqlx migrate info` reported `00001` through `00004` as installed.

The dedicated database was retained in this fully migrated local-only state.
No G6 execution, remote database access, deployment, commit, or production
cutover occurred.

## Owned diff

Only these files belong to this amendment:

- `server/migrations/20260728000003_defer_operation_claim_principal_fk.sql`
- `server/migrations/README.md`
- `server/tests/chat_protocol_operation_claims.rs`
- `server/docs/20260729-operation-claim-principal-fk-migration-amendment.md`

There is no protocol or schema-authority semantic change. Any later proposal
that changes those semantics requires a fresh independent review.
