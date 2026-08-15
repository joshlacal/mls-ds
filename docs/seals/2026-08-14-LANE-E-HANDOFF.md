# Lane E handover — 2026-08-14

Written for the successor who picks up the finding-3 wedge. Read this before
resuming. Everything below was verified by execution unless it says otherwise.

Workspace: `mls-ds-lane-e-ws`, a jj workspace off `main` @ `425e149f`.
Unpushed. `main` and `clean-chat-c2` were never moved.

---

## 1. What is sealed (7 commits, oldest first)

| commit | what |
|---|---|
| `7025a9b0` | repair two stale lane-tip test guards (no production change) |
| `330475eb` | finding 5a — stop rejecting the schema's mandated touching interval boundary |
| `47f8d99b` | finding 2 — reject a commit metadata re-encryption of the wrong length |
| `26b7b86c` | bring the C2 seal doc into the repo with dated addenda |
| `01abbd7f` | finding 5b — settle the entry_intervals contradiction on the frozen spec |
| `e524af38` | apply cargo fmt (mechanical) |
| `ca10120e` | give the frozen crypto-wire corpus a durable in-repo home |

Suite state at the tip, all `--test-threads=1`:

```
executor               183/0/1      state_machine          145/0
wire                    38/0        snapshot                10/0
g7_entitlement         172/0/20     transition_repository  123/0/1
inventory              131/0/1      conversation_substrate 169/0/128
production_cfg           9/0/16     (--no-default-features --features chat-protocol-production-proof)
```

Counts rise in several suites because tests added to `state_machine.rs` run in
every harness that `include!`s it. The g7 IGNORED set also runs: 20/0.

---

## 2. Finding 3 — the wedge. THE MAIN OUTSTANDING WORK.

### The ruling, verbatim

> Josh has ruled on the finding-3 wedge: BOTH shapes.
> (b) `revokeDevice` terminalizes the revoked principal's pending reset requests.
> (a) a lapsed-row expiry/disposal route that binds to the immutable signed bytes
> and the row's RECORDED authority rather than live device state.
> **HARD CONSTRAINT: `activateReset` keeps FULL strict live-authority
> verification, unchanged. The relaxation applies to expiry/disposal only.**
> No sweeper that composes the existing seal.

Sequencing: repro first (it is also the acceptance evidence) → (b) → (a) → flip
the repro tests from wedge-documentation to desired-state assertions. Seal (b)
and (a) as separate commits with the ruling recorded in each message.

### The trace

`prepare_reset_read_set_inner` (`server/src/chat_protocol/repository/reset.rs`,
~2290) does, for BOTH endpoints:

```rust
let pending_row = load_locked_pending_row(transaction, conversation_id).await?;
let pending = match pending_row {
    None => None,
    Some(row) => Some(seal_pending_reset(row, ...)?),   // unconditional, and `?`
};
```

`seal_pending_reset` (~2840) re-verifies the ORIGINAL requester's live device:

```rust
if device.auth_generation() != row.requester_auth_generation
    || key.enrollment_auth_generation() != row.requester_auth_generation
    || device.status() != "active"
    || device.revoked_at().is_some()
    || key.revoked_at().is_some()
{
    return Err(ResetRepositoryError::DeviceOrKeyDrift);
}
```

Therefore, once a pending reset row's original requester is revoked or bumps
`auth_generation` via rebind:

1. `activateReset` fails with `DeviceOrKeyDrift`.
2. `requestReset` — the documented rescue, which would classify the row
   `ExpiredReplacement` and clear it — fails with the SAME error BEFORE reaching
   that arm. The rescue is unreachable.
3. `load_locked_pending_row` selects by `conversation_id` ONLY, so this blocks
   EVERY principal, not just the original requester.
4. Nothing else clears it. Revocation does not terminalize pending resets, and
   `terminalize_locked_reset_request` has exactly ONE caller (reset.rs:1285),
   downstream of the failing seal. There is no reset arm in `expiry_sweep.rs`.

`revokeDevice` is a live endpoint, so the trigger is routine. Result: permanent,
conversation-wide loss of reset capability. The C2 seal filed this as
"inconsistency, not a wedge" — that classification is wrong.

**Why the obvious fix fails:** a sweeper arm composing the Request route
(`load_locked_pending_row` → `seal_pending_reset(Request)` →
`terminalize_locked_reset_request`) hits the identical seal and fails on exactly
the rows that need sweeping. Hence fix (a)'s "must NOT compose the live seal".

### The blocker — read this before trying anything

The ordered DB-backed reproduction CANNOT RUN as things stand:

- `chat.reset_requests` in `catbird_chat_protocol_test_20260722` contains ZERO
  rows (verified by direct query, not inferred).
- Consequently all 17 `#[ignore]`d tests in
  `server/tests/chat_protocol_reset_repository.rs` fail identically at `:601`
  with `"full aggregate-hydratable active Reset fixture"`.
  Measured: default `120/0/17`, `--ignored` `0 passed / 17 failed`.
- The "ALICE reset fixture corpus" those tests name does not exist in the
  shared database.

**Do not repeat the g7 shortcut.** In `chat_protocol_g7_entitlement.rs` the
`#[ignore]` reasons were merely STALE — those fixtures bootstrap their own
per-run database, and all 20 ran once tried (that is how 5b was verified). The
reset suite is different: it is genuinely blocked on missing data. Trying
`--ignored` there again will just reproduce 17 failures.

### Scouted unblock (not implemented)

Add a pending-ONLY fixture to `tests/common/executor_seed.rs`.
`seed_private_genuine_reset` (:5629) already does:

```
seed_dynamic_genuine_two_leaf_graph(pool)
  → commit_dynamic_reset_request(pool, graph, request_at)   // :3895
  → commit_dynamic_reset_activation(...)                    // consumes it
```

`commit_dynamic_reset_request` inserts a real `chat.reset_requests` row with
genuine `signed_request_bytes`, `signing_transcript_bytes`, `request_digest` and
`signature`. Stopping BEFORE the activation call leaves a genuine PENDING row in
a self-bootstrapping per-run database. Roughly twenty lines, no new crypto.

**Never seed the shared database.** Other lanes share it; the per-run isolated
DB is the pattern that works here.

### Ratified repro shape

Start with the child-module variant — it is the decisive core and needs no
second-principal admission:

> include `reset.rs` and drive `load_locked_pending_row` + `seal_pending_reset`
> directly, proving `DeviceOrKeyDrift` for BOTH `ResetPreparationKind::Request`
> and `::Activation` on a revoked AND a rebound requester.

`reset.rs` has no `#[cfg(test)]` prohibition (unlike `read_authority.rs`, see §4),
so either an in-src test module or a child module inside a harness's include
block will work.

Then the endpoint-level variant, enabled by the pending-only fixture, adding
"nothing in the schedule clears the row". Both are wanted; child-module first.

Full repro spec, verbatim from the ruling:

> pending reset row → original requester revoked via the real `revokeDevice`
> path (or `auth_generation` bumped via rebind — cover both variants) → prove
> `requestReset` AND `activateReset` both return `DeviceOrKeyDrift` for a
> DIFFERENT principal in the conversation → prove nothing in the schedule clears
> the row.

Seal these as ignored-by-default DB-gated tests **clearly labelled wedge
documentation, not desired-state assertions**. After (b) and (a) they flip:
after (b), revocation-while-pending leaves no wedged row; after (a), a
pre-existing wedged row (created by bypassing (b)'s path, or via the rebind
variant) is expirable by a different principal's `requestReset`.

---

## 3. Traps that cost time in this lane

**The `git` shell function is BROKEN here.** It calls a jj-guard python script
with an unset `$JJ_GIT_GUARD_SCRIPT`, so every `git` invocation prints an error
and returns nothing — a silent-success trap. Use `/usr/bin/git`, and pass an
explicit start commit because `HEAD` is detached at an unrelated commit.

**Never end a cargo command with `| head`/`| tail`.** The pipeline returns the
last stage's exit code. A compile failure was masked as `exit 0` this way, twice.
Always check for the `test result:` line — its ABSENCE means the target did not
build or was truncated, which is not the same as "fewer failures".

**Absence proofs need a positive control.** A grep truncated by `head` produced a
false "no guard pins this" conclusion here; a guard did pin it.

**`rg` respects gitignore.** A workspace-wide sweep for the corpus path returned
ONE hit and looked conclusive; the sub-repos were being skipped. Re-run per repo
with `-uu` (excluding `target/`, `.jj/`, `.git/`). That single mistake is the
difference between the two reference sites first reported and the ten that exist.

**Take a frozen hash AFTER formatting, never before.** Repointing the corpus
paths shortened lines enough that rustfmt reflowed three files, `executor_seed.rs`
among them. The hash was pinned, the format then invalidated it, and it had to be
re-pinned a second time to the post-format bytes. Order is: edit → `rustfmt` →
`shasum` → pin → run the suites.

---

## 4. Guards you must not casually break

- `read_authority.rs` must contain ZERO `#[cfg(test)]`. Asserted by
  `b_auth_read_authority_privacy_and_call_graph_guards`, beside asserts that the
  two read-admission budgets have exactly one constructor each. It stops a
  test-only backdoor minting read authority. To test private items there, put a
  child module inside the harness's own `pub mod read_authority { include!(…) }`
  block — a descendant module reaches its ancestor's private items, so no
  production visibility change is needed.
- `FROZEN_EXECUTOR_SEED_SHA256` pins `tests/common/executor_seed.rs` at TWO
  assertion sites in `chat_protocol_g7_entitlement.rs`. Any edit to that file
  requires re-pinning both, in the same commit, with the reason recorded.
  Current value `ba8aa803…`, pinned to POST-rustfmt bytes.
- `tests/chat_protocol_schema.rs` is a complete-source authority guard that
  hashes ITS OWN bytes (byte offsets `83449..83830`, `raw_sha256`,
  `tokens_sha256`, `body_sha256`). It is deliberately EXCLUDED from
  `cargo fmt`: formatting it took the suite from 27/2 to 24/5. Re-sealing those
  digests is substantive, not mechanical. `cargo fmt --all -- --check`
  therefore still reports exactly this one file, by design.

### Two PRE-EXISTING schema failures (not caused by this lane)

`chat_protocol_schema` is `27 passed / 2 failed / 3 ignored` both before and
after every change here. Verified at `425e149f` itself, not assumed:

- `fixed_target_helper_uses_one_closed_exact13_migrator_and_unchanged_api`
  asserts a setup-caller inventory of 226 while the tree contains 229. Counting
  `setup_chat_protocol_db(` at `425e149f` also gives 229. Same stale-constant
  class as the executor-seed hash repaired in `7025a9b0`.
- `operation_claim_completeness_cutover_matches_durable_classification` fails on
  shared-database state: "expected exactly one completeness cutover row,
  observed 0". Environmental, not source.

---

## 5. Crypto-wire corpus — DONE, with one thing left

Seal `ca10120e`. All 22 files committed at `server/tests/fixtures/crypto-wire`,
byte-identical to the generated originals (`diff -r`), 160,388 bytes total.

The required sweep found **TEN sites across FIVE Rust files**, not the two first
identified — `rg` respects gitignore, which hid the sub-repos on the first pass:

| file | sites |
|---|---|
| `tests/common/executor_seed.rs` | `:148` `include_str!`, plus 2 `.join` |
| `tests/chat_protocol_conversation_substrate.rs` | 4 `.join` |
| `tests/chat_protocol_snapshot.rs` | 1 |
| `tests/chat_protocol_state_machine.rs` | 1 |
| `tests/common/frozen_public_state.rs` | 1 |

All now `CARGO_MANIFEST_DIR`-relative; no Rust path traverses out of the repo.
Proven by execution: with the workspace-root symlink shim MOVED ASIDE entirely,
executor 183/0/1, snapshot 10/0, state_machine 145/0 and
conversation_substrate 169/0/128 all stayed green.

`tests/mls_chat_lexicon_contract.py` is deliberately NOT repointed and is
documented in place. It resolves `STACK_ROOT / "docs/…"` and is cross-stack by
construction (it also reads canonical lexicons from the PetrelCatbird sibling
repo); it checks artifacts where the GENERATOR writes them. Keeping the two
paths distinct makes it a drift detector for a regeneration that has not been
re-snapshotted into the repo.

**The workspace-root symlink shim STAYS**
(`Catbird+Petrel/docs/generated-artifacts/mls-chat-v1/crypto-wire`). The Python
contract test resolves through it, the generator's write home does not move,
and the canonical `Catbird+Petrel/mls-ds` checkout still needs it until this
lane lands on `main`. It is gitignored (root `.gitignore:50`) so it cannot
pollute a commit.

Durability upstream, in `.codex-workspaces/mls-v2-stack`: the last untracked
artifact `creation-signed-request.cbor` is now committed (`2cfb6fcf`,
path-restricted — that working copy carries ~944 files of another actor's
unrelated uncommitted work, left untouched), and the local bookmark
`crypto-wire-corpus-keep` pins that commit so the lineage no longer depends on a
working-copy pointer. Never pushed; `main` there was not moved.

---

## 6. Still owed

- The finding-3 repro, then fix (b), then fix (a). See §2.
- Addenda to `docs/seals/2026-08-13-C2-SEAL.md` recording the 5b ruling, the
  finding-3 ruling and outcome, and the corpus ruling. Held back deliberately so
  the addendum records outcomes rather than in-progress state — write it once
  finding 3 is resolved.
- Finding 4 (`run_fulfillment_scenario` cannot hydrate through the production
  aggregate reader) — untouched. Test-fidelity gap, needs production-hydratable
  fixtures.
- The 19 handler stubs — a separate charter. Inputs already produced: the 5a fix
  (a hard prerequisite, `getEntries` would have returned `Invariant` for every
  reset activator on day one) and the client paging invariants, where
  `nextAfterSeq` is STRICT equality with the greatest returned seq, `hasMore` is
  computed over caller-VISIBLE entries after filtering, and an empty page with
  `hasMore=true` is contradictory.
- 83 leaked `chat_exec_*` databases, 664 MB, plus shared-DB residue (12
  dispositions, 391 conversations, 238 events, 175 welcome deliveries). Left in
  place by decision. If another suite hardcodes a globally-unique column, fix
  that suite the way `7025a9b0` did (take `max(...)+1`) rather than purging.
