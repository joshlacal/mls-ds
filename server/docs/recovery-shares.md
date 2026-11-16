# Erasable Labyrinth recovery shares

The delivery service stores one 32-byte share per recovery method. PostgreSQL
holds only AES-256-GCM ciphertext under a separately mounted key-encryption
key (KEK). A successful fetch returns a fresh HPKE ciphertext sealed to the
caller's single-use X25519 public key; neither the share nor the fetch token is
stored in the seven-day `labyrinth.operations` table.
Putting, deleting, and listing shares requires the caller's active,
non-revoked chat device, verified through the account service JWT and signed
device request. A pending device may call only the capability probe and
`getRecoveryShare` to restore before approval. The delivery service no longer
stores Labyrinth device records after the clean-slate migration, so this
surface does not assert a separate physical Labyrinth device binding.
Before a v3 restore, a pending or active device uses the signed
`getRecoveryShareCapabilities` query on its account's resolved home service
to pin protocol version 1 and the HPKE suite. A missing or mismatched
capability is a hard failure.

## Required mounts

With `CHAT_CUTOVER_ENABLED=1`, startup requires:

- `LABYRINTH_RECOVERY_SHARE_KEK_FILE`: a private regular file containing
  exactly 32 raw random bytes. Mount it outside PostgreSQL backups.
- `LABYRINTH_RECOVERY_SHARE_KEK_ID`: a stable, nonempty ASCII token naming
  that key. Live rows carry this ID. Replacing the key requires a separate
  rewrap procedure; changing the bytes under the same ID fails journal
  authentication at startup.
- `LABYRINTH_RECOVERY_SHARE_TOMBSTONE_FILE`: a private, append-only regular
  file on a durable mount outside PostgreSQL backups. Keep the same file
  across database restores. The service takes an exclusive OS lock, so only
  one serving process can use this journal.

For a **new** empty journal, run the `provision_recovery_journal` binary with
those three environment variables before starting the service. It creates
the file with mode 0600, an authenticated header, and an fsync. It refuses an
existing path. Never provision a replacement for a lost journal: a replacement
would lose erasure commitments and the service must remain stopped until the
original journal is recovered.

Startup validates the KEK, the journal MAC and file integrity, and every live
row's KEK ID. It replays all journaled deletions into PostgreSQL before
starting workers or opening the HTTP listener. A bad, missing, or locked
journal fails startup closed.

## Database restore

Stop all serving processes before restoring PostgreSQL. Restore the database
while keeping the KEK and external journal unchanged, then restart the
service. Startup replay clears ciphertext brought back by an older database
backup before traffic resumes. A process that remains running also checks the
journal on every share read and refuses journaled methods, but its database
may retain restored ciphertext until replay runs. The existing restore
scripts do not restart the service or invoke replay themselves; operators
must follow this stop, restore, restart sequence.

Back up the journal and KEK separately with stricter access controls than
the database. Losing either makes v3 recovery unavailable. Restoring a
journal older than a recorded deletion can resurrect a recovery method, so
do not roll the journal back with the database.
