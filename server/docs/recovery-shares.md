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
  file in a private, writable directory on a durable mount outside PostgreSQL backups. Keep the base file and its segment files together across database restores. The service takes an exclusive OS lock, so only
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

Restore into a fresh database, never over the live one with
`pg_restore --clean`. Since `20261104000012_postgres_churn_partitions`,
`outbound_queue` and `federation_outbox` are partitioned, and a
`--clean` restore over them fails (seen on the Nov 26, 2026 deploy).
From a `pg_dump -Fc` dump:

```bash
systemctl stop catbird-mls-server
runuser -u postgres -- dropdb --if-exists catbird      # destroys the current copy
runuser -u postgres -- createdb -O "$DB_OWNER" catbird   # the role in DATABASE_URL
runuser -u postgres -- pg_restore --exit-on-error -d catbird < /root/catbird.dump
# keep the KEK and journal as they are, then:
systemctl start catbird-mls-server
```

To check a dump first, restore it into another name (`createdb
catbird_restored`) the same way and compare. Roll the binary back with
the database: an older binary refuses a database that holds migrations it
doesn't know, and the newer binary would apply its pending migrations again
on start.

## Journal rollover and recovery

The configured path is the original version-1 journal. A running server keeps its exclusive lock on that base file across rotations. At 256 MiB it creates a private sibling named `<base>.segment.<UUID>`, syncs the file and directory, and appends and syncs an authenticated link before acknowledging any erasure in that successor. The limit triggers rollover. Existing valid version-1 journals above the limit are replayed in full and roll forward on their next append.

Take a consistent snapshot of the whole journal directory with the writer stopped or using an atomic filesystem snapshot. Restore the base and every linked segment together. On startup the server verifies each segment header, successor link, and erasure record. A missing linked segment, an invalid header, or a truncated record blocks startup; recover the intact chain from the independent journal backup. A crash between creating the new file and recording its link can leave an unreferenced header-only file. It contains no acknowledged erasures. Keep it with the snapshot. Do not truncate the journal, remove old segments, or substitute an earlier snapshot to make startup succeed. Once the first rollover has occurred, use a server version that reads the segmented format.

Back up the journal and KEK separately with stricter access controls than
the database. Losing either makes v3 recovery unavailable. Restoring a
journal older than a recorded deletion can resurrect a recovery method, so
do not roll the journal back with the database.
