# Conversation Space storage and authority policy

This change lets each sender retain one encrypted batch in its own repository inside a conversation Space while the MLS delivery service retains the reference, authenticated order and redactions. Existing conversations stay on DS storage. New conversations choose their placement once in the creation transaction. This is local integration infrastructure: no hosted authority account, production Space or production service has been provisioned by these changes.

The governing archive design is [Labyrinth's MLS DS backend](../../labyrinth/docs/MLSDS_BACKEND.md), with the immutable-placement and authority-integration decisions in [DECISIONS.md](DECISIONS.md). The production lifecycle still requires operator deployment, a provisioned authority account, and the corresponding Swan issuer configuration.

## Configuration and creation

With no `LABYRINTH_CONVERSATION_SPACE_AUTHORITY_DID`, new local conversations persist `placement=mlsds` and a UUID storage generation. If that variable is present, `LABYRINTH_CONVERSATION_SPACE_ISSUER_READY=true` must also be explicitly set after connecting the issuer's live policy lookup. Authority configuration without that readiness acknowledgement fails conversation creation. Invalid authority DIDs also fail creation.

When enabled, creation persists `placement=space`, a random UUID generation, and exactly `at://<authority DID>/space/blue.catbird.labyrinth.conversation/<generation>`. The standard native creation path and encrypted-request publication path initialize storage in their own existing transaction. The latter cannot archive through Space while any participant remains pending: the accepted-participant policy remains a gate. The migration pins every existing conversation to DS storage; it never migrates ciphertext.

The configuration does not create or verify a live hosted account or Space. The readiness acknowledgement is an operator deployment gate, not proof of provider interoperability. Missing placement returns `StorageNotConfigured`; legacy batch APIs reject a Space placement. There is no placement update API. The authority calls `deleteSpaceGeneration` to invoke the internal terminal transition for the exact stored generation; it cannot undelete or replace that generation.

## Sender and reader APIs

The signed Labyrinth gateway serves `getThreadStorage`, `appendSpaceBatch`, and `listSpaceBatches`. Existing service JWT, exact endpoint binding, device proof, key revocation locks and operation replay protection apply unchanged. Space admission additionally requires the caller's exact current MLS leaf/key/generation, accepted membership and MEK generation/sequence bounds. Sender timestamps are filters only: the DS stamps its own per-conversation sequence and last committed chat sequence under the conversation lock.

The sender supplies the typed batch transiently so the DS can verify its canonical DRISL DAG-CBOR/SHA-256 CID. Binary values use CBOR byte strings. The DS retains only the source Space, generation, author DID derived from authentication, record key, CID, message metadata and ordering. A database trigger forbids ciphertext in a Space metadata row. The same source pointer and CID replay the original receipt across operation IDs; changing the CID at that pointer is a conflict.

The existing `batches` and `batch_items` metadata path is intentionally reused. It preserves quota accounting for retained bytes, signed per-message redactions, account deletion, attachment invalidation and the durable deletion outbox. Space listings include required `redactions` and `itemCount`, so clients can recognize a fully redacted batch even after the sender's source record is purged. Partial redaction still requires authenticating the original referenced CID before overlaying tombstones.

Remote conversations and conversations with any remote or pending current participant return explicit `StorageNotConfigured` for Space operations. The original DS-hosted and encrypted-request paths continue using their existing policies. No federation or pending-request credential authorization is inferred from a replicated leaf.

## Swan authority lookup

The canonical Space credential request remains unchanged. Swan verifies the user's canonical delegation, then sends a separate authority-authenticated request:

```
GET /xrpc/blue.catbird.labyrinth.getSpaceMembership?space=<exact Space ref>&user=<delegated DID>
Authorization: Bearer <authority service JWT>
```

The JWT issuer must be the exact authority DID in the immutable stored Space reference. The audience is the configured MLS service reference, `lxm` is `blue.catbird.labyrinth.getSpaceMembership`, `jti` is unique, and `exp-iat` is at most 60 seconds. User device headers are not used here. The DS independently verifies the issuer signature, audience, endpoint, freshness, replay and rate limits.

A grant response is `{space,generation,user,chatGeneration,chatSeq}`. Its membership must be accepted and current, with at least one current-generation leaf whose exact registered key is active and unrevoked. Deleted generations, unaccepted participants, removed members, revoked keys and mismatched authorities fail closed. The policy locks the chosen registered device and key before the conversation head, matching device revocation, then revalidates the same exact leaf under the head lock. A removal or generation change between those steps fails closed without acquiring more identity locks. Responses carry `Cache-Control: no-store`. The issuer must bind all returned identity fields to its request and must not cache a positive grant. This authorizes access to encrypted Space bytes; it does not replace the client's MLS decryption and history authorization.

## Terminal generation deletion

The authority first persists a pending-deletion state that refuses new credentials. It then sends `POST /xrpc/blue.catbird.labyrinth.deleteSpaceGeneration` with `{space,generation}` and the same standard authority service authentication, with `lxm` bound to that procedure. The DS validates the exact authority and immutable binding, serializes against conversation admission, commits the terminal state, and returns `{space,generation,deleted:true}`. Concurrent calls and later fresh-JWT retries return the same result. Wrong authorities and mismatched generations cannot delete the binding.

Once terminal, policy, placement discovery, reference reads, wrapped-key lookup (`findMeks`), writes and attachment-liveness checks fail closed with `SpaceDeleted`. Swan may acknowledge deletion only after the DS succeeds and local terminal state plus standard deletion notifications to registered recipients are durable. A failed DS request leaves the authority pending and credential issuance disabled; retries cannot create another generation. Recipient notification handling must reject a previously cached credential after receiving the terminal notification. Local runtime verification of these separate stages is recorded in [the verification report](SPACE_CONVERSATION_STORAGE_VERIFICATION.md); this contract alone is not a production lifecycle qualification.

## Local verification

`server/tests/labyrinth_space.rs` uses disposable PostgreSQL databases and the actual authenticated Axum routes. Its deterministic encrypted-byte fixtures test admission and persistence only; they do not assert live PDS publication or successful MLS decryption. The normal suite covers reference/CID binding, replay, per-MEK reads, server ordering, generation bounds, redaction, terminal deletion, SQL immutability, and the authority policy route.

The opt-in `live_policy_fixture` test exposes the actual policy router on an ephemeral loopback TCP port for Swan integration. It writes `ready.json` with the origin, audience, authority DID, user DID, valid/removed/deleted/deletable Spaces and paths to generated test-only P-256 keys. The raw key files are created with mode 0600. All accounts, keys and databases are local fixtures. The fixture refreshes its same ephemeral public DID documents in the test cache every minute and checks the authenticated membership route, because these disposable DIDs do not exist in the public directory. Production authentication and its five-minute cache lifetime are unchanged. Write a `stop` file into the explicit fixture directory to stop the server; it also expires after one hour.

```sh
TEST_DATABASE_URL=postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722 \
SERVICE_DID=did:web:labyrinth-test.invalid \
CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
CMAKE_POLICY_VERSION_MINIMUM=3.5 \
cargo test -p catbird-server --no-default-features --features test-support \
  --test labyrinth_space -- --test-threads=1
```

The test harness validates the loopback maintenance URL and mints a separate database per test; it does not migrate or reset the shared database named in that URL. Production deployment, production migration, live-account authority issuance, remote conversation support and actual PDS lifecycle delivery remain separate qualifications.
