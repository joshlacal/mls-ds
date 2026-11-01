# Self-Hosting `mls-ds` (Clean-Slate Spaces & Post-Quantum Edition)

`mls-ds` is an open, federated MLS Delivery Service and Option A Conversation Space Authority/Host (`atproto#5187`). Any operator can run a self-hosted `mls-ds` instance identified by either `did:web` or `did:plc` and federate seamlessly with `did:web:chat.catbird.blue` and third-party PDSes (including `Swan`).

## 1. Zero-Content Data Line (`G6` / `I14`)

A clean-slate `mls-ds` stores **zero long-term user message history, Labyrinth archive records, or encrypted media blobs**:

- User message history (`blue.catbird.labyrinth.msgEntry`), Labyrinth key envelopes (`blue.catbird.labyrinth.mek`), and encrypted media/avatar blobs live exclusively inside each user's ATProto Spaces (`com.atproto.space.*`) on their own Spaces-capable PDS (`#atproto_pds` + `#atproto_kem`).
- `mls-ds` stores only transient operational MLS delivery state (`chat.entries`), device leaf & post-quantum `X-Wing` KeyPackages (`chat.devices`, `chat.key_packages` with `>= 35d` direct-request lifetime for `C33`), Labyrinth head metadata (`labyrinth.epoch_heads`, `labyrinth.device_keys`, `labyrinth.otc_sessions`), and Option A Space authority metadata (`chat.conversation_spaces`, `chat.conversation_space_writers`, `chat.space_credential_jtis`).
- Once every active participant device acknowledges a `seq` via `blue.catbird.chat.acknowledgeEntries` (or after the `30d` TTL), `mls-ds` nulls `chat.entries.payload_json` while keeping sequence numbers contiguous (`payloadPruned = true`).

## 2. Server Identity (`did:web` or `did:plc`)

Configure `SERVICE_DID` and `SELF_ENDPOINT`:

- **`did:web` example:**
  - `SERVICE_DID=did:web:chat.example.org`
  - `SELF_ENDPOINT=https://chat.example.org`
  - Serve `/.well-known/did.json` advertising `#atproto` (ES256 P-256 verification method for Space credentials and Push Gateway JWTs), `#catbird_receipt` (`I13` sequencer receipt verification method), and service `#atproto_mls` (`AtprotoMlsDeliveryService` at `https://chat.example.org`).
- **`did:plc` example:**
  - `SERVICE_DID=did:plc:<24-char-plc-id>`
  - `SELF_ENDPOINT=https://chat.example.org`
  - Publish `#atproto`, `#catbird_receipt`, and `#atproto_mls` in the PLC directory (`PLC_DIRECTORY_URL`, default `https://plc.directory`).

Users advertise their chosen home `mls-ds` in `blue.catbird.chat.declaration/self` on their PDS.

## 3. Option A Conversation Space Authority & Host (`com.atproto.space.*`)

Every sequencing `mls-ds` automatically hosts the Space Authority and Space Host endpoints for conversations it sequences (`at://{authority_did}/space/blue.catbird.labyrinth.conversation/{conversation_id}-{generation}`):

- `GET /xrpc/com.atproto.space.getSpaceCredential` — exchanges a 60-second single-use PDS delegation JWT (`atproto-space-delegation+jwt`) for a 10-minute PoP-bound `atproto-space-credential+jwt` (`status = 'active'` members only, local or federated).
- `GET /xrpc/com.atproto.space.listRepos` — returns all conversation writers (`status IN ('active', 'left', 'removed')`) in ascending `spaceRev` order while excluding unaccepted `C33` direct-request targets and deleted accounts.
- `GET /xrpc/com.atproto.space.getSpace` — returns Space metadata and latest `spaceRev`.
- `POST /xrpc/com.atproto.space.notifyWrite` — records monotonic writer `spaceRev` heads (`status = 'active'` only) and fans out to registered syncers.
- `POST /xrpc/com.atproto.space.removeWriter`, `registerNotify`, `unregisterNotify`.
- Post-commit revocation & closure webhooks (`notifyCredentialRevoked`, `notifySpaceDeleted`) fan out asynchronously with DNS-pinned SSRF protection (`M-F04`).

Set `SIGNING_KEY_PEM` (or `SPACE_HOST_SIGNING_KEY_PEM`) to the PKCS#8 PEM corresponding to your `SERVICE_DID#atproto` P-256 key.

## 4. `D1` Cross-Server Group Relay & `3A` Stateless Space Relays

Clients talk **only** to their own home `mls-ds`:

- **`D1` Group Mutations:** When a member homed on `ds-b` sends to a group sequenced on `ds-a`, `ds-b` relays via `/xrpc/blue.catbird.mlsDS.relayGroupMutation` (`15 MiB` symmetric body limit, `M-F11`), `ds-a` sequences and attaches an `I13` ES256 `sequencerReceipt`, and `ds-a` fans out `/xrpc/blue.catbird.mlsDS.deliverGroupEntry` to each remote member's home `mls-ds`.
- **`3A` Stateless Space Relays:** Clients call `/xrpc/blue.catbird.chat.relaySpaceCredential` and `/xrpc/blue.catbird.chat.relaySpaceRead` on their home `mls-ds` (under existing OAuth + DPoP auth) to mint remote Space credentials and read `com.atproto.space.{listRepos,getRecord,listRecords,getBlob,listBlobs,getRepo}` from remote writer PDSes without browser CORS or third-party OAuth audience sprawl. Both relays write **zero** operational rows on the home `mls-ds` and preserve `Atproto-Space-Mac` end-to-end.

## 5. `D2` Authenticated Push Gateway Architecture

`mls-ds` holds **zero APNs `.p8` or FCM service-account keys** and **zero raw device push tokens**:

1. Each client registers its raw APNs/FCM token with its app distributor's Push Gateway (`blue.catbird.push.registerKey`, e.g., `nest` for official Catbird builds) and receives an opaque `pushKey`.
2. The device registers `{gatewayUrl, appId, pushKey}` with its home `mls-ds` via `blue.catbird.chat.registerPushGateway` (`CATBIRD-CHAT-PUSH-GATEWAY\0` Ed25519 device signature).
3. On local entry arrival, the home `mls-ds` signs a `#atproto` ES256 service JWT (`lxm = "blue.catbird.push.deliver"`) and POSTs a zero-metadata `wakePayload` (inline `ciphertext` iff `<= 2,200` bytes per `I12`) over DNS-pinned HTTPS `:443`. On `410 Gone` (`PushTokenGone`), `mls-ds` prunes the stale binding immediately.

## 6. Local Multi-DS Smoke Stack

Use `docker-compose.federation.yml` to boot two federated `mls-ds` instances (`ds-a` on `:3001`, `ds-b` on `:3002`), isolated PostgreSQL 16 instances, and a Spaces-enabled `Swan` PDS (`:2583`):

```bash
docker compose -f docker-compose.federation.yml up --build
```
