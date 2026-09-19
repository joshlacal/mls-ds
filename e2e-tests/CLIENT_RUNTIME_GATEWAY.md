# Local client runtime gateway

This debug-only launcher lets installed development clients exercise the real delivery-service router with synthetic local sessions and identities. It starts the existing guarded PostgreSQL/service fixture, a strict synthetic DID/PDS facade, and a loopback TLS gateway. Client MLS keys remain client-owned; the gateway retains synthetic service-JWT signing keys only in memory. This is a local qualification tool, not a replacement login service or permission to activate production requests.

Governing plan: [encrypted message requests](../../docs/superpowers/plans/2026-09-19-encrypted-message-requests.md). Coordinate the guarded database window with the integration steward before starting; stop the launcher before releasing that window.

## Build and start

From `mls-ds/`:

```sh
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --locked --manifest-path server/Cargo.toml --features test-support --bin encrypted_request_server_fixture
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --locked --manifest-path e2e-tests/Cargo.toml --features local-runtime-fixture --example client_runtime_gateway
```

The gateway is excluded unless `local-runtime-fixture` is enabled and deliberately fails compilation without debug assertions. It accepts one bounded JSON configuration from stdin, then waits for Ctrl-C or its lifetime (maximum one hour). `output_dir` must be absolute and must not already exist. `cors_origin` must be an exact loopback HTTP(S) origin, without a trailing slash or path.

```sh
printf '%s' '{"output_dir":"/tmp/catbird-client-gateway-run-001","cors_origin":"http://127.0.0.1:5173","lifetime_seconds":1800}' |
  REQUEST_TEST_DATABASE_URL=postgresql://127.0.0.1:5432/catbird_direct_requests_test_20260919 \
  REQUEST_SERVER_FIXTURE_BINARY="$PWD/target/debug/encrypted_request_server_fixture" \
  e2e-tests/target/debug/examples/client_runtime_gateway
```

The database must already have the reviewed baseline and additive migrations. This launcher uses the exact guard and does not migrate another database. All listeners bind `127.0.0.1`. Startup writes a new mode-0700 directory and mode-0600 files. Stdout contains only `{"manifest":"/absolute/path/manifest.json"}` after TLS/session checks pass. Never print, copy into reports, or commit `sessions.json`.

## Public manifest and protected sessions

`manifest.json` contains:

```json
{
  "fixtureOnly": true,
  "origin": "https://gateway-<run>.request-fixture.catbird.blue",
  "corsOrigin": "http://127.0.0.1:5173",
  "caPem": "/absolute/output/ca.pem",
  "tlsCertificatePem": "/absolute/output/tls-certificate.pem",
  "tlsSpkiSha256": "<base64 SHA256 of exact TLS leaf SubjectPublicKeyInfo>",
  "hosts": {"<synthetic-host>": "127.0.0.1:<tls-port>"},
  "accounts": [{"label": "alice", "did": "did:web:alice-<run>.request-fixture.catbird.blue", "deviceId": "<reserved-native-device-uuid>"}]
}
```

There are Alice and Bob accounts. The host map includes their DID/PDS hosts, the gateway, `chat.catbird.blue` for the signed receipt DID document, and `public.api.bsky.app` for the service's synthetic relationship source. `deviceId` is reserved for native preseeding; a browser's real enrollment generates its own UUID and must use the returned service device identity instead.

`sessions.json` contains the same labels/DIDs/reserved IDs plus an opaque `session` per account. Load this file only into an isolated debug client profile. Requests authenticate using `Authorization: Bearer <session>` or the `catbird_session` cookie. Conflicting bearer/cookie identities fail. `GET /auth/session` returns the authenticated synthetic DID and handle; authenticated `app.bsky.actor.getProfile`, `getProfiles`, `searchActors`, `searchActorsTypeahead`, and `app.bsky.graph.getBlocks` provide bounded fixture-only responses. Profile search returns at most the two synthetic accounts; repeated `actors` parameters are supported for `getProfiles`.

Client transport must preserve the logical HTTPS hostname for TLS/SNI verification while connecting through the manifest mapping, trust only this fixture CA in this debug client, reject unlisted hosts/redirects, and never fall back to public network. Android emulator connections replace the map's IP with `10.0.2.2`, retaining the mapped port and original TLS hostname. Do not install the CA in system trust or alter production trust. Actual browsers need a dedicated test browser context/runner with the equivalent exact host and fixture-CA mapping; this launcher does not configure a user's browser.

## Native public-key preseeding

Generate the client's signing key in its normal protected store for `<did>#<reserved-deviceId>`. Send only the public raw 32-byte Ed25519 key:

```text
POST <origin>/fixture/enroll
Authorization: Bearer <opaque session>
Content-Type: application/json

{"device_id":"<reserved-deviceId>","signature_public_key":"<canonical standard base64 raw32>"}
```

The response is `{did,deviceId,seeded:true}`. The helper uses the guarded existing native-fixture seeder and publishes the matching public PDS declaration. Different keys for the same identity are rejected; no private key enters the gateway. This path is explicitly **preseeded native authority**, not evidence that native enrollment itself ran.

## Real client enrollment

Do **not** call `/fixture/enroll` when qualifying actual enrollment (browser or native). Initialize its protected store/session and let its real enrollment method generate the UUID/key/packages and signed `blue.catbird.chat.enrollDevice` body. The authenticated gateway checks exact account, generation-zero enrollment, canonical UUID, and public key encoding; it publishes only that account's public `blue.catbird.chat.device` declaration before forwarding the original body unchanged. The real service must verify its signature/package/DID/PDS authority and create the absent device. No database seeding occurs on this path.

Public `com.atproto.repo.listRecords` requires the exact DID host/repo and device collection. Authenticated `putRecord` permits only the device declaration shape, immutable device keys, and null/absent `swapRecord`. Public relationship data is limited to these synthetic accounts. Canonical XRPC bodies/queries are forwarded unchanged with a scoped service JWT; the response is streamed through a 32-MiB bound before buffering. Incoming bodies are bounded at 16 MiB, queries at 8 KiB, configuration at 16 KiB, and device declarations at 16 per account. CORS accepts only the configured origin, explicit allowed headers, and GET/POST preflights.

## Evidence and remaining limits

Startup checks actual untrusted-CA rejection, wrong-hostname rejection, missing-session rejection, wrong-origin rejection, and account-exact session restoration before publishing readiness. Unit tests cover config/key/query guards, immutable public declarations, and unauthorized/origin-mismatched writes. Neither substitutes for a client-specific real enrollment/request/accept/reply trace.

The opt-in fixture subscription endpoint is exactly `wss://chat.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents`. Native clients may omit `Origin`; any supplied `Origin` must occur exactly once and equal `cors_origin`. Browsers supply that header. Origin is not authentication: every connection still requires the actual service-issued one-use ticket. The TLS relay validates the upgrade and this origin policy, then tunnels the original ticket/cursor to the actual shipping service route. It does not mint or rewrite tickets. Bidirectional buffers and idle/lifetime limits are bounded, and disconnect closes both sockets. A retained smoke passed three real empty inventories with identical session/cursor/scope `[1,2]`, a real ticket handshake (101), and same-ticket replay rejection (400). This proves the transport/ticket seam with a preseeded synthetic device, not MLS event delivery or client UI behavior. UI asset serving is not implemented. Synthetic session/PDS/relationship authority is deliberate and must be disclosed separately from real MLS cryptography, delivery-service authorization and database effects. No production DNS, trust store, credentials, service or database is changed.
