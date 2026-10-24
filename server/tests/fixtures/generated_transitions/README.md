# Generated Swift submitTransition fixtures

These files exercise the actual generated `PetrelCatbird` Swift serializer for
all five `blue.catbird.chat.submitTransition` variants. They expose the nested
`$type` tags and `{"$bytes": ...}` representation emitted by real SDK values.
The original server signing and fingerprint corpora remain unchanged. Server
decoder, signature, handler, persistence, and replay tests consume these exact
bytes separately.

The maintained producer is a small SwiftPM executable in `SwiftProducer/`.
It uses the sibling Petrel revision
`e115236537041a900ec971be05185a70cca73e8a` and PetrelCatbird revision
`8672c80ffeb3b9cfbdb6bd98f66efa09b13fe0db`. The reproduction driver compares SDK
sources and manifests against those revisions, rejects untracked SDK sources,
and verifies every SwiftPM SDK dependency edge resolves to the selected sibling.
It never edits or regenerates either SDK.

From the `mls-ds` repository root, with `Petrel` and `PetrelCatbird` as siblings:

```sh
python3 server/tests/fixtures/generated_transitions/reproduce.py --check
```

`--check` builds the producer, creates temporary outputs, and compares every
generated fixture and provenance file byte for byte. `--write` updates this
directory after a deliberate fixture change, retaining replaced files under
`_trash/`. `SwiftProducer/Package.resolved` pins the producer's transitive Swift
dependencies. The first build requires those dependencies and a macOS 15+ SDK.

The five ordinary cases take their semantic fields from
`../mls_chat_control_fingerprint_source.json` and signatures, public keys,
canonical DAG-CBOR, signing transcripts, and request digests from
`../mls_chat_contract_vectors.json`. Schema-directed input materialization
expands the corpus's UUID/byte notation into decoder inputs. The producer
decodes each concrete generated body, constructs its generated signed wrapper
and `BlueCatbirdChatSubmitTransition.Input`, and calls `JSONEncoder.encode`.
It does not hand-build the emitted Swift request JSON. The two encoder options,
`sortedKeys` and `withoutEscapingSlashes`, make exact bytes reproducible while
retaining the generated DTO representation.

The additional `recovery-nonempty` case consumes
`inputs/recovery-nonempty.canonical.json` and its companion expected-products
file. That input is produced by the maintained Rust helper in
`../../common/generated_transition_requests.rs`, signed using the production
signing transcript and a public test key. It exercises nonempty leaf changes
and Welcome delivery/provenance objects; the older frozen recovery case is
retained separately with its original empty manifest. Reproduction requires
both supplemental files once committed.

For each case, `swift-*.request.json` is the exact generated HTTP request body.
`swift-*.wrapper.json` is the exact `signedRequest` byte slice; the producer
checks that this slice equals the separately encoded generated wrapper.
`swift-fixtures.json` records their sizes and SHA-256 hashes, all emitted nested
type tags, frozen expected products, and typed decode/re-encode equality. The
producer rejects unknown-union fallback cases. `provenance.json` records source,
schema, producer, supplemental-input, and output hashes plus the Swift toolchain.

The executable also checks actual server response bytes using generated
`Output` decoders, rejecting any unknown-union fallback:

```sh
python3 server/tests/fixtures/generated_transitions/reproduce.py \
  --decode-response submitTransition /absolute/path/server-response.json
python3 server/tests/fixtures/generated_transitions/reproduce.py \
  --decode-response getEntries /absolute/path/entries-response.json
python3 server/tests/fixtures/generated_transitions/reproduce.py \
  --decode-response getConversationState /absolute/path/state-response.json
```

These are serializer and wire-contract fixtures. Deterministic signing
validity does not establish MLS commit acceptance or metadata decryption: the
frozen corpus includes opaque fixture ciphertext and placeholder MLS bytes.
Actual handler/database and MLS execution evidence must be reported separately.

For a handler test with a canonical signed request built for its seeded database
state, the same producer can encode that supplied wrapper through actual Swift
DTOs. `VARIANT` is one of `commit`, `policy`, `metadata`, `recovery`, or `leave`:

```sh
python3 server/tests/fixtures/generated_transitions/reproduce.py \
  --encode-wrapper policy /absolute/path/canonical-wrapper.json /tmp/swift-policy
```

The input must contain `body` and a bare standard-base64 `signature`. The output
directory receives the generated request, its exact wrapper slice, and a
serialization receipt binding both to the source bytes. This mode never signs
or changes the supplied semantic values.

For retries of a single operation, callers must retain and reuse the exact
encoded request bytes. Freshly encoding equivalent JSON can change key order,
whitespace, tags, or byte presentation and is not byte-idempotent: the server
retains and compares the accepted wrapper bytes. Reuse the original encoded
payload instead of reconstructing it from an equivalent DTO for that operation.
This fixture work does not change SDK retry behavior.
