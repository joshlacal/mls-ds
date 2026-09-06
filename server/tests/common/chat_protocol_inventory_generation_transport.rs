//! Real inventory rotation and shared cursor receipts on two upgraded sockets.
//! The proof owner mounts this only in the separate non-shipping library test
//! copy. The initial ready group reuses the existing guarded fixture containing
//! real signed creation/acceptance/Add entries and verified OpenMLS states.
//! Inventory, tickets, application sends, events and receipts use real handlers;
//! no event/session/receipt rows are manufactured by this regression.
#![cfg(all(test, feature = "test-support"))]
#![allow(dead_code)]

#[path = "http_acceptance.rs"]
mod http;

// The proof owner mounts this module inside production_composition_proof and
// adds only a test-only current-epoch application payload field to that fixture.
use super::production_proof_fixture::{
    coordinate_json, seed_durable_recovery_fulfillment_fixture_for_identities,
    DurableRecoveryFulfillmentFixture, FixtureIdentity,
};

use crate::chat_protocol::{
    transcript::decode_canonical_signed_mutation, validation::ed25519_key_id,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use futures::{SinkExt, StreamExt};
use openmls::prelude::{
    tls_codec::Serialize as TlsSerialize, BasicCredential, Capabilities, Ciphersuite,
    CredentialType, CredentialWithKey, GroupId, Lifetime, MlsGroup, MlsGroupCreateConfig,
    ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha384};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{collections::BTreeMap, time::Duration as StdDuration};
use tls_codec::{Deserialize as _, VLBytes};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{oneshot, Mutex},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use uuid::Uuid;

const TEST_DATABASE: &str = "catbird_chat_protocol_test_20260905_heartbeat";
type ClientSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;
static SERIAL: Mutex<()> = Mutex::const_new(());

async fn owned_database() -> PgPool {
    let connection =
        std::env::var("TEST_DATABASE_URL").expect("explicit dedicated TEST_DATABASE_URL required");
    let parsed = url::Url::parse(&connection).expect("parse test database URL");
    assert!(matches!(parsed.scheme(), "postgres" | "postgresql"));
    assert_eq!(
        parsed.host_str(),
        Some("127.0.0.1"),
        "heartbeat test requires IPv4 loopback"
    );
    assert_eq!(parsed.path(), format!("/{TEST_DATABASE}"));
    assert!(
        parsed.query().is_none(),
        "connection overrides are not allowed"
    );
    let pool = PgPoolOptions::new()
        .max_connections(6)
        .acquire_timeout(StdDuration::from_secs(10))
        .connect(&connection)
        .await
        .expect("connect to owned heartbeat database");
    let (database, loopback, owner): (String, bool, bool) = sqlx::query_as(
        "SELECT current_database(), inet_server_addr() = '127.0.0.1'::inet, datdba = (SELECT oid FROM pg_roles WHERE rolname = current_user) FROM pg_database WHERE datname = current_database()"
    ).fetch_one(&pool).await.expect("verify actual database identity");
    assert_eq!(database, TEST_DATABASE);
    assert!(loopback && owner, "test requires the local database owner");

    let mut expected = BTreeMap::new();
    for path in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).unwrap() {
        let path = path.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("sql") {
            continue;
        }
        let filename = path.file_name().unwrap().to_str().unwrap();
        let version: i64 = filename.split_once('_').unwrap().0.parse().unwrap();
        assert!(expected
            .insert(
                version,
                Sha384::digest(std::fs::read(path).unwrap()).to_vec()
            )
            .is_none());
    }
    assert_eq!(
        expected.len(),
        85,
        "exact deployed stage migration inventory"
    );
    let applied: Vec<(i64, bool, Vec<u8>)> =
        sqlx::query_as("SELECT version, success, checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .expect("read dedicated migration ledger");
    assert_eq!(applied.len(), expected.len());
    for (version, success, checksum) in applied {
        assert!(success, "migration {version} must be successful");
        assert_eq!(
            expected.get(&version),
            Some(&checksum),
            "migration {version} checksum"
        );
    }
    http::ensure_fence(&pool).await;
    pool
}

async fn clock_now(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .expect("database clock")
}

struct RunningServer {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}
impl Drop for RunningServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl RunningServer {
    async fn stop(mut self) {
        self.shutdown
            .take()
            .unwrap()
            .send(())
            .expect("server shutdown receiver");
        timeout(StdDuration::from_secs(3), &mut self.task)
            .await
            .expect("server finishes after peer closes")
            .expect("server task");
    }
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestGroupInfoEnvelope {
    version: u16,
    wire_format: u16,
    group_info: TestGroupInfo,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestGroupInfo {
    context: TestGroupContext,
    extensions: Vec<TestExtension>,
    confirmation_tag: VLBytes,
    signer: u32,
    signature: VLBytes,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestGroupContext {
    protocol_version: u16,
    ciphersuite: u16,
    group_id: VLBytes,
    epoch: u64,
    tree_hash: VLBytes,
    confirmed_transcript_hash: VLBytes,
    extensions: Vec<TestExtension>,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestExtension {
    extension_type: u16,
    extension_data: VLBytes,
}
struct CreationTestFixture {
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_ed25519_public_key: Vec<u8>,
    actor_ed25519_signing_key: Ed25519SigningKey,
    signed_request_json: Value,
    cid: Uuid,
    transition_id: Uuid,
    group_id: [u8; 32],
    group_context_hash: [u8; 32],
    confirmation_tag: [u8; 32],
    provider: openmls_libcrux_crypto::Provider,
    signer: SignatureKeyPair,
    group: MlsGroup,
}

fn random_did() -> String {
    let bytes: [u8; 15] = Uuid::new_v4().as_bytes()[..15].try_into().unwrap();
    let suffix: String = (0..24)
        .map(|i| {
            let value = (bytes[i % 15] as usize + i * 7) % 32;
            char::from(b"abcdefghijklmnopqrstuvwxyz234567"[value])
        })
        .collect();
    format!("did:plc:{suffix}")
}

fn build_test_creation_fixture(trusted_at: DateTime<Utc>) -> CreationTestFixture {
    build_test_creation_fixture_with_invitee(trusted_at, None)
}

fn build_test_creation_fixture_with_invitee(
    trusted_at: DateTime<Utc>,
    invitee_did: Option<&str>,
) -> CreationTestFixture {
    let cid = Uuid::new_v4();
    let transition_id = Uuid::new_v4();
    let actor_did = random_did();
    let actor_device_id = Uuid::new_v4();
    let mut seed = [0_u8; 32];
    seed[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    seed[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    let ed_signing = Ed25519SigningKey::from_bytes(&seed);
    let public_key_bytes = ed_signing.verifying_key().to_bytes();
    let actor_key_id = ed25519_key_id(&public_key_bytes)
        .unwrap()
        .as_str()
        .to_owned();

    let signed_at = (trusted_at - chrono::Duration::milliseconds(500))
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let now_sec = u64::try_from(trusted_at.timestamp()).unwrap();
    let lifetime = Lifetime::init(now_sec - 60, now_sec + 3600);

    let provider = openmls_libcrux_crypto::Provider::new().expect("libcrux provider");
    let ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
    let signer = SignatureKeyPair::from_raw(
        ciphersuite.signature_algorithm(),
        ed_signing.to_bytes().to_vec(),
        public_key_bytes.to_vec(),
    );
    signer.store(provider.storage()).expect("store signer");

    let actor_credential = format!("{actor_did}#{actor_device_id}").into_bytes();
    let capabilities = Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[ciphersuite]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    );

    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .capabilities(capabilities)
        .lifetime(lifetime)
        .build();

    let group_id: [u8; 32] =
        Sha256::digest([b"CATBIRD-TEST-GROUP\0".as_ref(), cid.as_bytes()].concat()).into();

    let group = MlsGroup::new_with_group_id(
        &provider,
        &signer,
        &config,
        GroupId::from_slice(&group_id),
        CredentialWithKey {
            credential: BasicCredential::new(actor_credential.clone()).into(),
            signature_key: signer.to_public_vec().into(),
        },
    )
    .expect("create MLS group");

    let genesis_group_info = group
        .export_group_info(provider.crypto(), &signer, true)
        .expect("export GroupInfo")
        .tls_serialize_detached()
        .expect("serialize GroupInfo");

    let envelope = TestGroupInfoEnvelope::tls_deserialize_exact(&genesis_group_info)
        .expect("parse coordinate GroupInfo");
    let group_context_hash: [u8; 32] = Sha256::digest(
        envelope
            .group_info
            .context
            .tls_serialize_detached()
            .expect("serialize coordinate GroupContext"),
    )
    .into();
    let confirmation_tag_32: [u8; 32] = envelope
        .group_info
        .confirmation_tag
        .as_slice()
        .try_into()
        .expect("32-byte confirmation tag");
    let metadata_ciphertext = [0x99_u8; 32];
    let body = json!({
        "$type": "blue.catbird.chat.defs#creationBody",
        "signatureDomain": "CATBIRD-CHAT-CREATE\u{0000}",
        "conversationId": cid.hyphenated().to_string(),
        "transitionId": transition_id.hyphenated().to_string(),
        "conversationKind": "group",
        "absence": true,
        "actorDid": &actor_did,
        "actorDeviceId": actor_device_id.hyphenated().to_string(),
        "authGeneration": 1,
        "idempotencyKey": transition_id.hyphenated().to_string(),
        "keyId": &actor_key_id,
        "signedAt": &signed_at,
        "next": {
            "conversationId": cid.hyphenated().to_string(),
            "generation": 0,
            "stateVersion": 0,
            "groupId": STANDARD.encode(group_id),
            "epoch": 0,
            "groupContextHash": STANDARD.encode(group_context_hash),
            "confirmationTag": STANDARD.encode(confirmation_tag_32),
            "lifecycle": "active"
        },
        "manifest": {
            "actorLeaf": {
                "userDid": &actor_did,
                "deviceId": actor_device_id.hyphenated().to_string(),
                "leafOrigin": "genesis",
            },
            "participants": match invitee_did {
                Some(invitee) => {
                    let mut list = vec![
                        json!({
                            "userDid": &actor_did,
                            "status": "active",
                            "role": "admin"
                        }),
                        json!({
                            "userDid": invitee,
                            "status": "pending",
                            "role": "member"
                        }),
                    ];
                    list.sort_by(|a, b| a["userDid"].as_str().cmp(&b["userDid"].as_str()));
                    json!(list)
                }
                None => json!([
                    {
                        "userDid": &actor_did,
                        "status": "active",
                        "role": "admin"
                    }
                ]),
            },
        },
        "genesisGroupInfo": {
            "framing": "mlsMessage",
            "contentType": "groupInfo",
            "bytes": STANDARD.encode(&genesis_group_info),
            "sha256": STANDARD.encode(Sha256::digest(&genesis_group_info))
        },
        "metadataSnapshot": {
            "coordinate": {
                "conversationId": STANDARD.encode(cid.as_bytes()),
                "generation": 0,
                "groupId": STANDARD.encode(group_id),
                "epoch": 0,
                "groupContextHash": STANDARD.encode(group_context_hash),
                "confirmationTag": STANDARD.encode(confirmation_tag_32),
            },
            "originTransitionId": transition_id.hyphenated().to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode([0x73_u8; 12]),
            "ciphertext": STANDARD.encode(metadata_ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(metadata_ciphertext)),
            "ciphertextSize": metadata_ciphertext.len(),
            "authorProof": {
                "authorDid": &actor_did,
                "authorDeviceId": actor_device_id.hyphenated().to_string(),
                "authorKeyId": &actor_key_id,
                "signaturePublicKey": STANDARD.encode(public_key_bytes),
                "authGenerationAtOrigin": 1,
                "originTransitionId": transition_id.hyphenated().to_string(),
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active",
            },
        }
    });

    let mut wrapper = json!({
        "body": body,
        "signature": STANDARD.encode([0_u8; 64]),
    });
    let unsigned = serde_json::to_vec(&wrapper).unwrap();
    let canonical =
        decode_canonical_signed_mutation(&unsigned).expect("canonicalize creation body");
    let signature = ed_signing.sign(canonical.transcript_bytes());
    wrapper["signature"] = json!(STANDARD.encode(signature.to_bytes()));
    CreationTestFixture {
        actor_did,
        actor_device_id,
        actor_key_id,
        actor_ed25519_public_key: public_key_bytes.to_vec(),
        actor_ed25519_signing_key: ed_signing,
        signed_request_json: wrapper,
        cid,
        transition_id,
        group_id,
        group_context_hash,
        confirmation_tag: confirmation_tag_32,
        provider,
        signer,
        group,
    }
}

async fn seed_group_device(pool: &PgPool, fixture: &CreationTestFixture) -> http::Device {
    let signing = http::random_p256();
    let jwk = http::public_jwk(&signing);
    let jkt = http::jwk_thumbprint(&jwk);
    let device = http::Device {
        did: fixture.actor_did.clone(),
        device_id: fixture.actor_device_id,
        signing,
        jwk,
        jkt,
    };
    // The fixture device exists before the signed creation and whole-second
    // inventory fence. All subsequent protocol writes use actual HTTP routes.
    let created_at = clock_now(pool).await - Duration::seconds(2);
    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
        .bind(&device.did)
        .bind(created_at)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'inventory-generation-test','active',$3,1,chat.protocol_capabilities(),$4,$4)")
        .bind(&device.did).bind(device.device_id).bind(&device.jkt).bind(created_at).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,$5)")
        .bind(&device.did).bind(device.device_id).bind(&fixture.actor_key_id).bind(&fixture.actor_ed25519_public_key).bind(created_at).execute(pool).await.unwrap();
    http::cache_device_did(&device).await;
    device
}

/// Seed a coherent initial history through the pre-existing cryptographic
/// fixture. This is initial-state setup, not a claim to exercise group admission
/// over HTTP. The fixture keeps every relational guard enabled and verifies its
/// real creation, acceptance and Add artifacts before commit.
async fn ready_group(pool: &PgPool) -> (DurableRecoveryFulfillmentFixture, http::Device) {
    let trusted = crate::chat_protocol::validation::TrustedRequestInstant::from_datetime(
        clock_now(pool).await - Duration::seconds(2),
    )
    .unwrap();
    let first = FixtureIdentity::fresh(b"inventory-generation-sender").unwrap();
    let second = FixtureIdentity::fresh(b"inventory-generation-peer").unwrap();
    let fixture = seed_durable_recovery_fulfillment_fixture_for_identities(
        pool,
        &trusted,
        first,
        second,
        Uuid::new_v4(),
    )
    .await
    .expect("guarded real signed two-member initial history");
    assert_eq!(fixture.prior.epoch(), 1);
    assert_eq!(fixture.prior.state_version(), 2);
    assert_eq!(fixture.application_messages.len(), 2);
    assert_ne!(
        fixture.application_messages[0], fixture.application_messages[1],
        "each actual application uses a distinct native sender generation"
    );
    let signing = http::random_p256();
    let jwk = http::public_jwk(&signing);
    let jkt = http::jwk_thumbprint(&jwk);
    let device = http::Device {
        did: fixture.requester.did.clone(),
        device_id: fixture.requester.device_id,
        signing,
        jwk,
        jkt,
    };
    // Service auth uses the cached public DID key. It does not replace the
    // fixture's separately registered MLS Ed25519 or DPoP device keys.
    http::cache_device_did(&device).await;
    (fixture, device)
}

/// Use the existing deterministic external graph transport with the production
/// collector/sealer/writer. No relationship table or authority flag is written
/// by this test; the real send handler still loads and consumes the exact scope.
async fn seed_traffic_projection(pool: &PgPool, fixture: &DurableRecoveryFulfillmentFixture) {
    use crate::chat_protocol::{
        relationship_policy::{fixed_production_relationship_policy_config, RelationshipAuthority},
        repository::relationship::{
            allocate_projection_revision, observe_relationship_persistence,
            persist_traffic_projection,
        },
        test_support::DeterministicTestTransport,
    };
    let authority = RelationshipAuthority::new(
        fixed_production_relationship_policy_config().unwrap(),
        DeterministicTestTransport,
    );
    let mut roster = vec![fixture.requester.did.clone(), fixture.fulfiller.did.clone()];
    roster.sort();
    let mut transaction = pool.begin().await.unwrap();
    let live_allocation = allocate_projection_revision(&mut transaction)
        .await
        .unwrap();
    let fallback_allocation = allocate_projection_revision(&mut transaction)
        .await
        .unwrap();
    let live = authority
        .collect_traffic_projection(live_allocation, fixture.requester.did.clone(), roster)
        .await
        .expect("collect exact two-member traffic graph through test transport");
    let observation = observe_relationship_persistence();
    let fallback = live
        .export_persisted_fallback(fallback_allocation, &authority, &observation)
        .expect("seal actual traffic projection");
    persist_traffic_projection(&mut transaction, fallback)
        .await
        .expect("persist validated traffic projection");
    transaction.commit().await.unwrap();
}

async fn advance_unrelated_global_event(pool: &PgPool, router: &axum::Router) {
    // A new unrelated singleton creation emits a genuine global event without
    // needing a ready recipient for an application in that unrelated group.
    let fixture = build_test_creation_fixture(clock_now(pool).await);
    let device = seed_group_device(pool, &fixture).await;
    create_group(router, &device, &fixture).await;
}

async fn send_ready_application(
    pool: &PgPool,
    router: &axum::Router,
    device: &http::Device,
    fixture: &mut DurableRecoveryFulfillmentFixture,
) -> (Uuid, u64) {
    seed_traffic_projection(pool, fixture).await;
    let message_id = Uuid::new_v4();
    let prior = coordinate_json(&fixture.prior);
    let mut aad_prior = prior.clone();
    aad_prior["conversationId"] = json!(STANDARD.encode(fixture.conversation_id.as_bytes()));
    assert!(
        !fixture.application_messages.is_empty(),
        "distinct native payload remains"
    );
    let application = fixture.application_messages.remove(0);
    let body = json!({
        "$type":"blue.catbird.chat.defs#applicationSendBody", "signatureDomain":"CATBIRD-CHAT-MESSAGE\u{0000}",
        "messageId":message_id,"actorDid":fixture.requester.did,"actorDeviceId":fixture.requester.device_id,
        "keyId":fixture.requester.key_id,"authGeneration":1,"prior":prior,
        "signedAt":Utc::now().to_rfc3339_opts(SecondsFormat::Millis,true),"blobBindings":[],
        "aad":{"conversationId":STANDARD.encode(fixture.conversation_id.as_bytes()),"generation":0,"protocolVersion":"1",
            "messageId":STANDARD.encode(message_id.as_bytes()),"prior":aad_prior},
        "applicationMessage":{"framing":"mlsMessage","contentType":"privateMessageApplication",
            "bytes":STANDARD.encode(&application),"sha256":STANDARD.encode(Sha256::digest(&application))}
    });
    let mut wrapper = json!({"body":body,"signature":STANDARD.encode([0_u8;64])});
    let unsigned = serde_json::to_vec(&wrapper).unwrap();
    let canonical = decode_canonical_signed_mutation(&unsigned).unwrap();
    wrapper["signature"] = json!(STANDARD.encode(
        fixture
            .requester
            .signing_key
            .sign(canonical.transcript_bytes())
            .to_bytes(),
    ));
    let response = signed_post(router, device, "blue.catbird.chat.sendMessage", wrapper).await;
    (message_id, response["entry"]["seq"].as_u64().unwrap())
}

async fn signed_post(
    router: &axum::Router,
    device: &http::Device,
    nsid: &str,
    wrapper: Value,
) -> Value {
    let (status, body) = http::send(
        router.clone(),
        http::unsigned_json_request(
            device,
            nsid,
            serde_json::to_vec(&json!({"signedRequest":wrapper})).unwrap(),
        ),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "real signed {nsid} must succeed; error={:?}",
        body.get("error")
    );
    body
}

async fn create_group(router: &axum::Router, device: &http::Device, fixture: &CreationTestFixture) {
    let created = signed_post(
        router,
        device,
        "blue.catbird.chat.createConversation",
        fixture.signed_request_json.clone(),
    )
    .await;
    assert_eq!(
        created["result"]["$type"],
        "blue.catbird.chat.defs#conversationCreatedResult"
    );
}

struct Inventory {
    capability: String,
    cursor: String,
    session_id: Uuid,
    session_row: Value,
}

fn capability_hash(capability: &str) -> Vec<u8> {
    Sha256::digest(
        URL_SAFE_NO_PAD
            .decode(capability)
            .expect("canonical emitted capability"),
    )
    .to_vec()
}

async fn inventory_roundtrip(
    pool: &PgPool,
    router: &axum::Router,
    device: &http::Device,
) -> Inventory {
    let query = format!("?actorDeviceId={}&limit=100", device.device_id);
    let (status, conversations) = http::send(
        router.clone(),
        http::unsigned_request(device, "blue.catbird.chat.getConversations", "GET", &query),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "real conversations inventory; error={:?}",
        conversations.get("error")
    );
    assert_eq!(
        conversations["hasMore"], false,
        "one-group fixture fits one complete page"
    );
    assert_eq!(conversations["items"].as_array().unwrap().len(), 1);
    let capability = conversations["inventorySessionId"]
        .as_str()
        .unwrap()
        .to_owned();
    let cursor = conversations["snapshotEventCursor"]
        .as_str()
        .unwrap()
        .to_owned();
    for nsid in [
        "blue.catbird.chat.getPendingWelcomes",
        "blue.catbird.chat.getLeafRecoveryInbox",
    ] {
        let query = format!(
            "?actorDeviceId={}&inventorySessionId={capability}&limit=100",
            device.device_id
        );
        let (status, page) = http::send(
            router.clone(),
            http::unsigned_request(device, nsid, "GET", &query),
        )
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "actual {nsid} consumes this session; error={:?}",
            page.get("error")
        );
        assert_eq!(page["inventorySessionId"], capability);
        assert_eq!(page["hasMore"], false);
        assert!(
            page["items"].is_array(),
            "actual domain page is materialized"
        );
    }
    let row: Value = sqlx::query_scalar("SELECT to_jsonb(session) FROM chat.inventory_sessions session WHERE token_hash=$1 AND user_did=$2 AND device_id=$3")
        .bind(capability_hash(&capability)).bind(&device.did).bind(device.device_id).fetch_one(pool).await.expect("actual inventory parent");
    for consumed in [
        "conversations_consumed",
        "welcomes_consumed",
        "recovery_consumed",
    ] {
        assert_eq!(
            row[consumed], true,
            "all real inventory domains are consumed"
        );
    }
    // The deployed creator rounds its whole-second timestamp upward. Ticket
    // minting also checks the lower bound, so wait for the actual retained
    // session to become live instead of altering its signed/sealed times.
    let created_at = DateTime::parse_from_rfc3339(row["created_at"].as_str().unwrap())
        .expect("actual session creation timestamp")
        .with_timezone(&Utc);
    timeout(StdDuration::from_secs(3), async {
        while clock_now(pool).await < created_at {
            sleep(StdDuration::from_millis(10)).await;
        }
    })
    .await
    .expect("database clock reaches the emitted session's lower bound");
    Inventory {
        capability,
        cursor,
        session_id: Uuid::parse_str(row["inventory_session_id"].as_str().unwrap()).unwrap(),
        session_row: row,
    }
}

async fn serve_router(router: axum::Router) -> (std::net::SocketAddr, RunningServer) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    (
        address,
        RunningServer {
            shutdown: Some(shutdown),
            task,
        },
    )
}

async fn mint_existing_ticket(
    router: &axum::Router,
    device: &http::Device,
    inventory: &Inventory,
) -> String {
    let (status, response) = http::send(router.clone(), http::unsigned_json_request(device,
        "blue.catbird.chat.getSubscriptionTicket", serde_json::to_vec(&json!({
            "actorDeviceId":device.device_id,"inventorySessionId":inventory.capability,"eventCursor":inventory.cursor
        })).unwrap())).await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "actual ticket mint failed; declared error={:?}",
        response.get("error")
    );
    response["ticket"].as_str().unwrap().to_owned()
}

async fn upgrade(
    router: &axum::Router,
    device: &http::Device,
    inventory: &Inventory,
    address: std::net::SocketAddr,
) -> ClientSocket {
    let ticket = mint_existing_ticket(router, device, inventory).await;
    let (socket, response) = connect_async(format!(
        "ws://{address}/xrpc/blue.catbird.chat.subscribeEvents?cursor={}&ticket={ticket}",
        inventory.cursor
    ))
    .await
    .expect("actual upgraded original stream");
    assert_eq!(response.status().as_u16(), 101);
    socket
}

async fn assert_quiet(socket: &mut ClientSocket) {
    let observed = timeout(StdDuration::from_millis(600), async {
        loop {
            match socket
                .next()
                .await
                .expect("original stream remains open")
                .expect("WebSocket frame")
            {
                Message::Ping(payload) => socket.send(Message::Pong(payload)).await.unwrap(),
                Message::Pong(_) => {}
                frame => return frame,
            }
        }
    })
    .await;
    assert!(
        observed.is_err(),
        "unrelated global events must not reach the exact-device stream: {observed:?}"
    );
}

async fn next_envelope(socket: &mut ClientSocket, anchor_retained: bool) -> String {
    timeout(StdDuration::from_secs(5), async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Ping(payload))) => socket.send(Message::Pong(payload)).await.unwrap(),
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Text(frame))) => return frame,
                other => panic!("original upgraded stream ended before the addressed event; original anchor retained={anchor_retained}; transport={other:?}"),
            }
        }
    }).await.expect("addressed event arrives on the original stream within five seconds")
}

async fn send_application(
    router: &axum::Router,
    device: &http::Device,
    fixture: &mut CreationTestFixture,
) -> (Uuid, u64) {
    let message_id = Uuid::new_v4();
    let prior = fixture.signed_request_json["body"]["next"].clone();
    let mut aad_prior = prior.clone();
    aad_prior["conversationId"] = json!(STANDARD.encode(fixture.cid.as_bytes()));
    fixture.group.set_aad(Vec::new());
    let application = fixture
        .group
        .create_message(
            &fixture.provider,
            &fixture.signer,
            b"inventory generation regression",
        )
        .expect("real MLS application encryption")
        .tls_serialize_detached()
        .unwrap();
    let body = json!({
        "$type":"blue.catbird.chat.defs#applicationSendBody", "signatureDomain":"CATBIRD-CHAT-MESSAGE\u{0000}",
        "messageId":message_id,"actorDid":fixture.actor_did,"actorDeviceId":fixture.actor_device_id,
        "keyId":fixture.actor_key_id,"authGeneration":1,"prior":prior,
        "signedAt":Utc::now().to_rfc3339_opts(SecondsFormat::Millis,true),"blobBindings":[],
        "aad":{"conversationId":STANDARD.encode(fixture.cid.as_bytes()),"generation":0,"protocolVersion":"1",
            "messageId":STANDARD.encode(message_id.as_bytes()),"prior":aad_prior},
        "applicationMessage":{"framing":"mlsMessage","contentType":"privateMessageApplication",
            "bytes":STANDARD.encode(&application),"sha256":STANDARD.encode(Sha256::digest(&application))}
    });
    let mut wrapper = json!({"body":body,"signature":STANDARD.encode([0_u8;64])});
    let unsigned = serde_json::to_vec(&wrapper).unwrap();
    let canonical = decode_canonical_signed_mutation(&unsigned)
        .expect("canonical application signature transcript");
    wrapper["signature"] = json!(STANDARD.encode(
        fixture
            .actor_ed25519_signing_key
            .sign(canonical.transcript_bytes())
            .to_bytes()
    ));
    let response = signed_post(router, device, "blue.catbird.chat.sendMessage", wrapper).await;
    (message_id, response["entry"]["seq"].as_u64().unwrap())
}

async fn row_by_session(pool: &PgPool, session_id: Uuid) -> Option<Value> {
    sqlx::query_scalar("SELECT to_jsonb(session) FROM chat.inventory_sessions session WHERE inventory_session_id=$1")
        .bind(session_id).fetch_optional(pool).await.unwrap()
}

async fn receipt(pool: &PgPool, cursor: &str) -> Option<Value> {
    sqlx::query_scalar(
        "SELECT to_jsonb(receipt) FROM chat.event_cursor_receipts receipt WHERE cursor_hash=$1",
    )
    .bind(capability_hash(cursor))
    .fetch_optional(pool)
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn newer_inventory_preserves_two_original_streams_and_their_shared_receipt_chain() {
    let _serial = SERIAL.lock().await;
    let pool = owned_database().await;
    let (mut group_a, device_a) = ready_group(&pool).await;
    let router = http::router_for_authenticated_acceptance(pool.clone()).await;
    let initial = inventory_roundtrip(&pool, &router, &device_a).await;
    let (address, server) = serve_router(router.clone()).await;
    let mut first = upgrade(&router, &device_a, &initial, address).await;
    let mut second = upgrade(&router, &device_a, &initial, address).await;
    let anchor = receipt(&pool, &initial.cursor)
        .await
        .expect("both upgrades share the committed initial receipt");
    let ticket_count: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.subscription_tickets WHERE inventory_session_id=$1 AND consumed_at IS NOT NULL")
        .bind(initial.session_id).fetch_one(&pool).await.unwrap();
    assert_eq!(
        ticket_count, 2,
        "two independent one-use tickets, one original fence"
    );
    let mut previous_cursor = initial.cursor.clone();
    let mut prior_inventory = initial.session_row.clone();
    let mut prior_capability = initial.capability.clone();
    let mut retained_receipts = vec![(initial.cursor.clone(), anchor)];

    for _rotation in 0..2 {
        // Only B's authentic operations advance the global log while A is
        // quiet. A is never an audience member for B's group or application.
        advance_unrelated_global_event(&pool, &router).await;
        tokio::join!(assert_quiet(&mut first), assert_quiet(&mut second));
        let refreshed = inventory_roundtrip(&pool, &router, &device_a).await;
        assert_ne!(
            refreshed.capability, prior_capability,
            "actual inventory refresh observes the newer global event fence"
        );
        assert!(
            refreshed.session_row["snapshot_event_position"]
                .as_i64()
                .unwrap()
                > prior_inventory["snapshot_event_position"].as_i64().unwrap()
        );
        let anchor_retained = receipt(&pool, &initial.cursor).await.is_some();
        // Do not stop at the missing-anchor diagnostic on RED: actually send
        // the next addressed message and require delivery on both original101s.
        let (message_id, seq) =
            send_ready_application(&pool, &router, &device_a, &mut group_a).await;
        let (first_frame, second_frame) = tokio::join!(
            next_envelope(&mut first, anchor_retained),
            next_envelope(&mut second, anchor_retained)
        );
        assert_eq!(
            first_frame, second_frame,
            "same-fence streams replay byte-identical canonical envelopes"
        );
        let envelope: Value = serde_json::from_str(&first_frame).unwrap();
        assert_eq!(envelope["previousCursor"], previous_cursor);
        assert_eq!(
            envelope["payload"]["$type"],
            "blue.catbird.chat.defs#messageAvailableEvent"
        );
        assert_eq!(
            envelope["payload"]["conversationId"],
            group_a.conversation_id.to_string()
        );
        assert_eq!(envelope["payload"]["seq"], seq);
        let cursor = envelope["cursor"].as_str().unwrap().to_owned();
        let successor = receipt(&pool, &cursor)
            .await
            .expect("receipt commits before the frame");
        assert_eq!(
            successor["inventory_session_id"],
            initial.session_id.to_string()
        );
        assert_eq!(
            successor["expires_at"], initial.session_row["expires_at"],
            "refresh does not renew old stream authority"
        );
        assert_eq!(
            successor["predecessor_cursor_hash"],
            format!("\\x{}", hex::encode(capability_hash(&previous_cursor)))
        );
        assert_eq!(
            successor["canonical_envelope_sha256"],
            format!("\\x{}", hex::encode(Sha256::digest(first_frame.as_bytes())))
        );
        assert_ne!(
            refreshed.session_id, initial.session_id,
            "old and new inventory bindings are distinct"
        );
        assert!(
            row_by_session(&pool, initial.session_id).await.as_ref() == Some(&initial.session_row),
            "original parent remains byte-equivalent"
        );
        for (old_cursor, old_row) in &retained_receipts {
            assert!(
                receipt(&pool, old_cursor).await.as_ref() == Some(old_row),
                "existing cursor receipts remain immutable"
            );
        }
        let entries: Vec<i64> = sqlx::query_scalar(
            "SELECT seq FROM chat.entries WHERE conversation_id=$1 AND message_id=$2",
        )
        .bind(group_a.conversation_id)
        .bind(message_id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(entries, vec![i64::try_from(seq).unwrap()]);
        let events: Vec<i64> = sqlx::query_scalar("SELECT event_position FROM chat.events WHERE event_kind='messageAvailable' AND convert_from(payload_bytes,'UTF8')::jsonb->>'conversationId'=$1 AND (convert_from(payload_bytes,'UTF8')::jsonb->>'seq')::bigint=$2")
            .bind(group_a.conversation_id.to_string()).bind(i64::try_from(seq).unwrap()).fetch_all(&pool).await.unwrap();
        assert_eq!(
            events.len(),
            1,
            "one durable event for one accepted application"
        );
        let recipients: Vec<(String,Uuid)> = sqlx::query_as("SELECT user_did,device_id FROM chat.event_recipients WHERE event_position=$1 ORDER BY user_did,device_id")
            .bind(events[0]).fetch_all(&pool).await.unwrap();
        let mut expected_recipients = vec![
            (device_a.did.clone(), device_a.device_id),
            (group_a.fulfiller.did.clone(), group_a.fulfiller.device_id),
        ];
        expected_recipients.sort();
        assert_eq!(
            recipients, expected_recipients,
            "exact two-member frozen event audience"
        );
        let receipt_count: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.event_cursor_receipts WHERE inventory_session_id=$1 AND device_id=$2 AND event_position=$3")
            .bind(initial.session_id).bind(device_a.device_id).bind(events[0]).fetch_one(&pool).await.unwrap();
        assert_eq!(
            receipt_count, 1,
            "two live sockets share one successor receipt"
        );
        // Probe lookup by the ORIGINAL capability only after both original
        // sockets delivered. Leave the new ticket unused: it must not hide a
        // broken original connection by reconnecting around the failure.
        let _unused_original_ticket = mint_existing_ticket(&router, &device_a, &initial).await;
        retained_receipts.push((cursor.clone(), successor));
        previous_cursor = cursor;
        prior_inventory = refreshed.session_row;
        prior_capability = refreshed.capability;
        tokio::join!(assert_quiet(&mut first), assert_quiet(&mut second));
    }
    first.close(None).await.unwrap();
    second.close(None).await.unwrap();
    drop(first);
    drop(second);
    server.stop().await;
}

async fn inventory_rows(pool: &PgPool) -> BTreeMap<&'static str, Value> {
    let mut rows = BTreeMap::new();
    for table in [
        "inventory_sessions",
        "inventory_page_receipts",
        "inventory_conversation_items",
        "inventory_welcome_items",
        "inventory_recovery_items",
        "event_cursor_receipts",
        "subscription_tickets",
        "device_inventory_sessions",
        "device_inventory_items",
    ] {
        let query = format!("SELECT COALESCE(jsonb_agg(row_data ORDER BY row_data::text), '[]'::jsonb) FROM (SELECT to_jsonb(row_value) AS row_data FROM chat.{table} row_value) rows");
        rows.insert(
            table,
            sqlx::query_scalar(&query).fetch_one(pool).await.unwrap(),
        );
    }
    rows
}

async fn active_session_count(pool: &PgPool, device: &http::Device) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM (SELECT 1 FROM chat.inventory_sessions WHERE user_did=$1 AND device_id=$2 AND expires_at>clock_timestamp() UNION ALL SELECT 1 FROM chat.device_inventory_sessions WHERE user_did=$1 AND device_id=$2 AND expires_at>clock_timestamp()) active")
        .bind(&device.did).bind(device.device_id).fetch_one(pool).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ninth_inventory_fence_is_rate_limited_without_mutating_retained_sessions_or_breaking_the_old_stream(
) {
    let _serial = SERIAL.lock().await;
    let pool = owned_database().await;
    let (mut group_a, device_a) = ready_group(&pool).await;
    let router = http::router_for_authenticated_acceptance(pool.clone()).await;
    advance_unrelated_global_event(&pool, &router).await;
    let own_query = format!("?actorDeviceId={}", device_a.device_id);
    let (status, _) = http::send(
        router.clone(),
        http::unsigned_request(
            &device_a,
            "blue.catbird.chat.getOwnDevices",
            "GET",
            &own_query,
        ),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "real own-device inventory consumes one shared capacity slot"
    );
    assert_eq!(active_session_count(&pool, &device_a).await, 1);
    let initial = inventory_roundtrip(&pool, &router, &device_a).await;
    let (address, server) = serve_router(router.clone()).await;
    let mut socket = upgrade(&router, &device_a, &initial, address).await;
    let mut sessions = vec![initial.session_id];
    // Six new shared generations plus the initial shared generation and one
    // actual own-device snapshot reach the unchanged combined cap of eight.
    for expected_count in 3..=8 {
        advance_unrelated_global_event(&pool, &router).await;
        let next = inventory_roundtrip(&pool, &router, &device_a).await;
        assert!(
            !sessions.contains(&next.session_id),
            "each advanced fence has a distinct retained parent"
        );
        sessions.push(next.session_id);
        assert_eq!(active_session_count(&pool, &device_a).await, expected_count);
    }
    advance_unrelated_global_event(&pool, &router).await;
    assert_quiet(&mut socket).await;
    let before = inventory_rows(&pool).await;
    let (status, body) = http::send(
        router.clone(),
        http::unsigned_request(
            &device_a,
            "blue.catbird.chat.getConversations",
            "GET",
            &format!("?actorDeviceId={}&limit=100", device_a.device_id),
        ),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        "a fresh ninth inventory cannot evict live retained parents"
    );
    assert_eq!(body["error"], "RateLimited");
    let after = inventory_rows(&pool).await;
    for (table, old_rows) in &before {
        assert!(
            after.get(table) == Some(old_rows),
            "capacity rejection mutated chat.{table}"
        );
    }
    assert_eq!(active_session_count(&pool, &device_a).await, 8);
    for nsid in [
        "blue.catbird.chat.getPendingWelcomes",
        "blue.catbird.chat.getLeafRecoveryInbox",
    ] {
        let query = format!(
            "?actorDeviceId={}&inventorySessionId={}&limit=100",
            device_a.device_id, initial.capability
        );
        let (status, page) = http::send(
            router.clone(),
            http::unsigned_request(&device_a, nsid, "GET", &query),
        )
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "explicit original inventory page remains usable at capacity"
        );
        assert_eq!(page["inventorySessionId"], initial.capability);
        assert_eq!(page["hasMore"], false);
    }
    let (_, seq) = send_ready_application(&pool, &router, &device_a, &mut group_a).await;
    let frame = next_envelope(&mut socket, receipt(&pool, &initial.cursor).await.is_some()).await;
    let envelope: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(envelope["previousCursor"], initial.cursor);
    assert_eq!(
        envelope["payload"]["conversationId"],
        group_a.conversation_id.to_string()
    );
    assert_eq!(envelope["payload"]["seq"], seq);
    let successor = receipt(&pool, envelope["cursor"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        successor["inventory_session_id"],
        initial.session_id.to_string()
    );
    assert_eq!(successor["expires_at"], initial.session_row["expires_at"]);
    assert!(row_by_session(&pool, initial.session_id).await.as_ref() == Some(&initial.session_row));
    socket.close(None).await.unwrap();
    drop(socket);
    server.stop().await;
}

#[path = "chat_protocol_atproto_stream_transport.rs"]
mod atproto_stream_transport_tests;

#[path = "chat_protocol_canonical_receipt_digest.rs"]
mod canonical_receipt_digest_tests;

#[path = "chat_protocol_inventory_generation_admission.rs"]
mod admission;
