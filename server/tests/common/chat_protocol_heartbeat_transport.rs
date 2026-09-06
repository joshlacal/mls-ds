//! Actual upgraded subscribeEvents transport regression against an owned local database.
//! Run only with --features test-support and the dedicated heartbeat TEST_DATABASE_URL.
//! The stage owner prepares the schema; this test verifies every ledger checksum and
//! never migrates, truncates, or reads any other database.
#![cfg(feature = "test-support")]
#![allow(dead_code)]

#[path = "http_acceptance.rs"]
mod http;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use catbird_server::chat_protocol::cursor::{
    CursorSealer, SealerBinding, SecureRandom, SecureRandomError,
};
use chrono::{DateTime, Duration, Timelike, Utc};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha384};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{collections::BTreeMap, time::Duration as StdDuration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{oneshot, Mutex},
    task::JoinHandle,
    time::{sleep, timeout, Instant},
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Error as WsError, Message},
    MaybeTlsStream, WebSocketStream,
};
use uuid::Uuid;
use zeroize::Zeroizing;

const TEST_DATABASE: &str = "catbird_chat_protocol_test_20260905_heartbeat";
static SERIAL: Mutex<()> = Mutex::const_new(());
type ClientSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

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

struct FixtureRandom(u8);

impl SecureRandom for FixtureRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), SecureRandomError> {
        out.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}

fn fresh_blob() -> Vec<u8> {
    let mut b = Uuid::new_v4().as_bytes().to_vec();
    b.extend_from_slice(Uuid::new_v4().as_bytes());
    b
}

struct DeviceFixture {
    did: String,
    device_id: Uuid,
    jkt: String,
    auth_generation: i64,
}

struct SessionFixture {
    inventory_session_id: Uuid,
    snapshot_event_position: i64,
    capability: String,
    capability_hash: Vec<u8>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

const INVENTORY_MATERIALIZATION_ENCODING_VERSION: u8 = 2;

fn derive_inventory_session_uuid(
    user_did: &str,
    device_id: Uuid,
    jkt: Option<&str>,
    auth_generation: u64,
) -> Uuid {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-INVENTORY-SESSION-IDENTITY\0");
    digest.update([INVENTORY_MATERIALIZATION_ENCODING_VERSION]);
    digest.update((user_did.len() as u64).to_be_bytes());
    digest.update(user_did.as_bytes());
    digest.update(device_id.as_bytes());
    let jkt_str = jkt.unwrap_or_default();
    digest.update((jkt_str.len() as u64).to_be_bytes());
    digest.update(jkt_str.as_bytes());
    digest.update(auth_generation.to_be_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(&bytes[..16]);
    uuid_bytes[6] = (uuid_bytes[6] & 0x0F) | 0x40;
    uuid_bytes[8] = (uuid_bytes[8] & 0x3F) | 0x80;
    Uuid::from_bytes(uuid_bytes)
}

/// Seed one inventory session. When `complete` is true all three shared domains
/// are marked complete with zero materialized items (count 0, hash SHA256("")).
async fn seed_session(
    pool: &PgPool,
    device: &DeviceFixture,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    complete: bool,
) -> SessionFixture {
    let inventory_session_id = derive_inventory_session_uuid(
        &device.did,
        device.device_id,
        Some(device.jkt.as_str()),
        device.auth_generation as u64,
    );
    let capability_bytes = fresh_blob();
    let capability = URL_SAFE_NO_PAD.encode(&capability_bytes);
    let capability_hash = Sha256::digest(&capability_bytes).to_vec();
    let empty_hash = Sha256::digest([]).to_vec();
    let device_created_at: DateTime<Utc> = sqlx::query_scalar(
        "SELECT created_at FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&device.did)
    .bind(device.device_id)
    .fetch_one(pool)
    .await
    .expect("read session device creation timestamp");
    let device_session_floor = if device_created_at.timestamp_subsec_nanos() == 0 {
        device_created_at
    } else {
        device_created_at + Duration::seconds(1)
            - Duration::nanoseconds(i64::from(device_created_at.timestamp_subsec_nanos()))
    };
    // Sealed inventory-session bindings use whole-second timestamps, matching
    // the production `unix_seconds` validation. The session must also be no
    // earlier than the device row for the deferred identity trigger.
    let mut created_at = created_at
        .with_nanosecond(0)
        .expect("normalize session creation timestamp");
    if created_at < device_session_floor {
        created_at = device_session_floor;
    }
    let expires_at = expires_at
        .with_nanosecond(0)
        .expect("normalize session expiry timestamp");

    // Completion evidence is all-or-nothing per domain; a complete-with-zero
    // domain carries count 0 and the empty-string SHA-256.
    let (conv_count, conv_hash, wel_count, wel_hash, rec_count, rec_hash): (
        Option<i64>,
        Option<Vec<u8>>,
        Option<i64>,
        Option<Vec<u8>>,
        Option<i64>,
        Option<Vec<u8>>,
    ) = if complete {
        (
            Some(0),
            Some(empty_hash.clone()),
            Some(0),
            Some(empty_hash.clone()),
            Some(0),
            Some(empty_hash.clone()),
        )
    } else {
        (None, None, None, None, None, None)
    };

    let (protocol_instance_id, cursor_key_id, retained_floor): (Uuid, String, i64) =
        sqlx::query_as(
            "SELECT protocol_instance_id, cursor_key_id, retained_floor FROM chat.protocol_instances JOIN chat.event_retention USING (protocol_instance_id) WHERE singleton = TRUE",
        )
        .fetch_one(pool)
        .await
        .expect("read protocol fence");
    let snapshot_event_position: i64 =
        sqlx::query_scalar("SELECT coalesce(max(event_position), 0)::bigint FROM chat.events")
            .fetch_one(pool)
            .await
            .expect("read event head for sealed session");
    let key_id: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&cursor_key_id)
        .expect("decode cursor key id")
        .try_into()
        .expect("cursor key id is 32 bytes");
    let sealer = CursorSealer::new(key_id, Zeroizing::new([0xA5_u8; 32]))
        .expect("construct HTTP acceptance cursor sealer");
    let binding = SealerBinding::for_event_cursor_receipt(
        inventory_session_id,
        device.did.as_bytes(),
        device.device_id,
        device.jkt.as_bytes(),
        u64::try_from(device.auth_generation).expect("generation fits u64"),
        protocol_instance_id,
        cursor_key_id.as_bytes(),
        u64::try_from(snapshot_event_position).expect("event position fits u64"),
        None,
        u64::try_from(retained_floor).expect("retained floor fits u64"),
        u64::try_from(created_at.timestamp()).expect("creation timestamp fits u64"),
        u64::try_from(expires_at.timestamp()).expect("expiry timestamp fits u64"),
    )
    .expect("bind sealed session capability");
    let sealed = sealer
        .seal_successor(
            capability_bytes.as_slice(),
            &binding,
            &mut FixtureRandom(0x33),
        )
        .expect("seal session capability");
    sqlx::query(
        r#"
        INSERT INTO chat.inventory_sessions(
            inventory_session_id, token_hash, user_did, device_id, jkt, auth_generation,
            snapshot_event_position, snapshot_event_cursor_sha256, created_at, expires_at,
            protocol_instance_id, cursor_key_id, cursor_format_version, snapshot_retained_floor,
            snapshot_event_cursor_nonce, snapshot_event_cursor_ciphertext,
            conversations_complete, welcomes_complete, recovery_complete,
            conversation_item_count, conversation_items_sha256,
            welcome_item_count, welcome_items_sha256,
            recovery_item_count, recovery_items_sha256,
            conversation_payload_bytes, welcome_payload_bytes, recovery_payload_bytes,
            conversations_consumed, welcomes_consumed, recovery_consumed,
            conversations_consumed_at, welcomes_consumed_at, recovery_consumed_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,$13,$14,$15,$16,$16,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31)
        "#,
    )
    .bind(inventory_session_id)
    .bind(&capability_hash)
    .bind(&device.did)
    .bind(device.device_id)
    .bind(&device.jkt)
    .bind(device.auth_generation)
    .bind(snapshot_event_position)
    .bind(&capability_hash)
    .bind(created_at)
    .bind(expires_at)
    .bind(protocol_instance_id)
    .bind(&cursor_key_id)
    .bind(retained_floor)
    .bind(&sealed.nonce)
    .bind(&sealed.ciphertext)
    .bind(complete)
    .bind(conv_count)
    .bind(conv_hash)
    .bind(wel_count)
    .bind(wel_hash)
    .bind(rec_count)
    .bind(rec_hash)
    .bind(if complete { Some(0_i64) } else { None })
    .bind(if complete { Some(0_i64) } else { None })
    .bind(if complete { Some(0_i64) } else { None })
    .bind(complete)
    .bind(complete)
    .bind(complete)
    .bind(if complete { Some(created_at) } else { None })
    .bind(if complete { Some(created_at) } else { None })
    .bind(if complete { Some(created_at) } else { None })
    .execute(pool)
    .await
    .expect("insert inventory session");

    SessionFixture {
        inventory_session_id,
        snapshot_event_position,
        capability,
        capability_hash,
        created_at,
        expires_at,
    }
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

struct Connection {
    pool: PgPool,
    device: http::Device,
    session: SessionFixture,
    socket: ClientSocket,
    server: RunningServer,
}

async fn connect(lifetime: Duration) -> Connection {
    let pool = owned_database().await;
    let device = http::seed_device(&pool).await;
    let now = clock_now(&pool).await;
    let session = seed_session(
        &pool,
        &DeviceFixture {
            did: device.did.clone(),
            device_id: device.device_id,
            jkt: device.jkt.clone(),
            auth_generation: 1,
        },
        now,
        now + lifetime,
        true,
    )
    .await;
    while clock_now(&pool).await < session.created_at {
        sleep(StdDuration::from_millis(10)).await;
    }
    let router = http::router_for_authenticated_acceptance(pool.clone()).await;
    let (status, ticket) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &device,
            "blue.catbird.chat.getSubscriptionTicket",
            serde_json::to_vec(&json!({"actorDeviceId":device.device_id,
            "inventorySessionId":session.capability,"eventCursor":session.capability}))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "actual authenticated ticket route"
    );
    let ticket = ticket["ticket"].as_str().expect("minted ticket");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local actual router");
    let address = listener.local_addr().unwrap();
    let (shutdown, stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .expect("serve upgraded handler");
    });
    let server = RunningServer {
        shutdown: Some(shutdown),
        task,
    };
    let (socket, response) = connect_async(format!(
        "ws://{address}/xrpc/blue.catbird.chat.subscribeEvents?cursor={}&ticket={ticket}",
        session.capability
    ))
    .await
    .expect("actual TCP WebSocket upgrade");
    assert_eq!(response.status().as_u16(), 101);
    Connection {
        pool,
        device,
        session,
        socket,
        server,
    }
}

// Full rows, with stable ordering, including receipts omitted by the shared
// protocol snapshot helper. Capture AFTER upgrade consumed the one-use ticket
// and committed the initial cursor receipt; control frames must change none.
async fn durable_snapshot(pool: &PgPool) -> BTreeMap<&'static str, Value> {
    let mut snapshot = BTreeMap::new();
    for table in [
        "events",
        "event_recipients",
        "inventory_sessions",
        "subscription_tickets",
        "event_cursor_receipts",
        "event_retention",
    ] {
        let query = format!("SELECT COALESCE(jsonb_agg(row_data ORDER BY row_data::text), '[]'::jsonb) FROM (SELECT to_jsonb(row_value) AS row_data FROM chat.{table} row_value) rows");
        snapshot.insert(
            table,
            sqlx::query_scalar(&query)
                .fetch_one(pool)
                .await
                .expect("complete durable snapshot"),
        );
    }
    snapshot
}

async fn assert_snapshot_unchanged(pool: &PgPool, before: &BTreeMap<&'static str, Value>) {
    let after = durable_snapshot(pool).await;
    for (table, rows) in before {
        assert!(
            after.get(table) == Some(rows),
            "WebSocket control traffic mutated chat.{table}"
        );
    }
}

async fn wait_for_ping(socket: &mut ClientSocket, within: StdDuration) {
    timeout(within, async {
        loop {
            match socket
                .next()
                .await
                .expect("socket stays open")
                .expect("valid control frame")
            {
                Message::Ping(payload) => {
                    socket.send(Message::Pong(payload)).await.unwrap();
                    return;
                }
                Message::Pong(_) => {}
                other => panic!("expected only transport control traffic, got {other:?}"),
            }
        }
    })
    .await
    .expect("server heartbeat arrives by deadline");
}

async fn expect_transport_termination(socket: &mut ClientSocket, within: StdDuration) {
    timeout(within, async {
        loop {
            match socket.next().await {
                None | Some(Ok(Message::Close(_))) | Some(Err(WsError::ConnectionClosed | WsError::AlreadyClosed)) => return,
                // The existing authorization guard returns and drops its socket;
                // it does not promise a Close handshake on authority failure.
                Some(Err(WsError::Protocol(tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake))) => return,
                Some(Ok(Message::Pong(_))) => {}
                other => panic!("authority failure must end transport without application frames: {other:?}"),
            }
        }
    }).await.expect("handler ends transport promptly");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upgraded_handler_heartbeats_survive_polling_and_control_traffic_without_cursor_mutation_or_bursts(
) {
    let _serial = SERIAL.lock().await;
    let Connection {
        pool,
        device,
        mut socket,
        server,
        ..
    } = connect(Duration::minutes(10)).await;
    let before = durable_snapshot(&pool).await;
    assert!(
        !before["event_cursor_receipts"]
            .as_array()
            .unwrap()
            .is_empty(),
        "upgrade committed a real cursor receipt"
    );
    let started = Instant::now();
    let mut ping_times = Vec::new();
    let mut probes_sent = 0_u64;
    let mut matching_pongs = 0;
    let mut probes = std::collections::HashSet::new();
    let mut traffic = tokio::time::interval_at(
        started + StdDuration::from_secs(1),
        StdDuration::from_secs(1),
    );
    traffic.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut deadline = started + StdDuration::from_secs(35);
    while ping_times.len() < 2 {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => panic!("expected periodic heartbeat {} despite 250ms polling and 1s client traffic", ping_times.len() + 1),
            _ = traffic.tick() => {
                probes_sent += 1;
                let payload = format!("client-control-{probes_sent}").into_bytes();
                probes.insert(payload.clone());
                socket.send(Message::Ping(payload)).await.unwrap();
                socket.send(Message::Pong(b"unsolicited-client-pong".to_vec())).await.unwrap();
            }
            incoming = socket.next() => match incoming.expect("live upgraded socket").expect("control frame") {
                Message::Ping(payload) => {
                    let at = Instant::now();
                    let previous = ping_times.last().copied().unwrap_or(started);
                    assert!(at.duration_since(previous) >= StdDuration::from_secs(25), "heartbeat is periodic, not immediate or a burst");
                    ping_times.push(at);
                    socket.send(Message::Pong(payload)).await.unwrap();
                    deadline = at + StdDuration::from_secs(35);
                }
                Message::Pong(payload) => {
                    if probes.remove(&payload) { matching_pongs += 1; }
                }
                other => panic!("idle subscription emitted a non-control frame: {other:?}"),
            }
        }
    }
    assert!(
        probes_sent >= 50 && matching_pongs >= 45,
        "client Ping payloads get matching Pong while server timer progresses"
    );
    assert_snapshot_unchanged(&pool, &before).await;

    // Block this exact fixture device's FOR SHARE authority check for two
    // heartbeat periods. No customer rows or shared global fence are locked.
    let mut blocker = pool.begin().await.unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("SELECT device_id FROM chat.devices WHERE user_did=$1 AND device_id=$2 FOR UPDATE")
        .bind(&device.did)
        .bind(device.device_id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    timeout(StdDuration::from_secs(3), async {
        loop {
            let queued: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)))")
                .bind(blocker_pid).fetch_one(&pool).await.unwrap();
            if queued { break; }
            sleep(StdDuration::from_millis(20)).await;
        }
    }).await.expect("actual handler waits on exact-device authority lock");
    sleep(StdDuration::from_secs(65)).await;
    blocker.rollback().await.unwrap();
    wait_for_ping(&mut socket, StdDuration::from_secs(3)).await;
    let burst = timeout(StdDuration::from_secs(2), async {
        loop {
            match socket
                .next()
                .await
                .expect("socket remains live")
                .expect("valid frame")
            {
                Message::Pong(_) => {}
                Message::Ping(_) => return,
                other => panic!("no application frames on idle subscription: {other:?}"),
            }
        }
    })
    .await;
    assert!(
        burst.is_err(),
        "missed heartbeats must Skip rather than catch up in a burst"
    );
    assert_snapshot_unchanged(&pool, &before).await;
    socket.close(None).await.expect("client initiates Close");
    expect_transport_termination(&mut socket, StdDuration::from_secs(3)).await;
    server.stop().await;
    assert_snapshot_unchanged(&pool, &before).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upgraded_handler_stops_at_inventory_expiry_without_heartbeat_extending_authority() {
    let _serial = SERIAL.lock().await;
    let Connection {
        pool,
        mut socket,
        server,
        session,
        ..
    } = connect(Duration::seconds(6)).await;
    let before = durable_snapshot(&pool).await;
    expect_transport_termination(&mut socket, StdDuration::from_secs(8)).await;
    assert!(
        clock_now(&pool).await >= session.expires_at,
        "closure follows the existing trusted expiry fence"
    );
    server.stop().await;
    assert_snapshot_unchanged(&pool, &before).await;
}

// Model a committed revocation using the existing inventory test's complete
// G6 fixture mapping: claim, receipt, revocation, device and key commit together.
// This is state setup for the socket guard, not a test of revocation admission.
// The ticket and upgrade above still use the real service-authenticated routes.
async fn seed_committed_revocation(pool: &PgPool, device: &http::Device) {
    let did = device.did.as_str();
    let device_id = device.device_id;
    let jkt = device.jkt.clone();
    let key_id: String = sqlx::query_scalar(
        "SELECT key_id FROM chat.device_keys WHERE user_did=$1 AND device_id=$2",
    )
    .bind(did)
    .bind(device_id)
    .fetch_one(pool)
    .await
    .expect("fixture device key");
    let accepted_at = clock_now(pool).await;
    let revocation_id = Uuid::new_v4();
    let accepted_request_bytes =
        br#"{"body":{"$type":"blue.catbird.chat.defs#deviceRevocationBody"}}"#.to_vec();
    let accepted_request_sha256: [u8; 32] = Sha256::digest(&accepted_request_bytes).into();
    let mut signing_transcript_bytes = b"CATBIRD-CHAT-DEVICE-REVOKE\0".to_vec();
    signing_transcript_bytes.extend_from_slice(&fresh_blob());
    let request_digest: [u8; 32] = Sha256::digest(&signing_transcript_bytes).into();
    let signature = [3_u8; 64];
    let response = br#"{"revoked":true}"#;
    let response_sha256: [u8; 32] = Sha256::digest(response).into();

    let mut tx = pool.begin().await.expect("begin revocation");
    // The operation claim is the receipt's parent row
    // (`idempotency_records_operation_claim_fk` is IMMEDIATE), inserted first
    // in the same transaction with the exact receipt-matching authority
    // columns the deferred mapping assert re-joins on.
    sqlx::query(
        r#"
        INSERT INTO chat.operation_claims (
            operation_id, principal_did, endpoint_nsid, mutation_kind,
            request_digest, accepted_request_sha256, signature, claimed_at
        ) VALUES ($1,$2,'blue.catbird.chat.revokeDevice',
                  'blue.catbird.chat.defs#deviceRevocationBody',$3,$4,$5,$6)
        "#,
    )
    .bind(revocation_id)
    .bind(did)
    .bind(request_digest.as_slice())
    .bind(accepted_request_sha256.as_slice())
    .bind(signature.as_slice())
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert revokeDevice operation claim");
    sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records (
            principal_did, endpoint_nsid, operation_id, request_digest,
            accepted_request_bytes, signing_transcript_bytes, signature,
            completed_status, response_bytes, response_sha256,
            historical_jkt, completed_at
        ) VALUES ($1,'blue.catbird.chat.revokeDevice',$2,$3,$4,$5,$6,200,$7,$8,$9,$10)
        "#,
    )
    .bind(did)
    .bind(revocation_id)
    .bind(request_digest.as_slice())
    .bind(&accepted_request_bytes)
    .bind(&signing_transcript_bytes)
    .bind(signature.as_slice())
    .bind(response.as_slice())
    .bind(response_sha256.as_slice())
    .bind(&jkt)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert revokeDevice receipt");
    sqlx::query(
        r#"
        INSERT INTO chat.device_revocations (
            revocation_id, actor_did, actor_device_id, actor_key_id,
            actor_auth_generation, target_did, target_device_id,
            target_auth_generation, accepted_request_bytes,
            signing_transcript_bytes, request_digest, signature,
            signed_at, accepted_at
        ) VALUES ($1,$2,$3,$4,1,$2,$3,1,$5,$6,$7,$8,$9,$9)
        "#,
    )
    .bind(revocation_id)
    .bind(did)
    .bind(device_id)
    .bind(&key_id)
    .bind(&accepted_request_bytes)
    .bind(&signing_transcript_bytes)
    .bind(request_digest.as_slice())
    .bind(signature.as_slice())
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert device revocation");
    sqlx::query(
        "UPDATE chat.devices SET status='revoked', updated_at=$3, revoked_at=$3, revocation_id=$4 \
         WHERE user_did=$1 AND device_id=$2",
    )
    .bind(did)
    .bind(device_id)
    .bind(accepted_at)
    .bind(revocation_id)
    .execute(&mut *tx)
    .await
    .expect("revoke target device");
    sqlx::query(
        "UPDATE chat.device_keys SET revoked_at=$3, revocation_id=$4 WHERE user_did=$1 AND device_id=$2",
    )
    .bind(did)
    .bind(device_id)
    .bind(accepted_at)
    .bind(revocation_id)
    .execute(&mut *tx)
    .await
    .expect("revoke target device key");
    tx.commit().await.expect("commit revocation");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upgraded_handler_stops_when_its_exact_device_is_revoked() {
    let _serial = SERIAL.lock().await;
    let Connection {
        pool,
        device,
        mut socket,
        server,
        ..
    } = connect(Duration::minutes(10)).await;
    let before = durable_snapshot(&pool).await;
    seed_committed_revocation(&pool, &device).await;
    expect_transport_termination(&mut socket, StdDuration::from_secs(3)).await;
    server.stop().await;
    assert_snapshot_unchanged(&pool, &before).await;
}
