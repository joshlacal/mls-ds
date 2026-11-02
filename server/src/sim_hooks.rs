//! Deterministic simulation hooks, clock/spawner seams, SQL wall-clock default audit,
//! and sub-millisecond PostgreSQL schema reset for the Catbird MLS Hydrostatic Pressure Tank.
//!
//! Production runtimes default to [`SystemDsClock`] and [`TokioTaskSpawner`] with zero
//! behavioral change. Simulation harnesses inject [`ManualDsClock`] and [`QueuedTaskSpawner`]
//! so identical schedules and seeds produce bit-for-bit identical transcripts, sequencer
//! receipts, and fan-out task queues across isolated worker databases.

use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    future::Future,
    path::Path,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, LazyLock, Mutex, RwLock,
    },
    time::Duration,
};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::{DateTime, TimeDelta, Utc};
use sha2::{Digest as _, Sha256};
use sqlx::{postgres::PgPoolOptions, Connection as _, PgConnection, PgPool};
use uuid::Uuid;

/// Shared databases that simulation helpers MUST NEVER create, truncate, or drop.
pub const PROTECTED_DATABASE_NAMES: &[&str] = &[
    "catbird_chat_protocol_test_20260722",
    "catbird",
    "catbird_test",
    "catbird_mls_v2_test_20260722",
    "postgres",
    "template0",
    "template1",
];

/// Reserved prefix for disposable simulation databases.
pub const SIM_DISPOSABLE_DB_PREFIX: &str = "sim_tank_";

/// Shared PostgreSQL advisory lock key on `/postgres` serializing catalog migrations
/// across concurrent test/simulator processes (`0x43415442_49524431` == `"CATBIRD1"`).
pub const SIM_MIGRATION_ADVISORY_LOCK_KEY: i64 = 0x43415442_49524431;

const DEFAULT_LOCAL_MAINTENANCE_URL: &str = "postgresql://127.0.0.1:5432/postgres";
const DEFAULT_SIM_PROTOCOL_INSTANCE_ID: Uuid = Uuid::from_bytes([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
]);
const OPERATION_CLAIM_ACTIVATION_APPROVAL: &str = "handlers-and-legacy-apis-sealed";

static IN_PROCESS_MIGRATION_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

static RESET_SQL_PLAN_CACHE: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static SIM_JTI_COUNTER: AtomicU64 = AtomicU64::new(0);

// =============================================================================
// 1. Deterministic Server Clock (`DsClock`)
// =============================================================================

/// Injectable server clock governing JWT/mutation timestamp checks, projection clocks,
/// `receivedAt` stamps, and `I13` sequencer receipt `issuedAtMs` fields.
pub trait DsClock: Send + Sync {
    /// Sample the current UTC timestamp.
    fn now_utc(&self) -> DateTime<Utc>;

    /// Sample the current UTC timestamp in Unix epoch milliseconds.
    fn now_millis(&self) -> i64 {
        self.now_utc().timestamp_millis()
    }

    /// Whether this clock represents a deterministic simulation clock rather than
    /// the host wall clock (`SystemDsClock`).
    fn is_deterministic(&self) -> bool {
        true
    }
}

/// Production wall-clock implementation delegating directly to [`Utc::now`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemDsClock;

impl DsClock for SystemDsClock {
    fn now_utc(&self) -> DateTime<Utc> {
        Utc::now()
    }

    fn is_deterministic(&self) -> bool {
        false
    }
}

/// Manually controlled simulation clock with atomic/synchronized stepping.
pub struct ManualDsClock {
    current: RwLock<DateTime<Utc>>,
}

impl std::fmt::Debug for ManualDsClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManualDsClock")
            .field("now_utc", &self.now_utc())
            .finish()
    }
}

impl ManualDsClock {
    pub fn new(initial: DateTime<Utc>) -> Self {
        Self {
            current: RwLock::new(initial),
        }
    }

    pub fn set_utc(&self, next: DateTime<Utc>) {
        let mut guard = self.current.write().unwrap_or_else(|e| e.into_inner());
        *guard = next;
    }

    pub fn advance(&self, delta: TimeDelta) {
        let mut guard = self.current.write().unwrap_or_else(|e| e.into_inner());
        *guard = guard
            .checked_add_signed(delta)
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
    }
}

impl DsClock for ManualDsClock {
    fn now_utc(&self) -> DateTime<Utc> {
        *self.current.read().unwrap_or_else(|e| e.into_inner())
    }
}

tokio::task_local! {
    static TASK_DS_CLOCK: Arc<dyn DsClock>;
}

thread_local! {
    static SYNC_DS_CLOCK: RefCell<Option<Arc<dyn DsClock>>> = const { RefCell::new(None) };
}

struct SyncClockGuard {
    previous: Option<Arc<dyn DsClock>>,
}

impl Drop for SyncClockGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        SYNC_DS_CLOCK.with(|slot| {
            *slot.borrow_mut() = previous;
        });
    }
}

/// Scope `clock` across all `.await` points of `fut`.
pub async fn scope_ds_clock<F: Future>(clock: Arc<dyn DsClock>, fut: F) -> F::Output {
    TASK_DS_CLOCK.scope(clock, fut).await
}

/// Scope `clock` across a synchronous closure `f` on the current thread.
pub fn with_ds_clock<R>(clock: Arc<dyn DsClock>, f: impl FnOnce() -> R) -> R {
    let previous = SYNC_DS_CLOCK.with(|slot| slot.borrow_mut().replace(clock));
    let _guard = SyncClockGuard { previous };
    f()
}

fn active_scoped_clock() -> Option<Arc<dyn DsClock>> {
    if let Ok(clock) = TASK_DS_CLOCK.try_with(Arc::clone) {
        return Some(clock);
    }
    SYNC_DS_CLOCK.with(|slot| slot.borrow().as_ref().map(Arc::clone))
}

/// Return the active scoped [`DsClock`]'s UTC timestamp, or [`Utc::now`] when unscoped.
pub fn current_utc() -> DateTime<Utc> {
    match active_scoped_clock() {
        Some(clock) => clock.now_utc(),
        None => Utc::now(),
    }
}

/// Whether a deterministic (non-[`SystemDsClock`]) clock is currently active on this task/thread.
pub fn is_deterministic_clock_active() -> bool {
    active_scoped_clock().is_some_and(|clock| clock.is_deterministic())
}

/// Mint a canonical RFC 4122 UUIDv4 for server-assigned transcript `entryId` fields.
///
/// Under `SystemDsClock` (production), delegates directly to `Uuid::new_v4()`.
/// Under an active deterministic `DsClock`, derives a reproducible RFC 4122 v4 UUID
/// from `(current_utc, domain, parts)` so replays produce byte-identical entries and receipts.
pub(crate) fn mint_entry_uuid_v4(domain: &[u8], parts: &[&[u8]]) -> Uuid {
    if !is_deterministic_clock_active() {
        return Uuid::new_v4();
    }
    let now = current_utc();
    let mut hasher = Sha256::new();
    hasher.update(b"CATBIRD-SIM-ENTRY-UUID-V4\0");
    hasher.update(now.timestamp().to_be_bytes());
    hasher.update(now.timestamp_subsec_nanos().to_be_bytes());
    hasher.update((domain.len() as u32).to_be_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(*part);
    }
    let digest = hasher.finalize();
    let mut bytes: [u8; 16] = digest[..16].try_into().expect("16-byte SHA-256 prefix");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

/// Mint an outbound JWT `jti` UUIDv4 (deterministic counter under `DsClock`, random otherwise).
pub(crate) fn mint_outbound_jti_uuid_v4(domain: &[u8], parts: &[&[u8]]) -> Uuid {
    if !is_deterministic_clock_active() {
        return Uuid::new_v4();
    }
    let seq = SIM_JTI_COUNTER.fetch_add(1, Ordering::SeqCst).to_be_bytes();
    let mut extended: Vec<&[u8]> = Vec::with_capacity(parts.len() + 1);
    extended.extend_from_slice(parts);
    extended.push(&seq);
    mint_entry_uuid_v4(domain, &extended)
}

// =============================================================================
// 2. Deterministic Background Task Spawner (`TaskSpawner`)
// =============================================================================

/// Boxed `Send` future submitted to a [`TaskSpawner`].
pub type BoxedTaskFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Seam for post-commit fan-out, push wakes, and SSE emit-queue consumers.
pub trait TaskSpawner: Send + Sync {
    fn spawn_box(&self, label: &'static str, fut: BoxedTaskFuture);

    /// Whether tasks are captured into a deterministic step queue rather than driven concurrently.
    fn is_queued(&self) -> bool {
        false
    }
}

/// Production spawner delegating directly to [`tokio::spawn`].
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioTaskSpawner;

impl TaskSpawner for TokioTaskSpawner {
    fn spawn_box(&self, _label: &'static str, fut: BoxedTaskFuture) {
        tokio::spawn(fut);
    }
}

/// Deterministic queue spawner capturing background futures into a FIFO `VecDeque`
/// until explicitly stepped by the simulation scheduler.
#[derive(Default)]
pub struct QueuedTaskSpawner {
    queue: Mutex<VecDeque<(&'static str, BoxedTaskFuture)>>,
}

impl std::fmt::Debug for QueuedTaskSpawner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuedTaskSpawner")
            .field("labels", &self.labels())
            .finish()
    }
}

impl QueuedTaskSpawner {
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
        }
    }

    pub fn pending_len(&self) -> usize {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn labels(&self) -> Vec<&'static str> {
        self.queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(label, _)| *label)
            .collect()
    }

    /// Pop and execute the next queued future in FIFO order. Returns `false` if empty.
    pub async fn drain_next(&self) -> bool {
        let next = {
            let mut guard = self.queue.lock().unwrap_or_else(|e| e.into_inner());
            guard.pop_front()
        };
        let Some((_label, fut)) = next else {
            return false;
        };
        fut.await;
        true
    }

    /// Drain all queued futures (including any follow-on tasks enqueued during draining).
    pub async fn drain_all(&self) -> usize {
        let mut count = 0_usize;
        while self.drain_next().await {
            count += 1;
        }
        count
    }

    /// Drop all queued futures without executing them.
    pub fn clear(&self) {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

impl TaskSpawner for QueuedTaskSpawner {
    fn spawn_box(&self, label: &'static str, fut: BoxedTaskFuture) {
        self.queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back((label, fut));
    }

    fn is_queued(&self) -> bool {
        true
    }
}

// =============================================================================
// 3. Disposable Worker DB Provisioning & Fast `< 25 ms` Schema Reset
// =============================================================================

fn resolve_local_maintenance_url(base_url: Option<&str>) -> Result<url::Url, String> {
    let raw = match base_url {
        Some(explicit) => explicit.to_owned(),
        None => std::env::var("SIM_POSTGRES_BASE_URL")
            .unwrap_or_else(|_| DEFAULT_LOCAL_MAINTENANCE_URL.to_owned()),
    };
    let mut parsed =
        url::Url::parse(&raw).map_err(|e| format!("invalid sim Postgres base URL {raw:?}: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("sim Postgres URL {raw:?} missing host"))?;
    if !matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]") {
        return Err(format!(
            "refusing non-loopback Postgres host {host:?} for simulation database"
        ));
    }
    parsed.set_path("/postgres");
    Ok(parsed)
}

fn validate_sim_database_name(db_name: &str) -> Result<(), String> {
    if PROTECTED_DATABASE_NAMES.contains(&db_name) {
        return Err(format!(
            "refusing to operate on protected database {db_name:?}"
        ));
    }
    if db_name.is_empty()
        || db_name.len() > 63
        || !db_name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(format!(
            "invalid simulation database identifier {db_name:?} (must be lowercase ASCII [a-z0-9_], <=63 chars)"
        ));
    }
    Ok(())
}

fn configured_or_default_cursor_key_id() -> String {
    std::env::var("CHAT_CURSOR_KEY_ID")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| URL_SAFE_NO_PAD.encode([0x11_u8; 32]))
}

async fn migrate_and_seed_sim_database(db_url: &str) -> Result<(), String> {
    let _in_proc = IN_PROCESS_MIGRATION_LOCK.lock().await;
    let mut maint_url = url::Url::parse(db_url).map_err(|e| e.to_string())?;
    maint_url.set_path("/postgres");

    let mut lock_conn = PgConnection::connect(maint_url.as_str())
        .await
        .map_err(|e| format!("connect maintenance DB for advisory lock: {e}"))?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(SIM_MIGRATION_ADVISORY_LOCK_KEY)
        .execute(&mut lock_conn)
        .await
        .map_err(|e| format!("acquire sim migration advisory lock: {e}"))?;

    let mut migrate_conn = PgConnection::connect(db_url)
        .await
        .map_err(|e| format!("connect target sim DB for migrations: {e}"))?;
    sqlx::query(&format!(
        "SET chat.operation_claim_activation_approved = '{OPERATION_CLAIM_ACTIVATION_APPROVAL}'"
    ))
    .execute(&mut migrate_conn)
    .await
    .map_err(|e| format!("set operation_claim_activation_approved: {e}"))?;

    let migrate_res = sqlx::migrate!("./migrations").run(&mut migrate_conn).await;
    let _ = sqlx::query("RESET chat.operation_claim_activation_approved")
        .execute(&mut migrate_conn)
        .await;

    if let Err(err) = migrate_res {
        let _ = migrate_conn.close().await;
        let _ = lock_conn.close().await;
        return Err(format!("run migrations on sim DB: {err}"));
    }

    let cursor_key_id = configured_or_default_cursor_key_id();
    let bootstrap_epoch = DateTime::parse_from_rfc3339("2026-01-01T00:00:00.000Z")
        .expect("static RFC3339 epoch")
        .with_timezone(&Utc);
    sqlx::query(
        "INSERT INTO chat.protocol_instances \
             (singleton, protocol_version, protocol_instance_id, cursor_key_id, created_at) \
         VALUES (TRUE, '1', $1, $2, $3) \
         ON CONFLICT (singleton) DO NOTHING",
    )
    .bind(DEFAULT_SIM_PROTOCOL_INSTANCE_ID)
    .bind(&cursor_key_id)
    .bind(bootstrap_epoch)
    .execute(&mut migrate_conn)
    .await
    .map_err(|e| format!("seed chat.protocol_instances: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.event_retention (protocol_instance_id, retained_floor, updated_at) \
         SELECT protocol_instance_id, 0, created_at \
           FROM chat.protocol_instances \
          WHERE singleton = TRUE \
         ON CONFLICT (protocol_instance_id) DO NOTHING",
    )
    .execute(&mut migrate_conn)
    .await
    .map_err(|e| format!("seed chat.event_retention: {e}"))?;

    let _ = migrate_conn.close().await;
    let _ = lock_conn.close().await;
    Ok(())
}

/// Create (if absent), migrate, and open a `max_connections(1)` worker pool for `db_name`.
pub async fn open_sim_worker_pool(base_url: Option<&str>, db_name: &str) -> Result<PgPool, String> {
    validate_sim_database_name(db_name)?;
    let maintenance_url = resolve_local_maintenance_url(base_url)?;

    let mut admin = PgConnection::connect(maintenance_url.as_str())
        .await
        .map_err(|e| format!("connect loopback maintenance DB: {e}"))?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)")
            .bind(db_name)
            .fetch_one(&mut admin)
            .await
            .map_err(|e| format!("check database existence for {db_name}: {e}"))?;
    if !exists {
        sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
            .execute(&mut admin)
            .await
            .map_err(|e| format!("create simulation database {db_name}: {e}"))?;
    }
    let _ = admin.close().await;

    let mut target_url = maintenance_url;
    target_url.set_path(&format!("/{db_name}"));
    migrate_and_seed_sim_database(target_url.as_str()).await?;

    // Under `#[tokio::test(flavor = "current_thread", start_paused = true)]`, `PgPoolOptions::connect`
    // wraps the initial loopback TCP handshake in `tokio::time::timeout(acquire_timeout, ...)`.
    // Keeping a lightweight yield task runnable until the handshake completes prevents Tokio's
    // paused time driver from auto-advancing `acquire_timeout` while kqueue completes the socket
    // connect, and preserves `tokio::time::Instant::now()` at +0ns.
    // Setting `test_before_acquire(false)`, `idle_timeout(None)`, and `max_lifetime(None)` ensures
    // the warm single connection stays in `idle_conns` and every subsequent `acquire()` resolves in
    // `Poll::Ready` on its first poll without registering any Tokio `Sleep` timer.
    let yield_guard = tokio::spawn(async {
        loop {
            std::thread::sleep(Duration::from_micros(50));
            tokio::task::yield_now().await;
        }
    });
    let pool_slot: Arc<Mutex<Option<sqlx::pool::Pool<sqlx::Postgres>>>> =
        Arc::new(Mutex::new(None));
    let pool_slot_for_release = Arc::clone(&pool_slot);
    let connect_res = PgPoolOptions::new()
        .max_connections(1)
        .test_before_acquire(false)
        .idle_timeout(None)
        .max_lifetime(None)
        .acquire_timeout(Duration::from_secs(10))
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                sqlx::query("SET synchronous_commit = off")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .after_release(move |_conn, _meta| {
            let pool_opt = pool_slot_for_release
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            Box::pin(async move {
                // `sqlx` runs `self.raw.ping().await` right after `after_release` before
                // releasing the single semaphore permit. Under `#[tokio::test(start_paused = true)]`,
                // keeping a micro-yield task runnable until `ping()` returns the connection to
                // `idle_conns` prevents Tokio from auto-advancing `acquire_timeout` mid-ping.
                if let Some(pool) = pool_opt {
                    tokio::spawn(async move {
                        let started = std::time::Instant::now();
                        while !pool.is_closed()
                            && pool.num_idle() == 0
                            && started.elapsed() < Duration::from_millis(250)
                        {
                            std::thread::sleep(Duration::from_micros(50));
                            tokio::task::yield_now().await;
                        }
                    });
                }
                Ok(true)
            })
        })
        .connect(target_url.as_str())
        .await;
    yield_guard.abort();
    let _ = yield_guard.await;

    let pool =
        connect_res.map_err(|e| format!("connect max_connections(1) sim pool {db_name}: {e}"))?;
    *pool_slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(pool.clone());
    Ok(pool)
}

/// Isolated disposable simulation PostgreSQL database with `max_connections(1)` and RAII drop reaper.
pub struct DisposableSimPool {
    pool: PgPool,
    maintenance_url: String,
    database_name: String,
    max_connections: u32,
    cleaned_up: bool,
}

impl DisposableSimPool {
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn database_name(&self) -> &str {
        &self.database_name
    }

    pub fn max_connections(&self) -> u32 {
        self.max_connections
    }

    /// Explicitly close the pool and drop the disposable simulation database.
    pub async fn cleanup(mut self) -> Result<(), String> {
        self.cleaned_up = true;
        validate_sim_database_name(&self.database_name)?;
        self.pool.close().await;
        RESET_SQL_PLAN_CACHE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.database_name);
        drop_sim_database_async(&self.maintenance_url, &self.database_name).await
    }
}

impl Drop for DisposableSimPool {
    fn drop(&mut self) {
        if self.cleaned_up {
            return;
        }
        if validate_sim_database_name(&self.database_name).is_err() {
            return;
        }
        let maintenance_url = self.maintenance_url.clone();
        let db_name = self.database_name.clone();
        RESET_SQL_PLAN_CACHE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&db_name);
        let _ = std::thread::spawn(move || {
            if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                let _ = rt.block_on(drop_sim_database_async(&maintenance_url, &db_name));
            }
        })
        .join();
    }
}

async fn drop_sim_database_async(maintenance_url: &str, db_name: &str) -> Result<(), String> {
    validate_sim_database_name(db_name)?;
    let mut admin = PgConnection::connect(maintenance_url)
        .await
        .map_err(|e| format!("connect maintenance DB for cleanup of {db_name}: {e}"))?;
    let _ = sqlx::query(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
         WHERE datname = $1 AND pid <> pg_backend_pid()",
    )
    .bind(db_name)
    .execute(&mut admin)
    .await;
    sqlx::query(&format!("DROP DATABASE IF EXISTS \"{db_name}\""))
        .execute(&mut admin)
        .await
        .map_err(|e| format!("drop simulation database {db_name}: {e}"))?;
    let _ = admin.close().await;
    Ok(())
}

/// Mint a fresh uniquely named disposable database (`sim_tank_<32hex>`), migrate it,
/// seed its protocol fence, and open a `max_connections(1)` pool.
pub async fn open_disposable_sim_pool(base_url: Option<&str>) -> Result<DisposableSimPool, String> {
    let maintenance_url = resolve_local_maintenance_url(base_url)?;
    let database_name = format!("{SIM_DISPOSABLE_DB_PREFIX}{}", Uuid::new_v4().simple());
    let pool = match open_sim_worker_pool(Some(maintenance_url.as_str()), &database_name).await {
        Ok(pool) => pool,
        Err(err) => {
            let _ = drop_sim_database_async(maintenance_url.as_str(), &database_name).await;
            return Err(err);
        }
    };
    Ok(DisposableSimPool {
        pool,
        maintenance_url: maintenance_url.into(),
        database_name,
        max_connections: 1,
        cleaned_up: false,
    })
}

async fn build_reset_sql_batch(conn: &mut PgConnection) -> sqlx::Result<String> {
    let tables: Vec<(String, String)> = sqlx::query_as(
        "SELECT schemaname, tablename \
           FROM pg_tables \
          WHERE schemaname IN ('public', 'chat', 'labyrinth', 'federation') \
            AND NOT (schemaname = 'public' AND tablename IN ('_sqlx_migrations', 'schema_version')) \
            AND NOT (schemaname = 'chat' AND tablename IN ( \
                'operation_claim_completeness_cutover', \
                'protocol_instances', \
                'direct_request_budget', \
                'event_retention' \
            )) \
          ORDER BY schemaname ASC, tablename ASC",
    )
    .fetch_all(&mut *conn)
    .await?;

    let sequences: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT schemaname, sequencename, start_value \
           FROM pg_sequences \
          WHERE schemaname IN ('public', 'chat', 'labyrinth', 'federation') \
          ORDER BY schemaname ASC, sequencename ASC",
    )
    .fetch_all(&mut *conn)
    .await?;

    let has_direct_budget = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS( \
             SELECT 1 FROM pg_tables \
              WHERE schemaname = 'chat' AND tablename = 'direct_request_budget' \
         )",
    )
    .fetch_one(&mut *conn)
    .await?;

    let has_event_retention = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS( \
             SELECT 1 FROM pg_tables \
              WHERE schemaname = 'chat' AND tablename = 'event_retention' \
         ) AND EXISTS( \
             SELECT 1 FROM pg_tables \
              WHERE schemaname = 'chat' AND tablename = 'protocol_instances' \
         )",
    )
    .fetch_one(&mut *conn)
    .await?;

    // Compile a session-local `pg_temp.catbird_sim_reset()` PL/pgSQL function so PostgreSQL caches
    // the query plans for all `EXISTS (SELECT 1 ... LIMIT 1)` occupancy probes across resets
    // (~1.5-3 ms steady-state instead of ~20 ms anonymous-DO re-parse overhead).
    let mut create_fn = String::with_capacity(12_288);
    create_fn.push_str(
        "CREATE OR REPLACE FUNCTION pg_temp.catbird_sim_reset() RETURNS void\n\
         LANGUAGE plpgsql\n\
         SET plan_cache_mode = force_generic_plan\n\
         AS $sim_reset$\n\
         DECLARE\n\
             targets text[] := ARRAY[]::text[];\n\
             reseed_retention boolean := FALSE;\n\
         BEGIN\n\
             BEGIN\n\
                 EXECUTE 'SET LOCAL session_replication_role = replica';\n",
    );

    for (schema, table) in &tables {
        create_fn.push_str(&format!("        DELETE FROM \"{schema}\".\"{table}\";\n"));
    }

    if has_event_retention {
        create_fn.push_str(
            "        UPDATE chat.event_retention er\n\
                        SET retained_floor = 0, updated_at = pi.created_at\n\
                       FROM chat.protocol_instances pi\n\
                      WHERE pi.singleton = TRUE\n\
                        AND er.protocol_instance_id = pi.protocol_instance_id\n\
                        AND (er.retained_floor <> 0 OR er.updated_at <> pi.created_at);\n",
        );
    }

    create_fn.push_str("    EXCEPTION WHEN insufficient_privilege THEN\n");

    for (schema, table) in &tables {
        create_fn.push_str(&format!(
            "        IF EXISTS (SELECT 1 FROM \"{schema}\".\"{table}\" LIMIT 1) THEN\n\
                         targets := array_append(targets, '\"{schema}\".\"{table}\"');\n\
                     END IF;\n"
        ));
    }

    if has_event_retention {
        create_fn.push_str(
            "        IF NOT EXISTS (\n\
                         SELECT 1 FROM chat.event_retention er\n\
                           JOIN chat.protocol_instances pi\n\
                             ON pi.protocol_instance_id = er.protocol_instance_id\n\
                          WHERE pi.singleton = TRUE\n\
                            AND er.retained_floor = 0\n\
                            AND er.updated_at = pi.created_at\n\
                     ) THEN\n\
                         targets := array_append(targets, '\"chat\".\"event_retention\"');\n\
                         reseed_retention := TRUE;\n\
                     END IF;\n",
        );
    }

    create_fn.push_str(
        "        IF array_length(targets, 1) IS NOT NULL THEN\n\
                     EXECUTE 'TRUNCATE TABLE ' || array_to_string(targets, ', ') || ' RESTART IDENTITY CASCADE';\n\
                 END IF;\n",
    );

    if has_event_retention {
        create_fn.push_str(
            "        IF reseed_retention THEN\n\
                         INSERT INTO chat.event_retention (protocol_instance_id, retained_floor, updated_at)\n\
                         SELECT protocol_instance_id, 0, created_at\n\
                           FROM chat.protocol_instances\n\
                          WHERE singleton = TRUE\n\
                         ON CONFLICT (protocol_instance_id) DO NOTHING;\n\
                     END IF;\n",
        );
    }

    create_fn.push_str("    END;\n");

    for (schema, seq, start_val) in &sequences {
        create_fn.push_str(&format!(
            "    PERFORM setval('\"{schema}\".\"{seq}\"', {start_val}, false);\n"
        ));
    }

    if has_direct_budget {
        create_fn.push_str(
            "    UPDATE chat.direct_request_budget\n\
                    SET pending_bytes = 0, retained_bytes = 0\n\
                  WHERE singleton = TRUE\n\
                    AND (pending_bytes <> 0 OR retained_bytes <> 0);\n",
        );
    }

    create_fn.push_str(
        "END\n\
         $sim_reset$;\n",
    );

    Ok(create_fn)
}

/// Sub-25ms schema + in-memory cache reset over a simulation worker pool (`max_connections(1)`).
///
/// Refuses every database listed in [`PROTECTED_DATABASE_NAMES`]. Truncates all operational
/// `chat.*`, `labyrinth.*`, `federation.*`, and `public.*` tables with `RESTART IDENTITY CASCADE`,
/// restarts standalone sequences, restores singleton budget/retention floors, and clears all
/// process-local JTI, rate-limiter, typing, and TID caches while keeping seeded DID documents intact.
pub async fn reset_sim_postgres_schema(pool: &PgPool) -> sqlx::Result<()> {
    let mut conn = pool.acquire().await?;
    let db_name: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&mut *conn)
        .await?;
    if PROTECTED_DATABASE_NAMES.contains(&db_name.as_str()) {
        return Err(sqlx::Error::Configuration(
            format!("refusing reset_sim_postgres_schema on protected database {db_name:?}").into(),
        ));
    }

    let cached_create_fn = {
        RESET_SQL_PLAN_CACHE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&db_name)
            .cloned()
    };
    let create_fn = match cached_create_fn {
        Some(plan) => plan,
        None => {
            let plan = build_reset_sql_batch(&mut conn).await?;
            sqlx::raw_sql(&plan).execute(&mut *conn).await?;
            RESET_SQL_PLAN_CACHE
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(db_name, plan.clone());
            plan
        }
    };

    const CALL_FAST_RESET_SQL: &str =
        "BEGIN; SET LOCAL synchronous_commit = off; SELECT pg_temp.catbird_sim_reset(); COMMIT;";
    if let Err(err) = sqlx::raw_sql(CALL_FAST_RESET_SQL).execute(&mut *conn).await {
        let _ = sqlx::raw_sql("ROLLBACK;").execute(&mut *conn).await;
        let is_undefined_fn = err
            .as_database_error()
            .and_then(|db_err| db_err.code())
            .is_some_and(|code| code == "42883");
        if is_undefined_fn {
            sqlx::raw_sql(&create_fn).execute(&mut *conn).await?;
            sqlx::raw_sql(CALL_FAST_RESET_SQL)
                .execute(&mut *conn)
                .await?;
        } else {
            return Err(err);
        }
    }
    drop(conn);
    while !pool.is_closed() && pool.num_idle() == 0 {
        tokio::task::yield_now().await;
    }

    crate::auth::clear_sim_auth_caches();
    crate::middleware::rate_limit::clear_all_rate_limiters();
    crate::chat_protocol::repository::message_delivery::clear_ephemeral_typing_state();
    crate::labyrinth::tid::reset_tid_state();
    SIM_JTI_COUNTER.store(0, Ordering::SeqCst);

    Ok(())
}

// =============================================================================
// 4. SQL Wall-Clock Default Audit (`migrations/*.sql` + Live `information_schema`)
// =============================================================================

/// Reviewed operational/bootstrap/historical column defaults in `chat.*` and `labyrinth.*`
/// migrations that never stamp transcript entries or sequencer receipts without explicit app binds.
pub const REVIEWED_SQL_TIMESTAMP_DEFAULT_SITES: &[(&str, &str)] = &[
    // Bootstrap singleton row; sim seeding binds an explicit deterministic epoch.
    (
        "20260722000001_chat_protocol_core.sql",
        "chat.protocol_instances.created_at",
    ),
    // Legacy blob table dropped by `20261031200001_clean_slate_spaces_only.sql`.
    (
        "20260722000003_chat_protocol_blobs.sql",
        "chat.blob_usage.updated_at",
    ),
    // Internal S2S direct-request staging/inbox operational metadata (non-transcript).
    (
        "20260919000022_federated_transport_inbox.sql",
        "chat.direct_request_remote_leases.leased_at",
    ),
    (
        "20260919000022_federated_transport_inbox.sql",
        "chat.direct_request_transport_inbox.created_at",
    ),
    (
        "20260919000022_federated_transport_inbox.sql",
        "chat.direct_request_transport_inbox.updated_at",
    ),
    (
        "20260919000022_federated_transport_inbox.sql",
        "chat.direct_request_transport_entries.created_at",
    ),
    (
        "20260919000023_expired_federated_lease_release.sql",
        "chat.direct_request_outbound_routes.created_at",
    ),
    (
        "20260919000024_c33_coordinator_hardening.sql",
        "chat.direct_request_reservation_intents.created_at",
    ),
    (
        "20260919000024_c33_coordinator_hardening.sql",
        "chat.direct_request_reserved_remote_packages.created_at",
    ),
    // Legacy ORF tombstone table dropped by `20261031200001_clean_slate_spaces_only.sql`.
    (
        "20261004100009_labyrinth_review2_hardening.sql",
        "labyrinth.orf_state_tombstones.deleted_at",
    ),
    // Operational backfill defaults; runtime handlers bind explicit `DsClock` instants on write/update.
    (
        "20261031200001_clean_slate_spaces_only.sql",
        "chat.devices.last_active_at",
    ),
    (
        "20261031200002_space_host_operational_state.sql",
        "chat.conversation_space_syncers.expires_at",
    ),
];

/// Reviewed live catalog operational columns permitted to carry a PostgreSQL backfill default.
pub const REVIEWED_LIVE_CATALOG_TIMESTAMP_DEFAULTS: &[(&str, &str, &str)] = &[
    ("chat", "protocol_instances", "created_at"),
    ("chat", "devices", "last_active_at"),
    ("chat", "conversation_space_syncers", "expires_at"),
    ("chat", "direct_request_remote_leases", "leased_at"),
    ("chat", "direct_request_transport_inbox", "created_at"),
    ("chat", "direct_request_transport_inbox", "updated_at"),
    ("chat", "direct_request_transport_entries", "created_at"),
    ("chat", "direct_request_outbound_routes", "created_at"),
    ("chat", "direct_request_reservation_intents", "created_at"),
    (
        "chat",
        "direct_request_reserved_remote_packages",
        "created_at",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlTimestampAuditReport {
    pub scanned_migration_files: usize,
    pub reviewed_allowlisted_defaults: Vec<String>,
    pub unreviewed_protocol_defaults: Vec<String>,
}

fn contains_wall_clock_default(lower_line: &str) -> bool {
    let Some(idx) = lower_line.find("default") else {
        return false;
    };
    let after = &lower_line[idx + "default".len()..];
    after.contains("now()")
        || after.contains("current_timestamp")
        || after.contains("clock_timestamp()")
        || after.contains("statement_timestamp()")
        || after.contains("transaction_timestamp()")
}

fn extract_qualified_table(lower_trimmed: &str, prefix: &str) -> Option<String> {
    let rest = lower_trimmed.strip_prefix(prefix)?.trim_start();
    let rest = rest
        .strip_prefix("if not exists")
        .map(str::trim_start)
        .unwrap_or(rest);
    let rest = rest
        .strip_prefix("if exists")
        .map(str::trim_start)
        .unwrap_or(rest);
    let token: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
        .collect();
    if token.starts_with("chat.")
        || token.starts_with("labyrinth.")
        || token.starts_with("federation.")
    {
        Some(token)
    } else {
        None
    }
}

fn extract_column_name_from_ddl_line(trimmed: &str) -> Option<String> {
    let lower = trimmed.to_ascii_lowercase();
    let rest = if let Some(after_add) = lower.strip_prefix("add column") {
        let after_add = after_add.trim_start();
        after_add
            .strip_prefix("if not exists")
            .map(str::trim_start)
            .unwrap_or(after_add)
    } else if let Some(after_alter) = lower.strip_prefix("alter column") {
        after_alter.trim_start()
    } else {
        lower.as_str()
    };
    let col: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if col.is_empty()
        || matches!(
            col.as_str(),
            "constraint" | "primary" | "unique" | "check" | "foreign"
        )
    {
        None
    } else {
        Some(col)
    }
}

/// Scan `migrations/*.sql` to verify no unreviewed `DEFAULT now()` / `DEFAULT CURRENT_TIMESTAMP` /
/// `DEFAULT clock_timestamp()` column defaults exist on `chat.*`, `labyrinth.*`, or `federation.*` tables.
pub fn audit_sql_timestamp_defaults(
    migrations_dir: &Path,
) -> Result<SqlTimestampAuditReport, String> {
    let mut entries: Vec<_> = std::fs::read_dir(migrations_dir)
        .map_err(|e| {
            format!(
                "read migrations directory {}: {e}",
                migrations_dir.display()
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("iterate migrations directory: {e}"))?;
    entries.sort_by_key(|e| e.file_name());

    let mut scanned_migration_files = 0_usize;
    let mut reviewed_allowlisted_defaults = Vec::new();
    let mut unreviewed_protocol_defaults = Vec::new();

    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("sql") {
            continue;
        }
        scanned_migration_files += 1;
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| format!("read migration {}: {e}", path.display()))?;

        let mut in_dollar_block = false;
        let mut active_table: Option<String> = None;

        for (line_idx, raw_line) in contents.lines().enumerate() {
            let without_comment = raw_line.split("--").next().unwrap_or("");
            let trimmed = without_comment.trim();
            if trimmed.is_empty() {
                continue;
            }
            if without_comment.matches("$$").count() % 2 == 1 {
                in_dollar_block = !in_dollar_block;
                continue;
            }
            if in_dollar_block {
                continue;
            }

            let lower = trimmed.to_ascii_lowercase();
            if let Some(tbl) = extract_qualified_table(&lower, "create table")
                .or_else(|| extract_qualified_table(&lower, "alter table"))
            {
                active_table = Some(tbl);
            } else if lower.starts_with("create table ")
                || lower.starts_with("alter table ")
                || lower.starts_with("create index ")
                || lower.starts_with("create unique index ")
                || lower.starts_with("drop table ")
            {
                active_table = None;
            }

            if let Some(ref table) = active_table {
                if contains_wall_clock_default(&lower) {
                    let col = extract_column_name_from_ddl_line(trimmed)
                        .unwrap_or_else(|| format!("line_{}", line_idx + 1));
                    let qualified_col = format!("{table}.{col}");
                    let is_reviewed = REVIEWED_SQL_TIMESTAMP_DEFAULT_SITES
                        .iter()
                        .any(|(f, q)| *f == file_name && *q == qualified_col);
                    let descriptor = format!("{file_name}:{} ({qualified_col})", line_idx + 1);
                    if is_reviewed {
                        reviewed_allowlisted_defaults.push(descriptor);
                    } else {
                        unreviewed_protocol_defaults.push(descriptor);
                    }
                }
            }

            if trimmed.ends_with(';') {
                active_table = None;
            }
        }
    }

    Ok(SqlTimestampAuditReport {
        scanned_migration_files,
        reviewed_allowlisted_defaults,
        unreviewed_protocol_defaults,
    })
}

/// Query live `information_schema.columns` on a migrated database and return any unreviewed
/// wall-clock `column_default` on `chat.*`, `labyrinth.*`, or `federation.*` tables.
pub async fn audit_live_catalog_timestamp_defaults(
    pool: &PgPool,
) -> Result<Vec<(String, String, String)>, sqlx::Error> {
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT table_schema, table_name, column_name, column_default \
           FROM information_schema.columns \
          WHERE table_schema IN ('chat', 'labyrinth', 'federation') \
            AND column_default IS NOT NULL \
          ORDER BY table_schema ASC, table_name ASC, ordinal_position ASC",
    )
    .fetch_all(pool)
    .await?;

    let mut violations = Vec::new();
    for (schema, table, column, default_expr) in rows {
        let lower = default_expr.to_ascii_lowercase();
        let uses_wall_clock = lower.contains("now()")
            || lower.contains("current_timestamp")
            || lower.contains("clock_timestamp()")
            || lower.contains("statement_timestamp()")
            || lower.contains("transaction_timestamp()");
        if !uses_wall_clock {
            continue;
        }
        let is_reviewed = REVIEWED_LIVE_CATALOG_TIMESTAMP_DEFAULTS
            .iter()
            .any(|(s, t, c)| *s == schema && *t == table && *c == column);
        if !is_reviewed {
            violations.push((schema, table, column));
        }
    }
    Ok(violations)
}

// =============================================================================
// 5. Simulation Actor & Transcript Signing Helpers (No `test-support` Feature Needed)
// =============================================================================

/// Seed a synthetic actor [`crate::auth::DidDocument`] into the server's DID cache for
/// offline deterministic simulation without outbound PLC/HTTPS calls.
pub async fn seed_sim_did_document(doc: crate::auth::DidDocument) {
    crate::auth::cache_sim_did_document(doc).await;
}

/// Derive the canonical 43-character base64url RFC 8037 OKP Ed25519 key thumbprint (`keyId`)
/// for a 32-byte Ed25519 verifying key.
pub fn derive_sim_ed25519_key_id(public_key_bytes: &[u8; 32]) -> Result<String, String> {
    crate::chat_protocol::validation::ed25519_key_id(public_key_bytes)
        .map(|kt| kt.as_str().to_owned())
        .map_err(|e| format!("invalid Ed25519 public key for keyId: {e:?}"))
}

/// Project `body` through the server's canonical `blue.catbird.chat.*` DAG-CBOR transcript
/// projector, sign the domain-separated transcript with `signing_key`, and return the canonical
/// JSON `{"body": ..., "signature": ...}` wrapper bytes.
pub fn sign_sim_chat_body(
    body: serde_json::Value,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<Vec<u8>, String> {
    use ed25519_dalek::Signer as _;

    let placeholder = serde_json::to_vec(&serde_json::json!({
        "body": body.clone(),
        "signature": STANDARD.encode([0_u8; 64]),
    }))
    .map_err(|e| format!("encode placeholder signed wrapper: {e}"))?;
    let canonical =
        crate::chat_protocol::transcript::decode_canonical_signed_mutation(&placeholder)
            .map_err(|e| format!("canonical signed mutation projection failed: {e:?}"))?;
    let signature = signing_key.sign(canonical.transcript_bytes());
    serde_json::to_vec(&serde_json::json!({
        "body": body,
        "signature": STANDARD.encode(signature.to_bytes()),
    }))
    .map_err(|e| format!("encode signed wrapper: {e}"))
}
