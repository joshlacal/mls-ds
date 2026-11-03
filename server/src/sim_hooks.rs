//! Deterministic simulation hooks, clock/spawner seams, SQL wall-clock default audit,
//! and fast PostgreSQL schema reset for the Catbird MLS Hydrostatic Pressure Tank.
//!
//! Production runtimes default to [`SystemDsClock`] and [`TokioTaskSpawner`] with zero
//! behavioral change. Simulation harnesses inject [`ManualDsClock`] and [`QueuedTaskSpawner`]
//! so identical schedules and seeds produce bit-for-bit identical transcripts, sequencer
//! receipts, and fan-out task queues across isolated worker databases.
//!
//! Crash faults target client SQLite/SQLCipher state, not the PostgreSQL process
//! or host OS. [`open_sim_worker_pool`] therefore disables synchronous commit
//! only on its guarded loopback simulation pool sessions. Transaction isolation
//! and committed-row visibility are unchanged; server crash durability is outside
//! this model.

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

/// Request-local service identity and wire transport for multi-DS simulations.
///
/// Enable the `sim` feature to run independent delivery services in one process.
/// Each runtime owns its hooks; nested S2S requests enter the target runtime's
/// scope. Only HTTP/DNS are substituted: JWTs, device signatures, SSRF policy,
/// bounded decoding, and the real federation handlers remain on the normal path.
#[cfg(feature = "sim")]
pub struct SimDsHooks {
    pub service_did: String,
    pub self_endpoint: String,
    pub signing_key_pem: Option<String>,
    pub group_relay_hmac_secret: Option<String>,
    pub http_transport: SimHttpTransport,
    pub dns_resolver: SimDnsResolver,
    /// P8 plant: deliberately retain application ciphertext when pruning is due.
    pub retain_application_ciphertext: bool,
}

/// Exact HTTP request emitted by a real DS client, before network I/O.
#[cfg(feature = "sim")]
pub struct SimHttpRequest {
    pub method: http::Method,
    pub url: url::Url,
    pub headers: http::HeaderMap,
    pub body: Vec<u8>,
}

/// Route requests through real in-process routers; return an error to partition a link.
#[cfg(feature = "sim")]
pub type SimHttpTransport = Arc<
    dyn Fn(
            SimHttpRequest,
        ) -> Pin<Box<dyn Future<Output = Result<http::Response<Vec<u8>>, String>> + Send>>
        + Send
        + Sync,
>;

/// Deterministic DNS answers still pass the ordinary public-address checks.
#[cfg(feature = "sim")]
pub type SimDnsResolver = Arc<dyn Fn(&str) -> Result<Vec<std::net::IpAddr>, String> + Send + Sync>;

#[cfg(feature = "sim")]
tokio::task_local! {
    static TASK_SIM_DS: Arc<SimDsHooks>;
}

#[cfg(feature = "sim")]
thread_local! {
    static SYNC_SIM_DS: RefCell<Option<Arc<SimDsHooks>>> = const { RefCell::new(None) };
}

#[cfg(feature = "sim")]
struct SyncSimDsGuard(Option<Arc<SimDsHooks>>);

#[cfg(feature = "sim")]
impl Drop for SyncSimDsGuard {
    fn drop(&mut self) {
        SYNC_SIM_DS.with(|slot| *slot.borrow_mut() = self.0.take());
    }
}

/// Scope one DS's identity, transport, and fault plants across every await point.
#[cfg(feature = "sim")]
pub async fn scope_sim_ds<F: Future>(hooks: Arc<SimDsHooks>, fut: F) -> F::Output {
    TASK_SIM_DS.scope(hooks, fut).await
}

/// Scope synchronous runtime construction without changing process environment.
#[cfg(feature = "sim")]
pub fn with_sim_ds<R>(hooks: Arc<SimDsHooks>, f: impl FnOnce() -> R) -> R {
    let previous = SYNC_SIM_DS.with(|slot| slot.borrow_mut().replace(hooks));
    let _guard = SyncSimDsGuard(previous);
    f()
}

#[cfg(feature = "sim")]
pub fn active_sim_ds() -> Option<Arc<SimDsHooks>> {
    TASK_SIM_DS
        .try_with(Arc::clone)
        .ok()
        .or_else(|| SYNC_SIM_DS.with(|slot| slot.borrow().as_ref().map(Arc::clone)))
}

#[cfg(feature = "sim")]
pub(crate) async fn scope_optional_sim_ds<F: Future>(
    hooks: Option<Arc<SimDsHooks>>,
    fut: F,
) -> F::Output {
    match hooks {
        Some(hooks) => scope_sim_ds(hooks, fut).await,
        None => fut.await,
    }
}

#[cfg(feature = "sim")]
pub(crate) fn intercept_sim_dns(host: &str) -> Option<Result<Vec<std::net::IpAddr>, String>> {
    active_sim_ds().map(|hooks| (hooks.dns_resolver)(host))
}

#[cfg(feature = "sim")]
pub(crate) fn intercept_sim_http(
    request: &reqwest::RequestBuilder,
) -> Option<Pin<Box<dyn Future<Output = Result<reqwest::Response, String>> + Send>>> {
    let hooks = active_sim_ds()?;
    let request = request
        .try_clone()
        .ok_or_else(|| "simulation transport requires a replayable HTTP body".to_string())
        .and_then(|request| request.build().map_err(|error| error.to_string()));
    Some(Box::pin(async move {
        let request = request?;
        let body = match request.body() {
            Some(body) => body
                .as_bytes()
                .ok_or_else(|| "simulation transport requires a buffered HTTP body".to_string())?
                .to_vec(),
            None => Vec::new(),
        };
        let response = (hooks.http_transport)(SimHttpRequest {
            method: request.method().clone(),
            url: request.url().clone(),
            headers: request.headers().clone(),
            body,
        })
        .await?;
        Ok(reqwest::Response::from(response))
    }))
}

pub(crate) async fn send_reqwest(
    request: reqwest::RequestBuilder,
) -> Result<reqwest::Response, String> {
    #[cfg(feature = "sim")]
    if let Some(response) = intercept_sim_http(&request) {
        return response.await;
    }
    request.send().await.map_err(|error| error.to_string())
}

// =============================================================================
// 1. Deterministic Server Clock (`DsClock`)
// =============================================================================

/// Injectable server clock governing JWT/mutation timestamp checks, projection clocks,
/// `receivedAt` stamps, and `I13` sequencer receipt `issuedAtMs` fields.
pub trait DsClock: Send + Sync {
    /// Sample the current UTC timestamp.
    fn now_utc(&self) -> DateTime<Utc>;

    /// Advance a simulated clock to a publication horizon; wall clocks do nothing.
    fn advance_to(&self, _target: DateTime<Utc>) {}

    /// Sample the current UTC timestamp in Unix epoch milliseconds.
    fn now_millis(&self) -> i64 {
        self.now_utc().timestamp_millis()
    }

    /// Counter state owned by this deterministic clock, never shared across workers.
    fn simulation_counters(&self) -> Option<&DsClockCounters> {
        None
    }

    /// Whether this clock represents a deterministic simulation clock rather than
    /// the host wall clock (`SystemDsClock`).
    fn is_deterministic(&self) -> bool {
        self.simulation_counters().is_some()
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

/// Replay sequences owned by a deterministic clock instance.
#[derive(Debug, Default)]
pub struct DsClockCounters {
    entry_uuid: AtomicU64,
    outbound_jti: AtomicU64,
    tid_micros: AtomicU64,
    entropy: AtomicU64,
}

impl DsClockCounters {
    fn reset(&self) {
        self.entry_uuid.store(0, Ordering::SeqCst);
        self.outbound_jti.store(0, Ordering::SeqCst);
        self.tid_micros.store(0, Ordering::SeqCst);
        self.entropy.store(0, Ordering::SeqCst);
    }
}

/// Manually controlled simulation clock with atomic/synchronized stepping.
pub struct ManualDsClock {
    current: RwLock<DateTime<Utc>>,
    counters: DsClockCounters,
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
            counters: DsClockCounters::default(),
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

    /// Restart this worker's UUID, JTI, TID, and capability-entropy sequences.
    ///
    /// Call only between runs, after this clock's queued work has been drained.
    /// The current timestamp is unchanged; use [`Self::set_utc`] to rewind it.
    pub fn reset_counters(&self) {
        self.counters.reset();
    }
}

impl DsClock for ManualDsClock {
    fn now_utc(&self) -> DateTime<Utc> {
        *self.current.read().unwrap_or_else(|e| e.into_inner())
    }

    fn advance_to(&self, target: DateTime<Utc>) {
        let mut guard = self.current.write().unwrap_or_else(|e| e.into_inner());
        *guard = (*guard).max(target);
    }

    fn simulation_counters(&self) -> Option<&DsClockCounters> {
        Some(&self.counters)
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

pub fn active_scoped_clock() -> Option<Arc<dyn DsClock>> {
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
/// Production uses `Uuid::new_v4()`. A deterministic clock owns its sequence,
/// so identical worker-local schedules replay without sharing process state.
pub fn mint_entry_uuid_v4(domain: &[u8], parts: &[&[u8]]) -> Uuid {
    let Some(clock) = active_scoped_clock().filter(|clock| clock.is_deterministic()) else {
        return Uuid::new_v4();
    };
    let counters = clock
        .simulation_counters()
        .expect("deterministic clocks own simulation counters");
    let sequence = counters.entry_uuid.fetch_add(1, Ordering::SeqCst);
    deterministic_uuid_v4(
        b"CATBIRD-SIM-ENTRY-UUID-V4\0",
        clock.now_utc(),
        sequence,
        domain,
        parts,
    )
}

/// Mint an outbound JWT `jti` with a clock-local sequence, random in production.
pub(crate) fn mint_outbound_jti_uuid_v4(domain: &[u8], parts: &[&[u8]]) -> Uuid {
    let Some(clock) = active_scoped_clock().filter(|clock| clock.is_deterministic()) else {
        return Uuid::new_v4();
    };
    let counters = clock
        .simulation_counters()
        .expect("deterministic clocks own simulation counters");
    let sequence = counters.outbound_jti.fetch_add(1, Ordering::SeqCst);
    deterministic_uuid_v4(
        b"CATBIRD-SIM-JTI-UUID-V4\0",
        clock.now_utc(),
        sequence,
        domain,
        parts,
    )
}

fn deterministic_uuid_v4(
    purpose: &[u8],
    now: DateTime<Utc>,
    sequence: u64,
    domain: &[u8],
    parts: &[&[u8]],
) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(purpose);
    hasher.update(now.timestamp().to_be_bytes());
    hasher.update(now.timestamp_subsec_nanos().to_be_bytes());
    hasher.update(sequence.to_be_bytes());
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

/// Fill simulation capability entropy, leaving `output` untouched in production.
pub fn deterministic_entropy(domain: &[u8], output: &mut [u8]) -> bool {
    let Some(clock) = active_scoped_clock().filter(|clock| clock.is_deterministic()) else {
        return false;
    };
    let counters = clock
        .simulation_counters()
        .expect("deterministic clocks own simulation counters");
    let sequence = counters.entropy.fetch_add(1, Ordering::SeqCst);
    let now = clock.now_utc();
    let mut hasher = Sha256::new();
    hasher.update(b"CATBIRD-SIM-CAPABILITY-ENTROPY\0");
    hasher.update(now.timestamp().to_be_bytes());
    hasher.update(now.timestamp_subsec_nanos().to_be_bytes());
    hasher.update(sequence.to_be_bytes());
    hasher.update((domain.len() as u32).to_be_bytes());
    hasher.update(domain);
    for (block, chunk) in output.chunks_mut(32).enumerate() {
        let mut block_hasher = hasher.clone();
        block_hasher.update((block as u64).to_be_bytes());
        let digest = block_hasher.finalize();
        chunk.copy_from_slice(&digest[..chunk.len()]);
    }
    true
}

pub(crate) fn next_deterministic_tid_micros() -> Option<u64> {
    let clock = active_scoped_clock().filter(|clock| clock.is_deterministic())?;
    let counters = clock
        .simulation_counters()
        .expect("deterministic clocks own simulation counters");
    let now = clock.now_utc().timestamp_micros().max(0) as u64;
    Some(
        counters
            .tid_micros
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |last| {
                Some(now.max(last.saturating_add(1)))
            })
            .map(|last| now.max(last.saturating_add(1)))
            .expect("TID counter updates cannot fail"),
    )
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
        #[cfg(feature = "sim")]
        let fut = scope_optional_sim_ds(active_sim_ds(), fut);
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
        // Queued work captures its own clock inside the future, not on the caller.
        drive_sim_io(fut).await;
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
        #[cfg(feature = "sim")]
        let fut = match active_sim_ds() {
            Some(hooks) => Box::pin(scope_sim_ds(hooks, fut)) as BoxedTaskFuture,
            None => fut,
        };
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
    if !["catbird_sim_", SIM_DISPOSABLE_DB_PREFIX]
        .iter()
        .any(|&prefix| {
            db_name
                .strip_prefix(prefix)
                .is_some_and(|suffix| !suffix.is_empty())
        })
    {
        return Err(format!(
            "refusing database {db_name:?}: simulation databases require catbird_sim_ or sim_tank_ prefix"
        ));
    }
    Ok(())
}

fn validate_sim_reset_target(db_name: &str, server_addr: Option<&str>) -> Result<(), String> {
    validate_sim_database_name(db_name)?;
    if !server_addr
        .and_then(|addr| addr.parse::<std::net::IpAddr>().ok())
        .is_some_and(|addr| addr.is_loopback())
    {
        return Err(format!(
            "refusing simulation reset on non-loopback PostgreSQL server {server_addr:?}"
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

/// Keep the paused Tokio driver from advancing pool timers while real PostgreSQL
/// I/O is pending. This caller-owned loop has a real deadline, no spawned task,
/// and no assumption that a released connection must become idle.
pub async fn drive_sim_io<F: Future>(future: F) -> F::Output {
    let started = std::time::Instant::now();
    tokio::pin!(future);
    loop {
        tokio::select! {
            biased;
            result = &mut future => return result,
            () = tokio::task::yield_now() => {}
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "simulation I/O exceeded its 10s real-time deadline"
        );
    }
}

/// Create (if absent), migrate, and open a `max_connections(1)` worker pool for `db_name`.
///
/// Every pooled connection, including a replacement connection, runs session-local
/// `SET synchronous_commit = off` after connecting. The loopback and simulation-name
/// guards run first; no database-wide, server-wide, or production setting changes.
/// This assumes the tank crashes clients, not PostgreSQL or its host: a server/OS
/// crash could lose recently acknowledged commits with this session setting.
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

    drive_sim_io(
        PgPoolOptions::new()
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
            .connect(target_url.as_str()),
    )
    .await
    .map_err(|e| format!("connect max_connections(1) sim pool {db_name}: {e}"))
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
        drive_sim_io(async {
            self.pool.close().await;
            RESET_SQL_PLAN_CACHE
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&self.database_name);
            drop_sim_database_async(&self.maintenance_url, &self.database_name).await
        })
        .await
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

    // One physical-storage filter gates cached static DELETE plans, avoiding
    // unused-table work and dynamic replanning on every reset.
    let mut create_fn = String::with_capacity(16_384);
    create_fn.push_str(
        "CREATE OR REPLACE FUNCTION pg_temp.catbird_sim_delete(force_plan_warm boolean) RETURNS void\n\
         LANGUAGE plpgsql\n\
         SET plan_cache_mode = force_generic_plan\n\
         AS $sim_delete$\n\
         DECLARE\n\
             active_relations text[];\n\
         BEGIN\n\
             EXECUTE 'SET LOCAL session_replication_role = replica';\n\
             SELECT COALESCE(array_agg(relation_name), '{}'::text[]) INTO active_relations\n\
               FROM unnest(ARRAY[\n",
    );

    for (index, (schema, table)) in tables.iter().enumerate() {
        if index > 0 {
            create_fn.push_str(",\n");
        }
        create_fn.push_str(&format!("'\"{schema}\".\"{table}\"'"));
    }
    create_fn.push_str(
        "]::text[]) AS targets(relation_name)\n\
                  WHERE pg_relation_size(relation_name::regclass) > 0;\n",
    );
    for (schema, table) in &tables {
        create_fn.push_str(&format!(
            "    IF force_plan_warm OR '\"{schema}\".\"{table}\"' = ANY(active_relations) THEN\n\
                     DELETE FROM \"{schema}\".\"{table}\";\n\
                 END IF;\n"
        ));
    }

    if has_event_retention {
        create_fn.push_str(
            "            UPDATE chat.event_retention er\n\
                            SET retained_floor = 0, updated_at = pi.created_at\n\
                           FROM chat.protocol_instances pi\n\
                          WHERE pi.singleton = TRUE\n\
                            AND er.protocol_instance_id = pi.protocol_instance_id\n\
                            AND (er.retained_floor <> 0 OR er.updated_at <> pi.created_at);\n\
                         INSERT INTO chat.event_retention (protocol_instance_id, retained_floor, updated_at)\n\
                         SELECT protocol_instance_id, 0, created_at\n\
                           FROM chat.protocol_instances WHERE singleton = TRUE\n\
                         ON CONFLICT (protocol_instance_id) DO NOTHING;\n",
        );
    }

    create_fn.push_str(
        "END\n\
         $sim_delete$;\n\
         CREATE OR REPLACE FUNCTION pg_temp.catbird_sim_reset(force_compaction boolean) RETURNS void\n\
         LANGUAGE plpgsql\n\
         SET plan_cache_mode = force_generic_plan\n\
         AS $sim_reset$\n\
         DECLARE\n\
             targets text[] := ARRAY[]::text[];\n\
             reset_count integer := COALESCE(NULLIF(current_setting('catbird_sim.resets_since_compaction', TRUE), ''), '0')::integer;\n\
             cold_session boolean := NULLIF(current_setting('catbird_sim.resets_since_compaction', TRUE), '') IS NULL;\n\
             fast_reset boolean := FALSE;\n\
             reseed_retention boolean := FALSE;\n\
         BEGIN\n\
             IF NOT force_compaction AND NOT cold_session AND reset_count < 63 THEN\n\
                 BEGIN\n\
                     PERFORM pg_temp.catbird_sim_delete(FALSE);\n\
                     fast_reset := TRUE;\n\
                 EXCEPTION WHEN insufficient_privilege THEN\n\
                     fast_reset := FALSE;\n\
                 END;\n\
             END IF;\n\
             IF fast_reset THEN\n\
                 reset_count := reset_count + 1;\n\
             ELSE\n",
    );

    for (schema, table) in &tables {
        create_fn.push_str(&format!(
            "        IF EXISTS (SELECT 1 FROM \"{schema}\".\"{table}\" LIMIT 1)\n\
                        OR pg_relation_size('\"{schema}\".\"{table}\"'::regclass) > 0 THEN\n\
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
                     ) OR pg_relation_size('chat.event_retention') > 0 THEN\n\
                         reseed_retention := TRUE;\n\
                         IF EXISTS (SELECT 1 FROM chat.event_retention LIMIT 1)\n\
                            OR pg_relation_size('chat.event_retention') > 0 THEN\n\
                             targets := array_append(targets, '\"chat\".\"event_retention\"');\n\
                         END IF;\n\
                     END IF;\n",
        );
    }

    if has_direct_budget {
        create_fn.push_str(
            "        IF EXISTS (SELECT 1 FROM chat.direct_request_budget WHERE pending_bytes <> 0 OR retained_bytes <> 0)\n\
                        OR pg_relation_size('chat.direct_request_budget') > 0 THEN\n\
                         targets := array_append(targets, '\"chat\".\"direct_request_budget\"');\n\
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

    // Prime all static DELETE plans on the slow compaction path, after every
    // operational heap is empty. These warm-up DELETEs create no tombstones.
    create_fn.push_str(
        "        BEGIN\n\
                     PERFORM pg_temp.catbird_sim_delete(TRUE);\n\
                 EXCEPTION WHEN insufficient_privilege THEN\n\
                     NULL;\n\
                 END;\n\
                 reset_count := 0;\n\
             END IF;\n",
    );

    for (schema, seq, start_val) in &sequences {
        create_fn.push_str(&format!(
            "    PERFORM setval('\"{schema}\".\"{seq}\"', {start_val}, false);\n"
        ));
    }

    if has_direct_budget {
        create_fn.push_str(
            "    UPDATE chat.direct_request_budget\n\
                    SET pending_bytes = 0, retained_bytes = 0\n\
                  WHERE singleton = TRUE AND (pending_bytes <> 0 OR retained_bytes <> 0);\n\
                 INSERT INTO chat.direct_request_budget (singleton, pending_bytes, retained_bytes)\n\
                     VALUES (TRUE, 0, 0) ON CONFLICT (singleton) DO NOTHING;\n",
        );
    }

    create_fn.push_str(
        "    PERFORM set_config('catbird_sim.resets_since_compaction', reset_count::text, FALSE);\n\
         END\n\
         $sim_reset$;\n",
    );

    Ok(create_fn)
}

/// Reset an isolated simulation worker's schema, sequences, and scoped counters.
///
/// Checks the actual database name and server address: only `catbird_sim_*` /
/// `sim_tank_*` databases on TCP loopback are allowed, and protected names remain
/// forbidden. Privileged local workers use `SET LOCAL session_replication_role =
/// replica` plus DELETE for the steady-state fast path (target: <25ms).
///
/// Every 64th warm reset uses occupancy/storage-filtered `TRUNCATE ... RESTART
/// IDENTITY CASCADE` to bound dead tuples to 63 fast resets. Exact physical heap
/// size includes live-empty DELETE-bloated tables without relying on stale stats.
/// A fresh/replacement session first compacts existing heap storage. Call
/// [`compact_sim_postgres_schema`] to compact explicitly. Compaction and the
/// insufficient-privilege TRUNCATE fallback are not covered by the <25ms target.
///
/// A scoped clock's counters reset after success. Outside [`scope_ds_clock`],
/// call [`ManualDsClock::reset_counters`] separately. Process-global production
/// caches and seeded DID documents are untouched; deterministic requests bypass
/// the global replay/rate/typing fast paths.
pub async fn reset_sim_postgres_schema(pool: &PgPool) -> sqlx::Result<()> {
    reset_sim_postgres_schema_inner(pool, false).await
}

/// Force full worker compaction, including live-empty heaps left by fast resets.
///
/// Uses the same allowlist/loopback guard as [`reset_sim_postgres_schema`],
/// truncates occupied/nonempty heap storage, resets sequences and floors,
/// and restarts the session's 64-reset cadence at zero. This is intentionally
/// slower than a steady-state fast reset and requires no replication privilege.
pub async fn compact_sim_postgres_schema(pool: &PgPool) -> sqlx::Result<()> {
    reset_sim_postgres_schema_inner(pool, true).await
}

async fn reset_sim_postgres_schema_inner(
    pool: &PgPool,
    force_compaction: bool,
) -> sqlx::Result<()> {
    drive_sim_io(async {
        let mut conn = pool.acquire().await?;
        let (db_name, server_addr): (String, Option<String>) =
            sqlx::query_as("SELECT current_database(), host(inet_server_addr())")
                .fetch_one(&mut *conn)
                .await?;
        validate_sim_reset_target(&db_name, server_addr.as_deref())
            .map_err(|err| sqlx::Error::Configuration(err.into()))?;

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

        let reset_sql = if force_compaction {
            "BEGIN; SET LOCAL synchronous_commit = off; SELECT pg_temp.catbird_sim_reset(TRUE); COMMIT;"
        } else {
            "BEGIN; SET LOCAL synchronous_commit = off; SELECT pg_temp.catbird_sim_reset(FALSE); COMMIT;"
        };
        if let Err(err) = sqlx::raw_sql(reset_sql).execute(&mut *conn).await {
            let _ = sqlx::raw_sql("ROLLBACK;").execute(&mut *conn).await;
            let missing_session_plan = err
                .as_database_error()
                .and_then(|db_err| db_err.code())
                .is_some_and(|code| code == "42883" || code == "3F000");
            if missing_session_plan {
                sqlx::raw_sql(&create_fn).execute(&mut *conn).await?;
                sqlx::raw_sql(reset_sql)
                    .execute(&mut *conn)
                    .await?;
            } else {
                return Err(err);
            }
        }
        // Await sqlx's health check/return directly. A discarded connection is
        // valid too; unlike waiting for num_idle(), this cannot livelock on it.
        conn.return_to_pool().await;

        if let Some(clock) = active_scoped_clock() {
            if let Some(counters) = clock.simulation_counters() {
                counters.reset();
            }
        }
        Ok(())
    })
    .await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_uuid_and_entropy_sequences_are_clock_local_and_resettable() {
        fn draw(clock: Arc<ManualDsClock>) -> ([Uuid; 4], [u8; 65]) {
            with_ds_clock(clock, || {
                let uuids = [
                    mint_entry_uuid_v4(b"same-domain", &[b"same-input"]),
                    mint_outbound_jti_uuid_v4(b"same-domain", &[b"same-input"]),
                    mint_entry_uuid_v4(b"same-domain", &[b"same-input"]),
                    mint_outbound_jti_uuid_v4(b"same-domain", &[b"same-input"]),
                ];
                let mut entropy = [0; 65];
                assert!(deterministic_entropy(b"cursor", &mut entropy));
                (uuids, entropy)
            })
        }

        let now = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap();
        let first = Arc::new(ManualDsClock::new(now));
        let second = Arc::new(ManualDsClock::new(now));
        let baseline = draw(first.clone());
        assert_eq!(draw(second.clone()), baseline);
        assert_ne!(baseline.0[0], baseline.0[1]);
        assert_ne!(baseline.0[0], baseline.0[2]);
        assert_ne!(baseline.0[1], baseline.0[3]);
        first.reset_counters();
        assert_eq!(draw(first.clone()), baseline);
        assert_eq!(draw(first.clone()), draw(second.clone()));
        first.reset_counters();
        with_ds_clock(first.clone(), || {
            mint_entry_uuid_v4(b"independent-stream", &[]);
        });
        second.reset_counters();
        let first_jti = with_ds_clock(first, || mint_outbound_jti_uuid_v4(b"jti-stream", &[]));
        let second_jti = with_ds_clock(second, || mint_outbound_jti_uuid_v4(b"jti-stream", &[]));
        assert_eq!(first_jti, second_jti);
    }

    #[test]
    fn production_entropy_leaves_output_untouched() {
        let mut output = [0xa5; 33];
        assert!(!deterministic_entropy(b"cursor", &mut output));
        with_ds_clock(Arc::new(SystemDsClock), || {
            assert!(!deterministic_entropy(b"cursor", &mut output));
        });
        assert_eq!(output, [0xa5; 33]);
    }

    #[test]
    fn reset_target_requires_allowlisted_database_and_actual_loopback_address() {
        for db in ["catbird_sim_w0", "sim_tank_0123456789abcdef"] {
            for addr in ["127.0.0.1", "127.0.0.2", "::1"] {
                validate_sim_reset_target(db, Some(addr)).unwrap();
            }
            for addr in [
                None,
                Some("192.0.2.1"),
                Some("localhost"),
                Some("::ffff:192.0.2.1"),
            ] {
                assert!(validate_sim_reset_target(db, addr).is_err());
            }
        }
        for db in PROTECTED_DATABASE_NAMES.iter().copied().chain([
            "production",
            "catbird_sim_",
            "sim_tank_",
            "catbird_sim_w0;DROP DATABASE catbird",
        ]) {
            assert!(validate_sim_reset_target(db, Some("127.0.0.1")).is_err());
        }
    }

    #[cfg(feature = "sim")]
    #[tokio::test]
    async fn sim_ds_scope_isolates_nested_identities_and_intercepts_transport() {
        let hooks_a = Arc::new(SimDsHooks {
            service_did: "did:web:chat.catbird.blue#atproto_mls".to_string(),
            self_endpoint: "https://chat.catbird.blue".to_string(),
            signing_key_pem: None,
            group_relay_hmac_secret: Some("secret-a".to_string()),
            http_transport: Arc::new(|req| {
                Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(
                            serde_json::to_vec(&serde_json::json!({
                                "url": req.url.as_str(),
                            }))
                            .unwrap(),
                        )
                        .unwrap())
                })
            }),
            dns_resolver: Arc::new(|_| Ok(vec!["93.184.216.34".parse().unwrap()])),
            retain_application_ciphertext: false,
        });
        let hooks_b = Arc::new(SimDsHooks {
            service_did: "did:plc:dsbsimdeliveryaaaaaaaaaa".to_string(),
            self_endpoint: "https://ds-b.catbird.blue".to_string(),
            signing_key_pem: None,
            group_relay_hmac_secret: None,
            http_transport: Arc::new(|_| Box::pin(async { Err("partitioned".to_string()) })),
            dns_resolver: Arc::new(|_| Err("nxdomain".to_string())),
            retain_application_ciphertext: true,
        });

        scope_sim_ds(Arc::clone(&hooks_a), async {
            assert_eq!(
                crate::identity::service_did_base(),
                "did:web:chat.catbird.blue"
            );
            assert_eq!(
                crate::identity::self_endpoint(),
                "https://chat.catbird.blue"
            );
            let resp =
                send_reqwest(reqwest::Client::new().get("https://ds-b.catbird.blue/xrpc/test"))
                    .await
                    .unwrap();
            assert_eq!(resp.status().as_u16(), 200);

            scope_sim_ds(Arc::clone(&hooks_b), async {
                assert_eq!(
                    crate::identity::service_did_base(),
                    "did:plc:dsbsimdeliveryaaaaaaaaaa"
                );
                assert_eq!(
                    crate::identity::self_endpoint(),
                    "https://ds-b.catbird.blue"
                );
                assert!(send_reqwest(
                    reqwest::Client::new().get("https://chat.catbird.blue/xrpc/test")
                )
                .await
                .is_err());
            })
            .await;

            assert_eq!(
                crate::identity::service_did_base(),
                "did:web:chat.catbird.blue"
            );
        })
        .await;
    }
}
