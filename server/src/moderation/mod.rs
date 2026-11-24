//! Operator account moderation, driven by the Catbird Ozone instance.
//!
//! Reports never reach this server. Users report through their PDS straight
//! to Ozone, carrying only DIDs and ids, never message content. When the
//! operator takes an account down in Ozone, Ozone emits a `!takedown` (or
//! timed `!suspend`) label on the account DID. A background poller re-reads
//! those labels from `com.atproto.label.queryLabels` into
//! `moderation.account_labels`, and service-auth admission refuses any
//! account whose latest enforced label is live.
//!
//! Ozone must run with `OZONE_LABEL_QUERY_WILDCARDS_ENABLED=true`, since the
//! poller asks for labels by DID prefix.
//!
//! When `MODERATION_LABELER_DID` / `MODERATION_LABELER_URL` are unset the
//! poller does not run, startup clears stored labels, and nothing is
//! restricted.

pub mod labels;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::storage::DbPool;
use labels::{
    account_label_event, parse_enforced_labels, AccountLabelEvent, LabelBucket, QueryLabelsOutput,
};

/// Largest `queryLabels` page body we will read.
const MAX_PAGE_BYTES: usize = 4 * 1024 * 1024;
/// Page size requested from Ozone (the lexicon maximum is 250).
const PAGE_LIMIT: usize = 250;
/// Upper bound on `queryLabels` requests in one reconcile pass.
const MAX_REQUESTS_PER_RECONCILE: usize = 2_000;

/// Configuration for following the operator's Ozone labels.
#[derive(Debug, Clone)]
pub struct ModerationLabelConfig {
    /// DID of the Ozone service account (labels are only trusted from it).
    pub labeler_did: String,
    /// Base URL of the Ozone service, e.g. `https://ozone.catbird.blue`.
    pub labeler_url: String,
    /// Label values that lock an account out.
    pub enforced_labels: Vec<String>,
    /// How often to re-read the labeler's full account-label set.
    pub poll_interval: Duration,
}

impl ModerationLabelConfig {
    /// `None` when moderation is not configured.
    pub fn from_env() -> Option<Self> {
        let labeler_did = std::env::var("MODERATION_LABELER_DID")
            .ok()
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())?;
        let labeler_url = std::env::var("MODERATION_LABELER_URL")
            .ok()
            .map(|v| v.trim().trim_end_matches('/').to_owned())
            .filter(|v| !v.is_empty())?;
        if !labels::is_account_did(&labeler_did) {
            tracing::error!(
                "MODERATION_LABELER_DID is not a did:plc or did:web; moderation disabled"
            );
            return None;
        }
        if !labeler_url.starts_with("https://") && !labeler_url.starts_with("http://127.0.0.1") {
            tracing::error!("MODERATION_LABELER_URL must be https; moderation disabled");
            return None;
        }
        let secs = |name: &str, default: u64| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(default)
        };
        Some(Self {
            labeler_did,
            labeler_url,
            enforced_labels: parse_enforced_labels(
                std::env::var("MODERATION_ENFORCED_LABELS").ok().as_deref(),
            ),
            poll_interval: Duration::from_secs(secs("MODERATION_LABEL_POLL_SECS", 30)),
        })
    }
}

/// Drop stored labels the current configuration no longer trusts or
/// enforces: rows from another labeler, or values outside
/// `MODERATION_ENFORCED_LABELS`. With moderation unconfigured every row goes,
/// so removing the configuration lifts enforcement. Run once at startup,
/// before the poller; the next reconcile restores anything still in force.
pub async fn prune_to_config(
    pool: &DbPool,
    cfg: Option<&ModerationLabelConfig>,
) -> Result<u64, sqlx::Error> {
    let result = match cfg {
        Some(cfg) => {
            sqlx::query(
                "DELETE FROM moderation.account_labels \
                  WHERE src <> $1 OR NOT (val = ANY($2))",
            )
            .bind(&cfg.labeler_did)
            .bind(&cfg.enforced_labels)
            .execute(pool)
            .await?
        }
        None => {
            sqlx::query("DELETE FROM moderation.account_labels")
                .execute(pool)
                .await?
        }
    };
    Ok(result.rows_affected())
}

/// Whether this process enforces Ozone labels. Set once at startup from
/// [`ModerationLabelConfig::from_env`]. While it is off the stored-label table
/// is empty (startup prunes it), so admission skips the lookup entirely.
static ENFORCEMENT_ENABLED: AtomicBool = AtomicBool::new(false);

/// Turn label enforcement on or off for this process.
pub fn set_enforcement_enabled(enabled: bool) {
    ENFORCEMENT_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Whether admission should look up account labels at all.
pub fn enforcement_enabled() -> bool {
    ENFORCEMENT_ENABLED.load(Ordering::Relaxed)
}

/// Endpoints a restricted account may still call. Deleting one's own data
/// must always work.
pub fn exempt_from_account_restriction(endpoint_nsid: &str) -> bool {
    endpoint_nsid == "blue.catbird.labyrinth.deleteAccountData"
}

/// Whether `did` is currently locked out by the operator.
pub async fn is_account_restricted(pool: &DbPool, did: &str) -> Result<bool, sqlx::Error> {
    let now = crate::sim_hooks::current_utc();
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM moderation.account_labels \
          WHERE did = $1 AND NOT neg AND (exp IS NULL OR exp > $2))",
    )
    .bind(did)
    .bind(now)
    .fetch_one(pool)
    .await
}

/// Store one label event if it is at least as new as what we hold.
pub async fn apply_label_event(pool: &DbPool, ev: &AccountLabelEvent) -> Result<(), sqlx::Error> {
    let now = crate::sim_hooks::current_utc();
    sqlx::query(
        "INSERT INTO moderation.account_labels (src, did, val, cts, exp, neg, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (src, did, val) DO UPDATE \
            SET cts = EXCLUDED.cts, exp = EXCLUDED.exp, neg = EXCLUDED.neg, \
                updated_at = EXCLUDED.updated_at \
          WHERE moderation.account_labels.cts <= EXCLUDED.cts",
    )
    .bind(&ev.src)
    .bind(&ev.did)
    .bind(&ev.val)
    .bind(ev.cts)
    .bind(ev.exp)
    .bind(ev.neg)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Why a reconcile pass stopped early. Already-applied labels are kept.
#[derive(Debug)]
enum ReconcileError {
    /// Ozone refuses wildcard `queryLabels` patterns.
    WildcardsDisabled,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for ReconcileError {
    fn from(error: anyhow::Error) -> Self {
        Self::Other(error)
    }
}

impl From<sqlx::Error> for ReconcileError {
    fn from(error: sqlx::Error) -> Self {
        Self::Other(error.into())
    }
}

/// Fetch every label from the trusted labeler in `bucket`, in one request. `None` means the page came back full, so the
/// bucket may hold more than one page and must be split.
async fn query_bucket(
    http: &reqwest::Client,
    cfg: &ModerationLabelConfig,
    bucket: &LabelBucket,
) -> Result<Option<Vec<labels::WireLabel>>, ReconcileError> {
    let pattern = bucket.pattern();
    let limit = PAGE_LIMIT.to_string();
    let response = http
        .get(format!(
            "{}/xrpc/com.atproto.label.queryLabels",
            cfg.labeler_url
        ))
        .query(&[
            ("uriPatterns", pattern.as_str()),
            ("sources", cfg.labeler_did.as_str()),
            ("limit", limit.as_str()),
        ])
        .send()
        .await
        .map_err(anyhow::Error::from)?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        if status == reqwest::StatusCode::BAD_REQUEST && body.contains("wildcard") {
            return Err(ReconcileError::WildcardsDisabled);
        }
        return Err(anyhow::anyhow!("queryLabels returned HTTP {status}").into());
    }
    if response
        .content_length()
        .is_some_and(|len| len as usize > MAX_PAGE_BYTES)
    {
        return Err(anyhow::anyhow!("queryLabels page too large").into());
    }
    let body = response.bytes().await.map_err(anyhow::Error::from)?;
    if body.len() > MAX_PAGE_BYTES {
        return Err(anyhow::anyhow!("queryLabels page too large").into());
    }
    let page: QueryLabelsOutput = serde_json::from_slice(&body).map_err(anyhow::Error::from)?;
    if page.labels.len() >= PAGE_LIMIT {
        return Ok(None);
    }
    Ok(Some(page.labels))
}

/// Read the labeler's whole account-label set and apply it.
///
/// Ozone's `queryLabels` pages without an `ORDER BY`, so a cursor walk can
/// skip rows. Instead each request asks for one subject prefix (see
/// [`LabelBucket`]); a page that comes back short holds every matching row,
/// and a full page is split into longer prefixes until every bucket fits.
/// A small labeler costs one request per pass. Returns how many labels were
/// applied.
///
/// `pending` carries the walk between calls: a pass that runs out of its
/// request budget, or fails, leaves its unvisited buckets there and the next
/// call picks up where it stopped instead of restarting at the root, so no
/// prefix is starved. An empty `pending` starts a fresh pass.
async fn reconcile(
    pool: &DbPool,
    http: &reqwest::Client,
    cfg: &ModerationLabelConfig,
    pending: &mut Vec<LabelBucket>,
) -> Result<usize, ReconcileError> {
    if pending.is_empty() {
        pending.push(LabelBucket::Prefix(labels::RECONCILE_ROOT.to_owned()));
    }
    let mut requests = 0usize;
    let mut applied = 0usize;
    while let Some(bucket) = pending.last().cloned() {
        if requests >= MAX_REQUESTS_PER_RECONCILE {
            tracing::info!(
                left = pending.len(),
                "moderation label pass continues next poll"
            );
            return Ok(applied);
        }
        requests += 1;
        // Leave the bucket queued until its rows are applied, so a failed
        // request is retried on the next call.
        let Some(rows) = query_bucket(http, cfg, &bucket).await? else {
            pending.pop();
            match bucket.split() {
                Some(children) => pending.extend(children),
                None => tracing::error!(
                    "moderation labels under one subject exceed a page; some may be missed"
                ),
            }
            continue;
        };
        for label in &rows {
            match account_label_event(label, &cfg.labeler_did, &cfg.enforced_labels) {
                Ok(ev) => {
                    apply_label_event(pool, &ev).await?;
                    applied += 1;
                }
                Err(skip) => tracing::debug!(?skip, "moderation label skipped"),
            }
        }
        pending.pop();
    }
    Ok(applied)
}

/// Background worker: re-read the labeler's labels every poll interval
/// until the process exits.
pub async fn run_label_poller(pool: DbPool, http: reqwest::Client, cfg: ModerationLabelConfig) {
    tracing::info!(
        labeler = %cfg.labeler_did,
        labels = ?cfg.enforced_labels,
        "moderation label poller started"
    );
    let mut pending = Vec::new();
    loop {
        match reconcile(&pool, &http, &cfg, &mut pending).await {
            Ok(applied) => tracing::debug!(applied, "moderation labels reconciled"),
            Err(ReconcileError::WildcardsDisabled) => tracing::error!(
                "Ozone refuses wildcard label queries, so takedowns are NOT enforced; \
                 set OZONE_LABEL_QUERY_WILDCARDS_ENABLED=true on the Ozone service"
            ),
            // Keep the last known state: an unreachable Ozone never lifts a
            // ban and never adds one.
            Err(ReconcileError::Other(error)) => {
                tracing::warn!(%error, "moderation label reconcile failed")
            }
        }
        tokio::time::sleep(cfg.poll_interval).await;
    }
}
