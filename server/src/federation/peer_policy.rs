use sqlx::PgPool;

use super::{errors::FederationError, FederationMode};
use crate::identity::canonical_did;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStatus {
    Pending,
    Allow,
    Suspend,
    Block,
}

impl PeerStatus {
    pub fn from_str(status: &str) -> Option<Self> {
        match status {
            "pending" => Some(Self::Pending),
            "allow" => Some(Self::Allow),
            "suspend" => Some(Self::Suspend),
            "block" => Some(Self::Block),
            _ => None,
        }
    }

    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Allow => "allow",
            Self::Suspend => "suspend",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskTier {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskTier {
    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerPolicy {
    pub status: PeerStatus,
    pub configured_max_requests_per_minute: Option<u32>,
    pub max_requests_per_minute: Option<u32>,
    pub trust_score: i32,
    pub risk_tier: RiskTier,
}

fn parse_status(status: &str) -> PeerStatus {
    PeerStatus::from_str(status).unwrap_or(PeerStatus::Pending)
}

const FEDERATION_EMERGENCY_KILL_SWITCH_ENV: &str = "FEDERATION_EMERGENCY_KILL_SWITCH";
const POLICY_AUDIT_ACTION_UPSERT: &str = "upsert";
const POLICY_AUDIT_ACTION_DELETE: &str = "delete";
const OPEN_INTELLIGENT_PENDING_TRUST_SCORE: i32 = -100;
const OPEN_INTELLIGENT_PENDING_MAX_REQUESTS_DEFAULT: i32 = 60;
const OPEN_INTELLIGENT_PENDING_MAX_REQUESTS_CAP: i32 = 600;
const OPEN_INTELLIGENT_PENDING_MAX_REQUESTS_ENV: &str =
    "FEDERATION_PENDING_MAX_REQUESTS_PER_MINUTE";
const AUTO_SUSPEND_REJECTED_REQUEST_COUNT_DEFAULT: i64 = 25;
const AUTO_SUSPEND_REJECTED_REQUEST_COUNT_ENV: &str =
    "FEDERATION_AUTO_SUSPEND_REJECTED_REQUEST_COUNT";
const AUTO_SUSPEND_INVALID_TOKEN_COUNT_DEFAULT: i64 = 10;
const AUTO_SUSPEND_INVALID_TOKEN_COUNT_ENV: &str = "FEDERATION_AUTO_SUSPEND_INVALID_TOKEN_COUNT";
const AUTO_SUSPEND_COUNTER_THRESHOLD_CAP: i64 = 1_000_000;
const AUTO_SUSPEND_TRUST_SCORE_FLOOR_DEFAULT: i32 = -200;
const AUTO_SUSPEND_TRUST_SCORE_FLOOR_ENV: &str = "FEDERATION_AUTO_SUSPEND_TRUST_SCORE_FLOOR";
const RISK_TIER_MEDIUM_RATIO_DEFAULT: f64 = 0.35;
const RISK_TIER_MEDIUM_RATIO_ENV: &str = "FEDERATION_RISK_TIER_MEDIUM_RATIO";
const RISK_TIER_HIGH_RATIO_DEFAULT: f64 = 0.65;
const RISK_TIER_HIGH_RATIO_ENV: &str = "FEDERATION_RISK_TIER_HIGH_RATIO";
const RISK_TIER_CRITICAL_RATIO_DEFAULT: f64 = 0.9;
const RISK_TIER_CRITICAL_RATIO_ENV: &str = "FEDERATION_RISK_TIER_CRITICAL_RATIO";
const RISK_MEDIUM_LIMIT_MULTIPLIER_DEFAULT: f64 = 0.75;
const RISK_MEDIUM_LIMIT_MULTIPLIER_ENV: &str = "FEDERATION_RISK_MEDIUM_LIMIT_MULTIPLIER";
const RISK_HIGH_LIMIT_MULTIPLIER_DEFAULT: f64 = 0.5;
const RISK_HIGH_LIMIT_MULTIPLIER_ENV: &str = "FEDERATION_RISK_HIGH_LIMIT_MULTIPLIER";
const RISK_CRITICAL_LIMIT_MULTIPLIER_DEFAULT: f64 = 0.25;
const RISK_CRITICAL_LIMIT_MULTIPLIER_ENV: &str = "FEDERATION_RISK_CRITICAL_LIMIT_MULTIPLIER";
const RISK_MIN_EFFECTIVE_LIMIT_DEFAULT: i32 = 5;
const RISK_MIN_EFFECTIVE_LIMIT_CAP: i32 = 10_000;
const RISK_MIN_EFFECTIVE_LIMIT_ENV: &str = "FEDERATION_RISK_MIN_EFFECTIVE_MAX_REQUESTS_PER_MINUTE";
const AUTO_QUARANTINE_MIN_RISK_TIER_DEFAULT: RiskTier = RiskTier::Critical;
const AUTO_QUARANTINE_MIN_RISK_TIER_ENV: &str = "FEDERATION_AUTO_QUARANTINE_MIN_RISK_TIER";
const FEDERATION_ALERTS_ENABLED_ENV: &str = "FEDERATION_ALERTS_ENABLED";

#[derive(Debug, Clone, Copy)]
struct AutoSuspendThresholds {
    rejected_request_count: i64,
    invalid_token_count: i64,
    trust_score_floor: i32,
}

#[derive(Debug, Clone, Copy)]
struct RiskTuning {
    medium_ratio: f64,
    high_ratio: f64,
    critical_ratio: f64,
    medium_limit_multiplier: f64,
    high_limit_multiplier: f64,
    critical_limit_multiplier: f64,
    min_effective_limit: u32,
    auto_quarantine_min_tier: RiskTier,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FederationPeerRecord {
    pub ds_did: String,
    pub status: String,
    pub trust_score: i32,
    pub max_requests_per_minute: Option<i32>,
    pub note: Option<String>,
    pub invalid_token_count: i64,
    pub rejected_request_count: i64,
    pub successful_request_count: i64,
    pub last_seen_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

pub fn inbound_emergency_kill_switch_enabled() -> bool {
    std::env::var(FEDERATION_EMERGENCY_KILL_SWITCH_ENV)
        .ok()
        .map(|raw| match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "on" | "yes" => true,
            "0" | "false" | "off" | "no" => false,
            _ => true,
        })
        .unwrap_or(false)
}

fn parse_open_intelligent_pending_limit(raw: Option<&str>) -> i32 {
    raw.and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(OPEN_INTELLIGENT_PENDING_MAX_REQUESTS_DEFAULT)
        .clamp(1, OPEN_INTELLIGENT_PENDING_MAX_REQUESTS_CAP)
}

fn open_intelligent_pending_limit() -> i32 {
    parse_open_intelligent_pending_limit(
        std::env::var(OPEN_INTELLIGENT_PENDING_MAX_REQUESTS_ENV)
            .ok()
            .as_deref(),
    )
}

fn parse_auto_suspend_counter_threshold(raw: Option<&str>, default: i64) -> i64 {
    raw.and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(default)
        .clamp(1, AUTO_SUSPEND_COUNTER_THRESHOLD_CAP)
}

fn parse_auto_suspend_trust_score_floor(raw: Option<&str>) -> i32 {
    raw.and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(AUTO_SUSPEND_TRUST_SCORE_FLOOR_DEFAULT)
        .clamp(-1000, 1000)
}

fn auto_suspend_thresholds() -> AutoSuspendThresholds {
    AutoSuspendThresholds {
        rejected_request_count: parse_auto_suspend_counter_threshold(
            std::env::var(AUTO_SUSPEND_REJECTED_REQUEST_COUNT_ENV)
                .ok()
                .as_deref(),
            AUTO_SUSPEND_REJECTED_REQUEST_COUNT_DEFAULT,
        ),
        invalid_token_count: parse_auto_suspend_counter_threshold(
            std::env::var(AUTO_SUSPEND_INVALID_TOKEN_COUNT_ENV)
                .ok()
                .as_deref(),
            AUTO_SUSPEND_INVALID_TOKEN_COUNT_DEFAULT,
        ),
        trust_score_floor: parse_auto_suspend_trust_score_floor(
            std::env::var(AUTO_SUSPEND_TRUST_SCORE_FLOOR_ENV)
                .ok()
                .as_deref(),
        ),
    }
}

fn parse_risk_ratio(raw: Option<&str>, default: f64) -> f64 {
    raw.and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(default)
        .clamp(0.0, 1.0)
}

fn parse_limit_multiplier(raw: Option<&str>, default: f64) -> f64 {
    raw.and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(default)
        .clamp(0.05, 1.0)
}

fn parse_min_effective_limit(raw: Option<&str>) -> u32 {
    raw.and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(RISK_MIN_EFFECTIVE_LIMIT_DEFAULT)
        .clamp(1, RISK_MIN_EFFECTIVE_LIMIT_CAP) as u32
}

fn parse_auto_quarantine_min_tier(raw: Option<&str>) -> RiskTier {
    raw.and_then(RiskTier::from_str)
        .unwrap_or(AUTO_QUARANTINE_MIN_RISK_TIER_DEFAULT)
}

fn risk_tuning() -> RiskTuning {
    let medium_ratio = parse_risk_ratio(
        std::env::var(RISK_TIER_MEDIUM_RATIO_ENV).ok().as_deref(),
        RISK_TIER_MEDIUM_RATIO_DEFAULT,
    );
    let high_ratio = parse_risk_ratio(
        std::env::var(RISK_TIER_HIGH_RATIO_ENV).ok().as_deref(),
        RISK_TIER_HIGH_RATIO_DEFAULT,
    )
    .max(medium_ratio);
    let critical_ratio = parse_risk_ratio(
        std::env::var(RISK_TIER_CRITICAL_RATIO_ENV).ok().as_deref(),
        RISK_TIER_CRITICAL_RATIO_DEFAULT,
    )
    .max(high_ratio);

    RiskTuning {
        medium_ratio,
        high_ratio,
        critical_ratio,
        medium_limit_multiplier: parse_limit_multiplier(
            std::env::var(RISK_MEDIUM_LIMIT_MULTIPLIER_ENV)
                .ok()
                .as_deref(),
            RISK_MEDIUM_LIMIT_MULTIPLIER_DEFAULT,
        ),
        high_limit_multiplier: parse_limit_multiplier(
            std::env::var(RISK_HIGH_LIMIT_MULTIPLIER_ENV)
                .ok()
                .as_deref(),
            RISK_HIGH_LIMIT_MULTIPLIER_DEFAULT,
        ),
        critical_limit_multiplier: parse_limit_multiplier(
            std::env::var(RISK_CRITICAL_LIMIT_MULTIPLIER_ENV)
                .ok()
                .as_deref(),
            RISK_CRITICAL_LIMIT_MULTIPLIER_DEFAULT,
        ),
        min_effective_limit: parse_min_effective_limit(
            std::env::var(RISK_MIN_EFFECTIVE_LIMIT_ENV).ok().as_deref(),
        ),
        auto_quarantine_min_tier: parse_auto_quarantine_min_tier(
            std::env::var(AUTO_QUARANTINE_MIN_RISK_TIER_ENV)
                .ok()
                .as_deref(),
        ),
    }
}

pub fn federation_alerts_enabled() -> bool {
    std::env::var(FEDERATION_ALERTS_ENABLED_ENV)
        .ok()
        .map(|raw| match raw.trim().to_ascii_lowercase().as_str() {
            "0" | "false" | "off" | "no" => false,
            "1" | "true" | "on" | "yes" => true,
            _ => true,
        })
        .unwrap_or(true)
}

fn normalized_trust_risk(trust_score: i32, trust_score_floor: i32) -> f64 {
    if trust_score >= 0 {
        return 0.0;
    }
    let floor = trust_score_floor.min(-1);
    let span = (0 - floor) as f64;
    if span <= 0.0 {
        return 1.0;
    }
    ((0 - trust_score) as f64 / span).clamp(0.0, 1.0)
}

fn normalized_counter_risk(count: i64, threshold: i64) -> f64 {
    if threshold <= 0 {
        return 0.0;
    }
    (count as f64 / threshold as f64).clamp(0.0, 4.0)
}

fn calculate_risk_tier(
    trust_score: i32,
    rejected_request_count: i64,
    invalid_token_count: i64,
    thresholds: AutoSuspendThresholds,
    tuning: RiskTuning,
) -> RiskTier {
    let risk_score = normalized_trust_risk(trust_score, thresholds.trust_score_floor)
        .max(normalized_counter_risk(
            rejected_request_count,
            thresholds.rejected_request_count,
        ))
        .max(normalized_counter_risk(
            invalid_token_count,
            thresholds.invalid_token_count,
        ));

    if risk_score >= tuning.critical_ratio {
        RiskTier::Critical
    } else if risk_score >= tuning.high_ratio {
        RiskTier::High
    } else if risk_score >= tuning.medium_ratio {
        RiskTier::Medium
    } else {
        RiskTier::Low
    }
}

fn apply_risk_based_limit(
    base_limit: Option<u32>,
    risk_tier: RiskTier,
    tuning: RiskTuning,
) -> Option<u32> {
    let base_limit = base_limit?;
    let multiplier = match risk_tier {
        RiskTier::Low => 1.0,
        RiskTier::Medium => tuning.medium_limit_multiplier,
        RiskTier::High => tuning.high_limit_multiplier,
        RiskTier::Critical => tuning.critical_limit_multiplier,
    };
    if (multiplier - 1.0).abs() < f64::EPSILON {
        return Some(base_limit);
    }

    let adjusted = ((base_limit as f64) * multiplier).floor().max(1.0) as u32;
    Some(adjusted.max(tuning.min_effective_limit.min(base_limit)))
}

fn emit_trust_risk_transitions(
    ds_did: &str,
    previous_trust_score: i32,
    current_trust_score: i32,
    previous_risk_tier: RiskTier,
    current_risk_tier: RiskTier,
    previous_status: &str,
    current_status: &str,
) {
    if previous_trust_score != current_trust_score {
        let direction = if current_trust_score > previous_trust_score {
            "improved"
        } else {
            "degraded"
        };
        crate::metrics::record_federation_trust_transition(
            direction,
            previous_risk_tier.as_str(),
            current_risk_tier.as_str(),
        );
    }

    if previous_risk_tier != current_risk_tier || previous_status != current_status {
        crate::metrics::record_federation_risk_transition(
            previous_risk_tier.as_str(),
            current_risk_tier.as_str(),
            current_status,
        );
        tracing::info!(
            event = "federation_peer_risk_transition",
            peer_ds_did = %crate::crypto::redact_for_log(ds_did),
            previous_trust_score,
            trust_score = current_trust_score,
            previous_risk_tier = %previous_risk_tier.as_str(),
            risk_tier = %current_risk_tier.as_str(),
            previous_status = %previous_status,
            status = %current_status,
            "Federation peer trust/risk transition observed"
        );
    }
}

fn maybe_emit_alert_hook(
    alert_type: &'static str,
    ds_did: &str,
    status: &str,
    risk_tier: RiskTier,
    rejected_request_count: i64,
    invalid_token_count: i64,
    trust_score: i32,
) {
    if !federation_alerts_enabled() {
        return;
    }
    tracing::error!(
        event = "federation_alert_hook",
        alert_type,
        peer_ds_did = %crate::crypto::redact_for_log(ds_did),
        status,
        risk_tier = %risk_tier.as_str(),
        rejected_request_count,
        invalid_token_count,
        trust_score,
        "Federation alert hook emitted"
    );
}

async fn provision_open_intelligent_pending_peer(
    pool: &PgPool,
    ds_did: &str,
) -> Result<(String, Option<i32>, i32, i64, i64), FederationError> {
    sqlx::query_as(
        "INSERT INTO federation_peers \
            (ds_did, status, trust_score, max_requests_per_minute, updated_at, last_seen_at) \
         VALUES ($1, 'pending', $2, $3, NOW(), NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET updated_at = NOW() \
         RETURNING status, max_requests_per_minute, trust_score, \
                   rejected_request_count, invalid_token_count",
    )
    .bind(ds_did)
    .bind(OPEN_INTELLIGENT_PENDING_TRUST_SCORE)
    .bind(open_intelligent_pending_limit())
    .fetch_one(pool)
    .await
    .map_err(FederationError::Database)
}

async fn record_policy_audit_event(
    pool: &PgPool,
    actor_did: &str,
    target_peer_did: &str,
    action: &str,
) -> Result<(), FederationError> {
    sqlx::query(
        "INSERT INTO federation_peer_policy_audit_log \
            (actor_did, target_peer_did, action, created_at) \
         VALUES ($1, $2, $3, NOW())",
    )
    .bind(canonical_did(actor_did))
    .bind(canonical_did(target_peer_did))
    .bind(action)
    .execute(pool)
    .await
    .map_err(FederationError::Database)?;
    Ok(())
}

fn build_peer_policy(
    status: &str,
    max_requests_per_minute: Option<i32>,
    trust_score: i32,
    rejected_request_count: i64,
    invalid_token_count: i64,
) -> PeerPolicy {
    let thresholds = auto_suspend_thresholds();
    let tuning = risk_tuning();
    let risk_tier = calculate_risk_tier(
        trust_score,
        rejected_request_count,
        invalid_token_count,
        thresholds,
        tuning,
    );
    let configured_limit = max_requests_per_minute.map(|v| v.max(1) as u32);
    let effective_limit = apply_risk_based_limit(configured_limit, risk_tier, tuning);

    PeerPolicy {
        status: parse_status(status),
        configured_max_requests_per_minute: configured_limit,
        max_requests_per_minute: effective_limit,
        trust_score,
        risk_tier,
    }
}

pub async fn enforce_inbound_peer_policy(
    pool: &PgPool,
    ds_did: &str,
) -> Result<PeerPolicy, FederationError> {
    let ds_did = canonical_did(ds_did);
    let mode = FederationMode::from_env();
    let row: Option<(String, Option<i32>, i32, i64, i64)> = sqlx::query_as(
        "SELECT status, max_requests_per_minute, trust_score, \
                 rejected_request_count, invalid_token_count \
         FROM federation_peers WHERE ds_did = $1",
    )
    .bind(ds_did)
    .fetch_optional(pool)
    .await
    .map_err(FederationError::Database)?;

    let (status, max_requests_per_minute, trust_score, rejected_request_count, invalid_token_count) =
        match row {
            Some(row) => row,
            None => match mode {
                FederationMode::OpenIntelligent => {
                    provision_open_intelligent_pending_peer(pool, ds_did).await?
                }
                FederationMode::Off | FederationMode::Allowlist => {
                    return Err(FederationError::AuthFailed {
                        reason: format!("Peer DS '{}' is not allowlisted", ds_did),
                    });
                }
            },
        };

    let policy = build_peer_policy(
        &status,
        max_requests_per_minute,
        trust_score,
        rejected_request_count,
        invalid_token_count,
    );

    match policy.status {
        PeerStatus::Allow => Ok(policy),
        PeerStatus::Pending if matches!(mode, FederationMode::OpenIntelligent) => Ok(policy),
        PeerStatus::Pending => Err(FederationError::AuthFailed {
            reason: format!("Peer DS '{}' is pending approval", ds_did),
        }),
        PeerStatus::Suspend => Err(FederationError::AuthFailed {
            reason: format!("Peer DS '{}' is suspended", ds_did),
        }),
        PeerStatus::Block => Err(FederationError::AuthFailed {
            reason: format!("Peer DS '{}' is blocklisted", ds_did),
        }),
    }
}

fn evaluate_peer_record_policy(
    ds_did: &str,
    row: Option<(String, Option<i32>, i32, i64, i64)>,
) -> Result<PeerPolicy, FederationError> {
    let Some((
        status,
        max_requests_per_minute,
        trust_score,
        rejected_request_count,
        invalid_token_count,
    )) = row
    else {
        return Err(FederationError::AuthFailed {
            reason: format!("Peer DS '{}' is not allowlisted", ds_did),
        });
    };

    let policy = build_peer_policy(
        &status,
        max_requests_per_minute,
        trust_score,
        rejected_request_count,
        invalid_token_count,
    );

    match policy.status {
        PeerStatus::Allow => Ok(policy),
        PeerStatus::Pending => Err(FederationError::AuthFailed {
            reason: format!("Peer DS '{}' is pending approval", ds_did),
        }),
        PeerStatus::Suspend => Err(FederationError::AuthFailed {
            reason: format!("Peer DS '{}' is suspended", ds_did),
        }),
        PeerStatus::Block => Err(FederationError::AuthFailed {
            reason: format!("Peer DS '{}' is blocklisted", ds_did),
        }),
    }
}

pub async fn enforce_outbound_peer_policy(
    pool: &PgPool,
    ds_did: &str,
) -> Result<PeerPolicy, FederationError> {
    let ds_did = canonical_did(ds_did);
    let row: Option<(String, Option<i32>, i32, i64, i64)> = sqlx::query_as(
        "SELECT status, max_requests_per_minute, trust_score, \
                 rejected_request_count, invalid_token_count \
         FROM federation_peers WHERE ds_did = $1",
    )
    .bind(ds_did)
    .fetch_optional(pool)
    .await
    .map_err(FederationError::Database)?;

    evaluate_peer_record_policy(ds_did, row)
}

pub(crate) async fn enforce_outbound_peer_policy_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ds_did: &str,
) -> Result<PeerPolicy, FederationError> {
    let ds_did = canonical_did(ds_did);
    let row: Option<(String, Option<i32>, i32, i64, i64)> = sqlx::query_as(
        "SELECT status, max_requests_per_minute, trust_score, \
                 rejected_request_count, invalid_token_count \
         FROM federation_peers WHERE ds_did = $1 FOR SHARE",
    )
    .bind(ds_did)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    evaluate_peer_record_policy(ds_did, row)
}

pub async fn record_success(pool: &PgPool, ds_did: &str) {
    let ds_did = canonical_did(ds_did);
    let thresholds = auto_suspend_thresholds();
    let tuning = risk_tuning();
    let update = sqlx::query_as::<_, (String, i32, i64, i64, String, i32, i64, i64)>(
        "WITH previous AS ( \
            SELECT status, trust_score, rejected_request_count, invalid_token_count \
            FROM federation_peers \
            WHERE ds_did = $1 \
        ), updated AS ( \
            UPDATE federation_peers \
            SET successful_request_count = successful_request_count + 1, \
                trust_score = LEAST(trust_score + 1, 1000), \
                last_seen_at = NOW(), \
                updated_at = NOW() \
            WHERE ds_did = $1 \
            RETURNING status, trust_score, rejected_request_count, invalid_token_count \
        ) \
        SELECT previous.status, previous.trust_score, previous.rejected_request_count, \
               previous.invalid_token_count, updated.status, updated.trust_score, \
               updated.rejected_request_count, updated.invalid_token_count \
        FROM previous \
        JOIN updated ON TRUE",
    )
    .bind(ds_did)
    .fetch_optional(pool)
    .await;

    if let Ok(Some((
        previous_status,
        previous_trust_score,
        previous_rejected_count,
        previous_invalid_count,
        current_status,
        current_trust_score,
        current_rejected_count,
        current_invalid_count,
    ))) = update
    {
        let previous_risk_tier = calculate_risk_tier(
            previous_trust_score,
            previous_rejected_count,
            previous_invalid_count,
            thresholds,
            tuning,
        );
        let current_risk_tier = calculate_risk_tier(
            current_trust_score,
            current_rejected_count,
            current_invalid_count,
            thresholds,
            tuning,
        );
        emit_trust_risk_transitions(
            ds_did,
            previous_trust_score,
            current_trust_score,
            previous_risk_tier,
            current_risk_tier,
            &previous_status,
            &current_status,
        );
    }
}

pub async fn record_rejected(pool: &PgPool, ds_did: &str) {
    let ds_did = canonical_did(ds_did);
    crate::metrics::record_federation_rejection_reason("peer_rejected");
    record_abuse_telemetry(pool, ds_did, 1, 0, 5).await;
}

pub async fn record_invalid_token(pool: &PgPool, ds_did: &str) {
    let ds_did = canonical_did(ds_did);
    crate::metrics::record_federation_rejection_reason("invalid_token");
    record_abuse_telemetry(pool, ds_did, 0, 1, 10).await;
}

async fn record_abuse_telemetry(
    pool: &PgPool,
    ds_did: &str,
    rejected_increment: i64,
    invalid_increment: i64,
    trust_penalty: i32,
) {
    let thresholds = auto_suspend_thresholds();
    let tuning = risk_tuning();
    let update = sqlx::query_as::<_, (String, i32, i64, i64, String, i32, i64, i64)>(
        "WITH previous AS ( \
            SELECT status, trust_score, rejected_request_count, invalid_token_count \
            FROM federation_peers \
            WHERE ds_did = $1 \
        ), updated AS ( \
            UPDATE federation_peers \
            SET rejected_request_count = rejected_request_count + $2, \
                invalid_token_count = invalid_token_count + $3, \
                trust_score = GREATEST(trust_score - $4, -1000), \
                status = CASE \
                    WHEN status = 'block' THEN status \
                    WHEN (rejected_request_count + $2) >= $5 \
                      OR (invalid_token_count + $3) >= $6 \
                      OR GREATEST(trust_score - $4, -1000) <= $7 \
                    THEN 'suspend' \
                    ELSE status \
                END, \
                last_seen_at = NOW(), \
                updated_at = NOW() \
            WHERE ds_did = $1 \
            RETURNING status, trust_score, rejected_request_count, invalid_token_count \
        ) \
        SELECT previous.status, previous.trust_score, previous.rejected_request_count, \
               previous.invalid_token_count, updated.status, updated.trust_score, \
               updated.rejected_request_count, updated.invalid_token_count \
        FROM previous \
        JOIN updated ON TRUE",
    )
    .bind(ds_did)
    .bind(rejected_increment)
    .bind(invalid_increment)
    .bind(trust_penalty)
    .bind(thresholds.rejected_request_count)
    .bind(thresholds.invalid_token_count)
    .bind(thresholds.trust_score_floor)
    .fetch_optional(pool)
    .await;

    if let Ok(Some((
        previous_status,
        previous_trust_score,
        previous_rejected_count,
        previous_invalid_count,
        mut current_status,
        current_trust_score,
        current_rejected_count,
        current_invalid_count,
    ))) = update
    {
        let previous_risk_tier = calculate_risk_tier(
            previous_trust_score,
            previous_rejected_count,
            previous_invalid_count,
            thresholds,
            tuning,
        );
        let current_risk_tier = calculate_risk_tier(
            current_trust_score,
            current_rejected_count,
            current_invalid_count,
            thresholds,
            tuning,
        );

        let mut auto_quarantined_by_risk = false;
        let should_auto_quarantine = current_status != "block"
            && current_status != "suspend"
            && current_risk_tier >= tuning.auto_quarantine_min_tier;
        if should_auto_quarantine {
            if let Ok(result) = sqlx::query(
                "UPDATE federation_peers \
                 SET status = 'suspend', updated_at = NOW() \
                 WHERE ds_did = $1 AND status NOT IN ('block', 'suspend')",
            )
            .bind(ds_did)
            .execute(pool)
            .await
            {
                if result.rows_affected() > 0 {
                    current_status = "suspend".to_string();
                    auto_quarantined_by_risk = true;
                    crate::metrics::record_federation_auto_quarantine("risk_tier");
                    tracing::warn!(
                        event = "federation_peer_auto_quarantined",
                        peer_ds_did = %crate::crypto::redact_for_log(ds_did),
                        previous_status = %previous_status,
                        risk_tier = %current_risk_tier.as_str(),
                        quarantine_threshold_risk_tier = %tuning.auto_quarantine_min_tier.as_str(),
                        rejected_request_count = current_rejected_count,
                        invalid_token_count = current_invalid_count,
                        trust_score = current_trust_score,
                        "Auto-quarantined federation peer due to computed risk tier"
                    );
                    maybe_emit_alert_hook(
                        "auto_quarantine",
                        ds_did,
                        &current_status,
                        current_risk_tier,
                        current_rejected_count,
                        current_invalid_count,
                        current_trust_score,
                    );
                }
            }
        }

        if previous_status != "suspend" && current_status == "suspend" {
            if !auto_quarantined_by_risk {
                crate::metrics::record_federation_auto_quarantine("threshold");
            }
            tracing::warn!(
                event = "federation_peer_auto_suspended",
                peer_ds_did = %crate::crypto::redact_for_log(ds_did),
                previous_status = %previous_status,
                rejected_request_count = current_rejected_count,
                invalid_token_count = current_invalid_count,
                trust_score = current_trust_score,
                risk_tier = %current_risk_tier.as_str(),
                rejected_request_threshold = thresholds.rejected_request_count,
                invalid_token_threshold = thresholds.invalid_token_count,
                trust_score_floor = thresholds.trust_score_floor,
                "Auto-suspended federation peer due to abuse telemetry thresholds"
            );
            if !auto_quarantined_by_risk {
                maybe_emit_alert_hook(
                    "auto_quarantine_threshold",
                    ds_did,
                    &current_status,
                    current_risk_tier,
                    current_rejected_count,
                    current_invalid_count,
                    current_trust_score,
                );
            }
        }

        emit_trust_risk_transitions(
            ds_did,
            previous_trust_score,
            current_trust_score,
            previous_risk_tier,
            current_risk_tier,
            &previous_status,
            &current_status,
        );
    }
}

pub async fn list_peer_policies(
    pool: &PgPool,
    status_filter: Option<PeerStatus>,
    limit: u32,
) -> Result<Vec<FederationPeerRecord>, FederationError> {
    let limit = limit.clamp(1, 500) as i64;
    let status_filter = status_filter.map(|s| s.as_db_str().to_string());

    sqlx::query_as::<_, FederationPeerRecord>(
        "SELECT ds_did, status, trust_score, max_requests_per_minute, note, \
                invalid_token_count, rejected_request_count, successful_request_count, \
                last_seen_at, created_at, updated_at \
         FROM federation_peers \
         WHERE ($1::TEXT IS NULL OR status = $1) \
         ORDER BY updated_at DESC \
         LIMIT $2",
    )
    .bind(status_filter)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(FederationError::Database)
}

pub async fn upsert_peer_policy(
    pool: &PgPool,
    actor_did: &str,
    ds_did: &str,
    status: PeerStatus,
    max_requests_per_minute: Option<u32>,
    note: Option<&str>,
) -> Result<FederationPeerRecord, FederationError> {
    let ds_did = canonical_did(ds_did);
    let max_requests_per_minute = max_requests_per_minute.map(|v| v.max(1) as i32);

    let record = sqlx::query_as::<_, FederationPeerRecord>(
        "INSERT INTO federation_peers \
            (ds_did, status, max_requests_per_minute, note, updated_at, last_seen_at) \
         VALUES ($1, $2, $3, $4, NOW(), NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET \
           status = EXCLUDED.status, \
           max_requests_per_minute = EXCLUDED.max_requests_per_minute, \
           note = EXCLUDED.note, \
           updated_at = NOW() \
         RETURNING ds_did, status, trust_score, max_requests_per_minute, note, \
                   invalid_token_count, rejected_request_count, successful_request_count, \
                   last_seen_at, created_at, updated_at",
    )
    .bind(ds_did)
    .bind(status.as_db_str())
    .bind(max_requests_per_minute)
    .bind(note)
    .fetch_one(pool)
    .await
    .map_err(FederationError::Database)?;

    record_policy_audit_event(pool, actor_did, &record.ds_did, POLICY_AUDIT_ACTION_UPSERT).await?;

    Ok(record)
}

pub async fn delete_peer_policy(
    pool: &PgPool,
    actor_did: &str,
    ds_did: &str,
) -> Result<bool, FederationError> {
    let ds_did = canonical_did(ds_did);
    let result = sqlx::query("DELETE FROM federation_peers WHERE ds_did = $1")
        .bind(ds_did)
        .execute(pool)
        .await
        .map_err(FederationError::Database)?;

    if result.rows_affected() == 0 {
        return Ok(false);
    }

    record_policy_audit_event(pool, actor_did, ds_did, POLICY_AUDIT_ACTION_DELETE).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{
        apply_risk_based_limit, calculate_risk_tier, parse_auto_quarantine_min_tier,
        parse_auto_suspend_counter_threshold, parse_auto_suspend_trust_score_floor,
        parse_open_intelligent_pending_limit, parse_risk_ratio, AutoSuspendThresholds, RiskTier,
        RiskTuning, AUTO_SUSPEND_COUNTER_THRESHOLD_CAP, AUTO_SUSPEND_TRUST_SCORE_FLOOR_DEFAULT,
        OPEN_INTELLIGENT_PENDING_MAX_REQUESTS_CAP, OPEN_INTELLIGENT_PENDING_MAX_REQUESTS_DEFAULT,
    };

    #[test]
    fn pending_limit_uses_default_for_missing_or_invalid_values() {
        assert_eq!(
            parse_open_intelligent_pending_limit(None),
            OPEN_INTELLIGENT_PENDING_MAX_REQUESTS_DEFAULT
        );
        assert_eq!(
            parse_open_intelligent_pending_limit(Some("invalid")),
            OPEN_INTELLIGENT_PENDING_MAX_REQUESTS_DEFAULT
        );
    }

    #[test]
    fn pending_limit_is_clamped_to_safe_range() {
        assert_eq!(parse_open_intelligent_pending_limit(Some("0")), 1);
        assert_eq!(
            parse_open_intelligent_pending_limit(Some("5000")),
            OPEN_INTELLIGENT_PENDING_MAX_REQUESTS_CAP
        );
    }

    #[test]
    fn auto_suspend_counter_threshold_uses_default_and_clamps() {
        assert_eq!(parse_auto_suspend_counter_threshold(None, 25), 25);
        assert_eq!(parse_auto_suspend_counter_threshold(Some("oops"), 25), 25);
        assert_eq!(parse_auto_suspend_counter_threshold(Some("0"), 25), 1);
        assert_eq!(
            parse_auto_suspend_counter_threshold(Some("5000000"), 25),
            AUTO_SUSPEND_COUNTER_THRESHOLD_CAP
        );
    }

    #[test]
    fn auto_suspend_trust_score_floor_uses_default_and_clamps() {
        assert_eq!(
            parse_auto_suspend_trust_score_floor(None),
            AUTO_SUSPEND_TRUST_SCORE_FLOOR_DEFAULT
        );
        assert_eq!(
            parse_auto_suspend_trust_score_floor(Some("oops")),
            AUTO_SUSPEND_TRUST_SCORE_FLOOR_DEFAULT
        );
        assert_eq!(parse_auto_suspend_trust_score_floor(Some("-5000")), -1000);
        assert_eq!(parse_auto_suspend_trust_score_floor(Some("5000")), 1000);
    }

    #[test]
    fn risk_ratio_uses_default_and_clamps() {
        assert_eq!(parse_risk_ratio(None, 0.5), 0.5);
        assert_eq!(parse_risk_ratio(Some("bad"), 0.5), 0.5);
        assert_eq!(parse_risk_ratio(Some("-1"), 0.5), 0.0);
        assert_eq!(parse_risk_ratio(Some("5"), 0.5), 1.0);
    }

    #[test]
    fn parse_auto_quarantine_tier_defaults_to_critical() {
        assert_eq!(parse_auto_quarantine_min_tier(None), RiskTier::Critical);
        assert_eq!(parse_auto_quarantine_min_tier(Some("HIGH")), RiskTier::High);
        assert_eq!(
            parse_auto_quarantine_min_tier(Some("unknown")),
            RiskTier::Critical
        );
    }

    #[test]
    fn calculate_risk_tier_uses_trust_and_abuse_counters() {
        let thresholds = AutoSuspendThresholds {
            rejected_request_count: 20,
            invalid_token_count: 10,
            trust_score_floor: -200,
        };
        let tuning = RiskTuning {
            medium_ratio: 0.35,
            high_ratio: 0.65,
            critical_ratio: 0.9,
            medium_limit_multiplier: 0.75,
            high_limit_multiplier: 0.5,
            critical_limit_multiplier: 0.25,
            min_effective_limit: 5,
            auto_quarantine_min_tier: RiskTier::Critical,
        };

        assert_eq!(
            calculate_risk_tier(5, 0, 0, thresholds, tuning),
            RiskTier::Low
        );
        assert_eq!(
            calculate_risk_tier(-80, 2, 1, thresholds, tuning),
            RiskTier::Medium
        );
        assert_eq!(
            calculate_risk_tier(-150, 8, 3, thresholds, tuning),
            RiskTier::High
        );
        assert_eq!(
            calculate_risk_tier(-180, 18, 9, thresholds, tuning),
            RiskTier::Critical
        );
    }

    #[test]
    fn risk_based_limit_applies_minimum_without_increasing_base() {
        let tuning = RiskTuning {
            medium_ratio: 0.35,
            high_ratio: 0.65,
            critical_ratio: 0.9,
            medium_limit_multiplier: 0.75,
            high_limit_multiplier: 0.5,
            critical_limit_multiplier: 0.25,
            min_effective_limit: 5,
            auto_quarantine_min_tier: RiskTier::Critical,
        };

        assert_eq!(
            apply_risk_based_limit(Some(100), RiskTier::Low, tuning),
            Some(100)
        );
        assert_eq!(
            apply_risk_based_limit(Some(100), RiskTier::High, tuning),
            Some(50)
        );
        assert_eq!(
            apply_risk_based_limit(Some(8), RiskTier::Critical, tuning),
            Some(5)
        );
        assert_eq!(
            apply_risk_based_limit(Some(3), RiskTier::Critical, tuning),
            Some(3)
        );
    }
}
