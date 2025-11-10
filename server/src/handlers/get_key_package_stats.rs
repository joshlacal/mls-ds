use axum::{extract::{RawQuery, State}, http::StatusCode, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::{info, warn, error};

use crate::{
    auth::AuthUser,
    storage::DbPool,
};

const RECOMMENDED_THRESHOLD: i32 = 5;

#[derive(Debug, Serialize)]
pub struct CipherSuiteStats {
    #[serde(rename = "cipherSuite")]
    cipher_suite: String,
    available: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    consumed: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct KeyPackageStatsResponse {
    available: i32,
    threshold: i32,
    #[serde(rename = "needsReplenish")]
    needs_replenish: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "oldestExpiresIn")]
    oldest_expires_in: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "byCipherSuite")]
    by_cipher_suite: Option<Vec<CipherSuiteStats>>,

    // New consumption tracking fields
    total: i32,
    consumed: i32,
    #[serde(rename = "consumedLast24h")]
    consumed_last_24h: i32,
    #[serde(rename = "consumedLast7d")]
    consumed_last_7d: i32,
    #[serde(rename = "averageDailyConsumption")]
    average_daily_consumption: i32,  // Multiplied by 100 (e.g., 250 = 2.5/day)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "predictedDepletionDays")]
    predicted_depletion_days: Option<i32>,  // Multiplied by 100 (e.g., 350 = 3.5 days)
}

/// Get key package inventory statistics
/// GET /xrpc/blue.catbird.mls.getKeyPackageStats
#[tracing::instrument(skip(pool))]
pub async fn get_key_package_stats(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    RawQuery(query): RawQuery,
) -> Result<Json<KeyPackageStatsResponse>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.getKeyPackageStats") {
        warn!("Unauthorized access attempt");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Parse query parameters
    let query_str = query.unwrap_or_default();
    let mut target_did = None;
    let mut cipher_suite_filter = None;

    for pair in query_str.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let decoded_value = urlencoding::decode(value).unwrap_or_default().to_string();
            match key {
                "did" => target_did = Some(decoded_value),
                "cipherSuite" => cipher_suite_filter = Some(decoded_value),
                _ => {}
            }
        }
    }

    // Use target DID if provided, otherwise use authenticated user's DID
    let did = target_did.as_deref().unwrap_or(&auth_user.did);

    info!("Fetching key package stats");

    // Get available key packages count
    let available = get_available_count(&pool, did, cipher_suite_filter.as_deref()).await
        .map_err(|e| {
            error!("Failed to count available key packages: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Get oldest expiration timestamp
    let oldest_expires_at = get_oldest_expiration(&pool, did, cipher_suite_filter.as_deref()).await
        .map_err(|e| {
            error!("Failed to get oldest expiration: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let oldest_expires_in = oldest_expires_at.map(|exp| {
        format_duration_until(exp)
    });

    // Get breakdown by cipher suite if no filter is provided
    let by_cipher_suite = if cipher_suite_filter.is_none() {
        Some(get_stats_by_cipher_suite(&pool, did).await
            .map_err(|e| {
                error!("Failed to get stats by cipher suite: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?)
    } else {
        None
    };

    // Get consumption statistics
    let total = crate::db::count_all_key_packages(&pool, did, cipher_suite_filter.as_deref()).await
        .map_err(|e| {
            error!("Failed to count all key packages: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })? as i32;

    let consumed = total - available;

    let consumed_last_24h = crate::db::count_consumed_key_packages(&pool, did, 24).await
        .map_err(|e| {
            error!("Failed to count consumed packages (24h): {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })? as i32;

    let consumed_last_7d = crate::db::count_consumed_key_packages(&pool, did, 24 * 7).await
        .map_err(|e| {
            error!("Failed to count consumed packages (7d): {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })? as i32;

    let average_daily_consumption_f64 = crate::db::get_consumption_rate(&pool, did).await
        .map_err(|e| {
            error!("Failed to get consumption rate: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Convert to integer (multiply by 100)
    let average_daily_consumption = (average_daily_consumption_f64 * 100.0) as i32;

    // Calculate predicted depletion days
    let predicted_depletion_days = if average_daily_consumption_f64 > 0.1 && available > 0 {
        let days = (available as f64) / average_daily_consumption_f64;
        Some((days * 100.0) as i32)  // Multiply by 100
    } else {
        None
    };

    // Enhanced needs_replenish logic: replenish if below threshold OR predicted to deplete in < 3 days
    // Note: predicted_depletion_days is multiplied by 100, so < 300 means < 3.0 days
    let needs_replenish = available < RECOMMENDED_THRESHOLD ||
        predicted_depletion_days.map_or(false, |days| days < 300);

    info!(
        "Key package stats for {}: available={}, threshold={}, needs_replenish={}, consumption_rate={:.2}/day",
        did, available, RECOMMENDED_THRESHOLD, needs_replenish, average_daily_consumption_f64
    );

    Ok(Json(KeyPackageStatsResponse {
        available,
        threshold: RECOMMENDED_THRESHOLD,
        needs_replenish,
        oldest_expires_in,
        by_cipher_suite,
        total,
        consumed,
        consumed_last_24h,
        consumed_last_7d,
        average_daily_consumption,
        predicted_depletion_days,
    }))
}

async fn get_available_count(
    pool: &DbPool,
    did: &str,
    cipher_suite: Option<&str>,
) -> Result<i32, anyhow::Error> {
    let count: i64 = if let Some(suite) = cipher_suite {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM key_packages
            WHERE owner_did = $1
              AND cipher_suite = $2
              AND consumed_at IS NULL
              AND expires_at > NOW()
            "#
        )
        .bind(did)
        .bind(suite)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM key_packages
            WHERE owner_did = $1
              AND consumed_at IS NULL
              AND expires_at > NOW()
            "#
        )
        .bind(did)
        .fetch_one(pool)
        .await?
    };

    Ok(count as i32)
}

async fn get_oldest_expiration(
    pool: &DbPool,
    did: &str,
    cipher_suite: Option<&str>,
) -> Result<Option<DateTime<Utc>>, anyhow::Error> {
    let exp: Option<Option<DateTime<Utc>>> = if let Some(suite) = cipher_suite {
        sqlx::query_scalar(
            r#"
            SELECT MIN(expires_at)
            FROM key_packages
            WHERE owner_did = $1
              AND cipher_suite = $2
              AND consumed_at IS NULL
              AND expires_at > NOW()
            "#
        )
        .bind(did)
        .bind(suite)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query_scalar(
            r#"
            SELECT MIN(expires_at)
            FROM key_packages
            WHERE owner_did = $1
              AND consumed_at IS NULL
              AND expires_at > NOW()
            "#
        )
        .bind(did)
        .fetch_optional(pool)
        .await?
    };

    Ok(exp.flatten())
}

async fn get_stats_by_cipher_suite(
    pool: &DbPool,
    did: &str,
) -> Result<Vec<CipherSuiteStats>, anyhow::Error> {
    struct Row {
        cipher_suite: String,
        available: i64,
        consumed: i64,
    }

    let rows: Vec<Row> = sqlx::query_as!(
        Row,
        r#"
        SELECT
            cipher_suite,
            COUNT(*) FILTER (WHERE consumed_at IS NULL AND expires_at > NOW()) as "available!",
            COUNT(*) FILTER (WHERE consumed_at IS NOT NULL) as "consumed!"
        FROM key_packages
        WHERE owner_did = $1
        GROUP BY cipher_suite
        ORDER BY cipher_suite
        "#,
        did
    )
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|row| CipherSuiteStats {
        cipher_suite: row.cipher_suite,
        available: row.available as i32,
        consumed: Some(row.consumed as i32),
    }).collect())
}

fn format_duration_until(expires_at: DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = expires_at.signed_duration_since(now);

    if duration.num_days() > 0 {
        let days = duration.num_days();
        let hours = duration.num_hours() % 24;
        if hours > 0 {
            format!("{}d {}h", days, hours)
        } else {
            format!("{}d", days)
        }
    } else if duration.num_hours() > 0 {
        let hours = duration.num_hours();
        let minutes = duration.num_minutes() % 60;
        if minutes > 0 {
            format!("{}h {}m", hours, minutes)
        } else {
            format!("{}h", hours)
        }
    } else if duration.num_minutes() > 0 {
        format!("{}m", duration.num_minutes())
    } else if duration.num_seconds() > 0 {
        format!("{}s", duration.num_seconds())
    } else {
        "expired".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[tokio::test]
    async fn test_get_stats_with_available_packages() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig {
            database_url: db_url,
            max_connections: 5,
            min_connections: 1,
            acquire_timeout: std::time::Duration::from_secs(5),
            idle_timeout: std::time::Duration::from_secs(30),
        })
        .await
        .unwrap();

        let did = "did:plc:test_stats_user";
        let cipher_suite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
        let now = Utc::now();
        let expires = now + Duration::days(30);

        // Create 3 key packages
        for i in 0..3 {
            let key_data = format!("key_package_{}", i).into_bytes();
            let _ = crate::db::store_key_package(&pool, did, cipher_suite, key_data, expires).await;
        }

        let auth_user = AuthUser {
            did: did.to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: did.to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        let result = get_key_package_stats(
            State(pool),
            auth_user,
            RawQuery(None),
        )
        .await;

        assert!(result.is_ok());
        let stats = result.unwrap().0;
        assert_eq!(stats.available, 3);
        assert_eq!(stats.threshold, 5);
        assert_eq!(stats.needs_replenish, true); // 3 < 5
        assert!(stats.oldest_expires_in.is_some());
    }

    #[test]
    fn test_format_duration() {
        let now = Utc::now();

        // Test days and hours
        let in_2d_3h = now + Duration::days(2) + Duration::hours(3);
        assert_eq!(format_duration_until(in_2d_3h), "2d 3h");

        // Test just days
        let in_5d = now + Duration::days(5);
        let formatted = format_duration_until(in_5d);
        assert!(formatted.starts_with("5d") || formatted.starts_with("4d")); // Allow for rounding

        // Test hours and minutes
        let in_3h_15m = now + Duration::hours(3) + Duration::minutes(15);
        assert_eq!(format_duration_until(in_3h_15m), "3h 15m");

        // Test just minutes
        let in_45m = now + Duration::minutes(45);
        assert_eq!(format_duration_until(in_45m), "45m");
    }
}
