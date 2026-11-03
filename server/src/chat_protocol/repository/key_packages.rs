// Key-package persistence sink for the clean chat protocol (ruling OQ-9).
//
// This is the single certified writer that turns already-validated key
// packages into `available` `chat.key_packages` rows. Wire/profile/signature
// validation is the caller's job (`wire::validate_key_package`); this module
// only persists the resulting primitive columns, so it stays self-contained
// (`chrono`/`sha2`/`sqlx`/`uuid`) and independently testable — the handler maps
// a `wire::ValidatedKeyPackage` plus its original wire bytes into
// `NewKeyPackage` before calling in. Regular `//` comments (not `//!`) so the
// `#[path]`-including integration harness can inline this file as a module.
//
// `chat.key_packages` is not an inventory-selection domain: publishing an
// `available` package is a plain batch INSERT with no delivery-event append.
// The only cross-row invariant at publish time is the per-device live-inventory
// limit, enforced by the deferred `enforce_live_key_package_limit` trigger at
// COMMIT; this module additionally checks it proactively so it can surface a
// typed error instead of a commit-time abort.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

const UNIQUE_VIOLATION: &str = "23505";
const CHECK_VIOLATION: &str = "23514";
const FOREIGN_KEY_VIOLATION: &str = "23503";

/// The per-device live (`available` + `reserved`) key-package cap enforced by
/// `chat.enforce_live_key_package_limit`. Checked proactively here so a full
/// device surfaces a typed error rather than a deferred commit abort.
const MAX_LIVE_KEY_PACKAGES: i64 = 1000;

#[derive(Debug, Error)]
pub(crate) enum KeyPackageRepositoryError {
    #[error("clean-chat key-package batch was empty")]
    EmptyBatch,
    #[error("clean-chat key-package lifetime is not representable")]
    InvalidLifetime,
    #[error("clean-chat key-package violates a storage invariant")]
    ConstraintViolation,
    #[error("clean-chat key-package ref or init key already exists")]
    DuplicateKeyPackage,
    #[error("clean-chat device key-package inventory limit reached")]
    LiveLimitExceeded,
    #[error("clean-chat key-package owner device key is missing")]
    OwnerKeyMissing,
    #[error("clean-chat key-package owner device is revoked")]
    OwnerRevoked,
    #[error("clean-chat key-package publication authority belongs to another transaction")]
    ForeignTransaction,
    #[error("clean-chat key-package database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// The device that owns the published key packages. The caller has already
/// authorized this device; the owner identity here binds the rows to it.
pub(crate) struct KeyPackageOwner<'a> {
    pub(crate) user_did: &'a str,
    pub(crate) device_id: Uuid,
    pub(crate) key_id: &'a str,
    pub(crate) auth_generation: i64,
}

/// One publishable, already-validated key package projected to its storage
/// columns. `wrapper_bytes` is the exact validatable `MLSMessage` wire form (so
/// recovery hydration can re-validate it); `not_*_unix` are Unix seconds.
pub(crate) struct NewKeyPackage<'a> {
    pub(crate) key_package_ref: &'a [u8],
    pub(crate) wrapper_bytes: &'a [u8],
    pub(crate) init_key: &'a [u8],
    pub(crate) not_before_unix: u64,
    pub(crate) not_after_unix: u64,
}

/// Persist a batch of validated key packages as `available` rows owned by
/// `owner`, all inside the caller's transaction. Returns the number of rows
/// inserted. Rejects a revoked owner (defense in depth) and a batch that would
/// exceed the per-device live-inventory limit before writing any row.
pub(crate) async fn publish_key_packages(
    transaction: &mut Transaction<'_, Postgres>,
    owner: &KeyPackageOwner<'_>,
    packages: &[NewKeyPackage<'_>],
    created_at: DateTime<Utc>,
) -> Result<u64, KeyPackageRepositoryError> {
    if packages.is_empty() {
        return Err(KeyPackageRepositoryError::EmptyBatch);
    }

    // Lock the owning device + key. The FK already requires the key row to
    // exist; this additionally refuses to mint packages for a revoked owner.
    let guard: Option<(String, Option<DateTime<Utc>>)> = sqlx::query_as(
        r#"
        SELECT d.status, k.revoked_at
        FROM chat.device_keys k
        JOIN chat.devices d
          ON d.user_did = k.user_did AND d.device_id = k.device_id
        WHERE k.user_did = $1 AND k.device_id = $2 AND k.key_id = $3
          AND d.auth_generation = $4
          AND k.enrollment_auth_generation <= d.auth_generation
          AND NOT EXISTS(SELECT 1 FROM chat.device_keys newer
              WHERE newer.user_did=k.user_did AND newer.device_id=k.device_id
                AND newer.enrollment_auth_generation>k.enrollment_auth_generation
                AND newer.enrollment_auth_generation<=d.auth_generation)
        FOR UPDATE OF d, k
        "#,
    )
    .bind(owner.user_did)
    .bind(owner.device_id)
    .bind(owner.key_id)
    .bind(owner.auth_generation)
    .fetch_optional(&mut **transaction)
    .await?;
    let (status, revoked_at) = guard.ok_or(KeyPackageRepositoryError::OwnerKeyMissing)?;
    if status != "active" || revoked_at.is_some() {
        return Err(KeyPackageRepositoryError::OwnerRevoked);
    }

    // Proactive live-inventory limit; the deferred DDL trigger remains the
    // ultimate backstop against a concurrent interleave.
    let live: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM chat.key_packages
        WHERE owner_did = $1 AND owner_device_id = $2
          AND status IN ('available', 'reserved')
        "#,
    )
    .bind(owner.user_did)
    .bind(owner.device_id)
    .fetch_one(&mut **transaction)
    .await?;
    let projected = live.saturating_add(packages.len() as i64);
    if projected > MAX_LIVE_KEY_PACKAGES {
        return Err(KeyPackageRepositoryError::LiveLimitExceeded);
    }

    for package in packages {
        let not_before = unix_to_timestamptz(package.not_before_unix)?;
        let not_after = unix_to_timestamptz(package.not_after_unix)?;
        let wrapper_sha256 = Sha256::digest(package.wrapper_bytes).to_vec();
        let result = sqlx::query(
            r#"
            INSERT INTO chat.key_packages(
                key_package_ref, wrapper_bytes, wrapper_sha256, init_key,
                owner_did, owner_device_id, owner_key_id, owner_auth_generation,
                not_before, not_after, status, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'available', $11)
            "#,
        )
        .bind(package.key_package_ref)
        .bind(package.wrapper_bytes)
        .bind(&wrapper_sha256)
        .bind(package.init_key)
        .bind(owner.user_did)
        .bind(owner.device_id)
        .bind(owner.key_id)
        .bind(owner.auth_generation)
        .bind(not_before)
        .bind(not_after)
        .bind(created_at)
        .execute(&mut **transaction)
        .await;
        if let Err(error) = result {
            return Err(classify_insert_error(error));
        }
    }
    Ok(packages.len() as u64)
}

/// Reserve one recovery KeyPackage of `owner_did` for an authorized remote DS
/// (GET `blue.catbird.mlsDS.fetchKeyPackage`) inside the caller's transaction.
/// Locks follow the canonical principal -> device -> package order of
/// enrollment, replenishment, recovery and direct requests, so the deferred
/// mapping's principal lock at commit is already held. Only a device whose
/// current key is in `authorized_signing_keys` qualifies; a package under a live
/// group export lease is left to its pending acceptance. Returns the wrapper and
/// its SHA-256, or `None` when nothing is available.
pub(crate) async fn reserve_federated_key_package(
    transaction: &mut Transaction<'_, Postgres>,
    owner_did: &str,
    requester_ds_did: &str,
    authorized_signing_keys: &[Vec<u8>],
    now: DateTime<Utc>,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, sqlx::Error> {
    let principal: Option<String> =
        sqlx::query_scalar("SELECT user_did FROM chat.principals WHERE user_did = $1 FOR UPDATE")
            .bind(owner_did)
            .fetch_optional(&mut **transaction)
            .await?;
    if principal.is_none() {
        return Ok(None);
    }
    let devices: Vec<(Uuid, String, i64)> = sqlx::query_as(
        r#"
        SELECT d.device_id, k.key_id, d.auth_generation
        FROM chat.devices d
        JOIN chat.device_keys k ON k.user_did = d.user_did AND k.device_id = d.device_id
        WHERE d.user_did = $1 AND d.status = 'active' AND d.revoked_at IS NULL
          AND k.revoked_at IS NULL AND k.signing_public_key = ANY($2)
          AND k.enrollment_auth_generation <= d.auth_generation
          AND NOT EXISTS(SELECT 1 FROM chat.device_keys newer
              WHERE newer.user_did = k.user_did AND newer.device_id = k.device_id
                AND newer.enrollment_auth_generation > k.enrollment_auth_generation
                AND newer.enrollment_auth_generation <= d.auth_generation)
        ORDER BY uuid_send(d.device_id)
        FOR SHARE OF d
        "#,
    )
    .bind(owner_did)
    .bind(authorized_signing_keys)
    .fetch_all(&mut **transaction)
    .await?;
    let device_ids: Vec<Uuid> = devices.iter().map(|device| device.0).collect();
    let key_ids: Vec<&str> = devices.iter().map(|device| device.1.as_str()).collect();
    let generations: Vec<i64> = devices.iter().map(|device| device.2).collect();
    let candidate: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT p.key_package_ref, p.wrapper_bytes, p.wrapper_sha256
        FROM chat.key_packages p
        JOIN unnest($2::uuid[], $3::text[], $4::bigint[]) AS d(device_id, key_id, auth_generation)
          ON p.owner_device_id = d.device_id AND p.owner_key_id = d.key_id
         AND p.owner_auth_generation = d.auth_generation
        WHERE p.owner_did = $1 AND p.usage_scope = 'recovery' AND p.status = 'available'
          AND p.not_before < $5 AND $5 < p.not_after
          AND NOT EXISTS(SELECT 1 FROM chat.group_key_package_exports e
              WHERE e.key_package_ref = p.key_package_ref AND e.expires_at > $5)
        ORDER BY p.created_at, p.key_package_ref
        LIMIT 1
        FOR UPDATE OF p SKIP LOCKED
        "#,
    )
    .bind(owner_did)
    .bind(&device_ids)
    .bind(&key_ids)
    .bind(&generations)
    .bind(now)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some((key_package_ref, wrapper_bytes, wrapper_sha256)) = candidate else {
        return Ok(None);
    };
    sqlx::query(
        "UPDATE chat.key_packages SET status = 'reserved' \
          WHERE key_package_ref = $1 AND status = 'available'",
    )
    .bind(&key_package_ref)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO chat.federated_key_package_reservations \
             (key_package_ref, requester_ds_did, reserved_at) VALUES ($1, $2, $3)",
    )
    .bind(&key_package_ref)
    .bind(requester_ds_did)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    Ok(Some((wrapper_bytes, wrapper_sha256)))
}

fn unix_to_timestamptz(secs: u64) -> Result<DateTime<Utc>, KeyPackageRepositoryError> {
    let secs = i64::try_from(secs).map_err(|_| KeyPackageRepositoryError::InvalidLifetime)?;
    DateTime::from_timestamp(secs, 0).ok_or(KeyPackageRepositoryError::InvalidLifetime)
}

fn classify_insert_error(error: sqlx::Error) -> KeyPackageRepositoryError {
    if let sqlx::Error::Database(db) = &error {
        match db.code().as_deref() {
            Some(UNIQUE_VIOLATION) => return KeyPackageRepositoryError::DuplicateKeyPackage,
            Some(CHECK_VIOLATION) => return KeyPackageRepositoryError::ConstraintViolation,
            Some(FOREIGN_KEY_VIOLATION) => return KeyPackageRepositoryError::OwnerKeyMissing,
            _ => {}
        }
    }
    KeyPackageRepositoryError::Database(error)
}
