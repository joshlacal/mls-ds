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
        FOR UPDATE OF d, k
        "#,
    )
    .bind(owner.user_did)
    .bind(owner.device_id)
    .bind(owner.key_id)
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
