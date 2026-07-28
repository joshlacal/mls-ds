// Read-only device-directory projections for the clean chat protocol (Task 4,
// seal 2b). These build the exact fields the `deviceView` / `addressableDevice`
// / `ownDeviceView` lexicon outputs need, which no existing certified read
// returns: the per-device key identity (`chat.device_keys`), the pinned
// capability profile (`chat.devices.capabilities` JSONB), and the live
// key-package counts (`chat.key_packages`).
//
// Self-contained (`chrono`/`sqlx`/`uuid`) so the `#[path]`-including harness can
// inline this file as a module; regular `//` comments (not `//!`) for the same
// reason. Capabilities are read as `::text` because the crate's sqlx build has
// no `json` feature; the handler decodes that text into the generated
// `deviceCapability` DTO (a decode mismatch is an internal invariant violation,
// never a silent default).
//
// Predicates MIRROR the certified surface, they do not invent:
//   - "available"/"reserved" key packages = `status = 'available'` /
//     `status = 'reserved'` — status-only, NOT time-windowed. This matches the
//     certified `chat.key_packages` surface (repository/key_packages.rs:112 live
//     count `status IN ('available','reserved')`; repository/transition.rs:1468
//     `cas_key_package_status` matches on `status = $2` only). The time-windowed
//     `expires_at > NOW()` predicate belongs to the LEGACY key_packages table in
//     the `public` schema (handlers/mls_chat/get_key_packages.rs) and is NOT
//     copied. Counts filter to the exact status literals so a future
//     `key_packages` status can never silently inflate a live count.
//   - The device's key is a per-device singleton: `chat.device_keys` PRIMARY KEY
//     is `(user_did, device_id)` (core.sql:337), so the JOIN yields exactly one
//     key row; there is no multi-key ambiguity.
//
// Bounding for the getDevices path is NOT reimplemented here: the getDevices
// handler reuses the certified `inventory::get_devices` verbatim (its
// MAX_GET_DEVICES_DIDS / MAX_DEVICES_PER_DID / MAX_GET_DEVICES_TOTAL bounds and
// `(user_did, created_at, device_id)` order) for the audience set, then enriches
// each returned device via `read_device_view`. This module therefore introduces
// no device-count bound constant of its own.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub(crate) enum DeviceDirectoryError {
    #[error("clean-chat device-directory database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, Error)]
pub(crate) enum RevocationDeviceViewError {
    #[error("clean-chat revocation device-view database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("clean-chat revocation target device is missing")]
    Missing,
    #[error("clean-chat revocation target device is already revoked")]
    Revoked,
    #[error("clean-chat revocation target authentication generation changed")]
    AuthGenerationConflict,
    #[error("clean-chat revocation device-view projection is inconsistent")]
    Projection,
}

/// Every column the `deviceView` lexicon output needs for one device, plus the
/// raw pinned capability JSON (decoded by the handler). `available_package_count`
/// / `reserved_package_count` are the live status-only counts.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct DeviceDirectoryView {
    pub(crate) device_id: Uuid,
    pub(crate) key_id: String,
    pub(crate) signing_public_key: Vec<u8>,
    pub(crate) auth_generation: i64,
    pub(crate) dpop_jkt: String,
    pub(crate) status: String,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
    pub(crate) available_package_count: i64,
    pub(crate) reserved_package_count: i64,
    pub(crate) capabilities_json: String,
}

/// Transaction-bound prewrite projection of the exact active target device
/// and its immutable key. The G6 facade locks this before any business writer,
/// then consumes it to derive the response's post-revocation `deviceView`
/// without a post-write SQL read.
#[must_use]
pub(crate) struct LockedRevocationDeviceView {
    transaction_id: Box<str>,
    target_did: Box<str>,
    locked_at: DateTime<Utc>,
    active: DeviceDirectoryView,
    locked_row_digest: [u8; 32],
}

impl LockedRevocationDeviceView {
    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    /// Consume the prewrite projection only when the sealed batch accounts for
    /// every live package counted under the target device lock. The resulting
    /// value is the exact state produced by the batch-level registration and
    /// package CASes: identity fields are unchanged, status is terminal, both
    /// live counts are zero, and `updated_at` is the server acceptance instant.
    pub(crate) fn into_post_revocation_view(
        self,
        target_did: &str,
        target_device_id: Uuid,
        target_auth_generation: u64,
        accepted_at: DateTime<Utc>,
        revoked_live_package_count: usize,
    ) -> Result<DeviceDirectoryView, RevocationDeviceViewError> {
        let counted_live_packages = self
            .active
            .available_package_count
            .checked_add(self.active.reserved_package_count)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(RevocationDeviceViewError::Projection)?;
        let expected_digest = revocation_device_view_digest(
            &self.transaction_id,
            &self.target_did,
            self.locked_at,
            &self.active,
        );
        if self.locked_row_digest != expected_digest
            || self.target_did.as_ref() != target_did
            || self.active.device_id != target_device_id
            || u64::try_from(self.active.auth_generation).ok() != Some(target_auth_generation)
            || self.active.status != "active"
            || accepted_at != self.locked_at
            || counted_live_packages != revoked_live_package_count
        {
            return Err(RevocationDeviceViewError::Projection);
        }
        Ok(DeviceDirectoryView {
            device_id: self.active.device_id,
            key_id: self.active.key_id,
            signing_public_key: self.active.signing_public_key,
            auth_generation: self.active.auth_generation,
            dpop_jkt: self.active.dpop_jkt,
            status: "revoked".to_owned(),
            created_at: self.active.created_at,
            updated_at: accepted_at,
            available_package_count: 0,
            reserved_package_count: 0,
            capabilities_json: self.active.capabilities_json,
        })
    }
}

#[derive(sqlx::FromRow)]
struct ActiveRevocationDeviceViewRow {
    device_id: Uuid,
    key_id: String,
    signing_public_key: Vec<u8>,
    auth_generation: i64,
    enrollment_auth_generation: i64,
    dpop_jkt: String,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    device_revoked_at: Option<DateTime<Utc>>,
    device_revocation_id: Option<Uuid>,
    key_revoked_at: Option<DateTime<Utc>>,
    key_revocation_id: Option<Uuid>,
    available_package_count: i64,
    reserved_package_count: i64,
    capabilities_json: String,
}

const SELECT_DEVICE_VIEW: &str = r#"
    SELECT device.device_id AS device_id,
           device_key.key_id AS key_id,
           device_key.signing_public_key AS signing_public_key,
           device.auth_generation AS auth_generation,
           device.dpop_jkt AS dpop_jkt,
           device.status AS status,
           device.created_at AS created_at,
           device.updated_at AS updated_at,
           device.capabilities::text AS capabilities_json,
           (SELECT count(*)
              FROM chat.key_packages kp
             WHERE kp.owner_did = device.user_did
               AND kp.owner_device_id = device.device_id
               AND kp.status = 'available') AS available_package_count,
           (SELECT count(*)
              FROM chat.key_packages kp
             WHERE kp.owner_did = device.user_did
               AND kp.owner_device_id = device.device_id
               AND kp.status = 'reserved') AS reserved_package_count
      FROM chat.devices device
      JOIN chat.device_keys device_key
        ON device_key.user_did = device.user_did
       AND device_key.device_id = device.device_id
"#;

/// The full `deviceView` projection for one device identified by its primary
/// key `(user_did, device_id)`. Returns `None` when the device (or its key row)
/// does not exist. Status-agnostic: an active or revoked device both resolve
/// (the `status` field carries which), so it serves enroll/replenish/rebind
/// outputs and per-device enrichment for getDevices/getOwnDevices alike.
pub(crate) async fn read_device_view(
    transaction: &mut Transaction<'_, Postgres>,
    user_did: &str,
    device_id: Uuid,
) -> Result<Option<DeviceDirectoryView>, DeviceDirectoryError> {
    let query =
        format!("{SELECT_DEVICE_VIEW} WHERE device.user_did = $1 AND device.device_id = $2");
    let view = sqlx::query_as::<_, DeviceDirectoryView>(&query)
        .bind(user_did)
        .bind(device_id)
        .fetch_optional(&mut **transaction)
        .await?;
    Ok(view)
}

/// Lock and seal the complete response projection for a first-execution G6
/// revocation. The shared identity prelude already owns these row locks; the
/// explicit `FOR UPDATE` keeps this boundary independently fail-closed and
/// prevents a future caller from using it without that prelude.
pub(crate) async fn lock_active_revocation_device_view(
    transaction: &mut Transaction<'_, Postgres>,
    target_did: &str,
    target_device_id: Uuid,
    target_auth_generation: u64,
    locked_at: DateTime<Utc>,
) -> Result<LockedRevocationDeviceView, RevocationDeviceViewError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    let row: Option<ActiveRevocationDeviceViewRow> = sqlx::query_as(
        r#"
        SELECT device.device_id,
               device_key.key_id,
               device_key.signing_public_key,
               device.auth_generation,
               device_key.enrollment_auth_generation,
               device.dpop_jkt,
               device.status,
               device.created_at,
               device.updated_at,
               device.revoked_at AS device_revoked_at,
               device.revocation_id AS device_revocation_id,
               device_key.revoked_at AS key_revoked_at,
               device_key.revocation_id AS key_revocation_id,
               device.capabilities::text AS capabilities_json,
               (SELECT count(*)
                  FROM chat.key_packages kp
                 WHERE kp.owner_did=device.user_did
                   AND kp.owner_device_id=device.device_id
                   AND kp.status='available') AS available_package_count,
               (SELECT count(*)
                  FROM chat.key_packages kp
                 WHERE kp.owner_did=device.user_did
                   AND kp.owner_device_id=device.device_id
                   AND kp.status='reserved') AS reserved_package_count
          FROM chat.devices device
          JOIN chat.device_keys device_key
            ON device_key.user_did=device.user_did
           AND device_key.device_id=device.device_id
         WHERE device.user_did=$1
           AND device.device_id=$2
         FOR UPDATE OF device,device_key
        "#,
    )
    .bind(target_did)
    .bind(target_device_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let row = match row {
        Some(row) => row,
        None => {
            let device_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM chat.devices WHERE user_did=$1 AND device_id=$2)",
            )
            .bind(target_did)
            .bind(target_device_id)
            .fetch_one(&mut **transaction)
            .await?;
            return Err(if device_exists {
                RevocationDeviceViewError::Projection
            } else {
                RevocationDeviceViewError::Missing
            });
        }
    };
    let active = validate_active_revocation_device_view_row(
        row,
        target_device_id,
        target_auth_generation,
        locked_at,
    )?;
    let locked_row_digest =
        revocation_device_view_digest(&transaction_id, target_did, locked_at, &active);
    Ok(LockedRevocationDeviceView {
        transaction_id: transaction_id.into_boxed_str(),
        target_did: target_did.to_owned().into_boxed_str(),
        locked_at,
        active,
        locked_row_digest,
    })
}

fn validate_active_revocation_device_view_row(
    row: ActiveRevocationDeviceViewRow,
    target_device_id: Uuid,
    target_auth_generation: u64,
    locked_at: DateTime<Utc>,
) -> Result<DeviceDirectoryView, RevocationDeviceViewError> {
    let target_auth_generation =
        i64::try_from(target_auth_generation).map_err(|_| RevocationDeviceViewError::Projection)?;
    if row.device_id != target_device_id
        || row.enrollment_auth_generation <= 0
        || row.enrollment_auth_generation > row.auth_generation
        || row.signing_public_key.len() != 32
        || row.created_at > row.updated_at
        || locked_at.timestamp_millis() < 0
        || locked_at.timestamp_subsec_nanos() % 1_000_000 != 0
        || row.available_package_count < 0
        || row.reserved_package_count < 0
    {
        return Err(RevocationDeviceViewError::Projection);
    }
    match row.status.as_str() {
        "active"
            if row.device_revoked_at.is_none()
                && row.device_revocation_id.is_none()
                && row.key_revoked_at.is_none()
                && row.key_revocation_id.is_none()
                && row.updated_at <= locked_at => {}
        "revoked"
            if row.device_revoked_at.is_some()
                && row.device_revocation_id.is_some()
                && row.key_revoked_at == row.device_revoked_at
                && row.key_revocation_id == row.device_revocation_id
                && row.updated_at == row.device_revoked_at.unwrap() =>
        {
            return Err(RevocationDeviceViewError::Revoked);
        }
        _ => return Err(RevocationDeviceViewError::Projection),
    }
    if row.auth_generation != target_auth_generation {
        return Err(RevocationDeviceViewError::AuthGenerationConflict);
    }
    Ok(DeviceDirectoryView {
        device_id: row.device_id,
        key_id: row.key_id,
        signing_public_key: row.signing_public_key,
        auth_generation: row.auth_generation,
        dpop_jkt: row.dpop_jkt,
        status: row.status,
        created_at: row.created_at,
        updated_at: row.updated_at,
        available_package_count: row.available_package_count,
        reserved_package_count: row.reserved_package_count,
        capabilities_json: row.capabilities_json,
    })
}

/// Every device owned by `user_did` (active AND revoked), in the canonical
/// `(created_at, device_id)` order the certified directory read uses. Feeds the
/// getOwnDevices device-inventory fence, one `ownDeviceView` per row.
pub(crate) async fn list_own_device_views(
    transaction: &mut Transaction<'_, Postgres>,
    user_did: &str,
) -> Result<Vec<DeviceDirectoryView>, DeviceDirectoryError> {
    let query = format!(
        "{SELECT_DEVICE_VIEW} WHERE device.user_did = $1 \
         ORDER BY device.created_at, device.device_id"
    );
    let views = sqlx::query_as::<_, DeviceDirectoryView>(&query)
        .bind(user_did)
        .fetch_all(&mut **transaction)
        .await?;
    Ok(views)
}

fn revocation_device_view_digest(
    transaction_id: &str,
    target_did: &str,
    locked_at: DateTime<Utc>,
    view: &DeviceDirectoryView,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-LOCKED-REVOCATION-DEVICE-VIEW\0");
    for value in [
        transaction_id.as_bytes(),
        target_did.as_bytes(),
        view.key_id.as_bytes(),
        view.signing_public_key.as_slice(),
        view.dpop_jkt.as_bytes(),
        view.status.as_bytes(),
        view.capabilities_json.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update(view.device_id.as_bytes());
    digest.update(view.auth_generation.to_be_bytes());
    digest.update(view.created_at.timestamp_micros().to_be_bytes());
    digest.update(view.updated_at.timestamp_micros().to_be_bytes());
    digest.update(view.available_package_count.to_be_bytes());
    digest.update(view.reserved_package_count.to_be_bytes());
    digest.update(locked_at.timestamp_millis().to_be_bytes());
    digest.finalize().into()
}

#[cfg(test)]
mod revocation_tests {
    use super::*;

    fn active_view() -> DeviceDirectoryView {
        DeviceDirectoryView {
            device_id: Uuid::parse_str("a65a1a3b-a442-4bfd-9f08-c6877e5c7ecb").unwrap(),
            key_id: "ERERERERERERERERERERERERERERERERERERERERERE".to_owned(),
            signing_public_key: vec![17; 32],
            auth_generation: 3,
            dpop_jkt: "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI".to_owned(),
            status: "active".to_owned(),
            created_at: DateTime::from_timestamp_millis(1_700_000_000_000).unwrap(),
            updated_at: DateTime::from_timestamp_millis(1_700_000_001_000).unwrap(),
            available_package_count: 2,
            reserved_package_count: 1,
            capabilities_json: "{\"mlsProtocolVersion\":\"1.0\"}".to_owned(),
        }
    }

    fn locked_view() -> LockedRevocationDeviceView {
        let transaction_id = "g6-pure-transaction";
        let target_did = "did:plc:g6puretest";
        let locked_at = DateTime::from_timestamp_millis(1_700_000_002_000).unwrap();
        let active = active_view();
        let locked_row_digest =
            revocation_device_view_digest(transaction_id, target_did, locked_at, &active);
        LockedRevocationDeviceView {
            transaction_id: transaction_id.to_owned().into_boxed_str(),
            target_did: target_did.to_owned().into_boxed_str(),
            locked_at,
            active,
            locked_row_digest,
        }
    }

    fn active_row() -> ActiveRevocationDeviceViewRow {
        let view = active_view();
        ActiveRevocationDeviceViewRow {
            device_id: view.device_id,
            key_id: view.key_id,
            signing_public_key: view.signing_public_key,
            auth_generation: view.auth_generation,
            enrollment_auth_generation: 1,
            dpop_jkt: view.dpop_jkt,
            status: view.status,
            created_at: view.created_at,
            updated_at: view.updated_at,
            device_revoked_at: None,
            device_revocation_id: None,
            key_revoked_at: None,
            key_revocation_id: None,
            available_package_count: view.available_package_count,
            reserved_package_count: view.reserved_package_count,
            capabilities_json: view.capabilities_json,
        }
    }

    #[test]
    fn g6_prewrite_derives_the_exact_terminal_device_view() {
        let target = active_view().device_id;
        let accepted_at = DateTime::from_timestamp_millis(1_700_000_002_000).unwrap();
        let post = locked_view()
            .into_post_revocation_view("did:plc:g6puretest", target, 3, accepted_at, 3)
            .expect("complete sealed package footprint");
        assert_eq!(post.device_id, target);
        assert_eq!(post.status, "revoked");
        assert_eq!(post.updated_at, accepted_at);
        assert_eq!(post.available_package_count, 0);
        assert_eq!(post.reserved_package_count, 0);
        assert_eq!(post.key_id, active_view().key_id);
        assert_eq!(post.signing_public_key, active_view().signing_public_key);
    }

    #[test]
    fn g6_prewrite_rejects_an_incomplete_package_footprint() {
        let target = active_view().device_id;
        let accepted_at = DateTime::from_timestamp_millis(1_700_000_002_000).unwrap();
        assert!(locked_view()
            .into_post_revocation_view("did:plc:g6puretest", target, 3, accepted_at, 2)
            .is_err());
    }

    #[test]
    fn g6_prewrite_rejects_a_tampered_projection_seal() {
        let target = active_view().device_id;
        let accepted_at = DateTime::from_timestamp_millis(1_700_000_002_000).unwrap();
        let mut locked = locked_view();
        locked.locked_row_digest[0] ^= 1;
        assert!(locked
            .into_post_revocation_view("did:plc:g6puretest", target, 3, accepted_at, 3)
            .is_err());
    }

    #[test]
    fn g6_target_generation_conflict_is_semantic() {
        let row = active_row();
        let device_id = row.device_id;
        let locked_at = DateTime::from_timestamp_millis(1_700_000_002_000).unwrap();
        assert!(matches!(
            validate_active_revocation_device_view_row(row, device_id, 4, locked_at),
            Err(RevocationDeviceViewError::AuthGenerationConflict)
        ));
    }

    #[test]
    fn g6_already_revoked_target_is_semantic_but_corrupt_mapping_is_not() {
        let mut row = active_row();
        let device_id = row.device_id;
        let accepted_at = DateTime::from_timestamp_millis(1_700_000_002_000).unwrap();
        let revocation_id = Uuid::parse_str("db1a8853-0a86-4fe3-9eb7-569106628ff9").unwrap();
        row.status = "revoked".to_owned();
        row.updated_at = accepted_at;
        row.device_revoked_at = Some(accepted_at);
        row.device_revocation_id = Some(revocation_id);
        row.key_revoked_at = Some(accepted_at);
        row.key_revocation_id = Some(revocation_id);
        assert!(matches!(
            validate_active_revocation_device_view_row(row, device_id, 3, accepted_at),
            Err(RevocationDeviceViewError::Revoked)
        ));

        let mut corrupt = active_row();
        corrupt.status = "revoked".to_owned();
        corrupt.updated_at = accepted_at;
        corrupt.device_revoked_at = Some(accepted_at);
        corrupt.device_revocation_id = Some(revocation_id);
        corrupt.key_revoked_at = Some(accepted_at);
        corrupt.key_revocation_id =
            Some(Uuid::parse_str("94497004-0ca0-4c20-b3e5-54dc5dc7d6ef").unwrap());
        assert!(matches!(
            validate_active_revocation_device_view_row(corrupt, device_id, 3, accepted_at),
            Err(RevocationDeviceViewError::Projection)
        ));
    }
}
