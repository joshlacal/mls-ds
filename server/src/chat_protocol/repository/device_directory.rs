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
use sqlx::{Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub(crate) enum DeviceDirectoryError {
    #[error("clean-chat device-directory database error: {0}")]
    Database(#[from] sqlx::Error),
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
