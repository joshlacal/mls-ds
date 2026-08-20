//! Shared projection of the certified `device_directory` read rows into the
//! generated `blue.catbird.chat` wire DTOs (`deviceView` / `addressableDevice` /
//! `ownDeviceView`), plus the endpoint-declared error mapping for the certified
//! repository sinks the device handlers compose.
//!
//! One code path builds every `deviceView` so enroll/replenish/rebind/getDevices/
//! getOwnDevices cannot drift in field shaping. The pinned device capability is
//! ALWAYS decoded from the stored `chat.devices.capabilities` JSON into the
//! generated `deviceCapability` DTO — never reconstructed in Rust — and a decode
//! mismatch is an internal invariant violation, never a silent default (seal-2b
//! ruling (c)).

use jacquard_common::deps::bytes::Bytes;
use jacquard_common::deps::smol_str::SmolStr;
use jacquard_common::DefaultStr;

use catbird_atproto::generated::blue_catbird::chat as chat_dto;

use crate::chat_protocol::error::{ChatEndpoint, ChatProtocolErrorCode};
use crate::chat_protocol::repository::device_directory::{
    DeviceDirectoryError, DeviceDirectoryView,
};
use crate::chat_protocol::repository::inventory::InventoryRepositoryError;
use crate::chat_protocol::repository::key_packages::KeyPackageRepositoryError;
use crate::chat_protocol::transcript::{CanonicalValueRef, ClosedObjectRef};
use crate::sqlx_jacquard::chrono_to_datetime;

use super::errors::ChatFailure;

/// The canonical hyphenated lowercase UUID string for a device id.
fn device_id_string(view: &DeviceDirectoryView) -> SmolStr {
    SmolStr::from(view.device_id.to_string())
}

/// Decode the pinned capability JSON into the generated `deviceCapability` DTO.
/// A decode failure is a stored-shape invariant break (the column is
/// DDL-pinned to `chat.protocol_capabilities()`), surfaced as an internal
/// invariant violation with no wire vocabulary.
fn decode_capability(
    view: &DeviceDirectoryView,
    endpoint: ChatEndpoint,
) -> Result<chat_dto::DeviceCapability<DefaultStr>, ChatFailure> {
    serde_json::from_str::<chat_dto::DeviceCapability<DefaultStr>>(&view.capabilities_json)
        .map_err(|_| ChatFailure::invariant(endpoint))
}

/// Build the full `deviceView` straight from a certified directory row. Used
/// verbatim by replenish (post-publish) and getOwnDevices; enroll and rebind
/// build a `deviceView` with the same field shaping but override the fields the
/// mutation changes (rebind) or that no row yet carries (enroll first-execution).
pub(super) fn device_view_from_directory(
    view: &DeviceDirectoryView,
) -> chat_dto::DeviceView<DefaultStr> {
    chat_dto::DeviceView {
        auth_generation: view.auth_generation,
        available_package_count: view.available_package_count,
        created_at: chrono_to_datetime(view.created_at),
        device_id: device_id_string(view),
        key_id: SmolStr::from(view.key_id.as_str()),
        reserved_package_count: view.reserved_package_count,
        signature_public_key: Bytes::from(view.signing_public_key.clone()),
        status: SmolStr::from(view.status.as_str()),
        updated_at: chrono_to_datetime(view.updated_at),
        extra_data: None,
    }
}

/// Build the `addressableDevice` projection for one enriched directory row
/// (getDevices). Carries the key identity, the decoded pinned capability, and the
/// live available-package count.
pub(super) fn addressable_device_from_directory(
    view: &DeviceDirectoryView,
    user_did: &str,
    endpoint: ChatEndpoint,
) -> Result<chat_dto::AddressableDevice<DefaultStr>, ChatFailure> {
    let capability = decode_capability(view, endpoint)?;
    let user_did = jacquard_common::types::string::Did::new_owned(user_did)
        .map_err(|_| ChatFailure::invariant(endpoint))?;
    Ok(chat_dto::AddressableDevice {
        available_package_count: view.available_package_count,
        capability,
        device_id: device_id_string(view),
        key_id: SmolStr::from(view.key_id.as_str()),
        user_did,
        extra_data: None,
    })
}

/// Wrap a `deviceView` as an `ownDeviceView` (getOwnDevices fence item).
pub(super) fn own_device_view(
    device: chat_dto::DeviceView<DefaultStr>,
) -> chat_dto::OwnDeviceView<DefaultStr> {
    chat_dto::OwnDeviceView {
        device,
        extra_data: None,
    }
}

/// One key package as it travels in the signed request body: the exact MLS
/// wire-form `bytes` and the declared `keyPackageRef`. Owned so it outlives the
/// borrowed canonical projection.
pub(super) struct RawKeyPackage {
    pub(super) wrapper: Vec<u8>,
    pub(super) key_package_ref: Vec<u8>,
}

/// Extract the `keyPackages` array + `signaturePublicKey` from a signed mutation's
/// canonical projection body. This reads the CERTIFIED canonical decode (bytes are
/// real byte strings), not the generated DTO (whose JSON bytes helper expects a
/// `{$bytes: …}` object that the signed-request wire form does not use). A
/// missing/wrong-shaped field is an internal invariant break — the auth layer
/// already proved the body decodes and its signature verifies.
pub(super) fn extract_key_packages(
    body: &ClosedObjectRef<'_>,
    endpoint: ChatEndpoint,
) -> Result<(Vec<RawKeyPackage>, Vec<u8>), ChatFailure> {
    let signature_public_key = match body.get("signaturePublicKey") {
        Some(CanonicalValueRef::Bytes(bytes)) => bytes.to_vec(),
        _ => return Err(ChatFailure::invariant(endpoint)),
    };
    let array = match body.get("keyPackages") {
        Some(CanonicalValueRef::Array(array)) => array,
        _ => return Err(ChatFailure::invariant(endpoint)),
    };
    let mut packages = Vec::with_capacity(array.len());
    for index in 0..array.len() {
        let object = match array.get(index) {
            Some(CanonicalValueRef::Object(object)) => object,
            _ => return Err(ChatFailure::invariant(endpoint)),
        };
        let wrapper = match object.get("bytes") {
            Some(CanonicalValueRef::Bytes(bytes)) => bytes.to_vec(),
            _ => return Err(ChatFailure::invariant(endpoint)),
        };
        let key_package_ref = match object.get("keyPackageRef") {
            Some(CanonicalValueRef::Bytes(bytes)) => bytes.to_vec(),
            _ => return Err(ChatFailure::invariant(endpoint)),
        };
        packages.push(RawKeyPackage {
            wrapper,
            key_package_ref,
        });
    }
    Ok((packages, signature_public_key))
}

/// Map a key-package persistence failure to the calling endpoint's declared wire
/// code. Both enrollDevice and replenishKeyPackages declare `InvalidKeyPackage`
/// and `KeyPackageInventoryLimitReached`; every constraint/lifetime rejection is
/// an invalid key package, an over-limit device is the inventory limit, an empty
/// batch is a malformed request, and a revoked/absent owner is the device-state
/// code. Storage faults never carry a protocol code.
///
/// Reachable-code note (M-3): this is a SHARED superset mapper, not every arm is
/// reachable from every caller. On the fresh-enroll path the device + key are
/// inserted active in the same transaction before `publish_key_packages`, so
/// `OwnerRevoked`/`OwnerKeyMissing` (→ `DeviceRevoked`/`DeviceNotRegistered`,
/// which enrollDevice does not declare) cannot fire there; if a future change
/// ever made one reachable for a caller that does not declare it,
/// `ChatFailure::protocol` downgrades it to `InvariantViolation`/500 (OQ-11) — no
/// undeclared code can cross the boundary.
pub(super) fn key_package_failure(
    endpoint: ChatEndpoint,
    error: KeyPackageRepositoryError,
) -> ChatFailure {
    use ChatProtocolErrorCode as C;
    use KeyPackageRepositoryError as E;
    let code = match error {
        E::Database(_) => return ChatFailure::storage(endpoint),
        E::EmptyBatch => C::InvalidRequest,
        E::InvalidLifetime | E::ConstraintViolation | E::DuplicateKeyPackage => {
            C::InvalidKeyPackage
        }
        E::LiveLimitExceeded => C::KeyPackageInventoryLimitReached,
        E::OwnerRevoked => C::DeviceRevoked,
        E::OwnerKeyMissing => C::DeviceNotRegistered,
        E::ForeignTransaction => return ChatFailure::invariant(endpoint),
    };
    ChatFailure::protocol(endpoint, code)
}

/// Map a device-directory read failure. These reads back the certified device
/// state for output shaping; a database fault is an internal storage failure and
/// never a wire code.
pub(super) fn directory_failure(
    endpoint: ChatEndpoint,
    error: DeviceDirectoryError,
) -> ChatFailure {
    match error {
        DeviceDirectoryError::Database(_) => ChatFailure::storage(endpoint),
    }
}

/// Map an inventory read/fence failure for the getDevices / getOwnDevices paths.
/// `SnapshotConflict` is surfaced to the caller so the OQ-8 whole-call retry can
/// re-run; `RequestTooBroad` is a malformed request; every other fault is an
/// internal storage/invariant failure carrying no wire vocabulary.
pub(super) enum InventoryFailure {
    Retryable,
    Terminal(ChatFailure),
}

pub(super) fn inventory_failure(
    endpoint: ChatEndpoint,
    error: InventoryRepositoryError,
) -> InventoryFailure {
    use ChatProtocolErrorCode as C;
    use InventoryRepositoryError as E;
    match error {
        E::SnapshotConflict => InventoryFailure::Retryable,
        E::RequestTooBroad => {
            InventoryFailure::Terminal(ChatFailure::protocol(endpoint, C::InvalidRequest))
        }
        E::Database(_) => InventoryFailure::Terminal(ChatFailure::storage(endpoint)),
        _ => InventoryFailure::Terminal(ChatFailure::invariant(endpoint)),
    }
}
