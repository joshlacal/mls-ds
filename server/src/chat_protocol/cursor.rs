// Authenticated, domain-separated opaque cursors for clean-chat delivery.

use std::{error::Error, fmt};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};
use uuid::{Uuid, Variant, Version};
use zeroize::Zeroizing;

use super::repository::inventory::LockedInventoryCursorEvidence;
use super::validation::{BareDid, KeyThumbprint};

type HmacSha256 = Hmac<Sha256>;

pub(super) const MAX_OPAQUE_CURSOR_ASCII_BYTES: usize = 512;

const MAGIC: &[u8; 4] = b"CBCC";
const WIRE_VERSION: u8 = 1;
const EVENT_DOMAIN: u8 = 1;
const INVENTORY_SESSION_DOMAIN: u8 = 2;
const INVENTORY_CONVERSATIONS_DOMAIN: u8 = 3;
const INVENTORY_WELCOMES_DOMAIN: u8 = 4;
const INVENTORY_RECOVERY_DOMAIN: u8 = 5;
const OWN_DEVICE_DOMAIN: u8 = 6;
const MAC_BYTES: usize = 32;
const HEADER_BYTES: usize = MAGIC.len() + 1 + 1 + 16 + 32 + 8 + 8;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CursorCodecError {
    InvalidConfiguration,
    InvalidEncoding,
    InvalidField,
    TooLong,
    AuthenticationFailed,
    UnsupportedVersion,
    WrongDomain,
    WrongProtocolInstance,
    WrongKey,
    BindingMismatch,
    DigestMismatch,
    IssuedInFuture,
    Expired,
    BelowRetentionFloor,
    PositionInFuture,
}

impl fmt::Display for CursorCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid clean-chat cursor configuration",
            Self::InvalidEncoding => "invalid clean-chat cursor encoding",
            Self::InvalidField => "invalid clean-chat cursor field",
            Self::TooLong => "clean-chat cursor exceeds its public size limit",
            Self::AuthenticationFailed => "clean-chat cursor authentication failed",
            Self::UnsupportedVersion => "unsupported clean-chat cursor version",
            Self::WrongDomain => "clean-chat cursor belongs to a different domain",
            Self::WrongProtocolInstance => {
                "clean-chat cursor belongs to a different protocol instance"
            }
            Self::WrongKey => "clean-chat cursor was issued under a different key",
            Self::BindingMismatch => "clean-chat cursor binding mismatch",
            Self::DigestMismatch => "clean-chat persisted cursor digest mismatch",
            Self::IssuedInFuture => "clean-chat cursor was issued in the future",
            Self::Expired => "clean-chat cursor has expired",
            Self::BelowRetentionFloor => "clean-chat cursor is below the retention floor",
            Self::PositionInFuture => "clean-chat cursor position is in the future",
        })
    }
}

impl Error for CursorCodecError {}

pub(super) struct CursorCodec {
    protocol_instance: Uuid,
    key_id: [u8; 32],
    secret: Zeroizing<[u8; 32]>,
}

impl CursorCodec {
    pub(super) fn new(
        protocol_instance: Uuid,
        key_id: &str,
        secret: Zeroizing<[u8; 32]>,
    ) -> Result<Self, CursorCodecError> {
        require_uuid_v4(protocol_instance).map_err(|_| CursorCodecError::InvalidConfiguration)?;
        if secret.iter().all(|byte| *byte == 0) {
            return Err(CursorCodecError::InvalidConfiguration);
        }
        let decoded_key_id = decode_canonical_base64url(key_id)
            .map_err(|_| CursorCodecError::InvalidConfiguration)?;
        let key_id = <[u8; 32]>::try_from(decoded_key_id.as_slice())
            .map_err(|_| CursorCodecError::InvalidConfiguration)?;
        Ok(Self {
            protocol_instance,
            key_id,
            secret,
        })
    }

    pub(super) fn matches_protocol_configuration(
        &self,
        protocol_instance: Uuid,
        cursor_key_id: &str,
    ) -> bool {
        protocol_instance == self.protocol_instance
            && decode_canonical_base64url(cursor_key_id)
                .is_ok_and(|decoded| decoded.as_slice() == self.key_id)
    }

    pub(super) fn issue_event_cursor(
        &self,
        device: &DeviceCursorBinding,
        position: u64,
        retained_floor: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<EventCursor, CursorCodecError> {
        validate_lifetime(issued_at, expires_at)?;
        require_safe_integer(position)?;
        require_safe_integer(retained_floor)?;
        if position < retained_floor {
            return Err(CursorCodecError::BelowRetentionFloor);
        }

        let body = self.event_body(device, position, retained_floor, issued_at, expires_at);
        EventCursor::from_body(self.authenticate(body)?)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn hydrate_event_cursor(
        &self,
        persisted_bytes: &[u8],
        expected_sha256: [u8; 32],
        expected_device: &DeviceCursorBinding,
        expected_position: u64,
        expected_expires_at: u64,
        now: u64,
        current_retained_floor: u64,
        maximum_event_position: u64,
    ) -> Result<EventCursor, CursorCodecError> {
        require_safe_integer(expected_position)?;
        require_safe_integer(expected_expires_at)?;
        let encoded = persisted_encoded_with_digest(persisted_bytes, expected_sha256)?;
        let verified = self.verify_event_cursor(
            encoded,
            expected_device,
            now,
            current_retained_floor,
            maximum_event_position,
        )?;
        if verified.position != expected_position || verified.expires_at != expected_expires_at {
            return Err(CursorCodecError::BindingMismatch);
        }
        Ok(EventCursor(encoded.to_owned()))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn bind_inventory_session(
        &self,
        device: DeviceCursorBinding,
        session_id: Uuid,
        snapshot_event_cursor: &EventCursor,
        expected_snapshot_event_position: u64,
        expected_expires_at: u64,
        now: u64,
        current_retained_floor: u64,
        maximum_event_position: u64,
    ) -> Result<InventorySessionBinding, CursorCodecError> {
        let verified = self.verify_event_cursor(
            snapshot_event_cursor.as_str(),
            &device,
            now,
            current_retained_floor,
            maximum_event_position,
        )?;
        if verified.position != expected_snapshot_event_position
            || verified.expires_at != expected_expires_at
        {
            return Err(CursorCodecError::BindingMismatch);
        }
        InventorySessionBinding::new(
            device,
            session_id,
            expected_snapshot_event_position,
            snapshot_event_cursor,
            expected_expires_at,
        )
    }

    pub(super) fn hydrate_inventory_session_token(
        &self,
        persisted_bytes: &[u8],
        expected_sha256: [u8; 32],
        expected: &InventorySessionBinding,
        now: u64,
        current_retained_floor: u64,
        maximum_event_position: u64,
    ) -> Result<InventorySessionToken, CursorCodecError> {
        let encoded = persisted_encoded_with_digest(persisted_bytes, expected_sha256)?;
        self.verify_inventory_session_id(
            encoded,
            expected,
            now,
            current_retained_floor,
            maximum_event_position,
        )?;
        Ok(InventorySessionToken(encoded.to_owned()))
    }

    pub(super) fn verify_event_cursor(
        &self,
        encoded: &str,
        expected_device: &DeviceCursorBinding,
        now: u64,
        current_retained_floor: u64,
        maximum_event_position: u64,
    ) -> Result<VerifiedEventCursor, CursorCodecError> {
        require_safe_integer(now)?;
        require_safe_integer(current_retained_floor)?;
        require_safe_integer(maximum_event_position)?;
        if current_retained_floor > maximum_event_position {
            return Err(CursorCodecError::InvalidField);
        }

        let envelope = self.verify_envelope(encoded, EVENT_DOMAIN)?;
        validate_at(envelope.issued_at, envelope.expires_at, now)?;

        let mut reader = Reader::new(&envelope.payload);
        let did_hash = reader.take_array::<32>()?;
        let device_id = parse_uuid_v4(reader.take_array::<16>()?)?;
        let auth_generation = reader.take_u64()?;
        let jkt_hash = reader.take_array::<32>()?;
        let position = reader.take_u64()?;
        let retained_floor = reader.take_u64()?;
        reader.finish()?;

        require_auth_generation(auth_generation)?;
        require_safe_integer(position)?;
        require_safe_integer(retained_floor)?;
        if did_hash != expected_device.did_hash
            || device_id != expected_device.device_id
            || auth_generation != expected_device.auth_generation
            || jkt_hash != expected_device.jkt_hash
        {
            return Err(CursorCodecError::BindingMismatch);
        }
        if retained_floor > position || position < current_retained_floor {
            return Err(CursorCodecError::BelowRetentionFloor);
        }
        if retained_floor > current_retained_floor || position > maximum_event_position {
            return Err(CursorCodecError::PositionInFuture);
        }

        let canonical = self.event_body(
            expected_device,
            position,
            retained_floor,
            envelope.issued_at,
            envelope.expires_at,
        );
        if canonical != envelope.body {
            return Err(CursorCodecError::InvalidEncoding);
        }

        Ok(VerifiedEventCursor {
            position,
            retained_floor,
            expires_at: envelope.expires_at,
        })
    }

    pub(super) fn issue_inventory_session_id(
        &self,
        binding: &InventorySessionBinding,
        issued_at: u64,
        current_retained_floor: u64,
        maximum_event_position: u64,
    ) -> Result<InventorySessionId, CursorCodecError> {
        validate_lifetime(issued_at, binding.expires_at)?;
        self.validate_inventory_session_binding(
            binding,
            issued_at,
            current_retained_floor,
            maximum_event_position,
        )?;
        let body = self.inventory_session_body(binding, issued_at);
        InventorySessionToken::from_body(self.authenticate(body)?)
    }

    pub(super) fn verify_inventory_session_id(
        &self,
        encoded: &str,
        expected: &InventorySessionBinding,
        now: u64,
        current_retained_floor: u64,
        maximum_event_position: u64,
    ) -> Result<VerifiedInventorySession, CursorCodecError> {
        require_safe_integer(now)?;
        require_safe_integer(current_retained_floor)?;
        require_safe_integer(maximum_event_position)?;
        if current_retained_floor > maximum_event_position {
            return Err(CursorCodecError::InvalidField);
        }

        let envelope = self.verify_envelope(encoded, INVENTORY_SESSION_DOMAIN)?;
        validate_at(envelope.issued_at, envelope.expires_at, now)?;
        let mut reader = Reader::new(&envelope.payload);
        let device = DecodedDeviceBinding::read(&mut reader)?;
        let session_id = parse_uuid_v4(reader.take_array::<16>()?)?;
        let snapshot_event_position = reader.take_u64()?;
        let snapshot_event_cursor_hash = reader.take_array::<32>()?;
        reader.finish()?;

        require_safe_integer(snapshot_event_position)?;
        if !device.matches(&expected.device)
            || session_id != expected.session_id
            || snapshot_event_position != expected.snapshot_event_position
            || snapshot_event_cursor_hash != expected.snapshot_event_cursor_hash
            || envelope.expires_at != expected.expires_at
        {
            return Err(CursorCodecError::BindingMismatch);
        }
        if snapshot_event_position < current_retained_floor {
            return Err(CursorCodecError::BelowRetentionFloor);
        }
        if snapshot_event_position > maximum_event_position {
            return Err(CursorCodecError::PositionInFuture);
        }

        self.validate_inventory_session_binding(
            expected,
            now,
            current_retained_floor,
            maximum_event_position,
        )?;

        let canonical = self.inventory_session_body(expected, envelope.issued_at);
        if canonical != envelope.body {
            return Err(CursorCodecError::InvalidEncoding);
        }

        Ok(VerifiedInventorySession {
            session_id,
            snapshot_event_position,
            snapshot_event_cursor_hash,
            expires_at: envelope.expires_at,
        })
    }

    fn validate_inventory_session_binding(
        &self,
        binding: &InventorySessionBinding,
        now: u64,
        current_retained_floor: u64,
        maximum_event_position: u64,
    ) -> Result<VerifiedEventCursor, CursorCodecError> {
        let verified = self.verify_event_cursor(
            binding.snapshot_event_cursor.as_str(),
            &binding.device,
            now,
            current_retained_floor,
            maximum_event_position,
        )?;
        if verified.position != binding.snapshot_event_position
            || verified.expires_at != binding.expires_at
            || binding.snapshot_event_cursor.binding_hash() != binding.snapshot_event_cursor_hash
        {
            return Err(CursorCodecError::BindingMismatch);
        }
        Ok(verified)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn bind_inventory_page(
        &self,
        session_binding: &InventorySessionBinding,
        inventory_session: &InventorySessionToken,
        snapshot_event_cursor: &EventCursor,
        domain: InventoryPageDomain,
        canonical_filter: &[u8],
        now: u64,
        current_retained_floor: u64,
        maximum_event_position: u64,
    ) -> Result<InventoryPageBinding, CursorCodecError> {
        self.verify_inventory_session_id(
            inventory_session.as_str(),
            session_binding,
            now,
            current_retained_floor,
            maximum_event_position,
        )?;
        let verified_event = self.verify_event_cursor(
            snapshot_event_cursor.as_str(),
            &session_binding.device,
            now,
            current_retained_floor,
            maximum_event_position,
        )?;
        if snapshot_event_cursor.as_str() != session_binding.snapshot_event_cursor.as_str()
            || verified_event.position != session_binding.snapshot_event_position
            || verified_event.expires_at != session_binding.expires_at
        {
            return Err(CursorCodecError::BindingMismatch);
        }
        InventoryPageBinding::new(
            session_binding,
            inventory_session,
            snapshot_event_cursor,
            domain,
            canonical_filter,
        )
    }

    pub(super) fn issue_inventory_page_cursor(
        &self,
        binding: &InventoryPageBinding,
        last_ordinal: u64,
        item_key: &[u8],
        issued_at: u64,
        current_retained_floor: u64,
        maximum_event_position: u64,
    ) -> Result<InventoryPageCursor, CursorCodecError> {
        validate_lifetime(issued_at, binding.expires_at)?;
        require_safe_integer(last_ordinal)?;
        self.validate_inventory_page_binding(
            binding,
            issued_at,
            current_retained_floor,
            maximum_event_position,
        )?;
        let item_key_hash = inventory_item_key_hash(binding.domain, item_key)?;
        let body = self.inventory_page_body(binding, last_ordinal, item_key_hash, issued_at);
        InventoryPageCursor::from_body(self.authenticate(body)?)
    }

    /// Performs only the public, MAC-authenticated phase of inventory paging.
    ///
    /// The returned locator is deliberately not page authority. Its session
    /// token hash may be used only to select and lock the matching retained
    /// `inventory_sessions` row. The exact cursor must then pass
    /// `verify_located_inventory_page_cursor` against the binding derived from
    /// that locked row before any inventory item is read or completion state is
    /// changed.
    pub(super) fn locate_inventory_page_cursor(
        &self,
        encoded: &str,
        expected_domain: InventoryPageDomain,
        now: u64,
    ) -> Result<InventoryPageLocator, CursorCodecError> {
        require_safe_integer(now)?;
        let envelope = self.verify_envelope(encoded, expected_domain.wire_domain())?;
        validate_at(envelope.issued_at, envelope.expires_at, now)?;

        let mut reader = Reader::new(&envelope.payload);
        let _device = DecodedDeviceBinding::read(&mut reader)?;
        let session_token_hash = reader.take_array::<32>()?;
        let snapshot_event_position = reader.take_u64()?;
        let _snapshot_event_cursor_hash = reader.take_array::<32>()?;
        let last_ordinal = reader.take_u64()?;
        let _item_key_hash = reader.take_array::<32>()?;
        let _filter_hash = reader.take_array::<32>()?;
        reader.finish()?;

        require_safe_integer(snapshot_event_position)?;
        require_safe_integer(last_ordinal)?;
        Ok(InventoryPageLocator {
            domain: expected_domain,
            session_token_hash,
            authenticated_cursor_hash: opaque_binding_hash(encoded.as_bytes())?,
            expires_at: envelope.expires_at,
        })
    }

    /// Completes inventory-page verification after the repository has selected
    /// and locked the exact hash-bound session row. Consuming the locator keeps
    /// the selection and verification phases paired to one authenticated
    /// cursor spelling; a locator cannot be reused for a different page.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn verify_located_inventory_page_cursor(
        &self,
        encoded: &str,
        locator: InventoryPageLocator,
        evidence: LockedInventoryCursorEvidence,
    ) -> Result<LockedInventoryPageVerification, CursorCodecError> {
        let (
            session_binding,
            inventory_session,
            snapshot_event_cursor,
            domain,
            canonical_filter,
            now,
            current_retained_floor,
            maximum_event_position,
        ) = evidence.into_cursor_parts();
        let expected = self.bind_inventory_page(
            &session_binding,
            &inventory_session,
            &snapshot_event_cursor,
            domain,
            &canonical_filter,
            now,
            current_retained_floor,
            maximum_event_position,
        )?;
        if locator.domain != expected.domain
            || locator.session_token_hash != expected.inventory_session_hash
            || locator.authenticated_cursor_hash != opaque_binding_hash(encoded.as_bytes())?
        {
            return Err(CursorCodecError::BindingMismatch);
        }
        let verified = self.verify_inventory_page_cursor(
            encoded,
            &expected,
            now,
            current_retained_floor,
            maximum_event_position,
        )?;
        if verified.expires_at != locator.expires_at {
            return Err(CursorCodecError::BindingMismatch);
        }
        Ok(LockedInventoryPageVerification {
            verified,
            binding: expected,
        })
    }

    fn verify_inventory_page_cursor(
        &self,
        encoded: &str,
        expected: &InventoryPageBinding,
        now: u64,
        current_retained_floor: u64,
        maximum_event_position: u64,
    ) -> Result<VerifiedInventoryPageCursor, CursorCodecError> {
        require_safe_integer(now)?;
        require_safe_integer(current_retained_floor)?;
        require_safe_integer(maximum_event_position)?;
        if current_retained_floor > maximum_event_position {
            return Err(CursorCodecError::InvalidField);
        }

        let envelope = self.verify_envelope(encoded, expected.domain.wire_domain())?;
        validate_at(envelope.issued_at, envelope.expires_at, now)?;
        let mut reader = Reader::new(&envelope.payload);
        let device = DecodedDeviceBinding::read(&mut reader)?;
        let inventory_session_hash = reader.take_array::<32>()?;
        let snapshot_event_position = reader.take_u64()?;
        let snapshot_event_cursor_hash = reader.take_array::<32>()?;
        let last_ordinal = reader.take_u64()?;
        let item_key_hash = reader.take_array::<32>()?;
        let filter_hash = reader.take_array::<32>()?;
        reader.finish()?;

        require_safe_integer(snapshot_event_position)?;
        require_safe_integer(last_ordinal)?;
        if !device.matches(&expected.device)
            || inventory_session_hash != expected.inventory_session_hash
            || snapshot_event_position != expected.snapshot_event_position
            || snapshot_event_cursor_hash != expected.snapshot_event_cursor_hash
            || filter_hash != expected.filter_hash
            || envelope.expires_at != expected.expires_at
        {
            return Err(CursorCodecError::BindingMismatch);
        }
        if snapshot_event_position < current_retained_floor {
            return Err(CursorCodecError::BelowRetentionFloor);
        }
        if snapshot_event_position > maximum_event_position {
            return Err(CursorCodecError::PositionInFuture);
        }

        self.validate_inventory_page_binding(
            expected,
            now,
            current_retained_floor,
            maximum_event_position,
        )?;

        let canonical =
            self.inventory_page_body(expected, last_ordinal, item_key_hash, envelope.issued_at);
        if canonical != envelope.body {
            return Err(CursorCodecError::InvalidEncoding);
        }

        Ok(VerifiedInventoryPageCursor {
            domain: expected.domain,
            last_ordinal,
            item_key_hash,
            expires_at: envelope.expires_at,
        })
    }

    #[cfg(test)]
    pub(super) fn verify_inventory_page_cursor_for_test(
        &self,
        encoded: &str,
        expected: &InventoryPageBinding,
        now: u64,
        current_retained_floor: u64,
        maximum_event_position: u64,
    ) -> Result<VerifiedInventoryPageCursor, CursorCodecError> {
        self.verify_inventory_page_cursor(
            encoded,
            expected,
            now,
            current_retained_floor,
            maximum_event_position,
        )
    }

    fn validate_inventory_page_binding(
        &self,
        binding: &InventoryPageBinding,
        now: u64,
        current_retained_floor: u64,
        maximum_event_position: u64,
    ) -> Result<(), CursorCodecError> {
        self.verify_inventory_session_id(
            binding.inventory_session.as_str(),
            &binding.session_binding,
            now,
            current_retained_floor,
            maximum_event_position,
        )?;
        let verified_event = self.verify_event_cursor(
            binding.snapshot_event_cursor.as_str(),
            &binding.device,
            now,
            current_retained_floor,
            maximum_event_position,
        )?;
        if binding.device != binding.session_binding.device
            || binding.inventory_session_hash != binding.inventory_session.binding_hash()
            || binding.snapshot_event_position != binding.session_binding.snapshot_event_position
            || binding.snapshot_event_cursor.as_str()
                != binding.session_binding.snapshot_event_cursor.as_str()
            || binding.snapshot_event_cursor_hash != binding.snapshot_event_cursor.binding_hash()
            || binding.snapshot_event_cursor_hash
                != binding.session_binding.snapshot_event_cursor_hash
            || binding.expires_at != binding.session_binding.expires_at
            || verified_event.position != binding.snapshot_event_position
            || verified_event.expires_at != binding.expires_at
        {
            return Err(CursorCodecError::BindingMismatch);
        }
        Ok(())
    }

    pub(super) fn issue_own_device_cursor(
        &self,
        binding: &OwnDeviceCursorBinding,
        last_ordinal: u64,
        item_key: &[u8],
        issued_at: u64,
    ) -> Result<OwnDeviceCursor, CursorCodecError> {
        validate_lifetime(issued_at, binding.expires_at)?;
        require_safe_integer(last_ordinal)?;
        let item_key_hash = own_device_item_key_hash(item_key)?;
        let body = self.own_device_body(binding, last_ordinal, item_key_hash, issued_at);
        OwnDeviceCursor::from_body(self.authenticate(body)?)
    }

    pub(super) fn verify_own_device_cursor(
        &self,
        encoded: &str,
        expected: &OwnDeviceCursorBinding,
        now: u64,
        maximum_fence_revision: u64,
    ) -> Result<VerifiedOwnDeviceCursor, CursorCodecError> {
        require_safe_integer(now)?;
        require_safe_integer(maximum_fence_revision)?;
        let envelope = self.verify_envelope(encoded, OWN_DEVICE_DOMAIN)?;
        validate_at(envelope.issued_at, envelope.expires_at, now)?;
        let mut reader = Reader::new(&envelope.payload);
        let device = DecodedDeviceBinding::read(&mut reader)?;
        let device_inventory_session_id = parse_uuid_v4(reader.take_array::<16>()?)?;
        let fence_revision = reader.take_u64()?;
        let last_ordinal = reader.take_u64()?;
        let item_key_hash = reader.take_array::<32>()?;
        let filter_hash = reader.take_array::<32>()?;
        reader.finish()?;

        require_safe_integer(fence_revision)?;
        require_safe_integer(last_ordinal)?;
        if !device.matches(&expected.device)
            || device_inventory_session_id != expected.device_inventory_session_id
            || fence_revision != expected.fence_revision
            || filter_hash != expected.filter_hash
            || envelope.expires_at != expected.expires_at
        {
            return Err(CursorCodecError::BindingMismatch);
        }
        if fence_revision > maximum_fence_revision {
            return Err(CursorCodecError::PositionInFuture);
        }

        let canonical =
            self.own_device_body(expected, last_ordinal, item_key_hash, envelope.issued_at);
        if canonical != envelope.body {
            return Err(CursorCodecError::InvalidEncoding);
        }

        Ok(VerifiedOwnDeviceCursor {
            device_inventory_session_id,
            fence_revision,
            last_ordinal,
            item_key_hash,
            expires_at: envelope.expires_at,
        })
    }

    fn event_body(
        &self,
        device: &DeviceCursorBinding,
        position: u64,
        retained_floor: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Vec<u8> {
        let mut body = self.header(EVENT_DOMAIN, issued_at, expires_at);
        body.extend_from_slice(&device.did_hash);
        body.extend_from_slice(device.device_id.as_bytes());
        body.extend_from_slice(&device.auth_generation.to_be_bytes());
        body.extend_from_slice(&device.jkt_hash);
        body.extend_from_slice(&position.to_be_bytes());
        body.extend_from_slice(&retained_floor.to_be_bytes());
        body
    }

    fn inventory_session_body(&self, binding: &InventorySessionBinding, issued_at: u64) -> Vec<u8> {
        let mut body = self.header(INVENTORY_SESSION_DOMAIN, issued_at, binding.expires_at);
        binding.device.append_to(&mut body);
        body.extend_from_slice(binding.session_id.as_bytes());
        body.extend_from_slice(&binding.snapshot_event_position.to_be_bytes());
        body.extend_from_slice(&binding.snapshot_event_cursor_hash);
        body
    }

    fn inventory_page_body(
        &self,
        binding: &InventoryPageBinding,
        last_ordinal: u64,
        item_key_hash: [u8; 32],
        issued_at: u64,
    ) -> Vec<u8> {
        let mut body = self.header(binding.domain.wire_domain(), issued_at, binding.expires_at);
        binding.device.append_to(&mut body);
        body.extend_from_slice(&binding.inventory_session_hash);
        body.extend_from_slice(&binding.snapshot_event_position.to_be_bytes());
        body.extend_from_slice(&binding.snapshot_event_cursor_hash);
        body.extend_from_slice(&last_ordinal.to_be_bytes());
        body.extend_from_slice(&item_key_hash);
        body.extend_from_slice(&binding.filter_hash);
        body
    }

    fn own_device_body(
        &self,
        binding: &OwnDeviceCursorBinding,
        last_ordinal: u64,
        item_key_hash: [u8; 32],
        issued_at: u64,
    ) -> Vec<u8> {
        let mut body = self.header(OWN_DEVICE_DOMAIN, issued_at, binding.expires_at);
        binding.device.append_to(&mut body);
        body.extend_from_slice(binding.device_inventory_session_id.as_bytes());
        body.extend_from_slice(&binding.fence_revision.to_be_bytes());
        body.extend_from_slice(&last_ordinal.to_be_bytes());
        body.extend_from_slice(&item_key_hash);
        body.extend_from_slice(&binding.filter_hash);
        body
    }

    fn header(&self, domain: u8, issued_at: u64, expires_at: u64) -> Vec<u8> {
        let mut body = Vec::with_capacity(HEADER_BYTES);
        body.extend_from_slice(MAGIC);
        body.push(WIRE_VERSION);
        body.push(domain);
        body.extend_from_slice(self.protocol_instance.as_bytes());
        body.extend_from_slice(&self.key_id);
        body.extend_from_slice(&issued_at.to_be_bytes());
        body.extend_from_slice(&expires_at.to_be_bytes());
        body
    }

    fn authenticate(&self, mut body: Vec<u8>) -> Result<Vec<u8>, CursorCodecError> {
        let mut mac = HmacSha256::new_from_slice(self.secret.as_slice())
            .map_err(|_| CursorCodecError::InvalidConfiguration)?;
        mac.update(&body);
        body.extend_from_slice(&mac.finalize().into_bytes());
        Ok(body)
    }

    fn verify_envelope(
        &self,
        encoded: &str,
        expected_domain: u8,
    ) -> Result<VerifiedEnvelope, CursorCodecError> {
        let decoded = decode_cursor(encoded)?;
        if decoded.len() < HEADER_BYTES + MAC_BYTES {
            return Err(CursorCodecError::InvalidEncoding);
        }
        let mac_offset = decoded
            .len()
            .checked_sub(MAC_BYTES)
            .ok_or(CursorCodecError::InvalidEncoding)?;
        let (body, tag) = decoded.split_at(mac_offset);

        let mut mac = HmacSha256::new_from_slice(self.secret.as_slice())
            .map_err(|_| CursorCodecError::InvalidConfiguration)?;
        mac.update(body);
        mac.verify_slice(tag)
            .map_err(|_| CursorCodecError::AuthenticationFailed)?;

        let mut reader = Reader::new(body);
        if reader.take_array::<4>()? != *MAGIC {
            return Err(CursorCodecError::InvalidEncoding);
        }
        if reader.take_u8()? != WIRE_VERSION {
            return Err(CursorCodecError::UnsupportedVersion);
        }
        if reader.take_u8()? != expected_domain {
            return Err(CursorCodecError::WrongDomain);
        }
        if parse_uuid_v4(reader.take_array::<16>()?)? != self.protocol_instance {
            return Err(CursorCodecError::WrongProtocolInstance);
        }
        if reader.take_array::<32>()? != self.key_id {
            return Err(CursorCodecError::WrongKey);
        }
        let issued_at = reader.take_u64()?;
        let expires_at = reader.take_u64()?;
        validate_lifetime(issued_at, expires_at)?;

        Ok(VerifiedEnvelope {
            body: body.to_vec(),
            payload: reader.remaining().to_vec(),
            issued_at,
            expires_at,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DeviceCursorBinding {
    did_hash: [u8; 32],
    device_id: Uuid,
    auth_generation: u64,
    jkt_hash: [u8; 32],
}

impl DeviceCursorBinding {
    pub(super) fn new(
        did: &BareDid,
        device_id: Uuid,
        auth_generation: u64,
        jkt: &KeyThumbprint,
    ) -> Result<Self, CursorCodecError> {
        require_uuid_v4(device_id)?;
        require_auth_generation(auth_generation)?;

        let did_hash = exact_identity_hash(b"CBCC-DID-BINDING\0", did.as_str().as_bytes())?;
        let jkt_hash = exact_identity_hash(b"CBCC-JKT-BINDING\0", jkt.as_str().as_bytes())?;
        Ok(Self {
            did_hash,
            device_id,
            auth_generation,
            jkt_hash,
        })
    }

    fn append_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.did_hash);
        bytes.extend_from_slice(self.device_id.as_bytes());
        bytes.extend_from_slice(&self.auth_generation.to_be_bytes());
        bytes.extend_from_slice(&self.jkt_hash);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct InventorySessionBinding {
    device: DeviceCursorBinding,
    session_id: Uuid,
    snapshot_event_position: u64,
    snapshot_event_cursor: EventCursor,
    snapshot_event_cursor_hash: [u8; 32],
    expires_at: u64,
}

impl InventorySessionBinding {
    fn new(
        device: DeviceCursorBinding,
        session_id: Uuid,
        snapshot_event_position: u64,
        snapshot_event_cursor: &EventCursor,
        expires_at: u64,
    ) -> Result<Self, CursorCodecError> {
        require_uuid_v4(session_id)?;
        require_safe_integer(snapshot_event_position)?;
        require_safe_integer(expires_at)?;
        Ok(Self {
            device,
            session_id,
            snapshot_event_position,
            snapshot_event_cursor: snapshot_event_cursor.clone(),
            snapshot_event_cursor_hash: snapshot_event_cursor.binding_hash(),
            expires_at,
        })
    }

    pub(super) const fn session_id(&self) -> Uuid {
        self.session_id
    }

    pub(super) const fn snapshot_event_cursor_hash(&self) -> [u8; 32] {
        self.snapshot_event_cursor_hash
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InventoryPageDomain {
    Conversations,
    PendingWelcomes,
    LeafRecovery,
}

impl InventoryPageDomain {
    const fn wire_domain(self) -> u8 {
        match self {
            Self::Conversations => INVENTORY_CONVERSATIONS_DOMAIN,
            Self::PendingWelcomes => INVENTORY_WELCOMES_DOMAIN,
            Self::LeafRecovery => INVENTORY_RECOVERY_DOMAIN,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct InventoryPageBinding {
    session_binding: InventorySessionBinding,
    inventory_session: InventorySessionToken,
    snapshot_event_cursor: EventCursor,
    device: DeviceCursorBinding,
    inventory_session_hash: [u8; 32],
    domain: InventoryPageDomain,
    snapshot_event_position: u64,
    snapshot_event_cursor_hash: [u8; 32],
    filter_hash: [u8; 32],
    expires_at: u64,
}

impl InventoryPageBinding {
    fn new(
        session_binding: &InventorySessionBinding,
        inventory_session: &InventorySessionToken,
        snapshot_event_cursor: &EventCursor,
        domain: InventoryPageDomain,
        canonical_filter: &[u8],
    ) -> Result<Self, CursorCodecError> {
        Ok(Self {
            session_binding: session_binding.clone(),
            inventory_session: inventory_session.clone(),
            snapshot_event_cursor: snapshot_event_cursor.clone(),
            device: session_binding.device.clone(),
            inventory_session_hash: inventory_session.binding_hash(),
            domain,
            snapshot_event_position: session_binding.snapshot_event_position,
            snapshot_event_cursor_hash: snapshot_event_cursor.binding_hash(),
            filter_hash: inventory_filter_hash(domain, canonical_filter)?,
            expires_at: session_binding.expires_at,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct OwnDeviceCursorBinding {
    device: DeviceCursorBinding,
    device_inventory_session_id: Uuid,
    fence_revision: u64,
    filter_hash: [u8; 32],
    expires_at: u64,
}

impl OwnDeviceCursorBinding {
    pub(super) fn new(
        device: DeviceCursorBinding,
        device_inventory_session_id: Uuid,
        fence_revision: u64,
        canonical_filter: &[u8],
        expires_at: u64,
    ) -> Result<Self, CursorCodecError> {
        require_uuid_v4(device_inventory_session_id)?;
        require_safe_integer(fence_revision)?;
        require_safe_integer(expires_at)?;
        Ok(Self {
            device,
            device_inventory_session_id,
            fence_revision,
            filter_hash: own_device_filter_hash(canonical_filter)?,
            expires_at,
        })
    }

    pub(super) const fn session_id(&self) -> Uuid {
        self.device_inventory_session_id
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct EventCursor(String);

impl EventCursor {
    fn from_body(bytes: Vec<u8>) -> Result<Self, CursorCodecError> {
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        if encoded.len() > MAX_OPAQUE_CURSOR_ASCII_BYTES {
            return Err(CursorCodecError::TooLong);
        }
        Ok(Self(encoded))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }

    pub(super) fn binding_hash(&self) -> [u8; 32] {
        opaque_binding_hash(self.0.as_bytes()).expect("issued cursor is within the public bound")
    }
}

impl fmt::Debug for EventCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EventCursor(REDACTED)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct InventorySessionToken(String);

pub(super) type InventorySessionId = InventorySessionToken;

impl InventorySessionToken {
    fn from_body(bytes: Vec<u8>) -> Result<Self, CursorCodecError> {
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        if encoded.len() > MAX_OPAQUE_CURSOR_ASCII_BYTES {
            return Err(CursorCodecError::TooLong);
        }
        Ok(Self(encoded))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }

    pub(super) fn binding_hash(&self) -> [u8; 32] {
        opaque_binding_hash(self.0.as_bytes()).expect("issued cursor is within the public bound")
    }
}

impl fmt::Debug for InventorySessionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InventorySessionToken(REDACTED)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct InventoryPageCursor(String);

impl InventoryPageCursor {
    fn from_body(bytes: Vec<u8>) -> Result<Self, CursorCodecError> {
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        if encoded.len() > MAX_OPAQUE_CURSOR_ASCII_BYTES {
            return Err(CursorCodecError::TooLong);
        }
        Ok(Self(encoded))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for InventoryPageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InventoryPageCursor(REDACTED)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct OwnDeviceCursor(String);

impl OwnDeviceCursor {
    fn from_body(bytes: Vec<u8>) -> Result<Self, CursorCodecError> {
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        if encoded.len() > MAX_OPAQUE_CURSOR_ASCII_BYTES {
            return Err(CursorCodecError::TooLong);
        }
        Ok(Self(encoded))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OwnDeviceCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnDeviceCursor(REDACTED)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct VerifiedEventCursor {
    position: u64,
    retained_floor: u64,
    expires_at: u64,
}

impl VerifiedEventCursor {
    pub(super) const fn position(self) -> u64 {
        self.position
    }

    pub(super) const fn retained_floor(self) -> u64 {
        self.retained_floor
    }

    pub(super) const fn expires_at(self) -> u64 {
        self.expires_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct VerifiedInventorySession {
    session_id: Uuid,
    snapshot_event_position: u64,
    snapshot_event_cursor_hash: [u8; 32],
    expires_at: u64,
}

impl VerifiedInventorySession {
    pub(super) const fn session_id(self) -> Uuid {
        self.session_id
    }

    pub(super) const fn snapshot_event_position(self) -> u64 {
        self.snapshot_event_position
    }

    pub(super) const fn snapshot_event_cursor_hash(self) -> [u8; 32] {
        self.snapshot_event_cursor_hash
    }

    pub(super) const fn expires_at(self) -> u64 {
        self.expires_at
    }
}

/// MAC-verified lookup material for the first phase of inventory paging.
/// This value intentionally exposes no page ordinal, item key, filter, device,
/// or event-fence authority. The token hash selects one durable session row;
/// authorization is completed only against that row's locked binding.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct InventoryPageLocator {
    domain: InventoryPageDomain,
    session_token_hash: [u8; 32],
    authenticated_cursor_hash: [u8; 32],
    expires_at: u64,
}

impl InventoryPageLocator {
    pub(super) const fn session_token_hash(&self) -> [u8; 32] {
        self.session_token_hash
    }

    pub(super) const fn authenticated_cursor_hash(&self) -> [u8; 32] {
        self.authenticated_cursor_hash
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct VerifiedInventoryPageCursor {
    domain: InventoryPageDomain,
    last_ordinal: u64,
    item_key_hash: [u8; 32],
    expires_at: u64,
}

#[derive(Debug)]
pub(crate) struct LockedInventoryPageVerification {
    pub(crate) verified: VerifiedInventoryPageCursor,
    pub(crate) binding: InventoryPageBinding,
}

impl VerifiedInventoryPageCursor {
    pub(super) const fn domain(self) -> InventoryPageDomain {
        self.domain
    }

    pub(super) const fn last_ordinal(self) -> u64 {
        self.last_ordinal
    }

    pub(super) const fn item_key_hash(self) -> [u8; 32] {
        self.item_key_hash
    }

    pub(super) const fn expires_at(self) -> u64 {
        self.expires_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct VerifiedOwnDeviceCursor {
    device_inventory_session_id: Uuid,
    fence_revision: u64,
    last_ordinal: u64,
    item_key_hash: [u8; 32],
    expires_at: u64,
}

impl VerifiedOwnDeviceCursor {
    pub(super) const fn device_inventory_session_id(self) -> Uuid {
        self.device_inventory_session_id
    }

    pub(super) const fn fence_revision(self) -> u64 {
        self.fence_revision
    }

    pub(super) const fn last_ordinal(self) -> u64 {
        self.last_ordinal
    }

    pub(super) const fn item_key_hash(self) -> [u8; 32] {
        self.item_key_hash
    }

    pub(super) const fn expires_at(self) -> u64 {
        self.expires_at
    }
}

struct DecodedDeviceBinding {
    did_hash: [u8; 32],
    device_id: Uuid,
    auth_generation: u64,
    jkt_hash: [u8; 32],
}

impl DecodedDeviceBinding {
    fn read(reader: &mut Reader<'_>) -> Result<Self, CursorCodecError> {
        let value = Self {
            did_hash: reader.take_array::<32>()?,
            device_id: parse_uuid_v4(reader.take_array::<16>()?)?,
            auth_generation: reader.take_u64()?,
            jkt_hash: reader.take_array::<32>()?,
        };
        require_auth_generation(value.auth_generation)?;
        Ok(value)
    }

    fn matches(&self, expected: &DeviceCursorBinding) -> bool {
        self.did_hash == expected.did_hash
            && self.device_id == expected.device_id
            && self.auth_generation == expected.auth_generation
            && self.jkt_hash == expected.jkt_hash
    }
}

struct VerifiedEnvelope {
    body: Vec<u8>,
    payload: Vec<u8>,
    issued_at: u64,
    expires_at: u64,
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], CursorCodecError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(CursorCodecError::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CursorCodecError::InvalidEncoding)?;
        self.offset = end;
        Ok(value)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], CursorCodecError> {
        self.take(N)?
            .try_into()
            .map_err(|_| CursorCodecError::InvalidEncoding)
    }

    fn take_u8(&mut self) -> Result<u8, CursorCodecError> {
        Ok(self.take_array::<1>()?[0])
    }

    fn take_u64(&mut self) -> Result<u64, CursorCodecError> {
        Ok(u64::from_be_bytes(self.take_array::<8>()?))
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    fn finish(self) -> Result<(), CursorCodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CursorCodecError::InvalidEncoding)
        }
    }
}

fn decode_cursor(encoded: &str) -> Result<Vec<u8>, CursorCodecError> {
    if encoded.len() > MAX_OPAQUE_CURSOR_ASCII_BYTES {
        return Err(CursorCodecError::TooLong);
    }
    if encoded.is_empty() || !encoded.is_ascii() || encoded.contains('=') {
        return Err(CursorCodecError::InvalidEncoding);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CursorCodecError::InvalidEncoding)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(CursorCodecError::InvalidEncoding);
    }
    Ok(decoded)
}

fn persisted_encoded_with_digest(
    persisted_bytes: &[u8],
    expected_sha256: [u8; 32],
) -> Result<&str, CursorCodecError> {
    if persisted_bytes.len() > MAX_OPAQUE_CURSOR_ASCII_BYTES {
        return Err(CursorCodecError::TooLong);
    }
    let actual_sha256: [u8; 32] = Sha256::digest(persisted_bytes).into();
    if actual_sha256 != expected_sha256 {
        return Err(CursorCodecError::DigestMismatch);
    }
    let encoded =
        std::str::from_utf8(persisted_bytes).map_err(|_| CursorCodecError::InvalidEncoding)?;
    decode_cursor(encoded)?;
    Ok(encoded)
}

pub(super) fn opaque_binding_hash(bytes: &[u8]) -> Result<[u8; 32], CursorCodecError> {
    if bytes.is_empty() || bytes.len() > MAX_OPAQUE_CURSOR_ASCII_BYTES {
        return Err(CursorCodecError::InvalidField);
    }
    Ok(Sha256::digest(bytes).into())
}

pub(super) fn inventory_item_key_hash(
    domain: InventoryPageDomain,
    item_key: &[u8],
) -> Result<[u8; 32], CursorCodecError> {
    bounded_domain_hash(b"CBCC-INVENTORY-ITEM\0", domain, item_key, 1, 512)
}

fn inventory_filter_hash(
    domain: InventoryPageDomain,
    canonical_filter: &[u8],
) -> Result<[u8; 32], CursorCodecError> {
    bounded_domain_hash(
        b"CBCC-INVENTORY-FILTER\0",
        domain,
        canonical_filter,
        0,
        1_024,
    )
}

fn bounded_domain_hash(
    label: &[u8],
    domain: InventoryPageDomain,
    value: &[u8],
    minimum: usize,
    maximum: usize,
) -> Result<[u8; 32], CursorCodecError> {
    if !(minimum..=maximum).contains(&value.len()) {
        return Err(CursorCodecError::InvalidField);
    }
    let length = u16::try_from(value.len()).map_err(|_| CursorCodecError::InvalidField)?;
    let mut digest = Sha256::new();
    digest.update(label);
    digest.update([domain.wire_domain()]);
    digest.update(length.to_be_bytes());
    digest.update(value);
    Ok(digest.finalize().into())
}

fn exact_identity_hash(label: &[u8], value: &[u8]) -> Result<[u8; 32], CursorCodecError> {
    let length = u16::try_from(value.len()).map_err(|_| CursorCodecError::InvalidField)?;
    let mut digest = Sha256::new();
    digest.update(label);
    digest.update(length.to_be_bytes());
    digest.update(value);
    Ok(digest.finalize().into())
}

pub(super) fn own_device_item_key_hash(item_key: &[u8]) -> Result<[u8; 32], CursorCodecError> {
    bounded_hash(b"CBCC-OWN-DEVICE-ITEM\0", item_key, 1, 512)
}

fn own_device_filter_hash(canonical_filter: &[u8]) -> Result<[u8; 32], CursorCodecError> {
    bounded_hash(b"CBCC-OWN-DEVICE-FILTER\0", canonical_filter, 0, 1_024)
}

fn bounded_hash(
    label: &[u8],
    value: &[u8],
    minimum: usize,
    maximum: usize,
) -> Result<[u8; 32], CursorCodecError> {
    if !(minimum..=maximum).contains(&value.len()) {
        return Err(CursorCodecError::InvalidField);
    }
    let length = u16::try_from(value.len()).map_err(|_| CursorCodecError::InvalidField)?;
    let mut digest = Sha256::new();
    digest.update(label);
    digest.update(length.to_be_bytes());
    digest.update(value);
    Ok(digest.finalize().into())
}

fn decode_canonical_base64url(encoded: &str) -> Result<Vec<u8>, CursorCodecError> {
    if encoded.is_empty() || !encoded.is_ascii() || encoded.contains('=') {
        return Err(CursorCodecError::InvalidEncoding);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CursorCodecError::InvalidEncoding)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(CursorCodecError::InvalidEncoding);
    }
    Ok(decoded)
}

fn validate_lifetime(issued_at: u64, expires_at: u64) -> Result<(), CursorCodecError> {
    require_safe_integer(issued_at)?;
    require_safe_integer(expires_at)?;
    if issued_at >= expires_at {
        return Err(CursorCodecError::InvalidField);
    }
    Ok(())
}

fn validate_at(issued_at: u64, expires_at: u64, now: u64) -> Result<(), CursorCodecError> {
    if issued_at > now {
        return Err(CursorCodecError::IssuedInFuture);
    }
    if now >= expires_at {
        return Err(CursorCodecError::Expired);
    }
    Ok(())
}

fn require_safe_integer(value: u64) -> Result<(), CursorCodecError> {
    if value <= MAX_SAFE_INTEGER {
        Ok(())
    } else {
        Err(CursorCodecError::InvalidField)
    }
}

fn require_auth_generation(value: u64) -> Result<(), CursorCodecError> {
    require_safe_integer(value)?;
    if value == 0 {
        Err(CursorCodecError::InvalidField)
    } else {
        Ok(())
    }
}

fn require_uuid_v4(value: Uuid) -> Result<(), CursorCodecError> {
    if value.get_variant() == Variant::RFC4122 && value.get_version() == Some(Version::Random) {
        Ok(())
    } else {
        Err(CursorCodecError::InvalidField)
    }
}

fn parse_uuid_v4(bytes: [u8; 16]) -> Result<Uuid, CursorCodecError> {
    let value = Uuid::from_bytes(bytes);
    require_uuid_v4(value)?;
    Ok(value)
}
