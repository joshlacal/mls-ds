//! Clean-cutover chat protocol primitives.

use std::panic::AssertUnwindSafe;

use libcrux_kem::{Algorithm as KemAlgorithm, PublicKey as KemPublicKey};

pub(crate) const XWING_PUBLIC_KEY_BYTES: usize = 1_216;
pub(crate) const XWING_KEM_OUTPUT_BYTES: usize = 1_120;
// Canonical BasicCredential identity is `actorDid + "#" + deviceId`.
// Protocol v1 supports exact `did:plc:[a-z2-7]{24}` identities or hostname-only
// production `did:web` identities. `did:web:a.co` is the shortest supported DID,
// while `did:web:` plus a 253-byte hostname is the longest; device IDs are
// canonical textual UUIDv4 values.
pub(crate) const MIN_BASIC_CREDENTIAL_BYTES: usize = 12 + 1 + 36;
pub(crate) const MAX_BASIC_CREDENTIAL_BYTES: usize = (8 + 253) + 1 + 36;
const XWING_X25519_PUBLIC_KEY_OFFSET: usize = 1_184;
const XWING_X25519_KEM_OUTPUT_OFFSET: usize = 1_088;
const X25519_FIELD_MODULUS_LE: [u8; 32] = [
    0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
];

/// Reject RFC 7748 aliases and low-order points before a component can enter
/// XWing's raw-byte combiner. The pinned libcrux decoder masks noncanonical
/// encodings, while XWing hashes their original bytes, which otherwise makes
/// encapsulation and decapsulation derive different secrets.
fn x25519_component_is_canonical_and_usable(bytes: &[u8]) -> bool {
    let Ok(component) = <[u8; 32]>::try_from(bytes) else {
        return false;
    };
    let mut less_than_modulus = false;
    for index in (0..component.len()).rev() {
        if component[index] < X25519_FIELD_MODULUS_LE[index] {
            less_than_modulus = true;
            break;
        }
        if component[index] > X25519_FIELD_MODULUS_LE[index] {
            return false;
        }
    }
    if !less_than_modulus {
        return false;
    }
    x25519_dalek::x25519([0xA5; 32], component) != [0; 32]
}

pub(crate) fn xwing_public_key_is_valid(bytes: &[u8]) -> bool {
    if bytes.len() != XWING_PUBLIC_KEY_BYTES
        || !x25519_component_is_canonical_and_usable(&bytes[XWING_X25519_PUBLIC_KEY_OFFSET..])
    {
        return false;
    }
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        let public_key = KemPublicKey::decode(KemAlgorithm::XWingKemDraft06, bytes)?;
        public_key.encapsulate_derand(&[0xA5; 64]).map(|_| ())
    }))
    .is_ok_and(|result| result.is_ok())
}

pub(crate) fn xwing_kem_output_is_valid(bytes: &[u8]) -> bool {
    bytes.len() == XWING_KEM_OUTPUT_BYTES
        && x25519_component_is_canonical_and_usable(&bytes[XWING_X25519_KEM_OUTPUT_OFFSET..])
}

pub mod snapshot;
pub mod wire;
