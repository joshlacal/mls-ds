//! Device DID parsing and manipulation utilities for multi-device support

/// Parse device MLS DID into (user_did, device_id)
///
/// Format: `did:plc:user#device-uuid`
/// Returns: `(did:plc:user, device-uuid)`
///
/// # Examples
///
/// ```
/// use catbird_server::device_utils::parse_device_did;
///
/// let (user, device) = parse_device_did("did:plc:josh#abc-123").unwrap();
/// assert_eq!(user, "did:plc:josh");
/// assert_eq!(device, "abc-123");
/// ```
///
/// # Errors
///
/// Returns an error if the DID format is invalid.
pub fn parse_device_did(device_did: &str) -> Result<(String, String), String> {
    match device_did.split_once('#') {
        Some((user_part, device_part)) => {
            if user_part.is_empty() || device_part.is_empty() {
                Err(format!("Invalid device DID format: {}", device_did))
            } else {
                Ok((user_part.to_string(), device_part.to_string()))
            }
        }
        None => {
            // Single-device mode: no # suffix
            Ok((device_did.to_string(), String::new()))
        }
    }
}

/// Hash a raw device ID into the opaque storage bucket used by key_packages.
///
/// The server stores key packages under a short stable bucket so per-device
/// reconciliation can partition packages without using the raw device ID as the
/// primary lookup key.
pub fn bucket_device_id(user_did: &str, raw_device_id: &str) -> String {
    let raw_device_id = raw_device_id.trim();
    if raw_device_id.is_empty() {
        String::new()
    } else {
        let bucket_input = format!("{}#{}", user_did, raw_device_id);
        crate::crypto::sha256_hex(bucket_input.as_bytes())[..16].to_string()
    }
}

/// Construct device MLS DID from user DID and device ID
///
/// # Examples
///
/// ```
/// use catbird_server::device_utils::construct_device_did;
///
/// let mls_did = construct_device_did("did:plc:josh", "abc-123");
/// assert_eq!(mls_did, "did:plc:josh#abc-123");
/// ```
pub fn construct_device_did(user_did: &str, device_id: &str) -> String {
    if device_id.is_empty() {
        user_did.to_string()
    } else {
        format!("{}#{}", user_did, device_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_device_did() {
        let (user, device) = parse_device_did("did:plc:josh#abc-123").unwrap();
        assert_eq!(user, "did:plc:josh");
        assert_eq!(device, "abc-123");

        // UUID format
        let (user2, device2) =
            parse_device_did("did:plc:alice#a1b2c3d4-5678-90ab-cdef-1234567890ab").unwrap();
        assert_eq!(user2, "did:plc:alice");
        assert_eq!(device2, "a1b2c3d4-5678-90ab-cdef-1234567890ab");

        // Single-device mode
        let (user3, device3) = parse_device_did("did:plc:bob").unwrap();
        assert_eq!(user3, "did:plc:bob");
        assert_eq!(device3, "");
    }

    #[test]
    fn test_parse_device_did_errors() {
        // Empty device part
        assert!(parse_device_did("did:plc:josh#").is_err());

        // Empty user part
        assert!(parse_device_did("#device").is_err());
    }

    #[test]
    fn test_construct_device_did() {
        assert_eq!(
            construct_device_did("did:plc:josh", "abc-123"),
            "did:plc:josh#abc-123"
        );

        // UUID format
        assert_eq!(
            construct_device_did("did:plc:alice", "a1b2c3d4-5678-90ab-cdef-1234567890ab"),
            "did:plc:alice#a1b2c3d4-5678-90ab-cdef-1234567890ab"
        );

        // Single-device mode
        assert_eq!(construct_device_did("did:plc:bob", ""), "did:plc:bob");
    }

    #[test]
    fn test_bucket_device_id_matches_publish_key_packages_storage() {
        assert_eq!(bucket_device_id("did:plc:bob", ""), "");
        assert_eq!(
            bucket_device_id("did:plc:alice", "device-1"),
            crate::crypto::sha256_hex("did:plc:alice#device-1".as_bytes())[..16].to_string()
        );
    }

    #[test]
    fn test_round_trip() {
        let original = "did:plc:test#device-123";
        let (user, device) = parse_device_did(original).unwrap();
        let reconstructed = construct_device_did(&user, &device);
        assert_eq!(original, reconstructed);
    }
}
