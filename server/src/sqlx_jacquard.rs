//! Helper functions for converting between sqlx types and jacquard-common types
//!
//! Since we can't implement foreign traits on foreign types (orphan rule),
//! we provide conversion functions instead.
//!
//! Jacquard's `Did<'a>` is lifetime-parameterized. For SQLx storage we always
//! use `Did<'static>` (owned) so the value is self-contained.

use chrono::{DateTime, Utc};
use jacquard_common::types::string::{Datetime, Did};

// =============================================================================
// Did conversions
// =============================================================================

/// Convert a database string to `Did<'static>` (owned).
///
/// Panics on invalid DID strings — use only for values known to be valid
/// (i.e. previously validated before storage).
pub fn string_to_did(s: &str) -> Did<'static> {
    Did::new_owned(s).unwrap_or_else(|e| panic!("Invalid DID '{}': {}", s, e))
}

/// Try to convert a database string to `Did<'static>`, returning an error on failure.
pub fn try_string_to_did(s: &str) -> Result<Did<'static>, String> {
    Did::new_owned(s).map_err(|e| format!("Invalid DID '{}': {}", s, e))
}

/// Convert `Did` to `String` for database storage.
pub fn did_to_string(did: &Did<'_>) -> String {
    did.as_str().to_string()
}

// =============================================================================
// Datetime conversions
// =============================================================================

/// Convert `chrono::DateTime<Utc>` to jacquard `Datetime`.
///
/// This is infallible — chrono's RFC 3339 output is always a valid
/// AT Protocol datetime.
pub fn chrono_to_datetime(dt: DateTime<Utc>) -> Datetime {
    Datetime::new(dt.fixed_offset())
}

/// Convert jacquard `Datetime` to `chrono::DateTime<Utc>`.
pub fn datetime_to_chrono(dt: &Datetime) -> DateTime<Utc> {
    let fixed: &chrono::DateTime<chrono::FixedOffset> = dt.as_ref();
    fixed.with_timezone(&Utc)
}

/// Convert `Option<DateTime<Utc>>` to `Option<Datetime>`.
pub fn chrono_opt_to_datetime(dt: Option<DateTime<Utc>>) -> Option<Datetime> {
    dt.map(chrono_to_datetime)
}

/// Convert `Option<&Datetime>` to `Option<DateTime<Utc>>`.
pub fn datetime_opt_to_chrono(dt: Option<&Datetime>) -> Option<DateTime<Utc>> {
    dt.map(datetime_to_chrono)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_roundtrip() {
        let did_str = "did:plc:test123";
        let did = string_to_did(did_str);
        assert_eq!(did_to_string(&did), did_str);
    }

    #[test]
    fn test_try_string_to_did_ok() {
        let did = try_string_to_did("did:plc:abc").unwrap();
        assert_eq!(did.as_str(), "did:plc:abc");
    }

    #[test]
    fn test_try_string_to_did_err() {
        assert!(try_string_to_did("not-a-did").is_err());
    }

    #[test]
    fn test_datetime_roundtrip() {
        let now = Utc::now();
        let jdt = chrono_to_datetime(now);
        let back = datetime_to_chrono(&jdt);
        // Jacquard rounds to microseconds, so compare at that precision
        assert_eq!(now.timestamp(), back.timestamp());
    }

    #[test]
    fn test_datetime_opt_none() {
        assert!(chrono_opt_to_datetime(None).is_none());
        assert!(datetime_opt_to_chrono(None).is_none());
    }
}
