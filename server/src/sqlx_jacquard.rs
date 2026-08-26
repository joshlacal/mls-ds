//! Helper functions for converting between sqlx types and jacquard-common types
//!
//! Since we can't implement foreign traits on foreign types (orphan rule),
//! we provide conversion functions instead.
//!
//! Jacquard's `Did` is lifetime-parameterized. For SQLx storage we always
//! use `Did` (owned) so the value is self-contained.

use chrono::{DateTime, Utc};
use jacquard_common::types::string::{Datetime, Did};

// =============================================================================
// Did conversions
// =============================================================================

/// Convert a database string to `Did` (owned).
///
/// Panics on invalid DID strings — use only for values known to be valid
/// (i.e. previously validated before storage).
pub fn string_to_did(s: &str) -> Did {
    Did::new_owned(s).unwrap_or_else(|e| panic!("Invalid DID '{}': {}", s, e))
}

/// Try to convert a database string to `Did`, returning an error on failure.
pub fn try_string_to_did(s: &str) -> Result<Did, String> {
    Did::new_owned(s).map_err(|e| format!("Invalid DID '{}': {}", s, e))
}

/// Convert `Did` to `String` for database storage.
pub fn did_to_string(did: &Did) -> String {
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

/// Convert a canonical clean-chat timestamp (exact 24-char millis UTC grammar)
/// to jacquard `Datetime`, preserving the exact serialized spelling.
///
/// `Datetime::new` re-serializes with microsecond precision, which breaks the
/// canonical 24-char millis form the envelope digest binds. `FromStr` keeps
/// the input spelling verbatim, so this is the only spelling-preserving
/// conversion for canonical timestamps.
pub fn canonical_to_datetime(
    value: &crate::chat_protocol::validation::CanonicalTimestamp,
) -> Datetime {
    value
        .as_str()
        .parse()
        .expect("canonical timestamp is a valid AT Protocol datetime")
}

/// Convert `chrono::DateTime<Utc>` to jacquard `Datetime` in the canonical
/// 24-char millis spelling (not `Datetime::new`'s microsecond form).
pub fn chrono_to_canonical_datetime(dt: DateTime<Utc>) -> Datetime {
    let text = dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    text.parse()
        .expect("canonical millis datetime is a valid AT Protocol datetime")
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
