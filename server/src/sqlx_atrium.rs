//! Helper functions for converting between sqlx types and Atrium types
//!
//! Since we can't implement foreign traits on foreign types (orphan rule),
//! we provide conversion functions instead.

use atrium_api::types::string::{Datetime, Did};
use chrono::{DateTime, Utc};

// =============================================================================
// Did conversions
// =============================================================================

/// Convert String to Did (for database queries)
pub fn string_to_did(s: &str) -> Result<Did, String> {
    s.parse::<Did>().map_err(|e| format!("Invalid DID: {}", e))
}

/// Convert Did to String (for database storage)
pub fn did_to_string(did: &Did) -> String {
    did.as_str().to_string()
}

// =============================================================================
// Datetime conversions
// =============================================================================

/// Convert chrono DateTime to Atrium Datetime
///
/// # Safety
/// This function is infallible because RFC3339 strings produced by chrono
/// are always valid Datetime strings per the ATProto spec.
pub fn chrono_to_datetime(dt: DateTime<Utc>) -> Datetime {
    // Parse RFC3339 string to Datetime
    // SAFETY: chrono's to_rfc3339() always produces valid RFC3339 format,
    // which is a subset of the Datetime format accepted by Atrium.
    // The only way this can fail is if there's a bug in chrono or Atrium,
    // which would be a critical library bug that should crash the program.
    dt.to_rfc3339()
        .parse::<Datetime>()
        .expect("BUG: chrono RFC3339 should always parse as Datetime")
}

/// Convert Atrium Datetime to chrono DateTime
///
/// # Safety
/// This function is infallible because Datetime strings from Atrium
/// are always valid RFC3339 strings per the ATProto spec.
pub fn datetime_to_chrono(dt: &Datetime) -> DateTime<Utc> {
    // SAFETY: Atrium Datetime is guaranteed to be valid RFC3339 per ATProto spec.
    // The only way this can fail is if the Datetime validation is broken,
    // which would be a critical library bug that should crash the program.
    DateTime::parse_from_rfc3339(dt.as_str())
        .expect("BUG: Atrium Datetime should always be valid RFC3339")
        .with_timezone(&Utc)
}

/// Convert Option<DateTime<Utc>> to Option<Datetime>
pub fn chrono_opt_to_datetime(dt: Option<DateTime<Utc>>) -> Option<Datetime> {
    dt.map(chrono_to_datetime)
}

/// Convert Option<Datetime> to Option<DateTime<Utc>>
pub fn datetime_opt_to_chrono(dt: Option<&Datetime>) -> Option<DateTime<Utc>> {
    dt.map(datetime_to_chrono)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_conversion() {
        let did_str = "did:plc:test123";
        let did = string_to_did(did_str).unwrap();
        assert_eq!(did_to_string(&did), did_str);
    }

    #[test]
    fn test_datetime_conversion() {
        let now = Utc::now();
        let atrium_dt = chrono_to_datetime(now);
        let back = datetime_to_chrono(&atrium_dt);

        // Should be equal (RFC3339 has second precision)
        assert_eq!(now.timestamp(), back.timestamp());
    }
}
