//! Conversions between storage types (`chrono`, `String`) and Petrel ATProto
//! types (`petrel_core::{Did, Datetime}`).
//!
//! These are free functions because the orphan rule forbids implementing the
//! foreign sqlx traits on foreign Petrel types.

use chrono::{DateTime, Utc};
use petrel_core::{Datetime, Did};

// =============================================================================
// Did conversions
// =============================================================================

/// Parse a DID read back from storage. Panics on an invalid DID, which means a
/// row bypassed write-side validation.
pub fn string_to_did(s: &str) -> Did {
    Did::parse(s).unwrap_or_else(|e| panic!("Invalid DID '{}': {}", s, e))
}

pub fn try_string_to_did(s: &str) -> Result<Did, String> {
    Did::parse(s).map_err(|e| format!("Invalid DID '{}': {}", s, e))
}

pub fn did_to_string(did: &Did) -> String {
    did.as_str().to_string()
}

// =============================================================================
// Datetime conversions
// =============================================================================

/// Convert `chrono::DateTime<Utc>` to an AT Protocol `Datetime`.
///
/// The wire spelling is pinned to the pre-Petrel form: rounded to
/// microseconds and rendered `YYYY-MM-DDTHH:MM:SS.ffffffZ` (see the
/// `chrono_to_datetime_spelling` test).
pub fn chrono_to_datetime(dt: DateTime<Utc>) -> Datetime {
    use chrono::DurationRound as _;
    let rounded = dt
        .duration_round(chrono::Duration::microseconds(1))
        .unwrap_or(dt);
    Datetime::parse(rounded.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
        .expect("RFC 3339 micros UTC is a valid AT Protocol datetime")
}

/// Convert a validated MLS canonical timestamp (`YYYY-MM-DDTHH:MM:SS.sssZ`)
/// to `Datetime`, preserving the exact serialized spelling.
pub fn canonical_to_datetime(
    value: &crate::chat_protocol::validation::CanonicalTimestamp,
) -> Datetime {
    Datetime::parse(value.as_str()).expect("canonical timestamp is a valid AT Protocol datetime")
}

/// Convert `chrono::DateTime<Utc>` to `Datetime` in the canonical
/// millisecond `Z` spelling used by signed chat protocol payloads.
pub fn chrono_to_canonical_datetime(dt: DateTime<Utc>) -> Datetime {
    let text = dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    Datetime::parse(text).expect("canonical millis datetime is a valid AT Protocol datetime")
}

/// Convert `Datetime` to `chrono::DateTime<Utc>`.
pub fn datetime_to_chrono(dt: &Datetime) -> DateTime<Utc> {
    DateTime::<Utc>::try_from(dt.clone()).expect("AT Protocol datetime is within chrono's range")
}

pub fn chrono_opt_to_datetime(dt: Option<DateTime<Utc>>) -> Option<Datetime> {
    dt.map(chrono_to_datetime)
}

pub fn datetime_opt_to_chrono(dt: Option<&Datetime>) -> Option<DateTime<Utc>> {
    dt.map(datetime_to_chrono)
}

// =============================================================================
// Lexicon enum conversions
// =============================================================================

/// Build a Petrel open lexicon enum (`known values` + `Unknown(String)`) from
/// its wire spelling. Petrel's `FromStr` for these enums is infallible.
pub fn open_enum<T>(value: impl AsRef<str>) -> T
where
    T: std::str::FromStr<Err = std::convert::Infallible>,
{
    match value.as_ref().parse::<T>() {
        Ok(parsed) => parsed,
        Err(never) => match never {},
    }
}

/// Petrel writes unpadded base64 in DAG-JSON byte objects. Clean-chat reads
/// retain the padded spelling used by the deployed protocol and its digests.
pub fn padded_chat_bytes(encoded: &str) -> Result<String, base64::DecodeError> {
    use base64::{
        engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
        Engine,
    };
    let format = if encoded.ends_with('=') {
        STANDARD
    } else {
        STANDARD_NO_PAD
    };
    format.decode(encoded).map(|bytes| STANDARD.encode(bytes))
}

/// Serialize a generated Petrel value for existing Catbird peers. Typed bytes
/// use padded DAG-JSON at this boundary, including inside tagged unions.
pub fn wire_json_value<T: petrel_core::ToValue>(dto: &T) -> serde_json::Result<serde_json::Value> {
    fn project(value: petrel_core::Value) -> serde_json::Result<serde_json::Value> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use petrel_core::Value;
        match value {
            Value::Bytes(bytes) => Ok(serde_json::json!({"$bytes": STANDARD.encode(bytes)})),
            Value::Array(items) => items
                .into_iter()
                .map(project)
                .collect::<Result<Vec<_>, _>>()
                .map(Into::into),
            Value::Object(entries) => entries
                .into_iter()
                .map(|(key, value)| Ok((key, project(value)?)))
                .collect::<Result<serde_json::Map<_, _>, _>>()
                .map(Into::into),
            scalar => serde_json::to_value(scalar),
        }
    }
    project(dto.to_value().map_err(serde::ser::Error::custom)?)
}

pub fn wire_json_bytes<T: petrel_core::ToValue>(dto: &T) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&wire_json_value(dto)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_chat_bytes_keep_padded_wire_spelling_in_nested_values() {
        use petrel_core::Value;
        let message = Value::Object(
            [
                (
                    "$type".to_owned(),
                    Value::String("example.test#item".into()),
                ),
                (
                    "parts".to_owned(),
                    Value::Array(vec![Value::Bytes(vec![0xff]), Value::String("/w".into())]),
                ),
            ]
            .into_iter()
            .collect(),
        );
        let expected = serde_json::json!({
            "$type": "example.test#item",
            "parts": [{"$bytes": "/w=="}, "/w"]
        });
        assert_eq!(wire_json_value(&message).unwrap(), expected);
        assert_eq!(
            wire_json_bytes(&message).unwrap(),
            serde_json::to_vec(&expected).unwrap()
        );
    }

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
        // Datetimes round to microseconds, so compare at second precision.
        assert_eq!(now.timestamp(), back.timestamp());
    }

    #[test]
    fn test_datetime_opt_none() {
        assert!(chrono_opt_to_datetime(None).is_none());
        assert!(datetime_opt_to_chrono(None).is_none());
    }

    #[test]
    fn chrono_to_datetime_spelling() {
        let dt = DateTime::parse_from_rfc3339("2026-11-27T12:34:56.123456789Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            chrono_to_datetime(dt).as_str(),
            "2026-11-27T12:34:56.123457Z"
        );
        let whole = DateTime::parse_from_rfc3339("2026-11-27T12:34:56Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            chrono_to_datetime(whole).as_str(),
            "2026-11-27T12:34:56.000000Z"
        );
        assert_eq!(
            chrono_to_canonical_datetime(dt).as_str(),
            "2026-11-27T12:34:56.123Z"
        );
    }
}
