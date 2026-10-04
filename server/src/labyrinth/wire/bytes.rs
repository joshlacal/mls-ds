//! The atproto JSON `bytes` value (`{"$bytes": "<base64, no padding>"}`) and
//! the small checks every Labyrinth record shares.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};

/// Bytes in the atproto JSON data model.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// The value as `[u8; N]`; `what` names the field in the error.
    pub fn array<const N: usize>(&self, what: &str) -> LabyrinthResult<[u8; N]> {
        self.0
            .as_slice()
            .try_into()
            .map_err(|_| LabyrinthError::invalid(format!("{what} must be {N} bytes")))
    }

    /// Lexicon `minLength`/`maxLength` on a bytes field.
    pub fn check(&self, what: &str, min: usize, max: usize) -> LabyrinthResult<()> {
        if (min..=max).contains(&self.0.len()) {
            Ok(())
        } else {
            Err(LabyrinthError::invalid(format!(
                "{what} must be {min}..={max} bytes"
            )))
        }
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("$bytes", &STANDARD_NO_PAD.encode(&self.0))?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            #[serde(rename = "$bytes")]
            bytes: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        // atproto writes unpadded base64; accept padded input too, as the
        // crate's reader does.
        STANDARD_NO_PAD
            .decode(&wire.bytes)
            .or_else(|_| STANDARD.decode(&wire.bytes))
            .map(Bytes)
            .map_err(serde::de::Error::custom)
    }
}

/// Lexicon `maxLength` on a string (UTF-8 bytes) plus non-emptiness.
pub fn check_str(what: &str, value: &str, max: usize) -> LabyrinthResult<()> {
    if value.is_empty() || value.len() > max {
        return Err(LabyrinthError::invalid(format!(
            "{what} must be 1..={max} bytes"
        )));
    }
    Ok(())
}

/// An RFC 3339 `datetime` string.
pub fn check_datetime(what: &str, value: &str) -> LabyrinthResult<()> {
    if value.len() > 64 || chrono::DateTime::parse_from_rfc3339(value).is_err() {
        return Err(LabyrinthError::invalid(format!(
            "{what} is not an RFC 3339 datetime"
        )));
    }
    Ok(())
}

/// A bare DID exactly as `chat.is_bare_did` accepts it: `did:plc:` with 24
/// base32 characters, or `did:web:` with a lowercase multi-label public
/// hostname.
pub fn check_did(what: &str, value: &str) -> LabyrinthResult<()> {
    if is_bare_did(value) {
        Ok(())
    } else {
        Err(LabyrinthError::invalid(format!("{what} is not a bare DID")))
    }
}

fn is_bare_did(value: &str) -> bool {
    if !(12..=261).contains(&value.len()) || !value.is_ascii() {
        return false;
    }
    if let Some(id) = value.strip_prefix("did:plc:") {
        return id.len() == 24 && id.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'));
    }
    let Some(host) = value.strip_prefix("did:web:") else {
        return false;
    };
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
    {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let label_ok =
        |l: &str| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-');
    if !labels.iter().all(|l| label_ok(l)) {
        return false;
    }
    let last = labels[labels.len() - 1];
    last.as_bytes()[0].is_ascii_lowercase()
        && !matches!(
            last,
            "alt"
                | "arpa"
                | "example"
                | "internal"
                | "invalid"
                | "local"
                | "localhost"
                | "onion"
                | "test"
        )
}

/// Lexicon epoch-number bound (`maximum: 2^40`).
pub const MAX_EPOCH_NUMBER: u64 = 1 << 40;

pub fn check_epoch_number(what: &str, value: u64) -> LabyrinthResult<()> {
    if value <= MAX_EPOCH_NUMBER {
        Ok(())
    } else {
        Err(LabyrinthError::invalid(format!("{what} exceeds 2^40")))
    }
}

/// `$type` must name the record collection.
pub fn check_type(found: &str, nsid: &str) -> LabyrinthResult<()> {
    if found == nsid {
        Ok(())
    } else {
        Err(LabyrinthError::invalid(format!("$type must be {nsid}")))
    }
}

/// Fixed-size lowercase-hex query parameter.
pub fn hex_array<const N: usize>(what: &str, value: &str) -> LabyrinthResult<[u8; N]> {
    if value.len() != 2 * N || value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(LabyrinthError::invalid(format!(
            "{what} must be {} lowercase hex digits",
            2 * N
        )));
    }
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| LabyrinthError::invalid(format!("{what} is not hex")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_unpadded_and_accept_padded() {
        let b = Bytes(vec![1, 2, 3, 4]);
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(json, r#"{"$bytes":"AQIDBA"}"#);
        assert_eq!(serde_json::from_str::<Bytes>(&json).unwrap(), b);
        assert_eq!(
            serde_json::from_str::<Bytes>(r#"{"$bytes":"AQIDBA=="}"#).unwrap(),
            b
        );
        assert!(serde_json::from_str::<Bytes>(r#"{"$bytes":"AQ","x":1}"#).is_err());
    }

    #[test]
    fn did_and_hex_checks() {
        assert!(check_did("d", "did:plc:abcdefghijklmnopqrstuvwx").is_ok());
        assert!(check_did("d", "did:web:chat.catbird.blue").is_ok());
        assert!(check_did("d", "did:plc:abc234").is_err());
        assert!(check_did("d", "did:web:example.test").is_err());
        assert!(check_did("d", "did:web:-bad.com").is_err());
        assert!(check_did("d", "did:plc:abcdefghijklmnopqrstuvw#").is_err());
        assert_eq!(hex_array::<2>("h", "0aff").unwrap(), [0x0a, 0xff]);
        assert!(hex_array::<2>("h", "0AFF").is_err());
        assert!(hex_array::<2>("h", "0a").is_err());
    }
}
