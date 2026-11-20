/// Custom serde module for handling ATProto bytes format: { "$bytes": "base64..." }
use base64::Engine;
use serde::{Deserialize, Deserializer, Serializer};

#[derive(serde::Deserialize)]
struct BytesWrapper {
    #[serde(rename = "$bytes")]
    bytes: String,
}

/// Standard-alphabet base64 that takes padding or leaves it.
///
/// The ATProto data model writes `$bytes` without padding, and the reference PDS does so;
/// Swan and this server pad. A decoder that insists on padding refuses every byte string
/// the reference PDS sends.
///
/// Still checked: the alphabet, the length, and that the bits left over in the last
/// symbol are zero, so each byte string has one spelling apart from its padding. Padding
/// itself is only loosely checked: none and the canonical amount are both accepted, and
/// so is a single `=` where two are canonical (`AA=`). Every caller uses the decoded
/// bytes, never the text, so those spellings are not distinguishable downstream.
const BYTES_DECODER: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

/// Decodes the text of a `$bytes` value from any ATProto server.
pub fn decode_base64(text: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BYTES_DECODER.decode(text)
}

pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::Serialize;

    #[derive(serde::Serialize)]
    struct Wrapper<'a> {
        #[serde(rename = "$bytes")]
        bytes: &'a str,
    }

    let base64_string = base64::engine::general_purpose::STANDARD.encode(bytes);
    Wrapper {
        bytes: &base64_string,
    }
    .serialize(serializer)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let wrapper = BytesWrapper::deserialize(deserializer)?;
    decode_base64(&wrapper.bytes).map_err(serde::de::Error::custom)
}

/// Serde module for optional ATProto bytes: None -> null, Some(bytes) -> {"$bytes": "base64..."}
pub mod option {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    #[derive(serde::Deserialize)]
    struct BytesWrapper {
        #[serde(rename = "$bytes")]
        bytes: String,
    }

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::Serialize;

        #[derive(serde::Serialize)]
        struct Wrapper<'a> {
            #[serde(rename = "$bytes")]
            bytes: &'a str,
        }

        match bytes {
            None => serializer.serialize_none(),
            Some(b) => {
                let base64_string = base64::engine::general_purpose::STANDARD.encode(b);
                Wrapper {
                    bytes: &base64_string,
                }
                .serialize(serializer)
            }
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt_wrapper: Option<BytesWrapper> = Option::deserialize(deserializer)?;
        match opt_wrapper {
            None => Ok(None),
            Some(wrapper) => {
                let bytes =
                    super::decode_base64(&wrapper.bytes).map_err(serde::de::Error::custom)?;
                Ok(Some(bytes))
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "crate::atproto_bytes")]
        data: Vec<u8>,
    }

    #[test]
    fn test_deserialize() {
        let json = r#"{"data": {"$bytes": "SGVsbG8gV29ybGQ="}}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.data, b"Hello World");
    }

    /// The reference PDS writes `$bytes` without padding; Swan and this server pad it.
    #[test]
    fn deserializes_unpadded_bytes_as_the_reference_pds_writes_them() {
        let json = r#"{"data": {"$bytes": "SGVsbG8gV29ybGQ"}}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.data, b"Hello World");

        let optional: TestOptionalStruct = serde_json::from_str(json).unwrap();
        assert_eq!(optional.data, Some(b"Hello World".to_vec()));
    }

    #[test]
    fn a_thirty_two_byte_value_decodes_with_or_without_padding() {
        let bytes = [0xA5u8; 32];
        let padded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
        let unpadded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, bytes);
        assert_eq!(padded.len(), 44);
        assert_eq!(unpadded.len(), 43);
        assert_eq!(crate::atproto_bytes::decode_base64(&padded).unwrap(), bytes);
        assert_eq!(
            crate::atproto_bytes::decode_base64(&unpadded).unwrap(),
            bytes
        );
    }

    #[test]
    fn rejects_text_that_is_not_base64_in_either_form() {
        // Outside the alphabet; an impossible length; non-zero bits left in the last
        // symbol; padding in the middle; more padding than a group can have.
        for text in [
            "SGVsbG8*",
            "SGVsbG8gV29ybGQ==",
            "SGVsbG8gV29ybGR",
            "AA==AA==",
            "AA===",
        ] {
            assert!(
                crate::atproto_bytes::decode_base64(text).is_err(),
                "{text} must be refused"
            );
        }
    }

    /// Pins what "padding optional" means with this decoder, so a change is noticed.
    #[test]
    fn padding_may_be_absent_canonical_or_short() {
        for text in ["AA", "AA==", "AA="] {
            assert_eq!(
                crate::atproto_bytes::decode_base64(text).unwrap(),
                vec![0u8],
                "{text}"
            );
        }
    }

    #[test]
    fn test_serialize() {
        let test_struct = TestStruct {
            data: b"Hello World".to_vec(),
        };
        let json = serde_json::to_string(&test_struct).unwrap();
        assert!(json.contains(r#""$bytes""#));
        assert!(json.contains("SGVsbG8gV29ybGQ="));
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestOptionalStruct {
        #[serde(with = "crate::atproto_bytes::option")]
        #[serde(skip_serializing_if = "Option::is_none")]
        // The `option` module's deserializer is invoked when the field is
        // present (including null); for a fully-missing field, serde looks
        // for `Default`. Without `#[serde(default)]` the test for
        // missing-field handling failed with `missing field "data"`. Adding
        // `default` matches the behavior the test expects and aligns with
        // the production lexicons that emit `data` only when populated.
        #[serde(default)]
        data: Option<Vec<u8>>,
    }

    #[test]
    fn test_optional_deserialize_some() {
        let json = r#"{"data": {"$bytes": "SGVsbG8gV29ybGQ="}}"#;
        let result: TestOptionalStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.data, Some(b"Hello World".to_vec()));
    }

    #[test]
    fn test_optional_deserialize_null() {
        let json = r#"{"data": null}"#;
        let result: TestOptionalStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.data, None);
    }

    #[test]
    fn test_optional_deserialize_missing() {
        let json = r#"{}"#;
        let result: TestOptionalStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.data, None);
    }

    #[test]
    fn test_optional_serialize_some() {
        let test_struct = TestOptionalStruct {
            data: Some(b"Hello World".to_vec()),
        };
        let json = serde_json::to_string(&test_struct).unwrap();
        assert!(json.contains(r#""$bytes""#));
        assert!(json.contains("SGVsbG8gV29ybGQ="));
    }

    #[test]
    fn test_optional_serialize_none() {
        let test_struct = TestOptionalStruct { data: None };
        let json = serde_json::to_string(&test_struct).unwrap();
        // With skip_serializing_if, None should not appear in JSON
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_optional_roundtrip() {
        let original = TestOptionalStruct {
            data: Some(b"Test Data".to_vec()),
        };
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: TestOptionalStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }
}
