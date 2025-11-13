/// Custom serde module for handling ATProto bytes format: { "$bytes": "base64..." }
use base64::Engine;
use serde::{Deserialize, Deserializer, Serializer};

#[derive(serde::Deserialize)]
struct BytesWrapper {
    #[serde(rename = "$bytes")]
    bytes: String,
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
    Wrapper { bytes: &base64_string }.serialize(serializer)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let wrapper = BytesWrapper::deserialize(deserializer)?;
    base64::engine::general_purpose::STANDARD
        .decode(&wrapper.bytes)
        .map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn test_serialize() {
        let test_struct = TestStruct {
            data: b"Hello World".to_vec(),
        };
        let json = serde_json::to_string(&test_struct).unwrap();
        assert!(json.contains(r#""$bytes""#));
        assert!(json.contains("SGVsbG8gV29ybGQ="));
    }
}
