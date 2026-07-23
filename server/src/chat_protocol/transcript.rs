//! Closed clean-chat signing and outer-control transcript authority.
//!
//! The public API never accepts a caller-defined schema, domain, or type ID.
//! Raw JSON is decoded with duplicate/null/float rejection and projected only
//! through the embedded canonical `blue.catbird.chat.defs` contract before any
//! generated DTO or cryptographic authority can exist.

use std::{collections::BTreeMap, fmt, sync::OnceLock};

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeMap, SerializeSeq},
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_json::Value as SchemaValue;
use sha2::{Digest, Sha256};

use super::{
    model::AuthPrimitiveError,
    validation::{
        ed25519_key_id, BareDid, CanonicalTimestamp, CanonicalUuidV4, KeyThumbprint,
        TrustedRequestInstant, ValidatedChatNsid, MAX_SAFE_INTEGER,
    },
};

const TYPE_PREFIX: &str = "blue.catbird.chat.defs#";
const APPLICATION_FINGERPRINT_DOMAIN: &[u8] = b"CATBIRD-CHAT-APPLICATION-ENTRY-FINGERPRINT\0";
const CONTROL_FINGERPRINT_DOMAIN: &[u8] = b"CATBIRD-CHAT-CONTROL-ENTRY-FINGERPRINT\0";
// The frozen contract permits 100 maximum-size 64-KiB KeyPackages. Their
// compact canonical-base64 JSON representation is under 9 MiB; 16 MiB admits
// that maximum batch while retaining a hard pre-deserialization transport cap.
const MAX_SIGNED_JSON_BYTES: usize = 16 * 1024 * 1024;
const CONTRACT_JSON: &str =
    include_str!("../../../lexicon/blue/catbird/chat/blue.catbird.chat.defs.json");

#[derive(Debug)]
enum RawJson {
    String(String),
    Integer(u64),
    Bool(bool),
    Array(Vec<RawJson>),
    Object(BTreeMap<String, RawJson>),
}

impl<'de> Deserialize<'de> for RawJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(RawJsonVisitor)
    }
}

struct RawJsonVisitor;

impl<'de> Visitor<'de> for RawJsonVisitor {
    type Value = RawJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("closed non-null clean-chat JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(RawJson::Bool(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(RawJson::Integer(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        u64::try_from(value)
            .map(RawJson::Integer)
            .map_err(|_| E::custom("negative integers are not in the clean-chat profile"))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("floats are not in the clean-chat profile"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(RawJson::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(RawJson::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("null is forbidden"))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("null is forbidden"))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(RawJson::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value()?;
            if values.insert(key, value).is_some() {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
        }
        Ok(RawJson::Object(values))
    }
}

fn decode_raw_json(raw: &[u8]) -> Result<RawJson, AuthPrimitiveError> {
    if raw.is_empty() || raw.len() > MAX_SIGNED_JSON_BYTES {
        return Err(AuthPrimitiveError::invalid("signed JSON size"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = RawJson::deserialize(&mut deserializer)
        .map_err(|_| AuthPrimitiveError::invalid("invalid strict signed JSON"))?;
    deserializer
        .end()
        .map_err(|_| AuthPrimitiveError::invalid("trailing signed JSON data"))?;
    Ok(value)
}

/// Lossless subset accepted at the bytes-based public-entry boundary. It is
/// deliberately separate from `RawJson`: byte strings remain byte strings,
/// and no JSON or generated DTO can inhabit this decode path.
#[derive(Clone, Debug)]
enum RawCbor {
    Text(String),
    Bytes(Vec<u8>),
    Integer(u64),
    Bool(bool),
    Array(Vec<RawCbor>),
    Map(BTreeMap<String, RawCbor>),
}

impl<'de> Deserialize<'de> for RawCbor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(RawCborVisitor)
    }
}

struct RawCborVisitor;

impl<'de> Visitor<'de> for RawCborVisitor {
    type Value = RawCbor;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("closed canonical clean-chat DAG-CBOR")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(RawCbor::Bool(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(RawCbor::Integer(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        u64::try_from(value)
            .map(RawCbor::Integer)
            .map_err(|_| E::custom("negative integers are not in the clean-chat profile"))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("floats are not in the clean-chat profile"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(RawCbor::Text(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(RawCbor::Text(value))
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E> {
        Ok(RawCbor::Bytes(value.to_vec()))
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        Ok(RawCbor::Bytes(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("null is forbidden"))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("null is forbidden"))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(RawCbor::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value()?;
            if values.insert(key, value).is_some() {
                return Err(de::Error::custom("duplicate DAG-CBOR map key"));
            }
        }
        Ok(RawCbor::Map(values))
    }
}

impl Serialize for RawCbor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Text(value) => serializer.serialize_str(value),
            Self::Bytes(value) => serializer.serialize_bytes(value),
            Self::Integer(value) => serializer.serialize_u64(*value),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(value)?;
                }
                sequence.end()
            }
            Self::Map(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in values {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

fn decode_canonical_raw_cbor(raw: &[u8]) -> Result<RawCbor, AuthPrimitiveError> {
    if raw.is_empty() || raw.len() > MAX_SIGNED_JSON_BYTES {
        return Err(AuthPrimitiveError::invalid("application entry size"));
    }
    let value: RawCbor = serde_ipld_dagcbor::from_slice(raw)
        .map_err(|_| AuthPrimitiveError::invalid("invalid application entry DAG-CBOR"))?;
    let canonical = serde_ipld_dagcbor::to_vec(&value)
        .map_err(|_| AuthPrimitiveError::invalid("application entry DAG-CBOR encoding"))?;
    if canonical != raw {
        return Err(AuthPrimitiveError::invalid(
            "noncanonical or trailing application entry DAG-CBOR",
        ));
    }
    Ok(value)
}

#[derive(Clone, Debug)]
enum DagValue {
    Text(String),
    Uuid(CanonicalUuidV4),
    Did(BareDid),
    Thumbprint(KeyThumbprint),
    Timestamp(CanonicalTimestamp),
    Bytes(Vec<u8>),
    Integer(u64),
    Bool(bool),
    Array(Vec<DagValue>),
    Map(BTreeMap<String, DagValue>),
}

impl Serialize for DagValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Text(value) => serializer.serialize_str(value),
            Self::Uuid(value) => serializer.serialize_bytes(value.as_bytes()),
            Self::Did(value) => serializer.serialize_str(value.as_str()),
            Self::Thumbprint(value) => serializer.serialize_str(value.as_str()),
            Self::Timestamp(value) => serializer.serialize_str(value.as_str()),
            Self::Bytes(value) => serializer.serialize_bytes(value),
            Self::Integer(value) => serializer.serialize_u64(*value),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(value)?;
                }
                sequence.end()
            }
            Self::Map(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in values {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

fn contract() -> &'static SchemaValue {
    static CONTRACT: OnceLock<SchemaValue> = OnceLock::new();
    CONTRACT.get_or_init(|| {
        serde_json::from_str(CONTRACT_JSON).expect("embedded clean-chat lexicon must be valid JSON")
    })
}

fn definition(name: &str) -> Result<&'static SchemaValue, AuthPrimitiveError> {
    contract()["defs"]
        .get(name)
        .ok_or_else(|| AuthPrimitiveError::invalid("unknown embedded contract definition"))
}

fn cbor_ref_to_raw_json(
    name: &str,
    input: &RawCbor,
    tagged: bool,
) -> Result<RawJson, AuthPrimitiveError> {
    match name {
        "operationId" | "deviceId" => match input {
            RawCbor::Bytes(value) => {
                let bytes: [u8; 16] = value
                    .as_slice()
                    .try_into()
                    .map_err(|_| AuthPrimitiveError::invalid("UUID byte length"))?;
                let text = uuid::Uuid::from_bytes(bytes).hyphenated().to_string();
                CanonicalUuidV4::parse(&text)?;
                Ok(RawJson::String(text))
            }
            _ => Err(AuthPrimitiveError::invalid("UUID DAG-CBOR field type")),
        },
        "bareDid" | "keyId" | "canonicalDatetime" => match input {
            RawCbor::Text(value) => Ok(RawJson::String(value.clone())),
            _ => Err(AuthPrimitiveError::invalid("text DAG-CBOR field type")),
        },
        _ => cbor_schema_to_raw_json(definition(name)?, input, Some(name), tagged),
    }
}

fn cbor_schema_to_raw_json(
    schema: &SchemaValue,
    input: &RawCbor,
    definition_name: Option<&str>,
    tagged: bool,
) -> Result<RawJson, AuthPrimitiveError> {
    match schema["type"].as_str() {
        Some("ref") => {
            let name = schema["ref"]
                .as_str()
                .and_then(|value| value.strip_prefix('#'))
                .ok_or_else(|| AuthPrimitiveError::invalid("invalid embedded CBOR ref"))?;
            cbor_ref_to_raw_json(name, input, false)
        }
        Some("union") => {
            let RawCbor::Map(values) = input else {
                return Err(AuthPrimitiveError::invalid(
                    "closed CBOR union must be an object",
                ));
            };
            let type_id = match values.get("$type") {
                Some(RawCbor::Text(value)) => value.as_str(),
                _ => {
                    return Err(AuthPrimitiveError::invalid(
                        "closed CBOR union requires exact $type",
                    ));
                }
            };
            let name = type_id
                .strip_prefix(TYPE_PREFIX)
                .ok_or_else(|| AuthPrimitiveError::invalid("closed CBOR union namespace"))?;
            let allowed = schema["refs"]
                .as_array()
                .ok_or_else(|| AuthPrimitiveError::invalid("invalid embedded CBOR union refs"))?
                .iter()
                .filter_map(SchemaValue::as_str)
                .filter_map(|value| value.strip_prefix('#'))
                .any(|candidate| candidate == name);
            if !allowed {
                return Err(AuthPrimitiveError::invalid(
                    "unknown closed CBOR union variant",
                ));
            }
            cbor_ref_to_raw_json(name, input, true)
        }
        Some("object") => {
            let RawCbor::Map(values) = input else {
                return Err(AuthPrimitiveError::invalid("CBOR object field type"));
            };
            let properties = schema["properties"].as_object().ok_or_else(|| {
                AuthPrimitiveError::invalid("invalid embedded CBOR object properties")
            })?;
            let mut output = BTreeMap::new();
            for (name, value) in values {
                if name == "$type" {
                    if !tagged {
                        return Err(AuthPrimitiveError::invalid("unexpected CBOR $type"));
                    }
                    let expected = format!("{TYPE_PREFIX}{}", definition_name.unwrap_or_default());
                    match value {
                        RawCbor::Text(actual) if actual == &expected => {
                            output.insert(name.clone(), RawJson::String(actual.clone()));
                        }
                        _ => {
                            return Err(AuthPrimitiveError::invalid(
                                "wrong closed CBOR object $type",
                            ));
                        }
                    }
                    continue;
                }
                let property = properties
                    .get(name)
                    .ok_or_else(|| AuthPrimitiveError::invalid("unknown closed CBOR field"))?;
                output.insert(
                    name.clone(),
                    cbor_schema_to_raw_json(property, value, Some(name), false)?,
                );
            }
            if tagged && !output.contains_key("$type") {
                return Err(AuthPrimitiveError::invalid(
                    "missing closed CBOR object $type",
                ));
            }
            let required = schema["required"].as_array().ok_or_else(|| {
                AuthPrimitiveError::invalid("invalid embedded CBOR required fields")
            })?;
            if required
                .iter()
                .filter_map(SchemaValue::as_str)
                .any(|name| !output.contains_key(name))
            {
                return Err(AuthPrimitiveError::invalid(
                    "missing required closed CBOR object field",
                ));
            }
            Ok(RawJson::Object(output))
        }
        Some("string") => match input {
            RawCbor::Text(value) => Ok(RawJson::String(value.clone())),
            _ => Err(AuthPrimitiveError::invalid("CBOR string field type")),
        },
        Some("bytes") => match input {
            RawCbor::Bytes(value) => Ok(RawJson::String(STANDARD.encode(value))),
            _ => Err(AuthPrimitiveError::invalid("CBOR bytes field type")),
        },
        Some("integer") => match input {
            RawCbor::Integer(value) => Ok(RawJson::Integer(*value)),
            _ => Err(AuthPrimitiveError::invalid("CBOR integer field type")),
        },
        Some("boolean") => match input {
            RawCbor::Bool(value) => Ok(RawJson::Bool(*value)),
            _ => Err(AuthPrimitiveError::invalid("CBOR boolean field type")),
        },
        Some("array") => {
            let RawCbor::Array(values) = input else {
                return Err(AuthPrimitiveError::invalid("CBOR array field type"));
            };
            let items = schema
                .get("items")
                .ok_or_else(|| AuthPrimitiveError::invalid("invalid embedded CBOR array items"))?;
            values
                .iter()
                .map(|value| cbor_schema_to_raw_json(items, value, None, false))
                .collect::<Result<Vec<_>, _>>()
                .map(RawJson::Array)
        }
        _ => Err(AuthPrimitiveError::invalid(
            "unsupported embedded CBOR schema type",
        )),
    }
}

fn project_ref(name: &str, input: &RawJson, tagged: bool) -> Result<DagValue, AuthPrimitiveError> {
    match name {
        "operationId" | "deviceId" => match input {
            RawJson::String(value) => Ok(DagValue::Uuid(CanonicalUuidV4::parse(value)?)),
            _ => Err(AuthPrimitiveError::invalid("UUID field type")),
        },
        "bareDid" => match input {
            RawJson::String(value) => Ok(DagValue::Did(BareDid::parse(value)?)),
            _ => Err(AuthPrimitiveError::invalid("DID field type")),
        },
        "keyId" => match input {
            RawJson::String(value) => Ok(DagValue::Thumbprint(KeyThumbprint::parse(value)?)),
            _ => Err(AuthPrimitiveError::invalid("key ID field type")),
        },
        "canonicalDatetime" => match input {
            RawJson::String(value) => Ok(DagValue::Timestamp(CanonicalTimestamp::parse(value)?)),
            _ => Err(AuthPrimitiveError::invalid("timestamp field type")),
        },
        _ => project_schema(definition(name)?, input, Some(name), tagged),
    }
}

fn project_schema(
    schema: &SchemaValue,
    input: &RawJson,
    field_name: Option<&str>,
    tagged_object: bool,
) -> Result<DagValue, AuthPrimitiveError> {
    match schema["type"].as_str() {
        Some("ref") => {
            let name = schema["ref"]
                .as_str()
                .and_then(|value| value.strip_prefix('#'))
                .ok_or_else(|| AuthPrimitiveError::invalid("invalid embedded ref"))?;
            project_ref(name, input, false)
        }
        Some("union") => project_union(schema, input),
        Some("object") => project_object(schema, input, field_name, tagged_object),
        Some("string") => project_string(schema, input, field_name),
        Some("bytes") => project_bytes(schema, input),
        Some("integer") => project_integer(schema, input),
        Some("boolean") => project_boolean(schema, input),
        Some("array") => project_array(schema, input, field_name),
        _ => Err(AuthPrimitiveError::invalid(
            "unsupported embedded schema type",
        )),
    }
}

fn project_union(schema: &SchemaValue, input: &RawJson) -> Result<DagValue, AuthPrimitiveError> {
    let RawJson::Object(values) = input else {
        return Err(AuthPrimitiveError::invalid(
            "closed union must be an object",
        ));
    };
    let type_id = match values.get("$type") {
        Some(RawJson::String(value)) => value.as_str(),
        _ => {
            return Err(AuthPrimitiveError::invalid(
                "closed union requires exact $type",
            ));
        }
    };
    let name = type_id
        .strip_prefix(TYPE_PREFIX)
        .ok_or_else(|| AuthPrimitiveError::invalid("closed union type namespace"))?;
    let allowed = schema["refs"]
        .as_array()
        .ok_or_else(|| AuthPrimitiveError::invalid("invalid embedded union refs"))?
        .iter()
        .filter_map(SchemaValue::as_str)
        .filter_map(|value| value.strip_prefix('#'))
        .any(|candidate| candidate == name);
    if !allowed {
        return Err(AuthPrimitiveError::invalid("unknown closed union variant"));
    }
    project_ref(name, input, true)
}

fn project_object(
    schema: &SchemaValue,
    input: &RawJson,
    definition_name: Option<&str>,
    tagged: bool,
) -> Result<DagValue, AuthPrimitiveError> {
    let RawJson::Object(values) = input else {
        return Err(AuthPrimitiveError::invalid("object field type"));
    };
    let properties = schema["properties"]
        .as_object()
        .ok_or_else(|| AuthPrimitiveError::invalid("invalid embedded object properties"))?;
    let mut output = BTreeMap::new();
    for (name, value) in values {
        if name == "$type" {
            if !tagged {
                return Err(AuthPrimitiveError::invalid("unexpected $type"));
            }
            let expected = format!("{TYPE_PREFIX}{}", definition_name.unwrap_or_default());
            match value {
                RawJson::String(actual) if actual == &expected => {
                    output.insert(name.clone(), DagValue::Text(actual.clone()));
                }
                _ => return Err(AuthPrimitiveError::invalid("wrong closed object $type")),
            }
            continue;
        }
        let property = properties
            .get(name)
            .ok_or_else(|| AuthPrimitiveError::invalid("unknown closed object field"))?;
        output.insert(
            name.clone(),
            project_schema(property, value, Some(name), false)?,
        );
    }
    if tagged && !output.contains_key("$type") {
        return Err(AuthPrimitiveError::invalid("missing closed object $type"));
    }
    let required = schema["required"]
        .as_array()
        .ok_or_else(|| AuthPrimitiveError::invalid("invalid embedded required fields"))?;
    if required
        .iter()
        .filter_map(SchemaValue::as_str)
        .any(|name| !output.contains_key(name))
    {
        return Err(AuthPrimitiveError::invalid(
            "missing required closed object field",
        ));
    }
    if let Some(name) = definition_name {
        enforce_contract_order(name, &output)?;
    }
    Ok(DagValue::Map(output))
}

fn project_string(
    schema: &SchemaValue,
    input: &RawJson,
    field_name: Option<&str>,
) -> Result<DagValue, AuthPrimitiveError> {
    let RawJson::String(value) = input else {
        return Err(AuthPrimitiveError::invalid("string field type"));
    };
    if let Some(expected) = schema["const"].as_str() {
        if value != expected {
            return Err(AuthPrimitiveError::invalid("wrong constant string"));
        }
    }
    if let Some(values) = schema["enum"].as_array() {
        if !values
            .iter()
            .filter_map(SchemaValue::as_str)
            .any(|item| item == value)
        {
            return Err(AuthPrimitiveError::invalid("string outside closed enum"));
        }
    }
    if let Some(values) = schema["knownValues"].as_array() {
        if !values
            .iter()
            .filter_map(SchemaValue::as_str)
            .any(|item| item == value)
        {
            return Err(AuthPrimitiveError::invalid(
                "string outside closed known values",
            ));
        }
    }
    let length = value.len() as u64;
    if schema["minLength"].as_u64().is_some_and(|min| length < min)
        || schema["maxLength"].as_u64().is_some_and(|max| length > max)
    {
        return Err(AuthPrimitiveError::invalid("string length bound"));
    }
    if matches!(
        field_name,
        Some("dpopJkt" | "currentDpopJkt" | "newDpopJkt")
    ) {
        return Ok(DagValue::Thumbprint(KeyThumbprint::parse(value)?));
    }
    Ok(DagValue::Text(value.clone()))
}

fn decode_standard_base64(value: &str) -> Result<Vec<u8>, AuthPrimitiveError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| AuthPrimitiveError::invalid("invalid standard base64 bytes"))?;
    if STANDARD.encode(&decoded) != value {
        return Err(AuthPrimitiveError::invalid(
            "noncanonical standard base64 bytes",
        ));
    }
    Ok(decoded)
}

fn project_bytes(schema: &SchemaValue, input: &RawJson) -> Result<DagValue, AuthPrimitiveError> {
    let RawJson::String(value) = input else {
        return Err(AuthPrimitiveError::invalid("bytes field type"));
    };
    let decoded = decode_standard_base64(value)?;
    let length = decoded.len() as u64;
    if schema["minLength"].as_u64().is_some_and(|min| length < min)
        || schema["maxLength"].as_u64().is_some_and(|max| length > max)
    {
        return Err(AuthPrimitiveError::invalid("bytes length bound"));
    }
    Ok(DagValue::Bytes(decoded))
}

fn project_integer(schema: &SchemaValue, input: &RawJson) -> Result<DagValue, AuthPrimitiveError> {
    let RawJson::Integer(value) = input else {
        return Err(AuthPrimitiveError::invalid("integer field type"));
    };
    if *value > MAX_SAFE_INTEGER as u64
        || schema["minimum"].as_u64().is_some_and(|min| *value < min)
        || schema["maximum"].as_u64().is_some_and(|max| *value > max)
        || schema["const"]
            .as_u64()
            .is_some_and(|constant| *value != constant)
    {
        return Err(AuthPrimitiveError::invalid("integer value bound"));
    }
    Ok(DagValue::Integer(*value))
}

fn project_boolean(schema: &SchemaValue, input: &RawJson) -> Result<DagValue, AuthPrimitiveError> {
    let RawJson::Bool(value) = input else {
        return Err(AuthPrimitiveError::invalid("boolean field type"));
    };
    if schema["const"]
        .as_bool()
        .is_some_and(|constant| *value != constant)
    {
        return Err(AuthPrimitiveError::invalid("wrong constant boolean"));
    }
    Ok(DagValue::Bool(*value))
}

fn project_array(
    schema: &SchemaValue,
    input: &RawJson,
    field_name: Option<&str>,
) -> Result<DagValue, AuthPrimitiveError> {
    let RawJson::Array(values) = input else {
        return Err(AuthPrimitiveError::invalid("array field type"));
    };
    let length = values.len() as u64;
    if schema["minLength"].as_u64().is_some_and(|min| length < min)
        || schema["maxLength"].as_u64().is_some_and(|max| length > max)
    {
        return Err(AuthPrimitiveError::invalid("array length bound"));
    }
    let items = schema
        .get("items")
        .ok_or_else(|| AuthPrimitiveError::invalid("invalid embedded array items"))?;
    values
        .iter()
        .map(|value| project_schema(items, value, field_name, false))
        .collect::<Result<Vec<_>, _>>()
        .map(DagValue::Array)
}

fn map_value<'a>(
    map: &'a BTreeMap<String, DagValue>,
    name: &str,
) -> Result<&'a DagValue, AuthPrimitiveError> {
    map.get(name)
        .ok_or_else(|| AuthPrimitiveError::invalid("missing canonical field"))
}

fn value_map(value: &DagValue) -> Result<&BTreeMap<String, DagValue>, AuthPrimitiveError> {
    match value {
        DagValue::Map(value) => Ok(value),
        _ => Err(AuthPrimitiveError::invalid("canonical object expected")),
    }
}

fn value_array(value: &DagValue) -> Result<&[DagValue], AuthPrimitiveError> {
    match value {
        DagValue::Array(value) => Ok(value),
        _ => Err(AuthPrimitiveError::invalid("canonical array expected")),
    }
}

fn value_did(value: &DagValue) -> Result<&BareDid, AuthPrimitiveError> {
    match value {
        DagValue::Did(value) => Ok(value),
        _ => Err(AuthPrimitiveError::invalid("canonical DID expected")),
    }
}

fn value_uuid(value: &DagValue) -> Result<&CanonicalUuidV4, AuthPrimitiveError> {
    match value {
        DagValue::Uuid(value) => Ok(value),
        _ => Err(AuthPrimitiveError::invalid("canonical UUID expected")),
    }
}

fn value_bytes(value: &DagValue) -> Result<&[u8], AuthPrimitiveError> {
    match value {
        DagValue::Bytes(value) => Ok(value),
        _ => Err(AuthPrimitiveError::invalid("canonical bytes expected")),
    }
}

fn enforce_contract_order(
    definition_name: &str,
    object: &BTreeMap<String, DagValue>,
) -> Result<(), AuthPrimitiveError> {
    if matches!(
        definition_name,
        "creationManifest" | "resetActivationManifest"
    ) {
        enforce_did_array(object, "participants", "userDid")?;
    }
    if matches!(
        definition_name,
        "transitionManifest" | "policyTransitionBody"
    ) {
        enforce_did_array(object, "participantChanges", "userDid")?;
    }
    if definition_name == "transitionManifest" {
        let values = value_array(map_value(object, "leafChanges")?)?;
        let mut prior: Option<(&[u8], &[u8; 16])> = None;
        for value in values {
            let item = value_map(value)?;
            let did = value_did(map_value(item, "userDid")?)?.as_str().as_bytes();
            let device = value_uuid(map_value(item, "deviceId")?)?.as_bytes();
            if prior.is_some_and(|previous| {
                (previous.0, previous.1.as_slice()) >= (did, device.as_slice())
            }) {
                return Err(AuthPrimitiveError::invalid(
                    "leaf changes are not strictly ordered",
                ));
            }
            prior = Some((did, device));
        }
    }
    if matches!(
        definition_name,
        "deviceEnrollmentBody" | "keyPackageReplenishmentBody"
    ) {
        let values = value_array(map_value(object, "keyPackages")?)?;
        let mut prior: Option<&[u8]> = None;
        for value in values {
            let item = value_map(value)?;
            let key_package_ref = value_bytes(map_value(item, "keyPackageRef")?)?;
            if prior.is_some_and(|previous| previous >= key_package_ref) {
                return Err(AuthPrimitiveError::invalid(
                    "KeyPackage refs are not strictly ordered",
                ));
            }
            prior = Some(key_package_ref);
        }
    }
    Ok(())
}

fn enforce_did_array(
    object: &BTreeMap<String, DagValue>,
    array_name: &str,
    did_name: &str,
) -> Result<(), AuthPrimitiveError> {
    let values = value_array(map_value(object, array_name)?)?;
    let mut prior: Option<&[u8]> = None;
    for value in values {
        let item = value_map(value)?;
        let did = value_did(map_value(item, did_name)?)?.as_str().as_bytes();
        if prior.is_some_and(|previous| previous >= did) {
            return Err(AuthPrimitiveError::invalid(
                "DID array is not strictly ordered",
            ));
        }
        prior = Some(did);
    }
    Ok(())
}

macro_rules! signed_mutation_kinds {
    ($(($variant:ident, $body:literal, $domain:literal)),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum SignedMutationKind { $($variant),+ }

        impl SignedMutationKind {
            pub const ALL: [Self; signed_mutation_kinds!(@count $($variant),+)] = [$(Self::$variant),+];

            pub const fn type_id(self) -> &'static str {
                match self { $(Self::$variant => concat!("blue.catbird.chat.defs#", $body)),+ }
            }

            pub const fn body_name(self) -> &'static str {
                match self { $(Self::$variant => $body),+ }
            }

            pub const fn domain(self) -> &'static [u8] {
                match self { $(Self::$variant => $domain.as_bytes()),+ }
            }

            fn from_type_id(value: &str) -> Option<Self> {
                match value { $(concat!("blue.catbird.chat.defs#", $body) => Some(Self::$variant)),+, _ => None }
            }
        }
    };
    (@count $head:ident $(,$tail:ident)*) => { 1usize $(+ signed_mutation_kinds!(@one $tail))* };
    (@one $item:ident) => { 1usize };
}

signed_mutation_kinds!(
    (
        DeviceEnrollment,
        "deviceEnrollmentBody",
        "CATBIRD-CHAT-DEVICE-ENROLL\0"
    ),
    (
        KeyPackageReplenishment,
        "keyPackageReplenishmentBody",
        "CATBIRD-CHAT-DEVICE-REPLENISH\0"
    ),
    (
        DeviceAuthenticationRebind,
        "deviceAuthenticationRebindBody",
        "CATBIRD-CHAT-DEVICE-REBIND\0"
    ),
    (
        DeviceRevocation,
        "deviceRevocationBody",
        "CATBIRD-CHAT-DEVICE-REVOKE\0"
    ),
    (
        BlobUploadPreparation,
        "blobUploadPreparationBody",
        "CATBIRD-CHAT-BLOB-PREPARE\0"
    ),
    (
        BlobDeletion,
        "blobDeletionBody",
        "CATBIRD-CHAT-BLOB-DELETE\0"
    ),
    (Creation, "creationBody", "CATBIRD-CHAT-CREATE\0"),
    (
        CommitTransition,
        "commitTransitionBody",
        "CATBIRD-CHAT-COMMIT\0"
    ),
    (
        PolicyTransition,
        "policyTransitionBody",
        "CATBIRD-CHAT-POLICY\0"
    ),
    (
        ParticipantAcceptance,
        "participantAcceptanceBody",
        "CATBIRD-CHAT-ACCEPT\0"
    ),
    (
        ApplicationSend,
        "applicationSendBody",
        "CATBIRD-CHAT-MESSAGE\0"
    ),
    (Typing, "typingBody", "CATBIRD-CHAT-TYPING\0"),
    (
        MetadataTransition,
        "metadataTransitionBody",
        "CATBIRD-CHAT-METADATA\0"
    ),
    (
        ResetRequest,
        "resetRequestBody",
        "CATBIRD-CHAT-RESET-REQUEST\0"
    ),
    (
        ResetActivation,
        "resetActivationBody",
        "CATBIRD-CHAT-RESET-ACTIVATE\0"
    ),
    (
        LeafRecoveryRequest,
        "leafRecoveryRequestBody",
        "CATBIRD-CHAT-LEAF-RECOVERY-REQUEST\0"
    ),
    (
        LeafRecoveryCancellation,
        "leafRecoveryCancellationBody",
        "CATBIRD-CHAT-LEAF-RECOVERY-CANCEL\0"
    ),
    (
        LeafRecoveryFulfillment,
        "leafRecoveryFulfillmentBody",
        "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\0"
    ),
    (
        ConversationClose,
        "conversationCloseBody",
        "CATBIRD-CHAT-CLOSE\0"
    ),
    (
        LeaveRequest,
        "leaveRequestBody",
        "CATBIRD-CHAT-LEAVE-REQUEST\0"
    ),
    (
        ZeroLeafLeave,
        "zeroLeafLeaveBody",
        "CATBIRD-CHAT-LEAVE-ZERO-LEAF\0"
    ),
    (
        LeaveCancellation,
        "leaveCancellationBody",
        "CATBIRD-CHAT-LEAVE-CANCEL\0"
    ),
    (
        LeaveCommitFulfillment,
        "leaveCommitFulfillmentBody",
        "CATBIRD-CHAT-LEAVE-FULFILL-COMMIT\0"
    ),
    (
        WelcomeAcknowledgement,
        "welcomeAcknowledgementBody",
        "CATBIRD-CHAT-WELCOME-ACK\0"
    ),
    (
        WelcomeRejection,
        "welcomeRejectionBody",
        "CATBIRD-CHAT-WELCOME-REJECT\0"
    ),
);

#[derive(Debug)]
struct SigningTranscript {
    canonical_projection: Vec<u8>,
    bytes: Vec<u8>,
    request_digest: [u8; 32],
}

fn transcript_for(
    kind: SignedMutationKind,
    body: &BTreeMap<String, DagValue>,
) -> Result<SigningTranscript, AuthPrimitiveError> {
    let canonical_projection = serde_ipld_dagcbor::to_vec(&DagMapRef(body))
        .map_err(|_| AuthPrimitiveError::invalid("DAG-CBOR signing projection"))?;
    let mut bytes = Vec::with_capacity(kind.domain().len() + canonical_projection.len());
    bytes.extend_from_slice(kind.domain());
    bytes.extend_from_slice(&canonical_projection);
    let request_digest = Sha256::digest(&bytes).into();
    Ok(SigningTranscript {
        canonical_projection,
        bytes,
        request_digest,
    })
}

// `serde_ipld_dagcbor::to_vec` owns its argument. This borrowed serializable
// wrapper avoids cloning any authority-bearing canonical value.
struct DagMapRef<'a>(&'a BTreeMap<String, DagValue>);

impl Serialize for DagMapRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

/// Strictly decoded and canonically projected, but not yet Ed25519-authorized.
/// It is intentionally non-Clone and cannot be deserialized or forged.
#[derive(Debug)]
pub struct CanonicalSignedMutation {
    kind: SignedMutationKind,
    body: BTreeMap<String, DagValue>,
    signature: [u8; 64],
    transcript: SigningTranscript,
    // Present only when this authority was decoded from an exact signed-wrapper
    // byte string. A mutation reconstructed from a returned control row cannot
    // prove the original wrapper bytes and deliberately carries `None`.
    accepted_wrapper_bytes: Option<Vec<u8>>,
}

impl CanonicalSignedMutation {
    pub fn kind(&self) -> SignedMutationKind {
        self.kind
    }
    pub fn type_id(&self) -> &'static str {
        self.kind.type_id()
    }
    pub fn domain(&self) -> &'static [u8] {
        self.kind.domain()
    }
    pub fn canonical_projection(&self) -> &[u8] {
        &self.transcript.canonical_projection
    }
    pub fn transcript_bytes(&self) -> &[u8] {
        &self.transcript.bytes
    }
    pub fn request_digest(&self) -> &[u8; 32] {
        &self.transcript.request_digest
    }
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
    pub fn accepted_wrapper_bytes(&self) -> Option<&[u8]> {
        self.accepted_wrapper_bytes.as_deref()
    }
    pub fn actor_did(&self) -> &BareDid {
        body_did(&self.body, "actorDid")
    }
    pub fn actor_device_id(&self) -> &CanonicalUuidV4 {
        let field = if self.kind == SignedMutationKind::DeviceEnrollment {
            "deviceId"
        } else {
            "actorDeviceId"
        };
        body_uuid(&self.body, field)
    }
    pub fn key_id(&self) -> &KeyThumbprint {
        body_thumbprint(&self.body, "keyId")
    }
    pub fn auth_generation(&self) -> u64 {
        let field = if matches!(
            self.kind,
            SignedMutationKind::DeviceEnrollment | SignedMutationKind::DeviceAuthenticationRebind
        ) {
            "expectedAuthGeneration"
        } else {
            "authGeneration"
        };
        body_integer(&self.body, field)
    }
    pub fn signed_at(&self) -> &CanonicalTimestamp {
        body_timestamp(&self.body, "signedAt")
    }
}

fn exact_wrapper_fields(
    mut object: BTreeMap<String, RawJson>,
) -> Result<(RawJson, [u8; 64]), AuthPrimitiveError> {
    if object.len() != 2 {
        return Err(AuthPrimitiveError::invalid("signed wrapper field set"));
    }
    let body = object
        .remove("body")
        .ok_or_else(|| AuthPrimitiveError::invalid("missing signed body"))?;
    let signature = match object.remove("signature") {
        Some(RawJson::String(value)) => decode_standard_base64(&value)?,
        _ => return Err(AuthPrimitiveError::invalid("signed wrapper signature")),
    };
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| AuthPrimitiveError::invalid("Ed25519 signature length"))?;
    Ok((body, signature))
}

fn canonical_from_projected(
    body: BTreeMap<String, DagValue>,
    signature: [u8; 64],
    accepted_wrapper_bytes: Option<Vec<u8>>,
) -> Result<CanonicalSignedMutation, AuthPrimitiveError> {
    let type_id = match body.get("$type") {
        Some(DagValue::Text(value)) => value.as_str(),
        _ => return Err(AuthPrimitiveError::invalid("signed body $type")),
    };
    let kind = SignedMutationKind::from_type_id(type_id)
        .ok_or_else(|| AuthPrimitiveError::invalid("unknown signed mutation type"))?;
    match body.get("signatureDomain") {
        Some(DagValue::Text(value)) if value.as_bytes() == kind.domain() => {}
        _ => return Err(AuthPrimitiveError::invalid("signed body domain")),
    }
    let transcript = transcript_for(kind, &body)?;
    Ok(CanonicalSignedMutation {
        kind,
        body,
        signature,
        transcript,
        accepted_wrapper_bytes,
    })
}

pub fn decode_canonical_signed_mutation(
    raw_json: &[u8],
) -> Result<CanonicalSignedMutation, AuthPrimitiveError> {
    let raw = decode_raw_json(raw_json)?;
    let RawJson::Object(wrapper) = raw else {
        return Err(AuthPrimitiveError::invalid("signed wrapper must be object"));
    };
    let (body, signature) = exact_wrapper_fields(wrapper)?;
    let RawJson::Object(body_fields) = &body else {
        return Err(AuthPrimitiveError::invalid("signed body must be object"));
    };
    let type_id = match body_fields.get("$type") {
        Some(RawJson::String(value)) => value.as_str(),
        _ => return Err(AuthPrimitiveError::invalid("signed body exact $type")),
    };
    let kind = SignedMutationKind::from_type_id(type_id)
        .ok_or_else(|| AuthPrimitiveError::invalid("unknown signed body variant"))?;
    let projected = project_ref(kind.body_name(), &body, true)?;
    let DagValue::Map(body) = projected else {
        unreachable!()
    };
    canonical_from_projected(body, signature, Some(raw_json.to_vec()))
}

pub fn verify_ed25519_strict(
    public_key: &[u8],
    transcript: &[u8],
    signature: &[u8],
) -> Result<(), AuthPrimitiveError> {
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| AuthPrimitiveError::invalid("Ed25519 public key length"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| AuthPrimitiveError::invalid("invalid Ed25519 public key"))?;
    let signature = Signature::from_slice(signature)
        .map_err(|_| AuthPrimitiveError::invalid("Ed25519 signature length"))?;
    verifying_key
        .verify_strict(transcript, &signature)
        .map_err(|_| AuthPrimitiveError::invalid("invalid Ed25519 signature"))
}

/// Ed25519-verified signed mutation. Construction is possible only by strict
/// raw decode/canonical projection followed by `verify_strict`.
#[derive(Debug)]
pub struct VerifiedSignedMutation {
    canonical: CanonicalSignedMutation,
}

pub fn verify_signed_mutation(
    canonical: CanonicalSignedMutation,
    historical_public_key: &[u8],
) -> Result<VerifiedSignedMutation, AuthPrimitiveError> {
    if &ed25519_key_id(historical_public_key)? != canonical.key_id() {
        return Err(AuthPrimitiveError::invalid("signed body key ID mismatch"));
    }
    verify_ed25519_strict(
        historical_public_key,
        canonical.transcript_bytes(),
        canonical.signature(),
    )?;
    Ok(VerifiedSignedMutation { canonical })
}

pub fn decode_and_verify_signed_mutation(
    raw_json: &[u8],
    historical_public_key: &[u8],
) -> Result<VerifiedSignedMutation, AuthPrimitiveError> {
    verify_signed_mutation(
        decode_canonical_signed_mutation(raw_json)?,
        historical_public_key,
    )
}

impl VerifiedSignedMutation {
    pub fn kind(&self) -> SignedMutationKind {
        self.canonical.kind()
    }
    pub fn type_id(&self) -> &'static str {
        self.canonical.type_id()
    }
    pub fn domain(&self) -> &'static [u8] {
        self.canonical.domain()
    }
    pub fn canonical_projection(&self) -> &[u8] {
        self.canonical.canonical_projection()
    }
    pub fn transcript_bytes(&self) -> &[u8] {
        self.canonical.transcript_bytes()
    }
    pub fn request_digest(&self) -> &[u8; 32] {
        self.canonical.request_digest()
    }
    pub fn signature(&self) -> &[u8; 64] {
        self.canonical.signature()
    }
    pub fn accepted_wrapper_bytes(&self) -> Option<&[u8]> {
        self.canonical.accepted_wrapper_bytes()
    }
    pub fn actor_did(&self) -> &BareDid {
        self.canonical.actor_did()
    }
    pub fn actor_device_id(&self) -> &CanonicalUuidV4 {
        self.canonical.actor_device_id()
    }
    pub fn key_id(&self) -> &KeyThumbprint {
        self.canonical.key_id()
    }
    pub fn auth_generation(&self) -> u64 {
        self.canonical.auth_generation()
    }
    pub fn signed_at(&self) -> &CanonicalTimestamp {
        self.canonical.signed_at()
    }
    pub fn projection(&self) -> VerifiedMutationProjection<'_> {
        projection_for(self)
    }
}

fn body_did<'a>(body: &'a BTreeMap<String, DagValue>, name: &str) -> &'a BareDid {
    match body.get(name) {
        Some(DagValue::Did(value)) => value,
        _ => unreachable!("strict contract DID"),
    }
}
fn body_uuid<'a>(body: &'a BTreeMap<String, DagValue>, name: &str) -> &'a CanonicalUuidV4 {
    match body.get(name) {
        Some(DagValue::Uuid(value)) => value,
        _ => unreachable!("strict contract UUID"),
    }
}
fn body_thumbprint<'a>(body: &'a BTreeMap<String, DagValue>, name: &str) -> &'a KeyThumbprint {
    match body.get(name) {
        Some(DagValue::Thumbprint(value)) => value,
        _ => unreachable!("strict contract thumbprint"),
    }
}
fn body_timestamp<'a>(body: &'a BTreeMap<String, DagValue>, name: &str) -> &'a CanonicalTimestamp {
    match body.get(name) {
        Some(DagValue::Timestamp(value)) => value,
        _ => unreachable!("strict contract timestamp"),
    }
}
fn body_integer(body: &BTreeMap<String, DagValue>, name: &str) -> u64 {
    match body.get(name) {
        Some(DagValue::Integer(value)) => *value,
        _ => unreachable!("strict contract integer"),
    }
}
fn body_object<'a>(body: &'a BTreeMap<String, DagValue>, name: &str) -> ClosedObjectRef<'a> {
    match body.get(name) {
        Some(DagValue::Map(value)) => ClosedObjectRef(value),
        _ => unreachable!("strict contract object"),
    }
}
fn body_text<'a>(body: &'a BTreeMap<String, DagValue>, name: &str) -> &'a str {
    match body.get(name) {
        Some(DagValue::Text(value)) => value,
        _ => unreachable!("strict contract text"),
    }
}

pub struct ClosedObjectRef<'a>(&'a BTreeMap<String, DagValue>);

impl ClosedObjectRef<'_> {
    pub fn canonical_dag_cbor(&self) -> Vec<u8> {
        serde_ipld_dagcbor::to_vec(&DagMapRef(self.0)).expect("verified canonical object encodes")
    }
    pub fn get(&self, name: &str) -> Option<CanonicalValueRef<'_>> {
        self.0.get(name).map(CanonicalValueRef::from)
    }
}

pub enum CanonicalValueRef<'a> {
    Text(&'a str),
    Uuid(&'a CanonicalUuidV4),
    Did(&'a BareDid),
    Thumbprint(&'a KeyThumbprint),
    Timestamp(&'a CanonicalTimestamp),
    Bytes(&'a [u8]),
    Integer(u64),
    Bool(bool),
    Array(CanonicalArrayRef<'a>),
    Object(ClosedObjectRef<'a>),
}

impl<'a> From<&'a DagValue> for CanonicalValueRef<'a> {
    fn from(value: &'a DagValue) -> Self {
        match value {
            DagValue::Text(v) => Self::Text(v),
            DagValue::Uuid(v) => Self::Uuid(v),
            DagValue::Did(v) => Self::Did(v),
            DagValue::Thumbprint(v) => Self::Thumbprint(v),
            DagValue::Timestamp(v) => Self::Timestamp(v),
            DagValue::Bytes(v) => Self::Bytes(v),
            DagValue::Integer(v) => Self::Integer(*v),
            DagValue::Bool(v) => Self::Bool(*v),
            DagValue::Array(v) => Self::Array(CanonicalArrayRef(v)),
            DagValue::Map(v) => Self::Object(ClosedObjectRef(v)),
        }
    }
}

pub struct CanonicalArrayRef<'a>(&'a [DagValue]);
impl CanonicalArrayRef<'_> {
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn get(&self, index: usize) -> Option<CanonicalValueRef<'_>> {
        self.0.get(index).map(CanonicalValueRef::from)
    }
}

macro_rules! projection_types {
    ($(($variant:ident, $name:ident)),+ $(,)?) => {
        $(pub struct $name<'a>(&'a VerifiedSignedMutation);)+
        pub enum VerifiedMutationProjection<'a> { $($variant($name<'a>)),+ }
    };
}

projection_types!(
    (DeviceEnrollment, DeviceEnrollmentProjection),
    (KeyPackageReplenishment, KeyPackageReplenishmentProjection),
    (
        DeviceAuthenticationRebind,
        DeviceAuthenticationRebindProjection
    ),
    (DeviceRevocation, DeviceRevocationProjection),
    (BlobUploadPreparation, BlobUploadPreparationProjection),
    (BlobDeletion, BlobDeletionProjection),
    (Creation, CreationProjection),
    (CommitTransition, CommitTransitionProjection),
    (PolicyTransition, PolicyTransitionProjection),
    (ParticipantAcceptance, ParticipantAcceptanceProjection),
    (ApplicationSend, ApplicationSendProjection),
    (Typing, TypingProjection),
    (MetadataTransition, MetadataTransitionProjection),
    (ResetRequest, ResetRequestProjection),
    (ResetActivation, ResetActivationProjection),
    (LeafRecoveryRequest, LeafRecoveryRequestProjection),
    (LeafRecoveryCancellation, LeafRecoveryCancellationProjection),
    (LeafRecoveryFulfillment, LeafRecoveryFulfillmentProjection),
    (ConversationClose, ConversationCloseProjection),
    (LeaveRequest, LeaveRequestProjection),
    (ZeroLeafLeave, ZeroLeafLeaveProjection),
    (LeaveCancellation, LeaveCancellationProjection),
    (LeaveCommitFulfillment, LeaveCommitFulfillmentProjection),
    (WelcomeAcknowledgement, WelcomeAcknowledgementProjection),
    (WelcomeRejection, WelcomeRejectionProjection),
);

fn projection_for(value: &VerifiedSignedMutation) -> VerifiedMutationProjection<'_> {
    match value.kind() {
        SignedMutationKind::DeviceEnrollment => {
            VerifiedMutationProjection::DeviceEnrollment(DeviceEnrollmentProjection(value))
        }
        SignedMutationKind::KeyPackageReplenishment => {
            VerifiedMutationProjection::KeyPackageReplenishment(KeyPackageReplenishmentProjection(
                value,
            ))
        }
        SignedMutationKind::DeviceAuthenticationRebind => {
            VerifiedMutationProjection::DeviceAuthenticationRebind(
                DeviceAuthenticationRebindProjection(value),
            )
        }
        SignedMutationKind::DeviceRevocation => {
            VerifiedMutationProjection::DeviceRevocation(DeviceRevocationProjection(value))
        }
        SignedMutationKind::BlobUploadPreparation => {
            VerifiedMutationProjection::BlobUploadPreparation(BlobUploadPreparationProjection(
                value,
            ))
        }
        SignedMutationKind::BlobDeletion => {
            VerifiedMutationProjection::BlobDeletion(BlobDeletionProjection(value))
        }
        SignedMutationKind::Creation => {
            VerifiedMutationProjection::Creation(CreationProjection(value))
        }
        SignedMutationKind::CommitTransition => {
            VerifiedMutationProjection::CommitTransition(CommitTransitionProjection(value))
        }
        SignedMutationKind::PolicyTransition => {
            VerifiedMutationProjection::PolicyTransition(PolicyTransitionProjection(value))
        }
        SignedMutationKind::ParticipantAcceptance => {
            VerifiedMutationProjection::ParticipantAcceptance(ParticipantAcceptanceProjection(
                value,
            ))
        }
        SignedMutationKind::ApplicationSend => {
            VerifiedMutationProjection::ApplicationSend(ApplicationSendProjection(value))
        }
        SignedMutationKind::Typing => VerifiedMutationProjection::Typing(TypingProjection(value)),
        SignedMutationKind::MetadataTransition => {
            VerifiedMutationProjection::MetadataTransition(MetadataTransitionProjection(value))
        }
        SignedMutationKind::ResetRequest => {
            VerifiedMutationProjection::ResetRequest(ResetRequestProjection(value))
        }
        SignedMutationKind::ResetActivation => {
            VerifiedMutationProjection::ResetActivation(ResetActivationProjection(value))
        }
        SignedMutationKind::LeafRecoveryRequest => {
            VerifiedMutationProjection::LeafRecoveryRequest(LeafRecoveryRequestProjection(value))
        }
        SignedMutationKind::LeafRecoveryCancellation => {
            VerifiedMutationProjection::LeafRecoveryCancellation(
                LeafRecoveryCancellationProjection(value),
            )
        }
        SignedMutationKind::LeafRecoveryFulfillment => {
            VerifiedMutationProjection::LeafRecoveryFulfillment(LeafRecoveryFulfillmentProjection(
                value,
            ))
        }
        SignedMutationKind::ConversationClose => {
            VerifiedMutationProjection::ConversationClose(ConversationCloseProjection(value))
        }
        SignedMutationKind::LeaveRequest => {
            VerifiedMutationProjection::LeaveRequest(LeaveRequestProjection(value))
        }
        SignedMutationKind::ZeroLeafLeave => {
            VerifiedMutationProjection::ZeroLeafLeave(ZeroLeafLeaveProjection(value))
        }
        SignedMutationKind::LeaveCancellation => {
            VerifiedMutationProjection::LeaveCancellation(LeaveCancellationProjection(value))
        }
        SignedMutationKind::LeaveCommitFulfillment => {
            VerifiedMutationProjection::LeaveCommitFulfillment(LeaveCommitFulfillmentProjection(
                value,
            ))
        }
        SignedMutationKind::WelcomeAcknowledgement => {
            VerifiedMutationProjection::WelcomeAcknowledgement(WelcomeAcknowledgementProjection(
                value,
            ))
        }
        SignedMutationKind::WelcomeRejection => {
            VerifiedMutationProjection::WelcomeRejection(WelcomeRejectionProjection(value))
        }
    }
}

macro_rules! projection_body {
    ($($name:ident),+ $(,)?) => {$(
        impl<'a> $name<'a> {
            pub fn body(&self) -> ClosedObjectRef<'a> { ClosedObjectRef(&self.0.canonical.body) }
        }
    )+};
}
projection_body!(
    DeviceEnrollmentProjection,
    KeyPackageReplenishmentProjection,
    DeviceAuthenticationRebindProjection,
    DeviceRevocationProjection,
    BlobUploadPreparationProjection,
    BlobDeletionProjection,
    CreationProjection,
    CommitTransitionProjection,
    PolicyTransitionProjection,
    ParticipantAcceptanceProjection,
    ApplicationSendProjection,
    TypingProjection,
    MetadataTransitionProjection,
    ResetRequestProjection,
    ResetActivationProjection,
    LeafRecoveryRequestProjection,
    LeafRecoveryCancellationProjection,
    LeafRecoveryFulfillmentProjection,
    ConversationCloseProjection,
    LeaveRequestProjection,
    ZeroLeafLeaveProjection,
    LeaveCancellationProjection,
    LeaveCommitFulfillmentProjection,
    WelcomeAcknowledgementProjection,
    WelcomeRejectionProjection
);

macro_rules! transition_projection {
    ($name:ident, $id:literal) => {
        impl<'a> $name<'a> {
            pub fn transition_id(&self) -> &'a CanonicalUuidV4 {
                body_uuid(&self.0.canonical.body, $id)
            }
            pub fn prior(&self) -> ClosedObjectRef<'a> {
                body_object(&self.0.canonical.body, "prior")
            }
            pub fn next(&self) -> ClosedObjectRef<'a> {
                body_object(&self.0.canonical.body, "next")
            }
        }
    };
}
transition_projection!(CommitTransitionProjection, "transitionId");
transition_projection!(PolicyTransitionProjection, "transitionId");
transition_projection!(ParticipantAcceptanceProjection, "transitionId");
transition_projection!(MetadataTransitionProjection, "transitionId");
transition_projection!(LeafRecoveryFulfillmentProjection, "transitionId");
transition_projection!(ZeroLeafLeaveProjection, "transitionId");
transition_projection!(LeaveCommitFulfillmentProjection, "transitionId");

impl<'a> CreationProjection<'a> {
    pub fn conversation_id(&self) -> &'a CanonicalUuidV4 {
        body_uuid(&self.0.canonical.body, "conversationId")
    }
    pub fn transition_id(&self) -> &'a CanonicalUuidV4 {
        body_uuid(&self.0.canonical.body, "transitionId")
    }
    pub fn conversation_kind(&self) -> &'a str {
        body_text(&self.0.canonical.body, "conversationKind")
    }
    pub fn next(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "next")
    }
    pub fn manifest(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "manifest")
    }
    pub fn genesis_group_info(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "genesisGroupInfo")
    }
    pub fn metadata_snapshot(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "metadataSnapshot")
    }
}
impl<'a> CommitTransitionProjection<'a> {
    pub fn aad(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "aad")
    }
    pub fn manifest(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "manifest")
    }
    pub fn commit(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "commit")
    }
    pub fn metadata_snapshot(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "metadataSnapshot")
    }
}
impl<'a> PolicyTransitionProjection<'a> {
    pub fn participant_changes(&self) -> CanonicalValueRef<'a> {
        CanonicalValueRef::from(self.0.canonical.body.get("participantChanges").unwrap())
    }
}
impl<'a> ParticipantAcceptanceProjection<'a> {
    pub fn recovery_request_id(&self) -> &'a CanonicalUuidV4 {
        body_uuid(&self.0.canonical.body, "recoveryRequestId")
    }
    pub fn invitation_provenance(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "invitationProvenance")
    }
}
impl<'a> MetadataTransitionProjection<'a> {
    pub fn metadata_snapshot(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "metadataSnapshot")
    }
}
impl<'a> ResetRequestProjection<'a> {
    pub fn reset_request_id(&self) -> &'a CanonicalUuidV4 {
        body_uuid(&self.0.canonical.body, "resetRequestId")
    }
    pub fn prior(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "prior")
    }
    pub fn reason(&self) -> &'a str {
        body_text(&self.0.canonical.body, "reason")
    }
}
impl<'a> ResetActivationProjection<'a> {
    pub fn reset_request_id(&self) -> &'a CanonicalUuidV4 {
        body_uuid(&self.0.canonical.body, "resetRequestId")
    }
    pub fn transition_id(&self) -> &'a CanonicalUuidV4 {
        body_uuid(&self.0.canonical.body, "transitionId")
    }
    pub fn conversation_kind(&self) -> &'a str {
        body_text(&self.0.canonical.body, "conversationKind")
    }
    pub fn prior(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "prior")
    }
    pub fn retired(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "retired")
    }
    pub fn successor(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "successor")
    }
    pub fn manifest(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "manifest")
    }
    pub fn genesis_group_info(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "genesisGroupInfo")
    }
    pub fn metadata_snapshot(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "metadataSnapshot")
    }
}
impl<'a> LeafRecoveryRequestProjection<'a> {
    pub fn recovery_request_id(&self) -> &'a CanonicalUuidV4 {
        body_uuid(&self.0.canonical.body, "recoveryRequestId")
    }
    pub fn prior(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "prior")
    }
    pub fn recovery_kind(&self) -> &'a str {
        body_text(&self.0.canonical.body, "recoveryKind")
    }
}
impl<'a> LeafRecoveryCancellationProjection<'a> {
    pub fn recovery_request_id(&self) -> &'a CanonicalUuidV4 {
        body_uuid(&self.0.canonical.body, "recoveryRequestId")
    }
}
impl<'a> LeafRecoveryFulfillmentProjection<'a> {
    pub fn recovery_request_id(&self) -> &'a CanonicalUuidV4 {
        body_uuid(&self.0.canonical.body, "recoveryRequestId")
    }
    pub fn aad(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "aad")
    }
    pub fn manifest(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "manifest")
    }
    pub fn commit(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "commit")
    }
    pub fn metadata_snapshot(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "metadataSnapshot")
    }
}
impl<'a> ConversationCloseProjection<'a> {
    pub fn transition_id(&self) -> &'a CanonicalUuidV4 {
        body_uuid(&self.0.canonical.body, "transitionId")
    }
    pub fn conversation_kind(&self) -> &'a str {
        body_text(&self.0.canonical.body, "conversationKind")
    }
    pub fn prior(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "prior")
    }
    pub fn retired(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "retired")
    }
}
impl<'a> LeaveRequestProjection<'a> {
    pub fn leave_request_id(&self) -> &'a CanonicalUuidV4 {
        body_uuid(&self.0.canonical.body, "leaveRequestId")
    }
    pub fn prior(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "prior")
    }
}
impl<'a> LeaveCancellationProjection<'a> {
    pub fn conversation_id(&self) -> &'a CanonicalUuidV4 {
        body_uuid(&self.0.canonical.body, "conversationId")
    }
    pub fn leave_request_id(&self) -> &'a CanonicalUuidV4 {
        body_uuid(&self.0.canonical.body, "leaveRequestId")
    }
}
impl<'a> LeaveCommitFulfillmentProjection<'a> {
    pub fn leave_request_id(&self) -> &'a CanonicalUuidV4 {
        body_uuid(&self.0.canonical.body, "leaveRequestId")
    }
    pub fn aad(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "aad")
    }
    pub fn manifest(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "manifest")
    }
    pub fn commit(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "commit")
    }
    pub fn metadata_snapshot(&self) -> ClosedObjectRef<'a> {
        body_object(&self.0.canonical.body, "metadataSnapshot")
    }
}

/// Enrollment evidence issued only after strict contract decode, exact key-ID
/// derivation/signing-key digest, and Ed25519 verification under the immutable
/// public key carried by the body. Freshness is deliberately deferred until
/// repository arbitration has ruled out exact completed digest/signature replay.
#[derive(Debug)]
pub struct VerifiedEnrollmentBody {
    verified: VerifiedSignedMutation,
    signing_key_sha256: [u8; 32],
}

pub fn decode_and_verify_enrollment_body(
    raw_json: &[u8],
) -> Result<VerifiedEnrollmentBody, AuthPrimitiveError> {
    let canonical = decode_canonical_signed_mutation(raw_json)?;
    if canonical.kind() != SignedMutationKind::DeviceEnrollment {
        return Err(AuthPrimitiveError::invalid("enrollment body type"));
    }
    let public_key: [u8; 32] = value_bytes(map_value(&canonical.body, "signaturePublicKey")?)?
        .try_into()
        .map_err(|_| AuthPrimitiveError::invalid("enrollment signing key length"))?;
    if &ed25519_key_id(&public_key)? != canonical.key_id() {
        return Err(AuthPrimitiveError::invalid("enrollment key ID mismatch"));
    }
    let signing_key_sha256 = Sha256::digest(public_key).into();
    let verified = verify_signed_mutation(canonical, &public_key)?;
    Ok(VerifiedEnrollmentBody {
        verified,
        signing_key_sha256,
    })
}

impl VerifiedEnrollmentBody {
    pub fn mutation(&self) -> &VerifiedSignedMutation {
        &self.verified
    }
    pub fn subject(&self) -> &BareDid {
        self.verified.actor_did()
    }
    pub fn device_id(&self) -> &CanonicalUuidV4 {
        self.verified.actor_device_id()
    }
    pub fn dpop_jkt(&self) -> &KeyThumbprint {
        body_thumbprint(&self.verified.canonical.body, "dpopJkt")
    }
    pub fn key_id(&self) -> &KeyThumbprint {
        self.verified.key_id()
    }
    pub fn signing_key_sha256(&self) -> &[u8; 32] {
        &self.signing_key_sha256
    }
    pub fn enrollment_transcript_sha256(&self) -> &[u8; 32] {
        self.verified.request_digest()
    }
    pub fn request_digest(&self) -> &[u8; 32] {
        self.verified.request_digest()
    }
    pub fn signature(&self) -> &[u8; 64] {
        self.verified.signature()
    }
    pub fn signed_at(&self) -> &CanonicalTimestamp {
        self.verified.signed_at()
    }
    pub fn idempotency_key(&self) -> &CanonicalUuidV4 {
        body_uuid(&self.verified.canonical.body, "idempotencyKey")
    }
    pub fn accepted_wrapper_bytes(&self) -> &[u8] {
        self.verified
            .accepted_wrapper_bytes()
            .expect("enrollment evidence is decoded from an exact signed wrapper")
    }
}

/// Strictly decoded rebind bootstrap. Its body signature is retained but not
/// elevated to final authority: the repository must resolve the immutable
/// stored Ed25519 key and current JKT/generation, verify, and CAS atomically.
#[derive(Debug)]
pub struct CanonicalRebindBootstrap {
    canonical: CanonicalSignedMutation,
}

pub fn decode_rebind_bootstrap(
    raw_json: &[u8],
) -> Result<CanonicalRebindBootstrap, AuthPrimitiveError> {
    let canonical = decode_canonical_signed_mutation(raw_json)?;
    if canonical.kind() != SignedMutationKind::DeviceAuthenticationRebind {
        return Err(AuthPrimitiveError::invalid("rebind body type"));
    }
    Ok(CanonicalRebindBootstrap { canonical })
}

impl CanonicalRebindBootstrap {
    pub fn subject(&self) -> &BareDid {
        self.canonical.actor_did()
    }
    pub fn device_id(&self) -> &CanonicalUuidV4 {
        self.canonical.actor_device_id()
    }
    pub fn key_id(&self) -> &KeyThumbprint {
        self.canonical.key_id()
    }
    pub fn expected_auth_generation(&self) -> u64 {
        self.canonical.auth_generation()
    }
    pub fn current_dpop_jkt(&self) -> &KeyThumbprint {
        body_thumbprint(&self.canonical.body, "currentDpopJkt")
    }
    pub fn new_dpop_jkt(&self) -> &KeyThumbprint {
        body_thumbprint(&self.canonical.body, "newDpopJkt")
    }
    pub fn signed_at(&self) -> &CanonicalTimestamp {
        self.canonical.signed_at()
    }
    pub fn idempotency_key(&self) -> &CanonicalUuidV4 {
        body_uuid(&self.canonical.body, "idempotencyKey")
    }
    pub fn accepted_wrapper_bytes(&self) -> &[u8] {
        self.canonical
            .accepted_wrapper_bytes()
            .expect("rebind bootstrap is decoded from an exact signed wrapper")
    }
    pub fn request_digest(&self) -> &[u8; 32] {
        self.canonical.request_digest()
    }
    pub fn signature(&self) -> &[u8; 64] {
        self.canonical.signature()
    }
    pub fn verify_signature_with_stored_key(
        &self,
        stored_public_key: &[u8],
    ) -> Result<(), AuthPrimitiveError> {
        if &ed25519_key_id(stored_public_key)? != self.canonical.key_id() {
            return Err(AuthPrimitiveError::invalid("rebind key ID mismatch"));
        }
        verify_ed25519_strict(
            stored_public_key,
            self.canonical.transcript_bytes(),
            self.canonical.signature(),
        )
    }
    pub fn verify_with_stored_key(
        self,
        stored_public_key: &[u8],
    ) -> Result<VerifiedSignedMutation, AuthPrimitiveError> {
        verify_signed_mutation(self.canonical, stored_public_key)
    }
}

/// Repository-private authority for one exact, closed
/// `blue.catbird.chat.defs#applicationEntry`.
///
/// This type is intentionally non-Clone and has no raw-field constructor. Its
/// two entry paths either consume an already Ed25519-verified application-send
/// mutation plus repository row identity, or strictly decode exact canonical
/// bytes and re-verify the historical signature.
#[derive(Debug)]
pub(crate) struct VerifiedApplicationEntry {
    entry_id: CanonicalUuidV4,
    conversation_id: CanonicalUuidV4,
    seq: u64,
    received_at: CanonicalTimestamp,
    canonical_entry_bytes: Vec<u8>,
    accepted_payload_sha256: [u8; 32],
    outer_application_projection: Vec<u8>,
    outer_application_fingerprint: [u8; 32],
    mutation: VerifiedSignedMutation,
}

/// Seal a fresh append row. Raw JSON, generated DTOs, unsigned projections,
/// caller-selected digests, and caller-selected fingerprints are not inputs.
pub(crate) fn build_verified_application_entry(
    mutation: VerifiedSignedMutation,
    entry_id: CanonicalUuidV4,
    conversation_id: CanonicalUuidV4,
    seq: u64,
    received_at: &TrustedRequestInstant,
) -> Result<VerifiedApplicationEntry, AuthPrimitiveError> {
    if mutation.kind() != SignedMutationKind::ApplicationSend {
        return Err(AuthPrimitiveError::invalid(
            "mutation is not an application send",
        ));
    }
    if mutation.accepted_wrapper_bytes().is_none() {
        return Err(AuthPrimitiveError::invalid(
            "fresh application send lacks exact accepted wrapper bytes",
        ));
    }
    finish_verified_application_entry(
        entry_id,
        conversation_id,
        seq,
        received_at.as_canonical().clone(),
        mutation,
    )
}

/// Strictly decode the exact bytes-based DAG-CBOR public row and verify its
/// embedded historical send signature before returning any fingerprint or
/// application authority. JSON and signature-wrapper reserialization are not
/// accepted at this boundary.
pub(crate) fn decode_and_verify_application_entry(
    canonical_entry_bytes: &[u8],
    historical_public_key: &[u8],
) -> Result<VerifiedApplicationEntry, AuthPrimitiveError> {
    let raw = decode_canonical_raw_cbor(canonical_entry_bytes)?;
    let json_projection = cbor_ref_to_raw_json("applicationEntry", &raw, false)?;
    let projected = project_ref("applicationEntry", &json_projection, false)?;
    let DagValue::Map(mut row) = projected else {
        unreachable!("applicationEntry is an object in the embedded contract")
    };

    let entry_id = take_uuid(&mut row, "entryId")?;
    let conversation_id = take_uuid(&mut row, "conversationId")?;
    let seq = take_integer(&mut row, "seq")?;
    let received_at = take_timestamp(&mut row, "receivedAt")?;
    let mut signed = match row.remove("signedRequest") {
        Some(DagValue::Map(value)) => value,
        _ => return Err(AuthPrimitiveError::invalid("application signedRequest")),
    };
    if !row.is_empty() {
        return Err(AuthPrimitiveError::invalid("extra application row fields"));
    }
    let body = match signed.remove("body") {
        Some(DagValue::Map(value)) => value,
        _ => return Err(AuthPrimitiveError::invalid("application signed body")),
    };
    let signature: [u8; 64] = match signed.remove("signature") {
        Some(DagValue::Bytes(value)) => value
            .try_into()
            .map_err(|_| AuthPrimitiveError::invalid("application signature length"))?,
        _ => return Err(AuthPrimitiveError::invalid("application signature")),
    };
    if !signed.is_empty() {
        return Err(AuthPrimitiveError::invalid(
            "application signed wrapper fields",
        ));
    }
    let canonical = canonical_from_projected(body, signature, None)?;
    if canonical.kind() != SignedMutationKind::ApplicationSend {
        return Err(AuthPrimitiveError::invalid(
            "application row/signed variant mismatch",
        ));
    }
    if signed_body_conversation_id(&canonical)? != &conversation_id {
        return Err(AuthPrimitiveError::invalid(
            "application row/body conversation mismatch",
        ));
    }
    let mutation = verify_signed_mutation(canonical, historical_public_key)?;
    let entry =
        finish_verified_application_entry(entry_id, conversation_id, seq, received_at, mutation)?;
    if entry.canonical_entry_bytes != canonical_entry_bytes {
        return Err(AuthPrimitiveError::invalid(
            "application entry canonical byte mismatch",
        ));
    }
    Ok(entry)
}

/// Re-enter a persisted application row only after every independently stored
/// crypto column agrees with the exact public-row bytes and a separately
/// retained signed wrapper verifies under the historical device key.
#[allow(clippy::too_many_arguments)]
pub(crate) fn rebind_persisted_application_entry(
    entry: VerifiedApplicationEntry,
    accepted_payload_bytes: &[u8],
    accepted_payload_sha256: &[u8; 32],
    raw_signed_wrapper: &[u8],
    persisted_request_digest: &[u8; 32],
    persisted_signature: &[u8; 64],
    persisted_outer_fingerprint: &[u8; 32],
    historical_public_key: &[u8],
) -> Result<VerifiedApplicationEntry, AuthPrimitiveError> {
    let payload_sha256: [u8; 32] = Sha256::digest(accepted_payload_bytes).into();
    if accepted_payload_bytes != entry.canonical_entry_bytes
        || accepted_payload_sha256 != &payload_sha256
        || accepted_payload_sha256 != &entry.accepted_payload_sha256
        || persisted_request_digest != entry.mutation.request_digest()
        || persisted_signature != entry.mutation.signature()
        || persisted_outer_fingerprint != &entry.outer_application_fingerprint
    {
        return Err(AuthPrimitiveError::invalid(
            "persisted application crypto-column mismatch",
        ));
    }

    let mutation = decode_and_verify_signed_mutation(raw_signed_wrapper, historical_public_key)?;
    let original = entry.mutation();
    if mutation.kind() != SignedMutationKind::ApplicationSend
        || mutation.kind() != original.kind()
        || mutation.type_id() != original.type_id()
        || mutation.domain() != original.domain()
        || mutation.canonical_projection() != original.canonical_projection()
        || mutation.transcript_bytes() != original.transcript_bytes()
        || mutation.request_digest() != original.request_digest()
        || mutation.signature() != original.signature()
        || mutation.actor_did() != original.actor_did()
        || mutation.actor_device_id() != original.actor_device_id()
        || mutation.key_id() != original.key_id()
        || mutation.auth_generation() != original.auth_generation()
        || mutation.signed_at() != original.signed_at()
        || mutation.accepted_wrapper_bytes() != Some(raw_signed_wrapper)
    {
        return Err(AuthPrimitiveError::invalid(
            "persisted application signed-wrapper splice",
        ));
    }

    let original_entry_bytes = entry.canonical_entry_bytes.clone();
    let original_payload_sha256 = entry.accepted_payload_sha256;
    let original_outer_projection = entry.outer_application_projection.clone();
    let original_outer_fingerprint = entry.outer_application_fingerprint;
    let rebuilt = finish_verified_application_entry(
        entry.entry_id,
        entry.conversation_id,
        entry.seq,
        entry.received_at,
        mutation,
    )?;
    if rebuilt.canonical_entry_bytes != original_entry_bytes
        || rebuilt.accepted_payload_sha256 != original_payload_sha256
        || rebuilt.outer_application_projection != original_outer_projection
        || rebuilt.outer_application_fingerprint != original_outer_fingerprint
    {
        return Err(AuthPrimitiveError::invalid(
            "persisted application outer-row splice",
        ));
    }
    Ok(rebuilt)
}

fn finish_verified_application_entry(
    entry_id: CanonicalUuidV4,
    conversation_id: CanonicalUuidV4,
    seq: u64,
    received_at: CanonicalTimestamp,
    mutation: VerifiedSignedMutation,
) -> Result<VerifiedApplicationEntry, AuthPrimitiveError> {
    if !(1..=MAX_SAFE_INTEGER as u64).contains(&seq) {
        return Err(AuthPrimitiveError::invalid("application seq"));
    }
    if mutation.kind() != SignedMutationKind::ApplicationSend {
        return Err(AuthPrimitiveError::invalid(
            "application row/signed variant mismatch",
        ));
    }
    if signed_body_conversation_id(&mutation.canonical)? != &conversation_id {
        return Err(AuthPrimitiveError::invalid(
            "application row/body conversation mismatch",
        ));
    }

    let signed_request = BTreeMap::from([
        (
            "body".to_owned(),
            DagValue::Map(mutation.canonical.body.clone()),
        ),
        (
            "signature".to_owned(),
            DagValue::Bytes(mutation.signature().to_vec()),
        ),
    ]);
    let row = BTreeMap::from([
        ("entryId".to_owned(), DagValue::Uuid(entry_id.clone())),
        (
            "conversationId".to_owned(),
            DagValue::Uuid(conversation_id.clone()),
        ),
        ("seq".to_owned(), DagValue::Integer(seq)),
        ("signedRequest".to_owned(), DagValue::Map(signed_request)),
        (
            "receivedAt".to_owned(),
            DagValue::Timestamp(received_at.clone()),
        ),
    ]);
    let canonical_entry_bytes = serde_ipld_dagcbor::to_vec(&DagMapRef(&row))
        .map_err(|_| AuthPrimitiveError::invalid("application entry DAG-CBOR"))?;
    let accepted_payload_sha256 = Sha256::digest(&canonical_entry_bytes).into();

    let fingerprint_projection = BTreeMap::from([
        ("entryId".to_owned(), DagValue::Uuid(entry_id.clone())),
        (
            "conversationId".to_owned(),
            DagValue::Uuid(conversation_id.clone()),
        ),
        ("seq".to_owned(), DagValue::Integer(seq)),
        (
            "requestDigest".to_owned(),
            DagValue::Bytes(mutation.request_digest().to_vec()),
        ),
        (
            "signature".to_owned(),
            DagValue::Bytes(mutation.signature().to_vec()),
        ),
        (
            "receivedAt".to_owned(),
            DagValue::Timestamp(received_at.clone()),
        ),
    ]);
    let outer_application_projection =
        serde_ipld_dagcbor::to_vec(&DagMapRef(&fingerprint_projection)).map_err(|_| {
            AuthPrimitiveError::invalid("application fingerprint projection DAG-CBOR")
        })?;
    let mut digest = Sha256::new();
    digest.update(APPLICATION_FINGERPRINT_DOMAIN);
    digest.update(&outer_application_projection);
    let outer_application_fingerprint = digest.finalize().into();

    Ok(VerifiedApplicationEntry {
        entry_id,
        conversation_id,
        seq,
        received_at,
        canonical_entry_bytes,
        accepted_payload_sha256,
        outer_application_projection,
        outer_application_fingerprint,
        mutation,
    })
}

impl VerifiedApplicationEntry {
    pub(crate) fn entry_id(&self) -> &CanonicalUuidV4 {
        &self.entry_id
    }

    pub(crate) fn conversation_id(&self) -> &CanonicalUuidV4 {
        &self.conversation_id
    }

    pub(crate) fn seq(&self) -> u64 {
        self.seq
    }

    pub(crate) fn received_at(&self) -> &CanonicalTimestamp {
        &self.received_at
    }

    pub(crate) fn canonical_entry_bytes(&self) -> &[u8] {
        &self.canonical_entry_bytes
    }

    pub(crate) fn accepted_payload_sha256(&self) -> &[u8; 32] {
        &self.accepted_payload_sha256
    }

    pub(crate) fn outer_application_projection(&self) -> &[u8] {
        &self.outer_application_projection
    }

    pub(crate) fn outer_application_fingerprint(&self) -> &[u8; 32] {
        &self.outer_application_fingerprint
    }

    pub(crate) fn mutation(&self) -> &VerifiedSignedMutation {
        &self.mutation
    }
}

macro_rules! control_entry_kinds {
    ($(($variant:ident, $entry:literal, $signed:ident, $server:expr)),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum ControlEntryKind { $($variant),+ }
        impl ControlEntryKind {
            pub const ALL: [Self; control_entry_kinds!(@count $($variant),+)] = [$(Self::$variant),+];
            pub const fn type_id(self) -> &'static str { match self { $(Self::$variant => concat!("blue.catbird.chat.defs#", $entry)),+ } }
            pub const fn signed_kind(self) -> SignedMutationKind { match self { $(Self::$variant => SignedMutationKind::$signed),+ } }
            const fn server_field(self) -> Option<&'static str> { match self { $(Self::$variant => $server),+ } }
            fn from_type_id(value: &str) -> Option<Self> { match value { $(concat!("blue.catbird.chat.defs#", $entry) => Some(Self::$variant)),+, _ => None } }
            fn from_signed_kind(value: SignedMutationKind) -> Option<Self> {
                Self::ALL.into_iter().find(|kind| kind.signed_kind() == value)
            }
        }
    };
    (@count $head:ident $(,$tail:ident)*) => { 1usize $(+ control_entry_kinds!(@one $tail))* };
    (@one $item:ident) => { 1usize };
}

control_entry_kinds!(
    (Commit, "commitEntry", CommitTransition, None),
    (Policy, "policyEntry", PolicyTransition, None),
    (Metadata, "metadataEntry", MetadataTransition, None),
    (Creation, "creationEntry", Creation, None),
    (
        ParticipantAcceptance,
        "participantAcceptanceEntry",
        ParticipantAcceptance,
        Some("recovery")
    ),
    (
        ConversationClose,
        "conversationCloseEntry",
        ConversationClose,
        Some("tombstone")
    ),
    (ResetRequest, "resetRequestEntry", ResetRequest, None),
    (
        ResetActivation,
        "resetActivationEntry",
        ResetActivation,
        None
    ),
    (
        LeafRecoveryFulfillment,
        "leafRecoveryFulfillmentEntry",
        LeafRecoveryFulfillment,
        None
    ),
    (LeaveRequest, "leaveRequestEntry", LeaveRequest, None),
    (ZeroLeafLeave, "zeroLeafLeaveEntry", ZeroLeafLeave, None),
    (
        LeaveCancellation,
        "leaveCancellationEntry",
        LeaveCancellation,
        None
    ),
    (
        LeaveCommitFulfillment,
        "leaveCommitFulfillmentEntry",
        LeaveCommitFulfillment,
        None
    ),
);

impl ControlEntryKind {
    fn endpoint(self) -> &'static str {
        match self {
            Self::Creation => "blue.catbird.chat.createConversation",
            Self::ParticipantAcceptance => "blue.catbird.chat.acceptConversation",
            Self::ConversationClose => "blue.catbird.chat.closeConversation",
            Self::ResetRequest => "blue.catbird.chat.requestReset",
            Self::ResetActivation => "blue.catbird.chat.activateReset",
            Self::LeaveRequest => "blue.catbird.chat.requestLeave",
            Self::LeaveCancellation => "blue.catbird.chat.cancelLeave",
            Self::Commit
            | Self::Policy
            | Self::Metadata
            | Self::LeafRecoveryFulfillment
            | Self::ZeroLeafLeave
            | Self::LeaveCommitFulfillment => "blue.catbird.chat.submitTransition",
        }
    }
}

/// Exact, closed server-authored fields for one control entry kind. The type
/// is non-Clone and its map is private, so callers cannot splice unvalidated
/// fields into a fingerprint.
#[derive(Debug)]
pub struct CanonicalControlServerFields {
    kind: ControlEntryKind,
    fields: BTreeMap<String, DagValue>,
}

impl CanonicalControlServerFields {
    pub fn empty(kind: ControlEntryKind) -> Result<Self, AuthPrimitiveError> {
        if kind.server_field().is_some() {
            return Err(AuthPrimitiveError::invalid(
                "special control entry requires exact serverFields",
            ));
        }
        Ok(Self {
            kind,
            fields: BTreeMap::new(),
        })
    }

    /// Strictly closes only the server-authored `serverFields` object. This
    /// never accepts or reparses a signed request wrapper.
    pub fn decode(
        kind: ControlEntryKind,
        raw_server_fields_json: &[u8],
    ) -> Result<Self, AuthPrimitiveError> {
        let raw = decode_raw_json(raw_server_fields_json)?;
        let fields = project_server_fields(kind, &raw)?;
        Ok(Self { kind, fields })
    }

    pub fn canonical_dag_cbor(&self) -> Vec<u8> {
        serde_ipld_dagcbor::to_vec(&DagMapRef(&self.fields))
            .expect("closed serverFields always encode")
    }
}

#[derive(Debug)]
pub struct CanonicalControlFingerprint {
    kind: ControlEntryKind,
    canonical_projection: Vec<u8>,
    fingerprint: [u8; 32],
}

impl CanonicalControlFingerprint {
    pub fn kind(&self) -> ControlEntryKind {
        self.kind
    }
    pub fn canonical_projection(&self) -> &[u8] {
        &self.canonical_projection
    }
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
}

fn decode_control_projection_object(
    mut object: BTreeMap<String, RawJson>,
) -> Result<(ControlEntryKind, BTreeMap<String, DagValue>), AuthPrimitiveError> {
    const FIELDS: [&str; 8] = [
        "entryKind",
        "entryId",
        "conversationId",
        "seq",
        "requestDigest",
        "signature",
        "serverFields",
        "receivedAt",
    ];
    if object.len() != FIELDS.len() || FIELDS.iter().any(|field| !object.contains_key(*field)) {
        return Err(AuthPrimitiveError::invalid("control fingerprint field set"));
    }
    let entry_kind_text = match object.remove("entryKind") {
        Some(RawJson::String(value)) => value,
        _ => return Err(AuthPrimitiveError::invalid("control entry kind")),
    };
    let kind = ControlEntryKind::from_type_id(&entry_kind_text)
        .ok_or_else(|| AuthPrimitiveError::invalid("unknown control entry kind"))?;
    let entry_id = match object.remove("entryId") {
        Some(RawJson::String(value)) => CanonicalUuidV4::parse(&value)?,
        _ => return Err(AuthPrimitiveError::invalid("control entry ID")),
    };
    let conversation_id = match object.remove("conversationId") {
        Some(RawJson::String(value)) => CanonicalUuidV4::parse(&value)?,
        _ => return Err(AuthPrimitiveError::invalid("control conversation ID")),
    };
    let seq = match object.remove("seq") {
        Some(RawJson::Integer(value)) if (1..=MAX_SAFE_INTEGER as u64).contains(&value) => value,
        _ => return Err(AuthPrimitiveError::invalid("control seq")),
    };
    let request_digest = fixed_standard_bytes(object.remove("requestDigest"), 32)?;
    let signature = fixed_standard_bytes(object.remove("signature"), 64)?;
    let received_at = match object.remove("receivedAt") {
        Some(RawJson::String(value)) => CanonicalTimestamp::parse(&value)?,
        _ => return Err(AuthPrimitiveError::invalid("control receivedAt")),
    };
    let server_fields_raw = object.remove("serverFields").unwrap();
    let server_fields = project_server_fields(kind, &server_fields_raw)?;
    let mut projection = BTreeMap::new();
    projection.insert("entryKind".into(), DagValue::Text(entry_kind_text));
    projection.insert("entryId".into(), DagValue::Uuid(entry_id));
    projection.insert("conversationId".into(), DagValue::Uuid(conversation_id));
    projection.insert("seq".into(), DagValue::Integer(seq));
    projection.insert("requestDigest".into(), DagValue::Bytes(request_digest));
    projection.insert("signature".into(), DagValue::Bytes(signature));
    projection.insert("serverFields".into(), DagValue::Map(server_fields));
    projection.insert("receivedAt".into(), DagValue::Timestamp(received_at));
    Ok((kind, projection))
}

fn fixed_standard_bytes(
    raw: Option<RawJson>,
    length: usize,
) -> Result<Vec<u8>, AuthPrimitiveError> {
    let RawJson::String(value) =
        raw.ok_or_else(|| AuthPrimitiveError::invalid("missing bytes field"))?
    else {
        return Err(AuthPrimitiveError::invalid("bytes field type"));
    };
    let decoded = decode_standard_base64(&value)?;
    if decoded.len() != length {
        return Err(AuthPrimitiveError::invalid("fixed bytes length"));
    }
    Ok(decoded)
}

fn project_server_fields(
    kind: ControlEntryKind,
    raw: &RawJson,
) -> Result<BTreeMap<String, DagValue>, AuthPrimitiveError> {
    let RawJson::Object(values) = raw else {
        return Err(AuthPrimitiveError::invalid("serverFields object"));
    };
    match kind.server_field() {
        None if values.is_empty() => Ok(BTreeMap::new()),
        None => Err(AuthPrimitiveError::invalid(
            "ordinary control serverFields must be empty",
        )),
        Some(field) if values.len() == 1 && values.contains_key(field) => {
            let definition_name = if field == "recovery" {
                "leafRecoveryView"
            } else {
                "conversationCloseTombstone"
            };
            let projected = project_ref(definition_name, values.get(field).unwrap(), false)?;
            Ok(BTreeMap::from([(field.to_owned(), projected)]))
        }
        Some(_) => Err(AuthPrimitiveError::invalid(
            "special control serverFields set",
        )),
    }
}

fn control_fingerprint_from_projection(
    kind: ControlEntryKind,
    projection: &BTreeMap<String, DagValue>,
) -> Result<CanonicalControlFingerprint, AuthPrimitiveError> {
    let canonical_projection = serde_ipld_dagcbor::to_vec(&DagMapRef(projection))
        .map_err(|_| AuthPrimitiveError::invalid("control fingerprint DAG-CBOR"))?;
    let mut digest = Sha256::new();
    digest.update(CONTROL_FINGERPRINT_DOMAIN);
    digest.update(&canonical_projection);
    Ok(CanonicalControlFingerprint {
        kind,
        canonical_projection,
        fingerprint: digest.finalize().into(),
    })
}

pub fn decode_control_fingerprint(
    raw_json: &[u8],
) -> Result<CanonicalControlFingerprint, AuthPrimitiveError> {
    let raw = decode_raw_json(raw_json)?;
    let RawJson::Object(object) = raw else {
        return Err(AuthPrimitiveError::invalid("control fingerprint object"));
    };
    let (kind, projection) = decode_control_projection_object(object)?;
    control_fingerprint_from_projection(kind, &projection)
}

#[derive(Debug)]
pub struct VerifiedControlEntry {
    kind: ControlEntryKind,
    entry_id: CanonicalUuidV4,
    conversation_id: CanonicalUuidV4,
    seq: u64,
    received_at: CanonicalTimestamp,
    server_fields: BTreeMap<String, DagValue>,
    fingerprint: CanonicalControlFingerprint,
    mutation: VerifiedSignedMutation,
}

/// Seals an already verified mutation with repository-allocated row identity
/// and the request's one trusted instant. No raw signed wrapper, signature, or
/// caller-selected fingerprint enters this path.
pub fn build_verified_control_entry(
    mutation: VerifiedSignedMutation,
    endpoint: &ValidatedChatNsid,
    entry_id: CanonicalUuidV4,
    conversation_id: CanonicalUuidV4,
    seq: u64,
    received_at: &TrustedRequestInstant,
    server_fields: CanonicalControlServerFields,
) -> Result<VerifiedControlEntry, AuthPrimitiveError> {
    let kind = ControlEntryKind::from_signed_kind(mutation.kind())
        .ok_or_else(|| AuthPrimitiveError::invalid("mutation is not a control entry kind"))?;
    if kind.endpoint() != endpoint.as_str() {
        return Err(AuthPrimitiveError::invalid(
            "control endpoint/signed variant mismatch",
        ));
    }
    finish_verified_control_entry(
        kind,
        entry_id,
        conversation_id,
        seq,
        received_at.as_canonical().clone(),
        server_fields,
        mutation,
    )
}

pub fn decode_and_verify_control_entry(
    raw_json: &[u8],
    historical_public_key: &[u8],
) -> Result<VerifiedControlEntry, AuthPrimitiveError> {
    let raw = decode_raw_json(raw_json)?;
    let projected = project_ref("conversationEntry", &raw, false)?;
    let DagValue::Map(mut row) = projected else {
        unreachable!()
    };
    let type_id = match row.remove("$type") {
        Some(DagValue::Text(value)) => value,
        _ => return Err(AuthPrimitiveError::invalid("control row $type")),
    };
    let kind = ControlEntryKind::from_type_id(&type_id)
        .ok_or_else(|| AuthPrimitiveError::invalid("application row is not control authority"))?;
    let entry_id = take_uuid(&mut row, "entryId")?;
    let conversation_id = take_uuid(&mut row, "conversationId")?;
    let seq = take_integer(&mut row, "seq")?;
    let received_at = take_timestamp(&mut row, "receivedAt")?;
    let signed = match row.remove("signedRequest") {
        Some(DagValue::Map(value)) => value,
        _ => return Err(AuthPrimitiveError::invalid("control signedRequest")),
    };
    let mut signed = signed;
    let body = match signed.remove("body") {
        Some(DagValue::Map(value)) => value,
        _ => return Err(AuthPrimitiveError::invalid("control signed body")),
    };
    let signature: [u8; 64] = match signed.remove("signature") {
        Some(DagValue::Bytes(value)) => value
            .try_into()
            .map_err(|_| AuthPrimitiveError::invalid("control signature length"))?,
        _ => return Err(AuthPrimitiveError::invalid("control signature")),
    };
    if !signed.is_empty() {
        return Err(AuthPrimitiveError::invalid("control signed wrapper fields"));
    }
    let canonical = canonical_from_projected(body, signature, None)?;
    if canonical.kind() != kind.signed_kind() {
        return Err(AuthPrimitiveError::invalid(
            "control row/signed variant mismatch",
        ));
    }
    let body_conversation = signed_body_conversation_id(&canonical)?;
    if body_conversation != &conversation_id {
        return Err(AuthPrimitiveError::invalid(
            "control row/body conversation mismatch",
        ));
    }
    let mutation = verify_signed_mutation(canonical, historical_public_key)?;
    let mut server_fields = BTreeMap::new();
    if let Some(field) = kind.server_field() {
        let value = row
            .remove(field)
            .ok_or_else(|| AuthPrimitiveError::invalid("missing special control server field"))?;
        server_fields.insert(field.to_owned(), value);
    }
    if !row.is_empty() {
        return Err(AuthPrimitiveError::invalid("extra control row fields"));
    }
    finish_verified_control_entry(
        kind,
        entry_id,
        conversation_id,
        seq,
        received_at,
        CanonicalControlServerFields {
            kind,
            fields: server_fields,
        },
        mutation,
    )
}

/// Re-pair a decoded persisted public control row with the separately retained
/// exact signed wrapper. The public-row decoder deliberately carries no raw
/// wrapper authority; this seam re-verifies the wrapper with the historical
/// key, compares every signed projection field, rebuilds the outer projection
/// from the retained row identity/server fields, and rejects any splice.
pub fn rebind_persisted_control_entry(
    entry: VerifiedControlEntry,
    raw_signed_wrapper: &[u8],
    historical_public_key: &[u8],
) -> Result<VerifiedControlEntry, AuthPrimitiveError> {
    let mutation = decode_and_verify_signed_mutation(raw_signed_wrapper, historical_public_key)?;
    let original = entry.mutation();
    if mutation.kind() != original.kind()
        || mutation.type_id() != original.type_id()
        || mutation.domain() != original.domain()
        || mutation.canonical_projection() != original.canonical_projection()
        || mutation.transcript_bytes() != original.transcript_bytes()
        || mutation.request_digest() != original.request_digest()
        || mutation.signature() != original.signature()
        || mutation.actor_did() != original.actor_did()
        || mutation.actor_device_id() != original.actor_device_id()
        || mutation.key_id() != original.key_id()
        || mutation.auth_generation() != original.auth_generation()
        || mutation.signed_at() != original.signed_at()
        || mutation.accepted_wrapper_bytes() != Some(raw_signed_wrapper)
    {
        return Err(AuthPrimitiveError::invalid(
            "persisted control signed-wrapper splice",
        ));
    }
    let original_outer_projection = entry.fingerprint.canonical_projection().to_vec();
    let original_fingerprint = *entry.outer_control_fingerprint();
    let original_server_fields = serde_ipld_dagcbor::to_vec(&DagMapRef(&entry.server_fields))
        .map_err(|_| AuthPrimitiveError::invalid("persisted control serverFields DAG-CBOR"))?;
    let rebuilt = finish_verified_control_entry(
        entry.kind,
        entry.entry_id,
        entry.conversation_id,
        entry.seq,
        entry.received_at,
        CanonicalControlServerFields {
            kind: entry.kind,
            fields: entry.server_fields,
        },
        mutation,
    )?;
    if rebuilt.outer_control_projection() != original_outer_projection
        || rebuilt.outer_control_fingerprint() != &original_fingerprint
        || rebuilt.server_fields_dag_cbor()? != original_server_fields
    {
        return Err(AuthPrimitiveError::invalid(
            "persisted control outer-row splice",
        ));
    }
    Ok(rebuilt)
}

fn finish_verified_control_entry(
    kind: ControlEntryKind,
    entry_id: CanonicalUuidV4,
    conversation_id: CanonicalUuidV4,
    seq: u64,
    received_at: CanonicalTimestamp,
    server_fields: CanonicalControlServerFields,
    mutation: VerifiedSignedMutation,
) -> Result<VerifiedControlEntry, AuthPrimitiveError> {
    if !(1..=MAX_SAFE_INTEGER as u64).contains(&seq) {
        return Err(AuthPrimitiveError::invalid("control seq"));
    }
    if mutation.kind() != kind.signed_kind() {
        return Err(AuthPrimitiveError::invalid(
            "control row/signed variant mismatch",
        ));
    }
    if server_fields.kind != kind {
        return Err(AuthPrimitiveError::invalid(
            "control kind/serverFields mismatch",
        ));
    }
    if signed_body_conversation_id(&mutation.canonical)? != &conversation_id {
        return Err(AuthPrimitiveError::invalid(
            "control row/body conversation mismatch",
        ));
    }

    let server_fields = server_fields.fields;
    let mut projection = BTreeMap::new();
    projection.insert(
        "entryKind".into(),
        DagValue::Text(kind.type_id().to_owned()),
    );
    projection.insert("entryId".into(), DagValue::Uuid(entry_id.clone()));
    projection.insert(
        "conversationId".into(),
        DagValue::Uuid(conversation_id.clone()),
    );
    projection.insert("seq".into(), DagValue::Integer(seq));
    projection.insert(
        "requestDigest".into(),
        DagValue::Bytes(mutation.request_digest().to_vec()),
    );
    projection.insert(
        "signature".into(),
        DagValue::Bytes(mutation.signature().to_vec()),
    );
    projection.insert("serverFields".into(), DagValue::Map(server_fields.clone()));
    projection.insert(
        "receivedAt".into(),
        DagValue::Timestamp(received_at.clone()),
    );
    let fingerprint = control_fingerprint_from_projection(kind, &projection)?;
    Ok(VerifiedControlEntry {
        kind,
        entry_id,
        conversation_id,
        seq,
        received_at,
        server_fields,
        fingerprint,
        mutation,
    })
}

fn take_uuid(
    map: &mut BTreeMap<String, DagValue>,
    name: &str,
) -> Result<CanonicalUuidV4, AuthPrimitiveError> {
    match map.remove(name) {
        Some(DagValue::Uuid(value)) => Ok(value),
        _ => Err(AuthPrimitiveError::invalid("control UUID field")),
    }
}
fn take_integer(
    map: &mut BTreeMap<String, DagValue>,
    name: &str,
) -> Result<u64, AuthPrimitiveError> {
    match map.remove(name) {
        Some(DagValue::Integer(value)) => Ok(value),
        _ => Err(AuthPrimitiveError::invalid("control integer field")),
    }
}
fn take_timestamp(
    map: &mut BTreeMap<String, DagValue>,
    name: &str,
) -> Result<CanonicalTimestamp, AuthPrimitiveError> {
    match map.remove(name) {
        Some(DagValue::Timestamp(value)) => Ok(value),
        _ => Err(AuthPrimitiveError::invalid("control timestamp field")),
    }
}
fn signed_body_conversation_id(
    canonical: &CanonicalSignedMutation,
) -> Result<&CanonicalUuidV4, AuthPrimitiveError> {
    if matches!(
        canonical.kind(),
        SignedMutationKind::Creation | SignedMutationKind::LeaveCancellation
    ) {
        return Ok(body_uuid(&canonical.body, "conversationId"));
    }
    let prior = value_map(map_value(&canonical.body, "prior")?)?;
    value_uuid(map_value(prior, "conversationId")?)
}

impl VerifiedControlEntry {
    pub fn kind(&self) -> ControlEntryKind {
        self.kind
    }
    pub fn entry_id(&self) -> &CanonicalUuidV4 {
        &self.entry_id
    }
    pub fn conversation_id(&self) -> &CanonicalUuidV4 {
        &self.conversation_id
    }
    pub fn seq(&self) -> u64 {
        self.seq
    }
    pub fn received_at(&self) -> &CanonicalTimestamp {
        &self.received_at
    }
    pub fn outer_control_fingerprint(&self) -> &[u8; 32] {
        self.fingerprint.fingerprint()
    }
    pub fn outer_control_projection(&self) -> &[u8] {
        self.fingerprint.canonical_projection()
    }
    pub fn server_fields_dag_cbor(&self) -> Result<Vec<u8>, AuthPrimitiveError> {
        serde_ipld_dagcbor::to_vec(&DagMapRef(&self.server_fields))
            .map_err(|_| AuthPrimitiveError::invalid("control serverFields DAG-CBOR"))
    }
    pub fn server_fields(&self) -> ClosedObjectRef<'_> {
        ClosedObjectRef(&self.server_fields)
    }
    pub fn mutation(&self) -> &VerifiedSignedMutation {
        &self.mutation
    }
}
