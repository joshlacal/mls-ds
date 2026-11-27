//! Compatibility with stored MLS response bytes and federated receipt digests.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use super::{
    direct_request_transcript::{endpoint_output_schema, read_ref_name},
    transcript::definition as read_definition,
};

// Earlier Rust clients admitted integer arrays for named bytes aliases. Only
// rewrite fields that the lexicon identifies as an alias during decoding.
fn adapt_byte_aliases(schema: &Value, value: &mut Value, depth: usize) -> serde_json::Result<()> {
    use serde::de::Error as _;
    if depth > 128 {
        return Err(serde_json::Error::custom("chat schema nesting cap"));
    }
    match schema["type"].as_str() {
        Some("ref") => {
            if let Some(name) = schema["ref"].as_str().and_then(read_ref_name) {
                if matches!(name, "artifactHash" | "identifierBytes") {
                    if value.is_array() {
                        let bytes: Vec<u8> = serde_json::from_value(value.take())?;
                        *value = json!({"$bytes": STANDARD.encode(bytes)});
                    }
                } else {
                    let definition = read_definition(name).map_err(serde_json::Error::custom)?;
                    adapt_byte_aliases(definition, value, depth + 1)?;
                }
            }
        }
        Some("object") => {
            if let (Some(fields), Some(properties)) =
                (value.as_object_mut(), schema["properties"].as_object())
            {
                for (key, member) in fields {
                    if let Some(property) = properties.get(key) {
                        adapt_byte_aliases(property, member, depth + 1)?;
                    }
                }
            }
        }
        Some("array") => {
            if let Some(items) = value.as_array_mut() {
                for item in items {
                    adapt_byte_aliases(&schema["items"], item, depth + 1)?;
                }
            }
        }
        Some("union") => {
            let refs = schema["refs"]
                .as_array()
                .ok_or_else(|| serde_json::Error::custom("invalid chat union schema"))?;
            let tag = value
                .get("$type")
                .and_then(Value::as_str)
                .and_then(read_ref_name);
            let member = refs
                .iter()
                .filter_map(Value::as_str)
                .filter_map(read_ref_name)
                .find(|name| Some(*name) == tag || (tag.is_none() && refs.len() == 1));
            if let Some(member) = member {
                if value.get("$type").is_none() {
                    if let Some(object) = value.as_object_mut() {
                        object.insert(
                            "$type".into(),
                            Value::String(format!("blue.catbird.chat.defs#{member}")),
                        );
                    }
                }
                let definition = read_definition(member).map_err(serde_json::Error::custom)?;
                adapt_byte_aliases(definition, value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Decode retained chat data into the current generated DTO, including
/// the original integer-array representation of named byte aliases.
pub fn decode_definition<T: serde::de::DeserializeOwned>(
    name: &str,
    mut value: Value,
) -> serde_json::Result<T> {
    use serde::de::Error as _;
    let schema = read_definition(name).map_err(serde_json::Error::custom)?;
    adapt_byte_aliases(schema, &mut value, 0)?;
    serde_json::from_value(value)
}

pub fn decode_output<T: serde::de::DeserializeOwned>(
    nsid: &str,
    mut value: Value,
) -> serde_json::Result<T> {
    use serde::de::Error as _;
    let schema = endpoint_output_schema(nsid)
        .ok_or_else(|| serde_json::Error::custom("unknown chat output schema"))?;
    adapt_byte_aliases(schema, &mut value, 0)?;
    serde_json::from_value(value)
}

/// Receipt digests cover JSON object order. The original Rust DTOs serialized
/// union discriminators first, ordinary struct fields in generated field order,
/// and flattened extension fields last. Single-member unions were concrete
/// structs, where an explicitly present discriminator was an extension.
fn write_retained_chat_value(
    out: &mut Vec<u8>,
    schema: &Value,
    value: &Value,
    source: Option<&Value>,
    tagged: bool,
) -> serde_json::Result<()> {
    use serde::ser::Error as _;
    match schema["type"].as_str() {
        Some("ref" | "union") => {
            let is_union = schema["type"] == "union";
            let reference = if is_union {
                value["$type"].as_str()
            } else {
                schema["ref"].as_str()
            };
            let name = reference
                .and_then(read_ref_name)
                .ok_or_else(|| serde_json::Error::custom("unknown retained chat reference"))?;
            let definition = read_definition(name).map_err(serde_json::Error::custom)?;
            let tagged = is_union && schema["refs"].as_array().is_some_and(|refs| refs.len() > 1);
            write_retained_chat_value(out, definition, value, source, tagged)
        }
        Some("object") if value.is_object() => {
            let properties = &schema["properties"];
            let mut fields: Vec<_> = value.as_object().expect("object").iter().collect();
            fields.sort_by_key(|(key, _)| {
                if tagged && *key == "$type" {
                    0
                } else if properties.get(*key).is_some() {
                    1
                } else {
                    2
                }
            });
            out.push(b'{');
            let mut first = true;
            for (key, field) in fields {
                if key == "$type"
                    && !tagged
                    && source.is_some_and(|source| source.get(key).is_none())
                {
                    continue;
                }
                if !first {
                    out.push(b',');
                }
                first = false;
                serde_json::to_writer(&mut *out, key)?;
                out.push(b':');
                if let Some(property) = properties.get(key) {
                    write_retained_chat_value(
                        out,
                        property,
                        field,
                        source.and_then(|source| source.get(key)),
                        false,
                    )?;
                } else {
                    serde_json::to_writer(&mut *out, field)?;
                }
            }
            out.push(b'}');
            Ok(())
        }
        Some("array") if value.is_array() => {
            out.push(b'[');
            for (i, item) in value.as_array().expect("array").iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_retained_chat_value(
                    out,
                    &schema["items"],
                    item,
                    source.and_then(|source| source.get(i)),
                    false,
                )?;
            }
            out.push(b']');
            Ok(())
        }
        _ => serde_json::to_writer(out, value),
    }
}

pub fn encode_output<T: petrel_core::ToValue>(nsid: &str, dto: &T) -> serde_json::Result<Vec<u8>> {
    encode_output_with_source(nsid, dto, None)
}

pub fn encode_output_with_source<T: petrel_core::ToValue>(
    nsid: &str,
    dto: &T,
    source: Option<&Value>,
) -> serde_json::Result<Vec<u8>> {
    use serde::ser::Error as _;
    let schema = endpoint_output_schema(nsid)
        .ok_or_else(|| serde_json::Error::custom("unknown chat output schema"))?;
    let value = catbird_server::atproto_conv::wire_json_value(dto)?;
    let mut bytes = Vec::new();
    write_retained_chat_value(&mut bytes, schema, &value, source, false)?;
    Ok(bytes)
}

fn submit_commit_schema() -> &'static Value {
    static SCHEMA: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    SCHEMA.get_or_init(|| {
        let mut doc: Value = serde_json::from_str(include_str!(
            "../../../lexicon/blue/catbird/mlsDS/blue.catbird.mlsDS.submitCommit.json"
        ))
        .expect("embedded submitCommit schema");
        doc["defs"]["main"]["output"]["schema"].take()
    })
}

pub fn decode_submit_commit_output<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> serde_json::Result<T> {
    // Petrel's data-model visitor rejects duplicate map keys before conversion.
    let document: petrel_core::Value = serde_json::from_slice(bytes)?;
    let mut value = catbird_server::atproto_conv::wire_json_value(&document)?;
    adapt_byte_aliases(submit_commit_schema(), &mut value, 0)?;
    serde_json::from_value(value)
}
