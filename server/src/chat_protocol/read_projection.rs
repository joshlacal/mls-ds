//! C1 canonical-JCS v1 encoder for generated clean-chat DTOs.
//!
//! Owns the versioned canonical-JSON entry point
//! [`encode_canonical_generated_chat_json_v1`] that C1 projections (and the
//! G-send materialization path) use to byte-check their generated closed
//! DTOs exactly once. The contract is frozen by Checkpoint C1 of the
//! G7 downstream-readiness amendment:
//!
//! * UTF-8 only; no BOM, insignificant whitespace, trailing bytes, or Unicode
//!   normalization. Strings pass through byte-for-byte (a composed `é`
//!   (U+00E9) is never decomposed and a decomposed `e` + combining acute is
//!   never composed).
//! * Object member names are sorted by UTF-16 code-unit order (RFC 8785/JCS).
//! * Strings escape quotation mark and reverse solidus, use `\b`, `\t`, `\n`,
//!   `\f`, and `\r` for those controls, lowercase `\u00xx` for all other
//!   U+0000 through U+001F controls, never escape solidus, and otherwise emit
//!   the original Unicode scalar values.
//! * Only integers are accepted; shortest base-10, no leading zero or plus,
//!   zero exactly `0`, absolute value at most `9007199254740991`; every
//!   floating-point form rejects.
//! * `true`, `false`, and schema-declared `null` use those lowercase
//!   spellings; arrays preserve generated DTO order.
//! * The generated DTO serializer's `Option::None` omission rule is followed
//!   (it already emitted the object); `null` is accepted only where the
//!   selected definition explicitly permits it (no `nullable` field exists in
//!   `blue.catbird.chat.defs`, so every null rejects).
//! * Union definitions require their exact full `$type` string; `$type` is
//!   sorted as an ordinary key and never invented or repaired.
//! * A schema-aware normalization against the exact `definition_id` rejects
//!   unknown/missing fields, unknown union tags, duplicate keys, invalid
//!   nulls, and any non-empty `extra_data` before any canonical byte is
//!   written. Bytes normalize to bare standard padded base64 text (canonical
//!   spelling required) and datetimes must already be the checked canonical
//!   UTC text (`YYYY-MM-DDTHH:MM:SS.sssZ`).
//! * Stored-byte validation re-parses the canonical bytes with a
//!   duplicate-detecting parser, re-normalizes them against the exact
//!   definition, re-encodes with this encoder, and requires byte-for-byte
//!   equality.
//!
//! The generated chat DTO surface carries byte fields in two JSON shapes
//! (`{"$bytes": <padded base64>}` for `serde_bytes_helper` fields and plain
//! byte arrays for the bare `bytes::Bytes` aliases such as `ArtifactHash` and
//! `IdentifierBytes`); both normalize to the same bare padded base64 text, as
//! does a bare base64 string. The encoder is not left to an unspecified
//! `serde_json::to_vec` ordering: it serializes the DTO once with the
//! generated serializer and performs its own local canonical write.

use std::{cmp::Ordering, collections::HashSet, fmt, sync::OnceLock};

use base64::{engine::general_purpose::STANDARD, Engine};
use catbird_atproto::generated::blue_catbird::chat as chat_dto;
use jacquard_common::deps::{bytes::Bytes, smol_str::SmolStr};
use jacquard_common::types::string::Did;
use jacquard_common::DefaultStr;
use jacquard_lexicon::{
    lexicon::{
        LexArrayItem, LexObject, LexObjectProperty, LexRefUnion, LexStringFormat, LexUserType,
        LexiconDoc,
    },
    schema::LexiconSchema,
};
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Serialize,
};
use sha2::{Digest, Sha256};

use super::validation::CanonicalTimestamp;

/// Version of the canonical chat JSON encoding frozen by Checkpoint C1.
pub(crate) const CANONICAL_CHAT_JSON_VERSION: u16 = 1;

const CHAT_NSID: &str = "blue.catbird.chat.defs";
const TYPE_PREFIX: &str = "blue.catbird.chat.defs#";
/// Hard pre-normalization transport cap: the largest closed projection is
/// orders of magnitude smaller; the cap keeps malformed or hostile input from
/// allocating unbounded trees.
const MAX_CANONICAL_JSON_BYTES: usize = 64 * 1024 * 1024;
/// RFC 8785/JCS safe-integer bound; the lexicon also caps every integer at
/// this value.
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
/// Defensive bound on schema-reference following; the static chat schema
/// contains no cycles, so this is unreachable in practice.
const MAX_SCHEMA_DEPTH: usize = 64;

const E_DUPLICATE_KEY: &str = "catbird canonical JSON: duplicate JSON object key";
const E_FLOAT: &str = "catbird canonical JSON: floating-point forms are rejected";
const E_UNSAFE_INTEGER: &str = "catbird canonical JSON: integer outside the safe range";

/// Canonical-JSON v1 result: the checked canonical UTF-8 bytes plus their
/// SHA-256. Both fields are private; consumers receive them through accessors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalChatJsonV1 {
    bytes: Vec<u8>,
    sha256: [u8; 32],
}

impl CanonicalChatJsonV1 {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    /// Lowercase hexadecimal SHA-256 of the canonical bytes.
    pub(crate) fn sha256_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.sha256 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

/// Stable failure classes the tests assert against.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ProjectionErrorKind {
    InvalidDefinitionId,
    DefinitionNotFound,
    UnsupportedSchema,
    SerializationFailed,
    InvalidJsonSyntax,
    DuplicateKey,
    FloatNotAllowed,
    IntegerOutOfRange,
    UnknownField,
    MissingField,
    UnknownUnionTag,
    InvalidNull,
    InvalidDatetime,
    NonCanonicalBase64,
    InvalidBytesForm,
    WrongValueType,
    StringEnumViolation,
    StringConstViolation,
    IntegerConstViolation,
    SchemaRecursionLimit,
    InputTooLarge,
    StoredBytesNotCanonical,
    /// A removal/close arm has no historical conversationState; only its
    /// tombstone materializes (`AccessOutsideMembershipInterval`-shaped
    /// semantics).
    NoConversationStateProjection,
    /// An inbox variant tag does not match the retained recovery-work
    /// terminal shape.
    WrongTerminalShape,
    /// A checked-source byte field violates its exact pinned length
    /// (SHA-256 32 bytes, MLS RefHash 32 bytes, IdentifierBytes 16 bytes,
    /// Ed25519 public key 32 bytes, GCM nonce 12 bytes).
    InvalidByteLength,
    /// A checked-source DID does not validate against the AT Protocol DID
    /// grammar (`did:method:identifier`, <= 2048 bytes).
    InvalidDid,
    /// Cross-field or ordering inconsistency inside a checked source
    /// (unsorted leaves/participants, reservation bound to another request,
    /// status/reservation mismatch, genesis leaf with a key-package ref,
    /// pending participant without provenance, mismatched coordinates).
    InconsistentSourceFields,
}

/// Private-field projection failure. Every failure carries a redacted static
/// reason plus the schema-known member path; no raw DTO bytes or payload
/// values ever enter the error.
#[derive(Clone, Debug)]
pub(crate) struct ProjectionError {
    kind: ProjectionErrorKind,
    path: String,
    reason: &'static str,
}

impl ProjectionError {
    fn new(kind: ProjectionErrorKind, path: &str, reason: &'static str) -> Self {
        Self {
            kind,
            path: path.to_owned(),
            reason,
        }
    }

    pub(crate) fn kind(&self) -> ProjectionErrorKind {
        self.kind
    }
}

impl fmt::Display for ProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?} at {:?}: {}",
            self.kind, self.path, self.reason
        )
    }
}

impl std::error::Error for ProjectionError {}

/// The local canonical tree: `serde_json`'s parser/value model, closed to
/// exactly the JCS subset the encoder accepts. Objects keep insertion order
/// (duplicates rejected at parse time) and are sorted at write time.
#[derive(Clone, Debug, Eq, PartialEq)]
enum CanonValue {
    Null,
    Bool(bool),
    Integer(i64),
    String(String),
    Array(Vec<CanonValue>),
    Object(Vec<(String, CanonValue)>),
}

impl<'de> Deserialize<'de> for CanonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(CanonValueVisitor)
    }
}

struct CanonValueVisitor;

impl<'de> Visitor<'de> for CanonValueVisitor {
    type Value = CanonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("closed non-null canonical clean-chat JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(CanonValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
            return Err(E::custom(E_UNSAFE_INTEGER));
        }
        Ok(CanonValue::Integer(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value > MAX_SAFE_INTEGER as u64 {
            return Err(E::custom(E_UNSAFE_INTEGER));
        }
        Ok(CanonValue::Integer(value as i64))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom(E_FLOAT))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(CanonValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(CanonValue::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(CanonValue::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(CanonValue::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(CanonValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Vec::new();
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(E_DUPLICATE_KEY));
            }
            let value = map.next_value()?;
            values.push((key, value));
        }
        Ok(CanonValue::Object(values))
    }
}

/// Strict duplicate-detecting parse of the closed canonical JSON domain.
///
/// The first/last-byte guards reject BOMs, insignificant leading whitespace,
/// scalar roots, and trailing whitespace; `Deserializer::end()` rejects
/// trailing non-whitespace bytes. `serde_json`'s default value model keeps
/// the last duplicate key, so duplicate detection happens here, in the
/// visitor, for both the incoming generated-DTO serialization and the
/// stored-byte validation pass.
fn parse_strict_canonical_json(bytes: &[u8]) -> Result<CanonValue, ProjectionError> {
    if bytes.len() > MAX_CANONICAL_JSON_BYTES {
        return Err(ProjectionError::new(
            ProjectionErrorKind::InputTooLarge,
            "",
            "canonical JSON input exceeds the hard size cap",
        ));
    }
    if bytes.is_empty() || !matches!(bytes[0], b'{' | b'[') {
        return Err(ProjectionError::new(
            ProjectionErrorKind::InvalidJsonSyntax,
            "",
            "BOM, insignificant whitespace, or scalar root are rejected",
        ));
    }
    if !matches!(bytes[bytes.len() - 1], b'}' | b']') {
        return Err(ProjectionError::new(
            ProjectionErrorKind::InvalidJsonSyntax,
            "",
            "trailing bytes or insignificant trailing whitespace are rejected",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value =
        CanonValue::deserialize(&mut deserializer).map_err(|error| classify_parse_error(error))?;
    deserializer.end().map_err(|_| {
        ProjectionError::new(
            ProjectionErrorKind::InvalidJsonSyntax,
            "",
            "trailing data after the JSON root",
        )
    })?;
    Ok(value)
}

fn classify_parse_error(error: serde_json::Error) -> ProjectionError {
    let text = error.to_string();
    let kind = if text.contains("duplicate JSON object key") {
        ProjectionErrorKind::DuplicateKey
    } else if text.contains("floating-point") {
        ProjectionErrorKind::FloatNotAllowed
    } else if text.contains("safe range") {
        ProjectionErrorKind::IntegerOutOfRange
    } else {
        ProjectionErrorKind::InvalidJsonSyntax
    };
    ProjectionError::new(kind, "", "invalid strict canonical JSON")
}

fn chat_defs_doc() -> &'static LexiconDoc<'static> {
    static DOC: OnceLock<LexiconDoc<'static>> = OnceLock::new();
    DOC.get_or_init(|| <chat_dto::ConversationState<DefaultStr> as LexiconSchema>::lexicon_doc())
}

fn split_definition_id(definition_id: &str) -> Result<&str, ProjectionError> {
    let Some((nsid, def_name)) = definition_id.split_once('#') else {
        return Err(ProjectionError::new(
            ProjectionErrorKind::InvalidDefinitionId,
            "",
            "definition id must be nsid#defName",
        ));
    };
    if nsid != CHAT_NSID || def_name.is_empty() {
        return Err(ProjectionError::new(
            ProjectionErrorKind::InvalidDefinitionId,
            "",
            "definition id must name a def in blue.catbird.chat.defs",
        ));
    }
    Ok(def_name)
}

fn resolve_ref_name(ref_text: &str) -> Option<&str> {
    if let Some(name) = ref_text.strip_prefix('#') {
        return Some(name);
    }
    if let Some(name) = ref_text.strip_prefix(TYPE_PREFIX) {
        return Some(name);
    }
    None
}

fn field_path(path: &str, field: &str) -> String {
    if path.is_empty() {
        field.to_owned()
    } else {
        format!("{path}.{field}")
    }
}

/// Schema-aware normalization against the exact definition. Rejects unknown
/// and missing fields, unknown union tags, invalid nulls, and (via the
/// unknown-field rule) any non-empty `extra_data`; normalizes bytes to bare
/// standard padded base64 text and verifies datetimes are the checked
/// canonical UTC text.
fn normalize_def(
    doc: &LexiconDoc<'static>,
    def_name: &str,
    value: &CanonValue,
    depth: usize,
    path: &str,
) -> Result<CanonValue, ProjectionError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(ProjectionError::new(
            ProjectionErrorKind::SchemaRecursionLimit,
            path,
            "schema recursion limit exceeded",
        ));
    }
    let Some(definition) = doc.defs.get(def_name) else {
        return Err(ProjectionError::new(
            ProjectionErrorKind::DefinitionNotFound,
            path,
            "definition not found in blue.catbird.chat.defs",
        ));
    };
    match definition {
        LexUserType::Object(object) => normalize_object(doc, object, value, depth, path),
        LexUserType::Union(union) => normalize_union(doc, union, value, depth, path),
        LexUserType::String(string) => normalize_string(string, value, path),
        LexUserType::Integer(integer) => normalize_integer(integer, value, path),
        LexUserType::Boolean(_) => normalize_boolean(value, path),
        LexUserType::Bytes(_) => normalize_bytes(value, path),
        LexUserType::Array(array) => normalize_array(doc, array, value, depth, path),
        LexUserType::Unknown(_) => match value {
            CanonValue::Null => Err(ProjectionError::new(
                ProjectionErrorKind::InvalidNull,
                path,
                "null is not permitted here",
            )),
            _ => Ok(value.clone()),
        },
        LexUserType::Record(_)
        | LexUserType::XrpcQuery(_)
        | LexUserType::XrpcProcedure(_)
        | LexUserType::XrpcSubscription(_)
        | LexUserType::Blob(_)
        | LexUserType::Token(_)
        | LexUserType::CidLink(_)
        | LexUserType::PermissionSet(_) => Err(ProjectionError::new(
            ProjectionErrorKind::UnsupportedSchema,
            path,
            "definition type is not encodable by the canonical chat encoder",
        )),
    }
}

fn normalize_object(
    doc: &LexiconDoc<'static>,
    object: &LexObject<'static>,
    value: &CanonValue,
    depth: usize,
    path: &str,
) -> Result<CanonValue, ProjectionError> {
    let CanonValue::Object(entries) = value else {
        return Err(ProjectionError::new(
            ProjectionErrorKind::WrongValueType,
            path,
            "definition requires an object",
        ));
    };
    let mut output = Vec::with_capacity(entries.len());
    for (key, entry) in entries {
        if key == "$type" {
            return Err(ProjectionError::new(
                ProjectionErrorKind::UnknownField,
                &field_path(path, key),
                "$type is not permitted on an object definition",
            ));
        }
        let Some(property) = object.properties.get(key.as_str()) else {
            return Err(ProjectionError::new(
                ProjectionErrorKind::UnknownField,
                &field_path(path, key),
                "unknown member (a non-empty extra_data map can never smuggle one)",
            ));
        };
        let entry_path = field_path(path, key);
        if let CanonValue::Null = entry {
            let nullable = object.nullable.as_deref().unwrap_or_default();
            if !nullable.iter().any(|name| name.as_str() == key.as_str()) {
                return Err(ProjectionError::new(
                    ProjectionErrorKind::InvalidNull,
                    &entry_path,
                    "null is not permitted for this member",
                ));
            }
            output.push((key.clone(), CanonValue::Null));
            continue;
        }
        let normalized = normalize_property(doc, property, entry, depth + 1, &entry_path)?;
        output.push((key.clone(), normalized));
    }
    if let Some(required) = &object.required {
        for name in required {
            if !entries.iter().any(|(key, _)| key.as_str() == name.as_str()) {
                return Err(ProjectionError::new(
                    ProjectionErrorKind::MissingField,
                    &field_path(path, name.as_str()),
                    "required member is missing",
                ));
            }
        }
    }
    Ok(CanonValue::Object(output))
}

fn normalize_property(
    doc: &LexiconDoc<'static>,
    property: &LexObjectProperty<'static>,
    value: &CanonValue,
    depth: usize,
    path: &str,
) -> Result<CanonValue, ProjectionError> {
    match property {
        LexObjectProperty::Ref(reference) => {
            let Some(name) = resolve_ref_name(reference.r#ref.as_ref()) else {
                return Err(ProjectionError::new(
                    ProjectionErrorKind::UnsupportedSchema,
                    path,
                    "cross-document refs are not encodable here",
                ));
            };
            normalize_def(doc, name, value, depth, path)
        }
        LexObjectProperty::Union(union) => normalize_union(doc, union, value, depth, path),
        LexObjectProperty::Bytes(_) => normalize_bytes(value, path),
        LexObjectProperty::Array(array) => normalize_array(doc, array, value, depth, path),
        LexObjectProperty::Object(object) => normalize_object(doc, object, value, depth, path),
        LexObjectProperty::Boolean(_) => normalize_boolean(value, path),
        LexObjectProperty::Integer(integer) => normalize_integer(integer, value, path),
        LexObjectProperty::String(string) => normalize_string(string, value, path),
        LexObjectProperty::Unknown(_) => match value {
            CanonValue::Null => Err(ProjectionError::new(
                ProjectionErrorKind::InvalidNull,
                path,
                "null is not permitted here",
            )),
            _ => Ok(value.clone()),
        },
        LexObjectProperty::CidLink(_) | LexObjectProperty::Blob(_) => Err(ProjectionError::new(
            ProjectionErrorKind::UnsupportedSchema,
            path,
            "property type is not encodable by the canonical chat encoder",
        )),
    }
}

fn normalize_union(
    doc: &LexiconDoc<'static>,
    union: &LexRefUnion<'static>,
    value: &CanonValue,
    depth: usize,
    path: &str,
) -> Result<CanonValue, ProjectionError> {
    let CanonValue::Object(entries) = value else {
        return Err(ProjectionError::new(
            ProjectionErrorKind::WrongValueType,
            path,
            "union definition requires an object",
        ));
    };
    let tag = entries
        .iter()
        .find(|(key, _)| key == "$type")
        .ok_or_else(|| {
            ProjectionError::new(
                ProjectionErrorKind::UnknownUnionTag,
                path,
                "union object is missing its $type discriminator",
            )
        })?;
    let CanonValue::String(tag_value) = &tag.1 else {
        return Err(ProjectionError::new(
            ProjectionErrorKind::UnknownUnionTag,
            path,
            "union $type must be a string",
        ));
    };
    let Some(variant) = tag_value.strip_prefix(TYPE_PREFIX) else {
        return Err(ProjectionError::new(
            ProjectionErrorKind::UnknownUnionTag,
            path,
            "union $type must be the exact full type string",
        ));
    };
    let allowed = union
        .refs
        .iter()
        .any(|reference| reference.as_ref().strip_prefix('#') == Some(variant));
    if !allowed {
        return Err(ProjectionError::new(
            ProjectionErrorKind::UnknownUnionTag,
            path,
            "union $type is not a member of this definition's refs",
        ));
    }
    let Some(variant_definition) = doc.defs.get(variant) else {
        return Err(ProjectionError::new(
            ProjectionErrorKind::UnsupportedSchema,
            path,
            "union variant definition is missing",
        ));
    };
    let LexUserType::Object(variant_object) = variant_definition else {
        return Err(ProjectionError::new(
            ProjectionErrorKind::UnsupportedSchema,
            path,
            "union variant must be a concrete object definition",
        ));
    };
    let rest = entries
        .iter()
        .filter(|(key, _)| key != "$type")
        .cloned()
        .collect();
    let normalized_rest = normalize_object(
        doc,
        variant_object,
        &CanonValue::Object(rest),
        depth + 1,
        &field_path(path, variant),
    )?;
    let CanonValue::Object(normalized_entries) = normalized_rest else {
        return Err(ProjectionError::new(
            ProjectionErrorKind::UnsupportedSchema,
            path,
            "union variant normalization did not yield an object",
        ));
    };
    let mut output = Vec::with_capacity(normalized_entries.len() + 1);
    output.push(("$type".to_owned(), CanonValue::String(tag_value.clone())));
    output.extend(normalized_entries);
    Ok(CanonValue::Object(output))
}

fn normalize_bytes(value: &CanonValue, path: &str) -> Result<CanonValue, ProjectionError> {
    let encoded: &str = match value {
        CanonValue::String(text) => text.as_str(),
        CanonValue::Object(entries) if entries.len() == 1 => {
            match (&entries[0].0[..], &entries[0].1) {
                (key, CanonValue::String(text)) if key == "$bytes" => text.as_str(),
                _ => {
                    return Err(ProjectionError::new(
                        ProjectionErrorKind::InvalidBytesForm,
                        path,
                        "byte field must be a $bytes object, a byte array, or base64 text",
                    ))
                }
            }
        }
        CanonValue::Array(items) => {
            let mut raw = Vec::with_capacity(items.len());
            for item in items {
                let CanonValue::Integer(byte) = item else {
                    return Err(ProjectionError::new(
                        ProjectionErrorKind::InvalidBytesForm,
                        path,
                        "byte array entries must be integers in 0..=255",
                    ));
                };
                if !(0..=255).contains(byte) {
                    return Err(ProjectionError::new(
                        ProjectionErrorKind::InvalidBytesForm,
                        path,
                        "byte array entries must be integers in 0..=255",
                    ));
                }
                raw.push(*byte as u8);
            }
            return Ok(CanonValue::String(STANDARD.encode(raw)));
        }
        _ => {
            return Err(ProjectionError::new(
                ProjectionErrorKind::InvalidBytesForm,
                path,
                "byte field must be a $bytes object, a byte array, or base64 text",
            ))
        }
    };
    let Ok(decoded) = STANDARD.decode(encoded) else {
        return Err(ProjectionError::new(
            ProjectionErrorKind::NonCanonicalBase64,
            path,
            "byte field is not standard padded base64",
        ));
    };
    if STANDARD.encode(&decoded) != encoded {
        return Err(ProjectionError::new(
            ProjectionErrorKind::NonCanonicalBase64,
            path,
            "byte field base64 spelling is not canonical",
        ));
    }
    Ok(CanonValue::String(encoded.to_owned()))
}

fn normalize_array(
    doc: &LexiconDoc<'static>,
    array: &jacquard_lexicon::lexicon::LexArray<'static>,
    value: &CanonValue,
    depth: usize,
    path: &str,
) -> Result<CanonValue, ProjectionError> {
    let CanonValue::Array(items) = value else {
        return Err(ProjectionError::new(
            ProjectionErrorKind::WrongValueType,
            path,
            "definition requires an array",
        ));
    };
    let mut output = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_path = field_path(path, &index.to_string());
        output.push(normalize_array_item(
            doc,
            &array.items,
            item,
            depth,
            &item_path,
        )?);
    }
    Ok(CanonValue::Array(output))
}

fn normalize_array_item(
    doc: &LexiconDoc<'static>,
    item: &LexArrayItem<'static>,
    value: &CanonValue,
    depth: usize,
    path: &str,
) -> Result<CanonValue, ProjectionError> {
    match item {
        LexArrayItem::Ref(reference) => {
            let Some(name) = resolve_ref_name(reference.r#ref.as_ref()) else {
                return Err(ProjectionError::new(
                    ProjectionErrorKind::UnsupportedSchema,
                    path,
                    "cross-document refs are not encodable here",
                ));
            };
            normalize_def(doc, name, value, depth, path)
        }
        LexArrayItem::Union(union) => normalize_union(doc, union, value, depth, path),
        LexArrayItem::Bytes(_) => normalize_bytes(value, path),
        LexArrayItem::Object(object) => normalize_object(doc, object, value, depth, path),
        LexArrayItem::Boolean(_) => normalize_boolean(value, path),
        LexArrayItem::Integer(integer) => normalize_integer(integer, value, path),
        LexArrayItem::String(string) => normalize_string(string, value, path),
        LexArrayItem::Unknown(_) => match value {
            CanonValue::Null => Err(ProjectionError::new(
                ProjectionErrorKind::InvalidNull,
                path,
                "null is not permitted here",
            )),
            _ => Ok(value.clone()),
        },
        LexArrayItem::CidLink(_) | LexArrayItem::Blob(_) => Err(ProjectionError::new(
            ProjectionErrorKind::UnsupportedSchema,
            path,
            "array item type is not encodable by the canonical chat encoder",
        )),
    }
}

fn normalize_string(
    string: &jacquard_lexicon::lexicon::LexString<'static>,
    value: &CanonValue,
    path: &str,
) -> Result<CanonValue, ProjectionError> {
    let CanonValue::String(text) = value else {
        return Err(ProjectionError::new(
            ProjectionErrorKind::WrongValueType,
            path,
            "definition requires a string",
        ));
    };
    if string.format == Some(LexStringFormat::Datetime) {
        CanonicalTimestamp::parse(text).map_err(|_| {
            ProjectionError::new(
                ProjectionErrorKind::InvalidDatetime,
                path,
                "datetime is not the checked canonical UTC text",
            )
        })?;
    }
    if let Some(enum_values) = &string.r#enum {
        if !enum_values.iter().any(|value| value.as_ref() == text) {
            return Err(ProjectionError::new(
                ProjectionErrorKind::StringEnumViolation,
                path,
                "string is not a member of the definition's enum",
            ));
        }
    }
    if let Some(const_value) = &string.r#const {
        if const_value.as_ref() != text {
            return Err(ProjectionError::new(
                ProjectionErrorKind::StringConstViolation,
                path,
                "string does not match the definition's const value",
            ));
        }
    }
    Ok(value.clone())
}

fn normalize_integer(
    integer: &jacquard_lexicon::lexicon::LexInteger<'static>,
    value: &CanonValue,
    path: &str,
) -> Result<CanonValue, ProjectionError> {
    let CanonValue::Integer(number) = value else {
        return Err(ProjectionError::new(
            ProjectionErrorKind::WrongValueType,
            path,
            "definition requires an integer",
        ));
    };
    if let Some(minimum) = integer.minimum {
        if *number < minimum {
            return Err(ProjectionError::new(
                ProjectionErrorKind::IntegerOutOfRange,
                path,
                "integer is below the definition's minimum",
            ));
        }
    }
    if let Some(maximum) = integer.maximum {
        if *number > maximum {
            return Err(ProjectionError::new(
                ProjectionErrorKind::IntegerOutOfRange,
                path,
                "integer exceeds the definition's maximum",
            ));
        }
    }
    if let Some(const_value) = integer.r#const {
        if *number != const_value {
            return Err(ProjectionError::new(
                ProjectionErrorKind::IntegerConstViolation,
                path,
                "integer does not match the definition's const value",
            ));
        }
    }
    Ok(value.clone())
}

fn normalize_boolean(value: &CanonValue, path: &str) -> Result<CanonValue, ProjectionError> {
    match value {
        CanonValue::Bool(_) => Ok(value.clone()),
        _ => Err(ProjectionError::new(
            ProjectionErrorKind::WrongValueType,
            path,
            "definition requires a boolean",
        )),
    }
}

/// RFC 8785/JCS member-name ordering: UTF-16 code-unit order.
fn utf16_code_unit_cmp(left: &str, right: &str) -> Ordering {
    let mut left_units = left.encode_utf16();
    let mut right_units = right.encode_utf16();
    loop {
        match (left_units.next(), right_units.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(left_unit), Some(right_unit)) => match left_unit.cmp(&right_unit) {
                Ordering::Equal => continue,
                other => return other,
            },
        }
    }
}

/// Local canonical writer over the parsed value model. Emits the original
/// Unicode scalar values verbatim (no normalization), sorts object member
/// names by UTF-16 code-unit order, applies the JCS string escape set exactly,
/// and never escapes solidus.
fn write_canonical_value(out: &mut Vec<u8>, value: &CanonValue) {
    match value {
        CanonValue::Null => out.extend_from_slice(b"null"),
        CanonValue::Bool(true) => out.extend_from_slice(b"true"),
        CanonValue::Bool(false) => out.extend_from_slice(b"false"),
        CanonValue::Integer(number) => {
            out.extend_from_slice(number.to_string().as_bytes());
        }
        CanonValue::String(text) => write_canonical_string(out, text),
        CanonValue::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical_value(out, item);
            }
            out.push(b']');
        }
        CanonValue::Object(entries) => {
            let mut sorted: Vec<&(String, CanonValue)> = entries.iter().collect();
            sorted.sort_by(|left, right| utf16_code_unit_cmp(&left.0, &right.0));
            out.push(b'{');
            for (index, (key, item)) in sorted.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical_string(out, key);
                out.push(b':');
                write_canonical_value(out, item);
            }
            out.push(b'}');
        }
    }
}

fn write_canonical_string(out: &mut Vec<u8>, text: &str) {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    for c in text.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{0008}' => out.extend_from_slice(b"\\b"),
            '\u{0009}' => out.extend_from_slice(b"\\t"),
            '\u{000A}' => out.extend_from_slice(b"\\n"),
            '\u{000C}' => out.extend_from_slice(b"\\f"),
            '\u{000D}' => out.extend_from_slice(b"\\r"),
            '\u{0000}'..='\u{001F}' => {
                out.extend_from_slice(b"\\u00");
                out.push(HEX_DIGITS[(c as u32 >> 4) as usize]);
                out.push(HEX_DIGITS[(c as u32 & 0x0F) as usize]);
            }
            _ => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Stored-byte validation: decode the canonical bytes with the
/// duplicate-detecting parser, decode them against the exact generated
/// definition (schema-aware normalization), re-encode with this encoder, and
/// require byte-for-byte equality. `T: Serialize` alone is the frozen
/// interface, so the "exact generated definition" decode is the schema-aware
/// normalization of the same tree the encoder itself writes; a writer that
/// emitted anything non-canonical or denormalized is caught here.
fn stored_byte_validation(
    doc: &LexiconDoc<'static>,
    def_name: &str,
    canonical: &[u8],
) -> Result<(), ProjectionError> {
    let tree = parse_strict_canonical_json(canonical)?;
    let normalized = normalize_def(doc, def_name, &tree, 0, "")?;
    let mut rewritten = Vec::with_capacity(canonical.len());
    write_canonical_value(&mut rewritten, &normalized);
    if rewritten != canonical {
        return Err(ProjectionError::new(
            ProjectionErrorKind::StoredBytesNotCanonical,
            "",
            "stored bytes are not canonical (re-encode mismatch)",
        ));
    }
    Ok(())
}

/// Versioned canonical-JSON encoder for generated clean-chat DTOs.
///
/// Serializes the DTO exactly once via the generated serializer, parses that
/// output with a duplicate-detecting parser, schema-aware normalizes it
/// against the exact `definition_id` (rejecting unknown/missing fields,
/// unknown union tags, duplicate keys, invalid nulls, and any non-empty
/// `extra_data`), canonically writes it (RFC 8785/JCS), byte-checks the
/// output, and returns the checked bytes plus SHA-256.
pub(crate) fn encode_canonical_generated_chat_json_v1<T: Serialize>(
    dto: &T,
    definition_id: &'static str,
) -> Result<CanonicalChatJsonV1, ProjectionError> {
    let def_name = split_definition_id(definition_id)?;
    let doc = chat_defs_doc();
    if doc.id.as_ref() != CHAT_NSID {
        return Err(ProjectionError::new(
            ProjectionErrorKind::UnsupportedSchema,
            "",
            "lexicon document namespace mismatch",
        ));
    }
    let bytes = serde_json::to_vec(dto).map_err(|_| {
        ProjectionError::new(
            ProjectionErrorKind::SerializationFailed,
            "",
            "generated DTO serializer failed",
        )
    })?;
    if bytes.len() > MAX_CANONICAL_JSON_BYTES {
        return Err(ProjectionError::new(
            ProjectionErrorKind::InputTooLarge,
            "",
            "generated DTO serialization exceeds the hard size cap",
        ));
    }
    let tree = parse_strict_canonical_json(&bytes)?;
    let normalized = normalize_def(doc, def_name, &tree, 0, "")?;
    let mut canonical = Vec::with_capacity(bytes.len() + bytes.len() / 8);
    write_canonical_value(&mut canonical, &normalized);
    stored_byte_validation(doc, def_name, &canonical)?;
    let digest = Sha256::digest(&canonical);
    Ok(CanonicalChatJsonV1 {
        bytes: canonical,
        sha256: digest.into(),
    })
}

// ============================================================================
// C1-2: checked projection source types and the six projection functions.
//
// The generated lexicon doc drops enum/const constraints (verified: zero
// r#enum/r#const in the generated doc), so THESE checked sources are the sole
// guarantee of status/value correctness: every constructor validates the
// closed enum vocabulary, the canonical UTC datetime text, safe integer
// bounds, the exact pinned byte lengths, strict input ordering, and the
// cross-field consistency rules of the DTO documentation BEFORE any DTO is
// materialized. An unknown `$type` cannot be represented (the source unions
// are closed), a missing or extra field cannot be passed (fixed constructor
// signatures), and a wrong terminal shape cannot survive a checked inbox
// constructor or the projection's own re-check.
//
// The six projection functions build the generated closed DTOs only. They
// never return pre-serialized bytes and never accept them; the D facade
// composes projection -> `encode_canonical_generated_chat_json_v1` exactly
// once. `extra_data` is always `None` in every materialized DTO, so the
// encoder's unknown-field rule guarantees `extraData` can never be non-empty
// in produced canonical bytes.
// ============================================================================

const CIPHER_SUITE_V1: &str = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";
const LIFECYCLE_ACTIVE: &str = "active";
const LIFECYCLE_SUPERSEDED: &str = "superseded";
const CONVERSATION_KIND_DIRECT: &str = "direct";
const CONVERSATION_KIND_GROUP: &str = "group";
const MEMBER_ROLE_ADMIN: &str = "admin";
const MEMBER_ROLE_MEMBER: &str = "member";
const PARTICIPANT_STATUS_PENDING: &str = "pending";
const PARTICIPANT_STATUS_ACTIVE: &str = "active";
const DEVICE_STATUS_ACTIVE: &str = "active";
const DEVICE_STATUS_REVOKED: &str = "revoked";
const LEAF_ORIGIN_GENESIS: &str = "genesis";
const LEAF_ORIGIN_KEY_PACKAGE: &str = "keyPackage";
const LEAF_RECOVERY_KIND_ADD: &str = "add";
const LEAF_RECOVERY_KIND_REPLACE: &str = "replace";
const LEAF_RECOVERY_STATUS_OPEN: &str = "open";
const LEAF_RECOVERY_STATUS_FULFILLED: &str = "fulfilled";
const LEAF_RECOVERY_STATUS_CANCELLED: &str = "cancelled";
const LEAF_RECOVERY_STATUS_EXPIRED: &str = "expired";
const LEAF_RECOVERY_STATUS_SUPERSEDED: &str = "superseded";
const RESERVATION_STATUS_ACTIVE: &str = "active";
const RESERVATION_STATUS_CONSUMED: &str = "consumed";
const RESERVATION_STATUS_EXPIRED: &str = "expired";
const RESERVATION_STATUS_RELEASED: &str = "released";
const WELCOME_STATUS_PENDING: &str = "pending";
const WELCOME_STATUS_ACKNOWLEDGED: &str = "acknowledged";
const WELCOME_STATUS_REJECTED: &str = "rejected";
const WELCOME_STATUS_EXPIRED: &str = "expired";
const WELCOME_STATUS_SUPERSEDED: &str = "superseded";
const WORK_SOURCE_KIND_WELCOME_EXPIRED: &str = "welcomeExpired";
const WORK_SOURCE_KIND_WELCOME_REJECTED: &str = "welcomeRejected";
const WORK_STATUS_PENDING: &str = "pending";
const WORK_STATUS_COMPLETED: &str = "completed";
const WORK_STATUS_SUPERSEDED: &str = "superseded";
const AVATAR_PURPOSE_METADATA: &str = "metadata";
/// ArtifactHash and every SHA-256 field: exact 32 bytes.
const EXACT_SHA256_BYTES: usize = 32;
/// `IdentifierBytes` (`MetadataCryptoContext.conversationId`): exact 16 bytes.
const EXACT_IDENTIFIER_BYTES: usize = 16;
/// MLS 1.0 `KeyPackageRef` is RefHash over the exact inner KeyPackage TLS
/// bytes (SHA-256): exact 32 bytes.
const EXACT_KEY_PACKAGE_REF_BYTES: usize = 32;
/// Ed25519 public keys in the metadata author proof: exact 32 bytes.
const EXACT_ED25519_PUBLIC_KEY_BYTES: usize = 32;
/// Metadata AES-256-GCM nonce is a fresh 96-bit CSPRNG value: exact 12 bytes.
const EXACT_GCM_NONCE_BYTES: usize = 12;

fn checked_nonempty(value: &str, path: &str) -> Result<(), ProjectionError> {
    if value.is_empty() {
        return Err(ProjectionError::new(
            ProjectionErrorKind::MissingField,
            path,
            "required field is empty",
        ));
    }
    Ok(())
}

fn checked_enum(value: &str, allowed: &[&str], path: &str) -> Result<(), ProjectionError> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(ProjectionError::new(
            ProjectionErrorKind::StringEnumViolation,
            path,
            "value is not a member of the closed vocabulary",
        ))
    }
}

fn checked_datetime(value: &str, path: &str) -> Result<(), ProjectionError> {
    CanonicalTimestamp::parse(value).map(|_| ()).map_err(|_| {
        ProjectionError::new(
            ProjectionErrorKind::InvalidDatetime,
            path,
            "datetime is not the checked canonical UTC text",
        )
    })
}

fn checked_sequence(value: i64, minimum: i64, path: &str) -> Result<(), ProjectionError> {
    if value < minimum {
        return Err(ProjectionError::new(
            ProjectionErrorKind::IntegerOutOfRange,
            path,
            "sequence integer is below its checked minimum",
        ));
    }
    Ok(())
}

fn checked_exact_bytes(value: &[u8], expected: usize, path: &str) -> Result<(), ProjectionError> {
    if value.len() != expected {
        return Err(ProjectionError::new(
            ProjectionErrorKind::InvalidByteLength,
            path,
            "byte field violates its exact pinned length",
        ));
    }
    Ok(())
}

fn checked_did(value: &str, path: &str) -> Result<Did<SmolStr>, ProjectionError> {
    Did::new(SmolStr::from(value)).map_err(|_| {
        ProjectionError::new(
            ProjectionErrorKind::InvalidDid,
            path,
            "value is not a valid AT Protocol DID",
        )
    })
}

fn source_inconsistency(path: &str, reason: &'static str) -> ProjectionError {
    ProjectionError::new(ProjectionErrorKind::InconsistentSourceFields, path, reason)
}

/// Checked conversation coordinates (`blue.catbird.chat.defs#conversationCoordinates`).
#[derive(Eq, PartialEq)]
pub(crate) struct CheckedConversationCoordinates {
    conversation_id: SmolStr,
    generation: i64,
    state_version: i64,
    group_id: Bytes,
    epoch: i64,
    group_context_hash: Bytes,
    confirmation_tag: Bytes,
    lifecycle: SmolStr,
}

impl CheckedConversationCoordinates {
    pub(crate) fn new(
        conversation_id: &str,
        generation: i64,
        state_version: i64,
        group_id: &[u8],
        epoch: i64,
        group_context_hash: &[u8],
        confirmation_tag: &[u8],
        lifecycle: &str,
    ) -> Result<Self, ProjectionError> {
        checked_nonempty(conversation_id, "coordinates.conversationId")?;
        checked_sequence(generation, 0, "coordinates.generation")?;
        checked_sequence(state_version, 0, "coordinates.stateVersion")?;
        checked_sequence(epoch, 0, "coordinates.epoch")?;
        checked_enum(
            lifecycle,
            &[LIFECYCLE_ACTIVE, LIFECYCLE_SUPERSEDED],
            "coordinates.lifecycle",
        )?;
        Ok(Self {
            conversation_id: SmolStr::from(conversation_id),
            generation,
            state_version,
            group_id: Bytes::copy_from_slice(group_id),
            epoch,
            group_context_hash: Bytes::copy_from_slice(group_context_hash),
            confirmation_tag: Bytes::copy_from_slice(confirmation_tag),
            lifecycle: SmolStr::from(lifecycle),
        })
    }
}

/// Checked invitation provenance (`blue.catbird.chat.defs#invitationProvenance`).
pub(crate) struct CheckedInvitationProvenance {
    invitation_transition_id: SmolStr,
    invited_by_did: Did<SmolStr>,
    invited_by_device_id: SmolStr,
}

impl CheckedInvitationProvenance {
    pub(crate) fn new(
        invitation_transition_id: &str,
        invited_by_did: &str,
        invited_by_device_id: &str,
    ) -> Result<Self, ProjectionError> {
        checked_nonempty(
            invitation_transition_id,
            "invitationProvenance.invitationTransitionId",
        )?;
        checked_nonempty(
            invited_by_device_id,
            "invitationProvenance.invitedByDeviceId",
        )?;
        Ok(Self {
            invitation_transition_id: SmolStr::from(invitation_transition_id),
            invited_by_did: checked_did(invited_by_did, "invitationProvenance.invitedByDid")?,
            invited_by_device_id: SmolStr::from(invited_by_device_id),
        })
    }
}

/// Checked device leaf view (`blue.catbird.chat.defs#deviceLeafView`).
///
/// `genesis` forbids `joinKeyPackageRef`; `keyPackage` requires it (the
/// consumed Add package's exact RefHash).
pub(crate) struct CheckedDeviceLeafView {
    user_did: Did<SmolStr>,
    device_id: SmolStr,
    leaf_origin: SmolStr,
    key_id: SmolStr,
    device_status: SmolStr,
    join_key_package_ref: Option<Bytes>,
}

impl CheckedDeviceLeafView {
    pub(crate) fn new(
        user_did: &str,
        device_id: &str,
        leaf_origin: &str,
        key_id: &str,
        device_status: &str,
        join_key_package_ref: Option<&[u8]>,
    ) -> Result<Self, ProjectionError> {
        checked_nonempty(device_id, "leaf.deviceId")?;
        checked_nonempty(key_id, "leaf.keyId")?;
        checked_enum(
            leaf_origin,
            &[LEAF_ORIGIN_GENESIS, LEAF_ORIGIN_KEY_PACKAGE],
            "leaf.leafOrigin",
        )?;
        checked_enum(
            device_status,
            &[DEVICE_STATUS_ACTIVE, DEVICE_STATUS_REVOKED],
            "leaf.deviceStatus",
        )?;
        let join_key_package_ref = match (leaf_origin, join_key_package_ref) {
            (LEAF_ORIGIN_GENESIS, Some(_)) => {
                return Err(source_inconsistency(
                    "leaf.joinKeyPackageRef",
                    "a genesis leaf forbids joinKeyPackageRef",
                ))
            }
            (LEAF_ORIGIN_KEY_PACKAGE, None) => {
                return Err(source_inconsistency(
                    "leaf.joinKeyPackageRef",
                    "a keyPackage leaf requires joinKeyPackageRef",
                ))
            }
            (_, bytes) => bytes.map(Bytes::copy_from_slice),
        };
        Ok(Self {
            user_did: checked_did(user_did, "leaf.userDid")?,
            device_id: SmolStr::from(device_id),
            leaf_origin: SmolStr::from(leaf_origin),
            key_id: SmolStr::from(key_id),
            device_status: SmolStr::from(device_status),
            join_key_package_ref,
        })
    }
}

/// Checked participant view (`blue.catbird.chat.defs#participantView`).
///
/// A pending participant has zero leaves and immutable invitation
/// provenance; a group pending participant is a member, the sole direct
/// invitee is admin.
pub(crate) struct CheckedParticipantView {
    user_did: Did<SmolStr>,
    role: SmolStr,
    status: SmolStr,
    leaf_count: i64,
    invitation_provenance: Option<CheckedInvitationProvenance>,
}

impl CheckedParticipantView {
    pub(crate) fn new(
        user_did: &str,
        role: &str,
        status: &str,
        leaf_count: i64,
        invitation_provenance: Option<CheckedInvitationProvenance>,
    ) -> Result<Self, ProjectionError> {
        checked_enum(
            role,
            &[MEMBER_ROLE_ADMIN, MEMBER_ROLE_MEMBER],
            "participant.role",
        )?;
        checked_enum(
            status,
            &[PARTICIPANT_STATUS_PENDING, PARTICIPANT_STATUS_ACTIVE],
            "participant.status",
        )?;
        checked_sequence(leaf_count, 0, "participant.leafCount")?;
        if status == PARTICIPANT_STATUS_PENDING {
            if leaf_count != 0 {
                return Err(source_inconsistency(
                    "participant.leafCount",
                    "a pending participant can never be an MLS leaf",
                ));
            }
            if invitation_provenance.is_none() {
                return Err(source_inconsistency(
                    "participant.invitationProvenance",
                    "a pending participant requires immutable invitation provenance",
                ));
            }
        }
        Ok(Self {
            user_did: checked_did(user_did, "participant.userDid")?,
            role: SmolStr::from(role),
            status: SmolStr::from(status),
            leaf_count,
            invitation_provenance,
        })
    }
}

/// Checked metadata author proof (`blue.catbird.chat.defs#metadataAuthorProof`).
pub(crate) struct CheckedMetadataAuthorProof {
    author_did: Did<SmolStr>,
    author_device_id: SmolStr,
    author_key_id: SmolStr,
    signature_public_key: Bytes,
    auth_generation_at_origin: i64,
    origin_transition_id: SmolStr,
    origin_seq: i64,
    role_at_origin: SmolStr,
    device_status_at_origin: SmolStr,
}

impl CheckedMetadataAuthorProof {
    pub(crate) fn new(
        author_did: &str,
        author_device_id: &str,
        author_key_id: &str,
        signature_public_key: &[u8],
        auth_generation_at_origin: i64,
        origin_transition_id: &str,
        origin_seq: i64,
        role_at_origin: &str,
        device_status_at_origin: &str,
    ) -> Result<Self, ProjectionError> {
        checked_nonempty(author_device_id, "authorProof.authorDeviceId")?;
        checked_nonempty(author_key_id, "authorProof.authorKeyId")?;
        checked_exact_bytes(
            signature_public_key,
            EXACT_ED25519_PUBLIC_KEY_BYTES,
            "authorProof.signaturePublicKey",
        )?;
        checked_sequence(
            auth_generation_at_origin,
            1,
            "authorProof.authGenerationAtOrigin",
        )?;
        checked_nonempty(origin_transition_id, "authorProof.originTransitionId")?;
        checked_sequence(origin_seq, 1, "authorProof.originSeq")?;
        checked_nonempty(role_at_origin, "authorProof.roleAtOrigin")?;
        checked_nonempty(device_status_at_origin, "authorProof.deviceStatusAtOrigin")?;
        Ok(Self {
            author_did: checked_did(author_did, "authorProof.authorDid")?,
            author_device_id: SmolStr::from(author_device_id),
            author_key_id: SmolStr::from(author_key_id),
            signature_public_key: Bytes::copy_from_slice(signature_public_key),
            auth_generation_at_origin,
            origin_transition_id: SmolStr::from(origin_transition_id),
            origin_seq,
            role_at_origin: SmolStr::from(role_at_origin),
            device_status_at_origin: SmolStr::from(device_status_at_origin),
        })
    }
}

/// Checked metadata avatar binding (`blue.catbird.chat.defs#metadataAvatarBinding`).
///
/// The binding purpose is exactly `metadata`; an attachment-purpose upload
/// cannot inhabit the metadata snapshot.
pub(crate) struct CheckedMetadataAvatarBinding {
    blob_id: SmolStr,
    ciphertext_sha256: Bytes,
    ciphertext_size: i64,
    purpose: SmolStr,
}

impl CheckedMetadataAvatarBinding {
    pub(crate) fn new(
        blob_id: &str,
        ciphertext_sha256: &[u8],
        ciphertext_size: i64,
        purpose: &str,
    ) -> Result<Self, ProjectionError> {
        checked_nonempty(blob_id, "avatarBinding.blobId")?;
        checked_exact_bytes(
            ciphertext_sha256,
            EXACT_SHA256_BYTES,
            "avatarBinding.ciphertextSha256",
        )?;
        checked_sequence(ciphertext_size, 16, "avatarBinding.ciphertextSize")?;
        if purpose != AVATAR_PURPOSE_METADATA {
            return Err(source_inconsistency(
                "avatarBinding.purpose",
                "the metadata avatar binding purpose is exactly metadata",
            ));
        }
        Ok(Self {
            blob_id: SmolStr::from(blob_id),
            ciphertext_sha256: Bytes::copy_from_slice(ciphertext_sha256),
            ciphertext_size,
            purpose: SmolStr::from(purpose),
        })
    }
}

/// Checked metadata crypto context (`blue.catbird.chat.defs#metadataCryptoContext`).
pub(crate) struct CheckedMetadataCryptoContext {
    conversation_id: Bytes,
    generation: i64,
    group_id: Bytes,
    epoch: i64,
    group_context_hash: Bytes,
    confirmation_tag: Bytes,
}

impl CheckedMetadataCryptoContext {
    pub(crate) fn new(
        conversation_id: &[u8],
        generation: i64,
        group_id: &[u8],
        epoch: i64,
        group_context_hash: &[u8],
        confirmation_tag: &[u8],
    ) -> Result<Self, ProjectionError> {
        checked_exact_bytes(
            conversation_id,
            EXACT_IDENTIFIER_BYTES,
            "metadataCryptoContext.conversationId",
        )?;
        checked_sequence(generation, 0, "metadataCryptoContext.generation")?;
        checked_sequence(epoch, 0, "metadataCryptoContext.epoch")?;
        Ok(Self {
            conversation_id: Bytes::copy_from_slice(conversation_id),
            generation,
            group_id: Bytes::copy_from_slice(group_id),
            epoch,
            group_context_hash: Bytes::copy_from_slice(group_context_hash),
            confirmation_tag: Bytes::copy_from_slice(confirmation_tag),
        })
    }
}

/// Checked metadata snapshot (`blue.catbird.chat.defs#metadataSnapshot`).
pub(crate) struct CheckedMetadataSnapshot {
    coordinate: CheckedMetadataCryptoContext,
    origin_transition_id: SmolStr,
    metadata_version: i64,
    nonce: Bytes,
    ciphertext: Bytes,
    ciphertext_sha256: Bytes,
    ciphertext_size: i64,
    author_proof: CheckedMetadataAuthorProof,
    avatar_binding: Option<CheckedMetadataAvatarBinding>,
}

impl CheckedMetadataSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        coordinate: CheckedMetadataCryptoContext,
        origin_transition_id: &str,
        metadata_version: i64,
        nonce: &[u8],
        ciphertext: &[u8],
        ciphertext_sha256: &[u8],
        ciphertext_size: i64,
        author_proof: CheckedMetadataAuthorProof,
        avatar_binding: Option<CheckedMetadataAvatarBinding>,
    ) -> Result<Self, ProjectionError> {
        checked_nonempty(origin_transition_id, "metadataSnapshot.originTransitionId")?;
        checked_sequence(metadata_version, 1, "metadataSnapshot.metadataVersion")?;
        checked_exact_bytes(nonce, EXACT_GCM_NONCE_BYTES, "metadataSnapshot.nonce")?;
        checked_exact_bytes(
            ciphertext_sha256,
            EXACT_SHA256_BYTES,
            "metadataSnapshot.ciphertextSha256",
        )?;
        checked_sequence(ciphertext_size, 16, "metadataSnapshot.ciphertextSize")?;
        Ok(Self {
            coordinate,
            origin_transition_id: SmolStr::from(origin_transition_id),
            metadata_version,
            nonce: Bytes::copy_from_slice(nonce),
            ciphertext: Bytes::copy_from_slice(ciphertext),
            ciphertext_sha256: Bytes::copy_from_slice(ciphertext_sha256),
            ciphertext_size,
            author_proof,
            avatar_binding,
        })
    }
}

/// Checked key-package artifact (`blue.catbird.chat.defs#keyPackageArtifact`).
pub(crate) struct CheckedKeyPackageArtifact {
    framing: SmolStr,
    content_type: SmolStr,
    bytes: Bytes,
    sha256: Bytes,
    key_package_ref: Bytes,
}

impl CheckedKeyPackageArtifact {
    pub(crate) fn new(
        framing: &str,
        content_type: &str,
        bytes: &[u8],
        sha256: &[u8],
        key_package_ref: &[u8],
    ) -> Result<Self, ProjectionError> {
        checked_nonempty(framing, "keyPackage.framing")?;
        checked_nonempty(content_type, "keyPackage.contentType")?;
        checked_exact_bytes(sha256, EXACT_SHA256_BYTES, "keyPackage.sha256")?;
        checked_exact_bytes(
            key_package_ref,
            EXACT_KEY_PACKAGE_REF_BYTES,
            "keyPackage.keyPackageRef",
        )?;
        Ok(Self {
            framing: SmolStr::from(framing),
            content_type: SmolStr::from(content_type),
            bytes: Bytes::copy_from_slice(bytes),
            sha256: Bytes::copy_from_slice(sha256),
            key_package_ref: Bytes::copy_from_slice(key_package_ref),
        })
    }
}

/// Checked leaf-recovery reservation (`blue.catbird.chat.defs#leafRecoveryReservation`).
pub(crate) struct CheckedLeafRecoveryReservation {
    recovery_request_id: SmolStr,
    conversation_id: SmolStr,
    bound_coordinate: CheckedConversationCoordinates,
    requester_did: Did<SmolStr>,
    requester_device_id: SmolStr,
    requester_key_id: SmolStr,
    requester_auth_generation: i64,
    key_package_ref: Bytes,
    cipher_suite: SmolStr,
    purpose: SmolStr,
    status: SmolStr,
    expires_at: SmolStr,
    key_package: CheckedKeyPackageArtifact,
}

impl CheckedLeafRecoveryReservation {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        recovery_request_id: &str,
        conversation_id: &str,
        bound_coordinate: CheckedConversationCoordinates,
        requester_did: &str,
        requester_device_id: &str,
        requester_key_id: &str,
        requester_auth_generation: i64,
        key_package_ref: &[u8],
        cipher_suite: &str,
        purpose: &str,
        status: &str,
        expires_at: &str,
        key_package: CheckedKeyPackageArtifact,
    ) -> Result<Self, ProjectionError> {
        checked_nonempty(recovery_request_id, "reservation.recoveryRequestId")?;
        checked_nonempty(conversation_id, "reservation.conversationId")?;
        checked_nonempty(requester_device_id, "reservation.requesterDeviceId")?;
        checked_nonempty(requester_key_id, "reservation.requesterKeyId")?;
        checked_sequence(
            requester_auth_generation,
            1,
            "reservation.requesterAuthGeneration",
        )?;
        checked_exact_bytes(
            key_package_ref,
            EXACT_KEY_PACKAGE_REF_BYTES,
            "reservation.keyPackageRef",
        )?;
        checked_enum(cipher_suite, &[CIPHER_SUITE_V1], "reservation.cipherSuite")?;
        checked_nonempty(purpose, "reservation.purpose")?;
        checked_enum(
            status,
            &[
                RESERVATION_STATUS_ACTIVE,
                RESERVATION_STATUS_CONSUMED,
                RESERVATION_STATUS_EXPIRED,
                RESERVATION_STATUS_RELEASED,
            ],
            "reservation.status",
        )?;
        checked_datetime(expires_at, "reservation.expiresAt")?;
        Ok(Self {
            recovery_request_id: SmolStr::from(recovery_request_id),
            conversation_id: SmolStr::from(conversation_id),
            bound_coordinate,
            requester_did: checked_did(requester_did, "reservation.requesterDid")?,
            requester_device_id: SmolStr::from(requester_device_id),
            requester_key_id: SmolStr::from(requester_key_id),
            requester_auth_generation,
            key_package_ref: Bytes::copy_from_slice(key_package_ref),
            cipher_suite: SmolStr::from(cipher_suite),
            purpose: SmolStr::from(purpose),
            status: SmolStr::from(status),
            expires_at: SmolStr::from(expires_at),
            key_package,
        })
    }
}

/// Checked recovery-Welcome provenance (`blue.catbird.chat.defs#recoveryWelcomeProvenance`).
pub(crate) struct CheckedWelcomeProvenance {
    recovery_request_id: SmolStr,
    key_package_ref: Bytes,
}

impl CheckedWelcomeProvenance {
    pub(crate) fn new(
        recovery_request_id: &str,
        key_package_ref: &[u8],
    ) -> Result<Self, ProjectionError> {
        checked_nonempty(recovery_request_id, "provenance.recoveryRequestId")?;
        checked_exact_bytes(
            key_package_ref,
            EXACT_KEY_PACKAGE_REF_BYTES,
            "provenance.keyPackageRef",
        )?;
        Ok(Self {
            recovery_request_id: SmolStr::from(recovery_request_id),
            key_package_ref: Bytes::copy_from_slice(key_package_ref),
        })
    }
}

/// Checked conversation-state projection source (closed state/removal/close
/// union). The removal arm yields only its tombstone
/// (`AccessOutsideMembershipInterval`-shaped semantics); the close arm yields
/// only the close tombstone.
pub(crate) enum ConversationProjectionSource {
    State(CheckedConversationState),
    Removal(CheckedConversationRemoval),
    Close(CheckedConversationClose),
}

pub(crate) struct CheckedConversationState {
    cipher_suite: SmolStr,
    conversation_kind: SmolStr,
    coordinates: CheckedConversationCoordinates,
    leaves: Vec<CheckedDeviceLeafView>,
    metadata_snapshot: CheckedMetadataSnapshot,
    participants: Vec<CheckedParticipantView>,
    snapshot_seq: i64,
}

pub(crate) struct CheckedConversationRemoval {
    conversation_id: SmolStr,
    user_did: Did<SmolStr>,
    device_id: SmolStr,
    membership_interval_id: SmolStr,
    removed_at: SmolStr,
    terminal_seq: i64,
}

pub(crate) struct CheckedConversationClose {
    closed_at: SmolStr,
    closed_by_did: Did<SmolStr>,
    closed_by_device_id: SmolStr,
    conversation_id: SmolStr,
    conversation_kind: SmolStr,
    retired: CheckedConversationCoordinates,
    terminal_seq: i64,
}

impl ConversationProjectionSource {
    pub(crate) fn state(
        cipher_suite: &str,
        conversation_kind: &str,
        coordinates: CheckedConversationCoordinates,
        leaves: Vec<CheckedDeviceLeafView>,
        metadata_snapshot: CheckedMetadataSnapshot,
        participants: Vec<CheckedParticipantView>,
        snapshot_seq: i64,
    ) -> Result<Self, ProjectionError> {
        checked_enum(cipher_suite, &[CIPHER_SUITE_V1], "cipherSuite")?;
        checked_enum(
            conversation_kind,
            &[CONVERSATION_KIND_DIRECT, CONVERSATION_KIND_GROUP],
            "conversationKind",
        )?;
        checked_sequence(snapshot_seq, 0, "snapshotSeq")?;
        for (index, pair) in leaves.windows(2).enumerate() {
            let (left, right) = (&pair[0], &pair[1]);
            let left_key = (left.user_did.as_str(), left.device_id.as_str());
            let right_key = (right.user_did.as_str(), right.device_id.as_str());
            if left_key >= right_key {
                return Err(source_inconsistency(
                    &format!("leaves[{index}]"),
                    "leaves must be strictly increasing by (userDid, deviceId) exact bytes",
                ));
            }
        }
        for (index, pair) in participants.windows(2).enumerate() {
            let (left, right) = (&pair[0], &pair[1]);
            if left.user_did.as_str() >= right.user_did.as_str() {
                return Err(source_inconsistency(
                    &format!("participants[{index}]"),
                    "participants must be strictly increasing by userDid exact UTF-8 bytes",
                ));
            }
        }
        Ok(Self::State(CheckedConversationState {
            cipher_suite: SmolStr::from(cipher_suite),
            conversation_kind: SmolStr::from(conversation_kind),
            coordinates,
            leaves,
            metadata_snapshot,
            participants,
            snapshot_seq,
        }))
    }

    pub(crate) fn removal(
        conversation_id: &str,
        user_did: &str,
        device_id: &str,
        membership_interval_id: &str,
        removed_at: &str,
        terminal_seq: i64,
    ) -> Result<Self, ProjectionError> {
        checked_nonempty(conversation_id, "removal.conversationId")?;
        checked_nonempty(device_id, "removal.deviceId")?;
        checked_nonempty(membership_interval_id, "removal.membershipIntervalId")?;
        checked_datetime(removed_at, "removal.removedAt")?;
        checked_sequence(terminal_seq, 1, "removal.terminalSeq")?;
        Ok(Self::Removal(CheckedConversationRemoval {
            conversation_id: SmolStr::from(conversation_id),
            user_did: checked_did(user_did, "removal.userDid")?,
            device_id: SmolStr::from(device_id),
            membership_interval_id: SmolStr::from(membership_interval_id),
            removed_at: SmolStr::from(removed_at),
            terminal_seq,
        }))
    }

    pub(crate) fn close(
        closed_at: &str,
        closed_by_did: &str,
        closed_by_device_id: &str,
        conversation_id: &str,
        conversation_kind: &str,
        retired: CheckedConversationCoordinates,
        terminal_seq: i64,
    ) -> Result<Self, ProjectionError> {
        checked_datetime(closed_at, "close.closedAt")?;
        checked_nonempty(closed_by_device_id, "close.closedByDeviceId")?;
        checked_nonempty(conversation_id, "close.conversationId")?;
        checked_enum(
            conversation_kind,
            &[CONVERSATION_KIND_DIRECT, CONVERSATION_KIND_GROUP],
            "close.conversationKind",
        )?;
        checked_sequence(terminal_seq, 1, "close.terminalSeq")?;
        if retired.conversation_id.as_str() != conversation_id {
            return Err(source_inconsistency(
                "close.retired.conversationId",
                "the retired coordinates must name the closed conversation",
            ));
        }
        Ok(Self::Close(CheckedConversationClose {
            closed_at: SmolStr::from(closed_at),
            closed_by_did: checked_did(closed_by_did, "close.closedByDid")?,
            closed_by_device_id: SmolStr::from(closed_by_device_id),
            conversation_id: SmolStr::from(conversation_id),
            conversation_kind: SmolStr::from(conversation_kind),
            retired,
            terminal_seq,
        }))
    }
}

/// Checked retained-Welcome projection source.
///
/// One immutable recipient row is retained for every Welcome delivery;
/// `sha256` is the exact 32-byte SHA-256 of the opaque Welcome bytes and
/// `expiresAt` is the canonical UTC datetime representation of the exact
/// consumed Add KeyPackage not_after Unix second.
pub(crate) struct RetainedWelcomeProjectionSource {
    welcome_id: SmolStr,
    conversation_id: SmolStr,
    transition_seq: i64,
    coordinates: CheckedConversationCoordinates,
    status: SmolStr,
    opaque_welcome: Bytes,
    sha256: Bytes,
    recipient_did: Did<SmolStr>,
    recipient_device_id: SmolStr,
    provenance: CheckedWelcomeProvenance,
    expires_at: SmolStr,
}

impl RetainedWelcomeProjectionSource {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        welcome_id: &str,
        conversation_id: &str,
        transition_seq: i64,
        coordinates: CheckedConversationCoordinates,
        status: &str,
        opaque_welcome: &[u8],
        sha256: &[u8],
        recipient_did: &str,
        recipient_device_id: &str,
        provenance: CheckedWelcomeProvenance,
        expires_at: &str,
    ) -> Result<Self, ProjectionError> {
        checked_nonempty(welcome_id, "welcome.welcomeId")?;
        checked_nonempty(conversation_id, "welcome.conversationId")?;
        checked_sequence(transition_seq, 1, "welcome.transitionSeq")?;
        checked_enum(
            status,
            &[
                WELCOME_STATUS_PENDING,
                WELCOME_STATUS_ACKNOWLEDGED,
                WELCOME_STATUS_REJECTED,
                WELCOME_STATUS_EXPIRED,
                WELCOME_STATUS_SUPERSEDED,
            ],
            "welcome.status",
        )?;
        checked_exact_bytes(sha256, EXACT_SHA256_BYTES, "welcome.sha256")?;
        checked_nonempty(recipient_device_id, "welcome.recipientDeviceId")?;
        checked_datetime(expires_at, "welcome.expiresAt")?;
        if coordinates.conversation_id.as_str() != conversation_id {
            return Err(source_inconsistency(
                "welcome.coordinates.conversationId",
                "the Welcome coordinates must name the welcome's conversation",
            ));
        }
        Ok(Self {
            welcome_id: SmolStr::from(welcome_id),
            conversation_id: SmolStr::from(conversation_id),
            transition_seq,
            coordinates,
            status: SmolStr::from(status),
            opaque_welcome: Bytes::copy_from_slice(opaque_welcome),
            sha256: Bytes::copy_from_slice(sha256),
            recipient_did: checked_did(recipient_did, "welcome.recipientDid")?,
            recipient_device_id: SmolStr::from(recipient_device_id),
            provenance,
            expires_at: SmolStr::from(expires_at),
        })
    }
}

/// Checked retained leaf-recovery projection source.
///
/// The reservation is bound to the requester's signed recovery request,
/// identity, and bound coordinate, and its status is consistent with the
/// retained view status (open->active, fulfilled->consumed,
/// cancelled->released, superseded->released, expired->expired).
pub(crate) struct RetainedLeafRecoveryProjectionSource {
    recovery_request_id: SmolStr,
    conversation_id: SmolStr,
    requester_did: Did<SmolStr>,
    requester_device_id: SmolStr,
    recovery_kind: SmolStr,
    bound_coordinate: CheckedConversationCoordinates,
    status: SmolStr,
    requested_at: SmolStr,
    expires_at: SmolStr,
    reservation: CheckedLeafRecoveryReservation,
}

impl RetainedLeafRecoveryProjectionSource {
    pub(crate) fn new(
        recovery_request_id: &str,
        conversation_id: &str,
        requester_did: &str,
        requester_device_id: &str,
        recovery_kind: &str,
        bound_coordinate: CheckedConversationCoordinates,
        status: &str,
        requested_at: &str,
        expires_at: &str,
        reservation: CheckedLeafRecoveryReservation,
    ) -> Result<Self, ProjectionError> {
        checked_nonempty(recovery_request_id, "leafRecovery.recoveryRequestId")?;
        checked_nonempty(conversation_id, "leafRecovery.conversationId")?;
        checked_nonempty(requester_device_id, "leafRecovery.requesterDeviceId")?;
        checked_enum(
            recovery_kind,
            &[LEAF_RECOVERY_KIND_ADD, LEAF_RECOVERY_KIND_REPLACE],
            "leafRecovery.recoveryKind",
        )?;
        checked_enum(
            status,
            &[
                LEAF_RECOVERY_STATUS_OPEN,
                LEAF_RECOVERY_STATUS_FULFILLED,
                LEAF_RECOVERY_STATUS_CANCELLED,
                LEAF_RECOVERY_STATUS_EXPIRED,
                LEAF_RECOVERY_STATUS_SUPERSEDED,
            ],
            "leafRecovery.status",
        )?;
        checked_datetime(requested_at, "leafRecovery.requestedAt")?;
        checked_datetime(expires_at, "leafRecovery.expiresAt")?;
        if reservation.recovery_request_id.as_str() != recovery_request_id {
            return Err(source_inconsistency(
                "reservation.recoveryRequestId",
                "the reservation must be bound to the exact recovery request",
            ));
        }
        if reservation.conversation_id.as_str() != conversation_id {
            return Err(source_inconsistency(
                "reservation.conversationId",
                "the reservation must name the exact conversation",
            ));
        }
        if reservation.requester_did.as_str() != requester_did
            || reservation.requester_device_id.as_str() != requester_device_id
        {
            return Err(source_inconsistency(
                "reservation.requester identity",
                "the reservation must be bound to the exact requester identity",
            ));
        }
        if reservation.bound_coordinate != bound_coordinate {
            return Err(source_inconsistency(
                "reservation.boundCoordinate",
                "the reservation bound coordinate must equal the view bound coordinate",
            ));
        }
        let expected_reservation_status = match status {
            LEAF_RECOVERY_STATUS_OPEN => RESERVATION_STATUS_ACTIVE,
            LEAF_RECOVERY_STATUS_FULFILLED => RESERVATION_STATUS_CONSUMED,
            LEAF_RECOVERY_STATUS_CANCELLED => RESERVATION_STATUS_RELEASED,
            LEAF_RECOVERY_STATUS_EXPIRED => RESERVATION_STATUS_EXPIRED,
            LEAF_RECOVERY_STATUS_SUPERSEDED => RESERVATION_STATUS_RELEASED,
            _ => unreachable!("status was enum-checked above"),
        };
        if reservation.status.as_str() != expected_reservation_status {
            return Err(source_inconsistency(
                "reservation.status",
                "reservation status is not consistent with the retained leaf-recovery status",
            ));
        }
        Ok(Self {
            recovery_request_id: SmolStr::from(recovery_request_id),
            conversation_id: SmolStr::from(conversation_id),
            requester_did: checked_did(requester_did, "leafRecovery.requesterDid")?,
            requester_device_id: SmolStr::from(requester_device_id),
            recovery_kind: SmolStr::from(recovery_kind),
            bound_coordinate,
            status: SmolStr::from(status),
            requested_at: SmolStr::from(requested_at),
            expires_at: SmolStr::from(expires_at),
            reservation,
        })
    }
}

/// Closed terminal shape of one retained recovery-work row: pending,
/// completed-by-transition, superseded-by-transition, or
/// superseded-by-revocation. The DTO status is derived from the arm, so a
/// terminal arm can never disagree with its status.
pub(crate) enum RetainedRecoveryWorkTerminal {
    Pending,
    CompletedByTransition {
        terminal_transition_id: SmolStr,
        terminal_at: SmolStr,
    },
    SupersededByTransition {
        terminal_transition_id: SmolStr,
        terminal_at: SmolStr,
    },
    SupersededByRevocation {
        terminal_revocation_id: SmolStr,
        terminal_at: SmolStr,
    },
}

/// Checked retained recovery-work projection source: common
/// work/conversation/recipient/source fields plus exactly one terminal arm
/// consistent with its status.
pub(crate) struct RetainedRecoveryWorkProjectionSource {
    recovery_work_id: SmolStr,
    conversation_id: SmolStr,
    recipient_did: Did<SmolStr>,
    recipient_device_id: SmolStr,
    source_kind: SmolStr,
    source_id: SmolStr,
    source_coordinate: CheckedConversationCoordinates,
    created_at: SmolStr,
    terminal: RetainedRecoveryWorkTerminal,
}

impl RetainedRecoveryWorkProjectionSource {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        recovery_work_id: &str,
        conversation_id: &str,
        recipient_did: &str,
        recipient_device_id: &str,
        source_kind: &str,
        source_id: &str,
        source_coordinate: CheckedConversationCoordinates,
        created_at: &str,
        terminal: RetainedRecoveryWorkTerminal,
    ) -> Result<Self, ProjectionError> {
        checked_nonempty(recovery_work_id, "recoveryWork.recoveryWorkId")?;
        checked_nonempty(conversation_id, "recoveryWork.conversationId")?;
        checked_nonempty(recipient_device_id, "recoveryWork.recipientDeviceId")?;
        checked_enum(
            source_kind,
            &[
                WORK_SOURCE_KIND_WELCOME_EXPIRED,
                WORK_SOURCE_KIND_WELCOME_REJECTED,
            ],
            "recoveryWork.sourceKind",
        )?;
        checked_nonempty(source_id, "recoveryWork.sourceId")?;
        checked_datetime(created_at, "recoveryWork.createdAt")?;
        match &terminal {
            RetainedRecoveryWorkTerminal::Pending => {}
            RetainedRecoveryWorkTerminal::CompletedByTransition {
                terminal_transition_id,
                terminal_at,
            }
            | RetainedRecoveryWorkTerminal::SupersededByTransition {
                terminal_transition_id,
                terminal_at,
            } => {
                checked_nonempty(terminal_transition_id, "recoveryWork.terminalTransitionId")?;
                checked_datetime(terminal_at, "recoveryWork.terminalAt")?;
            }
            RetainedRecoveryWorkTerminal::SupersededByRevocation {
                terminal_revocation_id,
                terminal_at,
            } => {
                checked_nonempty(terminal_revocation_id, "recoveryWork.terminalRevocationId")?;
                checked_datetime(terminal_at, "recoveryWork.terminalAt")?;
            }
        }
        if source_coordinate.conversation_id.as_str() != conversation_id {
            return Err(source_inconsistency(
                "recoveryWork.sourceCoordinate.conversationId",
                "the source coordinate must name the work's conversation",
            ));
        }
        Ok(Self {
            recovery_work_id: SmolStr::from(recovery_work_id),
            conversation_id: SmolStr::from(conversation_id),
            recipient_did: checked_did(recipient_did, "recoveryWork.recipientDid")?,
            recipient_device_id: SmolStr::from(recipient_device_id),
            source_kind: SmolStr::from(source_kind),
            source_id: SmolStr::from(source_id),
            source_coordinate,
            created_at: SmolStr::from(created_at),
            terminal,
        })
    }
}

/// Closed leaf-recovery inbox input: exactly the generated five variants.
/// A sixth variant is unrepresentable.
pub(crate) enum LeafRecoveryInboxInput {
    LeafRecoveryView(RetainedLeafRecoveryProjectionSource),
    RecoveryWorkPendingView(RetainedRecoveryWorkProjectionSource),
    RecoveryWorkCompletedByTransitionView(RetainedRecoveryWorkProjectionSource),
    RecoveryWorkSupersededByTransitionView(RetainedRecoveryWorkProjectionSource),
    RecoveryWorkSupersededByRevocationView(RetainedRecoveryWorkProjectionSource),
}

fn wrong_terminal_shape() -> ProjectionError {
    ProjectionError::new(
        ProjectionErrorKind::WrongTerminalShape,
        "",
        "inbox variant does not match the retained recovery-work terminal shape",
    )
}

impl LeafRecoveryInboxInput {
    pub(crate) fn leaf_recovery(source: RetainedLeafRecoveryProjectionSource) -> Self {
        Self::LeafRecoveryView(source)
    }

    pub(crate) fn recovery_work_pending(
        source: RetainedRecoveryWorkProjectionSource,
    ) -> Result<Self, ProjectionError> {
        match source.terminal {
            RetainedRecoveryWorkTerminal::Pending => Ok(Self::RecoveryWorkPendingView(source)),
            _ => Err(wrong_terminal_shape()),
        }
    }

    pub(crate) fn recovery_work_completed_by_transition(
        source: RetainedRecoveryWorkProjectionSource,
    ) -> Result<Self, ProjectionError> {
        match source.terminal {
            RetainedRecoveryWorkTerminal::CompletedByTransition { .. } => {
                Ok(Self::RecoveryWorkCompletedByTransitionView(source))
            }
            _ => Err(wrong_terminal_shape()),
        }
    }

    pub(crate) fn recovery_work_superseded_by_transition(
        source: RetainedRecoveryWorkProjectionSource,
    ) -> Result<Self, ProjectionError> {
        match source.terminal {
            RetainedRecoveryWorkTerminal::SupersededByTransition { .. } => {
                Ok(Self::RecoveryWorkSupersededByTransitionView(source))
            }
            _ => Err(wrong_terminal_shape()),
        }
    }

    pub(crate) fn recovery_work_superseded_by_revocation(
        source: RetainedRecoveryWorkProjectionSource,
    ) -> Result<Self, ProjectionError> {
        match source.terminal {
            RetainedRecoveryWorkTerminal::SupersededByRevocation { .. } => {
                Ok(Self::RecoveryWorkSupersededByRevocationView(source))
            }
            _ => Err(wrong_terminal_shape()),
        }
    }
}

fn require_terminal_shape(
    source: &RetainedRecoveryWorkProjectionSource,
    shape_ok: impl FnOnce(&RetainedRecoveryWorkTerminal) -> bool,
) -> Result<(), ProjectionError> {
    if shape_ok(&source.terminal) {
        Ok(())
    } else {
        Err(wrong_terminal_shape())
    }
}

pub(crate) fn conversation_coordinates_dto(
    coordinates: &CheckedConversationCoordinates,
) -> chat_dto::ConversationCoordinates<DefaultStr> {
    chat_dto::ConversationCoordinates {
        conversation_id: coordinates.conversation_id.clone(),
        generation: coordinates.generation,
        state_version: coordinates.state_version,
        group_id: coordinates.group_id.clone(),
        epoch: coordinates.epoch,
        group_context_hash: coordinates.group_context_hash.clone(),
        confirmation_tag: coordinates.confirmation_tag.clone(),
        lifecycle: coordinates.lifecycle.clone(),
        extra_data: None,
    }
}

/// Project the checked conversation source to the generated
/// `ConversationState` DTO. A removal or close arm has no historical
/// `conversationState` (`AccessOutsideMembershipInterval`-shaped tombstone
/// semantics) and fails before any state materializes.
pub(crate) fn conversation_state_view(
    source: &ConversationProjectionSource,
) -> Result<chat_dto::ConversationState<DefaultStr>, ProjectionError> {
    let ConversationProjectionSource::State(state) = source else {
        return Err(ProjectionError::new(
            ProjectionErrorKind::NoConversationStateProjection,
            "",
            "removal/close arms project only their tombstone (AccessOutsideMembershipInterval-shaped semantics); no historical conversationState exists",
        ));
    };
    Ok(chat_dto::ConversationState {
        cipher_suite: state.cipher_suite.clone(),
        conversation_kind: state.conversation_kind.clone(),
        coordinates: conversation_coordinates_dto(&state.coordinates),
        leaves: state
            .leaves
            .iter()
            .map(|leaf| chat_dto::DeviceLeafView {
                user_did: leaf.user_did.clone(),
                device_id: leaf.device_id.clone(),
                leaf_origin: leaf.leaf_origin.clone(),
                key_id: leaf.key_id.clone(),
                device_status: leaf.device_status.clone(),
                join_key_package_ref: leaf.join_key_package_ref.clone(),
                extra_data: None,
            })
            .collect(),
        metadata_snapshot: chat_dto::MetadataSnapshot {
            coordinate: chat_dto::MetadataCryptoContext {
                conversation_id: state.metadata_snapshot.coordinate.conversation_id.clone(),
                generation: state.metadata_snapshot.coordinate.generation,
                group_id: state.metadata_snapshot.coordinate.group_id.clone(),
                epoch: state.metadata_snapshot.coordinate.epoch,
                group_context_hash: state
                    .metadata_snapshot
                    .coordinate
                    .group_context_hash
                    .clone(),
                confirmation_tag: state.metadata_snapshot.coordinate.confirmation_tag.clone(),
                extra_data: None,
            },
            origin_transition_id: state.metadata_snapshot.origin_transition_id.clone(),
            metadata_version: state.metadata_snapshot.metadata_version,
            nonce: state.metadata_snapshot.nonce.clone(),
            ciphertext: state.metadata_snapshot.ciphertext.clone(),
            ciphertext_sha256: state.metadata_snapshot.ciphertext_sha256.clone(),
            ciphertext_size: state.metadata_snapshot.ciphertext_size,
            author_proof: chat_dto::MetadataAuthorProof {
                author_did: state.metadata_snapshot.author_proof.author_did.clone(),
                author_device_id: state
                    .metadata_snapshot
                    .author_proof
                    .author_device_id
                    .clone(),
                author_key_id: state.metadata_snapshot.author_proof.author_key_id.clone(),
                signature_public_key: state
                    .metadata_snapshot
                    .author_proof
                    .signature_public_key
                    .clone(),
                auth_generation_at_origin: state
                    .metadata_snapshot
                    .author_proof
                    .auth_generation_at_origin,
                origin_transition_id: state
                    .metadata_snapshot
                    .author_proof
                    .origin_transition_id
                    .clone(),
                origin_seq: state.metadata_snapshot.author_proof.origin_seq,
                role_at_origin: state.metadata_snapshot.author_proof.role_at_origin.clone(),
                device_status_at_origin: state
                    .metadata_snapshot
                    .author_proof
                    .device_status_at_origin
                    .clone(),
                extra_data: None,
            },
            avatar_binding: state
                .metadata_snapshot
                .avatar_binding
                .as_ref()
                .map(|binding| chat_dto::MetadataAvatarBinding {
                    blob_id: binding.blob_id.clone(),
                    ciphertext_sha256: binding.ciphertext_sha256.clone(),
                    ciphertext_size: binding.ciphertext_size,
                    purpose: binding.purpose.clone(),
                    extra_data: None,
                }),
            extra_data: None,
        },
        participants: state
            .participants
            .iter()
            .map(|participant| chat_dto::ParticipantView {
                user_did: participant.user_did.clone(),
                role: participant.role.clone(),
                status: participant.status.clone(),
                leaf_count: participant.leaf_count,
                invitation_provenance: participant.invitation_provenance.as_ref().map(
                    |provenance| chat_dto::InvitationProvenance {
                        invitation_transition_id: provenance.invitation_transition_id.clone(),
                        invited_by_did: provenance.invited_by_did.clone(),
                        invited_by_device_id: provenance.invited_by_device_id.clone(),
                        extra_data: None,
                    },
                ),
                extra_data: None,
            })
            .collect(),
        snapshot_seq: state.snapshot_seq,
        extra_data: None,
    })
}

/// Project the checked conversation source to the generated
/// `ConversationInventoryItem` union: the state arm wraps the state DTO, the
/// removal arm materializes the removal tombstone, and the close arm
/// materializes the close tombstone.
pub(crate) fn conversation_inventory_item(
    source: &ConversationProjectionSource,
) -> Result<chat_dto::ConversationInventoryItem<DefaultStr>, ProjectionError> {
    match source {
        ConversationProjectionSource::State(state) => Ok(
            chat_dto::ConversationInventoryItem::ConversationInventoryState(Box::new(
                chat_dto::ConversationInventoryState {
                    state: chat_dto::ConversationState {
                        cipher_suite: state.cipher_suite.clone(),
                        conversation_kind: state.conversation_kind.clone(),
                        coordinates: conversation_coordinates_dto(&state.coordinates),
                        leaves: state
                            .leaves
                            .iter()
                            .map(|leaf| chat_dto::DeviceLeafView {
                                user_did: leaf.user_did.clone(),
                                device_id: leaf.device_id.clone(),
                                leaf_origin: leaf.leaf_origin.clone(),
                                key_id: leaf.key_id.clone(),
                                device_status: leaf.device_status.clone(),
                                join_key_package_ref: leaf.join_key_package_ref.clone(),
                                extra_data: None,
                            })
                            .collect(),
                        metadata_snapshot: chat_dto::MetadataSnapshot {
                            coordinate: chat_dto::MetadataCryptoContext {
                                conversation_id: state
                                    .metadata_snapshot
                                    .coordinate
                                    .conversation_id
                                    .clone(),
                                generation: state.metadata_snapshot.coordinate.generation,
                                group_id: state.metadata_snapshot.coordinate.group_id.clone(),
                                epoch: state.metadata_snapshot.coordinate.epoch,
                                group_context_hash: state
                                    .metadata_snapshot
                                    .coordinate
                                    .group_context_hash
                                    .clone(),
                                confirmation_tag: state
                                    .metadata_snapshot
                                    .coordinate
                                    .confirmation_tag
                                    .clone(),
                                extra_data: None,
                            },
                            origin_transition_id: state
                                .metadata_snapshot
                                .origin_transition_id
                                .clone(),
                            metadata_version: state.metadata_snapshot.metadata_version,
                            nonce: state.metadata_snapshot.nonce.clone(),
                            ciphertext: state.metadata_snapshot.ciphertext.clone(),
                            ciphertext_sha256: state.metadata_snapshot.ciphertext_sha256.clone(),
                            ciphertext_size: state.metadata_snapshot.ciphertext_size,
                            author_proof: chat_dto::MetadataAuthorProof {
                                author_did: state.metadata_snapshot.author_proof.author_did.clone(),
                                author_device_id: state
                                    .metadata_snapshot
                                    .author_proof
                                    .author_device_id
                                    .clone(),
                                author_key_id: state
                                    .metadata_snapshot
                                    .author_proof
                                    .author_key_id
                                    .clone(),
                                signature_public_key: state
                                    .metadata_snapshot
                                    .author_proof
                                    .signature_public_key
                                    .clone(),
                                auth_generation_at_origin: state
                                    .metadata_snapshot
                                    .author_proof
                                    .auth_generation_at_origin,
                                origin_transition_id: state
                                    .metadata_snapshot
                                    .author_proof
                                    .origin_transition_id
                                    .clone(),
                                origin_seq: state.metadata_snapshot.author_proof.origin_seq,
                                role_at_origin: state
                                    .metadata_snapshot
                                    .author_proof
                                    .role_at_origin
                                    .clone(),
                                device_status_at_origin: state
                                    .metadata_snapshot
                                    .author_proof
                                    .device_status_at_origin
                                    .clone(),
                                extra_data: None,
                            },
                            avatar_binding: state.metadata_snapshot.avatar_binding.as_ref().map(
                                |binding| chat_dto::MetadataAvatarBinding {
                                    blob_id: binding.blob_id.clone(),
                                    ciphertext_sha256: binding.ciphertext_sha256.clone(),
                                    ciphertext_size: binding.ciphertext_size,
                                    purpose: binding.purpose.clone(),
                                    extra_data: None,
                                },
                            ),
                            extra_data: None,
                        },
                        participants: state
                            .participants
                            .iter()
                            .map(|participant| chat_dto::ParticipantView {
                                user_did: participant.user_did.clone(),
                                role: participant.role.clone(),
                                status: participant.status.clone(),
                                leaf_count: participant.leaf_count,
                                invitation_provenance: participant
                                    .invitation_provenance
                                    .as_ref()
                                    .map(|provenance| chat_dto::InvitationProvenance {
                                        invitation_transition_id: provenance
                                            .invitation_transition_id
                                            .clone(),
                                        invited_by_did: provenance.invited_by_did.clone(),
                                        invited_by_device_id: provenance
                                            .invited_by_device_id
                                            .clone(),
                                        extra_data: None,
                                    }),
                                extra_data: None,
                            })
                            .collect(),
                        snapshot_seq: state.snapshot_seq,
                        extra_data: None,
                    },
                    extra_data: None,
                },
            )),
        ),
        ConversationProjectionSource::Removal(removal) => Ok(
            chat_dto::ConversationInventoryItem::ConversationRemovalTombstone(Box::new(
                chat_dto::ConversationRemovalTombstone {
                    conversation_id: removal.conversation_id.clone(),
                    device_id: removal.device_id.clone(),
                    membership_interval_id: removal.membership_interval_id.clone(),
                    removed_at: chat_dto::CanonicalDatetime::raw_str(removal.removed_at.as_str()),
                    terminal_seq: removal.terminal_seq,
                    user_did: removal.user_did.clone(),
                    extra_data: None,
                },
            )),
        ),
        ConversationProjectionSource::Close(close) => Ok(
            chat_dto::ConversationInventoryItem::ConversationCloseTombstone(Box::new(
                chat_dto::ConversationCloseTombstone {
                    closed_at: chat_dto::CanonicalDatetime::raw_str(close.closed_at.as_str()),
                    closed_by_device_id: close.closed_by_device_id.clone(),
                    closed_by_did: close.closed_by_did.clone(),
                    conversation_id: close.conversation_id.clone(),
                    conversation_kind: close.conversation_kind.clone(),
                    retired: conversation_coordinates_dto(&close.retired),
                    terminal_seq: close.terminal_seq,
                    extra_data: None,
                },
            )),
        ),
    }
}

/// Project the retained Welcome source to the generated `WelcomeView` DTO.
pub(crate) fn welcome_view(
    source: &RetainedWelcomeProjectionSource,
) -> Result<chat_dto::WelcomeView<DefaultStr>, ProjectionError> {
    Ok(chat_dto::WelcomeView {
        conversation_id: source.conversation_id.clone(),
        coordinates: conversation_coordinates_dto(&source.coordinates),
        expires_at: chat_dto::CanonicalDatetime::raw_str(source.expires_at.as_str()),
        opaque_welcome: source.opaque_welcome.clone(),
        provenance: chat_dto::RecoveryWelcomeProvenance {
            key_package_ref: source.provenance.key_package_ref.clone(),
            recovery_request_id: source.provenance.recovery_request_id.clone(),
            extra_data: None,
        },
        recipient_device_id: source.recipient_device_id.clone(),
        recipient_did: source.recipient_did.clone(),
        sha256: source.sha256.clone(),
        status: source.status.clone(),
        transition_seq: source.transition_seq,
        welcome_id: source.welcome_id.clone(),
        extra_data: None,
    })
}

/// Project the retained leaf-recovery source to the generated
/// `LeafRecoveryView` DTO.
pub(crate) fn leaf_recovery_view(
    source: &RetainedLeafRecoveryProjectionSource,
) -> Result<chat_dto::LeafRecoveryView<DefaultStr>, ProjectionError> {
    Ok(chat_dto::LeafRecoveryView {
        bound_coordinate: conversation_coordinates_dto(&source.bound_coordinate),
        conversation_id: source.conversation_id.clone(),
        expires_at: chat_dto::CanonicalDatetime::raw_str(source.expires_at.as_str()),
        recovery_kind: source.recovery_kind.clone(),
        recovery_request_id: source.recovery_request_id.clone(),
        requested_at: chat_dto::CanonicalDatetime::raw_str(source.requested_at.as_str()),
        requester_device_id: source.requester_device_id.clone(),
        requester_did: source.requester_did.clone(),
        reservation: chat_dto::LeafRecoveryReservation {
            bound_coordinate: conversation_coordinates_dto(&source.reservation.bound_coordinate),
            cipher_suite: source.reservation.cipher_suite.clone(),
            conversation_id: source.reservation.conversation_id.clone(),
            expires_at: chat_dto::CanonicalDatetime::raw_str(
                source.reservation.expires_at.as_str(),
            ),
            key_package: chat_dto::KeyPackageArtifact {
                bytes: source.reservation.key_package.bytes.clone(),
                content_type: source.reservation.key_package.content_type.clone(),
                framing: source.reservation.key_package.framing.clone(),
                key_package_ref: source.reservation.key_package.key_package_ref.clone(),
                sha256: source.reservation.key_package.sha256.clone(),
                extra_data: None,
            },
            key_package_ref: source.reservation.key_package_ref.clone(),
            purpose: source.reservation.purpose.clone(),
            recovery_request_id: source.reservation.recovery_request_id.clone(),
            requester_auth_generation: source.reservation.requester_auth_generation,
            requester_device_id: source.reservation.requester_device_id.clone(),
            requester_did: source.reservation.requester_did.clone(),
            requester_key_id: source.reservation.requester_key_id.clone(),
            status: source.reservation.status.clone(),
            extra_data: None,
        },
        status: source.status.clone(),
        extra_data: None,
    })
}

fn recovery_work_common_fields(
    source: &RetainedRecoveryWorkProjectionSource,
) -> (
    SmolStr,
    chat_dto::CanonicalDatetime,
    SmolStr,
    Did<SmolStr>,
    SmolStr,
    chat_dto::ConversationCoordinates<DefaultStr>,
    SmolStr,
    SmolStr,
) {
    (
        source.conversation_id.clone(),
        chat_dto::CanonicalDatetime::raw_str(source.created_at.as_str()),
        source.recipient_device_id.clone(),
        source.recipient_did.clone(),
        source.recovery_work_id.clone(),
        conversation_coordinates_dto(&source.source_coordinate),
        source.source_id.clone(),
        source.source_kind.clone(),
    )
}

fn recovery_work_pending_dto(
    source: &RetainedRecoveryWorkProjectionSource,
) -> chat_dto::RecoveryWorkPendingView<DefaultStr> {
    let (
        conversation_id,
        created_at,
        recipient_device_id,
        recipient_did,
        recovery_work_id,
        source_coordinate,
        source_id,
        source_kind,
    ) = recovery_work_common_fields(source);
    chat_dto::RecoveryWorkPendingView {
        conversation_id,
        created_at,
        recipient_device_id,
        recipient_did,
        recovery_work_id,
        source_coordinate,
        source_id,
        source_kind,
        status: SmolStr::from(WORK_STATUS_PENDING),
        extra_data: None,
    }
}

fn recovery_work_completed_by_transition_dto(
    source: &RetainedRecoveryWorkProjectionSource,
) -> chat_dto::RecoveryWorkCompletedByTransitionView<DefaultStr> {
    let (
        conversation_id,
        created_at,
        recipient_device_id,
        recipient_did,
        recovery_work_id,
        source_coordinate,
        source_id,
        source_kind,
    ) = recovery_work_common_fields(source);
    let RetainedRecoveryWorkTerminal::CompletedByTransition {
        terminal_transition_id,
        terminal_at,
    } = &source.terminal
    else {
        unreachable!("the caller checked the terminal shape");
    };
    chat_dto::RecoveryWorkCompletedByTransitionView {
        conversation_id,
        created_at,
        recipient_device_id,
        recipient_did,
        recovery_work_id,
        source_coordinate,
        source_id,
        source_kind,
        status: SmolStr::from(WORK_STATUS_COMPLETED),
        terminal_transition_id: terminal_transition_id.clone(),
        terminal_at: chat_dto::CanonicalDatetime::raw_str(terminal_at.as_str()),
        extra_data: None,
    }
}

fn recovery_work_superseded_by_transition_dto(
    source: &RetainedRecoveryWorkProjectionSource,
) -> chat_dto::RecoveryWorkSupersededByTransitionView<DefaultStr> {
    let (
        conversation_id,
        created_at,
        recipient_device_id,
        recipient_did,
        recovery_work_id,
        source_coordinate,
        source_id,
        source_kind,
    ) = recovery_work_common_fields(source);
    let RetainedRecoveryWorkTerminal::SupersededByTransition {
        terminal_transition_id,
        terminal_at,
    } = &source.terminal
    else {
        unreachable!("the caller checked the terminal shape");
    };
    chat_dto::RecoveryWorkSupersededByTransitionView {
        conversation_id,
        created_at,
        recipient_device_id,
        recipient_did,
        recovery_work_id,
        source_coordinate,
        source_id,
        source_kind,
        status: SmolStr::from(WORK_STATUS_SUPERSEDED),
        terminal_transition_id: terminal_transition_id.clone(),
        terminal_at: chat_dto::CanonicalDatetime::raw_str(terminal_at.as_str()),
        extra_data: None,
    }
}

fn recovery_work_superseded_by_revocation_dto(
    source: &RetainedRecoveryWorkProjectionSource,
) -> chat_dto::RecoveryWorkSupersededByRevocationView<DefaultStr> {
    let (
        conversation_id,
        created_at,
        recipient_device_id,
        recipient_did,
        recovery_work_id,
        source_coordinate,
        source_id,
        source_kind,
    ) = recovery_work_common_fields(source);
    let RetainedRecoveryWorkTerminal::SupersededByRevocation {
        terminal_revocation_id,
        terminal_at,
    } = &source.terminal
    else {
        unreachable!("the caller checked the terminal shape");
    };
    chat_dto::RecoveryWorkSupersededByRevocationView {
        conversation_id,
        created_at,
        recipient_device_id,
        recipient_did,
        recovery_work_id,
        source_coordinate,
        source_id,
        source_kind,
        status: SmolStr::from(WORK_STATUS_SUPERSEDED),
        terminal_revocation_id: terminal_revocation_id.clone(),
        terminal_at: chat_dto::CanonicalDatetime::raw_str(terminal_at.as_str()),
        extra_data: None,
    }
}

/// Project the retained recovery-work source to the generated
/// `RecoveryWorkView` union. The DTO status is derived from the closed
/// terminal arm, so every arm is consistent with its status by construction.
pub(crate) fn recovery_work(
    source: &RetainedRecoveryWorkProjectionSource,
) -> Result<chat_dto::RecoveryWorkView<DefaultStr>, ProjectionError> {
    Ok(match &source.terminal {
        RetainedRecoveryWorkTerminal::Pending => {
            chat_dto::RecoveryWorkView::RecoveryWorkPendingView(Box::new(
                recovery_work_pending_dto(source),
            ))
        }
        RetainedRecoveryWorkTerminal::CompletedByTransition { .. } => {
            chat_dto::RecoveryWorkView::RecoveryWorkCompletedByTransitionView(Box::new(
                recovery_work_completed_by_transition_dto(source),
            ))
        }
        RetainedRecoveryWorkTerminal::SupersededByTransition { .. } => {
            chat_dto::RecoveryWorkView::RecoveryWorkSupersededByTransitionView(Box::new(
                recovery_work_superseded_by_transition_dto(source),
            ))
        }
        RetainedRecoveryWorkTerminal::SupersededByRevocation { .. } => {
            chat_dto::RecoveryWorkView::RecoveryWorkSupersededByRevocationView(Box::new(
                recovery_work_superseded_by_revocation_dto(source),
            ))
        }
    })
}

/// Project the closed inbox input to the generated `LeafRecoveryInboxItem`
/// union. The checked constructors already bind the variant to the terminal
/// shape; the projection re-checks the pair before materialization.
pub(crate) fn leaf_recovery_inbox_item(
    input: LeafRecoveryInboxInput,
) -> Result<chat_dto::LeafRecoveryInboxItem<DefaultStr>, ProjectionError> {
    match input {
        LeafRecoveryInboxInput::LeafRecoveryView(source) => {
            Ok(chat_dto::LeafRecoveryInboxItem::LeafRecoveryView(Box::new(
                leaf_recovery_view(&source)?,
            )))
        }
        LeafRecoveryInboxInput::RecoveryWorkPendingView(source) => {
            require_terminal_shape(&source, |terminal| {
                matches!(terminal, RetainedRecoveryWorkTerminal::Pending)
            })?;
            Ok(chat_dto::LeafRecoveryInboxItem::RecoveryWorkPendingView(
                Box::new(recovery_work_pending_dto(&source)),
            ))
        }
        LeafRecoveryInboxInput::RecoveryWorkCompletedByTransitionView(source) => {
            require_terminal_shape(&source, |terminal| {
                matches!(
                    terminal,
                    RetainedRecoveryWorkTerminal::CompletedByTransition { .. }
                )
            })?;
            Ok(
                chat_dto::LeafRecoveryInboxItem::RecoveryWorkCompletedByTransitionView(Box::new(
                    recovery_work_completed_by_transition_dto(&source),
                )),
            )
        }
        LeafRecoveryInboxInput::RecoveryWorkSupersededByTransitionView(source) => {
            require_terminal_shape(&source, |terminal| {
                matches!(
                    terminal,
                    RetainedRecoveryWorkTerminal::SupersededByTransition { .. }
                )
            })?;
            Ok(
                chat_dto::LeafRecoveryInboxItem::RecoveryWorkSupersededByTransitionView(Box::new(
                    recovery_work_superseded_by_transition_dto(&source),
                )),
            )
        }
        LeafRecoveryInboxInput::RecoveryWorkSupersededByRevocationView(source) => {
            require_terminal_shape(&source, |terminal| {
                matches!(
                    terminal,
                    RetainedRecoveryWorkTerminal::SupersededByRevocation { .. }
                )
            })?;
            Ok(
                chat_dto::LeafRecoveryInboxItem::RecoveryWorkSupersededByRevocationView(Box::new(
                    recovery_work_superseded_by_revocation_dto(&source),
                )),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    fn obj(entries: &[(&str, CanonValue)]) -> CanonValue {
        CanonValue::Object(
            entries
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        )
    }

    fn int(value: i64) -> CanonValue {
        CanonValue::Integer(value)
    }

    fn text(value: &str) -> CanonValue {
        CanonValue::String(value.to_owned())
    }

    fn canonical(value: &CanonValue) -> Vec<u8> {
        let mut out = Vec::new();
        write_canonical_value(&mut out, value);
        out
    }

    #[test]
    fn writer_sorts_object_keys_by_utf16_code_units() {
        // UTF-16 code-unit order: a (U+0061) < z (U+007A) < é (U+00E9) <
        // 😀 (U+1F600, surrogate pair 0xD83D 0xDE00).
        let value = obj(&[("😀", int(1)), ("a", int(2)), ("é", int(3)), ("z", int(4))]);
        assert_eq!(
            canonical(&value),
            "{\"a\":2,\"z\":4,\"é\":3,\"😀\":1}".as_bytes().to_vec()
        );
    }

    #[test]
    fn writer_applies_jcs_escape_set_and_never_escapes_solidus() {
        let value =
            text("a\"b\\c\u{0008}\u{0009}\u{000A}\u{000C}\u{000D}\u{0000}\u{0001}\u{001F}/x");
        assert_eq!(
            canonical(&value),
            br#""a\"b\\c\b\t\n\f\r\u0000\u0001\u001f/x""#.to_vec()
        );
    }

    #[test]
    fn writer_preserves_composed_and_decomposed_strings_byte_for_byte() {
        let composed = canonical(&text("é"));
        let decomposed = canonical(&text("e\u{0301}"));
        assert_eq!(composed, "\"é\"".as_bytes().to_vec());
        assert_eq!(decomposed, "\"e\u{0301}\"".as_bytes().to_vec());
        assert_ne!(composed, decomposed);
    }

    #[test]
    fn writer_emits_shortest_base10_integers() {
        assert_eq!(canonical(&int(0)), b"0".to_vec());
        assert_eq!(
            canonical(&int(MAX_SAFE_INTEGER)),
            b"9007199254740991".to_vec()
        );
        assert_eq!(
            canonical(&int(-MAX_SAFE_INTEGER)),
            b"-9007199254740991".to_vec()
        );
        assert_eq!(canonical(&int(1234)), b"1234".to_vec());
    }

    #[test]
    fn writer_preserves_array_order_and_lowercase_literals() {
        let value = CanonValue::Array(vec![
            CanonValue::Bool(true),
            CanonValue::Null,
            CanonValue::Bool(false),
        ]);
        assert_eq!(canonical(&value), b"[true,null,false]".to_vec());
    }

    fn parse_kind(bytes: &[u8]) -> ProjectionErrorKind {
        parse_strict_canonical_json(bytes)
            .map(|_| ProjectionErrorKind::InvalidJsonSyntax)
            .map_err(|error| error.kind())
            .unwrap_or_else(|kind| kind)
    }

    #[test]
    fn parser_rejects_duplicate_keys() {
        assert_eq!(
            parse_kind(br#"{"a":1,"a":2}"#),
            ProjectionErrorKind::DuplicateKey
        );
        assert_eq!(
            parse_kind(br#"{"a":{"b":1,"b":2}}"#),
            ProjectionErrorKind::DuplicateKey
        );
    }

    #[test]
    fn parser_rejects_floats() {
        assert_eq!(parse_kind(b"1.5"), ProjectionErrorKind::InvalidJsonSyntax);
        assert_eq!(parse_kind(b"1e3"), ProjectionErrorKind::InvalidJsonSyntax);
        assert_eq!(parse_kind(b"-1.5"), ProjectionErrorKind::InvalidJsonSyntax);
        assert_eq!(
            parse_kind(br#"{"a":0.25}"#),
            ProjectionErrorKind::FloatNotAllowed
        );
        assert_eq!(
            parse_kind(br#"{"a":1.5,"b":2}"#),
            ProjectionErrorKind::FloatNotAllowed
        );
        assert_eq!(
            parse_kind(br#"{"a":[1e3]}"#),
            ProjectionErrorKind::FloatNotAllowed
        );
    }

    #[test]
    fn parser_rejects_unsafe_integers() {
        assert_eq!(
            parse_kind(b"9007199254740992"),
            ProjectionErrorKind::InvalidJsonSyntax
        );
        assert_eq!(
            parse_kind(b"-9007199254740992"),
            ProjectionErrorKind::InvalidJsonSyntax
        );
        assert_eq!(
            parse_kind(b"18446744073709551616"),
            ProjectionErrorKind::InvalidJsonSyntax
        );
        assert_eq!(
            parse_kind(br#"{"a":9007199254740992}"#),
            ProjectionErrorKind::IntegerOutOfRange
        );
        assert_eq!(
            parse_kind(br#"{"a":-9007199254740992}"#),
            ProjectionErrorKind::IntegerOutOfRange
        );
        // 2^64 does not fit the u64 range; serde_json parses it as a float,
        // which the canonical profile rejects as a floating-point form.
        assert_eq!(
            parse_kind(br#"{"a":18446744073709551616}"#),
            ProjectionErrorKind::FloatNotAllowed
        );
    }

    #[test]
    fn parser_rejects_bom_whitespace_trailing_and_scalar_roots() {
        assert_eq!(
            parse_kind(b"\xEF\xBB\xBF{}"),
            ProjectionErrorKind::InvalidJsonSyntax
        );
        assert_eq!(parse_kind(b"  {}"), ProjectionErrorKind::InvalidJsonSyntax);
        assert_eq!(parse_kind(b"{}  "), ProjectionErrorKind::InvalidJsonSyntax);
        assert_eq!(
            parse_kind(b"{}garbage"),
            ProjectionErrorKind::InvalidJsonSyntax
        );
        assert_eq!(parse_kind(b"42"), ProjectionErrorKind::InvalidJsonSyntax);
        assert_eq!(parse_kind(b"true"), ProjectionErrorKind::InvalidJsonSyntax);
        assert_eq!(parse_kind(b"null"), ProjectionErrorKind::InvalidJsonSyntax);
        assert_eq!(parse_kind(b""), ProjectionErrorKind::InvalidJsonSyntax);
    }

    #[test]
    fn parser_rejects_negative_zero_as_a_floating_point_form() {
        // serde_json parses "-0" as -0.0 (a float), which the canonical
        // profile rejects; zero is canonically spelled `0`.
        assert_eq!(
            parse_kind(br#"{"a":-0}"#),
            ProjectionErrorKind::FloatNotAllowed
        );
        let value = parse_strict_canonical_json(br#"{"a":0}"#).unwrap();
        assert_eq!(
            value,
            CanonValue::Object(vec![("a".to_owned(), CanonValue::Integer(0))])
        );
    }

    #[test]
    fn normalize_rejects_missing_and_unknown_fields() {
        let doc = chat_defs_doc();
        let name = "conversationRemovalTombstone";
        // Missing terminalSeq and removedAt.
        let value = obj(&[
            (
                "conversationId",
                text("123e4567-e89b-12d3-a456-426614174000"),
            ),
            (
                "membershipIntervalId",
                text("123e4567-e89b-12d3-a456-426614174000"),
            ),
            ("userDid", text("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")),
            ("deviceId", text("123e4567-e89b-12d3-a456-426614174001")),
        ]);
        let error = normalize_def(doc, name, &value, 0, "").unwrap_err();
        assert_eq!(error.kind(), ProjectionErrorKind::MissingField);
        // Unknown field.
        let value = obj(&[
            (
                "conversationId",
                text("123e4567-e89b-12d3-a456-426614174000"),
            ),
            (
                "membershipIntervalId",
                text("123e4567-e89b-12d3-a456-426614174000"),
            ),
            ("userDid", text("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")),
            ("deviceId", text("123e4567-e89b-12d3-a456-426614174001")),
            ("terminalSeq", int(1)),
            ("removedAt", text("2026-07-30T12:00:00.000Z")),
            ("smuggled", text("x")),
        ]);
        let error = normalize_def(doc, name, &value, 0, "").unwrap_err();
        assert_eq!(error.kind(), ProjectionErrorKind::UnknownField);
        assert!(error.to_string().contains("smuggled"));
    }

    #[test]
    fn normalize_rejects_invalid_null_everywhere() {
        let doc = chat_defs_doc();
        let name = "conversationRemovalTombstone";
        let mut entries = vec![
            (
                "conversationId",
                text("123e4567-e89b-12d3-a456-426614174000"),
            ),
            (
                "membershipIntervalId",
                text("123e4567-e89b-12d3-a456-426614174000"),
            ),
            ("userDid", text("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")),
            ("deviceId", text("123e4567-e89b-12d3-a456-426614174001")),
            ("terminalSeq", int(1)),
            ("removedAt", CanonValue::Null),
        ];
        let error = normalize_def(doc, name, &obj(&entries), 0, "").unwrap_err();
        assert_eq!(error.kind(), ProjectionErrorKind::InvalidNull);
        assert!(error.to_string().contains("removedAt"));
        entries.pop();
        let error = normalize_def(doc, name, &obj(&entries), 0, "").unwrap_err();
        assert_eq!(error.kind(), ProjectionErrorKind::MissingField);
    }

    #[test]
    fn normalize_rejects_noncanonical_datetimes() {
        let doc = chat_defs_doc();
        let name = "conversationRemovalTombstone";
        for bad in [
            "2026-07-30T12:00:00Z",
            "2026-07-30T12:00:00.000+00:00",
            "2026-07-30t12:00:00.000z",
            "2026-07-30T12:00:00.1Z",
            "2026-07-30T12:00:60.000Z",
            "2026-07-30T12:00:00.0000Z",
        ] {
            let value = obj(&[
                (
                    "conversationId",
                    text("123e4567-e89b-12d3-a456-426614174000"),
                ),
                (
                    "membershipIntervalId",
                    text("123e4567-e89b-12d3-a456-426614174000"),
                ),
                ("userDid", text("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")),
                ("deviceId", text("123e4567-e89b-12d3-a456-426614174001")),
                ("terminalSeq", int(1)),
                ("removedAt", text(bad)),
            ]);
            let error = normalize_def(doc, name, &value, 0, "").unwrap_err();
            assert_eq!(error.kind(), ProjectionErrorKind::InvalidDatetime, "{bad}");
        }
    }

    #[test]
    fn normalize_union_rejects_missing_nonstring_and_unknown_tags() {
        let doc = chat_defs_doc();
        let name = "recoveryWorkView";
        let base = [
            (
                "recoveryWorkId",
                text("123e4567-e89b-12d3-a456-426614174000"),
            ),
            (
                "conversationId",
                text("123e4567-e89b-12d3-a456-426614174000"),
            ),
            ("recipientDid", text("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")),
            (
                "recipientDeviceId",
                text("123e4567-e89b-12d3-a456-426614174001"),
            ),
            ("sourceKind", text("welcomeExpired")),
            ("sourceId", text("123e4567-e89b-12d3-a456-426614174002")),
            ("status", text("pending")),
            ("createdAt", text("2026-08-04T10:00:00.000Z")),
        ];
        let mut without_tag = base.to_vec();
        let error = normalize_def(doc, name, &obj(&without_tag), 0, "").unwrap_err();
        assert_eq!(error.kind(), ProjectionErrorKind::UnknownUnionTag);

        without_tag.push(("$type", int(7)));
        let error = normalize_def(doc, name, &obj(&without_tag), 0, "").unwrap_err();
        assert_eq!(error.kind(), ProjectionErrorKind::UnknownUnionTag);

        let mut unknown_tag = base.to_vec();
        unknown_tag.push(("$type", text("blue.catbird.chat.defs#conversationState")));
        let error = normalize_def(doc, name, &obj(&unknown_tag), 0, "").unwrap_err();
        assert_eq!(error.kind(), ProjectionErrorKind::UnknownUnionTag);

        let mut no_ns = base.to_vec();
        no_ns.push(("$type", text("recoveryWorkPendingView")));
        let error = normalize_def(doc, name, &obj(&no_ns), 0, "").unwrap_err();
        assert_eq!(error.kind(), ProjectionErrorKind::UnknownUnionTag);
    }

    #[test]
    fn normalize_union_requires_variant_members() {
        // The generated lexicon doc carries no `enum`/`const` constraints
        // (verified: zero r#enum/r#const in the generated doc), so a wrong
        // status value passes the member walk; the missing terminal members
        // still reject. Status/value correctness is enforced by the checked
        // sources (C1-2) and the generated `validate()`, not by this encoder.
        let doc = chat_defs_doc();
        let name = "recoveryWorkView";
        let common = |tag: &str, status: &str| {
            vec![
                ("$type", text(tag)),
                (
                    "recoveryWorkId",
                    text("123e4567-e89b-12d3-a456-426614174000"),
                ),
                (
                    "conversationId",
                    text("123e4567-e89b-12d3-a456-426614174000"),
                ),
                ("recipientDid", text("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")),
                (
                    "recipientDeviceId",
                    text("123e4567-e89b-12d3-a456-426614174001"),
                ),
                ("sourceKind", text("welcomeExpired")),
                ("sourceId", text("123e4567-e89b-12d3-a456-426614174002")),
                (
                    "sourceCoordinate",
                    obj(&[
                        (
                            "conversationId",
                            text("123e4567-e89b-12d3-a456-426614174000"),
                        ),
                        ("generation", int(0)),
                        ("stateVersion", int(0)),
                        (
                            "groupId",
                            text("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8="),
                        ),
                        ("epoch", int(0)),
                        (
                            "groupContextHash",
                            text("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8="),
                        ),
                        (
                            "confirmationTag",
                            text("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8="),
                        ),
                        ("lifecycle", text("active")),
                    ]),
                ),
                ("status", text(status)),
                ("createdAt", text("2026-08-04T10:00:00.000Z")),
            ]
        };
        // Completed tag without the terminal members (status value irrelevant
        // to the doc's structural check): missing members reject.
        let value = common(
            "blue.catbird.chat.defs#recoveryWorkCompletedByTransitionView",
            "pending",
        );
        let error = normalize_def(doc, name, &obj(&value), 0, "").unwrap_err();
        assert_eq!(error.kind(), ProjectionErrorKind::MissingField);
        assert!(error.to_string().contains("terminalTransitionId"));

        // All members present: the union normalizes (the doc carries no
        // status const, so `pending` here is structurally accepted).
        let mut value = common(
            "blue.catbird.chat.defs#recoveryWorkCompletedByTransitionView",
            "pending",
        );
        value.push((
            "terminalTransitionId",
            text("123e4567-e89b-12d3-a456-426614174001"),
        ));
        value.push(("terminalAt", text("2026-08-04T11:00:00.000Z")));
        assert!(normalize_def(doc, name, &obj(&value), 0, "").is_ok());
    }

    #[test]
    fn normalize_rejects_dollar_type_on_object_definitions() {
        let doc = chat_defs_doc();
        let name = "conversationRemovalTombstone";
        let value = vec![
            (
                "conversationId",
                text("123e4567-e89b-12d3-a456-426614174000"),
            ),
            (
                "membershipIntervalId",
                text("123e4567-e89b-12d3-a456-426614174000"),
            ),
            ("userDid", text("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")),
            ("deviceId", text("123e4567-e89b-12d3-a456-426614174001")),
            ("terminalSeq", int(1)),
            ("removedAt", text("2026-07-30T12:00:00.000Z")),
            (
                "$type",
                text("blue.catbird.chat.defs#conversationRemovalTombstone"),
            ),
        ];
        let error = normalize_def(doc, name, &obj(&value), 0, "").unwrap_err();
        assert_eq!(error.kind(), ProjectionErrorKind::UnknownField);
    }

    #[test]
    fn normalize_bytes_accepts_all_generated_shapes_and_rejects_bad_base64() {
        let doc = chat_defs_doc();
        // conversationCoordinates.groupId is a bytes member.
        let name = "conversationCoordinates";
        let build = |group_id: CanonValue| {
            obj(&[
                (
                    "conversationId",
                    text("123e4567-e89b-12d3-a456-426614174000"),
                ),
                ("generation", int(0)),
                ("stateVersion", int(0)),
                ("groupId", group_id),
                ("epoch", int(0)),
                (
                    "groupContextHash",
                    text("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8="),
                ),
                (
                    "confirmationTag",
                    text("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8="),
                ),
                ("lifecycle", text("active")),
            ])
        };
        // Bare base64 text normalizes to itself.
        let value = build(text("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8="));
        let normalized = normalize_def(doc, name, &value, 0, "").unwrap();
        let CanonValue::Object(entries) = normalized else {
            panic!("expected object");
        };
        let group_id = entries
            .iter()
            .find(|(key, _)| key == "groupId")
            .expect("groupId")
            .1
            .clone();
        assert_eq!(
            group_id,
            text("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=")
        );
        // $bytes object normalizes to bare text.
        let value = build(obj(&[(
            "$bytes",
            text("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8="),
        )]));
        let normalized = normalize_def(doc, name, &value, 0, "").unwrap();
        let CanonValue::Object(entries) = normalized else {
            panic!("expected object");
        };
        let group_id = entries
            .iter()
            .find(|(key, _)| key == "groupId")
            .expect("groupId")
            .1
            .clone();
        assert_eq!(
            group_id,
            text("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=")
        );
        // Byte array normalizes to bare text.
        let bytes: Vec<CanonValue> = (64..96).map(|value| int(value as i64)).collect();
        let value = build(CanonValue::Array(bytes));
        let normalized = normalize_def(doc, name, &value, 0, "").unwrap();
        let CanonValue::Object(entries) = normalized else {
            panic!("expected object");
        };
        let group_id = entries
            .iter()
            .find(|(key, _)| key == "groupId")
            .expect("groupId")
            .1
            .clone();
        assert_eq!(
            group_id,
            text("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=")
        );
        // Invalid: unpadded base64.
        let value = build(text("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8"));
        let error = normalize_def(doc, name, &value, 0, "").unwrap_err();
        assert_eq!(error.kind(), ProjectionErrorKind::NonCanonicalBase64);
        // Invalid: byte array with an out-of-range entry.
        let bytes = vec![int(64), int(256)];
        let value = build(CanonValue::Array(bytes));
        let error = normalize_def(doc, name, &value, 0, "").unwrap_err();
        assert_eq!(error.kind(), ProjectionErrorKind::InvalidBytesForm);
    }

    #[test]
    fn stored_byte_validation_rejects_noncanonical_spelling() {
        let doc = chat_defs_doc();
        let name = "conversationRemovalTombstone";
        let canonical = br#"{"conversationId":"123e4567-e89b-12d3-a456-426614174000","deviceId":"123e4567-e89b-12d3-a456-426614174001","membershipIntervalId":"123e4567-e89b-12d3-a456-426614174000","removedAt":"2026-07-30T12:00:00.000Z","terminalSeq":7,"userDid":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        assert!(stored_byte_validation(doc, name, canonical).is_ok());
        // A key-order-different spelling of the same object parses and
        // normalizes, but its re-encode sorts the members and therefore
        // differs: stored bytes that are not already canonical must reject.
        let reordered = br#"{"userDid":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","terminalSeq":7,"removedAt":"2026-07-30T12:00:00.000Z","membershipIntervalId":"123e4567-e89b-12d3-a456-426614174000","deviceId":"123e4567-e89b-12d3-a456-426614174001","conversationId":"123e4567-e89b-12d3-a456-426614174000"}"#;
        assert_ne!(reordered, canonical);
        let error = stored_byte_validation(doc, name, reordered).unwrap_err();
        assert_eq!(error.kind(), ProjectionErrorKind::StoredBytesNotCanonical);
    }

    #[test]
    fn definition_id_validation() {
        assert!(split_definition_id("blue.catbird.chat.defs#conversationState").is_ok());
        assert_eq!(
            split_definition_id("blue.catbird.chat.defs#")
                .unwrap_err()
                .kind(),
            ProjectionErrorKind::InvalidDefinitionId
        );
        assert_eq!(
            split_definition_id("other.ns#conversationState")
                .unwrap_err()
                .kind(),
            ProjectionErrorKind::InvalidDefinitionId
        );
        assert_eq!(
            split_definition_id("no-definition-id").unwrap_err().kind(),
            ProjectionErrorKind::InvalidDefinitionId
        );
        assert_eq!(
            normalize_def(chat_defs_doc(), "noSuchDef", &CanonValue::Null, 0, "")
                .unwrap_err()
                .kind(),
            ProjectionErrorKind::DefinitionNotFound
        );
    }

    #[test]
    fn entry_rejects_unsafe_integers_and_scalar_roots() {
        #[derive(Serialize)]
        struct Poison {
            snapshot_seq: i64,
        }
        // Unsafe integer through the public entry (rejected at parse).
        let poison = Poison {
            snapshot_seq: MAX_SAFE_INTEGER + 1,
        };
        let error = encode_canonical_generated_chat_json_v1(
            &poison,
            "blue.catbird.chat.defs#conversationState",
        )
        .unwrap_err();
        assert_eq!(error.kind(), ProjectionErrorKind::IntegerOutOfRange);
        // A scalar root through the public entry is rejected before
        // normalization (wrong shape at the byte boundary).
        let error = encode_canonical_generated_chat_json_v1(
            &"x".to_string(),
            "blue.catbird.chat.defs#conversationState",
        )
        .unwrap_err();
        assert_eq!(error.kind(), ProjectionErrorKind::InvalidJsonSyntax);
        // A string where the definition requires an object rejects in
        // normalization.
        let error =
            normalize_def(chat_defs_doc(), "conversationState", &text("x"), 0, "").unwrap_err();
        assert_eq!(error.kind(), ProjectionErrorKind::WrongValueType);
    }
}
