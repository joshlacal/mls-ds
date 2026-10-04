//! Procedure inputs and shared output pieces of the Labyrinth endpoints.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::value::RawValue;

use super::bytes::Bytes;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};

/// A record exactly as received: its typed shape, its JSON text (stored as
/// JSONB) and its byte length for size accounting.
pub struct Received<T> {
    pub value: T,
    pub text: String,
    pub bytes: i32,
}

impl<T: DeserializeOwned> Received<T> {
    pub fn parse(raw: &RawValue, what: &str) -> LabyrinthResult<Self> {
        let text = raw.get();
        let value = serde_json::from_str(text)
            .map_err(|e| LabyrinthError::invalid(format!("{what}: {e}")))?;
        let bytes = i32::try_from(text.len())
            .map_err(|_| LabyrinthError::invalid(format!("{what} is too large")))?;
        Ok(Self {
            value,
            text: text.to_owned(),
            bytes,
        })
    }
}

/// Parse a procedure body.
pub fn body<T: DeserializeOwned>(bytes: &[u8]) -> LabyrinthResult<T> {
    serde_json::from_slice(bytes).map_err(|e| LabyrinthError::invalid(e.to_string()))
}

/// `{record}` input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordIn {
    pub record: Box<RawValue>,
}

/// `createEpoch` input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateEpochIn {
    pub epoch: Box<RawValue>,
    pub members: Vec<Box<RawValue>>,
}

/// `registerOrfState` parent / `createVirtualDevice#orfParent`.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrfParent {
    pub device_key_pubkey: Bytes,
    pub evolve_token: Bytes,
}

/// `createVirtualDevice` input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateVirtualDeviceIn {
    pub record: Box<RawValue>,
    #[serde(default)]
    pub member: Option<Box<RawValue>>,
    #[serde(default)]
    pub orf: Option<OrfParent>,
}

/// `markDeviceRevoked` input.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MarkRevokedIn {
    pub device_key_pubkey: Bytes,
    pub revoked_at: String,
}

/// `registerOrfState` input.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterOrfIn {
    pub device_key_pubkey: Bytes,
    #[serde(default)]
    pub parent: Option<OrfParent>,
}

/// `deleteOrfState` input.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceKeyIn {
    pub device_key_pubkey: Bytes,
}

/// `publishEpochHead` input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishHeadIn {
    pub epoch: Box<RawValue>,
}

/// `putAttachmentRef` input.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PutAttachmentRefIn {
    pub device_key_pubkey: Bytes,
    pub blinded_index: Bytes,
    pub blinded_token: Bytes,
    pub conversation_id: String,
    pub blob_id: String,
    pub message_id: String,
}

/// `defs#serverOrder`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerOrder {
    pub seq: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chat_seq: Option<i64>,
    pub received_at: String,
}

/// `{items, cursor?}`.
#[derive(Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// RFC 3339 UTC with milliseconds, as every Labyrinth datetime is written.
pub fn datetime(at: chrono::DateTime<chrono::Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// JSON bytes of a response value.
pub fn to_bytes<T: Serialize>(value: &T) -> LabyrinthResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|error| {
        tracing::error!(?error, "labyrinth response serialization failed");
        LabyrinthError::internal()
    })
}
