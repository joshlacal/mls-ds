//! Procedure inputs and shared output pieces of the active Labyrinth directory endpoints.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::value::RawValue;

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

/// `publishEpochHead` input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishHeadIn {
    pub epoch: Box<RawValue>,
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
