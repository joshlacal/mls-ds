use serde::Deserialize;

/// `labyrinthWriteBody`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WriteBodyWire {
    pub(crate) operation_id: String,
    pub(crate) actor_device_id: String,
    pub(crate) endpoint_nsid: String,
    pub(crate) payload_sha256: String,
    pub(crate) signed_at: String,
}
