// This file is manually generated based on the lexicon
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputData {
    pub convo_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Input {
    #[serde(flatten)]
    pub data: InputData,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputData {
    pub requested: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_members: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Output {
    #[serde(flatten)]
    pub data: OutputData,
}

impl From<OutputData> for Output {
    fn from(data: OutputData) -> Self {
        Output { data }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "error", content = "message")]
pub enum Error {
    Unauthorized(Option<String>),
    NotFound(Option<String>),
    NoActiveMembers(Option<String>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unauthorized(msg) => write!(f, "Unauthorized: {:?}", msg),
            Error::NotFound(msg) => write!(f, "NotFound: {:?}", msg),
            Error::NoActiveMembers(msg) => write!(f, "NoActiveMembers: {:?}", msg),
        }
    }
}

impl std::error::Error for Error {}
