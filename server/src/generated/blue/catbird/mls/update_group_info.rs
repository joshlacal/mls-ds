// This file is manually generated based on the lexicon
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputData {
    pub convo_id: String,
    pub group_info: String,
    pub epoch: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Input {
    #[serde(flatten)]
    pub data: InputData,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputData {
    pub updated: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Output {
    #[serde(flatten)]
    pub data: OutputData,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "error", content = "message")]
pub enum Error {
    Unauthorized(Option<String>),
    InvalidGroupInfo(Option<String>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unauthorized(msg) => write!(f, "Unauthorized: {:?}", msg),
            Error::InvalidGroupInfo(msg) => write!(f, "InvalidGroupInfo: {:?}", msg),
        }
    }
}

impl std::error::Error for Error {}
