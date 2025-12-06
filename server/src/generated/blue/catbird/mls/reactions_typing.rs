// @generated - This file was manually created for the new reaction and typing endpoints
// These mirror the lexicons at blue.catbird.mls.addReaction, removeReaction, sendTypingIndicator

use serde::{Deserialize, Serialize};

pub mod add_reaction {
    use super::*;
    
    pub const NSID: &str = "blue.catbird.mls.addReaction";
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Input {
        pub convo_id: String,
        pub message_id: String,
        pub reaction: String,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Output {
        pub success: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub reacted_at: Option<String>,
    }
}

pub mod remove_reaction {
    use super::*;
    
    pub const NSID: &str = "blue.catbird.mls.removeReaction";
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Input {
        pub convo_id: String,
        pub message_id: String,
        pub reaction: String,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Output {
        pub success: bool,
    }
}

pub mod send_typing_indicator {
    use super::*;
    
    pub const NSID: &str = "blue.catbird.mls.sendTypingIndicator";
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Input {
        pub convo_id: String,
        pub is_typing: bool,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Output {
        pub success: bool,
    }
}
