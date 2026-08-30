#![allow(dead_code)]

mod common;

pub use catbird_server::{auth, crypto, federation, handlers, identity, sqlx_jacquard, util};

#[path = "common/chat_protocol_harness.rs"]
mod chat_protocol;

mod repository {
    pub(crate) use crate::chat_protocol::repository::*;
}
