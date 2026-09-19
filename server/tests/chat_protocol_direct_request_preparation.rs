//! Request-only package selection and immutable snapshot database boundaries.
#![allow(dead_code)]
pub use catbird_server::{auth, chat_protocol};
#[path = "common/chat_protocol.rs"]
pub mod chat_protocol_baseline;
mod common {
    pub use super::chat_protocol_baseline as chat_protocol;
    pub mod direct_request_database;
}
mod repository {
    mod device_directory {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/device_directory.rs"
        ));
    }
    pub mod prelude {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/direct_request_lock.rs"
        ));
    }
    mod direct_request_preparation {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/direct_request_store.rs"
        ));
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/common/direct_request_preparation_cases.rs"
        ));
    }
}
