#![allow(dead_code)]

#[path = "../src/chat_protocol/dpop.rs"]
mod dpop;
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

mod repository {
    pub mod auth {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/auth.rs"
        ));
    }
    pub mod prelude {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/prelude.rs"
        ));
    }
}
