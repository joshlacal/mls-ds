#![allow(dead_code)]

#[path = "../src/chat_protocol/model.rs"]
mod model;
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

mod chat_protocol {
    pub mod model {
        pub use crate::model::*;
    }

    pub mod transcript {
        pub use crate::transcript::*;
    }

    pub mod validation {
        pub use crate::validation::*;
    }

    pub mod repository {
        pub mod auth {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/auth.rs"
            ));
        }
        pub mod key_packages {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/key_packages.rs"
            ));
        }
        pub mod prelude {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/prelude.rs"
            ));
        }
    }

    pub mod dpop {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/dpop.rs"
        ));
    }
}

mod repository {
    pub(crate) use crate::chat_protocol::repository::*;
}
