//! Stable `crate::blue_catbird::<namespace>` paths over the Petrel-generated
//! Catbird overlay (`petrel_catbird::generated::blue::catbird`).
//!
//! Petrel keeps each namespace's shared `defs` lexicon in its own `defs`
//! module. This facade also re-exports those definitions at the namespace
//! root, so `blue_catbird::chat::ConversationCoordinates` and
//! `blue_catbird::chat::get_entries::Parameters` both resolve. It only
//! re-exports generated items; it defines no types of its own.

macro_rules! namespace_with_defs {
    ($($name:ident),+ $(,)?) => {
        $(
            pub mod $name {
                pub use petrel_catbird::generated::blue::catbird::$name::*;
                pub use petrel_catbird::generated::blue::catbird::$name::defs::*;
            }
        )+
    };
}

namespace_with_defs!(chat, mls_ds, labyrinth, intel, onboarding);

pub mod circle {
    pub use petrel_catbird::generated::blue::catbird::circle::defs::*;
    // This namespace also defines the blue.catbird.circle record itself.
    pub use petrel_catbird::generated::blue::catbird::circle::{NSID, *};
}

pub use petrel_catbird::generated::blue::catbird::{bskychat, push};
