//! PostgreSQL boundaries for clean-chat protocol authority.

pub(crate) mod acceptance;
pub(crate) mod auth;
#[allow(dead_code)]
pub(crate) mod blobs;
pub(crate) mod conversation;
pub(crate) mod coordinate;
pub(crate) mod core;
pub(crate) mod creation;
pub(crate) mod delivery;
#[allow(dead_code)]
pub(crate) mod device_directory;
pub(crate) mod entry_read;
#[allow(dead_code)]
pub(crate) mod execution_context;
#[allow(dead_code)]
pub(crate) mod expiry_sweep;
pub(crate) mod inventory;
#[allow(dead_code)]
pub(crate) mod key_packages;
pub(crate) mod leave;
pub(crate) mod message_delivery;
pub(crate) mod prelude;
#[allow(dead_code)]
pub(crate) mod recovery;
pub mod relationship;
#[allow(dead_code)]
pub(crate) mod reset;
#[allow(dead_code)]
pub(crate) mod revocation;
pub(crate) mod submit_transition;
pub(crate) mod subscription;
#[allow(dead_code)]
pub(crate) mod ticket;
pub(crate) mod transition;
#[allow(dead_code)]
pub(crate) mod welcome;
#[allow(dead_code)]
pub(crate) mod welcome_terminal;
