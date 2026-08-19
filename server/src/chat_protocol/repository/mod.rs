//! PostgreSQL boundaries for clean-chat protocol authority.

pub(crate) mod auth;
pub(crate) mod acceptance;
#[allow(dead_code)]
pub(crate) mod blobs;
pub(crate) mod conversation;
pub(crate) mod core;
pub(crate) mod creation;
#[allow(dead_code)]
pub(crate) mod execution_context;
#[allow(dead_code)]
pub(crate) mod expiry_sweep;
pub(crate) mod delivery;
pub(crate) mod entry_read;
pub(crate) mod message_delivery;
#[allow(dead_code)]
pub(crate) mod device_directory;
pub(crate) mod inventory;
#[allow(dead_code)]
pub(crate) mod key_packages;
pub(crate) mod leave;
pub(crate) mod prelude;
#[allow(dead_code)]
pub(crate) mod recovery;
pub(crate) mod relationship;
#[allow(dead_code)]
pub(crate) mod reset;
#[allow(dead_code)]
pub(crate) mod revocation;
pub(crate) mod submit_transition;
pub(crate) mod transition;
#[allow(dead_code)]
pub(crate) mod welcome_terminal;
#[allow(dead_code)]
pub(crate) mod welcome;
pub(crate) mod subscription;
#[allow(dead_code)]
pub(crate) mod ticket;
