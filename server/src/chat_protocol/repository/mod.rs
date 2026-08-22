//! PostgreSQL boundaries for clean-chat protocol authority.

pub mod acceptance;
pub mod auth;
#[allow(dead_code)]
pub mod blobs;
pub mod conversation;
pub mod core;
pub mod coordinate;
pub mod creation;
pub mod delivery;
#[allow(dead_code)]
pub mod device_directory;
pub mod entry_read;
#[allow(dead_code)]
pub mod execution_context;
#[allow(dead_code)]
pub mod expiry_sweep;
pub mod inventory;
#[allow(dead_code)]
pub mod key_packages;
pub mod leave;
pub mod message_delivery;
pub mod prelude;
#[allow(dead_code)]
pub mod recovery;
pub mod relationship;
#[allow(dead_code)]
pub mod reset;
#[allow(dead_code)]
pub mod revocation;
pub mod submit_transition;
pub mod subscription;
#[allow(dead_code)]
pub mod ticket;
pub mod transition;
#[allow(dead_code)]
pub mod welcome;
#[allow(dead_code)]
pub mod welcome_terminal;
