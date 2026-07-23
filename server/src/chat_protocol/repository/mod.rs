//! PostgreSQL boundaries for clean-chat protocol authority.

pub(crate) mod auth;
#[cfg(not(test))]
pub(crate) mod core;
#[cfg(not(test))]
pub(crate) mod delivery;
pub(crate) mod inventory;
#[cfg(not(test))]
pub(crate) mod relationship;
