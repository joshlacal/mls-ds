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
#[allow(dead_code)]
pub(crate) mod direct_request_preparation;
#[allow(dead_code)]
pub(crate) mod direct_request_publication;
pub(crate) mod direct_request_push;
#[allow(dead_code)]
pub mod direct_request_receipts;
pub(crate) mod direct_request_retention;
pub(crate) mod entry_read;
#[allow(dead_code)]
pub(crate) mod execution_context;
#[allow(dead_code)]
pub mod expiry_sweep;
pub(crate) mod inventory;
#[allow(dead_code)]
pub(crate) mod key_packages;
pub(crate) mod leave;
pub(crate) mod message_delivery;
mod message_event;
pub(crate) mod prelude;
#[allow(dead_code)]
pub(crate) mod recovery;
pub(crate) mod relationship;
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

pub(crate) mod direct_request_lifecycle;

pub(crate) mod push_binding;

#[cfg(test)]
mod concurrency_tests;
#[cfg(test)]
mod rollback_tests;
#[cfg(test)]
mod inventory_repository_tests;
#[cfg(test)]
#[path = "delivery/read_tests.rs"]
mod delivery_read_tests;
#[cfg(test)]
#[path = "welcome/tests.rs"]
mod welcome_tests;
#[cfg(test)]
#[path = "recovery/tests.rs"]
mod recovery_tests;
#[cfg(test)]
#[path = "ticket/tests.rs"]
mod ticket_tests;
#[cfg(test)]
#[path = "reset/tests.rs"]
mod reset_repository_tests;
#[cfg(test)]
#[path = "reset/wedge_tests.rs"]
mod reset_wedge_tests;
#[cfg(test)]
#[path = "relationship/tests.rs"]
mod relationship_repository_tests;
#[cfg(test)]
#[path = "transition/tests.rs"]
mod transition_repository_tests;
#[cfg(test)]
#[path = "auth/tests.rs"]
mod auth_repository_tests;
#[cfg(test)]
mod inventory_tests;
#[cfg(test)]
mod g7_entitlement_tests;
#[cfg(test)]
mod conversation_substrate_tests;
