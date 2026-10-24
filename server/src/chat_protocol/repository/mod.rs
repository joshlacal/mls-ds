//! PostgreSQL boundaries for clean-chat protocol authority.

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod acceptance;
#[cfg(any(test, feature = "test-support"))]
pub mod acceptance;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod auth;
#[cfg(any(test, feature = "test-support"))]
pub mod auth;

#[allow(dead_code)]
#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod blobs;
#[allow(dead_code)]
#[cfg(any(test, feature = "test-support"))]
pub mod blobs;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod conversation;
#[cfg(any(test, feature = "test-support"))]
pub mod conversation;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod coordinate;
#[cfg(any(test, feature = "test-support"))]
pub mod coordinate;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod core;
#[cfg(any(test, feature = "test-support"))]
pub mod core;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod creation;
#[cfg(any(test, feature = "test-support"))]
pub mod creation;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod delivery;
#[cfg(any(test, feature = "test-support"))]
pub mod delivery;

#[allow(dead_code)]
#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod device_directory;
#[allow(dead_code)]
#[cfg(any(test, feature = "test-support"))]
pub mod device_directory;

#[allow(dead_code)]
pub(crate) mod direct_request_preparation;

#[allow(dead_code)]
pub(crate) mod direct_request_publication;

pub(crate) mod direct_request_push;

#[allow(dead_code)]
pub mod direct_request_receipts;

pub(crate) mod direct_request_retention;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod entry_read;
#[cfg(any(test, feature = "test-support"))]
pub mod entry_read;

#[allow(dead_code)]
#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod execution_context;
#[allow(dead_code)]
#[cfg(any(test, feature = "test-support"))]
pub mod execution_context;

#[allow(dead_code)]
#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod expiry_sweep;
#[allow(dead_code)]
#[cfg(any(test, feature = "test-support"))]
pub mod expiry_sweep;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod federation;
#[cfg(any(test, feature = "test-support"))]
pub mod federation;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod inventory;
#[cfg(any(test, feature = "test-support"))]
pub mod inventory;

#[allow(dead_code)]
#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod key_packages;
#[allow(dead_code)]
#[cfg(any(test, feature = "test-support"))]
pub mod key_packages;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod leave;
#[cfg(any(test, feature = "test-support"))]
pub mod leave;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod message_delivery;
#[cfg(any(test, feature = "test-support"))]
pub mod message_delivery;

pub(crate) mod message_event;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod prelude;
#[cfg(any(test, feature = "test-support"))]
pub mod prelude;

#[allow(dead_code)]
#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod recovery;
#[allow(dead_code)]
#[cfg(any(test, feature = "test-support"))]
pub mod recovery;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod relationship;
#[cfg(any(test, feature = "test-support"))]
pub mod relationship;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod remote_prefix;
#[cfg(any(test, feature = "test-support"))]
pub mod remote_prefix;

#[allow(dead_code)]
#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod reset;
#[allow(dead_code)]
#[cfg(any(test, feature = "test-support"))]
pub mod reset;

#[allow(dead_code)]
#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod revocation;
#[allow(dead_code)]
#[cfg(any(test, feature = "test-support"))]
pub mod revocation;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod submit_transition;
#[cfg(any(test, feature = "test-support"))]
pub mod submit_transition;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod subscription;
#[cfg(any(test, feature = "test-support"))]
pub mod subscription;

#[allow(dead_code)]
#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod ticket;
#[allow(dead_code)]
#[cfg(any(test, feature = "test-support"))]
pub mod ticket;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod transition;
#[cfg(any(test, feature = "test-support"))]
pub mod transition;

#[allow(dead_code)]
#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod welcome;
#[allow(dead_code)]
#[cfg(any(test, feature = "test-support"))]
pub mod welcome;

#[allow(dead_code)]
#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod welcome_terminal;
#[allow(dead_code)]
#[cfg(any(test, feature = "test-support"))]
pub mod welcome_terminal;

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
