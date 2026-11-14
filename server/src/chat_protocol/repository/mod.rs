//! PostgreSQL boundaries for clean-chat protocol authority.

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod acceptance;
#[cfg(any(test, feature = "test-support"))]
pub mod acceptance;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod auth;
#[cfg(any(test, feature = "test-support"))]
pub mod auth;

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

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod device_approval;
#[cfg(any(test, feature = "test-support"))]
pub mod device_approval;

#[allow(dead_code)]
#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod device_directory;
#[allow(dead_code)]
#[cfg(any(test, feature = "test-support"))]
pub mod device_directory;

pub(crate) mod direct_request_opening;

#[allow(dead_code)]
pub(crate) mod direct_request_preparation;

#[allow(dead_code)]
pub(crate) mod direct_request_publication;

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

pub(crate) mod transport_welcome;

pub(crate) mod close_terminal;

#[cfg(test)]
#[path = "auth/tests.rs"]
mod auth_repository_tests;
#[cfg(test)]
mod concurrency_tests;
#[cfg(test)]
mod conversation_substrate_tests;
#[cfg(test)]
#[path = "delivery/read_tests.rs"]
mod delivery_read_tests;
#[cfg(all(test, feature = "test-support"))]
#[path = "delivery/remote_pruning_tests.rs"]
mod delivery_remote_pruning_tests;
#[cfg(all(test, feature = "test-support", feature = "sim"))]
#[path = "direct_request_opening/tests.rs"]
pub(crate) mod direct_request_opening_tests;
#[cfg(test)]
mod g7_entitlement_tests;
#[cfg(all(test, feature = "test-support", feature = "sim"))]
#[path = "delivery/idempotency_erasure_tests.rs"]
mod idempotency_erasure_tests;
#[cfg(test)]
mod inventory_repository_tests;
#[cfg(test)]
mod inventory_tests;
#[cfg(test)]
#[path = "key_packages/federated_reservation_tests.rs"]
mod key_package_federated_reservation_tests;
#[cfg(test)]
#[path = "recovery/tests.rs"]
mod recovery_tests;
#[cfg(test)]
#[path = "relationship/tests.rs"]
mod relationship_repository_tests;
#[cfg(test)]
#[path = "reset/tests.rs"]
mod reset_repository_tests;
#[cfg(test)]
#[path = "reset/wedge_tests.rs"]
mod reset_wedge_tests;
#[cfg(test)]
mod rollback_tests;
#[cfg(test)]
#[path = "ticket/tests.rs"]
mod ticket_tests;
#[cfg(test)]
#[path = "transition/tests.rs"]
mod transition_repository_tests;
#[cfg(test)]
#[path = "welcome/tests.rs"]
mod welcome_tests;
