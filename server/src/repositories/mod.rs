//! Repository abstractions for the crypto-session architecture.
//!
//! Phase 2: traits backed by Postgres reads/writes against the new
//! `crypto_sessions` and `delivery_events` tables. Reads on
//! `CryptoSessionRepository` fall back to legacy `conversations` MLS
//! columns during the compatibility window and emit a counter so the
//! cleanup migration can be telemetry-gated.

pub mod crypto_session;
pub mod delivery_log;
pub mod fakes;

pub use crypto_session::{CryptoSessionRepository, PostgresCryptoSessionRepository};
pub use delivery_log::{DeliveryLogRepository, PostgresDeliveryLogRepository};

use thiserror::Error;

/// Repository-level errors.
#[derive(Debug, Error)]
pub enum RepositoryError {
    /// Reserved for future operations not yet plumbed through. No Phase 2
    /// path returns this; it is kept on the surface for forward compat.
    #[error("not implemented")]
    NotImplemented,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

pub type RepositoryResult<T> = Result<T, RepositoryError>;
