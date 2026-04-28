//! Repository abstractions for the crypto-session architecture.
//!
//! Phase 1: trait + Postgres reads against legacy columns; writes return
//! `RepositoryError::NotImplemented` until Phase 2 introduces the
//! `crypto_sessions` and `delivery_events` tables.
//!
//! These traits exist so Phase 4 actor split can use fakes; Phase 1 does not
//! plumb them into `ConversationActor`.

pub mod crypto_session;
pub mod delivery_log;
pub mod fakes;

pub use crypto_session::{CryptoSessionRepository, PostgresCryptoSessionRepository};
pub use delivery_log::{DeliveryLogRepository, PostgresDeliveryLogRepository};

use thiserror::Error;

/// Repository-level errors. Phase 1 keeps these narrow; Phase 2 may extend.
#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("not implemented until Phase 2 schema migration")]
    NotImplemented,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

pub type RepositoryResult<T> = Result<T, RepositoryError>;
