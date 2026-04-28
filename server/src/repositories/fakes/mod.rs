//! In-memory fakes for repository traits. Test-only.

pub mod crypto_session;
pub mod delivery_log;

pub use crypto_session::InMemoryCryptoSessionRepository;
pub use delivery_log::InMemoryDeliveryLogRepository;
