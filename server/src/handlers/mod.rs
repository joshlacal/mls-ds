// Handler modules for API endpoints
pub mod chat;
pub mod ds;
mod federation_mode_admin;
mod federation_peers_admin;
pub mod get_request_count;
pub mod resolve_delivery_service;
pub mod subscription_ticket;

// Re-exports
pub use federation_mode_admin::{get_federation_mode, set_federation_mode};
pub use federation_peers_admin::{
    delete_federation_peer, get_federation_peers, upsert_federation_peer,
};
pub use subscription_ticket::get_subscription_ticket;
