pub mod actors;
pub mod admin_system;
pub mod atproto_bytes;
pub mod auth;
pub mod block_sync;
pub mod crypto;
pub mod db;
pub mod device_utils;
pub mod error;
pub mod error_responses;
pub mod fanout;
pub mod federation;
pub mod group_info;
pub mod handlers;
pub mod health;
pub mod identity;
// pub mod jobs;  // Temporarily disabled - requires new DB schema
pub mod jacquard_json;
pub mod metrics;
pub mod middleware;
pub mod models;
pub mod notifications;
pub mod realtime;
pub mod storage;
pub mod util;

// Re-export jacquard-common types for generated and migrated code
pub use jacquard_common::types;

// Generated types from lexicon schemas
pub mod generated;
pub mod generated_types;

// Re-export jacquard-generated namespaces at the crate root so external crates
// can depend on a stable, ergonomic path (e.g., `server::blue_catbird`) rather
// than importing from the internal `generated` module hierarchy. These re-exports
// are part of the intended public API surface for jacquard-generated types.
pub use generated::blue_catbird;
pub use generated::builder_types;

// sqlx conversion helpers for jacquard-common types
pub mod sqlx_jacquard;
