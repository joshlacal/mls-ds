pub mod auth;
pub mod crypto;
pub mod db;
pub mod fanout;
pub mod handlers;
pub mod health;
pub mod jobs;
pub mod metrics;
pub mod middleware;
pub mod models;
pub mod realtime;
pub mod storage;
pub mod util;
// Re-export atrium-api types as  so generated modules compile
pub use atrium_api::types;

// Generated API for custom blue.catbird.mls namespace
pub mod generated_api;
// Expose blue namespace and generated client/record at crate root
pub use generated_api::blue;
pub use generated_api::client as atp_client;
pub use generated_api::record as atp_record;
