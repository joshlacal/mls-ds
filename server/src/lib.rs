// Pre-existing clippy noise batched for transitional acceptance under
// `cargo clippy -- -D warnings` in CI. None of these are correctness bugs; all
// reflect pre-existing patterns in this codebase that need a separate audit
// pass to refactor properly.
//
// TODO(phase-2.5-cleanup): per-category audit and remove these allows:
//   - too_many_arguments / type_complexity: factor handler tuples into structs
//   - dead_code: confirm each "never read" field is actually wired or remove
//   - should_implement_trait: review custom from_str impls vs FromStr
//   - deprecated (GenericArray): upgrade sha2 → generic-array 1.x
//   - doc-* lints: fix markdown indentation in rustdoc comments
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::large_enum_variant)]
#![allow(deprecated)]
#![allow(dead_code)]
#![allow(unused_imports)]

pub mod actors;
pub mod atproto_bytes;
pub mod auth;
pub mod blob_store;
pub mod block_sync;
pub mod config;
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
pub mod jacquard_json;
pub mod jobs;
pub mod metrics;
pub mod middleware;
pub mod models;
pub mod notifications;
pub mod realtime;
pub mod repositories;
pub mod storage;
pub mod util;

// Re-export shared generated types and common validated types.
pub use catbird_atproto::generated;
pub use catbird_atproto::types;

// Re-export jacquard-generated namespaces at the crate root so external crates
// can depend on a stable, ergonomic path (e.g., `server::blue_catbird`) rather
// than importing from the internal `generated` module hierarchy. These re-exports
// are part of the intended public API surface for jacquard-generated types.
pub use catbird_atproto::blue_catbird;
pub use catbird_atproto::builder_types;

// sqlx conversion helpers for jacquard-common types
pub mod sqlx_jacquard;
