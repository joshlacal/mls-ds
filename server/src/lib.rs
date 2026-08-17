// Crate-level clippy allows still load-bearing under
// `cargo clippy -- -D warnings`.
//
// `chore/ci-cleanup` (Apr 2026) removed the following blanket allows after
// the underlying violations were either fixed at the call site or scoped to
// per-struct / per-field allows: `dead_code`, `unused_imports`,
// `clippy::large_enum_variant`, `clippy::doc_overindented_list_items`,
// `clippy::doc_lazy_continuation`. Re-adding any of those at the crate level
// requires justification — fix the violation or add the narrowest local
// allow.
//
// Surviving allows. Each has a concrete follow-up; do not remove without
// fixing the underlying issues:
//
//   - `clippy::too_many_arguments` — 7 functions in `handlers::mls_chat`
//     and the federation outbound path exceed the 7-arg default. Refactor
//     groups stable bundles (auth context, db pool + conversation id,
//     idempotency keys) into request structs. Tracked as
//     TODO(phase-2.5-cleanup-too-many-args).
//   - `clippy::type_complexity` — 10 sites use deeply nested generic types
//     (`Arc<Mutex<HashMap<String, Box<dyn Fn(...) -> Result<...>>>>>`-shaped).
//     Fix per-site: introduce a `type` alias or a thin newtype. Tracked as
//     TODO(phase-2.5-cleanup-type-aliases).
//   - `clippy::should_implement_trait` — 3 inherent `from_str` methods on
//     state-machine enums (`TrustLevel`, `CryptoSessionState`, etc.).
//     Migrating to `impl FromStr` is mechanical but breaks every inherent
//     call site, so it ships in its own PR. Tracked as
//     TODO(phase-2.5-cleanup-fromstr).
//   - `deprecated` — 4 callers of
//     `sha2::digest::generic_array::GenericArray::from_slice`, deprecated in
//     generic-array 0.14 (still in tree via `sha2 0.10`). The replacement is
//     `<&[u8]>::try_into` or `GenericArray::from_slice` from generic-array
//     1.x, which lands when we bump to `sha2 = "0.11"`. Tracked as
//     TODO(phase-2.5-cleanup-genericarray).
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::should_implement_trait)]
#![allow(deprecated)]

#[cfg(all(feature = "server-bin", feature = "chat-protocol-production-proof"))]
compile_error!(
    "`chat-protocol-production-proof` is a non-shipping test surface and cannot coexist with `server-bin`"
);
#[cfg(all(feature = "subscription-production-proof", feature = "server-bin"))]
compile_error!(
    "`subscription-production-proof` is a non-shipping test surface and cannot coexist with `server-bin`"
);

pub mod actors;
pub mod atproto_bytes;
pub mod auth;
pub mod blob_store;
pub mod block_sync;
pub mod chat_protocol;
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
pub mod mls_group_info_verifier;
pub mod mls_transition;
pub mod models;
pub mod notifications;
pub mod realtime;
pub mod repositories;
pub mod storage;
pub mod util;
pub mod workers;

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
