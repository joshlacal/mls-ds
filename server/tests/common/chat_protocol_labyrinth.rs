//! Mount the private Labyrinth write-body wire alongside the chat repository harness.
pub use catbird_server::labyrinth::*;

#[path = "../../src/labyrinth/write_body_wire.rs"]
pub mod auth;
