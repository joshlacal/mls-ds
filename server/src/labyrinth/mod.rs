//! Labyrinth 1.1 storage backend (`blue.catbird.labyrinth.*`).
//!
//! mls-ds serves Catbird's encrypted-history protocol as a full backend:
//! a personal mailbox per DID, a sender-record store per conversation with
//! server-assigned order ([CB-27]), the ORF server role ([CB-17]) and an
//! independent, verifying directory of every DID's epoch heads ([CB-28],
//! [CB-29]). Design: labyrinth `docs/MLSDS_BACKEND.md` (decisions Y1–Y8).
//!
//! Layout: `wire` (strict record and input shapes), `heads` (the sha256
//! head and Ed25519 attestation checks, re-implemented per Y1), `orf`
//! (Ristretto255 server operations), `auth` (admission, device locking,
//! signed writes, idempotency), `repo` (SQL over the `labyrinth` schema,
//! migrations `20261004100001`–`20261004100003`). HTTP handlers live in
//! `handlers::labyrinth`; the `labyrinthHead` projection of
//! `getConversationState` lives in `chat_protocol::repository::conversation`.
//!
//! Also: `relay` (the `labyrinthRelay` federation procedure, design Y3),
//! `digest` (keyed attachment-reference digests, J4) and
//! `repo::retention` (unsend, purges, recovery-bundle lifecycle, J1/J2).

pub mod auth;
pub mod digest;
pub mod error;
pub mod heads;
pub mod orf;
pub mod relay;
pub mod repo;
pub mod tid;
pub mod wire;
pub mod xeddsa;

pub use error::{LabyrinthError, LabyrinthResult};
