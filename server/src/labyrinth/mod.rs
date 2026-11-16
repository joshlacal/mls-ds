//! Labyrinth 1.1 verifying epoch-head directory and device-key view (`blue.catbird.labyrinth.*`).
//!
//! Under clean-slate Spaces-only consolidation (`G6`, `I14`, `2A`), `mls-ds` stores zero
//! Labyrinth mailboxes, sender batches, MEKs, attachment references, ORF states, or virtual
//! devices. The Dec 1 erasable recovery feature adds one KEK-wrapped share per
//! recovery method and an external erasure journal. `mls-ds` serves:
//! - the verifying `EpochPublic` head-chain directory (`publishEpochHead`, `getEpochHead`)
//!   with `L-F01` monotonic `floorSeq` (`purgeMailbox`, `deleteAccountData`);
//! - the chat device-key and conversation leaf views (`getChatDeviceKeys`, `getMemberDevices`);
//! - short-TTL (7-day) operation idempotency (`labyrinth.operations`).
//! - private recovery-share XRPCs, with fetch sealed to a caller's ephemeral key.

pub mod auth;
pub mod error;
pub mod heads;
pub mod read_auth;
pub mod recovery_crypto;
pub mod recovery_tombstones;
pub mod repo;
pub mod tid;
pub mod wire;

pub use error::{LabyrinthError, LabyrinthResult};
