//! Strict wire shapes of `blue.catbird.labyrinth.defs#epochPublic` and
//! `#transportAttestation` as accepted by the `mls-ds` epoch-head directory.

use serde::{Deserialize, Serialize};

use super::bytes::{check_epoch_number, Bytes};
use crate::labyrinth::error::LabyrinthResult;

/// `defs#transportAttestation`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportAttestation {
    pub transport_pubkey: Bytes,
    pub sig: Bytes,
}

/// `defs#epochPublic`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochPublic {
    pub epoch_number: u64,
    pub auth_pubkey: Bytes,
    pub encryption_pubkey: Bytes,
    pub signing_pubkey: Bytes,
    pub members_hash: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_epoch_head: Option<Bytes>,
    pub epoch_head: Bytes,
    pub self_sig: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_sig: Option<Bytes>,
    pub attestation: TransportAttestation,
}

impl EpochPublic {
    pub fn validate(&self) -> LabyrinthResult<()> {
        check_epoch_number("epochNumber", self.epoch_number)?;
        self.auth_pubkey.check("authPubkey", 32, 32)?;
        self.encryption_pubkey
            .check("encryptionPubkey", 1216, 1216)?;
        self.signing_pubkey.check("signingPubkey", 32, 32)?;
        self.members_hash.check("membersHash", 32, 32)?;
        if let Some(h) = &self.previous_epoch_head {
            h.check("previousEpochHead", 32, 32)?;
        }
        self.epoch_head.check("epochHead", 32, 32)?;
        self.self_sig.check("selfSig", 64, 64)?;
        if let Some(s) = &self.prev_sig {
            s.check("prevSig", 64, 64)?;
        }
        self.attestation
            .transport_pubkey
            .check("attestation.transportPubkey", 32, 32)?;
        self.attestation.sig.check("attestation.sig", 64, 64)
    }
}
