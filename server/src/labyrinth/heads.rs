//! Epoch-head checks mls-ds performs itself (design §1a, Y1).
//!
//! The labyrinth crate is private, so mls-ds re-implements exactly two small
//! pieces of it: the sha256 epoch-head recomputation of SPEC §5.3 (with the
//! account DID in place of Meta's fbid, [CB-1]) and the [CB-18] Ed25519
//! attestation by a chat device key. It does NOT verify the XEdDSA
//! `selfSig`/`prevSig`: clients verify those (`src/client/pins.rs`), and the
//! server chain is anchored by contiguity, the previous-head link and the
//! live chat identity of the attesting key instead.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use super::error::{LabyrinthError, LabyrinthResult};
use super::wire::records::EpochPublic;

const ATTEST_PREFIX: &str = "catbird.labyrinth.epoch_head_attest:";

/// The parsed fixed-size parts of an `epochPublic` the server checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadParts {
    pub epoch_number: u64,
    pub head: [u8; 32],
    pub previous_head: Option<[u8; 32]>,
    pub attestation_key: [u8; 32],
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// `get_epoch_head` (SPEC §5.3; paper p.22–23) with `user_did`.
pub fn compute_epoch_head(
    epoch_number: u64,
    auth_pubkey: &[u8],
    encryption_pubkey: &[u8],
    signing_pubkey: &[u8],
    previous_head: Option<&[u8; 32]>,
    did: &str,
) -> [u8; 32] {
    let prev = previous_head.map_or_else(|| "null".to_owned(), hex::encode);
    let epoch_hash = sha256(
        format!(
            "epoch_public_data:auth_pubkey={};encryption_pubkey={};epoch_number={epoch_number};\
             previous_epoch_head={prev};signing_pubkey={};user_did={did}",
            hex::encode(auth_pubkey),
            hex::encode(encryption_pubkey),
            hex::encode(signing_pubkey),
        )
        .as_bytes(),
    );
    sha256(
        format!(
            "epoch_head:epoch_hash={};epoch_number={epoch_number};previous_epoch_head={prev}",
            hex::encode(epoch_hash)
        )
        .as_bytes(),
    )
}

/// The [CB-18] attestation message.
pub fn attestation_message(did: &str, head: &[u8; 32]) -> Vec<u8> {
    [format!("{ATTEST_PREFIX}{did}:").as_bytes(), head.as_slice()].concat()
}

/// Checks 3 and 4 of design §1a: the head recomputes from the public keys
/// and the attestation is a valid Ed25519 signature over it. Also enforces
/// the genesis shape (epoch 0 has no predecessor and no `prevSig`; later
/// epochs have both). Returns the parts the chain checks need.
pub fn verify_epoch_public(did: &str, epoch: &EpochPublic) -> LabyrinthResult<HeadParts> {
    epoch.validate()?;
    let previous_head = epoch
        .previous_epoch_head
        .as_ref()
        .map(|h| h.array::<32>("previousEpochHead"))
        .transpose()?;
    let genesis = epoch.epoch_number == 0;
    if genesis != previous_head.is_none() || genesis != epoch.prev_sig.is_none() {
        return Err(LabyrinthError::invalid(
            "epoch 0 has no previousEpochHead/prevSig and every later epoch has both",
        ));
    }
    let head = epoch.epoch_head.array::<32>("epochHead")?;
    let expected = compute_epoch_head(
        epoch.epoch_number,
        &epoch.auth_pubkey.0,
        &epoch.encryption_pubkey.0,
        &epoch.signing_pubkey.0,
        previous_head.as_ref(),
        did,
    );
    if expected != head {
        return Err(LabyrinthError::invalid(
            "epochHead does not match the recomputed head",
        ));
    }
    let attestation_key = epoch
        .attestation
        .transport_pubkey
        .array::<32>("attestation.transportPubkey")?;
    let sig = epoch.attestation.sig.array::<64>("attestation.sig")?;
    let key = VerifyingKey::from_bytes(&attestation_key)
        .map_err(|_| LabyrinthError::invalid("attestation key is not an Ed25519 point"))?;
    key.verify_strict(
        &attestation_message(did, &head),
        &Signature::from_bytes(&sig),
    )
    .map_err(|_| LabyrinthError::invalid("attestation signature does not verify"))?;
    Ok(HeadParts {
        epoch_number: epoch.epoch_number,
        head,
        previous_head,
        attestation_key,
    })
}

/// Check 1 and 2 of design §1a against the stored latest head of the DID:
/// genesis only on an empty chain, otherwise exactly latest + 1 linking to
/// the latest head.
pub fn check_chain_link(parts: &HeadParts, latest: Option<(u64, [u8; 32])>) -> LabyrinthResult<()> {
    let ok = match latest {
        None => parts.epoch_number == 0,
        Some((n, head)) => {
            n.checked_add(1) == Some(parts.epoch_number) && parts.previous_head == Some(head)
        }
    };
    if ok {
        Ok(())
    } else {
        Err(LabyrinthError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "InvalidEpochChain",
            "epoch head must be genesis or extend the latest head by one",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_link_rules() {
        let parts = |n, prev| HeadParts {
            epoch_number: n,
            head: [9; 32],
            previous_head: prev,
            attestation_key: [0; 32],
        };
        assert!(check_chain_link(&parts(0, None), None).is_ok());
        assert!(check_chain_link(&parts(1, Some([1; 32])), None).is_err());
        assert!(check_chain_link(&parts(1, Some([1; 32])), Some((0, [1; 32]))).is_ok());
        assert!(check_chain_link(&parts(1, Some([2; 32])), Some((0, [1; 32]))).is_err());
        assert!(check_chain_link(&parts(2, Some([1; 32])), Some((0, [1; 32]))).is_err());
        assert!(check_chain_link(&parts(0, None), Some((0, [1; 32]))).is_err());
    }
}
