//! Epoch-head verification delegated to `labyrinth_protocol::epoch_chain` (`Gate 3`, `Gate 6`).

use labyrinth_protocol::epoch_chain::{
    compute_epoch_head as protocol_compute_epoch_head, ed25519_verify_strict, xeddsa_verify,
};
use labyrinth_protocol::transcripts::{
    EPOCH_ATTEST_PREFIX, EPOCH_PREV_SIG_PREFIX, EPOCH_SELF_SIG_PREFIX,
};

use super::error::{LabyrinthError, LabyrinthResult};
use super::wire::records::EpochPublic;

/// The parsed fixed-size parts of an `epochPublic` the server checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadParts {
    pub epoch_number: u64,
    pub head: [u8; 32],
    pub members_hash: [u8; 32],
    pub previous_head: Option<[u8; 32]>,
    pub attestation_key: [u8; 32],
    /// The epoch's XEdDSA signing key (X25519 u-coordinate).
    pub signing_key: [u8; 32],
    pub prev_sig: Option<[u8; 64]>,
}

/// `get_epoch_head` (`SPEC §5.3` + `Gate 3` `membersHash` binding) with `user_did`.
pub fn compute_epoch_head(
    epoch_number: u64,
    auth_pubkey: &[u8; 32],
    encryption_pubkey: &[u8],
    signing_pubkey: &[u8; 32],
    members_hash: &[u8; 32],
    previous_head: Option<&[u8; 32]>,
    did: &str,
) -> [u8; 32] {
    protocol_compute_epoch_head(
        epoch_number,
        auth_pubkey,
        encryption_pubkey,
        signing_pubkey,
        members_hash,
        previous_head,
        did,
    )
}

/// The `[CB-18]` attestation message.
pub fn attestation_message(did: &str, head: &[u8; 32]) -> Vec<u8> {
    [
        format!("{EPOCH_ATTEST_PREFIX}{did}:").as_bytes(),
        head.as_slice(),
    ]
    .concat()
}

fn bad_sig(what: &str) -> LabyrinthError {
    LabyrinthError::invalid(format!("{what} does not verify"))
}

/// Verify `EpochPublic` recomputation, `membersHash` binding, Ed25519 attestation,
/// and XEdDSA `selfSig` via `labyrinth_protocol::epoch_chain`.
pub fn verify_epoch_public(did: &str, epoch: &EpochPublic) -> LabyrinthResult<HeadParts> {
    epoch.validate()?;
    let auth_pubkey = epoch.auth_pubkey.array::<32>("authPubkey")?;
    let signing_key = epoch.signing_pubkey.array::<32>("signingPubkey")?;
    let members_hash = epoch.members_hash.array::<32>("membersHash")?;
    let previous_head = epoch
        .previous_epoch_head
        .as_ref()
        .map(|h| h.array::<32>("previousEpochHead"))
        .transpose()?;
    let valid_link_shape = if epoch.epoch_number == 0 {
        previous_head.is_none() && epoch.prev_sig.is_none()
    } else {
        previous_head.is_none() == epoch.prev_sig.is_none()
    };
    if !valid_link_shape {
        return Err(LabyrinthError::invalid(
            "epoch 0 has no previousEpochHead/prevSig and later epochs carry both or neither",
        ));
    }
    let head = epoch.epoch_head.array::<32>("epochHead")?;
    let expected = compute_epoch_head(
        epoch.epoch_number,
        &auth_pubkey,
        &epoch.encryption_pubkey.0,
        &signing_key,
        &members_hash,
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
    ed25519_verify_strict(&attestation_key, &attestation_message(did, &head), &sig)
        .map_err(|_| LabyrinthError::invalid("attestation signature does not verify"))?;

    let self_sig = epoch.self_sig.array::<64>("selfSig")?;
    xeddsa_verify(
        &signing_key,
        &[EPOCH_SELF_SIG_PREFIX, head.as_slice()].concat(),
        &self_sig,
    )
    .map_err(|_| bad_sig("selfSig"))?;

    let prev_sig = epoch
        .prev_sig
        .as_ref()
        .map(|s| s.array::<64>("prevSig"))
        .transpose()?;
    Ok(HeadParts {
        epoch_number: epoch.epoch_number,
        head,
        members_hash,
        previous_head,
        attestation_key,
        signing_key,
        prev_sig,
    })
}

/// SPEC §5.3 `prev_sig`: epoch `n`'s head signed by epoch `n - 1`'s signing key.
pub fn verify_prev_sig(parts: &HeadParts, previous_signing_key: &[u8; 32]) -> LabyrinthResult<()> {
    match &parts.prev_sig {
        Some(sig)
            if xeddsa_verify(
                previous_signing_key,
                &[EPOCH_PREV_SIG_PREFIX, parts.head.as_slice()].concat(),
                sig,
            )
            .is_ok() =>
        {
            Ok(())
        }
        _ => Err(bad_sig("prevSig")),
    }
}

/// Check genesis / post-purge `floor + 1` restart / contiguous `latest + 1` extension.
pub fn check_chain_link(
    parts: &HeadParts,
    latest: Option<(u64, [u8; 32])>,
    floor: Option<u64>,
) -> LabyrinthResult<()> {
    let ok = match (latest, floor) {
        (None, None) => parts.epoch_number == 0 && parts.previous_head.is_none(),
        (None, Some(prior_max)) => {
            prior_max.checked_add(1) == Some(parts.epoch_number)
                && parts.previous_head.is_none()
                && parts.prev_sig.is_none()
        }
        (Some((n, head)), _) => {
            n.checked_add(1) == Some(parts.epoch_number) && parts.previous_head == Some(head)
        }
    };
    if ok {
        Ok(())
    } else {
        Err(LabyrinthError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "InvalidEpochChain",
            "epoch head must be genesis, restart at floor + 1, or extend the latest head by one",
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
            members_hash: [5; 32],
            previous_head: prev,
            attestation_key: [0; 32],
            signing_key: [0; 32],
            prev_sig: prev.map(|_| [7; 64]),
        };
        assert!(check_chain_link(&parts(0, None), None, None).is_ok());
        assert!(check_chain_link(&parts(1, Some([1; 32])), None, None).is_err());
        assert!(check_chain_link(&parts(1, Some([1; 32])), Some((0, [1; 32])), None).is_ok());
        assert!(check_chain_link(&parts(1, Some([2; 32])), Some((0, [1; 32])), None).is_err());
        assert!(check_chain_link(&parts(2, Some([1; 32])), Some((0, [1; 32])), None).is_err());
        assert!(check_chain_link(&parts(0, None), Some((0, [1; 32])), None).is_err());
        // Post-purge floor enforcement:
        assert!(check_chain_link(&parts(0, None), None, Some(1)).is_err());
        assert!(check_chain_link(&parts(1, None), None, Some(1)).is_err());
        assert!(check_chain_link(&parts(2, Some([1; 32])), None, Some(1)).is_err());
        assert!(check_chain_link(&parts(3, None), None, Some(1)).is_err());
        assert!(check_chain_link(&parts(2, None), None, Some(1)).is_ok());
    }
}
