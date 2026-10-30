//! Test-built epoch chains (`epochPublic`, labyrinth SPEC §5.3) with keys the
//! test controls: a deterministic XEdDSA signer for `selfSig` / `prevSig`
//! and the [CB-18] attestation by a harness chat device. The crate's golden
//! vectors (`harness::vectors`) cover crate interop; these cover chains the
//! crate never signs (wrong `prevSig`, attacker-built heads).

#![allow(dead_code)]

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::{clamp_integer, Scalar};
use ed25519_dalek::Signer as _;
use serde_json::Value;
use sha2::{Digest, Sha512};

use catbird_server::labyrinth::heads::{attestation_message, compute_epoch_head};

use crate::harness::{b, Device};

/// XEdDSA public key (X25519 u-coordinate) of private key `k`.
pub fn xpub(k: [u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(k).to_bytes()
}

/// XEdDSA signature (Signal spec §2.3-2.4) with a deterministic nonce.
pub fn xsign(k: [u8; 32], msg: &[u8]) -> [u8; 64] {
    let mut a = Scalar::from_bytes_mod_order(clamp_integer(k));
    let mut a_point = EdwardsPoint::mul_base(&a);
    if a_point.compress().as_bytes()[31] >> 7 == 1 {
        a = -a;
        a_point = -a_point;
    }
    let nonce: [u8; 64] = Sha512::digest([&k[..], msg].concat()).into();
    let r = Scalar::from_bytes_mod_order_wide(&nonce);
    let r_bytes = EdwardsPoint::mul_base(&r).compress().to_bytes();
    let mut h = Sha512::new();
    h.update(r_bytes);
    h.update(a_point.compress().as_bytes());
    h.update(msg);
    let h = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice((r + h * a).as_bytes());
    sig
}

/// One link of a test chain: the epoch's signing key and its head.
#[derive(Clone, Copy)]
pub struct Link {
    pub signing_seed: [u8; 32],
    pub head: [u8; 32],
}

/// Build epoch `n` of `attester`'s DID: signing key `signing_seed`, linked
/// to `prev` (`None` for genesis) whose key signs `prevSig` unless
/// `prev_signer` overrides it.
pub fn epoch_public(
    attester: &Device,
    n: u64,
    signing_seed: [u8; 32],
    prev: Option<Link>,
    prev_signer: Option<[u8; 32]>,
) -> (Value, Link) {
    let did = &attester.did;
    let auth = [n as u8 ^ 0x21; 32];
    let enc = vec![n as u8 ^ 0x42; 1216];
    let signing = xpub(signing_seed);
    let head = compute_epoch_head(
        n,
        &auth,
        &enc,
        &signing,
        prev.as_ref().map(|p| &p.head),
        did,
    );
    let self_sig = xsign(
        signing_seed,
        &[
            b"minos.unstructured_signature.epoch_self:".as_slice(),
            &head,
        ]
        .concat(),
    );
    let mut v = serde_json::json!({
        "epochNumber": n,
        "authPubkey": b(&auth),
        "encryptionPubkey": b(&enc),
        "signingPubkey": b(&signing),
        "epochHead": b(&head),
        "selfSig": b(&self_sig),
        "attestation": {
            "transportPubkey": b(&attester.chat_pub()),
            "sig": b(&attester.chat_key.sign(&attestation_message(did, &head)).to_bytes()),
        },
    });
    if let Some(p) = prev {
        let signer = prev_signer.unwrap_or(p.signing_seed);
        let prev_sig = xsign(
            signer,
            &[
                b"minos.unstructured_signature.epoch_prev:".as_slice(),
                &head,
            ]
            .concat(),
        );
        v["previousEpochHead"] = b(&p.head);
        v["prevSig"] = b(&prev_sig);
    }
    (v, Link { signing_seed, head })
}
