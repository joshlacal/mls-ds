//! The ORF server role over Ristretto255 (labyrinth SPEC §3.6, §8; [CB-17]).
//!
//! ```text
//! server_map(s, domain, P) = HMAC-SHA256(key = domain, data = compress(P * s))
//! server_evolve(s, r)      = s * r^-1
//! ```
//!
//! mls-ds holds one scalar per Labyrinth device key and applies `server_map`
//! only inside its attachment-reference endpoints, under the two fixed
//! domains below. It exposes no raw map oracle.

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use super::error::{LabyrinthError, LabyrinthResult};

/// Server domain for an attachment's blinded index (decision: fixed server
/// constants; the client binds its own scope in `client_map`).
pub const ATTACHMENT_INDEX_DOMAIN: &[u8] = b"catbird.labyrinth.orf.attachment_index";
/// Server domain for an attachment's blinded access token.
pub const ATTACHMENT_TOKEN_DOMAIN: &[u8] = b"catbird.labyrinth.orf.attachment_token";

fn nonzero_scalar(bytes: [u8; 32], what: &str) -> LabyrinthResult<Scalar> {
    let scalar: Option<Scalar> = Scalar::from_canonical_bytes(bytes).into();
    match scalar {
        Some(s) if s != Scalar::ZERO => Ok(s),
        _ => Err(LabyrinthError::invalid(format!(
            "{what} is not a canonical nonzero scalar"
        ))),
    }
}

/// A fresh uniform nonzero server state (`orf_server_init`).
pub fn server_init() -> [u8; 32] {
    loop {
        let mut wide = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut wide);
        let s = Scalar::from_bytes_mod_order_wide(&wide);
        if s != Scalar::ZERO {
            return s.to_bytes();
        }
    }
}

/// `orf_server_evolve(parent, token)`.
pub fn server_evolve(parent: [u8; 32], token: [u8; 32]) -> LabyrinthResult<[u8; 32]> {
    let s = nonzero_scalar(parent, "stored ORF state")?;
    let r = nonzero_scalar(token, "evolveToken")?;
    Ok((s * r.invert()).to_bytes())
}

/// `orf_server_map(state, domain, id)`; rejects ids that are not Ristretto
/// encodings or are the identity.
pub fn server_map(state: [u8; 32], domain: &[u8], id: [u8; 32]) -> LabyrinthResult<[u8; 32]> {
    let s = nonzero_scalar(state, "stored ORF state")?;
    let point = CompressedRistretto(id)
        .decompress()
        .ok_or_else(|| LabyrinthError::invalid("blinded value is not a Ristretto point"))?;
    if point.is_identity() {
        return Err(LabyrinthError::invalid("blinded value is the identity"));
    }
    let mapped = (point * s).compress();
    let mut mac = Hmac::<Sha256>::new_from_slice(domain).expect("HMAC accepts any key length");
    mac.update(mapped.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;

    fn client_point(c: Scalar, x: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        let h: [u8; 64] = sha2::Sha512::digest(x).into();
        (RistrettoPoint::from_uniform_bytes(&h) * c)
            .compress()
            .to_bytes()
    }

    #[test]
    fn evolve_preserves_the_map_output() {
        let s = server_init();
        let c = Scalar::from(11u64);
        let base = server_map(s, b"d", client_point(c, b"x")).unwrap();
        let r = Scalar::from(7u64);
        let s2 = server_evolve(s, r.to_bytes()).unwrap();
        let mapped = server_map(s2, b"d", client_point(c * r, b"x")).unwrap();
        assert_eq!(mapped, base);
    }

    #[test]
    fn rejects_zero_noncanonical_and_identity() {
        let s = server_init();
        assert!(server_evolve(s, [0; 32]).is_err());
        assert!(server_evolve([0xff; 32], Scalar::ONE.to_bytes()).is_err());
        assert!(server_map(s, b"d", [0; 32]).is_err());
        assert!(server_map(s, b"d", [0xff; 32]).is_err());
    }
}
