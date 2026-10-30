//! XEdDSA verification (Signal XEdDSA rev. 1 §2.4, labyrinth SPEC §3.3).
//!
//! mls-ds re-implements this one small check instead of depending on the
//! private labyrinth crate (design Y1, as amended by the second security
//! review): the head directory verifies an epoch's `selfSig` and, along the
//! chain, its `prevSig`, so an attested-but-unchained head cannot be planted.
//! It mirrors the crate's `XVerifyingKey::verify` exactly, including its two
//! stricter-than-spec checks (canonical `s`, no small-order public key).
//!
//! ```text
//! verify(u, M, R || s):
//!   reject u >= p, s >= q, u not on the curve, A small-order
//!   A = convert_mont(u) (sign bit 0);  h = SHA-512(R || A || M) mod q
//!   accept iff encode(sB - hA) == R
//! ```

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// `2^255 - 19`, little-endian.
const P_LE: [u8; 32] = {
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};

/// Little-endian `x < p` (also rejects the high bit).
fn is_reduced_field(x: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if x[i] != P_LE[i] {
            return x[i] < P_LE[i];
        }
    }
    false
}

/// Verify XEdDSA signature `sig` over `msg` under the X25519 public key `u`.
pub fn verify(u: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let r_bytes: [u8; 32] = sig[..32].try_into().expect("32-byte half");
    let s_bytes: [u8; 32] = sig[32..].try_into().expect("32-byte half");
    if !is_reduced_field(u) || s_bytes[31] & 0xe0 != 0 {
        return false;
    }
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
        return false;
    };
    let Some(a_point) = MontgomeryPoint(*u).to_edwards(0) else {
        return false;
    };
    if a_point.is_small_order() {
        return false;
    }
    let mut h = Sha512::new();
    h.update(r_bytes);
    h.update(a_point.compress().as_bytes());
    h.update(msg);
    let wide: [u8; 64] = h.finalize().into();
    let h = Scalar::from_bytes_mod_order_wide(&wide);
    let r_check = EdwardsPoint::vartime_double_scalar_mul_basepoint(&-h, &a_point, &s);
    super::repo::ct_eq(r_check.compress().as_bytes(), &r_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::clamp_integer;

    /// An XEdDSA signer (spec §2.3 calculate_key_pair + §2.4 sign) with a
    /// deterministic nonce, for tests only.
    fn sign(k: [u8; 32], msg: &[u8]) -> ([u8; 32], [u8; 64]) {
        let mut a = Scalar::from_bytes_mod_order(clamp_integer(k));
        let mut a_point = EdwardsPoint::mul_base(&a);
        if a_point.compress().as_bytes()[31] >> 7 == 1 {
            a = -a;
            a_point = -a_point;
        }
        let r = Scalar::from_bytes_mod_order_wide(&Sha512::digest([&k[..], msg].concat()).into());
        let r_bytes = EdwardsPoint::mul_base(&r).compress().to_bytes();
        let mut h = Sha512::new();
        h.update(r_bytes);
        h.update(a_point.compress().as_bytes());
        h.update(msg);
        let h = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
        let s = r + h * a;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice(s.as_bytes());
        (MontgomeryPoint::mul_base_clamped(k).to_bytes(), sig)
    }

    #[test]
    fn round_trip_and_rejections() {
        let (u, sig) = sign([7; 32], b"hello");
        assert!(verify(&u, b"hello", &sig));
        assert!(!verify(&u, b"hellp", &sig));
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!verify(&u, b"hello", &bad));
        // s >= 2^253 is refused.
        let mut big = sig;
        big[63] |= 0x80;
        assert!(!verify(&u, b"hello", &big));
        // u >= p.
        assert!(!verify(&[0xff; 32], b"hello", &sig));
    }
}
