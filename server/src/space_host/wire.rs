//! Wire details shared with deployed Space hosts and readers.
use axum::http::{HeaderMap, HeaderValue};
use petrel_core::{AtUri, Cid, Did, Nsid, RecordKey, SpaceRef, Tid};
use petrel_crypto::{ATProtoSignatureVerificationOptions, PublicKey};
use petrel_spaces::{
    sf::{parse_dictionary, DuplicatePolicy, SfDictionary, SfMember},
    MacProfile, SpaceError, SpaceMacHeaders,
};

pub(super) const ACCEPT_SIGNATURE_HEADER: &str = "accept-signature";
pub(super) const MAX_RECORD_BYTES: usize = 1024 * 1024;

pub(super) fn is_atproto_did(raw: &str) -> bool {
    Did::parse(raw).is_ok_and(|did| matches!(did.method(), "plc" | "web"))
}

pub(super) fn record_uri(
    space: &SpaceRef,
    repo: &str,
    collection: &str,
    key: &str,
) -> Result<AtUri, petrel_core::SyntaxError> {
    space.record_uri(
        &Did::parse(repo)?,
        &Nsid::parse(collection)?,
        &RecordKey::parse(key)?,
    )
}

fn header_error() -> SpaceError {
    SpaceError::InvalidSignatureHeader("invalid Space signature headers".into())
}

fn tagged<'a>(dict: &'a SfDictionary, tag: &str) -> petrel_spaces::Result<(&'a str, &'a SfMember)> {
    let mut matches = dict.entries.iter().filter(|(_, member)| {
        matches!(member, SfMember::InnerList(_, _))
            && member.param("tag").and_then(|v| v.as_string_strict()) == Some(tag)
    });
    let (label, member) = matches.next().ok_or_else(header_error)?;
    if matches.next().is_some() {
        return Err(header_error());
    }
    Ok((label, member))
}

fn header_values(headers: &HeaderMap, name: &str, single: bool) -> petrel_spaces::Result<String> {
    let mut values = headers.get_all(name).iter();
    let first = values
        .next()
        .ok_or_else(header_error)?
        .to_str()
        .map_err(|_| header_error())?;
    if first.len() > 8192 {
        return Err(header_error());
    }
    let mut out = first.trim().to_owned();
    for value in values {
        let field = value.to_str().map_err(|_| header_error())?;
        if single || out.len() + field.len() + 2 > 8192 {
            return Err(header_error());
        }
        out.push_str(", ");
        out.push_str(field.trim());
    }
    Ok(out)
}

/// Older readers choose the RFC 9421 dictionary label and may supply alg/keyid
/// and extension parameters. All parameters remain covered in the signature base.
pub(super) fn presentation_audience(
    headers: &HeaderMap,
    cnf: &str,
    now: u64,
) -> petrel_spaces::Result<String> {
    let auth = header_values(headers, "authorization", true)?;
    let audience = header_values(headers, "atproto-space-audience", true)?;
    Did::parse(&audience).map_err(|_| header_error())?;
    let inputs = parse_dictionary(
        &header_values(headers, "signature-input", false)?,
        DuplicatePolicy::OverwriteLast,
    )?;
    let signatures = parse_dictionary(
        &header_values(headers, "signature", false)?,
        DuplicatePolicy::OverwriteLast,
    )?;
    let (label, input) = tagged(&inputs, petrel_spaces::SPACE_SIGNATURE_TAG)?;
    let SfMember::InnerList(covered, _) = input else {
        return Err(header_error());
    };
    if covered.len() != 2
        || !covered
            .iter()
            .zip(["authorization", "atproto-space-audience"])
            .all(|(item, name)| {
                item.params.is_empty() && item.bare.as_string_strict() == Some(name)
            })
    {
        return Err(header_error());
    }
    if input
        .param("alg")
        .is_some_and(|v| v.as_string_strict() != Some("ecdsa-p256-sha256"))
        || input
            .param("keyid")
            .is_some_and(|v| v.as_string_strict() != Some(cnf))
        || input.param("nonce").is_some_and(|v| {
            !v.as_string_strict()
                .is_some_and(|n| !n.is_empty() && n.len() <= 512)
        })
    {
        return Err(header_error());
    }
    for (key, oldest, newest) in [
        ("created", now.saturating_sub(300), now.saturating_add(30)),
        ("expires", now.saturating_sub(30), u64::MAX),
    ] {
        if let Some(value) = input.param(key) {
            let stamp = value
                .as_int()
                .and_then(|v| u64::try_from(v).ok())
                .ok_or_else(header_error)?;
            if !(oldest..=newest).contains(&stamp) {
                return Err(header_error());
            }
        }
    }
    let sig_item = signatures
        .get(label)
        .and_then(SfMember::as_item)
        .ok_or_else(header_error)?;
    if !sig_item.params.is_empty() {
        return Err(header_error());
    }
    let sig = sig_item.bare.as_bytes().ok_or_else(header_error)?;
    let base = format!("\"authorization\": {auth}\n\"atproto-space-audience\": {audience}\n\"@signature-params\": {}",input.format());
    let key = PublicKey::from_did_key(cnf).map_err(|_| header_error())?;
    if !key.is_valid_signature(
        sig,
        base.as_bytes(),
        ATProtoSignatureVerificationOptions::JWT,
    ) {
        return Err(SpaceError::InvalidSignature);
    }
    Ok(audience)
}

pub(super) fn parse_accept_signature(
    raw: &str,
    profile: MacProfile,
) -> petrel_spaces::Result<(String, String)> {
    let dict = parse_dictionary(raw, DuplicatePolicy::Reject)?;
    let (label, member) = tagged(&dict, profile.as_str())?;
    let request = petrel_spaces::parse_accept_signature(&format!("mac={}", member.format()))?;
    Ok((label.to_owned(), request.keyid))
}

pub(super) struct LabeledMac(MacProfile, String, SpaceMacHeaders);

impl LabeledMac {
    pub(super) fn apply_to(&self, headers: &mut HeaderMap) -> petrel_spaces::Result<()> {
        let rename = |field: &str| -> petrel_spaces::Result<HeaderValue> {
            let (_, value) = field.split_once('=').ok_or_else(header_error)?;
            HeaderValue::from_str(&format!("{}={value}", self.1)).map_err(|_| header_error())
        };
        headers.insert(
            self.0.response_header(),
            HeaderValue::from_str(&self.2.covered_signature).map_err(|_| header_error())?,
        );
        headers.insert("signature-input", rename(&self.2.signature_input)?);
        headers.insert("signature", rename(&self.2.signature)?);
        Ok(())
    }
}

pub(super) fn sign_commit_mac(
    secret: &[u8; 32],
    key: &str,
    label: &str,
    space: &str,
    repo: &str,
    rev: &str,
    data: &[u8; 32],
) -> petrel_spaces::Result<LabeledMac> {
    let headers = petrel_spaces::sign_commit_mac(
        secret,
        &petrel_spaces::parse_space_ref(space)?,
        &Did::parse(repo).map_err(|e| SpaceError::InvalidDid(e.to_string()))?,
        &Tid::parse(rev).map_err(|e| SpaceError::InvalidTid(e.to_string()))?,
        data,
        key,
    )?;
    Ok(LabeledMac(MacProfile::Commit, label.to_owned(), headers))
}

pub(super) fn sign_record_mac(
    secret: &[u8; 32],
    key: &str,
    label: &str,
    uri: &AtUri,
    cid: &str,
) -> petrel_spaces::Result<LabeledMac> {
    let headers = petrel_spaces::sign_record_mac(
        secret,
        uri,
        &Cid::parse(cid).map_err(|e| SpaceError::InvalidCid(e.to_string()))?,
        key,
    )?;
    Ok(LabeledMac(MacProfile::Record, label.to_owned(), headers))
}

// The v1 inventory hashes a length-delimited tuple and the binary repository digest.
pub fn add_inventory_entry(
    state: &mut [u8; 2048],
    did: &str,
    rev: &str,
    space_rev: &str,
    data: &[u8; 32],
) -> Result<(), std::num::TryFromIntError> {
    let mut h = petrel_crypto::blake3::Hasher::new();
    h.update(b"atproto-space-writer-inventory-v1");
    for field in [did, rev, space_rev] {
        h.update(&u16::try_from(field.len())?.to_be_bytes());
        h.update(field.as_bytes());
    }
    h.update(data);
    let mut mask = [0u8; 2048];
    h.finalize_xof().fill(&mut mask);
    for (lane, delta) in state.chunks_exact_mut(2).zip(mask.chunks_exact(2)) {
        let v = u16::from_le_bytes([lane[0], lane[1]])
            .wrapping_add(u16::from_le_bytes([delta[0], delta[1]]));
        lane.copy_from_slice(&v.to_le_bytes());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_peer_selected_label_for_a_signed_presentation() {
        // The public minimal_profile interoperability vector, using a peer-selected label.
        let key = "did:key:zDnaerxEGHGe8yDDxEVcNvNRKyyPotnMrBb5saawSY12RkkpS";
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Atproto-Space-Credential eyJhbGciOiJFUzI1NiJ9.eyJ2ZWN0b3IiOiJmcmVzaG5lc3MifQ.c2lnbmF0dXJl"));
        headers.insert(
            "atproto-space-audience",
            HeaderValue::from_static("did:web:space-host.example.com"),
        );
        headers.insert("signature-input", HeaderValue::from_static("client=(\"authorization\" \"atproto-space-audience\");tag=\"atproto-space-credential\""));
        headers.insert("signature", HeaderValue::from_static("client=:Ph85TfUdhpX4yjs0BDcrtFxENd/3kGG9nEpjUNjCyOA52+n22WQ60L5DHE0k+IIZst21DgnkCdX+XbUu2WVCRQ==:"));
        assert_eq!(
            presentation_audience(&headers, key, 1_800_000_000).unwrap(),
            "did:web:space-host.example.com"
        );
        headers.append(
            "atproto-space-audience",
            HeaderValue::from_static("did:web:other.example.com"),
        );
        assert!(presentation_audience(&headers, key, 1_800_000_000).is_err());
    }
}
