//! Request-only final GroupInfo verification. Generic genesis/recovery rules
//! remain unchanged. This proves public consistency, never application secrets.
use super::*;

#[derive(TlsDeserialize, TlsSize)]
struct ParentNode {
    _encryption_key: VLBytes,
    _parent_hash: VLBytes,
    _unmerged_leaves: Vec<u32>,
}

pub struct VerifiedRequestFinalGroupInfo {
    group_info: ValidatedGroupInfo,
    earliest_key_package_expiry: u64,
}
impl VerifiedRequestFinalGroupInfo {
    pub fn group_info(&self) -> &ValidatedGroupInfo {
        &self.group_info
    }
    pub fn earliest_key_package_expiry(&self) -> u64 {
        self.earliest_key_package_expiry
    }
}

/// Verify the actor-signed epoch-one full tree and compare it with the state
/// independently derived by processing the bootstrap Add. Lifetime is derived
/// from the actual final tree: a creator's replaced KeyPackage leaf is excluded.
pub fn verify_final_group_info(
    bytes: &[u8],
    policy: GroupInfoValidationPolicy<'_>,
    expected: &PublicGroupSnapshotBinding,
) -> Result<VerifiedRequestFinalGroupInfo, WireValidationError> {
    if policy.max_members < 2 || policy.max_members > 40 || policy.max_ratchet_tree_bytes == 0 {
        return Err(WireValidationError::InvalidLimit);
    }
    let message = preflight_exact_message(
        bytes,
        WireFormat::GroupInfo,
        policy.max_bytes,
        MAX_GROUP_INFO_WIRE_BYTES,
    )?;
    let MlsMessageBodyIn::GroupInfo(info) = message.extract() else {
        return Err(WireValidationError::Malformed);
    };
    let envelope = tls_deserialize_exact_no_panic::<WireGroupInfoEnvelope>(bytes)
        .map_err(|_| WireValidationError::Malformed)?;
    let canonical = envelope
        .tls_serialize_detached()
        .map_err(|_| WireValidationError::Malformed)?;
    let context = &envelope.group_info.context;
    if canonical != bytes {
        return Err(WireValidationError::NonCanonicalEncoding);
    }
    if envelope.version != MLS_1_0_WIRE_VALUE
        || context.protocol_version != MLS_1_0_WIRE_VALUE
        || context.ciphersuite != XWING_CIPHERSUITE as u16
        || context.epoch != 1
        || envelope.group_info.signer != 0
        || !context.extensions.is_empty()
        || envelope
            .group_info
            .extensions
            .iter()
            .map(|e| e.extension_type)
            .collect::<Vec<_>>()
            != [2, 4]
        || context.confirmed_transcript_hash.as_slice().len() != 32
    {
        return Err(WireValidationError::InvalidGroupInfo);
    }
    let group_context_hash: [u8; 32] = Sha256::digest(
        context
            .tls_serialize_detached()
            .map_err(|_| WireValidationError::Malformed)?,
    )
    .into();
    let confirmation_tag: [u8; 32] = envelope
        .group_info
        .confirmation_tag
        .as_slice()
        .try_into()
        .map_err(|_| WireValidationError::Malformed)?;
    if context.group_id.as_slice() != expected.group_id()
        || context.epoch != expected.epoch()
        || group_context_hash != *expected.group_context_hash()
        || confirmation_tag != *expected.confirmation_tag()
        || context.tree_hash.as_slice() != expected.tree_summary().tree_hash()
    {
        return Err(WireValidationError::InvalidGroupInfo);
    }
    let tree_bytes = envelope.group_info.extensions[0].extension_data.as_slice();
    if tree_bytes.len() > policy.max_ratchet_tree_bytes {
        return Err(WireValidationError::RatchetTreeTooLarge {
            actual: tree_bytes.len(),
            maximum: policy.max_ratchet_tree_bytes,
        });
    }
    let encoded = tls_deserialize_exact_no_panic::<VLBytes>(tree_bytes)
        .map_err(|_| WireValidationError::Malformed)?;
    let mut remaining = encoded.as_slice();
    let mut earliest = u64::MAX;
    let mut leaves = 0;
    let mut index = 0u32;
    while !remaining.is_empty() {
        if index >= 79 {
            return Err(WireValidationError::InvalidGroupInfo);
        }
        match u8::tls_deserialize(&mut remaining).map_err(|_| WireValidationError::Malformed)? {
            0 => (),
            1 => match u8::tls_deserialize(&mut remaining)
                .map_err(|_| WireValidationError::Malformed)?
            {
                1 if index % 2 == 0 => {
                    let leaf = WireLeafNode::tls_deserialize(&mut remaining)
                        .map_err(|_| WireValidationError::Malformed)?;
                    validate_clean_leaf_shape(&leaf)?;
                    match leaf.payload.source {
                        WireLeafNodeSource::KeyPackage(lifetime) => {
                            validate_clean_lifetime(lifetime, policy.now_unix_seconds)?;
                            earliest = earliest.min(lifetime.not_after);
                        }
                        WireLeafNodeSource::Commit(_) if index == 0 => (),
                        _ => return Err(WireValidationError::UnsupportedLeafSource),
                    }
                    leaves += 1;
                }
                2 if index % 2 == 1 => {
                    ParentNode::tls_deserialize(&mut remaining)
                        .map_err(|_| WireValidationError::Malformed)?;
                }
                _ => return Err(WireValidationError::Malformed),
            },
            _ => return Err(WireValidationError::Malformed),
        }
        index += 1;
    }
    if leaves < 2 || leaves > policy.max_members || earliest == u64::MAX {
        return Err(WireValidationError::InvalidGroupInfo);
    }
    let external = tls_deserialize_exact_no_panic::<ExternalPubExtension>(
        envelope.group_info.extensions[1].extension_data.as_slice(),
    )
    .map_err(|_| WireValidationError::Malformed)?;
    validate_xwing_public_key(external.external_pub().as_slice())?;
    let tree = info
        .extensions()
        .ratchet_tree()
        .ok_or(WireValidationError::MissingRatchetTree)?
        .ratchet_tree()
        .clone();
    let provider = openmls_libcrux_crypto::Provider::new()
        .map_err(|_| WireValidationError::ProviderInitialization)?;
    let key = SignaturePublicKey::from(policy.expected_signature_key)
        .into_signature_public_key_enriched(info.ciphersuite().signature_algorithm());
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        info.verify_no_out(provider.crypto(), &key)
    }))
    .map_err(|_| WireValidationError::WrongGroupInfoSigner)?
    .map_err(|_| WireValidationError::WrongGroupInfoSigner)?;
    let (group, _) = std::panic::catch_unwind(AssertUnwindSafe(|| {
        PublicGroup::from_external_at(
            provider.crypto(),
            provider.storage(),
            tree,
            info,
            ProposalStore::new(),
            openmls::prelude::UnixSeconds::new(policy.now_unix_seconds),
        )
    }))
    .map_err(|_| WireValidationError::InvalidGroupInfo)?
    .map_err(|_| WireValidationError::InvalidGroupInfo)?;
    let members = group.members().collect::<Vec<_>>();
    if members.len() != leaves {
        return Err(WireValidationError::InvalidGroupInfo);
    }
    let actor = members
        .iter()
        .find(|m| m.index.u32() == 0)
        .ok_or(WireValidationError::WrongGroupInfoSigner)?;
    if actor.signature_key != policy.expected_signature_key
        || actor.credential.serialized_content() != policy.expected_basic_credential
    {
        return Err(WireValidationError::WrongGroupInfoSigner);
    }
    let state = PublicGroupState::new(provider, group);
    let summary = super::super::snapshot::public_group_snapshot_tree_summary(&state)
        .map_err(|_| WireValidationError::InvalidGroupInfo)?;
    if &summary != expected.tree_summary() {
        return Err(WireValidationError::InvalidGroupInfo);
    }
    Ok(VerifiedRequestFinalGroupInfo {
        group_info: ValidatedGroupInfo {
            canonical_bytes: canonical,
            group_context_hash,
            confirmation_tag,
            public_state: state,
        },
        earliest_key_package_expiry: earliest,
    })
}
