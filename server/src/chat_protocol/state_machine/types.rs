#![allow(unused_imports)]
use super::*;

pub(crate) fn closed_coordinate(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
) -> Result<PublicGroupSnapshotCoordinate, StateMachineError> {
    let conversation_id = closed_uuid(object, "conversationId")?;
    let generation = closed_integer(object, "generation")?;
    let state_version = closed_integer(object, "stateVersion")?;
    let group_id = match object.get("groupId") {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let epoch = closed_integer(object, "epoch")?;
    let group_context_hash = match object.get("groupContextHash") {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let confirmation_tag = match object.get("confirmationTag") {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let lifecycle = match closed_text(object, "lifecycle")? {
        "active" => PublicGroupSnapshotLifecycle::Active,
        "superseded" => PublicGroupSnapshotLifecycle::Superseded,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    Ok(PublicGroupSnapshotCoordinate::new(
        conversation_id,
        generation,
        state_version,
        group_id,
        epoch,
        group_context_hash,
        confirmation_tag,
        lifecycle,
    ))
}

pub(in crate::chat_protocol::state_machine) fn closed_coordinate_from_field(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
    name: &str,
) -> Result<PublicGroupSnapshotCoordinate, StateMachineError> {
    let Some(CanonicalValueRef::Object(coordinates)) = object.get(name) else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    closed_coordinate(&coordinates)
}

pub(in crate::chat_protocol::state_machine) fn parse_conversation_kind(
    value: &str,
) -> Result<ConversationKind, StateMachineError> {
    match value {
        "direct" => Ok(ConversationKind::Direct),
        "group" => Ok(ConversationKind::Group),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

pub(in crate::chat_protocol::state_machine) fn sealed_object_digest(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
) -> [u8; 32] {
    Sha256::digest(object.canonical_dag_cbor()).into()
}

pub(crate) fn commit_aad_bytes(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
) -> Vec<u8> {
    let encoded = object.canonical_dag_cbor();
    let mut aad = Vec::with_capacity(COMMIT_AAD_DOMAIN.len() + encoded.len());
    aad.extend_from_slice(COMMIT_AAD_DOMAIN);
    aad.extend_from_slice(&encoded);
    aad
}

pub(in crate::chat_protocol::state_machine) fn commit_aad_sha256(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
) -> [u8; 32] {
    Sha256::digest(commit_aad_bytes(object)).into()
}

pub(in crate::chat_protocol::state_machine) fn checked_artifact_sha256(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
) -> Result<[u8; 32], StateMachineError> {
    let bytes = match object.get("bytes") {
        Some(CanonicalValueRef::Bytes(value)) => value,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let declared: [u8; 32] = match object.get("sha256") {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if declared != actual {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(actual)
}

pub(crate) fn checked_artifact_bytes(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
) -> Result<Vec<u8>, StateMachineError> {
    let bytes = match object.get("bytes") {
        Some(CanonicalValueRef::Bytes(value)) => value,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let declared = closed_fixed_bytes::<32>(object, "sha256")?;
    if <[u8; 32]>::from(Sha256::digest(bytes)) != declared {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(bytes.to_vec())
}

pub(in crate::chat_protocol::state_machine) fn checked_metadata_snapshot_digest(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
) -> Result<[u8; 32], StateMachineError> {
    let ciphertext = match object.get("ciphertext") {
        Some(CanonicalValueRef::Bytes(value)) => value,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let declared_sha256: [u8; 32] = match object.get("ciphertextSha256") {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    if closed_integer(object, "ciphertextSize")? != ciphertext.len() as u64
        || <[u8; 32]>::from(Sha256::digest(ciphertext)) != declared_sha256
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(sealed_object_digest(object))
}

pub(in crate::chat_protocol::state_machine) fn parse_metadata_snapshot(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
) -> Result<MetadataSnapshotBinding, StateMachineError> {
    let ciphertext = match object.get("ciphertext") {
        Some(CanonicalValueRef::Bytes(value)) => value.to_vec(),
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let ciphertext_sha256 = closed_fixed_bytes::<32>(object, "ciphertextSha256")?;
    if closed_integer(object, "ciphertextSize")? != ciphertext.len() as u64
        || <[u8; 32]>::from(Sha256::digest(&ciphertext)) != ciphertext_sha256
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let nonce = closed_fixed_bytes::<12>(object, "nonce")?;
    let origin_transition_id = closed_uuid(object, "originTransitionId")?;
    let metadata_version = closed_integer(object, "metadataVersion")?;
    if metadata_version == 0 || metadata_version > MAX_PROTOCOL_INTEGER {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let Some(CanonicalValueRef::Object(coordinate)) = object.get("coordinate") else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    let coordinate = MetadataCryptoCoordinate {
        // The metadata crypto context binds conversationId as the compact 16-byte
        // form (lexicon `#identifierBytes`: "Exact 16 UUID bytes corresponding to
        // the canonical outer UUIDv4 text"), NOT the canonical text `#operationId`
        // that transport coordinates (`#conversationCoordinates`) carry — so it
        // projects to `CanonicalValueRef::Bytes`, not `Uuid`, and must be read as
        // exact-16 bytes (reading it with `closed_uuid` never matched and left
        // parse_metadata_snapshot unable to admit any metadata snapshot). The
        // required correspondence — these 16 bytes ARE the outer conversation's
        // UUIDv4 — is enforced bytes-to-bytes downstream by
        // `metadata_coordinate_matches` (see `metadata.coordinate.conversation_id
        // == *coordinate.conversation_id()`), so no re-check is needed here.
        conversation_id: closed_fixed_bytes::<16>(&coordinate, "conversationId")?,
        generation: closed_integer(&coordinate, "generation")?,
        group_id: closed_fixed_bytes(&coordinate, "groupId")?,
        epoch: closed_integer(&coordinate, "epoch")?,
        group_context_hash: closed_fixed_bytes(&coordinate, "groupContextHash")?,
        confirmation_tag: closed_fixed_bytes(&coordinate, "confirmationTag")?,
    };
    let Some(CanonicalValueRef::Object(proof)) = object.get("authorProof") else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    if closed_text(&proof, "roleAtOrigin")? != "admin"
        || closed_text(&proof, "deviceStatusAtOrigin")? != "active"
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let signature_public_key = closed_fixed_bytes::<32>(&proof, "signaturePublicKey")?;
    let author_key = match proof.get("authorKeyId") {
        Some(CanonicalValueRef::Thumbprint(value)) => value,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    if ed25519_key_id(&signature_public_key)
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
        != *author_key
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let author_key_id: [u8; 32] = URL_SAFE_NO_PAD
        .decode(author_key.as_str())
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
        .try_into()
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
    let author_proof = MetadataAuthorProofBinding {
        author: closed_device(&proof, "authorDid", "authorDeviceId")?,
        author_key_id,
        signature_public_key,
        auth_generation_at_origin: closed_integer(&proof, "authGenerationAtOrigin")?,
        origin_transition_id: closed_uuid(&proof, "originTransitionId")?,
        origin_seq: closed_integer(&proof, "originSeq")?,
    };
    if author_proof.auth_generation_at_origin == 0
        || author_proof.auth_generation_at_origin > MAX_PROTOCOL_INTEGER
        || author_proof.origin_seq == 0
        || author_proof.origin_seq > MAX_PROTOCOL_INTEGER
        || author_proof.origin_transition_id != origin_transition_id
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let avatar_binding = match object.get("avatarBinding") {
        None => None,
        Some(CanonicalValueRef::Object(value)) => {
            if closed_text(&value, "purpose")? != "metadata" {
                return Err(StateMachineError::InvalidHydrationAuthority);
            }
            let canonical_descriptor = value.canonical_dag_cbor();
            let digest = Sha256::digest(&canonical_descriptor).into();
            Some(MetadataAvatarDescriptorBinding {
                blob_id: closed_uuid(&value, "blobId")?,
                ciphertext_sha256: closed_fixed_bytes::<32>(&value, "ciphertextSha256")?,
                ciphertext_size: closed_integer(&value, "ciphertextSize")?,
                canonical_descriptor,
                digest,
            })
        }
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let canonical_snapshot = object.canonical_dag_cbor();
    let digest = Sha256::digest(&canonical_snapshot).into();
    Ok(MetadataSnapshotBinding {
        coordinate,
        origin_transition_id,
        metadata_version,
        nonce,
        ciphertext,
        ciphertext_sha256,
        avatar_binding,
        author_proof,
        canonical_snapshot,
        digest,
    })
}

pub(in crate::chat_protocol::state_machine) fn metadata_coordinate_matches(
    metadata: &MetadataSnapshotBinding,
    coordinate: &PublicGroupSnapshotCoordinate,
) -> bool {
    metadata.coordinate.conversation_id == *coordinate.conversation_id()
        && metadata.coordinate.generation == coordinate.generation()
        && metadata.coordinate.group_id == *coordinate.group_id()
        && metadata.coordinate.epoch == coordinate.epoch()
        && metadata.coordinate.group_context_hash == *coordinate.group_context_hash()
        && metadata.coordinate.confirmation_tag == *coordinate.confirmation_tag()
}

pub(in crate::chat_protocol::state_machine) fn transition_binding_is_route_bound(
    binding: &TransitionBodyBinding,
    conversation_id: &[u8; 16],
) -> bool {
    let coordinate_matches = |coordinate: &PublicGroupSnapshotCoordinate| {
        coordinate.conversation_id() == conversation_id
    };
    match binding {
        TransitionBodyBinding::DirectRequestPublication { prior, next, .. } => {
            prior.as_ref().is_none_or(coordinate_matches) && coordinate_matches(next)
        }
        TransitionBodyBinding::DirectRequestAcceptance { prior, next, .. } => {
            coordinate_matches(prior) && coordinate_matches(next)
        }
        TransitionBodyBinding::Creation { next, .. } => coordinate_matches(next),
        TransitionBodyBinding::Commit { prior, next, .. }
        | TransitionBodyBinding::Policy { prior, next, .. }
        | TransitionBodyBinding::Acceptance { prior, next, .. }
        | TransitionBodyBinding::Metadata { prior, next, .. }
        | TransitionBodyBinding::LeafRecoveryFulfillment { prior, next, .. }
        | TransitionBodyBinding::ZeroLeafLeave { prior, next }
        | TransitionBodyBinding::LeaveCommitFulfillment { prior, next, .. } => {
            coordinate_matches(prior) && coordinate_matches(next)
        }
        TransitionBodyBinding::ResetActivation {
            prior,
            retired,
            successor,
            ..
        } => {
            coordinate_matches(prior)
                && coordinate_matches(retired)
                && coordinate_matches(successor)
        }
        TransitionBodyBinding::ConversationClose { prior, retired, .. } => {
            coordinate_matches(prior) && coordinate_matches(retired)
        }
    }
}

pub(in crate::chat_protocol::state_machine) fn transition_body_prior(
    binding: &TransitionBodyBinding,
) -> Option<&PublicGroupSnapshotCoordinate> {
    match binding {
        TransitionBodyBinding::DirectRequestPublication { prior, .. } => prior.as_ref(),
        TransitionBodyBinding::DirectRequestAcceptance { prior, .. } => Some(prior),
        TransitionBodyBinding::Creation { .. } => None,
        TransitionBodyBinding::Commit { prior, .. }
        | TransitionBodyBinding::Policy { prior, .. }
        | TransitionBodyBinding::Acceptance { prior, .. }
        | TransitionBodyBinding::Metadata { prior, .. }
        | TransitionBodyBinding::ResetActivation { prior, .. }
        | TransitionBodyBinding::LeafRecoveryFulfillment { prior, .. }
        | TransitionBodyBinding::ConversationClose { prior, .. }
        | TransitionBodyBinding::ZeroLeafLeave { prior, .. }
        | TransitionBodyBinding::LeaveCommitFulfillment { prior, .. } => Some(prior),
    }
}

pub(in crate::chat_protocol::state_machine) fn validate_special_server_fields(
    entry: &VerifiedControlEntry,
    binding: &TransitionBodyBinding,
) -> Result<(), StateMachineError> {
    match binding {
        TransitionBodyBinding::ConversationClose { kind, retired, .. } => {
            let fields = entry.server_fields();
            let Some(CanonicalValueRef::Object(tombstone)) = fields.get("tombstone") else {
                return Err(StateMachineError::InvalidHydrationAuthority);
            };
            let closed_at = match tombstone.get("closedAt") {
                Some(CanonicalValueRef::Timestamp(value)) => value,
                _ => return Err(StateMachineError::InvalidHydrationAuthority),
            };
            let closed_by = closed_device(&tombstone, "closedByDid", "closedByDeviceId")?;
            let signed_retired = match tombstone.get("retired") {
                Some(CanonicalValueRef::Object(value)) => closed_coordinate(&value)?,
                _ => return Err(StateMachineError::InvalidHydrationAuthority),
            };
            let signed_actor = DeviceIdentity::new(
                PrincipalId::new(entry.mutation().actor_did().as_str().as_bytes().to_vec())?,
                *entry.mutation().actor_device_id().as_bytes(),
            )?;
            if closed_uuid(&tombstone, "conversationId")? != *entry.conversation_id().as_bytes()
                || parse_conversation_kind(closed_text(&tombstone, "conversationKind")?)? != *kind
                || signed_retired != *retired
                || closed_by != signed_actor
                || closed_integer(&tombstone, "terminalSeq")? != entry.seq()
                || closed_at.as_str() != entry.received_at().as_str()
            {
                return Err(StateMachineError::InvalidHydrationAuthority);
            }
        }
        TransitionBodyBinding::Acceptance { recovery, .. } => {
            if recovery.canonical_digest == [0; 32] {
                return Err(StateMachineError::InvalidHydrationAuthority);
            }
        }
        _ => {}
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine) fn parse_acceptance_recovery(
    server_fields: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
) -> Result<AcceptanceRecoveryBinding, StateMachineError> {
    let Some(CanonicalValueRef::Object(recovery)) = server_fields.get("recovery") else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    if closed_text(&recovery, "status")? != "open" {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let request_id = closed_uuid(&recovery, "recoveryRequestId")?;
    let conversation_id = closed_uuid(&recovery, "conversationId")?;
    let target = closed_device(&recovery, "requesterDid", "requesterDeviceId")?;
    let kind = match closed_text(&recovery, "recoveryKind")? {
        "add" => LeafRecoveryKind::Add,
        "replace" => LeafRecoveryKind::Replace,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let bound_coordinate = closed_coordinate_from_field(&recovery, "boundCoordinate")?;
    let requested_at = closed_timestamp(&recovery, "requestedAt")?;
    let expires_at = closed_timestamp(&recovery, "expiresAt")?;
    let Some(CanonicalValueRef::Object(reservation)) = recovery.get("reservation") else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    if closed_text(&reservation, "cipherSuite")? != "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"
        || closed_text(&reservation, "purpose")? != "leafRecovery"
        || closed_text(&reservation, "status")? != "active"
        || closed_uuid(&reservation, "recoveryRequestId")? != request_id
        || closed_uuid(&reservation, "conversationId")? != conversation_id
        || closed_device(&reservation, "requesterDid", "requesterDeviceId")? != target
        || closed_coordinate_from_field(&reservation, "boundCoordinate")? != bound_coordinate
        || closed_timestamp(&reservation, "expiresAt")? != expires_at
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let requester_key_id = closed_key_id(&reservation, "requesterKeyId")?;
    let requester_auth_generation = closed_integer(&reservation, "requesterAuthGeneration")?;
    let key_package_ref = closed_fixed_bytes::<32>(&reservation, "keyPackageRef")?;
    let Some(CanonicalValueRef::Object(package)) = reservation.get("keyPackage") else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    if closed_text(&package, "framing")? != "mlsMessage"
        || closed_text(&package, "contentType")? != "keyPackage"
        || closed_fixed_bytes::<32>(&package, "keyPackageRef")? != key_package_ref
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let key_package_wrapper = match package.get("bytes") {
        Some(CanonicalValueRef::Bytes(bytes)) if !bytes.is_empty() => bytes.to_vec(),
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let key_package_wrapper_sha256 = closed_fixed_bytes::<32>(&package, "sha256")?;
    if <[u8; 32]>::from(Sha256::digest(&key_package_wrapper)) != key_package_wrapper_sha256 {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(AcceptanceRecoveryBinding {
        request_id,
        conversation_id,
        target,
        kind,
        bound_coordinate,
        requester_key_id,
        requester_auth_generation,
        key_package_ref,
        key_package_wrapper,
        key_package_wrapper_sha256,
        requested_at,
        expires_at,
        canonical_digest: sealed_object_digest(&recovery),
    })
}

pub(in crate::chat_protocol::state_machine) fn closed_fixed_bytes<const N: usize>(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
    name: &str,
) -> Result<[u8; N], StateMachineError> {
    match object.get(name) {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

pub(in crate::chat_protocol::state_machine) fn closed_device(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
    did_field: &str,
    device_field: &str,
) -> Result<DeviceIdentity, StateMachineError> {
    let principal = closed_principal(object, did_field)?;
    let device_id = closed_uuid(object, device_field)?;
    DeviceIdentity::new(principal, device_id)
}

pub(in crate::chat_protocol::state_machine) fn parse_participant_role(
    value: &str,
) -> Result<ParticipantRole, StateMachineError> {
    match value {
        "admin" => Ok(ParticipantRole::Admin),
        "member" => Ok(ParticipantRole::Member),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

pub(in crate::chat_protocol::state_machine) fn parse_participant_status(
    value: &str,
) -> Result<ParticipantStatus, StateMachineError> {
    match value {
        "pending" => Ok(ParticipantStatus::Pending),
        "active" => Ok(ParticipantStatus::Active),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

pub(in crate::chat_protocol::state_machine) fn parse_invitation(
    value: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
) -> Result<InvitationBinding, StateMachineError> {
    Ok(InvitationBinding {
        transition_id: closed_uuid(value, "invitationTransitionId")?,
        inviter: closed_device(value, "invitedByDid", "invitedByDeviceId")?,
    })
}

pub(in crate::chat_protocol::state_machine) fn parse_roster_manifest(
    manifest: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
) -> Result<RosterManifestBinding, StateMachineError> {
    let participants = match manifest.get("participants") {
        Some(CanonicalValueRef::Array(values)) => values,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let mut parsed = Vec::with_capacity(participants.len());
    for index in 0..participants.len() {
        let Some(CanonicalValueRef::Object(participant)) = participants.get(index) else {
            return Err(StateMachineError::InvalidHydrationAuthority);
        };
        let invitation = match participant.get("invitationProvenance") {
            None => None,
            Some(CanonicalValueRef::Object(value)) => Some(parse_invitation(&value)?),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        parsed.push(RosterParticipantBinding {
            principal: closed_principal(&participant, "userDid")?,
            status: parse_participant_status(closed_text(&participant, "status")?)?,
            role: parse_participant_role(closed_text(&participant, "role")?)?,
            invitation,
        });
    }
    if parsed.is_empty()
        || parsed
            .windows(2)
            .any(|pair| pair[0].principal >= pair[1].principal)
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let Some(CanonicalValueRef::Object(actor_leaf)) = manifest.get("actorLeaf") else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    if closed_text(&actor_leaf, "leafOrigin")? != "genesis"
        || actor_leaf.get("joinKeyPackageRef").is_some()
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(RosterManifestBinding {
        participants: parsed,
        actor_leaf: closed_device(&actor_leaf, "userDid", "deviceId")?,
    })
}

pub(in crate::chat_protocol::state_machine) fn parse_participant_changes(
    value: CanonicalValueRef<'_>,
) -> Result<Vec<ManifestParticipantChange>, StateMachineError> {
    let CanonicalValueRef::Array(values) = value else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    let mut changes = Vec::with_capacity(values.len());
    for index in 0..values.len() {
        let Some(CanonicalValueRef::Object(change)) = values.get(index) else {
            return Err(StateMachineError::InvalidHydrationAuthority);
        };
        let principal = closed_principal(&change, "userDid")?;
        changes.push(match closed_text(&change, "$type")? {
            "blue.catbird.chat.defs#addParticipant" => ManifestParticipantChange::Add(principal),
            "blue.catbird.chat.defs#removeParticipant" => {
                ManifestParticipantChange::Remove(principal)
            }
            "blue.catbird.chat.defs#changeParticipantRole" => {
                ManifestParticipantChange::ChangeRole(
                    principal,
                    parse_participant_role(closed_text(&change, "role")?)?,
                )
            }
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        });
    }
    if changes.is_empty()
        || changes
            .windows(2)
            .any(|pair| manifest_change_principal(&pair[0]) >= manifest_change_principal(&pair[1]))
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(changes)
}

pub(in crate::chat_protocol::state_machine) fn manifest_change_principal(
    change: &ManifestParticipantChange,
) -> &PrincipalId {
    match change {
        ManifestParticipantChange::Add(value)
        | ManifestParticipantChange::Remove(value)
        | ManifestParticipantChange::ChangeRole(value, _) => value,
    }
}

pub(in crate::chat_protocol::state_machine) fn parse_transition_manifest(
    manifest: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
) -> Result<TransitionManifestBinding, StateMachineError> {
    let participant_values = match manifest.get("participantChanges") {
        Some(CanonicalValueRef::Array(values)) => values,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let mut participant_changes = Vec::with_capacity(participant_values.len());
    for index in 0..participant_values.len() {
        let Some(CanonicalValueRef::Object(change)) = participant_values.get(index) else {
            return Err(StateMachineError::InvalidHydrationAuthority);
        };
        let principal = closed_principal(&change, "userDid")?;
        participant_changes.push(match closed_text(&change, "$type")? {
            "blue.catbird.chat.defs#addParticipant" => ManifestParticipantChange::Add(principal),
            "blue.catbird.chat.defs#removeParticipant" => {
                ManifestParticipantChange::Remove(principal)
            }
            "blue.catbird.chat.defs#changeParticipantRole" => {
                ManifestParticipantChange::ChangeRole(
                    principal,
                    parse_participant_role(closed_text(&change, "role")?)?,
                )
            }
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        });
    }

    let leaf_values = match manifest.get("leafChanges") {
        Some(CanonicalValueRef::Array(values)) => values,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let mut leaf_changes = Vec::with_capacity(leaf_values.len());
    for index in 0..leaf_values.len() {
        let Some(CanonicalValueRef::Object(change)) = leaf_values.get(index) else {
            return Err(StateMachineError::InvalidHydrationAuthority);
        };
        let device = closed_device(&change, "userDid", "deviceId")?;
        leaf_changes.push(match closed_text(&change, "$type")? {
            "blue.catbird.chat.defs#addLeafByRecovery" => ManifestLeafChange::Add {
                device,
                recovery_request_id: closed_uuid(&change, "recoveryRequestId")?,
                key_package_ref: closed_fixed_bytes(&change, "keyPackageRef")?,
            },
            "blue.catbird.chat.defs#removeLeaf" => ManifestLeafChange::Remove(device),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        });
    }

    let leaf_recovery_request_id = match manifest.get("leafRecoveryRequestId") {
        None => None,
        Some(CanonicalValueRef::Uuid(value)) => Some(*value.as_bytes()),
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let welcome = match manifest.get("welcomeBundle") {
        None => None,
        Some(CanonicalValueRef::Object(bundle)) => {
            let opaque_welcome = match bundle.get("opaqueWelcome") {
                Some(CanonicalValueRef::Bytes(value)) => value.to_vec(),
                _ => return Err(StateMachineError::InvalidHydrationAuthority),
            };
            let sha256 = closed_fixed_bytes(&bundle, "sha256")?;
            if <[u8; 32]>::from(Sha256::digest(&opaque_welcome)) != sha256 {
                return Err(StateMachineError::InvalidHydrationAuthority);
            }
            let deliveries = match bundle.get("deliveries") {
                Some(CanonicalValueRef::Array(values)) if values.len() == 1 => values,
                _ => return Err(StateMachineError::InvalidHydrationAuthority),
            };
            let Some(CanonicalValueRef::Object(delivery)) = deliveries.get(0) else {
                return Err(StateMachineError::InvalidHydrationAuthority);
            };
            let Some(CanonicalValueRef::Object(provenance)) = delivery.get("provenance") else {
                return Err(StateMachineError::InvalidHydrationAuthority);
            };
            Some(ManifestWelcomeBinding {
                welcome_id: closed_uuid(&bundle, "welcomeId")?,
                opaque_welcome,
                sha256,
                recipient: closed_device(&delivery, "recipientDid", "recipientDeviceId")?,
                recovery_request_id: closed_uuid(&provenance, "recoveryRequestId")?,
                key_package_ref: closed_fixed_bytes(&provenance, "keyPackageRef")?,
            })
        }
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    Ok(TransitionManifestBinding {
        participant_changes,
        leaf_changes,
        leaf_recovery_request_id,
        welcome,
    })
}

pub(in crate::chat_protocol::state_machine) fn closed_coordinate_conversation_id(
    body: crate::chat_protocol::transcript::ClosedObjectRef<'_>,
    coordinate_field: &str,
) -> Result<[u8; 16], StateMachineError> {
    let Some(CanonicalValueRef::Object(coordinates)) = body.get(coordinate_field) else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    closed_uuid(&coordinates, "conversationId")
}

pub(in crate::chat_protocol::state_machine) fn durable_signed_request_row_digest(
    kind: RequestEntryKind,
    envelope: &DurableSignedRequestEnvelope,
    request_id: &[u8; 16],
    mutation: &VerifiedSignedMutation,
) -> Result<[u8; 32], StateMachineError> {
    let signed_request = mutation
        .accepted_wrapper_bytes()
        .filter(|bytes| !bytes.is_empty())
        .ok_or(StateMachineError::InvalidHydrationAuthority)?;
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-DURABLE-SIGNED-ROW\0");
    digest.update([kind as u8]);
    digest.update(envelope.conversation_id);
    digest.update(request_id);
    digest.update(envelope.received_at.unix_millis().to_be_bytes());
    digest.update(mutation.request_digest());
    digest.update(mutation.signature());
    digest.update((signed_request.len() as u64).to_be_bytes());
    digest.update(signed_request);
    Ok(digest.finalize().into())
}

pub(in crate::chat_protocol::state_machine) fn device_revocation_row_digest(
    evidence: &DeviceRevocationEvidence,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-DURABLE-DEVICE-REVOCATION\0");
    digest.update(evidence.revocation_id);
    digest.update((evidence.actor.principal().as_bytes().len() as u64).to_be_bytes());
    digest.update(evidence.actor.principal().as_bytes());
    digest.update(evidence.actor.device_id());
    digest.update(evidence.target.device_id());
    digest.update(evidence.actor_key_id);
    digest.update(evidence.actor_auth_generation.to_be_bytes());
    digest.update(evidence.expected_target_auth_generation.to_be_bytes());
    digest.update(evidence.signed_at.unix_millis().to_be_bytes());
    digest.update(evidence.accepted_at.unix_millis().to_be_bytes());
    digest.update(evidence.request_digest);
    digest.update(evidence.signature);
    digest.update((evidence.signed_request_bytes.len() as u64).to_be_bytes());
    digest.update(&evidence.signed_request_bytes);
    digest.update((evidence.signing_transcript_bytes.len() as u64).to_be_bytes());
    digest.update(&evidence.signing_transcript_bytes);
    digest.finalize().into()
}

pub(in crate::chat_protocol::state_machine) fn validate_device_revocation_evidence(
    evidence: &DeviceRevocationEvidence,
) -> bool {
    is_uuid_v4(&evidence.revocation_id)
        && evidence.actor.principal() == evidence.target.principal()
        // Self-revoke (actor device == target device) is a first-class spec
        // operation (CHAT_PROTOCOL.md L56: "Completed first-enroll, self-revoke,
        // and rebind operations have one narrow response-loss path"), and the DB
        // schema accepts it (device_revocations positive fixture, and
        // assert_device_revocation_mapping's actor.revoked_at >= accepted_at
        // tolerance). Same-DID is already required above; both self-revoke and
        // sibling-revoke are permitted. Do NOT reintroduce an actor != target
        // requirement — it makes a single-device user unable to revoke their only
        // device and contradicts the DB authority.
        && evidence.actor_key_id != [0; 32]
        && evidence.actor_auth_generation > 0
        && evidence.actor_auth_generation <= MAX_PROTOCOL_INTEGER
        && evidence.expected_target_auth_generation > 0
        && evidence.expected_target_auth_generation <= MAX_PROTOCOL_INTEGER
        && evidence
            .accepted_at
            .checked_add_millis(MAX_FIRST_EXECUTION_FUTURE_SKEW_MILLIS)
            .is_ok_and(|deadline| evidence.signed_at <= deadline)
        && evidence.request_digest != [0; 32]
        && evidence.signature != [0; 64]
        && !evidence.signed_request_bytes.is_empty()
        && !evidence.signing_transcript_bytes.is_empty()
        && evidence.durable_row_digest == device_revocation_row_digest(evidence)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PersistedRegistrationStatus {
    Active,
    Revoked,
}

/// Canonically typed device/key registration row supplied by persistence.
/// The constructor accepts only values that already passed the shared exact
/// DID, UUID, and thumbprint grammars and independently checks its stored row
/// digest when authority is sealed.
#[cfg(test)]
pub(crate) struct PersistedRegistrationRow {
    pub(in crate::chat_protocol::state_machine) conversation_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) actor: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) key_id: [u8; 32],
    pub(in crate::chat_protocol::state_machine) registered_mls_signature_key: [u8; 32],
    pub(in crate::chat_protocol::state_machine) auth_generation: u64,
    pub(in crate::chat_protocol::state_machine) status: PersistedRegistrationStatus,
    pub(in crate::chat_protocol::state_machine) durable_row_digest: [u8; 32],
}

#[cfg(test)]
impl PersistedRegistrationRow {
    pub(crate) fn new(
        conversation_id: [u8; 16],
        actor_did: BareDid,
        device_id: CanonicalUuidV4,
        key_id: KeyThumbprint,
        registered_mls_signature_key: [u8; 32],
        auth_generation: u64,
        status: PersistedRegistrationStatus,
        durable_row_digest: [u8; 32],
    ) -> Result<Self, StateMachineError> {
        let key_id: [u8; 32] = URL_SAFE_NO_PAD
            .decode(key_id.as_str())
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        if !is_uuid_v4(&conversation_id)
            || auth_generation == 0
            || auth_generation > MAX_PROTOCOL_INTEGER
            || registered_mls_signature_key == [0; 32]
            || durable_row_digest == [0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            conversation_id,
            actor: DeviceIdentity::new(
                PrincipalId::new(actor_did.as_str().as_bytes().to_vec())?,
                *device_id.as_bytes(),
            )?,
            key_id,
            registered_mls_signature_key,
            auth_generation,
            status,
            durable_row_digest,
        })
    }

    /// Deterministic value persistence stores beside the canonical row.
    pub(crate) fn expected_digest(
        conversation_id: [u8; 16],
        actor: &DeviceIdentity,
        key_id: [u8; 32],
        registered_mls_signature_key: [u8; 32],
        auth_generation: u64,
        status: PersistedRegistrationStatus,
    ) -> [u8; 32] {
        registration_row_digest_fields(
            &conversation_id,
            actor,
            &key_id,
            &registered_mls_signature_key,
            auth_generation,
            status,
        )
    }
}

#[cfg(test)]
pub(in crate::chat_protocol::state_machine) fn registration_row_digest(
    row: &PersistedRegistrationRow,
) -> [u8; 32] {
    registration_row_digest_fields(
        &row.conversation_id,
        &row.actor,
        &row.key_id,
        &row.registered_mls_signature_key,
        row.auth_generation,
        row.status,
    )
}

#[cfg(test)]
pub(in crate::chat_protocol::state_machine) fn registration_row_digest_fields(
    conversation_id: &[u8; 16],
    actor: &DeviceIdentity,
    key_id: &[u8; 32],
    registered_mls_signature_key: &[u8; 32],
    auth_generation: u64,
    status: PersistedRegistrationStatus,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-DURABLE-REGISTRATION-ROW\0");
    digest.update(conversation_id);
    digest.update((actor.principal().as_bytes().len() as u64).to_be_bytes());
    digest.update(actor.principal().as_bytes());
    digest.update(actor.device_id());
    digest.update(key_id);
    digest.update(registered_mls_signature_key);
    digest.update(auth_generation.to_be_bytes());
    digest.update([match status {
        PersistedRegistrationStatus::Active => 1,
        PersistedRegistrationStatus::Revoked => 2,
    }]);
    digest.finalize().into()
}

impl LockedRegistrationProjection {
    #[cfg(test)]
    pub(crate) fn for_test(evidence: &RequestEvidence) -> Self {
        Self {
            conversation_id: evidence.conversation_id,
            actor: evidence.actor.clone(),
            key_id: evidence.key_id,
            registered_mls_signature_key: [0x71; 32],
            auth_generation: evidence.auth_generation,
            status: PersistedRegistrationStatus::Active,
            trusted_read_at: evidence.received_at,
            durable_row_digest: [0x7a; 32],
            transaction_id: String::new(),
            authority_scope_digest: [0x7b; 32],
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_status(
        evidence: &RequestEvidence,
        status: PersistedRegistrationStatus,
    ) -> Self {
        let mut projection = Self::for_test(evidence);
        projection.status = status;
        projection
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_key(evidence: &RequestEvidence, key_id: [u8; 32]) -> Self {
        let mut projection = Self::for_test(evidence);
        projection.key_id = key_id;
        projection
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_auth_generation(
        evidence: &RequestEvidence,
        auth_generation: u64,
    ) -> Self {
        let mut projection = Self::for_test(evidence);
        projection.auth_generation = auth_generation;
        projection
    }
}
