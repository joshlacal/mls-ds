#![allow(unused_imports)]
use super::*;

/// Open a leaf-recovery request + its paired reservation and reserve the
/// requester's key package (Available -> Reserved), all bound to
/// `recovery.bound_coordinate()`. Shared by the acceptance edge (source
/// `acceptConversation`, kind `add`, bound to the successor) and the
/// leaf-recovery request edge (source `requestLeafRecovery`, `add`/`replace`,
/// bound to the current coordinate). The requester and recipient are the same
/// device — the transition/request actor (`ctx.actor`). Timestamps are DB-clock:
/// `created_at == requested_at == applied_at` and
/// `expires_at == LEAST(applied_at + 5 min, package.not_after)`, exactly what
/// `assert_recovery_fulfillment_mapping` cross-checks.
pub(in crate::chat_protocol::state_machine::executor) async fn write_recovery_open(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    recovery: &crate::chat_protocol::state_machine::RecoveryRequest,
    conversation_id: Uuid,
    applied_at: DateTime<Utc>,
) -> Result<(), ExecutorError> {
    let open = ctx
        .recovery_open
        .as_ref()
        .ok_or(ExecutorError::MissingContext("recovery open context"))?;
    let bound = recovery.bound_coordinate();
    let generation = checked_i64(bound.generation())?;
    let bound_state_version = checked_i64(bound.state_version())?;
    let bound_epoch = checked_i64(bound.epoch())?;
    let requested_at = applied_at;
    let expires_at = (applied_at + chrono::Duration::minutes(5)).min(open.package_not_after);
    let recovery_request_id = Uuid::from_bytes(*recovery.request_id());
    let key_package_ref = recovery.key_package_ref().to_vec();
    let recovery_kind = match recovery.kind() {
        LeafRecoveryKind::Add => RepoLeafRecoveryKind::Add,
        LeafRecoveryKind::Replace => RepoLeafRecoveryKind::Replace {
            replaced_leaf_period_id: open.replaced_leaf_period_id.ok_or(
                ExecutorError::MissingContext("replace request replaced leaf period id"),
            )?,
        },
    };
    let source = match recovery.source() {
        RecoverySource::Acceptance => LeafRecoverySource::AcceptConversation,
        RecoverySource::Request => LeafRecoverySource::RequestLeafRecovery,
    };
    transition::insert_leaf_recovery_request(
        transaction,
        &NewLeafRecoveryRequest {
            recovery_request_id,
            conversation_id,
            generation,
            requester_did: ctx.actor.user_did.clone(),
            requester_device_id: ctx.actor.device_id,
            requester_key_id: ctx.actor.key_id.clone(),
            requester_auth_generation: ctx.actor.auth_generation,
            recovery_kind,
            source,
            bound_state_version,
            bound_group_id: bound.group_id().to_vec(),
            bound_epoch,
            bound_group_context_hash: bound.group_context_hash().to_vec(),
            bound_confirmation_tag: bound.confirmation_tag().to_vec(),
            reservation_request_id: recovery_request_id,
            signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
            signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
            request_digest: ctx.entry().request_digest.clone(),
            signature: ctx.entry().signature.clone(),
            requested_at,
            expires_at,
        },
    )
    .await?;
    transition::insert_reservation(
        transaction,
        &NewReservation {
            recovery_request_id,
            key_package_ref: key_package_ref.clone(),
            conversation_id,
            generation,
            requester_did: ctx.actor.user_did.clone(),
            requester_device_id: ctx.actor.device_id,
            requester_key_id: ctx.actor.key_id.clone(),
            requester_auth_generation: ctx.actor.auth_generation,
            recipient_did: ctx.actor.user_did.clone(),
            recipient_device_id: ctx.actor.device_id,
            bound_state_version,
            bound_group_id: bound.group_id().to_vec(),
            bound_epoch,
            bound_group_context_hash: bound.group_context_hash().to_vec(),
            bound_confirmation_tag: bound.confirmation_tag().to_vec(),
            expires_at,
            created_at: requested_at,
        },
    )
    .await?;
    transition::cas_key_package_status(
        transaction,
        &key_package_ref,
        RepoPackageStatus::Available,
        &PackageSuccessor::Reserve,
    )
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn write_successor_leaf(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    hydration: &ConversationStateHydration,
    row: &LeafHydrationRow,
    leaf_period_id: Uuid,
    conversation_id: Uuid,
    generation: i64,
    transition_id: Uuid,
    state_version: i64,
    seq_i64: i64,
    applied_at: DateTime<Utc>,
) -> Result<(), ExecutorError> {
    let cols = ctx
        .opened_leaves
        .iter()
        .find(|cols| cols.device == row.device)
        .ok_or(ExecutorError::MissingContext("successor leaf columns"))?;
    let participant_period_id = participant_period_for(ctx, hydration, row.device.principal())?;
    transition::insert_leaf_period(
        transaction,
        &NewLeafPeriod {
            leaf_period_id,
            participant_period_id,
            conversation_id,
            generation,
            user_did: device_did(&row.device)?,
            device_id: device_uuid(&row.device),
            leaf_index: checked_i64(u64::from(row.leaf_index))?,
            basic_credential: row.basic_credential.clone(),
            leaf_signature_key: row.signature_key.clone(),
            leaf_key_id: cols.leaf_key_id.clone(),
            leaf_auth_generation: cols.leaf_auth_generation,
            origin: LeafOrigin::Genesis,
            joined_state_version: state_version,
            joined_transition_id: transition_id,
            joined_seq: seq_i64,
            created_at: applied_at,
        },
    )
    .await?;
    Ok(())
}

pub(in crate::chat_protocol::state_machine::executor) fn closing_leaf_period(
    ctx: &ExecutionContext,
    device: &DeviceIdentity,
) -> Result<Uuid, ExecutorError> {
    ctx.closing_leaf_periods
        .iter()
        .find(|(candidate, _)| candidate == device)
        .map(|(_, id)| *id)
        .ok_or(ExecutorError::MissingContext("closing leaf period id"))
}

pub(in crate::chat_protocol::state_machine::executor) fn repo_interval_close_kind(
    kind: CloseKind,
) -> IntervalCloseKind {
    match kind {
        CloseKind::DirectRequest => IntervalCloseKind::DirectRequest,
        CloseKind::Remove => IntervalCloseKind::Remove,
        CloseKind::Replace => IntervalCloseKind::Replace,
        CloseKind::Reset => IntervalCloseKind::Reset,
        CloseKind::Terminal => IntervalCloseKind::Terminal,
    }
}

pub(in crate::chat_protocol::state_machine::executor) fn direct_pair(
    participants: &[ParticipantHydrationRow],
) -> Result<(String, String), ExecutorError> {
    if participants.len() != 2 {
        return Err(ExecutorError::InconsistentPlan(
            "direct conversation is not a pair",
        ));
    }
    let mut dids = participants
        .iter()
        .map(|row| principal_did(&row.principal))
        .collect::<Result<Vec<_>, _>>()?;
    dids.sort();
    Ok((dids[0].clone(), dids[1].clone()))
}

pub(in crate::chat_protocol::state_machine::executor) fn build_append_entry(
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    transition_id: Uuid,
) -> AppendEntry {
    AppendEntry {
        conversation_id,
        entry_id: ctx.entry().entry_id,
        entry_kind: ctx.entry().entry_kind.clone(),
        accepted_payload_bytes: ctx.entry().accepted_payload_bytes.clone(),
        accepted_payload_sha256: ctx.entry().accepted_payload_sha256.clone(),
        signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
        request_digest: ctx.entry().request_digest.clone(),
        signature: ctx.entry().signature.clone(),
        server_fields_bytes: ctx.entry().server_fields_bytes.clone(),
        outer_entry_fingerprint: ctx.entry().outer_entry_fingerprint.clone(),
        actor_did: ctx.actor.user_did.clone(),
        actor_device_id: ctx.actor.device_id,
        actor_key_id: ctx.actor.key_id.clone(),
        actor_auth_generation: ctx.actor.auth_generation,
        generation: Some(generation),
        state_version: Some(state_version),
        transition_id: Some(transition_id),
        message_id: None,
        received_at: ctx.applied_at,
    }
}

/// Persist the creation metadata snapshot. The author identity is sourced
/// from the **actor** (not the binding): for creation the metadata author is
/// definitionally the creation actor, and the deferred author-proof trigger
/// joins the snapshot's author columns back to the creation transition's
/// actor columns, so they must byte-equal. The encrypted CONTENT (nonce,
/// ciphertext, its digest) is sourced from the plan's `MetadataSnapshotBinding`;
/// `origin_transition_id`/`metadata_version`/`author_origin_seq` are the
/// creation transition itself / 1 / the genesis seq.
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn write_creation_metadata_snapshot(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    metadata: &MetadataSnapshotBinding,
    author_cols: &MetadataAuthorColumns,
    actor: &ExecutionActor,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    epoch: i64,
    group_id: &[u8],
    group_context_hash: &[u8],
    confirmation_tag: &[u8],
    transition_id: Uuid,
    seq_i64: i64,
    applied_at: DateTime<Utc>,
) -> Result<(), ExecutorError> {
    let ciphertext = metadata.ciphertext().to_vec();
    let ciphertext_size = checked_i64(ciphertext.len() as u64)?;
    transition::insert_metadata_snapshot(
        transaction,
        &NewMetadataSnapshot {
            metadata_snapshot_id: author_cols.metadata_snapshot_id,
            conversation_id,
            generation,
            state_version,
            group_id: group_id.to_vec(),
            epoch,
            group_context_hash: group_context_hash.to_vec(),
            confirmation_tag: confirmation_tag.to_vec(),
            producing_transition_id: transition_id,
            // Self-origin snapshot: creation (version 1) and reset activation
            // (fresh, version prior+1) both set origin_transition_id to the
            // producing transition and author = the actor; the version comes
            // from the plan's binding so this serves both edges.
            origin_transition_id: transition_id,
            metadata_version: checked_i64(metadata.metadata_version())?,
            nonce: metadata.nonce().to_vec(),
            ciphertext_sha256: metadata.ciphertext_sha256().to_vec(),
            ciphertext,
            ciphertext_size,
            avatar: None,
            author_did: actor.user_did.clone(),
            author_device_id: actor.device_id,
            author_key_id: actor.key_id.clone(),
            author_public_key: author_cols.author_public_key.clone(),
            author_auth_generation: actor.auth_generation,
            author_origin_seq: seq_i64,
            author_role: author_cols.author_role.clone(),
            author_device_status: author_cols.author_device_status.clone(),
            created_at: applied_at,
        },
    )
    .await?;
    Ok(())
}

/// Persist a self-origin `signedMetadataTransition` snapshot. Unlike an
/// epoch re-encryption, this edge advances `metadata_version`, binds the new
/// origin to this transition, and records the current admin signer as the
/// author. The pure preflight has already proved those facts against the
/// signed body, actor, and repository-hydrated author columns.
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn write_metadata_update_snapshot(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    metadata: &MetadataSnapshotBinding,
    author_cols: &MetadataAuthorColumns,
    avatar: Option<&MetadataAvatarBinding>,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    epoch: i64,
    group_id: &[u8],
    group_context_hash: &[u8],
    confirmation_tag: &[u8],
    transition_id: Uuid,
    seq_i64: i64,
    applied_at: DateTime<Utc>,
) -> Result<(), ExecutorError> {
    let ciphertext = metadata.ciphertext().to_vec();
    let ciphertext_size = checked_i64(ciphertext.len() as u64)?;
    transition::insert_metadata_snapshot(
        transaction,
        &NewMetadataSnapshot {
            metadata_snapshot_id: author_cols.metadata_snapshot_id,
            conversation_id,
            generation,
            state_version,
            group_id: group_id.to_vec(),
            epoch,
            group_context_hash: group_context_hash.to_vec(),
            confirmation_tag: confirmation_tag.to_vec(),
            producing_transition_id: transition_id,
            origin_transition_id: transition_id,
            metadata_version: checked_i64(metadata.metadata_version())?,
            nonce: metadata.nonce().to_vec(),
            ciphertext_sha256: metadata.ciphertext_sha256().to_vec(),
            ciphertext,
            ciphertext_size,
            avatar: avatar.cloned(),
            author_did: device_did(metadata.author())?,
            author_device_id: device_uuid(metadata.author()),
            author_key_id: author_cols.author_key_id.clone(),
            author_public_key: metadata.signature_public_key().to_vec(),
            author_auth_generation: checked_i64(metadata.author_auth_generation_at_origin())?,
            author_origin_seq: seq_i64,
            author_role: author_cols.author_role.clone(),
            author_device_status: author_cols.author_device_status.clone(),
            created_at: applied_at,
        },
    )
    .await?;
    Ok(())
}

/// Persist a commit/leafRecovery metadata RE-ENCRYPTION snapshot. Per the DDL
/// `assert_metadata_snapshot_mapping` `commit/leafRecovery/leaveCommit` arm the
/// new snapshot's author / origin / metadata_version / ciphertext_size / avatar
/// columns must byte-equal the PRIOR snapshot's — only nonce / ciphertext /
/// ciphertext_sha256 are fresh (the metadata content re-encrypted for the new
/// epoch). So author identity is CARRIED FORWARD from the re-encryption
/// binding's author-proof (the ORIGINAL author — creation/metadata author, NOT
/// the fulfiller `ctx.actor`), with the DB `author_key_id` / `author_role` /
/// `author_device_status` / snapshot PK supplied by `MetadataAuthorColumns`;
/// `producing_transition_id` and the coordinate are this transition's successor.
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn write_commit_metadata_snapshot(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    metadata: &MetadataSnapshotBinding,
    author_cols: &MetadataAuthorColumns,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    epoch: i64,
    group_id: &[u8],
    group_context_hash: &[u8],
    confirmation_tag: &[u8],
    producing_transition_id: Uuid,
    applied_at: DateTime<Utc>,
) -> Result<(), ExecutorError> {
    let proof = &metadata.author_proof;
    let ciphertext = metadata.ciphertext().to_vec();
    let ciphertext_size = checked_i64(ciphertext.len() as u64)?;
    transition::insert_metadata_snapshot(
        transaction,
        &NewMetadataSnapshot {
            metadata_snapshot_id: author_cols.metadata_snapshot_id,
            conversation_id,
            generation,
            state_version,
            group_id: group_id.to_vec(),
            epoch,
            group_context_hash: group_context_hash.to_vec(),
            confirmation_tag: confirmation_tag.to_vec(),
            producing_transition_id,
            // Carry-forward origin + version from the prior snapshot.
            origin_transition_id: Uuid::from_bytes(*metadata.origin_transition_id()),
            metadata_version: checked_i64(metadata.metadata_version())?,
            // Fresh re-encryption (same ciphertext size as the prior snapshot).
            nonce: metadata.nonce().to_vec(),
            ciphertext_sha256: metadata.ciphertext_sha256().to_vec(),
            ciphertext,
            ciphertext_size,
            avatar: None,
            // Carry-forward author identity from the binding's author-proof.
            author_did: principal_did(proof.author.principal())?,
            author_device_id: device_uuid(&proof.author),
            author_key_id: author_cols.author_key_id.clone(),
            author_public_key: proof.signature_public_key.to_vec(),
            author_auth_generation: checked_i64(proof.auth_generation_at_origin)?,
            author_origin_seq: checked_i64(proof.origin_seq)?,
            author_role: author_cols.author_role.clone(),
            author_device_status: author_cols.author_device_status.clone(),
            created_at: applied_at,
        },
    )
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn write_participants(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    hydration: &ConversationStateHydration,
    effects: &TransitionEffects,
    transition_id: Uuid,
    applied_at: DateTime<Utc>,
    allow_role_changes: bool,
) -> Result<(), ExecutorError> {
    let creator = &ctx.actor;
    let mut period_ids = ctx.participant_period_ids.iter();
    for change in effects.participant_changes() {
        let after = match (change.before(), change.after()) {
            (Some(before), Some(after)) if allow_role_changes => {
                transition::cas_participant_active_role(
                    transaction,
                    &ParticipantRoleCas {
                        conversation_id: Uuid::from_bytes(*hydration.coordinate.conversation_id()),
                        user_did: principal_did(after.principal())?,
                        expected_role: repo_participant_role(before.role()),
                        successor_role: repo_participant_role(after.role()),
                        role_transition_id: transition_id,
                        role_changed_at: applied_at,
                    },
                )
                .await?;
                continue;
            }
            (None, Some(after)) => after,
            (Some(_), None) if allow_role_changes => continue,
            _ => {
                return Err(ExecutorError::UnsupportedEffect(
                    "participant change is not an insert or policy role change",
                ))
            }
        };
        let row = hydration
            .participants
            .iter()
            .find(|row| &row.principal == after.principal())
            .ok_or(ExecutorError::InconsistentPlan(
                "participant not in hydration",
            ))?;
        let period_id = *period_ids
            .next()
            .ok_or(ExecutorError::MissingContext("participant period id"))?;
        let invitation = match &row.invitation {
            Some(_) => Some(ParticipantInvitation {
                invitation_transition_id: transition_id,
                invitation_entry_id: ctx.entry().entry_id,
                invited_at: applied_at,
            }),
            None => None,
        };
        let user_did = principal_did(&row.principal)?;
        // `Some(None)` is an explicit local route. A missing map entry is
        // missing authority and must never silently become local.
        let ds_did = ctx
            .participant_ds_dids
            .get(&user_did)
            .cloned()
            .ok_or(ExecutorError::MissingParticipantRoutingAuthority)?;
        transition::insert_participant_period(
            transaction,
            &NewParticipantPeriod {
                participant_period_id: period_id,
                conversation_id: Uuid::from_bytes(*hydration.coordinate.conversation_id()),
                user_did,
                status: repo_participant_status(row.status),
                role: repo_participant_role(row.role),
                role_transition_id: transition_id,
                role_changed_at: applied_at,
                created_by_did: creator.user_did.clone(),
                created_by_device_id: creator.device_id,
                invitation,
                acceptance: None,
                created_at: applied_at,
                ds_did,
            },
        )
        .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn write_creation_leaves(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    hydration: &ConversationStateHydration,
    effects: &TransitionEffects,
    conversation_id: Uuid,
    generation: i64,
    transition_id: Uuid,
    state_version: i64,
    seq_i64: i64,
    applied_at: DateTime<Utc>,
) -> Result<HashMap<DeviceIdentity, Uuid>, ExecutorError> {
    let mut opened: HashMap<DeviceIdentity, Uuid> = HashMap::new();
    let mut leaf_ids = ctx.leaf_period_ids.iter();
    for change in effects.leaf_changes() {
        let after = match (change.before(), change.after()) {
            (None, Some(after)) => after,
            _ => {
                return Err(ExecutorError::UnsupportedEffect(
                    "leaf change is not a creation insert",
                ))
            }
        };
        let row: &LeafHydrationRow = hydration
            .leaves
            .iter()
            .find(|row| &row.device == after.device())
            .ok_or(ExecutorError::InconsistentPlan("leaf not in hydration"))?;
        let cols = ctx
            .opened_leaves
            .iter()
            .find(|cols| &cols.device == after.device())
            .ok_or(ExecutorError::MissingContext("leaf persistence columns"))?;
        // The owning participant period must already be inserted; its id is
        // matched by DID (one current period per DID at creation).
        let participant_period_id =
            participant_period_for(ctx, hydration, after.device().principal())?;
        let leaf_id = *leaf_ids
            .next()
            .ok_or(ExecutorError::MissingContext("leaf period id"))?;
        transition::insert_leaf_period(
            transaction,
            &NewLeafPeriod {
                leaf_period_id: leaf_id,
                participant_period_id,
                conversation_id,
                generation,
                user_did: device_did(after.device())?,
                device_id: device_uuid(after.device()),
                leaf_index: checked_i64(u64::from(row.leaf_index))?,
                basic_credential: row.basic_credential.clone(),
                leaf_signature_key: row.signature_key.clone(),
                leaf_key_id: cols.leaf_key_id.clone(),
                leaf_auth_generation: cols.leaf_auth_generation,
                origin: LeafOrigin::Genesis,
                joined_state_version: state_version,
                joined_transition_id: transition_id,
                joined_seq: seq_i64,
                created_at: applied_at,
            },
        )
        .await?;
        opened.insert(after.device().clone(), leaf_id);
    }
    Ok(opened)
}

/// Resolve the participant-period id the executor minted for `principal`.
/// Creation inserts periods in the plan's canonical participant order, so the
/// id is the ctx `participant_period_ids` entry at that principal's index.
pub(in crate::chat_protocol::state_machine::executor) fn participant_period_for(
    ctx: &ExecutionContext,
    hydration: &ConversationStateHydration,
    principal: &PrincipalId,
) -> Result<Uuid, ExecutorError> {
    let index = hydration
        .participants
        .iter()
        .position(|row| &row.principal == principal)
        .ok_or(ExecutorError::InconsistentPlan(
            "leaf owner not a participant",
        ))?;
    ctx.participant_period_ids
        .get(index)
        .copied()
        .ok_or(ExecutorError::MissingContext(
            "participant period id for leaf owner",
        ))
}

pub(in crate::chat_protocol::state_machine::executor) async fn write_creation_intervals(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    effects: &TransitionEffects,
    leaf_ids: &HashMap<DeviceIdentity, Uuid>,
    conversation_id: Uuid,
    applied_at: DateTime<Utc>,
) -> Result<(), ExecutorError> {
    for change in effects.interval_changes() {
        let after = match (change.before(), change.after()) {
            (None, Some(after)) => after,
            _ => {
                return Err(ExecutorError::UnsupportedEffect(
                    "interval change is not a creation open",
                ))
            }
        };
        if after.end().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "creation interval is born closed",
            ));
        }
        if after.opening_kind() != crate::chat_protocol::state_machine::OpeningKind::Creation {
            return Err(ExecutorError::UnsupportedEffect(
                "non-creation interval opening in a creation plan",
            ));
        }
        let opening_transition_id = Uuid::from_bytes(*after.opening_transition_id());
        let opening_leaf_period_id =
            *leaf_ids
                .get(after.recipient())
                .ok_or(ExecutorError::InconsistentPlan(
                    "interval recipient has no opened leaf",
                ))?;
        let opening_context = after.opening_context();
        delivery::insert_application_interval(
            transaction,
            &NewApplicationInterval {
                membership_interval_id: opening_transition_id,
                conversation_id,
                generation: checked_i64(opening_context.generation())?,
                recipient_did: device_did(after.recipient())?,
                recipient_device_id: device_uuid(after.recipient()),
                start_seq: checked_i64(after.opening_seq())?,
                opening_kind: IntervalOpeningKind::Creation,
                opening_transition_id,
                opening_outer_entry_fingerprint: after.opening_outer_entry_fingerprint().to_vec(),
                opening_state_version: checked_i64(opening_context.state_version())?,
                opening_group_id: opening_context.group_id().to_vec(),
                opening_epoch: checked_i64(opening_context.epoch())?,
                opening_group_context_hash: opening_context.group_context_hash().to_vec(),
                opening_confirmation_tag: opening_context.confirmation_tag().to_vec(),
                opening_leaf_period_id,
                created_at: applied_at,
            },
        )
        .await?;
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine::executor) fn build_entry_recipients(
    recipients: &[(DeviceIdentity, EntryEntitlementKind)],
) -> Result<Vec<EntryRecipient>, ExecutorError> {
    recipients
        .iter()
        .map(|(device, kind)| {
            Ok(EntryRecipient {
                user_did: device_did(device)?,
                device_id: device_uuid(device),
                entitlement_kind: *kind,
            })
        })
        .collect()
}
