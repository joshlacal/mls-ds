#![allow(unused_imports)]
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum EventChainCursorError {
    #[error("event-chain prelude digest or device vector is invalid")]
    PreludeDigestMismatch,
    #[error("event-chain schedule received an unexpected event")]
    UnexpectedEvent,
    #[error("event-chain event shape changed after preparation")]
    EventShapeMismatch,
    #[error("event-chain event repeats or reorders a recipient")]
    DuplicateRecipient,
    #[error("event-chain event names a device outside the locked prelude")]
    UnknownSlot,
    #[error("event-chain cursor already has an event pending completion")]
    EventAlreadyPending,
    #[error("event-chain cursor has no event pending completion")]
    NoPendingEvent,
    #[error("event-chain event position is not monotonic")]
    PositionNotMonotonic,
    #[error("event-chain schedule was not fully consumed")]
    IncompleteSchedule,
}

pub(in crate::chat_protocol::state_machine::executor) struct PendingPreparedEvent {
    pub(in crate::chat_protocol::state_machine::executor) event_id: Uuid,
    pub(in crate::chat_protocol::state_machine::executor) slots: Vec<EventChainSlot>,
}

/// Pure, SQL-free resolver for the device-global event predecessor chain.
/// It is deliberately single-use and remains owned by the opaque prepared
/// revocation batch.
pub(crate) struct EventChainCursor {
    pub(in crate::chat_protocol::state_machine::executor) prelude_digest: [u8; 32],
    pub(in crate::chat_protocol::state_machine::executor) devices: Vec<DeviceIdentity>,
    pub(in crate::chat_protocol::state_machine::executor) current_tails: Vec<Option<i64>>,
    pub(in crate::chat_protocol::state_machine::executor) remaining: VecDeque<PreparedRevocationEvent>,
    pub(in crate::chat_protocol::state_machine::executor) pending_event: Option<PendingPreparedEvent>,
    pub(in crate::chat_protocol::state_machine::executor) initial_binding_digest: [u8; 32],
}

impl EventChainCursor {
    pub(crate) fn new(
        prelude_digest: [u8; 32],
        devices: Vec<DeviceIdentity>,
        current_tails: Vec<Option<i64>>,
        schedule: Vec<PreparedRevocationEvent>,
    ) -> Result<Self, EventChainCursorError> {
        if prelude_digest == [0; 32] {
            return Err(EventChainCursorError::PreludeDigestMismatch);
        }
        if devices.len() != current_tails.len() || devices.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(EventChainCursorError::PreludeDigestMismatch);
        }
        let mut event_ids = BTreeSet::new();
        for event in &schedule {
            if !event_ids.insert(event.event_id) {
                return Err(EventChainCursorError::EventShapeMismatch);
            }
            let mut previous = None;
            for recipient in &event.recipients {
                let slot = usize::try_from(recipient.slot.0)
                    .map_err(|_| EventChainCursorError::UnknownSlot)?;
                if slot >= devices.len() {
                    return Err(EventChainCursorError::UnknownSlot);
                }
                if previous.is_some_and(|prior| prior >= recipient.slot) {
                    return Err(EventChainCursorError::DuplicateRecipient);
                }
                previous = Some(recipient.slot);
            }
        }
        let initial_binding_digest = event_chain_cursor_binding_digest(
            &prelude_digest,
            &devices,
            &current_tails,
            schedule.len(),
            schedule.iter(),
        );
        Ok(Self {
            prelude_digest,
            devices,
            current_tails,
            remaining: schedule.into(),
            pending_event: None,
            initial_binding_digest,
        })
    }

    pub(in crate::chat_protocol::state_machine::executor) fn recompute_initial_binding_digest(&self) -> [u8; 32] {
        event_chain_cursor_binding_digest(
            &self.prelude_digest,
            &self.devices,
            &self.current_tails,
            self.remaining.len(),
            self.remaining.iter(),
        )
    }

    pub(in crate::chat_protocol::state_machine::executor) fn initial_binding_is_intact(&self) -> bool {
        self.pending_event.is_none()
            && self.initial_binding_digest == self.recompute_initial_binding_digest()
    }

    pub(in crate::chat_protocol::state_machine::executor) fn initial_binding_digest(&self) -> &[u8; 32] {
        &self.initial_binding_digest
    }

    pub(crate) fn begin_event(
        &mut self,
        event: &PreparedRevocationEvent,
    ) -> Result<Vec<EventRecipient>, EventChainCursorError> {
        if self.pending_event.is_some() {
            return Err(EventChainCursorError::EventAlreadyPending);
        }
        let expected = self
            .remaining
            .front()
            .ok_or(EventChainCursorError::UnexpectedEvent)?;
        if event.event_id != expected.event_id {
            return Err(EventChainCursorError::UnexpectedEvent);
        }
        let actual_digest = prepared_revocation_event_digest(
            event.event_id,
            event.event_kind,
            &event.payload_bytes,
            &event.recipients,
            &event.outbox,
        );
        if actual_digest != expected.schedule_digest
            || actual_digest != event.schedule_digest
            || event.event_kind != expected.event_kind
            || event.payload_bytes != expected.payload_bytes
            || event.recipients != expected.recipients
            || event.outbox != expected.outbox
        {
            return Err(EventChainCursorError::EventShapeMismatch);
        }
        let mut rows = Vec::with_capacity(event.recipients.len());
        let mut slots = Vec::with_capacity(event.recipients.len());
        for recipient in &event.recipients {
            let slot = usize::try_from(recipient.slot.0)
                .map_err(|_| EventChainCursorError::UnknownSlot)?;
            let device = self
                .devices
                .get(slot)
                .ok_or(EventChainCursorError::UnknownSlot)?;
            rows.push(EventRecipient {
                user_did: String::from_utf8(device.principal().as_bytes().to_vec())
                    .map_err(|_| EventChainCursorError::UnknownSlot)?,
                device_id: Uuid::from_bytes(*device.device_id()),
                entitlement_kind: recipient.entitlement,
                audience_predecessor_position: self.current_tails[slot],
            });
            slots.push(recipient.slot);
        }
        self.pending_event = Some(PendingPreparedEvent {
            event_id: event.event_id,
            slots,
        });
        Ok(rows)
    }

    pub(in crate::chat_protocol::state_machine::executor) fn begin_fanout(
        &mut self,
        event: &EventFanout,
    ) -> Result<Vec<EventRecipient>, EventChainCursorError> {
        if self.pending_event.is_some() {
            return Err(EventChainCursorError::EventAlreadyPending);
        }
        let expected = self
            .remaining
            .front()
            .ok_or(EventChainCursorError::UnexpectedEvent)?;
        if event.event_id != expected.event_id {
            return Err(EventChainCursorError::UnexpectedEvent);
        }
        if event.event_kind != expected.event_kind
            || event.payload_bytes != expected.payload_bytes
            || event.outbox != expected.outbox
            || event.recipients.len() != expected.recipients.len()
        {
            return Err(EventChainCursorError::EventShapeMismatch);
        }
        let mut rows = Vec::with_capacity(expected.recipients.len());
        let mut slots = Vec::with_capacity(expected.recipients.len());
        for (actual, expected_recipient) in event.recipients.iter().zip(&expected.recipients) {
            let slot = expected_recipient.slot.0 as usize;
            let expected_device = self
                .devices
                .get(slot)
                .ok_or(EventChainCursorError::UnknownSlot)?;
            if &actual.0 != expected_device || actual.1 != expected_recipient.entitlement {
                return Err(EventChainCursorError::EventShapeMismatch);
            }
            rows.push(EventRecipient {
                user_did: device_did(expected_device)
                    .map_err(|_| EventChainCursorError::UnknownSlot)?,
                device_id: device_uuid(expected_device),
                entitlement_kind: expected_recipient.entitlement,
                audience_predecessor_position: self.current_tails[slot],
            });
            slots.push(expected_recipient.slot);
        }
        self.pending_event = Some(PendingPreparedEvent {
            event_id: event.event_id,
            slots,
        });
        Ok(rows)
    }

    pub(crate) fn complete_event(
        &mut self,
        event_id: Uuid,
        event_position: i64,
    ) -> Result<(), EventChainCursorError> {
        let pending = self
            .pending_event
            .as_ref()
            .ok_or(EventChainCursorError::NoPendingEvent)?;
        if pending.event_id != event_id {
            return Err(EventChainCursorError::UnexpectedEvent);
        }
        if event_position <= 0
            || pending.slots.iter().any(|slot| {
                self.current_tails[slot.0 as usize].is_some_and(|tail| event_position <= tail)
            })
        {
            return Err(EventChainCursorError::PositionNotMonotonic);
        }
        let pending = self.pending_event.take().expect("checked pending event");
        for slot in pending.slots {
            self.current_tails[slot.0 as usize] = Some(event_position);
        }
        self.remaining.pop_front();
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<(), EventChainCursorError> {
        if self.pending_event.is_some() || !self.remaining.is_empty() {
            return Err(EventChainCursorError::IncompleteSchedule);
        }
        let _ = self.prelude_digest;
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::chat_protocol::state_machine::executor) fn finish_for_test(&self) -> Result<(), EventChainCursorError> {
        if self.pending_event.is_some() || !self.remaining.is_empty() {
            Err(EventChainCursorError::IncompleteSchedule)
        } else {
            Ok(())
        }
    }
}

pub(in crate::chat_protocol::state_machine::executor) fn event_chain_cursor_binding_digest<'event>(
    prelude_digest: &[u8; 32],
    devices: &[DeviceIdentity],
    initial_tails: &[Option<i64>],
    schedule_len: usize,
    schedule: impl IntoIterator<Item = &'event PreparedRevocationEvent>,
) -> [u8; 32] {
    let mut digest = sha2::Sha256::new();
    digest.update(b"CATBIRD-CHAT-G6-EVENT-CHAIN-CURSOR\0");
    digest.update(prelude_digest);
    digest.update((devices.len() as u64).to_be_bytes());
    for (device, tail) in devices.iter().zip(initial_tails) {
        digest.update((device.principal().as_bytes().len() as u64).to_be_bytes());
        digest.update(device.principal().as_bytes());
        digest.update(device.device_id());
        match tail {
            Some(value) => {
                digest.update([1]);
                digest.update(value.to_be_bytes());
            }
            None => digest.update([0]),
        }
    }
    digest.update((schedule_len as u64).to_be_bytes());
    for event in schedule {
        digest.update(event.schedule_digest);
    }
    digest.finalize().into()
}

/// For a `welcomeExpiry` edge: the DB-side facts the plan does not carry — the
/// fresh `recovery_work_items` primary key and the `welcomeDisposition` event
/// whose position binds the disposition row. The welcome id / recipient /
/// bound coordinate / `expires_at` come from the plan's `welcome_changes`.
/// `None` for every other edge.
#[derive(Clone, Debug)]
pub(crate) struct WelcomeExpiryContext {
    pub(crate) recovery_work_id: Uuid,
    pub(crate) event: EventFanout,
}

/// For a `welcomeAcknowledgement` / `welcomeRejection` edge: the
/// `welcomeDisposition` event (its position binds the disposition row) plus, for
/// a REJECTION only, the `welcomeRejected` recovery work. The client-authored
/// signed authorization the disposition row binds comes from `ctx.entry` (the
/// signed request's bytes/digest/signature); the welcome id / recipient / bound
/// coordinate come from the plan's `welcome_changes`. `None` otherwise.
#[derive(Clone, Debug)]
pub(crate) struct WelcomeResponseContext {
    pub(crate) event: EventFanout,
    /// `Some` for a rejection (adds a `welcomeRejected` recovery work item with
    /// the closed reason); `None` for an acknowledgement (no recovery work).
    pub(crate) rejection: Option<WelcomeRejectionWork>,
}

/// The `welcomeRejected` recovery work a rejection creates.
#[derive(Clone, Debug)]
pub(crate) struct WelcomeRejectionWork {
    pub(crate) recovery_work_id: Uuid,
    pub(crate) reason: WelcomeRejectionReason,
}

/// Everything the plan does NOT carry. AUDIENCE IS INPUT, NOT DERIVED: the
/// executor never queries `chat.devices` to invent an audience.
#[cfg_attr(test, derive(Clone))]
#[derive(Debug)]
pub(crate) struct ExecutionContext {
    pub(crate) protocol_instance_id: Uuid,
    /// The trusted request instant `T` — every `*_at` the executor writes.
    pub(crate) applied_at: DateTime<Utc>,
    pub(crate) actor: ExecutionActor,
    pub(crate) authority: ExecutionAuthority,
    pub(crate) spine: SpineArtifacts,
    pub(crate) opened_leaves: Vec<LeafPersistenceColumns>,
    pub(crate) metadata_author: Option<MetadataAuthorColumns>,
    pub(crate) metadata_avatar: Option<MetadataAvatarPersistence>,
    /// Fresh participant-period ids in the plan's canonical participant order.
    pub(crate) participant_period_ids: Vec<Uuid>,
    /// Fresh leaf-period ids in the plan's opened-leaf order.
    pub(crate) leaf_period_ids: Vec<Uuid>,
    /// The exact control-entry audience, canonical `(DID, device)` order.
    pub(crate) entry_recipients: Vec<(DeviceIdentity, EntryEntitlementKind)>,
    pub(crate) events: Vec<EventFanout>,
    /// For a `close`/`reset` edge that closes existing intervals: the exact
    /// active leaf-period id to record as each interval's
    /// `closing_leaf_period_id`. The facade queries `chat.member_devices` for
    /// the recipient's active leaf under lock; the plan's `interval_changes`
    /// supply everything else (terminal seq, closing transition + fingerprint).
    /// Empty for edges that close no interval (creation / policy / reset req).
    pub(crate) closing_leaf_periods: Vec<(DeviceIdentity, Uuid)>,
    /// For an edge that TERMINALIZES an existing participant period (a
    /// Policy/leave removal): the
    /// exact active `chat.participants.participant_period_id` to close. The
    /// removed participant is NOT in the successor hydration, so its period id
    /// cannot come from `participant_period_ids`; the facade queries
    /// `chat.participants` for it under lock. Empty for every other edge.
    pub(crate) closing_participant_periods: Vec<(PrincipalId, Uuid)>,
    /// For a `reset request` edge: the exact `chat.reset_requests` row content
    /// the signed request carries (reason + signed material + expiry). `None`
    /// for every other edge.
    pub(crate) reset_request_row: Option<ResetRequestRow>,
    /// For an edge that OPENS a leaf-recovery request + reservation and
    /// reserves a key package (acceptance / leaf-recovery request): the DB-side
    /// facts the plan does not carry. `None` for every other edge. The
    /// requester/recipient identity is the transition/request actor
    /// (`ctx.actor`); the request id, kind, bound coordinate, and key-package
    /// ref come from the plan's `recovery_request_changes`.
    pub(crate) recovery_open: Option<RecoveryOpenContext>,
    /// For a `welcomeExpiry` edge (see `WelcomeExpiryContext`). `None` otherwise.
    pub(crate) welcome_expiry: Option<WelcomeExpiryContext>,
    /// For a `welcomeAcknowledgement`/`welcomeRejection` edge (see
    /// `WelcomeResponseContext`). `None` otherwise.
    pub(crate) welcome_response: Option<WelcomeResponseContext>,
    /// For a coordinate-changing commit that SUPERSEDES a prior-coordinate
    /// pending Welcome: the `welcomeDisposition` event the executor appends and
    /// binds the disposition row to (one per superseded welcome). Empty for
    pub(crate) welcome_dispositions: Vec<WelcomeDispositionInput>,
    pub(crate) is_remote: bool,
    pub(crate) sequencer_ds: Option<String>,
    pub(crate) sequencer_term: i64,
    pub(crate) participant_ds_dids: std::collections::HashMap<String, Option<String>>,
}

impl ExecutionContext {
    pub(in crate::chat_protocol::state_machine::executor) fn entry(&self) -> &ControlEntryContent {
        self.authority
            .control_entry()
            .expect("execution authority validated before executor dispatch")
    }

    pub(in crate::chat_protocol::state_machine::executor) fn operation_id(&self) -> Uuid {
        self.authority.operation_id()
    }
}

/// A single-use execution capsule minted only after repository hydration
/// has bound one exact plan and context to the live SQL transaction.
///
/// The constructor requires an unforgeable token owned by
/// `repository::execution_context`. No production API accepts a separable
/// plan or raw `ExecutionContext`.
#[must_use = "a prepared execution must be consumed by the atomic executor"]
pub(crate) struct PreparedConversationExecution<'borrow, 'connection, 'plan> {
    pub(in crate::chat_protocol::state_machine::executor) transaction: &'borrow mut sqlx::Transaction<'connection, sqlx::Postgres>,
    pub(in crate::chat_protocol::state_machine::executor) plan: &'plan ConversationPersistencePlan,
    pub(in crate::chat_protocol::state_machine::executor) context: ExecutionContext,
    pub(in crate::chat_protocol::state_machine::executor) expected_transaction_id: Box<str>,
    pub(in crate::chat_protocol::state_machine::executor) recovery_write_authority:
        Option<crate::chat_protocol::repository::recovery::RecoveryExecutorWriteAuthority<'plan>>,
    pub(in crate::chat_protocol::state_machine::executor) historical_write_authority: Option<HistoricalExecutionWriteAuthority>,
    pub(in crate::chat_protocol::state_machine::executor) _proof: crate::chat_protocol::repository::execution_context::ExecutionContextHydrationProof,
    #[cfg(any(
        test,
        all(
            feature = "chat-protocol-production-proof",
            not(feature = "server-bin")
        )
    ))]
    pub(in crate::chat_protocol::state_machine::executor) drop_safety_probe: Option<DropSafetyProbe>,
}

impl<'borrow, 'connection, 'plan> PreparedConversationExecution<'borrow, 'connection, 'plan> {
    pub(crate) fn from_hydrated_parts(
        transaction: &'borrow mut sqlx::Transaction<'connection, sqlx::Postgres>,
        plan: &'plan ConversationPersistencePlan,
        context: ExecutionContext,
        expected_transaction_id: Box<str>,
        proof: crate::chat_protocol::repository::execution_context::ExecutionContextHydrationProof,
    ) -> Self {
        Self {
            transaction,
            plan,
            context,
            expected_transaction_id,
            recovery_write_authority: None,
            historical_write_authority: None,
            _proof: proof,
            #[cfg(any(
                test,
                all(
                    feature = "chat-protocol-production-proof",
                    not(feature = "server-bin")
                )
            ))]
            drop_safety_probe: None,
        }
    }

    /// Attach a deterministic test-only suspension/unwind point without
    /// changing any plan, authority, context, or transaction binding.
    #[cfg(test)]
    pub(crate) fn with_drop_safety_probe_for_test(mut self, probe: DropSafetyProbe) -> Self {
        self.drop_safety_probe = Some(probe);
        self
    }

    /// Attach the same per-capsule post-write probe to the non-shipping
    /// production-proof build. The proof feature is compile-incompatible
    /// with `server-bin`, so this seam cannot enter the shipping executor.
    #[cfg(all(
        feature = "chat-protocol-production-proof",
        not(feature = "server-bin")
    ))]
    pub(in crate::chat_protocol) fn with_drop_safety_probe_for_proof(
        mut self,
        probe: DropSafetyProbe,
    ) -> Self {
        self.drop_safety_probe = Some(probe);
        self
    }

    pub(in crate::chat_protocol) fn with_recovery_write_authority(
        mut self,
        authority: crate::chat_protocol::repository::recovery::RecoveryExecutorWriteAuthority<'plan>,
    ) -> Self {
        self.recovery_write_authority = Some(authority);
        self
    }

    pub(in crate::chat_protocol) fn with_historical_write_authority(
        mut self,
        authority: HistoricalExecutionWriteAuthority,
    ) -> Self {
        self.historical_write_authority = Some(authority);
        self
    }
}

/// Test-only behavior at the prepared executor's post-write,
/// pre-savepoint-release boundary.
#[cfg(any(
    test,
    all(
        feature = "chat-protocol-production-proof",
        not(feature = "server-bin")
    )
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DropSafetyProbeMode {
    Pending,
    Panic,
}

/// Per-capsule drop-safety probe. It is neither global nor cloneable and is
/// attachable only after repository hydration has minted the production
/// capsule, so it cannot weaken any authority or artifact check.
#[cfg(any(
    test,
    all(
        feature = "chat-protocol-production-proof",
        not(feature = "server-bin")
    )
))]
pub(crate) struct DropSafetyProbe {
    pub(in crate::chat_protocol::state_machine::executor) mode: DropSafetyProbeMode,
    pub(in crate::chat_protocol::state_machine::executor) reached: tokio::sync::oneshot::Sender<()>,
}

#[cfg(any(
    test,
    all(
        feature = "chat-protocol-production-proof",
        not(feature = "server-bin")
    )
))]
impl DropSafetyProbe {
    pub(crate) fn new(mode: DropSafetyProbeMode) -> (Self, tokio::sync::oneshot::Receiver<()>) {
        let (reached, receiver) = tokio::sync::oneshot::channel();
        (Self { mode, reached }, receiver)
    }

    pub(in crate::chat_protocol::state_machine::executor) async fn reach(self) {
        let _ = self.reached.send(());
        match self.mode {
            DropSafetyProbeMode::Pending => std::future::pending::<()>().await,
            DropSafetyProbeMode::Panic => {
                panic!("prepared-executor drop-safety probe")
            }
        }
    }
}

pub(crate) fn plan_transaction_bindings_match(
    plan: &ConversationPersistencePlan,
    expected_transaction_id: &str,
) -> bool {
    let effects = plan.effects();
    effects
        .head_cas()
        .is_some_and(|binding| binding.transaction_id() == expected_transaction_id)
        && effects
            .recovery_package_cas()
            .iter()
            .all(|binding| binding.transaction_id() == expected_transaction_id)
        && effects
            .revocation_package_cas()
            .iter()
            .all(|binding| binding.transaction_id() == expected_transaction_id)
        && effects
            .revocation_target_cas()
            .is_none_or(|binding| binding.transaction_id() == expected_transaction_id)
        && effects
            .welcome_cas()
            .is_none_or(|binding| binding.transaction_id() == expected_transaction_id)
        && effects
            .invitation_quota_cas()
            .is_none_or(|binding| binding.transaction_id() == expected_transaction_id)
}

pub(crate) fn batch_transaction_bindings_match(
    plan: &DeviceRevocationBatchPersistencePlan,
    expected_transaction_id: &str,
) -> bool {
    plan.target_cas().transaction_id() == expected_transaction_id
        && plan
            .revoked_packages()
            .iter()
            .all(|binding| binding.transaction_id() == expected_transaction_id)
        && plan.conversations().iter().all(|conversation| {
            plan_transaction_bindings_match(conversation, expected_transaction_id)
        })
}

/// The `welcomeDisposition` event + outbox the executor appends when a
/// coordinate change retires a prior-coordinate pending Welcome. The
/// disposition row (`terminalize_welcome_delivery`) is bound to this event's
/// position.
///
/// A prior-bound welcome retires one of two ways, and the DB treats them very
/// differently. `Pending->Superseded` is caused BY the transition and creates no
/// recovery work. `Pending->Expired` is a due expiry the transition merely
/// OBSERVES — `assert_recovery_work_integrity` requires exactly one
/// `welcomeExpired` `recovery_work_items` row for it, exactly as the dedicated
/// `apply_welcome_expiry` arm writes. So the expiry case needs the same fresh
/// primary key `WelcomeExpiryContext` carries, minted by the same repository
/// hydration; `None` for the supersession case, which must have no work item.
#[derive(Clone, Debug)]
pub(crate) struct WelcomeDispositionInput {
    pub(crate) welcome_id: Uuid,
    /// `Some` iff this welcome's delta is `Pending->Expired`.
    pub(crate) recovery_work_id: Option<Uuid>,
    pub(crate) event: EventFanout,
}

/// DB-side facts a recovery-opening edge needs that the plan does not carry.
/// The `expires_at` the mapping trigger checks is
/// `LEAST(created_at + 5 min, package.not_after)`, so the executor writes
/// DB-clock timestamps (`created_at = requested_at = applied_at`) and needs the
/// reserved package's `not_after` to compute that bound exactly.
#[derive(Clone, Debug)]
pub(crate) struct RecoveryOpenContext {
    /// The acceptor's current participant period — the acceptance CAS target.
    /// `Some` only for the acceptance edge (a leaf-recovery request touches no
    /// participant row).
    pub(crate) participant_period_id: Option<Uuid>,
    /// `chat.key_packages.not_after` of the reserved package.
    pub(crate) package_not_after: DateTime<Utc>,
    /// For a `replace` leaf-recovery request: the leaf period being replaced.
    /// `None` for an `add`.
    pub(crate) replaced_leaf_period_id: Option<Uuid>,
}

/// The exact `chat.reset_requests` row a reset-request edge persists. Sourced
/// from the verified signed `requestReset` body; the executor writes it
/// verbatim (the DB re-verifies `request_digest`/`expires_at`).
#[derive(Clone, Debug)]
pub(crate) struct ResetRequestRow {
    pub(crate) reset_request_id: Uuid,
    pub(crate) reason: transition::ResetReason,
    pub(crate) signed_request_bytes: Vec<u8>,
    pub(crate) signing_transcript_bytes: Vec<u8>,
    pub(crate) request_digest: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) expires_at: DateTime<Utc>,
}

/// What the executor allocated/produced, echoed for the caller's response.
#[derive(Clone, Debug)]
pub(crate) struct AppliedTransition {
    pub(crate) allocated_seq: u64,
    pub(crate) entry_id: Uuid,
    pub(crate) event_positions: Vec<i64>,
    pub(crate) successor_coordinate: Option<PublicGroupSnapshotCoordinate>,
}

