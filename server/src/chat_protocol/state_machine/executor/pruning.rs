#![allow(unused_imports)]
use super::*;

/// Consume the prior-coordinate open-work SUPERSESSION deltas a
/// coordinate-changing commit carries (the planner's `resolve_prior_bound_work`
/// emits them; E2b-7 arm 1). For each `(Open -> Superseded)` recovery request:
/// terminalize `SupersededByTransition`. For each `(Active -> Released)`
/// reservation: terminalize `ReleasedByTransition`. For each
/// `Reserved -> Available` package edge: re-activate. The OWN delta of an
/// edge (a fulfillment's `Fulfilled`/`Consumed`/`Consumed`) has a DIFFERENT
/// shape and is SKIPPED here (the arm handles it), so this is safely callable
/// from every coordinate-changing arm. Returns the number of each family
/// superseded so the caller can enforce exact-shape (own + supersessions ==
/// total). All three are bound to the same producing transition.
pub(in crate::chat_protocol::state_machine::executor) async fn write_prior_bound_supersessions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    effects: &TransitionEffects,
    transition_id: Uuid,
    applied_at: DateTime<Utc>,
) -> Result<PriorBoundWriteReceipt, ExecutorError> {
    let mut counts = FamilyCounts::default();
    let mut keys: BTreeSet<([u8; 16], [u8; 32])> = BTreeSet::new();
    // Consume the exact locked package authority while its paired durable
    // request/reservation rows are still in the Open/Active pre-state.
    // Terminalizing those rows first would force this writer to fall back
    // to a semantic `(ref,status)` edge and discard the guard.
    for edge in effects.package_transitions() {
        if edge.from == PackageStatus::Reserved
            && matches!(edge.to, PackageStatus::Available | PackageStatus::Expired)
        {
            let mut matches = effects.recovery_package_cas().iter().filter(|binding| {
                binding.request_id == edge.request_id
                    && binding.key_package_ref == edge.key_package_ref
                    && binding.expected_status == edge.from
                    && binding.successor_status == edge.to
            });
            let binding = matches.next().ok_or(ExecutorError::InconsistentPlan(
                "prior-bound package edge has no exact locked authority",
            ))?;
            if matches.next().is_some() {
                return Err(ExecutorError::InconsistentPlan(
                    "prior-bound package edge has duplicate locked authority",
                ));
            }
            let target_did = device_did(&binding.target)?;
            let target_key_id = URL_SAFE_NO_PAD.encode(binding.target_key_id);
            transition::release_reserved_recovery_package(
                transaction,
                &transition::ReservedRecoveryPackageReleaseCas {
                    transaction_id: &binding.transaction_id,
                    conversation_id: Uuid::from_bytes(binding.conversation_id),
                    request_id: Uuid::from_bytes(binding.request_id),
                    target_did: &target_did,
                    target_device_id: device_uuid(&binding.target),
                    target_key_id: &target_key_id,
                    target_auth_generation: checked_i64(binding.target_auth_generation)?,
                    generation: checked_i64(binding.bound_coordinate.generation())?,
                    state_version: checked_i64(binding.bound_coordinate.state_version())?,
                    group_id: binding.bound_coordinate.group_id(),
                    epoch: checked_i64(binding.bound_coordinate.epoch())?,
                    group_context_hash: binding.bound_coordinate.group_context_hash(),
                    confirmation_tag: binding.bound_coordinate.confirmation_tag(),
                    key_package_ref: &binding.key_package_ref,
                    wrapper_sha256: &binding.key_package_wrapper_sha256,
                    package_not_after: server_instant(binding.package_not_after)?,
                    claimed_at: server_instant(binding.claimed_at)?,
                    locked_row_digest: &binding.locked_row_digest,
                    authority_digest: &binding.authority_digest,
                    successor_status: match binding.successor_status {
                        PackageStatus::Available => RepoPackageStatus::Available,
                        PackageStatus::Expired => RepoPackageStatus::Expired,
                        _ => {
                            return Err(ExecutorError::InconsistentPlan(
                                "prior-bound package has an illegal terminal successor",
                            ))
                        }
                    },
                    terminal_at: (binding.successor_status == PackageStatus::Expired)
                        .then_some(server_instant(binding.package_not_after)?),
                },
            )
            .await?;
            counts.packages += 1;
            keys.insert((edge.request_id, edge.key_package_ref));
        }
    }
    for change in effects.recovery_request_changes() {
        if let (Some(before), Some(after)) = (change.before(), change.after()) {
            if before.status() == RecoveryRequestStatus::Open {
                let termination = match after.status() {
                    RecoveryRequestStatus::Superseded => {
                        Some(LeafRecoveryTermination::SupersededByTransition {
                            terminal_transition_id: transition_id,
                            terminal_at: applied_at,
                        })
                    }
                    RecoveryRequestStatus::Expired => Some(LeafRecoveryTermination::Expired {
                        terminal_at: server_instant(*after.expires_at())?,
                    }),
                    _ => None,
                };
                if let Some(termination) = termination {
                    transition::terminalize_leaf_recovery_request(
                        transaction,
                        Uuid::from_bytes(*after.request_id()),
                        &termination,
                    )
                    .await?;
                    counts.requests += 1;
                }
            }
        }
    }
    for change in effects.reservation_changes() {
        if let (Some(before), Some(after)) = (change.before(), change.after()) {
            if before.status() == ReservationStatus::Active {
                let termination = match after.status() {
                    ReservationStatus::Released => {
                        Some(ReservationTermination::ReleasedByTransition {
                            terminal_transition_id: transition_id,
                            terminal_at: applied_at,
                        })
                    }
                    ReservationStatus::Expired => Some(ReservationTermination::Expired {
                        terminal_at: server_instant(after.expires_at)?,
                    }),
                    _ => None,
                };
                if let Some(termination) = termination {
                    transition::terminalize_reservation(
                        transaction,
                        Uuid::from_bytes(after.request_id),
                        &termination,
                    )
                    .await?;
                    counts.reservations += 1;
                }
            }
        }
    }
    Ok(PriorBoundWriteReceipt::new(counts, keys))
}

/// Durably stale each prior-coordinate PENDING reset/leave request the plan
/// retired. `resolve_prior_bound_work` marks a `Pending` reset request `Stale`
/// and a `Pending` leave request `Stale` when a coordinate-advancing transition
/// supersedes the coordinate they were bound to; this consumes exactly those
/// `(Pending -> Stale)` deltas. A reset/leave delta of any OTHER shape (the
/// arm's OWN `Pending -> Consumed` reset-activation edge, or `Pending ->
/// Fulfilled` leave-fulfillment edge) is SKIPPED here and handled by the arm,
/// with `reconcile_coordinate_change_families` proving `own + staled == total`
/// per family so nothing is silently dropped.
///
/// The leave-request `stale` terminal edge binds the STALING transition's own
/// request digest (`assert_leave_request_mapping` requires
/// `terminal_request_digest == transition.request_digest`). Per ADR-019
/// Erratum 01 the terminal transition may be of ANY kind, INCLUDING
/// `leaveCommit`/`leavePolicy`: the coordinate-binding invariant governs, so a
/// coordinate-advancing leave-kind transition stales OTHER members'
/// predecessor-bound pending leave requests (the `fulfilled`-not-`stale`
/// distinction for the request the transition fulfills is enforced here in the
/// executor, not the DDL). The reset-request `stale` edge needs only the
/// transition id + instant. Returns the per-family staled counts for the
/// caller's reconciliation.
pub(in crate::chat_protocol::state_machine::executor) async fn write_prior_bound_staling(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    effects: &TransitionEffects,
    transition_id: Uuid,
    staling_request_digest: &[u8],
    applied_at: DateTime<Utc>,
) -> Result<FamilyCounts, ExecutorError> {
    let mut counts = FamilyCounts::default();
    for change in effects.reset_request_changes() {
        if let (Some(before), Some(after)) = (change.before(), change.after()) {
            if before.status() == ResetRequestStatus::Pending {
                let termination = match after.status() {
                    ResetRequestStatus::Stale => Some(ResetRequestTermination::Stale {
                        terminal_transition_id: transition_id,
                        terminal_at: applied_at,
                    }),
                    ResetRequestStatus::Expired => Some(ResetRequestTermination::Expired {
                        terminal_at: server_instant(after.expires_at)?,
                    }),
                    _ => None,
                };
                if let Some(termination) = termination {
                    transition::terminalize_reset_request(
                        transaction,
                        Uuid::from_bytes(after.request_id),
                        &termination,
                    )
                    .await?;
                    counts.reset_requests += 1;
                }
            }
        }
    }
    for change in effects.leave_request_changes() {
        if let (Some(before), Some(after)) = (change.before(), change.after()) {
            if before.status() == LeaveRequestStatus::Pending {
                let termination = match after.status() {
                    LeaveRequestStatus::Stale => Some(LeaveRequestTermination::Stale {
                        terminal_request_digest: staling_request_digest.to_vec(),
                        terminal_transition_id: transition_id,
                        terminal_at: applied_at,
                    }),
                    LeaveRequestStatus::Expired => Some(LeaveRequestTermination::Expired {
                        terminal_at: server_instant(after.expires_at)?,
                    }),
                    _ => None,
                };
                if let Some(termination) = termination {
                    transition::terminalize_leave_request(
                        transaction,
                        Uuid::from_bytes(after.request_id),
                        &termination,
                    )
                    .await?;
                    counts.leave_requests += 1;
                }
            }
        }
    }
    Ok(counts)
}

/// Durably record the OBSERVED expiry of every past-due `pending` leave
/// request an expire-first planner swept on the coordinate-PRESERVING request
/// path (`expire_due_leave_requests`).
///
/// This writes the identical terminal shape `write_prior_bound_staling` writes
/// for the identical `Pending -> Expired` delta, and for the identical reason:
/// status `expired`, NULL `terminal_request_digest`, NULL
/// `terminal_transition_id`, and `terminal_at` = the request's OWN `expires_at`
/// — the only combination `leave_requests_terminal_shape_check` accepts for
/// `expired`. Nothing about the observing actor is bound, so the row records
/// that consent lapsed, never that anyone withdrew or superseded it.
///
/// Any delta that is not exactly `Pending -> Expired` is skipped here; the
/// caller has already proven that the ONLY shapes present are its own opening
/// plus these expiries, and cross-checks this function's return against that
/// count, so a skipped delta can never become a silent drop.
pub(in crate::chat_protocol::state_machine::executor) async fn write_observed_leave_expiries(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    effects: &TransitionEffects,
) -> Result<usize, ExecutorError> {
    let mut written = 0;
    for change in effects.leave_request_changes() {
        let (Some(before), Some(after)) = (change.before(), change.after()) else {
            continue;
        };
        if before.status() != LeaveRequestStatus::Pending
            || after.status() != LeaveRequestStatus::Expired
        {
            continue;
        }
        transition::terminalize_leave_request(
            transaction,
            Uuid::from_bytes(after.request_id),
            &LeaveRequestTermination::Expired {
                terminal_at: server_instant(after.expires_at)?,
            },
        )
        .await?;
        written += 1;
    }
    Ok(written)
}

/// The per-family count of deltas a coordinate-changing arm actually
/// consumed. Used for both the applied SUPERSESSIONS (what
/// `write_prior_bound_supersessions` / `write_welcome_supersessions` wrote) and
/// the arm's OWN edges, so the reconciliation `own + superseded == total` holds
/// per family (see `reconcile_coordinate_change_families`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::chat_protocol::state_machine::executor) struct FamilyCounts {
    pub(in crate::chat_protocol::state_machine::executor) requests: usize,
    pub(in crate::chat_protocol::state_machine::executor) reservations: usize,
    pub(in crate::chat_protocol::state_machine::executor) packages: usize,
    pub(in crate::chat_protocol::state_machine::executor) welcomes: usize,
    pub(in crate::chat_protocol::state_machine::executor) reset_requests: usize,
    pub(in crate::chat_protocol::state_machine::executor) leave_requests: usize,
}

/// The silent-drop guard for every coordinate-changing arm (fulfillment,
/// generic commit, leave fulfillment). `write_prior_bound_supersessions` and
/// `write_welcome_supersessions` SKIP any delta that is not their exact
/// supersession shape; an arm's own-edge handling consumes exactly its own
/// deltas. So a delta that is NEITHER the arm's own shape NOR a valid
/// supersession (e.g. an `Open->Expired` request, a wrong-direction package
/// edge, a `Pending->Expired` welcome) would be neither applied nor rejected —
/// a silent drop. This reconciliation makes that impossible: for EVERY family,
/// `own + superseded` MUST equal the plan's total delta count, else the whole
/// transaction is a hard `InconsistentPlan` (rolled back by the caller). A
/// future planner that emits a shape neither path handles surfaces here, never
/// as a lost write.
pub(in crate::chat_protocol::state_machine::executor) fn reconcile_coordinate_change_families(
    effects: &TransitionEffects,
    own: &FamilyCounts,
    superseded: &FamilyCounts,
) -> Result<(), ExecutorError> {
    if own.requests + superseded.requests != effects.recovery_request_changes().len() {
        return Err(ExecutorError::InconsistentPlan(
            "recovery request delta neither applied as own nor superseded (silent-drop guard)",
        ));
    }
    if own.reservations + superseded.reservations != effects.reservation_changes().len() {
        return Err(ExecutorError::InconsistentPlan(
            "reservation delta neither applied as own nor released (silent-drop guard)",
        ));
    }
    if own.packages + superseded.packages != effects.package_transitions().len() {
        return Err(ExecutorError::InconsistentPlan(
            "package edge neither applied as own nor reactivated (silent-drop guard)",
        ));
    }
    if own.welcomes + superseded.welcomes != effects.welcome_changes().len() {
        return Err(ExecutorError::InconsistentPlan(
            "welcome delta neither applied as own nor superseded (silent-drop guard)",
        ));
    }
    if own.reset_requests + superseded.reset_requests != effects.reset_request_changes().len() {
        return Err(ExecutorError::InconsistentPlan(
            "reset request delta neither applied as own nor staled (silent-drop guard)",
        ));
    }
    if own.leave_requests + superseded.leave_requests != effects.leave_request_changes().len() {
        return Err(ExecutorError::InconsistentPlan(
            "leave request delta neither applied as own nor staled (silent-drop guard)",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub(in crate::chat_protocol::state_machine::executor) enum WelcomeSupersessionCause {
    Transition { terminal_transition_id: Uuid },
    Revocation { terminal_revocation_id: Uuid },
}

/// Supersede each prior-coordinate pending Welcome the plan retired: append its
/// `welcomeDisposition` event and terminalize the delivery as `superseded`,
/// bound to that event and to the exact transition/revocation already held by
/// the executor authority. A coordinate-changing commit whose prior carried a
/// pending Welcome (e.g. an epoch commit after a leaf-recovery fulfillment)
/// carries these `welcome_changes` `(Pending -> Superseded)`; consuming them
/// keeps the durable delivery in sync with the state machine.
///
/// Returns the COUNT of welcomes actually superseded so the caller can
/// reconcile `own + superseded == total` (`reconcile_coordinate_change_families`)
/// — a `Pending->Expired` or other non-supersession welcome delta is skipped
/// here and must be caught by that reconciliation, never silently dropped.
pub(in crate::chat_protocol::state_machine::executor) async fn write_welcome_supersessions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    effects: &TransitionEffects,
    cause: WelcomeSupersessionCause,
) -> Result<usize, ExecutorError> {
    write_welcome_supersessions_with_cursor(transaction, ctx, effects, cause, None).await
}

pub(in crate::chat_protocol::state_machine::executor) async fn write_welcome_supersessions_with_cursor(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    effects: &TransitionEffects,
    cause: WelcomeSupersessionCause,
    mut event_cursor: Option<&mut EventChainCursor>,
) -> Result<usize, ExecutorError> {
    let mut superseded = 0usize;
    for change in effects.welcome_changes() {
        // Only prior-bound supersessions here; a fulfillment's OWN new welcome
        // (None->Some Pending) is handled by its arm and skipped.
        let after = match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == WelcomeStatus::Pending
                    && matches!(
                        after.status(),
                        WelcomeStatus::Superseded | WelcomeStatus::Expired
                    ) =>
            {
                after
            }
            _ => continue,
        };
        let welcome_id = Uuid::from_bytes(*after.welcome_id());
        let disposition = ctx
            .welcome_dispositions
            .iter()
            .find(|input| input.welcome_id == welcome_id)
            .ok_or(ExecutorError::MissingContext(
                "welcome disposition event for a superseded welcome",
            ))?;
        if after.status() == WelcomeStatus::Expired {
            // A DUE EXPIRY the transition merely OBSERVES. Every instant this
            // writes is the welcome's own `expires_at`, never `applied_at`:
            // `assert_welcome_disposition_cas` pins `event.created_at =
            // delivery.terminal_at`, and `assert_recovery_work_integrity` pins
            // `recovery_work_items.created_at = disposition.terminal_at`. This is
            // exactly the shape the dedicated `apply_welcome_expiry` arm writes.
            let terminal_at = server_instant(after.expires_at())?;
            let recovery_work_id =
                disposition
                    .recovery_work_id
                    .ok_or(ExecutorError::MissingContext(
                        "recovery work id for a prior-bound Welcome expiry",
                    ))?;
            let position = append_one_event_at_with_cursor(
                transaction,
                ctx,
                &disposition.event,
                terminal_at,
                event_cursor.as_deref_mut(),
            )
            .await?;
            delivery::terminalize_prior_bound_welcome_expiry(
                transaction,
                after,
                terminal_at,
                position,
            )
            .await?;
            // The `welcomeExpired` re-add work the recipient is owed. Without it
            // the deferred `assert_recovery_work_integrity` rejects the WHOLE
            // transition (`winner_kind='expired'` requires exactly one item), and
            // the invitee is never re-invited.
            delivery::insert_recovery_work_item(
                transaction,
                &delivery::NewRecoveryWorkItem {
                    recovery_work_id,
                    conversation_id: Uuid::from_bytes(*after.coordinate().conversation_id()),
                    recipient_did: device_did(after.recipient())?,
                    recipient_device_id: device_uuid(after.recipient()),
                    source_kind: delivery::RecoveryWorkSourceKind::WelcomeExpired,
                    source_id: welcome_id,
                    generation: checked_i64(after.coordinate().generation())?,
                    state_version: checked_i64(after.coordinate().state_version())?,
                    created_at: terminal_at,
                },
            )
            .await?;
        } else {
            if disposition.recovery_work_id.is_some() {
                // Only a due expiry creates recovery work; a supersession that
                // carried one would be rejected by the same deferred trigger
                // ('non-recovery Welcome disposition has recovery work').
                return Err(ExecutorError::InconsistentPlan(
                    "prior-bound Welcome supersession must carry no recovery work id",
                ));
            }
            let position = append_one_event_with_cursor(
                transaction,
                ctx,
                &disposition.event,
                event_cursor.as_deref_mut(),
            )
            .await?;
            let terminal_disposition = match cause {
                WelcomeSupersessionCause::Transition {
                    terminal_transition_id,
                } => WelcomeDisposition::SupersededByTransition {
                    terminal_transition_id,
                },
                WelcomeSupersessionCause::Revocation {
                    terminal_revocation_id,
                } => WelcomeDisposition::SupersededByRevocation {
                    terminal_revocation_id,
                },
            };
            delivery::terminalize_welcome_delivery_for_supersession(
                transaction,
                welcome_id,
                &terminal_disposition,
                ctx.applied_at,
                position,
            )
            .await?;
        }
        superseded += 1;
    }
    Ok(superseded)
}

/// Append one event with its audience + outbox, returning its position.
pub(in crate::chat_protocol::state_machine::executor) async fn append_one_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    event: &EventFanout,
) -> Result<i64, ExecutorError> {
    append_one_event_with_cursor(transaction, ctx, event, None).await
}

pub(in crate::chat_protocol::state_machine::executor) async fn append_one_event_with_cursor(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    event: &EventFanout,
    event_cursor: Option<&mut EventChainCursor>,
) -> Result<i64, ExecutorError> {
    append_one_event_at_with_cursor(transaction, ctx, event, ctx.applied_at, event_cursor).await
}

/// `append_one_event_with_cursor` with an explicit `created_at` for the event
/// row and its outbox work.
///
/// Almost every event is stamped `ctx.applied_at`. The exception is a Welcome
/// terminal disposition: `assert_welcome_disposition_cas` requires
/// `event.created_at = delivery.terminal_at`, and a due EXPIRY's terminal
/// instant is the welcome's own `expires_at`, which is strictly before
/// `applied_at` whenever the expiry is observed by a later transition. The
/// dedicated `apply_welcome_expiry` arm already appends at `terminal_at`
/// directly; this is the same rule for the shared prior-bound writer.
pub(in crate::chat_protocol::state_machine::executor) async fn append_one_event_at_with_cursor(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    event: &EventFanout,
    created_at: DateTime<Utc>,
    mut event_cursor: Option<&mut EventChainCursor>,
) -> Result<i64, ExecutorError> {
    // The symbolic schedule is a prewrite contract. Resolve and validate
    // the exact audience before allocating the durable event position.
    let recipients = match event_cursor.as_deref_mut() {
        Some(cursor) => cursor
            .begin_fanout(event)
            .map_err(ExecutorError::EventChain)?,
        None => event
            .recipients
            .iter()
            .map(|(device, kind, predecessor)| {
                Ok(EventRecipient {
                    user_did: device_did(device)?,
                    device_id: device_uuid(device),
                    entitlement_kind: *kind,
                    audience_predecessor_position: *predecessor,
                })
            })
            .collect::<Result<Vec<_>, ExecutorError>>()?,
    };
    let position = delivery::append_event(
        transaction,
        &NewEvent {
            event_id: event.event_id,
            event_kind: event.event_kind,
            payload_bytes: event.payload_bytes.clone(),
            created_at,
            protocol_instance_id: ctx.protocol_instance_id,
        },
    )
    .await?;
    delivery::insert_event_recipients(transaction, position, &recipients).await?;
    for (outbox_id, work_kind) in &event.outbox {
        delivery::enqueue_outbox(transaction, *outbox_id, position, *work_kind, created_at).await?;
    }
    if let Some(cursor) = event_cursor {
        cursor
            .complete_event(event.event_id, position)
            .map_err(ExecutorError::EventChain)?;
    }
    Ok(position)
}

pub(in crate::chat_protocol::state_machine::executor) async fn write_events(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    historical_write_authority: Option<&HistoricalExecutionWriteAuthority>,
) -> Result<Vec<i64>, ExecutorError> {
    write_events_with_cursor(transaction, ctx, None, historical_write_authority).await
}

pub(in crate::chat_protocol::state_machine::executor) async fn write_events_with_cursor(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    mut event_cursor: Option<&mut EventChainCursor>,
    historical_write_authority: Option<&HistoricalExecutionWriteAuthority>,
) -> Result<Vec<i64>, ExecutorError> {
    if let Some(historical) = historical_write_authority {
        let entry = ctx.entry();
        if !historical.matches_context(
            entry.entry_id,
            entry.entry_kind.as_str(),
            &entry.accepted_payload_sha256,
            &entry.outer_entry_fingerprint,
        ) {
            return Err(ExecutorError::MissingContext(
                "historical write authority entry context mismatch",
            ));
        }
        return Ok(Vec::new());
    }

    let mut positions = Vec::with_capacity(ctx.events.len());
    for event in &ctx.events {
        let position =
            append_one_event_with_cursor(transaction, ctx, event, event_cursor.as_deref_mut())
                .await?;
        positions.push(position);
    }
    Ok(positions)
}
