// Transaction-bound facade for Welcome acknowledgement/rejection.
//
// Lock order is inherited from the shared business prelude: operation,
// identity scope, conversation aggregate, exact Welcome delivery. No handler
// bytes or post-head identity lookup crosses this boundary.

use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use super::{
    core::{
        hydrate_locked_conversation_state, lock_welcome_terminal, ConversationStateHydrationError,
        LockedWelcomeTerminal, WelcomeLockError,
    },
    execution_context::{
        apply_prepared_welcome_terminal_execution, prepare_welcome_terminal_execution,
        ExecutionContextHydrationError,
    },
    prelude::{
        OperationCompletionGuard, PreludeError, PreparedBusinessPrelude,
        ScopeBoundBusinessAuthority, WelcomeOperationEndpoint,
    },
};
use crate::chat_protocol::{
    state_machine::{
        AppliedTransition, ConversationPersistencePlan, DurableSignedRequestEnvelope,
        ExecutorError, HydrationAuthority, StateMachineError, WelcomeTerminalPlan,
    },
    transcript::{CanonicalValueRef, VerifiedMutationProjection, VerifiedSignedMutation},
    validation::TrustedRequestInstant,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WelcomeEndpoint {
    Acknowledge,
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WelcomeTerminalClass {
    PendingNotDue,
    PendingDue,
    Acknowledged,
    Rejected,
    Expired,
    SupersededByTransition,
    SupersededByRevocation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WelcomeTerminalDecision {
    PrepareAcknowledgement,
    PrepareRejection,
    PrepareExpiry,
    ExactAcknowledgementReplay,
    ExactRejectionReplay,
    AcknowledgementConflict,
    RejectionConflict,
    WelcomeExpired,
    SupersededByTransition,
    SupersededByRevocation,
}

pub(crate) fn classify_welcome_terminal(
    endpoint: WelcomeEndpoint,
    classification: WelcomeTerminalClass,
    exact_replay: bool,
) -> WelcomeTerminalDecision {
    match classification {
        WelcomeTerminalClass::PendingNotDue => match endpoint {
            WelcomeEndpoint::Acknowledge => WelcomeTerminalDecision::PrepareAcknowledgement,
            WelcomeEndpoint::Reject => WelcomeTerminalDecision::PrepareRejection,
        },
        WelcomeTerminalClass::PendingDue => WelcomeTerminalDecision::PrepareExpiry,
        WelcomeTerminalClass::Acknowledged
            if endpoint == WelcomeEndpoint::Acknowledge && exact_replay =>
        {
            WelcomeTerminalDecision::ExactAcknowledgementReplay
        }
        WelcomeTerminalClass::Rejected if endpoint == WelcomeEndpoint::Reject && exact_replay => {
            WelcomeTerminalDecision::ExactRejectionReplay
        }
        WelcomeTerminalClass::Acknowledged => WelcomeTerminalDecision::AcknowledgementConflict,
        WelcomeTerminalClass::Rejected => WelcomeTerminalDecision::RejectionConflict,
        WelcomeTerminalClass::Expired => WelcomeTerminalDecision::WelcomeExpired,
        WelcomeTerminalClass::SupersededByTransition => {
            WelcomeTerminalDecision::SupersededByTransition
        }
        WelcomeTerminalClass::SupersededByRevocation => {
            WelcomeTerminalDecision::SupersededByRevocation
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WelcomeCanonicalMaterial {
    Acknowledged {
        welcome_id: Uuid,
    },
    Rejected {
        welcome_id: Uuid,
    },
    ExactReplay {
        welcome_id: Uuid,
        terminal: WelcomeTerminalClass,
    },
    Conflict {
        welcome_id: Uuid,
        terminal: WelcomeTerminalClass,
    },
    WelcomeExpired {
        welcome_id: Uuid,
        expired_at: DateTime<Utc>,
    },
    WelcomeSuperseded {
        welcome_id: Uuid,
        cause: WelcomeSupersessionCause,
    },
    WelcomeNotFound {
        welcome_id: Uuid,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WelcomeSupersessionCause {
    Transition(Uuid),
    DeviceRevocation(Uuid),
}

pub(crate) struct WelcomeCompletion {
    scope_authority: ScopeBoundBusinessAuthority,
    completion: OperationCompletionGuard,
}

impl WelcomeCompletion {
    pub(crate) fn into_parts(self) -> (ScopeBoundBusinessAuthority, OperationCompletionGuard) {
        (self.scope_authority, self.completion)
    }
}

pub(crate) struct PreparedWelcomeMutation {
    plan: ConversationPersistencePlan,
    completion: WelcomeCompletion,
    material: WelcomeCanonicalMaterial,
}

impl PreparedWelcomeMutation {
    pub(crate) fn material(&self) -> &WelcomeCanonicalMaterial {
        &self.material
    }

    pub(crate) async fn apply(
        self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<AppliedWelcomeMutation, WelcomeTerminalFacadeError> {
        let Self {
            plan,
            completion,
            material,
        } = self;
        let prepared = prepare_welcome_terminal_execution(transaction, &plan).await?;
        let applied = apply_prepared_welcome_terminal_execution(prepared).await?;
        Ok(AppliedWelcomeMutation {
            applied,
            completion,
            material,
        })
    }
}

pub(crate) struct AppliedWelcomeMutation {
    pub(crate) applied: AppliedTransition,
    pub(crate) completion: WelcomeCompletion,
    pub(crate) material: WelcomeCanonicalMaterial,
}

pub(crate) enum WelcomeTerminalTransactionOutcome {
    Prepared(PreparedWelcomeMutation),
    Classified {
        completion: WelcomeCompletion,
        material: WelcomeCanonicalMaterial,
    },
}

#[derive(Debug, Error)]
pub(crate) enum WelcomeTerminalFacadeError {
    #[error("Welcome request body is out of domain")]
    InvalidRequest,
    #[error("Welcome operation claim is invalid: {0}")]
    Prelude(#[from] PreludeError),
    #[error("Welcome aggregate hydration failed: {0}")]
    Aggregate(#[from] ConversationStateHydrationError),
    #[error("Welcome lock failed: {0}")]
    WelcomeLock(#[from] WelcomeLockError),
    #[error("Welcome planning failed: {0}")]
    StateMachine(#[from] StateMachineError),
    #[error("Welcome execution hydration failed: {0}")]
    ExecutionHydration(#[from] ExecutionContextHydrationError),
    #[error("Welcome execution failed: {0:?}")]
    Execution(ExecutorError),
}

impl From<ExecutorError> for WelcomeTerminalFacadeError {
    fn from(value: ExecutorError) -> Self {
        Self::Execution(value)
    }
}

pub(crate) async fn prepare_welcome_terminal(
    transaction: &mut Transaction<'_, Postgres>,
    prelude: PreparedBusinessPrelude,
    mutation: VerifiedSignedMutation,
    trusted_instant: &TrustedRequestInstant,
) -> Result<WelcomeTerminalTransactionOutcome, WelcomeTerminalFacadeError> {
    let parsed = parse_welcome_request(&mutation)?;
    let prelude = prelude.verify_welcome_operation(
        parsed.operation_endpoint,
        parsed.operation_id,
        &mutation,
    )?;
    if prelude.scope_authority().trusted_instant() != trusted_instant.datetime() {
        return Err(WelcomeTerminalFacadeError::InvalidRequest);
    }

    let aggregate = hydrate_locked_conversation_state(
        transaction,
        parsed.conversation_id,
        trusted_instant.datetime(),
    )
    .await?;
    let classification =
        match lock_welcome_terminal(transaction, &aggregate, parsed.welcome_id).await {
            Ok(classification) => classification,
            Err(WelcomeLockError::Missing) => {
                let (scope_authority, completion) = prelude.into_execution_parts();
                return Ok(WelcomeTerminalTransactionOutcome::Classified {
                    completion: WelcomeCompletion {
                        scope_authority,
                        completion,
                    },
                    material: WelcomeCanonicalMaterial::WelcomeNotFound {
                        welcome_id: parsed.welcome_id,
                    },
                });
            }
            Err(error) => return Err(error.into()),
        };

    let snapshot = welcome_terminal_snapshot(&classification);
    let hydration = HydrationAuthority::from_locked_conversation(&aggregate)?;
    let registration =
        hydration.locked_registration_from_scope_authority(prelude.scope_authority())?;
    let envelope =
        DurableSignedRequestEnvelope::new(*parsed.conversation_id.as_bytes(), trusted_instant)?;
    let composed = hydration.compose_welcome_terminal(
        &aggregate,
        envelope,
        mutation,
        registration,
        classification,
    )?;
    let (scope_authority, completion) = prelude.into_execution_parts();
    let completion = WelcomeCompletion {
        scope_authority,
        completion,
    };

    match composed {
        WelcomeTerminalPlan::Planned(plan) => {
            let material = match parsed.endpoint {
                WelcomeEndpoint::Acknowledge => WelcomeCanonicalMaterial::Acknowledged {
                    welcome_id: parsed.welcome_id,
                },
                WelcomeEndpoint::Reject => WelcomeCanonicalMaterial::Rejected {
                    welcome_id: parsed.welcome_id,
                },
            };
            Ok(WelcomeTerminalTransactionOutcome::Prepared(
                PreparedWelcomeMutation {
                    plan: plan.into_persistence_plan()?,
                    completion,
                    material,
                },
            ))
        }
        WelcomeTerminalPlan::DueExpiry(plan) => {
            let expired_at = snapshot
                .terminal_at
                .ok_or(WelcomeTerminalFacadeError::InvalidRequest)?;
            Ok(WelcomeTerminalTransactionOutcome::Prepared(
                PreparedWelcomeMutation {
                    plan: plan.into_persistence_plan()?,
                    completion,
                    material: WelcomeCanonicalMaterial::WelcomeExpired {
                        welcome_id: parsed.welcome_id,
                        expired_at,
                    },
                },
            ))
        }
        WelcomeTerminalPlan::Terminal { exact_replay, .. } => {
            let decision =
                classify_welcome_terminal(parsed.endpoint, snapshot.classification, exact_replay);
            let material = terminal_material(parsed.welcome_id, snapshot, decision)?;
            Ok(WelcomeTerminalTransactionOutcome::Classified {
                completion,
                material,
            })
        }
    }
}

struct ParsedWelcomeRequest {
    endpoint: WelcomeEndpoint,
    operation_endpoint: WelcomeOperationEndpoint,
    operation_id: Uuid,
    welcome_id: Uuid,
    conversation_id: Uuid,
}

fn parse_welcome_request(
    mutation: &VerifiedSignedMutation,
) -> Result<ParsedWelcomeRequest, WelcomeTerminalFacadeError> {
    let (endpoint, operation_endpoint, body) = match mutation.projection() {
        VerifiedMutationProjection::WelcomeAcknowledgement(value) => (
            WelcomeEndpoint::Acknowledge,
            WelcomeOperationEndpoint::AcknowledgeWelcome,
            value.body(),
        ),
        VerifiedMutationProjection::WelcomeRejection(value) => (
            WelcomeEndpoint::Reject,
            WelcomeOperationEndpoint::RejectWelcome,
            value.body(),
        ),
        _ => return Err(WelcomeTerminalFacadeError::InvalidRequest),
    };
    let operation_id = body_uuid(&body, "idempotencyKey")?;
    let welcome_id = body_uuid(&body, "welcomeId")?;
    let coordinates = match body.get("coordinates") {
        Some(CanonicalValueRef::Object(value)) => value,
        _ => return Err(WelcomeTerminalFacadeError::InvalidRequest),
    };
    let conversation_id = body_uuid(&coordinates, "conversationId")?;
    Ok(ParsedWelcomeRequest {
        endpoint,
        operation_endpoint,
        operation_id,
        welcome_id,
        conversation_id,
    })
}

fn body_uuid(
    body: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
    field: &str,
) -> Result<Uuid, WelcomeTerminalFacadeError> {
    match body.get(field) {
        Some(CanonicalValueRef::Uuid(value)) => Ok(Uuid::from_bytes(*value.as_bytes())),
        _ => Err(WelcomeTerminalFacadeError::InvalidRequest),
    }
}

struct WelcomeTerminalSnapshot {
    classification: WelcomeTerminalClass,
    terminal_at: Option<DateTime<Utc>>,
    cause: Option<WelcomeSupersessionCause>,
}

fn welcome_terminal_snapshot(value: &LockedWelcomeTerminal) -> WelcomeTerminalSnapshot {
    match value {
        LockedWelcomeTerminal::PendingNotDue(_) => WelcomeTerminalSnapshot {
            classification: WelcomeTerminalClass::PendingNotDue,
            terminal_at: None,
            cause: None,
        },
        LockedWelcomeTerminal::PendingDue(guard) => WelcomeTerminalSnapshot {
            classification: WelcomeTerminalClass::PendingDue,
            terminal_at: Some(guard.expires_at()),
            cause: None,
        },
        LockedWelcomeTerminal::Acknowledged { terminal_at, .. } => WelcomeTerminalSnapshot {
            classification: WelcomeTerminalClass::Acknowledged,
            terminal_at: Some(*terminal_at),
            cause: None,
        },
        LockedWelcomeTerminal::Rejected { terminal_at, .. } => WelcomeTerminalSnapshot {
            classification: WelcomeTerminalClass::Rejected,
            terminal_at: Some(*terminal_at),
            cause: None,
        },
        LockedWelcomeTerminal::Expired { terminal_at, .. } => WelcomeTerminalSnapshot {
            classification: WelcomeTerminalClass::Expired,
            terminal_at: Some(*terminal_at),
            cause: None,
        },
        LockedWelcomeTerminal::SupersededByTransition {
            transition_id,
            terminal_at,
            ..
        } => WelcomeTerminalSnapshot {
            classification: WelcomeTerminalClass::SupersededByTransition,
            terminal_at: Some(*terminal_at),
            cause: Some(WelcomeSupersessionCause::Transition(*transition_id)),
        },
        LockedWelcomeTerminal::SupersededByRevocation {
            revocation_id,
            terminal_at,
            ..
        } => WelcomeTerminalSnapshot {
            classification: WelcomeTerminalClass::SupersededByRevocation,
            terminal_at: Some(*terminal_at),
            cause: Some(WelcomeSupersessionCause::DeviceRevocation(*revocation_id)),
        },
    }
}

fn terminal_material(
    welcome_id: Uuid,
    snapshot: WelcomeTerminalSnapshot,
    decision: WelcomeTerminalDecision,
) -> Result<WelcomeCanonicalMaterial, WelcomeTerminalFacadeError> {
    Ok(match decision {
        WelcomeTerminalDecision::ExactAcknowledgementReplay
        | WelcomeTerminalDecision::ExactRejectionReplay => WelcomeCanonicalMaterial::ExactReplay {
            welcome_id,
            terminal: snapshot.classification,
        },
        WelcomeTerminalDecision::AcknowledgementConflict
        | WelcomeTerminalDecision::RejectionConflict => WelcomeCanonicalMaterial::Conflict {
            welcome_id,
            terminal: snapshot.classification,
        },
        WelcomeTerminalDecision::WelcomeExpired => WelcomeCanonicalMaterial::WelcomeExpired {
            welcome_id,
            expired_at: snapshot
                .terminal_at
                .ok_or(WelcomeTerminalFacadeError::InvalidRequest)?,
        },
        WelcomeTerminalDecision::SupersededByTransition
        | WelcomeTerminalDecision::SupersededByRevocation => {
            WelcomeCanonicalMaterial::WelcomeSuperseded {
                welcome_id,
                cause: snapshot
                    .cause
                    .ok_or(WelcomeTerminalFacadeError::InvalidRequest)?,
            }
        }
        WelcomeTerminalDecision::PrepareAcknowledgement
        | WelcomeTerminalDecision::PrepareRejection
        | WelcomeTerminalDecision::PrepareExpiry => {
            return Err(WelcomeTerminalFacadeError::InvalidRequest)
        }
    })
}
