use crate::chat_protocol::transcript::SignedMutationKind;

/// Closed table over all legacy signed mutation classes. A bootstrap creator is
/// constrained just like the pending recipient; an active sender leaf is never
/// evidence that the recipient has consented.
pub(crate) fn allowed_while_pending(kind: SignedMutationKind) -> bool {
    use SignedMutationKind::*;
    match kind {
        ConversationClose | WelcomeAcknowledgement | WelcomeRejection => true,
        DeviceEnrollment
        | KeyPackageReplenishment
        | DeviceRevocation => true,
        DirectRequestPublication
        | DirectRequestAcceptance
        | BlobUploadPreparation
        | BlobDeletion
        | Creation
        | CommitTransition
        | PolicyTransition
        | ParticipantAcceptance
        | ApplicationSend
        | Typing
        | MetadataTransition
        | ResetRequest
        | ResetActivation
        | LeafRecoveryRequest
        | LeafRecoveryCancellation
        | LeafRecoveryFulfillment
        | LeaveRequest
        | ZeroLeafLeave
        | LeaveCancellation
        | LeaveCommitFulfillment => false,
    }
}
