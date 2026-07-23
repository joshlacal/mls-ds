//! Closed error vocabulary for the clean chat protocol.
//!
//! Protocol-facing failures are represented by [`ChatProtocolErrorCode`].
//! Storage and invariant failures deliberately live in [`ErrorExposure`] and
//! have no protocol code, so internal details cannot become an accidental XRPC
//! error string.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! define_error_codes {
    ($($variant:ident),+ $(,)?) => {
        /// Exact public errors declared by the frozen `blue.catbird.chat.*`
        /// Lexicons. The spelling is part of the wire contract.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum ChatProtocolErrorCode {
            $($variant),+
        }

        impl ChatProtocolErrorCode {
            /// Complete frozen public vocabulary. This deliberately excludes
            /// internal storage and invariant failures.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => stringify!($variant)),+
                }
            }
        }

        impl FromStr for ChatProtocolErrorCode {
            type Err = UnknownChatProtocolErrorCode;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $(stringify!($variant) => Ok(Self::$variant)),+,
                    _ => Err(UnknownChatProtocolErrorCode(value.to_owned())),
                }
            }
        }
    };
}

define_error_codes!(
    AccessOutsideMembershipInterval,
    AcknowledgementConflict,
    AdminRequired,
    AuthenticationGenerationConflict,
    BlobAlreadyExists,
    BlobBindingConflict,
    BlobBound,
    BlobConflict,
    BlobHashMismatch,
    BlobNotFound,
    BlobQuotaExceeded,
    BlobSizeMismatch,
    BlockedRelationship,
    CancellationConflict,
    CommitterSelfRemovalForbidden,
    ConversationAlreadyExists,
    ConversationCloseNotAllowed,
    ConversationLeafLimitReached,
    ConversationNotAccepted,
    ConversationNotFound,
    CoordinateOverflow,
    CursorExpired,
    CutoverRequired,
    DeviceAlreadyExists,
    DeviceLimitReached,
    DeviceNotFound,
    DeviceNotLeaf,
    DeviceNotRegistered,
    DeviceRevoked,
    DeviceTombstoned,
    DirectParticipantMutationForbidden,
    DuplicateDeviceLeaf,
    ExternalCommitForbidden,
    GroupInvitesDisabled,
    IdempotencyConflict,
    InvalidApplicationMessage,
    InvalidCommit,
    InvalidDPoP,
    InvalidGenesisGroupInfo,
    InvalidKeyPackage,
    InvalidLeaveManifest,
    InvalidMetadataSnapshot,
    InvalidMlsArtifact,
    InvalidRequest,
    InvalidSignature,
    InvalidTicket,
    InvalidWelcomeMapping,
    InventoryIncomplete,
    InventorySessionExpired,
    InventorySessionMismatch,
    InvitationLimitReached,
    InvitationNotFound,
    InvitationNotPending,
    InvitationProvenanceMismatch,
    KeyPackageInventoryLimitReached,
    KeyPackageUnavailable,
    LastAdminRequired,
    LeafRecoveryAlreadyOpen,
    LeafRecoveryExpired,
    LeafRecoveryNotFound,
    LeafRecoverySuperseded,
    LeaveAlreadyPending,
    LeaveRequestExpired,
    LeaveRequestNotFound,
    LeaveRequestStale,
    MessagesDisabled,
    MetadataNonceReuse,
    MetadataVersionOverflow,
    MissingMetadataSnapshot,
    NotAuthorized,
    NotEntitled,
    NotFollowedByRecipient,
    NotMember,
    NotParticipant,
    ParticipantLeafLimitReached,
    ParticipantLimitReached,
    RateLimited,
    RecipientNotReady,
    RejectionConflict,
    RelationshipPolicyUnavailable,
    ResetAlreadyPending,
    ResetRequestNotFound,
    ResetRequestStale,
    StaleCoordinates,
    StandaloneProposalForbidden,
    UnsupportedMlsProfile,
    UploadTicketExpired,
    UploadTicketNotFound,
    WelcomeExpired,
    WelcomeNotFound,
    WelcomeSuperseded,
);

impl ChatProtocolErrorCode {
    /// Public failures whose frozen semantics explicitly permit a retry after
    /// waiting for capacity or fresh relationship evidence.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::RelationshipPolicyUnavailable)
    }
}

impl fmt::Display for ChatProtocolErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for ChatProtocolErrorCode {}

impl Serialize for ChatProtocolErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ChatProtocolErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownChatProtocolErrorCode(String);

impl fmt::Display for UnknownChatProtocolErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown clean-chat protocol error code")
    }
}

impl std::error::Error for UnknownChatProtocolErrorCode {}

macro_rules! define_endpoint_contracts {
    ($($variant:ident => ($nsid:literal, [$($error:ident),+ $(,)?])),+ $(,)?) => {
        /// Known clean-chat endpoint. Unknown names under the namespace never
        /// acquire a contract through this type.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum ChatEndpoint {
            $($variant),+
        }

        impl ChatEndpoint {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            #[must_use]
            pub const fn nsid(self) -> &'static str {
                match self {
                    $(Self::$variant => $nsid),+
                }
            }

            #[must_use]
            pub const fn declared_errors(self) -> &'static [ChatProtocolErrorCode] {
                match self {
                    $(Self::$variant => &[$(ChatProtocolErrorCode::$error),+]),+
                }
            }

            #[must_use]
            pub fn declares(self, code: ChatProtocolErrorCode) -> bool {
                self.declared_errors().contains(&code)
            }
        }

        impl FromStr for ChatEndpoint {
            type Err = UnknownChatEndpoint;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($nsid => Ok(Self::$variant)),+,
                    _ => Err(UnknownChatEndpoint),
                }
            }
        }
    };
}

define_endpoint_contracts!(
    AcceptConversation => ("blue.catbird.chat.acceptConversation", [
        BlockedRelationship,
        ConversationNotFound,
        CoordinateOverflow,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        GroupInvitesDisabled,
        IdempotencyConflict,
        InvalidDPoP,
        InvalidRequest,
        InvalidSignature,
        InvitationNotFound,
        InvitationNotPending,
        InvitationProvenanceMismatch,
        KeyPackageUnavailable,
        MessagesDisabled,
        NotFollowedByRecipient,
        NotParticipant,
        RelationshipPolicyUnavailable,
        StaleCoordinates,
    ]),
    AcknowledgeWelcome => ("blue.catbird.chat.acknowledgeWelcome", [
        AcknowledgementConflict,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidDPoP,
        InvalidRequest,
        InvalidSignature,
        WelcomeExpired,
        WelcomeNotFound,
        WelcomeSuperseded,
    ]),
    ActivateReset => ("blue.catbird.chat.activateReset", [
        AdminRequired,
        ConversationNotFound,
        CoordinateOverflow,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidDPoP,
        InvalidGenesisGroupInfo,
        InvalidMetadataSnapshot,
        InvalidMlsArtifact,
        InvalidRequest,
        InvalidSignature,
        MetadataNonceReuse,
        NotAuthorized,
        NotMember,
        ResetRequestNotFound,
        ResetRequestStale,
        StaleCoordinates,
        UnsupportedMlsProfile,
    ]),
    CancelLeafRecovery => ("blue.catbird.chat.cancelLeafRecovery", [
        CancellationConflict,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidDPoP,
        InvalidRequest,
        InvalidSignature,
        LeafRecoveryNotFound,
        NotAuthorized,
    ]),
    CancelLeave => ("blue.catbird.chat.cancelLeave", [
        CancellationConflict,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidDPoP,
        InvalidRequest,
        InvalidSignature,
        LeaveRequestNotFound,
        NotAuthorized,
    ]),
    CloseConversation => ("blue.catbird.chat.closeConversation", [
        ConversationCloseNotAllowed,
        ConversationNotFound,
        CoordinateOverflow,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidDPoP,
        InvalidRequest,
        InvalidSignature,
        NotParticipant,
        StaleCoordinates,
    ]),
    CreateConversation => ("blue.catbird.chat.createConversation", [
        BlockedRelationship,
        ConversationAlreadyExists,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        GroupInvitesDisabled,
        IdempotencyConflict,
        InvalidDPoP,
        InvalidGenesisGroupInfo,
        InvalidMetadataSnapshot,
        InvalidMlsArtifact,
        InvalidRequest,
        InvalidSignature,
        InvitationLimitReached,
        MessagesDisabled,
        MetadataNonceReuse,
        NotAuthorized,
        NotFollowedByRecipient,
        RelationshipPolicyUnavailable,
        UnsupportedMlsProfile,
    ]),
    DeleteBlob => ("blue.catbird.chat.deleteBlob", [
        BlobBound,
        BlobNotFound,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidDPoP,
        InvalidRequest,
        InvalidSignature,
        NotAuthorized,
    ]),
    EnrollDevice => ("blue.catbird.chat.enrollDevice", [
        AuthenticationGenerationConflict,
        CutoverRequired,
        DeviceAlreadyExists,
        DeviceLimitReached,
        DeviceTombstoned,
        IdempotencyConflict,
        InvalidDPoP,
        InvalidKeyPackage,
        InvalidRequest,
        InvalidSignature,
        KeyPackageInventoryLimitReached,
        NotAuthorized,
    ]),
    GetBlob => ("blue.catbird.chat.getBlob", [
        BlobNotFound,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidDPoP,
        NotAuthorized,
    ]),
    GetBlobUsage => ("blue.catbird.chat.getBlobUsage", [
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidDPoP,
    ]),
    GetConversationState => ("blue.catbird.chat.getConversationState", [
        AccessOutsideMembershipInterval,
        ConversationNotFound,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidDPoP,
        InvalidRequest,
        NotEntitled,
    ]),
    GetConversations => ("blue.catbird.chat.getConversations", [
        CursorExpired,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidDPoP,
        InvalidRequest,
    ]),
    GetDevices => ("blue.catbird.chat.getDevices", [
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidDPoP,
        InvalidRequest,
    ]),
    GetEntries => ("blue.catbird.chat.getEntries", [
        AccessOutsideMembershipInterval,
        ConversationNotFound,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidDPoP,
        InvalidRequest,
        NotEntitled,
    ]),
    GetLeafRecoveryInbox => ("blue.catbird.chat.getLeafRecoveryInbox", [
        CursorExpired,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidDPoP,
        InvalidRequest,
        InventorySessionExpired,
        InventorySessionMismatch,
    ]),
    GetOwnDevices => ("blue.catbird.chat.getOwnDevices", [
        CursorExpired,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidDPoP,
    ]),
    GetPendingWelcomes => ("blue.catbird.chat.getPendingWelcomes", [
        CursorExpired,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidDPoP,
        InvalidRequest,
        InventorySessionExpired,
        InventorySessionMismatch,
    ]),
    GetSubscriptionTicket => ("blue.catbird.chat.getSubscriptionTicket", [
        CursorExpired,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidDPoP,
        InvalidRequest,
        InventoryIncomplete,
        InventorySessionExpired,
        InventorySessionMismatch,
    ]),
    PrepareBlobUpload => ("blue.catbird.chat.prepareBlobUpload", [
        BlobAlreadyExists,
        BlobQuotaExceeded,
        ConversationNotFound,
        CutoverRequired,
        DeviceNotLeaf,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidDPoP,
        InvalidRequest,
        InvalidSignature,
        NotAuthorized,
        StaleCoordinates,
    ]),
    PublishTyping => ("blue.catbird.chat.publishTyping", [
        BlockedRelationship,
        ConversationNotAccepted,
        ConversationNotFound,
        CutoverRequired,
        DeviceNotLeaf,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidDPoP,
        InvalidRequest,
        InvalidSignature,
        RateLimited,
        RecipientNotReady,
        RelationshipPolicyUnavailable,
        StaleCoordinates,
    ]),
    RebindDeviceAuthentication => ("blue.catbird.chat.rebindDeviceAuthentication", [
        AuthenticationGenerationConflict,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidDPoP,
        InvalidRequest,
        InvalidSignature,
        NotAuthorized,
    ]),
    RejectWelcome => ("blue.catbird.chat.rejectWelcome", [
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidDPoP,
        InvalidRequest,
        InvalidSignature,
        RejectionConflict,
        WelcomeExpired,
        WelcomeNotFound,
        WelcomeSuperseded,
    ]),
    ReplenishKeyPackages => ("blue.catbird.chat.replenishKeyPackages", [
        AuthenticationGenerationConflict,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidDPoP,
        InvalidKeyPackage,
        InvalidRequest,
        InvalidSignature,
        KeyPackageInventoryLimitReached,
        NotAuthorized,
    ]),
    RequestLeafRecovery => ("blue.catbird.chat.requestLeafRecovery", [
        BlockedRelationship,
        ConversationNotFound,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidDPoP,
        InvalidRequest,
        InvalidSignature,
        KeyPackageUnavailable,
        LeafRecoveryAlreadyOpen,
        NotParticipant,
        RelationshipPolicyUnavailable,
        StaleCoordinates,
    ]),
    RequestLeave => ("blue.catbird.chat.requestLeave", [
        ConversationNotFound,
        CoordinateOverflow,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        DirectParticipantMutationForbidden,
        IdempotencyConflict,
        InvalidDPoP,
        InvalidRequest,
        InvalidSignature,
        LastAdminRequired,
        LeaveAlreadyPending,
        NotMember,
        StaleCoordinates,
    ]),
    RequestReset => ("blue.catbird.chat.requestReset", [
        ConversationNotFound,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidDPoP,
        InvalidRequest,
        InvalidSignature,
        NotMember,
        ResetAlreadyPending,
        StaleCoordinates,
    ]),
    RevokeDevice => ("blue.catbird.chat.revokeDevice", [
        AuthenticationGenerationConflict,
        CutoverRequired,
        DeviceNotFound,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidDPoP,
        InvalidRequest,
        InvalidSignature,
        NotAuthorized,
    ]),
    SendMessage => ("blue.catbird.chat.sendMessage", [
        BlobBindingConflict,
        BlobNotFound,
        BlockedRelationship,
        ConversationNotAccepted,
        ConversationNotFound,
        CutoverRequired,
        DeviceNotLeaf,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidApplicationMessage,
        InvalidDPoP,
        InvalidRequest,
        InvalidSignature,
        NotMember,
        RecipientNotReady,
        RelationshipPolicyUnavailable,
        StaleCoordinates,
        UnsupportedMlsProfile,
    ]),
    SubmitTransition => ("blue.catbird.chat.submitTransition", [
        AdminRequired,
        BlockedRelationship,
        CommitterSelfRemovalForbidden,
        ConversationLeafLimitReached,
        ConversationNotFound,
        CoordinateOverflow,
        CutoverRequired,
        DeviceNotLeaf,
        DeviceNotRegistered,
        DeviceRevoked,
        DirectParticipantMutationForbidden,
        DuplicateDeviceLeaf,
        ExternalCommitForbidden,
        GroupInvitesDisabled,
        IdempotencyConflict,
        InvalidCommit,
        InvalidDPoP,
        InvalidLeaveManifest,
        InvalidMetadataSnapshot,
        InvalidRequest,
        InvalidSignature,
        InvalidWelcomeMapping,
        InvitationLimitReached,
        LastAdminRequired,
        LeafRecoveryExpired,
        LeafRecoveryNotFound,
        LeafRecoverySuperseded,
        LeaveRequestExpired,
        LeaveRequestNotFound,
        LeaveRequestStale,
        MetadataNonceReuse,
        MetadataVersionOverflow,
        MissingMetadataSnapshot,
        NotAuthorized,
        NotFollowedByRecipient,
        NotMember,
        ParticipantLeafLimitReached,
        ParticipantLimitReached,
        RelationshipPolicyUnavailable,
        StaleCoordinates,
        StandaloneProposalForbidden,
        UnsupportedMlsProfile,
    ]),
    SubscribeEvents => ("blue.catbird.chat.subscribeEvents", [
        CursorExpired,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidTicket,
    ]),
    UploadBlob => ("blue.catbird.chat.uploadBlob", [
        BlobConflict,
        BlobHashMismatch,
        BlobSizeMismatch,
        CutoverRequired,
        InvalidDPoP,
        InvalidRequest,
        UploadTicketExpired,
        UploadTicketNotFound,
    ]),
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownChatEndpoint;

impl fmt::Display for UnknownChatEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown clean-chat endpoint")
    }
}

impl std::error::Error for UnknownChatEndpoint {}

/// A public error that has been checked against the exact endpoint Lexicon.
/// Its fields are private so an adapter cannot manufacture an undeclared pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointProtocolError {
    endpoint: ChatEndpoint,
    code: ChatProtocolErrorCode,
}

impl EndpointProtocolError {
    pub fn new(
        endpoint: ChatEndpoint,
        code: ChatProtocolErrorCode,
    ) -> Result<Self, UndeclaredEndpointError> {
        if endpoint.declares(code) {
            Ok(Self { endpoint, code })
        } else {
            Err(UndeclaredEndpointError { endpoint, code })
        }
    }

    #[must_use]
    pub const fn endpoint(self) -> ChatEndpoint {
        self.endpoint
    }

    #[must_use]
    pub const fn code(self) -> ChatProtocolErrorCode {
        self.code
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UndeclaredEndpointError {
    endpoint: ChatEndpoint,
    code: ChatProtocolErrorCode,
}

impl UndeclaredEndpointError {
    #[must_use]
    pub const fn endpoint(self) -> ChatEndpoint {
        self.endpoint
    }

    #[must_use]
    pub const fn code(self) -> ChatProtocolErrorCode {
        self.code
    }
}

impl fmt::Display for UndeclaredEndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("error code is not declared for clean-chat endpoint")
    }
}

impl std::error::Error for UndeclaredEndpointError {}

/// Controls whether a failure may cross the protocol boundary. Internal
/// variants intentionally carry no database error, artifact, identifier, or
/// free-form string that an adapter could leak to a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorExposure {
    Protocol(EndpointProtocolError),
    InvariantViolation,
    StorageFailure,
}

impl ErrorExposure {
    #[must_use]
    pub const fn public_code(self) -> Option<ChatProtocolErrorCode> {
        match self {
            Self::Protocol(error) => Some(error.code()),
            Self::InvariantViolation | Self::StorageFailure => None,
        }
    }

    #[must_use]
    pub const fn public_error(self) -> Option<EndpointProtocolError> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::InvariantViolation | Self::StorageFailure => None,
        }
    }
}
