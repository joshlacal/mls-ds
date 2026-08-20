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
    AccountSessionExpired,
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
    DeviceBindingMismatch,
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
    ProtocolUpgradeRequired,
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
        AccountSessionExpired,
        BlockedRelationship,
        ConversationNotFound,
        CoordinateOverflow,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        GroupInvitesDisabled,
        IdempotencyConflict,
        InvalidRequest,
        InvalidSignature,
        InvitationNotFound,
        InvitationNotPending,
        InvitationProvenanceMismatch,
        KeyPackageUnavailable,
        MessagesDisabled,
        NotFollowedByRecipient,
        NotParticipant,
        RateLimited,
        RelationshipPolicyUnavailable,
        StaleCoordinates,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    AcknowledgeWelcome => ("blue.catbird.chat.acknowledgeWelcome", [
        AccountSessionExpired,
        AcknowledgementConflict,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidRequest,
        InvalidSignature,
        RateLimited,
        WelcomeExpired,
        WelcomeNotFound,
        WelcomeSuperseded,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    ActivateReset => ("blue.catbird.chat.activateReset", [
        AccountSessionExpired,
        AdminRequired,
        ConversationNotFound,
        CoordinateOverflow,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidGenesisGroupInfo,
        InvalidMetadataSnapshot,
        InvalidMlsArtifact,
        InvalidRequest,
        InvalidSignature,
        MetadataNonceReuse,
        NotAuthorized,
        NotMember,
        RateLimited,
        ResetRequestNotFound,
        ResetRequestStale,
        StaleCoordinates,
        UnsupportedMlsProfile,
        ProtocolUpgradeRequired,
        DeviceBindingMismatch,
    ]),
    CancelLeafRecovery => ("blue.catbird.chat.cancelLeafRecovery", [
        AccountSessionExpired,
        CancellationConflict,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidRequest,
        InvalidSignature,
        LeafRecoveryNotFound,
        NotAuthorized,
        RateLimited,
        ProtocolUpgradeRequired,
        DeviceBindingMismatch,
    ]),
    CancelLeave => ("blue.catbird.chat.cancelLeave", [
        AccountSessionExpired,
        CancellationConflict,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidRequest,
        InvalidSignature,
        LeaveRequestNotFound,
        NotAuthorized,
        RateLimited,
        ProtocolUpgradeRequired,
        DeviceBindingMismatch,
    ]),
    CloseConversation => ("blue.catbird.chat.closeConversation", [
        AccountSessionExpired,
        ConversationCloseNotAllowed,
        ConversationNotFound,
        CoordinateOverflow,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidRequest,
        InvalidSignature,
        NotParticipant,
        RateLimited,
        StaleCoordinates,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    CreateConversation => ("blue.catbird.chat.createConversation", [
        AccountSessionExpired,
        BlockedRelationship,
        ConversationAlreadyExists,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        GroupInvitesDisabled,
        IdempotencyConflict,
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
        RateLimited,
        RelationshipPolicyUnavailable,
        UnsupportedMlsProfile,
        ProtocolUpgradeRequired,
        DeviceBindingMismatch,
    ]),
    DeleteBlob => ("blue.catbird.chat.deleteBlob", [
        AccountSessionExpired,
        BlobBound,
        BlobNotFound,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidRequest,
        InvalidSignature,
        NotAuthorized,
        RateLimited,
        ProtocolUpgradeRequired,
        DeviceBindingMismatch,
    ]),
    EnrollDevice => ("blue.catbird.chat.enrollDevice", [
        AccountSessionExpired,
        AuthenticationGenerationConflict,
        CutoverRequired,
        DeviceAlreadyExists,
        DeviceLimitReached,
        DeviceTombstoned,
        IdempotencyConflict,
        InvalidKeyPackage,
        InvalidRequest,
        InvalidSignature,
        KeyPackageInventoryLimitReached,
        NotAuthorized,
        RateLimited,
        ProtocolUpgradeRequired,
        DeviceBindingMismatch,
    ]),
    GetBlob => ("blue.catbird.chat.getBlob", [
        AccountSessionExpired,
        BlobNotFound,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidRequest,
        NotAuthorized,
        RateLimited,
        ProtocolUpgradeRequired,
        DeviceBindingMismatch,
    ]),
    GetBlobUsage => ("blue.catbird.chat.getBlobUsage", [
        AccountSessionExpired,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidRequest,
        RateLimited,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    GetConversationState => ("blue.catbird.chat.getConversationState", [
        AccountSessionExpired,
        AccessOutsideMembershipInterval,
        ConversationNotFound,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidRequest,
        NotEntitled,
        RateLimited,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    GetConversations => ("blue.catbird.chat.getConversations", [
        AccountSessionExpired,
        CursorExpired,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidRequest,
        RateLimited,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    GetDevices => ("blue.catbird.chat.getDevices", [
        AccountSessionExpired,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidRequest,
        RateLimited,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    GetEntries => ("blue.catbird.chat.getEntries", [
        AccountSessionExpired,
        AccessOutsideMembershipInterval,
        ConversationNotFound,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidRequest,
        NotEntitled,
        RateLimited,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    GetLeafRecoveryInbox => ("blue.catbird.chat.getLeafRecoveryInbox", [
        AccountSessionExpired,
        CursorExpired,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidRequest,
        InventorySessionExpired,
        InventorySessionMismatch,
        RateLimited,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    GetOwnDevices => ("blue.catbird.chat.getOwnDevices", [
        AccountSessionExpired,
        CursorExpired,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidRequest,
        RateLimited,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    GetPendingWelcomes => ("blue.catbird.chat.getPendingWelcomes", [
        AccountSessionExpired,
        CursorExpired,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidRequest,
        InventorySessionExpired,
        InventorySessionMismatch,
        RateLimited,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    GetSubscriptionTicket => ("blue.catbird.chat.getSubscriptionTicket", [
        AccountSessionExpired,
        CursorExpired,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidRequest,
        InventoryIncomplete,
        InventorySessionExpired,
        InventorySessionMismatch,
        RateLimited,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    PrepareBlobUpload => ("blue.catbird.chat.prepareBlobUpload", [
        AccountSessionExpired,
        BlobAlreadyExists,
        BlobQuotaExceeded,
        ConversationNotFound,
        CutoverRequired,
        DeviceNotLeaf,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidRequest,
        InvalidSignature,
        NotAuthorized,
        RateLimited,
        StaleCoordinates,
        ProtocolUpgradeRequired,
        DeviceBindingMismatch,
    ]),
    PublishTyping => ("blue.catbird.chat.publishTyping", [
        AccountSessionExpired,
        BlockedRelationship,
        ConversationNotAccepted,
        ConversationNotFound,
        CutoverRequired,
        DeviceNotLeaf,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidRequest,
        InvalidSignature,
        RateLimited,
        RecipientNotReady,
        RelationshipPolicyUnavailable,
        StaleCoordinates,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    RejectWelcome => ("blue.catbird.chat.rejectWelcome", [
        AccountSessionExpired,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidRequest,
        InvalidSignature,
        RateLimited,
        RejectionConflict,
        WelcomeExpired,
        WelcomeNotFound,
        WelcomeSuperseded,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    ReplenishKeyPackages => ("blue.catbird.chat.replenishKeyPackages", [
        AccountSessionExpired,
        AuthenticationGenerationConflict,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidKeyPackage,
        InvalidRequest,
        InvalidSignature,
        KeyPackageInventoryLimitReached,
        NotAuthorized,
        RateLimited,
        ProtocolUpgradeRequired,
        DeviceBindingMismatch,
    ]),
    RequestLeafRecovery => ("blue.catbird.chat.requestLeafRecovery", [
        AccountSessionExpired,
        BlockedRelationship,
        ConversationNotFound,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidRequest,
        InvalidSignature,
        KeyPackageUnavailable,
        LeafRecoveryAlreadyOpen,
        NotParticipant,
        RateLimited,
        RelationshipPolicyUnavailable,
        StaleCoordinates,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    RequestLeave => ("blue.catbird.chat.requestLeave", [
        AccountSessionExpired,
        ConversationNotFound,
        CoordinateOverflow,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        DirectParticipantMutationForbidden,
        IdempotencyConflict,
        InvalidRequest,
        InvalidSignature,
        LastAdminRequired,
        LeaveAlreadyPending,
        NotMember,
        RateLimited,
        StaleCoordinates,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    RequestReset => ("blue.catbird.chat.requestReset", [
        AccountSessionExpired,
        ConversationNotFound,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidRequest,
        InvalidSignature,
        NotMember,
        RateLimited,
        ResetAlreadyPending,
        StaleCoordinates,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    RevokeDevice => ("blue.catbird.chat.revokeDevice", [
        AccountSessionExpired,
        AuthenticationGenerationConflict,
        CutoverRequired,
        DeviceNotFound,
        DeviceNotRegistered,
        DeviceRevoked,
        IdempotencyConflict,
        InvalidRequest,
        InvalidSignature,
        NotAuthorized,
        RateLimited,
        ProtocolUpgradeRequired,
        DeviceBindingMismatch,
    ]),
    SendMessage => ("blue.catbird.chat.sendMessage", [
        AccountSessionExpired,
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
        InvalidRequest,
        InvalidSignature,
        NotMember,
        RateLimited,
        RecipientNotReady,
        RelationshipPolicyUnavailable,
        StaleCoordinates,
        UnsupportedMlsProfile,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    SubmitTransition => ("blue.catbird.chat.submitTransition", [
        AccountSessionExpired,
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
        RateLimited,
        RelationshipPolicyUnavailable,
        StaleCoordinates,
        StandaloneProposalForbidden,
        UnsupportedMlsProfile,
        ProtocolUpgradeRequired,
        DeviceBindingMismatch,
    ]),
    SubscribeEvents => ("blue.catbird.chat.subscribeEvents", [
        AccountSessionExpired,
        CursorExpired,
        CutoverRequired,
        DeviceNotRegistered,
        DeviceRevoked,
        InvalidTicket,
        RateLimited,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
    ]),
    UploadBlob => ("blue.catbird.chat.uploadBlob", [
        AccountSessionExpired,
        BlobConflict,
        BlobHashMismatch,
        BlobSizeMismatch,
        CutoverRequired,
        InvalidRequest,
        RateLimited,
        UploadTicketExpired,
        UploadTicketNotFound,
        ProtocolUpgradeRequired,
        NotAuthorized,
        DeviceBindingMismatch,
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
