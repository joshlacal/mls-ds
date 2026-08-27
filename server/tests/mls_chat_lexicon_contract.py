#!/usr/bin/env python3
"""Executable semantic guard for the clean ``blue.catbird.chat`` contract.

The Lexicon parser is intentionally not the only oracle.  Current generators
accept unknown schema keywords and do not enforce closed objects, unions,
canonical ordering, or signature projections.  This guard therefore walks the
actual AST, resolves references, validates checked-in instances and golden
vectors, and applies negative mutations before Task 2 is allowed to consume the
contract.
"""

from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
import unicodedata
import unittest
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Iterable


SERVER_ROOT = Path(__file__).resolve().parents[1]
MLS_DS_ROOT = SERVER_ROOT.parent
STACK_ROOT = MLS_DS_ROOT.parent
CANONICAL_ROOT = STACK_ROOT / "PetrelCatbird/lexicons/blue/catbird/chat"
MIRROR_ROOT = MLS_DS_ROOT / "lexicon/blue/catbird/chat"
VECTOR_PATH = Path(__file__).with_name("fixtures") / "mls_chat_contract_vectors.json"
# Deliberately still the GENERATION home, not the in-repo snapshot. The Rust
# suites now read a frozen copy committed at server/tests/fixtures/crypto-wire so
# they never traverse out of the repository; this contract test is cross-stack by
# nature (see CANONICAL_ROOT in PetrelCatbird above) and checks the artifacts
# where the generator writes them. Keeping the two paths distinct is what lets a
# regeneration that has not been re-snapshotted into the repo be noticed here.
CRYPTO_WIRE_ROOT = STACK_ROOT / "docs/generated-artifacts/mls-chat-v1/crypto-wire"
CRYPTO_WIRE_V09_ROOT = STACK_ROOT / "docs/generated-artifacts/mls-chat-v1/crypto-wire-v09"
PROTOCOL_PATH = STACK_ROOT / "docs/mls-v2/CHAT_PROTOCOL.md"
STANDARD_APPVIEW_ADR_PATH = STACK_ROOT / "docs/design-docs/adr-001-mls-standard-appview-auth.md"
APPLICATION_PROTOCOL_PATH = STACK_ROOT / "docs/CHAT_APPLICATION_PROTOCOL.md"
APPLICATION_MANIFEST_PATH = STACK_ROOT / "docs/generated-artifacts/chat-application-v1/manifest.json"
APPLICATION_MANIFEST_INPUT_ENV = "CATBIRD_CHAT_APPLICATION_FIXTURE_INPUT"
FROZEN_APPLICATION_MANIFEST_SHA256 = "d7a856c2473579c06af7ddad67a17ea3b633064d0856093b009766f1d849df24"
TASK1_DOC_PATHS = (
    STACK_ROOT / ".superpowers/sdd/mls-chat-task-1-semantic-repair-brief.md",
    STACK_ROOT / ".superpowers/sdd/mls-chat-task-1-report.md",
    STACK_ROOT / ".superpowers/sdd/mls-chat-task-1-fix-report.md",
    STACK_ROOT / ".superpowers/sdd/mls-chat-task-1-final-review.md",
)
AUTH_DECISION_DOC_PATHS = (
    STACK_ROOT / "docs/program/decisions/ADR-019-chat-protocol-clean-cutover.md",
    STACK_ROOT / "docs/superpowers/plans/2026-07-22-chat-protocol.md",
    STACK_ROOT / ".superpowers/sdd/mls-chat-task-2-brief.md",
)

APPLICATION_VECTOR_ORACLES: dict[str, tuple[str, str | None, str | None]] = {
    "text": ("supported", None, "message"),
    "encryptedGif": ("supported", None, "message"),
    "encryptedAudio": ("supported", None, "message"),
    "blurhashMinimum": ("supported", None, "message"),
    "blurhashMaximum": ("supported", None, "message"),
    "atRecordDidPlcLowercaseAccepted": ("supported", None, "message"),
    "atRecordCollectionAndRkeyCasePreserved": ("supported", None, "message"),
    "atRecordDidWebLowercaseHostnameAccepted": ("supported", None, "message"),
    "atRecordHandleLowercaseHostnameAccepted": ("supported", None, "message"),
    "atRecordDidWebLabel63Accepted": ("supported", None, "message"),
    "atRecordDidWebHost253Accepted": ("supported", None, "message"),
    "atRecordHandleLabel63Accepted": ("supported", None, "message"),
    "atRecordHandleHost253Accepted": ("supported", None, "message"),
    "externalLink": ("supported", None, "message"),
    "reactionAdd": ("supported", None, "reaction"),
    "reactionRemove": ("supported", None, "reaction"),
    "messageWithReplyTo": ("supported", None, "message"),
    "edit": ("supported", None, "edit"),
    "tombstone": ("supported", None, "tombstone"),
    "readState": ("supported", None, "readState"),
    "futureVersionOpaque": ("unsupported", None, None),
    "innerOuterMessageIdMismatch": ("rejected", "bindingMismatch", None),
    "innerOuterConversationIdMismatch": ("rejected", "bindingMismatch", None),
    "innerOuterGenerationMismatch": ("rejected", "bindingMismatch", None),
    "innerOuterStateVersionMismatch": ("rejected", "bindingMismatch", None),
    "innerOuterGroupIdMismatch": ("rejected", "bindingMismatch", None),
    "innerOuterEpochMismatch": ("rejected", "bindingMismatch", None),
    "innerOuterGroupContextHashMismatch": ("rejected", "bindingMismatch", None),
    "innerOuterConfirmationTagMismatch": ("rejected", "bindingMismatch", None),
    "v1LifecycleClosedRejected": ("rejected", "unknownField", None),
    "v1KnownContextGenerationAboveUint53": ("rejected", "integerOverflow", None),
    "cborDuplicateKey": ("rejected", "duplicateKey", None),
    "cborNonminimalInteger": ("rejected", "nonCanonical", None),
    "cborNonminimalLength": ("rejected", "nonCanonical", None),
    "cborWrongKeyOrder": ("rejected", "nonCanonical", None),
    "cborIndefiniteLength": ("rejected", "indefiniteLength", None),
    "cborInvalidUtf8": ("rejected", "invalidUtf8", None),
    "cborTagV1": ("rejected", "tagNotAllowed", None),
    "cborFloatV1": ("rejected", "floatNotAllowed", None),
    "cborNullV1": ("rejected", "nullNotAllowed", None),
    "cborTrailingData": ("rejected", "trailingData", None),
    "futureV2FiniteF64": ("unsupported", None, None),
    "futureV2CidLink": ("unsupported", None, None),
    "futureV2Null": ("unsupported", None, None),
    "futureV2Bool": ("unsupported", None, None),
    "futureV2DefiniteArray": ("unsupported", None, None),
    "futureV2CanonicalMap": ("unsupported", None, None),
    "futureV2IntegerAboveUint53": ("unsupported", None, None),
    "futureV2PositiveInfinity": ("rejected", "floatNotAllowed", None),
    "futureV2NaN": ("rejected", "floatNotAllowed", None),
    "futureV2Non42Tag": ("rejected", "tagNotAllowed", None),
    "futureV2CidMissingMultibaseZero": ("rejected", "invalidValue", None),
    "futureV2MalformedCid": ("rejected", "invalidValue", None),
    "futureV2NoncanonicalCid": ("rejected", "invalidValue", None),
    "futureV2HalfFloat": ("rejected", "floatNotAllowed", None),
    "futureV2SingleFloat": ("rejected", "floatNotAllowed", None),
    "atRecordMissingCollectionRejected": ("rejected", "invalidValue", None),
    "atRecordMissingRkeyRejected": ("rejected", "invalidValue", None),
    "atRecordFragmentRejected": ("rejected", "invalidValue", None),
    "atRecordUppercaseSchemeRejected": ("rejected", "invalidValue", None),
    "atRecordDidPlcUppercaseMethodRejected": ("rejected", "invalidValue", None),
    "atRecordDidPlcUppercaseMethodSpecificRejected": ("rejected", "invalidValue", None),
    "atRecordDidPlcMalformedRejected": ("rejected", "invalidValue", None),
    "atRecordDidPlcInvalidAlphabetRejected": ("rejected", "invalidValue", None),
    "atRecordUnsupportedDidMethodRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebIpv6Rejected": ("rejected", "invalidValue", None),
    "atRecordDidWebLabelOver63Rejected": ("rejected", "invalidValue", None),
    "atRecordDidWebHostOver253Rejected": ("rejected", "invalidValue", None),
    "atRecordHandleLabelOver63Rejected": ("rejected", "invalidValue", None),
    "atRecordHandleHostOver253Rejected": ("rejected", "invalidValue", None),
    "atRecordRkeyDotRejected": ("rejected", "invalidValue", None),
    "atRecordRkeyDotDotRejected": ("rejected", "invalidValue", None),
    "atRecordUppercaseHandleRejected": ("rejected", "invalidValue", None),
    "atRecordNonAsciiAuthorityRejected": ("rejected", "invalidValue", None),
    "atRecordLeadingHyphenAuthorityRejected": ("rejected", "invalidValue", None),
    "atRecordTrailingHyphenAuthorityRejected": ("rejected", "invalidValue", None),
    "atRecordEmptyAuthorityLabelRejected": ("rejected", "invalidValue", None),
    "atRecordUppercaseCollectionDomainRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebUppercaseHostRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebPathRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebUppercasePathRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebPortRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebSingleLabelRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebLocalhostRejected": ("rejected", "invalidValue", None),
    "atRecordBareLocalhostHandleRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebIpRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebNumericTldRejected": ("rejected", "invalidValue", None),
    "atRecordHandleNumericTldRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebReservedAltTldRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebReservedArpaTldRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebReservedExampleTldRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebReservedInternalTldRejected": ("rejected", "invalidValue", None),
    "atRecordReservedTldRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebReservedLocalTldRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebReservedLocalhostTldRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebReservedOnionTldRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebReservedTestTldRejected": ("rejected", "invalidValue", None),
    "atRecordHandleReservedAltTldRejected": ("rejected", "invalidValue", None),
    "atRecordHandleReservedArpaTldRejected": ("rejected", "invalidValue", None),
    "atRecordHandleReservedExampleTldRejected": ("rejected", "invalidValue", None),
    "atRecordHandleReservedInternalTldRejected": ("rejected", "invalidValue", None),
    "atRecordHandleInvalidRejected": ("rejected", "invalidValue", None),
    "atRecordHandleReservedLocalTldRejected": ("rejected", "invalidValue", None),
    "atRecordHandleReservedLocalhostTldRejected": ("rejected", "invalidValue", None),
    "atRecordHandleReservedOnionTldRejected": ("rejected", "invalidValue", None),
    "atRecordHandleReservedTestTldRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebPercentRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebLowercasePercentEscapeRejected": ("rejected", "invalidValue", None),
    "atRecordDidWebAsciiPercentEscapeRejected": ("rejected", "invalidValue", None),
    "atRecordRkeyPercentRejected": ("rejected", "invalidValue", None),
    "atRecordQueryRejected": ("rejected", "invalidValue", None),
    "atRecordTrailingPathRejected": ("rejected", "invalidValue", None),
    "atRecordDuplicateSlashRejected": ("rejected", "invalidValue", None),
    "atRecordDotPathSegmentRejected": ("rejected", "invalidValue", None),
    "atRecordEmptyCollectionRejected": ("rejected", "invalidValue", None),
    "atRecordCollectionDotRejected": ("rejected", "invalidValue", None),
    "atRecordParentPathSegmentRejected": ("rejected", "invalidValue", None),
    "atRecordExtraSegmentRejected": ("rejected", "invalidValue", None),
    "externalLinkNonHttps": ("rejected", "invalidValue", None),
    "externalLinkRelative": ("rejected", "invalidValue", None),
    "externalLinkEmptyHost": ("rejected", "invalidValue", None),
    "externalLinkUserinfo": ("rejected", "invalidValue", None),
    "externalLinkBackslash": ("rejected", "invalidValue", None),
    "externalLinkWhitespace": ("rejected", "invalidValue", None),
    "externalLinkControl": ("rejected", "invalidValue", None),
    "externalLinkInvalidPercent": ("rejected", "invalidValue", None),
    "reactionNonNfc": ("rejected", "invalidReaction", None),
    "reactionTwoGraphemes": ("rejected", "invalidReaction", None),
    "reactionSingleGraphemeOver64Bytes": ("rejected", "invalidReaction", None),
    "blurhashBelowMinimum": ("rejected", "invalidValue", None),
    "blurhashAboveMaximum": ("rejected", "sizeLimitExceeded", None),
    "imageCiphertextTagSizeMismatch": ("rejected", "sizeLimitExceeded", None),
    "audioCiphertextTagSizeMismatch": ("rejected", "sizeLimitExceeded", None),
    "applicationMetadataPurposeForbidden": ("rejected", "bindingMismatch", None),
    "outerMetadataBindingForbidden": ("outerRejected", "invalidValue", None),
    "unknownV1TopField": ("rejected", "unknownField", None),
    "transportTypingBodyForbidden": ("rejected", "unknownField", None),
    "nullV1Field": ("rejected", "nullNotAllowed", None),
    "gifMissingOuterBinding": ("rejected", "bindingMismatch", None),
    "textDanglingOuterBinding": ("rejected", "bindingMismatch", None),
    "gifOuterHashMismatch": ("rejected", "bindingMismatch", None),
    "senderCredentialMismatch": ("rejected", "bindingMismatch", None),
    "senderLeafKeyMismatch": ("rejected", "bindingMismatch", None),
}

PREFIX = "blue.catbird.chat"
RETIRED_PREFIX = "blue.catbird.mlsChat"
SAFE_INTEGER_MAX = 9_007_199_254_740_991
SUITE = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"

ENDPOINTS: dict[str, str] = {
    "enrollDevice": "procedure",
    "replenishKeyPackages": "procedure",
    "revokeDevice": "procedure",
    "getDevices": "query",
    "getOwnDevices": "query",
    "prepareBlobUpload": "procedure",
    "uploadBlob": "procedure",
    "deleteBlob": "procedure",
    "getBlob": "query",
    "getBlobUsage": "query",
    "createConversation": "procedure",
    "acceptConversation": "procedure",
    "closeConversation": "procedure",
    "getConversations": "query",
    "getConversationState": "query",
    "submitTransition": "procedure",
    "sendMessage": "procedure",
    "publishTyping": "procedure",
    "getEntries": "query",
    "getPendingWelcomes": "query",
    "acknowledgeWelcome": "procedure",
    "rejectWelcome": "procedure",
    "requestLeafRecovery": "procedure",
    "cancelLeafRecovery": "procedure",
    "getLeafRecoveryInbox": "query",
    "requestLeave": "procedure",
    "cancelLeave": "procedure",
    "requestReset": "procedure",
    "activateReset": "procedure",
    "getSubscriptionTicket": "procedure",
    "subscribeEvents": "subscription",
    "updatePushToken": "procedure",
}

RECORDS: dict[str, str] = {
    "declaration": "record",
    "device": "record",
}

SIGNED_PROJECTIONS: dict[str, tuple[str, str]] = {
    "signedDeviceEnrollment": ("deviceEnrollmentBody", "CATBIRD-CHAT-DEVICE-ENROLL\0"),
    "signedKeyPackageReplenishment": ("keyPackageReplenishmentBody", "CATBIRD-CHAT-DEVICE-REPLENISH\0"),
    "signedDeviceRevocation": ("deviceRevocationBody", "CATBIRD-CHAT-DEVICE-REVOKE\0"),
    "signedBlobUploadPreparation": ("blobUploadPreparationBody", "CATBIRD-CHAT-BLOB-PREPARE\0"),
    "signedBlobDeletion": ("blobDeletionBody", "CATBIRD-CHAT-BLOB-DELETE\0"),
    "signedCreation": ("creationBody", "CATBIRD-CHAT-CREATE\0"),
    "signedCommitTransition": ("commitTransitionBody", "CATBIRD-CHAT-COMMIT\0"),
    "signedPolicyTransition": ("policyTransitionBody", "CATBIRD-CHAT-POLICY\0"),
    "signedParticipantAcceptance": ("participantAcceptanceBody", "CATBIRD-CHAT-ACCEPT\0"),
    "signedApplicationSend": ("applicationSendBody", "CATBIRD-CHAT-MESSAGE\0"),
    "signedTyping": ("typingBody", "CATBIRD-CHAT-TYPING\0"),
    "signedMetadataTransition": ("metadataTransitionBody", "CATBIRD-CHAT-METADATA\0"),
    "signedResetRequest": ("resetRequestBody", "CATBIRD-CHAT-RESET-REQUEST\0"),
    "signedResetActivation": ("resetActivationBody", "CATBIRD-CHAT-RESET-ACTIVATE\0"),
    "signedLeafRecoveryRequest": ("leafRecoveryRequestBody", "CATBIRD-CHAT-LEAF-RECOVERY-REQUEST\0"),
    "signedLeafRecoveryCancellation": ("leafRecoveryCancellationBody", "CATBIRD-CHAT-LEAF-RECOVERY-CANCEL\0"),
    "signedLeafRecoveryFulfillment": ("leafRecoveryFulfillmentBody", "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\0"),
    "signedConversationClose": ("conversationCloseBody", "CATBIRD-CHAT-CLOSE\0"),
    "signedLeaveRequest": ("leaveRequestBody", "CATBIRD-CHAT-LEAVE-REQUEST\0"),
    "signedZeroLeafLeave": ("zeroLeafLeaveBody", "CATBIRD-CHAT-LEAVE-ZERO-LEAF\0"),
    "signedLeaveCancellation": ("leaveCancellationBody", "CATBIRD-CHAT-LEAVE-CANCEL\0"),
    "signedLeaveCommitFulfillment": ("leaveCommitFulfillmentBody", "CATBIRD-CHAT-LEAVE-FULFILL-COMMIT\0"),
    "signedWelcomeAcknowledgement": ("welcomeAcknowledgementBody", "CATBIRD-CHAT-WELCOME-ACK\0"),
    "signedWelcomeRejection": ("welcomeRejectionBody", "CATBIRD-CHAT-WELCOME-REJECT\0"),
}

CONTROL_ENTRY_FINGERPRINT_KINDS: dict[str, tuple[str, str | None]] = {
    f"{PREFIX}.defs#commitEntry": ("signedCommitTransition", None),
    f"{PREFIX}.defs#policyEntry": ("signedPolicyTransition", None),
    f"{PREFIX}.defs#metadataEntry": ("signedMetadataTransition", None),
    f"{PREFIX}.defs#creationEntry": ("signedCreation", None),
    f"{PREFIX}.defs#participantAcceptanceEntry": ("signedParticipantAcceptance", "recovery"),
    f"{PREFIX}.defs#conversationCloseEntry": ("signedConversationClose", "tombstone"),
    f"{PREFIX}.defs#resetRequestEntry": ("signedResetRequest", None),
    f"{PREFIX}.defs#resetActivationEntry": ("signedResetActivation", None),
    f"{PREFIX}.defs#leafRecoveryFulfillmentEntry": ("signedLeafRecoveryFulfillment", None),
    f"{PREFIX}.defs#leaveRequestEntry": ("signedLeaveRequest", None),
    f"{PREFIX}.defs#zeroLeafLeaveEntry": ("signedZeroLeafLeave", None),
    f"{PREFIX}.defs#leaveCancellationEntry": ("signedLeaveCancellation", None),
    f"{PREFIX}.defs#leaveCommitFulfillmentEntry": ("signedLeaveCommitFulfillment", None),
}

RECOVERY_WORK_VARIANTS = {
    "recoveryWorkPendingView",
    "recoveryWorkCompletedByTransitionView",
    "recoveryWorkSupersededByTransitionView",
    "recoveryWorkSupersededByRevocationView",
}

CLOSED_UNIONS: dict[str, set[str]] = {
    "participantChange": {"addParticipant", "removeParticipant", "changeParticipantRole"},
    "leafChange": {"addLeafByRecovery", "removeLeaf"},
    "conversationInventoryItem": {"conversationInventoryState", "conversationRemovalTombstone", "conversationCloseTombstone"},
    "conversationEntry": {
        "applicationEntry", "commitEntry", "policyEntry", "metadataEntry", "creationEntry",
        "participantAcceptanceEntry", "conversationCloseEntry", "resetRequestEntry",
        "resetActivationEntry", "leafRecoveryFulfillmentEntry", "leaveRequestEntry",
        "zeroLeafLeaveEntry", "leaveCancellationEntry", "leaveCommitFulfillmentEntry",
    },
    "protocolEventPayload": {
        "conversationChangedEvent", "messageAvailableEvent", "welcomeAvailableEvent",
        "conversationClosedEvent", "welcomeDispositionEvent", "resetRequestedEvent", "leafRecoveryEvent",
        "leaveRequestEvent", "accessEndedEvent", "watermarkEvent",
    },
    "signedTransition": {
        "signedCommitTransition", "signedPolicyTransition", "signedLeafRecoveryFulfillment",
        "signedMetadataTransition", "signedLeaveCommitFulfillment",
    },
    "signedLeaveOperation": {"signedLeaveRequest", "signedZeroLeafLeave"},
    "leaveOperationResult": {"durableLeaveRequestResult", "zeroLeafLeaveResult"},
    "conversationCreationResult": {"conversationCreatedResult", "existingDirectConversationResult"},
    "recoveryWorkView": RECOVERY_WORK_VARIANTS,
    "leafRecoveryInboxItem": {"leafRecoveryView", *RECOVERY_WORK_VARIANTS},
    "applicationFrameBody": {"messageFrameVariant", "reactionFrameVariant", "editFrameVariant", "tombstoneFrameVariant", "readStateFrameVariant"},
    "applicationEmbed": {"encryptedImageEmbedVariant", "encryptedAudioEmbedVariant", "atprotoRecordEmbedVariant", "externalLinkEmbedVariant"},
    "subscriptionMessage": {"eventEnvelope", "typingEvent"},
}

COORDINATE_FIELDS = {
    "conversationId", "generation", "stateVersion", "groupId", "epoch",
    "groupContextHash", "confirmationTag", "lifecycle",
}

TIMESTAMP_RE = re.compile(r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$")
UUID_V4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
PLC_DID_RE = re.compile(r"^did:plc:[a-z2-7]{24}$")
NSID_RE = re.compile(
    r"^[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
    r"\.[A-Za-z][A-Za-z0-9]{0,62}$"
)
RESERVED_PRODUCTION_TLDS = {
    "alt", "arpa", "example", "internal", "invalid", "local", "localhost",
    "onion", "test",
}
KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


def is_valid_production_atproto_hostname(value: str) -> bool:
    if value != value.lower() or not 1 <= len(value.encode("ascii", errors="ignore")) <= 253:
        return False
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    if (
        not labels[-1]
        or labels[-1] in RESERVED_PRODUCTION_TLDS
        or not labels[-1][0].isalpha()
    ):
        return False
    return all(
        1 <= len(label) <= 63 and re.fullmatch(DNS_LABEL, label) is not None
        for label in labels
    )


def is_valid_bare_did(value: str) -> bool:
    if not 12 <= len(value.encode("utf-8")) <= 261:
        return False
    if PLC_DID_RE.fullmatch(value):
        return True
    if not value.startswith("did:web:"):
        return False
    return is_valid_production_atproto_hostname(value.removeprefix("did:web:"))

SCHEMA_KEYS: dict[str, set[str]] = {
    "object": {"type", "description", "required", "properties"},
    "array": {"type", "description", "items", "minLength", "maxLength"},
    "union": {"type", "description", "refs", "closed"},
    "ref": {"type", "description", "ref"},
    "bytes": {"type", "description", "minLength", "maxLength"},
    "string": {
        "type", "description", "format", "default", "minLength", "maxLength",
        "minGraphemes", "maxGraphemes", "enum", "const", "knownValues",
    },
    "integer": {"type", "description", "default", "minimum", "maximum", "enum", "const"},
    "boolean": {"type", "description", "default", "const"},
    "unknown": {"type", "description"},
}


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json_loads(source: str) -> Any:
    return json.loads(source, object_pairs_hook=reject_duplicate_pairs)


def strict_load(path: Path) -> Any:
    return strict_json_loads(path.read_text(encoding="utf-8"))


def load_documents(root: Path) -> dict[str, dict[str, Any]]:
    return {path.name: strict_load(path) for path in sorted(root.glob("*.json"))}


def required(schema: dict[str, Any]) -> set[str]:
    return set(schema.get("required", []))


def local_ref_name(ref: str) -> str:
    return ref.split("#", 1)[1]


def ref_for(name: str) -> set[str]:
    return {f"#{name}", f"{PREFIX}.defs#{name}"}


def assert_ref(schema: dict[str, Any], name: str) -> None:
    assert schema.get("type") == "ref", schema
    assert schema.get("ref") in ref_for(name), schema


def endpoint_document(documents: dict[str, dict[str, Any]], name: str) -> dict[str, Any]:
    return documents[f"{PREFIX}.{name}.json"]


def endpoint_input(document: dict[str, Any]) -> dict[str, Any]:
    main = document["defs"]["main"]
    return main["parameters"] if main["type"] in {"query", "subscription"} else main["input"]["schema"]


def endpoint_output(document: dict[str, Any]) -> dict[str, Any]:
    return document["defs"]["main"]["output"]["schema"]


def walk_values(value: Any, path: str = "$") -> Iterable[tuple[str, dict[str, Any]]]:
    if isinstance(value, dict):
        yield path, value
        for key, child in value.items():
            yield from walk_values(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_values(child, f"{path}[{index}]")


def contains_null(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, dict):
        return any(contains_null(child) for child in value.values())
    if isinstance(value, list):
        return any(contains_null(child) for child in value)
    return False


def resolve_ref(documents: dict[str, dict[str, Any]], current: dict[str, Any], ref: str) -> dict[str, Any]:
    if ref.startswith("#"):
        document = current
    else:
        nsid, _ = ref.split("#", 1)
        filename = f"{nsid}.json"
        assert filename in documents, f"unresolved reference document: {ref}"
        document = documents[filename]
    name = local_ref_name(ref)
    assert name in document["defs"], f"unresolved definition: {ref}"
    return document["defs"][name]


def resolve_ref_with_document(
    documents: dict[str, dict[str, Any]], current: dict[str, Any], ref: str
) -> tuple[dict[str, Any], dict[str, Any], str]:
    if ref.startswith("#"):
        document = current
        canonical_ref = f"{current['id']}#{local_ref_name(ref)}"
    else:
        nsid, _ = ref.split("#", 1)
        document = documents[f"{nsid}.json"]
        canonical_ref = ref
    return document, resolve_ref(documents, current, ref), canonical_ref


def is_canonical_key_id(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 43:
        return False
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        return False
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except ValueError:
        return False
    return (
        len(decoded) == 32
        and base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") == value
    )


def assert_closed_lexicon_scalar(
    schema: dict[str, Any], value: Any, path: str
) -> None:
    node_type = schema["type"]
    if node_type == "bytes":
        assert isinstance(value, bytes), f"expected bytes at {path}"
        assert schema.get("minLength", 0) <= len(value), f"bytes too short at {path}"
        assert len(value) <= schema.get("maxLength", SAFE_INTEGER_MAX), (
            f"bytes too long at {path}"
        )
        return
    if node_type == "string":
        assert isinstance(value, str), f"expected string at {path}"
        encoded_length = len(value.encode("utf-8"))
        assert schema.get("minLength", 0) <= encoded_length, f"string too short at {path}"
        assert encoded_length <= schema.get("maxLength", SAFE_INTEGER_MAX), (
            f"string too long at {path}"
        )
        if "const" in schema:
            assert value == schema["const"], f"wrong string const at {path}"
        if "enum" in schema:
            assert value in schema["enum"], f"unknown string enum value at {path}"
        if schema.get("format") == "did":
            assert is_valid_bare_did(value), f"invalid bare DID at {path}"
        if schema.get("format") == "datetime":
            assert TIMESTAMP_RE.fullmatch(value), f"invalid canonical datetime at {path}"
            dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
        return
    if node_type == "integer":
        assert type(value) is int, f"expected integer at {path}"
        assert schema.get("minimum", 0) <= value, f"integer too small at {path}"
        assert value <= schema.get("maximum", SAFE_INTEGER_MAX), (
            f"integer too large at {path}"
        )
        if "const" in schema:
            assert value == schema["const"], f"wrong integer const at {path}"
        if "enum" in schema:
            assert value in schema["enum"], f"unknown integer enum value at {path}"
        return
    if node_type == "boolean":
        assert type(value) is bool, f"expected boolean at {path}"
        if "const" in schema:
            assert value is schema["const"], f"wrong boolean const at {path}"
        return
    if node_type == "unknown":
        assert value is not None, f"null is forbidden at {path}"
        return
    raise AssertionError(f"unsupported scalar schema type {node_type!r} at {path}")


def assert_closed_lexicon_value(
    documents: dict[str, dict[str, Any]],
    current: dict[str, Any],
    schema: dict[str, Any],
    value: Any,
    path: str,
    expected_type_tag: str | None = None,
) -> None:
    """Recursively enforce closed object fields and closed-union `$type` tags."""

    node_type = schema["type"]
    if node_type == "ref":
        target_document, target_schema, canonical_ref = resolve_ref_with_document(
            documents, current, schema["ref"]
        )
        if canonical_ref in {
            f"{PREFIX}.defs#operationId",
            f"{PREFIX}.defs#deviceId",
        }:
            assert isinstance(value, bytes) and len(value) == 16, (
                f"expected canonical UUID bytes at {path}"
            )
            identifier = uuid.UUID(bytes=value)
            assert identifier.version == 4 and identifier.variant == uuid.RFC_4122, (
                f"expected RFC 4122 UUIDv4 bytes at {path}"
            )
            return
        if canonical_ref == f"{PREFIX}.defs#keyId":
            assert is_canonical_key_id(value), f"invalid key thumbprint at {path}"
        assert_closed_lexicon_value(
            documents, target_document, target_schema, value, path, expected_type_tag
        )
        return
    if node_type == "union":
        assert isinstance(value, dict), f"closed union must be a tagged object at {path}"
        actual_tag = value.get("$type")
        assert isinstance(actual_tag, str), f"closed union missing $type at {path}"
        choices: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
        for ref in schema["refs"]:
            target_document, target_schema, canonical_ref = resolve_ref_with_document(
                documents, current, ref
            )
            choices[canonical_ref] = (target_document, target_schema)
        assert actual_tag in choices, f"closed union unknown $type {actual_tag!r} at {path}"
        target_document, target_schema = choices[actual_tag]
        assert_closed_lexicon_value(
            documents, target_document, target_schema, value, path, actual_tag
        )
        return
    if node_type == "object":
        assert isinstance(value, dict), f"expected object at {path}"
        properties = schema.get("properties", {})
        allowed = set(properties)
        if expected_type_tag is not None:
            assert value.get("$type") == expected_type_tag, f"wrong $type at {path}"
            allowed.add("$type")
        assert required(schema) <= set(value), f"missing required field(s) at {path}"
        assert set(value) <= allowed, f"unknown field(s) at {path}"
        public_key = value.get("signaturePublicKey")
        if isinstance(public_key, bytes):
            expected_key_id = base64.urlsafe_b64encode(
                hashlib.sha256(public_key).digest()
            ).rstrip(b"=").decode("ascii")
            for key_field in ("keyId", "authorKeyId", "requesterKeyId"):
                if key_field in value:
                    assert value[key_field] == expected_key_id, (
                        f"{key_field} does not bind signaturePublicKey at {path}"
                    )
        for name, child in value.items():
            if name != "$type":
                assert_closed_lexicon_value(
                    documents, current, properties[name], child, f"{path}.{name}"
                )
        return
    if node_type == "array":
        assert isinstance(value, list), f"expected array at {path}"
        assert schema["minLength"] <= len(value) <= schema["maxLength"], (
            f"array length outside contract at {path}"
        )
        for index, child in enumerate(value):
            assert_closed_lexicon_value(
                documents, current, schema["items"], child, f"{path}[{index}]"
            )
        return
    assert_closed_lexicon_scalar(schema, value, path)


def closed_lexicon_value_is_valid(
    documents: dict[str, dict[str, Any]],
    current: dict[str, Any],
    schema: dict[str, Any],
    value: Any,
    expected_type_tag: str,
) -> bool:
    try:
        assert_closed_lexicon_value(
            documents, current, schema, value, "$", expected_type_tag
        )
    except (AssertionError, KeyError, TypeError, ValueError):
        return False
    return True


def validate_schema_ast(documents: dict[str, dict[str, Any]]) -> None:
    for filename, document in documents.items():
        assert strict_json_loads(json.dumps(document, separators=(",", ":"))) == document
        for path, node in walk_values(document):
            assert "minItems" not in node and "maxItems" not in node, f"invalid Lexicon array keyword at {filename}:{path}"
            node_type = node.get("type")
            if node_type in SCHEMA_KEYS:
                unknown = set(node) - SCHEMA_KEYS[node_type]
                assert not unknown, f"unknown {node_type} keyword(s) {sorted(unknown)} at {filename}:{path}"
            if node_type == "object":
                assert required(node) <= set(node.get("properties", {})), f"required/property mismatch at {filename}:{path}"
                assert "extra_data" not in node.get("properties", {}), f"extra_data is forbidden at {filename}:{path}"
            elif node_type == "array":
                assert isinstance(node.get("minLength"), int), f"array missing minLength at {filename}:{path}"
                assert isinstance(node.get("maxLength"), int), f"array missing maxLength at {filename}:{path}"
                assert 0 <= node["minLength"] <= node["maxLength"] <= 100, f"invalid array bounds at {filename}:{path}"
            elif node_type == "union":
                assert node.get("closed") is True, f"union must be closed at {filename}:{path}"
                assert node.get("refs"), f"empty union at {filename}:{path}"
                for ref in node["refs"]:
                    resolve_ref(documents, document, ref)
            elif node_type == "ref":
                resolve_ref(documents, document, node["ref"])
            elif node_type == "integer" and ("minimum" in node or "maximum" in node):
                assert node.get("minimum", -SAFE_INTEGER_MAX) >= -SAFE_INTEGER_MAX, f"integer minimum outside safe range at {filename}:{path}"
                assert node.get("maximum", SAFE_INTEGER_MAX) <= SAFE_INTEGER_MAX, f"integer maximum outside safe range at {filename}:{path}"


def validate_manifest(documents: dict[str, dict[str, Any]]) -> None:
    expected = {f"{PREFIX}.defs.json", f"{PREFIX}.authFull.json"} | {
        f"{PREFIX}.{name}.json" for name in ENDPOINTS
    } | {
        f"{PREFIX}.{name}.json" for name in RECORDS
    }
    assert set(documents) == expected, f"manifest mismatch: missing={sorted(expected-set(documents))}, extra={sorted(set(documents)-expected)}"
    encoded = json.dumps(documents, sort_keys=True)
    for forbidden in (
        '#blobBinding"', "dpopJkt", "currentDpopJkt", "newDpopJkt",
        "rebindDeviceAuthentication",
    ):
        assert forbidden not in encoded, f"superseded contract token remains: {forbidden}"
    for filename, document in documents.items():
        suffix = filename.removeprefix(f"{PREFIX}.").removesuffix(".json")
        assert document.get("lexicon") == 1
        assert document.get("id") == f"{PREFIX}.{suffix}"


def validate_core_definitions(documents: dict[str, dict[str, Any]]) -> None:
    defs_document = documents[f"{PREFIX}.defs.json"]
    defs = defs_document["defs"]
    security_profile = defs_document.get("description", "")
    for phrase in (
        "signedAt in [T-300 seconds,T+60 seconds]",
        "standard ATProto inter-service authentication",
        "issuer is the account DID",
        "audience is the exact MLS service reference",
        "lxm is the endpoint NSID",
        "jti is one-use",
        "client-generated device UUIDv4",
        "immutable Ed25519 keyId",
        "authGeneration",
        "exact completed idempotent replay",
        "actorDid#deviceId",
    ):
        assert phrase in security_profile, f"missing request security invariant: {phrase}"

    suite = defs["cipherSuite"]
    assert suite["type"] == "string" and suite.get("enum") == [SUITE]
    assert defs["protocolVersion"].get("enum") == ["1"]
    assert defs["lifecycle"].get("enum") == ["active", "superseded"]
    assert defs["conversationKind"].get("enum") == ["direct", "group"]
    assert defs["participantStatus"].get("enum") == ["pending", "active"]
    assert defs["incomingConsentPolicy"].get("enum") == ["all", "none", "following"]
    assert defs["welcomeStatus"].get("enum") == ["pending", "acknowledged", "rejected", "expired", "superseded"]
    assert defs["welcomeRejectionReason"].get("enum") == [
        "noMatchingKeyPackage", "invalidWelcome", "unsupportedCipherSuite",
        "coordinateMismatch", "localStateConflict",
    ]
    assert defs["leafRecoveryStatus"].get("enum") == ["open", "fulfilled", "cancelled", "expired", "superseded"]
    assert defs["recoveryWorkSourceKind"].get("enum") == ["welcomeExpired", "welcomeRejected"]
    assert defs["recoveryWorkStatus"].get("enum") == ["pending", "completed", "superseded"]
    assert defs["leaveRequestStatus"].get("enum") == ["pending", "fulfilled", "cancelled", "expired", "stale"]
    assert defs["resetReason"].get("enum") == [
        "localStateLost", "poisonedState", "epochDivergence", "manualRecovery",
    ]
    encoded_defs = json.dumps(defs, sort_keys=True)
    assert "joinFailure" not in encoded_defs
    assert encoded_defs.count('"poisonedState"') == 1

    coordinates = defs["conversationCoordinates"]
    assert required(coordinates) == COORDINATE_FIELDS
    for field in ("generation", "stateVersion", "epoch"):
        value = coordinates["properties"][field]
        assert value["type"] == "integer" and value["minimum"] == 0 and value["maximum"] == SAFE_INTEGER_MAX
    for field in ("groupId", "groupContextHash", "confirmationTag"):
        value = coordinates["properties"][field]
        assert value["type"] == "bytes" and value["minLength"] == 32 and value["maxLength"] == 32

    for union_name, expected_variants in CLOSED_UNIONS.items():
        union = defs[union_name]
        assert union["type"] == "union" and union.get("closed") is True
        assert {local_ref_name(ref) for ref in union["refs"]} == expected_variants

    artifacts = {
        "keyPackageArtifact": ("mlsMessage", "keyPackage", 8),
        "publicCommit": ("mlsMessage", "publicMessageCommit", 8),
        "groupInfoArtifact": ("mlsMessage", "groupInfo", 8),
        "privateApplicationMessage": ("mlsMessage", "privateMessageApplication", 8),
    }
    for name, (framing, content_type, minimum_bytes) in artifacts.items():
        artifact = defs[name]
        assert required(artifact) >= {"framing", "contentType", "bytes"}
        assert artifact["properties"]["framing"].get("const") == framing
        assert artifact["properties"]["contentType"].get("const") == content_type
        assert artifact["properties"]["bytes"]["minLength"] == minimum_bytes
        assert artifact["properties"]["bytes"]["maxLength"] <= 1_048_576
    public_commit_description = defs["publicCommit"].get("description", "")
    assert "structurally validates suite-specific XWing update-path ciphertext" in public_commit_description
    assert "does not prove that any recipient can decrypt" in public_commit_description

    key_package = defs["keyPackageArtifact"]
    assert required(key_package) == {"framing", "contentType", "bytes", "sha256", "keyPackageRef"}
    assert key_package["properties"]["bytes"]["maxLength"] == 65_536
    key_ref = key_package["properties"]["keyPackageRef"]
    assert key_ref["type"] == "bytes" and key_ref["minLength"] == key_ref["maxLength"] == 32

    welcome = defs["welcomeBundle"]
    assert required(welcome) == {"welcomeId", "framing", "contentType", "opaqueWelcome", "sha256", "deliveries"}
    assert welcome["properties"]["framing"].get("const") == "mlsMessage"
    assert welcome["properties"]["contentType"].get("const") == "welcome"
    deliveries = welcome["properties"]["deliveries"]
    assert deliveries["type"] == "array" and deliveries["minLength"] == deliveries["maxLength"] == 1
    delivery = defs["welcomeDelivery"]
    assert required(delivery) == {"recipientDid", "recipientDeviceId", "provenance"}
    assert_ref(delivery["properties"]["provenance"], "recoveryWelcomeProvenance")
    assert required(defs["recoveryWelcomeProvenance"]) == {"recoveryRequestId", "keyPackageRef"}
    welcome_view_description = defs["welcomeView"].get("description", "")
    assert "exact consumed Add KeyPackage not_after" in welcome_view_description
    assert "immutable recipient row" in welcome_view_description
    assert "compare-and-set terminal race" in welcome_view_description
    for misplaced in ("participantChanges", "leafChanges", "reservationIds", "Inputs are rejected rather than sorted"):
        assert misplaced not in welcome_view_description

    capability = defs["deviceCapability"]
    assert capability["properties"]["externalPubGroupInfo"].get("const") == "presentButExternalCommitsForbidden"
    assert "exactly [ratchet_tree, external_pub]" in capability.get("description", "")

    for body_name, manifest_name in (("creationBody", "creationManifest"), ("resetActivationBody", "resetActivationManifest")):
        body = defs[body_name]
        assert "genesisGroupInfo" in required(body)
        assert "bootstrapProof" not in body["properties"]
        assert_ref(body["properties"]["genesisGroupInfo"], "groupInfoArtifact")
        manifest = defs[manifest_name]
        assert required(manifest) == {"participants", "actorLeaf"}
        assert "selectedLeaves" not in manifest["properties"] and "reservationIds" not in manifest["properties"]

    aad_prior = defs["mlsAadPriorContext"]
    assert required(aad_prior) == COORDINATE_FIELDS
    assert_ref(aad_prior["properties"]["conversationId"], "identifierBytes")
    for aad_name, operation_field in (("commitAad", "transitionId"), ("applicationAad", "messageId")):
        aad = defs[aad_name]
        assert_ref(aad["properties"]["conversationId"], "identifierBytes")
        assert_ref(aad["properties"][operation_field], "identifierBytes")
        assert_ref(aad["properties"]["prior"], "mlsAadPriorContext")
    assert set(defs["commitAad"]["properties"]) == required(defs["commitAad"])
    assert "reservationIntentDigest" not in defs["commitAad"]["properties"]

    for body_name in ("applicationSendBody", "typingBody"):
        assert "idempotencyKey" not in defs[body_name]["properties"]
        assert "idempotencyKey" not in required(defs[body_name])
    assert "metadataSnapshot" in required(defs["commitTransitionBody"])

    assert "blobBinding" not in defs
    binding_fields = {"blobId", "ciphertextSha256", "ciphertextSize", "purpose"}
    for binding_name in (
        "uploadedBlobBinding", "applicationAttachmentBinding", "metadataAvatarBinding",
    ):
        binding = defs[binding_name]
        assert required(binding) == binding_fields
        assert set(binding["properties"]) == binding_fields
    assert_ref(defs["uploadedBlobBinding"]["properties"]["purpose"], "blobPurpose")
    assert defs["applicationAttachmentBinding"]["properties"]["purpose"] == {
        "type": "string", "const": "attachment",
    }
    assert defs["metadataAvatarBinding"]["properties"]["purpose"] == {
        "type": "string", "const": "metadata",
    }
    assert_ref(
        defs["applicationSendBody"]["properties"]["blobBindings"]["items"],
        "applicationAttachmentBinding",
    )
    assert_ref(
        defs["metadataSnapshot"]["properties"]["avatarBinding"],
        "metadataAvatarBinding",
    )

    for image_name in ("encryptedImageEmbed", "metadataAvatarEmbed"):
        image = defs[image_name]
        assert image["properties"]["algorithm"].get("const") == "A256GCM"
        assert image["properties"]["altText"]["maxLength"] == 4_096
        assert image["properties"]["blurhash"] == {
            "type": "string", "minLength": 6, "maxLength": 256,
        }
    assert defs["encryptedImageEmbed"]["properties"]["mimeType"].get("enum") == [
        "image/heic", "image/jpeg", "image/png", "image/webp", "image/gif",
    ]
    assert defs["metadataAvatarEmbed"]["properties"]["mimeType"].get("enum") == [
        "image/heic", "image/jpeg", "image/png", "image/webp",
    ]
    for encrypted_embed_name in (
        "encryptedImageEmbed", "encryptedAudioEmbed", "metadataAvatarEmbed",
    ):
        description = defs[encrypted_embed_name].get("description", "")
        assert "ciphertextSize == plaintextSize + 16" in description
        assert "checked safe-integer arithmetic" in description
        assert "appended 16-byte AES-GCM tag" in description
    atproto_description = defs["atprotoRecordEmbed"].get("description", "")
    assert "deliberately unescaped restricted canonical AT URI" in atproto_description
    assert defs["atprotoRecordEmbed"]["properties"]["uri"]["maxLength"] == 1_097
    assert "at most 1097 ASCII bytes" in atproto_description
    assert "exact lowercase at:// scheme" in atproto_description
    assert "no percent sign or escape anywhere" in atproto_description
    assert "hostname-level did:web" in atproto_description
    assert "normalized lowercase production handle" in atproto_description
    assert "record key equal to . or .." in atproto_description
    assert "no query, fragment, trailing slash, duplicate slash" in atproto_description
    assert "Parser acceptance or round-trip alone is not canonicality proof" in atproto_description
    assert "path/port/IP/single-label/localhost" in atproto_description
    assert "handle.invalid is not an authority" in atproto_description
    assert "canonical round-trip CID text" in atproto_description
    assert "reserialization byte-equals" in atproto_description
    external_description = defs["externalLinkEmbed"].get("description", "")
    for phrase in (
        "absolute HTTPS URI", "nonempty host", "no userinfo", "no backslash",
        "no whitespace or control character", "valid port when present",
        "valid percent encoding",
    ):
        assert phrase in external_description
    assert required(defs["externalLinkEmbed"]) == {"uri"}
    reaction_description = defs["reactionFrameBody"].get("description", "")
    assert "Unicode 17.0.0 NFC" in reaction_description
    assert "exactly one Unicode 17.0.0 UAX #29 extended grapheme cluster" in reaction_description
    assert "control-free" in reaction_description

    avatar = defs["metadataAvatarEmbed"]
    assert {"originTransitionId", "originalMetadataVersion"} <= required(avatar)
    avatar_aad = defs["metadataAvatarBlobAad"]
    assert required(avatar_aad) == {
        "protocol", "conversationId", "originTransitionId", "originalMetadataVersion",
        "blobId", "purpose", "mediaType", "plaintextSize",
    }

    leaf = defs["deviceLeaf"]
    assert required(leaf) == {"userDid", "deviceId", "leafOrigin"}
    assert "joinKeyPackageRef" in leaf["properties"]
    assert defs["leafOrigin"].get("enum") == ["genesis", "keyPackage"]
    recovery_reservation = defs["leafRecoveryReservation"]
    assert "recoveryRequestId" in required(recovery_reservation)
    assert "boundCoordinate" in required(recovery_reservation)
    assert "prior" not in recovery_reservation["properties"]
    assert_ref(recovery_reservation["properties"]["boundCoordinate"], "conversationCoordinates")
    assert "requestLeafRecovery, boundCoordinate equals the signed prior" in recovery_reservation.get("description", "")
    assert "acceptConversation, it equals the exact post-acceptance next coordinate, never prior" in recovery_reservation.get("description", "")
    for forbidden in ("reservationId", "transitionId", "intentDigest"):
        assert forbidden not in recovery_reservation["properties"]
    assert_ref(defs["leafRecoveryView"]["properties"]["reservation"], "leafRecoveryReservation")
    assert "boundCoordinate" in required(defs["leafRecoveryView"])
    assert "prior" not in defs["leafRecoveryView"]["properties"]
    assert_ref(defs["leafRecoveryView"]["properties"]["boundCoordinate"], "conversationCoordinates")
    assert recovery_reservation["properties"]["purpose"].get("const") == "leafRecovery"
    recovery_work_required = {
        "recoveryWorkId", "conversationId", "recipientDid", "recipientDeviceId",
        "sourceKind", "sourceId", "sourceCoordinate", "status", "createdAt",
    }
    recovery_work_variants = {
        "recoveryWorkPendingView": ("pending", set()),
        "recoveryWorkCompletedByTransitionView": (
            "completed", {"terminalTransitionId", "terminalAt"},
        ),
        "recoveryWorkSupersededByTransitionView": (
            "superseded", {"terminalTransitionId", "terminalAt"},
        ),
        "recoveryWorkSupersededByRevocationView": (
            "superseded", {"terminalRevocationId", "terminalAt"},
        ),
    }
    assert set(recovery_work_variants) == RECOVERY_WORK_VARIANTS
    assert {status for status, _ in recovery_work_variants.values()} == set(
        defs["recoveryWorkStatus"]["enum"]
    )
    for variant_name, (status, terminal_fields) in recovery_work_variants.items():
        variant = defs[variant_name]
        assert variant["type"] == "object"
        assert required(variant) == recovery_work_required | terminal_fields
        assert set(variant["properties"]) == recovery_work_required | terminal_fields
        assert_ref(variant["properties"]["recoveryWorkId"], "operationId")
        assert_ref(variant["properties"]["conversationId"], "operationId")
        assert_ref(variant["properties"]["recipientDid"], "bareDid")
        assert_ref(variant["properties"]["recipientDeviceId"], "deviceId")
        assert_ref(variant["properties"]["sourceKind"], "recoveryWorkSourceKind")
        assert_ref(variant["properties"]["sourceId"], "operationId")
        assert_ref(variant["properties"]["sourceCoordinate"], "conversationCoordinates")
        assert variant["properties"]["status"] == {"type": "string", "const": status}
        assert_ref(variant["properties"]["createdAt"], "canonicalDatetime")
        if "terminalTransitionId" in terminal_fields:
            assert_ref(variant["properties"]["terminalTransitionId"], "operationId")
        if "terminalRevocationId" in terminal_fields:
            assert_ref(variant["properties"]["terminalRevocationId"], "operationId")
        if "terminalAt" in terminal_fields:
            assert_ref(variant["properties"]["terminalAt"], "canonicalDatetime")

    recovery_work = defs["recoveryWorkView"]
    recovery_inbox = defs["leafRecoveryInboxItem"]
    for union in (recovery_work, recovery_inbox):
        assert union["type"] == "union" and union.get("closed") is True
        for ref in union["refs"]:
            assert defs[local_ref_name(ref)]["type"] == "object", (
                "a public union must directly reference concrete object variants"
            )
    assert {local_ref_name(ref) for ref in recovery_work["refs"]} == RECOVERY_WORK_VARIANTS
    assert {local_ref_name(ref) for ref in recovery_inbox["refs"]} == {
        "leafRecoveryView", *RECOVERY_WORK_VARIANTS,
    }
    recovery_work_description = recovery_work.get("description", "")
    for phrase in (
        "four concrete object variants",
        "pending has no terminal fields",
        "completed-by-transition requires exactly terminalTransitionId plus terminalAt",
        "superseded-by-transition requires exactly terminalTransitionId plus terminalAt",
        "superseded-by-revocation requires exactly terminalRevocationId plus terminalAt",
        "exact recipient DID/device",
        "does not authorize recovery",
        "does not grant application history",
        "does not prove MLS poison or decryptability failure",
    ):
        assert phrase in recovery_work_description
    revocation_work_description = defs["recoveryWorkSupersededByRevocationView"].get(
        "description", ""
    )
    for phrase in (
        "target DID byte-equals recipientDid",
        "target device ID byte-equals recipientDeviceId",
        "same-DID sibling-device revocation rejects",
    ):
        assert phrase in revocation_work_description
    finalized = defs["transitionManifest"]
    assert required(finalized) == {"participantChanges", "leafChanges"}
    assert "target-device-signed" in finalized.get("description", "")
    assert "exactly one addLeafByRecovery" in finalized.get("description", "")
    assert (
        "userDid exact UTF-8 bytes, deviceId raw UUID bytes, operation rank"
        in finalized.get("description", "")
    )
    assert (
        "removeLeaf before addLeafByRecovery for the same (userDid, deviceId)"
        in finalized.get("description", "")
    )
    assert {local_ref_name(ref) for ref in defs["leafChange"]["refs"]} == {"addLeafByRecovery", "removeLeaf"}
    for removed_name in (
        "reservationPurpose", "reservationRecipient", "keyPackageReservation",
        "reservationIntentBody", "reservationCancellationBody", "plannedAddLeaf",
        "plannedRemoveLeaf", "plannedLeafChange", "plannedTransitionManifest",
        "addLeafByReservation", "membershipWelcomeProvenance", "welcomeProvenance",
        "signedReservationIntent", "signedReservationCancellation",
    ):
        assert removed_name not in defs

    for name in ("deviceEnrollmentBody", "keyPackageReplenishmentBody"):
        description = defs[name].get("description", "")
        assert "computed raw KeyPackageRef" in description
        assert "not_before < T < not_after" in description
        assert "2595600" in description
        packages = defs[name]["properties"]["keyPackages"]
        assert packages["minLength"] == 1 and packages["maxLength"] == 100
    assert "min(T+300, KeyPackage not_after)" not in json.dumps(defs)  # endpoint prose owns reservation TTL

    device_view = defs["deviceView"]
    assert "deviceDid" not in device_view["properties"]
    assert "deviceDid" not in defs["addressableDevice"]["properties"]
    assert device_view["properties"]["availablePackageCount"]["maximum"] == 1000
    assert device_view["properties"]["reservedPackageCount"]["maximum"] == 1000
    assert "at most 1000 live nonterminal" in device_view.get("description", "")

    state = defs["conversationState"]
    assert "conversationKind" in required(state)
    assert_ref(state["properties"]["conversationKind"], "conversationKind")
    assert state["properties"]["participants"]["minLength"] == 1
    assert state["properties"]["participants"]["maxLength"] == 100
    assert state["properties"]["leaves"]["minLength"] == 1
    assert state["properties"]["leaves"]["maxLength"] == 100
    assert "snapshotSeq" in required(state) and "afterSeq" not in state["properties"]
    assert "not a caller entry cursor" in state.get("description", "")
    assert "at least one active admin" in state.get("description", "")
    assert "never inferred from participant count" in state.get("description", "")
    participant = defs["participant"]
    assert required(participant) == {"userDid", "role", "status"}
    assert "invitationProvenance" in participant["properties"]
    assert "pending/admin/zero-leaf" in participant.get("description", "")
    add_participant = defs["addParticipant"]
    assert add_participant["properties"]["role"].get("const") == "member"
    assert add_participant["properties"]["status"].get("const") == "pending"
    assert "Direct conversations forbid addParticipant" in add_participant.get("description", "")
    tombstone = defs["conversationRemovalTombstone"]
    assert {"membershipIntervalId", "userDid", "deviceId", "terminalSeq"} <= required(tombstone)
    assert "opening creation, reset activation, or Add transition ID" in tombstone.get("description", "")
    assert "another leaf of the same DID never extends it" in tombstone.get("description", "")
    access_ended = defs["accessEndedEvent"]
    assert {"membershipIntervalId", "userDid", "deviceId", "terminalSeq"} <= required(access_ended)

    assert "generation 0, stateVersion 0, epoch 0" in defs["creationBody"].get("description", "")
    assert "conversationKind" in required(defs["creationBody"])
    assert "conversationKind" in required(defs["resetActivationBody"])
    assert "exactly creator plus one pending admin-role invitee" in defs["creationBody"].get("description", "")
    assert "ordinary Commit" in defs["leafRecoveryFulfillmentBody"].get("description", "")
    commit_description = defs["commitTransitionBody"].get("description", "")
    assert "generic signedCommitTransition requires zero Add proposals and zero membership changes" in commit_description
    assert "only signedLeafRecoveryFulfillment may contain exactly one request-bound Add" in commit_description
    assert "confirmation tag also differs" in commit_description
    assert "must byte-equal the parsed authenticated Commit" in commit_description
    assert "does not cryptographically derive or verify that secret confirmation MAC" in commit_description
    assert "confirmation tag are freshly derived" not in commit_description
    assert "stateVersion increments by exactly one" in defs["policyTransitionBody"].get("description", "")
    assert "metadataVersion is exactly the prior metadataVersion plus one" in defs["metadataTransitionBody"].get("description", "")
    reset_description = defs["resetActivationBody"].get("description", "")
    assert "generation = prior.generation + 1" in reset_description
    assert "need not be an old-generation leaf" in reset_description
    assert "immutable conversationKind" in reset_description
    assert "does not derive or verify the secret confirmation MAC" in reset_description

    enrollment_description = defs["deviceEnrollmentBody"].get("description", "")
    for phrase in (
        "standard ATProto service auth for actorDid",
        "Ed25519-signed canonical body",
        "absent device row and tombstone",
        "expectedAuthGeneration zero",
        "client-generated canonical UUIDv4 deviceId",
        "keyId matching signaturePublicKey",
        "BasicCredential identity is exactly actorDid#deviceId",
        "strictly ordered by computed raw KeyPackageRef",
        "not_before < T < not_after",
        "at most 2595600 seconds",
        "atomically persists the device, immutable signing key, packages, and exact idempotent response",
    ):
        assert phrase in enrollment_description
    assert "deviceAuthenticationRebindBody" not in defs

    metadata_exporter = defs["metadataExporterContext"]
    assert required(metadata_exporter) == {
        "protocol", "version", "conversationId", "generation", "epoch",
        "groupContextHash", "metadataVersion",
    }
    assert_ref(metadata_exporter["properties"]["conversationId"], "identifierBytes")
    assert metadata_exporter["properties"]["metadataVersion"] == {
        "type": "integer", "minimum": 1, "maximum": SAFE_INTEGER_MAX,
    }
    exporter_description = metadata_exporter.get("description", "")
    assert "metadataVersion is included" in exporter_description
    assert "different metadata versions in one MLS epoch may derive different keys" in exporter_description
    assert "metadataVersion" not in exporter_description.split("forbidden", 1)[-1]
    metadata_aad = defs["metadataAad"]
    assert required(metadata_aad) == {
        "protocol", "version", "coordinate", "metadataVersion",
        "originTransitionId", "ciphertextSize",
    }
    assert_ref(metadata_aad["properties"]["coordinate"], "metadataCryptoContext")
    assert_ref(metadata_aad["properties"]["originTransitionId"], "identifierBytes")
    assert "authorProof" in required(defs["metadataSnapshot"])
    assert_ref(defs["metadataSnapshot"]["properties"]["authorProof"], "metadataAuthorProof")
    metadata_snapshot_description = defs["metadataSnapshot"].get("description", "")
    assert "MetadataNonceReuse" in metadata_snapshot_description
    assert "(conversationId,generation,epoch,nonce)" in metadata_snapshot_description
    assert "defense-in-depth" in metadata_snapshot_description
    assert "subsumes nonce uniqueness" in metadata_snapshot_description
    assert "avatarBinding, when present, is the exact metadataAvatarBinding with purpose metadata" in metadata_snapshot_description
    assert "applicationAttachmentBinding and generic uploadedBlobBinding are forbidden" in metadata_snapshot_description
    assert "All snapshots in the exact (conversationId,generation,epoch) share that key" not in metadata_snapshot_description
    assert required(defs["metadataAuthorProof"]) >= {
        "authorDid", "authorDeviceId", "authorKeyId", "signaturePublicKey",
        "originTransitionId", "originSeq", "roleAtOrigin", "deviceStatusAtOrigin",
    }
    assert defs["applicationSendBody"]["properties"]["blobBindings"]["maxLength"] == 1
    send_description = defs["applicationSendBody"].get("description", "")
    assert "canonical request digest is raw SHA-256" in send_description
    assert "64-byte signature is stored separately" in send_description
    assert "Raw JSON or generated DTO bytes are never hashed" in send_description
    assert "blobBindings contains zero or one exact applicationAttachmentBinding with purpose attachment" in send_description
    assert "metadataAvatarBinding and generic uploadedBlobBinding are forbidden" in send_description
    application_entry = defs["applicationEntry"]
    assert required(application_entry) == {
        "entryId", "conversationId", "seq", "signedRequest", "receivedAt",
    }
    assert set(application_entry["properties"]) == required(application_entry)
    assert_ref(application_entry["properties"]["signedRequest"], "signedApplicationSend")
    for duplicated_unsigned_field in (
        "actorDid", "actorDeviceId", "coordinates", "messageId",
        "applicationMessage", "blobBindings",
    ):
        assert duplicated_unsigned_field not in application_entry["properties"]
    application_entry_description = application_entry.get("description", "")
    for phrase in (
        "conversationId must byte-equal signedRequest.body.prior.conversationId",
        "verify its 64-byte Ed25519 signature",
        "CATBIRD-CHAT-MESSAGE\\0 canonical signing transcript",
        "before decryption, attribution, display, or effects",
        "CATBIRD-CHAT-APPLICATION-ENTRY-FINGERPRINT\\0",
        "{entryId: UUID bytes16, conversationId: UUID bytes16, seq: safe integer, requestDigest: bytes32, signature: bytes64, receivedAt: canonical text}",
        "requestDigest is raw SHA-256 of the exact send signing transcript",
        "Raw JSON, generated DTO bytes, plaintext-only digests, and unsigned outer surrogates are forbidden",
    ):
        assert phrase in application_entry_description

    conversation_entry = defs["conversationEntry"]
    assert conversation_entry["type"] == "union" and conversation_entry.get("closed") is True
    assert {f"{PREFIX}.defs#{local_ref_name(ref)}" for ref in conversation_entry["refs"]} == {
        f"{PREFIX}.defs#applicationEntry",
        *CONTROL_ENTRY_FINGERPRINT_KINDS,
    }
    control_fingerprint_description = conversation_entry.get("description", "")
    for phrase in (
        "CATBIRD-CHAT-CONTROL-ENTRY-FINGERPRINT\\0",
        "{entryKind,entryId:bytes16,conversationId:bytes16,seq:positive-safe-integer,requestDigest:bytes32,signature:bytes64,serverFields,receivedAt:canonical-text}",
        "exact full type ID",
        "requestDigest is raw SHA-256 of the exact variant domain-prefixed canonical unsigned signing transcript",
        "serverFields is always present",
        "{recovery: exact #leafRecoveryView}",
        "{tombstone: exact #conversationCloseTombstone}",
        "Unknown, missing, or extra fields reject",
        "historical Ed25519 signature",
        "before fingerprinting",
        "Every nested closed-union value in an unsigned signing projection carries its exact full $type",
        "Missing, wrong, or unknown nested tags reject before signature acceptance",
        "Raw JSON, generated DTO bytes, and signature-containing wrapper bytes are forbidden",
    ):
        assert phrase in control_fingerprint_description

    common_control_fields = {"entryId", "conversationId", "seq", "signedRequest", "receivedAt"}
    for entry_kind, (signed_request_ref, server_field) in CONTROL_ENTRY_FINGERPRINT_KINDS.items():
        entry = defs[entry_kind.split("#", 1)[1]]
        expected_fields = common_control_fields | ({server_field} if server_field else set())
        assert required(entry) == expected_fields
        assert set(entry["properties"]) == expected_fields
        assert_ref(entry["properties"]["signedRequest"], signed_request_ref)
    leave_cancellation = defs["leaveCancellationBody"]
    assert "conversationId" in required(leave_cancellation)
    assert_ref(leave_cancellation["properties"]["conversationId"], "operationId")
    leave_cancellation_description = leave_cancellation.get("description", "")
    for phrase in (
        "conversationId must byte-equal the cancellation entry row conversationId",
        "exact retained authenticated leaveRequestEntry",
        "referenced body leaveRequestId must byte-equal this leaveRequestId",
        "referenced row and body conversationId must byte-equal this conversationId",
        "actorDid must byte-equal the referenced requester actorDid",
        "another currently active registered device of that same DID",
        "own key, authentication generation, canonical transcript, and Ed25519 signature",
        "Missing, wrong-type, wrong-ID, cross-conversation, and wrong-requester references reject",
        "leaveRequestId is the exact globally resolved signed request key",
        "retained reference entry is distinct and has seq strictly less than cancellation seq",
        "Same-seq, later, and self-reference reject",
        "retained reference remains independently verifiable",
    ):
        assert phrase in leave_cancellation_description
    assert "24 hours" in defs["leaveRequestBody"].get("description", "")
    assert "last active admin" in defs["leaveRequestBody"].get("description", "")
    assert "different DID" in defs["leaveCommitFulfillmentBody"].get("description", "")
    assert "Group-only immediate self-removal" in defs["zeroLeafLeaveBody"].get("description", "")
    recovery_request_description = defs["leafRecoveryRequestBody"].get("description", "")
    assert "poisoned honest client can sign replace outside MLS" in recovery_request_description
    assert "poison is not server-visible" in recovery_request_description
    recovery_fulfillment_description = defs["leafRecoveryFulfillmentBody"].get("description", "")
    assert "Honest poison containment selects a healthy different-DID fulfiller" in recovery_fulfillment_description
    assert "server enforces only different-current-leaf" in recovery_fulfillment_description
    assert "never backfills history" in recovery_fulfillment_description
    acceptance = defs["participantAcceptanceBody"]
    assert {"recoveryRequestId", "invitationProvenance", "prior", "next"} <= required(acceptance)
    assert "status becomes active and role is preserved" in acceptance.get("description", "")
    assert "every unordered roster pair" in acceptance.get("description", "")
    assert "exact post-acceptance next coordinate, never prior" in acceptance.get("description", "")
    assert "immediately superseding its own request" in acceptance.get("description", "")
    close = defs["conversationCloseBody"]
    assert {"conversationKind", "prior", "retired"} <= required(close)
    assert "has no successor" in close.get("description", "")
    assert "including the pending invitee" in close.get("description", "")
    assert "sole remaining logical participant" in close.get("description", "")
    for removed_name in ("leavePolicyFulfillmentBody", "signedLeavePolicyFulfillment", "leavePolicyFulfillmentEntry"):
        assert removed_name not in defs

    for signed_name, (body_name, domain) in SIGNED_PROJECTIONS.items():
        signed = defs[signed_name]
        assert signed["type"] == "object" and required(signed) == {"body", "signature"}
        body_union = signed["properties"]["body"]
        assert body_union["type"] == "union" and body_union.get("closed") is True
        assert {local_ref_name(ref) for ref in body_union["refs"]} == {body_name}
        signature = signed["properties"]["signature"]
        assert signature["type"] == "bytes" and signature["minLength"] == signature["maxLength"] == 64
        body = defs[body_name]
        assert body["type"] == "object" and "signature" not in body.get("properties", {})
        assert "signatureDomain" in required(body)
        assert "signedAt" in required(body)
        assert_ref(body["properties"]["signedAt"], "canonicalDatetime")
        assert body["properties"]["signatureDomain"].get("const") == domain

    assert defs["deviceId"]["type"] == "string" and defs["deviceId"]["minLength"] == defs["deviceId"]["maxLength"] == 36
    assert defs["operationId"]["type"] == "string" and defs["operationId"]["minLength"] == defs["operationId"]["maxLength"] == 36
    assert defs["keyId"]["type"] == "string" and defs["keyId"]["minLength"] == defs["keyId"]["maxLength"] == 43
    assert defs["canonicalDatetime"]["type"] == "string" and defs["canonicalDatetime"].get("format") == "datetime"
    bare_did = defs["bareDid"]
    assert bare_did["type"] == "string" and bare_did.get("format") == "did"
    assert bare_did["minLength"] == 12 and bare_did["maxLength"] == 261
    for phrase in (
        "hostname-level did:web", "at least two dot-separated labels",
        "alt, arpa, example, internal, invalid, local, localhost, onion, and test",
        "did:web path DIDs, ports, percent escapes, IP literals, single-label names",
        "12-261 bytes", "BasicCredential identity is 49-298 bytes",
    ):
        assert phrase in bare_did.get("description", "")


def validate_endpoint_contract(documents: dict[str, dict[str, Any]]) -> None:
    for name, kind in ENDPOINTS.items():
        document = endpoint_document(documents, name)
        main = document["defs"]["main"]
        assert main["type"] == kind
        errors = [entry["name"] for entry in main.get("errors", [])]
        assert len(errors) == len(set(errors)), f"{name} errors must be unique"
        assert "InvalidDPoP" not in errors, f"{name} must not expose retired custom DPoP"
        if name != "subscribeEvents":
            assert "AccountSessionExpired" in errors
            assert "ProtocolUpgradeRequired" in errors
        if kind == "procedure":
            if name == "uploadBlob":
                assert main["input"]["encoding"] == "application/octet-stream"
                assert "schema" not in main["input"]
            else:
                schema = endpoint_input(document)
                if name != "updatePushToken":
                    assert required(schema), f"{name} must have a typed input"
        if "output" in main:
            if main["output"]["encoding"] == "application/json":
                output = endpoint_output(document)
                if name not in {"getConversations"}:
                    assert "eventCursor" not in output.get("properties", {}), f"{name} must not advance event cursors"

    upload_output = endpoint_output(endpoint_document(documents, "uploadBlob"))
    assert required(upload_output) == {"binding", "uploadedAt"}
    assert_ref(upload_output["properties"]["binding"], "uploadedBlobBinding")

    get_devices_input = endpoint_input(endpoint_document(documents, "getDevices"))
    queried_dids = get_devices_input["properties"]["userDids"]["items"]
    assert queried_dids["format"] == "did"
    assert queried_dids["minLength"] == 12 and queried_dids["maxLength"] == 261

    refs = {
        "enrollDevice": "signedDeviceEnrollment",
        "replenishKeyPackages": "signedKeyPackageReplenishment",
        "revokeDevice": "signedDeviceRevocation",
        "prepareBlobUpload": "signedBlobUploadPreparation",
        "deleteBlob": "signedBlobDeletion",
        "createConversation": "signedCreation",
        "acceptConversation": "signedParticipantAcceptance",
        "closeConversation": "signedConversationClose",
        "sendMessage": "signedApplicationSend",
        "publishTyping": "signedTyping",
        "acknowledgeWelcome": "signedWelcomeAcknowledgement",
        "rejectWelcome": "signedWelcomeRejection",
        "requestLeafRecovery": "signedLeafRecoveryRequest",
        "cancelLeafRecovery": "signedLeafRecoveryCancellation",
        "requestReset": "signedResetRequest",
        "activateReset": "signedResetActivation",
        "requestLeave": "signedLeaveOperation",
        "cancelLeave": "signedLeaveCancellation",
    }
    for endpoint, signed_name in refs.items():
        schema = endpoint_input(endpoint_document(documents, endpoint))
        assert required(schema) == {"signedRequest"}
        assert_ref(schema["properties"]["signedRequest"], signed_name)
        errors = {entry["name"] for entry in endpoint_document(documents, endpoint)["defs"]["main"]["errors"]}
        assert "InvalidRequest" in errors, f"{endpoint} must reject an out-of-window signedAt"

    transition_input = endpoint_input(endpoint_document(documents, "submitTransition"))
    assert required(transition_input) == {"signedRequest"}
    assert_ref(transition_input["properties"]["signedRequest"], "signedTransition")
    transition_errors = {
        entry["name"] for entry in endpoint_document(documents, "submitTransition")["defs"]["main"]["errors"]
    }
    assert {
        "AdminRequired", "CoordinateOverflow", "DeviceNotLeaf", "InvalidWelcomeMapping",
        "LeafRecoveryNotFound", "LeafRecoveryExpired", "LeafRecoverySuperseded",
        "MetadataNonceReuse", "MetadataVersionOverflow", "BlockedRelationship",
        "RelationshipPolicyUnavailable", "DirectParticipantMutationForbidden",
    } <= transition_errors
    assert "InvalidRequest" in transition_errors
    assert "KeyPackageReservationConflict" not in transition_errors
    assert "KeyPackageReservationExpired" not in transition_errors

    creation_output = endpoint_output(endpoint_document(documents, "createConversation"))
    assert required(creation_output) == {"result"}
    assert_ref(creation_output["properties"]["result"], "conversationCreationResult")
    creation_errors = {entry["name"] for entry in endpoint_document(documents, "createConversation")["defs"]["main"]["errors"]}
    assert {
        "BlockedRelationship", "GroupInvitesDisabled", "InvitationLimitReached",
        "MessagesDisabled", "MetadataNonceReuse", "NotFollowedByRecipient",
        "RelationshipPolicyUnavailable",
    } <= creation_errors

    acceptance_output = endpoint_output(endpoint_document(documents, "acceptConversation"))
    assert required(acceptance_output) == {"coordinates", "entry", "recovery"}
    assert_ref(acceptance_output["properties"]["entry"], "participantAcceptanceEntry")
    assert_ref(acceptance_output["properties"]["recovery"], "leafRecoveryView")
    acceptance_errors = {entry["name"] for entry in endpoint_document(documents, "acceptConversation")["defs"]["main"]["errors"]}
    assert {
        "BlockedRelationship", "GroupInvitesDisabled", "InvitationNotPending",
        "InvitationProvenanceMismatch", "MessagesDisabled", "NotFollowedByRecipient",
        "RelationshipPolicyUnavailable",
    } <= acceptance_errors

    close_output = endpoint_output(endpoint_document(documents, "closeConversation"))
    assert required(close_output) == {"result"}
    assert_ref(close_output["properties"]["result"], "conversationCloseResult")
    close_description = endpoint_document(documents, "closeConversation").get("description", "")
    assert "sole remaining logical participant is an active admin" in close_description
    close_errors = {entry["name"] for entry in endpoint_document(documents, "closeConversation")["defs"]["main"]["errors"]}
    assert "ConversationCloseNotAllowed" in close_errors
    assert "BlockedRelationship" not in close_errors and "RelationshipPolicyUnavailable" not in close_errors

    leave_input = endpoint_input(endpoint_document(documents, "requestLeave"))
    assert_ref(leave_input["properties"]["signedRequest"], "signedLeaveOperation")
    leave_output = endpoint_output(endpoint_document(documents, "requestLeave"))
    assert_ref(leave_output["properties"]["result"], "leaveOperationResult")
    leave_errors = {entry["name"] for entry in endpoint_document(documents, "requestLeave")["defs"]["main"]["errors"]}
    assert "DirectParticipantMutationForbidden" in leave_errors
    assert "BlockedRelationship" not in leave_errors and "RelationshipPolicyUnavailable" not in leave_errors

    send_endpoint_description = endpoint_document(documents, "sendMessage").get("description", "")
    assert "exactly applicationAttachmentBinding with purpose attachment" in send_endpoint_description
    assert "metadataAvatarBinding or generic uploadedBlobBinding rejects" in send_endpoint_description
    assert "exact signedRequest rather than duplicated unsigned" in send_endpoint_description
    assert "entry conversationId must equal signedRequest.body.prior.conversationId" in send_endpoint_description
    assert "CATBIRD-CHAT-MESSAGE\\0 Ed25519 transcript" in send_endpoint_description
    assert "CATBIRD-CHAT-APPLICATION-ENTRY-FINGERPRINT\\0" in send_endpoint_description
    assert "requestDigest bytes32, signature bytes64" in send_endpoint_description
    assert "plaintext-only or unsigned substitutes are forbidden" in send_endpoint_description
    upload_endpoint_description = endpoint_document(documents, "uploadBlob").get("description", "")
    assert "uploadedBlobBinding result reports the prepared attachment or metadata purpose" in upload_endpoint_description
    assert "upload-result transport only and cannot inhabit either signed projection" in upload_endpoint_description
    send_errors = {entry["name"] for entry in endpoint_document(documents, "sendMessage")["defs"]["main"]["errors"]}
    assert {"DeviceNotLeaf", "BlockedRelationship", "RelationshipPolicyUnavailable", "ConversationNotAccepted", "RecipientNotReady"} <= send_errors
    typing_errors = {entry["name"] for entry in endpoint_document(documents, "publishTyping")["defs"]["main"]["errors"]}
    assert {"BlockedRelationship", "RelationshipPolicyUnavailable", "ConversationNotAccepted", "RecipientNotReady"} <= typing_errors
    recovery_errors = {entry["name"] for entry in endpoint_document(documents, "requestLeafRecovery")["defs"]["main"]["errors"]}
    assert {"BlockedRelationship", "RelationshipPolicyUnavailable"} <= recovery_errors

    ack_errors = {entry["name"] for entry in endpoint_document(documents, "acknowledgeWelcome")["defs"]["main"]["errors"]}
    assert "StaleCoordinates" not in ack_errors and "NotMember" not in ack_errors
    assert "AcknowledgementConflict" in ack_errors

    get_conversations = endpoint_document(documents, "getConversations")
    params = endpoint_input(get_conversations)
    assert set(params["properties"]) == {"actorDeviceId", "pageCursor", "limit"}
    assert "actorDeviceId" in required(params)
    assert "afterCursor" not in params["properties"]
    output = endpoint_output(get_conversations)
    assert {"items", "inventorySessionId", "snapshotEventCursor", "hasMore", "snapshotExpiresAt"} <= required(output)
    assert "nextPageCursor" in output["properties"] and "nextPageCursor" not in required(output)
    assert_ref(output["properties"]["items"]["items"], "conversationInventoryItem")

    for endpoint, item_ref in (
        ("getPendingWelcomes", "welcomeView"),
        ("getLeafRecoveryInbox", "leafRecoveryInboxItem"),
    ):
        document = endpoint_document(documents, endpoint)
        params = endpoint_input(document)
        assert {"inventorySessionId", "pageCursor", "limit"} <= set(params["properties"])
        assert "inventorySessionId" in required(params)
        output = endpoint_output(document)
        assert {"items", "inventorySessionId", "snapshotEventCursor", "hasMore", "snapshotExpiresAt"} <= required(output)
        assert "nextPageCursor" in output["properties"] and "nextPageCursor" not in required(output)
        assert_ref(output["properties"]["items"]["items"], item_ref)

    recovery_inbox_description = endpoint_document(documents, "getLeafRecoveryInbox").get("description", "")
    assert "flat closed exact-device recovery inbox" in recovery_inbox_description
    assert "Every union ref is a concrete object" in recovery_inbox_description
    assert "sourced only from retained expired or rejected Welcomes" in recovery_inbox_description

    own_devices = endpoint_document(documents, "getOwnDevices")
    own_device_params = endpoint_input(own_devices)
    assert set(own_device_params["properties"]) == {"actorDeviceId", "pageCursor", "limit"}
    own_device_output = endpoint_output(own_devices)
    assert {"items", "hasMore", "snapshotExpiresAt"} <= required(own_device_output)
    assert "inventorySessionId" not in own_device_output["properties"]
    assert "snapshotEventCursor" not in own_device_output["properties"]
    assert "nextPageCursor" in own_device_output["properties"] and "nextPageCursor" not in required(own_device_output)
    assert_ref(own_device_output["properties"]["items"]["items"], "ownDeviceView")

    state = endpoint_output(endpoint_document(documents, "getConversationState"))
    assert "pendingResetRequests" in required(state)
    assert "pendingLeaveRequests" in required(state)
    assert_ref(state["properties"]["state"], "conversationState")
    assert_ref(state["properties"]["pendingResetRequests"]["items"], "resetRequestView")
    assert_ref(state["properties"]["pendingLeaveRequests"]["items"], "leaveRequestView")

    entries = endpoint_input(endpoint_document(documents, "getEntries"))
    assert {"conversationId", "afterSeq", "limit"} <= required(entries)
    for endpoint in ("getConversationState", "getEntries"):
        conversation_id = endpoint_input(endpoint_document(documents, endpoint))["properties"]["conversationId"]
        assert conversation_id["type"] == "string"
        assert conversation_id["minLength"] == conversation_id["maxLength"] == 36
        assert "UUIDv4" in conversation_id.get("description", "")
    assert entries["properties"]["afterSeq"]["maximum"] == SAFE_INTEGER_MAX
    entry_description = endpoint_document(documents, "getEntries").get("description", "")
    assert "per concrete MLS leaf" in entry_description
    assert "server skips inaccessible gaps" in entry_description
    assert "nextAfterSeq is afterSeq when entries is empty" in entry_description
    assert "another caller-visible" in entry_description
    entries_output = endpoint_output(endpoint_document(documents, "getEntries"))
    assert required(entries_output) == {"entries", "nextAfterSeq", "hasMore"}
    assert "terminalSeq" not in entries_output["properties"]

    devices = endpoint_input(endpoint_document(documents, "getDevices"))["properties"]["userDids"]
    assert devices["minLength"] == 1 and devices["maxLength"] == 5
    ticket_input = endpoint_input(endpoint_document(documents, "getSubscriptionTicket"))
    assert required(ticket_input) == {"actorDeviceId", "inventorySessionId", "eventCursor"}
    subscribe = endpoint_document(documents, "subscribeEvents")
    assert "one-use short-lived getSubscriptionTicket token" in subscribe.get("description", "")
    assert "consumed atomically" in subscribe.get("description", "")

    enroll_description = endpoint_document(documents, "enrollDevice").get("description", "")
    assert "standard ATProto service-authenticated AppView request" in enroll_description
    assert "canonical Ed25519-signed body" in enroll_description
    assert "Existing login is sufficient" in enroll_description

    submit_description = endpoint_document(documents, "submitTransition").get("description", "")
    assert "Generic signedCommitTransition has zero Add proposals and zero membership changes" in submit_description
    assert "only signedLeafRecoveryFulfillment may contain exactly one" in submit_description


def validate_normative_prose() -> None:
    prose = PROTOCOL_PATH.read_text(encoding="utf-8")
    prose += "\n" + STANDARD_APPVIEW_ADR_PATH.read_text(encoding="utf-8")
    for required_phrase in (
        "not currently an IANA-assigned stable MLS ciphersuite codepoint",
        "requires a new internal chat protocol version",
        "exactly `[ratchet_tree, external_pub]`",
        "external commits",
        "There is no creation preparation endpoint",
        "epoch zero never invents or consumes a package",
        "never inherits application ciphertext",
        "A later title-only metadata version may reuse",
        "UTF8(signatureDomain including its terminal NUL)",
        "stateVersion=0",
        "There is no public general reservation API",
        "Every Add refines exactly one open request signed by the target device itself",
        "`conversationKind` is a closed `direct | group` discriminator",
        "existingDirectConversationResult",
        "`closeConversation` is the terminal escape hatch",
        "exact path `/xrpc/app.bsky.graph.getRelationships`",
        "`chat.bsky.actor.declaration`",
        "`blocking`, `blockedBy`, `blockingByList`, or `blockedByList`",
        "five live pending invitations",
        "100 newly created pending invitations per inviter",
        "100 live pending invitations per recipient",
        "no optional reservation, intent, digest, or recovery field",
        "MetadataNonceReuse",
        "separately locked current conversation head/append sequence",
        "cannot self-detect rollback of the whole database head and blob together",
        "admin-only",
        "one-use short-lived",
        "inventorySession",
        "record count `4`",
        "canonical base64url without padding whose exact decoding is 12–32 bytes",
        "configured trusted external base",
        "never derived from `Host`, `Forwarded`, or any `X-Forwarded-*` header",
        "lowercase ASCII/IDNA A-label",
        "`htu = base + exact /xrpc/{NSID}`",
        "one trusted server instant `T`",
        "`signedAt` must be in the inclusive interval `[T-300s,T+60s]`",
        "may bypass only the `signedAt` age check",
        "PDS service-auth JWT -> mls-ds",
        "derived from server `receivedAt`, never client `signedAt`",
        "typing TTL and every server-authored timestamp derive from `T`",
        "metadataVersion",
        "deliberately stronger defense-in-depth nonce rule",
        "post-acceptance `next` coordinate, never `prior`",
        "did:web:chat.catbird.blue#atproto_mls",
        "Nest does not mint MLS authorization, fabricate a device identifier, inspect canonical signed bodies, or rotate MLS device bindings",
        "whose `iss` is the account DID, `aud` exactly equals the service reference, and `lxm` exactly equals the requested NSID",
        "`iat` and `exp` must form a short-lived interval, `jti` is consumed once",
        "signature must resolve through the issuer DID's `#atproto` verification method",
        "authenticated service principal, signed body, and locked device row must agree",
        "Authenticated reads carry `actorDeviceId` in their Lexicon input",
        "A missing device row produces automatic enrollment",
        "Only a PDS account-session failure or an actual chat-permission denial may initiate login or permission-upgrade UI",
        "canonical request digest is the raw 32-byte SHA-256",
        "same bytes verified by Ed25519",
        "signature is stored and compared separately",
        "No digest is ever computed from raw JSON spelling",
        "production canonical bare ATProto DID of exactly 12–261 ASCII bytes",
        "BasicCredential identity, which is exactly UTF-8 `actorDid + \"#\" + deviceId` and therefore exactly 49–298 bytes",
        "parsed authenticated artifact, merged OpenMLS public state, signed `next`",
        "does not cryptographically derive or verify the confirmation MAC",
        "Recipients verify the secret confirmation tag after processing",
        "structurally validate every suite-specific XWing update-path ciphertext",
        "server acceptance never proves recipient decryptability",
        "poisoned victim authenticates outside MLS",
        "`recoveryWorkView` is a named closed union of four concrete object variants",
        "The recovery inbox item union is flat and closed",
        "never the union-valued `recoveryWorkView`",
        "Its source kind is exactly `welcomeExpired | welcomeRejected`",
        "Recovery work never authorizes recovery",
        "`terminalTransitionId + terminalAt`",
        "`terminalRevocationId + terminalAt`",
        "same-DID sibling-device revocation is invalid",
        "receives no history backfill",
        "malicious sole admin",
        "three-DID poison → victim-signed `replace`",
        "all-peers-poisoned active-admin reset and direct-close flows",
        "Catbird Chat Application Content Protocol v1",
        "docs/generated-artifacts/chat-application-v1/manifest.json",
        "applicationEntry = {entryId,conversationId,seq,signedRequest,receivedAt}",
        "no duplicated unsigned actor, device, coordinate, message-ID, application-artifact, or blob-binding fields",
        "`entry.conversationId` MUST equal `signedRequest.body.prior.conversationId`",
        "verifies the 64-byte Ed25519 signature over the exact `CATBIRD-CHAT-MESSAGE\\0` canonical signing transcript before decrypting",
        "CATBIRD-CHAT-APPLICATION-ENTRY-FINGERPRINT\\0",
        "{entryId:bytes16,conversationId:bytes16,seq,requestDigest:bytes32,signature:bytes64,receivedAt:canonical-text}",
        "`requestDigest` is the already-frozen raw SHA-256 of that exact send signing transcript",
        "Raw transport JSON, generated DTO serialization, plaintext-only digests, and unsigned outer surrogates are forbidden substitutes",
        "encrypted-image MIME set is exactly `image/heic | image/jpeg | image/png | image/webp | image/gif`",
        "Optional blurhash is exactly 6–256 UTF-8 bytes",
        "Message attachments instead use `applicationAttachmentBinding`, whose purpose is structurally fixed to `attachment`",
        "A metadata avatar uses the distinct `metadataAvatarBinding`, whose purpose is structurally fixed to `metadata`",
        "returns `uploadedBlobBinding`, whose purpose reflects the prepared `attachment | metadata` value",
        "checked arithmetic requires `ciphertextSize == plaintextSize + 16`",
        "A reaction value uses Unicode 17.0.0 NFC",
        "exactly one UAX #29 extended grapheme cluster under Unicode 17.0.0",
        "deliberately unescaped restricted canonical AT URI",
        "at most exactly 1,097 ASCII bytes",
        "no percent sign/escape anywhere",
        "record key equal to `.` or `..`",
        "Parser acceptance or round-trip alone is not canonicality proof",
        "hostname-level `did:web` using the same normalized lowercase production handle-shaped hostname",
        "path/port/IP/single-label/`localhost` forms",
        "`handle.invalid` is not accepted here",
        "External links retain their separate 2,048-byte cap",
        "including canonical CIDv0 where applicable",
        "invalid port",
        "A metadata avatar uses the distinct `metadataAvatarBinding`",
        "Its descriptor also requires checked `ciphertextSize == plaintextSize + 16`",
        "Each application reducer is permanently bound to one immutable `conversationId` and exact recipient",
        "`{openingSeq,openingKind,openingTransitionId,openingOuterEntryFingerprint,openingContext}`",
        "`{closingTransitionId,closingOuterEntryFingerprint,closeKind}`",
        "The only legal touching schedules are `Replace -> Add` and `Reset -> Reset`",
        "A finite inclusive `endSeq` is strictly greater than that interval's `openingSeq`",
        "equality is only between the prior interval's close seq and the successor interval's opening seq",
        "creation/open plus terminal close at that same seq",
        "`Remove` requires a strict later gap before Add, and terminal close has no successor",
        "registered active-admin reset activator who was not an old leaf",
        "tombstone/event/inventory `terminalSeq` is navigation/wakeup data only and is never close authority",
        "former device is entitled to the exact signed close control row at `terminalSeq`",
        "separate irreversible schedule-level terminal proof without rewriting the old interval close or granting gap history",
        "Terminal does not claim its `previous` equals the reducer's stale expected context",
        "Every historical exact-device recipient schedule also remains entitled to fetch the later exact signed Terminal control",
        "requires `previous == expected` before its exact verified `next` becomes expected",
        "The authenticated shared row is processed once",
        "every post-terminal row or reanchor are terminal invalid",
        "did:plc:[a-z2-7]{24}",
        "per exact authenticated `(DID,deviceId)` MLS leaf",
        "opening creation, reset-activation, or Add signed transition ID",
        "generic `signedCommitTransition` form has zero Add proposals and zero membership changes",
        "Only `signedLeafRecoveryFulfillment` may contain an Add",
        "sole remaining logical participant is an active admin",
        "statically configured canonical HTTPS AppView/direct-XRPC origin",
        "never forward caller `Authorization`, DPoP, cookies, `atproto-proxy`, or a Nest clean-chat token",
        "`relationships` must have exactly the requested target set once each",
        "`actor=recipient` with `inviter` included among that call's 1–30 `others`",
        "service ID `#atproto_pds`",
        "exact service type `AtprotoPersonalDataServer`",
        "Only a structured `com.atproto.repo.getRecord` `RecordNotFound` response",
        "parsed `uri` must be exactly `at://<recipient canonical DID>/chat.bsky.actor.declaration/self`",
        "exact `$type` is `chat.bsky.actor.declaration`",
        "open `knownValues`",
        "Network work never runs while holding the conversation mutation lock",
        "graph-call hard cap is `99 * 2 = 198`",
        "admission source-call hard cap is 396",
        "`completedAt` is assigned only after the final response has strictly validated",
        "never a fictitious upstream graph or PDS revision",
        "cannot linearize an external ATProto block write",
        "Policy evaluation fully collects and strictly validates the canonical evidence scope without denial short-circuit",
        "Deterministic precedence is:",
        "Every failure leaves zero conversation mutation, invitation count, package reservation, or idempotency-result residue",
        "conversationState.snapshotSeq",
        "exactly these 32 endpoints",
    ):
        assert required_phrase in prose, f"normative protocol missing phrase: {required_phrase}"

    forbidden_task1_tokens = (
        "reservationIntentDigest",
        "reserveKeyPackages",
        "cancelKeyPackageReservation",
        "planned-to-final",
        "exact intent digest",
        "authorizeAndBootstrapReset",
        "non-admin reset",
    )
    for path in TASK1_DOC_PATHS:
        if not path.is_file():
            continue
        source = path.read_text(encoding="utf-8")
        for forbidden in forbidden_task1_tokens:
            assert forbidden not in source, f"stale Task 1 token {forbidden!r} in {path}"
        for required in (
            "applicationAttachmentBinding",
            "metadataAvatarBinding",
            "uploadedBlobBinding",
            "ciphertextSize == plaintextSize + 16",
            "Unicode 17.0.0",
            "percent sign",
            "openingOuterEntryFingerprint",
            "closingOuterEntryFingerprint",
            "recipient",
            "Replace -> Add",
            "terminalSeq",
            "12–261",
            "49–298",
            "1,097",
            "reanchor",
        ):
            assert required in source, f"Task 1 document missing application repair token {required!r}: {path}"

    for path in AUTH_DECISION_DOC_PATHS:
        if not path.is_file():
            continue
        source = path.read_text(encoding="utf-8")
        for required in (
            "applicationAttachmentBinding",
            "metadataAvatarBinding",
            "uploadedBlobBinding",
            "ciphertextSize == plaintextSize + 16",
            "Unicode 17.0.0",
            "percent sign",
            "openingOuterEntryFingerprint",
            "closingOuterEntryFingerprint",
            "recipient",
            "Replace -> Add",
            "terminalSeq",
            "12–261",
            "49–298",
            "1,097",
            "reanchor",
        ):
            assert required in source, f"decision/Task 2 document missing application repair token {required!r}: {path}"

    if AUTH_DECISION_DOC_PATHS[-1].is_file():
        task2_brief = AUTH_DECISION_DOC_PATHS[-1].read_text(encoding="utf-8")
        for required in (
            "Source kind is closed to `welcomeExpired | welcomeRejected`",
            "The named `recoveryWorkView` is a closed union of four concrete object variants",
            "each repeating exactly `recoveryWorkId,conversationId,recipientDid,recipientDeviceId,sourceKind,sourceId,sourceCoordinate,status,createdAt` with a status const",
            "`getLeafRecoveryInbox` uses a flat closed union that directly references the unchanged signed-request/reservation `leafRecoveryView` plus the same four concrete recovery-work objects",
            "neither public union directly references another union",
        ):
            assert required in task2_brief, f"Task 2 recovery-work contract missing {required!r}"
        assert "expired/rejected/poisoned Welcome or deterministic join failure" not in task2_brief
        assert (
            "Malformed, out-of-bounds, misbound, unknown/duplicate/null, or signature-invalid attempts "
            "must leave the same capability unpinned, unburned, and usable by a later valid body"
        ) in task2_brief, "Task 2 must test that invalid pre-pin bodies cannot burn enrollment evidence"
        assert (
            "Use golden and one-field mutation vectors for the exact raw "
            "`SHA256(UTF8(\"CATBIRD-CHAT-APPLICATION-ENTRY-FINGERPRINT\\0\")"
        ) in task2_brief, "Task 2 must test the frozen application-entry fingerprint projection"
        assert "mutations to every entry scalar, signed-body field through `requestDigest`, and the separate signature" in task2_brief
    control_fingerprint_paths = (
        PROTOCOL_PATH,
        APPLICATION_PROTOCOL_PATH,
        STACK_ROOT / "docs/program/decisions/ADR-019-chat-protocol-clean-cutover.md",
        STACK_ROOT / "docs/superpowers/plans/2026-07-22-chat-protocol.md",
        STACK_ROOT / ".superpowers/sdd/mls-chat-task-1-report.md",
        STACK_ROOT / ".superpowers/sdd/mls-chat-task-2-brief.md",
    )
    control_entry_kinds = tuple(CONTROL_ENTRY_FINGERPRINT_KINDS)
    for path in control_fingerprint_paths:
        if not path.is_file():
            continue
        source = path.read_text(encoding="utf-8")
        normalized_source = " ".join(source.split())
        for required in (
            "CATBIRD-CHAT-CONTROL-ENTRY-FINGERPRINT\\0",
            "{entryKind,entryId:bytes16,conversationId:bytes16,seq:positive-safe-integer,requestDigest:bytes32,signature:bytes64,serverFields,receivedAt:canonical-text}",
            "{recovery: exact #leafRecoveryView}",
            "{tombstone: exact #conversationCloseTombstone}",
            "historical Ed25519",
            "recipient is not a fingerprint input",
            "`leaveCancellationBody` requires signed `conversationId`",
            "exact retained authenticated `leaveRequestEntry`",
            "`body.leaveRequestId`",
            "row/body conversation",
            "cancellation `actorDid`",
            "currently active registered device of the same DID",
            "own key, authentication generation, canonical transcript, and Ed25519 signature",
            "Missing, wrong-type, wrong-ID, cross-conversation, and wrong-requester",
            "`leaveRequestId` is the exact globally resolved signed request key",
            "reference is a distinct entry with `referenceSeq < cancellationSeq`",
            "same-seq, later, and self-reference",
            "requester device `70707070-7070-4070-b070-707070707070` under historical seed `0x91`",
            "same-DID cancellation device `72727272-7272-4272-b272-727272727272` under seed `0x92`",
            "retained reference remains independently verifiable",
            "nested closed-union value carries its exact full `$type`",
        ):
            assert required in normalized_source, (
                f"control-fingerprint contract missing {required!r}: {path}"
            )
        for entry_kind in control_entry_kinds:
            assert entry_kind in normalized_source, (
                f"control-fingerprint kind missing {entry_kind!r}: {path}"
            )

    auth_contract_paths = (
        PROTOCOL_PATH,
        *TASK1_DOC_PATHS,
        *AUTH_DECISION_DOC_PATHS,
        CANONICAL_ROOT / f"{PREFIX}.defs.json",
        CANONICAL_ROOT / f"{PREFIX}.enrollDevice.json",
        MIRROR_ROOT / f"{PREFIX}.defs.json",
        MIRROR_ROOT / f"{PREFIX}.enrollDevice.json",
    )
    forbidden_auth_claims = (
        "interactiveauthorizationonly",
        "sessionrefreshorcookieallowed",
        "newly completed interactive authorization",
        "new interactive authorization",
        "forced interactive reauthentication",
        "force interactive authorization",
        "implementation blocker",
        "same open capability",
        "atomically consumed once to mint one",
    )
    for path in auth_contract_paths:
        if not path.is_file():
            continue
        source = path.read_text(encoding="utf-8").lower()
        for forbidden in forbidden_auth_claims:
            assert forbidden not in source, f"stale enrollment-auth claim {forbidden!r} in {path}"

    application_contract_paths = (
        PROTOCOL_PATH,
        APPLICATION_PROTOCOL_PATH,
        *TASK1_DOC_PATHS,
        *AUTH_DECISION_DOC_PATHS,
        CANONICAL_ROOT / f"{PREFIX}.defs.json",
        CANONICAL_ROOT / f"{PREFIX}.sendMessage.json",
        MIRROR_ROOT / f"{PREFIX}.defs.json",
        MIRROR_ROOT / f"{PREFIX}.sendMessage.json",
    )
    forbidden_application_entry_claims = (
        "signed outer append entry supplies",
        "fingerprint of the complete immutable canonical signed outer entry",
        "complete canonical signed entry, including its entry identity and signature",
    )
    for path in application_contract_paths:
        if not path.is_file():
            continue
        source = path.read_text(encoding="utf-8").lower()
        for forbidden in forbidden_application_entry_claims:
            assert forbidden not in source, f"stale application-entry claim {forbidden!r} in {path}"

    if APPLICATION_PROTOCOL_PATH.is_file():
        selected_manifest, _ = application_manifest_path()
        assert selected_manifest.is_file(), f"missing application corpus manifest: {selected_manifest}"


def application_manifest_path() -> tuple[Path, bool]:
    override = os.environ.get(APPLICATION_MANIFEST_INPUT_ENV)
    return (Path(override), True) if override is not None else (APPLICATION_MANIFEST_PATH, False)


def strict_provenance_bytes(relative_path: str, *, require_utf8: bool) -> bytes:
    relative = Path(relative_path)
    assert relative_path and "\\" not in relative_path
    assert not relative.is_absolute()
    assert relative.as_posix() == relative_path
    assert all(part not in ("", ".", "..") for part in relative.parts)
    current = STACK_ROOT
    assert current.is_dir() and not current.is_symlink()
    for part in relative.parts:
        current = current / part
        assert current.exists() and not current.is_symlink(), relative_path
    assert current.is_file(), relative_path
    value = current.read_bytes()
    if require_utf8:
        value.decode("utf-8")
    return value


def validate_application_provenance(generator: dict[str, Any]) -> None:
    assert set(generator) == {
        "command", "source", "sourceSha256Hex", "cargoToml", "cargoLock",
        "authoritySources", "authoritySourcesAggregateAlgorithm",
        "authoritySourcesAggregateDomainHex", "authoritySourcesAggregateSha256Hex",
        "contractSources", "contractMirrorEquality", "frozenCryptoManifestSha256Hex",
        "frozenCryptoReference",
    }
    assert generator["command"] == (
        "CATBIRD_REGENERATE_CHAT_APPLICATION_FIXTURES=1 cargo run --locked --features "
        "test-utils --example generate_chat_application_fixtures"
    )
    generator_path = "catbird-mls/examples/generate_chat_application_fixtures.rs"
    assert generator["source"] == generator_path
    generator_bytes = strict_provenance_bytes(generator_path, require_utf8=True)
    assert hashlib.sha256(generator_bytes).hexdigest() == generator["sourceSha256Hex"]

    for field, expected_path, extra_keys in (
        ("cargoToml", "catbird-mls/Cargo.toml", set()),
        ("cargoLock", "catbird-mls/Cargo.lock", {"jjTracked"}),
    ):
        record = generator[field]
        assert set(record) == {"path", "sha256Hex"} | extra_keys
        assert record["path"] == expected_path
        source = strict_provenance_bytes(expected_path, require_utf8=True)
        assert hashlib.sha256(source).hexdigest() == record["sha256Hex"]
    assert generator["cargoLock"]["jjTracked"] is True
    cargo_toml = strict_provenance_bytes("catbird-mls/Cargo.toml", require_utf8=True).decode()
    assert 'catbird-atproto = { path = "../catbird-atproto" }' in cargo_toml
    tracked = subprocess.run(
        ["jj", "file", "list", "Cargo.lock"],
        cwd=STACK_ROOT / "catbird-mls",
        check=False,
        capture_output=True,
        text=True,
    )
    assert tracked.returncode == 0
    assert "Cargo.lock" in {line.strip() for line in tracked.stdout.splitlines()}

    authority_roots = (
        STACK_ROOT / "catbird-mls/src/chat_protocol",
        STACK_ROOT / "catbird-atproto/src",
    )
    authority_paths = {
        "catbird-atproto/Cargo.toml",
        "catbird-mls/build.rs",
        "catbird-mls/src/application_content.rs",
        "catbird-mls/src/lib.rs",
    }
    for root in authority_roots:
        assert root.is_dir() and not root.is_symlink()
        for path in root.rglob("*"):
            assert not path.is_symlink(), path
            if path.is_file() and path.suffix == ".rs":
                path.read_bytes().decode("utf-8")
                authority_paths.add(path.relative_to(STACK_ROOT).as_posix())
    expected_authority_paths = sorted(authority_paths)
    authority_sources = generator["authoritySources"]
    assert len(authority_sources) == len(expected_authority_paths) == 593
    assert [source["path"] for source in authority_sources] == expected_authority_paths
    assert len(set(expected_authority_paths)) == len(expected_authority_paths)
    authority_bytes: list[tuple[str, bytes]] = []
    for source in authority_sources:
        assert set(source) == {"path", "sha256Hex"}
        value = strict_provenance_bytes(source["path"], require_utf8=True)
        assert hashlib.sha256(value).hexdigest() == source["sha256Hex"]
        authority_bytes.append((source["path"], value))
    aggregate_algorithm = (
        "SHA-256(domain || count:u64be || repeated(pathLength:u64be || UTF-8 path || "
        "sourceLength:u64be || exact source bytes)), records sorted by path"
    )
    aggregate_domain = b"CATBIRD-CHAT-AUTHORITY-SOURCES-V1\0"
    assert generator["authoritySourcesAggregateAlgorithm"] == aggregate_algorithm
    assert generator["authoritySourcesAggregateDomainHex"] == aggregate_domain.hex()
    aggregate = hashlib.sha256()
    aggregate.update(aggregate_domain)
    aggregate.update(len(authority_bytes).to_bytes(8, "big"))
    for path, value in authority_bytes:
        encoded_path = path.encode("utf-8")
        aggregate.update(len(encoded_path).to_bytes(8, "big"))
        aggregate.update(encoded_path)
        aggregate.update(len(value).to_bytes(8, "big"))
        aggregate.update(value)
    assert aggregate.hexdigest() == generator["authoritySourcesAggregateSha256Hex"]

    contract_paths = [
        "PetrelCatbird/lexicons/blue/catbird/chat/blue.catbird.chat.defs.json",
        "PetrelCatbird/lexicons/blue/catbird/chat/blue.catbird.chat.sendMessage.json",
        "mls-ds/lexicon/blue/catbird/chat/blue.catbird.chat.defs.json",
        "mls-ds/lexicon/blue/catbird/chat/blue.catbird.chat.sendMessage.json",
        "docs/CHAT_PROTOCOL.md",
        "docs/CHAT_APPLICATION_PROTOCOL.md",
        "docs/superpowers/plans/2026-07-22-chat-protocol.md",
        "docs/program/decisions/ADR-019-chat-protocol-clean-cutover.md",
        "mls-ds/server/tests/fixtures/mls_chat_contract_vectors.json",
        "mls-ds/server/tests/generate_mls_chat_contract_vectors.py",
        "mls-ds/server/tests/fixtures/mls_chat_control_fingerprint_source.json",
    ]
    contract_sources = generator["contractSources"]
    assert len(contract_sources) == 11
    assert [source["path"] for source in contract_sources] == contract_paths
    contract_by_path: dict[str, tuple[dict[str, Any], bytes]] = {}
    for source in contract_sources:
        assert set(source) == {"path", "sha256Hex"}
        value = strict_provenance_bytes(source["path"], require_utf8=True)
        assert hashlib.sha256(value).hexdigest() == source["sha256Hex"]
        contract_by_path[source["path"]] = (source, value)

    mirror_records = generator["contractMirrorEquality"]
    expected_mirrors = (
        ("defs", contract_paths[0], contract_paths[2]),
        ("sendMessage", contract_paths[1], contract_paths[3]),
    )
    assert len(mirror_records) == 2
    for record, (name, client_path, server_path) in zip(mirror_records, expected_mirrors):
        assert set(record) == {"name", "clientPath", "serverPath", "byteEqual", "sha256Hex"}
        assert (record["name"], record["clientPath"], record["serverPath"]) == (
            name, client_path, server_path,
        )
        assert record["byteEqual"] is True
        client_record, client_bytes = contract_by_path[client_path]
        server_record, server_bytes = contract_by_path[server_path]
        assert client_bytes == server_bytes
        assert record["sha256Hex"] == client_record["sha256Hex"] == server_record["sha256Hex"]

    crypto = generator["frozenCryptoReference"]
    assert set(crypto) == {
        "manifest", "applicationFrame", "applicationPrivateMessage", "verifier",
        "verifierTestTarget", "verifierTestName", "verificationCommand",
    }
    expected_artifacts = {
        "manifest": "docs/generated-artifacts/mls-chat-v1/crypto-wire/manifest.json",
        "applicationFrame": "docs/generated-artifacts/mls-chat-v1/crypto-wire/application-frame.cbor",
        "applicationPrivateMessage": "docs/generated-artifacts/mls-chat-v1/crypto-wire/application-private.mls",
    }
    artifact_bytes: dict[str, bytes] = {}
    for name, expected_path in expected_artifacts.items():
        record = crypto[name]
        assert set(record) == {"path", "length", "sha256Hex"}
        assert record["path"] == expected_path
        value = strict_provenance_bytes(expected_path, require_utf8=name == "manifest")
        assert len(value) == record["length"]
        assert hashlib.sha256(value).hexdigest() == record["sha256Hex"]
        artifact_bytes[name] = value
    assert generator["frozenCryptoManifestSha256Hex"] == crypto["manifest"]["sha256Hex"]
    verifier = crypto["verifier"]
    assert set(verifier) == {"path", "sha256Hex"}
    assert verifier["path"] == "catbird-mls/tests/chat_crypto_wire_corpus_tests.rs"
    verifier_source = strict_provenance_bytes(verifier["path"], require_utf8=True)
    assert hashlib.sha256(verifier_source).hexdigest() == verifier["sha256Hex"]
    assert crypto["verifierTestTarget"] == "chat_crypto_wire_corpus_tests"
    assert crypto["verifierTestName"] == "frozen_crypto_wire_corpus_is_complete_hash_bound_and_consumable"
    assert crypto["verificationCommand"] == (
        "cargo test --locked --features test-utils --test chat_crypto_wire_corpus_tests "
        "frozen_crypto_wire_corpus_is_complete_hash_bound_and_consumable -- --nocapture"
    )
    assert b"fn frozen_crypto_wire_corpus_is_complete_hash_bound_and_consumable()" in verifier_source
    crypto_manifest = strict_json_loads(artifact_bytes["manifest"].decode("utf-8"))
    assert crypto_manifest["schemaVersion"] == 1
    assert crypto_manifest["protocol"] == "blue.catbird.chat"
    assert crypto_manifest["protocolVersion"] == "1"
    assert crypto_manifest["cipherSuite"] == {"code": 77, "name": SUITE}
    assert crypto_manifest["liveProof"]["privateApplicationDecryptedByBob"] is True
    for reference_name, filename in (
        ("applicationFrame", "application-frame.cbor"),
        ("applicationPrivateMessage", "application-private.mls"),
    ):
        assert crypto[reference_name]["length"] == crypto_manifest["files"][filename]["length"]
        assert crypto[reference_name]["sha256Hex"] == crypto_manifest["files"][filename]["sha256Hex"]
    assert crypto_manifest["files"]["application-frame.cbor"]["kind"] == "canonicalDagCborApplicationFrame"
    assert crypto_manifest["files"]["application-private.mls"] == {
        "epoch": 1,
        "kind": "mlsMessagePrivateApplication",
        "length": crypto["applicationPrivateMessage"]["length"],
        "sha256Hex": crypto["applicationPrivateMessage"]["sha256Hex"],
        "wireFormat": 2,
    }


def validate_signed_application_fixture(
    fixture: dict[str, Any], registered_public_key: bytes
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    assert set(fixture) == {
        "applicationEntryCborHex", "applicationEntryCborSha256Hex",
        "applicationEntryFingerprintDomainHex", "fingerprintHex",
        "fingerprintProjectionCborHex", "messageSignatureDomainHex", "requestDigestHex",
        "signatureAlgorithm", "signingTranscriptHex", "unsignedSendProjectionCborHex",
    }
    message_domain = b"CATBIRD-CHAT-MESSAGE\0"
    fingerprint_domain = b"CATBIRD-CHAT-APPLICATION-ENTRY-FINGERPRINT\0"
    assert fixture["signatureAlgorithm"] == "Ed25519"
    assert fixture["messageSignatureDomainHex"] == message_domain.hex()
    assert fixture["applicationEntryFingerprintDomainHex"] == fingerprint_domain.hex()
    assert len(registered_public_key) == 32

    entry_cbor = bytes.fromhex(fixture["applicationEntryCborHex"])
    assert hashlib.sha256(entry_cbor).hexdigest() == fixture["applicationEntryCborSha256Hex"]
    entry = decode_dag_cbor(entry_cbor)
    assert set(entry) == {"entryId", "conversationId", "seq", "signedRequest", "receivedAt"}
    assert len(entry["entryId"]) == len(entry["conversationId"]) == 16
    assert isinstance(entry["seq"], int) and 1 <= entry["seq"] <= SAFE_INTEGER_MAX
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", entry["receivedAt"])
    signed_request = entry["signedRequest"]
    assert set(signed_request) == {"body", "signature"}
    signature = signed_request["signature"]
    assert len(signature) == 64
    body = signed_request["body"]
    assert set(body) == {
        "$type", "aad", "actorDeviceId", "actorDid", "applicationMessage", "authGeneration",
        "blobBindings", "keyId", "messageId", "prior", "signatureDomain", "signedAt",
    }
    assert body["$type"] == "blue.catbird.chat.defs#applicationSendBody"
    assert body["signatureDomain"].encode() == message_domain
    assert body["authGeneration"] == 1
    assert len(body["actorDeviceId"]) == len(body["messageId"]) == 16
    assert uuid.UUID(bytes=body["actorDeviceId"]).version == 4
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", body["signedAt"])
    expected_key_id = base64.urlsafe_b64encode(hashlib.sha256(registered_public_key).digest()).decode().rstrip("=")
    assert body["keyId"] == expected_key_id
    prior = body["prior"]
    assert set(prior) == {
        "conversationId", "generation", "stateVersion", "groupId", "epoch",
        "groupContextHash", "confirmationTag", "lifecycle",
    }
    assert prior["lifecycle"] == "active"
    assert len(prior["conversationId"]) == 16
    for field in ("groupId", "groupContextHash", "confirmationTag"):
        assert len(prior[field]) == 32
    assert entry["conversationId"] == prior["conversationId"]
    aad = body["aad"]
    assert set(aad) == {"protocolVersion", "conversationId", "generation", "messageId", "prior"}
    assert aad == {
        "protocolVersion": "1",
        "conversationId": prior["conversationId"],
        "generation": prior["generation"],
        "messageId": body["messageId"],
        "prior": prior,
    }
    artifact = body["applicationMessage"]
    assert set(artifact) == {"bytes", "sha256", "framing", "contentType"}
    assert artifact["framing"] == "mlsMessage"
    assert artifact["contentType"] == "privateMessageApplication"
    assert hashlib.sha256(artifact["bytes"]).digest() == artifact["sha256"]
    for binding in body["blobBindings"]:
        assert set(binding) == {"blobId", "ciphertextSha256", "ciphertextSize", "purpose"}
        assert len(binding["blobId"]) == 16 and len(binding["ciphertextSha256"]) == 32
        assert binding["purpose"] in {"attachment", "metadata"}

    unsigned_projection = bytes.fromhex(fixture["unsignedSendProjectionCborHex"])
    assert decode_dag_cbor(unsigned_projection) == body
    transcript = message_domain + unsigned_projection
    assert bytes.fromhex(fixture["signingTranscriptHex"]) == transcript
    request_digest = hashlib.sha256(transcript).digest()
    assert bytes.fromhex(fixture["requestDigestHex"]) == request_digest
    assert ed25519_verify(registered_public_key, transcript, signature)

    projection_cbor = bytes.fromhex(fixture["fingerprintProjectionCborHex"])
    projection = decode_dag_cbor(projection_cbor)
    assert set(projection) == {
        "entryId", "conversationId", "seq", "requestDigest", "signature", "receivedAt",
    }
    assert projection == {
        "entryId": entry["entryId"],
        "conversationId": entry["conversationId"],
        "seq": entry["seq"],
        "requestDigest": request_digest,
        "signature": signature,
        "receivedAt": entry["receivedAt"],
    }
    fingerprint = hashlib.sha256(fingerprint_domain + projection_cbor).digest()
    assert fingerprint.hex() == fixture["fingerprintHex"]
    return entry, body, fingerprint


def validate_application_vector(
    manifest: dict[str, Any], vector: dict[str, Any], oracle: tuple[str, str | None, str | None]
) -> tuple[str, str]:
    name = vector["name"]
    disposition, reason, body_tag = oracle
    common_keys = {
        "name", "messageIdHex", "cborHex", "length", "sha256Hex", "outerBlobBindings",
        "signedOuterEntry", "outerEntryFingerprintHex", "transportEvidence", "senderMode",
        "expectedDisposition", "expectedReason",
    }
    expected_keys = set(common_keys)
    if body_tag is not None:
        expected_keys.add("expectedBodyTag")
    if name in {"v1LifecycleClosedRejected", "v1KnownContextGenerationAboveUint53"}:
        expected_keys.add("constructionEvidence")
    if name in {"senderCredentialMismatch", "senderLeafKeyMismatch"}:
        expected_keys |= {"senderFactsSource", "receiverFactsUsedWithoutMutation", "senderBindingEvidence"}
    assert set(vector) == expected_keys, name
    assert vector["expectedDisposition"] == disposition
    assert vector["expectedReason"] == reason
    assert vector.get("expectedBodyTag") == body_tag
    raw = bytes.fromhex(vector["cborHex"])
    assert len(raw) == vector["length"]
    assert hashlib.sha256(raw).hexdigest() == vector["sha256Hex"]
    if body_tag is not None and name != "v1KnownContextGenerationAboveUint53":
        decoded_artifact = decode_dag_cbor(raw)
        assert set(decoded_artifact["body"]) == {body_tag}
    if name == "v1LifecycleClosedRejected":
        assert vector["constructionEvidence"] == {
            "byteSpliceUsed": False,
            "field": "context.lifecycle",
            "kind": "explicitRawCborField",
            "value": "closed",
        }
    elif name == "v1KnownContextGenerationAboveUint53":
        assert vector["constructionEvidence"] == {
            "field": "context.generation",
            "kind": "knownContextIntegerField",
            "unknownExtensionUsed": False,
            "valueDecimal": "9007199254740992",
        }

    transport = vector["transportEvidence"]
    assert set(transport) == {
        "mode", "laneName", "memberCount", "senderLeafIndex", "senderCredentialType",
        "senderCredentialIdentityHex", "senderLeafSignaturePublicKeyHex", "senderActorDid",
        "senderDeviceId", "receiverActorDid", "receiverDeviceId", "conversationIdHex",
        "groupIdHex", "epoch", "applicationAadLength", "applicationAadSha256Hex",
        "processedAadExact", "decryptedPlaintextLength", "decryptedPlaintextSha256Hex",
        "decryptedPlaintextExact",
    }
    assert transport["mode"] == "twoMemberOpenMlsReceiver"
    assert transport["memberCount"] == 2 and transport["senderLeafIndex"] in (0, 1)
    assert transport["senderCredentialType"] == "BasicCredential"
    assert transport["processedAadExact"] is True
    assert transport["decryptedPlaintextExact"] is True
    assert transport["decryptedPlaintextLength"] == len(raw)
    assert transport["decryptedPlaintextSha256Hex"] == hashlib.sha256(raw).hexdigest()
    application_aad = b"CATBIRD-CHAT-MLS-AAD-MESSAGE\0" + encode_dag_cbor(
        decode_dag_cbor(bytes.fromhex(vector["signedOuterEntry"]["unsignedSendProjectionCborHex"]))["aad"]
    )
    assert transport["applicationAadLength"] == len(application_aad)
    assert transport["applicationAadSha256Hex"] == hashlib.sha256(application_aad).hexdigest()
    credential = bytes.fromhex(transport["senderCredentialIdentityHex"])
    assert credential == f'{transport["senderActorDid"]}#{transport["senderDeviceId"]}'.encode()
    leaf_key = bytes.fromhex(transport["senderLeafSignaturePublicKeyHex"])
    assert len(leaf_key) == 32

    actor_keys = {
        (actor["actorDid"], device["actorDeviceId"]): bytes.fromhex(device["signaturePublicKeyHex"])
        for actor in manifest["identity"]["actors"] for device in actor["devices"]
    }
    assert actor_keys[(transport["senderActorDid"], transport["senderDeviceId"])] == leaf_key
    assert (transport["receiverActorDid"], transport["receiverDeviceId"]) in actor_keys
    lanes = {lane["name"]: lane for lane in manifest["liveProof"]["lanes"]}
    lane = lanes[transport["laneName"]]
    assert lane["context"]["conversationIdHex"] == transport["conversationIdHex"]
    assert lane["context"]["groupIdHex"] == transport["groupIdHex"]
    assert lane["context"]["epoch"] == transport["epoch"]
    endpoints = {
        (lane["left"]["actorDid"], lane["left"]["actorDeviceId"]),
        (lane["right"]["actorDid"], lane["right"]["actorDeviceId"]),
    }
    assert endpoints == {
        (transport["senderActorDid"], transport["senderDeviceId"]),
        (transport["receiverActorDid"], transport["receiverDeviceId"]),
    }

    if vector["senderMode"] == "receiverFactsExact":
        assert name in {"senderCredentialMismatch", "senderLeafKeyMismatch"}
        evidence = vector["senderBindingEvidence"]
        assert set(evidence) == {
            "mismatchDimension", "transportSenderActorDid", "transportSenderDeviceId",
            "signedOuterActorDid", "signedOuterDeviceId", "registeredSignaturePublicKeyHex",
        }
        registered_key = bytes.fromhex(evidence["registeredSignaturePublicKeyHex"])
        assert vector["senderFactsSource"] == "processedMemberLeaf"
        assert vector["receiverFactsUsedWithoutMutation"] is True
        assert (evidence["transportSenderActorDid"], evidence["transportSenderDeviceId"]) == (
            transport["senderActorDid"], transport["senderDeviceId"],
        )
    else:
        assert vector["senderMode"] == "exact"
        registered_key = leaf_key
    entry, body, fingerprint = validate_signed_application_fixture(vector["signedOuterEntry"], registered_key)
    assert fingerprint.hex() == vector["outerEntryFingerprintHex"]
    assert body["messageId"].hex() == vector["messageIdHex"]
    assert body["prior"]["conversationId"].hex() == transport["conversationIdHex"]
    assert body["prior"]["groupId"].hex() == transport["groupIdHex"]
    assert body["prior"]["epoch"] == transport["epoch"]
    assert entry["conversationId"] == body["prior"]["conversationId"]
    normalized_bindings = [
        {
            "blobIdHex": binding["blobId"].hex(),
            "ciphertextSha256Hex": binding["ciphertextSha256"].hex(),
            "ciphertextSize": binding["ciphertextSize"],
            "purpose": binding["purpose"],
        }
        for binding in body["blobBindings"]
    ]
    assert normalized_bindings == vector["outerBlobBindings"]
    if vector["senderMode"] == "receiverFactsExact":
        evidence = vector["senderBindingEvidence"]
        signed_device = str(uuid.UUID(bytes=body["actorDeviceId"]))
        assert (evidence["signedOuterActorDid"], evidence["signedOuterDeviceId"]) == (
            body["actorDid"], signed_device,
        )
        if evidence["mismatchDimension"] == "credentialIdentity":
            assert (transport["senderActorDid"], transport["senderDeviceId"]) != (
                body["actorDid"], signed_device,
            )
        else:
            assert evidence["mismatchDimension"] == "leafSignaturePublicKey"
            assert (transport["senderActorDid"], transport["senderDeviceId"]) == (
                body["actorDid"], signed_device,
            )
            assert leaf_key != registered_key
    return vector["outerEntryFingerprintHex"], transport["laneName"]


def validate_application_manifest_categories(
    manifest: dict[str, Any], actor_keys: dict[tuple[str, str], bytes]
) -> None:
    live = manifest["liveProof"]
    assert set(live) == {
        "profile", "transportLaneCount", "memberCountPerLane",
        "everyEncryptedApplicationProcessedByReceiverBeforeAuthorityIngest",
        "senderFactsExtractedFromProcessedMemberLeaf", "basicCredentialRequired",
        "topLevelApplicationVectorCount", "scenarioApplicationStepCount",
        "scenarioUniqueTransportCount", "scenarioReplayOccurrenceCount",
        "totalApplicationOccurrenceCount", "totalProcessedApplicationCount",
        "perLaneProcessedApplicationCounts", "perLaneApplicationOccurrenceCounts",
        "applicationOccurrenceTraversalComplete", "utf8BoundaryVectorsAreCodecOnly",
        "reducerScenarioCount", "lanes",
    }
    assert live["profile"] == "two independent deterministic two-member OpenMLS 0.8.1 lanes"
    assert live["transportLaneCount"] == live["memberCountPerLane"] == 2
    for field in (
        "everyEncryptedApplicationProcessedByReceiverBeforeAuthorityIngest",
        "senderFactsExtractedFromProcessedMemberLeaf", "basicCredentialRequired",
        "applicationOccurrenceTraversalComplete", "utf8BoundaryVectorsAreCodecOnly",
    ):
        assert live[field] is True
    assert {
        "topLevelApplicationVectorCount": 143,
        "scenarioApplicationStepCount": 66,
        "scenarioUniqueTransportCount": 65,
        "scenarioReplayOccurrenceCount": 1,
        "totalApplicationOccurrenceCount": 209,
        "totalProcessedApplicationCount": 208,
        "reducerScenarioCount": 17,
    }.items() <= live.items()
    assert live["perLaneProcessedApplicationCounts"] == {
        "sameDidTwoDevice": 203, "differentDidAuthor": 5,
    }
    assert live["perLaneApplicationOccurrenceCounts"] == {
        "sameDidTwoDevice": 204, "differentDidAuthor": 5,
    }
    lanes = live["lanes"]
    assert [lane["name"] for lane in lanes] == ["sameDidTwoDevice", "differentDidAuthor"]
    for lane in lanes:
        assert set(lane) == {"name", "left", "right", "context"}
        assert set(lane["left"]) == set(lane["right"]) == {"actorDid", "actorDeviceId"}
        for endpoint in (lane["left"], lane["right"]):
            assert (endpoint["actorDid"], endpoint["actorDeviceId"]) in actor_keys
        assert set(lane["context"]) == {
            "conversationIdHex", "generation", "stateVersion", "groupIdHex", "epoch",
            "groupContextHashHex", "confirmationTagHex", "lifecycle",
        }
    assert lanes[0]["left"]["actorDid"] == lanes[0]["right"]["actorDid"]
    assert lanes[1]["left"]["actorDid"] != lanes[1]["right"]["actorDid"]

    vectors_list = manifest["vectors"]
    assert len(vectors_list) == len(APPLICATION_VECTOR_ORACLES) == 143
    assert [vector["name"] for vector in vectors_list] == list(APPLICATION_VECTOR_ORACLES)
    assert "atprotoRecord" not in APPLICATION_VECTOR_ORACLES
    assert "senderNotMember" not in APPLICATION_VECTOR_ORACLES
    fingerprints: dict[str, dict[str, Any]] = {}
    lane_processed = {"sameDidTwoDevice": 0, "differentDidAuthor": 0}
    for vector in vectors_list:
        fingerprint, lane_name = validate_application_vector(
            manifest, vector, APPLICATION_VECTOR_ORACLES[vector["name"]]
        )
        assert fingerprint not in fingerprints
        fingerprints[fingerprint] = vector
        lane_processed[lane_name] += 1

    authority = manifest["authorityBoundaryVectors"]
    assert len(authority) == 1
    sender_not_member = authority[0]
    assert set(sender_not_member) == {
        "name", "validationScope", "receiverProcessed", "baseReceiverProcessedVector",
        "senderFactsConstruction", "expectedDisposition", "expectedReason",
    }
    assert sender_not_member["name"] == "senderNotMember"
    assert sender_not_member["validationScope"] == "authorityBoundary"
    assert sender_not_member["receiverProcessed"] is False
    assert sender_not_member["baseReceiverProcessedVector"] == "text"
    assert sender_not_member["expectedDisposition"] == "rejected"
    assert sender_not_member["expectedReason"] == "bindingMismatch"
    construction = sender_not_member["senderFactsConstruction"]
    assert set(construction) == {
        "isMember", "credentialIdentityHex", "leafSignaturePublicKeyHex", "mutation",
    }
    assert construction["isMember"] is False and construction["mutation"] == "membershipFlagOnly"
    base = vectors_list[0]
    assert base["name"] == "text"
    assert construction["credentialIdentityHex"] == base["transportEvidence"]["senderCredentialIdentityHex"]
    assert construction["leafSignaturePublicKeyHex"] == base["transportEvidence"]["senderLeafSignaturePublicKeyHex"]

    identity_boundaries = manifest["identityBoundaryVectors"]
    identity_names = [
        "bareDidMin12BasicCredentialMin49Accepted",
        "bareDidMax261BasicCredentialMax298Accepted",
        "bareDidBelowMin11BasicCredentialBelowMin48Rejected",
        "bareDidAboveMax262BasicCredentialAboveMax299Rejected",
    ]
    assert [vector["name"] for vector in identity_boundaries] == identity_names
    for vector, (did_length, credential_length, accepted) in zip(
        identity_boundaries, ((12, 49, True), (261, 298, True), (11, 48, False), (262, 299, False))
    ):
        expected_keys = {
            "name", "validationScope", "receiverProcessed", "actorDid", "actorDidUtf8Length",
            "actorDeviceId", "basicCredentialIdentityHex", "basicCredentialUtf8Length",
            "credentialDerivation", "expectedRegistration", "expectedDisposition",
            "expectedReason", "outerSenderBindingChecked", "signedOuterEntry",
        }
        if accepted:
            expected_keys.add("applicationArtifactSource")
        assert set(vector) == expected_keys
        assert vector["validationScope"] == "identityBoundary" and vector["receiverProcessed"] is False
        assert vector["actorDidUtf8Length"] == len(vector["actorDid"].encode()) == did_length
        credential = f'{vector["actorDid"]}#{vector["actorDeviceId"]}'.encode()
        assert vector["basicCredentialIdentityHex"] == credential.hex()
        assert vector["basicCredentialUtf8Length"] == len(credential) == credential_length
        assert vector["credentialDerivation"] == 'UTF8(actorDid + "#" + actorDeviceId)'
        if accepted:
            assert vector["applicationArtifactSource"] == "text.receiverProcessed"
            assert vector["expectedRegistration"] == "accepted"
            assert vector["expectedDisposition"] == "supported" and vector["expectedReason"] is None
            assert vector["outerSenderBindingChecked"] is True
            _, body, _ = validate_signed_application_fixture(
                vector["signedOuterEntry"], bytes.fromhex(manifest["identity"]["signaturePublicKeyHex"])
            )
            assert body["actorDid"] == vector["actorDid"]
            assert str(uuid.UUID(bytes=body["actorDeviceId"])) == vector["actorDeviceId"]
        else:
            assert vector["expectedRegistration"] == "rejected"
            assert vector["expectedDisposition"] == "rejectedBeforeOuter"
            assert vector["expectedReason"] == "invalidValue"
            assert vector["outerSenderBindingChecked"] is False and vector["signedOuterEntry"] is None

    utf8_vectors = manifest["utf8BoundaryVectors"]
    utf8_limits = {
        "body.message.text": (16_384, "sizeLimitExceeded"),
        "body.edit.replacementText": (16_384, "sizeLimitExceeded"),
        "encryptedAudio.transcript": (16_384, "sizeLimitExceeded"),
        "encryptedImage.altText": (4_096, "sizeLimitExceeded"),
        "externalLink.title": (512, "sizeLimitExceeded"),
        "externalLink.description": (2_048, "sizeLimitExceeded"),
        "externalLink.uri": (2_048, "invalidValue"),
        "body.reaction.emoji": (64, "invalidReaction"),
        "atprotoRecord.uri": (1_097, "invalidValue"),
    }
    utf8_value_paths = {
        "body.message.text": ("body", "message", "text"),
        "body.edit.replacementText": ("body", "edit", "replacementText"),
        "encryptedAudio.transcript": (
            "body", "message", "embed", "encryptedAudio", "transcript",
        ),
        "encryptedImage.altText": (
            "body", "message", "embed", "encryptedImage", "altText",
        ),
        "externalLink.title": ("body", "message", "embed", "externalLink", "title"),
        "externalLink.description": (
            "body", "message", "embed", "externalLink", "description",
        ),
        "externalLink.uri": ("body", "message", "embed", "externalLink", "uri"),
        "body.reaction.emoji": ("body", "reaction", "emoji"),
        "atprotoRecord.uri": ("body", "message", "embed", "atprotoRecord", "uri"),
    }
    assert set(utf8_value_paths) == set(utf8_limits)
    assert [vector["field"] for vector in utf8_vectors] == list(utf8_limits)
    for vector in utf8_vectors:
        expected_keys = {
            "field", "validationScope", "evidenceMode", "receiverProcessed", "authorityChecked",
            "limitBytes", "prefix", "unit", "unitUtf8Hex", "unitRepeats", "atLimitSuffix",
            "overLimitSuffix", "atLimitBytes", "overLimitBytes", "atLimitUtf8Sha256Hex",
            "overLimitUtf8Sha256Hex", "atLimitCborHex", "atLimitCborLength",
            "atLimitCborSha256Hex", "canonicalRoundTripMatched", "decodedFrameMatched",
            "expectedAtLimit", "expectedOverLimit", "expectedOverReason",
        }
        if vector["field"] == "atprotoRecord.uri":
            expected_keys |= {"acceptedCaseName", "rejectedCaseName"}
            assert vector["acceptedCaseName"] == "atRecordUriMax1097Accepted"
            assert vector["rejectedCaseName"] == "atRecordUriTooLong1098Rejected"
        assert set(vector) == expected_keys
        limit, reason = utf8_limits[vector["field"]]
        assert vector["validationScope"] == "codecOnly"
        assert vector["evidenceMode"] == "authorityCodecRoundTrip"
        assert vector["receiverProcessed"] is False and vector["authorityChecked"] is True
        assert vector["limitBytes"] == vector["atLimitBytes"] == limit
        assert vector["expectedAtLimit"] == "supported"
        assert vector["expectedOverLimit"] == "rejected" and vector["expectedOverReason"] == reason
        assert vector["canonicalRoundTripMatched"] is True
        assert vector["decodedFrameMatched"] is True
        assert vector["unit"].encode() == bytes.fromhex(vector["unitUtf8Hex"])
        at_limit = (
            vector["prefix"] + vector["unit"] * vector["unitRepeats"] + vector["atLimitSuffix"]
        ).encode()
        over_limit = (
            vector["prefix"] + vector["unit"] * vector["unitRepeats"] + vector["overLimitSuffix"]
        ).encode()
        assert len(at_limit) == vector["atLimitBytes"]
        assert len(over_limit) == vector["overLimitBytes"]
        assert hashlib.sha256(at_limit).hexdigest() == vector["atLimitUtf8Sha256Hex"]
        assert hashlib.sha256(over_limit).hexdigest() == vector["overLimitUtf8Sha256Hex"]
        at_limit_cbor = bytes.fromhex(vector["atLimitCborHex"])
        assert len(at_limit_cbor) == vector["atLimitCborLength"]
        assert hashlib.sha256(at_limit_cbor).hexdigest() == vector["atLimitCborSha256Hex"]
        decoded = decode_dag_cbor(at_limit_cbor)
        decoded_value: Any = decoded
        for component in utf8_value_paths[vector["field"]]:
            decoded_value = decoded_value[component]
        assert decoded_value.encode() == at_limit

    outer_oracles = {
        "applicationEntryDuplicateTopLevelKey": ("duplicateKey", False),
        "applicationEntryUnknownTopLevelField": ("unknownField", False),
        "applicationEntryNoncanonicalKeyOrder": ("nonCanonical", False),
        "applicationEntryNonminimalMapHeader": ("nonCanonical", False),
        "badSignature": ("invalidSignature", True),
        "entryBodyConversationMismatch": ("bindingMismatch", True),
        "bodyAadMismatch": ("bindingMismatch", True),
        "registryDidMismatch": ("bindingMismatch", True),
        "registryDeviceMismatch": ("bindingMismatch", True),
        "registryKeyIdMismatch": ("bindingMismatch", True),
        "registryAuthGenerationMismatch": ("bindingMismatch", True),
        "applicationArtifactShaMismatch": ("integrityMismatch", True),
    }
    outer_vectors = manifest["outerEntryRejectionVectors"]
    assert [vector["name"] for vector in outer_vectors] == list(outer_oracles)
    for vector in outer_vectors:
        assert set(vector) == {
            "name", "validationStage", "terminalPreDecrypt", "applicationEntryCborHex",
            "applicationEntryCborSha256Hex", "canonicalTypedEntry", "registeredDevice",
            "expectedDisposition", "expectedReason",
        }
        reason, canonical = outer_oracles[vector["name"]]
        assert vector["validationStage"] == "outerPreDecrypt" and vector["terminalPreDecrypt"] is True
        assert vector["expectedDisposition"] == "outerRejected" and vector["expectedReason"] == reason
        assert vector["canonicalTypedEntry"] is canonical
        raw = bytes.fromhex(vector["applicationEntryCborHex"])
        assert hashlib.sha256(raw).hexdigest() == vector["applicationEntryCborSha256Hex"]
        registration = vector["registeredDevice"]
        assert set(registration) == {
            "actorDid", "actorDeviceId", "keyId", "authGeneration", "signaturePublicKeyHex",
        }
        key = bytes.fromhex(registration["signaturePublicKeyHex"])
        assert registration["keyId"] == base64.urlsafe_b64encode(
            hashlib.sha256(key).digest()
        ).decode().rstrip("=")

    hint_vectors = manifest["hintAuthorityBoundaryVectors"]
    hint_names = [
        ("tombstoneTerminalSeqOnlyCannotAuthorizeClose", "tombstone"),
        ("eventTerminalSeqOnlyCannotAuthorizeClose", "event"),
        ("inventoryTerminalSeqOnlyCannotAuthorizeClose", "inventory"),
        ("intervalSummaryTerminalSeqOnlyCannotAuthorizeClose", "intervalSummary"),
    ]
    assert [(vector["name"], vector["hintKind"]) for vector in hint_vectors] == hint_names
    initial_baseline = manifest["reducerInitializationVectors"][0]["expectedState"]
    for vector in hint_vectors:
        assert set(vector) == {
            "name", "validationScope", "evidenceMode", "hintKind", "hint", "hintJsonSha256Hex",
            "receiverProcessed", "signedControlRowPresent", "outerEntryFingerprintPresent",
            "forbiddenAuthorityFieldsAbsent", "productionAuthorityApi", "reducerCall",
            "controlConstructorCalled", "expectedDisposition", "expectedReason", "stateBefore",
            "stateAfter", "openIntervalUnchanged", "terminalStateUnchanged",
        }
        assert vector["validationScope"] == "authorityTypeBoundary"
        assert vector["evidenceMode"] == "hintOnlyExactDto" and vector["hint"] == {"terminalSeq": 3}
        hint_json = json.dumps(vector["hint"], separators=(",", ":")).encode()
        assert hashlib.sha256(hint_json).hexdigest() == vector["hintJsonSha256Hex"]
        for field in (
            "receiverProcessed", "signedControlRowPresent", "outerEntryFingerprintPresent",
            "controlConstructorCalled",
        ):
            assert vector[field] is False
        assert vector["forbiddenAuthorityFieldsAbsent"] is True
        assert vector["productionAuthorityApi"] == (
            "ApplicationReducer::advance_non_application(&VerifiedApplicationControlEntry)"
        )
        assert vector["reducerCall"] == "noneByType"
        assert vector["expectedDisposition"] == "rejectedBeforeControlAuthority"
        assert vector["expectedReason"] == "unverifiedHintCannotConstructControl"
        assert vector["stateBefore"] == vector["stateAfter"] == initial_baseline
        assert vector["openIntervalUnchanged"] is vector["terminalStateUnchanged"] is True

    validate_application_reducer_evidence(manifest, fingerprints, lane_processed)
    validate_application_signed_control(manifest, actor_keys)


def validate_application_reducer_evidence(
    manifest: dict[str, Any],
    top_fingerprints: dict[str, dict[str, Any]],
    top_lane_processed: dict[str, int],
) -> None:
    initialization_names = [
        "exactInitialOpeningAccepted", "appendEntryIdIsIndependentPositive",
        "initialOpeningSeqMismatch", "initialOpeningKindMismatch",
        "initialOpeningTransitionIdMismatch", "initialOpeningFingerprintMismatch",
        "initialOpeningContextMismatch", "initialOpeningRecipientDidMismatch",
        "initialOpeningSiblingDeviceMismatch", "appendEntryIdCannotSubstituteForOpeningTransitionId",
        "exactResetFirstOpeningAccepted", "resetFirstOpeningSeqMismatch",
        "resetFirstOpeningKindMismatch", "resetFirstOpeningTransitionIdMismatch",
        "resetFirstOpeningFingerprintMismatch", "resetFirstOpeningContextMismatch",
    ]
    initialization = manifest["reducerInitializationVectors"]
    assert [vector["name"] for vector in initialization] == initialization_names
    successful_initializations = {
        "exactInitialOpeningAccepted", "appendEntryIdIsIndependentPositive",
        "exactResetFirstOpeningAccepted",
    }
    for vector in initialization:
        expected_keys = {"name", "opening", "accessIntervals", "expectedResult", "expectedState"}
        if vector["name"] == "resetFirstOpeningKindMismatch":
            expected_keys |= {"validationLayer", "reducerConstructed"}
            assert vector["validationLayer"] == "verifiedControlConstruction"
            assert vector["reducerConstructed"] is False
        assert set(vector) == expected_keys
        if vector["name"] in successful_initializations:
            assert vector["expectedResult"] == {"status": "ok", "code": "initialized", "detail": {}}
            assert isinstance(vector["expectedState"], dict)
        else:
            assert vector["expectedResult"]["status"] == "error"
            assert vector["expectedResult"]["code"] == "invalid_interval_opening"
            assert vector["expectedState"] is None

    schedule_names = [
        "finiteIntervalMissingClosingProof", "finiteIntervalPartialClosingProof",
        "openIntervalCarriesClosingProof", "finiteIntervalEndSeqClosingSeqMismatch",
        "creationOpenTerminalCloseSameSeq", "finiteIntervalCloseBeforeOpeningRejected",
        "removeTouchingAddRejected", "removeWithoutStrictGapRejected",
        "terminalIntervalHasNoSuccessor", "replaceAddNonsharedProofRejected",
        "resetTouchingAddRejected",
    ]
    schedules = manifest["reducerScheduleValidationVectors"]
    assert [vector["name"] for vector in schedules] == schedule_names
    for index, vector in enumerate(schedules):
        assert set(vector) == {
            "name", "opening", "accessIntervals", "validationLayer", "expectedResult", "expectedState",
        }
        assert vector["validationLayer"] == ("strictFixtureRestore" if index < 6 else "reducerSchedule")
        assert vector["expectedResult"]["status"] == "error"
        assert vector["expectedResult"]["code"] == "invalid_access_intervals"
        assert vector["expectedState"] is None

    scenario_names = [
        "editReplyEmbedReplayAndConflicts", "reactionLifecycleAndTombstone",
        "replyPresentationDistinctions", "readFrontierSemantics",
        "sameDidCrossDeviceAuthorAuthority", "differentDidAuthorAuthority",
        "missingAccessibleTargetCorruption", "dynamicReplaceAddExactRecipient",
        "touchingReplaceAddOpeningProvenance", "touchingResetResetOpeningProvenance",
        "finiteCloseExactProvenance", "nonLeafResetActivatorFirstInterval",
        "terminalAfterRemoveClosedGap", "terminalAfterResetClosedGap",
        "contextTransitionResetAndTerminal", "nonTouchingWelcomeReanchor",
        "opaqueRejectedAndRetiredIdentifiers",
    ]
    scenarios = manifest["reducerScenarios"]
    assert [scenario["name"] for scenario in scenarios] == scenario_names
    expected_step_counts = [10, 7, 8, 7, 4, 4, 3, 6, 9, 9, 11, 1, 19, 19, 22, 10, 6]
    assert [len(scenario["steps"]) for scenario in scenarios] == expected_step_counts

    def assert_processed_unique(state: dict[str, Any]) -> None:
        processed = state["processed"]
        assert len({row["seq"] for row in processed}) == len(processed)
        assert len({row["entryIdHex"] for row in processed}) == len(processed)

    occurrence_count = 0
    operation_counts = {
        "application": 0, "control": 0, "controlConstructionRejected": 0,
        "testCorruptionRemoveStoredOriginal": 0,
    }
    unique_scenario_oracles: list[tuple[str, str, str | None, str | None]] = []
    all_fingerprints = dict(top_fingerprints)
    lane_occurrences = {"sameDidTwoDevice": top_lane_processed["sameDidTwoDevice"],
                        "differentDidAuthor": top_lane_processed["differentDidAuthor"]}
    lane_processed = dict(lane_occurrences)
    replay_count = 0
    for scenario, expected_steps in zip(scenarios, expected_step_counts):
        assert set(scenario) == {
            "name", "initial", "steps", "finalState", "invariant", "trackedMessages", "readActors",
        }
        assert len(scenario["steps"]) == expected_steps
        assert set(scenario["initial"]) == {"opening", "accessIntervals", "state"}
        assert scenario["steps"]
        assert scenario["initial"]["state"] == scenario["steps"][0]["expect"]["stateBefore"]
        assert_processed_unique(scenario["initial"]["state"])
        for index, step in enumerate(scenario["steps"]):
            operation = step["op"]
            assert operation in operation_counts
            operation_counts[operation] += 1
            assert set(step["expect"]) == {"result", "stateBefore", "stateAfter"}
            if index:
                assert scenario["steps"][index - 1]["expect"]["stateAfter"] == step["expect"]["stateBefore"]
            assert_processed_unique(step["expect"]["stateBefore"])
            assert_processed_unique(step["expect"]["stateAfter"])
            result = step["expect"]["result"]
            if result["status"] == "error" or result["code"] == "exactReplay":
                assert step["expect"]["stateBefore"] == step["expect"]["stateAfter"]
            if operation == "application":
                assert set(step) == {"op", "application", "expect"}
                occurrence_count += 1
                application = step["application"]
                oracle = (
                    application["name"], application["expectedDisposition"],
                    application.get("expectedReason"), application.get("expectedBodyTag"),
                )
                if oracle not in unique_scenario_oracles:
                    unique_scenario_oracles.append(oracle)
                fingerprint, lane_name = validate_application_vector(manifest, application, oracle[1:])
                lane_occurrences[lane_name] += 1
                is_replay = result["code"] == "exactReplay"
                if fingerprint in all_fingerprints:
                    assert is_replay
                    assert all_fingerprints[fingerprint] == application
                    replay_count += 1
                else:
                    assert not is_replay
                    all_fingerprints[fingerprint] = application
                    lane_processed[lane_name] += 1
            elif operation == "control":
                assert set(step) == {"op", "control", "expect"}
                assert step["control"]["kind"] in {
                    "intervalOpening", "intervalClosing", "contextTransition", "terminal",
                }
            elif operation == "controlConstructionRejected":
                assert set(step) == {"op", "validationLayer", "controlCandidate", "expect"}
                assert step["validationLayer"] == "verifiedControlConstruction"
            else:
                assert set(step) == {"op", "target", "expect"}
                assert set(step["target"]) == {"targetSeq", "targetMessageIdHex"}
        assert scenario["steps"][-1]["expect"]["stateAfter"] == scenario["finalState"]
        assert_processed_unique(scenario["finalState"])

    assert operation_counts == {
        "application": 66, "control": 86, "controlConstructionRejected": 2,
        "testCorruptionRemoveStoredOriginal": 1,
    }
    assert occurrence_count == 66 and replay_count == 1
    assert len(unique_scenario_oracles) == 65
    oracle_bytes = "\n".join(
        "\0".join("" if value is None else value for value in oracle)
        for oracle in unique_scenario_oracles
    ).encode()
    assert hashlib.sha256(oracle_bytes).hexdigest() == (
        "071d755884774e387479933595fc5dd244a73f17b586371698b5e4f8f187008b"
    )
    assert len(all_fingerprints) == 208
    assert lane_occurrences == {"sameDidTwoDevice": 204, "differentDidAuthor": 5}
    assert lane_processed == {"sameDidTwoDevice": 203, "differentDidAuthor": 5}
    live = manifest["liveProof"]
    assert live["topLevelApplicationVectorCount"] == len(top_fingerprints)
    assert live["scenarioApplicationStepCount"] == occurrence_count
    assert live["scenarioUniqueTransportCount"] == len(unique_scenario_oracles)
    assert live["scenarioReplayOccurrenceCount"] == replay_count
    assert live["totalApplicationOccurrenceCount"] == len(top_fingerprints) + occurrence_count
    assert live["totalProcessedApplicationCount"] == len(all_fingerprints)
    assert live["perLaneApplicationOccurrenceCounts"] == lane_occurrences
    assert live["perLaneProcessedApplicationCounts"] == lane_processed


def validate_application_signed_control(
    manifest: dict[str, Any], actor_keys: dict[tuple[str, str], bytes]
) -> None:
    vectors = manifest["signedControlEnvelopeVectors"]
    assert len(vectors) == 1
    vector = vectors[0]
    assert set(vector) == {
        "name", "entryKind", "signedRequestRef", "signingDomainHex",
        "controlEntryFingerprintDomainHex", "signatureAlgorithm",
        "historicalSignaturePublicKeyHex", "unsignedSigningProjectionCanonicalDagCborHex",
        "signingTranscriptHex", "requestDigestHex", "signatureHex",
        "conversationCloseEntryCanonicalDagCborHex",
        "fingerprintProjectionCanonicalDagCborHex", "fingerprintSha256Hex",
        "canonicalBodyRoundTripMatched", "canonicalEntryRoundTripMatched",
        "canonicalFingerprintProjectionRoundTripMatched", "historicalSignatureVerified",
        "terminalRecipient", "authorizedCloseSigner", "signerScenarioRosterBinding",
        "signerIsTerminalRecipientDevice", "deliveryOrAudienceRoutingClaimed",
        "scenarioBinding", "contractFixtureReference",
    }
    close_entry_kind = "blue.catbird.chat.defs#conversationCloseEntry"
    close_body_type = "blue.catbird.chat.defs#conversationCloseBody"
    close_domain = b"CATBIRD-CHAT-CLOSE\0"
    fingerprint_domain = b"CATBIRD-CHAT-CONTROL-ENTRY-FINGERPRINT\0"
    assert vector["name"] == "formerDeviceRemoveGapTerminalSignedEnvelope"
    assert vector["entryKind"] == close_entry_kind
    assert vector["signedRequestRef"] == "blue.catbird.chat.defs#signedConversationClose"
    assert vector["signatureAlgorithm"] == "Ed25519"
    assert vector["signingDomainHex"] == close_domain.hex()
    assert vector["controlEntryFingerprintDomainHex"] == fingerprint_domain.hex()
    for field in (
        "canonicalBodyRoundTripMatched", "canonicalEntryRoundTripMatched",
        "canonicalFingerprintProjectionRoundTripMatched", "historicalSignatureVerified",
    ):
        assert vector[field] is True
    assert vector["signerIsTerminalRecipientDevice"] is False
    assert vector["deliveryOrAudienceRoutingClaimed"] is False

    public_key = bytes.fromhex(vector["historicalSignaturePublicKeyHex"])
    assert len(public_key) == 32
    unsigned = bytes.fromhex(vector["unsignedSigningProjectionCanonicalDagCborHex"])
    body = decode_dag_cbor(unsigned)
    assert set(body) == {
        "$type", "actorDeviceId", "actorDid", "authGeneration", "conversationKind",
        "idempotencyKey", "keyId", "prior", "retired", "signatureDomain", "signedAt",
        "transitionId",
    }
    assert body["$type"] == close_body_type
    assert body["signatureDomain"].encode() == close_domain
    assert body["conversationKind"] == "group" and body["authGeneration"] == 1
    assert body["keyId"] == base64.urlsafe_b64encode(
        hashlib.sha256(public_key).digest()
    ).decode().rstrip("=")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", body["signedAt"])
    assert len(body["actorDeviceId"]) == len(body["idempotencyKey"]) == len(body["transitionId"]) == 16
    prior = body["prior"]
    retired = body["retired"]
    context_keys = {
        "conversationId", "generation", "stateVersion", "groupId", "epoch",
        "groupContextHash", "confirmationTag", "lifecycle",
    }
    assert set(prior) == set(retired) == context_keys
    assert prior["lifecycle"] == "active" and retired["lifecycle"] == "superseded"
    assert retired["stateVersion"] == prior["stateVersion"] + 1
    for field in (
        "conversationId", "generation", "groupId", "epoch", "groupContextHash", "confirmationTag",
    ):
        assert retired[field] == prior[field]
    transcript = close_domain + unsigned
    assert bytes.fromhex(vector["signingTranscriptHex"]) == transcript
    digest = hashlib.sha256(transcript).digest()
    assert bytes.fromhex(vector["requestDigestHex"]) == digest
    signature = bytes.fromhex(vector["signatureHex"])
    assert len(signature) == 64 and ed25519_verify(public_key, transcript, signature)

    entry_cbor = bytes.fromhex(vector["conversationCloseEntryCanonicalDagCborHex"])
    entry = decode_dag_cbor(entry_cbor)
    assert set(entry) == {
        "entryId", "conversationId", "seq", "signedRequest", "receivedAt", "tombstone",
    }
    assert set(entry["signedRequest"]) == {"body", "signature"}
    assert entry["signedRequest"] == {"body": body, "signature": signature}
    assert entry["conversationId"] == prior["conversationId"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", entry["receivedAt"])
    tombstone = entry["tombstone"]
    assert set(tombstone) == {
        "conversationId", "conversationKind", "retired", "terminalSeq", "closedByDid",
        "closedByDeviceId", "closedAt",
    }
    assert tombstone == {
        "conversationId": entry["conversationId"],
        "conversationKind": body["conversationKind"],
        "retired": retired,
        "terminalSeq": entry["seq"],
        "closedByDid": body["actorDid"],
        "closedByDeviceId": body["actorDeviceId"],
        "closedAt": entry["receivedAt"],
    }

    projection_cbor = bytes.fromhex(vector["fingerprintProjectionCanonicalDagCborHex"])
    projection = decode_dag_cbor(projection_cbor)
    assert set(projection) == {
        "entryKind", "entryId", "conversationId", "seq", "requestDigest", "signature",
        "serverFields", "receivedAt",
    }
    assert projection == {
        "entryKind": close_entry_kind,
        "entryId": entry["entryId"],
        "conversationId": entry["conversationId"],
        "seq": entry["seq"],
        "requestDigest": digest,
        "signature": signature,
        "serverFields": {"tombstone": tombstone},
        "receivedAt": entry["receivedAt"],
    }
    fingerprint = hashlib.sha256(fingerprint_domain + projection_cbor).digest()
    assert fingerprint.hex() == vector["fingerprintSha256Hex"]

    recipient = vector["terminalRecipient"]
    signer = vector["authorizedCloseSigner"]
    for actor in (recipient, signer):
        assert set(actor) == {"actorDid", "actorDeviceId"}
    assert recipient == {
        "actorDid": "did:plc:alicefixtureaaaaaaaaaaaa",
        "actorDeviceId": "70707070-7070-4070-b070-707070707070",
    }
    assert signer == {
        "actorDid": body["actorDid"],
        "actorDeviceId": str(uuid.UUID(bytes=body["actorDeviceId"])),
    }
    assert recipient != signer
    assert actor_keys[(signer["actorDid"], signer["actorDeviceId"])] == public_key
    assert uuid.UUID(recipient["actorDeviceId"]).bytes not in projection_cbor
    roster = vector["signerScenarioRosterBinding"]
    assert roster == {
        "conversationKind": "group", "participantStatus": "active", "participantRole": "admin",
        "mlsLeafState": "current",
        "liveMemberEvidenceRef": "liveProof.lanes[name=sameDidTwoDevice].right",
        "evidenceScope": "authoredScenarioInputNotServerAuthorizationProof",
    }
    same_did_lane = next(lane for lane in manifest["liveProof"]["lanes"] if lane["name"] == "sameDidTwoDevice")
    assert same_did_lane["right"] == signer

    reference = vector["contractFixtureReference"]
    compared_fields = [
        "entryKind", "signedRequestRef", "signingDomain",
        "unsignedSigningProjectionCanonicalDagCborHex", "signingTranscriptHex",
        "historicalPublicKeyRef", "entryId", "conversationId", "seq", "requestDigest",
        "signature", "serverFields", "receivedAt", "uuidBytePaths", "base64BytePaths",
        "canonicalDagCborHex", "fingerprintSha256Hex",
    ]
    assert set(reference) == {
        "path", "sourceSha256Hex", "root", "entryKind", "historicalPublicKeyRef",
        "comparedFields", "exactCrossLanguageEquality",
    }
    assert reference == {
        "path": "mls-ds/server/tests/fixtures/mls_chat_contract_vectors.json",
        "sourceSha256Hex": hashlib.sha256(VECTOR_PATH.read_bytes()).hexdigest(),
        "root": "controlEntryFingerprints",
        "entryKind": close_entry_kind,
        "historicalPublicKeyRef": "activeAdminDevice7272",
        "comparedFields": compared_fields,
        "exactCrossLanguageEquality": True,
    }
    contract_fixture = strict_load(VECTOR_PATH)
    contract = contract_fixture[reference["root"]]
    cases = [case for case in contract["cases"] if case["entryKind"] == close_entry_kind]
    assert len(cases) == 1
    case = cases[0]
    assert set(case) == set(compared_fields)
    assert case["signedRequestRef"] == vector["signedRequestRef"]
    assert case["signingDomain"].encode() == close_domain
    assert case["unsignedSigningProjectionCanonicalDagCborHex"] == vector[
        "unsignedSigningProjectionCanonicalDagCborHex"
    ]
    assert case["signingTranscriptHex"] == vector["signingTranscriptHex"]
    assert contract["historicalPublicKeys"][case["historicalPublicKeyRef"]] == public_key.hex()
    contract_projection = {
        "entryKind": case["entryKind"],
        "entryId": case["entryId"],
        "conversationId": case["conversationId"],
        "seq": case["seq"],
        "requestDigest": case["requestDigest"],
        "signature": case["signature"],
        "serverFields": case["serverFields"],
        "receivedAt": case["receivedAt"],
    }
    converted_projection = fixture_projection(
        contract_projection, case["uuidBytePaths"], case["base64BytePaths"]
    )
    assert converted_projection == projection
    assert encode_dag_cbor(converted_projection).hex() == case["canonicalDagCborHex"]
    assert case["fingerprintSha256Hex"] == vector["fingerprintSha256Hex"]

    binding = vector["scenarioBinding"]
    assert set(binding) == {
        "scenarioName", "stepIndex", "controlName", "entryIdHex", "conversationIdHex",
        "seq", "transitionIdHex", "terminalOuterEntryFingerprintHex",
    }
    assert binding == {
        "scenarioName": "terminalAfterRemoveClosedGap",
        "stepIndex": 7,
        "controlName": "terminalAfterRemove.terminal",
        "entryIdHex": entry["entryId"].hex(),
        "conversationIdHex": entry["conversationId"].hex(),
        "seq": entry["seq"],
        "transitionIdHex": body["transitionId"].hex(),
        "terminalOuterEntryFingerprintHex": fingerprint.hex(),
    }
    scenario = next(
        scenario for scenario in manifest["reducerScenarios"] if scenario["name"] == binding["scenarioName"]
    )
    step = scenario["steps"][binding["stepIndex"]]
    replay = scenario["steps"][binding["stepIndex"] + 1]
    control = step["control"]
    assert set(control) == {
        "entryIdHex", "transitionIdHex", "seq", "outerEntryFingerprintHex", "kind",
        "recipientDid", "recipientDeviceId", "previous", "evidenceMode",
        "signedControlEnvelopeRef",
    }
    assert control["kind"] == "terminal"
    assert control["evidenceMode"] == "signedControlEnvelopeBound"
    assert control["signedControlEnvelopeRef"] == vector["name"]
    assert control["entryIdHex"] == binding["entryIdHex"]
    assert control["transitionIdHex"] == binding["transitionIdHex"]
    assert control["seq"] == binding["seq"]
    assert control["outerEntryFingerprintHex"] == binding["terminalOuterEntryFingerprintHex"]
    assert (control["recipientDid"], control["recipientDeviceId"]) == (
        recipient["actorDid"], recipient["actorDeviceId"],
    )
    assert control["previous"] == {
        "conversationIdHex": prior["conversationId"].hex(),
        "generation": prior["generation"], "stateVersion": prior["stateVersion"],
        "groupIdHex": prior["groupId"].hex(), "epoch": prior["epoch"],
        "groupContextHashHex": prior["groupContextHash"].hex(),
        "confirmationTagHex": prior["confirmationTag"].hex(), "lifecycle": prior["lifecycle"],
    }
    assert step["expect"]["result"] == {"status": "ok", "code": "conversationTerminated", "detail": {}}
    terminal_proof = step["expect"]["stateAfter"]["terminalProof"]
    assert terminal_proof["outerEntryFingerprintHex"] == fingerprint.hex()
    assert terminal_proof["entryIdHex"] == entry["entryId"].hex()
    assert terminal_proof["transitionIdHex"] == body["transitionId"].hex()
    assert terminal_proof["seq"] == entry["seq"]
    assert step["expect"]["stateBefore"]["accessIntervals"][0]["closing"]["kind"] == "remove"
    assert step["expect"]["stateBefore"]["accessIntervals"][0]["closing"]["seq"] == 3
    assert replay["control"] == control
    assert replay["expect"]["result"] == {"status": "ok", "code": "exactReplay", "detail": {}}
    assert replay["expect"]["stateBefore"] == replay["expect"]["stateAfter"]
    references = [
        (scenario["name"], index, candidate["control"]["signedControlEnvelopeRef"])
        for scenario in manifest["reducerScenarios"]
        for index, candidate in enumerate(scenario["steps"])
        if candidate["op"] == "control" and "signedControlEnvelopeRef" in candidate["control"]
    ]
    assert references == [
        ("terminalAfterRemoveClosedGap", 7, vector["name"]),
        ("terminalAfterRemoveClosedGap", 8, vector["name"]),
    ]


def validate_application_contract() -> None:
    if not APPLICATION_PROTOCOL_PATH.is_file():
        return
    application_source = APPLICATION_PROTOCOL_PATH.read_text(encoding="utf-8")
    application_prose = " ".join(application_source.split())
    assert "| AT URI | 1,097 |" in application_source
    assert "| AT URI | 2,048 |" not in application_source
    for phrase in (
        "Catbird Chat Application Content Protocol v1",
        "The authoritative append row is exactly `{entryId, conversationId, seq, signedRequest, receivedAt}`",
        "the row carries no duplicated unsigned actor, device, coordinate, message, application-artifact, blob-binding, or fingerprint field",
        "`entry.conversationId` equals `entry.signedRequest.body.prior.conversationId`",
        "verifies its 64-byte Ed25519 signature over the exact `CATBIRD-CHAT-MESSAGE\\0` canonical signing transcript before decrypting",
        "come only from that verified body",
        "It is not a transported `applicationEntry` property",
        "authenticated MLS member-leaf credential tuple `(actorDid, actorDeviceId)` is the sole post-decrypt attribution and display authority",
        "Verified `signedRequest.body.actorDid`/`actorDeviceId` MUST equal that leaf tuple",
        "signed-body or transport identity alone is never an attribution authority",
        "production canonical bare ATProto DID of exactly 12–261 ASCII bytes",
        "BasicCredential identity is therefore 49–298 bytes",
        "CATBIRD-CHAT-APPLICATION-ENTRY-FINGERPRINT\\0",
        "`requestDigest` is the already-frozen raw SHA-256 of the exact `CATBIRD-CHAT-MESSAGE\\0` signing transcript",
        "without claiming those server fields were client-signed",
        "plaintext-only digest, or an unsigned outer surrogate",
        "`encryptedImage.blurhash`, when present, is exactly `6..=256` UTF-8 bytes",
        "Allowed MIME types are `image/heic`, `image/jpeg`, `image/png`, `image/webp`, and `image/gif`",
        "one Unicode 17.0.0 NFC, control-free UAX #29 extended grapheme cluster under Unicode 17.0.0, <= 64 UTF-8 bytes",
        "deliberately unescaped restricted canonical AT URI",
        "at most exactly 1,097 ASCII bytes",
        "a percent sign/escape is forbidden anywhere",
        "hostname-level `did:web`",
        "path/port/IP/single-label/`localhost` forms",
        "`handle.invalid` is not accepted",
        "`.` or `..` record key",
        "including canonical CIDv0 where applicable",
        "a valid port when present",
        "`ciphertextSize == plaintextSize + 16`",
        "`applicationAttachmentBinding`, whose purpose is structurally fixed to `attachment`",
        "distinct `metadataAvatarBinding`, whose purpose is structurally fixed to `metadata`",
        "separate `uploadedBlobBinding` result type",
        "The reducer and every interval are bound to one exact recipient",
        "Every finite inclusive `endSeq` has exact authenticated close proof",
        "The only legal touching schedules are `Replace -> Add` and `Reset -> Reset`",
        "Every finite inclusive `endSeq` is strictly greater than that interval's `startSeq`",
        "Sequence equality means only prior close seq equals successor opening seq",
        "Creation/open plus terminal close at that same seq is invalid",
        "`Remove` requires a strict later gap before any `Add`; terminal close has no successor",
        "registered active-admin reset activator who was not an old leaf",
        "`terminalSeq` only as navigation/wakeup data, never as interval-close authority",
        "Terminal also finalizes the recipient schedule",
        "separate irreversible schedule-level terminal proof",
        "does not claim `previous` equals the reducer's stale post-close expected context",
        "bounded exact-device control queries",
        "A reducer is permanently bound to one immutable `conversationId`",
        "every authenticated control row that changes chat context MUST have `previous == expected`",
        "no later row or reanchor is accepted",
        "only from the verified Welcome or post-join opening transition identity and context for that interval",
        "the exact shared authenticated opening control is processed once",
        "mid-interval reanchor, cross-conversation context, or reanchor after terminal close is terminal invalid",
        "Reactions exist only inside encrypted MLS application content",
        "Unsupported protocol/version",
        "Supported v1 with an unknown field/variant, null, or other semantic failure",
        "verifies the manifest’s own provenance and every vector SHA-256/length",
        "provenance binds the generator source, `Cargo.toml`, `Cargo.lock`, and every executed local path-dependency source tree",
        "real two-member OpenMLS `process_message` roundtrip",
        "exact plaintext, AAD, sender-member `BasicCredential`, and sender leaf signature key",
        "enforces sender and outer-blob mismatch cases",
    ):
        assert phrase in application_prose, f"application protocol missing phrase: {phrase}"

    manifest_path, overridden = application_manifest_path()
    assert manifest_path.is_file(), f"missing application corpus manifest: {manifest_path}"
    manifest_bytes = manifest_path.read_bytes()
    assert manifest_bytes.endswith(b"\n")
    if not overridden:
        assert hashlib.sha256(manifest_bytes).hexdigest() == FROZEN_APPLICATION_MANIFEST_SHA256
    manifest = strict_json_loads(manifest_bytes.decode("utf-8"))
    assert set(manifest) == {
        "schemaVersion", "protocol", "protocolVersion", "encoding", "generator", "identity",
        "context", "liveProof", "limits", "utf8BoundaryVectors", "vectors",
        "authorityBoundaryVectors", "hintAuthorityBoundaryVectors", "signedControlEnvelopeVectors",
        "identityBoundaryVectors", "outerEntryRejectionVectors", "reducerInitializationVectors",
        "reducerScheduleValidationVectors", "reducerScenarios",
    }
    assert manifest["schemaVersion"] == 1
    assert manifest["protocol"] == "blue.catbird.chat.application"
    assert manifest["protocolVersion"] == 1
    assert manifest["encoding"] == "deterministic RFC8949 length-first DAG-CBOR"
    assert manifest["limits"] == {
        "frameBytes": 65_536,
        "imageCiphertextBytes": 10_485_760,
        "audioCiphertextBytes": 8_388_608,
        "waveformSamples": 64,
        "waveformSampleMinimum": 0,
        "waveformSampleMaximum": 255,
        "waveformSemantics": (
            "chronological equal-duration amplitude buckets; presentation-only and untrusted"
        ),
    }

    identity = manifest["identity"]
    assert set(identity) == {
        "actorDid", "actorDeviceId", "credentialIdentity", "signaturePublicKeyHex", "actors",
    }
    assert identity["credentialIdentity"] == f'{identity["actorDid"]}#{identity["actorDeviceId"]}'
    assert len(bytes.fromhex(identity["signaturePublicKeyHex"])) == 32
    actors = identity["actors"]
    assert len(actors) == 2
    actor_keys: dict[tuple[str, str], bytes] = {}
    for actor in actors:
        assert set(actor) == {"actorDid", "devices"}
        assert actor["devices"]
        for device in actor["devices"]:
            assert set(device) == {"actorDeviceId", "credentialIdentity", "signaturePublicKeyHex"}
            assert device["credentialIdentity"] == f'{actor["actorDid"]}#{device["actorDeviceId"]}'
            public_key = bytes.fromhex(device["signaturePublicKeyHex"])
            assert len(public_key) == 32
            key = (actor["actorDid"], device["actorDeviceId"])
            assert key not in actor_keys
            actor_keys[key] = public_key
    assert actor_keys[(identity["actorDid"], identity["actorDeviceId"])] == bytes.fromhex(
        identity["signaturePublicKeyHex"]
    )
    context = manifest["context"]
    assert set(context) == {
        "conversationIdHex", "generation", "stateVersion", "groupIdHex", "epoch",
        "groupContextHashHex", "confirmationTagHex", "lifecycle",
    }
    assert len(bytes.fromhex(context["conversationIdHex"])) == 16
    for field in ("groupIdHex", "groupContextHashHex", "confirmationTagHex"):
        assert len(bytes.fromhex(context[field])) == 32
    assert context["lifecycle"] == "active"
    validate_application_provenance(manifest["generator"])
    validate_application_manifest_categories(manifest, actor_keys)


def encode_major(major: int, length: int) -> bytes:
    assert 0 <= major <= 7 and 0 <= length <= SAFE_INTEGER_MAX
    prefix = major << 5
    if length < 24:
        return bytes([prefix | length])
    if length <= 0xFF:
        return bytes([prefix | 24, length])
    if length <= 0xFFFF:
        return bytes([prefix | 25]) + length.to_bytes(2, "big")
    if length <= 0xFFFFFFFF:
        return bytes([prefix | 26]) + length.to_bytes(4, "big")
    return bytes([prefix | 27]) + length.to_bytes(8, "big")


def encode_dag_cbor(value: Any) -> bytes:
    """Minimal strict RFC 8949 section 4.2.3 DAG-CBOR encoder for golden vectors."""
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int) and 0 <= value <= SAFE_INTEGER_MAX:
        return encode_major(0, value)
    if isinstance(value, bytes):
        return encode_major(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return encode_major(3, len(encoded)) + encoded
    if isinstance(value, list):
        return encode_major(4, len(value)) + b"".join(encode_dag_cbor(item) for item in value)
    if isinstance(value, dict):
        items = []
        for key, item in value.items():
            assert isinstance(key, str)
            encoded_key = encode_dag_cbor(key)
            items.append((len(encoded_key), encoded_key, encode_dag_cbor(item)))
        items.sort(key=lambda item: (item[0], item[1]))
        return encode_major(5, len(items)) + b"".join(key + item for _, key, item in items)
    raise AssertionError(f"unsupported fixture value: {value!r}")


def decode_dag_cbor(encoded: bytes) -> Any:
    """Decode the finite DAG-CBOR subset used by the signing goldens."""

    def read_argument(additional: int, offset: int) -> tuple[int, int]:
        if additional < 24:
            return additional, offset
        width = {24: 1, 25: 2, 26: 4, 27: 8}.get(additional)
        if width is None or offset + width > len(encoded):
            raise ValueError("invalid or truncated DAG-CBOR argument")
        value = int.from_bytes(encoded[offset:offset + width], "big")
        minimum = {1: 24, 2: 0x100, 4: 0x10000, 8: 0x100000000}[width]
        if value < minimum:
            raise ValueError("nonminimal DAG-CBOR argument")
        return value, offset + width

    def decode_at(offset: int) -> tuple[Any, int]:
        if offset >= len(encoded):
            raise ValueError("truncated DAG-CBOR item")
        initial = encoded[offset]
        offset += 1
        major = initial >> 5
        additional = initial & 0x1F

        if major == 0:
            value, offset = read_argument(additional, offset)
            if value > SAFE_INTEGER_MAX:
                raise ValueError("DAG-CBOR integer exceeds safe range")
            return value, offset
        if major in (2, 3):
            length, offset = read_argument(additional, offset)
            end = offset + length
            if end > len(encoded):
                raise ValueError("truncated DAG-CBOR string")
            value = encoded[offset:end]
            if major == 3:
                value = value.decode("utf-8")
            return value, end
        if major == 4:
            length, offset = read_argument(additional, offset)
            values = []
            for _ in range(length):
                value, offset = decode_at(offset)
                values.append(value)
            return values, offset
        if major == 5:
            length, offset = read_argument(additional, offset)
            result: dict[str, Any] = {}
            for _ in range(length):
                key, offset = decode_at(offset)
                if not isinstance(key, str) or key in result:
                    raise ValueError("DAG-CBOR map keys must be unique text")
                result[key], offset = decode_at(offset)
            return result, offset
        if major == 7 and additional in (20, 21):
            return additional == 21, offset
        raise ValueError("unsupported DAG-CBOR item in signing golden")

    value, final_offset = decode_at(0)
    if final_offset != len(encoded):
        raise ValueError("trailing DAG-CBOR bytes")
    if encode_dag_cbor(value) != encoded:
        raise ValueError("noncanonical DAG-CBOR signing projection")
    return value


_ED25519_P = 2**255 - 19
_ED25519_Q = 2**252 + 27742317777372353535851937790883648493
_ED25519_D = (-121665 * pow(121666, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
_ED25519_I = pow(2, (_ED25519_P - 1) // 4, _ED25519_P)


def ed25519_recover_x(y: int, sign: int) -> int:
    if y >= _ED25519_P:
        raise ValueError("non-canonical Ed25519 y-coordinate")
    xx = ((y * y - 1) * pow(_ED25519_D * y * y + 1, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
    x = pow(xx, (_ED25519_P + 3) // 8, _ED25519_P)
    if (x * x - xx) % _ED25519_P != 0:
        x = (x * _ED25519_I) % _ED25519_P
    if (x * x - xx) % _ED25519_P != 0:
        raise ValueError("invalid Ed25519 point")
    if (x & 1) != sign:
        x = _ED25519_P - x
    return x


def ed25519_decode_point(encoded: bytes) -> tuple[int, int, int, int]:
    if len(encoded) != 32:
        raise ValueError("invalid Ed25519 point length")
    encoded_y = int.from_bytes(encoded, "little")
    y = encoded_y & ((1 << 255) - 1)
    x = ed25519_recover_x(y, encoded_y >> 255)
    point = (x, y, 1, (x * y) % _ED25519_P)
    if ed25519_encode_point(point) != encoded:
        raise ValueError("non-canonical Ed25519 point")
    return point


def ed25519_encode_point(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    inverse_z = pow(z, _ED25519_P - 2, _ED25519_P)
    affine_x = (x * inverse_z) % _ED25519_P
    affine_y = (y * inverse_z) % _ED25519_P
    return (affine_y | ((affine_x & 1) << 255)).to_bytes(32, "little")


def ed25519_add(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = ((y1 - x1) * (y2 - x2)) % _ED25519_P
    b = ((y1 + x1) * (y2 + x2)) % _ED25519_P
    c = (2 * _ED25519_D * t1 * t2) % _ED25519_P
    d = (2 * z1 * z2) % _ED25519_P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % _ED25519_P, g * h % _ED25519_P, f * g % _ED25519_P, e * h % _ED25519_P)


def ed25519_multiply(
    scalar: int, point: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = ed25519_add(result, point)
        point = ed25519_add(point, point)
        scalar >>= 1
    return result


_ED25519_BASE_Y = (4 * pow(5, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
_ED25519_BASE_X = ed25519_recover_x(_ED25519_BASE_Y, 0)
_ED25519_BASE = (
    _ED25519_BASE_X,
    _ED25519_BASE_Y,
    1,
    (_ED25519_BASE_X * _ED25519_BASE_Y) % _ED25519_P,
)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= _ED25519_Q:
        return False
    try:
        public_point = ed25519_decode_point(public_key)
        nonce_point = ed25519_decode_point(signature[:32])
    except ValueError:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % _ED25519_Q
    expected = ed25519_add(nonce_point, ed25519_multiply(challenge, public_point))
    return ed25519_encode_point(ed25519_multiply(scalar, _ED25519_BASE)) == ed25519_encode_point(expected)


def set_fixture_path(value: Any, path: str, replacement: Any) -> None:
    current = value
    parts = path.split(".")
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    final = parts[-1]
    if isinstance(current, list):
        current[int(final)] = replacement
    else:
        current[final] = replacement


def fixture_projection(
    value: dict[str, Any], uuid_paths: list[str], base64_paths: list[str]
) -> dict[str, Any]:
    projection = copy.deepcopy(value)
    for path in uuid_paths:
        current = projection
        parts = path.split(".")
        for part in parts:
            current = current[int(part)] if isinstance(current, list) else current[part]
        assert isinstance(current, str) and UUID_V4_RE.fullmatch(current), path
        set_fixture_path(projection, path, uuid.UUID(current).bytes)
    for path in base64_paths:
        current = projection
        parts = path.split(".")
        for part in parts:
            current = current[int(part)] if isinstance(current, list) else current[part]
        assert isinstance(current, str)
        set_fixture_path(projection, path, base64.b64decode(current, validate=True))
    return projection


def validate_vectors(documents: dict[str, dict[str, Any]], vectors: dict[str, Any]) -> None:
    grammar = vectors["grammar"]
    for value in grammar["validTimestamps"]:
        assert TIMESTAMP_RE.fullmatch(value), value
        dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc)
    for value in grammar["invalidTimestamps"]:
        if not TIMESTAMP_RE.fullmatch(value):
            continue
        try:
            dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            continue
        raise AssertionError(value)
    for value in grammar["validUuidV4"]:
        assert UUID_V4_RE.fullmatch(value), value
    for value in grammar["invalidUuidV4"]:
        assert not UUID_V4_RE.fullmatch(value), value
    for value in grammar["validBareDids"]:
        assert is_valid_bare_did(value), value
    for value in grammar["invalidBareDids"]:
        assert not is_valid_bare_did(value), value
    for case in grammar["didCaseMutations"]:
        assert is_valid_bare_did(case["accepted"])
        assert not is_valid_bare_did(case["rejected"])
        assert case["accepted"].encode("utf-8") != case["rejected"].encode("utf-8")
    hostname_253 = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])
    hostname_254 = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 62])
    assert len(hostname_253) == 253 and is_valid_bare_did(f"did:web:{hostname_253}")
    assert len(hostname_254) == 254 and not is_valid_bare_did(f"did:web:{hostname_254}")
    bare_did_bounds = grammar["bareDidByteBounds"]
    assert bare_did_bounds == {
        "minimum": 12, "maximum": 261,
        "basicCredentialMinimum": 49, "basicCredentialMaximum": 298,
    }
    shortest_did = "did:web:a.co"
    longest_did = f"did:web:{hostname_253}"
    device_id = "00000000-0000-4000-8000-000000000000"
    assert len(shortest_did.encode("ascii")) == bare_did_bounds["minimum"]
    assert len(longest_did.encode("ascii")) == bare_did_bounds["maximum"]
    assert len(f"{shortest_did}#{device_id}".encode("ascii")) == bare_did_bounds["basicCredentialMinimum"]
    assert len(f"{longest_did}#{device_id}".encode("ascii")) == bare_did_bounds["basicCredentialMaximum"]

    def decode_canonical_jti(value: str) -> bytes | None:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", value) or "=" in value:
            return None
        try:
            decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
        except (ValueError, base64.binascii.Error):
            return None
        if not 12 <= len(decoded) <= 32:
            return None
        if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
            return None
        return decoded

    assert all(decode_canonical_jti(value) is not None for value in grammar["validDpopJti"])
    assert all(decode_canonical_jti(value) is None for value in grammar["invalidDpopJti"])
    for value in grammar["validKeyIds"]:
        assert KEY_ID_RE.fullmatch(value) and "=" not in value
    for value in grammar["invalidKeyIds"]:
        assert not KEY_ID_RE.fullmatch(value) or "=" in value

    ordering = vectors["canonicalOrdering"]
    assert sorted(ordering["strings"], key=lambda item: item.encode("utf-8")) == ordering["expectedStrings"]
    byte_values = [base64.b64decode(value, validate=True) for value in ordering["bytesBase64"]]
    assert sorted(byte_values) == [base64.b64decode(value, validate=True) for value in ordering["expectedBytesBase64"]]

    dag = vectors["dagCbor"]
    encoded = encode_dag_cbor(dag["value"])
    assert encoded.hex() == dag["canonicalHex"]
    assert hashlib.sha256(encoded).hexdigest() == dag["sha256Hex"]
    assert hashlib.sha256(encoded + b"\0").hexdigest() != dag["sha256Hex"]

    signature = vectors["ed25519"]
    assert len(bytes.fromhex(signature["publicKeyHex"])) == 32
    assert len(bytes.fromhex(signature["signatureHex"])) == 64
    assert signature["mutatedSignatureHex"] != signature["signatureHex"]

    mutator = vectors["signedMutator"]
    transport_body = mutator["body"]
    assert transport_body["$type"] == f"{PREFIX}.defs#blobDeletionBody"
    projection = copy.deepcopy(transport_body)
    for field in mutator["uuidByteFields"]:
        assert UUID_V4_RE.fullmatch(projection[field])
        projection[field] = uuid.UUID(projection[field]).bytes
    unsigned = encode_dag_cbor(projection)
    assert unsigned.hex() == mutator["canonicalUnsignedDagCborHex"]
    transcript = transport_body["signatureDomain"].encode("utf-8") + unsigned
    assert transcript.hex() == mutator["transcriptHex"]
    assert transcript.startswith(b"CATBIRD-CHAT-BLOB-DELETE\0")
    request_digest = hashlib.sha256(transcript).digest()
    assert len(request_digest) == 32
    assert request_digest.hex() == mutator["canonicalRequestDigestHex"]
    assert len(bytes.fromhex(mutator["publicKeyHex"])) == 32
    assert len(bytes.fromhex(mutator["signatureHex"])) == 64
    mutated_transport = copy.deepcopy(transport_body)
    mutated_transport[mutator["mutation"]["field"]] = mutator["mutation"]["value"]
    mutated_projection = copy.deepcopy(mutated_transport)
    for field in mutator["uuidByteFields"]:
        mutated_projection[field] = uuid.UUID(mutated_projection[field]).bytes
    mutated_transcript = mutated_transport["signatureDomain"].encode("utf-8") + encode_dag_cbor(mutated_projection)
    assert mutated_transcript.hex() == mutator["mutatedTranscriptHex"]
    assert mutated_transcript != transcript
    mutated_request_digest = hashlib.sha256(mutated_transcript).digest()
    assert mutated_request_digest.hex() == mutator["mutatedRequestDigestHex"]
    assert mutated_request_digest != request_digest
    assert len(bytes.fromhex(mutator["signatureHex"])) == 64

    auth = vectors["standardServiceAuth"]
    assert auth["serviceRef"] == "did:web:chat.catbird.blue#atproto_mls"
    assert auth["maxTokenLifetimeSeconds"] == 60
    assert auth["requiredTokenClaims"] == ["iss", "aud", "lxm", "iat", "exp", "jti"]
    assert auth["exactAudienceRequired"] is True
    assert auth["exactMethodLxmRequired"] is True
    assert auth["issuerVerificationMethod"] == "#atproto"
    assert auth["jtiConsumedOnce"] is True
    assert auth["delegatedNestTokensAccepted"] is False
    assert auth["customCleanChatDpopAccepted"] is False
    assert auth["accountAuthorityFields"] == ["iss", "aud", "lxm", "iat", "exp", "jti"]
    assert auth["deviceAuthorityFields"] == [
        "actorDid", "actorDeviceId", "keyId", "authGeneration", "signature",
    ]
    assert auth["enrollmentGeneration"] == 0
    assert auth["clientDeviceIdAuthoritative"] is True
    assert auth["basicCredentialIdentity"] == "actorDid#deviceId"
    assert auth["exactReplayReturnsStoredResult"] is True

    entry_fingerprint = vectors["applicationEntryFingerprint"]
    assert entry_fingerprint["domain"] == "CATBIRD-CHAT-APPLICATION-ENTRY-FINGERPRINT\0"
    fingerprint_fields = (
        "entryId", "conversationId", "seq", "requestDigest", "signature", "receivedAt",
    )
    fingerprint_input = {field: entry_fingerprint[field] for field in fingerprint_fields}
    assert TIMESTAMP_RE.fullmatch(fingerprint_input["receivedAt"])
    projected_entry = fixture_projection(
        fingerprint_input,
        entry_fingerprint["uuidBytePaths"],
        entry_fingerprint["base64BytePaths"],
    )
    assert set(projected_entry) == set(fingerprint_fields)
    assert len(projected_entry["entryId"]) == 16
    assert len(projected_entry["conversationId"]) == 16
    assert len(projected_entry["requestDigest"]) == 32
    assert len(projected_entry["signature"]) == 64
    encoded_entry_fingerprint = encode_dag_cbor(projected_entry)
    assert encoded_entry_fingerprint.hex() == entry_fingerprint["canonicalDagCborHex"]
    fingerprint_domain = entry_fingerprint["domain"].encode("utf-8")
    frozen_fingerprint = hashlib.sha256(fingerprint_domain + encoded_entry_fingerprint).digest()
    assert frozen_fingerprint.hex() == entry_fingerprint["fingerprintSha256Hex"]
    fingerprint_mutations = {
        "entryId": "018f3f6a-7b2c-4d91-8a5e-0f123456789b",
        "conversationId": "3b241101-e2bb-4255-8caf-4136c566a963",
        "seq": 43,
        "requestDigest": base64.b64encode(b"V" * 32).decode("ascii"),
        "signature": base64.b64encode(b"g" * 64).decode("ascii"),
        "receivedAt": "2026-07-22T14:05:09.124Z",
    }
    for field, replacement in fingerprint_mutations.items():
        mutated = copy.deepcopy(fingerprint_input)
        mutated[field] = replacement
        mutated_bytes = encode_dag_cbor(fixture_projection(
            mutated,
            entry_fingerprint["uuidBytePaths"],
            entry_fingerprint["base64BytePaths"],
        ))
        assert hashlib.sha256(fingerprint_domain + mutated_bytes).digest() != frozen_fingerprint

    control_fingerprints = vectors["controlEntryFingerprints"]
    assert control_fingerprints["domain"] == "CATBIRD-CHAT-CONTROL-ENTRY-FINGERPRINT\0"
    control_projection_fields = (
        "entryKind", "entryId", "conversationId", "seq", "requestDigest",
        "signature", "serverFields", "receivedAt",
    )
    assert control_fingerprints["projectionFields"] == list(control_projection_fields)
    assert control_fingerprints["ordinaryServerFields"] == {}
    assert control_fingerprints["nonemptyServerFields"] == {
        f"{PREFIX}.defs#participantAcceptanceEntry": ["recovery"],
        f"{PREFIX}.defs#conversationCloseEntry": ["tombstone"],
    }
    public_keys = {
        key_ref: bytes.fromhex(public_key_hex)
        for key_ref, public_key_hex in control_fingerprints["historicalPublicKeys"].items()
    }
    assert public_keys and all(len(public_key) == 32 for public_key in public_keys.values())
    assert "requesterDevice7070" in public_keys
    assert public_keys["requesterDevice7070"].hex() == (
        "8ca63145907a2e6c5fb3dc0791c0189b8252da3e4143704b3b2ca4e526f25dd1"
    )
    authoritative_reference_bindings = control_fingerprints["authoritativeReferenceBindings"]
    assert authoritative_reference_bindings == {
        f"{PREFIX}.defs#leaveCancellationEntry": {
            "referenceEntryKind": f"{PREFIX}.defs#leaveRequestEntry",
            "referenceSignedRequestRef": f"{PREFIX}.defs#signedLeaveRequest",
            "referenceEntryId": "89898989-8989-4989-8989-898989898989",
            "referenceSeq": 51,
            "referenceField": "leaveRequestId",
            "referenceValue": "00000000-0000-4000-8000-000000000041",
            "conversationId": "11111111-1111-4111-9111-111111111111",
            "requesterDid": "did:plc:alicefixtureaaaaaaaaaaaa",
            "referenceActorDeviceId": "70707070-7070-4070-b070-707070707070",
            "referenceKeyId": "nPA28lsnpJybeU3AHnUN7Kj8EqPuYa7O13Rtuo1zAYA",
            "referenceAuthGeneration": 1,
            "referenceHistoricalPublicKeyRef": "requesterDevice7070",
            "cancellationActorDeviceId": "72727272-7272-4272-b272-727272727272",
            "cancellationActorDeviceStatus": "active",
            "cancellationKeyId": "OQpJSMbjoMkp9Mz8qJRGo6zAieMT1g9qNZJr8WtW6i8",
            "cancellationAuthGeneration": 1,
            "cancellationHistoricalPublicKeyRef": "activeAdminDevice7272",
            "actorDeviceMayDifferOnlyWithinSameDid": True,
            "referenceEntryDistinctAndStrictlyEarlier": True,
            "leaveRequestIdIsGlobalSignedRequestKey": True,
            "retainedReferenceIndependentlyVerifiable": True,
        }
    }

    control_cases = control_fingerprints["cases"]
    assert len(control_cases) == len(CONTROL_ENTRY_FINGERPRINT_KINDS) == 13
    assert {case["entryKind"] for case in control_cases} == set(CONTROL_ENTRY_FINGERPRINT_KINDS)
    assert len({case["fingerprintSha256Hex"] for case in control_cases}) == len(control_cases)
    control_fingerprint_domain = control_fingerprints["domain"].encode("utf-8")
    defs_document = documents[f"{PREFIX}.defs.json"]
    decoded_control_cases: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    signature_verified_kinds: set[str] = set()
    fingerprint_verified_kinds: set[str] = set()
    expected_case_fields = {
        "entryKind", "signedRequestRef", "signingDomain",
        "unsignedSigningProjectionCanonicalDagCborHex", "signingTranscriptHex",
        "historicalPublicKeyRef", "entryId", "conversationId", "seq",
        "requestDigest", "signature", "serverFields", "receivedAt",
        "uuidBytePaths", "base64BytePaths", "canonicalDagCborHex",
        "fingerprintSha256Hex",
    }
    recovery_fields = {
        "recoveryRequestId", "conversationId", "requesterDid", "requesterDeviceId",
        "recoveryKind", "boundCoordinate", "reservation", "status", "requestedAt", "expiresAt",
    }
    reservation_fields = {
        "recoveryRequestId", "conversationId", "boundCoordinate", "requesterDid",
        "requesterDeviceId", "requesterKeyId", "requesterAuthGeneration", "keyPackageRef",
        "cipherSuite", "purpose", "status", "expiresAt", "keyPackage",
    }
    coordinate_fields = {
        "conversationId", "generation", "stateVersion", "groupId", "epoch",
        "groupContextHash", "confirmationTag", "lifecycle",
    }
    tombstone_fields = {
        "conversationId", "conversationKind", "retired", "closedByDid",
        "closedByDeviceId", "terminalSeq", "closedAt",
    }

    def collect_conversation_ids(value: Any) -> list[bytes]:
        found: list[bytes] = []
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "conversationId":
                    assert isinstance(child, bytes) and len(child) == 16
                    found.append(child)
                else:
                    found.extend(collect_conversation_ids(child))
        elif isinstance(value, list):
            for child in value:
                found.extend(collect_conversation_ids(child))
        return found

    def preflight_signed_control(
        entry_kind: str, verify_fingerprint: bool = True
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        case = next(case for case in control_cases if case["entryKind"] == entry_kind)
        signed_request_ref, _ = CONTROL_ENTRY_FINGERPRINT_KINDS[entry_kind]
        body_ref, signing_domain = SIGNED_PROJECTIONS[signed_request_ref]
        unsigned_projection = bytes.fromhex(
            case["unsignedSigningProjectionCanonicalDagCborHex"]
        )
        body = decode_dag_cbor(unsigned_projection)
        assert_closed_lexicon_value(
            documents,
            defs_document,
            defs_document["defs"][body_ref],
            body,
            f"controlEntryFingerprints.{entry_kind}.referencePreflight",
            f"{PREFIX}.defs#{body_ref}",
        )
        transcript = bytes.fromhex(case["signingTranscriptHex"])
        assert transcript == signing_domain.encode("utf-8") + unsigned_projection
        assert hashlib.sha256(transcript).digest() == base64.b64decode(
            case["requestDigest"], validate=True
        )
        public_key = public_keys[case["historicalPublicKeyRef"]]
        signature = base64.b64decode(case["signature"], validate=True)
        assert ed25519_verify(public_key, transcript, signature)
        if verify_fingerprint:
            fingerprint_input = {field: case[field] for field in control_projection_fields}
            encoded = encode_dag_cbor(fixture_projection(
                fingerprint_input, case["uuidBytePaths"], case["base64BytePaths"]
            ))
            assert encoded.hex() == case["canonicalDagCborHex"]
            assert hashlib.sha256(control_fingerprint_domain + encoded).hexdigest() == case[
                "fingerprintSha256Hex"
            ]
        return case, body

    preflight_leave_request_kind = f"{PREFIX}.defs#leaveRequestEntry"
    preflight_cancellation_kind = f"{PREFIX}.defs#leaveCancellationEntry"
    preflight_reference_case, preflight_reference_body = preflight_signed_control(
        preflight_leave_request_kind
    )
    preflight_cancellation_case, preflight_cancellation_body = preflight_signed_control(
        preflight_cancellation_kind, verify_fingerprint=False
    )
    preflight_binding = authoritative_reference_bindings[preflight_cancellation_kind]
    preflight_reference_id = uuid.UUID(preflight_binding["referenceValue"]).bytes
    assert preflight_reference_case["entryId"] != preflight_cancellation_case["entryId"]
    assert preflight_reference_case["seq"] < preflight_cancellation_case["seq"]
    assert preflight_reference_body["leaveRequestId"] == preflight_reference_id
    assert preflight_cancellation_body["leaveRequestId"] == preflight_reference_id
    assert preflight_reference_body["prior"]["conversationId"] == uuid.UUID(
        preflight_reference_case["conversationId"]
    ).bytes
    assert preflight_cancellation_body["conversationId"] == uuid.UUID(
        preflight_cancellation_case["conversationId"]
    ).bytes
    assert preflight_reference_body["prior"]["conversationId"] == preflight_cancellation_body[
        "conversationId"
    ]
    assert preflight_reference_body["actorDid"] == preflight_cancellation_body["actorDid"]
    assert preflight_reference_body["actorDeviceId"] != preflight_cancellation_body[
        "actorDeviceId"
    ]
    assert preflight_binding["cancellationActorDeviceStatus"] == "active"
    reference_preflight_passed_before_cancellation_fingerprint = True

    for case_index, case in enumerate(control_cases):
        assert set(case) == expected_case_fields
        signed_request_ref, server_field = CONTROL_ENTRY_FINGERPRINT_KINDS[case["entryKind"]]
        assert case["signedRequestRef"] == f"{PREFIX}.defs#{signed_request_ref}"
        body_ref, signing_domain = SIGNED_PROJECTIONS[signed_request_ref]
        assert case["signingDomain"] == signing_domain
        unsigned_projection = bytes.fromhex(case["unsignedSigningProjectionCanonicalDagCborHex"])
        unsigned_value = decode_dag_cbor(unsigned_projection)
        assert isinstance(unsigned_value, dict)
        decoded_control_cases[case["entryKind"]] = (case, unsigned_value)
        assert unsigned_value["$type"] == f"{PREFIX}.defs#{body_ref}"
        assert unsigned_value["signatureDomain"] == signing_domain
        assert_closed_lexicon_value(
            documents,
            defs_document,
            defs_document["defs"][body_ref],
            unsigned_value,
            f"controlEntryFingerprints.{case['entryKind']}.unsignedSigningProjection",
            f"{PREFIX}.defs#{body_ref}",
        )
        if case["entryKind"] == f"{PREFIX}.defs#policyEntry":
            participant_change = unsigned_value["participantChanges"][0]
            assert participant_change["$type"] == f"{PREFIX}.defs#addParticipant"
            tag_mutations = []
            missing_tag = copy.deepcopy(unsigned_value)
            missing_tag["participantChanges"][0].pop("$type")
            tag_mutations.append(missing_tag)
            wrong_tag = copy.deepcopy(unsigned_value)
            wrong_tag["participantChanges"][0]["$type"] = f"{PREFIX}.defs#removeParticipant"
            tag_mutations.append(wrong_tag)
            unknown_tag = copy.deepcopy(unsigned_value)
            unknown_tag["participantChanges"][0]["$type"] = f"{PREFIX}.defs#unknownParticipantChange"
            tag_mutations.append(unknown_tag)
            for mutated in tag_mutations:
                assert not closed_lexicon_value_is_valid(
                    documents,
                    defs_document,
                    defs_document["defs"][body_ref],
                    mutated,
                    f"{PREFIX}.defs#{body_ref}",
                )
        row_conversation_id = uuid.UUID(case["conversationId"]).bytes
        body_conversation_ids = collect_conversation_ids(unsigned_value)
        if body_conversation_ids:
            assert all(value == row_conversation_id for value in body_conversation_ids)
        else:
            binding = authoritative_reference_bindings[case["entryKind"]]
            assert binding["conversationId"] == case["conversationId"]
            assert unsigned_value[binding["referenceField"]] == uuid.UUID(
                binding["referenceValue"]
            ).bytes
        signing_transcript = bytes.fromhex(case["signingTranscriptHex"])
        assert signing_transcript == signing_domain.encode("utf-8") + unsigned_projection
        request_digest = hashlib.sha256(signing_transcript).digest()
        assert base64.b64decode(case["requestDigest"], validate=True) == request_digest

        public_key = public_keys[case["historicalPublicKeyRef"]]
        signature_bytes = base64.b64decode(case["signature"], validate=True)
        assert len(signature_bytes) == 64
        assert ed25519_verify(public_key, signing_transcript, signature_bytes)
        signature_verified_kinds.add(case["entryKind"])
        mutated_signature = bytearray(signature_bytes)
        mutated_signature[0] ^= 1
        assert not ed25519_verify(public_key, signing_transcript, bytes(mutated_signature))
        mutated_transcript = bytearray(signing_transcript)
        mutated_transcript[-1] ^= 1
        assert not ed25519_verify(public_key, bytes(mutated_transcript), signature_bytes)

        server_fields = case["serverFields"]
        if server_field is None:
            assert server_fields == control_fingerprints["ordinaryServerFields"]
        else:
            assert set(server_fields) == {server_field}
        if server_field == "recovery":
            recovery = server_fields["recovery"]
            assert set(recovery) == recovery_fields
            assert set(recovery["boundCoordinate"]) == coordinate_fields
            assert set(recovery["reservation"]) == reservation_fields
            assert set(recovery["reservation"]["boundCoordinate"]) == coordinate_fields
            assert set(recovery["reservation"]["keyPackage"]) == {
                "framing", "contentType", "bytes", "sha256", "keyPackageRef",
            }
        elif server_field == "tombstone":
            tombstone = server_fields["tombstone"]
            assert set(tombstone) == tombstone_fields
            assert set(tombstone["retired"]) == coordinate_fields
            expected_transition_bytes = bytearray(hashlib.sha256(
                b"CATBIRD-CHAT-SCENARIO-TRANSITION\0terminalAfterRemove.terminal"
            ).digest()[:16])
            expected_transition_bytes[6] = (expected_transition_bytes[6] & 0x0F) | 0x40
            expected_transition_bytes[8] = (expected_transition_bytes[8] & 0x3F) | 0x80
            expected_transition_id = uuid.UUID(bytes=bytes(expected_transition_bytes))
            assert str(expected_transition_id) == "03adfab0-b088-4e86-b992-0f611d2eb64a"
            assert case["entryId"] == "66666666-6666-4666-a666-666666666666"
            assert case["conversationId"] == "11111111-1111-4111-9111-111111111111"
            assert case["seq"] == 10
            assert case["historicalPublicKeyRef"] == "activeAdminDevice7272"
            assert public_keys[case["historicalPublicKeyRef"]].hex() == (
                "c6d0c796bb4c3c923615f8dc85e6fc35149eb6b1317de523d3a5085584f5c109"
            )
            assert case["requestDigest"] == "B37WM9HngLShUkvTt94rxCwTWJN7z/+k/osIAZ+Pwl0="
            assert case["signature"] == (
                "dkYfoSb/xeOsSriPc2333AIasgWsW/TOlq8vT09BBIApeOabmDPdIWsr7OkYwDA8u/2mTPyqbchg193pkratDQ=="
            )
            assert case["fingerprintSha256Hex"] == (
                "39009aff7d5685b763a84bb3956604eeff30b0d4720e041a612b3b62760eea5a"
            )
            assert case["receivedAt"] == "2026-07-22T12:34:56.000Z"
            assert unsigned_value["signedAt"] == "2026-07-22T12:34:55.000Z"
            assert unsigned_value["actorDid"] == "did:plc:alicefixtureaaaaaaaaaaaa"
            assert unsigned_value["actorDeviceId"] == uuid.UUID(
                "72727272-7272-4272-b272-727272727272"
            ).bytes
            assert unsigned_value["actorDeviceId"] != uuid.UUID(
                "70707070-7070-4070-b070-707070707070"
            ).bytes
            assert unsigned_value["transitionId"] == expected_transition_id.bytes
            prior = unsigned_value["prior"]
            retired = unsigned_value["retired"]
            assert prior == {
                "conversationId": row_conversation_id,
                "generation": 78,
                "stateVersion": 79,
                "groupId": b"\x22" * 32,
                "epoch": 3,
                "groupContextHash": b"\x7e" + b"\x33" * 31,
                "confirmationTag": b"\x09" + b"\x44" * 31,
                "lifecycle": "active",
            }
            assert retired == {**prior, "stateVersion": 80, "lifecycle": "superseded"}
            assert tombstone["closedByDid"] == unsigned_value["actorDid"]
            assert uuid.UUID(tombstone["closedByDeviceId"]).bytes == unsigned_value["actorDeviceId"]
            assert tombstone["terminalSeq"] == case["seq"]
            assert tombstone["closedAt"] == case["receivedAt"]

        fingerprint_input = {field: case[field] for field in control_projection_fields}
        if case["entryKind"] == f"{PREFIX}.defs#leaveCancellationEntry":
            assert reference_preflight_passed_before_cancellation_fingerprint is True
        assert set(fingerprint_input) == set(control_projection_fields)
        assert TIMESTAMP_RE.fullmatch(fingerprint_input["receivedAt"])
        assert type(fingerprint_input["seq"]) is int
        assert 1 <= fingerprint_input["seq"] <= SAFE_INTEGER_MAX
        projected_control = fixture_projection(
            fingerprint_input, case["uuidBytePaths"], case["base64BytePaths"]
        )
        assert len(projected_control["entryId"]) == 16
        assert len(projected_control["conversationId"]) == 16
        assert len(projected_control["requestDigest"]) == 32
        assert len(projected_control["signature"]) == 64
        encoded_control = encode_dag_cbor(projected_control)
        assert encoded_control.hex() == case["canonicalDagCborHex"]
        frozen_control_fingerprint = hashlib.sha256(
            control_fingerprint_domain + encoded_control
        ).digest()
        assert frozen_control_fingerprint.hex() == case["fingerprintSha256Hex"]
        fingerprint_verified_kinds.add(case["entryKind"])

        mutated_server_fields = copy.deepcopy(case["serverFields"])
        if server_field == "recovery":
            mutated_server_fields["recovery"]["requestedAt"] = "2026-07-22T14:05:09.124Z"
        elif server_field == "tombstone":
            mutated_server_fields["tombstone"]["terminalSeq"] += 1
        else:
            mutated_server_fields = {"unexpected": case_index}
        next_kind = control_cases[(case_index + 1) % len(control_cases)]["entryKind"]
        field_mutations = {
            "entryKind": next_kind,
            "entryId": "018f3f6a-7b2c-4d91-8a5e-0f123456789b",
            "conversationId": "3b241101-e2bb-4255-8caf-4136c566a963",
            "seq": fingerprint_input["seq"] + 1,
            "requestDigest": base64.b64encode(b"V" * 32).decode("ascii"),
            "signature": base64.b64encode(b"g" * 64).decode("ascii"),
            "serverFields": mutated_server_fields,
            "receivedAt": "2026-07-22T14:05:09.124Z",
        }
        for field, replacement in field_mutations.items():
            mutated = copy.deepcopy(fingerprint_input)
            mutated[field] = replacement
            mutated_bytes = encode_dag_cbor(fixture_projection(
                mutated, case["uuidBytePaths"], case["base64BytePaths"]
            ))
            assert hashlib.sha256(
                control_fingerprint_domain + mutated_bytes
            ).digest() != frozen_control_fingerprint

        missing_server_fields = copy.deepcopy(fingerprint_input)
        missing_server_fields.pop("serverFields")
        extra_projection_field = {**fingerprint_input, "unexpected": True}
        assert set(missing_server_fields) != set(control_projection_fields)
        assert set(extra_projection_field) != set(control_projection_fields)

    cancellation_kind = f"{PREFIX}.defs#leaveCancellationEntry"
    leave_request_kind = f"{PREFIX}.defs#leaveRequestEntry"
    cancellation_binding = authoritative_reference_bindings[cancellation_kind]
    cancellation_case, cancellation_body = decoded_control_cases[cancellation_kind]
    leave_request_case, leave_request_body = decoded_control_cases[leave_request_kind]

    def assert_leave_cancellation_reference(
        binding: dict[str, Any],
        cancellation_row: dict[str, Any],
        cancellation: Any,
        reference_row: dict[str, Any] | None,
        reference: Any,
    ) -> None:
        assert isinstance(cancellation, dict)
        assert isinstance(reference_row, dict) and isinstance(reference, dict)
        assert cancellation_row["entryKind"] == cancellation_kind
        assert cancellation_row["signedRequestRef"] == f"{PREFIX}.defs#signedLeaveCancellation"
        assert cancellation["$type"] == f"{PREFIX}.defs#leaveCancellationBody"
        assert reference_row["entryKind"] == binding["referenceEntryKind"] == leave_request_kind
        assert reference_row["signedRequestRef"] == binding["referenceSignedRequestRef"]
        assert reference_row["entryId"] == binding["referenceEntryId"]
        assert reference_row["seq"] == binding["referenceSeq"]
        assert binding["referenceEntryDistinctAndStrictlyEarlier"] is True
        assert reference_row["entryId"] != cancellation_row["entryId"]
        assert reference_row["seq"] < cancellation_row["seq"]
        assert reference["$type"] == f"{PREFIX}.defs#leaveRequestBody"

        cancellation_conversation_id = uuid.UUID(cancellation_row["conversationId"]).bytes
        reference_conversation_id = uuid.UUID(reference_row["conversationId"]).bytes
        assert cancellation["conversationId"] == cancellation_conversation_id
        assert reference["prior"]["conversationId"] == reference_conversation_id
        assert reference_conversation_id == cancellation_conversation_id
        assert uuid.UUID(binding["conversationId"]).bytes == cancellation_conversation_id

        reference_field = binding["referenceField"]
        reference_value = uuid.UUID(binding["referenceValue"]).bytes
        assert cancellation[reference_field] == reference_value
        assert reference[reference_field] == reference_value
        assert binding["leaveRequestIdIsGlobalSignedRequestKey"] is True
        matching_leave_requests = [
            body for kind, (_, body) in decoded_control_cases.items()
            if kind == leave_request_kind and body.get(reference_field) == reference_value
        ]
        assert matching_leave_requests == [reference]
        assert cancellation["actorDid"] == reference["actorDid"] == binding["requesterDid"]

        assert uuid.UUID(binding["referenceActorDeviceId"]).bytes == reference["actorDeviceId"]
        assert binding["referenceKeyId"] == reference["keyId"]
        assert binding["referenceAuthGeneration"] == reference["authGeneration"]
        assert reference_row["historicalPublicKeyRef"] == binding[
            "referenceHistoricalPublicKeyRef"
        ]
        assert binding["referenceHistoricalPublicKeyRef"] in public_keys
        assert binding["cancellationActorDeviceStatus"] == "active"
        assert uuid.UUID(binding["cancellationActorDeviceId"]).bytes == cancellation["actorDeviceId"]
        assert binding["cancellationKeyId"] == cancellation["keyId"]
        assert binding["cancellationAuthGeneration"] == cancellation["authGeneration"]
        assert cancellation_row["historicalPublicKeyRef"] == binding[
            "cancellationHistoricalPublicKeyRef"
        ]
        assert binding["cancellationHistoricalPublicKeyRef"] in public_keys
        assert cancellation["actorDeviceId"] != reference["actorDeviceId"]
        assert cancellation["keyId"] != reference["keyId"]
        assert binding["cancellationHistoricalPublicKeyRef"] != binding[
            "referenceHistoricalPublicKeyRef"
        ]
        assert public_keys[binding["cancellationHistoricalPublicKeyRef"]] != public_keys[
            binding["referenceHistoricalPublicKeyRef"]
        ]
        assert binding["actorDeviceMayDifferOnlyWithinSameDid"] is True
        assert cancellation["actorDid"] == reference["actorDid"]

        assert binding["retainedReferenceIndependentlyVerifiable"] is True
        assert {cancellation_kind, leave_request_kind} <= signature_verified_kinds
        assert {cancellation_kind, leave_request_kind} <= fingerprint_verified_kinds

    def leave_cancellation_reference_is_valid(
        binding: dict[str, Any],
        cancellation_row: dict[str, Any],
        cancellation: Any,
        reference_row: dict[str, Any] | None,
        reference: Any,
    ) -> bool:
        try:
            assert_leave_cancellation_reference(
                binding, cancellation_row, cancellation, reference_row, reference
            )
        except (AssertionError, KeyError, TypeError, ValueError):
            return False
        return True

    assert_leave_cancellation_reference(
        cancellation_binding,
        cancellation_case,
        cancellation_body,
        leave_request_case,
        leave_request_body,
    )

    wrong_conversation_id = uuid.UUID("22222222-2222-4222-a222-222222222222").bytes
    reference_mutations: list[tuple[
        dict[str, Any], dict[str, Any], Any, dict[str, Any] | None, Any
    ]] = []
    missing_reference_body = None
    reference_mutations.append((
        cancellation_binding, cancellation_case, cancellation_body,
        leave_request_case, missing_reference_body,
    ))
    reference_mutations.append((
        cancellation_binding, cancellation_case, cancellation_body,
        None, None,
    ))
    reference_mutations.append((
        cancellation_binding, cancellation_case, cancellation_body,
        decoded_control_cases[f"{PREFIX}.defs#policyEntry"][0],
        decoded_control_cases[f"{PREFIX}.defs#policyEntry"][1],
    ))
    for target, path in (
        ("cancellation", "leaveRequestId"),
        ("reference", "leaveRequestId"),
        ("cancellation", "conversationId"),
        ("reference", "prior.conversationId"),
    ):
        mutated_cancellation = copy.deepcopy(cancellation_body)
        mutated_reference = copy.deepcopy(leave_request_body)
        selected = mutated_cancellation if target == "cancellation" else mutated_reference
        if path == "prior.conversationId":
            selected["prior"]["conversationId"] = wrong_conversation_id
        elif path == "conversationId":
            selected[path] = wrong_conversation_id
        else:
            selected[path] = uuid.UUID("00000000-0000-4000-8000-000000000099").bytes
        reference_mutations.append((
            cancellation_binding, cancellation_case, mutated_cancellation,
            leave_request_case, mutated_reference,
        ))
    for target in ("cancellation", "reference"):
        mutated_cancellation = copy.deepcopy(cancellation_body)
        mutated_reference = copy.deepcopy(leave_request_body)
        selected = mutated_cancellation if target == "cancellation" else mutated_reference
        selected["actorDid"] = "did:plc:bobfixtureaaaaaaaaaaaaaa"
        reference_mutations.append((
            cancellation_binding, cancellation_case, mutated_cancellation,
            leave_request_case, mutated_reference,
        ))
    for row_target in ("cancellation", "reference"):
        mutated_cancellation_row = copy.deepcopy(cancellation_case)
        mutated_reference_row = copy.deepcopy(leave_request_case)
        selected_row = (
            mutated_cancellation_row if row_target == "cancellation" else mutated_reference_row
        )
        selected_row["conversationId"] = "22222222-2222-4222-a222-222222222222"
        reference_mutations.append((
            cancellation_binding, mutated_cancellation_row, cancellation_body,
            mutated_reference_row, leave_request_body,
        ))
    for invalid_reference_seq in (cancellation_case["seq"], cancellation_case["seq"] + 1):
        mutated_reference_row = copy.deepcopy(leave_request_case)
        mutated_reference_row["seq"] = invalid_reference_seq
        mutated_binding = copy.deepcopy(cancellation_binding)
        mutated_binding["referenceSeq"] = invalid_reference_seq
        reference_mutations.append((
            mutated_binding, cancellation_case, cancellation_body,
            mutated_reference_row, leave_request_body,
        ))
    self_reference_row = copy.deepcopy(leave_request_case)
    self_reference_row["entryId"] = cancellation_case["entryId"]
    mutated_binding = copy.deepcopy(cancellation_binding)
    mutated_binding["referenceEntryId"] = cancellation_case["entryId"]
    reference_mutations.append((
        mutated_binding, cancellation_case, cancellation_body,
        self_reference_row, leave_request_body,
    ))
    wrong_reference_row = copy.deepcopy(leave_request_case)
    wrong_reference_row["entryId"] = "88888888-8888-4888-8888-888888888888"
    reference_mutations.append((
        cancellation_binding, cancellation_case, cancellation_body,
        wrong_reference_row, leave_request_body,
    ))
    for binding_field, replacement in (
        ("referenceActorDeviceId", "71717171-7171-4171-b171-717171717171"),
        ("referenceKeyId", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("referenceAuthGeneration", 2),
        ("referenceHistoricalPublicKeyRef", "missingReferenceKey"),
        ("cancellationActorDeviceStatus", "revoked"),
        ("cancellationActorDeviceId", "73737373-7373-4373-b373-737373737373"),
        ("cancellationKeyId", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("cancellationAuthGeneration", 2),
        ("cancellationHistoricalPublicKeyRef", "missingKey"),
        ("referenceEntryDistinctAndStrictlyEarlier", False),
        ("leaveRequestIdIsGlobalSignedRequestKey", False),
        ("retainedReferenceIndependentlyVerifiable", False),
    ):
        mutated_binding = copy.deepcopy(cancellation_binding)
        mutated_binding[binding_field] = replacement
        reference_mutations.append((
            mutated_binding, cancellation_case, cancellation_body,
            leave_request_case, leave_request_body,
        ))
    for mutation in reference_mutations:
        assert not leave_cancellation_reference_is_valid(*mutation)

    application_semantics = vectors["applicationSemanticConstraints"]
    binding_fields = {"blobId", "ciphertextSha256", "ciphertextSize", "purpose"}
    attachment_binding = application_semantics["applicationAttachmentBinding"]
    metadata_binding = application_semantics["metadataAvatarBinding"]
    assert set(attachment_binding) == binding_fields and set(metadata_binding) == binding_fields
    assert UUID_V4_RE.fullmatch(attachment_binding["blobId"])
    assert UUID_V4_RE.fullmatch(metadata_binding["blobId"])
    assert len(base64.b64decode(attachment_binding["ciphertextSha256"], validate=True)) == 32
    assert len(base64.b64decode(metadata_binding["ciphertextSha256"], validate=True)) == 32
    assert attachment_binding["purpose"] == "attachment"
    assert metadata_binding["purpose"] == "metadata"
    assert application_semantics["invalidApplicationPurpose"] != attachment_binding["purpose"]
    assert application_semantics["invalidMetadataPurpose"] != metadata_binding["purpose"]

    def checked_aead_size(case: dict[str, Any]) -> bool:
        maximums = {
            "image": (10_485_744, 10_485_760),
            "audio": (8_388_592, 8_388_608),
            "metadataAvatar": (10_485_744, 10_485_760),
        }
        plaintext_maximum, ciphertext_maximum = maximums[case["kind"]]
        plaintext_size = case["plaintextSize"]
        ciphertext_size = case["ciphertextSize"]
        return (
            type(plaintext_size) is int
            and type(ciphertext_size) is int
            and 1 <= plaintext_size <= plaintext_maximum
            and 17 <= ciphertext_size <= ciphertext_maximum
            and plaintext_size <= SAFE_INTEGER_MAX - 16
            and ciphertext_size == plaintext_size + 16
        )

    for case in application_semantics["aeadSizeCases"]:
        assert checked_aead_size(case) is case["valid"]

    def fixture_extended_grapheme_count(value: str) -> int:
        """Exercise the fixture's ASCII, combining, emoji-ZWJ, and emoji cases.

        Shared Rust remains the normative full UAX #29 implementation.  This
        independent test oracle deliberately covers every shape present in the
        contract vector without pretending that Python's stdlib exposes a full
        extended-grapheme segmenter.
        """
        count = 0
        previous_was_zwj = False
        regional_indicator_run = 0
        for character in value:
            codepoint = ord(character)
            is_zwj = codepoint == 0x200D
            is_regional_indicator = 0x1F1E6 <= codepoint <= 0x1F1FF
            is_extend = (
                unicodedata.combining(character) != 0
                or unicodedata.category(character) in {"Mn", "Me"}
                or 0xFE00 <= codepoint <= 0xFE0F
                or 0xE0100 <= codepoint <= 0xE01EF
                or 0x1F3FB <= codepoint <= 0x1F3FF
            )
            if count == 0:
                count = 1
            elif not (is_extend or is_zwj or previous_was_zwj):
                if not (is_regional_indicator and regional_indicator_run % 2 == 1):
                    count += 1
            if is_regional_indicator:
                regional_indicator_run += 1
            elif not is_extend:
                regional_indicator_run = 0
            previous_was_zwj = is_zwj
        return count

    def reaction_is_nfc_control_free_single_grapheme(value: str) -> bool:
        return (
            1 <= len(value.encode("utf-8")) <= 64
            and unicodedata.normalize("NFC", value) == value
            and not any(unicodedata.category(character) == "Cc" for character in value)
            and fixture_extended_grapheme_count(value) == 1
        )

    for case in application_semantics["reactionCases"]:
        assert reaction_is_nfc_control_free_single_grapheme(case["emoji"]) is case["valid"]
    assert any(
        case["valid"] and len(case["emoji"]) > 1
        for case in application_semantics["reactionCases"]
    ), "reaction corpus must prove a multi-codepoint extended grapheme"
    assert any(
        not case["valid"] and fixture_extended_grapheme_count(case["emoji"]) > 1
        for case in application_semantics["reactionCases"]
    ), "reaction corpus must reject multiple graphemes"
    assert any(
        not case["valid"] and len(case["emoji"].encode("utf-8")) > 64
        for case in application_semantics["reactionCases"]
    ), "reaction corpus must reject the UTF-8 byte bound"

    invalid_percent = re.compile(r"%(?![0-9A-Fa-f]{2})")

    def parser_valid_at_authority(value: str) -> bool:
        if value.startswith("did:"):
            return is_valid_bare_did(value)
        return is_valid_production_atproto_hostname(value)

    def parser_valid_collection(value: str) -> bool:
        if not value.isascii() or not 1 <= len(value) <= 317 or NSID_RE.fullmatch(value) is None:
            return False
        domain_authority, _ = value.rsplit(".", 1)
        return domain_authority == domain_authority.lower()

    def canonical_record_at_uri(value: str) -> bool:
        if (
            not 1 <= len(value.encode("utf-8")) <= 1_097
            or not value.startswith("at://")
            or "%" in value
            or "?" in value
            or "#" in value
        ):
            return False
        parts = value.removeprefix("at://").split("/")
        if len(parts) != 3:
            return False
        authority, collection, record_key = parts
        return (
            parser_valid_at_authority(authority)
            and parser_valid_collection(collection)
            and 1 <= len(record_key.encode("utf-8")) <= 512
            and record_key not in {".", ".."}
            and re.fullmatch(r"[A-Za-z0-9._:~-]+", record_key) is not None
        )

    for case in application_semantics["atUriCases"]:
        assert canonical_record_at_uri(case["uri"]) is case["valid"]
    at_uri_results = {case["uri"]: case["valid"] for case in application_semantics["atUriCases"]}
    assert at_uri_results[
        "at://did:web:example.com:lowercasepath/app.bsky.feed.post/3jzfcijpj2z2a"
    ] is False
    assert at_uri_results[
        "at://did:plc:EWVI7NXZYOUN6ZHXHRS64OIZ/app.bsky.feed.post/3jzfcijpj2z2a"
    ] is False
    assert at_uri_results[
        "at://did:web:EXAMPLE.COM/app.bsky.feed.post/3jzfcijpj2z2a"
    ] is False
    assert at_uri_results[
        "at://did:web:example.com:CaseSensitivePath/app.bsky.feed.post/3jzfcijpj2z2a"
    ] is False
    assert at_uri_results[
        "at://handle.invalid/app.bsky.feed.post/3jzfcijpj2z2a"
    ] is False
    for reserved_tld in sorted(RESERVED_PRODUCTION_TLDS):
        assert at_uri_results[
            f"at://a.{reserved_tld}/app.bsky.feed.post/3jzfcijpj2z2a"
        ] is False
    assert at_uri_results[
        "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/."
    ] is False
    assert at_uri_results[
        "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/.."
    ] is False

    authority_labels = ("a", "b", "c", "d")
    collection_labels = ("e", "f", "g", "h", "I")
    for case in application_semantics["atUriLengthCases"]:
        authority_host = ".".join(
            label * length
            for label, length in zip(authority_labels, case["authorityLabelLengths"], strict=True)
        )
        collection = ".".join(
            label * length
            for label, length in zip(collection_labels, case["collectionLabelLengths"], strict=True)
        )
        uri = (
            f"at://did:web:{authority_host}/{collection}/"
            + "r" * case["recordKeyLength"]
        )
        assert len(uri.encode("ascii")) == case["expectedLength"]
        assert canonical_record_at_uri(uri) is case["valid"]

    def decode_uvarint(value: bytes, offset: int) -> tuple[int, int] | None:
        decoded = 0
        shift = 0
        for index in range(offset, min(len(value), offset + 10)):
            byte = value[index]
            decoded |= (byte & 0x7F) << shift
            if byte & 0x80 == 0:
                if index > offset and byte == 0:
                    return None
                return decoded, index + 1
            shift += 7
        return None

    def canonical_cid_v1(value: str) -> bool:
        if not 1 <= len(value.encode("utf-8")) <= 256 or not re.fullmatch(r"b[a-z2-7]+", value):
            return False
        payload = value[1:]
        try:
            decoded = base64.b32decode(
                payload.upper() + "=" * ((8 - len(payload) % 8) % 8),
                casefold=False,
            )
        except (ValueError, base64.binascii.Error):
            return False
        if "b" + base64.b32encode(decoded).decode("ascii").lower().rstrip("=") != value:
            return False
        version_result = decode_uvarint(decoded, 0)
        if version_result is None or version_result[0] != 1:
            return False
        codec_result = decode_uvarint(decoded, version_result[1])
        if codec_result is None or codec_result[0] == 0:
            return False
        hash_result = decode_uvarint(decoded, codec_result[1])
        if hash_result is None or hash_result[0] == 0:
            return False
        length_result = decode_uvarint(decoded, hash_result[1])
        if length_result is None or length_result[0] == 0:
            return False
        return len(decoded) - length_result[1] == length_result[0]

    base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    base58_indexes = {character: index for index, character in enumerate(base58_alphabet)}

    def decode_base58btc(value: str) -> bytes | None:
        number = 0
        try:
            for character in value:
                number = number * 58 + base58_indexes[character]
        except KeyError:
            return None
        body = b"" if number == 0 else number.to_bytes((number.bit_length() + 7) // 8, "big")
        return b"\0" * (len(value) - len(value.lstrip("1"))) + body

    def encode_base58btc(value: bytes) -> str:
        zero_count = len(value) - len(value.lstrip(b"\0"))
        number = int.from_bytes(value, "big")
        encoded = ""
        while number:
            number, remainder = divmod(number, 58)
            encoded = base58_alphabet[remainder] + encoded
        return "1" * zero_count + encoded

    def canonical_cid(value: str) -> bool:
        if not 1 <= len(value.encode("utf-8")) <= 256:
            return False
        if value.startswith("Qm"):
            decoded = decode_base58btc(value)
            return (
                len(value) == 46
                and decoded is not None
                and len(decoded) == 34
                and decoded[:2] == b"\x12\x20"
                and encode_base58btc(decoded) == value
            )
        return canonical_cid_v1(value)

    for case in application_semantics["cidCases"]:
        assert canonical_cid(case["cid"]) is case["valid"]

    def external_link_is_valid(value: str) -> bool:
        if "\\" in value or invalid_percent.search(value):
            return False
        if any(character.isspace() or unicodedata.category(character) == "Cc" for character in value):
            return False
        try:
            parsed = urllib.parse.urlsplit(value)
            parsed.port
            return (
                parsed.scheme == "https"
                and parsed.hostname is not None
                and parsed.hostname != ""
                and parsed.username is None
                and parsed.password is None
            )
        except ValueError:
            return False

    for case in application_semantics["externalLinkCases"]:
        assert external_link_is_valid(case["uri"]) is case["valid"]

    interval_provenance = vectors["applicationIntervalProvenance"]
    assert set(interval_provenance) == {
        "recipientDid", "recipientDeviceId", "appendEntryIds", "intervals",
        "touchingScheduleCases", "resetActivatorCases", "closeAuthorityCases",
        "sameIntervalCloseCases", "terminalScheduleCases", "requiredOneFieldNegatives",
    }
    recipient_did = interval_provenance["recipientDid"]
    recipient_device_id = interval_provenance["recipientDeviceId"]
    assert is_valid_bare_did(recipient_did)
    assert UUID_V4_RE.fullmatch(recipient_device_id)
    append_entry_ids = set(interval_provenance["appendEntryIds"].values())
    assert set(interval_provenance["appendEntryIds"]) == {"creation", "reset"}
    assert all(UUID_V4_RE.fullmatch(entry_id) for entry_id in append_entry_ids)

    def exact_base64_bytes(value: Any, length: int) -> bool:
        if not isinstance(value, str):
            return False
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, base64.binascii.Error):
            return False
        return len(decoded) == length and base64.b64encode(decoded).decode("ascii") == value

    def opening_context_is_valid(context: Any, conversation_id: str | None) -> bool:
        return (
            isinstance(context, dict)
            and set(context) == COORDINATE_FIELDS
            and UUID_V4_RE.fullmatch(context.get("conversationId", "")) is not None
            and (conversation_id is None or context["conversationId"] == conversation_id)
            and all(
                type(context[field]) is int and 0 <= context[field] <= SAFE_INTEGER_MAX
                for field in ("generation", "stateVersion", "epoch")
            )
            and exact_base64_bytes(context.get("groupId"), 32)
            and exact_base64_bytes(context.get("groupContextHash"), 32)
            and exact_base64_bytes(context.get("confirmationTag"), 32)
            and context.get("lifecycle") == "active"
        )

    intervals = interval_provenance["intervals"]
    assert isinstance(intervals, list) and intervals
    conversation_id: str | None = None
    transition_ids: set[str] = set()
    previous_interval: dict[str, Any] | None = None
    for interval in intervals:
        is_closed = "endSeq" in interval or "closing" in interval
        expected_interval_fields = {
            "recipientDid", "recipientDeviceId", "startSeq", "opening",
        } | ({"endSeq", "closing"} if is_closed else set())
        assert set(interval) == expected_interval_fields
        assert interval["recipientDid"] == recipient_did
        assert interval["recipientDeviceId"] == recipient_device_id
        assert type(interval["startSeq"]) is int and 1 <= interval["startSeq"] <= SAFE_INTEGER_MAX

        opening = interval["opening"]
        assert set(opening) == {"seq", "kind", "transitionId", "outerEntryFingerprint", "context"}
        assert opening["seq"] == interval["startSeq"]
        assert opening["kind"] in {"creation", "add", "reset"}
        assert UUID_V4_RE.fullmatch(opening["transitionId"])
        assert opening["transitionId"] not in append_entry_ids
        assert exact_base64_bytes(opening["outerEntryFingerprint"], 32)
        assert opening_context_is_valid(opening["context"], conversation_id)
        conversation_id = opening["context"]["conversationId"]
        transition_ids.add(opening["transitionId"])

        if is_closed:
            assert type(interval["endSeq"]) is int
            assert interval["startSeq"] < interval["endSeq"] <= SAFE_INTEGER_MAX
            closing = interval["closing"]
            assert set(closing) == {
                "seq", "kind", "transitionId", "outerEntryFingerprint",
                "recipientDid", "recipientDeviceId",
            }
            assert closing["seq"] == interval["endSeq"]
            assert closing["kind"] in {"replace", "remove", "reset", "terminal"}
            assert UUID_V4_RE.fullmatch(closing["transitionId"])
            assert closing["transitionId"] not in append_entry_ids
            assert exact_base64_bytes(closing["outerEntryFingerprint"], 32)
            assert closing["recipientDid"] == recipient_did
            assert closing["recipientDeviceId"] == recipient_device_id
            transition_ids.add(closing["transitionId"])

        if previous_interval is not None:
            previous_end = previous_interval["endSeq"]
            previous_closing = previous_interval["closing"]
            assert interval["startSeq"] >= previous_end
            if interval["startSeq"] == previous_end:
                assert (previous_closing["kind"], opening["kind"]) in {
                    ("replace", "add"), ("reset", "reset"),
                }
                assert previous_closing["transitionId"] == opening["transitionId"]
                assert (
                    previous_closing["outerEntryFingerprint"]
                    == opening["outerEntryFingerprint"]
                )
            else:
                assert previous_closing["kind"] != "terminal"
        previous_interval = interval

    assert append_entry_ids.isdisjoint(transition_ids)

    def touching_schedule_is_valid(case: dict[str, Any]) -> bool:
        return (
            case["sameTransitionAndFingerprint"] is True
            and (case["closingKind"], case["openingKind"]) in {
                ("replace", "add"), ("reset", "reset"),
            }
        )

    for case in interval_provenance["touchingScheduleCases"]:
        assert touching_schedule_is_valid(case) is case["valid"]

    def reset_activator_is_valid(case: dict[str, Any]) -> bool:
        return (
            case["activeAdmin"] is True
            and case["openingKind"] == "reset"
            and case["hasPreResetAccess"] is case["wasOldLeaf"]
        )

    for case in interval_provenance["resetActivatorCases"]:
        assert reset_activator_is_valid(case) is case["valid"]

    for case in interval_provenance["closeAuthorityCases"]:
        assert (case["hasVerifiedSignedControlRow"] is True) is case["valid"]

    for case in interval_provenance["sameIntervalCloseCases"]:
        valid = (
            case["openingKind"] in {"creation", "add", "reset"}
            and case["closingKind"] in {"replace", "remove", "reset", "terminal"}
            and type(case["startSeq"]) is int
            and type(case["endSeq"]) is int
            and 1 <= case["startSeq"] < case["endSeq"] <= SAFE_INTEGER_MAX
        )
        assert valid is case["valid"]

    def terminal_schedule_is_valid(case: dict[str, Any]) -> bool:
        if not case["hasExactSignedRecipientConversationProof"]:
            return False
        if case["rewritesPriorIntervalClose"] or case["grantsGapHistory"]:
            return False
        if case["priorIntervalState"] == "open":
            return case["previousMatchesExpected"] is True
        if case["priorIntervalState"] in {"closedRemove", "closedReset"}:
            return case["previousMatchesExpected"] is False
        return False

    for case in interval_provenance["terminalScheduleCases"]:
        assert terminal_schedule_is_valid(case) is case["valid"]

    assert set(interval_provenance["requiredOneFieldNegatives"]) == {
        "recipientDid", "recipientDeviceId", "openingSeq", "openingKind",
        "openingTransitionId", "openingOuterEntryFingerprint", "openingContext",
        "closingTransitionId", "closingOuterEntryFingerprint", "closeKind",
        "entryIdSubstitution", "sameIntervalEndEqualsStart",
        "terminalProofMissing", "terminalRewritesPriorClose", "terminalGrantsGapHistory",
    }

    metadata = vectors["metadataProjections"]
    exporter = fixture_projection(
        metadata["exporterContext"],
        metadata["exporterUuidBytePaths"],
        metadata["exporterBase64BytePaths"],
    )
    exporter_bytes = encode_dag_cbor(exporter)
    assert exporter_bytes.hex() == metadata["exporterCanonicalDagCborHex"]
    mutated_exporter = copy.deepcopy(metadata["exporterContext"])
    set_fixture_path(mutated_exporter, metadata["exporterMutation"]["path"], metadata["exporterMutation"]["value"])
    mutated_exporter_bytes = encode_dag_cbor(fixture_projection(
        mutated_exporter,
        metadata["exporterUuidBytePaths"],
        metadata["exporterBase64BytePaths"],
    ))
    assert mutated_exporter_bytes.hex() == metadata["mutatedExporterCanonicalDagCborHex"]
    assert mutated_exporter_bytes != exporter_bytes

    metadata_aad = fixture_projection(
        metadata["aad"], metadata["aadUuidBytePaths"], metadata["aadBase64BytePaths"]
    )
    metadata_aad_bytes = encode_dag_cbor(metadata_aad)
    assert metadata_aad_bytes.hex() == metadata["aadCanonicalDagCborHex"]
    metadata_aad_transcript = b"CATBIRD-CHAT-METADATA\0" + metadata_aad_bytes
    assert hashlib.sha256(metadata_aad_transcript).hexdigest() == metadata["aadTranscriptSha256Hex"]
    mutated_aad = copy.deepcopy(metadata["aad"])
    set_fixture_path(mutated_aad, metadata["aadMutation"]["path"], metadata["aadMutation"]["value"])
    mutated_aad_bytes = encode_dag_cbor(fixture_projection(
        mutated_aad, metadata["aadUuidBytePaths"], metadata["aadBase64BytePaths"]
    ))
    assert hashlib.sha256(b"CATBIRD-CHAT-METADATA\0" + mutated_aad_bytes).hexdigest() == metadata["mutatedAadTranscriptSha256Hex"]
    assert mutated_aad_bytes != metadata_aad_bytes

    lifetime = vectors["keyPackageLifetime"]
    evaluation = lifetime["evaluationUnixSeconds"]

    def lifetime_is_valid(case: dict[str, int]) -> bool:
        not_before = case["notBefore"]
        not_after = case["notAfter"]
        if not (0 <= not_before <= SAFE_INTEGER_MAX and 0 <= not_after <= SAFE_INTEGER_MAX):
            return False
        if not_before >= not_after:
            return False
        if not (not_before < evaluation < not_after):
            return False
        remaining = not_after - evaluation
        total = not_after - not_before
        return remaining >= 600 and total <= 2_595_600

    assert all(lifetime_is_valid(case) for case in lifetime["valid"])
    assert all(not lifetime_is_valid(case) for case in lifetime["invalid"])
    assert lifetime["reservationExpiryUnixSeconds"] == min(
        evaluation + 300, lifetime["valid"][0]["notAfter"]
    )

    freshness = vectors["signedAtFreshness"]
    trusted_instant = dt.datetime.fromisoformat(
        freshness["trustedServerInstant"].replace("Z", "+00:00")
    )

    def first_execution_is_fresh(value: str) -> bool:
        instant = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return trusted_instant - dt.timedelta(seconds=300) <= instant <= trusted_instant + dt.timedelta(seconds=60)

    assert all(first_execution_is_fresh(value) for value in freshness["validFirstExecution"])
    assert all(not first_execution_is_fresh(value) for value in freshness["invalidFirstExecution"])
    assert not first_execution_is_fresh(freshness["oldCompletedReplay"])
    assert freshness["completedReplayMayBypassSignedAtAge"] is True
    assert freshness["completedReplayStillRequiresFreshDpopJti"] is True
    assert freshness["pendingExpirySource"] == "serverReceivedAt"
    assert freshness["typingAndServerTimestampSource"] == "trustedServerInstant"

    syntax = vectors["strictJson"]
    assert strict_json_loads(syntax["valid"])
    for source in syntax["invalid"]:
        try:
            parsed = strict_json_loads(source)
        except (ValueError, json.JSONDecodeError):
            continue
        assert contains_null(parsed), source


def validate_crypto_wire_v08_corpus() -> None:
    assert CRYPTO_WIRE_ROOT.is_dir(), f"missing authoritative crypto wire corpus: {CRYPTO_WIRE_ROOT}"
    expected_files = {
        "manifest.json", "key-package.mls", "key-package-inner.tls",
        "key-package-ref.bin", "group-info.mls", "commit-public.mls",
        "welcome.mls", "application-frame.cbor", "application-private.mls",
        "genesis-public-state.bin", "committed-public-state.bin",
        "commit-generic-public.mls", "committed-generic-public-state.bin",
        "commit-remove-public.mls", "committed-remove-public-state.bin",
        "rejoin-key-package.mls", "rejoin-key-package-inner.tls",
        "rejoin-key-package-ref.bin", "commit-rejoin-public.mls",
        "rejoin-welcome.mls", "committed-rejoin-public-state.bin",
        "creation-signed-request.cbor",
    }
    actual_files = {path.name for path in CRYPTO_WIRE_ROOT.iterdir() if path.is_file()}
    assert actual_files == expected_files, f"crypto wire manifest mismatch: missing={sorted(expected_files-actual_files)}, extra={sorted(actual_files-expected_files)}"
    manifest = strict_load(CRYPTO_WIRE_ROOT / "manifest.json")
    assert manifest["schemaVersion"] == 1
    assert manifest["protocol"] == PREFIX and manifest["protocolVersion"] == "1"
    assert set(manifest["identifiers"]) == {
        "conversationId", "conversationIdHex", "messageId", "messageIdHex",
        "transitionId", "transitionIdHex",
        "genericTransitionId", "genericTransitionIdHex",
        "leaveFulfillmentTransitionId", "leaveFulfillmentTransitionIdHex",
        "rejoinTransitionId", "rejoinTransitionIdHex",
    }
    assert "reservationIntentDigest" not in json.dumps(manifest)
    assert isinstance(manifest["evaluationUnixSeconds"], int) and manifest["evaluationUnixSeconds"] > 0
    assert manifest["cipherSuite"] == {"name": SUITE, "code": 77}
    expected_dependency_versions = {
        "openmls": "0.8.1",
        "openmls_basic_credential": "0.5.0",
        "openmls_libcrux_crypto": "0.3.1",
        "openmls_memory_storage": "0.5.0",
        "openmls_traits": "0.5.0",
        "serde_ipld_dagcbor": "0.6.4",
        "tls_codec": "0.4.2",
    }
    assert set(manifest["dependencies"]) == set(expected_dependency_versions)
    for package, profile in manifest["dependencies"].items():
        assert package and set(profile) == {"version", "source", "checksum"}
        assert all(isinstance(profile[field], str) and profile[field] for field in profile)
        assert profile["version"] == expected_dependency_versions[package]

    identity = manifest["identity"]
    for principal in ("alice", "bob"):
        entry = identity[principal]
        assert is_valid_bare_did(entry["actorDid"])
        assert UUID_V4_RE.fullmatch(entry["deviceId"])
        assert entry["credentialIdentity"] == f'{entry["actorDid"]}#{entry["deviceId"]}'
        public_key = bytes.fromhex(entry["signaturePublicKeyHex"])
        assert len(public_key) == 32
        public_digest = hashlib.sha256(public_key).digest()
        assert public_digest.hex() == entry["signaturePublicKeySha256Hex"]
        assert base64.urlsafe_b64encode(public_digest).rstrip(b"=").decode("ascii") == entry["keyId"]

    payload_names = expected_files - {"manifest.json"}
    assert set(manifest["files"]) == payload_names
    payloads: dict[str, bytes] = {}
    for filename in sorted(payload_names):
        payload = (CRYPTO_WIRE_ROOT / filename).read_bytes()
        payloads[filename] = payload
        record = manifest["files"][filename]
        assert set(record) >= {"length", "sha256Hex", "kind"}
        assert record["length"] == len(payload) and record["length"] > 0
        assert record["sha256Hex"] == hashlib.sha256(payload).hexdigest()

    wrapper_formats = {
        "key-package.mls": 5,
        "group-info.mls": 4,
        "commit-public.mls": 1,
        "commit-generic-public.mls": 1,
        "commit-remove-public.mls": 1,
        "rejoin-key-package.mls": 5,
        "commit-rejoin-public.mls": 1,
        "rejoin-welcome.mls": 3,
        "welcome.mls": 3,
        "application-private.mls": 2,
    }
    for filename, wire_format in wrapper_formats.items():
        payload = payloads[filename]
        assert len(payload) >= 4 and int.from_bytes(payload[:2], "big") == 1
        assert int.from_bytes(payload[2:4], "big") == wire_format
        assert manifest["files"][filename]["wireFormat"] == wire_format
    inner = payloads["key-package-inner.tls"]
    assert len(inner) >= 4 and inner[:4].hex() == "0001004d"
    assert payloads["key-package.mls"][4:] == inner
    assert len(payloads["key-package-ref.bin"]) == 32
    assert payloads["key-package.mls"] != inner
    rejoin_inner = payloads["rejoin-key-package-inner.tls"]
    assert len(rejoin_inner) >= 4 and rejoin_inner[:4].hex() == "0001004d"
    assert payloads["rejoin-key-package.mls"][4:] == rejoin_inner
    assert len(payloads["rejoin-key-package-ref.bin"]) == 32
    assert payloads["rejoin-key-package-ref.bin"] != payloads["key-package-ref.bin"]

    chain = manifest["chain"]
    assert chain["genesisEpoch"] == 0 and chain["committedEpoch"] == 1
    assert chain["genesisStateVersion"] == 0 and chain["addPriorStateVersion"] == 2
    assert chain["committedStateVersion"] == 3
    assert chain["genericPriorStateVersion"] == 3
    assert chain["genericCommittedStateVersion"] == 4
    assert chain["removePriorStateVersion"] == 4
    assert chain["removeCommittedStateVersion"] == 5
    assert chain["rejoinPriorStateVersion"] == 7
    assert chain["rejoinEpoch"] == 4 and chain["rejoinStateVersion"] == 8
    assert chain["rejoinMemberCredentials"] == chain["committedMemberCredentials"]

    public_snapshot_profile = manifest["publicSnapshots"]
    assert public_snapshot_profile["schema"] == 1
    assert public_snapshot_profile["openmlsVersion"] == "0.8.1"
    assert public_snapshot_profile["storageVersion"] == "0.5.0"
    assert public_snapshot_profile["recordCount"] == 4
    assert public_snapshot_profile["storageSchemaSuffixHex"] == "0001"
    assert public_snapshot_profile["containsSecrets"] is False
    expected_snapshot_keys = [bytes.fromhex(value) for value in public_snapshot_profile["genesisRecordKeyHex"]]
    assert len(expected_snapshot_keys) == 4 and expected_snapshot_keys == sorted(set(expected_snapshot_keys))

    def validate_v08_public_snapshot(filename: str) -> list[bytes]:
        snapshot = payloads[filename]
        assert 1 <= len(snapshot) <= 8 * 1_048_576
        for forbidden_secret_marker in (b"EpochSecrets", b"MessageSecrets", b"SignatureKeyPair", b"Psk", b"EncryptionKeyPair"):
            assert forbidden_secret_marker not in snapshot, f"{filename} contains a secret-bearing record marker"
        offset = 0

        def take(length: int) -> bytes:
            nonlocal offset
            assert length >= 0 and offset + length <= len(snapshot), f"truncated {filename}"
            result = snapshot[offset:offset + length]
            offset += length
            return result

        def take_u16() -> int:
            return int.from_bytes(take(2), "big")

        def take_u32() -> int:
            return int.from_bytes(take(4), "big")

        assert take(8) == b"CBPGSNAP"
        assert take_u16() == 1
        openmls_version = take(take_u16()).decode("utf-8")
        storage_version = take(take_u16()).decode("utf-8")
        assert openmls_version == "0.8.1" and storage_version == "0.5.0"
        count = take_u32()
        assert count == 4
        previous_key: bytes | None = None
        keys: list[bytes] = []
        for _ in range(count):
            key_length = take_u32()
            assert 1 <= key_length <= 65_536
            key = take(key_length)
            value_length = take_u32()
            assert 1 <= value_length <= 4_194_304
            take(value_length)
            assert previous_key is None or previous_key < key, f"{filename} keys must be unique and sorted"
            previous_key = key
            keys.append(key)
        assert offset == len(snapshot), f"trailing bytes in {filename}"
        assert keys == expected_snapshot_keys, f"{filename} must contain only the four exact public record keys"
        return keys

    assert validate_v08_public_snapshot("genesis-public-state.bin") == validate_v08_public_snapshot("committed-public-state.bin")
    assert validate_v08_public_snapshot("genesis-public-state.bin") == validate_v08_public_snapshot("committed-rejoin-public-state.bin")
    assert payloads["genesis-public-state.bin"] != payloads["committed-public-state.bin"]
    assert payloads["committed-remove-public-state.bin"] != payloads["committed-rejoin-public-state.bin"]


def validate_crypto_wire_v09_corpus() -> None:
    assert CRYPTO_WIRE_V09_ROOT.is_dir(), f"missing authoritative crypto wire v09 corpus: {CRYPTO_WIRE_V09_ROOT}"
    expected_files = {
        "manifest.json", "key-package.mls", "key-package-inner.tls",
        "key-package-ref.bin", "group-info.mls", "commit-public.mls",
        "welcome.mls", "application-frame.cbor", "application-private.mls",
        "genesis-public-state.bin", "committed-public-state.bin",
        "commit-generic-public.mls", "committed-generic-public-state.bin",
        "commit-remove-public.mls", "committed-remove-public-state.bin",
        "rejoin-key-package.mls", "rejoin-key-package-inner.tls",
        "rejoin-key-package-ref.bin", "commit-rejoin-public.mls",
        "rejoin-welcome.mls", "committed-rejoin-public-state.bin",
        "creation-signed-request.cbor",
    }
    actual_files = {path.name for path in CRYPTO_WIRE_V09_ROOT.iterdir() if path.is_file()}
    assert actual_files == expected_files, f"crypto wire v09 manifest mismatch: missing={sorted(expected_files-actual_files)}, extra={sorted(actual_files-expected_files)}"
    manifest = strict_load(CRYPTO_WIRE_V09_ROOT / "manifest.json")
    assert manifest["schemaVersion"] == 1
    assert manifest["protocol"] == PREFIX and manifest["protocolVersion"] == "1"
    assert set(manifest["identifiers"]) == {
        "conversationId", "conversationIdHex", "messageId", "messageIdHex",
        "transitionId", "transitionIdHex",
        "genericTransitionId", "genericTransitionIdHex",
        "leaveFulfillmentTransitionId", "leaveFulfillmentTransitionIdHex",
        "rejoinTransitionId", "rejoinTransitionIdHex",
    }
    assert "reservationIntentDigest" not in json.dumps(manifest)
    assert isinstance(manifest["evaluationUnixSeconds"], int) and manifest["evaluationUnixSeconds"] > 0
    assert manifest["cipherSuite"] == {"name": SUITE, "code": 77}
    expected_dependency_versions = {
        "openmls": "0.9.0-rc.3",
        "openmls_basic_credential": "0.6.0-rc.3",
        "openmls_libcrux_crypto": "0.4.0-rc.3",
        "openmls_memory_storage": "0.6.0-rc.3",
        "openmls_traits": "0.6.0-rc.3",
        "serde_ipld_dagcbor": "0.6.4",
        "tls_codec": "0.5.0",
    }
    assert set(manifest["dependencies"]) == set(expected_dependency_versions)
    lock_path = STACK_ROOT / "catbird-mls/Cargo.lock"
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    lock_packages = lock["package"]
    for package, profile in manifest["dependencies"].items():
        assert package and "version" in profile and "source" in profile
        assert profile["version"] == expected_dependency_versions[package]
        matches = [
            entry for entry in lock_packages
            if entry["name"] == package and entry["version"] == profile["version"]
        ]
        assert len(matches) == 1, f"Cargo.lock package ambiguity for {package}"
        assert matches[0].get("source") == profile["source"]
        if "checksum" in profile:
            assert matches[0].get("checksum") == profile["checksum"]

    generator = manifest["generator"]
    generator_source = STACK_ROOT / generator["source"]
    cargo_manifest_path = STACK_ROOT / "catbird-mls/Cargo.toml"
    assert hashlib.sha256(generator_source.read_bytes()).hexdigest() == generator["sourceSha256Hex"]
    assert hashlib.sha256(cargo_manifest_path.read_bytes()).hexdigest() == generator["cargoManifestSha256Hex"]
    assert hashlib.sha256(lock_path.read_bytes()).hexdigest() == generator["cargoLockSha256Hex"]
    assert generator["officialClientRevision"] == "e7c2437e845eb767d2cdd22eece2b3c5d484e4e7"
    assert generator["catbirdOpenMlsForkRev"] == "3ea192fc346663fba5db63aa8c90ccc3ae49f12b"

    source_root = STACK_ROOT / "catbird-mls/src/chat_v2"
    source_files = sorted(
        (path.relative_to(source_root).as_posix(), path.read_bytes())
        for path in source_root.rglob("*.rs")
    )
    assert source_files
    source_hasher = hashlib.sha256()
    for relative, source_bytes in source_files:
        source_hasher.update(relative.encode("utf-8"))
        source_hasher.update(b"\0")
        source_hasher.update(len(source_bytes).to_bytes(8, "big"))
        source_hasher.update(source_bytes)
    assert source_hasher.hexdigest() == generator["chatProtocolSourceTreeSha256Hex"]

    identity = manifest["identity"]
    for principal in ("alice", "bob"):
        entry = identity[principal]
        assert is_valid_bare_did(entry["actorDid"])
        assert UUID_V4_RE.fullmatch(entry["deviceId"])
        assert entry["credentialIdentity"] == f'{entry["actorDid"]}#{entry["deviceId"]}'
        public_key = bytes.fromhex(entry["signaturePublicKeyHex"])
        assert len(public_key) == 32
        public_digest = hashlib.sha256(public_key).digest()
        assert public_digest.hex() == entry["signaturePublicKeySha256Hex"]
        assert base64.urlsafe_b64encode(public_digest).rstrip(b"=").decode("ascii") == entry["keyId"]

    payload_names = expected_files - {"manifest.json"}
    assert set(manifest["files"]) == payload_names
    payloads: dict[str, bytes] = {}
    for filename in sorted(payload_names):
        payload = (CRYPTO_WIRE_V09_ROOT / filename).read_bytes()
        payloads[filename] = payload
        record = manifest["files"][filename]
        assert set(record) >= {"length", "sha256Hex", "kind"}
        assert record["length"] == len(payload) and record["length"] > 0
        assert record["sha256Hex"] == hashlib.sha256(payload).hexdigest()

    wrapper_formats = {
        "key-package.mls": 5,
        "group-info.mls": 4,
        "commit-public.mls": 1,
        "commit-generic-public.mls": 1,
        "commit-remove-public.mls": 1,
        "rejoin-key-package.mls": 5,
        "commit-rejoin-public.mls": 1,
        "rejoin-welcome.mls": 3,
        "welcome.mls": 3,
        "application-private.mls": 2,
    }
    for filename, wire_format in wrapper_formats.items():
        payload = payloads[filename]
        assert len(payload) >= 4 and int.from_bytes(payload[:2], "big") == 1
        assert int.from_bytes(payload[2:4], "big") == wire_format
        assert manifest["files"][filename]["wireFormat"] == wire_format
    inner = payloads["key-package-inner.tls"]
    assert len(inner) >= 4 and inner[:4].hex() == "0001004d"
    assert payloads["key-package.mls"][4:] == inner
    assert len(payloads["key-package-ref.bin"]) == 32
    assert payloads["key-package.mls"] != inner
    rejoin_inner = payloads["rejoin-key-package-inner.tls"]
    assert len(rejoin_inner) >= 4 and rejoin_inner[:4].hex() == "0001004d"
    assert payloads["rejoin-key-package.mls"][4:] == rejoin_inner
    assert len(payloads["rejoin-key-package-ref.bin"]) == 32
    assert payloads["rejoin-key-package-ref.bin"] != payloads["key-package-ref.bin"]

    chain = manifest["chain"]
    assert chain["genesisEpoch"] == 0 and chain["committedEpoch"] == 1
    assert chain["genesisStateVersion"] == 0 and chain["addPriorStateVersion"] == 2
    assert chain["committedStateVersion"] == 3
    assert chain["genericPriorStateVersion"] == 3
    assert chain["genericCommittedStateVersion"] == 4
    assert chain["removePriorStateVersion"] == 4
    assert chain["removeCommittedStateVersion"] == 5
    assert chain["rejoinPriorStateVersion"] == 7
    assert chain["rejoinEpoch"] == 4 and chain["rejoinStateVersion"] == 8
    assert chain["rejoinMemberCredentials"] == chain["committedMemberCredentials"]

    public_snapshot_profile = manifest["publicSnapshots"]
    assert set(public_snapshot_profile) == {
        "schema", "openmlsVersion", "storageVersion", "recordCount", "recordLabels",
        "storageSchemaSuffixHex", "containsSecrets", "genesisRecordKeyHex",
        "committedRecordKeyHex", "rejoinRecordKeyHex",
    }
    assert public_snapshot_profile == {
        **public_snapshot_profile,
        "schema": 2,
        "openmlsVersion": "0.9.0-rc.3",
        "storageVersion": "0.6.0-rc.3",
        "recordCount": 4,
        "recordLabels": ["Tree", "GroupContext", "InterimTranscriptHash", "ConfirmationTag"],
        "storageSchemaSuffixHex": "0001",
        "containsSecrets": False,
    }
    assert public_snapshot_profile["genesisRecordKeyHex"] == public_snapshot_profile["committedRecordKeyHex"]
    assert public_snapshot_profile["genesisRecordKeyHex"] == public_snapshot_profile["rejoinRecordKeyHex"]
    expected_snapshot_keys = [bytes.fromhex(value) for value in public_snapshot_profile["genesisRecordKeyHex"]]
    assert len(expected_snapshot_keys) == 4 and expected_snapshot_keys == sorted(set(expected_snapshot_keys))
    expected_labels = {b"Tree", b"GroupContext", b"InterimTranscriptHash", b"ConfirmationTag"}
    assert {next(label for label in expected_labels if key.startswith(label)) for key in expected_snapshot_keys} == expected_labels
    assert all(key.endswith(b"\0\1") for key in expected_snapshot_keys)

    def validate_v09_public_snapshot(filename: str) -> list[bytes]:
        snapshot = payloads[filename]
        assert 1 <= len(snapshot) <= 8 * 1_048_576
        for forbidden_secret_marker in (b"EpochSecrets", b"MessageSecrets", b"SignatureKeyPair", b"Psk", b"EncryptionKeyPair"):
            assert forbidden_secret_marker not in snapshot, f"{filename} contains a secret-bearing record marker"
        offset = 0

        def take(length: int) -> bytes:
            nonlocal offset
            assert length >= 0 and offset + length <= len(snapshot), f"truncated {filename}"
            result = snapshot[offset:offset + length]
            offset += length
            return result

        def take_u16() -> int:
            return int.from_bytes(take(2), "big")

        def take_u32() -> int:
            return int.from_bytes(take(4), "big")

        assert take(8) == b"CBPGSNAP"
        assert take_u16() == 2
        openmls_version = take(take_u16()).decode("utf-8")
        storage_version = take(take_u16()).decode("utf-8")
        assert openmls_version == "0.9.0-rc.3" and storage_version == "0.6.0-rc.3"
        count = take_u32()
        assert count == 4
        previous_key: bytes | None = None
        keys: list[bytes] = []
        for _ in range(count):
            key_length = take_u32()
            assert 1 <= key_length <= 65_536
            key = take(key_length)
            value_length = take_u32()
            assert 1 <= value_length <= 4_194_304
            take(value_length)
            assert previous_key is None or previous_key < key, f"{filename} keys must be unique and sorted"
            previous_key = key
            keys.append(key)
        assert offset == len(snapshot), f"trailing bytes in {filename}"
        assert keys == expected_snapshot_keys, f"{filename} must contain only the four exact public record keys"
        return keys

    assert validate_v09_public_snapshot("genesis-public-state.bin") == validate_v09_public_snapshot("committed-public-state.bin")
    assert validate_v09_public_snapshot("genesis-public-state.bin") == validate_v09_public_snapshot("committed-rejoin-public-state.bin")
    assert payloads["genesis-public-state.bin"] != payloads["committed-public-state.bin"]
    assert payloads["committed-remove-public-state.bin"] != payloads["committed-rejoin-public-state.bin"]


def validate_crypto_wire_corpus() -> None:
    validate_crypto_wire_v08_corpus()
    validate_crypto_wire_v09_corpus()

def validate_non_crypto_contract(documents: dict[str, dict[str, Any]], vectors: dict[str, Any]) -> None:
    validate_manifest(documents)
    validate_schema_ast(documents)
    validate_core_definitions(documents)
    validate_endpoint_contract(documents)
    validate_vectors(documents, vectors)
    validate_normative_prose()
    validate_application_contract()


def validate_contract(documents: dict[str, dict[str, Any]], vectors: dict[str, Any]) -> None:
    validate_non_crypto_contract(documents, vectors)
    validate_crypto_wire_corpus()


class ChatLexiconContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.canonical = load_documents(CANONICAL_ROOT)
        self.vectors = strict_load(VECTOR_PATH)

    def test_manifest_and_semantic_schema_are_decision_complete(self) -> None:
        validate_contract(self.canonical, self.vectors)

    def test_non_crypto_contract_is_decision_complete(self) -> None:
        validate_non_crypto_contract(self.canonical, self.vectors)

    def test_control_fingerprint_corpus_matches_deterministic_generator(self) -> None:
        generator = Path(__file__).with_name("generate_mls_chat_contract_vectors.py")
        completed = subprocess.run(
            [sys.executable, str(generator), "--check"],
            cwd=MLS_DS_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            completed.returncode,
            0,
            completed.stdout + completed.stderr,
        )

    def test_control_fingerprint_generator_rejects_duplicate_source_keys(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "unittest",
                "server.tests.generate_mls_chat_contract_vectors_test",
            ],
            cwd=MLS_DS_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            completed.returncode,
            0,
            completed.stdout + completed.stderr,
        )

    def test_closed_lexicon_validator_rejects_noncanonical_nested_key_id(self) -> None:
        case = next(
            candidate
            for candidate in self.vectors["controlEntryFingerprints"]["cases"]
            if candidate["entryKind"] == f"{PREFIX}.defs#commitEntry"
        )
        body = decode_dag_cbor(
            bytes.fromhex(case["unsignedSigningProjectionCanonicalDagCborHex"])
        )
        body["metadataSnapshot"]["authorProof"]["authorKeyId"] = "a" * 43
        defs_document = self.canonical[f"{PREFIX}.defs.json"]
        body_ref, _ = SIGNED_PROJECTIONS["signedCommitTransition"]
        self.assertFalse(
            closed_lexicon_value_is_valid(
                self.canonical,
                defs_document,
                defs_document["defs"][body_ref],
                body,
                f"{PREFIX}.defs#{body_ref}",
            )
        )

    def test_closed_lexicon_validator_rejects_wrong_boolean_const(self) -> None:
        case = next(
            candidate
            for candidate in self.vectors["controlEntryFingerprints"]["cases"]
            if candidate["entryKind"] == f"{PREFIX}.defs#creationEntry"
        )
        body = decode_dag_cbor(
            bytes.fromhex(case["unsignedSigningProjectionCanonicalDagCborHex"])
        )
        body["absence"] = False
        defs_document = self.canonical[f"{PREFIX}.defs.json"]
        body_ref, _ = SIGNED_PROJECTIONS["signedCreation"]
        self.assertFalse(
            closed_lexicon_value_is_valid(
                self.canonical,
                defs_document,
                defs_document["defs"][body_ref],
                body,
                f"{PREFIX}.defs#{body_ref}",
            )
        )

    def test_recovery_work_terminal_shapes_are_structurally_closed(self) -> None:
        defs_document = self.canonical[f"{PREFIX}.defs.json"]
        defs = defs_document["defs"]
        recovery_work = defs["recoveryWorkView"]
        recovery_inbox = defs["leafRecoveryInboxItem"]

        def uuid_bytes(value: str) -> bytes:
            return uuid.UUID(value).bytes

        coordinates = {
            "conversationId": uuid_bytes("11111111-1111-4111-9111-111111111111"),
            "generation": 3,
            "stateVersion": 7,
            "groupId": b"g" * 32,
            "epoch": 5,
            "groupContextHash": b"h" * 32,
            "confirmationTag": b"t" * 32,
            "lifecycle": "active",
        }
        base = {
            "recoveryWorkId": uuid_bytes("22222222-2222-4222-a222-222222222222"),
            "conversationId": coordinates["conversationId"],
            "recipientDid": "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
            "recipientDeviceId": uuid_bytes("33333333-3333-4333-b333-333333333333"),
            "sourceKind": "welcomeExpired",
            "sourceId": uuid_bytes("44444444-4444-4444-8444-444444444444"),
            "sourceCoordinate": coordinates,
            "createdAt": "2026-07-22T12:00:00.000Z",
        }
        transition_id = uuid_bytes("55555555-5555-4555-9555-555555555555")
        revocation_id = uuid_bytes("66666666-6666-4666-a666-666666666666")
        terminal_at = "2026-07-22T12:01:00.000Z"
        positives = {
            "recoveryWorkPendingView": {**base, "status": "pending"},
            "recoveryWorkCompletedByTransitionView": {
                **base,
                "status": "completed",
                "terminalTransitionId": transition_id,
                "terminalAt": terminal_at,
            },
            "recoveryWorkSupersededByTransitionView": {
                **base,
                "status": "superseded",
                "terminalTransitionId": transition_id,
                "terminalAt": terminal_at,
            },
            "recoveryWorkSupersededByRevocationView": {
                **base,
                "status": "superseded",
                "terminalRevocationId": revocation_id,
                "terminalAt": terminal_at,
            },
        }

        terminal_values = {
            "terminalTransitionId": transition_id,
            "terminalRevocationId": revocation_id,
            "terminalAt": terminal_at,
        }
        revocation_targets = {
            revocation_id: (base["recipientDid"], base["recipientDeviceId"]),
        }

        def is_valid_with_revocation_authority(value: dict[str, Any]) -> bool:
            if not closed_lexicon_value_is_valid(
                self.canonical,
                defs_document,
                recovery_work,
                value,
                f"{PREFIX}.defs#recoveryWorkView",
            ):
                return False
            if value["$type"] != (
                f"{PREFIX}.defs#recoveryWorkSupersededByRevocationView"
            ):
                return True
            return revocation_targets.get(value["terminalRevocationId"]) == (
                value["recipientDid"],
                value["recipientDeviceId"],
            )

        for variant_name, untagged in positives.items():
            tagged = {
                "$type": f"{PREFIX}.defs#{variant_name}",
                **untagged,
            }
            self.assertTrue(
                closed_lexicon_value_is_valid(
                    self.canonical,
                    defs_document,
                    recovery_work,
                    tagged,
                    f"{PREFIX}.defs#recoveryWorkView",
                ),
                variant_name,
            )
            self.assertTrue(
                closed_lexicon_value_is_valid(
                    self.canonical,
                    defs_document,
                    recovery_inbox,
                    tagged,
                    f"{PREFIX}.defs#leafRecoveryInboxItem",
                ),
                f"inbox {variant_name}",
            )

            variant_schema = defs[variant_name]
            for field in required(variant_schema) | {"$type"}:
                missing = copy.deepcopy(tagged)
                missing.pop(field)
                self.assertFalse(
                    closed_lexicon_value_is_valid(
                        self.canonical,
                        defs_document,
                        recovery_work,
                        missing,
                        f"{PREFIX}.defs#recoveryWorkView",
                    ),
                    f"{variant_name} accepted missing {field}",
                )

            for field, value in terminal_values.items():
                if field in variant_schema["properties"]:
                    continue
                extra = copy.deepcopy(tagged)
                extra[field] = value
                self.assertFalse(
                    closed_lexicon_value_is_valid(
                        self.canonical,
                        defs_document,
                        recovery_work,
                        extra,
                        f"{PREFIX}.defs#recoveryWorkView",
                    ),
                    f"{variant_name} accepted extra {field}",
                )

            unknown = copy.deepcopy(tagged)
            unknown["unexpected"] = True
            self.assertFalse(
                closed_lexicon_value_is_valid(
                    self.canonical,
                    defs_document,
                    recovery_work,
                    unknown,
                    f"{PREFIX}.defs#recoveryWorkView",
                ),
                f"{variant_name} accepted an unknown field",
            )

            for wrong_status in {"pending", "completed", "superseded"} - {tagged["status"]}:
                wrong = copy.deepcopy(tagged)
                wrong["status"] = wrong_status
                self.assertFalse(
                    closed_lexicon_value_is_valid(
                        self.canonical,
                        defs_document,
                        recovery_work,
                        wrong,
                        f"{PREFIX}.defs#recoveryWorkView",
                    ),
                    f"{variant_name} accepted status {wrong_status}",
                )

        rejected_welcome_source = {
            "$type": f"{PREFIX}.defs#recoveryWorkPendingView",
            **positives["recoveryWorkPendingView"],
            "sourceKind": "welcomeRejected",
        }
        self.assertTrue(
            closed_lexicon_value_is_valid(
                self.canonical,
                defs_document,
                recovery_work,
                rejected_welcome_source,
                f"{PREFIX}.defs#recoveryWorkView",
            )
        )

        both_terminal_ids = {
            "$type": f"{PREFIX}.defs#recoveryWorkSupersededByTransitionView",
            **positives["recoveryWorkSupersededByTransitionView"],
            "terminalRevocationId": revocation_id,
        }
        self.assertFalse(
            closed_lexicon_value_is_valid(
                self.canonical,
                defs_document,
                recovery_work,
                both_terminal_ids,
                f"{PREFIX}.defs#recoveryWorkView",
            )
        )

        revocation_variant = {
            "$type": f"{PREFIX}.defs#recoveryWorkSupersededByRevocationView",
            **positives["recoveryWorkSupersededByRevocationView"],
        }
        self.assertTrue(is_valid_with_revocation_authority(revocation_variant))
        sibling_device = copy.deepcopy(revocation_variant)
        sibling_device["recipientDeviceId"] = uuid_bytes(
            "77777777-7777-4777-b777-777777777777"
        )
        self.assertTrue(
            closed_lexicon_value_is_valid(
                self.canonical,
                defs_document,
                recovery_work,
                sibling_device,
                f"{PREFIX}.defs#recoveryWorkView",
            ),
            "the closed object validates shape; authority must reject sibling evidence",
        )
        self.assertFalse(is_valid_with_revocation_authority(sibling_device))
        wrong_recipient = copy.deepcopy(revocation_variant)
        wrong_recipient["recipientDid"] = "did:web:bob.example.net"
        self.assertFalse(is_valid_with_revocation_authority(wrong_recipient))
        wrong_revocation = copy.deepcopy(revocation_variant)
        wrong_revocation["terminalRevocationId"] = uuid_bytes(
            "88888888-8888-4888-8888-888888888888"
        )
        self.assertFalse(is_valid_with_revocation_authority(wrong_revocation))

        nested_union_tag = {
            "$type": f"{PREFIX}.defs#recoveryWorkView",
            **positives["recoveryWorkPendingView"],
        }
        self.assertFalse(
            closed_lexicon_value_is_valid(
                self.canonical,
                defs_document,
                recovery_inbox,
                nested_union_tag,
                f"{PREFIX}.defs#leafRecoveryInboxItem",
            )
        )

        for forbidden_source in ("poisonedState", "joinFailure"):
            wrong_source = {
                "$type": f"{PREFIX}.defs#recoveryWorkPendingView",
                **positives["recoveryWorkPendingView"],
                "sourceKind": forbidden_source,
            }
            self.assertFalse(
                closed_lexicon_value_is_valid(
                    self.canonical,
                    defs_document,
                    recovery_work,
                    wrong_source,
                    f"{PREFIX}.defs#recoveryWorkView",
                )
            )

        unknown_variant = {
            "$type": f"{PREFIX}.defs#unknownRecoveryWorkView",
            **positives["recoveryWorkPendingView"],
        }
        self.assertFalse(
            closed_lexicon_value_is_valid(
                self.canonical,
                defs_document,
                recovery_work,
                unknown_variant,
                f"{PREFIX}.defs#recoveryWorkView",
            )
        )

    def test_server_mirror_has_exact_manifest_and_bytes(self) -> None:
        canonical = {path.name: path.read_bytes() for path in CANONICAL_ROOT.glob("*.json")}
        mirror = {path.name: path.read_bytes() for path in MIRROR_ROOT.glob("*.json")}
        self.assertEqual(canonical, mirror)

    def test_negative_schema_mutations_are_rejected(self) -> None:
        try:
            validate_non_crypto_contract(self.canonical, self.vectors)
        except (AssertionError, KeyError):
            self.skipTest("negative mutations require the repaired base corpus")

        cases: list[tuple[str, dict[str, dict[str, Any]]]] = []

        raw_key_package = copy.deepcopy(self.canonical)
        raw_key_package[f"{PREFIX}.defs.json"]["defs"]["keyPackageArtifact"]["properties"]["framing"]["const"] = "rawKeyPackage"
        cases.append(("raw inner KeyPackage", raw_key_package))

        missing_context_hash = copy.deepcopy(self.canonical)
        missing_context_hash[f"{PREFIX}.defs.json"]["defs"]["conversationCoordinates"]["required"].remove("groupContextHash")
        cases.append(("missing groupContextHash", missing_context_hash))

        open_union = copy.deepcopy(self.canonical)
        open_union[f"{PREFIX}.defs.json"]["defs"]["conversationEntry"]["closed"] = False
        cases.append(("open entry union", open_union))

        unbounded_array = copy.deepcopy(self.canonical)
        del unbounded_array[f"{PREFIX}.defs.json"]["defs"]["welcomeBundle"]["properties"]["deliveries"]["maxLength"]
        cases.append(("unbounded deliveries", unbounded_array))

        ambiguous_signature = copy.deepcopy(self.canonical)
        ambiguous_signature[f"{PREFIX}.defs.json"]["defs"]["applicationSendBody"]["properties"]["signatureDomain"]["const"] = "CATBIRD-CHAT-COMMIT\0"
        cases.append(("reused signature domain", ambiguous_signature))

        stale_ack = copy.deepcopy(self.canonical)
        stale_ack[f"{PREFIX}.acknowledgeWelcome.json"]["defs"]["main"]["errors"].append({"name": "StaleCoordinates"})
        cases.append(("current-coordinate Welcome acknowledgement", stale_ack))

        mixed_inventory_cursor = copy.deepcopy(self.canonical)
        params = mixed_inventory_cursor[f"{PREFIX}.getConversations.json"]["defs"]["main"]["parameters"]
        params["properties"]["afterCursor"] = {"type": "string"}
        cases.append(("event cursor reused as page cursor", mixed_inventory_cursor))

        missing_recovery_welcome = copy.deepcopy(self.canonical)
        missing_recovery_welcome[f"{PREFIX}.defs.json"]["defs"]["welcomeDelivery"]["properties"]["provenance"]["ref"] = "#artifactHash"
        cases.append(("missing recovery Welcome provenance", missing_recovery_welcome))

        ambiguous_welcome = copy.deepcopy(self.canonical)
        ambiguous_welcome[f"{PREFIX}.defs.json"]["defs"]["welcomeDelivery"]["properties"]["provenance"] = {
            "type": "object",
            "properties": {
                "recoveryRequestId": {"type": "ref", "ref": "#operationId"},
                "welcomeId": {"type": "ref", "ref": "#operationId"},
            },
        }
        cases.append(("ambiguous Welcome provenance", ambiguous_welcome))

        wrong_recovery_welcome = copy.deepcopy(self.canonical)
        recovery_provenance = wrong_recovery_welcome[f"{PREFIX}.defs.json"]["defs"]["recoveryWelcomeProvenance"]
        recovery_provenance["required"] = ["welcomeId", "keyPackageRef"]
        recovery_provenance["properties"]["welcomeId"] = recovery_provenance["properties"].pop("recoveryRequestId")
        cases.append(("wrong recovery Welcome provenance", wrong_recovery_welcome))

        misplaced_welcome_ordering = copy.deepcopy(self.canonical)
        misplaced_welcome_ordering[f"{PREFIX}.defs.json"]["defs"]["welcomeView"]["description"] = (
            misplaced_welcome_ordering[f"{PREFIX}.defs.json"]["defs"]["transitionManifest"]["description"]
        )
        cases.append(("transition ordering prose misplaced on Welcome view", misplaced_welcome_ordering))

        for label, documents in cases:
            with self.subTest(label=label), self.assertRaises((AssertionError, KeyError)):
                validate_non_crypto_contract(documents, self.vectors)

    def test_strict_json_duplicate_null_unknown_and_union_instances(self) -> None:
        with self.assertRaises(ValueError):
            strict_json_loads('{"deviceId":"a","deviceId":"b"}')
        self.assertIsNone(strict_json_loads('{"deviceId":null}')["deviceId"])

        defs = self.canonical[f"{PREFIX}.defs.json"]["defs"]
        entry_union = defs["conversationEntry"]
        if entry_union.get("type") != "union":
            self.skipTest("instance-union checks require the repaired base corpus")
        known = {f"{PREFIX}.defs#{local_ref_name(ref)}" for ref in entry_union["refs"]}
        self.assertNotIn(f"{PREFIX}.defs#unknownEntry", known)
        self.assertTrue(entry_union["closed"])


if __name__ == "__main__":
    unittest.main()
