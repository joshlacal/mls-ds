# MLS Membership Change Events Specification

## Overview

This document specifies the required backend lexicon updates for MLS membership change events. These events enable the client to track when members join, leave, or are removed from conversations, including kick events and conversation recovery scenarios.

## Client Implementation Status

The iOS client has been prepared for these events with the following changes:

### 1. New MLSStateEvent Cases (MLSConversationManager.swift)
- `membershipChanged(convoId: String, did: DID, action: MembershipAction)`
- `kickedFromConversation(convoId: String, by: DID, reason: String?)`
- `conversationNeedsRecovery(convoId: String, reason: RecoveryReason)`

### 2. Supporting Enums
```swift
enum MembershipAction: String, Codable, Sendable {
    case joined
    case left
    case removed
    case kicked
}

enum RecoveryReason: String, Codable, Sendable {
    case epochMismatch
    case keyPackageDesync
    case memberRemoval
    case serverStateInconsistent
}
```

### 3. Storage Updates (MLSMemberModel)
Added fields to track removal details:
- `removedBy: String?` - DID of user who removed the member
- `removalReason: String?` - Human-readable reason for removal

### 4. Event Handlers (MLSEventStreamManager)
Added handler callbacks in EventHandler struct:
- `onMembershipChanged: ((String, DID, MembershipAction) async -> Void)?`
- `onKickedFromConversation: ((String, DID, String?) async -> Void)?`
- `onConversationNeedsRecovery: ((String, RecoveryReason) async -> Void)?`

## Required Backend Lexicon Updates

The lexicon file `blue.catbird.mls.streamConvoEvents.json` needs the following additions:

### 1. MembershipChangeEvent

Add to the `defs` section and the event union:

```json
{
  "membershipChangeEvent": {
    "type": "object",
    "description": "Event indicating a member joined, left, or was removed from a conversation",
    "required": ["cursor", "convoId", "did", "action", "timestamp"],
    "properties": {
      "cursor": {
        "type": "string",
        "description": "Resume cursor for this event position"
      },
      "convoId": {
        "type": "string",
        "description": "Conversation identifier"
      },
      "did": {
        "type": "string",
        "format": "did",
        "description": "DID of the member whose membership changed"
      },
      "action": {
        "type": "string",
        "description": "Membership action performed",
        "knownValues": ["joined", "left", "removed", "kicked"]
      },
      "timestamp": {
        "type": "string",
        "format": "datetime",
        "description": "When the membership change occurred"
      },
      "removedBy": {
        "type": "string",
        "format": "did",
        "description": "DID of user who removed the member (for removed/kicked actions)"
      },
      "reason": {
        "type": "string",
        "description": "Human-readable reason for the membership change"
      }
    }
  }
}
```

### 2. KickedEvent

```json
{
  "kickedEvent": {
    "type": "object",
    "description": "Event indicating the authenticated user was kicked from a conversation",
    "required": ["cursor", "convoId", "kickedBy", "timestamp"],
    "properties": {
      "cursor": {
        "type": "string",
        "description": "Resume cursor for this event position"
      },
      "convoId": {
        "type": "string",
        "description": "Conversation identifier"
      },
      "kickedBy": {
        "type": "string",
        "format": "did",
        "description": "DID of the user who performed the kick"
      },
      "reason": {
        "type": "string",
        "description": "Optional reason provided for the kick"
      },
      "timestamp": {
        "type": "string",
        "format": "datetime",
        "description": "When the kick occurred"
      }
    }
  }
}
```

### 3. ConversationRecoveryEvent

```json
{
  "conversationRecoveryEvent": {
    "type": "object",
    "description": "Event indicating a conversation needs recovery due to state inconsistency",
    "required": ["cursor", "convoId", "reason", "timestamp"],
    "properties": {
      "cursor": {
        "type": "string",
        "description": "Resume cursor for this event position"
      },
      "convoId": {
        "type": "string",
        "description": "Conversation identifier"
      },
      "reason": {
        "type": "string",
        "description": "Reason for recovery requirement",
        "knownValues": ["epochMismatch", "keyPackageDesync", "memberRemoval", "serverStateInconsistent"]
      },
      "timestamp": {
        "type": "string",
        "format": "datetime",
        "description": "When the recovery was triggered"
      },
      "details": {
        "type": "string",
        "description": "Additional diagnostic information"
      }
    }
  }
}
```

### 4. Update Event Union

In the `eventWrapper` definition, update the union to include the new event types:

```json
{
  "event": {
    "type": "union",
    "description": "The actual event (message, reaction, typing, info, membership change, kicked, or recovery)",
    "refs": [
      "#messageEvent",
      "#reactionEvent",
      "#typingEvent",
      "#infoEvent",
      "#newDeviceEvent",
      "#groupInfoRefreshRequestedEvent",
      "#readditionRequestedEvent",
      "#membershipChangeEvent",
      "#kickedEvent",
      "#conversationRecoveryEvent"
    ]
  }
}
```

## Backend Server Implementation

The backend server needs to emit these events in the following scenarios:

### MembershipChangeEvent
- When a user joins a conversation (action: "joined")
- When a user voluntarily leaves (action: "left")
- When a user is removed by an admin (action: "removed", include removedBy)
- When a user is kicked (action: "kicked", include removedBy and reason)

### KickedEvent
- Sent specifically to the kicked user's SSE stream
- Provides immediate notification of removal with reason
- Should trigger conversation state cleanup on client

### ConversationRecoveryEvent
- When epoch mismatch is detected (reason: "epochMismatch")
- When key package desync occurs (reason: "keyPackageDesync")
- When member removal causes state issues (reason: "memberRemoval")
- When server detects any state inconsistency (reason: "serverStateInconsistent")

## Event Processing Flow

1. **MembershipChangeEvent received**
   - Client updates local MLSMemberModel with removedBy/removalReason
   - Triggers MLSStateEvent.membershipChanged
   - UI updates to reflect membership change
   - If self is removed, triggers conversation cleanup

2. **KickedEvent received**
   - Client immediately triggers MLSStateEvent.kickedFromConversation
   - Shows user-facing notification with reason
   - Initiates conversation state cleanup
   - Removes conversation from active list

3. **ConversationRecoveryEvent received**
   - Client triggers MLSStateEvent.conversationNeedsRecovery
   - Initiates recovery procedure based on reason
   - May request group info refresh or re-addition
   - Logs diagnostic information

## Migration Notes

- Database migration required for MLSMemberModel to add `removedBy` and `removalReason` columns
- Existing members can have NULL values for these fields
- Client handlers are backward compatible and will not break with old backend

## Testing Scenarios

1. **Member leaves voluntarily**: Verify action="left", no removedBy
2. **Admin removes member**: Verify action="removed", removedBy set to admin DID
3. **Member kicked with reason**: Verify action="kicked", removedBy and reason populated
4. **Self kicked**: Verify both KickedEvent and MembershipChangeEvent received
5. **Epoch mismatch**: Verify ConversationRecoveryEvent with reason="epochMismatch"
6. **Resume from cursor**: Verify events replayed correctly after reconnection

## Code Generation

After updating the lexicon, regenerate Petrel types:

```bash
cd Petrel
python Generator/main.py
```

This will generate the Swift types in `Petrel/Sources/Petrel/Generated/Lexicons/Blue/Catbird/BlueCatbirdMlsStreamConvoEvents.swift`.

The generated union enum will automatically include:
- `.blueCatbirdMlsStreamConvoEventsMembershipChangeEvent`
- `.blueCatbirdMlsStreamConvoEventsKickedEvent`
- `.blueCatbirdMlsStreamConvoEventsConversationRecoveryEvent`

Then update the client handleEvent switch statement to uncomment the prepared handlers.
