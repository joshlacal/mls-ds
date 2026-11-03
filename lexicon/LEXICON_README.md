# Lexicons

AT Protocol lexicons for `mls-ds`, by namespace. The JSON files are the source of truth; the server's generated Rust types come from `catbird-atproto` (`catbird_atproto::generated::blue_catbird::*`). The `blue.catbird.mls.*` lexicons this file used to describe belong to the pre-clean-slate API and no longer exist.

| Directory | Contents |
|---|---|
| `blue/catbird/chat/` | The client API served by `server/src/handlers/chat`: 36 queries and procedures plus the `subscribeEvents` subscription. Also `defs`, the `authFull` permission set, and the `declaration` and `device` records each account publishes on its PDS. |
| `blue/catbird/labyrinth/` | The six directory and account-lifecycle endpoints served by `server/src/handlers/labyrinth` (`publishEpochHead`, `purgeMailbox`, `deleteAccountData`, `getEpochHead`, `getChatDeviceKeys`, `getMemberDevices`), plus `defs` and the Labyrinth record and Space types clients write to their own PDS. The `conversation` Space holds `batch`, `mek` and `attachmentManifest` records. |
| `blue/catbird/mlsDS/` | The original S2S methods (`deliverMessage`, `deliverWelcome`, `submitCommit`, `fetchKeyPackage`, `getConvoDigest`, `getConvoEvents`, `transferSequencer`, `healthCheck`) and the peer-administration methods. |
| `blue/catbird/bskychat/` | `pushHeartbeat` and `updateMuteStatus`. `mls-ds` mounts neither. |

The S2S methods added for groups, cross-home effects and C33, such as `relayGroupMutation`, `deliverGroupEntry`, `relayEntryAck`, `notifyEntriesPruned`, `relayAccountDeletion`, `deliverTransportControlEntry` and `deliverDirectRequest`, have no lexicon file here. Their request types are defined in `server/src/federation/` and `server/src/handlers/ds/direct_requests.rs`. Every mounted route is listed in [../server/README.md](../server/README.md#routes).
