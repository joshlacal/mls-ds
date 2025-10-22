# MLS Chat - Frequently Asked Questions

**Version**: 1.0  
**Last Updated**: October 21, 2025

---

## 📚 Table of Contents

- [General Questions](#general-questions)
- [Security & Privacy](#security--privacy)
- [Technical Questions](#technical-questions)
- [Troubleshooting](#troubleshooting)
- [Usage Questions](#usage-questions)
- [Comparison with Other Apps](#comparison-with-other-apps)

---

## 🌐 General Questions

### What is MLS Chat?

**MLS Chat** is an end-to-end encrypted group messaging feature in the Catbird iOS app. It uses the **MLS (Messaging Layer Security)** protocol (RFC 9420) to provide secure group conversations with forward secrecy and post-compromise security.

---

### How is MLS different from regular Bluesky chat?

| Feature | Bluesky Chat | MLS Chat |
|---------|-------------|----------|
| **Encryption** | None (plaintext) | End-to-end encrypted |
| **Server Access** | Can read messages | Cannot read messages |
| **Protocol** | AT Protocol DMs | MLS (RFC 9420) |
| **Group Support** | Limited | Native group design |
| **Forward Secrecy** | No | Yes |
| **Post-Compromise Security** | No | Yes |

---

### Why use MLS instead of Signal Protocol?

Both are excellent E2EE protocols. Key differences:

| MLS | Signal Protocol |
|-----|-----------------|
| ✅ Designed for **large groups** | ✅ Optimized for **1-on-1** and small groups |
| ✅ Efficient key management (tree-based) | ⚠️ Pairwise keys (scales poorly) |
| ✅ **IETF standard** (RFC 9420) | ⚠️ Open source but not standardized |
| ✅ Multiple implementations | ⚠️ Primarily Signal's implementation |
| ⚠️ Newer (2023) | ✅ Battle-tested since 2013 |

**We chose MLS** because it's a modern standard with better scalability for groups.

---

### Is MLS Chat compatible with other apps?

**Currently: No.** MLS Chat is Catbird-specific.

**Future:** Since MLS is a standard, we could interoperate with other MLS-compatible apps if they:
- Use compatible cipher suites
- Support AT Protocol for identity
- Agree on message formats

---

### Does MLS Chat work offline?

**Partially:**
- ✅ You can **read** downloaded messages offline
- ❌ You cannot **send** messages (requires server connection)
- ❌ You cannot **join** new groups
- ✅ Decryption happens locally (doesn't need internet)

---

### How much data does MLS Chat use?

**Approximate bandwidth:**
- Text message: ~2 KB encrypted
- Photo (compressed): ~500 KB - 2 MB encrypted
- Video (1 min): ~10 MB encrypted
- KeyPackage download: ~1 KB per member
- Group creation: ~10 KB + member count

**Storage:**
- Messages: ~1-2 KB each
- Media: Variable (encrypted)
- Group state: ~50 KB per group
- KeyPackages: ~1 KB each (you store 3-5)

---

## 🔒 Security & Privacy

### Can the server read my messages?

**No.** Messages are encrypted **before** leaving your device. The server only sees:
- Ciphertext (encrypted bytes)
- Metadata (sender DID, conversation ID, timestamp)

Even if the server is compromised, attackers cannot decrypt past or future messages.

---

### What metadata is visible to the server?

The server can see:
- ⚠️ **Participant DIDs** (who's in each group)
- ⚠️ **Message timestamps** (when messages were sent)
- ⚠️ **Message sizes** (approximate length)
- ⚠️ **Conversation IDs** (which group, but not the name)
- ⚠️ **Epoch numbers** (group state version)

This is standard for E2EE systems. Even Signal exposes similar metadata.

---

### What if someone steals my phone?

**Immediate risk:**
- ✅ Messages on device are accessible if unlocked
- ✅ Group state is encrypted but could be decrypted

**Mitigation:**
1. Enable **Face ID / Touch ID** on the app
2. Use **iOS passcode** protection
3. Enable **remote wipe** via Find My iPhone

**Long-term protection:**
- Once you report the device compromised, you can be **removed from groups**
- After removal, the stolen device **cannot decrypt future messages** (post-compromise security)

---

### Can I verify someone's identity?

**Yes.** MLS Chat uses **AT Protocol DIDs** for identity:

1. Tap on a member in group info
2. View their full DID (e.g., `did:plc:abc123...`)
3. **Verify out-of-band** (phone call, in-person, etc.)
4. Confirm the DID matches

**Advanced:** You can also verify their DID via:
- Their AT Protocol profile
- DNS records (for `did:web`)
- PLC directory (for `did:plc`)

---

### What happens if I lose my phone?

**Without backup:**
- ❌ You **lose access** to all MLS groups
- ❌ Cannot rejoin groups (different identity keys)
- ❌ Message history is lost

**With iCloud backup (if enabled):**
- ✅ Group state backed up (encrypted)
- ✅ Identity keys backed up to Keychain
- ✅ Can restore on new device

**Recommendation:** Enable iCloud Keychain and SwiftData backups.

---

### Is MLS quantum-resistant?

**No.** The default cipher suite uses:
- **X25519** (key exchange) - vulnerable to quantum computers
- **Ed25519** (signatures) - vulnerable to quantum computers

**Future-proofing:**
- MLS spec allows adding post-quantum cipher suites
- We'll upgrade when post-quantum algorithms are standardized (NIST competition ongoing)

**Current risk:** Minimal (quantum computers can't break X25519 yet).

---

### Can admins see who reads messages?

**No.** Read receipts are **optional** and **client-to-client**:
- If you enable them, other clients see your read status
- The server does **not** track read receipts
- Admins have no special visibility

---

## 🔧 Technical Questions

### What cipher suite does MLS Chat use?

**Default:** `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`

**Breakdown:**
- **DHKEM-X25519**: Diffie-Hellman key exchange (HPKE)
- **AES-128-GCM**: Authenticated encryption
- **SHA-256**: Hash function
- **Ed25519**: Digital signatures

This is **mandatory-to-implement** in MLS RFC 9420, ensuring broad compatibility.

---

### How long are KeyPackages valid?

**Default lifetime:** 24-48 hours

**Why expire?**
- Limits exposure if private key is compromised
- Prevents stale key reuse
- Forces regular rotation

**Auto-rotation:** The app automatically publishes new KeyPackages before expiry.

---

### What's an "epoch" in MLS?

An **epoch** is a version number for the group state. It increments whenever:
- A member is **added**
- A member is **removed**
- A member performs an **Update** commit (key rotation)

**Example:**
```
Epoch 0: Alice creates group
Epoch 1: Alice adds Bob
Epoch 2: Alice adds Charlie
Epoch 3: Bob leaves
Epoch 4: Alice sends Update commit
```

Each epoch has **unique encryption keys**, providing forward secrecy.

---

### How does forward secrecy work?

**Forward Secrecy (FS):** Past messages remain secure even if current keys are compromised.

**MLS implementation:**
1. Each epoch uses keys derived from a **ratchet tree**
2. Old key material is **deleted** after epoch advance
3. Attacker with current keys cannot compute past keys

**Example:** If your device is compromised in Epoch 5, Epochs 0-4 are still secure.

---

### How does post-compromise security work?

**Post-Compromise Security (PCS):** Future messages remain secure after a compromise is detected.

**MLS implementation:**
1. Remove compromised member from group
2. Group advances to new epoch with fresh keys
3. Removed member cannot decrypt future messages

**Example:** Alice's phone is stolen → Remove Alice → Epoch advances → Stolen device can't decrypt new messages.

---

### Can I use MLS Chat with multiple devices?

**Not natively.** MLS Chat currently supports **one device per user**.

**Workaround:**
- Create separate DIDs for each device
- Invite both DIDs to the group
- Treat them as separate members

**Future:** We may add multi-device support via:
- Device-level sub-identities
- Shared identity across devices (requires coordination)

---

### What's the maximum group size?

**Recommended:** Up to 50 members
**Technical limit:** ~1000 members (MLS protocol supports up to 2^32)

**Why limit?**
- Larger groups = more KeyPackages to fetch
- Higher bandwidth for group updates
- Slower encryption/decryption

For very large groups (>100), consider:
- Broadcast channels (fewer permissions)
- Read-only announcements

---

### How are attachments encrypted?

**Process:**
1. File is encrypted **client-side** with a random symmetric key
2. Encrypted file uploaded to server (blob storage)
3. Encryption key included in MLS message payload
4. Recipients download blob and decrypt locally

**Security:**
- Server sees encrypted blob (ciphertext)
- Decryption key never leaves MLS-encrypted channel
- Integrity verified via HMAC

---

## 🐛 Troubleshooting

### "Cannot send message: Epoch mismatch"

**Cause:** Your local group state is out of sync with the server.

**Solution:**
1. Pull down to refresh the conversation
2. Wait for pending group updates to process
3. If still failing, leave and ask to be re-added

**Prevention:** Keep app open/backgrounded to receive updates in real-time.

---

### "No KeyPackages available for [DID]"

**Cause:** The recipient hasn't published recent KeyPackages.

**Solution:**
1. Ask recipient to open Catbird and let it sync
2. Wait 30-60 seconds
3. Retry adding them to the group

**Why it happens:**
- KeyPackages expired (24-48 hour lifetime)
- Recipient hasn't opened app recently
- Network issues prevented publishing

---

### "Group state corrupted"

**Cause:** Local database inconsistency or failed group update.

**Solution:**
1. **Export important messages** (screenshots)
2. Leave the group
3. Ask admin to re-invite you
4. If widespread, admin should create new group

**Prevention:** Ensure stable network during group updates.

---

### "Message decryption failed"

**Cause:** Missing keys, wrong epoch, or corrupted ciphertext.

**Solution:**
- Refresh conversation (pull down)
- Verify you're on the latest epoch
- If multiple messages fail, leave and rejoin

**Report to admin if:**
- Entire group affected
- Happens after specific member action

---

### App crashes when opening MLS Chat

**Cause:** Corrupted SwiftData store or FFI issue.

**Solution:**
1. Force quit app
2. Clear cache: Settings → MLS Chat → Clear Cache
3. If persists, reinstall app (⚠️ loses all groups)

**Before reinstalling:**
- Export conversation lists
- Notify group admins you'll rejoin

---

### "Connection timeout" errors

**Cause:** Server unreachable or network issues.

**Solution:**
1. Check internet connection
2. Verify server status: Settings → MLS → Server Health
3. Try switching Wi-Fi/cellular
4. Contact server admin if down

**Server health check:**
```bash
curl https://mls.catbird.chat/health
# Should return: {"status": "healthy"}
```

---

## 💬 Usage Questions

### How do I create a group?

1. Tap **"+"** in MLS Chat
2. Enter group name (optional)
3. Select members from contacts
4. Tap **"Create"**

Wait for all members to join (green checkmarks appear).

---

### How do I add someone to an existing group?

**Admin only:**
1. Open group info (tap group name)
2. Tap **"Add Members"**
3. Select users
4. Confirm

**Note:** New members cannot see past messages (by design for forward secrecy).

---

### How do I leave a group?

1. Open group info
2. Tap **"Leave Group"** (bottom, red text)
3. Confirm

**Warning:** This is irreversible. You'll need to be re-invited to rejoin.

---

### Can I delete messages?

**Currently: No.** Messages are immutable once sent.

**Workaround:**
- Leave the group (deletes local messages)
- Ask others to delete their local copies

**Future:** We may add:
- Delete for yourself (local only)
- Delete for everyone (sends delete request)

---

### How do I mute a group?

Settings → Notifications → Mute MLS Chat → Select duration

Or per-group: Group info → Mute Notifications

---

### How do I export a conversation?

**Currently: No built-in export.**

**Workaround:**
- Screenshots
- Copy-paste text messages
- Save media manually

**Future:** We'll add JSON export feature.

---

## 🆚 Comparison with Other Apps

### MLS Chat vs. Signal

| Feature | MLS Chat | Signal |
|---------|----------|--------|
| **E2EE Protocol** | MLS (RFC 9420) | Signal Protocol |
| **Group Size** | Up to 1000 | Up to 1000 |
| **Forward Secrecy** | ✅ | ✅ |
| **Post-Compromise Security** | ✅ | ✅ |
| **Identity System** | AT Protocol DIDs | Phone numbers |
| **Self-Hostable** | ✅ | ❌ |
| **Multi-Device** | ❌ (planned) | ✅ |
| **Sealed Sender** | ❌ (planned) | ✅ |
| **Voice/Video Calls** | ❌ | ✅ |

---

### MLS Chat vs. WhatsApp

| Feature | MLS Chat | WhatsApp |
|---------|----------|----------|
| **E2EE** | ✅ (MLS) | ✅ (Signal Protocol) |
| **Metadata Privacy** | ⚠️ DIDs visible to server | ⚠️ Phone numbers visible |
| **Self-Hostable** | ✅ | ❌ |
| **Open Source** | ✅ | ❌ |
| **Owned By** | Community | Meta/Facebook |
| **Group Admin Controls** | Basic | Advanced |

---

### MLS Chat vs. Telegram Secret Chats

| Feature | MLS Chat | Telegram |
|---------|----------|----------|
| **E2EE by Default** | ✅ | ❌ (optional) |
| **Group E2EE** | ✅ | ❌ |
| **Forward Secrecy** | ✅ | ✅ (Secret Chats) |
| **Self-Hostable** | ✅ | ❌ |
| **Cloud Sync** | ❌ | ✅ (non-E2EE) |

---

## 🛠️ Getting Help

### Where can I report bugs?

- **GitHub**: Open an issue at [github.com/catbird/mls](https://github.com/catbird/mls)
- **In-App**: Settings → Help → Report Issue
- **Email**: support@catbird.chat

---

### How do I request a feature?

- **Forum**: [discuss.catbird.chat](https://discuss.catbird.chat)
- **GitHub Discussions**: Feature Requests section

---

### Is there a community forum?

Yes! Join us at:
- **Forum**: https://discuss.catbird.chat
- **Discord**: Catbird Community Server
- **Matrix**: #catbird:matrix.org

---

### Where can I learn more about MLS?

- **MLS RFC 9420**: https://www.rfc-editor.org/rfc/rfc9420.html
- **OpenMLS Docs**: https://openmls.tech/
- **MLS Working Group**: https://datatracker.ietf.org/wg/mls/

---

## 📖 Additional Documentation

- **[USER_GUIDE.md](USER_GUIDE.md)** - Comprehensive user guide
- **[DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md)** - For developers
- **[ADMIN_GUIDE.md](ADMIN_GUIDE.md)** - For server operators
- **[SECURITY.md](SECURITY.md)** - Deep security analysis

---

**Still have questions?** Ask in the community forum or email support@catbird.chat!
