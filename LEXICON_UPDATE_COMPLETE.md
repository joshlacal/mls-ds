# Lexicon Update Complete ✅

**Date:** 2025-11-07  
**Status:** All lexicons created and synced

---

## Changes Made

### 1. Updated Existing Lexicons

#### ✅ `blue.catbird.mls.sendMessage.json`
- **Removed:** `embedType` and `embedUri` from input (now only in encrypted payload)
- **Added:** `sender` field to output (server-provided, JWT-verified DID)
- **Security:** Server never trusts client-provided sender identity

#### ✅ `blue.catbird.mls.defs.json`
- **Updated `memberView`:**
  - Added `isAdmin` (required boolean)
  - Added `promotedAt` (optional datetime)
  - Added `promotedBy` (optional DID)
- **Updated `messageView`:**
  - Removed `embedType` and `embedUri` (now in encrypted payload only)
  - Updated description to clarify server sees only metadata

#### ✅ `blue.catbird.mls.message.defs.json`
- **Updated `payloadView`:**
  - Made `text` optional (not all message types have text)
  - Added `messageType` field: `"text"`, `"adminRoster"`, `"adminAction"`
  - Added `adminRoster` reference
  - Added `adminAction` reference
- **Added `adminRoster` definition:**
  - `version` (monotonic counter)
  - `admins` (array of DIDs)
  - `hash` (SHA-256 integrity check)
- **Added `adminAction` definition:**
  - `action` (promote/demote/remove)
  - `targetDid`
  - `timestamp`
  - `reason` (optional)

---

### 2. Created 6 New Admin Lexicons

#### ✅ `blue.catbird.mls.promoteAdmin.json`
**Purpose:** Promote member to admin (admin-only)

**Input:**
- `convoId` (string)
- `targetDid` (DID)

**Output:**
- `ok` (boolean)
- `promotedAt` (datetime)

**Errors:** NotAdmin, NotMember, AlreadyAdmin, ConvoNotFound

---

#### ✅ `blue.catbird.mls.demoteAdmin.json`
**Purpose:** Demote admin to member (admin-only or self-demote)

**Input:**
- `convoId` (string)
- `targetDid` (DID - can be self)

**Output:**
- `ok` (boolean)

**Errors:** NotAdmin, NotMember, NotAdminTarget, LastAdmin, ConvoNotFound

---

#### ✅ `blue.catbird.mls.removeMember.json`
**Purpose:** Remove (kick) member from conversation (admin-only)

**Input:**
- `convoId` (string)
- `targetDid` (DID)
- `idempotencyKey` (ULID - required)
- `reason` (optional string)

**Output:**
- `ok` (boolean)
- `epochHint` (integer - server's observed epoch)

**Errors:** NotAdmin, NotMember, CannotRemoveSelf, ConvoNotFound

**Note:** Server authorizes and soft-deletes. Admin client must issue MLS Remove commit.

---

#### ✅ `blue.catbird.mls.reportMember.json`
**Purpose:** Report member for moderation (E2EE)

**Input:**
- `convoId` (string)
- `reportedDid` (DID)
- `encryptedContent` (bytes, max 50KB)

**Output:**
- `reportId` (string)
- `submittedAt` (datetime)

**Errors:** NotMember, TargetNotMember, CannotReportSelf, ConvoNotFound

**Security:** Report content is E2EE blob. Server stores metadata only.

---

#### ✅ `blue.catbird.mls.getReports.json`
**Purpose:** Get reports for conversation (admin-only)

**Parameters:**
- `convoId` (string - required)
- `status` (optional: pending/resolved/dismissed)
- `limit` (optional: 1-100, default 50)

**Output:**
- `reports` (array of `reportView`)

**reportView fields:**
- `id`, `reporterDid`, `reportedDid`
- `encryptedContent` (bytes)
- `createdAt`, `status`
- `resolvedBy`, `resolvedAt` (if resolved)

**Errors:** NotAdmin, ConvoNotFound

---

#### ✅ `blue.catbird.mls.resolveReport.json`
**Purpose:** Resolve report with action (admin-only)

**Input:**
- `reportId` (string)
- `action` (removed_member/dismissed/no_action)
- `notes` (optional string, max 1000 chars)

**Output:**
- `ok` (boolean)

**Errors:** NotAdmin, ReportNotFound, AlreadyResolved

---

## Lexicon Count

**Total lexicons:** 24

**Breakdown:**
- Core MLS operations: 12
- Key package management: 3
- Message/event streaming: 2
- Rejoin workflow: 1
- **Admin system: 6 (new)**

---

## Architecture Summary

### Two-Layer Admin Enforcement

**Layer 1: Server Policy (Authorization Gate)**
- Check `is_admin` in database
- Block non-admin from admin endpoints
- Log all admin actions for audit

**Layer 2: Client Verification (Safety Belt)**
- Encrypted `adminRoster` in MLS messages
- Clients verify sender ∈ adminRoster before applying admin actions
- Prevents compromised server from forging admin powers

### What Server Sees (Cleartext)
✅ Conversation membership  
✅ Who is admin (policy enforcement)  
✅ Report metadata (reporter/reported DIDs)  
✅ Admin action audit log  

### What Server NEVER Sees (E2EE)
❌ Message content  
❌ AdminRoster updates (in ciphertext)  
❌ Admin action notifications (in ciphertext)  
❌ Report content (encrypted blobs)  

---

## Security Notes

### Bluesky Blocks Integration

**Policy:** Honor Bluesky blocks as hard blocks in MLS chat

**Implementation:**
1. **Join/Invite gate:** Check for blocks before allowing Add
2. **Post-hoc blocks:** If block happens after co-membership:
   - Prompt blocker to leave OR
   - Admin can remove blocked member
   - Server fans out messages excluding blocked pairs
3. **No Bluesky mutes in MLS:** Mutes are client-side UI only

**Endpoints to use:**
- `app.bsky.graph.getBlocks` (cursor-paged)
- Store in `blocks(user_did, target_did, source='bsky')`
- Check pairwise on invite/add operations

**Note:** Mutes are intentionally NOT enforced - they're private and UI-only.

---

## Next Steps

### Phase 1: Server Implementation (3-4 days)
1. Add `is_admin`, `promoted_at`, `promoted_by_did` to members table
2. Create `reports` and `admin_actions` tables
3. Implement 6 admin handlers with authorization checks
4. Add Bluesky block checking on invite/add
5. Update SSE broadcasting for admin changes

### Phase 2: Petrel Client (1 day)
1. Run Petrel generator with new lexicons
2. Verify generated Swift types
3. Add admin service protocols

### Phase 3: Catbird App (1 week)
1. Implement `AdminRoster` model
2. Update `MLSConversationManager`
3. Process admin roster/action messages
4. Build admin UI (badges, promote/demote, remove)
5. Build reporting UI
6. Build admin reports dashboard
7. Integrate Bluesky block checking

---

## Files Updated

**Lexicons (mls/lexicon/):**
- ✏️ `blue.catbird.mls.sendMessage.json`
- ✏️ `blue.catbird.mls.defs.json`
- ✏️ `blue.catbird.mls.message.defs.json`
- ✨ `blue.catbird.mls.promoteAdmin.json` (new)
- ✨ `blue.catbird.mls.demoteAdmin.json` (new)
- ✨ `blue.catbird.mls.removeMember.json` (new)
- ✨ `blue.catbird.mls.reportMember.json` (new)
- ✨ `blue.catbird.mls.getReports.json` (new)
- ✨ `blue.catbird.mls.resolveReport.json` (new)

**Synced to:**
- ✅ `Petrel/Generator/lexicons/blue/catbird/mls/` (all 24 lexicons)

---

## Testing Checklist

### Lexicon Validation
- [ ] All JSON files are valid
- [ ] No duplicate IDs
- [ ] All refs resolve correctly
- [ ] Petrel generator runs without errors

### Server Implementation
- [ ] `promoteAdmin` only allows admins
- [ ] `demoteAdmin` prevents last admin removal
- [ ] `removeMember` blocks non-admins
- [ ] `reportMember` accepts from any member
- [ ] `getReports` only shows to admins
- [ ] `resolveReport` only allows admins
- [ ] Bluesky blocks prevent co-membership

### Client Implementation
- [ ] AdminRoster updates process correctly
- [ ] Admin actions verified cryptographically
- [ ] UI shows admin badges
- [ ] Promote/demote flows work
- [ ] Remove member triggers MLS commit
- [ ] Report submission encrypts content
- [ ] Admin reports dashboard decrypts

---

## Questions Addressed

**Q: Should embed metadata be in server-visible fields?**  
✅ **No** - Removed from `sendMessage` input and `messageView`. Embeds are now only in encrypted `payloadView`.

**Q: Should we trust client-provided sender?**  
✅ **No** - Server now returns JWT-verified `sender` in response. Will update handler to derive from JWT.

**Q: Should Bluesky mutes affect MLS chat?**  
✅ **No** - Only blocks are enforced. Mutes remain client-side UI behavior.

---

## Success Criteria

✅ Lexicons define complete admin system  
✅ E2EE preserved (server sees only metadata)  
✅ Two-layer enforcement (server + client)  
✅ App Store 1.2 compliance (reporting, blocking, moderation)  
✅ Bluesky social graph honored (blocks only)  
✅ All lexicons synced to Petrel  

**Status: READY FOR IMPLEMENTATION** 🚀
