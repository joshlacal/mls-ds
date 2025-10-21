# Security Considerations

## Threat Model

### Server Compromise
- **Risk**: Attacker gains access to server/database
- **Mitigation**: All messages stored as MLS ciphertext only
- **Impact**: Metadata visible (DIDs, conversation IDs, timing), but no plaintext

### Client Device Compromise
- **Risk**: Device stolen or malware installed
- **Mitigation**: 
  - Remove compromised member from group (new epoch = new keys)
  - Store keys in iOS Keychain/Secure Enclave
- **Impact**: Past messages on device accessible, but future messages secure after removal (PCS)

### Malicious Group Member
- **Risk**: Insider leaks messages
- **Mitigation**: None (social/policy issue)
- **Detection**: All messages signed, forgery detectable

### Network Eavesdropper
- **Risk**: Man-in-the-middle attack
- **Mitigation**: TLS for transport + MLS E2EE for content
- **Impact**: No plaintext exposure

## Security Properties

### Forward Secrecy
- Each epoch uses fresh keys derived from ratchet tree
- Compromise of current keys doesn't reveal past messages
- Automatic via MLS protocol

### Post-Compromise Security (PCS)
- After member removal, new keys generated
- Compromised device cannot decrypt future messages
- Achieved via Remove commit and tree updates

### Authentication
- All messages signed by sender's MLS credential
- Credentials bound to AT Protocol DID
- DID public keys verified via DID document

### Integrity
- MLS provides authenticated encryption (AEAD)
- Tampering detected and rejected
- Replay attacks prevented via epoch + sequence numbers

## Privacy Protections

### Message Content
- **Status**: ✅ Protected via E2EE
- Server never sees plaintext

### Membership
- **Status**: ⚠️ Visible to server (necessary for routing)
- Not published to public AT Protocol network

### Metadata
- **Status**: ⚠️ Visible to server
- Includes: conversation IDs, message sizes, timing, sender/recipient DIDs
- **Future**: Could add padding, dummy traffic, or onion routing

### DID Key Publication
- **Status**: ⚠️ MLS public keys may be in DID document
- **Mitigation**: Use same key as existing atproto signing key
- Reduces fingerprinting risk

## Key Management

### Identity Keys (Ed25519)
- **Storage**: iOS Keychain with Secure Enclave access
- **Lifetime**: Long-term (tied to DID)
- **Usage**: Sign MLS credentials and handshake messages

### Ephemeral Keys (X25519)
- **Storage**: In-memory during session, encrypted on disk
- **Lifetime**: Per KeyPackage (24-48 hours)
- **Usage**: HPKE for Welcome message encryption

### Group Keys
- **Storage**: OpenMLS state (encrypted on disk)
- **Lifetime**: Per epoch
- **Usage**: Symmetric encryption of application messages

### KeyPackage Rotation
- Generate fresh KeyPackage after each use (one-time)
- Proactively publish 3-5 packages to allow concurrent invites
- Enforce expiration (24-48 hour lifetime)

## Attack Mitigations

### Replay Attacks
- **Protection**: MLS sequence numbers + epoch tracking
- Each message has unique nonce

### Rollback Attacks
- **Protection**: Monotonic epoch numbers
- Clients reject messages from past epochs

### Key Compromise
- **Response**: Remove affected member, advance to new epoch
- Old keys cannot decrypt new messages

### Traffic Analysis
- **Current**: Message sizes and timing visible to server
- **Future**: Add padding to uniform size, send dummy messages

### Denial of Service
- **Protection**: Rate limiting, authentication required
- Invalid messages rejected before processing

## Logging Policy

### What We Log
- High-level events (group created, member added/removed)
- Hashed conversation IDs (8-byte SHA256)
- Truncated DIDs or hashes
- Error types and status codes

### What We DON'T Log
- Message plaintext or ciphertext
- Private keys
- Full conversation IDs (only hashes)
- Attachment content

## Compliance Notes

- No PII stored in plaintext
- GDPR: Users can request data deletion (ciphertext only)
- E2EE means provider cannot moderate content
- Users responsible for their own backups (state loss = cannot rejoin)

## Known Limitations (MVP)

1. **No message deniability**: MLS provides authentication (signatures)
2. **Metadata visible to server**: DIDs, conversation membership, timing
3. **Single device per user**: Multi-device requires coordination
4. **No offline message sending**: Sender must be online to commit
5. **Manual key rotation**: No automatic epoch updates (Update commits)

## Future Enhancements

- [ ] Sealed sender (hide sender from server)
- [ ] Onion routing for metadata privacy
- [ ] Multi-device support per user
- [ ] Periodic automatic Update commits (key rotation)
- [ ] PSK-based recovery for lost devices
- [ ] Message expiration / ephemeral messages
