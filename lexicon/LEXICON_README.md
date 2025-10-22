# Catbird MLS Lexicon

AT Protocol lexicon schemas for MLS (Messaging Layer Security) integration in the Catbird/Petrel messaging system.

## Overview

This lexicon defines a complete set of AT Protocol schemas for implementing end-to-end encrypted group messaging using the IETF MLS protocol. The lexicon includes:

- **Core data definitions** for conversations, messages, members, and key packages
- **Conversation management** procedures for creating and managing encrypted groups
- **Message operations** for sending and retrieving encrypted messages
- **Key package distribution** for establishing secure group membership
- **Blob management** for encrypted file attachments

## Lexicon Files

### Core Definitions

#### `blue.catbird.mls.defs.json`

Defines shared data types and structures used across all MLS operations:

- **convoView**: Complete view of an MLS conversation with members and metadata
- **messageView**: View of an encrypted MLS message
- **memberView**: Information about a conversation member
- **keyPackageRef**: Reference to an MLS key package for adding members
- **blobRef**: Reference to an uploaded blob/attachment
- **epochInfo**: Information about an MLS epoch
- **cipherSuiteEnum**: Enumeration of supported MLS cipher suites

### Conversation Management

#### `blue.catbird.mls.createConvo.json`

**Type**: Procedure  
**Description**: Create a new MLS conversation

**Input**:
```json
{
  "cipherSuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
  "initialMembers": ["did:plc:example1", "did:plc:example2"],
  "metadata": {
    "name": "Team Chat",
    "description": "Private team discussion"
  }
}
```

**Output**:
```json
{
  "convo": { /* convoView */ },
  "welcomeMessages": [
    {
      "did": "did:plc:example1",
      "welcome": "base64-encoded-welcome-message"
    }
  ]
}
```

**Errors**:
- `InvalidCipherSuite`: Unsupported cipher suite
- `KeyPackageNotFound`: Key package not found for one or more members
- `TooManyMembers`: Too many initial members (max 100)

#### `blue.catbird.mls.addMembers.json`

**Type**: Procedure  
**Description**: Add members to an existing conversation

**Input**:
```json
{
  "convoId": "conversation-tid",
  "members": ["did:plc:example3"]
}
```

**Output**:
```json
{
  "convo": { /* updated convoView */ },
  "commit": "base64-encoded-commit-message",
  "welcomeMessages": [
    {
      "did": "did:plc:example3",
      "welcome": "base64-encoded-welcome-message"
    }
  ]
}
```

**Errors**:
- `ConvoNotFound`: Conversation not found
- `NotMember`: Caller is not a member
- `KeyPackageNotFound`: Key package not found
- `AlreadyMember`: DID is already a member
- `TooManyMembers`: Would exceed maximum member count

#### `blue.catbird.mls.leaveConvo.json`

**Type**: Procedure  
**Description**: Leave an MLS conversation

**Input**:
```json
{
  "convoId": "conversation-tid"
}
```

**Output**:
```json
{
  "commit": "base64-encoded-commit-message",
  "epoch": { /* epochInfo */ }
}
```

**Errors**:
- `ConvoNotFound`: Conversation not found
- `NotMember`: Caller is not a member
- `LastMember`: Cannot leave as the last member

#### `blue.catbird.mls.getConvos.json`

**Type**: Query  
**Description**: Retrieve conversations for the authenticated user

**Parameters**:
```
limit=50
cursor=optional-pagination-cursor
sortBy=lastMessageAt
sortOrder=desc
```

**Output**:
```json
{
  "convos": [ /* array of convoView */ ],
  "cursor": "next-page-cursor"
}
```

### Message Operations

#### `blue.catbird.mls.sendMessage.json`

**Type**: Procedure  
**Description**: Send an encrypted message to a conversation

**Input**:
```json
{
  "convoId": "conversation-tid",
  "ciphertext": "base64-encoded-mls-ciphertext",
  "contentType": "text/plain",
  "attachments": [ /* optional blob references */ ]
}
```

**Output**:
```json
{
  "message": { /* messageView */ }
}
```

**Errors**:
- `ConvoNotFound`: Conversation not found
- `NotMember`: Caller is not a member
- `InvalidCiphertext`: Ciphertext is malformed
- `EpochMismatch`: Message epoch doesn't match current epoch
- `MessageTooLarge`: Message exceeds maximum size (1MB)

#### `blue.catbird.mls.getMessages.json`

**Type**: Query  
**Description**: Retrieve messages from a conversation

**Parameters**:
```
convoId=conversation-tid
limit=50
cursor=optional-pagination-cursor
since=2024-01-01T00:00:00Z (optional)
until=2024-12-31T23:59:59Z (optional)
epoch=5 (optional)
```

**Output**:
```json
{
  "messages": [ /* array of messageView */ ],
  "cursor": "next-page-cursor"
}
```

**Errors**:
- `ConvoNotFound`: Conversation not found
- `NotMember`: Caller is not a member
- `InvalidCursor`: Pagination cursor is invalid

### Key Package Management

#### `blue.catbird.mls.publishKeyPackage.json`

**Type**: Procedure  
**Description**: Publish a key package to enable others to add you to conversations

**Input**:
```json
{
  "keyPackage": "base64-encoded-key-package",
  "cipherSuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
  "expiresAt": "2024-12-31T23:59:59Z"
}
```

**Output**:
```json
{
  "keyPackage": { /* keyPackageRef */ }
}
```

**Errors**:
- `InvalidKeyPackage`: Key package is malformed
- `InvalidCipherSuite`: Cipher suite not supported
- `ExpirationTooFar`: Expiration date exceeds 90 days
- `TooManyKeyPackages`: Maximum key packages per user exceeded

#### `blue.catbird.mls.getKeyPackages.json`

**Type**: Query  
**Description**: Retrieve key packages for DIDs to add them to conversations

**Parameters**:
```
dids=did:plc:example1,did:plc:example2
cipherSuite=MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (optional)
```

**Output**:
```json
{
  "keyPackages": [ /* array of keyPackageRef */ ],
  "missing": [ /* DIDs without key packages */ ]
}
```

**Errors**:
- `TooManyDids`: Too many DIDs requested (max 100)
- `InvalidDid`: One or more DIDs are invalid

### Blob Management

#### `blue.catbird.mls.uploadBlob.json`

**Type**: Procedure  
**Description**: Upload a blob (file attachment) for use in messages

**Input**: Binary blob data (max 50MB)

**Output**:
```json
{
  "blob": { /* blobRef */ }
}
```

**Errors**:
- `BlobTooLarge`: Blob exceeds 50MB
- `UnsupportedMimeType`: MIME type not supported
- `QuotaExceeded`: User storage quota exceeded

## Cipher Suites

Supported MLS cipher suites (as defined in RFC 9420):

- `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (Recommended)
- `MLS_128_DHKEMP256_AES128GCM_SHA256_P256`
- `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
- `MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448`
- `MLS_256_DHKEMP521_AES256GCM_SHA512_P521`
- `MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448`

## Usage Examples

### Creating a Conversation

```typescript
import { AtpAgent } from '@atproto/api';

const agent = new AtpAgent({ service: 'https://catbird.social' });
await agent.login({ identifier: 'user.catbird.social', password: 'xxx' });

// Create conversation
const response = await agent.api.blue.catbird.mls.createConvo({
  cipherSuite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
  initialMembers: ['did:plc:alice', 'did:plc:bob'],
  metadata: {
    name: 'Project Discussion',
    description: 'Planning our next release'
  }
});

console.log('Created conversation:', response.data.convo.id);

// Distribute welcome messages to new members
for (const welcome of response.data.welcomeMessages) {
  await distributeWelcome(welcome.did, welcome.welcome);
}
```

### Publishing Key Packages

```typescript
import { generateKeyPackage } from './mls-client';

// Generate key package using MLS library
const keyPackage = await generateKeyPackage({
  cipherSuite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
  credential: userCredential,
  privateKey: userPrivateKey
});

// Publish to server
await agent.api.blue.catbird.mls.publishKeyPackage({
  keyPackage: Buffer.from(keyPackage).toString('base64'),
  cipherSuite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
  expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
});
```

### Sending Messages

```typescript
import { encryptMessage } from './mls-client';

// Encrypt message using MLS group context
const plaintext = JSON.stringify({
  text: 'Hello, team!',
  timestamp: new Date().toISOString()
});

const ciphertext = await encryptMessage(groupContext, plaintext);

// Send encrypted message
await agent.api.blue.catbird.mls.sendMessage({
  convoId: 'conversation-tid',
  ciphertext: Buffer.from(ciphertext).toString('base64'),
  contentType: 'application/json'
});
```

### Adding Members

```typescript
// Fetch key packages for new members
const keyPackages = await agent.api.blue.catbird.mls.getKeyPackages({
  dids: ['did:plc:charlie'],
  cipherSuite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'
});

if (keyPackages.data.missing.length > 0) {
  console.error('Missing key packages for:', keyPackages.data.missing);
  return;
}

// Add members to conversation
const result = await agent.api.blue.catbird.mls.addMembers({
  convoId: 'conversation-tid',
  members: ['did:plc:charlie']
});

// Distribute commit to existing members
await distributeCommit(result.data.commit);

// Distribute welcome to new members
for (const welcome of result.data.welcomeMessages) {
  await distributeWelcome(welcome.did, welcome.welcome);
}
```

### Retrieving Messages

```typescript
// Get recent messages
const messages = await agent.api.blue.catbird.mls.getMessages({
  convoId: 'conversation-tid',
  limit: 50
});

// Decrypt and display messages
for (const message of messages.data.messages) {
  const ciphertext = Buffer.from(message.ciphertext, 'base64');
  const plaintext = await decryptMessage(groupContext, ciphertext);
  console.log(`${message.sender}: ${plaintext}`);
}

// Paginate for older messages
if (messages.data.cursor) {
  const olderMessages = await agent.api.blue.catbird.mls.getMessages({
    convoId: 'conversation-tid',
    cursor: messages.data.cursor,
    limit: 50
  });
}
```

### Uploading Attachments

```typescript
import { readFileSync } from 'fs';

// Upload file
const fileData = readFileSync('document.pdf');
const blobResult = await agent.api.blue.catbird.mls.uploadBlob(fileData);

// Send message with attachment
await agent.api.blue.catbird.mls.sendMessage({
  convoId: 'conversation-tid',
  ciphertext: encryptedMessageCiphertext,
  attachments: [blobResult.data.blob]
});
```

## Validation Rules

### String Lengths
- Conversation name: max 128 characters
- Conversation description: max 512 characters
- MIME type: max 256 characters
- Ciphertext: max 1MB (1,048,576 bytes)
- Key package: max 64KB (65,536 bytes)

### Array Limits
- Initial members: 0-100
- Add members: 1-50
- Message attachments: max 10
- Get key packages: 1-100 DIDs
- Message query limit: 1-100

### File Sizes
- Blob/attachment: max 50MB (52,428,800 bytes)
- Avatar image: max 1MB (1,000,000 bytes)

### Key Package Expiration
- Default: 30 days
- Maximum: 90 days

## Security Considerations

1. **Cipher Suite Selection**: Use `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` for best performance and security
2. **Key Package Rotation**: Publish fresh key packages regularly (at least monthly)
3. **Epoch Management**: Clients must track epochs and reject messages from old epochs
4. **Forward Secrecy**: All encryption keys are ephemeral and rotated with each epoch
5. **Authentication**: All operations require authenticated AT Protocol sessions
6. **Post-Compromise Security**: MLS provides automatic recovery from key compromise

## Error Handling

All procedures may return standard AT Protocol errors:
- `AuthenticationRequired`: User must authenticate
- `InvalidRequest`: Request validation failed
- `RateLimitExceeded`: Too many requests

Handle errors gracefully:

```typescript
try {
  await agent.api.blue.catbird.mls.sendMessage(params);
} catch (error) {
  if (error.error === 'EpochMismatch') {
    // Sync group state and retry
    await syncGroupState(params.convoId);
    await agent.api.blue.catbird.mls.sendMessage(params);
  } else {
    console.error('Send failed:', error);
  }
}
```

## Integration with AT Protocol

These lexicons follow AT Protocol conventions:

- All records are stored in user repositories
- DIDs are used for all identity references
- Blobs use standard AT Protocol blob storage
- Pagination uses cursor-based patterns
- Timestamps use ISO 8601 format

## License

MIT License - See LICENSE file for details

## References

- [MLS RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)
- [AT Protocol Specifications](https://atproto.com/specs)
- [Lexicon Documentation](https://atproto.com/specs/lexicon)
