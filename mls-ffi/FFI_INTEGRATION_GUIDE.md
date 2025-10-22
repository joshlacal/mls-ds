# MLS FFI Integration Guide

## Overview

This document provides comprehensive guidance for integrating the MLS (Messaging Layer Security) FFI library into iOS applications. The FFI layer provides a C-compatible interface designed for maximum safety and ease of use.

## Current Implementation Status

### ✅ Fully Implemented

- **Context Management**: Thread-safe initialization and cleanup
- **Memory Management**: Proper allocation/deallocation with explicit cleanup
- **Error Handling**: Comprehensive error types and FFI-safe error propagation
- **Type Safety**: C-compatible structures with clear ownership semantics
- **Test Suite**: Comprehensive tests for all implemented functionality
- **Build System**: Multi-platform iOS build support
- **Documentation**: Complete API reference and examples

### 🚧 Pending Full OpenMLS Integration

The following functions have placeholder implementations and require complete OpenMLS integration:

- `mls_add_members`: Full commit/welcome message generation
- `mls_encrypt_message`: Group message encryption
- `mls_decrypt_message`: Message decryption and validation
- `mls_process_welcome`: Welcome message processing

The FFI structure is complete and ready - only the OpenMLS-specific implementations need to be added.

## Architecture

### Component Overview

```
┌─────────────────────────────────────┐
│         iOS Application             │
│     (Swift/Objective-C Code)        │
└──────────────┬──────────────────────┘
               │ C FFI Boundary
┌──────────────▼──────────────────────┐
│      FFI Layer (ffi.rs)             │
│  • Parameter validation             │
│  • Memory management                │
│  • Error handling                   │
│  • Thread-safe context access       │
└──────────────┬──────────────────────┘
               │ Rust Internal API
┌──────────────▼──────────────────────┐
│    Context Management               │
│  • Group storage                    │
│  • Credential management            │
│  • Thread synchronization           │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│    OpenMLS (To Be Integrated)       │
│  • MLS protocol implementation      │
│  • Cryptographic operations         │
└─────────────────────────────────────┘
```

### Key Components

1. **FFI Layer** (`src/ffi.rs`)
   - C-compatible function exports
   - Parameter validation and conversion
   - Memory ownership transfer
   - Error propagation

2. **Context Management** (`src/mls_context.rs`)
   - Thread-safe context storage
   - Group lifecycle management
   - Future: Credential and key management

3. **Error Handling** (`src/error.rs`)
   - Comprehensive error types
   - FFI-safe error messages
   - Conversion to C strings

4. **Tests** (`src/tests.rs`)
   - Unit tests for all functions
   - Memory leak detection
   - Error handling verification

### Thread Safety

The FFI layer achieves thread safety through:

- **Global Context Storage**: `Arc<Mutex<HashMap<usize, Arc<MLSContext>>>>`
  - Each context is independently lockable
  - Contexts can be safely shared across threads
  - Atomic context ID generation prevents collisions

- **Per-Context Locking**: Each `MLSContext` has its own internal locks
  - Group operations don't block other contexts
  - Fine-grained locking minimizes contention

- **No Global Mutable State**: All state is either immutable or behind locks

### Memory Management

#### Ownership Rules

1. **Rust Allocates, Caller Frees**
   - All data returned to C is heap-allocated by Rust
   - Caller must explicitly free using provided functions
   - No automatic cleanup - explicit resource management required

2. **Input Parameters**
   - Borrowed for the duration of the call
   - Not freed by Rust
   - Must remain valid for the call duration

3. **Return Values**
   - Ownership transfers to caller
   - Must be freed with appropriate function
   - Contains both data and metadata for proper cleanup

#### Memory Lifecycle

```c
// 1. Initialize context (allocates)
uintptr_t ctx = mls_init();

// 2. Call function (allocates result)
struct MLSResult result = mls_create_group(ctx, identity, id_len);

// 3. Use data
if (result.success) {
    // result.data is valid here
    process_data(result.data, result.data_len);
}

// 4. Free result (deallocates)
mls_free_result(result);

// 5. Free context (deallocates)
mls_free_context(ctx);
```

## Building

### Prerequisites

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Add iOS targets
rustup target add aarch64-apple-ios          # iOS device
rustup target add x86_64-apple-ios           # iOS simulator (Intel)
rustup target add aarch64-apple-ios-sim      # iOS simulator (Apple Silicon)

# Install cbindgen (for header generation)
cargo install cbindgen
```

### Build Commands

```bash
# Quick build for current platform
cargo build --release

# Build for all iOS platforms
./build_all.sh

# Build for specific target
cargo build --release --target aarch64-apple-ios

# Generate C header (automatic during build)
cargo build

# Run tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Check for compilation errors without building
cargo check
```

### Build Output

After building, you'll find:

```
target/
├── aarch64-apple-ios/
│   └── release/
│       └── libmls_ffi.a          # iOS device library
├── x86_64-apple-ios/
│   └── release/
│       └── libmls_ffi.a          # iOS simulator (Intel) library
└── aarch64-apple-ios-sim/
    └── release/
        └── libmls_ffi.a          # iOS simulator (ARM64) library

include/
└── mls_ffi.h                     # C header file

build/ios/                        # Created by build_all.sh
├── libmls_ffi_aarch64-apple-ios.a
├── libmls_ffi_x86_64-apple-ios.a
├── libmls_ffi_aarch64-apple-ios-sim.a
└── mls_ffi.h
```

## C API Reference

### Core Types

#### `MLSResult`

```c
typedef struct MLSResult {
    bool success;           // true if operation succeeded
    char *error_message;    // error description (if success == false)
    uint8_t *data;         // result data (if success == true)
    uintptr_t data_len;    // length of data in bytes
} MLSResult;
```

**Memory Management:**
- If `success == true`: `data` contains result, must be freed
- If `success == false`: `error_message` contains error, must be freed
- **Always** call `mls_free_result()` regardless of success/failure

### Initialization Functions

#### `mls_init`

```c
uintptr_t mls_init(void);
```

Initialize an MLS context.

**Returns:**
- Non-zero context ID on success
- 0 on failure

**Example:**
```c
uintptr_t context_id = mls_init();
if (context_id == 0) {
    fprintf(stderr, "Failed to initialize MLS\n");
    return -1;
}
```

**Thread Safety:** Yes - can be called from multiple threads

**Memory:** Allocates context - must call `mls_free_context()` when done

#### `mls_free_context`

```c
void mls_free_context(uintptr_t context_id);
```

Free an MLS context and all associated resources.

**Parameters:**
- `context_id`: Context handle from `mls_init()`

---

### Group Management

#### `mls_create_group`

```c
MLSResult mls_create_group(
    usize context_id,
    const uint8_t* identity_bytes,
    usize identity_len
);
```

Create a new MLS group.

**Parameters:**
- `context_id`: Context handle
- `identity_bytes`: User identity (email, user ID, etc.)
- `identity_len`: Length of identity

**Returns:** `MLSResult` containing group ID

**Example:**
```c
const char* identity = "alice@example.com";
MLSResult result = mls_create_group(
    context_id,
    (const uint8_t*)identity,
    strlen(identity)
);

if (result.success) {
    uint8_t* group_id = result.data;
    size_t group_id_len = result.data_len;
    // Use group_id...
    mls_free_result(result);
} else {
    fprintf(stderr, "Error: %s\n", result.error_message);
    mls_free_result(result);
}
```

#### `mls_add_members`

```c
MLSResult mls_add_members(
    usize context_id,
    const uint8_t* group_id,
    usize group_id_len,
    const uint8_t* key_packages_bytes,
    usize key_packages_len
);
```

Add members to an existing group.

**Parameters:**
- `context_id`: Context handle
- `group_id`: Group identifier
- `group_id_len`: Length of group ID
- `key_packages_bytes`: JSON array of serialized KeyPackages
- `key_packages_len`: Length of key packages data

**Returns:** `MLSResult` containing JSON with `commit` and `welcome` fields

**Example:**
```c
// Assume key_packages_json contains serialized KeyPackages
MLSResult result = mls_add_members(
    context_id,
    group_id,
    group_id_len,
    (const uint8_t*)key_packages_json,
    strlen(key_packages_json)
);

if (result.success) {
    // Parse JSON to extract commit and welcome messages
    // Send commit to group, welcome to new members
    mls_free_result(result);
}
```

#### `mls_get_epoch`

```c
uint64_t mls_get_epoch(
    usize context_id,
    const uint8_t* group_id,
    usize group_id_len
);
```

Get the current epoch number of a group.

**Returns:** Epoch number (0 on error)

---

### Key Package Management

#### `mls_create_key_package`

```c
MLSResult mls_create_key_package(
    usize context_id,
    const uint8_t* identity_bytes,
    usize identity_len
);
```

Create a key package for joining groups.

**Returns:** `MLSResult` containing serialized KeyPackage

**Example:**
```c
const char* identity = "bob@example.com";
MLSResult result = mls_create_key_package(
    context_id,
    (const uint8_t*)identity,
    strlen(identity)
);

if (result.success) {
    // Upload key package to server
    upload_key_package(result.data, result.data_len);
    mls_free_result(result);
}
```

#### `mls_process_welcome`

```c
MLSResult mls_process_welcome(
    usize context_id,
    const uint8_t* welcome_bytes,
    usize welcome_len,
    const uint8_t* identity_bytes,
    usize identity_len
);
```

Process a Welcome message to join a group.

**Returns:** `MLSResult` containing group ID

---

### Message Encryption/Decryption

#### `mls_encrypt_message`

```c
MLSResult mls_encrypt_message(
    usize context_id,
    const uint8_t* group_id,
    usize group_id_len,
    const uint8_t* plaintext,
    usize plaintext_len
);
```

Encrypt a message for the group.

**Returns:** `MLSResult` containing ciphertext

**Example:**
```c
const char* message = "Hello, World!";
MLSResult result = mls_encrypt_message(
    context_id,
    group_id,
    group_id_len,
    (const uint8_t*)message,
    strlen(message)
);

if (result.success) {
    send_to_group(result.data, result.data_len);
    mls_free_result(result);
}
```

#### `mls_decrypt_message`

```c
MLSResult mls_decrypt_message(
    usize context_id,
    const uint8_t* group_id,
    usize group_id_len,
    const uint8_t* ciphertext,
    usize ciphertext_len
);
```

Decrypt a message from the group.

**Returns:** `MLSResult` containing plaintext

---

### Advanced Features

#### `mls_export_secret`

```c
MLSResult mls_export_secret(
    usize context_id,
    const uint8_t* group_id,
    usize group_id_len,
    const char* label,
    const uint8_t* context_bytes,
    usize context_len,
    usize key_length
);
```

Export a secret from the group's key schedule for application-specific use.

**Parameters:**
- `label`: ASCII label for the exported secret
- `context_bytes`: Additional context data
- `key_length`: Desired length of exported secret

**Example:**
```c
MLSResult result = mls_export_secret(
    context_id,
    group_id,
    group_id_len,
    "encryption-key",
    (const uint8_t*)"v1",
    2,
    32  // 256 bits
);

if (result.success) {
    // Use the exported secret
    use_key(result.data, result.data_len);
    mls_free_result(result);
}
```

---

### Memory Management

#### `mls_free_result`

```c
void mls_free_result(MLSResult result);
```

Free memory associated with an `MLSResult`.

**Important:** Always call this after processing a result.

#### `mls_free_string`

```c
void mls_free_string(char* s);
```

Free a C string allocated by the library.

---

## Data Types

### `MLSResult`

```c
typedef struct {
    bool success;
    char* error_message;
    uint8_t* data;
    size_t data_len;
} MLSResult;
```

- `success`: `true` if operation succeeded
- `error_message`: NULL on success, error string on failure
- `data`: Result data (NULL on failure)
- `data_len`: Length of data in bytes

---

## iOS Integration

### Xcode Setup

1. **Add Static Library:**
   - Drag `libmls_ffi.a` into your Xcode project
   - Add to "Link Binary With Libraries" build phase

2. **Add Header:**
   - Add `mls_ffi.h` to your project
   - Create a bridging header for Swift projects

3. **Configure Build Settings:**
   ```
   Library Search Paths: $(PROJECT_DIR)/path/to/lib
   Header Search Paths: $(PROJECT_DIR)/path/to/include
   ```

### Swift Bridging

Create `mls_ffi-Bridging-Header.h`:

```objc
#ifndef MLS_FFI_BRIDGING_HEADER_H
#define MLS_FFI_BRIDGING_HEADER_H

#include "mls_ffi.h"

#endif
```

### Swift Wrapper Example

```swift
import Foundation

class MLSManager {
    private var contextId: UInt
    
    init?() {
        let id = mls_init()
        guard id != 0 else { return nil }
        self.contextId = id
    }
    
    deinit {
        mls_free_context(contextId)
    }
    
    func createGroup(identity: String) -> Data? {
        let identityData = identity.data(using: .utf8)!
        let result = identityData.withUnsafeBytes { buffer in
            mls_create_group(
                contextId,
                buffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                buffer.count
            )
        }
        
        defer { mls_free_result(result) }
        
        guard result.success else {
            if let errorMsg = result.error_message {
                print("Error: \(String(cString: errorMsg))")
            }
            return nil
        }
        
        return Data(bytes: result.data, count: result.data_len)
    }
    
    func encryptMessage(groupId: Data, message: String) -> Data? {
        let messageData = message.data(using: .utf8)!
        
        let result = groupId.withUnsafeBytes { groupBuffer in
            messageData.withUnsafeBytes { msgBuffer in
                mls_encrypt_message(
                    contextId,
                    groupBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    groupBuffer.count,
                    msgBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    msgBuffer.count
                )
            }
        }
        
        defer { mls_free_result(result) }
        
        guard result.success else { return nil }
        return Data(bytes: result.data, count: result.data_len)
    }
    
    func decryptMessage(groupId: Data, ciphertext: Data) -> String? {
        let result = groupId.withUnsafeBytes { groupBuffer in
            ciphertext.withUnsafeBytes { ctBuffer in
                mls_decrypt_message(
                    contextId,
                    groupBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    groupBuffer.count,
                    ctBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    ctBuffer.count
                )
            }
        }
        
        defer { mls_free_result(result) }
        
        guard result.success else { return nil }
        let data = Data(bytes: result.data, count: result.data_len)
        return String(data: data, encoding: .utf8)
    }
}
```

### Objective-C Wrapper Example

```objc
#import "MLSManager.h"
#import "mls_ffi.h"

@interface MLSManager ()
@property (nonatomic, assign) uintptr_t contextId;
@end

@implementation MLSManager

- (instancetype)init {
    self = [super init];
    if (self) {
        _contextId = mls_init();
        if (_contextId == 0) {
            return nil;
        }
    }
    return self;
}

- (void)dealloc {
    if (_contextId != 0) {
        mls_free_context(_contextId);
    }
}

- (NSData *)createGroupWithIdentity:(NSString *)identity error:(NSError **)error {
    const char *identityCStr = [identity UTF8String];
    MLSResult result = mls_create_group(
        self.contextId,
        (const uint8_t *)identityCStr,
        strlen(identityCStr)
    );
    
    NSData *groupId = nil;
    
    if (result.success) {
        groupId = [NSData dataWithBytes:result.data length:result.data_len];
    } else if (error) {
        NSString *errorMsg = [NSString stringWithUTF8String:result.error_message];
        *error = [NSError errorWithDomain:@"MLSError"
                                     code:-1
                                 userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
    }
    
    mls_free_result(result);
    return groupId;
}

- (NSData *)encryptMessage:(NSString *)message
                   groupId:(NSData *)groupId
                     error:(NSError **)error {
    const char *msgCStr = [message UTF8String];
    MLSResult result = mls_encrypt_message(
        self.contextId,
        groupId.bytes,
        groupId.length,
        (const uint8_t *)msgCStr,
        strlen(msgCStr)
    );
    
    NSData *ciphertext = nil;
    
    if (result.success) {
        ciphertext = [NSData dataWithBytes:result.data length:result.data_len];
    } else if (error) {
        NSString *errorMsg = [NSString stringWithUTF8String:result.error_message];
        *error = [NSError errorWithDomain:@"MLSError"
                                     code:-1
                                 userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
    }
    
    mls_free_result(result);
    return ciphertext;
}

@end
```

---

## Error Handling

### Error Types

All errors are returned through `MLSResult.error_message`. Common error types:

- **Null pointer errors**: Invalid input pointers
- **Invalid context**: Context ID doesn't exist
- **OpenMLS errors**: Core MLS protocol errors
- **Serialization errors**: Data encoding/decoding failures
- **Thread safety errors**: Lock acquisition failures
- **Memory allocation errors**: Out of memory conditions

### Best Practices

1. **Always check `result.success`** before accessing data
2. **Log error messages** for debugging
3. **Call `mls_free_result()`** even on errors
4. **Handle context initialization failure** (returns 0)
5. **Validate input data** before passing to FFI

---

## Performance Considerations

### Memory Usage

- Each context maintains its own state
- Groups are stored in memory (consider persistence for production)
- Key packages and credentials are cached per context

### Concurrency

- Multiple contexts can be used from different threads
- Single context operations are serialized via Mutex
- Consider using separate contexts per thread for better parallelism

### Optimization Tips

1. **Reuse contexts** across multiple operations
2. **Batch operations** when possible (e.g., adding multiple members)
3. **Profile memory usage** in production
4. **Consider implementing persistence** for large group counts

---

## Security Considerations

### Key Management

- Credentials are stored in-memory only
- No automatic key rotation (implement at application level)
- Export secrets carefully (proper key derivation)

### Best Practices

1. **Clear sensitive data** when done
2. **Use secure storage** for persistence
3. **Validate all inputs** from untrusted sources
4. **Implement proper access control**
5. **Use TLS for network transport**
6. **Regular security audits**

---

## Troubleshooting

### Common Issues

**Issue:** `mls_init()` returns 0
- **Solution:** Check system resources, restart application

**Issue:** Group operations fail after app restart
- **Solution:** Implement persistence (groups are in-memory only)

**Issue:** Memory leaks detected
- **Solution:** Ensure all `MLSResult` objects are freed with `mls_free_result()`

**Issue:** Thread safety violations
- **Solution:** Don't share context IDs across threads unsafely

### Debugging

Enable Rust logging:
```bash
RUST_LOG=debug cargo test
```

Build with debug symbols:
```bash
cargo build --target aarch64-apple-ios
```

---

## Testing

### Run Rust Tests

```bash
cargo test
```

### iOS Integration Tests

Create XCTest targets that exercise the FFI layer from Swift/Objective-C.

Example test:
```swift
func testMLSEncryption() {
    guard let manager = MLSManager() else {
        XCTFail("Failed to initialize MLS")
        return
    }
    
    let identity = "test@example.com"
    guard let groupId = manager.createGroup(identity: identity) else {
        XCTFail("Failed to create group")
        return
    }
    
    let message = "Test message"
    guard let ciphertext = manager.encryptMessage(groupId: groupId, message: message) else {
        XCTFail("Failed to encrypt")
        return
    }
    
    guard let decrypted = manager.decryptMessage(groupId: groupId, ciphertext: ciphertext) else {
        XCTFail("Failed to decrypt")
        return
    }
    
    XCTAssertEqual(decrypted, message)
}
```

---

## Future Enhancements

### Planned Features

1. **Persistence Layer**: Save/restore groups from storage
2. **Key Package Store**: External key package management
3. **Delivery Service**: Built-in message delivery
4. **Advanced Proposals**: Remove members, update keys
5. **External Commits**: Support for server-side operations
6. **PSK Support**: Pre-shared key integration

### Contribution Guidelines

See the main project README for contribution guidelines.

---

## Support

For issues or questions:
- GitHub Issues: [Project Repository]
- Email: [Support Email]
- Documentation: [Project Docs]

---

## License

MIT License - See LICENSE file for details.
