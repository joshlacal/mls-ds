# Catbird iOS Client

End-to-end encrypted group chat client using MLS.

## Features

- MLS 1.0 E2EE via Rust FFI
- AT Protocol DID identity
- Secure key storage (Keychain)
- Real-time message sync
- Encrypted attachments

## Requirements

- iOS 17.0+
- Xcode 15.0+
- Swift 5.9+

## Setup

1. Build MLS FFI library:
```bash
cd ../mls-ffi
cargo build --release --target aarch64-apple-ios
```

2. Open in Xcode:
```bash
open CatbirdChat.xcodeproj
```

3. Configure server endpoint in `Config.swift`

## Architecture

```
SwiftUI Views
    ↓
ViewModels
    ↓
CatbirdClient (Network)
    ↓
MLSManager (FFI Bridge)
    ↓
Rust MLS Library
```

## Key Components

- `MLSManager.swift` - FFI bridge to Rust MLS library
- `CatbirdClient.swift` - Network API client
- `KeychainManager.swift` - Secure key storage
- `ConversationView.swift` - Chat UI
- `MessageStore.swift` - Local message persistence

## Security Notes

- Private keys stored in iOS Keychain
- MLS group state encrypted on disk
- No plaintext in logs
- Memory cleared after sensitive operations
