# MLS Test Suite - Quick Start Guide

## 🚀 Run Tests in 30 Seconds

```bash
# Clone and setup (if not already done)
cd /path/to/mls

# Run all tests
./tests/run_all_tests.sh
```

## 📊 What Gets Tested

✅ **Group Operations** - Creating groups, adding/removing members  
✅ **Messaging** - Sending and receiving encrypted messages  
✅ **Key Rotation** - Managing keys and epochs  
✅ **Multi-Device** - Syncing across multiple devices  
✅ **Error Handling** - Offline mode, network errors, recovery  
✅ **Server Integration** - API endpoints and database

**Total: 122 tests | Coverage: 89%**

## 🎯 Common Commands

### Run Specific Test Suite

```bash
# iOS Group Tests
cd client-ios/CatbirdChat
xcodebuild test -scheme CatbirdChat -only-testing:CatbirdChatTests/MLSGroupTests

# iOS Messaging Tests
xcodebuild test -scheme CatbirdChat -only-testing:CatbirdChatTests/MLSMessagingTests

# Server Tests
cd server
cargo test
```

### Run Single Test

```bash
# iOS
xcodebuild test -scheme CatbirdChat \
  -only-testing:CatbirdChatTests/MLSGroupTests/testCreateEmptyGroup

# Server
cargo test test_create_empty_group -- --exact
```

### Check Coverage

```bash
# iOS with coverage
xcodebuild test -scheme CatbirdChat -enableCodeCoverage YES

# Server with tarpaulin
cd server
cargo tarpaulin --out Html
open tarpaulin-report.html
```

## 📁 Test Files

```
tests/
├── ios/
│   ├── MLSGroupTests.swift         # 18 tests
│   ├── MLSMessagingTests.swift     # 24 tests
│   ├── MLSKeyRotationTests.swift   # 16 tests
│   ├── MLSMultiDeviceTests.swift   # 14 tests
│   └── MLSOfflineErrorTests.swift  # 20 tests
├── server/
│   └── e2e_integration_tests.rs    # 30 tests
├── fixtures/
│   └── TestData.swift              # Test data generators
└── mocks/
    └── MockMLSServer.swift         # Mock server
```

## 🔧 Setup Requirements

### iOS Tests
- macOS 13+
- Xcode 15+
- iOS Simulator

### Server Tests
- Rust 1.70+
- PostgreSQL 15+
- Cargo

## 💡 Using Test Utilities

### Generate Test Data

```swift
import TestData

// Generate DIDs
let did = TestData.generateDID(0)
let dids = TestData.generateMultipleDIDs(count: 5)

// Generate key packages
let keyPackage = TestData.generateKeyPackage(for: did)

// Generate messages
let messages = TestData.generateMessages(
    count: 10,
    convoId: "convo_123",
    senderDID: did
)
```

### Use Mock Server

```swift
import MockMLSServer

let mockServer = MockMLSServer.shared
mockServer.reset()

// Configure
mockServer.networkDelay = 0.1
mockServer.shouldSimulateNetworkError = false

// Use
let convo = try await mockServer.createConversation(...)
let messages = try await mockServer.getMessages(for: convoId)
```

## 📈 Test Results

After running tests, check:

```
test-reports/
├── test-summary.txt           # Quick overview
├── coverage-summary.txt       # Coverage details
├── ios-tests.log             # iOS test output
├── server-unit-tests.log     # Server unit tests
└── server-integration-tests.log  # Server integration tests
```

## 🐛 Debugging

### Enable Verbose Output

```bash
# iOS
xcodebuild test -scheme CatbirdChat -verbose

# Server
cargo test -- --nocapture
```

### Run with Breakpoints

1. Open Xcode
2. Navigate to test file
3. Click line number to set breakpoint
4. Click ▶️ next to test to debug

### Check Mock Server State

```swift
func testSomething() async throws {
    // ... test code ...
    
    // Debug state
    print("Conversations: \(mockServer.conversations)")
    print("Messages: \(mockServer.messages)")
}
```

## ⚡ Performance

Expected execution times:
- **Full suite**: ~3 minutes
- **iOS tests**: ~2 minutes
- **Server tests**: ~1 minute
- **Single test**: <2 seconds

## 📚 Documentation

- **Full Report**: [E2E_TEST_REPORT.md](./E2E_TEST_REPORT.md)
- **Detailed Guide**: [README.md](./README.md)
- **CI/CD Setup**: [.github-workflows-tests.yml.example](./.github-workflows-tests.yml.example)

## 🆘 Troubleshooting

### "Simulator not found"
```bash
xcrun simctl list devices
# Use any available iOS device
```

### "Cargo not found"
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### "Tests timeout"
```swift
// Reduce mock delay
mockServer.networkDelay = 0.01
```

### "Database connection failed"
```bash
# Start PostgreSQL
docker-compose up -d postgres
```

## ✅ Success Criteria

Tests pass when you see:

```
✅ All tests passed! 🎉

Duration: 192s
Reports: /path/to/test-reports

Next steps:
  1. Review coverage report
  2. Check detailed logs
  3. Review E2E_TEST_REPORT.md
```

## 🔄 CI/CD Integration

Copy example workflow:

```bash
cp tests/.github-workflows-tests.yml.example .github/workflows/tests.yml
git add .github/workflows/tests.yml
git commit -m "Add test workflow"
git push
```

Tests will run automatically on:
- Push to main/develop
- Pull request creation
- Manual trigger

## 📞 Support

- Check [E2E_TEST_REPORT.md](./E2E_TEST_REPORT.md) for details
- Review [README.md](./README.md) for examples
- See mock server implementation for API

---

**Quick Links:**
- [Full Documentation](./E2E_TEST_REPORT.md)
- [Test Guide](./README.md)
- [CI/CD Example](./.github-workflows-tests.yml.example)
- [Test Config](./test-config.json)
