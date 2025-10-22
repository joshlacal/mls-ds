# MLS E2E Test Suite - Quick Index

**Quick Links:** [Test Report](E2E_TEST_REPORT.md) | [README](README.md) | [Quick Start](QUICK_START.md) | [Implementation Summary](IMPLEMENTATION_SUMMARY.md)

---

## 🎯 I Want To...

### Run Tests
- **Run everything**: `./run_all_tests.sh`
- **iOS only**: See [QUICK_START.md](QUICK_START.md#run-specific-test-suite)
- **Server only**: `cd server && cargo test`
- **Single test**: See [README.md](README.md#run-specific-test-suite)

### Understand the Tests
- **Overview**: Read [E2E_TEST_REPORT.md](E2E_TEST_REPORT.md#executive-summary)
- **Test scenarios**: See [E2E_TEST_REPORT.md](E2E_TEST_REPORT.md#test-scenarios)
- **Coverage metrics**: See [E2E_TEST_REPORT.md](E2E_TEST_REPORT.md#success-metrics)

### Write New Tests
- **Test template**: See [README.md](README.md#writing-new-tests)
- **Use test data**: See [README.md](README.md#test-utilities)
- **Use mock server**: See [README.md](README.md#mockmslserver)

### Debug Tests
- **Troubleshooting**: See [README.md](README.md#troubleshooting)
- **Debugging guide**: See [README.md](README.md#debugging-tests)
- **Common issues**: See [QUICK_START.md](QUICK_START.md#troubleshooting)

### Setup CI/CD
- **GitHub Actions**: Copy `.github-workflows-tests.yml.example`
- **Integration guide**: See [README.md](README.md#cicd-integration)
- **Example workflow**: See [E2E_TEST_REPORT.md](E2E_TEST_REPORT.md#continuous-integration)

---

## 📂 File Navigator

### Test Suites
| File | Tests | Description |
|------|-------|-------------|
| [ios/MLSGroupTests.swift](ios/MLSGroupTests.swift) | 18 | Group creation, members |
| [ios/MLSMessagingTests.swift](ios/MLSMessagingTests.swift) | 24 | Send/receive messages |
| [ios/MLSKeyRotationTests.swift](ios/MLSKeyRotationTests.swift) | 16 | Key rotation, epochs |
| [ios/MLSMultiDeviceTests.swift](ios/MLSMultiDeviceTests.swift) | 14 | Multi-device sync |
| [ios/MLSOfflineErrorTests.swift](ios/MLSOfflineErrorTests.swift) | 20 | Offline, error recovery |
| [server/e2e_integration_tests.rs](server/e2e_integration_tests.rs) | 30 | Server integration |

### Test Infrastructure
| File | Purpose |
|------|---------|
| [fixtures/TestData.swift](fixtures/TestData.swift) | Test data generators |
| [mocks/MockMLSServer.swift](mocks/MockMLSServer.swift) | Mock server |
| [run_all_tests.sh](run_all_tests.sh) | Test runner |
| [test-config.json](test-config.json) | Configuration |

### Documentation
| File | Content |
|------|---------|
| [E2E_TEST_REPORT.md](E2E_TEST_REPORT.md) | Comprehensive report (17KB) |
| [README.md](README.md) | Detailed guide (10KB) |
| [QUICK_START.md](QUICK_START.md) | Quick reference (5KB) |
| [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) | Implementation details (12KB) |
| [INDEX.md](INDEX.md) | This file |

---

## 📊 Test Coverage by Category

| Category | Tests | Coverage | File |
|----------|-------|----------|------|
| Group Operations | 18 | 95% | MLSGroupTests.swift |
| Messaging | 24 | 92% | MLSMessagingTests.swift |
| Key Rotation | 16 | 90% | MLSKeyRotationTests.swift |
| Multi-Device | 14 | 88% | MLSMultiDeviceTests.swift |
| Offline/Error | 20 | 93% | MLSOfflineErrorTests.swift |
| Server | 30 | 75% | e2e_integration_tests.rs |
| **Total** | **122** | **89%** | - |

---

## 🔍 Find Tests By Scenario

### Group Operations
- Create group: `MLSGroupTests.swift` lines 24-73
- Add members: `MLSGroupTests.swift` lines 77-141
- Remove members: `MLSGroupTests.swift` lines 145-183

### Messaging
- Send messages: `MLSMessagingTests.swift` lines 35-132
- Receive messages: `MLSMessagingTests.swift` lines 136-204
- Concurrent: `MLSMessagingTests.swift` lines 232-259

### Key Rotation
- Key packages: `MLSKeyRotationTests.swift` lines 24-86
- Epoch management: `MLSKeyRotationTests.swift` lines 90-170
- Rotation scenarios: `MLSKeyRotationTests.swift` lines 174-245

### Multi-Device
- Device setup: `MLSMultiDeviceTests.swift` lines 24-78
- Message sync: `MLSMultiDeviceTests.swift` lines 82-178
- State sync: `MLSMultiDeviceTests.swift` lines 235-310

### Error Handling
- Network errors: `MLSOfflineErrorTests.swift` lines 24-82
- Offline ops: `MLSOfflineErrorTests.swift` lines 86-150
- Recovery: `MLSOfflineErrorTests.swift` lines 154-230

---

## 🚀 Common Workflows

### First Time Setup
1. Read [QUICK_START.md](QUICK_START.md)
2. Run `./run_all_tests.sh`
3. Review reports in `test-reports/`

### Daily Development
1. Write code
2. Write/update tests
3. Run tests: `./run_all_tests.sh`
4. Check coverage

### Before Commit
1. Run full suite: `./run_all_tests.sh`
2. Verify coverage: Check `test-reports/coverage-summary.txt`
3. Fix any failures
4. Commit

### CI/CD Setup
1. Copy `.github-workflows-tests.yml.example` to `.github/workflows/`
2. Commit and push
3. Monitor workflow runs

---

## 💡 Tips & Best Practices

### Writing Tests
- Use `TestData` generators for consistency
- Use `MockMLSServer` for isolation
- Include both success and error cases
- Keep tests focused and atomic

### Debugging
- Enable verbose output: `xcodebuild test -verbose`
- Use breakpoints in Xcode
- Check mock server state
- Review detailed logs

### Performance
- Keep tests under 2 seconds
- Use parallel execution
- Mock expensive operations
- Profile slow tests

### Maintenance
- Review flaky tests monthly
- Update scenarios quarterly
- Refactor annually
- Monitor coverage trends

---

## 📞 Getting Help

### Documentation
- **Comprehensive**: [E2E_TEST_REPORT.md](E2E_TEST_REPORT.md)
- **Examples**: [README.md](README.md)
- **Quick Ref**: [QUICK_START.md](QUICK_START.md)

### Common Questions
- **How do I run tests?** → [QUICK_START.md](QUICK_START.md#-run-tests-in-30-seconds)
- **How do I write tests?** → [README.md](README.md#writing-new-tests)
- **How do I debug?** → [README.md](README.md#debugging-tests)
- **What's the coverage?** → [E2E_TEST_REPORT.md](E2E_TEST_REPORT.md#success-metrics)

### Support Resources
- Test examples in each suite file
- Mock server implementation
- Test data generator utilities
- CI/CD workflow templates

---

## ✅ Quick Status Check

**Test Suite:** 122 tests  
**Coverage:** 89%  
**Status:** ✅ Complete  
**Location:** `/Users/joshlacalamito/Developer/Catbird+Petrel/mls/tests/`

**Last Updated:** 2025-10-21

---

**Start Here:** [QUICK_START.md](QUICK_START.md) | **Full Docs:** [E2E_TEST_REPORT.md](E2E_TEST_REPORT.md)
