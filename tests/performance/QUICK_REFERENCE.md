# Performance Testing Quick Reference

## Quick Start

```bash
# Run all performance tests
./tests/performance/run_performance_tests.sh

# Run with Instruments profiling
./tests/performance/run_instruments.sh
```

## Common Commands

### Run Specific Test Suite

```bash
# Core encryption tests
xcodebuild test -scheme CatbirdChat \
  -destination 'platform=iOS Simulator,name=iPhone 14 Pro' \
  -only-testing:CatbirdChatTests/MLSPerformanceTests

# Large group tests
xcodebuild test -scheme CatbirdChat \
  -destination 'platform=iOS Simulator,name=iPhone 14 Pro' \
  -only-testing:CatbirdChatTests/MLSLargeGroupPerformanceTests

# App launch tests
xcodebuild test -scheme CatbirdChat \
  -destination 'platform=iOS Simulator,name=iPhone 14 Pro' \
  -only-testing:CatbirdChatTests/MLSAppLaunchPerformanceTests

# Memory tests
xcodebuild test -scheme CatbirdChat \
  -destination 'platform=iOS Simulator,name=iPhone 14 Pro' \
  -only-testing:CatbirdChatTests/MLSMemoryPerformanceTests

# Network tests
xcodebuild test -scheme CatbirdChat \
  -destination 'platform=iOS Simulator,name=iPhone 14 Pro' \
  -only-testing:CatbirdChatTests/MLSNetworkPerformanceTests

# Database tests
xcodebuild test -scheme CatbirdChat \
  -destination 'platform=iOS Simulator,name=iPhone 14 Pro' \
  -only-testing:CatbirdChatTests/MLSDatabasePerformanceTests

# Battery tests
xcodebuild test -scheme CatbirdChat \
  -destination 'platform=iOS Simulator,name=iPhone 14 Pro' \
  -only-testing:CatbirdChatTests/MLSBatteryPerformanceTests
```

### Run on Physical Device

```bash
xcodebuild test -scheme CatbirdChat \
  -destination 'platform=iOS,name=Your iPhone' \
  -only-testing:CatbirdChatTests/MLSBatteryPerformanceTests
```

## Keyboard Shortcuts (Xcode)

| Action | Shortcut |
|--------|----------|
| Run all tests | ⌘U |
| Run last test | ⌃⌥⌘G |
| Test Navigator | ⌘6 |
| Profile (Instruments) | ⌘I |
| Stop running test | ⌘. |

## Performance Targets

| Metric | Target | Acceptable | Critical |
|--------|--------|------------|----------|
| Message encrypt (<1KB) | <5ms | <10ms | >20ms |
| Message decrypt (<1KB) | <5ms | <10ms | >20ms |
| Group creation | <100ms | <200ms | >500ms |
| Add member (100+ group) | <200ms | <400ms | >1000ms |
| App cold launch | <500ms | <1000ms | >2000ms |
| Memory per group | <100KB | <250KB | >500KB |
| Battery (1hr active) | <5% | <8% | >15% |

## Instruments Templates

| Template | Use Case | Duration |
|----------|----------|----------|
| Time Profiler | CPU usage, hot paths | 30s |
| Allocations | Memory usage, growth | 30s |
| Leaks | Memory leak detection | 30s |
| Energy Log | Battery impact | 60s |
| Network | Bandwidth, requests | 30s |
| System Trace | Overall performance | 30s |

## Common Issues & Solutions

### Test Timeout
```swift
// Increase timeout
wait(for: [expectation], timeout: 60.0)
```

### Inconsistent Results
```bash
# Reset simulator
xcrun simctl shutdown all
xcrun simctl erase all
```

### Memory Warnings
```swift
// Use autoreleasepool
autoreleasepool {
    // Your test code
}
```

### Instruments Won't Attach
```bash
# Clean derived data
rm -rf ~/Library/Developer/Xcode/DerivedData
killall Instruments Xcode
```

## Reading Results

### XCTest Metrics
- **Average:** Mean value across iterations
- **Min/Max:** Performance range
- **Std Dev:** Consistency (lower is better)
- **Baseline:** Reference for comparison

### Regression Indicators
- 🟢 Green: Within 10% of baseline
- 🟡 Yellow: 10-20% slower than baseline
- 🔴 Red: >20% slower than baseline

## File Locations

```
tests/performance/
├── MLSPerformanceTests.swift              # Core encryption tests
├── MLSLargeGroupPerformanceTests.swift    # Large group tests
├── MLSAppLaunchPerformanceTests.swift     # Launch time tests
├── MLSMemoryPerformanceTests.swift        # Memory tests
├── MLSNetworkPerformanceTests.swift       # Network tests
├── MLSDatabasePerformanceTests.swift      # Database tests
├── MLSBatteryPerformanceTests.swift       # Battery tests
├── TestHelpers.swift                      # Mock classes
├── README.md                              # Full documentation
├── SETUP_GUIDE.md                         # Setup instructions
├── QUICK_REFERENCE.md                     # This file
├── run_performance_tests.sh               # Run all tests
└── run_instruments.sh                     # Run Instruments

PERFORMANCE_REPORT.md                      # Detailed report & recommendations
```

## Next Steps After Running Tests

1. ✅ Compare results to targets in PERFORMANCE_REPORT.md
2. ✅ Profile with Instruments if any tests fail
3. ✅ Document any regressions
4. ✅ Implement optimizations from report
5. ✅ Set baseline for future comparisons
6. ✅ Set up CI/CD integration

## Resources

- Full Documentation: [README.md](./README.md)
- Setup Guide: [SETUP_GUIDE.md](./SETUP_GUIDE.md)
- Performance Report: [PERFORMANCE_REPORT.md](../PERFORMANCE_REPORT.md)
- Apple Docs: https://developer.apple.com/documentation/xctest/performance_testing
