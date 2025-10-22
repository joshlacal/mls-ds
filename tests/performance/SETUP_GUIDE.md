# Performance Testing Setup Guide

## Prerequisites

### Required Tools

1. **Xcode 15.0+**
   - Download from Mac App Store or Apple Developer
   - Includes XCTest framework and Instruments

2. **Xcode Command Line Tools**
   ```bash
   xcode-select --install
   ```

3. **xcpretty** (Optional, for prettier output)
   ```bash
   gem install xcpretty
   ```

### Recommended Setup

1. **Simulator**
   - iPhone 14 Pro Simulator
   - iOS 17.0 or later
   - Sufficient disk space (5GB+)

2. **Physical Device** (for accurate battery/energy tests)
   - iPhone with iOS 17.0+
   - Development provisioning profile
   - Connected via USB

---

## Project Setup

### 1. Add Test Target to Xcode Project

If not already present, add a test target:

1. Open project in Xcode
2. File > New > Target
3. Choose "Unit Testing Bundle"
4. Name it "CatbirdChatTests"
5. Add to your app target

### 2. Add Performance Test Files

```bash
# From the repository root
cd /Users/joshlacalamito/Developer/Catbird+Petrel/mls

# Ensure test files are in the project
ls tests/performance/

# Expected files:
# - MLSPerformanceTests.swift
# - MLSLargeGroupPerformanceTests.swift
# - MLSAppLaunchPerformanceTests.swift
# - MLSMemoryPerformanceTests.swift
# - MLSNetworkPerformanceTests.swift
# - MLSDatabasePerformanceTests.swift
# - MLSBatteryPerformanceTests.swift
# - TestHelpers.swift
```

### 3. Add Test Files to Xcode

1. Right-click on your test target in Project Navigator
2. Select "Add Files to [YourProject]"
3. Navigate to `tests/performance/`
4. Select all `.swift` files
5. Ensure "Copy items if needed" is checked
6. Add to your test target

### 4. Configure Test Target

In your test target's Build Settings:

```
SWIFT_VERSION = 5.9
IPHONEOS_DEPLOYMENT_TARGET = 17.0
ENABLE_TESTABILITY = YES
```

In your app target's Build Settings:

```
ENABLE_TESTABILITY = YES
```

---

## Running Tests

### Method 1: Xcode GUI

1. **Open Test Navigator** (⌘6)
2. **Select test class or individual test**
3. **Click the play button** next to the test
4. **View results** in Test Navigator

### Method 2: Keyboard Shortcuts

- **Run all tests:** ⌘U
- **Run last test:** ⌃⌥⌘G
- **Show Test Navigator:** ⌘6

### Method 3: Command Line

```bash
# Make scripts executable
chmod +x tests/performance/run_performance_tests.sh
chmod +x tests/performance/run_instruments.sh

# Run all performance tests
./tests/performance/run_performance_tests.sh

# Run specific test class
xcodebuild test \
  -scheme CatbirdChat \
  -destination 'platform=iOS Simulator,name=iPhone 14 Pro' \
  -only-testing:CatbirdChatTests/MLSPerformanceTests
```

---

## Using Instruments

### Launch from Xcode

1. **Product > Profile** (⌘I)
2. **Select profiling template:**
   - Time Profiler (CPU)
   - Allocations (Memory)
   - Leaks (Memory leaks)
   - Energy Log (Battery)
   - Network (Network activity)
   - System Trace (All)
3. **Click Record** to start profiling
4. **Exercise the app** or run tests
5. **Stop recording** to analyze

### Using the Script

```bash
# Interactive menu
./tests/performance/run_instruments.sh

# Select option:
# 1. Time Profiler
# 2. Allocations
# 3. Leaks
# 4. Energy Log
# 5. Network
# 6. System Trace
# 7. All
```

---

## Interpreting Results

### XCTest Performance Results

#### In Xcode

1. Open Test Navigator (⌘6)
2. Click on a performance test
3. View metrics in the editor:
   - **Clock Time:** Execution duration
   - **Memory:** Peak memory usage
   - **CPU:** CPU cycles used
   - **Storage:** Disk I/O

4. Set baseline:
   - Click "Set Baseline" in test results
   - Future runs will compare against this

5. View trends:
   - Click "Edit" on a performance test
   - View graph of performance over time

#### Via xcresulttool

```bash
# Extract results to JSON
xcresulttool get \
  --path TestResults.xcresult \
  --format json > results.json

# View specific metrics
xcresulttool get \
  --path TestResults.xcresult \
  --format json | jq '.metrics'
```

### Instruments Analysis

#### Time Profiler

**Look for:**
- Functions consuming > 5% CPU time
- Unexpected hot paths
- Long-running functions

**Actions:**
- Click on function to see call tree
- Use "Heaviest Stack Trace" to find bottlenecks
- Focus on your code (hide system libraries)

#### Allocations

**Look for:**
- Continuous memory growth
- Large allocations (> 1MB)
- Excessive allocations (> 1000/sec)

**Actions:**
- Filter by object type
- Track specific allocations
- Use "Generations" to detect leaks
- Compare heap snapshots

#### Leaks

**Look for:**
- Any detected leaks (red bars)
- Leaked object types
- Leak source code location

**Actions:**
- Click on leak to see backtrace
- Review object ownership
- Check retain cycles

#### Energy Log

**Look for:**
- High energy overhead (> 50)
- Background CPU usage
- Network activity patterns

**Actions:**
- Identify high-energy operations
- Optimize or defer expensive work
- Batch network operations

#### Network

**Look for:**
- Request frequency
- Payload sizes
- Connection patterns

**Actions:**
- Implement batching
- Reduce request size
- Use HTTP/2 multiplexing
- Implement caching

---

## Best Practices

### 1. Consistent Testing Environment

```bash
# Always use the same device/simulator
DEVICE="iPhone 14 Pro"

# Close other apps
killall Simulator

# Reset simulator state
xcrun simctl shutdown all
xcrun simctl erase all
```

### 2. Multiple Test Runs

- Run each test 5-10 times
- Calculate average, min, max
- Check standard deviation
- Discard outliers

### 3. Baseline Management

```bash
# Set baseline for all tests
# 1. Run tests
# 2. In Xcode Test Navigator:
#    - Right-click on test class
#    - Select "Set Baseline"
```

### 4. Regression Detection

```bash
# Compare against baseline
# Xcode will automatically flag regressions:
# - Yellow: 10-20% slower
# - Red: > 20% slower
```

### 5. Device vs Simulator

**Simulator:**
- Good for: Relative performance, API correctness
- Not accurate for: Battery, exact timings

**Device:**
- Good for: Absolute performance, battery tests
- Required for: Energy profiling

---

## Troubleshooting

### Tests Timeout

**Problem:** Tests hang or timeout

**Solution:**
```swift
// Increase expectation timeout
wait(for: [expectation], timeout: 60.0)

// Or set test timeout
func testLongRunning() throws {
    // Set in Xcode test target settings
    // Or use XCTSkip for problematic tests
}
```

### Inconsistent Results

**Problem:** Performance varies significantly between runs

**Solutions:**
1. Close other apps
2. Disable background processes
3. Use device instead of simulator
4. Increase test iterations
5. Run during off-peak hours

### Memory Warnings

**Problem:** Tests crash with memory warnings

**Solutions:**
1. Reduce test data size
2. Run tests individually
3. Clear caches between tests
4. Use autoreleasepool

### Instruments Won't Launch

**Problem:** Instruments fails to start or attach

**Solutions:**
```bash
# Reset instruments
rm -rf ~/Library/Developer/Xcode/DerivedData
killall Instruments

# Check signing
codesign -dv --verbose=4 /path/to/app

# Restart Xcode
killall Xcode
```

---

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Performance Tests

on:
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  performance:
    runs-on: macos-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Select Xcode
      run: sudo xcode-select -s /Applications/Xcode_15.0.app
    
    - name: Run Performance Tests
      run: |
        xcodebuild test \
          -scheme CatbirdChat \
          -destination 'platform=iOS Simulator,name=iPhone 14 Pro' \
          -only-testing:CatbirdChatTests/MLSPerformanceTests \
          -resultBundlePath TestResults.xcresult
    
    - name: Upload Results
      uses: actions/upload-artifact@v3
      with:
        name: performance-results
        path: TestResults.xcresult
    
    - name: Check for Regressions
      run: |
        # Custom script to compare results
        ./scripts/check_performance_regression.sh
```

---

## Next Steps

1. **Run initial tests** to establish baselines
2. **Review PERFORMANCE_REPORT.md** for expected values
3. **Profile with Instruments** for detailed analysis
4. **Document findings** in your project
5. **Set up CI/CD** for continuous monitoring
6. **Implement optimizations** based on results

---

## Resources

- [XCTest Performance Testing Documentation](https://developer.apple.com/documentation/xctest/performance_testing)
- [Instruments User Guide](https://help.apple.com/instruments/)
- [WWDC 2023: Measuring Performance](https://developer.apple.com/videos/play/wwdc2023/10181/)
- [MLS Performance Report](./PERFORMANCE_REPORT.md)
- [Test Suite README](./README.md)

---

## Support

For questions or issues:

1. Check troubleshooting section above
2. Review test output and error messages
3. Consult PERFORMANCE_REPORT.md
4. Open an issue in the repository
