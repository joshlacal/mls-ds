# MLS Performance Test Suite

Comprehensive performance testing suite for MLS (Messaging Layer Security) integration in CatbirdChat.

## Test Suites

### 1. MLSPerformanceTests.swift
Core encryption and decryption performance tests.

**Tests:**
- Encryption speed (100 iterations)
- Decryption speed (100 iterations)
- Large message encryption/decryption (10KB)
- Bulk message processing (50 messages)
- Key pair generation
- Key package creation
- Group creation speed
- Add/remove member performance
- Concurrent encryption operations
- Concurrent group operations

**Metrics:**
- XCTClockMetric (execution time)
- XCTMemoryMetric (memory usage)
- XCTCPUMetric (CPU utilization)

### 2. MLSLargeGroupPerformanceTests.swift
Performance tests for large group operations (100-250+ members).

**Tests:**
- Create 100-member group
- Message encryption/decryption in large groups
- Add member to 100-member group
- Remove member from 100-member group
- Create 250-member group
- Group state export/import
- Message throughput in large groups

**Metrics:**
- XCTClockMetric
- XCTMemoryMetric
- XCTCPUMetric
- XCTStorageMetric

### 3. MLSAppLaunchPerformanceTests.swift
App launch time impact tests.

**Tests:**
- MLS initialization time
- Cold launch with 0/10/50 groups
- Warm launch performance
- Database connection time
- Load groups from database
- Load key packages on launch
- Cache warming performance
- Background initialization
- First message send after launch

**Metrics:**
- XCTClockMetric
- XCTMemoryMetric
- XCTCPUMetric
- XCTStorageMetric

### 4. MLSMemoryPerformanceTests.swift
Memory usage and leak detection tests.

**Tests:**
- Baseline memory usage
- Memory usage with 10/100 groups
- Memory usage per member
- Memory leak detection (encryption/decryption)
- Memory leak in group operations
- Message cache memory usage
- Key package cache memory usage
- Peak memory during bulk operations
- Memory recovery after cleanup

**Metrics:**
- XCTMemoryMetric
- XCTStorageMetric

### 5. MLSNetworkPerformanceTests.swift
Network efficiency and bandwidth tests.

**Tests:**
- Encrypted message overhead
- Welcome message size
- Commit message size
- Bandwidth for message burst
- Bandwidth for group updates
- Message round-trip time
- Key package upload latency
- Batch message efficiency
- Compression ratio
- Connection pool efficiency
- Retry performance

**Metrics:**
- XCTClockMetric
- XCTStorageMetric

### 6. MLSDatabasePerformanceTests.swift
Database query and storage performance tests.

**Tests:**
- Insert/select/update/delete performance
- Bulk operations (1000 records)
- Indexed vs unindexed queries
- Join query performance
- Transaction performance
- Database cache hit rate
- Concurrent read/write operations
- Database size growth
- Vacuum performance

**Metrics:**
- XCTClockMetric
- XCTStorageMetric
- XCTCPUMetric

### 7. MLSBatteryPerformanceTests.swift
Battery drain and energy usage tests.

**Tests:**
- Idle energy consumption
- Encryption/decryption energy usage
- Group operation energy usage
- Background sync energy
- Key refresh energy usage
- CPU usage during operations
- Network operation energy
- Batch vs individual energy efficiency
- Caching energy impact
- Low power mode impact
- Extended usage energy drain

**Metrics:**
- XCTCPUMetric

## Running the Tests

### Using Xcode

1. Open the project in Xcode
2. Select Product > Test or press ⌘U
3. To run specific test suite, select the test class in the Test Navigator
4. View results in the Test Navigator and Report Navigator

### Using Xcode Command Line

```bash
# Run all performance tests
xcodebuild test -scheme CatbirdChat -destination 'platform=iOS Simulator,name=iPhone 14 Pro' -only-testing:CatbirdChatTests/MLSPerformanceTests

# Run specific test class
xcodebuild test -scheme CatbirdChat -destination 'platform=iOS Simulator,name=iPhone 14 Pro' -only-testing:CatbirdChatTests/MLSLargeGroupPerformanceTests

# Run on device
xcodebuild test -scheme CatbirdChat -destination 'platform=iOS,name=Your iPhone'
```

### Using Instruments

For detailed profiling:

1. **Time Profiler**: Analyze CPU usage patterns
   - Product > Profile > Time Profiler
   - Run performance tests
   - Analyze hotspots and call trees

2. **Allocations**: Track memory usage and leaks
   - Product > Profile > Allocations
   - Monitor heap growth during tests
   - Check for memory leaks

3. **Leaks**: Detect memory leaks
   - Product > Profile > Leaks
   - Run memory performance tests
   - Investigate any detected leaks

4. **Energy Log**: Monitor power consumption
   - Product > Profile > Energy Log
   - Run battery performance tests
   - Analyze energy impact

5. **Network**: Analyze network traffic
   - Product > Profile > Network
   - Run network performance tests
   - Check bandwidth usage

6. **System Trace**: Overall system performance
   - Product > Profile > System Trace
   - Comprehensive view of all metrics

## Performance Baselines

Expected performance targets:

### Encryption/Decryption
- Small message (< 1KB): < 5ms per operation
- Medium message (1-10KB): < 20ms per operation
- Large message (> 10KB): < 50ms per operation

### Group Operations
- Create group: < 100ms
- Add member (< 10 members): < 50ms
- Add member (100+ members): < 200ms
- Remove member: < 100ms

### App Launch
- MLS initialization: < 500ms
- Load 10 groups: < 200ms
- Load 50 groups: < 1000ms

### Memory
- Baseline (no groups): < 5MB
- Per group overhead: < 100KB
- Per member overhead: < 10KB
- Maximum for 100-member group: < 15MB

### Battery
- Idle (1 hour): < 1% battery drain
- Active messaging (1 hour): < 5% battery drain
- Background sync (1 hour): < 2% battery drain

### Network
- Message overhead: < 30%
- Batch efficiency: > 70% savings
- RTT (round-trip time): < 100ms

### Database
- Single query: < 10ms
- Bulk insert (1000 records): < 500ms
- Complex join: < 50ms

## Interpreting Results

### Baseline Comparison
Compare results against baselines to identify regressions.

### Relative Performance
Focus on relative changes between runs rather than absolute values.

### Statistical Significance
XCTest runs each test multiple times (default: 5 iterations).
- Review average, min, max, and standard deviation
- High standard deviation indicates variability

### Regression Detection
Xcode can detect performance regressions automatically:
- Set baseline in Xcode Test Navigator
- New runs compared against baseline
- Alerts on significant changes

## Optimization Recommendations

Based on test results, consider:

1. **Caching**: If repeated operations show consistent performance
2. **Batch Operations**: If individual operations show high overhead
3. **Lazy Loading**: If initialization time is high
4. **Background Processing**: If operations block UI
5. **Memory Pooling**: If memory allocation is frequent
6. **Connection Pooling**: If network operations are slow
7. **Index Optimization**: If database queries are slow
8. **Compression**: If network overhead is high

## Continuous Integration

Integrate performance tests in CI pipeline:

```yaml
# Example GitHub Actions workflow
- name: Run Performance Tests
  run: |
    xcodebuild test \
      -scheme CatbirdChat \
      -destination 'platform=iOS Simulator,name=iPhone 14 Pro' \
      -only-testing:CatbirdChatTests/MLSPerformanceTests \
      | xcpretty
```

## Troubleshooting

### Tests Timing Out
- Increase timeout in test expectations
- Check for deadlocks or infinite loops

### Inconsistent Results
- Close other apps to reduce system load
- Run on device instead of simulator
- Ensure consistent test data

### Memory Warnings
- Reduce test data size
- Run tests individually
- Check for memory leaks

## Additional Resources

- [XCTest Performance Testing](https://developer.apple.com/documentation/xctest/performance_testing)
- [Instruments User Guide](https://help.apple.com/instruments/)
- [Energy Efficiency Guide](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/EnergyGuide-iOS/)
