# MLS Performance Test Suite Index

## 📊 Overview

Comprehensive performance testing suite for MLS integration in CatbirdChat, covering encryption speed, memory usage, network efficiency, battery consumption, and database performance.

## 📁 File Structure

### Test Files (Swift)

1. **MLSPerformanceTests.swift** (5.8 KB)
   - Core encryption/decryption performance
   - Key generation and package creation
   - Group operations
   - Concurrent operations
   - Tests: 12 test methods

2. **MLSLargeGroupPerformanceTests.swift** (7.2 KB)
   - 100-member group operations
   - 250-member group operations
   - Group state management
   - Message throughput in large groups
   - Tests: 10 test methods

3. **MLSAppLaunchPerformanceTests.swift** (5.8 KB)
   - Cold/warm launch performance
   - Database loading
   - Cache warming
   - Background initialization
   - Tests: 11 test methods

4. **MLSMemoryPerformanceTests.swift** (7.0 KB)
   - Memory footprint analysis
   - Leak detection
   - Cache memory usage
   - Peak memory usage
   - Memory recovery
   - Tests: 14 test methods

5. **MLSNetworkPerformanceTests.swift** (9.7 KB)
   - Message payload overhead
   - Bandwidth usage
   - Network latency
   - Batch efficiency
   - Compression tests
   - Tests: 14 test methods

6. **MLSDatabasePerformanceTests.swift** (11 KB)
   - Query performance (CRUD)
   - Bulk operations
   - Index performance
   - Transaction performance
   - Concurrent access
   - Tests: 16 test methods

7. **MLSBatteryPerformanceTests.swift** (11 KB)
   - Idle energy consumption
   - Active operation energy
   - Background activity energy
   - CPU usage
   - Optimization impact
   - Tests: 13 test methods

8. **TestHelpers.swift** (7.2 KB)
   - Mock classes for testing
   - Test data structures
   - Helper utilities

### Documentation Files

1. **README.md** (7.8 KB)
   - Complete test suite documentation
   - Running instructions
   - Performance baselines
   - Interpreting results
   - Optimization recommendations

2. **SETUP_GUIDE.md** (8.8 KB)
   - Prerequisites and requirements
   - Project setup instructions
   - Running tests (multiple methods)
   - Using Instruments
   - Troubleshooting guide
   - CI/CD integration

3. **QUICK_REFERENCE.md** (4.9 KB)
   - Quick start commands
   - Common commands
   - Keyboard shortcuts
   - Performance targets
   - Common issues & solutions

4. **INDEX.md** (This file)
   - File structure overview
   - Quick access guide

### Shell Scripts

1. **run_performance_tests.sh** (2.6 KB)
   - Automated test runner
   - Runs all test suites
   - Generates reports
   - Opens results in Xcode

2. **run_instruments.sh** (3.0 KB)
   - Instruments profiling automation
   - Multiple profiling templates
   - Interactive menu
   - Saves trace files

### Reports

1. **PERFORMANCE_REPORT.md** (21 KB) - Located in repository root
   - Executive summary
   - Detailed test results
   - Bottlenecks identified
   - Optimization recommendations
   - Implementation priorities
   - Monitoring strategy

## 🚀 Quick Start

### 1. First Time Setup

```bash
# Navigate to performance tests directory
cd /Users/joshlacalamito/Developer/Catbird+Petrel/mls/tests/performance

# Read setup guide
open SETUP_GUIDE.md

# Make scripts executable (already done)
chmod +x *.sh
```

### 2. Run Tests

```bash
# Run all performance tests
./run_performance_tests.sh

# Or use Xcode
# Press ⌘6 to open Test Navigator
# Press ⌘U to run all tests
```

### 3. Profile with Instruments

```bash
# Interactive profiling
./run_instruments.sh

# Or use Xcode
# Press ⌘I to profile
# Select template and record
```

### 4. Review Results

```bash
# Open performance report
open ../PERFORMANCE_REPORT.md

# View test documentation
open README.md

# Check quick reference
open QUICK_REFERENCE.md
```

## 📈 Test Coverage

### Total Tests: 90 test methods

| Test Suite | Tests | Focus Area |
|------------|-------|------------|
| MLSPerformanceTests | 12 | Core operations |
| MLSLargeGroupPerformanceTests | 10 | Scalability |
| MLSAppLaunchPerformanceTests | 11 | Startup time |
| MLSMemoryPerformanceTests | 14 | Memory management |
| MLSNetworkPerformanceTests | 14 | Network efficiency |
| MLSDatabasePerformanceTests | 16 | Database performance |
| MLSBatteryPerformanceTests | 13 | Energy consumption |

### Metrics Measured

- ⏱️ **Execution Time** (XCTClockMetric)
- 💾 **Memory Usage** (XCTMemoryMetric)
- ⚡ **CPU Usage** (XCTCPUMetric)
- 💿 **Storage I/O** (XCTStorageMetric)

## 🎯 Performance Targets

| Category | Metric | Target |
|----------|--------|--------|
| Encryption | Small message | < 5ms |
| Encryption | Large message (10KB) | < 50ms |
| Groups | Creation | < 100ms |
| Groups | Add member (100+) | < 200ms |
| Launch | Cold start | < 500ms |
| Launch | With 50 groups | < 1000ms |
| Memory | Per group | < 100KB |
| Memory | Per member | < 10KB |
| Network | Message overhead | < 30% |
| Battery | 1 hour active | < 5% |
| Database | Simple query | < 10ms |
| Database | Bulk (1000) | < 500ms |

## 📖 Reading Guide

### For Developers

1. Start with **QUICK_REFERENCE.md** for immediate commands
2. Read **SETUP_GUIDE.md** for detailed setup
3. Review **README.md** for comprehensive documentation
4. Consult **PERFORMANCE_REPORT.md** for optimization guidance

### For QA/Testing

1. Follow **SETUP_GUIDE.md** to set up environment
2. Use **run_performance_tests.sh** to run tests
3. Compare results against **PERFORMANCE_REPORT.md** baselines
4. Document any regressions

### For DevOps

1. Review **SETUP_GUIDE.md** CI/CD section
2. Integrate **run_performance_tests.sh** into pipeline
3. Set up alerts based on **PERFORMANCE_REPORT.md** targets
4. Monitor trends over time

### For Product/Management

1. Read **PERFORMANCE_REPORT.md** executive summary
2. Review optimization priorities
3. Understand implementation timelines
4. Track KPIs from monitoring strategy

## 🔧 Tools Required

### Essential
- Xcode 15.0+
- iOS Simulator or Device
- macOS 13.0+

### Optional
- xcpretty (prettier output)
- jq (JSON parsing)
- Instruments (included with Xcode)

## 📊 Output Files

### Test Results
- `performance-results/TestResults_*.xcresult` - Test bundle
- `performance-results/results_*.json` - JSON results
- `instruments-results/*.trace` - Instruments traces

### Generated Reports
- Xcode Test Navigator shows visual results
- JSON files for programmatic analysis
- Trace files for detailed profiling

## 🐛 Troubleshooting

### Common Issues

1. **Tests timeout** → See SETUP_GUIDE.md troubleshooting
2. **Inconsistent results** → Reset simulator, close apps
3. **Memory warnings** → Reduce test data, use autoreleasepool
4. **Instruments fails** → Clean derived data, restart

### Getting Help

1. Check **SETUP_GUIDE.md** troubleshooting section
2. Review test output and error messages
3. Consult **PERFORMANCE_REPORT.md**
4. Open an issue in repository

## 🔄 Continuous Improvement

### Regular Tasks

- **Daily:** Run tests on development
- **Weekly:** Review performance trends
- **Monthly:** Update baselines
- **Quarterly:** Full profiling with Instruments

### Update Process

1. Run tests to establish baseline
2. Make code changes
3. Re-run tests
4. Compare results
5. Document changes
6. Update baselines if needed

## 📞 Support

- **Documentation:** See README.md, SETUP_GUIDE.md
- **Quick Help:** See QUICK_REFERENCE.md
- **Detailed Report:** See PERFORMANCE_REPORT.md
- **Issues:** Repository issue tracker

## 🎓 Learning Resources

- [XCTest Performance Testing](https://developer.apple.com/documentation/xctest/performance_testing)
- [Instruments User Guide](https://help.apple.com/instruments/)
- [WWDC: Measuring Performance](https://developer.apple.com/videos/play/wwdc2023/10181/)
- [Energy Efficiency Guide](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/EnergyGuide-iOS/)

---

**Last Updated:** October 21, 2025  
**Version:** 1.0.0  
**Total Files:** 13 (8 Swift, 3 Markdown, 2 Shell Scripts)  
**Total Tests:** 90 test methods  
**Documentation:** ~30 KB
