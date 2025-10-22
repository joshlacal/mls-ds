#!/bin/bash
#
# Performance Test Runner Script
# Runs comprehensive MLS performance tests and generates reports
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCHEME="CatbirdChat"
DESTINATION="platform=iOS Simulator,name=iPhone 14 Pro,OS=latest"
RESULTS_DIR="performance-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULT_BUNDLE="${RESULTS_DIR}/TestResults_${TIMESTAMP}.xcresult"

# Create results directory
mkdir -p "${RESULTS_DIR}"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}MLS Performance Test Suite${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Function to run a specific test class
run_test_suite() {
    local test_name=$1
    echo -e "${YELLOW}Running ${test_name}...${NC}"
    
    xcodebuild test \
        -scheme "${SCHEME}" \
        -destination "${DESTINATION}" \
        -only-testing:"${SCHEME}Tests/${test_name}" \
        -resultBundlePath "${RESULT_BUNDLE}" \
        2>&1 | xcpretty
    
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        echo -e "${GREEN}✓ ${test_name} completed${NC}"
    else
        echo -e "${RED}✗ ${test_name} failed${NC}"
        return 1
    fi
    echo ""
}

# Run all performance test suites
echo "Starting performance tests..."
echo ""

run_test_suite "MLSPerformanceTests"
run_test_suite "MLSLargeGroupPerformanceTests"
run_test_suite "MLSAppLaunchPerformanceTests"
run_test_suite "MLSMemoryPerformanceTests"
run_test_suite "MLSNetworkPerformanceTests"
run_test_suite "MLSDatabasePerformanceTests"
run_test_suite "MLSBatteryPerformanceTests"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}All performance tests completed!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Results saved to: ${RESULT_BUNDLE}"
echo ""

# Generate summary report
echo "Generating summary report..."

# Extract test results using xcresulttool
if command -v xcresulttool &> /dev/null; then
    xcresulttool get --path "${RESULT_BUNDLE}" --format json > "${RESULTS_DIR}/results_${TIMESTAMP}.json"
    echo -e "${GREEN}✓ JSON report generated${NC}"
fi

# Open results in Xcode
if [ "$1" != "--no-open" ]; then
    echo "Opening results in Xcode..."
    open "${RESULT_BUNDLE}"
fi

echo ""
echo -e "${GREEN}Performance testing complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Review results in Xcode"
echo "2. Compare against baseline in PERFORMANCE_REPORT.md"
echo "3. Run Instruments for detailed profiling (see run_instruments.sh)"
echo "4. Document any regressions"
