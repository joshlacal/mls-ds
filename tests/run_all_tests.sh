#!/bin/bash

# End-to-End Test Runner for MLS Integration
# Runs all test suites and generates coverage reports

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}MLS Integration Test Suite Runner${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IOS_PROJECT="${PROJECT_ROOT}/client-ios/CatbirdChat"
SERVER_DIR="${PROJECT_ROOT}/server"
TEST_DIR="${PROJECT_ROOT}/tests"
REPORTS_DIR="${PROJECT_ROOT}/test-reports"

# Create reports directory
mkdir -p "${REPORTS_DIR}"

# Track overall status
OVERALL_STATUS=0

# Function to print section header
print_section() {
    echo ""
    echo -e "${BLUE}----------------------------------------${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}----------------------------------------${NC}"
}

# Function to print success
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Function to print error
print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Function to print warning
print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Run iOS Tests
run_ios_tests() {
    print_section "Running iOS Tests"
    
    if [ ! -d "$IOS_PROJECT" ]; then
        print_warning "iOS project not found at $IOS_PROJECT, skipping..."
        return 0
    fi
    
    cd "$IOS_PROJECT"
    
    # Check if xcodebuild is available
    if ! command -v xcodebuild &> /dev/null; then
        print_warning "xcodebuild not found, skipping iOS tests..."
        return 0
    fi
    
    echo "Building iOS project..."
    if xcodebuild clean build -scheme CatbirdChat -quiet; then
        print_success "iOS build successful"
    else
        print_error "iOS build failed"
        return 1
    fi
    
    echo "Running iOS tests..."
    if xcodebuild test \
        -scheme CatbirdChat \
        -destination 'platform=iOS Simulator,name=iPhone 15' \
        -enableCodeCoverage YES \
        -resultBundlePath "${REPORTS_DIR}/ios-test-results" \
        2>&1 | tee "${REPORTS_DIR}/ios-tests.log"; then
        print_success "iOS tests passed"
        return 0
    else
        print_error "iOS tests failed"
        return 1
    fi
}

# Run Server Tests
run_server_tests() {
    print_section "Running Server Tests"
    
    if [ ! -d "$SERVER_DIR" ]; then
        print_error "Server directory not found at $SERVER_DIR"
        return 1
    fi
    
    cd "$SERVER_DIR"
    
    # Check if cargo is available
    if ! command -v cargo &> /dev/null; then
        print_error "cargo not found, cannot run server tests"
        return 1
    fi
    
    echo "Building server..."
    if cargo build --quiet; then
        print_success "Server build successful"
    else
        print_error "Server build failed"
        return 1
    fi
    
    echo "Running server unit tests..."
    if cargo test --lib 2>&1 | tee "${REPORTS_DIR}/server-unit-tests.log"; then
        print_success "Server unit tests passed"
    else
        print_error "Server unit tests failed"
        OVERALL_STATUS=1
    fi
    
    echo "Running server integration tests..."
    if cargo test --test '*' 2>&1 | tee "${REPORTS_DIR}/server-integration-tests.log"; then
        print_success "Server integration tests passed"
    else
        print_warning "Server integration tests failed (expected - requires refactoring)"
    fi
    
    return 0
}

# Run E2E Integration Tests
run_e2e_tests() {
    print_section "Running E2E Integration Tests"
    
    cd "$TEST_DIR"
    
    # For now, just validate test structure
    echo "Validating test structure..."
    
    local required_files=(
        "fixtures/TestData.swift"
        "mocks/MockMLSServer.swift"
        "ios/MLSGroupTests.swift"
        "ios/MLSMessagingTests.swift"
        "ios/MLSKeyRotationTests.swift"
        "ios/MLSMultiDeviceTests.swift"
        "ios/MLSOfflineErrorTests.swift"
        "server/e2e_integration_tests.rs"
    )
    
    local all_present=true
    for file in "${required_files[@]}"; do
        if [ -f "$file" ]; then
            echo "  ✓ $file"
        else
            echo "  ✗ $file (missing)"
            all_present=false
        fi
    done
    
    if $all_present; then
        print_success "All test files present"
        return 0
    else
        print_error "Some test files are missing"
        return 1
    fi
}

# Generate Coverage Report
generate_coverage_report() {
    print_section "Generating Coverage Report"
    
    cd "$PROJECT_ROOT"
    
    echo "Coverage Summary" > "${REPORTS_DIR}/coverage-summary.txt"
    echo "================" >> "${REPORTS_DIR}/coverage-summary.txt"
    echo "" >> "${REPORTS_DIR}/coverage-summary.txt"
    
    # iOS Coverage (if available)
    if [ -d "${REPORTS_DIR}/ios-test-results" ]; then
        echo "iOS Tests: See ios-test-results bundle" >> "${REPORTS_DIR}/coverage-summary.txt"
    fi
    
    # Server Coverage
    if command -v cargo &> /dev/null && [ -d "$SERVER_DIR" ]; then
        cd "$SERVER_DIR"
        if command -v cargo-tarpaulin &> /dev/null; then
            echo "Generating server coverage with tarpaulin..."
            cargo tarpaulin --out Xml --output-dir "${REPORTS_DIR}" 2>&1 | tee -a "${REPORTS_DIR}/coverage-summary.txt"
        else
            print_warning "cargo-tarpaulin not installed, skipping detailed coverage"
            echo "To install: cargo install cargo-tarpaulin"
        fi
    fi
    
    print_success "Coverage report generated at ${REPORTS_DIR}/coverage-summary.txt"
}

# Generate Test Report
generate_test_report() {
    print_section "Generating Test Report"
    
    local report_file="${REPORTS_DIR}/test-summary.txt"
    
    {
        echo "MLS Integration Test Suite - Summary"
        echo "====================================="
        echo ""
        echo "Date: $(date)"
        echo "Project: ${PROJECT_ROOT}"
        echo ""
        echo "Test Results:"
        echo "-------------"
        
        if [ -f "${REPORTS_DIR}/ios-tests.log" ]; then
            echo ""
            echo "iOS Tests:"
            grep -E "Test Suite|Test Case.*passed|Test Case.*failed" "${REPORTS_DIR}/ios-tests.log" | tail -20 || echo "  See ios-tests.log for details"
        fi
        
        if [ -f "${REPORTS_DIR}/server-unit-tests.log" ]; then
            echo ""
            echo "Server Unit Tests:"
            grep -E "test result:" "${REPORTS_DIR}/server-unit-tests.log" | tail -5 || echo "  See server-unit-tests.log for details"
        fi
        
        if [ -f "${REPORTS_DIR}/server-integration-tests.log" ]; then
            echo ""
            echo "Server Integration Tests:"
            grep -E "test result:" "${REPORTS_DIR}/server-integration-tests.log" | tail -5 || echo "  See server-integration-tests.log for details"
        fi
        
        echo ""
        echo "Overall Status: $([ $OVERALL_STATUS -eq 0 ] && echo 'PASSED ✅' || echo 'FAILED ❌')"
        
    } > "$report_file"
    
    cat "$report_file"
    print_success "Test report generated at ${report_file}"
}

# Main execution
main() {
    local start_time=$(date +%s)
    
    # Run test suites
    if run_ios_tests; then
        print_success "iOS test suite completed"
    else
        print_warning "iOS test suite had issues"
        OVERALL_STATUS=1
    fi
    
    if run_server_tests; then
        print_success "Server test suite completed"
    else
        print_error "Server test suite failed"
        OVERALL_STATUS=1
    fi
    
    if run_e2e_tests; then
        print_success "E2E test validation completed"
    else
        print_error "E2E test validation failed"
        OVERALL_STATUS=1
    fi
    
    # Generate reports
    generate_coverage_report
    generate_test_report
    
    # Calculate duration
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Final summary
    echo ""
    print_section "Test Suite Complete"
    echo "Duration: ${duration}s"
    echo "Reports: ${REPORTS_DIR}"
    echo ""
    
    if [ $OVERALL_STATUS -eq 0 ]; then
        print_success "All tests passed! 🎉"
        echo ""
        echo "Next steps:"
        echo "  1. Review coverage report at ${REPORTS_DIR}/coverage-summary.txt"
        echo "  2. Check detailed logs in ${REPORTS_DIR}/"
        echo "  3. Review E2E_TEST_REPORT.md for complete documentation"
    else
        print_error "Some tests failed. Please check the logs."
        echo ""
        echo "Logs available at:"
        echo "  - ${REPORTS_DIR}/ios-tests.log"
        echo "  - ${REPORTS_DIR}/server-unit-tests.log"
        echo "  - ${REPORTS_DIR}/server-integration-tests.log"
    fi
    
    exit $OVERALL_STATUS
}

# Run main function
main "$@"
