#!/bin/bash

# Battle Test Runner for MLS Server
# This script helps set up and run the battle test suite

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
TEST_DB_URL="${DATABASE_URL:-postgresql://catbird:password@localhost:5432/catbird_test}"
RUN_SETUP=false
SPECIFIC_TEST=""
SHOW_LIST=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --setup)
            RUN_SETUP=true
            shift
            ;;
        --test)
            SPECIFIC_TEST="$2"
            shift 2
            ;;
        --list)
            SHOW_LIST=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --setup         Set up test database and run migrations"
            echo "  --test NAME     Run specific test by name"
            echo "  --list          List all available tests"
            echo "  --help          Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  DATABASE_URL    Test database URL (default: $TEST_DB_URL)"
            echo ""
            echo "Examples:"
            echo "  $0 --setup                  # Set up database and run all tests"
            echo "  $0                          # Run all tests"
            echo "  $0 --test idempotency       # Run idempotency stress test"
            echo "  $0 --list                   # List all available tests"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           MLS SERVER BATTLE TEST RUNNER                      ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Show test list if requested
if [ "$SHOW_LIST" = true ]; then
    echo -e "${YELLOW}Available Tests:${NC}\n"
    echo "1. test_idempotency_stress_100x_concurrent_identical_requests"
    echo "   → Idempotency under 100x concurrent load"
    echo ""
    echo "2. test_concurrent_member_addition_race_conditions"
    echo "   → Race conditions in member additions"
    echo ""
    echo "3. test_message_ordering_under_high_concurrency"
    echo "   → Message timestamps under concurrent sends"
    echo ""
    echo "4. test_cache_ttl_and_cleanup"
    echo "   → Cache expiration and cleanup"
    echo ""
    echo "5. test_leave_convo_natural_idempotency"
    echo "   → Natural idempotency via SQL WHERE"
    echo ""
    echo "6. test_welcome_message_grace_period_recovery"
    echo "   → Two-phase commit with grace period"
    echo ""
    echo "7. test_database_constraints_prevent_corruption"
    echo "   → UNIQUE constraints prevent duplicates"
    echo ""
    exit 0
fi

# Check if PostgreSQL is running
echo -e "${YELLOW}Checking PostgreSQL...${NC}"
if ! docker-compose ps postgres | grep -q "Up"; then
    echo -e "${RED}PostgreSQL is not running!${NC}"
    echo -e "${YELLOW}Starting PostgreSQL with docker-compose...${NC}"
    docker-compose up -d postgres
    echo -e "${GREEN}Waiting for PostgreSQL to be ready...${NC}"
    sleep 3
fi

# Test database connection
if psql "$TEST_DB_URL" -c "SELECT 1" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ PostgreSQL is running and accessible${NC}\n"
else
    echo -e "${RED}✗ Cannot connect to database at: $TEST_DB_URL${NC}"
    echo -e "${YELLOW}Please check your DATABASE_URL environment variable${NC}"
    exit 1
fi

# Run setup if requested
if [ "$RUN_SETUP" = true ]; then
    echo -e "${YELLOW}Setting up test database...${NC}"

    # Check if sqlx-cli is installed
    if ! command -v sqlx &> /dev/null; then
        echo -e "${YELLOW}Installing sqlx-cli...${NC}"
        cargo install sqlx-cli --no-default-features --features postgres
    fi

    # Run migrations
    echo -e "${YELLOW}Running migrations...${NC}"
    export DATABASE_URL="$TEST_DB_URL"
    sqlx migrate run
    echo -e "${GREEN}✓ Database setup complete${NC}\n"
fi

# Change to server directory
cd "$(dirname "$0")"

# Set environment
export DATABASE_URL="$TEST_DB_URL"
export RUST_BACKTRACE=1

# Run tests
if [ -n "$SPECIFIC_TEST" ]; then
    # Run specific test
    echo -e "${YELLOW}Running test: ${SPECIFIC_TEST}${NC}\n"

    # Try to find matching test name
    FULL_TEST_NAME=""
    case "$SPECIFIC_TEST" in
        idempotency|idem|stress)
            FULL_TEST_NAME="test_idempotency_stress_100x_concurrent_identical_requests"
            ;;
        member|members|race)
            FULL_TEST_NAME="test_concurrent_member_addition_race_conditions"
            ;;
        message|ordering|concurrent)
            FULL_TEST_NAME="test_message_ordering_under_high_concurrency"
            ;;
        cache|ttl|cleanup)
            FULL_TEST_NAME="test_cache_ttl_and_cleanup"
            ;;
        leave|natural)
            FULL_TEST_NAME="test_leave_convo_natural_idempotency"
            ;;
        welcome|grace|two-phase)
            FULL_TEST_NAME="test_welcome_message_grace_period_recovery"
            ;;
        constraint|constraints)
            FULL_TEST_NAME="test_database_constraints_prevent_corruption"
            ;;
        *)
            FULL_TEST_NAME="$SPECIFIC_TEST"
            ;;
    esac

    cargo test --test battle_tests "$FULL_TEST_NAME" -- --ignored --nocapture
else
    # Run all tests
    echo -e "${YELLOW}Running all battle tests...${NC}\n"
    cargo test --test battle_tests -- --ignored --nocapture --test-threads=1
fi

# Check exit code
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                  ALL TESTS PASSED ✓                          ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                  TESTS FAILED ✗                              ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    exit 1
fi
