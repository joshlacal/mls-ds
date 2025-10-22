#!/bin/bash
# MLS Integration Parallel Agent Execution Script
# This script orchestrates all 5 phases of the MLS integration using parallel agents

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CATBIRD_DIR="$SCRIPT_DIR/../Catbird"
PARALLEL_AGENTS="$CATBIRD_DIR/parallel-agents.py"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if parallel-agents.py exists
if [ ! -f "$PARALLEL_AGENTS" ]; then
    echo -e "${RED}Error: parallel-agents.py not found at $PARALLEL_AGENTS${NC}"
    echo "Please ensure the Catbird repository is cloned at the expected location."
    exit 1
fi

# Function to run a phase
run_phase() {
    local phase_num=$1
    local phase_name=$2
    local config_file=$3
    local max_agents=$4
    
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Phase $phase_num: $phase_name${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}\n"
    
    python3 "$PARALLEL_AGENTS" from-config "$config_file" --max-agents "$max_agents"
    
    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}✓ Phase $phase_num completed successfully${NC}\n"
    else
        echo -e "\n${RED}✗ Phase $phase_num failed${NC}"
        echo -e "${YELLOW}Check the logs in parallel-agents-results/ for details${NC}\n"
        exit 1
    fi
}

# Welcome message
echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     MLS E2EE Chat Integration for Catbird                    ║
║     Parallel Agent Execution System                          ║
║                                                               ║
║     Total: 5 Phases | 14 Days | 200+ Tasks                   ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}\n"

# Confirm execution
read -p "This will execute all MLS integration phases. Continue? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Phase 1: Preparation & Infrastructure (2 days)
run_phase 1 "Preparation & Infrastructure" \
    "$SCRIPT_DIR/mls-parallel-agents-phase1.json" 3

echo -e "${YELLOW}⚠ Manual checkpoint: Review git setup and architecture audit before proceeding${NC}"
read -p "Press Enter to continue to Phase 2..."

# Phase 2: Code Generation (2 days)
run_phase 2 "Code Generation" \
    "$SCRIPT_DIR/mls-parallel-agents-phase2.json" 3

echo -e "${YELLOW}⚠ Manual checkpoint: Review generated models and API client before proceeding${NC}"
read -p "Press Enter to continue to Phase 3..."

# Phase 3: Server Implementation (3 days)
run_phase 3 "Server Implementation" \
    "$SCRIPT_DIR/mls-parallel-agents-phase3.json" 4

echo -e "${YELLOW}⚠ Manual checkpoint: Test server endpoints locally before proceeding${NC}"
read -p "Press Enter to continue to Phase 4..."

# Phase 4: iOS Integration (5 days)
run_phase 4 "iOS Integration" \
    "$SCRIPT_DIR/mls-parallel-agents-phase4.json" 6

echo -e "${YELLOW}⚠ Manual checkpoint: Build and run Catbird app to test MLS features${NC}"
read -p "Press Enter to continue to Phase 5..."

# Phase 5: Testing, Security & Deployment (2 days)
run_phase 5 "Testing, Security & Deployment" \
    "$SCRIPT_DIR/mls-parallel-agents-phase5.json" 5

# Success summary
echo -e "\n${GREEN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     ✓ MLS Integration Complete!                              ║
║                                                               ║
║     All 5 phases executed successfully.                      ║
║     Review the documentation and test results.               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}\n"

echo -e "${BLUE}Next steps:${NC}"
echo "1. Review all logs in parallel-agents-results/"
echo "2. Run the full test suite"
echo "3. Perform manual QA testing"
echo "4. Review security audit report"
echo "5. Deploy to staging environment"
echo "6. Create PR for review"
echo ""
echo -e "${GREEN}Documentation generated:${NC}"
echo "  - mls-git-setup.md"
echo "  - LEXICON_README.md"
echo "  - mls-catbird-architecture-audit.md"
echo "  - petrel-generation-report.md"
echo "  - MLS_API_CLIENT_README.md"
echo "  - FFI_INTEGRATION_GUIDE.md"
echo "  - DATABASE_SCHEMA.md"
echo "  - DEPLOYMENT.md"
echo "  - FFI_SWIFT_BRIDGE.md"
echo "  - STORAGE_ARCHITECTURE.md"
echo "  - MLS_INTEGRATION_CHECKLIST.md"
echo "  - E2E_TEST_REPORT.md"
echo "  - SECURITY_AUDIT_REPORT.md"
echo "  - PERFORMANCE_REPORT.md"
echo "  - User, Developer, and Admin Guides in docs/"
echo "  - PRODUCTION_DEPLOYMENT.md"
echo ""
