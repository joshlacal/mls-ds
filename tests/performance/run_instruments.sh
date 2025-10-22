#!/bin/bash
#
# Instruments Profiling Script
# Runs detailed profiling with various Instruments templates
#

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
APP_NAME="CatbirdChat"
DEVICE="iPhone 14 Pro"
RESULTS_DIR="instruments-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "${RESULTS_DIR}"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}MLS Instruments Profiling${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Function to run instruments with a specific template
run_instruments() {
    local template=$1
    local output_name=$2
    local duration=${3:-30}
    
    echo -e "${YELLOW}Running ${template} profiling...${NC}"
    echo "Duration: ${duration} seconds"
    echo ""
    
    local trace_file="${RESULTS_DIR}/${output_name}_${TIMESTAMP}.trace"
    
    # Note: This requires the app to be running
    # You may need to adjust based on your setup
    instruments \
        -t "${template}" \
        -D "${trace_file}" \
        -l "${duration}" \
        "${APP_NAME}"
    
    echo -e "${GREEN}✓ ${template} profiling complete${NC}"
    echo "Results saved to: ${trace_file}"
    echo ""
}

# Display menu
echo "Select profiling template:"
echo "1. Time Profiler (CPU usage)"
echo "2. Allocations (Memory usage)"
echo "3. Leaks (Memory leaks)"
echo "4. Energy Log (Battery impact)"
echo "5. Network (Network activity)"
echo "6. System Trace (Comprehensive)"
echo "7. All (Run all profiles - takes ~3 minutes)"
echo ""
read -p "Enter choice [1-7]: " choice

case $choice in
    1)
        run_instruments "Time Profiler" "time_profiler" 30
        ;;
    2)
        run_instruments "Allocations" "allocations" 30
        ;;
    3)
        run_instruments "Leaks" "leaks" 30
        ;;
    4)
        run_instruments "Energy Log" "energy_log" 60
        ;;
    5)
        run_instruments "Network" "network" 30
        ;;
    6)
        run_instruments "System Trace" "system_trace" 30
        ;;
    7)
        echo "Running all profiling templates..."
        echo ""
        run_instruments "Time Profiler" "time_profiler" 30
        run_instruments "Allocations" "allocations" 30
        run_instruments "Leaks" "leaks" 30
        run_instruments "Energy Log" "energy_log" 60
        run_instruments "Network" "network" 30
        run_instruments "System Trace" "system_trace" 30
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}Profiling complete!${NC}"
echo ""
echo "Trace files saved to: ${RESULTS_DIR}"
echo ""
echo "To open a trace file:"
echo "  open ${RESULTS_DIR}/<trace_file>.trace"
echo ""
echo "Analysis tips:"
echo "- Time Profiler: Look for hot paths and long-running functions"
echo "- Allocations: Check for excessive allocations and memory growth"
echo "- Leaks: Investigate any detected memory leaks"
echo "- Energy Log: Review energy impact and optimize high-impact operations"
echo "- Network: Analyze bandwidth usage and request patterns"
echo "- System Trace: Get comprehensive view of all system interactions"
