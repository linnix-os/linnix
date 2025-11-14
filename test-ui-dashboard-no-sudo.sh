#!/bin/bash
set -e

echo "=== Testing Linnix UI Dashboard ==="
echo ""
echo "NOTE: Run this first if capabilities aren't set:"
echo "  sudo setcap cap_sys_admin,cap_bpf,cap_net_admin,cap_perfmon+eip ./target/release/cognitod"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

BINARY="./target/release/cognitod"
PORT=3000
BASE_URL="http://localhost:$PORT"

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo -e "${RED}✗ Binary not found: $BINARY${NC}"
    echo "Run: cargo build --release --features fake-events"
    exit 1
fi

# Kill any existing cognitod
pkill -9 cognitod 2>/dev/null || true
sleep 1

# Start cognitod with fake events in background
echo "Starting cognitod with demo mode..."
$BINARY --demo fork-storm > /tmp/cognitod_ui_test.log 2>&1 &
COGNITOD_PID=$!
echo "Started cognitod (PID: $COGNITOD_PID)"

# Give it time to start
sleep 3

# Test function
test_endpoint() {
    local name="$1"
    local endpoint="$2"
    local expect_html="${3:-false}"

    echo -n "Testing $name... "

    if [ "$expect_html" = "true" ]; then
        # For HTML responses, check for content
        if curl -s -f "$BASE_URL$endpoint" | grep -q "<!DOCTYPE html>"; then
            echo -e "${GREEN}✓${NC}"
            return 0
        else
            echo -e "${RED}✗ (no HTML)${NC}"
            return 1
        fi
    else
        # For JSON endpoints
        if curl -s -f "$BASE_URL$endpoint" > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC}"
            return 0
        else
            echo -e "${RED}✗ (failed)${NC}"
            return 1
        fi
    fi
}

# Counter
PASSED=0
FAILED=0

echo ""
echo "=== UI Endpoints ==="

if test_endpoint "Dashboard (root)" "/" true; then
    ((PASSED++))
else
    ((FAILED++))
fi

if test_endpoint "Dashboard (/dashboard)" "/dashboard" true; then
    ((PASSED++))
else
    ((FAILED++))
fi

echo ""
echo "=== API Endpoints (for UI) ==="

if test_endpoint "System info" "/system"; then
    ((PASSED++))
else
    ((FAILED++))
fi

if test_endpoint "System metrics" "/metrics/system"; then
    ((PASSED++))
else
    ((FAILED++))
fi

if test_endpoint "Processes" "/processes"; then
    ((PASSED++))
else
    ((FAILED++))
fi

if test_endpoint "Timeline" "/timeline"; then
    ((PASSED++))
else
    ((FAILED++))
fi

echo ""
echo "=== Live Streaming ==="

# Test SSE endpoint
echo -n "Testing SSE /processes/live... "
if timeout 3 curl -s -N "$BASE_URL/processes/live" 2>&1 | head -5 | grep -q "data:"; then
    echo -e "${GREEN}✓ (streaming)${NC}"
    ((PASSED++))
else
    echo -e "${YELLOW}~ (timeout or no data)${NC}"
    ((FAILED++))
fi

echo ""
echo "=== Browser Test ==="
echo "Dashboard is accessible at: ${YELLOW}http://localhost:$PORT${NC}"
echo ""
echo "Features to test in browser:"
echo "  ✓ Real-time process table with CPU/memory usage"
echo "  ✓ System metrics (CPU %, Memory usage)"
echo "  ✓ Alert timeline showing fork storms and other incidents"
echo "  ✓ Live updates via Server-Sent Events (SSE)"
echo "  ✓ Sortable process table (by CPU, Memory, Age, PID)"
echo ""

# Results
echo "=== Test Results ==="
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}Some tests failed${NC}"
fi

echo ""
echo "cognitod is running (PID: $COGNITOD_PID)"
echo "View logs: tail -f /tmp/cognitod_ui_test.log"
echo "Stop with: kill $COGNITOD_PID"
echo ""

exit 0
