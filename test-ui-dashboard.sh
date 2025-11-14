#!/bin/bash
set -e

echo "=== Testing Linnix UI Dashboard ==="
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

# Set capabilities if needed
if ! getcap "$BINARY" | grep -q cap_sys_admin; then
    echo "Setting capabilities on binary..."
    sudo setcap cap_sys_admin,cap_bpf,cap_net_admin,cap_perfmon+eip "$BINARY" 2>/dev/null || \
        sudo setcap cap_sys_admin+eip "$BINARY"
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
echo "Dashboard should be accessible at: ${YELLOW}http://localhost:$PORT${NC}"
echo ""
echo "To test in browser:"
echo "  1. Open: http://localhost:$PORT"
echo "  2. You should see live process monitoring dashboard"
echo "  3. Check for real-time updates in the process table"
echo "  4. Look for alerts in the timeline section"
echo ""

# Results
echo "=== Results ==="
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}Some tests failed${NC}"
fi

echo ""
echo "cognitod is still running (PID: $COGNITOD_PID)"
echo "View logs: tail -f /tmp/cognitod_ui_test.log"
echo "Stop with: kill $COGNITOD_PID"
echo ""
echo "Press Ctrl+C to exit (cognitod will keep running)"
echo "Or press Enter to view the dashboard in the terminal..."
read

# Show a sample of the dashboard HTML
echo ""
echo "=== Dashboard Preview ==="
curl -s "$BASE_URL/" | head -30
echo "..."

exit 0
