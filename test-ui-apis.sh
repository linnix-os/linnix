#!/bin/bash
# UI Dashboard API Test Script
# Tests all Phase 1 APIs with fake-events data

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Linnix UI Dashboard API Test Suite ===${NC}\n"

# 1. Build with fake-events
echo -e "${YELLOW}[1/6] Building cognitod with fake-events feature...${NC}"
cargo build --release --package cognitod --features fake-events 2>&1 | tail -3
echo -e "${GREEN}✓ Build complete${NC}\n"

# 2. Set capabilities
echo -e "${YELLOW}[2/6] Setting capabilities...${NC}"
sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep ./target/release/cognitod
echo -e "${GREEN}✓ Capabilities set${NC}\n"

# 3. Stop old process if running
echo -e "${YELLOW}[3/6] Stopping old cognitod instances...${NC}"
if [ -f /tmp/cognitod_test.pid ]; then
    OLD_PID=$(cat /tmp/cognitod_test.pid)
    if kill -0 $OLD_PID 2>/dev/null; then
        kill $OLD_PID
        sleep 1
    fi
fi
pkill -f "target/release/cognitod" || true
sleep 2
echo -e "${GREEN}✓ Old instances stopped${NC}\n"

# 4. Start cognitod with fake-events
echo -e "${YELLOW}[4/6] Starting cognitod with fake-events...${NC}"
./target/release/cognitod --demo fork-storm > /tmp/cognitod_test.log 2>&1 &
COGNITOD_PID=$!
echo $COGNITOD_PID > /tmp/cognitod_test.pid
echo -e "${GREEN}✓ Started cognitod with --demo fork-storm (PID: $COGNITOD_PID)${NC}"

# Wait for startup and data population
echo -e "${YELLOW}Waiting 8 seconds for fake events to populate...${NC}"
sleep 8

# 5. Test all APIs
echo -e "\n${YELLOW}[5/6] Testing all API endpoints...${NC}\n"

API_BASE="http://localhost:3000"
PASS=0
FAIL=0

# Helper function to test endpoint
test_endpoint() {
    local name=$1
    local url=$2
    local expected_field=$3

    echo -e "${YELLOW}Testing: ${name}${NC}"
    echo "  URL: $url"

    RESPONSE=$(curl -s "$url")
    STATUS=$?

    if [ $STATUS -eq 0 ]; then
        if [ -n "$expected_field" ]; then
            if echo "$RESPONSE" | jq -e "$expected_field" > /dev/null 2>&1; then
                echo -e "  ${GREEN}✓ PASS${NC} - Response valid"
                echo "  Sample: $(echo "$RESPONSE" | jq -c "$expected_field" 2>/dev/null | head -c 80)..."
                PASS=$((PASS + 1))
            else
                echo -e "  ${RED}✗ FAIL${NC} - Expected field not found: $expected_field"
                FAIL=$((FAIL + 1))
            fi
        else
            echo -e "  ${GREEN}✓ PASS${NC} - Response received"
            PASS=$((PASS + 1))
        fi
    else
        echo -e "  ${RED}✗ FAIL${NC} - Request failed"
        FAIL=$((FAIL + 1))
    fi
    echo ""
}

# Test each endpoint
test_endpoint "GET /healthz" "$API_BASE/healthz" ".status"
test_endpoint "GET /status" "$API_BASE/status" ".version"
test_endpoint "GET /metrics/system" "$API_BASE/metrics/system" ".cpu_total_pct"
test_endpoint "GET /processes" "$API_BASE/processes" ".[0].pid"
test_endpoint "GET /processes (filtered)" "$API_BASE/processes?filter=cpu_pct>0" ".[]"
test_endpoint "GET /processes (sorted)" "$API_BASE/processes?sort=cpu_pct:desc" ".[0].cpu_pct"
test_endpoint "GET /timeline" "$API_BASE/timeline" "."
test_endpoint "GET /system" "$API_BASE/system" ".cpu_percent"

# Test specific PID (get first PID from processes)
echo -e "${YELLOW}Testing: GET /processes/{pid}${NC}"
FIRST_PID=$(curl -s "$API_BASE/processes" | jq -r '.[0].pid' 2>/dev/null)
if [ -n "$FIRST_PID" ] && [ "$FIRST_PID" != "null" ]; then
    echo "  URL: $API_BASE/processes/$FIRST_PID"
    RESPONSE=$(curl -s "$API_BASE/processes/$FIRST_PID")
    if echo "$RESPONSE" | jq -e '.pid' > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓ PASS${NC} - Retrieved process PID $FIRST_PID"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗ FAIL${NC} - Invalid response"
        FAIL=$((FAIL + 1))
    fi
else
    echo -e "  ${YELLOW}⊘ SKIP${NC} - No processes available"
fi
echo ""

# Test SSE endpoint
echo -e "${YELLOW}Testing: GET /processes/live (SSE)${NC}"
echo "  URL: $API_BASE/processes/live"
echo "  Streaming for 5 seconds..."
timeout 5 curl -N -s "$API_BASE/processes/live" > /tmp/sse_test.txt 2>&1 || true
if grep -q "event: processes" /tmp/sse_test.txt; then
    echo -e "  ${GREEN}✓ PASS${NC} - SSE stream working"
    echo "  Events received: $(grep -c "event: processes" /tmp/sse_test.txt)"
    PASS=$((PASS + 1))
else
    echo -e "  ${RED}✗ FAIL${NC} - No SSE events received"
    FAIL=$((FAIL + 1))
fi
echo ""

# Test alert detail (if alerts exist)
echo -e "${YELLOW}Testing: GET /alerts/{id}${NC}"
FIRST_ALERT=$(curl -s "$API_BASE/timeline" | jq -r '.[0].id' 2>/dev/null)
if [ -n "$FIRST_ALERT" ] && [ "$FIRST_ALERT" != "null" ]; then
    echo "  URL: $API_BASE/alerts/$FIRST_ALERT"
    RESPONSE=$(curl -s "$API_BASE/alerts/$FIRST_ALERT")
    if echo "$RESPONSE" | jq -e '.remediation' > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓ PASS${NC} - Retrieved alert detail with remediation"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗ FAIL${NC} - Invalid response"
        FAIL=$((FAIL + 1))
    fi
else
    echo -e "  ${YELLOW}⊘ SKIP${NC} - No alerts available yet (fake-events may need more time)"
fi
echo ""

# 6. Summary and sample data
echo -e "${YELLOW}[6/6] Summary and Sample Data${NC}\n"

echo -e "${GREEN}=== Test Results ===${NC}"
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}\n"
else
    echo -e "${RED}✗ Some tests failed${NC}\n"
fi

echo -e "${GREEN}=== Sample Data ===${NC}\n"

echo "System Metrics:"
curl -s "$API_BASE/metrics/system" | jq '.'
echo ""

echo "Process Count:"
PROC_COUNT=$(curl -s "$API_BASE/processes" | jq 'length')
echo "$PROC_COUNT processes tracked"
echo ""

echo "Top 3 Processes by CPU:"
curl -s "$API_BASE/processes?sort=cpu_pct:desc" | jq '.[0:3] | .[] | {pid, comm, cpu_pct, mem_pct}'
echo ""

echo "Alert Timeline (last 3):"
curl -s "$API_BASE/timeline" | jq '.[0:3] | .[] | {id, timestamp, severity, rule, message}'
echo ""

echo -e "${GREEN}=== Logs ===${NC}"
echo "Cognitod logs: /tmp/cognitod_test.log"
echo "Cognitod PID: $COGNITOD_PID (saved to /tmp/cognitod_test.pid)"
echo ""

echo -e "${YELLOW}To stop cognitod: kill $COGNITOD_PID${NC}"
echo -e "${YELLOW}To view logs: tail -f /tmp/cognitod_test.log${NC}"
echo -e "${YELLOW}To test manually: curl http://localhost:3000/processes | jq${NC}"
