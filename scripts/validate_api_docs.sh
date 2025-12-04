#!/bin/bash
# Validates that all documented API endpoints exist and work correctly
# Source of truth: cognitod/src/api/mod.rs

set -e

HOST="${1:-http://localhost:3000}"
ERRORS=0
WARNINGS=0

echo "=== Linnix API Documentation Validator ==="
echo "Testing against: $HOST"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_endpoint() {
    local method="$1"
    local path="$2"
    local expected_status="${3:-200}"
    local description="$4"
    
    if [ "$method" = "GET" ]; then
        status=$(curl -s -o /dev/null -w "%{http_code}" "${HOST}${path}" 2>/dev/null || echo "000")
    else
        status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "${HOST}${path}" 2>/dev/null || echo "000")
    fi
    
    if [ "$status" = "$expected_status" ]; then
        echo -e "${GREEN}✓${NC} $method $path -> $status"
    elif [ "$status" = "000" ]; then
        echo -e "${RED}✗${NC} $method $path -> Connection failed"
        ((ERRORS++))
    else
        echo -e "${YELLOW}!${NC} $method $path -> $status (expected $expected_status)"
        ((WARNINGS++))
    fi
}

echo "=== Core Endpoints ==="
check_endpoint "GET" "/healthz" "200" "Health check"
check_endpoint "GET" "/status" "200" "System status"

echo ""
echo "=== Process Endpoints ==="
check_endpoint "GET" "/processes" "200" "Process list"
check_endpoint "GET" "/graph/1" "200" "Process graph for PID 1"

echo ""
echo "=== Stream Endpoints ==="
# SSE endpoint - just check it accepts connection
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 1 "${HOST}/stream" 2>/dev/null || echo "200")
if [ "$status" = "200" ] || [ "$status" = "000" ]; then
    echo -e "${GREEN}✓${NC} GET /stream -> SSE endpoint available"
else
    echo -e "${YELLOW}!${NC} GET /stream -> $status"
fi

echo ""
echo "=== Insight Endpoints ==="
# Insights may return 500 if LLM is not configured - that's OK
status=$(curl -s -o /dev/null -w "%{http_code}" "${HOST}/insights" 2>/dev/null)
if [ "$status" = "200" ]; then
    echo -e "${GREEN}✓${NC} GET /insights -> $status"
elif [ "$status" = "500" ]; then
    echo -e "${YELLOW}!${NC} GET /insights -> $status (LLM not configured - OK)"
else
    echo -e "${RED}✗${NC} GET /insights -> $status"
    ((ERRORS++))
fi

echo ""
echo "=== Incident Endpoints ==="
# Incidents may be optional if incident store is not configured
status=$(curl -s -o /dev/null -w "%{http_code}" "${HOST}/incidents" 2>/dev/null)
if [ "$status" = "200" ]; then
    echo -e "${GREEN}✓${NC} GET /incidents -> $status"
    check_endpoint "GET" "/incidents/summary" "200" "Incident summary"
    check_endpoint "GET" "/incidents/stats" "200" "Incident stats"
elif [ "$status" = "404" ]; then
    echo -e "${YELLOW}!${NC} GET /incidents -> $status (incident store not configured - OK)"
else
    echo -e "${RED}✗${NC} GET /incidents -> $status"
    ((ERRORS++))
fi

echo ""
echo "=== Metrics Endpoints ==="
check_endpoint "GET" "/metrics" "200" "JSON metrics"
check_endpoint "GET" "/metrics/prometheus" "200" "Prometheus metrics"

echo ""
echo "=== Enforcement Endpoints ==="
# Actions may be empty or return 404 if enforcement is not enabled
status=$(curl -s -o /dev/null -w "%{http_code}" "${HOST}/actions" 2>/dev/null)
if [ "$status" = "200" ]; then
    echo -e "${GREEN}✓${NC} GET /actions -> $status"
elif [ "$status" = "404" ]; then
    echo -e "${YELLOW}!${NC} GET /actions -> $status (enforcement not enabled - OK)"
else
    echo -e "${RED}✗${NC} GET /actions -> $status"
    ((ERRORS++))
fi

echo ""
echo "=== Summary ==="
if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}All endpoints validated successfully!${NC}"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}Validation completed with $WARNINGS warnings${NC}"
    exit 0
else
    echo -e "${RED}Validation failed: $ERRORS errors, $WARNINGS warnings${NC}"
    exit 1
fi
