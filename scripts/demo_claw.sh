#!/bin/bash
# =============================================================================
# scripts/demo_claw.sh — Linnix-Claw Phase 2 Demo Script
# =============================================================================
#
# Exercises all mandate/receipt/agent-card API endpoints.
# Requires cognitod running on localhost:3000.
#
# Usage:
#   # Start cognitod first (needs BPF, run as root):
#   sudo LINNIX_BPF_PATH=target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf \
#     LINNIX_LISTEN_ADDR=0.0.0.0:3000 \
#     ./target/release/cognitod --config configs/linnix.toml \
#     --handler rules:configs/rules.yaml
#
#   # Then run demo:
#   bash scripts/demo_claw.sh
#
set -euo pipefail

BASE_URL="${LINNIX_API_URL:-http://localhost:3000}"
PASS=0
FAIL=0

# Colors (if terminal supports them)
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

check() {
    local label="$1"
    local expected_code="$2"
    local actual_code="$3"

    if [[ "$actual_code" == "$expected_code" ]]; then
        echo -e "  ${GREEN}✓${NC} ${label} (HTTP ${actual_code})"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${NC} ${label} — expected HTTP ${expected_code}, got ${actual_code}"
        FAIL=$((FAIL + 1))
    fi
}

# ── Wait for cognitod ────────────────────────────────────────────────────────
echo -e "${CYAN}Waiting for cognitod at ${BASE_URL}...${NC}"
for i in $(seq 1 10); do
    if curl -sf "${BASE_URL}/healthz" >/dev/null 2>&1; then
        break
    fi
    if [[ $i -eq 10 ]]; then
        echo "ERROR: cognitod not reachable at ${BASE_URL}"
        exit 1
    fi
    sleep 1
done
echo ""

# ── 1. Health ────────────────────────────────────────────────────────────────
echo -e "${CYAN}1. GET /health/mandate${NC}"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/health/mandate")
check "mandate health" "200" "$CODE"
curl -s "${BASE_URL}/health/mandate" | python3 -m json.tool
echo ""

# ── 2. Agent Card ────────────────────────────────────────────────────────────
echo -e "${CYAN}2. GET /.well-known/agent-card.json${NC}"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/.well-known/agent-card.json")
check "agent card" "200" "$CODE"
CARD=$(curl -s "${BASE_URL}/.well-known/agent-card.json")
echo "$CARD" | python3 -m json.tool
# Verify x-linnix-claw extension present
echo "$CARD" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'x-linnix-claw' in d, 'missing x-linnix-claw'" && \
    echo -e "  ${GREEN}✓${NC} x-linnix-claw extension present" && PASS=$((PASS + 1)) || \
    (echo -e "  ${RED}✗${NC} x-linnix-claw extension missing" && FAIL=$((FAIL + 1)))
echo ""

# ── 3. Create Mandate ───────────────────────────────────────────────────────
echo -e "${CYAN}3. POST /mandates${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/mandates" \
    -H 'Content-Type: application/json' \
    -d "{\"pid\": 1, \"args\": [\"/bin/ls\", \"-la\", \"/tmp\"], \"ttl_ms\": 60000}")
BODY=$(echo "$RESPONSE" | head -n -1)
CODE=$(echo "$RESPONSE" | tail -n 1)
check "create mandate" "201" "$CODE"
echo "$BODY" | python3 -m json.tool
MANDATE_ID=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")
echo ""

# ── 4. Get Mandate ──────────────────────────────────────────────────────────
echo -e "${CYAN}4. GET /mandates/{id}${NC}"
if [[ -n "$MANDATE_ID" ]]; then
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/mandates/${MANDATE_ID}")
    check "get mandate" "200" "$CODE"
    curl -s "${BASE_URL}/mandates/${MANDATE_ID}" | python3 -m json.tool
else
    echo -e "  ${RED}✗${NC} skipped (no mandate_id)"
    FAIL=$((FAIL + 1))
fi
echo ""

# ── 5. List Mandates ────────────────────────────────────────────────────────
echo -e "${CYAN}5. GET /mandates${NC}"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/mandates")
check "list mandates" "200" "$CODE"
curl -s "${BASE_URL}/mandates" | python3 -m json.tool
echo ""

# ── 6. Mandate Stats ────────────────────────────────────────────────────────
echo -e "${CYAN}6. GET /mandates/stats${NC}"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/mandates/stats")
check "mandate stats" "200" "$CODE"
curl -s "${BASE_URL}/mandates/stats" | python3 -m json.tool
echo ""

# ── 7. Receipt for Active Mandate (expect 202) ──────────────────────────────
echo -e "${CYAN}7. GET /mandates/{id}/receipt (active → 202)${NC}"
if [[ -n "$MANDATE_ID" ]]; then
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/mandates/${MANDATE_ID}/receipt")
    check "receipt (active→202)" "202" "$CODE"
    curl -s "${BASE_URL}/mandates/${MANDATE_ID}/receipt" | python3 -m json.tool
else
    echo -e "  ${RED}✗${NC} skipped"
    FAIL=$((FAIL + 1))
fi
echo ""

# ── 8. Batch Create ─────────────────────────────────────────────────────────
echo -e "${CYAN}8. POST /mandates/batch${NC}"
BATCH_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/mandates/batch" \
    -H 'Content-Type: application/json' \
    -d "{\"mandates\": [
        {\"pid\": 1, \"args\": [\"/usr/bin/curl\", \"https://example.com\"], \"ttl_ms\": 30000},
        {\"pid\": 1, \"args\": [\"/usr/bin/python3\", \"script.py\"], \"ttl_ms\": 30000},
        {\"pid\": 999999, \"args\": [\"/bin/false\"], \"ttl_ms\": 5000}
    ]}")
BATCH_BODY=$(echo "$BATCH_RESPONSE" | head -n -1)
BATCH_CODE=$(echo "$BATCH_RESPONSE" | tail -n 1)
check "batch create" "200" "$BATCH_CODE"
echo "$BATCH_BODY" | python3 -m json.tool
# Verify partial success (2 ok, 1 failed for PID 999999)
echo "$BATCH_BODY" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['succeeded'] >= 2, f'expected >=2 succeeded, got {d[\"succeeded\"]}'
assert d['failed'] >= 1, f'expected >=1 failed, got {d[\"failed\"]}'
" && echo -e "  ${GREEN}✓${NC} batch partial success verified" && PASS=$((PASS + 1)) || \
    (echo -e "  ${RED}✗${NC} batch result mismatch" && FAIL=$((FAIL + 1)))
echo ""

# ── 9. Revoke Mandate ───────────────────────────────────────────────────────
echo -e "${CYAN}9. DELETE /mandates/{id}${NC}"
if [[ -n "$MANDATE_ID" ]]; then
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${BASE_URL}/mandates/${MANDATE_ID}")
    check "revoke mandate" "204" "$CODE"
else
    echo -e "  ${RED}✗${NC} skipped"
    FAIL=$((FAIL + 1))
fi
echo ""

# ── 10. Receipt for Revoked (expect 404) ────────────────────────────────────
echo -e "${CYAN}10. GET /mandates/{id}/receipt (revoked → 404)${NC}"
if [[ -n "$MANDATE_ID" ]]; then
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/mandates/${MANDATE_ID}/receipt")
    check "receipt (revoked→404)" "404" "$CODE"
else
    echo -e "  ${RED}✗${NC} skipped"
    FAIL=$((FAIL + 1))
fi
echo ""

# ── 11. Receipt for nonexistent (expect 404) ────────────────────────────────
echo -e "${CYAN}11. GET /mandates/nonexistent/receipt (404)${NC}"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/mandates/00000000-0000-0000-0000-000000000000/receipt")
check "receipt (nonexistent→404)" "404" "$CODE"
echo ""

# ── 12. Final Stats ─────────────────────────────────────────────────────────
echo -e "${CYAN}12. GET /mandates/stats (final)${NC}"
curl -s "${BASE_URL}/mandates/stats" | python3 -m json.tool
echo ""

# ── Summary ──────────────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL))
echo "=============================================="
if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}ALL ${TOTAL} CHECKS PASSED${NC}"
else
    echo -e "${RED}${FAIL}/${TOTAL} CHECKS FAILED${NC}"
fi
echo "=============================================="

exit $FAIL
