#!/bin/bash
# Run cognitod natively with BPF LSM support for Claw testing
set -e

cd "$(dirname "$0")"

# Kill any existing cognitod
sudo pkill -f "target/release/cognitod" 2>/dev/null || true
sleep 1

echo "Starting cognitod with BPF LSM support..."
sudo LINNIX_BPF_PATH="$PWD/target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf" \
  LINNIX_LISTEN_ADDR=0.0.0.0:3000 \
  "$PWD/target/release/cognitod" \
  --config "$PWD/configs/linnix.toml" \
  --handler "rules:$PWD/configs/rules.yaml" &

COGNITOD_PID=$!
sleep 3

echo ""
echo "=== Mandate Health ==="
curl -s http://localhost:3000/health/mandate | python3 -m json.tool

echo ""
echo "=== Create Mandate ==="
RESPONSE=$(curl -s -X POST http://localhost:3000/mandates \
  -H 'Content-Type: application/json' \
  -d "{\"pid\": $$, \"args\": [\"/bin/ls\", \"-la\", \"/tmp\"], \"ttl_ms\": 30000}")
echo "$RESPONSE" | python3 -m json.tool
MANDATE_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

echo ""
echo "=== Get Mandate ==="
curl -s "http://localhost:3000/mandates/$MANDATE_ID" | python3 -m json.tool

echo ""
echo "=== Stats ==="
curl -s http://localhost:3000/mandates/stats | python3 -m json.tool

echo ""
echo "=== Receipt for Active Mandate (expect 202) ==="
curl -s -w "\nHTTP %{http_code}\n" "http://localhost:3000/mandates/$MANDATE_ID/receipt"

echo ""
echo "=== Revoke Mandate ==="
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "http://localhost:3000/mandates/$MANDATE_ID")
echo "HTTP $HTTP_CODE"

echo ""
echo "=== Receipt for Revoked Mandate (expect 404) ==="
curl -s -w "\nHTTP %{http_code}\n" "http://localhost:3000/mandates/$MANDATE_ID/receipt"

echo ""
echo "=== Get After Revoke ==="
curl -s "http://localhost:3000/mandates/$MANDATE_ID" | python3 -m json.tool

echo ""
echo "=== Final Stats ==="
curl -s http://localhost:3000/mandates/stats | python3 -m json.tool

echo ""
echo "=== Invalid PID ==="
curl -s -w "\nHTTP %{http_code}\n" -X POST http://localhost:3000/mandates \
  -H 'Content-Type: application/json' \
  -d '{"pid": 999999, "args": ["/bin/ls"], "ttl_ms": 5000}'

echo ""
echo "=== Nonexistent Receipt (expect 404) ==="
curl -s -w "\nHTTP %{http_code}\n" http://localhost:3000/mandates/00000000-0000-0000-0000-000000000000/receipt

echo ""
echo "Smoke test complete! cognitod running as PID $COGNITOD_PID"
echo "Kill with: sudo kill $COGNITOD_PID"
