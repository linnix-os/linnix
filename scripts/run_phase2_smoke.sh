#!/bin/bash
# Run cognitod + demo_claw.sh smoke test
# Usage: sudo bash scripts/run_phase2_smoke.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# Kill lingering cognitod
pkill -f "target/release/cognitod" 2>/dev/null || true
sleep 1

echo "Starting cognitod..."
LINNIX_BPF_PATH=target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf \
  LINNIX_LISTEN_ADDR=0.0.0.0:3000 \
  ./target/release/cognitod --config configs/linnix.toml \
  --handler rules:configs/rules.yaml &
PID=$!

cleanup() { kill $PID 2>/dev/null || true; wait $PID 2>/dev/null || true; }
trap cleanup EXIT

# Wait for startup
for i in $(seq 1 15); do
    if curl -sf http://localhost:3000/healthz >/dev/null 2>&1; then
        echo "cognitod ready (pid $PID)"
        break
    fi
    [[ $i -eq 15 ]] && { echo "TIMEOUT"; exit 1; }
    sleep 1
done

echo ""
bash scripts/demo_claw.sh
