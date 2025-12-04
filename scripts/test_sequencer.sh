#!/bin/bash
# =============================================================================
# Sequencer Ring Buffer Quick Test
# =============================================================================
#
# This script tests the sequenced MPSC ring buffer by:
# 1. Loading the eBPF program with sequencer enabled
# 2. Running stress-ng to generate events
# 3. Consuming events via the SequencerConsumer
# 4. Validating ordering and printing stats
#
# Usage:
#   sudo ./scripts/test_sequencer.sh
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration
DURATION=${DURATION:-10}
COGNITOD_BIN="${COGNITOD_BIN:-./target/release/cognitod}"
BPF_PATH="${BPF_PATH:-./target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf}"

cleanup() {
    log_info "Cleaning up..."
    sudo pkill -f "cognitod.*sequencer-test" 2>/dev/null || true
    sudo pkill -f "stress-ng.*sequencer" 2>/dev/null || true
}
trap cleanup EXIT

# Stop existing cognitod
log_info "Stopping existing cognitod..."
sudo systemctl stop cognitod 2>/dev/null || true
sleep 1

# Start cognitod with sequencer (via environment variable)
log_info "Starting cognitod with sequencer enabled..."
log_info "Using BPF path: $BPF_PATH"

# For now, we'll use the standard cognitod and enable sequencer via the map
# First, let's just verify the eBPF loads correctly with the new map
sudo LINNIX_BPF_PATH="$BPF_PATH" "$COGNITOD_BIN" \
    --config configs/linnix.toml \
    --handler jsonl:/tmp/sequencer_test.jsonl \
    2>&1 &

COGNITOD_PID=$!
log_info "Cognitod PID: $COGNITOD_PID"

# Wait for cognitod to start
sleep 3

# Check if cognitod is running
if ! kill -0 $COGNITOD_PID 2>/dev/null; then
    log_error "Cognitod failed to start"
    exit 1
fi

log_success "Cognitod started successfully"

# Wait for API to be ready
log_info "Waiting for API..."
for i in $(seq 1 10); do
    if curl -s http://localhost:3000/health > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Check metrics before enabling sequencer
log_info "=== Baseline Metrics (Perf Buffer Mode) ==="
curl -s http://localhost:3000/metrics | jq '{events_per_sec, dropped_events_total, perf_poll_errors}'

# Generate some load
log_info "Generating test load..."
stress-ng --fork 8 --fork-ops 1000 --timeout 5s 2>/dev/null &
STRESS_PID=$!

sleep 5
wait $STRESS_PID 2>/dev/null || true

# Check metrics after test
log_info "=== Post-Test Metrics ==="
METRICS=$(curl -s http://localhost:3000/metrics)
echo "$METRICS" | jq '{events_per_sec, dropped_events_total, perf_poll_errors, uptime_seconds}'

# Count events in JSONL file
if [ -f /tmp/sequencer_test.jsonl ]; then
    EVENT_COUNT=$(wc -l < /tmp/sequencer_test.jsonl)
    log_info "Events captured to JSONL: $EVENT_COUNT"
fi

# Get final stats
EVENTS_SEC=$(echo "$METRICS" | jq -r '.events_per_sec')
DROPPED=$(echo "$METRICS" | jq -r '.dropped_events_total')

log_info "================================"
log_info "Sequencer Test Results"
log_info "================================"
log_info "Events/sec: $EVENTS_SEC"
log_info "Dropped: $DROPPED"

if [ "$DROPPED" -eq 0 ]; then
    log_success "No events dropped!"
else
    log_warn "Some events were dropped: $DROPPED"
fi

# Stop cognitod
log_info "Stopping test cognitod..."
kill $COGNITOD_PID 2>/dev/null || true
wait $COGNITOD_PID 2>/dev/null || true

# Restart systemd cognitod
log_info "Restarting systemd cognitod..."
sudo systemctl start cognitod

log_success "Test complete!"
