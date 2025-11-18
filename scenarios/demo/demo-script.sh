#!/bin/bash
# Linnix Demo Script - runs all three showcase scenarios

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
LOG_DIR="$REPO_ROOT/logs"
ALERT_LOG="$LOG_DIR/autodemo-alerts.log"

mkdir -p "$LOG_DIR"

echo "======================================"
echo "  Linnix Demo: End-to-End Detection"
echo "======================================"
echo ""
echo "Running memory leak, fork bomb, and FD exhaustion scenarios"
echo "to showcase the alerting pipeline."
echo ""

cleanup() {
    [[ -n "${CURL_PID:-}" ]] && kill "$CURL_PID" 2>/dev/null || true
    docker rm -f demo-memory-leak demo-fork-bomb demo-fd-exhaustion >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_cognitod() {
    if ! curl -sf http://localhost:3000/healthz >/dev/null 2>&1; then
        echo "❌ Cognitod not running on port 3000"
        echo "Please start: ./quickstart.sh"
        exit 1
    fi
    echo "✅ Linnix monitoring is active"
}

ensure_image() {
    local tag=$1
    local path=$2
    if ! docker image inspect "$tag" >/dev/null 2>&1; then
        echo "   📦 Building image $tag"
        docker build -t "$tag" "$path" >/tmp/"${tag//\//_}".build.log 2>&1 || {
            echo "❌ Failed to build $tag (see /tmp/${tag//\//_}.build.log)"
            exit 1
        }
    fi
}

start_alert_listener() {
    echo "📡 Streaming alerts to $ALERT_LOG"
    : > "$ALERT_LOG"
    curl -N http://localhost:3000/alerts 2>/dev/null | while read -r line; do
        if [[ "$line" == data:* ]]; then
            local payload=${line#data: }
            echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) 🚨 ${payload}" | tee -a "$ALERT_LOG"
        fi
    done &
    CURL_PID=$!
}

run_memory_leak() {
    echo "🔥 Launching memory leak scenario (10MB/sec allocations)"
    ensure_image linnix-demo-memory-leak "$REPO_ROOT/scenarios/memory-leak"
    timeout 90s docker run --rm --name demo-memory-leak \
        --memory=200m --memory-reservation=50m \
        linnix-demo-memory-leak:latest >/tmp/demo-memory-leak.log 2>&1 || true
    cat /tmp/demo-memory-leak.log >> "$LOG_DIR/autodemo-workloads.log" 2>/dev/null || true
    sleep 5
}

run_fork_bomb() {
    echo "🍴 Launching fork bomb scenario (100 forks at 50/sec)"
    ensure_image linnix-demo-fork-bomb "$REPO_ROOT/scenarios/fork-bomb"
    timeout 60s docker run --rm --name demo-fork-bomb \
        --pids-limit=200 \
        linnix-demo-fork-bomb:latest >/tmp/demo-fork-bomb.log 2>&1 || true
    cat /tmp/demo-fork-bomb.log >> "$LOG_DIR/autodemo-workloads.log" 2>/dev/null || true
    sleep 5
}

run_fd_exhaustion() {
    echo "📁 Launching FD exhaustion scenario (ulimit 256)"
    ensure_image linnix-demo-fd-exhaustion "$REPO_ROOT/scenarios/fd-exhaustion"
    timeout 60s docker run --rm --name demo-fd-exhaustion \
        --ulimit nofile=256:256 \
        linnix-demo-fd-exhaustion:latest >/tmp/demo-fd-exhaustion.log 2>&1 || true
    cat /tmp/demo-fd-exhaustion.log >> "$LOG_DIR/autodemo-workloads.log" 2>/dev/null || true
    sleep 5
}

wait_for_cognitod
start_alert_listener

run_memory_leak
run_fork_bomb
run_fd_exhaustion

echo "✅ All demo scenarios completed. Alerts captured in $ALERT_LOG"
