#!/bin/bash
# Simple manual test for grace period feature
set -e

echo "=================================================================="
echo "  GRACE PERIOD MANUAL TEST"
echo "=================================================================="
echo ""

WORK_DIR=$(mktemp -d)
DB_PATH="$WORK_DIR/incidents.db"
CONFIG_PATH="$WORK_DIR/linnix.toml"

echo "📁 Working directory: $WORK_DIR"
echo "💾 Database: $DB_PATH"
echo ""

# Config with 15s grace period
cat > "$CONFIG_PATH" <<EOF
[circuit_breaker]
enabled = true
cpu_usage_threshold = 60.0
cpu_psi_threshold = 30.0
grace_period_secs = 15
check_interval_secs = 3
require_human_approval = false

[reasoner]
enabled = true
endpoint = "http://localhost:8090/v1/chat/completions"
timeout_ms = 90000

[api]
listen_addr = "127.0.0.1:8080"
EOF

echo "🔨 Building cognitod..."
cargo build --quiet --bin cognitod 2>&1 | grep "Compiling cognitod" || echo "   Build complete"

echo ""
echo "📋 Configuration:"
echo "   Grace Period: 15 seconds"
echo "   CPU Threshold: > 60%"
echo "   PSI Threshold: > 30%"
echo "   Check Interval: every 3s"
echo ""
echo "=================================================================="
echo "  RUNNING COGNITOD"
echo "=================================================================="
echo ""
echo "Watch the logs for:"
echo "   - 'BREACH DETECTED' when thresholds first exceeded"
echo "   - 'BREACH SUSTAINED - Xs/15s' during grace period"
echo "   - 'conditions normalized' if CPU/PSI drops"
echo "   - 'AUTO-KILLED' after 15s of sustained breach"
echo ""
echo "Press Ctrl+C to stop"
echo ""

LINNIX_INCIDENT_DB="$DB_PATH" \
LINNIX_SKIP_CAP_CHECK=1 \
LINNIX_CONFIG="$CONFIG_PATH" \
RUST_LOG=info \
./target/debug/cognitod

# Note: This will run until you Ctrl+C it
