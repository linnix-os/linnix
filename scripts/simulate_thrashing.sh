#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== Starting End-to-End Circuit Breaker Simulation ===${NC}"

# 1. Setup Environment
WORK_DIR=$(mktemp -d)
echo "Working directory: $WORK_DIR"

PSI_CPU="$WORK_DIR/psi_cpu"
PSI_MEM="$WORK_DIR/psi_mem"
PSI_IO="$WORK_DIR/psi_io"
DB_PATH="$WORK_DIR/incidents.db"
CONFIG_PATH="$WORK_DIR/linnix.toml"

# Initialize PSI files with low pressure
echo "some avg10=0.00 avg60=0.00 avg300=0.00 total=0" > "$PSI_CPU"
echo "some avg10=0.00 avg60=0.00 avg300=0.00 total=0" > "$PSI_MEM"
echo "full avg10=0.00 avg60=0.00 avg300=0.00 total=0" >> "$PSI_MEM"
echo "some avg10=0.00 avg60=0.00 avg300=0.00 total=0" > "$PSI_IO"
echo "full avg10=0.00 avg60=0.00 avg300=0.00 total=0" >> "$PSI_IO"

# Create Config
cat > "$CONFIG_PATH" <<EOF
[circuit_breaker]
enabled = true
cpu_usage_threshold = 10.0
cpu_psi_threshold = 10.0
memory_psi_full_threshold = 10.0
io_psi_full_threshold = 10.0
check_interval_secs = 1
require_human_approval = false

[api]
listen_addr = "127.0.0.1:0"

[logging]
level = "info"
EOF

# 2. Build Cognitod (if needed)
echo "Building cognitod..."
cargo build --quiet --bin cognitod

COGNITOD_BIN="./target/debug/cognitod"

# 3. Start Stressor
echo "Starting CPU stressor..."
yes > /dev/null &
STRESS_PID=$!
echo "Stressor PID: $STRESS_PID"

# 4. Start Cognitod
echo "Starting Cognitod..."
export LINNIX_PSI_CPU_PATH="$PSI_CPU"
export LINNIX_PSI_MEMORY_PATH="$PSI_MEM"
export LINNIX_PSI_IO_PATH="$PSI_IO"
export LINNIX_INCIDENT_DB="$DB_PATH"
export LINNIX_SKIP_CAP_CHECK=1
export LINNIX_CONFIG="$CONFIG_PATH"
export RUST_LOG=info

$COGNITOD_BIN &
COGNITOD_PID=$!
echo "Cognitod PID: $COGNITOD_PID"

# Allow startup
sleep 3

# 5. Trigger Circuit Breaker
echo -e "${GREEN}>>> TRIGGERING HIGH PSI <<<${NC}"
# Write high PSI to file
echo "some avg10=50.00 avg60=0.00 avg300=0.00 total=0" > "$PSI_CPU"

# Wait for detection and kill
echo "Waiting for circuit breaker action..."
for i in {1..10}; do
    if ! kill -0 $STRESS_PID 2>/dev/null; then
        echo -e "${GREEN}SUCCESS: Stressor process $STRESS_PID was killed!${NC}"
        break
    fi
    echo "Stressor still running... ($i/10)"
    sleep 1
done

if kill -0 $STRESS_PID 2>/dev/null; then
    echo -e "${RED}FAILURE: Stressor process was NOT killed.${NC}"
    kill $STRESS_PID
    kill $COGNITOD_PID
    exit 1
fi

# 6. Verify Database
echo "Verifying incident database..."
if [ -f "$DB_PATH" ]; then
    echo "Database exists."
    # We can use sqlite3 CLI if available, or just assume success if file exists and process was killed.
    # Let's try to query if sqlite3 is installed.
    if command -v sqlite3 &> /dev/null; then
        sqlite3 "$DB_PATH" "SELECT * FROM incidents;"
    else
        echo "sqlite3 not found, skipping query verification."
    fi
else
    echo -e "${RED}FAILURE: Incident database not found.${NC}"
    kill $COGNITOD_PID
    exit 1
fi

# Cleanup
echo "Cleaning up..."
kill $COGNITOD_PID
rm -rf "$WORK_DIR"
echo -e "${GREEN}=== Simulation Complete ===${NC}"
