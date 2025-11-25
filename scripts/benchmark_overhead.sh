#!/bin/bash
# Benchmark cognitod overhead under various load conditions
set -e

# Configuration
DURATION=30
OUTPUT_FILE="benchmark_results.csv"
COGNITOD_BIN="./target/release/cognitod"

# Check dependencies
if ! command -v stress-ng &> /dev/null; then
    echo "❌ stress-ng not found. Please install it (apt install stress-ng)"
    exit 1
fi
if ! command -v pidstat &> /dev/null; then
    echo "❌ pidstat not found. Please install sysstat (apt install sysstat)"
    exit 1
fi

echo "🔨 Building cognitod (release)..."
cargo build --release --bin cognitod --quiet

# Initialize output
echo "Scenario,Timestamp,CPU_Percent,RSS_KB" > "$OUTPUT_FILE"

run_scenario() {
    local scenario="$1"
    local stress_cmd="$2"
    
    echo "================================================================"
    echo "  SCENARIO: $scenario"
    echo "================================================================"
    
    # Start cognitod in background
    LOG_FILE="cognitod_${scenario}.log"
    echo "   Logs: $LOG_FILE"
    
    # Use random port to avoid conflicts
    PORT=$((3000 + RANDOM % 1000))
    DB_PATH=$(mktemp)
    
    # Create temp config
    CONFIG_FILE="config_${scenario}.toml"
    cp configs/linnix.toml "$CONFIG_FILE"
    sed -i "s/listen_addr = .*/listen_addr = \"127.0.0.1:$PORT\"/" "$CONFIG_FILE"
    # Disable reasoner to measure core overhead
    sed -i "s/enabled = true/enabled = false/" "$CONFIG_FILE"
    
    LINNIX_INCIDENT_DB="$DB_PATH" LINNIX_SKIP_CAP_CHECK=1 LINNIX_CONFIG="$CONFIG_FILE" RUST_LOG=info $COGNITOD_BIN > "$LOG_FILE" 2>&1 &
    COGNITOD_PID=$!
    
    # Wait for startup
    sleep 2
    
    # Start stress load if defined
    STRESS_PID=""
    if [ -n "$stress_cmd" ]; then
        echo "🔥 Starting load: $stress_cmd"
        $stress_cmd --timeout "${DURATION}s" > /dev/null 2>&1 &
        STRESS_PID=$!
    fi
    
    echo "📊 Measuring overhead for ${DURATION}s..."
    
    # Capture raw pidstat for debugging
    RAW_PIDSTAT="pidstat_${scenario}.txt"
    
    # Capture metrics
    # pidstat -p PID -r (memory) -u (cpu) 1 (interval) count
    LC_ALL=C pidstat -p "$COGNITOD_PID" -r -u 1 "$DURATION" | tee "$RAW_PIDSTAT" | \
    awk -v scen="$scenario" '
        # Skip header lines
        /^$/ { next }
        /^Linux/ { next }
        /^Average/ { next }
        /^#/ { next }
        
        # CPU Line (10 fields): ... %wait %CPU CPU Command
        NF == 10 && $8 ~ /^[0-9]/ { 
            cpu=$8 
        }
        
        # Memory Line (9 fields): ... VSZ RSS %MEM Command
        NF == 9 && $7 ~ /^[0-9]/ { 
            rss=$7 
            # Only print if we have a CPU value paired with this RSS
            if (cpu != "") {
                print scen "," systime() "," cpu "," rss
                cpu=""
            }
        }
    ' >> "$OUTPUT_FILE"
    
    # Cleanup
    kill "$COGNITOD_PID" 2>/dev/null || true
    wait "$COGNITOD_PID" 2>/dev/null || true
    
    if [ -n "$STRESS_PID" ]; then
        kill "$STRESS_PID" 2>/dev/null || true
        wait "$STRESS_PID" 2>/dev/null || true
    fi
    
    echo "✅ Scenario complete"
    echo ""
    sleep 2
}

# Run Scenarios
run_scenario "Idle" ""
run_scenario "CPU_Stress" "stress-ng --cpu 4"
run_scenario "Fork_Stress" "stress-ng --fork 4"

echo "================================================================"
echo "  RESULTS SUMMARY"
echo "================================================================"
echo ""
echo "Scenario      | Avg CPU% | Max RSS (MB)"
echo "--------------|----------|-------------"

for scen in Idle CPU_Stress Fork_Stress; do
    avg_cpu=$(grep "$scen" "$OUTPUT_FILE" | awk -F, '{sum+=$3; count++} END {if (count>0) printf "%.2f", sum/count; else print "0"}')
    max_rss=$(grep "$scen" "$OUTPUT_FILE" | awk -F, '{if ($4>max) max=$4} END {printf "%.1f", max/1024}')
    printf "%-13s | %-8s | %s\n" "$scen" "$avg_cpu" "$max_rss"
done

echo ""
echo "Full data saved to $OUTPUT_FILE"
