#!/bin/bash
# =============================================================================
# White Paper Benchmark Script
# =============================================================================
#
# Generates benchmark data for the paper:
# "The Cost of Causality: High-Frequency, Causal Observability with eBPF Sequencers"
#
# This script runs comprehensive benchmarks at different core counts and
# outputs structured data for generating the paper's graphs.
#
# Prerequisites:
#   - cognitod and sequencer_test binaries built
#   - stress-ng installed
#   - Root/sudo access (required for eBPF and CPU affinity)
#   - jq installed
#
# Usage:
#   sudo ./scripts/benchmark_whitepaper.sh [OPTIONS]
#
# Options:
#   --cores "16,32,64,128,192"   Core counts to test (comma-separated)
#   --duration 30               Duration per test in seconds
#   --iterations 3              Number of iterations per config
#   --output results.json       Output file for results
#   --mode all|perf|sequencer   Which modes to benchmark
#
# The script simulates different core counts using CPU affinity (taskset).
# For accurate 192-core results, run on a c6a.48xlarge or similar.
#
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Defaults
CORE_COUNTS="${CORE_COUNTS:-16,32,64,128}"
DURATION="${DURATION:-30}"
WARMUP="${WARMUP:-5}"
ITERATIONS="${ITERATIONS:-3}"
OUTPUT_FILE="${OUTPUT_FILE:-benchmark_results.json}"
BENCHMARK_MODE="${BENCHMARK_MODE:-all}"

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COGNITOD_BIN="${COGNITOD_BIN:-$PROJECT_ROOT/target/release/cognitod}"
SEQUENCER_TEST_BIN="${SEQUENCER_TEST_BIN:-$PROJECT_ROOT/target/release/sequencer-test}"
BPF_PATH="${BPF_PATH:-$PROJECT_ROOT/target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf}"
LOG_DIR="${LOG_DIR:-$PROJECT_ROOT/logs/whitepaper-benchmark}"
RESULTS_DIR="${RESULTS_DIR:-$PROJECT_ROOT/benchmark-results}"

# Runtime state
TOTAL_CORES=$(nproc)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Logging - all output goes to stderr to avoid polluting JSON results
log_info()    { echo -e "${BLUE}[INFO]${NC} $1" >&2; }
log_success() { echo -e "${GREEN}[OK]${NC} $1" >&2; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1" >&2; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_header()  { echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}" >&2; echo -e "${CYAN}  $1${NC}" >&2; echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}" >&2; }


# =============================================================================
# SETUP & VALIDATION
# =============================================================================

show_usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

White Paper Benchmark Script - Generates publication-quality benchmark data

OPTIONS:
    --cores COUNTS      Comma-separated core counts to test (default: $CORE_COUNTS)
    --duration SEC      Duration per test in seconds (default: $DURATION)
    --warmup SEC        Warmup duration in seconds (default: $WARMUP)
    --iterations N      Iterations per configuration (default: $ITERATIONS)
    --output FILE       Output JSON file (default: $OUTPUT_FILE)
    --mode MODE         Benchmark mode: all, perf, sequencer (default: $BENCHMARK_MODE)
    --help              Show this help message

EXAMPLES:
    # Quick test on local machine
    sudo $0 --cores "4,8,16" --duration 10 --iterations 1

    # Full benchmark for paper (on c6a.48xlarge)
    sudo $0 --cores "16,32,64,128,192" --duration 60 --iterations 5

    # Sequencer-only test
    sudo $0 --mode sequencer --cores "32,64" --iterations 3

OUTPUT:
    Results are saved to a JSON file with the following structure:
    {
      "metadata": { ... },
      "results": [
        { "cores": 16, "mode": "perf", "events_per_sec": [...], ... },
        ...
      ]
    }
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --cores)
                CORE_COUNTS="$2"
                shift 2
                ;;
            --duration)
                DURATION="$2"
                shift 2
                ;;
            --warmup)
                WARMUP="$2"
                shift 2
                ;;
            --iterations)
                ITERATIONS="$2"
                shift 2
                ;;
            --output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            --mode)
                BENCHMARK_MODE="$2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

check_prerequisites() {
    log_header "Checking Prerequisites"
    
    # Check root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script requires root privileges for eBPF and CPU affinity."
        echo "Please run with sudo: sudo $0 $*"
        exit 1
    fi
    
    # Check stress-ng
    if ! command -v stress-ng &> /dev/null; then
        log_error "stress-ng is required but not installed."
        echo "Install with: apt install stress-ng"
        exit 1
    fi
    
    # Check jq
    if ! command -v jq &> /dev/null; then
        log_error "jq is required for JSON processing."
        echo "Install with: apt install jq"
        exit 1
    fi
    
    # Check taskset (for CPU affinity)
    if ! command -v taskset &> /dev/null; then
        log_error "taskset is required for CPU affinity."
        echo "Install with: apt install util-linux"
        exit 1
    fi
    
    # Check/build cognitod
    if [[ ! -x "$COGNITOD_BIN" ]]; then
        log_warn "cognitod binary not found. Building..."
        (cd "$PROJECT_ROOT" && cargo build --release -p cognitod)
    fi
    
    # Check/build sequencer-test
    if [[ ! -x "$SEQUENCER_TEST_BIN" ]]; then
        log_warn "sequencer-test binary not found. Building..."
        (cd "$PROJECT_ROOT" && cargo build --release -p cognitod --bin sequencer-test)
    fi
    
    # Check BPF object
    if [[ ! -f "$BPF_PATH" ]]; then
        log_warn "BPF object not found. Building..."
        (cd "$PROJECT_ROOT" && cargo xtask build-ebpf)
    fi
    
    # Validate core counts against available cores
    log_info "System has $TOTAL_CORES cores"
    for cores in ${CORE_COUNTS//,/ }; do
        if [[ $cores -gt $TOTAL_CORES ]]; then
            log_warn "Requested $cores cores but only $TOTAL_CORES available. Will skip this configuration."
        fi
    done
    
    # Create directories
    mkdir -p "$LOG_DIR" "$RESULTS_DIR"
    
    log_success "Prerequisites check passed"
}

# =============================================================================
# CPU AFFINITY HELPERS
# =============================================================================

# Generate a CPU mask for N cores (cores 0 to N-1)
generate_cpu_mask() {
    local num_cores=$1
    local mask=""
    
    # For small core counts, use explicit list
    if [[ $num_cores -le 64 ]]; then
        # e.g., "0-15" for 16 cores
        mask="0-$((num_cores - 1))"
    else
        # For large counts, use full mask specification
        mask="0-$((num_cores - 1))"
    fi
    
    echo "$mask"
}

# =============================================================================
# BENCHMARK FUNCTIONS
# =============================================================================

cleanup_processes() {
    pkill -9 cognitod 2>/dev/null || true
    pkill -9 sequencer-test 2>/dev/null || true
    pkill -9 stress-ng 2>/dev/null || true
    sleep 2
    
    # Wait for port 3000 to be free
    local retries=0
    while lsof -i:3000 >/dev/null 2>&1; do
        sleep 1
        retries=$((retries + 1))
        if [[ $retries -gt 10 ]]; then
            log_warn "Port 3000 still in use, force killing..."
            fuser -k 3000/tcp >/dev/null 2>&1 || true
            sleep 2
            break
        fi
    done
}



start_cognitod_perf() {
    local cores=$1
    local cpu_mask=$(generate_cpu_mask "$cores")
    local log_file="$LOG_DIR/cognitod_perf_${cores}cores_${TIMESTAMP}.log"
    
    log_info "Starting cognitod (perf buffer mode) on cores 0-$((cores-1))..."
    log_info "Using BPF: $BPF_PATH"
    
    # Start with CPU affinity and explicit BPF path
    LINNIX_BPF_PATH="$BPF_PATH" taskset -c "$cpu_mask" "$COGNITOD_BIN" \
        --config "$PROJECT_ROOT/configs/linnix.toml" \
        > "$log_file" 2>&1 &
    
    COGNITOD_PID=$!
    
    # Wait for API to be ready
    local retries=0
    while ! curl -s "http://localhost:3000/health" > /dev/null 2>&1; do
        sleep 1
        retries=$((retries + 1))
        if [[ $retries -gt 30 ]]; then
            log_error "cognitod failed to start. Check $log_file"
            cat "$log_file" | tail -30
            exit 1
        fi
    done
    
    log_success "cognitod started (PID: $COGNITOD_PID)"
}


start_stress_workload() {
    local cores=$1
    local duration=$2
    local cpu_mask=$(generate_cpu_mask "$cores")
    
    # Fork storm - each fork creates 2 events (fork + exit)
    # Scale workers based on core count
    local workers=$((cores / 2))
    [[ $workers -lt 4 ]] && workers=4
    
    log_info "Starting stress workload: stress-ng --fork $workers on $cores cores for ${duration}s"
    
    taskset -c "$cpu_mask" stress-ng --fork "$workers" --timeout "${duration}s" 2>/dev/null &
    STRESS_PID=$!
}

collect_metrics() {
    local label=$1
    
    local metrics
    metrics=$(curl -s "http://localhost:3000/metrics" 2>/dev/null || echo "{}")
    
    echo "$metrics"
}

run_perf_benchmark() {
    local cores=$1
    local iteration=$2
    local log_file="$LOG_DIR/cognitod_perf_${cores}cores_iter${iteration}_${TIMESTAMP}.log"
    
    log_info "Running perf buffer benchmark: $cores cores, iteration $iteration"
    
    cleanup_processes
    
    local cpu_mask=$(generate_cpu_mask "$cores")
    
    log_info "Starting cognitod (perf buffer mode) on cores 0-$((cores-1))..."
    log_info "Using BPF: $BPF_PATH"
    
    # Start with CPU affinity and explicit BPF path
    LINNIX_BPF_PATH="$BPF_PATH" taskset -c "$cpu_mask" "$COGNITOD_BIN" \
        --config "$PROJECT_ROOT/configs/linnix.toml" \
        > "$log_file" 2>&1 &
    
    COGNITOD_PID=$!
    
    # Wait for cognitod to initialize
    sleep 5
    
    if ! kill -0 $COGNITOD_PID 2>/dev/null; then
        log_error "cognitod failed to start. Check $log_file"
        cat "$log_file" | tail -30
        cleanup_processes
        echo "{\"cores\": $cores, \"mode\": \"perf\", \"iteration\": $iteration, \"events_per_sec\": 0, \"dropped\": 0, \"ordering_violations\": \"n/a\"}"
        return
    fi
    
    log_success "cognitod started (PID: $COGNITOD_PID)"
    
    # Warmup phase
    log_info "Warmup phase (${WARMUP}s)..."
    start_stress_workload "$cores" "$WARMUP"
    sleep "$WARMUP"
    wait $STRESS_PID 2>/dev/null || true
    
    # Count current events in log BEFORE main test
    local start_count
    start_count=$(grep -c '\[event\]' "$log_file" 2>/dev/null) || start_count=0
    start_count=${start_count:-0}
    
    # Main test phase
    log_info "Main test phase (${DURATION}s)..."
    start_stress_workload "$cores" "$DURATION"
    sleep "$DURATION"
    wait $STRESS_PID 2>/dev/null || true
    
    # Count events in log AFTER main test
    local end_count
    end_count=$(grep -c '\[event\]' "$log_file" 2>/dev/null) || end_count=0
    end_count=${end_count:-0}
    
    # Get dropped events from API if available
    local dropped=0
    if curl -s "http://localhost:3000/metrics" > /dev/null 2>&1; then
        dropped=$(curl -s "http://localhost:3000/metrics" | jq -r '.dropped_events_total // 0' 2>/dev/null) || dropped=0
    fi
    dropped=${dropped:-0}
    
    # Calculate events per second - ensure values are integers
    start_count=$(echo "$start_count" | tr -d '[:space:]')
    end_count=$(echo "$end_count" | tr -d '[:space:]')
    local event_delta=$((end_count - start_count))
    local events_per_sec=$((event_delta / DURATION))

    
    cleanup_processes
    
    log_success "Perf buffer: ${events_per_sec} events/sec (${event_delta} events in ${DURATION}s), dropped: ${dropped}"
    
    # Output result as JSON line
    echo "{\"cores\": $cores, \"mode\": \"perf\", \"iteration\": $iteration, \"events_per_sec\": $events_per_sec, \"dropped\": $dropped, \"ordering_violations\": \"n/a\"}"
}



run_sequencer_benchmark() {
    local cores=$1
    local iteration=$2
    
    log_info "Running sequencer benchmark: $cores cores, iteration $iteration"
    
    cleanup_processes
    
    local cpu_mask=$(generate_cpu_mask "$cores")
    local log_file="$LOG_DIR/sequencer_${cores}cores_iter${iteration}_${TIMESTAMP}.log"
    
    # Use sequencer-test binary for accurate ordering validation
    log_info "Starting sequencer-test on cores 0-$((cores-1))..."
    
    # Start sequencer test in background
    taskset -c "$cpu_mask" "$SEQUENCER_TEST_BIN" \
        --bpf-path "$BPF_PATH" \
        --duration "$((WARMUP + DURATION))" \
        --batch-size 1000 \
        > "$log_file" 2>&1 &
    
    local TEST_PID=$!
    sleep 3  # Wait for eBPF to load
    
    # Generate load with CPU affinity
    log_info "Generating workload..."
    start_stress_workload "$cores" "$((WARMUP + DURATION))"
    
    # Wait for test to complete
    wait $TEST_PID 2>/dev/null || true
    wait $STRESS_PID 2>/dev/null || true
    
    # Parse results from log file
    local events_per_sec=0
    local ordering_violations=0
    
    if [[ -f "$log_file" ]]; then
        # Look for the summary lines in the log (handles whitespace: "Events/sec:                 10883")
        events_per_sec=$(grep -oP 'Events/sec:\s*\K[0-9]+' "$log_file" | tail -1 || echo "0")
        ordering_violations=$(grep -oP 'Ordering Violations:\s*\K[0-9]+' "$log_file" | tail -1 || echo "0")
        
        # Alternative: parse from the final success message
        if [[ -z "$events_per_sec" || "$events_per_sec" == "0" ]]; then
            events_per_sec=$(grep -oP 'All \K[0-9]+(?= events processed)' "$log_file" | tail -1 || echo "0")
            if [[ -n "$events_per_sec" && "$events_per_sec" != "0" ]]; then
                # Calculate from total / duration
                local duration_match=$(grep -oP 'Duration:\s*\K[0-9.]+' "$log_file" | tail -1 || echo "0")
                if [[ -n "$duration_match" && "$duration_match" != "0" ]]; then
                    events_per_sec=$(echo "$events_per_sec / $duration_match" | bc 2>/dev/null || echo "0")
                fi
            fi
        fi
        
        # Check for violation messages
        if grep -q "ORDERING VIOLATION" "$log_file"; then
            ordering_violations=$(grep -c "ORDERING VIOLATION" "$log_file" || echo "0")
        fi
    fi
    
    [[ -z "$events_per_sec" ]] && events_per_sec=0
    [[ -z "$ordering_violations" ]] && ordering_violations=0
    
    cleanup_processes
    
    log_success "Sequencer: ${events_per_sec} events/sec, ${ordering_violations} ordering violations"
    
    echo "{\"cores\": $cores, \"mode\": \"sequencer\", \"iteration\": $iteration, \"events_per_sec\": $events_per_sec, \"dropped\": 0, \"ordering_violations\": $ordering_violations}"
}


# =============================================================================
# MAIN BENCHMARK LOOP
# =============================================================================

run_benchmarks() {
    log_header "Starting Benchmark Suite"
    
    local results_file="$RESULTS_DIR/raw_results_${TIMESTAMP}.jsonl"
    echo "" > "$results_file"
    
    # Parse core counts
    IFS=',' read -ra CORES_ARRAY <<< "$CORE_COUNTS"
    
    local total_tests=$((${#CORES_ARRAY[@]} * ITERATIONS * 2))
    if [[ "$BENCHMARK_MODE" != "all" ]]; then
        total_tests=$((${#CORES_ARRAY[@]} * ITERATIONS))
    fi
    
    local current_test=0
    
    for cores in "${CORES_ARRAY[@]}"; do
        # Skip if we don't have enough cores
        if [[ $cores -gt $TOTAL_CORES ]]; then
            log_warn "Skipping $cores cores (system has only $TOTAL_CORES)"
            continue
        fi
        
        log_header "Benchmarking with $cores cores"
        
        for ((i=1; i<=ITERATIONS; i++)); do
            # Perf buffer mode
            if [[ "$BENCHMARK_MODE" == "all" || "$BENCHMARK_MODE" == "perf" ]]; then
                current_test=$((current_test + 1))
                log_info "Test $current_test/$total_tests"
                run_perf_benchmark "$cores" "$i" >> "$results_file"
            fi
            
            # Sequencer mode
            if [[ "$BENCHMARK_MODE" == "all" || "$BENCHMARK_MODE" == "sequencer" ]]; then
                current_test=$((current_test + 1))
                log_info "Test $current_test/$total_tests"
                run_sequencer_benchmark "$cores" "$i" >> "$results_file"
            fi
        done
    done
    
    # Generate final JSON output
    generate_final_report "$results_file"
}

generate_final_report() {
    local raw_file=$1
    local output_path="$RESULTS_DIR/$OUTPUT_FILE"
    
    log_header "Generating Final Report"
    
    # Create metadata
    local metadata
    metadata=$(cat << EOF
{
    "timestamp": "$(date -Iseconds)",
    "system": {
        "hostname": "$(hostname)",
        "kernel": "$(uname -r)",
        "total_cores": $TOTAL_CORES,
        "cpu_model": "$(lscpu | grep 'Model name' | cut -d: -f2 | xargs || echo 'unknown')"
    },
    "config": {
        "core_counts_tested": "$CORE_COUNTS",
        "duration_per_test": $DURATION,
        "warmup_duration": $WARMUP,
        "iterations": $ITERATIONS,
        "benchmark_mode": "$BENCHMARK_MODE"
    }
}
EOF
)
    
    # Aggregate results by cores and mode
    local aggregated
    aggregated=$(cat "$raw_file" | jq -s '
        sort_by([.cores, .mode]) |
        group_by([.cores, .mode]) | 
        map({
            cores: .[0].cores,
            mode: .[0].mode,
            events_per_sec_mean: ([.[].events_per_sec] | add / length),
            events_per_sec_min: ([.[].events_per_sec] | min),
            events_per_sec_max: ([.[].events_per_sec] | max),
            events_per_sec_all: [.[].events_per_sec],
            dropped_total: ([.[].dropped] | add),
            ordering_violations_total: ([.[].ordering_violations | select(type == "number")] | add // 0),
            iterations: length
        })
    ')
    
    # Combine into final report
    jq -n --argjson metadata "$metadata" --argjson results "$aggregated" '{
        metadata: $metadata,
        results: $results
    }' > "$output_path"
    
    log_success "Report saved to: $output_path"
    
    # Print summary table
    log_header "Benchmark Summary"
    echo ""
    printf "%-8s %-12s %-15s %-15s %-12s\n" "Cores" "Mode" "Events/sec" "Range" "Violations"
    printf "%-8s %-12s %-15s %-15s %-12s\n" "-----" "----" "----------" "-----" "----------"
    
    echo "$aggregated" | jq -r '.[] | [.cores, .mode, .events_per_sec_mean, "\(.events_per_sec_min)-\(.events_per_sec_max)", .ordering_violations_total] | @tsv' | \
    while IFS=$'\t' read -r cores mode mean range violations; do
        printf "%-8s %-12s %-15.0f %-15s %-12s\n" "$cores" "$mode" "$mean" "$range" "$violations"
    done
    
    echo ""
    log_info "Raw results: $raw_file"
    log_info "Final report: $output_path"
}

# =============================================================================
# ENTRY POINT
# =============================================================================

main() {
    parse_args "$@"
    check_prerequisites
    
    log_header "White Paper Benchmark Suite"
    log_info "Configuration:"
    log_info "  Core counts: $CORE_COUNTS"
    log_info "  Duration: ${DURATION}s per test"
    log_info "  Warmup: ${WARMUP}s"
    log_info "  Iterations: $ITERATIONS"
    log_info "  Mode: $BENCHMARK_MODE"
    log_info "  Output: $OUTPUT_FILE"
    
    run_benchmarks
    
    log_header "Benchmark Complete"
    log_success "Results ready for white paper!"
}

# Trap for cleanup on exit
trap cleanup_processes EXIT

main "$@"
