#!/bin/bash
# =============================================================================
# Sequencer Ring Buffer Benchmark
# =============================================================================
#
# This script benchmarks the custom MPSC sequencer ring buffer against
# standard perf buffers to validate the performance improvements.
#
# Prerequisites:
#   - cognitod built and accessible
#   - Root/sudo access (required for eBPF)
#   - stress-ng installed (apt install stress-ng)
#
# Usage:
#   sudo ./scripts/benchmark_sequencer.sh [--sequencer|--perf] [--duration SECONDS]
#
# =============================================================================

set -e

# Configuration
DURATION=${DURATION:-30}
WARMUP=${WARMUP:-5}
COGNITOD_URL="${COGNITOD_URL:-http://localhost:3000}"
COGNITOD_BIN="${COGNITOD_BIN:-./target/release/cognitod}"
LOG_DIR="${LOG_DIR:-./logs/benchmark}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check for root
    if [ "$EUID" -ne 0 ]; then
        log_error "This script requires root privileges for eBPF operations."
        echo "Please run with sudo: sudo $0 $*"
        exit 1
    fi
    
    # Check for stress-ng
    if ! command -v stress-ng &> /dev/null; then
        log_error "stress-ng is required but not installed."
        echo "Install with: apt install stress-ng"
        exit 1
    fi
    
    # Check for cognitod binary
    if [ ! -x "$COGNITOD_BIN" ]; then
        log_warn "cognitod binary not found at $COGNITOD_BIN"
        log_info "Building cognitod..."
        cargo build --release -p cognitod
    fi
    
    # Check for jq
    if ! command -v jq &> /dev/null; then
        log_error "jq is required for JSON parsing."
        echo "Install with: apt install jq"
        exit 1
    fi
    
    mkdir -p "$LOG_DIR"
    log_success "Prerequisites check passed"
}

start_cognitod() {
    local mode=$1
    log_info "Starting cognitod in $mode mode..."
    
    # Kill any existing cognitod
    pkill -9 cognitod 2>/dev/null || true
    sleep 1
    
    # Start cognitod with appropriate mode
    if [ "$mode" == "sequencer" ]; then
        # Enable sequencer mode (when implemented)
        SEQUENCER_ENABLED=1 $COGNITOD_BIN \
            --config configs/linnix.toml \
            2>&1 | tee "$LOG_DIR/cognitod_${mode}.log" &
    else
        # Standard perf buffer mode
        $COGNITOD_BIN \
            --config configs/linnix.toml \
            2>&1 | tee "$LOG_DIR/cognitod_${mode}.log" &
    fi
    
    COGNITOD_PID=$!
    
    # Wait for cognitod to be ready
    log_info "Waiting for cognitod to initialize..."
    sleep 3
    
    # Check if cognitod is running
    if ! kill -0 $COGNITOD_PID 2>/dev/null; then
        log_error "cognitod failed to start. Check $LOG_DIR/cognitod_${mode}.log"
        exit 1
    fi
    
    # Wait for API to be available
    local retries=0
    while ! curl -s "$COGNITOD_URL/health" > /dev/null 2>&1; do
        sleep 1
        retries=$((retries + 1))
        if [ $retries -gt 30 ]; then
            log_error "cognitod API not responding after 30 seconds"
            exit 1
        fi
    done
    
    log_success "cognitod started (PID: $COGNITOD_PID)"
}

stop_cognitod() {
    log_info "Stopping cognitod..."
    if [ -n "$COGNITOD_PID" ]; then
        kill -TERM $COGNITOD_PID 2>/dev/null || true
        wait $COGNITOD_PID 2>/dev/null || true
    fi
    pkill -9 cognitod 2>/dev/null || true
    sleep 1
}

run_workload() {
    local name=$1
    local cmd=$2
    local duration=$3
    
    log_info "Running workload: $name"
    log_info "Command: $cmd"
    log_info "Duration: ${duration}s"
    
    # Run the workload
    eval "$cmd" &
    WORKLOAD_PID=$!
    
    # Wait for completion
    sleep "$duration"
    
    # Stop workload
    kill -TERM $WORKLOAD_PID 2>/dev/null || true
    wait $WORKLOAD_PID 2>/dev/null || true
    
    log_success "Workload $name completed"
}

capture_metrics() {
    local mode=$1
    local phase=$2
    
    # Capture metrics from cognitod
    local metrics_file="$LOG_DIR/metrics_${mode}_${phase}.json"
    
    if curl -s "$COGNITOD_URL/metrics" > "$metrics_file" 2>/dev/null; then
        log_info "Metrics captured to $metrics_file"
    else
        log_warn "Failed to capture metrics"
        echo "{}" > "$metrics_file"
    fi
    
    echo "$metrics_file"
}

calculate_throughput() {
    local start_file=$1
    local end_file=$2
    local duration=$3
    
    # Extract event counts
    local start_count=$(jq -r '.events_processed_total // 0' "$start_file" 2>/dev/null || echo "0")
    local end_count=$(jq -r '.events_processed_total // 0' "$end_file" 2>/dev/null || echo "0")
    
    # Calculate throughput
    local delta=$((end_count - start_count))
    local rate=$((delta / duration))
    
    echo "$rate"
}

run_benchmark() {
    local mode=$1
    
    log_info "====================================="
    log_info "Running benchmark in $mode mode"
    log_info "====================================="
    
    start_cognitod "$mode"
    
    # Warmup phase
    log_info "Warming up for ${WARMUP}s..."
    run_workload "warmup" "stress-ng --fork 16 --timeout ${WARMUP}s" "$WARMUP"
    
    # Capture start metrics
    local start_metrics=$(capture_metrics "$mode" "start")
    
    # Run main benchmark workloads
    log_info "Running main benchmark for ${DURATION}s..."
    
    # Fork-heavy workload (tests event throughput)
    run_workload "fork-storm" "stress-ng --fork 32 --timeout ${DURATION}s" "$DURATION" &
    WORKLOAD1=$!
    
    # Exec-heavy workload (more realistic)
    run_workload "exec-flood" "stress-ng --exec 16 --timeout ${DURATION}s" "$DURATION" &
    WORKLOAD2=$!
    
    # Wait for workloads
    wait $WORKLOAD1 2>/dev/null || true
    wait $WORKLOAD2 2>/dev/null || true
    
    # Capture end metrics
    local end_metrics=$(capture_metrics "$mode" "end")
    
    # Calculate results
    local throughput=$(calculate_throughput "$start_metrics" "$end_metrics" "$DURATION")
    
    log_info "====================================="
    log_info "Results for $mode mode:"
    log_info "  Duration: ${DURATION}s"
    log_info "  Throughput: $throughput events/sec"
    log_info "====================================="
    
    # Store results
    echo "$mode,$throughput" >> "$LOG_DIR/results.csv"
    
    stop_cognitod
}

run_ordering_test() {
    log_info "====================================="
    log_info "Running ordering validation test"
    log_info "====================================="
    
    start_cognitod "sequencer"
    
    log_info "Generating high-concurrency load..."
    stress-ng --fork 32 --timeout 10s &
    STRESS_PID=$!
    
    sleep 10
    
    # Check logs for ordering violations
    if grep -q "ORDERING VIOLATION" "$LOG_DIR/cognitod_sequencer.log" 2>/dev/null; then
        log_error "ORDERING VIOLATIONS DETECTED!"
        grep "ORDERING VIOLATION" "$LOG_DIR/cognitod_sequencer.log"
        stop_cognitod
        exit 1
    else
        log_success "No ordering violations detected"
    fi
    
    kill -TERM $STRESS_PID 2>/dev/null || true
    wait $STRESS_PID 2>/dev/null || true
    
    stop_cognitod
}

run_reaper_test() {
    log_info "====================================="
    log_info "Running reaper (fault tolerance) test"
    log_info "====================================="
    
    # This test requires the fault injection feature to be enabled
    # in the eBPF code. For now, we just verify the reaper logging works.
    
    log_info "Note: Full reaper testing requires --features fault-injection"
    log_info "Checking reaper timeout configuration..."
    
    # Verify the REAPER_TIMEOUT_NS constant
    if grep -q "REAPER_TIMEOUT_NS.*10_000_000" linnix-ai-ebpf/linnix-ai-ebpf-common/src/lib.rs; then
        log_success "Reaper timeout is configured (10ms)"
    else
        log_warn "Reaper timeout may not be configured correctly"
    fi
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --sequencer      Test only sequencer mode"
    echo "  --perf           Test only perf buffer mode"
    echo "  --compare        Compare both modes (default)"
    echo "  --ordering       Run ordering validation test"
    echo "  --reaper         Run reaper/fault tolerance test"
    echo "  --duration N     Set benchmark duration in seconds (default: 30)"
    echo "  --help           Show this help message"
    echo ""
    echo "Example:"
    echo "  sudo $0 --compare --duration 60"
}

main() {
    local mode="compare"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --sequencer)
                mode="sequencer"
                shift
                ;;
            --perf)
                mode="perf"
                shift
                ;;
            --compare)
                mode="compare"
                shift
                ;;
            --ordering)
                mode="ordering"
                shift
                ;;
            --reaper)
                mode="reaper"
                shift
                ;;
            --duration)
                DURATION="$2"
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
    
    check_prerequisites
    
    # Initialize results file
    echo "mode,throughput_eps" > "$LOG_DIR/results.csv"
    
    case $mode in
        sequencer)
            run_benchmark "sequencer"
            ;;
        perf)
            run_benchmark "perf"
            ;;
        compare)
            run_benchmark "perf"
            run_benchmark "sequencer"
            
            log_info "====================================="
            log_info "COMPARISON RESULTS"
            log_info "====================================="
            cat "$LOG_DIR/results.csv"
            ;;
        ordering)
            run_ordering_test
            ;;
        reaper)
            run_reaper_test
            ;;
    esac
    
    log_success "Benchmark completed. Results in $LOG_DIR/"
}

# Cleanup on exit
cleanup() {
    log_info "Cleaning up..."
    pkill -9 cognitod 2>/dev/null || true
    pkill -9 stress-ng 2>/dev/null || true
}

trap cleanup EXIT

main "$@"
