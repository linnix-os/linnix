#!/usr/bin/env bash
set -euo pipefail

# Unified UI test runner for Linnix
# Combines features from:
#  - test-ui-apis.sh
#  - test-ui-apis-no-sudo.sh
#  - scripts/ui_smoke_with_demo.sh
#
# Features:
#  - optional build with features
#  - optional setcap (sudo) or no-sudo mode (requires pre-setcap)
#  - start/stop mock Apprise server
#  - start Cognitod demo (various demo types)
#  - runs API checks (jq-based assertions when available)
#  - saves artifacts to timestamped directory under /tmp

PROG=$(basename "$0")
OUTDIR=""
API_BASE="http://127.0.0.1:3000"
DEMO_TYPE="fork-storm"
DEMO_DURATION=8
BUILD_FEATURES=""
DO_BUILD=false
START_MOCK=false
TRY_SETCAP=true
CI_MODE=false
NO_SUDO=false

usage() {
  cat <<EOF
$PROG - unified UI test runner

Usage: $PROG [options]

Options:
  --help            Show this message
  --api-base URL    API base (default: $API_BASE)
  --demo TYPE       Demo type to run (default: $DEMO_TYPE)
  --duration SEC    How long to wait for demo data (default: $DEMO_DURATION)
  --build-features F Comma-separated cargo features to build (e.g. fake-events)
  --build           Build the binary before running
  --start-mock      Start the local mock Apprise server (scripts/mock_apprise_server.py)
  --no-setcap       Do not attempt to set capabilities (useful in CI when pre-provisioned)
  --no-sudo         Do not call sudo; if setcap is required it must be pre-applied
  --ci              CI-friendly mode (non-interactive)

Examples:
  $PROG --build --build-features fake-events --start-mock --demo fork-storm
  $PROG --no-setcap --no-sudo --api-base http://localhost:8080

EOF
}

die() { echo "$PROG: $*" >&2; exit 2; }
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --help) usage; exit 0 ;;
      --api-base) API_BASE=$2; shift 2 ;;
      --demo) DEMO_TYPE=$2; shift 2 ;;
      --duration) DEMO_DURATION=$2; shift 2 ;;
      --build-features) BUILD_FEATURES=$2; DO_BUILD=true; shift 2 ;;
      --build) DO_BUILD=true; shift 1 ;;
      --start-mock) START_MOCK=true; shift 1 ;;
      --no-setcap) TRY_SETCAP=false; shift 1 ;;
      --no-sudo) NO_SUDO=true; TRY_SETCAP=false; shift 1 ;;
      --ci) CI_MODE=true; shift 1 ;;
      *) die "unknown arg: $1" ;;
    esac
  done
}

setup_artifacts() {
  TS=$(date -u +%Y%m%dT%H%M%SZ)
  OUTDIR="/tmp/ui_test_${TS}"
  mkdir -p "$OUTDIR"
  log "Artifacts dir: $OUTDIR"
}

ensure_mock_server() {
  if ! pgrep -f mock_apprise_server.py >/dev/null; then
    log "Starting mock Apprise server"
    nohup python3 scripts/mock_apprise_server.py > "$OUTDIR/mock_server.log" 2>&1 &
    echo $! > "$OUTDIR/mock_server.pid"
    sleep 1
    log "mock server pid=$(cat $OUTDIR/mock_server.pid)"
  else
    PID=$(pgrep -f mock_apprise_server.py | head -n1)
    log "mock server already running pid=$PID"
  fi
}

try_setcap() {
  if [ "$TRY_SETCAP" = true ]; then
    if getcap ./target/release/cognitod >/dev/null 2>&1; then
      log "capabilities already present: $(getcap ./target/release/cognitod)"
      return
    fi
    if [ "$NO_SUDO" = true ]; then
      die "capabilities missing and --no-sudo set; please run: sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep ./target/release/cognitod"
    fi
    log "Setting capabilities (sudo may be required)"
    sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep ./target/release/cognitod || log "setcap failed (continuing)"
    getcap ./target/release/cognitod || true
  else
    log "Skipping setcap as requested"
  fi
}

start_cognitod_demo() {
  if [ -f "$OUTDIR/cognitod.pid" ]; then
    OLD=$(cat "$OUTDIR/cognitod.pid")
    log "Stopping old cognitod pid=$OLD"
    sudo kill -TERM "$OLD" >/dev/null 2>&1 || true
    sleep 1
  fi
  log "Starting cognitod demo=$DEMO_TYPE"
  nohup env RUST_LOG=info LINNIX_CONFIG=/tmp/test-linnix.toml ./target/release/cognitod --handler rules:demo-rules.yaml --demo "$DEMO_TYPE" > "$OUTDIR/cognitod.log" 2>&1 &
  echo $! > "$OUTDIR/cognitod.pid"
  log "cognitod pid=$(cat $OUTDIR/cognitod.pid)"
}

run_api_checks() {
  log "Running API checks against $API_BASE"
  echo "---- timeline ----" > "$OUTDIR/api_timeline.txt"
  curl -sS -D - "$API_BASE/timeline" | sed -n '1,400p' > "$OUTDIR/api_timeline.txt" || true

  curl -sS -D - "$API_BASE/processes" | sed -n '1,400p' > "$OUTDIR/api_processes.txt" || true
  curl -sS -D - "$API_BASE/system" | sed -n '1,200p' > "$OUTDIR/api_system.txt" || true
  curl -sS -D - "$API_BASE/metrics/system" | sed -n '1,200p' > "$OUTDIR/api_metrics_system.txt" || true

  # SSE: stream briefly
  timeout $((DEMO_DURATION+2))s curl -sS -N "$API_BASE/processes/live" > "$OUTDIR/api_sse.txt" 2>&1 || true

  # Basic jq-driven assertions if jq present
  if command -v jq >/dev/null 2>&1; then
    PASS=0; FAIL=0
    if jq -e '.[0].id' "$OUTDIR/api_timeline.txt" >/dev/null 2>&1; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
    if jq -e '.[0].pid' "$OUTDIR/api_processes.txt" >/dev/null 2>&1; then PASS=$((PASS+1)); else log "process list empty or invalid"; fi
    if jq -e '.cpu_percent' "$OUTDIR/api_system.txt" >/dev/null 2>&1; then PASS=$((PASS+1)); else log "system metrics missing"; fi
    echo "PASS=$PASS FAIL=$FAIL" > "$OUTDIR/assert_summary.txt"
  else
    log "jq not available; skipping JSON assertions"
  fi
}

cleanup() {
  log "Cleaning up (if any started processes)"
  [ -f "$OUTDIR/cognitod.pid" ] && { PID=$(cat "$OUTDIR/cognitod.pid"); sudo kill -TERM "$PID" >/dev/null 2>&1 || true; }
  [ -f "$OUTDIR/mock_server.pid" ] && { PID=$(cat "$OUTDIR/mock_server.pid"); kill -TERM "$PID" >/dev/null 2>&1 || true; }
  log "Done"
}

main() {
  parse_args "$@"
  setup_artifacts

  require_cmd curl
  require_cmd timeout
  # jq optional

  if [ "$START_MOCK" = true ]; then
    ensure_mock_server
  fi

  if [ "$DO_BUILD" = true ]; then
    if [ -n "$BUILD_FEATURES" ]; then
      log "Building with features: $BUILD_FEATURES"
      cargo build --release --package cognitod --features "$BUILD_FEATURES" >> "$OUTDIR/build.log" 2>&1
    else
      log "Building release binary"
      cargo build --release -p cognitod >> "$OUTDIR/build.log" 2>&1
    fi
  fi

  try_setcap

  start_cognitod_demo
  log "Waiting $DEMO_DURATION seconds for demo to produce events"
  sleep "$DEMO_DURATION"

  run_api_checks

  log "Results saved under $OUTDIR"
  log "Artifacts: $OUTDIR/*"

  if [ "$CI_MODE" = true ]; then
    # In CI mode don't cleanup so logs can be inspected
    log "CI mode: not cleaning up started processes"
  else
    trap cleanup EXIT
  fi
}

main "$@"
