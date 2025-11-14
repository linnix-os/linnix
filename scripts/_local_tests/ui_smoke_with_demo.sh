#!/usr/bin/env bash
set -euo pipefail

# Run Cognitod demo + UI smoke tests and archive logs for CI/debugging.
# Writes a combined log at /tmp/ui_api_test_with_demo.log and leaves
# supporting logs at /tmp/mock_server.log, /tmp/cognitod_demo.log, /tmp/http-posts.log

OUT=/tmp/ui_api_test_with_demo.log
echo "UI smoke-with-demo run: $(date -u)" > "$OUT"

log() { echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*" | tee -a "$OUT" >&2; }

log "Ensuring mock Apprise server is running"
if pgrep -f mock_apprise_server.py >/dev/null; then
  PID=$(pgrep -f mock_apprise_server.py | head -n1)
  log "mock_apprise_server already running (pid=$PID)"
else
  log "starting mock_apprise_server.py"
  nohup python3 scripts/mock_apprise_server.py > /tmp/mock_server.log 2>&1 &
  echo $! > /tmp/mock_apprise.pid
  sleep 1
  log "mock_apprise_server started pid=$(cat /tmp/mock_apprise.pid)"
fi

log "Building cognitod (if needed)"
if [ ! -x ./target/release/cognitod ]; then
  log "cognitod binary not found; building release"
  cargo build --release -p cognitod >> "$OUT" 2>&1
  log "build finished"
fi

log "Ensure capabilities set on ./target/release/cognitod (may require sudo)"
if getcap ./target/release/cognitod >/dev/null 2>&1; then
  getcap ./target/release/cognitod | tee -a "$OUT"
else
  log "no capabilities found; attempting to set (may ask for sudo)"
  sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep ./target/release/cognitod || true
  getcap ./target/release/cognitod | tee -a "$OUT" || true
fi

log "Restarting Cognitod demo (fork-storm)"
if [ -f /tmp/cognitod_demo.pid ]; then
  OLD=$(cat /tmp/cognitod_demo.pid)
  log "stopping old cognitod demo pid=$OLD"
  sudo kill -TERM "$OLD" >/dev/null 2>&1 || true
  sleep 1
fi

nohup env RUST_LOG=info LINNIX_CONFIG=/tmp/test-linnix.toml ./target/release/cognitod --handler rules:demo-rules.yaml --demo fork-storm > /tmp/cognitod_demo.log 2>&1 &
echo $! > /tmp/cognitod_demo.pid
sleep 2
log "cognitod demo started pid=$(cat /tmp/cognitod_demo.pid)"

log "Waiting a few seconds for demo rules to fire and notifications to be delivered"
sleep 4

log "Collecting mock server and Apprise logs"
echo "---- /tmp/mock_server.log (tail 200) ----" >> "$OUT"
tail -n 200 /tmp/mock_server.log >> "$OUT" 2>&1 || true
echo "---- /tmp/http-posts.log (tail 200) ----" >> "$OUT"
tail -n 200 /tmp/http-posts.log >> "$OUT" 2>&1 || true
echo "---- /tmp/cognitod_demo.log (tail 200) ----" >> "$OUT"
tail -n 200 /tmp/cognitod_demo.log >> "$OUT" 2>&1 || true

log "Running API smoke checks against http://127.0.0.1:3000"

echo "---- API /timeline ----" >> "$OUT"
curl -sS -D - http://127.0.0.1:3000/timeline | sed -n '1,300p' >> "$OUT" 2>&1 || true

echo "---- API /processes ----" >> "$OUT"
curl -sS -D - http://127.0.0.1:3000/processes | sed -n '1,300p' >> "$OUT" 2>&1 || true

echo "---- API /system ----" >> "$OUT"
curl -sS -D - http://127.0.0.1:3000/system | sed -n '1,200p' >> "$OUT" 2>&1 || true

echo "---- SSE /processes/live (6s) ----" >> "$OUT"
timeout 6s curl -sS -N http://127.0.0.1:3000/processes/live >> "$OUT" 2>&1 || true

log "Basic smoke checks complete — output saved to $OUT"
log "Artifacts: /tmp/mock_server.log /tmp/http-posts.log /tmp/cognitod_demo.log /tmp/cognitod_demo.pid"

cat <<'EOF'
To re-run locally:
  bash scripts/_local_tests/ui_smoke_with_demo.sh

Notes:
- The script may prompt for sudo when setting capabilities.
- The script restarts Cognitod in demo (fork-storm) mode; it writes logs to /tmp.
EOF

exit 0
