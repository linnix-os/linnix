# Testing Apprise Integration

## Quick Test (5 minutes)

### 1. Install Apprise

```bash
pip3 install apprise
apprise --version
```

### 2. Create Test Configuration

```bash
cat > /tmp/test-linnix.toml <<'EOF'
[runtime]
offline = false

[rules]
path = "demo-rules.yaml"

[notifications.apprise]
urls = ["json://localhost:8888"]
min_severity = "info"
EOF
```

### 3. Start Mock HTTP Server (Terminal 1)

Run the included helper script which starts a POST-capable mock server and
appends incoming requests to `/tmp/http-posts.log`:

```bash
python3 scripts/mock_apprise_server.py
```

If you prefer to run an ad-hoc server inline, see the repository's
`scripts/mock_apprise_server.py` for the implementation.

### 4. Grant eBPF Capabilities (One-Time Setup)

```bash
# Build first
cargo build --release --bin cognitod

# Grant capabilities (required for eBPF)
sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep target/release/cognitod

# Verify capabilities were set
getcap target/release/cognitod
# Should show: target/release/cognitod cap_bpf,cap_perfmon,cap_sys_admin=ep
```

**Note:** Capabilities are sticky to the binary. If you rebuild, you'll need to re-run `setcap`.

### 5. Start Linnix with Test Config (Terminal 2)

```bash
# Ensure logs are visible at info level so the Apprise notifier message appears
# (service units set RUST_LOG=info by default).
RUST_LOG=info LINNIX_CONFIG=/tmp/test-linnix.toml ./target/release/cognitod

# Or explicitly load rules via CLI (equivalent to the config `rules.path`):
RUST_LOG=info LINNIX_CONFIG=/tmp/test-linnix.toml ./target/release/cognitod --handler rules:demo-rules.yaml
```

**Expected output:**
```
[cognitod] Starting Cognition Daemon...
[cognitod] Fork program loaded and attached.
[cognitod] Rules handler loaded from demo-rules.yaml (X rules)
[cognitod] Apprise notifier started with 1 URL(s)
[cognitod] BPF logger initialized.
[cognitod] Listening on http://0.0.0.0:3000
```

**If you see "missing CAP_BPF capability" error:**
- Go back to step 4 and run the `setcap` command
- Make sure you're running the binary directly (`./target/release/cognitod`), not via `cargo run`

### 6. Trigger Test Alert (Terminal 3)

```bash
# Option A: Use demo fork bomb scenario (if docker images built)
docker run --rm linnix-demo-fork-bomb

# Option B: Trigger alert manually via fake process activity
# Create a simple fork storm yourself
for i in {1..100}; do (sleep 0.1 &); done

# Note: This doc intentionally omits the in-repo "fake events" demo CLI
# instructions. Use Option A or B above, or run the daemon with `--handler`
# and a real trigger source to generate alerts.
```

### 7. Verify Notification Received (Terminal 1)

You should see HTTP POST requests in the Python HTTP server:

```
POST / HTTP/1.1
Host: localhost:8888
Content-Type: application/json
...
```

The JSON body will contain the alert data formatted by Apprise.

---

## Real Service Test (10 minutes)

### Slack Example

1. Create a Slack webhook: https://api.slack.com/messaging/webhooks
2. Update config:

```toml
[notifications.apprise]
urls = ["slack://xoxb-YOUR-BOT-TOKEN/C0123456789"]
min_severity = "medium"
```

3. Restart cognitod
4. Trigger alert
5. Check Slack channel for notification

### Discord Example

1. Create Discord webhook: Server Settings → Integrations → Webhooks
2. Copy webhook URL: `https://discord.com/api/webhooks/ID/TOKEN`
3. Update config:

```toml
[notifications.apprise]
urls = ["discord://ID/TOKEN"]
```

4. Restart cognitod
5. Check Discord channel

---

## Troubleshooting

### "Failed to execute apprise command"

**Problem:** Apprise CLI not found

**Solution:**
```bash
which apprise
# If not found:
pip3 install --user apprise

# Add to PATH permanently
echo 'export PATH="$PATH:$HOME/.local/bin"' >> ~/.bashrc
source ~/.bashrc

# Or for current session only:
export PATH="$PATH:$HOME/.local/bin"
```

### "missing CAP_BPF capability"

**Problem:** Binary doesn't have eBPF permissions

**Solution:**
```bash
# Must run setcap on the binary (not via cargo run)
cargo build --release --bin cognitod
sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep target/release/cognitod

# Then run the binary directly:
./target/release/cognitod
# NOT: cargo run
```

### "Apprise notifier lagged by X alerts"

**Problem:** Alerts coming faster than Apprise can send

**Solution:** This is normal for burst scenarios (fork bombs). The notifier logs the lag but continues processing. Consider:
- Increasing `min_severity` to reduce volume
- Using async Apprise API mode (future enhancement)

### No notifications received

**Check:**
1. Is cognitod running? `curl http://localhost:3000/health`
2. Are rules triggering? `curl -N http://localhost:3000/alerts` (leave running, watch for alerts)
3. Is Apprise installed? `apprise --version`
4. Check cognitod logs for "Apprise notifier started" message
5. Test Apprise directly: `apprise -t "test" -b "body" json://localhost:8888`
6. Verify demo-rules.yaml exists and has low thresholds for testing

---

## Success Criteria

✅ Apprise notifier starts without errors
✅ Mock HTTP server receives POST requests
✅ Alert title includes severity and rule name
✅ Alert body includes host and message
✅ Multiple URLs all receive notifications
✅ Severity filtering works (only medium/high sent when configured)

---

## Next Steps

Once testing is complete:
1. Update GitHub Discussion #2 with results
2. Add screenshot/output to APPRISE_RESPONSE.md
3. Push branch and create PR
4. Celebrate shipping in 1 hour! 🎉
