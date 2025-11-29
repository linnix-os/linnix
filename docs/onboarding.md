# Linnix Design Partner Onboarding

Welcome to the Linnix Design Partner program! This guide will help you get up and running with Linnix in your environment.

## Prerequisites

Before installing, ensure your environment meets these requirements:

*   **OS**: Linux (Kernel 5.8+ recommended for full CO-RE support).
*   **Privileges**: Root access (required to load eBPF probes).
*   **Dependencies**:
    *   `curl` (for installation).
    *   `systemd` (for service management).
*   **Network**: Outbound access to:
    *   Your Slack Webhook URL (for alerts).
    *   Linnix artifact repository (for updates).

## Quick Install

Run the following command to install the latest version of Linnix:

```bash
curl -sL https://install.linnix.io/beta | sudo bash
```

*(Note: During the closed beta, you may need to manually place the binary if the public endpoint is not yet active.)*

## The First 24 Hours

### 1. Verify Health
Run the doctor command to ensure everything is hooked up correctly:
```bash
linnix doctor
```
You should see green checks for "BPF Probes", "Connectivity", and "AI Engine".

### 2. Configure Alerts
Edit `/etc/linnix/config.yaml` to add your Slack webhook:
```yaml
notifications:
  slack:
    webhook_url: "https://hooks.slack.com/services/..."
    channel: "#linnix-alerts"
```
Restart the service: `sudo systemctl restart cognitod`.

### 3. Run a Test (Optional)
To verify the circuit breaker is working, you can run a safe "noise" script:
```bash
# Simulates a high-churn process (safe to run)
./scripts/noise_maker.sh --mode fork_storm --safe
```
Check Slack for a "Fork Storm" alert!

### 4. Monitor
Linnix runs silently in the background. It will only alert you when:
*   A process threatens system stability (e.g., fork bomb, OOM risk).
*   A "Grey Failure" pattern is detected (e.g., slow memory leak).

## Data Flow & Privacy

**What leaves the node by default**: Nothing. All analysis is local.

**What leaves if you configure Slack**: Alert summaries only (reason, pod names, timestamps).

**How redaction works**: Set `privacy.redact_sensitive_data = true` in `/etc/linnix/config.yaml` and pod/namespace names will be SHA-256 hashed (8-char truncated). Hashes are deterministic for easy correlation.

**Where data is stored**: Incident history lives in SQLite at `/var/lib/linnix/incidents.db`. Feedback is logged to `/var/log/linnix/insights_feedback.json`.

See [SECURITY.md](../SECURITY.md) and [docs/architecture.md](architecture.md) for full details.

## Support
If you encounter any issues, please reach out via the shared Slack channel or email `partners@linnix.io`.
