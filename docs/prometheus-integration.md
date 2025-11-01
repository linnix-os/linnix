# Prometheus Integration Guide

This note captures the steps required to expose Cognitod metrics in Prometheus, wire the scrape target, and validate data flow end-to-end.

## 1. Enable the exporter

Set the Prometheus flag in the Cognitod config (usually `/etc/linnix/linnix.toml`):

```toml
[outputs]
prometheus = true
```

Restart Cognitod if it is already running. The daemon will now serve a text exposition at `http://<host>:3000/metrics/prometheus` alongside the JSON `/metrics` endpoint.

## 2. Install & run Cognitod via systemd

1. Build the artifacts:

   ```bash
   cargo build --release -p cognitod
   cargo xtask build-ebpf
   ```

2. Install the binary, config, and service unit:

   ```bash
   sudo install -m0755 target/release/cognitod /usr/local/bin/
   sudo install -D -m0644 packaging/linnix.toml /etc/linnix/linnix.toml
   sudo install -D -m0644 packaging/systemd/cognitod.service \
       /etc/systemd/system/cognitod.service
   sudo install -D -m0644 target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf \
       /usr/local/share/linnix/linnix-ai-ebpf-ebpf
   ```

3. Grant the binary eBPF capabilities:

   ```bash
   sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep /usr/local/bin/cognitod
   ```

4. Start the service:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now cognitod.service
   ```

Check `systemctl status cognitod` or `journalctl -u cognitod -f` to confirm it's healthy.

## 3. Configure Prometheus

If Prometheus is not already installed:

```bash
sudo apt install prometheus            # Debian/Ubuntu
# or grab the official tarball / run the Docker image
```

Append the Cognitod scrape job to `/etc/prometheus/prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'prometheus'
    scrape_interval: 5s
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'linnix'
    metrics_path: /metrics/prometheus
    static_configs:
      - targets: ['127.0.0.1:3000']
```

Reload Prometheus:

```bash
sudo systemctl reload prometheus
```

Verify in the UI (`http://localhost:9090 → Status → Targets`) that the `linnix` job reports `UP`.

## 4. Verify metrics flow

1. Tail the exporter directly:

   ```bash
   curl -H 'Accept: text/plain' http://127.0.0.1:3000/metrics/prometheus
   ```

   You should see counters such as `linnix_events_total`, `linnix_alerts_emitted_total`, and gauges for process CPU/RSS.

2. Run a Prometheus query:

   - `linnix_events_total`
   - `rate(linnix_events_total[1m])`
   - `linnix_alerts_emitted_total`

   The values should match the exporter output and tick upwards when events arrive.

3. Trigger a synthetic incident (`scripts/trigger_incidents.sh`) to exercise the rule engine and watch metrics change in both the curl output and Prometheus UI.

## 5. Optional next steps

- **Grafana dashboards**: point Grafana at `http://localhost:9090`, then chart `rate(linnix_events_total[1m])`, `linnix_alerts_emitted_total`, or `linnix_ilm_insights_total`.
- **Alerting**: add a rule file, e.g., alert if `rate(linnix_events_total[5m])` stays at zero for 10 minutes.
- **Documentation**: embed these steps in internal runbooks so operators can reproduce the setup quickly.

With the scrape job and exporter in place, Cognitod telemetry now feeds Prometheus for dashboards and alerting. Reach out if you want sample Grafana JSON or Prometheus rule templates.	    
