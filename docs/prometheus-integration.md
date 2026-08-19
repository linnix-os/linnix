# Prometheus Integration Guide

This note captures the steps required to expose Cognitod metrics in Prometheus, wire the scrape target, and validate data flow end-to-end.

> **Looking for the differentiator?** Jump to [§5 Noisy-neighbour metrics](#5-noisy-neighbour-metrics) — `linnix_stall_induced_seconds_total{offender_pod, victim_pod}` is the first workload-*pair* series your existing Prometheus/Grafana stack can query. Nothing else in a typical scrape target answers "who caused this stall," only "is there pressure."

## 1. Enable the exporter

Set the Prometheus flag in the Cognitod config (usually `/etc/linnix/linnix.toml`):

```toml
[outputs]
prometheus = true
metrics_listen_addr = "127.0.0.1:9090"
```

Restart Cognitod if it is already running. The daemon serves Prometheus text
exposition at `http://<host>:9090/metrics/prometheus`. This operational listener
also serves health and readiness, but it does not expose the JSON `/metrics`
endpoint or any process, incident, or action routes.

## 2. Install & run Cognitod via systemd

1. Build the artifacts:

   ```bash
   cargo build --release -p cognitod
   cargo xtask build-ebpf
   ```

2. Install the binary, config, and service unit:

   ```bash
   sudo install -m0755 target/release/cognitod /usr/local/bin/
   sudo install -D -m0644 configs/linnix.toml /etc/linnix/linnix.toml
   sudo install -D -m0644 configs/systemd/linnix-cognitod.service \
       /etc/systemd/system/cognitod.service
   sudo install -D -m0644 target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf \
       /usr/local/share/linnix/linnix-ai-ebpf-ebpf
   ```

3. Grant the binary eBPF capabilities:

   ```bash
   sudo setcap cap_bpf,cap_perfmon=ep /usr/local/bin/cognitod
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
      - targets: ['127.0.0.1:9090']
```

Reload Prometheus:

```bash
sudo systemctl reload prometheus
```

Verify in the UI (`http://localhost:9090 → Status → Targets`) that the `linnix` job reports `UP`.

## 4. Verify metrics flow

1. Tail the exporter directly:

   ```bash
   curl -H 'Accept: text/plain' http://127.0.0.1:9090/metrics/prometheus
   ```

   You should see counters such as `linnix_events_total`, `linnix_alerts_emitted_total`, and gauges for process CPU/RSS.

2. Run a Prometheus query:

   - `linnix_events_total`
   - `rate(linnix_events_total[1m])`
   - `linnix_alerts_emitted_total`

   The values should match the exporter output and tick upwards when events arrive.

3. Trigger a synthetic incident (`scripts/simulate_thrashing.sh`) to exercise the rule engine and watch metrics change in both the curl output and Prometheus UI.

## 5. Noisy-neighbour metrics

When cognitod runs with Kubernetes context, the PSI monitor exports two
pod-labelled families in addition to the agent-health counters above. They are
only populated on nodes where the cgroup PSI files are readable.

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `linnix_pod_psi_pressure_total` | counter (µs) | `namespace`, `pod`, `node` | CPU pressure stall accumulated by a pod. Summed across the pod's containers and carried across container restarts. |
| `linnix_stall_induced_seconds_total` | counter (s) | `offender_pod`, `offender_namespace`, `victim_pod`, `victim_namespace` | Stall time attributed to an offending pod. Each victim's stall is split across its offenders in proportion to blame, so summing this never exceeds the stall actually observed. |
| `linnix_blame_series_evicted_total` | counter | — | Series dropped because the per-family cardinality cap was reached. Non-zero means some blame series are incomplete. |

Useful queries:

- Who is suffering: `topk(10, rate(linnix_pod_psi_pressure_total[5m]))`
- Who is causing it: `topk(10, sum by (offender_namespace, offender_pod) (rate(linnix_stall_induced_seconds_total[5m])))`
- Blame for one victim: `sum by (offender_pod) (rate(linnix_stall_induced_seconds_total{victim_pod="payment-api"}[5m]))`

Each attribution over 100ms also emits a JSON line on stdout with
`"event_type": "linnix.stall_attribution"`, carrying the same victim/offender
pair plus a `reason` of `high_cpu_contention`, `fork_storm`, or
`short_job_churn` for log-based tooling.

## 6. Optional next steps

- **Grafana dashboards**: point Grafana at `http://localhost:9090`, then chart `rate(linnix_events_total[1m])`, `linnix_alerts_emitted_total`, or `linnix_dropped_events_total`.
- **Alerting**: add a rule file, e.g., alert if `rate(linnix_events_total[5m])` stays at zero for 10 minutes.
- **Documentation**: embed these steps in internal runbooks so operators can reproduce the setup quickly.

With the scrape job and exporter in place, Cognitod telemetry now feeds Prometheus for dashboards and alerting. Reach out if you want sample Grafana JSON or Prometheus rule templates.	    
