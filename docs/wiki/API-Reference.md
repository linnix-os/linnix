# API Reference

Base URL: `http://localhost:3000`

## Authentication

Set `LINNIX_API_TOKEN` to authenticate the API. The daemon refuses to start a
TCP API bound outside loopback without this token (or `api.auth_token`).

```bash
# With auth enabled
curl -H "Authorization: Bearer <token>" http://localhost:3000/status
```

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/actions` | GET | - |
| `/actions/{id}/approve` | POST | - |
| `/actions/{id}` | GET | - |
| `/actions/{id}/reject` | POST | - |
| `/alerts` | GET | - |
| `/api/feedback` | POST | - |
| `/api/slack/interactions` | POST | - |
| `/attribution` | GET | - |
| `/context` | GET | - |
| `/dashboard` | GET | - |
| `/events` | GET | - |
| `/` | GET | - |
| `/graph/{pid}` | GET | - |
| `/healthz` | GET | - |
| `/incidents` | GET | - |
| `/incidents/{id}` | GET | - |
| `/incidents/stats` | GET | - |
| `/incidents/summary` | GET | - |
| `/insights` | GET | - |
| `/insights/{id}/feedback` | POST | - |
| `/insights/{id}` | GET | - |
| `/insights/recent` | GET | - |
| `/insights/schema` | GET | - |
| `/metrics` | GET | - |
| `/metrics/system` | GET | - |
| `/ppid/{ppid}` | GET | - |
| `/processes` | GET | - |
| `/processes/live` | GET | - |
| `/processes/{pid}` | GET | - |
| `/processes/{pid}/contention` | GET | - |
| `/status` | GET | - |
| `/stream` | GET | - |
| `/system` | GET | - |
| `/timeline` | GET | - |

## Detailed Endpoint Documentation

### Health & Status

#### GET /healthz
Returns health status of the daemon.

```bash
curl http://localhost:3000/healthz
# {"status":"ok","version":"0.1.0"}
```

#### GET /status
Returns detailed system status including probe state and reasoner config.

```bash
curl http://localhost:3000/status | jq
```

### Process Monitoring

#### GET /processes
Returns all tracked processes with CPU/memory metrics.

```bash
curl http://localhost:3000/processes | jq
```

#### GET /processes/{pid}/contention
Returns the per-process runqueue-wait finding from the userspace schedstat
detector (label `measured`): ms the process's threads spent waiting on a
runqueue inside the 10s measurement window, plus the deterministic verdict
against the frozen 2000/5000 ms thresholds. This is the same measurement the
`cpu_starvation` incidents come from, exposed read-only per PID — not a new
sensor. An explicit query pins the PID so subsequent polls measure it even
outside the top-50 CPU gate.

- `404` — the PID doesn't exist, or exists but hasn't been measured yet
  (typed absence, never a fabricated zero).
- `503` — the detector is degraded (schedstat unreadable) or not running.

```bash
curl http://localhost:3000/processes/1234/contention | jq
```

#### GET /graph/{pid}
Returns process tree ancestry for the given PID.

```bash
curl http://localhost:3000/graph/1234 | jq
```

### Event Streaming

#### GET /stream
Server-Sent Events (SSE) stream of real-time process events.

```bash
curl -N http://localhost:3000/stream
```

### Insights & Incidents

#### GET /insights
Returns AI-generated insights about current system state.

```bash
curl http://localhost:3000/insights | jq
```

#### GET /incidents
Returns list of detected incidents.

```bash
curl http://localhost:3000/incidents | jq
```

### Metrics

#### GET /metrics
Returns metrics in JSON format.

```bash
curl http://localhost:3000/metrics | jq
```

#### GET /metrics/prometheus (operational listener)
Returns metrics in Prometheus text exposition format from the separate
operational listener, which defaults to `http://localhost:9464`.

```bash
curl http://localhost:9464/metrics/prometheus
```

---
*Source: `cognitod/src/api/mod.rs`*
