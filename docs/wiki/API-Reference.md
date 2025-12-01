# API Reference

Base URL: `http://localhost:3000`

## Authentication

Set the `LINNIX_API_TOKEN` environment variable to enable Bearer token authentication.

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
| `/metrics/prometheus` | GET | - |
| `/metrics/system` | GET | - |
| `/ppid/{ppid}` | GET | - |
| `/processes` | GET | - |
| `/processes/live` | GET | - |
| `/processes/{pid}` | GET | - |
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

#### GET /metrics/prometheus
Returns metrics in Prometheus text exposition format.

```bash
curl http://localhost:3000/metrics/prometheus
```

---
*Source: `cognitod/src/api/mod.rs`*
