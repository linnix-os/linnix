# Configuration Guide

## Config File Location

Cognitod searches for configuration in this order:
1. `LINNIX_CONFIG` environment variable
2. `--config` command-line flag
3. `/etc/linnix/linnix.toml` (default)

## Configuration Sections

```toml
# Linnix Configuration
# Documentation: https://docs.linnix.io/configuration

[api]
listen_addr = "127.0.0.1:3000"
# auth_token = "your-secret-token"

[runtime]
offline = false

[telemetry]
# Sample interval for CPU/memory metrics (milliseconds)
sample_interval_ms = 1000

# Event retention window (seconds)
retention_seconds = 60

[reasoner]
# AI-powered incident detection
enabled = true
endpoint = "http://localhost:8090/v1/chat/completions"
model = "linnix-3b-distilled"
window_seconds = 10
timeout_ms = 30000
min_eps_to_enable = 10  # Enable for testing

[prometheus]
# Prometheus metrics endpoint
enabled = true

# ─────────────────────────────────────────────────────────────────────────────
# Notifications via Apprise (optional)
# ─────────────────────────────────────────────────────────────────────────────
# Apprise supports 100+ services: Slack, Discord, Teams, Telegram, SMS, Email, etc.
# See https://github.com/caronc/apprise#supported-notifications for URL formats
#
# [notifications.apprise]
# urls = [
#     "slack://xoxb-YOUR-BOT-TOKEN/C0123456789",
#     "discord://WEBHOOK_ID/WEBHOOK_TOKEN",
#     "mailto://user:pass@smtp.gmail.com"
# ]
# min_severity = "medium"  # Options: info, low, medium, high (default: info)
```

## Section Reference

### [api]
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen_addr` | string | "127.0.0.1:3000" | HTTP server bind address |
| `auth_token` | string | null | Optional API authentication token |

### [runtime]
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `offline` | bool | false | Disable all external HTTP egress |

### [telemetry]
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `sample_interval_ms` | u64 | 1000 | CPU/memory sampling interval |
| `retention_seconds` | u64 | 60 | Event retention window |

### [reasoner]
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | true | Enable AI reasoning |
| `endpoint` | string | "http://localhost:8090/v1/chat/completions" | LLM endpoint URL |
| `model` | string | "linnix-3b-distilled" | Model name |
| `window_seconds` | u64 | 10 | Analysis window |
| `timeout_ms` | u64 | 30000 | Request timeout |
| `min_eps_to_enable` | u64 | 10 | Minimum events/sec threshold |

### [prometheus]
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | true | Enable /metrics/prometheus endpoint |

### [notifications.apprise]
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `urls` | Vec<string> | [] | Apprise notification URLs |
| `min_severity` | string | "info" | Minimum severity to notify |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `LINNIX_CONFIG` | Override config file path |
| `LINNIX_BPF_PATH` | Override eBPF object path |
| `LINNIX_LISTEN_ADDR` | Override listen address |
| `LINNIX_API_TOKEN` | Set API authentication token |
| `LLM_ENDPOINT` | Override LLM endpoint |
| `LLM_MODEL` | Override LLM model |
| `OPENAI_API_KEY` | API key for OpenAI-compatible endpoints |

---
*Source: `cognitod/src/config.rs`*
