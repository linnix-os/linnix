# Threat Model

## Data Handling
- No PII is collected or stored.
- Offline mode disables all network egress; data remains on the host.

## Exposed Endpoints
- `/context`
- `/processes`
- `/processes/{pid}`
- `/ppid/{ppid}`
- `/graph/{pid}`
- `/events`
- `/stream`
- `/system`
- `/alerts`
- `/insights`
- `/metrics`
- `/status`
- `/healthz`

## Outputs
Slack, PagerDuty and Prometheus outputs require `offline=false` and explicit enablement.

```
            +-----------+            +-------------+
            | cognitod  |--/stream--> | CLI/Dashboard|
            | daemon    |--/alerts--> |             |
            |           |--/metrics-> |             |
            +-----------+            +-------------+
                   |
                   | offline=false
                   v
        +------------------------------+
        | Slack | PagerDuty | Prometheus|
        +------------------------------+
```

