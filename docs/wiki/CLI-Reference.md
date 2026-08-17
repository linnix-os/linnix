# CLI Reference

The `linnix-cli` tool provides command-line access to cognitod.

## Installation

```bash
cargo install --path linnix-cli
```

## Global Options

| Option | Description |
|--------|-------------|
| `--host <URL>` | Cognitod server URL (default: http://127.0.0.1:3000) |
| `-h, --help` | Show help |
| `-V, --version` | Show version |

## Commands

### doctor
Check system health and connectivity.

```bash
linnix-cli doctor
```

### processes
List all tracked processes.

```bash
linnix-cli processes
```

### stream
Stream real-time events from cognitod.

```bash
linnix-cli stream
```

### alerts
View recent alerts.

```bash
linnix-cli alerts
```

### export
Export data in various formats.

```bash
linnix-cli export --format json --output data.json
```

### stats
Show system statistics.

```bash
linnix-cli stats
```

### metrics
Display metrics.

```bash
linnix-cli metrics
```

---

## Authentication

When cognitod is started with an API token configured, every TCP route requires
a bearer token. Set `LINNIX_API_TOKEN` and the CLI attaches it to all requests:

```bash
export LINNIX_API_TOKEN=your-token-here
linnix-cli investigate default/checkout-api --since 20m
```

Leave the variable unset for local, unauthenticated runs.

> The built-in web dashboard has no token-entry flow yet, so a token-protected
> deployment is currently reachable via the CLI and the API, not the browser UI.

---
*Source: `linnix-cli/src/main.rs`*
