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
*Source: `linnix-cli/src/main.rs`*
