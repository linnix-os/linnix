# Linnix Documentation

Welcome to the official Linnix documentation.

**Linnix** is an eBPF-powered Linux observability platform with AI-assisted incident triage for Kubernetes and bare-metal systems.

## Quick Navigation

| Section | Description |
|---------|-------------|
| [Getting Started](Getting-Started.md) | Installation and first steps |
| [Architecture Overview](Architecture-Overview.md) | System design and components |
| [API Reference](API-Reference.md) | HTTP API endpoints |
| [Configuration Guide](Configuration-Guide.md) | Config file options |
| [CLI Reference](CLI-Reference.md) | Command-line tool usage |
| [Collector Guide](Collector-Guide.md) | eBPF probe documentation |
| [Safety Model](Safety-Model.md) | Security and enforcement guarantees |
| [Troubleshooting](Troubleshooting.md) | Common issues and solutions |

## Component Overview

| Component | Purpose | Port |
|-----------|---------|------|
| cognitod | Main daemon - eBPF loader, event processor, API server | 3000 |
| linnix-cli | CLI client for querying cognitod | - |
| linnix-reasoner | LLM integration for AI insights | - |
| llama-server | Local LLM inference (optional) | 8090 |

## Key Features

- **Zero-config eBPF**: Automatic kernel compatibility via BTF
- **Real-time streaming**: SSE-based event stream for live monitoring
- **AI-powered insights**: LLM-based incident classification and recommendations
- **Kubernetes native**: DaemonSet deployment with priority class support
- **Safety guarantees**: Resource limits, circuit breakers, graceful degradation

## Resources

- [GitHub Repository](https://github.com/linnix-os/linnix)
- [Issue Tracker](https://github.com/linnix-os/linnix/issues)
