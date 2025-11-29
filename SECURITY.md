# Security Policy

## Overview
Linnix is designed with a "Safety First" architecture. As an eBPF-based agent running with high privileges, we take security extremely seriously. This document outlines our security model, required privileges, and data privacy controls.

## Privilege Model

Cognitod requires the following capabilities to function:

*   **`CAP_BPF`** (or `CAP_SYS_ADMIN` on older kernels): Required to load eBPF programs into the kernel.
*   **`CAP_PERFMON`** (or `CAP_SYS_ADMIN`): Required to attach probes to kernel tracepoints and read from perf buffers.
*   **`CAP_NET_ADMIN`**: Required only if network traffic shaping/enforcement is enabled (currently disabled by default).

We recommend running Cognitod as a systemd service with these specific capabilities rather than full root, where possible.

## Unsafe Code Audit

Linnix uses Rust for memory safety. However, `unsafe` blocks are necessary for interacting with the kernel and C libraries.

| Location | Justification |
|----------|---------------|
| `runtime/stream_listener.rs` | `ptr::read_unaligned`: Reading raw bytes from the eBPF ring buffer. Validated by BPF verifier. |
| `bpf_config.rs` | `libc::sysconf`: querying system page size. Standard FFI. |
| `config.rs` | `unsafe impl Pod`: Marker trait for configuration structs to be safely cast to bytes for BPF maps. |

## Data Privacy

### Data Collection
*   **Metrics**: CPU, Memory, I/O stats (aggregated).
*   **Metadata**: Pod names, Namespaces, Container IDs.
*   **Process Info**: Command lines (sanitized).

### Data Egress
*   **Default**: No data leaves the node. All analysis is local.
*   **Slack**: If configured, alerts are sent to your Slack webhook.
*   **Redaction**: You can enable `privacy.redact_sensitive_data = true` in `config.yaml` to hash Pod names and Namespaces in alerts.

## Reporting Vulnerabilities

Please report security vulnerabilities to `security@linnix.io`. We pledge to respond within 24 hours.
