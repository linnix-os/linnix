# Security Policy

## Overview
Linnix is designed with a "Safety First" architecture. As an eBPF-based agent running with high privileges, we take security extremely seriously. This document outlines our security model, required privileges, and data privacy controls.

## Privilege Model

Cognitod requires the following capabilities to function:

*   **`CAP_BPF`**: Required to load eBPF programs into the kernel.
*   **`CAP_PERFMON`**: Required to attach probes to kernel tracepoints and read from ring buffers.

The kernel floor is Linux 5.12+ (x86_64) / 5.18+ (arm64), so `CAP_BPF` is always available and the older `CAP_SYS_ADMIN` fallback does not apply. The shipped systemd unit uses only these two capabilities. The shipped Kubernetes DaemonSet currently runs `privileged: true`; see [docs/security/blast-radius.md](docs/security/blast-radius.md).

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
*   **Default**: No data leaves the cluster. The LLM reasoner is enabled by default but targets a local model server (`localhost:8090`); pointing `[reasoner] endpoint` at a hosted API sends incident data to that provider.
*   **Opt-in**: Slack, Apprise and Linnix Cloud export send data only when configured.
*   **Inventory**: every outbound destination, its config key and default are listed in [docs/security/blast-radius.md](docs/security/blast-radius.md). `k8s/hardening/networkpolicy-egress.yaml` enforces default-deny egress.
*   **Redaction**: `privacy.redact_sensitive_data` is parsed from `linnix.toml` but is **not yet applied** to any output. Pod names and namespaces appear unhashed in alerts. Do not rely on it.

## Release Integrity

Release assets and container images carry Sigstore-backed build provenance attestations, and releases include CycloneDX SBOMs. See [docs/security/verifying-releases.md](docs/security/verifying-releases.md).

## Reporting Vulnerabilities

Please report security vulnerabilities to `security@linnix.io`. We pledge to respond within 24 hours.
