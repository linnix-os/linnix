# eBPF Collector Guide

The Linnix collector uses eBPF to capture kernel events with minimal overhead.

## Probe Inventory

### Mandatory Probes (Lifecycle)
| Purpose | Hook | Type |
|---------|------|------|
| Process exec | `sched/sched_process_exec` | Tracepoint |
| Process fork | `sched/sched_process_fork` | Tracepoint |
| Process exit | `sched/sched_process_exit` | Tracepoint |

### Optional Probes (Telemetry)
| Purpose | Hook | Type | Default |
|---------|------|------|---------|
| TCP send/recv | `tcp_sendmsg`, `tcp_recvmsg` | kprobe | Disabled |
| UDP send/recv | `udp_sendmsg`, `udp_recvmsg` | kprobe | Disabled |
| File I/O | `vfs_read`, `vfs_write` | kprobe | Disabled |
| Block I/O | `block/block_bio_queue` | Tracepoint | Disabled |
| Page faults | `page_fault_*` | BTF Tracepoint | Requires BTF |

## Kernel Requirements

| Kernel | Support Level |
|--------|--------------|
| 5.4+ | Basic (sched tracepoints) |
| 5.8+ | Full (BTF support) |
| 5.15+ | Enhanced (page fault tracking) |

## Required Capabilities

```
CAP_BPF       - Load eBPF programs
CAP_PERFMON   - Read perf events
CAP_SYS_ADMIN - Required on older kernels
```

## Building eBPF Programs

```bash
# Requires Rust nightly-2024-12-10
cargo xtask build-ebpf
```

Output: `target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf`

## BPF Object Search Path

1. `LINNIX_BPF_PATH` environment variable
2. `/usr/local/share/linnix/linnix-ai-ebpf-ebpf`
3. `target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf`
4. `target/bpf/*.o` (fallback)

## BTF Support

Check if your system has BTF:
```bash
ls -la /sys/kernel/btf/vmlinux
```

If present, Linnix can derive struct offsets dynamically for enhanced telemetry.

---
*Source: `docs/collector.md`, `linnix-ai-ebpf/`*
