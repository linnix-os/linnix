# Cognitod Collector

Linnix Cognitod ships an eBPF collector that streams Linux process lifecycle data (fork/exec/exit) plus lightweight resource usage into the daemon runtime. This note captures the kernel interfaces we rely on so operators can validate support on their hosts and understand which probes are optional.

## Kernel Probes and Tracepoints

| Purpose | Program | Type | Notes |
|---------|---------|------|-------|
| Process exec events | `sched/sched_process_exec` | Tracepoint | Mandatory for command attribution |
| Process fork events | `sched/sched_process_fork` | Tracepoint | Mandatory for parent/child lineage |
| Process exit events | `sched/sched_process_exit` | Tracepoint | Mandatory for runtime + exit correlation |
| TCP send | `tcp_sendmsg` | kprobe | Optional; powers network byte counters † |
| TCP recv | `tcp_recvmsg` | kprobe | Optional † |
| UDP send/recv | `udp_sendmsg`, `udp_recvmsg` | kprobes | Optional † |
| Unix socket send/recv | `unix_stream_sendmsg`, `unix_stream_recvmsg`, `unix_dgram_sendmsg`, `unix_dgram_recvmsg` | kprobes | Optional † |
| File IO | `vfs_read`, `vfs_write` | kprobes | Optional file throughput metrics † |
| Block IO queue | `block/block_bio_queue` | Tracepoint | Optional; requires block layer symbols † |
| Block IO issue/complete | `block/block_rq_issue`, `block/block_rq_complete` | Tracepoints | Optional † |
| Page faults | `page_fault_user`, `page_fault_kernel` | BTF tracepoints | Enabled when system BTF is present |
| Syscall entry | `raw_syscalls/sys_enter` | Tracepoint | Optional high-volume telemetry gated by rate limiting † |

The `sched_*` tracepoints are the only mandatory hooks for lifecycle tracking. Cognitod treats the network, filesystem, block, and syscall probes as best-effort; failures are logged but not fatal (see `attach_kprobe_optional` and friends in `cognitod/src/main.rs`).

† These high-volume probes are suppressed by default in `linnix-ai-ebpf/linnix-ai-ebpf-ebpf/src/program.rs` to keep perf buffers focused on lifecycle telemetry. To re-enable them, edit `emit_activity_event(...)` so it no longer returns early for `EventType::Net`, `EventType::FileIo`, `EventType::Syscall`, or `EventType::BlockIo`, rebuild the probes with `cargo xtask build-ebpf`, and redeploy the resulting object files. Be prepared to add sampling or rate limiting in userspace before turning them back on in production.

## Deployment Checklist

1. Ensure your kernel exposes the tracepoints listed above (`sudo trace-cmd list -t` is a quick check).
2. Provide `/sys/kernel/btf/vmlinux` if you want to enable BTF tracepoints (page-fault deltas and richer RSS sampling).
3. Grant the daemon `CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_ADMIN` (see `configs/systemd/cognitod.service`).
4. Set `LINNIX_BPF_PATH` and `LINNIX_KERNEL_BTF` if you install assets outside the defaults.

With those pieces in place, the perf-ring listener (see `cognitod/src/runtime/stream_listener.rs`) delivers fork/exec/exit events that the rule engine, reasoner, and dashboards consume.

## Metrics Export

Cognitod always exposes an operator-friendly JSON snapshot at `/metrics`. If you prefer Prometheus scraping, set:

```toml
[outputs]
prometheus = true
```

in `/etc/linnix/linnix.toml` (or the generated config). When enabled, the daemon adds a `/metrics/prometheus` endpoint that emits the standard text exposition format with counters for event volume, drops, rule activity, ILM insight totals, and the daemon’s own CPU/RSS usage. A quick health check:

```bash
curl -H 'Accept: text/plain' http://127.0.0.1:3000/metrics/prometheus
```

The JSON endpoint remains available alongside the Prometheus view, so dashboards and scripts can pick whichever format they need.
