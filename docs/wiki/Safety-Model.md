# Safety Model

Linnix is designed with safety as the #1 priority.

## Monitor-First Guarantee

By default, Linnix runs in **Monitor Mode**:

✅ **What it does:**
- Detects incidents
- Logs events
- Sends alerts
- Proposes remediation actions

❌ **What it does NOT do:**
- Execute kill/throttle actions
- Modify running processes
- Change system configuration

## Enforcement Safety Rails

When enforcement is explicitly enabled:

### Protected Processes
- PID 1 (init) - Never killed
- Kernel threads - Never killed
- Allowlisted processes (kubelet, containerd, systemd)

### Grace Periods
- Minimum 15 seconds before any action
- Configurable per detection rule
- Multiple confirmation thresholds

### Code Reference
```rust
// From cognitod/src/enforcement/safety.rs
fn is_protected(pid: u32, comm: &str) -> bool {
    if pid == 1 { return true; }
    if is_kernel_thread(pid) { return true; }
    ALLOWLIST.contains(comm)
}
```

## AI Safety

The LLM is used for **analysis only**, never for real-time decisions:

```
Decision Path: Rules Engine (Rust) → Alert
Analysis Path: Alert → LLM → Explanation
```

The LLM cannot trigger enforcement actions.

## Privilege Requirements

| Capability | Purpose | Risk |
|------------|---------|------|
| CAP_BPF | Load eBPF programs | Read-only kernel access |
| CAP_PERFMON | Read trace events | Process visibility |
| CAP_NET_ADMIN | Network monitoring | Optional |

**Not required:** `privileged: true`, full root access

---
*Source: `SAFETY.md`, `cognitod/src/enforcement/safety.rs`*
