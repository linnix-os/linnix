# cognitod eBPF Process Tracking in Kubernetes

## How cognitod Sees Processes in Other Pods

### Core Principle
eBPF programs run in **kernel space**, not container space. When cognitod loads eBPF programs, they attach to kernel tracepoints that fire for **all processes on the node**, regardless of container boundaries.

```
Container Isolation ≠ Kernel Isolation

┌─────────────────────────────────────┐
│ Kernel (One Shared Instance)        │
│                                      │
│  eBPF Programs ← Attached here      │
│  ├─ sched_process_fork              │
│  ├─ sched_process_exec              │
│  └─ sched_process_exit              │
│       ↑ Fires for ALL processes     │
└─────────────────────────────────────┘
         │         │         │
    ┌────┘         │         └────┐
    │              │              │
┌───▼────┐   ┌────▼─────┐   ┌───▼────┐
│Pod A   │   │cognitod  │   │Pod C   │
│(nginx) │   │Pod       │   │(java)  │
└────────┘   └──────────┘   └────────┘
```

### Required Kubernetes Permissions

**1. hostPID: true**
- Shares host's PID namespace
- cognitod sees PIDs 1-65535 (same as host)
- Without this: cognitod only sees own container (PID 1)

**2. privileged: true** (or CAP_BPF + CAP_SYS_ADMIN)
```yaml
securityContext:
  privileged: true  # Simplest, but broad permissions
  # OR more restrictive:
  capabilities:
    add:
    - SYS_ADMIN   # Required for bpf() syscall (legacy kernels)
    - SYS_RESOURCE # Required for rlimit adjustments
    - BPF          # Required for BPF operations (kernel 5.8+)
    - NET_ADMIN    # Optional, for network probes
```

**3. /proc and /sys Access**
```yaml
volumeMounts:
- name: proc
  mountPath: /host/proc
  readOnly: true
- name: sys
  mountPath: /sys
  readOnly: true
```

### Process-to-Pod Mapping

cognitod reads `/proc/<pid>/cgroup` to identify which pod owns each process:

```bash
# Example from inside cognitod container
cat /host/proc/12345/cgroup

# Output (Kubernetes 1.25+, cgroup v2):
0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uuid>.slice/cri-containerd-<container_id>.scope

# Parsed tags (see cognitod/src/context.rs):
# - k8s_pod:<uuid>
# - container:<container_id_short>
# - cgroup:kubepods-burstable
```

### Security Models for Enterprises

#### Option A: Privileged DaemonSet (Highest Visibility)
**Use when:**
- Security team approves eBPF observability
- Node-level monitoring required (like Datadog, Falco)
- Cloud-native security standards (e.g., PCI DSS allows with controls)

**Restrictions:**
```yaml
# Deploy only to specific node pools
nodeSelector:
  node-pool: observability-tier
tolerations:
- key: observability
  operator: Equal
  value: "true"
  effect: NoSchedule
```

#### Option B: Unprivileged with BPF LSM (Kernel 5.8+)
**Use when:**
- Strict security policies (no privileged pods)
- Modern kernels with BPF LSM support

```yaml
securityContext:
  privileged: false
  allowPrivilegeEscalation: false
  capabilities:
    add:
    - BPF
    drop:
    - ALL
  seccompProfile:
    type: RuntimeDefault

# Requires Kubernetes admission controller to allow CAP_BPF
```

**Limitations:**
- Not all cloud providers support CAP_BPF without privileged
- May need AppArmor/SELinux policy adjustments

#### Option C: Sidecar Injection (Per-Namespace)
**Use when:**
- Cannot run privileged DaemonSet
- Only need monitoring for specific workloads

```yaml
# Inject cognitod as sidecar into target pods
# Via mutating webhook or service mesh (Istio, Linkerd)
apiVersion: v1
kind: Pod
metadata:
  annotations:
    sidecar.linnix.io/inject: "true"
spec:
  containers:
  - name: app
    image: myapp:latest
  - name: cognitod-sidecar
    image: ghcr.io/linnix-os/cognitod:sidecar
    securityContext:
      capabilities:
        add: [SYS_PTRACE]  # For process inspection
    # Shares PID namespace with app container
    # Only sees processes in this pod
```

**Trade-offs:**
- ❌ Cannot see processes outside pod
- ✅ No node-level privileges
- ✅ Per-team opt-in

### Comparison with Other Tools

| Tool | Approach | Privileges | Visibility |
|------|----------|------------|------------|
| **cognitod** | eBPF DaemonSet | Privileged + hostPID | All node processes |
| **Falco** | eBPF DaemonSet | Privileged + hostPID | All node processes |
| **Cilium** | eBPF DaemonSet | Privileged + hostNetwork | Network only |
| **Datadog Agent** | DaemonSet + cgroup | Privileged + hostPID | All node processes |
| **Prometheus** | HTTP scrape | None | App metrics only |
| **APM Sidecar** | Per-pod injection | None | Single pod only |

cognitod follows the same security model as Falco/Datadog - necessary for kernel-level observability.

### Validating Access in Production

**Test script to verify eBPF can see all pods:**
```bash
kubectl exec -it -n linnix-observability cognitod-<pod> -- /bin/sh

# Inside cognitod container:
# 1. Check host PID visibility
ls /host/proc | wc -l  # Should show hundreds/thousands of PIDs

# 2. Check eBPF program is loaded
bpftool prog show | grep sched_process

# 3. Check cgroup parsing works
for pid in $(ls /host/proc | grep '^[0-9]'); do
  [ -f /host/proc/$pid/cgroup ] && cat /host/proc/$pid/cgroup | head -1
done

# 4. Verify perf buffer consumption
cat /sys/kernel/debug/tracing/trace_pipe | head -20
```

### Compliance & Audit

For SOC2/ISO27001 compliance, document:
1. **Why privileged access**: Required for eBPF kernel instrumentation
2. **Scope limitation**: Only reads process metadata, no memory/data access
3. **Audit logging**: All insights logged to Prometheus metrics
4. **RBAC**: Restrict cognitod ConfigMap to platform team
5. **Network isolation**: LLM service only accessible from cognitod pods

Example audit statement:
> "cognitod requires privileged Linux capabilities (CAP_BPF, CAP_SYS_ADMIN) to load eBPF programs for process lifecycle tracking. eBPF programs are read-only observers attached to kernel tracepoints and do not modify system behavior. Access is restricted via Kubernetes RBAC to the linnix-observability namespace and monitored via Prometheus metrics."

---

## References
- eBPF security model: https://ebpf.io/what-is-ebpf/#security
- Kubernetes hostPID: https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces
- BPF LSM: https://www.kernel.org/doc/html/latest/bpf/bpf_lsm.html
- Falco deployment (similar model): https://falco.org/docs/getting-started/deployment/
