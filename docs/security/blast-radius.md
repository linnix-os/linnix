# Runtime Blast Radius

What the Linnix agent (`cognitod`) can touch on a node, what it sends off the
node, and how to constrain it. This describes the manifests and configs that
ship in this repository. Where a hardened variant is described but not yet
tested in CI, it is labelled as such.

## 1. Privileges

### Kubernetes (`k8s/daemonset.yaml`)

| Setting | Value | Why |
|---|---|---|
| `securityContext.privileged` | **`true`** | Simplest way to load eBPF programs. See "Capabilities-only" below. |
| `hostPID` | `true` | Read host `/proc` to attribute stalls to host processes. |
| `hostNetwork` | not set (false) | The agent stays in the pod network, so NetworkPolicy applies to it. |
| Host mounts | `/sys/kernel/btf/vmlinux` (ro), `/sys/kernel/debug` (**rw**), `/var/lib/linnix` (rw, state) | BTF for CO-RE, tracefs for tracepoints, incident DB and spool. |
| ServiceAccount RBAC | `get`/`list`/`watch` on `pods`, `nodes` | Metadata enrichment only. No write verbs. |
| Resources | requests `100m` / `128Mi`, limits `500m` / `512Mi` | Hard cgroup ceilings enforced by the kubelet. |

**Capabilities-only (untested).** A non-privileged variant is listed, commented
out, in `k8s/daemonset.yaml`:

```yaml
securityContext:
  privileged: false
  capabilities:
    add: ["BPF", "PERFMON", "SYS_RESOURCE", "SYS_ADMIN"]
```

CI does not currently test this variant. `SYS_ADMIN` is broad, so it is not a
large reduction over `privileged: true`. Treat it as a starting point, not a
guarantee.

`cognitod-daemonset.yaml` at the repository root is a local-development
manifest (`imagePullPolicy: Never`, `RUST_LOG=debug`). Do not use it in
production.

### systemd (`configs/systemd/linnix-cognitod.service`)

The systemd unit runs with only `CAP_BPF` and `CAP_PERFMON`
(`AmbientCapabilities` and `CapabilityBoundingSet`), plus `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, `ProtectKernelModules`,
`ProtectKernelTunables` and `ProtectControlGroups`. Writable paths are limited
to `/var/lib/linnix` and `/var/log/linnix`.

The unit sets no `User=`, so it runs as UID 0. `CAP_KILL` is not in the
bounding set, so an enforcement action cannot signal processes owned by
*other* UIDs. It can still signal root-owned processes, which covers most
system daemons. `SafetyGuard` (section 3) is what protects those.

The unit sets no `CPUQuota` or `MemoryMax`. You can add them through a drop-in
for hard ceilings outside Kubernetes. On 5.11+ kernels, BPF map memory is
charged to the agent's memory cgroup, so a tight `MemoryMax` can make map
creation fail at startup. Leave headroom above the agent's steady-state RSS.

### Kernel requirements

The eBPF programs need **Linux 5.12+ on x86_64** and **5.18+ on arm64**, with
BTF (`/sys/kernel/btf/vmlinux`). On older kernels, or without BTF or `CAP_BPF`,
the agent stays up in userspace-only mode and reports `0/1 Ready`. It does not
crash-loop.

## 2. eBPF safety

- Every program must pass the kernel's BPF verifier at load time. The verifier
  is designed to reject unbounded loops, out-of-bounds memory access and
  invalid helper calls. Verifier bugs do occur, so keep node kernels patched.
- kprobes on hot kernel paths add per-event overhead. Measured numbers are in
  [OVERHEAD.md](../OVERHEAD.md).
- The programs attach to tracepoints, BTF tracepoints and kprobes for observation. They do not
  modify packets, syscalls or scheduler decisions.
- Data reaches userspace through ring buffers. If userspace falls behind,
  events are dropped. The kernel is never blocked.
- `unsafe` userspace code is limited and listed in [SECURITY.md](../../SECURITY.md).

## 3. Actions on workloads

| Mode | Behaviour |
|---|---|
| `circuit_breaker.mode = "monitor"` (**default**) | Detects incidents and *proposes* actions. Never executes them. |
| `mode = "enforce"`, `require_human_approval = true` (**default**) | Executes a proposed kill only after a human approves it through the API, or through the Slack "Approve" button when Slack interactivity is configured. |
| `mode = "enforce"`, `require_human_approval = false` | Automatic. Opt-in only. |

Slack approvals arrive at `POST /api/slack/interactions` on the API listener.
They are rejected unless the request carries a valid Slack signature
(`[notifications.slack] signing_secret`). The approver is recorded as a
generic `slack_user`, not as the individual Slack identity. If you need
per-person accountability, approve through the API instead.

Every kill goes through `SafetyGuard::is_safe_to_kill`
(`cognitod/src/enforcement/safety.rs`), which refuses PID ≤ 1, the agent
itself, its own children and a list of critical process names.

The agent watches its own usage against `runtime.cpu_target_pct` and
`runtime.rss_cap_mb`. These settings only log warnings. The hard limits are
the Kubernetes resource limits or a systemd drop-in.

## 4. Network egress inventory

Built from the code, not from configuration examples. "Default" is the
behaviour with no config file. The shipped Kubernetes ConfigMap
(`k8s/configmap.yaml`) turns off the reasoner as well.

| Destination | Purpose | Config key | Default | Data sent |
|---|---|---|---|---|
| Kubernetes API server | Pod/node metadata enrichment | automatic in-cluster (`KUBERNETES_SERVICE_HOST`) | on in Kubernetes | Read-only GETs/WATCHes with the pod's ServiceAccount token |
| LLM endpoint | Incident analysis, `/insights` summaries | `[reasoner] enabled`, `endpoint` (env `LLM_ENDPOINT`) | **enabled**, `http://localhost:8090` (local llama.cpp) | Incident facts, process names, CPU/memory figures. Sends `OPENAI_API_KEY` as a bearer token if it is set |
| Slack webhook | Alerts | `[notifications.slack]` | off | Alert text, including pod and namespace (`privacy.redact_sensitive_data` is parsed but not yet applied) |
| Apprise | Alerts (runs the local `apprise` CLI) | `[notifications.apprise] urls` | off | Alert text to whatever URLs you configure |
| Linnix Cloud edge | Evidence batch export | `[cloud] enabled`, `endpoint` | **off** | Detection batches, including stall attributions with victim and offender **pod names and namespaces** (always sent; that is what an attribution is). `comm`, PIDs, cmdline and cgroup paths are scrubbed unless `export_process_identity = true` |

Notes:

- The reasoner is zero-egress only while `endpoint` points at loopback or an
  in-cluster service. Pointing it at a hosted LLM API sends incident data to
  that provider.
- `[cloud]` rejects plain `http://` for non-loopback hosts, so its bearer token
  never travels unencrypted.
- `[outputs] pagerduty` is a config flag with no network sender in `cognitod`
  today.
- **`runtime.offline = true` currently gates only the `/insights` LLM call.**
  It does not stop the incident analyzer, Slack, Apprise or cloud export.
  For zero egress, disable those sections.

Local subprocesses the agent may run: `logger` (alert syslog), `dmesg` (OOM
witness), `k3s --version` (environment detection), `apprise` (only when
configured).

### Default-deny egress NetworkPolicy

[`k8s/hardening/networkpolicy-egress.yaml`](../../k8s/hardening/networkpolicy-egress.yaml) denies
all egress except DNS and the API server. Commented blocks cover cloud export
and Slack. Set the API server `ipBlock` placeholder for your cluster before
applying it. Ingress is restricted separately by
[`k8s/networkpolicy.yaml`](../../k8s/networkpolicy.yaml).

**What this policy does and doesn't protect against.** It stops a
misconfigured or newly enabled sink from sending data off the cluster. It does
**not** contain a compromised agent. Under the shipped DaemonSet
(`privileged: true`, `hostPID: true`) the agent is effectively root on the
node: it can enter the host network namespace and bypass any pod-level
NetworkPolicy. Treat the agent's image and release provenance (see
[verifying-releases.md](verifying-releases.md)) as the control for that risk.
Node-level egress firewalling is the backstop.

`docker-compose.yml` runs the agent with `network_mode: host`, so NetworkPolicy
does not apply there.

## 5. Listeners

| Port | Bind (Kubernetes ConfigMap) | Auth | Exposes |
|---|---|---|---|
| 3000 | `0.0.0.0` | Bearer token (`LINNIX_API_TOKEN`, from a Secret) required for non-loopback | Processes, incidents, actions, approvals |
| 9464 | `0.0.0.0` | None | `/metrics/prometheus`, `/healthz`, `/readyz` only |

Outside Kubernetes, both default to `127.0.0.1`.

## 6. Container image

The runtime image is `debian:bookworm-slim` plus `ca-certificates`, `libssl3`
and `curl`. `curl` is there for the Docker `HEALTHCHECK`. The image is not yet
distroless. Moving to distroless or a static binary is tracked work, and would
remove `curl` and the shell from the attack surface.

Release provenance and SBOMs: see [verifying-releases.md](verifying-releases.md).
