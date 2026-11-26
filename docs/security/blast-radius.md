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

Because `CAP_KILL` is not in the bounding set, enforcement actions cannot signal
other users' processes under this unit, even if enforcement is enabled.

The unit sets no `CPUQuota` or `MemoryMax`. Add them through a drop-in if you
want hard ceilings outside Kubernetes. Leave `LimitMEMLOCK=infinity` in place,
because eBPF maps need it on kernels that still charge memlock.

### Kernel requirements

The eBPF programs need **Linux 5.12+ on x86_64** and **5.18+ on arm64**, with
BTF (`/sys/kernel/btf/vmlinux`). On older kernels, or without BTF or `CAP_BPF`,
the agent stays up in userspace-only mode and reports `0/1 Ready`. It does not
crash-loop.

## 2. eBPF safety

- Every program passes the kernel's BPF verifier at load time. The verifier
  rejects unbounded loops, out-of-bounds memory access and invalid helper
  calls. A program that would crash the kernel cannot be loaded.
- The programs attach to tracepoints, BTF tracepoints and kprobes for observation. They do not
  modify packets, syscalls or scheduler decisions.
- Data reaches userspace through ring buffers. If userspace falls behind,
  events are dropped. The kernel is never blocked.
- `unsafe` userspace code is limited and listed in [SECURITY.md](../../SECURITY.md).

## 3. Actions on workloads

| Mode | Behaviour |
|---|---|
| `circuit_breaker.mode = "monitor"` (**default**) | Detects incidents and *proposes* actions. Never executes them. |
| `mode = "enforce"`, `require_human_approval = true` (**default**) | Executes a proposed kill only after a human approves it through the API. |
| `mode = "enforce"`, `require_human_approval = false` | Automatic. Opt-in only. |

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
| Slack webhook | Alerts | `[notifications.slack]` | off | Alert text, optionally with redacted pod/namespace |
| Apprise | Alerts (runs the local `apprise` CLI) | `[notifications.apprise] urls` | off | Alert text to whatever URLs you configure |
| Linnix Cloud edge | Evidence batch export | `[cloud] enabled`, `endpoint` | **off** | Detection batches. `comm`, PIDs, cmdline and cgroup paths are scrubbed unless `export_process_identity = true` |

Notes:

- The reasoner is zero-egress only while `endpoint` points at loopback or an
  in-cluster service. Pointing it at a hosted LLM API sends incident data to
  that provider.
- `[cloud]` rejects plain `http://` for non-loopback hosts, so its bearer token
  never travels unencrypted.
- `[outputs] pagerduty` is a config flag with no network sender in `cognitod`
  today.
- **`runtime.offline = true` currently gates only the `/insights` LLM call.**
  It does not stop the incident analyzer, Slack, Apprise or cloud export. To
  guarantee zero egress, disable those sections. Use
  [`k8s/hardening/networkpolicy-egress.yaml`](../../k8s/hardening/networkpolicy-egress.yaml) as
  the enforcement backstop.

Local subprocesses the agent may run: `logger` (alert syslog), `dmesg` (OOM
witness), `k3s --version` (environment detection), `apprise` (only when
configured).

### Default-deny egress NetworkPolicy

[`k8s/hardening/networkpolicy-egress.yaml`](../../k8s/hardening/networkpolicy-egress.yaml) denies
all egress except DNS and the API server. Commented blocks cover cloud export
and Slack. Set the API server `ipBlock` placeholder for your cluster before
applying it. Ingress is restricted separately by
[`k8s/networkpolicy.yaml`](../../k8s/networkpolicy.yaml).

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
