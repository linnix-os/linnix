# Linnix on Kubernetes

This directory contains manifests to deploy Linnix as a DaemonSet on your Kubernetes cluster.

## Quick Start

```bash
kubectl create secret generic linnix-api-token \
  --namespace default \
  --from-literal=token="$(openssl rand -base64 32)"
kubectl apply -f k8s/
```

This will create:
- `Secret/linnix-api-token`: Operator-created bearer token for the API.
- `ConfigMap/linnix-config`: Default configuration (monitor mode, no secrets).
- `ServiceAccount/linnix-agent`: Identity for the agent.
- `DaemonSet/linnix-agent`: The agent pod on every node.
- `NetworkPolicy/linnix-agent-ingress`: Restricts access to the privileged API.

## Configuration

Edit `k8s/configmap.yaml` to change settings.

The API on port 3000 binds to all pod interfaces and requires
`LINNIX_API_TOKEN`, which the DaemonSet reads from `Secret/linnix-api-token`
key `token`. Do not add the token to the ConfigMap. Workloads that need the API
must have label `linnix.io/api-access: "true"`, be in the same namespace, and
send `Authorization: Bearer <token>`.

Prometheus, liveness, and readiness use the separate unauthenticated
operational listener on port 9464. It exposes only `/metrics/prometheus`,
`/healthz`, and `/readyz`; it cannot serve process, incident, or action data.
The included NetworkPolicy allows this port from pods in any namespace. Narrow
the Prometheus rule to your collector's labels if your cluster policy supports
that selector. It takes effect only with a CNI that enforces Kubernetes
NetworkPolicy.

### Capabilities & Privileges

Linnix requires eBPF privileges. The default `daemonset.yaml` uses `privileged: true` for simplicity.

For tighter security, you can disable privileged mode and use capabilities (requires kernel 5.8+ and container runtime support):

```yaml
securityContext:
  privileged: false
  capabilities:
    add: ["BPF", "PERFMON", "SYS_RESOURCE", "SYS_ADMIN"]
```

### Host Mounts

Linnix mounts:
- `/sys/kernel/btf/vmlinux`: For BTF type information (required for CO-RE).
- `/sys/kernel/debug`: For debugfs (tracepoints).
- `hostPID: true`: To correlate events with host processes.

### State & Identity

The DaemonSet mounts a `hostPath` volume at `/var/lib/linnix` and injects
`NODE_NAME` from the downward API (`spec.nodeName`). Both are required for
the agent's identity to survive pod restarts:

- **Durable state**: `/var/lib/linnix` holds `incidents.db`, the cloud
  exporter's `cloud_identity.json` (agent instance ID, batch sequence,
  export watermark), and the `cloud_spool/` batch queue. Without the
  hostPath mount, every pod restart would mint a new agent instance ID,
  reset the batch sequence to 0, drop queued-but-unsent batches, and
  re-export already-sent incidents — breaking the edge's gap detector and
  batch idempotency keys.
- **Stable node name**: the agent resolves its node ID as
  `NODE_NAME` → `HOSTNAME` → OS hostname and persists the first value it
  sees. `HOSTNAME` inside a pod is the pod name, which changes on every
  restart; `spec.nodeName` is the actual Kubernetes node name and is
  stable, so the persisted identity stays bound to the node.

`hostPath` is the simplest correct choice for a DaemonSet: exactly one pod
runs per node, so node-local storage is the right scope — no PVCs or
storage classes needed. `DirectoryOrCreate` provisions the directory on
fresh nodes automatically. Note the agent runs privileged and stores its
operational state here; treat host access to `/var/lib/linnix` like host
disk access generally. If you override the incident DB location with
`LINNIX_INCIDENT_DB`, point the mount at that path's parent directory
instead.

## Cloud Provider Notes

### AWS EKS

**Option A: Quick Start with `eksctl` (Recommended)**

We provide a configuration file to spin up a compatible cluster (Amazon Linux 2023, Kernel 6.1+):

```bash
# Create cluster (takes ~15 mins)
eksctl create cluster -f infrastructure/eks-cluster.yaml

# Create the Secret from Quick Start, then deploy Linnix
kubectl apply -f k8s/
```

**Option B: Existing Cluster**

1. **Connect to Cluster**:
   ```bash
   aws eks update-kubeconfig --region region-code --name my-cluster
   ```

2. **Kernel Support**:
   Ensure your node group uses **Amazon Linux 2023** or a recent **Bottlerocket** OS (Kernel 5.10+ with BTF enabled).
   Older Amazon Linux 2 might require a kernel upgrade for full eBPF support.

3. **Deploy**:
   ```bash
   # Create the Secret from Quick Start, then deploy Linnix
   kubectl apply -f k8s/
   ```
