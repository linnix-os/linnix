# Linnix on Kubernetes

This directory contains manifests to deploy Linnix as a DaemonSet on your Kubernetes cluster.

## Quick Start

```bash
kubectl apply -f k8s/
```

This will create:
- `ConfigMap/linnix-config`: Default configuration (monitor mode).
- `ServiceAccount/linnix-agent`: Identity for the agent.
- `DaemonSet/linnix-agent`: The agent pod on every node.

## Configuration

Edit `k8s/configmap.yaml` to change settings.

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

## Cloud Provider Notes

### AWS EKS

**Option A: Quick Start with `eksctl` (Recommended)**

We provide a configuration file to spin up a compatible cluster (Amazon Linux 2023, Kernel 6.1+):

```bash
# Create cluster (takes ~15 mins)
eksctl create cluster -f infrastructure/eks-cluster.yaml

# Deploy Linnix
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
   kubectl apply -f k8s/
   ```
