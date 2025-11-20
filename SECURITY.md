# Security Model

## Overview

Linnix requires elevated privileges to monitor system-level events using eBPF. This document explains the security model and mitigations in place.

## Why Root + Capabilities are Required

eBPF monitoring requires two Linux capabilities:
- **CAP_BPF**: Load and manage eBPF programs
- **CAP_PERFMON**: Access kernel tracepoints and perf buffers

**Docker limitation**: Capabilities only work reliably for the root user in containers. Linnix runs as root but with ONLY these two capabilities (all others are implicitly dropped).

## Security Mitigations

### 1. Minimal Capabilities (Principle of Least Privilege)

The container runs with ONLY two capabilities:
```yaml
cap_add:
  - BPF         # Load eBPF programs
  - PERFMON     # Access perf events
```

All other capabilities are implicitly dropped. This is far more restrictive than:
- Running with `--privileged` (grants ALL 40+ capabilities)
- Running with `sudo` on the host (full root access)

### 2. Read-Only Root Filesystem

```yaml
read_only: true
tmpfs:
  - /tmp
  - /var/run
```

The container cannot modify its own binaries or configuration. Only temporary directories are writable.

### 3. No Privilege Escalation

```yaml
security_opt:
  - no-new-privileges:true
```

Prevents processes from gaining additional privileges through setuid binaries or capability inheritance.

### 4. Process Isolation

```yaml
pid: host  # Required to monitor host processes
```

While the container shares the host PID namespace (required for monitoring), it cannot:
- Kill arbitrary host processes (no CAP_KILL)
- Change process priorities (no CAP_SYS_NICE)
- Trace processes (no CAP_SYS_PTRACE)

### 5. Network Isolation

```yaml
network_mode: host
```

Host network mode is required to monitor network connections. However:
- Container cannot bind to privileged ports <1024 (no CAP_NET_BIND_SERVICE)
- Cannot modify network configuration (no CAP_NET_ADMIN)

## Attack Surface Analysis

### What an Attacker CANNOT Do

Even if an attacker gains shell access inside the container:

1. **Cannot escalate to host root**: no-new-privileges prevents privilege escalation
2. **Cannot modify binaries**: read-only root filesystem
3. **Cannot access host filesystem**: no volume mounts to sensitive host paths
4. **Cannot kill host processes**: no CAP_KILL capability
5. **Cannot modify kernel**: no CAP_SYS_MODULE or CAP_SYS_ADMIN

### What an Attacker COULD Do

With CAP_BPF + CAP_PERFMON, an attacker could:

1. **Read kernel memory**: eBPF programs can read arbitrary kernel data structures
2. **Monitor all processes**: See process arguments, environment variables, file descriptors
3. **DOS via malicious eBPF**: Load poorly written eBPF programs that consume kernel resources

**Mitigation**: The kernel's eBPF verifier prevents:
- Infinite loops
- Out-of-bounds memory access
- Arbitrary kernel writes (eBPF is read-only by design)

## Comparison to Alternatives

| Approach | Security Level | eBPF Support |
|----------|---------------|--------------|
| **Current (root + 2 caps only)** | **Medium-High** | Full |
| --privileged flag | Very Low (40+ caps) | Full |
| Host + sudo | Low (full root access) | Full |
| Host + setcap (non-root) | High (2 caps, no root) | Full |

## Best Practices for Production

1. **Use official images**: Pull from `ghcr.io/linnix-os/cognitod:latest` (signed releases)
2. **Pin image versions**: Use specific tags instead of `latest`
3. **Audit eBPF programs**: Linnix eBPF code is open source and auditable
4. **Monitor the monitor**: Use Docker logs and healthchecks to detect anomalies
5. **Network isolation**: Run on isolated networks if possible
6. **Regular updates**: Keep Linnix and base images updated for security patches

## API Authentication

### Default Configuration

Linnix binds to `127.0.0.1:3000` by default (localhost only, no authentication required).

### Remote Access

For remote access, configure authentication:

**Environment Variable (Recommended):**
```bash
export LINNIX_API_TOKEN="$(openssl rand -hex 32)"
```

**Configuration File:**
```toml
# /etc/linnix/linnix.toml
[api]
listen_addr = "0.0.0.0:3000"
auth_token = "your-secret-token"
```

**Priority:** `LINNIX_API_TOKEN` env var overrides config file.

### Client Usage

**cURL:**
```bash
curl -H "Authorization: Bearer your-secret-token" \
  http://your-server:3000/processes
```

**SSH Tunnel (No Auth Required):**
```bash
ssh -L 3000:localhost:3000 user@server
curl http://localhost:3000/processes
```

## Reporting Security Issues

If you discover a security vulnerability:

1. **DO NOT** open a public GitHub issue
2. Email: security@linnix.com (if available) OR
3. Open a private security advisory on GitHub

## Native Installation (Alternative)

For environments where Docker is not acceptable, you can install natively:

```bash
# Download binary
wget https://github.com/linnix-os/linnix/releases/latest/download/cognitod-linux-amd64

# Grant capabilities (one-time, requires sudo)
sudo setcap cap_bpf+eip cap_perfmon+eip cognitod-linux-amd64

# Run as non-root user (no sudo needed)
./cognitod-linux-amd64
```

This approach:
- Runs as your regular user (not root)
- Uses file capabilities instead of container capabilities
- No Docker overhead

**Trade-off**: Requires direct access to host kernel, no container isolation.

## References

- [Linux Capabilities Man Page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [eBPF Security Documentation](https://ebpf.io/what-is-ebpf/#security)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
