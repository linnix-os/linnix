# Troubleshooting

## Common Issues

### eBPF Load Failure

**Symptom**: "Failed to load eBPF program"

**Solutions**:
1. Check kernel version: `uname -r` (need 5.4+)
2. Verify capabilities: `getcap /usr/local/bin/cognitod`
3. Check BTF: `ls /sys/kernel/btf/vmlinux`
4. Run with sudo for initial testing

### API Not Responding

**Symptom**: `curl localhost:3000/healthz` fails

**Solutions**:
1. Check if running: `systemctl status cognitod`
2. Check logs: `journalctl -u cognitod -f`
3. Verify listen address in config
4. Check port conflicts: `netstat -tlnp | grep 3000`

### No Insights Generated

**Symptom**: `/insights` returns empty

**Solutions**:
1. Check LLM server: `curl localhost:8090/health`
2. Verify reasoner config in linnix.toml
3. Check `min_eps_to_enable` threshold
4. Generate some activity: `stress --cpu 1 --timeout 10`

### High CPU Usage

**Symptom**: cognitod using >5% CPU

**Solutions**:
1. Increase `sample_interval_ms`
2. Disable optional probes
3. Check for fork storms on host
4. Review event rate: `curl localhost:3000/metrics | jq .events_per_second`

## Diagnostic Commands

```bash
# Service status
systemctl status cognitod

# View logs
journalctl -u cognitod -f

# Health check
curl http://localhost:3000/healthz

# Full status
curl http://localhost:3000/status | jq

# Check eBPF programs
bpftool prog list | grep linnix

# Run doctor
linnix-cli doctor

# Check metrics
curl http://localhost:3000/metrics | jq
```

## Log Analysis

```bash
# Filter errors
journalctl -u cognitod --since "1 hour ago" | grep -E "ERROR|error|failed"

# Check startup
journalctl -u cognitod | head -50
```

---
*For additional help, open an issue on GitHub.*
