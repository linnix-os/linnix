# Linnix

**Find which process is hurting your SLOs — not just who's using CPU, but who's causing stalls.**

[![CI](https://github.com/linnix-os/linnix/actions/workflows/docker.yml/badge.svg)](https://github.com/linnix-os/linnix/actions/workflows/docker.yml)
[![License](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18042323.svg)](https://doi.org/10.5281/zenodo.18042323)

---

## The Problem

`top` shows 80% CPU. Prometheus shows high latency. But *which pod* is actually stalling your payment service?

Linnix uses **eBPF** + **PSI (Pressure Stall Information)** to answer this. PSI measures actual stall time — not usage, but contention. A pod using 40% CPU with 60% PSI is worse than one using 100% CPU with 5% PSI.

**What Linnix detects:**
- **Noisy Neighbors**: Which container is starving others
- **Fork Storms**: Runaway process creation before it crashes the node
- **Stall Attribution**: "Pod X caused 300ms stall to Pod Y"
- **PSI Saturation**: CPU/IO/Memory pressure that doesn't show in `top`

> [!IMPORTANT]
> **Monitor-only by default.** Linnix detects and reports — it never takes action without explicit configuration.

### 🔒 Security & Privacy

- **[Security Policy](SECURITY.md)**: See our security model, privileges required, and vulnerability reporting process
- **[Safety Guarantees](SAFETY.md)**: Understand our "Monitor-First" architecture and safety controls
- **[Architecture Overview](docs/architecture.md)**: System diagram and data flow for security reviews

**Key Promise**: All analysis happens locally. No data leaves your infrastructure unless you explicitly configure Slack notifications. [Learn more about data privacy →](SECURITY.md#data-privacy)

---

## Quickstart (Kubernetes)

Deploy Linnix as a DaemonSet to monitor your cluster.

```bash
# Apply the manifests
kubectl apply -f k8s/
```

**Access the API:**
```bash
kubectl port-forward daemonset/linnix-agent 3000:3000
# API available at http://localhost:3000
# Stream events: curl http://localhost:3000/stream
```

## Quickstart (Docker)

Try it on your local machine in 30 seconds.

```bash
git clone https://github.com/linnix-os/linnix.git && cd linnix
./quickstart.sh
```

---

## How It Works

1.  **Collector (eBPF)**: Sits in the kernel, watching `fork`, `exec`, `exit`, and scheduler events with <1% overhead.
2.  **Reasoning Engine**: Aggregates signals (PSI + CPU + Process Tree) to detect failure patterns.
3.  **Triage Assistant**: When a threshold is breached, Linnix captures the system state and explains the root cause.

### Supported Detections

| Incident Type | Detection Logic | Triage Value |
| :--- | :--- | :--- |
| **Circuit Breaker** | High PSI (>40%) + High CPU (>90%) | Identifies the *specific* process tree causing the stall. |
| **Fork Storm** | >10 forks/sec for 2s | Catches runaway scripts before they crash the node. |
| **Memory Leak** | Sustained RSS growth | Flags containers that will eventually OOM. |
| **Short-lived Jobs** | Rapid exec/exit churn | Identifies inefficient build scripts or crash loops. |

---

## Safety & Architecture

Linnix is designed for production safety.

*   **Monitor-First**: Enforcement capabilities are opt-in and require explicit configuration.
*   **Low Overhead**: Uses eBPF perf buffers, not `/proc` polling.
*   **Privilege Isolation**: Can run with `CAP_BPF` and `CAP_PERFMON` on bare metal. Kubernetes DaemonSet currently uses privileged mode for simplicity.

See [SAFETY.md](SAFETY.md) for our detailed safety model.

---

## Kubernetes Features

Linnix has first-class Kubernetes support:

- **Pod Attribution**: Every process event is tagged with `pod_name`, `namespace`, `container_id`
- **Namespace Awareness**: Filter and query by namespace
- **PSI Contribution Tracking**: See which pod contributed to system-wide PSI pressure
- **cgroup Integration**: Maps processes to their cgroups for container-level aggregation

```bash
# Example: Get processes causing stalls in the payments namespace
curl "http://localhost:3000/processes?namespace=payments&sort=psi_contribution"
```

---

## Commerce / On-Chain Settlement

Linnix includes a trustless payment layer (**Linnix-Claw**) that settles agent-to-agent work on-chain via ERC-20 stablecoins. When one agent delegates a task to another, the result — a signed receipt with telemetry proof — is submitted to a `TaskSettlement` smart contract that releases payment directly from payer to payee.

### Architecture

```
Agent A (payer)                    Agent B (payee)
   │  createTask(taskId, payeeDID, maxAmount)
   │──────────────────────────────────▶│
   │                                   │ ← does work, captures eBPF telemetry
   │    submitReceipt(taskId, amount, receipt, sig)
   │◀──────────────────────────────────│
   │                                   │
   └──── TaskSettlement.sol ─── ERC-20 transfer ──▶ payee
```

**Key contracts** (Base Sepolia testnet):

| Contract | Address |
| :--- | :--- |
| AgentRegistry | `0x9a6FeBA6d7B97ef91099051eB61F372d1EcD83a3` |
| TaskSettlement | `0x60eE6872920addF41359625B47A07401496bBD5b` |
| StakeBond | `0xEE31fC610B9b64982990adB3ba228E9dBbfF6a73` |

### Configuration

Add a `[chain]` section to your `linnix.toml`:

```toml
[chain]
enabled = true
rpc_url = "https://sepolia.base.org"
chain_id = 84532
settlement_contract = "0x60eE6872920addF41359625B47A07401496bBD5b"
registry_contract = "0x9a6FeBA6d7B97ef91099051eB61F372d1EcD83a3"
token_address = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"  # USDC on Base Sepolia
token_decimals = 6
```

The signer key is resolved in priority order:
1. `chain.private_key` in config
2. `LINNIX_CHAIN_PRIVATE_KEY` env var
3. HKDF-derived secp256k1 key from the agent's Ed25519 identity (default — zero config)

### End-to-End Demo

```bash
# Deploy contracts to a local Hardhat node
cd linnix-claw-contracts && npx hardhat node &
npx hardhat run scripts/deploy.js --network localhost

# Run the commerce demo
./scripts/demo_commerce_e2e.sh --local
```

See the [contract source](https://github.com/linnix-os/linnix-claw-contracts) and `cognitod/src/onchain.rs` for implementation details.

---

## Early Adopters

This project is under active development. If you're using it or evaluating it, open an issue or email parth21.shah@gmail.com.

---

## License

*   **Agent (`cognitod`)**: AGPL-3.0
*   **eBPF Collector**: GPL-2.0 or MIT (eBPF programs must be GPL-compatible for kernel loading)

Commercial licensing available for teams that can't use AGPL. See [LICENSE_FAQ.md](LICENSE_FAQ.md) for details.
