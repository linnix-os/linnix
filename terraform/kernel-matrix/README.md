# Incident Lab: kernel/topology matrix + injection harness

Boots N disposable EC2 cells across different kernels/architectures, each
running cognitod with `[episode_capture]` on, injects real fault scenarios
into each one, and pulls back genuine `VmCapture` episodes for `xtask lab
score` to grade per-cell. See `main.tf`'s header comment for why this is a
separate module from `../ec2`, and `episode.rs`/`config.rs` in `cognitod`
for the capture path itself.

## 1. Launch the matrix

```bash
terraform init
terraform apply \
  -var 'vpc_id=vpc-xxxx' \
  -var 'subnet_id=subnet-xxxx' \
  -var 'key_name=your-ec2-key-pair' \
  -var 'admin_cidr_blocks=["<your-ip>/32"]' \
  -var 'cells=[{name="amd64-jammy",ami_id="ami-xxxx",instance_type="t3.medium",arch="amd64"}, ...]'
```

Wait for each cell's user-data to finish (`ssh ... "tail -f /var/log/user-data.log"`
until "cognitod installed with episode_capture enabled"). This now also
installs a single-node k3s and points cognitod's `K8sContext` at it in
"manual mode" (`K8S_API_URL`/`K8S_TOKEN` env, see `k8s.rs`) -- without a real
cluster to resolve pod identity from, `PsiMonitor` never starts at all
(`main.rs` gates it on `Some(k8s_context)`), and `[episode_capture]` would be
dead config. Confirm before injecting anything:

```bash
ssh -i <key>.pem ubuntu@<cell-ip> "sudo systemctl is-active linnix-cognitod"
ssh -i <key>.pem ubuntu@<cell-ip> "sudo journalctl -u linnix-cognitod | grep 'K8s context initialized'"
```

## 2. Inject a fault, fetch the episode

```bash
./inject.sh <cell-name> <cell-ip> <key-path>.pem fork_storm datasets/episodes/vm_capture
./inject.sh <cell-name> <cell-ip> <key-path>.pem cpu_noisy_neighbor datasets/episodes/vm_capture
./inject.sh <cell-name> <cell-ip> <key-path>.pem short_job_churn datasets/episodes/vm_capture
```

Each run: deploys `scenarios/namespace.yaml`'s `payment-api` victim (left
running across scenarios), applies the named scenario's offender pod(s),
waits `INJECT_DURATION_SECONDS` (default 120s -- comfortably past
`psi.sustained_pressure_seconds`'s 15s default), tears the offender down,
diffs `/var/lib/linnix/episodes` before/after, and fetches whatever's new.
Only three scenarios are wired up -- see `../../xtask-lab/src/injection.rs`
for why `below_reporting_bar`/`multi_process_pod`/`victim_self_exclusion`
aren't.

Output files land as `<cell-name>-<scenario>-<episode_id>.json` (flat, not
nested under a per-cell directory: `xtask-lab`'s `load_episodes_from_dir` is
non-recursive). `cargo lab stamp` runs automatically at the end of each
fetch -- cognitod itself always writes a capture with `ground_truth: null`
(`Episode::from_capture`'s doc comment), since only the harness that
deployed the fault knows what it actually was.

## 3. Score the corpus

```bash
cargo lab score datasets/episodes/vm_capture
```

`VmCapture` accuracy is a number to watch per cell (e.g. arm64 without BTF
degrading to PSI-only), not a CI gate -- only the `Synthetic` breakdown from
`datasets/scenarios/` fails the build. See `xtask-lab/src/main.rs`'s
`SourceBreakdown` doc comment.

## 4. Tear down

```bash
terraform destroy
```

Each cell also self-terminates after `ttl_hours` (default 4) regardless, as
a safety net -- see `user-data.sh.tftpl`.
