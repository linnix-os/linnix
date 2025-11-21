# Contributing to Linnix

Thanks for helping improve Linnix! This guide covers how to get set up, coding standards, testing expectations, and a “Good First Issue” checklist for new contributors.

## Ways to Contribute

- **Code**: eBPF programs, the `cognitod` daemon, CLI tools, dashboards, scripts.
- **Docs**: Quickstarts, troubleshooting, or deep dives (like `docs/HOW_IT_WORKS.md`).
- **Testing**: Reproducing bugs, adding regression tests, vetting kernel compatibility.
- **Feedback**: File GitHub issues/discussions with reproducible steps and logs.

## Development Environment

```bash
git clone https://github.com/linnix-os/linnix.git
cd linnix

# Build the Rust workspace
cargo build --workspace

# Build eBPF object files
cargo xtask build-ebpf

# Run unit + integration tests
cargo test --workspace

# (Optional) run CLI tests
pushd linnix-cli && cargo test && popd
```

Recommended toolchain versions:
- Rust stable (check `rust-toolchain.toml` if present)
- `clang`/`llvm` ≥ 14 for eBPF builds
- Linux kernel 5.8+ with BTF data for local testing

## Workflow

### Install Git Hooks (Recommended)

Run checks locally before every commit:

```bash
./scripts/install-git-hooks.sh
```

This installs a pre-commit hook that automatically runs:
- `cargo fmt --check` - Code formatting
- `cargo clippy` - Lints
- `cargo nextest run` - Unit tests
- `cargo deny check` - Dependency audit (if installed)

To skip hooks temporarily: `git commit --no-verify`

### Development Steps

1. **Fork & branch**: `git checkout -b feat/my-change`
2. **Make changes** with clear, small commits.
3. **Format + lint**:
   - `cargo fmt --all`
   - `cargo clippy --all-targets -- -D warnings`
   - `cargo xtask fmt-ebpf` (if you touched eBPF code)
4. **Run tests** that cover your surface area (daemon, CLI, docs lint if applicable).
5. **Open a Pull Request** with:
   - Description of change
   - Testing evidence (command + outcome)
   - Screenshots/GIFs for UI/doc updates when helpful

## Coding Standards

- **Rust**: Keep functions small, prefer ` anyhow::Result<T> ` for daemon code, add error context with `context()`. Document non-obvious invariants with concise comments.
- **eBPF**: Avoid heap allocations, keep maps bounded, and guard optional probes (network/file IO) behind feature flags or config toggles.
- **Shell scripts**: Use `set -euo pipefail`, keep commands idempotent, document environment variables at the top.
- **Docs**: Place new pages under `docs/`, use Markdown headings, and link from `README.md` or relevant indexes so readers can find them.

## “Good First Issue” Guide

We tag approachable tasks with the `good first issue` label. To work on one:

1. **Pick an issue**: Browse [GitHub Issues](https://github.com/linnix-os/linnix/issues) filtered by the label. Comment saying you’d like to take it so maintainers can assign it.
2. **Reproduce or restate**: For bugs, share the kernel version, distribution, and exact command output that reproduces the problem. For docs/tasks, restate the desired end state to confirm understanding.
3. **Plan the change**:
   - Code issues: identify the crate/file and add a minimal test if possible.
   - Docs issues: outline the sections you will add before writing.
4. **Stay small**: Keep the PR scoped to the single issue. Open follow-ups if you discover related work.
5. **Ask for help**: Use GitHub Discussions or mention maintainers directly on the issue if you’re blocked. Sharing logs (`/tmp/cognitod*.log`) or screenshots accelerates reviews.
6. **Document verification**: Include `cargo test` output or screenshots (for docs/UI) in your PR description so reviewers can reproduce success quickly.

Great first contributions often include:
- Writing or clarifying documentation (FAQ entries, setup instructions).
- Adding targeted tests (e.g., CLI snapshot tests, reasoner config parsing).
- Improving scripts (`scripts/*.sh`) with better error handling or automation.
- Packaging tweaks (systemd unit updates, Docker fixes) that can be tested locally.

## Communication Channels

- **Issues**: Bugs, feature requests, tracking tasks.
- **Discussions**: Design proposals, deployment stories, Q&A.
- **Security**: Email `security@linnix.io` for responsible disclosure (do not open public issues).
- **Community**: Discord (`https://discord.gg/linnix`) and Twitter `@linnixhq` for quick questions.

## Licensing

By contributing, you agree that your work is licensed under the repository’s AGPL-3.0 license (and GPL-2.0 OR MIT for eBPF programs). Please ensure you have permission to contribute any code or assets you submit.

Thanks again for helping build the future of AI-assisted observability! 🚀
