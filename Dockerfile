# Multi-stage build for Linnix Cognitod
# Produces small production image with eBPF artifacts

# Stage 1: Build eBPF programs (requires nightly Rust)
FROM rust:1.90-bookworm AS ebpf-builder

# Install eBPF build dependencies
RUN apt-get update && apt-get install -y \
    llvm \
    clang \
    libelf-dev \
    linux-headers-generic \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Rust nightly for eBPF (pinned version for stability)
RUN rustup install nightly-2024-12-10
RUN rustup component add rust-src --toolchain nightly-2024-12-10

# Install bpf-linker (use specific version compatible with Rust 1.83)
RUN cargo install bpf-linker --version 0.9.13 --locked

WORKDIR /build

# Copy only Cargo files first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY linnix-ai-ebpf/Cargo.toml.bak ./linnix-ai-ebpf/
COPY linnix-ai-ebpf/linnix-ai-ebpf/Cargo.toml ./linnix-ai-ebpf/linnix-ai-ebpf/
COPY linnix-ai-ebpf/linnix-ai-ebpf-common/Cargo.toml ./linnix-ai-ebpf/linnix-ai-ebpf-common/
COPY linnix-ai-ebpf/linnix-ai-ebpf-ebpf/Cargo.toml ./linnix-ai-ebpf/linnix-ai-ebpf-ebpf/
COPY linnix-ai-ebpf/linnix-ai-ebpf-ebpf/rust-toolchain.toml ./linnix-ai-ebpf/linnix-ai-ebpf-ebpf/
COPY cognitod/Cargo.toml ./cognitod/
COPY linnix-cli/Cargo.toml ./linnix-cli/
COPY linnix-reasoner/Cargo.toml ./linnix-reasoner/

# Copy source code
COPY . .

# Build eBPF programs (cargo build script automatically compiles eBPF)
WORKDIR /build/linnix-ai-ebpf/linnix-ai-ebpf-ebpf
RUN cargo +nightly-2024-12-10 build --release --target=bpfel-unknown-none -Z build-std=core

# Stage 2: Build Rust userspace binaries
FROM rust:1.90-bookworm AS rust-builder

WORKDIR /build

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./
COPY linnix-ai-ebpf/Cargo.toml.bak ./linnix-ai-ebpf/
COPY linnix-ai-ebpf/linnix-ai-ebpf/Cargo.toml ./linnix-ai-ebpf/linnix-ai-ebpf/
COPY linnix-ai-ebpf/linnix-ai-ebpf-common/Cargo.toml ./linnix-ai-ebpf/linnix-ai-ebpf-common/
COPY cognitod/Cargo.toml ./cognitod/
COPY linnix-cli/Cargo.toml ./linnix-cli/
COPY linnix-reasoner/Cargo.toml ./linnix-reasoner/

# Copy source
COPY . .

# Build release binaries
RUN cargo build --release -p cognitod

# Stage 3: Runtime image (minimal Debian)
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create linnix user and directories
RUN useradd -r -s /bin/false linnix && \
    mkdir -p /etc/linnix /var/lib/linnix /usr/local/share/linnix && \
    chown -R linnix:linnix /var/lib/linnix

# Copy binaries from builder
COPY --from=rust-builder /build/target/release/cognitod /usr/local/bin/

# Copy eBPF programs from eBPF builder
COPY --from=ebpf-builder /build/target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf \
    /usr/local/share/linnix/

# Copy default config
COPY configs/linnix.toml /etc/linnix/linnix.toml.example
COPY configs/rules.yaml /etc/linnix/rules.yaml

# Set environment
ENV LINNIX_BPF_PATH=/usr/local/share/linnix/linnix-ai-ebpf-ebpf
ENV LINNIX_CONFIG=/etc/linnix/linnix.toml
ENV RUST_LOG=info

# Expose API port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:3000/healthz || exit 1

# Run as root (required for eBPF)
USER root

# Start cognitod
CMD ["cognitod", "--config", "/etc/linnix/linnix.toml", "--handler", "rules:/etc/linnix/rules.yaml"]
