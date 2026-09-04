use anyhow::{Context, Result};
use std::process::Command;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: cargo xtask <command>");
        eprintln!("Commands:");
        eprintln!("  build-ebpf    Build eBPF programs");
        eprintln!();
        eprintln!("The Incident Lab CLI (replay/score episodes) lives in a separate");
        eprintln!("binary, `cargo lab`, so `cargo xtask build-ebpf` never has to compile");
        eprintln!("cognitod under the pinned eBPF nightly toolchain.");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "build-ebpf" => build_ebpf(),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            std::process::exit(1);
        }
    }
}

fn build_ebpf() -> Result<()> {
    let status = Command::new("cargo")
        .args([
            "build",
            "--package",
            "linnix-ai-ebpf-ebpf",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ])
        .env("RUSTUP_TOOLCHAIN", "nightly-2024-12-10")
        .status()
        .context("Failed to execute cargo build for eBPF")?;

    if !status.success() {
        anyhow::bail!("eBPF build failed with exit code: {}", status);
    }

    println!("✅ eBPF programs built successfully");
    Ok(())
}
