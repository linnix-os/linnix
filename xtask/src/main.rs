mod lab;

use anyhow::{Context, Result, bail};
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "build-ebpf" => build_ebpf(),
        "lab" => run_lab(&args[2..]),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!("Usage: cargo xtask <command>");
    eprintln!("Commands:");
    eprintln!("  build-ebpf              Build eBPF programs");
    eprintln!("  lab replay <episode>    Replay one episode, print its predicted offender");
    eprintln!("  lab score <path>        Score an episode file or directory against ground truth");
}

fn run_lab(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("replay") => {
            let path = args
                .get(1)
                .context("usage: cargo xtask lab replay <episode.json>")?;
            lab::run_replay(&PathBuf::from(path))
        }
        Some("score") => {
            let path = args
                .get(1)
                .context("usage: cargo xtask lab score <episode.json|dir>")?;
            lab::run_score(&PathBuf::from(path))
        }
        Some(other) => bail!("unknown lab subcommand: {other}"),
        None => bail!("usage: cargo xtask lab <replay|score> <path>"),
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
