//! Sequencer Ring Buffer Integration Test
//!
//! This binary tests the sequenced MPSC ring buffer by:
//! 1. Loading eBPF programs with sequencer enabled
//! 2. Consuming events from the sequencer ring
//! 3. Validating strict ordering
//! 4. Printing performance statistics

use anyhow::{Context, Result};
use aya::maps::{Array, Map};
use aya::programs::{BtfTracePoint, TracePoint};
use aya::{Btf, EbpfLoader, Pod};
use clap::Parser;
use log::{error, info, warn};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use cognitod::bpf_config::derive_telemetry_config;
use cognitod::runtime::sequencer::SequencerConsumer;
use linnix_ai_ebpf_common::TelemetryConfig;

/// Wrapper to satisfy aya's Pod requirement for set_global
#[repr(transparent)]
#[derive(Copy, Clone)]
struct TelemetryConfigPod(TelemetryConfig);

unsafe impl Pod for TelemetryConfigPod {}

#[derive(Parser, Debug)]
#[command(name = "sequencer-test", about = "Test the sequenced MPSC ring buffer")]
struct Args {
    /// Duration to run the test in seconds
    #[arg(short, long, default_value = "10")]
    duration: u64,

    /// Path to the eBPF object file
    #[arg(
        short,
        long,
        default_value = "target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf"
    )]
    bpf_path: String,

    /// Batch size for polling
    #[arg(short = 'B', long, default_value = "256")]
    batch_size: usize,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    info!("Sequencer Ring Buffer Test");
    info!("===========================");
    info!("Duration: {}s", args.duration);
    info!("BPF Path: {}", args.bpf_path);
    info!("Batch Size: {}", args.batch_size);

    // Load eBPF program
    info!("Loading eBPF programs...");
    let bpf_data = std::fs::read(&args.bpf_path)
        .with_context(|| format!("Failed to read BPF object from {}", args.bpf_path))?;

    // ==========================================================================
    // LOAD TELEMETRY CONFIG (CO-RE: Runtime Offset Discovery)
    // ==========================================================================
    // This populates TELEMETRY_CONFIG with task_struct field offsets discovered
    // from the host kernel's BTF. Required for portable BTF raw tracepoints.
    let telemetry_result =
        derive_telemetry_config().context("Failed to derive telemetry config from kernel BTF")?;

    info!(
        "Telemetry config loaded: task_tgid_offset=0x{:x}, task_comm_offset=0x{:x}",
        telemetry_result.config.task_tgid_offset, telemetry_result.config.task_comm_offset
    );

    // Load eBPF with telemetry config injected into global variable
    let telemetry_pod = TelemetryConfigPod(telemetry_result.config);
    let mut loader = EbpfLoader::new();
    loader.set_global("TELEMETRY_CONFIG", &telemetry_pod, true);
    let mut ebpf = loader
        .load(&bpf_data)
        .context("Failed to load eBPF program")?;

    // Load BTF from /sys/kernel/btf/vmlinux for raw tracepoints
    let btf = Btf::from_sys_fs().ok();
    let btf_available = btf.is_some();

    // ==========================================================================
    // FORK HANDLER - Prefer BTF raw tracepoint for maximum performance
    // ==========================================================================
    let use_btf_fork = btf_available && ebpf.program("handle_fork_raw").is_some();

    if use_btf_fork {
        let btf_ref = btf.as_ref().unwrap();
        let prog: &mut BtfTracePoint = ebpf
            .program_mut("handle_fork_raw")
            .context("Failed to find handle_fork_raw BTF program")?
            .try_into()
            .context("Failed to convert to BtfTracePoint")?;
        prog.load("sched_process_fork", btf_ref)
            .context("Failed to load BTF fork program")?;
        prog.attach()
            .context("Failed to attach BTF fork tracepoint")?;
        info!("Fork BTF tracepoint attached (SPEED DEMON MODE)");
    } else {
        let prog: &mut TracePoint = ebpf
            .program_mut("handle_fork")
            .context("Failed to find handle_fork program")?
            .try_into()
            .context("Failed to convert to TracePoint")?;
        prog.load().context("Failed to load fork program")?;
        prog.attach("sched", "sched_process_fork")
            .context("Failed to attach fork tracepoint")?;
        info!("Fork tracepoint attached (fallback mode)");
    }

    // ==========================================================================
    // EXEC HANDLER - Prefer BTF raw tracepoint for maximum performance
    // ==========================================================================
    let use_btf_exec = btf_available && ebpf.program("handle_exec_raw").is_some();

    if use_btf_exec {
        let btf_ref = btf.as_ref().unwrap();
        let prog: &mut BtfTracePoint = ebpf
            .program_mut("handle_exec_raw")
            .context("Failed to find handle_exec_raw BTF program")?
            .try_into()
            .context("Failed to convert to BtfTracePoint")?;
        prog.load("sched_process_exec", btf_ref)
            .context("Failed to load BTF exec program")?;
        prog.attach()
            .context("Failed to attach BTF exec tracepoint")?;
        info!("Exec BTF tracepoint attached (SPEED DEMON MODE)");
    } else {
        let prog: &mut TracePoint = ebpf
            .program_mut("linnix_ai_ebpf")
            .context("Failed to find exec program")?
            .try_into()
            .context("Failed to convert to TracePoint")?;
        prog.load().context("Failed to load exec program")?;
        prog.attach("sched", "sched_process_exec")
            .context("Failed to attach exec tracepoint")?;
        info!("Exec tracepoint attached (fallback mode)");
    }

    // ==========================================================================
    // EXIT HANDLER - Prefer BTF raw tracepoint for maximum performance
    // ==========================================================================
    let use_btf_exit = btf_available && ebpf.program("handle_exit_raw").is_some();

    if use_btf_exit {
        let btf_ref = btf.as_ref().unwrap();
        let prog: &mut BtfTracePoint = ebpf
            .program_mut("handle_exit_raw")
            .context("Failed to find handle_exit_raw BTF program")?
            .try_into()
            .context("Failed to convert to BtfTracePoint")?;
        prog.load("sched_process_exit", btf_ref)
            .context("Failed to load BTF exit program")?;
        prog.attach()
            .context("Failed to attach BTF exit tracepoint")?;
        info!("Exit BTF tracepoint attached (SPEED DEMON MODE)");
    } else {
        let prog: &mut TracePoint = ebpf
            .program_mut("handle_exit")
            .context("Failed to find handle_exit program")?
            .try_into()
            .context("Failed to convert to TracePoint")?;
        prog.load().context("Failed to load exit program")?;
        prog.attach("sched", "sched_process_exit")
            .context("Failed to attach exit tracepoint")?;
        info!("Exit tracepoint attached (fallback mode)");
    }

    // IMPORTANT: Create consumer FIRST (before enabling sequencer)
    // This ensures the ring buffer is zeroed before eBPF starts writing.
    // Otherwise we race: eBPF writes -> memset overwrites -> corruption.
    info!("Creating sequencer consumer (mmap mode)...");

    // Take ownership of the ring map - we need to keep it alive for the mmap
    let ring_map = ebpf
        .take_map("SEQUENCER_RING")
        .context("Failed to find SEQUENCER_RING map")?;

    // Extract MapData from the Map enum
    let ring_map_data = match ring_map {
        Map::Array(data) => data,
        other => anyhow::bail!("SEQUENCER_RING is not an Array map, got {:?}", other),
    };

    // Get the fd from MapData and create consumer with mmap
    // Note: ring_map_data must stay alive for the mmap to remain valid
    let fd = ring_map_data.fd().as_fd();
    info!("SEQUENCER_RING map fd: {:?}", fd);

    // Create consumer - this will mmap AND ZERO the ring buffer
    let consumer = SequencerConsumer::from_fd(fd)
        .context("Failed to create SequencerConsumer. Ensure BPF_F_MMAPABLE flag is set.")?;

    // NOTE: SEQUENCER_INDEX is now a .bss global variable (GLOBAL_SEQUENCER),
    // not a BPF map. It automatically initializes to 0 when the eBPF program loads.
    // No explicit reset is needed!
    info!("Sequencer index auto-initialized to 0 (via .bss global)");

    // Enable sequencer mode - NOW eBPF will start writing to the clean ring
    info!("Enabling sequencer mode...");
    {
        let mut enabled_map: Array<_, u32> = Array::try_from(
            ebpf.map_mut("SEQUENCER_ENABLED")
                .context("Failed to find SEQUENCER_ENABLED map")?,
        )
        .context("Failed to create Array from SEQUENCER_ENABLED map")?;

        enabled_map
            .set(0, 1, 0)
            .context("Failed to set SEQUENCER_ENABLED to 1")?;
        info!("Sequencer ENABLED in eBPF");
    }

    // Run the consumer loop
    // NOTE: Disabled ctrlc handler because it was causing stress-ng to be interrupted
    // The test will just run for the specified duration.

    info!("Starting consumer loop for {}s...", args.duration);
    info!(
        "(Generate load with: stress-ng --fork 16 --timeout {}s)",
        args.duration
    );

    let start = Instant::now();
    let deadline = start + Duration::from_secs(args.duration);
    let mut consumer = consumer;
    let mut total_events: u64 = 0;
    let mut poll_cycles: u64 = 0;
    let mut max_batch: usize = 0;
    let mut empty_polls: u64 = 0;

    while Instant::now() < deadline {
        let events = consumer.poll_batch(args.batch_size);
        poll_cycles += 1;

        if events.is_empty() {
            empty_polls += 1;
            // Sleep briefly to avoid busy-spinning
            std::thread::sleep(Duration::from_micros(100));
        } else {
            let batch_size = events.len();
            total_events += batch_size as u64;
            if batch_size > max_batch {
                max_batch = batch_size;
            }
        }
    }

    let elapsed = start.elapsed();
    let stats = consumer.stats();

    // Print results
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           SEQUENCER RING BUFFER TEST RESULTS                 ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!(
        "║ Duration:              {:>10.2}s                          ║",
        elapsed.as_secs_f64()
    );
    println!(
        "║ Total Events:          {:>10}                           ║",
        stats.events_processed
    );
    println!(
        "║ Events/sec:            {:>10.0}                           ║",
        stats.events_processed as f64 / elapsed.as_secs_f64()
    );
    println!(
        "║ Poll Cycles:           {:>10}                           ║",
        poll_cycles
    );
    println!(
        "║ Empty Polls:           {:>10}                           ║",
        empty_polls
    );
    println!(
        "║ Max Batch Size:        {:>10}                           ║",
        max_batch
    );
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!(
        "║ Events Reaped:         {:>10}                           ║",
        stats.events_reaped
    );
    println!(
        "║ Events Abandoned:      {:>10}                           ║",
        stats.events_abandoned
    );
    println!(
        "║ Ordering Violations:   {:>10}                           ║",
        stats.ordering_violations
    );
    println!("╚══════════════════════════════════════════════════════════════╝");

    if stats.ordering_violations > 0 {
        error!(
            "❌ ORDERING VIOLATIONS DETECTED: {}",
            stats.ordering_violations
        );
    } else if stats.events_processed > 0 {
        info!(
            "✅ All {} events processed in strict order",
            stats.events_processed
        );
    } else {
        warn!("⚠️  No events captured. Run stress-ng to generate events.");
    }

    Ok(())
}
