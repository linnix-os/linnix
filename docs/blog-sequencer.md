# We Made eBPF Capture 100% of Events (Perf Buffers Drop Up to 77%)

*How we applied the LMAX Disruptor pattern to kernel-space observability*

---

If you've built production eBPF tooling, you've hit this wall: **perf buffers drop events under load**.

We ran benchmarks on a 192-core AMD EPYC and found that standard `BPF_PERF_EVENT_ARRAY` drops up to **77% of events** at high core counts. Our solution—a wait-free ring buffer inspired by the LMAX Disruptor—captures **100% with zero ordering violations**.

Here's what we learned.

## The Problem: Neither Primitive Scales

Modern eBPF tools have two choices for streaming events to userspace:

1. **`BPF_PERF_EVENT_ARRAY`** (legacy): Per-CPU buffers. Fast, but no global ordering and drops events under uneven load.

2. **`BPF_RINGBUF`** (Linux 5.8+): Shared ring buffer with strict ordering. The preferred choice for modern tools like Falco, Tetragon, and Tracee.

So why not just use `BPF_RINGBUF`? **It uses a spinlock for synchronization, which collapses at high core counts.**

We tested with a fixed workload (50K fork operations = ~100K kernel events):


| Cores | Perf Buffer Events | Capture Rate |
|-------|-------------------|--------------|
| 8 | 90,191 | 90% |
| 32 | 59,650 | 60% |
| 64 | 38,312 | 38% |
| 128 | 26,862 | 27% |
| 192 | 23,327 | **23%** |

At 192 cores, perf buffers drop **77% of events**. Silently. No errors. Just missing data.

## Why Both Primitives Struggle

**Perf Buffer** (`BPF_PERF_EVENT_ARRAY`):
```
CPU 0: [per-CPU buffer] → full, drop events
CPU 1: [per-CPU buffer] → full, drop events  
...
CPU 191: [per-CPU buffer] → you get the idea
```
Each per-CPU buffer has fixed capacity (~64KB). Userspace can't drain 192 buffers fast enough.

**Ring Buffer** (`BPF_RINGBUF`):
```
CPU 0──┐
CPU 1──┼── spin_lock(&lock) ── [shared buffer]
CPU 2──┘   ↑ contention!
```
Acquires a kernel spinlock on every write. At 64+ cores, CPUs spend more time waiting for the lock than processing events.

Neither primitive provides: **Global ordering + Wait-free operation + High throughput**.

## The Fix: LMAX Disruptor in Kernel Space

The [LMAX Disruptor](https://lmax-exchange.github.io/disruptor/) is a high-performance queue used by trading systems. Key insight: **replace locks with atomic ticket counters**.

Instead of N per-CPU buffers, we use:
- **One shared 128MB ring buffer** (mmap'd into userspace)
- **One atomic counter** for global sequencing
- **Zero-copy reads** via mmap

```rust
// Get globally-unique sequence number (wait-free)
let seq = GLOBAL_SEQUENCER.fetch_add(1, Ordering::Relaxed);

// Write directly to slot
ring[seq % RING_SIZE] = event;
```

Hardware atomic operations complete in ~20-50 cycles. Spinlock contention can cost thousands of cycles plus context switches.

## Results

Same workload, same hardware, dramatic difference:

| Cores | Perf Buffer | Sequencer | Ordering Violations |
|-------|-------------|-----------|---------------------|
| 8 | 90% | **100%** | 0 |
| 32 | 60% | **100%** | 0 |
| 64 | 38% | **100%** | 0 |
| 128 | 27% | **100%** | 0 |
| 192 | 23% | **100%** | 0 |

**Zero events dropped. Zero ordering violations. At 192 cores.**

## Why This Matters

Missing events means:
- **Security**: Attacks slip through undetected
- **Debugging**: Race conditions are impossible to reproduce
- **Compliance**: Audit trails have gaps

If you're building eBPF tooling for high-core-count systems, standard primitives will fail you—silently.

## Try It

Linnix is open source: [github.com/linnix-os/linnix](https://github.com/linnix-os/linnix)

The sequencer implementation lives in `linnix-ai-ebpf/` and `cognitod/src/runtime/sequencer.rs`.

Full technical details in our [white paper](./whitepaper.md).

---

*Questions? Find us on GitHub or reach out on Twitter [@linnix_os](https://twitter.com/linnix_os).*
