# The Cost of Causality: High-Frequency, Causal Observability with eBPF Sequencers

*A Technical White Paper by Linnix*

**Draft: December 2025**

---

## Abstract

Production observability faces a fundamental tradeoff: standard eBPF primitives force a choice between throughput and ordering. `BPF_PERF_EVENT_ARRAY` delivers high throughput through per-CPU buffers but sacrifices global event ordering—making it impossible to diagnose race conditions and process lifecycle bugs. `BPF_RINGBUF` provides ordering through a shared ring but collapses under spinlock contention at high core counts.

This paper introduces **Linnix-Sequencer**, a wait-free eBPF primitive that achieves strict global ordering at line rate. Based on the LMAX Disruptor pattern, our approach replaces kernel spinlocks with an atomic serialization point: a cache-line-aligned ticket counter that moves contention from software (OS scheduler) to hardware (CPU mesh interconnect). Combined with BTF-powered raw tracepoints and zero-copy mmap, the sequencer **captures 100% of kernel events** while standard perf buffers drop up to 77% at high core counts—maintaining **zero ordering violations** across 8 to 192 cores on AMD EPYC systems.

---

## 1. Introduction: The Observability Uncertainty Principle

Modern distributed systems require precise event ordering to debug race conditions, reconstruct attack timelines, and ensure correctness. Yet the very act of observing high-frequency kernel events introduces a fundamental tradeoff—what we call the **Observability Uncertainty Principle**:

> *High-throughput event capture destroys the ordering required to diagnose the bugs it detects.*

### 1.1 The Problem

Consider a common production scenario: a process forks, the child executes, and an exit event occurs. A security or debugging tool must capture these events in the exact order they occurred. Any misordering could:

- **False positives**: An exit appearing before a fork suggests a process that died before it was born
- **Missed attacks**: A privilege escalation detected after a kill appears as normal termination
- **Debugging failures**: Race condition analysis requires nanosecond-accurate causality

Standard Linux eBPF primitives force a choice:

| Primitive | Throughput | Global Ordering | Scalability |
|-----------|------------|-----------------|-------------|
| `BPF_PERF_EVENT_ARRAY` | ✓ High | ✗ Per-CPU only | ✓ Linear |
| `BPF_RINGBUF` | Medium | ✓ Single producer | ✗ Spinlock collapse |
| **Linnix-Sequencer** | **✓ High** | **✓ Global** | **✓ Linear** |

### 1.2 Our Contribution

We present the first wait-free, strictly-ordered eBPF primitive that doesn't sacrifice throughput. Our key insight: **move contention from software (kernel spinlocks) to hardware (atomic CPU operations)**. This paper documents:

1. **Design**: An LMAX Disruptor-inspired architecture for kernel space
2. **Implementation**: BTF-powered raw tracepoints, zero-copy mmap, and cache-line optimization
3. **Evaluation**: 100% event capture at all core counts (vs 23-90% for perf buffers) with zero ordering violations

---

## 2. Background: Why Standard Primitives Fail

### 2.1 BPF_PERF_EVENT_ARRAY: High Throughput, No Ordering

The perf event array provides one ring buffer per CPU. Each CPU writes events to its own buffer, eliminating cross-core synchronization:

```
CPU 0: [fork₁] [exec₂] [fork₃] ...
CPU 1: [exit₁] [fork₂] [exec₃] ...
CPU 2: [exec₁] [exit₂] [fork₃] ...
```

**Problem**: Userspace receives N independent streams. Merging by timestamp is unreliable—clock skew between cores, NMI delays, and scheduler jitter introduce reordering. A fork on CPU 0 and its child's exit on CPU 1 may appear in wrong order.

### 2.2 BPF_RINGBUF: Ordering via Spinlock

The ring buffer uses a kernel spinlock to serialize writes from all CPUs to a single buffer:

```c
spin_lock(&ring->spinlock);
slot = ring->head++;
memcpy(&ring->data[slot], event, size);
spin_unlock(&ring->spinlock);
```

**Problem**: At high core counts (64+), spinlock contention becomes catastrophic. CPUs spend more time waiting for the lock than processing events. Throughput collapses, and the spinlock can even block the application being observed—violating the fundamental principle that observability should not perturb the system.

### 2.3 The Gap

No existing primitive provides: **Global ordering + Wait-free operation + High throughput**. This gap forces observability tool authors to accept compromised data quality or restricted scale.

---

## 3. Design: LMAX Disruptor in Kernel Space

The Linnix-Sequencer is built on three pillars:

### 3.1 The Atomic Ticket Counter

Instead of a spinlock, we use an atomic ticket counter placed in a dedicated cache line:

```rust
#[repr(C, align(64))]  // Cache-line aligned
struct GlobalSequencer {
    value: u64,         // Ticket counter
    _padding: [u8; 56], // Fill to 64 bytes
}

static GLOBAL_SEQUENCER: GlobalSequencer = ...;
```

Each producer atomically increments this counter to claim a unique sequence number:

```rust
let seq = GLOBAL_SEQUENCER.value.fetch_add(1, Ordering::Relaxed);
// seq is now this producer's globally-unique, strictly-ordered position
```

**Key insight**: This is still a serialization point, but contention now happens in **hardware** (the CPU cache coherency protocol), not **software** (the OS scheduler). Hardware atomic operations complete in ~20-50 cycles; spinlock contention can cost thousands of cycles plus context switches.

### 3.2 The Zero-Copy Ring Buffer

Events are written directly to an mmap-backed BPF array:

```
┌──────────────────────────────────────────────────────────────┐
│ Kernel Space                                                 │
│  CPU₀──┐                                                     │
│  CPU₁──┼─► [Atomic fetch_add] ─► slot_index ─► Ring Buffer   │
│  CPU₂──┘                              │                      │
│                                       ▼                      │
│           ┌────────────────────────────────────────────┐     │
│           │ Slot 0 │ Slot 1 │ Slot 2 │ ... │ Slot N    │     │
│           └────────┴────────┴────────┴─────┴───────────┘     │
└──────────────────────────────────────┼───────────────────────┘
                                       │ mmap (zero-copy)
┌──────────────────────────────────────┼───────────────────────┐
│ Userspace                            ▼                       │
│           ┌────────────────────────────────────────────┐     │
│           │ Slot 0 │ Slot 1 │ Slot 2 │ ... │ Slot N    │     │
│           └────────┴────────┴────────┴─────┴───────────┘     │
│                       Consumer reads sequentially            │
└──────────────────────────────────────────────────────────────┘
```

- **128MB ring** with 1 million 128-byte slots
- **BPF_F_MMAPABLE** flag enables direct userspace access
- **No syscalls** on the hot path—consumer reads directly from RAM

### 3.3 The Consumer Protocol

The consumer advances through slots using sequence number validation:

```rust
loop {
    let slot = &ring[consumer_index % RING_SIZE];
    if slot.seq == consumer_index && slot.flags == READY {
        process_event(slot);
        consumer_index += 1;
    }
}
```

**Key property**: Events are processed in exact sequence order, regardless of which CPU produced them or when the write completed.

---

## 4. Implementation Details

### 4.1 BTF-Powered Raw Tracepoints

Standard tracepoints incur overhead from kernel argument marshaling. BTF raw tracepoints provide direct struct access:

```rust
// Standard: kernel copies arguments to stack
fn handle_sched_process_fork(parent_pid: u32, child_pid: u32) { ... }

// BTF raw: direct access to task_struct
fn handle_sched_process_fork_btf(ctx: RawTracePointContext) {
    let task = unsafe { bpf_get_current_task_btf() };
    let pid = task.tgid;   // Direct memory access
    let comm = task.comm;  // No marshaling overhead
}
```

Offsets are discovered at runtime via `/sys/kernel/btf/vmlinux`, enabling portable binaries.

### 4.2 Huge Page Optimization

A 128MB ring spans 32,768 pages at 4KB. Each TLB miss costs ~100ns for page table walks. We advise the kernel to use 2MB huge pages:

```rust
unsafe {
    libc::madvise(ring_ptr, RING_SIZE, libc::MADV_HUGEPAGE);
}
```

This reduces TLB entries from 32K to ~64, dramatically improving cache locality.

### 4.3 Cache-Line Alignment

Each slot spans exactly **two cache lines** (128 bytes):

- **Line 1**: Metadata (sequence number, flags, timestamp)
- **Line 2**: Event payload

This ensures:
- Producer writes don't cause false sharing on consumer reads
- Adjacent slots don't share cache lines

---

## 5. Evaluation

### 5.1 Test Environment

| Property | Value |
|----------|-------|
| **Hardware** | AWS c6a.48xlarge (192 vCPUs) |
| **CPU** | AMD EPYC 7R13 (Milan) |
| **Kernel** | Linux 6.8.0-1044-aws |
| **Workload** | `stress-ng --fork N --fork-ops 50000` (fixed 50K fork operations) |
| **Core Counts** | 8, 32, 64, 128, 192 |
| **Methodology** | Fixed workload ensures identical event count across tests |

### 5.2 Throughput Results

To ensure a fair comparison, we ran both modes against an identical fixed workload (50,000 fork operations) across increasing core counts on a c6a.48xlarge (192 vCPUs, AMD EPYC 7R13).

| Cores | Perf Buffer | Sequencer | Perf Capture Rate | Ordering Violations |
|-------|-------------|-----------|-------------------|---------------------|
| 8 | 90,191 | 100,150 | **90%** | **0** |
| 32 | 59,650 | 100,269 | **60%** | **0** |
| 64 | 38,312 | 100,103 | **38%** | **0** |
| 128 | 26,862 | 100,231 | **27%** | **0** |
| 192 | 23,327 | 100,232 | **23%** | **0** |

*Each test: 50,000 fork operations = ~100K total kernel events (fork + exit + exec)*

**Key findings:**

1. **Perf buffer capture degrades with scale**: From 90% at 8 cores to just 23% at 192 cores
2. **Sequencer captures 100% at all core counts**: No degradation as cores increase
3. **Zero ordering violations**: All 100K+ events processed in strict causal order across all tests
4. **4x capture gap at high core counts**: At 192 cores, sequencer captures 4.3x more events

### 5.3 Why Perf Buffer Degrades at Scale

The perf buffer's per-CPU design causes progressively worse event loss:

- Each per-CPU ring buffer has fixed capacity (~64KB default)
- More cores = more concurrent event producers
- Userspace poll loop cannot drain N buffers fast enough
- Events are silently dropped—no error, no warning

The sequencer's shared 128MB ring buffer eliminates this bottleneck through wait-free writes and zero-copy mmap access.



---

## 6. Related Work

| Tool | Buffer Type | Ordering | Wait-Free | Scales to 100+ Cores |
|------|-------------|----------|-----------|----------------------|
| **Falco** | Ringbuf* | Global | ✗ (spinlock) | ✗ |
| **Tetragon** | Ringbuf* | Global | ✗ (spinlock) | ✗ |
| **Tracee** | Ringbuf* | Global | ✗ (spinlock) | ✗ |
| **BCC/bpftrace** | Perf/Ringbuf | Varies | ✓ | ✗ |
| **Linnix-Sequencer** | Custom | **Global** | **✓** | **✓** |

*Modern tools prefer `BPF_RINGBUF` (Linux 5.8+) for ordering, falling back to `BPF_PERF_EVENT_ARRAY` on older kernels.

The key difference: `BPF_RINGBUF` provides global ordering but uses a kernel spinlock that causes contention at high core counts. The Linnix-Sequencer replaces the spinlock with an atomic ticket counter, achieving the same ordering guarantees without lock contention.

---

## 7. Conclusion

The Linnix-Sequencer demonstrates that wait-free observability with strict global ordering is possible. By applying the LMAX Disruptor pattern to kernel space—replacing spinlocks with atomic ticket counters—we achieve:

- **100% event capture** at all core counts (vs 23-90% for perf buffers)
- **Zero ordering violations** across all tests from 8 to 192 cores
- **No degradation at scale**: Sequencer maintains full capture while perf buffer drops from 90% to 23%

### Future Work

- **NUMA-aware allocation**: Reduce cross-socket traffic for multi-socket systems
- **Batch ticket reservation**: Amortize atomic overhead for micro-batch publishing
- **Hardware timestamp integration**: Use CPU TSC for nanosecond-precision timestamps

---

## References

1. LMAX Disruptor: High Performance Alternative to Bounded Queues. Trisha Gee and Martin Thompson, 2011.
2. BPF and XDP Reference Guide. Linux Kernel Documentation.
3. BTF Type Format. https://www.kernel.org/doc/html/latest/bpf/btf.html
4. Falco: Cloud-Native Runtime Security. https://falco.org/
5. Tetragon: eBPF-based Security Observability. https://github.com/cilium/tetragon

---

*Linnix is open source software available at https://github.com/linnix-os/linnix*
