//! Sequenced MPSC Ring Buffer - Userspace Consumer
//!
//! This module implements the consumer side of a lock-free, strictly-ordered
//! ring buffer that receives events from eBPF producers.
//!
//! # Architecture
//!
//! The ring buffer uses a ticket-based protocol:
//! - Kernel producers atomically reserve tickets (sequence numbers)
//! - Each ticket maps to a slot in the ring buffer
//! - The consumer reads slots in strict ticket order
//!
//! # Safety Mechanisms
//!
//! 1. **Strict Ordering**: Events are processed in ticket order (1, 2, 3, ...)
//! 2. **Reaper Timeout**: Stalled producers (WRITING state too long) are skipped
//! 3. **Validator**: Runtime assertion that ordering is never violated
//!
//! # Implementation Modes
//!
//! - **Mmap Mode** (default): Zero-copy access via memory-mapped BPF array.
//!   Requires BPF_F_MMAPABLE flag on the map. Maximum performance.
//! - **Syscall Mode** (fallback): Uses bpf() syscalls for reading.
//!   Works with any BPF array but has context switch overhead.
//!
//! # Performance Optimizations
//!
//! - **Huge Pages**: We request transparent huge pages via madvise(MADV_HUGEPAGE)
//!   to reduce TLB misses when scanning the 128MB ring buffer.
//! - **Read-Only Consumer**: We never write EMPTY flags back to the ring buffer,
//!   avoiding cache ping-pong with kernel producers.

#![allow(dead_code)] // Suppress unused warnings for WIP sequencer
use std::io;
use std::os::fd::{BorrowedFd, RawFd};

use linnix_ai_ebpf_common::{
    ProcessEvent, REAPER_TIMEOUT_NS, SEQUENCER_RING_MASK, SEQUENCER_RING_SIZE, SequencedSlot,
    slot_flags,
};
use log::{debug, error, info, warn};
use memmap2::MmapMut;

// =============================================================================
// HUGE PAGES OPTIMIZATION
// =============================================================================
//
// The 128MB ring buffer spans ~32,000 pages at 4KB page size. Each TLB miss
// on a slot access causes a page table walk (~100ns). With huge pages (2MB),
// we only need ~64 TLB entries, reducing cache pressure significantly.
//
// We use madvise(MADV_HUGEPAGE) to request transparent huge pages. This is
// a hint - the kernel may or may not use huge pages depending on availability.

/// MADV_HUGEPAGE constant (14 on Linux)
const MADV_HUGEPAGE: libc::c_int = 14;

/// Request transparent huge pages for the ring buffer.
/// This is a best-effort hint - the kernel may ignore it.
fn advise_hugepages(ptr: *mut SequencedSlot, len: usize) {
    let ret = unsafe { libc::madvise(ptr as *mut libc::c_void, len, MADV_HUGEPAGE) };

    if ret == 0 {
        info!(
            "MADV_HUGEPAGE succeeded for ring buffer ({} MB) - TLB optimization active",
            len / (1024 * 1024)
        );
    } else {
        let err = std::io::Error::last_os_error();
        warn!(
            "MADV_HUGEPAGE failed ({}): {} - continuing without huge pages. \
             Consider enabling transparent huge pages: \
             echo 'always' | sudo tee /sys/kernel/mm/transparent_hugepage/enabled",
            err.raw_os_error().unwrap_or(-1),
            err
        );
    }
}

/// Statistics for the sequencer consumer
#[derive(Debug, Default, Clone)]
pub struct SequencerStats {
    /// Total events successfully processed
    pub events_processed: u64,
    /// Events skipped due to reaper timeout
    pub events_reaped: u64,
    /// Events found in abandoned state
    pub events_abandoned: u64,
    /// Total poll cycles
    pub poll_cycles: u64,
    /// Maximum batch size seen
    pub max_batch_size: usize,
    /// Number of ordering violations detected (should always be 0)
    pub ordering_violations: u64,
}

/// Validates strict ordering of incoming events
#[derive(Debug, Default)]
pub struct OrderingValidator {
    last_ticket: Option<u64>,
    violations: u64,
}

impl OrderingValidator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check that the given ticket maintains strict ordering.
    /// Returns true if ordering is correct, false if violated.
    pub fn check(&mut self, ticket: u64) -> bool {
        if let Some(last) = self.last_ticket
            && ticket != last + 1
        {
            error!(
                "ORDERING VIOLATION: Expected ticket {}, got {}. Gap of {} events.",
                last + 1,
                ticket,
                ticket.saturating_sub(last + 1)
            );
            self.violations += 1;
            self.last_ticket = Some(ticket);
            return false;
        }
        self.last_ticket = Some(ticket);
        true
    }

    pub fn violations(&self) -> u64 {
        self.violations
    }

    pub fn last_ticket(&self) -> Option<u64> {
        self.last_ticket
    }
}

/// Consumer for the sequenced MPSC ring buffer.
///
/// Uses memory-mapped access for zero-copy reads from the BPF Array.
/// The map must be created with BPF_F_MMAPABLE flag (0x400).
pub struct SequencerConsumer {
    /// Memory-mapped ring buffer (keeps the mapping alive)
    _mmap: MmapMut,
    /// Raw pointer to the ring buffer for volatile reads
    ring_ptr: *mut SequencedSlot,
    /// Local cursor (our position in the stream)
    cursor: u64,
    /// Mask for wrapping (RING_SIZE - 1)
    mask: u64,
    /// Ordering validator
    validator: OrderingValidator,
    /// Statistics
    stats: SequencerStats,
    /// Reaper timeout in nanoseconds
    reaper_timeout_ns: u64,
}

// SAFETY: The mmap is process-local and we only have one consumer thread.
// The ring_ptr is derived from the mmap and stays valid as long as _mmap is alive.
unsafe impl Send for SequencerConsumer {}

impl SequencerConsumer {
    /// Create a new consumer from a BPF map file descriptor.
    ///
    /// The map MUST have been created with BPF_F_MMAPABLE flag.
    /// This constructor will mmap the entire ring buffer for zero-copy access.
    pub fn from_fd(fd: BorrowedFd<'_>) -> io::Result<Self> {
        let ring_size_bytes = (SEQUENCER_RING_SIZE as usize) * std::mem::size_of::<SequencedSlot>();

        info!(
            "Initializing sequencer consumer (mmap mode): {} slots, {} bytes ({} MB)",
            SEQUENCER_RING_SIZE,
            ring_size_bytes,
            ring_size_bytes / (1024 * 1024)
        );

        // CRITICAL: mmap the BPF array for zero-copy access
        // This requires the map to have BPF_F_MMAPABLE flag set (0x400)
        let mmap = unsafe {
            memmap2::MmapOptions::new()
                .len(ring_size_bytes)
                .map_mut(&fd)
                .map_err(|e| {
                    error!(
                        "Failed to mmap SEQUENCER_RING: {}. \
                         Ensure the map was created with BPF_F_MMAPABLE flag (0x400).",
                        e
                    );
                    e
                })?
        };

        let ring_ptr = mmap.as_ptr() as *mut SequencedSlot;

        // Request transparent huge pages to reduce TLB misses.
        // The 128MB ring buffer benefits significantly from 2MB pages
        // instead of 4KB pages (64x fewer TLB entries needed).
        advise_hugepages(ring_ptr, ring_size_bytes);

        info!(
            "Sequencer mmap SUCCESS! Base address: {:p}, size: {} MB (huge pages advised)",
            ring_ptr,
            ring_size_bytes / (1024 * 1024)
        );

        let mut consumer = Self {
            _mmap: mmap,
            ring_ptr,
            cursor: 0, // Will be set by caller if needed
            mask: SEQUENCER_RING_MASK as u64,
            validator: OrderingValidator::new(),
            stats: SequencerStats::default(),
            reaper_timeout_ns: REAPER_TIMEOUT_NS,
        };

        // Zero the ring buffer to clear any uninitialized memory.
        // This is safe because:
        // 1. For new maps: memory may be uninitialized
        // 2. For reused maps: caller should reset SEQUENCER_INDEX first
        // The memset is fast (~50ms for 256MB)
        consumer.zero_ring_buffer();

        Ok(consumer)
    }

    /// Fast zero of entire ring buffer using memset.
    /// Called once at startup to ensure no garbage data.
    fn zero_ring_buffer(&mut self) {
        let len = (SEQUENCER_RING_SIZE as usize) * std::mem::size_of::<SequencedSlot>();
        info!("Zeroing ring buffer ({} MB)...", len / (1024 * 1024));
        let start = std::time::Instant::now();
        unsafe {
            let ptr = self.ring_ptr as *mut u8;
            core::ptr::write_bytes(ptr, 0, len);
        }
        info!("Ring buffer zeroed in {:?}", start.elapsed());
    }

    /// Set the consumer cursor position.
    /// Use this to sync with the current producer position (SEQUENCER_INDEX).
    pub fn set_cursor(&mut self, cursor: u64) {
        info!("Setting consumer cursor to {}", cursor);
        self.cursor = cursor;
    }

    /// Create consumer from raw fd (for backwards compatibility)
    pub fn from_raw_fd(raw_fd: RawFd) -> io::Result<Self> {
        // SAFETY: We're borrowing the fd for the duration of this call.
        // The caller must ensure the fd remains valid.
        let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
        Self::from_fd(fd)
    }

    /// Set the reaper timeout (default is 10ms)
    pub fn set_reaper_timeout_ms(&mut self, timeout_ms: u64) {
        self.reaper_timeout_ns = timeout_ms * 1_000_000;
    }

    /// Get current statistics
    pub fn stats(&self) -> &SequencerStats {
        &self.stats
    }

    /// Get current cursor position
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Get the current boot time in nanoseconds (for reaper timeout checks)
    fn get_boot_time_ns() -> u64 {
        use nix::time::{ClockId, clock_gettime};
        match clock_gettime(ClockId::CLOCK_BOOTTIME) {
            Ok(ts) => (ts.tv_sec() as u64) * 1_000_000_000 + (ts.tv_nsec() as u64),
            Err(_) => 0,
        }
    }

    /// ZERO-COPY slot read - just a pointer dereference!
    /// This is the hot path. No syscalls, no copies.
    #[inline(always)]
    fn get_slot(&self, index: u64) -> &SequencedSlot {
        unsafe {
            let offset = (index & self.mask) as usize;
            &*self.ring_ptr.add(offset)
        }
    }

    /// Get mutable reference to a slot (for resetting)
    #[inline(always)]
    fn get_slot_mut(&mut self, index: u64) -> *mut SequencedSlot {
        unsafe {
            let offset = (index & self.mask) as usize;
            self.ring_ptr.add(offset)
        }
    }

    /// Mark a slot as empty (for reuse by producers)
    #[inline(always)]
    fn mark_slot_empty(&mut self, index: u64) {
        let slot = self.get_slot_mut(index);
        unsafe {
            core::ptr::write_volatile(&mut (*slot).flags, slot_flags::EMPTY);
        }
    }

    /// Mark a slot as abandoned (reaper action)
    #[inline(always)]
    fn mark_slot_abandoned(&mut self, index: u64) {
        let slot = self.get_slot_mut(index);
        unsafe {
            core::ptr::write_volatile(&mut (*slot).flags, slot_flags::ABANDONED);
        }
    }

    /// Poll for a batch of events.
    ///
    /// OPTIMIZED READ-ONLY CONSUMER:
    /// - We NEVER write to the ring buffer (no cache ping-pong!)
    /// - We use ticket_id to distinguish new vs old data
    /// - This keeps cache lines in Shared state, eliminating coherency traffic
    pub fn poll_batch(&mut self, max_batch_size: usize) -> Vec<ProcessEvent> {
        let mut events = Vec::with_capacity(max_batch_size);
        let now_ns = Self::get_boot_time_ns();
        self.stats.poll_cycles += 1;

        for _ in 0..max_batch_size {
            // ZERO-COPY READ: Just a pointer dereference, no syscalls!
            let slot_ptr = unsafe {
                let offset = (self.cursor & self.mask) as usize;
                self.ring_ptr.add(offset)
            };

            // Read flag with volatile to ensure we see kernel updates
            let flags = unsafe { core::ptr::read_volatile(&(*slot_ptr).flags) };

            // NOTE: On x86, volatile reads have implicit acquire semantics.
            // We skip the explicit fence for performance.

            match flags {
                x if x == slot_flags::READY => {
                    // Read ticket FIRST to check if this is new data or old
                    let ticket = unsafe { core::ptr::read_volatile(&(*slot_ptr).ticket_id) };

                    if ticket == self.cursor {
                        // MATCH! This is the event we're waiting for.
                        let event = unsafe { core::ptr::read_volatile(&(*slot_ptr).event) };

                        // Validate ordering (should always pass since ticket == cursor)
                        if !self.validator.check(ticket) {
                            self.stats.ordering_violations += 1;
                        }

                        events.push(event);

                        // PERFORMANCE OPTIMIZATION:
                        // We DO NOT write EMPTY back to the slot!
                        // This eliminates cache ping-pong between producer/consumer cores.
                        // The ticket_id check prevents re-reading old data.

                        self.cursor += 1;
                        self.stats.events_processed += 1;
                    } else if ticket < self.cursor {
                        // OLD DATA: Producer hasn't wrapped around to this slot yet.
                        // The slot still holds data from a previous lap.
                        // Treat as "not ready" and wait.
                        break;
                    } else {
                        // ticket > cursor: We somehow missed events (shouldn't happen)
                        error!(
                            "Gap detected! Cursor: {}, Slot Ticket: {}. Resyncing.",
                            self.cursor, ticket
                        );
                        self.stats.ordering_violations += 1;
                        self.cursor = ticket; // Resync to current position
                    }
                }

                x if x == slot_flags::WRITING => {
                    // Producer has reserved but not yet committed.
                    // Check ticket to confirm this is the CURRENT write, not old data
                    let ticket = unsafe { core::ptr::read_volatile(&(*slot_ptr).ticket_id) };

                    if ticket == self.cursor {
                        // This is the slot we're waiting for
                        let reserved_at =
                            unsafe { core::ptr::read_volatile(&(*slot_ptr).reserved_at_ns) };

                        // SANITY CHECK: reserved_at == 0 means initialization race
                        if reserved_at == 0 {
                            debug!(
                                "Slot {} has flags=WRITING but reserved_at=0, waiting...",
                                self.cursor
                            );
                            break;
                        }

                        if now_ns.saturating_sub(reserved_at) > self.reaper_timeout_ns {
                            // THE REAPER: Producer stalled or crashed.
                            warn!(
                                "REAPER: Slot {} (ticket {}) stuck in WRITING for {}ms. Skipping.",
                                self.cursor,
                                ticket,
                                (now_ns.saturating_sub(reserved_at)) / 1_000_000
                            );

                            // READ-ONLY: We don't write ABANDONED, just advance cursor locally
                            // Since we're single-consumer, this is safe.
                            self.stats.events_reaped += 1;
                            self.cursor += 1;
                        } else {
                            // Producer still working, wait
                            break;
                        }
                    } else {
                        // Old data being overwritten, or ticket mismatch - wait
                        break;
                    }
                }

                x if x == slot_flags::EMPTY => {
                    // We've caught up to the producers. No new data.
                    break;
                }

                x if x == slot_flags::ABANDONED => {
                    // Previously reaped slot - but in read-only mode we shouldn't see this
                    // unless we wrote it ourselves in a previous reaper action
                    debug!("Skipping abandoned slot {}", self.cursor);
                    self.cursor += 1;
                    self.stats.events_abandoned += 1;
                }

                _ => {
                    // Unknown flag - could be uninitialized memory
                    // Check ticket to see if this is our slot
                    let ticket = unsafe { core::ptr::read_volatile(&(*slot_ptr).ticket_id) };
                    if ticket < self.cursor {
                        // Old data, wait for producer to wrap around
                        break;
                    } else {
                        error!(
                            "Unknown slot flag {} at cursor {} (ticket {}). Waiting.",
                            flags, self.cursor, ticket
                        );
                        break;
                    }
                }
            }
        }

        if events.len() > self.stats.max_batch_size {
            self.stats.max_batch_size = events.len();
        }

        events
    }

    /// Drain all available events (up to a reasonable limit).
    pub fn drain(&mut self) -> Vec<ProcessEvent> {
        const MAX_DRAIN: usize = 10_000;
        let mut all_events = Vec::new();

        loop {
            let batch = self.poll_batch(1000);
            if batch.is_empty() {
                break;
            }
            all_events.extend(batch);
            if all_events.len() >= MAX_DRAIN {
                warn!("Drain limit reached at {} events", all_events.len());
                break;
            }
        }

        all_events
    }
}

/// Enable the sequencer in the eBPF program.
pub fn enable_sequencer(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    use anyhow::Context;
    use aya::maps::Array;

    let mut enabled_map: Array<_, u32> = Array::try_from(
        ebpf.map_mut("SEQUENCER_ENABLED")
            .context("Failed to find SEQUENCER_ENABLED map")?,
    )
    .context("Failed to create Array from SEQUENCER_ENABLED map")?;

    enabled_map
        .set(0, 1, 0)
        .context("Failed to set SEQUENCER_ENABLED to 1")?;

    info!("Sequencer ENABLED - eBPF will now use the lock-free ring buffer");

    Ok(())
}

/// Disable the sequencer, reverting to legacy perf buffer.
pub fn disable_sequencer(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    use anyhow::Context;
    use aya::maps::Array;

    let mut enabled_map: Array<_, u32> = Array::try_from(
        ebpf.map_mut("SEQUENCER_ENABLED")
            .context("Failed to find SEQUENCER_ENABLED map")?,
    )
    .context("Failed to create Array from SEQUENCER_ENABLED map")?;

    enabled_map
        .set(0, 0, 0)
        .context("Failed to set SEQUENCER_ENABLED to 0")?;

    info!("Sequencer DISABLED - eBPF will use legacy perf buffer");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ordering_validator() {
        let mut validator = OrderingValidator::new();

        assert!(validator.check(0));
        assert!(validator.check(1));
        assert!(validator.check(2));

        // Gap should be detected
        assert!(!validator.check(5));
        assert_eq!(validator.violations(), 1);

        // Continue from new position
        assert!(validator.check(6));
        assert!(validator.check(7));
    }

    #[test]
    fn test_sequenced_slot_alignment() {
        use std::mem::{align_of, size_of};

        // SequencedSlot is 128 bytes with 128-byte alignment (2 cache lines)
        assert_eq!(size_of::<SequencedSlot>(), 128);
        assert_eq!(align_of::<SequencedSlot>(), 128);
    }

    #[test]
    fn test_stats_default() {
        let stats = SequencerStats::default();
        assert_eq!(stats.events_processed, 0);
        assert_eq!(stats.events_reaped, 0);
        assert_eq!(stats.ordering_violations, 0);
    }
}
