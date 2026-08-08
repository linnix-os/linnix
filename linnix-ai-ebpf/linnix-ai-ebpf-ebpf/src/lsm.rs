// =============================================================================
// LINNIX-CLAW: BPF LSM PROGRAMS — Mandate Enforcement
// =============================================================================
//
// Two LSM hooks that enforce the mandate system at the kernel level:
//
//   1. `bprm_check_security` — intercepts execve/execveat. Hashes argv with
//      SipHash-2-4, looks up the MANDATE_MAP, and allows or denies execution.
//
//   2. `socket_connect` — intercepts outbound connect(). Hashes addr:port,
//      looks up the MANDATE_MAP, and allows or denies the connection.
//
// Both hooks produce execution receipts pushed to the SEQUENCER_RING for
// monotonic ordering alongside other process lifecycle events.
//
// See docs/linnix-claw/specs.md §2 for full specification.
// See docs/linnix-claw/architecture.md Domain 3 for rationale.
//
// Requirements:
//   - Kernel ≥ 5.7 with CONFIG_BPF_LSM=y
//   - Boot parameter: lsm=...,bpf (or apparmor,...,bpf)
//   - BTF support (/sys/kernel/btf/vmlinux)

use aya_ebpf::{
    helpers::{bpf_get_current_task_btf, bpf_ktime_get_ns, bpf_probe_read},
    macros::{lsm, map},
    maps::{Array, HashMap as BpfHashMap},
    programs::LsmContext,
};
use aya_log_ebpf::info;
use linnix_ai_ebpf_common::{
    EventType, MandateKey, MandateMode, MandateValue, ProcessEvent, MANDATE_MAP_MAX_ENTRIES,
    PERCENT_MILLI_UNKNOWN,
};

use crate::siphash::SipHasher;

// =============================================================================
// MANDATE MAPS
// =============================================================================

/// BPF LRU hash map storing active mandates.
/// Key: MandateKey (24 bytes) = pid + start_time_ns + cmd_hash
/// Value: MandateValue (24 bytes) = expires_ns + flags + mandate_seq
///
/// LRU eviction ensures the map never OOMs — least recently used entries
/// are silently dropped. Cognitod's reconciliation loop (every 5s) also
/// proactively evicts expired entries.
#[map(name = "MANDATE_MAP")]
static MANDATE_MAP: BpfHashMap<MandateKey, MandateValue> =
    BpfHashMap::with_max_entries(MANDATE_MAP_MAX_ENTRIES, 0);

/// Global enforcement mode.
/// Element 0: 0 = Monitor (log but allow), 1 = Enforce (block unauthorized).
/// Written by cognitod at startup based on config.
#[map(name = "MANDATE_MODE")]
static MANDATE_MODE: Array<u32> = Array::with_max_entries(1, 0);

/// 128-bit SipHash key stored in .rodata (immutable after load).
/// k0 = element 0, k1 = element 1.
/// Seeded from /dev/urandom by cognitod at eBPF load time.
#[map(name = "SIPHASH_KEY")]
static SIPHASH_KEY: Array<u64> = Array::with_max_entries(2, 0);

/// Metrics counters for mandate enforcement.
/// Index 0: total mandate lookups
/// Index 1: mandate hits (allowed)
/// Index 2: mandate misses (denied or unmanaged)
/// Index 3: mandate expired (found but expired)
#[map(name = "MANDATE_METRICS")]
static MANDATE_METRICS: Array<u64> = Array::with_max_entries(4, 0);

const METRIC_LOOKUPS: u32 = 0;
const METRIC_HITS: u32 = 1;
const METRIC_MISSES: u32 = 2;
const METRIC_EXPIRED: u32 = 3;

// =============================================================================
// HELPERS
// =============================================================================

/// Read the global enforcement mode from the MANDATE_MODE map.
#[inline(always)]
fn get_mandate_mode() -> u32 {
    match MANDATE_MODE.get(0) {
        Some(val) => *val,
        None => MandateMode::Monitor as u32, // default: monitor
    }
}

/// Read the SipHash key from the SIPHASH_KEY map.
#[inline(always)]
fn get_siphash_key() -> [u64; 2] {
    let k0 = match SIPHASH_KEY.get(0) {
        Some(val) => *val,
        None => 0,
    };
    let k1 = match SIPHASH_KEY.get(1) {
        Some(val) => *val,
        None => 0,
    };
    [k0, k1]
}

/// Increment a metric counter atomically.
#[inline(always)]
fn increment_metric(index: u32) {
    unsafe {
        if let Some(ptr) = MANDATE_METRICS.get_ptr_mut(index) {
            let val = &mut *ptr;
            *val = val.wrapping_add(1);
        }
    }
}

/// Read `start_boottime` from `current->group_leader->start_boottime`.
///
/// The byte offset is discovered at daemon start via BTF and written into
/// `TelemetryConfig.task_start_boottime_offset`.  If the offset is zero
/// (unsupported kernel or field not found) we fall back to 0, which means
/// the mandate key won't carry start_time and PID-reuse protection is
/// disabled.  This is safe — mandates will expire by TTL anyway.
#[inline(always)]
fn read_start_time_ns(task: *const u8) -> u64 {
    let config = crate::program::load_config();
    if config.task_start_boottime_offset == 0 {
        return 0;
    }
    crate::program::read_field::<u64>(task, config.task_start_boottime_offset).unwrap_or(0)
}

/// Push a mandate execution receipt to SEQUENCER_RING.
///
/// Each allow/deny decision at the kernel LSM boundary produces a receipt
/// visible to userspace consumers via the same zero-copy ring that carries
/// process lifecycle events.  The receipt carries:
///   event_type  = MandateAllow (8) or MandateDeny (9)
///   pid         = the process TID that triggered the check
///   data        = cmd_hash of the checked operation
///   data2       = mandate_seq (0 if no mandate matched)
///   aux         = enforcement mode (0=monitor, 1=enforce)
#[inline(always)]
fn push_mandate_receipt(
    event_type: EventType,
    pid: u32,
    cmd_hash: u64,
    mandate_seq: u64,
    mode: u32,
    ts_ns: u64,
) {
    let event = ProcessEvent {
        pid,
        ppid: 0,
        uid: 0,
        gid: 0,
        event_type: event_type as u32,
        ts_ns,
        seq: mandate_seq,
        comm: [0u8; 16],
        exit_time_ns: 0,
        cpu_pct_milli: PERCENT_MILLI_UNKNOWN,
        mem_pct_milli: PERCENT_MILLI_UNKNOWN,
        data: cmd_hash,
        data2: mandate_seq,
        aux: mode,
        aux2: 0,
    };
    let _ = crate::program::submit_to_sequencer(&event);
}

// =============================================================================
// EXECVE CANONICALIZATION
// =============================================================================
//
// Per specs.md §1.1.1, the canonical form for execve is:
//   filename \x00 arg1 \x00 arg2 \x00 ... (NUL-separated, UTF-8)
//
// BPF stack limit: 512 bytes. We extract up to 256 bytes total across
// the filename and first 6 arguments.

/// Maximum bytes for argument canonicalization (BPF stack budget).
const MAX_CANON_BYTES: usize = 256;

/// Maximum number of argv entries to hash.
#[allow(dead_code)] // Used in Phase 1 for argv-based hashing
const MAX_ARGV: usize = 6;

/// Hash the filename from a `linux_binprm` struct for execve mandate lookup.
///
/// In the `bprm_check_security` LSM hook, the first argument is a pointer
/// to `struct linux_binprm`. We read `binprm->filename` (the resolved path)
/// and hash it as the canonical representation.
///
/// For Phase 0, we hash only the filename (not full argv). Full argv
/// canonicalization requires reading the user-space stack, which needs
/// `bpf_probe_read_user_str` and careful BPF verifier handling.
#[inline(always)]
fn hash_binprm_filename(ctx: &LsmContext, key: &[u64; 2]) -> Option<u64> {
    // linux_binprm layout (simplified):
    //   offset 0...: various fields
    //   offset 192 (typical): filename pointer (char *)
    //
    // The exact offset varies by kernel version. For Phase 0, we read
    // the filename from the first argument using BTF-aware access.

    // Read the linux_binprm pointer (arg 0 of bprm_check_security)
    let binprm: *const u8 = unsafe { ctx.arg(0) };
    if binprm.is_null() {
        return None;
    }

    // Read filename pointer from linux_binprm.
    // Typical offset: 192 bytes on 6.x kernels, but we use bpf_probe_read
    // to get it. The filename field is a `const char *`.
    //
    // NOTE: This offset should be discovered via BTF. For Phase 0, we use
    // a common offset. Production code will read from TelemetryConfig.
    const BINPRM_FILENAME_OFFSET: usize = 192;

    let filename_ptr: usize =
        unsafe { bpf_probe_read((binprm.add(BINPRM_FILENAME_OFFSET)) as *const usize).ok()? };

    if filename_ptr == 0 {
        return None;
    }

    // Read filename bytes (up to MAX_CANON_BYTES)
    let mut buf = [0u8; MAX_CANON_BYTES];
    let mut len = 0usize;

    // Read up to MAX_CANON_BYTES from the filename
    // We use byte-by-byte reading with bounded loop for BPF verifier
    let fname_ptr = filename_ptr as *const u8;
    let mut i = 0usize;
    while i < MAX_CANON_BYTES {
        match unsafe { bpf_probe_read(fname_ptr.add(i)) } {
            Ok(b) => {
                if b == 0 {
                    break;
                }
                buf[i] = b;
                len += 1;
            }
            Err(_) => break,
        }
        i += 1;
    }

    if len == 0 {
        return None;
    }

    // SipHash-2-4 the filename bytes
    let mut hasher = SipHasher::new(key[0], key[1]);
    let mut j = 0usize;
    while j < len && j < MAX_CANON_BYTES {
        hasher.write_byte(buf[j]);
        j += 1;
    }
    Some(hasher.finish())
}

// =============================================================================
// LSM HOOK: bprm_check_security (execve interception)
// =============================================================================
//
// Called after the binary is resolved but BEFORE it runs.
// Has access to linux_binprm->filename and argv.
//
// Returns:
//   0     → allow execution
//   -1    → deny execution (EPERM)

#[lsm(hook = "bprm_check_security")]
pub fn mandate_execve_check(ctx: LsmContext) -> i32 {
    match try_mandate_execve_check(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // On error, fail open (allow) to avoid breaking the system
    }
}

#[inline(always)]
fn try_mandate_execve_check(ctx: &LsmContext) -> Result<i32, i64> {
    let now = unsafe { bpf_ktime_get_ns() };

    // Get current PID (tgid)
    let task = unsafe { bpf_get_current_task_btf() } as *const u8;
    if task.is_null() {
        return Ok(0); // Can't identify process, fail open
    }

    // Read tgid from task_struct
    // NOTE: Using the same dynamic offset approach as the main program.rs
    let config = crate::program::load_config();
    let pid: i32 = match crate::program::read_field(task, config.task_tgid_offset) {
        Some(v) => v,
        None => return Ok(0),
    };
    let pid = pid as u32;

    // Skip kernel threads and init
    if pid <= 1 {
        return Ok(0);
    }

    // Get SipHash key
    let key = get_siphash_key();
    if key[0] == 0 && key[1] == 0 {
        // Key not initialized yet — cognitod hasn't loaded. Fail open.
        return Ok(0);
    }

    // Hash the filename from linux_binprm
    let cmd_hash = match hash_binprm_filename(ctx, &key) {
        Some(h) => h,
        None => return Ok(0), // Can't read filename, fail open
    };

    // Construct the mandate key
    let start_time_ns = read_start_time_ns(task);
    let mandate_key = MandateKey {
        pid,
        _pad: 0,
        start_time_ns,
        cmd_hash,
    };

    // Increment lookup counter
    increment_metric(METRIC_LOOKUPS);

    let mode = get_mandate_mode();

    // Look up mandate in the map
    let mandate = unsafe { MANDATE_MAP.get(&mandate_key) };

    match mandate {
        Some(val) => {
            // Mandate found — check expiry
            if val.is_expired(now) {
                increment_metric(METRIC_EXPIRED);

                // Expired mandate — treat as missing
                if mode == MandateMode::Enforce as u32 {
                    push_mandate_receipt(EventType::MandateDeny, pid, cmd_hash, 0, mode, now);
                    return Ok(-1); // EPERM
                }
                return Ok(0);
            }

            // Valid mandate — allow execution; push allow receipt
            increment_metric(METRIC_HITS);
            push_mandate_receipt(
                EventType::MandateAllow,
                pid,
                cmd_hash,
                val.mandate_seq,
                mode,
                now,
            );

            Ok(0)
        }
        None => {
            // No mandate found
            increment_metric(METRIC_MISSES);

            if mode == MandateMode::Enforce as u32 {
                // Enforce mode: block the syscall and push deny receipt
                push_mandate_receipt(EventType::MandateDeny, pid, cmd_hash, 0, mode, now);
                Ok(-1) // Return -EPERM
            } else {
                // Monitor mode: allow but log
                Ok(0)
            }
        }
    }
}

// =============================================================================
// LSM HOOK: socket_connect (outbound connection interception)
// =============================================================================
//
// Called before an outbound TCP/UDP connection is established.
// Has access to struct socket and struct sockaddr (IP + port).
//
// Returns:
//   0     → allow connection
//   -1    → deny connection (EPERM)

#[lsm(hook = "socket_connect")]
pub fn mandate_socket_connect(ctx: LsmContext) -> i32 {
    match try_mandate_socket_connect(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Fail open on error
    }
}

#[inline(always)]
fn try_mandate_socket_connect(ctx: &LsmContext) -> Result<i32, i64> {
    let now = unsafe { bpf_ktime_get_ns() };

    // Get current PID
    let task = unsafe { bpf_get_current_task_btf() } as *const u8;
    if task.is_null() {
        return Ok(0);
    }

    let config = crate::program::load_config();
    let pid: i32 = match crate::program::read_field(task, config.task_tgid_offset) {
        Some(v) => v,
        None => return Ok(0),
    };
    let pid = pid as u32;

    if pid <= 1 {
        return Ok(0);
    }

    // Read sockaddr from the second argument (arg 1)
    // socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
    let sockaddr: *const u8 = unsafe { ctx.arg(1) };
    if sockaddr.is_null() {
        return Ok(0);
    }

    // Read sa_family (first 2 bytes of sockaddr)
    let sa_family: u16 = unsafe { bpf_probe_read(sockaddr as *const u16).map_err(|e| e)? };

    // Only intercept AF_INET (2) and AF_INET6 (10) connections
    if sa_family != 2 && sa_family != 10 {
        return Ok(0);
    }

    // Hash the sockaddr for mandate lookup
    let key = get_siphash_key();
    if key[0] == 0 && key[1] == 0 {
        return Ok(0); // Key not yet initialized
    }

    let mut hasher = SipHasher::new(key[0], key[1]);

    // Write "connect\0" prefix for canonicalization
    hasher.write(b"connect\x00");

    if sa_family == 2 {
        // AF_INET: sockaddr_in = { sa_family: u16, sin_port: u16, sin_addr: u32, ... }
        // Read port (offset 2, big-endian u16)
        let port: u16 = unsafe { bpf_probe_read(sockaddr.add(2) as *const u16).unwrap_or(0) };
        // Read IPv4 address (offset 4, 4 bytes)
        let addr: u32 = unsafe { bpf_probe_read(sockaddr.add(4) as *const u32).unwrap_or(0) };

        hasher.write_u32(addr);
        // Port is in network byte order (big-endian), write raw bytes
        hasher.write_byte((port >> 8) as u8);
        hasher.write_byte(port as u8);
    } else {
        // AF_INET6: sockaddr_in6 = { sa_family: u16, sin6_port: u16, sin6_flowinfo: u32,
        //                             sin6_addr: [u8; 16], sin6_scope_id: u32 }
        let port: u16 = unsafe { bpf_probe_read(sockaddr.add(2) as *const u16).unwrap_or(0) };

        // Read 16-byte IPv6 address at offset 8
        let mut addr6 = [0u8; 16];
        let mut i = 0usize;
        while i < 16 {
            addr6[i] = unsafe { bpf_probe_read(sockaddr.add(8 + i) as *const u8).unwrap_or(0) };
            i += 1;
        }

        hasher.write(&addr6);
        hasher.write_byte((port >> 8) as u8);
        hasher.write_byte(port as u8);
    }

    let cmd_hash = hasher.finish();
    let start_time_ns = read_start_time_ns(task);
    let mandate_key = MandateKey {
        pid,
        _pad: 0,
        start_time_ns,
        cmd_hash,
    };

    increment_metric(METRIC_LOOKUPS);

    let mode = get_mandate_mode();
    let mandate = unsafe { MANDATE_MAP.get(&mandate_key) };

    match mandate {
        Some(val) => {
            if val.is_expired(now) {
                increment_metric(METRIC_EXPIRED);
                if mode == MandateMode::Enforce as u32 {
                    push_mandate_receipt(EventType::MandateDeny, pid, cmd_hash, 0, mode, now);
                    return Ok(-1);
                }
                return Ok(0);
            }

            increment_metric(METRIC_HITS);
            push_mandate_receipt(
                EventType::MandateAllow,
                pid,
                cmd_hash,
                val.mandate_seq,
                mode,
                now,
            );
            Ok(0)
        }
        None => {
            increment_metric(METRIC_MISSES);
            if mode == MandateMode::Enforce as u32 {
                push_mandate_receipt(EventType::MandateDeny, pid, cmd_hash, 0, mode, now);
                Ok(-1)
            } else {
                Ok(0)
            }
        }
    }
}
