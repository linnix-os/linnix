// =============================================================================
// LINNIX-CLAW: MandateManager — Userspace BPF Map Controller
// =============================================================================
//
// Owns the lifecycle of mandates: create, lookup, revoke, expire.
// Writes MandateKey→MandateValue entries into the BPF LRU hash map.
// Runs a periodic reconciliation loop (every 5s) to evict expired entries.
//
// See docs/linnix-claw/specs.md §3 for API specification.
// See docs/linnix-claw/specs.md §1.3 for LRU eviction policy.

use anyhow::{Context, Result, anyhow};
use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, MapData};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex as TokioMutex, RwLock};

use crate::receipt::ExecutionReceipt;

use linnix_ai_ebpf_common::{
    MANDATE_MAP_MAX_ENTRIES, MANDATE_MAP_WATERMARK, MANDATE_RECONCILE_INTERVAL_SECS, MandateKey,
    MandateMode, MandateValue,
};

// =============================================================================
// AYA POD WRAPPERS
// =============================================================================
//
// aya::maps::HashMap requires key/value types to implement aya::Pod.
// MandateKey and MandateValue are defined in linnix_ai_ebpf_common (a foreign
// crate), so we cannot implement aya::Pod for them directly (orphan rule).
// These transparent wrappers have identical memory layout and satisfy aya.

#[repr(transparent)]
#[derive(Copy, Clone)]
pub(crate) struct BpfMandateKey(MandateKey);

#[repr(transparent)]
#[derive(Copy, Clone)]
pub(crate) struct BpfMandateValue(MandateValue);

// SAFETY: both MandateKey and MandateValue are #[repr(C)] POD structs with
// no padding holes, and are safe to copy byte-for-byte to/from kernel memory.
unsafe impl aya::Pod for BpfMandateKey {}
unsafe impl aya::Pod for BpfMandateValue {}

/// BPF map handles passed from init_ebpf() to connect_bpf_maps().
///
/// Construct via [`build_bpf_mandate_maps`] — the inner types are
/// transparent-wrapper internals and not part of the public API.
pub struct BpfMandateMaps {
    mandate_map: AyaHashMap<MapData, BpfMandateKey, BpfMandateValue>,
    mode_map: AyaArray<MapData, u32>,
    siphash_map: AyaArray<MapData, u64>,
}

/// Build a [`BpfMandateMaps`] from three raw aya `Map` objects taken from the
/// loaded BPF object.
///
/// Intended to be called in `main.rs` right after `init_ebpf()`:
/// ```ignore
/// let mandate_maps = build_bpf_mandate_maps(
///     bpf.take_map("MANDATE_MAP").ok_or(...)?,
///     bpf.take_map("MANDATE_MODE").ok_or(...)?,
///     bpf.take_map("SIPHASH_KEY").ok_or(...)?,
/// )?;
/// ```
pub fn build_bpf_mandate_maps(
    mandate_map_raw: aya::maps::Map,
    mode_map_raw: aya::maps::Map,
    siphash_map_raw: aya::maps::Map,
) -> anyhow::Result<BpfMandateMaps> {
    use anyhow::Context as _;
    Ok(BpfMandateMaps {
        mandate_map: AyaHashMap::try_from(mandate_map_raw).context("MANDATE_MAP type mismatch")?,
        mode_map: AyaArray::try_from(mode_map_raw).context("MANDATE_MODE type mismatch")?,
        siphash_map: AyaArray::try_from(siphash_map_raw).context("SIPHASH_KEY type mismatch")?,
    })
}

// =============================================================================
// SipHash-2-4 (userspace implementation)
// =============================================================================
//
// Mirrors the eBPF-side siphash.rs implementation exactly.
// Both MUST produce identical output for the same inputs and key.

#[inline]
fn rotl(x: u64, b: u32) -> u64 {
    x.rotate_left(b)
}

#[inline]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = rotl(*v1, 13);
    *v1 ^= *v0;
    *v0 = rotl(*v0, 32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = rotl(*v3, 16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = rotl(*v3, 21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = rotl(*v1, 17);
    *v1 ^= *v2;
    *v2 = rotl(*v2, 32);
}

pub struct SipHasher {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    buf: u64,
    count: usize,
}

impl SipHasher {
    pub fn new(k0: u64, k1: u64) -> Self {
        Self {
            v0: k0 ^ 0x736f6d6570736575,
            v1: k1 ^ 0x646f72616e646f6d,
            v2: k0 ^ 0x6c7967656e657261,
            v3: k1 ^ 0x7465646279746573,
            buf: 0,
            count: 0,
        }
    }

    pub fn write_byte(&mut self, byte: u8) {
        let shift = (self.count % 8) * 8;
        self.buf |= (byte as u64) << shift;
        self.count += 1;

        if self.count.is_multiple_of(8) {
            self.compress();
        }
    }

    pub fn write(&mut self, data: &[u8]) {
        for &b in data {
            self.write_byte(b);
        }
    }

    fn compress(&mut self) {
        self.v3 ^= self.buf;
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        self.v0 ^= self.buf;
        self.buf = 0;
    }

    pub fn finish(mut self) -> u64 {
        let b = (self.count as u64) << 56;
        self.buf |= b;

        self.v3 ^= self.buf;
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        self.v0 ^= self.buf;

        self.v2 ^= 0xff;
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);

        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }
}

/// Compute SipHash-2-4 of data with the given 128-bit key.
pub fn siphash_2_4(key: [u64; 2], data: &[u8]) -> u64 {
    let mut hasher = SipHasher::new(key[0], key[1]);
    hasher.write(data);
    hasher.finish()
}

// =============================================================================
// MANDATE TYPES
// =============================================================================

/// Unique mandate identifier (UUID-based for API consumers).
pub type MandateId = String;

/// Request to create a new mandate.
#[derive(Debug, Clone, Deserialize)]
pub struct MandateRequest {
    /// Target process ID.
    pub pid: u32,
    /// The command arguments to authorize (will be canonicalized and hashed).
    pub args: Vec<String>,
    /// Time-to-live in milliseconds (mandate expires after this duration).
    pub ttl_ms: u64,
    /// Optional container ID for PID namespace translation.
    #[serde(default)]
    pub container_id: Option<String>,
    /// If true, mandate is in monitor-only mode (allow but tag receipts).
    #[serde(default)]
    pub monitor_only: bool,
    /// Correlation ID for settlement. Not sent to kernel.
    #[serde(default)]
    pub task_id: Option<String>,
    /// Spend cap for this mandate in USD cents (§8.5). Tracked by cognitod.
    #[serde(default)]
    pub max_spend_cents: Option<u64>,
    /// Counterparty DID for compliance screening (§10.3).
    #[serde(default)]
    pub counterparty_did: Option<String>,
    /// Wallet address for KYT screening (§10.3).
    #[serde(default)]
    pub wallet_address: Option<String>,
    /// Jurisdiction code for sanctions screening (§10.3).
    #[serde(default)]
    pub jurisdiction: Option<String>,
}

impl MandateRequest {
    /// Whether this mandate has settlement-related fields (commerce request).
    /// Commerce requests are subject to the §11.1 commerce policy.
    pub fn is_commerce_request(&self) -> bool {
        self.task_id.is_some() || self.max_spend_cents.is_some()
    }
}

/// Batch mandate creation request.
#[derive(Debug, Clone, Deserialize)]
pub struct BatchMandateRequest {
    /// Up to 64 mandates to create atomically.
    pub mandates: Vec<MandateRequest>,
}

/// Result for a single mandate in a batch operation.
#[derive(Debug, Clone, Serialize)]
pub struct BatchMandateResult {
    /// Index of this item in the request array.
    pub index: usize,
    /// The mandate response if creation succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandate: Option<MandateResponse>,
    /// Error message if creation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Response for a batch mandate creation.
#[derive(Debug, Clone, Serialize)]
pub struct BatchMandateResponse {
    /// Total mandates requested.
    pub total: usize,
    /// Number that succeeded.
    pub succeeded: usize,
    /// Number that failed.
    pub failed: usize,
    /// Individual results.
    pub results: Vec<BatchMandateResult>,
}

/// Response after creating a mandate.
#[derive(Debug, Clone, Serialize)]
pub struct MandateResponse {
    /// Unique mandate ID for tracking.
    pub id: MandateId,
    /// The BPF map key that was written.
    pub key: MandateKeyInfo,
    /// When the mandate expires (Unix timestamp ms).
    pub expires_at_ms: u64,
    /// Current mandate status.
    pub status: MandateStatus,
    /// Whether this mandate is kernel-enforced (BPF LSM active).
    #[serde(default)]
    pub enforced: bool,
    /// Enforcement mode: "enforce", "monitor", or "none".
    pub enforcement_mode: String,
}

/// Human-readable representation of a MandateKey.
#[derive(Debug, Clone, Serialize)]
pub struct MandateKeyInfo {
    pub pid: u32,
    pub start_time_ns: u64,
    pub cmd_hash: u64,
}

/// Mandate lifecycle status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MandateStatus {
    Active,
    Expired,
    Revoked,
    Executed,
}

/// Internal mandate record tracked by the manager.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used in Phase 1 (BPF map writeback)
struct MandateRecord {
    id: MandateId,
    key: MandateKey,
    value: MandateValue,
    args: Vec<String>,
    status: MandateStatus,
    created_at: Instant,
    /// Wall-clock expiry time (Unix timestamp ms) for API responses.
    expires_at_ms: u64,
    /// If the mandate has been written to the BPF map.
    bpf_committed: bool,
    /// Signed execution receipt (populated after mandate execution completes).
    receipt: Option<ExecutionReceipt>,
}

/// Summary statistics for the mandate system.
#[derive(Debug, Clone, Serialize)]
pub struct MandateStats {
    pub active_count: usize,
    pub total_created: u64,
    pub total_expired: u64,
    pub total_revoked: u64,
    pub total_executed: u64,
    pub bpf_map_usage: u32,
    pub bpf_map_capacity: u32,
    pub backpressure_active: bool,
}

/// Health status for the mandate subsystem.
#[derive(Debug, Clone, Serialize)]
pub struct MandateHealth {
    pub status: String,
    pub bpf_lsm_loaded: bool,
    pub enforcement_mode: String,
    pub map_usage_percent: f32,
    pub siphash_key_set: bool,
    pub reconciliation_interval_secs: u64,
}

// =============================================================================
// MANDATE MANAGER
// =============================================================================

pub struct MandateManager {
    /// Active mandates indexed by their API-level ID.
    mandates: RwLock<HashMap<MandateId, MandateRecord>>,

    /// Reverse index: mandate_seq → mandate_id.
    /// Populated on create(), cleaned up on reconcile().
    /// Allows the MandateReceiptHandler to look up mandates from kernel events.
    seq_to_id: RwLock<HashMap<u64, MandateId>>,

    /// SipHash-2-4 key (128-bit: [k0, k1]).
    siphash_key: [u64; 2],

    /// Whether BPF LSM is loaded and functional.
    bpf_available: bool,

    /// Current enforcement mode.
    mode: MandateMode,

    /// Monotonic mandate sequence counter.
    next_seq: AtomicU64,

    /// Counters for stats.
    total_created: AtomicU64,
    total_expired: AtomicU64,
    total_revoked: AtomicU64,
    total_executed: AtomicU64,

    /// Approximate count of entries in the BPF map (tracked locally since
    /// BPF LRU maps don't expose count directly).
    bpf_map_count: AtomicU64,

    /// BPF MANDATE_MAP handle for kernel enforcement.
    /// Populated by connect_bpf_maps() after eBPF load.
    bpf_mandate_map: TokioMutex<Option<AyaHashMap<MapData, BpfMandateKey, BpfMandateValue>>>,
}

impl MandateManager {
    /// Create a new MandateManager.
    ///
    /// `siphash_key` — 128-bit key matching what was loaded into eBPF .rodata.
    /// `bpf_available` — whether BPF LSM programs were successfully loaded.
    /// `mode` — initial enforcement mode (Monitor or Enforce).
    pub fn new(siphash_key: [u64; 2], bpf_available: bool, mode: MandateMode) -> Self {
        Self {
            mandates: RwLock::new(HashMap::new()),
            seq_to_id: RwLock::new(HashMap::new()),
            siphash_key,
            bpf_available,
            mode,
            next_seq: AtomicU64::new(1),
            total_created: AtomicU64::new(0),
            total_expired: AtomicU64::new(0),
            total_revoked: AtomicU64::new(0),
            total_executed: AtomicU64::new(0),
            bpf_map_count: AtomicU64::new(0),
            bpf_mandate_map: TokioMutex::new(None),
        }
    }

    /// Whether BPF LSM is available for kernel enforcement.
    pub fn bpf_available(&self) -> bool {
        self.bpf_available
    }

    /// Current enforcement mode.
    pub fn mode(&self) -> &MandateMode {
        &self.mode
    }

    /// Enforcement mode as a string for API responses.
    pub fn enforcement_mode_str(&self) -> &'static str {
        match self.mode {
            MandateMode::Monitor => "monitor",
            MandateMode::Enforce => "enforce",
        }
    }

    /// Connect the BPF maps taken from the loaded eBPF object.
    ///
    /// Must be called after eBPF programs are loaded. Writes the SipHash key
    /// and enforcement mode into the kernel maps so the LSM hooks can use them.
    /// After this call, create/revoke/reconcile will maintain the MANDATE_MAP.
    pub async fn connect_bpf_maps(&self, mut maps: BpfMandateMaps) {
        // Write SipHash key into SIPHASH_KEY array map (indices 0 and 1).
        if let Err(e) = maps.siphash_map.set(0, self.siphash_key[0], 0) {
            warn!("[mandate] failed to write SIPHASH_KEY[0] to BPF map: {e}");
        }
        if let Err(e) = maps.siphash_map.set(1, self.siphash_key[1], 0) {
            warn!("[mandate] failed to write SIPHASH_KEY[1] to BPF map: {e}");
        }

        // Write enforcement mode to MANDATE_MODE array map (index 0).
        let mode_val = self.mode as u32;
        if let Err(e) = maps.mode_map.set(0, mode_val, 0) {
            warn!("[mandate] failed to write MANDATE_MODE to BPF map: {e}");
        }

        info!(
            "[mandate] BPF maps connected: siphash_key=[{:#x}, {:#x}] mode={}",
            self.siphash_key[0],
            self.siphash_key[1],
            self.enforcement_mode_str()
        );

        *self.bpf_mandate_map.lock().await = Some(maps.mandate_map);
    }

    /// Canonicalize command arguments and compute SipHash-2-4.
    ///
    /// Canonical form (per specs.md §1.1.1):
    ///   arg0 \x00 arg1 \x00 arg2 \x00 ...
    /// UTF-8 encoded, NUL-separated, no trailing NUL.
    ///
    /// NOTE: This hashes ALL args. For BPF map keys, use [`hash_filename`]
    /// which matches the kernel LSM hook's hashing (filename only).
    pub fn hash_args(&self, args: &[String]) -> u64 {
        let mut hasher = SipHasher::new(self.siphash_key[0], self.siphash_key[1]);
        for (i, arg) in args.iter().enumerate() {
            if i > 0 {
                hasher.write_byte(0x00); // NUL separator
            }
            hasher.write(arg.as_bytes());
        }
        hasher.finish()
    }

    /// Compute the BPF-map-compatible hash using only the first argument
    /// (the binary filename / resolved path).
    ///
    /// The kernel LSM hook (`bprm_check_security`) hashes only
    /// `linux_binprm->filename` — the resolved binary path — not the full
    /// argv.  This method MUST produce the same hash so that mandate
    /// lookups in the BPF map succeed.
    pub fn hash_filename(&self, args: &[String]) -> u64 {
        let mut hasher = SipHasher::new(self.siphash_key[0], self.siphash_key[1]);
        if let Some(filename) = args.first() {
            hasher.write(filename.as_bytes());
        }
        hasher.finish()
    }

    /// Read the start_time_ns for a process from /proc/<pid>/stat.
    ///
    /// Field 22 is `starttime` in clock ticks since boot.
    /// Converted to nanoseconds via `ticks * (1e9 / CLK_TCK)`.
    fn read_start_time_ns(pid: u32) -> Result<u64> {
        if pid == 0 {
            return Err(anyhow!("invalid PID 0"));
        }
        // Construct path from a u32 — only digits, no path traversal possible.
        let mut stat_path = std::path::PathBuf::from("/proc");
        stat_path.push(pid.to_string());
        stat_path.push("stat");
        let stat_content = std::fs::read_to_string(&stat_path)
            .with_context(|| format!("failed to read {}", stat_path.display()))?;

        // /proc/<pid>/stat format: pid (comm) state ppid ... field22=starttime
        // The comm field can contain spaces and parens, so we find the last ')'
        // and work from there.
        let last_paren = stat_content
            .rfind(')')
            .ok_or_else(|| anyhow!("malformed /proc/{}/stat: no closing paren", pid))?;

        let fields_after_comm = &stat_content[last_paren + 2..]; // skip ") "
        let fields: Vec<&str> = fields_after_comm.split_whitespace().collect();

        // Field 22 in the full stat is starttime. After ")" and state, it's at
        // index 19 (0-indexed) in the remaining fields.
        // Fields after ')': state(0) ppid(1) pgrp(2) session(3) tty_nr(4) tpgid(5)
        //   flags(6) minflt(7) cminflt(8) majflt(9) cmajflt(10) utime(11) stime(12)
        //   cutime(13) cstime(14) priority(15) nice(16) num_threads(17) itrealvalue(18)
        //   starttime(19)
        const STARTTIME_INDEX: usize = 19;

        if fields.len() <= STARTTIME_INDEX {
            return Err(anyhow!(
                "malformed /proc/{}/stat: not enough fields (got {})",
                pid,
                fields.len()
            ));
        }

        let starttime_ticks: u64 = fields[STARTTIME_INDEX]
            .parse()
            .with_context(|| format!("failed to parse starttime from /proc/{}/stat", pid))?;

        // Convert clock ticks to nanoseconds
        let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if clk_tck <= 0 {
            return Err(anyhow!("sysconf(_SC_CLK_TCK) returned {}", clk_tck));
        }

        let ns_per_tick = 1_000_000_000u64 / (clk_tck as u64);
        Ok(starttime_ticks.saturating_mul(ns_per_tick))
    }

    /// Resolve a container PID to a host PID using `/proc/*/cgroup` matching.
    ///
    /// See specs.md §2.5. When `container_id` is provided, we scan `/proc`
    /// entries whose cgroup path contains the container ID prefix (12+ chars).
    /// Returns the host-namespace PID.
    pub fn resolve_container_pid(container_pid: u32, container_id: &str) -> Result<u32> {
        if container_id.len() < 12 {
            return Err(anyhow!("container_id must be at least 12 hex chars"));
        }
        // Validate container_id contains only hex characters to prevent
        // injection via cgroup path matching.
        if !container_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow!("container_id must contain only hex characters"));
        }

        let prefix = &container_id[..12];

        // Scan /proc for processes whose cgroup contains this container ID
        let proc_dir = std::fs::read_dir("/proc").context("failed to read /proc")?;

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Only look at numeric (PID) directories
            let Ok(host_pid) = name_str.parse::<u32>() else {
                continue;
            };

            // Check cgroup for container ID — host_pid is a parsed u32, safe.
            let mut cgroup_path = std::path::PathBuf::from("/proc");
            cgroup_path.push(host_pid.to_string());
            cgroup_path.push("cgroup");
            let Ok(cgroup_content) = std::fs::read_to_string(&cgroup_path) else {
                continue;
            };

            if !cgroup_content.contains(prefix) {
                continue;
            }

            // Found a process in this container. Now check NSpid to see if the
            // namespace PID matches the requested container_pid.
            let mut status_path = std::path::PathBuf::from("/proc");
            status_path.push(host_pid.to_string());
            status_path.push("status");
            let Ok(status_content) = std::fs::read_to_string(&status_path) else {
                continue;
            };

            for line in status_content.lines() {
                if let Some(nspid_str) = line.strip_prefix("NSpid:") {
                    let pids: Vec<u32> = nspid_str
                        .split_whitespace()
                        .filter_map(|s| s.parse().ok())
                        .collect();

                    // NSpid lists PIDs from outermost to innermost namespace.
                    // The last entry is the container-visible PID.
                    if pids.last() == Some(&container_pid) {
                        info!(
                            "[mandate] resolved container PID {} (container={}) → host PID {}",
                            container_pid,
                            &container_id[..12],
                            host_pid
                        );
                        return Ok(host_pid);
                    }
                }
            }
        }

        Err(anyhow!(
            "pid {} not found in container {} namespace",
            container_pid,
            &container_id[..12]
        ))
    }

    /// Check if backpressure should be applied (map usage > 80%).
    pub fn is_backpressure_active(&self) -> bool {
        self.bpf_map_count.load(Ordering::Relaxed) as u32 >= MANDATE_MAP_WATERMARK
    }

    /// Create a new mandate.
    ///
    /// Returns `Err` with a descriptive message if:
    /// - The PID doesn't exist
    /// - Backpressure is active (map > 80% full)
    /// - The process start time can't be read
    /// - The args list is empty or exceeds size limits
    pub async fn create(&self, req: MandateRequest) -> Result<MandateResponse> {
        // Validate args to prevent unbounded allocation from user input.
        const MAX_ARGS: usize = 128;
        const MAX_ARG_BYTES: usize = 4096;
        if req.args.is_empty() {
            return Err(anyhow!("args must not be empty"));
        }
        if req.args.len() > MAX_ARGS {
            return Err(anyhow!(
                "too many args ({}, max {})",
                req.args.len(),
                MAX_ARGS
            ));
        }
        let total_bytes: usize = req.args.iter().map(|a| a.len()).sum();
        if total_bytes > MAX_ARG_BYTES {
            return Err(anyhow!(
                "total args size {} bytes exceeds max {} bytes",
                total_bytes,
                MAX_ARG_BYTES
            ));
        }

        // Check backpressure
        if self.is_backpressure_active() {
            return Err(anyhow!(
                "mandate map backpressure active ({}/{} entries). Retry later.",
                self.bpf_map_count.load(Ordering::Relaxed),
                MANDATE_MAP_MAX_ENTRIES
            ));
        }

        // Resolve container PID → host PID if container_id is provided (§2.5)
        let effective_pid = if let Some(ref cid) = req.container_id {
            Self::resolve_container_pid(req.pid, cid).with_context(|| {
                format!(
                    "container PID {} in container {} could not be resolved",
                    req.pid,
                    &cid[..cid.len().min(12)]
                )
            })?
        } else {
            req.pid
        };

        // Validate the PID exists
        let start_time_ns = Self::read_start_time_ns(effective_pid)
            .with_context(|| format!("PID {} does not exist or is not readable", effective_pid))?;

        // Hash only the filename (first arg) for the BPF map key.
        // This matches the kernel LSM hook which hashes binprm->filename only.
        let cmd_hash = self.hash_filename(&req.args);

        // Build the key
        let key = MandateKey {
            pid: effective_pid,
            _pad: 0,
            start_time_ns,
            cmd_hash,
        };

        // Calculate expiry
        let now_ns = nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME)
            .map(|ts| ts.tv_sec() as u64 * 1_000_000_000 + ts.tv_nsec() as u64)
            .unwrap_or(0);
        let expires_ns = now_ns.saturating_add(req.ttl_ms.saturating_mul(1_000_000));

        // Build the value
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let flags = if req.monitor_only {
            MandateValue::FLAG_MONITOR
        } else {
            0
        };

        let value = MandateValue {
            expires_ns,
            flags,
            _reserved: 0,
            mandate_seq: seq,
        };

        // Generate mandate ID
        let id = uuid::Uuid::new_v4().to_string();

        // Calculate expires_at for the API response (wall-clock)
        let expires_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
            + req.ttl_ms;

        // Store the record
        let record = MandateRecord {
            id: id.clone(),
            key,
            value,
            args: req.args,
            status: MandateStatus::Active,
            created_at: Instant::now(),
            expires_at_ms,
            bpf_committed: self.bpf_available, // mark as committed if BPF is available
            receipt: None,
        };

        let response = MandateResponse {
            id: id.clone(),
            key: MandateKeyInfo {
                pid: key.pid,
                start_time_ns: key.start_time_ns,
                cmd_hash: key.cmd_hash,
            },
            expires_at_ms,
            status: MandateStatus::Active,
            enforced: self.bpf_available && self.mode == MandateMode::Enforce,
            enforcement_mode: self.enforcement_mode_str().to_string(),
        };

        {
            let mut mandates = self.mandates.write().await;
            mandates.insert(id.clone(), record);
        }

        // Populate reverse index for kernel event → mandate ID lookups.
        {
            let mut seq_map = self.seq_to_id.write().await;
            seq_map.insert(seq, id.clone());
        }

        // Write to BPF MANDATE_MAP so the LSM hook can enforce this mandate.
        {
            let mut bpf_guard = self.bpf_mandate_map.lock().await;
            if let Some(ref mut bpf_map) = *bpf_guard {
                if let Err(e) = bpf_map.insert(BpfMandateKey(key), BpfMandateValue(value), 0) {
                    warn!("[mandate] BPF map insert failed for mandate {}: {}", id, e);
                } else {
                    debug!(
                        "[mandate] BPF map: inserted mandate {} (pid={})",
                        id, key.pid
                    );
                }
            }
        }

        self.total_created.fetch_add(1, Ordering::Relaxed);
        self.bpf_map_count.fetch_add(1, Ordering::Relaxed);

        Ok(response)
    }

    /// Get a mandate by ID.
    pub async fn get(&self, id: &str) -> Option<MandateResponse> {
        let mandates = self.mandates.read().await;
        let record = mandates.get(id)?;

        Some(MandateResponse {
            id: record.id.clone(),
            key: MandateKeyInfo {
                pid: record.key.pid,
                start_time_ns: record.key.start_time_ns,
                cmd_hash: record.key.cmd_hash,
            },
            expires_at_ms: record.expires_at_ms,
            status: record.status.clone(),
            enforced: self.bpf_available && self.mode == MandateMode::Enforce,
            enforcement_mode: self.enforcement_mode_str().to_string(),
        })
    }

    /// Revoke (delete) a mandate by ID.
    pub async fn revoke(&self, id: &str) -> Result<()> {
        let revoked_key = {
            let mut mandates = self.mandates.write().await;
            let record = mandates
                .get_mut(id)
                .ok_or_else(|| anyhow!("mandate {} not found", id))?;

            if record.status != MandateStatus::Active {
                return Err(anyhow!(
                    "mandate {} is not active (status: {:?})",
                    id,
                    record.status
                ));
            }

            record.status = MandateStatus::Revoked;
            record.key
        };

        // Remove from BPF MANDATE_MAP so the LSM hook stops enforcing it.
        {
            let mut bpf_guard = self.bpf_mandate_map.lock().await;
            if let Some(ref mut bpf_map) = *bpf_guard {
                if let Err(e) = bpf_map.remove(&BpfMandateKey(revoked_key)) {
                    warn!("[mandate] BPF map remove failed for mandate {}: {}", id, e);
                } else {
                    debug!(
                        "[mandate] BPF map: removed revoked mandate {} (pid={})",
                        id, revoked_key.pid
                    );
                }
            }
        }

        self.total_revoked.fetch_add(1, Ordering::Relaxed);
        self.bpf_map_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            })
            .ok();

        info!("[mandate] revoked mandate {}", id);
        Ok(())
    }

    /// Create multiple mandates in a batch (up to 64).
    ///
    /// Each mandate is created independently — individual failures do not
    /// prevent other mandates from being created. Returns per-item results.
    pub async fn create_batch(&self, batch: BatchMandateRequest) -> BatchMandateResponse {
        const MAX_BATCH_SIZE: usize = 64;

        let mandates = if batch.mandates.len() > MAX_BATCH_SIZE {
            warn!(
                "[mandate] batch size {} exceeds max {}, truncating",
                batch.mandates.len(),
                MAX_BATCH_SIZE
            );
            &batch.mandates[..MAX_BATCH_SIZE]
        } else {
            &batch.mandates
        };

        let total = mandates.len().min(MAX_BATCH_SIZE);
        let mut results = Vec::with_capacity(total);
        let mut succeeded = 0usize;
        let mut failed = 0usize;

        for (index, req) in mandates.iter().enumerate() {
            match self.create(req.clone()).await {
                Ok(resp) => {
                    results.push(BatchMandateResult {
                        index,
                        mandate: Some(resp),
                        error: None,
                    });
                    succeeded += 1;
                }
                Err(e) => {
                    results.push(BatchMandateResult {
                        index,
                        mandate: None,
                        error: Some(e.to_string()),
                    });
                    failed += 1;
                }
            }
        }

        BatchMandateResponse {
            total,
            succeeded,
            failed,
            results,
        }
    }

    /// Mark a mandate as executed and attach a signed receipt.
    ///
    /// Called when the mandated process completes (exit event received).
    pub async fn mark_executed(&self, id: &str, receipt: ExecutionReceipt) -> Result<()> {
        let mut mandates = self.mandates.write().await;
        let record = mandates
            .get_mut(id)
            .ok_or_else(|| anyhow!("mandate {} not found", id))?;

        if record.status != MandateStatus::Active {
            return Err(anyhow!(
                "mandate {} is not active (status: {:?})",
                id,
                record.status
            ));
        }

        record.status = MandateStatus::Executed;
        record.receipt = Some(receipt);

        self.total_executed.fetch_add(1, Ordering::Relaxed);
        self.bpf_map_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            })
            .ok();

        info!("[mandate] mandate {} executed, receipt stored", id);
        Ok(())
    }

    /// Get the execution receipt for a mandate.
    ///
    /// Returns `None` if the mandate doesn't exist or hasn't been executed yet.
    pub async fn get_receipt(&self, id: &str) -> Option<ExecutionReceipt> {
        let mandates = self.mandates.read().await;
        mandates.get(id)?.receipt.clone()
    }

    /// Get the arguments for a mandate.
    pub async fn get_args(&self, id: &str) -> Option<Vec<String>> {
        let mandates = self.mandates.read().await;
        mandates.get(id).map(|r| r.args.clone())
    }

    /// Get the mandate status.
    pub async fn get_status(&self, id: &str) -> Option<MandateStatus> {
        let mandates = self.mandates.read().await;
        mandates.get(id).map(|r| r.status.clone())
    }

    /// Look up a mandate ID by its kernel sequence number.
    ///
    /// Used by MandateReceiptHandler to resolve kernel MandateAllow events
    /// (which carry mandate_seq) back to the API-level mandate ID.
    pub async fn find_id_by_seq(&self, seq: u64) -> Option<MandateId> {
        let seq_map = self.seq_to_id.read().await;
        seq_map.get(&seq).cloned()
    }

    /// Get the execution data needed to build a receipt for a mandate.
    ///
    /// Returns `(args, mandate_seq)` if the mandate exists and is active.
    pub async fn get_execution_data(&self, id: &str) -> Option<(Vec<String>, u64)> {
        let mandates = self.mandates.read().await;
        let record = mandates.get(id)?;
        if record.status != MandateStatus::Active {
            return None;
        }
        Some((record.args.clone(), record.value.mandate_seq))
    }

    /// Run the reconciliation loop — scans all mandates and evicts expired ones.
    /// Called every MANDATE_RECONCILE_INTERVAL_SECS by a background task.
    pub async fn reconcile(&self) -> usize {
        // Current boot-monotonic time matches MandateValue.expires_ns (eBPF side).
        let now_ns = nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME)
            .map(|ts| ts.tv_sec() as u64 * 1_000_000_000 + ts.tv_nsec() as u64)
            .unwrap_or(0);

        let mut mandates = self.mandates.write().await;
        let mut to_expire: Vec<(MandateId, MandateKey, u64)> = Vec::new();

        for (id, record) in mandates.iter() {
            if record.status == MandateStatus::Active && now_ns >= record.value.expires_ns {
                to_expire.push((id.clone(), record.key, record.value.mandate_seq));
            }
        }

        let expired_count = to_expire.len();

        if expired_count > 0 {
            // Remove from BPF map before updating userspace state.
            {
                let mut bpf_guard = self.bpf_mandate_map.lock().await;
                if let Some(ref mut bpf_map) = *bpf_guard {
                    for (id, key, _seq) in &to_expire {
                        if let Err(e) = bpf_map.remove(&BpfMandateKey(*key)) {
                            // Key may already have been evicted by LRU; not an error.
                            debug!("[mandate] BPF map remove on expire (mandate={}): {}", id, e);
                        }
                    }
                }
            }

            // Clean up seq_to_id reverse index for expired mandates.
            {
                let mut seq_map = self.seq_to_id.write().await;
                for (_id, _key, seq) in &to_expire {
                    seq_map.remove(seq);
                }
            }

            for (id, _key, _seq) in &to_expire {
                if let Some(record) = mandates.get_mut(id) {
                    record.status = MandateStatus::Expired;
                }
            }

            self.total_expired
                .fetch_add(expired_count as u64, Ordering::Relaxed);
            self.bpf_map_count
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(expired_count as u64))
                })
                .ok();
            debug!(
                "[mandate] reconciliation: expired {} mandates",
                expired_count
            );
        }

        expired_count
    }

    /// Get current mandate statistics.
    pub async fn stats(&self) -> MandateStats {
        let mandates = self.mandates.read().await;
        let active_count = mandates
            .values()
            .filter(|r| r.status == MandateStatus::Active)
            .count();

        MandateStats {
            active_count,
            total_created: self.total_created.load(Ordering::Relaxed),
            total_expired: self.total_expired.load(Ordering::Relaxed),
            total_revoked: self.total_revoked.load(Ordering::Relaxed),
            total_executed: self.total_executed.load(Ordering::Relaxed),
            bpf_map_usage: self.bpf_map_count.load(Ordering::Relaxed) as u32,
            bpf_map_capacity: MANDATE_MAP_MAX_ENTRIES,
            backpressure_active: self.is_backpressure_active(),
        }
    }

    /// Get health status for the mandate subsystem.
    pub fn health(&self) -> MandateHealth {
        MandateHealth {
            status: if self.bpf_available {
                "healthy".into()
            } else {
                "degraded".into()
            },
            bpf_lsm_loaded: self.bpf_available,
            enforcement_mode: match self.mode {
                MandateMode::Monitor => "monitor".into(),
                MandateMode::Enforce => "enforce".into(),
            },
            map_usage_percent: (self.bpf_map_count.load(Ordering::Relaxed) as f32
                / MANDATE_MAP_MAX_ENTRIES as f32)
                * 100.0,
            siphash_key_set: self.siphash_key[0] != 0 || self.siphash_key[1] != 0,
            reconciliation_interval_secs: MANDATE_RECONCILE_INTERVAL_SECS,
        }
    }

    /// List all mandates (optionally filtered by status).
    pub async fn list(&self, status_filter: Option<MandateStatus>) -> Vec<MandateResponse> {
        let mandates = self.mandates.read().await;

        mandates
            .values()
            .filter(|r| status_filter.as_ref().is_none_or(|s| &r.status == s))
            .map(|r| MandateResponse {
                id: r.id.clone(),
                key: MandateKeyInfo {
                    pid: r.key.pid,
                    start_time_ns: r.key.start_time_ns,
                    cmd_hash: r.key.cmd_hash,
                },
                expires_at_ms: r.expires_at_ms,
                status: r.status.clone(),
                enforced: self.bpf_available && self.mode == MandateMode::Enforce,
                enforcement_mode: self.enforcement_mode_str().to_string(),
            })
            .collect()
    }

    /// Spawn the background reconciliation loop.
    pub fn spawn_reconciliation_loop(self: &Arc<Self>) {
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(MANDATE_RECONCILE_INTERVAL_SECS));
            loop {
                interval.tick().await;
                let expired = manager.reconcile().await;
                if expired > 0 {
                    debug!(
                        "[mandate] reconciliation tick: expired {} mandates",
                        expired
                    );
                }
            }
        });
    }
}

// =============================================================================
// SIPHASH TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_siphash_deterministic() {
        let key = [0xdeadbeef_u64, 0xcafebabe_u64];
        let data = b"curl https://example.com";
        let h1 = siphash_2_4(key, data);
        let h2 = siphash_2_4(key, data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_siphash_reference_vector() {
        // Same test vector as the eBPF-side implementation
        let k0 = u64::from_le_bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        let k1 = u64::from_le_bytes([0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);

        let input: Vec<u8> = (0..15u8).collect();
        let hash = siphash_2_4([k0, k1], &input);

        assert_eq!(hash, 0xa129ca6149be45e5, "reference vector mismatch");
    }

    #[test]
    fn test_canonicalize_args() {
        let mgr = MandateManager::new([0xdeadbeef, 0xcafebabe], false, MandateMode::Monitor);

        // Same args should produce same hash
        let args1 = vec!["curl".to_string(), "https://example.com".to_string()];
        let args2 = vec!["curl".to_string(), "https://example.com".to_string()];
        assert_eq!(mgr.hash_args(&args1), mgr.hash_args(&args2));

        // Different args should produce different hash
        let args3 = vec!["wget".to_string(), "https://example.com".to_string()];
        assert_ne!(mgr.hash_args(&args1), mgr.hash_args(&args3));
    }

    #[test]
    fn test_hash_filename_matches_first_arg_only() {
        let mgr = MandateManager::new([0xdeadbeef, 0xcafebabe], false, MandateMode::Monitor);

        // hash_filename should only use the first arg
        let args_full = vec![
            "/usr/bin/curl".to_string(),
            "https://example.com".to_string(),
        ];
        let args_cmd_only = vec!["/usr/bin/curl".to_string()];
        assert_eq!(
            mgr.hash_filename(&args_full),
            mgr.hash_filename(&args_cmd_only),
            "hash_filename should ignore args beyond the first"
        );

        // hash_filename should differ from hash_args for multi-arg inputs
        assert_ne!(
            mgr.hash_filename(&args_full),
            mgr.hash_args(&args_full),
            "hash_filename and hash_args should differ for multi-arg inputs"
        );
    }

    #[tokio::test]
    async fn test_get_returns_stored_expiry() {
        let mgr = MandateManager::new([1, 2], false, MandateMode::Monitor);
        let ttl_ms = 60_000u64;

        let req = MandateRequest {
            pid: std::process::id(),
            args: vec!["test".to_string()],
            ttl_ms,
            container_id: None,
            monitor_only: false,
            task_id: None,
            max_spend_cents: None,
            counterparty_did: None,
            wallet_address: None,
            jurisdiction: None,
        };

        let resp = mgr.create(req).await.unwrap();
        let fetched = mgr.get(&resp.id).await.unwrap();

        // expires_at_ms from get() should match create() response
        assert_eq!(fetched.expires_at_ms, resp.expires_at_ms);
        // And should be in the future (not just current time)
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(
            fetched.expires_at_ms > now_ms,
            "expires_at_ms should be in the future"
        );
    }

    #[tokio::test]
    async fn test_create_rejects_empty_args() {
        let mgr = MandateManager::new([1, 2], false, MandateMode::Monitor);
        let req = MandateRequest {
            pid: std::process::id(),
            args: vec![],
            ttl_ms: 5000,
            container_id: None,
            monitor_only: false,
            task_id: None,
            max_spend_cents: None,
            counterparty_did: None,
            wallet_address: None,
            jurisdiction: None,
        };
        assert!(mgr.create(req).await.is_err());
    }

    #[tokio::test]
    async fn test_create_rejects_too_many_args() {
        let mgr = MandateManager::new([1, 2], false, MandateMode::Monitor);
        let args: Vec<String> = (0..200).map(|i| format!("arg{}", i)).collect();
        let req = MandateRequest {
            pid: std::process::id(),
            args,
            ttl_ms: 5000,
            container_id: None,
            monitor_only: false,
            task_id: None,
            max_spend_cents: None,
            counterparty_did: None,
            wallet_address: None,
            jurisdiction: None,
        };
        assert!(mgr.create(req).await.is_err());
    }

    #[test]
    fn test_backpressure() {
        let mgr = MandateManager::new([1, 2], false, MandateMode::Monitor);
        assert!(!mgr.is_backpressure_active());

        // Simulate high map usage
        mgr.bpf_map_count
            .store(MANDATE_MAP_WATERMARK as u64, Ordering::Relaxed);
        assert!(mgr.is_backpressure_active());
    }

    #[tokio::test]
    async fn test_create_and_get_mandate() {
        let mgr = MandateManager::new([1, 2], false, MandateMode::Monitor);

        // Create a mandate for our own PID (which definitely exists)
        let req = MandateRequest {
            pid: std::process::id(),
            args: vec!["test".to_string(), "command".to_string()],
            ttl_ms: 5000,
            container_id: None,
            monitor_only: false,
            task_id: None,
            max_spend_cents: None,
            counterparty_did: None,
            wallet_address: None,
            jurisdiction: None,
        };

        let resp = mgr.create(req).await.expect("create should succeed");
        assert_eq!(resp.status, MandateStatus::Active);
        assert_eq!(resp.key.pid, std::process::id());

        // Get it back
        let fetched = mgr.get(&resp.id).await.expect("should find mandate");
        assert_eq!(fetched.id, resp.id);
    }

    #[tokio::test]
    async fn test_revoke_mandate() {
        let mgr = MandateManager::new([1, 2], false, MandateMode::Monitor);

        let req = MandateRequest {
            pid: std::process::id(),
            args: vec!["test".to_string()],
            ttl_ms: 5000,
            container_id: None,
            monitor_only: false,
            task_id: None,
            max_spend_cents: None,
            counterparty_did: None,
            wallet_address: None,
            jurisdiction: None,
        };

        let resp = mgr.create(req).await.unwrap();
        mgr.revoke(&resp.id).await.expect("revoke should succeed");

        let fetched = mgr.get(&resp.id).await.unwrap();
        assert_eq!(fetched.status, MandateStatus::Revoked);

        // Double revoke should fail
        assert!(mgr.revoke(&resp.id).await.is_err());
    }

    #[tokio::test]
    async fn test_stats() {
        let mgr = MandateManager::new([1, 2], false, MandateMode::Monitor);

        let stats = mgr.stats().await;
        assert_eq!(stats.active_count, 0);
        assert_eq!(stats.total_created, 0);

        let req = MandateRequest {
            pid: std::process::id(),
            args: vec!["test".to_string()],
            ttl_ms: 5000,
            container_id: None,
            monitor_only: false,
            task_id: None,
            max_spend_cents: None,
            counterparty_did: None,
            wallet_address: None,
            jurisdiction: None,
        };

        mgr.create(req).await.unwrap();
        let stats = mgr.stats().await;
        assert_eq!(stats.active_count, 1);
        assert_eq!(stats.total_created, 1);
    }
}
