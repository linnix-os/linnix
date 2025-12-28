//! CUDA uprobe attachment for GPU call tracing
//!
//! This module provides runtime attachment of eBPF uprobes to libcuda.so
//! for tracing CUDA API calls with sub-millisecond precision.

use anyhow::{Result, anyhow};
use aya::Ebpf;
use aya::programs::UProbe;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Known paths where libcuda.so might be installed
const CUDA_LIB_PATHS: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu/libcuda.so.1",
    "/usr/lib64/libcuda.so.1",
    "/usr/local/cuda/lib64/libcuda.so.1",
    "/lib/x86_64-linux-gnu/libcuda.so.1",
    "/usr/lib/libcuda.so.1",
];

/// CUDA functions we want to trace
const CUDA_FUNCTIONS: &[(&str, &str)] = &[
    ("handle_cuda_malloc", "cudaMalloc"),
    ("handle_cuda_free", "cudaFree"),
    ("handle_cuda_launch_kernel", "cudaLaunchKernel"),
    ("handle_cuda_memcpy", "cudaMemcpy"),
];

/// Find the path to libcuda.so on this system
pub fn find_libcuda_path() -> Option<PathBuf> {
    for path in CUDA_LIB_PATHS {
        if Path::new(path).exists() {
            return Some(PathBuf::from(path));
        }
    }
    None
}

/// Attach a single CUDA uprobe
fn attach_cuda_uprobe_internal(
    bpf: &mut Ebpf,
    program_name: &str,
    function_name: &str,
    cuda_path: &Path,
) -> Result<()> {
    let uprobe: &mut UProbe = bpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow!("{} program not found in eBPF object", program_name))?
        .try_into()?;

    uprobe.load()?;
    // aya UProbe::attach(location: fn_name | offset, target: Path, pid: Option<i32>, cookie: Option<u64>)
    uprobe.attach(function_name, cuda_path, None, None)?;

    info!(
        "[cuda] Attached uprobe {} to {}",
        program_name, function_name
    );
    Ok(())
}

/// Attach all CUDA uprobes to libcuda.so
///
/// This function is called during cognitod startup when the cuda feature is enabled.
/// It gracefully handles missing libcuda.so (non-GPU systems).
///
/// # Returns
/// - `Ok(true)` if at least one uprobe was attached
/// - `Ok(false)` if libcuda.so was not found
/// - `Err` if attachment failed unexpectedly
pub fn attach_cuda_uprobes(bpf: &mut Ebpf) -> Result<bool> {
    let cuda_path = match find_libcuda_path() {
        Some(path) => path,
        None => {
            info!("[cuda] libcuda.so not found, CUDA uprobes not attached");
            return Ok(false);
        }
    };

    info!("[cuda] Found libcuda.so at {:?}", cuda_path);

    let mut attached_count = 0;

    for (program_name, function_name) in CUDA_FUNCTIONS {
        match attach_cuda_uprobe_internal(bpf, program_name, function_name, &cuda_path) {
            Ok(()) => attached_count += 1,
            Err(e) => {
                warn!(
                    "[cuda] Failed to attach {} to {}: {}",
                    program_name, function_name, e
                );
            }
        }
    }

    if attached_count > 0 {
        info!(
            "[cuda] Attached {}/{} CUDA uprobes",
            attached_count,
            CUDA_FUNCTIONS.len()
        );
        Ok(true)
    } else {
        warn!("[cuda] No CUDA uprobes attached, symbol resolution may have failed");
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_libcuda_path_graceful() {
        // Should return None on systems without CUDA, not panic
        let _ = find_libcuda_path();
    }
}
