//! Detects the kernel/topology cell the daemon is running on.
//!
//! Only used to stamp `episode::Cell` onto a captured `VmCapture` episode --
//! Phase 3's kernel/topology matrix scores accuracy per cell, so a capture
//! that can't say what it ran on is not useful data. Detection is
//! best-effort: a field that can't be determined is `None`/a fallback string
//! rather than a hard error, since a stall attribution scan must never fail
//! because of missing capture metadata.

use std::path::Path;
use std::process::Command;

use crate::episode::Cell;

const BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
const CGROUP_V2_MARKER: &str = "/sys/fs/cgroup/cgroup.controllers";

/// Detects the current cell against real system paths (`/proc`, `/sys`, and
/// `PATH`). Call once per process -- none of this changes while a daemon
/// runs.
pub fn detect_cell() -> Cell {
    detect_cell_with_root(Path::new("/"))
}

/// Same as [`detect_cell`], but reading `/proc` and `/sys` under `root`
/// instead of the real filesystem root, so tests can exercise this without
/// depending on the host kernel.
fn detect_cell_with_root(root: &Path) -> Cell {
    let is_cgroup_v2 = root.join(CGROUP_V2_MARKER.trim_start_matches('/')).exists();
    Cell {
        kernel_release: read_kernel_release(root),
        arch: std::env::consts::ARCH.to_string(),
        btf_present: root.join(BTF_PATH.trim_start_matches('/')).exists(),
        cgroup_driver: if is_cgroup_v2 { "cgroupv2" } else { "cgroupv1" }.to_string(),
        k3s_version: detect_k3s_version(),
    }
}

fn read_kernel_release(root: &Path) -> String {
    std::fs::read_to_string(root.join("proc/sys/kernel/osrelease"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// `k3s --version`'s first line (e.g. "k3s version v1.30.2+k3s1 ..."), or
/// `None` when the binary isn't on `PATH` or the command fails -- the daemon
/// itself doesn't require k3s, only the Phase 3 matrix VMs do.
fn detect_k3s_version() -> Option<String> {
    let output = Command::new("k3s").arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()?
        .lines()
        .next()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn falls_back_to_unknown_kernel_release_when_proc_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let cell = detect_cell_with_root(tmp.path());
        assert_eq!(cell.kernel_release, "unknown");
        assert_eq!(cell.cgroup_driver, "cgroupv1");
        assert!(!cell.btf_present);
    }

    #[test]
    fn reads_kernel_release_and_detects_cgroup_v2_and_btf() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("proc/sys/kernel")).unwrap();
        fs::write(
            tmp.path().join("proc/sys/kernel/osrelease"),
            "5.15.0-1053-aws\n",
        )
        .unwrap();
        fs::create_dir_all(tmp.path().join("sys/fs/cgroup")).unwrap();
        fs::write(tmp.path().join("sys/fs/cgroup/cgroup.controllers"), "").unwrap();
        fs::create_dir_all(tmp.path().join("sys/kernel/btf")).unwrap();
        fs::write(tmp.path().join("sys/kernel/btf/vmlinux"), "").unwrap();

        let cell = detect_cell_with_root(tmp.path());
        assert_eq!(cell.kernel_release, "5.15.0-1053-aws");
        assert_eq!(cell.cgroup_driver, "cgroupv2");
        assert!(cell.btf_present);
        assert_eq!(cell.arch, std::env::consts::ARCH);
    }
}
