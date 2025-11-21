use sysinfo::{Pid, ProcessesToUpdate, System};

static CRITICAL_NAMES: &[&str] = &[
    "systemd",
    "init",
    "sshd",
    "auditd",
    "cognitod",
    "containerd",
    "dockerd",
];

pub struct SafetyGuard;

impl SafetyGuard {
    pub fn is_safe_to_kill(pid: u32) -> Result<(), String> {
        if pid <= 1 {
            return Err(format!("pid {} is init/systemd", pid));
        }

        let my_pid = std::process::id();
        if pid == my_pid {
            return Err("cannot kill self".to_string());
        }

        let mut sys = System::new();
        let pid_obj = Pid::from_u32(pid);

        sys.refresh_processes(ProcessesToUpdate::Some(&[pid_obj]), false);
        if let Some(proc) = sys.process(pid_obj) {
            let name = proc.name().to_str().unwrap_or("").to_lowercase();

            for critical in CRITICAL_NAMES {
                if name.contains(critical) {
                    return Err(format!("process '{}' is critical", name));
                }
            }

            if let Some(parent) = proc.parent()
                && parent.as_u32() == my_pid
            {
                return Err("cannot kill own child".to_string());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cannot_kill_pid_1() {
        let result = SafetyGuard::is_safe_to_kill(1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("init"));
    }

    #[test]
    fn test_cannot_kill_self() {
        let my_pid = std::process::id();
        let result = SafetyGuard::is_safe_to_kill(my_pid);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("self"));
    }

    #[test]
    fn test_nonexistent_pid() {
        let result = SafetyGuard::is_safe_to_kill(999999);
        assert!(result.is_ok());
    }
}
