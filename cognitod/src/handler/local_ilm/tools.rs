use std::collections::{HashSet, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const PROC_ROOT: &str = "/proc";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

fn proc_path(pid: i32) -> PathBuf {
    Path::new(PROC_ROOT).join(pid.to_string())
}

fn read_cmdline(pid: i32) -> io::Result<String> {
    let mut cmdline_path = proc_path(pid);
    cmdline_path.push("cmdline");
    match fs::read(cmdline_path) {
        Ok(bytes) if !bytes.is_empty() => {
            let mut rendered = Vec::new();
            for part in bytes.split(|b| *b == 0) {
                if part.is_empty() {
                    continue;
                }
                rendered.push(String::from_utf8_lossy(part).into_owned());
            }
            if rendered.is_empty() {
                read_comm(pid)
            } else {
                Ok(rendered.join(" "))
            }
        }
        _ => read_comm(pid),
    }
}

fn read_comm(pid: i32) -> io::Result<String> {
    let mut comm_path = proc_path(pid);
    comm_path.push("comm");
    let text = fs::read_to_string(comm_path)?;
    Ok(text.trim().to_string())
}

fn read_children(pid: i32) -> Vec<i32> {
    let mut path = proc_path(pid);
    path.push("task");
    path.push(pid.to_string());
    path.push("children");
    if let Ok(contents) = fs::read_to_string(path) {
        contents
            .split_whitespace()
            .filter_map(|part| part.parse::<i32>().ok())
            .collect()
    } else {
        Vec::new()
    }
}

pub fn ps_tree(root_pid: i32) -> io::Result<String> {
    let mut output = Vec::new();
    let mut queue = VecDeque::from([(root_pid, 0usize)]);
    let mut visited = HashSet::new();

    while let Some((pid, depth)) = queue.pop_front() {
        if !visited.insert(pid) {
            continue;
        }
        let indent = "  ".repeat(depth.min(8));
        let line = match read_cmdline(pid) {
            Ok(cmd) => format!("{indent}{pid} {cmd}"),
            Err(_) => format!("{indent}{pid} <unreadable>"),
        };
        output.push(line);
        if output.len() >= 50 {
            break;
        }
        for child in read_children(pid) {
            queue.push_back((child, depth + 1));
        }
    }

    if output.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no processes found for ps_tree",
        ))
    } else {
        Ok(output.join("\n"))
    }
}

pub fn proc_status(pid: i32) -> io::Result<String> {
    let mut path = proc_path(pid);
    path.push("status");
    let contents = fs::read_to_string(path)?;
    let mut threads = None;
    let mut vmrss = None;
    for line in contents.lines() {
        if line.starts_with("Threads:") {
            threads = Some(line.trim().to_string());
        } else if line.starts_with("VmRSS:") {
            vmrss = Some(line.trim().to_string());
        }
        if threads.is_some() && vmrss.is_some() {
            break;
        }
    }
    let mut parts = Vec::new();
    if let Some(t) = threads {
        parts.push(t);
    }
    if let Some(rss) = vmrss {
        parts.push(rss);
    }
    if parts.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Threads/VmRSS not found in status",
        ));
    }
    Ok(parts.join("\n"))
}

pub fn cgroup_cpu(pid: i32) -> io::Result<String> {
    let mut path = proc_path(pid);
    path.push("cgroup");
    let cgroup_data = fs::read_to_string(path)?;
    let mut chosen_path: Option<&str> = None;
    for line in cgroup_data.lines() {
        let mut parts = line.split(':');
        let _hierarchy = parts.next();
        let controllers = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("/");
        if controllers.is_empty() || controllers.split(',').any(|c| c == "cpu") {
            chosen_path = Some(path);
            if !controllers.is_empty() {
                break;
            }
        }
    }

    let rel = chosen_path.unwrap_or("/");
    let mut base = PathBuf::from(CGROUP_ROOT);
    let trimmed = rel.trim_start_matches('/');
    if !trimmed.is_empty() {
        base = base.join(trimmed);
    }

    let mut snippets = Vec::new();
    for candidate in [
        "cpu.max",
        "cpu.weight",
        "cpu.cfs_quota_us",
        "cpu.cfs_period_us",
    ] {
        let candidate_path = base.join(candidate);
        if let Ok(content) = fs::read_to_string(&candidate_path) {
            snippets.push(format!(
                "{}={}",
                candidate,
                content.split_whitespace().collect::<Vec<_>>().join(" ")
            ));
        }
    }

    if snippets.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "cpu control files unavailable",
        ))
    } else {
        Ok(snippets.join("\n"))
    }
}

pub fn open_fds(pid: i32) -> io::Result<usize> {
    let mut path = proc_path(pid);
    path.push("fd");
    let entries = fs::read_dir(path)?;
    Ok(entries.filter(|entry| entry.is_ok()).count())
}

pub fn net_conns(pid: i32) -> io::Result<usize> {
    let mut path = proc_path(pid);
    path.push("fd");
    let entries = fs::read_dir(path)?;
    let mut count = 0usize;
    for entry in entries.flatten() {
        if let Ok(target) = fs::read_link(entry.path())
            && let Some(name) = target.as_os_str().to_str()
            && name.starts_with("socket:")
        {
            count += 1;
        }
    }
    Ok(count)
}

pub fn format_tool_error(tool: &str, err: io::Error) -> String {
    format!("{tool} error: {err}")
}

pub fn format_count(label: &str, result: io::Result<usize>) -> String {
    match result {
        Ok(value) => format!("{label}: {value}"),
        Err(err) => format!("{label} error: {err}"),
    }
}
