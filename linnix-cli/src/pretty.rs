use crate::event::ProcessEvent;
use colored::*;
use linnix_ai_ebpf_common::{BlockOp, EventType, FileOp, NetOp, PageFaultFlags, PageFaultOrigin};

const DEVICE_MINOR_BITS: u32 = 20;
const DEVICE_MINOR_MASK: u32 = (1 << DEVICE_MINOR_BITS) - 1;

fn format_pct(opt: Option<f32>) -> String {
    match opt {
        Some(value) => format!("{:.1}%", value),
        None => "-".to_string(),
    }
}

fn decode_net_op(op: u32) -> Option<NetOp> {
    match op {
        x if x == NetOp::TcpSend as u32 => Some(NetOp::TcpSend),
        x if x == NetOp::TcpRecv as u32 => Some(NetOp::TcpRecv),
        x if x == NetOp::UdpSend as u32 => Some(NetOp::UdpSend),
        x if x == NetOp::UdpRecv as u32 => Some(NetOp::UdpRecv),
        x if x == NetOp::UnixStreamSend as u32 => Some(NetOp::UnixStreamSend),
        x if x == NetOp::UnixStreamRecv as u32 => Some(NetOp::UnixStreamRecv),
        x if x == NetOp::UnixDgramSend as u32 => Some(NetOp::UnixDgramSend),
        x if x == NetOp::UnixDgramRecv as u32 => Some(NetOp::UnixDgramRecv),
        _ => None,
    }
}

fn decode_file_op(op: u32) -> Option<FileOp> {
    match op {
        x if x == FileOp::Read as u32 => Some(FileOp::Read),
        x if x == FileOp::Write as u32 => Some(FileOp::Write),
        _ => None,
    }
}

fn decode_block_op(op: u32) -> Option<BlockOp> {
    match op {
        x if x == BlockOp::Queue as u32 => Some(BlockOp::Queue),
        x if x == BlockOp::Issue as u32 => Some(BlockOp::Issue),
        x if x == BlockOp::Complete as u32 => Some(BlockOp::Complete),
        _ => None,
    }
}

fn decode_block_dev(dev: u32) -> (u32, u32) {
    let major = dev >> DEVICE_MINOR_BITS;
    let minor = dev & DEVICE_MINOR_MASK;
    (major, minor)
}

fn decode_fault_origin(origin: u32) -> Option<PageFaultOrigin> {
    match origin {
        x if x == PageFaultOrigin::User as u32 => Some(PageFaultOrigin::User),
        x if x == PageFaultOrigin::Kernel as u32 => Some(PageFaultOrigin::Kernel),
        _ => None,
    }
}

pub trait PrettyEvent {
    fn pretty(&self, color: bool) -> String;
}

impl PrettyEvent for ProcessEvent {
    fn pretty(&self, color: bool) -> String {
        let tags = if !self.tags.is_empty() {
            let tag_str = self.tags.join(", ");
            if color {
                format!(" [{}]", tag_str.yellow())
            } else {
                format!(" [{tag_str}]")
            }
        } else {
            "".to_string()
        };
        let styled_pid = if color {
            self.pid.to_string().cyan().to_string()
        } else {
            self.pid.to_string()
        };
        let styled_ppid = if color {
            self.ppid.to_string().cyan().to_string()
        } else {
            self.ppid.to_string()
        };
        let styled_comm = if color {
            self.comm.clone().magenta().to_string()
        } else {
            self.comm.clone()
        };

        match self.event_type {
            x if x == EventType::Exec as u32 => {
                let etype = if color {
                    "[EXEC]".green().bold().to_string()
                } else {
                    "[EXEC]".to_string()
                };
                let cpu = format_pct(self.cpu_percent());
                let mem = format_pct(self.mem_percent());
                format!(
                    "{etype}    PID {styled_pid:<8} PPID {styled_ppid:<8} CPU {cpu:<6} MEM {mem:<6} CMD {styled_comm}{tags}"
                )
            }
            x if x == EventType::Fork as u32 => {
                let etype = if color {
                    "[FORK]".blue().bold().to_string()
                } else {
                    "[FORK]".to_string()
                };
                let cpu = format_pct(self.cpu_percent());
                let mem = format_pct(self.mem_percent());
                format!(
                    "{etype}    PID {styled_pid:<8} PPID {styled_ppid:<8} CPU {cpu:<6} MEM {mem:<6} CMD {styled_comm}{tags}"
                )
            }
            x if x == EventType::Exit as u32 => {
                let etype = if color {
                    "[EXIT]".red().bold().to_string()
                } else {
                    "[EXIT]".to_string()
                };
                format!(
                    "{etype}    PID {styled_pid:<8} CMD {styled_comm}  at {} ns{tags}",
                    self.exit_time().unwrap_or(0)
                )
            }
            x if x == EventType::Net as u32 => {
                let etype = if color {
                    "[NET]".yellow().bold().to_string()
                } else {
                    "[NET]".to_string()
                };
                let (proto, direction) = match decode_net_op(self.aux) {
                    Some(NetOp::TcpSend) => ("TCP", "sent"),
                    Some(NetOp::TcpRecv) => ("TCP", "received"),
                    Some(NetOp::UdpSend) => ("UDP", "sent"),
                    Some(NetOp::UdpRecv) => ("UDP", "received"),
                    Some(NetOp::UnixStreamSend) => ("UNIX-stream", "sent"),
                    Some(NetOp::UnixStreamRecv) => ("UNIX-stream", "received"),
                    Some(NetOp::UnixDgramSend) => ("UNIX-dgram", "sent"),
                    Some(NetOp::UnixDgramRecv) => ("UNIX-dgram", "received"),
                    None => ("net", "transferred"),
                };
                format!(
                    "{etype} PID {styled_pid:<8} {proto} {direction} {bytes} bytes CMD {styled_comm}{tags}",
                    bytes = self.data
                )
            }
            x if x == EventType::FileIo as u32 => {
                let etype = if color {
                    "[FILE]".bright_cyan().bold().to_string()
                } else {
                    "[FILE]".to_string()
                };
                let op = match decode_file_op(self.aux) {
                    Some(FileOp::Write) => "written",
                    Some(FileOp::Read) => "read",
                    None => "touched",
                };
                format!(
                    "{etype} PID {styled_pid:<8} {bytes} bytes {op} CMD {styled_comm}{tags}",
                    bytes = self.data
                )
            }
            x if x == EventType::Syscall as u32 => {
                let etype = if color {
                    "[SYSCALL]".white().bold().to_string()
                } else {
                    "[SYSCALL]".to_string()
                };
                format!(
                    "{etype} PID {styled_pid:<8} call #{call} CMD {styled_comm}{tags}",
                    call = self.data
                )
            }
            x if x == EventType::BlockIo as u32 => {
                let etype = if color {
                    "[BLOCK]".bright_green().bold().to_string()
                } else {
                    "[BLOCK]".to_string()
                };
                let op = match decode_block_op(self.aux) {
                    Some(BlockOp::Queue) => "queued",
                    Some(BlockOp::Issue) => "issued",
                    Some(BlockOp::Complete) => "completed",
                    None => "handled",
                };
                let (major, minor) = decode_block_dev(self.aux2);
                format!(
                    "{etype} PID {styled_pid:<8} {op} {bytes} bytes dev {major}:{minor} sector {sector} CMD {styled_comm}{tags}",
                    bytes = self.data,
                    major = major,
                    minor = minor,
                    sector = self.data2
                )
            }
            x if x == EventType::PageFault as u32 => {
                let etype = if color {
                    "[FAULT]".bright_red().bold().to_string()
                } else {
                    "[FAULT]".to_string()
                };
                let flags = PageFaultFlags::new(self.aux);
                let mut parts: Vec<&'static str> = Vec::new();
                if flags.contains(PageFaultFlags::PROTECTION) {
                    parts.push("protection");
                }
                if flags.contains(PageFaultFlags::WRITE) {
                    parts.push("write");
                }
                if flags.contains(PageFaultFlags::RESERVED) {
                    parts.push("reserved");
                }
                if flags.contains(PageFaultFlags::INSTRUCTION) {
                    parts.push("instruction");
                }
                if flags.contains(PageFaultFlags::SHADOW_STACK) {
                    parts.push("shadow_stack");
                }
                let origin = match decode_fault_origin(self.aux2) {
                    Some(PageFaultOrigin::User) => "user",
                    Some(PageFaultOrigin::Kernel) => "kernel",
                    None => "unknown",
                };
                let flag_desc = if parts.is_empty() {
                    "flags=none".to_string()
                } else {
                    format!("flags={}", parts.join("|"))
                };
                format!(
                    "{etype} PID {styled_pid:<8} addr 0x{addr:016x} ip 0x{ip:016x} {flag_desc} origin={origin} CMD {styled_comm}{tags}",
                    addr = self.data,
                    ip = self.data2,
                    flag_desc = flag_desc,
                    origin = origin
                )
            }
            _ => {
                let etype = if color {
                    "[UNKNOWN]".white().on_red().to_string()
                } else {
                    "[UNKNOWN]".to_string()
                };
                format!("{etype} PID {styled_pid:<8} PPID {styled_ppid:<8} CMD {styled_comm}{tags}")
            }
        }
    }
}
