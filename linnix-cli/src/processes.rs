use colored::*;
use reqwest::Client;
use serde::Deserialize;
use std::error::Error;

#[derive(Debug, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub cpu_pct: Option<f32>,
    pub mem_pct: Option<f32>,
    pub priority: Option<Priority>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

impl Priority {
    fn color(&self) -> Color {
        match self {
            Self::Critical => Color::Red,
            Self::High => Color::Yellow,
            Self::Medium => Color::Green,
            Self::Low => Color::Blue,
        }
    }
}

pub async fn run_processes(client: &Client, url: &str) -> Result<(), Box<dyn Error>> {
    let processes: Vec<ProcessInfo> = client
        .get(format!("{}/processes", url))
        .send()
        .await?
        .json()
        .await?;

    println!(
        "{:<8} {:<8} {:<6} {:<6} {:<10} CMD",
        "PID", "PPID", "CPU%", "MEM%", "PRIORITY"
    );

    for p in processes {
        let priority_str = match p.priority {
            Some(ref prio) => format!("{:?}", prio).to_uppercase(),
            None => "-".to_string(),
        };

        let priority_colored = if let Some(ref prio) = p.priority {
            priority_str.color(prio.color())
        } else {
            priority_str.normal()
        };

        println!(
            "{:<8} {:<8} {:<6} {:<6} {:<10} {}",
            p.pid,
            p.ppid,
            format_pct(p.cpu_pct),
            format_pct(p.mem_pct),
            priority_colored,
            p.comm
        );
    }

    Ok(())
}

fn format_pct(opt: Option<f32>) -> String {
    match opt {
        Some(value) => format!("{:.1}", value),
        None => "-".to_string(),
    }
}
