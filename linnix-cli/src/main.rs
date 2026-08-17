use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use serde::Deserialize;
use std::collections::HashSet;
use std::error::Error;

mod alert;
mod blame;
mod doctor;
mod event;
mod explain;
mod export;
mod http;
mod investigate;
mod pretty;
mod processes;
mod sse;
use alert::Alert;
use event::ProcessEvent;
use export::{export_incident, Format};
use pretty::PrettyEvent;

#[derive(clap::Parser, Debug)]
struct Args {
    /// Base URL of the Cognitod service
    #[clap(long, default_value = "http://127.0.0.1:3000")]
    url: String,

    /// Show daemon status and exit
    #[clap(long)]
    stats: bool,

    /// Stream alerts via SSE
    #[clap(long)]
    alerts: bool,

    /// Disable colorized output
    #[clap(long)]
    no_color: bool,

    /// Subcommands
    #[clap(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Export an incident report
    Export {
        /// Time window to query (e.g. 15m, 1h)
        #[clap(long)]
        since: String,
        /// Rule identifier
        #[clap(long)]
        rule: String,
        /// Output format
        #[clap(long, value_enum, default_value = "txt")]
        format: Format,
    },
    /// Investigate which workloads stalled a pod, and on what evidence
    Investigate {
        /// Victim pod as NAMESPACE/POD
        pod: String,
        /// Time window to investigate (e.g. 20m, 1h)
        #[clap(long, default_value = "15m")]
        since: String,
    },
    /// Explain an incident: what was concluded, and on what evidence
    Explain {
        /// Incident id, as shown by /incidents
        id: String,
    },
    /// Blame a node for performance issues (requires kubectl)
    Blame {
        /// Node name to analyze
        node_name: String,
    },
    /// Provide feedback on an insight
    Feedback {
        /// Insight ID
        id: String,
        /// Feedback type (useful/noise)
        #[clap(value_enum)]
        #[clap(rename_all = "snake_case")]
        rating: FeedbackRating,
    },
    /// Check system health and connectivity
    Doctor,
    /// List running processes with priority
    Processes,
}

#[derive(clap::ValueEnum, Clone, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum FeedbackRating {
    Useful,
    Noise,
}

#[derive(Deserialize, Debug)]
struct Status {
    cpu_pct: f64,
    rss_mb: u64,
    #[serde(rename = "events_per_sec")]
    events_per_sec: u64,
    rb_overflows: u64,
    rate_limited: u64,
    offline: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let client = crate::http::client();
    let color = !args.no_color;

    if let Some(Command::Export {
        since,
        rule,
        format,
    }) = args.command.clone()
    {
        let report = export_incident(&client, &args.url, &since, &rule, format).await?;
        println!("{report}");
        return Ok(());
    }

    if let Some(Command::Investigate { pod, since }) = args.command.clone() {
        investigate::run_investigate(&client, &args.url, &pod, &since, color).await?;
        return Ok(());
    }

    if let Some(Command::Explain { id }) = args.command.clone() {
        explain::run_explain(&client, &args.url, &id, color).await?;
        return Ok(());
    }

    if let Some(Command::Blame { node_name }) = args.command {
        blame::run_blame(&node_name).await?;
        return Ok(());
    }

    if let Some(Command::Feedback { id, rating }) = args.command {
        let url = format!("{}/insights/{}/feedback", args.url, id);
        let resp = client
            .post(&url)
            .json(&serde_json::json!({ "feedback": rating }))
            .send()
            .await?;

        if resp.status().is_success() {
            println!("Feedback submitted successfully.");
        } else {
            eprintln!("Failed to submit feedback: {}", resp.status());
        }
        return Ok(());
    }

    if let Some(Command::Doctor) = args.command {
        doctor::run_doctor(&args.url).await?;
        return Ok(());
    }

    if let Some(Command::Processes) = args.command {
        processes::run_processes(&client, &args.url).await?;
        return Ok(());
    }

    if args.stats {
        let status: Status = client
            .get(format!("{}/status", args.url))
            .send()
            .await?
            .json()
            .await?;
        let header = format!(
            "{:<8} {:<7} {:<8} {:<12} {:<12} {}",
            "cpu_pct", "rss_mb", "events/s", "rb_overflows", "rate_limited", "offline"
        );
        println!("{header}");
        println!(
            "{:<8.2} {:<7} {:<8} {:<12} {:<12} {}",
            status.cpu_pct,
            status.rss_mb,
            status.events_per_sec,
            status.rb_overflows,
            status.rate_limited,
            status.offline
        );
        return Ok(());
    }

    if args.alerts {
        let mut stream = sse::connect_sse(&client, &format!("{}/alerts", args.url)).await?;
        let mut seen: HashSet<Alert> = HashSet::new();
        while let Some(event) = stream.next().await {
            match event {
                Ok(sse::SseEvent::Message(msg)) => {
                    let json = msg.strip_prefix("data: ").unwrap_or(&msg);
                    if let Ok(alert) = serde_json::from_str::<Alert>(json) {
                        if seen.insert(alert.clone()) {
                            println!("{}", alert.pretty(color));
                        }
                    }
                }
                Ok(sse::SseEvent::Heartbeat) => {}
                Err(e) => {
                    eprintln!("Error reading SSE: {e}");
                    break;
                }
            }
        }
        return Ok(());
    }

    let mut stream = sse::connect_sse(&client, &format!("{}/stream", args.url)).await?;

    while let Some(event) = stream.next().await {
        match event {
            Ok(sse::SseEvent::Message(msg)) => {
                let json = msg.strip_prefix("data: ").unwrap_or(&msg);
                match serde_json::from_str::<ProcessEvent>(json) {
                    Ok(ev) => println!("{}", ev.pretty(color)),
                    Err(e) => {
                        eprintln!("Failed to parse JSON: {e}\nInput: {json}");
                        println!("{msg}");
                    }
                }
            }
            Ok(sse::SseEvent::Heartbeat) => {}
            Err(e) => {
                eprintln!("Error reading SSE: {e}");
                break;
            }
        }
    }
    Ok(())
}
