use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::error::Error;

mod alert;
mod event;
mod export;
mod pretty;
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
    let client = Client::new();
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
