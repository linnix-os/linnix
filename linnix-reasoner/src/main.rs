use clap::Parser;
use colored::*;
use eventsource_stream::Eventsource;
use futures_util::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Parser)]
struct Args {
    /// Print a one-line summary from the LLM
    #[arg(long)]
    short: bool,
    /// Output raw JSON for scripting/integration
    #[arg(long)]
    json: bool,
    /// Override OpenAI API endpoint
    #[arg(long)]
    endpoint: Option<String>,
    /// Override OpenAI API key
    #[arg(long)]
    api_key: Option<String>,
    /// Override LLM model (default: gpt-3.5-turbo)
    #[arg(long)]
    model: Option<String>,
    /// Show process alerts from cognitod
    #[arg(long)]
    alerts: bool,
    /// Show system-level insights from cognitod
    #[arg(long)]
    insights: bool,
    /// Override cognitod host (default: http://127.0.0.1:3000)
    #[arg(long, default_value = "http://127.0.0.1:3000")]
    host: String,
    /// Write output to a file
    #[arg(long)]
    output: Option<String>,
    /// Stream live process events from cognitod
    #[arg(long)]
    stream: bool,
    /// Output raw JSON for stream events
    #[arg(long)]
    raw: bool,
    /// Only show events matching this tag
    #[arg(long)]
    filter: Option<String>,
    /// Disable colored output
    #[arg(long)]
    no_color: bool,
}

#[derive(Debug, Deserialize)]
struct SystemSnapshot {
    timestamp: u64,
    cpu_percent: f32,
    mem_percent: f32,
    load_avg: [f32; 3],
}

#[derive(Debug, Deserialize)]
struct ProcessAlert {
    pid: u32,
    #[allow(dead_code)]
    ppid: u32,
    comm: String,
    #[allow(dead_code)]
    uid: u32,
    tags: Vec<String>,
    cpu_percent: Option<f32>,
    mem_percent: Option<f32>,
    event_type: u32,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct ProcessEvent {
    pid: u32,
    ppid: u32,
    uid: u32,
    #[allow(dead_code)]
    gid: u32,
    comm: String,
    event_type: u32,
    #[allow(dead_code)]
    ts_ns: u64,
    #[allow(dead_code)]
    seq: u64,
    #[allow(dead_code)]
    exit_time_ns: u64,
    #[allow(dead_code)]
    cpu_pct_milli: u16,
    #[allow(dead_code)]
    mem_pct_milli: u16,
    tags: Vec<String>,
}

#[derive(Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
}

#[derive(Serialize, Deserialize)]
struct ChatChoice {
    message: ChatMessageContent,
}

#[derive(Serialize, Deserialize)]
struct ChatMessageContent {
    content: String,
}

#[derive(Serialize, Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let client = Client::new();

    if args.stream {
        let url = format!("{}/stream", args.host.trim_end_matches('/'));
        let response = client.get(&url).send().await?.error_for_status()?;
        let mut stream = response.bytes_stream().eventsource();

        while let Some(event) = stream.next().await {
            match event {
                Ok(ev) => {
                    let data = ev.data;
                    if args.raw {
                        println!("{data}");
                        continue;
                    }
                    match serde_json::from_str::<ProcessEvent>(&data) {
                        Ok(ev) => {
                            if let Some(ref tag) = args.filter {
                                if !ev.tags.iter().any(|t| t == tag) {
                                    continue;
                                }
                            }
                            let color = !args.no_color;
                            let etype = match ev.event_type {
                                0 => {
                                    if color {
                                        "Exec".green().bold()
                                    } else {
                                        "Exec".normal()
                                    }
                                }
                                1 => {
                                    if color {
                                        "Fork".blue().bold()
                                    } else {
                                        "Fork".normal()
                                    }
                                }
                                2 => {
                                    if color {
                                        "Exit".red().bold()
                                    } else {
                                        "Exit".normal()
                                    }
                                }
                                _ => {
                                    if color {
                                        "Unknown".white().on_red()
                                    } else {
                                        "Unknown".normal()
                                    }
                                }
                            };
                            let line = format!(
                                "[event] PID={} PPID={} COMM={} UID={} TAGS={:?} TYPE={}",
                                ev.pid, ev.ppid, ev.comm, ev.uid, ev.tags, etype
                            );

                            if color {
                                let colored_line = match ev.event_type {
                                    0 => line.green().bold(), // Exec
                                    1 => line.blue().bold(),  // Fork
                                    2 => line.red().bold(),   // Exit
                                    _ => line.white().on_red(),
                                };
                                println!("{colored_line}");
                            } else {
                                println!("{line}");
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to parse event: {e} | data: {data}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Stream error: {e}");
                    break;
                }
            }
        }
        return Ok(());
    }

    if args.alerts {
        let url = "http://localhost:3000/alerts";
        let resp = client.get(url).send().await?;
        let alerts: Vec<ProcessAlert> = resp.json().await?;
        if alerts.is_empty() {
            println!("No active alerts.");
        } else {
            println!("Active Alerts:");
            for alert in alerts {
                println!(
                    "PID: {} CMD: {} TAGS: {:?} CPU: {:.1?}% MEM: {:.1?}% EVENT: {} REASON: {}",
                    alert.pid,
                    alert.comm,
                    alert.tags,
                    alert.cpu_percent,
                    alert.mem_percent,
                    alert.event_type,
                    alert.reason
                );
            }
        }
        return Ok(());
    }

    if args.insights {
        let url = format!("{}/insights", args.host.trim_end_matches('/'));
        let client = Client::new();
        let resp = client
            .get(&url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await;

        let now = chrono::Utc::now();

        let output = match resp {
            Ok(r) => match r.json::<serde_json::Value>().await {
                Ok(json) => {
                    if args.json {
                        serde_json::to_string_pretty(&json).unwrap()
                    } else {
                        let summary = json
                            .get("summary")
                            .and_then(|v| v.as_str())
                            .unwrap_or("No summary.");
                        let risks = json
                            .get("risks")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default();
                        let mut out = String::new();
                        out.push_str(&format!(
                            "{} {}\n{}\n\n",
                            "System Summary:".bold().cyan(),
                            now.format("[%Y-%m-%d %H:%M:%S UTC]"),
                            summary
                        ));
                        if risks.is_empty() {
                            out.push_str(&format!(
                                "{}\n  {}\n",
                                "Risks:".bold().yellow(),
                                "None detected."
                            ));
                        } else {
                            out.push_str(&format!("{}\n", "Risks:".bold().red()));
                            for risk in risks {
                                out.push_str(&format!(
                                    "  - {}\n",
                                    risk.as_str().unwrap_or("Unknown risk")
                                ));
                            }
                        }
                        out
                    }
                }
                Err(_) => "Failed to parse /insights response as JSON.".to_string(),
            },
            Err(e) => format!("Failed to fetch /insights: {e}"),
        };

        if let Some(path) = args.output {
            if let Err(e) = std::fs::write(&path, &output) {
                eprintln!("Failed to write to {path}: {e}");
            }
        } else {
            println!("{output}");
        }
        return Ok(());
    }

    let url = "http://localhost:3000/system";

    let resp = client.get(url).send().await?;
    let snapshot: SystemSnapshot = resp.json().await?;

    // Prepare prompt
    let prompt = if args.short {
        format!(
            "Given this Linux system snapshot: {snapshot:#?}\n\
            Summarize the system state in one short sentence."
        )
    } else {
        format!(
            "Given this Linux system snapshot: {snapshot:#?}\n\
            Answer in one paragraph: What is happening in the OS? Any anomalies or risks? Suggest a cleanup if needed."
        )
    };

    // Read model, endpoint, and API key from CLI args or env
    // Default to local Linnix model if available
    let model = args
        .model
        .or_else(|| env::var("LLM_MODEL").ok())
        .unwrap_or_else(|| "linnix-qwen-v1".to_string());
    let openai_url = args
        .endpoint
        .or_else(|| env::var("LLM_ENDPOINT").ok())
        .unwrap_or_else(|| "http://localhost:8090/v1/chat/completions".to_string());
    
    // API key is optional for local models
    let api_key = args
        .api_key
        .or_else(|| env::var("OPENAI_API_KEY").ok())
        .unwrap_or_else(|| "not-needed-for-local".to_string());

    let req_body = ChatRequest {
        model,
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: "You are a Linux system expert.".to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: prompt,
            },
        ],
    };

    let res = client
        .post(openai_url)
        .bearer_auth(api_key)
        .json(&req_body)
        .send()
        .await?;

    let chat_resp: ChatResponse = res.json().await?;

    if args.json {
        let pretty = serde_json::to_string_pretty(&chat_resp)?;
        println!("{pretty}");
    } else {
        let answer = &chat_resp.choices[0].message.content;
        println!(
            "{}\n  Timestamp: {}\n  CPU: {:.1}%\n  Mem: {:.1}%\n  Load: [{:.2}, {:.2}, {:.2}]",
            "System Snapshot".bold().cyan(),
            snapshot.timestamp,
            snapshot.cpu_percent,
            snapshot.mem_percent,
            snapshot.load_avg[0],
            snapshot.load_avg[1],
            snapshot.load_avg[2]
        );
        println!("\n{}\n{}", "LLM Analysis:".bold().yellow(), answer);
    }

    Ok(())
}
