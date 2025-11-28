use std::process::{Command, Stdio};
use std::time::Duration;
use std::error::Error;
use reqwest::Client;
use serde::Deserialize;
use colored::*;
use std::io::{BufRead, BufReader};

#[derive(Deserialize, Debug)]
struct InsightRecord {
    #[allow(dead_code)]
    timestamp: u64,
    insight: Insight,
}

#[derive(Deserialize, Debug)]
struct Insight {
    reason_code: String,
    confidence: f64,
    summary: String,
    top_pods: Vec<PodContribution>,
    suggested_next_step: String,
    // Compat
    primary_process: Option<String>,
    actions: Vec<String>,
    k8s: Option<K8sMetadata>,
}

#[derive(Deserialize, Debug)]
struct PodContribution {
    namespace: String,
    pod: String,
    cpu_usage: f32,
    psi_contribution: f32,
}

#[derive(Deserialize, Debug)]
struct K8sMetadata {
    pod_name: String,
    namespace: String,
    #[allow(dead_code)]
    container_name: String,
}

pub async fn run_blame(node_name: &str) -> Result<(), Box<dyn Error>> {
    println!("{} {}...", "Analyzing node".bold().blue(), node_name);

    // 1. Find the pod
    println!("{} Finding cognitod pod on node {}...", "Step 1:".bold(), node_name);
    let output = Command::new("kubectl")
        .args(&[
            "get", "pods", "-A", 
            "--field-selector", &format!("spec.nodeName={}", node_name),
            "-l", "app=cognitod",
            "-o", "jsonpath={.items[0].metadata.name}/{.items[0].metadata.namespace}"
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!("Failed to find cognitod pod: {}", String::from_utf8_lossy(&output.stderr)).into());
    }

    let pod_info = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if pod_info.is_empty() {
        return Err(format!("No cognitod pod found on node {}", node_name).into());
    }

    let parts: Vec<&str> = pod_info.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid pod info format: {}", pod_info).into());
    }
    let pod_name = parts[0];
    let namespace = parts[1];
    println!("{} Found pod {} in namespace {}", "Success:".bold().green(), pod_name, namespace);

    // 2. Port-forward
    println!("{} Establishing secure tunnel...", "Step 2:".bold());
    let mut child = Command::new("kubectl")
        .args(&[
            "port-forward", 
            "-n", namespace,
            pod_name,
            ":3000" 
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()) 
        .spawn()?;

    let stdout = child.stdout.take().ok_or("Failed to capture stdout")?;
    let reader = BufReader::new(stdout);
    
    let (tx, rx) = std::sync::mpsc::channel();
    
    std::thread::spawn(move || {
        for line in reader.lines() {
            if let Ok(l) = line {
                if l.starts_with("Forwarding from") {
                    if let Some(part) = l.split("127.0.0.1:").nth(1) {
                        if let Some(port_str) = part.split(" ->").next() {
                            if let Ok(p) = port_str.parse::<u16>() {
                                let _ = tx.send(p);
                                break;
                            }
                        }
                    }
                }
            }
        }
    });

    let local_port = match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(p) => p,
        Err(_) => {
            let _ = child.kill();
            return Err("Timed out waiting for port-forward".into());
        }
    };

    println!("{} Tunnel established on port {}", "Success:".bold().green(), local_port);

    // 3. Query API
    println!("{} Fetching recent insights...", "Step 3:".bold());
    let client = Client::new();
    let url = format!("http://127.0.0.1:{}/insights/recent?limit=5", local_port);
    
    let resp = client.get(&url).send().await;
    
    match resp {
        Ok(r) => {
            if r.status().is_success() {
                 let insights: Vec<InsightRecord> = r.json().await?;
                 println!("\n{}", "Recent Insights:".bold().underline());
                 if insights.is_empty() {
                     println!("  No recent insights found.");
                 } else {
                     for record in insights {
                         let i = record.insight;
                         let color = match i.reason_code.as_str() {
                             "normal" => "green",
                             "fork_storm" | "cpu_spin" | "runaway_tree" => "red",
                             _ => "yellow",
                         };
                         
                         // Header: Reason | Confidence
                         println!("  [{}] (Confidence: {:.0}%)", 
                            i.reason_code.color(color).bold(), 
                            i.confidence * 100.0
                         );
                         
                         // Summary
                         println!("    {}", i.summary);

                         // Top Pods
                         if !i.top_pods.is_empty() {
                             println!("\n    {}", "Top Contributing Pods:".bold());
                             for pod in i.top_pods {
                                 println!("    • {}/{} (CPU: {:.1}%, PSI: {:.1}%)", 
                                    pod.namespace, pod.pod, pod.cpu_usage, pod.psi_contribution);
                             }
                         }

                         // Suggested Next Step
                         println!("\n    {}: {}", "Suggested Next Step".bold(), i.suggested_next_step);

                         // Compat: Primary Process
                         if let Some(proc) = i.primary_process {
                             print!("\n    Process: {}", proc.bold());
                             if let Some(k8s) = i.k8s {
                                 print!(" (Pod: {}/{})", k8s.namespace, k8s.pod_name);
                             }
                             println!();
                         }
                         
                         println!();
                         println!("{}", "-".repeat(60).dimmed());
                         println!();
                     }
                 }
            } else {
                println!("{} API Error: {}", "Error:".bold().red(), r.status());
            }
        }
        Err(e) => {
             println!("{} Connection failed: {}", "Error:".bold().red(), e);
        }
    }

    // Cleanup
    let _ = child.kill();
    Ok(())
}
