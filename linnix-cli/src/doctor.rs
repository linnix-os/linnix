use colored::*;
use reqwest::Client;
use serde::Deserialize;
use std::error::Error;

#[derive(Deserialize, Debug)]
struct HealthResponse {
    #[allow(dead_code)]
    status: String,
}

#[derive(Deserialize, Debug)]
struct StatusResponse {
    version: String,
    uptime_s: u64,
    #[allow(dead_code)]
    offline: bool,
    events_per_sec: u64,
    #[allow(dead_code)]
    rb_overflows: u64,
    #[allow(dead_code)]
    rate_limited: u64,
    #[allow(dead_code)]
    kernel_version: String,
    #[allow(dead_code)]
    aya_version: String,
    #[allow(dead_code)]
    transport: String,
    #[allow(dead_code)]
    active_rules: usize,
    probes: StatusProbeState,
    reasoner: ReasonerStatus,
    incidents_last_1h: Option<usize>,
    feedback_entries: u64,
    slack_stats: SlackStats,
    perf_poll_errors: u64,
    dropped_events_total: u64,
}

#[derive(Deserialize, Debug)]
struct StatusProbeState {
    rss_probe: String,
    btf: bool,
}

#[derive(Deserialize, Debug)]
struct ReasonerStatus {
    #[allow(dead_code)]
    configured: bool,
    #[allow(dead_code)]
    endpoint: Option<String>,
    ilm_enabled: bool,
}

#[derive(Deserialize, Debug)]
struct SlackStats {
    sent: u64,
    failed: u64,
    approved: u64,
    denied: u64,
}

pub async fn run_doctor(url: &str) -> Result<(), Box<dyn Error>> {
    println!("{}", "🩺 Linnix Doctor".bold().cyan());
    println!("{}", "Checking system health...".dimmed());
    println!();

    let client = Client::new();
    let mut all_good = true;

    // 1. Check Connectivity & Health
    print!("• Agent Connectivity: ");
    match client.get(format!("{}/healthz", url)).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                if resp.json::<HealthResponse>().await.is_ok() {
                    println!("{}", "OK".green());
                } else {
                    println!("{}", "OK (Invalid JSON)".yellow());
                }
            } else {
                println!("{}", format!("FAIL (Status {})", resp.status()).red());
                all_good = false;
            }
        }
        Err(e) => {
            println!("{}", format!("FAIL ({})", e).red());
            println!("  → Is cognitod running? Try 'systemctl status cognitod'");
            return Ok(()); // Stop here if we can't connect
        }
    }

    // 2. Fetch Status for deeper checks
    print!("• Agent Status:       ");
    let status: StatusResponse = match client.get(format!("{}/status", url)).send().await {
        Ok(resp) => resp.json().await?,
        Err(e) => {
            println!("{}", format!("FAIL ({})", e).red());
            return Ok(());
        }
    };
    println!("{}", format!("OK (v{})", status.version).green());

    // 3. Check Uptime
    print!("• Uptime:             ");
    if status.uptime_s < 60 {
        println!(
            "{}",
            format!("{}s (Just started)", status.uptime_s).yellow()
        );
    } else {
        println!("{}", format!("{}s", status.uptime_s).green());
    }

    // 4. Check BPF Status
    print!("• BPF Probes:         ");
    if status.events_per_sec > 0 {
        println!(
            "{}",
            format!("Active ({} events/sec)", status.events_per_sec).green()
        );
    } else {
        println!("{}", "Idle (0 events/sec)".yellow());
    }

    // 5. Check BTF
    print!("• Kernel BTF:         ");
    if status.probes.btf {
        println!("{}", "Available".green());
    } else {
        println!("{}", "MISSING".red());
        println!("  → Linnix needs BTF for optimal BPF performance.");
        all_good = false;
    }

    // 6. Check RSS Mode
    print!("• RSS Probe Mode:     ");
    if status.probes.rss_probe == "disabled" {
        println!("{}", "DISABLED".red());
        println!("  → Memory metrics will be limited.");
        all_good = false;
    } else {
        println!("{}", status.probes.rss_probe.green());
    }

    // 7. Check Errors
    print!("• Perf Poll Errors:   ");
    if status.perf_poll_errors > 0 {
        println!(
            "{}",
            format!("{} (Warning)", status.perf_poll_errors).yellow()
        );
    } else {
        println!("{}", "0".green());
    }

    // 8. Check Dropped Events
    print!("• Dropped Events:     ");
    if status.dropped_events_total > 1000 {
        println!(
            "{}",
            format!("{} (High Load)", status.dropped_events_total).yellow()
        );
    } else {
        println!("{}", status.dropped_events_total.to_string().green());
    }

    // 9. Check Incidents (Last 1h)
    print!("• Incidents (1h):     ");
    if let Some(count) = status.incidents_last_1h {
        if count > 0 {
            println!("{}", format!("{} (Recent Activity)", count).yellow());
        } else {
            println!("{}", "0".green());
        }
    } else {
        println!("{}", "N/A (Store disabled)".dimmed());
    }

    // 10. Check Feedback
    print!("• User Feedback:      ");
    println!("{}", status.feedback_entries.to_string().green());

    // 11. Check Slack Integration
    print!("• Slack Integration:  ");
    if status.slack_stats.sent > 0 {
        println!(
            "{}",
            format!(
                "Active ({} sent, {} approved, {} denied)",
                status.slack_stats.sent, status.slack_stats.approved, status.slack_stats.denied
            )
            .green()
        );
    } else if status.slack_stats.failed > 0 {
        println!(
            "{}",
            format!("Failing ({} errors)", status.slack_stats.failed).red()
        );
    } else {
        println!("{}", "Idle / Not Configured".dimmed());
    }

    // 12. Check ILM Status
    print!("• AI Analysis:        ");
    if status.reasoner.ilm_enabled {
        println!("{}", "Enabled".green());
    } else {
        println!("{}", "Disabled".dimmed());
    }

    println!();
    if all_good {
        println!(
            "{}",
            "✅ System is healthy and ready for triage.".bold().green()
        );
    } else {
        println!("{}", "⚠️  System has issues. See above.".bold().yellow());
    }

    Ok(())
}
