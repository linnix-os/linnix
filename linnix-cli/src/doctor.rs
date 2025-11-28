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
struct MetricsResponse {
    uptime_seconds: u64,
    events_per_sec: u64,
    dropped_events_total: u64,
    rss_probe_mode: String,
    kernel_btf_available: bool,
    perf_poll_errors: u64,
    #[allow(dead_code)]
    ilm_enabled: bool,
    alerts_generated: u64,
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
                if let Ok(_) = resp.json::<HealthResponse>().await {
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

    // 2. Fetch Metrics for deeper checks
    print!("• Agent Metrics:      ");
    let metrics: MetricsResponse = match client.get(format!("{}/metrics", url)).send().await {
        Ok(resp) => resp.json().await?,
        Err(e) => {
            println!("{}", format!("FAIL ({})", e).red());
            return Ok(());
        }
    };
    println!("{}", "OK".green());

    // 3. Check Uptime
    print!("• Uptime:             ");
    if metrics.uptime_seconds < 60 {
        println!(
            "{}",
            format!("{}s (Just started)", metrics.uptime_seconds).yellow()
        );
    } else {
        println!("{}", format!("{}s", metrics.uptime_seconds).green());
    }

    // 4. Check BPF Status
    print!("• BPF Probes:         ");
    if metrics.events_per_sec > 0 {
        println!(
            "{}",
            format!("Active ({} events/sec)", metrics.events_per_sec).green()
        );
    } else {
        println!("{}", "Idle (0 events/sec)".yellow());
    }

    // 5. Check BTF
    print!("• Kernel BTF:         ");
    if metrics.kernel_btf_available {
        println!("{}", "Available".green());
    } else {
        println!("{}", "MISSING".red());
        println!("  → Linnix needs BTF for optimal BPF performance.");
        all_good = false;
    }

    // 6. Check RSS Mode
    print!("• RSS Probe Mode:     ");
    if metrics.rss_probe_mode == "disabled" {
        println!("{}", "DISABLED".red());
        println!("  → Memory metrics will be limited.");
        all_good = false;
    } else {
        println!("{}", metrics.rss_probe_mode.green());
    }

    // 7. Check Errors
    print!("• Perf Poll Errors:   ");
    if metrics.perf_poll_errors > 0 {
        println!(
            "{}",
            format!("{} (Warning)", metrics.perf_poll_errors).yellow()
        );
    } else {
        println!("{}", "0".green());
    }

    // 8. Check Dropped Events
    print!("• Dropped Events:     ");
    if metrics.dropped_events_total > 1000 {
        println!(
            "{}",
            format!("{} (High Load)", metrics.dropped_events_total).yellow()
        );
    } else {
        println!("{}", metrics.dropped_events_total.to_string().green());
    }

    // 9. Check Alerts
    print!("• Alerts Generated:   ");
    if metrics.alerts_generated > 0 {
        println!(
            "{}",
            format!("{} (Check 'linnix-cli alerts')", metrics.alerts_generated).yellow()
        );
    } else {
        println!("{}", "0".green());
    }

    // 10. Check ILM Status
    print!("• AI Analysis:        ");
    if metrics.ilm_enabled {
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
