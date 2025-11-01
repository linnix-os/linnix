use clap::ValueEnum;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::Write;

#[derive(Clone, Debug, ValueEnum)]
pub enum Format {
    Md,
    Txt,
}

#[derive(Deserialize)]
struct ExportEvent {
    pid: u32,
    ppid: u32,
    comm: String,
    argv: Vec<String>,
}

#[derive(Deserialize)]
struct StatusResp {
    cpu_pct: f64,
    rss_mb: u64,
}

pub async fn export_incident(
    client: &Client,
    base: &str,
    since: &str,
    rule: &str,
    format: Format,
) -> Result<String, Box<dyn Error>> {
    let events: Vec<ExportEvent> = client
        .get(format!("{}/events", base))
        .query(&[("since", since), ("rule", rule)])
        .send()
        .await?
        .json()
        .await?;

    let status: StatusResp = client
        .get(format!("{}/status", base))
        .send()
        .await?
        .json()
        .await?;

    let mut out = String::new();
    match format {
        Format::Md => {
            writeln!(out, "# Incident: {rule}")?;
            writeln!(out)?;
            writeln!(out, "**Timeframe:** since {since}")?;
        }
        Format::Txt => {
            writeln!(out, "Incident: {rule}")?;
            writeln!(out, "Timeframe: since {since}")?;
        }
    }

    if let Some(ev) = events.first() {
        let chain = format!("{} -> {}", ev.ppid, ev.pid);
        match format {
            Format::Md => writeln!(out, "**Top suspect:** {chain}")?,
            Format::Txt => writeln!(out, "Top suspect: {chain}")?,
        };
        let (args_redacted, argv_hash) = redact_and_hash(&ev.argv);
        match format {
            Format::Md => {
                writeln!(out, "**Command:** {} {}", ev.comm, args_redacted.join(" "))?;
                writeln!(out, "**argv_hash:** {argv_hash}")?;
            }
            Format::Txt => {
                writeln!(out, "Command: {} {}", ev.comm, args_redacted.join(" "))?;
                writeln!(out, "argv_hash: {argv_hash}")?;
            }
        }
    }

    match format {
        Format::Md => {
            writeln!(out, "**CPU:** {:.2}%", status.cpu_pct)?;
            writeln!(out, "**RSS:** {} MB", status.rss_mb)?;
            writeln!(out)?;
            writeln!(out, "## Next safe steps")?;
            writeln!(out, "- Investigate process")?;
            writeln!(out, "- Apply containment")?;
        }
        Format::Txt => {
            writeln!(out, "CPU: {:.2}%", status.cpu_pct)?;
            writeln!(out, "RSS: {} MB", status.rss_mb)?;
            writeln!(out)?;
            writeln!(out, "Next safe steps:")?;
            writeln!(out, "- Investigate process")?;
            writeln!(out, "- Apply containment")?;
        }
    }
    Ok(out)
}

pub fn redact_and_hash(argv: &[String]) -> (Vec<String>, String) {
    let mut hasher = Sha256::new();
    let mut redacted = Vec::new();
    for arg in argv {
        hasher.update(arg.as_bytes());
        if arg.contains('=') {
            if let Some((k, _)) = arg.split_once('=') {
                redacted.push(format!("{k}=<redacted>"));
            } else {
                redacted.push("<redacted>".to_string());
            }
        } else if arg.starts_with('/') {
            redacted.push("<path>".to_string());
        } else {
            redacted.push(arg.clone());
        }
    }
    let hash = format!("{:x}", hasher.finalize());
    (redacted, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_and_hash_stable() {
        let argv = vec![
            "ENV=secret".to_string(),
            "/usr/bin/ls".to_string(),
            "normal".to_string(),
        ];
        let (redacted1, hash1) = redact_and_hash(&argv);
        assert_eq!(redacted1, vec!["ENV=<redacted>", "<path>", "normal"]);
        let (redacted2, hash2) = redact_and_hash(&argv);
        assert_eq!(redacted1, redacted2);
        assert_eq!(hash1, hash2);
    }
}
