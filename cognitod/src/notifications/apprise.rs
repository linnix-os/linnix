use crate::alerts::{Alert, Severity};
use crate::config::AppriseConfig;
use anyhow::{Context, Result};
use log::{debug, error, info};
use tokio::process::Command;
use tokio::sync::broadcast;

/// Apprise notification handler
///
/// Subscribes to the alert broadcast channel and forwards alerts to Apprise CLI,
/// which handles delivery to 100+ notification services (Slack, Discord, etc.)
pub struct AppriseNotifier {
    urls: Vec<String>,
    min_severity: Severity,
    rx: broadcast::Receiver<Alert>,
}

impl AppriseNotifier {
    /// Create a new Apprise notifier
    pub fn new(config: AppriseConfig, rx: broadcast::Receiver<Alert>) -> Self {
        let min_severity = parse_severity(
            config
                .min_severity
                .as_deref()
                .unwrap_or("info"),
        );

        Self {
            urls: config.urls,
            min_severity,
            rx,
        }
    }

    /// Run the notifier loop
    ///
    /// Listens for alerts on the broadcast channel and sends them via Apprise.
    /// Runs until the channel is closed.
    pub async fn run(mut self) {
        info!(
            "Apprise notifier started with {} URL(s), min severity: {}",
            self.urls.len(),
            self.min_severity.as_str()
        );

        loop {
            match self.rx.recv().await {
                Ok(alert) => {
                    // Filter by severity
                    if alert.severity < self.min_severity {
                        debug!(
                            "Skipping alert '{}' (severity {} < threshold {})",
                            alert.rule,
                            alert.severity.as_str(),
                            self.min_severity.as_str()
                        );
                        continue;
                    }

                    // Send notification
                    if let Err(e) = self.notify(&alert).await {
                        error!("Failed to send Apprise notification: {}", e);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    error!(
                        "Apprise notifier lagged by {} alerts (processing too slow or burst too fast)",
                        n
                    );
                }
                Err(broadcast::error::RecvError::Closed) => {
                    info!("Alert channel closed, stopping Apprise notifier");
                    break;
                }
            }
        }
    }

    /// Send a single alert via Apprise CLI
    async fn notify(&self, alert: &Alert) -> Result<()> {
        let title = format!("[{}] {}", alert.severity.as_str().to_uppercase(), alert.rule);
        let body = format!("Host: {}\n\n{}", alert.host, alert.message);

        debug!("Sending notification: '{}'", title);

        // Send to each URL (failures on one don't block others)
        for url in &self.urls {
            if let Err(e) = self.send_to_url(url, &title, &body).await {
                error!("Failed to notify {}: {}", mask_url(url), e);
            }
        }

        Ok(())
    }

    /// Send notification to a single Apprise URL
    async fn send_to_url(&self, url: &str, title: &str, body: &str) -> Result<()> {
        let output = Command::new("apprise")
            .arg("--title")
            .arg(title)
            .arg("--body")
            .arg(body)
            .arg(url)
            .output()
            .await
            .context("Failed to execute apprise command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Apprise command failed: {}", stderr.trim());
        }

        debug!("Successfully notified {}", mask_url(url));
        Ok(())
    }
}

/// Parse severity string into Severity enum
fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Mask sensitive information in URLs for logging
fn mask_url(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let scheme = &url[..scheme_end];
        format!("{}://***", scheme)
    } else {
        "***".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_severity() {
        assert!(matches!(parse_severity("high"), Severity::High));
        assert!(matches!(parse_severity("HIGH"), Severity::High));
        assert!(matches!(parse_severity("medium"), Severity::Medium));
        assert!(matches!(parse_severity("low"), Severity::Low));
        assert!(matches!(parse_severity("info"), Severity::Info));
        assert!(matches!(parse_severity("invalid"), Severity::Info));
    }

    #[test]
    fn test_mask_url() {
        assert_eq!(mask_url("slack://token/channel"), "slack://***");
        assert_eq!(mask_url("discord://id/token"), "discord://***");
        assert_eq!(mask_url("invalid-url"), "***");
    }
}
