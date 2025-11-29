use crate::alerts::{Alert, Severity};
use crate::config::SlackConfig;
use crate::schema::Insight;
use anyhow::{Context, Result};
use log::{debug, error, info};
use reqwest::Client;
use serde_json::json;
use tokio::sync::broadcast;

/// Slack notification handler
pub struct SlackNotifier {
    webhook_url: String,
    channel: Option<String>,
    dashboard_base_url: String,
    rx: broadcast::Receiver<Alert>,
    client: Client,
}

impl SlackNotifier {
    pub fn new(config: SlackConfig, rx: broadcast::Receiver<Alert>) -> Self {
        Self {
            webhook_url: config.webhook_url,
            channel: config.channel,
            dashboard_base_url: config.dashboard_base_url,
            rx,
            client: Client::new(),
        }
    }

    pub async fn run(mut self) {
        info!("Slack notifier started");

        loop {
            match self.rx.recv().await {
                Ok(alert) => {
                    if let Err(e) = self.send_alert(&alert).await {
                        error!("Failed to send Slack alert: {}", e);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    error!("Slack notifier lagged by {} alerts", n);
                }
                Err(broadcast::error::RecvError::Closed) => {
                    info!("Alert channel closed, stopping Slack notifier");
                    break;
                }
            }
        }
    }

    async fn send_alert(&self, alert: &Alert) -> Result<()> {
        let color = match alert.severity {
            Severity::High => "#FF0000",   // Red
            Severity::Medium => "#FFA500", // Orange
            Severity::Low => "#FFFF00",    // Yellow
            Severity::Info => "#0000FF",   // Blue
        };

        let payload = json!({
            "channel": self.channel,
            "attachments": [{
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": format!("🚨 Alert: {}", alert.rule),
                            "emoji": true
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": format!("*Severity:*\n{}", alert.severity.as_str().to_uppercase())
                            },
                            {
                                "type": "mrkdwn",
                                "text": format!("*Host:*\n{}", alert.host)
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": format!("*Message:*\n{}", alert.message)
                        }
                    }
                ]
            }]
        });

        self.post_to_slack(&payload).await
    }

    pub async fn send_insight(&self, insight: &Insight, action_ids: &[String]) -> Result<()> {
        // Note: Redaction should be applied by caller before calling this method

        info!(target: "audit", "Sending insight notification to Slack. Reason: {:?}, ID: {}", insight.reason_code, insight.id);

        let color = match insight.reason_code {
            crate::schema::InsightReason::Normal => "#36a64f", // Green
            _ => "#FF0000",                                    // Red for anomalies
        };

        let mut blocks = vec![
            json!({
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": format!("🚨 {} | 🤖 {:.0}%", insight.reason_code.as_str(), insight.confidence * 100.0),
                    "emoji": true
                }
            }),
            json!({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!("*Summary:*\n{}", insight.summary)
                }
            }),
        ];

        // Top Pods Table
        if !insight.top_pods.is_empty() {
            let mut pod_text = String::from("*Top Contributing Pods:*\n");
            for pod in &insight.top_pods {
                pod_text.push_str(&format!(
                    "• `{}/{}` (CPU: {:.1}%, PSI: {:.1}%)\n",
                    pod.namespace, pod.pod, pod.cpu_usage, pod.psi_contribution
                ));
            }
            blocks.push(json!({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": pod_text
                }
            }));
        }

        // Suggested Next Step
        blocks.push(json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!("*Suggested Next Step:*\n{}", insight.suggested_next_step)
            }
        }));

        // Deprecated compat: Primary Process (if still populated)
        if let Some(proc) = &insight.primary_process {
            blocks.push(json!({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": format!("Primary Process: `{}`", proc)
                }]
            }));
        }

        // Add interactive buttons
        let mut elements = Vec::new();

        // Add Approve/Deny buttons if there are enforcement actions
        if !action_ids.is_empty() {
            let approve_value = format!("approve:{}", action_ids.join("|"));
            let deny_value = format!("deny:{}", action_ids.join("|"));

            elements.push(json!({
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "Approve Fix",
                    "emoji": true
                },
                "style": "primary",
                "value": approve_value,
                "action_id": "approve_action"
            }));

            elements.push(json!({
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "Deny",
                    "emoji": true
                },
                "style": "danger",
                "value": deny_value,
                "action_id": "deny_action"
            }));
        }

        // View Dashboard & Feedback (ID is now mandatory)
        elements.push(json!({
            "type": "button",
            "text": {
                "type": "plain_text",
                "text": "View Dashboard",
                "emoji": true
            },
            "url": format!("{}/insights/{}", self.dashboard_base_url, insight.id)
        }));

        elements.push(json!({
            "type": "button",
            "text": {
                "type": "plain_text",
                "text": "👍 Useful",
                "emoji": true
            },
            "value": format!("useful:{}", insight.id),
            "action_id": "feedback_useful"
        }));

        elements.push(json!({
            "type": "button",
            "text": {
                "type": "plain_text",
                "text": "👎 Noise",
                "emoji": true
            },
            "value": format!("noise:{}", insight.id),
            "action_id": "feedback_noise"
        }));

        blocks.push(json!({
            "type": "actions",
            "elements": elements
        }));

        let payload = json!({
            "channel": self.channel,
            "attachments": [{
                "color": color,
                "blocks": blocks
            }]
        });

        self.post_to_slack(&payload).await?;

        info!(target: "audit", "Successfully sent insight notification to Slack. Reason: {:?}, ID: {}", insight.reason_code, insight.id);
        Ok(())
    }

    async fn post_to_slack(&self, payload: &serde_json::Value) -> Result<()> {
        let res = self
            .client
            .post(&self.webhook_url)
            .json(payload)
            .send()
            .await
            .context("Failed to send request to Slack")?;

        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            anyhow::bail!("Slack API error: {}", text);
        }

        debug!("Successfully sent notification to Slack");
        Ok(())
    }
}
