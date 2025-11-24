//! LLM-based incident analysis
//!
//! Provides asynchronous post-incident analysis using the local LLM to:
//! - Determine root cause of circuit breaker triggers
//! - Classify incident severity
//! - Suggest preventive measures
//! - Detect patterns across multiple incidents

use super::Incident;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use tracing::{debug, warn};

/// Analysis result from LLM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentAnalysis {
    pub action_summary: String,
    pub root_cause: String,
    pub impact: String,
    pub severity: String, // "low", "medium", "high", "critical"
    pub recommendation: String,
    pub confidence: f32, // 0.0 to 1.0
}

/// Incident analyzer using local LLM
pub struct IncidentAnalyzer {
    endpoint: String,
    timeout: Duration,
    client: reqwest::Client,
}

impl IncidentAnalyzer {
    /// Create a new incident analyzer
    pub fn new(endpoint: String, timeout: Duration) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder().timeout(timeout).build()?;

        Ok(Self {
            endpoint,
            timeout,
            client,
        })
    }

    /// Analyze an incident using the LLM
    pub async fn analyze(
        &self,
        incident: &Incident,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let prompt = self.build_analysis_prompt(incident);

        let request_body = json!({
            "model": "linnix-3b-distilled",
            "messages": [
                {
                    "role": "system",
                    "content": "You are Linnix AI, an expert system performance analyst. Analyze circuit breaker incidents and provide concise root cause analysis, severity assessment, and actionable recommendations."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,
            "max_tokens": 500
        });

        debug!("[incident_analyzer] Requesting LLM analysis for incident");

        let response = self
            .client
            .post(&self.endpoint)
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("LLM request failed: {} - {}", status, body).into());
        }

        let response_json: serde_json::Value = response.json().await?;

        // Extract LLM response
        let analysis = response_json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("Analysis unavailable")
            .to_string();

        debug!(
            "[incident_analyzer] Received analysis ({} chars)",
            analysis.len()
        );

        Ok(analysis)
    }

    /// Build the analysis prompt from incident data
    fn build_analysis_prompt(&self, incident: &Incident) -> String {
        let timestamp = chrono::DateTime::from_timestamp(incident.timestamp, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "unknown".to_string());

        format!(
            r#"INCIDENT REPORT

Timestamp: {}
Event Type: {}

ACTION TAKEN BY CIRCUIT BREAKER:
{} - Target Process: {} (PID: {})

SYSTEM METRICS AT INCIDENT TIME:
- CPU Usage: {:.1}%
- CPU PSI (Pressure Stall): {:.1}%
- Memory PSI (Full): {:.1}%
- Load Average: {}

CIRCUIT BREAKER TRIGGER REASON:
{}

ANALYSIS TASK:
You are analyzing a circuit breaker incident where an automated action was taken to protect system stability.

Provide a concise analysis covering:

1. ACTION_SUMMARY: Clearly state what action was taken and to which process (1 sentence)
2. ROOT_CAUSE: Why did this process cause the circuit breaker to trigger? (1-2 sentences)
3. IMPACT: What would have happened if we didn't kill this process? (1 sentence)
4. SEVERITY: Rate as "low", "medium", "high", or "critical"
5. RECOMMENDATION: What should be investigated or changed to prevent this? (2-3 sentences)
6. CONFIDENCE: Your confidence level (0.0-1.0)

Format your response as:

ACTION_SUMMARY: <what we did>
ROOT_CAUSE: <why it happened>
IMPACT: <consequences of inaction>
SEVERITY: <level>
RECOMMENDATION: <suggestion>
CONFIDENCE: <0.0-1.0>
"#,
            timestamp,
            incident.event_type,
            incident.action,
            incident.target_name.as_deref().unwrap_or("unknown"),
            incident.target_pid.unwrap_or(0),
            incident.cpu_percent,
            incident.psi_cpu,
            incident.psi_memory,
            incident.load_avg,
            self.explain_event_type(&incident.event_type, incident.psi_cpu, incident.cpu_percent)
        )
    }

    /// Explain why the circuit breaker triggered
    fn explain_event_type(&self, event_type: &str, psi_cpu: f32, cpu_percent: f32) -> String {
        match event_type {
            "circuit_breaker_cpu" => {
                format!(
                    "Dual-signal CPU thrashing detected: CPU usage at {:.1}% AND PSI at {:.1}%. \
                     This indicates processes were stalled {:.1}% of the time - not just busy, but blocked. \
                     High PSI means context switching overhead dominated actual work.",
                    cpu_percent, psi_cpu, psi_cpu
                )
            }
            "circuit_breaker_memory" => {
                "Memory thrashing detected: System was spending excessive time managing memory pressure \
                 rather than doing useful work. Processes were blocked waiting for memory."
                    .to_string()
            }
            _ => format!("Circuit breaker triggered for event type: {}", event_type),
        }
    }

    /// Parse structured analysis from LLM response
    pub fn parse_analysis(text: &str) -> Option<IncidentAnalysis> {
        let mut action_summary = None;
        let mut root_cause = None;
        let mut impact = None;
        let mut severity = None;
        let mut recommendation = None;
        let mut confidence = None;

        for line in text.lines() {
            let line = line.trim();
            if line.starts_with("ACTION_SUMMARY:") {
                action_summary = Some(line.strip_prefix("ACTION_SUMMARY:")?.trim().to_string());
            } else if line.starts_with("ROOT_CAUSE:") {
                root_cause = Some(line.strip_prefix("ROOT_CAUSE:")?.trim().to_string());
            } else if line.starts_with("IMPACT:") {
                impact = Some(line.strip_prefix("IMPACT:")?.trim().to_string());
            } else if line.starts_with("SEVERITY:") {
                severity = Some(line.strip_prefix("SEVERITY:")?.trim().to_lowercase());
            } else if line.starts_with("RECOMMENDATION:") {
                recommendation = Some(line.strip_prefix("RECOMMENDATION:")?.trim().to_string());
            } else if line.starts_with("CONFIDENCE:") {
                let conf_str = line.strip_prefix("CONFIDENCE:")?.trim();
                confidence = conf_str.parse::<f32>().ok();
            }
        }

        Some(IncidentAnalysis {
            action_summary: action_summary?,
            root_cause: root_cause?,
            impact: impact?,
            severity: severity?,
            recommendation: recommendation?,
            confidence: confidence?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_analysis() {
        let response = r#"
ROOT_CAUSE: Process fork bomb created 200 competing processes, overwhelming scheduler
SEVERITY: critical
RECOMMENDATION: Implement process limits (ulimit -u) and monitor fork rates
CONFIDENCE: 0.95
"#;

        let analysis = IncidentAnalyzer::parse_analysis(response).unwrap();
        assert_eq!(analysis.severity, "critical");
        assert_eq!(analysis.confidence, 0.95);
        assert!(analysis.root_cause.contains("fork bomb"));
    }

    #[test]
    fn test_build_prompt() {
        let incident = Incident {
            id: Some(1),
            timestamp: 1732242135,
            event_type: "circuit_breaker_cpu".to_string(),
            psi_cpu: 75.21,
            psi_memory: 12.34,
            cpu_percent: 96.3,
            load_avg: "26.00,24.20,21.30".to_string(),
            action: "auto_kill".to_string(),
            target_pid: Some(472693),
            target_name: Some("aggressive-stress.sh".to_string()),
            system_snapshot: None,
            llm_analysis: None,
            llm_analyzed_at: None,
            recovery_time_ms: None,
            psi_after: None,
        };

        let analyzer = IncidentAnalyzer::new(
            "http://localhost:8090/v1/chat/completions".to_string(),
            Duration::from_secs(30),
        )
        .unwrap();

        let prompt = analyzer.build_analysis_prompt(&incident);

        assert!(prompt.contains("75.21%"));
        assert!(prompt.contains("aggressive-stress.sh"));
        assert!(prompt.contains("Dual-signal CPU thrashing"));
    }
}
