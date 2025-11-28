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
use tracing::{debug, error, info};

/// Analysis result from LLM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentAnalysis {
    pub reason_code: String, // "fork_storm", "cpu_spin", etc.
    pub summary: String,
    pub confidence: f32,
    pub suggested_next_step: String,
    pub top_pods: Vec<PodContribution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodContribution {
    pub namespace: String,
    pub pod: String,
    pub cpu_usage: f32,
    pub psi_contribution: f32,
}

/// Incident analyzer using local LLM
pub struct IncidentAnalyzer {
    endpoint: String,
    client: reqwest::Client,
}

impl IncidentAnalyzer {
    /// Create a new incident analyzer
    pub fn new(endpoint: String, timeout: Duration) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder().timeout(timeout).build()?;

        Ok(Self { endpoint, client })
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
        info!(target: "audit", "Sending incident analysis request to LLM. Endpoint: {}, Event: {}, Target: {:?}", 
            self.endpoint, 
            incident.event_type,
            incident.target_name
        );

        let response = self
            .client
            .post(&self.endpoint)
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!(target: "audit", "LLM request failed. Status: {}, Error: {}", status, body);
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
        
        info!(target: "audit", "LLM analysis completed successfully. Response length: {} chars", analysis.len());

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
1. REASON_CODE: One of [fork_storm, short_job_flood, runaway_tree, cpu_spin, io_saturation, oom_risk, normal]
2. SUMMARY: A concise explanation of what happened and why (1-2 sentences)
3. CONFIDENCE: Your confidence level (0.0-1.0)
4. SUGGESTED_NEXT_STEP: What should the operator do next? (1 sentence)
5. TOP_PODS: JSON array of pods contributing to the issue (if applicable)

Format your response as a JSON object:
{{
  "reason_code": "fork_storm",
  "summary": "Process foo spawned 200 children...",
  "confidence": 0.95,
  "suggested_next_step": "Check deployment config for replicas",
  "top_pods": [
    {{"namespace": "default", "pod": "foo-123", "cpu_usage": 80.5, "psi_contribution": 10.2}}
  ]
}}
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
        // Find the first '{' and last '}' to extract JSON
        let start = text.find('{')?;
        let end = text.rfind('}')?;
        let json_str = &text[start..=end];

        match serde_json::from_str::<IncidentAnalysis>(json_str) {
            Ok(analysis) => Some(analysis),
            Err(e) => {
                debug!("[incident_analyzer] Failed to parse LLM JSON: {}", e);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_analysis() {
        let response = r#"
Here is the analysis:
{
  "reason_code": "fork_storm",
  "summary": "Process fork bomb created 200 competing processes",
  "confidence": 0.95,
  "suggested_next_step": "Implement process limits",
  "top_pods": []
}
"#;

        let analysis = IncidentAnalyzer::parse_analysis(response).unwrap();
        assert_eq!(analysis.reason_code, "fork_storm");
        assert_eq!(analysis.confidence, 0.95);
        assert!(analysis.summary.contains("fork bomb"));
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

        assert!(prompt.contains("75.2%")); // .1 precision
        assert!(prompt.contains("aggressive-stress.sh"));
        assert!(prompt.contains("Dual-signal CPU thrashing"));
    }
}
