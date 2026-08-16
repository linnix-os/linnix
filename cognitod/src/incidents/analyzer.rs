//! LLM-based incident analysis.
//!
//! The daemon assembles what it observed into a numbered list of facts, and
//! the model's job is to propose hypotheses that *cite* those facts rather
//! than restate them. See [`super::investigation`] for why the citation is the
//! whole point: it is what keeps a fluent answer from passing as a grounded
//! one.

use super::Incident;
use super::investigation::{Fact, IncidentInvestigation, parse_and_ground};
use serde_json::json;
use std::time::Duration;
use tracing::{debug, error, info};

/// What one analysis attempt produced.
///
/// The raw reply is kept whatever happens. When grounding fails there is
/// nothing structured to store, and the only way to tell a broken endpoint
/// from a model that answers badly is to still have what it said.
#[derive(Debug, Clone)]
pub struct AnalysisOutcome {
    pub raw_response: String,
    pub investigation: Option<IncidentInvestigation>,
    /// Why the reply did not yield a grounded investigation, if it did not.
    pub parse_error: Option<String>,
}

/// Turns an incident into the facts the model is allowed to reason from.
///
/// Only values the daemon actually measured become facts. Anything absent is
/// omitted rather than defaulted, because a fact reading "PID 0" invites a
/// hypothesis about PID 0.
pub fn facts_from_incident(incident: &Incident) -> Vec<Fact> {
    let mut facts = vec![
        Fact::new("f1", format!("CPU usage was {:.1}%", incident.cpu_percent)),
        Fact::new(
            "f2",
            format!(
                "CPU pressure stall was {:.1}% — tasks were blocked, not merely busy",
                incident.psi_cpu
            ),
        ),
        Fact::new(
            "f3",
            format!(
                "Memory pressure stall (full) was {:.1}%",
                incident.psi_memory
            ),
        ),
        Fact::new("f4", format!("Load average was {}", incident.load_avg)),
        Fact::new(
            "f5",
            format!(
                "The circuit breaker fired for event type '{}' and took action '{}'",
                incident.event_type, incident.action
            ),
        ),
    ];

    if let Some(name) = &incident.target_name {
        let pid = incident
            .target_pid
            .map(|p| format!(" (PID {p})"))
            .unwrap_or_default();
        facts.push(Fact::new(
            "f6",
            format!("The action targeted process '{name}'{pid}"),
        ));
    }

    facts
}

/// Incident analyzer using local LLM
pub struct IncidentAnalyzer {
    endpoint: String,
    model: String,
    client: reqwest::Client,
}

impl IncidentAnalyzer {
    /// Create a new incident analyzer
    pub fn new(endpoint: String, model: String, timeout: Duration) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder().timeout(timeout).build()?;

        Ok(Self {
            endpoint,
            model,
            client,
        })
    }

    /// Investigates an incident, returning hypotheses grounded in the facts
    /// the daemon supplied.
    ///
    /// A transport failure is an error. A reply that arrives but does not
    /// ground is not: that is a result about the model, and the caller stores
    /// it rather than retrying into the same wall.
    pub async fn analyze(
        &self,
        incident: &Incident,
    ) -> Result<AnalysisOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let facts = facts_from_incident(incident);
        let prompt = Self::build_analysis_prompt(&facts);

        let request_body = json!({
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are Linnix AI, a Linux performance analyst. You reason only from \
                                the numbered facts you are given. You cite facts by id; you never \
                                restate their contents, and you never introduce measurements that \
                                are not among them. Reply with JSON only."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,
            "max_tokens": 800
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

        let raw_response = response_json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        debug!(
            "[incident_analyzer] Received analysis ({} chars)",
            raw_response.len()
        );

        match parse_and_ground(&raw_response, facts) {
            Ok(investigation) => {
                info!(
                    target: "audit",
                    "LLM analysis grounded: {} hypotheses kept, {} discarded for citing unsupplied evidence",
                    investigation.hypotheses.len(),
                    investigation.discarded.len()
                );
                Ok(AnalysisOutcome {
                    raw_response,
                    investigation: Some(investigation),
                    parse_error: None,
                })
            }
            Err(e) => {
                error!(target: "audit", "LLM reply could not be grounded: {}", e);
                Ok(AnalysisOutcome {
                    raw_response,
                    investigation: None,
                    parse_error: Some(e),
                })
            }
        }
    }

    /// Builds the prompt: the facts, then the shape of the reply.
    ///
    /// The facts are numbered because the ids are the only handle the model
    /// gets on them. Asking for citations rather than restatements is what
    /// makes an ungrounded answer detectable instead of merely unlikely.
    fn build_analysis_prompt(facts: &[Fact]) -> String {
        let mut prompt = String::from("OBSERVED FACTS\n\n");
        for fact in facts {
            prompt.push_str(&format!("{}: {}\n", fact.id, fact.statement));
        }

        prompt.push_str(
            r#"
TASK

Propose up to three hypotheses for what caused this incident, most likely
first. Each hypothesis must cite the facts above by id.

Rules:
- Cite only ids from the list. Do not invent facts, measurements, pod names
  or process names that do not appear above.
- A hypothesis with no supporting citation will be discarded.
- If a fact argues against your hypothesis, cite it under
  contradicting_fact_ids. Saying so is worth more than omitting it.
- reason_code must be one of: fork_storm, short_job_flood, runaway_tree,
  cpu_spin, io_saturation, oom_risk, normal.
- confidence is your own estimate, 0.0 to 1.0.

Reply with JSON only, in exactly this shape:

{
  "hypotheses": [
    {
      "reason_code": "cpu_spin",
      "statement": "A single process held the CPU in a tight loop",
      "supporting_fact_ids": ["f1", "f2"],
      "contradicting_fact_ids": [],
      "confidence": 0.7,
      "proposed_action": "Inspect the targeted process before restarting it"
    }
  ]
}
"#,
        );

        prompt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn incident() -> Incident {
        Incident {
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
            investigation: None,
            recovery_time_ms: None,
            psi_after: None,
        }
    }

    #[test]
    fn facts_carry_the_measurements_the_daemon_took() {
        let facts = facts_from_incident(&incident());
        let joined = facts
            .iter()
            .map(|f| f.statement.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(joined.contains("96.3%"));
        assert!(joined.contains("75.2%")); // .1 precision
        assert!(joined.contains("aggressive-stress.sh"));
        assert!(joined.contains("472693"));

        // Ids have to be unique, since they are the model's only handle on a
        // fact and a duplicate would make a citation ambiguous.
        let mut ids: Vec<&str> = facts.iter().map(|f| f.id.as_str()).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count);
    }

    #[test]
    fn an_absent_target_yields_no_fact_about_it() {
        // A fact reading "process 'unknown' (PID 0)" would invite a hypothesis
        // about a process that was never identified.
        let mut incident = incident();
        incident.target_name = None;
        incident.target_pid = None;

        let facts = facts_from_incident(&incident);
        assert!(facts.iter().all(|f| !f.statement.contains("unknown")));
        assert!(facts.iter().all(|f| !f.statement.contains("PID 0")));
    }

    #[test]
    fn the_prompt_lists_every_fact_by_id() {
        let facts = facts_from_incident(&incident());
        let prompt = IncidentAnalyzer::build_analysis_prompt(&facts);

        for fact in &facts {
            assert!(prompt.contains(&fact.id));
            assert!(prompt.contains(&fact.statement));
        }
        assert!(prompt.contains("Cite only ids from the list"));
    }

    #[test]
    fn a_reply_citing_supplied_facts_grounds() {
        let facts = facts_from_incident(&incident());
        let reply = r#"{"hypotheses":[{"reason_code":"cpu_spin",
            "statement":"A tight loop held the CPU","supporting_fact_ids":["f1","f2"],
            "confidence":0.7}]}"#;

        let out = parse_and_ground(reply, facts).expect("well-formed reply grounds");
        assert_eq!(out.hypotheses.len(), 1);
        assert!(out.discarded.is_empty());
    }

    #[test]
    fn a_reply_inventing_a_pod_is_discarded() {
        // The realistic failure: fluent, plausible, and citing evidence that
        // was never supplied.
        let facts = facts_from_incident(&incident());
        let reply = r#"{"hypotheses":[{"reason_code":"fork_storm",
            "statement":"The checkout pod spawned 400 workers",
            "supporting_fact_ids":["f11"]}]}"#;

        let out = parse_and_ground(reply, facts).expect("parses");
        assert!(out.hypotheses.is_empty());
        assert_eq!(out.discarded.len(), 1);
        assert!(!out.render().contains("checkout"));
    }
}
