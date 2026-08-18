//! `linnix explain <incident-id>` — what was concluded about an incident, and
//! on what evidence.
//!
//! The daemon renders the investigation; this command prints it. That split is
//! deliberate and is the same rule the grounding itself follows: every cited
//! fact is resolved through the daemon's own wording, so a client cannot
//! restate a fact while appearing to quote it. A CLI that formatted the
//! hypotheses itself would be free to drift from what was stored.

use colored::*;
use reqwest::Client;
use serde::Deserialize;
use std::error::Error;

#[derive(Deserialize, Debug)]
pub struct IncidentView {
    pub timestamp: i64,
    pub event_type: String,
    pub action: String,
    pub target_name: Option<String>,
    pub target_pid: Option<i64>,
    pub psi_cpu: f32,
    pub cpu_percent: f32,
    /// Present only when a grounded investigation exists.
    pub investigation_rendered: Option<String>,
    /// The stored investigation itself. Present-but-unrendered means the
    /// daemon kept the row and could not read it — a different situation from
    /// there being no investigation at all, and one the operator has to be
    /// told about rather than shown a plausible wrong explanation.
    pub investigation: Option<serde_json::Value>,
    /// The model's reply verbatim. Kept even when nothing grounded, which is
    /// the only way to tell a broken endpoint from a model that answers badly.
    pub llm_analysis: Option<String>,
    pub psi_after: Option<f32>,
    pub recovery_time_ms: Option<i64>,
}

/// Renders the incident. Returned rather than printed so tests can read it.
pub fn render(incident: &IncidentView, id: &str, color: bool) -> String {
    let heading = |s: &str| {
        if color {
            s.bold().to_string()
        } else {
            s.to_string()
        }
    };

    let mut out = format!(
        "{} #{} — {} at unix {}\n",
        heading("Incident:"),
        id,
        incident.event_type,
        incident.timestamp
    );

    let target = match (&incident.target_name, incident.target_pid) {
        (Some(name), Some(pid)) => format!("{name} ({pid})"),
        (Some(name), None) => name.clone(),
        (None, Some(pid)) => format!("pid {pid}"),
        (None, None) => "unknown target".to_string(),
    };
    out.push_str(&format!(
        "  Action:   {} on {}\n  At the time: CPU {:.1}%, CPU pressure {:.1}%\n",
        incident.action, target, incident.cpu_percent, incident.psi_cpu
    ));

    // The outcome, kept in the three states the daemon distinguishes: it
    // recovered, it was watched and did not, or nobody measured.
    match (incident.recovery_time_ms, incident.psi_after) {
        (Some(ms), Some(psi)) => out.push_str(&format!(
            "  Afterwards:  recovered after {:.1}s, pressure {:.1}%\n",
            ms as f64 / 1000.0,
            psi
        )),
        (None, Some(psi)) => out.push_str(&format!(
            "  Afterwards:  did not recover — pressure still {psi:.1}% when the watch ended\n"
        )),
        _ => out.push_str("  Afterwards:  not measured\n"),
    }

    out.push('\n');

    match &incident.investigation_rendered {
        Some(rendered) => {
            out.push_str(&format!("{}\n", heading("Investigation")));
            // Facts quote process names, which are attacker-controlled, and
            // hypothesis text comes from a model. Either can carry escape
            // sequences that rewrite what the terminal displays — including
            // overwriting the evidence above this line.
            out.push_str(&strip_terminal_controls(rendered));
        }
        None => {
            // Three distinct situations, and telling an operator the wrong one
            // sends them to debug the wrong thing.
            out.push_str(match (&incident.investigation, &incident.llm_analysis) {
                // Stored but unrendered: the daemon kept the row and could not
                // read it — corrupt, or written by a newer build.
                (Some(_), _) => {
                    "This incident has a stored investigation the daemon could not read: \
                     it is corrupt, or was written by a newer version. The raw record is \
                     still on the incident.\n"
                }
                (None, Some(_)) => {
                    "No hypothesis survived grounding for this incident: the model \
                     replied, but nothing it claimed could be checked against the \
                     facts the daemon supplied.\n"
                }
                (None, None) => "No analysis has run for this incident.\n",
            });
        }
    }

    out
}

/// Removes control characters that a terminal would act on rather than print.
///
/// Newline and tab are kept because the daemon's rendering uses them for
/// layout. Everything else in the C0 range, plus DEL, is dropped — ESC is the
/// entry point for ANSI and OSC sequences, so removing it disarms the whole
/// family without needing to parse it. The wording itself is untouched, which
/// matters: this text is evidence, and rewriting it would defeat the point of
/// resolving citations through the daemon.
fn strip_terminal_controls(text: &str) -> String {
    text.chars()
        .filter(|c| *c == '\n' || *c == '\t' || (!c.is_control()))
        .collect()
}

pub async fn run_explain(
    client: &Client,
    base: &str,
    id: &str,
    color: bool,
) -> Result<(), Box<dyn Error>> {
    let resp = client
        .get(format!("{}/incidents/{}", base.trim_end_matches('/'), id))
        .send()
        .await?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(format!("no incident #{id}").into());
    }
    if resp.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE {
        return Err("cognitod has no incident store configured".into());
    }
    if !resp.status().is_success() {
        return Err(format!("incident query failed: {}", resp.status()).into());
    }

    let incident: IncidentView = resp.json().await?;
    print!("{}", render(&incident, id, color));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn incident() -> IncidentView {
        IncidentView {
            timestamp: 1_732_242_135,
            event_type: "circuit_breaker_cpu".to_string(),
            action: "auto_kill".to_string(),
            target_name: Some("aggressive-stress.sh".to_string()),
            target_pid: Some(472_693),
            psi_cpu: 75.2,
            cpu_percent: 96.3,
            investigation_rendered: None,
            investigation: None,
            llm_analysis: None,
            psi_after: None,
            recovery_time_ms: None,
        }
    }

    #[test]
    fn the_daemons_rendering_is_printed_verbatim() {
        let mut view = incident();
        view.investigation_rendered =
            Some("1. [cpu_spin] A runaway loop\n   supports:    CPU usage was 96.3%\n".to_string());

        let out = render(&view, "7", false);
        assert!(out.contains("1. [cpu_spin] A runaway loop"), "{out}");
        assert!(out.contains("supports:    CPU usage was 96.3%"), "{out}");
    }

    #[test]
    fn a_reply_that_did_not_ground_is_distinguished_from_no_analysis() {
        let mut answered = incident();
        answered.llm_analysis = Some("some prose".to_string());
        let out = render(&answered, "7", false);
        assert!(out.contains("nothing it claimed could be checked"), "{out}");

        let never = incident();
        let out = render(&never, "7", false);
        assert!(out.contains("No analysis has run"), "{out}");
    }

    #[test]
    fn an_unreadable_investigation_is_not_reported_as_ungrounded() {
        // The daemon keeps the row and omits the rendering when it cannot
        // parse it. Reading only `llm_analysis` here would tell the operator
        // the model failed to ground, sending them to debug the reasoner when
        // the real problem is a corrupt or newer-version record.
        let mut view = incident();
        view.llm_analysis = Some("some prose".to_string());
        view.investigation = Some(serde_json::json!({"schema_version": 99}));

        let out = render(&view, "7", false);
        assert!(out.contains("could not read"), "{out}");
        assert!(
            !out.contains("No hypothesis survived grounding"),
            "an unreadable record must not be reported as a grounding failure: {out}"
        );
    }

    #[test]
    fn terminal_controls_in_evidence_are_disarmed() {
        let mut view = incident();
        // A process name is attacker-controlled and reaches the facts verbatim.
        view.investigation_rendered = Some(
            "1. [cpu_spin] Runaway loop\n   supports:    process \u{1b}[2J\u{1b}[Hevil was busy\n"
                .to_string(),
        );

        let out = render(&view, "7", false);
        assert!(
            !out.contains('\u{1b}'),
            "escape sequences must not reach the terminal: {out:?}"
        );
        // The wording survives — this is evidence, not decoration.
        assert!(out.contains("Runaway loop"), "{out}");
        assert!(out.contains("evil was busy"), "{out}");
        assert!(out.contains("supports:"), "{out}");
    }

    #[test]
    fn the_three_outcome_states_read_differently() {
        let mut recovered = incident();
        recovered.recovery_time_ms = Some(3_200);
        recovered.psi_after = Some(4.1);
        assert!(render(&recovered, "7", false).contains("recovered after 3.2s"));

        let mut stuck = incident();
        stuck.psi_after = Some(71.0);
        assert!(render(&stuck, "7", false).contains("did not recover"));

        // Never measured must not read as a finding.
        assert!(render(&incident(), "7", false).contains("not measured"));
    }
}
