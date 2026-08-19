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
    /// The daemon's rendering.
    ///
    /// Three states that have to stay distinct: a string is the rendering; an
    /// explicit `null` means this daemon tried and could not read the stored
    /// record; an **absent** key means the daemon predates this field. Typed
    /// as `Value` because serde cannot otherwise tell a null from a missing
    /// key, and collapsing those two reports a version skew as a corrupt
    /// record.
    #[serde(default)]
    pub investigation_rendered: Option<serde_json::Value>,
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

impl IncidentView {
    /// Strips terminal controls from every string that arrived from the
    /// daemon, once, on the way in.
    ///
    /// Doing this per-field at the point of printing is what failed review:
    /// `investigation_rendered` was sanitized and `target_name` — which is
    /// `proc.comm`, chosen by whoever started the process — was not. Cleaning
    /// at the boundary means a field added later cannot reintroduce the hole,
    /// and it keeps the intended styling below safe, since that is applied
    /// after this runs rather than being stripped by it.
    fn sanitized(self) -> Self {
        Self {
            // Header fields are interpolated into single lines, so a break in
            // one forges a line: a process named "x\n  Afterwards: recovered"
            // would print a header row the daemon never wrote. Same reasoning
            // as the daemon's own renderer — layout is meaning.
            event_type: single_line(&self.event_type),
            action: single_line(&self.action),
            target_name: self.target_name.as_deref().map(single_line),
            // The one field whose newlines *are* the daemon's layout. Its
            // scalars were already flattened server-side before being placed
            // into that layout, so only escape sequences need removing here.
            investigation_rendered: self.investigation_rendered.map(|v| match v {
                serde_json::Value::String(s) => {
                    serde_json::Value::String(strip_terminal_controls(&s))
                }
                other => other,
            }),
            llm_analysis: self.llm_analysis.as_deref().map(single_line),
            ..self
        }
    }
}

/// Renders the incident. Returned rather than printed so tests can read it.
pub fn render(incident: &IncidentView, id: i64, color: bool) -> String {
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

    match incident
        .investigation_rendered
        .as_ref()
        .and_then(|v| v.as_str())
    {
        Some(rendered) => {
            out.push_str(&format!("{}\n", heading("Investigation")));
            // Facts quote process names, which are attacker-controlled, and
            // hypothesis text comes from a model. Either can carry escape
            // sequences that rewrite what the terminal displays — including
            // overwriting the evidence above this line.
            out.push_str(rendered);
        }
        None => {
            // Four distinct situations, and telling an operator the wrong one
            // sends them to debug the wrong thing.
            //
            // An explicit null means this daemon tried and failed; an absent
            // key means it has no such field, which is a version skew rather
            // than a bad record.
            let daemon_tried = incident.investigation_rendered.is_some();

            out.push_str(match (&incident.investigation, &incident.llm_analysis) {
                (Some(_), _) if daemon_tried => {
                    "This incident has a stored investigation the daemon could not read: \
                     it is corrupt, or was written by a newer version. The raw record is \
                     still on the incident.\n"
                }
                (Some(_), _) => {
                    "This incident has a stored investigation, but this daemon is an older \
                     version that cannot render it. Upgrade cognitod, or read the raw \
                     record on the incident.\n"
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

/// Flattens a value onto one line, so it cannot forge the layout around it.
///
/// For every field printed inside a single line. Breaks become their escaped
/// spelling rather than vanishing: a process name that tried to fake a header
/// row is worth seeing as an attempt.
fn single_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {}
            c => out.push(c),
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
    id: i64,
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
    print!("{}", render(&incident.sanitized(), id, color));
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
        view.investigation_rendered = Some(serde_json::json!(
            "1. [cpu_spin] A runaway loop\n   supports:    CPU usage was 96.3%\n"
        ));

        let out = render(&view, 7, false);
        assert!(out.contains("1. [cpu_spin] A runaway loop"), "{out}");
        assert!(out.contains("supports:    CPU usage was 96.3%"), "{out}");
    }

    #[test]
    fn a_reply_that_did_not_ground_is_distinguished_from_no_analysis() {
        let mut answered = incident();
        answered.llm_analysis = Some("some prose".to_string());
        let out = render(&answered, 7, false);
        assert!(out.contains("nothing it claimed could be checked"), "{out}");

        let never = incident();
        let out = render(&never, 7, false);
        assert!(out.contains("No analysis has run"), "{out}");
    }

    #[test]
    fn an_older_daemon_is_not_reported_as_a_corrupt_record() {
        // The previous daemon returns the investigation as a JSON string and
        // has no `investigation_rendered` key at all. Telling an operator
        // mid-upgrade that their record is corrupt sends them to fix data that
        // is fine.
        let mut view = incident();
        view.llm_analysis = Some("some prose".to_string());
        view.investigation = Some(serde_json::json!("{\"schema_version\":1}"));
        view.investigation_rendered = None; // absent, not null

        let out = render(&view.sanitized(), 7, false);
        assert!(out.contains("older version that cannot render"), "{out}");
        assert!(
            !out.contains("could not read"),
            "a version skew is not a corrupt record: {out}"
        );
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
        // The daemon says "I tried and could not" with an explicit null, which
        // is what separates this from a daemon that has no such field.
        view.investigation_rendered = Some(serde_json::Value::Null);

        let out = render(&view, 7, false);
        assert!(out.contains("could not read"), "{out}");
        assert!(
            !out.contains("No hypothesis survived grounding"),
            "an unreadable record must not be reported as a grounding failure: {out}"
        );
    }

    #[test]
    fn every_daemon_supplied_string_is_disarmed_not_just_the_evidence() {
        // `target_name` is `proc.comm`: whoever started the process chose it.
        // The header prints before the investigation, so an escape here can
        // clear the screen and rewrite everything that follows.
        let mut view = incident();
        view.target_name = Some("\u{1b}[2J\u{1b}[Hinnocent".to_string());
        view.event_type = "\u{1b}[31mcircuit_breaker_cpu".to_string();
        view.action = "auto_kill\u{7}".to_string();
        view.llm_analysis = Some("prose\u{1b}[2J".to_string());

        let out = render(&view.sanitized(), 7, false);

        assert!(
            !out.contains('\u{1b}') && !out.contains('\u{7}'),
            "no daemon-supplied string may carry terminal controls: {out:?}"
        );
        // The names themselves survive — an operator still needs to read them.
        assert!(out.contains("innocent"), "{out}");
        assert!(out.contains("circuit_breaker_cpu"), "{out}");
        assert!(out.contains("auto_kill"), "{out}");
    }

    #[test]
    fn the_incident_id_cannot_carry_layout_at_all() {
        // The id is typed `i64` at the command line, so a value like
        // `7#\n  Afterwards: recovered` — which the daemon would still answer,
        // since a URL fragment is never sent — cannot reach this function.
        // This pins the type rather than a sanitizer: the class is impossible,
        // not escaped.
        let out = render(&incident().sanitized(), 7, false);
        assert!(out.contains("Incident: #7 "), "{out}");

        let forged: Vec<&str> = out
            .lines()
            .filter(|l| l.trim_start().starts_with("Afterwards:"))
            .collect();
        assert_eq!(forged.len(), 1, "one outcome row only: {out}");
    }

    #[test]
    fn a_process_name_cannot_forge_a_header_row() {
        // Removing escapes is not enough: a bare newline in `proc.comm` splits
        // the Action line and the second half reads as a header the daemon
        // wrote. The outcome row is the tempting target — "recovered" is the
        // most useful lie available.
        let mut view = incident();
        view.target_name = Some("innocent\n  Afterwards:  recovered after 0.1s".to_string());

        let out = render(&view.sanitized(), 7, false);

        let forged: Vec<&str> = out
            .lines()
            .filter(|l| l.trim_start().starts_with("Afterwards:"))
            .collect();
        assert_eq!(
            forged.len(),
            1,
            "only the daemon's own outcome row may appear: {out}"
        );
        assert!(
            forged[0].contains("not measured"),
            "the surviving row must be the real one: {out}"
        );
        // Still legible, with the attempt visible rather than trimmed away.
        assert!(out.contains("innocent\\n"), "{out}");
    }

    #[test]
    fn sanitizing_does_not_strip_the_cli_own_styling() {
        // `colored` disables itself when stdout is not a terminal, which it is
        // not under a test harness, so the override is what makes this assert
        // anything at all.
        colored::control::set_override(true);
        let out = render(&incident().sanitized(), 7, true);
        colored::control::unset_override();

        assert!(
            out.contains('\u{1b}'),
            "styling is applied after cleaning and must survive it"
        );
    }

    #[test]
    fn terminal_controls_in_evidence_are_disarmed() {
        let mut view = incident();
        // A process name is attacker-controlled and reaches the facts verbatim.
        view.investigation_rendered = Some(serde_json::json!(
            "1. [cpu_spin] Runaway loop\n   supports:    process \u{1b}[2J\u{1b}[Hevil was busy\n"
        ));

        let out = render(&view.sanitized(), 7, false);
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
        assert!(render(&recovered, 7, false).contains("recovered after 3.2s"));

        let mut stuck = incident();
        stuck.psi_after = Some(71.0);
        assert!(render(&stuck, 7, false).contains("did not recover"));

        // Never measured must not read as a finding.
        assert!(render(&incident(), 7, false).contains("not measured"));
    }
}
