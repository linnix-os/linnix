//! The structured result of investigating an incident.
//!
//! The analyzer used to hand back whatever prose the model produced and store
//! it verbatim. That output could assert anything — a pod name that never
//! appeared, a CPU figure off by an order of magnitude — and nothing in the
//! pipeline could tell the difference between a sound conclusion and a
//! fluent one.
//!
//! The shape here removes most of that surface. The daemon states the facts;
//! the model may only *cite* them, by id, as supporting or contradicting a
//! hypothesis. It never gets to say what a fact contains, so a hypothesis
//! cannot misquote its own evidence: rendering looks every citation back up in
//! the daemon's copy. What the model still authors is the hypothesis statement
//! itself — that is the part that is genuinely its judgement — and a
//! hypothesis citing a fact that was never supplied is discarded rather than
//! reported, because a model inventing evidence has told you exactly how much
//! the rest of its answer is worth.

use crate::schema::InsightReason;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Bumped when the stored shape changes in a way readers must notice.
pub const SCHEMA_VERSION: u32 = 1;

/// One thing the daemon observed, phrased by the daemon.
///
/// The `id` is what the model cites. The `statement` is never sent back by the
/// model and never read from its response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact {
    pub id: String,
    pub statement: String,
}

impl Fact {
    pub fn new(id: impl Into<String>, statement: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            statement: statement.into(),
        }
    }
}

/// A hypothesis exactly as the model proposed it, before grounding.
#[derive(Debug, Clone, Deserialize)]
pub struct ProposedHypothesis {
    pub reason_code: InsightReason,
    pub statement: String,
    #[serde(default)]
    pub supporting_fact_ids: Vec<String>,
    #[serde(default)]
    pub contradicting_fact_ids: Vec<String>,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub proposed_action: Option<String>,
}

/// The model's raw reply. Only ever an intermediate: [`ground`] turns it into
/// an [`IncidentInvestigation`], and nothing else should consume it.
///
/// `hypotheses` is deliberately required. Defaulting it would make every JSON
/// object a valid reply — `{"error": "..."}`, or a model still answering in
/// the old summary format — and each would ground into an empty investigation
/// that reads as "hypotheses were proposed and none held up" rather than "the
/// question was never answered".
#[derive(Debug, Clone, Deserialize)]
pub struct ProposedInvestigation {
    pub hypotheses: Vec<ProposedHypothesis>,
}

/// A hypothesis whose every citation resolved to a supplied fact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hypothesis {
    pub reason_code: InsightReason,
    pub statement: String,
    pub supporting_fact_ids: Vec<String>,
    pub contradicting_fact_ids: Vec<String>,
    /// The model's own stated confidence, kept under a name that says whose it
    /// is. Nothing calibrates it against outcomes, so it must not be rendered
    /// as though Linnix vouched for the number.
    pub model_stated_confidence: Option<f32>,
    pub proposed_action: Option<String>,
}

/// Why a proposed hypothesis did not survive grounding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum DiscardReason {
    /// Cited no supplied fact at all — an assertion, not a finding.
    NoSupportingFacts,
    /// Cited facts that were never supplied.
    UnknownFactIds { ids: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscardedHypothesis {
    pub statement: String,
    pub reason: DiscardReason,
}

/// A grounded investigation: every surviving hypothesis cites only facts the
/// daemon supplied.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentInvestigation {
    pub schema_version: u32,
    /// The facts as given to the model, stored so a reader can check the
    /// citations without reconstructing the incident.
    pub facts: Vec<Fact>,
    /// Kept in the order the model returned, which is its own ranking.
    pub hypotheses: Vec<Hypothesis>,
    /// Retained rather than dropped: how often a model invents evidence is the
    /// number that tells you whether to trust this path at all.
    pub discarded: Vec<DiscardedHypothesis>,
}

impl IncidentInvestigation {
    /// The daemon's wording for a cited fact.
    pub fn fact_statement(&self, id: &str) -> Option<&str> {
        self.facts
            .iter()
            .find(|f| f.id == id)
            .map(|f| f.statement.as_str())
    }

    /// True when nothing survived grounding. Distinct from "no incident":
    /// something was proposed, and none of it held up.
    pub fn is_empty(&self) -> bool {
        self.hypotheses.is_empty()
    }

    /// One line naming what was discarded and why, or `None` if nothing was.
    ///
    /// The two discard reasons are different failures and are counted apart. A
    /// hypothesis citing nothing is an unsupported assertion; one citing a fact
    /// that was never supplied invented its evidence, which says considerably
    /// more about the rest of the reply. A single catch-all wording would
    /// misreport whichever case it did not describe.
    fn discard_summary(&self) -> Option<String> {
        if self.discarded.is_empty() {
            return None;
        }

        let fabricated = self
            .discarded
            .iter()
            .filter(|d| matches!(d.reason, DiscardReason::UnknownFactIds { .. }))
            .count();
        let unsupported = self.discarded.len() - fabricated;

        let mut causes = Vec::new();
        if fabricated > 0 {
            causes.push(format!("{fabricated} cited evidence that was not supplied"));
        }
        if unsupported > 0 {
            causes.push(format!("{unsupported} cited no evidence at all"));
        }

        Some(format!(
            "{} {} discarded: {}.\n",
            self.discarded.len(),
            if self.discarded.len() == 1 {
                "hypothesis"
            } else {
                "hypotheses"
            },
            causes.join(", ")
        ))
    }

    /// Renders the investigation for a human, resolving every citation through
    /// the daemon's own text rather than anything the model wrote.
    ///
    /// Every interpolated scalar is forced onto one line first. The layout
    /// *is* the guarantee here — a line beginning `supports:` means the daemon
    /// resolved that citation — so a statement containing a newline could
    /// otherwise print a fabricated citation that reads exactly like a real
    /// one. The model authors the statement, and fact text quotes process
    /// names, so both sides of this are untrusted.
    pub fn render(&self) -> String {
        let mut out = String::new();

        if self.hypotheses.is_empty() {
            out.push_str("No grounded hypothesis for this incident.\n");
            if let Some(summary) = self.discard_summary() {
                out.push_str(&summary);
            }
            return out;
        }

        for (i, hypothesis) in self.hypotheses.iter().enumerate() {
            out.push_str(&format!(
                "{}. [{}] {}\n",
                i + 1,
                hypothesis.reason_code.as_str(),
                single_line(&hypothesis.statement)
            ));

            for id in &hypothesis.supporting_fact_ids {
                if let Some(statement) = self.fact_statement(id) {
                    out.push_str(&format!("   supports:    {}\n", single_line(statement)));
                }
            }
            for id in &hypothesis.contradicting_fact_ids {
                if let Some(statement) = self.fact_statement(id) {
                    out.push_str(&format!("   contradicts: {}\n", single_line(statement)));
                }
            }
            if let Some(action) = &hypothesis.proposed_action {
                out.push_str(&format!("   proposed:    {}\n", single_line(action)));
            }
            if let Some(confidence) = hypothesis.model_stated_confidence {
                out.push_str(&format!(
                    "   the model rates its own confidence {confidence:.2} (uncalibrated)\n"
                ));
            }
            out.push('\n');
        }

        if let Some(summary) = self.discard_summary() {
            out.push_str(&summary);
        }

        out
    }
}

/// Checks every citation against the supplied facts.
///
/// A hypothesis survives only if it cites at least one supplied fact and cites
/// nothing else. Partial credit is deliberately not given: a response that
/// half-invents its evidence is not a response to reason about.
pub fn ground(proposed: ProposedInvestigation, facts: Vec<Fact>) -> IncidentInvestigation {
    let known: HashSet<&str> = facts.iter().map(|f| f.id.as_str()).collect();
    let mut hypotheses = Vec::new();
    let mut discarded = Vec::new();

    for hypothesis in proposed.hypotheses {
        let unknown: Vec<String> = hypothesis
            .supporting_fact_ids
            .iter()
            .chain(hypothesis.contradicting_fact_ids.iter())
            .filter(|id| !known.contains(id.as_str()))
            .cloned()
            .collect();

        if !unknown.is_empty() {
            discarded.push(DiscardedHypothesis {
                statement: hypothesis.statement,
                reason: DiscardReason::UnknownFactIds { ids: unknown },
            });
            continue;
        }

        if hypothesis.supporting_fact_ids.is_empty() {
            discarded.push(DiscardedHypothesis {
                statement: hypothesis.statement,
                reason: DiscardReason::NoSupportingFacts,
            });
            continue;
        }

        // A confidence outside 0..=1 is not a number to clamp into range:
        // rounding 1.7 down to 1.0 would invent total certainty out of a
        // malformed field. Dropping it says what is actually known.
        let model_stated_confidence = hypothesis
            .confidence
            .filter(|c| c.is_finite() && (0.0..=1.0).contains(c));

        hypotheses.push(Hypothesis {
            reason_code: hypothesis.reason_code,
            statement: hypothesis.statement,
            supporting_fact_ids: hypothesis.supporting_fact_ids,
            contradicting_fact_ids: hypothesis.contradicting_fact_ids,
            model_stated_confidence,
            proposed_action: hypothesis.proposed_action,
        });
    }

    IncidentInvestigation {
        schema_version: SCHEMA_VERSION,
        facts,
        hypotheses,
        discarded,
    }
}

/// Extracts the JSON object from a model reply that may wrap it in prose or a
/// code fence, then grounds it.
pub fn parse_and_ground(text: &str, facts: Vec<Fact>) -> Result<IncidentInvestigation, String> {
    let start = text.find('{').ok_or("no JSON object in response")?;
    let end = text.rfind('}').ok_or("no JSON object in response")?;
    if end <= start {
        return Err("no JSON object in response".to_string());
    }

    let proposed: ProposedInvestigation =
        serde_json::from_str(&text[start..=end]).map_err(|e| e.to_string())?;

    Ok(ground(proposed, facts))
}

/// Flattens a value onto one line so it cannot forge the layout around it.
///
/// Line breaks and tabs become their escaped spelling rather than being
/// dropped: the operator should see that the text contained them, since a
/// statement trying to fake a citation is itself worth noticing. Other control
/// characters are removed — they carry no meaning here and ESC begins the
/// terminal-escape family.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Vec<Fact> {
        vec![
            Fact::new("f1", "CPU usage was 96.3%"),
            Fact::new("f2", "CPU pressure stall was 75.2%"),
        ]
    }

    fn proposed(json: &str) -> ProposedInvestigation {
        serde_json::from_str(json).expect("fixture parses")
    }

    #[test]
    fn a_hypothesis_citing_supplied_facts_survives() {
        let out = ground(
            proposed(
                r#"{"hypotheses":[{"reason_code":"cpu_spin","statement":"Runaway loop",
                   "supporting_fact_ids":["f1","f2"],"confidence":0.8}]}"#,
            ),
            facts(),
        );

        assert_eq!(out.hypotheses.len(), 1);
        assert!(out.discarded.is_empty());
        assert_eq!(out.hypotheses[0].model_stated_confidence, Some(0.8));
        assert_eq!(out.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn a_hypothesis_citing_an_unsupplied_fact_is_discarded() {
        // The failure this schema exists to catch: evidence that never existed.
        let out = ground(
            proposed(
                r#"{"hypotheses":[{"reason_code":"fork_storm","statement":"Fork bomb",
                   "supporting_fact_ids":["f1","f9"]}]}"#,
            ),
            facts(),
        );

        assert!(out.hypotheses.is_empty());
        assert_eq!(
            out.discarded[0].reason,
            DiscardReason::UnknownFactIds {
                ids: vec!["f9".to_string()]
            }
        );
    }

    #[test]
    fn an_uncited_hypothesis_is_discarded() {
        let out = ground(
            proposed(
                r#"{"hypotheses":[{"reason_code":"oom_risk","statement":"Probably memory",
                   "supporting_fact_ids":[]}]}"#,
            ),
            facts(),
        );

        assert!(out.hypotheses.is_empty());
        assert_eq!(out.discarded[0].reason, DiscardReason::NoSupportingFacts);
    }

    #[test]
    fn a_bad_citation_does_not_discard_its_neighbours() {
        let out = ground(
            proposed(
                r#"{"hypotheses":[
                   {"reason_code":"cpu_spin","statement":"Sound","supporting_fact_ids":["f1"]},
                   {"reason_code":"fork_storm","statement":"Invented","supporting_fact_ids":["f7"]}]}"#,
            ),
            facts(),
        );

        assert_eq!(out.hypotheses.len(), 1);
        assert_eq!(out.hypotheses[0].statement, "Sound");
        assert_eq!(out.discarded.len(), 1);
    }

    #[test]
    fn contradicting_citations_are_checked_too() {
        let out = ground(
            proposed(
                r#"{"hypotheses":[{"reason_code":"cpu_spin","statement":"Loop",
                   "supporting_fact_ids":["f1"],"contradicting_fact_ids":["f4"]}]}"#,
            ),
            facts(),
        );

        assert!(out.hypotheses.is_empty());
        assert_eq!(
            out.discarded[0].reason,
            DiscardReason::UnknownFactIds {
                ids: vec!["f4".to_string()]
            }
        );
    }

    #[test]
    fn an_out_of_range_confidence_is_dropped_not_clamped() {
        // Clamping 1.7 to 1.0 would turn a malformed field into total
        // certainty. The honest result is that no confidence was stated.
        let out = ground(
            proposed(
                r#"{"hypotheses":[{"reason_code":"cpu_spin","statement":"Loop",
                   "supporting_fact_ids":["f1"],"confidence":1.7}]}"#,
            ),
            facts(),
        );

        assert_eq!(out.hypotheses[0].model_stated_confidence, None);
    }

    /// The layout carries the guarantee: a line starting `supports:` means the
    /// daemon resolved that citation. A statement with an embedded newline
    /// could otherwise print a line indistinguishable from a real one.
    #[test]
    fn a_statement_cannot_forge_a_citation_line() {
        let out = ground(
            proposed(
                r#"{"hypotheses":[{"reason_code":"cpu_spin",
                   "statement":"Runaway loop\n   supports:    the disk was on fire",
                   "supporting_fact_ids":["f1"]}]}"#,
            ),
            facts(),
        );

        let report = out.render();
        let forged: Vec<&str> = report
            .lines()
            .filter(|l| l.trim_start().starts_with("supports:"))
            .collect();

        assert_eq!(
            forged.len(),
            1,
            "only the daemon's own citation may appear as a supports line: {report}"
        );
        assert!(
            forged[0].contains("CPU usage was 96.3%"),
            "the surviving line must be the resolved fact: {report}"
        );
        assert!(
            !report.contains("\n   supports:    the disk"),
            "the injected break must not survive as layout: {report}"
        );
        // The text is still shown, with the break visible as an escape, so an
        // operator can see the attempt rather than a silently trimmed line.
        assert!(report.contains("Runaway loop\\n"), "{report}");
    }

    /// Facts quote process names, so the same injection arrives from the other
    /// direction — through text the daemon itself wrote.
    #[test]
    fn a_fact_cannot_forge_a_citation_line_either() {
        let out = ground(
            proposed(
                r#"{"hypotheses":[{"reason_code":"cpu_spin","statement":"Runaway loop",
                   "supporting_fact_ids":["f1"]}]}"#,
            ),
            vec![Fact::new(
                "f1",
                "process evil\n   contradicts: nothing was wrong was busy",
            )],
        );

        let report = out.render();
        assert!(
            !report
                .lines()
                .any(|l| l.trim_start().starts_with("contradicts:")),
            "a process name must not be able to add a contradicts line: {report}"
        );
    }

    #[test]
    fn rendering_quotes_the_daemons_facts_not_the_models() {
        let out = ground(
            proposed(
                r#"{"hypotheses":[{"reason_code":"cpu_spin","statement":"Runaway loop",
                   "supporting_fact_ids":["f1"],"proposed_action":"Check the deployment"}]}"#,
            ),
            facts(),
        );

        let report = out.render();
        assert!(report.contains("Runaway loop"));
        assert!(report.contains("CPU usage was 96.3%"));
        assert!(report.contains("Check the deployment"));
    }

    #[test]
    fn an_all_discarded_investigation_reports_nothing_grounded() {
        let out = ground(
            proposed(
                r#"{"hypotheses":[{"reason_code":"cpu_spin","statement":"Invented",
                   "supporting_fact_ids":["f9"]}]}"#,
            ),
            facts(),
        );

        assert!(out.is_empty());
        let report = out.render();
        assert!(report.contains("No grounded hypothesis"));
        assert!(!report.contains("Invented"));
    }

    #[test]
    fn the_report_names_the_discard_reason_it_actually_recorded() {
        // A hypothesis that cited nothing did not invent evidence, and saying
        // it did misdescribes both the model's failure and its severity.
        let out = ground(
            proposed(
                r#"{"hypotheses":[{"reason_code":"oom_risk","statement":"Probably memory",
                   "supporting_fact_ids":[]}]}"#,
            ),
            facts(),
        );

        let report = out.render();
        assert!(report.contains("cited no evidence at all"));
        assert!(!report.contains("not supplied"));
    }

    #[test]
    fn mixed_discard_reasons_are_counted_apart() {
        let out = ground(
            proposed(
                r#"{"hypotheses":[
                   {"reason_code":"cpu_spin","statement":"Sound","supporting_fact_ids":["f1"]},
                   {"reason_code":"fork_storm","statement":"Invented","supporting_fact_ids":["f7"]},
                   {"reason_code":"oom_risk","statement":"Bare assertion","supporting_fact_ids":[]}]}"#,
            ),
            facts(),
        );

        assert_eq!(out.hypotheses.len(), 1);
        let report = out.render();
        assert!(report.contains("2 hypotheses discarded"));
        assert!(report.contains("1 cited evidence that was not supplied"));
        assert!(report.contains("1 cited no evidence at all"));
    }

    #[test]
    fn json_is_extracted_from_surrounding_prose() {
        let reply = "Here is my analysis:\n```json\n{\"hypotheses\":[{\"reason_code\":\"cpu_spin\",\
                     \"statement\":\"Loop\",\"supporting_fact_ids\":[\"f1\"]}]}\n```\nHope that helps.";
        let out = parse_and_ground(reply, facts()).expect("embedded JSON parses");
        assert_eq!(out.hypotheses.len(), 1);
    }

    #[test]
    fn a_malformed_reply_is_an_error_rather_than_an_empty_result() {
        // An empty investigation means "nothing held up"; a parse failure means
        // "we never got an answer". Collapsing them would hide a broken model
        // endpoint as a quiet all-clear.
        assert!(parse_and_ground("the model was unavailable", facts()).is_err());
        assert!(parse_and_ground("{ not json }", facts()).is_err());

        // Well-formed JSON that never answers the question. A refusal, and a
        // model still replying in the pre-grounding summary format — the
        // likeliest regression of the two, since a stale endpoint produces it
        // on every incident.
        assert!(parse_and_ground(r#"{"error":"I cannot help with that"}"#, facts()).is_err());
        assert!(
            parse_and_ground(
                r#"{"reason_code":"fork_storm","summary":"high CPU","confidence":0.9}"#,
                facts(),
            )
            .is_err()
        );
        assert!(parse_and_ground("{}", facts()).is_err());
    }

    #[test]
    fn an_explicitly_empty_hypothesis_list_is_a_valid_answer() {
        // Distinct from the cases above: the model addressed the schema and
        // had nothing to propose. That is a result, not a failure to reply.
        let out = parse_and_ground(r#"{"hypotheses":[]}"#, facts()).expect("valid reply");
        assert!(out.is_empty());
        assert!(out.discarded.is_empty());
    }

    #[test]
    fn an_unknown_reason_code_is_rejected() {
        // The vocabulary is closed on purpose: a free-text category would let
        // the model coin a new incident type that nothing downstream handles.
        assert!(
            parse_and_ground(
                r#"{"hypotheses":[{"reason_code":"gpu_meltdown","statement":"x",
               "supporting_fact_ids":["f1"]}]}"#,
                facts(),
            )
            .is_err()
        );
    }
}
