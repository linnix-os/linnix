//! `linnix investigate` — who slowed this pod down, and what is the evidence.
//!
//! Reads the stall attributions cognitod already persists and turns the raw
//! per-window rows into one ranked answer per offender. The daemon decides
//! *whether* a neighbour is to blame; this command only aggregates and
//! presents that conclusion, so it deliberately holds no scoring logic of its
//! own.
//!
//! What it reports is *contention attribution*, not proven causality: the
//! evidence says these workloads contended over a resource while the victim
//! stalled. Confirming a fix means changing something and watching the stall
//! fall, which is a separate step.

use colored::*;
use reqwest::Client;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::error::Error;

/// One stored attribution row: a single offender's share of one victim stall
/// window, as served by cognitod's `/attribution`.
#[derive(Deserialize, Debug, Clone)]
pub struct Attribution {
    pub offender_pod: String,
    pub offender_namespace: String,
    /// The victim's *total* stall for this window. The same value repeats
    /// across every offender of one event, so summing it across rows
    /// double-counts.
    pub stall_us: u64,
    /// This offender's share of `stall_us`. `None` on rows written before the
    /// split existed, which is why share arithmetic has to skip them.
    pub attributed_stall_us: Option<u64>,
    pub timestamp: u64,
    pub cpu_share: f64,
    pub fork_count: u64,
    pub short_job_count: u64,
    /// Dominant signal, classified server-side.
    pub reason: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct AttributionResponse {
    pub attributions: Vec<Attribution>,
}

/// An offender's aggregated contribution across every window in the query.
#[derive(Debug, Clone, PartialEq)]
pub struct OffenderSummary {
    pub namespace: String,
    pub pod: String,
    /// Summed `attributed_stall_us` across windows — the only stall field that
    /// is safe to add up.
    pub attributed_stall_us: u64,
    /// Fraction of all attributed stall in the window that landed on this
    /// offender. `None` when no row carried a split to divide.
    pub share: Option<f64>,
    /// Number of distinct detection windows this offender appears in.
    pub windows: usize,
    pub peak_cpu_share: f64,
    pub forks: u64,
    pub short_jobs: u64,
    /// Dominant signal from the window where this offender was blamed most.
    pub reason: Option<String>,
    /// Rows for this offender that carried no per-offender split. An offender
    /// with only these has a genuinely unknown share, which must not be
    /// rendered as zero.
    pub unsplit_rows: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Investigation {
    /// The victim's real stall: `stall_us` summed over *distinct* timestamps,
    /// since one window repeats its total on every offender row.
    pub victim_stall_us: u64,
    pub windows: usize,
    pub offenders: Vec<OffenderSummary>,
    /// Rows too old to carry a per-offender split. They still count as
    /// evidence of contention but cannot take part in the share arithmetic,
    /// so the report says so rather than quietly ranking on partial data.
    pub rows_without_split: usize,
}

/// Collapses per-window rows into one ranked entry per offender.
pub fn summarise(attributions: &[Attribution]) -> Investigation {
    // One window reports the same victim total on each of its offender rows,
    // so the rows of an event have to collapse to one figure.
    //
    // The key is (timestamp, stall_us), not the timestamp alone. Timestamps
    // have one-second resolution and a victim's containers are scanned
    // separately, so one pod can produce two distinct events within a second.
    // Keying on time alone drops one of them, and the attributed total then
    // exceeds the victim total it is meant to be a share of. `stall_us` is a
    // microsecond delta, so it separates them — the same key the store's own
    // backfill groups on. Two events identical in both fields still collapse;
    // telling those apart needs an event id the daemon does not yet emit.
    let mut victim_windows: HashSet<(u64, u64)> = HashSet::new();
    for attr in attributions {
        victim_windows.insert((attr.timestamp, attr.stall_us));
    }
    let victim_stall_us: u64 = victim_windows.iter().map(|(_, stall)| stall).sum();

    let mut by_offender: HashMap<(String, String), OffenderSummary> = HashMap::new();
    let mut seen_windows: HashMap<(String, String), HashSet<(u64, u64)>> = HashMap::new();
    // Tracks which window currently justifies each offender's reported reason,
    // so the reason shown is the one from its worst window rather than
    // whichever row happened to sort last.
    let mut reason_peak: HashMap<(String, String), u64> = HashMap::new();
    let mut rows_without_split = 0usize;

    for attr in attributions {
        let key = (attr.offender_namespace.clone(), attr.offender_pod.clone());
        let attributed = attr.attributed_stall_us.unwrap_or(0);
        if attr.attributed_stall_us.is_none() {
            rows_without_split += 1;
        }

        let entry = by_offender
            .entry(key.clone())
            .or_insert_with(|| OffenderSummary {
                namespace: attr.offender_namespace.clone(),
                pod: attr.offender_pod.clone(),
                attributed_stall_us: 0,
                share: None,
                windows: 0,
                peak_cpu_share: 0.0,
                forks: 0,
                short_jobs: 0,
                reason: None,
                unsplit_rows: 0,
            });

        if attr.attributed_stall_us.is_none() {
            entry.unsplit_rows += 1;
        }
        entry.attributed_stall_us += attributed;
        entry.peak_cpu_share = entry.peak_cpu_share.max(attr.cpu_share);
        entry.forks += attr.fork_count;
        entry.short_jobs += attr.short_job_count;

        let peak = reason_peak.entry(key.clone()).or_insert(0);
        if attr.reason.is_some() && (attributed >= *peak || entry.reason.is_none()) {
            *peak = attributed;
            entry.reason = attr.reason.clone();
        }

        seen_windows
            .entry(key)
            .or_default()
            .insert((attr.timestamp, attr.stall_us));
    }

    for (key, windows) in seen_windows {
        if let Some(entry) = by_offender.get_mut(&key) {
            entry.windows = windows.len();
        }
    }

    let total_attributed: u64 = by_offender.values().map(|o| o.attributed_stall_us).sum();
    let mut offenders: Vec<OffenderSummary> = by_offender.into_values().collect();
    for offender in &mut offenders {
        // An offender whose every row predates the split contributed an
        // unknown amount, not zero. Rendering it as 0% would read as an
        // exoneration the data does not support.
        let share_is_knowable = total_attributed > 0
            && !(offender.attributed_stall_us == 0 && offender.unsplit_rows > 0);
        if share_is_knowable {
            offender.share = Some(offender.attributed_stall_us as f64 / total_attributed as f64);
        }
    }

    // Ties broken by name so repeated runs over the same window agree.
    offenders.sort_by(|a, b| {
        b.attributed_stall_us
            .cmp(&a.attributed_stall_us)
            .then_with(|| (&a.namespace, &a.pod).cmp(&(&b.namespace, &b.pod)))
    });

    Investigation {
        victim_stall_us,
        windows: victim_windows.len(),
        offenders,
        rows_without_split,
    }
}

/// Parses `20m`, `1h`, `90s` into whole minutes, which is the unit
/// `/attribution` takes. Sub-minute windows round up rather than to zero.
pub fn parse_since_minutes(since: &str) -> Result<i64, String> {
    let since = since.trim();
    let (value, unit) = since.split_at(
        since
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(since.len()),
    );
    let value: i64 = value
        .parse()
        .map_err(|_| format!("invalid duration '{since}' (expected e.g. 20m, 1h, 90s)"))?;
    if value <= 0 {
        return Err(format!("duration '{since}' must be positive"));
    }

    let minutes = match unit {
        "s" => (value + 59) / 60,
        "m" | "" => value,
        "h" => value * 60,
        other => return Err(format!("unknown duration unit '{other}' (use s, m or h)")),
    };
    Ok(minutes.max(1))
}

fn format_stall(us: u64) -> String {
    let seconds = us as f64 / 1_000_000.0;
    if seconds >= 1.0 {
        format!("{seconds:.1}s")
    } else {
        format!("{}ms", us / 1_000)
    }
}

fn humanise_reason(reason: Option<&str>) -> &str {
    match reason {
        Some("high_cpu_contention") => "high CPU contention",
        Some("fork_storm") => "fork storm",
        Some("short_job_churn") => "short-job churn",
        Some(other) => other,
        None => "unclassified",
    }
}

/// Renders the investigation. Returns the report so tests can assert on it
/// without going through stdout.
pub fn render(
    investigation: &Investigation,
    namespace: &str,
    pod: &str,
    since: &str,
    color: bool,
) -> String {
    let mut out = String::new();
    let heading = |s: &str| {
        if color {
            s.bold().to_string()
        } else {
            s.to_string()
        }
    };

    out.push_str(&format!(
        "{} {}/{} over the last {}\n\n",
        heading("Investigation:"),
        namespace,
        pod,
        since
    ));

    if investigation.offenders.is_empty() {
        out.push_str(
            "No contention attributed to any neighbour in this window.\n\n\
             The pod may still be slow — this only rules out other workloads on \
             the node as the cause. Look at the pod's own limits, throttling and \
             workload next.\n",
        );
        return out;
    }

    out.push_str(&format!(
        "{} {}/{} lost {} to stalls across {} detection window{}.\n",
        heading("Victim:"),
        namespace,
        pod,
        format_stall(investigation.victim_stall_us),
        investigation.windows,
        if investigation.windows == 1 { "" } else { "s" }
    ));

    // Naming the denominator keeps the percentages below from reading as
    // shares of the victim's whole stall. They are shares of the part that
    // could be pinned on a neighbour, which is usually less.
    let total_attributed: u64 = investigation
        .offenders
        .iter()
        .map(|o| o.attributed_stall_us)
        .sum();
    out.push_str(&format!(
        "  {} of that is attributed to neighbours; the percentages below split \
         that figure.\n\n",
        format_stall(total_attributed)
    ));

    let (primary, rest) = investigation.offenders.split_first().expect("non-empty");
    let share = primary
        .share
        .map(|s| format!("{:.0}% of attributed stall", s * 100.0))
        .unwrap_or_else(|| "share unavailable".to_string());

    let offender_line = format!("{}/{}", primary.namespace, primary.pod);
    out.push_str(&format!(
        "{} {} — {}\n",
        heading("Likely offender:"),
        if color {
            offender_line.red().to_string()
        } else {
            offender_line
        },
        share
    ));
    out.push_str(&format!(
        "  Attributed stall: {} across {} window{}\n",
        format_stall(primary.attributed_stall_us),
        primary.windows,
        if primary.windows == 1 { "" } else { "s" }
    ));
    out.push_str(&format!(
        "  Dominant signal:  {}\n",
        humanise_reason(primary.reason.as_deref())
    ));
    out.push_str(&format!(
        "  Evidence:         peak CPU share {:.2}, {} forks, {} short jobs\n",
        primary.peak_cpu_share, primary.forks, primary.short_jobs
    ));

    if !rest.is_empty() {
        out.push_str(&format!("\n{}\n", heading("Also contributing:")));
        for offender in rest {
            match offender.share {
                Some(share) => out.push_str(&format!(
                    "  {}/{} — {:.0}% ({}, {})\n",
                    offender.namespace,
                    offender.pod,
                    share * 100.0,
                    format_stall(offender.attributed_stall_us),
                    humanise_reason(offender.reason.as_deref())
                )),
                None => out.push_str(&format!(
                    "  {}/{} — share unknown ({}, blamed in {} window{})\n",
                    offender.namespace,
                    offender.pod,
                    humanise_reason(offender.reason.as_deref()),
                    offender.windows,
                    if offender.windows == 1 { "" } else { "s" }
                )),
            }
        }
    }

    if investigation.rows_without_split > 0 {
        let (noun, verb) = if investigation.rows_without_split == 1 {
            ("attribution", "predates")
        } else {
            ("attributions", "predate")
        };
        out.push_str(&format!(
            "\nNote: {} {} {} per-offender stall splitting and {} excluded from the \
             percentages above.\n",
            investigation.rows_without_split,
            noun,
            verb,
            if investigation.rows_without_split == 1 {
                "is"
            } else {
                "are"
            }
        ));
    }

    out.push_str(
        "\nThis is contention attribution, not proven causality. To confirm, change \
         one thing — move the offender, or give it a CPU limit — and check whether \
         the victim's stall falls.\n",
    );

    out
}

pub async fn run_investigate(
    client: &Client,
    base: &str,
    target: &str,
    since: &str,
    color: bool,
) -> Result<(), Box<dyn Error>> {
    let (namespace, pod) = target
        .split_once('/')
        .ok_or_else(|| format!("expected NAMESPACE/POD, got '{target}'"))?;
    if namespace.is_empty() || pod.is_empty() {
        return Err(format!("expected NAMESPACE/POD, got '{target}'").into());
    }
    let window = parse_since_minutes(since)?;

    let resp = client
        .get(format!("{base}/attribution"))
        .query(&[
            ("pod", pod.to_string()),
            ("namespace", namespace.to_string()),
            ("window", window.to_string()),
        ])
        .send()
        .await?;

    if resp.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE {
        return Err(
            "cognitod has no incident store configured, so no attribution history exists".into(),
        );
    }
    if !resp.status().is_success() {
        return Err(format!("attribution query failed: {}", resp.status()).into());
    }

    let body: AttributionResponse = resp.json().await?;
    let investigation = summarise(&body.attributions);
    print!("{}", render(&investigation, namespace, pod, since, color));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(pod: &str, ts: u64, attributed: Option<u64>, stall: u64) -> Attribution {
        Attribution {
            offender_pod: pod.to_string(),
            offender_namespace: "media".to_string(),
            stall_us: stall,
            attributed_stall_us: attributed,
            timestamp: ts,
            cpu_share: 0.5,
            fork_count: 10,
            short_job_count: 5,
            reason: Some("high_cpu_contention".to_string()),
        }
    }

    #[test]
    fn victim_stall_counts_each_window_once() {
        // Two offenders in one window: the window's total must not be doubled.
        let rows = vec![
            attr("resizer", 100, Some(600_000), 1_000_000),
            attr("etl", 100, Some(400_000), 1_000_000),
        ];
        let out = summarise(&rows);
        assert_eq!(out.victim_stall_us, 1_000_000);
        assert_eq!(out.windows, 1);
    }

    #[test]
    fn two_events_in_one_second_are_not_collapsed() {
        // Attribution timestamps have one-second resolution and a victim's
        // containers are scanned separately, so one pod can produce two events
        // within a second. Keying the victim's stall on the timestamp alone
        // drops one of them, and the attributed total then exceeds the victim
        // total it is supposed to be a share of. The store's own backfill
        // separates these events on (timestamp, stall_us) for this reason.
        let rows = vec![
            attr("resizer", 100, Some(500_000), 500_000),
            attr("etl", 100, Some(900_000), 900_000),
        ];
        let out = summarise(&rows);

        assert_eq!(out.victim_stall_us, 1_400_000);
        assert_eq!(out.windows, 2);

        let attributed: u64 = out.offenders.iter().map(|o| o.attributed_stall_us).sum();
        assert!(
            attributed <= out.victim_stall_us,
            "attributed {attributed} exceeds the victim's {} total",
            out.victim_stall_us
        );
    }

    #[test]
    fn offender_rows_aggregate_across_windows() {
        let rows = vec![
            attr("resizer", 100, Some(600_000), 1_000_000),
            attr("resizer", 200, Some(400_000), 800_000),
            attr("etl", 100, Some(400_000), 1_000_000),
        ];
        let out = summarise(&rows);
        assert_eq!(out.offenders.len(), 2);

        let top = &out.offenders[0];
        assert_eq!(top.pod, "resizer");
        assert_eq!(top.attributed_stall_us, 1_000_000);
        assert_eq!(top.windows, 2);
        // 1.0s of the 1.4s attributed overall.
        assert!((top.share.unwrap() - 1.0 / 1.4).abs() < 1e-9);
        assert_eq!(out.victim_stall_us, 1_800_000);
    }

    #[test]
    fn ranking_uses_summed_stall_not_row_order() {
        // A single large row outranks two smaller ones from a louder offender.
        let rows = vec![
            attr("chatty", 100, Some(100_000), 500_000),
            attr("chatty", 200, Some(100_000), 500_000),
            attr("heavy", 300, Some(900_000), 900_000),
        ];
        let out = summarise(&rows);
        assert_eq!(out.offenders[0].pod, "heavy");
        assert_eq!(out.offenders[1].pod, "chatty");
    }

    #[test]
    fn rows_without_split_are_reported_not_ranked() {
        let rows = vec![
            attr("legacy", 100, None, 500_000),
            attr("modern", 200, Some(300_000), 300_000),
        ];
        let out = summarise(&rows);
        assert_eq!(out.rows_without_split, 1);
        assert_eq!(out.offenders[0].pod, "modern");
        assert_eq!(out.offenders[0].share, Some(1.0));
        // The legacy row contributes no stall it cannot account for.
        assert_eq!(out.offenders[1].attributed_stall_us, 0);
    }

    #[test]
    fn an_unsplit_offender_reads_as_unknown_not_exonerated() {
        // Showing 0% for an offender we simply cannot measure would read as
        // clearing it, which the data does not support.
        let rows = vec![
            attr("modern", 100, Some(300_000), 300_000),
            attr("legacy", 200, None, 500_000),
        ];
        let out = summarise(&rows);
        let legacy = out.offenders.iter().find(|o| o.pod == "legacy").unwrap();
        assert_eq!(legacy.share, None);
        assert_eq!(legacy.unsplit_rows, 1);

        let report = render(&out, "payments", "api", "20m", false);
        let legacy_line = report
            .lines()
            .find(|l| l.contains("media/legacy"))
            .expect("the unmeasurable offender is still listed");
        assert!(legacy_line.contains("share unknown"));
        assert!(!legacy_line.contains('%'));
        assert!(report.contains("1 attribution predates"));
    }

    #[test]
    fn no_offenders_reports_absence_rather_than_accusing() {
        let out = summarise(&[]);
        assert!(out.offenders.is_empty());
        let report = render(&out, "payments", "api", "20m", false);
        assert!(report.contains("No contention attributed"));
        assert!(!report.contains("Likely offender"));
    }

    #[test]
    fn report_names_top_offender_and_share() {
        let rows = vec![
            attr("resizer", 100, Some(700_000), 1_000_000),
            attr("etl", 100, Some(300_000), 1_000_000),
        ];
        let report = render(&summarise(&rows), "payments", "api", "20m", false);
        assert!(report.contains("media/resizer"));
        assert!(report.contains("70% of attributed stall"));
        assert!(report.contains("high CPU contention"));
        // The victim lost 1.0s, all of which was attributable here.
        assert!(report.contains("lost 1.0s to stalls"));
        assert!(report.contains("1.0s of that is attributed to neighbours"));
    }

    #[test]
    fn unattributed_stall_stays_visible() {
        // Only 400ms of a 1s stall could be pinned on a neighbour. Reporting
        // the offender at 100% without naming the denominator would read as
        // "this pod caused the whole second".
        let rows = vec![attr("resizer", 100, Some(400_000), 1_000_000)];
        let report = render(&summarise(&rows), "payments", "api", "20m", false);
        assert!(report.contains("lost 1.0s to stalls"));
        assert!(report.contains("400ms of that is attributed to neighbours"));
    }

    #[test]
    fn durations_parse_into_minutes() {
        assert_eq!(parse_since_minutes("20m").unwrap(), 20);
        assert_eq!(parse_since_minutes("1h").unwrap(), 60);
        assert_eq!(parse_since_minutes("30").unwrap(), 30);
        // Sub-minute windows round up rather than collapsing to zero.
        assert_eq!(parse_since_minutes("90s").unwrap(), 2);
        assert_eq!(parse_since_minutes("5s").unwrap(), 1);
        assert!(parse_since_minutes("0m").is_err());
        assert!(parse_since_minutes("abc").is_err());
        assert!(parse_since_minutes("10d").is_err());
    }
}
