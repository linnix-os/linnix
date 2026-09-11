//! Privacy enforcement for cloud export.
//!
//! The schema's data-minimization classes are hard rules here, not config:
//!
//! - **NEVER export** (removed unconditionally): tokens, secrets, passwords,
//!   authorization headers, environment blocks, cookies/sessions.
//! - **OPT-IN only** (removed unless `[cloud] export_process_identity =
//!   true`): process identity — comm, PIDs, cmdline, exe paths, raw cgroup
//!   paths, and the incident's `target_pid`/`target_name`.
//! - **Default allow** (kept): pod namespace/name, PSI values, stall pairs,
//!   fork counts, thresholds, verdicts, evidence labels, probe health.
//!
//! Blocked keys are dropped from the JSON (not replaced with a marker), so
//! the edge never sees either the value or its shape.

use serde_json::Value;

/// Process-identity keys: opt-in only. Matched exactly (case-insensitive);
/// nested objects are walked, so `{"parent": {"pid": 1}}` is scrubbed too.
const IDENTITY_KEYS: &[&str] = &[
    "comm",
    "parent_comm",
    "target_name",
    "process_name",
    "pid",
    "tid",
    "tgid",
    "ppid",
    "parent_pid",
    "target_pid",
    "cmdline",
    "cmd_line",
    "exe",
    "executable",
    "exec_path",
    "cgroup",
    "cgroup_path",
];

/// Secret keys: never exported. Matched as a case-insensitive substring so
/// `api_auth_token`, `signing_secret`, `db_password` are all caught.
const SECRET_FRAGMENTS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "private_key",
    "cookie",
    "sessionid",
    "session_id",
];

/// Environment blocks: never exported. Exact match (case-insensitive) —
/// a substring match would eat legitimate keys like `environment_score`.
const ENV_KEYS: &[&str] = &["env", "environ", "environment", "env_vars"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrubPolicy {
    /// When true, process-identity keys are kept. Secrets are still removed.
    pub export_process_identity: bool,
}

impl ScrubPolicy {
    pub fn from_opt_in(export_process_identity: bool) -> Self {
        Self {
            export_process_identity,
        }
    }
}

fn is_secret_key(lower_key: &str) -> bool {
    SECRET_FRAGMENTS.iter().any(|frag| lower_key.contains(frag)) || ENV_KEYS.contains(&lower_key)
}

fn is_identity_key(lower_key: &str) -> bool {
    IDENTITY_KEYS.contains(&lower_key)
}

/// Recursively drop blocked keys from a JSON value in place.
pub fn scrub_value(value: &mut Value, policy: ScrubPolicy) {
    match value {
        Value::Object(map) => {
            map.retain(|key, _| {
                let lower = key.to_ascii_lowercase();
                if is_secret_key(&lower) {
                    return false;
                }
                if !policy.export_process_identity && is_identity_key(&lower) {
                    return false;
                }
                true
            });
            for child in map.values_mut() {
                scrub_value(child, policy);
            }
        }
        Value::Array(items) => {
            for item in items {
                scrub_value(item, policy);
            }
        }
        _ => {}
    }
}

/// Scrub an incident's `system_snapshot` JSON for export. Returns the
/// scrubbed value (an object), or `None` when there is no snapshot or it
/// isn't valid JSON — the caller then ships an empty details object rather
/// than inventing one.
pub fn scrub_snapshot(snapshot: Option<&str>, policy: ScrubPolicy) -> Option<Value> {
    let raw = snapshot?;
    let mut value: Value = serde_json::from_str(raw).ok()?;
    scrub_value(&mut value, policy);
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const STRICT: ScrubPolicy = ScrubPolicy {
        export_process_identity: false,
    };
    const OPT_IN: ScrubPolicy = ScrubPolicy {
        export_process_identity: true,
    };

    fn kitchen_sink() -> Value {
        json!({
            "verdict": "StormCritical",
            "forks_per_sec": 87.5,
            "threshold_per_sec": 30.0,
            "window_secs": 10.0,
            "parent_pid": 4242,
            "parent_comm": "runaway.sh",
            "cmdline": "/bin/bash runaway.sh",
            "cgroup_path": "/sys/fs/cgroup/system.slice/evil.service",
            "evidence": {"fork_rate": "measured", "offending_parent": "inferred"},
            "nested": {"pid": 99, "exe": "/usr/bin/x", "keep_me": 1},
            "api_token": "tok-123",
            "signing_secret": "shh",
            "environment": {"HOME": "/root"},
            "list": [{"tid": 5, "v": 1}]
        })
    }

    #[test]
    fn strict_scrub_removes_identity_and_secrets_keeps_measurements() {
        let mut v = kitchen_sink();
        scrub_value(&mut v, STRICT);
        // Identity gone.
        for key in ["parent_pid", "parent_comm", "cmdline", "cgroup_path"] {
            assert!(v.get(key).is_none(), "{key} must be scrubbed");
        }
        assert!(v["nested"].get("pid").is_none());
        assert!(v["nested"].get("exe").is_none());
        assert!(v["list"][0].get("tid").is_none());
        // Secrets gone.
        assert!(v.get("api_token").is_none());
        assert!(v.get("signing_secret").is_none());
        assert!(v.get("environment").is_none());
        // Measurements and labels kept.
        assert_eq!(v["verdict"], "StormCritical");
        assert_eq!(v["forks_per_sec"], 87.5);
        assert_eq!(v["threshold_per_sec"], 30.0);
        assert_eq!(v["evidence"]["fork_rate"], "measured");
        assert_eq!(v["nested"]["keep_me"], 1);
        assert_eq!(v["list"][0]["v"], 1);
    }

    #[test]
    fn opt_in_keeps_identity_but_never_secrets() {
        let mut v = kitchen_sink();
        scrub_value(&mut v, OPT_IN);
        assert_eq!(v["parent_pid"], 4242);
        assert_eq!(v["parent_comm"], "runaway.sh");
        assert_eq!(v["cmdline"], "/bin/bash runaway.sh");
        assert!(v.get("api_token").is_none());
        assert!(v.get("signing_secret").is_none());
        assert!(v.get("environment").is_none());
    }

    #[test]
    fn key_matching_is_case_insensitive_and_exact_where_it_matters() {
        let mut v = json!({
            "Parent_PID": 1,
            "COMM": "x",
            "environment_score": 0.9,
            "my_tokenizer": "keep?",
        });
        scrub_value(&mut v, STRICT);
        assert!(v.get("Parent_PID").is_none());
        assert!(v.get("COMM").is_none());
        // Exact-match env keys don't eat `environment_score`...
        assert_eq!(v["environment_score"], 0.9);
        // ...but substring secret fragments do match `my_tokenizer`.
        assert!(v.get("my_tokenizer").is_none());
    }

    #[test]
    fn strict_scrub_removes_tgid_from_cpu_starvation_snapshots() {
        // Shape mirrors collectors/runqueue_starvation.rs: the subject's
        // tgid plus one per top_waiters entry. All are process identity.
        let mut v = json!({
            "tid": 4321,
            "tgid": 1234,
            "comm": "victim",
            "wait_ms": 6100.0,
            "window_secs": 10.0,
            "top_waiters": [
                {"tid": 111, "tgid": 100, "comm": "hog-a", "wait_ms": 50.0},
                {"tid": 222, "tgid": 200, "comm": "hog-b", "wait_ms": 40.0}
            ],
            "evidence": {"runqueue_wait": "measured", "offender": "unavailable"}
        });
        scrub_value(&mut v, STRICT);
        assert!(v.get("tid").is_none());
        assert!(v.get("tgid").is_none());
        assert!(v.get("comm").is_none());
        for w in v["top_waiters"].as_array().unwrap() {
            assert!(w.get("tid").is_none());
            assert!(w.get("tgid").is_none());
            assert!(w.get("comm").is_none());
            assert!(w.get("wait_ms").is_some());
        }
        // Measurements survive.
        assert_eq!(v["wait_ms"], 6100.0);
        assert_eq!(v["evidence"]["runqueue_wait"], "measured");
    }

    #[test]
    fn opt_in_preserves_tgid() {
        let mut v = json!({"tgid": 1234, "top_waiters": [{"tgid": 100}]});
        scrub_value(&mut v, OPT_IN);
        assert_eq!(v["tgid"], 1234);
        assert_eq!(v["top_waiters"][0]["tgid"], 100);
    }

    #[test]
    fn scrub_snapshot_returns_none_for_missing_or_invalid_json() {
        assert!(scrub_snapshot(None, STRICT).is_none());
        assert!(scrub_snapshot(Some("not json"), STRICT).is_none());
        let v = scrub_snapshot(Some(r#"{"a": 1, "pid": 2}"#), STRICT).unwrap();
        assert_eq!(v["a"], 1);
        assert!(v.get("pid").is_none());
    }
}
